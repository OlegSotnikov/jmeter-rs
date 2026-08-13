// SPDX-License-Identifier: Apache-2.0
//! Bounded, fail-closed JTL normalization and differential comparison.
//!
//! The comparator intentionally has no dependency on the results crate.  A JTL
//! is an external wire format and the neutral representation here is kept
//! independent while that crate's public API continues to evolve.

use std::collections::{BTreeMap, BTreeSet, btree_map::Entry};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use serde::Serialize;
use serde_json::{Map, Value, json};

use super::{
    DEFAULT_MAX_ARTIFACT_BYTES, DEFAULT_MAX_INPUT_BYTES, ErrorCode, OracleError, Result,
    ValidatedCase, absolute_path,
};

const DEFAULT_MAX_TEXT_BYTES: usize = 4 * 1024 * 1024;
const HARD_MAX_TEXT_BYTES: usize = 64 * 1024 * 1024;
const HARD_MAX_INPUT_BYTES: u64 = 256 * 1024 * 1024;
const HARD_MAX_DEPTH: usize = 1024;
const HARD_MAX_EVENTS: usize = 1_000_000;
const HARD_MAX_NODES: usize = 4_000_000;
const HARD_MAX_ATTRIBUTES: usize = 1_000_000;
const HARD_MAX_CSV_COLUMNS: usize = 100_000;
const HARD_MAX_ASSERTION_RESULTS: usize = 1_000_000;
const HARD_MAX_PROPERTIES: usize = 4_000_000;
const HARD_MAX_PROPERTIES_PER_ELEMENT: usize = 1_000_000;
const HARD_MAX_DIAGNOSTICS: usize = 1_000_000;
const HARD_MAX_OPAQUE_BYTES: usize = 64 * 1024 * 1024;
const HARD_MAX_DIFF_COUNT: usize = 1_000_000;
const HARD_MAX_HUMAN_DIFF_BYTES: usize = 1024 * 1024;
const HARD_MAX_IGNORED_LINE_PATTERNS: usize = 4_096;
const HARD_MAX_IGNORED_LINE_PATTERN_BYTES: usize = 8 * 1024 * 1024;
const MAX_JSON_NODES_PER_EVENT: usize = 256;
const MAX_DIFF_VALUE: usize = 512;
const MAX_HUMAN_DIFF: usize = 8 * 1024;
const MAX_PATTERN_ALTERNATIVES: usize = 256;
const MAX_PATTERN_GROUP_DEPTH: usize = 32;
const MAX_PATTERN_BYTES: usize = 16 * 1024;

/// Supported input/output projection formats.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompareFormat {
    /// JMeter CSV JTL.
    Csv,
    /// JMeter XML JTL.
    Xml,
    /// A neutral JSON projection.
    Json,
    /// A bounded semantic projection of a JMX test plan.
    JmxSemantic,
}

impl CompareFormat {
    fn as_str(self) -> &'static str {
        match self {
            Self::Csv => "jtl-csv",
            Self::Xml => "jtl-xml",
            Self::Json => "neutral-json",
            Self::JmxSemantic => "jmx-semantic",
        }
    }

    pub(crate) fn from_hint(hint: &str) -> Option<Self> {
        match hint.to_ascii_lowercase().as_str() {
            "csv" | "jtl-csv" => Some(Self::Csv),
            "xml" | "jtl-xml" => Some(Self::Xml),
            "json" | "neutral-json" => Some(Self::Json),
            "jmx" | "jmx-semantic" => Some(Self::JmxSemantic),
            _ => None,
        }
    }

    fn from_path(path: &Path) -> Option<Self> {
        path.extension()
            .and_then(|extension| extension.to_str())
            .and_then(Self::from_hint)
    }
}

impl Serialize for CompareFormat {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

/// Resource bounds for parsing and comparing result artifacts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompareLimits {
    /// Maximum bytes read from one input artifact.
    pub max_input_bytes: u64,
    /// Maximum number of top-level events in one input.
    pub max_events: usize,
    /// Maximum XML nesting depth.
    pub max_depth: usize,
    /// Maximum XML nodes retained while parsing one artifact.
    pub max_nodes: usize,
    /// Maximum XML attributes retained while parsing one artifact.
    pub max_attributes: usize,
    /// Maximum CSV columns in one record.
    pub max_csv_columns: usize,
    /// Maximum assertion results retained in one JTL artifact.
    pub max_assertion_results: usize,
    /// Maximum typed/opaque property descriptors retained by a JMX input.
    pub max_properties: usize,
    /// Maximum typed/opaque property descriptors under one JMX element.
    pub max_properties_per_element: usize,
    /// Maximum semantic diagnostics retained by a JMX input.
    pub max_diagnostics: usize,
    /// Maximum aggregate raw bytes accounted to opaque JMX subtrees.
    pub max_opaque_bytes: usize,
    /// Maximum bytes retained in one text value, field, name, or JSON string.
    pub max_text_bytes: usize,
    /// Maximum number of retained differences.
    pub max_diff_count: usize,
    /// Maximum bytes in the human-readable diff.
    pub max_human_diff_bytes: usize,
}

impl Default for CompareLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: DEFAULT_MAX_ARTIFACT_BYTES,
            max_events: 100_000,
            max_depth: 256,
            max_nodes: 1_000_000,
            max_attributes: 100_000,
            max_csv_columns: 1_024,
            max_assertion_results: 10_000,
            max_properties: 500_000,
            max_properties_per_element: 100_000,
            max_diagnostics: 4_096,
            max_opaque_bytes: 8 * 1024 * 1024,
            max_text_bytes: DEFAULT_MAX_TEXT_BYTES,
            max_diff_count: 256,
            max_human_diff_bytes: MAX_HUMAN_DIFF,
        }
    }
}

impl CompareLimits {
    pub(crate) fn validate_for_jmx(&self) -> Result<()> {
        self.validate()
    }

    fn validate(&self) -> Result<()> {
        if self.max_input_bytes == 0
            || self.max_events == 0
            || self.max_depth == 0
            || self.max_nodes == 0
            || self.max_attributes == 0
            || self.max_csv_columns == 0
            || self.max_assertion_results == 0
            || self.max_properties == 0
            || self.max_properties_per_element == 0
            || self.max_diagnostics == 0
            || self.max_opaque_bytes == 0
            || self.max_text_bytes == 0
            || self.max_diff_count == 0
            || self.max_human_diff_bytes == 0
        {
            return Err(OracleError::new_for_cli(
                ErrorCode::Configuration,
                "compare limits must be greater than zero",
            ));
        }
        if self.max_input_bytes > HARD_MAX_INPUT_BYTES {
            return Err(OracleError::new_for_cli(
                ErrorCode::Configuration,
                format!("max_input_bytes exceeds hard maximum {HARD_MAX_INPUT_BYTES}"),
            ));
        }
        if self.max_events > HARD_MAX_EVENTS {
            return Err(OracleError::new_for_cli(
                ErrorCode::Configuration,
                format!("max_events exceeds hard maximum {HARD_MAX_EVENTS}"),
            ));
        }
        if self.max_depth > HARD_MAX_DEPTH {
            return Err(OracleError::new_for_cli(
                ErrorCode::Configuration,
                format!("max_depth exceeds hard maximum {HARD_MAX_DEPTH}"),
            ));
        }
        if self.max_nodes > HARD_MAX_NODES {
            return Err(OracleError::new_for_cli(
                ErrorCode::Configuration,
                format!("max_nodes exceeds hard maximum {HARD_MAX_NODES}"),
            ));
        }
        if self.max_attributes > HARD_MAX_ATTRIBUTES {
            return Err(OracleError::new_for_cli(
                ErrorCode::Configuration,
                format!("max_attributes exceeds hard maximum {HARD_MAX_ATTRIBUTES}"),
            ));
        }
        if self.max_csv_columns > HARD_MAX_CSV_COLUMNS {
            return Err(OracleError::new_for_cli(
                ErrorCode::Configuration,
                format!("max_csv_columns exceeds hard maximum {HARD_MAX_CSV_COLUMNS}"),
            ));
        }
        if self.max_assertion_results > HARD_MAX_ASSERTION_RESULTS {
            return Err(OracleError::new_for_cli(
                ErrorCode::Configuration,
                format!("max_assertion_results exceeds hard maximum {HARD_MAX_ASSERTION_RESULTS}"),
            ));
        }
        if self.max_properties > HARD_MAX_PROPERTIES {
            return Err(OracleError::new_for_cli(
                ErrorCode::Configuration,
                format!("max_properties exceeds hard maximum {HARD_MAX_PROPERTIES}"),
            ));
        }
        if self.max_properties_per_element > HARD_MAX_PROPERTIES_PER_ELEMENT {
            return Err(OracleError::new_for_cli(
                ErrorCode::Configuration,
                format!(
                    "max_properties_per_element exceeds hard maximum {HARD_MAX_PROPERTIES_PER_ELEMENT}"
                ),
            ));
        }
        if self.max_diagnostics > HARD_MAX_DIAGNOSTICS {
            return Err(OracleError::new_for_cli(
                ErrorCode::Configuration,
                format!("max_diagnostics exceeds hard maximum {HARD_MAX_DIAGNOSTICS}"),
            ));
        }
        if self.max_opaque_bytes > HARD_MAX_OPAQUE_BYTES {
            return Err(OracleError::new_for_cli(
                ErrorCode::Configuration,
                format!("max_opaque_bytes exceeds hard maximum {HARD_MAX_OPAQUE_BYTES}"),
            ));
        }
        if self.max_text_bytes > HARD_MAX_TEXT_BYTES {
            return Err(OracleError::new_for_cli(
                ErrorCode::Configuration,
                format!("max_text_bytes exceeds hard maximum {HARD_MAX_TEXT_BYTES}"),
            ));
        }
        if self.max_diff_count > HARD_MAX_DIFF_COUNT {
            return Err(OracleError::new_for_cli(
                ErrorCode::Configuration,
                format!("max_diff_count exceeds hard maximum {HARD_MAX_DIFF_COUNT}"),
            ));
        }
        if self.max_human_diff_bytes > HARD_MAX_HUMAN_DIFF_BYTES {
            return Err(OracleError::new_for_cli(
                ErrorCode::Configuration,
                format!("max_human_diff_bytes exceeds hard maximum {HARD_MAX_HUMAN_DIFF_BYTES}"),
            ));
        }
        Ok(())
    }
}

/// Explicit comparison and normalization choices.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CompareOptions {
    /// Optional format override.  Without it, the path/content is inspected.
    pub format: Option<CompareFormat>,
    /// Normalization policy IDs declared by the case/profile.
    pub normalization_policy_refs: BTreeSet<String>,
    /// Exact expected-projection fields allowed to be ignored.
    pub ignored_fields: BTreeSet<String>,
    /// Anchored wildcard patterns allowed for dynamic debug lines.
    pub ignored_line_patterns: Vec<String>,
    /// Configured CSV field names when the writer omits its header row.
    pub csv_header: Option<Vec<String>>,
    /// Resource bounds.
    pub limits: CompareLimits,
}

impl CompareOptions {
    /// Create options with explicit policy references.
    pub fn with_policies<I, S>(policies: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            normalization_policy_refs: policies.into_iter().map(Into::into).collect(),
            ..Self::default()
        }
    }
}

/// A normalized assertion result retained in event order.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NeutralAssertion {
    /// Assertion attributes such as name/failure/error/failureMessage.
    pub fields: BTreeMap<String, String>,
}

/// A normalized JTL event/tree node.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NeutralEvent {
    /// Position among top-level events, or child position for nested nodes.
    pub position: usize,
    /// XML element name, or `row` for CSV.
    pub element: String,
    /// Wire attributes (XML) or configured columns (CSV).
    pub attributes: BTreeMap<String, String>,
    /// Text-bearing child sections such as responseData and samplerData.
    pub sections: BTreeMap<String, String>,
    /// Direct text for this node, retained for unknown XML children.
    pub text: String,
    /// Assertion results in source order.
    pub assertions: Vec<NeutralAssertion>,
    /// Nested sample/tree nodes in source order.
    pub children: Vec<NeutralEvent>,
    /// Every XML child element in source order, including assertions, sections,
    /// URL elements, nested samples, and unknown/plugin elements.
    pub child_events: Vec<NeutralXmlChild>,
}

/// One lossless-enough ordered XML child event. Attributes retain wire
/// metadata such as `class`, and repeated element names remain distinct by
/// their position in the parent stream.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NeutralXmlChild {
    /// Position among the parent's XML child elements.
    pub position: usize,
    /// Wire element/tag name.
    pub element: String,
    /// Wire attributes, including `class` when present.
    pub attributes: BTreeMap<String, String>,
    /// Direct text content of this child.
    pub text: String,
    /// Recursively retained ordered child elements.
    pub children: Vec<NeutralXmlChild>,
}

/// Neutral ordered result document.  `projection` is the stable comparison
/// view; the event/tree fields make the ordering and hierarchy inspectable.
#[derive(Clone, Debug, Serialize)]
pub struct NeutralDocument {
    /// Detected input format.
    pub format: CompareFormat,
    /// XML root element/attributes, when applicable.
    pub root: Option<NeutralRoot>,
    /// CSV header in wire order, when applicable.
    pub header: Option<Vec<String>>,
    /// Top-level result events in wire order.
    pub events: Vec<NeutralEvent>,
    /// Canonical neutral projection used by the comparator.
    pub projection: Value,
}

impl NeutralDocument {
    /// Return the canonical projection without exposing raw input bytes.
    #[must_use]
    pub fn projection(&self) -> &Value {
        &self.projection
    }
}

/// XML root metadata in the neutral document.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NeutralRoot {
    /// Root element name.
    pub element: String,
    /// Root attributes in lexical-independent order.
    pub attributes: BTreeMap<String, String>,
    /// Direct root text, excluding indentation-only text from projections.
    pub text: String,
    /// Direct root children in wire order.
    pub child_events: Vec<NeutralXmlChild>,
}

/// One structured difference. Values are bounded and redacted.
#[derive(Clone, Debug, Serialize)]
pub struct StructuredDiff {
    /// JSON-like neutral path.
    pub path: String,
    /// Difference kind (`missing`, `unexpected`, or `changed`).
    pub kind: String,
    /// Expected value, if any.
    pub expected: Option<Value>,
    /// Actual value, if any.
    pub actual: Option<Value>,
}

/// Machine-readable and concise human-readable comparison result.
#[derive(Clone, Debug, Serialize)]
pub struct CompareReport {
    /// Whether all declared expectations matched.
    pub equal: bool,
    /// Left-hand artifact metadata.
    pub actual: ArtifactSummary,
    /// Expected artifact metadata.
    pub expected: ArtifactSummary,
    /// Declared policy references used by this comparison.
    pub normalization_policy_refs: Vec<String>,
    /// Explicitly ignored fields.
    pub normalized_fields: Vec<String>,
    /// Bounded structured differences.
    pub structured_diff: Vec<StructuredDiff>,
    /// Bounded diagnostic differences before normalization is applied.
    pub raw_diagnostic_diff: Vec<StructuredDiff>,
    /// Bounded concise summary.
    pub human_diff: String,
}

/// Bounded artifact identity metadata in a comparison report.
#[derive(Clone, Debug, Serialize)]
pub struct ArtifactSummary {
    /// Input path, with no content embedded.
    pub path: String,
    /// Detected format.
    pub format: CompareFormat,
    /// Input size.
    pub size_bytes: u64,
    /// Number of top-level events, when parsed.
    pub event_count: usize,
}

struct ParsedInput {
    document: NeutralDocument,
    summary: ArtifactSummary,
}

/// Parse a bounded JTL or neutral JSON projection.
pub fn parse_jtl(path: impl AsRef<Path>, limits: &CompareLimits) -> Result<NeutralDocument> {
    parse_input(path.as_ref(), limits, None, None).map(|parsed| parsed.document)
}

/// Parse with an explicit format hint.
pub fn parse_jtl_with_format(
    path: impl AsRef<Path>,
    format: CompareFormat,
    limits: &CompareLimits,
) -> Result<NeutralDocument> {
    parse_input(path.as_ref(), limits, Some(format), None).map(|parsed| parsed.document)
}

/// Compare two raw JTL/neutral projection files using only the explicitly
/// supplied normalization choices.
pub fn compare_jtl_files(
    actual_path: impl AsRef<Path>,
    expected_path: impl AsRef<Path>,
    options: &CompareOptions,
) -> Result<CompareReport> {
    validate_options(options)?;
    let actual = parse_input(
        actual_path.as_ref(),
        &options.limits,
        options.format,
        options.csv_header.as_deref(),
    )?;
    let expected = parse_input(
        expected_path.as_ref(),
        &options.limits,
        options.format,
        options.csv_header.as_deref(),
    )?;
    let mut report = base_report(&actual.summary, &expected.summary, options);
    report.raw_diagnostic_diff = raw_projection_diff(
        &actual.document.projection,
        &expected.document.projection,
        options,
    );
    compare_neutral_documents(
        &actual.document,
        &expected.document.projection,
        options,
        &mut report,
    );
    Ok(finish_report(report, options.limits.max_human_diff_bytes))
}

/// Compare an actual JTL/projection against an existing case expectation.
///
/// When `expected_path` is omitted, the case manifest must contain exactly one
/// `execution.expected` path.  Multiple format variants require an explicit
/// path so a same-format projection is never selected by position.  The
/// expected projection's own `normalization` section is accepted only for
/// fields allowed by the case's declared profile policies.
pub fn compare_case_artifacts(
    fixture: &ValidatedCase,
    actual_path: impl AsRef<Path>,
    expected_path: Option<impl AsRef<Path>>,
    options: &CompareOptions,
) -> Result<CompareReport> {
    let mut effective = options.clone();
    effective
        .normalization_policy_refs
        .extend(fixture.case().normalization_policy_refs().iter().cloned());
    let actual_path = absolute_path(actual_path.as_ref())?;
    let expected_path = match expected_path {
        Some(path) => canonical_contained_expected_file(
            fixture.fixture_dir(),
            &absolute_path(path.as_ref())?,
        )?,
        None => select_expected_path(fixture)?,
    };
    // Apply the case's plan/input byte bound before opening the expectation.
    // The manifest may select a JMX expectation without an explicit CLI
    // format hint; delaying this until after the read would make the bound
    // route-dependent and allow an oversized expectation to be parsed first.
    super::jmx::apply_case_jmx_expected_read_limit(
        fixture.case().document(),
        &mut effective.limits,
    )?;
    let (expected_projection, expected_size_bytes) =
        read_json_bounded_contained(fixture.fixture_dir(), &expected_path, &effective.limits)?;
    let expected_is_jmx = expected_projection
        .get("format")
        .and_then(Value::as_str)
        .is_some_and(|format| format.eq_ignore_ascii_case("jmx-semantic"));
    if expected_is_jmx || options.format == Some(CompareFormat::JmxSemantic) {
        return super::jmx::compare_case_jmx_projection(
            fixture,
            &actual_path,
            &expected_path,
            &expected_projection,
            expected_size_bytes,
            &effective,
        );
    }
    apply_fixture_resource_limits(fixture.case().document(), &mut effective.limits)?;
    validate_options(&effective)?;
    let expected_format = expected_projection_format(&expected_projection)?;
    validate_comparator_variant(&expected_projection)?;
    match expected_format {
        CompareFormat::Csv => {
            validate_expected_csv_projection_with_limits(&expected_projection, &effective.limits)?;
        }
        CompareFormat::Xml => {
            validate_expected_xml_projection(&expected_projection, &effective.limits)?;
        }
        CompareFormat::Json => {}
        CompareFormat::JmxSemantic => {
            return Err(OracleError::new_for_cli(
                ErrorCode::UnsupportedFormat,
                "jmx-semantic projections require the JMX semantic comparator route",
            ));
        }
    }
    load_expected_normalization(&expected_projection, &mut effective)?;
    validate_options(&effective)?;
    let csv_header = if expected_format == CompareFormat::Csv {
        expected_csv_header(&expected_projection)?
    } else {
        None
    };
    let actual = parse_input(
        &actual_path,
        &effective.limits,
        options.format,
        csv_header.as_deref().or(effective.csv_header.as_deref()),
    )?;
    if expected_format != actual.document.format {
        return Err(OracleError::new_for_cli(
            ErrorCode::UnsupportedFormat,
            format!(
                "actual format '{}' does not match expected format '{}'",
                actual.document.format.as_str(),
                expected_format.as_str()
            ),
        ));
    }
    let expected_summary = ArtifactSummary {
        path: expected_path.to_string_lossy().into_owned(),
        format: expected_format,
        size_bytes: expected_size_bytes,
        event_count: expected_event_count(&expected_projection, &effective.limits)?,
    };
    let mut report = base_report(&actual.summary, &expected_summary, &effective);
    report.raw_diagnostic_diff = raw_projection_diff(
        &actual.document.projection,
        &expected_projection,
        &effective,
    );
    compare_expected_projection(
        &actual.document,
        &expected_projection,
        &effective,
        &mut report,
    )?;
    Ok(finish_report(report, effective.limits.max_human_diff_bytes))
}

fn validate_options(options: &CompareOptions) -> Result<()> {
    options.limits.validate()?;
    let max_ignored_fields = options
        .limits
        .max_diff_count
        .checked_mul(4)
        .ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::OutputLimit,
                "normalization field bound overflowed",
            )
        })?;
    if options.ignored_fields.len() > max_ignored_fields {
        return Err(OracleError::new_for_cli(
            ErrorCode::OutputLimit,
            "normalization field count exceeds the comparison bound",
        ));
    }
    if options.ignored_line_patterns.len() > HARD_MAX_IGNORED_LINE_PATTERNS {
        return Err(OracleError::new_for_cli(
            ErrorCode::OutputLimit,
            format!(
                "ignored line pattern count exceeds the hard maximum {HARD_MAX_IGNORED_LINE_PATTERNS}"
            ),
        ));
    }
    let pattern_bytes = options
        .ignored_line_patterns
        .iter()
        .try_fold(0_usize, |total, pattern| total.checked_add(pattern.len()))
        .ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::OutputLimit,
                "ignored line pattern byte count overflowed",
            )
        })?;
    if pattern_bytes > HARD_MAX_IGNORED_LINE_PATTERN_BYTES {
        return Err(OracleError::new_for_cli(
            ErrorCode::OutputLimit,
            format!(
                "ignored line pattern bytes exceed the hard maximum {HARD_MAX_IGNORED_LINE_PATTERN_BYTES}"
            ),
        ));
    }
    for policy in &options.normalization_policy_refs {
        if !known_policy(policy) {
            return Err(OracleError::new_for_cli(
                ErrorCode::Normalization,
                format!("unknown normalization policy '{policy}'"),
            ));
        }
    }
    for field in &options.ignored_fields {
        if field.is_empty() || field.len() > options.limits.max_text_bytes {
            return Err(OracleError::new_for_cli(
                ErrorCode::Normalization,
                "normalization field is empty or exceeds its bound",
            ));
        }
        if !allowed_ignored_field(field, &options.normalization_policy_refs) {
            return Err(OracleError::new_for_cli(
                ErrorCode::Normalization,
                format!("normalization field '{field}' is not allowed by declared policies"),
            ));
        }
    }
    for pattern in &options.ignored_line_patterns {
        if pattern.is_empty()
            || pattern.len() > options.limits.max_text_bytes
            || pattern.len() > MAX_PATTERN_BYTES
        {
            return Err(OracleError::new_for_cli(
                ErrorCode::Normalization,
                "ignored line pattern is empty or exceeds its text/complexity bound",
            ));
        }
        if !has_policy(&options.normalization_policy_refs, "NORM-ENV-001")
            && !has_policy(&options.normalization_policy_refs, "NORM-TIME-001")
        {
            return Err(OracleError::new_for_cli(
                ErrorCode::Normalization,
                "dynamic line normalization requires NORM-ENV-001 or NORM-TIME-001",
            ));
        }
        let trimmed = pattern.trim_matches(['^', '$']);
        if trimmed == ".*" || pattern == "^.*$" {
            return Err(OracleError::new_for_cli(
                ErrorCode::Normalization,
                "an unscoped ignored line wildcard is not allowed",
            ));
        }
        if !valid_line_pattern(pattern) {
            return Err(OracleError::new_for_cli(
                ErrorCode::Normalization,
                "ignored line pattern is malformed or exceeds its complexity bound",
            ));
        }
    }
    Ok(())
}

fn known_policy(id: &str) -> bool {
    matches!(
        id,
        "NORM-STRUCTURE-001"
            | "NORM-JMX-001"
            | "NORM-JTL-001"
            | "NORM-TIME-001"
            | "NORM-CLI-001"
            | "NORM-CONFIG-001"
            | "NORM-ENV-001"
            | "NORM-REPORT-001"
            | "NORM-EXTERNAL-001"
            | "NORM-SECURITY-001"
    )
}

fn has_policy(policies: &BTreeSet<String>, id: &str) -> bool {
    policies.contains(id)
}

fn allowed_ignored_field(field: &str, policies: &BTreeSet<String>) -> bool {
    let field = canonical_field_path(field);
    let lower = field.to_ascii_lowercase();
    if lower == "xml_lexical_whitespace" || lower.contains("label") {
        return false;
    }
    if lower == "debug_response.dynamic_lines" {
        return has_policy(policies, "NORM-ENV-001") || has_policy(policies, "NORM-TIME-001");
    }
    if matches!(
        lower.as_str(),
        "sample.t"
            | "sample.it"
            | "sample.lt"
            | "sample.ct"
            | "sample.ts"
            | "rows[*].elapsed"
            | "rows[*].latency"
            | "rows[*].connect"
            | "rows[*].idletime"
            | "rows[*].timestamp"
    ) {
        return has_policy(policies, "NORM-TIME-001");
    }
    if matches!(
        lower.as_str(),
        "sample.by" | "sample.sby" | "rows[*].bytes" | "rows[*].sentbytes"
    ) {
        return has_policy(policies, "NORM-JTL-001") && has_policy(policies, "NORM-TIME-001");
    }
    if matches!(
        lower.as_str(),
        "sample.hn"
            | "sample.host"
            | "sample.hostname"
            | "rows[*].host"
            | "rows[*].hostname"
            | "rows[*].port"
            | "run.hostname"
            | "run.ephemeral_root"
            | "runtime.hostname"
            | "runtime.display_id"
            | "runtime.ephemeral_root"
            | "runtime.target_image_id"
    ) {
        return has_policy(policies, "NORM-ENV-001");
    }
    false
}

fn expected_projection_format(expected: &Value) -> Result<CompareFormat> {
    let format = expected
        .get("format")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::UnsupportedFormat,
                "expected projection must declare a string format",
            )
        })?;
    CompareFormat::from_hint(format).ok_or_else(|| {
        OracleError::new_for_cli(
            ErrorCode::UnsupportedFormat,
            format!("expected projection format '{format}' is unsupported"),
        )
    })
}

/// Validate every descriptor which can contribute normalization, regardless
/// of whether the optional top-level `normalization` object exists.  Expected
/// projections are untrusted JSON; a failed `and_then(as_array)` here would
/// turn a malformed descriptor into an omitted assertion.
fn validate_expected_normalization_descriptors(
    expected: &Value,
    limits: &CompareLimits,
) -> Result<()> {
    // Neutral JSON is an open projection envelope.  Its `rows`/`samples`
    // keys, when present, are ordinary user data rather than JTL descriptor
    // namespaces.  The direct helper tests omit `format`, which deliberately
    // keeps the strict descriptor audit enabled for untyped inputs.
    let validates_jtl_descriptors = !matches!(
        expected
            .get("format")
            .and_then(Value::as_str)
            .and_then(CompareFormat::from_hint),
        Some(CompareFormat::Json | CompareFormat::JmxSemantic)
    );
    if let Some(value) = expected.get("normalization") {
        let normalization = value.as_object().ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "expected projection normalization must be an object",
            )
        })?;
        for key in normalization.keys() {
            if !matches!(key.as_str(), "ignored_fields" | "reason") {
                return Err(OracleError::new_for_cli(
                    ErrorCode::UnsupportedFormat,
                    format!("unsupported expected normalization field '{key}'"),
                ));
            }
        }
        if let Some(fields) = normalization.get("ignored_fields") {
            validate_string_array(fields, "expected normalization ignored_fields")?;
        }
        if let Some(reason) = normalization.get("reason")
            && !reason.is_string()
        {
            return Err(OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "expected normalization reason must be a string",
            ));
        }
    }
    if validates_jtl_descriptors && let Some(value) = expected.get("rows") {
        let rows = value.as_array().ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "expected CSV rows must be an array",
            )
        })?;
        if rows.len() > limits.max_events {
            return Err(OracleError::new_for_cli(
                ErrorCode::OutputLimit,
                "expected CSV rows exceed the event bound",
            ));
        }
        for row in rows {
            let row = row.as_object().ok_or_else(|| {
                OracleError::new_for_cli(
                    ErrorCode::ManifestSchema,
                    "expected CSV row must be an object",
                )
            })?;
            if let Some(fields) = row.get("ignored_fields") {
                validate_string_array(fields, "expected CSV row ignored_fields")?;
            }
        }
    }
    if validates_jtl_descriptors && let Some(value) = expected.get("samples") {
        let samples = value.as_array().ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "expected XML samples must be an array",
            )
        })?;
        if samples.len() > limits.max_events {
            return Err(OracleError::new_for_cli(
                ErrorCode::OutputLimit,
                "expected XML samples exceed the event bound",
            ));
        }
        for sample in samples {
            validate_expected_xml_sample(sample, limits, 0)?;
        }
    }
    if validates_jtl_descriptors && let Some(contract) = expected.get("sample_contract") {
        validate_expected_xml_sample(contract, limits, 0)?;
    }
    Ok(())
}

fn load_expected_normalization(expected: &Value, options: &mut CompareOptions) -> Result<()> {
    // Validate first and mutate only after every descriptor has been checked.
    // This makes an error atomic for callers that reuse their options value.
    validate_expected_normalization_descriptors(expected, &options.limits)?;
    let validates_jtl_descriptors = !matches!(
        expected
            .get("format")
            .and_then(Value::as_str)
            .and_then(CompareFormat::from_hint),
        Some(CompareFormat::Json | CompareFormat::JmxSemantic)
    );

    let mut ignored_fields = BTreeSet::new();
    let mut ignored_line_patterns = Vec::new();
    if let Some(normalization) = expected.get("normalization") {
        let normalization = normalization.as_object().ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "expected projection normalization must be an object",
            )
        })?;
        if let Some(fields) = normalization.get("ignored_fields") {
            let fields = fields.as_array().ok_or_else(|| {
                OracleError::new_for_cli(
                    ErrorCode::ManifestSchema,
                    "expected normalization ignored_fields must be an array",
                )
            })?;
            for field in fields {
                let field = field.as_str().ok_or_else(|| {
                    OracleError::new_for_cli(
                        ErrorCode::ManifestSchema,
                        "expected normalization ignored field must be a string",
                    )
                })?;
                ignored_fields.insert(field.to_owned());
            }
        }
    }
    if validates_jtl_descriptors && let Some(rows) = expected.get("rows") {
        let rows = rows.as_array().ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "expected CSV rows must be an array",
            )
        })?;
        for row in rows {
            let row = row.as_object().ok_or_else(|| {
                OracleError::new_for_cli(
                    ErrorCode::ManifestSchema,
                    "expected CSV row must be an object",
                )
            })?;
            if let Some(fields) = row.get("ignored_fields") {
                let fields = fields.as_array().ok_or_else(|| {
                    OracleError::new_for_cli(
                        ErrorCode::ManifestSchema,
                        "expected CSV row ignored_fields must be an array",
                    )
                })?;
                for field in fields {
                    let field = field.as_str().ok_or_else(|| {
                        OracleError::new_for_cli(
                            ErrorCode::ManifestSchema,
                            "expected CSV row ignored field must be a string",
                        )
                    })?;
                    ignored_fields.insert(format!("rows[*].{field}"));
                }
            }
        }
    }
    let mut collect_xml_descriptors = |sample: &Value| -> Result<()> {
        let sample = sample.as_object().ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "expected XML normalization descriptor must be an object",
            )
        })?;
        if let Some(patterns) = sample
            .get("debug_response_projection")
            .and_then(Value::as_object)
            .and_then(|projection| projection.get("ignored_line_patterns"))
        {
            let patterns = patterns.as_array().ok_or_else(|| {
                OracleError::new_for_cli(
                    ErrorCode::ManifestSchema,
                    "expected debug ignored_line_patterns must be an array",
                )
            })?;
            for pattern in patterns {
                let pattern = pattern.as_str().ok_or_else(|| {
                    OracleError::new_for_cli(
                        ErrorCode::ManifestSchema,
                        "expected debug ignored line pattern must be a string",
                    )
                })?;
                ignored_line_patterns.push(pattern.to_owned());
            }
        }
        if let Some(attributes) = sample.get("ignored_attributes") {
            let attributes = attributes.as_array().ok_or_else(|| {
                OracleError::new_for_cli(
                    ErrorCode::ManifestSchema,
                    "expected XML ignored_attributes must be an array",
                )
            })?;
            for attribute in attributes {
                let attribute = attribute.as_str().ok_or_else(|| {
                    OracleError::new_for_cli(
                        ErrorCode::ManifestSchema,
                        "expected XML ignored attribute must be a string",
                    )
                })?;
                ignored_fields.insert(format!("sample.{attribute}"));
            }
        }
        Ok(())
    };
    if validates_jtl_descriptors && let Some(samples) = expected.get("samples") {
        let samples = samples.as_array().ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "expected XML samples must be an array",
            )
        })?;
        for sample in samples {
            collect_xml_descriptors(sample)?;
        }
    }
    if validates_jtl_descriptors && let Some(contract) = expected.get("sample_contract") {
        collect_xml_descriptors(contract)?;
    }
    options.ignored_fields.extend(ignored_fields);
    options.ignored_line_patterns.extend(ignored_line_patterns);
    Ok(())
}

fn parse_input(
    path: &Path,
    limits: &CompareLimits,
    hint: Option<CompareFormat>,
    csv_header: Option<&[String]>,
) -> Result<ParsedInput> {
    limits.validate()?;
    let bytes = read_bounded(path, limits.max_input_bytes)?;
    let text = std::str::from_utf8(&bytes).map_err(|error| {
        OracleError::new_for_cli(
            ErrorCode::JtlParse,
            format!("artifact '{}' is not UTF-8: {error}", path.display()),
        )
    })?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let format = hint.or_else(|| detect_format(path, text)).ok_or_else(|| {
        OracleError::new_for_cli(
            ErrorCode::UnsupportedFormat,
            format!("cannot detect JTL format for '{}'", path.display()),
        )
    })?;
    let document = match format {
        CompareFormat::Csv => parse_csv(text, limits, csv_header)?,
        CompareFormat::Xml => parse_xml(text, limits)?,
        CompareFormat::Json => parse_neutral_json(text, limits, path)?,
        CompareFormat::JmxSemantic => {
            return Err(OracleError::new_for_cli(
                ErrorCode::UnsupportedFormat,
                "JMX semantic inputs use the jmx-semantic comparator route",
            ));
        }
    };
    let size_bytes = bytes.len() as u64;
    let summary = ArtifactSummary {
        path: path.to_string_lossy().into_owned(),
        format,
        size_bytes,
        event_count: document.events.len(),
    };
    Ok(ParsedInput { document, summary })
}

fn detect_format(path: &Path, text: &str) -> Option<CompareFormat> {
    if let Some(format) = CompareFormat::from_path(path) {
        return Some(format);
    }
    let first = text.chars().find(|character| !character.is_whitespace())?;
    if first == '<' {
        Some(CompareFormat::Xml)
    } else if first == '{' || first == '[' {
        Some(CompareFormat::Json)
    } else {
        Some(CompareFormat::Csv)
    }
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    reject_symlink_components(path, "comparison input")?;
    let file = File::open(path).map_err(|error| {
        OracleError::new_for_cli(
            ErrorCode::File,
            format!("open comparison input '{}': {error}", path.display()),
        )
    })?;
    reject_symlink_components(path, "comparison input")?;
    let handle_metadata = file.metadata().map_err(|error| {
        OracleError::new_for_cli(
            ErrorCode::File,
            format!("stat opened comparison input '{}': {error}", path.display()),
        )
    })?;
    let path_metadata = fs::metadata(path).map_err(|error| {
        OracleError::new_for_cli(
            ErrorCode::File,
            format!("stat comparison input '{}': {error}", path.display()),
        )
    })?;
    if !same_file_identity(&handle_metadata, &path_metadata) {
        return Err(OracleError::new_for_cli(
            ErrorCode::PathPolicy,
            format!(
                "comparison input '{}' changed while opening",
                path.display()
            ),
        ));
    }
    read_bounded_handle(file, path, maximum)
}

fn read_bounded_handle(file: File, path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let metadata = file.metadata().map_err(|error| {
        OracleError::new_for_cli(
            ErrorCode::File,
            format!("stat opened comparison input '{}': {error}", path.display()),
        )
    })?;
    if !metadata.is_file() {
        return Err(OracleError::new_for_cli(
            ErrorCode::File,
            format!(
                "comparison input is not a regular file '{}',",
                path.display()
            ),
        ));
    }
    let maximum_plus_one = maximum.checked_add(1).ok_or_else(|| {
        OracleError::new_for_cli(
            ErrorCode::Configuration,
            "comparison input bound is too large",
        )
    })?;
    let capacity = usize::try_from(metadata.len().min(maximum_plus_one)).map_err(|_| {
        OracleError::new_for_cli(
            ErrorCode::OutputLimit,
            "comparison input bound cannot be represented on this platform",
        )
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    let mut limited = file.take(maximum_plus_one);
    limited.read_to_end(&mut bytes).map_err(|error| {
        OracleError::new_for_cli(
            ErrorCode::File,
            format!("read comparison input '{}': {error}", path.display()),
        )
    })?;
    if bytes.len() as u64 > maximum {
        return Err(OracleError::new_for_cli(
            ErrorCode::OutputLimit,
            format!(
                "comparison input '{}' grew beyond {maximum} bytes",
                path.display()
            ),
        ));
    }
    Ok(bytes)
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

fn read_json_bounded_contained(
    root: &Path,
    path: &Path,
    limits: &CompareLimits,
) -> Result<(Value, u64)> {
    let canonical = canonical_contained_expected_file(root, path)?;
    // Re-check the path immediately around opening and bind the comparison to
    // the opened handle's metadata.  A later rename cannot redirect the bytes
    // that are parsed, and a pre-existing symlink is rejected before opening.
    reject_symlink_components(&canonical, "expected projection")?;
    let file = File::open(&canonical).map_err(|error| {
        OracleError::new_for_cli(
            ErrorCode::File,
            format!(
                "open expected projection '{}': {error}",
                canonical.display()
            ),
        )
    })?;
    reject_symlink_components(&canonical, "expected projection")?;
    let handle_metadata = file.metadata().map_err(|error| {
        OracleError::new_for_cli(
            ErrorCode::File,
            format!(
                "stat opened expected projection '{}': {error}",
                canonical.display()
            ),
        )
    })?;
    if !handle_metadata.is_file() {
        return Err(OracleError::new_for_cli(
            ErrorCode::File,
            format!(
                "expected projection is not a regular file '{}',",
                canonical.display()
            ),
        ));
    }
    let path_metadata = fs::metadata(&canonical).map_err(|error| {
        OracleError::new_for_cli(
            ErrorCode::File,
            format!(
                "stat expected projection '{}': {error}",
                canonical.display()
            ),
        )
    })?;
    if !same_file_identity(&handle_metadata, &path_metadata) {
        return Err(OracleError::new_for_cli(
            ErrorCode::PathPolicy,
            format!(
                "expected projection '{}' changed while opening",
                canonical.display()
            ),
        ));
    }
    let bytes = read_bounded_handle(
        file,
        &canonical,
        limits.max_input_bytes.min(DEFAULT_MAX_INPUT_BYTES),
    )?;
    parse_bounded_json(&canonical, bytes, limits)
}

fn parse_bounded_json(path: &Path, bytes: Vec<u8>, limits: &CompareLimits) -> Result<(Value, u64)> {
    let text = std::str::from_utf8(&bytes).map_err(|error| {
        OracleError::new_for_cli(
            ErrorCode::ManifestJson,
            format!(
                "expected projection '{}' is not UTF-8: {error}",
                path.display()
            ),
        )
    })?;
    validate_json_lexical_limits(text, limits)?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|error| {
        OracleError::new_for_cli(
            ErrorCode::ManifestJson,
            format!("parse expected projection '{}': {error}", path.display()),
        )
    })?;
    let mut nodes = 0_usize;
    validate_json_limits(&value, limits, 0, &mut nodes)?;
    Ok((value, bytes.len() as u64))
}

fn parse_neutral_json(text: &str, limits: &CompareLimits, path: &Path) -> Result<NeutralDocument> {
    validate_json_lexical_limits(text, limits)?;
    let projection: Value = serde_json::from_str(text).map_err(|error| {
        OracleError::new_for_cli(
            ErrorCode::JtlParse,
            format!("parse neutral JSON '{}': {error}", path.display()),
        )
    })?;
    let declared_format = projection
        .get("format")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::UnsupportedFormat,
                "neutral JSON input must declare format neutral-json",
            )
        })?;
    if declared_format.eq_ignore_ascii_case("jmx-semantic") {
        return Err(OracleError::new_for_cli(
            ErrorCode::UnsupportedFormat,
            "jmx-semantic projections are not supported by the JTL comparator",
        ));
    }
    if !declared_format.eq_ignore_ascii_case("neutral-json") {
        return Err(OracleError::new_for_cli(
            ErrorCode::UnsupportedFormat,
            format!("JSON format '{declared_format}' is not supported by the JTL comparator"),
        ));
    }
    let mut nodes = 0_usize;
    validate_json_limits(&projection, limits, 0, &mut nodes)?;
    let events = if let Some(value) = projection.get("events") {
        let events = value.as_array().ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::ManifestJson,
                "neutral JSON events must be an array",
            )
        })?;
        if events.len() > limits.max_events {
            return Err(OracleError::new_for_cli(
                ErrorCode::OutputLimit,
                format!("neutral JSON event count exceeds {}", limits.max_events),
            ));
        }
        events
            .iter()
            .enumerate()
            .map(|(position, value)| neutral_event_from_json(position, value))
            .collect::<Result<Vec<_>>>()?
    } else {
        Vec::new()
    };
    Ok(NeutralDocument {
        format: CompareFormat::Json,
        root: None,
        header: None,
        events,
        projection,
    })
}

fn validate_json_lexical_limits(text: &str, limits: &CompareLimits) -> Result<()> {
    let bytes = text.as_bytes();
    let mut depth = 0_usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut string_start = 0_usize;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if in_string {
            if index.saturating_sub(string_start) > limits.max_text_bytes {
                return Err(OracleError::new_for_cli(
                    ErrorCode::OutputLimit,
                    "neutral JSON string exceeds the configured text bound",
                ));
            }
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => {
                in_string = true;
                string_start = index;
            }
            b'{' | b'[' => {
                depth = depth.checked_add(1).ok_or_else(|| {
                    OracleError::new_for_cli(
                        ErrorCode::OutputLimit,
                        "neutral JSON nesting depth overflowed",
                    )
                })?;
                if depth > limits.max_depth {
                    return Err(OracleError::new_for_cli(
                        ErrorCode::OutputLimit,
                        format!("neutral JSON nesting exceeds {}", limits.max_depth),
                    ));
                }
            }
            b'}' | b']' => {
                depth = depth.checked_sub(1).ok_or_else(|| {
                    OracleError::new_for_cli(
                        ErrorCode::ManifestJson,
                        "neutral JSON closes more containers than it opens",
                    )
                })?;
            }
            _ => {}
        }
    }
    if in_string {
        return Err(OracleError::new_for_cli(
            ErrorCode::ManifestJson,
            "neutral JSON contains an unterminated string",
        ));
    }
    if depth != 0 {
        return Err(OracleError::new_for_cli(
            ErrorCode::ManifestJson,
            "neutral JSON contains an unterminated container",
        ));
    }
    Ok(())
}

fn validate_json_limits(
    value: &Value,
    limits: &CompareLimits,
    depth: usize,
    nodes: &mut usize,
) -> Result<()> {
    if depth > limits.max_depth {
        return Err(OracleError::new_for_cli(
            ErrorCode::OutputLimit,
            format!("neutral JSON nesting exceeds {}", limits.max_depth),
        ));
    }
    *nodes = nodes.checked_add(1).ok_or_else(|| {
        OracleError::new_for_cli(ErrorCode::OutputLimit, "neutral JSON node count overflowed")
    })?;
    let max_nodes = limits
        .max_events
        .checked_mul(MAX_JSON_NODES_PER_EVENT)
        .ok_or_else(|| {
            OracleError::new_for_cli(ErrorCode::OutputLimit, "neutral JSON node bound overflowed")
        })?
        .max(MAX_JSON_NODES_PER_EVENT);
    if *nodes > max_nodes {
        return Err(OracleError::new_for_cli(
            ErrorCode::OutputLimit,
            format!("neutral JSON node count exceeds {max_nodes}"),
        ));
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
                    return Err(OracleError::new_for_cli(
                        ErrorCode::OutputLimit,
                        format!(
                            "neutral JSON object key exceeds {} bytes",
                            limits.max_text_bytes
                        ),
                    ));
                }
                validate_json_limits(child, limits, depth + 1, nodes)?;
            }
        }
        Value::String(text) => {
            if text.len() > limits.max_text_bytes {
                return Err(OracleError::new_for_cli(
                    ErrorCode::OutputLimit,
                    format!(
                        "neutral JSON text value exceeds {} bytes",
                        limits.max_text_bytes
                    ),
                ));
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    Ok(())
}

fn neutral_event_from_json(position: usize, value: &Value) -> Result<NeutralEvent> {
    let object = value.as_object().ok_or_else(|| {
        OracleError::new_for_cli(
            ErrorCode::ManifestJson,
            "neutral JSON event must be an object",
        )
    })?;
    let element = match object.get("element") {
        None => "event".to_owned(),
        Some(value) => value
            .as_str()
            .ok_or_else(|| {
                OracleError::new_for_cli(
                    ErrorCode::ManifestJson,
                    "neutral JSON event element must be a string",
                )
            })?
            .to_owned(),
    };
    let attributes = string_map(object.get("attributes"), "neutral JSON event attributes")?;
    let sections = string_map(object.get("sections"), "neutral JSON event sections")?;
    let text = match object.get("text") {
        None => String::new(),
        Some(value) => value
            .as_str()
            .ok_or_else(|| {
                OracleError::new_for_cli(
                    ErrorCode::ManifestJson,
                    "neutral JSON event text must be a string",
                )
            })?
            .to_owned(),
    };
    Ok(NeutralEvent {
        position,
        element,
        attributes,
        sections,
        text,
        assertions: Vec::new(),
        children: Vec::new(),
        child_events: Vec::new(),
    })
}

fn string_map(value: Option<&Value>, label: &str) -> Result<BTreeMap<String, String>> {
    let Some(value) = value else {
        return Ok(BTreeMap::new());
    };
    let map = value.as_object().ok_or_else(|| {
        OracleError::new_for_cli(
            ErrorCode::ManifestJson,
            format!("{label} must be an object"),
        )
    })?;
    let mut result = BTreeMap::new();
    for (key, value) in map {
        let value = value.as_str().ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::ManifestJson,
                format!("{label} values must be strings"),
            )
        })?;
        result.insert(key.clone(), value.to_owned());
    }
    Ok(result)
}

fn parse_csv(
    text: &str,
    limits: &CompareLimits,
    header_override: Option<&[String]>,
) -> Result<NeutralDocument> {
    let delimiter = detect_delimiter(text);
    let line_ending = detect_line_ending(text);
    let record_line_endings = detect_record_line_endings(text);
    let final_terminator = final_record_terminator(text);
    let mut records = CsvRecordReader::new(text, delimiter, limits.max_text_bytes);
    // With print_field_names=false the configured header is metadata, not a
    // record in the input.  Do not consume the first data row as though it
    // were a physical header (and permit an empty no-header artifact).
    let header_record = if header_override.is_some() {
        None
    } else {
        Some(records.next_record()?.ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::JtlParse,
                "CSV JTL is empty; a header row is required",
            )
        })?)
    };
    let header = header_override.map_or_else(
        || {
            header_record
                .as_deref()
                .unwrap_or_default()
                .iter()
                .map(|cell| cell.value.clone())
                .collect()
        },
        |header| header.to_vec(),
    );
    if header.len() > limits.max_csv_columns {
        return Err(OracleError::new_for_cli(
            ErrorCode::OutputLimit,
            format!("CSV column count exceeds {}", limits.max_csv_columns),
        ));
    }
    let header_serialized: Vec<String> = if header_override.is_some() {
        Vec::new()
    } else {
        header_record
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(|cell| cell.serialized.clone())
            .collect()
    };
    let header_line = header_serialized.join(&char::from(delimiter).to_string());
    let writer_wire = json!({
        "header_line": header_line,
        "sample_variable_headers_quoted": header_record
            .as_deref()
            .unwrap_or_default()
            .iter()
            .any(|cell| cell.serialized.starts_with('"')),
        "delimiter": delimiter_name(delimiter),
        "line_ending": line_ending,
        "record_line_endings": record_line_endings,
        "final_terminator": final_terminator,
        "print_field_names": header_override.is_none(),
    });
    if header.is_empty() || header.iter().any(String::is_empty) {
        return Err(OracleError::new_for_cli(
            ErrorCode::JtlParse,
            "CSV JTL header contains an empty column",
        ));
    }
    let mut seen = BTreeSet::new();
    for column in &header {
        if !seen.insert(column.clone()) {
            return Err(OracleError::new_for_cli(
                ErrorCode::JtlParse,
                format!("CSV JTL header repeats column '{column}'"),
            ));
        }
    }
    let mut events = Vec::new();
    let mut rows = Vec::new();
    while records.has_more() {
        if events.len() >= limits.max_events {
            return Err(OracleError::new_for_cli(
                ErrorCode::OutputLimit,
                format!("CSV JTL event count exceeds {}", limits.max_events),
            ));
        }
        let row_index = events.len();
        let record = records.next_record()?.ok_or_else(|| {
            OracleError::new_for_cli(ErrorCode::JtlParse, "CSV record parser made no progress")
        })?;
        if record.len() > limits.max_csv_columns {
            return Err(OracleError::new_for_cli(
                ErrorCode::OutputLimit,
                format!("CSV column count exceeds {}", limits.max_csv_columns),
            ));
        }
        if record.len() != header.len() {
            return Err(OracleError::new_for_cli(
                ErrorCode::JtlParse,
                format!(
                    "CSV JTL row {} has {} fields; header has {}",
                    row_index,
                    record.len(),
                    header.len()
                ),
            ));
        }
        let mut fields = Map::new();
        let mut serialized_fields = Map::new();
        let mut attributes = BTreeMap::new();
        for (column, cell) in header.iter().zip(record) {
            fields.insert(column.clone(), Value::String(cell.value.clone()));
            serialized_fields.insert(column.clone(), Value::String(cell.serialized.clone()));
            attributes.insert(column.clone(), cell.value.clone());
        }
        let event = NeutralEvent {
            position: row_index,
            element: "row".to_owned(),
            attributes,
            sections: BTreeMap::new(),
            text: String::new(),
            assertions: Vec::new(),
            children: Vec::new(),
            child_events: Vec::new(),
        };
        events.push(event);
        rows.push(json!({
            "position": row_index,
            "fields": Value::Object(fields),
            "serialized_fields": Value::Object(serialized_fields),
        }));
    }
    let projection = json!({
        "format": "jtl-csv",
        "delimiter": delimiter_name(delimiter),
        "line_ending": line_ending,
        "record_line_endings": record_line_endings,
        "final_terminator": final_terminator,
        "header": header,
        "header_serialized": header_serialized,
        "writer_wire": writer_wire,
        "sample_count": rows.len(),
        "rows": rows,
    });
    Ok(NeutralDocument {
        format: CompareFormat::Csv,
        root: None,
        header: Some(header.clone()),
        events,
        projection,
    })
}

#[derive(Clone, Debug)]
struct CsvCell {
    value: String,
    serialized: String,
}

struct CsvRecordReader<'a> {
    characters: std::iter::Peekable<std::str::Chars<'a>>,
    delimiter: char,
    max_text_bytes: usize,
    record_bytes: usize,
}

impl<'a> CsvRecordReader<'a> {
    fn new(text: &'a str, delimiter: u8, max_text_bytes: usize) -> Self {
        Self {
            characters: text.chars().peekable(),
            delimiter: char::from(delimiter),
            max_text_bytes,
            record_bytes: 0,
        }
    }

    fn has_more(&mut self) -> bool {
        self.characters.peek().is_some()
    }

    fn next_record(&mut self) -> Result<Option<Vec<CsvCell>>> {
        if !self.has_more() {
            return Ok(None);
        }
        let mut record = Vec::new();
        let mut field = String::new();
        let mut serialized = String::new();
        let mut quoted = false;
        let mut after_quote = false;
        while let Some(character) = self.characters.next() {
            self.record_bytes = self
                .record_bytes
                .checked_add(character.len_utf8())
                .ok_or_else(|| {
                    OracleError::new_for_cli(
                        ErrorCode::OutputLimit,
                        "CSV record byte count overflowed",
                    )
                })?;
            self.check_record_bound()?;
            if quoted {
                if character == '"' {
                    if self.characters.peek() == Some(&'"') {
                        field.push('"');
                        serialized.push_str("\"\"");
                        self.characters.next();
                        self.record_bytes = self.record_bytes.checked_add(1).ok_or_else(|| {
                            OracleError::new_for_cli(
                                ErrorCode::OutputLimit,
                                "CSV record byte count overflowed",
                            )
                        })?;
                        self.check_record_bound()?;
                    } else {
                        quoted = false;
                        after_quote = true;
                        serialized.push('"');
                    }
                } else {
                    field.push(character);
                    serialized.push(character);
                }
                self.check_field_bound(&field, &serialized)?;
                continue;
            }
            if after_quote {
                match character {
                    '\r' => {
                        if self.characters.peek() == Some(&'\n') {
                            self.characters.next();
                            self.record_bytes =
                                self.record_bytes.checked_add(1).ok_or_else(|| {
                                    OracleError::new_for_cli(
                                        ErrorCode::OutputLimit,
                                        "CSV record byte count overflowed",
                                    )
                                })?;
                            self.check_record_bound()?;
                        }
                        finish_csv_field(&mut record, &mut field, &mut serialized);
                        self.record_bytes = 0;
                        return Ok(Some(record));
                    }
                    '\n' => {
                        finish_csv_field(&mut record, &mut field, &mut serialized);
                        self.record_bytes = 0;
                        return Ok(Some(record));
                    }
                    value if value == self.delimiter => {
                        finish_csv_field(&mut record, &mut field, &mut serialized);
                        after_quote = false;
                    }
                    _ => {
                        return Err(OracleError::new_for_cli(
                            ErrorCode::JtlParse,
                            "CSV has characters after a closing quote",
                        ));
                    }
                }
                self.check_field_bound(&field, &serialized)?;
                continue;
            }
            match character {
                '"' if field.is_empty() => {
                    quoted = true;
                    serialized.push('"');
                }
                value if value == self.delimiter => {
                    finish_csv_field(&mut record, &mut field, &mut serialized);
                }
                '\n' => {
                    finish_csv_field(&mut record, &mut field, &mut serialized);
                    self.record_bytes = 0;
                    return Ok(Some(record));
                }
                '\r' => {
                    if self.characters.peek() == Some(&'\n') {
                        self.characters.next();
                        self.record_bytes = self.record_bytes.checked_add(1).ok_or_else(|| {
                            OracleError::new_for_cli(
                                ErrorCode::OutputLimit,
                                "CSV record byte count overflowed",
                            )
                        })?;
                        self.check_record_bound()?;
                    }
                    finish_csv_field(&mut record, &mut field, &mut serialized);
                    self.record_bytes = 0;
                    return Ok(Some(record));
                }
                value => {
                    field.push(value);
                    serialized.push(value);
                }
            }
            self.check_field_bound(&field, &serialized)?;
        }
        if quoted {
            return Err(OracleError::new_for_cli(
                ErrorCode::JtlParse,
                "CSV has an unterminated quoted field",
            ));
        }
        if after_quote || !field.is_empty() || !record.is_empty() {
            finish_csv_field(&mut record, &mut field, &mut serialized);
            self.record_bytes = 0;
            return Ok(Some(record));
        }
        Ok(None)
    }

    fn check_field_bound(&self, field: &str, serialized: &str) -> Result<()> {
        if field.len() > self.max_text_bytes || serialized.len() > self.max_text_bytes {
            return Err(OracleError::new_for_cli(
                ErrorCode::OutputLimit,
                "CSV field exceeds the configured text bound",
            ));
        }
        Ok(())
    }

    fn check_record_bound(&self) -> Result<()> {
        if self.record_bytes > self.max_text_bytes {
            return Err(OracleError::new_for_cli(
                ErrorCode::OutputLimit,
                "CSV record exceeds the configured line-byte bound",
            ));
        }
        Ok(())
    }
}

fn detect_delimiter(text: &str) -> u8 {
    let mut scores = [0_usize; 256];
    let mut quoted = false;
    let bytes = text.as_bytes();
    let mut index = 0_usize;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'"' {
            if quoted && bytes.get(index + 1) == Some(&b'"') {
                index += 2;
                continue;
            }
            quoted = !quoted;
        } else if !quoted
            && (byte == b'\t'
                || ((0x21..=0x7e).contains(&byte)
                    && !byte.is_ascii_alphanumeric()
                    && byte != b'_'
                    && byte != b'"'))
        {
            scores[byte as usize] += 1;
        }
        if !quoted && matches!(byte, b'\r' | b'\n') {
            break;
        }
        index += 1;
    }
    let mut candidates = Vec::with_capacity(96);
    candidates.extend(*b",;\t");
    candidates.extend((0x21..=0x7e).filter(|byte| {
        !matches!(*byte, b',' | b';' | b'"') && !byte.is_ascii_alphanumeric() && *byte != b'_'
    }));
    let mut best = b',';
    let mut best_score = 0_usize;
    for candidate in candidates {
        let score = scores[candidate as usize];
        // Candidate order intentionally breaks ties in favor of the common
        // comma/semicolon/tab forms, while still accepting any printable
        // delimiter that is actually present in the record.
        if score > best_score {
            best = candidate;
            best_score = score;
        }
    }
    best
}

fn delimiter_name(delimiter: u8) -> String {
    match delimiter {
        b'\t' => "TAB".to_owned(),
        value => char::from(value).to_string(),
    }
}

fn detect_line_ending(text: &str) -> &'static str {
    let mut saw_lf = false;
    let mut saw_crlf = false;
    let mut saw_cr = false;
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'\r' if bytes.get(index + 1) == Some(&b'\n') => {
                saw_crlf = true;
                index += 2;
                continue;
            }
            b'\r' => saw_cr = true,
            b'\n' => saw_lf = true,
            _ => {}
        }
        index += 1;
    }
    match (saw_lf, saw_crlf, saw_cr) {
        (false, false, false) => "NONE",
        (true, false, false) => "LF",
        (false, true, false) => "CRLF",
        (false, false, true) => "CR",
        _ => "MIXED",
    }
}

fn detect_record_line_endings(text: &str) -> Vec<&'static str> {
    let bytes = text.as_bytes();
    let mut endings = Vec::new();
    let mut quoted = false;
    let mut index = 0_usize;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => {
                if quoted && bytes.get(index + 1) == Some(&b'"') {
                    index += 2;
                    continue;
                }
                quoted = !quoted;
                index += 1;
            }
            b'\r' if !quoted => {
                if bytes.get(index + 1) == Some(&b'\n') {
                    endings.push("CRLF");
                    index += 2;
                } else {
                    endings.push("CR");
                    index += 1;
                }
            }
            b'\n' if !quoted => {
                endings.push("LF");
                index += 1;
            }
            _ => index += 1,
        }
    }
    endings
}

fn final_record_terminator(text: &str) -> &'static str {
    let bytes = text.as_bytes();
    if bytes.ends_with(b"\r\n") {
        "CRLF"
    } else if bytes.ends_with(b"\n") {
        "LF"
    } else if bytes.ends_with(b"\r") {
        "CR"
    } else {
        "NONE"
    }
}

fn finish_csv_field(record: &mut Vec<CsvCell>, field: &mut String, serialized: &mut String) {
    record.push(CsvCell {
        value: std::mem::take(field),
        serialized: std::mem::take(serialized),
    });
}

fn parse_xml(text: &str, limits: &CompareLimits) -> Result<NeutralDocument> {
    let mut parser = XmlParser::new(text, limits);
    let root = parser.parse_document()?;
    if root.name != "testResults" {
        return Err(OracleError::new_for_cli(
            ErrorCode::JtlParse,
            format!("JTL XML root must be testResults, got '{}'", root.name),
        ));
    }
    let root_metadata = NeutralRoot {
        element: root.name.clone(),
        attributes: root.attributes.clone(),
        text: root.text.clone(),
        child_events: root
            .children
            .iter()
            .enumerate()
            .map(|(position, child)| xml_child_event(child, position, limits, 1))
            .collect::<Result<Vec<_>>>()?,
    };
    let mut events = Vec::new();
    let mut samples = Vec::new();
    let mut assertion_count = 0_usize;
    for child in &root.children {
        if child.name == "sample" || child.name == "httpSample" {
            if events.len() >= limits.max_events {
                return Err(OracleError::new_for_cli(
                    ErrorCode::OutputLimit,
                    format!("XML JTL event count exceeds {}", limits.max_events),
                ));
            }
            let event = xml_event(child, events.len(), limits, 0, &mut assertion_count)?;
            samples.push(xml_event_value(&event));
            events.push(event);
        } else if !child.is_ignorable() {
            return Err(unsupported_xml(format!(
                "unexpected XML root child '{}'",
                child.name
            )));
        }
    }
    let root_value = root_projection(&root_metadata);
    let projection = json!({
        "format": "jtl-xml",
        "root": root_value,
        "sample_count": samples.len(),
        "samples": samples,
    });
    Ok(NeutralDocument {
        format: CompareFormat::Xml,
        root: Some(root_metadata),
        header: None,
        events,
        projection,
    })
}

fn root_projection(root: &NeutralRoot) -> Value {
    let mut map = Map::new();
    map.insert("element".to_owned(), Value::String(root.element.clone()));
    for (key, value) in &root.attributes {
        map.insert(key.clone(), Value::String(value.clone()));
    }
    if !root.text.trim().is_empty() {
        map.insert("text".to_owned(), Value::String(root.text.clone()));
    }
    Value::Object(map)
}

fn xml_event(
    node: &XmlNode,
    position: usize,
    limits: &CompareLimits,
    depth: usize,
    assertion_count: &mut usize,
) -> Result<NeutralEvent> {
    if depth > limits.max_depth {
        return Err(OracleError::new_for_cli(
            ErrorCode::OutputLimit,
            format!("XML JTL nesting exceeds {}", limits.max_depth),
        ));
    }
    let mut sections = BTreeMap::new();
    let mut assertions = Vec::new();
    let mut children = Vec::new();
    let mut child_position = 0_usize;
    for child in &node.children {
        if child.name == "assertionResult" {
            *assertion_count = assertion_count.checked_add(1).ok_or_else(|| {
                OracleError::new_for_cli(
                    ErrorCode::OutputLimit,
                    "XML assertion result count overflowed",
                )
            })?;
            if *assertion_count > limits.max_assertion_results {
                return Err(OracleError::new_for_cli(
                    ErrorCode::OutputLimit,
                    format!(
                        "XML assertion result count exceeds {}",
                        limits.max_assertion_results
                    ),
                ));
            }
            let fields = xml_assertion_fields(child)?;
            assertions.push(NeutralAssertion { fields });
        } else if child.name == "sample" || child.name == "httpSample" {
            children.push(xml_event(
                child,
                child_position,
                limits,
                depth + 1,
                assertion_count,
            )?);
            child_position += 1;
        } else if is_jmeter_string_section(child) {
            if child.attributes.len() != 1 || !child.children.is_empty() {
                return Err(unsupported_xml(format!(
                    "section '{}' has unsupported XML metadata",
                    child.name
                )));
            }
            insert_xml_section(&mut sections, child.name.clone(), child.text.clone())?;
        } else if is_url_element(&child.name) {
            // URL elements belong to the ordered wire stream.  They are not
            // nested sample results and must not inflate sub-result counts.
        } else if child.children.is_empty() && child.attributes.is_empty() {
            insert_xml_section(&mut sections, child.name.clone(), child.text.clone())?;
        } else {
            // Unknown nested result data remains in `child_events`; the
            // typed `children` vector is reserved for sample sub-results.
        }
    }
    Ok(NeutralEvent {
        position,
        element: node.name.clone(),
        attributes: node.attributes.clone(),
        sections,
        text: node.text.clone(),
        assertions,
        children,
        child_events: node
            .children
            .iter()
            .enumerate()
            .map(|(position, child)| xml_child_event(child, position, limits, depth + 1))
            .collect::<Result<Vec<_>>>()?,
    })
}

fn is_jmeter_string_section(node: &XmlNode) -> bool {
    node.attributes
        .get("class")
        .is_some_and(|class| class == "java.lang.String")
}

fn insert_xml_section(
    sections: &mut BTreeMap<String, String>,
    name: String,
    value: String,
) -> Result<()> {
    let base_name = name.clone();
    if let Entry::Vacant(entry) = sections.entry(name) {
        entry.insert(value);
        return Ok(());
    }
    let mut duplicate = 2_usize;
    loop {
        let key = format!("{base_name}#{duplicate}");
        if let Entry::Vacant(entry) = sections.entry(key) {
            entry.insert(value);
            return Ok(());
        }
        duplicate = duplicate.checked_add(1).ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::OutputLimit,
                "duplicate XML section count overflowed",
            )
        })?;
    }
}

fn xml_assertion_fields(node: &XmlNode) -> Result<BTreeMap<String, String>> {
    let mut fields = BTreeMap::new();
    for (key, value) in &node.attributes {
        if !matches!(
            key.as_str(),
            "name" | "failure" | "error" | "failureMessage" | "errorMessage"
        ) {
            return Err(unsupported_xml(format!(
                "assertionResult contains unsupported attribute '{key}'"
            )));
        }
        insert_assertion_field(&mut fields, key, value)?;
    }
    if !node.text.trim().is_empty() {
        return Err(unsupported_xml(
            "assertionResult contains unsupported direct text",
        ));
    }
    for child in &node.children {
        let key = assertion_field_name(&child.name);
        if !matches!(
            child.name.as_str(),
            "name" | "failure" | "error" | "failureMessage" | "errorMessage"
        ) {
            return Err(unsupported_xml(format!(
                "assertionResult contains unsupported child '{}'",
                child.name
            )));
        }
        if !child.attributes.is_empty() || !child.children.is_empty() {
            return Err(unsupported_xml(format!(
                "assertionResult field '{}' has unsupported nested XML",
                child.name
            )));
        }
        insert_assertion_field(&mut fields, key, &child.text)?;
    }
    // JMeter's writer-wire assertion representation always emits the three
    // core fields.  An optional failureMessage/errorMessage is a fourth
    // child; it is not a substitute for any of the mandatory fields.
    for required in ["name", "failure", "error"] {
        if !fields.contains_key(required) {
            return Err(unsupported_xml(format!(
                "assertionResult is missing mandatory '{required}' field"
            )));
        }
    }
    Ok(fields)
}

fn assertion_field_name(name: &str) -> &str {
    match name {
        "failureMessage" => "failure_message",
        "errorMessage" => "error_message",
        other => other,
    }
}

fn insert_assertion_field(
    fields: &mut BTreeMap<String, String>,
    name: &str,
    value: &str,
) -> Result<()> {
    let name = assertion_field_name(name);
    if fields.insert(name.to_owned(), value.to_owned()).is_some() {
        return Err(unsupported_xml(format!(
            "assertionResult repeats field '{name}'"
        )));
    }
    Ok(())
}

fn unsupported_xml(message: impl Into<String>) -> OracleError {
    OracleError::new_for_cli(
        ErrorCode::UnsupportedFormat,
        format!("unsupported JTL XML: {}", message.into()),
    )
}

fn xml_event_value(event: &NeutralEvent) -> Value {
    let assertions: Vec<Value> = event
        .assertions
        .iter()
        .map(|assertion| Value::Object(string_value_map(&assertion.fields)))
        .collect();
    let children: Vec<Value> = event.children.iter().map(xml_event_value).collect();
    json!({
        "position": event.position,
        "element": event.element,
        "attributes": string_value_map(&event.attributes),
        "sections": string_value_map(&event.sections),
        "text": event.text,
        "assertions": assertions,
        "children": children,
        "child_events": &event.child_events,
    })
}

fn xml_child_event(
    node: &XmlNode,
    position: usize,
    limits: &CompareLimits,
    depth: usize,
) -> Result<NeutralXmlChild> {
    if depth > limits.max_depth {
        return Err(OracleError::new_for_cli(
            ErrorCode::OutputLimit,
            format!("XML JTL nesting exceeds {}", limits.max_depth),
        ));
    }
    Ok(NeutralXmlChild {
        position,
        element: node.name.clone(),
        attributes: node.attributes.clone(),
        text: node.text.clone(),
        children: node
            .children
            .iter()
            .enumerate()
            .map(|(child_position, child)| {
                xml_child_event(child, child_position, limits, depth + 1)
            })
            .collect::<Result<Vec<_>>>()?,
    })
}

fn string_value_map(values: &BTreeMap<String, String>) -> Map<String, Value> {
    values
        .iter()
        .map(|(key, value)| (key.clone(), Value::String(value.clone())))
        .collect()
}

#[derive(Clone, Debug)]
struct XmlNode {
    name: String,
    attributes: BTreeMap<String, String>,
    children: Vec<XmlNode>,
    text: String,
}

impl XmlNode {
    fn is_ignorable(&self) -> bool {
        self.name == "#comment" || self.name == "#processing"
    }
}

struct XmlParser<'a> {
    input: &'a str,
    position: usize,
    limits: &'a CompareLimits,
    nodes: usize,
    attributes: usize,
    events: usize,
}

impl<'a> XmlParser<'a> {
    fn new(input: &'a str, limits: &'a CompareLimits) -> Self {
        Self {
            input,
            position: 0,
            limits,
            nodes: 0,
            attributes: 0,
            events: 0,
        }
    }

    fn parse_document(&mut self) -> Result<XmlNode> {
        self.skip_misc(true)?;
        let root = self.parse_element(0)?;
        self.skip_misc(false)?;
        if self.position != self.input.len() {
            return Err(OracleError::new_for_cli(
                ErrorCode::JtlParse,
                "XML has trailing non-whitespace content",
            ));
        }
        Ok(root)
    }

    fn parse_element(&mut self, depth: usize) -> Result<XmlNode> {
        if depth > self.limits.max_depth {
            return Err(OracleError::new_for_cli(
                ErrorCode::OutputLimit,
                format!("XML JTL nesting exceeds {}", self.limits.max_depth),
            ));
        }
        self.expect_byte(b'<')?;
        if self.consume_bytes(b"!--") {
            return Err(unsupported_xml(
                "XML comments inside the result tree are not retained",
            ));
        }
        if self.consume_byte(b'?') {
            return Err(unsupported_xml(
                "XML processing instructions inside the result tree are not retained",
            ));
        }
        if self.consume_byte(b'!') {
            return Err(OracleError::new_for_cli(
                ErrorCode::JtlParse,
                "DOCTYPE/CDATA is not valid at an XML element boundary",
            ));
        }
        let name = self.parse_name()?;
        self.count_node()?;
        if depth == 1 && (name == "sample" || name == "httpSample") {
            self.events = self.events.checked_add(1).ok_or_else(|| {
                OracleError::new_for_cli(ErrorCode::OutputLimit, "XML event count overflowed")
            })?;
            if self.events > self.limits.max_events {
                return Err(OracleError::new_for_cli(
                    ErrorCode::OutputLimit,
                    format!("XML JTL event count exceeds {}", self.limits.max_events),
                ));
            }
        }
        let mut attributes = BTreeMap::new();
        loop {
            self.skip_whitespace();
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
            if self.attributes >= self.limits.max_attributes {
                return Err(OracleError::new_for_cli(
                    ErrorCode::OutputLimit,
                    format!("XML attribute count exceeds {}", self.limits.max_attributes),
                ));
            }
            let key = self.parse_name()?;
            if attributes.contains_key(&key) {
                return Err(OracleError::new_for_cli(
                    ErrorCode::JtlParse,
                    format!("XML element '{name}' repeats attribute '{key}'"),
                ));
            }
            self.skip_whitespace();
            self.expect_byte(b'=')?;
            self.skip_whitespace();
            let value = self.parse_quoted_value()?;
            attributes.insert(key, value);
            self.attributes = self.attributes.checked_add(1).ok_or_else(|| {
                OracleError::new_for_cli(ErrorCode::OutputLimit, "XML attribute count overflowed")
            })?;
        }
        let mut children = Vec::new();
        let mut text = String::new();
        loop {
            if self.position >= self.input.len() {
                return Err(OracleError::new_for_cli(
                    ErrorCode::JtlParse,
                    format!("XML element '{name}' is not closed"),
                ));
            }
            if self.input[self.position..].starts_with("</") {
                self.position += 2;
                let closing = self.parse_name()?;
                self.skip_whitespace();
                self.expect_byte(b'>')?;
                if closing != name {
                    return Err(OracleError::new_for_cli(
                        ErrorCode::JtlParse,
                        format!("XML closing element '{closing}' does not match '{name}'"),
                    ));
                }
                break;
            }
            if self.input[self.position..].starts_with("<!--") {
                return Err(unsupported_xml(
                    "XML comments inside the result tree are not retained",
                ));
            }
            if self.input[self.position..].starts_with("<?") {
                return Err(unsupported_xml(
                    "XML processing instructions inside the result tree are not retained",
                ));
            }
            if self.input[self.position..].starts_with("<![CDATA[") {
                self.position += 9;
                let end = self.input[self.position..].find("]]>").ok_or_else(|| {
                    OracleError::new_for_cli(ErrorCode::JtlParse, "unterminated XML CDATA")
                })?;
                let cdata = &self.input[self.position..self.position + end];
                if !cdata.chars().all(is_xml_character) {
                    return Err(OracleError::new_for_cli(
                        ErrorCode::JtlParse,
                        "XML CDATA contains a character outside the XML character range",
                    ));
                }
                self.append_text(&mut text, cdata)?;
                self.position += end + 3;
                continue;
            }
            if self.input.as_bytes()[self.position] == b'<' {
                children.push(self.parse_element(depth + 1)?);
            } else {
                let end = self.input[self.position..]
                    .find('<')
                    .map(|offset| self.position + offset)
                    .unwrap_or(self.input.len());
                let raw = &self.input[self.position..end];
                if raw.contains("]]>") {
                    return Err(OracleError::new_for_cli(
                        ErrorCode::JtlParse,
                        "XML text contains an unescaped ']]>'",
                    ));
                }
                let decoded = decode_entities(raw, self.limits.max_text_bytes)?;
                self.append_text(&mut text, &decoded)?;
                self.position = end;
            }
        }
        Ok(XmlNode {
            name,
            attributes,
            children,
            text,
        })
    }

    fn count_node(&mut self) -> Result<()> {
        self.nodes = self.nodes.checked_add(1).ok_or_else(|| {
            OracleError::new_for_cli(ErrorCode::OutputLimit, "XML node count overflowed")
        })?;
        if self.nodes > self.limits.max_nodes {
            return Err(OracleError::new_for_cli(
                ErrorCode::OutputLimit,
                format!("XML node count exceeds {}", self.limits.max_nodes),
            ));
        }
        Ok(())
    }

    fn append_text(&self, target: &mut String, text: &str) -> Result<()> {
        if target
            .len()
            .checked_add(text.len())
            .is_none_or(|length| length > self.limits.max_text_bytes)
        {
            Err(OracleError::new_for_cli(
                ErrorCode::OutputLimit,
                "XML text value exceeds the configured bound",
            ))
        } else {
            target.push_str(text);
            Ok(())
        }
    }

    fn parse_name(&mut self) -> Result<String> {
        let start = self.position;
        let first = self.input[self.position..].chars().next().ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::JtlParse,
                "XML element/attribute name is empty or invalid",
            )
        })?;
        if !is_xml_name_start(first) {
            return Err(OracleError::new_for_cli(
                ErrorCode::JtlParse,
                "XML element/attribute name is empty or invalid",
            ));
        }
        self.position += first.len_utf8();
        if self.position - start > self.limits.max_text_bytes {
            return Err(OracleError::new_for_cli(
                ErrorCode::OutputLimit,
                "XML name exceeds the configured text bound",
            ));
        }
        while let Some(character) = self.input[self.position..].chars().next() {
            if !is_xml_name_character(character) {
                break;
            }
            self.position += character.len_utf8();
            if self.position - start > self.limits.max_text_bytes {
                return Err(OracleError::new_for_cli(
                    ErrorCode::OutputLimit,
                    "XML name exceeds the configured text bound",
                ));
            }
        }
        Ok(self.input[start..self.position].to_owned())
    }

    fn parse_quoted_value(&mut self) -> Result<String> {
        let quote = *self.input.as_bytes().get(self.position).ok_or_else(|| {
            OracleError::new_for_cli(ErrorCode::JtlParse, "XML attribute value is missing")
        })?;
        if quote != b'"' && quote != b'\'' {
            return Err(OracleError::new_for_cli(
                ErrorCode::JtlParse,
                "XML attribute value must be quoted",
            ));
        }
        self.position += 1;
        let start = self.position;
        while self.position < self.input.len() && self.input.as_bytes()[self.position] != quote {
            self.position += 1;
        }
        if self.position >= self.input.len() {
            return Err(OracleError::new_for_cli(
                ErrorCode::JtlParse,
                "unterminated XML attribute value",
            ));
        }
        let raw = &self.input[start..self.position];
        if raw.contains('<') {
            return Err(OracleError::new_for_cli(
                ErrorCode::JtlParse,
                "XML attribute value contains an unescaped '<'",
            ));
        }
        self.position += 1;
        let value = decode_entities(raw, self.limits.max_text_bytes)?;
        Ok(value)
    }

    fn skip_misc(&mut self, allow_xml_declaration: bool) -> Result<()> {
        let mut declaration_allowed = allow_xml_declaration;
        loop {
            self.skip_whitespace();
            if declaration_allowed && self.input[self.position..].starts_with("<?xml") {
                if self
                    .input
                    .as_bytes()
                    .get(self.position + 5)
                    .is_none_or(|byte| !byte.is_ascii_whitespace())
                {
                    return Err(OracleError::new_for_cli(
                        ErrorCode::JtlParse,
                        "malformed XML declaration",
                    ));
                }
                self.position += 2;
                self.skip_until(b"?>")?;
                declaration_allowed = false;
            } else if self.input[self.position..].starts_with("<!--") {
                return Err(unsupported_xml(
                    "XML comments outside the result tree are not retained",
                ));
            } else if self.input[self.position..].starts_with("<?") {
                return Err(unsupported_xml(
                    "XML processing instructions outside the result tree are not retained",
                ));
            } else {
                break;
            }
        }
        Ok(())
    }

    fn skip_whitespace(&mut self) {
        while self
            .input
            .as_bytes()
            .get(self.position)
            .is_some_and(u8::is_ascii_whitespace)
        {
            self.position += 1;
        }
    }

    fn expect_byte(&mut self, expected: u8) -> Result<()> {
        if self.input.as_bytes().get(self.position) == Some(&expected) {
            self.position += 1;
            Ok(())
        } else {
            Err(OracleError::new_for_cli(
                ErrorCode::JtlParse,
                format!("XML expected '{}',", char::from(expected)),
            ))
        }
    }

    fn consume_byte(&mut self, expected: u8) -> bool {
        if self.input.as_bytes().get(self.position) == Some(&expected) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn consume_bytes(&mut self, expected: &[u8]) -> bool {
        if self.input.as_bytes()[self.position..].starts_with(expected) {
            self.position += expected.len();
            true
        } else {
            false
        }
    }

    fn skip_until(&mut self, marker: &[u8]) -> Result<()> {
        let Some(offset) = self.input.as_bytes()[self.position..]
            .windows(marker.len())
            .position(|window| window == marker)
        else {
            return Err(OracleError::new_for_cli(
                ErrorCode::JtlParse,
                "unterminated XML comment/processing instruction",
            ));
        };
        self.position += offset + marker.len();
        Ok(())
    }
}

fn is_xml_name_start(character: char) -> bool {
    let code = character as u32;
    character == ':'
        || character == '_'
        || character.is_ascii_alphabetic()
        || (0xC0..=0xD6).contains(&code)
        || (0xD8..=0xF6).contains(&code)
        || (0xF8..=0x2FF).contains(&code)
        || (0x370..=0x37D).contains(&code)
        || (0x37F..=0x1FFF).contains(&code)
        || (0x200C..=0x200D).contains(&code)
        || (0x2070..=0x218F).contains(&code)
        || (0x2C00..=0x2FEF).contains(&code)
        || (0x3001..=0xD7FF).contains(&code)
        || (0xF900..=0xFDCF).contains(&code)
        || (0xFDF0..=0xFFFD).contains(&code)
        || (0x10000..=0xEFFFF).contains(&code)
}

fn is_xml_name_character(character: char) -> bool {
    let code = character as u32;
    is_xml_name_start(character)
        || character == '-'
        || character == '.'
        || character.is_ascii_digit()
        || code == 0xB7
        || (0x300..=0x36F).contains(&code)
        || (0x203F..=0x2040).contains(&code)
}

fn is_xml_character(character: char) -> bool {
    let code = character as u32;
    matches!(code, 0x9 | 0xA | 0xD)
        || (0x20..=0xD7FF).contains(&code)
        || (0xE000..=0xFFFD).contains(&code)
        || (0x10000..=0x10FFFF).contains(&code)
}

fn decode_entities(raw: &str, maximum: usize) -> Result<String> {
    if !raw.contains('&') {
        if raw.chars().all(is_xml_character) {
            if raw.len() > maximum {
                return Err(OracleError::new_for_cli(
                    ErrorCode::OutputLimit,
                    "XML text value exceeds the configured bound",
                ));
            }
            return Ok(raw.to_owned());
        }
        return Err(OracleError::new_for_cli(
            ErrorCode::JtlParse,
            "XML contains a character outside the XML character range",
        ));
    }
    let mut result = String::with_capacity(raw.len().min(maximum));
    let mut remainder = raw;
    while let Some(index) = remainder.find('&') {
        append_bounded_xml_text(&mut result, &remainder[..index], maximum)?;
        let tail = &remainder[index + 1..];
        let end = tail.find(';').ok_or_else(|| {
            OracleError::new_for_cli(ErrorCode::JtlParse, "unterminated XML entity")
        })?;
        let entity = &tail[..end];
        let character = match entity {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            "apos" => '\'',
            value if value.starts_with("#x") || value.starts_with("#X") => {
                u32::from_str_radix(&value[2..], 16)
                    .ok()
                    .and_then(char::from_u32)
                    .filter(|character| is_xml_character(*character))
                    .ok_or_else(|| {
                        OracleError::new_for_cli(
                            ErrorCode::JtlParse,
                            "invalid hexadecimal XML entity",
                        )
                    })?
            }
            value if value.starts_with('#') => value[1..]
                .parse::<u32>()
                .ok()
                .and_then(char::from_u32)
                .filter(|character| is_xml_character(*character))
                .ok_or_else(|| {
                    OracleError::new_for_cli(ErrorCode::JtlParse, "invalid numeric XML entity")
                })?,
            _ => {
                return Err(OracleError::new_for_cli(
                    ErrorCode::JtlParse,
                    format!("unsupported XML entity '&{entity};'"),
                ));
            }
        };
        if !is_xml_character(character) {
            return Err(OracleError::new_for_cli(
                ErrorCode::JtlParse,
                "XML entity resolves outside the XML character range",
            ));
        }
        append_bounded_xml_text(&mut result, &character.to_string(), maximum)?;
        remainder = &tail[end + 1..];
    }
    append_bounded_xml_text(&mut result, remainder, maximum)?;
    if !result.chars().all(is_xml_character) {
        return Err(OracleError::new_for_cli(
            ErrorCode::JtlParse,
            "XML contains a character outside the XML character range",
        ));
    }
    Ok(result)
}

fn append_bounded_xml_text(target: &mut String, text: &str, maximum: usize) -> Result<()> {
    if target
        .len()
        .checked_add(text.len())
        .is_none_or(|length| length > maximum)
    {
        return Err(OracleError::new_for_cli(
            ErrorCode::OutputLimit,
            "XML text value exceeds the configured bound",
        ));
    }
    target.push_str(text);
    Ok(())
}

fn canonical_contained_expected_file(root: &Path, path: &Path) -> Result<PathBuf> {
    reject_symlink_components(root, "fixture root")?;
    reject_symlink_components(path, "expected projection")?;
    let root = fs::canonicalize(root).map_err(|error| {
        OracleError::new_for_cli(
            ErrorCode::File,
            format!("canonicalize fixture root '{}': {error}", root.display()),
        )
    })?;
    let canonical = fs::canonicalize(path).map_err(|error| {
        OracleError::new_for_cli(
            ErrorCode::File,
            format!(
                "canonicalize expected projection '{}': {error}",
                path.display()
            ),
        )
    })?;
    if !canonical.starts_with(&root) {
        return Err(OracleError::new_for_cli(
            ErrorCode::PathPolicy,
            format!(
                "expected projection '{}' escapes fixture root '{}'",
                canonical.display(),
                root.display()
            ),
        ));
    }
    Ok(canonical)
}

fn reject_symlink_components(path: &Path, label: &str) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current).map_err(|error| {
            OracleError::new_for_cli(
                ErrorCode::File,
                format!("inspect {label} path '{}': {error}", current.display()),
            )
        })?;
        if metadata.file_type().is_symlink() {
            return Err(OracleError::new_for_cli(
                ErrorCode::PathPolicy,
                format!("{label} path '{}' contains a symlink", path.display()),
            ));
        }
    }
    Ok(())
}

fn contained_expected_relative_file(root: &Path, relative: &str) -> Result<PathBuf> {
    let candidate = Path::new(relative);
    if relative.is_empty()
        || candidate.is_absolute()
        || candidate.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(OracleError::new_for_cli(
            ErrorCode::PathPolicy,
            format!("expected projection path '{relative}' is not contained"),
        ));
    }
    canonical_contained_expected_file(root, &root.join(candidate))
}

fn apply_fixture_resource_limits(document: &Value, limits: &mut CompareLimits) -> Result<()> {
    let object_limit = |section: &str, key: &str| -> Result<Option<u64>> {
        let Some(value) = document.get(section) else {
            return Ok(None);
        };
        let object = value.as_object().ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                format!("case {section} must be an object"),
            )
        })?;
        let Some(value) = object.get(key) else {
            return Ok(None);
        };
        let value = value.as_u64().ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                format!("case {section}.{key} must be an unsigned integer"),
            )
        })?;
        if value == 0 {
            return Err(OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                format!("case {section}.{key} must be greater than zero"),
            ));
        }
        Ok(Some(value))
    };
    let bound_or_resource = |key: &str| -> Result<Option<u64>> {
        let resource = object_limit("resource_limits", key)?;
        let bound = object_limit("bounds", key)?;
        Ok(match (resource, bound) {
            (Some(resource), Some(bound)) => Some(resource.min(bound)),
            (Some(value), None) | (None, Some(value)) => Some(value),
            (None, None) => None,
        })
    };
    let max_samples = match object_limit("resource_limits", "max_samples")? {
        Some(value) => Some(value),
        None => object_limit("bounds", "max_samples")?,
    };
    if let Some(max_samples) = max_samples {
        let max_samples = usize::try_from(max_samples).map_err(|_| {
            OracleError::new_for_cli(ErrorCode::ManifestSchema, "case max_samples is too large")
        })?;
        limits.max_events = limits.max_events.min(max_samples);
    }
    let max_text_bytes = match object_limit("resource_limits", "max_response_bytes")? {
        Some(value) => Some(value),
        None => match object_limit("bounds", "max_result_bytes")? {
            Some(value) => Some(value),
            None => object_limit("bounds", "max_text_bytes")?,
        },
    };
    if let Some(max_response_bytes) = max_text_bytes {
        let max_response_bytes = usize::try_from(max_response_bytes).map_err(|_| {
            OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "case result byte bound is too large",
            )
        })?;
        limits.max_text_bytes = limits.max_text_bytes.min(max_response_bytes);
    }
    if let Some(max_input_bytes) = object_limit("bounds", "max_input_bytes")? {
        limits.max_input_bytes = limits.max_input_bytes.min(max_input_bytes);
    }
    if let Some(max_depth) = object_limit("bounds", "max_depth")? {
        limits.max_depth = limits
            .max_depth
            .min(usize::try_from(max_depth).map_err(|_| {
                OracleError::new_for_cli(ErrorCode::ManifestSchema, "case max_depth is too large")
            })?);
    }
    if let Some(max_nodes) = object_limit("bounds", "max_xml_nodes")? {
        limits.max_nodes = limits
            .max_nodes
            .min(usize::try_from(max_nodes).map_err(|_| {
                OracleError::new_for_cli(
                    ErrorCode::ManifestSchema,
                    "case max_xml_nodes is too large",
                )
            })?);
    }
    if let Some(max_attributes) = object_limit("bounds", "max_xml_attributes")? {
        limits.max_attributes =
            limits
                .max_attributes
                .min(usize::try_from(max_attributes).map_err(|_| {
                    OracleError::new_for_cli(
                        ErrorCode::ManifestSchema,
                        "case max_xml_attributes is too large",
                    )
                })?);
    }
    if let Some(max_line_bytes) = bound_or_resource("max_line_bytes")? {
        limits.max_text_bytes =
            limits
                .max_text_bytes
                .min(usize::try_from(max_line_bytes).map_err(|_| {
                    OracleError::new_for_cli(
                        ErrorCode::ManifestSchema,
                        "case max_line_bytes is too large",
                    )
                })?);
    }
    if let Some(max_columns) = bound_or_resource("max_csv_columns")? {
        limits.max_csv_columns = limits
            .max_csv_columns
            .min(usize::try_from(max_columns).map_err(|_| {
                OracleError::new_for_cli(
                    ErrorCode::ManifestSchema,
                    "case max_csv_columns is too large",
                )
            })?);
    }
    if let Some(max_assertions) = bound_or_resource("max_assertion_results")? {
        limits.max_assertion_results =
            limits
                .max_assertion_results
                .min(usize::try_from(max_assertions).map_err(|_| {
                    OracleError::new_for_cli(
                        ErrorCode::ManifestSchema,
                        "case max_assertion_results is too large",
                    )
                })?);
    }
    Ok(())
}

fn select_expected_path(fixture: &ValidatedCase) -> Result<PathBuf> {
    let execution = fixture
        .case()
        .document()
        .get("execution")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "case execution object is required for compare mode",
            )
        })?;
    let expected = execution.get("expected").ok_or_else(|| {
        OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "case execution.expected is required when --expected is omitted",
        )
    })?;
    let candidates: Vec<&str> = match expected {
        Value::String(path) => vec![path.as_str()],
        Value::Array(paths) => paths
            .iter()
            .map(|path| {
                path.as_str()
                    .or_else(|| path.get("path").and_then(Value::as_str))
                    .ok_or_else(|| {
                        OracleError::new_for_cli(
                            ErrorCode::ManifestSchema,
                            "case execution.expected array entries must be paths or path objects",
                        )
                    })
            })
            .collect::<Result<Vec<_>>>()?,
        _ => {
            return Err(OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "case execution.expected must be a string or array of path entries",
            ));
        }
    };
    let path = match candidates.as_slice() {
        [] => {
            return Err(OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "case execution.expected cannot be empty",
            ));
        }
        [path] => path,
        _ => {
            return Err(OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "multiple expected projections require an explicit --expected path",
            ));
        }
    };
    contained_expected_relative_file(fixture.fixture_dir(), path)
}

fn expected_event_count(value: &Value, limits: &CompareLimits) -> Result<usize> {
    let count = if let Some(sample_count) = value.get("sample_count") {
        if sample_count.is_null() {
            if let Some(rows) = value.get("rows") {
                rows.as_array()
                    .ok_or_else(|| {
                        OracleError::new_for_cli(
                            ErrorCode::ManifestSchema,
                            "expected projection rows must be an array",
                        )
                    })?
                    .len() as u64
            } else if let Some(samples) = value.get("samples") {
                samples
                    .as_array()
                    .ok_or_else(|| {
                        OracleError::new_for_cli(
                            ErrorCode::ManifestSchema,
                            "expected projection samples must be an array",
                        )
                    })?
                    .len() as u64
            } else {
                0
            }
        } else {
            sample_count.as_u64().ok_or_else(|| {
                OracleError::new_for_cli(
                    ErrorCode::ManifestSchema,
                    "expected projection sample_count must be an unsigned integer",
                )
            })?
        }
    } else if let Some(rows) = value.get("rows") {
        rows.as_array()
            .ok_or_else(|| {
                OracleError::new_for_cli(
                    ErrorCode::ManifestSchema,
                    "expected projection rows must be an array",
                )
            })?
            .len() as u64
    } else if let Some(samples) = value.get("samples") {
        samples
            .as_array()
            .ok_or_else(|| {
                OracleError::new_for_cli(
                    ErrorCode::ManifestSchema,
                    "expected projection samples must be an array",
                )
            })?
            .len() as u64
    } else {
        0
    };
    if count > limits.max_events as u64 {
        return Err(OracleError::new_for_cli(
            ErrorCode::OutputLimit,
            format!(
                "expected projection event count exceeds {}",
                limits.max_events
            ),
        ));
    }
    usize::try_from(count).map_err(|_| {
        OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "expected projection event count does not fit the target",
        )
    })
}

fn expected_csv_header(value: &Value) -> Result<Option<Vec<String>>> {
    let no_header = value
        .get("writer_wire")
        .and_then(Value::as_object)
        .and_then(|wire| wire.get("print_field_names"))
        .and_then(Value::as_bool)
        == Some(false)
        || value.get("print_field_names").and_then(Value::as_bool) == Some(false);
    if !no_header {
        return Ok(None);
    }
    let header = value
        .get("header")
        .ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "expected CSV header is required when print_field_names is false",
            )
        })?
        .as_array()
        .ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "expected CSV header must be an array",
            )
        })?;
    if header.is_empty() {
        return Err(OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "expected CSV header cannot be empty when print_field_names is false",
        ));
    }
    let mut values = Vec::with_capacity(header.len());
    let mut seen = BTreeSet::new();
    for (index, value) in header.iter().enumerate() {
        let value = value.as_str().ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                format!("expected CSV header entry {index} must be a string"),
            )
        })?;
        if value.is_empty() {
            return Err(OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "expected CSV header cannot contain an empty column",
            ));
        }
        if !seen.insert(value) {
            return Err(OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                format!("expected CSV header repeats column '{value}'"),
            ));
        }
        values.push(value.to_owned());
    }
    Ok(Some(values))
}

pub(crate) fn base_report(
    actual: &ArtifactSummary,
    expected: &ArtifactSummary,
    options: &CompareOptions,
) -> CompareReport {
    CompareReport {
        equal: true,
        actual: actual.clone(),
        expected: expected.clone(),
        normalization_policy_refs: options.normalization_policy_refs.iter().cloned().collect(),
        normalized_fields: options.ignored_fields.iter().cloned().collect(),
        structured_diff: Vec::new(),
        raw_diagnostic_diff: Vec::new(),
        human_diff: String::new(),
    }
}

pub(crate) fn raw_projection_diff(
    actual: &Value,
    expected: &Value,
    options: &CompareOptions,
) -> Vec<StructuredDiff> {
    let mut raw_options = options.clone();
    raw_options.ignored_fields.clear();
    raw_options.ignored_line_patterns.clear();
    let summary = ArtifactSummary {
        path: "<raw-diagnostic>".to_owned(),
        format: CompareFormat::Json,
        size_bytes: 0,
        event_count: 0,
    };
    let mut report = base_report(&summary, &summary, &raw_options);
    compare_projection_values(actual, expected, "", &raw_options, &mut report);
    report.structured_diff
}

fn compare_neutral_documents(
    actual: &NeutralDocument,
    expected: &Value,
    options: &CompareOptions,
    report: &mut CompareReport,
) {
    if expected
        .get("format")
        .and_then(Value::as_str)
        .and_then(CompareFormat::from_hint)
        .is_some_and(|format| format != actual.format)
    {
        push_diff(
            report,
            options,
            "/format",
            "changed",
            expected.get("format"),
            Some(&Value::String(actual.format.as_str().to_owned())),
        );
        return;
    }
    compare_projection_values(&actual.projection, expected, "", options, report);
}

fn compare_expected_projection(
    actual: &NeutralDocument,
    expected: &Value,
    options: &CompareOptions,
    report: &mut CompareReport,
) -> Result<()> {
    validate_comparator_variant(expected)?;
    let expected_format = expected
        .get("format")
        .and_then(Value::as_str)
        .and_then(CompareFormat::from_hint);
    if expected_format == Some(CompareFormat::Xml) {
        validate_expected_xml_projection(expected, &options.limits)?;
    }
    if expected_format == Some(CompareFormat::Csv) {
        validate_expected_csv_projection(expected)?;
    }
    if expected_format == Some(CompareFormat::Json) {
        compare_projection_values(&actual.projection, expected, "", options, report);
        return Ok(());
    }
    match expected_format {
        Some(CompareFormat::Csv) => compare_csv_expectation(actual, expected, options, report),
        Some(CompareFormat::Xml) => compare_xml_expectation(actual, expected, options, report)?,
        None => push_diff(
            report,
            options,
            "/format",
            "missing",
            expected.get("format"),
            None,
        ),
        Some(CompareFormat::Json) => {
            compare_projection_values(&actual.projection, expected, "", options, report)
        }
        Some(CompareFormat::JmxSemantic) => {
            return Err(OracleError::new_for_cli(
                ErrorCode::UnsupportedFormat,
                "jmx-semantic projections require the JMX semantic comparator route",
            ));
        }
    }
    Ok(())
}

fn validate_comparator_variant(expected: &Value) -> Result<()> {
    let Some(object) = expected.as_object() else {
        return Ok(());
    };
    let contract_kind = if let Some(value) = object.get("contract_kind") {
        Some(value.as_str().ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "expected projection contract_kind must be a string",
            )
        })?)
    } else {
        None
    };
    let non_comparator_kind = contract_kind.is_some_and(|kind| {
        matches!(
            kind,
            "rust-reader-projection"
                | "jmeter-reader-compat"
                | "jmeter-reader-semantics"
                | "rust-no-drop-parser"
                | "invalid-input-contract"
                | "resource-limit-contract"
        )
    });
    let non_comparator_fields = [
        "contracts",
        "reader_semantics",
        "reader_contracts",
        "no_drop_contract",
    ];
    if non_comparator_kind
        || non_comparator_fields
            .iter()
            .any(|field| object.contains_key(*field))
    {
        let detail = contract_kind.unwrap_or("reader/contract descriptor");
        return Err(OracleError::new_for_cli(
            ErrorCode::UnsupportedFormat,
            format!(
                "expected projection variant '{detail}' is a non-comparator descriptor; use a dedicated reader/error/contract comparator"
            ),
        ));
    }
    if let Some(kind) = contract_kind
        && kind != "jmeter-writer-wire"
    {
        return Err(OracleError::new_for_cli(
            ErrorCode::UnsupportedFormat,
            format!("unsupported comparator contract_kind '{kind}'"),
        ));
    }
    Ok(())
}

fn compare_csv_expectation(
    actual: &NeutralDocument,
    expected: &Value,
    options: &CompareOptions,
    report: &mut CompareReport,
) {
    if actual.format != CompareFormat::Csv {
        push_diff(
            report,
            options,
            "/format",
            "changed",
            expected.get("format"),
            Some(&Value::String(actual.format.as_str().to_owned())),
        );
        return;
    }
    compare_declared_value(
        actual.projection.get("format"),
        expected.get("format"),
        "/format",
        options,
        report,
    );
    compare_declared_value(
        actual.projection.get("header"),
        expected.get("header"),
        "/header",
        options,
        report,
    );
    if expected
        .get("sample_count_asserted")
        .and_then(Value::as_bool)
        != Some(false)
    {
        compare_optional_declared_value(
            actual.projection.get("sample_count"),
            expected.get("sample_count"),
            "/sample_count",
            options,
            report,
        );
    }
    for field in [
        "delimiter",
        "line_ending",
        "record_line_endings",
        "final_terminator",
        "header_serialized",
    ] {
        compare_optional_declared_value(
            actual.projection.get(field),
            expected.get(field),
            &format!("/{field}"),
            options,
            report,
        );
    }
    if let Some(writer_wire) = expected.get("writer_wire").filter(|value| !value.is_null()) {
        let actual_writer_wire = actual.projection.get("writer_wire");
        compare_declared_object_fields(
            actual_writer_wire,
            writer_wire,
            "/writer_wire",
            options,
            report,
        );
    }
    let actual_rows = actual
        .projection
        .get("rows")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if let Some(expected_rows_value) = expected.get("rows") {
        if let Some(expected_rows) = expected_rows_value.as_array() {
            if actual_rows.len() != expected_rows.len() {
                push_diff(
                    report,
                    options,
                    "/rows",
                    "changed",
                    Some(&Value::Array(expected_rows.clone())),
                    Some(&Value::Array(actual_rows.clone())),
                );
            }
            for (index, expected_row) in expected_rows.iter().enumerate() {
                let path = format!("/rows/{index}");
                let Some(actual_row) = actual_rows.get(index) else {
                    push_diff(report, options, &path, "missing", Some(expected_row), None);
                    continue;
                };
                compare_declared_value(
                    actual_row.get("position"),
                    expected_row.get("position"),
                    &format!("{path}/position"),
                    options,
                    report,
                );
                let actual_fields = actual_row.get("fields").and_then(Value::as_object);
                let expected_fields = expected_row.get("fields").and_then(Value::as_object);
                compare_field_map(
                    actual_fields,
                    expected_fields,
                    &format!("{path}/fields"),
                    options,
                    report,
                );
            }
        } else {
            push_diff(
                report,
                options,
                "/rows",
                "changed",
                Some(expected_rows_value),
                Some(&Value::Array(actual_rows.clone())),
            );
        }
    }
    if let Some(quoting) = expected.get("quoting_assertions").and_then(Value::as_array) {
        for (index, assertion) in quoting.iter().enumerate() {
            let field = assertion.get("field").and_then(Value::as_str);
            let Some(field) = field else {
                push_diff(
                    report,
                    options,
                    &format!("/quoting_assertions/{index}/field"),
                    "missing",
                    Some(assertion),
                    None,
                );
                continue;
            };
            let actual_token = actual_rows
                .first()
                .and_then(|row| row.get("serialized_fields"))
                .and_then(|fields| fields.get(field));
            for (token_key, expected_token) in [
                (
                    "serialized_csv_token",
                    assertion.get("serialized_csv_token"),
                ),
                (
                    "serialized_field_lexeme",
                    assertion.get("serialized_field_lexeme"),
                ),
            ] {
                if let Some(expected_token) = expected_token {
                    compare_declared_value(
                        actual_token,
                        Some(expected_token),
                        &format!("/quoting_assertions/{index}/{token_key}"),
                        options,
                        report,
                    );
                }
            }
            let actual_value = actual_rows
                .first()
                .and_then(|row| row.get("fields"))
                .and_then(|fields| fields.get(field));
            compare_declared_value(
                actual_value,
                assertion.get("parsed_value"),
                &format!("/quoting_assertions/{index}/parsed_value"),
                options,
                report,
            );
        }
    }
}

fn validate_expected_csv_projection(expected: &Value) -> Result<()> {
    validate_expected_csv_projection_with_limits(expected, &CompareLimits::default())
}

fn validate_expected_csv_projection_with_limits(
    expected: &Value,
    limits: &CompareLimits,
) -> Result<()> {
    validate_expected_projection_envelope(expected, CompareFormat::Csv)?;
    if let Some(header) = expected.get("header") {
        let header = header.as_array().ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "expected CSV header must be an array",
            )
        })?;
        if header.iter().any(|value| !value.is_string()) {
            return Err(OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "expected CSV header must contain strings",
            ));
        }
        if header.len() > limits.max_csv_columns {
            return Err(OracleError::new_for_cli(
                ErrorCode::OutputLimit,
                format!(
                    "expected CSV column count exceeds {}",
                    limits.max_csv_columns
                ),
            ));
        }
        let mut seen = BTreeSet::new();
        for column in header {
            let Some(column) = column.as_str() else {
                return Err(OracleError::new_for_cli(
                    ErrorCode::ManifestSchema,
                    "expected CSV header must contain strings",
                ));
            };
            if column.is_empty() {
                return Err(OracleError::new_for_cli(
                    ErrorCode::ManifestSchema,
                    "expected CSV header cannot contain an empty column",
                ));
            }
            if !seen.insert(column) {
                return Err(OracleError::new_for_cli(
                    ErrorCode::ManifestSchema,
                    format!("expected CSV header repeats column '{column}'"),
                ));
            }
        }
    }
    if let Some(sample_count) = expected.get("sample_count")
        && !sample_count.is_null()
        && sample_count.as_u64().is_none()
    {
        return Err(OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "expected CSV sample_count must be an unsigned integer or null",
        ));
    }
    if let Some(sample_count) = expected.get("sample_count").and_then(Value::as_u64)
        && sample_count > limits.max_events as u64
    {
        return Err(OracleError::new_for_cli(
            ErrorCode::OutputLimit,
            format!("expected CSV sample count exceeds {}", limits.max_events),
        ));
    }
    if let Some(value) = expected.get("delimiter")
        && !value.is_null()
        && !value.is_string()
    {
        return Err(OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "expected CSV delimiter must be a string or null",
        ));
    }
    if let Some(delimiter) = expected.get("delimiter").and_then(Value::as_str)
        && !valid_delimiter_name(delimiter)
    {
        return Err(OracleError::new_for_cli(
            ErrorCode::UnsupportedFormat,
            format!("unsupported expected CSV delimiter '{delimiter}'"),
        ));
    }
    if let Some(value) = expected.get("line_ending")
        && !value.is_null()
        && !value.is_string()
    {
        return Err(OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "expected CSV line_ending must be a string or null",
        ));
    }
    if let Some(line_ending) = expected.get("line_ending").and_then(Value::as_str)
        && !matches!(line_ending, "LF" | "CRLF" | "CR" | "MIXED" | "NONE")
    {
        return Err(OracleError::new_for_cli(
            ErrorCode::UnsupportedFormat,
            format!("unsupported expected CSV line ending '{line_ending}'"),
        ));
    }
    if let Some(record_line_endings) = expected.get("record_line_endings") {
        validate_string_array(record_line_endings, "expected CSV record_line_endings")?;
        if record_line_endings.as_array().is_some_and(|values| {
            values.iter().any(|value| {
                value
                    .as_str()
                    .is_some_and(|ending| !matches!(ending, "LF" | "CRLF" | "CR"))
            })
        }) {
            return Err(OracleError::new_for_cli(
                ErrorCode::UnsupportedFormat,
                "expected CSV record_line_endings contains an unsupported terminator",
            ));
        }
    }
    if let Some(final_terminator) = expected.get("final_terminator") {
        if !final_terminator.is_string() {
            return Err(OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "expected CSV final_terminator must be a string",
            ));
        }
        if final_terminator
            .as_str()
            .is_some_and(|terminator| !matches!(terminator, "LF" | "CRLF" | "CR" | "NONE"))
        {
            return Err(OracleError::new_for_cli(
                ErrorCode::UnsupportedFormat,
                "expected CSV final_terminator is unsupported",
            ));
        }
    }
    if let Some(value) = expected.get("header_serialized")
        && !value.is_null()
    {
        validate_string_array(value, "expected CSV header_serialized")?;
    }
    if let Some(writer_wire) = expected.get("writer_wire")
        && !writer_wire.is_null()
    {
        let object = writer_wire.as_object().ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "expected CSV writer_wire must be an object or null",
            )
        })?;
        for key in object.keys() {
            if !matches!(
                key.as_str(),
                "header_line"
                    | "sample_variable_headers_quoted"
                    | "delimiter"
                    | "line_ending"
                    | "record_line_endings"
                    | "final_terminator"
                    | "print_field_names"
            ) {
                return Err(OracleError::new_for_cli(
                    ErrorCode::UnsupportedFormat,
                    format!("unsupported expected CSV writer_wire field '{key}'"),
                ));
            }
        }
        for key in [
            "header_line",
            "delimiter",
            "line_ending",
            "final_terminator",
        ] {
            if let Some(value) = object.get(key)
                && !value.is_string()
            {
                return Err(OracleError::new_for_cli(
                    ErrorCode::ManifestSchema,
                    format!("expected CSV writer_wire {key} must be a string"),
                ));
            }
        }
        if let Some(delimiter) = object.get("delimiter").and_then(Value::as_str)
            && !valid_delimiter_name(delimiter)
        {
            return Err(OracleError::new_for_cli(
                ErrorCode::UnsupportedFormat,
                format!("unsupported expected CSV writer_wire delimiter '{delimiter}'"),
            ));
        }
        if let Some(line_ending) = object.get("line_ending").and_then(Value::as_str)
            && !matches!(line_ending, "LF" | "CRLF" | "CR" | "MIXED" | "NONE")
        {
            return Err(OracleError::new_for_cli(
                ErrorCode::UnsupportedFormat,
                format!("unsupported expected CSV writer_wire line ending '{line_ending}'"),
            ));
        }
        if let Some(record_line_endings) = object.get("record_line_endings") {
            validate_string_array(
                record_line_endings,
                "expected CSV writer_wire record_line_endings",
            )?;
            if record_line_endings.as_array().is_some_and(|values| {
                values.iter().any(|value| {
                    value
                        .as_str()
                        .is_some_and(|ending| !matches!(ending, "LF" | "CRLF" | "CR"))
                })
            }) {
                return Err(OracleError::new_for_cli(
                    ErrorCode::UnsupportedFormat,
                    "expected CSV writer_wire record_line_endings contains an unsupported terminator",
                ));
            }
        }
        if let Some(final_terminator) = object.get("final_terminator").and_then(Value::as_str)
            && !matches!(final_terminator, "LF" | "CRLF" | "CR" | "NONE")
        {
            return Err(OracleError::new_for_cli(
                ErrorCode::UnsupportedFormat,
                "expected CSV writer_wire final_terminator is unsupported",
            ));
        }
        if let Some(value) = object.get("sample_variable_headers_quoted")
            && !value.is_boolean()
        {
            return Err(OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "expected CSV writer_wire sample_variable_headers_quoted must be boolean",
            ));
        }
        if let Some(value) = object.get("print_field_names")
            && !value.is_boolean()
        {
            return Err(OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "expected CSV writer_wire print_field_names must be boolean",
            ));
        }
    }
    if let Some(assertions) = expected.get("quoting_assertions") {
        let assertions = assertions.as_array().ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "expected CSV quoting_assertions must be an array",
            )
        })?;
        for assertion in assertions {
            let assertion = assertion.as_object().ok_or_else(|| {
                OracleError::new_for_cli(
                    ErrorCode::ManifestSchema,
                    "expected CSV quoting assertion must be an object",
                )
            })?;
            for key in assertion.keys() {
                if !matches!(
                    key.as_str(),
                    "field" | "parsed_value" | "serialized_csv_token" | "serialized_field_lexeme"
                ) {
                    return Err(OracleError::new_for_cli(
                        ErrorCode::UnsupportedFormat,
                        format!("unsupported expected CSV quoting assertion field '{key}'"),
                    ));
                }
            }
            for key in [
                "field",
                "parsed_value",
                "serialized_csv_token",
                "serialized_field_lexeme",
            ] {
                if let Some(value) = assertion.get(key)
                    && !value.is_string()
                {
                    return Err(OracleError::new_for_cli(
                        ErrorCode::ManifestSchema,
                        format!("expected CSV quoting assertion {key} must be a string"),
                    ));
                }
            }
        }
    }
    if let Some(rows) = expected.get("rows") {
        let rows = rows.as_array().ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "expected CSV rows must be an array",
            )
        })?;
        if rows.len() > limits.max_events {
            return Err(OracleError::new_for_cli(
                ErrorCode::OutputLimit,
                format!("expected CSV row count exceeds {}", limits.max_events),
            ));
        }
        for row in rows {
            let row = row.as_object().ok_or_else(|| {
                OracleError::new_for_cli(
                    ErrorCode::ManifestSchema,
                    "expected CSV row must be an object",
                )
            })?;
            for key in row.keys() {
                if !matches!(key.as_str(), "position" | "fields" | "ignored_fields") {
                    return Err(OracleError::new_for_cli(
                        ErrorCode::UnsupportedFormat,
                        format!("unsupported expected CSV row field '{key}'"),
                    ));
                }
            }
            if let Some(position) = row.get("position")
                && position.as_u64().is_none()
            {
                return Err(OracleError::new_for_cli(
                    ErrorCode::ManifestSchema,
                    "expected CSV row position must be an unsigned integer",
                ));
            }
            if let Some(fields) = row.get("fields")
                && !fields.is_object()
            {
                return Err(OracleError::new_for_cli(
                    ErrorCode::ManifestSchema,
                    "expected CSV row fields must be an object",
                ));
            }
            if let Some(fields) = row.get("fields").and_then(Value::as_object)
                && fields.values().any(|value| !value.is_string())
            {
                return Err(OracleError::new_for_cli(
                    ErrorCode::ManifestSchema,
                    "expected CSV row fields must contain strings",
                ));
            }
            if let Some(ignored_fields) = row.get("ignored_fields") {
                validate_string_array(ignored_fields, "expected CSV row ignored_fields")?;
            }
        }
    }
    Ok(())
}

fn valid_delimiter_name(value: &str) -> bool {
    value == "TAB"
        || value.chars().count() == 1
            && value
                .chars()
                .next()
                .is_some_and(|character| character.is_ascii_graphic() && character != '"')
}

fn validate_expected_projection_envelope(expected: &Value, format: CompareFormat) -> Result<()> {
    let object = expected.as_object().ok_or_else(|| {
        OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "expected projection must be an object",
        )
    })?;
    let allowed = match format {
        CompareFormat::Csv => &[
            "format",
            "schema_id",
            "schema_version",
            "profile_id",
            "case_id",
            "contract_kind",
            "evidence_status",
            "expectation_basis",
            "projection_schema",
            "writer_configuration",
            "generated_from",
            "process_exit",
            "rust_conformance_claim",
            "header",
            "sample_count",
            "sample_count_asserted",
            "rows",
            "delimiter",
            "line_ending",
            "record_line_endings",
            "final_terminator",
            "header_serialized",
            "writer_wire",
            "quoting_assertions",
            "normalization",
        ][..],
        CompareFormat::Xml => &[
            "format",
            "schema_id",
            "schema_version",
            "profile_id",
            "case_id",
            "contract_kind",
            "evidence_status",
            "expectation_basis",
            "projection_schema",
            "writer_configuration",
            "generated_from",
            "process_exit",
            "rust_conformance_claim",
            "root",
            "sample_count",
            "sample_count_asserted",
            "ordered_labels",
            "samples",
            "sample_contract",
            "wire_contract",
            "normalization",
        ][..],
        CompareFormat::Json | CompareFormat::JmxSemantic => &[][..],
    };
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(OracleError::new_for_cli(
                ErrorCode::UnsupportedFormat,
                format!(
                    "unsupported expected {} projection field '{key}'",
                    format.as_str()
                ),
            ));
        }
    }
    for key in [
        "format",
        "schema_id",
        "profile_id",
        "case_id",
        "contract_kind",
        "evidence_status",
        "expectation_basis",
        "projection_schema",
        "writer_configuration",
        "rust_conformance_claim",
    ] {
        if let Some(value) = object.get(key)
            && !value.is_string()
            && !(key == "rust_conformance_claim" && value.is_boolean())
        {
            return Err(OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                format!("expected projection {key} must be a string"),
            ));
        }
    }
    if let Some(value) = object.get("schema_version")
        && value.as_u64().is_none()
    {
        return Err(OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "expected projection schema_version must be an unsigned integer",
        ));
    }
    if let Some(value) = object.get("sample_count_asserted")
        && !value.is_boolean()
    {
        return Err(OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "expected projection sample_count_asserted must be boolean",
        ));
    }
    if let Some(value) = object.get("generated_from")
        && !value.is_object()
    {
        return Err(OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "expected projection generated_from must be an object",
        ));
    }
    if let Some(value) = object.get("process_exit")
        && !value.is_null()
        && value.as_i64().is_none()
    {
        return Err(OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "expected projection process_exit must be an integer or null",
        ));
    }
    if let Some(value) = object.get("normalization") {
        let normalization = value.as_object().ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "expected projection normalization must be an object",
            )
        })?;
        for key in normalization.keys() {
            if !matches!(key.as_str(), "ignored_fields" | "reason") {
                return Err(OracleError::new_for_cli(
                    ErrorCode::UnsupportedFormat,
                    format!("unsupported expected normalization field '{key}'"),
                ));
            }
        }
        if let Some(fields) = normalization.get("ignored_fields") {
            validate_string_array(fields, "expected normalization ignored_fields")?;
        }
        if let Some(reason) = normalization.get("reason")
            && !reason.is_string()
        {
            return Err(OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "expected normalization reason must be a string",
            ));
        }
    }
    Ok(())
}

fn compare_optional_declared_value(
    actual: Option<&Value>,
    expected: Option<&Value>,
    path: &str,
    options: &CompareOptions,
    report: &mut CompareReport,
) {
    if expected.is_some_and(|value| !value.is_null()) {
        compare_declared_value(actual, expected, path, options, report);
    }
}

fn compare_declared_object_fields(
    actual: Option<&Value>,
    expected: &Value,
    path: &str,
    options: &CompareOptions,
    report: &mut CompareReport,
) {
    let Some(expected) = expected.as_object() else {
        push_diff(report, options, path, "changed", Some(expected), actual);
        return;
    };
    let actual = actual.and_then(Value::as_object);
    for (key, expected_value) in expected {
        compare_optional_declared_value(
            actual.and_then(|map| map.get(key)),
            Some(expected_value),
            &format!("{path}/{key}"),
            options,
            report,
        );
    }
}

fn compare_field_map(
    actual: Option<&Map<String, Value>>,
    expected: Option<&Map<String, Value>>,
    path: &str,
    options: &CompareOptions,
    report: &mut CompareReport,
) {
    let Some(expected) = expected else {
        return;
    };
    for (field, expected_value) in expected {
        let field_path = format!("{path}/{field}");
        if is_ignored_field(&format!("rows[*].{field}"), options) {
            continue;
        }
        let actual_value = actual.and_then(|map| map.get(field));
        compare_declared_value(
            actual_value,
            Some(expected_value),
            &field_path,
            options,
            report,
        );
    }
    // Once a row declares a field map, every emitted column must be accounted
    // for by either an expected value or an explicit normalization rule.  A
    // partial row with no `fields` member remains an assertion-free row shape
    // used by metadata-only expectations.
    if let Some(actual) = actual {
        for (field, actual_value) in actual {
            if expected.contains_key(field)
                || is_ignored_field(&format!("rows[*].{field}"), options)
            {
                continue;
            }
            push_diff(
                report,
                options,
                &format!("{path}/{field}"),
                "unexpected",
                None,
                Some(actual_value),
            );
        }
    }
}

fn compare_xml_expectation(
    actual: &NeutralDocument,
    expected: &Value,
    options: &CompareOptions,
    report: &mut CompareReport,
) -> Result<()> {
    if actual.format != CompareFormat::Xml {
        push_diff(
            report,
            options,
            "/format",
            "changed",
            expected.get("format"),
            Some(&Value::String(actual.format.as_str().to_owned())),
        );
        return Ok(());
    }
    compare_declared_value(
        actual.projection.get("format"),
        expected.get("format"),
        "/format",
        options,
        report,
    );
    compare_declared_value(
        actual.projection.get("root"),
        expected.get("root"),
        "/root",
        options,
        report,
    );
    if let (Some(actual_root), Some(expected_root)) = (
        actual.projection.get("root").and_then(Value::as_object),
        expected.get("root").and_then(Value::as_object),
    ) {
        for (key, value) in actual_root {
            if !expected_root.contains_key(key) {
                push_diff(
                    report,
                    options,
                    &format!("/root/{key}"),
                    "unexpected",
                    None,
                    Some(value),
                );
            }
        }
    }
    if expected
        .get("sample_count_asserted")
        .and_then(Value::as_bool)
        != Some(false)
    {
        compare_optional_declared_value(
            actual.projection.get("sample_count"),
            expected.get("sample_count"),
            "/sample_count",
            options,
            report,
        );
    }
    let actual_samples = actual
        .projection
        .get("samples")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if let Some(labels) = expected.get("ordered_labels") {
        let actual_labels: Vec<Value> = actual_samples
            .iter()
            .map(|sample| {
                sample
                    .get("attributes")
                    .and_then(|attrs| attrs.get("lb"))
                    .cloned()
                    .unwrap_or(Value::Null)
            })
            .collect();
        compare_declared_value(
            Some(&Value::Array(actual_labels)),
            Some(labels),
            "/ordered_labels",
            options,
            report,
        );
    }
    if let Some(contract) = expected.get("sample_contract") {
        for (index, sample) in actual_samples.iter().enumerate() {
            compare_xml_sample(
                sample,
                contract,
                &format!("/samples/{index}"),
                expected.get("ordered_labels").is_some(),
                expected.get("wire_contract"),
                options,
                report,
            );
        }
    }
    if let Some(wire_contract) = expected.get("wire_contract") {
        for (index, sample) in actual_samples.iter().enumerate() {
            compare_xml_wire_contract(
                sample,
                wire_contract,
                &format!("/samples/{index}/wire_contract"),
                options,
                report,
            );
        }
    }
    if let Some(samples_value) = expected.get("samples") {
        if let Some(samples) = samples_value.as_array() {
            for (index, expected_sample) in samples.iter().enumerate() {
                let path = format!("/samples/{index}");
                let Some(actual_sample) = actual_samples.get(index) else {
                    push_diff(
                        report,
                        options,
                        &path,
                        "missing",
                        Some(expected_sample),
                        None,
                    );
                    continue;
                };
                compare_xml_sample(
                    actual_sample,
                    expected_sample,
                    &path,
                    false,
                    expected.get("wire_contract"),
                    options,
                    report,
                );
            }
            if actual_samples.len() != samples.len() {
                push_diff(
                    report,
                    options,
                    "/samples",
                    "changed",
                    Some(&Value::Array(samples.clone())),
                    Some(&Value::Array(actual_samples.clone())),
                );
            }
        } else {
            push_diff(
                report,
                options,
                "/samples",
                "changed",
                Some(samples_value),
                Some(&Value::Array(actual_samples)),
            );
        }
    }
    Ok(())
}

fn validate_expected_xml_projection(expected: &Value, limits: &CompareLimits) -> Result<()> {
    validate_expected_projection_envelope(expected, CompareFormat::Xml)?;
    if let Some(sample_count) = expected.get("sample_count")
        && !sample_count.is_null()
    {
        let sample_count = sample_count.as_u64().ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "expected XML sample_count must be an unsigned integer",
            )
        })?;
        if sample_count > limits.max_events as u64 {
            return Err(OracleError::new_for_cli(
                ErrorCode::OutputLimit,
                format!("expected XML sample count exceeds {}", limits.max_events),
            ));
        }
    }
    let samples: &[Value] = match expected.get("samples") {
        None => &[],
        Some(samples) => samples.as_array().ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "expected XML samples must be an array",
            )
        })?,
    };
    if samples.len() > limits.max_events {
        return Err(OracleError::new_for_cli(
            ErrorCode::OutputLimit,
            format!("expected XML sample count exceeds {}", limits.max_events),
        ));
    }
    if let Some(labels) = expected.get("ordered_labels")
        && !labels.is_null()
    {
        let labels = labels.as_array().ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "expected XML ordered_labels must be an array",
            )
        })?;
        if labels.len() > limits.max_events {
            return Err(OracleError::new_for_cli(
                ErrorCode::OutputLimit,
                format!("expected XML ordered_labels exceeds {}", limits.max_events),
            ));
        }
        if labels.iter().any(|label| !label.is_string()) {
            return Err(OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "expected XML ordered_labels must contain strings",
            ));
        }
    }
    for sample in samples {
        validate_expected_xml_sample(sample, limits, 0)?;
    }
    if let Some(contract) = expected.get("sample_contract") {
        validate_expected_xml_sample(contract, limits, 0)?;
    }
    if let Some(wire_contract) = expected.get("wire_contract") {
        validate_expected_xml_wire_contract(wire_contract, limits)?;
    }
    Ok(())
}

fn validate_expected_xml_sample(value: &Value, limits: &CompareLimits, depth: usize) -> Result<()> {
    if depth > limits.max_depth {
        return Err(OracleError::new_for_cli(
            ErrorCode::OutputLimit,
            format!("expected XML nesting exceeds {}", limits.max_depth),
        ));
    }
    let object = value.as_object().ok_or_else(|| {
        OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "expected XML sample must be an object",
        )
    })?;
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "position"
                | "element"
                | "label"
                | "attributes"
                | "ignored_attributes"
                | "absent_attributes"
                | "assertions"
                | "empty_children"
                | "absent_children"
                | "wire_children"
                | "unknown_children"
                | "children"
                | "sub_results"
                | "sampler_data_contains"
                | "debug_response_projection"
                | "response_data"
                | "response_file"
                | "response_code"
                | "response_message"
                | "text"
                | "sections"
        ) {
            return Err(OracleError::new_for_cli(
                ErrorCode::UnsupportedFormat,
                format!("unsupported expected XML sample field '{key}'"),
            ));
        }
    }
    if let Some(position) = object.get("position") {
        let position = position.as_u64().ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "expected XML sample position must be an unsigned integer",
            )
        })?;
        if position >= limits.max_events as u64 {
            return Err(OracleError::new_for_cli(
                ErrorCode::OutputLimit,
                "expected XML sample position exceeds the event bound",
            ));
        }
    }
    if let Some(element) = object.get("element") {
        validate_expected_sample_element(element)?;
    }
    for (key, expected_type) in [
        ("attributes", "an object"),
        ("sections", "an object"),
        ("assertions", "an array"),
        ("children", "an array or object"),
    ] {
        let Some(value) = object.get(key) else {
            continue;
        };
        let valid = match key {
            "attributes" | "sections" => value.is_object(),
            "assertions" => value.is_array(),
            "children" => value.is_array() || value.is_object(),
            _ => false,
        };
        if !valid {
            return Err(OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                format!("expected XML sample {key} must be {expected_type}"),
            ));
        }
    }
    if let Some(attributes) = object.get("attributes").and_then(Value::as_object)
        && attributes.values().any(|value| !value.is_string())
    {
        return Err(OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "expected XML sample attributes must contain strings",
        ));
    }
    if let Some(sections) = object.get("sections").and_then(Value::as_object)
        && sections.values().any(|value| !value.is_string())
    {
        return Err(OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "expected XML sample sections must contain strings",
        ));
    }
    if let Some(text) = object.get("text")
        && !text.is_string()
    {
        return Err(OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "expected XML sample text must be a string",
        ));
    }
    for key in [
        "label",
        "response_data",
        "response_file",
        "response_code",
        "response_message",
    ] {
        if let Some(value) = object.get(key)
            && !value.is_string()
        {
            return Err(OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                format!("expected XML sample {key} must be a string"),
            ));
        }
    }
    for key in [
        "ignored_attributes",
        "absent_attributes",
        "empty_children",
        "absent_children",
    ] {
        if let Some(value) = object.get(key) {
            validate_string_array(value, &format!("expected XML sample {key}"))?;
        }
    }
    if let Some(value) = object.get("sampler_data_contains") {
        validate_string_array(value, "expected XML sample sampler_data_contains")?;
    }
    if let Some(assertions) = object.get("assertions") {
        validate_expected_assertions(assertions, "expected XML sample assertions")?;
    }
    if let Some(debug) = object.get("debug_response_projection") {
        validate_expected_debug_projection(debug)?;
    }
    if let Some(value) = object.get("wire_children") {
        validate_expected_wire_children(value)?;
    }
    if let Some(value) = object.get("unknown_children") {
        validate_expected_unknown_children(value, limits, depth + 1)?;
    }
    if let Some(value) = object.get("children") {
        match value {
            Value::Array(children) => {
                if children.len() > limits.max_events {
                    return Err(OracleError::new_for_cli(
                        ErrorCode::OutputLimit,
                        "expected XML child descriptors exceed the event bound",
                    ));
                }
                for child in children {
                    validate_expected_xml_typed_child_descriptor(child, limits, depth + 1)?;
                }
            }
            Value::Object(_) => validate_expected_children_object(value)?,
            _ => {
                return Err(OracleError::new_for_cli(
                    ErrorCode::ManifestSchema,
                    "expected XML children must be an array or object",
                ));
            }
        }
    }
    if let Some(sub_results) = object.get("sub_results") {
        validate_expected_sub_results(sub_results, limits, depth + 1)?;
    }
    if let Some(wire_children) = object.get("wire_children") {
        validate_expected_wire_children(wire_children)?;
    }
    if let Some(unknown_children) = object.get("unknown_children") {
        validate_expected_unknown_children(unknown_children, limits, depth + 1)?;
    }
    Ok(())
}

fn validate_string_array(value: &Value, label: &str) -> Result<()> {
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

fn validate_expected_debug_projection(value: &Value) -> Result<()> {
    let object = value.as_object().ok_or_else(|| {
        OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "expected debug_response_projection must be an object",
        )
    })?;
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "required_sections" | "variables" | "properties" | "ignored_line_patterns"
        ) {
            return Err(OracleError::new_for_cli(
                ErrorCode::UnsupportedFormat,
                format!("unsupported expected debug_response_projection field '{key}'"),
            ));
        }
    }
    if let Some(value) = object.get("required_sections") {
        validate_string_array(value, "expected debug required_sections")?;
    }
    if let Some(value) = object.get("ignored_line_patterns") {
        validate_string_array(value, "expected debug ignored_line_patterns")?;
    }
    for key in ["variables", "properties"] {
        if let Some(value) = object.get(key) {
            let values = value.as_object().ok_or_else(|| {
                OracleError::new_for_cli(
                    ErrorCode::ManifestSchema,
                    format!("expected debug {key} must be an object"),
                )
            })?;
            if values.values().any(|value| !value.is_string()) {
                return Err(OracleError::new_for_cli(
                    ErrorCode::ManifestSchema,
                    format!("expected debug {key} must contain strings"),
                ));
            }
        }
    }
    Ok(())
}

fn validate_expected_assertions(value: &Value, label: &str) -> Result<()> {
    let assertions = value.as_array().ok_or_else(|| {
        OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            format!("{label} must be an array"),
        )
    })?;
    for assertion in assertions {
        let assertion = assertion.as_object().ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                format!("{label} entries must be objects"),
            )
        })?;
        for key in assertion.keys() {
            if !matches!(
                key.as_str(),
                "name" | "failure" | "error" | "failure_message" | "error_message"
            ) {
                return Err(OracleError::new_for_cli(
                    ErrorCode::UnsupportedFormat,
                    format!("unsupported {label} field '{key}'"),
                ));
            }
        }
        if assertion.values().any(|value| !value.is_string()) {
            return Err(OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                format!("{label} fields must contain strings"),
            ));
        }
    }
    Ok(())
}

fn validate_assertion_child_order(value: &Value, label: &str) -> Result<()> {
    validate_string_array(value, label)?;
    let mut seen = BTreeSet::new();
    if let Some(children) = value.as_array() {
        for child in children.iter().filter_map(Value::as_str) {
            if !seen.insert(child) {
                return Err(OracleError::new_for_cli(
                    ErrorCode::ManifestSchema,
                    format!("{label} must not repeat '{child}'"),
                ));
            }
        }
        let names: Vec<&str> = children.iter().filter_map(Value::as_str).collect();
        let required = ["name", "failure", "error"];
        if names.len() < required.len()
            || names[..required.len()] != required
            || names.len() > required.len() + 1
            || names
                .get(required.len())
                .is_some_and(|name| !matches!(*name, "failureMessage" | "errorMessage"))
        {
            return Err(OracleError::new_for_cli(
                ErrorCode::UnsupportedFormat,
                format!(
                    "{label} must be name, failure, error, optionally failureMessage/errorMessage"
                ),
            ));
        }
    }
    Ok(())
}

fn validate_expected_wire_children(value: &Value) -> Result<()> {
    let object = value.as_object().ok_or_else(|| {
        OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "expected XML wire_children must be an object",
        )
    })?;
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "string_children_class" | "wire_child_order" | "assertion_child_elements"
        ) {
            return Err(OracleError::new_for_cli(
                ErrorCode::UnsupportedFormat,
                format!("unsupported expected XML wire_children field '{key}'"),
            ));
        }
    }
    for key in [
        "string_children_class",
        "wire_child_order",
        "assertion_child_elements",
    ] {
        if let Some(value) = object.get(key) {
            if key == "assertion_child_elements" {
                validate_assertion_child_order(
                    value,
                    &format!("expected XML wire_children {key}"),
                )?;
            } else {
                validate_string_array(value, &format!("expected XML wire_children {key}"))?;
            }
            if key == "assertion_child_elements"
                && value.as_array().is_some_and(|children| {
                    children.iter().any(|child| {
                        child.as_str().is_none_or(|name| {
                            !matches!(
                                name,
                                "name" | "failure" | "error" | "failureMessage" | "errorMessage"
                            )
                        })
                    })
                })
            {
                return Err(OracleError::new_for_cli(
                    ErrorCode::UnsupportedFormat,
                    "expected XML wire_children assertion_child_elements contains an unsupported child",
                ));
            }
        }
    }
    Ok(())
}

fn validate_expected_xml_wire_contract(value: &Value, limits: &CompareLimits) -> Result<()> {
    let object = value.as_object().ok_or_else(|| {
        OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "expected XML wire_contract must be an object",
        )
    })?;
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "sample_variable_attributes"
                | "assertion_result"
                | "string_children"
                | "url_child"
                | "child_order"
                | "wire_order"
                | "response_file_policy"
                | "response_file"
                | "response_data"
                | "timestamp"
        ) {
            return Err(OracleError::new_for_cli(
                ErrorCode::UnsupportedFormat,
                format!("unsupported expected XML wire_contract field '{key}'"),
            ));
        }
    }
    if let Some(value) = object.get("sample_variable_attributes") {
        let value = value.as_object().ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "expected XML sample_variable_attributes must be an object",
            )
        })?;
        for key in value.keys() {
            if !matches!(
                key.as_str(),
                "spelling" | "configured_names" | "underscore_doubling"
            ) {
                return Err(OracleError::new_for_cli(
                    ErrorCode::UnsupportedFormat,
                    format!("unsupported expected XML sample_variable_attributes field '{key}'"),
                ));
            }
        }
        if let Some(spelling) = value.get("spelling")
            && !spelling.is_string()
        {
            return Err(OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "expected XML sample_variable_attributes spelling must be a string",
            ));
        }
        if value
            .get("spelling")
            .and_then(Value::as_str)
            .is_some_and(|spelling| spelling != "exact-configured-name")
        {
            return Err(OracleError::new_for_cli(
                ErrorCode::UnsupportedFormat,
                "expected XML sample_variable_attributes spelling is unsupported",
            ));
        }
        if let Some(names) = value.get("configured_names") {
            validate_string_array(names, "expected XML configured_names")?;
            if let Some(names) = names.as_array() {
                let mut seen = BTreeSet::new();
                for name in names.iter().filter_map(Value::as_str) {
                    if !seen.insert(name) {
                        return Err(OracleError::new_for_cli(
                            ErrorCode::ManifestSchema,
                            "expected XML configured_names must not repeat a name",
                        ));
                    }
                }
            }
        }
        if let Some(doubling) = value.get("underscore_doubling")
            && !doubling.is_boolean()
        {
            return Err(OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "expected XML underscore_doubling must be boolean",
            ));
        }
    }
    if let Some(value) = object.get("assertion_result") {
        let value = value.as_object().ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "expected XML assertion_result must be an object",
            )
        })?;
        for key in value.keys() {
            if !matches!(
                key.as_str(),
                "representation" | "child_order" | "failure_message_property"
            ) {
                return Err(OracleError::new_for_cli(
                    ErrorCode::UnsupportedFormat,
                    format!("unsupported expected XML assertion_result field '{key}'"),
                ));
            }
        }
        for key in ["representation", "failure_message_property"] {
            if let Some(value) = value.get(key)
                && !value.is_string()
            {
                return Err(OracleError::new_for_cli(
                    ErrorCode::ManifestSchema,
                    format!("expected XML assertion_result {key} must be a string"),
                ));
            }
        }
        if value
            .get("representation")
            .and_then(Value::as_str)
            .is_some_and(|representation| representation != "child-elements")
        {
            return Err(OracleError::new_for_cli(
                ErrorCode::UnsupportedFormat,
                "expected XML assertion_result representation must be child-elements",
            ));
        }
        if value
            .get("failure_message_property")
            .and_then(Value::as_str)
            .is_some_and(|property| {
                property != "jmeter.save.saveservice.assertion_results_failure_message"
            })
        {
            return Err(OracleError::new_for_cli(
                ErrorCode::UnsupportedFormat,
                "expected XML assertion_result failure_message_property is unsupported",
            ));
        }
        if let Some(child_order) = value.get("child_order") {
            validate_assertion_child_order(child_order, "expected XML assertion child_order")?;
            if child_order.as_array().is_some_and(|children| {
                children.iter().any(|child| {
                    child.as_str().is_none_or(|name| {
                        !matches!(
                            name,
                            "name" | "failure" | "error" | "failureMessage" | "errorMessage"
                        )
                    })
                })
            }) {
                return Err(OracleError::new_for_cli(
                    ErrorCode::UnsupportedFormat,
                    "expected XML assertion child_order contains an unsupported child",
                ));
            }
        }
    }
    if let Some(value) = object.get("string_children") {
        let children = value.as_array().ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "expected XML string_children must be an array",
            )
        })?;
        if children.len() > limits.max_events {
            return Err(OracleError::new_for_cli(
                ErrorCode::OutputLimit,
                "expected XML string_children exceeds the event bound",
            ));
        }
        for child in children {
            let child = child.as_object().ok_or_else(|| {
                OracleError::new_for_cli(
                    ErrorCode::ManifestSchema,
                    "expected XML string child must be an object",
                )
            })?;
            for key in child.keys() {
                if !matches!(key.as_str(), "element" | "class") {
                    return Err(OracleError::new_for_cli(
                        ErrorCode::UnsupportedFormat,
                        format!("unsupported expected XML string child field '{key}'"),
                    ));
                }
            }
            if !child.get("element").is_some_and(Value::is_string) {
                return Err(OracleError::new_for_cli(
                    ErrorCode::ManifestSchema,
                    "expected XML string child element is required",
                ));
            }
            if let Some(class) = child.get("class")
                && !class.is_null()
                && !class.is_string()
            {
                return Err(OracleError::new_for_cli(
                    ErrorCode::ManifestSchema,
                    "expected XML string child class must be a string or null",
                ));
            }
        }
    }
    if let Some(value) = object.get("url_child") {
        validate_expected_xml_url_descriptor(value)?;
    }
    for key in ["child_order", "wire_order"] {
        if let Some(value) = object.get(key) {
            validate_string_array(value, &format!("expected XML wire {key}"))?;
        }
    }
    if let Some(value) = object.get("response_file_policy")
        && !value.is_string()
    {
        return Err(OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "expected XML response_file_policy must be a string",
        ));
    }
    if object
        .get("response_file_policy")
        .and_then(Value::as_str)
        .is_some_and(|policy| policy != "only when filename saving is enabled")
    {
        return Err(OracleError::new_for_cli(
            ErrorCode::UnsupportedFormat,
            "expected XML response_file_policy is unsupported",
        ));
    }
    for key in ["response_file", "response_data"] {
        if let Some(value) = object.get(key) {
            validate_expected_xml_presence_descriptor(value, key)?;
        }
    }
    if let Some(timestamp) = object.get("timestamp") {
        validate_expected_xml_timestamp_descriptor(timestamp)?;
    }
    Ok(())
}

fn validate_expected_xml_timestamp_descriptor(value: &Value) -> Result<()> {
    let value = value.as_object().ok_or_else(|| {
        OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "expected XML timestamp must be an object",
        )
    })?;
    for key in value.keys() {
        if !matches!(
            key.as_str(),
            "format"
                | "attribute"
                | "source"
                | "sampleresult.timestamp.start"
                | "formatted_timestamp_fallback"
        ) {
            return Err(OracleError::new_for_cli(
                ErrorCode::UnsupportedFormat,
                format!("unsupported expected XML timestamp field '{key}'"),
            ));
        }
    }
    if value.get("format").and_then(Value::as_str) != Some("XML-millisecond-attribute") {
        return Err(OracleError::new_for_cli(
            ErrorCode::UnsupportedFormat,
            "expected XML timestamp format must be XML-millisecond-attribute",
        ));
    }
    if value.get("attribute").and_then(Value::as_str) != Some("ts") {
        return Err(OracleError::new_for_cli(
            ErrorCode::UnsupportedFormat,
            "expected XML timestamp attribute must be ts",
        ));
    }
    let source = value.get("source").and_then(Value::as_str).ok_or_else(|| {
        OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "expected XML timestamp source is required",
        )
    })?;
    if !matches!(source, "sample-start" | "sample-end") {
        return Err(OracleError::new_for_cli(
            ErrorCode::UnsupportedFormat,
            "expected XML timestamp source must be sample-start or sample-end",
        ));
    }
    let timestamp_starts = value
        .get("sampleresult.timestamp.start")
        .and_then(Value::as_bool)
        .ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "expected XML timestamp sampleresult.timestamp.start must be boolean",
            )
        })?;
    let expected_source = if timestamp_starts {
        "sample-start"
    } else {
        "sample-end"
    };
    if source != expected_source {
        return Err(OracleError::new_for_cli(
            ErrorCode::UnsupportedFormat,
            "expected XML timestamp source disagrees with sampleresult.timestamp.start",
        ));
    }
    if value
        .get("formatted_timestamp_fallback")
        .is_some_and(|fallback| fallback != &Value::Bool(false))
    {
        return Err(OracleError::new_for_cli(
            ErrorCode::UnsupportedFormat,
            "formatted XML timestamp fallback is unsupported",
        ));
    }
    Ok(())
}

fn validate_expected_xml_url_descriptor(value: &Value) -> Result<()> {
    let value = value.as_object().ok_or_else(|| {
        OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "expected XML url_child must be an object",
        )
    })?;
    for key in value.keys() {
        if !matches!(key.as_str(), "element" | "class") {
            return Err(OracleError::new_for_cli(
                ErrorCode::UnsupportedFormat,
                format!("unsupported expected XML url_child field '{key}'"),
            ));
        }
    }
    if !value.get("element").is_some_and(Value::is_string) {
        return Err(OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "expected XML url_child element is required",
        ));
    }
    if value
        .get("element")
        .and_then(Value::as_str)
        .is_none_or(|element| !is_url_element(element))
    {
        return Err(OracleError::new_for_cli(
            ErrorCode::UnsupportedFormat,
            "expected XML url_child element must be java.net.URL or its URL alias",
        ));
    }
    if let Some(class) = value.get("class")
        && !class.is_null()
        && !class.is_string()
    {
        return Err(OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "expected XML url_child class must be a string or null",
        ));
    }
    Ok(())
}

fn validate_expected_xml_presence_descriptor(value: &Value, field: &str) -> Result<()> {
    let value = value.as_object().ok_or_else(|| {
        OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            format!("expected XML {field} descriptor must be an object"),
        )
    })?;
    for key in value.keys() {
        if !matches!(
            key.as_str(),
            "enabled" | "expected" | "on_error" | "resource_reference"
        ) {
            return Err(OracleError::new_for_cli(
                ErrorCode::UnsupportedFormat,
                format!("unsupported expected XML {field} field '{key}'"),
            ));
        }
    }
    for key in ["enabled", "on_error"] {
        if let Some(value) = value.get(key)
            && !value.is_boolean()
        {
            return Err(OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                format!("expected XML {field} {key} must be boolean"),
            ));
        }
    }
    if let Some(value) = value.get("expected")
        && !value.is_boolean()
        && !value.is_string()
    {
        return Err(OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            format!("expected XML {field} expected must be boolean or a policy string"),
        ));
    }
    if let Some(value) = value.get("resource_reference")
        && !value.is_string()
    {
        return Err(OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            format!("expected XML {field} resource_reference must be a string"),
        ));
    }
    Ok(())
}

fn validate_expected_unknown_children(
    value: &Value,
    limits: &CompareLimits,
    depth: usize,
) -> Result<()> {
    let children = value.as_array().ok_or_else(|| {
        OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "expected XML unknown_children must be an array",
        )
    })?;
    if children.len() > limits.max_events {
        return Err(OracleError::new_for_cli(
            ErrorCode::OutputLimit,
            "expected XML unknown_children exceeds the event bound",
        ));
    }
    for child in children {
        validate_expected_unknown_child(child, limits, depth)?;
    }
    Ok(())
}

fn validate_expected_unknown_child(
    value: &Value,
    limits: &CompareLimits,
    depth: usize,
) -> Result<()> {
    if depth > limits.max_depth {
        return Err(OracleError::new_for_cli(
            ErrorCode::OutputLimit,
            format!(
                "expected XML unknown-child nesting exceeds {}",
                limits.max_depth
            ),
        ));
    }
    let child = value.as_object().ok_or_else(|| {
        OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "expected XML unknown child must be an object",
        )
    })?;
    for key in child.keys() {
        if !matches!(
            key.as_str(),
            "position" | "name" | "class" | "value" | "text" | "attributes" | "children"
        ) {
            return Err(OracleError::new_for_cli(
                ErrorCode::UnsupportedFormat,
                format!("unsupported expected XML unknown child field '{key}'"),
            ));
        }
    }
    if child.contains_key("value") && child.contains_key("text") {
        return Err(OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "expected XML unknown child cannot declare both value and text",
        ));
    }
    if let Some(position) = child.get("position")
        && position.as_u64().is_none()
    {
        return Err(OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "expected XML unknown child position must be an unsigned integer",
        ));
    }
    if let Some(position) = child.get("position").and_then(Value::as_u64)
        && position >= limits.max_events as u64
    {
        return Err(OracleError::new_for_cli(
            ErrorCode::OutputLimit,
            "expected XML unknown child position exceeds the event bound",
        ));
    }
    if let Some(attributes) = child.get("attributes") {
        let attributes = attributes.as_object().ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "expected XML unknown child attributes must be an object",
            )
        })?;
        if attributes.values().any(|value| !value.is_string()) {
            return Err(OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "expected XML unknown child attributes must contain strings",
            ));
        }
    }
    for key in ["name", "class", "value", "text"] {
        if let Some(value) = child.get(key)
            && !value.is_string()
        {
            return Err(OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                format!("expected XML unknown child {key} must be a string"),
            ));
        }
    }
    if !child.get("name").is_some_and(Value::is_string) {
        return Err(OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "expected XML unknown child name is required",
        ));
    }
    if let Some(children) = child.get("children") {
        let children = children.as_array().ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "expected XML unknown child children must be an array",
            )
        })?;
        if children.len() > limits.max_events {
            return Err(OracleError::new_for_cli(
                ErrorCode::OutputLimit,
                "expected XML unknown child children exceeds the event bound",
            ));
        }
        for nested in children {
            validate_expected_unknown_child(nested, limits, depth + 1)?;
        }
    }
    Ok(())
}

fn validate_expected_children_object(value: &Value) -> Result<()> {
    let object = value.as_object().ok_or_else(|| {
        OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "expected XML children must be an object",
        )
    })?;
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "response_data"
                | "response_file"
                | "response_headers"
                | "request_headers"
                | "sampler_data_contains"
                | "response_data_reason"
                | "url_element"
                | "string_children_class"
                | "wire_child_order"
                | "assertion_child_elements"
                | "assertions"
        ) {
            return Err(OracleError::new_for_cli(
                ErrorCode::UnsupportedFormat,
                format!("unsupported expected XML children field '{key}'"),
            ));
        }
    }
    for key in [
        "response_data",
        "response_file",
        "response_headers",
        "request_headers",
    ] {
        if let Some(value) = object.get(key)
            && !value.is_string()
        {
            return Err(OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                format!("expected XML children {key} must be a string"),
            ));
        }
    }
    if object.contains_key("response_data_reason") {
        return Err(OracleError::new_for_cli(
            ErrorCode::UnsupportedFormat,
            "expected XML children response_data_reason is diagnostic-only",
        ));
    }
    for key in [
        "sampler_data_contains",
        "string_children_class",
        "wire_child_order",
        "assertion_child_elements",
    ] {
        if let Some(value) = object.get(key) {
            validate_string_array(value, &format!("expected XML children {key}"))?;
        }
    }
    if let Some(url) = object.get("url_element") {
        let url = url.as_object().ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "expected XML children url_element must be an object",
            )
        })?;
        for key in url.keys() {
            if !matches!(key.as_str(), "name" | "value") {
                return Err(OracleError::new_for_cli(
                    ErrorCode::UnsupportedFormat,
                    format!("unsupported expected XML url_element field '{key}'"),
                ));
            }
        }
        for key in ["name", "value"] {
            if let Some(value) = url.get(key)
                && !value.is_string()
            {
                return Err(OracleError::new_for_cli(
                    ErrorCode::ManifestSchema,
                    format!("expected XML url_element {key} must be a string"),
                ));
            }
        }
        if url
            .get("name")
            .and_then(Value::as_str)
            .is_some_and(|name| !is_url_element(name))
        {
            return Err(OracleError::new_for_cli(
                ErrorCode::UnsupportedFormat,
                "expected XML url_element name must be java.net.URL or its URL alias",
            ));
        }
    }
    if let Some(assertions) = object.get("assertions") {
        validate_expected_assertions(assertions, "expected XML children assertions")?;
    }
    Ok(())
}

fn validate_expected_sub_results(
    value: &Value,
    limits: &CompareLimits,
    depth: usize,
) -> Result<()> {
    if depth > limits.max_depth {
        return Err(OracleError::new_for_cli(
            ErrorCode::OutputLimit,
            format!("expected sub-result nesting exceeds {}", limits.max_depth),
        ));
    }
    let object = value.as_object().ok_or_else(|| {
        OracleError::new_for_cli(
            ErrorCode::UnsupportedFormat,
            "expected sub_results must be an object",
        )
    })?;
    let count = object
        .get("count")
        .map(|count| {
            count.as_u64().ok_or_else(|| {
                OracleError::new_for_cli(
                    ErrorCode::ManifestSchema,
                    "expected sub_results.count must be an unsigned integer",
                )
            })
        })
        .transpose()?;
    if let Some(count) = count
        && count > limits.max_events as u64
    {
        return Err(OracleError::new_for_cli(
            ErrorCode::OutputLimit,
            "expected sub_results.count exceeds the event bound",
        ));
    }
    let nested = object
        .get("nested")
        .map(|nested| {
            nested.as_array().ok_or_else(|| {
                OracleError::new_for_cli(
                    ErrorCode::ManifestSchema,
                    "expected sub_results.nested must be an array",
                )
            })
        })
        .transpose()?;
    if let Some(nested) = nested {
        if nested.len() > limits.max_events {
            return Err(OracleError::new_for_cli(
                ErrorCode::OutputLimit,
                "expected sub_results.nested exceeds the event bound",
            ));
        }
        if count.is_some_and(|count| count != nested.len() as u64) {
            return Err(OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "expected sub_results.count disagrees with nested length",
            ));
        }
        for descriptor in nested {
            validate_expected_sub_result_descriptor(descriptor, limits, depth + 1)?;
        }
    }
    let labels = object
        .get("ordered_labels")
        .map(|labels| {
            labels.as_array().ok_or_else(|| {
                OracleError::new_for_cli(
                    ErrorCode::ManifestSchema,
                    "expected sub_results.ordered_labels must be an array",
                )
            })
        })
        .transpose()?;
    if let Some(labels) = labels {
        if labels.len() > limits.max_events {
            return Err(OracleError::new_for_cli(
                ErrorCode::OutputLimit,
                "expected sub_results.ordered_labels exceeds the event bound",
            ));
        }
        if nested.is_some_and(|nested| nested.len() != labels.len()) {
            return Err(OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "expected sub_results.ordered_labels disagrees with nested length",
            ));
        }
        if labels.iter().any(|label| !label.is_string()) {
            return Err(OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "expected sub_results.ordered_labels must contain strings",
            ));
        }
    }
    for key in object.keys() {
        if !matches!(key.as_str(), "count" | "ordered_labels" | "nested") {
            return Err(OracleError::new_for_cli(
                ErrorCode::UnsupportedFormat,
                format!("unsupported expected sub_results field '{key}'"),
            ));
        }
    }
    Ok(())
}

fn validate_expected_sub_result_descriptor(
    value: &Value,
    limits: &CompareLimits,
    depth: usize,
) -> Result<()> {
    if depth > limits.max_depth {
        return Err(OracleError::new_for_cli(
            ErrorCode::OutputLimit,
            format!("expected sub-result nesting exceeds {}", limits.max_depth),
        ));
    }
    let object = value.as_object().ok_or_else(|| {
        OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "expected sub-result descriptor must be an object",
        )
    })?;
    if let Some(element) = object.get("element") {
        validate_expected_sample_element(element)?;
    }
    if let Some(position) = object.get("position") {
        let position = position.as_u64().ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "expected sub-result position must be an unsigned integer",
            )
        })?;
        if position >= limits.max_events as u64 {
            return Err(OracleError::new_for_cli(
                ErrorCode::OutputLimit,
                "expected sub-result position exceeds the event bound",
            ));
        }
    }
    if let Some(label) = object.get("label")
        && !label.is_string()
    {
        return Err(OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "expected sub-result label must be a string",
        ));
    }
    for (key, expected_type) in [
        ("attributes", "an object"),
        ("assertions", "an array"),
        ("sections", "an object"),
    ] {
        let Some(value) = object.get(key) else {
            continue;
        };
        let valid = match key {
            "attributes" | "sections" => value.is_object(),
            "assertions" => value.is_array(),
            _ => false,
        };
        if !valid {
            return Err(OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                format!("expected sub-result {key} must be {expected_type}"),
            ));
        }
    }
    if let Some(attributes) = object.get("attributes").and_then(Value::as_object)
        && attributes.values().any(|value| !value.is_string())
    {
        return Err(OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "expected sub-result attributes must contain strings",
        ));
    }
    if let Some(sections) = object.get("sections").and_then(Value::as_object)
        && sections.values().any(|value| !value.is_string())
    {
        return Err(OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "expected sub-result sections must contain strings",
        ));
    }
    if let Some(assertions) = object.get("assertions") {
        validate_expected_assertions(assertions, "expected sub-result assertions")?;
    }
    if let Some(text) = object.get("text")
        && !text.is_string()
    {
        return Err(OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "expected sub-result text must be a string",
        ));
    }
    if let Some(children) = object.get("children") {
        let children = children.as_array().ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "expected sub-result children must be an array",
            )
        })?;
        if children.len() > limits.max_events {
            return Err(OracleError::new_for_cli(
                ErrorCode::OutputLimit,
                "expected sub-result children exceeds the event bound",
            ));
        }
        for child in children {
            validate_expected_sub_result_descriptor(child, limits, depth + 1)?;
        }
    }
    if let Some(sub_results) = object.get("sub_results") {
        validate_expected_sub_results(sub_results, limits, depth + 1)?;
    }
    if let Some(wire_children) = object.get("wire_children") {
        validate_expected_wire_children(wire_children)?;
    }
    if let Some(unknown_children) = object.get("unknown_children") {
        validate_expected_unknown_children(unknown_children, limits, depth + 1)?;
    }
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "element"
                | "position"
                | "label"
                | "attributes"
                | "assertions"
                | "sections"
                | "text"
                | "children"
                | "sub_results"
                | "wire_children"
                | "unknown_children"
        ) {
            return Err(OracleError::new_for_cli(
                ErrorCode::UnsupportedFormat,
                format!("unsupported expected sub-result field '{key}'"),
            ));
        }
    }
    Ok(())
}

fn validate_expected_sample_element(value: &Value) -> Result<()> {
    let Some(element) = value.as_str() else {
        return Err(OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "expected XML sample element must be a string",
        ));
    };
    if !matches!(element, "sample" | "httpSample") {
        return Err(OracleError::new_for_cli(
            ErrorCode::UnsupportedFormat,
            format!("unsupported expected XML sample element '{element}'"),
        ));
    }
    Ok(())
}

fn validate_expected_xml_typed_child_descriptor(
    value: &Value,
    limits: &CompareLimits,
    depth: usize,
) -> Result<()> {
    if depth > limits.max_depth {
        return Err(OracleError::new_for_cli(
            ErrorCode::OutputLimit,
            format!(
                "expected XML typed-child nesting exceeds {}",
                limits.max_depth
            ),
        ));
    }
    let object = value.as_object().ok_or_else(|| {
        OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "expected XML typed child must be an object",
        )
    })?;
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "position" | "element" | "attributes" | "sections" | "text" | "assertions" | "children"
        ) {
            return Err(OracleError::new_for_cli(
                ErrorCode::UnsupportedFormat,
                format!("unsupported expected XML typed child field '{key}'"),
            ));
        }
    }
    if let Some(position) = object.get("position") {
        let position = position.as_u64().ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "expected XML typed child position must be an unsigned integer",
            )
        })?;
        if position >= limits.max_events as u64 {
            return Err(OracleError::new_for_cli(
                ErrorCode::OutputLimit,
                "expected XML typed child position exceeds the event bound",
            ));
        }
    }
    let element = object.get("element").ok_or_else(|| {
        OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "expected XML typed child element is required",
        )
    })?;
    let element = element.as_str().ok_or_else(|| {
        OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "expected XML typed child element must be a string",
        )
    })?;
    if element.is_empty() {
        return Err(OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "expected XML typed child element cannot be empty",
        ));
    }
    for key in ["attributes", "sections"] {
        if let Some(value) = object.get(key) {
            let values = value.as_object().ok_or_else(|| {
                OracleError::new_for_cli(
                    ErrorCode::ManifestSchema,
                    format!("expected XML typed child {key} must be an object"),
                )
            })?;
            if values.values().any(|value| !value.is_string()) {
                return Err(OracleError::new_for_cli(
                    ErrorCode::ManifestSchema,
                    format!("expected XML typed child {key} must contain strings"),
                ));
            }
        }
    }
    if let Some(text) = object.get("text")
        && !text.is_string()
    {
        return Err(OracleError::new_for_cli(
            ErrorCode::ManifestSchema,
            "expected XML typed child text must be a string",
        ));
    }
    if let Some(assertions) = object.get("assertions") {
        validate_expected_assertions(assertions, "expected XML typed child assertions")?;
    }
    if let Some(children) = object.get("children") {
        let children = children.as_array().ok_or_else(|| {
            OracleError::new_for_cli(
                ErrorCode::ManifestSchema,
                "expected XML typed child children must be an array",
            )
        })?;
        if children.len() > limits.max_events {
            return Err(OracleError::new_for_cli(
                ErrorCode::OutputLimit,
                "expected XML typed child children exceed the event bound",
            ));
        }
        for child in children {
            validate_expected_xml_typed_child_descriptor(child, limits, depth + 1)?;
        }
    }
    Ok(())
}

fn compare_expected_assertions(
    actual: Option<&Value>,
    expected: &Value,
    path: &str,
    options: &CompareOptions,
    report: &mut CompareReport,
    wire_fields_declared: bool,
) {
    let Some(actual) = actual.and_then(Value::as_array) else {
        push_diff(report, options, path, "missing", Some(expected), actual);
        return;
    };
    let Some(expected) = expected.as_array() else {
        push_diff(
            report,
            options,
            path,
            "changed",
            Some(expected),
            Some(&Value::Array(actual.to_owned())),
        );
        return;
    };
    if actual.len() != expected.len() {
        push_diff(
            report,
            options,
            path,
            "changed",
            Some(&Value::Array(expected.clone())),
            Some(&Value::Array(actual.to_owned())),
        );
    }
    for (index, expected_assertion) in expected.iter().enumerate() {
        let assertion_path = format!("{path}/{index}");
        let Some(actual_assertion) = actual.get(index) else {
            push_diff(
                report,
                options,
                &assertion_path,
                "missing",
                Some(expected_assertion),
                None,
            );
            continue;
        };
        let Some(expected_fields) = expected_assertion.as_object() else {
            push_diff(
                report,
                options,
                &assertion_path,
                "changed",
                Some(expected_assertion),
                Some(actual_assertion),
            );
            continue;
        };
        for (field, expected_value) in expected_fields {
            compare_declared_value(
                actual_assertion.get(field),
                Some(expected_value),
                &format!("{assertion_path}/{field}"),
                options,
                report,
            );
        }
        if !wire_fields_declared && let Some(actual_fields) = actual_assertion.as_object() {
            for (field, actual_value) in actual_fields {
                if !expected_fields.contains_key(field) {
                    push_diff(
                        report,
                        options,
                        &format!("{assertion_path}/{field}"),
                        "unexpected",
                        None,
                        Some(actual_value),
                    );
                }
            }
        }
    }
}

fn compare_xml_sample(
    actual: &Value,
    expected: &Value,
    path: &str,
    allow_label_attribute: bool,
    wire_contract: Option<&Value>,
    options: &CompareOptions,
    report: &mut CompareReport,
) {
    compare_declared_value(
        actual.get("element"),
        expected.get("element"),
        &format!("{path}/element"),
        options,
        report,
    );
    compare_declared_value(
        actual.get("position"),
        expected.get("position"),
        &format!("{path}/position"),
        options,
        report,
    );
    let expected_attributes = expected.get("attributes").or_else(|| {
        expected
            .get("sample_contract")
            .and_then(|value| value.get("attributes"))
    });
    if let Some(attributes) = expected_attributes.and_then(Value::as_object) {
        let ignored = expected
            .get("ignored_attributes")
            .or_else(|| {
                expected
                    .get("sample_contract")
                    .and_then(|value| value.get("ignored_attributes"))
            })
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<BTreeSet<_>>()
            })
            .unwrap_or_default();
        let actual_attributes = actual.get("attributes").and_then(Value::as_object);
        for (attribute, expected_value) in attributes {
            if ignored.contains(attribute.as_str())
                || is_ignored_xml_attribute(attribute, path, options)
            {
                continue;
            }
            compare_declared_value(
                actual_attributes.and_then(|map| map.get(attribute)),
                Some(expected_value),
                &format!("{path}/attributes/{attribute}"),
                options,
                report,
            );
        }
        if let Some(actual_attributes) = actual_attributes {
            for (attribute, actual_value) in actual_attributes {
                if !attributes.contains_key(attribute)
                    && !ignored.contains(attribute.as_str())
                    && !is_ignored_xml_attribute(attribute, path, options)
                    && !(allow_label_attribute && attribute == "lb")
                {
                    push_diff(
                        report,
                        options,
                        &format!("{path}/attributes/{attribute}"),
                        "unexpected",
                        None,
                        Some(actual_value),
                    );
                }
            }
        }
    }
    if let Some(assertions) = expected.get("assertions") {
        let wire_fields_declared = expected
            .get("wire_children")
            .and_then(|value| value.get("assertion_child_elements"))
            .is_some()
            || wire_contract
                .and_then(|value| value.get("assertion_result"))
                .and_then(|value| value.get("child_order"))
                .is_some();
        compare_expected_assertions(
            actual.get("assertions"),
            assertions,
            &format!("{path}/assertions"),
            options,
            report,
            wire_fields_declared,
        );
    }
    for (expected_key, actual_key) in [
        ("response_code", "rc"),
        ("response_message", "rm"),
        ("label", "lb"),
    ] {
        if let Some(value) = expected.get(expected_key) {
            compare_declared_value(
                actual
                    .get("attributes")
                    .and_then(|attributes| attributes.get(actual_key)),
                Some(value),
                &format!("{path}/{expected_key}"),
                options,
                report,
            );
        }
    }
    if let Some(response_data) = expected.get("response_data") {
        compare_declared_value(
            actual
                .get("sections")
                .and_then(|sections| sections.get("responseData")),
            Some(response_data),
            &format!("{path}/response_data"),
            options,
            report,
        );
    }
    if let Some(response_file) = expected.get("response_file") {
        compare_declared_value(
            actual
                .get("sections")
                .and_then(|sections| sections.get("responseFile")),
            Some(response_file),
            &format!("{path}/response_file"),
            options,
            report,
        );
    }
    if let Some(absent_attributes) = expected.get("absent_attributes").and_then(Value::as_array) {
        let actual_attributes = actual.get("attributes").and_then(Value::as_object);
        for (index, attribute) in absent_attributes
            .iter()
            .filter_map(Value::as_str)
            .enumerate()
        {
            if let Some(actual_value) = actual_attributes.and_then(|map| map.get(attribute)) {
                push_diff(
                    report,
                    options,
                    &format!("{path}/absent_attributes/{index}"),
                    "unexpected",
                    None,
                    Some(actual_value),
                );
            }
        }
    }
    let mut declared_sections = BTreeSet::new();
    if expected.get("response_data").is_some() {
        declared_sections.insert("responseData".to_owned());
    }
    if expected.get("response_file").is_some() {
        declared_sections.insert("responseFile".to_owned());
    }
    if let Some(text) = expected.get("text") {
        compare_declared_value(
            actual.get("text"),
            Some(text),
            &format!("{path}/text"),
            options,
            report,
        );
    }
    if let Some(sections) = expected.get("sections") {
        if let Some(sections) = sections.as_object() {
            declared_sections.extend(sections.keys().cloned());
        }
        compare_declared_value(
            actual.get("sections"),
            Some(sections),
            &format!("{path}/sections"),
            options,
            report,
        );
    }
    match expected.get("children") {
        Some(Value::Array(expected_children)) => {
            let actual_typed_children = typed_child_event_values(actual);
            compare_declared_value(
                Some(&Value::Array(actual_typed_children)),
                Some(&Value::Array(expected_children.clone())),
                &format!("{path}/children"),
                options,
                report,
            );
        }
        Some(Value::Object(_)) => {}
        Some(expected_children) => {
            let actual_typed_children = typed_child_event_values(actual);
            push_diff(
                report,
                options,
                &format!("{path}/children"),
                "changed",
                Some(expected_children),
                Some(&Value::Array(actual_typed_children)),
            );
        }
        None => {
            if let Some(actual_children) = actual.get("children").and_then(Value::as_array)
                && !actual_children.is_empty()
                && expected.get("sub_results").is_none()
                && !expected_declares_child_stream(expected)
            {
                push_diff(
                    report,
                    options,
                    &format!("{path}/children"),
                    "unexpected",
                    None,
                    Some(&Value::Array(actual_children.clone())),
                );
            }
        }
    }
    if let Some(empty_children) = expected.get("empty_children").and_then(Value::as_array) {
        let actual_sections = actual.get("sections").and_then(Value::as_object);
        for child in empty_children.iter().filter_map(Value::as_str) {
            compare_declared_value(
                actual_sections.and_then(|map| map.get(child)),
                Some(&Value::String(String::new())),
                &format!("{path}/sections/{child}"),
                options,
                report,
            );
        }
    }
    let actual_sections = actual.get("sections").and_then(Value::as_object);
    if let Some(contains) = expected
        .get("sampler_data_contains")
        .and_then(Value::as_array)
    {
        declared_sections.insert("samplerData".to_owned());
        let data = actual_sections
            .and_then(|map| map.get("samplerData"))
            .and_then(Value::as_str)
            .unwrap_or("");
        for (index, needle) in contains.iter().filter_map(Value::as_str).enumerate() {
            if !data.contains(needle) {
                push_diff(
                    report,
                    options,
                    &format!("{path}/sections/samplerData/{index}"),
                    "missing",
                    Some(&Value::String(needle.to_owned())),
                    Some(&Value::String(data.to_owned())),
                );
            }
        }
    }
    if let Some(children) = expected.get("children").and_then(Value::as_object) {
        compare_xml_children_object(actual, children, path, options, report);
        if children.get("sampler_data_contains").is_some() {
            declared_sections.insert("samplerData".to_owned());
        }
        if children.get("response_headers").is_some() {
            declared_sections.insert("responseHeader".to_owned());
        }
        if children.get("request_headers").is_some() {
            declared_sections.insert("requestHeader".to_owned());
        }
        if children.get("response_data").is_some() {
            declared_sections.insert("responseData".to_owned());
        }
        if children.get("response_file").is_some() {
            declared_sections.insert("responseFile".to_owned());
        }
    }
    if let Some(wire_children) = expected.get("wire_children") {
        declared_sections.extend(wire_child_section_names(wire_children));
        compare_xml_wire_children(
            actual,
            wire_children,
            &format!("{path}/wire_children"),
            options,
            report,
        );
    }
    if let Some(wire_contract) = wire_contract {
        declared_sections.extend(wire_contract_section_names(wire_contract));
    }
    if let Some(unknown_children) = expected.get("unknown_children") {
        if let Some(children) = unknown_children.as_array() {
            declared_sections.extend(unknown_section_names(children));
        }
        compare_xml_unknown_children(
            actual,
            unknown_children,
            &format!("{path}/unknown_children"),
            options,
            report,
        );
    } else {
        let unknown_children = unknown_xml_child_values(actual);
        if !unknown_children.is_empty() {
            push_diff(
                report,
                options,
                &format!("{path}/unknown_children"),
                "unexpected",
                None,
                Some(&Value::Array(unknown_children)),
            );
        }
    }
    if let Some(absent_children) = expected.get("absent_children").and_then(Value::as_array) {
        let actual_children = child_event_values(actual);
        for (index, child) in absent_children.iter().filter_map(Value::as_str).enumerate() {
            if actual_children
                .iter()
                .any(|value| value.get("element").and_then(Value::as_str) == Some(child))
            {
                push_diff(
                    report,
                    options,
                    &format!("{path}/absent_children/{index}"),
                    "unexpected",
                    None,
                    Some(&Value::String(child.to_owned())),
                );
            }
        }
    }
    if let Some(debug) = expected.get("debug_response_projection") {
        declared_sections.insert("responseData".to_owned());
        compare_debug_projection(actual, debug, path, options, report);
    }
    if let Some(empty_children) = expected.get("empty_children").and_then(Value::as_array) {
        for child in empty_children.iter().filter_map(Value::as_str) {
            declared_sections.insert(child.to_owned());
        }
    }
    if let Some(sub_results) = expected.get("sub_results") {
        compare_sub_results_contract(
            actual,
            sub_results,
            &format!("{path}/sub_results"),
            options,
            report,
        );
    }
    if let Some(actual_sections) = actual_sections {
        let allow_declared_wire_duplicates =
            expected.get("wire_children").is_some() || wire_contract.is_some();
        for (section, value) in actual_sections {
            let duplicate_declared = allow_declared_wire_duplicates
                && section
                    .split_once('#')
                    .is_some_and(|(base, _)| declared_sections.contains(base));
            if !declared_sections.contains(section.as_str()) && !duplicate_declared {
                push_diff(
                    report,
                    options,
                    &format!("{path}/sections/{section}"),
                    "unexpected",
                    None,
                    Some(value),
                );
            }
        }
    }
}

fn doubled_xml_attribute_name(attribute: &str) -> String {
    attribute.replace('_', "__")
}

fn child_event_values(actual: &Value) -> Vec<Value> {
    actual
        .get("child_events")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn typed_child_event_values(actual: &Value) -> Vec<Value> {
    let mut position = 0_usize;
    child_event_values(actual)
        .into_iter()
        .filter(is_typed_xml_child)
        .map(|child| {
            let projection = typed_xml_child_projection(&child, position);
            position = position.saturating_add(1);
            projection
        })
        .collect()
}

fn is_typed_xml_child(child: &Value) -> bool {
    let Some(element) = child.get("element").and_then(Value::as_str) else {
        return false;
    };
    if element == "assertionResult" {
        return false;
    }
    if matches!(element, "sample" | "httpSample") {
        return true;
    }
    if is_jmeter_string_xml_child(child) {
        return false;
    }
    if is_known_xml_section_child(child) {
        return false;
    }
    true
}

fn is_jmeter_string_xml_child(child: &Value) -> bool {
    child
        .get("attributes")
        .and_then(|attributes| attributes.get("class"))
        .and_then(Value::as_str)
        == Some("java.lang.String")
}

fn is_known_xml_section_child(child: &Value) -> bool {
    let Some(element) = child.get("element").and_then(Value::as_str) else {
        return false;
    };
    matches!(
        element,
        "responseData" | "responseFile" | "responseHeader" | "requestHeader" | "samplerData"
    ) && child
        .get("attributes")
        .and_then(Value::as_object)
        .is_some_and(Map::is_empty)
        && child
            .get("children")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
}

fn typed_xml_child_projection(child: &Value, position: usize) -> Value {
    let raw_children = child
        .get("children")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut sections = BTreeMap::new();
    let mut assertions = Vec::new();
    let mut typed_children = Vec::new();
    let mut typed_position = 0_usize;
    for nested in &raw_children {
        if nested.get("element").and_then(Value::as_str) == Some("assertionResult") {
            assertions.push(xml_assertion_child_projection(nested));
        } else if (is_jmeter_string_xml_child(nested) || is_known_xml_section_child(nested))
            && let Some(element) = nested.get("element").and_then(Value::as_str)
        {
            let text = nested
                .get("text")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            let mut key = element.to_owned();
            if sections.contains_key(&key) {
                let mut duplicate = 2_usize;
                loop {
                    let candidate = format!("{element}#{duplicate}");
                    if !sections.contains_key(&candidate) {
                        key = candidate;
                        break;
                    }
                    duplicate = duplicate.saturating_add(1);
                }
            }
            sections.insert(key, text);
        }
        if is_typed_xml_child(nested) {
            typed_children.push(typed_xml_child_projection(nested, typed_position));
            typed_position = typed_position.saturating_add(1);
        }
    }
    let element = child
        .get("element")
        .cloned()
        .unwrap_or_else(|| Value::String(String::new()));
    let attributes = child
        .get("attributes")
        .cloned()
        .unwrap_or_else(|| Value::Object(Map::new()));
    let text = child
        .get("text")
        .cloned()
        .unwrap_or_else(|| Value::String(String::new()));
    let mut projection = Map::new();
    projection.insert("position".to_owned(), Value::from(position as u64));
    projection.insert("element".to_owned(), element);
    projection.insert("attributes".to_owned(), attributes);
    projection.insert("sections".to_owned(), string_value_map(&sections).into());
    projection.insert("text".to_owned(), text);
    if child
        .get("element")
        .and_then(Value::as_str)
        .is_some_and(|element| {
            matches!(element, "sample" | "httpSample") || is_url_element(element)
        })
    {
        projection.insert("assertions".to_owned(), Value::Array(assertions));
    }
    projection.insert("children".to_owned(), Value::Array(typed_children));
    Value::Object(projection)
}

fn xml_assertion_child_projection(child: &Value) -> Value {
    let mut fields = Map::new();
    if let Some(attributes) = child.get("attributes").and_then(Value::as_object) {
        for (name, value) in attributes {
            fields.insert(assertion_field_name(name).to_owned(), value.clone());
        }
    }
    if let Some(children) = child.get("children").and_then(Value::as_array) {
        for field in children {
            if let Some(name) = field.get("element").and_then(Value::as_str) {
                fields.insert(
                    assertion_field_name(name).to_owned(),
                    field
                        .get("text")
                        .cloned()
                        .unwrap_or_else(|| Value::String(String::new())),
                );
            }
        }
    }
    Value::Object(fields)
}

fn expected_declares_child_stream(expected: &Value) -> bool {
    let Some(expected) = expected.as_object() else {
        return false;
    };
    expected.contains_key("wire_children")
        || expected.contains_key("unknown_children")
        || expected.contains_key("wire_contract")
        || expected.get("children").is_some_and(Value::is_object)
}

fn wire_child_section_names(value: &Value) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let Some(object) = value.as_object() else {
        return names;
    };
    for key in ["string_children_class", "wire_child_order"] {
        if let Some(values) = object.get(key).and_then(Value::as_array) {
            for element in values.iter().filter_map(Value::as_str) {
                if !matches!(
                    element,
                    "assertionResult"
                        | "sample"
                        | "httpSample"
                        | "subresult"
                        | "java.net.URL"
                        | "URL"
                        | "url"
                ) {
                    names.insert(element.to_owned());
                }
            }
        }
    }
    names
}

fn unknown_section_names(children: &[Value]) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let mut occurrences = BTreeMap::<String, usize>::new();
    for name in children
        .iter()
        .filter_map(|child| child.get("name"))
        .filter_map(Value::as_str)
    {
        let occurrence = occurrences.entry(name.to_owned()).or_insert(0);
        *occurrence = occurrence.saturating_add(1);
        let key = if *occurrence == 1 {
            name.to_owned()
        } else {
            format!("{name}#{occurrence}")
        };
        names.insert(key);
    }
    names
}

fn wire_contract_section_names(value: &Value) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let Some(object) = value.as_object() else {
        return names;
    };
    for key in ["child_order", "wire_order"] {
        if let Some(values) = object.get(key).and_then(Value::as_array) {
            for element in values.iter().filter_map(Value::as_str) {
                if !matches!(
                    element,
                    "assertionResult"
                        | "sample"
                        | "httpSample"
                        | "subresult"
                        | "java.net.URL"
                        | "URL"
                        | "url"
                ) {
                    names.insert(element.to_owned());
                }
            }
        }
    }
    if let Some(values) = object.get("string_children").and_then(Value::as_array) {
        for element in values
            .iter()
            .filter_map(|child| child.get("element"))
            .filter_map(Value::as_str)
        {
            names.insert(element.to_owned());
        }
    }
    names
}

fn unknown_xml_child_values(actual: &Value) -> Vec<Value> {
    child_event_values(actual)
        .into_iter()
        .filter(|child| {
            child
                .get("element")
                .and_then(Value::as_str)
                .is_some_and(|element| !is_known_xml_child(element))
        })
        .collect()
}

fn compare_xml_wire_contract(
    actual: &Value,
    expected: &Value,
    path: &str,
    options: &CompareOptions,
    report: &mut CompareReport,
) {
    let Some(expected) = expected.as_object() else {
        push_diff(report, options, path, "changed", Some(expected), None);
        return;
    };
    let children = child_event_values(actual);
    for (key, expected_value) in expected {
        // A document-level contract describes optional writer children across
        // heterogeneous samples.  An empty sample has no wire stream to
        // compare here; sample-local `wire_children` descriptors remain
        // strict and still assert an explicitly expected empty/non-empty
        // stream.
        if children.is_empty()
            && matches!(
                key.as_str(),
                "child_order" | "wire_order" | "string_children" | "url_child"
            )
        {
            continue;
        }
        match key.as_str() {
            "child_order" | "wire_order" => {
                let actual_value = Value::Array(distinct_child_kinds(&children));
                compare_ordered_contract(
                    &actual_value,
                    expected_value,
                    &format!("{path}/{key}"),
                    options,
                    report,
                );
            }
            "string_children" => {
                let actual_value = Value::Array(
                    children
                        .iter()
                        .filter(|child| {
                            child
                                .get("attributes")
                                .and_then(|attributes| attributes.get("class"))
                                .is_some_and(|class| class == "java.lang.String")
                        })
                        .map(|child| {
                            json!({
                                "element": child.get("element").cloned().unwrap_or(Value::Null),
                                "class": child
                                    .get("attributes")
                                    .and_then(|attributes| attributes.get("class"))
                                    .cloned()
                                    .unwrap_or(Value::Null),
                            })
                        })
                        .collect(),
                );
                compare_ordered_contract(
                    &actual_value,
                    expected_value,
                    &format!("{path}/{key}"),
                    options,
                    report,
                );
            }
            "url_child" => {
                let actual_urls: Vec<&Value> = children
                    .iter()
                    .filter(|child| {
                        child
                            .get("element")
                            .and_then(Value::as_str)
                            .is_some_and(is_url_element)
                    })
                    .collect();
                let actual_url = actual_urls.first().map(|child| {
                    json!({
                        // URL aliases are a semantic descriptor concern. The
                        // ordered child stream above remains wire-exact.
                        "element": "java.net.URL",
                        "class": child
                            .get("attributes")
                            .and_then(|attributes| attributes.get("class"))
                            .cloned()
                            .unwrap_or(Value::Null),
                    })
                });
                let expected_url = canonical_url_descriptor(expected_value);
                compare_declared_value(
                    actual_url.as_ref(),
                    Some(&expected_url),
                    &format!("{path}/{key}"),
                    options,
                    report,
                );
                if actual_urls.len() > 1 {
                    push_diff(
                        report,
                        options,
                        &format!("{path}/{key}"),
                        "changed",
                        Some(expected_value),
                        Some(&Value::Array(
                            actual_urls
                                .iter()
                                .map(|child| child.get("element").cloned().unwrap_or(Value::Null))
                                .collect(),
                        )),
                    );
                }
            }
            "assertion_result" => {
                let Some(assertion_contract) = expected_value.as_object() else {
                    push_diff(
                        report,
                        options,
                        &format!("{path}/{key}"),
                        "changed",
                        Some(expected_value),
                        None,
                    );
                    continue;
                };
                compare_wire_contract_constant(
                    assertion_contract.get("representation"),
                    "child-elements",
                    &format!("{path}/{key}/representation"),
                    options,
                    report,
                );
                if let Some(child_order) = assertion_contract.get("child_order") {
                    compare_all_assertion_child_elements(
                        &children,
                        child_order,
                        &format!("{path}/{key}/child_order"),
                        options,
                        report,
                    );
                }
            }
            "sample_variable_attributes" => {
                compare_wire_contract_constant(
                    expected_value.get("spelling"),
                    "exact-configured-name",
                    &format!("{path}/{key}/spelling"),
                    options,
                    report,
                );
                if let Some(names) = expected_value
                    .get("configured_names")
                    .and_then(Value::as_array)
                {
                    let actual_attributes = actual.get("attributes").and_then(Value::as_object);
                    let underscore_doubling = expected_value
                        .get("underscore_doubling")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    for (index, name) in names.iter().filter_map(Value::as_str).enumerate() {
                        let wire_name = if underscore_doubling {
                            doubled_xml_attribute_name(name)
                        } else {
                            name.to_owned()
                        };
                        if actual_attributes
                            .and_then(|attributes| attributes.get(&wire_name))
                            .is_none()
                        {
                            push_diff(
                                report,
                                options,
                                &format!("{path}/{key}/configured_names/{index}"),
                                "missing",
                                Some(&Value::String(wire_name.clone())),
                                None,
                            );
                        }
                        let alternate = if underscore_doubling {
                            name
                        } else {
                            &doubled_xml_attribute_name(name)
                        };
                        if alternate != wire_name
                            && actual_attributes
                                .is_some_and(|attributes| attributes.contains_key(alternate))
                        {
                            push_diff(
                                report,
                                options,
                                &format!("{path}/{key}/configured_names/{index}"),
                                "changed",
                                Some(&Value::String(wire_name)),
                                actual_attributes.and_then(|attributes| attributes.get(alternate)),
                            );
                        }
                    }
                }
            }
            "response_file" | "response_data" => {
                let expected_presence = expected_value
                    .get("expected")
                    .and_then(Value::as_bool)
                    .or_else(|| {
                        expected_value
                            .get("on_error")
                            .and_then(Value::as_bool)
                            .map(|on_error| {
                                let failed = actual
                                    .get("attributes")
                                    .and_then(|attributes| attributes.get("s"))
                                    .and_then(Value::as_str)
                                    .is_some_and(|success| success.eq_ignore_ascii_case("false"));
                                on_error && failed
                            })
                    })
                    .or_else(|| expected_value.get("enabled").and_then(Value::as_bool));
                if let Some(expected_presence) = expected_presence {
                    let element = if key == "response_file" {
                        "responseFile"
                    } else {
                        "responseData"
                    };
                    let actual_presence = children
                        .iter()
                        .any(|child| child.get("element").and_then(Value::as_str) == Some(element));
                    compare_declared_value(
                        Some(&Value::Bool(actual_presence)),
                        Some(&Value::Bool(expected_presence)),
                        &format!("{path}/{key}/expected"),
                        options,
                        report,
                    );
                }
                if let Some(resource_reference) = expected_value.get("resource_reference") {
                    let element = if key == "response_file" {
                        "responseFile"
                    } else {
                        "responseData"
                    };
                    let actual_value = children
                        .iter()
                        .find(|child| child.get("element").and_then(Value::as_str) == Some(element))
                        .and_then(|child| child.get("text"));
                    compare_declared_value(
                        actual_value,
                        Some(resource_reference),
                        &format!("{path}/{key}/resource_reference"),
                        options,
                        report,
                    );
                }
                if let Some(expected_policy) =
                    expected_value.get("expected").and_then(Value::as_str)
                {
                    let canonical = if key == "response_file" {
                        "only-if-sample-filename-present"
                    } else {
                        "only-if-sample-failed"
                    };
                    compare_wire_contract_constant(
                        Some(&Value::String(expected_policy.to_owned())),
                        canonical,
                        &format!("{path}/{key}/expected"),
                        options,
                        report,
                    );
                }
            }
            "timestamp" => {
                compare_wire_contract_constant(
                    expected_value.get("format"),
                    "XML-millisecond-attribute",
                    &format!("{path}/{key}/format"),
                    options,
                    report,
                );
                if let Some(attribute) = expected_value.get("attribute").and_then(Value::as_str) {
                    let present = actual
                        .get("attributes")
                        .and_then(|attributes| attributes.get(attribute))
                        .is_some();
                    compare_declared_value(
                        Some(&Value::Bool(present)),
                        Some(&Value::Bool(true)),
                        &format!("{path}/{key}/attribute"),
                        options,
                        report,
                    );
                }
                if let Some(source) = expected_value.get("source") {
                    let timestamp_starts = expected_value
                        .get("sampleresult.timestamp.start")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    let actual_source = actual
                        .get("attributes")
                        .and_then(|attributes| attributes.get("ts"))
                        .map(|_| {
                            if timestamp_starts {
                                "sample-start"
                            } else {
                                "sample-end"
                            }
                        })
                        .unwrap_or(if timestamp_starts {
                            "sample-start"
                        } else {
                            "sample-end"
                        });
                    compare_declared_value(
                        Some(&Value::String(actual_source.to_owned())),
                        Some(source),
                        &format!("{path}/{key}/source"),
                        options,
                        report,
                    );
                }
                for field in [
                    "sampleresult.timestamp.start",
                    "formatted_timestamp_fallback",
                ] {
                    if let Some(expected_boolean) = expected_value.get(field) {
                        compare_declared_value(
                            Some(&Value::Bool(false)),
                            Some(expected_boolean),
                            &format!("{path}/{key}/{field}"),
                            options,
                            report,
                        );
                    }
                }
            }
            // These are validated wire-contract metadata.  Their meaning is
            // configuration/provenance rather than an additional JTL field;
            // retaining them in the validated envelope avoids silently
            // accepting misspelled extensions.
            "response_file_policy" => compare_wire_contract_constant(
                Some(expected_value),
                "only when filename saving is enabled",
                &format!("{path}/{key}"),
                options,
                report,
            ),
            _ => push_diff(
                report,
                options,
                &format!("{path}/{key}"),
                "unsupported",
                Some(expected_value),
                None,
            ),
        }
    }
}

fn distinct_child_kinds(children: &[Value]) -> Vec<Value> {
    children
        .iter()
        .filter_map(|child| {
            child.get("element").and_then(Value::as_str).map(|element| {
                if matches!(element, "sample" | "httpSample") {
                    Value::String("subresult".to_owned())
                } else {
                    Value::String(element.to_owned())
                }
            })
        })
        .collect()
}

fn compare_wire_contract_constant(
    declared: Option<&Value>,
    canonical: impl Into<Value>,
    path: &str,
    options: &CompareOptions,
    report: &mut CompareReport,
) {
    let Some(declared) = declared else {
        return;
    };
    let canonical = canonical.into();
    compare_declared_value(Some(&canonical), Some(declared), path, options, report);
}

/// Compare an ordered wire contract without collapsing repeated elements.
/// An omitted, reordered, or duplicated child cannot pass unnoticed.
fn compare_ordered_contract(
    actual: &Value,
    expected: &Value,
    path: &str,
    options: &CompareOptions,
    report: &mut CompareReport,
) {
    compare_declared_value(Some(actual), Some(expected), path, options, report);
}

fn compare_xml_wire_children(
    actual: &Value,
    expected: &Value,
    path: &str,
    options: &CompareOptions,
    report: &mut CompareReport,
) {
    let Some(expected) = expected.as_object() else {
        push_diff(report, options, path, "changed", Some(expected), None);
        return;
    };
    let children = child_event_values(actual);
    for (key, expected_value) in expected {
        match key.as_str() {
            "wire_child_order" => {
                let actual_value = Value::Array(
                    children
                        .iter()
                        .filter_map(|child| child.get("element").cloned())
                        .collect(),
                );
                compare_declared_value(
                    Some(&actual_value),
                    Some(expected_value),
                    &format!("{path}/{key}"),
                    options,
                    report,
                );
            }
            "string_children_class" => {
                let actual_value = Value::Array(
                    children
                        .iter()
                        .filter(|child| {
                            child
                                .get("attributes")
                                .and_then(|attributes| attributes.get("class"))
                                .and_then(Value::as_str)
                                == Some("java.lang.String")
                        })
                        .filter_map(|child| child.get("element").cloned())
                        .collect(),
                );
                compare_ordered_contract(
                    &actual_value,
                    expected_value,
                    &format!("{path}/{key}"),
                    options,
                    report,
                );
            }
            "assertion_child_elements" => {
                compare_all_assertion_child_elements(
                    &children,
                    expected_value,
                    &format!("{path}/{key}"),
                    options,
                    report,
                );
            }
            _ => push_diff(
                report,
                options,
                &format!("{path}/{key}"),
                "unsupported",
                Some(expected_value),
                None,
            ),
        }
    }
}

fn compare_assertion_child_elements(
    actual: Option<&Value>,
    expected: &Value,
    path: &str,
    options: &CompareOptions,
    report: &mut CompareReport,
) {
    let Some(actual) = actual.and_then(Value::as_array) else {
        push_diff(report, options, path, "missing", Some(expected), actual);
        return;
    };
    let Some(expected) = expected.as_array() else {
        push_diff(
            report,
            options,
            path,
            "changed",
            Some(expected),
            Some(&Value::Array(actual.to_owned())),
        );
        return;
    };
    let optional_failure_message = expected
        .last()
        .and_then(Value::as_str)
        .is_some_and(|name| matches!(name, "failureMessage" | "errorMessage"));
    let exact_match = actual.len() == expected.len()
        && actual
            .iter()
            .zip(expected)
            .all(|(actual, expected)| actual == expected);
    let optional_match = optional_failure_message
        && actual.len().saturating_add(1) == expected.len()
        && actual
            .iter()
            .zip(expected.iter().take(expected.len().saturating_sub(1)))
            .all(|(actual, expected)| actual == expected);
    if !exact_match && !optional_match {
        push_diff(
            report,
            options,
            path,
            "changed",
            Some(&Value::Array(expected.clone())),
            Some(&Value::Array(actual.to_owned())),
        );
    }
}

fn compare_all_assertion_child_elements(
    children: &[Value],
    expected: &Value,
    path: &str,
    options: &CompareOptions,
    report: &mut CompareReport,
) {
    let assertions: Vec<&Value> = children
        .iter()
        .filter(|child| child.get("element").and_then(Value::as_str) == Some("assertionResult"))
        .collect();
    if assertions.is_empty() {
        return;
    }
    for (index, assertion) in assertions.iter().enumerate() {
        let actual_value = Value::Array(
            assertion
                .get("children")
                .and_then(Value::as_array)
                .map(|children| {
                    children
                        .iter()
                        .filter_map(|child| child.get("element").cloned())
                        .collect()
                })
                .unwrap_or_default(),
        );
        compare_assertion_child_elements(
            Some(&actual_value),
            expected,
            &format!("{path}/{index}"),
            options,
            report,
        );
    }
}

fn compare_xml_unknown_children(
    actual: &Value,
    expected: &Value,
    path: &str,
    options: &CompareOptions,
    report: &mut CompareReport,
) {
    let actual_children = child_event_values(actual);
    let Some(expected_children) = expected.as_array() else {
        let actual = actual_children
            .iter()
            .map(unknown_child_projection)
            .collect::<Vec<_>>();
        compare_declared_value(
            Some(&Value::Array(actual)),
            Some(expected),
            path,
            options,
            report,
        );
        return;
    };
    let expected = expected_children
        .iter()
        .map(normalize_unknown_child_expectation)
        .collect::<Vec<_>>();
    let actual: Vec<Value> = actual_children
        .into_iter()
        .filter(|child| {
            child
                .get("element")
                .and_then(Value::as_str)
                .is_some_and(|element| !is_known_xml_child(element))
        })
        .enumerate()
        .map(|(index, child)| {
            let mut projection = unknown_child_projection(&child);
            if let Some(descriptor) = expected.get(index) {
                strip_unspecified_unknown_positions(&mut projection, descriptor);
            }
            projection
        })
        .collect();
    compare_declared_value(
        Some(&Value::Array(actual)),
        Some(&Value::Array(expected)),
        path,
        options,
        report,
    );
}

fn strip_unspecified_unknown_positions(actual: &mut Value, expected: &Value) {
    let Some(actual_object) = actual.as_object_mut() else {
        return;
    };
    let expected_object = expected.as_object();
    if !expected_object.is_some_and(|object| object.contains_key("position")) {
        actual_object.remove("position");
    }
    let Some(actual_children) = actual_object
        .get_mut("children")
        .and_then(Value::as_array_mut)
    else {
        return;
    };
    let Some(expected_children) = expected_object
        .and_then(|object| object.get("children"))
        .and_then(Value::as_array)
    else {
        return;
    };
    for (actual_child, expected_child) in actual_children.iter_mut().zip(expected_children) {
        strip_unspecified_unknown_positions(actual_child, expected_child);
    }
}

fn unknown_child_projection(child: &Value) -> Value {
    let mut projection = Map::new();
    if let Some(position) = child.get("position") {
        projection.insert("position".to_owned(), position.clone());
    }
    if let Some(element) = child.get("element") {
        projection.insert("name".to_owned(), element.clone());
    }
    if let Some(class) = child
        .get("attributes")
        .and_then(|attributes| attributes.get("class"))
    {
        projection.insert("class".to_owned(), class.clone());
    }
    if let Some(attributes) = child.get("attributes").and_then(Value::as_object) {
        let additional = attributes
            .iter()
            .filter(|(key, _)| key.as_str() != "class")
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Map<String, Value>>();
        if !additional.is_empty() {
            projection.insert("attributes".to_owned(), Value::Object(additional));
        }
    }
    if let Some(text) = child.get("text") {
        projection.insert("value".to_owned(), text.clone());
    }
    if let Some(children) = child.get("children").and_then(Value::as_array)
        && !children.is_empty()
    {
        projection.insert(
            "children".to_owned(),
            Value::Array(children.iter().map(unknown_child_projection).collect()),
        );
    }
    Value::Object(projection)
}

fn normalize_unknown_child_expectation(value: &Value) -> Value {
    let Some(object) = value.as_object() else {
        return value.clone();
    };
    let mut normalized = object.clone();
    if !normalized.contains_key("value") {
        if let Some(text) = normalized.remove("text") {
            normalized.insert("value".to_owned(), text);
        }
    } else {
        normalized.remove("text");
    }
    Value::Object(normalized)
}

fn is_known_xml_child(element: &str) -> bool {
    matches!(
        element,
        "assertionResult"
            | "sample"
            | "httpSample"
            | "responseData"
            | "responseFile"
            | "responseHeader"
            | "requestHeader"
            | "samplerData"
            | "java.net.URL"
            | "URL"
            | "url"
    )
}

/// URL is a typed JMeter child whose writer spelling is `java.net.URL`.
/// Reader/descriptor variants sometimes shorten that spelling to `URL` or
/// `url`; those aliases are accepted only for the URL semantic descriptor.
/// Ordered wire-child projections still expose the original tag verbatim.
fn is_url_element(element: &str) -> bool {
    matches!(element, "java.net.URL" | "URL" | "url")
}

fn canonical_url_descriptor(value: &Value) -> Value {
    let Some(object) = value.as_object() else {
        return value.clone();
    };
    let mut canonical = object.clone();
    if object
        .get("element")
        .and_then(Value::as_str)
        .is_some_and(is_url_element)
    {
        canonical.insert("element".to_owned(), Value::String("java.net.URL".into()));
    }
    if object
        .get("name")
        .and_then(Value::as_str)
        .is_some_and(is_url_element)
    {
        canonical.insert("name".to_owned(), Value::String("java.net.URL".into()));
    }
    Value::Object(canonical)
}

fn compare_xml_children_object(
    actual: &Value,
    expected: &Map<String, Value>,
    path: &str,
    options: &CompareOptions,
    report: &mut CompareReport,
) {
    let actual_sections = actual.get("sections").and_then(Value::as_object);
    for (key, expected_value) in expected {
        match key.as_str() {
            "response_data" => compare_declared_value(
                actual_sections.and_then(|sections| sections.get("responseData")),
                Some(expected_value),
                &format!("{path}/children/{key}"),
                options,
                report,
            ),
            "response_file" => compare_declared_value(
                actual_sections.and_then(|sections| sections.get("responseFile")),
                Some(expected_value),
                &format!("{path}/children/{key}"),
                options,
                report,
            ),
            "response_headers" => compare_declared_value(
                actual_sections.and_then(|sections| sections.get("responseHeader")),
                Some(expected_value),
                &format!("{path}/children/{key}"),
                options,
                report,
            ),
            "request_headers" => compare_declared_value(
                actual_sections.and_then(|sections| sections.get("requestHeader")),
                Some(expected_value),
                &format!("{path}/children/{key}"),
                options,
                report,
            ),
            "sampler_data_contains" => compare_sampler_data_contains(
                actual_sections,
                expected_value,
                &format!("{path}/children/{key}"),
                options,
                report,
            ),
            "string_children_class" | "wire_child_order" | "assertion_child_elements" => {
                compare_xml_wire_children(
                    actual,
                    &json!({key: expected_value}),
                    &format!("{path}/children"),
                    options,
                    report,
                );
            }
            "url_element" => {
                let actual_urls: Vec<Value> = child_event_values(actual)
                    .into_iter()
                    .filter(|child| {
                        child
                            .get("element")
                            .and_then(Value::as_str)
                            .is_some_and(is_url_element)
                    })
                    .collect();
                let actual_url = actual_urls.first().map(|child| {
                    json!({
                        "name": "java.net.URL",
                        "value": child.get("text").cloned().unwrap_or(Value::Null),
                    })
                });
                let expected_url = canonical_url_descriptor(expected_value);
                compare_declared_value(
                    actual_url.as_ref(),
                    Some(&expected_url),
                    &format!("{path}/children/{key}"),
                    options,
                    report,
                );
                if actual_urls.len() > 1 {
                    push_diff(
                        report,
                        options,
                        &format!("{path}/children/{key}"),
                        "changed",
                        Some(expected_value),
                        Some(&Value::Array(actual_urls)),
                    );
                }
            }
            "assertions" => {
                compare_expected_assertions(
                    actual.get("assertions"),
                    expected_value,
                    &format!("{path}/children/{key}"),
                    options,
                    report,
                    expected.get("assertion_child_elements").is_some(),
                );
            }
            "response_data_reason" => push_diff(
                report,
                options,
                &format!("{path}/children/{key}"),
                "unsupported",
                Some(expected_value),
                None,
            ),
            _ => {}
        }
    }
}

fn compare_sampler_data_contains(
    sections: Option<&Map<String, Value>>,
    expected: &Value,
    path: &str,
    options: &CompareOptions,
    report: &mut CompareReport,
) {
    let data = sections
        .and_then(|sections| sections.get("samplerData"))
        .and_then(Value::as_str)
        .unwrap_or("");
    if let Some(values) = expected.as_array() {
        for (index, value) in values.iter().enumerate() {
            if let Some(needle) = value.as_str()
                && !data.contains(needle)
            {
                push_diff(
                    report,
                    options,
                    &format!("{path}/{index}"),
                    "missing",
                    Some(value),
                    Some(&Value::String(data.to_owned())),
                );
            }
        }
    }
}

fn compare_sub_results_contract(
    actual: &Value,
    expected: &Value,
    path: &str,
    options: &CompareOptions,
    report: &mut CompareReport,
) {
    let actual_children = actual
        .get("children")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let Some(expected) = expected.as_object() else {
        push_diff(
            report,
            options,
            path,
            "changed",
            Some(expected),
            Some(&Value::Array(actual_children)),
        );
        return;
    };
    if let Some(count) = expected.get("count") {
        compare_declared_value(
            Some(&Value::from(actual_children.len() as u64)),
            Some(count),
            &format!("{path}/count"),
            options,
            report,
        );
    }
    if let Some(labels) = expected.get("ordered_labels") {
        let actual_labels: Vec<Value> = actual_children
            .iter()
            .map(|child| {
                child
                    .get("attributes")
                    .and_then(|attributes| attributes.get("lb"))
                    .cloned()
                    .unwrap_or(Value::Null)
            })
            .collect();
        compare_declared_value(
            Some(&Value::Array(actual_labels)),
            Some(labels),
            &format!("{path}/ordered_labels"),
            options,
            report,
        );
    }
    if let Some(expected_nested_value) = expected.get("nested") {
        if let Some(expected_nested) = expected_nested_value.as_array() {
            if actual_children.len() != expected_nested.len() {
                push_diff(
                    report,
                    options,
                    &format!("{path}/nested"),
                    "changed",
                    Some(&Value::Array(expected_nested.clone())),
                    Some(&Value::Array(actual_children.clone())),
                );
            }
            for (index, expected_child) in expected_nested.iter().enumerate() {
                let child_path = format!("{path}/nested/{index}");
                let Some(actual_child) = actual_children.get(index) else {
                    push_diff(
                        report,
                        options,
                        &child_path,
                        "missing",
                        Some(expected_child),
                        None,
                    );
                    continue;
                };
                compare_sub_result_descriptor(
                    actual_child,
                    expected_child,
                    &child_path,
                    options,
                    report,
                );
            }
        } else {
            push_diff(
                report,
                options,
                &format!("{path}/nested"),
                "changed",
                Some(expected_nested_value),
                Some(&Value::Array(actual_children.clone())),
            );
        }
    }
}

fn compare_sub_result_descriptor(
    actual: &Value,
    expected: &Value,
    path: &str,
    options: &CompareOptions,
    report: &mut CompareReport,
) {
    let Some(expected) = expected.as_object() else {
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
    for key in [
        "element",
        "position",
        "text",
        "attributes",
        "assertions",
        "sections",
    ] {
        if let Some(expected_value) = expected.get(key) {
            compare_declared_value(
                actual.get(key),
                Some(expected_value),
                &format!("{path}/{key}"),
                options,
                report,
            );
        }
    }
    if let Some(expected_label) = expected.get("label") {
        compare_declared_value(
            actual
                .get("attributes")
                .and_then(|attributes| attributes.get("lb")),
            Some(expected_label),
            &format!("{path}/label"),
            options,
            report,
        );
    }
    match expected.get("children") {
        Some(Value::Array(expected_children)) => {
            let actual_children = actual
                .get("children")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            if actual_children.len() != expected_children.len() {
                push_diff(
                    report,
                    options,
                    &format!("{path}/children"),
                    "changed",
                    Some(&Value::Array(expected_children.clone())),
                    Some(&Value::Array(actual_children.clone())),
                );
            }
            for (index, expected_child) in expected_children.iter().enumerate() {
                let child_path = format!("{path}/children/{index}");
                let Some(actual_child) = actual_children.get(index) else {
                    push_diff(
                        report,
                        options,
                        &child_path,
                        "missing",
                        Some(expected_child),
                        None,
                    );
                    continue;
                };
                compare_sub_result_descriptor(
                    actual_child,
                    expected_child,
                    &child_path,
                    options,
                    report,
                );
            }
        }
        Some(Value::Object(_)) => {}
        Some(expected_children) => push_diff(
            report,
            options,
            &format!("{path}/children"),
            "changed",
            Some(expected_children),
            actual.get("children"),
        ),
        None => {
            if let Some(actual_children) = actual.get("children").and_then(Value::as_array)
                && !actual_children.is_empty()
                && expected.get("sub_results").is_none()
            {
                push_diff(
                    report,
                    options,
                    &format!("{path}/children"),
                    "unexpected",
                    None,
                    Some(&Value::Array(actual_children.clone())),
                );
            }
        }
    }
    if let Some(expected_sub_results) = expected.get("sub_results") {
        compare_sub_results_contract(
            actual,
            expected_sub_results,
            &format!("{path}/sub_results"),
            options,
            report,
        );
    }
    if let Some(wire_children) = expected.get("wire_children") {
        compare_xml_wire_children(
            actual,
            wire_children,
            &format!("{path}/wire_children"),
            options,
            report,
        );
    }
    if let Some(unknown_children) = expected.get("unknown_children") {
        compare_xml_unknown_children(
            actual,
            unknown_children,
            &format!("{path}/unknown_children"),
            options,
            report,
        );
    } else {
        let unknown_children = unknown_xml_child_values(actual);
        if !unknown_children.is_empty() {
            push_diff(
                report,
                options,
                &format!("{path}/unknown_children"),
                "unexpected",
                None,
                Some(&Value::Array(unknown_children)),
            );
        }
    }
}

fn compare_debug_projection(
    actual: &Value,
    expected: &Value,
    path: &str,
    options: &CompareOptions,
    report: &mut CompareReport,
) {
    let data = actual
        .get("sections")
        .and_then(|sections| sections.get("responseData"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let expected_sections = expected
        .get("required_sections")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for (index, section) in expected_sections
        .iter()
        .filter_map(Value::as_str)
        .enumerate()
    {
        if !data.lines().any(|line| line.trim_end() == section) {
            push_diff(
                report,
                options,
                &format!("{path}/debug_response_projection/required_sections/{index}"),
                "missing",
                Some(&Value::String(section.to_owned())),
                Some(&Value::String(data.to_owned())),
            );
        }
    }
    let projection = parse_debug_sections(data, &options.ignored_line_patterns);
    for (kind, key) in [
        ("variables", "JMeterVariables:"),
        ("properties", "JMeterProperties:"),
    ] {
        let Some(expected_values) = expected.get(kind).and_then(Value::as_object) else {
            continue;
        };
        let actual_values = projection.get(key);
        for (name, expected_value) in expected_values {
            compare_declared_value(
                actual_values.and_then(|values| values.get(name)),
                Some(expected_value),
                &format!("{path}/debug_response_projection/{kind}/{name}"),
                options,
                report,
            );
        }
    }
}

fn parse_debug_sections(
    text: &str,
    ignored_patterns: &[String],
) -> BTreeMap<String, BTreeMap<String, Value>> {
    let mut sections: BTreeMap<String, BTreeMap<String, Value>> = BTreeMap::new();
    let mut current = String::new();
    for line in text.lines() {
        if ignored_patterns
            .iter()
            .any(|pattern| wildcard_match(pattern, line))
        {
            continue;
        }
        let line = line.trim_end_matches('\r');
        if line.ends_with(':') && !line.contains('=') {
            current = line.to_owned();
            sections.entry(current.clone()).or_default();
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        if current.is_empty() {
            continue;
        }
        sections
            .entry(current.clone())
            .or_default()
            .insert(name.to_owned(), Value::String(value.to_owned()));
    }
    sections
}

/// Validate the deliberately small wildcard language used for dynamic debug
/// lines.  The language is bounded and deterministic: `.*` matches a sequence
/// of characters, a backslash quotes the following character, and
/// parenthesized `|` alternatives are expanded up to a fixed limit.  It is
/// intentionally not a general regular-expression engine.
fn valid_line_pattern(pattern: &str) -> bool {
    expand_pattern_alternatives(pattern).is_some()
}

fn wildcard_match(pattern: &str, text: &str) -> bool {
    let pattern = pattern.strip_prefix('^').unwrap_or(pattern);
    let pattern = pattern.strip_suffix('$').unwrap_or(pattern);
    let Some(alternatives) = expand_pattern_alternatives(pattern) else {
        return false;
    };
    alternatives
        .iter()
        .any(|alternative| wildcard_match_inner(alternative, text))
}

fn wildcard_match_inner(pattern: &str, text: &str) -> bool {
    let Some(tokens) = wildcard_tokens(pattern) else {
        return false;
    };
    let text: Vec<char> = text.chars().collect();
    // This is the standard greedy glob matcher.  It uses O(pattern + text)
    // memory and linear backtracking to the most recent `.*`, avoiding a
    // pattern-by-response-size matrix for untrusted debug output.
    let mut pattern_index = 0_usize;
    let mut text_index = 0_usize;
    let mut star_index = None;
    let mut star_text_index = 0_usize;
    while text_index < text.len() {
        if let Some(WildcardToken::Literal(character)) = tokens.get(pattern_index)
            && *character == text[text_index]
        {
            pattern_index = pattern_index.saturating_add(1);
            text_index = text_index.saturating_add(1);
        } else if tokens.get(pattern_index) == Some(&WildcardToken::AnyMany) {
            star_index = Some(pattern_index);
            pattern_index = pattern_index.saturating_add(1);
            star_text_index = text_index;
        } else if let Some(star_index) = star_index {
            pattern_index = star_index.saturating_add(1);
            star_text_index = star_text_index.saturating_add(1);
            text_index = star_text_index;
        } else {
            return false;
        }
    }
    while tokens.get(pattern_index) == Some(&WildcardToken::AnyMany) {
        pattern_index = pattern_index.saturating_add(1);
    }
    pattern_index == tokens.len()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WildcardToken {
    Literal(char),
    AnyMany,
}

fn wildcard_tokens(pattern: &str) -> Option<Vec<WildcardToken>> {
    let characters: Vec<char> = pattern.chars().collect();
    let mut tokens = Vec::with_capacity(characters.len());
    let mut index = 0_usize;
    while index < characters.len() {
        match characters[index] {
            '\\' => {
                index = index.saturating_add(1);
                let escaped = *characters.get(index)?;
                tokens.push(WildcardToken::Literal(escaped));
            }
            '.' if characters.get(index.saturating_add(1)) == Some(&'*') => {
                tokens.push(WildcardToken::AnyMany);
                index = index.saturating_add(1);
            }
            character => tokens.push(WildcardToken::Literal(character)),
        }
        index = index.saturating_add(1);
    }
    Some(tokens)
}

/// Expand top-level parenthesized alternatives without relying on an
/// unbounded regex backtracker.  A malformed/unbalanced group or an expansion
/// beyond the hard cap is rejected by validation and simply cannot match.
fn expand_pattern_alternatives(pattern: &str) -> Option<Vec<String>> {
    expand_pattern_alternatives_at_depth(pattern, 0)
}

fn expand_pattern_alternatives_at_depth(pattern: &str, depth: usize) -> Option<Vec<String>> {
    if depth > MAX_PATTERN_GROUP_DEPTH {
        return None;
    }
    let characters: Vec<char> = pattern.chars().collect();
    let Some(open) = characters
        .iter()
        .enumerate()
        .find_map(|(index, character)| {
            (*character == '(' && !is_escaped(&characters, index)).then_some(index)
        })
    else {
        if characters
            .iter()
            .enumerate()
            .any(|(index, character)| *character == ')' && !is_escaped(&characters, index))
        {
            return None;
        }
        return Some(vec![pattern.to_owned()]);
    };
    let mut depth = 0_usize;
    let mut close = None;
    for index in open..characters.len() {
        if is_escaped(&characters, index) {
            continue;
        }
        match characters[index] {
            '(' => depth = depth.saturating_add(1),
            ')' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    close = Some(index);
                    break;
                }
            }
            _ => {}
        }
    }
    let close = close?;
    let inner = &characters[open + 1..close];
    let mut alternatives = Vec::new();
    let mut start = 0_usize;
    let mut inner_depth = 0_usize;
    for index in 0..=inner.len() {
        let split = index == inner.len()
            || (inner[index] == '|' && inner_depth == 0 && !is_escaped(inner, index));
        if split {
            alternatives.push(inner[start..index].iter().collect::<String>());
            start = index.saturating_add(1);
            continue;
        }
        if !is_escaped(inner, index) {
            match inner[index] {
                '(' => inner_depth = inner_depth.saturating_add(1),
                ')' => inner_depth = inner_depth.checked_sub(1)?,
                _ => {}
            }
        }
    }
    let prefix: String = characters[..open].iter().collect();
    let suffix: String = characters[close + 1..].iter().collect();
    let mut expanded = Vec::new();
    let mut expanded_bytes = 0_usize;
    for alternative in alternatives {
        let replacement = format!("{prefix}{alternative}{suffix}");
        let nested = expand_pattern_alternatives_at_depth(&replacement, depth.saturating_add(1))?;
        if expanded.len().saturating_add(nested.len()) > MAX_PATTERN_ALTERNATIVES {
            return None;
        }
        let nested_bytes = nested
            .iter()
            .try_fold(0_usize, |total, value| total.checked_add(value.len()))?;
        expanded_bytes = expanded_bytes.checked_add(nested_bytes)?;
        if expanded_bytes > HARD_MAX_IGNORED_LINE_PATTERN_BYTES {
            return None;
        }
        expanded.extend(nested);
    }
    Some(expanded)
}

fn is_escaped(characters: &[char], index: usize) -> bool {
    let mut backslashes = 0_usize;
    let mut cursor = index;
    while cursor > 0 && characters[cursor - 1] == '\\' {
        backslashes = backslashes.saturating_add(1);
        cursor -= 1;
    }
    backslashes % 2 == 1
}

fn compare_projection_values(
    actual: &Value,
    expected: &Value,
    path: &str,
    options: &CompareOptions,
    report: &mut CompareReport,
) {
    if is_ignored_field(path, options) {
        return;
    }
    match (actual, expected) {
        (Value::Object(actual_map), Value::Object(expected_map)) => {
            for (key, expected_value) in expected_map {
                let child_path = if path.is_empty() {
                    format!("/{key}")
                } else {
                    format!("{path}/{key}")
                };
                let actual_value = actual_map.get(key);
                compare_declared_value(
                    actual_value,
                    Some(expected_value),
                    &child_path,
                    options,
                    report,
                );
            }
            for (key, actual_value) in actual_map {
                if !expected_map.contains_key(key) {
                    let child_path = if path.is_empty() {
                        format!("/{key}")
                    } else {
                        format!("{path}/{key}")
                    };
                    push_diff(
                        report,
                        options,
                        &child_path,
                        "unexpected",
                        None,
                        Some(actual_value),
                    );
                }
            }
        }
        (Value::Array(actual_values), Value::Array(expected_values)) => {
            if actual_values.len() != expected_values.len() {
                push_diff(
                    report,
                    options,
                    path,
                    "changed",
                    Some(expected),
                    Some(actual),
                );
            }
            for (index, expected_value) in expected_values.iter().enumerate() {
                let child_path = format!("{path}/{index}");
                compare_declared_value(
                    actual_values.get(index),
                    Some(expected_value),
                    &child_path,
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

fn compare_declared_value(
    actual: Option<&Value>,
    expected: Option<&Value>,
    path: &str,
    options: &CompareOptions,
    report: &mut CompareReport,
) {
    if is_ignored_field(path, options) {
        return;
    }
    let Some(expected) = expected else {
        return;
    };
    let Some(actual) = actual else {
        push_diff(report, options, path, "missing", Some(expected), None);
        return;
    };
    compare_projection_values(actual, expected, path, options, report);
}

fn is_ignored_field(path: &str, options: &CompareOptions) -> bool {
    if path.is_empty() {
        return false;
    }
    let canonical = canonical_field_path(path);
    let raw = path.trim_start_matches('/');
    options.ignored_fields.iter().any(|field| {
        let field = field.trim_start_matches('/');
        field == canonical || field == raw || wildcard_path_matches(field, &canonical)
    })
}

/// Match an explicit dotted field path without treating a collection marker
/// as an unbounded prefix.  In particular, `rows[*].bytes` can only mask the
/// bytes field of a row; it can never mask `/rows` (and therefore cannot hide a
/// changed label or success value).
fn wildcard_path_matches(pattern: &str, value: &str) -> bool {
    let pattern: Vec<&str> = pattern.split('.').collect();
    let value: Vec<&str> = value.split('.').collect();
    pattern.len() == value.len()
        && pattern
            .iter()
            .zip(value)
            .all(|(pattern, value)| *pattern == "*" || *pattern == value)
}

fn canonical_field_path(path: &str) -> String {
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    if parts.len() >= 4
        && parts[0] == "rows"
        && (parts[2] == "fields" || parts[2] == "serialized_fields")
    {
        return format!("rows[*].{}", parts[3]);
    }
    if parts.len() >= 4 && parts[0] == "samples" && parts[2] == "attributes" {
        return format!("sample.{}", parts[3]);
    }
    path.trim_start_matches('/').replace('/', ".")
}

fn is_ignored_xml_attribute(attribute: &str, path: &str, options: &CompareOptions) -> bool {
    let sample_path = if path.starts_with("/samples/") {
        format!("sample.{attribute}")
    } else {
        attribute.to_owned()
    };
    is_ignored_field(&format!("/samples/0/attributes/{attribute}"), options)
        || options.ignored_fields.contains(&sample_path)
}

pub(crate) fn push_diff(
    report: &mut CompareReport,
    options: &CompareOptions,
    path: &str,
    kind: &str,
    expected: Option<&Value>,
    actual: Option<&Value>,
) {
    report.equal = false;
    if report.structured_diff.len() >= options.limits.max_diff_count {
        return;
    }
    report.structured_diff.push(StructuredDiff {
        path: if path.is_empty() {
            "/".to_owned()
        } else {
            path.to_owned()
        },
        kind: kind.to_owned(),
        expected: expected.map(|value| redact_value(value, path)),
        actual: actual.map(|value| redact_value(value, path)),
    });
}

fn redact_value(value: &Value, path: &str) -> Value {
    if is_sensitive_path(path) {
        return Value::String("<redacted>".to_owned());
    }
    match value {
        Value::String(text) => Value::String(bounded_diff_text(text, MAX_DIFF_VALUE)),
        Value::Array(values) => {
            let mut redacted = values
                .iter()
                .take(16)
                .map(|value| redact_value(value, path))
                .collect::<Vec<_>>();
            if values.len() > 16 {
                redacted.push(Value::String("<truncated>".to_owned()));
            }
            Value::Array(redacted)
        }
        Value::Object(values) => {
            // JMX property descriptors carry their semantic path beside a
            // generic `value` key.  Treat a descriptor path containing a
            // sensitive property name as context for redaction as well, so a
            // password cannot leak merely because its wire value is stored in
            // a neutral field named `value`.
            let sensitive_descriptor = values
                .get("path")
                .and_then(Value::as_str)
                .is_some_and(is_sensitive_path);
            let mut redacted = values
                .iter()
                .take(32)
                .map(|(key, value)| {
                    let child_path = format!("{path}/{key}");
                    let redacted = if is_sensitive_key(key)
                        || (sensitive_descriptor && matches!(key.as_str(), "value" | "wire_value"))
                    {
                        Value::String("<redacted>".to_owned())
                    } else {
                        redact_value(value, &child_path)
                    };
                    (key.clone(), redacted)
                })
                .collect::<Map<String, Value>>();
            if values.len() > 32 {
                redacted.insert("<truncated>".to_owned(), Value::Bool(true));
            }
            Value::Object(redacted)
        }
        _ => value.clone(),
    }
}

fn is_sensitive_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    if lower == "raw_xml" {
        return true;
    }
    [
        "password",
        "passwd",
        "passphrase",
        "secret",
        "token",
        "authorization",
        "credential",
        "private_key",
        "private-key",
        "privatekey",
        "api_key",
        "api-key",
        "apikey",
        "access_key",
        "access-key",
        "accesskey",
        "cookie",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn is_sensitive_path(path: &str) -> bool {
    path.split('/').any(is_sensitive_key)
}

pub(crate) fn finish_report(mut report: CompareReport, maximum: usize) -> CompareReport {
    if report.equal {
        report.human_diff = "match".to_owned();
        return report;
    }
    let mut human = String::new();
    let mut rendered = 0_usize;
    let mut truncated = false;
    for difference in &report.structured_diff {
        if human.len() >= maximum {
            truncated = true;
            break;
        }
        let expected = difference
            .expected
            .as_ref()
            .map(compact_value)
            .unwrap_or_else(|| "<absent>".to_owned());
        let actual = difference
            .actual
            .as_ref()
            .map(compact_value)
            .unwrap_or_else(|| "<absent>".to_owned());
        let line = format!(
            "{} {} expected {} actual {}",
            difference.kind, difference.path, expected, actual
        );
        let Some(line_bytes) = line.len().checked_add(1) else {
            truncated = true;
            break;
        };
        if human
            .len()
            .checked_add(line_bytes)
            .is_none_or(|length| length > maximum)
        {
            truncated = true;
            break;
        }
        human.push_str(&line);
        human.push('\n');
        let Some(next_rendered) = rendered.checked_add(1) else {
            truncated = true;
            break;
        };
        rendered = next_rendered;
    }
    if rendered < report.structured_diff.len() {
        truncated = true;
    }
    if truncated {
        const MARKER: &str = "<diff truncated>\n";
        if human
            .len()
            .checked_add(MARKER.len())
            .is_some_and(|length| length <= maximum)
        {
            human.push_str(MARKER);
        }
    }
    truncate_utf8(&mut human, maximum);
    report.human_diff = human;
    report
}

fn compact_value(value: &Value) -> String {
    let text = serde_json::to_string(value).unwrap_or_else(|_| "<unserializable>".to_owned());
    bounded_diff_text(&text, MAX_DIFF_VALUE)
}

fn bounded_diff_text(text: &str, maximum: usize) -> String {
    if text.len() <= maximum {
        return text.to_owned();
    }
    const MARKER: &str = "…<truncated>";
    if maximum <= MARKER.len() {
        let mut prefix = text.to_owned();
        truncate_utf8(&mut prefix, maximum);
        return prefix;
    }
    let mut prefix = text.to_owned();
    truncate_utf8(&mut prefix, maximum - MARKER.len());
    prefix.push_str(MARKER);
    prefix
}

fn truncate_utf8(text: &mut String, maximum: usize) {
    if text.len() <= maximum {
        return;
    }
    let mut boundary = maximum;
    while boundary > 0 && !text.is_char_boundary(boundary) {
        boundary -= 1;
    }
    text.truncate(boundary);
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    reason = "comparison fixtures use assertion-context panics only"
)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let base = std::env::temp_dir();
            for _attempt in 0..1024 {
                let nonce = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
                let path = base.join(format!(
                    "jmeter-oracle-compare-{}-{nonce}",
                    std::process::id()
                ));
                // `create_dir` is intentionally exclusive: an attacker or a
                // concurrent test cannot turn a predictable path into a
                // symlinked/shared fixture root between creation and use.
                match fs::create_dir(&path) {
                    Ok(()) => {
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            let mut permissions = fs::metadata(&path)
                                .expect("private temp directory metadata")
                                .permissions();
                            permissions.set_mode(0o700);
                            fs::set_permissions(&path, permissions)
                                .expect("private temp directory permissions");
                        }
                        return Self { path };
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("temp directory: {error}"),
                }
            }
            panic!("unable to allocate an exclusive temp directory")
        }

        fn write(&self, name: &str, contents: &str) -> PathBuf {
            let path = self.path.join(name);
            fs::write(&path, contents).expect("fixture");
            path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn active_fixture(name: &str) -> (ValidatedCase, PathBuf) {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let profile_path = root.join("../../compat/profiles/jmeter-5.6.3.json");
        let case_path = root.join(format!(
            "../../compat/fixtures/jmeter-5.6.3/{name}/case.json"
        ));
        let fixture_dir = case_path.parent().expect("case parent");
        let bundle = super::super::OracleRunner::validate(&profile_path, &case_path, fixture_dir)
            .expect("active fixture");
        (bundle, fixture_dir.to_path_buf())
    }

    #[test]
    fn csv_case_projection_compares_order_fields_and_quoting() {
        let temp = TempDir::new();
        let actual = temp.write(
            "actual.csv",
            "elapsed,label,responseCode,responseMessage,threadName,dataType,success,failureMessage,bytes,sentBytes,grpThreads,allThreads,URL,Filename,Latency,Encoding,SampleCount,ErrorCount,IdleTime,Connect,\"case_id\",\"comma_value\"\n0,jtl-field-sample,200,OK,One deterministic user 1-1,text,true,,99,0,1,1,null,,0,US-ASCII,1,0,0,0,jtl-fields,\"left,right\"\n",
        );
        let (bundle, fixture_dir) = active_fixture("jtl-fields");
        let options = CompareOptions::default();
        let report = compare_case_artifacts(
            &bundle,
            &actual,
            Some(fixture_dir.join("expected/csv.json")),
            &options,
        )
        .expect("compare");
        assert!(report.equal, "{}", report.human_diff);
        assert!(
            report
                .normalized_fields
                .iter()
                .any(|field| field == "rows[*].bytes")
        );
        assert!(
            report
                .normalized_fields
                .iter()
                .any(|field| field == "rows[*].elapsed")
        );
    }

    #[test]
    fn jmx_static_case_routes_before_process_or_generic_jtl_parsing() {
        let (bundle, fixture_dir) = active_fixture("jmx-topology/no-drop-boundaries");
        let report = compare_case_artifacts(
            &bundle,
            bundle.plan_path(),
            Some(fixture_dir.join("expected/semantic.json")),
            &CompareOptions {
                format: Some(CompareFormat::JmxSemantic),
                ..CompareOptions::default()
            },
        )
        .expect("static JMX route");
        // The no-drop descriptor is deliberately stale in two wire fields;
        // routing must still reach the strict JMX comparator and report those
        // mismatches instead of falling through to generic JTL parsing.
        assert!(!report.equal, "stale JMX wire claims unexpectedly matched");
        assert!(
            report
                .structured_diff
                .iter()
                .any(|difference| { difference.path == "/typed_properties/33/raw_xml_sha256" })
        );
    }

    #[test]
    fn csv_case_does_not_hide_label_or_success_differences() {
        let temp = TempDir::new();
        let actual = temp.write(
            "actual.csv",
            "elapsed,label,responseCode,responseMessage,threadName,dataType,success,failureMessage,bytes,sentBytes,grpThreads,allThreads,URL,Filename,Latency,Encoding,SampleCount,ErrorCount,IdleTime,Connect,\"case_id\",\"comma_value\"\n0,WRONG-LABEL,200,OK,One deterministic user 1-1,text,false,,99,0,1,1,null,,0,US-ASCII,1,0,0,0,jtl-fields,\"left,right\"\n",
        );
        let (bundle, fixture_dir) = active_fixture("jtl-fields");
        let report = compare_case_artifacts(
            &bundle,
            &actual,
            Some(fixture_dir.join("expected/csv.json")),
            &CompareOptions::default(),
        )
        .expect("compare");
        assert!(!report.equal);
        let diff = serde_json::to_string(&report.structured_diff).expect("diff json");
        assert!(diff.contains("label"));
        assert!(diff.contains("success"));
    }

    #[test]
    fn csv_no_header_and_printable_delimiter_are_bounded_wire_modes() {
        let temp = TempDir::new();
        let no_header = temp.write("no-header.csv", "alpha,beta\n");
        let options = CompareOptions {
            csv_header: Some(vec!["left".into(), "right".into()]),
            ..CompareOptions::default()
        };
        let document = parse_input(
            &no_header,
            &options.limits,
            Some(CompareFormat::Csv),
            options.csv_header.as_deref(),
        )
        .expect("configured CSV header");
        assert_eq!(
            document.document.projection["header"],
            json!(["left", "right"])
        );
        assert_eq!(
            document.document.projection["rows"][0]["fields"]["left"],
            "alpha"
        );
        assert_eq!(
            document.document.projection["writer_wire"]["print_field_names"],
            false
        );

        let printable = temp.write("printable.csv", "left#right\nalpha#beta\n");
        let parsed = parse_jtl(&printable, &CompareLimits::default()).expect("printable delimiter");
        assert_eq!(parsed.projection["delimiter"], "#");
        assert_eq!(parsed.projection["rows"][0]["fields"]["right"], "beta");

        let bad_quote = temp.write("bad-quote.csv", "\"header\" trailing\n");
        let error = parse_jtl(&bad_quote, &CompareLimits::default())
            .expect_err("post-quote whitespace must not be accepted");
        assert_eq!(error.code(), ErrorCode::JtlParse);

        let long_record = temp.write("long-record.csv", "a,b\n12345,ok\n");
        let error = parse_jtl(
            &long_record,
            &CompareLimits {
                max_text_bytes: 8,
                ..CompareLimits::default()
            },
        )
        .expect_err("record line-byte limit");
        assert_eq!(error.code(), ErrorCode::OutputLimit);

        let escaped_quote_record = temp.write("escaped-quote-record.csv", "\"a\"\"b\"\n");
        let error = parse_jtl(
            &escaped_quote_record,
            &CompareLimits {
                max_text_bytes: 6,
                ..CompareLimits::default()
            },
        )
        .expect_err("escaped quote bytes count toward the record bound");
        assert_eq!(error.code(), ErrorCode::OutputLimit);
    }

    #[test]
    fn xml_case_projection_compares_assertions_debug_sections_and_nested_shape() {
        let temp = TempDir::new();
        let actual = temp.write(
            "actual.xml",
            "<?xml version=\"1.0\"?><testResults version=\"1.2\"><sample t=\"999\" it=\"0\" lt=\"0\" ct=\"0\" by=\"999\" ts=\"999\" s=\"true\" lb=\"jtl-field-sample\" rc=\"200\" rm=\"OK\" tn=\"One deterministic user 1-1\" dt=\"text\" de=\"US-ASCII\" sby=\"0\" sc=\"1\" ec=\"0\" ng=\"1\" na=\"1\" case_id=\"jtl-fields\" comma_value=\"left,right\"><assertionResult><name>Known value assertion</name><failure>false</failure><error>false</error><failureMessage/></assertionResult><sample lb=\"nested\"/><responseHeader class=\"java.lang.String\"></responseHeader><requestHeader class=\"java.lang.String\"></requestHeader><responseData class=\"java.lang.String\">JMeterVariables:\nJMeterThread.last_sample_ok=true\ncase_id=jtl-fields\ncomma_value=left,right\nSTART.MS=dynamic\n</responseData><responseFile class=\"java.lang.String\"></responseFile><samplerData class=\"java.lang.String\">JMeterVariables:</samplerData><java.net.URL>https://example.invalid/</java.net.URL></sample></testResults>",
        );
        let (bundle, fixture_dir) = active_fixture("jtl-fields");
        let report = compare_case_artifacts(
            &bundle,
            &actual,
            Some(fixture_dir.join("expected/xml.json")),
            &CompareOptions::default(),
        )
        .expect("compare");
        // The nested sample is retained in the ordered wire stream.  The
        // legacy expectation intentionally omits it, so the comparator must
        // report the stale wire-order contract rather than normalize it away.
        assert!(!report.equal, "nested wire child must remain observable");
        assert!(
            report
                .structured_diff
                .iter()
                .any(|difference| difference.path.contains("wire_contract/child_order"))
        );
    }

    #[test]
    fn xml_jmeter_wire_shapes_parse_child_assertions_and_string_sections() {
        let temp = TempDir::new();
        let actual = temp.write(
            "wire.xml",
            r#"<?xml version="1.0" encoding="UTF-8"?>
<testResults version="1.2">
  <sample s="false" lb="wire-shape">
    <assertionResult>
      <name>body check</name>
      <failure>true</failure>
      <error>false</error>
      <failureMessage>expected &quot;needle&quot; &amp; more</failureMessage>
    </assertionResult>
    <responseData class="java.lang.String">body payload</responseData>
    <responseHeader class="java.lang.String">Content-Type: text/plain</responseHeader>
    <requestHeader class="java.lang.String"/>
    <responseFile class="java.lang.String"></responseFile>
    <samplerData class="java.lang.String">GET /wire</samplerData>
  </sample>
</testResults>"#,
        );
        let document = parse_jtl(&actual, &CompareLimits::default()).expect("wire XML");
        let sample = &document.projection["samples"][0];
        assert_eq!(
            sample["assertions"][0],
            json!({
                "error": "false",
                "failure": "true",
                "failure_message": "expected \"needle\" & more",
                "name": "body check"
            })
        );
        assert_eq!(sample["sections"]["responseData"], "body payload");
        assert_eq!(
            sample["sections"]["responseHeader"],
            "Content-Type: text/plain"
        );
        assert_eq!(sample["sections"]["requestHeader"], "");
        assert_eq!(sample["sections"]["responseFile"], "");
        assert_eq!(sample["sections"]["samplerData"], "GET /wire");
        assert_eq!(sample["children"].as_array().map(Vec::len), Some(0));
        let child_events = sample["child_events"].as_array().expect("ordered children");
        assert_eq!(
            child_events
                .iter()
                .map(|child| child["element"].as_str().expect("element"))
                .collect::<Vec<_>>(),
            vec![
                "assertionResult",
                "responseData",
                "responseHeader",
                "requestHeader",
                "responseFile",
                "samplerData"
            ]
        );
        assert_eq!(child_events[1]["attributes"]["class"], "java.lang.String");
        assert_eq!(
            child_events[0]["children"]
                .as_array()
                .expect("assertion child events")
                .iter()
                .map(|child| child["element"].as_str().expect("element"))
                .collect::<Vec<_>>(),
            vec!["name", "failure", "error", "failureMessage"]
        );
    }

    #[test]
    fn xml_unknown_result_data_is_retained_and_unsupported_shapes_fail_closed() {
        let temp = TempDir::new();
        let unknown = temp.write(
            "unknown.xml",
            r#"<testResults><sample lb="unknown">
  <vendorResult code="v1"><vendorValue>preserved</vendorValue></vendorResult>
</sample></testResults>"#,
        );
        let document = parse_jtl(&unknown, &CompareLimits::default()).expect("unknown XML");
        let child = &document.projection["samples"][0]["child_events"][0];
        assert_eq!(child["element"], "vendorResult");
        assert_eq!(child["attributes"]["code"], "v1");
        assert_eq!(child["children"][0]["element"], "vendorValue");
        assert_eq!(child["children"][0]["text"], "preserved");
        assert_eq!(
            document.projection()["samples"][0]["child_events"][0]["element"],
            "vendorResult"
        );
        assert_eq!(
            document.projection()["samples"][0]["child_events"][0]["children"][0]["element"],
            "vendorValue"
        );
        let expected = json!({
            "format": "jtl-xml",
            "samples": [{
                "position": 0,
                "element": "sample",
                "unknown_children": [{
                    "name": "vendorResult",
                    "attributes": {"code": "v1"},
                    "value": "",
                    "children": [{"name": "vendorValue", "value": "preserved"}]
                }]
            }]
        });
        validate_expected_xml_projection(&expected, &CompareLimits::default())
            .expect("recursive unknown expectation schema");
        let mut report = test_report();
        compare_xml_expectation(
            &document,
            &expected,
            &CompareOptions::default(),
            &mut report,
        )
        .expect("recursive unknown expectation");
        assert!(report.equal, "{}", report.human_diff);

        let nested_unknown = temp.write(
            "nested-unknown.xml",
            r#"<testResults><sample><sample lb="child"><pluginData class="vendor.Type"><pluginChild>nested opaque</pluginChild></pluginData><java.net.URL>https://example.invalid/nested</java.net.URL></sample></sample></testResults>"#,
        );
        let nested_document =
            parse_jtl(&nested_unknown, &CompareLimits::default()).expect("nested unknown XML");
        let nested_expected = json!({
            "format": "jtl-xml",
            "samples": [{
                "position": 0,
                "element": "sample",
                "sub_results": {
                    "count": 1,
                    "nested": [{
                        "position": 0,
                        "element": "sample",
                        "unknown_children": [{
                            "name": "pluginData",
                            "class": "vendor.Type",
                            "value": "",
                            "children": [{"name": "pluginChild", "value": "nested opaque"}]
                        }],
                        "wire_children": {"wire_child_order": ["pluginData", "java.net.URL"]}
                    }]
                }
            }]
        });
        validate_expected_xml_projection(&nested_expected, &CompareLimits::default())
            .expect("nested unknown expectation schema");
        let mut nested_report = test_report();
        compare_xml_expectation(
            &nested_document,
            &nested_expected,
            &CompareOptions::default(),
            &mut nested_report,
        )
        .expect("nested unknown expectation");
        assert!(nested_report.equal, "{:?}", nested_report.structured_diff);

        let bad_assertion = temp.write(
            "bad-assertion.xml",
            r#"<testResults><sample><assertionResult>
  <name>known</name><vendorField>must not disappear</vendorField>
</assertionResult></sample></testResults>"#,
        );
        let error = parse_jtl(&bad_assertion, &CompareLimits::default())
            .expect_err("unsupported assertion field");
        assert_eq!(error.code(), ErrorCode::UnsupportedFormat);
        assert!(error.message().contains("vendorField"));

        let bad_section = temp.write(
            "bad-section.xml",
            r#"<testResults><sample><responseData class="java.lang.String" extra="x">payload</responseData></sample></testResults>"#,
        );
        let error = parse_jtl(&bad_section, &CompareLimits::default())
            .expect_err("unsupported section metadata");
        assert_eq!(error.code(), ErrorCode::UnsupportedFormat);
        assert!(error.message().contains("responseData"));

        let duplicate_section = temp.write(
            "duplicate-section.xml",
            r#"<testResults><sample><responseData>one</responseData><responseData>two</responseData></sample></testResults>"#,
        );
        let error = parse_jtl(&duplicate_section, &CompareLimits::default())
            .expect("duplicate sections retained");
        assert_eq!(
            error.projection()["samples"][0]["child_events"]
                .as_array()
                .expect("ordered duplicate sections")
                .len(),
            2
        );
        assert_eq!(
            error.projection()["samples"][0]["sections"]["responseData"],
            "one"
        );
        assert_eq!(
            error.projection()["samples"][0]["sections"]["responseData#2"],
            "two"
        );

        let duplicate_unknown = temp.write(
            "duplicate-unknown.xml",
            "<testResults><sample><vendor>one</vendor><vendor>two</vendor></sample></testResults>",
        );
        let duplicate_unknown_document =
            parse_jtl(&duplicate_unknown, &CompareLimits::default()).expect("unknown leaves");
        let duplicate_unknown_expected = json!({
            "format": "jtl-xml",
            "samples": [{
                "position": 0,
                "element": "sample",
                "unknown_children": [
                    {"name": "vendor", "value": "one"},
                    {"name": "vendor", "value": "two"}
                ]
            }]
        });
        validate_expected_xml_projection(&duplicate_unknown_expected, &CompareLimits::default())
            .expect("duplicate unknown expectation schema");
        let mut duplicate_unknown_report = test_report();
        compare_xml_expectation(
            &duplicate_unknown_document,
            &duplicate_unknown_expected,
            &CompareOptions::default(),
            &mut duplicate_unknown_report,
        )
        .expect("duplicate unknown expectation");
        assert!(
            duplicate_unknown_report.equal,
            "{}",
            duplicate_unknown_report.human_diff
        );

        let root_text = temp.write(
            "root-text.xml",
            "<testResults>root-direct<sample/></testResults>",
        );
        let document = parse_jtl(&root_text, &CompareLimits::default()).expect("root text");
        assert_eq!(document.projection()["root"]["text"], "root-direct");
    }

    #[test]
    fn xml_wire_extensions_compare_order_class_url_and_unknown_identity() {
        let temp = TempDir::new();
        let path = temp.write(
            "extensions.xml",
            r#"<testResults><sample lb="ordered"><assertionResult><name>n</name><failure>false</failure><error>false</error></assertionResult><responseData class="java.lang.String">body</responseData><pluginData class="vendor.Type">opaque</pluginData><java.net.URL>https://example.invalid/✓</java.net.URL><responseData class="java.lang.String">second</responseData></sample></testResults>"#,
        );
        let actual = parse_jtl(&path, &CompareLimits::default()).expect("extension XML");
        let expected = json!({
            "format": "jtl-xml",
            "samples": [{
                "position": 0,
                "element": "sample",
                "wire_children": {
                    "wire_child_order": ["assertionResult", "responseData", "pluginData", "java.net.URL", "responseData"],
                    "string_children_class": ["responseData", "responseData"],
                    "assertion_child_elements": ["name", "failure", "error"]
                },
                "unknown_children": [{"name": "pluginData", "class": "vendor.Type", "value": "opaque"}]
            }]
        });
        validate_expected_xml_projection(&expected, &CompareLimits::default())
            .expect("extension expectation schema");
        let mut report = test_report();
        compare_xml_expectation(&actual, &expected, &CompareOptions::default(), &mut report)
            .expect("extension expectation");
        assert!(report.equal, "{:?}", report.structured_diff);

        let mut reordered = expected.clone();
        reordered["samples"][0]["wire_children"]["wire_child_order"][1] = json!("java.net.URL");
        let mut mismatch = test_report();
        compare_xml_expectation(
            &actual,
            &reordered,
            &CompareOptions::default(),
            &mut mismatch,
        )
        .expect("order mismatch is a comparison result");
        assert!(!mismatch.equal);
        assert!(
            mismatch
                .structured_diff
                .iter()
                .any(|difference| difference.path.contains("wire_child_order"))
        );

        let semantic_only_expected = json!({
            "format": "jtl-xml",
            "samples": [{
                "position": 0,
                "element": "sample",
                "assertions": [{"name": "n", "failure": "false", "error": "false"}]
            }]
        });
        let semantic_only_path = temp.write(
            "semantic-only.xml",
            "<testResults><sample><assertionResult><name>n</name><failure>false</failure><error>false</error><failureMessage>extra</failureMessage></assertionResult></sample></testResults>",
        );
        let semantic_only_actual =
            parse_jtl(&semantic_only_path, &CompareLimits::default()).expect("assertion XML");
        let mut semantic_only_report = test_report();
        compare_xml_expectation(
            &semantic_only_actual,
            &semantic_only_expected,
            &CompareOptions::default(),
            &mut semantic_only_report,
        )
        .expect("assertion extra comparison");
        assert!(!semantic_only_report.equal);
        assert!(
            semantic_only_report
                .structured_diff
                .iter()
                .any(|difference| { difference.path.ends_with("/assertions/0/failure_message") })
        );

        let mut missing_assertion_child = expected.clone();
        missing_assertion_child["samples"][0]["wire_children"]["assertion_child_elements"] =
            json!(["name", "error", "failure", "failureMessage"]);
        let mut assertion_mismatch = test_report();
        compare_xml_expectation(
            &actual,
            &missing_assertion_child,
            &CompareOptions::default(),
            &mut assertion_mismatch,
        )
        .expect("assertion child count mismatch is a comparison result");
        assert!(!assertion_mismatch.equal);

        let variable_path = temp.write(
            "variable-policy.xml",
            r#"<testResults><sample case__id="jtl-fields"/></testResults>"#,
        );
        let variable_actual =
            parse_jtl(&variable_path, &CompareLimits::default()).expect("variable XML");
        let variable_expected = json!({
            "format": "jtl-xml",
            "wire_contract": {
                "sample_variable_attributes": {
                    "spelling": "exact-configured-name",
                    "configured_names": ["case_id"],
                    "underscore_doubling": false
                }
            },
            "samples": [{"position": 0, "element": "sample"}]
        });
        let mut variable_mismatch = test_report();
        compare_xml_expectation(
            &variable_actual,
            &variable_expected,
            &CompareOptions::default(),
            &mut variable_mismatch,
        )
        .expect("variable spelling mismatch is a comparison result");
        assert!(!variable_mismatch.equal);
        assert!(
            variable_mismatch
                .structured_diff
                .iter()
                .any(|difference| difference.path.contains("configured_names"))
        );

        let mut doubled_expected = variable_expected;
        doubled_expected["wire_contract"]["sample_variable_attributes"]["underscore_doubling"] =
            json!(true);
        let mut doubled_match = test_report();
        compare_xml_expectation(
            &variable_actual,
            &doubled_expected,
            &CompareOptions::default(),
            &mut doubled_match,
        )
        .expect("declared doubled variable spelling");
        assert!(doubled_match.equal, "{}", doubled_match.human_diff);

        let on_error_path = temp.write(
            "response-on-error.xml",
            r#"<testResults><sample s="false"><responseData class="java.lang.String">failure body</responseData></sample></testResults>"#,
        );
        let on_error_actual =
            parse_jtl(&on_error_path, &CompareLimits::default()).expect("on-error XML");
        let on_error_expected = json!({
            "format": "jtl-xml",
            "wire_contract": {
                "string_children": [{"element": "responseData", "class": "java.lang.String"}],
                "child_order": ["responseData"],
                "response_data": {"enabled": false, "on_error": true},
                "response_file": {"enabled": false, "expected": false}
            },
            "samples": [{"position": 0, "element": "sample"}]
        });
        let mut on_error_report = test_report();
        compare_xml_expectation(
            &on_error_actual,
            &on_error_expected,
            &CompareOptions::default(),
            &mut on_error_report,
        )
        .expect("response-on-error expectation");
        assert!(on_error_report.equal, "{}", on_error_report.human_diff);

        let alias_url_expected = json!({
            "format": "jtl-xml",
            "wire_contract": {
                "url_child": {"element": "URL", "class": null}
            },
            "samples": [{"position": 0, "element": "sample"}]
        });
        let alias_url_path = temp.write(
            "url-alias.xml",
            "<testResults><sample><java.net.URL>https://example.invalid/</java.net.URL></sample></testResults>",
        );
        let alias_url_actual =
            parse_jtl(&alias_url_path, &CompareLimits::default()).expect("URL alias XML");
        validate_expected_xml_projection(&alias_url_expected, &CompareLimits::default())
            .expect("URL alias expectation schema");
        let mut alias_url_report = test_report();
        compare_xml_expectation(
            &alias_url_actual,
            &alias_url_expected,
            &CompareOptions::default(),
            &mut alias_url_report,
        )
        .expect("URL alias semantic comparison");
        assert!(alias_url_report.equal, "{}", alias_url_report.human_diff);
    }

    #[test]
    fn xml_typed_children_retain_url_unknown_and_optional_failure_message() {
        let temp = TempDir::new();
        let path = temp.write(
            "rich.xml",
            r#"<testResults version="1.2"><httpSample s="false" lb="parent"><assertionResult><name>header</name><failure>false</failure><error>false</error></assertionResult><assertionResult><name>body</name><failure>true</failure><error>false</error><failureMessage>missing</failureMessage></assertionResult><httpSample s="true" lb="child"><sample s="true" lb="leaf"/></httpSample><responseHeader class="java.lang.String">Header: value</responseHeader><java.net.URL>https://example.invalid/</java.net.URL></httpSample><sample s="true" lb="standalone"/></testResults>"#,
        );
        let actual = parse_jtl(&path, &CompareLimits::default()).expect("rich XML");
        let expected = json!({
            "format": "jtl-xml",
            "root": {"element": "testResults", "version": "1.2"},
            "sample_count": 2,
            "ordered_labels": ["parent", "standalone"],
            "wire_contract": {
                "assertion_result": {
                    "representation": "child-elements",
                    "child_order": ["name", "failure", "error", "failureMessage"]
                },
                "string_children": [{"element": "responseHeader", "class": "java.lang.String"}],
                "url_child": {"element": "java.net.URL", "class": null},
                "child_order": [
                    "assertionResult", "assertionResult", "subresult", "responseHeader", "java.net.URL"
                ],
                "wire_order": [
                    "assertionResult", "assertionResult", "subresult", "responseHeader", "java.net.URL"
                ],
                "response_file": {"enabled": false, "expected": false}
            },
            "samples": [{
                "position": 0,
                "element": "httpSample",
                "attributes": {"s": "false", "lb": "parent"},
                "assertions": [
                    {"name": "header", "failure": "false", "error": "false"},
                    {"name": "body", "failure": "true", "error": "false", "failure_message": "missing"}
                ],
                "sections": {"responseHeader": "Header: value"},
                "children": [
                    {
                        "position": 0,
                        "element": "httpSample",
                        "attributes": {"s": "true", "lb": "child"},
                        "sections": {},
                        "text": "",
                        "assertions": [],
                        "children": [{
                            "position": 0,
                            "element": "sample",
                            "attributes": {"s": "true", "lb": "leaf"},
                            "sections": {},
                            "text": "",
                            "assertions": [],
                            "children": []
                        }]
                    },
                    {
                        "position": 1,
                        "element": "java.net.URL",
                        "attributes": {},
                        "sections": {},
                        "text": "https://example.invalid/",
                        "assertions": [],
                        "children": []
                    }
                ]
            }, {
                "position": 1,
                "element": "sample",
                "attributes": {"s": "true", "lb": "standalone"},
                "assertions": [],
                "sections": {},
                "children": []
            }]
        });
        validate_expected_xml_projection(&expected, &CompareLimits::default())
            .expect("rich expectation schema");
        let mut report = test_report();
        compare_xml_expectation(&actual, &expected, &CompareOptions::default(), &mut report)
            .expect("rich expectation comparison");
        assert!(report.equal, "{}", report.human_diff);
    }

    #[test]
    fn report_xml_descriptor_extensions_are_explicitly_unsupported() {
        let expected = json!({
            "format": "jtl-xml",
            "samples": [{
                "position": 0,
                "element": "sample",
                "wire_attributes": {"ts": "1"},
                "semantic": {"label": "not a JTL comparator field"}
            }]
        });
        let error = validate_expected_xml_projection(&expected, &CompareLimits::default())
            .expect_err("report descriptor must not be treated as JTL projection");
        assert_eq!(error.code(), ErrorCode::UnsupportedFormat);
        assert!(error.message().contains("unsupported expected"));

        let rust_wire_extension = json!({
            "format": "jtl-xml",
            "wire_contract": {"wire_attributes": {"case__id": "preserve"}}
        });
        let error =
            validate_expected_xml_projection(&rust_wire_extension, &CompareLimits::default())
                .expect_err("Rust-only wire contract must not be consumed as JMeter wire");
        assert_eq!(error.code(), ErrorCode::UnsupportedFormat);

        let null_contract_kind = json!({
            "format": "jtl-xml",
            "contract_kind": null
        });
        let error =
            validate_expected_xml_projection(&null_contract_kind, &CompareLimits::default())
                .expect_err("contract_kind is a closed string enum");
        assert_eq!(error.code(), ErrorCode::ManifestSchema);
    }

    #[test]
    fn jmx_semantic_projection_is_explicitly_unsupported() {
        let temp = TempDir::new();
        let semantic = temp.write("semantic.json", r#"{"format":"jmx-semantic"}"#);
        let error = parse_jtl(&semantic, &CompareLimits::default())
            .expect_err("JMX semantic comparator is not implemented");
        assert_eq!(error.code(), ErrorCode::UnsupportedFormat);
        assert!(error.message().contains("jmx-semantic"));

        let http_trace = temp.write("http-trace.json", r#"{"format":"http-trace"}"#);
        let error = parse_jtl(&http_trace, &CompareLimits::default())
            .expect_err("HTTP trace is not a neutral JTL projection");
        assert_eq!(error.code(), ErrorCode::UnsupportedFormat);
        assert!(error.message().contains("http-trace"));
    }

    #[test]
    fn expected_xml_sample_alias_position_and_subresults_are_enforced() {
        let temp = TempDir::new();
        let actual_path = temp.write(
            "actual.xml",
            r#"<testResults><httpSample lb="parent"><httpSample lb="child"><sample lb="leaf"/></httpSample></httpSample></testResults>"#,
        );
        let actual = parse_jtl(&actual_path, &CompareLimits::default()).expect("actual XML");
        let expected = json!({
            "format": "jtl-xml",
            "samples": [{
                "position": 0,
                "element": "httpSample",
                "sub_results": {
                    "count": 1,
                    "ordered_labels": ["child"],
                    "nested": [{
                        "element": "httpSample",
                        "label": "child",
                        "children": [{
                            "element": "sample",
                            "label": "leaf"
                        }]
                    }]
                }
            }]
        });
        let mut report = test_report();
        compare_xml_expectation(&actual, &expected, &CompareOptions::default(), &mut report)
            .expect("valid XML expectation");
        assert!(report.equal, "{}", report.human_diff);

        let mut wrong_alias = test_report();
        let mut alias_expected = expected.clone();
        alias_expected["samples"][0]["element"] = json!("sample");
        compare_xml_expectation(
            &actual,
            &alias_expected,
            &CompareOptions::default(),
            &mut wrong_alias,
        )
        .expect("alias mismatch is a comparison result");
        assert!(!wrong_alias.equal);
        assert!(
            wrong_alias
                .structured_diff
                .iter()
                .any(|difference| difference.path.ends_with("/element"))
        );

        let mut wrong_position = test_report();
        let mut position_expected = expected.clone();
        position_expected["samples"][0]["position"] = json!(1);
        compare_xml_expectation(
            &actual,
            &position_expected,
            &CompareOptions::default(),
            &mut wrong_position,
        )
        .expect("position mismatch is a comparison result");
        assert!(!wrong_position.equal);
        assert!(
            wrong_position
                .structured_diff
                .iter()
                .any(|difference| difference.path.ends_with("/position"))
        );

        let mut wrong_nested = test_report();
        let mut nested_expected = expected;
        nested_expected["samples"][0]["sub_results"]["nested"][0]["children"][0]["label"] =
            json!("wrong");
        compare_xml_expectation(
            &actual,
            &nested_expected,
            &CompareOptions::default(),
            &mut wrong_nested,
        )
        .expect("nested mismatch is a comparison result");
        assert!(!wrong_nested.equal);
        assert!(
            wrong_nested
                .structured_diff
                .iter()
                .any(|difference| difference.path.contains("/children/0/label"))
        );
    }

    #[test]
    fn xml_nested_order_assertions_and_presence_are_not_collapsed() {
        let temp = TempDir::new();
        let nested_path = temp.write(
            "nested-order.xml",
            r#"<testResults><sample lb="parent"><assertionResult><name>first assertion</name><failure>false</failure><error>false</error></assertionResult><assertionResult><name>second assertion</name><failure>true</failure><error>false</error></assertionResult><sample lb="first"/><sample lb="second"/></sample></testResults>"#,
        );
        let actual = parse_jtl(&nested_path, &CompareLimits::default()).expect("nested XML");
        let expected = json!({
            "format": "jtl-xml",
            "samples": [{
                "position": 0,
                "element": "sample",
                "assertions": [
                    {"name": "first assertion", "failure": "false", "error": "false"},
                    {"name": "second assertion", "failure": "true", "error": "false"}
                ],
                "sub_results": {
                    "count": 2,
                    "ordered_labels": ["first", "second"],
                    "nested": [
                        {"element": "sample", "label": "first"},
                        {"element": "sample", "label": "second"}
                    ]
                }
            }]
        });
        validate_expected_xml_projection(&expected, &CompareLimits::default())
            .expect("nested order expectation schema");
        let mut report = test_report();
        compare_xml_expectation(&actual, &expected, &CompareOptions::default(), &mut report)
            .expect("nested order comparison");
        assert!(report.equal, "{}", report.human_diff);

        let mut reordered = expected.clone();
        reordered["samples"][0]["sub_results"]["ordered_labels"] = json!(["second", "first"]);
        let mut mismatch = test_report();
        compare_xml_expectation(
            &actual,
            &reordered,
            &CompareOptions::default(),
            &mut mismatch,
        )
        .expect("nested ordering mismatch is a comparison result");
        assert!(!mismatch.equal);
        assert!(
            mismatch
                .structured_diff
                .iter()
                .any(|difference| difference.path.contains("/sub_results/ordered_labels/"))
        );

        let mut assertion_reordered = expected.clone();
        assertion_reordered["samples"][0]["assertions"][0]["name"] = json!("second assertion");
        let mut assertion_mismatch = test_report();
        compare_xml_expectation(
            &actual,
            &assertion_reordered,
            &CompareOptions::default(),
            &mut assertion_mismatch,
        )
        .expect("assertion ordering mismatch is a comparison result");
        assert!(!assertion_mismatch.equal);
        assert!(
            assertion_mismatch
                .structured_diff
                .iter()
                .any(|difference| difference.path.ends_with("/assertions/0/name"))
        );

        let empty_path = temp.write(
            "empty-section.xml",
            "<testResults><sample><responseData class=\"java.lang.String\"/></sample></testResults>",
        );
        let empty_actual = parse_jtl(&empty_path, &CompareLimits::default()).expect("empty XML");
        let explicit_empty = json!({
            "format": "jtl-xml",
            "samples": [{
                "position": 0,
                "element": "sample",
                "sections": {"responseData": ""}
            }]
        });
        validate_expected_xml_projection(&explicit_empty, &CompareLimits::default())
            .expect("empty section expectation schema");
        let mut explicit_report = test_report();
        compare_xml_expectation(
            &empty_actual,
            &explicit_empty,
            &CompareOptions::default(),
            &mut explicit_report,
        )
        .expect("explicit empty section comparison");
        assert!(explicit_report.equal, "{}", explicit_report.human_diff);

        let absent_section = json!({
            "format": "jtl-xml",
            "samples": [{"position": 0, "element": "sample"}]
        });
        let mut absent_report = test_report();
        compare_xml_expectation(
            &empty_actual,
            &absent_section,
            &CompareOptions::default(),
            &mut absent_report,
        )
        .expect("missing section comparison");
        assert!(!absent_report.equal, "present empty section was dropped");

        let absent_path = temp.write("absent-section.xml", "<testResults><sample/></testResults>");
        let absent_actual = parse_jtl(&absent_path, &CompareLimits::default()).expect("absent XML");
        let mut present_report = test_report();
        compare_xml_expectation(
            &absent_actual,
            &explicit_empty,
            &CompareOptions::default(),
            &mut present_report,
        )
        .expect("missing versus explicit empty comparison");
        assert!(
            !present_report.equal,
            "missing section was collapsed to empty"
        );

        let csv_path = temp.write("rows.csv", "label\nvalue\n");
        let csv_actual = parse_jtl(&csv_path, &CompareLimits::default()).expect("CSV");
        let omitted_rows = json!({"format": "jtl-csv"});
        let mut omitted_report = test_report();
        compare_csv_expectation(
            &csv_actual,
            &omitted_rows,
            &CompareOptions::default(),
            &mut omitted_report,
        );
        assert!(
            omitted_report.equal,
            "omitted rows remain a partial expectation"
        );
        let explicit_rows = json!({"format": "jtl-csv", "rows": []});
        let mut explicit_rows_report = test_report();
        compare_csv_expectation(
            &csv_actual,
            &explicit_rows,
            &CompareOptions::default(),
            &mut explicit_rows_report,
        );
        assert!(
            !explicit_rows_report.equal,
            "explicit empty rows must assert no rows"
        );
    }

    #[test]
    fn comparator_limits_cover_text_depth_events_and_fixture_resources() {
        let temp = TempDir::new();
        let rows = temp.write("rows.csv", "label\none\ntwo\n");
        let error = parse_jtl(
            &rows,
            &CompareLimits {
                max_events: 1,
                ..CompareLimits::default()
            },
        )
        .expect_err("CSV event limit");
        assert_eq!(error.code(), ErrorCode::OutputLimit);

        let nested = temp.write(
            "nested.xml",
            "<testResults><sample><sample/></sample></testResults>",
        );
        let error = parse_jtl(
            &nested,
            &CompareLimits {
                max_depth: 1,
                ..CompareLimits::default()
            },
        )
        .expect_err("XML depth limit");
        assert_eq!(error.code(), ErrorCode::OutputLimit);

        let error = parse_jtl(
            &nested,
            &CompareLimits {
                max_nodes: 1,
                ..CompareLimits::default()
            },
        )
        .expect_err("XML node limit");
        assert_eq!(error.code(), ErrorCode::OutputLimit);

        let attributes = temp.write(
            "attributes.xml",
            "<testResults version=\"1.2\"><sample s=\"true\"/></testResults>",
        );
        let error = parse_jtl(
            &attributes,
            &CompareLimits {
                max_attributes: 1,
                ..CompareLimits::default()
            },
        )
        .expect_err("XML attribute limit");
        assert_eq!(error.code(), ErrorCode::OutputLimit);

        let text = temp.write("text.csv", "label\n12345\n");
        let error = parse_jtl(
            &text,
            &CompareLimits {
                max_text_bytes: 4,
                ..CompareLimits::default()
            },
        )
        .expect_err("text limit");
        assert_eq!(error.code(), ErrorCode::OutputLimit);

        let json_depth = temp.write(
            "deep.json",
            r#"{"format":"neutral-json","events":[{"element":"row","children":[{"element":"nested"}]}]}"#,
        );
        let error = parse_jtl(
            &json_depth,
            &CompareLimits {
                max_depth: 3,
                ..CompareLimits::default()
            },
        )
        .expect_err("JSON depth limit");
        assert_eq!(error.code(), ErrorCode::OutputLimit);

        let hard = CompareLimits {
            max_depth: HARD_MAX_DEPTH + 1,
            ..CompareLimits::default()
        };
        assert_eq!(
            hard.validate().expect_err("hard depth limit").code(),
            ErrorCode::Configuration
        );
        let hard_nodes = CompareLimits {
            max_nodes: HARD_MAX_NODES + 1,
            ..CompareLimits::default()
        };
        assert_eq!(
            hard_nodes.validate().expect_err("hard node limit").code(),
            ErrorCode::Configuration
        );
        let hard_input = CompareLimits {
            max_input_bytes: HARD_MAX_INPUT_BYTES + 1,
            ..CompareLimits::default()
        };
        assert_eq!(
            hard_input.validate().expect_err("hard input limit").code(),
            ErrorCode::Configuration
        );
        let fixture_document = json!({
            "resource_limits": {
                "max_samples": 2,
                "max_response_bytes": 8
            }
        });
        let mut fixture_limits = CompareLimits::default();
        apply_fixture_resource_limits(&fixture_document, &mut fixture_limits)
            .expect("fixture resource limits");
        assert_eq!(fixture_limits.max_events, 2);
        assert_eq!(fixture_limits.max_text_bytes, 8);

        let bounds_document = json!({
            "bounds": {
                "max_samples": 3,
                "max_result_bytes": 9,
                "max_input_bytes": 7,
                "max_line_bytes": 6,
                "max_csv_columns": 5,
                "max_assertion_results": 4
            }
        });
        let mut bounds_limits = CompareLimits::default();
        apply_fixture_resource_limits(&bounds_document, &mut bounds_limits)
            .expect("fixture bounds");
        assert_eq!(bounds_limits.max_events, 3);
        assert_eq!(bounds_limits.max_text_bytes, 6);
        assert_eq!(bounds_limits.max_input_bytes, 7);
        assert_eq!(bounds_limits.max_csv_columns, 5);
        assert_eq!(bounds_limits.max_assertion_results, 4);
    }

    #[test]
    fn sample_count_asserted_false_suppresses_only_count_metadata() {
        let temp = TempDir::new();
        let csv = temp.write("count.csv", "label\nvalue\n");
        let csv_document = parse_jtl(&csv, &CompareLimits::default()).expect("CSV input");
        let csv_expected = json!({
            "format": "jtl-csv",
            "sample_count": 99,
            "sample_count_asserted": false,
            "rows": [{"position": 0}]
        });
        validate_expected_csv_projection(&csv_expected).expect("CSV expectation");
        let mut csv_report = test_report();
        compare_csv_expectation(
            &csv_document,
            &csv_expected,
            &CompareOptions::default(),
            &mut csv_report,
        );
        assert!(csv_report.equal, "{}", csv_report.human_diff);

        let xml = temp.write("count.xml", "<testResults><sample/></testResults>");
        let xml_document = parse_jtl(&xml, &CompareLimits::default()).expect("XML input");
        let xml_expected = json!({
            "format": "jtl-xml",
            "sample_count": 99,
            "sample_count_asserted": false
        });
        validate_expected_xml_projection(&xml_expected, &CompareLimits::default())
            .expect("XML expectation");
        let mut xml_report = test_report();
        compare_xml_expectation(
            &xml_document,
            &xml_expected,
            &CompareOptions::default(),
            &mut xml_report,
        )
        .expect("XML count expectation");
        assert!(xml_report.equal, "{}", xml_report.human_diff);

        let bad_line_ending = json!({
            "format": "jtl-csv",
            "line_ending": "future-placeholder"
        });
        let error = validate_expected_csv_projection(&bad_line_ending)
            .expect_err("future line-ending materialization must fail closed");
        assert_eq!(error.code(), ErrorCode::UnsupportedFormat);
    }

    #[test]
    fn xml_names_entities_duplicates_and_external_entities_fail_closed() {
        let temp = TempDir::new();
        let uppercase_hex = temp.write(
            "uppercase-hex.xml",
            "<testResults><sample lb=\"&#X41;\"/></testResults>",
        );
        let document =
            parse_jtl(&uppercase_hex, &CompareLimits::default()).expect("uppercase hex entity");
        assert_eq!(document.projection["samples"][0]["attributes"]["lb"], "A");

        for (name, input) in [
            ("bad-name.xml", "<testResults><1sample/></testResults>"),
            (
                "xxe-doctype.xml",
                "<!DOCTYPE testResults [<!ENTITY xxe SYSTEM \"file:///secret\">]><testResults><sample>&xxe;</sample></testResults>",
            ),
            (
                "xxe-entity.xml",
                "<testResults><sample>&xxe;</sample></testResults>",
            ),
            (
                "bad-codepoint.xml",
                "<testResults><sample lb=\"&#x1;\"/></testResults>",
            ),
            (
                "duplicate-attribute.xml",
                "<testResults><sample lb=\"one\" lb=\"two\"/></testResults>",
            ),
        ] {
            let path = temp.write(name, input);
            let error = parse_jtl(&path, &CompareLimits::default()).expect_err("invalid XML input");
            assert_eq!(error.code(), ErrorCode::JtlParse, "{name}: {error}");
        }

        let duplicate_assertion = temp.write(
            "duplicate-assertion.xml",
            "<testResults><sample><assertionResult><name>one</name><name>two</name></assertionResult></sample></testResults>",
        );
        let error = parse_jtl(&duplicate_assertion, &CompareLimits::default())
            .expect_err("duplicate assertion field");
        assert_eq!(error.code(), ErrorCode::UnsupportedFormat);

        let missing_assertion_field = temp.write(
            "missing-assertion-field.xml",
            "<testResults><sample><assertionResult><name>one</name><failure>false</failure></assertionResult></sample></testResults>",
        );
        let error = parse_jtl(&missing_assertion_field, &CompareLimits::default())
            .expect_err("mandatory assertion field");
        assert_eq!(error.code(), ErrorCode::UnsupportedFormat);
        assert!(error.message().contains("mandatory 'error'"));

        for (name, input) in [
            (
                "leading-comment.xml",
                "<!--not retained--><testResults><sample/></testResults>",
            ),
            (
                "trailing-comment.xml",
                "<testResults><sample/></testResults><!--not retained-->",
            ),
            (
                "leading-pi.xml",
                "<?oracle instruction?><testResults><sample/></testResults>",
            ),
        ] {
            let path = temp.write(name, input);
            let error = parse_jtl(&path, &CompareLimits::default())
                .expect_err("root comment/PI is explicit");
            assert_eq!(
                error.code(),
                ErrorCode::UnsupportedFormat,
                "{name}: {error}"
            );
        }
    }

    #[test]
    fn expected_projection_paths_are_canonical_and_contained() {
        let temp = TempDir::new();
        let root = temp.path.join("fixture");
        fs::create_dir_all(&root).expect("fixture root");
        let expected = temp.write("outside.json", "{}");
        let error = canonical_contained_expected_file(&root, &expected)
            .expect_err("outside expected projection");
        assert_eq!(error.code(), ErrorCode::PathPolicy);
        let error = contained_expected_relative_file(&root, "../outside.json")
            .expect_err("traversal expected projection");
        assert_eq!(error.code(), ErrorCode::PathPolicy);
        let inside = root.join("expected.json");
        fs::write(&inside, "{}").expect("inside expected projection");
        let canonical = canonical_contained_expected_file(&root, &inside)
            .expect("contained expected projection");
        assert!(canonical.starts_with(fs::canonicalize(&root).expect("canonical root")));

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&expected, root.join("linked.json"))
                .expect("symlink fixture");
            let error = canonical_contained_expected_file(&root, &root.join("linked.json"))
                .expect_err("symlink expected projection");
            assert_eq!(error.code(), ErrorCode::PathPolicy);

            let linked_input = root.join("linked.csv");
            std::os::unix::fs::symlink(&expected, &linked_input).expect("symlink input");
            let error = parse_jtl(&linked_input, &CompareLimits::default())
                .expect_err("symlink comparison input");
            assert_eq!(error.code(), ErrorCode::PathPolicy);
        }
    }

    #[test]
    fn existing_xml_case_expectations_cover_assertion_controller_and_lifecycle_events() {
        let temp = TempDir::new();
        let assertion = temp.write(
            "assertion.xml",
            "<testResults version=\"1.2\"><sample t=\"1\" by=\"1\" it=\"0\" lt=\"0\" ct=\"0\" ts=\"1\" s=\"false\" lb=\"assertion-source\" rc=\"200\" rm=\"OK\" tn=\"One deterministic user 1-1\" dt=\"text\" de=\"US-ASCII\" sby=\"0\" sc=\"1\" ec=\"1\" ng=\"1\" na=\"1\"><assertionResult name=\"Absent literal assertion\" failure=\"true\" error=\"false\" failureMessage=\"Test failed: text expected to contain /never-present-in-debug-response/\"/><responseData>JMeterVariables:\nJMeterThread.last_sample_ok=true\nknown_value=present\n</responseData></sample></testResults>",
        );
        let (bundle, _) = active_fixture("assertion-failure");
        let report = compare_case_artifacts(
            &bundle,
            &assertion,
            None::<PathBuf>,
            &CompareOptions::default(),
        )
        .expect("assertion compare");
        assert!(report.equal, "{}", report.human_diff);

        let controller = temp.write(
            "controllers.xml",
            "<testResults version=\"1.2\"><sample s=\"true\" lb=\"simple-a\" rc=\"200\" rm=\"OK\" tn=\"Two iterations 1-1\" dt=\"text\" de=\"US-ASCII\" sby=\"0\" sc=\"1\" ec=\"0\" ng=\"1\" na=\"1\" t=\"1\" by=\"0\" it=\"0\" lt=\"0\" ct=\"0\" ts=\"1\"/><sample s=\"true\" lb=\"loop\" rc=\"200\" rm=\"OK\" tn=\"Two iterations 1-1\" dt=\"text\" de=\"US-ASCII\" sby=\"0\" sc=\"1\" ec=\"0\" ng=\"1\" na=\"1\" t=\"1\" by=\"0\" it=\"0\" lt=\"0\" ct=\"0\" ts=\"1\"/><sample s=\"true\" lb=\"loop\" rc=\"200\" rm=\"OK\" tn=\"Two iterations 1-1\" dt=\"text\" de=\"US-ASCII\" sby=\"0\" sc=\"1\" ec=\"0\" ng=\"1\" na=\"1\" t=\"1\" by=\"0\" it=\"0\" lt=\"0\" ct=\"0\" ts=\"1\"/><sample s=\"true\" lb=\"once\" rc=\"200\" rm=\"OK\" tn=\"Two iterations 1-1\" dt=\"text\" de=\"US-ASCII\" sby=\"0\" sc=\"1\" ec=\"0\" ng=\"1\" na=\"1\" t=\"1\" by=\"0\" it=\"0\" lt=\"0\" ct=\"0\" ts=\"1\"/><sample s=\"true\" lb=\"interleave-a\" rc=\"200\" rm=\"OK\" tn=\"Two iterations 1-1\" dt=\"text\" de=\"US-ASCII\" sby=\"0\" sc=\"1\" ec=\"0\" ng=\"1\" na=\"1\" t=\"1\" by=\"0\" it=\"0\" lt=\"0\" ct=\"0\" ts=\"1\"/><sample s=\"true\" lb=\"simple-a\" rc=\"200\" rm=\"OK\" tn=\"Two iterations 1-1\" dt=\"text\" de=\"US-ASCII\" sby=\"0\" sc=\"1\" ec=\"0\" ng=\"1\" na=\"1\" t=\"1\" by=\"0\" it=\"0\" lt=\"0\" ct=\"0\" ts=\"1\"/><sample s=\"true\" lb=\"interleave-b\" rc=\"200\" rm=\"OK\" tn=\"Two iterations 1-1\" dt=\"text\" de=\"US-ASCII\" sby=\"0\" sc=\"1\" ec=\"0\" ng=\"1\" na=\"1\" t=\"1\" by=\"0\" it=\"0\" lt=\"0\" ct=\"0\" ts=\"1\"/></testResults>",
        );
        let (bundle, _) = active_fixture("controllers");
        let report = compare_case_artifacts(
            &bundle,
            &controller,
            None::<PathBuf>,
            &CompareOptions::default(),
        )
        .expect("controller compare");
        assert!(report.equal, "{}", report.human_diff);

        let lifecycle = temp.write(
            "lifecycle.xml",
            "<testResults version=\"1.2\"><sample s=\"true\" lb=\"Debug variables and properties\" rc=\"200\" rm=\"OK\" tn=\"One deterministic user 1-1\" dt=\"text\" de=\"US-ASCII\" sby=\"0\" sc=\"1\" ec=\"0\" ng=\"1\" na=\"1\" t=\"1\" by=\"0\" it=\"0\" lt=\"0\" ct=\"0\" ts=\"1\"><responseHeader></responseHeader><requestHeader></requestHeader><samplerData>JMeterVariables:\nJMeterProperties:</samplerData><responseData>JMeterVariables:\nJMeterThread.last_sample_ok=true\nalpha=one\nderived=${alpha}-suffix\nproperty_echo=property-value\nJMeterProperties:\njmeter.version=5.6.3\njmeter.save.saveservice.output_format=xml\noracle.case.property=property-value\n</responseData></sample></testResults>",
        );
        let (bundle, _) = active_fixture("lifecycle-debug");
        let report = compare_case_artifacts(
            &bundle,
            &lifecycle,
            None::<PathBuf>,
            &CompareOptions::default(),
        )
        .expect("lifecycle compare");
        assert!(report.equal, "{}", report.human_diff);
    }

    #[test]
    fn normalization_is_fail_closed_and_byte_mask_is_explicit() {
        let temp = TempDir::new();
        let left = temp.write("left.csv", "label,bytes\na,1\n");
        let right = temp.write("right.csv", "label,bytes\na,2\n");
        let mismatch =
            compare_jtl_files(&left, &right, &CompareOptions::default()).expect("raw compare");
        assert!(!mismatch.equal);
        let mut options = CompareOptions::with_policies(["NORM-JTL-001", "NORM-TIME-001"]);
        options.ignored_fields.insert("rows[*].bytes".to_owned());
        let match_report = compare_jtl_files(&left, &right, &options).expect("masked compare");
        assert!(match_report.equal, "{}", match_report.human_diff);
        assert!(
            match_report
                .raw_diagnostic_diff
                .iter()
                .any(|difference| { difference.path.ends_with("/bytes") })
        );
        let mut bad = CompareOptions::default();
        bad.ignored_fields.insert("rows[*].label".to_owned());
        let error = compare_jtl_files(&left, &right, &bad).expect_err("label mask rejected");
        assert_eq!(error.code(), ErrorCode::Normalization);

        let mut wildcard = CompareOptions::with_policies(["NORM-ENV-001"]);
        wildcard.ignored_line_patterns.push("^.*$".to_owned());
        let error = compare_jtl_files(&left, &right, &wildcard)
            .expect_err("unscoped line wildcard rejected");
        assert_eq!(error.code(), ErrorCode::Normalization);

        let unicode_left = temp.write("unicode-left.csv", "label\n😀😀😀\n");
        let unicode_right = temp.write("unicode-right.csv", "label\n😃😃😃\n");
        let unicode_options = CompareOptions {
            limits: CompareLimits {
                max_human_diff_bytes: 7,
                ..CompareLimits::default()
            },
            ..CompareOptions::default()
        };
        let unicode_report =
            compare_jtl_files(&unicode_left, &unicode_right, &unicode_options).expect("unicode");
        assert!(!unicode_report.equal);
        assert!(unicode_report.human_diff.len() <= 7);
        assert!(
            unicode_report
                .human_diff
                .is_char_boundary(unicode_report.human_diff.len())
        );
        assert!(
            unicode_report
                .raw_diagnostic_diff
                .iter()
                .any(|difference| difference.path.contains("rows"))
        );

        let sensitive = redact_value(
            &json!({
                "path": "JDBCDataSource/password",
                "value": "fixture-secret",
                "wire_value": "fixture-secret"
            }),
            "/typed_properties/0",
        );
        assert_eq!(sensitive["value"], "<redacted>");
        assert_eq!(sensitive["wire_value"], "<redacted>");

        let api_key = redact_value(
            &json!({
                "api_key": "fixture-api-secret",
                "access_token": "fixture-token",
                "ordinary": "retained"
            }),
            "/request",
        );
        let rendered = serde_json::to_string(&api_key).expect("redacted diagnostic JSON");
        assert!(!rendered.contains("fixture-api-secret"));
        assert!(!rendered.contains("fixture-token"));
        assert_eq!(api_key["api_key"], "<redacted>");
        assert_eq!(api_key["access_token"], "<redacted>");
        assert_eq!(api_key["ordinary"], "retained");
    }

    #[test]
    fn normalization_paths_are_leaf_exact_and_patterns_are_bounded() {
        let temp = TempDir::new();
        let left = temp.write("left.csv", "label,success,bytes\na,true,1\n");
        let right = temp.write("right.csv", "label,success,bytes\na,false,2\n");
        let mut options = CompareOptions::with_policies(["NORM-JTL-001", "NORM-TIME-001"]);
        options.ignored_fields.insert("rows[*].bytes".to_owned());
        let report = compare_jtl_files(&left, &right, &options).expect("leaf comparison");
        assert!(!report.equal, "a success difference must remain observable");
        assert!(
            report
                .structured_diff
                .iter()
                .any(|difference| { difference.path.ends_with("/success") })
        );
        assert!(
            !report
                .structured_diff
                .iter()
                .any(|difference| { difference.path.ends_with("/bytes") })
        );

        let document = parse_jtl(&left, &CompareLimits::default()).expect("CSV document");
        let partial = json!({
            "format": "jtl-csv",
            "rows": [{"position": 0, "fields": {"label": "a"}}]
        });
        let mut partial_report = test_report();
        compare_csv_expectation(&document, &partial, &options, &mut partial_report);
        assert!(
            partial_report
                .structured_diff
                .iter()
                .any(|difference| { difference.path.ends_with("/success") }),
            "omitted stable row fields must not be hidden"
        );

        let mut broad = CompareOptions::with_policies(["NORM-JTL-001", "NORM-TIME-001"]);
        broad.ignored_fields.insert("rows[*]".to_owned());
        let error = compare_jtl_files(&left, &right, &broad)
            .expect_err("an array-wide normalization must be rejected");
        assert_eq!(error.code(), ErrorCode::Normalization);

        assert!(wildcard_match(
            r"^(START|TESTSTART)\.(HMS|MS|YMD)=.*$",
            "START.MS=123"
        ));
        assert!(wildcard_match(
            r"^(START|TESTSTART)\.(HMS|MS|YMD)=.*$",
            "TESTSTART.YMD=20260813"
        ));
        assert!(!wildcard_match(
            r"^(START|TESTSTART)\.(HMS|MS|YMD)=.*$",
            "OTHER.MS=123"
        ));
        assert!(!valid_line_pattern("^(unclosed|group$"));
        assert!(valid_line_pattern("^.*$"));
    }

    #[test]
    fn normalization_descriptors_do_not_drop_malformed_entries() {
        let cases = [
            (
                "missing normalization still validates line patterns",
                json!({
                    "samples": [{
                        "debug_response_projection": {
                            "ignored_line_patterns": ["valid", 7]
                        }
                    }]
                }),
                ErrorCode::ManifestSchema,
            ),
            (
                "missing normalization still validates attributes",
                json!({
                    "sample_contract": {"ignored_attributes": ["t", false]}
                }),
                ErrorCode::ManifestSchema,
            ),
            (
                "normalization must be an object",
                json!({"normalization": []}),
                ErrorCode::ManifestSchema,
            ),
            (
                "rows must be an array",
                json!({"rows": {"ignored_fields": ["bytes"]}}),
                ErrorCode::ManifestSchema,
            ),
            (
                "unknown normalization fields are unsupported",
                json!({"normalization": {"future_field": []}}),
                ErrorCode::UnsupportedFormat,
            ),
        ];
        for (label, malformed, expected_code) in cases {
            let mut options = CompareOptions::with_policies(["NORM-ENV-001"]);
            let before = options.clone();
            let error = load_expected_normalization(&malformed, &mut options)
                .expect_err("malformed descriptor must fail closed");
            assert_eq!(error.code(), expected_code, "{label}: {error}");
            assert_eq!(options, before, "{label} mutated options before failing");
        }

        let mut unknown = CompareOptions::with_policies(["NORM-JTL-001", "NORM-TIME-001"]);
        unknown
            .ignored_fields
            .insert("rows[*].bytes_blob".to_owned());
        let error = validate_options(&unknown).expect_err("unknown field must fail closed");
        assert_eq!(error.code(), ErrorCode::Normalization);

        let duplicate = CompareOptions::with_policies(["NORM-ENV-001", "NORM-ENV-001"]);
        assert_eq!(duplicate.normalization_policy_refs.len(), 1);
        validate_options(&duplicate).expect("duplicate policy references are de-duplicated");

        let unknown_policy = CompareOptions::with_policies(["NORM-UNKNOWN-999"]);
        let error = validate_options(&unknown_policy).expect_err("unknown policy must fail closed");
        assert_eq!(error.code(), ErrorCode::Normalization);
    }

    #[test]
    fn malformed_and_bounded_inputs_fail_without_partial_success() {
        let temp = TempDir::new();
        let malformed = temp.write("bad.xml", "<testResults><sample></testResults>");
        let error = parse_jtl(&malformed, &CompareLimits::default()).expect_err("malformed XML");
        assert_eq!(error.code(), ErrorCode::JtlParse);
        let large = temp.write("large.csv", "label\nthis-is-long\n");
        let limits = CompareLimits {
            max_input_bytes: 1,
            ..CompareLimits::default()
        };
        let error = parse_jtl(&large, &limits).expect_err("bounded input");
        assert_eq!(error.code(), ErrorCode::OutputLimit);
    }

    fn test_report() -> CompareReport {
        let summary = ArtifactSummary {
            path: "test".to_owned(),
            format: CompareFormat::Xml,
            size_bytes: 0,
            event_count: 0,
        };
        CompareReport {
            equal: true,
            actual: summary.clone(),
            expected: summary,
            normalization_policy_refs: Vec::new(),
            normalized_fields: Vec::new(),
            structured_diff: Vec::new(),
            raw_diagnostic_diff: Vec::new(),
            human_diff: String::new(),
        }
    }
}
