// SPDX-License-Identifier: Apache-2.0
//! Static validation for Decision 0006's HTTP acceptance matrix.
//!
//! This module is intentionally separate from the external-sampler checker.
//! It reads one repository-owned manifest and its declared source/expectation
//! files.  It never starts a service, asks Cargo for a capability, invokes a
//! JVM, or turns a planned descriptor into evidence.

use crate::diagnostics::{Diagnostic, Diagnostics};
use crate::profile;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;

const MANIFEST_FILE: &str = "http-acceptance/manifest.json";
const MANIFEST_SCHEMA_ID: &str = "jmeter-rs.http-acceptance-manifest";
const MANIFEST_SCHEMA_VERSION: u64 = 1;
const DECISION_ID: &str = "0006";
const DECISION_REVISION: u64 = 4;
const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;
const MAX_DECLARED_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_JSON_DEPTH: usize = 64;
const MAX_JSON_NODES: usize = 200_000;
const READ_CHUNK_BYTES: usize = 16 * 1024;

const REQUIRED_SCHEMA_IDS: [&str; 7] = [
    "http.attempt/1",
    "http.state-delta/1",
    "http.error-context/1",
    "http.parser-limits/1",
    "http.body-state/1",
    "http.body-replay/1",
    "http.budget-handoff/1",
];

const REQUIRED_PARSER_CATEGORIES: [&str; 16] = [
    "request-target",
    "authority",
    "status-line",
    "reason",
    "headers",
    "informational",
    "trailers",
    "chunk-framing",
    "wire-body",
    "decompression",
    "urlencoded",
    "multipart",
    "redirects",
    "embedded-resources",
    "trace",
    "diagnostics",
];

const REQUIRED_CASE_KINDS: [&str; 14] = [
    "request-construction",
    "state-delta",
    "redirect",
    "authentication",
    "embedded-resources",
    "proxy",
    "recorder",
    "mirror",
    "tls",
    "limits",
    "retry",
    "redaction",
    "unavailable",
    "cross-platform",
];

const REQUIRED_ATTEMPT_OUTCOMES: [&str; 8] = [
    "ResponseComplete",
    "TransportFailure",
    "ProtocolFailure",
    "TimedOut",
    "Cancelled",
    "DecompressionFailure",
    "TlsFailure",
    "EnvironmentFailure",
];

const ALLOWED_FEATURE_IDS: [&str; 9] = [
    "ELEM-001",
    "ELEM-005",
    "PROXY-001",
    "PROXY-002",
    "PROXY-003",
    "TLS-001",
    "TLS-002",
    "TEST-002",
    "TEST-004",
];

const REQUIRED_HARD_MAXIMA: [(&str, u64); 37] = [
    ("request_target_bytes", 64 * 1024),
    ("authority_bytes", 8 * 1024),
    ("status_line_bytes", 8 * 1024),
    ("reason_bytes", 4 * 1024),
    ("header_fields", 1_024),
    ("header_name_bytes", 8 * 1024),
    ("header_value_bytes", 64 * 1024),
    ("header_aggregate_bytes", 1_024 * 1_024),
    ("informational_responses", 32),
    ("informational_aggregate_bytes", 256 * 1024),
    ("trailer_fields", 256),
    ("trailer_name_bytes", 8 * 1024),
    ("trailer_value_bytes", 64 * 1024),
    ("trailer_aggregate_bytes", 256 * 1024),
    ("chunk_line_bytes", 8 * 1024),
    ("chunk_extensions", 128),
    ("chunk_extension_bytes", 64 * 1024),
    ("wire_request_bytes", 64 * 1024 * 1024),
    ("wire_response_bytes", 256 * 1024 * 1024),
    ("decoded_response_bytes", 512 * 1024 * 1024),
    ("decompression_ratio", 1_000),
    ("decompressed_output_bytes", 512 * 1024 * 1024),
    ("urlencoded_fields", 4_096),
    ("urlencoded_aggregate_bytes", 1024 * 1024),
    ("multipart_parts", 1_024),
    ("multipart_boundary_bytes", 256),
    ("multipart_header_bytes", 256 * 1024),
    ("multipart_body_bytes", 256 * 1024 * 1024),
    ("redirect_hops", 64),
    ("redirect_retained_bytes", 64 * 1024 * 1024),
    ("embedded_candidates", 4_096),
    ("embedded_depth", 32),
    ("embedded_concurrency", 256),
    ("embedded_retained_bytes", 512 * 1024 * 1024),
    ("trace_records", 16_384),
    ("trace_aggregate_bytes", 4 * 1024 * 1024),
    ("diagnostic_text_bytes", 4 * 1024),
];

const ALLOWED_MANIFEST_FIELDS: [&str; 18] = [
    "schema_id",
    "schema_version",
    "profile_id",
    "decision_id",
    "decision_revision",
    "status",
    "evidence_status",
    "source_only",
    "materialization",
    "schemas",
    "capabilities",
    "parser_limits",
    "contracts",
    "retry_policy",
    "automation_policy",
    "transaction_policies",
    "cases",
    "raw_diagnostics",
];

const ALLOWED_IDENTITY_FIELDS: [&str; 7] = [
    "schema_id",
    "version",
    "sha256",
    "name",
    "source",
    "kind",
    "role",
];
const ALLOWED_SCHEMA_FIELDS: [&str; 5] = ["id", "schema_id", "version", "sha256", "status"];
const ALLOWED_EXPECTED_SCHEMA_IDS: [&str; 13] = [
    "http.attempt/1",
    "http.state-delta/1",
    "http.error-context/1",
    "http.parser-limits/1",
    "http.body-state/1",
    "http.body-replay/1",
    "http.budget-handoff/1",
    "jmeter-rs.http-trace",
    "jmeter-rs.proxy-tls-ready",
    "jmeter-rs.proxy-recorder-ready",
    "jmeter-rs.proxy-mirror-expectation",
    "jmeter-rs.semantic-expectation",
    "jmeter-rs.oracle-case",
];

#[derive(Debug)]
enum ReadError {
    Open(io::Error),
    HandleMetadata(io::Error),
    PathMetadata(io::Error),
    Read(io::Error),
    NonRegular,
    Symlink,
    Changed,
    TooLarge(u64),
    Grew(u64),
    Truncated,
    InvalidLimit,
}

/// Run the static HTTP acceptance check.  `check_requested` is deliberately
/// explicit so `http-acceptance` without `--check` cannot look like a pass.
pub(crate) fn check(
    root: &Path,
    profile_path: &Path,
    fixture_root: &Path,
    check_requested: bool,
) -> Diagnostics {
    let mut diagnostics = Diagnostics::default();
    if !check_requested {
        diagnostics.push(Diagnostic::new(
            "HTTP-ACCEPTANCE-USAGE",
            "xtask http-acceptance",
            "the static checker requires --check",
        ));
        return diagnostics;
    }

    let (profile_diagnostics, profile_index) = profile::check(root, profile_path);
    diagnostics.extend(profile_diagnostics);
    let Some(profile_index) = profile_index else {
        diagnostics.push(Diagnostic::new(
            "HTTP-ACCEPTANCE-PROFILE",
            profile::display_path(root, profile_path),
            "cannot validate the HTTP matrix until the active profile is valid",
        ));
        return diagnostics;
    };

    let manifest_path = fixture_root.join(MANIFEST_FILE);
    let display = profile::display_path(root, &manifest_path);
    let value = match read_json(&manifest_path, MAX_MANIFEST_BYTES) {
        Ok(value) => value,
        Err(error) => {
            diagnostics.push(read_diagnostic(&display, error));
            return diagnostics;
        }
    };
    let Some(object) = value.as_object() else {
        diagnostics.push(Diagnostic::new(
            "HTTP-ACCEPTANCE-SCHEMA",
            display,
            "manifest top-level value must be an object",
        ));
        return diagnostics;
    };
    let mut nodes = 0;
    validate_json_limits(&value, &display, 0, &mut nodes, &mut diagnostics);
    validate_manifest(
        root,
        fixture_root,
        &display,
        object,
        &profile_index.profile_id,
        &mut diagnostics,
    );
    diagnostics.sort_deterministically();
    diagnostics
}

fn validate_manifest(
    root: &Path,
    fixture_root: &Path,
    path: &str,
    object: &Map<String, Value>,
    profile_id: &str,
    diagnostics: &mut Diagnostics,
) {
    reject_unknown_fields(object, &ALLOWED_MANIFEST_FIELDS, path, diagnostics);
    check_string(
        object,
        "schema_id",
        path,
        diagnostics,
        Some(MANIFEST_SCHEMA_ID),
    );
    check_u64(
        object,
        "schema_version",
        path,
        diagnostics,
        Some(MANIFEST_SCHEMA_VERSION),
    );
    check_string(object, "profile_id", path, diagnostics, Some(profile_id));
    check_string(object, "decision_id", path, diagnostics, Some(DECISION_ID));
    check_u64(
        object,
        "decision_revision",
        path,
        diagnostics,
        Some(DECISION_REVISION),
    );
    check_string(object, "status", path, diagnostics, Some("declared"));
    check_string(
        object,
        "evidence_status",
        path,
        diagnostics,
        Some("not-run-static"),
    );
    check_bool(object, "source_only", path, diagnostics, Some(true));
    validate_materialization(
        object.get("materialization"),
        &format!("{path}.materialization"),
        diagnostics,
        true,
    );

    let schemas = required_array(object, "schemas", path, diagnostics);
    if let Some(schemas) = schemas {
        validate_schemas(schemas, &format!("{path}.schemas"), diagnostics);
    }
    if let Some(parser_limits) = required_object(object, "parser_limits", path, diagnostics) {
        validate_parser_limits(parser_limits, &format!("{path}.parser_limits"), diagnostics);
    }
    if let Some(contracts) = required_object(object, "contracts", path, diagnostics) {
        validate_contracts(contracts, &format!("{path}.contracts"), diagnostics);
    }
    if let Some(retry_policy) = required_object(object, "retry_policy", path, diagnostics) {
        validate_retry_policy(retry_policy, &format!("{path}.retry_policy"), diagnostics);
    }
    if let Some(automation_policy) = required_object(object, "automation_policy", path, diagnostics)
    {
        validate_automation_policy(
            automation_policy,
            &format!("{path}.automation_policy"),
            diagnostics,
        );
    }
    if let Some(transaction_policies) =
        required_object(object, "transaction_policies", path, diagnostics)
    {
        validate_transaction_policies(
            transaction_policies,
            &format!("{path}.transaction_policies"),
            diagnostics,
        );
    }

    let capability_ids = required_array(object, "capabilities", path, diagnostics)
        .map(|capabilities| {
            validate_capabilities(capabilities, path, root, fixture_root, diagnostics)
        })
        .unwrap_or_default();
    if let Some(cases) = required_array(object, "cases", path, diagnostics) {
        validate_cases(
            cases,
            &format!("{path}.cases"),
            root,
            fixture_root,
            &capability_ids,
            diagnostics,
        );
    }
    if let Some(raw_diagnostics) = required_array(object, "raw_diagnostics", path, diagnostics) {
        validate_raw_diagnostics(
            raw_diagnostics,
            &format!("{path}.raw_diagnostics"),
            fixture_root,
            diagnostics,
        );
    }
}

fn validate_schemas(values: &[Value], path: &str, diagnostics: &mut Diagnostics) {
    let mut found = BTreeMap::<String, u64>::new();
    for (index, value) in values.iter().enumerate() {
        let item_path = format!("{path}[{index}]");
        let (id, version) = if let Some(id) = value.as_str() {
            if id.trim().is_empty() {
                diagnostics.push(Diagnostic::new(
                    "HTTP-ACCEPTANCE-SCHEMA",
                    item_path,
                    "schema IDs must not be empty",
                ));
                continue;
            }
            (id.to_owned(), 1)
        } else if let Some(object) = value.as_object() {
            reject_unknown_fields(object, &ALLOWED_SCHEMA_FIELDS, &item_path, diagnostics);
            let Some(id) = object
                .get("id")
                .or_else(|| object.get("schema_id"))
                .and_then(Value::as_str)
            else {
                diagnostics.push(Diagnostic::new(
                    "HTTP-ACCEPTANCE-SCHEMA",
                    format!("{item_path}.id"),
                    "schema declaration requires id",
                ));
                continue;
            };
            let Some(version) = object.get("version").and_then(Value::as_u64) else {
                diagnostics.push(Diagnostic::new(
                    "HTTP-ACCEPTANCE-SCHEMA",
                    format!("{item_path}.version"),
                    "schema declaration requires a positive version",
                ));
                continue;
            };
            if version == 0 {
                diagnostics.push(Diagnostic::new(
                    "HTTP-ACCEPTANCE-SCHEMA",
                    format!("{item_path}.version"),
                    "schema version must be nonzero",
                ));
            }
            if let Some(status) = object.get("status").and_then(Value::as_str)
                && status != "declared"
            {
                diagnostics.push(Diagnostic::new(
                    "HTTP-ACCEPTANCE-MATERIALIZATION",
                    format!("{item_path}.status"),
                    "schema materialization must be declared; planned or missing schemas are not accepted",
                ));
            }
            (id.to_owned(), version)
        } else {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-SCHEMA",
                item_path,
                "schema declaration must be a string ID or object",
            ));
            continue;
        };
        if found.insert(id.clone(), version).is_some() {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-SCHEMA",
                format!("{path}[{index}]"),
                format!("duplicate schema ID {id:?}"),
            ));
        }
    }
    let expected = REQUIRED_SCHEMA_IDS.iter().copied().collect::<BTreeSet<_>>();
    let actual = found.keys().map(String::as_str).collect::<BTreeSet<_>>();
    for missing in expected.difference(&actual) {
        diagnostics.push(Diagnostic::new(
            "HTTP-ACCEPTANCE-SCHEMA",
            path,
            format!("required schema identity {missing:?} is missing"),
        ));
    }
    for id in &REQUIRED_SCHEMA_IDS {
        if let Some(version) = found.get(*id)
            && *version != 1
        {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-SCHEMA",
                path,
                format!("schema identity {id:?} must use version 1"),
            ));
        }
    }
}

fn validate_parser_limits(object: &Map<String, Value>, path: &str, diagnostics: &mut Diagnostics) {
    const ALLOWED: [&str; 5] = [
        "schema_id",
        "schema_version",
        "categories",
        "hard_maxima",
        "active",
    ];
    reject_unknown_fields(object, &ALLOWED, path, diagnostics);
    check_string(
        object,
        "schema_id",
        path,
        diagnostics,
        Some("http.parser-limits/1"),
    );
    check_u64(object, "schema_version", path, diagnostics, Some(1));
    let categories = required_array(object, "categories", path, diagnostics);
    if let Some(categories) = categories {
        let mut actual = Vec::with_capacity(categories.len());
        for (index, value) in categories.iter().enumerate() {
            let item_path = format!("{path}.categories[{index}]");
            if let Some(value) = value.as_str() {
                actual.push(value.to_owned());
            } else {
                diagnostics.push(Diagnostic::new(
                    "HTTP-ACCEPTANCE-PARSER",
                    item_path,
                    "parser category must be a string",
                ));
            }
        }
        if actual != REQUIRED_PARSER_CATEGORIES {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-PARSER",
                format!("{path}.categories"),
                "parser categories must exactly match the closed Decision 0006 order",
            ));
        }
    }
    let Some(maxima) = required_object(object, "hard_maxima", path, diagnostics) else {
        return;
    };
    let allowed = REQUIRED_HARD_MAXIMA
        .iter()
        .map(|(name, _)| *name)
        .collect::<Vec<_>>();
    reject_unknown_fields(
        maxima,
        &allowed,
        &format!("{path}.hard_maxima"),
        diagnostics,
    );
    for (name, expected) in REQUIRED_HARD_MAXIMA {
        let maximum_path = format!("{path}.hard_maxima.{name}");
        let Some(actual) = maxima.get(name).and_then(Value::as_u64) else {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-PARSER",
                maximum_path,
                format!("hard maximum must be the exact finite value {expected}"),
            ));
            continue;
        };
        if actual != expected {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-PARSER",
                maximum_path,
                format!("hard maximum must be {expected}, got {actual}"),
            ));
        }
    }
    let Some(active) = required_object(object, "active", path, diagnostics) else {
        return;
    };
    let active_path = format!("{path}.active");
    reject_unknown_fields(active, &allowed, &active_path, diagnostics);
    for (name, hard_maximum) in REQUIRED_HARD_MAXIMA {
        let value_path = format!("{active_path}.{name}");
        let Some(active_value) = active.get(name).and_then(Value::as_u64) else {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-PARSER",
                value_path,
                "active parser limit must be a positive integer no greater than its hard maximum",
            ));
            continue;
        };
        if active_value == 0 || active_value > hard_maximum {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-PARSER",
                value_path,
                format!("active parser limit must be in 1..={hard_maximum}, got {active_value}"),
            ));
        }
    }
}

fn validate_contracts(object: &Map<String, Value>, path: &str, diagnostics: &mut Diagnostics) {
    const ALLOWED: [&str; 5] = ["attempt", "state_delta", "error_context", "body", "budget"];
    reject_unknown_fields(object, &ALLOWED, path, diagnostics);
    if let Some(attempt) = required_object(object, "attempt", path, diagnostics) {
        validate_attempt_contract(attempt, &format!("{path}.attempt"), diagnostics);
    }
    if let Some(state) = required_object(object, "state_delta", path, diagnostics) {
        validate_state_contract(state, &format!("{path}.state_delta"), diagnostics);
    }
    if let Some(error) = required_object(object, "error_context", path, diagnostics) {
        validate_error_contract(error, &format!("{path}.error_context"), diagnostics);
    }
    if let Some(body) = required_object(object, "body", path, diagnostics) {
        validate_body_contract(body, &format!("{path}.body"), diagnostics);
    }
    if let Some(budget) = required_object(object, "budget", path, diagnostics) {
        validate_budget_contract(budget, &format!("{path}.budget"), diagnostics);
    }
}

fn validate_attempt_contract(
    object: &Map<String, Value>,
    path: &str,
    diagnostics: &mut Diagnostics,
) {
    const ALLOWED: [&str; 14] = [
        "schema_id",
        "schema_version",
        "max_bytes",
        "max_headers",
        "max_header_bytes",
        "max_informational_responses",
        "max_trailers",
        "max_phases",
        "max_counters",
        "max_diagnostics",
        "ordered_headers",
        "byte_counter_states",
        "outcome_enum",
        "identity_fields",
    ];
    reject_unknown_fields(object, &ALLOWED, path, diagnostics);
    check_string(
        object,
        "schema_id",
        path,
        diagnostics,
        Some("http.attempt/1"),
    );
    check_u64(object, "schema_version", path, diagnostics, Some(1));
    check_u64(
        object,
        "max_bytes",
        path,
        diagnostics,
        Some(4 * 1024 * 1024),
    );
    check_u64(object, "max_headers", path, diagnostics, Some(1_024));
    check_u64(
        object,
        "max_header_bytes",
        path,
        diagnostics,
        Some(1_024 * 1_024),
    );
    check_u64(
        object,
        "max_informational_responses",
        path,
        diagnostics,
        Some(32),
    );
    check_u64(object, "max_trailers", path, diagnostics, Some(256));
    check_u64(object, "max_phases", path, diagnostics, Some(32));
    check_u64(object, "max_counters", path, diagnostics, Some(32));
    check_u64(object, "max_diagnostics", path, diagnostics, Some(64));
    check_bool(object, "ordered_headers", path, diagnostics, Some(true));
    check_string_list_exact(
        object,
        "byte_counter_states",
        path,
        &["Known", "Unavailable"],
        diagnostics,
    );
    check_string_list_exact(
        object,
        "outcome_enum",
        path,
        &REQUIRED_ATTEMPT_OUTCOMES,
        diagnostics,
    );
    check_string_list_exact(
        object,
        "identity_fields",
        path,
        &[
            "source_context",
            "operation_id",
            "attempt_index",
            "capability_identity",
            "route_identity",
        ],
        diagnostics,
    );
}

fn validate_state_contract(object: &Map<String, Value>, path: &str, diagnostics: &mut Diagnostics) {
    const ALLOWED: [&str; 6] = [
        "schema_id",
        "schema_version",
        "operations",
        "aggregate",
        "compare_and_swap",
        "missing_present_empty",
    ];
    const OPERATIONS: [&str; 17] = [
        "CookieUpsert",
        "CookieDelete",
        "CookieClear",
        "CacheUpsert",
        "CacheDelete",
        "CacheInvalidate",
        "AuthChallengeUpsert",
        "AuthChallengeDelete",
        "AuthChallengeClear",
        "DnsUpsert",
        "DnsDelete",
        "DnsClear",
        "HeaderReplace",
        "HeaderAppend",
        "HeaderRemove",
        "ConnectionObserve",
        "ConnectionForget",
    ];
    reject_unknown_fields(object, &ALLOWED, path, diagnostics);
    check_string(
        object,
        "schema_id",
        path,
        diagnostics,
        Some("http.state-delta/1"),
    );
    check_u64(object, "schema_version", path, diagnostics, Some(1));
    check_string_list_exact(object, "operations", path, &OPERATIONS, diagnostics);
    check_string(
        object,
        "aggregate",
        path,
        diagnostics,
        Some("HttpUserStateV1"),
    );
    check_bool(object, "compare_and_swap", path, diagnostics, Some(true));
    check_bool(
        object,
        "missing_present_empty",
        path,
        diagnostics,
        Some(true),
    );
}

fn validate_error_contract(object: &Map<String, Value>, path: &str, diagnostics: &mut Diagnostics) {
    const ALLOWED: [&str; 10] = [
        "schema_id",
        "schema_version",
        "source_node",
        "plan_path",
        "sampler_identity",
        "capability_identity",
        "embedded_resource_index",
        "phase_enum",
        "stable_error_codes",
        "diagnostics",
    ];
    const PHASES: [&str; 10] = [
        "dns",
        "pool",
        "connect",
        "proxy",
        "tls",
        "write",
        "read",
        "framing",
        "decompression",
        "timeout",
    ];
    reject_unknown_fields(object, &ALLOWED, path, diagnostics);
    check_string(
        object,
        "schema_id",
        path,
        diagnostics,
        Some("http.error-context/1"),
    );
    check_u64(object, "schema_version", path, diagnostics, Some(1));
    check_string(
        object,
        "source_node",
        path,
        diagnostics,
        Some("Unknown|DomainQualifiedNode"),
    );
    check_string(
        object,
        "plan_path",
        path,
        diagnostics,
        Some("bounded-domain-qualified"),
    );
    check_string(
        object,
        "sampler_identity",
        path,
        diagnostics,
        Some("bounded-sampler-identity"),
    );
    check_string(
        object,
        "capability_identity",
        path,
        diagnostics,
        Some("schema-version-sha256"),
    );
    check_string(
        object,
        "embedded_resource_index",
        path,
        diagnostics,
        Some("Absent|Present(u32)"),
    );
    check_string_list_exact(object, "phase_enum", path, &PHASES, diagnostics);
    check_string_list_nonempty_exact_prefix(
        object,
        "stable_error_codes",
        path,
        &["http."],
        diagnostics,
    );
    let Some(diagnostics_object) = required_object(object, "diagnostics", path, diagnostics) else {
        return;
    };
    const DIAGNOSTIC_FIELDS: [&str; 4] = [
        "max_records",
        "max_record_bytes",
        "max_total_bytes",
        "redacted",
    ];
    reject_unknown_fields(
        diagnostics_object,
        &DIAGNOSTIC_FIELDS,
        &format!("{path}.diagnostics"),
        diagnostics,
    );
    check_u64(
        diagnostics_object,
        "max_records",
        &format!("{path}.diagnostics"),
        diagnostics,
        Some(64),
    );
    check_u64(
        diagnostics_object,
        "max_record_bytes",
        &format!("{path}.diagnostics"),
        diagnostics,
        Some(4 * 1024),
    );
    check_u64(
        diagnostics_object,
        "max_total_bytes",
        &format!("{path}.diagnostics"),
        diagnostics,
        Some(64 * 1024),
    );
    check_bool(
        diagnostics_object,
        "redacted",
        &format!("{path}.diagnostics"),
        diagnostics,
        Some(true),
    );
}

fn validate_body_contract(object: &Map<String, Value>, path: &str, diagnostics: &mut Diagnostics) {
    const ALLOWED: [&str; 8] = [
        "state_schema_id",
        "replay_schema_id",
        "state_order",
        "transitions",
        "replayable_modes",
        "replay_requires_original_budget",
        "replay_requires_new_attempt",
        "no_replay_after_bytes_sent",
    ];
    const STATES: [&str; 5] = ["Fresh", "Reading", "Ended", "Failed", "Cancelled"];
    reject_unknown_fields(object, &ALLOWED, path, diagnostics);
    check_string(
        object,
        "state_schema_id",
        path,
        diagnostics,
        Some("http.body-state/1"),
    );
    check_string(
        object,
        "replay_schema_id",
        path,
        diagnostics,
        Some("http.body-replay/1"),
    );
    check_string_list_exact(object, "state_order", path, &STATES, diagnostics);
    check_string_list_exact(
        object,
        "transitions",
        path,
        &[
            "Fresh->Reading",
            "Reading->Fresh",
            "Fresh->Ended",
            "Fresh->Failed",
            "Fresh->Cancelled",
        ],
        diagnostics,
    );
    check_string_list_exact(object, "replayable_modes", path, &["explicit"], diagnostics);
    check_bool(
        object,
        "replay_requires_original_budget",
        path,
        diagnostics,
        Some(true),
    );
    check_bool(
        object,
        "replay_requires_new_attempt",
        path,
        diagnostics,
        Some(true),
    );
    check_bool(
        object,
        "no_replay_after_bytes_sent",
        path,
        diagnostics,
        Some(true),
    );
}

fn validate_budget_contract(
    object: &Map<String, Value>,
    path: &str,
    diagnostics: &mut Diagnostics,
) {
    const ALLOWED: [&str; 7] = [
        "schema_id",
        "schema_version",
        "units",
        "max_receiver_cap_ns",
        "reservation_rounding",
        "grant_rounding",
        "required_fields",
    ];
    reject_unknown_fields(object, &ALLOWED, path, diagnostics);
    check_string(
        object,
        "schema_id",
        path,
        diagnostics,
        Some("http.budget-handoff/1"),
    );
    check_u64(object, "schema_version", path, diagnostics, Some(1));
    check_string(object, "units", path, diagnostics, Some("nanoseconds"));
    check_u64(
        object,
        "max_receiver_cap_ns",
        path,
        diagnostics,
        Some(24 * 60 * 60 * 1_000_000_000),
    );
    check_string(
        object,
        "reservation_rounding",
        path,
        diagnostics,
        Some("up"),
    );
    check_string(object, "grant_rounding", path, diagnostics, Some("down"));
    check_string_list_exact(
        object,
        "required_fields",
        path,
        &[
            "remaining_ns",
            "reservation_ns",
            "grant_ns",
            "cap_ns",
            "deadline_ns",
        ],
        diagnostics,
    );
}

fn validate_retry_policy(object: &Map<String, Value>, path: &str, diagnostics: &mut Diagnostics) {
    const ALLOWED: [&str; 7] = [
        "owner",
        "native_transparent_retry",
        "redirects",
        "authentication",
        "body_replay",
        "httpclient4",
        "uncertain_outcome",
    ];
    reject_unknown_fields(object, &ALLOWED, path, diagnostics);
    check_string(object, "owner", path, diagnostics, Some("semantic-layer"));
    check_bool(
        object,
        "native_transparent_retry",
        path,
        diagnostics,
        Some(false),
    );
    check_string(
        object,
        "redirects",
        path,
        diagnostics,
        Some("semantic-layer"),
    );
    check_string(
        object,
        "authentication",
        path,
        diagnostics,
        Some("semantic-layer"),
    );
    check_string(
        object,
        "body_replay",
        path,
        diagnostics,
        Some("semantic-layer"),
    );
    check_string(
        object,
        "uncertain_outcome",
        path,
        diagnostics,
        Some("no-retry"),
    );
    let Some(httpclient4) = required_object(object, "httpclient4", path, diagnostics) else {
        return;
    };
    const HTTPCLIENT_FIELDS: [&str; 2] = [
        "httpclient4.retrycount",
        "httpclient4.request_sent_retry_enabled",
    ];
    reject_unknown_fields(
        httpclient4,
        &HTTPCLIENT_FIELDS,
        &format!("{path}.httpclient4"),
        diagnostics,
    );
    check_i64(
        httpclient4,
        "httpclient4.retrycount",
        &format!("{path}.httpclient4"),
        diagnostics,
        Some(0),
    );
    check_bool(
        httpclient4,
        "httpclient4.request_sent_retry_enabled",
        &format!("{path}.httpclient4"),
        diagnostics,
        Some(false),
    );
}

fn validate_automation_policy(
    object: &Map<String, Value>,
    path: &str,
    diagnostics: &mut Diagnostics,
) {
    const ALLOWED: [&str; 6] = [
        "redirects",
        "authentication",
        "client_retries",
        "unobserved_hop",
        "unobserved_challenge",
        "unobserved_retry",
    ];
    reject_unknown_fields(object, &ALLOWED, path, diagnostics);
    check_string(object, "redirects", path, diagnostics, Some("disabled"));
    check_string(
        object,
        "authentication",
        path,
        diagnostics,
        Some("disabled"),
    );
    check_string(
        object,
        "client_retries",
        path,
        diagnostics,
        Some("disabled"),
    );
    check_string(object, "unobserved_hop", path, diagnostics, Some("reject"));
    check_string(
        object,
        "unobserved_challenge",
        path,
        diagnostics,
        Some("reject"),
    );
    check_string(
        object,
        "unobserved_retry",
        path,
        diagnostics,
        Some("reject"),
    );
}

fn validate_transaction_policies(
    object: &Map<String, Value>,
    path: &str,
    diagnostics: &mut Diagnostics,
) {
    const ALLOWED: [&str; 4] = ["redirect", "authentication", "embedded_resources", "state"];
    reject_unknown_fields(object, &ALLOWED, path, diagnostics);
    validate_transaction(
        object,
        "redirect",
        path,
        "new-attempt",
        "semantic",
        diagnostics,
    );
    validate_transaction(
        object,
        "authentication",
        path,
        "new-attempt",
        "semantic",
        diagnostics,
    );
    validate_transaction(
        object,
        "embedded_resources",
        path,
        "ordered-subresult",
        "semantic",
        diagnostics,
    );
    let Some(state) = required_object(object, "state", path, diagnostics) else {
        return;
    };
    const STATE_FIELDS: [&str; 2] = ["commit", "conflict"];
    reject_unknown_fields(state, &STATE_FIELDS, &format!("{path}.state"), diagnostics);
    check_string(
        state,
        "commit",
        &format!("{path}.state"),
        diagnostics,
        Some("atomic-cas"),
    );
    check_string(
        state,
        "conflict",
        &format!("{path}.state"),
        diagnostics,
        Some("no-apply"),
    );
}

fn validate_transaction(
    parent: &Map<String, Value>,
    field: &str,
    path: &str,
    commit: &str,
    boundary: &str,
    diagnostics: &mut Diagnostics,
) {
    let item_path = format!("{path}.{field}");
    let Some(object) = required_object(parent, field, path, diagnostics) else {
        return;
    };
    const ALLOWED: [&str; 4] = ["commit", "boundary", "max_count", "ordered"];
    reject_unknown_fields(object, &ALLOWED, &item_path, diagnostics);
    check_string(object, "commit", &item_path, diagnostics, Some(commit));
    check_string(object, "boundary", &item_path, diagnostics, Some(boundary));
    let max_count = check_u64(object, "max_count", &item_path, diagnostics, None);
    if max_count.is_some_and(|value| value == 0) {
        diagnostics.push(Diagnostic::new(
            "HTTP-ACCEPTANCE-TRANSACTION",
            format!("{item_path}.max_count"),
            "transaction maximum must be nonzero",
        ));
    }
    check_bool(
        object,
        "ordered",
        &item_path,
        diagnostics,
        Some(field == "embedded_resources"),
    );
}

fn validate_capabilities(
    values: &[Value],
    manifest_path: &str,
    root: &Path,
    fixture_root: &Path,
    diagnostics: &mut Diagnostics,
) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    const REQUIRED: [&str; 3] = [
        "http.native/1",
        "http.jmeter-httpclient4/5.6.3",
        "http.jmeter-java/5.6.3",
    ];
    for (index, value) in values.iter().enumerate() {
        let path = format!("{manifest_path}.capabilities[{index}]");
        let Some(object) = value.as_object() else {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-SCHEMA",
                path,
                "capability declaration must be an object",
            ));
            continue;
        };
        const ALLOWED: [&str; 11] = [
            "id",
            "status",
            "implementation",
            "identity",
            "dependencies",
            "providers",
            "source_paths",
            "expected_artifacts",
            "raw_diagnostic_location",
            "materialization",
            "unavailable_reason",
        ];
        reject_unknown_fields(object, &ALLOWED, &path, diagnostics);
        let Some(id) = required_string(object, "id", &path, diagnostics) else {
            continue;
        };
        if !found.insert(id.clone()) {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-IDENTITY",
                format!("{path}.id"),
                format!("duplicate capability identity {id:?}"),
            ));
        }
        if !REQUIRED.contains(&id.as_str()) {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-IDENTITY",
                format!("{path}.id"),
                format!("unsupported capability identity {id:?}"),
            ));
        }
        let status = required_string(object, "status", &path, diagnostics);
        if status
            .as_deref()
            .is_some_and(|value| value == "planned" || value == "missing")
        {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-MATERIALIZATION",
                format!("{path}.status"),
                "planned or missing capabilities fail closed; use an explicit unavailable descriptor",
            ));
        } else if status
            .as_deref()
            .is_some_and(|value| !["declared", "unavailable"].contains(&value))
        {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-SCHEMA",
                format!("{path}.status"),
                "capability status must be declared or unavailable",
            ));
        }
        if let Some(identity) = required_object(object, "identity", &path, diagnostics) {
            validate_identity(identity, &format!("{path}.identity"), diagnostics);
        }
        validate_dependency_list(
            object.get("dependencies"),
            &format!("{path}.dependencies"),
            diagnostics,
        );
        validate_provider_list(
            object.get("providers"),
            &format!("{path}.providers"),
            id.as_str(),
            diagnostics,
        );
        validate_paths(
            object.get("source_paths"),
            &format!("{path}.source_paths"),
            root,
            fixture_root,
            diagnostics,
        );
        validate_expected_artifacts(
            object.get("expected_artifacts"),
            &format!("{path}.expected_artifacts"),
            fixture_root,
            diagnostics,
        );
        validate_raw_location(
            object.get("raw_diagnostic_location"),
            &format!("{path}.raw_diagnostic_location"),
            fixture_root,
            diagnostics,
        );
        validate_materialization(
            object.get("materialization"),
            &format!("{path}.materialization"),
            diagnostics,
            true,
        );
        if status.as_deref() == Some("unavailable")
            && required_string(object, "unavailable_reason", &path, diagnostics).is_none()
        {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-MATERIALIZATION",
                format!("{path}.unavailable_reason"),
                "unavailable capabilities require a stable reason",
            ));
        }
    }
    for required in REQUIRED {
        if !found.contains(required) {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-IDENTITY",
                format!("{manifest_path}.capabilities"),
                format!("required capability identity {required:?} is missing"),
            ));
        }
    }
    found
}

fn validate_cases(
    values: &[Value],
    path: &str,
    root: &Path,
    fixture_root: &Path,
    capabilities: &BTreeSet<String>,
    diagnostics: &mut Diagnostics,
) {
    let mut kinds = BTreeSet::new();
    let mut ids = BTreeSet::new();
    for (index, value) in values.iter().enumerate() {
        let item_path = format!("{path}[{index}]");
        let Some(object) = value.as_object() else {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-SCHEMA",
                item_path,
                "case declaration must be an object",
            ));
            continue;
        };
        const ALLOWED: [&str; 12] = [
            "id",
            "kind",
            "status",
            "evidence_status",
            "capability_ids",
            "input_paths",
            "expected_artifacts",
            "raw_diagnostics",
            "materialization",
            "feature_ids",
            "dependency_identities",
            "provider_identities",
        ];
        reject_unknown_fields(object, &ALLOWED, &item_path, diagnostics);
        let Some(id) = required_string(object, "id", &item_path, diagnostics) else {
            continue;
        };
        if !ids.insert(id) {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-CASE",
                format!("{item_path}.id"),
                "case IDs must be unique",
            ));
        }
        let kind = required_string(object, "kind", &item_path, diagnostics);
        if let Some(kind) = kind {
            kinds.insert(kind.clone());
            if !REQUIRED_CASE_KINDS.contains(&kind.as_str()) {
                diagnostics.push(Diagnostic::new(
                    "HTTP-ACCEPTANCE-CASE",
                    format!("{item_path}.kind"),
                    format!("unsupported case kind {kind:?}"),
                ));
            }
        }
        let status = required_string(object, "status", &item_path, diagnostics);
        if status
            .as_deref()
            .is_some_and(|value| value == "planned" || value == "missing")
        {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-MATERIALIZATION",
                format!("{item_path}.status"),
                "planned or missing cases fail closed",
            ));
        } else if status
            .as_deref()
            .is_some_and(|value| !["declared", "unavailable"].contains(&value))
        {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-CASE",
                format!("{item_path}.status"),
                "case status must be declared or unavailable",
            ));
        }
        check_string(
            object,
            "evidence_status",
            &item_path,
            diagnostics,
            Some("not-run-static"),
        );
        validate_string_list_refs(
            object,
            "capability_ids",
            &item_path,
            capabilities,
            diagnostics,
        );
        validate_path_list(
            object.get("input_paths"),
            &format!("{item_path}.input_paths"),
            root,
            fixture_root,
            true,
            diagnostics,
        );
        validate_expected_artifacts(
            object.get("expected_artifacts"),
            &format!("{item_path}.expected_artifacts"),
            fixture_root,
            diagnostics,
        );
        if let Some(raw) = required_array(object, "raw_diagnostics", &item_path, diagnostics) {
            validate_raw_diagnostics(
                raw,
                &format!("{item_path}.raw_diagnostics"),
                fixture_root,
                diagnostics,
            );
        }
        validate_materialization(
            object.get("materialization"),
            &format!("{item_path}.materialization"),
            diagnostics,
            false,
        );
        validate_feature_ids(object, &item_path, diagnostics);
        validate_identity_list(
            object.get("dependency_identities"),
            &format!("{item_path}.dependency_identities"),
            diagnostics,
        );
        validate_identity_list(
            object.get("provider_identities"),
            &format!("{item_path}.provider_identities"),
            diagnostics,
        );
    }
    for required in REQUIRED_CASE_KINDS {
        if !kinds.contains(required) {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-CASE",
                path,
                format!("required case kind {required:?} is missing"),
            ));
        }
    }
}

fn validate_feature_ids(object: &Map<String, Value>, path: &str, diagnostics: &mut Diagnostics) {
    let Some(values) = required_array(object, "feature_ids", path, diagnostics) else {
        return;
    };
    if values.is_empty() {
        diagnostics.push(Diagnostic::new(
            "HTTP-ACCEPTANCE-CASE",
            format!("{path}.feature_ids"),
            "at least one compatibility feature ID is required",
        ));
    }
    for (index, value) in values.iter().enumerate() {
        let item_path = format!("{path}.feature_ids[{index}]");
        let Some(value) = value.as_str() else {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-CASE",
                item_path,
                "feature IDs must be strings",
            ));
            continue;
        };
        if !ALLOWED_FEATURE_IDS.contains(&value) {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-CASE",
                item_path,
                format!("unsupported HTTP feature ID {value:?}"),
            ));
        }
    }
}

fn validate_raw_diagnostics(
    values: &[Value],
    path: &str,
    fixture_root: &Path,
    diagnostics: &mut Diagnostics,
) {
    if values.is_empty() {
        diagnostics.push(Diagnostic::new(
            "HTTP-ACCEPTANCE-DIAGNOSTIC",
            path,
            "at least one raw diagnostic location is required",
        ));
    }
    for (index, value) in values.iter().enumerate() {
        let item_path = format!("{path}[{index}]");
        let Some(object) = value.as_object() else {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-SCHEMA",
                item_path,
                "raw diagnostic declaration must be an object",
            ));
            continue;
        };
        const ALLOWED: [&str; 5] = ["path", "status", "redacted", "max_bytes", "purpose"];
        reject_unknown_fields(object, &ALLOWED, &item_path, diagnostics);
        let location = required_string(object, "path", &item_path, diagnostics);
        if let Some(location) = location {
            validate_raw_location_value(
                &location,
                &format!("{item_path}.path"),
                fixture_root,
                diagnostics,
            );
        }
        check_string(object, "status", &item_path, diagnostics, Some("declared"));
        check_bool(object, "redacted", &item_path, diagnostics, Some(true));
        if let Some(max_bytes) = check_u64(object, "max_bytes", &item_path, diagnostics, None)
            && (max_bytes == 0 || max_bytes > 64 * 1024)
        {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-BOUNDS",
                format!("{item_path}.max_bytes"),
                "raw diagnostic bound must be in 1..=65536 bytes",
            ));
        }
        check_string(object, "purpose", &item_path, diagnostics, None);
    }
}

fn validate_identity(object: &Map<String, Value>, path: &str, diagnostics: &mut Diagnostics) {
    reject_unknown_fields(object, &ALLOWED_IDENTITY_FIELDS, path, diagnostics);
    let _ = required_string(object, "schema_id", path, diagnostics);
    if check_u64(object, "version", path, diagnostics, None).is_some_and(|value| value == 0) {
        diagnostics.push(Diagnostic::new(
            "HTTP-ACCEPTANCE-IDENTITY",
            format!("{path}.version"),
            "identity version must be nonzero",
        ));
    }
    if let Some(value) = required_string(object, "sha256", path, diagnostics)
        && !is_sha256(&value)
    {
        diagnostics.push(Diagnostic::new(
            "HTTP-ACCEPTANCE-IDENTITY",
            format!("{path}.sha256"),
            "identity sha256 must be 64 lowercase hexadecimal characters",
        ));
    }
}

fn validate_dependency_list(value: Option<&Value>, path: &str, diagnostics: &mut Diagnostics) {
    let Some(values) = value.and_then(Value::as_array) else {
        diagnostics.push(Diagnostic::new(
            "HTTP-ACCEPTANCE-IDENTITY",
            path,
            "dependencies must be a declared array of exact identities",
        ));
        return;
    };
    if values.is_empty() {
        diagnostics.push(Diagnostic::new(
            "HTTP-ACCEPTANCE-IDENTITY",
            path,
            "at least one exact dependency identity is required",
        ));
    }
    validate_identity_list(Some(&Value::Array(values.to_vec())), path, diagnostics);
}

fn validate_provider_list(
    value: Option<&Value>,
    path: &str,
    capability_id: &str,
    diagnostics: &mut Diagnostics,
) {
    let Some(values) = value.and_then(Value::as_array) else {
        diagnostics.push(Diagnostic::new(
            "HTTP-ACCEPTANCE-IDENTITY",
            path,
            "providers must be a declared array of exact identities",
        ));
        return;
    };
    if values.is_empty() && capability_id != "http.native/1" {
        diagnostics.push(Diagnostic::new(
            "HTTP-ACCEPTANCE-IDENTITY",
            path,
            "JMeter capability requires an exact provider identity",
        ));
    }
    validate_identity_list(Some(&Value::Array(values.to_vec())), path, diagnostics);
}

fn validate_identity_list(value: Option<&Value>, path: &str, diagnostics: &mut Diagnostics) {
    let Some(values) = value.and_then(Value::as_array) else {
        diagnostics.push(Diagnostic::new(
            "HTTP-ACCEPTANCE-IDENTITY",
            path,
            "identity list must be an array",
        ));
        return;
    };
    for (index, value) in values.iter().enumerate() {
        let item_path = format!("{path}[{index}]");
        if let Some(object) = value.as_object() {
            validate_identity(object, &item_path, diagnostics);
            let _ = required_string(object, "name", &item_path, diagnostics);
            let _ = required_string(object, "source", &item_path, diagnostics);
        } else {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-IDENTITY",
                item_path,
                "identity list entries must be objects",
            ));
        }
    }
}

fn validate_paths(
    value: Option<&Value>,
    path: &str,
    root: &Path,
    fixture_root: &Path,
    diagnostics: &mut Diagnostics,
) {
    let Some(values) = value.and_then(Value::as_array) else {
        diagnostics.push(Diagnostic::new(
            "HTTP-ACCEPTANCE-PATH",
            path,
            "source_paths must be an array",
        ));
        return;
    };
    validate_path_list(
        Some(&Value::Array(values.to_vec())),
        path,
        root,
        fixture_root,
        true,
        diagnostics,
    );
}

fn validate_path_list(
    value: Option<&Value>,
    path: &str,
    root: &Path,
    fixture_root: &Path,
    require_materialized: bool,
    diagnostics: &mut Diagnostics,
) {
    let Some(values) = value.and_then(Value::as_array) else {
        diagnostics.push(Diagnostic::new(
            "HTTP-ACCEPTANCE-PATH",
            path,
            "path list must be an array",
        ));
        return;
    };
    if values.is_empty() {
        diagnostics.push(Diagnostic::new(
            "HTTP-ACCEPTANCE-PATH",
            path,
            "at least one declared path is required",
        ));
    }
    for (index, value) in values.iter().enumerate() {
        let item_path = format!("{path}[{index}]");
        let Some(value) = value.as_str() else {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-PATH",
                item_path,
                "declared path must be a string",
            ));
            continue;
        };
        let base = if value.starts_with("compat/") || value.starts_with("crates/") {
            root
        } else {
            fixture_root
        };
        let Some(path_value) = safe_relative_path(value) else {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-PATH",
                format!("{path}[{index}]"),
                "declared paths must be relative and cannot contain parent, root, or prefix components",
            ));
            continue;
        };
        if require_materialized {
            match read_bounded_file(&base.join(path_value), MAX_DECLARED_FILE_BYTES) {
                Ok(_) => {}
                Err(error) => diagnostics.push(read_diagnostic(&format!("{path}[{index}]"), error)),
            }
        }
    }
}

fn validate_expected_artifacts(
    value: Option<&Value>,
    path: &str,
    fixture_root: &Path,
    diagnostics: &mut Diagnostics,
) {
    let Some(values) = value.and_then(Value::as_array) else {
        diagnostics.push(Diagnostic::new(
            "HTTP-ACCEPTANCE-ARTIFACT",
            path,
            "expected_artifacts must be an array",
        ));
        return;
    };
    if values.is_empty() {
        diagnostics.push(Diagnostic::new(
            "HTTP-ACCEPTANCE-ARTIFACT",
            path,
            "at least one expected artifact must be declared",
        ));
    }
    for (index, value) in values.iter().enumerate() {
        let item_path = format!("{path}[{index}]");
        let Some(object) = value.as_object() else {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-SCHEMA",
                item_path,
                "expected artifact declaration must be an object",
            ));
            continue;
        };
        const ALLOWED: [&str; 5] = ["path", "schema_id", "schema_version", "sha256", "status"];
        reject_unknown_fields(object, &ALLOWED, &item_path, diagnostics);
        let artifact_path = required_string(object, "path", &item_path, diagnostics);
        if let Some(schema_id) = check_string(object, "schema_id", &item_path, diagnostics, None)
            && !ALLOWED_EXPECTED_SCHEMA_IDS.contains(&schema_id.as_str())
        {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-SCHEMA",
                format!("{item_path}.schema_id"),
                format!("unsupported expected-artifact schema identity {schema_id:?}"),
            ));
        }
        if check_u64(object, "schema_version", &item_path, diagnostics, None)
            .is_some_and(|version| version == 0)
        {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-SCHEMA",
                format!("{item_path}.schema_version"),
                "expected-artifact schema version must be nonzero",
            ));
        }
        let status = check_string(object, "status", &item_path, diagnostics, Some("declared"));
        if status
            .as_deref()
            .is_some_and(|value| value == "planned" || value == "missing")
        {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-MATERIALIZATION",
                format!("{item_path}.status"),
                "planned or missing expected artifacts fail closed",
            ));
        }
        if let Some(artifact_path) = artifact_path {
            let Some(path_value) = safe_relative_path(&artifact_path) else {
                diagnostics.push(Diagnostic::new(
                    "HTTP-ACCEPTANCE-PATH",
                    format!("{item_path}.path"),
                    "expected artifact path must be relative and contained",
                ));
                continue;
            };
            let path = fixture_root.join(path_value);
            match read_bounded_file(&path, MAX_DECLARED_FILE_BYTES) {
                Ok(bytes) => {
                    if let Some(expected) = object.get("sha256").and_then(Value::as_str) {
                        if !is_sha256(expected) {
                            diagnostics.push(Diagnostic::new(
                                "HTTP-ACCEPTANCE-IDENTITY",
                                format!("{item_path}.sha256"),
                                "artifact sha256 must be 64 lowercase hexadecimal characters",
                            ));
                        } else {
                            let actual = hex_digest(&bytes);
                            if actual != expected {
                                diagnostics.push(Diagnostic::new(
                                    "HTTP-ACCEPTANCE-ARTIFACT",
                                    format!("{item_path}.sha256"),
                                    "expected artifact digest does not match the materialized file",
                                ));
                            }
                        }
                    } else {
                        diagnostics.push(Diagnostic::new(
                            "HTTP-ACCEPTANCE-IDENTITY",
                            format!("{item_path}.sha256"),
                            "expected artifacts require an exact sha256",
                        ));
                    }
                }
                Err(error) => {
                    diagnostics.push(read_diagnostic(&format!("{item_path}.path"), error))
                }
            }
        }
    }
}

fn validate_raw_location(
    value: Option<&Value>,
    path: &str,
    fixture_root: &Path,
    diagnostics: &mut Diagnostics,
) {
    let Some(value) = value.and_then(Value::as_str) else {
        diagnostics.push(Diagnostic::new(
            "HTTP-ACCEPTANCE-DIAGNOSTIC",
            path,
            "raw_diagnostic_location must be declared as a string",
        ));
        return;
    };
    validate_raw_location_value(value, path, fixture_root, diagnostics);
}

fn validate_raw_location_value(
    value: &str,
    path: &str,
    _fixture_root: &Path,
    diagnostics: &mut Diagnostics,
) {
    let Some(path_value) = safe_relative_path(value) else {
        diagnostics.push(Diagnostic::new(
            "HTTP-ACCEPTANCE-PATH",
            path,
            "raw diagnostic location must be a contained relative path",
        ));
        return;
    };
    let normalized = path_value.to_string_lossy();
    if !(normalized.starts_with("oracle-runs/") || normalized.starts_with("diagnostics/")) {
        diagnostics.push(Diagnostic::new(
            "HTTP-ACCEPTANCE-DIAGNOSTIC",
            path,
            "raw diagnostic location must be under oracle-runs/ or diagnostics/",
        ));
    }
}

fn validate_materialization(
    value: Option<&Value>,
    path: &str,
    diagnostics: &mut Diagnostics,
    source_fixture_required: bool,
) {
    let Some(object) = value.and_then(Value::as_object) else {
        diagnostics.push(Diagnostic::new(
            "HTTP-ACCEPTANCE-MATERIALIZATION",
            path,
            "materialization declaration is required",
        ));
        return;
    };
    const ALLOWED: [&str; 4] = [
        "source_fixture_present",
        "oracle_evidence_materialized",
        "observed_run",
        "status",
    ];
    reject_unknown_fields(object, &ALLOWED, path, diagnostics);
    check_bool(
        object,
        "source_fixture_present",
        path,
        diagnostics,
        Some(source_fixture_required),
    );
    check_bool(
        object,
        "oracle_evidence_materialized",
        path,
        diagnostics,
        Some(false),
    );
    check_bool(object, "observed_run", path, diagnostics, Some(false));
    check_string(object, "status", path, diagnostics, Some("declared"));
}

fn validate_string_list_refs(
    object: &Map<String, Value>,
    field: &str,
    path: &str,
    allowed: &BTreeSet<String>,
    diagnostics: &mut Diagnostics,
) {
    let Some(values) = required_array(object, field, path, diagnostics) else {
        return;
    };
    if values.is_empty() {
        diagnostics.push(Diagnostic::new(
            "HTTP-ACCEPTANCE-IDENTITY",
            format!("{path}.{field}"),
            "at least one capability identity reference is required",
        ));
    }
    for (index, value) in values.iter().enumerate() {
        let item_path = format!("{path}.{field}[{index}]");
        let Some(value) = value.as_str() else {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-IDENTITY",
                item_path,
                "capability references must be strings",
            ));
            continue;
        };
        if !allowed.contains(value) {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-IDENTITY",
                item_path,
                "case references an undeclared capability",
            ));
        }
    }
}

fn reject_unknown_fields(
    object: &Map<String, Value>,
    allowed: &[&str],
    path: &str,
    diagnostics: &mut Diagnostics,
) {
    for field in object.keys() {
        if !allowed.contains(&field.as_str()) {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-SCHEMA",
                format!("{path}.{field}"),
                "unknown field is not permitted by the closed HTTP acceptance schema",
            ));
        }
    }
}

fn required_array<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    path: &str,
    diagnostics: &mut Diagnostics,
) -> Option<&'a Vec<Value>> {
    match object.get(field) {
        Some(Value::Array(values)) => Some(values),
        Some(_) => {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-SCHEMA",
                format!("{path}.{field}"),
                "field must be an array",
            ));
            None
        }
        None => {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-SCHEMA",
                format!("{path}.{field}"),
                "required field is missing",
            ));
            None
        }
    }
}

fn required_object<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    path: &str,
    diagnostics: &mut Diagnostics,
) -> Option<&'a Map<String, Value>> {
    match object.get(field) {
        Some(Value::Object(values)) => Some(values),
        Some(_) => {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-SCHEMA",
                format!("{path}.{field}"),
                "field must be an object",
            ));
            None
        }
        None => {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-SCHEMA",
                format!("{path}.{field}"),
                "required field is missing",
            ));
            None
        }
    }
}

fn required_string(
    object: &Map<String, Value>,
    field: &str,
    path: &str,
    diagnostics: &mut Diagnostics,
) -> Option<String> {
    match object.get(field) {
        Some(Value::String(value)) if !value.trim().is_empty() => Some(value.clone()),
        Some(Value::String(_)) => {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-SCHEMA",
                format!("{path}.{field}"),
                "string field must not be empty",
            ));
            None
        }
        Some(_) => {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-SCHEMA",
                format!("{path}.{field}"),
                "field must be a non-empty string",
            ));
            None
        }
        None => {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-SCHEMA",
                format!("{path}.{field}"),
                "required field is missing",
            ));
            None
        }
    }
}

fn check_string(
    object: &Map<String, Value>,
    field: &str,
    path: &str,
    diagnostics: &mut Diagnostics,
    expected: Option<&str>,
) -> Option<String> {
    let value = required_string(object, field, path, diagnostics)?;
    if let Some(expected) = expected
        && value != expected
    {
        diagnostics.push(Diagnostic::new(
            "HTTP-ACCEPTANCE-SCHEMA",
            format!("{path}.{field}"),
            format!("must be {expected:?}"),
        ));
    }
    Some(value)
}

fn check_u64(
    object: &Map<String, Value>,
    field: &str,
    path: &str,
    diagnostics: &mut Diagnostics,
    expected: Option<u64>,
) -> Option<u64> {
    let value = match object.get(field) {
        Some(Value::Number(value)) => value.as_u64(),
        Some(_) => None,
        None => {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-SCHEMA",
                format!("{path}.{field}"),
                "required unsigned integer field is missing",
            ));
            return None;
        }
    };
    let Some(value) = value else {
        diagnostics.push(Diagnostic::new(
            "HTTP-ACCEPTANCE-SCHEMA",
            format!("{path}.{field}"),
            "field must be a non-negative integer",
        ));
        return None;
    };
    if let Some(expected) = expected
        && value != expected
    {
        diagnostics.push(Diagnostic::new(
            "HTTP-ACCEPTANCE-SCHEMA",
            format!("{path}.{field}"),
            format!("must be {expected}, got {value}"),
        ));
    }
    Some(value)
}

fn check_i64(
    object: &Map<String, Value>,
    field: &str,
    path: &str,
    diagnostics: &mut Diagnostics,
    expected: Option<i64>,
) -> Option<i64> {
    let value = match object.get(field) {
        Some(Value::Number(value)) => value.as_i64(),
        Some(_) => None,
        None => {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-SCHEMA",
                format!("{path}.{field}"),
                "required integer field is missing",
            ));
            return None;
        }
    };
    let Some(value) = value else {
        diagnostics.push(Diagnostic::new(
            "HTTP-ACCEPTANCE-SCHEMA",
            format!("{path}.{field}"),
            "field must be an integer",
        ));
        return None;
    };
    if let Some(expected) = expected
        && value != expected
    {
        diagnostics.push(Diagnostic::new(
            "HTTP-ACCEPTANCE-SCHEMA",
            format!("{path}.{field}"),
            format!("must be {expected}, got {value}"),
        ));
    }
    Some(value)
}

fn check_bool(
    object: &Map<String, Value>,
    field: &str,
    path: &str,
    diagnostics: &mut Diagnostics,
    expected: Option<bool>,
) -> Option<bool> {
    let value = match object.get(field) {
        Some(Value::Bool(value)) => *value,
        Some(_) => {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-SCHEMA",
                format!("{path}.{field}"),
                "field must be a boolean",
            ));
            return None;
        }
        None => {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-SCHEMA",
                format!("{path}.{field}"),
                "required boolean field is missing",
            ));
            return None;
        }
    };
    if let Some(expected) = expected
        && value != expected
    {
        diagnostics.push(Diagnostic::new(
            "HTTP-ACCEPTANCE-SCHEMA",
            format!("{path}.{field}"),
            format!("must be {expected}, got {value}"),
        ));
    }
    Some(value)
}

fn check_string_list_exact(
    object: &Map<String, Value>,
    field: &str,
    path: &str,
    expected: &[&str],
    diagnostics: &mut Diagnostics,
) {
    let Some(values) = required_array(object, field, path, diagnostics) else {
        return;
    };
    let actual = values.iter().filter_map(Value::as_str).collect::<Vec<_>>();
    if actual != expected {
        diagnostics.push(Diagnostic::new(
            "HTTP-ACCEPTANCE-SCHEMA",
            format!("{path}.{field}"),
            format!("must exactly match {expected:?}"),
        ));
    }
}

fn check_string_list_nonempty_exact_prefix(
    object: &Map<String, Value>,
    field: &str,
    path: &str,
    prefixes: &[&str],
    diagnostics: &mut Diagnostics,
) {
    let Some(values) = required_array(object, field, path, diagnostics) else {
        return;
    };
    if values.is_empty()
        || values.iter().any(|value| {
            value
                .as_str()
                .is_none_or(|value| !prefixes.iter().any(|prefix| value.starts_with(prefix)))
        })
    {
        diagnostics.push(Diagnostic::new(
            "HTTP-ACCEPTANCE-SCHEMA",
            format!("{path}.{field}"),
            "must be a non-empty list of stable codes with an allowed prefix",
        ));
    }
}

fn validate_json_limits(
    value: &Value,
    path: &str,
    depth: usize,
    nodes: &mut usize,
    diagnostics: &mut Diagnostics,
) {
    *nodes = nodes.saturating_add(1);
    if depth > MAX_JSON_DEPTH {
        diagnostics.push(Diagnostic::new(
            "HTTP-ACCEPTANCE-BOUNDS",
            path,
            format!("JSON nesting exceeds {MAX_JSON_DEPTH} levels"),
        ));
        return;
    }
    if *nodes > MAX_JSON_NODES {
        diagnostics.push(Diagnostic::new(
            "HTTP-ACCEPTANCE-BOUNDS",
            path,
            format!("JSON node count exceeds {MAX_JSON_NODES}"),
        ));
        return;
    }
    match value {
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                validate_json_limits(
                    value,
                    &format!("{path}[{index}]"),
                    depth + 1,
                    nodes,
                    diagnostics,
                );
                if *nodes > MAX_JSON_NODES {
                    break;
                }
            }
        }
        Value::Object(values) => {
            for (key, value) in values {
                validate_json_limits(
                    value,
                    &format!("{path}.{key}"),
                    depth + 1,
                    nodes,
                    diagnostics,
                );
                if *nodes > MAX_JSON_NODES {
                    break;
                }
            }
        }
        _ => {}
    }
}

fn read_json(path: &Path, maximum: u64) -> Result<Value, ReadError> {
    let bytes = read_bounded_file(path, maximum)?;
    serde_json::from_slice(&bytes)
        .map_err(|_| ReadError::Read(io::Error::new(io::ErrorKind::InvalidData, "invalid JSON")))
}

fn read_bounded_file(path: &Path, maximum: u64) -> Result<Vec<u8>, ReadError> {
    let (file, metadata) = open_bounded_file(path, maximum)?;
    read_bounded_handle(file, path, &metadata, maximum)
}

fn open_bounded_file(path: &Path, maximum: u64) -> Result<(File, Metadata), ReadError> {
    if safe_relative_path(path.to_string_lossy().as_ref()).is_none() && path.is_relative() {
        return Err(ReadError::Changed);
    }
    reject_symlink_components(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    options.custom_flags(O_NOFOLLOW | O_NONBLOCK);
    let file = options.open(path).map_err(ReadError::Open)?;
    let metadata = file.metadata().map_err(ReadError::HandleMetadata)?;
    validate_binding(path, &metadata, maximum)?;
    Ok((file, metadata))
}

fn reject_symlink_components(path: &Path) -> Result<(), ReadError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current).map_err(ReadError::PathMetadata)?;
        if metadata.file_type().is_symlink() {
            return Err(ReadError::Symlink);
        }
    }
    Ok(())
}

fn validate_binding(path: &Path, handle: &Metadata, maximum: u64) -> Result<(), ReadError> {
    if !handle.is_file() {
        return Err(ReadError::NonRegular);
    }
    if handle.len() > maximum {
        return Err(ReadError::TooLarge(maximum));
    }
    let path_metadata = fs::symlink_metadata(path).map_err(ReadError::PathMetadata)?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(if path_metadata.file_type().is_symlink() {
            ReadError::Symlink
        } else {
            ReadError::NonRegular
        });
    }
    if !same_file_identity(handle, &path_metadata) || handle.len() != path_metadata.len() {
        return Err(ReadError::Changed);
    }
    Ok(())
}

fn read_bounded_handle(
    mut file: File,
    path: &Path,
    initial: &Metadata,
    maximum: u64,
) -> Result<Vec<u8>, ReadError> {
    let capacity = usize::try_from(maximum.checked_add(1).ok_or(ReadError::InvalidLimit)?)
        .map_err(|_| ReadError::InvalidLimit)?;
    let mut bytes = Vec::with_capacity(capacity.min(MAX_DECLARED_FILE_BYTES as usize + 1));
    let mut chunk = [0_u8; READ_CHUNK_BYTES];
    loop {
        if bytes.len() == capacity {
            break;
        }
        let length = (capacity - bytes.len()).min(chunk.len());
        let count = file.read(&mut chunk[..length]).map_err(ReadError::Read)?;
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    if u64::try_from(bytes.len()).map_err(|_| ReadError::InvalidLimit)? > maximum {
        return Err(ReadError::Grew(maximum));
    }
    let final_metadata = file.metadata().map_err(ReadError::HandleMetadata)?;
    validate_binding(path, &final_metadata, maximum)?;
    let count = u64::try_from(bytes.len()).map_err(|_| ReadError::InvalidLimit)?;
    if final_metadata.len() < initial.len() || count < initial.len() {
        return Err(ReadError::Truncated);
    }
    if final_metadata.len() != initial.len() || count != initial.len() {
        return Err(ReadError::Changed);
    }
    Ok(bytes)
}

#[cfg(unix)]
fn same_file_identity(left: &Metadata, right: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(windows)]
fn same_file_identity(left: &Metadata, right: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    match (
        left.volume_serial_number(),
        left.file_index(),
        right.volume_serial_number(),
        right.file_index(),
    ) {
        (Some(left_volume), Some(left_index), Some(right_volume), Some(right_index)) => {
            left_volume == right_volume && left_index == right_index
        }
        _ => false,
    }
}

#[cfg(not(any(unix, windows)))]
fn same_file_identity(_left: &Metadata, _right: &Metadata) -> bool {
    false
}

fn read_diagnostic(path: &str, error: ReadError) -> Diagnostic {
    match error {
        ReadError::Symlink => Diagnostic::new(
            "HTTP-ACCEPTANCE-PATH",
            path,
            "declared file or one of its path components is a symlink",
        ),
        ReadError::NonRegular => Diagnostic::new(
            "HTTP-ACCEPTANCE-PATH",
            path,
            "declared file must be a regular file",
        ),
        ReadError::TooLarge(limit) | ReadError::Grew(limit) => Diagnostic::new(
            "HTTP-ACCEPTANCE-BOUNDS",
            path,
            format!("declared file exceeds {limit}-byte read bound"),
        ),
        ReadError::Truncated | ReadError::Changed => Diagnostic::new(
            "HTTP-ACCEPTANCE-IO",
            path,
            "declared file changed while being read",
        ),
        ReadError::InvalidLimit => Diagnostic::new(
            "HTTP-ACCEPTANCE-BOUNDS",
            path,
            "read bound cannot be represented on this platform",
        ),
        ReadError::Open(error)
        | ReadError::HandleMetadata(error)
        | ReadError::PathMetadata(error)
        | ReadError::Read(error) => {
            let message = if error.kind() == io::ErrorKind::NotFound {
                "declared file is missing".to_owned()
            } else if error.kind() == io::ErrorKind::InvalidData {
                "declared JSON file is invalid".to_owned()
            } else {
                format!("cannot read declared file: {error}")
            };
            Diagnostic::new("HTTP-ACCEPTANCE-IO", path, message)
        }
    }
}

fn safe_relative_path(value: &str) -> Option<PathBuf> {
    if value.is_empty() {
        return None;
    }
    let path = Path::new(value);
    if path.is_absolute() {
        return None;
    }
    let mut output = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => output.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    (!output.as_os_str().is_empty()).then_some(output)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        && value == value.to_ascii_lowercase()
        && value.bytes().any(|byte| byte != b'0')
}

fn hex_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(target_os = "linux")]
const O_NOFOLLOW: i32 = 0o400000;
#[cfg(target_os = "linux")]
const O_NONBLOCK: i32 = 0o4000;

#[cfg(test)]
mod tests {
    use super::*;

    fn base_manifest() -> Map<String, Value> {
        let mut object = Map::new();
        object.insert(
            "schema_id".to_owned(),
            Value::String(MANIFEST_SCHEMA_ID.to_owned()),
        );
        object.insert("schema_version".to_owned(), Value::from(1));
        object.insert(
            "profile_id".to_owned(),
            Value::String("jmeter-5.6.3".to_owned()),
        );
        object.insert(
            "decision_id".to_owned(),
            Value::String(DECISION_ID.to_owned()),
        );
        object.insert("decision_revision".to_owned(), Value::from(4));
        object.insert("status".to_owned(), Value::String("declared".to_owned()));
        object.insert(
            "evidence_status".to_owned(),
            Value::String("not-run-static".to_owned()),
        );
        object.insert("source_only".to_owned(), Value::Bool(true));
        object.insert(
            "materialization".to_owned(),
            serde_json::json!({
                "source_fixture_present": true,
                "oracle_evidence_materialized": false,
                "observed_run": false,
                "status": "declared"
            }),
        );
        object.insert(
            "schemas".to_owned(),
            Value::Array(
                REQUIRED_SCHEMA_IDS
                    .iter()
                    .map(|id| Value::String((*id).to_owned()))
                    .collect(),
            ),
        );
        object.insert("parser_limits".to_owned(), parser_limits());
        object.insert("contracts".to_owned(), contracts());
        object.insert(
            "retry_policy".to_owned(),
            serde_json::json!({
                "owner": "semantic-layer",
                "native_transparent_retry": false,
                "redirects": "semantic-layer",
                "authentication": "semantic-layer",
                "body_replay": "semantic-layer",
                "uncertain_outcome": "no-retry",
                "httpclient4": {
                    "httpclient4.retrycount": 0,
                    "httpclient4.request_sent_retry_enabled": false
                }
            }),
        );
        object.insert(
            "automation_policy".to_owned(),
            serde_json::json!({
                "redirects": "disabled",
                "authentication": "disabled",
                "client_retries": "disabled",
                "unobserved_hop": "reject",
                "unobserved_challenge": "reject",
                "unobserved_retry": "reject"
            }),
        );
        object.insert(
            "transaction_policies".to_owned(),
            serde_json::json!({
                "redirect": {"commit": "new-attempt", "boundary": "semantic", "max_count": 64, "ordered": false},
                "authentication": {"commit": "new-attempt", "boundary": "semantic", "max_count": 32, "ordered": false},
                "embedded_resources": {"commit": "ordered-subresult", "boundary": "semantic", "max_count": 4096, "ordered": true},
                "state": {"commit": "atomic-cas", "conflict": "no-apply"}
            }),
        );
        object.insert("capabilities".to_owned(), Value::Array(Vec::new()));
        object.insert("cases".to_owned(), Value::Array(Vec::new()));
        object.insert("raw_diagnostics".to_owned(), Value::Array(Vec::new()));
        object
    }

    fn parser_limits() -> Value {
        let maxima = REQUIRED_HARD_MAXIMA
            .iter()
            .map(|(name, value)| ((*name).to_owned(), Value::from(*value)))
            .collect::<Map<_, _>>();
        serde_json::json!({
            "schema_id": "http.parser-limits/1",
            "schema_version": 1,
            "categories": REQUIRED_PARSER_CATEGORIES,
            "hard_maxima": maxima.clone(),
            "active": maxima
        })
    }

    fn contracts() -> Value {
        serde_json::json!({
            "attempt": {
                "schema_id": "http.attempt/1", "schema_version": 1, "max_bytes": 4194304,
                "max_headers": 1024, "max_header_bytes": 1048576,
                "max_informational_responses": 32, "max_trailers": 256, "max_phases": 32,
                "max_counters": 32, "max_diagnostics": 64, "ordered_headers": true,
                "byte_counter_states": ["Known", "Unavailable"], "outcome_enum": ["ResponseComplete", "TransportFailure", "ProtocolFailure", "TimedOut", "Cancelled", "DecompressionFailure", "TlsFailure", "EnvironmentFailure"],
                "identity_fields": ["source_context", "operation_id", "attempt_index", "capability_identity", "route_identity"]
            },
            "state_delta": {
                "schema_id": "http.state-delta/1", "schema_version": 1,
                "operations": ["CookieUpsert", "CookieDelete", "CookieClear", "CacheUpsert", "CacheDelete", "CacheInvalidate", "AuthChallengeUpsert", "AuthChallengeDelete", "AuthChallengeClear", "DnsUpsert", "DnsDelete", "DnsClear", "HeaderReplace", "HeaderAppend", "HeaderRemove", "ConnectionObserve", "ConnectionForget"],
                "aggregate": "HttpUserStateV1", "compare_and_swap": true, "missing_present_empty": true
            },
            "error_context": {
                "schema_id": "http.error-context/1", "schema_version": 1,
                "source_node": "Unknown|DomainQualifiedNode", "plan_path": "bounded-domain-qualified",
                "sampler_identity": "bounded-sampler-identity", "capability_identity": "schema-version-sha256",
                "embedded_resource_index": "Absent|Present(u32)",
                "phase_enum": ["dns", "pool", "connect", "proxy", "tls", "write", "read", "framing", "decompression", "timeout"],
                "stable_error_codes": ["http.timeout", "http.resource-limit"],
                "diagnostics": {"max_records": 64, "max_record_bytes": 4096, "max_total_bytes": 65536, "redacted": true}
            },
            "body": {
                "state_schema_id": "http.body-state/1", "replay_schema_id": "http.body-replay/1",
                "state_order": ["Fresh", "Reading", "Ended", "Failed", "Cancelled"],
                "transitions": ["Fresh->Reading", "Reading->Fresh", "Fresh->Ended", "Fresh->Failed", "Fresh->Cancelled"],
                "replayable_modes": ["explicit"], "replay_requires_original_budget": true,
                "replay_requires_new_attempt": true, "no_replay_after_bytes_sent": true
            },
            "budget": {
                "schema_id": "http.budget-handoff/1", "schema_version": 1, "units": "nanoseconds",
                "max_receiver_cap_ns": 86400000000000u64, "reservation_rounding": "up", "grant_rounding": "down",
                "required_fields": ["remaining_ns", "reservation_ns", "grant_ns", "cap_ns", "deadline_ns"]
            }
        })
    }

    #[test]
    fn missing_required_schema_is_rejected() {
        let mut manifest = base_manifest();
        manifest.insert("schemas".to_owned(), serde_json::json!(["http.attempt/1"]));
        let mut diagnostics = Diagnostics::default();
        validate_manifest(
            Path::new("."),
            Path::new("."),
            "manifest",
            &manifest,
            "jmeter-5.6.3",
            &mut diagnostics,
        );
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "HTTP-ACCEPTANCE-SCHEMA"
                && diagnostic.message.contains("http.state-delta/1")
        }));
    }

    #[test]
    fn parser_order_and_hard_maximum_are_closed() {
        let mut parser = parser_limits();
        let Some(object) = parser.as_object_mut() else {
            return;
        };
        object.insert("categories".to_owned(), serde_json::json!(["headers"]));
        let Some(maxima) = object.get_mut("hard_maxima").and_then(Value::as_object_mut) else {
            return;
        };
        maxima.insert("header_fields".to_owned(), Value::from(2));
        let mut diagnostics = Diagnostics::default();
        validate_parser_limits(object, "parser_limits", &mut diagnostics);
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "HTTP-ACCEPTANCE-PARSER" && diagnostic.path.ends_with("categories")
        }));
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "HTTP-ACCEPTANCE-PARSER"
                && diagnostic.path.ends_with("hard_maxima.header_fields")
        }));
    }

    #[test]
    fn planned_artifact_and_unbounded_diagnostic_fail_closed() {
        let mut artifact = serde_json::json!({
            "path": "expected.json", "schema_id": "http.attempt/1", "schema_version": 1,
            "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
            "status": "planned"
        });
        let Some(artifact_object) = artifact.as_object_mut() else {
            return;
        };
        let mut diagnostics = Diagnostics::default();
        validate_expected_artifacts(
            Some(&Value::Array(vec![Value::Object(artifact_object.clone())])),
            "artifacts",
            Path::new("."),
            &mut diagnostics,
        );
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "HTTP-ACCEPTANCE-MATERIALIZATION"
                && diagnostic.message.contains("planned")
        }));
    }

    #[test]
    fn unsafe_path_is_rejected_before_read() {
        let mut diagnostics = Diagnostics::default();
        validate_raw_location_value(
            "oracle-runs/../secrets.txt",
            "diagnostic.path",
            Path::new("."),
            &mut diagnostics,
        );
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "HTTP-ACCEPTANCE-PATH")
        );
    }
}
