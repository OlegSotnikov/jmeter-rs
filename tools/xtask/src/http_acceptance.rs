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
// Keep this in lockstep with the accepted decision record.  A stale revision
// must make the declaration fail closed: otherwise a manifest can appear to
// describe the current wire/evidence contract while omitting a newly added
// boundary.
const DECISION_REVISION: u64 = 9;
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

const REQUIRED_ATTEMPT_OUTCOMES: [&str; 7] = [
    "ResponseComplete",
    "TransportFailure",
    "ProtocolFailure",
    "TimedOut",
    "Cancelled",
    "ResourceLimit",
    "CapabilityUnavailable",
];

// These are the only stable error-code spellings admitted by the Decision
// 0006 evidence contract. Provider prose belongs in a bounded redacted
// diagnostic; accepting arbitrary `http.*` strings here would make a typo (or
// a provider-specific error) look like a portable compatibility key.
const REQUIRED_STABLE_ERROR_CODES: &[&str] = &[
    "http.dns",
    "http.pool",
    "http.connect",
    "http.proxy",
    "http.tls",
    "http.write",
    "http.read",
    "http.framing",
    "http.decompression",
    "http.timeout",
    "http.cancelled",
    "http.body-replay",
    "http.body-state",
    "http.response-lease",
    "http.state-conflict",
    "http.unsupported-implementation",
    "http.unsupported-auth",
    "http.unsupported-store",
    "http.automation-enabled",
    "http.budget-invalid",
    "http.recorder",
    "http.mirror",
    "http.internal-invariant",
    "http.limit.request-target",
    "http.limit.authority",
    "http.limit.status-line",
    "http.limit.reason",
    "http.limit.header-count",
    "http.limit.header-name",
    "http.limit.header-value",
    "http.limit.header-aggregate",
    "http.limit.informational-count",
    "http.limit.informational-aggregate",
    "http.limit.trailer-count",
    "http.limit.trailer-name",
    "http.limit.trailer-value",
    "http.limit.trailer-aggregate",
    "http.limit.chunk-line",
    "http.limit.chunk-count",
    "http.limit.chunk-extension-count",
    "http.limit.chunk-extension-bytes-per-chunk",
    "http.limit.chunk-extension-aggregate",
    "http.limit.wire-request-body",
    "http.limit.wire-response-body",
    "http.limit.content-length",
    "http.limit.compressed-input",
    "http.limit.decoded-output",
    "http.limit.expansion-ratio",
    "http.limit.codec-state",
    "http.limit.url-field-count",
    "http.limit.url-field-bytes",
    "http.limit.multipart-part-count",
    "http.limit.multipart-boundary",
    "http.limit.multipart-part-headers",
    "http.limit.multipart-part-body",
    "http.limit.redirect-count",
    "http.limit.redirect-retained",
    "http.limit.embedded-candidate-count",
    "http.limit.embedded-depth",
    "http.limit.embedded-concurrency",
    "http.limit.embedded-retained",
    "http.limit.trace-count",
    "http.limit.trace-bytes",
    "http.limit.diagnostic-count",
    "http.limit.diagnostic-text",
    "http.limit.diagnostic-aggregate",
];

const FORBIDDEN_SECRET_FIELDS: &[&str] = &[
    "secret",
    "password",
    "password_value",
    "credentials",
    "private_key",
    "private-key",
    "private_key_pem",
    "raw_secret",
    "secret_bytes",
    "secret_material",
    "secret_value",
    "token",
    "token_value",
    "access_token",
    "refresh_token",
    "api_key",
    "access_key",
    "credential",
    "credential_value",
    "cookie",
    "bearer",
    "authorization",
];

const IMPLEMENTATION_IDENTITIES: [(&str, &str); 4] = [
    ("http.native/1", "NativeV1"),
    ("http.native/2", "NativeV2"),
    ("http.jmeter-httpclient4/5.6.3", "JmeterHttpClient4V563"),
    ("http.jmeter-java/5.6.3", "JmeterJavaV563"),
];
const SOURCE_PROVIDER_IDENTITIES: [&str; 4] = [
    "http.native/1",
    "http.native/2",
    "http.jmeter-httpclient4/5.6.3",
    "http.jmeter-java/5.6.3",
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

// This is the JSON spelling of the normative hard-limit vector in Decision
// 0006 and the matching `ParserHardLimitsV1` field order.  Content-Length and
// compressed input have independent declarations even though both are bounded
// by the response-wire ceiling; they must be checked before any body
// allocation.  The active vector carries the same order and every value.
const REQUIRED_HARD_MAXIMA: [(&str, u64); 44] = [
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
    ("chunk_count", 16 * 1024 * 1024),
    ("chunk_extensions", 128),
    ("chunk_extension_bytes_per_chunk", 8 * 1024),
    ("chunk_extension_aggregate_bytes", 64 * 1024),
    ("wire_request_bytes", 64 * 1024 * 1024),
    ("wire_response_bytes", 256 * 1024 * 1024),
    ("content_length", 256 * 1024 * 1024),
    ("compressed_input_bytes", 256 * 1024 * 1024),
    ("decoded_response_bytes", 512 * 1024 * 1024),
    ("decompression_ratio", 1_000),
    ("decompression_absolute_bytes", 512 * 1024 * 1024),
    ("codec_state_bytes", 1024 * 1024),
    ("urlencoded_fields", 4_096),
    ("urlencoded_aggregate_bytes", 1024 * 1024),
    ("multipart_parts", 1_024),
    ("multipart_boundary_bytes", 256),
    ("multipart_headers_bytes_per_part", 256 * 1024),
    ("multipart_body_bytes_per_part", 256 * 1024 * 1024),
    ("redirects", 64),
    ("redirect_retained_bytes", 64 * 1024 * 1024),
    ("embedded_candidates", 4_096),
    ("embedded_depth", 32),
    ("embedded_concurrency", 256),
    ("embedded_retained_bytes", 512 * 1024 * 1024),
    ("trace_records", 16_384),
    ("trace_aggregate_bytes", 4 * 1024 * 1024),
    ("diagnostic_count", 64),
    ("diagnostic_text_bytes", 4 * 1024),
    ("diagnostic_aggregate_bytes", 64 * 1024),
];

const STANDALONE_SELECTOR_PROPERTY: &str = "jmeter-rs.http.capability";
const STANDALONE_SELECTOR_VALUES: [&str; 2] = ["http.native/1", "http.native/2"];
const STANDALONE_SELECTOR_OPERATIONS: [&str; 2] = [
    "-Jjmeter-rs.http.capability=http.native/1",
    "-Jjmeter-rs.http.capability=http.native/2",
];
const STANDALONE_V1_CAPABILITY: &str = "http.native/1";
const STANDALONE_V2_CAPABILITY: &str = "http.native/2";
const STANDALONE_V1_IMPLEMENTATION: &str = "NativeV1";
const STANDALONE_V2_IMPLEMENTATION: &str = "NativeV2";
const NATIVE_V2_DNS_PROPERTY: &str = "jmeter-rs.http.dns.nameservers";
const NATIVE_V2_DNS_IDENTITY: &str = "http.dns.explicit/1";
const NATIVE_V2_TLS_PROPERTY: &str = "jmeter-rs.http.tls.ca-file";
const NATIVE_V2_TLS_IDENTITY: &str = "http.tls.explicit-rustls-ring/1";
const NATIVE_V2_MAX_NAMESERVERS: u64 = 16;
const NATIVE_V2_MAX_CA_FILE_BYTES: u64 = 16 * 1024 * 1024;
const NATIVE_V2_DNS_RETURNED_ORDER: &str = "deterministic-returned-order";
const NATIVE_V2_DNS_ANSWER_LIST: &str = "bounded-without-truncation";
const NATIVE_V2_DNS_SELECTED_ADDRESS: &str = "first-address";
const NATIVE_V2_DNS_CONNECT_ATTEMPTS: &str = "exactly-one";
const NATIVE_V2_DNS_ADDRESS_FALLBACK: &str = "forbidden";
const NATIVE_V2_UNSUPPORTED: [&str; 14] = [
    "proxy",
    "redirect",
    "embedded-resources",
    "http/2",
    "decompression",
    "pooling",
    "transparent-retry",
    "manager",
    "jsse",
    "jks",
    "pkcs12",
    "pkcs11",
    "trust-all",
    "client-key",
];
const NATIVE_V2_DEPENDENCIES: [(&str, &str); 4] = [
    ("hickory-resolver", "=0.26.1"),
    ("mio", "=1.2.2"),
    ("rustls", "=0.23.43"),
    ("tokio", "=1.53.1"),
];
const NATIVE_V2_PROVIDERS: [(&str, &str); 2] = [("ring", "0.17.14"), ("rustls-webpki", "0.103.14")];

const ALLOWED_MANIFEST_FIELDS: [&str; 19] = [
    "schema_id",
    "schema_version",
    "profile_id",
    "decision_id",
    "decision_revision",
    "status",
    "evidence_status",
    "source_only",
    "materialization",
    "standalone_provider_substitution",
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
const ALLOWED_EXPECTED_SCHEMA_IDS: [&str; 16] = [
    "http.attempt/1",
    "http.native/2",
    "http.dns.explicit/1",
    "http.tls.explicit-rustls-ring/1",
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
    reject_secret_fields(&value, &display, &mut diagnostics);
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
    validate_standalone_provider_substitution(
        object.get("standalone_provider_substitution"),
        &format!("{path}.standalone_provider_substitution"),
        diagnostics,
    );

    let schemas = required_array(object, "schemas", path, diagnostics);
    if let Some(schemas) = schemas {
        validate_schemas(schemas, &format!("{path}.schemas"), diagnostics);
    }
    let parser_limits_digest =
        if let Some(parser_limits) = required_object(object, "parser_limits", path, diagnostics) {
            validate_parser_limits(parser_limits, &format!("{path}.parser_limits"), diagnostics);
            parser_limits.get("digest").and_then(Value::as_str)
        } else {
            None
        };
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
            validate_capabilities(
                capabilities,
                path,
                root,
                fixture_root,
                parser_limits_digest,
                diagnostics,
            )
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

fn validate_standalone_provider_substitution(
    value: Option<&Value>,
    path: &str,
    diagnostics: &mut Diagnostics,
) {
    let Some(object) = value.and_then(Value::as_object) else {
        diagnostics.push(Diagnostic::new(
            "HTTP-ACCEPTANCE-SELECTION",
            path,
            "standalone provider substitution declaration is required",
        ));
        return;
    };
    const ALLOWED: [&str; 8] = [
        "scope",
        "selector",
        "source_provider",
        "executed_providers",
        "without_selector",
        "admission",
        "native_edge",
        "native_v2",
    ];
    reject_unknown_fields(object, &ALLOWED, path, diagnostics);
    check_string(object, "scope", path, diagnostics, Some("plan-wide"));
    check_string(
        object,
        "without_selector",
        path,
        diagnostics,
        Some("compatibility-pack-required"),
    );

    let Some(selector) = required_object(object, "selector", path, diagnostics) else {
        return;
    };
    let selector_path = format!("{path}.selector");
    const SELECTOR_FIELDS: [&str; 7] = [
        "property",
        "values",
        "operations",
        "provenance",
        "cardinality",
        "rejected_sources",
        "invalid_inputs",
    ];
    reject_unknown_fields(selector, &SELECTOR_FIELDS, &selector_path, diagnostics);
    check_string(
        selector,
        "property",
        &selector_path,
        diagnostics,
        Some(STANDALONE_SELECTOR_PROPERTY),
    );
    check_string_list_exact(
        selector,
        "values",
        &selector_path,
        &STANDALONE_SELECTOR_VALUES,
        diagnostics,
    );
    check_string_list_exact(
        selector,
        "operations",
        &selector_path,
        &STANDALONE_SELECTOR_OPERATIONS,
        diagnostics,
    );
    check_string(
        selector,
        "provenance",
        &selector_path,
        diagnostics,
        Some("direct-command-line-only"),
    );
    check_string(
        selector,
        "cardinality",
        &selector_path,
        diagnostics,
        Some("exactly-one"),
    );
    check_string_list_exact(
        selector,
        "rejected_sources",
        &selector_path,
        &[
            "default",
            "user",
            "system",
            "additional-property",
            "environment",
            "jmeter-home",
        ],
        diagnostics,
    );
    check_string_list_exact(
        selector,
        "invalid_inputs",
        &selector_path,
        &[
            "empty",
            "removed",
            "repeated",
            "unknown",
            "non-command-line",
        ],
        diagnostics,
    );

    let Some(source_provider) = required_object(object, "source_provider", path, diagnostics)
    else {
        return;
    };
    let source_provider_path = format!("{path}.source_provider");
    const SOURCE_PROVIDER_FIELDS: [&str; 4] = ["preserved", "recorded", "lossless", "identities"];
    reject_unknown_fields(
        source_provider,
        &SOURCE_PROVIDER_FIELDS,
        &source_provider_path,
        diagnostics,
    );
    check_bool(
        source_provider,
        "preserved",
        &source_provider_path,
        diagnostics,
        Some(true),
    );
    check_bool(
        source_provider,
        "recorded",
        &source_provider_path,
        diagnostics,
        Some(true),
    );
    check_bool(
        source_provider,
        "lossless",
        &source_provider_path,
        diagnostics,
        Some(true),
    );
    check_string_list_exact(
        source_provider,
        "identities",
        &source_provider_path,
        &SOURCE_PROVIDER_IDENTITIES,
        diagnostics,
    );

    validate_executed_provider_list(
        required_array(object, "executed_providers", path, diagnostics),
        &format!("{path}.executed_providers"),
        diagnostics,
    );

    let Some(admission) = required_object(object, "admission", path, diagnostics) else {
        return;
    };
    let admission_path = format!("{path}.admission");
    const ADMISSION_FIELDS: [&str; 5] = [
        "mode",
        "resolve_before",
        "unsupported_feature",
        "supported_prefix",
        "silent_drop",
    ];
    reject_unknown_fields(admission, &ADMISSION_FIELDS, &admission_path, diagnostics);
    check_string(
        admission,
        "mode",
        &admission_path,
        diagnostics,
        Some("atomic"),
    );
    check_string_list_exact(
        admission,
        "resolve_before",
        &admission_path,
        &[
            "dns",
            "socket",
            "logger",
            "output",
            "report",
            "runtime-setup",
        ],
        diagnostics,
    );
    check_string(
        admission,
        "unsupported_feature",
        &admission_path,
        diagnostics,
        Some("reject-entire-plan"),
    );
    check_string(
        admission,
        "supported_prefix",
        &admission_path,
        diagnostics,
        Some("reject-entire-plan"),
    );
    check_string(
        admission,
        "silent_drop",
        &admission_path,
        diagnostics,
        Some("reject"),
    );

    let Some(native_edge) = required_object(object, "native_edge", path, diagnostics) else {
        return;
    };
    validate_native_edge(native_edge, &format!("{path}.native_edge"), diagnostics);

    validate_native_v2(
        object.get("native_v2"),
        &format!("{path}.native_v2"),
        diagnostics,
    );
}

fn validate_executed_provider_list(
    values: Option<&Vec<Value>>,
    path: &str,
    diagnostics: &mut Diagnostics,
) {
    let Some(values) = values else {
        return;
    };
    if values.len() != STANDALONE_SELECTOR_VALUES.len() {
        diagnostics.push(Diagnostic::new(
            "HTTP-ACCEPTANCE-SELECTION",
            path,
            "executed provider declarations must contain exactly one entry for each native selector",
        ));
    }
    let mut found = BTreeSet::new();
    for (index, value) in values.iter().enumerate() {
        let item_path = format!("{path}[{index}]");
        let Some(object) = value.as_object() else {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-SCHEMA",
                item_path,
                "executed provider declaration must be an object",
            ));
            continue;
        };
        const ALLOWED: [&str; 3] = ["implementation", "capability", "recorded"];
        reject_unknown_fields(object, &ALLOWED, &item_path, diagnostics);
        let capability = check_string(object, "capability", &item_path, diagnostics, None);
        let implementation = required_string(object, "implementation", &item_path, diagnostics);
        check_bool(object, "recorded", &item_path, diagnostics, Some(true));
        if let Some(capability) = capability {
            if !STANDALONE_SELECTOR_VALUES.contains(&capability.as_str()) {
                diagnostics.push(Diagnostic::new(
                    "HTTP-ACCEPTANCE-SELECTION",
                    format!("{item_path}.capability"),
                    format!("capability must be one of {STANDALONE_SELECTOR_VALUES:?}"),
                ));
            }
            if !found.insert(capability.clone()) {
                diagnostics.push(Diagnostic::new(
                    "HTTP-ACCEPTANCE-SELECTION",
                    format!("{item_path}.capability"),
                    "each native selector capability must be declared exactly once",
                ));
            }
            let expected = match capability.as_str() {
                STANDALONE_V1_CAPABILITY => Some(STANDALONE_V1_IMPLEMENTATION),
                STANDALONE_V2_CAPABILITY => Some(STANDALONE_V2_IMPLEMENTATION),
                _ => None,
            };
            if let (Some(actual), Some(expected)) = (implementation.as_deref(), expected)
                && actual != expected
            {
                diagnostics.push(Diagnostic::new(
                    "HTTP-ACCEPTANCE-IDENTITY",
                    format!("{item_path}.implementation"),
                    format!("capability {capability:?} must use implementation {expected:?}"),
                ));
            }
        }
    }
    for required in STANDALONE_SELECTOR_VALUES {
        if !found.contains(required) {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-SELECTION",
                path,
                format!("executed provider for {required:?} is missing"),
            ));
        }
    }
}

/// Validate the revision-9 `NativeV2` declaration.  This is deliberately a
/// policy declaration rather than an implementation probe: it records the
/// exact selector, subordinate identities, dependency/provider versions, and
/// the closed unsupported scope that admission must enforce before side
/// effects.  The `/1` edge above remains a separate contract and is not
/// upgraded merely because this declaration exists.
fn validate_native_v2(value: Option<&Value>, path: &str, diagnostics: &mut Diagnostics) {
    let Some(object) = value.and_then(Value::as_object) else {
        diagnostics.push(Diagnostic::new(
            "HTTP-ACCEPTANCE-IDENTITY",
            path,
            "NativeV2 declaration is required",
        ));
        return;
    };
    const ALLOWED: [&str; 13] = [
        "capability",
        "implementation",
        "selection",
        "protocol",
        "hostname",
        "https",
        "authority",
        "ownership",
        "unsupported",
        "identities",
        "dependency_versions",
        "provider_versions",
        "evidence",
    ];
    reject_unknown_fields(object, &ALLOWED, path, diagnostics);
    check_string(
        object,
        "capability",
        path,
        diagnostics,
        Some(STANDALONE_V2_CAPABILITY),
    );
    check_string(
        object,
        "implementation",
        path,
        diagnostics,
        Some(STANDALONE_V2_IMPLEMENTATION),
    );

    if let Some(selection) = required_object(object, "selection", path, diagnostics) {
        let selection_path = format!("{path}.selection");
        const FIELDS: [&str; 5] = ["mode", "upgrade_from_v1", "fallback", "source", "atomic"];
        reject_unknown_fields(selection, &FIELDS, &selection_path, diagnostics);
        check_string(
            selection,
            "mode",
            &selection_path,
            diagnostics,
            Some("explicit-selector-only"),
        );
        check_string(
            selection,
            "upgrade_from_v1",
            &selection_path,
            diagnostics,
            Some("forbidden"),
        );
        check_string(
            selection,
            "fallback",
            &selection_path,
            diagnostics,
            Some("forbidden"),
        );
        check_string(
            selection,
            "source",
            &selection_path,
            diagnostics,
            Some("direct-command-line-only"),
        );
        check_string(
            selection,
            "atomic",
            &selection_path,
            diagnostics,
            Some("plan-wide"),
        );
    }

    if let Some(protocol) = required_object(object, "protocol", path, diagnostics) {
        let protocol_path = format!("{path}.protocol");
        const FIELDS: [&str; 8] = [
            "route",
            "http_version",
            "alpn",
            "http2",
            "pooling",
            "decompression",
            "redirects",
            "embedded_resources",
        ];
        reject_unknown_fields(protocol, &FIELDS, &protocol_path, diagnostics);
        check_string(
            protocol,
            "route",
            &protocol_path,
            diagnostics,
            Some("direct-only"),
        );
        check_string(
            protocol,
            "http_version",
            &protocol_path,
            diagnostics,
            Some("HTTP/1.1"),
        );
        check_string_list_exact(protocol, "alpn", &protocol_path, &["http/1.1"], diagnostics);
        for field in [
            "http2",
            "pooling",
            "decompression",
            "redirects",
            "embedded_resources",
        ] {
            check_string(
                protocol,
                field,
                &protocol_path,
                diagnostics,
                Some("forbidden"),
            );
        }
    }

    if let Some(hostname) = required_object(object, "hostname", path, diagnostics) {
        let hostname_path = format!("{path}.hostname");
        const FIELDS: [&str; 14] = [
            "property",
            "provenance",
            "cardinality",
            "entry_format",
            "max_entries",
            "identity",
            "required_when",
            "system_config",
            "hosts_file",
            "search_domain",
            "ambient_cache",
            "lifetime",
            "cache_scope",
            "address_selection",
        ];
        reject_unknown_fields(hostname, &FIELDS, &hostname_path, diagnostics);
        check_string(
            hostname,
            "property",
            &hostname_path,
            diagnostics,
            Some(NATIVE_V2_DNS_PROPERTY),
        );
        check_string(
            hostname,
            "provenance",
            &hostname_path,
            diagnostics,
            Some("direct-command-line-only"),
        );
        check_string(
            hostname,
            "cardinality",
            &hostname_path,
            diagnostics,
            Some("exactly-one"),
        );
        check_string(
            hostname,
            "entry_format",
            &hostname_path,
            diagnostics,
            Some("bounded-numeric-socket-address"),
        );
        check_u64(
            hostname,
            "max_entries",
            &hostname_path,
            diagnostics,
            Some(NATIVE_V2_MAX_NAMESERVERS),
        );
        check_string(
            hostname,
            "identity",
            &hostname_path,
            diagnostics,
            Some(NATIVE_V2_DNS_IDENTITY),
        );
        check_string(
            hostname,
            "required_when",
            &hostname_path,
            diagnostics,
            Some("hostname"),
        );
        for field in [
            "system_config",
            "hosts_file",
            "search_domain",
            "ambient_cache",
        ] {
            check_string(
                hostname,
                field,
                &hostname_path,
                diagnostics,
                Some("forbidden"),
            );
        }
        check_string(
            hostname,
            "lifetime",
            &hostname_path,
            diagnostics,
            Some("one-run-owned"),
        );
        check_string(
            hostname,
            "cache_scope",
            &hostname_path,
            diagnostics,
            Some("per-virtual-user"),
        );
        if let Some(address_selection) =
            required_object(hostname, "address_selection", &hostname_path, diagnostics)
        {
            let address_selection_path = format!("{hostname_path}.address_selection");
            const FIELDS: [&str; 6] = [
                "returned_order",
                "answer_list",
                "max_addresses",
                "selected_address",
                "connect_attempts",
                "address_fallback",
            ];
            reject_unknown_fields(
                address_selection,
                &FIELDS,
                &address_selection_path,
                diagnostics,
            );
            check_string(
                address_selection,
                "returned_order",
                &address_selection_path,
                diagnostics,
                Some(NATIVE_V2_DNS_RETURNED_ORDER),
            );
            check_string(
                address_selection,
                "answer_list",
                &address_selection_path,
                diagnostics,
                Some(NATIVE_V2_DNS_ANSWER_LIST),
            );
            check_u64(
                address_selection,
                "max_addresses",
                &address_selection_path,
                diagnostics,
                Some(NATIVE_V2_MAX_NAMESERVERS),
            );
            check_string(
                address_selection,
                "selected_address",
                &address_selection_path,
                diagnostics,
                Some(NATIVE_V2_DNS_SELECTED_ADDRESS),
            );
            check_string(
                address_selection,
                "connect_attempts",
                &address_selection_path,
                diagnostics,
                Some(NATIVE_V2_DNS_CONNECT_ATTEMPTS),
            );
            check_string(
                address_selection,
                "address_fallback",
                &address_selection_path,
                diagnostics,
                Some(NATIVE_V2_DNS_ADDRESS_FALLBACK),
            );
        }
    }

    if let Some(https) = required_object(object, "https", path, diagnostics) {
        let https_path = format!("{path}.https");
        const FIELDS: [&str; 14] = [
            "property",
            "provenance",
            "cardinality",
            "path_policy",
            "format",
            "max_bytes",
            "identity",
            "required_when",
            "verification",
            "platform_roots",
            "webpki_roots",
            "trust_all",
            "client_key",
            "configuration",
        ];
        reject_unknown_fields(https, &FIELDS, &https_path, diagnostics);
        check_string(
            https,
            "property",
            &https_path,
            diagnostics,
            Some(NATIVE_V2_TLS_PROPERTY),
        );
        check_string(
            https,
            "provenance",
            &https_path,
            diagnostics,
            Some("direct-command-line-only"),
        );
        check_string(
            https,
            "cardinality",
            &https_path,
            diagnostics,
            Some("exactly-one"),
        );
        check_string(
            https,
            "path_policy",
            &https_path,
            diagnostics,
            Some("root-contained"),
        );
        check_string(
            https,
            "format",
            &https_path,
            diagnostics,
            Some("bounded-PEM-certificates-only"),
        );
        check_u64(
            https,
            "max_bytes",
            &https_path,
            diagnostics,
            Some(NATIVE_V2_MAX_CA_FILE_BYTES),
        );
        check_string(
            https,
            "identity",
            &https_path,
            diagnostics,
            Some(NATIVE_V2_TLS_IDENTITY),
        );
        check_string(
            https,
            "required_when",
            &https_path,
            diagnostics,
            Some("https"),
        );
        check_string(
            https,
            "verification",
            &https_path,
            diagnostics,
            Some("explicit-roots-only"),
        );
        for field in ["platform_roots", "webpki_roots", "trust_all", "client_key"] {
            check_string(https, field, &https_path, diagnostics, Some("forbidden"));
        }
        check_string(
            https,
            "configuration",
            &https_path,
            diagnostics,
            Some("immutable-run-owned"),
        );
    }

    if let Some(authority) = required_object(object, "authority", path, diagnostics) {
        let authority_path = format!("{path}.authority");
        const FIELDS: [&str; 6] = [
            "url_authority",
            "http_host",
            "tls_server_name",
            "numeric_peer",
            "rewrite",
            "ip_literal_sni",
        ];
        reject_unknown_fields(authority, &FIELDS, &authority_path, diagnostics);
        check_string(
            authority,
            "url_authority",
            &authority_path,
            diagnostics,
            Some("preserve-original"),
        );
        check_string(
            authority,
            "http_host",
            &authority_path,
            diagnostics,
            Some("original-url-host"),
        );
        check_string(
            authority,
            "tls_server_name",
            &authority_path,
            diagnostics,
            Some("original-url-host"),
        );
        check_string(
            authority,
            "numeric_peer",
            &authority_path,
            diagnostics,
            Some("resolved-address-only"),
        );
        check_string(
            authority,
            "rewrite",
            &authority_path,
            diagnostics,
            Some("forbidden"),
        );
        check_string(
            authority,
            "ip_literal_sni",
            &authority_path,
            diagnostics,
            Some("forbidden"),
        );
    }
    if let Some(ownership) = required_object(object, "ownership", path, diagnostics) {
        let ownership_path = format!("{path}.ownership");
        const FIELDS: [&str; 3] = ["configuration", "resolver", "tls"];
        reject_unknown_fields(ownership, &FIELDS, &ownership_path, diagnostics);
        check_string(
            ownership,
            "configuration",
            &ownership_path,
            diagnostics,
            Some("immutable-run-owned"),
        );
        check_string(
            ownership,
            "resolver",
            &ownership_path,
            diagnostics,
            Some("one-run-owned"),
        );
        check_string(
            ownership,
            "tls",
            &ownership_path,
            diagnostics,
            Some("immutable-run-owned"),
        );
    }

    if let Some(unsupported) = required_object(object, "unsupported", path, diagnostics) {
        let unsupported_path = format!("{path}.unsupported");
        const FIELDS: [&str; 4] = ["scope", "features", "partial", "silent_drop"];
        reject_unknown_fields(unsupported, &FIELDS, &unsupported_path, diagnostics);
        check_string(
            unsupported,
            "scope",
            &unsupported_path,
            diagnostics,
            Some("atomic-plan"),
        );
        check_string_list_exact(
            unsupported,
            "features",
            &unsupported_path,
            &NATIVE_V2_UNSUPPORTED,
            diagnostics,
        );
        check_string(
            unsupported,
            "partial",
            &unsupported_path,
            diagnostics,
            Some("reject-entire-plan"),
        );
        check_string(
            unsupported,
            "silent_drop",
            &unsupported_path,
            diagnostics,
            Some("forbidden"),
        );
    }

    check_string_list_exact(
        object,
        "identities",
        path,
        &[
            STANDALONE_V2_CAPABILITY,
            NATIVE_V2_DNS_IDENTITY,
            NATIVE_V2_TLS_IDENTITY,
        ],
        diagnostics,
    );
    validate_exact_named_versions(
        object.get("dependency_versions"),
        &format!("{path}.dependency_versions"),
        &NATIVE_V2_DEPENDENCIES,
        "dependency",
        diagnostics,
    );
    validate_exact_named_versions(
        object.get("provider_versions"),
        &format!("{path}.provider_versions"),
        &NATIVE_V2_PROVIDERS,
        "provider",
        diagnostics,
    );

    if let Some(evidence) = required_object(object, "evidence", path, diagnostics) {
        validate_planning_evidence(evidence, &format!("{path}.evidence"), diagnostics);
    }
}

fn validate_exact_named_versions(
    value: Option<&Value>,
    path: &str,
    expected: &[(&str, &str)],
    kind: &str,
    diagnostics: &mut Diagnostics,
) {
    let Some(values) = value.and_then(Value::as_array) else {
        diagnostics.push(Diagnostic::new(
            "HTTP-ACCEPTANCE-IDENTITY",
            path,
            format!("{kind} versions must be a declared array"),
        ));
        return;
    };
    if values.len() != expected.len() {
        diagnostics.push(Diagnostic::new(
            "HTTP-ACCEPTANCE-IDENTITY",
            path,
            format!("{kind} versions must record every exact subordinate version"),
        ));
    }
    let mut found = BTreeSet::new();
    for (index, value) in values.iter().enumerate() {
        let item_path = format!("{path}[{index}]");
        let Some(object) = value.as_object() else {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-IDENTITY",
                item_path,
                format!("{kind} version entry must be an object"),
            ));
            continue;
        };
        const ALLOWED: [&str; 3] = ["name", "version", "source"];
        reject_unknown_fields(object, &ALLOWED, &item_path, diagnostics);
        let name = required_string(object, "name", &item_path, diagnostics);
        let version = required_string(object, "version", &item_path, diagnostics);
        check_string(object, "source", &item_path, diagnostics, Some("crates.io"));
        let Some(name) = name else { continue };
        let Some(version) = version else { continue };
        if let Some((_, expected_version)) = expected.iter().find(|(item, _)| *item == name) {
            found.insert(name.clone());
            if version != *expected_version {
                diagnostics.push(Diagnostic::new(
                    "HTTP-ACCEPTANCE-IDENTITY",
                    format!("{item_path}.version"),
                    format!("{name} must record exact version {expected_version:?}"),
                ));
            }
        } else {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-IDENTITY",
                format!("{item_path}.name"),
                format!("unknown {kind} identity {name:?}"),
            ));
        }
    }
    for (name, _) in expected {
        if !found.contains(*name) {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-IDENTITY",
                path,
                format!("exact {kind} identity {name:?} is missing"),
            ));
        }
    }
}

/// Validate the revision-9 boundary around the synchronous standard-library
/// transport.  `NativeV1` owns only the HTTP attempt itself; the application
/// must own the worker lifecycle and every bounded admission/resource policy.
/// Keeping this contract in the provider-substitution descriptor makes it
/// impossible for a static declaration to describe an inline socket path as
/// the standalone implementation.  The connect edge is deliberately closed:
/// one Mio connect attempt and one readiness poll, a shared `Arc<Waker>` for
/// cancellation, and standard-library I/O after readiness.  A declaration
/// that describes timer-sliced retries or an async provider is not revision
/// 9's preserved `/1` contract.
fn validate_native_edge(object: &Map<String, Value>, path: &str, diagnostics: &mut Diagnostics) {
    const ALLOWED: [&str; 6] = [
        "worker_pool",
        "runtime_poll",
        "dns",
        "framing",
        "connect_edge",
        "evidence",
    ];
    reject_unknown_fields(object, &ALLOWED, path, diagnostics);

    if let Some(worker_pool) = required_object(object, "worker_pool", path, diagnostics) {
        validate_worker_pool(worker_pool, &format!("{path}.worker_pool"), diagnostics);
    }
    if let Some(runtime_poll) = required_object(object, "runtime_poll", path, diagnostics) {
        validate_runtime_poll(runtime_poll, &format!("{path}.runtime_poll"), diagnostics);
    }
    if let Some(dns) = required_object(object, "dns", path, diagnostics) {
        validate_bootstrap_dns(dns, &format!("{path}.dns"), diagnostics);
    }
    if let Some(framing) = required_object(object, "framing", path, diagnostics) {
        validate_bootstrap_framing(framing, &format!("{path}.framing"), diagnostics);
    }
    if let Some(connect_edge) = required_object(object, "connect_edge", path, diagnostics) {
        validate_native_connect_edge(connect_edge, &format!("{path}.connect_edge"), diagnostics);
    }
    if let Some(evidence) = required_object(object, "evidence", path, diagnostics) {
        validate_planning_evidence(evidence, &format!("{path}.evidence"), diagnostics);
    }
}

fn validate_native_connect_edge(
    object: &Map<String, Value>,
    path: &str,
    diagnostics: &mut Diagnostics,
) {
    const ALLOWED: [&str; 16] = [
        "socket",
        "connect_call",
        "connect_attempts",
        "poll_instances",
        "poll_registration",
        "waker",
        "cancellation",
        "readiness",
        "cancelled_stream",
        "post_connect_io",
        "deadline",
        "connect_timeout_attempts",
        "timer_slicing",
        "async_runtime",
        "async_provider",
        "mio_dependency",
    ];
    reject_unknown_fields(object, &ALLOWED, path, diagnostics);
    for (field, expected) in [
        ("socket", "mio::net::TcpStream"),
        ("connect_call", "mio::net::TcpStream::connect"),
        ("connect_attempts", "exactly-one"),
        ("poll_instances", "exactly-one"),
        ("poll_registration", "still-owned-stream"),
        ("waker", "Arc<Waker>"),
        ("cancellation", "shared-waker"),
        ("readiness", "writable-take-error"),
        ("cancelled_stream", "drop-exact-stream"),
        ("post_connect_io", "std::net::TcpStream"),
        ("deadline", "one-absolute-operation-deadline"),
        ("connect_timeout_attempts", "forbidden"),
        ("timer_slicing", "forbidden"),
        ("async_runtime", "forbidden"),
        ("async_provider", "forbidden"),
    ] {
        check_string(object, field, path, diagnostics, Some(expected));
    }

    let Some(mio_dependency) = required_object(object, "mio_dependency", path, diagnostics) else {
        return;
    };
    validate_mio_dependency(
        mio_dependency,
        &format!("{path}.mio_dependency"),
        diagnostics,
    );
}

fn validate_mio_dependency(object: &Map<String, Value>, path: &str, diagnostics: &mut Diagnostics) {
    const ALLOWED: [&str; 7] = [
        "name",
        "version",
        "source",
        "default_features",
        "features",
        "feature_policy",
        "runtime_role",
    ];
    reject_unknown_fields(object, &ALLOWED, path, diagnostics);
    check_string(object, "name", path, diagnostics, Some("mio"));
    let Some(version) = check_string(object, "version", path, diagnostics, None) else {
        return;
    };
    if !is_exact_semver_requirement(&version) {
        diagnostics.push(Diagnostic::new(
            "HTTP-ACCEPTANCE-IDENTITY",
            format!("{path}.version"),
            "Mio must use an exact (=major.minor.patch) version requirement",
        ));
    }
    check_string(object, "source", path, diagnostics, Some("crates.io"));
    check_bool(object, "default_features", path, diagnostics, Some(false));
    check_string_list_exact(object, "features", path, &["net", "os-poll"], diagnostics);
    check_string(
        object,
        "feature_policy",
        path,
        diagnostics,
        Some("exact-only"),
    );
    check_string(
        object,
        "runtime_role",
        path,
        diagnostics,
        Some("connect-readiness-only"),
    );
}

fn is_exact_semver_requirement(value: &str) -> bool {
    let Some(version) = value.strip_prefix('=') else {
        return false;
    };
    let mut parts = version.split('.');
    let Some(major) = parts.next() else {
        return false;
    };
    let Some(minor) = parts.next() else {
        return false;
    };
    let Some(patch) = parts.next() else {
        return false;
    };
    parts.next().is_none()
        && !major.is_empty()
        && !minor.is_empty()
        && !patch.is_empty()
        && major.bytes().all(|byte| byte.is_ascii_digit())
        && minor.bytes().all(|byte| byte.is_ascii_digit())
        && patch.bytes().all(|byte| byte.is_ascii_digit())
}

fn validate_worker_pool(object: &Map<String, Value>, path: &str, diagnostics: &mut Diagnostics) {
    const ALLOWED: [&str; 9] = [
        "owner",
        "kind",
        "workers",
        "queue",
        "retained_bytes",
        "dispatch",
        "cancellation",
        "finalization",
        "failures",
    ];
    reject_unknown_fields(object, &ALLOWED, path, diagnostics);
    check_string(
        object,
        "owner",
        path,
        diagnostics,
        Some("application-owned"),
    );
    check_string(object, "kind", path, diagnostics, Some("bounded-blocking"));

    if let Some(workers) = required_object(object, "workers", path, diagnostics) {
        let workers_path = format!("{path}.workers");
        const WORKER_FIELDS: [&str; 3] = ["count", "policy", "per_virtual_user"];
        reject_unknown_fields(workers, &WORKER_FIELDS, &workers_path, diagnostics);
        check_finite_positive_u64(workers, "count", &workers_path, diagnostics);
        check_string(
            workers,
            "policy",
            &workers_path,
            diagnostics,
            Some("finite-fixed"),
        );
        check_string(
            workers,
            "per_virtual_user",
            &workers_path,
            diagnostics,
            Some("forbidden"),
        );
    }

    if let Some(queue) = required_object(object, "queue", path, diagnostics) {
        let queue_path = format!("{path}.queue");
        const QUEUE_FIELDS: [&str; 3] = ["jobs", "capacity", "full_failure"];
        reject_unknown_fields(queue, &QUEUE_FIELDS, &queue_path, diagnostics);
        check_string(queue, "jobs", &queue_path, diagnostics, Some("bounded"));
        check_finite_positive_u64(queue, "capacity", &queue_path, diagnostics);
        check_string(
            queue,
            "full_failure",
            &queue_path,
            diagnostics,
            Some("typed"),
        );
    }

    if let Some(retained_bytes) = required_object(object, "retained_bytes", path, diagnostics) {
        let retained_path = format!("{path}.retained_bytes");
        const RETAINED_FIELDS: [&str; 3] = ["scope", "maximum", "full_failure"];
        reject_unknown_fields(
            retained_bytes,
            &RETAINED_FIELDS,
            &retained_path,
            diagnostics,
        );
        check_string(
            retained_bytes,
            "scope",
            &retained_path,
            diagnostics,
            Some("aggregate"),
        );
        check_finite_positive_u64(retained_bytes, "maximum", &retained_path, diagnostics);
        check_string(
            retained_bytes,
            "full_failure",
            &retained_path,
            diagnostics,
            Some("typed"),
        );
    }

    if let Some(dispatch) = required_object(object, "dispatch", path, diagnostics) {
        let dispatch_path = format!("{path}.dispatch");
        const DISPATCH_FIELDS: [&str; 2] = ["inline", "one_thread_per_virtual_user"];
        reject_unknown_fields(dispatch, &DISPATCH_FIELDS, &dispatch_path, diagnostics);
        check_string(
            dispatch,
            "inline",
            &dispatch_path,
            diagnostics,
            Some("forbidden"),
        );
        check_string(
            dispatch,
            "one_thread_per_virtual_user",
            &dispatch_path,
            diagnostics,
            Some("forbidden"),
        );
    }

    if let Some(cancellation) = required_object(object, "cancellation", path, diagnostics) {
        let cancellation_path = format!("{path}.cancellation");
        const CANCELLATION_FIELDS: [&str; 2] = ["operation", "drop"];
        reject_unknown_fields(
            cancellation,
            &CANCELLATION_FIELDS,
            &cancellation_path,
            diagnostics,
        );
        check_string(
            cancellation,
            "operation",
            &cancellation_path,
            diagnostics,
            Some("exact-operation"),
        );
        check_string(
            cancellation,
            "drop",
            &cancellation_path,
            diagnostics,
            Some("propagate-cancellation"),
        );
    }

    if let Some(finalization) = required_object(object, "finalization", path, diagnostics) {
        let finalization_path = format!("{path}.finalization");
        const FINALIZATION_FIELDS: [&str; 3] = ["join", "shutdown", "completion"];
        reject_unknown_fields(
            finalization,
            &FINALIZATION_FIELDS,
            &finalization_path,
            diagnostics,
        );
        check_string(
            finalization,
            "join",
            &finalization_path,
            diagnostics,
            Some("exact-owned"),
        );
        check_string(
            finalization,
            "shutdown",
            &finalization_path,
            diagnostics,
            Some("bounded"),
        );
        check_string(
            finalization,
            "completion",
            &finalization_path,
            diagnostics,
            Some("exact-once"),
        );
    }

    if let Some(failures) = required_object(object, "failures", path, diagnostics) {
        let failures_path = format!("{path}.failures");
        const FAILURE_FIELDS: [&str; 3] = ["full", "stopped", "stable_code"];
        reject_unknown_fields(failures, &FAILURE_FIELDS, &failures_path, diagnostics);
        check_string(failures, "full", &failures_path, diagnostics, Some("typed"));
        check_string(
            failures,
            "stopped",
            &failures_path,
            diagnostics,
            Some("typed"),
        );
        check_string(
            failures,
            "stable_code",
            &failures_path,
            diagnostics,
            Some("http.pool"),
        );
    }
}

fn validate_runtime_poll(object: &Map<String, Value>, path: &str, diagnostics: &mut Diagnostics) {
    const ALLOWED: [&str; 3] = ["dns", "socket", "response_parsing"];
    reject_unknown_fields(object, &ALLOWED, path, diagnostics);
    for field in ALLOWED {
        check_string(
            object,
            field,
            path,
            diagnostics,
            Some("outside-runtime-poll"),
        );
    }
}

fn validate_bootstrap_dns(object: &Map<String, Value>, path: &str, diagnostics: &mut Diagnostics) {
    const ALLOWED: [&str; 3] = ["bootstrap", "ambient", "resolver"];
    reject_unknown_fields(object, &ALLOWED, path, diagnostics);
    check_string(
        object,
        "bootstrap",
        path,
        diagnostics,
        Some("numeric-address-only"),
    );
    check_string(object, "ambient", path, diagnostics, Some("forbidden"));

    let Some(resolver) = required_object(object, "resolver", path, diagnostics) else {
        return;
    };
    let resolver_path = format!("{path}.resolver");
    const RESOLVER_FIELDS: [&str; 4] = ["mode", "identity", "bounded", "max_addresses"];
    reject_unknown_fields(resolver, &RESOLVER_FIELDS, &resolver_path, diagnostics);
    check_string(
        resolver,
        "mode",
        &resolver_path,
        diagnostics,
        Some("separate-capability-only"),
    );
    if let Some(identity) = required_string(resolver, "identity", &resolver_path, diagnostics) {
        validate_ascii_identifier(&identity, &format!("{resolver_path}.identity"), diagnostics);
    }
    check_bool(resolver, "bounded", &resolver_path, diagnostics, Some(true));
    check_finite_positive_u64(resolver, "max_addresses", &resolver_path, diagnostics);
}

fn validate_bootstrap_framing(
    object: &Map<String, Value>,
    path: &str,
    diagnostics: &mut Diagnostics,
) {
    const ALLOWED: [&str; 8] = [
        "completion",
        "content_length",
        "chunked",
        "no_body",
        "connection_close",
        "eof",
        "forced_connection_close",
        "forced_eof",
    ];
    reject_unknown_fields(object, &ALLOWED, path, diagnostics);
    check_string(
        object,
        "completion",
        path,
        diagnostics,
        Some("message-boundary"),
    );
    check_string(
        object,
        "content_length",
        path,
        diagnostics,
        Some("length-delimited"),
    );
    check_string(
        object,
        "chunked",
        path,
        diagnostics,
        Some("terminal-zero-chunk"),
    );
    check_string(
        object,
        "no_body",
        path,
        diagnostics,
        Some("status-or-method-delimited"),
    );
    check_string(
        object,
        "connection_close",
        path,
        diagnostics,
        Some("not-required"),
    );
    check_string(object, "eof", path, diagnostics, Some("not-required"));
    check_bool(
        object,
        "forced_connection_close",
        path,
        diagnostics,
        Some(false),
    );
    check_bool(object, "forced_eof", path, diagnostics, Some(false));
}

fn validate_planning_evidence(
    object: &Map<String, Value>,
    path: &str,
    diagnostics: &mut Diagnostics,
) {
    const ALLOWED: [&str; 4] = ["status", "conformance_evidence", "feature_ids", "promotion"];
    reject_unknown_fields(object, &ALLOWED, path, diagnostics);
    check_string(object, "status", path, diagnostics, Some("planning-only"));
    check_bool(
        object,
        "conformance_evidence",
        path,
        diagnostics,
        Some(false),
    );
    // The provider substitution descriptor is useful admission metadata, but
    // it cannot be counted as an ELEM-001 observation or as profile evidence.
    check_string_list_exact(object, "feature_ids", path, &[], diagnostics);
    check_string(object, "promotion", path, diagnostics, Some("forbidden"));
}

fn check_finite_positive_u64(
    object: &Map<String, Value>,
    field: &str,
    path: &str,
    diagnostics: &mut Diagnostics,
) -> Option<u64> {
    let value = check_u64(object, field, path, diagnostics, None)?;
    if value == 0 || value == u64::MAX {
        diagnostics.push(Diagnostic::new(
            "HTTP-ACCEPTANCE-BOUNDS",
            format!("{path}.{field}"),
            "bounded resource must be a finite positive integer (u64::MAX is reserved as unbounded)",
        ));
    }
    Some(value)
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
            validate_ascii_identifier(id, &item_path, diagnostics);
            if !REQUIRED_SCHEMA_IDS.contains(&id) {
                diagnostics.push(Diagnostic::new(
                    "HTTP-ACCEPTANCE-IDENTITY",
                    &item_path,
                    format!("unsupported top-level schema identity {id:?}"),
                ));
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
            if object.get("id").and_then(Value::as_str).is_some()
                && object.get("schema_id").and_then(Value::as_str).is_some()
                && object.get("id") != object.get("schema_id")
            {
                diagnostics.push(Diagnostic::new(
                    "HTTP-ACCEPTANCE-IDENTITY",
                    format!("{item_path}.schema_id"),
                    "id and schema_id must identify the same schema",
                ));
            }
            if !REQUIRED_SCHEMA_IDS.contains(&id) {
                diagnostics.push(Diagnostic::new(
                    "HTTP-ACCEPTANCE-IDENTITY",
                    format!("{item_path}.id"),
                    format!("unsupported top-level schema identity {id:?}"),
                ));
            }
            validate_ascii_identifier(id, &format!("{item_path}.id"), diagnostics);
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
    const ALLOWED: [&str; 7] = [
        "schema_id",
        "schema_version",
        "categories",
        "order",
        "hard_maxima",
        "active",
        "digest",
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
    let expected_order = REQUIRED_HARD_MAXIMA
        .iter()
        .map(|(name, _)| *name)
        .collect::<Vec<_>>();
    check_string_list_exact(object, "order", path, &expected_order, diagnostics);
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
    let Some(digest) = check_string(object, "digest", path, diagnostics, None) else {
        return;
    };
    if !is_sha256(&digest) {
        diagnostics.push(Diagnostic::new(
            "HTTP-ACCEPTANCE-IDENTITY",
            format!("{path}.digest"),
            "parser-limit digest must be a nonzero lowercase SHA-256 value",
        ));
    } else {
        let active_values = REQUIRED_HARD_MAXIMA
            .iter()
            .filter_map(|(name, _)| active.get(*name).and_then(Value::as_u64))
            .collect::<Vec<_>>();
        if active_values.len() == REQUIRED_HARD_MAXIMA.len() {
            let expected = parser_limits_digest(&active_values);
            if digest != expected {
                diagnostics.push(Diagnostic::new(
                    "HTTP-ACCEPTANCE-IDENTITY",
                    format!("{path}.digest"),
                    "parser-limit digest does not match the ordered active vector",
                ));
            }
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
    const ALLOWED: [&str; 11] = [
        "schema_id",
        "schema_version",
        "source_node",
        "plan_path",
        "sampler_identity",
        "capability_identity",
        "attempt_index",
        "embedded_resource_index",
        "phase_enum",
        "stable_error_codes",
        "diagnostics",
    ];
    const PHASES: [&str; 15] = [
        "queue",
        "dns",
        "pool",
        "proxy-connect",
        "connect",
        "proxy-tls",
        "origin-tls",
        "request-headers",
        "request-body",
        "response-headers",
        "response-body",
        "decompression",
        "state-commit",
        "result-routing",
        "cleanup",
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
        "attempt_index",
        path,
        diagnostics,
        Some("NonZeroU32"),
    );
    check_string(
        object,
        "embedded_resource_index",
        path,
        diagnostics,
        Some("Absent|Present(u32)"),
    );
    check_string_list_exact(object, "phase_enum", path, &PHASES, diagnostics);
    check_string_list_exact(
        object,
        "stable_error_codes",
        path,
        REQUIRED_STABLE_ERROR_CODES,
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
    parser_limits_digest: Option<&str>,
    diagnostics: &mut Diagnostics,
) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    const REQUIRED: [&str; 4] = [
        "http.native/1",
        "http.native/2",
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
        const ALLOWED: [&str; 12] = [
            "id",
            "status",
            "implementation",
            "parser_limits_digest",
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
        validate_ascii_identifier(&id, &format!("{path}.id"), diagnostics);
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
        let implementation = required_string(object, "implementation", &path, diagnostics);
        let declared_parser_digest =
            required_string(object, "parser_limits_digest", &path, diagnostics);
        if let (Some(actual), Some(expected)) =
            (declared_parser_digest.as_deref(), parser_limits_digest)
            && actual != expected
        {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-IDENTITY",
                format!("{path}.parser_limits_digest"),
                "capability parser-limit digest must match parser_limits.digest",
            ));
        }
        if let Some(digest) = declared_parser_digest.as_deref()
            && !is_sha256(digest)
        {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-IDENTITY",
                format!("{path}.parser_limits_digest"),
                "capability parser-limit digest must be a nonzero lowercase SHA-256 value",
            ));
        }
        let expected_implementation =
            IMPLEMENTATION_IDENTITIES
                .iter()
                .find_map(|(capability, implementation)| {
                    (capability == &id.as_str()).then_some(*implementation)
                });
        if let (Some(actual), Some(expected)) = (implementation, expected_implementation)
            && actual != expected
        {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-IDENTITY",
                format!("{path}.implementation"),
                format!("capability {id:?} must use implementation {expected:?}"),
            ));
        }
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
    let mut feature_ids = BTreeSet::new();
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
        if id.len() > 128 || id.bytes().any(|byte| byte.is_ascii_control()) {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-CASE",
                format!("{item_path}.id"),
                "case IDs must be at most 128 bytes and contain no control characters",
            ));
        }
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
        validate_feature_ids(object, &item_path, &mut feature_ids, diagnostics);
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
    for required in ALLOWED_FEATURE_IDS {
        if !feature_ids.contains(required) {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-CASE",
                format!("{path}.feature_ids"),
                format!("required HTTP feature {required:?} is not covered by any case"),
            ));
        }
    }
}

fn validate_feature_ids(
    object: &Map<String, Value>,
    path: &str,
    found: &mut BTreeSet<String>,
    diagnostics: &mut Diagnostics,
) {
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
        } else {
            // Repeating a feature across cases is useful for fixture-level
            // detail. The set is only used for aggregate coverage; each case
            // still preserves its declared ordered list.
            found.insert(value.to_owned());
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
    if let Some(schema_id) = required_string(object, "schema_id", path, diagnostics) {
        validate_ascii_identifier(&schema_id, &format!("{path}.schema_id"), diagnostics);
    }
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
    for field in ["name", "source", "kind", "role"] {
        if let Some(value) = object.get(field)
            && value
                .as_str()
                .is_none_or(|value| value.trim().is_empty() || value.len() > 4096)
        {
            diagnostics.push(Diagnostic::new(
                "HTTP-ACCEPTANCE-IDENTITY",
                format!("{path}.{field}"),
                "identity metadata must be a non-empty string of at most 4096 bytes when present",
            ));
        }
    }
}

fn validate_ascii_identifier(value: &str, path: &str, diagnostics: &mut Diagnostics) {
    if value.len() > 64 || !value.is_ascii() {
        diagnostics.push(Diagnostic::new(
            "HTTP-ACCEPTANCE-IDENTITY",
            path,
            "schema identity must be ASCII and at most 64 bytes",
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
    if values.is_empty() && capability_id == "http.native/2" {
        diagnostics.push(Diagnostic::new(
            "HTTP-ACCEPTANCE-IDENTITY",
            path,
            "NativeV2 requires exact subordinate provider identities",
        ));
    } else if values.is_empty() && capability_id != "http.native/1" {
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

fn reject_secret_fields(value: &Value, path: &str, diagnostics: &mut Diagnostics) {
    match value {
        Value::Object(values) => {
            for (key, value) in values {
                if FORBIDDEN_SECRET_FIELDS
                    .iter()
                    .any(|field| field.eq_ignore_ascii_case(key))
                {
                    diagnostics.push(Diagnostic::new(
                        "HTTP-ACCEPTANCE-SECURITY",
                        format!("{path}.{key}"),
                        "secret-bearing fields are forbidden; use a protected capability reference",
                    ));
                }
                reject_secret_fields(value, &format!("{path}.{key}"), diagnostics);
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                reject_secret_fields(value, &format!("{path}[{index}]"), diagnostics);
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

fn parser_limits_digest(values: &[u64]) -> String {
    let mut preimage = Vec::with_capacity("http.parser-limits/1".len() + 1 + values.len() * 8);
    preimage.extend_from_slice(b"http.parser-limits/1");
    preimage.push(0);
    for value in values {
        preimage.extend_from_slice(&value.to_be_bytes());
    }
    hex_digest(&preimage)
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
        object.insert(
            "decision_revision".to_owned(),
            Value::from(DECISION_REVISION),
        );
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
            "standalone_provider_substitution".to_owned(),
            standalone_provider_substitution(),
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

    fn standalone_provider_substitution() -> Value {
        serde_json::json!({
            "scope": "plan-wide",
            "selector": {
                "property": STANDALONE_SELECTOR_PROPERTY,
                "values": STANDALONE_SELECTOR_VALUES,
                "operations": STANDALONE_SELECTOR_OPERATIONS,
                "provenance": "direct-command-line-only",
                "cardinality": "exactly-one",
                "rejected_sources": [
                    "default", "user", "system", "additional-property", "environment", "jmeter-home"
                ],
                "invalid_inputs": ["empty", "removed", "repeated", "unknown", "non-command-line"]
            },
            "source_provider": {
                "preserved": true,
                "recorded": true,
                "lossless": true,
                "identities": SOURCE_PROVIDER_IDENTITIES
            },
            "executed_providers": [
                {
                    "implementation": STANDALONE_V1_IMPLEMENTATION,
                    "capability": STANDALONE_V1_CAPABILITY,
                    "recorded": true
                },
                {
                    "implementation": STANDALONE_V2_IMPLEMENTATION,
                    "capability": STANDALONE_V2_CAPABILITY,
                    "recorded": true
                }
            ],
            "without_selector": "compatibility-pack-required",
            "admission": {
                "mode": "atomic",
                "resolve_before": ["dns", "socket", "logger", "output", "report", "runtime-setup"],
                "unsupported_feature": "reject-entire-plan",
                "supported_prefix": "reject-entire-plan",
                "silent_drop": "reject"
            },
            "native_edge": native_edge(),
            "native_v2": native_v2()
        })
    }

    fn native_v2() -> Value {
        let dependency_versions = NATIVE_V2_DEPENDENCIES
            .iter()
            .map(|(name, version)| {
                serde_json::json!({
                    "name": name,
                    "version": version,
                    "source": "crates.io"
                })
            })
            .collect::<Vec<_>>();
        let provider_versions = NATIVE_V2_PROVIDERS
            .iter()
            .map(|(name, version)| {
                serde_json::json!({
                    "name": name,
                    "version": version,
                    "source": "crates.io"
                })
            })
            .collect::<Vec<_>>();
        serde_json::json!({
            "capability": STANDALONE_V2_CAPABILITY,
            "implementation": STANDALONE_V2_IMPLEMENTATION,
            "selection": {
                "mode": "explicit-selector-only",
                "upgrade_from_v1": "forbidden",
                "fallback": "forbidden",
                "source": "direct-command-line-only",
                "atomic": "plan-wide"
            },
            "protocol": {
                "route": "direct-only",
                "http_version": "HTTP/1.1",
                "alpn": ["http/1.1"],
                "http2": "forbidden",
                "pooling": "forbidden",
                "decompression": "forbidden",
                "redirects": "forbidden",
                "embedded_resources": "forbidden"
            },
            "hostname": {
                "property": NATIVE_V2_DNS_PROPERTY,
                "provenance": "direct-command-line-only",
                "cardinality": "exactly-one",
                "entry_format": "bounded-numeric-socket-address",
                "max_entries": NATIVE_V2_MAX_NAMESERVERS,
                "identity": NATIVE_V2_DNS_IDENTITY,
                "required_when": "hostname",
                "system_config": "forbidden",
                "hosts_file": "forbidden",
                "search_domain": "forbidden",
                "ambient_cache": "forbidden",
                "lifetime": "one-run-owned",
                "cache_scope": "per-virtual-user",
                "address_selection": {
                    "returned_order": NATIVE_V2_DNS_RETURNED_ORDER,
                    "answer_list": NATIVE_V2_DNS_ANSWER_LIST,
                    "max_addresses": NATIVE_V2_MAX_NAMESERVERS,
                    "selected_address": NATIVE_V2_DNS_SELECTED_ADDRESS,
                    "connect_attempts": NATIVE_V2_DNS_CONNECT_ATTEMPTS,
                    "address_fallback": NATIVE_V2_DNS_ADDRESS_FALLBACK
                }
            },
            "https": {
                "property": NATIVE_V2_TLS_PROPERTY,
                "provenance": "direct-command-line-only",
                "cardinality": "exactly-one",
                "path_policy": "root-contained",
                "format": "bounded-PEM-certificates-only",
                "max_bytes": NATIVE_V2_MAX_CA_FILE_BYTES,
                "identity": NATIVE_V2_TLS_IDENTITY,
                "required_when": "https",
                "verification": "explicit-roots-only",
                "platform_roots": "forbidden",
                "webpki_roots": "forbidden",
                "trust_all": "forbidden",
                "client_key": "forbidden",
                "configuration": "immutable-run-owned"
            },
            "authority": {
                "url_authority": "preserve-original",
                "http_host": "original-url-host",
                "tls_server_name": "original-url-host",
                "numeric_peer": "resolved-address-only",
                "rewrite": "forbidden",
                "ip_literal_sni": "forbidden"
            },
            "ownership": {
                "configuration": "immutable-run-owned",
                "resolver": "one-run-owned",
                "tls": "immutable-run-owned"
            },
            "unsupported": {
                "scope": "atomic-plan",
                "features": NATIVE_V2_UNSUPPORTED,
                "partial": "reject-entire-plan",
                "silent_drop": "forbidden"
            },
            "identities": [
                STANDALONE_V2_CAPABILITY,
                NATIVE_V2_DNS_IDENTITY,
                NATIVE_V2_TLS_IDENTITY
            ],
            "dependency_versions": dependency_versions,
            "provider_versions": provider_versions,
            "evidence": {
                "status": "planning-only",
                "conformance_evidence": false,
                "feature_ids": [],
                "promotion": "forbidden"
            }
        })
    }

    fn native_edge() -> Value {
        serde_json::json!({
            "worker_pool": {
                "owner": "application-owned",
                "kind": "bounded-blocking",
                "workers": {
                    "count": 4,
                    "policy": "finite-fixed",
                    "per_virtual_user": "forbidden"
                },
                "queue": {
                    "jobs": "bounded",
                    "capacity": 64,
                    "full_failure": "typed"
                },
                "retained_bytes": {
                    "scope": "aggregate",
                    "maximum": 64 * 1024 * 1024u64,
                    "full_failure": "typed"
                },
                "dispatch": {
                    "inline": "forbidden",
                    "one_thread_per_virtual_user": "forbidden"
                },
                "cancellation": {
                    "operation": "exact-operation",
                    "drop": "propagate-cancellation"
                },
                "finalization": {
                    "join": "exact-owned",
                    "shutdown": "bounded",
                    "completion": "exact-once"
                },
                "failures": {
                    "full": "typed",
                    "stopped": "typed",
                    "stable_code": "http.pool"
                }
            },
            "runtime_poll": {
                "dns": "outside-runtime-poll",
                "socket": "outside-runtime-poll",
                "response_parsing": "outside-runtime-poll"
            },
            "dns": {
                "bootstrap": "numeric-address-only",
                "ambient": "forbidden",
                "resolver": {
                    "mode": "separate-capability-only",
                    "identity": "dns.resolver/1",
                    "bounded": true,
                    "max_addresses": 32
                }
            },
            "framing": {
                "completion": "message-boundary",
                "content_length": "length-delimited",
                "chunked": "terminal-zero-chunk",
                "no_body": "status-or-method-delimited",
                "connection_close": "not-required",
                "eof": "not-required",
                "forced_connection_close": false,
                "forced_eof": false
            },
            "connect_edge": {
                "socket": "mio::net::TcpStream",
                "connect_call": "mio::net::TcpStream::connect",
                "connect_attempts": "exactly-one",
                "poll_instances": "exactly-one",
                "poll_registration": "still-owned-stream",
                "waker": "Arc<Waker>",
                "cancellation": "shared-waker",
                "readiness": "writable-take-error",
                "cancelled_stream": "drop-exact-stream",
                "post_connect_io": "std::net::TcpStream",
                "deadline": "one-absolute-operation-deadline",
                "connect_timeout_attempts": "forbidden",
                "timer_slicing": "forbidden",
                "async_runtime": "forbidden",
                "async_provider": "forbidden",
                "mio_dependency": {
                    "name": "mio",
                    "version": "=1.2.2",
                    "source": "crates.io",
                    "default_features": false,
                    "features": ["net", "os-poll"],
                    "feature_policy": "exact-only",
                    "runtime_role": "connect-readiness-only"
                }
            },
            "evidence": {
                "status": "planning-only",
                "conformance_evidence": false,
                "feature_ids": [],
                "promotion": "forbidden"
            }
        })
    }

    fn parser_limits() -> Value {
        let maxima = REQUIRED_HARD_MAXIMA
            .iter()
            .map(|(name, value)| ((*name).to_owned(), Value::from(*value)))
            .collect::<Map<_, _>>();
        let digest = parser_limits_digest(
            &REQUIRED_HARD_MAXIMA
                .iter()
                .map(|(_, value)| *value)
                .collect::<Vec<_>>(),
        );
        serde_json::json!({
            "schema_id": "http.parser-limits/1",
            "schema_version": 1,
            "categories": REQUIRED_PARSER_CATEGORIES,
            "order": REQUIRED_HARD_MAXIMA.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
            "hard_maxima": maxima.clone(),
            "active": maxima,
            "digest": digest
        })
    }

    fn contracts() -> Value {
        let mut contracts = serde_json::json!({
            "attempt": {
                "schema_id": "http.attempt/1", "schema_version": 1, "max_bytes": 4194304,
                "max_headers": 1024, "max_header_bytes": 1048576,
                "max_informational_responses": 32, "max_trailers": 256, "max_phases": 32,
                "max_counters": 32, "max_diagnostics": 64, "ordered_headers": true,
                "byte_counter_states": ["Known", "Unavailable"], "outcome_enum": ["ResponseComplete", "TransportFailure", "ProtocolFailure", "TimedOut", "Cancelled", "ResourceLimit", "CapabilityUnavailable"],
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
                "sampler_identity": "bounded-sampler-identity", "capability_identity": "schema-version-sha256", "attempt_index": "NonZeroU32",
                "embedded_resource_index": "Absent|Present(u32)",
                "phase_enum": ["queue", "dns", "pool", "proxy-connect", "connect", "proxy-tls", "origin-tls", "request-headers", "request-body", "response-headers", "response-body", "decompression", "state-commit", "result-routing", "cleanup"],
                "stable_error_codes": [],
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
        });
        let stable_codes = Value::Array(
            REQUIRED_STABLE_ERROR_CODES
                .iter()
                .map(|code| Value::String((*code).to_owned()))
                .collect(),
        );
        if let Some(error) = contracts
            .get_mut("error_context")
            .and_then(Value::as_object_mut)
        {
            error.insert("stable_error_codes".to_owned(), stable_codes);
        }
        contracts
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
    fn parser_order_is_required_and_new_revision_maxima_are_checked() {
        let mut parser = parser_limits();
        let Some(object) = parser.as_object_mut() else {
            return;
        };
        object.remove("order");
        let Some(maxima) = object.get_mut("hard_maxima").and_then(Value::as_object_mut) else {
            return;
        };
        maxima.insert("chunk_count".to_owned(), Value::from(1));
        let mut diagnostics = Diagnostics::default();
        validate_parser_limits(object, "parser_limits", &mut diagnostics);
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "HTTP-ACCEPTANCE-SCHEMA"
                && diagnostic.path.ends_with("parser_limits.order")
        }));
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "HTTP-ACCEPTANCE-PARSER"
                && diagnostic.path.ends_with("hard_maxima.chunk_count")
        }));
    }

    #[test]
    fn parser_digest_binds_ordered_active_limits() {
        let mut parser = parser_limits();
        let Some(object) = parser.as_object_mut() else {
            return;
        };
        let Some(active) = object.get_mut("active").and_then(Value::as_object_mut) else {
            return;
        };
        active.insert("chunk_count".to_owned(), Value::from(1_000_000));
        let mut diagnostics = Diagnostics::default();
        validate_parser_limits(object, "parser_limits", &mut diagnostics);
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "HTTP-ACCEPTANCE-IDENTITY"
                && diagnostic.path.ends_with("parser_limits.digest")
        }));
    }

    #[test]
    fn error_contract_rejects_open_ended_codes_and_stale_phase_names() {
        let mut contracts = contracts();
        let Some(root) = contracts.as_object_mut() else {
            return;
        };
        let Some(error) = root.get_mut("error_context").and_then(Value::as_object_mut) else {
            return;
        };
        error.insert(
            "stable_error_codes".to_owned(),
            serde_json::json!(["http.provider-specific"]),
        );
        error.insert(
            "phase_enum".to_owned(),
            serde_json::json!(["dns", "pool", "connect"]),
        );
        let mut diagnostics = Diagnostics::default();
        validate_error_contract(error, "contracts.error_context", &mut diagnostics);
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "HTTP-ACCEPTANCE-SCHEMA"
                && diagnostic.path.ends_with("stable_error_codes")
        }));
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "HTTP-ACCEPTANCE-SCHEMA" && diagnostic.path.ends_with("phase_enum")
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

    #[test]
    fn schema_alias_mismatch_and_unknown_identity_are_rejected() {
        let values = vec![
            serde_json::json!({
                "id": "http.attempt/1",
                "schema_id": "http.state-delta/1",
                "version": 1
            }),
            serde_json::json!({
                "id": "http.future/1",
                "version": 1
            }),
            serde_json::json!("http.future-string/1"),
        ];
        let mut diagnostics = Diagnostics::default();
        validate_schemas(&values, "schemas", &mut diagnostics);
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "HTTP-ACCEPTANCE-IDENTITY"
                && diagnostic.message.contains("same schema")
        }));
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "HTTP-ACCEPTANCE-IDENTITY"
                && diagnostic.message.contains("unsupported top-level")
        }));
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "HTTP-ACCEPTANCE-IDENTITY" && diagnostic.path.ends_with("schemas[2]")
        }));
    }

    #[test]
    fn secret_fields_are_rejected_even_when_nested() {
        let value = serde_json::json!({
            "capabilities": [{
                "identity": {"provider": {"token": "never", "PASSWORD": "never"}}
            }]
        });
        let mut diagnostics = Diagnostics::default();
        reject_secret_fields(&value, "manifest", &mut diagnostics);
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "HTTP-ACCEPTANCE-SECURITY"
                && diagnostic.path.ends_with("provider.token")
        }));
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "HTTP-ACCEPTANCE-SECURITY"
                && diagnostic.path.ends_with("provider.PASSWORD")
        }));
    }

    #[test]
    fn capability_identity_binds_implementation_and_parser_digest() {
        let parser_digest = parser_limits_digest(
            &REQUIRED_HARD_MAXIMA
                .iter()
                .map(|(_, value)| *value)
                .collect::<Vec<_>>(),
        );
        let capability = serde_json::json!({
            "id": "http.native/1",
            "status": "unavailable",
            "implementation": "JmeterJavaV563",
            "parser_limits_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "identity": {
                "schema_id": "http.native/1",
                "version": 1,
                "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "name": "NativeV1",
                "source": "static declaration"
            },
            "dependencies": [],
            "providers": [],
            "source_paths": [],
            "expected_artifacts": [],
            "raw_diagnostic_location": "diagnostics/http-native.json",
            "materialization": {
                "source_fixture_present": true,
                "oracle_evidence_materialized": false,
                "observed_run": false,
                "status": "declared"
            },
            "unavailable_reason": "native implementation is not materialized"
        });
        let mut diagnostics = Diagnostics::default();
        validate_capabilities(
            &[capability],
            "manifest",
            Path::new("root"),
            Path::new("fixture"),
            Some(&parser_digest),
            &mut diagnostics,
        );
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "HTTP-ACCEPTANCE-IDENTITY"
                && diagnostic.path.ends_with("capabilities[0].implementation")
        }));
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "HTTP-ACCEPTANCE-IDENTITY"
                && diagnostic
                    .path
                    .ends_with("capabilities[0].parser_limits_digest")
        }));
    }

    #[test]
    fn standalone_selector_contract_rejects_non_cli_or_fallback_values() {
        let mut declaration = standalone_provider_substitution();
        let Some(object) = declaration.as_object_mut() else {
            return;
        };
        let Some(selector) = object.get_mut("selector").and_then(Value::as_object_mut) else {
            return;
        };
        selector.insert(
            "operations".to_owned(),
            serde_json::json!(["-Jjmeter-rs.http.capability=http.jmeter-java/5.6.3"]),
        );
        selector.insert(
            "provenance".to_owned(),
            Value::String("environment".to_owned()),
        );
        selector.insert(
            "invalid_inputs".to_owned(),
            serde_json::json!(["empty", "removed"]),
        );
        let Some(source_provider) = object
            .get_mut("source_provider")
            .and_then(Value::as_object_mut)
        else {
            return;
        };
        source_provider.insert("preserved".to_owned(), Value::Bool(false));
        source_provider.insert(
            "identities".to_owned(),
            serde_json::json!(["http.native/1"]),
        );

        let mut diagnostics = Diagnostics::default();
        validate_standalone_provider_substitution(
            Some(&declaration),
            "manifest.standalone_provider_substitution",
            &mut diagnostics,
        );
        for suffix in [
            "selector.operations",
            "selector.provenance",
            "selector.invalid_inputs",
            "source_provider.preserved",
            "source_provider.identities",
        ] {
            assert!(
                diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.path.ends_with(suffix)),
                "missing diagnostic for {suffix}: {diagnostics:?}"
            );
        }
    }

    #[test]
    fn standalone_selector_rejects_aliases_and_implicit_upgrade() {
        let mut declaration = standalone_provider_substitution();
        let Some(object) = declaration.as_object_mut() else {
            return;
        };
        let Some(selector) = object.get_mut("selector").and_then(Value::as_object_mut) else {
            return;
        };
        selector.insert(
            "values".to_owned(),
            serde_json::json!(["http.native", "http.native/2"]),
        );
        selector.insert(
            "operations".to_owned(),
            serde_json::json!(["-Jjmeter-rs.http.capability=http.native"]),
        );
        let Some(native_v2) = object.get_mut("native_v2").and_then(Value::as_object_mut) else {
            return;
        };
        let Some(selection) = native_v2
            .get_mut("selection")
            .and_then(Value::as_object_mut)
        else {
            return;
        };
        selection.insert(
            "upgrade_from_v1".to_owned(),
            Value::String("allowed".to_owned()),
        );

        let mut diagnostics = Diagnostics::default();
        validate_standalone_provider_substitution(
            Some(&declaration),
            "manifest.standalone_provider_substitution",
            &mut diagnostics,
        );
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.path.ends_with("selector.values")
                && diagnostic.code == "HTTP-ACCEPTANCE-SCHEMA"
        }));
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.path.ends_with("selector.operations")
                && diagnostic.code == "HTTP-ACCEPTANCE-SCHEMA"
        }));
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic
                .path
                .ends_with("native_v2.selection.upgrade_from_v1")
        }));
    }

    #[test]
    fn native_v2_declaration_is_valid_planning_metadata() {
        let declaration = standalone_provider_substitution();
        let mut diagnostics = Diagnostics::default();
        validate_standalone_provider_substitution(
            Some(&declaration),
            "manifest.standalone_provider_substitution",
            &mut diagnostics,
        );
        assert!(
            diagnostics.is_empty(),
            "baseline NativeV1/NativeV2 declaration must be valid: {diagnostics:?}"
        );
    }

    #[test]
    fn native_v2_requires_direct_exactly_one_hostname_policy() {
        let mut declaration = standalone_provider_substitution();
        let Some(root) = declaration.as_object_mut() else {
            return;
        };
        let Some(native_v2) = root.get_mut("native_v2").and_then(Value::as_object_mut) else {
            return;
        };
        let Some(hostname) = native_v2.get_mut("hostname").and_then(Value::as_object_mut) else {
            return;
        };
        hostname.remove("property");
        hostname.insert(
            "provenance".to_owned(),
            Value::String("environment".to_owned()),
        );
        hostname.insert(
            "cardinality".to_owned(),
            Value::String("allow-repeated".to_owned()),
        );
        hostname.insert(
            "system_config".to_owned(),
            Value::String("allowed".to_owned()),
        );
        hostname.insert("hosts_file".to_owned(), Value::String("allowed".to_owned()));
        hostname.insert(
            "search_domain".to_owned(),
            Value::String("allowed".to_owned()),
        );
        hostname.insert(
            "ambient_cache".to_owned(),
            Value::String("allowed".to_owned()),
        );
        hostname.insert(
            "cache_scope".to_owned(),
            Value::String("run-global".to_owned()),
        );
        let mut diagnostics = Diagnostics::default();
        validate_native_v2(
            Some(&Value::Object(native_v2.clone())),
            "native_v2",
            &mut diagnostics,
        );
        for suffix in [
            "native_v2.hostname.property",
            "native_v2.hostname.provenance",
            "native_v2.hostname.cardinality",
            "native_v2.hostname.system_config",
            "native_v2.hostname.hosts_file",
            "native_v2.hostname.search_domain",
            "native_v2.hostname.ambient_cache",
            "native_v2.hostname.cache_scope",
        ] {
            assert!(
                diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.path.ends_with(suffix)),
                "missing diagnostic for {suffix}: {diagnostics:?}"
            );
        }
    }

    #[test]
    fn native_v2_requires_first_bounded_dns_answer_and_single_connect() {
        let mut declaration = standalone_provider_substitution();
        let Some(root) = declaration.as_object_mut() else {
            return;
        };
        let Some(native_v2) = root.get_mut("native_v2").and_then(Value::as_object_mut) else {
            return;
        };
        let Some(hostname) = native_v2.get_mut("hostname").and_then(Value::as_object_mut) else {
            return;
        };
        let Some(address_selection) = hostname
            .get_mut("address_selection")
            .and_then(Value::as_object_mut)
        else {
            return;
        };
        for (field, value) in [
            ("returned_order", "provider-order"),
            ("answer_list", "truncated"),
            ("selected_address", "last-address"),
            ("connect_attempts", "one-per-address"),
            ("address_fallback", "allowed"),
        ] {
            address_selection.insert(field.to_owned(), Value::String(value.to_owned()));
        }
        address_selection.insert("max_addresses".to_owned(), Value::Number(17.into()));
        let mut diagnostics = Diagnostics::default();
        validate_native_v2(
            Some(&Value::Object(native_v2.clone())),
            "native_v2",
            &mut diagnostics,
        );
        for field in [
            "returned_order",
            "answer_list",
            "max_addresses",
            "selected_address",
            "connect_attempts",
            "address_fallback",
        ] {
            let suffix = format!("native_v2.hostname.address_selection.{field}");
            assert!(
                diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.path.ends_with(&suffix)),
                "missing diagnostic for {suffix}: {diagnostics:?}"
            );
        }
    }

    #[test]
    fn native_v2_requires_direct_exactly_one_root_contained_pem_tls_policy() {
        let mut declaration = standalone_provider_substitution();
        let Some(root) = declaration.as_object_mut() else {
            return;
        };
        let Some(native_v2) = root.get_mut("native_v2").and_then(Value::as_object_mut) else {
            return;
        };
        let Some(https) = native_v2.get_mut("https").and_then(Value::as_object_mut) else {
            return;
        };
        https.remove("identity");
        https.insert("provenance".to_owned(), Value::String("system".to_owned()));
        https.insert(
            "cardinality".to_owned(),
            Value::String("allow-repeated".to_owned()),
        );
        https.insert(
            "path_policy".to_owned(),
            Value::String("unrestricted".to_owned()),
        );
        https.insert("format".to_owned(), Value::String("DER-or-PEM".to_owned()));
        https.insert(
            "platform_roots".to_owned(),
            Value::String("allowed".to_owned()),
        );
        https.insert(
            "webpki_roots".to_owned(),
            Value::String("allowed".to_owned()),
        );
        https.insert("trust_all".to_owned(), Value::String("allowed".to_owned()));
        https.insert("client_key".to_owned(), Value::String("allowed".to_owned()));
        https.insert(
            "configuration".to_owned(),
            Value::String("mutable".to_owned()),
        );
        let mut diagnostics = Diagnostics::default();
        validate_native_v2(
            Some(&Value::Object(native_v2.clone())),
            "native_v2",
            &mut diagnostics,
        );
        for suffix in [
            "native_v2.https.provenance",
            "native_v2.https.cardinality",
            "native_v2.https.path_policy",
            "native_v2.https.format",
            "native_v2.https.identity",
            "native_v2.https.platform_roots",
            "native_v2.https.webpki_roots",
            "native_v2.https.trust_all",
            "native_v2.https.client_key",
            "native_v2.https.configuration",
        ] {
            assert!(
                diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.path.ends_with(suffix)),
                "missing diagnostic for {suffix}: {diagnostics:?}"
            );
        }
    }

    #[test]
    fn native_v2_keeps_http11_authority_and_numeric_peer_separate() {
        let mut declaration = standalone_provider_substitution();
        let Some(root) = declaration.as_object_mut() else {
            return;
        };
        let Some(native_v2) = root.get_mut("native_v2").and_then(Value::as_object_mut) else {
            return;
        };
        let Some(protocol) = native_v2.get_mut("protocol").and_then(Value::as_object_mut) else {
            return;
        };
        protocol.insert(
            "http_version".to_owned(),
            Value::String("HTTP/2".to_owned()),
        );
        protocol.insert("alpn".to_owned(), serde_json::json!(["h2", "http/1.1"]));
        let Some(authority) = native_v2
            .get_mut("authority")
            .and_then(Value::as_object_mut)
        else {
            return;
        };
        authority.insert(
            "http_host".to_owned(),
            Value::String("resolved.numeric.peer".to_owned()),
        );
        authority.insert("rewrite".to_owned(), Value::String("allowed".to_owned()));
        authority.insert(
            "numeric_peer".to_owned(),
            Value::String("rewrites-authority".to_owned()),
        );
        let mut diagnostics = Diagnostics::default();
        validate_native_v2(
            Some(&Value::Object(native_v2.clone())),
            "native_v2",
            &mut diagnostics,
        );
        for suffix in [
            "native_v2.protocol.http_version",
            "native_v2.protocol.alpn",
            "native_v2.authority.http_host",
            "native_v2.authority.rewrite",
            "native_v2.authority.numeric_peer",
        ] {
            assert!(
                diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.path.ends_with(suffix)),
                "missing diagnostic for {suffix}: {diagnostics:?}"
            );
        }
    }

    #[test]
    fn native_v2_requires_subordinate_identity_and_dependency_versions() {
        let mut declaration = standalone_provider_substitution();
        let Some(root) = declaration.as_object_mut() else {
            return;
        };
        let Some(native_v2) = root.get_mut("native_v2").and_then(Value::as_object_mut) else {
            return;
        };
        native_v2.remove("identities");
        let Some(dependencies) = native_v2
            .get_mut("dependency_versions")
            .and_then(Value::as_array_mut)
        else {
            return;
        };
        dependencies.pop();
        let Some(provider) = native_v2
            .get_mut("provider_versions")
            .and_then(Value::as_array_mut)
        else {
            return;
        };
        let Some(entry) = provider.first_mut().and_then(Value::as_object_mut) else {
            return;
        };
        entry.insert("version".to_owned(), Value::String("0.0.0".to_owned()));
        let mut diagnostics = Diagnostics::default();
        validate_native_v2(
            Some(&Value::Object(native_v2.clone())),
            "native_v2",
            &mut diagnostics,
        );
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.path.ends_with("native_v2.identities")
                && diagnostic.code == "HTTP-ACCEPTANCE-SCHEMA"
        }));
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| { diagnostic.path.ends_with("native_v2.dependency_versions") })
        );
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic
                .path
                .ends_with("native_v2.provider_versions[0].version")
        }));
    }

    #[test]
    fn native_v2_unsupported_scope_is_atomic_and_planning_only() {
        let mut declaration = standalone_provider_substitution();
        let Some(root) = declaration.as_object_mut() else {
            return;
        };
        let Some(native_v2) = root.get_mut("native_v2").and_then(Value::as_object_mut) else {
            return;
        };
        let Some(unsupported) = native_v2
            .get_mut("unsupported")
            .and_then(Value::as_object_mut)
        else {
            return;
        };
        unsupported.insert("scope".to_owned(), Value::String("sampler".to_owned()));
        unsupported.insert("partial".to_owned(), Value::String("run-prefix".to_owned()));
        let Some(evidence) = native_v2.get_mut("evidence").and_then(Value::as_object_mut) else {
            return;
        };
        evidence.insert("conformance_evidence".to_owned(), Value::Bool(true));
        evidence.insert("feature_ids".to_owned(), serde_json::json!(["ELEM-001"]));
        let mut diagnostics = Diagnostics::default();
        validate_native_v2(
            Some(&Value::Object(native_v2.clone())),
            "native_v2",
            &mut diagnostics,
        );
        for suffix in [
            "native_v2.unsupported.scope",
            "native_v2.unsupported.partial",
            "native_v2.evidence.conformance_evidence",
            "native_v2.evidence.feature_ids",
        ] {
            assert!(
                diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.path.ends_with(suffix)),
                "missing diagnostic for {suffix}: {diagnostics:?}"
            );
        }
    }

    #[test]
    fn standalone_selector_declaration_is_required() {
        let mut diagnostics = Diagnostics::default();
        validate_standalone_provider_substitution(
            None,
            "manifest.standalone_provider_substitution",
            &mut diagnostics,
        );
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "HTTP-ACCEPTANCE-SELECTION"
                && diagnostic
                    .path
                    .ends_with("standalone_provider_substitution")
        }));
    }

    #[test]
    fn standalone_admission_rejects_partial_execution_and_side_effects() {
        let mut declaration = standalone_provider_substitution();
        let Some(object) = declaration.as_object_mut() else {
            return;
        };
        let Some(executed_providers) = object
            .get_mut("executed_providers")
            .and_then(Value::as_array_mut)
        else {
            return;
        };
        let Some(executed_provider) = executed_providers.get_mut(1).and_then(Value::as_object_mut)
        else {
            return;
        };
        executed_provider.insert(
            "implementation".to_owned(),
            Value::String("JmeterHttpClient4V563".to_owned()),
        );
        let Some(admission) = object.get_mut("admission").and_then(Value::as_object_mut) else {
            return;
        };
        admission.insert("mode".to_owned(), Value::String("best-effort".to_owned()));
        admission.insert(
            "resolve_before".to_owned(),
            serde_json::json!(["dns", "socket"]),
        );
        admission.insert(
            "unsupported_feature".to_owned(),
            Value::String("skip-node".to_owned()),
        );
        admission.insert(
            "supported_prefix".to_owned(),
            Value::String("run-prefix".to_owned()),
        );
        admission.insert("silent_drop".to_owned(), Value::String("allow".to_owned()));

        let mut diagnostics = Diagnostics::default();
        validate_standalone_provider_substitution(
            Some(&declaration),
            "manifest.standalone_provider_substitution",
            &mut diagnostics,
        );
        for suffix in [
            "executed_providers[1].implementation",
            "admission.mode",
            "admission.resolve_before",
            "admission.unsupported_feature",
            "admission.supported_prefix",
            "admission.silent_drop",
        ] {
            assert!(
                diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.path.ends_with(suffix)),
                "missing diagnostic for {suffix}: {diagnostics:?}"
            );
        }
    }

    #[test]
    fn native_edge_requires_an_application_worker_pool() {
        let mut edge = native_edge();
        let Some(object) = edge.as_object_mut() else {
            return;
        };
        object.remove("worker_pool");
        let mut diagnostics = Diagnostics::default();
        validate_native_edge(object, "native_edge", &mut diagnostics);
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.path.ends_with("native_edge.worker_pool")
                && diagnostic.message.contains("required field is missing")
        }));
    }

    #[test]
    fn native_edge_rejects_unbounded_queue_and_retained_bytes() {
        let mut edge = native_edge();
        let Some(object) = edge.as_object_mut() else {
            return;
        };
        let Some(pool) = object.get_mut("worker_pool").and_then(Value::as_object_mut) else {
            return;
        };
        let Some(queue) = pool.get_mut("queue").and_then(Value::as_object_mut) else {
            return;
        };
        queue.insert("capacity".to_owned(), Value::from(u64::MAX));
        let Some(retained) = pool
            .get_mut("retained_bytes")
            .and_then(Value::as_object_mut)
        else {
            return;
        };
        retained.insert("maximum".to_owned(), Value::from(u64::MAX));

        let mut diagnostics = Diagnostics::default();
        validate_worker_pool(pool, "native_edge.worker_pool", &mut diagnostics);
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.path.ends_with("worker_pool.queue.capacity")
                && diagnostic.code == "HTTP-ACCEPTANCE-BOUNDS"
        }));
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic
                .path
                .ends_with("worker_pool.retained_bytes.maximum")
                && diagnostic.code == "HTTP-ACCEPTANCE-BOUNDS"
        }));
    }

    #[test]
    fn native_edge_rejects_inline_and_per_user_thread_fallbacks() {
        let mut edge = native_edge();
        let Some(object) = edge.as_object_mut() else {
            return;
        };
        let Some(pool) = object.get_mut("worker_pool").and_then(Value::as_object_mut) else {
            return;
        };
        let Some(dispatch) = pool.get_mut("dispatch").and_then(Value::as_object_mut) else {
            return;
        };
        dispatch.insert("inline".to_owned(), Value::String("allowed".to_owned()));
        dispatch.insert(
            "one_thread_per_virtual_user".to_owned(),
            Value::String("allowed".to_owned()),
        );

        let mut diagnostics = Diagnostics::default();
        validate_worker_pool(pool, "native_edge.worker_pool", &mut diagnostics);
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| { diagnostic.path.ends_with("worker_pool.dispatch.inline") })
        );
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic
                .path
                .ends_with("worker_pool.dispatch.one_thread_per_virtual_user")
        }));
    }

    #[test]
    fn native_edge_rejects_ambient_bootstrap_dns() {
        let mut edge = native_edge();
        let Some(object) = edge.as_object_mut() else {
            return;
        };
        let Some(dns) = object.get_mut("dns").and_then(Value::as_object_mut) else {
            return;
        };
        dns.insert("ambient".to_owned(), Value::String("allowed".to_owned()));
        dns.insert(
            "bootstrap".to_owned(),
            Value::String("system-resolver".to_owned()),
        );

        let mut diagnostics = Diagnostics::default();
        validate_bootstrap_dns(dns, "native_edge.dns", &mut diagnostics);
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| { diagnostic.path.ends_with("native_edge.dns.ambient") })
        );
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| { diagnostic.path.ends_with("native_edge.dns.bootstrap") })
        );
    }

    #[test]
    fn native_edge_rejects_forced_close_or_eof_framing() {
        let mut edge = native_edge();
        let Some(object) = edge.as_object_mut() else {
            return;
        };
        let Some(framing) = object.get_mut("framing").and_then(Value::as_object_mut) else {
            return;
        };
        framing.insert(
            "connection_close".to_owned(),
            Value::String("required".to_owned()),
        );
        framing.insert("eof".to_owned(), Value::String("required".to_owned()));
        framing.insert("forced_connection_close".to_owned(), Value::Bool(true));
        framing.insert("forced_eof".to_owned(), Value::Bool(true));

        let mut diagnostics = Diagnostics::default();
        validate_bootstrap_framing(framing, "native_edge.framing", &mut diagnostics);
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic
                .path
                .ends_with("native_edge.framing.connection_close")
        }));
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.path.ends_with("native_edge.framing.eof"))
        );
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic
                .path
                .ends_with("native_edge.framing.forced_connection_close")
        }));
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.path.ends_with("native_edge.framing.forced_eof"))
        );
    }

    #[test]
    fn native_edge_rejects_multiple_connect_attempts() {
        let mut edge = native_edge();
        let Some(object) = edge.as_object_mut() else {
            return;
        };
        let Some(connect) = object
            .get_mut("connect_edge")
            .and_then(Value::as_object_mut)
        else {
            return;
        };
        connect.insert(
            "connect_attempts".to_owned(),
            Value::String("multiple".to_owned()),
        );
        let mut diagnostics = Diagnostics::default();
        validate_native_connect_edge(connect, "native_edge.connect_edge", &mut diagnostics);
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic
                .path
                .ends_with("native_edge.connect_edge.connect_attempts")
        }));
    }

    #[test]
    fn native_edge_rejects_timer_sliced_connect_timeout_attempts() {
        let mut edge = native_edge();
        let Some(object) = edge.as_object_mut() else {
            return;
        };
        let Some(connect) = object
            .get_mut("connect_edge")
            .and_then(Value::as_object_mut)
        else {
            return;
        };
        connect.insert(
            "connect_timeout_attempts".to_owned(),
            Value::String("repeated-short".to_owned()),
        );
        connect.insert(
            "timer_slicing".to_owned(),
            Value::String("allowed".to_owned()),
        );
        let mut diagnostics = Diagnostics::default();
        validate_native_connect_edge(connect, "native_edge.connect_edge", &mut diagnostics);
        for suffix in [
            "native_edge.connect_edge.connect_timeout_attempts",
            "native_edge.connect_edge.timer_slicing",
        ] {
            assert!(
                diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.path.ends_with(suffix)),
                "missing diagnostic for {suffix}: {diagnostics:?}"
            );
        }
    }

    #[test]
    fn native_edge_requires_shared_arc_waker_cancellation_readiness() {
        let mut edge = native_edge();
        let Some(object) = edge.as_object_mut() else {
            return;
        };
        let Some(connect) = object
            .get_mut("connect_edge")
            .and_then(Value::as_object_mut)
        else {
            return;
        };
        connect.remove("waker");
        connect.insert(
            "cancellation".to_owned(),
            Value::String("poll-only".to_owned()),
        );
        connect.insert(
            "readiness".to_owned(),
            Value::String("poll-only".to_owned()),
        );
        let mut diagnostics = Diagnostics::default();
        validate_native_connect_edge(connect, "native_edge.connect_edge", &mut diagnostics);
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.path.ends_with("native_edge.connect_edge.waker")
                && diagnostic.message.contains("required field is missing")
        }));
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic
                .path
                .ends_with("native_edge.connect_edge.cancellation")
        }));
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic
                .path
                .ends_with("native_edge.connect_edge.readiness")
        }));
    }

    #[test]
    fn native_edge_rejects_wrong_mio_features_or_defaults() {
        let mut edge = native_edge();
        let Some(object) = edge.as_object_mut() else {
            return;
        };
        let Some(connect) = object
            .get_mut("connect_edge")
            .and_then(Value::as_object_mut)
        else {
            return;
        };
        let Some(mio) = connect
            .get_mut("mio_dependency")
            .and_then(Value::as_object_mut)
        else {
            return;
        };
        mio.insert("default_features".to_owned(), Value::Bool(true));
        mio.insert(
            "features".to_owned(),
            serde_json::json!(["net", "os-poll", "os-poll"]),
        );
        let mut diagnostics = Diagnostics::default();
        validate_native_connect_edge(connect, "native_edge.connect_edge", &mut diagnostics);
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic
                .path
                .ends_with("native_edge.connect_edge.mio_dependency.default_features")
        }));
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic
                .path
                .ends_with("native_edge.connect_edge.mio_dependency.features")
        }));
    }

    #[test]
    fn native_edge_rejects_async_runtime_or_provider_drift() {
        let mut edge = native_edge();
        let Some(object) = edge.as_object_mut() else {
            return;
        };
        let Some(connect) = object
            .get_mut("connect_edge")
            .and_then(Value::as_object_mut)
        else {
            return;
        };
        connect.insert(
            "async_runtime".to_owned(),
            Value::String("tokio".to_owned()),
        );
        connect.insert(
            "async_provider".to_owned(),
            Value::String("hyper".to_owned()),
        );
        let mut diagnostics = Diagnostics::default();
        validate_native_connect_edge(connect, "native_edge.connect_edge", &mut diagnostics);
        for suffix in [
            "native_edge.connect_edge.async_runtime",
            "native_edge.connect_edge.async_provider",
        ] {
            assert!(
                diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.path.ends_with(suffix)),
                "missing diagnostic for {suffix}: {diagnostics:?}"
            );
        }
    }

    #[test]
    fn native_edge_descriptor_cannot_claim_elem_001_evidence() {
        let mut edge = native_edge();
        let Some(object) = edge.as_object_mut() else {
            return;
        };
        let Some(evidence) = object.get_mut("evidence").and_then(Value::as_object_mut) else {
            return;
        };
        evidence.insert("conformance_evidence".to_owned(), Value::Bool(true));
        evidence.insert("feature_ids".to_owned(), serde_json::json!(["ELEM-001"]));

        let mut diagnostics = Diagnostics::default();
        validate_planning_evidence(evidence, "native_edge.evidence", &mut diagnostics);
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic
                .path
                .ends_with("native_edge.evidence.conformance_evidence")
        }));
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic
                .path
                .ends_with("native_edge.evidence.feature_ids")
        }));
    }
}
