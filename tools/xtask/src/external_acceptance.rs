// SPDX-License-Identifier: Apache-2.0
//! Static Decision 0007 external-adapter acceptance validation.
//!
//! This check validates declarations only. It never starts a process/JVM,
//! opens a socket, resolves a service, reads an oracle archive, or turns a
//! descriptor into an observation.

use crate::diagnostics::{Diagnostic, Diagnostics};
use crate::profile::{ProfileIndex, display_path};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const SCHEMA_ID: &str = "jmeter-rs.external-acceptance";
const SCHEMA_VERSION: u64 = 2;
const DECISION: &str = "0007-rev2";
const MAX_INPUT_BYTES: u64 = 4 * 1024 * 1024;
const MAX_DEPTH: usize = 48;
const MAX_NODES: usize = 100_000;
const SHA256_LEN: usize = 64;
const SHA512_LEN: usize = 128;

// These are identity roles, rather than free-form labels.  A declaration
// which calls an artifact a "service" or "driver" must give us enough
// structure to bind the dependency before a worker is admitted.  Keeping the
// vocabulary closed is important: a typo must not turn an unpinned external
// dependency into a successful-looking declaration.
const ARTIFACT_ROLES: [&str; 11] = [
    "adapter",
    "helper",
    "schema",
    "classpath",
    "class-loader",
    "provider",
    "driver",
    "service",
    "plugin",
    "license",
    "notice",
];
const DEPENDENCY_ROLES: [&str; 4] = ["driver", "provider", "service", "plugin"];
const FORBIDDEN_STATIC_MARKERS: [&str; 8] = [
    "observed",
    "observed_run",
    "oracle_evidence_materialized",
    "release_claim_eligible",
    "release_eligible",
    "verified",
    "materialized",
    "evidence",
];
const FORBIDDEN_PROCESS_FIELDS: [&str; 8] = [
    "argv",
    "command",
    "shell",
    "pid",
    "pgid",
    "process_group",
    "raw_pid",
    "raw_handle",
];

const REQUIRED_CATEGORIES: [&str; 11] = [
    "positive",
    "unavailable",
    "wrong-identity",
    "timeout",
    "cancellation",
    "crash",
    "malformed-oversized",
    "redaction",
    "no-fallback",
    "setup-teardown",
    "terminal-accounting",
];
const ADAPTER_KINDS: [&str; 2] = ["jvm", "native"];
const CONCURRENCY_KINDS: [&str; 3] = ["RunSerial", "PerUserSerial", "BoundedParallel"];
const STATIC_STATUSES: [&str; 3] = ["planned", "unavailable", "not-run"];
const SECRET_KEYS: [&str; 19] = [
    "password",
    "password_value",
    "private_key",
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
    "credential",
    "credential_value",
    "argv_value",
    "key_material",
    "client_secret",
    "authorization",
];

/// Validate the Decision 0007 manifest for the active profile.
pub(crate) fn check(
    root: &Path,
    manifest_path: &Path,
    profile_path: &Path,
    profile: &ProfileIndex,
) -> Diagnostics {
    let mut diagnostics = Diagnostics::default();
    let Some(manifest) = read_json(root, manifest_path, &mut diagnostics) else {
        return diagnostics;
    };
    let path = display_path(root, manifest_path);
    let Some(object) = manifest.as_object() else {
        diagnostics.push(error(
            "EXTERNAL-ACCEPTANCE-SCHEMA",
            path,
            "manifest must be a JSON object",
        ));
        return diagnostics;
    };
    let mut nodes = 0;
    check_limits(&manifest, &path, 0, &mut nodes, &mut diagnostics);
    check_secret_keys(&manifest, &path, &mut diagnostics);
    check_static_markers(&manifest, &path, &mut diagnostics);
    check_process_fields(&manifest, &path, &mut diagnostics);

    exact_string(object, "schema_id", &path, SCHEMA_ID, &mut diagnostics);
    exact_u64(
        object,
        "schema_version",
        &path,
        SCHEMA_VERSION,
        &mut diagnostics,
    );
    exact_string(object, "decision", &path, DECISION, &mut diagnostics);

    let Some(active) = active_profile(root, profile_path, &mut diagnostics) else {
        return diagnostics;
    };
    bind_profile(
        root,
        manifest_path,
        profile_path,
        profile,
        &active,
        object,
        &mut diagnostics,
    );

    let Some(families) = array(object, "families", &path, &mut diagnostics) else {
        diagnostics.sort_deterministically();
        return diagnostics;
    };
    check_families(root, profile, &active, families, &mut diagnostics);
    diagnostics.sort_deterministically();
    diagnostics
}

#[derive(Clone, Debug)]
struct ActiveProfile {
    id: String,
    version: u64,
    sha256: String,
    project: String,
    oracle_version: String,
    source_commit: String,
    artifact: String,
    artifact_url: String,
    source_tree: String,
    digest_url: String,
    signature_url: String,
    keys_url: String,
    artifact_sha512: String,
    signature_verified: bool,
    signature_fingerprint: Option<String>,
}

fn active_profile(
    root: &Path,
    profile_path: &Path,
    diagnostics: &mut Diagnostics,
) -> Option<ActiveProfile> {
    let path = display_path(root, profile_path);
    let bytes = match regular_file(profile_path) {
        Ok(bytes) => bytes,
        Err(message) => {
            diagnostics.push(error(
                "EXTERNAL-ACCEPTANCE-IDENTITY",
                path,
                format!("cannot read active profile: {message}"),
            ));
            return None;
        }
    };
    let sha256 = digest(&bytes);
    let value = match serde_json::from_slice::<Value>(&bytes) {
        Ok(value) => value,
        Err(parse_error) => {
            diagnostics.push(error(
                "EXTERNAL-ACCEPTANCE-IDENTITY",
                path,
                format!("active profile JSON is malformed: {parse_error}"),
            ));
            return None;
        }
    };
    let Some(object) = value.as_object() else {
        diagnostics.push(error(
            "EXTERNAL-ACCEPTANCE-IDENTITY",
            path,
            "active profile must be a JSON object",
        ));
        return None;
    };
    let Some(upstream) = object.get("upstream").and_then(Value::as_object) else {
        diagnostics.push(error(
            "EXTERNAL-ACCEPTANCE-IDENTITY",
            format!("{path}.upstream"),
            "active profile upstream is missing",
        ));
        return None;
    };
    let Some(artifact) = upstream.get("artifact").and_then(Value::as_object) else {
        diagnostics.push(error(
            "EXTERNAL-ACCEPTANCE-IDENTITY",
            format!("{path}.upstream.artifact"),
            "active profile artifact is missing",
        ));
        return None;
    };
    let signature = artifact
        .get("verification")
        .and_then(Value::as_object)
        .and_then(|value| value.get("signature_verified"))
        .and_then(Value::as_bool);
    let signature_fingerprint = artifact
        .get("verification")
        .and_then(Value::as_object)
        .and_then(|value| {
            value
                .get("signature_fingerprint")
                .or_else(|| value.get("accepted_key_fingerprint"))
        })
        .and_then(Value::as_str);
    let fields = (
        object.get("profile_id").and_then(Value::as_str),
        object.get("profile_version").and_then(Value::as_u64),
        upstream.get("project").and_then(Value::as_str),
        upstream.get("version").and_then(Value::as_str),
        upstream.get("source_commit").and_then(Value::as_str),
        artifact.get("filename").and_then(Value::as_str),
        artifact.get("url").and_then(Value::as_str),
        upstream.get("source_tree").and_then(Value::as_str),
        artifact.get("digest_url").and_then(Value::as_str),
        artifact.get("signature_url").and_then(Value::as_str),
        artifact.get("keys_url").and_then(Value::as_str),
        artifact.get("digest").and_then(Value::as_str),
        signature,
        signature_fingerprint,
    );
    let (
        Some(id),
        Some(version),
        Some(project),
        Some(oracle_version),
        Some(source_commit),
        Some(artifact_name),
        Some(artifact_url),
        Some(source_tree),
        Some(digest_url),
        Some(signature_url),
        Some(keys_url),
        Some(artifact_sha512),
        Some(signature_verified),
        signature_fingerprint,
    ) = fields
    else {
        diagnostics.push(error(
            "EXTERNAL-ACCEPTANCE-IDENTITY",
            path,
            "active profile has incomplete oracle or signature identity",
        ));
        return None;
    };
    if signature_verified && signature_fingerprint.is_none_or(|value| !is_fingerprint(value)) {
        diagnostics.push(error(
            "EXTERNAL-ACCEPTANCE-IDENTITY",
            format!("{path}.upstream.artifact.verification.signature_fingerprint"),
            "active profile signature fingerprint must be a nonzero 40-character hexadecimal key ID",
        ));
    }
    if !is_digest(artifact_sha512, SHA512_LEN) {
        diagnostics.push(error(
            "EXTERNAL-ACCEPTANCE-IDENTITY",
            format!("{path}.upstream.artifact.digest"),
            "active profile artifact digest must be a nonzero lowercase SHA-512 value",
        ));
    }
    if source_commit.len() != 40
        || !source_commit
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        diagnostics.push(error(
            "EXTERNAL-ACCEPTANCE-IDENTITY",
            format!("{path}.upstream.source_commit"),
            "active profile source commit must be a lowercase 40-character hexadecimal ID",
        ));
    }
    for (field, value) in [
        ("url", artifact_url),
        ("digest_url", digest_url),
        ("signature_url", signature_url),
        ("keys_url", keys_url),
        ("source_tree", source_tree),
    ] {
        if !value.starts_with("https://") {
            diagnostics.push(error(
                "EXTERNAL-ACCEPTANCE-IDENTITY",
                format!("{path}.upstream.artifact.{field}"),
                "active profile oracle endpoints must use HTTPS",
            ));
        }
    }
    Some(ActiveProfile {
        id: id.to_owned(),
        version,
        sha256,
        project: project.to_owned(),
        oracle_version: oracle_version.to_owned(),
        source_commit: source_commit.to_owned(),
        artifact: artifact_name.to_owned(),
        artifact_url: artifact_url.to_owned(),
        source_tree: source_tree.to_owned(),
        digest_url: digest_url.to_owned(),
        signature_url: signature_url.to_owned(),
        keys_url: keys_url.to_owned(),
        artifact_sha512: artifact_sha512.to_owned(),
        signature_verified,
        signature_fingerprint: signature_fingerprint.map(str::to_owned),
    })
}

fn bind_profile(
    root: &Path,
    manifest_path: &Path,
    profile_path: &Path,
    profile: &ProfileIndex,
    active: &ActiveProfile,
    manifest: &Map<String, Value>,
    diagnostics: &mut Diagnostics,
) {
    let path = display_path(root, manifest_path);
    if active.id != profile.profile_id {
        diagnostics.push(error(
            "EXTERNAL-ACCEPTANCE-IDENTITY",
            format!("{path}.profile_id"),
            format!(
                "active profile file identifies {:?}, but profile index identifies {:?}",
                active.id, profile.profile_id
            ),
        ));
    }
    exact_string(
        manifest,
        "profile_id",
        &path,
        &profile.profile_id,
        &mut *diagnostics,
    );
    exact_string(
        manifest,
        "profile_path",
        &path,
        &display_path(root, profile_path),
        &mut *diagnostics,
    );
    exact_string(
        manifest,
        "profile_sha256",
        &path,
        &active.sha256,
        &mut *diagnostics,
    );
    exact_u64(
        manifest,
        "profile_version",
        &path,
        active.version,
        &mut *diagnostics,
    );
    if !active.signature_verified {
        diagnostics.push(error(
            "EXTERNAL-ACCEPTANCE-PROVENANCE",
            format!("{path}.profile_sha256"),
            "active profile artifact signature_verified is false; external execution/evidence remains unavailable",
        ));
    }
}

fn check_families(
    root: &Path,
    profile: &ProfileIndex,
    active: &ActiveProfile,
    families: &[Value],
    diagnostics: &mut Diagnostics,
) {
    let expected = profile
        .fixture_statuses
        .iter()
        .filter_map(|(id, status)| (status == "external").then_some(id.clone()))
        .collect::<BTreeSet<_>>();
    let mut declared = BTreeSet::new();
    let mut seen = BTreeMap::new();
    for (index, value) in families.iter().enumerate() {
        let path = format!("external-acceptance.json.families[{index}]");
        let Some(family) = value.as_object() else {
            diagnostics.push(error(
                "EXTERNAL-ACCEPTANCE-SCHEMA",
                path,
                "family entry must be an object",
            ));
            continue;
        };
        let Some(id) = nonempty(family, "fixture_family_id", &path, diagnostics) else {
            continue;
        };
        if let Some(previous) = seen.insert(id.to_owned(), index) {
            diagnostics.push(error(
                "EXTERNAL-ACCEPTANCE-DUPLICATE",
                format!("{path}.fixture_family_id"),
                format!("duplicate family; first declared at index {previous}"),
            ));
        }
        declared.insert(id.to_owned());
        if !expected.contains(id) {
            diagnostics.push(error(
                "EXTERNAL-ACCEPTANCE-FAMILY",
                format!("{path}.fixture_family_id"),
                format!("family {id:?} is not external in the active profile"),
            ));
            continue;
        }
        let Some(boundaries) = ids(family, "external_runtime_boundary_ids", &path, diagnostics)
        else {
            continue;
        };
        let mut unique_boundaries = BTreeSet::new();
        for boundary in &boundaries {
            if !unique_boundaries.insert(*boundary) {
                diagnostics.push(error(
                    "EXTERNAL-ACCEPTANCE-DUPLICATE",
                    format!("{path}.external_runtime_boundary_ids"),
                    format!("duplicate boundary ID {boundary:?}"),
                ));
            }
        }
        let actual = boundaries
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        let wanted = profile
            .fixture_boundaries
            .get(id)
            .cloned()
            .unwrap_or_default();
        if actual != wanted {
            diagnostics.push(error(
                "EXTERNAL-ACCEPTANCE-BOUNDARY",
                format!("{path}.external_runtime_boundary_ids"),
                format!("must exactly match profile boundaries {wanted:?}, found {actual:?}"),
            ));
        }
        let Some(paths) = array(family, "paths", &path, diagnostics) else {
            continue;
        };
        if paths.is_empty() {
            diagnostics.push(error(
                "EXTERNAL-ACCEPTANCE-PATH",
                format!("{path}.paths"),
                "each external family needs at least one implementation path",
            ));
        }
        check_paths(root, id, active, paths, diagnostics);
    }
    for id in expected.difference(&declared) {
        diagnostics.push(error(
            "EXTERNAL-ACCEPTANCE-FAMILY",
            "external-acceptance.json.families",
            format!("external profile family {id:?} has no declaration"),
        ));
    }
}

fn check_paths(
    root: &Path,
    family: &str,
    active: &ActiveProfile,
    paths: &[Value],
    diagnostics: &mut Diagnostics,
) {
    let mut seen = BTreeMap::new();
    for (index, value) in paths.iter().enumerate() {
        let path = format!("external-acceptance.json.{family}.paths[{index}]");
        let Some(path_object) = value.as_object() else {
            diagnostics.push(error(
                "EXTERNAL-ACCEPTANCE-SCHEMA",
                path,
                "path entry must be an object",
            ));
            continue;
        };
        let Some(path_id) = nonempty(path_object, "path_id", &path, diagnostics) else {
            continue;
        };
        if !logical_id(path_id) {
            diagnostics.push(error(
                "EXTERNAL-ACCEPTANCE-PATH",
                format!("{path}.path_id"),
                "path_id contains unsupported or unbounded characters",
            ));
        }
        if let Some(previous) = seen.insert(path_id.to_owned(), index) {
            diagnostics.push(error(
                "EXTERNAL-ACCEPTANCE-DUPLICATE",
                format!("{path}.path_id"),
                format!("duplicate path; first declared at index {previous}"),
            ));
        }
        let Some(identity) = object(path_object, "identity", &path, diagnostics) else {
            continue;
        };
        check_identity(identity, path_id, active, &path, diagnostics);
        let Some(cases) = array(path_object, "cases", &path, diagnostics) else {
            continue;
        };
        check_cases(root, family, path_id, identity, cases, &path, diagnostics);
    }
}

fn check_identity(
    identity: &Map<String, Value>,
    path_id: &str,
    active: &ActiveProfile,
    path: &str,
    diagnostics: &mut Diagnostics,
) {
    exact_string(identity, "path_id", path, path_id, diagnostics);
    nonzero_hex(identity, "capability_digest", path, SHA256_LEN, diagnostics);

    let Some(schema) = object(identity, "schema", path, diagnostics) else {
        return;
    };
    let Some(schema_id) = nonempty(schema, "id", &format!("{path}.schema"), diagnostics) else {
        return;
    };
    if !matches!(schema_id, "external-capability/1" | "jvm-capability/2") {
        diagnostics.push(error(
            "EXTERNAL-ACCEPTANCE-IDENTITY",
            format!("{path}.identity.schema.id"),
            "schema must be external-capability/1 or jvm-capability/2",
        ));
    }
    let expected_schema_version = match schema_id {
        "external-capability/1" => 1,
        "jvm-capability/2" => 2,
        _ => 0,
    };
    if expected_schema_version != 0 {
        exact_u64(
            identity,
            "schema_version",
            path,
            expected_schema_version,
            diagnostics,
        );
        exact_u64(
            schema,
            "version",
            &format!("{path}.schema"),
            expected_schema_version,
            diagnostics,
        );
    } else {
        positive_u64(identity, "schema_version", path, diagnostics);
        positive_u64(schema, "version", &format!("{path}.schema"), diagnostics);
    }

    let Some(adapter) = object(identity, "adapter", path, diagnostics) else {
        return;
    };
    let adapter_path = format!("{path}.identity.adapter");
    let Some(kind) = nonempty(adapter, "kind", &adapter_path, diagnostics) else {
        return;
    };
    if !ADAPTER_KINDS.contains(&kind) {
        diagnostics.push(error(
            "EXTERNAL-ACCEPTANCE-IDENTITY",
            format!("{adapter_path}.kind"),
            format!("adapter kind must be one of {ADAPTER_KINDS:?}"),
        ));
    }
    for field in ["id", "version"] {
        let _ = nonempty(adapter, field, &adapter_path, diagnostics);
    }
    nonzero_hex(
        adapter,
        "build_sha256",
        &adapter_path,
        SHA256_LEN,
        diagnostics,
    );

    let Some(profile_identity) = object(identity, "profile", path, diagnostics) else {
        return;
    };
    let profile_path = format!("{path}.identity.profile");
    exact_string(
        profile_identity,
        "id",
        &profile_path,
        &active.id,
        diagnostics,
    );
    exact_u64(
        profile_identity,
        "version",
        &profile_path,
        active.version,
        diagnostics,
    );
    exact_string(
        profile_identity,
        "sha256",
        &profile_path,
        &active.sha256,
        diagnostics,
    );

    let Some(oracle) = object(identity, "oracle", path, diagnostics) else {
        return;
    };
    let oracle_path = format!("{path}.identity.oracle");
    exact_string(
        oracle,
        "project",
        &oracle_path,
        &active.project,
        diagnostics,
    );
    exact_string(
        oracle,
        "version",
        &oracle_path,
        &active.oracle_version,
        diagnostics,
    );
    exact_string(
        oracle,
        "artifact",
        &oracle_path,
        &active.artifact,
        diagnostics,
    );
    exact_string(
        oracle,
        "artifact_url",
        &oracle_path,
        &active.artifact_url,
        diagnostics,
    );
    exact_string(
        oracle,
        "source_tree",
        &oracle_path,
        &active.source_tree,
        diagnostics,
    );
    exact_string(
        oracle,
        "digest_url",
        &oracle_path,
        &active.digest_url,
        diagnostics,
    );
    exact_string(
        oracle,
        "signature_url",
        &oracle_path,
        &active.signature_url,
        diagnostics,
    );
    exact_string(
        oracle,
        "keys_url",
        &oracle_path,
        &active.keys_url,
        diagnostics,
    );
    exact_string(
        oracle,
        "source_commit",
        &oracle_path,
        &active.source_commit,
        diagnostics,
    );
    exact_string(
        oracle,
        "artifact_sha512",
        &oracle_path,
        &active.artifact_sha512,
        diagnostics,
    );
    if active.signature_verified {
        if let Some(fingerprint) = active.signature_fingerprint.as_deref() {
            exact_string(
                oracle,
                "signature_fingerprint",
                &oracle_path,
                fingerprint,
                diagnostics,
            );
        } else {
            diagnostics.push(error(
                "EXTERNAL-ACCEPTANCE-IDENTITY",
                format!("{oracle_path}.signature_fingerprint"),
                "active profile has no accepted signing-key fingerprint",
            ));
        }
    }
    if oracle.get("signature_verified") != Some(&Value::Bool(true)) {
        diagnostics.push(error(
            "EXTERNAL-ACCEPTANCE-PROVENANCE",
            format!("{oracle_path}.signature_verified"),
            "exact execution identity requires signature_verified=true",
        ));
    }

    let Some(source_hashes) = object(identity, "source_hashes", path, diagnostics) else {
        return;
    };
    if source_hashes.is_empty() {
        diagnostics.push(error(
            "EXTERNAL-ACCEPTANCE-IDENTITY",
            format!("{path}.identity.source_hashes"),
            "at least one exact source hash is required",
        ));
    }
    for (name, value) in source_hashes {
        if value
            .as_str()
            .is_none_or(|value| !is_digest(value, SHA256_LEN))
        {
            diagnostics.push(error(
                "EXTERNAL-ACCEPTANCE-IDENTITY",
                format!("{path}.identity.source_hashes.{name}"),
                "source hash must be a nonzero lowercase SHA-256 value",
            ));
        }
    }

    let Some(artifacts) = array(identity, "artifacts", path, diagnostics) else {
        return;
    };
    if artifacts.is_empty() {
        diagnostics.push(error(
            "EXTERNAL-ACCEPTANCE-IDENTITY",
            format!("{path}.identity.artifacts"),
            "at least one helper/schema/provider/classpath artifact is required",
        ));
    }
    let mut artifact_roles = BTreeSet::new();
    let mut artifact_keys = BTreeSet::new();
    for (index, value) in artifacts.iter().enumerate() {
        let item_path = format!("{path}.identity.artifacts[{index}]");
        let Some(artifact) = value.as_object() else {
            diagnostics.push(error(
                "EXTERNAL-ACCEPTANCE-SCHEMA",
                item_path,
                "artifact identity must be an object",
            ));
            continue;
        };
        for field in ["role", "id", "version", "license", "provenance"] {
            let _ = nonempty(artifact, field, &item_path, diagnostics);
        }
        if let Some(role) = artifact.get("role").and_then(Value::as_str) {
            if !ARTIFACT_ROLES.contains(&role) {
                diagnostics.push(error(
                    "EXTERNAL-ACCEPTANCE-IDENTITY",
                    format!("{item_path}.role"),
                    format!("artifact role must be one of {ARTIFACT_ROLES:?}"),
                ));
            } else {
                artifact_roles.insert(role.to_owned());
            }
            let id = artifact.get("id").and_then(Value::as_str).unwrap_or("");
            if !artifact_keys.insert((role.to_owned(), id.to_owned())) {
                diagnostics.push(error(
                    "EXTERNAL-ACCEPTANCE-DUPLICATE",
                    format!("{item_path}.id"),
                    "artifact role and ID are duplicated",
                ));
            }
            if DEPENDENCY_ROLES.contains(&role) {
                for field in ["kind", "identity"] {
                    let _ = nonempty(artifact, field, &item_path, diagnostics);
                }
                if role == "service" {
                    let _ = nonempty(artifact, "endpoint", &item_path, diagnostics);
                }
            }
        }
        nonzero_hex(artifact, "sha256", &item_path, SHA256_LEN, diagnostics);
    }
    if !artifact_roles.contains("adapter") {
        diagnostics.push(error(
            "EXTERNAL-ACCEPTANCE-IDENTITY",
            format!("{path}.identity.artifacts"),
            "adapter artifact role is required",
        ));
    }
    if !artifact_roles.contains("schema") {
        diagnostics.push(error(
            "EXTERNAL-ACCEPTANCE-IDENTITY",
            format!("{path}.identity.artifacts"),
            "protocol schema artifact role is required",
        ));
    }
    if !artifact_roles
        .iter()
        .any(|role| DEPENDENCY_ROLES.contains(&role.as_str()))
    {
        diagnostics.push(error(
            "EXTERNAL-ACCEPTANCE-IDENTITY",
            format!("{path}.identity.artifacts"),
            "at least one exact service, driver, provider, or plugin identity is required",
        ));
    }

    let Some(policies) = object(identity, "policies", path, diagnostics) else {
        return;
    };
    let policy_path = format!("{path}.identity.policies");
    for field in ["network", "filesystem", "secret", "supervisor"] {
        let _ = nonempty(policies, field, &policy_path, diagnostics);
    }
    if policies
        .get("network")
        .and_then(Value::as_str)
        .is_some_and(|value| value.contains("public") || value.contains("ambient"))
    {
        diagnostics.push(error(
            "EXTERNAL-ACCEPTANCE-SECURITY",
            format!("{policy_path}.network"),
            "network policy cannot permit public or ambient access",
        ));
    }
    if policies
        .get("filesystem")
        .and_then(Value::as_str)
        .is_some_and(|value| {
            let value = value.to_ascii_lowercase();
            value.contains("ambient")
                || value.contains("unrestricted")
                || value.contains("public")
                || value == "any"
        })
    {
        diagnostics.push(error(
            "EXTERNAL-ACCEPTANCE-SECURITY",
            format!("{policy_path}.filesystem"),
            "filesystem policy cannot permit ambient, public, or unrestricted access",
        ));
    }
    if policies.get("secret").and_then(Value::as_str) != Some("protected-channel") {
        diagnostics.push(error(
            "EXTERNAL-ACCEPTANCE-SECURITY",
            format!("{policy_path}.secret"),
            "secret policy must use the protected-channel reference contract",
        ));
    }
    if policies.get("supervisor").and_then(Value::as_str) != Some("decision-0001") {
        diagnostics.push(error(
            "EXTERNAL-ACCEPTANCE-SECURITY",
            format!("{policy_path}.supervisor"),
            "external adapters must use the activated Decision 0001 supervisor",
        ));
    }

    let Some(concurrency) = object(identity, "concurrency", path, diagnostics) else {
        return;
    };
    let concurrency_path = format!("{path}.identity.concurrency");
    let Some(kind) = nonempty(concurrency, "kind", &concurrency_path, diagnostics) else {
        return;
    };
    if !CONCURRENCY_KINDS.contains(&kind) {
        diagnostics.push(error(
            "EXTERNAL-ACCEPTANCE-IDENTITY",
            format!("{concurrency_path}.kind"),
            format!("concurrency kind must be one of {CONCURRENCY_KINDS:?}"),
        ));
    }
    let Some(max_parallel) = unsigned(concurrency, "max_parallel", &concurrency_path, diagnostics)
    else {
        return;
    };
    if kind == "BoundedParallel" && max_parallel == 0 {
        diagnostics.push(error(
            "EXTERNAL-ACCEPTANCE-IDENTITY",
            format!("{concurrency_path}.max_parallel"),
            "BoundedParallel requires a nonzero max_parallel",
        ));
    }
    if kind != "BoundedParallel" && max_parallel != 1 {
        diagnostics.push(error(
            "EXTERNAL-ACCEPTANCE-IDENTITY",
            format!("{concurrency_path}.max_parallel"),
            "RunSerial and PerUserSerial must declare max_parallel=1",
        ));
    }

    let Some(lifecycle) = object(identity, "lifecycle", path, diagnostics) else {
        return;
    };
    let lifecycle_path = format!("{path}.identity.lifecycle");
    for field in ["setup", "sample", "teardown", "cancellation", "dispatch"] {
        let Some(value) = nonempty(lifecycle, field, &lifecycle_path, diagnostics) else {
            continue;
        };
        if is_placeholder(value) {
            diagnostics.push(error(
                "EXTERNAL-ACCEPTANCE-IDENTITY",
                format!("{lifecycle_path}.{field}"),
                "lifecycle boundary must be an explicit declared identity",
            ));
        }
    }
}

fn check_cases(
    root: &Path,
    family: &str,
    path_id: &str,
    identity: &Map<String, Value>,
    cases: &[Value],
    path: &str,
    diagnostics: &mut Diagnostics,
) {
    let expected_digest = identity
        .get("capability_digest")
        .and_then(Value::as_str)
        .unwrap_or("");
    let mut seen_ids = BTreeSet::new();
    let mut seen_categories = BTreeSet::new();
    for (index, value) in cases.iter().enumerate() {
        let case_path = format!("{path}.cases[{index}]");
        let Some(case) = value.as_object() else {
            diagnostics.push(error(
                "EXTERNAL-ACCEPTANCE-SCHEMA",
                case_path,
                "case declaration must be an object",
            ));
            continue;
        };
        let Some(category) = nonempty(case, "category", &case_path, diagnostics) else {
            continue;
        };
        seen_categories.insert(category.to_owned());
        if !REQUIRED_CATEGORIES.contains(&category) {
            diagnostics.push(error(
                "EXTERNAL-ACCEPTANCE-CASE",
                format!("{case_path}.category"),
                format!("unknown required-case category {category:?}"),
            ));
        }
        if let Some(id) = nonempty(case, "id", &case_path, diagnostics)
            && !seen_ids.insert(id.to_owned())
        {
            diagnostics.push(error(
                "EXTERNAL-ACCEPTANCE-DUPLICATE",
                format!("{case_path}.id"),
                "case ID is duplicated within the implementation path",
            ));
        }
        let Some(case_file) = safe_path(case, "case_path", &case_path, diagnostics) else {
            continue;
        };
        check_case_file(root, family, case_file, &case_path, diagnostics);
        let Some(raw_artifacts) = nonempty(case, "raw_artifacts", &case_path, diagnostics) else {
            continue;
        };
        if !safe_path_value(raw_artifacts) || !raw_artifacts.starts_with("oracle-runs/") {
            diagnostics.push(error(
                "EXTERNAL-ACCEPTANCE-ARTIFACT",
                format!("{case_path}.raw_artifacts"),
                "raw_artifacts must be an ignored oracle-runs/ location",
            ));
        }
        exact_string(
            case,
            "identity_digest",
            &case_path,
            expected_digest,
            diagnostics,
        );
        if case.get("observed") != Some(&Value::Bool(false)) {
            diagnostics.push(error(
                "EXTERNAL-ACCEPTANCE-EVIDENCE",
                format!("{case_path}.observed"),
                "static declarations must set observed=false",
            ));
        }
        let Some(status) = nonempty(case, "execution_status", &case_path, diagnostics) else {
            continue;
        };
        if !STATIC_STATUSES.contains(&status) {
            diagnostics.push(error(
                "EXTERNAL-ACCEPTANCE-EVIDENCE",
                format!("{case_path}.execution_status"),
                format!("status must be one of {STATIC_STATUSES:?}; observations are forbidden"),
            ));
        }
        expected_artifacts(case, &case_path, diagnostics);
    }
    for category in REQUIRED_CATEGORIES {
        if !seen_categories.contains(category) {
            diagnostics.push(error(
                "EXTERNAL-ACCEPTANCE-CASE",
                format!("{path}.cases"),
                format!("path {path_id:?} lacks category {category:?}"),
            ));
        }
    }
    if cases.len() != REQUIRED_CATEGORIES.len()
        || seen_categories.len() != REQUIRED_CATEGORIES.len()
    {
        diagnostics.push(error(
            "EXTERNAL-ACCEPTANCE-CASE",
            format!("{path}.cases"),
            format!(
                "must contain exactly {} unique required categories",
                REQUIRED_CATEGORIES.len()
            ),
        ));
    }
}

fn check_case_file(
    root: &Path,
    family: &str,
    case_file: &str,
    path: &str,
    diagnostics: &mut Diagnostics,
) {
    let file_path = root.join(case_file);
    let bytes = match regular_file(&file_path) {
        Ok(bytes) => bytes,
        Err(message) => {
            diagnostics.push(error(
                "EXTERNAL-ACCEPTANCE-CASE",
                format!("{path}.case_path"),
                format!("case manifest cannot be read: {message}"),
            ));
            return;
        }
    };
    let value = match serde_json::from_slice::<Value>(&bytes) {
        Ok(value) => value,
        Err(parse_error) => {
            diagnostics.push(error(
                "EXTERNAL-ACCEPTANCE-CASE",
                format!("{path}.case_path"),
                format!("case manifest is malformed: {parse_error}"),
            ));
            return;
        }
    };
    let Some(object) = value.as_object() else {
        diagnostics.push(error(
            "EXTERNAL-ACCEPTANCE-CASE",
            format!("{path}.case_path"),
            "case manifest must be an object",
        ));
        return;
    };
    let case_path = format!("{path}.case_path");
    let mut nodes = 0;
    check_limits(&value, &case_path, 0, &mut nodes, diagnostics);
    check_secret_keys(&value, &case_path, diagnostics);
    check_static_markers(&value, &case_path, diagnostics);
    check_process_fields(&value, &case_path, diagnostics);
    if object.get("fixture_family_id").and_then(Value::as_str) != Some(family) {
        diagnostics.push(error(
            "EXTERNAL-ACCEPTANCE-CASE",
            format!("{path}.case_path"),
            format!("case manifest belongs to a different family; expected {family:?}"),
        ));
    }
    if object.get("observed") == Some(&Value::Bool(true))
        || object.get("status").and_then(Value::as_str) == Some("observed")
    {
        diagnostics.push(error(
            "EXTERNAL-ACCEPTANCE-EVIDENCE",
            format!("{path}.case_path"),
            "observed case manifests cannot be accepted by this static check",
        ));
    }
    if object
        .get("execution")
        .and_then(Value::as_object)
        .and_then(|execution| execution.get("status"))
        .and_then(Value::as_str)
        == Some("observed")
    {
        diagnostics.push(error(
            "EXTERNAL-ACCEPTANCE-EVIDENCE",
            format!("{path}.case_path"),
            "observed case manifests cannot be accepted by this static check",
        ));
    }
}

fn expected_artifacts(case: &Map<String, Value>, path: &str, diagnostics: &mut Diagnostics) {
    let Some(artifacts) = array(case, "expected_artifacts", path, diagnostics) else {
        return;
    };
    if artifacts.is_empty() {
        diagnostics.push(error(
            "EXTERNAL-ACCEPTANCE-ARTIFACT",
            format!("{path}.expected_artifacts"),
            "at least one expected artifact is required",
        ));
    }
    for (index, value) in artifacts.iter().enumerate() {
        let item_path = format!("{path}.expected_artifacts[{index}]");
        let Some(artifact) = value.as_object() else {
            diagnostics.push(error(
                "EXTERNAL-ACCEPTANCE-SCHEMA",
                item_path,
                "expected artifact must be an object",
            ));
            continue;
        };
        if let Some(location) = nonempty(artifact, "path", &item_path, diagnostics)
            && (!safe_path_value(location) || !location.starts_with("oracle-runs/"))
        {
            diagnostics.push(error(
                "EXTERNAL-ACCEPTANCE-ARTIFACT",
                format!("{item_path}.path"),
                "expected artifact path must be an ignored oracle-runs/ location",
            ));
        }
        nonzero_hex(artifact, "sha256", &item_path, SHA256_LEN, diagnostics);
    }
}

fn read_json(root: &Path, path: &Path, diagnostics: &mut Diagnostics) -> Option<Value> {
    let display = display_path(root, path);
    let bytes = match regular_file(path) {
        Ok(bytes) => bytes,
        Err(message) => {
            diagnostics.push(error(
                "EXTERNAL-ACCEPTANCE-MANIFEST",
                display,
                format!("cannot read manifest: {message}"),
            ));
            return None;
        }
    };
    match serde_json::from_slice::<Value>(&bytes) {
        Ok(value) => Some(value),
        Err(parse_error) => {
            diagnostics.push(error(
                "EXTERNAL-ACCEPTANCE-JSON",
                display,
                format!("invalid JSON: {parse_error}"),
            ));
            None
        }
    }
}

fn regular_file(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() {
        return Err("symlink input is not allowed".to_owned());
    }
    if !metadata.is_file() {
        return Err("input is not a regular file".to_owned());
    }
    if metadata.len() > MAX_INPUT_BYTES {
        return Err(format!("input exceeds {MAX_INPUT_BYTES} bytes"));
    }
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(format!("input grew beyond {MAX_INPUT_BYTES} bytes"));
    }
    Ok(bytes)
}

fn array<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    path: &str,
    diagnostics: &mut Diagnostics,
) -> Option<&'a Vec<Value>> {
    match object.get(field).and_then(Value::as_array) {
        Some(value) => Some(value),
        None => {
            diagnostics.push(error(
                "EXTERNAL-ACCEPTANCE-SCHEMA",
                format!("{path}.{field}"),
                "required array is missing or has the wrong type",
            ));
            None
        }
    }
}

fn object<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    path: &str,
    diagnostics: &mut Diagnostics,
) -> Option<&'a Map<String, Value>> {
    match object.get(field).and_then(Value::as_object) {
        Some(value) => Some(value),
        None => {
            diagnostics.push(error(
                "EXTERNAL-ACCEPTANCE-SCHEMA",
                format!("{path}.{field}"),
                "required object is missing or has the wrong type",
            ));
            None
        }
    }
}

fn nonempty<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    path: &str,
    diagnostics: &mut Diagnostics,
) -> Option<&'a str> {
    match object.get(field).and_then(Value::as_str) {
        Some(value) if !value.is_empty() => Some(value),
        Some(_) => {
            diagnostics.push(error(
                "EXTERNAL-ACCEPTANCE-SCHEMA",
                format!("{path}.{field}"),
                "required string must not be empty",
            ));
            None
        }
        None => {
            diagnostics.push(error(
                "EXTERNAL-ACCEPTANCE-SCHEMA",
                format!("{path}.{field}"),
                "required non-empty string is missing",
            ));
            None
        }
    }
}

fn ids<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    path: &str,
    diagnostics: &mut Diagnostics,
) -> Option<Vec<&'a str>> {
    let values = array(object, field, path, diagnostics)?;
    let mut result = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        match value.as_str() {
            Some(value) if !value.is_empty() => result.push(value),
            _ => diagnostics.push(error(
                "EXTERNAL-ACCEPTANCE-SCHEMA",
                format!("{path}.{field}[{index}]"),
                "identifier must be a non-empty string",
            )),
        }
    }
    Some(result)
}

fn unsigned(
    object: &Map<String, Value>,
    field: &str,
    path: &str,
    diagnostics: &mut Diagnostics,
) -> Option<u64> {
    match object.get(field).and_then(Value::as_u64) {
        Some(value) => Some(value),
        None => {
            diagnostics.push(error(
                "EXTERNAL-ACCEPTANCE-SCHEMA",
                format!("{path}.{field}"),
                "required unsigned integer is missing",
            ));
            None
        }
    }
}

fn safe_path<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    path: &str,
    diagnostics: &mut Diagnostics,
) -> Option<&'a str> {
    let value = nonempty(object, field, path, diagnostics)?;
    if !safe_path_value(value) {
        diagnostics.push(error(
            "EXTERNAL-ACCEPTANCE-PATH",
            format!("{path}.{field}"),
            "path must be repository-relative without traversal or backslashes",
        ));
        return None;
    }
    Some(value)
}

fn safe_path_value(value: &str) -> bool {
    if value.is_empty() || value.contains('\0') || value.contains('\\') {
        return false;
    }
    let path = Path::new(value);
    !path.is_absolute()
        && !path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::RootDir
            )
        })
}

fn logical_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.contains("..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'/' | b'_' | b'-'))
}

fn exact_string(
    object: &Map<String, Value>,
    field: &str,
    path: &str,
    expected: &str,
    diagnostics: &mut Diagnostics,
) {
    match object.get(field).and_then(Value::as_str) {
        Some(value) if value == expected => {}
        Some(value) => diagnostics.push(error(
            "EXTERNAL-ACCEPTANCE-IDENTITY",
            format!("{path}.{field}"),
            format!("must equal {expected:?}, found {value:?}"),
        )),
        None => diagnostics.push(error(
            "EXTERNAL-ACCEPTANCE-SCHEMA",
            format!("{path}.{field}"),
            "required exact string is missing",
        )),
    }
}

fn exact_u64(
    object: &Map<String, Value>,
    field: &str,
    path: &str,
    expected: u64,
    diagnostics: &mut Diagnostics,
) {
    match object.get(field).and_then(Value::as_u64) {
        Some(value) if value == expected => {}
        Some(value) => diagnostics.push(error(
            "EXTERNAL-ACCEPTANCE-SCHEMA",
            format!("{path}.{field}"),
            format!("must equal {expected}, found {value}"),
        )),
        None => diagnostics.push(error(
            "EXTERNAL-ACCEPTANCE-SCHEMA",
            format!("{path}.{field}"),
            "required exact unsigned integer is missing",
        )),
    }
}

fn positive_u64(
    object: &Map<String, Value>,
    field: &str,
    path: &str,
    diagnostics: &mut Diagnostics,
) {
    if unsigned(object, field, path, diagnostics) == Some(0) {
        diagnostics.push(error(
            "EXTERNAL-ACCEPTANCE-SCHEMA",
            format!("{path}.{field}"),
            "value must be positive",
        ));
    }
}

fn nonzero_hex(
    object: &Map<String, Value>,
    field: &str,
    path: &str,
    length: usize,
    diagnostics: &mut Diagnostics,
) {
    let Some(value) = nonempty(object, field, path, diagnostics) else {
        return;
    };
    if !is_digest(value, length) {
        diagnostics.push(error(
            "EXTERNAL-ACCEPTANCE-IDENTITY",
            format!("{path}.{field}"),
            format!("must be a nonzero lowercase {length}-character hexadecimal digest"),
        ));
    }
}

fn is_digest(value: &str, length: usize) -> bool {
    value.len() == length
        && !value.bytes().all(|byte| byte == b'0')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn is_fingerprint(value: &str) -> bool {
    value.len() == 40
        && !value.bytes().all(|byte| byte == b'0')
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn check_limits(
    value: &Value,
    path: &str,
    depth: usize,
    nodes: &mut usize,
    diagnostics: &mut Diagnostics,
) {
    *nodes = nodes.saturating_add(1);
    if *nodes > MAX_NODES {
        diagnostics.push(error(
            "EXTERNAL-ACCEPTANCE-BOUNDS",
            path,
            format!("JSON node count exceeds {MAX_NODES}"),
        ));
        return;
    }
    if depth > MAX_DEPTH {
        diagnostics.push(error(
            "EXTERNAL-ACCEPTANCE-BOUNDS",
            path,
            format!("JSON depth exceeds {MAX_DEPTH}"),
        ));
        return;
    }
    match value {
        Value::Object(object) => {
            for (field, value) in object {
                check_limits(
                    value,
                    &format!("{path}.{field}"),
                    depth + 1,
                    nodes,
                    diagnostics,
                );
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                check_limits(
                    value,
                    &format!("{path}[{index}]"),
                    depth + 1,
                    nodes,
                    diagnostics,
                );
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn check_secret_keys(value: &Value, path: &str, diagnostics: &mut Diagnostics) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                if SECRET_KEYS.contains(&key.to_ascii_lowercase().as_str()) {
                    diagnostics.push(error(
                        "EXTERNAL-ACCEPTANCE-SECURITY",
                        format!("{path}.{key}"),
                        "secret-bearing values are forbidden; use an opaque protected reference",
                    ));
                }
                check_secret_keys(value, &format!("{path}.{key}"), diagnostics);
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                check_secret_keys(value, &format!("{path}[{index}]"), diagnostics);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

/// Static declarations may describe an unavailable or planned run, but they
/// must never carry a successful observation marker.  Apply this recursively
/// to referenced case descriptors as well as to the top-level manifest.
fn check_static_markers(value: &Value, path: &str, diagnostics: &mut Diagnostics) {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                let key_lower = key.to_ascii_lowercase();
                let child_path = format!("{path}.{key}");
                if FORBIDDEN_STATIC_MARKERS.contains(&key_lower.as_str()) {
                    let forbidden = match child {
                        Value::Bool(true) => true,
                        Value::String(value) => matches!(
                            value.to_ascii_lowercase().as_str(),
                            "observed" | "verified" | "eligible" | "materialized" | "completed"
                        ),
                        _ => false,
                    };
                    if forbidden {
                        diagnostics.push(error(
                            "EXTERNAL-ACCEPTANCE-EVIDENCE",
                            child_path.clone(),
                            "static declarations cannot contain observed, verified, eligible, or materialized evidence",
                        ));
                    }
                }
                check_static_markers(child, &child_path, diagnostics);
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                check_static_markers(child, &format!("{path}[{index}]"), diagnostics);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

/// Raw process handles, shell text, and argument vectors are not manifest
/// identities.  Rejecting them keeps future runners on the typed Decision
/// 0001 supervisor path instead of allowing an adapter-local escape hatch.
fn check_process_fields(value: &Value, path: &str, diagnostics: &mut Diagnostics) {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                let key_lower = key.to_ascii_lowercase();
                let child_path = format!("{path}.{key}");
                if FORBIDDEN_PROCESS_FIELDS.contains(&key_lower.as_str()) {
                    diagnostics.push(error(
                        "EXTERNAL-ACCEPTANCE-SECURITY",
                        child_path.clone(),
                        "raw process/command fields are forbidden; use the typed Decision 0001 supervisor policy",
                    ));
                }
                check_process_fields(child, &child_path, diagnostics);
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                check_process_fields(child, &format!("{path}[{index}]"), diagnostics);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn is_placeholder(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "unknown" | "unspecified" | "unavailable" | "not-pinned" | "not-provisioned" | "null"
    )
}

fn error(code: &str, path: impl Into<String>, message: impl Into<String>) -> Diagnostic {
    Diagnostic::new(code, path, message)
}

#[cfg(test)]
mod tests {
    use super::{check, digest};
    use crate::profile::{ProfileIndex, UpstreamPin};
    use serde_json::{Value, json};
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT: AtomicUsize = AtomicUsize::new(0);

    struct TempTree(std::path::PathBuf);

    impl TempTree {
        fn new() -> Option<Self> {
            let root = std::env::temp_dir().join(format!(
                "jmeter-rs-xtask-external-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&root).ok()?;
            Some(Self(root))
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn index() -> ProfileIndex {
        ProfileIndex {
            profile_id: "test-profile".to_owned(),
            fixture_statuses: BTreeMap::from([("FX-EXT-001".to_owned(), "external".to_owned())]),
            fixture_boundaries: BTreeMap::from([(
                "FX-EXT-001".to_owned(),
                BTreeSet::from(["EXT-SERVICE-001".to_owned()]),
            )]),
            upstream: UpstreamPin {
                project: "Apache JMeter".to_owned(),
                version: "5.6.3".to_owned(),
                source_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
                artifact: "apache-jmeter-5.6.3.zip".to_owned(),
                digest: "aabbccdd00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb".to_owned(),
                ..UpstreamPin::default()
            },
            ..ProfileIndex::default()
        }
    }

    fn profile() -> Value {
        json!({
            "profile_id": "test-profile",
            "profile_version": 7,
            "upstream": {
                "project": "Apache JMeter",
                "version": "5.6.3",
                "source_commit": "0123456789abcdef0123456789abcdef01234567",
                "source_tree": "https://example.invalid/jmeter/tree/0123456789abcdef0123456789abcdef01234567",
                "artifact": {
                    "filename": "apache-jmeter-5.6.3.zip",
                    "url": "https://example.invalid/jmeter/apache-jmeter-5.6.3.zip",
                    "digest_url": "https://example.invalid/jmeter/apache-jmeter-5.6.3.zip.sha512",
                    "signature_url": "https://example.invalid/jmeter/apache-jmeter-5.6.3.zip.asc",
                    "keys_url": "https://example.invalid/jmeter/KEYS",
                    "digest": "aabbccdd00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb",
                    "verification": {
                        "signature_verified": true,
                        "signature_fingerprint": "C4923F9ABFB2F1A06F08E88BAC214CAA0612B399"
                    }
                }
            }
        })
    }

    fn manifest(profile_sha256: &str) -> Value {
        let digest = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";
        let categories = [
            "positive",
            "unavailable",
            "wrong-identity",
            "timeout",
            "cancellation",
            "crash",
            "malformed-oversized",
            "redaction",
            "no-fallback",
            "setup-teardown",
            "terminal-accounting",
        ];
        let cases = categories.into_iter().enumerate().map(|(index, category)| {
            json!({
                "id": format!("case-{index}"),
                "category": category,
                "case_path": "cases/case.json",
                "raw_artifacts": format!("oracle-runs/demo/{category}/"),
                "identity_digest": digest,
                "observed": false,
                "execution_status": "unavailable",
                "expected_artifacts": [{"path": format!("oracle-runs/demo/{category}/expected.json"), "sha256": digest}]
            })
        }).collect::<Vec<_>>();
        json!({
            "schema_id": "jmeter-rs.external-acceptance",
            "schema_version": 2,
            "decision": "0007-rev2",
            "profile_id": "test-profile",
            "profile_version": 7,
            "profile_path": "profile.json",
            "profile_sha256": profile_sha256,
            "families": [{
                "fixture_family_id": "FX-EXT-001",
                "external_runtime_boundary_ids": ["EXT-SERVICE-001"],
                "paths": [{
                    "path_id": "native.demo/1",
                    "identity": {
                        "path_id": "native.demo/1",
                        "schema_version": 1,
                        "capability_digest": digest,
                        "schema": {"id": "external-capability/1", "version": 1},
                        "adapter": {"kind": "native", "id": "demo", "version": "1", "build_sha256": digest},
                        "profile": {"id": "test-profile", "version": 7, "sha256": profile_sha256},
                        "oracle": {
                            "project": "Apache JMeter",
                            "version": "5.6.3",
                            "artifact": "apache-jmeter-5.6.3.zip",
                            "artifact_url": "https://example.invalid/jmeter/apache-jmeter-5.6.3.zip",
                            "source_tree": "https://example.invalid/jmeter/tree/0123456789abcdef0123456789abcdef01234567",
                            "digest_url": "https://example.invalid/jmeter/apache-jmeter-5.6.3.zip.sha512",
                            "signature_url": "https://example.invalid/jmeter/apache-jmeter-5.6.3.zip.asc",
                            "keys_url": "https://example.invalid/jmeter/KEYS",
                            "source_commit": "0123456789abcdef0123456789abcdef01234567",
                            "artifact_sha512": "aabbccdd00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb",
                            "signature_fingerprint": "C4923F9ABFB2F1A06F08E88BAC214CAA0612B399",
                            "signature_verified": true
                        },
                        "source_hashes": {"source": digest},
                        "artifacts": [
                            {"role": "adapter", "id": "demo", "version": "1", "sha256": digest, "license": "Apache-2.0", "provenance": "source"},
                            {"role": "schema", "id": "external-capability/1", "version": "1", "sha256": digest, "license": "Apache-2.0", "provenance": "source"},
                            {"role": "service", "id": "demo-service", "version": "1", "kind": "loopback-fixture", "endpoint": "endpoint://demo-service", "identity": "service://demo-service/1", "sha256": digest, "license": "Apache-2.0", "provenance": "source"}
                        ],
                        "policies": {"network": "loopback-only", "filesystem": "allowlisted", "secret": "protected-channel", "supervisor": "decision-0001"},
                        "concurrency": {"kind": "RunSerial", "max_parallel": 1},
                        "lifecycle": {"setup": "run-setup/1", "sample": "sample-dispatch/1", "teardown": "run-teardown/1", "cancellation": "cancel-after-dispatch/1", "dispatch": "adapter-boundary/1"}
                    },
                    "cases": cases
                }]
            }]
        })
    }

    fn tree_with_manifest() -> Option<(TempTree, std::path::PathBuf, std::path::PathBuf, String)> {
        let tree = TempTree::new()?;
        let profile_path = tree.0.join("profile.json");
        let profile_bytes = serde_json::to_vec(&profile()).ok()?;
        let profile_sha256 = digest(&profile_bytes);
        fs::write(&profile_path, profile_bytes).ok()?;
        fs::create_dir_all(tree.0.join("cases")).ok()?;
        fs::write(
            tree.0.join("cases/case.json"),
            br#"{"fixture_family_id":"FX-EXT-001","execution":{"status":"unavailable"}}"#,
        )
        .ok()?;
        let manifest_path = tree.0.join("external-acceptance.json");
        Some((tree, profile_path, manifest_path, profile_sha256))
    }

    #[test]
    fn complete_manifest_is_accepted_as_static_declaration() {
        let Some((_tree, profile_path, manifest_path, profile_sha256)) = tree_with_manifest()
        else {
            return;
        };
        let manifest = manifest(&profile_sha256);
        assert!(
            fs::write(
                &manifest_path,
                serde_json::to_vec(&manifest).unwrap_or_default()
            )
            .is_ok()
        );
        let diagnostics = check(
            manifest_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new(".")),
            &manifest_path,
            &profile_path,
            &index(),
        );
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
    }

    #[test]
    fn missing_required_category_fails_closed() {
        let Some((_tree, profile_path, manifest_path, profile_sha256)) = tree_with_manifest()
        else {
            return;
        };
        let mut value = manifest(&profile_sha256);
        let Some(cases) = value["families"][0]["paths"][0]["cases"].as_array_mut() else {
            return;
        };
        let _ = cases.pop();
        assert!(
            fs::write(
                &manifest_path,
                serde_json::to_vec(&value).unwrap_or_default()
            )
            .is_ok()
        );
        let diagnostics = check(
            manifest_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new(".")),
            &manifest_path,
            &profile_path,
            &index(),
        );
        assert!(
            diagnostics
                .iter()
                .any(|item| item.code == "EXTERNAL-ACCEPTANCE-CASE")
        );
    }

    #[test]
    fn observed_case_fails_closed() {
        let Some((_tree, profile_path, manifest_path, profile_sha256)) = tree_with_manifest()
        else {
            return;
        };
        let mut value = manifest(&profile_sha256);
        value["families"][0]["paths"][0]["cases"][0]["observed"] = Value::Bool(true);
        assert!(
            fs::write(
                &manifest_path,
                serde_json::to_vec(&value).unwrap_or_default()
            )
            .is_ok()
        );
        let diagnostics = check(
            manifest_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new(".")),
            &manifest_path,
            &profile_path,
            &index(),
        );
        assert!(
            diagnostics
                .iter()
                .any(|item| item.code == "EXTERNAL-ACCEPTANCE-EVIDENCE")
        );
    }

    #[test]
    fn secrets_and_non_oracle_artifacts_fail_closed() {
        let Some((_tree, profile_path, manifest_path, profile_sha256)) = tree_with_manifest()
        else {
            return;
        };
        let mut value = manifest(&profile_sha256);
        value["password"] = Value::String("must-not-be-present".to_owned());
        value["families"][0]["paths"][0]["cases"][0]["expected_artifacts"][0]["path"] =
            Value::String("fixtures/claimed-observation.json".to_owned());
        assert!(
            fs::write(
                &manifest_path,
                serde_json::to_vec(&value).unwrap_or_default()
            )
            .is_ok()
        );
        let diagnostics = check(
            manifest_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new(".")),
            &manifest_path,
            &profile_path,
            &index(),
        );
        assert!(
            diagnostics
                .iter()
                .any(|item| item.code == "EXTERNAL-ACCEPTANCE-SECURITY")
        );
        assert!(
            diagnostics
                .iter()
                .any(|item| item.code == "EXTERNAL-ACCEPTANCE-ARTIFACT")
        );
    }

    #[test]
    fn nested_evidence_and_raw_process_fields_fail_closed() {
        let Some((_tree, profile_path, manifest_path, profile_sha256)) = tree_with_manifest()
        else {
            return;
        };
        let mut value = manifest(&profile_sha256);
        value["runner"] = json!({"command": "must-not-be-a-manifest-field"});
        assert!(
            fs::write(
                manifest_path.parent().unwrap_or_else(|| std::path::Path::new("."))
                    .join("cases/case.json"),
                br#"{"fixture_family_id":"FX-EXT-001","execution":{"status":"unavailable","observed_run":true}}"#,
            )
            .is_ok()
        );
        assert!(
            fs::write(
                &manifest_path,
                serde_json::to_vec(&value).unwrap_or_default()
            )
            .is_ok()
        );
        let diagnostics = check(
            manifest_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new(".")),
            &manifest_path,
            &profile_path,
            &index(),
        );
        assert!(
            diagnostics
                .iter()
                .any(|item| item.code == "EXTERNAL-ACCEPTANCE-EVIDENCE")
        );
        assert!(
            diagnostics
                .iter()
                .any(|item| item.code == "EXTERNAL-ACCEPTANCE-SECURITY")
        );
    }

    #[test]
    fn protected_secret_and_supervisor_policies_are_required() {
        let Some((_tree, profile_path, manifest_path, profile_sha256)) = tree_with_manifest()
        else {
            return;
        };
        let mut value = manifest(&profile_sha256);
        value["families"][0]["paths"][0]["identity"]["policies"]["secret"] =
            Value::String("environment".to_owned());
        value["families"][0]["paths"][0]["identity"]["policies"]["supervisor"] =
            Value::String("direct-child".to_owned());
        assert!(
            fs::write(
                &manifest_path,
                serde_json::to_vec(&value).unwrap_or_default()
            )
            .is_ok()
        );
        let diagnostics = check(
            manifest_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new(".")),
            &manifest_path,
            &profile_path,
            &index(),
        );
        assert_eq!(
            diagnostics
                .iter()
                .filter(|item| item.code == "EXTERNAL-ACCEPTANCE-SECURITY")
                .count(),
            2
        );
    }

    #[test]
    fn dependency_identity_and_lifecycle_boundaries_are_required() {
        let Some((_tree, profile_path, manifest_path, profile_sha256)) = tree_with_manifest()
        else {
            return;
        };
        let mut value = manifest(&profile_sha256);
        let identity = &mut value["families"][0]["paths"][0]["identity"];
        let Some(artifacts) = identity["artifacts"].as_array_mut() else {
            return;
        };
        let Some(service) = artifacts
            .iter_mut()
            .find(|artifact| artifact.get("role").and_then(Value::as_str) == Some("service"))
        else {
            return;
        };
        let _ = service
            .as_object_mut()
            .and_then(|object| object.remove("endpoint"));
        let _ = identity["lifecycle"]
            .as_object_mut()
            .and_then(|object| object.remove("dispatch"));
        assert!(
            fs::write(
                &manifest_path,
                serde_json::to_vec(&value).unwrap_or_default()
            )
            .is_ok()
        );
        let diagnostics = check(
            manifest_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new(".")),
            &manifest_path,
            &profile_path,
            &index(),
        );
        assert!(
            diagnostics
                .iter()
                .any(|item| item.code == "EXTERNAL-ACCEPTANCE-IDENTITY")
        );
        assert!(
            diagnostics
                .iter()
                .any(|item| item.code == "EXTERNAL-ACCEPTANCE-SCHEMA")
        );
    }
}
