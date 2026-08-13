// SPDX-License-Identifier: Apache-2.0
//! Oracle fixture manifest, provenance, path, and hash validation.

use crate::diagnostics::{Diagnostic, Diagnostics};
use crate::profile::{ProfileIndex, display_path, is_feature_id};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;

const CASE_SCHEMA_ID: &str = "jmeter-rs.oracle-case";
const PROVENANCE_SCHEMA_ID: &str = "jmeter-rs.fixture-provenance";
const EXPECTATION_SCHEMA_ID: &str = "jmeter-rs.semantic-expectation";
const SCHEMA_VERSION: u64 = 1;
const CUSTOM_EXPECTATION_SCHEMAS: [&str; 28] = [
    "jmeter-rs.cli-option-catalog",
    "jmeter-rs.cli-process-contract",
    "jmeter-rs.cli-runner-contract",
    "jmeter-rs.cli-scenario-descriptors",
    "jmeter-rs.configuration-projection",
    "jmeter-rs.fixture-bounds",
    "jmeter-rs.file-artifact-contract",
    "jmeter-rs.fuzz-artifact",
    "jmeter-rs.fuzz-campaign-evidence",
    "jmeter-rs.fuzz-campaign-evidence-schema",
    "jmeter-rs.fuzz-campaign-expectation",
    "jmeter-rs.gui-filesystem-descriptor",
    "jmeter-rs.gui-persistence-expectation",
    "jmeter-rs.gui-platform-expectation",
    "jmeter-rs.gui-platform-matrix",
    "jmeter-rs.harness-evidence",
    "jmeter-rs.harness-evidence-schema",
    "jmeter-rs.harness-manifest",
    "jmeter-rs.harness-manifest-schema",
    "jmeter-rs.harness-normalized-diff",
    "jmeter-rs.http-sampler-ready",
    "jmeter-rs.http-trace",
    "jmeter-rs.planned-constraint-contract",
    "jmeter-rs.proxy-mirror-api-expectation",
    "jmeter-rs.proxy-mirror-expectation",
    "jmeter-rs.proxy-mirror-inputs",
    "jmeter-rs.proxy-recorder-ready",
    "jmeter-rs.proxy-tls-ready",
];
const MAX_DECLARED_BOUND: u64 = 1_073_741_824;

// These are deliberately conservative: a fixture may contain small source
// inputs and structured expectations, but raw oracle output, archives, keys,
// and credential-bearing material must stay in ignored CI artifacts.
const UNSAFE_EXTENSIONS: [&str; 32] = [
    "7z",
    "asc",
    "bin",
    "cer",
    "crt",
    "der",
    "gz",
    "jar",
    "jks",
    "jtl",
    "key",
    "log",
    "p12",
    "pfx",
    "pem",
    "pcap",
    "raw",
    "secret",
    "sha512",
    "sqlite",
    "tar",
    "token",
    "zip",
    "env",
    "private",
    "credentials",
    "pyc",
    "class",
    "so",
    "dylib",
    "dll",
    "exe",
];
const MAX_FIXTURE_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_FIXTURE_DIRECTORY_DEPTH: usize = 64;
const MAX_FIXTURE_TREE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_JSON_DEPTH: usize = 64;
const MAX_JSON_NODES: usize = 200_000;
const FIXTURE_READ_CHUNK_BYTES: usize = 16 * 1024;

#[derive(Debug)]
enum FixtureReadError {
    Open(io::Error),
    HandleMetadata(io::Error),
    PathMetadata(io::Error),
    Read(io::Error),
    NonRegular,
    Symlink,
    Changed,
    TooLarge { limit: u64 },
    Grew { limit: u64 },
    Truncated,
    InvalidLimit,
}

fn read_bounded_file(path: &Path, maximum: u64) -> Result<Vec<u8>, FixtureReadError> {
    let (file, metadata) = open_fixture_file(path, maximum)?;
    read_bounded_handle(file, path, &metadata, maximum)
}

fn open_fixture_file(path: &Path, maximum: u64) -> Result<(File, Metadata), FixtureReadError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    options.custom_flags(O_NOFOLLOW | O_NONBLOCK);
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) => {
            if matches!(
                reject_fixture_symlink_components(path),
                Err(FixtureReadError::Symlink)
            ) {
                return Err(FixtureReadError::Symlink);
            }
            if let Ok(metadata) = fs::symlink_metadata(path) {
                if metadata.file_type().is_symlink() {
                    return Err(FixtureReadError::Symlink);
                }
                if !metadata.is_file() {
                    return Err(FixtureReadError::NonRegular);
                }
            }
            return Err(FixtureReadError::Open(error));
        }
    };
    let metadata = file.metadata().map_err(FixtureReadError::HandleMetadata)?;
    validate_fixture_file_binding(path, &metadata, maximum)?;
    Ok((file, metadata))
}

fn validate_fixture_file_binding(
    path: &Path,
    handle_metadata: &Metadata,
    maximum: u64,
) -> Result<(), FixtureReadError> {
    if !handle_metadata.is_file() {
        return Err(FixtureReadError::NonRegular);
    }
    reject_fixture_symlink_components(path)?;
    let path_metadata = fs::symlink_metadata(path).map_err(FixtureReadError::PathMetadata)?;
    if path_metadata.file_type().is_symlink() {
        return Err(FixtureReadError::Symlink);
    }
    if !path_metadata.is_file() {
        return Err(FixtureReadError::NonRegular);
    }
    if !same_file_identity(handle_metadata, &path_metadata) {
        return Err(FixtureReadError::Changed);
    }
    if handle_metadata.len() != path_metadata.len() {
        if path_metadata.len() > maximum {
            return Err(FixtureReadError::Grew { limit: maximum });
        }
        return Err(FixtureReadError::Changed);
    }
    Ok(())
}

fn reject_fixture_symlink_components(path: &Path) -> Result<(), FixtureReadError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current).map_err(FixtureReadError::PathMetadata)?;
        if metadata.file_type().is_symlink() {
            return Err(FixtureReadError::Symlink);
        }
    }
    Ok(())
}

fn read_bounded_handle(
    mut file: File,
    path: &Path,
    initial_metadata: &Metadata,
    maximum: u64,
) -> Result<Vec<u8>, FixtureReadError> {
    if initial_metadata.len() > maximum {
        return Err(FixtureReadError::TooLarge { limit: maximum });
    }
    let maximum_plus_one = maximum
        .checked_add(1)
        .ok_or(FixtureReadError::InvalidLimit)?;
    let capacity = usize::try_from(maximum_plus_one).map_err(|_| FixtureReadError::InvalidLimit)?;
    let mut bytes = Vec::with_capacity(capacity);
    let mut chunk = [0_u8; FIXTURE_READ_CHUNK_BYTES];
    loop {
        if bytes.len() == capacity {
            break;
        }
        let read_length = (capacity - bytes.len()).min(chunk.len());
        let count = file
            .read(&mut chunk[..read_length])
            .map_err(FixtureReadError::Read)?;
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    let byte_count = u64::try_from(bytes.len()).map_err(|_| FixtureReadError::InvalidLimit)?;
    if byte_count > maximum {
        return Err(FixtureReadError::Grew { limit: maximum });
    }

    let final_metadata = file.metadata().map_err(FixtureReadError::HandleMetadata)?;
    if final_metadata.len() > maximum {
        return Err(FixtureReadError::Grew { limit: maximum });
    }
    validate_fixture_file_binding(path, &final_metadata, maximum)?;
    if final_metadata.len() < initial_metadata.len() || byte_count < initial_metadata.len() {
        return Err(FixtureReadError::Truncated);
    }
    if final_metadata.len() > initial_metadata.len() || byte_count > initial_metadata.len() {
        return Err(FixtureReadError::Changed);
    }
    Ok(bytes)
}

fn push_fixture_read_diagnostic(
    diagnostics: &mut Diagnostics,
    path: &str,
    subject: &str,
    error: FixtureReadError,
    read_error_code: &str,
) {
    let (code, message) = match error {
        FixtureReadError::Symlink | FixtureReadError::NonRegular => (
            "FIXTURE-PATH",
            format!("{subject} must be a regular non-symlink file"),
        ),
        FixtureReadError::TooLarge { limit } => (
            "FIXTURE-BOUNDS",
            format!("{subject} exceeds {limit}-byte validator bound"),
        ),
        FixtureReadError::Grew { limit } => (
            "FIXTURE-BOUNDS",
            format!("{subject} grew beyond {limit}-byte validator bound while reading"),
        ),
        FixtureReadError::Changed => (
            "FIXTURE-IO",
            format!("cannot read {subject}: file changed while opening or reading"),
        ),
        FixtureReadError::Truncated => (
            "FIXTURE-IO",
            format!("cannot read {subject}: file was truncated while reading"),
        ),
        FixtureReadError::InvalidLimit => (
            "FIXTURE-BOUNDS",
            format!("{subject} validator bound cannot be represented on this platform"),
        ),
        FixtureReadError::Open(error)
        | FixtureReadError::HandleMetadata(error)
        | FixtureReadError::PathMetadata(error) => {
            ("FIXTURE-IO", format!("cannot read {subject}: {error}"))
        }
        FixtureReadError::Read(error) => {
            (read_error_code, format!("cannot read {subject}: {error}"))
        }
    };
    diagnostics.push(Diagnostic::new(code, path, message));
}

#[cfg(target_os = "linux")]
const O_NOFOLLOW: i32 = 0o400000;
#[cfg(target_os = "linux")]
const O_NONBLOCK: i32 = 0o4000;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExecutionState {
    Observed,
    NotRun,
    Unavailable,
    Quarantined,
}

/// Validate all materialized fixtures below a profile fixture root.
pub(crate) fn check(root: &Path, fixture_root: &Path, profile: &ProfileIndex) -> Diagnostics {
    let mut diagnostics = Diagnostics::default();
    let fixture_display = display_path(root, fixture_root);
    if !fixture_root.exists() {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-IO",
            fixture_display,
            "fixture root does not exist",
        ));
        return diagnostics;
    }
    if !fixture_root.is_dir() {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-PATH",
            fixture_display,
            "fixture root is not a directory",
        ));
        return diagnostics;
    }

    let mut files = Vec::new();
    collect_files(root, fixture_root, &mut files, &mut diagnostics);
    files.sort();
    let total_fixture_bytes = files
        .iter()
        .filter_map(|path| fs::symlink_metadata(path).ok())
        .map(|metadata| metadata.len())
        .sum::<u64>();
    if total_fixture_bytes > MAX_FIXTURE_TREE_BYTES {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-BOUNDS",
            fixture_display.clone(),
            format!(
                "fixture tree exceeds {MAX_FIXTURE_TREE_BYTES}-byte aggregate bound (found {total_fixture_bytes})"
            ),
        ));
    }
    for path in &files {
        check_file_extension(root, path, &mut diagnostics);
    }

    let case_paths = files
        .iter()
        .filter(|path| path.file_name().is_some_and(|name| name == "case.json"))
        .cloned()
        .collect::<Vec<_>>();
    if case_paths.is_empty() {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            fixture_display,
            "no case.json manifests were found",
        ));
    }

    let mut case_ids = BTreeMap::<String, String>::new();
    let mut provenance_ids = BTreeMap::<String, String>::new();
    let mut expected_case_ids = BTreeMap::<PathBuf, String>::new();
    let mut expected_case_manifests = BTreeMap::<PathBuf, Map<String, Value>>::new();
    let mut expected_case_states = BTreeMap::<PathBuf, ExecutionState>::new();
    let mut case_families = BTreeSet::new();
    let mut observed_case_families = BTreeSet::new();
    let mut materialized_evidence_families = BTreeSet::new();
    let mut provenance_ready_families = BTreeSet::new();
    let mut case_feature_coverage = BTreeMap::<String, BTreeSet<String>>::new();
    let mut case_normalization_coverage = BTreeMap::<String, BTreeSet<String>>::new();
    let mut case_boundary_coverage = BTreeMap::<String, BTreeSet<String>>::new();
    for case_path in case_paths {
        let case_dir = case_path.parent().unwrap_or(fixture_root);
        let case_display = display_path(root, &case_path);
        let Some(case_value) = read_json(root, &case_path, "FIXTURE-JSON", &mut diagnostics) else {
            continue;
        };
        let Some(case) = case_value.as_object() else {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                case_display.clone(),
                "case manifest must be a JSON object",
            ));
            continue;
        };
        let case_id = validate_case(
            root,
            &case_path,
            case_dir,
            fixture_root,
            case,
            profile,
            &mut diagnostics,
        );
        if let Some(family_id) = case.get("fixture_family_id").and_then(Value::as_str) {
            case_families.insert(family_id.to_owned());
            let state = execution_state(case);
            if state == Some(ExecutionState::Observed) {
                observed_case_families.insert(family_id.to_owned());
            }
            case_feature_coverage
                .entry(family_id.to_owned())
                .or_default()
                .extend(
                    case.get("conformance_ids")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .map(str::to_owned),
                );
            case_normalization_coverage
                .entry(family_id.to_owned())
                .or_default()
                .extend(
                    case.get("normalization_policy_refs")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .map(str::to_owned),
                );
            case_boundary_coverage
                .entry(family_id.to_owned())
                .or_default()
                .extend(
                    case.get("external_runtime_boundary_ids")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .map(str::to_owned),
                );
            if state == Some(ExecutionState::Observed)
                && case_has_immutable_expected_hashes(case, case_dir, fixture_root)
            {
                materialized_evidence_families.insert(family_id.to_owned());
            }
        }
        if let Some(case_id) = case_id.as_ref()
            && let Some(previous) = case_ids.insert(case_id.clone(), case_display.clone())
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-DUPLICATE-ID",
                case_display.clone(),
                format!("case_id {case_id:?} is already declared at {previous}"),
            ));
        }
        if let (Some(case_id), Some(execution)) = (
            case_id.as_ref(),
            case.get("execution").and_then(Value::as_object),
        ) && let Some(expected) = execution.get("expected")
        {
            for expected_path in expected_paths(expected) {
                if is_safe_relative_path(&expected_path) {
                    let expected_path = case_dir.join(expected_path);
                    expected_case_ids.insert(expected_path.clone(), case_id.clone());
                    expected_case_manifests.insert(expected_path, case.clone());
                }
            }
        }
        if let Some(case_id) = case_id.as_ref() {
            for field in ["inputs", "expected", "probes"] {
                if let Some(value) = case.get(field) {
                    for path in declared_paths(value) {
                        if is_safe_relative_path(&path) {
                            let expected_path = case_dir.join(path);
                            expected_case_ids.insert(expected_path.clone(), case_id.clone());
                            expected_case_manifests.insert(expected_path, case.clone());
                        }
                    }
                }
            }
        }
        if let Some(state) = execution_state(case) {
            for field in ["expected", "inputs", "probes"] {
                if let Some(value) = case.get(field) {
                    for expected_path in expected_paths(value) {
                        if is_safe_relative_path(&expected_path) {
                            expected_case_states.insert(case_dir.join(expected_path), state);
                        }
                    }
                }
            }
            if let Some(execution) = case.get("execution").and_then(Value::as_object)
                && let Some(value) = execution.get("expected")
            {
                for expected_path in expected_paths(value) {
                    if is_safe_relative_path(&expected_path) {
                        expected_case_states.insert(case_dir.join(expected_path), state);
                    }
                }
            }
        }

        let provenance_path = case_dir.join("provenance.json");
        let provenance_display = display_path(root, &provenance_path);
        let Some(provenance_value) =
            read_json(root, &provenance_path, "FIXTURE-JSON", &mut diagnostics)
        else {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-REFERENCE",
                provenance_display,
                "each case directory must contain provenance.json",
            ));
            continue;
        };
        let Some(provenance) = provenance_value.as_object() else {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                provenance_display,
                "provenance manifest must be a JSON object",
            ));
            continue;
        };
        let provenance_id = validate_provenance(
            provenance,
            ProvenanceContext {
                root,
                provenance_path: &provenance_path,
                case_id: case_id.as_deref(),
                case_dir,
                fixture_root,
                case,
                profile,
            },
            &mut diagnostics,
        );
        if let Some(family_id) = case.get("fixture_family_id").and_then(Value::as_str)
            && execution_state(case) == Some(ExecutionState::Observed)
            && provenance_has_verified_artifact_and_signature(provenance, profile)
        {
            provenance_ready_families.insert(family_id.to_owned());
        }
        if let Some(provenance_id) = provenance_id
            && let Some(previous) =
                provenance_ids.insert(provenance_id.clone(), provenance_display.clone())
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-DUPLICATE-ID",
                provenance_display,
                format!("provenance case_id {provenance_id:?} is already declared at {previous}"),
            ));
        }
    }

    // Parse every JSON file, including expectations not referenced by a case,
    // so malformed or accidentally committed private JSON cannot hide here.
    for path in files.iter().filter(|path| {
        path.extension()
            .is_some_and(|extension| extension == "json")
    }) {
        let Some(value) = read_json(root, path, "FIXTURE-JSON", &mut diagnostics) else {
            continue;
        };
        if path
            .file_name()
            .is_some_and(|name| name == "case.json" || name == "provenance.json")
        {
            continue;
        }
        if value
            .as_object()
            .is_some_and(|object| object.contains_key("$schema"))
            || path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".schema.json"))
        {
            validate_json_schema_document(root, path, &value, profile, &mut diagnostics);
            continue;
        }
        validate_expectation(
            root,
            path,
            &value,
            profile,
            expected_case_ids.get(path).map(String::as_str),
            expected_case_manifests.get(path),
            expected_case_states.get(path).copied(),
            &mut diagnostics,
        );
    }
    for family_id in &profile.fixture_ids {
        if !case_families.contains(family_id) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-REFERENCE",
                display_path(root, fixture_root),
                format!("profile fixture family {family_id:?} has no source case manifest"),
            ));
        }
    }
    for family_id in &profile.materialized_fixture_ids {
        if !materialized_evidence_families.contains(family_id) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-EVIDENCE",
                display_path(root, fixture_root),
                format!(
                    "profile marks fixture family {family_id:?} materialized, but no observed case has immutable expected hashes"
                ),
            ));
        }
    }
    for family_id in &profile.verified_fixture_ids {
        if !observed_case_families.contains(family_id) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-EVIDENCE",
                display_path(root, fixture_root),
                format!(
                    "verified fixture family {family_id:?} has source fixture presence but no observed execution"
                ),
            ));
        }
        if !materialized_evidence_families.contains(family_id) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-EVIDENCE",
                display_path(root, fixture_root),
                format!(
                    "verified fixture family {family_id:?} lacks materialized immutable expected evidence"
                ),
            ));
        }
        if !provenance_ready_families.contains(family_id) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-PROVENANCE",
                display_path(root, fixture_root),
                format!(
                    "verified fixture family {family_id:?} lacks independently verified artifact/signature provenance"
                ),
            ));
        }
        let expected_features = profile
            .feature_fixture_ids
            .iter()
            .filter_map(|(feature_id, fixture_ids)| {
                fixture_ids
                    .contains(family_id)
                    .then_some(feature_id.clone())
            })
            .collect::<BTreeSet<_>>();
        let actual_features = case_feature_coverage
            .get(family_id)
            .cloned()
            .unwrap_or_default();
        if actual_features != expected_features {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-COVERAGE",
                display_path(root, fixture_root),
                format!(
                    "verified fixture family {family_id:?} feature coverage must be exact: expected {expected_features:?}, found {actual_features:?}"
                ),
            ));
        }
        let expected_normalizations = expected_features
            .iter()
            .flat_map(|feature_id| {
                profile
                    .feature_normalization_ids
                    .get(feature_id)
                    .into_iter()
                    .flatten()
                    .cloned()
            })
            .collect::<BTreeSet<_>>();
        let actual_normalizations = case_normalization_coverage
            .get(family_id)
            .cloned()
            .unwrap_or_default();
        if actual_normalizations != expected_normalizations {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-NORMALIZATION",
                display_path(root, fixture_root),
                format!(
                    "verified fixture family {family_id:?} normalization references must be exact: expected {expected_normalizations:?}, found {actual_normalizations:?}"
                ),
            ));
        }
        let expected_boundaries = profile
            .fixture_boundaries
            .get(family_id)
            .cloned()
            .unwrap_or_default();
        let actual_boundaries = case_boundary_coverage
            .get(family_id)
            .cloned()
            .unwrap_or_default();
        if actual_boundaries != expected_boundaries {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-BOUNDARY",
                display_path(root, fixture_root),
                format!(
                    "verified fixture family {family_id:?} external boundary union must be exact: expected {expected_boundaries:?}, found {actual_boundaries:?}"
                ),
            ));
        }
    }
    diagnostics.sort_deterministically();
    diagnostics
}

fn validate_json_schema_document(
    root: &Path,
    path: &Path,
    value: &Value,
    profile: &ProfileIndex,
    diagnostics: &mut Diagnostics,
) {
    let display = display_path(root, path);
    let Some(object) = value.as_object() else {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            display,
            "JSON Schema document must be an object",
        ));
        return;
    };
    let schema_uri = object.get("$schema").and_then(Value::as_str);
    if schema_uri.is_none_or(|value| value.trim().is_empty()) {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{display}.$schema"),
            "JSON Schema document requires a non-empty $schema URI",
        ));
    }
    if object
        .get("$id")
        .and_then(Value::as_str)
        .is_none_or(|value| value.trim().is_empty())
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{display}.$id"),
            "JSON Schema document requires a non-empty declared $id",
        ));
    }
    if object.get("type").and_then(Value::as_str) != Some("object") {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{display}.type"),
            "top-level JSON Schema type must be object",
        ));
    }
    if object
        .get("properties")
        .and_then(Value::as_object)
        .is_none()
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{display}.properties"),
            "JSON Schema document requires an object properties member",
        ));
    }
    if let Some(required) = object.get("required") {
        let Some(required) = required.as_array() else {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{display}.required"),
                "required must be an array of strings",
            ));
            return;
        };
        for (position, value) in required.iter().enumerate() {
            if value.as_str().is_none() {
                diagnostics.push(Diagnostic::new(
                    "FIXTURE-SCHEMA",
                    format!("{display}.required[{position}]"),
                    "required list members must be strings",
                ));
            }
        }
    }
    if let Some(additional) = object.get("additionalProperties")
        && !additional.is_boolean()
        && !additional.is_object()
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{display}.additionalProperties"),
            "additionalProperties must be a boolean or schema object",
        ));
    }
    if let Some(schema_id) = object.get("schema_id").and_then(Value::as_str)
        && !CUSTOM_EXPECTATION_SCHEMAS.contains(&schema_id)
        && schema_id != EXPECTATION_SCHEMA_ID
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{display}.schema_id"),
            format!("unsupported declared schema ID {schema_id:?}"),
        ));
    }
    if let Some(profile_id) = object.get("profile_id").and_then(Value::as_str)
        && profile_id != profile.profile_id
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-REFERENCE",
            format!("{display}.profile_id"),
            format!("must match active profile {:?}", profile.profile_id),
        ));
    }
    let mut schema_nodes = 0;
    validate_schema_node(value, &display, 0, &mut schema_nodes, diagnostics);
}

fn validate_schema_node(
    value: &Value,
    path: &str,
    depth: usize,
    nodes: &mut usize,
    diagnostics: &mut Diagnostics,
) {
    if *nodes >= MAX_JSON_NODES {
        return;
    }
    *nodes += 1;
    if depth > MAX_JSON_DEPTH {
        return;
    }
    let Some(object) = value.as_object() else {
        if !value.is_boolean() {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                path,
                "schema nodes must be objects or booleans",
            ));
        }
        return;
    };
    if let Some(type_value) = object.get("type") {
        let valid_type = type_value.as_str().is_some_and(valid_schema_type)
            || type_value.as_array().is_some_and(|values| {
                !values.is_empty()
                    && values
                        .iter()
                        .all(|value| value.as_str().is_some_and(valid_schema_type))
            });
        if !valid_type {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.type"),
                "schema type must be a valid type name or non-empty type-name array",
            ));
        }
    }
    if let Some(required) = object.get("required") {
        validate_schema_string_array(required, &format!("{path}.required"), true, diagnostics);
    }
    for field in [
        "properties",
        "patternProperties",
        "$defs",
        "definitions",
        "dependentSchemas",
    ] {
        if let Some(value) = object.get(field) {
            let Some(properties) = value.as_object() else {
                diagnostics.push(Diagnostic::new(
                    "FIXTURE-SCHEMA",
                    format!("{path}.{field}"),
                    "schema map keyword must be an object",
                ));
                continue;
            };
            for (name, schema) in properties {
                validate_schema_node(
                    schema,
                    &format!("{path}.{field}.{name}"),
                    depth + 1,
                    nodes,
                    diagnostics,
                );
            }
        }
    }
    for field in [
        "items",
        "additionalProperties",
        "unevaluatedProperties",
        "contains",
        "propertyNames",
        "not",
        "if",
        "then",
        "else",
        "unevaluatedItems",
    ] {
        if let Some(schema) = object.get(field) {
            if !schema.is_object() && !schema.is_boolean() {
                diagnostics.push(Diagnostic::new(
                    "FIXTURE-SCHEMA",
                    format!("{path}.{field}"),
                    "schema keyword must contain an object or boolean schema",
                ));
            } else {
                validate_schema_node(
                    schema,
                    &format!("{path}.{field}"),
                    depth + 1,
                    nodes,
                    diagnostics,
                );
            }
        }
    }
    for field in ["prefixItems", "allOf", "anyOf", "oneOf"] {
        if let Some(values) = object.get(field) {
            let Some(values) = values.as_array() else {
                diagnostics.push(Diagnostic::new(
                    "FIXTURE-SCHEMA",
                    format!("{path}.{field}"),
                    "schema combinator keyword must be an array",
                ));
                continue;
            };
            for (position, schema) in values.iter().enumerate() {
                if !schema.is_object() && !schema.is_boolean() {
                    diagnostics.push(Diagnostic::new(
                        "FIXTURE-SCHEMA",
                        format!("{path}.{field}[{position}]"),
                        "schema combinator members must be objects or booleans",
                    ));
                } else {
                    validate_schema_node(
                        schema,
                        &format!("{path}.{field}[{position}]"),
                        depth + 1,
                        nodes,
                        diagnostics,
                    );
                }
            }
        }
    }
    for field in ["$ref", "$dynamicRef", "$anchor", "$dynamicAnchor"] {
        if let Some(value) = object.get(field)
            && value.as_str().is_none_or(str::is_empty)
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.{field}"),
                "schema reference/anchor must be a non-empty string",
            ));
        }
    }
    for field in [
        "minLength",
        "maxLength",
        "minItems",
        "maxItems",
        "minProperties",
        "maxProperties",
    ] {
        if let Some(value) = object.get(field)
            && value.as_u64().is_none()
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.{field}"),
                "schema size bound must be a non-negative integer",
            ));
        }
    }
    for field in [
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "multipleOf",
    ] {
        if let Some(value) = object.get(field)
            && value.as_f64().is_none()
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.{field}"),
                "schema numeric bound must be a number",
            ));
        }
    }
    for field in ["pattern", "format", "contentEncoding", "contentMediaType"] {
        if let Some(value) = object.get(field)
            && value.as_str().is_none()
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.{field}"),
                "schema string keyword must be a string",
            ));
        }
    }
    if let Some(enum_values) = object.get("enum")
        && enum_values.as_array().is_none()
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.enum"),
            "schema enum must be an array",
        ));
    }
}

fn valid_schema_type(value: &str) -> bool {
    matches!(
        value,
        "null" | "boolean" | "object" | "array" | "number" | "string" | "integer"
    )
}

fn validate_schema_string_array(
    value: &Value,
    path: &str,
    unique: bool,
    diagnostics: &mut Diagnostics,
) {
    let Some(values) = value.as_array() else {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            path,
            "schema string-list keyword must be an array",
        ));
        return;
    };
    let mut seen = BTreeSet::new();
    for (position, value) in values.iter().enumerate() {
        let Some(value) = value.as_str() else {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}[{position}]"),
                "schema string-list members must be strings",
            ));
            continue;
        };
        if unique && !seen.insert(value) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}[{position}]"),
                "schema string-list members must be unique",
            ));
        }
    }
}

fn provenance_has_verified_artifact_and_signature(
    provenance: &Map<String, Value>,
    profile: &ProfileIndex,
) -> bool {
    let Some(oracle) = provenance.get("oracle").and_then(Value::as_object) else {
        return false;
    };
    let artifact_ok = oracle
        .get("artifact_sha512")
        .and_then(Value::as_str)
        .is_some_and(|digest| digest == profile.upstream.digest)
        && oracle.get("sha512_verified_before_execution") == Some(&Value::Bool(true))
        && oracle
            .get("retrieved_at")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty());
    let pgp = oracle
        .get("pgp")
        .and_then(Value::as_object)
        .unwrap_or(oracle);
    let signature_status = pgp
        .get("signature_status")
        .or_else(|| pgp.get("status"))
        .and_then(Value::as_str);
    let signature_verified = pgp
        .get("signature_verified")
        .or_else(|| pgp.get("verified"))
        .and_then(Value::as_bool)
        == Some(true);
    let fingerprint = pgp
        .get("observed_fingerprint")
        .or_else(|| pgp.get("fingerprint"))
        .and_then(Value::as_str);
    let required_fingerprint = pgp
        .get("required_fingerprint")
        .or_else(|| pgp.get("expected_fingerprint"))
        .and_then(Value::as_str);
    let urls_ok = pgp
        .get("signature_url")
        .and_then(Value::as_str)
        .is_some_and(|value| value.starts_with("https://"))
        && pgp
            .get("keys_url")
            .and_then(Value::as_str)
            .is_some_and(|value| value.starts_with("https://"));
    let fingerprint_ok = fingerprint.is_some()
        && required_fingerprint.is_some()
        && fingerprint == required_fingerprint;
    artifact_ok
        && urls_ok
        && fingerprint_ok
        && signature_verified
        && matches!(
            signature_status,
            Some("verified" | "valid" | "verified-before-execution")
        )
}

fn collect_files(
    root: &Path,
    directory: &Path,
    files: &mut Vec<PathBuf>,
    diagnostics: &mut Diagnostics,
) {
    let depth = directory
        .strip_prefix(root)
        .map(|relative| relative.components().count())
        .unwrap_or(MAX_FIXTURE_DIRECTORY_DEPTH + 1);
    if depth > MAX_FIXTURE_DIRECTORY_DEPTH {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-BOUNDS",
            display_path(root, directory),
            format!("fixture directory nesting exceeds {MAX_FIXTURE_DIRECTORY_DEPTH} levels"),
        ));
        return;
    }
    let mut entries = match fs::read_dir(directory) {
        Ok(entries) => match entries.collect::<Result<Vec<_>, _>>() {
            Ok(entries) => entries,
            Err(error) => {
                diagnostics.push(Diagnostic::new(
                    "FIXTURE-IO",
                    display_path(root, directory),
                    format!("cannot enumerate fixture directory: {error}"),
                ));
                return;
            }
        },
        Err(error) => {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-IO",
                display_path(root, directory),
                format!("cannot read fixture directory: {error}"),
            ));
            return;
        }
    };
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(error) => {
                diagnostics.push(Diagnostic::new(
                    "FIXTURE-IO",
                    display_path(root, &path),
                    format!("cannot inspect fixture entry: {error}"),
                ));
                continue;
            }
        };
        if file_type.is_symlink() {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-PATH",
                display_path(root, &path),
                "symlinks are not allowed in fixture trees",
            ));
        } else if file_type.is_dir() {
            if path.components().any(|component| {
                matches!(
                    component.as_os_str().to_str(),
                    Some(
                        "__pycache__"
                            | "oracle-runs"
                            | "target"
                            | ".git"
                            | "generated"
                            | "raw-logs"
                    )
                )
            }) {
                diagnostics.push(Diagnostic::new(
                    "FIXTURE-SAFETY",
                    display_path(root, &path),
                    "generated, raw, or nested build-artifact directories are not allowed in fixture trees",
                ));
                continue;
            }
            collect_files(root, &path, files, diagnostics);
        } else if file_type.is_file() {
            if let Ok(metadata) = entry.metadata()
                && metadata.len() > MAX_FIXTURE_FILE_BYTES
            {
                diagnostics.push(Diagnostic::new(
                    "FIXTURE-BOUNDS",
                    display_path(root, &path),
                    format!("fixture file exceeds {MAX_FIXTURE_FILE_BYTES}-byte bound"),
                ));
            }
            files.push(path);
        } else {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-PATH",
                display_path(root, &path),
                "fixture entry must be a regular file or directory",
            ));
        }
    }
}

/// Return every path declared by a case's generic path/hash sections.  The
/// fixture corpus contains a few static descriptors (for example the local
/// HTTP mirror) that do not use the usual `plan`/`property_files` names.  The
/// same safety and digest rules still apply to those declarations.
fn declared_paths(value: &Value) -> Vec<String> {
    let mut paths = Vec::new();
    collect_declared_paths(value, &mut paths);
    paths
}

fn collect_declared_paths(value: &Value, paths: &mut Vec<String>) {
    match value {
        Value::Array(values) => {
            for value in values {
                collect_declared_paths(value, paths);
            }
        }
        Value::Object(object) => {
            if let Some(path) = object.get("path").and_then(Value::as_str)
                && object.get("sha256").is_some()
            {
                paths.push(path.to_owned());
            }
            for value in object.values() {
                collect_declared_paths(value, paths);
            }
        }
        _ => {}
    }
}

fn execution_state(case: &Map<String, Value>) -> Option<ExecutionState> {
    case.get("execution")
        .and_then(Value::as_object)
        .and_then(|execution| execution.get("status"))
        .and_then(parse_execution_state)
}

fn parse_execution_state(value: &Value) -> Option<ExecutionState> {
    let kind = value.as_str().or_else(|| {
        value
            .as_object()
            .and_then(|status| status.get("kind"))
            .and_then(Value::as_str)
    })?;
    const OBSERVED: [&str; 7] = [
        "observed",
        "passed",
        "failed",
        "completed",
        "verified",
        "verified-observed",
        "raw-observation",
    ];
    const NOT_RUN: [&str; 22] = [
        "planned",
        "not-run",
        "not_run",
        "not-run-static",
        "not-run-static-corpus",
        "not-run-static-only",
        "not-run-static-preservation",
        "planned; external Java/RMI runner not executed",
        "not-run-static-external",
        "not-run-static-handoff",
        "static-only",
        "static-only-forbidden-oracle",
        "static-only; oracle not executed",
        "planned; not-run",
        "planned; not observed",
        "planned-invalid-outcomes",
        "planned-normalization",
        "planned_not_materialized",
        "declared-not-run",
        "future-run-only",
        "deferred",
        "not-evaluated",
    ];
    const UNAVAILABLE: [&str; 8] = [
        "unavailable",
        "blocked",
        "unsupported",
        "external-unavailable",
        "unavailable-static",
        "external-unavailable; static-only; plugin oracle not executed",
        "capability-unavailable",
        "not-configured",
    ];
    const QUARANTINED: [&str; 1] = ["external-raw-observation"];
    if OBSERVED.contains(&kind) {
        Some(ExecutionState::Observed)
    } else if QUARANTINED.contains(&kind) {
        Some(ExecutionState::Quarantined)
    } else if NOT_RUN.contains(&kind) {
        Some(ExecutionState::NotRun)
    } else if UNAVAILABLE.contains(&kind) {
        Some(ExecutionState::Unavailable)
    } else {
        None
    }
}

fn validate_execution_state(
    case: &Map<String, Value>,
    path: &str,
    diagnostics: &mut Diagnostics,
) -> Option<ExecutionState> {
    let Some(state) = execution_state(case) else {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-EXECUTION",
            format!("{path}.execution.status"),
            "status must identify observed, not-run, unavailable, or quarantined execution state",
        ));
        return None;
    };
    if let Some(execution) = case.get("execution").and_then(Value::as_object) {
        let process_exit = execution.get("process_exit");
        match state {
            ExecutionState::Observed if process_exit.and_then(Value::as_u64).is_none() => {
                diagnostics.push(Diagnostic::new(
                    "FIXTURE-EXECUTION",
                    format!("{path}.execution.process_exit"),
                    "observed execution requires a non-negative process exit code",
                ));
            }
            ExecutionState::NotRun | ExecutionState::Unavailable | ExecutionState::Quarantined
                if !matches!(process_exit, Some(Value::Null))
                    && process_exit.and_then(Value::as_u64).is_none() =>
            {
                diagnostics.push(Diagnostic::new(
                    "FIXTURE-EXECUTION",
                    format!("{path}.execution.process_exit"),
                    "not-run or unavailable execution requires an integer or null exit code",
                ));
            }
            _ => {}
        }
    }
    Some(state)
}

fn validate_execution_status_value(
    execution: &Map<String, Value>,
    path: &str,
    diagnostics: &mut Diagnostics,
) {
    let Some(status) = execution.get("status") else {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.status"),
            "required status string or typed status object is missing",
        ));
        return;
    };
    match status {
        Value::String(value) => {
            if parse_execution_state(status).is_none() {
                diagnostics.push(Diagnostic::new(
                    "FIXTURE-SCHEMA",
                    format!("{path}.status"),
                    format!("unsupported closed execution status kind {value:?}"),
                ));
            }
        }
        Value::Object(status) => {
            if status.get("kind").and_then(Value::as_str).is_none() {
                diagnostics.push(Diagnostic::new(
                    "FIXTURE-SCHEMA",
                    format!("{path}.status.kind"),
                    "typed execution status requires a kind string",
                ));
            } else if parse_execution_state(&Value::Object(status.clone())).is_none() {
                diagnostics.push(Diagnostic::new(
                    "FIXTURE-SCHEMA",
                    format!("{path}.status.kind"),
                    "typed execution status kind is not in the closed vocabulary",
                ));
            }
            if let Some(value) = status.get("reason")
                && !value.is_null()
                && !value.is_string()
            {
                diagnostics.push(Diagnostic::new(
                    "FIXTURE-SCHEMA",
                    format!("{path}.status.reason"),
                    "status reason must be a string or null",
                ));
            }
            if let Some(value) = status.get("oracle_available")
                && !value.is_boolean()
            {
                diagnostics.push(Diagnostic::new(
                    "FIXTURE-SCHEMA",
                    format!("{path}.status.oracle_available"),
                    "oracle_available must be a boolean",
                ));
            }
        }
        _ => diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.status"),
            "status must be a string or typed status object",
        )),
    }
}

fn validate_quarantine_markers(
    object: &Map<String, Value>,
    path: &str,
    inherited_state: Option<ExecutionState>,
    diagnostics: &mut Diagnostics,
) {
    let local_state = object
        .get("status")
        .or_else(|| object.get("evidence_status"))
        .and_then(parse_execution_state)
        .or(inherited_state);
    let comparator_ready = object.get("comparator_ready").and_then(Value::as_bool);
    let rust_claim = object
        .get("rust_conformance_claim")
        .and_then(Value::as_bool);
    if comparator_ready == Some(false) && rust_claim == Some(false) {
        if local_state != Some(ExecutionState::Quarantined) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-EVIDENCE",
                path,
                "comparator_ready=false and rust_conformance_claim=false require external-raw-observation quarantine",
            ));
        }
    } else if local_state == Some(ExecutionState::Quarantined)
        && (comparator_ready == Some(true) || rust_claim == Some(true))
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-EVIDENCE",
            path,
            "quarantined external raw observation cannot be comparator-ready or claim Rust conformance",
        ));
    }
    for (field, value) in object {
        if let Value::Object(nested) = value {
            validate_quarantine_markers(
                nested,
                &format!("{path}.{field}"),
                local_state,
                diagnostics,
            );
        } else if let Value::Array(values) = value {
            for (position, value) in values.iter().enumerate() {
                if let Value::Object(nested) = value {
                    validate_quarantine_markers(
                        nested,
                        &format!("{path}.{field}[{position}]"),
                        local_state,
                        diagnostics,
                    );
                }
            }
        }
    }
}

fn validate_nested_schema_ids(
    value: &Map<String, Value>,
    path: &str,
    diagnostics: &mut Diagnostics,
) {
    if let Some(schema_id) = value.get("schema_id").and_then(Value::as_str) {
        let supported = matches!(
            schema_id,
            CASE_SCHEMA_ID | PROVENANCE_SCHEMA_ID | EXPECTATION_SCHEMA_ID
        ) || CUSTOM_EXPECTATION_SCHEMAS.contains(&schema_id);
        if !supported {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.schema_id"),
                format!("unsupported nested schema ID {schema_id:?}"),
            ));
        }
        match schema_id {
            "jmeter-rs.proxy-recorder-ready" => {
                validate_proxy_recorder_ready(value, path, diagnostics);
            }
            "jmeter-rs.proxy-tls-ready" => {
                validate_proxy_tls_ready(value, path, diagnostics);
            }
            _ => {}
        }
    }
    for (field, nested) in value {
        match nested {
            Value::Object(nested) => {
                validate_nested_schema_ids(nested, &format!("{path}.{field}"), diagnostics)
            }
            Value::Array(values) => {
                for (position, nested) in values.iter().enumerate() {
                    if let Value::Object(nested) = nested {
                        validate_nested_schema_ids(
                            nested,
                            &format!("{path}.{field}[{position}]"),
                            diagnostics,
                        );
                    }
                }
            }
            _ => {}
        }
    }
}

fn validate_proxy_recorder_ready(
    object: &Map<String, Value>,
    path: &str,
    diagnostics: &mut Diagnostics,
) {
    const FIELDS: [&str; 10] = [
        "schema_id",
        "schema_version",
        "required",
        "source",
        "host",
        "timeout_ms",
        "max_bytes",
        "fresh_run_root",
        "exact_child",
        "pid_authority",
    ];
    validate_closed_fields(object, path, &FIELDS, "proxy-recorder-ready", diagnostics);
    validate_schema_version(object, path, diagnostics);
    for field in ["required", "fresh_run_root", "exact_child", "pid_authority"] {
        if !object.get(field).is_some_and(Value::is_boolean) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.{field}"),
                "proxy-recorder-ready boolean field is missing or has the wrong type",
            ));
        }
    }
    let _ = required_string(object, "source", path, "FIXTURE-SCHEMA", diagnostics);
    let _ = required_string(object, "host", path, "FIXTURE-SCHEMA", diagnostics);
    let _ = required_u64(object, "timeout_ms", path, diagnostics);
    let _ = required_u64(object, "max_bytes", path, diagnostics);
}

fn validate_proxy_tls_ready(
    object: &Map<String, Value>,
    path: &str,
    diagnostics: &mut Diagnostics,
) {
    const FIELDS: [&str; 11] = [
        "schema_id",
        "schema_version",
        "required_object",
        "path",
        "atomic_rename",
        "host",
        "ports_source",
        "timeout_ms",
        "max_bytes",
        "pid_authority",
        "stale_file_policy",
    ];
    validate_closed_fields(object, path, &FIELDS, "proxy-tls-ready", diagnostics);
    validate_schema_version(object, path, diagnostics);
    let _ = required_string(
        object,
        "required_object",
        path,
        "FIXTURE-SCHEMA",
        diagnostics,
    );
    let _ = required_string(object, "path", path, "FIXTURE-SCHEMA", diagnostics);
    let _ = required_string(object, "host", path, "FIXTURE-SCHEMA", diagnostics);
    let _ = required_string(object, "ports_source", path, "FIXTURE-SCHEMA", diagnostics);
    let _ = required_string(
        object,
        "stale_file_policy",
        path,
        "FIXTURE-SCHEMA",
        diagnostics,
    );
    let _ = required_u64(object, "timeout_ms", path, diagnostics);
    let _ = required_u64(object, "max_bytes", path, diagnostics);
    for field in ["atomic_rename", "pid_authority"] {
        if !object.get(field).is_some_and(Value::is_boolean) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.{field}"),
                "proxy-tls-ready boolean field is missing or has the wrong type",
            ));
        }
    }
}

fn validate_closed_fields(
    object: &Map<String, Value>,
    path: &str,
    fields: &[&str],
    schema_name: &str,
    diagnostics: &mut Diagnostics,
) {
    for field in object.keys() {
        if !fields.contains(&field.as_str()) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.{field}"),
                format!("unknown {schema_name} field is not permitted"),
            ));
        }
    }
}

fn validate_schema_version(object: &Map<String, Value>, path: &str, diagnostics: &mut Diagnostics) {
    if object.get("schema_version").and_then(Value::as_u64) != Some(SCHEMA_VERSION) {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.schema_version"),
            format!("must be schema version {SCHEMA_VERSION}"),
        ));
    }
}

fn check_file_extension(root: &Path, path: &Path, diagnostics: &mut Diagnostics) {
    if path.components().any(|component| {
        matches!(
            component.as_os_str().to_str(),
            Some(
                "__pycache__"
                    | "oracle-runs"
                    | "target"
                    | ".git"
                    | "generated"
                    | "raw-logs"
                    | "logs"
            )
        )
    }) {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SAFETY",
            display_path(root, path),
            "generated output or raw oracle artifacts are not allowed in fixture trees",
        ));
    }
    let Some(extension) = path.extension().and_then(|extension| extension.to_str()) else {
        return;
    };
    let extension = extension.to_ascii_lowercase();
    if UNSAFE_EXTENSIONS.contains(&extension.as_str()) {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SAFETY",
            display_path(root, path),
            format!("raw artifact or secret-bearing extension .{extension} is not allowed in Git fixtures"),
        ));
    }
}

fn validate_case(
    root: &Path,
    case_path: &Path,
    case_dir: &Path,
    fixture_root: &Path,
    case: &Map<String, Value>,
    profile: &ProfileIndex,
    diagnostics: &mut Diagnostics,
) -> Option<String> {
    let path = display_path(root, case_path);
    check_schema_header(case, &path, CASE_SCHEMA_ID, diagnostics);
    let state = validate_execution_state(case, &path, diagnostics);
    validate_quarantine_markers(case, &path, state, diagnostics);
    validate_quarantine_materialization(case, &path, state, diagnostics);
    validate_nested_schema_ids(case, &path, diagnostics);
    validate_bound_sections(case, &path, diagnostics);
    validate_digest_fields(case, &path, state, diagnostics);
    let case_id = required_string(case, "case_id", &path, "FIXTURE-SCHEMA", diagnostics);
    if case_id
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.case_id"),
            "must not be empty",
        ));
    }
    if let Some(value) = required_string(case, "profile_id", &path, "FIXTURE-SCHEMA", diagnostics)
        && value != profile.profile_id
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-REFERENCE",
            format!("{path}.profile_id"),
            format!("must match active profile {:?}", profile.profile_id),
        ));
    }
    if let Some(value) = required_string(
        case,
        "fixture_family_id",
        &path,
        "FIXTURE-SCHEMA",
        diagnostics,
    ) && !profile.fixture_ids.contains(&value)
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-REFERENCE",
            format!("{path}.fixture_family_id"),
            format!("unknown profile fixture family {value:?}"),
        ));
    }
    check_id_array(
        case,
        "conformance_ids",
        &path,
        &profile.feature_ids,
        diagnostics,
        true,
    );
    check_id_array(
        case,
        "normalization_policy_refs",
        &path,
        &profile.normalization_ids,
        diagnostics,
        false,
    );
    if let Some(boundaries) = case.get("external_runtime_boundary_ids") {
        check_id_array(
            case,
            "external_runtime_boundary_ids",
            &path,
            &profile.boundary_ids,
            diagnostics,
            false,
        );
        if let Some(values) = boundaries.as_array() {
            let feature_ids = case
                .get("conformance_ids")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect::<BTreeSet<_>>();
            for (position, value) in values.iter().enumerate() {
                let Some(boundary) = value.as_str() else {
                    continue;
                };
                if !feature_ids.iter().any(|feature_id| {
                    profile
                        .feature_boundaries
                        .get(*feature_id)
                        .is_some_and(|boundaries| boundaries.contains(boundary))
                }) {
                    diagnostics.push(Diagnostic::new(
                        "FIXTURE-REFERENCE",
                        format!("{path}.external_runtime_boundary_ids[{position}]"),
                        format!(
                            "boundary {boundary:?} is not declared by any case conformance feature"
                        ),
                    ));
                }
            }
        }
    }

    let static_descriptor = case.get("plan").is_none()
        && (case.contains_key("inputs")
            || case.contains_key("expected")
            || case.contains_key("probes"));
    if let Some(plan) = case.get("plan").and_then(Value::as_object) {
        let plan_ref = required_safe_path(
            fixture_root,
            case_dir,
            plan,
            "path",
            &format!("{path}.plan"),
            diagnostics,
        );
        if let Some(plan_ref) = plan_ref.as_ref() {
            if !plan_ref.exists() {
                diagnostics.push(Diagnostic::new(
                    "FIXTURE-REFERENCE",
                    format!("{path}.plan.path"),
                    format!(
                        "referenced plan {} does not exist",
                        display_path(root, plan_ref)
                    ),
                ));
            }
            if let Some(hash) = optional_hash(
                plan,
                "sha256",
                &format!("{path}.plan"),
                state != Some(ExecutionState::Observed),
                diagnostics,
            ) {
                check_sha256(
                    root,
                    plan_ref,
                    &hash,
                    &format!("{path}.plan.sha256"),
                    diagnostics,
                );
            }
        }
    } else if !static_descriptor {
        let _ = required_object(case, "plan", &path, diagnostics);
    }

    if let Some(property_files) = case.get("property_files").and_then(Value::as_array) {
        if property_files.is_empty() {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.property_files"),
                "must contain at least one pinned property file",
            ));
        }
        for (position, value) in property_files.iter().enumerate() {
            let item_path = format!("{path}.property_files[{position}]");
            let Some(property) = value.as_object() else {
                diagnostics.push(Diagnostic::new(
                    "FIXTURE-SCHEMA",
                    item_path,
                    "property file entry must be an object",
                ));
                continue;
            };
            let file_ref = required_safe_path(
                fixture_root,
                case_dir,
                property,
                "path",
                &item_path,
                diagnostics,
            );
            if let Some(file_ref) = file_ref.as_ref() {
                if !file_ref.exists() {
                    diagnostics.push(Diagnostic::new(
                        "FIXTURE-REFERENCE",
                        format!("{item_path}.path"),
                        format!(
                            "referenced property file {} does not exist",
                            display_path(root, file_ref)
                        ),
                    ));
                }
                if let Some(hash) = optional_hash(
                    property,
                    "sha256",
                    &item_path,
                    state != Some(ExecutionState::Observed),
                    diagnostics,
                ) {
                    check_sha256(
                        root,
                        file_ref,
                        &hash,
                        &format!("{item_path}.sha256"),
                        diagnostics,
                    );
                }
            }
        }
    } else if !static_descriptor
        && !(state == Some(ExecutionState::NotRun)
            && case.get("property_files").is_some_and(Value::is_null))
    {
        let _ = required_array(case, "property_files", &path, diagnostics);
    }

    for (field, value) in case {
        if !matches!(
            field.as_str(),
            "source_references"
                | "plan"
                | "property_files"
                | "inputs"
                | "expected"
                | "probes"
                | "input_files"
                | "execution"
        ) {
            validate_path_hash_refs(
                fixture_root,
                case_dir,
                value,
                &format!("{path}.{field}"),
                state != Some(ExecutionState::Observed),
                diagnostics,
            );
            validate_named_path_hash_refs(
                fixture_root,
                case_dir,
                value,
                &format!("{path}.{field}"),
                state != Some(ExecutionState::Observed),
                diagnostics,
            );
        }
    }
    if let Some(source_references) = case.get("source_references") {
        validate_path_hash_refs(
            root,
            root,
            source_references,
            &format!("{path}.source_references"),
            state != Some(ExecutionState::Observed),
            diagnostics,
        );
    }

    let Some(command) = required_object(case, "command", &path, diagnostics) else {
        return case_id;
    };
    for field in ["mode", "network", "locale", "timezone", "default_charset"] {
        let _ = required_string(
            command,
            field,
            &format!("{path}.command"),
            "FIXTURE-SCHEMA",
            diagnostics,
        );
    }
    if let Some(working_directory) = command.get("working_directory").and_then(Value::as_str) {
        let _ = check_safe_path_value(
            fixture_root,
            case_dir,
            working_directory,
            &format!("{path}.command.working_directory"),
            diagnostics,
        );
    }
    if !command.contains_key("random_seed") {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.command.random_seed"),
            "required field is missing",
        ));
    }
    if command.get("argv_template").is_none() && command.get("argv_templates").is_none() {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.command"),
            "one of argv_template or argv_templates is required",
        ));
    }

    let Some(execution) = required_object(case, "execution", &path, diagnostics) else {
        return case_id;
    };
    validate_execution_status_value(execution, &format!("{path}.execution"), diagnostics);
    require_observed_materialization(execution, &format!("{path}.execution"), state, diagnostics);
    if state.is_none() {
        return case_id;
    }
    let expected = match execution.get("expected") {
        Some(value) => expected_paths(value),
        None => {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.execution.expected"),
                "required field is missing",
            ));
            Vec::new()
        }
    };
    if expected.is_empty() {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.execution.expected"),
            "must name at least one expected JSON file",
        ));
    }
    for (position, expected_path) in expected.iter().enumerate() {
        let item_path = format!("{path}.execution.expected[{position}]");
        if !check_safe_path_value(
            fixture_root,
            case_dir,
            expected_path,
            &item_path,
            diagnostics,
        ) {
            continue;
        }
        let full_path = case_dir.join(expected_path);
        if !full_path.exists() {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-REFERENCE",
                item_path,
                format!(
                    "referenced expectation {} does not exist",
                    display_path(root, &full_path)
                ),
            ));
        }
    }
    if let Some(expected_value) = execution.get("expected") {
        validate_path_hash_refs(
            fixture_root,
            case_dir,
            expected_value,
            &format!("{path}.execution.expected"),
            state != Some(ExecutionState::Observed),
            diagnostics,
        );
    }
    if let Some(raw_artifacts) = execution.get("raw_artifacts") {
        validate_raw_artifacts(
            root,
            case_dir,
            raw_artifacts,
            &format!("{path}.execution.raw_artifacts"),
            state,
            diagnostics,
        );
    } else {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.execution.raw_artifacts"),
            "required raw_artifacts declaration is missing",
        ));
    }
    let _ = required_array(case, "limitations", &path, diagnostics);
    case_id
}

struct ProvenanceContext<'a> {
    root: &'a Path,
    provenance_path: &'a Path,
    case_id: Option<&'a str>,
    case_dir: &'a Path,
    fixture_root: &'a Path,
    case: &'a Map<String, Value>,
    profile: &'a ProfileIndex,
}

fn validate_provenance(
    provenance: &Map<String, Value>,
    context: ProvenanceContext<'_>,
    diagnostics: &mut Diagnostics,
) -> Option<String> {
    let ProvenanceContext {
        root,
        provenance_path,
        case_id,
        case_dir,
        fixture_root,
        case,
        profile,
    } = context;
    let path = display_path(root, provenance_path);
    check_schema_header(provenance, &path, PROVENANCE_SCHEMA_ID, diagnostics);
    let state = execution_state(case);
    validate_quarantine_markers(provenance, &path, state, diagnostics);
    validate_quarantine_materialization(provenance, &path, state, diagnostics);
    validate_nested_schema_ids(provenance, &path, diagnostics);
    validate_bound_sections(provenance, &path, diagnostics);
    validate_digest_fields(provenance, &path, state, diagnostics);
    let provenance_case_id =
        required_string(provenance, "case_id", &path, "FIXTURE-SCHEMA", diagnostics);
    if let (Some(case_id), Some(provenance_case_id)) = (case_id, provenance_case_id.as_deref())
        && case_id != provenance_case_id
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-REFERENCE",
            format!("{path}.case_id"),
            format!("must match case manifest case_id {case_id:?}"),
        ));
    }
    let static_descriptor = execution_state(case) != Some(ExecutionState::Observed);
    let Some(origin) = provenance.get("origin").and_then(Value::as_object) else {
        if !static_descriptor {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.origin"),
                "observed provenance requires an origin object",
            ));
        }
        return provenance_case_id;
    };
    for field in ["kind", "author", "created_at", "description"] {
        let _ = required_string(
            origin,
            field,
            &format!("{path}.origin"),
            "FIXTURE-SCHEMA",
            diagnostics,
        );
    }
    let upstream_plan_copied = required_bool(
        origin,
        "upstream_plan_copied",
        &format!("{path}.origin"),
        diagnostics,
    );
    if upstream_plan_copied == Some(true) {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SAFETY",
            format!("{path}.origin.upstream_plan_copied"),
            "checked-in fixtures must not copy an upstream JMeter plan",
        ));
    }
    let Some(license) = required_object(provenance, "license", &path, diagnostics) else {
        return provenance_case_id;
    };
    for field in [
        "fixture_license",
        "repository_notice",
        "upstream_distribution_use",
    ] {
        let _ = required_string(
            license,
            field,
            &format!("{path}.license"),
            "FIXTURE-SCHEMA",
            diagnostics,
        );
    }
    let Some(oracle) = required_object(provenance, "oracle", &path, diagnostics) else {
        return provenance_case_id;
    };
    check_upstream_pin(root, &path, oracle, profile, state, diagnostics);
    let Some(runtime) = required_object(provenance, "runtime", &path, diagnostics) else {
        return provenance_case_id;
    };
    validate_runtime(&path, runtime, state, diagnostics);
    let Some(inputs) = required_object(provenance, "inputs", &path, diagnostics) else {
        return provenance_case_id;
    };
    validate_inputs(
        root,
        fixture_root,
        &path,
        inputs,
        case_dir,
        case,
        state,
        diagnostics,
    );
    for (field, value) in provenance {
        if !matches!(field.as_str(), "source_references" | "inputs") {
            validate_path_hash_refs(
                fixture_root,
                case_dir,
                value,
                &format!("{path}.{field}"),
                state != Some(ExecutionState::Observed),
                diagnostics,
            );
            validate_named_path_hash_refs(
                fixture_root,
                case_dir,
                value,
                &format!("{path}.{field}"),
                state != Some(ExecutionState::Observed),
                diagnostics,
            );
        }
    }
    if let Some(additional_static_inputs) = provenance.get("additional_static_inputs") {
        validate_keyed_path_hash_refs(
            root,
            case_dir,
            additional_static_inputs,
            &format!("{path}.additional_static_inputs"),
            state != Some(ExecutionState::Observed),
            diagnostics,
        );
    }
    if let Some(source_references) = provenance.get("source_references") {
        validate_path_hash_refs(
            root,
            root,
            source_references,
            &format!("{path}.source_references"),
            state != Some(ExecutionState::Observed),
            diagnostics,
        );
        validate_named_path_hash_refs(
            root,
            root,
            source_references,
            &format!("{path}.source_references"),
            state != Some(ExecutionState::Observed),
            diagnostics,
        );
    }
    provenance_case_id
}

fn check_upstream_pin(
    _root: &Path,
    path: &str,
    oracle: &Map<String, Value>,
    profile: &ProfileIndex,
    state: Option<ExecutionState>,
    diagnostics: &mut Diagnostics,
) {
    let fields = [
        ("project", &profile.upstream.project),
        ("version", &profile.upstream.version),
        ("release_tag", &profile.upstream.release_tag),
        ("source_commit", &profile.upstream.source_commit),
        ("artifact", &profile.upstream.artifact),
        ("artifact_sha512", &profile.upstream.digest),
    ];
    for (field, expected) in fields {
        if let Some(actual) = oracle.get(field).and_then(Value::as_str) {
            if !expected.is_empty() && actual != expected {
                diagnostics.push(Diagnostic::new(
                    "FIXTURE-PROVENANCE",
                    format!("{path}.oracle.{field}"),
                    format!("must match active profile upstream pin {expected:?}"),
                ));
            }
        } else {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.oracle.{field}"),
                "required pinned string is missing",
            ));
        }
    }
    for field in ["artifact_url", "digest_url"] {
        if let Some(value) = required_string(
            oracle,
            field,
            &format!("{path}.oracle"),
            "FIXTURE-SCHEMA",
            diagnostics,
        ) && !value.starts_with("https://")
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-PROVENANCE",
                format!("{path}.oracle.{field}"),
                "oracle provenance URLs must use HTTPS",
            ));
        }
    }
    for field in ["signature_url", "keys_url"] {
        let value = oracle.get(field).and_then(Value::as_str);
        if state == Some(ExecutionState::Observed) && value.is_none() {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.oracle.{field}"),
                "observed oracle evidence requires a pinned PGP URL",
            ));
        }
        if let Some(value) = value
            && !value.starts_with("https://")
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-PROVENANCE",
                format!("{path}.oracle.{field}"),
                "oracle provenance URLs must use HTTPS",
            ));
        }
    }
    validate_oracle_pgp(oracle, path, state, diagnostics);
    if state == Some(ExecutionState::Observed)
        && required_string(
            oracle,
            "retrieved_at",
            &format!("{path}.oracle"),
            "FIXTURE-SCHEMA",
            diagnostics,
        )
        .is_none()
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-PROVENANCE",
            format!("{path}.oracle.retrieved_at"),
            "observed evidence requires an artifact retrieval timestamp",
        ));
    }
    let verified = oracle
        .get("sha512_verified_before_execution")
        .and_then(Value::as_bool);
    if state == Some(ExecutionState::Observed) && verified != Some(true) {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-PROVENANCE",
            format!("{path}.oracle.sha512_verified_before_execution"),
            "observed evidence requires a verified pinned artifact",
        ));
    }
}

fn validate_oracle_pgp(
    oracle: &Map<String, Value>,
    path: &str,
    state: Option<ExecutionState>,
    diagnostics: &mut Diagnostics,
) {
    let Some(pgp) = oracle.get("pgp").and_then(Value::as_object) else {
        if state == Some(ExecutionState::Observed) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-PROVENANCE",
                format!("{path}.oracle.pgp"),
                "observed oracle evidence requires an independent PGP verification object",
            ));
        }
        return;
    };
    for field in ["signature_url", "keys_url"] {
        if let Some(value) = pgp.get(field).and_then(Value::as_str)
            && !value.starts_with("https://")
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-PROVENANCE",
                format!("{path}.oracle.pgp.{field}"),
                "PGP URLs must use HTTPS",
            ));
        }
    }
    let status = pgp.get("status").and_then(Value::as_str);
    if state == Some(ExecutionState::Observed)
        && !matches!(
            status,
            Some("verified" | "valid" | "verified-before-execution")
        )
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-PROVENANCE",
            format!("{path}.oracle.pgp.status"),
            "observed oracle evidence requires a verified PGP status",
        ));
    }
    for field in [
        "required_fingerprint",
        "observed_fingerprint",
        "fingerprint",
    ] {
        if let Some(value) = pgp.get(field).and_then(Value::as_str)
            && !is_hex_fingerprint(value)
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-PROVENANCE",
                format!("{path}.oracle.pgp.{field}"),
                "PGP fingerprint must be 40 hexadecimal characters",
            ));
        }
    }
    if let (Some(required), Some(observed)) = (
        pgp.get("required_fingerprint").and_then(Value::as_str),
        pgp.get("observed_fingerprint").and_then(Value::as_str),
    ) && !required.eq_ignore_ascii_case(observed)
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-PROVENANCE",
            format!("{path}.oracle.pgp.observed_fingerprint"),
            "observed PGP fingerprint must match the required fingerprint",
        ));
    }
    if state == Some(ExecutionState::Observed)
        && pgp.get("signature_verified").and_then(Value::as_bool) != Some(true)
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-PROVENANCE",
            format!("{path}.oracle.pgp.signature_verified"),
            "observed oracle evidence requires signature_verified=true",
        ));
    }
}

fn is_hex_fingerprint(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_runtime(
    path: &str,
    runtime: &Map<String, Value>,
    state: Option<ExecutionState>,
    diagnostics: &mut Diagnostics,
) {
    let Some(java) = required_object(runtime, "java", path, diagnostics) else {
        return;
    };
    for field in ["vendor", "version", "vm"] {
        if state == Some(ExecutionState::Observed) {
            let _ = required_string(
                java,
                field,
                &format!("{path}.runtime.java"),
                "FIXTURE-SCHEMA",
                diagnostics,
            );
        } else if let Some(value) = java.get(field)
            && !matches!(value, Value::Null | Value::String(_))
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.runtime.java.{field}"),
                "must be a string or null for non-observed evidence",
            ));
        }
    }
    if state == Some(ExecutionState::Observed) {
        let _ = required_u64(java, "major", &format!("{path}.runtime.java"), diagnostics);
    } else if let Some(value) = java.get("major")
        && !matches!(value, Value::Null | Value::Number(_))
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.runtime.java.major"),
            "must be an integer or null for non-observed evidence",
        ));
    }
    for field in [
        "target_triple",
        "os_image",
        "locale",
        "timezone",
        "default_charset",
        "hostname_policy",
        "jmeter_classpath",
    ] {
        if state == Some(ExecutionState::Observed) {
            let _ = required_string(runtime, field, path, "FIXTURE-SCHEMA", diagnostics);
        } else if let Some(value) = runtime.get(field)
            && !matches!(value, Value::Null | Value::String(_))
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.runtime.{field}"),
                "must be a string or null for non-observed evidence",
            ));
        }
    }
    for field in [
        "environment_allowlist",
        "plugin_artifacts",
        "script_engines",
    ] {
        if state == Some(ExecutionState::Observed) {
            let _ = required_array(runtime, field, path, diagnostics);
        } else if let Some(value) = runtime.get(field)
            && !value.is_array()
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.runtime.{field}"),
                "must be an array for non-observed evidence when present",
            ));
        }
    }
}

// This helper keeps the case/provenance paths explicit at the validation
// boundary; grouping them would obscure which root each path is relative to.
#[allow(clippy::too_many_arguments)]
fn validate_inputs(
    root: &Path,
    fixture_root: &Path,
    path: &str,
    inputs: &Map<String, Value>,
    case_dir: &Path,
    case: &Map<String, Value>,
    state: Option<ExecutionState>,
    diagnostics: &mut Diagnostics,
) {
    validate_path_hash_refs(
        fixture_root,
        case_dir,
        &Value::Object(inputs.clone()),
        &format!("{path}.inputs"),
        state != Some(ExecutionState::Observed),
        diagnostics,
    );
    validate_keyed_path_hash_refs(
        root,
        case_dir,
        &Value::Object(inputs.clone()),
        &format!("{path}.inputs"),
        state != Some(ExecutionState::Observed),
        diagnostics,
    );
    validate_named_input_hashes(root, path, inputs, case_dir, case, state, diagnostics);
    let Some(plan) = case.get("plan").and_then(Value::as_object) else {
        validate_input_safety(path, inputs, diagnostics);
        return;
    };
    let Some(plan_path) = plan.get("path").and_then(Value::as_str) else {
        return;
    };
    if !is_safe_relative_path(plan_path) {
        return;
    }
    let plan_file = case_dir.join(plan_path);
    if let Some(expected_hash) = plan.get("sha256").and_then(Value::as_str) {
        match inputs.get("plan_sha256").and_then(Value::as_str) {
            Some(_) if is_placeholder_hash(expected_hash) => {}
            Some(actual) if actual == expected_hash => {}
            Some(actual) => diagnostics.push(Diagnostic::new(
                "FIXTURE-PROVENANCE",
                format!("{path}.inputs.plan_sha256"),
                format!("must match case plan.sha256 {expected_hash:?}, found {actual:?}"),
            )),
            None => diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.inputs.plan_sha256"),
                "required hash is missing or not a string",
            )),
        }
        if !is_placeholder_hash(expected_hash) {
            check_sha256(
                root,
                &plan_file,
                expected_hash,
                &format!("{path}.inputs.plan_sha256"),
                diagnostics,
            );
        }
    }
    let Some(case_properties) = case.get("property_files").and_then(Value::as_array) else {
        return;
    };
    let Some(provenance_properties) = inputs.get("property_sha256") else {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.inputs.property_sha256"),
            "required property hash is missing",
        ));
        return;
    };
    if case_properties.len() == 1 && !provenance_properties.is_string() {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.inputs.property_sha256"),
            "a single property file requires a string SHA-256 value",
        ));
    }
    if case_properties.len() > 1 {
        let expected_paths = case_properties
            .iter()
            .filter_map(Value::as_object)
            .filter_map(|property| property.get("path"))
            .filter_map(Value::as_str)
            .collect::<BTreeSet<_>>();
        if let Some(values) = provenance_properties.as_object() {
            for key in values.keys() {
                if !expected_paths.contains(key.as_str()) {
                    diagnostics.push(Diagnostic::new(
                        "FIXTURE-REFERENCE",
                        format!("{path}.inputs.property_sha256.{key}"),
                        "property hash key is not declared by case.property_files",
                    ));
                }
            }
        } else {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.inputs.property_sha256"),
                "multiple property files require an object keyed by relative path",
            ));
        }
    }
    for (position, value) in case_properties.iter().enumerate() {
        let Some(property) = value.as_object() else {
            continue;
        };
        let Some(property_path) = property.get("path").and_then(Value::as_str) else {
            continue;
        };
        if !is_safe_relative_path(property_path) {
            continue;
        }
        let Some(expected_hash) = property.get("sha256").and_then(Value::as_str) else {
            continue;
        };
        let actual_hash = if case_properties.len() == 1 {
            provenance_properties.as_str().map(str::to_owned)
        } else {
            provenance_properties
                .as_object()
                .and_then(|values| values.get(property_path))
                .and_then(Value::as_str)
                .map(str::to_owned)
        };
        if !is_placeholder_hash(expected_hash) && actual_hash.as_deref() != Some(expected_hash) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-PROVENANCE",
                format!("{path}.inputs.property_sha256[{position}]"),
                format!("must match case property {property_path:?} hash {expected_hash:?}"),
            ));
        }
        if !is_placeholder_hash(expected_hash) {
            check_sha256(
                root,
                &case_dir.join(property_path),
                expected_hash,
                &format!("{path}.inputs.property_sha256[{position}]"),
                diagnostics,
            );
        }
    }
    for (field, expected) in [
        ("public_network_used", false),
        ("secrets_or_credentials", false),
    ] {
        if required_bool(inputs, field, path, diagnostics) != Some(expected) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SAFETY",
                format!("{path}.inputs.{field}"),
                "must be false for checked-in repository fixtures",
            ));
        }
    }
    validate_input_safety(path, inputs, diagnostics);
}

fn validate_input_safety(path: &str, inputs: &Map<String, Value>, diagnostics: &mut Diagnostics) {
    for field in ["public_network_used", "secrets_or_credentials"] {
        match inputs.get(field).and_then(Value::as_bool) {
            Some(false) => {}
            Some(true) => diagnostics.push(Diagnostic::new(
                "FIXTURE-SAFETY",
                format!("{path}.inputs.{field}"),
                "must be false for checked-in fixtures",
            )),
            None => diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.inputs.{field}"),
                "required safety boolean is missing or has the wrong type",
            )),
        }
    }
}

// Hash-link validation needs both roots and the owning case to prevent a
// provenance declaration from being checked against the wrong fixture tree.
#[allow(clippy::too_many_arguments)]
fn validate_named_input_hashes(
    root: &Path,
    path: &str,
    inputs: &Map<String, Value>,
    case_dir: &Path,
    case: &Map<String, Value>,
    state: Option<ExecutionState>,
    diagnostics: &mut Diagnostics,
) {
    let mut case_hashes = BTreeMap::new();
    // Include every nested case declaration, including secondary plans,
    // distributed manifests, static inputs, source references, and artifact
    // contracts.  Restricting this walk to the historical top-level fields
    // lets a scalar provenance hash evade its declared path.
    collect_hash_refs(&Value::Object(case.clone()), &mut case_hashes);
    if let (Some(expected_path), Some(expected_hash)) = (
        case.get("execution")
            .and_then(Value::as_object)
            .and_then(|execution| execution.get("expected"))
            .and_then(Value::as_str),
        inputs.get("expected_sha256").and_then(Value::as_str),
    ) {
        case_hashes.insert(expected_path.to_owned(), expected_hash.to_owned());
    }
    // `inputs.property_sha256` is validated above against the case's explicit
    // property_files map.  Remove only that top-level field from the generic
    // traversal so a second property file cannot be selected by a basename
    // heuristic; nested/unexpected property hashes remain covered below.
    let mut traversed_inputs = inputs.clone();
    traversed_inputs.remove("property_sha256");
    walk_input_hashes(
        root,
        path,
        &Value::Object(traversed_inputs),
        case_dir,
        &case_hashes,
        state != Some(ExecutionState::Observed),
        diagnostics,
    );
}

fn collect_hash_refs(value: &Value, hashes: &mut BTreeMap<String, String>) {
    match value {
        Value::Array(values) => {
            for value in values {
                collect_hash_refs(value, hashes);
            }
        }
        Value::Object(object) => {
            if let (Some(path), Some(hash)) = (
                object.get("path").and_then(Value::as_str),
                object.get("sha256").and_then(Value::as_str),
            ) {
                hashes.insert(path.to_owned(), hash.to_owned());
            }
            for value in object.values() {
                collect_hash_refs(value, hashes);
            }
        }
        _ => {}
    }
}

// Recursive provenance traversal carries the immutable path/hash context
// explicitly so nested declarations cannot inherit an ambient default.
#[allow(clippy::too_many_arguments)]
fn walk_input_hashes(
    root: &Path,
    parent_path: &str,
    value: &Value,
    case_dir: &Path,
    case_hashes: &BTreeMap<String, String>,
    placeholder_allowed: bool,
    diagnostics: &mut Diagnostics,
) {
    match value {
        Value::Array(values) => {
            for (position, value) in values.iter().enumerate() {
                walk_input_hashes(
                    root,
                    &format!("{parent_path}[{position}]"),
                    value,
                    case_dir,
                    case_hashes,
                    placeholder_allowed,
                    diagnostics,
                );
            }
        }
        Value::Object(object) => {
            for (field, value) in object {
                let field_path = format!("{parent_path}.{field}");
                if field.ends_with("_sha256") {
                    if let Some(declared_path) = sibling_hash_path(object, field) {
                        validate_declared_file_hash(
                            root,
                            case_dir,
                            declared_path,
                            value,
                            &field_path,
                            placeholder_allowed,
                            diagnostics,
                        );
                    } else {
                        validate_input_hash_value(
                            root,
                            &field_path,
                            field,
                            value,
                            case_dir,
                            case_hashes,
                            placeholder_allowed,
                            diagnostics,
                        );
                    }
                }
                walk_input_hashes(
                    root,
                    &field_path,
                    value,
                    case_dir,
                    case_hashes,
                    placeholder_allowed,
                    diagnostics,
                );
            }
        }
        _ => {}
    }
}

fn sibling_hash_path<'a>(object: &'a Map<String, Value>, field: &str) -> Option<&'a str> {
    let stem = field.strip_suffix("_sha256")?;
    for candidate in [
        format!("{stem}_path"),
        format!("{stem}_source"),
        format!("{stem}_file"),
        stem.to_owned(),
    ] {
        if let Some(path) = object.get(&candidate).and_then(Value::as_str) {
            return Some(path);
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn validate_input_hash_value(
    root: &Path,
    field_path: &str,
    field: &str,
    value: &Value,
    case_dir: &Path,
    case_hashes: &BTreeMap<String, String>,
    placeholder_allowed: bool,
    diagnostics: &mut Diagnostics,
) {
    let Some(value) = value.as_str() else {
        if let Some(values) = value.as_object() {
            for (declared_path, declared_hash) in values {
                let Some(declared_hash) = declared_hash.as_str() else {
                    diagnostics.push(Diagnostic::new(
                        "FIXTURE-SCHEMA",
                        format!("{field_path}.{declared_path}"),
                        "path-keyed SHA-256 declaration must be a string",
                    ));
                    continue;
                };
                if is_placeholder_hash(declared_hash) {
                    if !placeholder_allowed {
                        diagnostics.push(Diagnostic::new(
                            "FIXTURE-PROVENANCE",
                            format!("{field_path}.{declared_path}"),
                            "observed input cannot contain an unresolved digest",
                        ));
                    }
                    continue;
                }
                if !is_sha256(declared_hash) {
                    diagnostics.push(Diagnostic::new(
                        "FIXTURE-SCHEMA",
                        format!("{field_path}.{declared_path}"),
                        "must be a lowercase SHA-256 digest",
                    ));
                    continue;
                }
                if !is_safe_relative_path(declared_path) {
                    diagnostics.push(Diagnostic::new(
                        "FIXTURE-PATH",
                        format!("{field_path}.{declared_path}"),
                        "declared hash path must be safe and relative",
                    ));
                    continue;
                }
                if let Some(expected_hash) = case_hashes.get(declared_path)
                    && !is_placeholder_hash(expected_hash)
                    && expected_hash != declared_hash
                {
                    diagnostics.push(Diagnostic::new(
                        "FIXTURE-PROVENANCE",
                        format!("{field_path}.{declared_path}"),
                        "must match the case path/hash declaration",
                    ));
                }
                check_sha256(
                    root,
                    &case_dir.join(declared_path),
                    declared_hash,
                    &format!("{field_path}.{declared_path}"),
                    diagnostics,
                );
            }
        } else {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                field_path,
                "SHA-256 declaration must be a string or path-keyed object",
            ));
        }
        return;
    };
    if is_placeholder_hash(value) {
        if !placeholder_allowed {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-PROVENANCE",
                field_path,
                "observed input cannot contain an unresolved digest",
            ));
        }
        return;
    }
    if !is_sha256(value) {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            field_path,
            "must be a lowercase SHA-256 digest",
        ));
        return;
    }
    if field == "profile_sha256" {
        check_sha256(
            root,
            &root.join("compat/profiles/jmeter-5.6.3.json"),
            value,
            field_path,
            diagnostics,
        );
        return;
    }
    if field == "case_manifest_sha256" {
        check_sha256(
            root,
            &case_dir.join("case.json"),
            value,
            field_path,
            diagnostics,
        );
        return;
    }
    if field == "expected_semantic_sha256" {
        check_sha256(
            root,
            &case_dir.join("expected/semantic.json"),
            value,
            field_path,
            diagnostics,
        );
        return;
    }
    let stem = field.trim_end_matches("_sha256");
    let matches = case_hashes
        .iter()
        .filter(|(path, _)| hash_field_matches_path(stem, path))
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [(declared_path, declared_hash)] => {
            if !is_placeholder_hash(declared_hash) && *declared_hash != value {
                diagnostics.push(Diagnostic::new(
                    "FIXTURE-PROVENANCE",
                    field_path,
                    format!("must match case declaration for {declared_path:?}"),
                ));
            }
            let declared_file = resolve_declared_hash_path(root, case_dir, declared_path);
            check_sha256(root, &declared_file, value, field_path, diagnostics);
        }
        [] => diagnostics.push(Diagnostic::new(
            "FIXTURE-REFERENCE",
            field_path,
            "scalar SHA-256 declaration does not match any declared input, expected, probe, or artifact path",
        )),
        _ => diagnostics.push(Diagnostic::new(
            "FIXTURE-REFERENCE",
            field_path,
            "scalar SHA-256 declaration matches multiple paths; use an explicit path-keyed declaration",
        )),
    }
}

fn hash_field_matches_path(field: &str, path: &str) -> bool {
    let normalize = |value: &str| {
        value
            .trim_end_matches(".json")
            .replace(['_', '-', '/'], "")
            .to_ascii_lowercase()
    };
    let field = normalize(field);
    let basename = Path::new(path)
        .file_stem()
        .and_then(|value| value.to_str())
        .map(normalize)
        .unwrap_or_default();
    let path_normalized = normalize(path);
    let lower_path = path.to_ascii_lowercase();
    if field == "expectedapi" {
        return lower_path.ends_with("/expected/api.json") || lower_path == "expected/api.json";
    }
    if field == "expected" || field.starts_with("expected") {
        return lower_path.contains("/expected/")
            || lower_path.contains("expected")
            || basename.starts_with("expected");
    }
    if field == "harness" {
        return lower_path.contains("harness");
    }
    if field == "server" {
        return lower_path.contains("server");
    }
    if field == "tracecontract" {
        return lower_path.contains("trace-contract")
            || lower_path.contains("trace_contract")
            || lower_path.contains("tracecontract");
    }
    if field == "casemanifest" {
        return lower_path.ends_with("/case.json") || lower_path == "case.json";
    }
    basename == field
        || path_normalized.ends_with(&field)
        || field
            .strip_prefix("expected")
            .is_some_and(|short| basename == short || path_normalized.ends_with(short))
}

fn resolve_declared_hash_path(root: &Path, case_dir: &Path, declared_path: &str) -> PathBuf {
    if declared_path.starts_with("compat/")
        || declared_path.starts_with("fuzz/")
        || declared_path.starts_with("docs/")
        || declared_path == "Cargo.toml"
        || declared_path == "Cargo.lock"
        || declared_path.starts_with("rust-toolchain")
    {
        root.join(declared_path)
    } else {
        case_dir.join(declared_path)
    }
}

fn safe_fixture_path(fixture_root: &Path, base: &Path, value: &str) -> Option<PathBuf> {
    if value.is_empty()
        || value.contains('\0')
        || value.contains('\\')
        || Path::new(value).is_absolute()
    {
        return None;
    }
    let mut path = base.to_path_buf();
    for component in Path::new(value).components() {
        match component {
            Component::CurDir => {}
            Component::Normal(component) => path.push(component),
            Component::ParentDir => {
                if path == fixture_root || !path.pop() {
                    return None;
                }
            }
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    if path.strip_prefix(fixture_root).is_ok() {
        Some(path)
    } else {
        None
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_expectation(
    root: &Path,
    path: &Path,
    value: &Value,
    profile: &ProfileIndex,
    expected_case_id: Option<&str>,
    expected_case: Option<&Map<String, Value>>,
    expected_case_state: Option<ExecutionState>,
    diagnostics: &mut Diagnostics,
) {
    let display = display_path(root, path);
    let Some(object) = value.as_object() else {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            display,
            "expectation JSON must be an object",
        ));
        return;
    };
    let schema_id = match object.get("schema_id").and_then(Value::as_str) {
        Some(schema_id)
            if schema_id == EXPECTATION_SCHEMA_ID
                || CUSTOM_EXPECTATION_SCHEMAS.contains(&schema_id) =>
        {
            schema_id
        }
        Some(schema_id) => {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{display}.schema_id"),
                format!("unsupported fixture schema {schema_id:?}"),
            ));
            return;
        }
        None => {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{display}.schema_id"),
                "required schema_id string is missing",
            ));
            return;
        }
    };
    if object.get("schema_version").and_then(Value::as_u64) != Some(SCHEMA_VERSION) {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{display}.schema_version"),
            format!("must be schema version {SCHEMA_VERSION}"),
        ));
    }
    if let Some(profile_id) = object.get("profile_id").and_then(Value::as_str)
        && profile_id != profile.profile_id
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-REFERENCE",
            format!("{display}.profile_id"),
            format!("must match active profile {:?}", profile.profile_id),
        ));
    }
    if let Some(case_id) = object.get("case_id").and_then(Value::as_str)
        && let Some(expected_case_id) = expected_case_id
        && case_id != expected_case_id
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-REFERENCE",
            format!("{display}.case_id"),
            format!("must match case manifest case_id {expected_case_id:?}"),
        ));
    }
    check_expectation_normalization_refs(object, &display, profile, diagnostics);
    let expectation_state = expectation_state(object);
    validate_quarantine_markers(object, &display, expectation_state, diagnostics);
    validate_quarantine_materialization(object, &display, expectation_state, diagnostics);
    validate_nested_schema_ids(object, &display, diagnostics);
    validate_custom_identity(object, &display, profile, diagnostics);
    validate_bound_sections(object, &display, diagnostics);
    validate_digest_fields(object, &display, expectation_state, diagnostics);
    check_expectation_evidence(
        root,
        object,
        schema_id,
        &display,
        profile,
        expected_case_id,
        expected_case_state,
        expectation_state,
        diagnostics,
    );
    if schema_id != EXPECTATION_SCHEMA_ID {
        validate_custom_schema(
            schema_id,
            object,
            &display,
            expected_case,
            profile,
            diagnostics,
        );
        validate_custom_envelope(object, &display, diagnostics);
        // Custom descriptors intentionally own their schema.  Common identity,
        // provenance, digest, and normalization checks above still apply; the
        // validator must not reinterpret unknown fields or discard them.
        return;
    }
    let format = required_string(object, "format", &display, "FIXTURE-SCHEMA", diagnostics);
    if let Some(format) = format.as_deref()
        && !matches!(format, "jmx-semantic" | "jtl-xml" | "jtl-csv")
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{display}.format"),
            format!("unsupported expectation format {format:?}"),
        ));
    }
    // JTL expectations count emitted samples; JMX semantic expectations use
    // topology/property arrays instead and intentionally have no count.
    if format.as_deref() == Some("jtl-xml") {
        let _ = required_u64(object, "sample_count", &display, diagnostics);
    } else if format.as_deref() == Some("jtl-csv") {
        let _ = required_array(object, "header", &display, diagnostics);
        let _ = required_array(object, "rows", &display, diagnostics);
    }
    let Some(normalization) = required_object(object, "normalization", &display, diagnostics)
    else {
        return;
    };
    let _ = required_array(
        normalization,
        "ignored_fields",
        &format!("{display}.normalization"),
        diagnostics,
    );
    if normalization.contains_key("required_fields") {
        let _ = required_array(
            normalization,
            "required_fields",
            &format!("{display}.normalization"),
            diagnostics,
        );
    }
    if expectation_state == Some(ExecutionState::Observed)
        || !normalization.contains_key("required_fields")
    {
        let _ = required_string(
            normalization,
            "reason",
            &format!("{display}.normalization"),
            "FIXTURE-SCHEMA",
            diagnostics,
        );
    }
}

fn validate_custom_identity(
    object: &Map<String, Value>,
    path: &str,
    profile: &ProfileIndex,
    diagnostics: &mut Diagnostics,
) {
    if let Some(profile_id) = object.get("profile_id").and_then(Value::as_str) {
        if profile_id != profile.profile_id {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-REFERENCE",
                format!("{path}.profile_id"),
                format!("must match active profile {:?}", profile.profile_id),
            ));
        }
    } else {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.profile_id"),
            "custom fixture schema requires a profile_id string",
        ));
    }
    if let Some(fixture_family_id) = object.get("fixture_family_id").and_then(Value::as_str)
        && !profile.fixture_ids.contains(fixture_family_id)
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-REFERENCE",
            format!("{path}.fixture_family_id"),
            format!("unknown profile fixture family {fixture_family_id:?}"),
        ));
    }
    if object.contains_key("conformance_ids") {
        check_id_array(
            object,
            "conformance_ids",
            path,
            &profile.feature_ids,
            diagnostics,
            true,
        );
    }
    if object.contains_key("external_runtime_boundary_ids") {
        check_id_array(
            object,
            "external_runtime_boundary_ids",
            path,
            &profile.boundary_ids,
            diagnostics,
            false,
        );
        if let (Some(boundaries), Some(features)) = (
            object
                .get("external_runtime_boundary_ids")
                .and_then(Value::as_array),
            object.get("conformance_ids").and_then(Value::as_array),
        ) {
            let feature_ids = features
                .iter()
                .filter_map(Value::as_str)
                .collect::<BTreeSet<_>>();
            for (position, boundary) in boundaries.iter().enumerate() {
                let Some(boundary) = boundary.as_str() else {
                    continue;
                };
                if !feature_ids.iter().any(|feature| {
                    profile
                        .feature_boundaries
                        .get(*feature)
                        .is_some_and(|declared| declared.contains(boundary))
                }) {
                    diagnostics.push(Diagnostic::new(
                        "FIXTURE-REFERENCE",
                        format!("{path}.external_runtime_boundary_ids[{position}]"),
                        format!("boundary {boundary:?} is not owned by a conformance feature"),
                    ));
                }
            }
        }
    }
}

fn validate_custom_schema(
    schema_id: &str,
    object: &Map<String, Value>,
    path: &str,
    expected_case: Option<&Map<String, Value>>,
    profile: &ProfileIndex,
    diagnostics: &mut Diagnostics,
) {
    // Every supported custom ID has a named branch.  This is intentionally
    // verbose: adding a manifest schema requires adding its structural
    // validator instead of silently inheriting an underspecified catch-all.
    match schema_id {
        "jmeter-rs.cli-option-catalog" => {
            let _ = required_string(object, "source", path, "FIXTURE-SCHEMA", diagnostics);
            let _ = required_u64(object, "option_count", path, diagnostics);
            let _ = required_array(object, "options", path, diagnostics);
            let _ = required_object(object, "help_version_vocabulary", path, diagnostics);
        }
        "jmeter-rs.cli-process-contract" => {
            optional_object(object, "logging", path, diagnostics);
            optional_array(object, "exit_contracts", path, diagnostics);
            optional_object(object, "future_observations", path, diagnostics);
            optional_object(object, "comparator_contract", path, diagnostics);
            optional_object(object, "planned_assertions", path, diagnostics);
        }
        "jmeter-rs.cli-runner-contract" => {
            let _ = required_string(object, "purpose", path, "FIXTURE-SCHEMA", diagnostics);
            let _ = required_object(object, "argv_materialization", path, diagnostics);
            let _ = required_object(object, "platform_materialization", path, diagnostics);
            let _ = required_object(object, "filesystem_setup", path, diagnostics);
            let _ = required_object(object, "process_lifecycle", path, diagnostics);
            let _ = required_object(object, "observation_rules", path, diagnostics);
        }
        "jmeter-rs.cli-scenario-descriptors" => {
            let _ = required_string(object, "argv_policy", path, "FIXTURE-SCHEMA", diagnostics);
            let _ = required_u64(object, "scenario_count", path, diagnostics);
            let _ = required_array(object, "scenarios", path, diagnostics);
            let _ = required_array(object, "scenario_coverage_notes", path, diagnostics);
        }
        "jmeter-rs.configuration-projection" => {
            let _ = required_string(
                object,
                "projection_schema",
                path,
                "FIXTURE-SCHEMA",
                diagnostics,
            );
            let _ = required_u64(object, "projection_schema_version", path, diagnostics);
            let _ = required_array(object, "coverage", path, diagnostics);
            optional_object(object, "source_semantics", path, diagnostics);
            optional_object(object, "plan_projection", path, diagnostics);
            optional_object(object, "normalization", path, diagnostics);
        }
        "jmeter-rs.file-artifact-contract" => {
            validate_file_artifact_contract(object, path, diagnostics);
        }
        "jmeter-rs.fixture-bounds" => {
            let _ = required_object(object, "bounds", path, diagnostics);
        }
        "jmeter-rs.fuzz-artifact" => {
            let _ = required_string(object, "kind", path, "FIXTURE-SCHEMA", diagnostics);
            let _ = required_string(object, "status", path, "FIXTURE-SCHEMA", diagnostics);
        }
        "jmeter-rs.fuzz-campaign-evidence" | "jmeter-rs.fuzz-campaign-expectation" => {
            validate_fuzz_campaign(object, path, expected_case, diagnostics);
        }
        "jmeter-rs.fuzz-campaign-evidence-schema" => {
            let _ = required_string(
                object,
                "evidence_schema_id",
                path,
                "FIXTURE-SCHEMA",
                diagnostics,
            );
            let _ = required_array(object, "required", path, diagnostics);
            let _ = required_object(object, "properties", path, diagnostics);
        }
        "jmeter-rs.gui-filesystem-descriptor" => {
            let _ = required_array(object, "roots", path, diagnostics);
            let _ = required_array(object, "artifact_contracts", path, diagnostics);
            let _ = required_object(object, "path_tokens", path, diagnostics);
            let _ = required_object(object, "mutation_policy", path, diagnostics);
        }
        "jmeter-rs.gui-persistence-expectation" => {
            let _ = required_object(object, "contracts", path, diagnostics);
            let _ = required_object(object, "headless_contract", path, diagnostics);
            let _ = required_object(object, "oracle_observation", path, diagnostics);
        }
        "jmeter-rs.gui-platform-expectation" => {
            let _ = required_object(object, "settings", path, diagnostics);
            let _ = required_array(object, "platform_rows", path, diagnostics);
            let _ = required_object(object, "laf_contract", path, diagnostics);
            let _ = required_object(object, "oracle_observation", path, diagnostics);
        }
        "jmeter-rs.gui-platform-matrix" => {
            let _ = required_object(object, "common", path, diagnostics);
            let _ = required_array(object, "platforms", path, diagnostics);
            let _ = required_object(object, "normalization", path, diagnostics);
        }
        "jmeter-rs.harness-evidence" => {
            let _ = required_object(object, "materialization", path, diagnostics);
            let _ = required_object(object, "oracle_execution", path, diagnostics);
            let _ = required_object(object, "artifact_verification", path, diagnostics);
            let _ = required_object(object, "comparison", path, diagnostics);
            let _ = required_object(object, "release_conformance", path, diagnostics);
            validate_materialization_claim(object, path, diagnostics);
        }
        "jmeter-rs.harness-evidence-schema" => {
            let _ = required_array(object, "required", path, diagnostics);
            let _ = required_object(object, "properties", path, diagnostics);
        }
        "jmeter-rs.harness-manifest" => {
            let _ = required_object(object, "profile", path, diagnostics);
            let _ = required_object(object, "pinned_oracle", path, diagnostics);
            let _ = required_object(object, "verification_gates", path, diagnostics);
            let _ = required_object(object, "repository_inputs", path, diagnostics);
            validate_materialization_claim(object, path, diagnostics);
        }
        "jmeter-rs.harness-manifest-schema" => {
            let _ = required_array(object, "required", path, diagnostics);
            let _ = required_object(object, "properties", path, diagnostics);
        }
        "jmeter-rs.harness-normalized-diff" => {
            optional_array(object, "differences", path, diagnostics);
            optional_array(object, "ignored_fields", path, diagnostics);
            optional_u64(object, "difference_count", path, diagnostics);
            optional_string(object, "raw_reference", path, diagnostics);
        }
        "jmeter-rs.http-sampler-ready"
        | "jmeter-rs.proxy-recorder-ready"
        | "jmeter-rs.proxy-tls-ready" => {
            let _ = required_object(object, "readiness", path, diagnostics);
        }
        "jmeter-rs.http-trace" => {
            validate_http_trace(object, path, expected_case, profile, diagnostics);
        }
        "jmeter-rs.planned-constraint-contract" => {
            validate_planned_constraint_contract(object, path, diagnostics);
        }
        "jmeter-rs.proxy-mirror-api-expectation" => {
            validate_proxy_mirror_api_expectation(object, path, diagnostics);
        }
        "jmeter-rs.proxy-mirror-expectation" => {
            validate_proxy_mirror_expectation(object, path, diagnostics);
        }
        "jmeter-rs.proxy-mirror-inputs" => {
            validate_proxy_mirror_inputs(object, path, diagnostics);
        }
        _ => diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.schema_id"),
            format!("unsupported custom schema {schema_id:?}"),
        )),
    }
    validate_common_custom_schema(object, path, diagnostics);
}

fn validate_planned_constraint_contract(
    object: &Map<String, Value>,
    path: &str,
    diagnostics: &mut Diagnostics,
) {
    const FIELDS: &[&str] = &[
        "schema_id",
        "schema_version",
        "profile_id",
        "fixture_family_id",
        "case_id",
        "conformance_ids",
        "normalization_policy_refs",
        "external_runtime_boundary_ids",
        "expectation_basis",
        "descriptor_kind",
        "status",
        "evidence_status",
        "oracle_status",
        "artifacts_present",
        "plugin_artifacts",
        "aliases",
        "function_contract",
        "property_order_contract",
        "ordering_contract",
        "roots_in_discovery_order",
        "capability_matrix",
        "requests",
        "user_class_roots",
        "classes_present",
        "no_drop_contract",
        "bounds",
        "bounds_contract",
        "invariants",
        "planned_invariants",
        "negative_cases",
        "planned_constraints",
        "constraint_schema",
        "controller_contract",
        "controller_contracts",
        "lifecycle_contract",
        "comparator_contract",
        "assertion_results",
        "expansion_phase_contract",
        "side_effect_probe_contract",
        "sample_contract",
        "save_service_contract",
        "trace_shape",
        "expected_counts",
        "sample_count",
        "sample_count_asserted",
        "samples",
        "format",
        "root",
        "normalization",
        "generated_from",
        "raw_artifacts",
        "source_only",
        "preserved_wire_values",
        "unordered_segments",
        "ordered_prefix",
        "ordered_suffix",
    ];
    for field in object.keys() {
        if !FIELDS.contains(&field.as_str()) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.{field}"),
                "unknown planned-constraint field is not permitted",
            ));
        }
    }
    let _ = required_string(
        object,
        "expectation_basis",
        path,
        "FIXTURE-SCHEMA",
        diagnostics,
    );
    for field in ["descriptor_kind", "status"] {
        let valid = object
            .get(field)
            .is_none_or(|value| value.is_null() || value.is_string());
        if !valid {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.{field}"),
                "planned-constraint field must be a string or explicit null",
            ));
        }
    }
    let status = object.get("status").and_then(Value::as_str);
    if status.is_some_and(|status| {
        !matches!(
            status,
            "declarative-static-only" | "not-run" | "planned" | "planned-only" | "static-only"
        )
    }) {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.status"),
            "planned-constraint status must remain a closed static/planned value",
        ));
    }
    for field in [
        "plugin_artifacts",
        "aliases",
        "capability_matrix",
        "requests",
        "user_class_roots",
        "negative_cases",
        "samples",
        "ordered_prefix",
        "ordered_suffix",
    ] {
        optional_array(object, field, path, diagnostics);
    }
    for field in [
        "function_contract",
        "property_order_contract",
        "ordering_contract",
        "no_drop_contract",
        "bounds",
        "bounds_contract",
        "planned_constraints",
        "controller_contract",
        "lifecycle_contract",
        "comparator_contract",
        "expansion_phase_contract",
        "side_effect_probe_contract",
        "sample_contract",
        "save_service_contract",
        "trace_shape",
        "expected_counts",
        "root",
        "normalization",
        "generated_from",
    ] {
        optional_object(object, field, path, diagnostics);
    }
    for field in [
        "controller_contracts",
        "preserved_wire_values",
        "unordered_segments",
    ] {
        optional_array(object, field, path, diagnostics);
    }
    for field in ["invariants", "planned_invariants"] {
        optional_array_or_object(object, field, path, diagnostics);
    }
    if let Some(value) = object.get("constraint_schema")
        && !value.is_null()
        && !value.is_string()
        && !value.is_object()
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.constraint_schema"),
            "constraint_schema must be a string, object, or explicit null",
        ));
    }
    if let Some(value) = object.get("source_only")
        && !value.is_boolean()
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.source_only"),
            "source_only must be a boolean",
        ));
    }
    for field in [
        "artifacts_present",
        "classes_present",
        "sample_count_asserted",
    ] {
        if let Some(value) = object.get(field)
            && !value.is_boolean()
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.{field}"),
                "planned-constraint boolean field has the wrong type",
            ));
        }
    }
    if let Some(value) = object.get("sample_count")
        && !value.is_u64()
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.sample_count"),
            "planned-constraint sample_count must be a non-negative integer",
        ));
    }
    if object.contains_key("artifact_status") || object.contains_key("artifacts") {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.schema_id"),
            "file-artifact contracts must use jmeter-rs.file-artifact-contract",
        ));
    }
}

const FUZZ_CAMPAIGN_FIELDS: [&str; 20] = [
    "schema_id",
    "schema_version",
    "evidence_schema_id",
    "case_id",
    "profile_id",
    "fixture_family_id",
    "conformance_ids",
    "normalization_policy_refs",
    "evidence_status",
    "status",
    "not_run",
    "campaign",
    "runner",
    "targets",
    "corpus",
    "invariants",
    "target_outcomes",
    "outcome",
    "artifacts",
    "generated_from",
];

const FUZZ_COUNT_FIELDS: [&str; 8] = [
    "executions",
    "accepted_inputs",
    "rejected_inputs",
    "crashes",
    "hangs",
    "timeouts",
    "sanitizer_findings",
    "resource_limit_failures",
];

fn validate_fuzz_campaign(
    object: &Map<String, Value>,
    path: &str,
    expected_case: Option<&Map<String, Value>>,
    diagnostics: &mut Diagnostics,
) {
    for field in object.keys() {
        if !FUZZ_CAMPAIGN_FIELDS.contains(&field.as_str()) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.{field}"),
                "unknown fuzz campaign field is not permitted",
            ));
        }
    }
    let _ = required_string(
        object,
        "evidence_schema_id",
        path,
        "FIXTURE-SCHEMA",
        diagnostics,
    );
    let status = required_string(object, "status", path, "FIXTURE-SCHEMA", diagnostics);
    if status
        .as_deref()
        .is_some_and(|status| !matches!(status, "planned" | "external" | "verified" | "blocked"))
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.status"),
            "fuzz campaign status must be planned, external, verified, or blocked",
        ));
    }
    let evidence_status = required_string(
        object,
        "evidence_status",
        path,
        "FIXTURE-SCHEMA",
        diagnostics,
    );
    if evidence_status
        .as_deref()
        .and_then(|value| parse_expectation_state(&Value::String(value.to_owned())))
        .is_none()
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.evidence_status"),
            "fuzz evidence_status must use a closed execution-state vocabulary",
        ));
    }
    let not_run = required_bool(object, "not_run", path, diagnostics);
    if not_run == Some(true) && status.as_deref() != Some("planned") {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-EVIDENCE",
            format!("{path}.not_run"),
            "not_run=true requires status=planned",
        ));
    }
    let Some(campaign) = required_object(object, "campaign", path, diagnostics) else {
        return;
    };
    validate_fuzz_campaign_header(campaign, &format!("{path}.campaign"), diagnostics);
    let Some(runner) = required_object(object, "runner", path, diagnostics) else {
        return;
    };
    validate_fuzz_runner(runner, &format!("{path}.runner"), diagnostics);
    let Some(targets) = required_array(object, "targets", path, diagnostics) else {
        return;
    };
    let target_index = validate_fuzz_targets(
        targets,
        &format!("{path}.targets"),
        expected_case,
        diagnostics,
    );
    let Some(corpus) = required_object(object, "corpus", path, diagnostics) else {
        return;
    };
    validate_fuzz_corpus(
        corpus,
        &format!("{path}.corpus"),
        expected_case,
        &target_index,
        diagnostics,
    );
    let Some(invariants) = required_array(object, "invariants", path, diagnostics) else {
        return;
    };
    let invariant_index = validate_fuzz_invariants(
        invariants,
        &format!("{path}.invariants"),
        expected_case,
        diagnostics,
    );
    validate_fuzz_target_outcomes(
        object.get("target_outcomes"),
        &format!("{path}.target_outcomes"),
        &target_index,
        &invariant_index,
        runner,
        diagnostics,
    );
    validate_fuzz_outcome(
        object.get("outcome"),
        &format!("{path}.outcome"),
        &target_index,
        runner,
        campaign,
        diagnostics,
    );
    validate_fuzz_artifacts(
        object.get("artifacts"),
        &format!("{path}.artifacts"),
        object,
        runner,
        campaign,
        &invariant_index,
        diagnostics,
    );
}

fn validate_fuzz_campaign_header(
    campaign: &Map<String, Value>,
    path: &str,
    diagnostics: &mut Diagnostics,
) {
    const FIELDS: [&str; 6] = [
        "campaign_id",
        "source_revision",
        "started_at",
        "finished_at",
        "seed",
        "configuration",
    ];
    for field in campaign.keys() {
        if !FIELDS.contains(&field.as_str()) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.{field}"),
                "unknown campaign field is not permitted",
            ));
        }
    }
    let _ = required_string(campaign, "campaign_id", path, "FIXTURE-SCHEMA", diagnostics);
    for field in ["source_revision", "started_at", "finished_at", "seed"] {
        let _ = required_string(campaign, field, path, "FIXTURE-SCHEMA", diagnostics);
    }
    let Some(configuration) = required_object(campaign, "configuration", path, diagnostics) else {
        return;
    };
    const CONFIG_FIELDS: [&str; 12] = [
        "runs_per_target",
        "wall_seconds_per_target",
        "testcase_timeout_seconds",
        "rss_limit_megabytes",
        "max_input_bytes",
        "max_total_artifact_bytes",
        "max_single_artifact_bytes",
        "max_log_bytes",
        "network",
        "child_processes",
        "script_execution",
        "java_or_jmeter",
    ];
    for field in configuration.keys() {
        if field != "argv_templates" && !CONFIG_FIELDS.contains(&field.as_str()) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.configuration.{field}"),
                "unknown campaign configuration field is not permitted",
            ));
        }
    }
    for field in [
        "runs_per_target",
        "wall_seconds_per_target",
        "testcase_timeout_seconds",
        "rss_limit_megabytes",
        "max_input_bytes",
        "max_total_artifact_bytes",
        "max_single_artifact_bytes",
        "max_log_bytes",
    ] {
        let _ = required_u64(
            configuration,
            field,
            &format!("{path}.configuration"),
            diagnostics,
        );
    }
    if configuration.get("network").and_then(Value::as_str) != Some("none") {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SAFETY",
            format!("{path}.configuration.network"),
            "fuzz campaign network policy must be none",
        ));
    }
    for field in ["child_processes", "script_execution", "java_or_jmeter"] {
        if required_bool(
            configuration,
            field,
            &format!("{path}.configuration"),
            diagnostics,
        ) == Some(true)
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SAFETY",
                format!("{path}.configuration.{field}"),
                "fuzz campaign must not enable process, script, or Java/JMeter execution",
            ));
        }
    }
    if let Some(argv_templates) = configuration.get("argv_templates") {
        let Some(argv_templates) = argv_templates.as_array() else {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.configuration.argv_templates"),
                "argv_templates must be an array of string arrays",
            ));
            return;
        };
        for (position, template) in argv_templates.iter().enumerate() {
            let Some(template) = template.as_array() else {
                diagnostics.push(Diagnostic::new(
                    "FIXTURE-SCHEMA",
                    format!("{path}.configuration.argv_templates[{position}]"),
                    "argv template must be an array",
                ));
                continue;
            };
            for (argument, value) in template.iter().enumerate() {
                if value.as_str().is_none() {
                    diagnostics.push(Diagnostic::new(
                        "FIXTURE-SCHEMA",
                        format!("{path}.configuration.argv_templates[{position}][{argument}]"),
                        "argv template members must be strings",
                    ));
                }
            }
        }
    } else {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.configuration.argv_templates"),
            "campaign configuration requires argv_templates",
        ));
    }
}

fn validate_fuzz_runner(runner: &Map<String, Value>, path: &str, diagnostics: &mut Diagnostics) {
    const FIELDS: [&str; 4] = ["toolchain", "cargo_fuzz", "libfuzzer_sys", "flags"];
    for field in runner.keys() {
        if !FIELDS.contains(&field.as_str()) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.{field}"),
                "unknown fuzz runner field is not permitted",
            ));
        }
    }
    for field in ["toolchain", "cargo_fuzz", "libfuzzer_sys"] {
        let _ = required_string(runner, field, path, "FIXTURE-SCHEMA", diagnostics);
    }
    if runner.get("libfuzzer_sys").and_then(Value::as_str) != Some("0.4.13") {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-REFERENCE",
            format!("{path}.libfuzzer_sys"),
            "libfuzzer_sys must be pinned to 0.4.13",
        ));
    }
    let _ = required_string_list(runner, "flags", path, diagnostics);
}

fn validate_fuzz_targets(
    targets: &[Value],
    path: &str,
    expected_case: Option<&Map<String, Value>>,
    diagnostics: &mut Diagnostics,
) -> BTreeMap<String, Map<String, Value>> {
    let mut index = BTreeMap::new();
    for (position, value) in targets.iter().enumerate() {
        let item_path = format!("{path}[{position}]");
        let Some(target) = value.as_object() else {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                item_path,
                "fuzz target must be an object",
            ));
            continue;
        };
        const FIELDS: [&str; 8] = [
            "target",
            "source_path",
            "source_sha256",
            "corpus_directory",
            "bounds",
            "invariant_ids",
            "corpus_seed_count",
            "corpus_bytes",
        ];
        for field in target.keys() {
            if !FIELDS.contains(&field.as_str()) {
                diagnostics.push(Diagnostic::new(
                    "FIXTURE-SCHEMA",
                    format!("{item_path}.{field}"),
                    "unknown fuzz target field is not permitted",
                ));
            }
        }
        let Some(name) =
            required_string(target, "target", &item_path, "FIXTURE-SCHEMA", diagnostics)
        else {
            continue;
        };
        if index.insert(name.clone(), target.clone()).is_some() {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-REFERENCE",
                format!("{item_path}.target"),
                format!("duplicate fuzz target {name:?}"),
            ));
        }
        for field in ["source_path", "corpus_directory"] {
            let _ = required_string(target, field, &item_path, "FIXTURE-SCHEMA", diagnostics);
        }
        if let Some(hash) = required_string(
            target,
            "source_sha256",
            &item_path,
            "FIXTURE-SCHEMA",
            diagnostics,
        ) && !is_sha256(&hash)
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{item_path}.source_sha256"),
                "source_sha256 must be lowercase SHA-256",
            ));
        }
        let _ = required_object(target, "bounds", &item_path, diagnostics);
        let _ = required_string_list(target, "invariant_ids", &item_path, diagnostics);
        let _ = required_u64(target, "corpus_seed_count", &item_path, diagnostics);
        let _ = required_u64(target, "corpus_bytes", &item_path, diagnostics);
        if let Some(expected) = fuzz_source_reference(expected_case, "targets", &name) {
            for field in [
                "source_path",
                "source_sha256",
                "corpus_directory",
                "bounds",
                "invariant_ids",
                "corpus_seed_count",
                "corpus_bytes",
            ] {
                let source_field = match field {
                    "source_path" => "path",
                    "source_sha256" => "sha256",
                    other => other,
                };
                if target.get(field) != expected.get(source_field) {
                    diagnostics.push(Diagnostic::new(
                        "FIXTURE-REFERENCE",
                        format!("{item_path}.{field}"),
                        format!("must exactly match source_references.targets entry for {name:?}"),
                    ));
                }
            }
        }
    }
    if let Some(expected_case) = expected_case {
        let expected = expected_case
            .get("source_references")
            .and_then(Value::as_object)
            .and_then(|refs| refs.get("targets"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_object)
            .filter_map(|target| target.get("target").and_then(Value::as_str))
            .collect::<BTreeSet<_>>();
        let actual = index.keys().map(String::as_str).collect::<BTreeSet<_>>();
        if actual != expected {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-COVERAGE",
                path.to_owned(),
                format!("target set must exactly match case source references: expected {expected:?}, found {actual:?}"),
            ));
        }
    }
    index
}

fn fuzz_source_reference<'a>(
    expected_case: Option<&'a Map<String, Value>>,
    section: &str,
    name: &str,
) -> Option<&'a Map<String, Value>> {
    expected_case?
        .get("source_references")?
        .as_object()?
        .get(section)?
        .as_array()?
        .iter()
        .filter_map(Value::as_object)
        .find(|item| item.get("target").and_then(Value::as_str) == Some(name))
}

fn validate_fuzz_corpus(
    corpus: &Map<String, Value>,
    path: &str,
    expected_case: Option<&Map<String, Value>>,
    targets: &BTreeMap<String, Map<String, Value>>,
    diagnostics: &mut Diagnostics,
) {
    const FIELDS: [&str; 4] = [
        "provenance_path",
        "provenance_sha256",
        "seed_count",
        "total_bytes",
    ];
    for field in corpus.keys() {
        if !FIELDS.contains(&field.as_str()) && field != "seeds" {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.{field}"),
                "unknown fuzz corpus field is not permitted",
            ));
        }
    }
    let provenance_path = required_string(
        corpus,
        "provenance_path",
        path,
        "FIXTURE-SCHEMA",
        diagnostics,
    );
    let provenance_hash = required_string(
        corpus,
        "provenance_sha256",
        path,
        "FIXTURE-SCHEMA",
        diagnostics,
    );
    if let Some(hash) = provenance_hash
        && !is_sha256(&hash)
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.provenance_sha256"),
            "provenance_sha256 must be lowercase SHA-256",
        ));
    }
    let seed_count = required_u64(corpus, "seed_count", path, diagnostics);
    let total_bytes = required_u64(corpus, "total_bytes", path, diagnostics);
    let Some(seeds) = required_array(corpus, "seeds", path, diagnostics) else {
        return;
    };
    if seed_count != Some(seeds.len() as u64) {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-REFERENCE",
            format!("{path}.seed_count"),
            "seed_count must equal the materialized seeds length",
        ));
    }
    let mut seed_keys = BTreeSet::new();
    let mut aggregate_bytes = 0_u64;
    let mut per_target = BTreeMap::<String, (u64, u64)>::new();
    for (position, value) in seeds.iter().enumerate() {
        let item_path = format!("{path}.seeds[{position}]");
        let Some(seed) = value.as_object() else {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                item_path,
                "corpus seed must be an object",
            ));
            continue;
        };
        for field in ["target", "path", "sha256", "size_bytes"] {
            if !seed.contains_key(field) {
                diagnostics.push(Diagnostic::new(
                    "FIXTURE-SCHEMA",
                    format!("{item_path}.{field}"),
                    "corpus seed field is missing",
                ));
            }
        }
        let Some(target) =
            required_string(seed, "target", &item_path, "FIXTURE-SCHEMA", diagnostics)
        else {
            continue;
        };
        let Some(seed_path) =
            required_string(seed, "path", &item_path, "FIXTURE-SCHEMA", diagnostics)
        else {
            continue;
        };
        let Some(hash) = required_string(seed, "sha256", &item_path, "FIXTURE-SCHEMA", diagnostics)
        else {
            continue;
        };
        if !is_sha256(&hash) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{item_path}.sha256"),
                "corpus seed sha256 must be lowercase SHA-256",
            ));
        }
        let Some(size) = required_u64(seed, "size_bytes", &item_path, diagnostics) else {
            continue;
        };
        if !seed_keys.insert((target.clone(), seed_path.clone())) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-REFERENCE",
                format!("{item_path}.path"),
                "duplicate corpus target/path pair",
            ));
        }
        aggregate_bytes = aggregate_bytes.saturating_add(size);
        let entry = per_target.entry(target.clone()).or_default();
        entry.0 = entry.0.saturating_add(1);
        entry.1 = entry.1.saturating_add(size);
        if !targets.contains_key(&target) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-REFERENCE",
                format!("{item_path}.target"),
                format!("corpus seed references unknown target {target:?}"),
            ));
        } else if let Some(source) = fuzz_corpus_reference(expected_case, &target, &seed_path) {
            for field in ["target", "path", "sha256", "size_bytes"] {
                if seed.get(field) != source.get(field) {
                    diagnostics.push(Diagnostic::new(
                        "FIXTURE-REFERENCE",
                        format!("{item_path}.{field}"),
                        "corpus seed must exactly match case source reference",
                    ));
                }
            }
        }
    }
    if total_bytes != Some(aggregate_bytes) {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-REFERENCE",
            format!("{path}.total_bytes"),
            format!("total_bytes must equal seed aggregate {aggregate_bytes}"),
        ));
    }
    if let Some(expected_case) = expected_case {
        let source_refs = expected_case
            .get("source_references")
            .and_then(Value::as_object);
        let expected_provenance = source_refs
            .and_then(|refs| refs.get("documentation"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_object)
            .find(|item| {
                item.get("path").and_then(Value::as_str) == Some("fuzz/corpus/PROVENANCE.md")
            });
        if let Some(expected) = expected_provenance
            && (provenance_path.as_deref() != expected.get("path").and_then(Value::as_str)
                || corpus.get("provenance_path") != expected.get("path")
                || corpus.get("provenance_sha256") != expected.get("sha256"))
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-PROVENANCE",
                format!("{path}.provenance_sha256"),
                "corpus provenance path/hash must match case documentation reference",
            ));
        }
        let expected_seeds = source_refs
            .and_then(|refs| refs.get("corpus"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_object)
            .filter_map(|seed| {
                Some((
                    seed.get("target")?.as_str()?.to_owned(),
                    seed.get("path")?.as_str()?.to_owned(),
                ))
            })
            .collect::<BTreeSet<_>>();
        if seed_keys != expected_seeds {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-COVERAGE",
                format!("{path}.seeds"),
                "corpus seed set must exactly match case source references",
            ));
        }
    }
    for (target, declared) in targets {
        let actual = per_target.get(target).copied().unwrap_or_default();
        let expected_count = declared
            .get("corpus_seed_count")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let expected_bytes = declared
            .get("corpus_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        if actual != (expected_count, expected_bytes) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-REFERENCE",
                format!("{path}.seeds"),
                format!("corpus aggregate for {target:?} must be ({expected_count}, {expected_bytes}), found {actual:?}"),
            ));
        }
    }
}

fn fuzz_corpus_reference<'a>(
    expected_case: Option<&'a Map<String, Value>>,
    target: &str,
    path: &str,
) -> Option<&'a Map<String, Value>> {
    expected_case?
        .get("source_references")?
        .as_object()?
        .get("corpus")?
        .as_array()?
        .iter()
        .filter_map(Value::as_object)
        .find(|item| {
            item.get("target").and_then(Value::as_str) == Some(target)
                && item.get("path").and_then(Value::as_str) == Some(path)
        })
}

fn validate_fuzz_invariants(
    invariants: &[Value],
    path: &str,
    expected_case: Option<&Map<String, Value>>,
    diagnostics: &mut Diagnostics,
) -> BTreeMap<String, String> {
    let mut index = BTreeMap::new();
    for (position, value) in invariants.iter().enumerate() {
        let item_path = format!("{path}[{position}]");
        let Some(invariant) = value.as_object() else {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                item_path,
                "fuzz invariant must be an object",
            ));
            continue;
        };
        const FIELDS: [&str; 4] = ["invariant_id", "target", "status", "evidence"];
        for field in invariant.keys() {
            if !FIELDS.contains(&field.as_str()) {
                diagnostics.push(Diagnostic::new(
                    "FIXTURE-SCHEMA",
                    format!("{item_path}.{field}"),
                    "unknown fuzz invariant field is not permitted",
                ));
            }
        }
        let Some(id) = required_string(
            invariant,
            "invariant_id",
            &item_path,
            "FIXTURE-SCHEMA",
            diagnostics,
        ) else {
            continue;
        };
        let Some(target) = required_string(
            invariant,
            "target",
            &item_path,
            "FIXTURE-SCHEMA",
            diagnostics,
        ) else {
            continue;
        };
        if index.insert(id.clone(), target.clone()).is_some() {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-REFERENCE",
                format!("{item_path}.invariant_id"),
                format!("duplicate fuzz invariant {id:?}"),
            ));
        }
        let status = required_string(
            invariant,
            "status",
            &item_path,
            "FIXTURE-SCHEMA",
            diagnostics,
        );
        if status
            .as_deref()
            .is_some_and(|value| !matches!(value, "planned" | "not-run" | "observed" | "failed"))
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{item_path}.status"),
                "invariant status must be planned, not-run, observed, or failed",
            ));
        }
        let Some(evidence) = required_object(invariant, "evidence", &item_path, diagnostics) else {
            continue;
        };
        let executions = required_u64(
            evidence,
            "executions",
            &format!("{item_path}.evidence"),
            diagnostics,
        );
        let failures = required_u64(
            evidence,
            "failures",
            &format!("{item_path}.evidence"),
            diagnostics,
        );
        let _ = required_string_list(
            evidence,
            "artifact_ids",
            &format!("{item_path}.evidence"),
            diagnostics,
        );
        let _ = required_string(
            evidence,
            "notes",
            &format!("{item_path}.evidence"),
            "FIXTURE-SCHEMA",
            diagnostics,
        );
        if matches!(status.as_deref(), Some("planned" | "not-run"))
            && (executions != Some(0) || failures != Some(0))
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-EVIDENCE",
                format!("{item_path}.evidence"),
                "planned/not-run invariants must have zero executions and failures",
            ));
        }
    }
    if let Some(expected_case) = expected_case {
        let expected = expected_case
            .get("target_invariants")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_object)
            .filter_map(|item| {
                Some((
                    item.get("invariant_id")?.as_str()?.to_owned(),
                    item.get("target")?.as_str()?.to_owned(),
                ))
            })
            .collect::<BTreeMap<_, _>>();
        if index != expected {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-COVERAGE",
                path.to_owned(),
                format!("invariant set/target mapping must exactly match case target_invariants: expected {} entries, found {}", expected.len(), index.len()),
            ));
        }
    }
    index
}

fn validate_fuzz_target_outcomes(
    value: Option<&Value>,
    path: &str,
    targets: &BTreeMap<String, Map<String, Value>>,
    invariants: &BTreeMap<String, String>,
    runner: &Map<String, Value>,
    diagnostics: &mut Diagnostics,
) {
    let Some(values) = value.and_then(Value::as_array) else {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            path,
            "target_outcomes must be an array",
        ));
        return;
    };
    let mut seen = BTreeSet::new();
    for (position, value) in values.iter().enumerate() {
        let item_path = format!("{path}[{position}]");
        let Some(outcome) = value.as_object() else {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                item_path,
                "target outcome must be an object",
            ));
            continue;
        };
        const FIELDS: [&str; 7] = [
            "target",
            "status",
            "counts",
            "invariant_ids",
            "artifact_ids",
            "seed",
            "flags",
        ];
        for field in outcome.keys() {
            if !FIELDS.contains(&field.as_str()) {
                diagnostics.push(Diagnostic::new(
                    "FIXTURE-SCHEMA",
                    format!("{item_path}.{field}"),
                    "unknown target outcome field is not permitted",
                ));
            }
        }
        let Some(target) =
            required_string(outcome, "target", &item_path, "FIXTURE-SCHEMA", diagnostics)
        else {
            continue;
        };
        if !seen.insert(target.clone()) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-REFERENCE",
                format!("{item_path}.target"),
                "duplicate target outcome",
            ));
        }
        if !targets.contains_key(&target) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-REFERENCE",
                format!("{item_path}.target"),
                format!("target outcome references unknown target {target:?}"),
            ));
        }
        let status = required_string(outcome, "status", &item_path, "FIXTURE-SCHEMA", diagnostics);
        if status
            .as_deref()
            .is_some_and(|value| !matches!(value, "not_run" | "pass" | "fail"))
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{item_path}.status"),
                "target outcome status must be not_run, pass, or fail",
            ));
        }
        let Some(counts) = required_object(outcome, "counts", &item_path, diagnostics) else {
            continue;
        };
        validate_fuzz_counts(counts, &format!("{item_path}.counts"), runner, diagnostics);
        let Some(ids) = required_string_list(outcome, "invariant_ids", &item_path, diagnostics)
        else {
            continue;
        };
        let actual = ids.iter().cloned().collect::<BTreeSet<_>>();
        let expected = invariants
            .iter()
            .filter_map(|(id, invariant_target)| {
                (invariant_target == &target).then_some(id.clone())
            })
            .collect::<BTreeSet<_>>();
        if actual != expected {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-COVERAGE",
                format!("{item_path}.invariant_ids"),
                "target outcome invariant IDs must exactly match target invariants",
            ));
        }
        let _ = required_string_list(outcome, "artifact_ids", &item_path, diagnostics);
        match outcome.get("seed") {
            Some(Value::Null) | Some(Value::String(_)) => {}
            Some(_) | None => diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{item_path}.seed"),
                "seed must be a string or null",
            )),
        }
        let _ = required_string_list(outcome, "flags", &item_path, diagnostics);
        if status.as_deref() == Some("not_run")
            && (counts.get("executions").and_then(Value::as_u64) != Some(0)
                || outcome
                    .get("artifact_ids")
                    .and_then(Value::as_array)
                    .is_none_or(|ids| !ids.is_empty())
                || outcome.get("seed") != Some(&Value::Null)
                || outcome
                    .get("flags")
                    .and_then(Value::as_array)
                    .is_none_or(|flags| !flags.is_empty()))
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-EVIDENCE",
                item_path,
                "not_run target outcome must have zero executions, no artifacts, null seed, and no flags",
            ));
        }
    }
    let expected = targets.keys().cloned().collect::<BTreeSet<_>>();
    if seen != expected {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-COVERAGE",
            path,
            "target_outcomes must contain exactly one row for every target",
        ));
    }
}

fn validate_fuzz_counts(
    counts: &Map<String, Value>,
    path: &str,
    _runner: &Map<String, Value>,
    diagnostics: &mut Diagnostics,
) {
    for field in counts.keys() {
        if !FUZZ_COUNT_FIELDS.contains(&field.as_str()) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.{field}"),
                "unknown fuzz outcome count is not permitted",
            ));
        }
    }
    for field in FUZZ_COUNT_FIELDS {
        let _ = required_u64(counts, field, path, diagnostics);
    }
    let executions = counts
        .get("executions")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let accepted = counts
        .get("accepted_inputs")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let rejected = counts
        .get("rejected_inputs")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if accepted.saturating_add(rejected) > executions {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-REFERENCE",
            path,
            "accepted_inputs + rejected_inputs cannot exceed executions",
        ));
    }
}

fn validate_fuzz_outcome(
    value: Option<&Value>,
    path: &str,
    targets: &BTreeMap<String, Map<String, Value>>,
    runner: &Map<String, Value>,
    campaign: &Map<String, Value>,
    diagnostics: &mut Diagnostics,
) {
    let Some(outcome) = value.and_then(Value::as_object) else {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            path,
            "outcome must be an object",
        ));
        return;
    };
    const FIELDS: [&str; 5] = ["status", "counts", "artifacts", "minimization", "notes"];
    for field in outcome.keys() {
        if !FIELDS.contains(&field.as_str()) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.{field}"),
                "unknown aggregate outcome field is not permitted",
            ));
        }
    }
    let status = required_string(outcome, "status", path, "FIXTURE-SCHEMA", diagnostics);
    if status
        .as_deref()
        .is_some_and(|value| !matches!(value, "not_run" | "pass" | "fail"))
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.status"),
            "aggregate outcome status must be not_run, pass, or fail",
        ));
    }
    let Some(counts) = required_object(outcome, "counts", path, diagnostics) else {
        return;
    };
    validate_fuzz_counts(counts, &format!("{path}.counts"), runner, diagnostics);
    let _ = required_string_list(outcome, "artifacts", path, diagnostics);
    let Some(minimization) = required_object(outcome, "minimization", path, diagnostics) else {
        return;
    };
    let attempted = required_bool(
        minimization,
        "attempted",
        &format!("{path}.minimization"),
        diagnostics,
    );
    let minimization_status = required_string(
        minimization,
        "status",
        &format!("{path}.minimization"),
        "FIXTURE-SCHEMA",
        diagnostics,
    );
    let _ = required_string_list(
        minimization,
        "artifact_ids",
        &format!("{path}.minimization"),
        diagnostics,
    );
    if status.as_deref() == Some("not_run")
        && (counts.get("executions").and_then(Value::as_u64) != Some(0)
            || outcome
                .get("artifacts")
                .and_then(Value::as_array)
                .is_none_or(|ids| !ids.is_empty())
            || attempted != Some(false)
            || minimization_status.as_deref() != Some("not_run"))
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-EVIDENCE",
            path,
            "not_run aggregate outcome must have zero executions, no artifacts, and unattempted minimization",
        ));
    }
    let _ = required_string(outcome, "notes", path, "FIXTURE-SCHEMA", diagnostics);
    if let (Some(runs), Some(target_count)) = (
        campaign
            .get("configuration")
            .and_then(Value::as_object)
            .and_then(|configuration| configuration.get("runs_per_target"))
            .and_then(Value::as_u64),
        u64::try_from(targets.len()).ok(),
    ) && counts
        .get("executions")
        .and_then(Value::as_u64)
        .is_some_and(|executions| executions > runs.saturating_mul(target_count))
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-BOUNDS",
            format!("{path}.counts.executions"),
            "aggregate executions exceed runs_per_target multiplied by target count",
        ));
    }
}

fn validate_fuzz_artifacts(
    value: Option<&Value>,
    path: &str,
    record: &Map<String, Value>,
    runner: &Map<String, Value>,
    campaign: &Map<String, Value>,
    invariants: &BTreeMap<String, String>,
    diagnostics: &mut Diagnostics,
) {
    let Some(values) = value.and_then(Value::as_array) else {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            path,
            "artifacts must be an array",
        ));
        return;
    };
    if values.len() > 64 {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-BOUNDS",
            path,
            "fuzz artifact definitions are capped at 64",
        ));
    }
    let campaign_id = campaign.get("campaign_id").and_then(Value::as_str);
    let runner_toolchain = runner.get("toolchain").and_then(Value::as_str);
    let runner_cargo_fuzz = runner.get("cargo_fuzz").and_then(Value::as_str);
    let runner_libfuzzer = runner.get("libfuzzer_sys").and_then(Value::as_str);
    let runner_flags = runner.get("flags");
    let max_single = campaign
        .get("configuration")
        .and_then(Value::as_object)
        .and_then(|configuration| configuration.get("max_single_artifact_bytes"))
        .and_then(Value::as_u64)
        .unwrap_or(1_048_576);
    let max_total = campaign
        .get("configuration")
        .and_then(Value::as_object)
        .and_then(|configuration| configuration.get("max_total_artifact_bytes"))
        .and_then(Value::as_u64)
        .unwrap_or(67_108_864);
    let mut definitions = BTreeMap::<String, &Map<String, Value>>::new();
    let mut paths = BTreeSet::new();
    let mut total_size = 0_u64;
    for (position, value) in values.iter().enumerate() {
        let item_path = format!("{path}[{position}]");
        let Some(artifact) = value.as_object() else {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                item_path,
                "artifact definition must be an object",
            ));
            continue;
        };
        const FIELDS: [&str; 12] = [
            "artifact_id",
            "campaign_id",
            "target",
            "kind",
            "status",
            "path",
            "sha256",
            "size_bytes",
            "retention_reason",
            "input",
            "diagnostic",
            "toolchain",
        ];
        for field in artifact.keys() {
            if !FIELDS.contains(&field.as_str()) {
                diagnostics.push(Diagnostic::new(
                    "FIXTURE-SCHEMA",
                    format!("{item_path}.{field}"),
                    "unknown fuzz artifact field is not permitted",
                ));
            }
        }
        let Some(id) = required_string(
            artifact,
            "artifact_id",
            &item_path,
            "FIXTURE-SCHEMA",
            diagnostics,
        ) else {
            continue;
        };
        if definitions.insert(id.clone(), artifact).is_some() {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-REFERENCE",
                format!("{item_path}.artifact_id"),
                format!("duplicate artifact definition ID {id:?}"),
            ));
        }
        let Some(artifact_path) =
            required_string(artifact, "path", &item_path, "FIXTURE-SCHEMA", diagnostics)
        else {
            continue;
        };
        if !paths.insert(artifact_path) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-REFERENCE",
                format!("{item_path}.path"),
                "artifact definition paths must be unique",
            ));
        }
        if let Some(value) = artifact.get("sha256").and_then(Value::as_str)
            && !is_sha256(value)
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{item_path}.sha256"),
                "artifact sha256 must be lowercase SHA-256",
            ));
        } else if artifact.get("sha256").is_none() {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{item_path}.sha256"),
                "artifact sha256 is required",
            ));
        }
        let Some(size) = required_u64(artifact, "size_bytes", &item_path, diagnostics) else {
            continue;
        };
        if size > max_single {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-BOUNDS",
                format!("{item_path}.size_bytes"),
                format!("artifact exceeds max_single_artifact_bytes {max_single}"),
            ));
        }
        total_size = total_size.saturating_add(size);
        for field in [
            "campaign_id",
            "target",
            "kind",
            "status",
            "retention_reason",
        ] {
            let _ = required_string(artifact, field, &item_path, "FIXTURE-SCHEMA", diagnostics);
        }
        if campaign_id.is_some()
            && artifact.get("campaign_id").and_then(Value::as_str) != campaign_id
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-REFERENCE",
                format!("{item_path}.campaign_id"),
                "artifact campaign_id must match campaign campaign_id",
            ));
        }
        if artifact
            .get("kind")
            .and_then(Value::as_str)
            .is_some_and(|kind| {
                !matches!(
                    kind,
                    "crash"
                        | "hang"
                        | "timeout"
                        | "sanitizer"
                        | "oom"
                        | "resource-limit"
                        | "minimized-input"
                        | "regression"
                        | "log"
                        | "report"
                )
            })
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{item_path}.kind"),
                "unsupported artifact kind",
            ));
        }
        if artifact
            .get("status")
            .and_then(Value::as_str)
            .is_some_and(|status| !matches!(status, "observed" | "triaged" | "fixed" | "accepted"))
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{item_path}.status"),
                "unsupported artifact status",
            ));
        }
        let Some(input) = required_object(artifact, "input", &item_path, diagnostics) else {
            continue;
        };
        for field in ["path", "sha256", "source"] {
            let _ = required_string(
                input,
                field,
                &format!("{item_path}.input"),
                "FIXTURE-SCHEMA",
                diagnostics,
            );
        }
        let _ = required_u64(
            input,
            "size_bytes",
            &format!("{item_path}.input"),
            diagnostics,
        );
        if let Some(hash) = input.get("sha256").and_then(Value::as_str)
            && !is_sha256(hash)
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{item_path}.input.sha256"),
                "artifact input sha256 must be lowercase SHA-256",
            ));
        }
        let _ = required_bool(
            input,
            "minimized",
            &format!("{item_path}.input"),
            diagnostics,
        );
        let Some(diagnostic) = required_object(artifact, "diagnostic", &item_path, diagnostics)
        else {
            continue;
        };
        for field in ["exit_class", "stack_trace", "stable_error"] {
            if field == "exit_class" {
                let _ = required_string(
                    diagnostic,
                    field,
                    &format!("{item_path}.diagnostic"),
                    "FIXTURE-SCHEMA",
                    diagnostics,
                );
            } else if let Some(value) = diagnostic.get(field)
                && !value.is_null()
                && !value.is_string()
            {
                diagnostics.push(Diagnostic::new(
                    "FIXTURE-SCHEMA",
                    format!("{item_path}.diagnostic.{field}"),
                    "diagnostic text must be a string or null",
                ));
            }
        }
        let Some(toolchain) = required_object(artifact, "toolchain", &item_path, diagnostics)
        else {
            continue;
        };
        for field in ["rust", "cargo_fuzz", "libfuzzer_sys"] {
            let _ = required_string(
                toolchain,
                field,
                &format!("{item_path}.toolchain"),
                "FIXTURE-SCHEMA",
                diagnostics,
            );
        }
        let _ = required_string_list(
            toolchain,
            "flags",
            &format!("{item_path}.toolchain"),
            diagnostics,
        );
        for (field, expected) in [
            ("rust", runner_toolchain),
            ("cargo_fuzz", runner_cargo_fuzz),
            ("libfuzzer_sys", runner_libfuzzer),
        ] {
            if let Some(expected) = expected
                && toolchain.get(field).and_then(Value::as_str) != Some(expected)
            {
                diagnostics.push(Diagnostic::new(
                    "FIXTURE-REFERENCE",
                    format!("{item_path}.toolchain.{field}"),
                    "artifact toolchain must match runner toolchain",
                ));
            }
        }
        if let (Some(expected), Some(actual)) = (runner_flags, toolchain.get("flags"))
            && expected != actual
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-REFERENCE",
                format!("{item_path}.toolchain.flags"),
                "artifact toolchain flags must match runner flags",
            ));
        }
    }
    if total_size > max_total {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-BOUNDS",
            path,
            format!("artifact aggregate exceeds max_total_artifact_bytes {max_total}"),
        ));
    }
    let mut references = BTreeMap::<String, Option<String>>::new();
    if let Some(rows) = record.get("invariants").and_then(Value::as_array) {
        for row in rows {
            if let Some(row) = row.as_object()
                && let Some(target) = row.get("target").and_then(Value::as_str)
                && let Some(ids) = row
                    .get("evidence")
                    .and_then(Value::as_object)
                    .and_then(|evidence| evidence.get("artifact_ids"))
                    .and_then(Value::as_array)
            {
                for id in ids.iter().filter_map(Value::as_str) {
                    add_fuzz_artifact_reference(
                        &mut references,
                        id,
                        Some(target.to_owned()),
                        &format!("{path}.invariants"),
                        diagnostics,
                    );
                }
            }
        }
    }
    if let Some(rows) = record.get("target_outcomes").and_then(Value::as_array) {
        for row in rows {
            if let Some(row) = row.as_object()
                && let Some(target) = row.get("target").and_then(Value::as_str)
                && let Some(ids) = row.get("artifact_ids").and_then(Value::as_array)
            {
                for id in ids.iter().filter_map(Value::as_str) {
                    add_fuzz_artifact_reference(
                        &mut references,
                        id,
                        Some(target.to_owned()),
                        &format!("{path}.target_outcomes"),
                        diagnostics,
                    );
                }
            }
        }
    }
    for field in ["artifacts"] {
        if let Some(ids) = record
            .get("outcome")
            .and_then(Value::as_object)
            .and_then(|outcome| outcome.get(field))
            .and_then(Value::as_array)
        {
            for id in ids.iter().filter_map(Value::as_str) {
                add_fuzz_artifact_reference(
                    &mut references,
                    id,
                    None,
                    &format!("{path}.../outcome.{field}"),
                    diagnostics,
                );
            }
        }
    }
    if let Some(ids) = record
        .get("outcome")
        .and_then(Value::as_object)
        .and_then(|outcome| outcome.get("minimization"))
        .and_then(Value::as_object)
        .and_then(|minimization| minimization.get("artifact_ids"))
        .and_then(Value::as_array)
    {
        for id in ids.iter().filter_map(Value::as_str) {
            add_fuzz_artifact_reference(
                &mut references,
                id,
                None,
                &format!("{path}.../outcome.minimization"),
                diagnostics,
            );
        }
    }
    for id in references.keys() {
        if !definitions.contains_key(id) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-REFERENCE",
                path,
                format!("artifact reference {id:?} has no definition"),
            ));
        }
    }
    for id in definitions.keys() {
        if !references.contains_key(id) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-REFERENCE",
                path,
                format!("artifact definition {id:?} is unlinked"),
            ));
        }
    }
    for (id, target) in references {
        if let Some(artifact) = definitions.get(&id)
            && let Some(target) = target
            && artifact.get("target").and_then(Value::as_str) != Some(target.as_str())
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-REFERENCE",
                format!("{path}.{id}"),
                "artifact target does not match the referencing target",
            ));
        }
    }
    let _ = invariants;
}

fn add_fuzz_artifact_reference(
    references: &mut BTreeMap<String, Option<String>>,
    id: &str,
    target: Option<String>,
    path: &str,
    diagnostics: &mut Diagnostics,
) {
    if references.insert(id.to_owned(), target).is_some() {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-REFERENCE",
            path,
            format!("artifact ID {id:?} is referenced more than once"),
        ));
    }
}

const HTTP_TRACE_STATE_FIELDS: [&str; 24] = [
    "schema_id",
    "schema_version",
    "profile_id",
    "fixture_family_id",
    "case_id",
    "conformance_ids",
    "normalization_policy_refs",
    "external_runtime_boundary_ids",
    "format",
    "evidence_status",
    "oracle_available",
    "process_exit",
    "process_exit_asserted",
    "counts",
    "events",
    "state_projection",
    "result_projection",
    "normalization",
    "trace_schema",
    "generated_from",
    "materialization",
    "raw_artifacts",
    "source",
    "status",
];

const HTTP_TRACE_SAMPLER_FIELDS: [&str; 27] = [
    "schema_id",
    "schema_version",
    "profile_id",
    "fixture_family_id",
    "case_id",
    "conformance_ids",
    "normalization_policy_refs",
    "external_runtime_boundary_ids",
    "format",
    "evidence_status",
    "oracle_available",
    "process_exit",
    "process_exit_asserted",
    "sample_count",
    "ordered_labels",
    "events",
    "trace_contract",
    "request_body_contract",
    "response_body_contract",
    "response_header_contract",
    "response_data_contract",
    "jtl_mapping_contract",
    "state_projection",
    "normalization",
    "generated_from",
    "materialization",
    "raw_artifacts",
];

const HTTP_TRACE_RESULT_FIELDS: [&str; 23] = [
    "schema_id",
    "schema_version",
    "profile_id",
    "fixture_family_id",
    "case_id",
    "conformance_ids",
    "normalization_policy_refs",
    "external_runtime_boundary_ids",
    "format",
    "evidence_status",
    "oracle_available",
    "process_exit",
    "process_exit_asserted",
    "trace_schema",
    "counts",
    "events",
    "state_projection",
    "result_projection",
    "normalization",
    "generated_from",
    "materialization",
    "raw_artifacts",
    "status",
];

const HTTP_TRACE_COUNT_FIELDS: [&str; 16] = [
    "planned",
    "sampler_count",
    "request_count",
    "response_count",
    "redirect_hop_count",
    "auth_challenge_count",
    "cache_network_request_count",
    "cache_hit_count",
    "cache_revalidation_count",
    "cache_eviction_count",
    "cookie_set_count",
    "cookie_sent_count",
    "cookie_reset_count",
    "cookie_persist_count",
    "response_header_count_max",
    "transport_error_count",
];

fn validate_http_trace(
    object: &Map<String, Value>,
    path: &str,
    expected_case: Option<&Map<String, Value>>,
    profile: &ProfileIndex,
    diagnostics: &mut Diagnostics,
) {
    let has_state_counts = object.contains_key("counts");
    let has_sampler_contract = object.contains_key("trace_contract");
    let has_result_schema = object.contains_key("trace_schema");
    if has_state_counts && has_sampler_contract
        || !has_state_counts && !has_sampler_contract && !has_result_schema
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.schema_id"),
            "http-trace must select exactly one closed variant: state counts, sampler trace_contract, or observed trace_schema",
        ));
        return;
    }
    if has_state_counts {
        validate_http_state_contract(object, path, expected_case, profile, diagnostics);
    } else if has_sampler_contract {
        validate_http_sampler_contract(object, path, expected_case, profile, diagnostics);
    } else {
        validate_http_result_contract(object, path, expected_case, profile, diagnostics);
    }
}

fn reject_unknown_http_fields(
    object: &Map<String, Value>,
    allowed: &[&str],
    path: &str,
    diagnostics: &mut Diagnostics,
) {
    for field in object.keys() {
        if !allowed.contains(&field.as_str()) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.{field}"),
                "unknown field is not permitted by the closed http-trace schema",
            ));
        }
    }
}

fn validate_http_common_header(
    object: &Map<String, Value>,
    path: &str,
    diagnostics: &mut Diagnostics,
) -> Option<ExecutionState> {
    if object.get("format").and_then(Value::as_str) != Some("http-trace") {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.format"),
            "http-trace format must be exactly \"http-trace\"",
        ));
    }
    let evidence = required_string(
        object,
        "evidence_status",
        path,
        "FIXTURE-SCHEMA",
        diagnostics,
    );
    let state = evidence
        .as_deref()
        .and_then(|value| parse_expectation_state(&Value::String(value.to_owned())));
    if evidence.is_some() && state.is_none() {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.evidence_status"),
            "evidence_status must use a closed execution-state vocabulary",
        ));
    }
    let _ = required_bool(object, "oracle_available", path, diagnostics);
    let _ = required_bool(object, "process_exit_asserted", path, diagnostics);
    match object.get("process_exit") {
        Some(Value::Null) => {}
        Some(Value::Number(number)) if number.as_u64().is_some() => {}
        Some(_) => diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.process_exit"),
            "process_exit must be a non-negative integer or null",
        )),
        None => diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.process_exit"),
            "required process_exit field is missing",
        )),
    }
    for field in ["conformance_ids", "normalization_policy_refs"] {
        let _ = required_string_list(object, field, path, diagnostics);
    }
    Some(state.unwrap_or(ExecutionState::NotRun))
}

fn validate_http_static_state_header(
    object: &Map<String, Value>,
    path: &str,
    diagnostics: &mut Diagnostics,
) -> Option<ExecutionState> {
    let state = validate_http_common_header(object, path, diagnostics);
    if state != Some(ExecutionState::NotRun) {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-EVIDENCE",
            format!("{path}.evidence_status"),
            "static http-trace contracts must be explicitly not-run or unavailable",
        ));
    }
    if object.get("oracle_available") != Some(&Value::Bool(false)) {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-EVIDENCE",
            format!("{path}.oracle_available"),
            "not-run http-trace contracts cannot claim an available oracle",
        ));
    }
    if object.get("process_exit") != Some(&Value::Null)
        || object.get("process_exit_asserted") != Some(&Value::Bool(false))
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-EVIDENCE",
            format!("{path}.process_exit"),
            "not-run http-trace contracts must have process_exit=null and process_exit_asserted=false",
        ));
    }
    Some(ExecutionState::NotRun)
}

fn validate_http_state_contract(
    object: &Map<String, Value>,
    path: &str,
    expected_case: Option<&Map<String, Value>>,
    profile: &ProfileIndex,
    diagnostics: &mut Diagnostics,
) {
    reject_unknown_http_fields(object, &HTTP_TRACE_STATE_FIELDS, path, diagnostics);
    let state = validate_http_static_state_header(object, path, diagnostics);
    if let Some(case) = expected_case {
        validate_http_case_identity(object, case, path, profile, diagnostics);
    }
    let Some(counts) = required_object(object, "counts", path, diagnostics) else {
        return;
    };
    if let Some(trace_schema) = object.get("trace_schema").and_then(Value::as_object) {
        validate_http_trace_schema(trace_schema, &format!("{path}.trace_schema"), diagnostics);
    } else {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.trace_schema"),
            "static http-state contract requires a trace_schema object",
        ));
    }
    validate_http_counts(counts, &format!("{path}.counts"), true, diagnostics);
    let Some(events) = required_array(object, "events", path, diagnostics) else {
        return;
    };
    if events.is_empty() {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.events"),
            "http-state trace contract must declare at least one sampler event",
        ));
    }
    let mut sampler_names = BTreeSet::new();
    let mut request_total = 0_u64;
    let mut request_count_total = 0_u64;
    let mut network_total = 0_u64;
    let mut challenge_total = 0_u64;
    let mut redirect_total = 0_u64;
    let mut cache_hit_total = 0_u64;
    let mut revalidation_total = 0_u64;
    let mut eviction_total = 0_u64;
    let mut per_iteration_total = 0_u64;
    let mut has_request_count = false;
    let mut has_network_count = false;
    let mut has_per_iteration_count = false;
    for (position, event) in events.iter().enumerate() {
        let event_path = format!("{path}.events[{position}]");
        let Some(event) = event.as_object() else {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                event_path,
                "http-state event must be an object",
            ));
            continue;
        };
        validate_http_state_event(event, &event_path, state, diagnostics);
        let Some(sampler) = event.get("sampler").and_then(Value::as_str) else {
            continue;
        };
        if !sampler_names.insert(sampler.to_owned()) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{event_path}.sampler"),
                "sampler labels must be unique",
            ));
        }
        request_total = request_total.saturating_add(
            event
                .get("requests")
                .and_then(Value::as_array)
                .map_or(0, Vec::len) as u64,
        );
        if let Some(value) = event.get("request_count").and_then(Value::as_u64) {
            has_request_count = true;
            request_count_total = request_count_total.saturating_add(value);
        }
        if let Some(value) = event.get("network_request_count").and_then(Value::as_u64) {
            has_network_count = true;
            network_total = network_total.saturating_add(value);
        }
        if let (Some(per), Some(iterations)) = (
            event
                .get("request_count_per_iteration")
                .and_then(Value::as_u64),
            event.get("iterations").and_then(Value::as_u64),
        ) {
            has_per_iteration_count = true;
            per_iteration_total =
                per_iteration_total.saturating_add(per.saturating_mul(iterations));
        }
        challenge_total = challenge_total.saturating_add(
            event
                .get("challenge_count")
                .and_then(Value::as_u64)
                .unwrap_or(0),
        );
        redirect_total = redirect_total.saturating_add(
            event
                .get("redirect_hop_count")
                .and_then(Value::as_u64)
                .unwrap_or(0),
        );
        cache_hit_total = cache_hit_total.saturating_add(
            event
                .get("cache_hit_count")
                .and_then(Value::as_u64)
                .unwrap_or(0),
        );
        revalidation_total = revalidation_total.saturating_add(
            event
                .get("revalidation_count")
                .and_then(Value::as_u64)
                .unwrap_or(0),
        );
        eviction_total = eviction_total.saturating_add(
            event
                .get("eviction_count")
                .and_then(Value::as_u64)
                .unwrap_or(0),
        );
    }
    if counts
        .get("sampler_count")
        .and_then(Value::as_u64)
        .is_some_and(|count| count < events.len() as u64)
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-REFERENCE",
            format!("{path}.counts.sampler_count"),
            "sampler_count cannot be lower than the declared event count",
        ));
    }
    let actual_request_total = if has_request_count {
        request_count_total
    } else if has_network_count {
        network_total
    } else if has_per_iteration_count {
        per_iteration_total
    } else {
        request_total
    };
    compare_http_count(
        counts,
        "request_count",
        actual_request_total,
        &format!("{path}.counts.request_count"),
        diagnostics,
    );
    compare_http_count(
        counts,
        "response_count",
        actual_request_total,
        &format!("{path}.counts.response_count"),
        diagnostics,
    );
    compare_http_count(
        counts,
        "auth_challenge_count",
        challenge_total,
        &format!("{path}.counts.auth_challenge_count"),
        diagnostics,
    );
    compare_http_count(
        counts,
        "redirect_hop_count",
        redirect_total,
        &format!("{path}.counts.redirect_hop_count"),
        diagnostics,
    );
    compare_http_count(
        counts,
        "cache_hit_count",
        cache_hit_total,
        &format!("{path}.counts.cache_hit_count"),
        diagnostics,
    );
    compare_http_count(
        counts,
        "cache_revalidation_count",
        revalidation_total,
        &format!("{path}.counts.cache_revalidation_count"),
        diagnostics,
    );
    compare_http_count(
        counts,
        "cache_eviction_count",
        eviction_total,
        &format!("{path}.counts.cache_eviction_count"),
        diagnostics,
    );
    if let Some(case) = expected_case {
        validate_http_case_counts(case, counts, events.len() as u64, path, true, diagnostics);
    }
    for field in ["state_projection", "result_projection"] {
        let _ = required_object(object, field, path, diagnostics);
    }
    validate_http_normalization(object, path, expected_case, profile, diagnostics);
}

fn validate_http_counts(
    counts: &Map<String, Value>,
    path: &str,
    planned: bool,
    diagnostics: &mut Diagnostics,
) {
    for field in counts.keys() {
        if !HTTP_TRACE_COUNT_FIELDS.contains(&field.as_str()) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.{field}"),
                "unknown count is not permitted by the closed http-trace schema",
            ));
        }
    }
    let planned_value = required_bool(counts, "planned", path, diagnostics);
    if planned_value.is_some() && planned_value != Some(planned) {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-EVIDENCE",
            format!("{path}.planned"),
            format!("planned must be {planned} for this http-trace variant"),
        ));
    }
    for field in HTTP_TRACE_COUNT_FIELDS {
        if field != "planned" && field != "transport_error_count" {
            let _ = required_u64(counts, field, path, diagnostics);
        }
    }
}

fn compare_http_count(
    counts: &Map<String, Value>,
    field: &str,
    actual: u64,
    path: &str,
    diagnostics: &mut Diagnostics,
) {
    if let Some(expected) = counts.get(field).and_then(Value::as_u64)
        && expected != actual
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-REFERENCE",
            path,
            format!("must match cross-linked event count {actual}"),
        ));
    }
}

fn validate_http_state_event(
    event: &Map<String, Value>,
    path: &str,
    state: Option<ExecutionState>,
    diagnostics: &mut Diagnostics,
) {
    const FIELDS: [&str; 11] = [
        "sampler",
        "logical_request_count",
        "request_count",
        "network_request_count",
        "request_count_per_iteration",
        "iterations",
        "challenge_count",
        "redirect_hop_count",
        "cache_hit_count",
        "revalidation_count",
        "eviction_count",
    ];
    for field in event.keys() {
        if !FIELDS.contains(&field.as_str()) && field != "requests" {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.{field}"),
                "unknown sampler event field is not permitted",
            ));
        }
    }
    let _ = required_string(event, "sampler", path, "FIXTURE-SCHEMA", diagnostics);
    let _ = required_u64(event, "logical_request_count", path, diagnostics);
    let Some(requests) = required_array(event, "requests", path, diagnostics) else {
        return;
    };
    if requests.is_empty() {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.requests"),
            "sampler event must contain at least one request descriptor",
        ));
    }
    for field in FIELDS {
        if matches!(field, "sampler" | "logical_request_count") {
            continue;
        }
        if let Some(value) = event.get(field)
            && value.as_u64().is_none()
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.{field}"),
                "event count must be a non-negative integer",
            ));
        }
    }
    for (position, request) in requests.iter().enumerate() {
        let request_path = format!("{path}.requests[{position}]");
        let Some(request) = request.as_object() else {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                request_path,
                "request descriptor must be an object",
            ));
            continue;
        };
        validate_http_state_request(request, &request_path, state, diagnostics);
    }
}

fn validate_http_state_request(
    request: &Map<String, Value>,
    path: &str,
    state: Option<ExecutionState>,
    diagnostics: &mut Diagnostics,
) {
    const FIELDS: [&str; 16] = [
        "method",
        "path",
        "query",
        "response_status",
        "request_body_length",
        "request_body_sha256",
        "response_body_sha256",
        "response_headers_sha256",
        "request_headers",
        "response_body",
        "selected_auth_entry",
        "set_cookie_fields",
        "merge",
        "redirect_location",
        "connection_reused",
        "transport",
    ];
    for field in request.keys() {
        if !FIELDS.contains(&field.as_str()) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.{field}"),
                "unknown request descriptor field is not permitted",
            ));
        }
    }
    let _ = required_string(request, "method", path, "FIXTURE-SCHEMA", diagnostics);
    let _ = required_string(request, "path", path, "FIXTURE-SCHEMA", diagnostics);
    if let Some(value) = request.get("query")
        && !matches!(value, Value::String(_) | Value::Object(_))
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.query"),
            "query must be a string or object when present",
        ));
    }
    if let Some(value) = request.get("response_status")
        && !value.is_null()
        && value.as_u64().is_none()
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.response_status"),
            "response_status must be a non-negative integer or null",
        ));
    }
    for field in ["request_body_length", "set_cookie_fields"] {
        if let Some(value) = request.get(field)
            && value.as_u64().is_none()
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.{field}"),
                "request descriptor count must be a non-negative integer",
            ));
        }
    }
    for field in [
        "request_body_sha256",
        "response_body_sha256",
        "response_headers_sha256",
    ] {
        if let Some(value) = request.get(field) {
            validate_digest_value(value, 64, &format!("{path}.{field}"), state, diagnostics);
        }
    }
    if let Some(value) = request.get("request_headers")
        && !value.is_object()
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.request_headers"),
            "request_headers must be an object",
        ));
    }
    if let Some(value) = request.get("response_body")
        && !value.is_string()
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.response_body"),
            "response_body must be a redacted string",
        ));
    }
    for field in ["selected_auth_entry", "redirect_location"] {
        if let Some(value) = request.get(field)
            && !value.is_string()
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.{field}"),
                "request descriptor field must be a string",
            ));
        }
    }
    for field in ["merge", "transport"] {
        if let Some(value) = request.get(field)
            && !value.is_object()
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.{field}"),
                "request descriptor field must be an object",
            ));
        }
    }
    if let Some(value) = request.get("connection_reused")
        && !value.is_boolean()
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.connection_reused"),
            "connection_reused must be boolean",
        ));
    }
}

fn validate_http_sampler_contract(
    object: &Map<String, Value>,
    path: &str,
    expected_case: Option<&Map<String, Value>>,
    profile: &ProfileIndex,
    diagnostics: &mut Diagnostics,
) {
    reject_unknown_http_fields(object, &HTTP_TRACE_SAMPLER_FIELDS, path, diagnostics);
    let _ = validate_http_static_state_header(object, path, diagnostics);
    if let Some(case) = expected_case {
        validate_http_case_identity(object, case, path, profile, diagnostics);
    }
    let sample_count = required_u64(object, "sample_count", path, diagnostics);
    let Some(labels) = required_string_list(object, "ordered_labels", path, diagnostics) else {
        return;
    };
    let Some(events) = required_array(object, "events", path, diagnostics) else {
        return;
    };
    if sample_count != Some(events.len() as u64) || labels.len() != events.len() {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-REFERENCE",
            format!("{path}.sample_count"),
            "sample_count, ordered_labels, and events length must be equal",
        ));
    }
    let mut event_labels = Vec::new();
    for (position, event) in events.iter().enumerate() {
        let event_path = format!("{path}.events[{position}]");
        let Some(event) = event.as_object() else {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                event_path,
                "sampler trace event must be an object",
            ));
            continue;
        };
        const FIELDS: [&str; 4] = ["sequence", "sampler", "method", "path"];
        for field in event.keys() {
            if !FIELDS.contains(&field.as_str()) {
                diagnostics.push(Diagnostic::new(
                    "FIXTURE-SCHEMA",
                    format!("{event_path}.{field}"),
                    "unknown static sampler event field is not permitted",
                ));
            }
        }
        let sequence = required_u64(event, "sequence", &event_path, diagnostics);
        let sampler = required_string(event, "sampler", &event_path, "FIXTURE-SCHEMA", diagnostics);
        let method = required_string(event, "method", &event_path, "FIXTURE-SCHEMA", diagnostics);
        let _ = required_string(event, "path", &event_path, "FIXTURE-SCHEMA", diagnostics);
        if sequence != Some(position as u64 + 1) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-REFERENCE",
                format!("{event_path}.sequence"),
                "event sequences must be contiguous and one-based",
            ));
        }
        if let Some(method) = method
            && !matches!(
                method.as_str(),
                "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS"
            )
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{event_path}.method"),
                "unsupported HTTP method",
            ));
        }
        if let Some(sampler) = sampler {
            event_labels.push(sampler);
        }
    }
    if event_labels != labels {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-REFERENCE",
            format!("{path}.ordered_labels"),
            "ordered_labels must exactly match event sampler labels",
        ));
    }
    let Some(trace_contract) = required_object(object, "trace_contract", path, diagnostics) else {
        return;
    };
    let trace_path = format!("{path}.trace_contract");
    let event_count = required_u64(trace_contract, "event_count", &trace_path, diagnostics);
    let sequence_base = required_u64(trace_contract, "sequence_base", &trace_path, diagnostics);
    if event_count != sample_count || sequence_base != Some(1) {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-REFERENCE",
            &trace_path,
            "trace_contract event_count/sequence_base must cross-link to sample_count and one",
        ));
    }
    let Some(ordered_events) =
        required_array(trace_contract, "ordered_events", &trace_path, diagnostics)
    else {
        return;
    };
    if ordered_events.len() != events.len() {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-REFERENCE",
            format!("{trace_path}.ordered_events"),
            "trace_contract ordered_events must match events length",
        ));
    }
    for (position, event) in ordered_events.iter().enumerate() {
        let event_path = format!("{trace_path}.ordered_events[{position}]");
        let Some(event) = event.as_object() else {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                event_path,
                "ordered event must be an object",
            ));
            continue;
        };
        for field in ["sequence", "label", "method", "path"] {
            if !event.contains_key(field) {
                diagnostics.push(Diagnostic::new(
                    "FIXTURE-SCHEMA",
                    format!("{event_path}.{field}"),
                    "ordered event field is missing",
                ));
            }
        }
        if event.get("sequence").and_then(Value::as_u64) != Some(position as u64 + 1) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-REFERENCE",
                format!("{event_path}.sequence"),
                "ordered event sequence must be contiguous and one-based",
            ));
        }
        if let (Some(actual), Some(expected)) = (
            event.get("label").and_then(Value::as_str),
            labels.get(position),
        ) && actual != expected
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-REFERENCE",
                format!("{event_path}.label"),
                "ordered event label must match ordered_labels",
            ));
        }
    }
    for field in ["request_projection", "response_projection", "completion"] {
        let _ = required_object(trace_contract, field, &trace_path, diagnostics);
    }
    validate_http_body_contracts(object, path, &labels, diagnostics);
    for field in [
        "response_header_contract",
        "response_data_contract",
        "jtl_mapping_contract",
        "state_projection",
    ] {
        let _ = required_object(object, field, path, diagnostics);
    }
    validate_http_normalization(object, path, expected_case, profile, diagnostics);
    if let Some(case) = expected_case
        && let Some(max_requests) = http_case_max_requests(case)
        && sample_count.is_some_and(|count| count > max_requests)
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-BOUNDS",
            format!("{path}.sample_count"),
            format!("sample_count exceeds case max_requests bound {max_requests}"),
        ));
    }
}

fn validate_http_body_contracts(
    object: &Map<String, Value>,
    path: &str,
    labels: &[String],
    diagnostics: &mut Diagnostics,
) {
    let Some(requests) = required_array(object, "request_body_contract", path, diagnostics) else {
        return;
    };
    let Some(responses) = required_array(object, "response_body_contract", path, diagnostics)
    else {
        return;
    };
    let mut request_labels = BTreeSet::new();
    for (position, item) in requests.iter().enumerate() {
        let item_path = format!("{path}.request_body_contract[{position}]");
        let Some(item) = item.as_object() else {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                item_path,
                "request body contract item must be an object",
            ));
            continue;
        };
        let Some(label) = required_string(item, "label", &item_path, "FIXTURE-SCHEMA", diagnostics)
        else {
            continue;
        };
        if !request_labels.insert(label.clone()) || !labels.contains(&label) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-REFERENCE",
                format!("{item_path}.label"),
                "request body contract label must be unique and match an ordered event",
            ));
        }
        validate_http_optional_length(item, "length", &item_path, diagnostics);
        if let Some(value) = item.get("sha256") {
            validate_digest_value(
                value,
                64,
                &format!("{item_path}.sha256"),
                Some(ExecutionState::NotRun),
                diagnostics,
            );
            if item.get("length").is_some_and(Value::is_null) && !value.is_null() {
                diagnostics.push(Diagnostic::new(
                    "FIXTURE-REFERENCE",
                    format!("{item_path}.sha256"),
                    "null request length must not claim a concrete digest",
                ));
            }
        } else {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{item_path}.sha256"),
                "request body contract requires sha256",
            ));
        }
        for field in ["effective_bytes", "effective_form_bytes"] {
            if let Some(value) = item.get(field).and_then(Value::as_str)
                && let Some(expected) = item.get("sha256").and_then(Value::as_str)
                && is_sha256(expected)
            {
                let actual = Sha256::digest(value.as_bytes());
                let actual = actual
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                if actual != expected {
                    diagnostics.push(Diagnostic::new(
                        "FIXTURE-HASH",
                        format!("{item_path}.sha256"),
                        format!("request body digest does not match {field}"),
                    ));
                }
            }
        }
    }
    let mut response_labels = BTreeSet::new();
    for (position, item) in responses.iter().enumerate() {
        let item_path = format!("{path}.response_body_contract[{position}]");
        let Some(item) = item.as_object() else {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                item_path,
                "response body contract item must be an object",
            ));
            continue;
        };
        let Some(label) = required_string(item, "label", &item_path, "FIXTURE-SCHEMA", diagnostics)
        else {
            continue;
        };
        if !response_labels.insert(label.clone()) || !labels.contains(&label) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-REFERENCE",
                format!("{item_path}.label"),
                "response body contract label must be unique and match an ordered event",
            ));
        }
        if let Some(status) = item.get("status")
            && !status.is_null()
            && status.as_u64().is_none()
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{item_path}.status"),
                "status must be a non-negative integer or null",
            ));
        }
        match item.get("body") {
            Some(Value::Null) => {}
            Some(Value::Object(body)) => {
                for field in ["wire_length", "decoded_length"] {
                    let _ = required_u64(body, field, &format!("{item_path}.body"), diagnostics);
                }
                for field in ["wire_sha256", "decoded_sha256"] {
                    let _ = required_digest_string(
                        body,
                        field,
                        &format!("{item_path}.body"),
                        diagnostics,
                    );
                }
                if body.contains_key("declared_wire_length") {
                    let _ = required_u64(
                        body,
                        "declared_wire_length",
                        &format!("{item_path}.body"),
                        diagnostics,
                    );
                }
            }
            Some(_) => diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{item_path}.body"),
                "body must be an object or null",
            )),
            None => diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{item_path}.body"),
                "response body contract requires body",
            )),
        }
    }
}

fn validate_http_optional_length(
    object: &Map<String, Value>,
    field: &str,
    path: &str,
    diagnostics: &mut Diagnostics,
) {
    if let Some(value) = object.get(field)
        && !value.is_null()
        && value.as_u64().is_none()
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.{field}"),
            "length must be a non-negative integer or null",
        ));
    }
}

fn validate_http_result_contract(
    object: &Map<String, Value>,
    path: &str,
    expected_case: Option<&Map<String, Value>>,
    profile: &ProfileIndex,
    diagnostics: &mut Diagnostics,
) {
    reject_unknown_http_fields(object, &HTTP_TRACE_RESULT_FIELDS, path, diagnostics);
    let state = validate_http_common_header(object, path, diagnostics);
    let Some(trace_schema) = required_object(object, "trace_schema", path, diagnostics) else {
        return;
    };
    validate_http_trace_schema(trace_schema, &format!("{path}.trace_schema"), diagnostics);
    let Some(counts) = required_object(object, "counts", path, diagnostics) else {
        return;
    };
    validate_http_counts(counts, &format!("{path}.counts"), false, diagnostics);
    let Some(events) = required_array(object, "events", path, diagnostics) else {
        return;
    };
    if events.is_empty() {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.events"),
            "observed trace must contain events",
        ));
    }
    let required_event_fields = trace_schema
        .get("required_event_fields")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    for (position, value) in events.iter().enumerate() {
        let event_path = format!("{path}.events[{position}]");
        let Some(event) = value.as_object() else {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                event_path,
                "observed trace event must be an object",
            ));
            continue;
        };
        validate_http_result_event(
            event,
            &event_path,
            state,
            &required_event_fields,
            diagnostics,
        );
    }
    compare_http_count(
        counts,
        "sampler_count",
        events.len() as u64,
        &format!("{path}.counts.sampler_count"),
        diagnostics,
    );
    compare_http_count(
        counts,
        "request_count",
        events.len() as u64,
        &format!("{path}.counts.request_count"),
        diagnostics,
    );
    compare_http_count(
        counts,
        "response_count",
        events.len() as u64,
        &format!("{path}.counts.response_count"),
        diagnostics,
    );
    if state != Some(ExecutionState::Observed)
        || object.get("oracle_available") != Some(&Value::Bool(true))
        || object.get("process_exit_asserted") != Some(&Value::Bool(true))
        || object.get("process_exit").and_then(Value::as_u64).is_none()
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-EVIDENCE",
            path,
            "trace_schema variant is reserved for observed materialized evidence with asserted process exit",
        ));
    }
    if let Some(case) = expected_case {
        validate_http_case_identity(object, case, path, profile, diagnostics);
        validate_http_case_counts(case, counts, events.len() as u64, path, false, diagnostics);
    }
    for field in ["state_projection", "result_projection"] {
        let _ = required_object(object, field, path, diagnostics);
    }
    validate_http_normalization(object, path, expected_case, profile, diagnostics);
}

fn validate_http_trace_schema(
    schema: &Map<String, Value>,
    path: &str,
    diagnostics: &mut Diagnostics,
) {
    const FIELDS: [&str; 14] = [
        "schema_id",
        "schema_version",
        "encoding",
        "event_type",
        "request_fields",
        "response_fields",
        "required_event_fields",
        "digest_algorithm",
        "body_digest_observable",
        "header_digest_observable",
        "duplicate_header_values",
        "authorization_projection",
        "limits",
        "transport_fields",
    ];
    for field in schema.keys() {
        if !FIELDS.contains(&field.as_str()) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.{field}"),
                "unknown trace_schema field is not permitted",
            ));
        }
    }
    if schema.get("schema_id").and_then(Value::as_str) != Some("jmeter-rs.http-trace") {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.schema_id"),
            "trace_schema schema_id must be jmeter-rs.http-trace",
        ));
    }
    if schema.get("schema_version").and_then(Value::as_u64) != Some(1) {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.schema_version"),
            "trace_schema schema_version must be 1",
        ));
    }
    for field in [
        "encoding",
        "event_type",
        "digest_algorithm",
        "duplicate_header_values",
        "authorization_projection",
    ] {
        let _ = required_string(schema, field, path, "FIXTURE-SCHEMA", diagnostics);
    }
    for field in ["request_fields", "response_fields", "required_event_fields"] {
        let _ = required_string_list(schema, field, path, diagnostics);
    }
    for field in ["body_digest_observable", "header_digest_observable"] {
        let _ = required_bool(schema, field, path, diagnostics);
    }
    let _ = required_object(schema, "limits", path, diagnostics);
    if schema.get("digest_algorithm").and_then(Value::as_str) != Some("SHA-256") {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.digest_algorithm"),
            "trace digest algorithm must be SHA-256",
        ));
    }
}

fn validate_http_result_event(
    event: &Map<String, Value>,
    path: &str,
    state: Option<ExecutionState>,
    required_fields: &[&str],
    diagnostics: &mut Diagnostics,
) {
    const FIELDS: [&str; 15] = [
        "sequence",
        "method",
        "path",
        "query",
        "request_headers",
        "request_headers_sha256",
        "body_length",
        "body_sha256",
        "response",
        "sampler",
        "label",
        "connection_id",
        "connection_reused",
        "transport",
        "request_body",
    ];
    for field in event.keys() {
        if !FIELDS.contains(&field.as_str()) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.{field}"),
                "unknown observed trace event field is not permitted",
            ));
        }
    }
    for field in required_fields {
        let Some((container, member)) = field.split_once('.') else {
            if !event.contains_key(*field) {
                diagnostics.push(Diagnostic::new(
                    "FIXTURE-SCHEMA",
                    format!("{path}.{field}"),
                    "required event field is missing",
                ));
            }
            continue;
        };
        let Some(nested) = event.get(container).and_then(Value::as_object) else {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.{container}"),
                "required event object is missing",
            ));
            continue;
        };
        if !nested.contains_key(member) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.{container}.{member}"),
                "required event field is missing",
            ));
        }
    }
    let _ = required_u64(event, "sequence", path, diagnostics);
    let _ = required_string(event, "method", path, "FIXTURE-SCHEMA", diagnostics);
    let _ = required_string(event, "path", path, "FIXTURE-SCHEMA", diagnostics);
    let _ = required_u64(event, "body_length", path, diagnostics);
    let _ = required_digest_string(event, "request_headers_sha256", path, diagnostics);
    let _ = required_digest_string(event, "body_sha256", path, diagnostics);
    if let Some(headers) = event.get("request_headers")
        && !headers.is_array()
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.request_headers"),
            "request_headers must be an array",
        ));
    }
    let Some(response) = required_object(event, "response", path, diagnostics) else {
        return;
    };
    if let Some(status) = response.get("status")
        && !status.is_null()
        && status.as_u64().is_none()
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.response.status"),
            "response status must be a non-negative integer or null",
        ));
    }
    for field in ["body_length", "wire_body_length"] {
        let _ = required_u64(response, field, &format!("{path}.response"), diagnostics);
    }
    for field in ["headers_sha256", "body_sha256"] {
        let _ = required_digest_string(response, field, &format!("{path}.response"), diagnostics);
    }
    if let Some(headers) = response.get("headers")
        && !headers.is_array()
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.response.headers"),
            "response headers must be an array",
        ));
    }
    let _ = state;
}

fn required_digest_string(
    object: &Map<String, Value>,
    field: &str,
    path: &str,
    diagnostics: &mut Diagnostics,
) -> Option<String> {
    let value = required_string(object, field, path, "FIXTURE-SCHEMA", diagnostics)?;
    if !is_sha256(&value) {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.{field}"),
            "must be a lowercase SHA-256 digest",
        ));
        None
    } else {
        Some(value)
    }
}

fn required_string_list(
    object: &Map<String, Value>,
    field: &str,
    path: &str,
    diagnostics: &mut Diagnostics,
) -> Option<Vec<String>> {
    let values = required_array(object, field, path, diagnostics)?;
    let mut output = Vec::with_capacity(values.len());
    for (position, value) in values.iter().enumerate() {
        let Some(value) = value.as_str() else {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.{field}[{position}]"),
                "list members must be strings",
            ));
            continue;
        };
        if value.trim().is_empty() {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.{field}[{position}]"),
                "list members must not be empty",
            ));
        }
        output.push(value.to_owned());
    }
    Some(output)
}

fn validate_http_case_identity(
    object: &Map<String, Value>,
    case: &Map<String, Value>,
    path: &str,
    _profile: &ProfileIndex,
    diagnostics: &mut Diagnostics,
) {
    for field in ["case_id", "fixture_family_id"] {
        if let (Some(expected), Some(actual)) = (
            case.get(field).and_then(Value::as_str),
            object.get(field).and_then(Value::as_str),
        ) && expected != actual
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-REFERENCE",
                format!("{path}.{field}"),
                format!("must match case manifest {expected:?}"),
            ));
        }
    }
    for field in ["conformance_ids", "normalization_policy_refs"] {
        let expected = case.get(field).and_then(Value::as_array).map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .collect::<BTreeSet<_>>()
        });
        let actual = object.get(field).and_then(Value::as_array).map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .collect::<BTreeSet<_>>()
        });
        if expected.is_some() && actual != expected {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-REFERENCE",
                format!("{path}.{field}"),
                "http-trace identity references must exactly match the case manifest",
            ));
        }
    }
}

fn validate_http_case_counts(
    case: &Map<String, Value>,
    counts: &Map<String, Value>,
    event_count: u64,
    path: &str,
    static_contract: bool,
    diagnostics: &mut Diagnostics,
) {
    let Some(max_requests) = http_case_max_requests(case) else {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-REFERENCE",
            format!("{path}.counts.request_count"),
            "http-trace case must declare a finite command.fixture_server.max_requests bound",
        ));
        return;
    };
    for field in ["sampler_count", "request_count", "response_count"] {
        if let Some(value) = counts.get(field).and_then(Value::as_u64)
            && value > max_requests
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-BOUNDS",
                format!("{path}.counts.{field}"),
                format!("count exceeds case max_requests bound {max_requests}"),
            ));
        }
    }
    if event_count > max_requests {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-BOUNDS",
            format!("{path}.events"),
            format!("event count exceeds case max_requests bound {max_requests}"),
        ));
    }
    if let Some(expected) = http_case_expected_requests(case)
        && let Some(actual) = counts.get("request_count").and_then(Value::as_u64)
    {
        if static_contract && actual != expected {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-REFERENCE",
                format!("{path}.counts.request_count"),
                format!("static request_count must match case expected_request_count {expected}"),
            ));
        } else if !static_contract && actual > expected {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-BOUNDS",
                format!("{path}.counts.request_count"),
                format!(
                    "observed request_count exceeds case expected_request_count bound {expected}"
                ),
            ));
        }
    }
}

fn http_case_max_requests(case: &Map<String, Value>) -> Option<u64> {
    case.get("command")
        .and_then(Value::as_object)
        .and_then(|command| command.get("fixture_server"))
        .and_then(Value::as_object)
        .and_then(|server| server.get("max_requests"))
        .and_then(Value::as_u64)
}

fn http_case_expected_requests(case: &Map<String, Value>) -> Option<u64> {
    case.get("command")
        .and_then(Value::as_object)
        .and_then(|command| command.get("fixture_server"))
        .and_then(Value::as_object)
        .and_then(|server| server.get("expected_request_count"))
        .and_then(Value::as_u64)
}

fn validate_http_normalization(
    object: &Map<String, Value>,
    path: &str,
    expected_case: Option<&Map<String, Value>>,
    _profile: &ProfileIndex,
    diagnostics: &mut Diagnostics,
) {
    let Some(normalization) = required_object(object, "normalization", path, diagnostics) else {
        return;
    };
    let normalization_path = format!("{path}.normalization");
    let _ = required_string_list(
        normalization,
        "ignored_fields",
        &normalization_path,
        diagnostics,
    );
    let _ = required_string(
        normalization,
        "reason",
        &normalization_path,
        "FIXTURE-SCHEMA",
        diagnostics,
    );
    for field in ["required_fields", "observable_digest_fields"] {
        if normalization.contains_key(field) {
            let _ = required_string_list(normalization, field, &normalization_path, diagnostics);
        }
    }
    if let Some(case) = expected_case {
        let expected = case
            .get("normalization_policy_refs")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<BTreeSet<_>>()
            });
        let actual = object
            .get("normalization_policy_refs")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<BTreeSet<_>>()
            });
        if expected.is_some() && actual != expected {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-NORMALIZATION",
                format!("{path}.normalization_policy_refs"),
                "normalization policy references must exactly match the case manifest",
            ));
        }
    }
}

fn validate_common_custom_schema(
    object: &Map<String, Value>,
    path: &str,
    diagnostics: &mut Diagnostics,
) {
    if let Some(source_only) = object.get("source_only")
        && !source_only.is_boolean()
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.source_only"),
            "source_only must be a boolean when present",
        ));
    }
    for field in ["raw_artifacts", "artifact_directory"] {
        if let Some(value) = object.get(field)
            && !matches!(value, Value::String(_) | Value::Null | Value::Object(_))
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.{field}"),
                "must be a string or null when present",
            ));
        }
    }
}

fn validate_custom_envelope(
    object: &Map<String, Value>,
    path: &str,
    diagnostics: &mut Diagnostics,
) {
    for field in [
        "schema_id",
        "profile_id",
        "case_id",
        "fixture_family_id",
        "status",
        "evidence_status",
        "execution_status",
        "oracle_status",
        "format",
        "contract_kind",
    ] {
        if let Some(value) = object.get(field)
            && !matches!(value, Value::String(_) | Value::Object(_))
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.{field}"),
                "custom envelope field must be a string or typed object",
            ));
        }
    }
    for field in [
        "conformance_ids",
        "compatibility_ids",
        "normalization_policy_refs",
        "external_runtime_boundary_ids",
    ] {
        if let Some(value) = object.get(field)
            && !value.is_array()
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.{field}"),
                "custom envelope reference field must be an array",
            ));
        }
    }
    if let Some(value) = object.get("generated_from")
        && !value.is_object()
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.generated_from"),
            "generated_from must be an object",
        ));
    }
    if let Some(value) = object.get("materialization")
        && !value.is_object()
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.materialization"),
            "materialization must be an object",
        ));
    }
    if let Some(value) = object.get("raw_artifacts")
        && !matches!(
            value,
            Value::Null | Value::String(_) | Value::Object(_) | Value::Array(_)
        )
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.raw_artifacts"),
            "raw_artifacts must be null, a string, object, or array",
        ));
    }
    if let Some(normalization) = object.get("normalization").and_then(Value::as_object) {
        if let Some(ignored_fields) = normalization.get("ignored_fields")
            && ignored_fields
                .as_array()
                .is_none_or(|values| values.iter().any(|value| value.as_str().is_none()))
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.normalization.ignored_fields"),
                "normalization ignored_fields must be a string list",
            ));
        }
        if let Some(reason) = normalization.get("reason")
            && reason.as_str().is_none()
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.normalization.reason"),
                "normalization reason must be a string",
            ));
        }
    }
}

fn validate_file_artifact_contract(
    object: &Map<String, Value>,
    path: &str,
    diagnostics: &mut Diagnostics,
) {
    const FIELDS: [&str; 11] = [
        "schema_id",
        "schema_version",
        "contract_kind",
        "profile_id",
        "case_id",
        "fixture_family_id",
        "evidence_status",
        "artifact_status",
        "root",
        "artifacts",
        "normalization",
    ];
    for field in object.keys() {
        if !FIELDS.contains(&field.as_str()) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.{field}"),
                "unknown file-artifact contract field is not permitted",
            ));
        }
    }
    let contract_kind =
        required_string(object, "contract_kind", path, "FIXTURE-SCHEMA", diagnostics);
    if contract_kind.as_deref() != Some("string-to-file-artifacts") {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.contract_kind"),
            "file-artifact contract_kind must be string-to-file-artifacts",
        ));
    }
    let artifact_status = required_string(
        object,
        "artifact_status",
        path,
        "FIXTURE-SCHEMA",
        diagnostics,
    );
    if artifact_status.as_deref().is_some_and(|status| {
        !matches!(
            status,
            "future-run-only" | "not-run" | "planned" | "materialized" | "observed"
        )
    }) {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.artifact_status"),
            "unsupported closed artifact_status",
        ));
    }
    if let Some(root) = required_string(object, "root", path, "FIXTURE-SCHEMA", diagnostics)
        && !is_descriptor_path(&root)
        && !is_safe_relative_path(&root)
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-PATH",
            format!("{path}.root"),
            "artifact contract root must be a safe relative path or typed placeholder",
        ));
    }
    let Some(artifacts) = required_array(object, "artifacts", path, diagnostics) else {
        return;
    };
    if artifacts.is_empty() {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.artifacts"),
            "file artifact contract requires at least one artifact",
        ));
    }
    for (position, artifact) in artifacts.iter().enumerate() {
        let item_path = format!("{path}.artifacts[{position}]");
        let Some(artifact) = artifact.as_object() else {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                item_path,
                "file artifact contract entries must be objects",
            ));
            continue;
        };
        const ARTIFACT_FIELDS: [&str; 8] = [
            "path",
            "operation",
            "encoding",
            "expected_content",
            "repository_policy",
            "expected_bytes",
            "sha256",
            "present_in_repository",
        ];
        for field in artifact.keys() {
            if !ARTIFACT_FIELDS.contains(&field.as_str()) {
                diagnostics.push(Diagnostic::new(
                    "FIXTURE-SCHEMA",
                    format!("{item_path}.{field}"),
                    "unknown file artifact field is not permitted",
                ));
            }
        }
        let artifact_path =
            required_string(artifact, "path", &item_path, "FIXTURE-SCHEMA", diagnostics);
        let operation = required_string(
            artifact,
            "operation",
            &item_path,
            "FIXTURE-SCHEMA",
            diagnostics,
        );
        let encoding = required_string(
            artifact,
            "encoding",
            &item_path,
            "FIXTURE-SCHEMA",
            diagnostics,
        );
        let expected_content = required_string(
            artifact,
            "expected_content",
            &item_path,
            "FIXTURE-SCHEMA",
            diagnostics,
        );
        let repository_policy = required_string(
            artifact,
            "repository_policy",
            &item_path,
            "FIXTURE-SCHEMA",
            diagnostics,
        );
        let expected_bytes = required_u64(artifact, "expected_bytes", &item_path, diagnostics);
        let present_in_repository =
            required_bool(artifact, "present_in_repository", &item_path, diagnostics);
        if let Some(artifact_path) = artifact_path.as_deref()
            && !is_descriptor_path(artifact_path)
            && !is_safe_relative_path(artifact_path)
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-PATH",
                format!("{item_path}.path"),
                "file artifact path must be safe and relative or a typed placeholder",
            ));
        }
        if operation.as_deref().is_some_and(|operation| {
            !matches!(operation, "replace" | "append" | "replace-then-append")
        }) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{item_path}.operation"),
                "unsupported file artifact operation",
            ));
        }
        if encoding.as_deref().is_some_and(|encoding| {
            !matches!(encoding, "UTF-8" | "UTF-16LE" | "UTF-16BE" | "US-ASCII")
        }) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{item_path}.encoding"),
                "unsupported file artifact encoding",
            ));
        }
        if let (Some(content), Some(bytes), Some(encoding)) = (
            expected_content.as_deref(),
            expected_bytes,
            encoding.as_deref(),
        ) && encoded_content_len(content, encoding) != Some(bytes)
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-REFERENCE",
                format!("{item_path}.expected_bytes"),
                "must equal the encoded expected_content byte length",
            ));
        }
        if repository_policy.is_some()
            && present_in_repository == Some(true)
            && let Some(artifact_path) = artifact_path.as_deref()
            && is_descriptor_path(artifact_path)
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{item_path}.path"),
                "repository-present artifacts cannot use a typed future path placeholder",
            ));
        }
        let hash = required_string(
            artifact,
            "sha256",
            &item_path,
            "FIXTURE-SCHEMA",
            diagnostics,
        );
        if let Some(hash) = hash
            && !is_sha256(&hash)
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{item_path}.sha256"),
                "file artifact SHA-256 must be a lowercase digest",
            ));
        }
    }
    let Some(normalization) = required_object(object, "normalization", path, diagnostics) else {
        return;
    };
    let _ = required_array(
        normalization,
        "ignored_fields",
        &format!("{path}.normalization"),
        diagnostics,
    );
    let _ = required_string(
        normalization,
        "reason",
        &format!("{path}.normalization"),
        "FIXTURE-SCHEMA",
        diagnostics,
    );
}

fn validate_materialization_claim(
    object: &Map<String, Value>,
    path: &str,
    diagnostics: &mut Diagnostics,
) {
    let Some(materialization) = object.get("materialization").and_then(Value::as_object) else {
        return;
    };
    for field in [
        "source_fixture_present",
        "oracle_evidence_materialized",
        "observed_run",
    ] {
        if materialization
            .get(field)
            .and_then(Value::as_bool)
            .is_none()
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.materialization.{field}"),
                "materialization state must be an explicit boolean",
            ));
        }
    }
    if materialization.get("oracle_evidence_materialized") == Some(&Value::Bool(true))
        && materialization.get("observed_run") != Some(&Value::Bool(true))
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-EVIDENCE",
            format!("{path}.materialization.observed_run"),
            "materialized oracle evidence requires an observed run",
        ));
    }
    if materialization.get("oracle_evidence_materialized") == Some(&Value::Bool(true))
        && materialization.get("source_fixture_present") != Some(&Value::Bool(true))
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-EVIDENCE",
            format!("{path}.materialization.source_fixture_present"),
            "materialized oracle evidence requires source fixture presence",
        ));
    }
}

fn require_observed_materialization(
    object: &Map<String, Value>,
    path: &str,
    state: Option<ExecutionState>,
    diagnostics: &mut Diagnostics,
) {
    if state != Some(ExecutionState::Observed) {
        return;
    }
    let Some(materialization) = object.get("materialization").and_then(Value::as_object) else {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-EVIDENCE",
            format!("{path}.materialization"),
            "observed evidence requires an explicit materialization object",
        ));
        return;
    };
    for field in [
        "source_fixture_present",
        "oracle_evidence_materialized",
        "observed_run",
    ] {
        if materialization.get(field) != Some(&Value::Bool(true)) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-EVIDENCE",
                format!("{path}.materialization.{field}"),
                "observed evidence requires this materialization flag to be true",
            ));
        }
    }
    if let Some(immutable) = materialization.get("immutable")
        && immutable != &Value::Bool(true)
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-EVIDENCE",
            format!("{path}.materialization.immutable"),
            "observed evidence cannot use mutable materialization",
        ));
    }
}

fn validate_quarantine_materialization(
    object: &Map<String, Value>,
    path: &str,
    state: Option<ExecutionState>,
    diagnostics: &mut Diagnostics,
) {
    if state != Some(ExecutionState::Quarantined) {
        return;
    }
    if let Some(materialization) = object.get("materialization").and_then(Value::as_object) {
        for field in ["oracle_evidence_materialized", "observed_run", "immutable"] {
            if materialization.get(field) == Some(&Value::Bool(true)) {
                diagnostics.push(Diagnostic::new(
                    "FIXTURE-EVIDENCE",
                    format!("{path}.materialization.{field}"),
                    "quarantined external observations cannot materialize immutable oracle evidence",
                ));
            }
        }
    }
    if let Some(execution) = object.get("execution").and_then(Value::as_object)
        && let Some(raw_artifacts) = execution.get("raw_artifacts")
    {
        validate_quarantine_raw_artifacts(
            raw_artifacts,
            &format!("{path}.execution.raw_artifacts"),
            diagnostics,
        );
    }
    if let Some(raw_artifacts) = object.get("raw_artifacts") {
        validate_quarantine_raw_artifacts(
            raw_artifacts,
            &format!("{path}.raw_artifacts"),
            diagnostics,
        );
    }
}

fn validate_quarantine_raw_artifacts(value: &Value, path: &str, diagnostics: &mut Diagnostics) {
    match value {
        Value::Array(values) => {
            for (position, value) in values.iter().enumerate() {
                validate_quarantine_raw_artifacts(
                    value,
                    &format!("{path}[{position}]"),
                    diagnostics,
                );
            }
        }
        Value::Object(object) => {
            if object.get("present") == Some(&Value::Bool(true)) {
                diagnostics.push(Diagnostic::new(
                    "FIXTURE-EVIDENCE",
                    format!("{path}.present"),
                    "quarantined external observations cannot materialize raw artifacts",
                ));
            }
            for (field, nested) in object {
                if field != "present" {
                    validate_quarantine_raw_artifacts(
                        nested,
                        &format!("{path}.{field}"),
                        diagnostics,
                    );
                }
            }
        }
        _ => {}
    }
}

fn validate_proxy_mirror_inputs(
    object: &Map<String, Value>,
    path: &str,
    diagnostics: &mut Diagnostics,
) {
    let _ = required_string(object, "encoding", path, "FIXTURE-SCHEMA", diagnostics);
    let limits = required_object(object, "limits", path, diagnostics);
    let cases = required_array(object, "cases", path, diagnostics);
    let planned_cases = required_array(object, "planned_cases", path, diagnostics);
    if let Some(limits) = limits {
        for field in [
            "observed_case_count",
            "planned_case_count",
            "max_total_cases",
            "max_wire_bytes",
            "max_body_bytes",
            "max_request_headers",
            "max_response_headers",
            "max_redirect_hops",
            "server_pool_size",
            "server_queue_size",
            "max_saturation_clients",
        ] {
            let _ = required_u64(limits, field, &format!("{path}.limits"), diagnostics);
        }
        if let (Some(observed), Some(planned), Some(total)) = (
            limits.get("observed_case_count").and_then(Value::as_u64),
            limits.get("planned_case_count").and_then(Value::as_u64),
            limits.get("max_total_cases").and_then(Value::as_u64),
        ) && observed.saturating_add(planned) > total
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-BOUNDS",
                format!("{path}.limits.max_total_cases"),
                "max_total_cases must cover observed and planned case counts",
            ));
        }
    }
    validate_mirror_case_ids(cases, &format!("{path}.cases"), diagnostics);
    validate_mirror_case_ids(planned_cases, &format!("{path}.planned_cases"), diagnostics);
    if let (Some(cases), Some(limits)) = (cases, limits)
        && let Some(expected) = limits.get("observed_case_count").and_then(Value::as_u64)
        && cases.len() as u64 != expected
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-BOUNDS",
            format!("{path}.limits.observed_case_count"),
            format!("must match cases length {}", cases.len()),
        ));
    }
    if let (Some(cases), Some(limits)) = (planned_cases, limits)
        && let Some(expected) = limits.get("planned_case_count").and_then(Value::as_u64)
        && cases.len() as u64 != expected
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-BOUNDS",
            format!("{path}.limits.planned_case_count"),
            format!("must match planned_cases length {}", cases.len()),
        ));
    }
}

fn validate_proxy_mirror_expectation(
    object: &Map<String, Value>,
    path: &str,
    diagnostics: &mut Diagnostics,
) {
    let cases = required_array(object, "cases", path, diagnostics);
    let planned_cases = required_array(object, "planned_cases", path, diagnostics);
    let _ = required_object(object, "server", path, diagnostics);
    if let Some(normalization) = required_object(object, "normalization", path, diagnostics) {
        let _ = required_array(
            normalization,
            "ignored_fields",
            &format!("{path}.normalization"),
            diagnostics,
        );
        let _ = required_string(
            normalization,
            "reason",
            &format!("{path}.normalization"),
            "FIXTURE-SCHEMA",
            diagnostics,
        );
    }
    validate_mirror_case_ids(cases, &format!("{path}.cases"), diagnostics);
    validate_mirror_case_ids(planned_cases, &format!("{path}.planned_cases"), diagnostics);
}

fn validate_proxy_mirror_api_expectation(
    object: &Map<String, Value>,
    path: &str,
    diagnostics: &mut Diagnostics,
) {
    let source = required_object(object, "source", path, diagnostics);
    let control = required_object(object, "control", path, diagnostics);
    let server = required_object(object, "server", path, diagnostics);
    for (name, value) in [("source", source), ("control", control), ("server", server)] {
        if let Some(value) = value
            && name != "source"
            && value.get("class").and_then(Value::as_str).is_none()
        {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{path}.{name}.class"),
                "API descriptor requires a class string",
            ));
        }
    }
    if let Some(source) = source {
        for field in ["project", "version", "source_commit"] {
            let _ = required_string(
                source,
                field,
                &format!("{path}.source"),
                "FIXTURE-SCHEMA",
                diagnostics,
            );
        }
    }
}

fn validate_mirror_case_ids(cases: Option<&Vec<Value>>, path: &str, diagnostics: &mut Diagnostics) {
    let Some(cases) = cases else {
        return;
    };
    let mut ids = BTreeSet::new();
    for (position, value) in cases.iter().enumerate() {
        let item_path = format!("{path}[{position}]");
        let Some(case) = value.as_object() else {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                item_path,
                "mirror vector must be an object",
            ));
            continue;
        };
        let Some(id) = case.get("id").and_then(Value::as_str) else {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{item_path}.id"),
                "mirror vector requires an id string",
            ));
            continue;
        };
        if !ids.insert(id.to_owned()) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{item_path}.id"),
                format!("duplicate mirror vector ID {id:?}"),
            ));
        }
    }
}

fn validate_bound_sections(object: &Map<String, Value>, path: &str, diagnostics: &mut Diagnostics) {
    walk_bound_sections(object, path, diagnostics);
}

fn walk_bound_sections(object: &Map<String, Value>, path: &str, diagnostics: &mut Diagnostics) {
    for (field, value) in object {
        let field_path = format!("{path}.{field}");
        if field == "bounds" || field == "limits" {
            validate_bound_object(value, &field_path, diagnostics);
        }
        match value {
            Value::Object(value) => walk_bound_sections(value, &field_path, diagnostics),
            Value::Array(values) => {
                for (position, value) in values.iter().enumerate() {
                    if let Value::Object(value) = value {
                        walk_bound_sections(
                            value,
                            &format!("{field_path}[{position}]"),
                            diagnostics,
                        );
                    }
                }
            }
            _ => {}
        }
    }
}

fn validate_bound_object(value: &Value, path: &str, diagnostics: &mut Diagnostics) {
    let Some(object) = value.as_object() else {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            path,
            "bounds or limits must be an object",
        ));
        return;
    };
    validate_bound_map(object, path, diagnostics, false);
}

fn validate_bound_map(
    object: &Map<String, Value>,
    path: &str,
    diagnostics: &mut Diagnostics,
    network_disabled: bool,
) {
    if object.is_empty() {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-BOUNDS",
            path,
            "bounds or limits must declare at least one finite value",
        ));
    }
    for (field, value) in object {
        let field_path = format!("{path}.{field}");
        validate_bound_value(
            value,
            &field_path,
            diagnostics,
            network_disabled
                || (field == "network"
                    && value
                        .as_object()
                        .and_then(|network| network.get("policy"))
                        .and_then(Value::as_str)
                        == Some("none")),
        );
    }
}

fn validate_bound_value(
    value: &Value,
    path: &str,
    diagnostics: &mut Diagnostics,
    network_disabled: bool,
) {
    match value {
        Value::Number(number) => match number.as_u64() {
            Some(value) if value <= MAX_DECLARED_BOUND => {}
            Some(_) => diagnostics.push(Diagnostic::new(
                "FIXTURE-BOUNDS",
                path,
                format!("bound exceeds {MAX_DECLARED_BOUND}"),
            )),
            None => diagnostics.push(Diagnostic::new(
                "FIXTURE-BOUNDS",
                path,
                "bound must be a non-negative integer",
            )),
        },
        Value::Object(value) => validate_bound_map(value, path, diagnostics, network_disabled),
        Value::Array(values) => {
            if values.is_empty() && !(path.ends_with(".allowed_hosts") && network_disabled) {
                diagnostics.push(Diagnostic::new(
                    "FIXTURE-BOUNDS",
                    path,
                    "bound array must declare at least one finite value",
                ));
            }
            for (position, value) in values.iter().enumerate() {
                validate_bound_value(
                    value,
                    &format!("{path}[{position}]"),
                    diagnostics,
                    network_disabled,
                );
            }
        }
        Value::Bool(_) => {}
        Value::String(value) if !value.is_empty() => {}
        Value::String(_) => diagnostics.push(Diagnostic::new(
            "FIXTURE-BOUNDS",
            path,
            "bound text must not be empty",
        )),
        _ => diagnostics.push(Diagnostic::new(
            "FIXTURE-BOUNDS",
            path,
            "bound must be an integer, non-empty descriptor, array, or object",
        )),
    }
}

fn validate_digest_fields(
    object: &Map<String, Value>,
    path: &str,
    state: Option<ExecutionState>,
    diagnostics: &mut Diagnostics,
) {
    for (field, value) in object {
        let field_path = format!("{path}.{field}");
        let normalized = field.to_ascii_lowercase();
        if normalized == "sha256" || normalized.ends_with("_sha256") {
            validate_digest_value(value, 64, &field_path, state, diagnostics);
        } else if normalized == "sha512" || normalized.ends_with("_sha512") {
            validate_digest_value(value, 128, &field_path, state, diagnostics);
        }
        match value {
            Value::Object(value) => validate_digest_fields(value, &field_path, state, diagnostics),
            Value::Array(values) => {
                for (position, value) in values.iter().enumerate() {
                    if let Value::Object(value) = value {
                        validate_digest_fields(
                            value,
                            &format!("{field_path}[{position}]"),
                            state,
                            diagnostics,
                        );
                    }
                }
            }
            _ => {}
        }
    }
}

fn validate_digest_value(
    value: &Value,
    length: usize,
    path: &str,
    state: Option<ExecutionState>,
    diagnostics: &mut Diagnostics,
) {
    match value {
        Value::Object(object) if !looks_like_schema_descriptor(object) => {
            for value in object.values() {
                validate_digest_value(value, length, path, state, diagnostics);
            }
        }
        Value::Array(values) => {
            for (position, value) in values.iter().enumerate() {
                validate_digest_value(
                    value,
                    length,
                    &format!("{path}[{position}]"),
                    state,
                    diagnostics,
                );
            }
        }
        Value::Object(_) => {}
        Value::Null if state != Some(ExecutionState::Observed) => {}
        Value::String(value) if is_hex_digest(value, length) => {}
        Value::String(value)
            if state != Some(ExecutionState::Observed) && is_unresolved_digest_marker(value) => {}
        Value::Null | Value::String(_) => diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            path,
            format!("must be a {length}-character lowercase hexadecimal digest or an explicit static marker"),
        )),
        _ => diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            path,
            "digest must be a string or null for non-observed evidence",
        )),
    }
}

fn looks_like_schema_descriptor(object: &Map<String, Value>) -> bool {
    ["$ref", "type", "pattern", "anyOf", "const", "enum"]
        .iter()
        .any(|field| object.contains_key(*field))
}

fn is_hex_digest(value: &str, length: usize) -> bool {
    value.len() == length
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        && value.bytes().all(|byte| !byte.is_ascii_uppercase())
}

fn is_unresolved_digest_marker(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    is_placeholder_hash(value)
        || lower.contains("required")
        || lower.contains("not-recorded")
        || lower.contains("trace ")
        || lower.contains("not observed")
        || lower.contains("lowercase 64-character")
        || lower.contains("to_be_updated")
        || lower.contains("unavailable")
}

fn check_expectation_normalization_refs(
    object: &Map<String, Value>,
    path: &str,
    profile: &ProfileIndex,
    diagnostics: &mut Diagnostics,
) {
    let Some(values) = object
        .get("normalization_policy_refs")
        .and_then(Value::as_array)
    else {
        return;
    };
    let mut seen = BTreeSet::new();
    for (position, value) in values.iter().enumerate() {
        let item_path = format!("{path}.normalization_policy_refs[{position}]");
        let Some(reference) = value.as_str() else {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                item_path,
                "normalization policy reference must be a string",
            ));
            continue;
        };
        if !seen.insert(reference.to_owned()) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                item_path.clone(),
                "normalization policy references must be unique",
            ));
        }
        if !profile.normalization_ids.contains(reference) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-REFERENCE",
                item_path,
                format!("unknown profile normalization policy {reference:?}"),
            ));
        }
    }
}

fn expectation_state(object: &Map<String, Value>) -> Option<ExecutionState> {
    if object
        .get("generated_from")
        .and_then(Value::as_object)
        .is_some_and(|generated| generated.get("runtime_executed") == Some(&Value::Bool(false)))
    {
        return Some(ExecutionState::NotRun);
    }
    let candidates = [
        ("evidence_status", object.get("evidence_status")),
        ("execution_status", object.get("execution_status")),
        (
            "oracle_execution.status",
            object
                .get("oracle_execution")
                .and_then(Value::as_object)
                .and_then(|execution| execution.get("status")),
        ),
        (
            "generated_from.execution_status",
            object
                .get("generated_from")
                .and_then(Value::as_object)
                .and_then(|generated| generated.get("execution_status")),
        ),
        (
            "source.oracle_status",
            object
                .get("source")
                .and_then(Value::as_object)
                .and_then(|source| source.get("oracle_status")),
        ),
    ];
    for (field, value) in candidates {
        let Some(value) = value else {
            continue;
        };
        if let Some(state) = parse_expectation_state(value) {
            return Some(state);
        }
        // Explicit evidence fields are closed vocabularies.  Do not turn an
        // unknown value into a guessed state based on a substring.
        if field != "source.oracle_status" {
            return None;
        }
    }
    // A bare descriptor status is intentionally not an execution claim.
    // Custom schema validators validate its own vocabulary; the absence of
    // an evidence field means the descriptor remains not-run.
    Some(ExecutionState::NotRun)
}

fn parse_expectation_state(value: &Value) -> Option<ExecutionState> {
    if let Some(state) = parse_execution_state(value) {
        return Some(state);
    }
    let status = value.as_str()?;
    const OBSERVED: [&str; 6] = [
        "example-only",
        "example",
        "pass",
        "ok",
        "verified",
        "observed",
    ];
    const NOT_RUN: [&str; 21] = [
        "not_run",
        "not-run",
        "not-run-static",
        "not-run-static-corpus",
        "not-run-static-handoff",
        "static-not-run",
        "static-only",
        "static-only-forbidden-oracle",
        "static-projection-pending-round-trip",
        "planned",
        "planned; not-run",
        "planned; external Java/RMI runner not executed",
        "planned; external display/runtime not provisioned",
        "planned; no GUI smoke test run",
        "planned; no headless process was run",
        "planned; static descriptor only",
        "planned; static expectation only",
        "planned; not observed",
        "not-run-static-external",
        "not-run-static-only",
        "not-run-static-preservation",
    ];
    const UNAVAILABLE: [&str; 5] = [
        "external-unavailable",
        "external-unavailable; static-only; plugin oracle not executed",
        "unavailable-static",
        "unavailable",
        "blocked",
    ];
    if OBSERVED.contains(&status) {
        Some(ExecutionState::Observed)
    } else if NOT_RUN.contains(&status) {
        Some(ExecutionState::NotRun)
    } else if UNAVAILABLE.contains(&status) {
        Some(ExecutionState::Unavailable)
    } else {
        None
    }
}

fn expectation_is_static(object: &Map<String, Value>) -> bool {
    let Some(status) = object
        .get("evidence_status")
        .or_else(|| object.get("execution_status"))
        .or_else(|| object.get("status"))
        .and_then(Value::as_str)
    else {
        return false;
    };
    matches!(
        status,
        "static-only"
            | "static-only-forbidden-oracle"
            | "static-projection-pending-round-trip"
            | "static-not-run"
            | "not-run-static"
            | "not-run-static-corpus"
            | "planned; static descriptor only"
            | "planned; static expectation only"
            | "planned; not-run"
    )
}

#[allow(clippy::too_many_arguments)]
fn check_expectation_evidence(
    root: &Path,
    object: &Map<String, Value>,
    schema_id: &str,
    path: &str,
    profile: &ProfileIndex,
    expected_case_id: Option<&str>,
    expected_case_state: Option<ExecutionState>,
    state: Option<ExecutionState>,
    diagnostics: &mut Diagnostics,
) {
    let Some(state) = state else {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-EVIDENCE",
            path,
            "expectation evidence state must be observed, not-run, or unavailable",
        ));
        return;
    };
    let state_matches_case = expected_case_state.is_none_or(|expected_case_state| {
        expected_case_state == state
            || matches!(
                (expected_case_state, state),
                (ExecutionState::Unavailable, ExecutionState::NotRun)
                    | (ExecutionState::NotRun, ExecutionState::Unavailable)
                    | (ExecutionState::Quarantined, ExecutionState::NotRun)
            )
            || (expected_case_state == ExecutionState::Observed
                && state == ExecutionState::NotRun
                && expectation_is_static(object))
            || (expected_case_state == ExecutionState::Quarantined
                && state == ExecutionState::NotRun
                && expectation_is_static(object))
    });
    if let Some(expected_case_state) = expected_case_state
        && !state_matches_case
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-EVIDENCE",
            path,
            format!(
                "expectation state {state:?} does not match case execution state {expected_case_state:?}"
            ),
        ));
    }
    let generated = object.get("generated_from").and_then(Value::as_object);
    verify_oracle_artifact_digest(generated, path, profile, state, diagnostics);
    if let Some(expected_case_id) = expected_case_id
        && let Some(actual_case_id) = object.get("case_id").and_then(Value::as_str)
        && actual_case_id != expected_case_id
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-REFERENCE",
            format!("{path}.case_id"),
            format!("must match case manifest case_id {expected_case_id:?}"),
        ));
    }
    if state == ExecutionState::Observed
        && generated
            .and_then(|generated| generated.get("raw_artifacts"))
            .is_none()
    {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-EVIDENCE",
            format!("{path}.generated_from.raw_artifacts"),
            "observed expectation must identify retained local raw evidence or an explicit ignored path",
        ));
    }
    if let Some(generated) = generated
        && let Some(raw_artifacts) = generated.get("raw_artifacts")
    {
        validate_raw_artifacts(
            root,
            root,
            raw_artifacts,
            &format!("{path}.generated_from.raw_artifacts"),
            Some(state),
            diagnostics,
        );
    }
    require_observed_materialization(object, path, Some(state), diagnostics);
    let _ = schema_id;
}

fn verify_oracle_artifact_digest(
    generated: Option<&Map<String, Value>>,
    path: &str,
    profile: &ProfileIndex,
    state: ExecutionState,
    diagnostics: &mut Diagnostics,
) {
    let artifact_digest = generated
        .and_then(|generated| generated.get("artifact_sha512"))
        .and_then(Value::as_str);
    if let Some(artifact_digest) = artifact_digest {
        if artifact_digest != profile.upstream.digest {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-PROVENANCE",
                format!("{path}.generated_from.artifact_sha512"),
                "expectation artifact digest must match active profile",
            ));
        }
    } else if state == ExecutionState::Observed {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-EVIDENCE",
            format!("{path}.generated_from.artifact_sha512"),
            "observed expectation requires the pinned oracle artifact digest",
        ));
    }
}

fn validate_raw_artifacts(
    root: &Path,
    base: &Path,
    value: &Value,
    path: &str,
    state: Option<ExecutionState>,
    diagnostics: &mut Diagnostics,
) {
    match value {
        Value::String(raw) => {
            if state == Some(ExecutionState::Observed) {
                diagnostics.push(Diagnostic::new(
                    "FIXTURE-EVIDENCE",
                    path,
                    "observed raw artifacts require an object with a safe path, materialized content, and SHA-256 digest",
                ));
                return;
            }
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                diagnostics.push(Diagnostic::new(
                    "FIXTURE-SCHEMA",
                    path,
                    "raw_artifacts string must not be empty",
                ));
                return;
            }
            let first = trimmed.split_whitespace().next().unwrap_or_default();
            let ignored = trimmed.to_ascii_lowercase().contains("ignored")
                || trimmed.to_ascii_lowercase().contains("outside-git")
                || trimmed.to_ascii_lowercase().contains("not produced");
            if matches!(first, "none" | "null" | "ignored") {
                if state == Some(ExecutionState::Observed) {
                    diagnostics.push(Diagnostic::new(
                        "FIXTURE-EVIDENCE",
                        path,
                        "observed evidence must name a safe raw-artifact path or retained artifact object",
                    ));
                }
                return;
            }
            if !check_safe_path_value(root, base, first, path, diagnostics) {
                return;
            }
            let artifact_path = lexical_join(base, first).unwrap_or_else(|| base.join(first));
            if artifact_path.exists() && !ignored {
                validate_existing_raw_artifact(root, &artifact_path, path, diagnostics);
            } else if state == Some(ExecutionState::Observed) && !ignored {
                diagnostics.push(Diagnostic::new(
                    "FIXTURE-EVIDENCE",
                    path,
                    format!(
                        "observed raw artifact {} does not exist and is not explicitly marked ignored",
                        display_path(root, &artifact_path)
                    ),
                ));
            }
        }
        Value::Object(object) => {
            if let Some(present) = object.get("present")
                && !present.is_boolean()
            {
                diagnostics.push(Diagnostic::new(
                    "FIXTURE-SCHEMA",
                    format!("{path}.present"),
                    "raw-artifact present must be boolean",
                ));
            }
            if let Some(declared_path) = object.get("path").and_then(Value::as_str) {
                let present = object
                    .get("present")
                    .and_then(Value::as_bool)
                    .unwrap_or(true);
                if state == Some(ExecutionState::Observed) && !present {
                    diagnostics.push(Diagnostic::new(
                        "FIXTURE-EVIDENCE",
                        format!("{path}.present"),
                        "observed raw artifacts must be materialized (present=true)",
                    ));
                }
                let Some(artifact_path) = safe_fixture_path(root, base, declared_path) else {
                    diagnostics.push(Diagnostic::new(
                        "FIXTURE-PATH",
                        format!("{path}.path"),
                        "raw-artifact path must be safe and repository-relative",
                    ));
                    return;
                };
                if present {
                    if !artifact_path.is_file() {
                        diagnostics.push(Diagnostic::new(
                            "FIXTURE-REFERENCE",
                            format!("{path}.path"),
                            format!(
                                "materialized raw artifact {} does not exist",
                                display_path(root, &artifact_path)
                            ),
                        ));
                    }
                    if let Some(hash) = object.get("sha256") {
                        validate_declared_file_hash(
                            root,
                            base,
                            declared_path,
                            hash,
                            path,
                            state != Some(ExecutionState::Observed),
                            diagnostics,
                        );
                    } else {
                        diagnostics.push(Diagnostic::new(
                            "FIXTURE-SCHEMA",
                            format!("{path}.sha256"),
                            "materialized raw artifacts require a SHA-256 digest",
                        ));
                    }
                } else if let Some(hash) = object.get("sha256")
                    && !hash.is_null()
                {
                    diagnostics.push(Diagnostic::new(
                        "FIXTURE-SCHEMA",
                        format!("{path}.sha256"),
                        "absent raw artifacts must use a null digest",
                    ));
                }
            } else if state == Some(ExecutionState::Observed) {
                diagnostics.push(Diagnostic::new(
                    "FIXTURE-EVIDENCE",
                    path,
                    "observed raw artifact objects require a path and content digest",
                ));
            }
            for (field, nested) in object {
                if field != "path" && field != "sha256" {
                    validate_raw_artifacts(
                        root,
                        base,
                        nested,
                        &format!("{path}.{field}"),
                        state,
                        diagnostics,
                    );
                }
            }
        }
        Value::Array(values) => {
            for (position, value) in values.iter().enumerate() {
                validate_raw_artifacts(
                    root,
                    base,
                    value,
                    &format!("{path}[{position}]"),
                    state,
                    diagnostics,
                );
            }
        }
        Value::Null if state != Some(ExecutionState::Observed) => {}
        Value::Null => diagnostics.push(Diagnostic::new(
            "FIXTURE-EVIDENCE",
            path,
            "observed raw artifacts cannot be null",
        )),
        _ => diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            path,
            "raw_artifacts must be a string, object, or array",
        )),
    }
}

fn validate_existing_raw_artifact(
    root: &Path,
    path: &Path,
    diagnostic_path: &str,
    diagnostics: &mut Diagnostics,
) {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return;
    };
    if metadata.file_type().is_symlink() {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-PATH",
            diagnostic_path,
            "raw artifacts must not be symlinks",
        ));
        return;
    }
    if metadata.is_file() {
        if metadata.len() > MAX_FIXTURE_FILE_BYTES {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-BOUNDS",
                diagnostic_path,
                format!("raw artifact exceeds {MAX_FIXTURE_FILE_BYTES}-byte bound"),
            ));
        }
        check_file_extension(root, path, diagnostics);
    } else if metadata.is_dir() {
        let mut files = Vec::new();
        collect_files(root, path, &mut files, diagnostics);
        if files.is_empty() {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-EVIDENCE",
                diagnostic_path,
                "materialized raw-artifact directory must contain at least one file",
            ));
        }
    } else {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-PATH",
            diagnostic_path,
            "raw artifact must be a regular file or directory",
        ));
    }
}

fn check_schema_header(
    object: &Map<String, Value>,
    path: &str,
    expected: &str,
    diagnostics: &mut Diagnostics,
) {
    match object.get("schema_id").and_then(Value::as_str) {
        Some(actual) if actual == expected => {}
        Some(actual) => diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.schema_id"),
            format!("must be {expected:?}, found {actual:?}"),
        )),
        None => diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.schema_id"),
            "required schema_id string is missing",
        )),
    }
    match object.get("schema_version").and_then(Value::as_u64) {
        Some(actual) if actual == SCHEMA_VERSION => {}
        Some(actual) => diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.schema_version"),
            format!("must be schema version {SCHEMA_VERSION}, found {actual}"),
        )),
        None => diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{path}.schema_version"),
            "required schema_version integer is missing",
        )),
    }
}

fn check_id_array(
    object: &Map<String, Value>,
    field: &str,
    parent_path: &str,
    known: &BTreeSet<String>,
    diagnostics: &mut Diagnostics,
    feature_ids: bool,
) {
    let Some(values) = required_array(object, field, parent_path, diagnostics) else {
        return;
    };
    let mut seen = BTreeSet::new();
    for (position, value) in values.iter().enumerate() {
        let path = format!("{parent_path}.{field}[{position}]");
        let Some(value) = value.as_str() else {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                path,
                "reference must be a string",
            ));
            continue;
        };
        if !seen.insert(value.to_owned()) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                path.clone(),
                format!("duplicate reference {value:?}"),
            ));
        }
        if feature_ids && !is_feature_id(value) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-REFERENCE",
                path.clone(),
                format!("invalid conformance ID {value:?}"),
            ));
        }
        if !known.contains(value) {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-REFERENCE",
                path,
                format!("unknown profile reference {value:?}"),
            ));
        }
    }
}

fn required_safe_path(
    root: &Path,
    base: &Path,
    object: &Map<String, Value>,
    field: &str,
    parent_path: &str,
    diagnostics: &mut Diagnostics,
) -> Option<PathBuf> {
    let value = required_string(object, field, parent_path, "FIXTURE-SCHEMA", diagnostics)?;
    if !check_safe_path_value(
        root,
        base,
        &value,
        &format!("{parent_path}.{field}"),
        diagnostics,
    ) {
        return None;
    }
    Some(base.join(value))
}

fn check_safe_path_value(
    root: &Path,
    base: &Path,
    value: &str,
    path: &str,
    diagnostics: &mut Diagnostics,
) -> bool {
    let safe = !value.is_empty()
        && !value.contains('\0')
        && !value.contains('\\')
        && !Path::new(value).is_absolute()
        && lexical_join(base, value).is_some_and(|joined| joined.strip_prefix(root).is_ok());
    if !safe {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-PATH",
            path,
            "must be a safe relative path without traversal, absolute roots, or backslashes",
        ));
    }
    safe
}

fn lexical_join(base: &Path, value: &str) -> Option<PathBuf> {
    let mut joined = base.to_path_buf();
    for component in Path::new(value).components() {
        match component {
            Component::CurDir => {}
            Component::Normal(component) => joined.push(component),
            Component::ParentDir => {
                if !joined.pop() {
                    return None;
                }
            }
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(joined)
}

fn is_safe_relative_path(value: &str) -> bool {
    !value.is_empty()
        && !value.contains('\0')
        && !value.contains('\\')
        && !Path::new(value).is_absolute()
        && !Path::new(value)
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::RootDir))
}

fn expected_paths(value: &Value) -> Vec<String> {
    match value {
        Value::String(value) => vec![value.clone()],
        Value::Array(values) => values
            .iter()
            .filter_map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .or_else(|| value.get("path").and_then(Value::as_str).map(str::to_owned))
            })
            .collect(),
        Value::Object(object) => object
            .get("path")
            .and_then(Value::as_str)
            .map_or_else(Vec::new, |path| vec![path.to_owned()]),
        _ => Vec::new(),
    }
}

fn case_has_immutable_expected_hashes(
    case: &Map<String, Value>,
    case_dir: &Path,
    fixture_root: &Path,
) -> bool {
    case.get("execution")
        .and_then(Value::as_object)
        .and_then(|execution| execution.get("expected"))
        .is_some_and(|expected| {
            expected_value_has_immutable_hashes(expected, fixture_root, case_dir)
        })
}

fn expected_value_has_immutable_hashes(
    value: &Value,
    fixture_root: &Path,
    case_dir: &Path,
) -> bool {
    match value {
        Value::Object(object) => {
            let Some(path) = object.get("path").and_then(Value::as_str) else {
                return false;
            };
            let Some(hash) = object.get("sha256").and_then(Value::as_str) else {
                return false;
            };
            is_safe_relative_path(path)
                && is_sha256(hash)
                && safe_fixture_path(fixture_root, case_dir, path)
                    .is_some_and(|path| file_matches_sha256(&path, hash))
        }
        Value::Array(values) => {
            !values.is_empty()
                && values
                    .iter()
                    .all(|value| expected_value_has_immutable_hashes(value, fixture_root, case_dir))
        }
        Value::String(_) | Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

fn file_matches_sha256(path: &Path, expected: &str) -> bool {
    let Ok(bytes) = read_bounded_file(path, MAX_FIXTURE_FILE_BYTES) else {
        return false;
    };
    let digest = Sha256::digest(bytes);
    digest.iter().enumerate().all(|(position, byte)| {
        let offset = position * 2;
        let Some(pair) = expected.as_bytes().get(offset..offset + 2) else {
            return false;
        };
        let [high, low] = pair else {
            return false;
        };
        fn hex(value: u8) -> Option<u8> {
            match value {
                b'0'..=b'9' => Some(value - b'0'),
                b'a'..=b'f' => Some(value - b'a' + 10),
                _ => None,
            }
        }
        matches!((hex(*high), hex(*low)), (Some(high), Some(low)) if *byte == (high << 4) | low)
    })
}

fn read_json(root: &Path, path: &Path, code: &str, diagnostics: &mut Diagnostics) -> Option<Value> {
    let display = display_path(root, path);
    let bytes = match read_bounded_file(path, MAX_FIXTURE_FILE_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => {
            push_fixture_read_diagnostic(diagnostics, &display, "JSON file", error, code);
            return None;
        }
    };
    let text = match String::from_utf8(bytes) {
        Ok(text) => text,
        Err(error) => {
            diagnostics.push(Diagnostic::new(
                code,
                display,
                format!("cannot read JSON file: input is not valid UTF-8: {error}"),
            ));
            return None;
        }
    };
    match serde_json::from_str::<Value>(&text) {
        Ok(value) => {
            let mut nodes = 0;
            let within_bounds = validate_json_limits(&value, &display, 0, &mut nodes, diagnostics);
            validate_string_list_members(&value, &display, diagnostics);
            validate_sensitive_json_values(&value, &display, None, diagnostics);
            within_bounds.then_some(value)
        }
        Err(error) => {
            diagnostics.push(Diagnostic::new(
                code,
                display,
                format!(
                    "invalid JSON at line {}, column {}: {error}",
                    error.line(),
                    error.column()
                ),
            ));
            None
        }
    }
}

fn validate_json_limits(
    value: &Value,
    path: &str,
    depth: usize,
    nodes: &mut usize,
    diagnostics: &mut Diagnostics,
) -> bool {
    if *nodes >= MAX_JSON_NODES {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-BOUNDS",
            path,
            format!("JSON node count exceeds {MAX_JSON_NODES}"),
        ));
        return false;
    }
    if depth > MAX_JSON_DEPTH {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-BOUNDS",
            path,
            format!("JSON nesting exceeds {MAX_JSON_DEPTH} levels"),
        ));
        return false;
    }
    *nodes += 1;
    let mut valid = true;
    match value {
        Value::Object(object) => {
            for (field, value) in object {
                valid &= validate_json_limits(
                    value,
                    &format!("{path}.{field}"),
                    depth + 1,
                    nodes,
                    diagnostics,
                );
            }
        }
        Value::Array(values) => {
            for (position, value) in values.iter().enumerate() {
                valid &= validate_json_limits(
                    value,
                    &format!("{path}[{position}]"),
                    depth + 1,
                    nodes,
                    diagnostics,
                );
            }
        }
        _ => {}
    }
    valid
}

fn validate_string_list_members(value: &Value, path: &str, diagnostics: &mut Diagnostics) {
    match value {
        Value::Object(object) => {
            for (field, value) in object {
                let field_path = format!("{path}.{field}");
                if value.is_array()
                    && string_list_field(field)
                    && let Some(values) = value.as_array()
                {
                    for (position, member) in values.iter().enumerate() {
                        if member.as_str().is_none() {
                            diagnostics.push(Diagnostic::new(
                                "FIXTURE-SCHEMA",
                                format!("{field_path}[{position}]"),
                                "list members must be strings",
                            ));
                        }
                    }
                }
                validate_string_list_members(value, &field_path, diagnostics);
            }
        }
        Value::Array(values) => {
            for (position, value) in values.iter().enumerate() {
                validate_string_list_members(value, &format!("{path}[{position}]"), diagnostics);
            }
        }
        _ => {}
    }
}

fn string_list_field(field: &str) -> bool {
    let field = field.to_ascii_lowercase();
    field == "required"
        || field == "ignored_fields"
        || field == "environment_allowlist"
        || field == "compatibility_ids"
        || field.ends_with("_ids")
        || field.ends_with("_refs")
        || field.ends_with("_paths")
        || field.ends_with("_allowlist")
        || field == "required_fields"
}

fn validate_sensitive_json_values(
    value: &Value,
    path: &str,
    key_hint: Option<&str>,
    diagnostics: &mut Diagnostics,
) {
    match value {
        Value::Object(object) => {
            for (field, value) in object {
                validate_sensitive_json_values(
                    value,
                    &format!("{path}.{field}"),
                    Some(field),
                    diagnostics,
                );
            }
        }
        Value::Array(values) => {
            for (position, value) in values.iter().enumerate() {
                validate_sensitive_json_values(
                    value,
                    &format!("{path}[{position}]"),
                    key_hint,
                    diagnostics,
                );
            }
        }
        Value::String(value) => validate_sensitive_string(value, path, key_hint, diagnostics),
        _ => {}
    }
}

fn validate_sensitive_string(
    value: &str,
    path: &str,
    key_hint: Option<&str>,
    diagnostics: &mut Diagnostics,
) {
    let lower = value.to_ascii_lowercase();
    let hint = key_hint.unwrap_or_default().to_ascii_lowercase();
    let path_hint = hint == "path"
        || hint.ends_with("_path")
        || hint.contains("file")
        || hint.contains("directory")
        || hint == "cwd"
        || hint.contains("working");
    let machine_absolute = path_hint
        && ((value.starts_with("/home/")
            || value.starts_with("/Users/")
            || value.starts_with("/tmp/")
            || value.starts_with("/var/")
            || value.starts_with("/opt/")
            || value.starts_with("/root/")
            || value.starts_with("/etc/")
            || value.starts_with("/mnt/")
            || value.starts_with("/srv/")
            || value.starts_with("/run/")
            || value.starts_with("/private/")
            || value.starts_with("/usr/")
            || value.starts_with("/bin/")
            || value.starts_with("/sbin/")
            || value.starts_with("/lib/")
            || value.starts_with("/workspace/")
            || value.starts_with("/storage/"))
            || value.len() >= 3
                && value.as_bytes()[1] == b':'
                && matches!(value.as_bytes()[2], b'\\' | b'/')
            || value.starts_with("\\\\"));
    if machine_absolute {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SAFETY",
            path,
            "machine-specific absolute paths are not allowed in fixture declarations",
        ));
    }
    let secret_hint = matches!(
        hint.as_str(),
        "password"
            | "password_value"
            | "secret"
            | "secret_value"
            | "credentials"
            | "credential_value"
            | "private_key"
            | "private-key"
            | "api_key"
            | "access_key"
            | "authorization"
            | "cookie"
            | "bearer"
            | "token_value"
    );
    let placeholder = value.trim().is_empty()
        || matches!(
            lower.as_str(),
            "none"
                | "null"
                | "false"
                | "not-used"
                | "not_configured"
                | "not-configured"
                | "redacted"
                | "placeholder"
                | "no credentials"
                | "no secrets"
        )
        || lower.contains("not used")
        || lower.contains("not configured")
        || lower.contains("redacted")
        || lower.starts_with("none;")
        || lower.contains("placeholders only");
    let typed_reference = is_typed_secret_reference(value);
    let looks_secret = lower.contains("-----begin ") && lower.contains("private key")
        || lower.starts_with("bearer ")
        || lower.contains("password=")
        || lower.contains("token=")
        || lower.contains("api_key=")
        || (value.starts_with("AKIA") && value.len() >= 20);
    if (secret_hint || looks_secret) && !placeholder && !typed_reference {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SAFETY",
            path,
            "secrets, credentials, and private key material are not allowed in fixtures",
        ));
    }
}

fn is_typed_secret_reference(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.starts_with("secret-ref:") || trimmed.starts_with("secret://") {
        let reference = trimmed
            .split_once(':')
            .map(|(_, reference)| reference)
            .unwrap_or_default();
        return !reference.is_empty()
            && reference
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || "._/-".contains(character));
    }
    let Some(start) = trimmed.find('<') else {
        return false;
    };
    let Some(end) = trimmed[start + 1..].find('>') else {
        return false;
    };
    let end = start + 1 + end;
    if end <= start + 1
        || trimmed[end + 1..].chars().any(|character| {
            !(character.is_ascii_whitespace()
                || matches!(character, ',' | ';' | ')' | ']' | '}' | '.'))
        })
    {
        return false;
    }
    trimmed[start + 1..end]
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || "._:-".contains(character))
}

fn required_object<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    parent_path: &str,
    diagnostics: &mut Diagnostics,
) -> Option<&'a Map<String, Value>> {
    match object.get(field).and_then(Value::as_object) {
        Some(value) => Some(value),
        None => {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{parent_path}.{field}"),
                "required object is missing or has the wrong type",
            ));
            None
        }
    }
}

fn optional_object<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    parent_path: &str,
    diagnostics: &mut Diagnostics,
) -> Option<&'a Map<String, Value>> {
    match object.get(field) {
        Some(value) if value.is_null() => None,
        Some(value) => match value.as_object() {
            Some(value) => Some(value),
            None => {
                diagnostics.push(Diagnostic::new(
                    "FIXTURE-SCHEMA",
                    format!("{parent_path}.{field}"),
                    "optional object has the wrong type",
                ));
                None
            }
        },
        None => None,
    }
}

fn required_array<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    parent_path: &str,
    diagnostics: &mut Diagnostics,
) -> Option<&'a Vec<Value>> {
    match object.get(field).and_then(Value::as_array) {
        Some(value) => Some(value),
        None => {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{parent_path}.{field}"),
                "required array is missing or has the wrong type",
            ));
            None
        }
    }
}

fn optional_array<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    parent_path: &str,
    diagnostics: &mut Diagnostics,
) -> Option<&'a Vec<Value>> {
    match object.get(field) {
        Some(value) if value.is_null() => None,
        Some(value) => match value.as_array() {
            Some(value) => Some(value),
            None => {
                diagnostics.push(Diagnostic::new(
                    "FIXTURE-SCHEMA",
                    format!("{parent_path}.{field}"),
                    "optional array has the wrong type",
                ));
                None
            }
        },
        None => None,
    }
}

fn optional_array_or_object<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    parent_path: &str,
    diagnostics: &mut Diagnostics,
) -> Option<&'a Value> {
    match object.get(field) {
        Some(value) if value.is_null() || value.is_array() || value.is_object() => Some(value),
        Some(_) => {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{parent_path}.{field}"),
                "optional field must be an array, object, or explicit null",
            ));
            None
        }
        None => None,
    }
}

fn required_string(
    object: &Map<String, Value>,
    field: &str,
    parent_path: &str,
    code: &str,
    diagnostics: &mut Diagnostics,
) -> Option<String> {
    match object.get(field).and_then(Value::as_str) {
        Some(value) => Some(value.to_owned()),
        None => {
            diagnostics.push(Diagnostic::new(
                code,
                format!("{parent_path}.{field}"),
                "required string is missing or has the wrong type",
            ));
            None
        }
    }
}

fn optional_string(
    object: &Map<String, Value>,
    field: &str,
    parent_path: &str,
    diagnostics: &mut Diagnostics,
) -> Option<String> {
    match object.get(field) {
        Some(value) if value.is_null() => None,
        Some(value) => match value.as_str() {
            Some(value) => Some(value.to_owned()),
            None => {
                diagnostics.push(Diagnostic::new(
                    "FIXTURE-SCHEMA",
                    format!("{parent_path}.{field}"),
                    "optional string has the wrong type",
                ));
                None
            }
        },
        None => None,
    }
}

fn required_bool(
    object: &Map<String, Value>,
    field: &str,
    parent_path: &str,
    diagnostics: &mut Diagnostics,
) -> Option<bool> {
    match object.get(field).and_then(Value::as_bool) {
        Some(value) => Some(value),
        None => {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{parent_path}.{field}"),
                "required boolean is missing or has the wrong type",
            ));
            None
        }
    }
}

fn required_u64(
    object: &Map<String, Value>,
    field: &str,
    parent_path: &str,
    diagnostics: &mut Diagnostics,
) -> Option<u64> {
    match object.get(field).and_then(Value::as_u64) {
        Some(value) => Some(value),
        None => {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-SCHEMA",
                format!("{parent_path}.{field}"),
                "required non-negative integer is missing or has the wrong type",
            ));
            None
        }
    }
}

fn optional_u64(
    object: &Map<String, Value>,
    field: &str,
    parent_path: &str,
    diagnostics: &mut Diagnostics,
) -> Option<u64> {
    match object.get(field) {
        Some(value) if value.is_null() => None,
        Some(value) => match value.as_u64() {
            Some(value) => Some(value),
            None => {
                diagnostics.push(Diagnostic::new(
                    "FIXTURE-SCHEMA",
                    format!("{parent_path}.{field}"),
                    "optional integer has the wrong type",
                ));
                None
            }
        },
        None => None,
    }
}

/// Validate an optional SHA-256 declaration.  A placeholder is admissible
/// only for a non-observed case; it records a pending oracle artifact and can
/// never silently promote an expectation to evidence.
fn optional_hash(
    object: &Map<String, Value>,
    field: &str,
    parent_path: &str,
    placeholder_allowed: bool,
    diagnostics: &mut Diagnostics,
) -> Option<String> {
    let Some(raw_value) = object.get(field) else {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{parent_path}.{field}"),
            "required SHA-256 string is missing or has the wrong type",
        ));
        return None;
    };
    if raw_value.is_null() && placeholder_allowed {
        return None;
    }
    let Some(value) = raw_value.as_str() else {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{parent_path}.{field}"),
            "required SHA-256 string is missing or has the wrong type",
        ));
        return None;
    };
    if is_placeholder_hash(value) {
        if !placeholder_allowed {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-PROVENANCE",
                format!("{parent_path}.{field}"),
                "observed evidence cannot contain an unresolved digest",
            ));
        }
        return None;
    }
    if !is_sha256(value) {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{parent_path}.{field}"),
            "must be a 64-character lowercase hexadecimal SHA-256 digest",
        ));
        return None;
    }
    Some(value.to_owned())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        && value.bytes().all(|byte| !byte.is_ascii_uppercase())
}

fn is_placeholder_hash(value: &str) -> bool {
    matches!(value, "TO_BE_FILLED" | "TO_BE_UPDATED" | "PLACEHOLDER")
        || (value.len() == 64 && value.bytes().all(|byte| byte == b'0'))
        || (value.starts_with("__") && value.ends_with("__"))
}

fn validate_path_hash_refs(
    root: &Path,
    base: &Path,
    value: &Value,
    parent_path: &str,
    placeholder_allowed: bool,
    diagnostics: &mut Diagnostics,
) {
    match value {
        Value::Array(values) => {
            for (position, value) in values.iter().enumerate() {
                validate_path_hash_refs(
                    root,
                    base,
                    value,
                    &format!("{parent_path}[{position}]"),
                    placeholder_allowed,
                    diagnostics,
                );
            }
        }
        Value::Object(object) => {
            if object.contains_key("path") && object.contains_key("sha256") {
                let path = required_safe_path(root, base, object, "path", parent_path, diagnostics);
                if let Some(path) = path {
                    if !path.is_file() {
                        diagnostics.push(Diagnostic::new(
                            "FIXTURE-REFERENCE",
                            format!("{parent_path}.path"),
                            format!(
                                "referenced file {} does not exist",
                                display_path(root, &path)
                            ),
                        ));
                    }
                    if let Some(hash) = optional_hash(
                        object,
                        "sha256",
                        parent_path,
                        placeholder_allowed,
                        diagnostics,
                    ) {
                        check_sha256(
                            root,
                            &path,
                            &hash,
                            &format!("{parent_path}.sha256"),
                            diagnostics,
                        );
                    }
                }
            }
            for (field, nested) in object {
                if field == "sha256" || field == "path" {
                    continue;
                }
                validate_path_hash_refs(
                    root,
                    base,
                    nested,
                    &format!("{parent_path}.{field}"),
                    placeholder_allowed,
                    diagnostics,
                );
            }
        }
        _ => {}
    }
}

fn validate_keyed_path_hash_refs(
    root: &Path,
    base: &Path,
    value: &Value,
    parent_path: &str,
    placeholder_allowed: bool,
    diagnostics: &mut Diagnostics,
) {
    match value {
        Value::Array(values) => {
            for (position, value) in values.iter().enumerate() {
                validate_keyed_path_hash_refs(
                    root,
                    base,
                    value,
                    &format!("{parent_path}[{position}]"),
                    placeholder_allowed,
                    diagnostics,
                );
            }
        }
        Value::Object(object) => {
            for (key, nested) in object {
                let key_path = format!("{parent_path}.{key}");
                if let Some(hash) = nested.as_object().and_then(|nested| nested.get("sha256")) {
                    validate_declared_file_hash(
                        root,
                        base,
                        key,
                        hash,
                        &key_path,
                        placeholder_allowed,
                        diagnostics,
                    );
                }
                validate_keyed_path_hash_refs(
                    root,
                    base,
                    nested,
                    &key_path,
                    placeholder_allowed,
                    diagnostics,
                );
            }
        }
        _ => {}
    }
}

fn validate_named_path_hash_refs(
    root: &Path,
    base: &Path,
    value: &Value,
    parent_path: &str,
    placeholder_allowed: bool,
    diagnostics: &mut Diagnostics,
) {
    match value {
        Value::Array(values) => {
            for (position, value) in values.iter().enumerate() {
                validate_named_path_hash_refs(
                    root,
                    base,
                    value,
                    &format!("{parent_path}[{position}]"),
                    placeholder_allowed,
                    diagnostics,
                );
            }
        }
        Value::Object(object) => {
            for (field, value) in object {
                let field_path = format!("{parent_path}.{field}");
                if let Some(path_stem) = field.strip_suffix("_path")
                    && let Some(declared_path) = value.as_str()
                {
                    let hash_field = format!("{path_stem}_sha256");
                    let logical_reference = is_logical_path_reference(field, declared_path);
                    if logical_reference {
                        // Root names and static descriptor placeholders describe
                        // future policy, not a repository file.  They are not
                        // path/hash evidence; concrete `{path, sha256}` objects
                        // remain subject to validate_path_hash_refs below.
                    } else if let Some(hash) = object.get(&hash_field) {
                        validate_declared_file_hash(
                            root,
                            base,
                            declared_path,
                            hash,
                            &field_path,
                            placeholder_allowed,
                            diagnostics,
                        );
                    } else if path_stem == "artifact"
                        && let Some(hash) = object.get("sha256")
                    {
                        validate_declared_file_hash(
                            root,
                            base,
                            declared_path,
                            hash,
                            &field_path,
                            placeholder_allowed,
                            diagnostics,
                        );
                    } else if field == "server_path"
                        && parent_path.contains(".command.fixture_server")
                    {
                        // The case command points at a shared local server;
                        // its immutable digest is declared in provenance.inputs
                        // as server_source/server_sha256.
                    } else {
                        diagnostics.push(Diagnostic::new(
                            "FIXTURE-REFERENCE",
                            field_path.clone(),
                            format!("path declaration requires sibling {hash_field}"),
                        ));
                    }
                }
                validate_named_path_hash_refs(
                    root,
                    base,
                    value,
                    &field_path,
                    placeholder_allowed,
                    diagnostics,
                );
            }
        }
        _ => {}
    }
}

fn is_logical_path_reference(field: &str, declared_path: &str) -> bool {
    field == "root_path"
        || declared_path.starts_with('<')
        || declared_path.contains("#/")
        || declared_path.contains("<temporary-root>")
        || declared_path.contains("<case-root>")
}

fn is_descriptor_path(value: &str) -> bool {
    let Some(start) = value.find('<') else {
        return false;
    };
    let Some(end_offset) = value[start + 1..].find('>') else {
        return false;
    };
    let end = start + 1 + end_offset;
    if end <= start + 1 {
        return false;
    }
    value[start + 1..end]
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || "._:-".contains(character))
        && value[..start]
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._/-:".contains(character))
        && value[end + 1..]
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._/-:".contains(character))
}

fn encoded_content_len(value: &str, encoding: &str) -> Option<u64> {
    match encoding {
        "UTF-8" => Some(value.len() as u64),
        "UTF-16LE" | "UTF-16BE" => Some(value.encode_utf16().count() as u64 * 2),
        "US-ASCII" if value.is_ascii() => Some(value.len() as u64),
        "US-ASCII" => None,
        _ => None,
    }
}

fn validate_declared_file_hash(
    root: &Path,
    base: &Path,
    declared_path: &str,
    hash: &Value,
    diagnostic_path: &str,
    placeholder_allowed: bool,
    diagnostics: &mut Diagnostics,
) {
    let Some(mut path) = safe_fixture_path(root, base, declared_path) else {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-PATH",
            diagnostic_path,
            "declared path must remain within the allowed repository root",
        ));
        return;
    };
    if !path.is_file() {
        let repository_path = root.join(declared_path);
        if repository_path.is_file() {
            path = repository_path;
        }
    }
    if !path.is_file() {
        if placeholder_allowed && is_external_static_artifact_ref(diagnostic_path, declared_path) {
            return;
        }
        diagnostics.push(Diagnostic::new(
            "FIXTURE-REFERENCE",
            diagnostic_path,
            format!(
                "referenced file {} does not exist",
                display_path(root, &path)
            ),
        ));
    }
    let Some(hash) = hash.as_str() else {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{diagnostic_path}.sha256"),
            "file digest must be a string",
        ));
        return;
    };
    if is_placeholder_hash(hash) {
        if !placeholder_allowed {
            diagnostics.push(Diagnostic::new(
                "FIXTURE-PROVENANCE",
                format!("{diagnostic_path}.sha256"),
                "observed evidence cannot contain an unresolved digest",
            ));
        }
        return;
    }
    if !is_sha256(hash) {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-SCHEMA",
            format!("{diagnostic_path}.sha256"),
            "must be a lowercase SHA-256 digest",
        ));
        return;
    }
    check_sha256(
        root,
        &path,
        hash,
        &format!("{diagnostic_path}.sha256"),
        diagnostics,
    );
}

fn is_external_static_artifact_ref(diagnostic_path: &str, declared_path: &str) -> bool {
    let diagnostic_path = diagnostic_path.to_ascii_lowercase();
    let declared_path = declared_path.to_ascii_lowercase();
    (diagnostic_path.contains(".runtime.script_engines[")
        || diagnostic_path.contains(".runtime.classpath_artifacts["))
        && (declared_path.starts_with("lib/") || declared_path.ends_with(".jar"))
}

fn check_sha256(
    root: &Path,
    path: &Path,
    expected: &str,
    diagnostic_path: &str,
    diagnostics: &mut Diagnostics,
) {
    if path.strip_prefix(root).is_err() {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-PATH",
            diagnostic_path,
            "refusing to hash a path outside the repository root",
        ));
        return;
    }
    let bytes = match read_bounded_file(path, MAX_FIXTURE_FILE_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => {
            push_fixture_read_diagnostic(
                diagnostics,
                diagnostic_path,
                "file for SHA-256 verification",
                error,
                "FIXTURE-IO",
            );
            return;
        }
    };
    let digest = Sha256::digest(bytes);
    let actual = digest
        .iter()
        .fold(String::with_capacity(64), |mut output, byte| {
            use std::fmt::Write;
            let _ = write!(output, "{byte:02x}");
            output
        });
    if actual != expected.to_ascii_lowercase() {
        diagnostics.push(Diagnostic::new(
            "FIXTURE-HASH",
            diagnostic_path,
            format!(
                "SHA-256 mismatch for {}; expected {expected}, found {actual}",
                display_path(root, path)
            ),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ExecutionState, FixtureReadError, check_expectation_evidence, check_safe_path_value,
        check_sha256, execution_state, expectation_state, optional_hash, read_bounded_file,
        read_bounded_handle, read_json, validate_bound_object, validate_digest_value,
        validate_execution_status_value, validate_expectation, validate_fuzz_counts,
        validate_fuzz_targets, validate_http_trace, validate_input_hash_value,
        validate_json_schema_document, validate_mirror_case_ids, validate_nested_schema_ids,
        validate_sensitive_json_values,
    };
    use crate::diagnostics::Diagnostics;
    use crate::profile::ProfileIndex;
    use serde_json::{Map, Value, json};

    fn must_ok<T, E>(result: Result<T, E>, context: &str) -> Option<T> {
        assert!(result.is_ok(), "{context}");
        result.ok()
    }

    fn must_err<T, E>(result: Result<T, E>, context: &str) -> Option<E> {
        assert!(result.is_err(), "{context}");
        result.err()
    }

    #[test]
    fn unsafe_fixture_paths_are_diagnosed() {
        let mut diagnostics = Diagnostics::default();
        check_safe_path_value(
            std::path::Path::new("."),
            std::path::Path::new("."),
            "../secret.key",
            "case.plan.path",
            &mut diagnostics,
        );
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(
            diagnostics.iter().next().map(|item| item.code.as_str()),
            Some("FIXTURE-PATH")
        );
    }

    #[test]
    fn unresolved_digest_is_allowed_only_for_non_observed_case() {
        let object = json!({"sha256": "TO_BE_FILLED"});
        let Some(object) = object.as_object() else {
            return;
        };
        let mut planned = Diagnostics::default();
        assert!(optional_hash(object, "sha256", "case.plan", true, &mut planned,).is_none());
        assert!(planned.is_empty());

        let mut observed = Diagnostics::default();
        assert!(optional_hash(object, "sha256", "case.plan", false, &mut observed,).is_none());
        assert!(
            observed
                .iter()
                .any(|diagnostic| { diagnostic.code == "FIXTURE-PROVENANCE" })
        );

        let object = json!({"sha256": "PLACEHOLDER"});
        let Some(object) = object.as_object() else {
            return;
        };
        let mut planned = Diagnostics::default();
        assert!(optional_hash(object, "sha256", "case.plan", true, &mut planned).is_none());
        assert!(planned.is_empty());
    }

    #[test]
    fn structured_execution_status_requires_a_kind() {
        let value = json!({
            "execution": {
                "status": {
                    "kind": "not-run",
                    "reason": "oracle unavailable",
                    "oracle_available": false
                }
            }
        });
        let Some(case) = value.as_object() else {
            return;
        };
        assert_eq!(execution_state(case), Some(ExecutionState::NotRun));
        let Some(execution) = case.get("execution").and_then(|value| value.as_object()) else {
            return;
        };
        let mut diagnostics = Diagnostics::default();
        validate_execution_status_value(execution, "case.execution", &mut diagnostics);
        assert!(diagnostics.is_empty());

        let invalid = json!({"status": {"reason": "missing kind"}});
        let Some(invalid) = invalid.as_object() else {
            return;
        };
        let mut diagnostics = Diagnostics::default();
        validate_execution_status_value(invalid, "case.execution", &mut diagnostics);
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "FIXTURE-SCHEMA")
        );
    }

    #[test]
    fn execution_status_does_not_infer_from_substrings() {
        let value = json!({
            "execution": {
                "status": "planned-but-observed-later"
            }
        });
        let Some(case) = value.as_object() else {
            return;
        };
        assert_eq!(execution_state(case), None);
        let Some(execution) = case.get("execution").and_then(Value::as_object) else {
            return;
        };
        let mut diagnostics = Diagnostics::default();
        validate_execution_status_value(execution, "case.execution", &mut diagnostics);
        assert!(diagnostics.iter().any(|item| item.code == "FIXTURE-SCHEMA"));
    }

    #[test]
    fn external_raw_observation_is_quarantined_not_observed() {
        let value = json!({
            "execution": {"status": "external-raw-observation"}
        });
        let Some(case) = value.as_object() else {
            return;
        };
        assert_eq!(execution_state(case), Some(ExecutionState::Quarantined));
        let expectation = json!({
            "evidence_status": "external-raw-observation",
            "comparator_ready": false,
            "rust_conformance_claim": false
        });
        let Some(expectation) = expectation.as_object() else {
            return;
        };
        assert_eq!(
            expectation_state(expectation),
            Some(ExecutionState::Quarantined)
        );
    }

    #[test]
    fn schema_document_requires_declared_identity() {
        let value = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {},
            "required": []
        });
        let profile = ProfileIndex {
            profile_id: "test".to_owned(),
            ..ProfileIndex::default()
        };
        let mut diagnostics = Diagnostics::default();
        validate_json_schema_document(
            std::path::Path::new("."),
            std::path::Path::new("fixture.schema.json"),
            &value,
            &profile,
            &mut diagnostics,
        );
        assert!(diagnostics.iter().any(|item| item.path.ends_with(".$id")));
    }

    #[test]
    fn schema_document_validates_nested_schema_shapes() {
        let value = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "https://example.invalid/schema",
            "type": "object",
            "properties": {
                "value": {"type": "not-a-json-schema-type"}
            },
            "required": ["value"]
        });
        let profile = ProfileIndex {
            profile_id: "test".to_owned(),
            ..ProfileIndex::default()
        };
        let mut diagnostics = Diagnostics::default();
        validate_json_schema_document(
            std::path::Path::new("."),
            std::path::Path::new("fixture.schema.json"),
            &value,
            &profile,
            &mut diagnostics,
        );
        assert!(diagnostics.iter().any(|item| item.path.ends_with(".type")));
    }

    #[test]
    fn sensitive_json_values_reject_machine_paths_and_credentials() {
        let value = json!({
            "working_directory": "/home/runner/private",
            "authorization": "Bearer abc",
            "argv": "-Djavax.net.ssl.keyStorePassword=<protected-secret>"
        });
        let mut diagnostics = Diagnostics::default();
        validate_sensitive_json_values(&value, "fixture.json", None, &mut diagnostics);
        assert_eq!(
            diagnostics
                .iter()
                .filter(|item| item.code == "FIXTURE-SAFETY")
                .count(),
            2
        );

        let placeholder = json!({
            "authorization": "secret-ref:oracle-password",
            "password": "<protected-secret>"
        });
        let mut placeholder_diagnostics = Diagnostics::default();
        validate_sensitive_json_values(
            &placeholder,
            "fixture.json",
            None,
            &mut placeholder_diagnostics,
        );
        assert!(placeholder_diagnostics.is_empty());
    }

    #[test]
    fn custom_schema_dispatch_rejects_unknown_schema() {
        let value = json!({
            "schema_id": "jmeter-rs.unknown-custom-schema",
            "schema_version": 1,
            "profile_id": "test"
        });
        let profile = ProfileIndex {
            profile_id: "test".to_owned(),
            ..ProfileIndex::default()
        };
        let mut diagnostics = Diagnostics::default();
        validate_expectation(
            std::path::Path::new("."),
            std::path::Path::new("expectation.json"),
            &value,
            &profile,
            None,
            None,
            None,
            &mut diagnostics,
        );
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "FIXTURE-SCHEMA")
        );
    }

    #[test]
    fn nested_schema_ids_are_closed_and_proxy_recorder_ready_is_typed() {
        let valid = json!({
            "readiness": {
                "schema_id": "jmeter-rs.proxy-recorder-ready",
                "schema_version": 1,
                "required": true,
                "source": "pinned recorder adapter readiness",
                "host": "127.0.0.1",
                "timeout_ms": 10000,
                "max_bytes": 16384,
                "fresh_run_root": true,
                "exact_child": true,
                "pid_authority": false
            }
        });
        let Some(valid) = valid.as_object() else {
            return;
        };
        let mut valid_diagnostics = Diagnostics::default();
        validate_nested_schema_ids(valid, "case", &mut valid_diagnostics);
        assert!(valid_diagnostics.is_empty());

        let invalid = json!({
            "schema_id": "jmeter-rs.unknown-nested",
            "schema_version": 1
        });
        let Some(invalid) = invalid.as_object() else {
            return;
        };
        let mut invalid_diagnostics = Diagnostics::default();
        validate_nested_schema_ids(invalid, "case", &mut invalid_diagnostics);
        assert!(invalid_diagnostics.iter().any(|item| {
            item.code == "FIXTURE-SCHEMA" && item.message.contains("nested schema ID")
        }));
    }

    #[test]
    fn file_artifact_contract_requires_typed_artifacts() {
        let value = json!({
            "schema_id": "jmeter-rs.file-artifact-contract",
            "schema_version": 1,
            "profile_id": "test",
            "contract_kind": "file-output",
            "artifact_status": "not-run",
            "root": "outputs",
            "artifacts": [{
                "path": "outputs/example.txt",
                "sha256": "not-a-digest"
            }],
            "normalization": {
                "ignored_fields": [],
                "reason": "static"
            }
        });
        let profile = ProfileIndex {
            profile_id: "test".to_owned(),
            ..ProfileIndex::default()
        };
        let mut diagnostics = Diagnostics::default();
        validate_expectation(
            std::path::Path::new("."),
            std::path::Path::new("expectation.json"),
            &value,
            &profile,
            None,
            None,
            None,
            &mut diagnostics,
        );
        assert!(diagnostics.iter().any(|item| item.code == "FIXTURE-SCHEMA"));
    }

    #[test]
    fn http_trace_rejects_ambiguous_or_unknown_variants() {
        let value = json!({
            "schema_id": "jmeter-rs.http-trace",
            "schema_version": 1,
            "profile_id": "test",
            "format": "http-trace",
            "counts": {},
            "trace_contract": {},
            "trace_schema": {},
            "events": [],
            "unexpected": true
        });
        let Some(object) = value.as_object() else {
            return;
        };
        let mut diagnostics = Diagnostics::default();
        validate_http_trace(
            object,
            "expected/contract.json",
            None,
            &ProfileIndex {
                profile_id: "test".to_owned(),
                ..ProfileIndex::default()
            },
            &mut diagnostics,
        );
        assert!(diagnostics.iter().any(|item| {
            item.code == "FIXTURE-SCHEMA"
                && item.path.ends_with(".schema_id")
                && item.message.contains("exactly one closed variant")
        }));
    }

    #[test]
    fn http_trace_does_not_fabricate_observed_evidence() {
        let value = json!({
            "schema_id": "jmeter-rs.http-trace",
            "schema_version": 1,
            "profile_id": "test",
            "format": "http-trace",
            "evidence_status": "observed",
            "oracle_available": false,
            "process_exit": null,
            "process_exit_asserted": false,
            "conformance_ids": [],
            "normalization_policy_refs": [],
            "trace_schema": {
                "schema_id": "jmeter-rs.http-trace",
                "schema_version": 1,
                "encoding": "jsonl",
                "event_type": "request-response",
                "request_fields": [],
                "response_fields": [],
                "required_event_fields": [],
                "digest_algorithm": "SHA-256",
                "body_digest_observable": true,
                "header_digest_observable": true,
                "duplicate_header_values": "ordered-list",
                "authorization_projection": "redacted",
                "limits": {}
            },
            "counts": {
                "planned": false,
                "sampler_count": 0,
                "request_count": 0,
                "response_count": 0,
                "redirect_hop_count": 0,
                "auth_challenge_count": 0,
                "cache_network_request_count": 0,
                "cache_hit_count": 0,
                "cache_revalidation_count": 0,
                "cache_eviction_count": 0,
                "cookie_set_count": 0,
                "cookie_sent_count": 0,
                "cookie_reset_count": 0,
                "cookie_persist_count": 0,
                "response_header_count_max": 0
            },
            "events": []
        });
        let Some(object) = value.as_object() else {
            return;
        };
        let mut diagnostics = Diagnostics::default();
        validate_http_trace(
            object,
            "expected/contract.json",
            None,
            &ProfileIndex {
                profile_id: "test".to_owned(),
                ..ProfileIndex::default()
            },
            &mut diagnostics,
        );
        assert!(diagnostics.iter().any(|item| {
            item.code == "FIXTURE-EVIDENCE" && item.message.contains("static http-trace contracts")
        }));
    }

    #[test]
    fn fuzz_meta_validation_rejects_duplicate_targets_and_overaccepted_counts() {
        let mut count_diagnostics = Diagnostics::default();
        let counts = json!({
            "executions": 1,
            "accepted_inputs": 1,
            "rejected_inputs": 1,
            "crashes": 0,
            "hangs": 0,
            "timeouts": 0,
            "sanitizer_findings": 0,
            "resource_limit_failures": 0
        });
        let Some(counts) = counts.as_object() else {
            return;
        };
        validate_fuzz_counts(
            counts,
            "outcome.counts",
            &Map::new(),
            &mut count_diagnostics,
        );
        assert!(count_diagnostics.iter().any(|item| {
            item.code == "FIXTURE-REFERENCE"
                && item.message.contains("accepted_inputs + rejected_inputs")
        }));

        let target = json!({
            "target": "jmx_xml",
            "source_path": "fuzz/fuzz_targets/jmx_xml.rs",
            "source_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "corpus_directory": "fuzz/corpus/jmx_xml",
            "bounds": {"max_input_bytes": 1},
            "invariant_ids": ["JMX-LIMIT-001"],
            "corpus_seed_count": 0,
            "corpus_bytes": 0
        });
        let values = vec![target.clone(), target];
        let mut target_diagnostics = Diagnostics::default();
        validate_fuzz_targets(&values, "targets", None, &mut target_diagnostics);
        assert!(target_diagnostics.iter().any(|item| {
            item.code == "FIXTURE-REFERENCE" && item.message.contains("duplicate fuzz target")
        }));
    }

    #[test]
    fn custom_mirror_vectors_reject_duplicate_ids() {
        let values = vec![json!({"id": "same"}), json!({"id": "same"})];
        let mut diagnostics = Diagnostics::default();
        validate_mirror_case_ids(Some(&values), "input.cases", &mut diagnostics);
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "FIXTURE-SCHEMA")
        );
    }

    #[test]
    fn observed_digest_marker_and_oversized_bound_are_rejected() {
        let mut digest_diagnostics = Diagnostics::default();
        validate_digest_value(
            &json!("PLACEHOLDER"),
            64,
            "expected.sha256",
            Some(ExecutionState::Observed),
            &mut digest_diagnostics,
        );
        assert!(
            digest_diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "FIXTURE-SCHEMA")
        );

        let mut bound_diagnostics = Diagnostics::default();
        validate_bound_object(
            &json!({"max_bytes": 1_073_741_825_u64}),
            "case.bounds",
            &mut bound_diagnostics,
        );
        assert!(
            bound_diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "FIXTURE-BOUNDS")
        );

        let mut nested_bound_diagnostics = Diagnostics::default();
        validate_bound_object(
            &json!({"nested": [1_u64, 1_073_741_825_u64]}),
            "case.bounds",
            &mut nested_bound_diagnostics,
        );
        assert!(
            nested_bound_diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "FIXTURE-BOUNDS")
        );
    }

    #[test]
    fn empty_allowed_hosts_requires_explicit_network_disable() {
        let mut disabled = Diagnostics::default();
        validate_bound_object(
            &json!({
                "network": {
                    "policy": "none",
                    "allowed_hosts": []
                }
            }),
            "case.bounds",
            &mut disabled,
        );
        assert!(disabled.is_empty());

        let mut enabled = Diagnostics::default();
        validate_bound_object(
            &json!({
                "network": {
                    "policy": "local-only",
                    "allowed_hosts": []
                }
            }),
            "case.bounds",
            &mut enabled,
        );
        assert!(enabled.iter().any(|diagnostic| {
            diagnostic.code == "FIXTURE-BOUNDS" && diagnostic.path.ends_with("allowed_hosts")
        }));
    }

    #[test]
    fn ambiguous_scalar_hash_requires_explicit_path() {
        let mut case_hashes = std::collections::BTreeMap::new();
        case_hashes.insert(
            "expected/first.json".to_owned(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        );
        case_hashes.insert(
            "expected/second.json".to_owned(),
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
        );
        let mut diagnostics = Diagnostics::default();
        validate_input_hash_value(
            std::path::Path::new("."),
            "inputs.expected_sha256",
            "expected_sha256",
            &json!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            std::path::Path::new("."),
            &case_hashes,
            false,
            &mut diagnostics,
        );
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "FIXTURE-REFERENCE" && diagnostic.message.contains("multiple paths")
        }));
    }

    #[test]
    fn static_projection_does_not_claim_observed_expectation_evidence() {
        let object = json!({
            "schema_id": "jmeter-rs.semantic-expectation",
            "schema_version": 1,
            "profile_id": "test",
            "case_id": "CASE-001",
            "evidence_status": "static-projection-pending-round-trip",
            "generated_from": {
                "artifact_sha512": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "raw_artifacts": "oracle-runs/ (ignored; local evidence only)"
            }
        });
        let Some(object) = object.as_object() else {
            return;
        };
        let profile = ProfileIndex {
            profile_id: "test".to_owned(),
            upstream: crate::profile::UpstreamPin {
                digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
                ..crate::profile::UpstreamPin::default()
            },
            ..ProfileIndex::default()
        };
        let mut diagnostics = Diagnostics::default();
        let state = expectation_state(object);
        assert_eq!(state, Some(ExecutionState::NotRun));
        check_expectation_evidence(
            std::path::Path::new("."),
            object,
            "jmeter-rs.semantic-expectation",
            "expected/semantic.json",
            &profile,
            Some("CASE-001"),
            Some(ExecutionState::Observed),
            state,
            &mut diagnostics,
        );
        assert!(diagnostics.is_empty());
    }

    #[test]
    fn temporary_case_with_traversal_is_rejected() {
        use std::fs;
        use std::sync::atomic::{AtomicUsize, Ordering};

        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "jmeter-rs-xtask-fixture-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let fixture_root = root.join("fixtures");
        let created = fs::create_dir_all(&fixture_root);
        assert!(created.is_ok(), "create fixture tree: {created:?}");
        if created.is_err() {
            return;
        }
        let written = fs::write(
            fixture_root.join("case.json"),
            r#"{
                "schema_id":"jmeter-rs.oracle-case", "schema_version":1,
                "case_id":"CASE-001", "profile_id":"test",
                "fixture_family_id":"FX-001", "conformance_ids":[],
                "normalization_policy_refs":[],
                "plan":{"path":"../secret.jmx","sha256":"0000000000000000000000000000000000000000000000000000000000000000"},
                "property_files":[], "command":{"mode":"nongui","network":"none","locale":"C","timezone":"UTC","default_charset":"UTF-8","random_seed":null,"argv_template":[]},
                "execution":{"status":"planned","process_exit":0,"expected":"expected.json","raw_artifacts":"ignored"}
            }"#,
        );
        assert!(written.is_ok(), "write invalid case: {written:?}");
        if written.is_err() {
            let _ = fs::remove_dir_all(root);
            return;
        }
        let profile = ProfileIndex {
            profile_id: "test".to_owned(),
            ..ProfileIndex::default()
        };
        let diagnostics = super::check(&root, &fixture_root, &profile);
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "FIXTURE-PATH")
        );
        let removed = fs::remove_dir_all(root);
        assert!(removed.is_ok(), "remove fixture tree: {removed:?}");
    }

    #[test]
    fn bounded_fixture_read_rejects_initial_overlimit() {
        use std::fs;
        use std::sync::atomic::{AtomicUsize, Ordering};

        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let directory = std::env::temp_dir().join(format!(
            "jmeter-rs-xtask-fixture-overlimit-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        assert!(fs::create_dir_all(&directory).is_ok());
        let path = directory.join("expected.json");
        assert!(fs::write(&path, b"012345").is_ok());

        let Some(error) = must_err(read_bounded_file(&path, 4), "overlimit fixture must fail")
        else {
            return;
        };
        assert!(matches!(error, FixtureReadError::TooLarge { limit: 4 }));
        assert!(fs::remove_dir_all(directory).is_ok());
    }

    #[test]
    fn bounded_fixture_read_detects_growth_after_open() {
        use std::fs::{self, File, OpenOptions};
        use std::io::Write;
        use std::sync::atomic::{AtomicUsize, Ordering};

        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let directory = std::env::temp_dir().join(format!(
            "jmeter-rs-xtask-fixture-growth-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        assert!(fs::create_dir_all(&directory).is_ok());
        let path = directory.join("expected.json");
        assert!(fs::write(&path, b"12").is_ok());
        let Some(file) = must_ok(File::open(&path), "open fixture handle") else {
            return;
        };
        let Some(metadata) = must_ok(file.metadata(), "stat fixture handle") else {
            return;
        };
        let Some(mut writer) = must_ok(
            OpenOptions::new().append(true).open(&path),
            "open fixture writer",
        ) else {
            return;
        };
        if must_ok(writer.write_all(b"3456"), "append fixture bytes").is_none() {
            return;
        }

        let Some(error) = must_err(
            read_bounded_handle(file, &path, &metadata, 4),
            "grown fixture must fail",
        ) else {
            return;
        };
        assert!(matches!(error, FixtureReadError::Grew { limit: 4 }));
        assert!(fs::remove_dir_all(directory).is_ok());
    }

    #[test]
    fn bounded_fixture_read_detects_truncation_after_open() {
        use std::fs::{self, File, OpenOptions};
        use std::sync::atomic::{AtomicUsize, Ordering};

        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let directory = std::env::temp_dir().join(format!(
            "jmeter-rs-xtask-fixture-truncate-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        assert!(fs::create_dir_all(&directory).is_ok());
        let path = directory.join("provenance.json");
        assert!(fs::write(&path, b"012345").is_ok());
        let Some(file) = must_ok(File::open(&path), "open fixture handle") else {
            return;
        };
        let Some(metadata) = must_ok(file.metadata(), "stat fixture handle") else {
            return;
        };
        let Some(truncator) = must_ok(
            OpenOptions::new().write(true).open(&path),
            "open fixture truncator",
        ) else {
            return;
        };
        if must_ok(truncator.set_len(2), "truncate fixture").is_none() {
            return;
        }

        let Some(error) = must_err(
            read_bounded_handle(file, &path, &metadata, 8),
            "truncated fixture must fail",
        ) else {
            return;
        };
        assert!(matches!(error, FixtureReadError::Truncated));
        assert!(fs::remove_dir_all(directory).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn bounded_fixture_read_detects_replacement_after_open() {
        use std::fs::{self, File};
        use std::sync::atomic::{AtomicUsize, Ordering};

        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let directory = std::env::temp_dir().join(format!(
            "jmeter-rs-xtask-fixture-replacement-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        assert!(fs::create_dir_all(&directory).is_ok());
        let path = directory.join("case.json");
        let replacement = directory.join("replacement.json");
        assert!(fs::write(&path, b"original").is_ok());
        let Some(file) = must_ok(File::open(&path), "open fixture handle") else {
            return;
        };
        let Some(metadata) = must_ok(file.metadata(), "stat fixture handle") else {
            return;
        };
        assert!(fs::write(&replacement, b"replacement").is_ok());
        assert!(fs::rename(&replacement, &path).is_ok());

        let Some(error) = must_err(
            read_bounded_handle(file, &path, &metadata, 64),
            "replaced fixture must fail",
        ) else {
            return;
        };
        assert!(matches!(error, FixtureReadError::Changed));
        assert!(fs::remove_dir_all(directory).is_ok());
    }

    #[test]
    fn bounded_fixture_read_rejects_nonregular_input() {
        use std::fs;
        use std::sync::atomic::{AtomicUsize, Ordering};

        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let directory = std::env::temp_dir().join(format!(
            "jmeter-rs-xtask-fixture-nonregular-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        assert!(fs::create_dir_all(&directory).is_ok());

        let Some(error) = must_err(
            read_bounded_file(&directory, 8),
            "directory fixture must fail",
        ) else {
            return;
        };
        assert!(matches!(
            error,
            FixtureReadError::NonRegular | FixtureReadError::Open(_)
        ));
        assert!(fs::remove_dir_all(directory).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn bounded_fixture_read_rejects_symlink_input() {
        use std::fs;
        use std::os::unix::fs::symlink;
        use std::sync::atomic::{AtomicUsize, Ordering};

        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let directory = std::env::temp_dir().join(format!(
            "jmeter-rs-xtask-fixture-symlink-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        assert!(fs::create_dir_all(&directory).is_ok());
        let target = directory.join("target.json");
        let link = directory.join("expected.json");
        assert!(fs::write(&target, b"{}").is_ok());
        assert!(symlink(&target, &link).is_ok());

        let Some(error) = must_err(read_bounded_file(&link, 8), "symlink fixture must fail") else {
            return;
        };
        assert!(matches!(error, FixtureReadError::Symlink));

        let target_directory = directory.join("target-directory");
        let linked_directory = directory.join("linked-directory");
        assert!(fs::create_dir(&target_directory).is_ok());
        let nested = target_directory.join("nested.json");
        assert!(fs::write(&nested, b"{}").is_ok());
        assert!(symlink(&target_directory, &linked_directory).is_ok());
        let linked_nested = linked_directory.join("nested.json");
        let Some(error) = must_err(
            read_bounded_file(&linked_nested, 8),
            "symlink component fixture must fail",
        ) else {
            return;
        };
        assert!(matches!(error, FixtureReadError::Symlink));
        assert!(fs::remove_dir_all(directory).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn manifest_and_hash_readers_preserve_path_diagnostics() {
        use std::fs;
        use std::os::unix::fs::symlink;
        use std::sync::atomic::{AtomicUsize, Ordering};

        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "jmeter-rs-xtask-fixture-reader-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        assert!(fs::create_dir_all(&root).is_ok());
        let target = root.join("target.json");
        let link = root.join("case.json");
        assert!(fs::write(&target, b"{}").is_ok());
        assert!(symlink(&target, &link).is_ok());

        let mut json_diagnostics = Diagnostics::default();
        assert!(read_json(&root, &link, "FIXTURE-JSON", &mut json_diagnostics).is_none());
        assert!(
            json_diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "FIXTURE-PATH")
        );

        let mut hash_diagnostics = Diagnostics::default();
        check_sha256(
            &root,
            &link,
            "0000000000000000000000000000000000000000000000000000000000000000",
            "case.plan.sha256",
            &mut hash_diagnostics,
        );
        assert!(
            hash_diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "FIXTURE-PATH")
        );
        assert!(fs::remove_dir_all(root).is_ok());
    }
}
