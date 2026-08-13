// SPDX-License-Identifier: Apache-2.0
//! Deterministic policy checks for the TEST-003 and TEST-005 boundaries.
//!
//! This module intentionally validates the checked-in declarations directly.
//! It does not invoke the Python performance planner, Cargo, a fuzzing
//! harness, or any fixture service.  A policy check is therefore suitable for
//! ordinary offline correctness tests and cannot accidentally turn a plan into
//! an execution.

use crate::diagnostics::{Diagnostic, Diagnostics};
use crate::profile::{ProfileIndex, display_path, is_feature_id};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs;
use std::path::{Component, Path, PathBuf};

const MAX_DECLARATION_BYTES: u64 = 8 * 1024 * 1024;
const MAX_JSON_DEPTH: usize = 64;
const MAX_JSON_NODES: usize = 200_000;
const MAX_CORPUS_BYTES: u64 = 256 * 1024;
const MAX_DIRECTORY_DEPTH: usize = 32;
const CONFIG_SCHEMA_ID: &str = "jmeter-rs.perf-config";
const CONFIG_SCHEMA_VERSION: u64 = 3;
const RESULT_SCHEMA_ID: &str = "jmeter-rs.perf-result";
const RESULT_SCHEMA_VERSION: u64 = 3;
const FUZZ_SOURCE_COVERAGE_MARKER: &str = "//! Source-side coverage:";
const FUZZ_IO_POLICY_MARKER: &str = "//! I/O policy: none";
const ROOT_GENERATED_ARTIFACT_EXTENSIONS: [&str; 10] = [
    "rlib", "rmeta", "o", "obj", "a", "so", "dylib", "dll", "d", "pdb",
];
const STANDALONE_MANIFEST_PATH: &str = "apps/jmeter-rs/Cargo.toml";
const STANDALONE_SOURCE_PATH: &str = "apps/jmeter-rs/src";
const STANDALONE_FORBIDDEN_RUNTIME_PACKAGES: [&str; 3] = [
    "jmeter-rs-java-bridge",
    "jmeter-rs-plugin-host",
    "jmeter-rs-process-supervision",
];
const STANDALONE_FORBIDDEN_EMBEDDED_EXTENSIONS: [&str; 11] = [
    "jar", "class", "java", "jmod", "war", "ear", "zip", "exe", "dll", "so", "dylib",
];
const STANDALONE_NOTICE_FILES: [&str; 2] = ["LICENSE", "NOTICE"];
const FUZZ_FORBIDDEN_IO_MARKERS: [&str; 16] = [
    "std::fs::",
    "use std::fs",
    "std::net::",
    "use std::net",
    "std::process::",
    "use std::process",
    "std::env::",
    "use std::env",
    "Command::",
    "File::",
    "OpenOptions::",
    "TcpStream",
    "TcpListener",
    "UdpSocket",
    "read_to_string(",
    "read_to_end(",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FuzzTargetSpec {
    name: &'static str,
    source_path: &'static str,
    input_bound_bytes: u64,
    corpus_directory: Option<&'static str>,
}

const FUZZ_TARGETS: [FuzzTargetSpec; 13] = [
    FuzzTargetSpec {
        name: "jmx_xml",
        source_path: "fuzz_targets/jmx_xml.rs",
        input_bound_bytes: 256 * 1024,
        corpus_directory: Some("corpus/jmx_xml"),
    },
    FuzzTargetSpec {
        name: "jtl_csv",
        source_path: "fuzz_targets/jtl_csv.rs",
        input_bound_bytes: 256 * 1024,
        corpus_directory: Some("corpus/jtl_csv"),
    },
    FuzzTargetSpec {
        name: "jtl_xml",
        source_path: "fuzz_targets/jtl_xml.rs",
        input_bound_bytes: 256 * 1024,
        corpus_directory: Some("corpus/jtl_xml"),
    },
    FuzzTargetSpec {
        name: "jtl_model",
        source_path: "fuzz_targets/jtl_model.rs",
        input_bound_bytes: 256 * 1024,
        corpus_directory: None,
    },
    FuzzTargetSpec {
        name: "expr",
        source_path: "fuzz_targets/expr.rs",
        input_bound_bytes: 64 * 1024,
        corpus_directory: Some("corpus/expr"),
    },
    FuzzTargetSpec {
        name: "bridge",
        source_path: "fuzz_targets/bridge.rs",
        input_bound_bytes: 256 * 1024,
        corpus_directory: Some("corpus/bridge"),
    },
    FuzzTargetSpec {
        name: "bridge_rmi",
        source_path: "fuzz_targets/bridge_rmi.rs",
        input_bound_bytes: 256 * 1024,
        corpus_directory: Some("corpus/bridge_rmi"),
    },
    FuzzTargetSpec {
        name: "property_config",
        source_path: "fuzz_targets/property_config.rs",
        input_bound_bytes: 64 * 1024,
        corpus_directory: Some("corpus/property_config"),
    },
    FuzzTargetSpec {
        name: "save_config",
        source_path: "fuzz_targets/save_config.rs",
        input_bound_bytes: 64 * 1024,
        corpus_directory: Some("corpus/save_config"),
    },
    FuzzTargetSpec {
        name: "http_policy",
        source_path: "fuzz_targets/http_policy.rs",
        input_bound_bytes: 64 * 1024,
        corpus_directory: None,
    },
    FuzzTargetSpec {
        name: "plugin_json",
        source_path: "fuzz_targets/plugin_json.rs",
        input_bound_bytes: 64 * 1024,
        corpus_directory: None,
    },
    FuzzTargetSpec {
        name: "remote",
        source_path: "fuzz_targets/remote.rs",
        input_bound_bytes: 64 * 1024,
        corpus_directory: None,
    },
    FuzzTargetSpec {
        name: "runtime",
        source_path: "fuzz_targets/runtime.rs",
        input_bound_bytes: 64 * 1024,
        corpus_directory: None,
    },
];
const CONFIG_FILES: [&str; 5] = [
    "micro.json",
    "macro.json",
    "soak-1h.json",
    "soak-8h.json",
    "soak-24h.json",
];

/// Validate deterministic fuzz-corpus provenance and the plan-only
/// performance declarations.
pub(crate) fn check(root: &Path, fixture_root: &Path, profile: &ProfileIndex) -> Diagnostics {
    let mut diagnostics = Diagnostics::default();
    check_root_generated_artifacts(root, &mut diagnostics);
    check_standalone_release_policy(root, &mut diagnostics);
    check_fuzz(root, profile, &mut diagnostics);
    check_perf(root, fixture_root, profile, &mut diagnostics);
    diagnostics.sort_deterministically();
    diagnostics
}

/// Reject compiler/linker output in the repository root.
///
/// `.gitignore` keeps accidental root artifacts out of normal staging, but an
/// ignore rule is not a repository invariant: callers can force-add ignored
/// paths and a clean checkout can still be polluted by a misconfigured build.
/// This check therefore inspects only immediate root entries and reports the
/// generated artifact itself, without following it or reading its contents.
fn check_root_generated_artifacts(root: &Path, diagnostics: &mut Diagnostics) {
    let mut entries = match fs::read_dir(root) {
        Ok(entries) => {
            let mut collected: Vec<(PathBuf, fs::FileType)> = Vec::new();
            for result in entries {
                let entry = match result {
                    Ok(entry) => entry,
                    Err(error) => {
                        diagnostics.push(Diagnostic::new(
                            "POLICY-ROOT-ARTIFACT",
                            ".",
                            format!(
                                "cannot inspect a repository-root entry for generated artifacts: {error}"
                            ),
                        ));
                        continue;
                    }
                };
                let path = entry.path();
                let file_type = match entry.file_type() {
                    Ok(file_type) => file_type,
                    Err(error) => {
                        diagnostics.push(Diagnostic::new(
                            "POLICY-ROOT-ARTIFACT",
                            display_path(root, &path),
                            format!(
                                "cannot inspect repository-root entry for generated artifacts: {error}"
                            ),
                        ));
                        continue;
                    }
                };
                collected.push((path, file_type));
            }
            collected
        }
        Err(error) => {
            diagnostics.push(Diagnostic::new(
                "POLICY-ROOT-ARTIFACT",
                ".",
                format!("cannot inspect repository root for generated artifacts: {error}"),
            ));
            return;
        }
    };
    entries.sort_by(|(left, _), (right, _)| left.cmp(right));

    for (path, file_type) in entries {
        if !is_root_generated_artifact(&path) {
            continue;
        }
        if file_type.is_file() || file_type.is_symlink() {
            diagnostics.push(Diagnostic::new(
                "POLICY-ROOT-ARTIFACT",
                display_path(root, &path),
                "generated build artifacts must remain under target/ and must not be present at repository root",
            ));
        }
    }
}

fn is_root_generated_artifact(path: &Path) -> bool {
    path.extension()
        .and_then(OsStr::to_str)
        .is_some_and(|extension| {
            ROOT_GENERATED_ARTIFACT_EXTENSIONS
                .iter()
                .any(|expected| extension.eq_ignore_ascii_case(expected))
        })
}

fn check_fuzz(root: &Path, profile: &ProfileIndex, diagnostics: &mut Diagnostics) {
    let fuzz_root = root.join("fuzz");
    let manifest_path = fuzz_root.join("Cargo.toml");
    let manifest_display = display_path(root, &manifest_path);
    let Some(manifest_text) = read_text(root, &manifest_path, diagnostics) else {
        return;
    };
    let manifest = match manifest_text.parse::<toml::Table>() {
        Ok(value) => toml::Value::Table(value),
        Err(error) => {
            diagnostics.push(Diagnostic::new(
                "POLICY-FUZZ-MANIFEST",
                manifest_display,
                format!("invalid TOML: {error}"),
            ));
            return;
        }
    };
    let Some(manifest_table) = manifest.as_table() else {
        diagnostics.push(Diagnostic::new(
            "POLICY-FUZZ-MANIFEST",
            display_path(root, &manifest_path),
            "fuzz manifest must be a TOML table",
        ));
        return;
    };
    if manifest_table
        .get("workspace")
        .and_then(toml::Value::as_table)
        .is_none()
    {
        diagnostics.push(Diagnostic::new(
            "POLICY-FUZZ-MANIFEST",
            format!("{manifest_display}.workspace"),
            "fuzz package must remain a standalone Cargo workspace",
        ));
    }
    if let Some(package) = manifest_table
        .get("package")
        .and_then(toml::Value::as_table)
        && package.get("publish").and_then(toml::Value::as_bool) != Some(false)
    {
        diagnostics.push(Diagnostic::new(
            "POLICY-FUZZ-MANIFEST",
            format!("{manifest_display}.package.publish"),
            "fuzz package must not be publishable",
        ));
    }
    let Some(binaries) = manifest_table.get("bin").and_then(toml::Value::as_array) else {
        diagnostics.push(Diagnostic::new(
            "POLICY-FUZZ-MANIFEST",
            format!("{manifest_display}.[[bin]]"),
            "fuzz manifest must declare explicit fuzz targets",
        ));
        check_fuzz_corpus(root, &fuzz_root, profile, diagnostics);
        return;
    };
    let mut seen_targets = BTreeSet::new();
    for binary in binaries {
        let Some(binary) = binary.as_table() else {
            diagnostics.push(Diagnostic::new(
                "POLICY-FUZZ-MANIFEST",
                format!("{manifest_display}.[[bin]]"),
                "fuzz target declaration must be a table",
            ));
            continue;
        };
        let Some(name) = binary.get("name").and_then(toml::Value::as_str) else {
            diagnostics.push(Diagnostic::new(
                "POLICY-FUZZ-MANIFEST",
                format!("{manifest_display}.[[bin]].name"),
                "fuzz target name is required",
            ));
            continue;
        };
        let target_spec = FUZZ_TARGETS.iter().find(|spec| spec.name == name);
        if target_spec.is_none() {
            diagnostics.push(Diagnostic::new(
                "POLICY-FUZZ-MANIFEST",
                format!("{manifest_display}.[[bin]].name"),
                format!("unsupported fuzz target {name:?}"),
            ));
        }
        if !seen_targets.insert(name.to_owned()) {
            diagnostics.push(Diagnostic::new(
                "POLICY-FUZZ-MANIFEST",
                format!("{manifest_display}.[[bin]].name"),
                format!("duplicate fuzz target {name:?}"),
            ));
        }
        let Some(target_path) = binary.get("path").and_then(toml::Value::as_str) else {
            diagnostics.push(Diagnostic::new(
                "POLICY-FUZZ-MANIFEST",
                format!("{manifest_display}.[[bin]].path"),
                "fuzz target path is required",
            ));
            continue;
        };
        let target_path_display = format!("{manifest_display}.[[bin]].path");
        if !safe_relative_path(target_path) {
            diagnostics.push(Diagnostic::new(
                "POLICY-FUZZ-PATH",
                target_path_display,
                "fuzz target path must be a safe relative path",
            ));
        } else if !fuzz_root.join(target_path).is_file() {
            diagnostics.push(Diagnostic::new(
                "POLICY-FUZZ-REFERENCE",
                target_path_display,
                "declared fuzz target does not exist",
            ));
        }
        if let Some(spec) = target_spec
            && target_path != spec.source_path
        {
            diagnostics.push(Diagnostic::new(
                "POLICY-FUZZ-REFERENCE",
                format!("{manifest_display}.[[bin]].path"),
                format!("must match the static target registry for {name:?}"),
            ));
        }
        for field in ["test", "doc", "bench"] {
            if binary.get(field).and_then(toml::Value::as_bool) != Some(false) {
                diagnostics.push(Diagnostic::new(
                    "POLICY-FUZZ-MANIFEST",
                    format!("{manifest_display}.[[bin]].{field}"),
                    "fuzz targets must disable ordinary test, doc, and bench discovery",
                ));
            }
        }
    }
    for expected in FUZZ_TARGETS {
        if !seen_targets.contains(expected.name) {
            diagnostics.push(Diagnostic::new(
                "POLICY-FUZZ-MANIFEST",
                manifest_display.clone(),
                format!("required fuzz target {:?} is missing", expected.name),
            ));
        }
    }
    for target in FUZZ_TARGETS {
        check_fuzz_target_source(root, &fuzz_root, target, diagnostics);
    }
    check_fuzz_source_inventory(root, &fuzz_root, diagnostics);
    check_fuzz_readme(root, &fuzz_root, diagnostics);
    if profile.feature_ids.contains("TEST-003") && !profile.fixture_ids.is_empty() {
        check_fuzz_corpus(root, &fuzz_root, profile, diagnostics);
    }
}

fn check_fuzz_source_inventory(root: &Path, fuzz_root: &Path, diagnostics: &mut Diagnostics) {
    let directory = fuzz_root.join("fuzz_targets");
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) => {
            diagnostics.push(Diagnostic::new(
                "POLICY-FUZZ-IO",
                display_path(root, &directory),
                format!("cannot enumerate fuzz target sources: {error}"),
            ));
            return;
        }
    };
    for entry in entries {
        let Ok(entry) = entry else {
            diagnostics.push(Diagnostic::new(
                "POLICY-FUZZ-IO",
                display_path(root, &directory),
                "cannot inspect a fuzz target source entry",
            ));
            continue;
        };
        let path = entry.path();
        let is_rust_source = path.extension().and_then(OsStr::to_str) == Some("rs");
        if !is_rust_source {
            continue;
        }
        let Some(name) = path.file_stem().and_then(OsStr::to_str) else {
            continue;
        };
        if !FUZZ_TARGETS.iter().any(|target| target.name == name) {
            diagnostics.push(Diagnostic::new(
                "POLICY-FUZZ-MANIFEST",
                display_path(root, &path),
                format!("unregistered fuzz target source {name:?}"),
            ));
        }
    }
}

fn check_fuzz_readme(root: &Path, fuzz_root: &Path, diagnostics: &mut Diagnostics) {
    let path = fuzz_root.join("README.md");
    let Some(readme) = read_text(root, &path, diagnostics) else {
        return;
    };
    let display = display_path(root, &path);
    for target in FUZZ_TARGETS {
        let row_marker = format!("| `{}` |", target.name);
        if !readme.contains(&row_marker) {
            diagnostics.push(Diagnostic::new(
                "POLICY-FUZZ-README",
                display.clone(),
                format!(
                    "target {:?} is missing from the fuzz target table",
                    target.name
                ),
            ));
        }
    }
}

fn check_fuzz_target_source(
    root: &Path,
    fuzz_root: &Path,
    target: FuzzTargetSpec,
    diagnostics: &mut Diagnostics,
) {
    let path = fuzz_root.join(target.source_path);
    let Some(source) = read_text(root, &path, diagnostics) else {
        return;
    };
    let display = display_path(root, &path);
    if target.input_bound_bytes == 0 || target.input_bound_bytes > MAX_CORPUS_BYTES {
        diagnostics.push(Diagnostic::new(
            "POLICY-FUZZ-BOUNDS",
            display.clone(),
            format!("target registry input bound must be between 1 and {MAX_CORPUS_BYTES} bytes"),
        ));
    }
    if let Some(declared_bound) = declared_fuzz_input_bound(&source) {
        if declared_bound != target.input_bound_bytes {
            diagnostics.push(Diagnostic::new(
                "POLICY-FUZZ-BOUNDS",
                display.clone(),
                format!(
                    "source MAX_INPUT_BYTES is {declared_bound}, registry declares {}",
                    target.input_bound_bytes
                ),
            ));
        }
    }
    if source.matches("MAX_INPUT_BYTES").count() < 2 {
        diagnostics.push(Diagnostic::new(
            "POLICY-FUZZ-BOUNDS",
            display.clone(),
            "fuzz target must apply MAX_INPUT_BYTES beyond its declaration",
        ));
    }
    for (marker, message) in [
        (
            "const MAX_INPUT_BYTES: usize =",
            "fuzz target must declare a MAX_INPUT_BYTES bound",
        ),
        (
            "fuzz_target!(",
            "fuzz target must contain the libFuzzer entry point",
        ),
        (
            "//! Invariants",
            "fuzz target must declare source invariants",
        ),
        (
            FUZZ_SOURCE_COVERAGE_MARKER,
            "fuzz target must declare source-side inventory/property coverage",
        ),
        (
            FUZZ_IO_POLICY_MARKER,
            "fuzz target must declare an explicit no-I/O policy",
        ),
    ] {
        if !source.contains(marker) {
            diagnostics.push(Diagnostic::new(
                "POLICY-FUZZ-SOURCE",
                display.clone(),
                message,
            ));
        }
    }
    for (line_number, line) in source.lines().enumerate() {
        let code = line.split_once("//").map_or(line, |(code, _)| code).trim();
        if FUZZ_FORBIDDEN_IO_MARKERS
            .iter()
            .any(|marker| code.contains(marker))
        {
            diagnostics.push(Diagnostic::new(
                "POLICY-FUZZ-SAFETY",
                format!("{display}:{}", line_number + 1),
                "fuzz target source contains a forbidden filesystem, process, environment, or network I/O marker",
            ));
        }
    }
}

fn declared_fuzz_input_bound(source: &str) -> Option<u64> {
    let line = source.lines().find(|line| {
        line.trim_start()
            .starts_with("const MAX_INPUT_BYTES: usize =")
    })?;
    let expression = line.split_once('=')?.1.trim().trim_end_matches(';').trim();
    let mut value = 1_u64;
    for factor in expression.split('*') {
        value = value.checked_mul(factor.trim().parse::<u64>().ok()?)?;
    }
    Some(value)
}

fn check_fuzz_corpus(
    root: &Path,
    fuzz_root: &Path,
    profile: &ProfileIndex,
    diagnostics: &mut Diagnostics,
) {
    let corpus_root = fuzz_root.join("corpus");
    let provenance_path = corpus_root.join("PROVENANCE.md");
    let Some(provenance) = read_text(root, &provenance_path, diagnostics) else {
        return;
    };
    let provenance_display = display_path(root, &provenance_path);
    for marker in ["TEST-003", "original", "synthetic", "Apache-2.0"] {
        if !provenance.contains(marker) {
            diagnostics.push(Diagnostic::new(
                "POLICY-FUZZ-PROVENANCE",
                provenance_display.clone(),
                format!("provenance document must contain {marker:?}"),
            ));
        }
    }
    for marker in ["TODO", "TO_BE_FILLED", "placeholder"] {
        if provenance.contains(marker) {
            diagnostics.push(Diagnostic::new(
                "POLICY-FUZZ-PROVENANCE",
                provenance_display.clone(),
                format!("provenance document contains unresolved marker {marker:?}"),
            ));
        }
    }
    let declared = provenance
        .lines()
        .filter_map(|line| line.split('`').nth(1))
        .filter(|value| safe_relative_path(value) && *value != "PROVENANCE.md")
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    for target in FUZZ_TARGETS {
        let directory = target
            .corpus_directory
            .map(|relative| fuzz_root.join(relative));
        match directory {
            Some(directory) if !directory.is_dir() => diagnostics.push(Diagnostic::new(
                "POLICY-FUZZ-PROVENANCE",
                display_path(root, &directory),
                format!(
                    "target {:?} declares a corpus directory that does not exist",
                    target.name
                ),
            )),
            None => {
                let unexpected = fuzz_root.join("corpus").join(target.name);
                if unexpected.exists() {
                    diagnostics.push(Diagnostic::new(
                        "POLICY-FUZZ-PROVENANCE",
                        display_path(root, &unexpected),
                        format!(
                            "target {:?} is declared in-memory but has a corpus directory",
                            target.name
                        ),
                    ));
                }
            }
            Some(_) => {}
        }
    }
    let mut files = Vec::new();
    collect_files(root, &corpus_root, 0, &mut files, diagnostics);
    for path in files {
        let Ok(relative) = path.strip_prefix(&corpus_root) else {
            continue;
        };
        if relative == Path::new("PROVENANCE.md") {
            continue;
        }
        if relative.file_name().and_then(|name| name.to_str()) == Some("README.md") {
            continue;
        }
        let relative_path = relative;
        let relative = relative.to_string_lossy().replace('\\', "/");
        let target_name = relative.split('/').next().unwrap_or_default();
        let expected_directory = format!("corpus/{target_name}");
        if !FUZZ_TARGETS
            .iter()
            .any(|target| target.corpus_directory == Some(expected_directory.as_str()))
        {
            diagnostics.push(Diagnostic::new(
                "POLICY-FUZZ-PROVENANCE",
                display_path(root, &path),
                "corpus seed is outside the static target registry",
            ));
        }
        if !declared.contains(&relative) {
            diagnostics.push(Diagnostic::new(
                "POLICY-FUZZ-PROVENANCE",
                display_path(root, &path),
                "corpus seed is not listed in corpus/PROVENANCE.md",
            ));
        }
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.len() == 0 => diagnostics.push(Diagnostic::new(
                "POLICY-FUZZ-SEED",
                display_path(root, &path),
                "fuzz seed must not be empty",
            )),
            Ok(metadata) if metadata.len() > MAX_CORPUS_BYTES => diagnostics.push(Diagnostic::new(
                "POLICY-FUZZ-SEED",
                display_path(root, &path),
                format!("fuzz seed exceeds {}-byte bound", MAX_CORPUS_BYTES),
            )),
            Ok(_) => {}
            Err(error) => diagnostics.push(Diagnostic::new(
                "POLICY-FUZZ-IO",
                display_path(root, &path),
                format!("cannot inspect fuzz seed: {error}"),
            )),
        }
        if forbidden_corpus_artifact(relative_path) {
            diagnostics.push(Diagnostic::new(
                "POLICY-FUZZ-SAFETY",
                display_path(root, &path),
                "compiled, raw, log, or generated artifacts are not permitted in the fuzz corpus",
            ));
        }
    }
    if !profile.feature_ids.contains("TEST-003") {
        diagnostics.push(Diagnostic::new(
            "POLICY-FUZZ-REFERENCE",
            display_path(root, &provenance_path),
            "fuzz corpus exists but active profile has no TEST-003 feature",
        ));
    }
}

fn forbidden_corpus_artifact(path: &Path) -> bool {
    path.components().any(|component| {
        matches!(
            component,
            Component::Normal(value)
                if matches!(
                    value.to_str(),
                    Some("__pycache__" | "oracle-runs" | "target" | ".git" | "generated")
                )
        )
    }) || path
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "class"
                    | "dll"
                    | "dylib"
                    | "exe"
                    | "jtl"
                    | "log"
                    | "profdata"
                    | "profraw"
                    | "pyc"
                    | "raw"
                    | "so"
            )
        })
}

fn check_perf(
    root: &Path,
    fixture_root: &Path,
    profile: &ProfileIndex,
    diagnostics: &mut Diagnostics,
) {
    let perf_root = root.join("tools").join("perf");
    check_schema(
        root,
        &perf_root.join("schema/config.schema.json"),
        CONFIG_SCHEMA_ID,
        diagnostics,
    );
    check_schema(
        root,
        &perf_root.join("schema/result.schema.json"),
        RESULT_SCHEMA_ID,
        diagnostics,
    );
    check_orchestrator(root, &perf_root.join("orchestrator.py"), diagnostics);
    if !profile.feature_ids.contains("TEST-005") {
        diagnostics.push(Diagnostic::new(
            "POLICY-PERF-REFERENCE",
            display_path(root, &perf_root),
            "performance declarations require TEST-005 in the active profile",
        ));
    }
    let lock_hash = hash_file(root, &root.join("Cargo.lock"), diagnostics);
    let mut seen_configs = BTreeSet::new();
    for file in CONFIG_FILES {
        let path = perf_root.join("configs").join(file);
        let Some(value) = read_json(root, &path, diagnostics) else {
            continue;
        };
        let Some(config) = value.as_object() else {
            diagnostics.push(Diagnostic::new(
                "POLICY-PERF-SCHEMA",
                display_path(root, &path),
                "performance config must be an object",
            ));
            continue;
        };
        let config_id = validate_perf_config(
            root,
            fixture_root,
            profile,
            config,
            &path,
            lock_hash.as_deref(),
            diagnostics,
        );
        if let Some(config_id) = config_id
            && !seen_configs.insert(config_id.clone())
        {
            diagnostics.push(Diagnostic::new(
                "POLICY-PERF-SCHEMA",
                display_path(root, &path),
                format!("duplicate config_id {config_id:?}"),
            ));
        }
    }
}

fn validate_perf_config(
    root: &Path,
    fixture_root: &Path,
    profile: &ProfileIndex,
    config: &Map<String, Value>,
    path: &Path,
    lock_hash: Option<&str>,
    diagnostics: &mut Diagnostics,
) -> Option<String> {
    let display = display_path(root, path);
    expect_string(
        config,
        "schema_id",
        &display,
        Some(CONFIG_SCHEMA_ID),
        diagnostics,
    );
    expect_u64(
        config,
        "schema_version",
        &display,
        Some(CONFIG_SCHEMA_VERSION),
        diagnostics,
    );
    let config_id = config
        .get("config_id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if config_id.as_deref().is_none_or(|value| !valid_id(value)) {
        diagnostics.push(Diagnostic::new(
            "POLICY-PERF-SCHEMA",
            format!("{display}.config_id"),
            "must be a lowercase identifier of 3-64 characters",
        ));
    }
    let kind = config.get("kind").and_then(Value::as_str);
    if !matches!(kind, Some("micro" | "macro" | "soak")) {
        diagnostics.push(Diagnostic::new(
            "POLICY-PERF-SCHEMA",
            format!("{display}.kind"),
            "must be micro, macro, or soak",
        ));
    }

    let compatibility = object_field(config, "compatibility", &display, diagnostics);
    if let Some(compatibility) = compatibility {
        expect_string(
            compatibility,
            "profile_id",
            &format!("{display}.compatibility"),
            Some(&profile.profile_id),
            diagnostics,
        );
        let fixture_id = expect_string(
            compatibility,
            "fixture_id",
            &format!("{display}.compatibility"),
            None,
            diagnostics,
        );
        if let Some(fixture_id) = fixture_id.as_deref()
            && !profile.fixture_ids.contains(fixture_id)
        {
            diagnostics.push(Diagnostic::new(
                "POLICY-PERF-REFERENCE",
                format!("{display}.compatibility.fixture_id"),
                format!("unknown profile fixture family {fixture_id:?}"),
            ));
        }
        let feature_ids = string_array(
            compatibility,
            "feature_ids",
            &format!("{display}.compatibility"),
            diagnostics,
        );
        if !feature_ids.iter().any(|id| id == "TEST-005") {
            diagnostics.push(Diagnostic::new(
                "POLICY-PERF-REFERENCE",
                format!("{display}.compatibility.feature_ids"),
                "must include TEST-005",
            ));
        }
        for id in feature_ids {
            if !is_feature_id(&id) || !profile.feature_ids.contains(&id) {
                diagnostics.push(Diagnostic::new(
                    "POLICY-PERF-REFERENCE",
                    format!("{display}.compatibility.feature_ids"),
                    format!("unknown profile feature {id:?}"),
                ));
            }
        }
        let fixture_ids = string_array(
            compatibility,
            "fixture_ids",
            &format!("{display}.compatibility"),
            diagnostics,
        );
        if let Some(fixture_id) = fixture_id.as_deref()
            && !fixture_ids.iter().any(|id| id == fixture_id)
        {
            diagnostics.push(Diagnostic::new(
                "POLICY-PERF-REFERENCE",
                format!("{display}.compatibility.fixture_ids"),
                "fixture_ids must include the primary fixture_id",
            ));
        }
        if !fixture_ids.iter().any(|id| id == "FX-CROSS-PLATFORM-001") {
            diagnostics.push(Diagnostic::new(
                "POLICY-PERF-REFERENCE",
                format!("{display}.compatibility.fixture_ids"),
                "TEST-005 plans must include the cross-platform fixture family",
            ));
        }
        for id in fixture_ids {
            if !profile.fixture_ids.contains(&id) {
                diagnostics.push(Diagnostic::new(
                    "POLICY-PERF-REFERENCE",
                    format!("{display}.compatibility.fixture_ids"),
                    format!("unknown profile fixture family {id:?}"),
                ));
            }
        }
        for id in string_array(
            compatibility,
            "normalization_policy_refs",
            &format!("{display}.compatibility"),
            diagnostics,
        ) {
            if !profile.normalization_ids.contains(&id) {
                diagnostics.push(Diagnostic::new(
                    "POLICY-PERF-REFERENCE",
                    format!("{display}.compatibility.normalization_policy_refs"),
                    format!("unknown normalization policy {id:?}"),
                ));
            }
        }
    }

    let reproducibility = object_field(config, "reproducibility", &display, diagnostics);
    if let Some(reproducibility) = reproducibility {
        if reproducibility
            .get("seed")
            .and_then(Value::as_u64)
            .is_none()
        {
            diagnostics.push(Diagnostic::new(
                "POLICY-PERF-DETERMINISM",
                format!("{display}.reproducibility.seed"),
                "must be a non-negative integer",
            ));
        }
        for (field, expected) in [
            ("locale", "en-US"),
            ("timezone", "UTC"),
            ("charset", "UTF-8"),
            ("working_directory_policy", "ephemeral-run-root"),
        ] {
            expect_string(
                reproducibility,
                field,
                &format!("{display}.reproducibility"),
                Some(expected),
                diagnostics,
            );
        }
        for field in [
            "target_os",
            "target_triple",
            "os_image_id",
            "rust_toolchain",
        ] {
            if reproducibility
                .get(field)
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            {
                diagnostics.push(Diagnostic::new(
                    "POLICY-PERF-DETERMINISM",
                    format!("{display}.reproducibility.{field}"),
                    "must be a non-empty string",
                ));
            }
        }
        if !matches!(
            reproducibility.get("clock_mode").and_then(Value::as_str),
            Some("controlled-fixture" | "monotonic-only")
        ) {
            diagnostics.push(Diagnostic::new(
                "POLICY-PERF-DETERMINISM",
                format!("{display}.reproducibility.clock_mode"),
                "must use a controlled fixture or monotonic clock",
            ));
        }
        if let Some(expected_hash) = lock_hash {
            expect_string(
                reproducibility,
                "cargo_lock_sha256",
                &format!("{display}.reproducibility"),
                Some(expected_hash),
                diagnostics,
            );
        } else {
            let _ = expect_string(
                reproducibility,
                "cargo_lock_sha256",
                &format!("{display}.reproducibility"),
                None,
                diagnostics,
            );
        }
        if reproducibility
            .get("source_date_epoch")
            .and_then(Value::as_u64)
            .is_none()
        {
            diagnostics.push(Diagnostic::new(
                "POLICY-PERF-DETERMINISM",
                format!("{display}.reproducibility.source_date_epoch"),
                "must be a non-negative integer",
            ));
        }
        let environment = string_array(
            reproducibility,
            "environment_allowlist",
            &format!("{display}.reproducibility"),
            diagnostics,
        );
        let mut seen = BTreeSet::new();
        for key in environment {
            if key.contains('=') || !valid_environment_name(&key) || !seen.insert(key.clone()) {
                diagnostics.push(Diagnostic::new(
                    "POLICY-PERF-DETERMINISM",
                    format!("{display}.reproducibility.environment_allowlist"),
                    "must contain unique variable names, never KEY=VALUE entries",
                ));
            }
        }
    }

    let execution = object_field(config, "execution", &display, diagnostics);
    if let Some(execution) = execution {
        expect_string(
            execution,
            "mode",
            &display,
            Some("dry-run-only"),
            diagnostics,
        );
        if let Some(policy) = object_field(
            execution,
            "subprocess_policy",
            &format!("{display}.execution"),
            diagnostics,
        ) {
            for (field, expected) in [
                ("benchmark_processes", "forbidden"),
                ("service_processes", "forbidden"),
                ("network", "offline"),
                ("process_start", "disabled"),
                ("group_signalling", "forbidden"),
            ] {
                expect_string(
                    policy,
                    field,
                    &format!("{display}.execution.subprocess_policy"),
                    Some(expected),
                    diagnostics,
                );
            }
            expect_bool(
                policy,
                "shell",
                &format!("{display}.execution.subprocess_policy"),
                Some(false),
                diagnostics,
            );
        }
        if let Some(children) = array_field(
            execution,
            "children",
            &format!("{display}.execution"),
            diagnostics,
        ) {
            let mut ids = BTreeSet::new();
            for (index, child) in children.iter().enumerate() {
                let context = format!("{display}.execution.children[{index}]");
                let Some(child) = child.as_object() else {
                    diagnostics.push(Diagnostic::new(
                        "POLICY-PERF-SAFETY",
                        context,
                        "child must be an object",
                    ));
                    continue;
                };
                if let Some(id) = child.get("id").and_then(Value::as_str)
                    && !ids.insert(id.to_owned())
                {
                    diagnostics.push(Diagnostic::new(
                        "POLICY-PERF-SAFETY",
                        format!("{context}.id"),
                        "child IDs must be unique",
                    ));
                }
                for field in ["enabled", "future_only", "shell"] {
                    let expected = field == "future_only";
                    expect_bool(child, field, &context, Some(expected), diagnostics);
                }
                expect_string(
                    child,
                    "working_directory",
                    &context,
                    Some("ephemeral-run-root"),
                    diagnostics,
                );
                if child
                    .get("environment")
                    .and_then(Value::as_object)
                    .is_none_or(|value| !value.is_empty())
                {
                    diagnostics.push(Diagnostic::new(
                        "POLICY-PERF-SAFETY",
                        format!("{context}.environment"),
                        "future child environment must be empty",
                    ));
                }
                if let Some(ownership) = object_field(child, "ownership", &context, diagnostics) {
                    for (field, expected) in [
                        ("identity", "owned-child-handle"),
                        ("pre_signal_check", "try_wait-before-signal"),
                        ("reap", "wait-exact-child-on-all-paths"),
                        ("termination", "direct-child-only"),
                        ("pid_validation", "live-child-pgid-greater-than-one"),
                    ] {
                        expect_string(
                            ownership,
                            field,
                            &format!("{context}.ownership"),
                            Some(expected),
                            diagnostics,
                        );
                    }
                }
            }
        }
        if let Some(containers) = array_field(
            execution,
            "containers",
            &format!("{display}.execution"),
            diagnostics,
        ) {
            for (index, container) in containers.iter().enumerate() {
                let context = format!("{display}.execution.containers[{index}]");
                let Some(container) = container.as_object() else {
                    diagnostics.push(Diagnostic::new(
                        "POLICY-PERF-SAFETY",
                        context,
                        "container must be an object",
                    ));
                    continue;
                };
                for field in ["enabled", "future_only"] {
                    expect_bool(
                        container,
                        field,
                        &context,
                        Some(field == "future_only"),
                        diagnostics,
                    );
                }
                expect_string(
                    container,
                    "id_source",
                    &context,
                    Some("created-by-this-run"),
                    diagnostics,
                );
                expect_string(
                    container,
                    "cleanup",
                    &context,
                    Some("exact-created-id-only"),
                    diagnostics,
                );
                if container
                    .get("selectors")
                    .and_then(Value::as_array)
                    .is_none_or(|values| !values.is_empty())
                {
                    diagnostics.push(Diagnostic::new(
                        "POLICY-PERF-SAFETY",
                        format!("{context}.selectors"),
                        "container selectors must remain empty",
                    ));
                }
            }
        }
    }

    let workload = object_field(config, "workload", &display, diagnostics);
    if let Some(workload) = workload {
        let fixture_path = workload.get("fixture_path").and_then(Value::as_str);
        let fixture_sha256 = workload.get("fixture_sha256").and_then(Value::as_str);
        if fixture_sha256.is_none() {
            diagnostics.push(Diagnostic::new(
                "POLICY-PERF-SCHEMA",
                format!("{display}.workload.fixture_sha256"),
                "performance workload must declare fixture_sha256",
            ));
        }
        if fixture_path.is_none_or(|value| !safe_relative_path(value)) {
            diagnostics.push(Diagnostic::new(
                "POLICY-PERF-PATH",
                format!("{display}.workload.fixture_path"),
                "must be a safe repository-relative path",
            ));
        } else if let Some(fixture_path) = fixture_path {
            let full_path = root.join(fixture_path);
            if !full_path.is_file() {
                diagnostics.push(Diagnostic::new(
                    "POLICY-PERF-REFERENCE",
                    format!("{display}.workload.fixture_path"),
                    "fixture path does not exist",
                ));
            } else if let Some(expected) = fixture_sha256 {
                if !is_sha256(expected) {
                    diagnostics.push(Diagnostic::new(
                        "POLICY-PERF-SCHEMA",
                        format!("{display}.workload.fixture_sha256"),
                        "must be a lowercase SHA-256 digest",
                    ));
                } else if let Some(actual) = hash_file(root, &full_path, diagnostics)
                    && actual != expected
                {
                    diagnostics.push(Diagnostic::new(
                        "POLICY-PERF-HASH",
                        format!("{display}.workload.fixture_sha256"),
                        format!("fixture digest mismatch: expected {expected}, found {actual}"),
                    ));
                }
            }
        }
        let _ = fixture_root;
        if let Some(operations) = array_field(
            workload,
            "operations",
            &format!("{display}.workload"),
            diagnostics,
        ) {
            let mut ids = BTreeSet::new();
            for (index, operation) in operations.iter().enumerate() {
                let context = format!("{display}.workload.operations[{index}]");
                let Some(operation) = operation.as_object() else {
                    diagnostics.push(Diagnostic::new(
                        "POLICY-PERF-SCHEMA",
                        context,
                        "operation must be an object",
                    ));
                    continue;
                };
                if let Some(id) = operation.get("id").and_then(Value::as_str)
                    && !ids.insert(id.to_owned())
                {
                    diagnostics.push(Diagnostic::new(
                        "POLICY-PERF-SCHEMA",
                        format!("{context}.id"),
                        "operation IDs must be unique",
                    ));
                }
                if operation.get("enabled").and_then(Value::as_bool) != Some(true) {
                    diagnostics.push(Diagnostic::new(
                        "POLICY-PERF-SCHEMA",
                        format!("{context}.enabled"),
                        "declared operations must be enabled in a plan",
                    ));
                }
                if operation
                    .get("parameters")
                    .and_then(Value::as_object)
                    .is_none()
                {
                    diagnostics.push(Diagnostic::new(
                        "POLICY-PERF-SCHEMA",
                        format!("{context}.parameters"),
                        "operation parameters must be an object",
                    ));
                }
            }
        }
        if workload
            .get("virtual_users")
            .and_then(Value::as_u64)
            .is_none_or(|value| value == 0 || value > 1_000_000)
        {
            diagnostics.push(Diagnostic::new(
                "POLICY-PERF-BOUNDS",
                format!("{display}.workload.virtual_users"),
                "must be between 1 and 1,000,000",
            ));
        }
        let iterations = workload.get("iterations").and_then(Value::as_u64);
        let duration = workload.get("duration_seconds").and_then(Value::as_u64);
        if iterations.is_none() && duration.is_none() {
            diagnostics.push(Diagnostic::new(
                "POLICY-PERF-BOUNDS",
                format!("{display}.workload"),
                "workload must have a bounded iteration or duration value",
            ));
        }
    }
    if let Some(metrics) = object_field(config, "metrics", &display, diagnostics) {
        expect_string(
            metrics,
            "queue_policy",
            &format!("{display}.metrics"),
            Some("bounded-fail-on-overflow"),
            diagnostics,
        );
        if metrics
            .get("max_samples")
            .and_then(Value::as_u64)
            .is_none_or(|value| value == 0)
        {
            diagnostics.push(Diagnostic::new(
                "POLICY-PERF-BOUNDS",
                format!("{display}.metrics.max_samples"),
                "must be a positive bound",
            ));
        }
        if metrics
            .get("sample_interval_seconds")
            .and_then(Value::as_f64)
            .is_none_or(|value| value <= 0.0)
        {
            diagnostics.push(Diagnostic::new(
                "POLICY-PERF-DETERMINISM",
                format!("{display}.metrics.sample_interval_seconds"),
                "must be positive",
            ));
        }
        let required = ["rss_bytes", "open_fd_count", "thread_count", "task_count"];
        let resource_ids = metrics
            .get("resource_metrics")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(|value| value.get("id").and_then(Value::as_str))
                    .collect::<BTreeSet<_>>()
            })
            .unwrap_or_default();
        for id in required {
            if !resource_ids.contains(id) {
                diagnostics.push(Diagnostic::new(
                    "POLICY-PERF-SCHEMA",
                    format!("{display}.metrics.resource_metrics"),
                    format!("required resource metric {id:?} is missing"),
                ));
            }
        }
    }
    if let Some(thresholds) = object_field(config, "thresholds", &display, diagnostics) {
        expect_string(
            thresholds,
            "missing_metric_policy",
            &format!("{display}.thresholds"),
            Some("fail"),
            diagnostics,
        );
        if let Some(rules) = array_field(
            thresholds,
            "rules",
            &format!("{display}.thresholds"),
            diagnostics,
        ) {
            let mut ids = BTreeSet::new();
            for (index, rule) in rules.iter().enumerate() {
                if let Some(rule) = rule.as_object() {
                    if let Some(id) = rule.get("id").and_then(Value::as_str)
                        && !ids.insert(id.to_owned())
                    {
                        diagnostics.push(Diagnostic::new(
                            "POLICY-PERF-SCHEMA",
                            format!("{display}.thresholds.rules[{index}].id"),
                            "threshold rule IDs must be unique",
                        ));
                    }
                    if !matches!(
                        rule.get("operator")
                            .and_then(Value::as_str)
                            .or_else(|| rule.get("comparison").and_then(Value::as_str)),
                        Some("=" | ">=" | "<=" | ">" | "<")
                    ) {
                        diagnostics.push(Diagnostic::new(
                            "POLICY-PERF-SCHEMA",
                            format!("{display}.thresholds.rules[{index}]"),
                            "threshold operator is unsupported",
                        ));
                    }
                }
            }
        }
    }
    if let Some(leak) = object_field(config, "leak_sampling", &display, diagnostics) {
        expect_bool(
            leak,
            "enabled",
            &format!("{display}.leak_sampling"),
            Some(true),
            diagnostics,
        );
        expect_string(
            leak,
            "unavailable_policy",
            &format!("{display}.leak_sampling"),
            Some("fail"),
            diagnostics,
        );
        expect_bool(
            leak,
            "require_final_sample",
            &format!("{display}.leak_sampling"),
            Some(true),
            diagnostics,
        );
        if leak
            .get("interval_seconds")
            .and_then(Value::as_f64)
            .is_none_or(|value| value <= 0.0)
        {
            diagnostics.push(Diagnostic::new(
                "POLICY-PERF-DETERMINISM",
                format!("{display}.leak_sampling.interval_seconds"),
                "must be positive",
            ));
        }
    }
    if let Some(artifacts) = object_field(config, "artifacts", &display, diagnostics) {
        expect_string(
            artifacts,
            "write_mode",
            &format!("{display}.artifacts"),
            Some("dry-run-only"),
            diagnostics,
        );
        expect_bool(
            artifacts,
            "raw_samples",
            &format!("{display}.artifacts"),
            Some(false),
            diagnostics,
        );
        if artifacts
            .get("max_bytes")
            .and_then(Value::as_u64)
            .is_none_or(|value| value == 0 || value > 1_073_741_824)
        {
            diagnostics.push(Diagnostic::new(
                "POLICY-PERF-BOUNDS",
                format!("{display}.artifacts.max_bytes"),
                "must be a positive bound no larger than 1 GiB",
            ));
        }
        for field in ["root", "result_filename"] {
            if artifacts
                .get(field)
                .and_then(Value::as_str)
                .is_none_or(|value| !safe_relative_path(value))
            {
                diagnostics.push(Diagnostic::new(
                    "POLICY-PERF-PATH",
                    format!("{display}.artifacts.{field}"),
                    "must be a safe relative path",
                ));
            }
        }
    }
    if kind == Some("soak") {
        let expected_duration = config_id.as_deref().and_then(|id| match id {
            "soak-1h-offline" => Some(3_600),
            "soak-8h-offline" => Some(28_800),
            "soak-24h-offline" => Some(86_400),
            _ => None,
        });
        if let Some(expected_duration) = expected_duration
            && config
                .get("workload")
                .and_then(Value::as_object)
                .and_then(|workload| workload.get("duration_seconds"))
                .and_then(Value::as_u64)
                != Some(expected_duration)
        {
            diagnostics.push(Diagnostic::new(
                "POLICY-PERF-BOUNDS",
                format!("{display}.workload.duration_seconds"),
                format!("soak config must declare exactly {expected_duration} seconds"),
            ));
        }
    }
    config_id
}

fn check_schema(root: &Path, path: &Path, expected_id: &str, diagnostics: &mut Diagnostics) {
    let Some(value) = read_json(root, path, diagnostics) else {
        return;
    };
    let Some(object) = value.as_object() else {
        diagnostics.push(Diagnostic::new(
            "POLICY-SCHEMA",
            display_path(root, path),
            "schema document must be an object",
        ));
        return;
    };
    let display = display_path(root, path);
    if object.get("type").and_then(Value::as_str) != Some("object")
        || object.get("additionalProperties").and_then(Value::as_bool) != Some(false)
    {
        diagnostics.push(Diagnostic::new(
            "POLICY-SCHEMA",
            display.clone(),
            "schema must be a closed object schema",
        ));
    }
    if expected_id == CONFIG_SCHEMA_ID
        && object
            .get("$id")
            .and_then(Value::as_str)
            .is_none_or(|value| !value.ends_with("config.schema.json"))
    {
        diagnostics.push(Diagnostic::new(
            "POLICY-SCHEMA",
            format!("{display}.$id"),
            "config schema $id must identify config.schema.json",
        ));
    }
    if expected_id == RESULT_SCHEMA_ID
        && object
            .get("$id")
            .and_then(Value::as_str)
            .is_none_or(|value| !value.ends_with("result.schema.json"))
    {
        diagnostics.push(Diagnostic::new(
            "POLICY-SCHEMA",
            format!("{display}.$id"),
            "result schema $id must identify result.schema.json",
        ));
    }
    let properties = object.get("properties").and_then(Value::as_object);
    if properties
        .and_then(|properties| properties.get("schema_id"))
        .and_then(|schema_id| schema_id.get("const"))
        .and_then(Value::as_str)
        != Some(expected_id)
    {
        diagnostics.push(Diagnostic::new(
            "POLICY-SCHEMA",
            format!("{display}.properties.schema_id.const"),
            format!("must identify {expected_id:?}"),
        ));
    }
    if properties
        .and_then(|properties| properties.get("schema_version"))
        .and_then(|schema_version| schema_version.get("const"))
        .and_then(Value::as_u64)
        != Some(if expected_id == CONFIG_SCHEMA_ID {
            CONFIG_SCHEMA_VERSION
        } else {
            RESULT_SCHEMA_VERSION
        })
    {
        diagnostics.push(Diagnostic::new(
            "POLICY-SCHEMA",
            format!("{display}.properties.schema_version.const"),
            format!(
                "must be schema version {}",
                if expected_id == CONFIG_SCHEMA_ID {
                    CONFIG_SCHEMA_VERSION
                } else {
                    RESULT_SCHEMA_VERSION
                }
            ),
        ));
    }
    if object
        .get("required")
        .and_then(Value::as_array)
        .is_none_or(|values| values.is_empty())
    {
        diagnostics.push(Diagnostic::new(
            "POLICY-SCHEMA",
            format!("{display}.required"),
            "schema must declare required fields",
        ));
    }
}

fn check_orchestrator(root: &Path, path: &Path, diagnostics: &mut Diagnostics) {
    let Some(source) = read_text(root, path, diagnostics) else {
        return;
    };
    let display = display_path(root, path);
    for forbidden in [
        "import subprocess",
        "from subprocess",
        "subprocess.",
        "import socket",
        "from socket",
        "socket.",
        "Popen(",
        "create_subprocess",
    ] {
        for (line_number, line) in source.lines().enumerate() {
            let code = line.split('#').next().unwrap_or_default();
            if code.contains(forbidden) {
                diagnostics.push(Diagnostic::new(
                    "POLICY-PERF-SAFETY",
                    format!("{display}:{}", line_number + 1),
                    format!("orchestrator contains forbidden execution marker {forbidden:?}"),
                ));
            }
        }
    }
    if !source.contains("dry-run") || !source.contains("validate") {
        diagnostics.push(Diagnostic::new(
            "POLICY-PERF-SAFETY",
            display,
            "orchestrator must retain explicit dry-run and validate modes",
        ));
    }
}

fn collect_files(
    root: &Path,
    directory: &Path,
    depth: usize,
    files: &mut Vec<PathBuf>,
    diagnostics: &mut Diagnostics,
) {
    if depth > MAX_DIRECTORY_DEPTH {
        diagnostics.push(Diagnostic::new(
            "POLICY-PATH",
            display_path(root, directory),
            "directory nesting exceeds validator bound",
        ));
        return;
    }
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries.collect::<Result<Vec<_>, _>>(),
        Err(error) => {
            diagnostics.push(Diagnostic::new(
                "POLICY-IO",
                display_path(root, directory),
                format!("cannot read directory: {error}"),
            ));
            return;
        }
    };
    let mut entries = match entries {
        Ok(entries) => entries,
        Err(error) => {
            diagnostics.push(Diagnostic::new(
                "POLICY-IO",
                display_path(root, directory),
                format!("cannot enumerate directory: {error}"),
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
                    "POLICY-IO",
                    display_path(root, &path),
                    format!("cannot inspect entry: {error}"),
                ));
                continue;
            }
        };
        if file_type.is_symlink() {
            diagnostics.push(Diagnostic::new(
                "POLICY-PATH",
                display_path(root, &path),
                "symlinks are not allowed",
            ));
        } else if file_type.is_dir() {
            collect_files(root, &path, depth + 1, files, diagnostics);
        } else if file_type.is_file() {
            files.push(path);
        } else {
            diagnostics.push(Diagnostic::new(
                "POLICY-PATH",
                display_path(root, &path),
                "entry must be a regular file or directory",
            ));
        }
    }
}

fn read_json(root: &Path, path: &Path, diagnostics: &mut Diagnostics) -> Option<Value> {
    let text = read_text(root, path, diagnostics)?;
    match serde_json::from_str(&text) {
        Ok(value) => {
            let mut nodes = 0;
            validate_json_limits(
                &value,
                &display_path(root, path),
                0,
                &mut nodes,
                diagnostics,
            )
            .then_some(value)
        }
        Err(error) => {
            diagnostics.push(Diagnostic::new(
                "POLICY-JSON",
                display_path(root, path),
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
            "POLICY-BOUNDS",
            path,
            format!("JSON node count exceeds {MAX_JSON_NODES}"),
        ));
        return false;
    }
    if depth > MAX_JSON_DEPTH {
        diagnostics.push(Diagnostic::new(
            "POLICY-BOUNDS",
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

fn read_text(root: &Path, path: &Path, diagnostics: &mut Diagnostics) -> Option<String> {
    let display = display_path(root, path);
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            diagnostics.push(Diagnostic::new(
                "POLICY-IO",
                display,
                format!("cannot inspect file: {error}"),
            ));
            return None;
        }
    };
    if metadata.file_type().is_symlink() {
        diagnostics.push(Diagnostic::new(
            "POLICY-PATH",
            display,
            "symlinks are not allowed",
        ));
        return None;
    }
    if !metadata.is_file() {
        diagnostics.push(Diagnostic::new(
            "POLICY-PATH",
            display,
            "expected a regular file",
        ));
        return None;
    }
    if metadata.len() > MAX_DECLARATION_BYTES {
        diagnostics.push(Diagnostic::new(
            "POLICY-BOUNDS",
            display,
            format!("file exceeds {MAX_DECLARATION_BYTES}-byte validator bound"),
        ));
        return None;
    }
    match fs::read_to_string(path) {
        Ok(text) => {
            validate_text_safety(root, path, &text, diagnostics);
            Some(text)
        }
        Err(error) => {
            diagnostics.push(Diagnostic::new(
                "POLICY-IO",
                display,
                format!("cannot read file: {error}"),
            ));
            None
        }
    }
}

fn validate_text_safety(root: &Path, path: &Path, text: &str, diagnostics: &mut Diagnostics) {
    for (line_number, line) in text.lines().enumerate() {
        let lower = line.to_ascii_lowercase();
        if (lower.contains("-----begin ") && lower.contains("private key"))
            || lower.contains("password=")
            || lower.contains("api_key=")
            || lower.contains("bearer ")
            || (line.contains("AKIA") && line.len() >= 20)
        {
            diagnostics.push(Diagnostic::new(
                "POLICY-SAFETY",
                format!("{}:{}", display_path(root, path), line_number + 1),
                "secret or private credential material is not allowed in policy text",
            ));
        }
        if lower.contains("/home/")
            || lower.contains("/users/")
            || lower.contains("c:\\users\\")
            || line.trim_start().starts_with("\\\\")
        {
            diagnostics.push(Diagnostic::new(
                "POLICY-PATH",
                format!("{}:{}", display_path(root, path), line_number + 1),
                "machine-specific absolute paths are not allowed in policy text",
            ));
        }
    }
}

fn hash_file(root: &Path, path: &Path, diagnostics: &mut Diagnostics) -> Option<String> {
    let display = display_path(root, path);
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            diagnostics.push(Diagnostic::new(
                "POLICY-IO",
                display,
                format!("cannot inspect file: {error}"),
            ));
            return None;
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        diagnostics.push(Diagnostic::new(
            "POLICY-PATH",
            display,
            "hash input must be a regular non-symlink file",
        ));
        return None;
    }
    if metadata.len() > MAX_DECLARATION_BYTES {
        diagnostics.push(Diagnostic::new(
            "POLICY-BOUNDS",
            display,
            format!("hash input exceeds {MAX_DECLARATION_BYTES}-byte validator bound"),
        ));
        return None;
    }
    let digest = Sha256::digest(match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => {
            diagnostics.push(Diagnostic::new(
                "POLICY-IO",
                display,
                format!("cannot read hash input: {error}"),
            ));
            return None;
        }
    });
    Some(
        digest
            .iter()
            .fold(String::with_capacity(64), |mut output, byte| {
                use std::fmt::Write;
                let _ = write!(output, "{byte:02x}");
                output
            }),
    )
}

fn object_field<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    parent: &str,
    diagnostics: &mut Diagnostics,
) -> Option<&'a Map<String, Value>> {
    match object.get(field).and_then(Value::as_object) {
        Some(value) => Some(value),
        None => {
            diagnostics.push(Diagnostic::new(
                "POLICY-SCHEMA",
                format!("{parent}.{field}"),
                "required object is missing or has the wrong type",
            ));
            None
        }
    }
}

fn array_field<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    parent: &str,
    diagnostics: &mut Diagnostics,
) -> Option<&'a Vec<Value>> {
    match object.get(field).and_then(Value::as_array) {
        Some(value) => Some(value),
        None => {
            diagnostics.push(Diagnostic::new(
                "POLICY-SCHEMA",
                format!("{parent}.{field}"),
                "required array is missing or has the wrong type",
            ));
            None
        }
    }
}

fn string_array(
    object: &Map<String, Value>,
    field: &str,
    parent: &str,
    diagnostics: &mut Diagnostics,
) -> Vec<String> {
    let Some(values) = array_field(object, field, parent, diagnostics) else {
        return Vec::new();
    };
    values
        .iter()
        .filter_map(|value| value.as_str().map(str::to_owned))
        .collect()
}

fn expect_string(
    object: &Map<String, Value>,
    field: &str,
    parent: &str,
    expected: Option<&str>,
    diagnostics: &mut Diagnostics,
) -> Option<String> {
    let value = object.get(field).and_then(Value::as_str).map(str::to_owned);
    if value.is_none() {
        diagnostics.push(Diagnostic::new(
            "POLICY-SCHEMA",
            format!("{parent}.{field}"),
            "required non-empty string is missing or has the wrong type",
        ));
    } else if let Some(expected) = expected
        && value.as_deref() != Some(expected)
    {
        diagnostics.push(Diagnostic::new(
            "POLICY-REFERENCE",
            format!("{parent}.{field}"),
            format!("must be {expected:?}"),
        ));
    }
    value
}

fn expect_u64(
    object: &Map<String, Value>,
    field: &str,
    parent: &str,
    expected: Option<u64>,
    diagnostics: &mut Diagnostics,
) -> Option<u64> {
    let value = object.get(field).and_then(Value::as_u64);
    if value.is_none() {
        diagnostics.push(Diagnostic::new(
            "POLICY-SCHEMA",
            format!("{parent}.{field}"),
            "required non-negative integer is missing or has the wrong type",
        ));
    } else if let Some(expected) = expected
        && value != Some(expected)
    {
        diagnostics.push(Diagnostic::new(
            "POLICY-SCHEMA",
            format!("{parent}.{field}"),
            format!("must be {expected}"),
        ));
    }
    value
}

fn expect_bool(
    object: &Map<String, Value>,
    field: &str,
    parent: &str,
    expected: Option<bool>,
    diagnostics: &mut Diagnostics,
) -> Option<bool> {
    let value = object.get(field).and_then(Value::as_bool);
    if value.is_none() {
        diagnostics.push(Diagnostic::new(
            "POLICY-SCHEMA",
            format!("{parent}.{field}"),
            "required boolean is missing or has the wrong type",
        ));
    } else if let Some(expected) = expected
        && value != Some(expected)
    {
        diagnostics.push(Diagnostic::new(
            "POLICY-SCHEMA",
            format!("{parent}.{field}"),
            format!("must be {expected}"),
        ));
    }
    value
}

fn valid_id(value: &str) -> bool {
    (3..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && value
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

fn valid_environment_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_uppercase() || *byte == b'_')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        && value.bytes().all(|byte| !byte.is_ascii_uppercase())
}

fn safe_relative_path(value: &str) -> bool {
    !value.is_empty()
        && !value.contains('\0')
        && !value.contains('\\')
        && !Path::new(value).is_absolute()
        && !Path::new(value)
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::RootDir))
}

#[cfg(test)]
mod tests {
    use super::{
        CONFIG_SCHEMA_VERSION, FUZZ_TARGETS, RESULT_SCHEMA_VERSION, check_root_generated_artifacts,
        declared_fuzz_input_bound, forbidden_corpus_artifact, is_root_generated_artifact,
        is_sha256, safe_relative_path, valid_environment_name, valid_id,
    };
    use crate::diagnostics::Diagnostics;
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn temporary_root() -> std::path::PathBuf {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "jmeter-rs-policy-root-artifact-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        if root.exists() {
            fs::remove_dir_all(&root).expect("remove stale deterministic policy test root");
        }
        fs::create_dir_all(&root).expect("create deterministic policy test root");
        root
    }

    #[test]
    fn fuzz_target_inventory_is_exact_and_closed() {
        assert_eq!(
            FUZZ_TARGETS
                .iter()
                .map(|target| target.name)
                .collect::<Vec<_>>(),
            [
                "jmx_xml",
                "jtl_csv",
                "jtl_xml",
                "jtl_model",
                "expr",
                "bridge",
                "bridge_rmi",
                "property_config",
                "save_config",
                "http_policy",
                "plugin_json",
                "remote",
                "runtime",
            ]
        );
    }

    #[test]
    fn fuzz_source_bound_parser_accepts_bounded_arithmetic_only() {
        assert_eq!(
            declared_fuzz_input_bound("const MAX_INPUT_BYTES: usize = 256 * 1024;"),
            Some(256 * 1024)
        );
        assert_eq!(
            declared_fuzz_input_bound("const MAX_INPUT_BYTES: usize = MAX_BYTES;"),
            None
        );
    }

    #[test]
    fn performance_schema_versions_are_exactly_v3() {
        assert_eq!(CONFIG_SCHEMA_VERSION, 3);
        assert_eq!(RESULT_SCHEMA_VERSION, 3);
    }

    #[test]
    fn policy_identifiers_are_constrained() {
        assert!(valid_id("micro-jmx-roundtrip"));
        assert!(!valid_id("Micro"));
        assert!(valid_environment_name("SOURCE_DATE_EPOCH"));
        assert!(!valid_environment_name("PATH=/bin"));
        assert!(is_sha256(&"a".repeat(64)));
        assert!(!is_sha256(&"A".repeat(64)));
    }

    #[test]
    fn policy_paths_reject_traversal() {
        assert!(safe_relative_path("corpus/minimal.xml"));
        assert!(!safe_relative_path("../outside"));
        assert!(!safe_relative_path("C:\\outside"));
    }

    #[test]
    fn fuzz_corpus_rejects_nested_generated_artifacts() {
        assert!(forbidden_corpus_artifact(std::path::Path::new(
            "nested/__pycache__/seed.pyc",
        )));
        assert!(forbidden_corpus_artifact(std::path::Path::new(
            "oracle-runs/trace.log",
        )));
        assert!(!forbidden_corpus_artifact(std::path::Path::new(
            "jmx_xml/minimal-valid.jmx",
        )));
    }

    #[test]
    fn root_generated_artifact_is_reported_even_when_ignored() {
        let root = temporary_root();
        let artifact = root.join("libjmeter_rs_observe.rlib");
        fs::write(&artifact, b"compiler output").expect("write root artifact fixture");

        let mut diagnostics = Diagnostics::default();
        check_root_generated_artifacts(&root, &mut diagnostics);

        let entries = diagnostics.iter().collect::<Vec<_>>();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].code, "POLICY-ROOT-ARTIFACT");
        assert_eq!(entries[0].path, "libjmeter_rs_observe.rlib");
        fs::remove_dir_all(root).expect("remove policy test root");
    }

    #[test]
    fn root_artifact_check_is_extension_bound_and_does_not_read_sources() {
        let root = temporary_root();
        fs::write(root.join("README.md"), b"source text").expect("write source fixture");
        fs::write(root.join("libexample.RLIB"), b"compiler output")
            .expect("write uppercase artifact fixture");
        fs::create_dir(root.join("named.rlib")).expect("write directory fixture");

        assert!(is_root_generated_artifact(&root.join("libexample.RLIB")));
        assert!(!is_root_generated_artifact(&root.join("README.md")));

        let mut diagnostics = Diagnostics::default();
        check_root_generated_artifacts(&root, &mut diagnostics);
        let entries = diagnostics.iter().collect::<Vec<_>>();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "libexample.RLIB");
        fs::remove_dir_all(root).expect("remove policy test root");
    }
}
