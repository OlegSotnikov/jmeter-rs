// SPDX-License-Identifier: Apache-2.0
//! Cargo workspace metadata, inheritance, and dependency-direction checks.

use crate::diagnostics::{Diagnostic, Diagnostics};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const MAX_CARGO_METADATA_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const CARGO_METADATA_TIMEOUT_SECONDS: u64 = 30;
const CARGO_METADATA_POLL_MILLISECONDS: u64 = 10;
const MAX_CARGO_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;
const TOOLCHAIN_FILE: &str = "rust-toolchain.toml";
const LOCKFILE: &str = "Cargo.lock";
const PROVENANCE_DOCUMENT: &str = "docs/third-party-provenance.md";
const REQUIRED_TOOLCHAIN_CHANNEL: &str = "1.97.1";
const REQUIRED_TOOLCHAIN_PROFILE: &str = "minimal";
const REQUIRED_TOOLCHAIN_COMPONENTS: [&str; 2] = ["rustfmt", "clippy"];
const ALLOWED_REGISTRY_SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";
const STANDALONE_APP_MANIFEST: &str = "apps/jmeter-rs/Cargo.toml";
const STANDALONE_APP_SOURCE: &str = "apps/jmeter-rs/src";
const STANDALONE_MAIN_SOURCE: &str = "apps/jmeter-rs/src/main.rs";
const MAX_STANDALONE_FILES: usize = 16_384;
const MAX_STANDALONE_DIRECTORY_DEPTH: usize = 32;
const STANDALONE_FORBIDDEN_ROLES: [Role; 4] = [
    Role::JavaBridge,
    Role::PluginHost,
    Role::ProcessSupervision,
    Role::OracleTool,
];
const STANDALONE_FORBIDDEN_EXTENSIONS: [&str; 11] = [
    "jar", "class", "java", "jmod", "war", "ear", "zip", "exe", "dll", "so", "dylib",
];
const STANDALONE_FORBIDDEN_SOURCE_MARKERS: [&str; 5] = [
    "std::process::Command",
    "Command::new",
    "jmeter-rs-java-bridge",
    "jmeter-rs-plugin-host",
    "plugin-host-test-helper",
];
const STANDALONE_RUNTIME_PATH_DEPENDENCIES: [(&str, &str); 7] = [
    ("jmeter-rs-http", "../../crates/http"),
    ("jmeter-rs-http-native", "../../crates/http-native"),
    ("jmeter-rs-jmx", "../../crates/jmx"),
    ("jmeter-rs-model", "../../crates/model"),
    ("jmeter-rs-report", "../../crates/report"),
    ("jmeter-rs-results", "../../crates/results"),
    ("jmeter-rs-runtime", "../../crates/runtime"),
];
const STANDALONE_DEV_PATH_DEPENDENCIES: [(&str, &str); 1] =
    [("jmeter-rs-expr", "../../crates/expr")];
const STANDALONE_DEV_REGISTRY_DEPENDENCIES: [(&str, &str); 1] = [("rcgen", "=0.14.9")];
const REQUIRED_WORKSPACE_MEMBERS: [&str; 18] = [
    "apps/jmeter-rs",
    "crates/model",
    "crates/jmx",
    "crates/expr",
    "crates/runtime",
    "crates/results",
    "crates/http",
    "crates/http-native",
    "crates/report",
    "crates/remote",
    "crates/bridge-protocol",
    "crates/java-bridge",
    "crates/plugin-host",
    "crates/observe",
    "crates/test-support",
    "crates/process-supervision",
    "tools/jmeter-oracle",
    "tools/xtask",
];
type MetadataReaderResult = (Vec<u8>, bool, Option<String>);
type MetadataReader = thread::JoinHandle<MetadataReaderResult>;

const INHERITED_PACKAGE_FIELDS: [&str; 8] = [
    "version",
    "edition",
    "rust-version",
    "authors",
    "license",
    "repository",
    "description",
    "publish",
];

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Role {
    App,
    Model,
    Jmx,
    Expr,
    Runtime,
    Results,
    Http,
    HttpNative,
    Report,
    Remote,
    BridgeProtocol,
    JavaBridge,
    PluginHost,
    Observe,
    TestSupport,
    ProcessSupervision,
    OracleTool,
    Xtask,
    Unknown,
}

#[derive(Clone, Debug)]
struct Package {
    name: String,
    id: String,
    manifest_path: PathBuf,
    role: Role,
    object: Map<String, Value>,
}

/// Validate workspace metadata and dependency policy.
pub(crate) fn check(root: &Path) -> Diagnostics {
    let mut diagnostics = Diagnostics::default();
    let manifest_path = root.join("Cargo.toml");
    let manifest = match read_toml(&manifest_path, &mut diagnostics) {
        Some(manifest) => manifest,
        None => return diagnostics,
    };
    let Some(manifest_table) = manifest.as_table() else {
        diagnostics.push(Diagnostic::new(
            "WORKSPACE-SCHEMA",
            "Cargo.toml",
            "workspace manifest must be a TOML table",
        ));
        return diagnostics;
    };
    let Some(workspace) = manifest_table
        .get("workspace")
        .and_then(toml::Value::as_table)
    else {
        diagnostics.push(Diagnostic::new(
            "WORKSPACE-SCHEMA",
            "Cargo.toml.workspace",
            "root manifest must declare [workspace]",
        ));
        return diagnostics;
    };
    let static_policy_valid = validate_workspace_package(root, workspace, &mut diagnostics)
        && validate_workspace_lints(workspace, &mut diagnostics)
        && validate_toolchain_file(root, &mut diagnostics)
        && validate_lockfile(root, &mut diagnostics)
        && validate_provenance_files(root, &mut diagnostics);
    if !static_policy_valid {
        diagnostics.sort_deterministically();
        return diagnostics;
    }

    let metadata = match cargo_metadata(root, &manifest_path, &mut diagnostics) {
        Some(metadata) => metadata,
        None => return diagnostics,
    };
    let Some(package_values) = metadata.get("packages").and_then(Value::as_array) else {
        diagnostics.push(Diagnostic::new(
            "WORKSPACE-METADATA",
            "Cargo.toml",
            "cargo metadata output has no packages array",
        ));
        return diagnostics;
    };
    let workspace_root = metadata
        .get("workspace_root")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .unwrap_or_else(|| root.to_path_buf());
    let package_ids = metadata
        .get("workspace_members")
        .and_then(Value::as_array)
        .map(|members| {
            members
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();

    let mut packages = Vec::new();
    let mut package_names = BTreeMap::<String, String>::new();
    let mut package_ids_by_name = BTreeMap::<String, String>::new();
    for package_value in package_values {
        let Some(package) = package_value.as_object() else {
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-METADATA",
                "Cargo.toml",
                "cargo metadata package entry is not an object",
            ));
            continue;
        };
        let Some(name) = package.get("name").and_then(Value::as_str) else {
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-METADATA",
                "Cargo.toml.packages",
                "package entry is missing a name",
            ));
            continue;
        };
        let Some(id) = package.get("id").and_then(Value::as_str) else {
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-METADATA",
                format!("package {name}"),
                "package entry is missing an id",
            ));
            continue;
        };
        let Some(path) = package.get("manifest_path").and_then(Value::as_str) else {
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-METADATA",
                format!("package {name}"),
                "package entry is missing manifest_path",
            ));
            continue;
        };
        let path = PathBuf::from(path);
        let display = display_path(root, &path);
        let role = role_for_manifest(root, &path);
        if role == Role::Unknown {
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-BOUNDARY",
                display.clone(),
                "workspace member is outside the declared architecture boundaries",
            ));
        }
        if let Some(previous) = package_names.insert(name.to_owned(), display.clone()) {
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-METADATA",
                display.clone(),
                format!("duplicate package name {name:?}; first appears at {previous}"),
            ));
        }
        package_ids_by_name.insert(name.to_owned(), id.to_owned());
        let package = Package {
            name: name.to_owned(),
            id: id.to_owned(),
            manifest_path: path,
            role,
            object: package.clone(),
        };
        validate_package(root, &package, workspace, &mut diagnostics);
        if !package_ids.is_empty() && !package_ids.contains(id) {
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-METADATA",
                display,
                "package is listed by cargo metadata but not workspace_members",
            ));
        }
        packages.push(package);
    }
    if packages.is_empty() {
        diagnostics.push(Diagnostic::new(
            "WORKSPACE-METADATA",
            "Cargo.toml.workspace.members",
            "workspace must contain at least one package",
        ));
    }
    validate_member_manifest_set(root, workspace, &packages, &mut diagnostics);
    validate_lock_packages(root, &packages, &mut diagnostics);
    validate_dependencies(
        root,
        &metadata,
        &packages,
        &package_ids_by_name,
        &mut diagnostics,
    );
    validate_standalone_product(root, &packages, &mut diagnostics);
    diagnostics.sort_deterministically();
    let _ = workspace_root;
    diagnostics
}

fn validate_workspace_package(
    root: &Path,
    workspace: &toml::map::Map<String, toml::Value>,
    diagnostics: &mut Diagnostics,
) -> bool {
    let mut valid = true;
    let Some(package) = workspace.get("package").and_then(toml::Value::as_table) else {
        diagnostics.push(Diagnostic::new(
            "WORKSPACE-INHERITANCE",
            "Cargo.toml.workspace.package",
            "root workspace must declare [workspace.package]",
        ));
        return false;
    };
    for field in INHERITED_PACKAGE_FIELDS {
        let path = format!("Cargo.toml.workspace.package.{field}");
        if package.get(field).is_none() {
            valid = false;
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-INHERITANCE",
                path,
                "required shared package metadata is missing",
            ));
        }
    }
    for (field, expected) in [
        ("edition", "2024"),
        ("rust-version", REQUIRED_TOOLCHAIN_CHANNEL),
        ("license", "Apache-2.0"),
        ("repository", "https://github.com/OlegSotnikov/jmeter-rs"),
    ] {
        if package.get(field).and_then(toml::Value::as_str) != Some(expected) {
            valid = false;
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-INHERITANCE",
                format!("Cargo.toml.workspace.package.{field}"),
                format!("must be the pinned workspace value {expected:?}"),
            ));
        }
    }
    if package.get("publish").and_then(toml::Value::as_bool) != Some(false) {
        valid = false;
        diagnostics.push(Diagnostic::new(
            "WORKSPACE-INHERITANCE",
            "Cargo.toml.workspace.package.publish",
            "the workspace is internal-only and must set publish = false",
        ));
    }
    if let Some(members) = workspace.get("members").and_then(toml::Value::as_array) {
        if members.is_empty() {
            valid = false;
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-SCHEMA",
                "Cargo.toml.workspace.members",
                "must not be empty",
            ));
        }
        for (position, member) in members.iter().enumerate() {
            let Some(member) = member.as_str() else {
                valid = false;
                diagnostics.push(Diagnostic::new(
                    "WORKSPACE-SCHEMA",
                    format!("Cargo.toml.workspace.members[{position}]"),
                    "workspace member paths must be strings",
                ));
                continue;
            };
            if Path::new(member).is_absolute()
                || Path::new(member).components().any(|component| {
                    matches!(
                        component,
                        std::path::Component::ParentDir | std::path::Component::RootDir
                    )
                })
            {
                valid = false;
                diagnostics.push(Diagnostic::new(
                    "WORKSPACE-PATH",
                    format!("Cargo.toml.workspace.members[{position}]"),
                    "workspace member path must be relative and free of traversal",
                ));
            }
            if !member.contains('*') && !root.join(member).join("Cargo.toml").is_file() {
                valid = false;
                diagnostics.push(Diagnostic::new(
                    "WORKSPACE-PATH",
                    format!("Cargo.toml.workspace.members[{position}]"),
                    "workspace member path must contain Cargo.toml",
                ));
            }
        }
    } else {
        valid = false;
        diagnostics.push(Diagnostic::new(
            "WORKSPACE-SCHEMA",
            "Cargo.toml.workspace.members",
            "must be an array of member paths",
        ));
    }
    if let Some(members) = workspace.get("members").and_then(toml::Value::as_array) {
        let declared = members
            .iter()
            .filter_map(toml::Value::as_str)
            .collect::<BTreeSet<_>>();
        for required in REQUIRED_WORKSPACE_MEMBERS {
            if !declared.contains(required) {
                valid = false;
                diagnostics.push(Diagnostic::new(
                    "WORKSPACE-SCHEMA",
                    "Cargo.toml.workspace.members",
                    format!("required architecture member {required:?} is missing"),
                ));
            }
        }
    }
    valid
}

fn validate_workspace_lints(
    workspace: &toml::map::Map<String, toml::Value>,
    diagnostics: &mut Diagnostics,
) -> bool {
    let mut valid = true;
    let Some(lints) = workspace.get("lints").and_then(toml::Value::as_table) else {
        diagnostics.push(Diagnostic::new(
            "WORKSPACE-LINT",
            "Cargo.toml.workspace.lints",
            "root workspace must declare [workspace.lints]",
        ));
        return false;
    };
    for table_name in ["rust", "clippy"] {
        if !lints.contains_key(table_name) {
            valid = false;
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-LINT",
                format!("Cargo.toml.workspace.lints.{table_name}"),
                "workspace lint policy table is missing",
            ));
        }
    }
    let Some(rust) = lints.get("rust").and_then(toml::Value::as_table) else {
        return false;
    };
    let Some(clippy) = lints.get("clippy").and_then(toml::Value::as_table) else {
        return false;
    };
    for (name, expected) in [
        ("unsafe_code", "deny"),
        ("missing_docs", "warn"),
        ("unused_must_use", "deny"),
    ] {
        if lint_level(rust.get(name)) != Some(expected) {
            valid = false;
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-LINT",
                format!("Cargo.toml.workspace.lints.rust.{name}"),
                format!("must set the workspace lint level to {expected:?}"),
            ));
        }
    }
    if lint_level(rust.get("rust_2018_idioms")) != Some("deny") {
        valid = false;
        diagnostics.push(Diagnostic::new(
            "WORKSPACE-LINT",
            "Cargo.toml.workspace.lints.rust.rust_2018_idioms",
            "must set the workspace lint level to \"deny\"",
        ));
    }
    for (name, expected) in [
        ("unwrap_used", "warn"),
        ("expect_used", "warn"),
        ("panic", "warn"),
        ("todo", "deny"),
        ("unimplemented", "deny"),
    ] {
        if lint_level(clippy.get(name)) != Some(expected) {
            valid = false;
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-LINT",
                format!("Cargo.toml.workspace.lints.clippy.{name}"),
                format!("must set the workspace lint level to {expected:?}"),
            ));
        }
    }
    valid
}

fn lint_level(value: Option<&toml::Value>) -> Option<&str> {
    match value {
        Some(toml::Value::String(level)) => Some(level.as_str()),
        Some(toml::Value::Table(table)) => table.get("level").and_then(toml::Value::as_str),
        _ => None,
    }
}

fn validate_toolchain_file(root: &Path, diagnostics: &mut Diagnostics) -> bool {
    let path = root.join(TOOLCHAIN_FILE);
    let display = display_path(root, &path);
    let Some(document) = read_toml_document(&path, diagnostics, "toolchain file") else {
        return false;
    };
    let Some(toolchain) = document.get("toolchain").and_then(toml::Value::as_table) else {
        diagnostics.push(Diagnostic::new(
            "WORKSPACE-TOOLCHAIN",
            format!("{display}.toolchain"),
            "pinned rust-toolchain.toml must declare a [toolchain] table",
        ));
        return false;
    };
    let mut valid = true;
    if toolchain.get("channel").and_then(toml::Value::as_str) != Some(REQUIRED_TOOLCHAIN_CHANNEL) {
        valid = false;
        diagnostics.push(Diagnostic::new(
            "WORKSPACE-TOOLCHAIN",
            format!("{display}.toolchain.channel"),
            format!("must pin the reviewed stable Rust toolchain {REQUIRED_TOOLCHAIN_CHANNEL:?}"),
        ));
    }
    if toolchain.get("profile").and_then(toml::Value::as_str) != Some(REQUIRED_TOOLCHAIN_PROFILE) {
        valid = false;
        diagnostics.push(Diagnostic::new(
            "WORKSPACE-TOOLCHAIN",
            format!("{display}.toolchain.profile"),
            format!("must use the bounded {REQUIRED_TOOLCHAIN_PROFILE:?} profile"),
        ));
    }
    let components = toolchain
        .get("components")
        .and_then(toml::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(toml::Value::as_str)
                .collect::<BTreeSet<_>>()
        });
    let Some(components) = components else {
        valid = false;
        diagnostics.push(Diagnostic::new(
            "WORKSPACE-TOOLCHAIN",
            format!("{display}.toolchain.components"),
            "must explicitly list rustfmt and clippy",
        ));
        return valid;
    };
    for component in REQUIRED_TOOLCHAIN_COMPONENTS {
        if !components.contains(component) {
            valid = false;
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-TOOLCHAIN",
                format!("{display}.toolchain.components"),
                format!("required toolchain component {component:?} is missing"),
            ));
        }
    }
    valid
}

fn validate_lockfile(root: &Path, diagnostics: &mut Diagnostics) -> bool {
    let path = root.join(LOCKFILE);
    let display = display_path(root, &path);
    let Some(document) = read_toml_document(&path, diagnostics, "Cargo.lock") else {
        return false;
    };
    let mut valid = true;
    if document.get("version").and_then(toml::Value::as_integer) != Some(4) {
        valid = false;
        diagnostics.push(Diagnostic::new(
            "WORKSPACE-LOCK",
            format!("{display}.version"),
            "Cargo.lock must use lockfile format version 4",
        ));
    }
    let Some(packages) = document.get("package").and_then(toml::Value::as_array) else {
        diagnostics.push(Diagnostic::new(
            "WORKSPACE-LOCK",
            format!("{display}.package"),
            "Cargo.lock must contain a non-empty package array",
        ));
        return false;
    };
    if packages.is_empty() {
        valid = false;
        diagnostics.push(Diagnostic::new(
            "WORKSPACE-LOCK",
            format!("{display}.package"),
            "Cargo.lock must contain at least one package record",
        ));
    }
    for (index, package) in packages.iter().enumerate() {
        let context = format!("{display}.package[{index}]");
        let Some(package) = package.as_table() else {
            valid = false;
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-LOCK",
                context,
                "Cargo.lock package entries must be tables",
            ));
            continue;
        };
        if package.get("name").and_then(toml::Value::as_str).is_none()
            || package
                .get("version")
                .and_then(toml::Value::as_str)
                .is_none()
        {
            valid = false;
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-LOCK",
                context.clone(),
                "Cargo.lock package entries require name and version",
            ));
        }
        if let Some(source) = package.get("source").and_then(toml::Value::as_str) {
            if source != ALLOWED_REGISTRY_SOURCE {
                valid = false;
                diagnostics.push(Diagnostic::new(
                    "WORKSPACE-LOCK",
                    format!("{context}.source"),
                    "Cargo.lock may use only the pinned crates.io registry; Git and unknown registries are forbidden",
                ));
            }
            if package
                .get("checksum")
                .and_then(toml::Value::as_str)
                .is_none()
            {
                valid = false;
                diagnostics.push(Diagnostic::new(
                    "WORKSPACE-LOCK",
                    format!("{context}.checksum"),
                    "registry package records must carry a checksum",
                ));
            }
        }
    }
    valid
}

fn validate_provenance_files(root: &Path, diagnostics: &mut Diagnostics) -> bool {
    let mut valid = true;
    for relative in ["LICENSE", "NOTICE", PROVENANCE_DOCUMENT] {
        let path = root.join(relative);
        let Some(text) = read_text_file(&path, diagnostics, "provenance file") else {
            valid = false;
            continue;
        };
        if text.trim().is_empty() {
            valid = false;
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-PROVENANCE",
                relative,
                "required release provenance file must not be empty",
            ));
        }
    }
    let provenance = root.join(PROVENANCE_DOCUMENT);
    if let Some(text) = read_text_file(&provenance, diagnostics, "provenance file") {
        let lower = text.to_ascii_lowercase();
        for marker in ["cargo.lock", "license", "source"] {
            if !lower.contains(marker) {
                valid = false;
                diagnostics.push(Diagnostic::new(
                    "WORKSPACE-PROVENANCE",
                    PROVENANCE_DOCUMENT,
                    format!("provenance ledger must record {marker}"),
                ));
            }
        }
    }
    valid
}

fn read_toml_document(
    path: &Path,
    diagnostics: &mut Diagnostics,
    description: &str,
) -> Option<toml::Table> {
    let text = read_text_file(path, diagnostics, description)?;
    match text.parse::<toml::Table>() {
        Ok(table) => Some(table),
        Err(error) => {
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-TOML",
                path.to_string_lossy().replace('\\', "/"),
                format!("invalid {description} TOML: {error}"),
            ));
            None
        }
    }
}

fn read_text_file(path: &Path, diagnostics: &mut Diagnostics, description: &str) -> Option<String> {
    let display = path.to_string_lossy().replace('\\', "/");
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-IO",
                display,
                format!("cannot inspect {description}: {error}"),
            ));
            return None;
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        diagnostics.push(Diagnostic::new(
            "WORKSPACE-PATH",
            display,
            format!("{description} must be a regular non-symlink file"),
        ));
        return None;
    }
    if metadata.len() > MAX_CARGO_MANIFEST_BYTES {
        diagnostics.push(Diagnostic::new(
            "WORKSPACE-BOUNDS",
            display,
            format!("{description} exceeds {MAX_CARGO_MANIFEST_BYTES}-byte bound"),
        ));
        return None;
    }
    match fs::read_to_string(path) {
        Ok(text) => Some(text),
        Err(error) => {
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-IO",
                path.to_string_lossy().replace('\\', "/"),
                format!("cannot read {description}: {error}"),
            ));
            None
        }
    }
}

fn cargo_metadata(
    root: &Path,
    manifest_path: &Path,
    diagnostics: &mut Diagnostics,
) -> Option<Value> {
    let cargo_path = resolve_build_tool(
        option_env!("XTASK_BUILD_CARGO"),
        "Cargo",
        "cargo",
        diagnostics,
    )?;
    let rustc_path =
        resolve_optional_build_tool(option_env!("XTASK_BUILD_RUSTC"), "rustc", diagnostics);
    let cargo_bin = cargo_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();
    let mut path_entries = vec![cargo_bin.clone()];
    if let Some(rustc_path) = rustc_path.as_deref()
        && let Some(rustc_bin) = rustc_path.parent()
        && rustc_bin != cargo_bin
    {
        path_entries.push(rustc_bin.to_path_buf());
    }
    let path_value = match env::join_paths(path_entries) {
        Ok(value) => value,
        Err(error) => {
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-METADATA",
                "Cargo.toml",
                format!("cannot construct the restricted Cargo PATH: {error}"),
            ));
            return None;
        }
    };
    let cargo_home = cargo_bin
        .file_name()
        .filter(|name| *name == "bin")
        .and_then(|_| cargo_bin.parent())
        .filter(|path| path.is_dir())
        .map(Path::to_path_buf);
    let rustup_home = cargo_home
        .as_deref()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .filter(|path| path.join("rustup").is_dir());
    let manifest_path = if manifest_path.is_absolute() {
        manifest_path.to_path_buf()
    } else {
        root.join(manifest_path)
    };
    let mut command = Command::new(&cargo_path);
    command
        .env_clear()
        .arg("metadata")
        .arg("--format-version")
        .arg("1")
        .arg("--no-deps")
        .arg("--locked")
        .arg("--manifest-path")
        .arg(manifest_path)
        .arg("--config")
        .arg("net.offline=true")
        .current_dir(Path::new("/"))
        .env("CARGO_NET_OFFLINE", "true")
        .env("CARGO_TERM_COLOR", "never")
        .env("PATH", path_value)
        .env("RUST_BACKTRACE", "0");
    if let Some(cargo_home) = cargo_home {
        command.env("CARGO_HOME", cargo_home);
    }
    if let Some(rustup_home) = rustup_home {
        command.env("RUSTUP_HOME", rustup_home);
    }
    if let Some(rustc_path) = rustc_path {
        command.env("RUSTC", rustc_path);
    }
    let mut child = match command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-METADATA",
                "Cargo.toml",
                format!("cannot execute cargo metadata (validation is fail-closed): {error}"),
            ));
            return None;
        }
    };
    let stdout = take_reader(&mut child, true, diagnostics);
    let stderr = take_reader(&mut child, false, diagnostics);
    let Some(status) = wait_for_metadata_child(&mut child, diagnostics) else {
        join_reader(stdout, "stdout", diagnostics);
        join_reader(stderr, "stderr", diagnostics);
        return None;
    };
    let stdout = join_reader(stdout, "stdout", diagnostics)?;
    let stderr = join_reader(stderr, "stderr", diagnostics)?;
    if !status.success() {
        let stderr = String::from_utf8_lossy(&stderr).trim().to_owned();
        diagnostics.push(Diagnostic::new(
            "WORKSPACE-METADATA",
            "Cargo.toml",
            format!("cargo metadata failed (validation is fail-closed): {stderr}"),
        ));
        return None;
    }
    match serde_json::from_slice(&stdout) {
        Ok(value) => Some(value),
        Err(error) => {
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-METADATA",
                "Cargo.toml",
                format!("cargo metadata returned invalid JSON: {error}"),
            ));
            None
        }
    }
}

fn resolve_build_tool(
    anchor: Option<&str>,
    tool: &str,
    expected_name: &str,
    diagnostics: &mut Diagnostics,
) -> Option<PathBuf> {
    let Some(anchor) = anchor else {
        diagnostics.push(Diagnostic::new(
            "WORKSPACE-METADATA",
            "Cargo.toml",
            format!("trusted {tool} path is unavailable; workspace validation is fail-closed"),
        ));
        return None;
    };
    let path = PathBuf::from(anchor);
    if !path.is_absolute() || path.file_name().and_then(|name| name.to_str()) != Some(expected_name)
    {
        diagnostics.push(Diagnostic::new(
            "WORKSPACE-METADATA",
            "Cargo.toml",
            format!("trusted {tool} path must be an absolute {expected_name:?} executable"),
        ));
        return None;
    }
    let canonical = match fs::canonicalize(&path) {
        Ok(canonical) => canonical,
        Err(error) => {
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-METADATA",
                "Cargo.toml",
                format!("cannot resolve trusted {tool} path: {error}"),
            ));
            return None;
        }
    };
    if !is_executable_file(&canonical) {
        diagnostics.push(Diagnostic::new(
            "WORKSPACE-METADATA",
            "Cargo.toml",
            format!("trusted {tool} path is not an executable file"),
        ));
        return None;
    }
    Some(path)
}

fn resolve_optional_build_tool(
    anchor: Option<&str>,
    tool: &str,
    diagnostics: &mut Diagnostics,
) -> Option<PathBuf> {
    let anchor = anchor?;
    let path = PathBuf::from(anchor);
    if !path.is_absolute() || path.file_name().and_then(|name| name.to_str()) != Some(tool) {
        diagnostics.push(Diagnostic::new(
            "WORKSPACE-METADATA",
            "Cargo.toml",
            format!("trusted {tool} path must be an absolute executable"),
        ));
        return None;
    }
    let canonical = match fs::canonicalize(&path) {
        Ok(canonical) => canonical,
        Err(error) => {
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-METADATA",
                "Cargo.toml",
                format!("cannot resolve trusted {tool} path: {error}"),
            ));
            return None;
        }
    };
    if !is_executable_file(&canonical) {
        diagnostics.push(Diagnostic::new(
            "WORKSPACE-METADATA",
            "Cargo.toml",
            format!("trusted {tool} path is not an executable file"),
        ));
        return None;
    }
    Some(path)
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn wait_for_metadata_child(child: &mut Child, diagnostics: &mut Diagnostics) -> Option<ExitStatus> {
    let deadline = Instant::now() + Duration::from_secs(CARGO_METADATA_TIMEOUT_SECONDS);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if Instant::now() >= deadline => {
                diagnostics.push(Diagnostic::new(
                    "WORKSPACE-METADATA",
                    "Cargo.toml",
                    format!(
                        "cargo metadata exceeded the {}-second bound",
                        CARGO_METADATA_TIMEOUT_SECONDS
                    ),
                ));
                if let Err(error) = child.kill() {
                    diagnostics.push(Diagnostic::new(
                        "WORKSPACE-METADATA",
                        "Cargo.toml",
                        format!("cannot stop timed-out cargo metadata child: {error}"),
                    ));
                }
                if let Err(error) = child.wait() {
                    diagnostics.push(Diagnostic::new(
                        "WORKSPACE-METADATA",
                        "Cargo.toml",
                        format!("cannot reap timed-out cargo metadata child: {error}"),
                    ));
                }
                return None;
            }
            Ok(None) => thread::sleep(Duration::from_millis(CARGO_METADATA_POLL_MILLISECONDS)),
            Err(error) => {
                diagnostics.push(Diagnostic::new(
                    "WORKSPACE-METADATA",
                    "Cargo.toml",
                    format!("cannot poll cargo metadata child: {error}"),
                ));
                if let Err(wait_error) = child.wait() {
                    diagnostics.push(Diagnostic::new(
                        "WORKSPACE-METADATA",
                        "Cargo.toml",
                        format!("cannot reap cargo metadata child: {wait_error}"),
                    ));
                }
                return None;
            }
        }
    }
}

fn take_reader(
    child: &mut Child,
    stdout: bool,
    diagnostics: &mut Diagnostics,
) -> Option<MetadataReader> {
    let reader = if stdout {
        child
            .stdout
            .take()
            .map(|reader| Box::new(reader) as Box<dyn Read + Send>)
    } else {
        child
            .stderr
            .take()
            .map(|reader| Box::new(reader) as Box<dyn Read + Send>)
    };
    let Some(reader) = reader else {
        diagnostics.push(Diagnostic::new(
            "WORKSPACE-METADATA",
            "Cargo.toml",
            if stdout {
                "cargo metadata did not provide a stdout pipe"
            } else {
                "cargo metadata did not provide a stderr pipe"
            },
        ));
        return None;
    };
    Some(thread::spawn(move || read_bounded(reader)))
}

fn join_reader(
    reader: Option<MetadataReader>,
    stream: &str,
    diagnostics: &mut Diagnostics,
) -> Option<Vec<u8>> {
    let reader = reader?;
    match reader.join() {
        Ok((bytes, truncated, error)) => {
            if let Some(error) = error {
                diagnostics.push(Diagnostic::new(
                    "WORKSPACE-METADATA",
                    "Cargo.toml",
                    format!("cannot read cargo metadata {stream}: {error}"),
                ));
            }
            if truncated {
                diagnostics.push(Diagnostic::new(
                    "WORKSPACE-METADATA",
                    "Cargo.toml",
                    format!(
                        "cargo metadata stream exceeded {}-byte bound",
                        MAX_CARGO_METADATA_OUTPUT_BYTES
                    ),
                ));
            }
            Some(bytes)
        }
        Err(_) => {
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-METADATA",
                "Cargo.toml",
                "cargo metadata output reader panicked",
            ));
            None
        }
    }
}

fn read_bounded(mut reader: Box<dyn Read + Send>) -> (Vec<u8>, bool, Option<String>) {
    let mut output = Vec::new();
    let mut block = [0_u8; 8192];
    let mut truncated = false;
    loop {
        match reader.read(&mut block) {
            Ok(0) => break,
            Ok(count) => {
                let remaining = MAX_CARGO_METADATA_OUTPUT_BYTES.saturating_sub(output.len());
                if count > remaining {
                    output.extend_from_slice(&block[..remaining]);
                    truncated = true;
                } else {
                    output.extend_from_slice(&block[..count]);
                }
            }
            Err(error) => {
                return (output, truncated, Some(error.to_string()));
            }
        }
    }
    (output, truncated, None)
}

fn validate_package(
    root: &Path,
    package: &Package,
    workspace: &toml::map::Map<String, toml::Value>,
    diagnostics: &mut Diagnostics,
) {
    let display = display_path(root, &package.manifest_path);
    let manifest = match read_toml(&package.manifest_path, diagnostics) {
        Some(manifest) => manifest,
        None => return,
    };
    let Some(manifest_table) = manifest.as_table() else {
        diagnostics.push(Diagnostic::new(
            "WORKSPACE-SCHEMA",
            display,
            "member manifest must be a TOML table",
        ));
        return;
    };
    let Some(package_table) = manifest_table
        .get("package")
        .and_then(toml::Value::as_table)
    else {
        diagnostics.push(Diagnostic::new(
            "WORKSPACE-INHERITANCE",
            format!("{display}.package"),
            "member manifest must declare [package]",
        ));
        return;
    };
    for field in INHERITED_PACKAGE_FIELDS {
        let inherited = package_table
            .get(field)
            .and_then(toml::Value::as_table)
            .and_then(|table| table.get("workspace"))
            .and_then(toml::Value::as_bool)
            == Some(true);
        if !inherited {
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-INHERITANCE",
                format!("{display}.package.{field}"),
                "must use the shared workspace value (`workspace = true`)",
            ));
        }
        if workspace
            .get("package")
            .and_then(toml::Value::as_table)
            .and_then(|table| table.get(field))
            .is_none()
        {
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-INHERITANCE",
                format!("Cargo.toml.workspace.package.{field}"),
                "member inherits a field that is absent at the workspace root",
            ));
        }
    }
    let lints_inherited = manifest_table
        .get("lints")
        .and_then(toml::Value::as_table)
        .and_then(|table| table.get("workspace"))
        .and_then(toml::Value::as_bool)
        == Some(true);
    if !lints_inherited {
        diagnostics.push(Diagnostic::new(
            "WORKSPACE-LINT",
            format!("{display}.lints.workspace"),
            "member must inherit the workspace lint policy",
        ));
    }

    let metadata_edition = package
        .object
        .get("targets")
        .and_then(Value::as_array)
        .and_then(|targets| targets.first())
        .and_then(Value::as_object)
        .and_then(|target| target.get("edition"))
        .and_then(Value::as_str);
    let workspace_edition = workspace
        .get("package")
        .and_then(toml::Value::as_table)
        .and_then(|table| table.get("edition"))
        .and_then(toml::Value::as_str);
    if metadata_edition != workspace_edition {
        diagnostics.push(Diagnostic::new(
            "WORKSPACE-METADATA",
            format!("{display}.package.edition"),
            format!("resolved edition {metadata_edition:?} does not match workspace {workspace_edition:?}"),
        ));
    }
    for (metadata_field, workspace_field) in [
        ("rust_version", "rust-version"),
        ("license", "license"),
        ("repository", "repository"),
        ("description", "description"),
        ("authors", "authors"),
        ("publish", "publish"),
    ] {
        let actual = package.object.get(metadata_field);
        let expected = workspace
            .get("package")
            .and_then(toml::Value::as_table)
            .and_then(|table| table.get(workspace_field));
        if let (Some(actual), Some(expected)) = (actual, expected)
            && !metadata_values_equal(actual, expected)
        {
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-METADATA",
                format!("{display}.package.{workspace_field}"),
                "resolved package metadata does not match workspace.package",
            ));
        }
    }
}

fn validate_member_manifest_set(
    root: &Path,
    workspace: &toml::map::Map<String, toml::Value>,
    packages: &[Package],
    diagnostics: &mut Diagnostics,
) {
    let declared = workspace
        .get("members")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(toml::Value::as_str)
        .map(|member| root.join(member).to_string_lossy().replace('\\', "/"))
        .collect::<BTreeSet<_>>();
    let actual = packages
        .iter()
        .map(|package| {
            package
                .manifest_path
                .parent()
                .unwrap_or(Path::new("."))
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect::<BTreeSet<_>>();
    // Cargo permits globs in members.  Explicit member paths are compared
    // exactly; a glob remains a declared pattern but cannot hide a discovered
    // package outside the listed architecture roots.
    for package in packages {
        let directory = package
            .manifest_path
            .parent()
            .unwrap_or(Path::new("."))
            .to_string_lossy()
            .replace('\\', "/");
        if !declared.contains(&directory)
            && !declared.contains(&package.manifest_path.to_string_lossy().replace('\\', "/"))
        {
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-METADATA",
                display_path(root, &package.manifest_path),
                "package discovered by Cargo is not represented by workspace.members",
            ));
        }
    }
    for declared_member in declared.iter().filter(|member| !member.contains('*')) {
        if !actual.contains(declared_member) {
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-METADATA",
                declared_member.clone(),
                "workspace member path does not resolve to a Cargo package",
            ));
        }
    }
}

fn validate_lock_packages(root: &Path, packages: &[Package], diagnostics: &mut Diagnostics) {
    let path = root.join(LOCKFILE);
    let Some(document) = read_toml_document(&path, diagnostics, "Cargo.lock") else {
        return;
    };
    let Some(lock_packages) = document.get("package").and_then(toml::Value::as_array) else {
        return;
    };
    let lock_names = lock_packages
        .iter()
        .filter_map(toml::Value::as_table)
        .filter_map(|package| package.get("name").and_then(toml::Value::as_str))
        .collect::<BTreeSet<_>>();
    for package in packages {
        if !lock_names.contains(package.name.as_str()) {
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-LOCK",
                display_path(root, &package.manifest_path),
                format!(
                    "workspace package {:?} is absent from the pinned Cargo.lock",
                    package.name
                ),
            ));
        }
    }
}

fn validate_standalone_product(root: &Path, packages: &[Package], diagnostics: &mut Diagnostics) {
    let applications = packages
        .iter()
        .filter(|package| package.role == Role::App)
        .collect::<Vec<_>>();
    if applications.len() != 1 {
        diagnostics.push(Diagnostic::new(
            "WORKSPACE-STANDALONE",
            STANDALONE_APP_MANIFEST,
            "workspace must contain exactly one user-facing application package",
        ));
        return;
    }
    let application = applications[0];
    if application.name != "jmeter-rs" {
        diagnostics.push(Diagnostic::new(
            "WORKSPACE-STANDALONE",
            display_path(root, &application.manifest_path),
            "the standalone application package must be named \"jmeter-rs\"",
        ));
    }
    validate_standalone_targets(root, application, diagnostics);
    validate_standalone_manifest(root, application, diagnostics);
    validate_standalone_dependency_closure(root, application, packages, diagnostics);
    validate_standalone_artifacts(root, diagnostics);
}

fn validate_standalone_targets(root: &Path, application: &Package, diagnostics: &mut Diagnostics) {
    let display = display_path(root, &application.manifest_path);
    let Some(targets) = application.object.get("targets").and_then(Value::as_array) else {
        diagnostics.push(Diagnostic::new(
            "WORKSPACE-STANDALONE",
            format!("{display}.targets"),
            "standalone application metadata must expose its targets",
        ));
        return;
    };
    let mut binaries = Vec::new();
    for target in targets {
        let Some(target) = target.as_object() else {
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-STANDALONE",
                format!("{display}.targets"),
                "standalone target metadata entries must be objects",
            ));
            continue;
        };
        let kinds = target
            .get("kind")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect::<BTreeSet<_>>();
        if kinds.contains("custom-build") {
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-STANDALONE",
                format!("{display}.targets"),
                "standalone application must not declare a build-script target",
            ));
        }
        if kinds.contains("bin") {
            binaries.push(target);
        }
    }
    if binaries.len() != 1 {
        diagnostics.push(Diagnostic::new(
            "WORKSPACE-STANDALONE",
            format!("{display}.targets"),
            "standalone application must expose exactly one binary target",
        ));
        return;
    }
    let binary = binaries[0];
    let name = binary.get("name").and_then(Value::as_str);
    let expected_source = root
        .join(STANDALONE_MAIN_SOURCE)
        .to_string_lossy()
        .replace('\\', "/");
    let source = binary
        .get("src_path")
        .and_then(Value::as_str)
        .map(|path| path.replace('\\', "/"));
    if name != Some("jmeter-rs") || source.as_deref() != Some(expected_source.as_str()) {
        diagnostics.push(Diagnostic::new(
            "WORKSPACE-STANDALONE",
            format!("{display}.targets"),
            "the default standalone binary must be jmeter-rs at apps/jmeter-rs/src/main.rs",
        ));
    }
    if application
        .object
        .get("links")
        .is_some_and(|value| !value.is_null())
    {
        diagnostics.push(Diagnostic::new(
            "WORKSPACE-STANDALONE",
            format!("{display}.package.links"),
            "standalone application must not declare a native linkage sidecar",
        ));
    }
}

fn validate_standalone_manifest(root: &Path, application: &Package, diagnostics: &mut Diagnostics) {
    let display = display_path(root, &application.manifest_path);
    let Some(manifest) =
        read_toml_document(&application.manifest_path, diagnostics, "Cargo manifest")
    else {
        return;
    };
    if manifest.get("build").is_some() {
        diagnostics.push(Diagnostic::new(
            "WORKSPACE-STANDALONE",
            format!("{display}.package.build"),
            "standalone application must not use a build script that can emit a helper sidecar",
        ));
    }
    if manifest.get("default-run").is_some()
        && manifest.get("default-run").and_then(toml::Value::as_str) != Some("jmeter-rs")
    {
        diagnostics.push(Diagnostic::new(
            "WORKSPACE-STANDALONE",
            format!("{display}.default-run"),
            "the only default application binary must be jmeter-rs",
        ));
    }
    for section_name in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(section) = manifest.get(section_name).and_then(toml::Value::as_table) {
            let allowed = match section_name {
                "dependencies" => &STANDALONE_RUNTIME_PATH_DEPENDENCIES[..],
                "dev-dependencies" => &STANDALONE_DEV_PATH_DEPENDENCIES[..],
                _ => &[][..],
            };
            let allowed_registry = match section_name {
                "dev-dependencies" => &STANDALONE_DEV_REGISTRY_DEPENDENCIES[..],
                _ => &[][..],
            };
            check_standalone_manifest_dependencies(
                section,
                allowed,
                allowed_registry,
                &format!("{display}.{section_name}"),
                diagnostics,
            );
        }
    }
    if manifest.get("target").is_some() {
        diagnostics.push(Diagnostic::new(
            "WORKSPACE-STANDALONE",
            format!("{display}.target"),
            "standalone application must not add target-specific helper or compatibility dependencies",
        ));
    }
    if let Some(features) = manifest.get("features").and_then(toml::Value::as_table) {
        for (feature_name, values) in features {
            if let Some(values) = values.as_array() {
                for (index, value) in values.iter().enumerate() {
                    if let Some(value) = value.as_str()
                        && forbidden_standalone_dependency_name(value)
                    {
                        diagnostics.push(Diagnostic::new(
                            "WORKSPACE-STANDALONE",
                            format!("{display}.features.{feature_name}[{index}]"),
                            "standalone features must not activate a compatibility-pack dependency",
                        ));
                    }
                }
            } else {
                diagnostics.push(Diagnostic::new(
                    "WORKSPACE-STANDALONE",
                    format!("{display}.features.{feature_name}"),
                    "standalone feature values must be arrays",
                ));
            }
        }
    }
}

fn check_standalone_manifest_dependencies(
    dependencies: &toml::map::Map<String, toml::Value>,
    allowed: &[(&str, &str)],
    allowed_registry: &[(&str, &str)],
    display: &str,
    diagnostics: &mut Diagnostics,
) {
    for (declared_name, dependency) in dependencies {
        let context = format!("{display}.{declared_name}");
        let package_name = dependency
            .as_table()
            .and_then(|table| table.get("package"))
            .and_then(toml::Value::as_str)
            .unwrap_or(declared_name);
        let expected_path = allowed
            .iter()
            .find(|(name, _)| *name == package_name)
            .map(|(_, path)| *path);
        let expected_registry_version = allowed_registry
            .iter()
            .find(|(name, _)| *name == package_name)
            .map(|(_, version)| *version);
        if expected_path.is_none() && expected_registry_version.is_none() {
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-STANDALONE",
                context.clone(),
                format!(
                    "standalone dependency {package_name:?} is outside the closed native allowlist"
                ),
            ));
        }
        let Some(table) = dependency.as_table() else {
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-STANDALONE",
                context,
                "standalone dependencies must use explicit path tables",
            ));
            continue;
        };
        if let Some(path) = expected_path {
            if table.get("path").and_then(toml::Value::as_str) != Some(path) {
                diagnostics.push(Diagnostic::new(
                    "WORKSPACE-STANDALONE",
                    format!("{display}.{declared_name}.path"),
                    format!("native dependency {package_name:?} must use path {path:?}"),
                ));
            }
        } else if let Some(version) = expected_registry_version {
            if table.get("path").is_some() {
                diagnostics.push(Diagnostic::new(
                    "WORKSPACE-STANDALONE",
                    format!("{display}.{declared_name}.path"),
                    format!("dev-only registry dependency {package_name:?} must not use a path"),
                ));
            }
            if table.get("version").and_then(toml::Value::as_str) != Some(version) {
                diagnostics.push(Diagnostic::new(
                    "WORKSPACE-STANDALONE",
                    format!("{display}.{declared_name}.version"),
                    format!(
                        "dev-only registry dependency {package_name:?} must use version {version:?}"
                    ),
                ));
            }
            if table.get("default-features").and_then(toml::Value::as_bool) != Some(false) {
                diagnostics.push(Diagnostic::new(
                    "WORKSPACE-STANDALONE",
                    format!("{display}.{declared_name}.default-features"),
                    format!("dev-only registry dependency {package_name:?} must disable default features"),
                ));
            }
        }
        if table.get("git").is_some() || table.get("registry").is_some() {
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-STANDALONE",
                format!("{display}.{declared_name}"),
                "standalone dependencies must not come from Git or a registry",
            ));
        }
        if table.get("optional").and_then(toml::Value::as_bool) == Some(true) {
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-STANDALONE",
                format!("{display}.{declared_name}.optional"),
                "standalone dependencies must not be optional compatibility switches",
            ));
        }
        if table.get("default-features").and_then(toml::Value::as_bool) == Some(true) {
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-STANDALONE",
                format!("{display}.{declared_name}.default-features"),
                "standalone dependencies must not explicitly enable default features",
            ));
        }
    }
}

fn forbidden_standalone_dependency_name(name: &str) -> bool {
    let normalized = name.replace('_', "-").to_ascii_lowercase();
    [
        "java-bridge",
        "plugin-host",
        "process-supervision",
        "jmeter-oracle",
    ]
    .iter()
    .any(|forbidden| normalized == *forbidden || normalized.ends_with(&format!("-{forbidden}")))
}

fn validate_standalone_dependency_closure(
    root: &Path,
    application: &Package,
    packages: &[Package],
    diagnostics: &mut Diagnostics,
) {
    let package_by_path = packages
        .iter()
        .filter_map(|package| {
            package
                .manifest_path
                .parent()
                .map(|path| (path.to_string_lossy().replace('\\', "/"), package))
        })
        .collect::<BTreeMap<_, _>>();
    let package_by_name = packages
        .iter()
        .map(|package| (package.name.as_str(), package))
        .collect::<BTreeMap<_, _>>();
    let mut queue = vec![application];
    let mut visited = BTreeSet::new();
    while let Some(package) = queue.pop() {
        if !visited.insert(package.id.as_str()) {
            continue;
        }
        let Some(dependencies) = package.object.get("dependencies").and_then(Value::as_array)
        else {
            continue;
        };
        for dependency in dependencies {
            let Some(dependency) = dependency.as_object() else {
                diagnostics.push(Diagnostic::new(
                    "WORKSPACE-STANDALONE",
                    display_path(root, &package.manifest_path),
                    "dependency metadata entry must be an object",
                ));
                continue;
            };
            if dependency.get("kind").and_then(Value::as_str) == Some("dev") {
                continue;
            }
            let dependency_name = dependency.get("name").and_then(Value::as_str);
            let target = dependency
                .get("path")
                .and_then(Value::as_str)
                .map(|path| path.replace('\\', "/"))
                .and_then(|path| package_by_path.get(&path).copied())
                .or_else(|| dependency_name.and_then(|name| package_by_name.get(name).copied()));
            let Some(target) = target else {
                continue;
            };
            if STANDALONE_FORBIDDEN_ROLES.contains(&target.role)
                || forbidden_standalone_dependency_name(&target.name)
            {
                diagnostics.push(Diagnostic::new(
                    "WORKSPACE-STANDALONE",
                    format!(
                        "{}.dependencies.{}",
                        display_path(root, &package.manifest_path),
                        dependency_name.unwrap_or("<unknown>")
                    ),
                    format!(
                        "standalone binary dependency closure reaches forbidden package {:?}",
                        target.name
                    ),
                ));
            }
            queue.push(target);
        }
    }
}

fn validate_standalone_artifacts(root: &Path, diagnostics: &mut Diagnostics) {
    let source_root = root.join(STANDALONE_APP_SOURCE);
    let metadata = match fs::symlink_metadata(&source_root) {
        Ok(metadata) => metadata,
        Err(error) => {
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-STANDALONE",
                STANDALONE_APP_SOURCE,
                format!("cannot inspect standalone source tree: {error}"),
            ));
            return;
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        diagnostics.push(Diagnostic::new(
            "WORKSPACE-STANDALONE",
            STANDALONE_APP_SOURCE,
            "standalone source tree must be a regular directory, not a symlink",
        ));
        return;
    }
    let mut files = Vec::new();
    collect_standalone_files(&source_root, 0, &mut files, diagnostics);
    for path in files {
        let size = match fs::metadata(&path) {
            Ok(metadata) => metadata.len(),
            Err(error) => {
                diagnostics.push(Diagnostic::new(
                    "WORKSPACE-IO",
                    display_path(root, &path),
                    format!("cannot inspect standalone source size: {error}"),
                ));
                continue;
            }
        };
        if size > MAX_CARGO_MANIFEST_BYTES {
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-BOUNDS",
                display_path(root, &path),
                format!("standalone source file exceeds {MAX_CARGO_MANIFEST_BYTES}-byte bound"),
            ));
            continue;
        }
        if let Some(extension) = path.extension().and_then(OsStr::to_str)
            && STANDALONE_FORBIDDEN_EXTENSIONS
                .iter()
                .any(|expected| extension.eq_ignore_ascii_case(expected))
        {
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-STANDALONE",
                display_path(root, &path),
                format!(
                    "standalone source must not carry compatibility-pack artifact {extension:?}"
                ),
            ));
        }
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) => {
                diagnostics.push(Diagnostic::new(
                    "WORKSPACE-IO",
                    display_path(root, &path),
                    format!("cannot read standalone source for sidecar scan: {error}"),
                ));
                continue;
            }
        };
        let source = String::from_utf8_lossy(&bytes);
        for marker in STANDALONE_FORBIDDEN_SOURCE_MARKERS {
            if source.contains(marker) {
                diagnostics.push(Diagnostic::new(
                    "WORKSPACE-STANDALONE",
                    display_path(root, &path),
                    format!(
                        "standalone source must not probe or spawn compatibility sidecar marker {marker:?}"
                    ),
                ));
            }
        }
    }
}

fn collect_standalone_files(
    directory: &Path,
    depth: usize,
    files: &mut Vec<PathBuf>,
    diagnostics: &mut Diagnostics,
) {
    if depth > MAX_STANDALONE_DIRECTORY_DEPTH {
        diagnostics.push(Diagnostic::new(
            "WORKSPACE-BOUNDS",
            directory.to_string_lossy().replace('\\', "/"),
            format!("standalone source directory depth exceeds {MAX_STANDALONE_DIRECTORY_DEPTH}"),
        ));
        return;
    }
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) => {
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-IO",
                directory.to_string_lossy().replace('\\', "/"),
                format!("cannot inspect standalone source directory: {error}"),
            ));
            return;
        }
    };
    let mut paths = Vec::new();
    for entry in entries {
        match entry {
            Ok(entry) => paths.push(entry.path()),
            Err(error) => diagnostics.push(Diagnostic::new(
                "WORKSPACE-IO",
                directory.to_string_lossy().replace('\\', "/"),
                format!("cannot inspect standalone source entry: {error}"),
            )),
        }
    }
    paths.sort();
    for path in paths {
        if files.len() >= MAX_STANDALONE_FILES {
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-BOUNDS",
                directory.to_string_lossy().replace('\\', "/"),
                format!("standalone source file count exceeds {MAX_STANDALONE_FILES}"),
            ));
            return;
        }
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) => {
                diagnostics.push(Diagnostic::new(
                    "WORKSPACE-IO",
                    path.to_string_lossy().replace('\\', "/"),
                    format!("cannot inspect standalone source entry: {error}"),
                ));
                continue;
            }
        };
        if metadata.file_type().is_symlink() {
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-STANDALONE",
                path.to_string_lossy().replace('\\', "/"),
                "standalone source must not use symlinked files",
            ));
        } else if metadata.is_dir() {
            collect_standalone_files(&path, depth + 1, files, diagnostics);
        } else if metadata.is_file() {
            files.push(path);
        } else {
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-STANDALONE",
                path.to_string_lossy().replace('\\', "/"),
                "standalone source contains a non-regular entry",
            ));
        }
    }
}

fn validate_dependencies(
    root: &Path,
    metadata: &Value,
    packages: &[Package],
    package_ids_by_name: &BTreeMap<String, String>,
    diagnostics: &mut Diagnostics,
) {
    let package_by_name = packages
        .iter()
        .map(|package| (package.name.as_str(), package))
        .collect::<BTreeMap<_, _>>();
    let package_by_id = packages
        .iter()
        .map(|package| (package.id.as_str(), package))
        .collect::<BTreeMap<_, _>>();
    let resolve_edges = resolve_edge_map(metadata);
    for package in packages {
        let Some(dependencies) = package.object.get("dependencies").and_then(Value::as_array)
        else {
            continue;
        };
        let display = display_path(root, &package.manifest_path);
        for (position, dependency) in dependencies.iter().enumerate() {
            let Some(dependency) = dependency.as_object() else {
                diagnostics.push(Diagnostic::new(
                    "WORKSPACE-DEPENDENCY",
                    format!("{display}.dependencies[{position}]"),
                    "metadata dependency entry is not an object",
                ));
                continue;
            };
            let Some(dependency_name) = dependency.get("name").and_then(Value::as_str) else {
                continue;
            };
            let kind = dependency
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or("normal");
            if dependency.get("req").and_then(Value::as_str) == Some("*") {
                diagnostics.push(Diagnostic::new(
                    "WORKSPACE-DEPENDENCY",
                    format!("{display}.dependencies.{dependency_name}"),
                    "wildcard dependency requirements are not reproducible",
                ));
            }
            let target = resolve_edges
                .get(&(package.id.clone(), dependency_name.to_owned()))
                .and_then(|target_id| package_by_id.get(target_id.as_str()).copied())
                .or_else(|| {
                    let path_dependency =
                        dependency.get("source").map(Value::is_null).unwrap_or(true);
                    if path_dependency {
                        package_by_name.get(dependency_name).copied()
                    } else {
                        None
                    }
                });
            let Some(target) = target else {
                continue;
            };
            let allowed = allowed_edge(package.role, target.role, kind);
            if !allowed {
                diagnostics.push(Diagnostic::new(
                    "WORKSPACE-DEPENDENCY",
                    format!("{display}.dependencies.{dependency_name}"),
                    format!(
                        "{} ({:?}) may not depend on {} ({:?}) as a {kind} dependency",
                        package.name, package.role, target.name, target.role
                    ),
                ));
            }
            if is_pure_core(package.role) && forbidden_core_dependency(dependency_name) {
                diagnostics.push(Diagnostic::new(
                    "WORKSPACE-DEPENDENCY",
                    format!("{display}.dependencies.{dependency_name}"),
                    "pure core crates must not directly depend on Tokio, HTTP clients, JVM bindings, or filesystem adapters",
                ));
            }
        }
    }
    let _ = package_ids_by_name;
}

fn resolve_edge_map(metadata: &Value) -> BTreeMap<(String, String), String> {
    let mut edges = BTreeMap::new();
    let Some(nodes) = metadata
        .get("resolve")
        .and_then(|value| value.get("nodes"))
        .and_then(Value::as_array)
    else {
        return edges;
    };
    for node in nodes {
        let Some(node) = node.as_object() else {
            continue;
        };
        let Some(node_id) = node.get("id").and_then(Value::as_str) else {
            continue;
        };
        let Some(deps) = node.get("deps").and_then(Value::as_array) else {
            continue;
        };
        for dependency in deps {
            let Some(dependency) = dependency.as_object() else {
                continue;
            };
            let Some(name) = dependency.get("name").and_then(Value::as_str) else {
                continue;
            };
            let Some(package_id) = dependency.get("pkg").and_then(Value::as_str) else {
                continue;
            };
            edges.insert((node_id.to_owned(), name.to_owned()), package_id.to_owned());
        }
    }
    edges
}

fn allowed_edge(source: Role, target: Role, kind: &str) -> bool {
    if target == Role::Observe {
        return true;
    }
    if kind == "dev" {
        return target == Role::TestSupport
            || (source != Role::HttpNative && allowed_edge(source, target, "normal"));
    }
    if target == Role::TestSupport {
        return matches!(source, Role::OracleTool | Role::Xtask);
    }
    match source {
        Role::App => !matches!(target, Role::OracleTool | Role::Xtask),
        Role::OracleTool | Role::Xtask => true,
        Role::Model | Role::Results | Role::Observe => false,
        Role::Jmx | Role::Expr => target == Role::Model,
        Role::Runtime => matches!(target, Role::Model | Role::Expr | Role::Results),
        Role::Http | Role::Report => matches!(target, Role::Runtime | Role::Results),
        Role::HttpNative => target == Role::Http,
        Role::Remote => matches!(target, Role::Runtime | Role::Results | Role::BridgeProtocol),
        Role::BridgeProtocol => matches!(target, Role::Model | Role::Results),
        Role::JavaBridge | Role::PluginHost => {
            matches!(
                target,
                Role::Runtime | Role::Results | Role::BridgeProtocol | Role::ProcessSupervision
            )
        }
        Role::ProcessSupervision => false,
        Role::TestSupport | Role::Unknown => false,
    }
}

fn is_pure_core(role: Role) -> bool {
    matches!(role, Role::Model | Role::Jmx | Role::Expr | Role::Results)
}

fn forbidden_core_dependency(name: &str) -> bool {
    matches!(
        name,
        "tokio"
            | "reqwest"
            | "hyper"
            | "ureq"
            | "isahc"
            | "jni"
            | "j4rs"
            | "java-bindings"
            | "openssl"
    )
}

fn role_for_manifest(root: &Path, manifest: &Path) -> Role {
    let relative = manifest
        .strip_prefix(root)
        .unwrap_or(manifest)
        .to_string_lossy()
        .replace('\\', "/");
    match relative.as_str() {
        "apps/jmeter-rs/Cargo.toml" => Role::App,
        "crates/model/Cargo.toml" => Role::Model,
        "crates/jmx/Cargo.toml" => Role::Jmx,
        "crates/expr/Cargo.toml" => Role::Expr,
        "crates/runtime/Cargo.toml" => Role::Runtime,
        "crates/results/Cargo.toml" => Role::Results,
        "crates/http/Cargo.toml" => Role::Http,
        "crates/http-native/Cargo.toml" => Role::HttpNative,
        "crates/report/Cargo.toml" => Role::Report,
        "crates/remote/Cargo.toml" => Role::Remote,
        "crates/bridge-protocol/Cargo.toml" => Role::BridgeProtocol,
        "crates/java-bridge/Cargo.toml" => Role::JavaBridge,
        "crates/plugin-host/Cargo.toml" => Role::PluginHost,
        "crates/observe/Cargo.toml" => Role::Observe,
        "crates/test-support/Cargo.toml" => Role::TestSupport,
        "crates/process-supervision/Cargo.toml" => Role::ProcessSupervision,
        "tools/jmeter-oracle/Cargo.toml" => Role::OracleTool,
        "tools/xtask/Cargo.toml" => Role::Xtask,
        _ => Role::Unknown,
    }
}

fn metadata_values_equal(actual: &Value, expected: &toml::Value) -> bool {
    match (actual, expected) {
        (Value::String(actual), toml::Value::String(expected)) => actual == expected,
        (Value::Array(actual), toml::Value::Array(expected)) => {
            actual.len() == expected.len()
                && actual
                    .iter()
                    .zip(expected)
                    .all(|(actual, expected)| metadata_values_equal(actual, expected))
        }
        (Value::Array(actual), toml::Value::Boolean(false)) => actual.is_empty(),
        (Value::Bool(actual), toml::Value::Boolean(expected)) => actual == expected,
        (Value::Number(actual), toml::Value::Integer(expected)) => {
            actual.as_i64() == Some(*expected)
        }
        (Value::Number(actual), toml::Value::Float(expected)) => actual.as_f64() == Some(*expected),
        (Value::Null, toml::Value::String(expected)) => expected.is_empty(),
        _ => false,
    }
}

fn read_toml(path: &Path, diagnostics: &mut Diagnostics) -> Option<toml::Value> {
    let display = path.to_string_lossy().replace('\\', "/");
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-IO",
                display,
                format!("cannot inspect Cargo manifest: {error}"),
            ));
            return None;
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        diagnostics.push(Diagnostic::new(
            "WORKSPACE-PATH",
            display,
            "Cargo manifest must be a regular non-symlink file",
        ));
        return None;
    }
    if metadata.len() > MAX_CARGO_MANIFEST_BYTES {
        diagnostics.push(Diagnostic::new(
            "WORKSPACE-BOUNDS",
            display,
            format!("Cargo manifest exceeds {MAX_CARGO_MANIFEST_BYTES}-byte bound"),
        ));
        return None;
    }
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) => {
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-IO",
                path.to_string_lossy().replace('\\', "/"),
                format!("cannot read Cargo manifest: {error}"),
            ));
            return None;
        }
    };
    // TOML 1.1's `Value` parser is intentionally a value parser and rejects a
    // document containing a table header. Parse the document as a Table and
    // wrap it so the rest of the validator can use the stable Value API.
    match text.parse::<toml::Table>() {
        Ok(value) => Some(toml::Value::Table(value)),
        Err(error) => {
            diagnostics.push(Diagnostic::new(
                "WORKSPACE-TOML",
                path.to_string_lossy().replace('\\', "/"),
                format!("invalid Cargo manifest TOML: {error}"),
            ));
            None
        }
    }
}

fn display_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_CARGO_METADATA_OUTPUT_BYTES, REQUIRED_WORKSPACE_MEMBERS, Role,
        STANDALONE_DEV_REGISTRY_DEPENDENCIES, STANDALONE_FORBIDDEN_ROLES,
        STANDALONE_RUNTIME_PATH_DEPENDENCIES, allowed_edge, forbidden_core_dependency,
        forbidden_standalone_dependency_name, read_bounded, role_for_manifest, validate_lockfile,
        validate_standalone_artifacts, validate_standalone_dependency_closure,
        validate_toolchain_file,
    };

    #[test]
    fn native_http_role_and_workspace_membership_are_explicit() {
        let root = std::path::Path::new("/workspace");
        assert_eq!(
            role_for_manifest(root, &root.join("crates/http-native/Cargo.toml")),
            Role::HttpNative
        );
        assert!(REQUIRED_WORKSPACE_MEMBERS.contains(&"crates/http-native"));
        assert_eq!(STANDALONE_DEV_REGISTRY_DEPENDENCIES, [("rcgen", "=0.14.9")]);
        assert_eq!(
            STANDALONE_RUNTIME_PATH_DEPENDENCIES
                .iter()
                .find(|(name, _)| *name == "jmeter-rs-http"),
            Some(&("jmeter-rs-http", "../../crates/http"))
        );
        assert_eq!(
            STANDALONE_RUNTIME_PATH_DEPENDENCIES
                .iter()
                .find(|(name, _)| *name == "jmeter-rs-http-native"),
            Some(&("jmeter-rs-http-native", "../../crates/http-native"))
        );
    }

    #[test]
    fn native_http_dependency_direction_is_closed() {
        assert!(allowed_edge(Role::HttpNative, Role::Http, "normal"));
        assert!(allowed_edge(Role::HttpNative, Role::Observe, "normal"));
        assert!(!allowed_edge(Role::HttpNative, Role::Http, "dev"));
        assert!(!allowed_edge(Role::HttpNative, Role::Runtime, "normal"));
        assert!(!allowed_edge(Role::HttpNative, Role::Results, "normal"));
        assert!(!allowed_edge(Role::HttpNative, Role::JavaBridge, "normal"));
        assert!(!allowed_edge(
            Role::HttpNative,
            Role::ProcessSupervision,
            "normal"
        ));
    }

    #[test]
    fn standalone_closure_rejects_jvm_and_process_roles() {
        use serde_json::json;
        use std::path::PathBuf;

        let root = PathBuf::from("/workspace");
        let app_manifest = root.join("apps/jmeter-rs/Cargo.toml");
        let mut dependencies = Vec::new();
        let mut packages = Vec::new();
        for (index, (name, role, directory)) in [
            (
                "jmeter-rs-java-bridge",
                Role::JavaBridge,
                "crates/java-bridge",
            ),
            (
                "jmeter-rs-plugin-host",
                Role::PluginHost,
                "crates/plugin-host",
            ),
            (
                "jmeter-rs-process-supervision",
                Role::ProcessSupervision,
                "crates/process-supervision",
            ),
            (
                "jmeter-rs-jmeter-oracle",
                Role::OracleTool,
                "tools/jmeter-oracle",
            ),
        ]
        .into_iter()
        .enumerate()
        {
            dependencies.push(json!({"name": name}));
            packages.push(super::Package {
                name: name.to_owned(),
                id: format!("package-{index}"),
                manifest_path: root.join(directory).join("Cargo.toml"),
                role,
                object: serde_json::Map::new(),
            });
        }
        let mut application_object = serde_json::Map::new();
        application_object.insert("dependencies".to_owned(), json!(dependencies));
        let application = super::Package {
            name: "jmeter-rs".to_owned(),
            id: "application".to_owned(),
            manifest_path: app_manifest,
            role: Role::App,
            object: application_object,
        };
        packages.push(application.clone());
        let mut diagnostics = super::Diagnostics::default();
        validate_standalone_dependency_closure(&root, &application, &packages, &mut diagnostics);
        assert_eq!(diagnostics.len(), STANDALONE_FORBIDDEN_ROLES.len());
        for role in STANDALONE_FORBIDDEN_ROLES {
            assert!(packages.iter().any(|package| package.role == role));
        }
    }

    #[test]
    fn dependency_direction_keeps_protocols_out_of_pure_core() {
        assert!(allowed_edge(Role::Runtime, Role::Model, "normal"));
        assert!(allowed_edge(
            Role::JavaBridge,
            Role::BridgeProtocol,
            "normal"
        ));
        assert!(allowed_edge(
            Role::JavaBridge,
            Role::ProcessSupervision,
            "normal"
        ));
        assert!(allowed_edge(
            Role::PluginHost,
            Role::ProcessSupervision,
            "normal"
        ));
        assert!(allowed_edge(
            Role::OracleTool,
            Role::ProcessSupervision,
            "normal"
        ));
        assert!(!allowed_edge(
            Role::ProcessSupervision,
            Role::Runtime,
            "normal"
        ));
        assert!(!allowed_edge(Role::Model, Role::Runtime, "normal"));
        assert!(!allowed_edge(Role::Runtime, Role::TestSupport, "normal"));
        assert!(allowed_edge(Role::Runtime, Role::TestSupport, "dev"));
        assert!(!allowed_edge(Role::App, Role::TestSupport, "normal"));
        assert!(!allowed_edge(Role::App, Role::Xtask, "normal"));
    }

    #[test]
    fn pure_core_forbids_effectful_direct_dependencies() {
        assert!(forbidden_core_dependency("tokio"));
        assert!(forbidden_core_dependency("reqwest"));
        assert!(!forbidden_core_dependency("serde"));
    }

    #[test]
    fn cargo_metadata_reader_is_bounded_while_draining() {
        use std::io::Cursor;

        let source = vec![b'x'; MAX_CARGO_METADATA_OUTPUT_BYTES + 1];
        let (bytes, truncated, error) = read_bounded(Box::new(Cursor::new(source)));
        assert_eq!(bytes.len(), MAX_CARGO_METADATA_OUTPUT_BYTES);
        assert!(truncated);
        assert!(error.is_none());
    }

    #[test]
    fn pinned_toolchain_policy_rejects_unreviewed_channel() {
        use std::fs;
        use std::sync::atomic::{AtomicUsize, Ordering};

        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "jmeter-rs-xtask-toolchain-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        assert!(fs::create_dir_all(&root).is_ok());
        assert!(fs::write(
            root.join("rust-toolchain.toml"),
            "[toolchain]\nchannel = \"stable\"\nprofile = \"minimal\"\ncomponents = [\"rustfmt\", \"clippy\"]\n"
        )
        .is_ok());
        let mut diagnostics = super::Diagnostics::default();
        assert!(!validate_toolchain_file(&root, &mut diagnostics));
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "WORKSPACE-TOOLCHAIN"
                && diagnostic
                    .path
                    .ends_with("rust-toolchain.toml.toolchain.channel")
        }));
        assert!(fs::remove_dir_all(root).is_ok());
    }

    #[test]
    fn lockfile_policy_rejects_untrusted_source_and_missing_checksum() {
        use std::fs;
        use std::sync::atomic::{AtomicUsize, Ordering};

        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "jmeter-rs-xtask-lock-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        assert!(fs::create_dir_all(&root).is_ok());
        assert!(fs::write(
            root.join("Cargo.lock"),
            "version = 4\n\n[[package]]\nname = \"untrusted\"\nversion = \"1.0.0\"\nsource = \"git+https://example.invalid/repo\"\n"
        )
        .is_ok());
        let mut diagnostics = super::Diagnostics::default();
        assert!(!validate_lockfile(&root, &mut diagnostics));
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "WORKSPACE-LOCK" && diagnostic.path.ends_with(".source")
        }));
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "WORKSPACE-LOCK" && diagnostic.path.ends_with(".checksum")
        }));
        assert!(fs::remove_dir_all(root).is_ok());
    }

    #[test]
    fn standalone_policy_rejects_compatibility_names_and_embedded_pack_files() {
        use std::fs;
        use std::sync::atomic::{AtomicUsize, Ordering};

        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "jmeter-rs-xtask-standalone-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let source = root.join("apps/jmeter-rs/src");
        assert!(fs::create_dir_all(&source).is_ok());
        assert!(fs::write(source.join("compatibility.jar"), b"not a pack").is_ok());
        assert!(fs::write(source.join("main.rs"), b"Command::new(\"java\")").is_ok());
        assert!(forbidden_standalone_dependency_name(
            "jmeter-rs-java-bridge"
        ));
        assert!(forbidden_standalone_dependency_name(
            "jmeter_rs_plugin_host"
        ));
        assert!(!forbidden_standalone_dependency_name("jmeter-rs-runtime"));
        let mut diagnostics = super::Diagnostics::default();
        validate_standalone_artifacts(&root, &mut diagnostics);
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "WORKSPACE-STANDALONE"
                && diagnostic.path.ends_with("compatibility.jar")
        }));
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "WORKSPACE-STANDALONE" && diagnostic.path.ends_with("main.rs")
        }));
        assert!(fs::remove_dir_all(root).is_ok());
    }

    #[test]
    fn temporary_malformed_manifest_is_rejected() {
        use std::fs;
        use std::sync::atomic::{AtomicUsize, Ordering};

        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let directory = std::env::temp_dir().join(format!(
            "jmeter-rs-xtask-workspace-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let created = fs::create_dir_all(&directory);
        assert!(created.is_ok(), "create workspace tree: {created:?}");
        if created.is_err() {
            return;
        }
        let manifest = directory.join("Cargo.toml");
        let written = fs::write(&manifest, b"[workspace\n");
        assert!(written.is_ok(), "write invalid manifest: {written:?}");
        if written.is_err() {
            let _ = fs::remove_dir_all(directory);
            return;
        }
        let mut diagnostics = super::Diagnostics::default();
        let parsed = super::read_toml(&manifest, &mut diagnostics);
        assert!(parsed.is_none());
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "WORKSPACE-TOML")
        );
        let removed = fs::remove_dir_all(directory);
        assert!(removed.is_ok(), "remove workspace tree: {removed:?}");
    }

    #[test]
    fn member_inheritance_is_rejected_without_running_cargo() {
        use std::fs;
        use std::sync::atomic::{AtomicUsize, Ordering};

        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "jmeter-rs-xtask-workspace-member-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let member = root.join("crate");
        let created = fs::create_dir_all(&member);
        assert!(created.is_ok(), "create workspace member: {created:?}");
        if created.is_err() {
            return;
        }
        let root_manifest = r#"[workspace]
members = ["crate"]

[workspace.package]
version = "0.1.0"
edition = "2024"
rust-version = "1.97.1"
authors = ["test"]
license = "Apache-2.0"
repository = "https://example.invalid/test"
description = "temporary workspace"
publish = false

[workspace.lints.rust]
unsafe_code = "forbid"

[workspace.lints.clippy]
todo = "deny"
"#;
        let member_manifest = r#"[package]
name = "temporary-member"
version = "0.1.0"
edition = "2024"
"#;
        assert!(fs::write(root.join("Cargo.toml"), root_manifest).is_ok());
        assert!(fs::write(member.join("Cargo.toml"), member_manifest).is_ok());
        let root_value =
            super::read_toml(&root.join("Cargo.toml"), &mut super::Diagnostics::default());
        let workspace = root_value
            .and_then(|value| value.get("workspace").cloned())
            .and_then(|value| value.as_table().cloned());
        let package = super::Package {
            name: "temporary-member".to_owned(),
            id: "temporary-member 0.1.0 (path+file:///tmp/crate)".to_owned(),
            manifest_path: member.join("Cargo.toml"),
            role: super::Role::Unknown,
            object: serde_json::Map::new(),
        };
        let mut diagnostics = super::Diagnostics::default();
        if let Some(workspace) = workspace.as_ref() {
            super::validate_package(&root, &package, workspace, &mut diagnostics);
        }
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "WORKSPACE-INHERITANCE" || diagnostic.code == "WORKSPACE-LINT"
        }));
        assert!(fs::remove_dir_all(root).is_ok());
    }
}
