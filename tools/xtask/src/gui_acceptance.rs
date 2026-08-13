// SPDX-License-Identifier: Apache-2.0
//! Static acceptance gate for the Decision 0002 GUI boundary.
//!
//! This module intentionally has no process, JVM, GUI, network, or Cargo
//! execution path. It reads the checked-in GUI descriptors, verifies their
//! hashes and scope, and rejects the gate until per-lane evidence has a
//! dedicated GUI comparator and complete identity/provenance. The ordinary
//! fixture validator remains responsible for the generic fixture schemas;
//! this task owns the cross-case GUI acceptance invariants only.

use crate::diagnostics::{Diagnostic, Diagnostics};
use crate::profile::{ProfileIndex, display_path};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

const GUI_FEATURES: [&str; 3] = ["GUI-001", "GUI-002", "GUI-003"];
const GUI_FAMILY: &str = "FX-GUI-001";
const STANDALONE_PROJECTION: &str = "compat/capability-sets/standalone-native.json";
const GUI_BOUNDARIES: [&str; 3] = ["EXT-JVM-001", "EXT-PLUGIN-001", "EXT-OS-001"];
const DIRECT_BOUNDARIES: [&str; 2] = ["EXT-JVM-001", "EXT-OS-001"];
const TARGET_TRIPLES: [&str; 6] = [
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-pc-windows-msvc",
    "aarch64-pc-windows-msvc",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
];
const JAVA_MAJORS: [u64; 2] = [8, 17];
const GUI_ROUTES: [&str; 4] = [
    "gui-jmx-semantic",
    "gui-persistence",
    "gui-platform",
    "gui-capability-error",
];
const STATIC_DESCRIPTOR_ROUTE: &str = "static-descriptor";
const MAX_GUI_FILE_BYTES: u64 = 64 * 1024 * 1024;
const SHA256_HEX_LENGTH: usize = 64;

/// Run the GUI acceptance check against the supplied active profile.
pub(crate) fn check(
    root: &Path,
    fixtures_root: &Path,
    profile: &ProfileIndex,
    profile_path: &Path,
) -> Diagnostics {
    let mut diagnostics = Diagnostics::default();
    let gui_root = fixtures_root.join("gui-static");
    let profile_hash = hash_file(root, profile_path, "profile", &mut diagnostics);
    let lock_hash = hash_file(
        root,
        &root.join("Cargo.lock"),
        "Cargo.lock",
        &mut diagnostics,
    );

    validate_profile_scope(root, profile, &gui_root, &mut diagnostics);
    validate_standalone_projection(root, &mut diagnostics);

    let Some(case_dirs) = gui_case_dirs(root, &gui_root, &mut diagnostics) else {
        diagnostics.sort_deterministically();
        return diagnostics;
    };

    let mut seen_features = BTreeSet::new();
    let mut family_boundaries = BTreeSet::new();
    let mut routes = BTreeSet::new();
    let mut seen_case_ids = BTreeSet::new();
    let mut case_states = Vec::new();
    let mut platform_case = None;

    for case_dir in case_dirs {
        let case_path = case_dir.join("case.json");
        let case_display = display_path(root, &case_path);
        let Some(case) = read_json(root, &case_path, &mut diagnostics) else {
            continue;
        };
        let Some(case_object) = case.as_object() else {
            schema(
                &mut diagnostics,
                &case_display,
                "case manifest must be a JSON object",
            );
            continue;
        };
        let expected_path = case_object
            .get("execution")
            .and_then(Value::as_object)
            .and_then(|execution| execution.get("expected"))
            .and_then(Value::as_str)
            .map(|path| case_dir.join(path));
        let provenance_path = case_dir.join("provenance.json");
        let Some(provenance) = read_json(root, &provenance_path, &mut diagnostics) else {
            continue;
        };
        let Some(provenance_object) = provenance.as_object() else {
            schema(
                &mut diagnostics,
                &display_path(root, &provenance_path),
                "provenance must be a JSON object",
            );
            continue;
        };
        let Some(expected_path) = expected_path else {
            schema(
                &mut diagnostics,
                &format!("{case_display}.execution.expected"),
                "a single expected descriptor path is required",
            );
            continue;
        };
        let Some(expected) = read_json(root, &expected_path, &mut diagnostics) else {
            continue;
        };
        let Some(expected_object) = expected.as_object() else {
            schema(
                &mut diagnostics,
                &display_path(root, &expected_path),
                "expected descriptor must be a JSON object",
            );
            continue;
        };

        // A GUI descriptor is never an input to the standalone-native
        // projection.  Keep this prohibition at the acceptance boundary so a
        // future report cannot turn a static GUI row into native evidence by
        // merely copying its feature IDs.
        validate_standalone_exclusion(
            case_object,
            &format!("{case_display}.case"),
            &mut diagnostics,
        );
        validate_standalone_exclusion(
            expected_object,
            &format!("{case_display}.expected"),
            &mut diagnostics,
        );
        validate_standalone_exclusion(
            provenance_object,
            &format!("{case_display}.provenance"),
            &mut diagnostics,
        );

        let state = validate_case(
            root,
            &gui_root,
            &case_dir,
            case_object,
            provenance_object,
            expected_object,
            &case_display,
            &expected_path,
            profile,
            profile_hash.as_deref(),
            lock_hash.as_deref(),
            &mut diagnostics,
        );
        if let Some(state) = state {
            if !seen_case_ids.insert(state.case_id.clone()) {
                acceptance(
                    &mut diagnostics,
                    &case_display,
                    format!("duplicate GUI case_id {}", state.case_id),
                );
            }
            seen_features.extend(state.features.iter().cloned());
            family_boundaries.extend(state.boundaries.iter().cloned());
            routes.insert(state.route.to_owned());
            if state.is_platform {
                if platform_case.is_some() {
                    acceptance(
                        &mut diagnostics,
                        &case_display,
                        "exactly one GUI-003 platform-settings case is allowed",
                    );
                } else {
                    platform_case = Some((case_dir.clone(), case_object.clone()));
                }
            }
            case_states.push(state);
        }
    }

    let expected_features = GUI_FEATURES
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if seen_features != expected_features {
        acceptance(
            &mut diagnostics,
            &display_path(root, &gui_root),
            format!(
                "GUI feature coverage must be exactly {:?}, found {:?}",
                GUI_FEATURES, seen_features
            ),
        );
    }
    let expected_boundaries = GUI_BOUNDARIES
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if family_boundaries != expected_boundaries {
        acceptance(
            &mut diagnostics,
            &display_path(root, &gui_root),
            format!(
                "FX-GUI-001 boundary union must be {:?}, found {:?}",
                GUI_BOUNDARIES, family_boundaries
            ),
        );
    }
    let expected_routes = GUI_ROUTES
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if routes != expected_routes {
        acceptance(
            &mut diagnostics,
            &display_path(root, &gui_root),
            format!(
                "GUI route partition must be exactly {:?}, found {:?}",
                GUI_ROUTES, routes
            ),
        );
    }

    let platform_lanes_ready = if let Some((platform_dir, platform_case)) = platform_case {
        validate_platform_matrix(
            root,
            &platform_dir,
            &platform_case,
            profile_hash.as_deref(),
            lock_hash.as_deref(),
            &mut diagnostics,
        )
    } else {
        acceptance(
            &mut diagnostics,
            &display_path(root, &gui_root),
            "a GUI-003 platform-settings case is required",
        );
        false
    };

    validate_acceptance_readiness(
        root,
        &gui_root,
        &case_states,
        platform_lanes_ready,
        &mut diagnostics,
    );
    diagnostics.sort_deterministically();
    diagnostics
}

#[derive(Clone, Debug)]
struct CaseState {
    case_id: String,
    features: BTreeSet<String>,
    boundaries: BTreeSet<String>,
    route: &'static str,
    evidence_status: String,
    comparator_enforced: bool,
    is_platform: bool,
}

fn validate_profile_scope(
    root: &Path,
    profile: &ProfileIndex,
    gui_root: &Path,
    diagnostics: &mut Diagnostics,
) {
    for feature in GUI_FEATURES {
        if !profile.feature_ids.contains(feature) {
            acceptance(
                diagnostics,
                &display_path(root, gui_root),
                format!("active profile is missing required feature {feature}"),
            );
        }
    }
    // Decision 0002 also names TEST-005 as the cross-platform/performance
    // evidence boundary.  Check its profile references here so GUI-003 cannot
    // accidentally be treated as a substitute for the independent TEST-005
    // matrix.
    if !profile.feature_ids.contains("TEST-005") {
        acceptance(
            diagnostics,
            &display_path(root, gui_root),
            "active profile is missing required TEST-005 cross-platform evidence row",
        );
    }
    if !profile.fixture_ids.contains("FX-CROSS-PLATFORM-001") {
        acceptance(
            diagnostics,
            &display_path(root, gui_root),
            "active profile is missing FX-CROSS-PLATFORM-001 for TEST-005",
        );
    }
    if profile
        .feature_fixture_ids
        .get("TEST-005")
        .is_none_or(|fixtures| !fixtures.contains("FX-CROSS-PLATFORM-001"))
    {
        acceptance(
            diagnostics,
            &display_path(root, gui_root),
            "TEST-005 must require FX-CROSS-PLATFORM-001",
        );
    }
    let expected_feature_boundaries: BTreeMap<&str, BTreeSet<String>> = BTreeMap::from([
        (
            "GUI-001",
            ["EXT-JVM-001", "EXT-PLUGIN-001", "EXT-OS-001"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
        ),
        (
            "GUI-002",
            ["EXT-JVM-001", "EXT-OS-001"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
        ),
        (
            "GUI-003",
            ["EXT-JVM-001", "EXT-OS-001"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
        ),
    ]);
    for (feature, expected) in expected_feature_boundaries {
        if profile.feature_boundaries.get(feature) != Some(&expected) {
            acceptance(
                diagnostics,
                &display_path(root, gui_root),
                format!(
                    "active profile boundary scope for {feature} is not the Decision 0002 scope"
                ),
            );
        }
    }
    let expected_family = BTreeSet::from([
        "EXT-JVM-001".to_owned(),
        "EXT-PLUGIN-001".to_owned(),
        "EXT-OS-001".to_owned(),
    ]);
    if profile.fixture_boundaries.get(GUI_FAMILY) != Some(&expected_family) {
        acceptance(
            diagnostics,
            &display_path(root, gui_root),
            "active profile FX-GUI-001 boundary scope is not the Decision 0002 union",
        );
    }
}

fn validate_standalone_exclusion(
    object: &Map<String, Value>,
    path: &str,
    diagnostics: &mut Diagnostics,
) {
    // The standalone report is a separate projection (Decision 0009), not a
    // GUI-aware interpretation of these descriptors.  A descriptor may state
    // that it is excluded, but must never claim native support or a passing
    // standalone result.
    for field in [
        "standalone_status",
        "standalone_projection",
        "capability_set",
    ] {
        let Some(value) = object.get(field) else {
            continue;
        };
        let text = value
            .as_str()
            .map(str::to_owned)
            .or_else(|| value.get("name").and_then(Value::as_str).map(str::to_owned));
        if text.as_deref().is_some_and(|text| {
            text.eq_ignore_ascii_case("supported")
                || text.eq_ignore_ascii_case("verified")
                || text.eq_ignore_ascii_case("standalone-native")
        }) {
            acceptance(
                diagnostics,
                &format!("{path}.{field}"),
                "GUI descriptors cannot claim standalone-native support",
            );
        }
    }
    if object.get("standalone_native").and_then(Value::as_bool) == Some(true) {
        acceptance(
            diagnostics,
            &format!("{path}.standalone_native"),
            "GUI descriptors are excluded from the standalone-native projection",
        );
    }
}

fn validate_standalone_projection(root: &Path, diagnostics: &mut Diagnostics) {
    let path = root.join(STANDALONE_PROJECTION);
    let display = display_path(root, &path);
    let Some(value) = read_json(root, &path, diagnostics) else {
        return;
    };
    let Some(projection) = value.as_object() else {
        schema(
            diagnostics,
            &display,
            "standalone capability projection must be a JSON object",
        );
        return;
    };
    if projection.get("capability_set_id").and_then(Value::as_str) != Some("standalone-native") {
        acceptance(
            diagnostics,
            &display,
            "GUI acceptance requires the Decision 0009 standalone-native projection",
        );
    }
    let counts = projection.get("counts").and_then(Value::as_object);
    for field in ["promoted_parent_rows", "verified_parent_rows"] {
        if counts
            .and_then(|counts| counts.get(field))
            .and_then(Value::as_u64)
            != Some(0)
        {
            acceptance(
                diagnostics,
                &format!("{display}.counts.{field}"),
                "GUI rows cannot be promoted or counted as verified in standalone-native",
            );
        }
    }
    let gui_policy = projection
        .get("standalone_constraints")
        .and_then(Value::as_object)
        .and_then(|constraints| constraints.get("gui"))
        .and_then(Value::as_object);
    if gui_policy
        .and_then(|gui| gui.get("standalone_native_counted"))
        .and_then(Value::as_bool)
        != Some(false)
    {
        acceptance(
            diagnostics,
            &format!("{display}.standalone_constraints.gui.standalone_native_counted"),
            "GUI runtime must be explicitly excluded from standalone-native counts",
        );
    }

    let mut gui_feature_ids = BTreeSet::new();
    if let Some(features) = projection.get("features").and_then(Value::as_array) {
        for (index, value) in features.iter().enumerate() {
            let Some(feature) = value.as_object() else {
                continue;
            };
            let Some(id) = feature.get("id").and_then(Value::as_str) else {
                continue;
            };
            if !GUI_FEATURES.contains(&id) {
                continue;
            }
            gui_feature_ids.insert(id.to_owned());
            if feature.get("claim_status").and_then(Value::as_str) != Some("not-promoted") {
                acceptance(
                    diagnostics,
                    &format!("{display}.features[{index}].claim_status"),
                    "GUI feature rows cannot be promoted by standalone-native",
                );
            }
        }
    } else {
        schema(
            diagnostics,
            &format!("{display}.features"),
            "standalone-native feature rows are required",
        );
    }
    let expected_gui_features = GUI_FEATURES
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if gui_feature_ids != expected_gui_features {
        acceptance(
            diagnostics,
            &format!("{display}.features"),
            "standalone-native must retain all GUI rows without promoting them",
        );
    }

    if let Some(cases) = projection.get("cases").and_then(Value::as_array) {
        for (index, value) in cases.iter().enumerate() {
            let Some(case) = value.as_object() else {
                continue;
            };
            let Some(feature_id) = case.get("feature_id").and_then(Value::as_str) else {
                continue;
            };
            if !GUI_FEATURES.contains(&feature_id) {
                continue;
            }
            if case.get("claim_status").and_then(Value::as_str) != Some("not-promoted") {
                acceptance(
                    diagnostics,
                    &format!("{display}.cases[{index}].claim_status"),
                    "GUI cases cannot promote standalone-native compatibility",
                );
            }
            if case.get("partition").and_then(Value::as_str) == Some("native")
                && (case.get("capability_id").and_then(Value::as_str)
                    != Some("native.jmx.semantic@1")
                    || !case
                        .get("scope")
                        .and_then(Value::as_str)
                        .is_some_and(|scope| scope.to_ascii_lowercase().contains("headless")))
            {
                acceptance(
                    diagnostics,
                    &format!("{display}.cases[{index}]"),
                    "native GUI projection cases may cover only headless preservation, never GUI runtime",
                );
            }
        }
    } else {
        schema(
            diagnostics,
            &format!("{display}.cases"),
            "standalone-native case records are required",
        );
    }
}

fn gui_case_dirs(
    root: &Path,
    gui_root: &Path,
    diagnostics: &mut Diagnostics,
) -> Option<Vec<PathBuf>> {
    let metadata = match fs::symlink_metadata(gui_root) {
        Ok(metadata) => metadata,
        Err(error) => {
            io(
                diagnostics,
                &display_path(root, gui_root),
                format!("cannot inspect GUI fixture root: {error}"),
            );
            return None;
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        schema(
            diagnostics,
            &display_path(root, gui_root),
            "GUI fixture root must be a regular directory",
        );
        return None;
    }
    let mut directories = Vec::new();
    let entries = match fs::read_dir(gui_root) {
        Ok(entries) => entries,
        Err(error) => {
            io(
                diagnostics,
                &display_path(root, gui_root),
                format!("cannot enumerate GUI fixture root: {error}"),
            );
            return None;
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                io(
                    diagnostics,
                    &display_path(root, gui_root),
                    format!("cannot read GUI fixture entry: {error}"),
                );
                continue;
            }
        };
        let path = entry.path();
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            io(
                diagnostics,
                &display_path(root, &path),
                "cannot inspect GUI fixture entry",
            );
            continue;
        };
        if metadata.file_type().is_symlink() {
            schema(
                diagnostics,
                &display_path(root, &path),
                "GUI fixture case directory must not be a symlink",
            );
        } else if metadata.is_dir() {
            directories.push(path);
        }
    }
    directories.sort();
    if directories.is_empty() {
        acceptance(
            diagnostics,
            &display_path(root, gui_root),
            "GUI fixture root contains no case directories",
        );
        None
    } else {
        Some(directories)
    }
}

fn validate_case(
    root: &Path,
    gui_root: &Path,
    case_dir: &Path,
    case: &Map<String, Value>,
    provenance: &Map<String, Value>,
    expected: &Map<String, Value>,
    case_display: &str,
    expected_path: &Path,
    profile: &ProfileIndex,
    profile_hash: Option<&str>,
    lock_hash: Option<&str>,
    diagnostics: &mut Diagnostics,
) -> Option<CaseState> {
    let case_id = match string(case, "case_id", case_display, diagnostics) {
        Some(value) => value,
        None => return None,
    };
    let profile_id = string(case, "profile_id", case_display, diagnostics);
    if profile_id != Some(profile.profile_id.clone()) {
        acceptance(
            diagnostics,
            &format!("{case_display}.profile_id"),
            "case profile_id must match the active profile",
        );
    }
    if string(case, "fixture_family_id", case_display, diagnostics) != Some(GUI_FAMILY.to_owned()) {
        acceptance(
            diagnostics,
            &format!("{case_display}.fixture_family_id"),
            "GUI cases must belong to FX-GUI-001",
        );
    }
    let features = string_set(
        case.get("conformance_ids"),
        &format!("{case_display}.conformance_ids"),
        diagnostics,
    );
    if features.is_empty()
        || !features
            .iter()
            .all(|feature| GUI_FEATURES.contains(&feature.as_str()))
    {
        acceptance(
            diagnostics,
            &format!("{case_display}.conformance_ids"),
            "only GUI-001..GUI-003 are in Decision 0002 scope",
        );
    }
    if case.values().any(contains_forbidden_gui_004) {
        acceptance(
            diagnostics,
            case_display,
            "GUI-004 is outside the Decision 0002 scope and must not be declared",
        );
    }

    let boundaries = string_set(
        case.get("external_runtime_boundary_ids"),
        &format!("{case_display}.external_runtime_boundary_ids"),
        diagnostics,
    );
    let plugin_case = case_id.contains("PLUGIN-EDITOR") || boundaries.contains("EXT-PLUGIN-001");
    let expected_boundaries = if plugin_case {
        BTreeSet::from(GUI_BOUNDARIES.map(str::to_owned))
    } else {
        BTreeSet::from(DIRECT_BOUNDARIES.map(str::to_owned))
    };
    if boundaries != expected_boundaries {
        acceptance(
            diagnostics,
            &format!("{case_display}.external_runtime_boundary_ids"),
            format!(
                "case boundary set must be {:?}, found {:?}",
                expected_boundaries, boundaries
            ),
        );
    }
    for boundary in &boundaries {
        if !profile.boundary_ids.contains(boundary)
            || !features.iter().any(|feature| {
                profile
                    .feature_boundaries
                    .get(feature)
                    .is_some_and(|declared| declared.contains(boundary))
            })
        {
            acceptance(
                diagnostics,
                &format!("{case_display}.external_runtime_boundary_ids"),
                format!("boundary {boundary} is not declared by this case's profile feature scope"),
            );
        }
    }

    let input_hashes = validate_case_hashes(
        root,
        gui_root,
        case_dir,
        case,
        provenance,
        expected_path,
        case_display,
        diagnostics,
    );
    let route = expected_route(case_dir, &case_id);
    validate_route(expected, route, case_display, diagnostics);
    let evidence_status = validate_evidence_honesty(
        expected,
        provenance,
        route,
        &format!("{case_display}.execution.expected"),
        diagnostics,
    );
    let comparator_enforced = expected
        .get("validation_contract")
        .and_then(Value::as_object)
        .and_then(|contract| contract.get("comparator_enforced"))
        .and_then(Value::as_bool)
        .unwrap_or(false);

    if plugin_case {
        validate_plugin_case(case, expected, case_display, diagnostics);
    }
    validate_plan_path_hashes(
        case,
        expected,
        case_display,
        input_hashes.as_ref(),
        diagnostics,
    );
    let is_platform = features.contains("GUI-003")
        || case_dir
            .file_name()
            .is_some_and(|name| name == "platform-settings");
    if is_platform
        && case_dir
            .file_name()
            .is_none_or(|name| name != "platform-settings")
    {
        acceptance(
            diagnostics,
            case_display,
            "GUI-003 must use the platform-settings case directory",
        );
    }
    let _ = (profile_hash, lock_hash);
    Some(CaseState {
        case_id,
        features,
        boundaries,
        route,
        evidence_status,
        comparator_enforced,
        is_platform,
    })
}

fn validate_case_hashes(
    root: &Path,
    gui_root: &Path,
    case_dir: &Path,
    case: &Map<String, Value>,
    provenance: &Map<String, Value>,
    expected_path: &Path,
    case_display: &str,
    diagnostics: &mut Diagnostics,
) -> Option<BTreeMap<String, String>> {
    let mut hashes = BTreeMap::new();
    let inputs = match case.get("inputs").and_then(Value::as_array) {
        Some(inputs) => inputs,
        None => {
            schema(
                diagnostics,
                &format!("{case_display}.inputs"),
                "inputs must be an array of path/hash objects",
            );
            return None;
        }
    };
    for (index, item) in inputs.iter().enumerate() {
        let item_path = format!("{case_display}.inputs[{index}]");
        let Some(item) = item.as_object() else {
            schema(
                diagnostics,
                &item_path,
                "input declaration must be an object",
            );
            continue;
        };
        let Some(relative) = string(item, "path", &item_path, diagnostics) else {
            continue;
        };
        let Some(declared) = string(item, "sha256", &item_path, diagnostics) else {
            continue;
        };
        validate_digest(&declared, &format!("{item_path}.sha256"), diagnostics);
        let Some(path) =
            resolve_fixture_path(root, gui_root, case_dir, &relative, &item_path, diagnostics)
        else {
            continue;
        };
        if let Some(actual) = hash_file(root, &path, "fixture input", diagnostics) {
            if actual != declared {
                acceptance(
                    diagnostics,
                    &format!("{item_path}.sha256"),
                    format!("declared SHA-256 {declared} does not match actual {actual}"),
                );
            }
        }
        if hashes.insert(relative, declared).is_some() {
            acceptance(diagnostics, &item_path, "duplicate input path declaration");
        }
    }

    let Some(plan) = case.get("plan").and_then(Value::as_object) else {
        schema(
            diagnostics,
            &format!("{case_display}.plan"),
            "a plan path/hash object is required",
        );
        return Some(hashes);
    };
    let Some(plan_path) = string(plan, "path", &format!("{case_display}.plan"), diagnostics) else {
        return Some(hashes);
    };
    let plan_hash = string(plan, "sha256", &format!("{case_display}.plan"), diagnostics);
    if let Some(plan_hash) = plan_hash.as_deref() {
        validate_digest(
            plan_hash,
            &format!("{case_display}.plan.sha256"),
            diagnostics,
        );
        if hashes.get(&plan_path).map(String::as_str) != Some(plan_hash) {
            acceptance(
                diagnostics,
                &format!("{case_display}.plan.sha256"),
                "plan.sha256 must match the inputs declaration",
            );
        }
    }
    let expected_relative = expected_path
        .strip_prefix(case_dir)
        .ok()
        .and_then(|path| path.to_str())
        .map(str::to_owned);
    if let Some(expected_relative) = expected_relative.as_deref() {
        if !hashes.contains_key(expected_relative) {
            acceptance(
                diagnostics,
                &format!("{case_display}.inputs"),
                "execution.expected must be included in inputs with a hash",
            );
        }
    }

    let Some(provenance_inputs) = provenance.get("inputs").and_then(Value::as_object) else {
        schema(
            diagnostics,
            &format!("{case_display}.provenance.inputs"),
            "provenance inputs object is required",
        );
        return Some(hashes);
    };
    if let Some(plan_hash) = plan_hash.as_deref() {
        compare_provenance_hash(
            provenance_inputs,
            "plan_sha256",
            plan_hash,
            case_display,
            diagnostics,
        );
    }
    if let Some(expected_relative) = expected_relative
        .as_deref()
        .and_then(|path| hashes.get(path))
    {
        compare_provenance_hash(
            provenance_inputs,
            "expected_sha256",
            expected_relative,
            case_display,
            diagnostics,
        );
    }
    if let Some(properties) = case.get("property_files").and_then(Value::as_array) {
        if properties.len() == 1 {
            if let Some(property) = properties[0].as_object() {
                if let (Some(path), Some(hash)) = (
                    property.get("path").and_then(Value::as_str),
                    property.get("sha256").and_then(Value::as_str),
                ) {
                    if let Some(provenance_hash) = provenance_inputs
                        .get("property_sha256")
                        .and_then(Value::as_str)
                    {
                        if provenance_hash != hash {
                            acceptance(
                                diagnostics,
                                &format!("{case_display}.provenance.inputs.property_sha256"),
                                "property hash does not match case.property_files",
                            );
                        }
                    }
                    if hashes.get(path).map(String::as_str) != Some(hash) {
                        acceptance(
                            diagnostics,
                            &format!("{case_display}.property_files[0].sha256"),
                            "property hash must match inputs",
                        );
                    }
                }
            }
        }
    }
    Some(hashes)
}

fn compare_provenance_hash(
    provenance: &Map<String, Value>,
    field: &str,
    expected: &str,
    case_display: &str,
    diagnostics: &mut Diagnostics,
) {
    let path = format!("{case_display}.provenance.inputs.{field}");
    let Some(actual) = provenance.get(field).and_then(Value::as_str) else {
        schema(diagnostics, &path, "provenance hash is required");
        return;
    };
    validate_digest(actual, &path, diagnostics);
    if actual != expected {
        acceptance(diagnostics, &path, format!("must match {expected}"));
    }
}

fn validate_plan_path_hashes(
    case: &Map<String, Value>,
    expected: &Map<String, Value>,
    case_display: &str,
    input_hashes: Option<&BTreeMap<String, String>>,
    diagnostics: &mut Diagnostics,
) {
    let plan_hash = case
        .get("plan")
        .and_then(Value::as_object)
        .and_then(|plan| plan.get("sha256"))
        .and_then(Value::as_str);
    walk_plan_path_hashes(
        case,
        &format!("{case_display}.case"),
        plan_hash,
        true,
        input_hashes,
        diagnostics,
    );
    walk_plan_path_hashes(
        expected,
        &format!("{case_display}.expected"),
        plan_hash,
        true,
        input_hashes,
        diagnostics,
    );
}

fn walk_plan_path_hashes(
    value: &Map<String, Value>,
    path: &str,
    case_plan_hash: Option<&str>,
    required: bool,
    input_hashes: Option<&BTreeMap<String, String>>,
    diagnostics: &mut Diagnostics,
) {
    if let Some(plan_path) = value.get("plan_path") {
        let plan_path = plan_path.as_str();
        let hash = value.get("plan_sha256");
        if required && plan_path.is_some() && hash.is_none() {
            schema(
                diagnostics,
                path,
                "plan_path requires a sibling plan_sha256",
            );
        }
        if let Some(hash) = hash {
            if !hash.is_null() {
                if let Some(hash) = hash.as_str() {
                    validate_digest(hash, &format!("{path}.plan_sha256"), diagnostics);
                    if let Some(case_plan_hash) = case_plan_hash {
                        if hash != case_plan_hash && required {
                            acceptance(
                                diagnostics,
                                &format!("{path}.plan_sha256"),
                                "nested plan hash must match the case plan hash",
                            );
                        }
                    }
                    if required
                        && input_hashes
                            .is_some_and(|inputs| !inputs.values().any(|value| value == hash))
                    {
                        acceptance(
                            diagnostics,
                            &format!("{path}.plan_sha256"),
                            "nested plan hash is not represented by a checked input",
                        );
                    }
                } else {
                    schema(
                        diagnostics,
                        &format!("{path}.plan_sha256"),
                        "plan_sha256 must be a digest or null",
                    );
                }
            }
        }
    }
    for (field, nested) in value {
        match nested {
            Value::Object(object) => walk_plan_path_hashes(
                object,
                &format!("{path}.{field}"),
                case_plan_hash,
                required,
                input_hashes,
                diagnostics,
            ),
            Value::Array(values) => {
                for (index, nested) in values.iter().enumerate() {
                    if let Value::Object(object) = nested {
                        walk_plan_path_hashes(
                            object,
                            &format!("{path}.{field}[{index}]"),
                            case_plan_hash,
                            required,
                            input_hashes,
                            diagnostics,
                        );
                    }
                }
            }
            _ => {}
        }
    }
}

fn validate_route(
    expected: &Map<String, Value>,
    expected_route: &str,
    case_display: &str,
    diagnostics: &mut Diagnostics,
) {
    let comparator_route = expected
        .get("validation_contract")
        .and_then(Value::as_object)
        .and_then(|contract| contract.get("comparator_route"))
        .and_then(Value::as_str);
    let declared = expected
        .get("gui_route")
        .and_then(Value::as_str)
        .or_else(|| expected.get("route").and_then(Value::as_str))
        .or_else(|| {
            expected
                .get("validation_contract")
                .and_then(Value::as_object)
                .and_then(|contract| contract.get("gui_route"))
                .and_then(Value::as_str)
        });
    if declared.is_none() && comparator_route != Some(STATIC_DESCRIPTOR_ROUTE) {
        schema(
            diagnostics,
            &format!("{case_display}.expected.gui_route"),
            "GUI expected descriptors must declare their dedicated comparator route",
        );
    }
    if let Some(declared) = declared
        && (!GUI_ROUTES.contains(&declared) || declared != expected_route)
    {
        acceptance(
            diagnostics,
            &format!("{case_display}.expected.route"),
            format!("route must be {expected_route}, found {declared}"),
        );
    }
    match comparator_route {
        None => schema(
            diagnostics,
            &format!("{case_display}.expected.validation_contract.comparator_route"),
            "GUI expected descriptors must declare a static or dedicated comparator route",
        ),
        Some(comparator_route)
            if comparator_route != STATIC_DESCRIPTOR_ROUTE
                && !GUI_ROUTES.contains(&comparator_route) =>
        {
            acceptance(
                diagnostics,
                &format!("{case_display}.expected.validation_contract.comparator_route"),
                "generic/non-GUI comparator routes are forbidden for GUI acceptance",
            );
        }
        Some(_) => {}
    }
}

fn validate_evidence_honesty(
    expected: &Map<String, Value>,
    provenance: &Map<String, Value>,
    expected_route: &str,
    path: &str,
    diagnostics: &mut Diagnostics,
) -> String {
    let status = expected
        .get("evidence_status")
        .and_then(Value::as_str)
        .or_else(|| {
            expected
                .get("evidence")
                .and_then(Value::as_object)
                .and_then(|evidence| evidence.get("status"))
                .and_then(Value::as_str)
        })
        .unwrap_or("");
    if !["not-run", "observed", "unavailable", "failed"].contains(&status) {
        schema(
            diagnostics,
            &format!("{path}.evidence_status"),
            "GUI evidence_status must be not-run, observed, unavailable, or failed",
        );
    }
    let contract = expected
        .get("validation_contract")
        .and_then(Value::as_object);
    let comparator = contract
        .and_then(|contract| contract.get("comparator_enforced"))
        .and_then(Value::as_bool);
    if comparator.is_none() {
        schema(
            diagnostics,
            &format!("{path}.validation_contract.comparator_enforced"),
            "comparator_enforced is required",
        );
    }
    let runtime_observations = expected
        .get("source")
        .and_then(Value::as_object)
        .and_then(|source| source.get("runtime_observations"))
        .and_then(Value::as_bool);
    let oracle_performed = provenance
        .get("oracle_execution")
        .and_then(Value::as_object)
        .and_then(|execution| execution.get("performed"))
        .and_then(Value::as_bool);
    let comparator_id = contract
        .and_then(|contract| contract.get("comparator_id"))
        .and_then(Value::as_str);
    let comparator_result = contract
        .and_then(|contract| contract.get("comparator_result"))
        .and_then(Value::as_str)
        .or_else(|| {
            expected
                .get("evidence")
                .and_then(Value::as_object)
                .and_then(|evidence| evidence.get("comparator_result"))
                .and_then(Value::as_str)
        });
    let provenance_complete = ["inputs", "oracle", "runtime", "oracle_execution"]
        .into_iter()
        .all(|field| provenance.get(field).is_some_and(Value::is_object));
    let comparator_id_valid = comparator_id.is_some_and(|id| !id.trim().is_empty());
    match status {
        "not-run" => {
            if comparator == Some(true)
                || runtime_observations == Some(true)
                || oracle_performed == Some(true)
                || comparator_id.is_some()
                || comparator_result.is_some()
            {
                acceptance(
                    diagnostics,
                    path,
                    "not-run GUI evidence cannot claim observations or an enforced comparator",
                );
            }
        }
        "observed" => {
            if comparator != Some(true)
                || runtime_observations != Some(true)
                || oracle_performed != Some(true)
                || !comparator_id_valid
                || comparator_result != Some("pass")
                || !provenance_complete
            {
                acceptance(
                    diagnostics,
                    path,
                    "observed GUI evidence requires complete provenance, runtime observations, oracle execution, comparator identity, comparator_result=pass, and comparator_enforced=true",
                );
            }
            if contract
                .and_then(|contract| contract.get("comparator_route"))
                .and_then(Value::as_str)
                != Some(expected_route)
            {
                acceptance(
                    diagnostics,
                    path,
                    format!(
                        "observed GUI evidence must declare dedicated comparator route {expected_route}"
                    ),
                );
            }
            let route = expected
                .get("evidence")
                .and_then(Value::as_object)
                .and_then(|evidence| evidence.get("route"))
                .and_then(Value::as_str)
                .or_else(|| expected.get("gui_route").and_then(Value::as_str))
                .or_else(|| expected.get("route").and_then(Value::as_str))
                .or_else(|| {
                    contract
                        .and_then(|contract| contract.get("gui_route"))
                        .and_then(Value::as_str)
                });
            if route != Some(expected_route) {
                acceptance(
                    diagnostics,
                    path,
                    format!("observed GUI evidence must use dedicated route {expected_route}"),
                );
            }
        }
        _ => {
            if comparator == Some(true) {
                acceptance(
                    diagnostics,
                    path,
                    "unavailable/failed GUI evidence cannot be comparator-ready",
                );
            }
        }
    }
    status.to_owned()
}

fn validate_plugin_case(
    case: &Map<String, Value>,
    expected: &Map<String, Value>,
    case_display: &str,
    diagnostics: &mut Diagnostics,
) {
    let identity = case
        .get("command")
        .and_then(Value::as_object)
        .and_then(|command| command.get("pre_launch"))
        .and_then(Value::as_object)
        .and_then(|pre_launch| pre_launch.get("plugin_identity"))
        .and_then(Value::as_object);
    if identity.is_none() {
        schema(
            diagnostics,
            &format!("{case_display}.command.pre_launch.plugin_identity"),
            "plugin boundary requires an explicit identity contract",
        );
    } else if identity.is_some_and(|identity| {
        identity.get("native_fallback").and_then(Value::as_str) != Some("forbidden")
    }) {
        acceptance(
            diagnostics,
            &format!("{case_display}.command.pre_launch.plugin_identity.native_fallback"),
            "plugin routes must forbid native fallback",
        );
    }
    let contract = expected
        .get("plugin_editor_contract")
        .and_then(Value::as_object);
    let Some(contract) = contract else {
        schema(
            diagnostics,
            &format!("{case_display}.expected.plugin_editor_contract"),
            "plugin case requires positive and unavailable route descriptors",
        );
        return;
    };
    let static_descriptor = expected
        .get("validation_contract")
        .and_then(Value::as_object)
        .and_then(|contract| contract.get("comparator_route"))
        .and_then(Value::as_str)
        == Some(STATIC_DESCRIPTOR_ROUTE);
    for name in ["positive", "unavailable"] {
        let Some(route) = contract.get(name).and_then(Value::as_object) else {
            schema(
                diagnostics,
                &format!("{case_display}.expected.plugin_editor_contract.{name}"),
                "plugin route descriptor is required",
            );
            continue;
        };
        let route_boundaries = route
            .get("required_boundaries")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<BTreeSet<_>>()
            });
        if route_boundaries != Some(BTreeSet::from(GUI_BOUNDARIES))
            && !(static_descriptor && name == "unavailable" && route_boundaries.is_none())
        {
            acceptance(
                diagnostics,
                &format!(
                    "{case_display}.expected.plugin_editor_contract.{name}.required_boundaries"
                ),
                "plugin route must name JVM, plugin, and OS boundaries",
            );
        }
    }
}

fn validate_platform_matrix(
    root: &Path,
    platform_dir: &Path,
    platform_case: &Map<String, Value>,
    profile_hash: Option<&str>,
    lock_hash: Option<&str>,
    diagnostics: &mut Diagnostics,
) -> bool {
    let mut valid = true;
    let matrix_path = platform_dir.join("matrix.json");
    let expected_path = platform_case
        .get("execution")
        .and_then(Value::as_object)
        .and_then(|execution| execution.get("expected"))
        .and_then(Value::as_str)
        .map(|path| platform_dir.join(path));
    let Some(matrix) = read_json(root, &matrix_path, diagnostics) else {
        return false;
    };
    let Some(matrix_object) = matrix.as_object() else {
        schema(
            diagnostics,
            &display_path(root, &matrix_path),
            "platform matrix must be an object",
        );
        return false;
    };
    let Some(expected_path) = expected_path else {
        schema(
            diagnostics,
            &display_path(root, platform_dir),
            "platform case must declare an expected descriptor",
        );
        return false;
    };
    let Some(expected) = read_json(root, &expected_path, diagnostics) else {
        return false;
    };
    let Some(expected_object) = expected.as_object() else {
        schema(
            diagnostics,
            &display_path(root, &expected_path),
            "platform expected descriptor must be an object",
        );
        return false;
    };
    let matrix_lanes = validate_target_lanes(
        matrix_object.get("target_lanes"),
        &format!("{}.target_lanes", display_path(root, &matrix_path)),
        profile_hash,
        lock_hash,
        false,
        diagnostics,
    );
    let expected_lanes = validate_target_lanes(
        expected_object.get("target_lanes"),
        &format!("{}.target_lanes", display_path(root, &expected_path)),
        profile_hash,
        lock_hash,
        true,
        diagnostics,
    );
    if !target_lane_evidence_ready(expected_object.get("target_lanes")) {
        valid = false;
    }
    if let (Some(matrix_lanes), Some(expected_lanes)) = (matrix_lanes, expected_lanes)
        && matrix_lanes != expected_lanes
    {
        valid = false;
        acceptance(
            diagnostics,
            &display_path(root, &expected_path),
            "platform expected target rows do not match matrix target rows",
        );
    }
    valid
}

fn target_lane_evidence_ready(value: Option<&Value>) -> bool {
    let Some(rows) = value.and_then(Value::as_array) else {
        return false;
    };
    rows.len() == 12
        && rows.iter().all(|value| {
            let Some(row) = value.as_object() else {
                return false;
            };
            let status = row
                .get("evidence_status")
                .or_else(|| row.get("status"))
                .and_then(Value::as_str);
            let comparator = row
                .get("comparator_enforced")
                .and_then(Value::as_bool)
                .or_else(|| {
                    row.get("evidence")
                        .and_then(Value::as_object)
                        .and_then(|evidence| evidence.get("comparator_enforced"))
                        .and_then(Value::as_bool)
                });
            let comparator_result = row
                .get("comparator_result")
                .and_then(Value::as_str)
                .or_else(|| {
                    row.get("evidence")
                        .and_then(Value::as_object)
                        .and_then(|evidence| evidence.get("comparator_result"))
                        .and_then(Value::as_str)
                });
            let route = row
                .get("gui_route")
                .and_then(Value::as_str)
                .or_else(|| row.get("route").and_then(Value::as_str))
                .or_else(|| {
                    row.get("evidence")
                        .and_then(Value::as_object)
                        .and_then(|evidence| evidence.get("route"))
                        .and_then(Value::as_str)
                });
            status == Some("observed")
                && comparator == Some(true)
                && comparator_result == Some("pass")
                && route == Some("gui-platform")
        })
}

fn validate_target_lanes(
    value: Option<&Value>,
    path: &str,
    profile_hash: Option<&str>,
    lock_hash: Option<&str>,
    expected_descriptor: bool,
    diagnostics: &mut Diagnostics,
) -> Option<BTreeSet<(String, u64)>> {
    let Some(value) = value else {
        schema(
            diagnostics,
            path,
            "exactly twelve target×Java rows are required",
        );
        return None;
    };
    let Some(rows) = value.as_array() else {
        schema(diagnostics, path, "target_lanes must be an array");
        return None;
    };
    if rows.len() != 12 {
        acceptance(
            diagnostics,
            path,
            format!("target_lanes must contain 12 rows, found {}", rows.len()),
        );
    }
    let mut seen = BTreeSet::new();
    for (index, row) in rows.iter().enumerate() {
        let row_path = format!("{path}[{index}]");
        let Some(row) = row.as_object() else {
            schema(diagnostics, &row_path, "target lane must be an object");
            continue;
        };
        let observed_lane = row
            .get("evidence_status")
            .or_else(|| row.get("status"))
            .and_then(Value::as_str)
            .is_some_and(|status| status == "observed");
        let lane_id = string(row, "lane_id", &row_path, diagnostics).unwrap_or_default();
        let triple = string(row, "target_triple", &row_path, diagnostics).unwrap_or_default();
        let java_major = row
            .get("java_major")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        if !TARGET_TRIPLES.contains(&triple.as_str()) {
            acceptance(
                diagnostics,
                &format!("{row_path}.target_triple"),
                "target triple is outside the Decision 0002 six-triple matrix",
            );
        }
        if !JAVA_MAJORS.contains(&java_major) {
            acceptance(
                diagnostics,
                &format!("{row_path}.java_major"),
                "GUI evidence must use Java 8 or Java 17",
            );
        }
        if !seen.insert((triple.clone(), java_major)) {
            acceptance(diagnostics, &row_path, "duplicate target triple/Java row");
        }
        validate_fresh_roots(row, &lane_id, &row_path, diagnostics);
        validate_display(row, &lane_id, &row_path, observed_lane, diagnostics);
        validate_laf(row, &row_path, observed_lane, diagnostics);
        validate_lane_image(row, &row_path, observed_lane, diagnostics);
        let runtime_identity = row.get("runtime_identity").and_then(Value::as_object);
        if runtime_identity.is_none() {
            schema(
                diagnostics,
                &format!("{row_path}.runtime_identity"),
                "runtime identity object is required",
            );
        }
        let Some(runtime_identity) = runtime_identity else {
            continue;
        };
        validate_identity(
            runtime_identity.get("profile"),
            "profile",
            &row_path,
            profile_hash,
            observed_lane,
            diagnostics,
        );
        validate_identity(
            runtime_identity
                .get("lock")
                .or_else(|| runtime_identity.get("lock_identity")),
            "lock",
            &row_path,
            lock_hash,
            observed_lane,
            diagnostics,
        );
        validate_identity(
            runtime_identity.get("classpath"),
            "classpath",
            &row_path,
            None,
            observed_lane,
            diagnostics,
        );
        if runtime_identity.get("plugins").is_none() {
            schema(
                diagnostics,
                &format!("{row_path}.runtime_identity.plugins"),
                "plugin identity set is required, even when empty",
            );
        }
        if expected_descriptor {
            let status = row
                .get("evidence_status")
                .or_else(|| row.get("status"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let comparator = row
                .get("comparator_enforced")
                .and_then(Value::as_bool)
                .or_else(|| {
                    row.get("evidence")
                        .and_then(Value::as_object)
                        .and_then(|evidence| evidence.get("comparator_enforced"))
                        .and_then(Value::as_bool)
                });
            if status == "observed" && comparator != Some(true) {
                acceptance(
                    diagnostics,
                    &format!("{row_path}.comparator_enforced"),
                    "observed platform evidence requires its dedicated comparator",
                );
            }
        }
    }
    let expected_pairs = TARGET_TRIPLES
        .into_iter()
        .flat_map(|triple| {
            JAVA_MAJORS
                .into_iter()
                .map(move |java| (triple.to_owned(), java))
        })
        .collect::<BTreeSet<_>>();
    if seen != expected_pairs {
        acceptance(
            diagnostics,
            path,
            format!(
                "target×Java rows must be the complete six-triple×Java8/17 cross-product; found {:?}",
                seen
            ),
        );
    }
    Some(seen)
}

fn validate_fresh_roots(
    row: &Map<String, Value>,
    lane_id: &str,
    path: &str,
    diagnostics: &mut Diagnostics,
) {
    let mut roots = Vec::new();
    for field in ["workspace_root", "output_root", "preference_root"] {
        let Some(value) = string(row, field, path, diagnostics) else {
            continue;
        };
        if !value.contains("<temporary-root>")
            || !value.contains(lane_id)
            || value.contains("compat/fixtures")
        {
            acceptance(
                diagnostics,
                &format!("{path}.{field}"),
                "lane root must be a fresh temporary-root path containing its lane identity",
            );
        }
        roots.push((field, value));
    }
    let mut unique = BTreeSet::new();
    for (field, value) in roots {
        if !unique.insert(value) {
            acceptance(
                diagnostics,
                &format!("{path}.{field}"),
                "workspace/output/preference roots must be distinct",
            );
        }
    }
}

fn validate_display(
    row: &Map<String, Value>,
    lane_id: &str,
    path: &str,
    observed_lane: bool,
    diagnostics: &mut Diagnostics,
) {
    let Some(display) = row.get("display").and_then(Value::as_object) else {
        schema(
            diagnostics,
            &format!("{path}.display"),
            "display identity object is required",
        );
        return;
    };
    if display.get("required").and_then(Value::as_bool) != Some(true)
        || display.get("fresh_session").and_then(Value::as_bool) != Some(true)
    {
        acceptance(
            diagnostics,
            &format!("{path}.display"),
            "GUI lane requires a fresh display session",
        );
    }
    let session = row
        .get("display_session_id")
        .and_then(Value::as_str)
        .or_else(|| display.get("session_id").and_then(Value::as_str));
    if session.is_none_or(|session| session.is_empty() || !session.contains(lane_id)) {
        acceptance(
            diagnostics,
            &format!("{path}.display_session_id"),
            "display session identity must be fresh and lane-specific",
        );
    }
    let scaling = display
        .get("scaling")
        .or_else(|| row.get("scaling"))
        .or_else(|| row.get("planned_scaling"));
    if scaling.is_none() && observed_lane {
        schema(
            diagnostics,
            &format!("{path}.display.scaling"),
            "display scaling identity is required",
        );
    } else if scaling
        .is_some_and(|scaling| scaling.is_null() || scaling.as_str().is_some_and(str::is_empty))
    {
        acceptance(
            diagnostics,
            &format!("{path}.display.scaling"),
            "display scaling must be explicit, not empty or inherited",
        );
    }
}

fn validate_laf(
    row: &Map<String, Value>,
    path: &str,
    observed_lane: bool,
    diagnostics: &mut Diagnostics,
) {
    let Some(order) = row.get("laf_lookup_order").and_then(Value::as_array) else {
        schema(
            diagnostics,
            &format!("{path}.laf_lookup_order"),
            "LAF lookup order is required",
        );
        return;
    };
    if order.is_empty() || order[0].as_str() != Some("laf.command preference") {
        acceptance(
            diagnostics,
            &format!("{path}.laf_lookup_order"),
            "LAF lookup must start with the isolated laf.command preference",
        );
    }
    let has_laf = row
        .get("planned_laf")
        .or_else(|| row.get("planned_effective_laf"))
        .or_else(|| row.get("effective_laf"))
        .is_some();
    if !has_laf && observed_lane {
        schema(
            diagnostics,
            &format!("{path}.effective_laf"),
            "LAF result or explicit planned LAF is required",
        );
    }
}

fn validate_lane_image(
    row: &Map<String, Value>,
    path: &str,
    observed_lane: bool,
    diagnostics: &mut Diagnostics,
) {
    let Some(image) = row.get("os_image").or_else(|| row.get("os_image_identity")) else {
        if !observed_lane {
            return;
        }
        schema(
            diagnostics,
            &format!("{path}.os_image"),
            "OS image identity is required",
        );
        return;
    };
    if image.as_str().is_some_and(str::is_empty) || image.is_null() {
        acceptance(
            diagnostics,
            &format!("{path}.os_image"),
            "OS image identity must not be empty or inherited",
        );
    }
    if let Some(object) = image.as_object() {
        let digest = object
            .get("sha256")
            .or_else(|| object.get("digest"))
            .and_then(Value::as_str);
        if let Some(digest) = digest {
            validate_digest(digest, &format!("{path}.os_image.digest"), diagnostics);
        }
    }
}

fn validate_identity(
    value: Option<&Value>,
    name: &str,
    row_path: &str,
    expected_hash: Option<&str>,
    observed_lane: bool,
    diagnostics: &mut Diagnostics,
) {
    let path = format!("{row_path}.runtime_identity.{name}");
    let Some(value) = value else {
        if observed_lane {
            schema(diagnostics, &path, "identity declaration is required");
        }
        return;
    };
    match value {
        Value::String(value) if !value.is_empty() => {
            if expected_hash.is_some() && observed_lane && !is_planned_text(value) {
                acceptance(
                    diagnostics,
                    &path,
                    "identity must include a SHA-256 digest before acceptance",
                );
            }
        }
        Value::Object(object) => {
            let id = object
                .get("id")
                .or_else(|| object.get("name"))
                .or_else(|| object.get("path"))
                .and_then(Value::as_str);
            if name == "profile" && id.is_some_and(|id| id != "jmeter-5.6.3") {
                acceptance(
                    diagnostics,
                    &path,
                    "profile identity must name jmeter-5.6.3",
                );
            }
            let digest = object
                .get("sha256")
                .or_else(|| object.get("digest"))
                .or_else(|| object.get("identity_sha256"))
                .and_then(Value::as_str);
            if let Some(digest) = digest {
                validate_digest(digest, &format!("{path}.sha256"), diagnostics);
                if let Some(expected_hash) = expected_hash {
                    if digest != expected_hash && !is_planned_text(digest) {
                        acceptance(
                            diagnostics,
                            &format!("{path}.sha256"),
                            "identity digest does not match the pinned file",
                        );
                    }
                }
            } else if observed_lane {
                schema(
                    diagnostics,
                    &format!("{path}.sha256"),
                    "identity requires a SHA-256 digest",
                );
            }
            if name == "classpath" {
                let members = object
                    .get("members")
                    .or_else(|| object.get("ordered_members"))
                    .and_then(Value::as_array);
                if members.is_none() && digest.is_none() {
                    schema(
                        diagnostics,
                        &format!("{path}.members"),
                        "classpath identity requires ordered members or an identity digest",
                    );
                }
            }
        }
        _ => schema(
            diagnostics,
            &path,
            "identity must be a string declaration or object",
        ),
    }
}

fn validate_acceptance_readiness(
    root: &Path,
    gui_root: &Path,
    states: &[CaseState],
    platform_lanes_ready: bool,
    diagnostics: &mut Diagnostics,
) {
    let not_ready = states.len() != 5
        || !platform_lanes_ready
        || states
            .iter()
            .any(|state| state.evidence_status != "observed" || !state.comparator_enforced);
    if not_ready {
        acceptance(
            diagnostics,
            &display_path(root, gui_root),
            "GUI acceptance is fail-closed: all GUI cases and all 12 target×Java rows require observed evidence with a dedicated passing comparator; static not-run descriptors cannot promote conformance",
        );
    }
}

fn expected_route(case_dir: &Path, case_id: &str) -> &'static str {
    if case_id.contains("PERSISTENCE") {
        "gui-persistence"
    } else if case_id.contains("PLATFORM")
        || case_dir
            .file_name()
            .is_some_and(|name| name == "platform-settings")
    {
        "gui-platform"
    } else if case_id.contains("PLUGIN-EDITOR") {
        "gui-capability-error"
    } else {
        "gui-jmx-semantic"
    }
}

fn contains_forbidden_gui_004(value: &Value) -> bool {
    match value {
        Value::String(value) => value.contains("GUI-004"),
        Value::Array(values) => values.iter().any(contains_forbidden_gui_004),
        Value::Object(object) => object.values().any(contains_forbidden_gui_004),
        _ => false,
    }
}

fn string(
    object: &Map<String, Value>,
    field: &str,
    path: &str,
    diagnostics: &mut Diagnostics,
) -> Option<String> {
    match object.get(field).and_then(Value::as_str) {
        Some(value) if !value.is_empty() => Some(value.to_owned()),
        _ => {
            schema(
                diagnostics,
                &format!("{path}.{field}"),
                "required non-empty string is missing",
            );
            None
        }
    }
}

fn string_set(
    value: Option<&Value>,
    path: &str,
    diagnostics: &mut Diagnostics,
) -> BTreeSet<String> {
    let Some(values) = value.and_then(Value::as_array) else {
        schema(diagnostics, path, "required string array is missing");
        return BTreeSet::new();
    };
    values
        .iter()
        .enumerate()
        .filter_map(|(index, value)| {
            value.as_str().map(str::to_owned).or_else(|| {
                schema(
                    diagnostics,
                    &format!("{path}[{index}]"),
                    "array item must be a string",
                );
                None
            })
        })
        .collect()
}

fn resolve_fixture_path(
    root: &Path,
    gui_root: &Path,
    case_dir: &Path,
    relative: &str,
    path: &str,
    diagnostics: &mut Diagnostics,
) -> Option<PathBuf> {
    let relative_path = Path::new(relative);
    if relative_path.is_absolute()
        || relative_path
            .components()
            .any(|component| component == Component::RootDir)
    {
        schema(
            diagnostics,
            &format!("{path}.path"),
            "fixture input path must be relative",
        );
        return None;
    }
    let candidate = case_dir.join(relative_path);
    let metadata = match fs::symlink_metadata(&candidate) {
        Ok(metadata) => metadata,
        Err(error) => {
            io(
                diagnostics,
                &display_path(root, &candidate),
                format!("cannot inspect declared fixture input: {error}"),
            );
            return None;
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        schema(
            diagnostics,
            &display_path(root, &candidate),
            "declared fixture input must be a regular non-symlink file",
        );
        return None;
    }
    let Ok(gui_root) = gui_root.canonicalize() else {
        io(
            diagnostics,
            &display_path(root, gui_root),
            "cannot canonicalize GUI fixture root",
        );
        return None;
    };
    let Ok(candidate) = candidate.canonicalize() else {
        io(
            diagnostics,
            &display_path(root, &candidate),
            "cannot canonicalize declared fixture input",
        );
        return None;
    };
    if !candidate.starts_with(gui_root) {
        schema(
            diagnostics,
            &display_path(root, &candidate),
            "declared fixture input escapes gui-static",
        );
        return None;
    }
    Some(candidate)
}

fn read_json(root: &Path, path: &Path, diagnostics: &mut Diagnostics) -> Option<Value> {
    let bytes = read_file(root, path, diagnostics)?;
    match serde_json::from_slice(&bytes) {
        Ok(value) => Some(value),
        Err(error) => {
            schema(
                diagnostics,
                &display_path(root, path),
                format!("invalid JSON: {error}"),
            );
            None
        }
    }
}

fn hash_file(
    root: &Path,
    path: &Path,
    _subject: &str,
    diagnostics: &mut Diagnostics,
) -> Option<String> {
    let bytes = read_file(root, path, diagnostics)?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    Some(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn read_file(root: &Path, path: &Path, diagnostics: &mut Diagnostics) -> Option<Vec<u8>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            io(
                diagnostics,
                &display_path(root, path),
                format!("cannot read GUI acceptance file: {error}"),
            );
            return None;
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        schema(
            diagnostics,
            &display_path(root, path),
            "GUI acceptance input must be a regular non-symlink file",
        );
        return None;
    }
    if metadata.len() > MAX_GUI_FILE_BYTES {
        acceptance(
            diagnostics,
            &display_path(root, path),
            format!("file exceeds {MAX_GUI_FILE_BYTES}-byte static bound"),
        );
        return None;
    }
    match fs::read(path) {
        Ok(bytes) => Some(bytes),
        Err(error) => {
            io(
                diagnostics,
                &display_path(root, path),
                format!("cannot read GUI acceptance file: {error}"),
            );
            None
        }
    }
}

fn validate_digest(value: &str, path: &str, diagnostics: &mut Diagnostics) {
    if value.len() != SHA256_HEX_LENGTH
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        schema(diagnostics, path, "must be a lowercase SHA-256 digest");
    }
}

fn is_planned_text(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    value.contains("planned")
        || value.contains("not invoked")
        || value.contains("not provisioned")
        || value.contains("not-run")
}

fn schema(diagnostics: &mut Diagnostics, path: &str, message: impl Into<String>) {
    diagnostics.push(Diagnostic::new("GUI-ACCEPTANCE-SCHEMA", path, message));
}

fn acceptance(diagnostics: &mut Diagnostics, path: &str, message: impl Into<String>) {
    diagnostics.push(Diagnostic::new("GUI-ACCEPTANCE-GATE", path, message));
}

fn io(diagnostics: &mut Diagnostics, path: &str, message: impl Into<String>) {
    diagnostics.push(Diagnostic::new("GUI-ACCEPTANCE-IO", path, message));
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn diagnostics_for_lane(row: Value) -> Diagnostics {
        let mut diagnostics = Diagnostics::default();
        validate_target_lanes(
            Some(&json!([row])),
            "matrix.target_lanes",
            None,
            None,
            false,
            &mut diagnostics,
        );
        diagnostics
    }

    #[test]
    fn target_matrix_is_closed_to_the_six_by_two_cross_product() {
        let row = json!({
            "lane_id": "linux-x86_64-java8",
            "target_triple": "x86_64-unknown-linux-gnu",
            "java_major": 8,
            "workspace_root": "<temporary-root>/workspace/linux-x86_64-java8",
            "output_root": "<temporary-root>/output/linux-x86_64-java8",
            "preference_root": "<temporary-root>/prefs/linux-x86_64-java8",
            "display_session_id": "display-linux-x86_64-java8",
            "display": {"required": true, "fresh_session": true, "scaling": "1x"},
            "laf_lookup_order": ["laf.command preference", "jmeter.laf"],
            "planned_laf": "CrossPlatform",
            "os_image": "planned image",
            "runtime_identity": {
                "profile": "jmeter-5.6.3",
                "lock": "planned lock",
                "classpath": "planned classpath",
                "plugins": "none"
            }
        });
        let diagnostics = diagnostics_for_lane(row);
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.path == "matrix.target_lanes" && diagnostic.message.contains("12 rows")
        }));
    }

    #[test]
    fn not_run_evidence_cannot_enable_a_comparator() {
        let expected = json!({
            "evidence_status": "not-run",
            "source": {"runtime_observations": true},
            "validation_contract": {"comparator_enforced": true},
        });
        let provenance = json!({"oracle_execution": {"performed": true}});
        let mut diagnostics = Diagnostics::default();
        let status = validate_evidence_honesty(
            expected.as_object().expect("object"),
            provenance.as_object().expect("object"),
            "gui-jmx-semantic",
            "expected",
            &mut diagnostics,
        );
        assert_eq!(status, "not-run");
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "GUI-ACCEPTANCE-GATE")
        );
    }

    #[test]
    fn generic_comparator_route_is_rejected() {
        let expected = json!({
            "validation_contract": {"comparator_route": "jmx-semantic"}
        });
        let mut diagnostics = Diagnostics::default();
        validate_route(
            expected.as_object().expect("object"),
            "gui-jmx-semantic",
            "expected",
            &mut diagnostics,
        );
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "GUI-ACCEPTANCE-GATE")
        );
    }

    #[test]
    fn static_descriptor_route_is_allowed_only_for_not_run_evidence() {
        let expected = json!({
            "evidence_status": "not-run",
            "validation_contract": {
                "comparator_enforced": false,
                "comparator_route": "static-descriptor"
            }
        });
        let mut diagnostics = Diagnostics::default();
        validate_route(
            expected.as_object().expect("object"),
            "gui-jmx-semantic",
            "expected",
            &mut diagnostics,
        );
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
    }

    #[test]
    fn observed_evidence_requires_passing_dedicated_comparator_and_provenance() {
        let expected = json!({
            "evidence_status": "observed",
            "gui_route": "gui-jmx-semantic",
            "source": {"runtime_observations": true},
            "validation_contract": {
                "comparator_enforced": true,
                "comparator_id": "gui-jmx-semantic-v1",
                "comparator_result": "pass",
                "comparator_route": "gui-jmx-semantic"
            }
        });
        let provenance = json!({
            "inputs": {},
            "oracle": {},
            "runtime": {},
            "oracle_execution": {"performed": true}
        });
        let mut diagnostics = Diagnostics::default();
        let status = validate_evidence_honesty(
            expected.as_object().expect("object"),
            provenance.as_object().expect("object"),
            "gui-jmx-semantic",
            "expected",
            &mut diagnostics,
        );
        assert_eq!(status, "observed");
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
    }

    #[test]
    fn observed_static_descriptor_route_is_rejected() {
        let expected = json!({
            "evidence_status": "observed",
            "gui_route": "gui-jmx-semantic",
            "source": {"runtime_observations": true},
            "validation_contract": {
                "comparator_enforced": true,
                "comparator_id": "gui-jmx-semantic-v1",
                "comparator_result": "pass",
                "comparator_route": "static-descriptor"
            }
        });
        let provenance = json!({
            "inputs": {},
            "oracle": {},
            "runtime": {},
            "oracle_execution": {"performed": true}
        });
        let mut diagnostics = Diagnostics::default();
        validate_evidence_honesty(
            expected.as_object().expect("object"),
            provenance.as_object().expect("object"),
            "gui-jmx-semantic",
            "expected",
            &mut diagnostics,
        );
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| { diagnostic.message.contains("dedicated comparator route") })
        );
    }

    #[test]
    fn platform_lanes_require_twelve_observed_passing_rows() {
        let planned = json!({
            "target_lanes": [{
                "status": "planned; not observed",
                "comparator_enforced": false,
                "comparator_result": null,
                "gui_route": null
            }]
        });
        assert!(!target_lane_evidence_ready(planned.get("target_lanes")));

        let observed_row = json!({
            "status": "observed",
            "comparator_enforced": true,
            "comparator_result": "pass",
            "gui_route": "gui-platform"
        });
        let observed = json!({
            "target_lanes": std::iter::repeat_n(observed_row, 12).collect::<Vec<_>>()
        });
        assert!(target_lane_evidence_ready(observed.get("target_lanes")));
    }

    #[test]
    fn observed_lane_controls_runtime_only_requirements() {
        fn lane(status: &str) -> Value {
            json!({
                "lane_id": "linux-x86_64-java8",
                "target_triple": "x86_64-unknown-linux-gnu",
                "java_major": 8,
                "status": status,
                "workspace_root": "<temporary-root>/workspace/linux-x86_64-java8",
                "output_root": "<temporary-root>/output/linux-x86_64-java8",
                "preference_root": "<temporary-root>/prefs/linux-x86_64-java8",
                "display_session_id": "display-linux-x86_64-java8",
                "display": {"required": true, "fresh_session": true},
                "laf_lookup_order": ["laf.command preference"],
                "runtime_identity": {"plugins": []}
            })
        }

        let planned_diagnostics = diagnostics_for_lane(lane("planned; not observed"));
        for field in [
            ".display.scaling",
            ".effective_laf",
            ".os_image",
            ".runtime_identity.profile",
            ".runtime_identity.lock",
            ".runtime_identity.classpath",
        ] {
            assert!(
                !planned_diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.path.contains(field))
            );
        }

        let observed_diagnostics = diagnostics_for_lane(lane("observed"));
        for field in [
            ".display.scaling",
            ".effective_laf",
            ".os_image",
            ".runtime_identity.profile",
            ".runtime_identity.lock",
            ".runtime_identity.classpath",
        ] {
            assert!(
                observed_diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.path.contains(field))
            );
        }
    }

    #[test]
    fn gui_descriptors_cannot_claim_standalone_native_support() {
        let object = json!({
            "capability_set": "standalone-native",
            "standalone_native": true
        });
        let mut diagnostics = Diagnostics::default();
        validate_standalone_exclusion(
            object.as_object().expect("object"),
            "descriptor",
            &mut diagnostics,
        );
        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "GUI-ACCEPTANCE-GATE")
                .count(),
            2
        );
    }

    #[test]
    fn missing_plan_hash_sibling_is_rejected() {
        let value = json!({"scenario": {"plan_path": "<temporary-root>/plan.jmx"}});
        let mut diagnostics = Diagnostics::default();
        walk_plan_path_hashes(
            value.as_object().expect("object"),
            "case",
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            true,
            None,
            &mut diagnostics,
        );
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "GUI-ACCEPTANCE-SCHEMA")
        );
    }
}
