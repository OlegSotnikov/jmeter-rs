// SPDX-License-Identifier: Apache-2.0
//! Compatibility-profile schema, inventory, and reference validation.

use crate::diagnostics::{Diagnostic, Diagnostics};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;

const PROFILE_SCHEMA_ID: &str = "jmeter-rs.compatibility-profile";
const PROFILE_SCHEMA_VERSION: u64 = 1;
const EXPECTED_FEATURE_COUNT: usize = 52;
const FEATURE_PREFIXES: [&str; 14] = [
    "CLI", "CFG", "JMX", "JTL", "ELEM", "FUNC", "SCRIPT", "REPORT", "DIST", "PROXY", "TLS", "PLUG",
    "GUI", "TEST",
];
const ALLOWED_STATUSES: [&str; 4] = ["planned", "external", "verified", "blocked"];
const MAX_PROFILE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_PROFILE_JSON_DEPTH: usize = 64;
const MAX_PROFILE_JSON_NODES: usize = 200_000;
const PROFILE_READ_CHUNK_BYTES: usize = 16 * 1024;

#[derive(Debug)]
enum ProfileReadError {
    Open(io::Error),
    HandleMetadata(io::Error),
    PathMetadata(io::Error),
    Read(io::Error),
    InvalidUtf8(std::string::FromUtf8Error),
    NonRegular,
    Symlink,
    Changed,
    TooLarge { limit: u64 },
    Grew { limit: u64 },
    Truncated,
    InvalidLimit,
}

fn read_bounded_utf8(path: &Path, maximum: u64) -> Result<String, ProfileReadError> {
    let (file, metadata) = open_profile_file(path)?;
    let bytes = read_bounded_handle(file, path, &metadata, maximum)?;
    String::from_utf8(bytes).map_err(ProfileReadError::InvalidUtf8)
}

fn open_profile_file(path: &Path) -> Result<(File, Metadata), ProfileReadError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    options.custom_flags(O_NOFOLLOW | O_NONBLOCK);
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) => {
            // Linux's O_NOFOLLOW reports a symlink as ELOOP.  Recover the
            // stable path diagnostic without treating any other open error as
            // a symlink claim.
            if let Ok(metadata) = fs::symlink_metadata(path)
                && metadata.file_type().is_symlink()
            {
                return Err(ProfileReadError::Symlink);
            }
            return Err(ProfileReadError::Open(error));
        }
    };
    let handle_metadata = file.metadata().map_err(ProfileReadError::HandleMetadata)?;
    validate_opened_profile_path(path, &handle_metadata)?;
    Ok((file, handle_metadata))
}

fn validate_opened_profile_path(
    path: &Path,
    handle_metadata: &Metadata,
) -> Result<(), ProfileReadError> {
    if !handle_metadata.is_file() {
        return Err(ProfileReadError::NonRegular);
    }
    let path_metadata = fs::symlink_metadata(path).map_err(ProfileReadError::PathMetadata)?;
    if path_metadata.file_type().is_symlink() {
        return Err(ProfileReadError::Symlink);
    }
    if !path_metadata.is_file() {
        return Err(ProfileReadError::NonRegular);
    }
    if !same_file_identity(handle_metadata, &path_metadata)
        || handle_metadata.len() != path_metadata.len()
    {
        return Err(ProfileReadError::Changed);
    }
    Ok(())
}

fn read_bounded_handle(
    mut file: File,
    path: &Path,
    initial_metadata: &Metadata,
    maximum: u64,
) -> Result<Vec<u8>, ProfileReadError> {
    if initial_metadata.len() > maximum {
        return Err(ProfileReadError::TooLarge { limit: maximum });
    }
    let maximum_plus_one = maximum
        .checked_add(1)
        .ok_or(ProfileReadError::InvalidLimit)?;
    let maximum_plus_one_usize =
        usize::try_from(maximum_plus_one).map_err(|_| ProfileReadError::InvalidLimit)?;
    let mut bytes = Vec::with_capacity(maximum_plus_one_usize);
    let mut chunk = [0_u8; PROFILE_READ_CHUNK_BYTES];
    loop {
        if bytes.len() == maximum_plus_one_usize {
            break;
        }
        let read_length = (maximum_plus_one_usize - bytes.len()).min(chunk.len());
        let count = file
            .read(&mut chunk[..read_length])
            .map_err(ProfileReadError::Read)?;
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    let byte_count = u64::try_from(bytes.len()).map_err(|_| ProfileReadError::InvalidLimit)?;
    if byte_count > maximum {
        return Err(ProfileReadError::Grew { limit: maximum });
    }

    let final_metadata = file.metadata().map_err(ProfileReadError::HandleMetadata)?;
    validate_opened_profile_path(path, &final_metadata)?;
    if final_metadata.len() > maximum {
        return Err(ProfileReadError::Grew { limit: maximum });
    }
    if final_metadata.len() < initial_metadata.len() || byte_count < initial_metadata.len() {
        return Err(ProfileReadError::Truncated);
    }
    if final_metadata.len() > initial_metadata.len() || byte_count > initial_metadata.len() {
        return Err(ProfileReadError::Changed);
    }
    Ok(bytes)
}

fn profile_read_diagnostic(path: &str, subject: &str, error: ProfileReadError) -> Diagnostic {
    let bound_subject = if subject == "compatibility profile" {
        "profile"
    } else {
        subject
    };
    match error {
        ProfileReadError::Symlink | ProfileReadError::NonRegular => Diagnostic::new(
            "PROFILE-PATH",
            path,
            format!("{subject} must be a regular non-symlink file"),
        ),
        ProfileReadError::TooLarge { limit } => Diagnostic::new(
            "PROFILE-BOUNDS",
            path,
            format!("{bound_subject} exceeds {limit}-byte validator bound"),
        ),
        ProfileReadError::Grew { limit } => Diagnostic::new(
            "PROFILE-BOUNDS",
            path,
            format!("{bound_subject} grew beyond {limit}-byte validator bound while reading"),
        ),
        ProfileReadError::Changed => Diagnostic::new(
            "PROFILE-IO",
            path,
            format!("cannot read {subject}: file changed while opening or reading"),
        ),
        ProfileReadError::Truncated => Diagnostic::new(
            "PROFILE-IO",
            path,
            format!("cannot read {subject}: file was truncated while reading"),
        ),
        ProfileReadError::InvalidUtf8(error) => Diagnostic::new(
            "PROFILE-IO",
            path,
            format!("cannot read {subject}: input is not valid UTF-8: {error}"),
        ),
        ProfileReadError::InvalidLimit => Diagnostic::new(
            "PROFILE-BOUNDS",
            path,
            format!("{subject} validator bound cannot be represented on this platform"),
        ),
        ProfileReadError::Open(error)
        | ProfileReadError::HandleMetadata(error)
        | ProfileReadError::PathMetadata(error)
        | ProfileReadError::Read(error) => Diagnostic::new(
            "PROFILE-IO",
            path,
            format!("cannot read {subject}: {error}"),
        ),
    }
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

/// The IDs and upstream pin needed by fixture validation.
#[derive(Clone, Debug, Default)]
pub(crate) struct ProfileIndex {
    pub(crate) profile_id: String,
    pub(crate) feature_ids: BTreeSet<String>,
    pub(crate) feature_statuses: BTreeMap<String, String>,
    pub(crate) feature_fixture_ids: BTreeMap<String, BTreeSet<String>>,
    pub(crate) feature_normalization_ids: BTreeMap<String, BTreeSet<String>>,
    pub(crate) feature_boundaries: BTreeMap<String, BTreeSet<String>>,
    pub(crate) fixture_ids: BTreeSet<String>,
    pub(crate) materialized_fixture_ids: BTreeSet<String>,
    pub(crate) verified_fixture_ids: BTreeSet<String>,
    pub(crate) fixture_statuses: BTreeMap<String, String>,
    pub(crate) fixture_normalization_ids: BTreeMap<String, BTreeSet<String>>,
    pub(crate) fixture_boundaries: BTreeMap<String, BTreeSet<String>>,
    pub(crate) normalization_ids: BTreeSet<String>,
    pub(crate) boundary_ids: BTreeSet<String>,
    pub(crate) boundary_features: BTreeMap<String, BTreeSet<String>>,
    pub(crate) upstream: UpstreamPin,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct UpstreamPin {
    pub(crate) project: String,
    pub(crate) version: String,
    pub(crate) release_tag: String,
    pub(crate) source_commit: String,
    pub(crate) artifact: String,
    pub(crate) digest: String,
}

/// Validate a profile and return both diagnostics and its usable reference index.
pub(crate) fn check(root: &Path, profile_path: &Path) -> (Diagnostics, Option<ProfileIndex>) {
    let mut diagnostics = Diagnostics::default();
    let path = display_path(root, profile_path);
    let text = match read_bounded_utf8(profile_path, MAX_PROFILE_BYTES) {
        Ok(text) => text,
        Err(error) => {
            diagnostics.push(profile_read_diagnostic(
                &path,
                "compatibility profile",
                error,
            ));
            return (diagnostics, None);
        }
    };
    let value = match serde_json::from_str::<Value>(&text) {
        Ok(value) => value,
        Err(error) => {
            diagnostics.push(Diagnostic::new(
                "PROFILE-JSON",
                path,
                format!(
                    "invalid JSON at line {}, column {}: {error}",
                    error.line(),
                    error.column()
                ),
            ));
            return (diagnostics, None);
        }
    };
    let Some(root_object) = value.as_object() else {
        diagnostics.push(Diagnostic::new(
            "PROFILE-SCHEMA",
            display_path(root, profile_path),
            "top-level value must be a JSON object",
        ));
        return (diagnostics, None);
    };
    let mut nodes = 0;
    validate_json_limits(&value, &path, 0, &mut nodes, &mut diagnostics);

    let mut index = ProfileIndex::default();
    validate_root_fields(
        root,
        profile_path,
        root_object,
        &mut diagnostics,
        &mut index,
    );
    let source_path = checklist_source_path(root, profile_path, root_object, &mut diagnostics);
    let inventory_status = root_object
        .get("checklist_source")
        .and_then(Value::as_object)
        .and_then(|source| source.get("inventory_status_value"))
        .and_then(Value::as_str)
        .unwrap_or("TODO");
    let inventory = source_path
        .as_deref()
        .and_then(|path| read_inventory(root, path, inventory_status, &mut diagnostics));

    validate_normalization_policies(
        root,
        profile_path,
        root_object,
        &mut diagnostics,
        &mut index,
    );
    validate_features(
        root,
        profile_path,
        root_object,
        &mut diagnostics,
        &mut index,
        inventory.as_ref(),
    );
    validate_boundaries(
        root,
        profile_path,
        root_object,
        &mut diagnostics,
        &mut index,
    );
    validate_fixture_catalog(
        root,
        profile_path,
        root_object,
        &mut diagnostics,
        &mut index,
    );
    validate_cross_references(root, profile_path, root_object, &mut diagnostics, &index);

    if index.profile_id.is_empty() {
        return (diagnostics, None);
    }
    diagnostics.sort_deterministically();
    (diagnostics, Some(index))
}

fn validate_root_fields(
    root: &Path,
    profile_path: &Path,
    object: &Map<String, Value>,
    diagnostics: &mut Diagnostics,
    index: &mut ProfileIndex,
) {
    let path = display_path(root, profile_path);
    match required_string(object, "schema_id", &path, diagnostics) {
        Some(value) if value != PROFILE_SCHEMA_ID => diagnostics.push(Diagnostic::new(
            "PROFILE-SCHEMA",
            format!("{path}.schema_id"),
            format!("must be {PROFILE_SCHEMA_ID:?}"),
        )),
        _ => {}
    }
    match required_u64(object, "schema_version", &path, diagnostics) {
        Some(value) if value != PROFILE_SCHEMA_VERSION => diagnostics.push(Diagnostic::new(
            "PROFILE-SCHEMA",
            format!("{path}.schema_version"),
            format!("unsupported schema version {value}; expected {PROFILE_SCHEMA_VERSION}"),
        )),
        _ => {}
    }
    if let Some(value) = required_string(object, "profile_id", &path, diagnostics) {
        if !is_profile_id(&value) {
            diagnostics.push(Diagnostic::new(
                "PROFILE-SCHEMA",
                format!("{path}.profile_id"),
                "must be a non-empty lowercase profile identifier",
            ));
        }
        index.profile_id = value;
    }
    let _ = required_u64(object, "profile_version", &path, diagnostics);
    if let Some(value) = required_string(object, "profile_date", &path, diagnostics)
        && !is_iso_date(&value)
    {
        diagnostics.push(Diagnostic::new(
            "PROFILE-SCHEMA",
            format!("{path}.profile_date"),
            "must use YYYY-MM-DD format",
        ));
    }

    let Some(claim_policy) = required_object(object, "claim_policy", &path, diagnostics) else {
        return;
    };
    if let Some(value) = required_bool(
        claim_policy,
        "unverified_features_claimed",
        &format!("{path}.claim_policy"),
        diagnostics,
    ) && value
    {
        diagnostics.push(Diagnostic::new(
            "PROFILE-CLAIM",
            format!("{path}.claim_policy.unverified_features_claimed"),
            "must be false for a fail-closed unverified profile",
        ));
    }
    let statuses = required_array(
        claim_policy,
        "status_vocabulary",
        &format!("{path}.claim_policy"),
        diagnostics,
    );
    if let Some(statuses) = statuses {
        let mut values = BTreeSet::new();
        for (index, status) in statuses.iter().enumerate() {
            let item_path = format!("{path}.claim_policy.status_vocabulary[{index}]");
            if let Some(status) = status.as_str() {
                values.insert(status.to_owned());
                if !ALLOWED_STATUSES.contains(&status) {
                    diagnostics.push(Diagnostic::new(
                        "PROFILE-STATUS",
                        item_path,
                        format!(
                            "unknown status {status:?}; allowed values are {ALLOWED_STATUSES:?}"
                        ),
                    ));
                }
            } else {
                diagnostics.push(Diagnostic::new(
                    "PROFILE-SCHEMA",
                    item_path,
                    "status vocabulary entries must be strings",
                ));
            }
        }
        if values.len() != statuses.len() {
            diagnostics.push(Diagnostic::new(
                "PROFILE-DUPLICATE-REFERENCE",
                format!("{path}.claim_policy.status_vocabulary"),
                "status vocabulary entries must be unique",
            ));
        }
        let expected = ALLOWED_STATUSES
            .iter()
            .map(|status| (*status).to_owned())
            .collect::<BTreeSet<_>>();
        if values != expected {
            diagnostics.push(Diagnostic::new(
                "PROFILE-STATUS",
                format!("{path}.claim_policy.status_vocabulary"),
                format!("must contain exactly {ALLOWED_STATUSES:?}"),
            ));
        }
    }
    if let Some(status_rules) = required_object(
        claim_policy,
        "status_rules",
        &format!("{path}.claim_policy"),
        diagnostics,
    ) {
        for status in ALLOWED_STATUSES {
            let _ = required_string(
                status_rules,
                status,
                &format!("{path}.claim_policy.status_rules"),
                diagnostics,
            );
        }
    }

    let Some(upstream) = required_object(object, "upstream", &path, diagnostics) else {
        return;
    };
    if let Some(value) = required_string(
        upstream,
        "project",
        &format!("{path}.upstream"),
        diagnostics,
    ) {
        index.upstream.project = value;
    }
    if let Some(value) = required_string(
        upstream,
        "version",
        &format!("{path}.upstream"),
        diagnostics,
    ) {
        index.upstream.version = value;
    }
    if let Some(value) = required_string(
        upstream,
        "release_tag",
        &format!("{path}.upstream"),
        diagnostics,
    ) {
        index.upstream.release_tag = value;
    }
    if let Some(value) = required_string(
        upstream,
        "source_commit",
        &format!("{path}.upstream"),
        diagnostics,
    ) {
        if !is_hex(&value, 40) {
            diagnostics.push(Diagnostic::new(
                "PROFILE-SCHEMA",
                format!("{path}.upstream.source_commit"),
                "must be a 40-character hexadecimal commit",
            ));
        }
        index.upstream.source_commit = value;
    }
    if let Some(artifact) = required_object(
        upstream,
        "artifact",
        &format!("{path}.upstream"),
        diagnostics,
    ) {
        for field in ["format", "url", "digest_url", "signature_url", "keys_url"] {
            if let Some(value) = required_string(
                artifact,
                field,
                &format!("{path}.upstream.artifact"),
                diagnostics,
            ) && matches!(field, "url" | "digest_url" | "signature_url" | "keys_url")
                && !value.starts_with("https://")
            {
                diagnostics.push(Diagnostic::new(
                    "PROFILE-PROVENANCE",
                    format!("{path}.upstream.artifact.{field}"),
                    "upstream verification URLs must use HTTPS",
                ));
            }
        }
        if let Some(value) = required_string(
            artifact,
            "filename",
            &format!("{path}.upstream.artifact"),
            diagnostics,
        ) {
            index.upstream.artifact = value;
        }
        if let Some(value) = required_string(
            artifact,
            "digest",
            &format!("{path}.upstream.artifact"),
            diagnostics,
        ) {
            if !is_hex(&value, 128) {
                diagnostics.push(Diagnostic::new(
                    "PROFILE-SCHEMA",
                    format!("{path}.upstream.artifact.digest"),
                    "must be a 128-character hexadecimal SHA-512 digest",
                ));
            }
            index.upstream.digest = value;
        }
        match required_string(
            artifact,
            "digest_algorithm",
            &format!("{path}.upstream.artifact"),
            diagnostics,
        ) {
            Some(value) if !value.eq_ignore_ascii_case("SHA-512") => {
                diagnostics.push(Diagnostic::new(
                    "PROFILE-SCHEMA",
                    format!("{path}.upstream.artifact.digest_algorithm"),
                    "must be SHA-512",
                ))
            }
            _ => {}
        }
        if let Some(verification) = required_object(
            artifact,
            "verification",
            &format!("{path}.upstream.artifact"),
            diagnostics,
        ) {
            let _ = required_bool(
                verification,
                "verified",
                &format!("{path}.upstream.artifact.verification"),
                diagnostics,
            );
            for field in ["verified_at", "method", "official_digest_source", "notes"] {
                let _ = required_string(
                    verification,
                    field,
                    &format!("{path}.upstream.artifact.verification"),
                    diagnostics,
                );
            }
            validate_pgp_verification(
                verification,
                &format!("{path}.upstream.artifact.verification"),
                diagnostics,
            );
        }
    }
    validate_runtime_assumptions(root, profile_path, object, diagnostics);
}

fn checklist_source_path(
    root: &Path,
    profile_path: &Path,
    object: &Map<String, Value>,
    diagnostics: &mut Diagnostics,
) -> Option<PathBuf> {
    let profile_display = display_path(root, profile_path);
    let source = required_object(object, "checklist_source", &profile_display, diagnostics)?;
    let source_path = required_string(
        source,
        "path",
        &format!("{profile_display}.checklist_source"),
        diagnostics,
    )?;
    let path = safe_relative_path(&source_path).map(|_| root.join(&source_path));
    if path.is_none() {
        diagnostics.push(Diagnostic::new(
            "PROFILE-PATH",
            format!("{profile_display}.checklist_source.path"),
            "must be a safe repository-relative path",
        ));
    }
    if let Some(value) = required_string(
        source,
        "inventory_status_value",
        &format!("{profile_display}.checklist_source"),
        diagnostics,
    ) && value.trim().is_empty()
    {
        diagnostics.push(Diagnostic::new(
            "PROFILE-SCHEMA",
            format!("{profile_display}.checklist_source.inventory_status_value"),
            "must not be empty",
        ));
    }
    let _ = required_string(
        source,
        "inventory_status_meaning",
        &format!("{profile_display}.checklist_source"),
        diagnostics,
    );
    path
}

fn validate_runtime_assumptions(
    root: &Path,
    profile_path: &Path,
    object: &Map<String, Value>,
    diagnostics: &mut Diagnostics,
) {
    let profile_display = display_path(root, profile_path);
    let Some(assumptions) =
        required_object(object, "runtime_assumptions", &profile_display, diagnostics)
    else {
        return;
    };
    if let Some(java) = required_object(
        assumptions,
        "java",
        &format!("{profile_display}.runtime_assumptions"),
        diagnostics,
    ) {
        let minimum = required_u64(
            java,
            "minimum_major",
            &format!("{profile_display}.runtime_assumptions.java"),
            diagnostics,
        );
        let recommended = required_u64(
            java,
            "recommended_major",
            &format!("{profile_display}.runtime_assumptions.java"),
            diagnostics,
        );
        if let (Some(minimum), Some(recommended)) = (minimum, recommended)
            && recommended < minimum
        {
            diagnostics.push(Diagnostic::new(
                "PROFILE-SCHEMA",
                format!("{profile_display}.runtime_assumptions.java.recommended_major"),
                "recommended Java major must not be lower than minimum_major",
            ));
        }
        for field in ["distribution_policy", "vendor", "classpath_policy"] {
            let _ = required_string(
                java,
                field,
                &format!("{profile_display}.runtime_assumptions.java"),
                diagnostics,
            );
        }
    }
    if let Some(platform) = required_object(
        assumptions,
        "platform",
        &format!("{profile_display}.runtime_assumptions"),
        diagnostics,
    ) {
        let _ = required_array(
            platform,
            "target_operating_systems",
            &format!("{profile_display}.runtime_assumptions.platform"),
            diagnostics,
        );
        for field in [
            "target_triple_policy",
            "filesystem_policy",
            "network_policy",
            "process_policy",
        ] {
            let _ = required_string(
                platform,
                field,
                &format!("{profile_display}.runtime_assumptions.platform"),
                diagnostics,
            );
        }
    }
    if let Some(determinism) = required_object(
        assumptions,
        "determinism",
        &format!("{profile_display}.runtime_assumptions"),
        diagnostics,
    ) {
        for field in [
            "locale",
            "timezone",
            "default_charset",
            "hostname_policy",
            "random_seed",
            "clock_mode",
            "source_date_epoch",
        ] {
            let _ = required_string(
                determinism,
                field,
                &format!("{profile_display}.runtime_assumptions.determinism"),
                diagnostics,
            );
        }
        let _ = required_array(
            determinism,
            "environment_allowlist",
            &format!("{profile_display}.runtime_assumptions.determinism"),
            diagnostics,
        );
    }
}

fn validate_pgp_verification(
    verification: &Map<String, Value>,
    path: &str,
    diagnostics: &mut Diagnostics,
) {
    let Some(pgp) = verification.get("pgp").and_then(Value::as_object) else {
        return;
    };
    for field in ["signature_url", "keys_url"] {
        if let Some(value) = pgp.get(field).and_then(Value::as_str)
            && !value.starts_with("https://")
        {
            diagnostics.push(Diagnostic::new(
                "PROFILE-PROVENANCE",
                format!("{path}.pgp.{field}"),
                "PGP URLs must use HTTPS",
            ));
        }
    }
    if let Some(status) = pgp.get("status").and_then(Value::as_str)
        && !matches!(
            status,
            "not-run-static" | "not-run" | "verified" | "valid" | "failed" | "unavailable"
        )
    {
        diagnostics.push(Diagnostic::new(
            "PROFILE-PROVENANCE",
            format!("{path}.pgp.status"),
            "PGP status is outside the closed vocabulary",
        ));
    }
    for field in [
        "required_fingerprint",
        "observed_fingerprint",
        "fingerprint",
    ] {
        if let Some(value) = pgp.get(field).and_then(Value::as_str)
            && !is_hex(value, 40)
        {
            diagnostics.push(Diagnostic::new(
                "PROFILE-PROVENANCE",
                format!("{path}.pgp.{field}"),
                "PGP fingerprint must be a 40-character hexadecimal value",
            ));
        }
    }
    if let Some(value) = pgp.get("signature_verified")
        && !value.is_boolean()
    {
        diagnostics.push(Diagnostic::new(
            "PROFILE-PROVENANCE",
            format!("{path}.pgp.signature_verified"),
            "signature_verified must be boolean",
        ));
    }
    if pgp.get("signature_verified") == Some(&Value::Bool(true))
        && pgp
            .get("observed_fingerprint")
            .and_then(Value::as_str)
            .is_none()
    {
        diagnostics.push(Diagnostic::new(
            "PROFILE-PROVENANCE",
            format!("{path}.pgp.observed_fingerprint"),
            "verified PGP signature requires an observed fingerprint",
        ));
    }
}

fn read_inventory(
    root: &Path,
    path: &Path,
    expected_status: &str,
    diagnostics: &mut Diagnostics,
) -> Option<Vec<String>> {
    let display = display_path(root, path);
    let source = match read_bounded_utf8(path, MAX_PROFILE_BYTES) {
        Ok(source) => source,
        Err(error) => {
            diagnostics.push(profile_read_diagnostic(&display, "checklist source", error));
            return None;
        }
    };
    let mut inventory = Vec::new();
    let mut seen = BTreeSet::new();
    for (line_number, line) in source.lines().enumerate() {
        let cells = line.split('|').map(str::trim).collect::<Vec<_>>();
        if cells.len() < 2 || !is_feature_id(cells[1]) {
            continue;
        }
        if cells.len() >= 6 && cells[5] != expected_status {
            diagnostics.push(Diagnostic::new(
                "PROFILE-INVENTORY",
                format!("{display}:{}", line_number + 1),
                format!("checklist status {:?} does not match profile inventory_status_value {expected_status:?}", cells[5]),
            ));
        }
        let id = cells[1].to_owned();
        if !seen.insert(id.clone()) {
            diagnostics.push(Diagnostic::new(
                "PROFILE-INVENTORY",
                format!("{display}:{}", line_number + 1),
                format!("duplicate checklist ID {id}"),
            ));
        }
        inventory.push(id);
    }
    if inventory.len() != EXPECTED_FEATURE_COUNT {
        diagnostics.push(Diagnostic::new(
            "PROFILE-INVENTORY",
            display,
            format!(
                "expected {EXPECTED_FEATURE_COUNT} checklist IDs, found {}",
                inventory.len()
            ),
        ));
    }
    Some(inventory)
}

fn validate_normalization_policies(
    root: &Path,
    profile_path: &Path,
    object: &Map<String, Value>,
    diagnostics: &mut Diagnostics,
    index: &mut ProfileIndex,
) {
    let profile_display = display_path(root, profile_path);
    let Some(policies) = required_array(
        object,
        "normalization_policies",
        &profile_display,
        diagnostics,
    ) else {
        return;
    };
    let mut seen = BTreeMap::<String, usize>::new();
    for (position, value) in policies.iter().enumerate() {
        let path = format!("{profile_display}.normalization_policies[{position}]");
        let Some(policy) = value.as_object() else {
            diagnostics.push(Diagnostic::new(
                "PROFILE-SCHEMA",
                path,
                "policy must be an object",
            ));
            continue;
        };
        if let Some(id) = required_nonempty_string(policy, "id", &path, diagnostics) {
            if let Some(previous) = seen.insert(id.to_owned(), position) {
                diagnostics.push(Diagnostic::new(
                    "PROFILE-DUPLICATE-ID",
                    format!("{path}.id"),
                    format!(
                        "duplicate normalization policy ID {id}; first appears at index {previous}"
                    ),
                ));
            }
            index.normalization_ids.insert(id);
        }
        for field in ["name", "rule"] {
            let _ = required_string(policy, field, &path, diagnostics);
        }
    }
}

fn validate_features(
    root: &Path,
    profile_path: &Path,
    object: &Map<String, Value>,
    diagnostics: &mut Diagnostics,
    index: &mut ProfileIndex,
    inventory: Option<&Vec<String>>,
) {
    let profile_display = display_path(root, profile_path);
    let Some(features) = required_array(object, "features", &profile_display, diagnostics) else {
        return;
    };
    let source_status = object
        .get("checklist_source")
        .and_then(Value::as_object)
        .and_then(|value| value.get("inventory_status_value"))
        .and_then(Value::as_str)
        .unwrap_or("TODO");
    let mut seen = BTreeMap::<String, usize>::new();
    for (position, value) in features.iter().enumerate() {
        let path = format!("{profile_display}.features[{position}]");
        let Some(feature) = value.as_object() else {
            diagnostics.push(Diagnostic::new(
                "PROFILE-SCHEMA",
                path,
                "feature must be an object",
            ));
            continue;
        };
        let Some(id) = required_string(feature, "id", &path, diagnostics) else {
            continue;
        };
        if !is_feature_id(&id) {
            diagnostics.push(Diagnostic::new(
                "PROFILE-INVENTORY",
                format!("{path}.id"),
                format!("invalid checklist ID {id:?}"),
            ));
        }
        if let Some(previous) = seen.insert(id.clone(), position) {
            diagnostics.push(Diagnostic::new(
                "PROFILE-DUPLICATE-ID",
                format!("{path}.id"),
                format!("duplicate feature ID {id}; first appears at index {previous}"),
            ));
        }
        index.feature_ids.insert(id.clone());
        if let Some(status) = feature.get("status").and_then(Value::as_str) {
            index.feature_statuses.insert(id.clone(), status.to_owned());
        }
        if let Some(required_fixtures) = feature
            .get("required_oracle_fixture_ids")
            .and_then(Value::as_array)
        {
            index.feature_fixture_ids.insert(
                id.clone(),
                required_fixtures
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect(),
            );
        }
        if let Some(normalizations) = feature
            .get("normalization_policy_refs")
            .and_then(Value::as_array)
        {
            index.feature_normalization_ids.insert(
                id.clone(),
                normalizations
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect(),
            );
        }
        if let Some(boundaries) = feature
            .get("external_runtime_boundary_ids")
            .and_then(Value::as_array)
        {
            index.feature_boundaries.insert(
                id.clone(),
                boundaries
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect(),
            );
        }
        for field in ["surface", "tier", "required_evidence"] {
            let _ = required_string(feature, field, &path, diagnostics);
        }
        match required_string(feature, "status", &path, diagnostics) {
            Some(status) if !ALLOWED_STATUSES.contains(&status.as_str()) => {
                diagnostics.push(Diagnostic::new(
                    "PROFILE-STATUS",
                    format!("{path}.status"),
                    format!("unknown status {status:?}; allowed values are {ALLOWED_STATUSES:?}"),
                ))
            }
            _ => {}
        }
        match required_string(feature, "inventory_status", &path, diagnostics) {
            Some(status) if status != source_status => diagnostics.push(Diagnostic::new(
                "PROFILE-INVENTORY",
                format!("{path}.inventory_status"),
                format!("must match checklist_source.inventory_status_value {source_status:?}"),
            )),
            _ => {}
        }
        for field in [
            "required_oracle_fixture_ids",
            "normalization_policy_refs",
            "external_runtime_boundary_ids",
        ] {
            let _ = required_id_array(feature, field, &path, diagnostics);
        }
    }
    if features.len() != EXPECTED_FEATURE_COUNT {
        diagnostics.push(Diagnostic::new(
            "PROFILE-INVENTORY",
            format!("{profile_display}.features"),
            format!(
                "expected {EXPECTED_FEATURE_COUNT} feature records, found {}",
                features.len()
            ),
        ));
    }
    if let Some(inventory) = inventory {
        let feature_ids = seen.keys().cloned().collect::<BTreeSet<_>>();
        let inventory_ids = inventory.iter().cloned().collect::<BTreeSet<_>>();
        for id in inventory_ids.difference(&feature_ids) {
            diagnostics.push(Diagnostic::new(
                "PROFILE-INVENTORY",
                format!("{profile_display}.features"),
                format!("checklist ID {id} is missing from profile features"),
            ));
        }
        for id in feature_ids.difference(&inventory_ids) {
            diagnostics.push(Diagnostic::new(
                "PROFILE-INVENTORY",
                format!("{profile_display}.features"),
                format!("profile feature ID {id} is absent from checklist source"),
            ));
        }
    }
}

fn validate_boundaries(
    root: &Path,
    profile_path: &Path,
    object: &Map<String, Value>,
    diagnostics: &mut Diagnostics,
    index: &mut ProfileIndex,
) {
    let profile_display = display_path(root, profile_path);
    let Some(boundaries) = required_array(
        object,
        "external_runtime_boundaries",
        &profile_display,
        diagnostics,
    ) else {
        return;
    };
    let mut seen = BTreeMap::<String, usize>::new();
    for (position, value) in boundaries.iter().enumerate() {
        let path = format!("{profile_display}.external_runtime_boundaries[{position}]");
        let Some(boundary) = value.as_object() else {
            diagnostics.push(Diagnostic::new(
                "PROFILE-SCHEMA",
                path,
                "boundary must be an object",
            ));
            continue;
        };
        if let Some(id) = required_nonempty_string(boundary, "id", &path, diagnostics) {
            if let Some(previous) = seen.insert(id.to_owned(), position) {
                diagnostics.push(Diagnostic::new(
                    "PROFILE-DUPLICATE-ID",
                    format!("{path}.id"),
                    format!("duplicate boundary ID {id}; first appears at index {previous}"),
                ));
            }
            index.boundary_ids.insert(id.clone());
            if let Some(applies_to) = boundary.get("applies_to").and_then(Value::as_array) {
                index.boundary_features.insert(
                    id,
                    applies_to
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect(),
                );
            }
        }
        for field in ["name", "kind", "scope", "boundary_rule"] {
            let _ = required_string(boundary, field, &path, diagnostics);
        }
        match required_string(boundary, "status", &path, diagnostics) {
            Some(status) if !ALLOWED_STATUSES.contains(&status.as_str()) => {
                diagnostics.push(Diagnostic::new(
                    "PROFILE-STATUS",
                    format!("{path}.status"),
                    format!("unknown status {status:?}; allowed values are {ALLOWED_STATUSES:?}"),
                ))
            }
            _ => {}
        }
        let _ = required_id_array(boundary, "applies_to", &path, diagnostics);
    }
}

fn validate_fixture_catalog(
    root: &Path,
    profile_path: &Path,
    object: &Map<String, Value>,
    diagnostics: &mut Diagnostics,
    index: &mut ProfileIndex,
) {
    let profile_display = display_path(root, profile_path);
    let Some(fixtures) = required_array(
        object,
        "oracle_fixture_catalog",
        &profile_display,
        diagnostics,
    ) else {
        return;
    };
    let mut seen = BTreeMap::<String, usize>::new();
    for (position, value) in fixtures.iter().enumerate() {
        let path = format!("{profile_display}.oracle_fixture_catalog[{position}]");
        let Some(fixture) = value.as_object() else {
            diagnostics.push(Diagnostic::new(
                "PROFILE-SCHEMA",
                path,
                "fixture catalog entry must be an object",
            ));
            continue;
        };
        if let Some(id) = required_nonempty_string(fixture, "id", &path, diagnostics) {
            if let Some(previous) = seen.insert(id.to_owned(), position) {
                diagnostics.push(Diagnostic::new(
                    "PROFILE-DUPLICATE-ID",
                    format!("{path}.id"),
                    format!("duplicate fixture family ID {id}; first appears at index {previous}"),
                ));
            }
            index.fixture_ids.insert(id.clone());
            if let Some(status) = fixture.get("status").and_then(Value::as_str) {
                index.fixture_statuses.insert(id.clone(), status.to_owned());
            }
        }
        for field in ["kind", "description"] {
            let _ = required_string(fixture, field, &path, diagnostics);
        }
        if required_bool(fixture, "materialized", &path, diagnostics) == Some(true)
            && let Some(id) = fixture.get("id").and_then(Value::as_str)
        {
            index.materialized_fixture_ids.insert(id.to_owned());
        }
        let fixture_status = required_string(fixture, "status", &path, diagnostics);
        match fixture_status.as_deref() {
            Some(status) if !ALLOWED_STATUSES.contains(&status) => {
                diagnostics.push(Diagnostic::new(
                    "PROFILE-STATUS",
                    format!("{path}.status"),
                    format!("unknown status {status:?}; allowed values are {ALLOWED_STATUSES:?}"),
                ))
            }
            _ => {}
        }
        if fixture_status.as_deref() == Some("verified")
            && fixture.get("materialized").and_then(Value::as_bool) != Some(true)
        {
            diagnostics.push(Diagnostic::new(
                "PROFILE-CLAIM",
                format!("{path}.materialized"),
                "verified fixture evidence must be materialized",
            ));
        }
        if fixture_status.as_deref() == Some("verified")
            && let Some(id) = fixture.get("id").and_then(Value::as_str)
        {
            index.verified_fixture_ids.insert(id.to_owned());
        }
        if let Some(id) = fixture.get("id").and_then(Value::as_str) {
            let normalizations = fixture
                .get("normalization_policy_refs")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect();
            index
                .fixture_normalization_ids
                .insert(id.to_owned(), normalizations);
            let boundaries = fixture
                .get("external_runtime_boundary_ids")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect();
            index.fixture_boundaries.insert(id.to_owned(), boundaries);
        }
        let _ = required_id_array(fixture, "external_runtime_boundary_ids", &path, diagnostics);
    }
}

fn validate_cross_references(
    root: &Path,
    profile_path: &Path,
    object: &Map<String, Value>,
    diagnostics: &mut Diagnostics,
    index: &ProfileIndex,
) {
    let profile_display = display_path(root, profile_path);
    let Some(features) = object.get("features").and_then(Value::as_array) else {
        return;
    };
    for (position, value) in features.iter().enumerate() {
        let Some(feature) = value.as_object() else {
            continue;
        };
        let path = format!("{profile_display}.features[{position}]");
        check_refs(
            feature,
            "required_oracle_fixture_ids",
            &path,
            &index.fixture_ids,
            diagnostics,
        );
        check_refs(
            feature,
            "normalization_policy_refs",
            &path,
            &index.normalization_ids,
            diagnostics,
        );
        check_refs(
            feature,
            "external_runtime_boundary_ids",
            &path,
            &index.boundary_ids,
            diagnostics,
        );
        if feature.get("status").and_then(Value::as_str) == Some("verified") {
            for fixture_id in feature
                .get("required_oracle_fixture_ids")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                if !index.materialized_fixture_ids.contains(fixture_id) {
                    diagnostics.push(Diagnostic::new(
                        "PROFILE-CLAIM",
                        format!("{path}.required_oracle_fixture_ids"),
                        format!(
                            "verified feature requires materialized immutable fixture evidence {fixture_id:?}"
                        ),
                    ));
                }
            }
        }
    }
    if let Some(fixtures) = object
        .get("oracle_fixture_catalog")
        .and_then(Value::as_array)
    {
        for (position, value) in fixtures.iter().enumerate() {
            let Some(fixture) = value.as_object() else {
                continue;
            };
            check_refs(
                fixture,
                "external_runtime_boundary_ids",
                &format!("{profile_display}.oracle_fixture_catalog[{position}]"),
                &index.boundary_ids,
                diagnostics,
            );
        }
    }
    if let Some(boundaries) = object
        .get("external_runtime_boundaries")
        .and_then(Value::as_array)
    {
        for (position, value) in boundaries.iter().enumerate() {
            let Some(boundary) = value.as_object() else {
                continue;
            };
            check_refs(
                boundary,
                "applies_to",
                &format!("{profile_display}.external_runtime_boundaries[{position}]"),
                &index.feature_ids,
                diagnostics,
            );
        }
    }

    // Boundary ownership is bidirectional.  A feature row is the source of
    // truth for the boundary union, while each boundary's applies_to list is
    // the inverse index.  Do not infer a missing boundary from the other side:
    // a mismatch is an explicit profile error (for example PROXY-003 in a
    // stale profile), not a reason to silently classify a fixture as local or
    // external.
    for (feature_id, boundaries) in &index.feature_boundaries {
        for boundary_id in boundaries {
            if !index
                .boundary_features
                .get(boundary_id)
                .is_some_and(|features| features.contains(feature_id))
            {
                diagnostics.push(Diagnostic::new(
                    "PROFILE-BOUNDARY",
                    format!("{profile_display}.features[{feature_id}].external_runtime_boundary_ids"),
                    format!("boundary {boundary_id:?} does not list feature {feature_id:?} in applies_to"),
                ));
            }
        }
    }
    for (boundary_id, features) in &index.boundary_features {
        for feature_id in features {
            if !index
                .feature_boundaries
                .get(feature_id)
                .is_some_and(|boundaries| boundaries.contains(boundary_id))
            {
                diagnostics.push(Diagnostic::new(
                    "PROFILE-BOUNDARY",
                    format!(
                        "{profile_display}.external_runtime_boundaries[{boundary_id}].applies_to"
                    ),
                    format!("feature {feature_id:?} does not reference boundary {boundary_id:?}"),
                ));
            }
        }
    }
}

fn check_refs(
    object: &Map<String, Value>,
    field: &str,
    parent_path: &str,
    known: &BTreeSet<String>,
    diagnostics: &mut Diagnostics,
) {
    let Some(values) = object.get(field).and_then(Value::as_array) else {
        return;
    };
    for (position, value) in values.iter().enumerate() {
        let Some(reference) = value.as_str() else {
            continue;
        };
        if !known.contains(reference) {
            diagnostics.push(Diagnostic::new(
                "PROFILE-REFERENCE",
                format!("{parent_path}.{field}[{position}]"),
                format!("unknown reference {reference:?}"),
            ));
        }
    }
}

fn required_object<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    parent_path: &str,
    diagnostics: &mut Diagnostics,
) -> Option<&'a Map<String, Value>> {
    match object.get(field) {
        Some(value) => match value.as_object() {
            Some(value) => Some(value),
            None => {
                diagnostics.push(Diagnostic::new(
                    "PROFILE-SCHEMA",
                    format!("{parent_path}.{field}"),
                    "must be an object",
                ));
                None
            }
        },
        None => {
            diagnostics.push(Diagnostic::new(
                "PROFILE-SCHEMA",
                format!("{parent_path}.{field}"),
                "required field is missing",
            ));
            None
        }
    }
}

fn required_array<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    parent_path: &str,
    diagnostics: &mut Diagnostics,
) -> Option<&'a Vec<Value>> {
    match object.get(field) {
        Some(value) => match value.as_array() {
            Some(value) => Some(value),
            None => {
                diagnostics.push(Diagnostic::new(
                    "PROFILE-SCHEMA",
                    format!("{parent_path}.{field}"),
                    "must be an array",
                ));
                None
            }
        },
        None => {
            diagnostics.push(Diagnostic::new(
                "PROFILE-SCHEMA",
                format!("{parent_path}.{field}"),
                "required field is missing",
            ));
            None
        }
    }
}

fn required_string(
    object: &Map<String, Value>,
    field: &str,
    parent_path: &str,
    diagnostics: &mut Diagnostics,
) -> Option<String> {
    match object.get(field) {
        Some(value) => match value.as_str() {
            Some(value) => Some(value.to_owned()),
            None => {
                diagnostics.push(Diagnostic::new(
                    "PROFILE-SCHEMA",
                    format!("{parent_path}.{field}"),
                    "must be a string",
                ));
                None
            }
        },
        None => {
            diagnostics.push(Diagnostic::new(
                "PROFILE-SCHEMA",
                format!("{parent_path}.{field}"),
                "required field is missing",
            ));
            None
        }
    }
}

fn required_nonempty_string(
    object: &Map<String, Value>,
    field: &str,
    parent_path: &str,
    diagnostics: &mut Diagnostics,
) -> Option<String> {
    let value = required_string(object, field, parent_path, diagnostics)?;
    if value.trim().is_empty() {
        diagnostics.push(Diagnostic::new(
            "PROFILE-SCHEMA",
            format!("{parent_path}.{field}"),
            "must not be empty",
        ));
    }
    Some(value)
}

fn required_u64(
    object: &Map<String, Value>,
    field: &str,
    parent_path: &str,
    diagnostics: &mut Diagnostics,
) -> Option<u64> {
    match object.get(field) {
        Some(value) => match value.as_u64() {
            Some(value) => Some(value),
            None => {
                diagnostics.push(Diagnostic::new(
                    "PROFILE-SCHEMA",
                    format!("{parent_path}.{field}"),
                    "must be a non-negative integer",
                ));
                None
            }
        },
        None => {
            diagnostics.push(Diagnostic::new(
                "PROFILE-SCHEMA",
                format!("{parent_path}.{field}"),
                "required field is missing",
            ));
            None
        }
    }
}

fn required_bool(
    object: &Map<String, Value>,
    field: &str,
    parent_path: &str,
    diagnostics: &mut Diagnostics,
) -> Option<bool> {
    match object.get(field) {
        Some(value) => match value.as_bool() {
            Some(value) => Some(value),
            None => {
                diagnostics.push(Diagnostic::new(
                    "PROFILE-SCHEMA",
                    format!("{parent_path}.{field}"),
                    "must be a boolean",
                ));
                None
            }
        },
        None => {
            diagnostics.push(Diagnostic::new(
                "PROFILE-SCHEMA",
                format!("{parent_path}.{field}"),
                "required field is missing",
            ));
            None
        }
    }
}

fn required_id_array(
    object: &Map<String, Value>,
    field: &str,
    parent_path: &str,
    diagnostics: &mut Diagnostics,
) -> Option<Vec<String>> {
    let values = required_array(object, field, parent_path, diagnostics)?;
    let mut result = Vec::with_capacity(values.len());
    let mut seen = BTreeSet::new();
    for (position, value) in values.iter().enumerate() {
        let path = format!("{parent_path}.{field}[{position}]");
        match value.as_str() {
            Some(value) if !value.trim().is_empty() => {
                if !seen.insert(value.to_owned()) {
                    diagnostics.push(Diagnostic::new(
                        "PROFILE-DUPLICATE-REFERENCE",
                        path,
                        format!("duplicate reference {value:?}"),
                    ));
                }
                result.push(value.to_owned());
            }
            Some(_) => diagnostics.push(Diagnostic::new(
                "PROFILE-SCHEMA",
                path,
                "reference must not be empty",
            )),
            None => diagnostics.push(Diagnostic::new(
                "PROFILE-SCHEMA",
                path,
                "reference must be a string",
            )),
        }
    }
    Some(result)
}

fn safe_relative_path(value: &str) -> Option<()> {
    if value.is_empty() || value.contains('\0') || value.contains('\\') {
        return None;
    }
    let path = Path::new(value);
    if path.is_absolute() {
        return None;
    }
    if path.components().any(|component| {
        matches!(
            component,
            std::path::Component::ParentDir | std::path::Component::RootDir
        )
    }) {
        return None;
    }
    Some(())
}

fn is_profile_id(value: &str) -> bool {
    !value.is_empty()
        && value.chars().all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || character == '-'
                || character == '.'
        })
}

pub(crate) fn is_feature_id(value: &str) -> bool {
    let Some((prefix, number)) = value.split_once('-') else {
        return false;
    };
    FEATURE_PREFIXES.contains(&prefix)
        && number.len() == 3
        && number.chars().all(|character| character.is_ascii_digit())
}

fn is_iso_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit())
}

fn is_hex(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_json_limits(
    value: &Value,
    path: &str,
    depth: usize,
    nodes: &mut usize,
    diagnostics: &mut Diagnostics,
) {
    *nodes = nodes.saturating_add(1);
    if *nodes > MAX_PROFILE_JSON_NODES {
        diagnostics.push(Diagnostic::new(
            "PROFILE-BOUNDS",
            path,
            format!("JSON node count exceeds {MAX_PROFILE_JSON_NODES}"),
        ));
        return;
    }
    if depth > MAX_PROFILE_JSON_DEPTH {
        diagnostics.push(Diagnostic::new(
            "PROFILE-BOUNDS",
            path,
            format!("JSON nesting exceeds {MAX_PROFILE_JSON_DEPTH} levels"),
        ));
        return;
    }
    match value {
        Value::Object(object) => {
            for (field, value) in object {
                validate_json_limits(
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
                validate_json_limits(
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
}

pub(crate) fn display_path(root: &Path, path: &Path) -> String {
    let relative = path.strip_prefix(root).unwrap_or(path);
    relative.to_string_lossy().replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::{
        ProfileIndex, ProfileReadError, is_feature_id, read_bounded_handle, read_bounded_utf8,
        safe_relative_path, validate_cross_references,
    };
    use crate::diagnostics::Diagnostics;
    use serde_json::json;
    use std::collections::{BTreeMap, BTreeSet};

    fn must_ok<T, E>(result: Result<T, E>, context: &str) -> Option<T> {
        assert!(result.is_ok(), "{context}");
        result.ok()
    }

    fn must_err<T, E>(result: Result<T, E>, context: &str) -> Option<E> {
        assert!(result.is_err(), "{context}");
        result.err()
    }

    #[test]
    fn feature_ids_are_strict_and_inventory_shaped() {
        assert!(is_feature_id("TEST-001"));
        assert!(is_feature_id("CLI-999"));
        assert!(!is_feature_id("test-001"));
        assert!(!is_feature_id("TEST-01"));
        assert!(!is_feature_id("UNKNOWN-001"));
    }

    #[test]
    fn paths_reject_escape_and_platform_ambivalence() {
        assert!(safe_relative_path("plan.jmx").is_some());
        assert!(safe_relative_path("expected/semantic.json").is_some());
        assert!(safe_relative_path("../outside").is_none());
        assert!(safe_relative_path("/tmp/outside").is_none());
        assert!(safe_relative_path(r"expected\\semantic.json").is_none());
    }

    #[test]
    fn boundary_union_mismatch_is_reported_without_inference() {
        let value = json!({
            "features": [{
                "id": "TEST-001",
                "required_oracle_fixture_ids": [],
                "normalization_policy_refs": [],
                "external_runtime_boundary_ids": ["EXT-A"]
            }],
            "external_runtime_boundaries": [{
                "id": "EXT-A",
                "applies_to": ["TEST-002"]
            }]
        });
        let Some(object) = value.as_object() else {
            return;
        };
        let mut feature_boundaries = BTreeMap::new();
        feature_boundaries.insert("TEST-001".to_owned(), BTreeSet::from(["EXT-A".to_owned()]));
        let mut boundary_features = BTreeMap::new();
        boundary_features.insert("EXT-A".to_owned(), BTreeSet::from(["TEST-002".to_owned()]));
        let index = ProfileIndex {
            profile_id: "test".to_owned(),
            feature_ids: BTreeSet::from(["TEST-001".to_owned(), "TEST-002".to_owned()]),
            feature_boundaries,
            boundary_ids: BTreeSet::from(["EXT-A".to_owned()]),
            boundary_features,
            ..ProfileIndex::default()
        };
        let mut diagnostics = Diagnostics::default();
        validate_cross_references(
            std::path::Path::new("."),
            std::path::Path::new("profile.json"),
            object,
            &mut diagnostics,
            &index,
        );
        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "PROFILE-BOUNDARY")
                .count(),
            2
        );
    }

    #[test]
    fn malformed_profile_file_in_a_temporary_tree_is_rejected() {
        use std::fs;
        use std::sync::atomic::{AtomicUsize, Ordering};

        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let directory = std::env::temp_dir().join(format!(
            "jmeter-rs-xtask-profile-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let created = fs::create_dir_all(&directory);
        assert!(created.is_ok(), "create test tree: {created:?}");
        if created.is_err() {
            return;
        }
        let path = directory.join("profile.json");
        let written = fs::write(&path, b"{ not-json");
        assert!(written.is_ok(), "write invalid profile: {written:?}");
        if written.is_err() {
            let _ = fs::remove_dir_all(directory);
            return;
        }
        let (diagnostics, index) = super::check(&directory, &path);
        assert!(index.is_none());
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "PROFILE-JSON")
        );
        let removed = fs::remove_dir_all(directory);
        assert!(removed.is_ok(), "remove test tree: {removed:?}");
    }

    #[test]
    fn bounded_profile_read_rejects_initial_overlimit() {
        use std::fs;
        use std::sync::atomic::{AtomicUsize, Ordering};

        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let directory = std::env::temp_dir().join(format!(
            "jmeter-rs-xtask-profile-overlimit-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        assert!(fs::create_dir_all(&directory).is_ok());
        let path = directory.join("profile.json");
        assert!(fs::write(&path, b"012345").is_ok());

        let Some(error) = must_err(read_bounded_utf8(&path, 4), "overlimit input must fail") else {
            return;
        };
        assert!(matches!(error, ProfileReadError::TooLarge { limit: 4 }));
        assert!(fs::remove_dir_all(directory).is_ok());
    }

    #[test]
    fn bounded_profile_read_detects_growth_after_open() {
        use std::fs::{self, File, OpenOptions};
        use std::sync::atomic::{AtomicUsize, Ordering};

        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let directory = std::env::temp_dir().join(format!(
            "jmeter-rs-xtask-profile-growth-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        assert!(fs::create_dir_all(&directory).is_ok());
        let path = directory.join("profile.json");
        assert!(fs::write(&path, b"12").is_ok());
        let Some(file) = must_ok(File::open(&path), "open profile handle") else {
            return;
        };
        let Some(metadata) = must_ok(file.metadata(), "stat profile handle") else {
            return;
        };
        let Some(mut writer) = must_ok(
            OpenOptions::new().append(true).open(&path),
            "open profile writer",
        ) else {
            return;
        };
        use std::io::Write;
        if must_ok(writer.write_all(b"3456"), "append profile bytes").is_none() {
            return;
        }

        let Some(error) = must_err(
            read_bounded_handle(file, &path, &metadata, 4),
            "growth beyond the bound must fail",
        ) else {
            return;
        };
        assert!(matches!(error, ProfileReadError::Grew { limit: 4 }));
        assert!(fs::remove_dir_all(directory).is_ok());
    }

    #[test]
    fn bounded_profile_read_detects_truncation_after_open() {
        use std::fs::{self, File, OpenOptions};
        use std::sync::atomic::{AtomicUsize, Ordering};

        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let directory = std::env::temp_dir().join(format!(
            "jmeter-rs-xtask-profile-truncate-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        assert!(fs::create_dir_all(&directory).is_ok());
        let path = directory.join("profile.json");
        assert!(fs::write(&path, b"012345").is_ok());
        let Some(file) = must_ok(File::open(&path), "open profile handle") else {
            return;
        };
        let Some(metadata) = must_ok(file.metadata(), "stat profile handle") else {
            return;
        };
        let Some(truncator) = must_ok(
            OpenOptions::new().write(true).open(&path),
            "open profile truncator",
        ) else {
            return;
        };
        if must_ok(truncator.set_len(2), "truncate profile").is_none() {
            return;
        }

        let Some(error) = must_err(
            read_bounded_handle(file, &path, &metadata, 8),
            "truncation must fail closed",
        ) else {
            return;
        };
        assert!(matches!(error, ProfileReadError::Truncated));
        assert!(fs::remove_dir_all(directory).is_ok());
    }

    #[test]
    fn bounded_profile_read_rejects_non_regular_input() {
        use std::fs;
        use std::sync::atomic::{AtomicUsize, Ordering};

        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let directory = std::env::temp_dir().join(format!(
            "jmeter-rs-xtask-profile-nonfile-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        assert!(fs::create_dir_all(&directory).is_ok());

        let Some(error) = must_err(
            read_bounded_utf8(&directory, 8),
            "directory input must fail",
        ) else {
            return;
        };
        assert!(matches!(
            error,
            ProfileReadError::NonRegular | ProfileReadError::Open(_)
        ));
        assert!(fs::remove_dir_all(directory).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn bounded_profile_read_rejects_symlink_input() {
        use std::fs;
        use std::os::unix::fs::symlink;
        use std::sync::atomic::{AtomicUsize, Ordering};

        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let directory = std::env::temp_dir().join(format!(
            "jmeter-rs-xtask-profile-symlink-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        assert!(fs::create_dir_all(&directory).is_ok());
        let target = directory.join("target.json");
        let link = directory.join("profile.json");
        assert!(fs::write(&target, b"{}").is_ok());
        assert!(symlink(&target, &link).is_ok());

        let Some(error) = must_err(read_bounded_utf8(&link, 8), "symlink input must fail") else {
            return;
        };
        assert!(matches!(error, ProfileReadError::Symlink));
        assert!(fs::remove_dir_all(directory).is_ok());
    }
}
