// SPDX-License-Identifier: Apache-2.0
//! Deterministic CFG-002 inventory generation from the pinned JMeter files.
//!
//! This task deliberately reads only the local, profile-pinned distribution.
//! It does not load Java properties, start JMeter, invoke a process, or make a
//! network request.  Property entries are kept in source order (including
//! commented defaults, duplicates, and empty values) so the generated file is
//! a source inventory rather than a lossy effective-property map.

use crate::diagnostics::{Diagnostic, Diagnostics};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

const SCHEMA_ID: &str = "jmeter-rs.cfg-002-property-inventory";
const SCHEMA_VERSION: u64 = 1;
const PROFILE_ID: &str = "jmeter-5.6.3";
const PROFILE_VERSION: &str = "5.6.3";
const PROFILE_DECLARATION_VERSION: u64 = 2;
const PROFILE_SOURCE_COMMIT: &str = "34a2785748e9e0b14702595e8682c387869deda3";
const PROFILE_ARTIFACT_SHA512: &str = "387fadca903ee0aa30e3f2115fdfedb3898b102e6b9fe7cc3942703094bd2e65b235df2b0c6d0d3248e74c9a7950a36e42625fd74425368342c12e40b0163076";
const DEFAULT_SOURCE_RELATIVE: &str = "jmeter-oracle-cache/apache-jmeter-5.6.3/bin";
const DEFAULT_OUTPUT_RELATIVE: &str = "compat/inventory/jmeter-5.6.3/properties.json";
const GENERATOR_PATH: &str = "tools/xtask/src/property_inventory.rs";
const GENERATOR_COMMAND: &str = "cargo xtask property-inventory --generate";
const UPSTREAM_PROJECT: &str = "Apache JMeter";
const UPSTREAM_RELEASE: &str = "rel/v5.6.3";
const UPSTREAM_SOURCE_URL_BASE: &str =
    "https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/bin/";
const APACHE_LICENSE_EXPRESSION: &str = "Apache-2.0";
const APACHE_LICENSE_URL: &str = "https://www.apache.org/licenses/LICENSE-2.0";
const APACHE_SOURCE_LICENSE_PATH: &str = "LICENSE";
const APACHE_SOURCE_NOTICE_PATH: &str = "NOTICE";
const REPOSITORY_LICENSE_PATH: &str = "LICENSE";
const REPOSITORY_NOTICE_PATH: &str = "NOTICE";
const PROVENANCE_REVIEW_DOCUMENT: &str = "docs/third-party-provenance.md";
const APACHE_ATTRIBUTION: &str =
    "Apache JMeter; Copyright 1998-2024 The Apache Software Foundation";

// The distribution is pinned and small.  These bounds are intentionally
// finite so a malformed or accidentally substituted source cannot cause an
// unbounded allocation in the repository task.
const MAX_SOURCE_FILE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_SOURCE_TOTAL_BYTES: u64 = 32 * 1024 * 1024;
const MAX_SOURCE_LINE_BYTES: usize = 256 * 1024;
const MAX_SOURCE_LINES: usize = 100_000;
const MAX_ENTRIES_PER_FILE: usize = 50_000;
const MAX_TOTAL_ENTRIES: usize = 200_000;
const MAX_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;

const SOURCE_FILE_NAMES: [&str; 6] = [
    "jmeter.properties",
    "reportgenerator.properties",
    "saveservice.properties",
    "system.properties",
    "upgrade.properties",
    "user.properties",
];

/// The requested action for the CFG-002 inventory command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    /// Rebuild the checked-in inventory from the local pinned source.
    Generate,
    /// Compare the checked-in inventory with a fresh deterministic build.
    Check,
}

/// Run the property inventory action and return stable diagnostics.
pub(crate) fn run(
    root: &Path,
    action: Action,
    source_directory: Option<&Path>,
    output_path: Option<&Path>,
) -> Diagnostics {
    let source_directory = source_directory
        .map(Path::to_path_buf)
        .unwrap_or_else(|| root.join(DEFAULT_SOURCE_RELATIVE));
    let output_path = output_path
        .map(Path::to_path_buf)
        .unwrap_or_else(|| root.join(DEFAULT_OUTPUT_RELATIVE));
    let mut diagnostics = Diagnostics::default();
    let Some(output) = build_inventory(root, &source_directory, &output_path, &mut diagnostics)
    else {
        diagnostics.sort_deterministically();
        return diagnostics;
    };
    let expected = match serde_json::to_vec_pretty(&output) {
        Ok(mut bytes) => {
            bytes.push(b'\n');
            if bytes.len() as u64 > MAX_OUTPUT_BYTES {
                diagnostics.push(Diagnostic::new(
                    "INVENTORY-BOUNDS",
                    display_path(root, &output_path),
                    format!("generated inventory exceeds the {MAX_OUTPUT_BYTES}-byte output bound"),
                ));
                diagnostics.sort_deterministically();
                return diagnostics;
            }
            bytes
        }
        Err(error) => {
            diagnostics.push(Diagnostic::new(
                "INVENTORY-JSON",
                display_path(root, &output_path),
                format!("cannot serialize generated inventory: {error}"),
            ));
            diagnostics.sort_deterministically();
            return diagnostics;
        }
    };

    match action {
        Action::Generate => write_inventory(root, &output_path, &expected, &mut diagnostics),
        Action::Check => check_inventory(root, &output_path, &expected, &mut diagnostics),
    }
    diagnostics.sort_deterministically();
    diagnostics
}

fn build_inventory(
    root: &Path,
    source_directory: &Path,
    output_path: &Path,
    diagnostics: &mut Diagnostics,
) -> Option<Value> {
    let source_display = display_path(root, source_directory);
    match fs::symlink_metadata(source_directory) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            diagnostics.push(Diagnostic::new(
                "INVENTORY-SOURCE",
                source_display,
                "pinned JMeter properties directory must not be a symlink",
            ));
            return None;
        }
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => {
            diagnostics.push(Diagnostic::new(
                "INVENTORY-SOURCE",
                source_display,
                "pinned JMeter properties path must be a directory",
            ));
            return None;
        }
        Err(error) => {
            diagnostics.push(Diagnostic::new(
                "INVENTORY-SOURCE",
                source_display,
                format!("cannot inspect pinned JMeter properties directory: {error}"),
            ));
            return None;
        }
    }

    let mut source_files = Vec::with_capacity(SOURCE_FILE_NAMES.len());
    let mut total_bytes = 0_u64;
    let mut total_entries = 0_usize;
    for file_name in SOURCE_FILE_NAMES {
        let path = source_directory.join(file_name);
        let Some(source_file) = read_source_file(
            root,
            &path,
            &mut total_bytes,
            &mut total_entries,
            diagnostics,
        ) else {
            continue;
        };
        source_files.push(source_file);
    }
    if source_files.len() != SOURCE_FILE_NAMES.len() {
        return None;
    }
    if total_bytes > MAX_SOURCE_TOTAL_BYTES {
        diagnostics.push(Diagnostic::new(
            "INVENTORY-BOUNDS",
            source_display,
            format!("source files exceed the {MAX_SOURCE_TOTAL_BYTES}-byte aggregate bound"),
        ));
        return None;
    }
    if total_entries > MAX_TOTAL_ENTRIES {
        diagnostics.push(Diagnostic::new(
            "INVENTORY-BOUNDS",
            source_display,
            format!("source entries exceed the {MAX_TOTAL_ENTRIES}-entry aggregate bound"),
        ));
        return None;
    }

    let mut active_entries = 0_usize;
    let mut commented_entries = 0_usize;
    let mut empty_defaults = 0_usize;
    let mut keys = BTreeMap::<String, usize>::new();
    for file in &source_files {
        for entry in &file.entries {
            if entry
                .get("active")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                active_entries = active_entries.saturating_add(1);
            } else {
                commented_entries = commented_entries.saturating_add(1);
            }
            if entry
                .get("default")
                .and_then(Value::as_str)
                .is_some_and(str::is_empty)
            {
                empty_defaults = empty_defaults.saturating_add(1);
            }
            if let Some(key) = entry.get("key").and_then(Value::as_str) {
                *keys.entry(key.to_owned()).or_default() += 1;
            }
        }
    }
    let duplicate_key_count = keys.values().filter(|count| **count > 1).count();

    let source_root = relative_or_display(root, source_directory);
    let output_display = relative_or_display(root, output_path);
    let provenance_files = SOURCE_FILE_NAMES
        .iter()
        .zip(source_files.iter())
        .map(|(file_name, file)| {
            json!({
                "path": format!("bin/{file_name}"),
                "url": upstream_source_url(file_name),
                "local_path": file.as_value["path"],
                "hash_algorithm": "SHA-256",
                "sha256": file.as_value["sha256"],
                "bytes": file.as_value["bytes"],
                "line_ending": file.as_value["line_ending"],
            })
        })
        .collect::<Vec<_>>();
    let files = source_files
        .into_iter()
        .map(|file| file.as_value)
        .collect::<Vec<_>>();
    Some(json!({
        "schema_id": SCHEMA_ID,
        "schema_version": SCHEMA_VERSION,
        "compatibility_ids": ["CFG-002"],
        "profile": {
            "id": PROFILE_ID,
            "version": PROFILE_VERSION,
            "profile_version": PROFILE_DECLARATION_VERSION,
            "source_commit": PROFILE_SOURCE_COMMIT,
            "artifact": "apache-jmeter-5.6.3.zip",
            "artifact_sha512": PROFILE_ARTIFACT_SHA512,
        },
        "inventory_status": "inventory-only",
        "conformance_evidence": false,
        "generated_by": {
            "command": GENERATOR_COMMAND,
            "generator": GENERATOR_PATH,
            "output": output_display,
            "source_policy": "Read-only local files from the pinned Apache JMeter 5.6.3 distribution; no JVM, process, or network access.",
        },
        "provenance": {
            "upstream": {
                "project": UPSTREAM_PROJECT,
                "release": UPSTREAM_RELEASE,
                "source_commit": PROFILE_SOURCE_COMMIT,
                "artifact": "apache-jmeter-5.6.3.zip",
                "artifact_sha512": PROFILE_ARTIFACT_SHA512,
                "source_files": provenance_files,
            },
            "license": {
                "expression": APACHE_LICENSE_EXPRESSION,
                "source_license_url": APACHE_LICENSE_URL,
                "source_license_path": APACHE_SOURCE_LICENSE_PATH,
                "source_notice_path": APACHE_SOURCE_NOTICE_PATH,
                "repository_license": REPOSITORY_LICENSE_PATH,
                "repository_notice": REPOSITORY_NOTICE_PATH,
                "attribution": APACHE_ATTRIBUTION,
            },
            "transformation": {
                "kind": "derived-property-inventory",
                "command": GENERATOR_COMMAND,
                "generator": GENERATOR_PATH,
                "operations": [
                    "Read only the six listed regular files from the ignored local extraction and record each raw-byte SHA-256, byte count, line-ending kind, and source-relative path.",
                    "Parse declaration candidates in physical source order while retaining duplicate occurrences, active/commented state, exact source spelling, continuation spans, and empty defaults.",
                    "Copy a family only from a bounded comment heading with deterministic separator context; leave consumer and sensitivity classifications unresolved when source text cannot establish them.",
                    "Serialize stable pretty JSON with a trailing line feed; no Java properties decoding, effective merge, archive extraction, or source retrieval is performed.",
                ],
                "modification_notice": "The output is a selected, machine-readable inventory rather than a byte-for-byte copy of the Apache source files; raw declaration lines and source hashes are retained for traceability.",
            },
            "redistribution_review": {
                "status": "reviewed",
                "decision": "Redistribute the generated inventory under the repository Apache-2.0 terms with Apache JMeter attribution in the root NOTICE.",
                "review_documents": [
                    REPOSITORY_LICENSE_PATH,
                    REPOSITORY_NOTICE_PATH,
                    PROVENANCE_REVIEW_DOCUMENT,
                ],
                "included_material": "Generated metadata and selected source declaration spelling from the six Apache JMeter properties files.",
                "excluded_material": [
                    "The Apache JMeter archive and extracted distribution",
                    "JMeter binaries and third-party JARs",
                    "The complete upstream JMeter LICENSE, NOTICE, and third-party notice bundle",
                    "Raw oracle output, logs, credentials, and dependency caches",
                ],
            },
        },
        "source": {
            "directory": source_root,
            "hash_algorithm": "SHA-256",
            "files": files,
        },
        "summary": {
            "source_file_count": SOURCE_FILE_NAMES.len(),
            "source_bytes": total_bytes,
            "entry_count": total_entries,
            "active_entry_count": active_entries,
            "commented_entry_count": commented_entries,
            "empty_default_count": empty_defaults,
            "duplicate_key_count": duplicate_key_count,
        },
        "classification_policy": {
            "family": "Only an unambiguous comment section heading is used; otherwise family is unresolved.",
            "consumer": "Consumer identity is unresolved because a properties declaration does not prove all runtime readers.",
            "sensitivity": "Sensitivity is unresolved because a property name/value alone does not prove handling or secrecy requirements.",
            "default": "The default field is the exact source spelling after the Java-properties separator; no effective-property merge or escape normalization is performed.",
        },
    }))
}

struct SourceFile {
    as_value: Value,
    entries: Vec<Value>,
}

fn read_source_file(
    root: &Path,
    path: &Path,
    total_bytes: &mut u64,
    total_entries: &mut usize,
    diagnostics: &mut Diagnostics,
) -> Option<SourceFile> {
    let display = display_path(root, path);
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            diagnostics.push(Diagnostic::new(
                "INVENTORY-SOURCE",
                display,
                format!("cannot inspect pinned properties file: {error}"),
            ));
            return None;
        }
    };
    if !metadata.file_type().is_file() {
        diagnostics.push(Diagnostic::new(
            "INVENTORY-SOURCE",
            display,
            "pinned properties source must be a regular file",
        ));
        return None;
    }
    if metadata.len() > MAX_SOURCE_FILE_BYTES {
        diagnostics.push(Diagnostic::new(
            "INVENTORY-BOUNDS",
            display,
            format!("source file exceeds the {MAX_SOURCE_FILE_BYTES}-byte bound"),
        ));
        return None;
    }
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => {
            diagnostics.push(Diagnostic::new(
                "INVENTORY-SOURCE",
                display,
                format!("cannot read pinned properties file: {error}"),
            ));
            return None;
        }
    };
    if bytes.len() as u64 != metadata.len() {
        diagnostics.push(Diagnostic::new(
            "INVENTORY-SOURCE",
            display,
            "properties file changed while it was being read",
        ));
        return None;
    }
    *total_bytes = total_bytes.saturating_add(bytes.len() as u64);
    if *total_bytes > MAX_SOURCE_TOTAL_BYTES {
        diagnostics.push(Diagnostic::new(
            "INVENTORY-BOUNDS",
            display.clone(),
            format!("source files exceed the {MAX_SOURCE_TOTAL_BYTES}-byte aggregate bound"),
        ));
        return None;
    }
    let source_hash = sha256_hex(&bytes);
    let text = match String::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => {
            diagnostics.push(Diagnostic::new(
                "INVENTORY-ENCODING",
                display,
                "pinned properties file is not UTF-8; refusing lossy inventory output",
            ));
            return None;
        }
    };
    let lines = split_lines(&text);
    if lines.len() > MAX_SOURCE_LINES {
        diagnostics.push(Diagnostic::new(
            "INVENTORY-BOUNDS",
            display,
            format!("source file exceeds the {MAX_SOURCE_LINES}-line bound"),
        ));
        return None;
    }
    for line in &lines {
        if line.raw.len() > MAX_SOURCE_LINE_BYTES {
            diagnostics.push(Diagnostic::new(
                "INVENTORY-BOUNDS",
                display.clone(),
                format!(
                    "source line {} exceeds the {MAX_SOURCE_LINE_BYTES}-byte bound",
                    line.number
                ),
            ));
            return None;
        }
    }

    let headings = detect_headings(&lines);
    let mut entries = Vec::new();
    let mut occurrences = BTreeMap::<String, usize>::new();
    let mut index = 0_usize;
    while index < lines.len() {
        let line = &lines[index];
        let Some(mut parsed) = parse_property_line(&line.raw) else {
            index = index.saturating_add(1);
            continue;
        };
        let mut end = index;
        while has_continuation(&lines[end].raw) && end + 1 < lines.len() {
            end += 1;
        }
        let raw = lines[index..=end]
            .iter()
            .map(|line| line.raw.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        if end > index {
            for continuation in &lines[index.saturating_add(1)..=end] {
                parsed.default_source.push('\n');
                parsed.default_source.push_str(&continuation.raw);
            }
        }
        let occurrence = occurrences.entry(parsed.key.clone()).or_default();
        *occurrence = occurrence.saturating_add(1);
        let family = headings
            .iter()
            .rev()
            .find(|heading| heading.line <= line.number)
            .map(|heading| (heading.family.clone(), heading.family_id.clone()));
        entries.push(entry_value(
            entries.len().saturating_add(1),
            line.number,
            end.saturating_sub(index).saturating_add(1),
            &parsed,
            *occurrence,
            raw,
            family,
        ));
        if entries.len() > MAX_ENTRIES_PER_FILE {
            diagnostics.push(Diagnostic::new(
                "INVENTORY-BOUNDS",
                display,
                format!("source file exceeds the {MAX_ENTRIES_PER_FILE}-entry bound"),
            ));
            return None;
        }
        *total_entries = total_entries.saturating_add(1);
        if *total_entries > MAX_TOTAL_ENTRIES {
            diagnostics.push(Diagnostic::new(
                "INVENTORY-BOUNDS",
                path.to_string_lossy().into_owned(),
                format!("source entries exceed the {MAX_TOTAL_ENTRIES}-entry aggregate bound"),
            ));
            return None;
        }
        index = end.saturating_add(1);
    }

    let line_ending = line_ending_kind(&text);
    let relative_path = relative_or_display(root, path);
    Some(SourceFile {
        as_value: json!({
            "path": relative_path,
            "sha256": source_hash,
            "hash_algorithm": "SHA-256",
            "bytes": text.len(),
            "line_count": lines.len(),
            "line_ending": line_ending,
            "entries": entries.clone(),
        }),
        entries,
    })
}

#[derive(Clone, Debug)]
struct SourceLine {
    number: usize,
    raw: String,
}

fn split_lines(text: &str) -> Vec<SourceLine> {
    text.split_terminator('\n')
        .enumerate()
        .map(|(index, line)| SourceLine {
            number: index.saturating_add(1),
            raw: line.strip_suffix('\r').unwrap_or(line).to_owned(),
        })
        .collect()
}

fn line_ending_kind(text: &str) -> &'static str {
    let crlf = text.as_bytes().windows(2).any(|window| window == b"\r\n");
    let bare_lf =
        text.as_bytes().iter().enumerate().any(|(index, byte)| {
            *byte == b'\n' && (index == 0 || text.as_bytes()[index - 1] != b'\r')
        });
    let bare_cr = text
        .as_bytes()
        .iter()
        .enumerate()
        .any(|(index, byte)| *byte == b'\r' && text.as_bytes().get(index + 1) != Some(&b'\n'));
    match (crlf, bare_lf, bare_cr) {
        (true, false, false) => "CRLF",
        (false, true, false) => "LF",
        (false, false, true) => "CR",
        _ => "mixed-or-none",
    }
}

#[derive(Clone, Debug)]
struct ParsedProperty {
    key: String,
    default: String,
    default_source: String,
    separator: char,
    active: bool,
}

fn parse_property_line(line: &str) -> Option<ParsedProperty> {
    let leading_trimmed = line.trim_start();
    let (active, comment_compact, body) = match leading_trimmed.as_bytes().first() {
        Some(b'#' | b'!') => (
            false,
            leading_trimmed[1..]
                .chars()
                .next()
                .is_some_and(|character| !character.is_whitespace()),
            leading_trimmed[1..].trim_start(),
        ),
        Some(_) => (true, true, leading_trimmed),
        None => return None,
    };
    if body.starts_with("http://") || body.starts_with("https://") {
        return None;
    }
    let (index, initial_separator) = find_separator(body)?;
    let initial_separator_width = body[index..]
        .chars()
        .next()
        .map_or(initial_separator.len_utf8(), char::len_utf8);
    let mut explicit_separator = (initial_separator != ' ').then_some(initial_separator);
    if initial_separator == ' ' {
        let after_whitespace = skip_whitespace(body, index.saturating_add(initial_separator_width));
        explicit_separator = body[after_whitespace..]
            .chars()
            .next()
            .filter(|character| matches!(character, '=' | ':'));
    }
    let key = body[..index].trim_end().to_owned();
    if key.is_empty() || has_unescaped_whitespace(&key) {
        return None;
    }
    if !active
        && (explicit_separator.is_none()
            || (!comment_compact && explicit_separator == Some(':'))
            || !key.chars().any(|character| character.is_ascii_alphabetic()))
    {
        return None;
    }
    let mut separator = initial_separator;
    let mut value_start = index.saturating_add(initial_separator_width);
    let mut default_source_start = value_start;
    value_start = skip_whitespace(body, value_start);
    if separator == ' '
        && let Some(character @ ('=' | ':')) = body[value_start..].chars().next()
    {
        separator = character;
        value_start = value_start.saturating_add(character.len_utf8());
        default_source_start = value_start;
        value_start = skip_whitespace(body, value_start);
    }
    Some(ParsedProperty {
        key,
        default: body[value_start..].to_owned(),
        default_source: body[default_source_start..].to_owned(),
        separator,
        active,
    })
}

fn skip_whitespace(value: &str, mut offset: usize) -> usize {
    while let Some(character) = value[offset..].chars().next() {
        if !character.is_whitespace() {
            break;
        }
        offset = offset.saturating_add(character.len_utf8());
    }
    offset
}

fn find_separator(body: &str) -> Option<(usize, char)> {
    let mut escaped = false;
    for (index, character) in body.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if character == '\\' {
            escaped = true;
            continue;
        }
        if matches!(character, '=' | ':') {
            return Some((index, character));
        }
        if character.is_whitespace() {
            return Some((index, ' '));
        }
    }
    None
}

fn has_unescaped_whitespace(value: &str) -> bool {
    let mut escaped = false;
    for character in value.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        if character == '\\' {
            escaped = true;
        } else if character.is_whitespace() {
            return true;
        }
    }
    false
}

fn has_continuation(line: &str) -> bool {
    let backslashes = line
        .chars()
        .rev()
        .take_while(|character| *character == '\\')
        .count();
    backslashes % 2 == 1
}

#[derive(Clone, Debug)]
struct Heading {
    line: usize,
    family: String,
    family_id: String,
}

fn detect_headings(lines: &[SourceLine]) -> Vec<Heading> {
    let mut result = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        let Some(body) = comment_body(&line.raw) else {
            continue;
        };
        let body = body.trim();
        if body.is_empty() || is_separator(body) || body.contains(['=', ':']) {
            continue;
        }
        let previous_is_separator = index > 0
            && comment_body(&lines[index - 1].raw).is_some_and(|value| is_separator(value.trim()));
        let heading_has_closing_separator = if previous_is_separator {
            let mut found = false;
            for candidate in &lines[index.saturating_add(1)..] {
                if candidate.raw.trim().is_empty() {
                    continue;
                }
                let Some(candidate_body) = comment_body(&candidate.raw) else {
                    break;
                };
                if is_separator(candidate_body.trim()) {
                    found = true;
                    break;
                }
                if parse_property_line(&candidate.raw).is_some() {
                    break;
                }
            }
            found
        } else {
            false
        };
        let opening_separator_omitted = index > 0
            && lines[index - 1].raw.trim().is_empty()
            && lines
                .get(index + 1)
                .and_then(|line| comment_body(&line.raw))
                .is_some_and(|value| is_separator(value.trim()));
        if !(heading_has_closing_separator || opening_separator_omitted) {
            continue;
        }
        if let Some(family) = family_slug(body) {
            result.push(Heading {
                line: line.number,
                family: body.to_owned(),
                family_id: family,
            });
        }
    }
    result
}

fn comment_body(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    match trimmed.as_bytes().first() {
        Some(b'#' | b'!') => Some(trimmed[1..].trim_start()),
        _ => None,
    }
}

fn is_separator(value: &str) -> bool {
    value.len() >= 3
        && value
            .chars()
            .all(|character| matches!(character, '-' | '=' | '#' | '_'))
}

fn family_slug(value: &str) -> Option<String> {
    let mut result = String::new();
    let mut pending_dash = false;
    for character in value.chars() {
        if character.is_ascii_alphanumeric() {
            if pending_dash && !result.is_empty() {
                result.push('-');
            }
            pending_dash = false;
            result.push(character.to_ascii_lowercase());
        } else {
            pending_dash = true;
        }
    }
    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

fn entry_value(
    ordinal: usize,
    line: usize,
    span: usize,
    parsed: &ParsedProperty,
    occurrence: usize,
    raw: String,
    family: Option<(String, String)>,
) -> Value {
    let (family_value, family_id, family_status, family_reason) = match family {
        Some((family, family_id)) => (
            Value::String(family),
            Value::String(family_id),
            Value::String("deterministic".to_owned()),
            Value::Null,
        ),
        None => (
            Value::Null,
            Value::Null,
            Value::String("unresolved".to_owned()),
            Value::String("no unambiguous comment-derived section heading applies".to_owned()),
        ),
    };
    json!({
        "ordinal": ordinal,
        "line": line,
        "span": span,
        "raw": raw,
        "key": parsed.key,
        "default": parsed.default_source,
        "default_value": parsed.default,
        "default_is_empty": parsed.default_source.is_empty(),
        "separator": parsed.separator.to_string(),
        "active": parsed.active,
        "occurrence": occurrence,
        "family": family_value,
        "family_id": family_id,
        "family_status": family_status,
        "family_reason": family_reason,
        "consumer": "unresolved",
        "consumer_reason": "the source declaration does not prove the complete set of runtime consumers",
        "sensitivity": "unresolved",
        "sensitivity_reason": "sensitivity cannot be established from a property declaration alone",
    })
}

fn check_inventory(
    root: &Path,
    output_path: &Path,
    expected: &[u8],
    diagnostics: &mut Diagnostics,
) {
    let display = display_path(root, output_path);
    let metadata = match fs::symlink_metadata(output_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            diagnostics.push(Diagnostic::new(
                "INVENTORY-DRIFT",
                display,
                "generated inventory is missing; run cargo xtask property-inventory --generate",
            ));
            return;
        }
        Err(error) => {
            diagnostics.push(Diagnostic::new(
                "INVENTORY-IO",
                display,
                format!("cannot inspect generated inventory: {error}"),
            ));
            return;
        }
    };
    if !metadata.file_type().is_file() {
        diagnostics.push(Diagnostic::new(
            "INVENTORY-IO",
            display,
            "generated inventory must be a regular file",
        ));
        return;
    }
    if metadata.len() > MAX_OUTPUT_BYTES {
        diagnostics.push(Diagnostic::new(
            "INVENTORY-BOUNDS",
            display,
            format!("generated inventory exceeds the {MAX_OUTPUT_BYTES}-byte bound"),
        ));
        return;
    }
    let actual = match fs::read(output_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            diagnostics.push(Diagnostic::new(
                "INVENTORY-IO",
                display,
                format!("cannot read generated inventory: {error}"),
            ));
            return;
        }
    };
    if actual != expected {
        diagnostics.push(Diagnostic::new(
            "INVENTORY-DRIFT",
            display,
            format!(
                "generated inventory differs from pinned source (expected sha256 {}, found {})",
                sha256_hex(expected),
                sha256_hex(&actual)
            ),
        ));
    }
}

fn write_inventory(
    root: &Path,
    output_path: &Path,
    contents: &[u8],
    diagnostics: &mut Diagnostics,
) {
    let display = display_path(root, output_path);
    if let Ok(metadata) = fs::symlink_metadata(output_path)
        && metadata.file_type().is_symlink()
    {
        diagnostics.push(Diagnostic::new(
            "INVENTORY-IO",
            display,
            "refusing to overwrite a generated-inventory symlink",
        ));
        return;
    }
    let Some(parent) = output_path.parent() else {
        diagnostics.push(Diagnostic::new(
            "INVENTORY-IO",
            display,
            "generated inventory has no parent directory",
        ));
        return;
    };
    if let Err(error) = fs::create_dir_all(parent) {
        diagnostics.push(Diagnostic::new(
            "INVENTORY-IO",
            display,
            format!("cannot create generated inventory directory: {error}"),
        ));
        return;
    }
    if let Err(error) = fs::write(output_path, contents) {
        diagnostics.push(Diagnostic::new(
            "INVENTORY-IO",
            display,
            format!("cannot write generated inventory: {error}"),
        ));
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(digest.len().saturating_mul(2));
    for byte in digest {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    output
}

fn upstream_source_url(file_name: &str) -> String {
    format!("{UPSTREAM_SOURCE_URL_BASE}{file_name}")
}

fn relative_or_display(root: &Path, path: &Path) -> String {
    display_path(root, path)
}

fn display_path(root: &Path, path: &Path) -> String {
    let relative = path.strip_prefix(root).unwrap_or(path);
    relative.to_string_lossy().replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::{Action, MAX_SOURCE_FILE_BYTES, parse_property_line, run, sha256_hex};
    use serde_json::Value;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn property_entries_keep_duplicates_order_and_empty_defaults() {
        let first = parse_property_line("#alpha=");
        let second = parse_property_line("alpha=one");
        let third = parse_property_line("alpha=two");
        assert!(first.is_some());
        assert!(second.is_some());
        assert!(third.is_some());
        let first = first.unwrap_or_else(|| unreachable!("asserted property parse"));
        let second = second.unwrap_or_else(|| unreachable!("asserted property parse"));
        let third = third.unwrap_or_else(|| unreachable!("asserted property parse"));
        assert!(!first.active);
        assert!(second.active);
        assert_eq!(first.key, second.key);
        assert_eq!(first.default, "");
        assert_eq!(second.default, "one");
        assert_eq!(third.default, "two");
        let unicode_space = parse_property_line("unicode\u{2003}=value")
            .unwrap_or_else(|| unreachable!("asserted property parse"));
        assert_eq!(unicode_space.default, "value");
    }

    #[test]
    fn non_property_comments_are_not_invented_as_entries() {
        assert!(parse_property_line("# https://example.test/a=b").is_none());
        assert!(parse_property_line("# A sentence with = punctuation").is_none());
        assert!(parse_property_line("#key=value").is_some());
        assert!(parse_property_line("# key = value").is_some());
        assert!(parse_property_line("#key:value").is_some());
        assert!(parse_property_line("# Caution : prose").is_none());
        assert!(parse_property_line("#\u{2003}Caution : prose").is_none());
    }

    #[test]
    fn generated_inventory_is_reproducible_and_check_detects_drift() {
        let tree = TestTree::new();
        let source = tree
            .root
            .join("jmeter-oracle-cache/apache-jmeter-5.6.3/bin");
        assert!(fs::create_dir_all(&source).is_ok());
        for name in super::SOURCE_FILE_NAMES {
            let contents = if name == "jmeter.properties" {
                "#---\n# XML Parser\n#---\n#alpha=\nalpha=one\nalpha=two\ncontinued=one\\\n  two\n"
            } else if name == "reportgenerator.properties" {
                "#key=one\\\n# second\n"
            } else {
                "# sample\n#beta=\n"
            };
            assert!(fs::write(source.join(name), contents).is_ok());
        }
        let generated = run(&tree.root, Action::Generate, None, None);
        assert!(generated.is_empty(), "generate diagnostics: {generated:?}");
        let output = tree
            .root
            .join("compat/inventory/jmeter-5.6.3/properties.json");
        let document: Value =
            serde_json::from_slice(&fs::read(&output).unwrap_or_default()).unwrap_or(Value::Null);
        assert_eq!(document["compatibility_ids"][0], "CFG-002");
        assert_eq!(document["conformance_evidence"], false);
        assert_eq!(
            document["provenance"]["upstream"]["source_commit"],
            super::PROFILE_SOURCE_COMMIT
        );
        assert_eq!(
            document["provenance"]["upstream"]["source_files"]
                .as_array()
                .map(Vec::len),
            Some(6)
        );
        assert_eq!(
            document["provenance"]["upstream"]["source_files"][0]["sha256"],
            document["source"]["files"][0]["sha256"]
        );
        assert_eq!(
            document["provenance"]["license"]["expression"],
            "Apache-2.0"
        );
        assert_eq!(
            document["provenance"]["license"]["source_notice_path"],
            "NOTICE"
        );
        assert_eq!(
            document["provenance"]["license"]["repository_notice"],
            "NOTICE"
        );
        assert_eq!(
            document["provenance"]["transformation"]["command"],
            super::GENERATOR_COMMAND
        );
        assert_eq!(
            document["provenance"]["redistribution_review"]["status"],
            "reviewed"
        );
        assert_eq!(
            document["source"]["files"].as_array().map(Vec::len),
            Some(6)
        );
        let first_entry = &document["source"]["files"][0]["entries"][0];
        assert_eq!(first_entry["occurrence"], 1);
        assert_eq!(first_entry["family"], "XML Parser");
        assert_eq!(first_entry["family_status"], "deterministic");
        assert_eq!(first_entry["consumer"], "unresolved");
        assert_eq!(first_entry["sensitivity"], "unresolved");
        let continued = document["source"]["files"][0]["entries"]
            .as_array()
            .and_then(|entries| entries.iter().find(|entry| entry["key"] == "continued"));
        assert_eq!(
            continued.map(|entry| entry["default"].as_str()),
            Some(Some("one\\\n  two"))
        );
        let report_entry = &document["source"]["files"][1]["entries"][0];
        assert_eq!(report_entry["span"], 2);
        assert_eq!(report_entry["default"], "one\\\n# second");
        let checked = run(&tree.root, Action::Check, None, None);
        assert!(checked.is_empty(), "check diagnostics: {checked:?}");
        let mut bytes = fs::read(&output).unwrap_or_default();
        bytes.extend_from_slice(b"\n");
        assert!(fs::write(&output, bytes).is_ok());
        let drift = run(&tree.root, Action::Check, None, None);
        assert!(drift.iter().any(|item| item.code == "INVENTORY-DRIFT"));
    }

    #[test]
    fn oversized_source_is_rejected_before_inventory_generation() {
        let tree = TestTree::new();
        let source = tree
            .root
            .join("jmeter-oracle-cache/apache-jmeter-5.6.3/bin");
        assert!(fs::create_dir_all(&source).is_ok());
        for name in super::SOURCE_FILE_NAMES {
            let contents = if name == "jmeter.properties" {
                vec![b'x'; MAX_SOURCE_FILE_BYTES as usize + 1]
            } else {
                b"#key=value\n".to_vec()
            };
            assert!(fs::write(source.join(name), contents).is_ok());
        }
        let diagnostics = run(&tree.root, Action::Check, None, None);
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "INVENTORY-BOUNDS")
        );
    }

    #[test]
    fn source_hash_is_sha256_and_build_is_json() {
        let bytes = b"known";
        assert_eq!(
            sha256_hex(bytes),
            "7117fff2d0fd294462b3c802b7cb8753579f23f3946b99cf55f38e873f013f10"
        );
    }

    struct TestTree {
        root: PathBuf,
    }

    impl TestTree {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let root = std::env::temp_dir().join(format!(
                "jmeter-rs-property-inventory-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&root);
            assert!(fs::create_dir_all(&root).is_ok());
            Self { root }
        }
    }

    impl Drop for TestTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}
