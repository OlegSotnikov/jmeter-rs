// SPDX-License-Identifier: Apache-2.0
//! Check and safely regenerate declared profile/source hash references.
//!
//! This task owns a closed reference catalog rather than searching and
//! replacing arbitrary hexadecimal text. It hashes the active profile and the
//! two documentation sources referenced by the fixture provenance schemas,
//! then checks the bridge constant and the exact JSON pointers declared by
//! those schemas. Generation is opt-in and patches only those locations.

use crate::diagnostics::{Diagnostic, Diagnostics};
use crate::profile::display_path;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;

const ACTIVE_PROFILE_RELATIVE: &str = "compat/profiles/jmeter-5.6.3.json";
const ARCHITECTURE_RELATIVE: &str = "docs/architecture.md";
const COMPAT_README_RELATIVE: &str = "compat/README.md";
const BRIDGE_RELATIVE: &str = "crates/bridge-protocol/src/jvm_capability.rs";
const BRIDGE_CONSTANT: &str = "JVM_PROFILE_SHA256_HEX";
const MAX_REFERENCE_FILE_BYTES: u64 = 8 * 1024 * 1024;
const READ_CHUNK_BYTES: usize = 16 * 1024;
const MAX_JSON_DEPTH: usize = 64;
const GENERATOR_COMMAND: &str = "cargo xtask profile-references --generate";

/// The requested profile-reference action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    /// Check every closed reference against its canonical source bytes.
    Check,
    /// Patch only the closed reference fields after all locations validate.
    Generate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SourceKind {
    Profile,
    Architecture,
    CompatReadme,
}

impl SourceKind {
    const fn relative_path(self) -> &'static str {
        match self {
            Self::Profile => ACTIVE_PROFILE_RELATIVE,
            Self::Architecture => ARCHITECTURE_RELATIVE,
            Self::CompatReadme => COMPAT_README_RELATIVE,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct JsonTarget {
    relative_path: &'static str,
    pointer: &'static str,
    guard: Option<(&'static str, &'static str)>,
    source: SourceKind,
    role: &'static str,
}

const JSON_TARGETS: &[JsonTarget] = &[
    JsonTarget {
        relative_path: "compat/fixtures/jmeter-5.6.3/harness/manifest.json",
        pointer: "/profile/sha256",
        guard: Some(("/profile/path", ACTIVE_PROFILE_RELATIVE)),
        source: SourceKind::Profile,
        role: "harness manifest profile pin",
    },
    JsonTarget {
        relative_path: "compat/fixtures/jmeter-5.6.3/harness/manifest.json",
        pointer: "/repository_inputs/profile/0/sha256",
        guard: Some(("/repository_inputs/profile/0/path", ACTIVE_PROFILE_RELATIVE)),
        source: SourceKind::Profile,
        role: "harness repository-input profile pin",
    },
    JsonTarget {
        relative_path: "compat/fixtures/jmeter-5.6.3/harness/provenance.json",
        pointer: "/inputs/profile_sha256",
        guard: None,
        source: SourceKind::Profile,
        role: "harness provenance profile hash",
    },
    JsonTarget {
        relative_path: "compat/fixtures/jmeter-5.6.3/harness/evidence-unavailable.json",
        pointer: "/profile_ref/sha256",
        guard: Some(("/profile_ref/path", ACTIVE_PROFILE_RELATIVE)),
        source: SourceKind::Profile,
        role: "harness evidence profile reference",
    },
    JsonTarget {
        relative_path: "compat/fixtures/jmeter-5.6.3/harness/evidence-unavailable.json",
        pointer: "/identity/profile_hash/sha256",
        guard: Some(("/identity/profile_hash/path", ACTIVE_PROFILE_RELATIVE)),
        source: SourceKind::Profile,
        role: "harness evidence identity profile hash",
    },
    JsonTarget {
        relative_path: "compat/fixtures/jmeter-5.6.3/processors-extractors/core/provenance.json",
        pointer: "/source_references/0/sha256",
        guard: Some(("/source_references/0/path", ARCHITECTURE_RELATIVE)),
        source: SourceKind::Architecture,
        role: "processor/extractor architecture reference",
    },
    JsonTarget {
        relative_path: "compat/fixtures/jmeter-5.6.3/processors-extractors/core/provenance.json",
        pointer: "/source_references/3/sha256",
        guard: Some(("/source_references/3/path", COMPAT_README_RELATIVE)),
        source: SourceKind::CompatReadme,
        role: "processor/extractor compatibility README reference",
    },
    JsonTarget {
        relative_path: "compat/fixtures/jmeter-5.6.3/processors-extractors/core/provenance.json",
        pointer: "/source_references/4/sha256",
        guard: Some(("/source_references/4/path", ACTIVE_PROFILE_RELATIVE)),
        source: SourceKind::Profile,
        role: "processor/extractor profile reference",
    },
    JsonTarget {
        relative_path: "compat/fixtures/jmeter-5.6.3/processors-extractors/negative-bounds/provenance.json",
        pointer: "/source_references/0/sha256",
        guard: Some(("/source_references/0/path", ARCHITECTURE_RELATIVE)),
        source: SourceKind::Architecture,
        role: "negative processor/extractor architecture reference",
    },
    JsonTarget {
        relative_path: "compat/fixtures/jmeter-5.6.3/processors-extractors/negative-bounds/provenance.json",
        pointer: "/source_references/3/sha256",
        guard: Some(("/source_references/3/path", COMPAT_README_RELATIVE)),
        source: SourceKind::CompatReadme,
        role: "negative processor/extractor compatibility README reference",
    },
    JsonTarget {
        relative_path: "compat/fixtures/jmeter-5.6.3/processors-extractors/negative-bounds/provenance.json",
        pointer: "/source_references/4/sha256",
        guard: Some(("/source_references/4/path", ACTIVE_PROFILE_RELATIVE)),
        source: SourceKind::Profile,
        role: "negative processor/extractor profile reference",
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RustTarget {
    relative_path: &'static str,
    constant: &'static str,
    source: SourceKind,
    role: &'static str,
}

const RUST_TARGETS: &[RustTarget] = &[RustTarget {
    relative_path: BRIDGE_RELATIVE,
    constant: BRIDGE_CONSTANT,
    source: SourceKind::Profile,
    role: "bridge expected profile hash",
}];

#[derive(Clone, Debug)]
struct FilePlan {
    bytes: Vec<u8>,
    patches: Vec<Patch>,
}

#[derive(Clone, Debug)]
struct Patch {
    range: Range<usize>,
    replacement: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
struct SourceDigests {
    profile: String,
    architecture: String,
    compat_readme: String,
}

impl SourceDigests {
    fn get(&self, source: SourceKind) -> &str {
        match source {
            SourceKind::Profile => &self.profile,
            SourceKind::Architecture => &self.architecture,
            SourceKind::CompatReadme => &self.compat_readme,
        }
    }
}

/// Check or safely regenerate all declared profile/source hash references.
pub(crate) fn run(root: &Path, profile_path: &Path, action: Action) -> Diagnostics {
    let mut diagnostics = Diagnostics::default();
    let canonical_profile_path = root.join(ACTIVE_PROFILE_RELATIVE);
    if profile_path != canonical_profile_path {
        diagnostics.push(Diagnostic::new(
            "PROFILE-REFERENCE-SOURCE",
            display_path(root, profile_path),
            format!(
                "profile reference command requires the canonical active profile at {}",
                display_path(root, &canonical_profile_path)
            ),
        ));
        return diagnostics;
    }
    let Some(digests) = read_source_digests(root, profile_path, &mut diagnostics) else {
        diagnostics.sort_deterministically();
        return diagnostics;
    };

    let mut plans = BTreeMap::<PathBuf, FilePlan>::new();
    for target in JSON_TARGETS {
        let path = root.join(target.relative_path);
        if !load_file_plan(root, &path, &mut plans, &mut diagnostics) {
            continue;
        }
        let Some(plan) = plans.get_mut(&path) else {
            continue;
        };
        let document: Value = match serde_json::from_slice(&plan.bytes) {
            Ok(document) => document,
            Err(error) => {
                diagnostics.push(Diagnostic::new(
                    "PROFILE-REFERENCE-SCHEMA",
                    format!("{}#{}", target.relative_path, target.pointer),
                    format!("{} is not valid JSON: {error}", target.role),
                ));
                continue;
            }
        };
        if let Some((guard_pointer, expected_guard)) = target.guard {
            match json_pointer_string(&document, guard_pointer) {
                Ok(actual_guard) if actual_guard == expected_guard => {}
                Ok(actual_guard) => {
                    diagnostics.push(Diagnostic::new(
                        "PROFILE-REFERENCE-SCHEMA",
                        format!("{}#{}", target.relative_path, target.pointer),
                        format!(
                            "{} guard {guard_pointer} names {actual_guard:?}, expected {expected_guard:?}; refusing to patch",
                            target.role
                        ),
                    ));
                    continue;
                }
                Err(error) => {
                    diagnostics.push(Diagnostic::new(
                        "PROFILE-REFERENCE-SCHEMA",
                        format!("{}#{}", target.relative_path, target.pointer),
                        format!("{} guard {guard_pointer} is invalid: {error}", target.role),
                    ));
                    continue;
                }
            }
        }
        let expected = digests.get(target.source);
        let actual = match json_pointer_string(&document, target.pointer) {
            Ok(actual) => actual,
            Err(error) => {
                diagnostics.push(Diagnostic::new(
                    "PROFILE-REFERENCE-SCHEMA",
                    format!("{}#{}", target.relative_path, target.pointer),
                    format!("{}: {error}", target.role),
                ));
                continue;
            }
        };
        if !is_sha256(&actual) {
            diagnostics.push(Diagnostic::new(
                "PROFILE-REFERENCE-SCHEMA",
                format!("{}#{}", target.relative_path, target.pointer),
                format!(
                    "{} is not a lowercase SHA-256 value; refusing to patch",
                    target.role
                ),
            ));
            continue;
        }
        if actual == expected {
            continue;
        }
        if action == Action::Check {
            stale_diagnostic(
                &mut diagnostics,
                target.relative_path,
                target.pointer,
                target.role,
                target.source,
                expected,
                &actual,
            );
            continue;
        }
        let range = match locate_json_string(&plan.bytes, target.pointer) {
            Ok(range) => range,
            Err(error) => {
                diagnostics.push(Diagnostic::new(
                    "PROFILE-REFERENCE-SCHEMA",
                    format!("{}#{}", target.relative_path, target.pointer),
                    format!(
                        "cannot safely locate {} for generation: {error}",
                        target.role
                    ),
                ));
                continue;
            }
        };
        plan.patches.push(Patch {
            range,
            replacement: expected.as_bytes().to_vec(),
        });
    }

    for target in RUST_TARGETS {
        let path = root.join(target.relative_path);
        if !load_file_plan(root, &path, &mut plans, &mut diagnostics) {
            continue;
        }
        let Some(plan) = plans.get_mut(&path) else {
            continue;
        };
        let expected = digests.get(target.source);
        let (actual, range) = match rust_string_constant(&plan.bytes, target.constant) {
            Ok(value) => value,
            Err(error) => {
                diagnostics.push(Diagnostic::new(
                    "PROFILE-REFERENCE-SCHEMA",
                    format!("{}::{}", target.relative_path, target.constant),
                    format!("{}: {error}", target.role),
                ));
                continue;
            }
        };
        if actual == expected {
            continue;
        }
        if action == Action::Check {
            stale_diagnostic(
                &mut diagnostics,
                target.relative_path,
                target.constant,
                target.role,
                target.source,
                expected,
                &actual,
            );
            continue;
        }
        plan.patches.push(Patch {
            range,
            replacement: expected.as_bytes().to_vec(),
        });
    }

    if action == Action::Generate && diagnostics.is_empty() {
        write_plans(root, plans, &mut diagnostics);
    }
    diagnostics.sort_deterministically();
    diagnostics
}

fn read_source_digests(
    root: &Path,
    profile_path: &Path,
    diagnostics: &mut Diagnostics,
) -> Option<SourceDigests> {
    let source_paths = [
        (SourceKind::Profile, profile_path.to_path_buf()),
        (SourceKind::Architecture, root.join(ARCHITECTURE_RELATIVE)),
        (SourceKind::CompatReadme, root.join(COMPAT_README_RELATIVE)),
    ];
    let mut digests = SourceDigests::default();
    for (source, path) in source_paths {
        let display = display_path(root, &path);
        let bytes = match read_bounded_file(&path, MAX_REFERENCE_FILE_BYTES) {
            Ok(bytes) => bytes,
            Err(error) => {
                diagnostics.push(Diagnostic::new(
                    "PROFILE-REFERENCE-SOURCE",
                    display,
                    format!(
                        "cannot hash canonical {} source: {error}",
                        source.relative_path()
                    ),
                ));
                continue;
            }
        };
        let digest = sha256_hex(&bytes);
        match source {
            SourceKind::Profile => digests.profile = digest,
            SourceKind::Architecture => digests.architecture = digest,
            SourceKind::CompatReadme => digests.compat_readme = digest,
        }
    }
    if diagnostics.is_empty() {
        Some(digests)
    } else {
        None
    }
}

fn load_file_plan(
    root: &Path,
    path: &Path,
    plans: &mut BTreeMap<PathBuf, FilePlan>,
    diagnostics: &mut Diagnostics,
) -> bool {
    if plans.contains_key(path) {
        return true;
    }
    let display = display_path(root, path);
    let bytes = match read_bounded_file(path, MAX_REFERENCE_FILE_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => {
            diagnostics.push(Diagnostic::new(
                "PROFILE-REFERENCE-INPUT",
                display,
                format!("cannot read declared reference file: {error}"),
            ));
            return false;
        }
    };
    plans.insert(
        path.to_path_buf(),
        FilePlan {
            bytes,
            patches: Vec::new(),
        },
    );
    true
}

fn stale_diagnostic(
    diagnostics: &mut Diagnostics,
    relative_path: &str,
    location: &str,
    role: &str,
    source: SourceKind,
    expected: &str,
    actual: &str,
) {
    diagnostics.push(Diagnostic::new(
        "PROFILE-REFERENCE-DRIFT",
        format!("{relative_path}#{location}"),
        format!(
            "{role} is stale: found {actual}, expected {expected} (raw-byte SHA-256 of {}); run {GENERATOR_COMMAND} to update only declared references",
            source.relative_path(),
        ),
    ));
}

fn write_plans(root: &Path, plans: BTreeMap<PathBuf, FilePlan>, diagnostics: &mut Diagnostics) {
    for (path, plan) in plans {
        if plan.patches.is_empty() {
            continue;
        }
        let display = display_path(root, &path);
        let Some(contents) = apply_patches(&plan.bytes, &plan.patches, &display, diagnostics)
        else {
            continue;
        };
        if let Err(error) = atomic_replace(&path, &contents) {
            diagnostics.push(Diagnostic::new(
                "PROFILE-REFERENCE-WRITE",
                display,
                format!("cannot atomically update declared references: {error}"),
            ));
        }
    }
}

fn apply_patches(
    original: &[u8],
    patches: &[Patch],
    display: &str,
    diagnostics: &mut Diagnostics,
) -> Option<Vec<u8>> {
    let mut patches = patches.to_vec();
    patches.sort_by_key(|patch| (patch.range.start, patch.range.end));
    for pair in patches.windows(2) {
        if pair[0].range.end > pair[1].range.start {
            diagnostics.push(Diagnostic::new(
                "PROFILE-REFERENCE-SCHEMA",
                display,
                "declared reference locations overlap; refusing to generate",
            ));
            return None;
        }
    }
    let mut output = Vec::with_capacity(original.len());
    let mut cursor = 0;
    for patch in patches {
        if patch.range.end > original.len() || patch.range.start < cursor {
            diagnostics.push(Diagnostic::new(
                "PROFILE-REFERENCE-SCHEMA",
                display,
                "declared reference location is outside the bounded input",
            ));
            return None;
        }
        output.extend_from_slice(&original[cursor..patch.range.start]);
        output.extend_from_slice(&patch.replacement);
        cursor = patch.range.end;
    }
    output.extend_from_slice(&original[cursor..]);
    Some(output)
}

fn atomic_replace(path: &Path, contents: &[u8]) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "declared target must be a regular non-symlink file",
        ));
    }
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "declared target has no parent")
    })?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "declared target has no UTF-8 name",
            )
        })?;
    let permissions = metadata.permissions();
    let temporary = parent.join(format!(".{name}.profile-references.tmp"));
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        let mut file = options.open(&temporary)?;
        file.set_permissions(permissions.clone())?;
        file.write_all(contents)?;
        file.sync_all()?;
        fs::rename(&temporary, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn json_pointer_string(document: &Value, pointer: &str) -> Result<String, String> {
    let mut value = document;
    for segment in pointer_segments(pointer)? {
        value = match value {
            Value::Object(object) => object
                .get(&segment)
                .ok_or_else(|| format!("JSON pointer segment {segment:?} is missing"))?,
            Value::Array(array) => {
                let index = segment
                    .parse::<usize>()
                    .map_err(|_| format!("array pointer segment {segment:?} is not an index"))?;
                array
                    .get(index)
                    .ok_or_else(|| format!("array pointer index {index} is missing"))?
            }
            _ => return Err(format!("cannot descend through JSON value at {segment:?}")),
        };
    }
    value
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| "declared reference value must be a JSON string".to_owned())
}

fn pointer_segments(pointer: &str) -> Result<Vec<String>, String> {
    if pointer.is_empty() {
        return Ok(Vec::new());
    }
    let Some(pointer) = pointer.strip_prefix('/') else {
        return Err("JSON pointer must be empty or start with '/'".to_owned());
    };
    pointer
        .split('/')
        .map(|segment| {
            let mut decoded = String::with_capacity(segment.len());
            let mut chars = segment.chars();
            while let Some(character) = chars.next() {
                if character != '~' {
                    decoded.push(character);
                    continue;
                }
                match chars.next() {
                    Some('0') => decoded.push('~'),
                    Some('1') => decoded.push('/'),
                    _ => return Err("JSON pointer contains an invalid '~' escape".to_owned()),
                }
            }
            Ok(decoded)
        })
        .collect()
}

fn locate_json_string(bytes: &[u8], pointer: &str) -> Result<Range<usize>, String> {
    let target = pointer_segments(pointer)?;
    let mut scanner = JsonScanner {
        bytes,
        position: 0,
        target,
        found: None,
    };
    let mut path = Vec::new();
    scanner.parse_value(&mut path, 0)?;
    scanner.skip_whitespace();
    if scanner.position != bytes.len() {
        return Err("trailing bytes after JSON document".to_owned());
    }
    scanner
        .found
        .ok_or_else(|| "JSON pointer string location is missing".to_owned())
}

struct JsonScanner<'a> {
    bytes: &'a [u8],
    position: usize,
    target: Vec<String>,
    found: Option<Range<usize>>,
}

impl JsonScanner<'_> {
    fn parse_value(&mut self, path: &mut Vec<String>, depth: usize) -> Result<(), String> {
        if depth > MAX_JSON_DEPTH {
            return Err("JSON nesting exceeds the bounded reference depth".to_owned());
        }
        self.skip_whitespace();
        let Some(byte) = self.bytes.get(self.position).copied() else {
            return Err("unexpected end of JSON value".to_owned());
        };
        match byte {
            b'{' => self.parse_object(path, depth + 1),
            b'[' => self.parse_array(path, depth + 1),
            b'"' => {
                let (range, decoded) = self.scan_string()?;
                if *path == self.target {
                    if self.found.is_some() {
                        return Err("JSON pointer resolves more than once".to_owned());
                    }
                    if decoded.len() != range.len() {
                        return Err(
                            "target JSON string uses escapes; refusing to patch it".to_owned()
                        );
                    }
                    self.found = Some(range);
                }
                Ok(())
            }
            b't' => self.scan_literal(b"true"),
            b'f' => self.scan_literal(b"false"),
            b'n' => self.scan_literal(b"null"),
            b'-' | b'0'..=b'9' => self.scan_number(),
            _ => Err(format!("unexpected JSON byte 0x{byte:02x}")),
        }
    }

    fn parse_object(&mut self, path: &mut Vec<String>, depth: usize) -> Result<(), String> {
        self.expect_byte(b'{')?;
        self.skip_whitespace();
        if self.consume_byte(b'}') {
            return Ok(());
        }
        loop {
            self.skip_whitespace();
            let (_, key) = self.scan_string()?;
            self.skip_whitespace();
            self.expect_byte(b':')?;
            path.push(key);
            self.parse_value(path, depth)?;
            path.pop();
            self.skip_whitespace();
            if self.consume_byte(b'}') {
                return Ok(());
            }
            self.expect_byte(b',')?;
        }
    }

    fn parse_array(&mut self, path: &mut Vec<String>, depth: usize) -> Result<(), String> {
        self.expect_byte(b'[')?;
        self.skip_whitespace();
        if self.consume_byte(b']') {
            return Ok(());
        }
        let mut index = 0_usize;
        loop {
            path.push(index.to_string());
            self.parse_value(path, depth)?;
            path.pop();
            index = index.saturating_add(1);
            self.skip_whitespace();
            if self.consume_byte(b']') {
                return Ok(());
            }
            self.expect_byte(b',')?;
        }
    }

    fn scan_string(&mut self) -> Result<(Range<usize>, String), String> {
        let start = self.position;
        self.expect_byte(b'"')?;
        let mut escaped = false;
        while let Some(byte) = self.bytes.get(self.position).copied() {
            self.position += 1;
            if escaped {
                escaped = false;
                continue;
            }
            if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                let end = self.position;
                let decoded = serde_json::from_slice::<String>(&self.bytes[start..end])
                    .map_err(|error| format!("invalid JSON string: {error}"))?;
                return Ok((start + 1..end - 1, decoded));
            }
        }
        Err("unterminated JSON string".to_owned())
    }

    fn scan_literal(&mut self, literal: &[u8]) -> Result<(), String> {
        if self.bytes.get(self.position..self.position + literal.len()) != Some(literal) {
            return Err("invalid JSON literal".to_owned());
        }
        self.position += literal.len();
        Ok(())
    }

    fn scan_number(&mut self) -> Result<(), String> {
        let start = self.position;
        while let Some(byte) = self.bytes.get(self.position).copied() {
            if matches!(byte, b' ' | b'\n' | b'\r' | b'\t' | b',' | b']' | b'}') {
                break;
            }
            self.position += 1;
        }
        if start == self.position {
            Err("empty JSON number".to_owned())
        } else {
            Ok(())
        }
    }

    fn expect_byte(&mut self, expected: u8) -> Result<(), String> {
        if self.consume_byte(expected) {
            Ok(())
        } else {
            Err(format!("expected JSON byte 0x{expected:02x}"))
        }
    }

    fn consume_byte(&mut self, expected: u8) -> bool {
        if self.bytes.get(self.position) == Some(&expected) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn skip_whitespace(&mut self) {
        while matches!(
            self.bytes.get(self.position),
            Some(b' ' | b'\n' | b'\r' | b'\t')
        ) {
            self.position += 1;
        }
    }
}

fn rust_string_constant(bytes: &[u8], constant: &str) -> Result<(String, Range<usize>), String> {
    let marker = format!("pub const {constant}: &str =");
    let mut locations = bytes
        .windows(marker.len())
        .enumerate()
        .filter_map(|(index, window)| (window == marker.as_bytes()).then_some(index));
    let Some(start) = locations.next() else {
        return Err(format!("declaration {constant} is missing"));
    };
    if locations.next().is_some() {
        return Err(format!("declaration {constant} is duplicated"));
    }
    let mut position = start + marker.len();
    while matches!(bytes.get(position), Some(b' ' | b'\t' | b'\r' | b'\n')) {
        position += 1;
    }
    if bytes.get(position) != Some(&b'"') {
        return Err(format!(
            "declaration {constant} must assign a string literal"
        ));
    }
    let value_start = position + 1;
    let value_end = value_start + 64;
    if bytes.get(value_end) != Some(&b'"') {
        return Err(format!(
            "declaration {constant} must contain exactly 64 hex bytes"
        ));
    }
    let mut terminator = value_end + 1;
    while matches!(bytes.get(terminator), Some(b' ' | b'\t' | b'\r' | b'\n')) {
        terminator += 1;
    }
    if bytes.get(terminator) != Some(&b';') {
        return Err(format!("declaration {constant} must terminate with ';'"));
    }
    let value = std::str::from_utf8(&bytes[value_start..value_end])
        .map_err(|_| format!("declaration {constant} is not UTF-8"))?;
    if !is_sha256(value) {
        return Err(format!("declaration {constant} is not lowercase SHA-256"));
    }
    Ok((value.to_owned(), value_start..value_end))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn read_bounded_file(path: &Path, maximum: u64) -> Result<Vec<u8>, String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    options.custom_flags(O_NOFOLLOW | O_NONBLOCK);
    let mut file = options
        .open(path)
        .map_err(|error| format!("open failed: {error}"))?;
    let initial = file
        .metadata()
        .map_err(|error| format!("opened-file metadata failed: {error}"))?;
    validate_opened_path(path, &initial)?;
    if initial.len() > maximum {
        return Err(format!("file exceeds {maximum}-byte bound"));
    }
    let capacity = usize::try_from(maximum.saturating_add(1))
        .map_err(|_| "reference bound cannot fit in memory".to_owned())?;
    let mut bytes = Vec::with_capacity(capacity);
    let mut chunk = [0_u8; READ_CHUNK_BYTES];
    while bytes.len() < capacity {
        let read_length = (capacity - bytes.len()).min(chunk.len());
        let count = file
            .read(&mut chunk[..read_length])
            .map_err(|error| format!("read failed: {error}"))?;
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    if bytes.len() as u64 > maximum {
        return Err(format!("file grew beyond {maximum}-byte bound"));
    }
    let final_metadata = file
        .metadata()
        .map_err(|error| format!("final opened-file metadata failed: {error}"))?;
    validate_opened_path(path, &final_metadata)?;
    if final_metadata.len() != initial.len() || bytes.len() as u64 != initial.len() {
        return Err("file changed while it was being read".to_owned());
    }
    Ok(bytes)
}

fn validate_opened_path(path: &Path, handle: &Metadata) -> Result<(), String> {
    if !handle.is_file() {
        return Err("opened path is not a regular file".to_owned());
    }
    let path_metadata =
        fs::symlink_metadata(path).map_err(|error| format!("path metadata failed: {error}"))?;
    if path_metadata.file_type().is_symlink() {
        return Err("declared path is a symlink".to_owned());
    }
    if !path_metadata.is_file() || !same_file_identity(handle, &path_metadata) {
        return Err("opened file does not match the declared regular path".to_owned());
    }
    Ok(())
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

#[cfg(target_os = "linux")]
const O_NOFOLLOW: i32 = 0o400000;
#[cfg(target_os = "linux")]
const O_NONBLOCK: i32 = 0o4000;

#[cfg(test)]
mod tests {
    use super::{
        ACTIVE_PROFILE_RELATIVE, ARCHITECTURE_RELATIVE, Action, BRIDGE_RELATIVE,
        COMPAT_README_RELATIVE, JSON_TARGETS, SourceKind, is_sha256, json_pointer_string,
        locate_json_string, read_bounded_file, run, rust_string_constant, sha256_hex,
    };
    use crate::Options;
    use serde_json::json;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TempTree {
        root: PathBuf,
    }

    impl TempTree {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(1);
            let root = std::env::temp_dir().join(format!(
                "jmeter-rs-profile-references-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            assert!(fs::create_dir_all(&root).is_ok());
            Self { root }
        }

        fn write(&self, relative: &str, contents: &[u8]) {
            let path = self.root.join(relative);
            if let Some(parent) = path.parent() {
                assert!(fs::create_dir_all(parent).is_ok());
            }
            assert!(fs::write(path, contents).is_ok());
        }

        fn source_hash(&self, relative: &str) -> String {
            sha256_hex(&fs::read(self.root.join(relative)).unwrap_or_default())
        }

        fn seed(&self) -> String {
            let profile = r#"{"profile_id":"jmeter-5.6.3","profile_version":2}"#;
            self.write(ACTIVE_PROFILE_RELATIVE, profile.as_bytes());
            self.write(ARCHITECTURE_RELATIVE, b"architecture\n");
            self.write(COMPAT_README_RELATIVE, b"compat\n");
            let profile_hash = self.source_hash(ACTIVE_PROFILE_RELATIVE);
            let architecture_hash = self.source_hash(ARCHITECTURE_RELATIVE);
            let compat_hash = self.source_hash(COMPAT_README_RELATIVE);
            self.write(
                BRIDGE_RELATIVE,
                format!("pub const JVM_PROFILE_SHA256_HEX: &str = \"{profile_hash}\";\n")
                    .as_bytes(),
            );
            let manifest = json!({
                "profile": {"path": ACTIVE_PROFILE_RELATIVE, "sha256": profile_hash},
                "repository_inputs": {"profile": [{"path": ACTIVE_PROFILE_RELATIVE, "sha256": profile_hash}]}
            });
            self.write(
                "compat/fixtures/jmeter-5.6.3/harness/manifest.json",
                serde_json::to_vec(&manifest).unwrap_or_default().as_slice(),
            );
            let provenance = json!({"inputs": {"profile_sha256": profile_hash}});
            self.write(
                "compat/fixtures/jmeter-5.6.3/harness/provenance.json",
                serde_json::to_vec(&provenance)
                    .unwrap_or_default()
                    .as_slice(),
            );
            let evidence = json!({
                "profile_ref": {"path": ACTIVE_PROFILE_RELATIVE, "sha256": profile_hash},
                "identity": {"profile_hash": {"path": ACTIVE_PROFILE_RELATIVE, "sha256": profile_hash}}
            });
            self.write(
                "compat/fixtures/jmeter-5.6.3/harness/evidence-unavailable.json",
                serde_json::to_vec(&evidence).unwrap_or_default().as_slice(),
            );
            for relative in [
                "compat/fixtures/jmeter-5.6.3/processors-extractors/core/provenance.json",
                "compat/fixtures/jmeter-5.6.3/processors-extractors/negative-bounds/provenance.json",
            ] {
                let document = json!({
                    "source_references": [
                        {"path": ARCHITECTURE_RELATIVE, "sha256": architecture_hash},
                        {},
                        {},
                        {"path": COMPAT_README_RELATIVE, "sha256": compat_hash},
                        {"path": ACTIVE_PROFILE_RELATIVE, "sha256": profile_hash}
                    ]
                });
                self.write(
                    relative,
                    serde_json::to_vec(&document).unwrap_or_default().as_slice(),
                );
            }
            profile_hash
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn closed_catalog_checks_all_declared_references() {
        let tree = TempTree::new();
        let profile_hash = tree.seed();
        let diagnostics = run(
            &tree.root,
            &tree.root.join(ACTIVE_PROFILE_RELATIVE),
            Action::Check,
        );
        assert!(
            diagnostics.is_empty(),
            "unexpected diagnostics: {diagnostics:?}"
        );
        assert_eq!(profile_hash.len(), 64);
        assert_eq!(JSON_TARGETS.len(), 11);
    }

    #[test]
    fn check_reports_stale_references_without_mutating_files() {
        let tree = TempTree::new();
        tree.seed();
        let path = tree
            .root
            .join("compat/fixtures/jmeter-5.6.3/harness/manifest.json");
        let original = fs::read(&path).unwrap_or_default();
        let mut document: serde_json::Value = serde_json::from_slice(&original).unwrap_or_default();
        document["profile"]["sha256"] = json!("0".repeat(64));
        assert!(fs::write(&path, serde_json::to_vec(&document).unwrap_or_default()).is_ok());
        let changed = fs::read(&path).unwrap_or_default();
        let diagnostics = run(
            &tree.root,
            &tree.root.join(ACTIVE_PROFILE_RELATIVE),
            Action::Check,
        );
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "PROFILE-REFERENCE-DRIFT"
                && diagnostic
                    .path
                    .ends_with("harness/manifest.json#/profile/sha256")
        }));
        assert_eq!(fs::read(&path).unwrap_or_default(), changed);
        assert_ne!(changed, original);
    }

    #[test]
    fn generate_patches_only_declared_values_and_preserves_json_shape() {
        let tree = TempTree::new();
        let profile_hash = tree.seed();
        let path = tree
            .root
            .join("compat/fixtures/jmeter-5.6.3/harness/manifest.json");
        let stale = br#"{
  "profile": { "path": "compat/profiles/jmeter-5.6.3.json", "sha256": "0000000000000000000000000000000000000000000000000000000000000000", "extra": "retain" },
  "repository_inputs": { "profile": [{ "path": "compat/profiles/jmeter-5.6.3.json", "sha256": "0000000000000000000000000000000000000000000000000000000000000000" }] }
}
"#;
        assert!(fs::write(&path, stale).is_ok());
        let diagnostics = run(
            &tree.root,
            &tree.root.join(ACTIVE_PROFILE_RELATIVE),
            Action::Generate,
        );
        assert!(
            diagnostics.is_empty(),
            "generate diagnostics: {diagnostics:?}"
        );
        let generated = fs::read_to_string(&path).unwrap_or_default();
        assert!(generated.contains(&profile_hash));
        assert!(generated.contains("\"extra\": \"retain\""));
        assert!(
            run(
                &tree.root,
                &tree.root.join(ACTIVE_PROFILE_RELATIVE),
                Action::Check,
            )
            .is_empty()
        );
    }

    #[test]
    fn generate_rejects_unlisted_json_hashes_without_global_substitution() {
        let tree = TempTree::new();
        tree.seed();
        let path = tree
            .root
            .join("compat/fixtures/jmeter-5.6.3/harness/manifest.json");
        let profile_hash = tree.source_hash(ACTIVE_PROFILE_RELATIVE);
        let document = format!(
            "{{\"profile\":{{\"path\":\"{ACTIVE_PROFILE_RELATIVE}\",\"sha256\":\"{profile_hash}\"}},\"repository_inputs\":{{\"profile\":[{{\"path\":\"{ACTIVE_PROFILE_RELATIVE}\",\"sha256\":\"{profile_hash}\"}}]}},\"unlisted\":\"{}\"}}",
            "0".repeat(64)
        );
        assert!(fs::write(&path, document).is_ok());
        let diagnostics = run(
            &tree.root,
            &tree.root.join(ACTIVE_PROFILE_RELATIVE),
            Action::Generate,
        );
        assert!(
            diagnostics.is_empty(),
            "generate diagnostics: {diagnostics:?}"
        );
        let generated = fs::read_to_string(&path).unwrap_or_default();
        assert!(generated.contains(&"0".repeat(64)));
    }

    #[test]
    fn pointer_and_constant_locators_reject_ambiguous_or_escaped_values() {
        let document = json!({"a": [{"sha256": "abc"}]});
        assert_eq!(
            json_pointer_string(&document, "/a/0/sha256")
                .ok()
                .as_deref(),
            Some("abc")
        );
        assert!(locate_json_string(br#"{"a":[{"sha256":"abc"}]}"#, "/a/0/sha256").is_ok());
        assert!(is_sha256(&"a".repeat(64)));
        assert!(!is_sha256(&"A".repeat(64)));
        let source = b"pub const JVM_PROFILE_SHA256_HEX: &str =\n    \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\";";
        let (actual, range) =
            rust_string_constant(source, "JVM_PROFILE_SHA256_HEX").unwrap_or_default();
        assert_eq!(actual, "a".repeat(64));
        assert_eq!(
            &source[range],
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
    }

    #[test]
    fn options_can_select_profile_reference_command_action() {
        let mut options = Options::new(".");
        assert!(options.profile_reference_action.is_none());
        options.profile_reference_action = Some(Action::Check);
        assert_eq!(options.profile_reference_action, Some(Action::Check));
        assert_eq!(SourceKind::Profile.relative_path(), ACTIVE_PROFILE_RELATIVE);
    }

    #[test]
    fn noncanonical_profile_path_is_rejected_before_reference_reads() {
        let tree = TempTree::new();
        tree.seed();
        let diagnostics = run(
            &tree.root,
            &tree.root.join("other-profile.json"),
            Action::Check,
        );
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(
            diagnostics
                .iter()
                .next()
                .map(|diagnostic| diagnostic.code.as_str()),
            Some("PROFILE-REFERENCE-SOURCE")
        );
    }

    #[test]
    fn bounded_reader_rejects_overlimit_input() {
        let tree = TempTree::new();
        tree.write("input.txt", b"12345");
        let error = read_bounded_file(&tree.root.join("input.txt"), 4).unwrap_err();
        assert!(error.contains("bound"));
    }
}
