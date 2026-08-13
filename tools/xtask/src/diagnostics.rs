// SPDX-License-Identifier: Apache-2.0
//! Stable, bounded diagnostics used by every xtask check.
//!
//! Diagnostics are emitted by validators which often consume untrusted
//! manifests, paths, and tool output.  This module is therefore the last
//! boundary before text is printed or uploaded: records are made one-line,
//! sensitive locations are redacted, every field is bounded, and a full
//! collection fails closed with an explicit overflow record.  Callers may
//! still call [`Diagnostics::sort_deterministically`] at phase boundaries;
//! insertion already keeps the collection ordered so a missed call cannot
//! make output depend on traversal order.

use std::fmt::{self, Display, Formatter};

/// The maximum encoded size of one stable diagnostic code.
pub(crate) const MAX_CODE_BYTES: usize = 256;
/// The maximum encoded size of one diagnostic location.
pub(crate) const MAX_PATH_BYTES: usize = 16 * 1024;
/// The maximum encoded size of one diagnostic message.
pub(crate) const MAX_MESSAGE_BYTES: usize = 4 * 1024;
/// The maximum number of records in one diagnostic collection.
pub(crate) const MAX_RECORDS: usize = 64;
/// The maximum aggregate encoded size of one diagnostic collection.
pub(crate) const MAX_TOTAL_BYTES: usize = 64 * 1024;

const INVALID_CODE: &str = "XTASK-DIAGNOSTICS-CODE";
const OVERFLOW_CODE: &str = "XTASK-DIAGNOSTICS-BOUNDS";
const OVERFLOW_PATH: &str = "<diagnostics>";
const ABSOLUTE_PATH: &str = "<redacted-path>";
const REDACTED_VALUE: &str = "<redacted>";
const TRUNCATION_MARK: &str = "…";

/// Process status used when a check has no diagnostics.
pub const SUCCESS_EXIT_CODE: u8 = 0;
/// Process status used when a check has one or more diagnostics.
pub const FAILURE_EXIT_CODE: u8 = 1;

/// One actionable validation diagnostic.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct Diagnostic {
    /// Stable machine-readable code.
    pub code: String,
    /// Repository-relative (or explicitly supplied) location.
    ///
    /// Absolute locations and secret-like path components are redacted when
    /// the record is constructed.  The value is also re-normalized when it
    /// enters a [`Diagnostics`] collection because the fields are public for
    /// compatibility with existing xtask callers.
    pub path: String,
    /// Human-readable explanation and remediation hint.
    ///
    /// Control characters, obvious secret assignments, and absolute paths
    /// are removed before this text is retained.
    pub message: String,
}

impl Diagnostic {
    pub(crate) fn new(code: &str, path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: normalize_code(code),
            path: normalize_path(&path.into()),
            message: normalize_message(&message.into()),
        }
    }

    fn normalized(&self) -> Self {
        Self::new(&self.code, self.path.clone(), self.message.clone())
    }

    fn encoded_size(&self) -> usize {
        self.code
            .len()
            .saturating_add(self.path.len())
            .saturating_add(self.message.len())
    }
}

impl fmt::Debug for Diagnostic {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let normalized = self.normalized();
        formatter
            .debug_struct("Diagnostic")
            .field("code", &normalized.code)
            .field("path", &normalized.path)
            .field("message", &normalized.message)
            .finish()
    }
}

impl Display for Diagnostic {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let normalized = self.normalized();
        write!(
            formatter,
            "ERROR[{}] {}: {}",
            normalized.code, normalized.path, normalized.message
        )
    }
}

/// A deterministic, bounded collection of validation diagnostics.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct Diagnostics {
    entries: Vec<Diagnostic>,
    total_bytes: usize,
    truncated: bool,
}

impl fmt::Debug for Diagnostics {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Diagnostics")
            .field("entries", &self.entries)
            .finish()
    }
}

impl Diagnostics {
    pub(crate) fn push(&mut self, diagnostic: Diagnostic) {
        let diagnostic = diagnostic.normalized();
        let record_size = diagnostic.encoded_size();
        let fits = self.entries.len() < MAX_RECORDS
            && self
                .total_bytes
                .checked_add(record_size)
                .is_some_and(|size| size <= MAX_TOTAL_BYTES);
        if fits && !self.truncated {
            self.total_bytes = self.total_bytes.saturating_add(record_size);
            self.entries.push(diagnostic);
            self.sort_deterministically();
        } else {
            if !self.truncated {
                self.record_overflow();
            }
            self.retain_after_overflow(diagnostic);
        }
    }

    pub(crate) fn extend(&mut self, other: Self) {
        let other_was_truncated = other.truncated;
        for diagnostic in other.entries {
            if diagnostic.code != OVERFLOW_CODE {
                self.push(diagnostic);
            }
        }
        if other_was_truncated {
            self.record_overflow();
        }
    }

    /// Sort diagnostics by stable code, path, and message order.
    ///
    /// The collection is kept in this order after every insertion as well;
    /// this method remains public to make phase-boundary intent explicit in
    /// existing validators.
    pub(crate) fn sort_deterministically(&mut self) {
        self.entries.sort_unstable();
    }

    fn record_overflow(&mut self) {
        if self.truncated {
            return;
        }
        self.truncated = true;

        let overflow = Diagnostic::new(
            OVERFLOW_CODE,
            OVERFLOW_PATH,
            format!(
                "diagnostic output exceeded the {}-record or {}-byte bound; additional records were omitted",
                MAX_RECORDS, MAX_TOTAL_BYTES
            ),
        );
        let overflow_size = overflow.encoded_size();

        // Keep the explicit overflow marker even if the collection was full.
        // Removing the lexicographically last record is deterministic and
        // preserves the earliest errors, which are generally the actionable
        // root cause for a fail-closed validator.
        while (!self.entries.is_empty() && self.entries.len() >= MAX_RECORDS)
            || (self.total_bytes.saturating_add(overflow_size) > MAX_TOTAL_BYTES
                && !self.entries.is_empty())
        {
            if let Some(removed) = self.entries.pop() {
                self.total_bytes = self.total_bytes.saturating_sub(removed.encoded_size());
            }
        }

        if overflow_size <= MAX_TOTAL_BYTES {
            self.total_bytes = self.total_bytes.saturating_add(overflow_size);
            self.entries.push(overflow);
            self.sort_deterministically();
        }
    }

    fn retain_after_overflow(&mut self, candidate: Diagnostic) {
        if candidate.code == OVERFLOW_CODE {
            return;
        }
        let Some(marker_index) = self
            .entries
            .iter()
            .position(|entry| entry.code == OVERFLOW_CODE && entry.path == OVERFLOW_PATH)
        else {
            return;
        };
        let marker = self.entries.remove(marker_index);
        self.total_bytes = self.total_bytes.saturating_sub(marker.encoded_size());

        let candidate_size = candidate.encoded_size();
        if candidate_size <= MAX_TOTAL_BYTES {
            let retained_limit = MAX_RECORDS.saturating_sub(1);
            if self.entries.len() < retained_limit
                && self
                    .total_bytes
                    .checked_add(candidate_size)
                    .is_some_and(|size| size <= MAX_TOTAL_BYTES)
            {
                self.entries.push(candidate);
                self.total_bytes = self.total_bytes.saturating_add(candidate_size);
            } else if !self.entries.is_empty() {
                let code_seen = self
                    .entries
                    .iter()
                    .any(|entry| entry.code == candidate.code);
                let replacement_index = if code_seen {
                    self.entries.len() - 1
                } else {
                    self.entries
                        .iter()
                        .enumerate()
                        .rev()
                        .find(|(_, entry)| {
                            self.entries
                                .iter()
                                .filter(|other| other.code == entry.code)
                                .count()
                                > 1
                        })
                        .map_or(self.entries.len() - 1, |(index, _)| index)
                };
                let should_replace = !code_seen || candidate < self.entries[replacement_index];
                if should_replace {
                    let removed = self.entries.remove(replacement_index);
                    let fits = self
                        .total_bytes
                        .checked_sub(removed.encoded_size())
                        .and_then(|size| size.checked_add(candidate_size))
                        .is_some_and(|size| size <= MAX_TOTAL_BYTES);
                    if fits {
                        self.total_bytes = self
                            .total_bytes
                            .saturating_sub(removed.encoded_size())
                            .saturating_add(candidate_size);
                        self.entries.push(candidate);
                    } else {
                        self.total_bytes = self.total_bytes.saturating_add(removed.encoded_size());
                        self.entries.push(removed);
                    }
                }
            }
        }

        self.sort_deterministically();
        while (!self.entries.is_empty() && self.entries.len() >= MAX_RECORDS)
            || (self.total_bytes.saturating_add(marker.encoded_size()) > MAX_TOTAL_BYTES
                && !self.entries.is_empty())
        {
            let removal_index = self
                .entries
                .iter()
                .enumerate()
                .rev()
                .find(|(_, entry)| {
                    self.entries
                        .iter()
                        .filter(|other| other.code == entry.code)
                        .count()
                        > 1
                })
                .map_or_else(|| self.entries.len().saturating_sub(1), |(index, _)| index);
            if !self.entries.is_empty() {
                let removed = self.entries.remove(removal_index);
                self.total_bytes = self.total_bytes.saturating_sub(removed.encoded_size());
            }
        }
        self.total_bytes = self.total_bytes.saturating_add(marker.encoded_size());
        self.entries.push(marker);
        self.sort_deterministically();
    }

    /// Return whether the check produced no errors.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over diagnostics in code/path/message order.
    pub fn iter(&self) -> impl Iterator<Item = &Diagnostic> {
        self.entries.iter()
    }

    /// Number of diagnostics in this result, including an overflow marker.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return the bounded aggregate size of retained diagnostic fields.
    #[must_use]
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Return whether one or more diagnostics were omitted at a bound.
    #[must_use]
    pub fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Return the stable process status for a check.
    ///
    /// A non-empty collection, including a collection that hit a bound,
    /// always maps to failure.  There is no warning-only success path.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        if self.is_empty() {
            SUCCESS_EXIT_CODE
        } else {
            FAILURE_EXIT_CODE
        }
    }

    /// Return whether this collection maps to the successful process status.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.exit_code() == 0
    }
}

impl IntoIterator for Diagnostics {
    type Item = Diagnostic;
    type IntoIter = std::vec::IntoIter<Diagnostic>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}

fn normalize_code(code: &str) -> String {
    if code.is_empty()
        || code.len() > MAX_CODE_BYTES
        || !code.bytes().all(|byte| {
            byte.is_ascii_uppercase() || byte.is_ascii_digit() || b"-_.".contains(&byte)
        })
    {
        return INVALID_CODE.to_owned();
    }
    bounded_text(code, MAX_CODE_BYTES, false)
}

fn normalize_path(path: &str) -> String {
    let mut slash_normalized = String::with_capacity(path.len().min(MAX_PATH_BYTES));
    let mut truncated = false;
    for character in path.chars() {
        let character = if character == '\\' { '/' } else { character };
        let replacement = if character == '\n' || character == '\r' || character == '\t' {
            ' '
        } else if character.is_control() {
            '�'
        } else {
            character
        };
        if slash_normalized
            .len()
            .saturating_add(replacement.len_utf8())
            > MAX_PATH_BYTES
        {
            truncated = true;
            break;
        }
        slash_normalized.push(replacement);
    }
    let path = finish_bounded(slash_normalized, MAX_PATH_BYTES, truncated);
    if path.is_empty() {
        return "<unknown>".to_owned();
    }
    if is_absolute_path(&path) || path.starts_with("~/") || path.contains("://") {
        return ABSOLUTE_PATH.to_owned();
    }

    let mut normalized = String::with_capacity(path.len());
    for (index, component) in path.split('/').enumerate() {
        if index != 0 {
            normalized.push('/');
        }
        if sensitive_path_component(component) {
            normalized.push_str(REDACTED_VALUE);
        } else {
            normalized.push_str(component);
        }
    }
    let normalized = redact_secret_assignments(&normalized, MAX_PATH_BYTES);
    bounded_text(&normalized, MAX_PATH_BYTES, true)
}

fn normalize_message(message: &str) -> String {
    let with_secret_redactions = redact_secret_assignments(message, MAX_MESSAGE_BYTES);
    let with_path_redactions =
        redact_absolute_fragments(&with_secret_redactions, MAX_MESSAGE_BYTES);
    bounded_text(&with_path_redactions, MAX_MESSAGE_BYTES, true)
}

fn bounded_text(input: &str, maximum: usize, mark_truncation: bool) -> String {
    let mut output = String::with_capacity(input.len().min(maximum));
    let mut truncated = false;
    for character in input.chars() {
        if output.len().saturating_add(character.len_utf8()) > maximum {
            truncated = true;
            break;
        }
        output.push(character);
    }
    let input_was_truncated = truncated || output.len() < input.len();
    finish_bounded(output, maximum, mark_truncation && input_was_truncated)
}

fn finish_bounded(mut output: String, maximum: usize, truncated: bool) -> String {
    if !truncated || maximum == 0 {
        return output;
    }
    while output.len().saturating_add(TRUNCATION_MARK.len()) > maximum {
        if output.pop().is_none() {
            return String::new();
        }
    }
    output.push_str(TRUNCATION_MARK);
    output
}

fn is_absolute_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    path.starts_with('/')
        || path.starts_with("\\\\")
        || (bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && (bytes[2] == b'/' || bytes[2] == b'\\'))
}

fn sensitive_path_component(component: &str) -> bool {
    let lower = component.to_ascii_lowercase();
    if lower.is_empty() || lower == "." || lower == ".." {
        return false;
    }
    lower == ".env"
        || lower == ".netrc"
        || lower == ".ssh"
        || lower == "secret"
        || lower == "secrets"
        || lower == "token"
        || lower == "tokens"
        || lower == "password"
        || lower == "passwords"
        || lower == "credential"
        || lower == "credentials"
        || lower.contains("private-key")
        || lower.contains("private_key")
        || lower.ends_with(".pem")
        || lower.ends_with(".key")
        || lower.ends_with(".p12")
        || lower.ends_with(".pfx")
        || lower.ends_with(".jks")
}

fn redact_secret_assignments(input: &str, maximum: usize) -> String {
    const KEYS: [&str; 18] = [
        "password",
        "passwd",
        "token",
        "secret",
        "authorization",
        "proxy-authorization",
        "cookie",
        "body",
        "headers",
        "certificate",
        "certificate_path",
        "keystore",
        "truststore",
        "credential",
        "credentials",
        "api_key",
        "apikey",
        "private_key",
    ];

    let mut output = String::with_capacity(input.len().min(maximum));
    let mut cursor = 0;
    let mut truncated = false;
    while cursor < input.len() {
        let Some((start, value_start, value_end)) = find_secret_assignment(input, cursor, &KEYS)
        else {
            truncated |= append_sanitized(&mut output, &input[cursor..], maximum);
            break;
        };
        truncated |= append_sanitized(&mut output, &input[cursor..value_start], maximum);
        truncated |= append_sanitized(&mut output, REDACTED_VALUE, maximum);
        cursor = value_end.max(start + 1);
        if output.len() >= maximum {
            truncated = true;
            break;
        }
    }
    finish_bounded(output, maximum, truncated)
}

fn find_secret_assignment(
    input: &str,
    from: usize,
    keys: &[&str],
) -> Option<(usize, usize, usize)> {
    for (start, character) in input[from..].char_indices() {
        let start = from + start;
        if !character.is_ascii_alphanumeric() && character != '_' && character != '-' {
            continue;
        }
        let Some(key) = keys.iter().find(|key| {
            input[start..].len() >= key.len()
                && input.is_char_boundary(start + key.len())
                && input[start..start + key.len()].eq_ignore_ascii_case(key)
                && (start == 0
                    || !input.as_bytes()[start - 1].is_ascii_alphanumeric()
                        && input.as_bytes()[start - 1] != b'_'
                        && input.as_bytes()[start - 1] != b'-')
                && (start + key.len() == input.len()
                    || !input.as_bytes()[start + key.len()].is_ascii_alphanumeric()
                        && input.as_bytes()[start + key.len()] != b'_'
                        && input.as_bytes()[start + key.len()] != b'-')
        }) else {
            continue;
        };

        let mut separator = start + key.len();
        while separator < input.len() && input.as_bytes()[separator].is_ascii_whitespace() {
            separator += 1;
        }
        if separator >= input.len() || !matches!(input.as_bytes()[separator], b'=' | b':') {
            continue;
        }
        separator += 1;
        while separator < input.len() && input.as_bytes()[separator].is_ascii_whitespace() {
            separator += 1;
        }
        let quoted = input.as_bytes().get(separator).copied();
        let value_start = if matches!(quoted, Some(b'\'' | b'"')) {
            separator + 1
        } else {
            separator
        };
        let value_end = if let Some(quote) = quoted.filter(|quote| matches!(quote, b'\'' | b'"')) {
            input[value_start..]
                .find(char::from(quote))
                .map_or(input.len(), |offset| value_start + offset)
        } else {
            input[value_start..]
                .find(|character: char| ",}]".contains(character))
                .map_or(input.len(), |offset| value_start + offset)
        };
        return Some((start, value_start, value_end));
    }
    None
}

fn redact_absolute_fragments(input: &str, maximum: usize) -> String {
    let mut output = String::with_capacity(input.len().min(maximum));
    let mut cursor = 0;
    let mut truncated = false;
    while cursor < input.len() {
        let Some(start) = find_absolute_fragment(input, cursor) else {
            truncated |= append_sanitized(&mut output, &input[cursor..], maximum);
            break;
        };
        truncated |= append_sanitized(&mut output, &input[cursor..start], maximum);
        truncated |= append_sanitized(&mut output, ABSOLUTE_PATH, maximum);
        let mut end = start;
        while end < input.len() {
            let Some(character) = input[end..].chars().next() else {
                break;
            };
            if character.is_ascii_whitespace() || ",;\"'()[]{}".contains(character) {
                break;
            }
            end += character.len_utf8();
        }
        cursor = end.max(start + 1);
        if output.len() >= maximum {
            truncated = true;
            break;
        }
    }
    finish_bounded(output, maximum, truncated)
}

fn find_absolute_fragment(input: &str, from: usize) -> Option<usize> {
    for (offset, character) in input[from..].char_indices() {
        let position = from + offset;
        if is_uri_start(input, position) {
            return Some(position);
        }
        let boundary = position == 0
            || matches!(
                input.as_bytes()[position - 1],
                b' ' | b'\t' | b'=' | b':' | b'(' | b'[' | b'{' | b'"' | b'\''
            );
        if character == '/' && boundary {
            return Some(position);
        }
        if character.is_ascii_alphabetic()
            && input.as_bytes().get(position + 1) == Some(&b':')
            && matches!(input.as_bytes().get(position + 2), Some(b'/' | b'\\'))
            && boundary
        {
            return Some(position);
        }
    }
    None
}

fn is_uri_start(input: &str, position: usize) -> bool {
    let Some(first) = input.as_bytes().get(position).copied() else {
        return false;
    };
    if !first.is_ascii_alphabetic()
        || (position != 0
            && !matches!(
                input.as_bytes()[position - 1],
                b' ' | b'\t' | b'=' | b':' | b'(' | b'[' | b'{' | b'"' | b'\''
            ))
    {
        return false;
    }
    let mut cursor = position + 1;
    while let Some(byte) = input.as_bytes().get(cursor).copied() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.') {
            cursor += 1;
            continue;
        }
        return input.as_bytes().get(cursor..cursor + 3) == Some(b"://");
    }
    false
}

fn append_sanitized(output: &mut String, input: &str, maximum: usize) -> bool {
    let mut truncated = false;
    for character in input.chars() {
        let replacement = if character == '\n' || character == '\r' || character == '\t' {
            ' '
        } else if character.is_control() {
            '�'
        } else {
            character
        };
        if output.len().saturating_add(replacement.len_utf8()) > maximum {
            truncated = true;
            break;
        }
        output.push(replacement);
    }
    truncated || output.len() < input.len()
}

#[cfg(test)]
mod tests {
    use super::{
        ABSOLUTE_PATH, Diagnostic, Diagnostics, INVALID_CODE, MAX_MESSAGE_BYTES, MAX_PATH_BYTES,
        MAX_RECORDS, MAX_TOTAL_BYTES, OVERFLOW_CODE, REDACTED_VALUE,
    };

    #[test]
    fn normal_diagnostics_keep_stable_display_shape() {
        let diagnostic = Diagnostic::new("PROFILE-SCHEMA", "profile.features[0].id", "missing");
        assert_eq!(diagnostic.code, "PROFILE-SCHEMA");
        assert_eq!(diagnostic.path, "profile.features[0].id");
        assert_eq!(diagnostic.message, "missing");
        assert_eq!(
            diagnostic.to_string(),
            "ERROR[PROFILE-SCHEMA] profile.features[0].id: missing"
        );
    }

    #[test]
    fn control_characters_are_replaced_and_output_is_one_line() {
        let diagnostic = Diagnostic::new("TEST", "case\nfield", "bad\r\nvalue\t\u{0000}");
        assert!(!diagnostic.path.contains(['\n', '\r', '\t']));
        assert!(!diagnostic.message.contains(['\n', '\r', '\t']));
        assert!(!diagnostic.to_string().contains('\n'));
    }

    #[test]
    fn absolute_and_secret_paths_are_redacted() {
        let absolute = Diagnostic::new(
            "PATH",
            "/home/alice/private/project/plan.jmx",
            "cannot read",
        );
        assert_eq!(absolute.path, ABSOLUTE_PATH);

        let secret = Diagnostic::new("PATH", "fixtures/private-key.pem", "cannot read");
        assert!(secret.path.contains(REDACTED_VALUE));
        assert!(!secret.path.contains("private-key.pem"));

        let windows = Diagnostic::new("PATH", r"C:\Users\alice\secrets\plan.jmx", "cannot read");
        assert_eq!(windows.path, ABSOLUTE_PATH);
    }

    #[test]
    fn messages_redact_assignments_and_absolute_paths() {
        let diagnostic = Diagnostic::new(
            "IO",
            "case.plan",
            "password='do-not-log' while reading /home/alice/secret.jmx",
        );
        assert!(!diagnostic.message.contains("do-not-log"));
        assert!(!diagnostic.message.contains("/home/alice/secret.jmx"));
        assert!(diagnostic.message.contains(REDACTED_VALUE));

        let assignment = Diagnostic::new("IO", "case.plan", r"path=/home/alice/private.jmx");
        assert!(!assignment.message.contains("/home/alice/private.jmx"));

        let url = Diagnostic::new(
            "IO",
            "case.plan",
            "request failed at https://example.test/private",
        );
        assert!(!url.message.contains("https://example.test/private"));
        assert!(url.message.contains(ABSOLUTE_PATH));

        let cookie = Diagnostic::new("IO", "case.plan", "Cookie: a=secret; b=also-secret");
        assert!(!cookie.message.contains("secret"));
    }

    #[test]
    fn fields_are_bounded_without_panicking_on_large_input() {
        let diagnostic = Diagnostic::new(
            "TEST",
            "x".repeat(MAX_PATH_BYTES.saturating_mul(2)),
            "y".repeat(MAX_MESSAGE_BYTES.saturating_mul(2)),
        );
        assert!(diagnostic.path.len() <= MAX_PATH_BYTES);
        assert!(diagnostic.message.len() <= MAX_MESSAGE_BYTES);
    }

    #[test]
    fn invalid_codes_fail_closed_to_a_stable_code() {
        let diagnostic = Diagnostic::new("bad code\nwith secret", "case", "message");
        assert_eq!(diagnostic.code, INVALID_CODE);
    }

    #[test]
    fn insertion_and_extension_are_deterministically_sorted() {
        let mut diagnostics = Diagnostics::default();
        diagnostics.push(Diagnostic::new("B", "z", "two"));
        diagnostics.push(Diagnostic::new("A", "z", "three"));
        diagnostics.push(Diagnostic::new("A", "a", "one"));
        let actual = diagnostics
            .iter()
            .map(|item| {
                (
                    item.code.as_str(),
                    item.path.as_str(),
                    item.message.as_str(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            actual,
            [("A", "a", "one"), ("A", "z", "three"), ("B", "z", "two")]
        );

        let mut extension = Diagnostics::default();
        extension.push(Diagnostic::new("C", "c", "four"));
        diagnostics.extend(extension);
        assert_eq!(
            diagnostics.iter().next().map(|item| item.code.as_str()),
            Some("A")
        );
    }

    #[test]
    fn collection_bounds_emit_a_visible_failure_record() {
        let mut diagnostics = Diagnostics::default();
        for index in 0..=MAX_RECORDS {
            diagnostics.push(Diagnostic::new("TEST", format!("case[{index}]"), "failure"));
        }
        assert!(diagnostics.is_truncated());
        assert!(diagnostics.len() <= MAX_RECORDS);
        assert!(diagnostics.total_bytes() <= MAX_TOTAL_BYTES);
        assert!(diagnostics.iter().any(|item| item.code == OVERFLOW_CODE));
        assert_eq!(diagnostics.exit_code(), 1);
        assert!(!diagnostics.is_success());
    }

    #[test]
    fn aggregate_bound_is_fail_closed_even_with_few_records() {
        let mut diagnostics = Diagnostics::default();
        let message = "x".repeat(MAX_MESSAGE_BYTES / 2);
        for index in 0..MAX_RECORDS {
            diagnostics.push(Diagnostic::new("TEST", format!("case[{index}]"), &message));
        }
        diagnostics.push(Diagnostic::new("TEST", "overflow", "one more"));
        assert!(diagnostics.is_truncated());
        assert!(diagnostics.total_bytes() <= MAX_TOTAL_BYTES);
        assert!(diagnostics.iter().any(|item| item.code == OVERFLOW_CODE));
    }

    #[test]
    fn overflow_retains_late_diagnostic_categories() {
        let mut diagnostics = Diagnostics::default();
        for index in 0..=MAX_RECORDS {
            diagnostics.push(Diagnostic::new(
                "EXTERNAL-ACCEPTANCE-CASE",
                format!("case[{index}]"),
                "failure",
            ));
        }
        diagnostics.push(Diagnostic::new(
            "EXTERNAL-ACCEPTANCE-IDENTITY",
            "identity",
            "failure",
        ));
        diagnostics.push(Diagnostic::new(
            "EXTERNAL-ACCEPTANCE-SCHEMA",
            "schema",
            "failure",
        ));
        assert!(diagnostics.is_truncated());
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

    #[test]
    fn empty_collection_maps_to_success() {
        let diagnostics = Diagnostics::default();
        assert_eq!(diagnostics.exit_code(), 0);
        assert!(diagnostics.is_success());
    }
}
