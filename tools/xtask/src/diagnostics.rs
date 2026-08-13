// SPDX-License-Identifier: Apache-2.0
//! Stable, sortable diagnostics used by every xtask check.

use std::fmt::{self, Display, Formatter};

/// One actionable validation diagnostic.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Diagnostic {
    /// Stable machine-readable code.
    pub code: String,
    /// Repository-relative (or explicitly supplied) location.
    pub path: String,
    /// Human-readable explanation and remediation hint.
    pub message: String,
}

impl Diagnostic {
    pub(crate) fn new(code: &str, path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.to_owned(),
            path: path.into(),
            message: message.into(),
        }
    }
}

impl Display for Diagnostic {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "ERROR[{}] {}: {}",
            self.code, self.path, self.message
        )
    }
}

/// A deterministic collection of validation diagnostics.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Diagnostics {
    entries: Vec<Diagnostic>,
}

impl Diagnostics {
    pub(crate) fn push(&mut self, diagnostic: Diagnostic) {
        self.entries.push(diagnostic);
    }

    pub(crate) fn extend(&mut self, other: Self) {
        self.entries.extend(other.entries);
    }

    pub(crate) fn sort_deterministically(&mut self) {
        self.entries.sort();
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

    /// Number of diagnostics in this result.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

impl IntoIterator for Diagnostics {
    type Item = Diagnostic;
    type IntoIter = std::vec::IntoIter<Diagnostic>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}
