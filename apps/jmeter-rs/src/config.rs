// SPDX-License-Identifier: Apache-2.0
//! Bounded JMeter configuration loading.
//!
//! This module is the filesystem edge of the CLI.  It deliberately keeps the
//! command-line parser in [`crate::lib`] free of I/O: a [`ConfigPlan`] records
//! ordered sources and assignments, while [`ConfigLoader`] is the explicit
//! capability that reads those sources.  The loader never consults the
//! process environment and never starts a process.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;

use super::{
    Action, CliInvocation, CliOptions, ConfigurationPlan, ConfigurationStep, GlobalProperty,
    LogLevel, OptionId, PropertySource,
};

const REDACTED: &str = "<redacted>";

/// The property namespace receiving a configuration operation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ConfigNamespace {
    /// JMeter properties (`props` in JMeter scripts).
    Jmeter,
    /// Java system properties (`System.getProperties()`).
    System,
    /// Properties sent to remote JMeter workers by `-G`.
    Global,
}

impl ConfigNamespace {
    /// Returns the stable diagnostic label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Jmeter => "jmeter",
            Self::System => "system",
            Self::Global => "global",
        }
    }
}

impl fmt::Display for ConfigNamespace {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Decoding policy for a Java `.properties` byte stream.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DecodeMode {
    /// Java `Properties.load(InputStream)` semantics: bytes are ISO-8859-1
    /// and `\\uXXXX` escapes are decoded.
    #[default]
    JavaProperties,
    /// Strict UTF-8 input followed by Java property escape processing.
    Utf8,
    /// Explicit ISO-8859-1 input followed by Java property escape processing.
    Latin1,
    /// Alias for [`DecodeMode::JavaProperties`] for callers using the shorter
    /// name.
    Java,
}

impl DecodeMode {
    const fn is_utf8(self) -> bool {
        matches!(self, Self::Utf8)
    }
}

/// Policy applied when a configured source path contains symlinks.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SymlinkPolicy {
    /// Reject a path if any path component is a symbolic link.
    #[default]
    Deny,
    /// Allow links whose canonical target remains below the configured root.
    AllowWithinRoot,
    /// Short spelling for [`SymlinkPolicy::AllowWithinRoot`].
    WithinRoot,
    /// Allow symlinks without requiring a root solely because of the symlink
    /// mode.  A configured root still enforces containment.  This is intended
    /// for an explicitly selected operator policy, not the default.
    Allow,
}

impl SymlinkPolicy {
    const fn allows_links(self) -> bool {
        !matches!(self, Self::Deny)
    }

    const fn requires_root(self) -> bool {
        matches!(self, Self::AllowWithinRoot | Self::WithinRoot)
    }
}

/// Bounded input limits for property files and their decoded entries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigLimits {
    /// Maximum number of bytes read from one source file.
    pub max_file_bytes: usize,
    /// Maximum number of physical lines in one source file.
    pub max_lines: usize,
    /// Maximum number of logical property entries in one source file.
    pub max_properties: usize,
    /// Maximum number of physical continuation lines for one property.
    pub max_continuation_lines: usize,
    /// Maximum decoded key length in Java UTF-16 code units.
    pub max_key_chars: usize,
    /// Maximum decoded value length in Java UTF-16 code units.
    pub max_value_chars: usize,
    /// Maximum path representation length in bytes.
    pub max_path_bytes: usize,
    /// Maximum number of ordered operations accepted in one plan.
    pub max_operations: usize,
    /// Maximum number of decoded property entries across all sources and
    /// inline assignments.  This is an aggregate bound, not only a
    /// per-file bound.
    pub max_resolved_properties: usize,
    /// Maximum number of retained provenance records, including removals.
    pub max_provenance_entries: usize,
    /// Maximum overwritten provenance records retained for one effective key.
    pub max_overrides_per_property: usize,
    /// Maximum bytes read across all files in one resolution.
    pub max_total_file_bytes: usize,
}

impl Default for ConfigLimits {
    fn default() -> Self {
        Self {
            max_file_bytes: 8 * 1024 * 1024,
            max_lines: 100_000,
            max_properties: 100_000,
            max_continuation_lines: 128,
            max_key_chars: 16 * 1024,
            max_value_chars: 1024 * 1024,
            max_path_bytes: 16 * 1024,
            max_operations: 100_000,
            max_resolved_properties: 200_000,
            max_provenance_entries: 500_000,
            max_overrides_per_property: 100_000,
            max_total_file_bytes: 64 * 1024 * 1024,
        }
    }
}

impl ConfigLimits {
    /// Returns conservative defaults.
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            max_file_bytes: 8 * 1024 * 1024,
            max_lines: 100_000,
            max_properties: 100_000,
            max_continuation_lines: 128,
            max_key_chars: 16 * 1024,
            max_value_chars: 1024 * 1024,
            max_path_bytes: 16 * 1024,
            max_operations: 100_000,
            max_resolved_properties: 200_000,
            max_provenance_entries: 500_000,
            max_overrides_per_property: 100_000,
            max_total_file_bytes: 64 * 1024 * 1024,
        }
    }

    /// Sets the maximum source-file size.
    #[must_use]
    pub const fn with_max_file_bytes(mut self, value: usize) -> Self {
        self.max_file_bytes = value;
        self
    }

    /// Sets the maximum number of physical lines.
    #[must_use]
    pub const fn with_max_lines(mut self, value: usize) -> Self {
        self.max_lines = value;
        self
    }

    /// Sets the maximum number of properties in one file.
    #[must_use]
    pub const fn with_max_properties(mut self, value: usize) -> Self {
        self.max_properties = value;
        self
    }

    /// Sets the maximum continuation depth.
    #[must_use]
    pub const fn with_max_continuation_lines(mut self, value: usize) -> Self {
        self.max_continuation_lines = value;
        self
    }

    /// Sets the maximum decoded key length.
    #[must_use]
    pub const fn with_max_key_chars(mut self, value: usize) -> Self {
        self.max_key_chars = value;
        self
    }

    /// Sets the maximum decoded value length.
    #[must_use]
    pub const fn with_max_value_chars(mut self, value: usize) -> Self {
        self.max_value_chars = value;
        self
    }

    /// Sets the maximum path length.
    #[must_use]
    pub const fn with_max_path_bytes(mut self, value: usize) -> Self {
        self.max_path_bytes = value;
        self
    }

    /// Sets the maximum number of operations in one plan.
    #[must_use]
    pub const fn with_max_operations(mut self, value: usize) -> Self {
        self.max_operations = value;
        self
    }

    /// Sets the aggregate decoded-entry bound.
    #[must_use]
    pub const fn with_max_resolved_properties(mut self, value: usize) -> Self {
        self.max_resolved_properties = value;
        self
    }

    /// Sets the aggregate provenance bound.
    #[must_use]
    pub const fn with_max_provenance_entries(mut self, value: usize) -> Self {
        self.max_provenance_entries = value;
        self
    }

    /// Sets the per-key overwritten-history bound.
    #[must_use]
    pub const fn with_max_overrides_per_property(mut self, value: usize) -> Self {
        self.max_overrides_per_property = value;
        self
    }

    /// Sets the aggregate file-byte bound.
    #[must_use]
    pub const fn with_max_total_file_bytes(mut self, value: usize) -> Self {
        self.max_total_file_bytes = value;
        self
    }
}

/// Names used for implicit JMeter property sources.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigFileNames {
    /// Primary JMeter properties file.
    pub jmeter: String,
    /// Per-user JMeter properties file.
    pub user: String,
    /// Java system properties file.
    pub system: String,
}

impl Default for ConfigFileNames {
    fn default() -> Self {
        Self {
            jmeter: "jmeter.properties".to_owned(),
            user: "user.properties".to_owned(),
            system: "system.properties".to_owned(),
        }
    }
}

impl ConfigFileNames {
    /// Creates names from exact relative path strings.
    #[must_use]
    pub fn new(
        jmeter: impl Into<String>,
        user: impl Into<String>,
        system: impl Into<String>,
    ) -> Self {
        Self {
            jmeter: jmeter.into(),
            user: user.into(),
            system: system.into(),
        }
    }

    /// Returns the standard JMeter names.
    #[must_use]
    pub fn standard() -> Self {
        Self::default()
    }
}

/// A filesystem policy for configuration source paths.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigFsPolicy {
    /// Optional canonical containment root.  Relative source paths are
    /// resolved below this root when it is present.
    pub root: Option<PathBuf>,
    /// Additional explicit canonical roots, used for a selected JMeter home
    /// while keeping the caller's working directory as a separate root.
    pub additional_roots: Vec<PathBuf>,
    /// Symlink handling mode.
    pub symlink_policy: SymlinkPolicy,
}

impl Default for ConfigFsPolicy {
    fn default() -> Self {
        Self {
            root: None,
            additional_roots: Vec::new(),
            symlink_policy: SymlinkPolicy::Deny,
        }
    }
}

impl ConfigFsPolicy {
    /// Creates a policy rooted at `root`.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: Some(root.into()),
            ..Self::default()
        }
    }

    /// Creates a policy with no containment root.  Symlinks remain denied by
    /// default; callers must opt into [`SymlinkPolicy::Allow`] explicitly.
    #[must_use]
    pub fn unrestricted() -> Self {
        Self::default()
    }

    /// Sets or clears the containment root.
    #[must_use]
    pub fn with_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.root = Some(root.into());
        self
    }

    /// Clears the containment root.
    #[must_use]
    pub fn without_root(mut self) -> Self {
        self.root = None;
        self
    }

    /// Adds an explicit containment root without widening the existing root.
    #[must_use]
    pub fn with_additional_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.additional_roots.push(root.into());
        self
    }

    /// Sets symlink handling.
    #[must_use]
    pub const fn with_symlink_policy(mut self, policy: SymlinkPolicy) -> Self {
        self.symlink_policy = policy;
        self
    }

    /// Sets symlink handling in a mutable policy.
    pub const fn set_symlink_policy(&mut self, policy: SymlinkPolicy) {
        self.symlink_policy = policy;
    }
}

/// A path and role from which a property value originated.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[allow(
    missing_docs,
    reason = "source payload fields are documented by the variant descriptions"
)]
pub enum ConfigSource {
    /// The implicit primary `jmeter.properties` file.
    DefaultPrimary { path: PathBuf },
    /// The explicit `-p` primary file.
    ExplicitPrimary { path: PathBuf },
    /// The implicit `user.properties` file.
    DefaultUser { path: PathBuf },
    /// The implicit `system.properties` file.
    DefaultSystem { path: PathBuf },
    /// A `-q` additional JMeter properties file.
    AdditionalJmeter { path: PathBuf, occurrence: usize },
    /// An `-S` additional Java system properties file.
    AdditionalSystem { path: PathBuf, occurrence: usize },
    /// A `-G` global properties file.
    Global { path: PathBuf, occurrence: usize },
    /// A command-line assignment.
    CommandLine {
        namespace: ConfigNamespace,
        occurrence: usize,
    },
}

impl ConfigSource {
    /// Returns the source path, if this source reads a file.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::DefaultPrimary { path }
            | Self::ExplicitPrimary { path }
            | Self::DefaultUser { path }
            | Self::DefaultSystem { path }
            | Self::AdditionalJmeter { path, .. }
            | Self::AdditionalSystem { path, .. }
            | Self::Global { path, .. } => Some(path),
            Self::CommandLine { .. } => None,
        }
    }

    /// Returns the namespace naturally associated with this source.
    #[must_use]
    pub const fn namespace(&self) -> ConfigNamespace {
        match self {
            Self::DefaultSystem { .. } | Self::AdditionalSystem { .. } => ConfigNamespace::System,
            Self::Global { .. } => ConfigNamespace::Global,
            Self::DefaultPrimary { .. }
            | Self::ExplicitPrimary { .. }
            | Self::DefaultUser { .. }
            | Self::AdditionalJmeter { .. }
            | Self::CommandLine {
                namespace: ConfigNamespace::Jmeter,
                ..
            } => ConfigNamespace::Jmeter,
            Self::CommandLine { namespace, .. } => *namespace,
        }
    }

    /// Returns whether a missing source may be ignored as an implicit file.
    #[must_use]
    pub const fn is_optional_default(&self) -> bool {
        matches!(
            self,
            Self::DefaultPrimary { .. } | Self::DefaultUser { .. } | Self::DefaultSystem { .. }
        )
    }

    /// Returns whether a missing explicitly requested source is a warning
    /// rather than a fatal configuration error.  JMeter logs and continues
    /// for `-q`, `-S`, and `-G` file forms.
    #[must_use]
    pub const fn is_warning_source(&self) -> bool {
        matches!(
            self,
            Self::AdditionalJmeter { .. } | Self::AdditionalSystem { .. } | Self::Global { .. }
        )
    }
}

impl fmt::Display for ConfigSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DefaultPrimary { path } => {
                write!(formatter, "default primary ({})", path.display())
            }
            Self::ExplicitPrimary { path } => {
                write!(formatter, "explicit primary ({})", path.display())
            }
            Self::DefaultUser { path } => write!(formatter, "default user ({})", path.display()),
            Self::DefaultSystem { path } => {
                write!(formatter, "default system ({})", path.display())
            }
            Self::AdditionalJmeter { path, occurrence } => {
                write!(
                    formatter,
                    "additional JMeter #{occurrence} ({})",
                    path.display()
                )
            }
            Self::AdditionalSystem { path, occurrence } => {
                write!(
                    formatter,
                    "additional system #{occurrence} ({})",
                    path.display()
                )
            }
            Self::Global { path, occurrence } => {
                write!(formatter, "global #{occurrence} ({})", path.display())
            }
            Self::CommandLine {
                namespace,
                occurrence,
            } => write!(formatter, "command line {namespace} #{occurrence}"),
        }
    }
}

/// A Java UTF-16 string, including unpaired surrogate code units.
///
/// Java `Properties` is specified in terms of UTF-16 code units while Rust's
/// `String` is specified in terms of Unicode scalar values.  Keeping the
/// units explicitly is therefore necessary at this boundary: a malformed
/// (or intentionally adversarial) `\\uD800` value must not be rejected,
/// replaced with U+FFFD, or otherwise changed.  [`JavaString::escaped`]
/// provides a deterministic, lossless text projection for APIs that require a
/// Rust string.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct JavaString {
    units: Vec<u16>,
}

impl JavaString {
    /// Creates a Java string from exact UTF-16 code units.
    #[must_use]
    pub fn from_units(units: impl Into<Vec<u16>>) -> Self {
        Self {
            units: units.into(),
        }
    }

    /// Encodes a Rust string as UTF-16 code units.
    #[must_use]
    #[allow(
        clippy::should_implement_trait,
        reason = "JavaString::from_str is an explicit UTF-16 domain conversion"
    )]
    pub fn from_str(value: &str) -> Self {
        Self {
            units: value.encode_utf16().collect(),
        }
    }

    /// Returns the exact UTF-16 units.
    #[must_use]
    pub fn units(&self) -> &[u16] {
        &self.units
    }

    /// Returns the number of UTF-16 code units.
    #[must_use]
    pub const fn len_units(&self) -> usize {
        self.units.len()
    }

    /// Returns whether all units form valid Unicode scalar values.
    #[must_use]
    pub fn is_unicode(&self) -> bool {
        String::from_utf16(&self.units).is_ok()
    }

    /// Converts valid units to Rust UTF-8, preserving the surrogate-pair
    /// decoding performed by Java.
    #[must_use]
    pub fn to_utf8(&self) -> Option<String> {
        String::from_utf16(&self.units).ok()
    }

    /// Returns a lossless text projection.  Unpaired units are rendered as
    /// uppercase Java-style escapes so diagnostics and legacy string APIs do
    /// not silently lose their value.
    #[must_use]
    pub fn escaped(&self) -> String {
        let mut output = String::new();
        let mut index = 0;
        while index < self.units.len() {
            let unit = self.units[index];
            if (0xD800..=0xDBFF).contains(&unit)
                && self
                    .units
                    .get(index + 1)
                    .is_some_and(|next| (0xDC00..=0xDFFF).contains(next))
            {
                let pair = [unit, self.units[index + 1]];
                if let Ok(value) = String::from_utf16(&pair) {
                    output.push_str(&value);
                    index += 2;
                    continue;
                }
            }
            if (0xD800..=0xDFFF).contains(&unit) {
                use std::fmt::Write as _;
                let _ = write!(output, "\\u{unit:04X}");
            } else if let Some(value) = char::from_u32(u32::from(unit)) {
                output.push(value);
            }
            index += 1;
        }
        output
    }
}

impl fmt::Debug for JavaString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JavaString")
            .field("units", &self.units)
            .field("escaped", &self.escaped())
            .finish()
    }
}

impl fmt::Display for JavaString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.escaped())
    }
}

impl From<&str> for JavaString {
    fn from(value: &str) -> Self {
        Self::from_str(value)
    }
}

impl From<String> for JavaString {
    fn from(value: String) -> Self {
        Self::from_str(&value)
    }
}

/// A value in a property namespace.
///
/// The exact Java value is available through [`PropertyValue::java_string`].
/// `text` is retained as a compatibility projection for callers that operate
/// on ordinary Unicode strings.  Formatting this type never emits a sensitive
/// value.
#[derive(Clone, Eq, PartialEq)]
pub struct PropertyValue {
    /// Decoded property text.
    pub text: String,
    /// Exact Java UTF-16 value, including unpaired surrogate units.
    pub java: JavaString,
    /// Whether diagnostics must redact this value.
    pub sensitive: bool,
}

impl PropertyValue {
    /// Creates a non-sensitive value.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        let text = value.into();
        Self {
            java: JavaString::from_str(&text),
            text,
            sensitive: false,
        }
    }

    /// Creates a value with an explicit redaction bit.
    #[must_use]
    pub fn sensitive(value: impl Into<String>) -> Self {
        let text = value.into();
        Self {
            java: JavaString::from_str(&text),
            text,
            sensitive: true,
        }
    }

    /// Creates a value from exact Java UTF-16 units.
    #[must_use]
    pub fn from_java(java: JavaString, sensitive: bool) -> Self {
        let text = java.escaped();
        Self {
            text,
            java,
            sensitive,
        }
    }

    /// Returns the decoded value for execution use.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Returns the exact Java UTF-16 value.
    #[must_use]
    pub const fn java_string(&self) -> &JavaString {
        &self.java
    }

    /// Returns whether diagnostics should redact this value.
    #[must_use]
    pub const fn is_sensitive(&self) -> bool {
        self.sensitive
    }

    /// Returns the diagnostic-safe representation.
    #[must_use]
    pub fn redacted(&self) -> &str {
        if self.sensitive { REDACTED } else { &self.text }
    }
}

impl fmt::Debug for PropertyValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PropertyValue")
            .field("value", &self.redacted())
            .field("sensitive", &self.sensitive)
            .finish()
    }
}

impl fmt::Display for PropertyValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.redacted())
    }
}

/// Provenance attached to every effective property value.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PropertyProvenance {
    /// Logical source role.
    pub source: ConfigSource,
    /// Property namespace.
    pub namespace: ConfigNamespace,
    /// One-based physical line in a file, or zero for an inline assignment.
    pub line: usize,
    /// Zero-based operation position in the plan.
    pub operation: usize,
}

impl PropertyProvenance {
    /// Creates provenance for an inline assignment.
    #[must_use]
    pub fn inline(namespace: ConfigNamespace, occurrence: usize, operation: usize) -> Self {
        Self {
            source: ConfigSource::CommandLine {
                namespace,
                occurrence,
            },
            namespace,
            line: 0,
            operation,
        }
    }
}

/// A property value together with its winning provenance and overwritten
/// history.
#[derive(Clone, Eq, PartialEq)]
pub struct ResolvedProperty {
    /// Exact decoded key.
    pub key: String,
    /// Exact Java UTF-16 key, including unpaired surrogate units.
    pub java_key: JavaString,
    /// Decoded value and redaction metadata.
    pub value: PropertyValue,
    /// Source of the effective value.
    pub provenance: PropertyProvenance,
    /// Earlier values for this key, newest first.
    pub overridden: Vec<PropertyProvenance>,
}

impl ResolvedProperty {
    /// Returns the effective value text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.value.as_str()
    }

    /// Returns the exact Java UTF-16 key.
    #[must_use]
    pub const fn java_key(&self) -> &JavaString {
        &self.java_key
    }

    /// Alias for [`ResolvedProperty::as_str`].
    #[must_use]
    pub fn value(&self) -> &str {
        self.as_str()
    }

    /// Returns the source provenance.
    #[must_use]
    pub const fn source(&self) -> &PropertyProvenance {
        &self.provenance
    }

    /// Returns whether the value is sensitive.
    #[must_use]
    pub const fn is_sensitive(&self) -> bool {
        self.value.is_sensitive()
    }
}

impl fmt::Debug for ResolvedProperty {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedProperty")
            .field("key", &self.key)
            .field("value", &self.value)
            .field("provenance", &self.provenance)
            .field("overridden", &self.overridden)
            .finish()
    }
}

/// A deterministic view of final values in one property namespace.
///
/// Keys are ordered for deterministic diagnostics.  Each value retains its
/// winning source and the complete source history is available through the
/// `overridden` field on [`ResolvedProperty`].
#[derive(Clone, Eq, PartialEq, Default)]
pub struct PropertyMap {
    /// A deterministic Rust-string projection of final values.  This field is
    /// retained for callers that need the historical map shape; use
    /// [`Self::as_java_map`] for lossless keys because an unpaired surrogate's
    /// escaped projection can collide with a literal backslash sequence.
    pub entries: BTreeMap<String, ResolvedProperty>,
    java_entries: BTreeMap<JavaString, ResolvedProperty>,
}

impl PropertyMap {
    /// Creates an empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of effective properties.
    #[must_use]
    pub fn len(&self) -> usize {
        self.java_entries.len()
    }

    /// Returns whether no effective properties exist.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.java_entries.is_empty()
    }

    /// Gets an effective property by exact key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&ResolvedProperty> {
        self.java_entries.get(&JavaString::from_str(key))
    }

    /// Gets an effective property by exact Java UTF-16 key.
    #[must_use]
    pub fn get_java(&self, key: &JavaString) -> Option<&ResolvedProperty> {
        self.java_entries.get(key)
    }

    /// Gets only the effective value text.
    #[must_use]
    pub fn get_value(&self, key: &str) -> Option<&str> {
        self.get(key).map(ResolvedProperty::as_str)
    }

    /// Gets the effective property provenance.
    #[must_use]
    pub fn provenance(&self, key: &str) -> Option<&PropertyProvenance> {
        self.get(key).map(ResolvedProperty::source)
    }

    /// Returns an iterator over deterministic key/value pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &ResolvedProperty)> {
        self.entries.iter()
    }

    /// Returns an iterator over effective properties.
    pub fn values(&self) -> impl Iterator<Item = &ResolvedProperty> {
        self.java_entries.values()
    }

    /// Returns an iterator over keys.
    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.entries.keys()
    }

    /// Returns the underlying deterministic map.
    #[must_use]
    pub const fn as_map(&self) -> &BTreeMap<String, ResolvedProperty> {
        &self.entries
    }

    /// Returns the lossless map keyed by exact Java UTF-16 units.
    #[must_use]
    pub const fn as_java_map(&self) -> &BTreeMap<JavaString, ResolvedProperty> {
        &self.java_entries
    }

    fn insert(
        &mut self,
        key: String,
        java_key: JavaString,
        value: PropertyValue,
        provenance: PropertyProvenance,
    ) {
        if let Some(previous) = self.java_entries.get_mut(&java_key) {
            let prior = previous.provenance.clone();
            previous.overridden.insert(0, prior);
            previous.value = value;
            previous.java_key = java_key;
            previous.provenance = provenance;
            self.entries.insert(key, previous.clone());
        } else {
            let property = ResolvedProperty {
                key: key.clone(),
                java_key: java_key.clone(),
                value,
                provenance,
                overridden: Vec::new(),
            };
            self.java_entries.insert(java_key, property.clone());
            self.entries.insert(key, property);
        }
    }

    fn remove(&mut self, key: &str) {
        let java_key = JavaString::from_str(key);
        self.java_entries.remove(&java_key);
        self.entries.remove(key);
        // A lossless key with an unpaired surrogate can share the escaped
        // projection with a literal `\\uXXXX` key.  Restore that projection
        // after removing whichever exact key the caller selected.
        if let Some(property) = self
            .java_entries
            .values()
            .find(|property| property.key == key)
            .cloned()
        {
            self.entries.insert(key.to_owned(), property);
        }
    }

    /// Returns exact-key iteration without projecting surrogate code units.
    pub fn iter_java(&self) -> impl Iterator<Item = (&JavaString, &ResolvedProperty)> {
        self.java_entries.iter()
    }
}

impl fmt::Debug for PropertyMap {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_map()
            .entries(self.java_entries.iter())
            .finish()
    }
}

impl<'a> IntoIterator for &'a PropertyMap {
    type Item = (&'a String, &'a ResolvedProperty);
    type IntoIter = std::collections::btree_map::Iter<'a, String, ResolvedProperty>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
}

/// The type of an ordered plan operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PropertyOperationKind {
    /// Read a Java properties file.
    LoadFile,
    /// Apply an inline assignment to the namespace carried by the operation.
    Assignment,
    /// Remove an inline property whose value was explicitly empty (`-Jkey=`
    /// or `-Dkey=`).
    Remove,
    /// Apply a proxy-derived system property.
    Proxy,
    /// Apply a logging directive.
    Logging,
}

/// One ordered property/configuration operation.
#[derive(Clone, Eq, PartialEq)]
pub struct PropertyOperation {
    /// Operation kind.
    pub kind: PropertyOperationKind,
    /// Destination namespace.
    pub namespace: ConfigNamespace,
    /// Source/provenance role.
    pub source: ConfigSource,
    /// Exact key for an inline operation; absent for a file load.
    pub key: Option<String>,
    /// Exact value for an inline operation; absent for a file load.
    pub value: Option<PropertyValue>,
    /// Zero-based operation position.
    pub order: usize,
}

impl fmt::Debug for PropertyOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redact_value = self.key.as_deref().is_some_and(super::is_sensitive_key);
        let redacted_value = self
            .value
            .as_ref()
            .map(|_| PropertyValue::sensitive(REDACTED));
        let value = if redact_value {
            &redacted_value
        } else {
            &self.value
        };
        formatter
            .debug_struct("PropertyOperation")
            .field("kind", &self.kind)
            .field("namespace", &self.namespace)
            .field("source", &self.source)
            .field("key", &self.key)
            .field("value", value)
            .field("order", &self.order)
            .finish()
    }
}

/// A parsed logging directive retained by the configuration plan.
#[derive(Clone, Eq, PartialEq)]
pub struct LoggingDirective {
    /// Optional logger category.
    pub category: Option<String>,
    /// Exact level string.
    pub level: String,
    /// Original option occurrence index.
    pub occurrence: usize,
}

impl fmt::Debug for LoggingDirective {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoggingDirective")
            .field("category", &self.category)
            .field("level", &self.level)
            .field("occurrence", &self.occurrence)
            .finish()
    }
}

/// Ordered logging directives selected by `-L`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LoggingConfig {
    /// Directives in command-line order.
    pub directives: Vec<LoggingDirective>,
}

impl LoggingConfig {
    /// Creates an empty logging configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a directive while retaining order.
    pub fn push(&mut self, directive: LoggingDirective) {
        self.directives.push(directive);
    }

    /// Returns directives in order.
    #[must_use]
    pub fn directives(&self) -> &[LoggingDirective] {
        &self.directives
    }
}

/// An ordered, side-effect-free property resolution plan.
#[derive(Clone, Eq, PartialEq)]
pub struct ConfigPlan {
    /// Ordered file loads and inline assignments.
    pub operations: Vec<PropertyOperation>,
    /// Optional base directory used for relative source paths.
    pub base_dir: Option<PathBuf>,
    /// Optional JMeter home selected by `-d`.  It is intentionally separate
    /// from [`Self::base_dir`]: command-line paths are relative to the
    /// working directory, while JMeter uses the home/bin fallback for
    /// dynamic user/system property files.
    pub jmeter_home: Option<PathBuf>,
    /// Logging directives extracted from `-L` occurrences.
    pub logging: LoggingConfig,
}

impl Default for ConfigPlan {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ConfigPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfigPlan")
            .field("operations", &self.operations)
            .field("base_dir", &self.base_dir)
            .field("jmeter_home", &self.jmeter_home)
            .field("logging", &self.logging)
            .finish()
    }
}

impl ConfigPlan {
    /// Creates an empty plan.  Callers can add sources and assignments with
    /// the explicit `push_*` methods.
    #[must_use]
    pub fn new() -> Self {
        Self {
            operations: Vec::new(),
            base_dir: None,
            jmeter_home: None,
            logging: LoggingConfig::new(),
        }
    }

    /// Builds a plan from parsed CLI options without touching the filesystem.
    #[must_use]
    pub fn from_options(options: &CliOptions) -> Self {
        let mut plan = Self::new();
        if !matches!(options.action, Action::Execute) {
            return plan;
        }
        plan.jmeter_home = options.home_dir.as_deref().map(PathBuf::from);

        let primary = options.propfile.as_deref().map_or_else(
            || ConfigSource::DefaultPrimary {
                path: PathBuf::from("jmeter.properties"),
            },
            |path| ConfigSource::ExplicitPrimary {
                path: PathBuf::from(path),
            },
        );
        plan.push_file(primary);
        plan.push_file(ConfigSource::DefaultUser {
            path: PathBuf::from("user.properties"),
        });
        plan.push_file(ConfigSource::DefaultSystem {
            path: PathBuf::from("system.properties"),
        });

        for occurrence in &options.occurrences {
            match occurrence.id {
                OptionId::Addprop => {
                    if let Some(path) = occurrence.value() {
                        plan.push_file(ConfigSource::AdditionalJmeter {
                            path: PathBuf::from(path),
                            occurrence: occurrence.index,
                        });
                    }
                }
                OptionId::SystemPropertyFile => {
                    if let Some(path) = occurrence.value() {
                        plan.push_file(ConfigSource::AdditionalSystem {
                            path: PathBuf::from(path),
                            occurrence: occurrence.index,
                        });
                    }
                }
                OptionId::Jmeterproperty => {
                    if let Some(assignment) = parse_inline_assignment(occurrence.value()) {
                        plan.push_assignment_or_remove(
                            ConfigNamespace::Jmeter,
                            assignment.key,
                            assignment.value,
                            occurrence.index,
                        );
                    }
                }
                OptionId::Systemproperty => {
                    if let Some(assignment) = parse_inline_assignment(occurrence.value()) {
                        plan.push_assignment_or_remove(
                            ConfigNamespace::System,
                            assignment.key,
                            assignment.value,
                            occurrence.index,
                        );
                    }
                }
                OptionId::Globalproperty => {
                    if let Some(value) = occurrence.value() {
                        // JMeter treats an empty RHS as the file form.  In
                        // particular `-Gfoo=` is a request to read a path
                        // named `foo`; the separator is not part of the path.
                        let assignment_value_is_nonempty = value
                            .split_once('=')
                            .is_some_and(|(_, property_value)| !property_value.is_empty());
                        if assignment_value_is_nonempty {
                            if let Some(assignment) = parse_inline_assignment(Some(value)) {
                                plan.push_assignment(
                                    ConfigNamespace::Global,
                                    assignment.key,
                                    assignment.value,
                                    occurrence.index,
                                );
                            }
                        } else if !value.is_empty() {
                            let path = value.split_once('=').map_or(value, |(path, _)| path);
                            if path.is_empty() {
                                continue;
                            }
                            plan.push_file(ConfigSource::Global {
                                path: PathBuf::from(path),
                                occurrence: occurrence.index,
                            });
                        }
                    }
                }
                // JMeter applies proxy options in its post-property startup
                // phase.  They are appended below in that fixed phase order,
                // so a `-J`/`-D` value cannot accidentally override a proxy
                // flag merely because it appeared later in argv.
                OptionId::ProxyScheme
                | OptionId::ProxyHost
                | OptionId::ProxyPort
                | OptionId::NonProxyHosts
                | OptionId::Username
                | OptionId::Password => {}
                OptionId::Loglevel => {
                    if let Some(level) = occurrence.value().and_then(|raw| {
                        options
                            .log_levels
                            .iter()
                            .find(|candidate| candidate.raw == raw)
                    }) {
                        plan.logging.push(LoggingDirective {
                            category: level.category.clone(),
                            level: level.level.clone(),
                            occurrence: occurrence.index,
                        });
                        plan.operations.push(PropertyOperation {
                            kind: PropertyOperationKind::Logging,
                            namespace: ConfigNamespace::System,
                            source: ConfigSource::CommandLine {
                                namespace: ConfigNamespace::System,
                                occurrence: occurrence.index,
                            },
                            key: level.category.clone(),
                            value: Some(PropertyValue::new(level.level.clone())),
                            order: plan.operations.len(),
                        });
                    }
                }
                _ => {}
            }
        }

        let proxy_occurrence = |id| {
            options
                .occurrences
                .iter()
                .find(|occurrence| occurrence.id == id)
                .map(|occurrence| occurrence.index)
        };
        if let (Some(value), Some(occurrence)) = (
            options.proxy.username.as_deref(),
            proxy_occurrence(OptionId::Username),
        ) {
            plan.push_proxy_credential("proxyUser", value, occurrence, false);
        }
        if options.proxy.username.is_some()
            && let (Some(value), Some(occurrence)) = (
                options.proxy.password.as_deref(),
                proxy_occurrence(OptionId::Password),
            )
        {
            plan.push_proxy_credential("proxyPass", value, occurrence, true);
        }
        if let (Some(value), Some(occurrence)) = (
            options.proxy.host.as_deref(),
            proxy_occurrence(OptionId::ProxyHost),
        ) {
            plan.push_proxy_pair("proxyHost", value, occurrence);
        }
        if let (Some(value), Some(occurrence)) = (
            options.proxy.port.as_deref(),
            proxy_occurrence(OptionId::ProxyPort),
        ) {
            plan.push_proxy_pair("proxyPort", value, occurrence);
        }
        if options.proxy.host.is_some()
            && options.proxy.port.is_some()
            && let (Some(value), Some(occurrence)) = (
                options
                    .proxy
                    .scheme
                    .as_deref()
                    .filter(|value| !value.trim().is_empty()),
                proxy_occurrence(OptionId::ProxyScheme),
            )
        {
            plan.push_assignment_with_kind(
                ConfigNamespace::System,
                "http.proxyScheme".to_owned(),
                value.to_owned(),
                occurrence,
                PropertyOperationKind::Proxy,
            );
        }
        if let (Some(value), Some(occurrence)) = (
            options.proxy.non_proxy_hosts.as_deref(),
            proxy_occurrence(OptionId::NonProxyHosts),
        ) {
            plan.push_proxy_pair("nonProxyHosts", value, occurrence);
        }
        plan
    }

    /// Builds a plan from a complete parsed invocation.
    #[must_use]
    pub fn from_invocation(invocation: &CliInvocation) -> Self {
        Self::from_options(&invocation.options)
    }

    /// Alias for [`ConfigPlan::from_invocation`].
    #[must_use]
    pub fn from_cli(invocation: &CliInvocation) -> Self {
        Self::from_invocation(invocation)
    }

    /// Converts the existing pure `ConfigurationPlan` into a filesystem plan.
    #[must_use]
    pub fn from_configuration(configuration: &ConfigurationPlan) -> Self {
        let mut plan = Self::new();
        for step in configuration.steps() {
            match step {
                ConfigurationStep::LoadProperties { source } => {
                    plan.push_file(source_to_config_source(source));
                }
                ConfigurationStep::LoadUserProperties { .. } => {
                    plan.push_file(ConfigSource::DefaultUser {
                        path: PathBuf::from("user.properties"),
                    })
                }
                ConfigurationStep::LoadSystemProperties { .. } => {
                    plan.push_file(ConfigSource::DefaultSystem {
                        path: PathBuf::from("system.properties"),
                    })
                }
                ConfigurationStep::ApplyJmeterProperty {
                    assignment,
                    occurrence,
                } => plan.push_assignment_or_remove(
                    ConfigNamespace::Jmeter,
                    assignment.key.clone(),
                    assignment.value.clone(),
                    *occurrence,
                ),
                ConfigurationStep::ApplySystemProperty {
                    assignment,
                    occurrence,
                } => plan.push_assignment_or_remove(
                    ConfigNamespace::System,
                    assignment.key.clone(),
                    assignment.value.clone(),
                    *occurrence,
                ),
                ConfigurationStep::ApplyGlobalProperty {
                    property,
                    occurrence,
                } => match property {
                    GlobalProperty::Assignment(assignment) => plan.push_assignment_or_remove(
                        ConfigNamespace::Global,
                        assignment.key.clone(),
                        assignment.value.clone(),
                        *occurrence,
                    ),
                    GlobalProperty::File { path } => plan.push_file(ConfigSource::Global {
                        path: PathBuf::from(path),
                        occurrence: *occurrence,
                    }),
                },
                ConfigurationStep::ApplyProxy {
                    key,
                    value,
                    sensitive: _,
                    occurrence,
                } => {
                    let namespace = if key == &"http.proxyUser" || key == &"http.proxyPass" {
                        ConfigNamespace::Jmeter
                    } else {
                        ConfigNamespace::System
                    };
                    for key in key.split('/') {
                        plan.push_assignment_with_kind(
                            namespace,
                            key.to_owned(),
                            value.clone(),
                            *occurrence,
                            PropertyOperationKind::Proxy,
                        );
                    }
                }
                ConfigurationStep::ApplyLogLevel { level, occurrence } => {
                    plan.logging.push(logging_from_level(level, *occurrence));
                    plan.operations.push(PropertyOperation {
                        kind: PropertyOperationKind::Logging,
                        namespace: ConfigNamespace::System,
                        source: ConfigSource::CommandLine {
                            namespace: ConfigNamespace::System,
                            occurrence: *occurrence,
                        },
                        key: level.category.clone(),
                        value: Some(PropertyValue::new(level.level.clone())),
                        order: plan.operations.len(),
                    });
                }
                ConfigurationStep::SelectJmeterLog { .. }
                | ConfigurationStep::InitializeLogging { .. }
                | ConfigurationStep::SelectInputs { .. } => {}
            }
        }
        plan
    }

    /// Sets the base directory used for relative file sources.
    #[must_use]
    pub fn with_base_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.base_dir = Some(path.into());
        self
    }

    /// Sets the JMeter home used for dynamic property-file fallback.
    #[must_use]
    pub fn with_jmeter_home(mut self, path: impl Into<PathBuf>) -> Self {
        self.jmeter_home = Some(path.into());
        self
    }

    /// Appends a file load operation.
    pub fn push_file(&mut self, source: ConfigSource) {
        let namespace = source.namespace();
        self.operations.push(PropertyOperation {
            kind: PropertyOperationKind::LoadFile,
            namespace,
            source,
            key: None,
            value: None,
            order: self.operations.len(),
        });
    }

    /// Appends an inline assignment using the normal assignment kind.
    pub fn push_assignment(
        &mut self,
        namespace: ConfigNamespace,
        key: impl Into<String>,
        value: impl Into<String>,
        occurrence: usize,
    ) {
        self.push_assignment_with_kind(
            namespace,
            key.into(),
            value.into(),
            occurrence,
            PropertyOperationKind::Assignment,
        );
    }

    /// Appends an assignment, mapping an explicitly empty value to JMeter's
    /// command-line removal form.
    pub fn push_assignment_or_remove(
        &mut self,
        namespace: ConfigNamespace,
        key: impl Into<String>,
        value: impl Into<String>,
        occurrence: usize,
    ) {
        let key = key.into();
        let value = value.into();
        if value.is_empty() {
            self.operations.push(PropertyOperation {
                kind: PropertyOperationKind::Remove,
                namespace,
                source: ConfigSource::CommandLine {
                    namespace,
                    occurrence,
                },
                key: Some(key),
                value: Some(PropertyValue::new(value)),
                order: self.operations.len(),
            });
        } else {
            self.push_assignment(namespace, key, value, occurrence);
        }
    }

    fn push_assignment_with_kind(
        &mut self,
        namespace: ConfigNamespace,
        key: String,
        value: String,
        occurrence: usize,
        kind: PropertyOperationKind,
    ) {
        self.operations.push(PropertyOperation {
            kind,
            namespace,
            source: ConfigSource::CommandLine {
                namespace,
                occurrence,
            },
            key: Some(key),
            value: Some(PropertyValue::new(value)),
            order: self.operations.len(),
        });
        // The key is set in the operation immediately above.  Recompute the
        // sensitivity from that exact key to avoid retaining any secret in a
        // diagnostic built from a stale caller-side assignment.
        if let Some(operation) = self.operations.last_mut()
            && let (Some(key), Some(value)) = (&operation.key, &mut operation.value)
        {
            value.sensitive = super::is_sensitive_key(key);
        }
    }

    fn push_proxy_pair(&mut self, key: &str, value: &str, occurrence: usize) {
        self.push_assignment_with_kind(
            ConfigNamespace::System,
            format!("http.{key}"),
            value.to_owned(),
            occurrence,
            PropertyOperationKind::Proxy,
        );
        self.push_assignment_with_kind(
            ConfigNamespace::System,
            format!("https.{key}"),
            value.to_owned(),
            occurrence,
            PropertyOperationKind::Proxy,
        );
    }

    fn push_proxy_credential(
        &mut self,
        key: &str,
        value: &str,
        occurrence: usize,
        sensitive: bool,
    ) {
        self.push_assignment_with_kind(
            ConfigNamespace::Jmeter,
            format!("http.{key}"),
            value.to_owned(),
            occurrence,
            PropertyOperationKind::Proxy,
        );
        if sensitive
            && let Some(operation) = self.operations.last_mut()
            && let Some(property_value) = &mut operation.value
        {
            property_value.sensitive = true;
        }
    }

    /// Resolves this plan through an explicit loader.
    pub fn resolve(&self, loader: &ConfigLoader) -> Result<ResolvedConfig, ConfigError> {
        loader.resolve(self)
    }

    /// Returns operations in deterministic order.
    #[must_use]
    pub fn operations(&self) -> &[PropertyOperation] {
        &self.operations
    }
}

/// Ordered, executor-neutral configuration startup phases.
///
/// The phase names intentionally mirror the pinned JMeter startup boundary:
/// primary properties are available before the run log is selected, logging
/// is initialized before the implicit user/system files are read, and only
/// then are the remaining command-line operations applied.  This type does
/// not read files, create logs, inspect the process environment, or start a
/// process.  An adapter owns those capabilities and acknowledges each typed
/// request with a [`ConfigPhaseEvent`].
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ConfigPhase {
    /// The CLI has been parsed, but no configuration request was completed.
    Parsed,
    /// The selected primary properties source was loaded.
    PrimaryLoaded,
    /// The run-log target was selected.
    LogSelected,
    /// The logging adapter acknowledged initialization.
    LoggingReady,
    /// The implicit user properties source was handled.
    User,
    /// The implicit system properties source was handled.
    System,
    /// Remaining command-line operations are being applied in order.
    RemainingCli,
    /// Test and result input paths were selected.
    Inputs,
    /// All configuration phases completed successfully.
    Ready,
    /// A reducer or adapter failure made the machine terminal.
    Failed,
}

impl ConfigPhase {
    /// Returns whether no further request may be accepted.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Ready | Self::Failed)
    }
}

/// The selected test/result inputs carried by the final startup request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigPhaseInputs {
    /// Test plan path, if this mode runs a test plan.
    pub testfile: Option<super::PathArgument>,
    /// Result log path, if this mode writes one.
    pub logfile: Option<super::PathArgument>,
    /// Input JTL for report-only mode.
    pub report_only_file: Option<String>,
    /// Dashboard output directory.
    pub report_output_folder: Option<String>,
}

/// A side-effect-free request made by [`ConfigPhaseMachine`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfigPhaseRequest {
    /// Load the selected primary properties source.
    LoadPrimary { source: ConfigSource },
    /// Select the run-log target without creating or opening it.
    SelectJmeterLog { target: super::LogTarget },
    /// Ask the logging adapter to initialize against the selected target.
    InitializeLogging {
        /// Optional Log4j configuration path selected by `-i`.
        config_file: Option<String>,
        /// The target selected by the preceding request.
        target: super::LogTarget,
    },
    /// Load the dynamic/default user properties source.
    LoadUserProperties { source: ConfigSource },
    /// A primary property explicitly disabled the user source.
    SkipUserProperties,
    /// Load the dynamic/default Java system properties source.
    LoadSystemProperties { source: ConfigSource },
    /// A primary property explicitly disabled the system source.
    SkipSystemProperties,
    /// Apply one remaining CLI operation, retaining its namespace and
    /// original occurrence index in the embedded [`PropertyOperation`].
    ApplyCli { operation: PropertyOperation },
    /// Select paths and report inputs after all property operations finish.
    SelectInputs { inputs: ConfigPhaseInputs },
}

impl ConfigPhaseRequest {
    const fn expected_event(&self) -> ConfigPhaseEventKind {
        match self {
            Self::LoadPrimary { .. } => ConfigPhaseEventKind::PrimaryLoaded,
            Self::SelectJmeterLog { .. } => ConfigPhaseEventKind::LogSelected,
            Self::InitializeLogging { .. } => ConfigPhaseEventKind::LoggingReady,
            Self::LoadUserProperties { .. } => ConfigPhaseEventKind::UserPropertiesLoaded,
            Self::SkipUserProperties => ConfigPhaseEventKind::UserPropertiesSkipped,
            Self::LoadSystemProperties { .. } => ConfigPhaseEventKind::SystemPropertiesLoaded,
            Self::SkipSystemProperties => ConfigPhaseEventKind::SystemPropertiesSkipped,
            Self::ApplyCli { .. } => ConfigPhaseEventKind::CliApplied,
            Self::SelectInputs { .. } => ConfigPhaseEventKind::InputsSelected,
        }
    }
}

/// A reducer acknowledgement or explicit failure for a configuration request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfigPhaseEvent {
    /// The primary source was loaded and decoded in memory.
    PrimaryLoaded {
        /// The source acknowledged by the reducer.
        source: ConfigSource,
        /// The decoded primary map used only for selector derivation.
        properties: PropertyMap,
    },
    /// The run-log target was selected.
    LogSelected { target: super::LogTarget },
    /// The logging adapter is ready for subsequent property loads.
    LoggingReady {
        /// The Log4j configuration path acknowledged by the adapter.
        config_file: Option<String>,
        /// The run-log target acknowledged by the adapter.
        target: super::LogTarget,
    },
    /// The user properties source was loaded.
    UserPropertiesLoaded { source: ConfigSource },
    /// The user properties source was intentionally disabled.
    UserPropertiesSkipped,
    /// The Java system properties source was loaded.
    SystemPropertiesLoaded { source: ConfigSource },
    /// The Java system properties source was intentionally disabled.
    SystemPropertiesSkipped,
    /// One deferred CLI operation was applied.
    CliApplied { operation: PropertyOperation },
    /// The final input selection was acknowledged.
    InputsSelected { inputs: ConfigPhaseInputs },
    /// A capability adapter failed.  The machine becomes terminal and will
    /// reject every later event.
    Failed { code: &'static str },
}

impl ConfigPhaseEvent {
    const fn kind(&self) -> Option<ConfigPhaseEventKind> {
        Some(match self {
            Self::PrimaryLoaded { .. } => ConfigPhaseEventKind::PrimaryLoaded,
            Self::LogSelected { .. } => ConfigPhaseEventKind::LogSelected,
            Self::LoggingReady { .. } => ConfigPhaseEventKind::LoggingReady,
            Self::UserPropertiesLoaded { .. } => ConfigPhaseEventKind::UserPropertiesLoaded,
            Self::UserPropertiesSkipped => ConfigPhaseEventKind::UserPropertiesSkipped,
            Self::SystemPropertiesLoaded { .. } => ConfigPhaseEventKind::SystemPropertiesLoaded,
            Self::SystemPropertiesSkipped => ConfigPhaseEventKind::SystemPropertiesSkipped,
            Self::CliApplied { .. } => ConfigPhaseEventKind::CliApplied,
            Self::InputsSelected { .. } => ConfigPhaseEventKind::InputsSelected,
            Self::Failed { .. } => return None,
        })
    }
}

/// Stable event labels used by phase-transition errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigPhaseEventKind {
    /// [`ConfigPhaseEvent::PrimaryLoaded`].
    PrimaryLoaded,
    /// [`ConfigPhaseEvent::LogSelected`].
    LogSelected,
    /// [`ConfigPhaseEvent::LoggingReady`].
    LoggingReady,
    /// [`ConfigPhaseEvent::UserPropertiesLoaded`].
    UserPropertiesLoaded,
    /// [`ConfigPhaseEvent::UserPropertiesSkipped`].
    UserPropertiesSkipped,
    /// [`ConfigPhaseEvent::SystemPropertiesLoaded`].
    SystemPropertiesLoaded,
    /// [`ConfigPhaseEvent::SystemPropertiesSkipped`].
    SystemPropertiesSkipped,
    /// [`ConfigPhaseEvent::CliApplied`].
    CliApplied,
    /// [`ConfigPhaseEvent::InputsSelected`].
    InputsSelected,
}

/// Fail-closed errors from the executor-neutral phase reducer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfigPhaseError {
    /// The event kind does not belong to the current request.
    UnexpectedEvent {
        /// Phase in which the event was rejected.
        phase: ConfigPhase,
        /// Event required by the current request, if one exists.
        expected: Option<ConfigPhaseEventKind>,
        /// Event supplied by the reducer.
        actual: Option<ConfigPhaseEventKind>,
    },
    /// The event kind was correct but its source, target, or operation did
    /// not exactly match the request.  Payload values are deliberately not
    /// retained in this diagnostic.
    PayloadMismatch {
        /// Phase in which the payload was rejected.
        phase: ConfigPhase,
        /// Event whose payload did not match.
        event: ConfigPhaseEventKind,
    },
    /// A capability adapter reported a stable failure code.
    ReducerFailure {
        /// Phase at which the capability failed.
        phase: ConfigPhase,
        /// Stable adapter code; no user value is embedded.
        code: &'static str,
    },
    /// An event was submitted after the machine had reached a terminal phase.
    Terminal {
        /// The terminal phase (`Failed`).
        phase: ConfigPhase,
    },
}

impl ConfigPhaseError {
    /// Returns the stable diagnostic code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnexpectedEvent { .. } => "config.phase-unexpected-event",
            Self::PayloadMismatch { .. } => "config.phase-payload-mismatch",
            Self::ReducerFailure { code, .. } => code,
            Self::Terminal { .. } => "config.phase-terminal",
        }
    }

    /// Returns the phase at which the error was produced.
    #[must_use]
    pub const fn phase(&self) -> ConfigPhase {
        match self {
            Self::UnexpectedEvent { phase, .. }
            | Self::PayloadMismatch { phase, .. }
            | Self::ReducerFailure { phase, .. }
            | Self::Terminal { phase } => *phase,
        }
    }
}

impl fmt::Display for ConfigPhaseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEvent {
                phase,
                expected,
                actual,
            } => write!(
                formatter,
                "{}: unexpected event in {phase:?} (expected={expected:?}, actual={actual:?})",
                self.code()
            ),
            Self::PayloadMismatch { phase, event } => {
                write!(
                    formatter,
                    "{}: payload mismatch in {phase:?} ({event:?})",
                    self.code()
                )
            }
            Self::ReducerFailure { phase, code } => {
                write!(formatter, "{code}: capability failed in {phase:?}")
            }
            Self::Terminal { phase } => write!(formatter, "{}: phase={phase:?}", self.code()),
        }
    }
}

impl Error for ConfigPhaseError {}

/// Pure startup reducer for the pinned primary/logging/user/system/CLI order.
///
/// Constructing this machine only copies parsed CLI data into requests.  The
/// caller supplies decoded property maps and capability acknowledgements via
/// [`Self::advance`], making the ordering testable without filesystem,
/// process, logger, locale, timezone, or environment side effects.
#[derive(Clone, Debug)]
pub struct ConfigPhaseMachine {
    phase: ConfigPhase,
    request: Option<ConfigPhaseRequest>,
    terminal_error: Option<ConfigPhaseError>,
    primary_properties: Option<PropertyMap>,
    deferred_operations: Vec<PropertyOperation>,
    deferred_index: usize,
    file_names: ConfigFileNames,
    log_config_file: Option<String>,
    log_target: super::LogTarget,
    inputs: ConfigPhaseInputs,
}

impl ConfigPhaseMachine {
    /// Creates a machine using the standard implicit property filenames.
    #[must_use]
    pub fn from_options(options: &CliOptions) -> Self {
        Self::from_options_with_file_names(options, ConfigFileNames::standard())
    }

    /// Creates a machine using explicit names for implicit property sources.
    #[must_use]
    pub fn from_options_with_file_names(options: &CliOptions, file_names: ConfigFileNames) -> Self {
        let inputs = ConfigPhaseInputs {
            testfile: options.testfile.clone(),
            logfile: options.logfile.clone(),
            report_only_file: options.report_only_file.clone(),
            report_output_folder: options.report_output_folder.clone(),
        };
        let log_target = options
            .jmeterlogfile
            .clone()
            .map_or(super::LogTarget::Default, super::LogTarget::Selected);
        if !matches!(options.action, Action::Execute) {
            return Self {
                phase: ConfigPhase::Ready,
                request: None,
                terminal_error: None,
                primary_properties: None,
                deferred_operations: Vec::new(),
                deferred_index: 0,
                file_names,
                log_config_file: options.jmeterlogconf.clone(),
                log_target,
                inputs,
            };
        }

        let primary = options.propfile.as_deref().map_or_else(
            || ConfigSource::DefaultPrimary {
                path: PathBuf::from(&file_names.jmeter),
            },
            |path| ConfigSource::ExplicitPrimary {
                path: PathBuf::from(path),
            },
        );
        let deferred_operations = ConfigPlan::from_options(options)
            .operations
            .into_iter()
            .filter(|operation| {
                !matches!(
                    operation.source,
                    ConfigSource::DefaultPrimary { .. }
                        | ConfigSource::ExplicitPrimary { .. }
                        | ConfigSource::DefaultUser { .. }
                        | ConfigSource::DefaultSystem { .. }
                )
            })
            .collect();

        Self {
            phase: ConfigPhase::Parsed,
            request: Some(ConfigPhaseRequest::LoadPrimary { source: primary }),
            terminal_error: None,
            primary_properties: None,
            deferred_operations,
            deferred_index: 0,
            file_names,
            log_config_file: options.jmeterlogconf.clone(),
            log_target,
            inputs,
        }
    }

    /// Creates a machine from a complete parsed invocation.
    #[must_use]
    pub fn from_invocation(invocation: &CliInvocation) -> Self {
        Self::from_options(&invocation.options)
    }

    /// Returns the current phase.
    #[must_use]
    pub const fn phase(&self) -> ConfigPhase {
        self.phase
    }

    /// Returns the request currently awaiting an acknowledgement.
    #[must_use]
    pub const fn current_request(&self) -> Option<&ConfigPhaseRequest> {
        self.request.as_ref()
    }

    /// Alias for [`Self::current_request`].
    #[must_use]
    pub const fn next_request(&self) -> Option<&ConfigPhaseRequest> {
        self.current_request()
    }

    /// Returns all deferred CLI operations in their original plan order.
    #[must_use]
    pub fn deferred_operations(&self) -> &[PropertyOperation] {
        &self.deferred_operations
    }

    /// Returns the first reducer error, if this machine failed closed.
    #[must_use]
    pub const fn terminal_error(&self) -> Option<&ConfigPhaseError> {
        self.terminal_error.as_ref()
    }

    /// Acknowledges one request and returns the next pure request.
    ///
    /// Any wrong event, mismatched payload, or explicit reducer failure moves
    /// the machine to [`ConfigPhase::Failed`].  Calls after that point return
    /// [`ConfigPhaseError::Terminal`] and never advance.
    pub fn advance(
        &mut self,
        event: ConfigPhaseEvent,
    ) -> Result<Option<ConfigPhaseRequest>, ConfigPhaseError> {
        if self.phase.is_terminal() {
            return Err(ConfigPhaseError::Terminal { phase: self.phase });
        }
        if let ConfigPhaseEvent::Failed { code } = event {
            return Err(self.fail(ConfigPhaseError::ReducerFailure {
                phase: self.phase,
                code,
            }));
        }

        let actual = event.kind();
        let Some(request) = self.request.clone() else {
            return Err(self.fail(ConfigPhaseError::UnexpectedEvent {
                phase: self.phase,
                expected: None,
                actual,
            }));
        };
        let expected_event = request.expected_event();
        if Some(expected_event) != actual {
            return Err(self.fail(ConfigPhaseError::UnexpectedEvent {
                phase: self.phase,
                expected: Some(expected_event),
                actual,
            }));
        }

        match (request, event) {
            (
                ConfigPhaseRequest::LoadPrimary { source: expected },
                ConfigPhaseEvent::PrimaryLoaded { source, properties },
            ) => {
                if source != expected {
                    return Err(self.fail(ConfigPhaseError::PayloadMismatch {
                        phase: self.phase,
                        event: ConfigPhaseEventKind::PrimaryLoaded,
                    }));
                }
                self.primary_properties = Some(properties);
                self.phase = ConfigPhase::PrimaryLoaded;
                self.request = Some(ConfigPhaseRequest::SelectJmeterLog {
                    target: self.log_target.clone(),
                });
            }
            (
                ConfigPhaseRequest::SelectJmeterLog { target: expected },
                ConfigPhaseEvent::LogSelected { target },
            ) => {
                if target != expected {
                    return Err(self.fail(ConfigPhaseError::PayloadMismatch {
                        phase: self.phase,
                        event: ConfigPhaseEventKind::LogSelected,
                    }));
                }
                self.phase = ConfigPhase::LogSelected;
                self.request = Some(ConfigPhaseRequest::InitializeLogging {
                    config_file: self.log_config_file.clone(),
                    target: expected,
                });
            }
            (
                ConfigPhaseRequest::InitializeLogging {
                    config_file: expected_config,
                    target: expected_target,
                },
                ConfigPhaseEvent::LoggingReady {
                    config_file,
                    target,
                },
            ) => {
                if config_file != expected_config || target != expected_target {
                    return Err(self.fail(ConfigPhaseError::PayloadMismatch {
                        phase: self.phase,
                        event: ConfigPhaseEventKind::LoggingReady,
                    }));
                }
                self.phase = ConfigPhase::LoggingReady;
                self.request = Some(self.user_request());
            }
            (
                ConfigPhaseRequest::LoadUserProperties { source: expected },
                ConfigPhaseEvent::UserPropertiesLoaded { source },
            ) => {
                if source != expected {
                    return Err(self.fail(ConfigPhaseError::PayloadMismatch {
                        phase: self.phase,
                        event: ConfigPhaseEventKind::UserPropertiesLoaded,
                    }));
                }
                self.phase = ConfigPhase::User;
                self.request = Some(self.system_request());
            }
            (ConfigPhaseRequest::SkipUserProperties, ConfigPhaseEvent::UserPropertiesSkipped) => {
                self.phase = ConfigPhase::User;
                self.request = Some(self.system_request());
            }
            (
                ConfigPhaseRequest::LoadSystemProperties { source: expected },
                ConfigPhaseEvent::SystemPropertiesLoaded { source },
            ) => {
                if source != expected {
                    return Err(self.fail(ConfigPhaseError::PayloadMismatch {
                        phase: self.phase,
                        event: ConfigPhaseEventKind::SystemPropertiesLoaded,
                    }));
                }
                self.begin_remaining_cli();
            }
            (
                ConfigPhaseRequest::SkipSystemProperties,
                ConfigPhaseEvent::SystemPropertiesSkipped,
            ) => self.begin_remaining_cli(),
            (
                ConfigPhaseRequest::ApplyCli {
                    operation: expected,
                },
                ConfigPhaseEvent::CliApplied { operation },
            ) => {
                if operation != expected
                    || self.deferred_operations.get(self.deferred_index) != Some(&expected)
                {
                    return Err(self.fail(ConfigPhaseError::PayloadMismatch {
                        phase: self.phase,
                        event: ConfigPhaseEventKind::CliApplied,
                    }));
                }
                if self.phase == ConfigPhase::System {
                    self.phase = ConfigPhase::RemainingCli;
                }
                self.deferred_index += 1;
                self.request = self
                    .deferred_operations
                    .get(self.deferred_index)
                    .cloned()
                    .map(|operation| ConfigPhaseRequest::ApplyCli { operation });
                if self.request.is_none() {
                    self.phase = ConfigPhase::Inputs;
                    self.request = Some(ConfigPhaseRequest::SelectInputs {
                        inputs: self.inputs.clone(),
                    });
                }
            }
            (
                ConfigPhaseRequest::SelectInputs { inputs: expected },
                ConfigPhaseEvent::InputsSelected { inputs },
            ) => {
                if inputs != expected {
                    return Err(self.fail(ConfigPhaseError::PayloadMismatch {
                        phase: self.phase,
                        event: ConfigPhaseEventKind::InputsSelected,
                    }));
                }
                self.phase = ConfigPhase::Ready;
                self.request = None;
            }
            _ => {
                return Err(self.fail(ConfigPhaseError::UnexpectedEvent {
                    phase: self.phase,
                    expected: Some(expected_event),
                    actual,
                }));
            }
        }
        Ok(self.request.clone())
    }

    fn user_request(&self) -> ConfigPhaseRequest {
        match self.primary_properties.as_ref().and_then(|properties| {
            selected_dynamic_source(
                properties,
                "user.properties",
                &self.file_names.user,
                |path| ConfigSource::DefaultUser { path },
            )
        }) {
            Some(source) => ConfigPhaseRequest::LoadUserProperties { source },
            None => ConfigPhaseRequest::SkipUserProperties,
        }
    }

    fn system_request(&self) -> ConfigPhaseRequest {
        match self.primary_properties.as_ref().and_then(|properties| {
            selected_dynamic_source(
                properties,
                "system.properties",
                &self.file_names.system,
                |path| ConfigSource::DefaultSystem { path },
            )
        }) {
            Some(source) => ConfigPhaseRequest::LoadSystemProperties { source },
            None => ConfigPhaseRequest::SkipSystemProperties,
        }
    }

    fn begin_remaining_cli(&mut self) {
        self.phase = ConfigPhase::System;
        self.request = self
            .deferred_operations
            .first()
            .cloned()
            .map(|operation| ConfigPhaseRequest::ApplyCli { operation });
        if self.request.is_none() {
            self.phase = ConfigPhase::Inputs;
            self.request = Some(ConfigPhaseRequest::SelectInputs {
                inputs: self.inputs.clone(),
            });
        }
    }

    fn fail(&mut self, error: ConfigPhaseError) -> ConfigPhaseError {
        self.phase = ConfigPhase::Failed;
        self.request = None;
        self.terminal_error = Some(error.clone());
        error
    }
}

/// Selects an implicit user/system source from the primary map without
/// resolving the path or opening it.  Empty selector values disable the
/// corresponding source, matching JMeter's startup property semantics.
fn selected_dynamic_source(
    primary: &PropertyMap,
    selector: &str,
    default_name: &str,
    constructor: fn(PathBuf) -> ConfigSource,
) -> Option<ConfigSource> {
    let selected = primary.get_value(selector).unwrap_or(default_name);
    if selected.is_empty() {
        None
    } else {
        Some(constructor(PathBuf::from(selected)))
    }
}

fn source_to_config_source(source: &PropertySource) -> ConfigSource {
    match source {
        PropertySource::ExplicitPrimary { path } => ConfigSource::ExplicitPrimary {
            path: PathBuf::from(path),
        },
        PropertySource::DefaultPrimary => ConfigSource::DefaultPrimary {
            path: PathBuf::from("jmeter.properties"),
        },
        PropertySource::DefaultUser => ConfigSource::DefaultUser {
            path: PathBuf::from("user.properties"),
        },
        PropertySource::DefaultSystem => ConfigSource::DefaultSystem {
            path: PathBuf::from("system.properties"),
        },
        PropertySource::AdditionalJmeter { path, occurrence } => ConfigSource::AdditionalJmeter {
            path: PathBuf::from(path),
            occurrence: *occurrence,
        },
        PropertySource::AdditionalSystem { path, occurrence } => ConfigSource::AdditionalSystem {
            path: PathBuf::from(path),
            occurrence: *occurrence,
        },
        PropertySource::Global { path, occurrence } => ConfigSource::Global {
            path: PathBuf::from(path),
            occurrence: *occurrence,
        },
    }
}

fn logging_from_level(level: &LogLevel, occurrence: usize) -> LoggingDirective {
    LoggingDirective {
        category: level.category.clone(),
        level: level.level.clone(),
        occurrence,
    }
}

fn parse_inline_assignment(value: Option<&str>) -> Option<PropertyAssignmentOwned> {
    let value = value?;
    let (key, property_value) = value.split_once('=')?;
    if key.is_empty() {
        return None;
    }
    Some(PropertyAssignmentOwned {
        key: key.to_owned(),
        value: property_value.to_owned(),
    })
}

struct PropertyAssignmentOwned {
    key: String,
    value: String,
}

/// A non-fatal configuration diagnostic retained with a resolved plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfigWarning {
    /// A repeatable optional file source was not present.  This mirrors
    /// JMeter's warning-and-continue behavior for `-q`, `-S`, and `-G`.
    MissingSource {
        /// Source role and original occurrence.
        source: ConfigSource,
        /// Canonical/requested path that was checked.
        path: PathBuf,
    },
}

impl ConfigWarning {
    /// Returns a stable machine-readable warning code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::MissingSource { .. } => "config.missing-optional-source",
        }
    }
}

impl fmt::Display for ConfigWarning {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSource { source, path } => write!(
                formatter,
                "optional configuration source {source} is unavailable at {}",
                path.display()
            ),
        }
    }
}

/// Provenance records for properties explicitly removed by `-J`/`-D` (or a
/// manually constructed equivalent).  A removed key is absent from its final
/// map, but its removal remains auditable here.
pub type RemovalProvenance = BTreeMap<ConfigNamespace, BTreeMap<String, Vec<PropertyProvenance>>>;

/// The result of resolving a [`ConfigPlan`].
#[derive(Clone, Eq, PartialEq)]
pub struct ResolvedConfig {
    /// Effective local JMeter properties.
    pub jmeter: PropertyMap,
    /// Effective Java system properties.
    pub system: PropertyMap,
    /// Effective remote/global properties.
    pub global: PropertyMap,
    /// Ordered operations actually applied, including file loads.
    pub operations: Vec<PropertyOperation>,
    /// Effective logging directives.
    pub logging: LoggingConfig,
    /// Non-fatal missing-file diagnostics.
    pub warnings: Vec<ConfigWarning>,
    /// Provenance for explicit removals, grouped by namespace and key.
    pub removals: RemovalProvenance,
}

impl Default for ResolvedConfig {
    fn default() -> Self {
        Self {
            jmeter: PropertyMap::new(),
            system: PropertyMap::new(),
            global: PropertyMap::new(),
            operations: Vec::new(),
            logging: LoggingConfig::new(),
            warnings: Vec::new(),
            removals: RemovalProvenance::new(),
        }
    }
}

impl fmt::Debug for ResolvedConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedConfig")
            .field("jmeter", &self.jmeter)
            .field("system", &self.system)
            .field("global", &self.global)
            .field("operations", &self.operations)
            .field("logging", &self.logging)
            .field("warnings", &self.warnings)
            .field("removals", &self.removals)
            .finish()
    }
}

impl ResolvedConfig {
    /// Creates an empty resolved configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a namespace map.
    #[must_use]
    pub const fn namespace(&self, namespace: ConfigNamespace) -> &PropertyMap {
        match namespace {
            ConfigNamespace::Jmeter => &self.jmeter,
            ConfigNamespace::System => &self.system,
            ConfigNamespace::Global => &self.global,
        }
    }

    /// Returns an effective property by namespace and exact key.
    #[must_use]
    pub fn get(&self, namespace: ConfigNamespace, key: &str) -> Option<&ResolvedProperty> {
        self.namespace(namespace).get(key)
    }

    /// Returns only the effective value text.
    #[must_use]
    pub fn get_value(&self, namespace: ConfigNamespace, key: &str) -> Option<&str> {
        self.get(namespace, key).map(ResolvedProperty::as_str)
    }

    /// Returns the final map for JMeter properties.
    #[must_use]
    pub const fn jmeter_properties(&self) -> &PropertyMap {
        &self.jmeter
    }

    /// Returns the final map for Java system properties.
    #[must_use]
    pub const fn system_properties(&self) -> &PropertyMap {
        &self.system
    }

    /// Returns the final map for global properties.
    #[must_use]
    pub const fn global_properties(&self) -> &PropertyMap {
        &self.global
    }

    /// Returns retained removal provenance for a namespace/key pair.
    #[must_use]
    pub fn removal_provenance(
        &self,
        namespace: ConfigNamespace,
        key: &str,
    ) -> Option<&[PropertyProvenance]> {
        self.removals
            .get(&namespace)
            .and_then(|entries| entries.get(key))
            .map(Vec::as_slice)
    }

    /// Returns all retained removals for one namespace.
    #[must_use]
    pub fn removals(
        &self,
        namespace: ConfigNamespace,
    ) -> Option<&BTreeMap<String, Vec<PropertyProvenance>>> {
        self.removals.get(&namespace)
    }
}

/// Stable configuration-loader failures.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(
    missing_docs,
    reason = "error payload fields are self-describing and stable through code()"
)]
pub enum ConfigError {
    /// A source path could not be represented within configured limits.
    PathTooLong { path: PathBuf, limit: usize },
    /// The configured source did not exist or could not be opened.
    MissingSource { source: ConfigSource, path: PathBuf },
    /// An I/O error while reading a source.
    Io { path: PathBuf, message: String },
    /// A filesystem operation required by the bounded descriptor policy is
    /// unavailable on the current target.  Callers must not downgrade this
    /// to path-based I/O because doing so would remove the TOCTOU guarantee.
    Unsupported {
        capability: &'static str,
        path: PathBuf,
        message: String,
    },
    /// A filesystem source was requested without an explicit root or working
    /// directory.  The loader never resolves such a path through ambient CWD.
    UnrootedPath { path: PathBuf },
    /// The source resolved outside the configured root.
    OutsideRoot { path: PathBuf, root: PathBuf },
    /// The source path contains a disallowed symlink.
    SymlinkDenied { path: PathBuf },
    /// A symlink policy requiring a root was selected without one.
    SymlinkRootRequired { path: PathBuf },
    /// A source exceeded the byte limit.
    FileTooLarge { path: PathBuf, limit: usize },
    /// A source exceeded a logical resource limit.
    LimitExceeded {
        path: PathBuf,
        resource: &'static str,
        limit: usize,
    },
    /// Strict UTF-8 decoding failed.
    InvalidUtf8 { path: PathBuf },
    /// A Java Unicode escape was malformed.  Valid escapes are retained as
    /// exact UTF-16 units, including unpaired surrogates.
    InvalidEscape {
        path: PathBuf,
        line: usize,
        reason: &'static str,
    },
    /// A decoded key or value exceeded its configured limit.
    PropertyTooLong {
        path: PathBuf,
        line: usize,
        field: &'static str,
        limit: usize,
    },
    /// An operation in a manually constructed plan was incomplete.
    InvalidOperation { order: usize, reason: &'static str },
}

impl ConfigError {
    /// Returns a stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::PathTooLong { .. } => "config.path-too-long",
            Self::MissingSource { .. } => "config.missing-source",
            Self::Io { .. } => "config.io",
            Self::Unsupported { .. } => "config.unsupported-filesystem",
            Self::UnrootedPath { .. } => "config.unrooted-path",
            Self::OutsideRoot { .. } => "config.outside-root",
            Self::SymlinkDenied { .. } => "config.symlink-denied",
            Self::SymlinkRootRequired { .. } => "config.symlink-root-required",
            Self::FileTooLarge { .. } => "config.file-too-large",
            Self::LimitExceeded { .. } => "config.limit-exceeded",
            Self::InvalidUtf8 { .. } => "config.invalid-utf8",
            Self::InvalidEscape { .. } => "config.invalid-escape",
            Self::PropertyTooLong { .. } => "config.property-too-long",
            Self::InvalidOperation { .. } => "config.invalid-operation",
        }
    }

    /// Returns whether the failure is a target capability boundary rather
    /// than a malformed or unavailable user configuration.
    #[must_use]
    pub const fn is_unsupported(&self) -> bool {
        matches!(self, Self::Unsupported { .. })
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PathTooLong { path, limit } => {
                write!(
                    formatter,
                    "configuration path exceeds {limit} bytes: {}",
                    path.display()
                )
            }
            Self::MissingSource { source, path } => {
                write!(
                    formatter,
                    "configuration source {source} is unavailable at {}",
                    path.display()
                )
            }
            Self::Io { path, message } => {
                write!(
                    formatter,
                    "configuration read failed for {}: {message}",
                    path.display()
                )
            }
            Self::Unsupported {
                capability,
                path,
                message,
            } => write!(
                formatter,
                "configuration capability {capability} is unavailable for {}: {message}",
                path.display()
            ),
            Self::UnrootedPath { path } => write!(
                formatter,
                "configuration path {} requires an explicit root or working directory",
                path.display()
            ),
            Self::OutsideRoot { path, root } => write!(
                formatter,
                "configuration path {} is outside allowed root {}",
                path.display(),
                root.display()
            ),
            Self::SymlinkDenied { path } => {
                write!(
                    formatter,
                    "configuration symlink is not allowed: {}",
                    path.display()
                )
            }
            Self::SymlinkRootRequired { path } => write!(
                formatter,
                "symlink policy requires a containment root for {}",
                path.display()
            ),
            Self::FileTooLarge { path, limit } => {
                write!(
                    formatter,
                    "configuration file {} exceeds {limit} bytes",
                    path.display()
                )
            }
            Self::LimitExceeded {
                path,
                resource,
                limit,
            } => write!(
                formatter,
                "configuration file {} exceeds {resource} limit {limit}",
                path.display()
            ),
            Self::InvalidUtf8 { path } => {
                write!(
                    formatter,
                    "configuration file is not UTF-8: {}",
                    path.display()
                )
            }
            Self::InvalidEscape { path, line, reason } => write!(
                formatter,
                "invalid Java property escape in {} at line {line} ({reason})",
                path.display()
            ),
            Self::PropertyTooLong {
                path,
                line,
                field,
                limit,
            } => write!(
                formatter,
                "property {field} in {} at line {line} exceeds {limit} characters",
                path.display()
            ),
            Self::InvalidOperation { order, reason } => {
                write!(
                    formatter,
                    "invalid configuration operation #{order} ({reason})"
                )
            }
        }
    }
}

impl Error for ConfigError {}

/// Explicit filesystem/configuration capability.
#[derive(Clone, Debug, Default)]
pub struct ConfigLoader {
    /// Filesystem containment and symlink policy.
    pub fs_policy: ConfigFsPolicy,
    /// Resource limits.
    pub limits: ConfigLimits,
    /// Implicit source names.
    pub file_names: ConfigFileNames,
    /// Java properties decoder mode.
    pub decode_mode: DecodeMode,
    /// Explicit working directory used for relative CLI paths.  When absent,
    /// relative sources require an explicit filesystem root (or are treated
    /// as absent optional defaults); the loader never reads process
    /// `current_dir()`.
    pub working_dir: Option<PathBuf>,
}

impl ConfigLoader {
    /// Creates a loader with bounded defaults and no filesystem capability.
    /// Callers that need file sources must use [`Self::rooted`] or provide an
    /// explicit working directory/root policy.  Inline property decoding and
    /// plans containing only inline assignments remain supported.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a loader rooted at an explicit directory.
    #[must_use]
    pub fn rooted(root: impl Into<PathBuf>) -> Self {
        Self {
            fs_policy: ConfigFsPolicy::new(root),
            ..Self::default()
        }
    }

    /// Creates the explicitly rooted policy used by conformance callers.
    /// The default symlink-deny mode remains active; callers that need
    /// contained links must opt into [`SymlinkPolicy::AllowWithinRoot`].
    #[must_use]
    pub fn for_conformance(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            fs_policy: ConfigFsPolicy::new(&root),
            ..Self::default()
        }
    }

    /// Sets the filesystem policy.
    #[must_use]
    pub fn with_fs_policy(mut self, policy: ConfigFsPolicy) -> Self {
        self.fs_policy = policy;
        self
    }

    /// Alias for [`ConfigLoader::with_fs_policy`].
    #[must_use]
    pub fn with_policy(self, policy: ConfigFsPolicy) -> Self {
        self.with_fs_policy(policy)
    }

    /// Sets resource limits.
    #[must_use]
    pub fn with_limits(mut self, limits: ConfigLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Sets implicit source names.
    #[must_use]
    pub fn with_file_names(mut self, names: ConfigFileNames) -> Self {
        self.file_names = names;
        self
    }

    /// Sets the decoder mode.
    #[must_use]
    pub const fn with_decode_mode(mut self, mode: DecodeMode) -> Self {
        self.decode_mode = mode;
        self
    }

    /// Sets the explicit working directory used for relative paths.
    #[must_use]
    pub fn with_working_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.working_dir = Some(path.into());
        self
    }

    /// Resolves an ordered plan by reading its configured sources.
    pub fn resolve(&self, plan: &ConfigPlan) -> Result<ResolvedConfig, ConfigError> {
        if plan.operations.len() > self.limits.max_operations {
            return Err(ConfigError::LimitExceeded {
                path: PathBuf::from("<plan>"),
                resource: "operations",
                limit: self.limits.max_operations,
            });
        }
        if plan.logging.directives.len() > self.limits.max_operations {
            return Err(ConfigError::LimitExceeded {
                path: PathBuf::from("<plan>"),
                resource: "logging directives",
                limit: self.limits.max_operations,
            });
        }
        let mut resolved = ResolvedConfig::new();
        let mut total_properties = 0_usize;
        let mut total_provenance = 0_usize;
        let mut total_file_bytes = 0_usize;
        let working_dir = plan.base_dir.as_deref().or(self.working_dir.as_deref());
        for operation in &plan.operations {
            let mut effective_operation = operation.clone();
            match operation.kind {
                PropertyOperationKind::LoadFile => {
                    let path = operation
                        .source
                        .path()
                        .ok_or(ConfigError::InvalidOperation {
                            order: operation.order,
                            reason: "file-load-without-path",
                        })?;
                    let Some((mut source, source_path, dynamic_path)) =
                        self.dynamic_source(&resolved, &operation.source, path)
                    else {
                        resolved.operations.push(effective_operation);
                        continue;
                    };
                    let path = if dynamic_path {
                        source_path.clone()
                    } else {
                        self.source_path(&source, &source_path)
                    };
                    let resolved_path =
                        match self.resolve_file_path(plan, working_dir, &source, &path) {
                            Ok(value) => value,
                            Err(error @ ConfigError::MissingSource { .. })
                                if matches!(source, ConfigSource::ExplicitPrimary { .. }) =>
                            {
                                // JMeter's explicit primary load falls back to
                                // its ordinary jmeter.properties source.  Keep
                                // the fallback visible in operation/provenance
                                // instead of labeling the bytes as the missing
                                // `-p` path.
                                let fallback = ConfigSource::DefaultPrimary {
                                    path: PathBuf::from(&self.file_names.jmeter),
                                };
                                let fallback_path =
                                    self.source_path(&fallback, Path::new(&self.file_names.jmeter));
                                match self.resolve_file_path(
                                    plan,
                                    working_dir,
                                    &fallback,
                                    &fallback_path,
                                ) {
                                    Ok(Some(value)) => {
                                        source = fallback;
                                        Some(value)
                                    }
                                    Ok(None) | Err(ConfigError::MissingSource { .. }) => {
                                        return Err(error);
                                    }
                                    Err(other) => return Err(other),
                                }
                            }
                            Err(error) => return Err(error),
                        };
                    let Some(path) = resolved_path else {
                        self.record_missing_warning(&mut resolved, &source, &path);
                        resolved.operations.push(effective_operation);
                        continue;
                    };
                    effective_operation.source = source.clone();
                    let Some(bytes) = self.read_source(&source, &path)? else {
                        self.record_missing_warning(&mut resolved, &source, &path);
                        resolved.operations.push(effective_operation);
                        continue;
                    };
                    total_file_bytes = checked_total(
                        total_file_bytes,
                        bytes.len(),
                        self.limits.max_total_file_bytes,
                        &path,
                        "file bytes",
                    )?;
                    let entries =
                        parse_java_properties(&bytes, &path, self.decode_mode, self.limits)?;
                    for (key, value, line) in entries {
                        total_properties = checked_total(
                            total_properties,
                            1,
                            self.limits.max_resolved_properties,
                            &path,
                            "resolved properties",
                        )?;
                        total_provenance = checked_total(
                            total_provenance,
                            1,
                            self.limits.max_provenance_entries,
                            &path,
                            "provenance entries",
                        )?;
                        let provenance = PropertyProvenance {
                            source: source.clone(),
                            namespace: operation.namespace,
                            line,
                            operation: operation.order,
                        };
                        self.insert(
                            &mut resolved,
                            operation.namespace,
                            key,
                            value,
                            provenance,
                            &path,
                        )?;
                    }
                }
                PropertyOperationKind::Remove => {
                    let Some(key) = operation.key.as_deref() else {
                        return Err(ConfigError::InvalidOperation {
                            order: operation.order,
                            reason: "remove-without-key",
                        });
                    };
                    self.validate_inline_key(key)?;
                    total_properties = checked_total(
                        total_properties,
                        1,
                        self.limits.max_resolved_properties,
                        Path::new("<plan>"),
                        "resolved properties",
                    )?;
                    total_provenance = checked_total(
                        total_provenance,
                        1,
                        self.limits.max_provenance_entries,
                        Path::new("<plan>"),
                        "provenance entries",
                    )?;
                    let provenance = PropertyProvenance {
                        source: operation.source.clone(),
                        namespace: operation.namespace,
                        line: 0,
                        operation: operation.order,
                    };
                    self.remove(&mut resolved, operation.namespace, key, provenance);
                }
                PropertyOperationKind::Assignment | PropertyOperationKind::Proxy => {
                    let Some(key) = operation.key.clone() else {
                        return Err(ConfigError::InvalidOperation {
                            order: operation.order,
                            reason: "assignment-without-key",
                        });
                    };
                    let Some(value) = operation.value.clone() else {
                        return Err(ConfigError::InvalidOperation {
                            order: operation.order,
                            reason: "assignment-without-value",
                        });
                    };
                    self.validate_inline_key(&key)?;
                    self.validate_inline_value(&value)?;
                    let provenance = PropertyProvenance {
                        source: operation.source.clone(),
                        namespace: operation.namespace,
                        line: 0,
                        operation: operation.order,
                    };
                    total_properties = checked_total(
                        total_properties,
                        1,
                        self.limits.max_resolved_properties,
                        Path::new("<plan>"),
                        "resolved properties",
                    )?;
                    total_provenance = checked_total(
                        total_provenance,
                        1,
                        self.limits.max_provenance_entries,
                        Path::new("<plan>"),
                        "provenance entries",
                    )?;
                    self.insert(
                        &mut resolved,
                        operation.namespace,
                        JavaString::from_str(&key),
                        value,
                        provenance,
                        Path::new("<plan>"),
                    )?;
                }
                PropertyOperationKind::Logging => {}
            }
            resolved.operations.push(effective_operation);
        }
        resolved.logging = plan.logging.clone();
        Ok(resolved)
    }

    /// Alias for [`ConfigLoader::resolve`].
    pub fn load(&self, plan: &ConfigPlan) -> Result<ResolvedConfig, ConfigError> {
        self.resolve(plan)
    }

    /// Resolves a plan from an invocation in one explicit operation.
    pub fn resolve_invocation(
        &self,
        invocation: &CliInvocation,
    ) -> Result<ResolvedConfig, ConfigError> {
        self.resolve(&ConfigPlan::from_invocation(invocation))
    }

    /// Reads one explicitly selected bounded file through the loader's root,
    /// working-directory, and symlink policy.  The returned bytes come from a
    /// single opened handle; callers must not perform a separate metadata or
    /// existence check before consuming them.
    pub fn read_file(&self, path: impl Into<PathBuf>) -> Result<Vec<u8>, ConfigError> {
        let requested = path.into();
        let source = ConfigSource::ExplicitPrimary {
            path: requested.clone(),
        };
        let base = self.working_dir.as_deref();
        let resolved = self
            .resolve_path(base, &source, &requested)?
            .ok_or_else(|| ConfigError::MissingSource {
                source: source.clone(),
                path: requested.clone(),
            })?;
        self.read_source(&source, &resolved)?
            .ok_or(ConfigError::MissingSource {
                source,
                path: resolved,
            })
    }

    /// Parses an in-memory Java properties payload for a namespace.
    pub fn parse_bytes(
        &self,
        bytes: &[u8],
        source: ConfigSource,
    ) -> Result<PropertyMap, ConfigError> {
        let path = source.path().map_or(Path::new("<memory>"), |path| path);
        if bytes.len() > self.limits.max_file_bytes {
            return Err(ConfigError::FileTooLarge {
                path: path.to_owned(),
                limit: self.limits.max_file_bytes,
            });
        }
        let entries = parse_java_properties(bytes, path, self.decode_mode, self.limits)?;
        let namespace = source.namespace();
        let mut map = PropertyMap::new();
        let mut provenance_entries = 0_usize;
        for (index, (key, value, line)) in entries.into_iter().enumerate() {
            if index >= self.limits.max_resolved_properties {
                return Err(ConfigError::LimitExceeded {
                    path: path.to_owned(),
                    resource: "resolved properties",
                    limit: self.limits.max_resolved_properties,
                });
            }
            provenance_entries = checked_total(
                provenance_entries,
                1,
                self.limits.max_provenance_entries,
                path,
                "provenance entries",
            )?;
            if map.get_java(&key).is_some_and(|property| {
                property.overridden.len() >= self.limits.max_overrides_per_property
            }) {
                return Err(ConfigError::LimitExceeded {
                    path: path.to_owned(),
                    resource: "overrides per property",
                    limit: self.limits.max_overrides_per_property,
                });
            }
            map.insert(
                key.escaped(),
                key,
                value,
                PropertyProvenance {
                    source: source.clone(),
                    namespace,
                    line,
                    operation: 0,
                },
            );
        }
        Ok(map)
    }

    fn insert(
        &self,
        resolved: &mut ResolvedConfig,
        namespace: ConfigNamespace,
        key: JavaString,
        value: PropertyValue,
        provenance: PropertyProvenance,
        path: &Path,
    ) -> Result<(), ConfigError> {
        let mut value = value;
        let key_text = key.escaped();
        value.sensitive |= super::is_sensitive_key(&key_text);
        let map = match namespace {
            ConfigNamespace::Jmeter => &mut resolved.jmeter,
            ConfigNamespace::System => &mut resolved.system,
            ConfigNamespace::Global => &mut resolved.global,
        };
        if map.get_java(&key).is_some_and(|property| {
            property.overridden.len() >= self.limits.max_overrides_per_property
        }) {
            return Err(ConfigError::LimitExceeded {
                path: path.to_owned(),
                resource: "overrides per property",
                limit: self.limits.max_overrides_per_property,
            });
        }
        map.insert(key_text, key, value, provenance);
        Ok(())
    }

    fn validate_inline_key(&self, key: &str) -> Result<(), ConfigError> {
        if key.encode_utf16().count() > self.limits.max_key_chars {
            return Err(ConfigError::PropertyTooLong {
                path: PathBuf::from("<plan>"),
                line: 0,
                field: "key",
                limit: self.limits.max_key_chars,
            });
        }
        Ok(())
    }

    fn validate_inline_value(&self, value: &PropertyValue) -> Result<(), ConfigError> {
        if value.java_string().len_units() > self.limits.max_value_chars {
            return Err(ConfigError::PropertyTooLong {
                path: PathBuf::from("<plan>"),
                line: 0,
                field: "value",
                limit: self.limits.max_value_chars,
            });
        }
        Ok(())
    }

    fn remove(
        &self,
        resolved: &mut ResolvedConfig,
        namespace: ConfigNamespace,
        key: &str,
        provenance: PropertyProvenance,
    ) {
        match namespace {
            ConfigNamespace::Jmeter => {
                resolved.jmeter.remove(key);
            }
            ConfigNamespace::System => {
                resolved.system.remove(key);
            }
            ConfigNamespace::Global => {
                resolved.global.remove(key);
            }
        }
        resolved
            .removals
            .entry(namespace)
            .or_default()
            .entry(key.to_owned())
            .or_default()
            .insert(0, provenance);
    }

    fn read_source(
        &self,
        source: &ConfigSource,
        path: &Path,
    ) -> Result<Option<Vec<u8>>, ConfigError> {
        // Open once and inspect/read the same handle.  A metadata-then-open
        // sequence would introduce a replacement race between the canonical
        // containment check and the bytes consumed by the parser.  The Linux
        // implementation binds the final open to an already checked parent
        // directory and verifies the resulting descriptor through procfs;
        // a parent symlink swap therefore fails closed instead of redirecting
        // a configuration read.
        let mut canonical_roots = Vec::new();
        if let Some(root) = &self.fs_policy.root {
            canonical_roots.push(fs::canonicalize(root).map_err(|error| ConfigError::Io {
                path: root.clone(),
                message: error.to_string(),
            })?);
        }
        for root in &self.fs_policy.additional_roots {
            match fs::canonicalize(root) {
                Ok(canonical) => canonical_roots.push(canonical),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(ConfigError::Io {
                        path: root.clone(),
                        message: error.to_string(),
                    });
                }
            }
        }
        let file = match open_bound_read(path, &canonical_roots) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if source.is_optional_default() || source.is_warning_source() {
                    return Ok(None);
                }
                return Err(ConfigError::MissingSource {
                    source: source.clone(),
                    path: path.to_owned(),
                });
            }
            Err(error) if error.kind() == io::ErrorKind::Unsupported => {
                return Err(ConfigError::Unsupported {
                    capability: "descriptor-bound-filesystem",
                    path: path.to_owned(),
                    message: error.to_string(),
                });
            }
            Err(error) => {
                return Err(ConfigError::Io {
                    path: path.to_owned(),
                    message: error.to_string(),
                });
            }
        };
        let metadata = file.metadata().map_err(|error| ConfigError::Io {
            path: path.to_owned(),
            message: error.to_string(),
        })?;
        if !metadata.is_file() {
            return Err(ConfigError::Io {
                path: path.to_owned(),
                message: "source is not a regular file".to_owned(),
            });
        }
        let max_file_bytes = match u64::try_from(self.limits.max_file_bytes) {
            Ok(value) => value,
            Err(_) => {
                return Err(ConfigError::LimitExceeded {
                    path: path.to_owned(),
                    resource: "file bytes",
                    limit: self.limits.max_file_bytes,
                });
            }
        };
        if metadata.len() > max_file_bytes {
            return Err(ConfigError::FileTooLarge {
                path: path.to_owned(),
                limit: self.limits.max_file_bytes,
            });
        }

        let capacity = usize::try_from(metadata.len())
            .map_or(self.limits.max_file_bytes, |length| {
                length.min(self.limits.max_file_bytes)
            });
        let mut bytes = Vec::with_capacity(capacity);
        let read_limit =
            max_file_bytes
                .checked_add(1)
                .ok_or_else(|| ConfigError::LimitExceeded {
                    path: path.to_owned(),
                    resource: "file bytes",
                    limit: self.limits.max_file_bytes,
                })?;
        let mut limited = file.take(read_limit);
        limited
            .read_to_end(&mut bytes)
            .map_err(|error| ConfigError::Io {
                path: path.to_owned(),
                message: error.to_string(),
            })?;
        if bytes.len() > self.limits.max_file_bytes {
            return Err(ConfigError::FileTooLarge {
                path: path.to_owned(),
                limit: self.limits.max_file_bytes,
            });
        }
        Ok(Some(bytes))
    }

    fn source_path(&self, source: &ConfigSource, path: &Path) -> PathBuf {
        match source {
            ConfigSource::DefaultPrimary { .. } if path == Path::new("jmeter.properties") => {
                PathBuf::from(&self.file_names.jmeter)
            }
            ConfigSource::DefaultUser { .. } if path == Path::new("user.properties") => {
                PathBuf::from(&self.file_names.user)
            }
            ConfigSource::DefaultSystem { .. } if path == Path::new("system.properties") => {
                PathBuf::from(&self.file_names.system)
            }
            ConfigSource::ExplicitPrimary { .. }
            | ConfigSource::DefaultPrimary { .. }
            | ConfigSource::DefaultUser { .. }
            | ConfigSource::DefaultSystem { .. }
            | ConfigSource::AdditionalJmeter { .. }
            | ConfigSource::AdditionalSystem { .. }
            | ConfigSource::Global { .. }
            | ConfigSource::CommandLine { .. } => path.to_owned(),
        }
    }

    /// Selects the path for a staged default user/system load after the
    /// primary file has populated the JMeter namespace.  JMeter only loads
    /// these files when the primary property names are non-empty; the
    /// ordinary `user.properties`/`system.properties` names are fallback
    /// labels used when constructing plans from the pure compatibility API.
    fn dynamic_source(
        &self,
        resolved: &ResolvedConfig,
        source: &ConfigSource,
        path: &Path,
    ) -> Option<(ConfigSource, PathBuf, bool)> {
        match source {
            ConfigSource::DefaultUser { .. } => {
                let property_name = "user.properties";
                let default_path = path.to_owned();
                let selected = resolved
                    .jmeter
                    .get_value(property_name)
                    .map_or(default_path, PathBuf::from);
                if selected.as_os_str().is_empty() {
                    None
                } else {
                    Some((
                        ConfigSource::DefaultUser {
                            path: selected.clone(),
                        },
                        selected,
                        true,
                    ))
                }
            }
            ConfigSource::DefaultSystem { .. } => {
                let property_name = "system.properties";
                let default_path = path.to_owned();
                let selected = resolved
                    .jmeter
                    .get_value(property_name)
                    .map_or(default_path, PathBuf::from);
                if selected.as_os_str().is_empty() {
                    None
                } else {
                    Some((
                        ConfigSource::DefaultSystem {
                            path: selected.clone(),
                        },
                        selected,
                        true,
                    ))
                }
            }
            _ => Some((source.clone(), path.to_owned(), false)),
        }
    }

    /// Resolves a source with JMeter's two local lookup locations.  Explicit
    /// command-line paths are working-directory relative.  Dynamic
    /// user/system paths first use the working directory and then the
    /// selected JMeter `bin` directory.  The implicit primary follows the
    /// selected home/bin location when one is available.
    fn resolve_file_path(
        &self,
        plan: &ConfigPlan,
        working_dir: Option<&Path>,
        source: &ConfigSource,
        path: &Path,
    ) -> Result<Option<PathBuf>, ConfigError> {
        let mut candidates = Vec::new();
        if matches!(source, ConfigSource::DefaultPrimary { .. })
            && let Some(home) = plan.jmeter_home.as_deref()
        {
            candidates.push(home.join("bin").join(path));
        }
        candidates.push(path.to_owned());
        if matches!(
            source,
            ConfigSource::DefaultUser { .. } | ConfigSource::DefaultSystem { .. }
        ) && let Some(home) = plan.jmeter_home.as_deref()
        {
            candidates.push(home.join("bin").join(path));
        }

        for candidate in candidates {
            match self.resolve_path(working_dir, source, &candidate)? {
                Some(resolved) => return Ok(Some(resolved)),
                None => continue,
            }
        }
        Ok(None)
    }

    fn record_missing_warning(
        &self,
        resolved: &mut ResolvedConfig,
        source: &ConfigSource,
        path: &Path,
    ) {
        if source.is_warning_source() {
            resolved.warnings.push(ConfigWarning::MissingSource {
                source: source.clone(),
                path: path.to_owned(),
            });
        }
    }

    fn resolve_path(
        &self,
        base_dir: Option<&Path>,
        source: &ConfigSource,
        path: &Path,
    ) -> Result<Option<PathBuf>, ConfigError> {
        // A file source must have an explicit base/root capability.  In
        // particular, do not let fs::canonicalize below reinterpret a
        // caller's path against the process CWD.  Optional conventional
        // defaults can be absent when no filesystem capability was supplied;
        // explicit or warning sources fail closed with a stable error
        // instead.
        if base_dir.is_none() && self.fs_policy.root.is_none() {
            if path.is_relative() && source.is_optional_default() {
                return Ok(None);
            }
            return Err(ConfigError::UnrootedPath {
                path: path.to_owned(),
            });
        }
        let display_path = if let Some(base_dir) = base_dir {
            if path.is_relative() {
                base_dir.join(path)
            } else {
                path.to_owned()
            }
        } else if let Some(root) = &self.fs_policy.root {
            if path.is_relative() {
                root.join(path)
            } else {
                path.to_owned()
            }
        } else {
            path.to_owned()
        };
        if display_path.as_os_str().len() > self.limits.max_path_bytes {
            return Err(ConfigError::PathTooLong {
                path: display_path,
                limit: self.limits.max_path_bytes,
            });
        }

        let canonicalize_root = |root: &Path| fs::canonicalize(root);
        let canonical_root = match &self.fs_policy.root {
            Some(root) => Some(canonicalize_root(root).map_err(|error| ConfigError::Io {
                path: root.to_owned(),
                message: error.to_string(),
            })?),
            None => None,
        };
        let canonical_additional_roots = self
            .fs_policy
            .additional_roots
            .iter()
            .filter_map(|root| match canonicalize_root(root) {
                Ok(canonical) => Some(Ok(canonical)),
                Err(error) if error.kind() == io::ErrorKind::NotFound => None,
                Err(error) => Some(Err(ConfigError::Io {
                    path: root.clone(),
                    message: error.to_string(),
                })),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let has_symlink = contains_symlink(&display_path).map_err(|error| ConfigError::Io {
            path: display_path.clone(),
            message: error.to_string(),
        })?;
        if !self.fs_policy.symlink_policy.allows_links() && has_symlink {
            return Err(ConfigError::SymlinkDenied { path: display_path });
        }
        let canonical = match fs::canonicalize(&display_path) {
            Ok(canonical) => canonical,
            Err(error)
                if error.kind() == io::ErrorKind::NotFound
                    && (source.is_optional_default() || source.is_warning_source()) =>
            {
                return Ok(None);
            }
            Err(error) => {
                return Err(if error.kind() == io::ErrorKind::NotFound {
                    ConfigError::MissingSource {
                        source: source.clone(),
                        path: display_path,
                    }
                } else {
                    ConfigError::Io {
                        path: display_path,
                        message: error.to_string(),
                    }
                });
            }
        };

        if self.fs_policy.symlink_policy.requires_root()
            && canonical_root.is_none()
            && canonical_additional_roots.is_empty()
        {
            return Err(ConfigError::SymlinkRootRequired { path: canonical });
        }
        if canonical_root.is_some() || !canonical_additional_roots.is_empty() {
            let contained = canonical_root
                .iter()
                .chain(canonical_additional_roots.iter())
                .any(|root| canonical == *root || canonical.starts_with(root.join("")));
            if !contained {
                let root = canonical_root
                    .or_else(|| canonical_additional_roots.first().cloned())
                    .unwrap_or_else(|| PathBuf::from("<unrestricted>"));
                return Err(ConfigError::OutsideRoot {
                    path: canonical,
                    root,
                });
            }
        }
        Ok(Some(canonical))
    }
}

/// Adds filesystem resolution to the pure command-line configuration plan.
impl ConfigurationPlan {
    /// Converts this ordered effect plan into a filesystem-backed plan.
    #[must_use]
    pub fn config_plan(&self) -> ConfigPlan {
        ConfigPlan::from_configuration(self)
    }

    /// Resolves this plan using an explicit loader.
    pub fn resolve_config(&self, loader: &ConfigLoader) -> Result<ResolvedConfig, ConfigError> {
        loader.resolve(&self.config_plan())
    }
}

/// Adds a convenient plan accessor to parsed invocations.
impl CliInvocation {
    /// Converts this invocation into an ordered filesystem configuration plan.
    #[must_use]
    pub fn config_plan(&self) -> ConfigPlan {
        ConfigPlan::from_invocation(self)
    }

    /// Resolves this invocation through an explicit loader.
    pub fn resolve_config(&self, loader: &ConfigLoader) -> Result<ResolvedConfig, ConfigError> {
        loader.resolve_invocation(self)
    }
}

fn contains_symlink(path: &Path) -> io::Result<bool> {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(Path::new(std::path::MAIN_SEPARATOR_STR)),
            Component::CurDir => {}
            Component::ParentDir => current.push(".."),
            Component::Normal(value) => current.push(value),
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Ok(true),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        }
    }
    Ok(false)
}

/// A directory handle whose child operations remain bound to the directory
/// entry that was checked. Linux uses the procfs descriptor namespace to
/// address children without reopening a path through a potentially replaced
/// parent.
#[cfg(target_os = "linux")]
pub(crate) struct BoundDirectory {
    handle: File,
    canonical: PathBuf,
}

#[cfg(not(target_os = "linux"))]
pub(crate) struct BoundDirectory {
    canonical: PathBuf,
}

impl BoundDirectory {
    pub(crate) fn path(&self) -> PathBuf {
        #[cfg(target_os = "linux")]
        {
            proc_fd_path(&self.handle)
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.canonical.clone()
        }
    }

    pub(crate) fn child(&self, name: &std::ffi::OsStr) -> PathBuf {
        #[cfg(target_os = "linux")]
        {
            proc_fd_path(&self.handle).join(name)
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.canonical.join(name)
        }
    }

    pub(crate) fn canonical(&self) -> &Path {
        &self.canonical
    }

    #[cfg(target_os = "linux")]
    fn open_child(&self, name: &std::ffi::OsStr, expected_root: &Path) -> io::Result<Self> {
        let child = self.child(name);
        let canonical = fs::canonicalize(&child)?;
        ensure_within_root(&canonical, expected_root)?;
        let mut options = OpenOptions::new();
        options.read(true).custom_flags(O_DIRECTORY | O_NOFOLLOW);
        let handle = options.open(&child)?;
        let opened = fs::canonicalize(proc_fd_path(&handle))?;
        if opened != canonical {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "directory changed while opening",
            ));
        }
        Ok(Self { handle, canonical })
    }
}

pub(crate) fn open_bound_directory(
    path: &Path,
    expected_root: Option<&Path>,
) -> io::Result<BoundDirectory> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (path, expected_root);
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "descriptor-bound filesystem operations are unavailable on this platform",
        ));
    }
    #[cfg(target_os = "linux")]
    {
        if contains_symlink(path)? {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "directory path contains a symbolic link",
            ));
        }
        let canonical = fs::canonicalize(path)?;
        if let Some(root) = expected_root {
            ensure_within_root(&canonical, root)?;
        }
        let mut options = OpenOptions::new();
        options.read(true).custom_flags(O_DIRECTORY | O_NOFOLLOW);
        let handle = options.open(&canonical)?;
        let opened = fs::canonicalize(proc_fd_path(&handle))?;
        if opened != canonical {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "directory changed while opening",
            ));
        }
        Ok(BoundDirectory { handle, canonical })
    }
}

pub(crate) fn open_bound_read(path: &Path, expected_roots: &[PathBuf]) -> io::Result<File> {
    #[cfg(target_os = "linux")]
    {
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "input has no parent"))?;
        let expected_parent = fs::canonicalize(parent)?;
        let directory = open_bound_directory(parent, None)?;
        if directory.canonical() != expected_parent {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "input parent changed while opening",
            ));
        }
        ensure_within_any_root(directory.canonical(), expected_roots)?;
        let name = path
            .file_name()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "input has no filename"))?;
        let bound = directory.child(name);
        let mut options = OpenOptions::new();
        options.read(true).custom_flags(O_NOFOLLOW);
        let file = options.open(&bound)?;
        verify_file_target(&file, &directory.canonical().join(name))?;
        Ok(file)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (path, expected_roots);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "descriptor-bound filesystem operations are unavailable on this platform",
        ))
    }
}

pub(crate) fn open_bound_create_new(path: &Path, expected_root: &Path) -> io::Result<File> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "output has no parent"))?;
    let directory = open_bound_directory(parent, Some(expected_root))?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "output has no filename"))?;
    let bound = directory.child(name);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(target_os = "linux")]
    options.custom_flags(O_NOFOLLOW);
    let file = options.open(&bound)?;
    verify_file_target(&file, &directory.canonical().join(name))?;
    Ok(file)
}

#[cfg(test)]
pub(crate) fn ensure_bound_directory(path: &Path, expected_root: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "directory has no parent"))?;
    let directory = open_bound_directory(parent, Some(expected_root))?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "directory has no filename"))?;
    let bound = directory.child(name);
    match fs::create_dir(&bound) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(&bound)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "directory is not a regular directory",
                ));
            }
            Ok(())
        }
        Err(error) => Err(error),
    }
}

pub(crate) fn open_bound_append(path: &Path, expected_root: &Path) -> io::Result<File> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "log has no parent"))?;
    let directory = open_bound_directory(parent, Some(expected_root))?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "log has no filename"))?;
    let bound = directory.child(name);
    let mut options = OpenOptions::new();
    options.write(true).append(true).create(true);
    #[cfg(target_os = "linux")]
    options.custom_flags(O_NOFOLLOW);
    let file = options.open(&bound)?;
    verify_file_target(&file, &directory.canonical().join(name))?;
    Ok(file)
}

pub(crate) fn bound_metadata(path: &Path, expected_root: Option<&Path>) -> io::Result<Metadata> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    let directory = open_bound_directory(parent, expected_root)?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no filename"))?;
    fs::symlink_metadata(directory.child(name))
}

pub(crate) fn remove_bound_file(path: &Path, expected_root: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    let directory = open_bound_directory(parent, Some(expected_root))?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no filename"))?;
    fs::remove_file(directory.child(name))
}

/// Removes a directory tree through a descriptor-bound directory handle.
///
/// The final path is checked against `expected_identity` before opening, and
/// every nested directory is opened with `O_NOFOLLOW` from its already-bound
/// parent.  A replacement symlink, file, or out-of-root directory therefore
/// fails closed instead of being recursively followed.
pub(crate) fn remove_bound_tree(
    path: &Path,
    expected_root: &Path,
    expected_identity: Option<(u64, u64)>,
) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "tree has no parent"))?;
        let parent_directory = open_bound_directory(parent, Some(expected_root))?;
        let name = path
            .file_name()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "tree has no name"))?;
        let target = parent_directory.open_child(name, expected_root)?;
        if expected_identity.is_some()
            && metadata_identity(&target.handle.metadata()?) != expected_identity
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "directory changed before descriptor-bound deletion",
            ));
        }
        remove_bound_children(&target, expected_root)?;

        // `remove_dir` never follows a symlink.  Revalidate both the opened
        // descriptor and the parent-bound path before unlinking the now-empty
        // entry; a swap to a link or an out-of-root directory fails closed.
        let opened = fs::canonicalize(proc_fd_path(&target.handle))?;
        let current_metadata = fs::symlink_metadata(parent_directory.child(name))?;
        let current = fs::canonicalize(parent_directory.child(name))?;
        if opened != target.canonical()
            || current != target.canonical()
            || metadata_identity(&current_metadata) != metadata_identity(&target.handle.metadata()?)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "directory changed during descriptor-bound deletion",
            ));
        }
        fs::remove_dir(parent_directory.child(name))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (path, expected_root, expected_identity);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "descriptor-bound filesystem operations are unavailable on this platform",
        ))
    }
}

#[cfg(target_os = "linux")]
fn remove_bound_children(directory: &BoundDirectory, expected_root: &Path) -> io::Result<()> {
    for entry in fs::read_dir(directory.path())? {
        let entry = entry?;
        let name = entry.file_name();
        let child = directory.child(&name);
        let metadata = fs::symlink_metadata(&child)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            // remove_file unlinks a symlink itself and never recursively
            // follows a replacement directory.
            fs::remove_file(child)?;
            continue;
        }
        let identity = metadata_identity(&metadata);
        let child_directory = directory.open_child(&name, expected_root)?;
        if identity != metadata_identity(&child_directory.handle.metadata()?) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "nested directory changed while opening",
            ));
        }
        let child_canonical = child_directory.canonical().to_owned();
        remove_bound_children(&child_directory, expected_root)?;
        let opened = fs::canonicalize(proc_fd_path(&child_directory.handle))?;
        let current_path = directory.child(&name);
        let current_metadata = fs::symlink_metadata(&current_path)?;
        let current = fs::canonicalize(&current_path)?;
        if opened != child_canonical
            || current != child_canonical
            || metadata_identity(&current_metadata) != identity
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "nested directory changed during descriptor-bound deletion",
            ));
        }
        fs::remove_dir(directory.child(&name))?;
    }
    Ok(())
}

pub(crate) fn metadata_identity(metadata: &Metadata) -> Option<(u64, u64)> {
    #[cfg(unix)]
    {
        Some((metadata.dev(), metadata.ino()))
    }
    #[cfg(windows)]
    {
        // The stable standard library has no Windows-by-handle identity API
        // on the MSRV.  Every descriptor-bound mutating helper is therefore
        // explicitly unsupported on Windows below; returning no identity
        // keeps this diagnostic helper free of unstable APIs and cannot turn
        // an unsupported deletion into a path-based fallback.
        let _ = metadata;
        None
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = metadata;
        None
    }
}

pub(crate) fn rename_bound(
    source: &Path,
    destination: &Path,
    expected_root: &Path,
) -> io::Result<()> {
    let source_parent = source
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "source has no parent"))?;
    let destination_parent = destination
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "destination has no parent"))?;
    let source_directory = open_bound_directory(source_parent, Some(expected_root))?;
    let destination_directory = if destination_parent == source_parent {
        None
    } else {
        Some(open_bound_directory(
            destination_parent,
            Some(expected_root),
        )?)
    };
    let source_name = source
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "source has no filename"))?;
    let destination_name = destination.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "destination has no filename")
    })?;
    let source_path = source_directory.child(source_name);
    let destination_path = destination_directory.as_ref().map_or_else(
        || source_directory.child(destination_name),
        |dir| dir.child(destination_name),
    );
    fs::rename(source_path, destination_path)
}

#[cfg(target_os = "linux")]
fn verify_file_target(file: &File, expected: &Path) -> io::Result<()> {
    let actual = fs::canonicalize(proc_fd_path(file))?;
    if actual != expected {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "file changed while opening",
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn verify_file_target(_file: &File, _expected: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn proc_fd_path(file: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

#[cfg(target_os = "linux")]
fn ensure_within_root(path: &Path, root: &Path) -> io::Result<()> {
    let root = fs::canonicalize(root)?;
    if path == root || path.starts_with(root.join("")) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "path is outside the allowed root",
        ))
    }
}

#[cfg(target_os = "linux")]
fn ensure_within_any_root(path: &Path, roots: &[PathBuf]) -> io::Result<()> {
    if roots.is_empty()
        || roots
            .iter()
            .any(|root| path == root || path.starts_with(root))
    {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "path is outside the allowed roots",
        ))
    }
}

#[cfg(target_os = "linux")]
const O_DIRECTORY: i32 = 0o200000;

#[cfg(target_os = "linux")]
const O_NOFOLLOW: i32 = 0o400000;

fn checked_total(
    current: usize,
    additional: usize,
    limit: usize,
    path: &Path,
    resource: &'static str,
) -> Result<usize, ConfigError> {
    let Some(total) = current.checked_add(additional) else {
        return Err(ConfigError::LimitExceeded {
            path: path.to_owned(),
            resource,
            limit,
        });
    };
    if total > limit {
        return Err(ConfigError::LimitExceeded {
            path: path.to_owned(),
            resource,
            limit,
        });
    }
    Ok(total)
}

fn parse_java_properties(
    bytes: &[u8],
    path: &Path,
    mode: DecodeMode,
    limits: ConfigLimits,
) -> Result<Vec<(JavaString, PropertyValue, usize)>, ConfigError> {
    let text = decode_input(bytes, path, mode)?;
    let physical_lines = split_physical_lines(&text, path, limits.max_lines)?;
    let mut logical_lines = Vec::new();
    let mut index = 0;
    while index < physical_lines.len() {
        let (line_number, mut line) = physical_lines[index].clone();
        let mut continuation_count = 0;
        // Java Properties recognizes comments before applying continuation;
        // a comment ending in `\\` therefore cannot swallow the next
        // property's physical line.
        let is_comment = line
            .trim_start_matches([' ', '\t', '\u{000c}'])
            .starts_with('#')
            || line
                .trim_start_matches([' ', '\t', '\u{000c}'])
                .starts_with('!');
        while !is_comment && has_continuation(&line) {
            if continuation_count >= limits.max_continuation_lines {
                return Err(ConfigError::LimitExceeded {
                    path: path.to_owned(),
                    resource: "continuation lines",
                    limit: limits.max_continuation_lines,
                });
            }
            line.pop();
            index += 1;
            continuation_count += 1;
            if index >= physical_lines.len() {
                break;
            }
            let (_, next) = &physical_lines[index];
            line.push_str(next.trim_start_matches([' ', '\t', '\u{000c}']));
        }
        logical_lines.push((line_number, line));
        index += 1;
    }

    let mut properties = Vec::new();
    for (line_number, line) in logical_lines {
        let Some((key, raw_value)) = split_property_line(&line) else {
            continue;
        };
        let key = decode_property_fragment(key, path, line_number)?;
        let value = decode_property_fragment(raw_value, path, line_number)?;
        if key.len_units() > limits.max_key_chars {
            return Err(ConfigError::PropertyTooLong {
                path: path.to_owned(),
                line: line_number,
                field: "key",
                limit: limits.max_key_chars,
            });
        }
        if value.len_units() > limits.max_value_chars {
            return Err(ConfigError::PropertyTooLong {
                path: path.to_owned(),
                line: line_number,
                field: "value",
                limit: limits.max_value_chars,
            });
        }
        if properties.len() >= limits.max_properties {
            return Err(ConfigError::LimitExceeded {
                path: path.to_owned(),
                resource: "properties",
                limit: limits.max_properties,
            });
        }
        properties.push((
            key.clone(),
            PropertyValue::from_java(value, super::is_sensitive_key(&key.escaped())),
            line_number,
        ));
    }
    Ok(properties)
}

fn decode_input(bytes: &[u8], path: &Path, mode: DecodeMode) -> Result<String, ConfigError> {
    if mode.is_utf8() {
        String::from_utf8(bytes.to_vec()).map_err(|_| ConfigError::InvalidUtf8 {
            path: path.to_owned(),
        })
    } else {
        // Java's InputStream overload maps every byte to one ISO-8859-1 code
        // unit before processing escapes.  `Latin1` is explicit but equivalent
        // for this parser; `Java` is retained as a spelling alias.
        Ok(bytes.iter().map(|byte| char::from(*byte)).collect())
    }
}

fn split_physical_lines(
    text: &str,
    path: &Path,
    max_lines: usize,
) -> Result<Vec<(usize, String)>, ConfigError> {
    let mut lines = Vec::new();
    let mut line = String::new();
    let mut line_number = 1;
    let mut chars = text.chars().peekable();
    while let Some(character) = chars.next() {
        match character {
            '\n' => {
                if lines.len() >= max_lines {
                    return Err(ConfigError::LimitExceeded {
                        path: path.to_owned(),
                        resource: "physical lines",
                        limit: max_lines,
                    });
                }
                lines.push((line_number, std::mem::take(&mut line)));
                line_number += 1;
            }
            '\r' => {
                if lines.len() >= max_lines {
                    return Err(ConfigError::LimitExceeded {
                        path: path.to_owned(),
                        resource: "physical lines",
                        limit: max_lines,
                    });
                }
                lines.push((line_number, std::mem::take(&mut line)));
                line_number += 1;
                // Consume only the LF in a CRLF pair.  A second CR remains
                // in the iterator and starts its own physical line.
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
            }
            _ => line.push(character),
        }
    }
    if !line.is_empty() || lines.is_empty() {
        if lines.len() >= max_lines {
            return Err(ConfigError::LimitExceeded {
                path: path.to_owned(),
                resource: "physical lines",
                limit: max_lines,
            });
        }
        lines.push((line_number, line));
    }
    Ok(lines)
}

fn has_continuation(line: &str) -> bool {
    let mut count = 0;
    for character in line.chars().rev() {
        if character == '\\' {
            count += 1;
        } else {
            break;
        }
    }
    count % 2 == 1
}

fn split_property_line(line: &str) -> Option<(&str, &str)> {
    let mut chars = line.char_indices().peekable();
    let mut start = None;
    while let Some((index, character)) = chars.peek().copied() {
        if !matches!(character, ' ' | '\t' | '\u{000c}') {
            start = Some(index);
            break;
        }
        chars.next();
    }
    let start = start?;
    let first = line[start..].chars().next()?;
    if first == '#' || first == '!' {
        return None;
    }

    let mut escaped = false;
    let mut delimiter = None;
    for (index, character) in line[start..].char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if character == '\\' {
            escaped = true;
            continue;
        }
        if character == '=' || character == ':' || matches!(character, ' ' | '\t' | '\u{000c}') {
            delimiter = Some(start + index);
            break;
        }
    }
    let Some(delimiter) = delimiter else {
        return Some((&line[start..], ""));
    };
    let key = &line[start..delimiter];
    let mut value_start = delimiter;
    let delimiter_character = line[delimiter..].chars().next()?;
    if matches!(delimiter_character, ' ' | '\t' | '\u{000c}') {
        while let Some(character) = line[value_start..].chars().next()
            && matches!(character, ' ' | '\t' | '\u{000c}')
        {
            value_start += character.len_utf8();
        }
        if let Some(character) = line[value_start..].chars().next()
            && (character == '=' || character == ':')
        {
            value_start += character.len_utf8();
        }
    } else {
        value_start += delimiter_character.len_utf8();
    }
    while let Some(character) = line[value_start..].chars().next()
        && matches!(character, ' ' | '\t' | '\u{000c}')
    {
        value_start += character.len_utf8();
    }
    Some((key, &line[value_start..]))
}

fn decode_property_fragment(
    fragment: &str,
    path: &Path,
    line: usize,
) -> Result<JavaString, ConfigError> {
    let chars = fragment.chars().collect::<Vec<_>>();
    let mut units = Vec::with_capacity(chars.len());
    let mut index = 0;
    while index < chars.len() {
        let character = chars[index];
        if character != '\\' {
            let mut encoded = [0_u16; 2];
            for unit in character.encode_utf16(&mut encoded) {
                units.push(*unit);
            }
            index += 1;
            continue;
        }
        index += 1;
        if index >= chars.len() {
            // Java drops a terminal escape marker rather than creating an
            // unbounded or implicit continuation here.
            break;
        }
        match chars[index] {
            't' => units.push('\t' as u16),
            'n' => units.push('\n' as u16),
            'r' => units.push('\r' as u16),
            'f' => units.push('\u{000c}' as u16),
            'u' => {
                if index + 4 >= chars.len() {
                    return Err(ConfigError::InvalidEscape {
                        path: path.to_owned(),
                        line,
                        reason: "short-unicode-escape",
                    });
                }
                let mut value = 0_u16;
                for offset in 1..=4 {
                    let Some(digit) = chars[index + offset].to_digit(16) else {
                        return Err(ConfigError::InvalidEscape {
                            path: path.to_owned(),
                            line,
                            reason: "non-hex-unicode-escape",
                        });
                    };
                    value = (value << 4) | digit as u16;
                }
                units.push(value);
                index += 4;
            }
            other => {
                // Java's properties decoder removes the escape marker for
                // unrecognised escapes (`\q` becomes `q`).
                let mut encoded = [0_u16; 2];
                for unit in other.encode_utf16(&mut encoded) {
                    units.push(*unit);
                }
            }
        }
        index += 1;
    }
    let _ = (path, line);
    Ok(JavaString::from_units(units))
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "configuration tests use explicit setup assertions"
)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT_TEMP_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

    struct TempDirectory {
        path: PathBuf,
    }

    impl TempDirectory {
        fn new() -> Self {
            let sequence = NEXT_TEMP_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "jmeter-rs-config-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("temporary directory");
            Self { path }
        }

        fn write(&self, name: &str, contents: &[u8]) -> PathBuf {
            let path = self.path.join(name);
            fs::write(&path, contents).expect("temporary properties file");
            path
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn reducer_event(request: ConfigPhaseRequest, primary: &PropertyMap) -> ConfigPhaseEvent {
        match request {
            ConfigPhaseRequest::LoadPrimary { source } => ConfigPhaseEvent::PrimaryLoaded {
                source,
                properties: primary.clone(),
            },
            ConfigPhaseRequest::SelectJmeterLog { target } => {
                ConfigPhaseEvent::LogSelected { target }
            }
            ConfigPhaseRequest::InitializeLogging {
                config_file,
                target,
            } => ConfigPhaseEvent::LoggingReady {
                config_file,
                target,
            },
            ConfigPhaseRequest::LoadUserProperties { source } => {
                ConfigPhaseEvent::UserPropertiesLoaded { source }
            }
            ConfigPhaseRequest::SkipUserProperties => ConfigPhaseEvent::UserPropertiesSkipped,
            ConfigPhaseRequest::LoadSystemProperties { source } => {
                ConfigPhaseEvent::SystemPropertiesLoaded { source }
            }
            ConfigPhaseRequest::SkipSystemProperties => ConfigPhaseEvent::SystemPropertiesSkipped,
            ConfigPhaseRequest::ApplyCli { operation } => {
                ConfigPhaseEvent::CliApplied { operation }
            }
            ConfigPhaseRequest::SelectInputs { inputs } => {
                ConfigPhaseEvent::InputsSelected { inputs }
            }
        }
    }

    #[test]
    fn phase_machine_preserves_pinned_order_and_cli_occurrences_without_io() {
        let invocation = crate::parse([
            "-n",
            "-t",
            "plan.jmx",
            "-l",
            "result.jtl",
            "-p",
            "primary.properties",
            "-i",
            "log4j.xml",
            "-j",
            "run.log",
            "-q",
            "first.properties",
            "-S",
            "system-extra.properties",
            "-J",
            "jmeter.key=one",
            "-G",
            "remote.key=global",
            "-D",
            "system.key=one",
            "-L",
            "org.apache.jmeter=DEBUG",
            "-q",
            "later.properties",
            "-J",
            "jmeter.key=",
        ])
        .expect("arguments parse");
        let mut machine = ConfigPhaseMachine::from_invocation(&invocation);
        assert_eq!(machine.phase(), ConfigPhase::Parsed);
        let primary = PropertyMap::new();
        let mut phase_trace = vec![machine.phase()];
        let mut applied = Vec::new();
        while let Some(request) = machine.next_request().cloned() {
            let event = reducer_event(request, &primary);
            if let ConfigPhaseEvent::CliApplied { operation } = &event {
                applied.push(operation.clone());
            }
            machine
                .advance(event)
                .expect("fake reducer acknowledgement");
            if phase_trace.last() != Some(&machine.phase()) {
                phase_trace.push(machine.phase());
            }
        }

        assert_eq!(
            phase_trace,
            [
                ConfigPhase::Parsed,
                ConfigPhase::PrimaryLoaded,
                ConfigPhase::LogSelected,
                ConfigPhase::LoggingReady,
                ConfigPhase::User,
                ConfigPhase::System,
                ConfigPhase::RemainingCli,
                ConfigPhase::Inputs,
                ConfigPhase::Ready,
            ]
        );
        assert_eq!(machine.phase(), ConfigPhase::Ready);
        assert!(machine.terminal_error().is_none());
        assert_eq!(applied, machine.deferred_operations());
        assert_eq!(
            applied
                .iter()
                .map(|operation| operation.kind)
                .collect::<Vec<_>>(),
            [
                PropertyOperationKind::LoadFile,
                PropertyOperationKind::LoadFile,
                PropertyOperationKind::Assignment,
                PropertyOperationKind::Assignment,
                PropertyOperationKind::Assignment,
                PropertyOperationKind::Logging,
                PropertyOperationKind::LoadFile,
                PropertyOperationKind::Remove,
            ]
        );
        assert_eq!(
            applied
                .iter()
                .map(|operation| operation.namespace)
                .collect::<Vec<_>>(),
            [
                ConfigNamespace::Jmeter,
                ConfigNamespace::System,
                ConfigNamespace::Jmeter,
                ConfigNamespace::Global,
                ConfigNamespace::System,
                ConfigNamespace::System,
                ConfigNamespace::Jmeter,
                ConfigNamespace::Jmeter,
            ]
        );
        let expected_occurrences = invocation
            .options
            .occurrences
            .iter()
            .filter(|occurrence| {
                matches!(
                    occurrence.id,
                    OptionId::Addprop
                        | OptionId::SystemPropertyFile
                        | OptionId::Jmeterproperty
                        | OptionId::Globalproperty
                        | OptionId::Systemproperty
                        | OptionId::Loglevel
                )
            })
            .map(|occurrence| occurrence.index)
            .collect::<Vec<_>>();
        let actual_occurrences = applied
            .iter()
            .map(|operation| match &operation.source {
                ConfigSource::AdditionalJmeter { occurrence, .. }
                | ConfigSource::AdditionalSystem { occurrence, .. }
                | ConfigSource::Global { occurrence, .. }
                | ConfigSource::CommandLine { occurrence, .. } => *occurrence,
                source => panic!("deferred source was not occurrence-bearing: {source:?}"),
            })
            .collect::<Vec<_>>();
        assert_eq!(actual_occurrences, expected_occurrences);
    }

    #[test]
    fn phase_machine_derives_dynamic_sources_after_logging() {
        let invocation =
            crate::parse(["-n", "-t", "plan.jmx", "-J", "key=value"]).expect("arguments parse");
        let mut machine = ConfigPhaseMachine::from_invocation(&invocation);
        let primary = ConfigLoader::new()
            .parse_bytes(
                b"user.properties=selected-user.properties\nsystem.properties=selected-system.properties\n",
                ConfigSource::ExplicitPrimary {
                    path: PathBuf::from("memory-primary.properties"),
                },
            )
            .expect("primary properties decode");

        let request = machine.next_request().cloned().expect("primary request");
        machine
            .advance(ConfigPhaseEvent::PrimaryLoaded {
                source: match request {
                    ConfigPhaseRequest::LoadPrimary { source } => source,
                    other => panic!("unexpected request: {other:?}"),
                },
                properties: primary,
            })
            .expect("primary acknowledgement");
        let target = match machine.next_request().cloned().expect("log request") {
            ConfigPhaseRequest::SelectJmeterLog { target } => target,
            other => panic!("unexpected request: {other:?}"),
        };
        machine
            .advance(ConfigPhaseEvent::LogSelected {
                target: target.clone(),
            })
            .expect("log selection acknowledgement");
        let (config_file, target) = match machine.next_request().cloned().expect("logging request")
        {
            ConfigPhaseRequest::InitializeLogging {
                config_file,
                target,
            } => (config_file, target),
            other => panic!("unexpected request: {other:?}"),
        };
        machine
            .advance(ConfigPhaseEvent::LoggingReady {
                config_file,
                target,
            })
            .expect("logging acknowledgement");
        assert_eq!(machine.phase(), ConfigPhase::LoggingReady);

        let user_source = match machine.next_request().cloned().expect("user request") {
            ConfigPhaseRequest::LoadUserProperties { source } => source,
            other => panic!("unexpected request: {other:?}"),
        };
        assert_eq!(
            user_source.path(),
            Some(Path::new("selected-user.properties"))
        );
        machine
            .advance(ConfigPhaseEvent::UserPropertiesLoaded {
                source: user_source,
            })
            .expect("user acknowledgement");
        let system_source = match machine.next_request().cloned().expect("system request") {
            ConfigPhaseRequest::LoadSystemProperties { source } => source,
            other => panic!("unexpected request: {other:?}"),
        };
        assert_eq!(
            system_source.path(),
            Some(Path::new("selected-system.properties"))
        );
        assert_eq!(machine.phase(), ConfigPhase::User);
    }

    #[test]
    fn phase_machine_fails_closed_on_wrong_or_failed_events() {
        let invocation = crate::parse(["-n", "-t", "plan.jmx"]).expect("arguments parse");
        let mut wrong = ConfigPhaseMachine::from_invocation(&invocation);
        let error = wrong
            .advance(ConfigPhaseEvent::LoggingReady {
                config_file: None,
                target: crate::LogTarget::Default,
            })
            .expect_err("wrong event must fail");
        assert_eq!(error.code(), "config.phase-unexpected-event");
        assert_eq!(error.phase(), ConfigPhase::Parsed);
        assert_eq!(wrong.phase(), ConfigPhase::Failed);
        assert!(wrong.next_request().is_none());
        assert_eq!(wrong.terminal_error(), Some(&error));
        let terminal = wrong
            .advance(ConfigPhaseEvent::Failed {
                code: "late.failure",
            })
            .expect_err("failed machine must remain terminal");
        assert_eq!(terminal.code(), "config.phase-terminal");

        let mut failed = ConfigPhaseMachine::from_invocation(&invocation);
        let error = failed
            .advance(ConfigPhaseEvent::Failed {
                code: "config.primary-load",
            })
            .expect_err("adapter failure must fail closed");
        assert_eq!(error.code(), "config.primary-load");
        assert_eq!(failed.phase(), ConfigPhase::Failed);
        assert!(failed.terminal_error().is_some());
    }

    #[test]
    fn java_properties_decode_comments_escapes_and_continuations() {
        let loader = ConfigLoader::new();
        let source = ConfigSource::ExplicitPrimary {
            path: PathBuf::from("memory.properties"),
        };
        let map = loader
            .parse_bytes(
                br#"# comment
escaped\=key: left\=right\:value\\
continued=first\
  second
unicode=smile-\u263A
empty=
flag
"#,
                source,
            )
            .expect("properties decode");
        assert_eq!(map.get_value("escaped=key"), Some("left=right:value\\"));
        assert_eq!(map.get_value("continued"), Some("firstsecond"));
        assert_eq!(map.get_value("unicode"), Some("smile-☺"));
        assert_eq!(map.get_value("empty"), Some(""));
        assert_eq!(map.get_value("flag"), Some(""));
    }

    #[test]
    fn java_property_map_keeps_colliding_surrogate_and_literal_keys_distinct() {
        let map = ConfigLoader::new()
            .parse_bytes(
                b"\\uD800=surrogate\n\\\\uD800=literal\n",
                ConfigSource::ExplicitPrimary {
                    path: PathBuf::from("collision.properties"),
                },
            )
            .expect("properties decode");
        let surrogate = JavaString::from_units(vec![0xD800]);
        let literal = JavaString::from_str(r"\uD800");
        assert_eq!(map.len(), 2);
        assert_eq!(
            map.get_java(&surrogate).map(ResolvedProperty::as_str),
            Some("surrogate")
        );
        assert_eq!(
            map.get_java(&literal).map(ResolvedProperty::as_str),
            Some("literal")
        );
        assert_eq!(map.as_java_map().len(), 2);
    }

    #[test]
    fn duplicate_keys_are_last_write_wins_with_history() {
        let loader = ConfigLoader::new();
        let source = ConfigSource::ExplicitPrimary {
            path: PathBuf::from("duplicate.properties"),
        };
        let map = loader
            .parse_bytes(b"key=first\nkey=last\n", source.clone())
            .expect("properties decode");
        let property = map.get("key").expect("effective key");
        assert_eq!(property.value(), "last");
        assert_eq!(property.provenance.line, 2);
        assert_eq!(property.overridden.len(), 1);
        assert_eq!(property.overridden[0].source, source);
        assert_eq!(property.overridden[0].line, 1);
    }

    #[test]
    fn config_plan_preserves_namespace_order_and_inline_precedence() {
        let directory = TempDirectory::new();
        directory.write(
            "primary.properties",
            b"same=primary\nfrom.file=yes\nempty=from-file\n",
        );
        let invocation = crate::parse([
            "-p",
            "primary.properties",
            "-n",
            "-t",
            "plan.jmx",
            "-J",
            "same=first",
            "-J",
            "same=second",
            "-J",
            "empty=",
            "-D",
            "same=system",
            "-G",
            "same=global",
        ])
        .expect("CLI invocation");
        let plan = ConfigPlan::from_invocation(&invocation).with_base_dir(&directory.path);
        let resolved = ConfigLoader::rooted(&directory.path)
            .resolve(&plan)
            .expect("configuration resolution");
        assert_eq!(resolved.jmeter.get_value("same"), Some("second"));
        assert_eq!(resolved.jmeter.get_value("from.file"), Some("yes"));
        assert_eq!(resolved.jmeter.get_value("empty"), None);
        assert_eq!(resolved.system.get_value("same"), Some("system"));
        assert_eq!(resolved.global.get_value("same"), Some("global"));
        let property = resolved.jmeter.get("same").expect("jmeter same");
        assert_eq!(property.provenance.namespace, ConfigNamespace::Jmeter);
        assert_eq!(property.provenance.line, 0);
        assert_eq!(property.provenance.operation, 4);
        assert_eq!(property.overridden.len(), 2);
    }

    #[test]
    fn additional_files_and_global_files_keep_cli_order_and_distinct_maps() {
        let directory = TempDirectory::new();
        directory.write("primary.properties", b"same=primary\n");
        directory.write("first.properties", b"same=first-file\nq.only=first\n");
        directory.write("second.properties", b"same=second-file\nq.only=second\n");
        directory.write("global.properties", b"same=global-file\nremote.only=yes\n");
        let invocation = crate::parse([
            "-p",
            "primary.properties",
            "-q",
            "first.properties",
            "-q",
            "second.properties",
            "-G",
            "global.properties",
            "-n",
            "-t",
            "plan.jmx",
        ])
        .expect("CLI invocation");
        let plan = ConfigPlan::from_invocation(&invocation).with_base_dir(&directory.path);
        let operations = plan.operations();
        assert!(matches!(
            operations[0].source,
            ConfigSource::ExplicitPrimary { .. }
        ));
        assert!(matches!(
            operations[3].source,
            ConfigSource::AdditionalJmeter { occurrence: 2, .. }
        ));
        assert!(matches!(
            operations[4].source,
            ConfigSource::AdditionalJmeter { occurrence: 4, .. }
        ));
        assert!(matches!(
            operations[5].source,
            ConfigSource::Global { occurrence: 6, .. }
        ));
        let resolved = plan
            .resolve(&ConfigLoader::rooted(&directory.path))
            .expect("resolve");
        assert_eq!(resolved.jmeter.get_value("same"), Some("second-file"));
        assert_eq!(resolved.jmeter.get_value("q.only"), Some("second"));
        assert_eq!(resolved.global.get_value("same"), Some("global-file"));
        assert_eq!(resolved.global.get_value("remote.only"), Some("yes"));
        assert_eq!(resolved.system.get_value("same"), None);
    }

    #[test]
    fn absent_default_files_are_optional_but_explicit_files_fail() {
        let directory = TempDirectory::new();
        let loader = ConfigLoader::rooted(&directory.path);
        let mut defaults = ConfigPlan::new().with_base_dir(&directory.path);
        defaults.push_file(ConfigSource::DefaultPrimary {
            path: PathBuf::from("ignored-name.properties"),
        });
        defaults.push_file(ConfigSource::DefaultUser {
            path: PathBuf::from("ignored-user.properties"),
        });
        defaults.push_file(ConfigSource::DefaultSystem {
            path: PathBuf::from("ignored-system.properties"),
        });
        assert!(loader.resolve(&defaults).is_ok());

        let mut explicit = ConfigPlan::new().with_base_dir(&directory.path);
        explicit.push_file(ConfigSource::ExplicitPrimary {
            path: PathBuf::from("missing.properties"),
        });
        assert!(matches!(
            loader.resolve(&explicit),
            Err(ConfigError::MissingSource { .. })
        ));
    }

    #[test]
    fn unrooted_loader_rejects_relative_explicit_files_without_using_process_cwd() {
        let error = ConfigLoader::new()
            .read_file("relative.properties")
            .expect_err("relative explicit reads need an explicit root or base");
        assert!(
            matches!(error, ConfigError::UnrootedPath { path } if path == Path::new("relative.properties"))
        );
    }

    #[test]
    fn unrooted_loader_rejects_absolute_explicit_files_without_a_filesystem_root() {
        let path = std::env::temp_dir().join("jmeter-rs-unrooted.properties");
        let error = ConfigLoader::new()
            .read_file(&path)
            .expect_err("absolute reads also need an explicit filesystem capability");
        assert!(matches!(error, ConfigError::UnrootedPath { path: actual } if actual == path));
    }

    #[test]
    fn root_containment_rejects_parent_traversal() {
        let parent = TempDirectory::new();
        let child = parent.path.join("child");
        fs::create_dir_all(&child).expect("child directory");
        let outside = parent.write("outside.properties", b"outside=true\n");
        let mut plan = ConfigPlan::new().with_base_dir(&child);
        plan.push_file(ConfigSource::ExplicitPrimary {
            path: PathBuf::from("../outside.properties"),
        });
        let error = ConfigLoader::rooted(&child)
            .resolve(&plan)
            .expect_err("parent traversal must be rejected");
        assert!(matches!(error, ConfigError::OutsideRoot { .. }));
        assert!(outside.exists());
    }

    #[cfg(unix)]
    #[test]
    fn default_symlink_policy_denies_links_and_root_policy_allows_contained_links() {
        use std::os::unix::fs::symlink;

        let directory = TempDirectory::new();
        directory.write("real.properties", b"key=value\n");
        let link = directory.path.join("link.properties");
        symlink("real.properties", &link).expect("symlink");
        let mut plan = ConfigPlan::new().with_base_dir(&directory.path);
        plan.push_file(ConfigSource::ExplicitPrimary { path: link });
        assert!(matches!(
            ConfigLoader::rooted(&directory.path).resolve(&plan),
            Err(ConfigError::SymlinkDenied { .. })
        ));
        let broken = directory.path.join("broken.properties");
        symlink("does-not-exist.properties", &broken).expect("broken symlink");
        let mut broken_plan = ConfigPlan::new().with_base_dir(&directory.path);
        broken_plan.push_file(ConfigSource::ExplicitPrimary { path: broken });
        assert!(matches!(
            ConfigLoader::rooted(&directory.path).resolve(&broken_plan),
            Err(ConfigError::SymlinkDenied { .. })
        ));
        let allowed = ConfigLoader::rooted(&directory.path).with_fs_policy(
            ConfigFsPolicy::new(&directory.path)
                .with_symlink_policy(SymlinkPolicy::AllowWithinRoot),
        );
        assert_eq!(
            allowed
                .resolve(&plan)
                .expect("contained symlink")
                .jmeter
                .get_value("key"),
            Some("value")
        );
    }

    #[cfg(unix)]
    #[test]
    fn descriptor_bound_reads_fail_closed_for_replaced_parent_and_leaf_links() {
        use std::os::unix::fs::symlink;

        let directory = TempDirectory::new();
        directory.write("real.properties", b"key=value\n");
        fs::create_dir_all(directory.path.join("real-dir")).expect("real child directory");
        fs::write(
            directory.path.join("real-dir/value.properties"),
            b"key=value\n",
        )
        .expect("real nested property file");
        symlink("real.properties", directory.path.join("leaf.properties"))
            .expect("leaf symlink replacement");
        symlink("real-dir", directory.path.join("parent-link"))
            .expect("parent symlink replacement");

        let loader = ConfigLoader::rooted(&directory.path);
        assert!(matches!(
            loader.read_file(directory.path.join("leaf.properties")),
            Err(ConfigError::SymlinkDenied { .. })
        ));
        assert!(matches!(
            loader.read_file(directory.path.join("parent-link/value.properties")),
            Err(ConfigError::SymlinkDenied { .. })
        ));
    }

    #[test]
    fn limits_and_sensitive_values_fail_closed_or_redact() {
        let loader = ConfigLoader::new().with_limits(
            ConfigLimits::standard()
                .with_max_file_bytes(4)
                .with_max_properties(1),
        );
        let source = ConfigSource::ExplicitPrimary {
            path: PathBuf::from("large.properties"),
        };
        assert!(matches!(
            loader.parse_bytes(b"12345", source),
            Err(ConfigError::FileTooLarge { .. })
        ));

        let mut plan = ConfigPlan::new();
        plan.push_assignment(ConfigNamespace::System, "http.proxyPass", "do-not-print", 7);
        let debug = format!("{:?}", plan.operations[0]);
        assert!(!debug.contains("do-not-print"));
        assert!(debug.contains(REDACTED));
        let resolved = ConfigLoader::new().resolve(&plan).expect("inline config");
        assert_eq!(
            resolved.system.get_value("http.proxyPass"),
            Some("do-not-print")
        );
        assert!(format!("{:?}", resolved).contains(REDACTED));
        assert!(!format!("{:?}", resolved).contains("do-not-print"));
    }

    #[test]
    fn invalid_unicode_escapes_are_reported_with_line() {
        let source = ConfigSource::ExplicitPrimary {
            path: PathBuf::from("invalid.properties"),
        };
        let error = ConfigLoader::new()
            .parse_bytes(b"first=ok\nsecond=\\u12x4\n", source)
            .expect_err("invalid escape");
        assert_eq!(error.code(), "config.invalid-escape");
        assert!(matches!(error, ConfigError::InvalidEscape { line: 2, .. }));
    }

    #[test]
    fn comments_do_not_continue_and_cr_line_endings_are_preserved() {
        let source = ConfigSource::ExplicitPrimary {
            path: PathBuf::from("lines.properties"),
        };
        let map = ConfigLoader::new()
            .parse_bytes(b"# comment\\\r\nkey=one\r\rnext=two\r\nlast=three", source)
            .expect("line grammar");
        assert_eq!(map.get_value("key"), Some("one"));
        assert_eq!(map.get_value("next"), Some("two"));
        assert_eq!(map.get_value("last"), Some("three"));
        assert_eq!(map.get_value("key\\"), None);
    }

    #[test]
    fn lone_java_surrogates_are_preserved_as_exact_wtf16() {
        let source = ConfigSource::ExplicitPrimary {
            path: PathBuf::from("surrogate.properties"),
        };
        let map = ConfigLoader::new()
            .parse_bytes(b"value=\\uD800\n", source)
            .expect("WTF-16 value is retained");
        let value = map.get("value").expect("value").value.java_string();
        assert_eq!(value.units(), &[0xD800]);
        assert_eq!(value.escaped(), "\\uD800");
    }

    #[test]
    fn dynamic_user_and_system_paths_use_cwd_then_jmeter_bin_fallback() {
        let root = TempDirectory::new();
        let cwd = root.path.join("cwd");
        let home = root.path.join("home");
        fs::create_dir_all(home.join("bin")).expect("home bin");
        fs::create_dir_all(&cwd).expect("working directory");
        fs::write(
            cwd.join("primary.properties"),
            b"user.properties=dynamic-user.properties\nsystem.properties=dynamic-system.properties\n",
        )
        .expect("primary");
        fs::write(cwd.join("dynamic-user.properties"), b"origin=user-cwd\n").expect("cwd user");
        fs::write(
            cwd.join("dynamic-system.properties"),
            b"origin=system-cwd\n",
        )
        .expect("cwd system");
        let mut plan = ConfigPlan::new()
            .with_base_dir(&cwd)
            .with_jmeter_home(&home);
        plan.push_file(ConfigSource::ExplicitPrimary {
            path: PathBuf::from("primary.properties"),
        });
        plan.push_file(ConfigSource::DefaultUser {
            path: PathBuf::from("user.properties"),
        });
        plan.push_file(ConfigSource::DefaultSystem {
            path: PathBuf::from("system.properties"),
        });
        let loader = ConfigLoader::rooted(&root.path);
        let resolved = loader.resolve(&plan).expect("dynamic cwd sources");
        assert_eq!(resolved.jmeter.get_value("origin"), Some("user-cwd"));
        assert_eq!(resolved.system.get_value("origin"), Some("system-cwd"));
        assert_eq!(
            resolved.operations[1].source.path(),
            Some(Path::new("dynamic-user.properties"))
        );

        fs::remove_file(cwd.join("dynamic-user.properties")).expect("remove cwd user");
        fs::remove_file(cwd.join("dynamic-system.properties")).expect("remove cwd system");
        fs::write(
            home.join("bin/dynamic-user.properties"),
            b"origin=user-bin\n",
        )
        .expect("bin user");
        fs::write(
            home.join("bin/dynamic-system.properties"),
            b"origin=system-bin\n",
        )
        .expect("bin system");
        let resolved = loader.resolve(&plan).expect("dynamic bin fallback");
        assert_eq!(resolved.jmeter.get_value("origin"), Some("user-bin"));
        assert_eq!(resolved.system.get_value("origin"), Some("system-bin"));
    }

    #[test]
    fn default_user_and_system_sources_use_conventional_names_when_primary_is_silent() {
        let root = TempDirectory::new();
        let cwd = root.path.join("cwd");
        fs::create_dir_all(&cwd).expect("working directory");
        fs::write(cwd.join("jmeter.properties"), b"primary=yes\n").expect("primary");
        fs::write(cwd.join("user.properties"), b"user.default=yes\n").expect("user");
        fs::write(cwd.join("system.properties"), b"system.default=yes\n").expect("system");
        let mut plan = ConfigPlan::new().with_base_dir(&cwd);
        plan.push_file(ConfigSource::DefaultPrimary {
            path: PathBuf::from("jmeter.properties"),
        });
        plan.push_file(ConfigSource::DefaultUser {
            path: PathBuf::from("user.properties"),
        });
        plan.push_file(ConfigSource::DefaultSystem {
            path: PathBuf::from("system.properties"),
        });
        let resolved = ConfigLoader::rooted(&root.path)
            .resolve(&plan)
            .expect("conventional defaults");
        assert_eq!(resolved.jmeter.get_value("user.default"), Some("yes"));
        assert_eq!(resolved.system.get_value("system.default"), Some("yes"));
    }

    #[test]
    fn missing_explicit_primary_falls_back_to_default_primary_with_provenance() {
        let directory = TempDirectory::new();
        directory.write("jmeter.properties", b"fallback=yes\n");
        let mut plan = ConfigPlan::new().with_base_dir(&directory.path);
        plan.push_file(ConfigSource::ExplicitPrimary {
            path: PathBuf::from("missing-primary.properties"),
        });
        let resolved = ConfigLoader::rooted(&directory.path)
            .resolve(&plan)
            .expect("default primary fallback");
        assert_eq!(resolved.jmeter.get_value("fallback"), Some("yes"));
        assert!(matches!(
            resolved.operations[0].source,
            ConfigSource::DefaultPrimary { .. }
        ));
        assert!(matches!(
            resolved.jmeter.provenance("fallback"),
            Some(PropertyProvenance {
                source: ConfigSource::DefaultPrimary { .. },
                ..
            })
        ));
    }

    #[test]
    fn explicit_primary_fallback_retains_selected_jmeter_home_bin_path() {
        let root = TempDirectory::new();
        let cwd = root.path.join("cwd");
        let home = root.path.join("home");
        fs::create_dir_all(&cwd).expect("working directory");
        fs::create_dir_all(home.join("bin")).expect("home bin");
        fs::write(home.join("bin/jmeter.properties"), b"bundled=yes\n").expect("bundled primary");

        let mut plan = ConfigPlan::new()
            .with_base_dir(&cwd)
            .with_jmeter_home(&home);
        plan.push_file(ConfigSource::ExplicitPrimary {
            path: PathBuf::from("missing-primary.properties"),
        });
        let loader = ConfigLoader::rooted(&root.path)
            .with_fs_policy(ConfigFsPolicy::new(&root.path).with_additional_root(home.join("bin")));
        let resolved = loader.resolve(&plan).expect("home/bin primary fallback");
        assert_eq!(resolved.jmeter.get_value("bundled"), Some("yes"));
        assert!(matches!(
            resolved.operations[0].source,
            ConfigSource::DefaultPrimary { .. }
        ));
    }

    #[test]
    fn missing_repeatable_files_are_warnings_and_maps_stay_distinct() {
        let directory = TempDirectory::new();
        let mut plan = ConfigPlan::new().with_base_dir(&directory.path);
        plan.push_file(ConfigSource::AdditionalJmeter {
            path: PathBuf::from("missing-q.properties"),
            occurrence: 1,
        });
        plan.push_file(ConfigSource::AdditionalSystem {
            path: PathBuf::from("missing-s.properties"),
            occurrence: 2,
        });
        plan.push_file(ConfigSource::Global {
            path: PathBuf::from("missing-g.properties"),
            occurrence: 3,
        });
        let resolved = ConfigLoader::rooted(&directory.path)
            .resolve(&plan)
            .expect("optional file warning resolution");
        assert_eq!(resolved.warnings.len(), 3);
        assert!(
            resolved
                .warnings
                .iter()
                .all(|warning| warning.code() == "config.missing-optional-source")
        );
        assert!(resolved.jmeter.is_empty());
        assert!(resolved.system.is_empty());
        assert!(resolved.global.is_empty());
    }

    #[test]
    fn global_empty_rhs_is_a_file_path_not_a_removal() {
        let invocation = crate::parse(["-G", "file="]).expect("global file");
        assert!(matches!(
            &invocation.options.global_properties[0],
            GlobalProperty::File { path } if path == "file"
        ));
        let plan = ConfigPlan::from_invocation(&invocation);
        assert!(matches!(
            plan.operations[0].source,
            ConfigSource::DefaultPrimary { .. }
        ));
        assert!(matches!(
            plan.operations.last().map(|operation| &operation.source),
            Some(ConfigSource::Global { path, .. }) if path == Path::new("file")
        ));
        assert!(
            plan.operations
                .iter()
                .all(|operation| operation.kind != PropertyOperationKind::Remove)
        );
    }

    #[test]
    fn proxy_pairs_and_credentials_follow_jmeter_scopes() {
        let password_without_user = crate::parse([
            "-n",
            "-t",
            "plan.jmx",
            "-Dhttp.proxyHost=cli",
            "-H",
            "proxy",
            "-P",
            "8080",
            "-a",
            "secret",
        ])
        .expect("proxy options");
        let plan = ConfigPlan::from_invocation(&password_without_user);
        let resolved = ConfigLoader::new().resolve(&plan).expect("proxy plan");
        assert_eq!(resolved.system.get_value("http.proxyHost"), Some("proxy"));
        assert_eq!(resolved.system.get_value("https.proxyHost"), Some("proxy"));
        assert_eq!(resolved.system.get_value("http.proxyPort"), Some("8080"));
        assert_eq!(resolved.system.get_value("https.proxyPort"), Some("8080"));
        assert_eq!(resolved.system.get_value("http.proxyHost"), Some("proxy"));
        assert_eq!(resolved.jmeter.get_value("http.proxyPass"), None);

        let with_user = crate::parse([
            "-n", "-t", "plan.jmx", "-H", "proxy", "-P", "8080", "-u", "user", "-a", "secret",
        ])
        .expect("proxy credentials");
        let resolved = ConfigLoader::new()
            .resolve(&ConfigPlan::from_invocation(&with_user))
            .expect("proxy credential plan");
        assert_eq!(resolved.jmeter.get_value("http.proxyUser"), Some("user"));
        assert_eq!(resolved.jmeter.get_value("http.proxyPass"), Some("secret"));
        assert!(resolved.system.get_value("http.proxyPass").is_none());
    }

    #[test]
    fn removals_and_aggregate_bounds_remain_auditable_and_bounded() {
        let mut plan = ConfigPlan::new();
        plan.push_assignment(ConfigNamespace::Jmeter, "key", "value", 1);
        plan.push_assignment_or_remove(ConfigNamespace::Jmeter, "key", "", 2);
        let resolved = ConfigLoader::new().resolve(&plan).expect("removal");
        assert_eq!(resolved.jmeter.get_value("key"), None);
        let removals = resolved
            .removal_provenance(ConfigNamespace::Jmeter, "key")
            .expect("removal provenance");
        assert_eq!(removals.len(), 1);
        assert_eq!(removals[0].operation, 1);

        let too_many_operations =
            ConfigLoader::new().with_limits(ConfigLimits::standard().with_max_operations(1));
        assert!(matches!(
            too_many_operations.resolve(&plan),
            Err(ConfigError::LimitExceeded {
                resource: "operations",
                ..
            })
        ));
        let too_many_overrides = ConfigLoader::new()
            .with_limits(ConfigLimits::standard().with_max_overrides_per_property(0));
        let mut duplicate = ConfigPlan::new();
        duplicate.push_assignment(ConfigNamespace::Jmeter, "same", "one", 1);
        duplicate.push_assignment(ConfigNamespace::Jmeter, "same", "two", 2);
        assert!(matches!(
            too_many_overrides.resolve(&duplicate),
            Err(ConfigError::LimitExceeded {
                resource: "overrides per property",
                ..
            })
        ));
        let bounded_inline = ConfigLoader::new().with_limits(
            ConfigLimits::standard()
                .with_max_value_chars(1)
                .with_max_operations(4),
        );
        let mut oversized = ConfigPlan::new();
        oversized.push_assignment(ConfigNamespace::Jmeter, "key", "too long", 1);
        assert!(matches!(
            bounded_inline.resolve(&oversized),
            Err(ConfigError::PropertyTooLong { field: "value", .. })
        ));
    }
}
