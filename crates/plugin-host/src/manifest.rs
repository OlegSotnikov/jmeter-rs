// SPDX-License-Identifier: Apache-2.0

use crate::error::{PluginError, PluginErrorCode};
use serde::{Deserialize, Serialize, de, ser::SerializeMap};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    iter::FromIterator,
    str::FromStr,
    time::Duration,
};

/// The only manifest schema understood by this host.
pub const MANIFEST_SCHEMA_VERSION: u16 = 1;
/// Maximum length of a stable plugin identifier in bytes.
pub const MAX_PLUGIN_ID_LEN: usize = 128;
/// Maximum length of a plugin version in bytes.
pub const MAX_PLUGIN_VERSION_LEN: usize = 64;
/// Maximum length of an element/function ID or alias in bytes.
pub const MAX_CAPABILITY_ID_LEN: usize = 256;
/// Maximum aliases declared by one capability.
pub const MAX_CAPABILITY_ALIASES: usize = 256;
/// Maximum total canonical names and aliases in one manifest namespace.
pub const MAX_DECLARED_CAPABILITY_NAMES: usize = 16 * 1024;
/// Maximum compatibility profiles in one manifest.
pub const MAX_DECLARED_PROFILES: usize = 64;
/// Maximum top-level fields retained from one forward-compatible manifest.
pub const MAX_MANIFEST_EXTENSIONS: usize = 1024;
/// Maximum JMX forward-compatible fields retained for one element.
pub const MAX_JMX_EXTENSIONS: usize = 1024;
/// Maximum bytes in one forward-compatible field name.
pub const MAX_EXTENSION_KEY_BYTES: usize = 4096;
/// Maximum length of an opaque JMX property name in bytes.
///
/// JMX property names are payload keys, not plugin capability identifiers: a
/// plugin may use spaces, punctuation, or other Unicode characters here.  The
/// host only applies a size and NUL bound so unknown properties can be carried
/// without silently narrowing their upstream spelling.
pub const MAX_JMX_PROPERTY_NAME_LEN: usize = 4096;
/// Maximum number of typed/opaque properties retained for one JMX element.
pub const MAX_JMX_PROPERTIES: usize = 4096;
/// Maximum length of a JMX class/name field in bytes.
pub const MAX_JMX_METADATA_TEXT_LEN: usize = 4096;
/// Maximum raw subtree bytes retained by one plugin request.
pub const MAX_RAW_JMX_SUBTREE_BYTES: usize = 8 * 1024 * 1024;
/// Maximum bytes retained for one opaque JMX property value.
pub const MAX_UNKNOWN_JMX_PROPERTY_BYTES: usize = 8 * 1024 * 1024;
/// Maximum number of declared capabilities in one manifest.
pub const MAX_DECLARED_CAPABILITIES: usize = 1024;
/// Maximum number of dependency/artifact declarations in one manifest.
pub const MAX_PLUGIN_DEPENDENCIES: usize = 4096;
/// Maximum executable bytes that may be claimed by one artifact identity.
pub const MAX_PLUGIN_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;
/// Maximum bytes retained for one identity/provenance text field.
pub const MAX_IDENTITY_TEXT_BYTES: usize = 64 * 1024;
/// Maximum bytes in one hexadecimal SHA-256 digest.
pub const SHA256_HEX_LEN: usize = 64;
/// Maximum supported framed payload, independent of a per-plugin lower bound.
pub const HARD_MAX_MESSAGE_BYTES: usize =
    jmeter_rs_bridge_protocol::MAX_MESSAGE_BYTES - jmeter_rs_bridge_protocol::MAX_METADATA_LEN;
/// Maximum supported combined worker output quota.
pub const HARD_MAX_OUTPUT_BYTES: usize = 256 * 1024 * 1024;

fn default_schema_version() -> u16 {
    MANIFEST_SCHEMA_VERSION
}

/// A SHA-256 digest encoded as lower-case hexadecimal on the JSON wire.
///
/// Digest values are identity data, not arbitrary strings.  Keeping the
/// representation typed prevents accidental comparison of differently cased
/// or truncated values and gives manifest validation one canonical rule.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    /// The all-zero value.  It is useful as a construction default but is not
    /// a valid artifact identity.
    pub const ZERO: Self = Self([0; 32]);

    /// Creates a digest from raw bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Parses exactly 64 hexadecimal characters.
    pub fn from_hex(value: &str) -> Result<Self, PluginError> {
        if value.len() != SHA256_HEX_LEN {
            return Err(PluginError::new(
                PluginErrorCode::ManifestInvalid,
                "SHA-256 digest must contain exactly 64 hexadecimal bytes",
            ));
        }
        let mut bytes = [0_u8; 32];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            let high = decode_hex_digit(pair[0]).ok_or_else(|| {
                PluginError::new(
                    PluginErrorCode::ManifestInvalid,
                    "SHA-256 digest contains a non-hexadecimal character",
                )
            })?;
            let low = decode_hex_digit(pair[1]).ok_or_else(|| {
                PluginError::new(
                    PluginErrorCode::ManifestInvalid,
                    "SHA-256 digest contains a non-hexadecimal character",
                )
            })?;
            bytes[index] = (high << 4) | low;
        }
        Ok(Self(bytes))
    }

    /// Compatibility spelling matching the bridge identity types.
    pub fn parse_hex(value: &str) -> Result<Self, PluginError> {
        Self::from_hex(value)
    }

    /// Returns the raw bytes.
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Returns whether this is the forbidden all-zero identity sentinel.
    pub fn is_zero(self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
    }

    /// Returns lower-case hexadecimal wire text.
    pub fn to_hex(self) -> String {
        let mut value = String::with_capacity(SHA256_HEX_LEN);
        for byte in self.0 {
            use std::fmt::Write as _;
            let _ = write!(value, "{byte:02x}");
        }
        value
    }
}

impl Default for Sha256Digest {
    fn default() -> Self {
        Self::ZERO
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Sha256Digest(<redacted>)")
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

impl FromStr for Sha256Digest {
    type Err = PluginError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::from_hex(value)
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_hex(&value).map_err(de::Error::custom)
    }
}

fn decode_hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn validate_identity_text(value: &str, label: &str, allow_empty: bool) -> Result<(), PluginError> {
    if (!allow_empty && value.is_empty()) || value.len() > MAX_IDENTITY_TEXT_BYTES {
        return Err(PluginError::new(
            PluginErrorCode::ManifestInvalid,
            format!(
                "{label} must contain {}..={} bytes",
                if allow_empty { 0 } else { 1 },
                MAX_IDENTITY_TEXT_BYTES
            ),
        ));
    }
    if value.contains('\0') {
        return Err(PluginError::new(
            PluginErrorCode::ManifestInvalid,
            format!("{label} must not contain NUL"),
        ));
    }
    Ok(())
}

fn validate_digest(value: Sha256Digest, label: &str) -> Result<(), PluginError> {
    if value.is_zero() {
        return Err(PluginError::new(
            PluginErrorCode::ManifestInvalid,
            format!("{label} must not be the all-zero SHA-256 digest"),
        ));
    }
    Ok(())
}

fn validate_extension_map(
    extensions: &BTreeMap<String, Value>,
    maximum: usize,
    label: &str,
) -> Result<(), PluginError> {
    if extensions.len() > maximum {
        return Err(PluginError::new(
            PluginErrorCode::ManifestInvalid,
            format!(
                "{label} contains {}; maximum is {maximum}",
                extensions.len()
            ),
        ));
    }
    for name in extensions.keys() {
        if name.is_empty() || name.len() > MAX_EXTENSION_KEY_BYTES {
            return Err(PluginError::new(
                PluginErrorCode::ManifestInvalid,
                format!("{label} field names must contain 1..={MAX_EXTENSION_KEY_BYTES} bytes"),
            ));
        }
        if name.contains('\0') {
            return Err(PluginError::new(
                PluginErrorCode::ManifestInvalid,
                format!("{label} field names must not contain NUL"),
            ));
        }
    }
    Ok(())
}

/// A stable plugin identifier.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PluginId(String);

impl PluginId {
    /// Parses and validates an ID using the host's stable identifier rules.
    pub fn parse(value: impl Into<String>) -> Result<Self, PluginError> {
        let value = value.into();
        validate_identifier(&value, MAX_PLUGIN_ID_LEN, "plugin ID")?;
        Ok(Self(value))
    }

    /// Returns the identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PluginId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A stable, release (non-prerelease) semantic plugin version.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PluginVersion(String);

impl PluginVersion {
    /// Parses a `major.minor.patch` release version.
    pub fn parse(value: impl Into<String>) -> Result<Self, PluginError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_PLUGIN_VERSION_LEN {
            return Err(PluginError::new(
                PluginErrorCode::ManifestInvalid,
                format!("plugin version must contain 1..={MAX_PLUGIN_VERSION_LEN} bytes"),
            ));
        }
        let mut parts = value.split('.');
        let major = parse_version_component(parts.next(), "major")?;
        let minor = parse_version_component(parts.next(), "minor")?;
        let patch = parse_version_component(parts.next(), "patch")?;
        if parts.next().is_some() {
            return Err(PluginError::new(
                PluginErrorCode::ManifestInvalid,
                "plugin version must contain exactly major.minor.patch",
            ));
        }
        // Parsing to u32 also prevents values that would overflow a version
        // comparison in a worker handshake.
        let _ = (major, minor, patch);
        Ok(Self(value))
    }

    /// Returns the original canonical version string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PluginVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for PluginVersion {
    type Err = PluginError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value.to_owned())
    }
}

fn parse_version_component(value: Option<&str>, component: &str) -> Result<u32, PluginError> {
    let Some(value) = value else {
        return Err(PluginError::new(
            PluginErrorCode::ManifestInvalid,
            format!("plugin version is missing {component}"),
        ));
    };
    if value.is_empty() || (value.len() > 1 && value.starts_with('0')) {
        return Err(PluginError::new(
            PluginErrorCode::ManifestInvalid,
            format!("plugin version {component} is not a canonical integer"),
        ));
    }
    value.parse::<u32>().map_err(|_| {
        PluginError::new(
            PluginErrorCode::ManifestInvalid,
            format!("plugin version {component} is outside the supported range"),
        )
    })
}

fn validate_identifier(value: &str, maximum: usize, label: &str) -> Result<(), PluginError> {
    if value.is_empty() || value.len() > maximum {
        return Err(PluginError::new(
            PluginErrorCode::ManifestInvalid,
            format!("{label} must contain 1..={maximum} bytes"),
        ));
    }
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return Err(PluginError::new(
            PluginErrorCode::ManifestInvalid,
            format!("{label} is empty"),
        ));
    };
    if !first.is_ascii_alphanumeric()
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(PluginError::new(
            PluginErrorCode::ManifestInvalid,
            format!("{label} contains an unsupported character"),
        ));
    }
    Ok(())
}

fn validate_capability_identifier(
    value: &str,
    maximum: usize,
    label: &str,
) -> Result<(), PluginError> {
    if value.is_empty() || value.len() > maximum {
        return Err(PluginError::new(
            PluginErrorCode::ManifestInvalid,
            format!("{label} must contain 1..={maximum} bytes"),
        ));
    }
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return Err(PluginError::new(
            PluginErrorCode::ManifestInvalid,
            format!("{label} is empty"),
        ));
    };
    if !(first.is_ascii_alphanumeric() || first == b'_')
        || !bytes
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
    {
        return Err(PluginError::new(
            PluginErrorCode::ManifestInvalid,
            format!("{label} contains an unsupported character"),
        ));
    }
    Ok(())
}

fn validate_opaque_jmx_property_name(value: &str) -> Result<(), PluginError> {
    if value.is_empty() || value.len() > MAX_JMX_PROPERTY_NAME_LEN {
        return Err(PluginError::new(
            PluginErrorCode::InvalidJmx,
            format!("JMX property name must contain 1..={MAX_JMX_PROPERTY_NAME_LEN} bytes"),
        ));
    }
    if value.contains('\0') {
        return Err(PluginError::new(
            PluginErrorCode::InvalidJmx,
            "JMX property name must not contain NUL",
        ));
    }
    Ok(())
}

/// Insertion-preserving JMX property map.
///
/// JMeter's element state retains property insertion order and normalized JMX
/// output can observe it.  A `BTreeMap` would sort keys and silently change
/// that contract, so this small dependency-free map serializes as a JSON
/// object while retaining the source order during decode and re-encode.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct JmxProperties {
    entries: Vec<(String, Value)>,
}

impl JmxProperties {
    /// Creates an empty ordered property map.
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Inserts a property, replacing its value in its original position.
    pub fn insert(&mut self, name: impl Into<String>, value: Value) -> Option<Value> {
        let name = name.into();
        if let Some((_, existing)) = self.entries.iter_mut().find(|(key, _)| key == &name) {
            return Some(std::mem::replace(existing, value));
        }
        self.entries.push((name, value));
        None
    }

    /// Returns a property value by its exact upstream name.
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.entries
            .iter()
            .find_map(|(key, value)| (key == name).then_some(value))
    }

    /// Returns the number of properties.
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the map has no properties.
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Removes all properties.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Iterates properties in source insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.entries
            .iter()
            .map(|(name, value)| (name.as_str(), value))
    }
}

impl fmt::Debug for JmxProperties {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JmxProperties")
            .field("count", &self.entries.len())
            .finish()
    }
}

impl Serialize for JmxProperties {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.entries.len()))?;
        for (name, value) in &self.entries {
            map.serialize_entry(name, value)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for JmxProperties {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct JmxPropertiesVisitor;

        impl<'de> de::Visitor<'de> for JmxPropertiesVisitor {
            type Value = JmxProperties;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an insertion-preserving JMX property object")
            }

            fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut properties = JmxProperties::new();
                while let Some((name, value)) = access.next_entry::<String, Value>()? {
                    if properties.entries.len() >= MAX_JMX_PROPERTIES {
                        return Err(de::Error::custom(format!(
                            "JMX property count exceeds {MAX_JMX_PROPERTIES}"
                        )));
                    }
                    validate_opaque_jmx_property_name(&name).map_err(de::Error::custom)?;
                    if properties.get(&name).is_some() {
                        return Err(de::Error::custom("duplicate JMX property name"));
                    }
                    properties.entries.push((name, value));
                }
                Ok(properties)
            }
        }

        deserializer.deserialize_map(JmxPropertiesVisitor)
    }
}

impl FromIterator<(String, Value)> for JmxProperties {
    fn from_iter<T: IntoIterator<Item = (String, Value)>>(iter: T) -> Self {
        let mut properties = Self::new();
        for (name, value) in iter {
            properties.insert(name, value);
        }
        properties
    }
}

/// A closed protocol version interval supported by a plugin.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolRange {
    /// Lowest supported protocol version, inclusive.
    pub min: u16,
    /// Highest supported protocol version, inclusive.
    pub max: u16,
}

impl ProtocolRange {
    /// Creates and validates a protocol range.
    pub fn new(min: u16, max: u16) -> Result<Self, PluginError> {
        let range = Self { min, max };
        range.validate()?;
        Ok(range)
    }

    /// Returns whether a version falls in this range.
    pub const fn supports(self, version: u16) -> bool {
        version >= self.min && version <= self.max
    }

    /// Returns whether two ranges have at least one common version.
    pub const fn overlaps(self, other: Self) -> bool {
        self.min <= other.max && other.min <= self.max
    }

    /// Checks the range invariants.
    pub fn validate(self) -> Result<(), PluginError> {
        if self.min == 0 || self.max == 0 || self.min > self.max {
            return Err(PluginError::new(
                PluginErrorCode::ManifestInvalid,
                "protocol range must be non-zero and ordered",
            ));
        }
        Ok(())
    }
}

/// The two plugin capability families supported by this host.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CapabilityKind {
    /// A JMeter element/sampler/controller capability.
    Element,
    /// A JMeter expression/function capability.
    Function,
}

impl CapabilityKind {
    /// Returns the stable wire spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Element => "element",
            Self::Function => "function",
        }
    }
}

/// A canonical element or function ID and its JMX aliases.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapabilityDeclaration {
    /// Stable capability ID.
    pub id: String,
    /// Case-sensitive JMX/function aliases accepted by this plugin.
    #[serde(default)]
    pub aliases: Vec<String>,
    /// Forward-compatible metadata retained from a manifest.
    #[serde(flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl CapabilityDeclaration {
    /// Creates a declaration with no aliases.
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            aliases: Vec::new(),
            extensions: BTreeMap::new(),
        }
    }

    /// Returns whether a canonical ID or alias matches exactly.
    pub fn matches(&self, name: &str) -> bool {
        self.id == name || self.aliases.iter().any(|alias| alias == name)
    }

    /// Validates canonical and alias IDs.
    pub fn validate(&self, kind: CapabilityKind) -> Result<(), PluginError> {
        let label = format!("{} capability", kind.as_str());
        validate_capability_identifier(&self.id, MAX_CAPABILITY_ID_LEN, &label)?;
        if self.aliases.len() > MAX_CAPABILITY_ALIASES {
            return Err(PluginError::new(
                PluginErrorCode::ManifestInvalid,
                format!(
                    "{} capability {} declares {} aliases; maximum is {MAX_CAPABILITY_ALIASES}",
                    kind.as_str(),
                    self.id,
                    self.aliases.len()
                ),
            ));
        }
        let mut names = std::collections::BTreeSet::new();
        if !names.insert(self.id.as_str()) {
            return Err(PluginError::new(
                PluginErrorCode::ManifestInvalid,
                format!("duplicate {} capability ID {}", kind.as_str(), self.id),
            ));
        }
        for alias in &self.aliases {
            validate_capability_identifier(alias, MAX_CAPABILITY_ID_LEN, "capability alias")?;
            if !names.insert(alias.as_str()) {
                return Err(PluginError::new(
                    PluginErrorCode::ManifestInvalid,
                    format!("duplicate capability name {alias}"),
                ));
            }
        }
        validate_extension_map(
            &self.extensions,
            MAX_MANIFEST_EXTENSIONS,
            "capability extensions",
        )
    }
}

impl fmt::Debug for CapabilityDeclaration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityDeclaration")
            .field("id", &self.id)
            .field("aliases", &self.aliases)
            .field("extension_count", &self.extensions.len())
            .finish()
    }
}

/// The declared element/function capabilities in a plugin manifest.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityDeclarations {
    /// Element capabilities in manifest order.
    #[serde(default)]
    pub elements: Vec<CapabilityDeclaration>,
    /// Function capabilities in manifest order.
    #[serde(default)]
    pub functions: Vec<CapabilityDeclaration>,
}

impl CapabilityDeclarations {
    /// Iterates all declarations in deterministic element-then-function order.
    pub fn iter(&self) -> impl Iterator<Item = (CapabilityKind, &CapabilityDeclaration)> {
        self.elements
            .iter()
            .map(|item| (CapabilityKind::Element, item))
            .chain(
                self.functions
                    .iter()
                    .map(|item| (CapabilityKind::Function, item)),
            )
    }

    /// Finds a capability by canonical ID or alias.
    pub fn find(&self, kind: CapabilityKind, name: &str) -> Option<&CapabilityDeclaration> {
        let declarations = match kind {
            CapabilityKind::Element => &self.elements,
            CapabilityKind::Function => &self.functions,
        };
        declarations.iter().find(|item| item.matches(name))
    }

    /// Validates all declarations and their count.
    pub fn validate(&self) -> Result<(), PluginError> {
        let count = self.elements.len().saturating_add(self.functions.len());
        if count > MAX_DECLARED_CAPABILITIES {
            return Err(PluginError::new(
                PluginErrorCode::ManifestInvalid,
                format!(
                    "manifest declares {count} capabilities; maximum is {MAX_DECLARED_CAPABILITIES}"
                ),
            ));
        }
        let name_count = self
            .iter()
            .map(|(_, declaration)| 1_usize.saturating_add(declaration.aliases.len()))
            .fold(0_usize, usize::saturating_add);
        if name_count > MAX_DECLARED_CAPABILITY_NAMES {
            return Err(PluginError::new(
                PluginErrorCode::ManifestInvalid,
                format!(
                    "manifest declares {name_count} capability names; maximum is {MAX_DECLARED_CAPABILITY_NAMES}"
                ),
            ));
        }
        // Capability lookup is namespaced by kind.  Within one namespace,
        // however, every canonical ID and alias must resolve to exactly one
        // declaration before a manifest can be advertised or a worker
        // handshake can be accepted.  Registry indexing performs the same
        // check for discovered descriptors, but direct manifest/handshake
        // callers must fail closed at this lower pure boundary as well.
        let mut names = BTreeSet::new();
        for (kind, declaration) in self.iter() {
            declaration.validate(kind)?;
            for name in std::iter::once(declaration.id.as_str())
                .chain(declaration.aliases.iter().map(String::as_str))
            {
                if !names.insert((kind, name.to_owned())) {
                    return Err(PluginError::new(
                        PluginErrorCode::ManifestInvalid,
                        format!("duplicate {} capability name {name}", kind.as_str()),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// A capability requested by a JMX execution path.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityReference {
    /// Capability family.
    pub kind: CapabilityKind,
    /// Canonical ID or alias.
    pub name: String,
}

impl CapabilityReference {
    /// Creates a capability reference.
    pub fn new(kind: CapabilityKind, name: impl Into<String>) -> Self {
        Self {
            kind,
            name: name.into(),
        }
    }

    /// Validates a request-side canonical capability name or alias.
    pub fn validate(&self) -> Result<(), PluginError> {
        validate_capability_identifier(&self.name, MAX_CAPABILITY_ID_LEN, "plugin capability")
            .map_err(|error| {
                PluginError::new(PluginErrorCode::InvalidJmx, error.detail().to_owned())
            })
    }
}

/// Declares whether raw/unknown JMX information can be round-tripped.
///
/// This metadata is part of the plugin contract.  The host never drops the
/// raw subtree or unknown properties merely because a plugin does not decode
/// them; callers can inspect this contract before execution.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreservationContract {
    /// Version of this preservation metadata contract.
    #[serde(default = "default_preservation_contract_version")]
    pub contract_version: u16,
    /// The worker accepts and returns unknown element subtrees unchanged.
    #[serde(default)]
    pub unknown_elements: bool,
    /// The worker accepts and returns unknown element properties unchanged.
    #[serde(default)]
    pub unknown_properties: bool,
    /// The worker can carry the original raw XML subtree without decoding it.
    #[serde(default)]
    pub raw_subtree: bool,
}

fn default_preservation_contract_version() -> u16 {
    1
}

impl Default for PreservationContract {
    fn default() -> Self {
        Self {
            contract_version: 1,
            unknown_elements: false,
            unknown_properties: false,
            raw_subtree: false,
        }
    }
}

impl PreservationContract {
    /// Returns whether this contract can carry all unknown data in an element.
    pub const fn preserves_unknown_element(&self) -> bool {
        self.contract_version > 0
            && self.unknown_elements
            && self.unknown_properties
            && self.raw_subtree
    }

    /// Checks the metadata version.
    pub fn validate(&self) -> Result<(), PluginError> {
        if self.contract_version == 0 {
            return Err(PluginError::new(
                PluginErrorCode::ManifestInvalid,
                "preservation contract version must be non-zero",
            ));
        }
        Ok(())
    }
}

/// Per-worker limits declared by a plugin.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    /// Maximum kind-specific bridge payload bytes.
    pub max_message_bytes: usize,
    /// Maximum combined raw stdout bytes observed for one invocation.
    pub max_output_bytes: usize,
    /// Maximum raw stderr bytes observed for one invocation.
    #[serde(default = "default_max_stderr_bytes")]
    pub max_stderr_bytes: usize,
    /// Maximum worker startup duration in milliseconds.
    pub startup_timeout_ms: u64,
    /// Maximum duration of one request in milliseconds.
    pub request_timeout_ms: u64,
    /// Grace period advertised to a worker after cancellation.
    #[serde(default = "default_cancel_grace_timeout_ms")]
    pub cancel_grace_timeout_ms: u64,
    /// Maximum concurrently supervised worker calls for this plugin.
    #[serde(default = "default_max_concurrent_requests")]
    pub max_concurrent_requests: usize,
}

fn default_max_stderr_bytes() -> usize {
    64 * 1024
}

fn default_cancel_grace_timeout_ms() -> u64 {
    100
}

fn default_max_concurrent_requests() -> usize {
    1
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_message_bytes: 1024 * 1024,
            max_output_bytes: 1024 * 1024,
            max_stderr_bytes: default_max_stderr_bytes(),
            startup_timeout_ms: 5_000,
            request_timeout_ms: 30_000,
            cancel_grace_timeout_ms: default_cancel_grace_timeout_ms(),
            max_concurrent_requests: default_max_concurrent_requests(),
        }
    }
}

impl ResourceLimits {
    /// Validates all quota and duration bounds.
    pub fn validate(&self) -> Result<(), PluginError> {
        if self.max_message_bytes == 0
            || self.max_message_bytes > HARD_MAX_MESSAGE_BYTES
            || jmeter_rs_bridge_protocol::validate_max_message_bytes(self.max_message_bytes)
                .is_err()
        {
            return Err(PluginError::new(
                PluginErrorCode::ManifestInvalid,
                format!("max_message_bytes must be between 1 and {HARD_MAX_MESSAGE_BYTES}"),
            ));
        }
        if self.max_output_bytes == 0 || self.max_output_bytes > HARD_MAX_OUTPUT_BYTES {
            return Err(PluginError::new(
                PluginErrorCode::ManifestInvalid,
                format!("max_output_bytes must be between 1 and {HARD_MAX_OUTPUT_BYTES}"),
            ));
        }
        if self.max_stderr_bytes == 0 || self.max_stderr_bytes > self.max_output_bytes {
            return Err(PluginError::new(
                PluginErrorCode::ManifestInvalid,
                "max_stderr_bytes must be non-zero and no larger than max_output_bytes",
            ));
        }
        if self.startup_timeout_ms == 0 || self.startup_timeout_ms > 5 * 60 * 1_000 {
            return Err(PluginError::new(
                PluginErrorCode::ManifestInvalid,
                "startup_timeout_ms is outside the supported 1..=300000 range",
            ));
        }
        if self.request_timeout_ms == 0 || self.request_timeout_ms > 60 * 60 * 1_000 {
            return Err(PluginError::new(
                PluginErrorCode::ManifestInvalid,
                "request_timeout_ms is outside the supported 1..=3600000 range",
            ));
        }
        if self.cancel_grace_timeout_ms > 30 * 1_000 {
            return Err(PluginError::new(
                PluginErrorCode::ManifestInvalid,
                "cancel_grace_timeout_ms exceeds the supported 30 second bound",
            ));
        }
        if self.max_concurrent_requests == 0 || self.max_concurrent_requests > 1024 {
            return Err(PluginError::new(
                PluginErrorCode::ManifestInvalid,
                "max_concurrent_requests must be between 1 and 1024",
            ));
        }
        Ok(())
    }

    /// Returns the startup deadline as a duration.
    pub fn startup_timeout(&self) -> Duration {
        Duration::from_millis(self.startup_timeout_ms)
    }

    /// Returns the request deadline as a duration.
    pub fn request_timeout(&self) -> Duration {
        Duration::from_millis(self.request_timeout_ms)
    }

    /// Returns the cancellation grace duration.
    pub fn cancel_grace_timeout(&self) -> Duration {
        Duration::from_millis(self.cancel_grace_timeout_ms)
    }
}

/// License and NOTICE provenance state for one plugin artifact.
///
/// `Missing` is explicit rather than inferred from empty strings.  This keeps
/// a manifest's provenance decision observable while allowing a caller to
/// retain an artifact descriptor that is known to be incomplete.
#[derive(
    Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum LicenseNoticeStatus {
    /// The license and NOTICE material was checked against the artifact.
    Verified,
    /// The manifest declares license and NOTICE material but it was not
    /// independently verified by this host.
    Declared,
    /// One or both provenance documents are unavailable.
    #[default]
    Missing,
}

impl LicenseNoticeStatus {
    /// Returns whether this status requires declared license and NOTICE text.
    const fn requires_text(self) -> bool {
        matches!(self, Self::Verified | Self::Declared)
    }
}

/// One ordered plugin dependency/artifact identity.
///
/// Dependency entries are data only.  This crate does not resolve, load, or
/// execute them; the optional Java compatibility pack owns that behavior.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PluginDependency {
    /// Stable dependency or plugin name.
    pub name: String,
    /// Dependency release/version identity.
    pub version: String,
    /// SHA-256 of the exact dependency bytes.
    pub sha256: Sha256Digest,
    /// SPDX/license identifier or bounded provenance text.
    pub license: String,
    /// NOTICE identifier, digest, or bounded provenance text.
    pub notice: String,
    /// Position in the effective ordered classpath.
    #[serde(alias = "ordinal")]
    pub classpath_order: u32,
    /// Forward-compatible dependency metadata retained verbatim.
    #[serde(flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl PluginDependency {
    /// Validates dependency identity and provenance fields.
    pub fn validate(&self) -> Result<(), PluginError> {
        validate_identity_text(&self.name, "dependency name", false)?;
        validate_identity_text(&self.version, "dependency version", false)?;
        validate_digest(self.sha256, "dependency SHA-256")?;
        validate_identity_text(&self.license, "dependency license", false)?;
        validate_identity_text(&self.notice, "dependency NOTICE", false)?;
        validate_extension_map(
            &self.extensions,
            MAX_MANIFEST_EXTENSIONS,
            "dependency extensions",
        )
    }
}

impl fmt::Debug for PluginDependency {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginDependency")
            .field("name", &self.name)
            .field("version", &self.version)
            .field("sha256", &self.sha256)
            .field("license_len", &self.license.len())
            .field("notice_len", &self.notice.len())
            .field("classpath_order", &self.classpath_order)
            .field("extension_count", &self.extensions.len())
            .finish()
    }
}

/// Identity and provenance for the executable represented by a plugin
/// manifest.
///
/// This is optional for backwards-compatible native manifests.  When it is
/// present, validation is deliberately strict: a plugin can only claim a
/// reproducible artifact identity when its content digest, size, ordered
/// dependencies, and license/NOTICE state are all explicit.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PluginArtifact {
    /// SHA-256 of the exact executable bytes.
    #[serde(alias = "content_sha256", alias = "artifact_sha256")]
    pub sha256: Sha256Digest,
    /// Exact executable byte length.
    #[serde(default, alias = "size_bytes")]
    pub byte_length: u64,
    /// Plugin artifact release/version identity.
    #[serde(default)]
    pub version: String,
    /// Bounded source/provenance identifier.
    #[serde(default)]
    pub provenance: String,
    /// SPDX/license identifier or bounded provenance text.
    #[serde(default)]
    pub license: String,
    /// NOTICE identifier, digest, or bounded provenance text.
    #[serde(default)]
    pub notice: String,
    /// Explicit license/NOTICE accounting state.
    #[serde(default)]
    pub license_notice: LicenseNoticeStatus,
    /// Dependencies in effective classpath order.
    #[serde(default)]
    pub dependencies: Vec<PluginDependency>,
    /// Forward-compatible artifact metadata retained verbatim.
    #[serde(flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl PluginArtifact {
    /// Validates artifact identity, ordered dependencies, and provenance.
    pub fn validate(&self) -> Result<(), PluginError> {
        validate_digest(self.sha256, "plugin artifact SHA-256")?;
        if self.byte_length == 0 || self.byte_length > MAX_PLUGIN_ARTIFACT_BYTES {
            return Err(PluginError::new(
                PluginErrorCode::ManifestInvalid,
                format!(
                    "plugin artifact byte_length must be between 1 and {MAX_PLUGIN_ARTIFACT_BYTES}"
                ),
            ));
        }
        validate_identity_text(&self.version, "plugin artifact version", false)?;
        validate_identity_text(&self.provenance, "plugin artifact provenance", false)?;
        validate_identity_text(
            &self.license,
            "plugin artifact license",
            self.license_notice == LicenseNoticeStatus::Missing,
        )?;
        validate_identity_text(
            &self.notice,
            "plugin artifact NOTICE",
            self.license_notice == LicenseNoticeStatus::Missing,
        )?;
        if self.license_notice.requires_text()
            && (self.license.is_empty() || self.notice.is_empty())
        {
            return Err(PluginError::new(
                PluginErrorCode::ManifestInvalid,
                "plugin artifact license_notice state requires license and NOTICE text",
            ));
        }
        if self.dependencies.len() > MAX_PLUGIN_DEPENDENCIES {
            return Err(PluginError::new(
                PluginErrorCode::ManifestInvalid,
                format!(
                    "plugin artifact declares {}; maximum dependencies is {MAX_PLUGIN_DEPENDENCIES}",
                    self.dependencies.len()
                ),
            ));
        }
        let mut names = BTreeSet::new();
        let mut ordinals = BTreeSet::new();
        let mut previous_ordinal = None;
        for dependency in &self.dependencies {
            dependency.validate()?;
            if !names.insert(dependency.name.as_str()) {
                return Err(PluginError::new(
                    PluginErrorCode::ManifestInvalid,
                    format!("duplicate plugin dependency name {}", dependency.name),
                ));
            }
            if !ordinals.insert(dependency.classpath_order) {
                return Err(PluginError::new(
                    PluginErrorCode::ManifestInvalid,
                    format!(
                        "duplicate plugin dependency classpath order {}",
                        dependency.classpath_order
                    ),
                ));
            }
            if let Some(previous) = previous_ordinal
                && dependency.classpath_order <= previous
            {
                return Err(PluginError::new(
                    PluginErrorCode::ManifestInvalid,
                    "plugin dependency declarations must be in classpath order",
                ));
            }
            previous_ordinal = Some(dependency.classpath_order);
        }
        validate_extension_map(
            &self.extensions,
            MAX_MANIFEST_EXTENSIONS,
            "plugin artifact extensions",
        )
    }

    /// Returns whether an observed executable identity matches this artifact.
    pub fn matches_executable(&self, length: u64, digest: Sha256Digest) -> bool {
        self.byte_length == length && self.sha256 == digest
    }
}

impl fmt::Debug for PluginArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginArtifact")
            .field("sha256", &self.sha256)
            .field("byte_length", &self.byte_length)
            .field("version", &self.version)
            .field("provenance_len", &self.provenance.len())
            .field("license_len", &self.license.len())
            .field("notice_len", &self.notice.len())
            .field("license_notice", &self.license_notice)
            .field("dependency_count", &self.dependencies.len())
            .field("extension_count", &self.extensions.len())
            .finish()
    }
}

/// Compatibility aliases for callers that use the identity terminology from
/// the optional JVM/compatibility pack.
pub type ArtifactIdentity = PluginArtifact;
/// Compatibility alias for a dependency identity.
pub type DependencyIdentity = PluginDependency;

/// A versioned plugin manifest loaded from an explicitly allowlisted file.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PluginManifest {
    /// Manifest schema version.
    #[serde(default = "default_schema_version")]
    pub schema_version: u16,
    /// Stable plugin ID.
    pub id: PluginId,
    /// Stable release version.
    pub version: PluginVersion,
    /// Absolute path to the out-of-process executable.
    pub executable: std::path::PathBuf,
    /// Protocol versions supported by this worker.
    pub protocol: ProtocolRange,
    /// Compatibility profile IDs accepted by this worker.
    #[serde(alias = "profile_compatibility")]
    pub profiles: Vec<String>,
    /// Element and function capability declarations.
    pub capabilities: CapabilityDeclarations,
    /// Message/process resource limits.
    pub limits: ResourceLimits,
    /// Unknown JMX element/property preservation contract.
    #[serde(default)]
    pub preservation: PreservationContract,
    /// Optional executable/dependency identity and license provenance.
    ///
    /// `artifact` and `artifact_identity` are accepted as historical wire
    /// spellings; serialization always emits the canonical `identity` key.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "artifact",
        alias = "artifact_identity"
    )]
    pub identity: Option<PluginArtifact>,
    /// Forward-compatible manifest fields retained for inspection.
    #[serde(flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl PluginManifest {
    /// Builds a manifest with explicit defaults for protocol, capabilities,
    /// limits, and preservation metadata.  Callers must still set profiles
    /// before validation.
    pub fn new(
        id: PluginId,
        version: PluginVersion,
        executable: impl Into<std::path::PathBuf>,
    ) -> Self {
        Self {
            schema_version: MANIFEST_SCHEMA_VERSION,
            id,
            version,
            executable: executable.into(),
            protocol: ProtocolRange { min: 1, max: 1 },
            profiles: Vec::new(),
            capabilities: CapabilityDeclarations::default(),
            limits: ResourceLimits::default(),
            preservation: PreservationContract::default(),
            identity: None,
            extensions: BTreeMap::new(),
        }
    }

    /// Validates fields that do not require filesystem access.
    pub fn validate(&self) -> Result<(), PluginError> {
        if self.schema_version != MANIFEST_SCHEMA_VERSION {
            return Err(PluginError::new(
                PluginErrorCode::ManifestInvalid,
                format!(
                    "unsupported manifest schema version {}",
                    self.schema_version
                ),
            ));
        }
        PluginId::parse(self.id.as_str().to_owned())?;
        PluginVersion::parse(self.version.as_str().to_owned())?;
        if !self.executable.is_absolute() {
            return Err(PluginError::new(
                PluginErrorCode::ManifestInvalid,
                "executable path must be absolute",
            ));
        }
        let executable_text = self.executable.to_string_lossy();
        if executable_text.is_empty()
            || executable_text.len() > MAX_IDENTITY_TEXT_BYTES
            || executable_text.contains('\0')
        {
            return Err(PluginError::new(
                PluginErrorCode::ManifestInvalid,
                "executable path is empty, too long, or contains NUL",
            ));
        }
        self.protocol.validate()?;
        if self.profiles.is_empty() {
            return Err(PluginError::new(
                PluginErrorCode::ManifestInvalid,
                "at least one compatibility profile must be declared",
            ));
        }
        let mut profile_names = std::collections::BTreeSet::new();
        for profile in &self.profiles {
            validate_identifier(profile, MAX_PLUGIN_ID_LEN, "profile ID")?;
            if !profile_names.insert(profile) {
                return Err(PluginError::new(
                    PluginErrorCode::ManifestInvalid,
                    format!("duplicate profile ID {profile}"),
                ));
            }
        }
        if self.profiles.len() > MAX_DECLARED_PROFILES {
            return Err(PluginError::new(
                PluginErrorCode::ManifestInvalid,
                format!(
                    "manifest declares {}; maximum profiles is {MAX_DECLARED_PROFILES}",
                    self.profiles.len()
                ),
            ));
        }
        self.capabilities.validate()?;
        self.limits.validate()?;
        self.preservation.validate()?;
        if let Some(identity) = &self.identity {
            identity.validate()?;
            if identity.license_notice == LicenseNoticeStatus::Missing {
                return Err(PluginError::new(
                    PluginErrorCode::ManifestInvalid,
                    "plugin manifest artifact identity has missing license/NOTICE provenance",
                ));
            }
        }
        validate_extension_map(
            &self.extensions,
            MAX_MANIFEST_EXTENSIONS,
            "manifest extensions",
        )?;
        Ok(())
    }

    /// Returns whether the plugin declares a compatibility profile.
    pub fn supports_profile(&self, profile: &str) -> bool {
        self.profiles.iter().any(|item| item == profile)
    }

    /// Resolves a canonical capability ID or alias.
    pub fn find_capability(
        &self,
        reference: &CapabilityReference,
    ) -> Option<&CapabilityDeclaration> {
        self.capabilities.find(reference.kind, &reference.name)
    }

    /// Returns the optional artifact identity declaration.
    pub fn identity(&self) -> Option<&PluginArtifact> {
        self.identity.as_ref()
    }

    /// Returns the optional artifact identity declaration using the artifact
    /// terminology retained by older callers.
    pub fn artifact(&self) -> Option<&PluginArtifact> {
        self.identity()
    }

    /// Computes the SHA-256 of this manifest's canonical JSON representation.
    ///
    /// The digest is calculated after validation, and therefore includes the
    /// ordered capability/dependency declarations, negotiated limits,
    /// preservation contract, optional artifact identity, and retained
    /// extension fields.  It never includes a self-referential digest field.
    pub fn manifest_sha256(&self) -> Result<Sha256Digest, PluginError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|error| {
            PluginError::new(
                PluginErrorCode::ManifestInvalid,
                format!("could not encode canonical plugin manifest: {error}"),
            )
        })?;
        let mut digest = Sha256::new();
        digest.update(bytes);
        Ok(Sha256Digest::from_bytes(digest.finalize().into()))
    }

    /// Verifies an observed executable identity against the declared artifact.
    ///
    /// A manifest without identity metadata cannot make a content-integrity
    /// claim, so this method returns a typed manifest error instead of
    /// silently accepting an unverifiable executable.
    pub fn validate_executable_identity(
        &self,
        length: u64,
        digest: Sha256Digest,
    ) -> Result<(), PluginError> {
        let Some(identity) = self.identity.as_ref() else {
            return Err(PluginError::new(
                PluginErrorCode::ManifestInvalid,
                "plugin manifest does not declare executable identity",
            ));
        };
        identity.validate()?;
        if identity.matches_executable(length, digest) {
            Ok(())
        } else {
            Err(PluginError::new(
                PluginErrorCode::ManifestInvalid,
                "observed executable identity does not match plugin manifest",
            ))
        }
    }

    /// Returns a handshake description corresponding to this manifest.
    pub(crate) fn handshake_info(&self) -> crate::protocol::HandshakeInfo {
        crate::protocol::HandshakeInfo {
            plugin_id: self.id.clone(),
            plugin_version: self.version.clone(),
            protocol: self.protocol,
            profiles: self.profiles.clone(),
            capabilities: self.capabilities.clone(),
            preservation: self.preservation.clone(),
        }
    }
}

impl fmt::Debug for PluginManifest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginManifest")
            .field("schema_version", &self.schema_version)
            .field("id", &self.id)
            .field("version", &self.version)
            .field("executable", &self.executable)
            .field("protocol", &self.protocol)
            .field("profiles", &self.profiles)
            .field("capability_count", &self.capabilities.iter().count())
            .field("limits", &self.limits)
            .field("preservation", &self.preservation)
            .field("identity_present", &self.identity.is_some())
            .field("extension_count", &self.extensions.len())
            .finish()
    }
}

/// Lossless metadata passed to an element/function worker.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct JmxElementMetadata {
    /// Exact upstream `testclass` value.
    pub test_class: String,
    /// Exact upstream `guiclass` value, when present.
    #[serde(default)]
    pub gui_class: Option<String>,
    /// Element name, when present.
    #[serde(default)]
    pub name: Option<String>,
    /// Typed/known properties represented without dropping unknown keys.
    #[serde(default)]
    pub properties: JmxProperties,
    /// Unknown property bytes retained for round-trip purposes.
    #[serde(default)]
    pub unknown_properties: Vec<UnknownJmxProperty>,
    /// Original raw subtree, if the parser captured one.
    #[serde(default)]
    pub raw_subtree: Option<Vec<u8>>,
    /// Future metadata retained without interpretation.
    #[serde(flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl JmxElementMetadata {
    /// Creates metadata for an unknown element while retaining its raw subtree.
    pub fn unknown(test_class: impl Into<String>, raw_subtree: Vec<u8>) -> Self {
        Self {
            test_class: test_class.into(),
            gui_class: None,
            name: None,
            properties: JmxProperties::new(),
            unknown_properties: Vec::new(),
            raw_subtree: Some(raw_subtree),
            extensions: BTreeMap::new(),
        }
    }

    /// Returns whether this request contains arbitrary metadata that requires
    /// an all-fields preservation contract.  The host does not maintain a
    /// semantic registry for plugin-defined property keys, so every property
    /// map entry, opaque property, raw subtree, or extension is treated as
    /// preservation-sensitive.
    pub(crate) fn requires_preservation(&self) -> bool {
        !self.properties.is_empty()
            || !self.unknown_properties.is_empty()
            || self.raw_subtree.is_some()
            || !self.extensions.is_empty()
    }

    /// Validates the minimum metadata needed to avoid confusing invalid JMX
    /// with a missing plugin.
    pub fn validate(&self) -> Result<(), PluginError> {
        if self.test_class.trim().is_empty()
            || self.test_class.len() > MAX_JMX_METADATA_TEXT_LEN
            || self.test_class.contains('\0')
        {
            return Err(PluginError::new(
                PluginErrorCode::InvalidJmx,
                format!(
                    "JMX testclass must contain 1..={MAX_JMX_METADATA_TEXT_LEN} bytes and no NUL"
                ),
            ));
        }
        for (label, value) in [
            ("JMX guiclass", self.gui_class.as_deref()),
            ("JMX testname", self.name.as_deref()),
        ] {
            if let Some(value) = value
                && (value.len() > MAX_JMX_METADATA_TEXT_LEN || value.contains('\0'))
            {
                return Err(PluginError::new(
                    PluginErrorCode::InvalidJmx,
                    format!(
                        "{label} must not exceed {MAX_JMX_METADATA_TEXT_LEN} bytes or contain NUL"
                    ),
                ));
            }
        }
        if let Some(raw) = &self.raw_subtree
            && raw.is_empty()
        {
            return Err(PluginError::new(
                PluginErrorCode::InvalidJmx,
                "JMX raw subtree must not be empty when present",
            ));
        }
        if let Some(raw) = &self.raw_subtree
            && raw.len() > MAX_RAW_JMX_SUBTREE_BYTES
        {
            return Err(PluginError::new(
                PluginErrorCode::InvalidJmx,
                format!("JMX raw subtree exceeds {MAX_RAW_JMX_SUBTREE_BYTES} bytes"),
            ));
        }
        let property_count = self
            .properties
            .len()
            .saturating_add(self.unknown_properties.len());
        if property_count > MAX_JMX_PROPERTIES {
            return Err(PluginError::new(
                PluginErrorCode::InvalidJmx,
                format!("JMX property count exceeds {MAX_JMX_PROPERTIES}"),
            ));
        }
        if self.extensions.len() > MAX_JMX_EXTENSIONS {
            return Err(PluginError::new(
                PluginErrorCode::InvalidJmx,
                format!("JMX extension count exceeds {MAX_JMX_EXTENSIONS}"),
            ));
        }
        for name in self.extensions.keys() {
            if name.is_empty() || name.len() > MAX_EXTENSION_KEY_BYTES || name.contains('\0') {
                return Err(PluginError::new(
                    PluginErrorCode::InvalidJmx,
                    format!(
                        "JMX extension field names must contain 1..={MAX_EXTENSION_KEY_BYTES} bytes and no NUL"
                    ),
                ));
            }
        }

        // The typed property map and opaque-property vector each retain their
        // own order, but their relative wire order cannot be reconstructed
        // from two separate fields.  Flattened extension fields have the same
        // issue (and a BTreeMap also sorts multiple extension keys).  A raw
        // subtree is the only representation currently carrying that unified
        // source order, so reject an ambiguous mixed representation instead
        // of silently normalizing it.
        let property_kinds = usize::from(!self.properties.is_empty())
            .saturating_add(usize::from(!self.unknown_properties.is_empty()))
            .saturating_add(usize::from(!self.extensions.is_empty()));
        let extension_order_is_ambiguous = self.extensions.len() > 1;
        if (property_kinds > 1 || extension_order_is_ambiguous) && self.raw_subtree.is_none() {
            return Err(PluginError::new(
                PluginErrorCode::InvalidJmx,
                "mixed JMX metadata requires a raw subtree to preserve wire order",
            ));
        }

        let mut property_names = std::collections::BTreeSet::new();
        for (name, _) in self.properties.iter() {
            validate_opaque_jmx_property_name(name)?;
            if !property_names.insert(name) {
                return Err(PluginError::new(
                    PluginErrorCode::InvalidJmx,
                    "duplicate JMX property name",
                ));
            }
        }
        for property in &self.unknown_properties {
            validate_opaque_jmx_property_name(&property.name)?;
            if property.raw_value.len() > MAX_UNKNOWN_JMX_PROPERTY_BYTES {
                return Err(PluginError::new(
                    PluginErrorCode::InvalidJmx,
                    format!(
                        "opaque JMX property {} exceeds {MAX_UNKNOWN_JMX_PROPERTY_BYTES} bytes",
                        property.name
                    ),
                ));
            }
            if !property_names.insert(property.name.as_str()) {
                return Err(PluginError::new(
                    PluginErrorCode::InvalidJmx,
                    "duplicate JMX property name",
                ));
            }
        }
        let opaque_property_bytes = self
            .unknown_properties
            .iter()
            .map(|property| property.raw_value.len())
            .fold(0_usize, usize::saturating_add);
        let opaque_bytes =
            opaque_property_bytes.saturating_add(self.raw_subtree.as_ref().map_or(0, Vec::len));
        if opaque_bytes > MAX_RAW_JMX_SUBTREE_BYTES {
            return Err(PluginError::new(
                PluginErrorCode::InvalidJmx,
                format!("combined opaque JMX bytes exceed {MAX_RAW_JMX_SUBTREE_BYTES}"),
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for JmxElementMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JmxElementMetadata")
            .field("test_class", &self.test_class)
            .field("gui_class_present", &self.gui_class.is_some())
            .field("name_present", &self.name.is_some())
            .field("property_count", &self.properties.len())
            .field("unknown_property_count", &self.unknown_properties.len())
            .field("raw_subtree_len", &self.raw_subtree.as_ref().map(Vec::len))
            .field("extension_count", &self.extensions.len())
            .finish()
    }
}

/// An unknown JMX property retained as opaque bytes.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnknownJmxProperty {
    /// Original property name.
    pub name: String,
    /// Original encoded value.
    pub raw_value: Vec<u8>,
}

impl fmt::Debug for UnknownJmxProperty {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UnknownJmxProperty")
            .field("name", &self.name)
            .field("raw_value_len", &self.raw_value.len())
            .finish()
    }
}

/// A bounded operation sent to a plugin worker.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PluginRequest {
    /// Element/function to execute.
    pub capability: CapabilityReference,
    /// Exact JMX metadata, including unknown/raw fields.
    pub jmx: JmxElementMetadata,
    /// Capability-specific input bytes.
    #[serde(default)]
    pub input: Vec<u8>,
    /// Future request metadata retained by the host.
    #[serde(flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl PluginRequest {
    /// Validates request metadata before a process is started.
    pub fn validate(&self) -> Result<(), PluginError> {
        self.capability.validate()?;
        self.jmx.validate()?;
        validate_extension_map(
            &self.extensions,
            MAX_MANIFEST_EXTENSIONS,
            "request extensions",
        )
    }

    /// Validates the complete request shape and counts its JSON encoding
    /// against the worker message budget without allocating the encoded
    /// payload.  This preflight covers input bytes, raw JMX fields, and
    /// forward-compatible extension values as one aggregate bound.
    pub fn validate_for_message_limit(&self, maximum: usize) -> Result<(), PluginError> {
        self.validate()?;
        if maximum == 0 || maximum > HARD_MAX_MESSAGE_BYTES {
            return Err(PluginError::new(
                PluginErrorCode::WorkerMessageLimit,
                "request message budget is outside the supported range",
            ));
        }
        let mut writer = BudgetWriter {
            written: 0,
            maximum,
            exceeded: false,
        };
        match serde_json::to_writer(&mut writer, self) {
            Ok(()) => Ok(()),
            Err(_error) if writer.exceeded => Err(PluginError::new(
                PluginErrorCode::WorkerMessageLimit,
                format!("plugin request exceeds {maximum} encoded bytes"),
            )),
            Err(error) => Err(PluginError::new(
                PluginErrorCode::InvalidJmx,
                format!("could not encode plugin request: {error}"),
            )),
        }
    }
}

impl fmt::Debug for PluginRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginRequest")
            .field("capability", &self.capability)
            .field("jmx", &self.jmx)
            .field("input_len", &self.input.len())
            .field("extension_count", &self.extensions.len())
            .finish()
    }
}

struct BudgetWriter {
    written: usize,
    maximum: usize,
    exceeded: bool,
}

impl std::io::Write for BudgetWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let next = self.written.saturating_add(bytes.len());
        if next > self.maximum {
            self.exceeded = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "JSON request budget exceeded",
            ));
        }
        self.written = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A successful bounded plugin response.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginResponse {
    /// Capability-specific output bytes.
    #[serde(default)]
    pub output: Vec<u8>,
    /// Optional metadata returned without interpretation.
    #[serde(default)]
    pub metadata: BTreeMap<String, Value>,
}

impl fmt::Debug for PluginResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginResponse")
            .field("output_len", &self.output.len())
            .field("metadata_count", &self.metadata.len())
            .finish()
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "request-boundary tests use explicit deterministic values"
)]
mod tests {
    use super::*;

    fn request_with_raw_data() -> PluginRequest {
        let mut extensions = BTreeMap::new();
        extensions.insert(
            "secret_extension".to_owned(),
            Value::String("secret".to_owned()),
        );
        PluginRequest {
            capability: CapabilityReference::new(CapabilityKind::Element, "example.element"),
            jmx: JmxElementMetadata {
                test_class: "example.Element".to_owned(),
                gui_class: None,
                name: None,
                properties: JmxProperties::from_iter([(
                    "secret_property".to_owned(),
                    Value::String("secret-value".to_owned()),
                )]),
                unknown_properties: vec![UnknownJmxProperty {
                    name: "secret.raw".to_owned(),
                    raw_value: b"do-not-log".to_vec(),
                }],
                raw_subtree: Some(b"<secret>payload</secret>".to_vec()),
                extensions: BTreeMap::new(),
            },
            input: b"secret-input".to_vec(),
            extensions,
        }
    }

    #[test]
    fn request_debug_redacts_raw_values_and_input() {
        let debug = format!("{:?}", request_with_raw_data());
        assert!(debug.contains("input_len"));
        assert!(debug.contains("raw_subtree_len"));
        assert!(!debug.contains("secret-input"));
        assert!(!debug.contains("do-not-log"));
        assert!(!debug.contains("<secret>payload</secret>"));
        assert!(!debug.contains("secret-value"));
    }

    #[test]
    fn request_preflight_counts_all_encoded_fields_before_allocation() {
        let request = request_with_raw_data();
        let error = request
            .validate_for_message_limit(32)
            .expect_err("aggregate request must exceed the tiny budget");
        assert_eq!(error.code(), PluginErrorCode::WorkerMessageLimit);
        request
            .validate_for_message_limit(1024)
            .expect("request fits the larger deterministic budget");
    }

    #[test]
    fn opaque_jmx_property_names_use_their_own_bounded_validation() {
        let mut metadata = JmxElementMetadata {
            test_class: "example.Element".to_owned(),
            gui_class: None,
            name: None,
            properties: JmxProperties::new(),
            unknown_properties: vec![UnknownJmxProperty {
                name: "property name/with punctuation=and unicode-✓".to_owned(),
                raw_value: vec![1, 2, 3],
            }],
            raw_subtree: None,
            extensions: BTreeMap::new(),
        };
        metadata
            .validate()
            .expect("opaque property names are not capability identifiers");

        metadata.raw_subtree = Some(b"<element/>".to_vec());
        metadata.properties.insert(
            "property key with spaces/✓".to_owned(),
            Value::String("value".to_owned()),
        );
        metadata
            .validate()
            .expect("arbitrary property map keys use opaque-name validation");
        metadata.properties.clear();

        metadata.unknown_properties[0].name = "x".repeat(MAX_JMX_PROPERTY_NAME_LEN + 1);
        assert_eq!(
            metadata
                .validate()
                .expect_err("oversized opaque property name")
                .code(),
            PluginErrorCode::InvalidJmx
        );

        metadata.unknown_properties[0].name =
            "property name/with punctuation=and unicode-✓".to_owned();
        metadata
            .properties
            .insert("x".repeat(MAX_JMX_PROPERTY_NAME_LEN + 1), Value::Null);
        assert_eq!(
            metadata
                .validate()
                .expect_err("oversized property map key")
                .code(),
            PluginErrorCode::InvalidJmx
        );
        metadata.properties.clear();

        metadata.unknown_properties[0].name = "property\0name".to_owned();
        assert_eq!(
            metadata
                .validate()
                .expect_err("NUL in opaque property name")
                .code(),
            PluginErrorCode::InvalidJmx
        );
    }

    #[test]
    fn every_arbitrary_jmx_metadata_field_requires_preservation() {
        let mut metadata = JmxElementMetadata {
            test_class: "example.Element".to_owned(),
            gui_class: None,
            name: None,
            properties: JmxProperties::new(),
            unknown_properties: Vec::new(),
            raw_subtree: None,
            extensions: BTreeMap::new(),
        };
        assert!(!metadata.requires_preservation());

        metadata
            .properties
            .insert("arbitrary".to_owned(), Value::String("value".to_owned()));
        assert!(metadata.requires_preservation());
        metadata.properties.clear();
        metadata
            .extensions
            .insert("future".to_owned(), Value::Bool(true));
        assert!(metadata.requires_preservation());
    }

    #[test]
    fn mixed_jmx_metadata_requires_raw_subtree_for_cross_kind_order() {
        let mut metadata = JmxElementMetadata {
            test_class: "example.Element".to_owned(),
            gui_class: None,
            name: None,
            properties: JmxProperties::new(),
            unknown_properties: vec![UnknownJmxProperty {
                name: "opaque".to_owned(),
                raw_value: vec![1],
            }],
            raw_subtree: None,
            extensions: BTreeMap::new(),
        };
        metadata
            .properties
            .insert("typed".to_owned(), Value::String("value".to_owned()));
        assert_eq!(
            metadata
                .validate()
                .expect_err("separate property categories cannot retain cross-kind order")
                .code(),
            PluginErrorCode::InvalidJmx
        );

        metadata.raw_subtree = Some(b"<element/>".to_vec());
        metadata
            .validate()
            .expect("raw subtree carries the unified source ordering");
    }

    #[test]
    fn duplicate_jmx_property_names_are_rejected_across_categories() {
        let mut metadata = JmxElementMetadata::unknown("example.Element", b"<element/>".to_vec());
        metadata
            .properties
            .insert("duplicate".to_owned(), Value::Null);
        metadata.unknown_properties.push(UnknownJmxProperty {
            name: "duplicate".to_owned(),
            raw_value: vec![1],
        });
        assert_eq!(
            metadata
                .validate()
                .expect_err("duplicate property names are ambiguous")
                .code(),
            PluginErrorCode::InvalidJmx
        );
    }

    #[test]
    fn duplicate_capability_names_are_rejected_within_each_namespace() {
        let declarations = CapabilityDeclarations {
            elements: vec![
                CapabilityDeclaration::new("example.element"),
                CapabilityDeclaration {
                    id: "example.other".to_owned(),
                    aliases: vec!["example.element".to_owned()],
                    extensions: BTreeMap::new(),
                },
            ],
            functions: vec![CapabilityDeclaration::new("example.element")],
        };
        assert_eq!(
            declarations
                .validate()
                .expect_err("same-kind capability alias collision must fail")
                .code(),
            PluginErrorCode::ManifestInvalid
        );

        let separate_namespaces = CapabilityDeclarations {
            elements: vec![CapabilityDeclaration::new("example.shared")],
            functions: vec![CapabilityDeclaration::new("example.shared")],
        };
        separate_namespaces
            .validate()
            .expect("element and function capability namespaces are distinct");
    }

    fn valid_artifact() -> PluginArtifact {
        PluginArtifact {
            sha256: Sha256Digest::from_bytes([1; 32]),
            byte_length: 7,
            version: "1.2.3".to_owned(),
            provenance: "fixture-source".to_owned(),
            license: "Apache-2.0".to_owned(),
            notice: "NOTICE.fixture".to_owned(),
            license_notice: LicenseNoticeStatus::Verified,
            dependencies: Vec::new(),
            extensions: BTreeMap::new(),
        }
    }

    fn valid_manifest() -> PluginManifest {
        let mut manifest = PluginManifest::new(
            PluginId::parse("example.plugin").expect("plugin ID"),
            PluginVersion::parse("1.2.3").expect("plugin version"),
            "/opt/example-plugin",
        );
        manifest.profiles = vec!["jmeter-5.6.3".to_owned()];
        manifest.identity = Some(valid_artifact());
        manifest
    }

    #[test]
    fn digest_is_canonical_and_redacted_in_debug() {
        let digest = Sha256Digest::from_hex(
            "AABBCCDDEEFF00112233445566778899aabbccddeeff00112233445566778899",
        )
        .expect("hex digest");
        assert_eq!(
            digest.to_hex(),
            "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
        );
        assert_eq!(digest.as_bytes()[0], 0xaa);
        assert!(format!("{digest:?}").contains("redacted"));
        let encoded = serde_json::to_string(&digest).expect("digest JSON");
        assert_eq!(encoded, format!("\"{}\"", digest.to_hex()));
        let decoded: Sha256Digest = serde_json::from_str(&encoded).expect("digest JSON decode");
        assert_eq!(decoded, digest);
        assert!(Sha256Digest::from_hex("00").is_err());
    }

    #[test]
    fn artifact_identity_requires_hash_size_and_provenance() {
        valid_artifact()
            .validate()
            .expect("valid artifact identity");

        let mut artifact = valid_artifact();
        artifact.sha256 = Sha256Digest::ZERO;
        assert_eq!(
            artifact
                .validate()
                .expect_err("zero digest must fail")
                .code(),
            PluginErrorCode::ManifestInvalid
        );

        let mut artifact = valid_artifact();
        artifact.byte_length = 0;
        assert_eq!(
            artifact
                .validate()
                .expect_err("zero byte length must fail")
                .code(),
            PluginErrorCode::ManifestInvalid
        );

        let mut artifact = valid_artifact();
        artifact.license.clear();
        assert_eq!(
            artifact
                .validate()
                .expect_err("verified artifact needs license text")
                .code(),
            PluginErrorCode::ManifestInvalid
        );

        let mut manifest = valid_manifest();
        manifest.identity.as_mut().expect("identity").license_notice = LicenseNoticeStatus::Missing;
        assert_eq!(
            manifest
                .validate()
                .expect_err("admission rejects missing provenance")
                .code(),
            PluginErrorCode::ManifestInvalid
        );
    }

    #[test]
    fn dependency_identity_preserves_order_but_rejects_duplicates() {
        let dependency = PluginDependency {
            name: "dep-a".to_owned(),
            version: "1.0.0".to_owned(),
            sha256: Sha256Digest::from_bytes([2; 32]),
            license: "Apache-2.0".to_owned(),
            notice: "NOTICE.dep-a".to_owned(),
            classpath_order: 3,
            extensions: BTreeMap::new(),
        };
        let mut artifact = valid_artifact();
        artifact.dependencies = vec![
            dependency.clone(),
            PluginDependency {
                name: "dep-b".to_owned(),
                classpath_order: 4,
                ..dependency
            },
        ];
        artifact.validate().expect("ordered dependencies");

        artifact.dependencies[1].classpath_order = 3;
        assert_eq!(
            artifact
                .validate()
                .expect_err("duplicate classpath order")
                .code(),
            PluginErrorCode::ManifestInvalid
        );
        artifact.dependencies[1].classpath_order = 4;
        artifact.dependencies[1].name = "dep-a".to_owned();
        assert_eq!(
            artifact
                .validate()
                .expect_err("duplicate dependency name")
                .code(),
            PluginErrorCode::ManifestInvalid
        );
    }

    #[test]
    fn manifest_identity_hash_covers_ordered_contract_and_aliases() {
        let mut manifest = valid_manifest();
        manifest.validate().expect("valid manifest");
        let first = manifest.manifest_sha256().expect("manifest digest");
        assert_eq!(first, manifest.manifest_sha256().expect("stable digest"));

        manifest.capabilities.elements.push(CapabilityDeclaration {
            id: "example.element".to_owned(),
            aliases: vec!["HistoricalElement".to_owned()],
            extensions: BTreeMap::new(),
        });
        let second = manifest.manifest_sha256().expect("changed manifest digest");
        assert_ne!(first, second);
        assert!(
            manifest
                .validate_executable_identity(7, Sha256Digest::from_bytes([1; 32]))
                .is_ok()
        );
        assert!(
            manifest
                .validate_executable_identity(8, Sha256Digest::from_bytes([1; 32]))
                .is_err()
        );
    }

    #[test]
    fn artifact_wire_alias_is_accepted_and_canonicalized() {
        let manifest = valid_manifest();
        let mut value = serde_json::to_value(&manifest).expect("manifest JSON");
        let object = value.as_object_mut().expect("manifest object");
        let identity = object.remove("identity").expect("identity field");
        object.insert("artifact".to_owned(), identity);
        let decoded: PluginManifest = serde_json::from_value(value).expect("artifact alias");
        assert_eq!(decoded.identity, manifest.identity);
        assert_eq!(
            serde_json::to_value(decoded).expect("canonical JSON")["identity"],
            serde_json::to_value(&manifest).expect("manifest JSON")["identity"]
        );
    }

    #[test]
    fn capability_reference_and_manifest_limits_fail_closed() {
        let invalid = CapabilityReference::new(CapabilityKind::Element, "bad name");
        assert_eq!(
            invalid
                .validate()
                .expect_err("invalid capability name")
                .code(),
            PluginErrorCode::InvalidJmx
        );

        assert!(PluginVersion::parse("1.2.3".to_owned()).is_ok());
        assert!(
            PluginVersion::parse("1.2.3".to_owned() + &"x".repeat(MAX_PLUGIN_VERSION_LEN)).is_err()
        );

        let mut metadata =
            JmxElementMetadata::unknown("example.Element", vec![0; MAX_RAW_JMX_SUBTREE_BYTES + 1]);
        assert_eq!(
            metadata.validate().expect_err("raw subtree limit").code(),
            PluginErrorCode::InvalidJmx
        );
        metadata.raw_subtree = Some(vec![1]);
        metadata.test_class = "x".repeat(MAX_JMX_METADATA_TEXT_LEN + 1);
        assert_eq!(
            metadata.validate().expect_err("class text limit").code(),
            PluginErrorCode::InvalidJmx
        );
    }
}
