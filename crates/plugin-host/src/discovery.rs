// SPDX-License-Identifier: Apache-2.0

use crate::{
    error::{PluginError, PluginErrorCode},
    manifest::{CapabilityKind, HARD_MAX_MESSAGE_BYTES, PluginManifest},
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, Read},
    path::{Path, PathBuf},
};

/// Default maximum manifest file size.
pub const DEFAULT_MAX_MANIFEST_BYTES: usize = 1024 * 1024;
/// Default maximum directory entries inspected during one scan.
pub const DEFAULT_MAX_DISCOVERY_ENTRIES: usize = 4096;
/// Default maximum encoded path bytes admitted during one scan.
pub const DEFAULT_MAX_DISCOVERY_PATH_BYTES: usize = 4096;
/// Default maximum total manifest bytes admitted during one scan.
pub const DEFAULT_MAX_DISCOVERY_MANIFEST_BYTES: usize = 16 * 1024 * 1024;
/// Default maximum validated descriptors admitted during one scan.
pub const DEFAULT_MAX_DISCOVERY_DESCRIPTORS: usize = 1024;
/// Default maximum declared capabilities admitted during one scan.
pub const DEFAULT_MAX_DISCOVERY_CAPABILITIES: usize = 16 * 1024;
/// Default maximum diagnostics retained during one scan.
pub const DEFAULT_MAX_DISCOVERY_DIAGNOSTICS: usize = 1024;
/// Default maximum aggregate encoded path bytes admitted during one scan.
pub const DEFAULT_MAX_DISCOVERY_PATH_TOTAL_BYTES: usize = 1024 * 1024;
/// Maximum executable bytes hashed when establishing launch identity.
///
/// This is a deterministic resource bound, not a wall-clock timeout.  It
/// applies both during discovery validation and immediately before launch.
pub const MAX_EXECUTABLE_IDENTITY_BYTES: usize = 256 * 1024 * 1024;
/// Maximum read operations used to hash one executable identity.
///
/// The operation count bounds pathological short-read behavior without
/// relying on scheduler timing or an arbitrary sleep.
pub const MAX_EXECUTABLE_IDENTITY_READS: usize = 8 * 1024;
/// Hard cap for one discovery's aggregate manifest input.
pub const HARD_MAX_DISCOVERY_MANIFEST_BYTES: usize = 256 * 1024 * 1024;
/// Hard cap for one discovery's aggregate path accounting.
pub const HARD_MAX_DISCOVERY_PATH_TOTAL_BYTES: usize = 16 * 1024 * 1024;
/// Hard cap for one discovery's retained diagnostics.
pub const HARD_MAX_DISCOVERY_DIAGNOSTICS: usize = 16 * 1024;

/// Explicit filesystem policy for plugin discovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryConfig {
    /// One operator-supplied directory containing manifest files.
    pub directory: PathBuf,
    /// Maximum bytes read from any one manifest.
    pub max_manifest_bytes: usize,
    /// Maximum bytes admitted across all manifests in one scan.
    pub max_total_manifest_bytes: usize,
    /// Maximum validated descriptors admitted in one scan.
    pub max_descriptors: usize,
    /// Maximum declared capability declarations admitted in one scan.
    pub max_capabilities: usize,
    /// Maximum diagnostics retained in one scan.
    pub max_diagnostics: usize,
    /// Maximum aggregate encoded path bytes accounted for in one scan.
    pub max_total_path_bytes: usize,
    /// Whether a manifest symlink is permitted after containment checking.
    pub allow_manifest_symlinks: bool,
    /// Whether an executable symlink is permitted after containment checking.
    pub allow_executable_symlinks: bool,
}

impl DiscoveryConfig {
    /// Creates a strict discovery policy for one directory.
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
            max_manifest_bytes: DEFAULT_MAX_MANIFEST_BYTES,
            max_total_manifest_bytes: DEFAULT_MAX_DISCOVERY_MANIFEST_BYTES,
            max_descriptors: DEFAULT_MAX_DISCOVERY_DESCRIPTORS,
            max_capabilities: DEFAULT_MAX_DISCOVERY_CAPABILITIES,
            max_diagnostics: DEFAULT_MAX_DISCOVERY_DIAGNOSTICS,
            max_total_path_bytes: DEFAULT_MAX_DISCOVERY_PATH_TOTAL_BYTES,
            allow_manifest_symlinks: false,
            allow_executable_symlinks: false,
        }
    }

    /// Sets the manifest input bound.
    pub fn with_max_manifest_bytes(mut self, maximum: usize) -> Self {
        self.max_manifest_bytes = maximum;
        self
    }

    /// Sets the aggregate manifest input bound.
    pub fn with_max_total_manifest_bytes(mut self, maximum: usize) -> Self {
        self.max_total_manifest_bytes = maximum;
        self
    }

    /// Sets the aggregate descriptor bound.
    pub fn with_max_descriptors(mut self, maximum: usize) -> Self {
        self.max_descriptors = maximum;
        self
    }

    /// Sets the aggregate capability declaration bound.
    pub fn with_max_capabilities(mut self, maximum: usize) -> Self {
        self.max_capabilities = maximum;
        self
    }

    /// Sets the retained diagnostic bound.
    pub fn with_max_diagnostics(mut self, maximum: usize) -> Self {
        self.max_diagnostics = maximum;
        self
    }

    /// Sets the aggregate encoded path-byte bound.
    pub fn with_max_total_path_bytes(mut self, maximum: usize) -> Self {
        self.max_total_path_bytes = maximum;
        self
    }

    /// Enables symlinked manifests only when their canonical target remains in
    /// the allowlisted directory.
    pub fn allow_manifest_symlinks(mut self, allow: bool) -> Self {
        self.allow_manifest_symlinks = allow;
        self
    }

    /// Enables symlinked executables only when their canonical target remains
    /// in the allowlisted directory.
    pub fn allow_executable_symlinks(mut self, allow: bool) -> Self {
        self.allow_executable_symlinks = allow;
        self
    }
}

/// A validated manifest together with its canonical source paths.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginDescriptor {
    /// Validated plugin manifest.
    pub manifest: PluginManifest,
    /// Canonical manifest path used for deterministic diagnostics.
    pub manifest_path: PathBuf,
    /// Canonical executable path.
    pub executable_path: PathBuf,
}

impl PluginDescriptor {
    /// Checks that the public descriptor fields still describe one discovered
    /// executable.  Discovery canonicalizes both values before construction,
    /// but callers can construct this public struct directly; supervisors and
    /// registries must not trust a forged manifest/path pairing.
    pub fn validate_integrity(&self) -> Result<(), PluginError> {
        self.manifest.validate()?;
        if !self.manifest_path.is_absolute() || !self.executable_path.is_absolute() {
            return Err(PluginError::new(
                PluginErrorCode::PathOutsideRoot,
                "plugin descriptor paths must be absolute",
            ));
        }
        if self.manifest.executable != self.executable_path {
            return Err(PluginError::new(
                PluginErrorCode::ManifestInvalid,
                "plugin descriptor executable does not match its manifest",
            ));
        }
        let canonical_manifest = fs::canonicalize(&self.manifest_path).map_err(|error| {
            PluginError::new(
                PluginErrorCode::ManifestIo,
                format!("cannot canonicalize plugin descriptor manifest: {error}"),
            )
        })?;
        if canonical_manifest != self.manifest_path {
            return Err(PluginError::new(
                PluginErrorCode::PathOutsideRoot,
                "plugin descriptor manifest path is not canonical",
            ));
        }
        let canonical_executable = fs::canonicalize(&self.executable_path).map_err(|error| {
            PluginError::new(
                PluginErrorCode::ExecutableChanged,
                format!("cannot canonicalize plugin descriptor executable: {error}"),
            )
        })?;
        if canonical_executable != self.executable_path {
            return Err(PluginError::new(
                PluginErrorCode::ExecutableChanged,
                "plugin descriptor executable path is not canonical",
            ));
        }
        let bytes = read_bounded(&self.manifest_path, HARD_MAX_MESSAGE_BYTES)?;
        crate::protocol::preflight_json(&bytes, HARD_MAX_MESSAGE_BYTES).map_err(|error| {
            let code = if error.code() == PluginErrorCode::WorkerMessageLimit {
                PluginErrorCode::ManifestTooLarge
            } else {
                PluginErrorCode::ManifestParse
            };
            PluginError::new(
                code,
                "plugin descriptor manifest failed bounded JSON preflight",
            )
            .with_detail_suffix(error.code().as_str())
        })?;
        let mut on_disk: PluginManifest = serde_json::from_slice(&bytes).map_err(|error| {
            PluginError::new(
                PluginErrorCode::ManifestParse,
                format!("invalid plugin descriptor manifest JSON: {error}"),
            )
        })?;
        // Validate the wire representation before canonicalizing its path.
        // Otherwise a relative executable could be rewritten into an
        // absolute path and accidentally bypass the manifest's absolute-path
        // invariant during descriptor pairing.
        on_disk.validate()?;
        on_disk.executable = fs::canonicalize(&on_disk.executable).map_err(|error| {
            PluginError::new(
                PluginErrorCode::ExecutableChanged,
                format!("cannot canonicalize manifest executable: {error}"),
            )
        })?;
        if on_disk != self.manifest {
            return Err(PluginError::new(
                PluginErrorCode::ManifestInvalid,
                "plugin descriptor manifest changed after discovery",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExecutableIdentity {
    length: u64,
    content_digest: [u8; 32],
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(not(unix))]
    modified: Option<std::time::SystemTime>,
}

impl ExecutableIdentity {
    fn from_metadata(metadata: &fs::Metadata, content_digest: [u8; 32]) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Self {
                length: metadata.len(),
                content_digest,
                device: metadata.dev(),
                inode: metadata.ino(),
            }
        }
        #[cfg(not(unix))]
        {
            Self {
                length: metadata.len(),
                content_digest,
                modified: metadata.modified().ok(),
            }
        }
    }

    fn same_filesystem_object(&self, other: &Self) -> bool {
        self.length == other.length && {
            #[cfg(unix)]
            {
                self.device == other.device && self.inode == other.inode
            }
            #[cfg(not(unix))]
            {
                self.modified == other.modified
            }
        }
    }
}

/// Results of a non-failing discovery scan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryReport {
    /// Valid descriptors, in manifest filename order.
    pub plugins: Vec<PluginDescriptor>,
    /// Stable diagnostics for entries that could not be admitted.
    pub diagnostics: Vec<PluginError>,
    diagnostic_budget: usize,
    diagnostics_truncated: bool,
}

impl Default for DiscoveryReport {
    fn default() -> Self {
        Self {
            plugins: Vec::new(),
            diagnostics: Vec::new(),
            diagnostic_budget: DEFAULT_MAX_DISCOVERY_DIAGNOSTICS,
            diagnostics_truncated: false,
        }
    }
}

impl DiscoveryReport {
    fn with_diagnostic_budget(maximum: usize) -> Self {
        Self {
            diagnostic_budget: maximum.max(1),
            ..Self::default()
        }
    }

    fn push_diagnostic(&mut self, error: PluginError) {
        if self.diagnostics.len() < self.diagnostic_budget {
            self.diagnostics.push(error);
        } else if !self.diagnostics_truncated {
            // Keep the overflow outcome explicit while retaining a hard bound
            // on diagnostic allocations.
            let limit = PluginError::new(
                PluginErrorCode::DiscoveryDiagnosticLimit,
                format!(
                    "plugin discovery exceeded the {} diagnostic budget",
                    self.diagnostic_budget
                ),
            );
            if let Some(last) = self.diagnostics.last_mut() {
                *last = limit;
            }
            self.diagnostics_truncated = true;
        }
    }

    /// Returns whether every inspected manifest was valid and conflict-free.
    pub fn is_clean(&self) -> bool {
        self.diagnostics.is_empty()
    }

    /// Converts a clean scan to a registry, retaining the first deterministic
    /// diagnostic when the scan was not clean.
    pub fn into_registry(self) -> Result<PluginRegistry, PluginError> {
        if let Some(error) = self.diagnostics.into_iter().next() {
            return Err(error);
        }
        PluginRegistry::from_descriptors(self.plugins)
    }
}

/// Deterministically ordered plugin descriptors and capability indexes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginRegistry {
    descriptors: Vec<PluginDescriptor>,
    ids: BTreeMap<String, usize>,
    capabilities: BTreeMap<(CapabilityKind, String), usize>,
}

impl PluginRegistry {
    /// Scans the explicitly supplied directory and fails closed on any
    /// malformed entry or duplicate.
    pub fn discover(config: &DiscoveryConfig) -> Result<Self, PluginError> {
        scan(config).into_registry()
    }

    /// Performs a diagnostic-producing scan without discarding valid entries.
    pub fn scan(config: &DiscoveryConfig) -> DiscoveryReport {
        scan(config)
    }

    fn from_descriptors(descriptors: Vec<PluginDescriptor>) -> Result<Self, PluginError> {
        let mut ids = BTreeMap::new();
        let mut capabilities = BTreeMap::new();
        for (index, descriptor) in descriptors.iter().enumerate() {
            descriptor.validate_integrity()?;
            let id = descriptor.manifest.id.as_str().to_owned();
            if ids.insert(id.clone(), index).is_some() {
                return Err(PluginError::new(
                    PluginErrorCode::DuplicatePluginId,
                    format!("duplicate plugin ID {id}"),
                ));
            }
            for (kind, declaration) in descriptor.manifest.capabilities.iter() {
                for name in std::iter::once(declaration.id.as_str())
                    .chain(declaration.aliases.iter().map(String::as_str))
                {
                    let key = (kind, name.to_owned());
                    if capabilities.insert(key, index).is_some() {
                        return Err(PluginError::new(
                            PluginErrorCode::DuplicateCapabilityAlias,
                            format!("duplicate {kind:?} capability name {name}"),
                        ));
                    }
                }
            }
        }
        Ok(Self {
            descriptors,
            ids,
            capabilities,
        })
    }

    /// Returns descriptors in deterministic manifest order.
    pub fn plugins(&self) -> &[PluginDescriptor] {
        &self.descriptors
    }

    /// Looks up a plugin by stable ID.
    pub fn by_id(&self, id: &str) -> Option<&PluginDescriptor> {
        self.ids
            .get(id)
            .and_then(|index| self.descriptors.get(*index))
    }

    /// Resolves a capability name to its owning plugin descriptor.
    pub fn by_capability(
        &self,
        kind: CapabilityKind,
        name: &str,
    ) -> Option<(&PluginDescriptor, &crate::manifest::CapabilityDeclaration)> {
        let index = self.capabilities.get(&(kind, name.to_owned()))?;
        let descriptor = self.descriptors.get(*index)?;
        let declaration = descriptor.manifest.capabilities.find(kind, name)?;
        Some((descriptor, declaration))
    }

    /// Resolves and checks a capability for a compatibility profile/protocol.
    pub fn negotiate(
        &self,
        profile: &str,
        protocol_version: u16,
        reference: &crate::manifest::CapabilityReference,
    ) -> Result<crate::NegotiatedCapability<'_>, PluginError> {
        let Some((descriptor, declaration)) = self.by_capability(reference.kind, &reference.name)
        else {
            return Err(PluginError::new(
                PluginErrorCode::CapabilityMismatch,
                format!(
                    "no plugin declares {} capability {}",
                    reference.kind.as_str(),
                    reference.name
                ),
            ));
        };
        if !descriptor.manifest.protocol.supports(protocol_version) {
            return Err(PluginError::new(
                PluginErrorCode::ProtocolMismatch,
                format!(
                    "plugin {} does not support protocol {protocol_version}",
                    descriptor.manifest.id
                ),
            ));
        }
        if !descriptor.manifest.supports_profile(profile) {
            return Err(PluginError::new(
                PluginErrorCode::ProfileMismatch,
                format!(
                    "plugin {} does not support profile {profile}",
                    descriptor.manifest.id
                ),
            ));
        }
        Ok(crate::NegotiatedCapability {
            plugin: descriptor,
            declaration,
            canonical_name: declaration.id.clone(),
        })
    }
}

#[derive(Default)]
struct DiscoveryAccounting {
    manifest_bytes: usize,
    descriptors: usize,
    capabilities: usize,
    path_bytes: usize,
}

impl DiscoveryAccounting {
    fn reserve_path(&mut self, path: &Path, maximum: usize) -> bool {
        let length = path_bytes(path);
        let Some(total) = self.path_bytes.checked_add(length) else {
            return false;
        };
        if total > maximum {
            return false;
        }
        self.path_bytes = total;
        true
    }
}

fn validate_discovery_config(config: &DiscoveryConfig) -> Result<(), PluginError> {
    if config.max_manifest_bytes == 0 || config.max_manifest_bytes > HARD_MAX_MESSAGE_BYTES {
        return Err(PluginError::new(
            PluginErrorCode::ManifestInvalid,
            format!("manifest byte limit must be between 1 and {HARD_MAX_MESSAGE_BYTES}"),
        ));
    }
    if config.max_total_manifest_bytes == 0
        || config.max_total_manifest_bytes > HARD_MAX_DISCOVERY_MANIFEST_BYTES
    {
        return Err(PluginError::new(
            PluginErrorCode::DiscoveryManifestBytesLimit,
            format!(
                "total manifest byte limit must be between 1 and {HARD_MAX_DISCOVERY_MANIFEST_BYTES}"
            ),
        ));
    }
    if config.max_descriptors == 0 || config.max_descriptors > DEFAULT_MAX_DISCOVERY_ENTRIES {
        return Err(PluginError::new(
            PluginErrorCode::DiscoveryDescriptorLimit,
            format!("descriptor limit must be between 1 and {DEFAULT_MAX_DISCOVERY_ENTRIES}"),
        ));
    }
    if config.max_capabilities == 0 || config.max_capabilities > 1_048_576 {
        return Err(PluginError::new(
            PluginErrorCode::DiscoveryCapabilityLimit,
            "capability limit must be between 1 and 1048576",
        ));
    }
    if config.max_diagnostics == 0 || config.max_diagnostics > HARD_MAX_DISCOVERY_DIAGNOSTICS {
        return Err(PluginError::new(
            PluginErrorCode::DiscoveryDiagnosticLimit,
            format!("diagnostic limit must be between 1 and {HARD_MAX_DISCOVERY_DIAGNOSTICS}"),
        ));
    }
    if config.max_total_path_bytes == 0
        || config.max_total_path_bytes > HARD_MAX_DISCOVERY_PATH_TOTAL_BYTES
    {
        return Err(PluginError::new(
            PluginErrorCode::DiscoveryPathLimit,
            format!(
                "total path byte limit must be between 1 and {HARD_MAX_DISCOVERY_PATH_TOTAL_BYTES}"
            ),
        ));
    }
    Ok(())
}

fn scan(config: &DiscoveryConfig) -> DiscoveryReport {
    let mut report = DiscoveryReport::with_diagnostic_budget(config.max_diagnostics);
    if let Err(error) = validate_discovery_config(config) {
        report.push_diagnostic(error);
        return report;
    }
    let mut accounting = DiscoveryAccounting::default();
    if !config.directory.is_absolute() {
        report.push_diagnostic(PluginError::new(
            PluginErrorCode::DiscoveryDirectory,
            "plugin discovery directory must be absolute",
        ));
        return report;
    }
    if path_bytes(&config.directory) > DEFAULT_MAX_DISCOVERY_PATH_BYTES
        || !accounting.reserve_path(&config.directory, config.max_total_path_bytes)
    {
        report.push_diagnostic(PluginError::new(
            PluginErrorCode::DiscoveryPathLimit,
            format!(
                "plugin discovery directory exceeds the {DEFAULT_MAX_DISCOVERY_PATH_BYTES}-byte path budget"
            ),
        ));
        return report;
    }

    let root = match fs::canonicalize(&config.directory) {
        Ok(root) if root.is_dir() => root,
        Ok(_) => {
            report.push_diagnostic(
                PluginError::new(
                    PluginErrorCode::DiscoveryDirectory,
                    "plugin discovery path is not a directory",
                )
                .with_path(&config.directory),
            );
            return report;
        }
        Err(error) => {
            report.push_diagnostic(
                PluginError::new(
                    PluginErrorCode::DiscoveryDirectory,
                    format!("cannot canonicalize plugin discovery directory: {error}"),
                )
                .with_path(&config.directory),
            );
            return report;
        }
    };
    if path_bytes(&root) > DEFAULT_MAX_DISCOVERY_PATH_BYTES
        || !accounting.reserve_path(&root, config.max_total_path_bytes)
    {
        report.push_diagnostic(
            PluginError::new(
                PluginErrorCode::DiscoveryPathLimit,
                format!(
                    "canonical plugin discovery directory exceeds the {DEFAULT_MAX_DISCOVERY_PATH_BYTES}-byte path budget"
                ),
            )
            .with_path(root),
        );
        return report;
    }

    let mut entries = Vec::new();
    let mut inspected_entries = 0usize;
    match fs::read_dir(&root) {
        Ok(read_dir) => {
            for entry in read_dir {
                if inspected_entries >= DEFAULT_MAX_DISCOVERY_ENTRIES {
                    report.push_diagnostic(PluginError::new(
                        PluginErrorCode::DiscoveryEntryLimit,
                        format!(
                            "plugin discovery exceeded the {} entry budget",
                            DEFAULT_MAX_DISCOVERY_ENTRIES
                        ),
                    ));
                    break;
                }
                inspected_entries = inspected_entries.saturating_add(1);
                match entry {
                    Ok(entry) => {
                        let path = entry.path();
                        if path_bytes(&path) > DEFAULT_MAX_DISCOVERY_PATH_BYTES
                            || !accounting.reserve_path(&path, config.max_total_path_bytes)
                        {
                            report.push_diagnostic(
                                PluginError::new(
                                    PluginErrorCode::DiscoveryPathLimit,
                                    format!(
                                        "plugin discovery path exceeds {} bytes",
                                        DEFAULT_MAX_DISCOVERY_PATH_BYTES
                                    ),
                                )
                                .with_path(path),
                            );
                        } else {
                            entries.push(entry);
                        }
                    }
                    Err(error) => report.push_diagnostic(PluginError::new(
                        PluginErrorCode::DiscoveryIo,
                        format!("cannot read plugin directory entry: {error}"),
                    )),
                }
            }
        }
        Err(error) => {
            report.push_diagnostic(
                PluginError::new(
                    PluginErrorCode::DiscoveryIo,
                    format!("cannot read plugin discovery directory: {error}"),
                )
                .with_path(&root),
            );
            return report;
        }
    }
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        let path = entry.path();
        if !is_manifest_path(&path) {
            continue;
        }
        if accounting.descriptors >= config.max_descriptors {
            report.push_diagnostic(PluginError::new(
                PluginErrorCode::DiscoveryDescriptorLimit,
                format!(
                    "plugin discovery exceeded the {} descriptor budget",
                    config.max_descriptors
                ),
            ));
            break;
        }
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(error) => {
                report.push_diagnostic(
                    PluginError::new(
                        PluginErrorCode::DiscoveryIo,
                        format!("cannot inspect manifest entry: {error}"),
                    )
                    .with_path(&path),
                );
                continue;
            }
        };
        if file_type.is_symlink() && !config.allow_manifest_symlinks {
            report.push_diagnostic(
                PluginError::new(
                    PluginErrorCode::SymlinkNotAllowed,
                    "manifest symlinks are disabled by discovery policy",
                )
                .with_path(&path),
            );
            continue;
        }
        let canonical_path = match fs::canonicalize(&path) {
            Ok(canonical)
                if path_bytes(&canonical) <= DEFAULT_MAX_DISCOVERY_PATH_BYTES
                    && is_contained(&root, &canonical) =>
            {
                canonical
            }
            Ok(canonical) if path_bytes(&canonical) > DEFAULT_MAX_DISCOVERY_PATH_BYTES => {
                report.push_diagnostic(
                    PluginError::new(
                        PluginErrorCode::DiscoveryPathLimit,
                        format!(
                            "canonical manifest path exceeds {} bytes",
                            DEFAULT_MAX_DISCOVERY_PATH_BYTES
                        ),
                    )
                    .with_path(canonical),
                );
                continue;
            }
            Ok(canonical) => {
                report.push_diagnostic(
                    PluginError::new(
                        PluginErrorCode::PathOutsideRoot,
                        "manifest target leaves the allowlisted directory",
                    )
                    .with_path(canonical),
                );
                continue;
            }
            Err(error) => {
                report.push_diagnostic(
                    PluginError::new(
                        PluginErrorCode::ManifestIo,
                        format!("cannot canonicalize manifest: {error}"),
                    )
                    .with_path(&path),
                );
                continue;
            }
        };
        if !accounting.reserve_path(&canonical_path, config.max_total_path_bytes) {
            report.push_diagnostic(
                PluginError::new(
                    PluginErrorCode::DiscoveryPathLimit,
                    "plugin discovery exceeded the aggregate path-byte budget",
                )
                .with_path(&canonical_path),
            );
            continue;
        }
        let manifest_length = match fs::metadata(&canonical_path) {
            Ok(metadata) => metadata.len(),
            Err(error) => {
                report.push_diagnostic(
                    PluginError::new(
                        PluginErrorCode::ManifestIo,
                        format!("cannot inspect plugin manifest size: {error}"),
                    )
                    .with_path(&canonical_path),
                );
                continue;
            }
        };
        let manifest_length_usize = match usize::try_from(manifest_length) {
            Ok(length) => length,
            Err(_) => {
                report.push_diagnostic(
                    PluginError::new(
                        PluginErrorCode::ManifestTooLarge,
                        "plugin manifest size does not fit the host address space",
                    )
                    .with_path(&canonical_path),
                );
                continue;
            }
        };
        if manifest_length_usize > config.max_manifest_bytes {
            report.push_diagnostic(
                PluginError::new(
                    PluginErrorCode::ManifestTooLarge,
                    format!("manifest exceeds {} bytes", config.max_manifest_bytes),
                )
                .with_path(&canonical_path),
            );
            continue;
        }
        let total_before = accounting.manifest_bytes;
        let remaining_total = config.max_total_manifest_bytes.saturating_sub(total_before);
        if manifest_length_usize > remaining_total {
            report.push_diagnostic(
                PluginError::new(
                    PluginErrorCode::DiscoveryManifestBytesLimit,
                    format!(
                        "plugin discovery manifest bytes exceed the {}-byte aggregate budget",
                        config.max_total_manifest_bytes
                    ),
                )
                .with_path(&canonical_path),
            );
            continue;
        }
        let bytes = match read_bounded(
            &canonical_path,
            config.max_manifest_bytes.min(remaining_total),
        ) {
            Ok(bytes) => bytes,
            Err(error) => {
                report.push_diagnostic(error.with_path(&canonical_path));
                continue;
            }
        };
        let Some(total_manifest_bytes) = total_before.checked_add(bytes.len()) else {
            report.push_diagnostic(
                PluginError::new(
                    PluginErrorCode::DiscoveryManifestBytesLimit,
                    "plugin discovery manifest byte accounting overflowed",
                )
                .with_path(&canonical_path),
            );
            continue;
        };
        accounting.manifest_bytes = total_manifest_bytes;
        if let Err(error) =
            crate::protocol::preflight_json(&bytes, config.max_manifest_bytes.min(remaining_total))
        {
            let code = if error.code() == PluginErrorCode::WorkerMessageLimit {
                PluginErrorCode::ManifestTooLarge
            } else {
                PluginErrorCode::ManifestParse
            };
            report.push_diagnostic(
                PluginError::new(code, "plugin manifest failed bounded JSON preflight")
                    .with_path(&canonical_path),
            );
            continue;
        }
        let mut manifest: PluginManifest = match serde_json::from_slice(&bytes) {
            Ok(manifest) => manifest,
            Err(error) => {
                report.push_diagnostic(
                    PluginError::new(
                        PluginErrorCode::ManifestParse,
                        format!("invalid plugin manifest JSON: {error}"),
                    )
                    .with_path(&canonical_path),
                );
                continue;
            }
        };
        if let Err(error) = manifest.validate() {
            report.push_diagnostic(error.with_path(&canonical_path));
            continue;
        }
        if !accounting.reserve_path(&manifest.executable, config.max_total_path_bytes) {
            report.push_diagnostic(
                PluginError::new(
                    PluginErrorCode::DiscoveryPathLimit,
                    "plugin discovery exceeded the aggregate path-byte budget",
                )
                .with_path(&canonical_path),
            );
            continue;
        }
        let capability_count =
            manifest
                .capabilities
                .iter()
                .try_fold(0usize, |count, (_, declaration)| {
                    count
                        .checked_add(1)
                        .and_then(|count| count.checked_add(declaration.aliases.len()))
                });
        let Some(capability_count) = capability_count else {
            report.push_diagnostic(
                PluginError::new(
                    PluginErrorCode::DiscoveryCapabilityLimit,
                    "plugin discovery capability accounting overflowed",
                )
                .with_path(&canonical_path),
            );
            continue;
        };
        let Some(total_capabilities) = accounting.capabilities.checked_add(capability_count) else {
            report.push_diagnostic(
                PluginError::new(
                    PluginErrorCode::DiscoveryCapabilityLimit,
                    "plugin discovery capability accounting overflowed",
                )
                .with_path(&canonical_path),
            );
            continue;
        };
        if total_capabilities > config.max_capabilities {
            report.push_diagnostic(
                PluginError::new(
                    PluginErrorCode::DiscoveryCapabilityLimit,
                    format!(
                        "plugin discovery exceeded the {} capability budget",
                        config.max_capabilities
                    ),
                )
                .with_path(&canonical_path),
            );
            continue;
        }
        let executable = match validate_executable(
            &root,
            &manifest.executable,
            config.allow_executable_symlinks,
        ) {
            Ok(executable) => executable,
            Err(error) => {
                report.push_diagnostic(error.with_path(&canonical_path));
                continue;
            }
        };
        if !accounting.reserve_path(&executable, config.max_total_path_bytes) {
            report.push_diagnostic(
                PluginError::new(
                    PluginErrorCode::DiscoveryPathLimit,
                    "plugin discovery exceeded the aggregate path-byte budget",
                )
                .with_path(&canonical_path),
            );
            continue;
        }
        manifest.executable = executable.clone();
        accounting.descriptors = accounting.descriptors.saturating_add(1);
        accounting.capabilities = total_capabilities;
        report.plugins.push(PluginDescriptor {
            manifest,
            manifest_path: canonical_path,
            executable_path: executable,
        });
    }

    let plugins = std::mem::take(&mut report.plugins);
    add_conflict_diagnostics(&plugins, &mut report);
    report.plugins = plugins;
    report
}

fn is_manifest_path(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, PluginError> {
    let file = open_manifest(path).map_err(|error| {
        PluginError::new(
            PluginErrorCode::ManifestIo,
            format!("cannot open plugin manifest: {error}"),
        )
    })?;
    let mut bytes = Vec::new();
    let mut limited = file.take(maximum as u64 + 1);
    limited.read_to_end(&mut bytes).map_err(|error| {
        PluginError::new(
            PluginErrorCode::ManifestIo,
            format!("cannot read plugin manifest: {error}"),
        )
    })?;
    if bytes.len() > maximum {
        return Err(PluginError::new(
            PluginErrorCode::ManifestTooLarge,
            format!("manifest exceeds {maximum} bytes"),
        ));
    }
    Ok(bytes)
}

fn validate_executable(
    root: &Path,
    path: &Path,
    allow_symlink: bool,
) -> Result<PathBuf, PluginError> {
    if !path.is_absolute() {
        return Err(PluginError::new(
            PluginErrorCode::ManifestInvalid,
            "executable path must be absolute",
        ));
    }
    if path_bytes(path) > DEFAULT_MAX_DISCOVERY_PATH_BYTES {
        return Err(PluginError::new(
            PluginErrorCode::DiscoveryPathLimit,
            format!("declared executable path exceeds {DEFAULT_MAX_DISCOVERY_PATH_BYTES} bytes"),
        ));
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            PluginError::new(
                PluginErrorCode::ExecutableMissing,
                "declared executable does not exist",
            )
        } else {
            PluginError::new(
                PluginErrorCode::ManifestIo,
                format!("cannot inspect declared executable: {error}"),
            )
        }
    })?;
    if metadata.file_type().is_symlink() && !allow_symlink {
        return Err(PluginError::new(
            PluginErrorCode::SymlinkNotAllowed,
            "executable symlinks are disabled by discovery policy",
        ));
    }
    let canonical = fs::canonicalize(path).map_err(|error| {
        PluginError::new(
            PluginErrorCode::ExecutableMissing,
            format!("cannot canonicalize declared executable: {error}"),
        )
    })?;
    if path_bytes(&canonical) > DEFAULT_MAX_DISCOVERY_PATH_BYTES {
        return Err(PluginError::new(
            PluginErrorCode::DiscoveryPathLimit,
            format!("canonical executable path exceeds {DEFAULT_MAX_DISCOVERY_PATH_BYTES} bytes"),
        ));
    }
    if !is_contained(root, &canonical) {
        return Err(PluginError::new(
            PluginErrorCode::PathOutsideRoot,
            "declared executable leaves the allowlisted directory",
        ));
    }
    let metadata = fs::metadata(&canonical).map_err(|error| {
        PluginError::new(
            PluginErrorCode::ExecutableMissing,
            format!("cannot inspect canonical executable: {error}"),
        )
    })?;
    if !metadata.is_file() {
        return Err(PluginError::new(
            PluginErrorCode::ExecutableNotFile,
            "declared executable is not a regular file",
        ));
    }
    if metadata.len() > MAX_EXECUTABLE_IDENTITY_BYTES as u64 {
        return Err(PluginError::new(
            PluginErrorCode::ExecutableTooLarge,
            format!(
                "declared executable exceeds the {MAX_EXECUTABLE_IDENTITY_BYTES}-byte identity budget"
            ),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(PluginError::new(
                PluginErrorCode::ExecutableNotExecutable,
                "declared executable has no execute permission",
            ));
        }
    }
    Ok(canonical)
}

fn open_manifest(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits());
    }
    options.open(path)
}

fn path_bytes(path: &Path) -> usize {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        path.as_os_str().as_bytes().len()
    }
    #[cfg(not(unix))]
    {
        path.to_string_lossy().len()
    }
}

/// Re-checks the validated executable immediately before process creation.
/// The canonical path, opened-file identity, and streaming content digest must
/// still match. Stable `std::process::Command` cannot bind a child spawn to an
/// already-open file descriptor on every target, so this is the strongest
/// portable safe check; platform-specific stronger launch APIs remain outside
/// this crate and must coordinate before spawning.  This check therefore does
/// not eliminate the final path-to-spawn TOCTOU window: callers must treat the
/// launch as best-effort identity validation, and platforms without the
/// required identity support receive the typed
/// [`PluginErrorCode::ExecutableLaunchUnsupported`] error.
pub(crate) fn capture_executable_identity(path: &Path) -> Result<ExecutableIdentity, PluginError> {
    validate_executable_launch_support()?;
    let link_metadata = fs::symlink_metadata(path).map_err(|error| {
        PluginError::new(
            PluginErrorCode::ExecutableChanged,
            format!("cannot inspect validated executable path: {error}"),
        )
    })?;
    if link_metadata.file_type().is_symlink() {
        return Err(PluginError::new(
            PluginErrorCode::ExecutableChanged,
            "validated executable path is a symlink",
        ));
    }
    let canonical = fs::canonicalize(path).map_err(|error| {
        PluginError::new(
            PluginErrorCode::ExecutableChanged,
            format!("cannot canonicalize validated executable: {error}"),
        )
    })?;
    if canonical != path {
        return Err(PluginError::new(
            PluginErrorCode::ExecutableChanged,
            "validated executable path resolves differently",
        ));
    }
    let mut file = open_executable(path).map_err(|error| {
        PluginError::new(
            PluginErrorCode::ExecutableChanged,
            format!("cannot open validated executable: {error}"),
        )
    })?;
    let before = file.metadata().map_err(|error| {
        PluginError::new(
            PluginErrorCode::ExecutableChanged,
            format!("cannot inspect opened executable: {error}"),
        )
    })?;
    validate_executable_metadata(&before)?;
    if before.len() > MAX_EXECUTABLE_IDENTITY_BYTES as u64 {
        return Err(PluginError::new(
            PluginErrorCode::ExecutableTooLarge,
            format!(
                "validated executable exceeds the {MAX_EXECUTABLE_IDENTITY_BYTES}-byte identity budget"
            ),
        ));
    }
    let digest = digest_executable(&mut file)?;
    let after = file.metadata().map_err(|error| {
        PluginError::new(
            PluginErrorCode::ExecutableChanged,
            format!("cannot revalidate opened executable: {error}"),
        )
    })?;
    if after.len() > MAX_EXECUTABLE_IDENTITY_BYTES as u64 {
        return Err(PluginError::new(
            PluginErrorCode::ExecutableTooLarge,
            format!(
                "validated executable exceeds the {MAX_EXECUTABLE_IDENTITY_BYTES}-byte identity budget"
            ),
        ));
    }
    let before_identity = ExecutableIdentity::from_metadata(&before, [0; 32]);
    let after_identity = ExecutableIdentity::from_metadata(&after, [0; 32]);
    if !before_identity.same_filesystem_object(&after_identity) {
        return Err(PluginError::new(
            PluginErrorCode::ExecutableChanged,
            "validated executable changed while it was being hashed",
        ));
    }
    Ok(ExecutableIdentity::from_metadata(&after, digest))
}

fn validate_executable_launch_support() -> Result<(), PluginError> {
    #[cfg(any(unix, windows))]
    {
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(PluginError::new(
            PluginErrorCode::ExecutableLaunchUnsupported,
            "stable executable identity and launch validation are unavailable on this platform",
        ))
    }
}

/// Revalidates the executable identity immediately before spawning a worker.
/// This is not an atomic path-to-`Command` binding; the final TOCTOU interval
/// remains on platforms where stable Rust cannot spawn from the opened handle.
/// Unsupported identity platforms fail with
/// [`PluginErrorCode::ExecutableLaunchUnsupported`] during capture.
pub(crate) fn verify_executable_identity(
    path: &Path,
    expected: &ExecutableIdentity,
) -> Result<(), PluginError> {
    let link_metadata = fs::symlink_metadata(path).map_err(|error| {
        PluginError::new(
            PluginErrorCode::ExecutableChanged,
            format!("validated executable is no longer available: {error}"),
        )
    })?;
    if link_metadata.file_type().is_symlink() {
        return Err(PluginError::new(
            PluginErrorCode::ExecutableChanged,
            "validated executable path became a symlink",
        ));
    }
    let canonical = fs::canonicalize(path).map_err(|error| {
        PluginError::new(
            PluginErrorCode::ExecutableChanged,
            format!("validated executable cannot be canonicalized: {error}"),
        )
    })?;
    if canonical != path {
        return Err(PluginError::new(
            PluginErrorCode::ExecutableChanged,
            "validated executable path resolves differently before spawn",
        ));
    }
    let current = capture_executable_identity(path)?;
    if !current.same_filesystem_object(expected)
        || current.content_digest != expected.content_digest
    {
        return Err(PluginError::new(
            PluginErrorCode::ExecutableChanged,
            "validated executable filesystem identity or content changed before spawn",
        ));
    }
    Ok(())
}

fn open_executable(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits());
    }
    options.open(path)
}

fn validate_executable_metadata(metadata: &fs::Metadata) -> Result<(), PluginError> {
    if !metadata.is_file() {
        return Err(PluginError::new(
            PluginErrorCode::ExecutableChanged,
            "validated executable is no longer a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(PluginError::new(
                PluginErrorCode::ExecutableChanged,
                "validated executable no longer has execute permission",
            ));
        }
    }
    Ok(())
}

fn digest_executable(file: &mut File) -> Result<[u8; 32], PluginError> {
    digest_reader(
        file,
        MAX_EXECUTABLE_IDENTITY_BYTES,
        MAX_EXECUTABLE_IDENTITY_READS,
    )
}

fn digest_reader<R: Read>(
    reader: &mut R,
    maximum_bytes: usize,
    maximum_reads: usize,
) -> Result<[u8; 32], PluginError> {
    const CHUNK_BYTES: usize = 64 * 1024;
    let mut hasher = Sha256::new();
    let mut chunk = [0u8; CHUNK_BYTES];
    let mut total_bytes = 0usize;
    let mut read_operations = 0usize;
    loop {
        if read_operations >= maximum_reads {
            return Err(PluginError::new(
                PluginErrorCode::ExecutableReadLimit,
                format!("executable identity hashing exceeded the {maximum_reads}-read budget"),
            ));
        }
        read_operations = read_operations.saturating_add(1);
        let requested = maximum_bytes
            .saturating_sub(total_bytes)
            .saturating_add(1)
            .min(CHUNK_BYTES);
        let read = reader.read(&mut chunk[..requested]).map_err(|error| {
            PluginError::new(
                PluginErrorCode::ExecutableChanged,
                format!("cannot hash validated executable: {error}"),
            )
        })?;
        if read == 0 {
            break;
        }
        total_bytes = total_bytes.checked_add(read).ok_or_else(|| {
            PluginError::new(
                PluginErrorCode::ExecutableTooLarge,
                "executable identity byte count overflowed",
            )
        })?;
        if total_bytes > maximum_bytes {
            return Err(PluginError::new(
                PluginErrorCode::ExecutableTooLarge,
                format!("executable identity hashing exceeded the {maximum_bytes}-byte budget"),
            ));
        }
        hasher.update(&chunk[..read]);
    }
    Ok(hasher.finalize().into())
}

fn is_contained(root: &Path, candidate: &Path) -> bool {
    candidate.starts_with(root)
}

fn add_conflict_diagnostics(descriptors: &[PluginDescriptor], report: &mut DiscoveryReport) {
    let mut ids = BTreeMap::<String, PathBuf>::new();
    let mut names = BTreeMap::<(CapabilityKind, String), (String, PathBuf)>::new();
    for descriptor in descriptors {
        let id = descriptor.manifest.id.as_str().to_owned();
        if let Some(first) = ids.insert(id.clone(), descriptor.manifest_path.clone()) {
            report.push_diagnostic(
                PluginError::new(
                    PluginErrorCode::DuplicatePluginId,
                    format!("plugin ID {id} is declared more than once"),
                )
                .with_path(first),
            );
        }
        for (kind, declaration) in descriptor.manifest.capabilities.iter() {
            for name in std::iter::once(declaration.id.as_str())
                .chain(declaration.aliases.iter().map(String::as_str))
            {
                let key = (kind, name.to_owned());
                if let Some((first_id, first_path)) =
                    names.insert(key, (id.clone(), descriptor.manifest_path.clone()))
                {
                    report.push_diagnostic(
                        PluginError::new(
                            PluginErrorCode::DuplicateCapabilityAlias,
                            format!(
                                "{} capability name {name} conflicts between {first_id} and {id}",
                                kind.as_str()
                            ),
                        )
                        .with_path(first_path),
                    );
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "discovery tests assert deterministic fixture setup"
)]
mod tests {
    use super::*;
    use crate::manifest::{
        CapabilityDeclaration, CapabilityDeclarations, PluginId, PluginVersion, ProtocolRange,
        ResourceLimits,
    };
    use std::{
        fs::{self, OpenOptions},
        io::{Cursor, Write},
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TempDirectory(PathBuf);

    impl TempDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "jmeter-rs-plugin-host-{}-{}",
                std::process::id(),
                NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).expect("temporary directory");
            Self(path)
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn manifest(path: &Path, id: &str, capability: &str) -> PluginManifest {
        let mut manifest = PluginManifest::new(
            PluginId::parse(id).expect("plugin ID"),
            PluginVersion::parse("1.2.3").expect("version"),
            path,
        );
        manifest.protocol = ProtocolRange { min: 1, max: 1 };
        manifest.profiles = vec!["jmeter-5.6.3".to_owned()];
        manifest.capabilities = CapabilityDeclarations {
            elements: vec![CapabilityDeclaration {
                id: capability.to_owned(),
                aliases: vec![format!("{capability}Alias")],
                extensions: BTreeMap::new(),
            }],
            functions: Vec::new(),
        };
        manifest.limits = ResourceLimits::default();
        manifest
    }

    fn write_manifest(directory: &Path, name: &str, manifest: &PluginManifest) {
        let path = directory.join(name);
        let bytes = serde_json::to_vec(manifest).expect("manifest JSON");
        fs::write(path, bytes).expect("manifest write");
    }

    fn executable(directory: &Path, name: &str) -> PathBuf {
        let path = directory.join(name);
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .expect("executable fixture");
        file.write_all(b"fixture").expect("fixture bytes");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = file.metadata().expect("metadata").permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&path, permissions).expect("executable permissions");
        }
        path
    }

    #[test]
    fn discovery_is_sorted_by_manifest_filename() {
        let directory = TempDirectory::new();
        let first = executable(&directory.0, "first-helper");
        let second = executable(&directory.0, "second-helper");
        write_manifest(
            &directory.0,
            "z.json",
            &manifest(&second, "plug.z", "z.element"),
        );
        write_manifest(
            &directory.0,
            "a.json",
            &manifest(&first, "plug.a", "a.element"),
        );

        let registry = PluginRegistry::discover(&DiscoveryConfig::new(&directory.0))
            .expect("discovery succeeds");
        assert_eq!(registry.plugins()[0].manifest.id.as_str(), "plug.a");
        assert_eq!(registry.plugins()[1].manifest.id.as_str(), "plug.z");
    }

    #[test]
    fn duplicate_ids_and_aliases_are_diagnostics() {
        let directory = TempDirectory::new();
        let first = executable(&directory.0, "first-helper");
        let second = executable(&directory.0, "second-helper");
        write_manifest(
            &directory.0,
            "a.json",
            &manifest(&first, "same.id", "same.element"),
        );
        write_manifest(
            &directory.0,
            "b.json",
            &manifest(&second, "same.id", "other.element"),
        );
        let mut other = manifest(&second, "different.id", "same.element");
        other.executable = second;
        write_manifest(&directory.0, "c.json", &other);

        let report = PluginRegistry::scan(&DiscoveryConfig::new(&directory.0));
        assert!(
            report
                .diagnostics
                .iter()
                .any(|error| error.code() == PluginErrorCode::DuplicatePluginId)
        );
        assert!(
            report
                .diagnostics
                .iter()
                .any(|error| error.code() == PluginErrorCode::DuplicateCapabilityAlias)
        );
    }

    #[test]
    fn aggregate_manifest_and_descriptor_budgets_fail_closed_before_admission() {
        let directory = TempDirectory::new();
        let first = executable(&directory.0, "first-helper");
        let second = executable(&directory.0, "second-helper");
        let first_manifest = manifest(&first, "plug.first", "first.element");
        let second_manifest = manifest(&second, "plug.second", "second.element");
        write_manifest(&directory.0, "a.json", &first_manifest);
        write_manifest(&directory.0, "b.json", &second_manifest);
        let first_bytes = fs::metadata(directory.0.join("a.json"))
            .expect("first manifest metadata")
            .len() as usize;

        let report = PluginRegistry::scan(
            &DiscoveryConfig::new(&directory.0)
                .with_max_total_manifest_bytes(first_bytes)
                .with_max_descriptors(1),
        );
        assert_eq!(report.plugins.len(), 1);
        assert!(report.diagnostics.iter().any(|error| {
            error.code() == PluginErrorCode::DiscoveryManifestBytesLimit
                || error.code() == PluginErrorCode::DiscoveryDescriptorLimit
        }));
    }

    #[test]
    fn manifest_json_is_preflighted_before_unknown_extension_allocation() {
        let directory = TempDirectory::new();
        let helper = executable(&directory.0, "helper");
        let source = manifest(&helper, "plug.preflight", "preflight.element");
        let mut value = serde_json::to_value(source).expect("manifest value");
        let object = value.as_object_mut().expect("manifest object");
        for index in 0..(16 * 1024 + 1) {
            object.insert(format!("future_{index}"), serde_json::Value::Null);
        }
        fs::write(
            directory.0.join("a.json"),
            serde_json::to_vec(&value).expect("manifest bytes"),
        )
        .expect("manifest write");

        let report = PluginRegistry::scan(&DiscoveryConfig::new(&directory.0));
        assert!(report.plugins.is_empty());
        assert_eq!(
            report.diagnostics[0].code(),
            PluginErrorCode::ManifestTooLarge
        );
    }

    #[test]
    fn aggregate_capability_and_diagnostic_budgets_are_bounded() {
        let directory = TempDirectory::new();
        let helper = executable(&directory.0, "helper");
        let mut source = manifest(&helper, "plug.one", "one.element");
        source
            .capabilities
            .elements
            .push(CapabilityDeclaration::new("two.element"));
        write_manifest(&directory.0, "a.json", &source);
        let report = PluginRegistry::scan(
            &DiscoveryConfig::new(&directory.0)
                .with_max_capabilities(1)
                .with_max_diagnostics(1),
        );
        assert!(report.plugins.is_empty());
        assert_eq!(report.diagnostics.len(), 1);
        assert_eq!(
            report.diagnostics[0].code(),
            PluginErrorCode::DiscoveryCapabilityLimit
        );

        fs::write(directory.0.join("b.json"), b"not-json").expect("invalid manifest");
        fs::write(directory.0.join("c.json"), b"also-not-json").expect("invalid manifest");
        let report = PluginRegistry::scan(
            &DiscoveryConfig::new(&directory.0)
                .with_max_diagnostics(1)
                .with_max_total_manifest_bytes(1024 * 1024),
        );
        assert_eq!(report.diagnostics.len(), 1);
        assert_eq!(
            report.diagnostics[0].code(),
            PluginErrorCode::DiscoveryDiagnosticLimit
        );
    }

    #[test]
    fn aggregate_path_budget_is_preflighted_before_entry_retention() {
        let directory = TempDirectory::new();
        let report =
            PluginRegistry::scan(&DiscoveryConfig::new(&directory.0).with_max_total_path_bytes(1));
        assert!(report.plugins.is_empty());
        assert_eq!(
            report.diagnostics[0].code(),
            PluginErrorCode::DiscoveryPathLimit
        );
    }

    #[test]
    fn executable_content_digest_detects_same_identity_replacement() {
        let directory = TempDirectory::new();
        let path = executable(&directory.0, "helper");
        let identity = capture_executable_identity(&path).expect("capture identity");
        fs::write(&path, b"changed").expect("replace same-length executable");
        let error = verify_executable_identity(&path, &identity)
            .expect_err("content digest must reject changed executable");
        assert_eq!(error.code(), PluginErrorCode::ExecutableChanged);
    }

    #[test]
    fn descriptor_integrity_rejects_manifest_and_path_mismatch() {
        let directory = TempDirectory::new();
        let declared = executable(&directory.0, "declared-helper");
        let actual = executable(&directory.0, "actual-helper");
        let descriptor = PluginDescriptor {
            manifest: manifest(&declared, "plug.integrity", "integrity.element"),
            manifest_path: directory.0.join("plugin.json"),
            executable_path: actual,
        };
        let error = descriptor
            .validate_integrity()
            .expect_err("descriptor must bind manifest executable to path");
        assert_eq!(error.code(), PluginErrorCode::ManifestInvalid);
    }

    #[test]
    fn descriptor_integrity_rejects_manifest_file_replacement() {
        let directory = TempDirectory::new();
        let helper = executable(&directory.0, "helper");
        let source = manifest(&helper, "plug.integrity", "integrity.element");
        let manifest_path = directory.0.join("plugin.json");
        write_manifest(&directory.0, "plugin.json", &source);
        let descriptor = PluginDescriptor {
            manifest: source,
            manifest_path: fs::canonicalize(&manifest_path).expect("canonical manifest"),
            executable_path: fs::canonicalize(&helper).expect("canonical executable"),
        };
        descriptor
            .validate_integrity()
            .expect("descriptor starts with matching manifest");

        let mut replacement = manifest(&helper, "plug.replaced", "integrity.element");
        replacement.extensions.insert(
            "unexpected".to_owned(),
            serde_json::Value::String("changed".to_owned()),
        );
        write_manifest(&directory.0, "plugin.json", &replacement);
        let error = descriptor
            .validate_integrity()
            .expect_err("manifest replacement must be detected");
        assert_eq!(error.code(), PluginErrorCode::ManifestInvalid);
    }

    #[test]
    fn descriptor_integrity_does_not_canonicalize_away_relative_manifest_paths() {
        let directory = TempDirectory::new();
        let helper = executable(&directory.0, "helper");
        let source = manifest(&helper, "plug.integrity", "integrity.element");
        let manifest_path = directory.0.join("plugin.json");
        write_manifest(&directory.0, "plugin.json", &source);
        let descriptor = PluginDescriptor {
            manifest: source,
            manifest_path: fs::canonicalize(&manifest_path).expect("canonical manifest"),
            executable_path: fs::canonicalize(&helper).expect("canonical executable"),
        };

        let mut replacement = manifest(&helper, "plug.integrity", "integrity.element");
        replacement.executable = PathBuf::from("helper");
        write_manifest(&directory.0, "plugin.json", &replacement);
        let error = descriptor
            .validate_integrity()
            .expect_err("relative executable must remain invalid on the wire");
        assert_eq!(error.code(), PluginErrorCode::ManifestInvalid);
    }

    #[test]
    fn executable_identity_digest_has_deterministic_byte_and_read_budgets() {
        let mut oversized = Cursor::new(vec![0u8; 17]);
        let error = digest_reader(&mut oversized, 16, 4)
            .expect_err("digest must stop after its byte budget");
        assert_eq!(error.code(), PluginErrorCode::ExecutableTooLarge);

        let mut short_read_budget = Cursor::new(vec![0u8; 8]);
        let error = digest_reader(&mut short_read_budget, 64, 1)
            .expect_err("digest must stop before an unbounded EOF probe");
        assert_eq!(error.code(), PluginErrorCode::ExecutableReadLimit);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_manifest_and_executable_are_rejected_by_default() {
        let directory = TempDirectory::new();
        let outside = TempDirectory::new();
        let helper = executable(&outside.0, "outside-helper");
        let source = manifest(&helper, "outside.id", "outside.element");
        write_manifest(&outside.0, "source.json", &source);
        std::os::unix::fs::symlink(outside.0.join("source.json"), directory.0.join("link.json"))
            .expect("manifest symlink");
        let report = PluginRegistry::scan(&DiscoveryConfig::new(&directory.0));
        assert!(
            report
                .diagnostics
                .iter()
                .any(|error| error.code() == PluginErrorCode::SymlinkNotAllowed)
        );
    }
}
