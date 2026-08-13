// SPDX-License-Identifier: Apache-2.0
//! Out-of-process native plugin discovery, negotiation, and supervision.
//!
//! A plugin is an explicitly allowlisted executable described by a versioned
//! JSON manifest.  Rust native dynamic libraries and their unstable ABI are
//! intentionally unsupported.  Worker messages use the versioned
//! `jmeter-rs-bridge-protocol` framing crate; this crate owns only process and
//! filesystem policy around that protocol.
//!
//! Discovery never consults ambient `search_paths`, environment variables, or
//! a global plugin directory.  Callers must provide one [`DiscoveryConfig`]
//! and choose an explicit [`ProcessPolicy`] before a worker can start.

mod discovery;
mod error;
mod manifest;
mod protocol;
mod supervisor;

pub use discovery::{
    DEFAULT_MAX_DISCOVERY_CAPABILITIES, DEFAULT_MAX_DISCOVERY_DESCRIPTORS,
    DEFAULT_MAX_DISCOVERY_DIAGNOSTICS, DEFAULT_MAX_DISCOVERY_ENTRIES,
    DEFAULT_MAX_DISCOVERY_MANIFEST_BYTES, DEFAULT_MAX_DISCOVERY_PATH_BYTES,
    DEFAULT_MAX_DISCOVERY_PATH_TOTAL_BYTES, DEFAULT_MAX_MANIFEST_BYTES, DiscoveryConfig,
    DiscoveryReport, HARD_MAX_DISCOVERY_DIAGNOSTICS, HARD_MAX_DISCOVERY_MANIFEST_BYTES,
    HARD_MAX_DISCOVERY_PATH_TOTAL_BYTES, MAX_EXECUTABLE_IDENTITY_BYTES,
    MAX_EXECUTABLE_IDENTITY_READS, PluginDescriptor, PluginRegistry,
};
pub use error::{
    MAX_ERROR_DETAIL_BYTES, MAX_ERROR_PATH_BYTES, MAX_ERROR_SECONDARY_ERRORS,
    MAX_PLUGIN_ERROR_DETAIL_BYTES, MAX_PLUGIN_ERROR_PATH_BYTES, MAX_PLUGIN_ERROR_SECONDARY_ERRORS,
    MAX_SECONDARY_ERRORS, PluginError, PluginErrorCode, Retryability,
};
pub use manifest::{
    ArtifactIdentity, CapabilityDeclaration, CapabilityDeclarations, CapabilityKind,
    CapabilityReference, DependencyIdentity, HARD_MAX_MESSAGE_BYTES, HARD_MAX_OUTPUT_BYTES,
    JmxElementMetadata, JmxProperties, LicenseNoticeStatus, MANIFEST_SCHEMA_VERSION,
    MAX_CAPABILITY_ALIASES, MAX_CAPABILITY_ID_LEN, MAX_DECLARED_CAPABILITIES,
    MAX_DECLARED_CAPABILITY_NAMES, MAX_DECLARED_PROFILES, MAX_EXTENSION_KEY_BYTES,
    MAX_IDENTITY_TEXT_BYTES, MAX_JMX_EXTENSIONS, MAX_JMX_METADATA_TEXT_LEN, MAX_JMX_PROPERTIES,
    MAX_JMX_PROPERTY_NAME_LEN, MAX_MANIFEST_EXTENSIONS, MAX_PLUGIN_ARTIFACT_BYTES,
    MAX_PLUGIN_DEPENDENCIES, MAX_PLUGIN_ID_LEN, MAX_PLUGIN_VERSION_LEN, MAX_RAW_JMX_SUBTREE_BYTES,
    MAX_UNKNOWN_JMX_PROPERTY_BYTES, PluginArtifact, PluginDependency, PluginId, PluginManifest,
    PluginRequest, PluginResponse, PluginVersion, PreservationContract, ProtocolRange,
    ResourceLimits, SHA256_HEX_LEN, Sha256Digest, UnknownJmxProperty,
};
pub use protocol::{HandshakeInfo, decode_handshake, encode_handshake, encode_response};
pub use supervisor::{
    CancellationToken, CleanupPolicy, MAX_PROCESS_ARGUMENT_BYTES, MAX_PROCESS_ARGUMENT_COUNT,
    MAX_PROCESS_ENVIRONMENT_BYTES, MAX_PROCESS_ENVIRONMENT_COUNT, PluginSupervisor,
    ProcessGroupPolicy, ProcessPolicy, SupervisorConfig,
};

/// A capability resolved to one validated plugin descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegotiatedCapability<'a> {
    /// Owning plugin descriptor.
    pub plugin: &'a PluginDescriptor,
    /// Canonical capability declaration.
    pub declaration: &'a CapabilityDeclaration,
    /// Canonical ID selected from a canonical name or alias.
    pub canonical_name: String,
}
