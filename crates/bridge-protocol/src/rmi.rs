// SPDX-License-Identifier: Apache-2.0
//! The bounded, versioned event stream used by the pinned JMeter RMI adapter.
//!
//! This module is deliberately a data-only contract.  It does not implement
//! Java serialization, open a transport, start a process, or make a network
//! request.  A controller or worker may carry an encoded [`rmi::StreamMessage`]
//! inside the generic bridge framing layer, but the stream has its own schema
//! version and lifecycle rules.  In particular, a stream is not an ordinary
//! request/response frame with an unbounded payload.
//!
//! Version 1 uses a small, canonical big-endian binary representation.  All
//! lengths and counts are checked before allocation, unknown tags and flags
//! are rejected, and the decoder can be used incrementally without consuming
//! an incomplete prefix.  JTL attributes and children are retained as an
//! explicitly bounded tree so a future adapter can round-trip metadata rather
//! than silently dropping it.  `SampleStarted`, `SampleOccurred`, and
//! `SampleStopped` remain distinct when delivered, while sender modes may omit
//! any callback phase.  `Credit` and `Ack` are explicit bounded control events;
//! queue admission is never inferred from sample arrival.

// The closed schema exposes many small error-variant fields. Their names and
// stable types are self-documenting, while the module-level docs describe the
// wire contract; keep this suppression scoped to the schema module.
#![allow(missing_docs)]

use core::fmt;
use std::collections::BTreeSet;

use super::Cancellation;

/// Four-byte marker for a versioned RMI event-stream message.
pub const RMI_MAGIC: [u8; 4] = *b"JRMI";
/// Version of the standalone stream envelope.
pub const RMI_WIRE_VERSION: u8 = 1;
/// Version of the controller operation schema.
pub const RMI_OPERATION_SCHEMA_VERSION: u16 = 1;
/// Version of the event-stream schema.
pub const RMI_EVENT_STREAM_VERSION: u16 = 1;
/// Version of the unknown-field/preservation contract.
pub const RMI_PRESERVATION_VERSION: u16 = 1;
/// Bytes in the fixed stream header (`magic`, wire/event tag, three schema
/// versions, and reserved flags).
pub const RMI_HEADER_LEN: usize = 14;

/// Hard upper bound for one stream message, including its header.
pub const MAX_RMI_FRAME_BYTES: usize = 16 * 1024 * 1024;
/// Default per-message RMI stream ceiling; it may be negotiated lower but
/// never above [`MAX_RMI_FRAME_BYTES`].
pub const DEFAULT_RMI_FRAME_BYTES: usize = 1024 * 1024;
/// Hard upper bound for one text field.
pub const MAX_RMI_STRING_BYTES: usize = 1024 * 1024;
/// Hard upper bound for one request/response byte field.
pub const MAX_RMI_BYTES_FIELD: usize = 8 * 1024 * 1024;
/// Hard upper bound for one sample hierarchy.
pub const MAX_RMI_SAMPLE_DEPTH: usize = 64;
/// Hard upper bound for one sample hierarchy node count.
pub const MAX_RMI_SAMPLE_NODES: usize = 100_000;
/// Hard upper bound for event records in one stream message.
pub const MAX_RMI_EVENT_COUNT: usize = 10_000;
/// Hard upper bound for one batch.
pub const MAX_RMI_BATCH_ITEMS: usize = 4096;
/// Hard upper bound for assertions on one sample.
pub const MAX_RMI_ASSERTIONS: usize = 4096;
/// Hard upper bound for selected variables on one sample.
pub const MAX_RMI_VARIABLES: usize = 4096;
/// Hard upper bound for JTL attributes on one node.
pub const MAX_RMI_ATTRIBUTES: usize = 256;
/// Hard upper bound for JTL child nodes on one node.
pub const MAX_RMI_CHILDREN: usize = 4096;
/// Hard upper bound for identity/capability dependencies.
pub const MAX_RMI_DEPENDENCIES: usize = 256;
/// Hard upper bound for capability names.
pub const MAX_RMI_CAPABILITIES: usize = 256;
/// Hard upper bound for queue credits.
pub const MAX_RMI_QUEUE_CREDITS: u64 = 1_000_000;
/// Hard upper bound for one operation's remaining duration, in nanoseconds.
pub const MAX_RMI_OPERATION_DURATION_NANOS: u64 = 24 * 60 * 60 * 1_000_000_000;
/// Compatibility spelling for the duration limit field retained in
/// [`RmiLimits`].  Its value is nanoseconds on the wire.
pub const MAX_RMI_OPERATION_DURATION_MILLIS: u64 = MAX_RMI_OPERATION_DURATION_NANOS;
/// Hard upper bound for callback events accepted by one stream generation.
pub const MAX_RMI_STREAM_EVENTS: usize = 1_000_000;
/// Hard upper bound for encoded callback bytes accepted by one stream
/// generation.
pub const MAX_RMI_STREAM_BYTES: u64 = 1024 * 1024 * 1024;

/// A finite amount of operation time remaining at the instant a message is
/// sent.  Monotonic clock readings never cross the process boundary.  The
/// wire representation is always a non-zero finite nanosecond count; there
/// is no cross-process monotonic timestamp or unbounded-deadline sentinel.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct RemainingDuration(Option<u64>);

impl RemainingDuration {
    /// Legacy unbounded marker.  It is retained as an API spelling for source
    /// compatibility but is rejected by stream validation and decoding.
    pub const NONE: Self = Self(None);

    /// Creates a finite remaining duration in nanoseconds.
    pub const fn from_nanos(nanos: u64) -> Self {
        Self(Some(nanos))
    }

    /// Creates a finite remaining duration in milliseconds.
    pub const fn from_millis(millis: u64) -> Self {
        Self(Some(millis.saturating_mul(1_000_000)))
    }

    /// Returns the remaining duration in nanoseconds, or `None` for the
    /// invalid legacy unbounded marker.
    pub const fn as_nanos(self) -> Option<u64> {
        self.0
    }

    /// Returns the remaining duration in whole milliseconds, or `None` for
    /// the invalid legacy unbounded marker.
    pub const fn as_millis(self) -> Option<u64> {
        match self.0 {
            Some(nanos) => Some(nanos / 1_000_000),
            None => None,
        }
    }
}

impl Default for RemainingDuration {
    fn default() -> Self {
        Self::NONE
    }
}

impl fmt::Debug for RemainingDuration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(nanos) => formatter
                .debug_tuple("RemainingDuration")
                .field(&nanos)
                .finish(),
            None => formatter.write_str("RemainingDuration::NONE"),
        }
    }
}

/// A protocol/schema identity carried in every stream message.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct SchemaVersion {
    /// Generic bridge protocol version used by this stream payload.
    pub protocol: u16,
    /// Controller operation schema version.
    pub operation: u16,
    /// Event stream schema version.
    pub event_stream: u16,
    /// Preservation contract version.
    pub preservation: u16,
}

impl SchemaVersion {
    /// The only schema currently implemented by this module.
    pub const V1: Self = Self {
        protocol: RMI_WIRE_VERSION as u16,
        operation: RMI_OPERATION_SCHEMA_VERSION,
        event_stream: RMI_EVENT_STREAM_VERSION,
        preservation: RMI_PRESERVATION_VERSION,
    };

    /// Validates the closed version tuple.
    pub const fn validate(self) -> Result<(), SchemaError> {
        if self.protocol != RMI_WIRE_VERSION as u16 {
            return Err(SchemaError::UnsupportedProtocol(self.protocol));
        }
        if self.operation != RMI_OPERATION_SCHEMA_VERSION {
            return Err(SchemaError::UnsupportedOperation(self.operation));
        }
        if self.event_stream != RMI_EVENT_STREAM_VERSION {
            return Err(SchemaError::UnsupportedEventStream(self.event_stream));
        }
        if self.preservation != RMI_PRESERVATION_VERSION {
            return Err(SchemaError::UnsupportedPreservation(self.preservation));
        }
        Ok(())
    }
}

impl Default for SchemaVersion {
    fn default() -> Self {
        Self::V1
    }
}

impl fmt::Debug for SchemaVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SchemaVersion")
            .field("protocol", &self.protocol)
            .field("operation", &self.operation)
            .field("event_stream", &self.event_stream)
            .field("preservation", &self.preservation)
            .finish()
    }
}

/// A fixed-size SHA-256 digest used for profile and helper identities.
#[derive(Clone, Copy, Default, Eq, Hash, PartialEq)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    /// Creates a digest from its raw bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw digest bytes.
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Parses exactly 64 lower- or upper-case hexadecimal characters.
    pub fn parse_hex(value: &str) -> Result<Self, IdentityError> {
        let bytes = parse_digest_hex(value, 32)?;
        let mut digest = [0_u8; 32];
        digest.copy_from_slice(&bytes);
        Ok(Self(digest))
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Sha256Digest(<redacted>)")
    }
}

/// A fixed-size SHA-512 digest used for the pinned JMeter archive.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct Sha512Digest([u8; 64]);

impl Sha512Digest {
    /// Creates a digest from its raw bytes.
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Returns the raw digest bytes.
    pub const fn as_bytes(self) -> [u8; 64] {
        self.0
    }

    /// Parses exactly 128 hexadecimal characters.
    pub fn parse_hex(value: &str) -> Result<Self, IdentityError> {
        let bytes = parse_digest_hex(value, 64)?;
        let mut digest = [0_u8; 64];
        digest.copy_from_slice(&bytes);
        Ok(Self(digest))
    }
}

// Rust 1.97 does not implement `Default` for arrays of 64 bytes.
#[allow(clippy::derivable_impls)]
impl Default for Sha512Digest {
    fn default() -> Self {
        Self([0; 64])
    }
}

impl fmt::Debug for Sha512Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Sha512Digest(<redacted>)")
    }
}

/// A pinned profile identity.
#[derive(Clone, Eq, PartialEq)]
pub struct ProfileIdentity {
    /// Profile identifier, for example `jmeter-5.6.3`.
    pub id: String,
    /// Monotonic profile revision.
    pub version: u32,
    /// SHA-256 of the canonical profile document.
    pub sha256: Sha256Digest,
}

impl ProfileIdentity {
    /// Creates a profile identity.
    pub fn new(id: impl Into<String>, version: u32, sha256: Sha256Digest) -> Self {
        Self {
            id: id.into(),
            version,
            sha256,
        }
    }

    fn validate(&self, limits: RmiLimits) -> Result<(), IdentityError> {
        validate_text(&self.id, limits.max_string_bytes, "profile id")?;
        if self.version == 0 {
            return Err(IdentityError::ZeroVersion("profile"));
        }
        Ok(())
    }
}

impl fmt::Debug for ProfileIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProfileIdentity")
            .field("id_len", &self.id.len())
            .field("version", &self.version)
            .field("sha256", &self.sha256)
            .finish()
    }
}

/// A plugin/driver/classpath identity in the pinned artifact declaration.
#[derive(Clone, Eq, PartialEq)]
pub struct DependencyIdentity {
    /// Stable dependency or plugin name.
    pub name: String,
    /// Dependency version.
    pub version: String,
    /// SHA-256 of the ordered artifact bytes.
    pub sha256: Sha256Digest,
    /// License identifier retained for provenance checks.
    pub license: String,
    /// NOTICE identifier or digest, never secret material.
    pub notice: String,
    /// Position in the effective classpath.
    pub classpath_order: u32,
}

impl fmt::Debug for DependencyIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DependencyIdentity")
            .field("name_len", &self.name.len())
            .field("version_len", &self.version.len())
            .field("sha256", &self.sha256)
            .field("license_len", &self.license.len())
            .field("notice_len", &self.notice.len())
            .field("classpath_order", &self.classpath_order)
            .finish()
    }
}

/// Pinned JMeter/helper/runtime identity bound before useful execution.
#[derive(Clone, Eq, PartialEq)]
pub struct ArtifactIdentity {
    /// SHA-512 of `apache-jmeter-5.6.3.zip`.
    pub jmeter_archive_sha512: Sha512Digest,
    /// Pinned JMeter source commit.
    pub jmeter_source_commit: String,
    /// SHA-256 of original helper source.
    pub helper_source_sha256: Sha256Digest,
    /// SHA-256 of the reproducible helper build.
    pub helper_build_sha256: Sha256Digest,
    /// Absolute/compiler identity string.
    pub java_compiler: String,
    /// JVM vendor/version identity string.
    pub java_runtime: String,
    /// jmeter-rs source commit identity.
    pub jmeter_rs_commit: String,
    /// Platform profile identifier.
    pub platform_profile: String,
    /// Target triple.
    pub target: String,
    /// OS image identity.
    pub os: String,
    /// Ordered plugin/driver/classpath declarations.
    pub dependencies: Vec<DependencyIdentity>,
}

impl ArtifactIdentity {
    fn validate(&self, limits: RmiLimits) -> Result<(), IdentityError> {
        for (value, field) in [
            (&self.jmeter_source_commit, "JMeter source commit"),
            (&self.java_compiler, "Java compiler"),
            (&self.java_runtime, "Java runtime"),
            (&self.jmeter_rs_commit, "jmeter-rs commit"),
            (&self.platform_profile, "platform profile"),
            (&self.target, "target"),
            (&self.os, "OS"),
        ] {
            validate_text(value, limits.max_string_bytes, field)?;
        }
        if self.dependencies.len() > limits.max_dependencies {
            return Err(IdentityError::Count {
                field: "dependencies",
                actual: self.dependencies.len(),
                maximum: limits.max_dependencies,
            });
        }
        let mut classpath_orders = BTreeSet::new();
        for dependency in &self.dependencies {
            if !classpath_orders.insert(dependency.classpath_order) {
                return Err(IdentityError::Duplicate("dependency classpath order"));
            }
            for (value, field) in [
                (&dependency.name, "dependency name"),
                (&dependency.version, "dependency version"),
                (&dependency.license, "dependency license"),
                (&dependency.notice, "dependency notice"),
            ] {
                validate_text(value, limits.max_string_bytes, field)?;
            }
        }
        Ok(())
    }
}

impl fmt::Debug for ArtifactIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactIdentity")
            .field("jmeter_archive_sha512", &self.jmeter_archive_sha512)
            .field("jmeter_source_commit_len", &self.jmeter_source_commit.len())
            .field("helper_source_sha256", &self.helper_source_sha256)
            .field("helper_build_sha256", &self.helper_build_sha256)
            .field("java_compiler_len", &self.java_compiler.len())
            .field("java_runtime_len", &self.java_runtime.len())
            .field("jmeter_rs_commit_len", &self.jmeter_rs_commit.len())
            .field("platform_profile_len", &self.platform_profile.len())
            .field("target_len", &self.target.len())
            .field("os_len", &self.os.len())
            .field("dependencies", &self.dependencies.len())
            .finish()
    }
}

/// Role of the process at the stream endpoint.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum RmiRole {
    /// Rust-side controller/helper owner.
    Controller = 1,
    /// Pinned JMeter worker/helper owner.
    Worker = 2,
}

impl RmiRole {
    fn from_wire(value: u8) -> Result<Self, RmiDecodeError> {
        match value {
            1 => Ok(Self::Controller),
            2 => Ok(Self::Worker),
            other => Err(RmiDecodeError::InvalidEnum {
                field: "role",
                value: other as u64,
            }),
        }
    }
}

/// A negotiated stream-preservation declaration.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Preservation {
    /// Version of this declaration.
    pub version: u16,
    /// Whether operation fields unknown to this implementation are retained.
    /// Version 1 has no opaque operation-field representation and therefore
    /// rejects `true` during validation.
    pub unknown_operation_fields: bool,
}

impl Default for Preservation {
    fn default() -> Self {
        Self {
            version: RMI_PRESERVATION_VERSION,
            unknown_operation_fields: false,
        }
    }
}

impl Preservation {
    fn validate(self) -> Result<(), SchemaError> {
        if self.version != RMI_PRESERVATION_VERSION {
            return Err(SchemaError::UnsupportedPreservation(self.version));
        }
        if self.unknown_operation_fields {
            return Err(SchemaError::UnknownOperationFieldsUnsupported);
        }
        Ok(())
    }
}

/// Hard resource limits negotiated for one stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RmiLimits {
    /// Maximum encoded message bytes, including the fixed header.
    pub max_frame_bytes: usize,
    /// Maximum UTF-8 string field bytes.
    pub max_string_bytes: usize,
    /// Maximum one byte field.
    pub max_bytes_field: usize,
    /// Maximum event records in a message.
    pub max_event_count: usize,
    /// Maximum items in one batch.
    pub max_batch_items: usize,
    /// Maximum sample hierarchy depth.
    pub max_sample_depth: usize,
    /// Maximum sample hierarchy node count.
    pub max_sample_nodes: usize,
    /// Maximum assertions per sample.
    pub max_assertions: usize,
    /// Maximum variables per sample.
    pub max_variables: usize,
    /// Maximum JTL attributes per node.
    pub max_attributes: usize,
    /// Maximum JTL children per node.
    pub max_children: usize,
    /// Maximum dependencies in artifact identity.
    pub max_dependencies: usize,
    /// Maximum capabilities in a ready declaration.
    pub max_capabilities: usize,
    /// Maximum queue credits for one stream.
    pub max_queue_credits: u64,
    /// Maximum remaining operation duration accepted on the wire, in
    /// nanoseconds.
    pub max_operation_duration_millis: u64,
    /// Maximum callback events accepted by one stream generation.
    pub max_stream_events: usize,
    /// Maximum encoded callback bytes accepted by one stream generation.
    pub max_stream_bytes: u64,
}

impl Default for RmiLimits {
    fn default() -> Self {
        Self {
            max_frame_bytes: DEFAULT_RMI_FRAME_BYTES,
            max_string_bytes: MAX_RMI_STRING_BYTES,
            max_bytes_field: MAX_RMI_BYTES_FIELD,
            max_event_count: MAX_RMI_EVENT_COUNT,
            max_batch_items: MAX_RMI_BATCH_ITEMS,
            max_sample_depth: MAX_RMI_SAMPLE_DEPTH,
            max_sample_nodes: MAX_RMI_SAMPLE_NODES,
            max_assertions: MAX_RMI_ASSERTIONS,
            max_variables: MAX_RMI_VARIABLES,
            max_attributes: MAX_RMI_ATTRIBUTES,
            max_children: MAX_RMI_CHILDREN,
            max_dependencies: MAX_RMI_DEPENDENCIES,
            max_capabilities: MAX_RMI_CAPABILITIES,
            max_queue_credits: MAX_RMI_QUEUE_CREDITS,
            max_operation_duration_millis: MAX_RMI_OPERATION_DURATION_NANOS,
            max_stream_events: MAX_RMI_STREAM_EVENTS,
            max_stream_bytes: MAX_RMI_STREAM_BYTES,
        }
    }
}

impl RmiLimits {
    /// Validates limits against the module's hard caps.
    pub fn validate(self) -> Result<(), RmiLimitError> {
        check_limit(
            "max_frame_bytes",
            self.max_frame_bytes,
            RMI_HEADER_LEN,
            MAX_RMI_FRAME_BYTES,
        )?;
        check_limit(
            "max_string_bytes",
            self.max_string_bytes,
            1,
            MAX_RMI_STRING_BYTES,
        )?;
        check_limit(
            "max_bytes_field",
            self.max_bytes_field,
            0,
            MAX_RMI_BYTES_FIELD,
        )?;
        check_limit(
            "max_event_count",
            self.max_event_count,
            1,
            MAX_RMI_EVENT_COUNT,
        )?;
        check_limit(
            "max_batch_items",
            self.max_batch_items,
            1,
            MAX_RMI_BATCH_ITEMS,
        )?;
        check_limit(
            "max_sample_depth",
            self.max_sample_depth,
            1,
            MAX_RMI_SAMPLE_DEPTH,
        )?;
        check_limit(
            "max_sample_nodes",
            self.max_sample_nodes,
            1,
            MAX_RMI_SAMPLE_NODES,
        )?;
        check_limit("max_assertions", self.max_assertions, 1, MAX_RMI_ASSERTIONS)?;
        check_limit("max_variables", self.max_variables, 1, MAX_RMI_VARIABLES)?;
        check_limit("max_attributes", self.max_attributes, 1, MAX_RMI_ATTRIBUTES)?;
        check_limit("max_children", self.max_children, 1, MAX_RMI_CHILDREN)?;
        check_limit(
            "max_dependencies",
            self.max_dependencies,
            1,
            MAX_RMI_DEPENDENCIES,
        )?;
        check_limit(
            "max_capabilities",
            self.max_capabilities,
            1,
            MAX_RMI_CAPABILITIES,
        )?;
        if self.max_queue_credits == 0 || self.max_queue_credits > MAX_RMI_QUEUE_CREDITS {
            return Err(RmiLimitError {
                field: "max_queue_credits",
                actual: self.max_queue_credits as usize,
                maximum: MAX_RMI_QUEUE_CREDITS as usize,
            });
        }
        if self.max_operation_duration_millis == 0
            || self.max_operation_duration_millis > MAX_RMI_OPERATION_DURATION_NANOS
        {
            return Err(RmiLimitError {
                field: "max_operation_duration_nanos",
                actual: usize::try_from(self.max_operation_duration_millis).unwrap_or(usize::MAX),
                maximum: MAX_RMI_OPERATION_DURATION_NANOS as usize,
            });
        }
        check_limit(
            "max_stream_events",
            self.max_stream_events,
            1,
            MAX_RMI_STREAM_EVENTS,
        )?;
        if self.max_stream_bytes == 0 || self.max_stream_bytes > MAX_RMI_STREAM_BYTES {
            return Err(RmiLimitError {
                field: "max_stream_bytes",
                actual: usize::try_from(self.max_stream_bytes).unwrap_or(usize::MAX),
                maximum: MAX_RMI_STREAM_BYTES as usize,
            });
        }
        Ok(())
    }

    /// Returns a conservative component-wise intersection.
    pub fn intersect(self, peer: Self) -> Result<Self, RmiLimitError> {
        let result = Self {
            max_frame_bytes: self.max_frame_bytes.min(peer.max_frame_bytes),
            max_string_bytes: self.max_string_bytes.min(peer.max_string_bytes),
            max_bytes_field: self.max_bytes_field.min(peer.max_bytes_field),
            max_event_count: self.max_event_count.min(peer.max_event_count),
            max_batch_items: self.max_batch_items.min(peer.max_batch_items),
            max_sample_depth: self.max_sample_depth.min(peer.max_sample_depth),
            max_sample_nodes: self.max_sample_nodes.min(peer.max_sample_nodes),
            max_assertions: self.max_assertions.min(peer.max_assertions),
            max_variables: self.max_variables.min(peer.max_variables),
            max_attributes: self.max_attributes.min(peer.max_attributes),
            max_children: self.max_children.min(peer.max_children),
            max_dependencies: self.max_dependencies.min(peer.max_dependencies),
            max_capabilities: self.max_capabilities.min(peer.max_capabilities),
            max_queue_credits: self.max_queue_credits.min(peer.max_queue_credits),
            max_operation_duration_millis: self
                .max_operation_duration_millis
                .min(peer.max_operation_duration_millis),
            max_stream_events: self.max_stream_events.min(peer.max_stream_events),
            max_stream_bytes: self.max_stream_bytes.min(peer.max_stream_bytes),
        };
        result.validate()?;
        Ok(result)
    }
}

/// A stable resource-limit error.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RmiLimitError {
    /// Limit field that failed validation.
    pub field: &'static str,
    /// Declared value.
    pub actual: usize,
    /// Hard maximum (or minimum when `actual == 0`).
    pub maximum: usize,
}

impl fmt::Display for RmiLimitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} limit {} exceeds {}",
            self.field, self.actual, self.maximum
        )
    }
}

impl std::error::Error for RmiLimitError {}

/// Schema/version validation errors.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SchemaError {
    /// Generic stream protocol version is not supported.
    UnsupportedProtocol(u16),
    /// Operation schema version is not supported.
    UnsupportedOperation(u16),
    /// Event stream version is not supported.
    UnsupportedEventStream(u16),
    /// Preservation schema version is not supported.
    UnsupportedPreservation(u16),
    /// Version 1 has no opaque unknown-operation-field representation.
    UnknownOperationFieldsUnsupported,
}

impl fmt::Display for SchemaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedProtocol(value) => {
                write!(formatter, "unsupported stream protocol {value}")
            }
            Self::UnsupportedOperation(value) => {
                write!(formatter, "unsupported operation schema {value}")
            }
            Self::UnsupportedEventStream(value) => {
                write!(formatter, "unsupported event stream schema {value}")
            }
            Self::UnsupportedPreservation(value) => {
                write!(formatter, "unsupported preservation schema {value}")
            }
            Self::UnknownOperationFieldsUnsupported => formatter
                .write_str("unknown operation fields require a negotiated opaque representation"),
        }
    }
}

impl std::error::Error for SchemaError {}

/// Identity declaration errors.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum IdentityError {
    /// A text field is empty where an identity requires a value.
    Empty(&'static str),
    /// A text field exceeds the negotiated bound.
    TextTooLong {
        field: &'static str,
        actual: usize,
        maximum: usize,
    },
    /// A numeric identity/version is zero.
    ZeroVersion(&'static str),
    /// A list exceeds its negotiated bound.
    Count {
        field: &'static str,
        actual: usize,
        maximum: usize,
    },
    /// A digest has the wrong hexadecimal length or contains a bad digit.
    InvalidDigest,
    /// An ordered identity list contains a duplicate key.
    Duplicate(&'static str),
    /// The negotiated preservation declaration is unsupported.
    Preservation(String),
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty(field) => write!(formatter, "{field} must not be empty"),
            Self::TextTooLong {
                field,
                actual,
                maximum,
            } => {
                write!(formatter, "{field} is {actual} bytes; maximum is {maximum}")
            }
            Self::ZeroVersion(field) => write!(formatter, "{field} version must be non-zero"),
            Self::Count {
                field,
                actual,
                maximum,
            } => {
                write!(formatter, "{field} count {actual} exceeds {maximum}")
            }
            Self::InvalidDigest => formatter.write_str("digest is not valid hexadecimal"),
            Self::Duplicate(field) => write!(formatter, "duplicate {field}"),
            Self::Preservation(value) => write!(formatter, "unsupported preservation: {value}"),
        }
    }
}

impl std::error::Error for IdentityError {}

fn check_limit(
    field: &'static str,
    actual: usize,
    minimum: usize,
    maximum: usize,
) -> Result<(), RmiLimitError> {
    if actual < minimum || actual > maximum {
        Err(RmiLimitError {
            field,
            actual,
            maximum: if actual < minimum { minimum } else { maximum },
        })
    } else {
        Ok(())
    }
}

fn validate_text(value: &str, maximum: usize, field: &'static str) -> Result<(), IdentityError> {
    if value.is_empty() {
        return Err(IdentityError::Empty(field));
    }
    if value.len() > maximum {
        return Err(IdentityError::TextTooLong {
            field,
            actual: value.len(),
            maximum,
        });
    }
    Ok(())
}

fn parse_digest_hex(value: &str, bytes: usize) -> Result<Vec<u8>, IdentityError> {
    if value.len() != bytes.saturating_mul(2) {
        return Err(IdentityError::InvalidDigest);
    }
    let mut result = Vec::with_capacity(bytes);
    let raw = value.as_bytes();
    for pair in raw.chunks_exact(2) {
        let high = hex_digit(pair[0]).ok_or(IdentityError::InvalidDigest)?;
        let low = hex_digit(pair[1]).ok_or(IdentityError::InvalidDigest)?;
        result.push((high << 4) | low);
    }
    Ok(result)
}

fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

/// A worker/plugin capability advertised in [`Ready`].
#[derive(Clone, Eq, PartialEq)]
pub struct Capability {
    /// Stable capability identifier.
    pub id: String,
    /// Capability version or implementation revision.
    pub version: String,
}

impl Capability {
    /// Creates a capability declaration.
    pub fn new(id: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            version: version.into(),
        }
    }
}

impl fmt::Debug for Capability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Capability")
            .field("id_len", &self.id.len())
            .field("version_len", &self.version.len())
            .finish()
    }
}

/// Identity and negotiated declarations carried by a ready event.
#[derive(Clone, Eq, PartialEq)]
pub struct BridgeIdentity {
    /// Pinned compatibility profile.
    pub profile: ProfileIdentity,
    /// Pinned JMeter/helper/runtime artifacts.
    pub artifact: ArtifactIdentity,
    /// Endpoint role.
    pub role: RmiRole,
    /// Stable worker identity (empty only for the controller).
    pub worker_id: String,
    /// Ordered capability declarations.
    pub capabilities: Vec<Capability>,
    /// Preservation declaration negotiated before plan transfer.
    pub preservation: Preservation,
}

impl BridgeIdentity {
    /// Validates identity text, counts, and preservation semantics.
    pub fn validate(&self, limits: RmiLimits) -> Result<(), IdentityError> {
        self.profile.validate(limits)?;
        self.artifact.validate(limits)?;
        if self.role == RmiRole::Worker && self.worker_id.is_empty() {
            return Err(IdentityError::Empty("worker id"));
        }
        if !self.worker_id.is_empty() {
            validate_text(&self.worker_id, limits.max_string_bytes, "worker id")?;
        }
        if self.capabilities.len() > limits.max_capabilities {
            return Err(IdentityError::Count {
                field: "capabilities",
                actual: self.capabilities.len(),
                maximum: limits.max_capabilities,
            });
        }
        let mut capability_ids = BTreeSet::new();
        for capability in &self.capabilities {
            if !capability_ids.insert(&capability.id) {
                return Err(IdentityError::Duplicate("capability id"));
            }
            validate_text(&capability.id, limits.max_string_bytes, "capability id")?;
            validate_text(
                &capability.version,
                limits.max_string_bytes,
                "capability version",
            )?;
        }
        self.preservation
            .validate()
            .map_err(|error| IdentityError::Preservation(error.to_string()))
    }
}

impl fmt::Debug for BridgeIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BridgeIdentity")
            .field("profile", &self.profile)
            .field("artifact", &self.artifact)
            .field("role", &self.role)
            .field("worker_id_len", &self.worker_id.len())
            .field("capabilities", &self.capabilities.len())
            .field("preservation", &self.preservation)
            .finish()
    }
}

/// Queue admission information attached to lifecycle events.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct QueueCredit {
    /// Maximum event slots accepted by the bridge queue.
    pub capacity: u64,
    /// Event slots currently available to the producer.
    pub available: u64,
    /// Maximum encoded bytes accepted by the bridge queue.
    pub bytes_capacity: u64,
    /// Encoded bytes currently available to the producer.
    pub bytes_available: u64,
}

impl QueueCredit {
    /// Creates an empty queue credit declaration.
    pub const fn new(capacity: u64, bytes_capacity: u64) -> Self {
        Self {
            capacity,
            available: capacity,
            bytes_capacity,
            bytes_available: bytes_capacity,
        }
    }

    /// Validates queue arithmetic and hard bounds.
    pub fn validate(self, limits: RmiLimits) -> Result<(), QueueError> {
        if self.capacity == 0 || self.capacity > limits.max_queue_credits {
            return Err(QueueError::CreditLimit {
                declared: self.capacity,
                maximum: limits.max_queue_credits,
            });
        }
        if self.available > self.capacity {
            return Err(QueueError::CreditInconsistent {
                available: self.available,
                capacity: self.capacity,
            });
        }
        if self.bytes_capacity == 0 || self.bytes_capacity > limits.max_frame_bytes as u64 {
            return Err(QueueError::ByteCreditLimit {
                declared: self.bytes_capacity,
                maximum: limits.max_frame_bytes as u64,
            });
        }
        if self.bytes_available > self.bytes_capacity {
            return Err(QueueError::ByteCreditInconsistent {
                available: self.bytes_available,
                capacity: self.bytes_capacity,
            });
        }
        Ok(())
    }

    /// Attempts to reserve one event and its encoded bytes.
    pub fn reserve(&mut self, bytes: usize, limits: RmiLimits) -> Result<(), QueueError> {
        self.validate(limits)?;
        let bytes = u64::try_from(bytes).map_err(|_| QueueError::ByteCountOverflow)?;
        if self.available == 0 || self.bytes_available < bytes {
            return Err(QueueError::Full {
                requested_bytes: bytes,
                available_events: self.available,
                available_bytes: self.bytes_available,
            });
        }
        self.available -= 1;
        self.bytes_available -= bytes;
        Ok(())
    }

    /// Releases one previously accepted event.
    pub fn release(&mut self, bytes: usize, limits: RmiLimits) -> Result<(), QueueError> {
        self.validate(limits)?;
        let bytes = u64::try_from(bytes).map_err(|_| QueueError::ByteCountOverflow)?;
        let byte_room = self.bytes_capacity.saturating_sub(self.bytes_available);
        if self.available == self.capacity || bytes > byte_room {
            return Err(QueueError::ReleaseOverflow);
        }
        self.available += 1;
        self.bytes_available += bytes;
        Ok(())
    }
}

/// Queue backpressure policy.  Waiting is an adapter concern; the schema only
/// records the policy and its bounded result.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum BackpressurePolicy {
    /// Reject the producer immediately when credit is exhausted.
    Reject = 1,
    /// The adapter may wait for a credit until its deadline.
    WaitUntilDeadline = 2,
    /// The adapter initiates a bounded drain before rejecting.
    DrainThenReject = 3,
}

impl BackpressurePolicy {
    fn from_wire(value: u8) -> Result<Self, RmiDecodeError> {
        match value {
            1 => Ok(Self::Reject),
            2 => Ok(Self::WaitUntilDeadline),
            3 => Ok(Self::DrainThenReject),
            other => Err(RmiDecodeError::InvalidEnum {
                field: "backpressure policy",
                value: other as u64,
            }),
        }
    }
}

/// Typed queue admission outcome.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum QueueAdmission {
    /// The event was accepted and consumed one event/byte credit.
    Accepted,
    /// Queue is full; no event was accepted.
    Full,
}

/// Stable queue/backpressure failures.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum QueueError {
    /// Queue has no event or byte credit.
    Full {
        /// Bytes requested by the event.
        requested_bytes: u64,
        /// Event slots remaining.
        available_events: u64,
        /// Bytes remaining.
        available_bytes: u64,
    },
    /// Queue was explicitly closed.
    Closed,
    /// Stream cancellation has made admission impossible.
    Cancelled,
    /// Queue credit exceeds a negotiated hard bound.
    CreditLimit { declared: u64, maximum: u64 },
    /// Available event credit exceeds capacity.
    CreditInconsistent { available: u64, capacity: u64 },
    /// Queue byte credit exceeds a negotiated hard bound.
    ByteCreditLimit { declared: u64, maximum: u64 },
    /// Available byte credit exceeds capacity.
    ByteCreditInconsistent { available: u64, capacity: u64 },
    /// A byte count cannot be represented.
    ByteCountOverflow,
    /// Releasing an event would exceed the original credit.
    ReleaseOverflow,
}

impl QueueError {
    /// Stable machine-readable code.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Full { .. } => "queue_full",
            Self::Closed => "queue_closed",
            Self::Cancelled => "queue_cancelled",
            Self::CreditLimit { .. } => "queue_credit_limit",
            Self::CreditInconsistent { .. } => "queue_credit_inconsistent",
            Self::ByteCreditLimit { .. } => "queue_byte_credit_limit",
            Self::ByteCreditInconsistent { .. } => "queue_byte_credit_inconsistent",
            Self::ByteCountOverflow => "queue_byte_count_overflow",
            Self::ReleaseOverflow => "queue_release_overflow",
        }
    }
}

impl fmt::Display for QueueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for QueueError {}

/// Pure queue admission state used by adapters and deterministic tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueueState {
    /// Current queue credit.
    pub credit: QueueCredit,
    /// Configured policy for a full queue.
    pub policy: BackpressurePolicy,
    closed: bool,
    cancelled: bool,
}

impl QueueState {
    /// Creates an open queue with the supplied credit and policy.
    pub fn new(
        credit: QueueCredit,
        policy: BackpressurePolicy,
        limits: RmiLimits,
    ) -> Result<Self, QueueError> {
        credit.validate(limits)?;
        Ok(Self {
            credit,
            policy,
            closed: false,
            cancelled: false,
        })
    }

    /// Returns whether no further events can be admitted.
    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    /// Closes the queue without discarding already accepted events.
    pub const fn close(&mut self) {
        self.closed = true;
    }

    /// Marks the queue cancelled and closed.
    pub const fn cancel(&mut self) {
        self.cancelled = true;
        self.closed = true;
    }

    /// Attempts bounded admission; this method never waits.
    pub fn try_accept(
        &mut self,
        encoded_bytes: usize,
        limits: RmiLimits,
    ) -> Result<QueueAdmission, QueueError> {
        if self.cancelled {
            return Err(QueueError::Cancelled);
        }
        if self.closed {
            return Err(QueueError::Closed);
        }
        match self.credit.reserve(encoded_bytes, limits) {
            Ok(()) => Ok(QueueAdmission::Accepted),
            Err(QueueError::Full { .. }) => Ok(QueueAdmission::Full),
            Err(error) => Err(error),
        }
    }
}

/// A JTL attribute retained exactly as UTF-8 text.
#[derive(Clone, Eq, PartialEq)]
pub struct JtlAttribute {
    /// Attribute name.
    pub name: String,
    /// Attribute value, including an explicitly present empty value.
    pub value: String,
}

impl JtlAttribute {
    /// Creates an attribute.
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

impl fmt::Debug for JtlAttribute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JtlAttribute")
            .field("name_len", &self.name.len())
            .field("value_len", &self.value.len())
            .finish()
    }
}

/// A bounded opaque JTL child node.  Unknown elements are retained instead
/// of being discarded; the encoder/decoder enforce the negotiated depth and
/// child/attribute counts.
#[derive(Clone, Eq, PartialEq)]
pub struct JtlNode {
    /// Element name.
    pub name: String,
    /// Ordered attributes.
    pub attributes: Vec<JtlAttribute>,
    /// Optional raw text bytes; binary data remains binary.
    pub text: Option<Vec<u8>>,
    /// Ordered child elements.
    pub children: Vec<JtlNode>,
}

impl JtlNode {
    /// Creates an empty element node.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            attributes: Vec::new(),
            text: None,
            children: Vec::new(),
        }
    }
}

impl fmt::Debug for JtlNode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JtlNode")
            .field("name_len", &self.name.len())
            .field("attributes", &self.attributes.len())
            .field("text_len", &self.text.as_ref().map(Vec::len))
            .field("children", &self.children.len())
            .finish()
    }
}

/// JTL wire metadata needed for lossless result projection.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct JtlMetadata {
    /// `<sample>`/`<httpSample>` (or another preserved element) name.
    pub sample_element: Option<String>,
    /// Ordered sample attributes, including unknown attributes.
    pub attributes: Vec<JtlAttribute>,
    /// Ordered sample child nodes, including unknown nodes.
    pub children: Vec<JtlNode>,
    /// Root attributes retained when this result carries root context.
    pub root_attributes: Vec<JtlAttribute>,
    /// Root children before this sample.
    pub root_children: Vec<JtlNode>,
    /// Root children after this sample.
    pub root_children_after: Vec<JtlNode>,
}

impl fmt::Debug for JtlMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JtlMetadata")
            .field(
                "sample_element_len",
                &self.sample_element.as_ref().map(String::len),
            )
            .field("attributes", &self.attributes.len())
            .field("children", &self.children.len())
            .field("root_attributes", &self.root_attributes.len())
            .field("root_children", &self.root_children.len())
            .field("root_children_after", &self.root_children_after.len())
            .finish()
    }
}

/// Distinct JMeter control flags attached to a sample result.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct SampleFlags {
    /// Stop the current worker thread.
    pub stop_thread: bool,
    /// Gracefully stop the test.
    pub stop_test: bool,
    /// Immediately stop the test.
    pub stop_test_now: bool,
    /// Start the next loop.
    pub start_next_loop: bool,
    /// Ignore this result in result consumers.
    pub ignored: bool,
    /// Optional logical action; this is not collapsed into the booleans.
    pub logical_action: Option<LogicalAction>,
}

/// Logical action independent of stop flags.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum LogicalAction {
    /// Continue normal execution.
    Continue = 1,
    /// Start the next loop iteration.
    StartNextIteration = 2,
    /// Stop the current thread.
    StopThread = 3,
    /// Gracefully stop the test.
    StopTest = 4,
    /// Immediately stop the test.
    StopTestNow = 5,
}

impl LogicalAction {
    fn from_wire(value: u8) -> Result<Self, RmiDecodeError> {
        match value {
            1 => Ok(Self::Continue),
            2 => Ok(Self::StartNextIteration),
            3 => Ok(Self::StopThread),
            4 => Ok(Self::StopTest),
            5 => Ok(Self::StopTestNow),
            other => Err(RmiDecodeError::InvalidEnum {
                field: "logical action",
                value: other as u64,
            }),
        }
    }
}

/// Assertion projection retaining independent failure/error/message states.
#[derive(Clone, Eq, PartialEq)]
pub struct WireAssertion {
    /// Assertion name.
    pub name: String,
    /// Whether the assertion failed.
    pub failure: bool,
    /// Whether assertion evaluation errored.
    pub error: bool,
    /// Optional failure message, preserving present-empty.
    pub failure_message: Option<String>,
    /// Optional error message, preserving present-empty.
    pub error_message: Option<String>,
}

impl WireAssertion {
    /// Creates a passing assertion.
    pub fn passed(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            failure: false,
            error: false,
            failure_message: None,
            error_message: None,
        }
    }
}

impl fmt::Debug for WireAssertion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WireAssertion")
            .field("name_len", &self.name.len())
            .field("failure", &self.failure)
            .field("error", &self.error)
            .field(
                "failure_message_len",
                &self.failure_message.as_ref().map(String::len),
            )
            .field(
                "error_message_len",
                &self.error_message.as_ref().map(String::len),
            )
            .finish()
    }
}

/// A selected JMeter variable, retaining absent versus present-empty values.
#[derive(Clone, Eq, PartialEq)]
pub struct WireVariable {
    /// Variable name.
    pub name: String,
    /// `None` means selected-but-absent; `Some("")` is present-empty.
    pub value: Option<String>,
}

impl WireVariable {
    /// Creates an absent selected variable.
    pub fn absent(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: None,
        }
    }

    /// Creates a present variable.
    pub fn present(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: Some(value.into()),
        }
    }
}

impl fmt::Debug for WireVariable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WireVariable")
            .field("name_len", &self.name.len())
            .field("value_len", &self.value.as_ref().map(String::len))
            .finish()
    }
}

/// Complete bounded sample-result/JTL projection.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct WireSampleResult {
    /// Optional label, preserving an absent label.
    pub label: Option<String>,
    /// Serialized timestamp.
    pub timestamp: Option<i64>,
    /// Sample start timestamp.
    pub start_time: Option<i64>,
    /// Sample end timestamp.
    pub end_time: Option<i64>,
    /// Elapsed milliseconds.
    pub elapsed: Option<u64>,
    /// Latency milliseconds.
    pub latency: Option<u64>,
    /// Connect-time milliseconds.
    pub connect_time: Option<u64>,
    /// Idle-time milliseconds.
    pub idle_time: Option<u64>,
    /// Success flag.
    pub success: Option<bool>,
    /// Response code text.
    pub response_code: Option<String>,
    /// Response message text.
    pub response_message: Option<String>,
    /// Sample failure message.
    pub failure_message: Option<String>,
    /// JTL data type (`text`, `bin`, or an extension spelling).
    pub data_type: Option<String>,
    /// Response/request data encoding.
    pub data_encoding: Option<String>,
    /// Request body bytes.
    pub request_data: Option<Vec<u8>>,
    /// Response body bytes.
    pub response_data: Option<Vec<u8>>,
    /// Raw request headers.
    pub request_headers: Option<String>,
    /// Raw response headers.
    pub response_headers: Option<String>,
    /// Sampler data text.
    pub sampler_data: Option<String>,
    /// Response-file reference.
    pub response_file: Option<String>,
    /// Sampler URL text.
    pub url: Option<String>,
    /// Received byte count.
    pub received_bytes: Option<u64>,
    /// Sent byte count.
    pub sent_bytes: Option<u64>,
    /// Active threads in the group.
    pub group_threads: Option<u64>,
    /// Active threads globally.
    pub all_threads: Option<u64>,
    /// Sample count.
    pub sample_count: Option<u64>,
    /// Error count.
    pub error_count: Option<u64>,
    /// Independent result control flags.
    pub flags: SampleFlags,
    /// Thread identity attached to the JTL record.
    pub thread_name: Option<String>,
    /// Host identity attached to the JTL record.
    pub host: Option<String>,
    /// Selected variables.
    pub variables: Vec<WireVariable>,
    /// Assertion results.
    pub assertions: Vec<WireAssertion>,
    /// Nested sub-results in source order.
    pub sub_results: Vec<WireSampleResult>,
    /// Unknown and known JTL wire metadata.
    pub jtl: JtlMetadata,
}

impl fmt::Debug for WireSampleResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WireSampleResult")
            .field("label_len", &self.label.as_ref().map(String::len))
            .field("timestamp", &self.timestamp)
            .field("start_time", &self.start_time)
            .field("end_time", &self.end_time)
            .field("elapsed", &self.elapsed)
            .field("latency", &self.latency)
            .field("connect_time", &self.connect_time)
            .field("idle_time", &self.idle_time)
            .field("success", &self.success)
            .field("response_code_present", &self.response_code.is_some())
            .field("response_message_present", &self.response_message.is_some())
            .field("failure_message_present", &self.failure_message.is_some())
            .field("data_type_len", &self.data_type.as_ref().map(String::len))
            .field(
                "data_encoding_len",
                &self.data_encoding.as_ref().map(String::len),
            )
            .field(
                "request_data_len",
                &self.request_data.as_ref().map(Vec::len),
            )
            .field(
                "response_data_len",
                &self.response_data.as_ref().map(Vec::len),
            )
            .field(
                "request_headers_len",
                &self.request_headers.as_ref().map(String::len),
            )
            .field(
                "response_headers_len",
                &self.response_headers.as_ref().map(String::len),
            )
            .field(
                "sampler_data_len",
                &self.sampler_data.as_ref().map(String::len),
            )
            .field(
                "response_file_len",
                &self.response_file.as_ref().map(String::len),
            )
            .field("url_len", &self.url.as_ref().map(String::len))
            .field("received_bytes", &self.received_bytes)
            .field("sent_bytes", &self.sent_bytes)
            .field("group_threads", &self.group_threads)
            .field("all_threads", &self.all_threads)
            .field("sample_count", &self.sample_count)
            .field("error_count", &self.error_count)
            .field("flags", &self.flags)
            .field(
                "thread_name_len",
                &self.thread_name.as_ref().map(String::len),
            )
            .field("host_len", &self.host.as_ref().map(String::len))
            .field("variables", &self.variables.len())
            .field("assertions", &self.assertions.len())
            .field("sub_results", &self.sub_results.len())
            .field("jtl", &self.jtl)
            .finish()
    }
}

impl JtlMetadata {
    fn validate(&self, limits: RmiLimits) -> Result<(), SampleValidationError> {
        if let Some(name) = &self.sample_element {
            validate_text(name, limits.max_string_bytes, "JTL sample element")
                .map_err(SampleValidationError::Identity)?;
        }
        validate_attributes(&self.attributes, limits)?;
        validate_attributes(&self.root_attributes, limits)?;
        let mut node_count = 0_usize;
        validate_nodes(&self.children, limits, 1, &mut node_count)?;
        validate_nodes(&self.root_children, limits, 1, &mut node_count)?;
        validate_nodes(&self.root_children_after, limits, 1, &mut node_count)
    }
}

fn validate_attributes(
    attributes: &[JtlAttribute],
    limits: RmiLimits,
) -> Result<(), SampleValidationError> {
    if attributes.len() > limits.max_attributes {
        return Err(SampleValidationError::Count {
            field: "JTL attributes",
            actual: attributes.len(),
            maximum: limits.max_attributes,
        });
    }
    for attribute in attributes {
        validate_text(
            &attribute.name,
            limits.max_string_bytes,
            "JTL attribute name",
        )
        .map_err(SampleValidationError::Identity)?;
        if attribute.value.len() > limits.max_string_bytes {
            return Err(SampleValidationError::FieldTooLong {
                field: "JTL attribute value",
                actual: attribute.value.len(),
                maximum: limits.max_string_bytes,
            });
        }
    }
    Ok(())
}

fn validate_nodes(
    nodes: &[JtlNode],
    limits: RmiLimits,
    depth: usize,
    node_count: &mut usize,
) -> Result<(), SampleValidationError> {
    if depth > limits.max_sample_depth {
        return Err(SampleValidationError::Depth {
            actual: depth,
            maximum: limits.max_sample_depth,
        });
    }
    if nodes.len() > limits.max_children {
        return Err(SampleValidationError::Count {
            field: "JTL children",
            actual: nodes.len(),
            maximum: limits.max_children,
        });
    }
    for node in nodes {
        *node_count = node_count.saturating_add(1);
        if *node_count > limits.max_sample_nodes {
            return Err(SampleValidationError::Count {
                field: "JTL nodes",
                actual: *node_count,
                maximum: limits.max_sample_nodes,
            });
        }
        validate_text(&node.name, limits.max_string_bytes, "JTL node name")
            .map_err(SampleValidationError::Identity)?;
        validate_attributes(&node.attributes, limits)?;
        if let Some(text) = &node.text
            && text.len() > limits.max_bytes_field
        {
            return Err(SampleValidationError::FieldTooLong {
                field: "JTL node text",
                actual: text.len(),
                maximum: limits.max_bytes_field,
            });
        }
        validate_nodes(&node.children, limits, depth.saturating_add(1), node_count)?;
    }
    Ok(())
}

impl WireSampleResult {
    /// Validates every bounded field and the complete hierarchy.
    pub fn validate(&self, limits: RmiLimits) -> Result<(), SampleValidationError> {
        limits.validate().map_err(SampleValidationError::Limits)?;
        let mut stack = vec![(self, 1_usize)];
        let mut nodes = 0_usize;
        while let Some((result, depth)) = stack.pop() {
            nodes = nodes.saturating_add(1);
            if nodes > limits.max_sample_nodes {
                return Err(SampleValidationError::Count {
                    field: "sample nodes",
                    actual: nodes,
                    maximum: limits.max_sample_nodes,
                });
            }
            if depth > limits.max_sample_depth {
                return Err(SampleValidationError::Depth {
                    actual: depth,
                    maximum: limits.max_sample_depth,
                });
            }
            for (value, field) in [
                (&result.label, "sample label"),
                (&result.response_code, "response code"),
                (&result.response_message, "response message"),
                (&result.failure_message, "failure message"),
                (&result.data_type, "data type"),
                (&result.data_encoding, "data encoding"),
                (&result.request_headers, "request headers"),
                (&result.response_headers, "response headers"),
                (&result.sampler_data, "sampler data"),
                (&result.response_file, "response file"),
                (&result.url, "URL"),
                (&result.thread_name, "thread name"),
                (&result.host, "host"),
            ] {
                if let Some(value) = value
                    && value.len() > limits.max_string_bytes
                {
                    return Err(SampleValidationError::FieldTooLong {
                        field,
                        actual: value.len(),
                        maximum: limits.max_string_bytes,
                    });
                }
            }
            for (value, field) in [
                (&result.request_data, "request data"),
                (&result.response_data, "response data"),
            ] {
                if let Some(value) = value
                    && value.len() > limits.max_bytes_field
                {
                    return Err(SampleValidationError::FieldTooLong {
                        field,
                        actual: value.len(),
                        maximum: limits.max_bytes_field,
                    });
                }
            }
            if result.variables.len() > limits.max_variables {
                return Err(SampleValidationError::Count {
                    field: "sample variables",
                    actual: result.variables.len(),
                    maximum: limits.max_variables,
                });
            }
            for variable in &result.variables {
                validate_text(&variable.name, limits.max_string_bytes, "variable name")
                    .map_err(SampleValidationError::Identity)?;
                if let Some(value) = &variable.value
                    && value.len() > limits.max_string_bytes
                {
                    return Err(SampleValidationError::FieldTooLong {
                        field: "variable value",
                        actual: value.len(),
                        maximum: limits.max_string_bytes,
                    });
                }
            }
            if result.assertions.len() > limits.max_assertions {
                return Err(SampleValidationError::Count {
                    field: "assertions",
                    actual: result.assertions.len(),
                    maximum: limits.max_assertions,
                });
            }
            for assertion in &result.assertions {
                validate_text(&assertion.name, limits.max_string_bytes, "assertion name")
                    .map_err(SampleValidationError::Identity)?;
                for (value, field) in [
                    (&assertion.failure_message, "assertion failure message"),
                    (&assertion.error_message, "assertion error message"),
                ] {
                    if let Some(value) = value
                        && value.len() > limits.max_string_bytes
                    {
                        return Err(SampleValidationError::FieldTooLong {
                            field,
                            actual: value.len(),
                            maximum: limits.max_string_bytes,
                        });
                    }
                }
            }
            result.jtl.validate(limits)?;
            if result.sub_results.len() > limits.max_children {
                return Err(SampleValidationError::Count {
                    field: "sub-results",
                    actual: result.sub_results.len(),
                    maximum: limits.max_children,
                });
            }
            for child in result.sub_results.iter().rev() {
                stack.push((child, depth.saturating_add(1)));
            }
        }
        Ok(())
    }
}

/// Sample-result validation errors.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum SampleValidationError {
    /// A negotiated limit declaration is invalid.
    Limits(RmiLimitError),
    /// An identity/text field is invalid.
    Identity(IdentityError),
    /// A field exceeds the negotiated bound.
    FieldTooLong {
        /// Field name.
        field: &'static str,
        /// Actual bytes.
        actual: usize,
        /// Maximum bytes.
        maximum: usize,
    },
    /// A count exceeds the negotiated bound.
    Count {
        /// Count category.
        field: &'static str,
        /// Actual count.
        actual: usize,
        /// Maximum count.
        maximum: usize,
    },
    /// Hierarchy or child-node depth exceeds the negotiated bound.
    Depth {
        /// Actual depth.
        actual: usize,
        /// Maximum depth.
        maximum: usize,
    },
}

impl fmt::Display for SampleValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Limits(error) => error.fmt(formatter),
            Self::Identity(error) => error.fmt(formatter),
            Self::FieldTooLong {
                field,
                actual,
                maximum,
            }
            | Self::Count {
                field,
                actual,
                maximum,
            } => {
                write!(formatter, "{field} {actual} exceeds {maximum}")
            }
            Self::Depth { actual, maximum } => {
                write!(formatter, "sample depth {actual} exceeds {maximum}")
            }
        }
    }
}

impl std::error::Error for SampleValidationError {}

/// The sender selected by JMeter's pinned `SampleSender` factory.
///
/// `Hold` is intentionally absent: the pinned distribution exposes the class
/// but not a usable factory/constructor contract.  A custom provider must be
/// represented by a separately negotiated capability rather than guessed by
/// this closed schema.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum SenderMode {
    /// Synchronous, one-event delivery.
    Standard = 1,
    /// Threshold/time based batching.
    Batch = 2,
    /// Statistical aggregation sender.
    Statistical = 3,
    /// Synchronous response-stripping sender.
    Stripped = 4,
    /// Batched response-stripping sender.
    StrippedBatch = 5,
    /// Daemon-queue asynchronous sender.
    Asynch = 6,
    /// Response-stripping asynchronous sender.
    StrippedAsynch = 7,
    /// Disk-backed sender.
    DiskStore = 8,
    /// Response-stripping disk-backed sender.
    StrippedDiskStore = 9,
}

impl SenderMode {
    /// Stable capability identifier required before a positive drain proof
    /// can be accepted for this sender.  The pinned asynchronous modes have
    /// no reviewed completion hook and therefore return `None`.
    pub const fn drain_proof_capability(self) -> Option<&'static str> {
        match self {
            Self::Asynch | Self::StrippedAsynch => None,
            Self::Standard => Some("rmi.sender.standard.drain-proof"),
            Self::Batch => Some("rmi.sender.batch.drain-proof"),
            Self::Statistical => Some("rmi.sender.statistical.drain-proof"),
            Self::Stripped => Some("rmi.sender.stripped.drain-proof"),
            Self::StrippedBatch => Some("rmi.sender.stripped-batch.drain-proof"),
            Self::DiskStore => Some("rmi.sender.disk-store.drain-proof"),
            Self::StrippedDiskStore => Some("rmi.sender.stripped-disk-store.drain-proof"),
        }
    }

    /// Returns whether this sender may emit a callback during the bounded
    /// post-`TestEnded` drain phase under the current pinned contract.
    pub const fn allows_late_drain_callback(self) -> bool {
        self.drain_proof_capability().is_some()
    }

    fn from_wire(value: u8) -> Result<Self, RmiDecodeError> {
        match value {
            1 => Ok(Self::Standard),
            2 => Ok(Self::Batch),
            3 => Ok(Self::Statistical),
            4 => Ok(Self::Stripped),
            5 => Ok(Self::StrippedBatch),
            6 => Ok(Self::Asynch),
            7 => Ok(Self::StrippedAsynch),
            8 => Ok(Self::DiskStore),
            9 => Ok(Self::StrippedDiskStore),
            other => Err(RmiDecodeError::InvalidEnum {
                field: "sender mode",
                value: other as u64,
            }),
        }
    }
}

/// Which RemoteSampleListener callback delivered a result projection.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum DeliveryKind {
    /// A single `sampleOccurred` callback.
    SampleOccurred = 1,
    /// A first-class `processBatch` callback.
    ProcessBatch = 2,
}

impl DeliveryKind {
    fn from_wire(value: u8) -> Result<Self, RmiDecodeError> {
        match value {
            1 => Ok(Self::SampleOccurred),
            2 => Ok(Self::ProcessBatch),
            other => Err(RmiDecodeError::InvalidEnum {
                field: "delivery kind",
                value: other as u64,
            }),
        }
    }
}

/// Java callback overload used for test start/end notifications.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum LifecycleOverload {
    /// The no-host overload; host must be absent.
    NoHost = 1,
    /// The host-argument overload; the host presence state is retained.
    HostArgument = 2,
}

impl LifecycleOverload {
    fn from_wire(value: u8) -> Result<Self, RmiDecodeError> {
        match value {
            1 => Ok(Self::NoHost),
            2 => Ok(Self::HostArgument),
            other => Err(RmiDecodeError::InvalidEnum {
                field: "lifecycle overload",
                value: other as u64,
            }),
        }
    }
}

/// Host presence at callback time.  `Null` is distinct from an omitted host
/// and from a present-but-empty host string.
#[derive(Clone, Default, Eq, Hash, PartialEq)]
pub enum HostPresence {
    /// No host argument was supplied.
    #[default]
    Absent,
    /// The host argument was supplied with a Java null value.
    Null,
    /// The host argument was supplied with this string (which may be empty).
    Present(String),
}

impl fmt::Debug for HostPresence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Absent => formatter.write_str("HostPresence::Absent"),
            Self::Null => formatter.write_str("HostPresence::Null"),
            Self::Present(value) => formatter
                .debug_struct("HostPresence::Present")
                .field("len", &value.len())
                .finish(),
        }
    }
}

/// A worker failure's terminal phase.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum FailurePhase {
    /// An ordinary worker/run failure.
    Failed = 1,
    /// The run was explicitly aborted before normal completion.
    Aborted = 2,
    /// Cancellation ended the worker stream.
    Cancelled = 3,
    /// The authoritative deadline elapsed.
    TimedOut = 4,
    /// The worker disappeared without a semantic completion result.
    Crashed = 5,
    /// A frame, identity, or lifecycle rule was violated.
    ProtocolError = 6,
}

impl FailurePhase {
    fn from_wire(value: u8) -> Result<Self, RmiDecodeError> {
        match value {
            1 => Ok(Self::Failed),
            2 => Ok(Self::Aborted),
            3 => Ok(Self::Cancelled),
            4 => Ok(Self::TimedOut),
            5 => Ok(Self::Crashed),
            6 => Ok(Self::ProtocolError),
            other => Err(RmiDecodeError::InvalidEnum {
                field: "failure phase",
                value: other as u64,
            }),
        }
    }
}

/// A bounded reason that makes a pre-start retry safe.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum RetryReason {
    /// The worker registry was unavailable before configure admission.
    WorkerUnavailable = 1,
    /// A worker-local resource was missing before useful execution.
    MissingResource = 2,
    /// Transport setup failed before useful execution.
    TransportBeforeStart = 3,
    /// A declared capability was unavailable before useful execution.
    CapabilityUnavailable = 4,
}

impl RetryReason {
    fn from_wire(value: u8) -> Result<Self, RmiDecodeError> {
        match value {
            1 => Ok(Self::WorkerUnavailable),
            2 => Ok(Self::MissingResource),
            3 => Ok(Self::TransportBeforeStart),
            4 => Ok(Self::CapabilityUnavailable),
            other => Err(RmiDecodeError::InvalidEnum {
                field: "retry reason",
                value: other as u64,
            }),
        }
    }
}

/// Configuration/start phase carried by a final retry disposition.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum RetryPhase {
    /// Configure admission was attempted.
    Configure = 1,
    /// Start admission was attempted.
    Start = 2,
    /// A callback or later phase was reached.
    Callback = 3,
}

impl RetryPhase {
    fn from_wire(value: u8) -> Result<Self, RmiDecodeError> {
        match value {
            1 => Ok(Self::Configure),
            2 => Ok(Self::Start),
            3 => Ok(Self::Callback),
            other => Err(RmiDecodeError::InvalidEnum {
                field: "retry phase",
                value: other as u64,
            }),
        }
    }
}

/// Certainty attached to a non-retryable result.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum OutcomeCertainty {
    /// Useful work definitely did not begin, but this disposition is still
    /// final because the phase is not retry-safe.
    NotStarted = 1,
    /// Useful work began and cannot be repeated in this run.
    Started = 2,
    /// The outcome cannot be established safely.
    Unknown = 3,
}

impl OutcomeCertainty {
    fn from_wire(value: u8) -> Result<Self, RmiDecodeError> {
        match value {
            1 => Ok(Self::NotStarted),
            2 => Ok(Self::Started),
            3 => Ok(Self::Unknown),
            other => Err(RmiDecodeError::InvalidEnum {
                field: "outcome certainty",
                value: other as u64,
            }),
        }
    }
}

/// Closed retry disposition.  A peer reports an observation but cannot grant
/// itself retry permission; only the pre-start state machine can accept the
/// `PreStartSafe` variant.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RetryDisposition {
    /// Safe to retry before configure/start useful work was admitted.
    PreStartSafe {
        /// Why the pre-start attempt is safe to repeat.
        reason: RetryReason,
        /// One-based attempt number for the next generation.
        next_attempt: u32,
    },
    /// Retry is forbidden after a useful phase or a final classified result.
    FinalNonRetryable {
        /// Phase that made retry unsafe.
        phase: RetryPhase,
        /// Certainty of the attempted operation.
        outcome_certainty: OutcomeCertainty,
    },
    /// No safe outcome is known; replacement is forbidden.
    PoisonedUnknownOutcome,
}

impl RetryDisposition {
    const fn is_pre_start_safe(self) -> bool {
        matches!(self, Self::PreStartSafe { .. })
    }
}

/// Event and byte accounting carried by TestEnded and Terminal proofs.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct StreamAccounting {
    /// Callback events observed by the helper.
    pub delivered_events: u64,
    /// Callback events accepted by the result router.
    pub accepted_events: u64,
    /// Callback events acknowledged by the receiver.
    pub acknowledged_events: u64,
    /// Encoded callback bytes observed by the helper.
    pub delivered_bytes: u64,
    /// Encoded callback bytes accepted by the result router.
    pub accepted_bytes: u64,
    /// Encoded callback bytes acknowledged by the receiver.
    pub acknowledged_bytes: u64,
    /// Bridge events still pending at completion.
    pub pending_bridge_events: u64,
    /// Sender events still pending at completion.
    pub pending_sender_events: u64,
    /// Incomplete blobs still pending at completion.
    pub pending_blobs: u64,
}

impl StreamAccounting {
    const fn is_ordered(self) -> bool {
        self.accepted_events <= self.delivered_events
            && self.acknowledged_events <= self.accepted_events
            && self.accepted_bytes <= self.delivered_bytes
            && self.acknowledged_bytes <= self.accepted_bytes
    }

    const fn is_fully_acked(self) -> bool {
        self.delivered_events == self.accepted_events
            && self.accepted_events == self.acknowledged_events
            && self.delivered_bytes == self.accepted_bytes
            && self.accepted_bytes == self.acknowledged_bytes
            && self.pending_bridge_events == 0
            && self.pending_sender_events == 0
            && self.pending_blobs == 0
    }
}

/// Why a positive sender drain proof is unavailable on a non-success path.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum SenderProofAbsenceReason {
    /// No reviewed helper operation exists for the selected sender.
    HelperOperationUnavailable = 1,
    /// Sender terminated before its completion boundary was observed.
    SenderFailed = 2,
    /// Cancellation stopped proof collection.
    Cancelled = 3,
    /// The authoritative deadline stopped proof collection.
    TimedOut = 4,
    /// The worker crashed before proof collection.
    WorkerCrashed = 5,
    /// A protocol violation poisoned proof collection.
    ProtocolError = 6,
}

impl SenderProofAbsenceReason {
    fn from_wire(value: u8) -> Result<Self, RmiDecodeError> {
        match value {
            1 => Ok(Self::HelperOperationUnavailable),
            2 => Ok(Self::SenderFailed),
            3 => Ok(Self::Cancelled),
            4 => Ok(Self::TimedOut),
            5 => Ok(Self::WorkerCrashed),
            6 => Ok(Self::ProtocolError),
            other => Err(RmiDecodeError::InvalidEnum {
                field: "sender proof absence reason",
                value: other as u64,
            }),
        }
    }
}

/// Why a stream still requires a positive sender proof.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum SenderProofRequirement {
    /// A source-reviewed mode-specific completion hook is required.
    ModeSpecificHook = 1,
    /// Asynch requires a separately reviewed sentinel/join helper operation.
    AsynchHelperOperation = 2,
}

impl SenderProofRequirement {
    fn from_wire(value: u8) -> Result<Self, RmiDecodeError> {
        match value {
            1 => Ok(Self::ModeSpecificHook),
            2 => Ok(Self::AsynchHelperOperation),
            other => Err(RmiDecodeError::InvalidEnum {
                field: "sender proof requirement",
                value: other as u64,
            }),
        }
    }
}

/// Positive, mode-specific observation of sender completion.
#[derive(Clone, Eq, PartialEq)]
pub struct SenderDrainEvidence {
    /// Sender mode observed by the helper.
    pub sender: SenderMode,
    /// Lifecycle generation that produced the proof.
    pub generation: u64,
    /// Last delivered callback ordinal at the completion boundary.
    pub final_delivered_event_ordinal: u64,
    /// Cumulative emitted callback events.
    pub emitted_events: u64,
    /// Cumulative accepted callback events.
    pub accepted_events: u64,
    /// Cumulative acknowledged callback events.
    pub acknowledged_events: u64,
    /// Cumulative emitted callback bytes.
    pub emitted_bytes: u64,
    /// Cumulative accepted callback bytes.
    pub accepted_bytes: u64,
    /// Cumulative acknowledged callback bytes.
    pub acknowledged_bytes: u64,
    /// Pending sender-queue event count at the proof boundary.
    pub pending_sender_events: u64,
    /// Pending disk/spool event count at the proof boundary.
    pub pending_disk_events: u64,
    /// Identity of the reviewed completion hook.
    pub completion_hook: String,
    /// Digest of the helper observation transcript.
    pub proof_digest: Sha256Digest,
}

impl fmt::Debug for SenderDrainEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SenderDrainEvidence")
            .field("sender", &self.sender)
            .field("generation", &self.generation)
            .field(
                "final_delivered_event_ordinal",
                &self.final_delivered_event_ordinal,
            )
            .field("emitted_events", &self.emitted_events)
            .field("accepted_events", &self.accepted_events)
            .field("acknowledged_events", &self.acknowledged_events)
            .field("emitted_bytes", &self.emitted_bytes)
            .field("accepted_bytes", &self.accepted_bytes)
            .field("acknowledged_bytes", &self.acknowledged_bytes)
            .field("pending_sender_events", &self.pending_sender_events)
            .field("pending_disk_events", &self.pending_disk_events)
            .field("completion_hook_len", &self.completion_hook.len())
            .field("proof_digest", &self.proof_digest)
            .finish()
    }
}

/// Sender completion proof or a typed statement that proof is still required
/// or unavailable.  In particular, Asynch cannot be upgraded to `Proven` by
/// observing TestEnded, EOF, queue size, delay, or quiescence.
#[derive(Clone, Eq, PartialEq)]
pub enum SenderDrainProof {
    /// Positive observation from a reviewed helper operation.
    Proven(SenderDrainEvidence),
    /// The selected sender still requires a positive mode-specific operation.
    Required {
        /// Sender needing the proof.
        sender: SenderMode,
        /// Why the operation is required.
        reason: SenderProofRequirement,
    },
    /// A proof is unavailable on this non-success path.
    Unavailable {
        /// Sender for which proof could not be obtained.
        sender: SenderMode,
        /// Bounded absence reason.
        reason: SenderProofAbsenceReason,
    },
}

impl fmt::Debug for SenderDrainProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Proven(value) => formatter.debug_tuple("Proven").field(value).finish(),
            Self::Required { sender, reason } => formatter
                .debug_struct("Required")
                .field("sender", sender)
                .field("reason", reason)
                .finish(),
            Self::Unavailable { sender, reason } => formatter
                .debug_struct("Unavailable")
                .field("sender", sender)
                .field("reason", reason)
                .finish(),
        }
    }
}

impl SenderDrainProof {
    /// Returns the proof requirement for a sender mode.  Asynchronous modes
    /// are explicitly unavailable until a reviewed helper operation exists.
    pub const fn required(sender: SenderMode) -> Self {
        let reason = match sender {
            SenderMode::Asynch | SenderMode::StrippedAsynch => {
                SenderProofRequirement::AsynchHelperOperation
            }
            _ => SenderProofRequirement::ModeSpecificHook,
        };
        Self::Required { sender, reason }
    }

    /// Marks a sender proof unavailable because no reviewed helper operation
    /// can observe its completion boundary.  This is the only valid default
    /// for pinned Asynch/StrippedAsynch completion; delay, EOF, queue polling,
    /// and TestEnded cannot be promoted to proof.
    pub const fn unavailable_without_helper(sender: SenderMode) -> Self {
        Self::Unavailable {
            sender,
            reason: SenderProofAbsenceReason::HelperOperationUnavailable,
        }
    }

    /// Returns the sender identity carried by this proof state.
    pub const fn sender(&self) -> SenderMode {
        match self {
            Self::Proven(value) => value.sender,
            Self::Required { sender, .. } | Self::Unavailable { sender, .. } => *sender,
        }
    }

    const fn is_proven(&self) -> bool {
        matches!(self, Self::Proven(_))
    }
}

/// Explicit reason for omitting a TestEnded callback on a non-success path.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum TestEndedAbsenceReason {
    /// Worker failure occurred before JMeter delivered TestEnded.
    WorkerFailure = 1,
    /// Cancellation occurred before JMeter delivered TestEnded.
    CancelledBeforeCallback = 2,
    /// The deadline elapsed before JMeter delivered TestEnded.
    TimedOutBeforeCallback = 3,
    /// The worker crashed before JMeter delivered TestEnded.
    CrashedBeforeCallback = 4,
    /// The controller explicitly aborted before TestEnded.
    AbortedBeforeCallback = 5,
    /// The stream ended at EOF before TestEnded.
    EofBeforeCallback = 6,
    /// A protocol violation ended the stream before TestEnded.
    ProtocolErrorBeforeCallback = 7,
}

impl TestEndedAbsenceReason {
    fn from_wire(value: u8) -> Result<Self, RmiDecodeError> {
        match value {
            1 => Ok(Self::WorkerFailure),
            2 => Ok(Self::CancelledBeforeCallback),
            3 => Ok(Self::TimedOutBeforeCallback),
            4 => Ok(Self::CrashedBeforeCallback),
            5 => Ok(Self::AbortedBeforeCallback),
            6 => Ok(Self::EofBeforeCallback),
            7 => Ok(Self::ProtocolErrorBeforeCallback),
            other => Err(RmiDecodeError::InvalidEnum {
                field: "TestEnded absence reason",
                value: other as u64,
            }),
        }
    }
}

/// Event kind tags in canonical wire order.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum EventKind {
    /// Worker/controller identity and queue readiness.
    Ready = 1,
    /// Test execution began.
    TestStarted = 2,
    /// A sampler started.
    SampleStarted = 3,
    /// A complete sample result occurred.
    SampleOccurred = 4,
    /// A sampler stopped, with its terminal sample outcome.
    SampleStopped = 5,
    /// A bounded group of distinct sample lifecycle events.
    Batch = 6,
    /// A worker failure became observable.
    WorkerFailure = 7,
    /// JMeter delivered its test-ended callback.
    TestEnded = 8,
    /// Exactly-once stream terminal state.
    Terminal = 9,
    /// Absolute queue-credit update.
    Credit = 10,
    /// Acknowledgement of previously accepted stream data.
    Ack = 11,
}

impl EventKind {
    fn from_wire(value: u8) -> Result<Self, RmiDecodeError> {
        match value {
            1 => Ok(Self::Ready),
            2 => Ok(Self::TestStarted),
            3 => Ok(Self::SampleStarted),
            4 => Ok(Self::SampleOccurred),
            5 => Ok(Self::SampleStopped),
            6 => Ok(Self::Batch),
            7 => Ok(Self::WorkerFailure),
            8 => Ok(Self::TestEnded),
            9 => Ok(Self::Terminal),
            10 => Ok(Self::Credit),
            11 => Ok(Self::Ack),
            other => Err(RmiDecodeError::UnknownEventKind(other)),
        }
    }
}

/// Worker readiness declaration.
#[derive(Clone, Eq, PartialEq)]
pub struct Ready {
    /// Identity/profile/artifact declaration.
    pub identity: BridgeIdentity,
    /// Sender mode selected for this stream generation.
    pub sender: SenderMode,
    /// Initial queue credit.
    pub queue: QueueCredit,
    /// Queue policy used for accepted event delivery.
    pub backpressure: BackpressurePolicy,
}

impl fmt::Debug for Ready {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Ready")
            .field("identity", &self.identity)
            .field("sender", &self.sender)
            .field("queue", &self.queue)
            .field("backpressure", &self.backpressure)
            .finish()
    }
}

/// Test-start lifecycle declaration.
#[derive(Clone, Eq, PartialEq)]
pub struct TestStarted {
    /// Java callback overload used for this notification.
    pub overload: LifecycleOverload,
    /// Host argument presence at callback time.
    pub host: HostPresence,
    /// Callback invocation ordinal, independent of frame sequence.
    pub callback_invocation_ordinal: u64,
    /// Stable logical test/run name.
    pub test_id: String,
    /// SHA-256 of the complete JMX bytes transferred to workers.
    pub plan_sha256: Sha256Digest,
    /// Queue credit after test setup.
    pub queue: QueueCredit,
}

impl fmt::Debug for TestStarted {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TestStarted")
            .field("overload", &self.overload)
            .field("host", &self.host)
            .field(
                "callback_invocation_ordinal",
                &self.callback_invocation_ordinal,
            )
            .field("test_id_len", &self.test_id.len())
            .field("plan_sha256", &self.plan_sha256)
            .field("queue", &self.queue)
            .finish()
    }
}

/// Immutable metadata captured from one JMeter `SampleEvent` callback.
///
/// This is deliberately separate from [`WireSampleResult`]: JMeter captures
/// host, thread-group, selected-variable, and transaction state at callback
/// delivery time, and a later callback or sender reduction must not overwrite
/// that snapshot.  Sender modes may omit an entire callback phase, but a
/// phase that is delivered carries its complete snapshot here.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct SampleEventSnapshot {
    /// Thread-group identity captured by the callback.
    pub thread_group: Option<String>,
    /// Host identity captured by the callback.
    pub host: HostPresence,
    /// Selected variables captured by the callback, retaining absent versus
    /// present-empty values.
    pub variables: Vec<WireVariable>,
    /// Whether this callback represented a transaction sample event.
    pub is_transaction: bool,
    /// Optional complete bounded result projection present at callback time.
    /// A missing projection is distinct from a present empty result.
    pub result: Option<WireSampleResult>,
}

impl fmt::Debug for SampleEventSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SampleEventSnapshot")
            .field(
                "thread_group_len",
                &self.thread_group.as_ref().map(String::len),
            )
            .field(
                "host",
                &match &self.host {
                    HostPresence::Absent => "absent",
                    HostPresence::Null => "null",
                    HostPresence::Present(_) => "present",
                },
            )
            .field("variables", &self.variables.len())
            .field("is_transaction", &self.is_transaction)
            .field("result_present", &self.result.is_some())
            .finish()
    }
}

impl SampleEventSnapshot {
    fn validate(&self, limits: RmiLimits) -> Result<(), SampleValidationError> {
        if let Some(value) = &self.thread_group
            && value.len() > limits.max_string_bytes
        {
            return Err(SampleValidationError::FieldTooLong {
                field: "sample event thread group",
                actual: value.len(),
                maximum: limits.max_string_bytes,
            });
        }
        if let HostPresence::Present(value) = &self.host
            && value.len() > limits.max_string_bytes
        {
            return Err(SampleValidationError::FieldTooLong {
                field: "sample event host",
                actual: value.len(),
                maximum: limits.max_string_bytes,
            });
        }
        if self.variables.len() > limits.max_variables {
            return Err(SampleValidationError::Count {
                field: "sample event variables",
                actual: self.variables.len(),
                maximum: limits.max_variables,
            });
        }
        for variable in &self.variables {
            validate_text(
                &variable.name,
                limits.max_string_bytes,
                "sample event variable name",
            )
            .map_err(SampleValidationError::Identity)?;
            if let Some(value) = &variable.value
                && value.len() > limits.max_string_bytes
            {
                return Err(SampleValidationError::FieldTooLong {
                    field: "sample event variable value",
                    actual: value.len(),
                    maximum: limits.max_string_bytes,
                });
            }
        }
        if let Some(result) = &self.result {
            result.validate(limits)?;
        }
        Ok(())
    }
}

/// Sample-start notification.  This is intentionally separate from
/// [`SampleOccurred`] and [`SampleStopped`].
#[derive(Clone, Eq, PartialEq)]
pub struct SampleStarted {
    /// Callback invocation ordinal.  Batch items leave this at zero because
    /// the enclosing ProcessBatch invocation owns the ordinal.
    pub callback_invocation_ordinal: u64,
    /// Delivered-event ordinal.  Batch items leave this at zero because the
    /// enclosing batch declares the first ordinal and event count.
    pub delivered_event_ordinal: u64,
    /// Delivery callback kind for this event.
    pub delivery_kind: DeliveryKind,
    /// Non-zero sampler identity within the stream generation.
    pub sample_id: u64,
    /// Optional parent sample identity.
    pub parent_id: Option<u64>,
    /// Optional label known at sampler start.
    pub label: Option<String>,
    /// Callback-time host/thread/variable/transaction snapshot.
    pub snapshot: SampleEventSnapshot,
}

impl fmt::Debug for SampleStarted {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SampleStarted")
            .field(
                "callback_invocation_ordinal",
                &self.callback_invocation_ordinal,
            )
            .field("delivered_event_ordinal", &self.delivered_event_ordinal)
            .field("delivery_kind", &self.delivery_kind)
            .field("sample_id", &self.sample_id)
            .field("parent_id", &self.parent_id)
            .field("label_len", &self.label.as_ref().map(String::len))
            .field("snapshot", &self.snapshot)
            .finish()
    }
}

/// Complete sample-result notification.
#[derive(Clone, Eq, PartialEq)]
pub struct SampleOccurred {
    /// Callback invocation ordinal.  Batch items leave this at zero.
    pub callback_invocation_ordinal: u64,
    /// Delivered-event ordinal.  Batch items leave this at zero.
    pub delivered_event_ordinal: u64,
    /// Delivery callback kind for this event.
    pub delivery_kind: DeliveryKind,
    /// Sampler identity from [`SampleStarted`].
    pub sample_id: u64,
    /// Full bounded result/JTL projection.
    pub result: WireSampleResult,
    /// Callback-time host/thread/variable/transaction snapshot.
    pub snapshot: SampleEventSnapshot,
}

impl fmt::Debug for SampleOccurred {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SampleOccurred")
            .field(
                "callback_invocation_ordinal",
                &self.callback_invocation_ordinal,
            )
            .field("delivered_event_ordinal", &self.delivered_event_ordinal)
            .field("delivery_kind", &self.delivery_kind)
            .field("sample_id", &self.sample_id)
            .field("result", &self.result)
            .field("snapshot", &self.snapshot)
            .finish()
    }
}

/// Sample-stop notification with an independent outcome and cancellation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum SampleStopOutcome {
    /// Sampler stopped successfully.
    Completed = 1,
    /// Sampler result failed.
    Failed = 2,
    /// Sampler was cancelled.
    Cancelled = 3,
    /// Sampler deadline elapsed.
    TimedOut = 4,
}

impl SampleStopOutcome {
    fn from_wire(value: u8) -> Result<Self, RmiDecodeError> {
        match value {
            1 => Ok(Self::Completed),
            2 => Ok(Self::Failed),
            3 => Ok(Self::Cancelled),
            4 => Ok(Self::TimedOut),
            other => Err(RmiDecodeError::InvalidEnum {
                field: "sample stop outcome",
                value: other as u64,
            }),
        }
    }
}

/// Sample-stop lifecycle notification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SampleStopped {
    /// Callback invocation ordinal.  Batch items leave this at zero.
    pub callback_invocation_ordinal: u64,
    /// Delivered-event ordinal.  Batch items leave this at zero.
    pub delivered_event_ordinal: u64,
    /// Delivery callback kind for this event.
    pub delivery_kind: DeliveryKind,
    /// Sampler identity from [`SampleStarted`].
    pub sample_id: u64,
    /// Distinct stop outcome.
    pub outcome: SampleStopOutcome,
    /// Cancellation state observed at stop.
    pub cancellation: Cancellation,
    /// Callback-time host/thread/variable/transaction snapshot.
    pub snapshot: SampleEventSnapshot,
}

/// One sample lifecycle item embedded in a [`Batch`].
// Sample payloads are intentionally owned inline so callers can validate and
// inspect a complete result without an additional allocation boundary.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Eq, PartialEq)]
pub enum SampleEvent {
    /// Start phase.
    Started(SampleStarted),
    /// Occurred phase.
    Occurred(SampleOccurred),
    /// Stop phase.
    Stopped(SampleStopped),
}

impl SampleEvent {
    /// Returns the event kind without inspecting its payload.
    pub const fn kind(&self) -> EventKind {
        match self {
            Self::Started(_) => EventKind::SampleStarted,
            Self::Occurred(_) => EventKind::SampleOccurred,
            Self::Stopped(_) => EventKind::SampleStopped,
        }
    }
}

impl fmt::Debug for SampleEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Started(value) => formatter.debug_tuple("Started").field(value).finish(),
            Self::Occurred(value) => formatter.debug_tuple("Occurred").field(value).finish(),
            Self::Stopped(value) => formatter.debug_tuple("Stopped").field(value).finish(),
        }
    }
}

/// An item in a batch, retaining independent sequence/request/time-budget data.
#[derive(Clone, Eq, PartialEq)]
pub struct BatchItem {
    /// Stream sequence assigned to this lifecycle item.
    pub sequence: u64,
    /// Control request identity associated with this item.
    pub request_id: u64,
    /// Remaining operation duration at send time.
    pub remaining_duration: RemainingDuration,
    /// Item cancellation state.
    pub cancellation: Cancellation,
    /// One uncollapsed sample lifecycle phase.
    pub event: SampleEvent,
}

impl fmt::Debug for BatchItem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BatchItem")
            .field("sequence", &self.sequence)
            .field("request_id", &self.request_id)
            .field("remaining_duration", &self.remaining_duration)
            .field("cancellation", &self.cancellation)
            .field("event", &self.event)
            .finish()
    }
}

/// Bounded batch of explicit sample lifecycle phases.
#[derive(Clone, Eq, PartialEq)]
pub struct Batch {
    /// Sender identity bound by Ready for this stream generation.
    pub sender: SenderMode,
    /// ProcessBatch callback invocation ordinal.
    pub callback_invocation_ordinal: u64,
    /// First delivered-event ordinal in this nonempty batch.
    pub first_delivered_event_ordinal: u64,
    /// Stable sender-local batch identity.
    pub batch_id: u64,
    /// Explicit callback delivery kind; only ProcessBatch is valid here.
    pub delivery_kind: DeliveryKind,
    /// Declared number of delivered events; must equal `items.len()`.
    pub event_count: u64,
    /// Items in source/order sequence.
    pub items: Vec<BatchItem>,
}

/// An explicit absolute queue-credit update.
///
/// Credit is a control event rather than an implicit side effect of a result
/// callback.  A receiver can therefore apply the same bounded admission
/// policy to synchronous, batch, asynchronous, and disk-backed sender modes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Credit {
    /// Current event and byte credit granted to the sender.
    pub queue: QueueCredit,
}

/// Compatibility spelling for an explicit queue-credit update.
pub type QueueCreditUpdate = Credit;

/// An explicit acknowledgement for accepted stream data.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Ack {
    /// Last stream sequence acknowledged by the receiver.
    pub acknowledged_sequence: u64,
    /// Number of callback events acknowledged through that sequence.
    pub acknowledged_events: u64,
    /// Encoded bytes released by the acknowledgement.
    pub acknowledged_bytes: u64,
}

/// Compatibility spelling for a stream acknowledgement.
pub type QueueAck = Ack;

impl fmt::Debug for Batch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Batch")
            .field("sender", &self.sender)
            .field("items", &self.items.len())
            .finish()
    }
}

/// Stable worker failure categories.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum WorkerFailureCode {
    /// Worker could not accept a stream/operation.
    Unavailable = 1,
    /// Worker failed to resolve local data/dependency.
    MissingResource = 2,
    /// Queue credit was exhausted.
    QueueFull = 3,
    /// A negotiated byte/count/depth bound was exceeded.
    ResourceLimit = 4,
    /// Worker cancelled or timed out.
    Cancelled = 5,
    /// Worker protocol/state violation.
    Protocol = 6,
    /// TLS/RMI setup was unavailable; no fallback is implied.
    Transport = 7,
    /// Other explicitly classified worker failure.
    Other = 8,
}

impl WorkerFailureCode {
    fn from_wire(value: u16) -> Result<Self, RmiDecodeError> {
        match value {
            1 => Ok(Self::Unavailable),
            2 => Ok(Self::MissingResource),
            3 => Ok(Self::QueueFull),
            4 => Ok(Self::ResourceLimit),
            5 => Ok(Self::Cancelled),
            6 => Ok(Self::Protocol),
            7 => Ok(Self::Transport),
            8 => Ok(Self::Other),
            other => Err(RmiDecodeError::InvalidEnum {
                field: "worker failure code",
                value: other as u64,
            }),
        }
    }
}

/// Observable worker failure; message text is diagnostic and bounded.
#[derive(Clone, Eq, PartialEq)]
pub struct WorkerFailure {
    /// Stable worker identity.
    pub worker_id: String,
    /// Machine-readable failure category.
    pub code: WorkerFailureCode,
    /// Explicit terminal phase observed for this worker failure.
    pub phase: FailurePhase,
    /// Closed retry disposition.  A peer cannot grant itself retry permission.
    pub retry: RetryDisposition,
    /// Optional redacted diagnostic text.
    pub message: Option<String>,
}

impl fmt::Debug for WorkerFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkerFailure")
            .field("worker_id_len", &self.worker_id.len())
            .field("code", &self.code)
            .field("phase", &self.phase)
            .field("retry", &self.retry)
            .field("message_len", &self.message.as_ref().map(String::len))
            .finish()
    }
}

/// Test-ended lifecycle declaration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestEnded {
    /// Java callback overload used for this notification.
    pub overload: LifecycleOverload,
    /// Host argument presence at callback time.
    pub host: HostPresence,
    /// Callback invocation ordinal, independent of frame sequence.
    pub callback_invocation_ordinal: u64,
    /// Callback/event and encoded-byte accounting at callback delivery.
    pub accounting: StreamAccounting,
    /// Remaining queue credit at callback delivery.
    pub queue: QueueCredit,
}

/// Exactly-once stream terminal status.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum TerminalStatus {
    /// Successful terminal state after TestEnded and drain.
    Succeeded = 1,
    /// Failed terminal state.
    Failed = 2,
    /// Cancelled terminal state.
    Cancelled = 3,
    /// Deadline terminal state.
    TimedOut = 4,
    /// Protocol/bridge error terminal state.
    ProtocolError = 5,
    /// Worker crashed before a normal completion result.
    Crashed = 6,
    /// Controller explicitly aborted the run.
    Aborted = 7,
}

impl TerminalStatus {
    fn from_wire(value: u8) -> Result<Self, RmiDecodeError> {
        match value {
            1 => Ok(Self::Succeeded),
            2 => Ok(Self::Failed),
            3 => Ok(Self::Cancelled),
            4 => Ok(Self::TimedOut),
            5 => Ok(Self::ProtocolError),
            6 => Ok(Self::Crashed),
            7 => Ok(Self::Aborted),
            other => Err(RmiDecodeError::InvalidEnum {
                field: "terminal status",
                value: other as u64,
            }),
        }
    }
}

/// Exactly-once terminal frame.
#[derive(Clone, Eq, PartialEq)]
pub struct Terminal {
    /// Final status.
    pub status: TerminalStatus,
    /// Optional primary failure retained without replacing earlier failures.
    pub failure: Option<WorkerFailure>,
    /// Callback/event and byte totals at terminal publication.
    pub accounting: StreamAccounting,
    /// Positive sender proof or a typed requirement/absence declaration.
    pub sender_proof: SenderDrainProof,
    /// TestEnded callback ordinal, when TestEnded was delivered.
    pub test_ended_callback_ordinal: Option<u64>,
    /// Explicit reason when TestEnded was absent on a non-success path.
    pub test_ended_absence_reason: Option<TestEndedAbsenceReason>,
    /// Finalized result-router transcript digest; required for success.
    pub router_finalization_digest: Option<Sha256Digest>,
    /// Queue credit after all accepted events crossed the bridge.
    pub queue: QueueCredit,
}

impl fmt::Debug for Terminal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Terminal")
            .field("status", &self.status)
            .field("failure", &self.failure)
            .field("queue", &self.queue)
            .finish()
    }
}

/// All closed version-1 stream event variants.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Eq, PartialEq)]
pub enum StreamEvent {
    /// Readiness/identity event.
    Ready(Ready),
    /// Test-start event.
    TestStarted(TestStarted),
    /// Distinct sample-start event.
    SampleStarted(SampleStarted),
    /// Distinct complete sample occurrence.
    SampleOccurred(SampleOccurred),
    /// Distinct sample-stop event.
    SampleStopped(SampleStopped),
    /// Bounded batch of uncollapsed sample events.
    Batch(Batch),
    /// Worker failure.
    WorkerFailure(WorkerFailure),
    /// Test-ended callback.
    TestEnded(TestEnded),
    /// Exactly-once terminal.
    Terminal(Terminal),
    /// Explicit queue-credit update.
    Credit(Credit),
    /// Explicit acknowledgement for accepted stream data.
    Ack(Ack),
}

impl StreamEvent {
    /// Returns the canonical event kind.
    pub const fn kind(&self) -> EventKind {
        match self {
            Self::Ready(_) => EventKind::Ready,
            Self::TestStarted(_) => EventKind::TestStarted,
            Self::SampleStarted(_) => EventKind::SampleStarted,
            Self::SampleOccurred(_) => EventKind::SampleOccurred,
            Self::SampleStopped(_) => EventKind::SampleStopped,
            Self::Batch(_) => EventKind::Batch,
            Self::WorkerFailure(_) => EventKind::WorkerFailure,
            Self::TestEnded(_) => EventKind::TestEnded,
            Self::Terminal(_) => EventKind::Terminal,
            Self::Credit(_) => EventKind::Credit,
            Self::Ack(_) => EventKind::Ack,
        }
    }
}

impl fmt::Debug for StreamEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ready(value) => formatter.debug_tuple("Ready").field(value).finish(),
            Self::TestStarted(value) => formatter.debug_tuple("TestStarted").field(value).finish(),
            Self::SampleStarted(value) => {
                formatter.debug_tuple("SampleStarted").field(value).finish()
            }
            Self::SampleOccurred(value) => formatter
                .debug_tuple("SampleOccurred")
                .field(value)
                .finish(),
            Self::SampleStopped(value) => {
                formatter.debug_tuple("SampleStopped").field(value).finish()
            }
            Self::Batch(value) => formatter.debug_tuple("Batch").field(value).finish(),
            Self::WorkerFailure(value) => {
                formatter.debug_tuple("WorkerFailure").field(value).finish()
            }
            Self::TestEnded(value) => formatter.debug_tuple("TestEnded").field(value).finish(),
            Self::Terminal(value) => formatter.debug_tuple("Terminal").field(value).finish(),
            Self::Credit(value) => formatter.debug_tuple("Credit").field(value).finish(),
            Self::Ack(value) => formatter.debug_tuple("Ack").field(value).finish(),
        }
    }
}

/// Stream correlation and lifecycle envelope.
#[derive(Clone, Eq, PartialEq)]
pub struct StreamMessage {
    /// Schema/version tuple for this event.
    pub schema: SchemaVersion,
    /// Stable run identity.
    pub run_id: String,
    /// Stable worker identity.
    pub worker_id: String,
    /// Lifecycle generation; never reused for a stream owner.
    pub generation: u64,
    /// Monotonically increasing stream sequence.
    pub sequence: u64,
    /// Control request identity, separate from stream sequence.
    pub request_id: u64,
    /// Remaining operation duration sampled immediately before send.
    pub remaining_duration: RemainingDuration,
    /// Optional diagnostic wall-clock timestamp; never used for deadline
    /// comparisons across processes.
    pub diagnostic_wall_time: Option<u64>,
    /// Cancellation state.
    pub cancellation: Cancellation,
    /// Closed stream event payload.
    pub event: StreamEvent,
}

/// Compatibility spelling for a stream envelope.
pub type RmiStreamMessage = StreamMessage;
/// Compatibility spelling for a stream frame.
pub type StreamFrame = StreamMessage;
/// Compatibility spelling for event payloads.
pub type RmiEvent = StreamEvent;

impl StreamMessage {
    /// Creates a stream message with explicit correlation fields.
    pub fn new(
        schema: SchemaVersion,
        run_id: impl Into<String>,
        worker_id: impl Into<String>,
        generation: u64,
        sequence: u64,
        request_id: u64,
        event: StreamEvent,
    ) -> Self {
        Self {
            schema,
            run_id: run_id.into(),
            worker_id: worker_id.into(),
            generation,
            sequence,
            request_id,
            remaining_duration: RemainingDuration::from_nanos(MAX_RMI_OPERATION_DURATION_NANOS),
            diagnostic_wall_time: None,
            cancellation: Cancellation::None,
            event,
        }
    }

    /// Adds a remaining operation duration.
    pub fn with_remaining_duration(mut self, duration: RemainingDuration) -> Self {
        self.remaining_duration = duration;
        self
    }

    /// Adds a diagnostic wall-clock timestamp.  Receivers must not compare
    /// this field to their own clock.
    pub const fn with_diagnostic_wall_time(mut self, timestamp: u64) -> Self {
        self.diagnostic_wall_time = Some(timestamp);
        self
    }

    /// Adds cancellation state.
    pub fn with_cancellation(mut self, cancellation: Cancellation) -> Self {
        self.cancellation = cancellation;
        self
    }

    /// Returns the event kind.
    pub const fn kind(&self) -> EventKind {
        self.event.kind()
    }

    /// Validates envelope identity and event resource bounds.
    pub fn validate(&self, limits: RmiLimits) -> Result<(), RmiValidationError> {
        limits.validate().map_err(RmiValidationError::Limits)?;
        self.schema.validate().map_err(RmiValidationError::Schema)?;
        validate_text(&self.run_id, limits.max_string_bytes, "run id")
            .map_err(RmiValidationError::Identity)?;
        validate_text(&self.worker_id, limits.max_string_bytes, "worker id")
            .map_err(RmiValidationError::Identity)?;
        if self.generation == 0 {
            return Err(RmiValidationError::ZeroIdentity("generation"));
        }
        if self.sequence == 0 {
            return Err(RmiValidationError::ZeroIdentity("sequence"));
        }
        if self.request_id == 0 {
            return Err(RmiValidationError::ZeroIdentity("request id"));
        }
        validate_remaining_duration(self.remaining_duration, limits)?;
        validate_event(&self.event, limits)?;
        if let StreamEvent::Batch(batch) = &self.event {
            let item_count = u64::try_from(batch.items.len())
                .map_err(|_| RmiValidationError::Event("batch count"))?;
            if batch.event_count != item_count {
                return Err(RmiValidationError::Event("batch event count"));
            }
            if batch.callback_invocation_ordinal == 0 {
                return Err(RmiValidationError::ZeroIdentity(
                    "batch callback invocation ordinal",
                ));
            }
            if batch.first_delivered_event_ordinal == 0 {
                return Err(RmiValidationError::ZeroIdentity(
                    "batch delivered event ordinal",
                ));
            }
            if batch.batch_id == 0 {
                return Err(RmiValidationError::ZeroIdentity("batch id"));
            }
            self.sequence
                .checked_add(item_count.saturating_sub(1))
                .ok_or(RmiValidationError::Event("batch sequence"))?;
            for (index, item) in batch.items.iter().enumerate() {
                let offset = u64::try_from(index)
                    .map_err(|_| RmiValidationError::Event("batch sequence"))?;
                let expected = self
                    .sequence
                    .checked_add(offset)
                    .ok_or(RmiValidationError::Event("batch sequence"))?;
                if item.sequence != expected {
                    return Err(RmiValidationError::Event("batch sequence"));
                }
            }
        }
        Ok(())
    }
}

impl fmt::Debug for StreamMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StreamMessage")
            .field("schema", &self.schema)
            .field("run_id_len", &self.run_id.len())
            .field("worker_id_len", &self.worker_id.len())
            .field("generation", &self.generation)
            .field("sequence", &self.sequence)
            .field("request_id", &self.request_id)
            .field("remaining_duration", &self.remaining_duration)
            .field(
                "diagnostic_wall_time_present",
                &self.diagnostic_wall_time.is_some(),
            )
            .field("cancellation", &self.cancellation)
            .field("event", &self.event)
            .finish()
    }
}

/// Stream/message validation failure.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum RmiValidationError {
    /// Resource limit declaration or event data exceeds a bound.
    Limits(RmiLimitError),
    /// Unsupported schema tuple.
    Schema(SchemaError),
    /// Invalid profile/artifact/identity declaration.
    Identity(IdentityError),
    /// Event sample/result data is invalid.
    Sample(SampleValidationError),
    /// A required non-zero correlation value was zero.
    ZeroIdentity(&'static str),
    /// Event payload is invalid.
    Event(&'static str),
}

impl fmt::Display for RmiValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Limits(error) => error.fmt(formatter),
            Self::Schema(error) => error.fmt(formatter),
            Self::Identity(error) => error.fmt(formatter),
            Self::Sample(error) => error.fmt(formatter),
            Self::ZeroIdentity(field) => write!(formatter, "{field} must be non-zero"),
            Self::Event(field) => write!(formatter, "invalid {field} event"),
        }
    }
}

impl std::error::Error for RmiValidationError {}

fn validate_host_presence(
    host: &HostPresence,
    limits: RmiLimits,
) -> Result<(), RmiValidationError> {
    if let HostPresence::Present(value) = host
        && value.len() > limits.max_string_bytes
    {
        return Err(RmiValidationError::Sample(
            SampleValidationError::FieldTooLong {
                field: "callback host",
                actual: value.len(),
                maximum: limits.max_string_bytes,
            },
        ));
    }
    Ok(())
}

fn validate_remaining_duration(
    value: RemainingDuration,
    limits: RmiLimits,
) -> Result<(), RmiValidationError> {
    match value.as_nanos() {
        Some(nanos) if nanos != 0 && nanos <= limits.max_operation_duration_millis => Ok(()),
        _ => Err(RmiValidationError::Event("remaining duration")),
    }
}

fn validate_callback_host(
    overload: LifecycleOverload,
    host: &HostPresence,
    limits: RmiLimits,
) -> Result<(), RmiValidationError> {
    validate_host_presence(host, limits)?;
    if overload == LifecycleOverload::NoHost && !matches!(host, HostPresence::Absent) {
        return Err(RmiValidationError::Event("NoHost callback carries a host"));
    }
    if overload == LifecycleOverload::HostArgument && matches!(host, HostPresence::Absent) {
        return Err(RmiValidationError::Event(
            "HostArgument callback lacks a host",
        ));
    }
    Ok(())
}

fn validate_sample_callback_metadata(
    callback_invocation_ordinal: u64,
    delivered_event_ordinal: u64,
    delivery_kind: DeliveryKind,
    in_batch: bool,
) -> Result<(), RmiValidationError> {
    if in_batch {
        if callback_invocation_ordinal != 0 || delivered_event_ordinal != 0 {
            return Err(RmiValidationError::Event("batch item callback ordinal"));
        }
        if delivery_kind != DeliveryKind::ProcessBatch {
            return Err(RmiValidationError::Event("batch item delivery kind"));
        }
    } else {
        if callback_invocation_ordinal == 0 {
            return Err(RmiValidationError::ZeroIdentity(
                "callback invocation ordinal",
            ));
        }
        if delivered_event_ordinal == 0 {
            return Err(RmiValidationError::ZeroIdentity("delivered event ordinal"));
        }
        if delivery_kind != DeliveryKind::SampleOccurred {
            return Err(RmiValidationError::Event("single sample delivery kind"));
        }
    }
    Ok(())
}

fn validate_batch_sample_event(
    event: &SampleEvent,
    limits: RmiLimits,
) -> Result<(), RmiValidationError> {
    match event {
        SampleEvent::Started(value) => {
            validate_sample_callback_metadata(
                value.callback_invocation_ordinal,
                value.delivered_event_ordinal,
                value.delivery_kind,
                true,
            )?;
            validate_sample_started(value, limits)?;
        }
        SampleEvent::Occurred(value) => {
            validate_sample_callback_metadata(
                value.callback_invocation_ordinal,
                value.delivered_event_ordinal,
                value.delivery_kind,
                true,
            )?;
            validate_sample_occurred(value, limits)?;
        }
        SampleEvent::Stopped(value) => {
            validate_sample_callback_metadata(
                value.callback_invocation_ordinal,
                value.delivered_event_ordinal,
                value.delivery_kind,
                true,
            )?;
            validate_sample_stopped(value, limits)?;
        }
    }
    Ok(())
}

fn validate_sample_started(
    value: &SampleStarted,
    limits: RmiLimits,
) -> Result<(), RmiValidationError> {
    if value.sample_id == 0 {
        return Err(RmiValidationError::ZeroIdentity("sample id"));
    }
    if value.parent_id == Some(0) {
        return Err(RmiValidationError::ZeroIdentity("parent sample id"));
    }
    if let Some(label) = &value.label
        && label.len() > limits.max_string_bytes
    {
        return Err(RmiValidationError::Sample(
            SampleValidationError::FieldTooLong {
                field: "sample-start label",
                actual: label.len(),
                maximum: limits.max_string_bytes,
            },
        ));
    }
    value
        .snapshot
        .validate(limits)
        .map_err(RmiValidationError::Sample)
}

fn validate_sample_occurred(
    value: &SampleOccurred,
    limits: RmiLimits,
) -> Result<(), RmiValidationError> {
    if value.sample_id == 0 {
        return Err(RmiValidationError::ZeroIdentity("sample id"));
    }
    value
        .result
        .validate(limits)
        .map_err(RmiValidationError::Sample)?;
    value
        .snapshot
        .validate(limits)
        .map_err(RmiValidationError::Sample)
}

fn validate_sample_stopped(
    value: &SampleStopped,
    limits: RmiLimits,
) -> Result<(), RmiValidationError> {
    if value.sample_id == 0 {
        return Err(RmiValidationError::ZeroIdentity("sample id"));
    }
    value
        .snapshot
        .validate(limits)
        .map_err(RmiValidationError::Sample)
}

fn validate_accounting(
    value: StreamAccounting,
    limits: RmiLimits,
) -> Result<(), RmiValidationError> {
    if value.is_ordered() {
        let max_events = u64::try_from(limits.max_stream_events).unwrap_or(u64::MAX);
        if value.delivered_events > max_events
            || value.accepted_events > max_events
            || value.acknowledged_events > max_events
            || value.pending_bridge_events > max_events
            || value.pending_sender_events > max_events
            || value.pending_blobs > max_events
        {
            return Err(RmiValidationError::Event("accounting event limit"));
        }
        if value.delivered_bytes > limits.max_stream_bytes
            || value.accepted_bytes > limits.max_stream_bytes
            || value.acknowledged_bytes > limits.max_stream_bytes
        {
            return Err(RmiValidationError::Event("accounting byte limit"));
        }
        Ok(())
    } else {
        Err(RmiValidationError::Event("accounting order"))
    }
}

fn validate_sender_proof(
    value: &SenderDrainProof,
    limits: RmiLimits,
) -> Result<(), RmiValidationError> {
    if let SenderDrainProof::Proven(evidence) = value {
        if evidence.generation == 0 {
            return Err(RmiValidationError::ZeroIdentity("sender proof generation"));
        }
        validate_text(
            &evidence.completion_hook,
            limits.max_string_bytes,
            "sender completion hook",
        )
        .map_err(RmiValidationError::Identity)?;
        if evidence.accepted_events > evidence.emitted_events
            || evidence.acknowledged_events > evidence.accepted_events
            || evidence.accepted_bytes > evidence.emitted_bytes
            || evidence.acknowledged_bytes > evidence.accepted_bytes
        {
            return Err(RmiValidationError::Event("sender proof accounting"));
        }
        let max_events = u64::try_from(limits.max_stream_events).unwrap_or(u64::MAX);
        if evidence.emitted_events > max_events
            || evidence.accepted_events > max_events
            || evidence.acknowledged_events > max_events
            || evidence.pending_sender_events > max_events
            || evidence.pending_disk_events > max_events
        {
            return Err(RmiValidationError::Event("sender proof event limit"));
        }
        if evidence.emitted_bytes > limits.max_stream_bytes
            || evidence.accepted_bytes > limits.max_stream_bytes
            || evidence.acknowledged_bytes > limits.max_stream_bytes
        {
            return Err(RmiValidationError::Event("sender proof byte limit"));
        }
    }
    Ok(())
}

fn validate_event(event: &StreamEvent, limits: RmiLimits) -> Result<(), RmiValidationError> {
    match event {
        StreamEvent::Ready(value) => {
            value
                .identity
                .validate(limits)
                .map_err(RmiValidationError::Identity)?;
            value
                .queue
                .validate(limits)
                .map_err(|error| RmiValidationError::Event(queue_event_name(&error)))?;
        }
        StreamEvent::TestStarted(value) => {
            validate_callback_host(value.overload, &value.host, limits)?;
            if value.callback_invocation_ordinal == 0 {
                return Err(RmiValidationError::ZeroIdentity(
                    "TestStarted callback invocation ordinal",
                ));
            }
            validate_text(&value.test_id, limits.max_string_bytes, "test id")
                .map_err(RmiValidationError::Identity)?;
            value
                .queue
                .validate(limits)
                .map_err(|error| RmiValidationError::Event(queue_event_name(&error)))?;
        }
        StreamEvent::SampleStarted(value) => {
            validate_sample_callback_metadata(
                value.callback_invocation_ordinal,
                value.delivered_event_ordinal,
                value.delivery_kind,
                false,
            )?;
            validate_sample_started(value, limits)?;
        }
        StreamEvent::SampleOccurred(value) => {
            validate_sample_callback_metadata(
                value.callback_invocation_ordinal,
                value.delivered_event_ordinal,
                value.delivery_kind,
                false,
            )?;
            validate_sample_occurred(value, limits)?;
        }
        StreamEvent::SampleStopped(value) => {
            validate_sample_callback_metadata(
                value.callback_invocation_ordinal,
                value.delivered_event_ordinal,
                value.delivery_kind,
                false,
            )?;
            validate_sample_stopped(value, limits)?;
        }
        StreamEvent::Batch(value) => {
            if value.items.is_empty() {
                return Err(RmiValidationError::Event("empty batch"));
            }
            if value.items.len() > limits.max_batch_items {
                return Err(RmiValidationError::Sample(SampleValidationError::Count {
                    field: "batch items",
                    actual: value.items.len(),
                    maximum: limits.max_batch_items,
                }));
            }
            if value.delivery_kind != DeliveryKind::ProcessBatch {
                return Err(RmiValidationError::Event("batch delivery kind"));
            }
            let item_count = u64::try_from(value.items.len())
                .map_err(|_| RmiValidationError::Event("batch event count"))?;
            if value.event_count != item_count {
                return Err(RmiValidationError::Event("batch event count"));
            }
            let mut previous = 0_u64;
            let mut request_ids = BTreeSet::new();
            for item in &value.items {
                if item.sequence == 0 || item.request_id == 0 {
                    return Err(RmiValidationError::Event("batch identity"));
                }
                if !request_ids.insert(item.request_id) {
                    return Err(RmiValidationError::Event("duplicate batch request id"));
                }
                if item.sequence <= previous {
                    return Err(RmiValidationError::Event("batch sequence"));
                }
                previous = item.sequence;
                validate_remaining_duration(item.remaining_duration, limits)?;
                validate_batch_sample_event(&item.event, limits)?;
            }
        }
        StreamEvent::WorkerFailure(value) => {
            validate_text(
                &value.worker_id,
                limits.max_string_bytes,
                "failure worker id",
            )
            .map_err(RmiValidationError::Identity)?;
            if let Some(message) = &value.message
                && message.len() > limits.max_string_bytes
            {
                return Err(RmiValidationError::Sample(
                    SampleValidationError::FieldTooLong {
                        field: "failure message",
                        actual: message.len(),
                        maximum: limits.max_string_bytes,
                    },
                ));
            }
            if let RetryDisposition::PreStartSafe { next_attempt, .. } = value.retry
                && next_attempt == 0
            {
                return Err(RmiValidationError::ZeroIdentity("retry next attempt"));
            }
        }
        StreamEvent::TestEnded(value) => {
            validate_callback_host(value.overload, &value.host, limits)?;
            if value.callback_invocation_ordinal == 0 {
                return Err(RmiValidationError::ZeroIdentity(
                    "TestEnded callback invocation ordinal",
                ));
            }
            validate_accounting(value.accounting, limits)?;
            value
                .queue
                .validate(limits)
                .map_err(|error| RmiValidationError::Event(queue_event_name(&error)))?;
        }
        StreamEvent::Terminal(value) => {
            validate_accounting(value.accounting, limits)?;
            validate_sender_proof(&value.sender_proof, limits)?;
            if value.test_ended_callback_ordinal == Some(0) {
                return Err(RmiValidationError::ZeroIdentity(
                    "terminal TestEnded callback ordinal",
                ));
            }
            if value.test_ended_callback_ordinal.is_some()
                && value.test_ended_absence_reason.is_some()
            {
                return Err(RmiValidationError::Event(
                    "terminal has callback and absence reason",
                ));
            }
            if value.status == TerminalStatus::Succeeded {
                if value.test_ended_callback_ordinal.is_none()
                    || value.test_ended_absence_reason.is_some()
                    || !value.sender_proof.is_proven()
                    || value.router_finalization_digest.is_none()
                    || !value.accounting.is_fully_acked()
                {
                    return Err(RmiValidationError::Event("incomplete success proof"));
                }
            } else if value.test_ended_callback_ordinal.is_none()
                && value.test_ended_absence_reason.is_none()
            {
                return Err(RmiValidationError::Event(
                    "non-success terminal lacks TestEnded absence reason",
                ));
            }
            value
                .queue
                .validate(limits)
                .map_err(|error| RmiValidationError::Event(queue_event_name(&error)))?;
            if let Some(failure) = &value.failure {
                validate_event(&StreamEvent::WorkerFailure(failure.clone()), limits)?;
            }
        }
        StreamEvent::Credit(value) => value
            .queue
            .validate(limits)
            .map_err(|error| RmiValidationError::Event(queue_event_name(&error)))?,
        StreamEvent::Ack(value) => {
            if value.acknowledged_sequence == 0 {
                return Err(RmiValidationError::ZeroIdentity("acknowledged sequence"));
            }
        }
    }
    Ok(())
}

fn queue_event_name(error: &QueueError) -> &'static str {
    match error {
        QueueError::Full { .. } => "queue full",
        QueueError::Closed => "queue closed",
        QueueError::Cancelled => "queue cancelled",
        QueueError::CreditLimit { .. } => "queue credit",
        QueueError::CreditInconsistent { .. } => "queue credit",
        QueueError::ByteCreditLimit { .. } => "queue byte credit",
        QueueError::ByteCreditInconsistent { .. } => "queue byte credit",
        QueueError::ByteCountOverflow => "queue bytes",
        QueueError::ReleaseOverflow => "queue release",
    }
}

/// Incremental decode result.  Incomplete input is non-consuming and reports
/// the exact additional bytes needed for the current envelope header/body.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RmiDecodeResult {
    /// More bytes are required.
    Incomplete { needed: usize },
    /// One complete message and the number of consumed bytes.
    Complete {
        message: StreamMessage,
        consumed: usize,
    },
}

/// Decode policy for trailing bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RmiTrailingPolicy {
    /// Return one message and leave trailing bytes for the next message.
    Allow,
    /// Require the input to contain exactly one message.
    Reject,
}

/// Stream codec with bounded allocations and no transport side effects.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RmiCodec {
    limits: RmiLimits,
}

impl RmiCodec {
    /// Creates a codec after validating limits.
    pub fn new(limits: RmiLimits) -> Result<Self, RmiLimitError> {
        limits.validate()?;
        Ok(Self { limits })
    }

    /// Creates a codec without panicking; all later operations still validate
    /// the supplied limits before touching input allocations.
    pub const fn with_limits(limits: RmiLimits) -> Self {
        Self { limits }
    }

    /// Returns the configured limits.
    pub const fn limits(self) -> RmiLimits {
        self.limits
    }

    /// Encodes one complete stream message in canonical wire order.
    pub fn encode(&self, message: &StreamMessage) -> Result<Vec<u8>, RmiEncodeError> {
        self.limits.validate().map_err(RmiEncodeError::Limits)?;
        message
            .validate(self.limits)
            .map_err(RmiEncodeError::Validation)?;
        let mut writer = Writer::new(self.limits.max_frame_bytes);
        writer.bytes(&RMI_MAGIC)?;
        writer.u8(RMI_WIRE_VERSION);
        writer.u8(message.kind() as u8);
        writer.u16(message.schema.operation);
        writer.u16(message.schema.event_stream);
        writer.u16(message.schema.preservation);
        writer.u16(0);
        encode_envelope_fields(&mut writer, message, self.limits)?;
        encode_event(&mut writer, &message.event, self.limits)?;
        let bytes = writer.finish()?;
        if bytes.len() > self.limits.max_frame_bytes {
            return Err(RmiEncodeError::FrameTooLarge {
                actual: bytes.len(),
                maximum: self.limits.max_frame_bytes,
            });
        }
        Ok(bytes)
    }

    /// Decodes one message while allowing a following message in the input.
    pub fn decode(&self, input: &[u8]) -> Result<RmiDecodeResult, RmiDecodeError> {
        self.decode_with_policy(input, RmiTrailingPolicy::Allow)
    }

    /// Decodes one message according to an explicit trailing-byte policy.
    pub fn decode_with_policy(
        &self,
        input: &[u8],
        policy: RmiTrailingPolicy,
    ) -> Result<RmiDecodeResult, RmiDecodeError> {
        match self.decode_complete(input, policy) {
            Err(RmiDecodeError::Truncated { needed }) => Ok(RmiDecodeResult::Incomplete { needed }),
            result => result,
        }
    }

    fn decode_complete(
        &self,
        input: &[u8],
        policy: RmiTrailingPolicy,
    ) -> Result<RmiDecodeResult, RmiDecodeError> {
        self.limits.validate().map_err(RmiDecodeError::Limits)?;
        if input.len() < RMI_HEADER_LEN {
            return Ok(RmiDecodeResult::Incomplete {
                needed: RMI_HEADER_LEN - input.len(),
            });
        }
        if input[..4] != RMI_MAGIC {
            return Err(RmiDecodeError::InvalidMagic {
                found: [input[0], input[1], input[2], input[3]],
            });
        }
        if input[4] != RMI_WIRE_VERSION {
            return Err(RmiDecodeError::UnsupportedWireVersion(input[4]));
        }
        let kind = EventKind::from_wire(input[5])?;
        let operation = read_u16(&input[6..8]);
        let event_stream = read_u16(&input[8..10]);
        let preservation = read_u16(&input[10..12]);
        if read_u16(&input[12..14]) != 0 {
            return Err(RmiDecodeError::UnknownFlags(1));
        }
        let schema = SchemaVersion {
            protocol: RMI_WIRE_VERSION as u16,
            operation,
            event_stream,
            preservation,
        };
        schema.validate().map_err(RmiDecodeError::Schema)?;
        let mut reader = Reader::new(
            &input[RMI_HEADER_LEN..],
            self.limits.max_frame_bytes.saturating_sub(RMI_HEADER_LEN),
        );
        let envelope = decode_envelope_fields(&mut reader, self.limits)?;
        let event = decode_event(&mut reader, kind, self.limits)?;
        let consumed = RMI_HEADER_LEN
            .checked_add(reader.position())
            .ok_or(RmiDecodeError::LengthOverflow)?;
        if consumed > self.limits.max_frame_bytes {
            return Err(RmiDecodeError::FrameTooLarge {
                declared: consumed,
                maximum: self.limits.max_frame_bytes,
            });
        }
        if policy == RmiTrailingPolicy::Reject && input.len() > consumed {
            return Err(RmiDecodeError::TrailingBytes {
                count: input.len() - consumed,
            });
        }
        let message = StreamMessage {
            schema,
            run_id: envelope.run_id,
            worker_id: envelope.worker_id,
            generation: envelope.generation,
            sequence: envelope.sequence,
            request_id: envelope.request_id,
            remaining_duration: envelope.remaining_duration,
            diagnostic_wall_time: envelope.diagnostic_wall_time,
            cancellation: envelope.cancellation,
            event,
        };
        message
            .validate(self.limits)
            .map_err(RmiDecodeError::Validation)?;
        Ok(RmiDecodeResult::Complete { message, consumed })
    }

    /// Decodes exactly one message.
    pub fn decode_exact(&self, input: &[u8]) -> Result<StreamMessage, RmiDecodeError> {
        match self.decode_with_policy(input, RmiTrailingPolicy::Reject)? {
            RmiDecodeResult::Complete { message, .. } => Ok(message),
            RmiDecodeResult::Incomplete { needed } => Err(RmiDecodeError::Truncated { needed }),
        }
    }

    /// Decodes the next complete message and advances the caller slice only
    /// after successful validation.
    pub fn decode_next(&self, input: &mut &[u8]) -> Result<Option<StreamMessage>, RmiDecodeError> {
        match self.decode(input)? {
            RmiDecodeResult::Incomplete { .. } => Ok(None),
            RmiDecodeResult::Complete { message, consumed } => {
                *input = &input[consumed..];
                Ok(Some(message))
            }
        }
    }
}

struct EnvelopeFields {
    run_id: String,
    worker_id: String,
    generation: u64,
    sequence: u64,
    request_id: u64,
    remaining_duration: RemainingDuration,
    diagnostic_wall_time: Option<u64>,
    cancellation: Cancellation,
}

fn encode_envelope_fields(
    writer: &mut Writer,
    message: &StreamMessage,
    limits: RmiLimits,
) -> Result<(), RmiEncodeError> {
    writer.string(&message.run_id, limits.max_string_bytes)?;
    writer.string(&message.worker_id, limits.max_string_bytes)?;
    writer.u64(message.generation);
    writer.u64(message.sequence);
    writer.u64(message.request_id);
    encode_remaining_duration(writer, message.remaining_duration);
    encode_optional_u64(writer, message.diagnostic_wall_time);
    writer.u8(cancellation_to_wire(message.cancellation));
    writer.u8(0);
    Ok(())
}

fn decode_envelope_fields(
    reader: &mut Reader<'_>,
    limits: RmiLimits,
) -> Result<EnvelopeFields, RmiDecodeError> {
    let run_id = reader.string("run id", limits.max_string_bytes)?;
    let worker_id = reader.string("worker id", limits.max_string_bytes)?;
    let generation = reader.u64()?;
    let sequence = reader.u64()?;
    let request_id = reader.u64()?;
    let remaining_duration = decode_remaining_duration(reader)?;
    let diagnostic_wall_time = decode_optional_u64(reader)?;
    let cancellation = cancellation_from_wire(reader.u8()?)?;
    if reader.u8()? != 0 {
        return Err(RmiDecodeError::UnknownFlags(1));
    }
    Ok(EnvelopeFields {
        run_id,
        worker_id,
        generation,
        sequence,
        request_id,
        remaining_duration,
        diagnostic_wall_time,
        cancellation,
    })
}

fn encode_remaining_duration(writer: &mut Writer, value: RemainingDuration) {
    match value.as_nanos() {
        Some(nanos) => {
            writer.u8(1);
            writer.u64(nanos);
        }
        None => writer.u8(0),
    }
}

fn decode_remaining_duration(reader: &mut Reader<'_>) -> Result<RemainingDuration, RmiDecodeError> {
    match reader.u8()? {
        0 => Err(RmiDecodeError::InvalidOptionMarker(0)),
        1 => Ok(RemainingDuration::from_nanos(reader.u64()?)),
        other => Err(RmiDecodeError::InvalidOptionMarker(other)),
    }
}

fn encode_optional_u64(writer: &mut Writer, value: Option<u64>) {
    match value {
        Some(value) => {
            writer.u8(1);
            writer.u64(value);
        }
        None => writer.u8(0),
    }
}

fn decode_optional_u64(reader: &mut Reader<'_>) -> Result<Option<u64>, RmiDecodeError> {
    match reader.u8()? {
        0 => Ok(None),
        1 => Ok(Some(reader.u64()?)),
        other => Err(RmiDecodeError::InvalidOptionMarker(other)),
    }
}

fn cancellation_to_wire(value: Cancellation) -> u8 {
    match value {
        Cancellation::None => 0,
        Cancellation::Requested => 1,
        Cancellation::Cancelled => 2,
    }
}

fn cancellation_from_wire(value: u8) -> Result<Cancellation, RmiDecodeError> {
    match value {
        0 => Ok(Cancellation::None),
        1 => Ok(Cancellation::Requested),
        2 => Ok(Cancellation::Cancelled),
        other => Err(RmiDecodeError::InvalidEnum {
            field: "cancellation",
            value: other as u64,
        }),
    }
}

fn encode_event(
    writer: &mut Writer,
    event: &StreamEvent,
    limits: RmiLimits,
) -> Result<(), RmiEncodeError> {
    match event {
        StreamEvent::Ready(value) => encode_ready(writer, value, limits),
        StreamEvent::TestStarted(value) => encode_test_started(writer, value, limits),
        StreamEvent::SampleStarted(value) => encode_sample_started(writer, value, limits),
        StreamEvent::SampleOccurred(value) => encode_sample_occurred(writer, value, limits),
        StreamEvent::SampleStopped(value) => encode_sample_stopped(writer, value, limits),
        StreamEvent::Batch(value) => encode_batch(writer, value, limits),
        StreamEvent::WorkerFailure(value) => encode_worker_failure(writer, value, limits),
        StreamEvent::TestEnded(value) => encode_test_ended(writer, value, limits),
        StreamEvent::Terminal(value) => encode_terminal(writer, value, limits),
        StreamEvent::Credit(value) => encode_credit(writer, value),
        StreamEvent::Ack(value) => encode_ack(writer, value),
    }
}

fn decode_event(
    reader: &mut Reader<'_>,
    kind: EventKind,
    limits: RmiLimits,
) -> Result<StreamEvent, RmiDecodeError> {
    match kind {
        EventKind::Ready => decode_ready(reader, limits).map(StreamEvent::Ready),
        EventKind::TestStarted => decode_test_started(reader, limits).map(StreamEvent::TestStarted),
        EventKind::SampleStarted => {
            decode_sample_started(reader, limits).map(StreamEvent::SampleStarted)
        }
        EventKind::SampleOccurred => {
            decode_sample_occurred(reader, limits).map(StreamEvent::SampleOccurred)
        }
        EventKind::SampleStopped => {
            decode_sample_stopped(reader, limits).map(StreamEvent::SampleStopped)
        }
        EventKind::Batch => decode_batch(reader, limits).map(StreamEvent::Batch),
        EventKind::WorkerFailure => {
            decode_worker_failure(reader, limits).map(StreamEvent::WorkerFailure)
        }
        EventKind::TestEnded => decode_test_ended(reader, limits).map(StreamEvent::TestEnded),
        EventKind::Terminal => decode_terminal(reader, limits).map(StreamEvent::Terminal),
        EventKind::Credit => decode_credit(reader).map(StreamEvent::Credit),
        EventKind::Ack => decode_ack(reader).map(StreamEvent::Ack),
    }
}

fn encode_ready(
    writer: &mut Writer,
    value: &Ready,
    limits: RmiLimits,
) -> Result<(), RmiEncodeError> {
    encode_identity(writer, &value.identity, limits)?;
    writer.u8(value.sender as u8);
    encode_queue(writer, value.queue);
    writer.u8(backpressure_to_wire(value.backpressure));
    Ok(())
}

fn decode_ready(reader: &mut Reader<'_>, limits: RmiLimits) -> Result<Ready, RmiDecodeError> {
    let identity = decode_identity(reader, limits)?;
    let sender = SenderMode::from_wire(reader.u8()?)?;
    let queue = decode_queue(reader)?;
    let backpressure = BackpressurePolicy::from_wire(reader.u8()?)?;
    Ok(Ready {
        identity,
        sender,
        queue,
        backpressure,
    })
}

fn encode_identity(
    writer: &mut Writer,
    value: &BridgeIdentity,
    limits: RmiLimits,
) -> Result<(), RmiEncodeError> {
    writer.string(&value.profile.id, limits.max_string_bytes)?;
    writer.u32(value.profile.version);
    writer.bytes(&value.profile.sha256.as_bytes())?;
    writer.bytes(&value.artifact.jmeter_archive_sha512.as_bytes())?;
    writer.string(
        &value.artifact.jmeter_source_commit,
        limits.max_string_bytes,
    )?;
    writer.bytes(&value.artifact.helper_source_sha256.as_bytes())?;
    writer.bytes(&value.artifact.helper_build_sha256.as_bytes())?;
    writer.string(&value.artifact.java_compiler, limits.max_string_bytes)?;
    writer.string(&value.artifact.java_runtime, limits.max_string_bytes)?;
    writer.string(&value.artifact.jmeter_rs_commit, limits.max_string_bytes)?;
    writer.string(&value.artifact.platform_profile, limits.max_string_bytes)?;
    writer.string(&value.artifact.target, limits.max_string_bytes)?;
    writer.string(&value.artifact.os, limits.max_string_bytes)?;
    writer.count(value.artifact.dependencies.len(), limits.max_dependencies)?;
    for dependency in &value.artifact.dependencies {
        writer.string(&dependency.name, limits.max_string_bytes)?;
        writer.string(&dependency.version, limits.max_string_bytes)?;
        writer.bytes(&dependency.sha256.as_bytes())?;
        writer.string(&dependency.license, limits.max_string_bytes)?;
        writer.string(&dependency.notice, limits.max_string_bytes)?;
        writer.u32(dependency.classpath_order);
    }
    writer.u8(value.role as u8);
    writer.string(&value.worker_id, limits.max_string_bytes)?;
    writer.count(value.capabilities.len(), limits.max_capabilities)?;
    for capability in &value.capabilities {
        writer.string(&capability.id, limits.max_string_bytes)?;
        writer.string(&capability.version, limits.max_string_bytes)?;
    }
    writer.u16(value.preservation.version);
    writer.u8(value.preservation.unknown_operation_fields as u8);
    Ok(())
}

fn decode_identity(
    reader: &mut Reader<'_>,
    limits: RmiLimits,
) -> Result<BridgeIdentity, RmiDecodeError> {
    let profile_id = reader.string("profile id", limits.max_string_bytes)?;
    let profile_version = reader.u32()?;
    let profile_sha = Sha256Digest::from_bytes(reader.array::<32>()?);
    let archive_sha = Sha512Digest::from_bytes(reader.array::<64>()?);
    let source_commit = reader.string("JMeter source commit", limits.max_string_bytes)?;
    let helper_source = Sha256Digest::from_bytes(reader.array::<32>()?);
    let helper_build = Sha256Digest::from_bytes(reader.array::<32>()?);
    let java_compiler = reader.string("Java compiler", limits.max_string_bytes)?;
    let java_runtime = reader.string("Java runtime", limits.max_string_bytes)?;
    let jmeter_rs_commit = reader.string("jmeter-rs commit", limits.max_string_bytes)?;
    let platform_profile = reader.string("platform profile", limits.max_string_bytes)?;
    let target = reader.string("target", limits.max_string_bytes)?;
    let os = reader.string("OS", limits.max_string_bytes)?;
    let dependency_count = reader.count("dependencies", limits.max_dependencies)?;
    let mut dependencies = Vec::with_capacity(dependency_count);
    for _ in 0..dependency_count {
        dependencies.push(DependencyIdentity {
            name: reader.string("dependency name", limits.max_string_bytes)?,
            version: reader.string("dependency version", limits.max_string_bytes)?,
            sha256: Sha256Digest::from_bytes(reader.array::<32>()?),
            license: reader.string("dependency license", limits.max_string_bytes)?,
            notice: reader.string("dependency notice", limits.max_string_bytes)?,
            classpath_order: reader.u32()?,
        });
    }
    let role = RmiRole::from_wire(reader.u8()?)?;
    let worker_id = reader.string("worker id", limits.max_string_bytes)?;
    let capability_count = reader.count("capabilities", limits.max_capabilities)?;
    let mut capabilities = Vec::with_capacity(capability_count);
    for _ in 0..capability_count {
        capabilities.push(Capability {
            id: reader.string("capability id", limits.max_string_bytes)?,
            version: reader.string("capability version", limits.max_string_bytes)?,
        });
    }
    let preservation = Preservation {
        version: reader.u16()?,
        unknown_operation_fields: reader.u8()? != 0,
    };
    Ok(BridgeIdentity {
        profile: ProfileIdentity::new(profile_id, profile_version, profile_sha),
        artifact: ArtifactIdentity {
            jmeter_archive_sha512: archive_sha,
            jmeter_source_commit: source_commit,
            helper_source_sha256: helper_source,
            helper_build_sha256: helper_build,
            java_compiler,
            java_runtime,
            jmeter_rs_commit,
            platform_profile,
            target,
            os,
            dependencies,
        },
        role,
        worker_id,
        capabilities,
        preservation,
    })
}

fn encode_test_started(
    writer: &mut Writer,
    value: &TestStarted,
    limits: RmiLimits,
) -> Result<(), RmiEncodeError> {
    writer.u8(value.overload as u8);
    encode_host_presence(writer, &value.host, limits)?;
    writer.u64(value.callback_invocation_ordinal);
    writer.string(&value.test_id, limits.max_string_bytes)?;
    writer.bytes(&value.plan_sha256.as_bytes())?;
    encode_queue(writer, value.queue);
    Ok(())
}

fn decode_test_started(
    reader: &mut Reader<'_>,
    limits: RmiLimits,
) -> Result<TestStarted, RmiDecodeError> {
    Ok(TestStarted {
        overload: LifecycleOverload::from_wire(reader.u8()?)?,
        host: decode_host_presence(reader, limits)?,
        callback_invocation_ordinal: reader.u64()?,
        test_id: reader.string("test id", limits.max_string_bytes)?,
        plan_sha256: Sha256Digest::from_bytes(reader.array::<32>()?),
        queue: decode_queue(reader)?,
    })
}

fn encode_credit(writer: &mut Writer, value: &Credit) -> Result<(), RmiEncodeError> {
    encode_queue(writer, value.queue);
    Ok(())
}

fn decode_credit(reader: &mut Reader<'_>) -> Result<Credit, RmiDecodeError> {
    Ok(Credit {
        queue: decode_queue(reader)?,
    })
}

fn encode_ack(writer: &mut Writer, value: &Ack) -> Result<(), RmiEncodeError> {
    writer.u64(value.acknowledged_sequence);
    writer.u64(value.acknowledged_events);
    writer.u64(value.acknowledged_bytes);
    Ok(())
}

fn decode_ack(reader: &mut Reader<'_>) -> Result<Ack, RmiDecodeError> {
    Ok(Ack {
        acknowledged_sequence: reader.u64()?,
        acknowledged_events: reader.u64()?,
        acknowledged_bytes: reader.u64()?,
    })
}

fn encode_sample_snapshot(
    writer: &mut Writer,
    value: &SampleEventSnapshot,
    limits: RmiLimits,
) -> Result<(), RmiEncodeError> {
    value.validate(limits).map_err(RmiEncodeError::Sample)?;
    writer.optional_string(value.thread_group.as_deref(), limits.max_string_bytes)?;
    encode_host_presence(writer, &value.host, limits)?;
    writer.count(value.variables.len(), limits.max_variables)?;
    for variable in &value.variables {
        writer.string(&variable.name, limits.max_string_bytes)?;
        writer.optional_string(variable.value.as_deref(), limits.max_string_bytes)?;
    }
    writer.bool(value.is_transaction);
    match &value.result {
        Some(result) => {
            writer.u8(1);
            encode_sample(writer, result, limits)?;
        }
        None => writer.u8(0),
    }
    Ok(())
}

fn decode_sample_snapshot(
    reader: &mut Reader<'_>,
    limits: RmiLimits,
) -> Result<SampleEventSnapshot, RmiDecodeError> {
    let thread_group =
        reader.optional_string("sample event thread group", limits.max_string_bytes)?;
    let host = decode_host_presence(reader, limits)?;
    let variable_count = reader.count("sample event variables", limits.max_variables)?;
    let mut variables = Vec::with_capacity(variable_count);
    for _ in 0..variable_count {
        variables.push(WireVariable {
            name: reader.string("sample event variable name", limits.max_string_bytes)?,
            value: reader
                .optional_string("sample event variable value", limits.max_string_bytes)?,
        });
    }
    let is_transaction = reader.bool()?;
    let result = match reader.u8()? {
        0 => None,
        1 => Some(decode_sample(reader, limits, 1)?),
        other => return Err(RmiDecodeError::InvalidOptionMarker(other)),
    };
    Ok(SampleEventSnapshot {
        thread_group,
        host,
        variables,
        is_transaction,
        result,
    })
}

fn encode_host_presence(
    writer: &mut Writer,
    value: &HostPresence,
    limits: RmiLimits,
) -> Result<(), RmiEncodeError> {
    match value {
        HostPresence::Absent => writer.u8(0),
        HostPresence::Null => writer.u8(1),
        HostPresence::Present(value) => {
            writer.u8(2);
            writer.string(value, limits.max_string_bytes)?;
        }
    }
    Ok(())
}

fn decode_host_presence(
    reader: &mut Reader<'_>,
    limits: RmiLimits,
) -> Result<HostPresence, RmiDecodeError> {
    match reader.u8()? {
        0 => Ok(HostPresence::Absent),
        1 => Ok(HostPresence::Null),
        2 => Ok(HostPresence::Present(
            reader.string("callback host", limits.max_string_bytes)?,
        )),
        other => Err(RmiDecodeError::InvalidOptionMarker(other)),
    }
}

fn encode_sample_started(
    writer: &mut Writer,
    value: &SampleStarted,
    limits: RmiLimits,
) -> Result<(), RmiEncodeError> {
    encode_sample_started_payload(writer, value, limits, true)
}

fn encode_sample_started_payload(
    writer: &mut Writer,
    value: &SampleStarted,
    limits: RmiLimits,
    include_callback_metadata: bool,
) -> Result<(), RmiEncodeError> {
    if include_callback_metadata {
        writer.u64(value.callback_invocation_ordinal);
        writer.u64(value.delivered_event_ordinal);
        writer.u8(value.delivery_kind as u8);
    }
    writer.u64(value.sample_id);
    writer.optional_u64(value.parent_id);
    writer.optional_string(value.label.as_deref(), limits.max_string_bytes)?;
    encode_sample_snapshot(writer, &value.snapshot, limits)?;
    Ok(())
}

fn decode_sample_started(
    reader: &mut Reader<'_>,
    limits: RmiLimits,
) -> Result<SampleStarted, RmiDecodeError> {
    decode_sample_started_payload(reader, limits, true)
}

fn decode_sample_started_payload(
    reader: &mut Reader<'_>,
    limits: RmiLimits,
    include_callback_metadata: bool,
) -> Result<SampleStarted, RmiDecodeError> {
    let (callback_invocation_ordinal, delivered_event_ordinal, delivery_kind) =
        if include_callback_metadata {
            (
                reader.u64()?,
                reader.u64()?,
                DeliveryKind::from_wire(reader.u8()?)?,
            )
        } else {
            (0, 0, DeliveryKind::ProcessBatch)
        };
    Ok(SampleStarted {
        callback_invocation_ordinal,
        delivered_event_ordinal,
        delivery_kind,
        sample_id: reader.u64()?,
        parent_id: reader.optional_u64()?,
        label: reader.optional_string("sample-start label", limits.max_string_bytes)?,
        snapshot: decode_sample_snapshot(reader, limits)?,
    })
}

fn encode_sample_occurred(
    writer: &mut Writer,
    value: &SampleOccurred,
    limits: RmiLimits,
) -> Result<(), RmiEncodeError> {
    encode_sample_occurred_payload(writer, value, limits, true)
}

fn encode_sample_occurred_payload(
    writer: &mut Writer,
    value: &SampleOccurred,
    limits: RmiLimits,
    include_callback_metadata: bool,
) -> Result<(), RmiEncodeError> {
    if include_callback_metadata {
        writer.u64(value.callback_invocation_ordinal);
        writer.u64(value.delivered_event_ordinal);
        writer.u8(value.delivery_kind as u8);
    }
    writer.u64(value.sample_id);
    encode_sample(writer, &value.result, limits)?;
    encode_sample_snapshot(writer, &value.snapshot, limits)
}

fn decode_sample_occurred(
    reader: &mut Reader<'_>,
    limits: RmiLimits,
) -> Result<SampleOccurred, RmiDecodeError> {
    decode_sample_occurred_payload(reader, limits, true)
}

fn decode_sample_occurred_payload(
    reader: &mut Reader<'_>,
    limits: RmiLimits,
    include_callback_metadata: bool,
) -> Result<SampleOccurred, RmiDecodeError> {
    let (callback_invocation_ordinal, delivered_event_ordinal, delivery_kind) =
        if include_callback_metadata {
            (
                reader.u64()?,
                reader.u64()?,
                DeliveryKind::from_wire(reader.u8()?)?,
            )
        } else {
            (0, 0, DeliveryKind::ProcessBatch)
        };
    Ok(SampleOccurred {
        callback_invocation_ordinal,
        delivered_event_ordinal,
        delivery_kind,
        sample_id: reader.u64()?,
        result: decode_sample(reader, limits, 1)?,
        snapshot: decode_sample_snapshot(reader, limits)?,
    })
}

fn encode_sample_stopped(
    writer: &mut Writer,
    value: &SampleStopped,
    limits: RmiLimits,
) -> Result<(), RmiEncodeError> {
    encode_sample_stopped_payload(writer, value, limits, true)
}

fn encode_sample_stopped_payload(
    writer: &mut Writer,
    value: &SampleStopped,
    limits: RmiLimits,
    include_callback_metadata: bool,
) -> Result<(), RmiEncodeError> {
    if include_callback_metadata {
        writer.u64(value.callback_invocation_ordinal);
        writer.u64(value.delivered_event_ordinal);
        writer.u8(value.delivery_kind as u8);
    }
    writer.u64(value.sample_id);
    writer.u8(value.outcome as u8);
    writer.u8(cancellation_to_wire(value.cancellation));
    encode_sample_snapshot(writer, &value.snapshot, limits)
}

fn decode_sample_stopped(
    reader: &mut Reader<'_>,
    limits: RmiLimits,
) -> Result<SampleStopped, RmiDecodeError> {
    decode_sample_stopped_payload(reader, limits, true)
}

fn decode_sample_stopped_payload(
    reader: &mut Reader<'_>,
    limits: RmiLimits,
    include_callback_metadata: bool,
) -> Result<SampleStopped, RmiDecodeError> {
    let (callback_invocation_ordinal, delivered_event_ordinal, delivery_kind) =
        if include_callback_metadata {
            (
                reader.u64()?,
                reader.u64()?,
                DeliveryKind::from_wire(reader.u8()?)?,
            )
        } else {
            (0, 0, DeliveryKind::ProcessBatch)
        };
    Ok(SampleStopped {
        callback_invocation_ordinal,
        delivered_event_ordinal,
        delivery_kind,
        sample_id: reader.u64()?,
        outcome: SampleStopOutcome::from_wire(reader.u8()?)?,
        cancellation: cancellation_from_wire(reader.u8()?)?,
        snapshot: decode_sample_snapshot(reader, limits)?,
    })
}

fn encode_batch(
    writer: &mut Writer,
    value: &Batch,
    limits: RmiLimits,
) -> Result<(), RmiEncodeError> {
    writer.u8(value.sender as u8);
    writer.u64(value.callback_invocation_ordinal);
    writer.u64(value.first_delivered_event_ordinal);
    writer.u64(value.batch_id);
    writer.u8(value.delivery_kind as u8);
    writer.u64(value.event_count);
    writer.count(value.items.len(), limits.max_batch_items)?;
    for item in &value.items {
        writer.u64(item.sequence);
        writer.u64(item.request_id);
        encode_remaining_duration(writer, item.remaining_duration);
        writer.u8(cancellation_to_wire(item.cancellation));
        writer.u8(item.event.kind() as u8);
        match &item.event {
            SampleEvent::Started(value) => {
                encode_sample_started_payload(writer, value, limits, false)?
            }
            SampleEvent::Occurred(value) => {
                encode_sample_occurred_payload(writer, value, limits, false)?
            }
            SampleEvent::Stopped(value) => {
                encode_sample_stopped_payload(writer, value, limits, false)?
            }
        }
    }
    Ok(())
}

fn decode_batch(reader: &mut Reader<'_>, limits: RmiLimits) -> Result<Batch, RmiDecodeError> {
    let sender = SenderMode::from_wire(reader.u8()?)?;
    let callback_invocation_ordinal = reader.u64()?;
    let first_delivered_event_ordinal = reader.u64()?;
    let batch_id = reader.u64()?;
    let delivery_kind = DeliveryKind::from_wire(reader.u8()?)?;
    let event_count = reader.u64()?;
    let count = reader.count("batch items", limits.max_batch_items)?;
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        let sequence = reader.u64()?;
        let request_id = reader.u64()?;
        let remaining_duration = decode_remaining_duration(reader)?;
        let cancellation = cancellation_from_wire(reader.u8()?)?;
        let kind = EventKind::from_wire(reader.u8()?)?;
        let event = match kind {
            EventKind::SampleStarted => {
                SampleEvent::Started(decode_sample_started_payload(reader, limits, false)?)
            }
            EventKind::SampleOccurred => {
                SampleEvent::Occurred(decode_sample_occurred_payload(reader, limits, false)?)
            }
            EventKind::SampleStopped => {
                SampleEvent::Stopped(decode_sample_stopped_payload(reader, limits, false)?)
            }
            _ => return Err(RmiDecodeError::InvalidBatchEvent(kind)),
        };
        items.push(BatchItem {
            sequence,
            request_id,
            remaining_duration,
            cancellation,
            event,
        });
    }
    Ok(Batch {
        sender,
        callback_invocation_ordinal,
        first_delivered_event_ordinal,
        batch_id,
        delivery_kind,
        event_count,
        items,
    })
}

fn encode_worker_failure(
    writer: &mut Writer,
    value: &WorkerFailure,
    limits: RmiLimits,
) -> Result<(), RmiEncodeError> {
    writer.string(&value.worker_id, limits.max_string_bytes)?;
    writer.u16(value.code as u16);
    writer.u8(value.phase as u8);
    encode_retry_disposition(writer, value.retry);
    writer.optional_string(value.message.as_deref(), limits.max_string_bytes)?;
    Ok(())
}

fn decode_worker_failure(
    reader: &mut Reader<'_>,
    limits: RmiLimits,
) -> Result<WorkerFailure, RmiDecodeError> {
    Ok(WorkerFailure {
        worker_id: reader.string("failure worker id", limits.max_string_bytes)?,
        code: WorkerFailureCode::from_wire(reader.u16()?)?,
        phase: FailurePhase::from_wire(reader.u8()?)?,
        retry: decode_retry_disposition(reader)?,
        message: reader.optional_string("failure message", limits.max_string_bytes)?,
    })
}

fn encode_retry_disposition(writer: &mut Writer, value: RetryDisposition) {
    match value {
        RetryDisposition::PreStartSafe {
            reason,
            next_attempt,
        } => {
            writer.u8(1);
            writer.u8(reason as u8);
            writer.u32(next_attempt);
        }
        RetryDisposition::FinalNonRetryable {
            phase,
            outcome_certainty,
        } => {
            writer.u8(2);
            writer.u8(phase as u8);
            writer.u8(outcome_certainty as u8);
        }
        RetryDisposition::PoisonedUnknownOutcome => writer.u8(3),
    }
}

fn decode_retry_disposition(reader: &mut Reader<'_>) -> Result<RetryDisposition, RmiDecodeError> {
    match reader.u8()? {
        1 => Ok(RetryDisposition::PreStartSafe {
            reason: RetryReason::from_wire(reader.u8()?)?,
            next_attempt: reader.u32()?,
        }),
        2 => Ok(RetryDisposition::FinalNonRetryable {
            phase: RetryPhase::from_wire(reader.u8()?)?,
            outcome_certainty: OutcomeCertainty::from_wire(reader.u8()?)?,
        }),
        3 => Ok(RetryDisposition::PoisonedUnknownOutcome),
        other => Err(RmiDecodeError::InvalidEnum {
            field: "retry disposition",
            value: other as u64,
        }),
    }
}

fn encode_accounting(writer: &mut Writer, value: StreamAccounting) {
    writer.u64(value.delivered_events);
    writer.u64(value.accepted_events);
    writer.u64(value.acknowledged_events);
    writer.u64(value.delivered_bytes);
    writer.u64(value.accepted_bytes);
    writer.u64(value.acknowledged_bytes);
    writer.u64(value.pending_bridge_events);
    writer.u64(value.pending_sender_events);
    writer.u64(value.pending_blobs);
}

fn decode_accounting(reader: &mut Reader<'_>) -> Result<StreamAccounting, RmiDecodeError> {
    Ok(StreamAccounting {
        delivered_events: reader.u64()?,
        accepted_events: reader.u64()?,
        acknowledged_events: reader.u64()?,
        delivered_bytes: reader.u64()?,
        accepted_bytes: reader.u64()?,
        acknowledged_bytes: reader.u64()?,
        pending_bridge_events: reader.u64()?,
        pending_sender_events: reader.u64()?,
        pending_blobs: reader.u64()?,
    })
}

fn encode_test_ended(
    writer: &mut Writer,
    value: &TestEnded,
    limits: RmiLimits,
) -> Result<(), RmiEncodeError> {
    writer.u8(value.overload as u8);
    encode_host_presence(writer, &value.host, limits)?;
    writer.u64(value.callback_invocation_ordinal);
    encode_accounting(writer, value.accounting);
    encode_queue(writer, value.queue);
    Ok(())
}

fn decode_test_ended(
    reader: &mut Reader<'_>,
    limits: RmiLimits,
) -> Result<TestEnded, RmiDecodeError> {
    Ok(TestEnded {
        overload: LifecycleOverload::from_wire(reader.u8()?)?,
        host: decode_host_presence(reader, limits)?,
        callback_invocation_ordinal: reader.u64()?,
        accounting: decode_accounting(reader)?,
        queue: decode_queue(reader)?,
    })
}

fn encode_sender_proof(
    writer: &mut Writer,
    value: &SenderDrainProof,
    limits: RmiLimits,
) -> Result<(), RmiEncodeError> {
    match value {
        SenderDrainProof::Proven(evidence) => {
            writer.u8(1);
            writer.u8(evidence.sender as u8);
            writer.u64(evidence.generation);
            writer.u64(evidence.final_delivered_event_ordinal);
            writer.u64(evidence.emitted_events);
            writer.u64(evidence.accepted_events);
            writer.u64(evidence.acknowledged_events);
            writer.u64(evidence.emitted_bytes);
            writer.u64(evidence.accepted_bytes);
            writer.u64(evidence.acknowledged_bytes);
            writer.u64(evidence.pending_sender_events);
            writer.u64(evidence.pending_disk_events);
            writer.string(&evidence.completion_hook, limits.max_string_bytes)?;
            writer.bytes(&evidence.proof_digest.as_bytes())?;
        }
        SenderDrainProof::Required { sender, reason } => {
            writer.u8(2);
            writer.u8(*sender as u8);
            writer.u8(*reason as u8);
        }
        SenderDrainProof::Unavailable { sender, reason } => {
            writer.u8(3);
            writer.u8(*sender as u8);
            writer.u8(*reason as u8);
        }
    }
    Ok(())
}

fn decode_sender_proof(
    reader: &mut Reader<'_>,
    limits: RmiLimits,
) -> Result<SenderDrainProof, RmiDecodeError> {
    match reader.u8()? {
        1 => Ok(SenderDrainProof::Proven(SenderDrainEvidence {
            sender: SenderMode::from_wire(reader.u8()?)?,
            generation: reader.u64()?,
            final_delivered_event_ordinal: reader.u64()?,
            emitted_events: reader.u64()?,
            accepted_events: reader.u64()?,
            acknowledged_events: reader.u64()?,
            emitted_bytes: reader.u64()?,
            accepted_bytes: reader.u64()?,
            acknowledged_bytes: reader.u64()?,
            pending_sender_events: reader.u64()?,
            pending_disk_events: reader.u64()?,
            completion_hook: reader.string("sender completion hook", limits.max_string_bytes)?,
            proof_digest: Sha256Digest::from_bytes(reader.array::<32>()?),
        })),
        2 => Ok(SenderDrainProof::Required {
            sender: SenderMode::from_wire(reader.u8()?)?,
            reason: SenderProofRequirement::from_wire(reader.u8()?)?,
        }),
        3 => Ok(SenderDrainProof::Unavailable {
            sender: SenderMode::from_wire(reader.u8()?)?,
            reason: SenderProofAbsenceReason::from_wire(reader.u8()?)?,
        }),
        other => Err(RmiDecodeError::InvalidEnum {
            field: "sender drain proof",
            value: other as u64,
        }),
    }
}

fn encode_terminal(
    writer: &mut Writer,
    value: &Terminal,
    limits: RmiLimits,
) -> Result<(), RmiEncodeError> {
    writer.u8(value.status as u8);
    match &value.failure {
        Some(failure) => {
            writer.u8(1);
            encode_worker_failure(writer, failure, limits)?;
        }
        None => writer.u8(0),
    }
    encode_accounting(writer, value.accounting);
    encode_sender_proof(writer, &value.sender_proof, limits)?;
    encode_optional_u64(writer, value.test_ended_callback_ordinal);
    match value.test_ended_absence_reason {
        Some(reason) => writer.u8(reason as u8),
        None => writer.u8(0),
    }
    match value.router_finalization_digest {
        Some(digest) => {
            writer.u8(1);
            writer.bytes(&digest.as_bytes())?;
        }
        None => writer.u8(0),
    }
    encode_queue(writer, value.queue);
    Ok(())
}

fn decode_terminal(reader: &mut Reader<'_>, limits: RmiLimits) -> Result<Terminal, RmiDecodeError> {
    let status = TerminalStatus::from_wire(reader.u8()?)?;
    let failure = match reader.u8()? {
        0 => None,
        1 => Some(decode_worker_failure(reader, limits)?),
        other => return Err(RmiDecodeError::InvalidOptionMarker(other)),
    };
    let accounting = decode_accounting(reader)?;
    let sender_proof = decode_sender_proof(reader, limits)?;
    let test_ended_callback_ordinal = decode_optional_u64(reader)?;
    let test_ended_absence_reason = match reader.u8()? {
        0 => None,
        value => Some(TestEndedAbsenceReason::from_wire(value)?),
    };
    let router_finalization_digest = match reader.u8()? {
        0 => None,
        1 => Some(Sha256Digest::from_bytes(reader.array::<32>()?)),
        other => return Err(RmiDecodeError::InvalidOptionMarker(other)),
    };
    Ok(Terminal {
        status,
        failure,
        accounting,
        sender_proof,
        test_ended_callback_ordinal,
        test_ended_absence_reason,
        router_finalization_digest,
        queue: decode_queue(reader)?,
    })
}

fn backpressure_to_wire(value: BackpressurePolicy) -> u8 {
    value as u8
}

fn encode_queue(writer: &mut Writer, value: QueueCredit) {
    writer.u64(value.capacity);
    writer.u64(value.available);
    writer.u64(value.bytes_capacity);
    writer.u64(value.bytes_available);
}

fn decode_queue(reader: &mut Reader<'_>) -> Result<QueueCredit, RmiDecodeError> {
    Ok(QueueCredit {
        capacity: reader.u64()?,
        available: reader.u64()?,
        bytes_capacity: reader.u64()?,
        bytes_available: reader.u64()?,
    })
}

const SAMPLE_LABEL: u64 = 1 << 0;
const SAMPLE_TIMESTAMP: u64 = 1 << 1;
const SAMPLE_START: u64 = 1 << 2;
const SAMPLE_END: u64 = 1 << 3;
const SAMPLE_ELAPSED: u64 = 1 << 4;
const SAMPLE_LATENCY: u64 = 1 << 5;
const SAMPLE_CONNECT: u64 = 1 << 6;
const SAMPLE_IDLE: u64 = 1 << 7;
const SAMPLE_SUCCESS: u64 = 1 << 8;
const SAMPLE_RESPONSE_CODE: u64 = 1 << 9;
const SAMPLE_RESPONSE_MESSAGE: u64 = 1 << 10;
const SAMPLE_FAILURE_MESSAGE: u64 = 1 << 11;
const SAMPLE_DATA_TYPE: u64 = 1 << 12;
const SAMPLE_DATA_ENCODING: u64 = 1 << 13;
const SAMPLE_REQUEST_DATA: u64 = 1 << 14;
const SAMPLE_RESPONSE_DATA: u64 = 1 << 15;
const SAMPLE_REQUEST_HEADERS: u64 = 1 << 16;
const SAMPLE_RESPONSE_HEADERS: u64 = 1 << 17;
const SAMPLE_SAMPLER_DATA: u64 = 1 << 18;
const SAMPLE_RESPONSE_FILE: u64 = 1 << 19;
const SAMPLE_URL: u64 = 1 << 20;
const SAMPLE_RECEIVED_BYTES: u64 = 1 << 21;
const SAMPLE_SENT_BYTES: u64 = 1 << 22;
const SAMPLE_GROUP_THREADS: u64 = 1 << 23;
const SAMPLE_ALL_THREADS: u64 = 1 << 24;
const SAMPLE_COUNT: u64 = 1 << 25;
const SAMPLE_ERROR_COUNT: u64 = 1 << 26;
const SAMPLE_THREAD_NAME: u64 = 1 << 27;
const SAMPLE_HOST: u64 = 1 << 28;
const SAMPLE_KNOWN_MASK: u64 = (1 << 29) - 1;

fn sample_presence(value: &WireSampleResult) -> u64 {
    let mut mask = 0_u64;
    for (present, bit) in [
        (value.label.is_some(), SAMPLE_LABEL),
        (value.timestamp.is_some(), SAMPLE_TIMESTAMP),
        (value.start_time.is_some(), SAMPLE_START),
        (value.end_time.is_some(), SAMPLE_END),
        (value.elapsed.is_some(), SAMPLE_ELAPSED),
        (value.latency.is_some(), SAMPLE_LATENCY),
        (value.connect_time.is_some(), SAMPLE_CONNECT),
        (value.idle_time.is_some(), SAMPLE_IDLE),
        (value.success.is_some(), SAMPLE_SUCCESS),
        (value.response_code.is_some(), SAMPLE_RESPONSE_CODE),
        (value.response_message.is_some(), SAMPLE_RESPONSE_MESSAGE),
        (value.failure_message.is_some(), SAMPLE_FAILURE_MESSAGE),
        (value.data_type.is_some(), SAMPLE_DATA_TYPE),
        (value.data_encoding.is_some(), SAMPLE_DATA_ENCODING),
        (value.request_data.is_some(), SAMPLE_REQUEST_DATA),
        (value.response_data.is_some(), SAMPLE_RESPONSE_DATA),
        (value.request_headers.is_some(), SAMPLE_REQUEST_HEADERS),
        (value.response_headers.is_some(), SAMPLE_RESPONSE_HEADERS),
        (value.sampler_data.is_some(), SAMPLE_SAMPLER_DATA),
        (value.response_file.is_some(), SAMPLE_RESPONSE_FILE),
        (value.url.is_some(), SAMPLE_URL),
        (value.received_bytes.is_some(), SAMPLE_RECEIVED_BYTES),
        (value.sent_bytes.is_some(), SAMPLE_SENT_BYTES),
        (value.group_threads.is_some(), SAMPLE_GROUP_THREADS),
        (value.all_threads.is_some(), SAMPLE_ALL_THREADS),
        (value.sample_count.is_some(), SAMPLE_COUNT),
        (value.error_count.is_some(), SAMPLE_ERROR_COUNT),
        (value.thread_name.is_some(), SAMPLE_THREAD_NAME),
        (value.host.is_some(), SAMPLE_HOST),
    ] {
        if present {
            mask |= bit;
        }
    }
    mask
}

fn encode_sample(
    writer: &mut Writer,
    value: &WireSampleResult,
    limits: RmiLimits,
) -> Result<(), RmiEncodeError> {
    value.validate(limits).map_err(RmiEncodeError::Sample)?;
    let presence = sample_presence(value);
    writer.u64(presence);
    if let Some(value) = &value.label {
        writer.string(value, limits.max_string_bytes)?;
    }
    for (present, value) in [
        (value.timestamp.is_some(), value.timestamp),
        (value.start_time.is_some(), value.start_time),
        (value.end_time.is_some(), value.end_time),
    ] {
        if present {
            writer.i64(value.unwrap_or_default());
        }
    }
    for (present, value) in [
        (value.elapsed.is_some(), value.elapsed),
        (value.latency.is_some(), value.latency),
        (value.connect_time.is_some(), value.connect_time),
        (value.idle_time.is_some(), value.idle_time),
    ] {
        if present {
            writer.u64(value.unwrap_or_default());
        }
    }
    if let Some(value) = value.success {
        writer.bool(value);
    }
    for (bit, value) in [
        (SAMPLE_RESPONSE_CODE, value.response_code.as_deref()),
        (SAMPLE_RESPONSE_MESSAGE, value.response_message.as_deref()),
        (SAMPLE_FAILURE_MESSAGE, value.failure_message.as_deref()),
        (SAMPLE_DATA_TYPE, value.data_type.as_deref()),
        (SAMPLE_DATA_ENCODING, value.data_encoding.as_deref()),
    ] {
        if presence & bit != 0 {
            writer.string(value.unwrap_or_default(), limits.max_string_bytes)?;
        }
    }
    for (bit, value) in [
        (SAMPLE_REQUEST_DATA, value.request_data.as_deref()),
        (SAMPLE_RESPONSE_DATA, value.response_data.as_deref()),
    ] {
        if presence & bit != 0 {
            writer.data(value.unwrap_or_default(), limits.max_bytes_field)?;
        }
    }
    for (bit, value) in [
        (SAMPLE_REQUEST_HEADERS, value.request_headers.as_deref()),
        (SAMPLE_RESPONSE_HEADERS, value.response_headers.as_deref()),
        (SAMPLE_SAMPLER_DATA, value.sampler_data.as_deref()),
        (SAMPLE_RESPONSE_FILE, value.response_file.as_deref()),
        (SAMPLE_URL, value.url.as_deref()),
    ] {
        if presence & bit != 0 {
            writer.string(value.unwrap_or_default(), limits.max_string_bytes)?;
        }
    }
    for (present, value) in [
        (value.received_bytes.is_some(), value.received_bytes),
        (value.sent_bytes.is_some(), value.sent_bytes),
        (value.group_threads.is_some(), value.group_threads),
        (value.all_threads.is_some(), value.all_threads),
        (value.sample_count.is_some(), value.sample_count),
        (value.error_count.is_some(), value.error_count),
    ] {
        if present {
            writer.u64(value.unwrap_or_default());
        }
    }
    if let Some(value) = &value.thread_name {
        writer.string(value, limits.max_string_bytes)?;
    }
    if let Some(value) = &value.host {
        writer.string(value, limits.max_string_bytes)?;
    }
    encode_sample_flags(writer, value.flags);
    writer.count(value.variables.len(), limits.max_variables)?;
    for variable in &value.variables {
        writer.string(&variable.name, limits.max_string_bytes)?;
        writer.optional_string(variable.value.as_deref(), limits.max_string_bytes)?;
    }
    writer.count(value.assertions.len(), limits.max_assertions)?;
    for assertion in &value.assertions {
        writer.string(&assertion.name, limits.max_string_bytes)?;
        writer.bool(assertion.failure);
        writer.bool(assertion.error);
        writer.optional_string(
            assertion.failure_message.as_deref(),
            limits.max_string_bytes,
        )?;
        writer.optional_string(assertion.error_message.as_deref(), limits.max_string_bytes)?;
    }
    writer.count(value.sub_results.len(), limits.max_children)?;
    for child in &value.sub_results {
        encode_sample(writer, child, limits)?;
    }
    encode_jtl_metadata(writer, &value.jtl, limits)
}

fn decode_sample(
    reader: &mut Reader<'_>,
    limits: RmiLimits,
    depth: usize,
) -> Result<WireSampleResult, RmiDecodeError> {
    if depth > limits.max_sample_depth {
        return Err(RmiDecodeError::Depth {
            actual: depth,
            maximum: limits.max_sample_depth,
        });
    }
    let mask = reader.u64()?;
    if mask & !SAMPLE_KNOWN_MASK != 0 {
        return Err(RmiDecodeError::UnknownSampleFields(
            mask & !SAMPLE_KNOWN_MASK,
        ));
    }
    let label = read_if(mask, SAMPLE_LABEL, || {
        reader.string("sample label", limits.max_string_bytes)
    })
    .transpose()?;
    let timestamp = read_if(mask, SAMPLE_TIMESTAMP, || reader.i64()).transpose()?;
    let start_time = read_if(mask, SAMPLE_START, || reader.i64()).transpose()?;
    let end_time = read_if(mask, SAMPLE_END, || reader.i64()).transpose()?;
    let elapsed = read_if(mask, SAMPLE_ELAPSED, || reader.u64()).transpose()?;
    let latency = read_if(mask, SAMPLE_LATENCY, || reader.u64()).transpose()?;
    let connect_time = read_if(mask, SAMPLE_CONNECT, || reader.u64()).transpose()?;
    let idle_time = read_if(mask, SAMPLE_IDLE, || reader.u64()).transpose()?;
    let success = read_if(mask, SAMPLE_SUCCESS, || reader.bool()).transpose()?;
    let response_code = decode_optional_string_by_mask(
        reader,
        mask,
        SAMPLE_RESPONSE_CODE,
        "response code",
        limits,
    )?;
    let response_message = decode_optional_string_by_mask(
        reader,
        mask,
        SAMPLE_RESPONSE_MESSAGE,
        "response message",
        limits,
    )?;
    let failure_message = decode_optional_string_by_mask(
        reader,
        mask,
        SAMPLE_FAILURE_MESSAGE,
        "failure message",
        limits,
    )?;
    let data_type =
        decode_optional_string_by_mask(reader, mask, SAMPLE_DATA_TYPE, "data type", limits)?;
    let data_encoding = decode_optional_string_by_mask(
        reader,
        mask,
        SAMPLE_DATA_ENCODING,
        "data encoding",
        limits,
    )?;
    let request_data = decode_optional_data_by_mask(reader, mask, SAMPLE_REQUEST_DATA, limits)?;
    let response_data = decode_optional_data_by_mask(reader, mask, SAMPLE_RESPONSE_DATA, limits)?;
    let request_headers = decode_optional_string_by_mask(
        reader,
        mask,
        SAMPLE_REQUEST_HEADERS,
        "request headers",
        limits,
    )?;
    let response_headers = decode_optional_string_by_mask(
        reader,
        mask,
        SAMPLE_RESPONSE_HEADERS,
        "response headers",
        limits,
    )?;
    let sampler_data =
        decode_optional_string_by_mask(reader, mask, SAMPLE_SAMPLER_DATA, "sampler data", limits)?;
    let response_file = decode_optional_string_by_mask(
        reader,
        mask,
        SAMPLE_RESPONSE_FILE,
        "response file",
        limits,
    )?;
    let url = decode_optional_string_by_mask(reader, mask, SAMPLE_URL, "URL", limits)?;
    let received_bytes = read_if(mask, SAMPLE_RECEIVED_BYTES, || reader.u64()).transpose()?;
    let sent_bytes = read_if(mask, SAMPLE_SENT_BYTES, || reader.u64()).transpose()?;
    let group_threads = read_if(mask, SAMPLE_GROUP_THREADS, || reader.u64()).transpose()?;
    let all_threads = read_if(mask, SAMPLE_ALL_THREADS, || reader.u64()).transpose()?;
    let sample_count = read_if(mask, SAMPLE_COUNT, || reader.u64()).transpose()?;
    let error_count = read_if(mask, SAMPLE_ERROR_COUNT, || reader.u64()).transpose()?;
    let thread_name =
        decode_optional_string_by_mask(reader, mask, SAMPLE_THREAD_NAME, "thread name", limits)?;
    let host = decode_optional_string_by_mask(reader, mask, SAMPLE_HOST, "host", limits)?;
    let flags = decode_sample_flags(reader)?;
    let variable_count = reader.count("sample variables", limits.max_variables)?;
    let mut variables = Vec::with_capacity(variable_count);
    for _ in 0..variable_count {
        variables.push(WireVariable {
            name: reader.string("variable name", limits.max_string_bytes)?,
            value: reader.optional_string("variable value", limits.max_string_bytes)?,
        });
    }
    let assertion_count = reader.count("assertions", limits.max_assertions)?;
    let mut assertions = Vec::with_capacity(assertion_count);
    for _ in 0..assertion_count {
        assertions.push(WireAssertion {
            name: reader.string("assertion name", limits.max_string_bytes)?,
            failure: reader.bool()?,
            error: reader.bool()?,
            failure_message: reader
                .optional_string("assertion failure message", limits.max_string_bytes)?,
            error_message: reader
                .optional_string("assertion error message", limits.max_string_bytes)?,
        });
    }
    let child_count = reader.count("sub-results", limits.max_children)?;
    let mut sub_results = Vec::with_capacity(child_count);
    for _ in 0..child_count {
        sub_results.push(decode_sample(reader, limits, depth.saturating_add(1))?);
    }
    let jtl = decode_jtl_metadata(reader, limits)?;
    Ok(WireSampleResult {
        label,
        timestamp,
        start_time,
        end_time,
        elapsed,
        latency,
        connect_time,
        idle_time,
        success,
        response_code,
        response_message,
        failure_message,
        data_type,
        data_encoding,
        request_data,
        response_data,
        request_headers,
        response_headers,
        sampler_data,
        response_file,
        url,
        received_bytes,
        sent_bytes,
        group_threads,
        all_threads,
        sample_count,
        error_count,
        flags,
        thread_name,
        host,
        variables,
        assertions,
        sub_results,
        jtl,
    })
}

fn read_if<T, F>(mask: u64, bit: u64, reader: F) -> Option<Result<T, RmiDecodeError>>
where
    F: FnOnce() -> Result<T, RmiDecodeError>,
{
    (mask & bit != 0).then(reader)
}

fn decode_optional_string_by_mask(
    reader: &mut Reader<'_>,
    mask: u64,
    bit: u64,
    field: &'static str,
    limits: RmiLimits,
) -> Result<Option<String>, RmiDecodeError> {
    match read_if(mask, bit, || reader.string(field, limits.max_string_bytes)).transpose()? {
        Some(value) => Ok(Some(value)),
        None => Ok(None),
    }
}

fn decode_optional_data_by_mask(
    reader: &mut Reader<'_>,
    mask: u64,
    bit: u64,
    limits: RmiLimits,
) -> Result<Option<Vec<u8>>, RmiDecodeError> {
    match read_if(mask, bit, || reader.data(limits.max_bytes_field)).transpose()? {
        Some(value) => Ok(Some(value)),
        None => Ok(None),
    }
}

fn encode_sample_flags(writer: &mut Writer, flags: SampleFlags) {
    let mut bits = 0_u8;
    if flags.stop_thread {
        bits |= 1 << 0;
    }
    if flags.stop_test {
        bits |= 1 << 1;
    }
    if flags.stop_test_now {
        bits |= 1 << 2;
    }
    if flags.start_next_loop {
        bits |= 1 << 3;
    }
    if flags.ignored {
        bits |= 1 << 4;
    }
    writer.u8(bits);
    writer.u8(flags.logical_action.map_or(0, |value| value as u8));
}

fn decode_sample_flags(reader: &mut Reader<'_>) -> Result<SampleFlags, RmiDecodeError> {
    let bits = reader.u8()?;
    if bits & !0x1f != 0 {
        return Err(RmiDecodeError::UnknownFlags(bits & !0x1f));
    }
    let action = match reader.u8()? {
        0 => None,
        value => Some(LogicalAction::from_wire(value)?),
    };
    Ok(SampleFlags {
        stop_thread: bits & (1 << 0) != 0,
        stop_test: bits & (1 << 1) != 0,
        stop_test_now: bits & (1 << 2) != 0,
        start_next_loop: bits & (1 << 3) != 0,
        ignored: bits & (1 << 4) != 0,
        logical_action: action,
    })
}

fn encode_jtl_metadata(
    writer: &mut Writer,
    value: &JtlMetadata,
    limits: RmiLimits,
) -> Result<(), RmiEncodeError> {
    value.validate(limits).map_err(RmiEncodeError::Sample)?;
    writer.optional_string(value.sample_element.as_deref(), limits.max_string_bytes)?;
    encode_attributes(writer, &value.attributes, limits)?;
    encode_nodes(writer, &value.children, limits, 1)?;
    encode_attributes(writer, &value.root_attributes, limits)?;
    encode_nodes(writer, &value.root_children, limits, 1)?;
    encode_nodes(writer, &value.root_children_after, limits, 1)
}

fn decode_jtl_metadata(
    reader: &mut Reader<'_>,
    limits: RmiLimits,
) -> Result<JtlMetadata, RmiDecodeError> {
    Ok(JtlMetadata {
        sample_element: reader.optional_string("JTL sample element", limits.max_string_bytes)?,
        attributes: decode_attributes(reader, limits)?,
        children: decode_nodes(reader, limits, 1)?,
        root_attributes: decode_attributes(reader, limits)?,
        root_children: decode_nodes(reader, limits, 1)?,
        root_children_after: decode_nodes(reader, limits, 1)?,
    })
}

fn encode_attributes(
    writer: &mut Writer,
    attributes: &[JtlAttribute],
    limits: RmiLimits,
) -> Result<(), RmiEncodeError> {
    writer.count(attributes.len(), limits.max_attributes)?;
    for attribute in attributes {
        writer.string(&attribute.name, limits.max_string_bytes)?;
        writer.string(&attribute.value, limits.max_string_bytes)?;
    }
    Ok(())
}

fn decode_attributes(
    reader: &mut Reader<'_>,
    limits: RmiLimits,
) -> Result<Vec<JtlAttribute>, RmiDecodeError> {
    let count = reader.count("JTL attributes", limits.max_attributes)?;
    let mut attributes = Vec::with_capacity(count);
    for _ in 0..count {
        attributes.push(JtlAttribute {
            name: reader.string("JTL attribute name", limits.max_string_bytes)?,
            value: reader.string("JTL attribute value", limits.max_string_bytes)?,
        });
    }
    Ok(attributes)
}

fn encode_nodes(
    writer: &mut Writer,
    nodes: &[JtlNode],
    limits: RmiLimits,
    depth: usize,
) -> Result<(), RmiEncodeError> {
    if depth > limits.max_sample_depth {
        return Err(RmiEncodeError::Sample(SampleValidationError::Depth {
            actual: depth,
            maximum: limits.max_sample_depth,
        }));
    }
    writer.count(nodes.len(), limits.max_children)?;
    for node in nodes {
        writer.string(&node.name, limits.max_string_bytes)?;
        encode_attributes(writer, &node.attributes, limits)?;
        writer.optional_data(node.text.as_deref(), limits.max_bytes_field)?;
        encode_nodes(writer, &node.children, limits, depth.saturating_add(1))?;
    }
    Ok(())
}

fn decode_nodes(
    reader: &mut Reader<'_>,
    limits: RmiLimits,
    depth: usize,
) -> Result<Vec<JtlNode>, RmiDecodeError> {
    if depth > limits.max_sample_depth {
        return Err(RmiDecodeError::Depth {
            actual: depth,
            maximum: limits.max_sample_depth,
        });
    }
    let count = reader.count("JTL children", limits.max_children)?;
    let mut nodes = Vec::with_capacity(count);
    for _ in 0..count {
        nodes.push(JtlNode {
            name: reader.string("JTL node name", limits.max_string_bytes)?,
            attributes: decode_attributes(reader, limits)?,
            text: reader.optional_data(limits.max_bytes_field)?,
            children: decode_nodes(reader, limits, depth.saturating_add(1))?,
        });
    }
    Ok(nodes)
}

struct Writer {
    bytes: Vec<u8>,
    maximum: usize,
    overflowed: bool,
}

impl Writer {
    fn new(maximum: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(256),
            maximum,
            overflowed: false,
        }
    }

    fn ensure(&self, additional: usize) -> Result<(), RmiEncodeError> {
        let length = self
            .bytes
            .len()
            .checked_add(additional)
            .ok_or(RmiEncodeError::LengthOverflow)?;
        if length > self.maximum {
            return Err(RmiEncodeError::FrameTooLarge {
                actual: length,
                maximum: self.maximum,
            });
        }
        Ok(())
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), RmiEncodeError> {
        if self.overflowed {
            return Err(RmiEncodeError::FrameTooLarge {
                actual: self.maximum.saturating_add(1),
                maximum: self.maximum,
            });
        }
        self.ensure(value.len())?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn u8(&mut self, value: u8) {
        if self.bytes.len() < self.maximum {
            self.bytes.push(value);
        } else {
            self.overflowed = true;
        }
    }

    fn u16(&mut self, value: u16) {
        self.fixed(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.fixed(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.fixed(&value.to_be_bytes());
    }

    fn i64(&mut self, value: i64) {
        self.fixed(&value.to_be_bytes());
    }

    fn fixed(&mut self, value: &[u8]) {
        for byte in value {
            self.u8(*byte);
        }
    }

    fn bool(&mut self, value: bool) {
        self.u8(value as u8);
    }

    fn count(&mut self, value: usize, maximum: usize) -> Result<(), RmiEncodeError> {
        if value > maximum || value > u32::MAX as usize {
            return Err(RmiEncodeError::CountTooLarge {
                actual: value,
                maximum: maximum.min(u32::MAX as usize),
            });
        }
        self.u32(value as u32);
        Ok(())
    }

    fn string(&mut self, value: &str, maximum: usize) -> Result<(), RmiEncodeError> {
        if value.len() > maximum || value.len() > u32::MAX as usize {
            return Err(RmiEncodeError::FieldTooLong {
                field: "string",
                actual: value.len(),
                maximum: maximum.min(u32::MAX as usize),
            });
        }
        self.u32(value.len() as u32);
        self.bytes(value.as_bytes())
    }

    fn optional_string(
        &mut self,
        value: Option<&str>,
        maximum: usize,
    ) -> Result<(), RmiEncodeError> {
        match value {
            Some(value) => {
                self.u8(1);
                self.string(value, maximum)?;
            }
            None => self.u8(0),
        }
        Ok(())
    }

    fn data(&mut self, value: &[u8], maximum: usize) -> Result<(), RmiEncodeError> {
        if value.len() > maximum || value.len() > u32::MAX as usize {
            return Err(RmiEncodeError::FieldTooLong {
                field: "bytes",
                actual: value.len(),
                maximum: maximum.min(u32::MAX as usize),
            });
        }
        self.u32(value.len() as u32);
        self.bytes(value)
    }

    fn optional_data(
        &mut self,
        value: Option<&[u8]>,
        maximum: usize,
    ) -> Result<(), RmiEncodeError> {
        match value {
            Some(value) => {
                self.u8(1);
                self.data(value, maximum)?;
            }
            None => self.u8(0),
        }
        Ok(())
    }

    fn optional_u64(&mut self, value: Option<u64>) {
        match value {
            Some(value) => {
                self.u8(1);
                self.u64(value);
            }
            None => self.u8(0),
        }
    }

    fn finish(self) -> Result<Vec<u8>, RmiEncodeError> {
        if self.overflowed || self.bytes.len() > self.maximum {
            Err(RmiEncodeError::FrameTooLarge {
                actual: self.bytes.len().max(self.maximum.saturating_add(1)),
                maximum: self.maximum,
            })
        } else {
            Ok(self.bytes)
        }
    }
}

struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
    maximum: usize,
}

impl<'a> Reader<'a> {
    fn new(input: &'a [u8], maximum: usize) -> Self {
        Self {
            input,
            offset: 0,
            maximum,
        }
    }

    fn position(&self) -> usize {
        self.offset
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], RmiDecodeError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(RmiDecodeError::LengthOverflow)?;
        if end > self.maximum {
            return Err(RmiDecodeError::FrameTooLarge {
                declared: RMI_HEADER_LEN.saturating_add(end),
                maximum: RMI_HEADER_LEN.saturating_add(self.maximum),
            });
        }
        if end > self.input.len() {
            return Err(RmiDecodeError::Truncated {
                needed: end - self.input.len(),
            });
        }
        let value = &self.input[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, RmiDecodeError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, RmiDecodeError> {
        Ok(read_u16(self.take(2)?))
    }

    fn u32(&mut self) -> Result<u32, RmiDecodeError> {
        Ok(read_u32(self.take(4)?))
    }

    fn u64(&mut self) -> Result<u64, RmiDecodeError> {
        Ok(read_u64(self.take(8)?))
    }

    fn i64(&mut self) -> Result<i64, RmiDecodeError> {
        Ok(i64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| RmiDecodeError::LengthOverflow)?,
        ))
    }

    fn bool(&mut self) -> Result<bool, RmiDecodeError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(RmiDecodeError::InvalidBoolean(other)),
        }
    }

    fn count(&mut self, field: &'static str, maximum: usize) -> Result<usize, RmiDecodeError> {
        let count = self.u32()? as usize;
        if count > maximum {
            return Err(RmiDecodeError::CountTooLarge {
                field,
                actual: count,
                maximum,
            });
        }
        Ok(count)
    }

    fn string(&mut self, field: &'static str, maximum: usize) -> Result<String, RmiDecodeError> {
        let length = self.u32()? as usize;
        if length > maximum {
            return Err(RmiDecodeError::FieldTooLong {
                field,
                actual: length,
                maximum,
            });
        }
        let value = self.take(length)?;
        String::from_utf8(value.to_vec()).map_err(|_| RmiDecodeError::MalformedUtf8 { field })
    }

    fn optional_string(
        &mut self,
        field: &'static str,
        maximum: usize,
    ) -> Result<Option<String>, RmiDecodeError> {
        match self.u8()? {
            0 => Ok(None),
            1 => self.string(field, maximum).map(Some),
            other => Err(RmiDecodeError::InvalidOptionMarker(other)),
        }
    }

    fn data(&mut self, maximum: usize) -> Result<Vec<u8>, RmiDecodeError> {
        let length = self.u32()? as usize;
        if length > maximum {
            return Err(RmiDecodeError::FieldTooLong {
                field: "bytes",
                actual: length,
                maximum,
            });
        }
        Ok(self.take(length)?.to_vec())
    }

    fn optional_data(&mut self, maximum: usize) -> Result<Option<Vec<u8>>, RmiDecodeError> {
        match self.u8()? {
            0 => Ok(None),
            1 => self.data(maximum).map(Some),
            other => Err(RmiDecodeError::InvalidOptionMarker(other)),
        }
    }

    fn optional_u64(&mut self) -> Result<Option<u64>, RmiDecodeError> {
        match self.u8()? {
            0 => Ok(None),
            1 => self.u64().map(Some),
            other => Err(RmiDecodeError::InvalidOptionMarker(other)),
        }
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], RmiDecodeError> {
        self.take(N)?
            .try_into()
            .map_err(|_| RmiDecodeError::LengthOverflow)
    }
}

fn read_u16(value: &[u8]) -> u16 {
    u16::from_be_bytes([value[0], value[1]])
}

fn read_u32(value: &[u8]) -> u32 {
    u32::from_be_bytes([value[0], value[1], value[2], value[3]])
}

fn read_u64(value: &[u8]) -> u64 {
    u64::from_be_bytes([
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ])
}

/// Encoding failures for a bounded stream message.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum RmiEncodeError {
    /// Invalid negotiated limits.
    Limits(RmiLimitError),
    /// Invalid message/event state.
    Validation(RmiValidationError),
    /// Invalid sample-result projection.
    Sample(SampleValidationError),
    /// Encoded message exceeds the selected frame bound.
    FrameTooLarge { actual: usize, maximum: usize },
    /// A length/count arithmetic operation overflowed.
    LengthOverflow,
    /// A count exceeds a bound.
    CountTooLarge { actual: usize, maximum: usize },
    /// A field exceeds a bound.
    FieldTooLong {
        /// Field category.
        field: &'static str,
        /// Actual bytes.
        actual: usize,
        /// Maximum bytes.
        maximum: usize,
    },
}

impl fmt::Display for RmiEncodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Limits(error) => error.fmt(formatter),
            Self::Validation(error) => error.fmt(formatter),
            Self::Sample(error) => error.fmt(formatter),
            Self::FrameTooLarge { actual, maximum } => {
                write!(formatter, "RMI frame {actual} exceeds {maximum}")
            }
            Self::LengthOverflow => formatter.write_str("RMI length overflow"),
            Self::CountTooLarge { actual, maximum } => {
                write!(formatter, "RMI count {actual} exceeds {maximum}")
            }
            Self::FieldTooLong {
                field,
                actual,
                maximum,
            } => {
                write!(formatter, "RMI {field} length {actual} exceeds {maximum}")
            }
        }
    }
}

impl std::error::Error for RmiEncodeError {}

/// Decode failures.  A [`RmiDecodeError::Truncated`] result is converted to
/// [`RmiDecodeResult::Incomplete`] by [`RmiCodec::decode`].
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum RmiDecodeError {
    /// Invalid negotiated limits.
    Limits(RmiLimitError),
    /// Unsupported schema tuple.
    Schema(SchemaError),
    /// Invalid complete message/event state.
    Validation(RmiValidationError),
    /// Input is incomplete; the number is the minimum additional bytes.
    Truncated { needed: usize },
    /// Stream magic did not match.
    InvalidMagic { found: [u8; 4] },
    /// Stream wire version is unsupported.
    UnsupportedWireVersion(u8),
    /// Event tag is not in the closed schema.
    UnknownEventKind(u8),
    /// Enum value is not in its closed domain.
    InvalidEnum { field: &'static str, value: u64 },
    /// Unknown reserved flags were set.
    UnknownFlags(u8),
    /// Unknown sample-result presence bits were set.
    UnknownSampleFields(u64),
    /// Boolean byte was neither zero nor one.
    InvalidBoolean(u8),
    /// Optional-field marker was neither zero nor one.
    InvalidOptionMarker(u8),
    /// A length/count exceeds a negotiated bound.
    CountTooLarge {
        /// Count category.
        field: &'static str,
        /// Actual count.
        actual: usize,
        /// Maximum count.
        maximum: usize,
    },
    /// A field exceeds a negotiated bound.
    FieldTooLong {
        /// Field category.
        field: &'static str,
        /// Actual bytes.
        actual: usize,
        /// Maximum bytes.
        maximum: usize,
    },
    /// Text field was not UTF-8.
    MalformedUtf8 { field: &'static str },
    /// Hierarchy depth exceeds the negotiated bound.
    Depth { actual: usize, maximum: usize },
    /// A batch contained a non-sample event kind.
    InvalidBatchEvent(EventKind),
    /// Encoded message exceeds the selected frame bound.
    FrameTooLarge { declared: usize, maximum: usize },
    /// Exact decode received trailing bytes.
    TrailingBytes { count: usize },
    /// Length arithmetic overflowed.
    LengthOverflow,
}

impl fmt::Display for RmiDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Limits(error) => error.fmt(formatter),
            Self::Schema(error) => error.fmt(formatter),
            Self::Validation(error) => error.fmt(formatter),
            Self::Truncated { needed } => {
                write!(formatter, "RMI message needs {needed} more bytes")
            }
            Self::InvalidMagic { .. } => formatter.write_str("invalid RMI stream magic"),
            Self::UnsupportedWireVersion(value) => {
                write!(formatter, "unsupported RMI wire version {value}")
            }
            Self::UnknownEventKind(value) => write!(formatter, "unknown RMI event kind {value}"),
            Self::InvalidEnum { field, value } => {
                write!(formatter, "invalid {field} value {value}")
            }
            Self::UnknownFlags(value) => write!(formatter, "unknown RMI flags 0x{value:02x}"),
            Self::UnknownSampleFields(value) => {
                write!(formatter, "unknown RMI sample fields 0x{value:016x}")
            }
            Self::InvalidBoolean(value) => write!(formatter, "invalid RMI boolean {value}"),
            Self::InvalidOptionMarker(value) => {
                write!(formatter, "invalid RMI optional marker {value}")
            }
            Self::CountTooLarge {
                field,
                actual,
                maximum,
            } => {
                write!(formatter, "RMI {field} count {actual} exceeds {maximum}")
            }
            Self::FieldTooLong {
                field,
                actual,
                maximum,
            } => {
                write!(formatter, "RMI {field} length {actual} exceeds {maximum}")
            }
            Self::MalformedUtf8 { field } => write!(formatter, "RMI {field} is not UTF-8"),
            Self::Depth { actual, maximum } => {
                write!(formatter, "RMI depth {actual} exceeds {maximum}")
            }
            Self::InvalidBatchEvent(kind) => {
                write!(formatter, "invalid {kind:?} event in RMI batch")
            }
            Self::FrameTooLarge { declared, maximum } => {
                write!(formatter, "RMI frame {declared} exceeds {maximum}")
            }
            Self::TrailingBytes { count } => write!(formatter, "RMI has {count} trailing bytes"),
            Self::LengthOverflow => formatter.write_str("RMI length overflow"),
        }
    }
}

impl std::error::Error for RmiDecodeError {}

/// Stream lifecycle phase.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum StreamPhase {
    /// No Ready message has been accepted.
    New,
    /// Ready was accepted.
    Ready,
    /// TestStarted was accepted and callbacks may arrive.
    Running,
    /// TestEnded was accepted; the sender-specific drain boundary is next.
    TestEndedObserved,
    /// Late callbacks and acknowledgements are admitted only under the
    /// negotiated sender drain rule.
    DrainingAfterTestEnded,
    /// A sender-specific completion proof has drained the stream.
    Drained,
    /// A worker/run failure ended normal admission.
    Failed,
    /// The controller explicitly aborted admission.
    Aborted,
    /// Cancellation ended admission.
    Cancelled,
    /// The authoritative deadline ended admission.
    TimedOut,
    /// The worker disappeared before semantic completion.
    Crashed,
    /// A frame, identity, or lifecycle rule was violated.
    ProtocolError,
    /// Exactly one terminal message was accepted.
    Terminal,
}

const SAMPLE_PHASE_STARTED: u8 = 1 << 0;
const SAMPLE_PHASE_OCCURRED: u8 = 1 << 1;
const SAMPLE_PHASE_STOPPED: u8 = 1 << 2;

/// Result of accepting a stream message.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum StreamAcceptance {
    /// Message was accepted and stream remains open.
    Accepted,
    /// Terminal was accepted exactly once.
    TerminalAccepted,
}

/// Deterministic stream lifecycle/order validator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamState {
    run_id: String,
    worker_id: String,
    generation: u64,
    next_sequence: u64,
    next_callback_invocation_ordinal: u64,
    next_delivered_event_ordinal: u64,
    last_acknowledged_sequence: u64,
    cancellation: Cancellation,
    accounting: StreamAccounting,
    phase: StreamPhase,
    failure_phase: Option<FailurePhase>,
    sender: Option<SenderMode>,
    sender_proof_capability_negotiated: bool,
    last_queue: Option<QueueCredit>,
    test_ended_callback_ordinal: Option<u64>,
    samples: std::collections::BTreeMap<u64, u8>,
    seen_requests: BTreeSet<u64>,
    limits: RmiLimits,
}

impl StreamState {
    /// Creates a new stream state expecting `Ready` at sequence one.
    pub fn new(
        run_id: impl Into<String>,
        worker_id: impl Into<String>,
        generation: u64,
        limits: RmiLimits,
    ) -> Result<Self, RmiValidationError> {
        limits.validate().map_err(RmiValidationError::Limits)?;
        let run_id = run_id.into();
        let worker_id = worker_id.into();
        validate_text(&run_id, limits.max_string_bytes, "run id")
            .map_err(RmiValidationError::Identity)?;
        validate_text(&worker_id, limits.max_string_bytes, "worker id")
            .map_err(RmiValidationError::Identity)?;
        if generation == 0 {
            return Err(RmiValidationError::ZeroIdentity("generation"));
        }
        Ok(Self {
            run_id,
            worker_id,
            generation,
            next_sequence: 1,
            next_callback_invocation_ordinal: 1,
            next_delivered_event_ordinal: 1,
            last_acknowledged_sequence: 0,
            cancellation: Cancellation::None,
            accounting: StreamAccounting::default(),
            phase: StreamPhase::New,
            failure_phase: None,
            sender: None,
            sender_proof_capability_negotiated: false,
            last_queue: None,
            test_ended_callback_ordinal: None,
            samples: std::collections::BTreeMap::new(),
            seen_requests: BTreeSet::new(),
            limits,
        })
    }

    /// Accepts and validates one message, enforcing lifecycle and order.
    pub fn accept(
        &mut self,
        message: &StreamMessage,
    ) -> Result<StreamAcceptance, StreamStateError> {
        if self.phase == StreamPhase::Terminal {
            return Err(StreamStateError::Lifecycle("frame after terminal"));
        }
        message
            .validate(self.limits)
            .map_err(StreamStateError::Message)?;
        if message.run_id != self.run_id
            || message.worker_id != self.worker_id
            || message.generation != self.generation
        {
            return Err(StreamStateError::IdentityMismatch);
        }
        if message.sequence != self.next_sequence {
            return Err(if message.sequence < self.next_sequence {
                StreamStateError::DuplicateOrReplay {
                    sequence: message.sequence,
                }
            } else {
                StreamStateError::OutOfOrder {
                    expected: self.next_sequence,
                    actual: message.sequence,
                }
            });
        }
        if self.seen_requests.contains(&message.request_id) {
            return Err(StreamStateError::DuplicateRequestId {
                request_id: message.request_id,
            });
        }
        if cancellation_rank(message.cancellation) < cancellation_rank(self.cancellation) {
            return Err(StreamStateError::CancellationRegression {
                previous: self.cancellation,
                actual: message.cancellation,
            });
        }
        let request_count = match &message.event {
            StreamEvent::Batch(batch) => batch.items.len().saturating_add(1),
            _ => 1,
        };
        if self.seen_requests.len().saturating_add(request_count) > self.limits.max_event_count {
            return Err(StreamStateError::RequestLimit {
                maximum: self.limits.max_event_count,
            });
        }
        if let StreamEvent::Batch(batch) = &message.event {
            if batch
                .items
                .iter()
                .any(|item| self.seen_requests.contains(&item.request_id))
            {
                let request_id = batch
                    .items
                    .iter()
                    .find(|item| self.seen_requests.contains(&item.request_id))
                    .map_or(0, |item| item.request_id);
                return Err(StreamStateError::DuplicateRequestId { request_id });
            }
            if batch
                .items
                .iter()
                .any(|item| item.request_id == message.request_id)
            {
                return Err(StreamStateError::DuplicateRequestId {
                    request_id: message.request_id,
                });
            }
        }
        let sequence_advance = match &message.event {
            StreamEvent::Batch(batch) => {
                u64::try_from(batch.items.len()).map_err(|_| StreamStateError::SequenceExhausted)?
            }
            _ => 1,
        };
        if let StreamEvent::Ack(value) = &message.event
            && value.acknowledged_sequence >= message.sequence
        {
            return Err(StreamStateError::AckOrder {
                acknowledged: value.acknowledged_sequence,
                current: message.sequence,
            });
        }
        if let StreamEvent::Ack(value) = &message.event {
            if value.acknowledged_events < self.accounting.acknowledged_events {
                return Err(StreamStateError::AckEventRegression {
                    previous: self.accounting.acknowledged_events,
                    actual: value.acknowledged_events,
                });
            }
            if value.acknowledged_bytes < self.accounting.acknowledged_bytes {
                return Err(StreamStateError::AckByteRegression {
                    previous: self.accounting.acknowledged_bytes,
                    actual: value.acknowledged_bytes,
                });
            }
            if value.acknowledged_events > self.accounting.accepted_events
                || value.acknowledged_bytes > self.accounting.accepted_bytes
            {
                return Err(StreamStateError::AckExceedsAccepted);
            }
        }
        let next_sequence = self
            .next_sequence
            .checked_add(sequence_advance)
            .ok_or(StreamStateError::SequenceExhausted)?;
        let previous = self.clone();
        if let StreamEvent::Ack(value) = &message.event
            && value.acknowledged_sequence < self.last_acknowledged_sequence
        {
            return Err(StreamStateError::AckRegression {
                previous: self.last_acknowledged_sequence,
                actual: value.acknowledged_sequence,
            });
        }
        if let StreamEvent::TestEnded(value) = &message.event {
            if value.accounting.accepted_events != self.accounting.accepted_events {
                return Err(StreamStateError::AcceptedEventCount {
                    expected: self.accounting.accepted_events,
                    actual: value.accounting.accepted_events,
                });
            }
            if value.accounting.accepted_bytes != self.accounting.accepted_bytes {
                return Err(StreamStateError::AcceptedByteCount {
                    expected: self.accounting.accepted_bytes,
                    actual: value.accounting.accepted_bytes,
                });
            }
        }
        let encoded_bytes = RmiCodec::with_limits(self.limits)
            .encode(message)
            .map_err(|_| StreamStateError::MessageEncoding)?;
        let encoded_bytes =
            u64::try_from(encoded_bytes.len()).map_err(|_| StreamStateError::SequenceExhausted)?;
        if message.cancellation == Cancellation::Cancelled
            && matches!(&message.event, StreamEvent::Terminal(_))
        {
            self.phase = StreamPhase::Cancelled;
        }
        let acceptance = match self.accept_event(&message.event) {
            Ok(acceptance) => acceptance,
            Err(error) => {
                *self = previous;
                return Err(error);
            }
        };
        if cancellation_rank(message.cancellation) > cancellation_rank(self.cancellation) {
            self.cancellation = message.cancellation;
        }
        if message.cancellation == Cancellation::Cancelled
            && acceptance != StreamAcceptance::TerminalAccepted
        {
            self.phase = StreamPhase::Cancelled;
        }
        self.next_sequence = next_sequence;
        let accepted_increment = match &message.event {
            StreamEvent::Batch(batch) => {
                u64::try_from(batch.items.len()).map_err(|_| StreamStateError::SequenceExhausted)?
            }
            StreamEvent::Ready(_)
            | StreamEvent::WorkerFailure(_)
            | StreamEvent::Credit(_)
            | StreamEvent::Ack(_)
            | StreamEvent::TestEnded(_)
            | StreamEvent::Terminal(_) => 0,
            _ => 1,
        };
        let delivered_events = self
            .accounting
            .delivered_events
            .checked_add(accepted_increment)
            .ok_or(StreamStateError::SequenceExhausted)?;
        let delivered_bytes = if accepted_increment == 0 {
            self.accounting.delivered_bytes
        } else {
            self.accounting
                .delivered_bytes
                .checked_add(encoded_bytes)
                .ok_or(StreamStateError::SequenceExhausted)?
        };
        let max_stream_events = u64::try_from(self.limits.max_stream_events).unwrap_or(u64::MAX);
        if delivered_events > max_stream_events {
            *self = previous;
            return Err(StreamStateError::StreamEventLimit {
                maximum: self.limits.max_stream_events,
            });
        }
        if delivered_bytes > self.limits.max_stream_bytes {
            *self = previous;
            return Err(StreamStateError::StreamByteLimit {
                maximum: self.limits.max_stream_bytes,
            });
        }
        self.accounting.delivered_events = delivered_events;
        self.accounting.accepted_events = delivered_events;
        self.accounting.delivered_bytes = delivered_bytes;
        self.accounting.accepted_bytes = delivered_bytes;
        self.seen_requests.insert(message.request_id);
        if let StreamEvent::Batch(batch) = &message.event {
            self.seen_requests
                .extend(batch.items.iter().map(|item| item.request_id));
        }
        if let StreamEvent::Ack(value) = &message.event {
            self.last_acknowledged_sequence = value.acknowledged_sequence;
            self.accounting.acknowledged_events = value.acknowledged_events;
            self.accounting.acknowledged_bytes = value.acknowledged_bytes;
        }
        if acceptance == StreamAcceptance::TerminalAccepted {
            self.phase = StreamPhase::Terminal;
        }
        if let Some(queue) = event_queue(&message.event) {
            self.last_queue = Some(queue);
        }
        Ok(acceptance)
    }

    fn accept_event(&mut self, event: &StreamEvent) -> Result<StreamAcceptance, StreamStateError> {
        match event {
            StreamEvent::Ready(value) if self.phase == StreamPhase::New => {
                if value.identity.role == RmiRole::Worker
                    && value.identity.worker_id != self.worker_id
                {
                    return Err(StreamStateError::IdentityMismatch);
                }
                self.sender = Some(value.sender);
                self.sender_proof_capability_negotiated = value
                    .sender
                    .drain_proof_capability()
                    .is_some_and(|capability| {
                        value
                            .identity
                            .capabilities
                            .iter()
                            .any(|entry| entry.id == capability)
                    });
                self.phase = StreamPhase::Ready;
            }
            StreamEvent::Ready(_) => return Err(StreamStateError::Lifecycle("duplicate Ready")),
            StreamEvent::TestStarted(value) if self.phase == StreamPhase::Ready => {
                if value.callback_invocation_ordinal != self.next_callback_invocation_ordinal {
                    return Err(StreamStateError::CallbackOrdinal {
                        expected: self.next_callback_invocation_ordinal,
                        actual: value.callback_invocation_ordinal,
                    });
                }
                self.next_callback_invocation_ordinal = self
                    .next_callback_invocation_ordinal
                    .checked_add(1)
                    .ok_or(StreamStateError::SequenceExhausted)?;
                self.phase = StreamPhase::Running;
            }
            StreamEvent::TestStarted(_) => {
                return Err(StreamStateError::Lifecycle("TestStarted out of order"));
            }
            StreamEvent::SampleStarted(value) => {
                if self.phase != StreamPhase::Running {
                    if self.phase == StreamPhase::TestEndedObserved
                        && self
                            .sender
                            .is_some_and(SenderMode::allows_late_drain_callback)
                    {
                        self.phase = StreamPhase::DrainingAfterTestEnded;
                    } else if self.phase != StreamPhase::DrainingAfterTestEnded {
                        return Err(StreamStateError::Lifecycle("SampleStarted out of order"));
                    }
                }
                if !matches!(
                    self.phase,
                    StreamPhase::Running | StreamPhase::DrainingAfterTestEnded
                ) {
                    return Err(StreamStateError::Lifecycle("SampleStarted out of order"));
                }
                self.check_sample_ordinals(
                    value.callback_invocation_ordinal,
                    value.delivered_event_ordinal,
                )?;
                self.advance_sample_ordinals(1)?;
                self.accept_sample_phase(value.sample_id, SAMPLE_PHASE_STARTED)?;
            }
            StreamEvent::SampleOccurred(value) => {
                if self.phase != StreamPhase::Running {
                    if self.phase == StreamPhase::TestEndedObserved
                        && self
                            .sender
                            .is_some_and(SenderMode::allows_late_drain_callback)
                    {
                        self.phase = StreamPhase::DrainingAfterTestEnded;
                    } else if self.phase != StreamPhase::DrainingAfterTestEnded {
                        return Err(StreamStateError::Lifecycle("SampleOccurred out of order"));
                    }
                }
                if !matches!(
                    self.phase,
                    StreamPhase::Running | StreamPhase::DrainingAfterTestEnded
                ) {
                    return Err(StreamStateError::Lifecycle("SampleOccurred out of order"));
                }
                self.check_sample_ordinals(
                    value.callback_invocation_ordinal,
                    value.delivered_event_ordinal,
                )?;
                self.advance_sample_ordinals(1)?;
                self.accept_sample_phase(value.sample_id, SAMPLE_PHASE_OCCURRED)?;
            }
            StreamEvent::SampleStopped(value) => {
                if self.phase != StreamPhase::Running {
                    if self.phase == StreamPhase::TestEndedObserved
                        && self
                            .sender
                            .is_some_and(SenderMode::allows_late_drain_callback)
                    {
                        self.phase = StreamPhase::DrainingAfterTestEnded;
                    } else if self.phase != StreamPhase::DrainingAfterTestEnded {
                        return Err(StreamStateError::Lifecycle("SampleStopped out of order"));
                    }
                }
                if !matches!(
                    self.phase,
                    StreamPhase::Running | StreamPhase::DrainingAfterTestEnded
                ) {
                    return Err(StreamStateError::Lifecycle("SampleStopped out of order"));
                }
                self.check_sample_ordinals(
                    value.callback_invocation_ordinal,
                    value.delivered_event_ordinal,
                )?;
                self.advance_sample_ordinals(1)?;
                self.accept_sample_phase(value.sample_id, SAMPLE_PHASE_STOPPED)?;
            }
            StreamEvent::Batch(value) => {
                if self.phase != StreamPhase::Running {
                    if self.phase == StreamPhase::TestEndedObserved
                        && self
                            .sender
                            .is_some_and(SenderMode::allows_late_drain_callback)
                    {
                        self.phase = StreamPhase::DrainingAfterTestEnded;
                    } else if self.phase != StreamPhase::DrainingAfterTestEnded {
                        return Err(StreamStateError::Lifecycle("Batch out of order"));
                    }
                }
                if !matches!(
                    self.phase,
                    StreamPhase::Running | StreamPhase::DrainingAfterTestEnded
                ) {
                    return Err(StreamStateError::Lifecycle("Batch out of order"));
                }
                if Some(value.sender) != self.sender {
                    return Err(StreamStateError::SenderMismatch);
                }
                if value.callback_invocation_ordinal != self.next_callback_invocation_ordinal {
                    return Err(StreamStateError::CallbackOrdinal {
                        expected: self.next_callback_invocation_ordinal,
                        actual: value.callback_invocation_ordinal,
                    });
                }
                if value.first_delivered_event_ordinal != self.next_delivered_event_ordinal {
                    return Err(StreamStateError::DeliveredOrdinal {
                        expected: self.next_delivered_event_ordinal,
                        actual: value.first_delivered_event_ordinal,
                    });
                }
                for item in &value.items {
                    self.accept_sample_event(&item.event)?;
                }
                self.next_callback_invocation_ordinal = self
                    .next_callback_invocation_ordinal
                    .checked_add(1)
                    .ok_or(StreamStateError::SequenceExhausted)?;
                self.next_delivered_event_ordinal = self
                    .next_delivered_event_ordinal
                    .checked_add(value.event_count)
                    .ok_or(StreamStateError::SequenceExhausted)?;
            }
            StreamEvent::WorkerFailure(value)
                if matches!(
                    self.phase,
                    StreamPhase::Ready
                        | StreamPhase::Running
                        | StreamPhase::TestEndedObserved
                        | StreamPhase::DrainingAfterTestEnded
                ) =>
            {
                if value.worker_id != self.worker_id {
                    return Err(StreamStateError::IdentityMismatch);
                }
                if value.retry.is_pre_start_safe() && self.phase != StreamPhase::Ready {
                    return Err(StreamStateError::RetryAfterStart);
                }
                self.failure_phase = Some(value.phase);
                self.phase = match value.phase {
                    FailurePhase::Failed => StreamPhase::Failed,
                    FailurePhase::Aborted => StreamPhase::Aborted,
                    FailurePhase::Cancelled => StreamPhase::Cancelled,
                    FailurePhase::TimedOut => StreamPhase::TimedOut,
                    FailurePhase::Crashed => StreamPhase::Crashed,
                    FailurePhase::ProtocolError => StreamPhase::ProtocolError,
                };
            }
            StreamEvent::WorkerFailure(_) => {
                return Err(StreamStateError::Lifecycle("WorkerFailure out of order"));
            }
            StreamEvent::TestEnded(value)
                if matches!(
                    self.phase,
                    StreamPhase::Running
                        | StreamPhase::TestEndedObserved
                        | StreamPhase::DrainingAfterTestEnded
                        | StreamPhase::Failed
                        | StreamPhase::Aborted
                        | StreamPhase::Cancelled
                        | StreamPhase::TimedOut
                        | StreamPhase::Crashed
                ) =>
            {
                if value.callback_invocation_ordinal != self.next_callback_invocation_ordinal {
                    return Err(StreamStateError::CallbackOrdinal {
                        expected: self.next_callback_invocation_ordinal,
                        actual: value.callback_invocation_ordinal,
                    });
                }
                self.next_callback_invocation_ordinal = self
                    .next_callback_invocation_ordinal
                    .checked_add(1)
                    .ok_or(StreamStateError::SequenceExhausted)?;
                self.test_ended_callback_ordinal = Some(value.callback_invocation_ordinal);
                self.phase = StreamPhase::TestEndedObserved;
            }
            StreamEvent::TestEnded(_) => {
                return Err(StreamStateError::Lifecycle("TestEnded out of order"));
            }
            StreamEvent::Credit(_) | StreamEvent::Ack(_)
                if matches!(
                    self.phase,
                    StreamPhase::Ready
                        | StreamPhase::Running
                        | StreamPhase::TestEndedObserved
                        | StreamPhase::DrainingAfterTestEnded
                        | StreamPhase::Drained
                        | StreamPhase::Failed
                        | StreamPhase::Aborted
                        | StreamPhase::Cancelled
                        | StreamPhase::TimedOut
                        | StreamPhase::Crashed
                        | StreamPhase::ProtocolError
                ) => {}
            StreamEvent::Credit(_) | StreamEvent::Ack(_) => {
                return Err(StreamStateError::Lifecycle("control out of order"));
            }
            StreamEvent::Terminal(value) => {
                return self.accept_terminal(value);
            }
        }
        Ok(StreamAcceptance::Accepted)
    }

    fn check_sample_ordinals(
        &self,
        callback_invocation_ordinal: u64,
        delivered_event_ordinal: u64,
    ) -> Result<(), StreamStateError> {
        if callback_invocation_ordinal != self.next_callback_invocation_ordinal {
            return Err(StreamStateError::CallbackOrdinal {
                expected: self.next_callback_invocation_ordinal,
                actual: callback_invocation_ordinal,
            });
        }
        if delivered_event_ordinal != self.next_delivered_event_ordinal {
            return Err(StreamStateError::DeliveredOrdinal {
                expected: self.next_delivered_event_ordinal,
                actual: delivered_event_ordinal,
            });
        }
        Ok(())
    }

    fn advance_sample_ordinals(&mut self, count: u64) -> Result<(), StreamStateError> {
        self.next_callback_invocation_ordinal = self
            .next_callback_invocation_ordinal
            .checked_add(1)
            .ok_or(StreamStateError::SequenceExhausted)?;
        self.next_delivered_event_ordinal = self
            .next_delivered_event_ordinal
            .checked_add(count)
            .ok_or(StreamStateError::SequenceExhausted)?;
        Ok(())
    }

    fn accept_terminal(&self, value: &Terminal) -> Result<StreamAcceptance, StreamStateError> {
        let expected_status = match self.phase {
            StreamPhase::TestEndedObserved
            | StreamPhase::DrainingAfterTestEnded
            | StreamPhase::Drained => self.failure_phase.map(failure_terminal_status),
            StreamPhase::Failed => Some(TerminalStatus::Failed),
            StreamPhase::Aborted => Some(TerminalStatus::Aborted),
            StreamPhase::Cancelled => Some(TerminalStatus::Cancelled),
            StreamPhase::TimedOut => Some(TerminalStatus::TimedOut),
            StreamPhase::Crashed => Some(TerminalStatus::Crashed),
            StreamPhase::ProtocolError => Some(TerminalStatus::ProtocolError),
            StreamPhase::Ready | StreamPhase::Running => {
                if value.status == TerminalStatus::Succeeded
                    || value.test_ended_absence_reason.is_none()
                {
                    return Err(StreamStateError::TestEndedAbsence);
                }
                None
            }
            StreamPhase::New | StreamPhase::Terminal => {
                return Err(StreamStateError::Lifecycle("Terminal out of order"));
            }
        };
        if let Some(expected) = expected_status
            && value.status != expected
        {
            return Err(StreamStateError::TerminalStatus {
                expected,
                actual: value.status,
            });
        }
        if value.accounting != self.accounting {
            return Err(StreamStateError::CompletionAccounting);
        }
        if let Some(previous_queue) = self.last_queue
            && value.queue != previous_queue
        {
            return Err(StreamStateError::QueueAgreement);
        }
        if self
            .sender
            .is_some_and(|sender| value.sender_proof.sender() != sender)
        {
            return Err(StreamStateError::SenderMismatch);
        }
        if let Some(failure) = &value.failure
            && failure.worker_id != self.worker_id
        {
            return Err(StreamStateError::IdentityMismatch);
        }
        if value.status == TerminalStatus::Succeeded {
            let sender = self.sender.unwrap_or(SenderMode::Standard);
            if value.failure.is_some()
                || value.test_ended_callback_ordinal != self.test_ended_callback_ordinal
                || value.sender_proof.sender() != sender
                || !value.sender_proof.is_proven()
                || value.router_finalization_digest.is_none()
                || !value.accounting.is_fully_acked()
                || value.queue.available != value.queue.capacity
                || value.queue.bytes_available != value.queue.bytes_capacity
                || !self.sender_proof_capability_negotiated
            {
                return Err(StreamStateError::SenderProofRequired);
            }
            if let SenderDrainProof::Proven(evidence) = &value.sender_proof
                && (evidence.generation != self.generation
                    || evidence.sender != sender
                    || sender.drain_proof_capability() != Some(evidence.completion_hook.as_str())
                    || evidence.final_delivered_event_ordinal
                        != self.next_delivered_event_ordinal.saturating_sub(1)
                    || evidence.emitted_events != value.accounting.delivered_events
                    || evidence.accepted_events != value.accounting.accepted_events
                    || evidence.acknowledged_events != value.accounting.acknowledged_events
                    || evidence.emitted_bytes != value.accounting.delivered_bytes
                    || evidence.accepted_bytes != value.accounting.accepted_bytes
                    || evidence.acknowledged_bytes != value.accounting.acknowledged_bytes
                    || evidence.pending_sender_events != 0
                    || evidence.pending_disk_events != 0)
            {
                return Err(StreamStateError::CompletionAccounting);
            }
        } else if value.test_ended_callback_ordinal.is_none()
            && value.test_ended_absence_reason.is_none()
        {
            return Err(StreamStateError::TestEndedAbsence);
        }
        Ok(StreamAcceptance::TerminalAccepted)
    }

    fn accept_sample_event(&mut self, event: &SampleEvent) -> Result<(), StreamStateError> {
        match event {
            SampleEvent::Started(value) => {
                self.accept_sample_phase(value.sample_id, SAMPLE_PHASE_STARTED)?;
            }
            SampleEvent::Occurred(value) => {
                self.accept_sample_phase(value.sample_id, SAMPLE_PHASE_OCCURRED)?;
            }
            SampleEvent::Stopped(value) => {
                self.accept_sample_phase(value.sample_id, SAMPLE_PHASE_STOPPED)?;
            }
        }
        Ok(())
    }

    fn accept_sample_phase(&mut self, sample_id: u64, phase: u8) -> Result<(), StreamStateError> {
        if !self.samples.contains_key(&sample_id)
            && self.samples.len() >= self.limits.max_event_count
        {
            return Err(StreamStateError::SampleLimit {
                maximum: self.limits.max_event_count,
            });
        }
        match self.samples.entry(sample_id) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(phase);
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                let phases = entry.get_mut();
                if *phases & phase != 0 {
                    return Err(StreamStateError::SamplePhase {
                        sample_id,
                        expected: "phase not already delivered",
                    });
                }
                *phases |= phase;
            }
        }
        Ok(())
    }

    /// Returns the next required stream sequence.
    pub const fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    /// Returns the next callback invocation ordinal.
    pub const fn next_callback_invocation_ordinal(&self) -> u64 {
        self.next_callback_invocation_ordinal
    }

    /// Returns the next delivered-event ordinal.
    pub const fn next_delivered_event_ordinal(&self) -> u64 {
        self.next_delivered_event_ordinal
    }

    /// Returns the accounting observed by the state validator.
    pub const fn accounting(&self) -> StreamAccounting {
        self.accounting
    }

    /// Returns the current lifecycle phase.
    pub const fn phase(&self) -> StreamPhase {
        self.phase
    }

    /// Returns the strongest cancellation state observed so far.
    pub const fn cancellation(&self) -> Cancellation {
        self.cancellation
    }

    /// Returns whether the terminal event was accepted.
    pub const fn is_terminal(&self) -> bool {
        matches!(self.phase, StreamPhase::Terminal)
    }
}

fn failure_terminal_status(phase: FailurePhase) -> TerminalStatus {
    match phase {
        FailurePhase::Failed => TerminalStatus::Failed,
        FailurePhase::Aborted => TerminalStatus::Aborted,
        FailurePhase::Cancelled => TerminalStatus::Cancelled,
        FailurePhase::TimedOut => TerminalStatus::TimedOut,
        FailurePhase::Crashed => TerminalStatus::Crashed,
        FailurePhase::ProtocolError => TerminalStatus::ProtocolError,
    }
}

const fn cancellation_rank(value: Cancellation) -> u8 {
    match value {
        Cancellation::None => 0,
        Cancellation::Requested => 1,
        Cancellation::Cancelled => 2,
    }
}

/// Lifecycle/order failures for a stream.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum StreamStateError {
    /// Message did not validate against stream bounds/schema.
    Message(RmiValidationError),
    /// A valid message could not be canonically encoded for byte accounting.
    MessageEncoding,
    /// Run/worker/generation did not match the stream owner.
    IdentityMismatch,
    /// Sequence was repeated.
    DuplicateOrReplay { sequence: u64 },
    /// Sequence skipped ahead.
    OutOfOrder { expected: u64, actual: u64 },
    /// Sequence cannot advance further.
    SequenceExhausted,
    /// A control request identity was repeated.
    DuplicateRequestId { request_id: u64 },
    /// The bounded request identity table is full.
    RequestLimit { maximum: usize },
    /// The stream callback event total exceeded its negotiated bound.
    StreamEventLimit { maximum: usize },
    /// The stream callback byte total exceeded its negotiated bound.
    StreamByteLimit { maximum: u64 },
    /// Lifecycle event was not allowed in the current phase.
    Lifecycle(&'static str),
    /// Sample ID/phase identity was repeated.
    DuplicateSample { sample_id: u64 },
    /// Sample ID was not started.
    UnknownSample { sample_id: u64 },
    /// A sample phase was repeated for the same sample identity.
    SamplePhase {
        sample_id: u64,
        expected: &'static str,
    },
    /// The stream's bounded sample-state table is full.
    SampleLimit { maximum: usize },
    /// An acknowledgement refers to the current or a future stream item.
    AckOrder { acknowledged: u64, current: u64 },
    /// An acknowledgement moved backwards relative to an earlier one.
    AckRegression { previous: u64, actual: u64 },
    /// An acknowledgement moved backwards in event count.
    AckEventRegression { previous: u64, actual: u64 },
    /// An acknowledgement moved backwards in byte count.
    AckByteRegression { previous: u64, actual: u64 },
    /// An acknowledgement exceeds accepted event or byte totals.
    AckExceedsAccepted,
    /// Cancellation severity moved backwards within a stream generation.
    CancellationRegression {
        previous: Cancellation,
        actual: Cancellation,
    },
    /// TestEnded did not report the number of accepted callback events.
    AcceptedEventCount { expected: u64, actual: u64 },
    /// TestEnded did not report the number of accepted callback bytes.
    AcceptedByteCount { expected: u64, actual: u64 },
    /// Callback invocation ordinal was gapped or replayed.
    CallbackOrdinal { expected: u64, actual: u64 },
    /// Delivered-event ordinal was gapped or replayed.
    DeliveredOrdinal { expected: u64, actual: u64 },
    /// A pre-start retry disposition appeared after useful work began.
    RetryAfterStart,
    /// Terminal status did not match a failed stream phase.
    TerminalStatus {
        expected: TerminalStatus,
        actual: TerminalStatus,
    },
    /// Terminal omitted an explicit TestEnded absence reason.
    TestEndedAbsence,
    /// Terminal accounting did not match accepted state.
    CompletionAccounting,
    /// Success lacked a positive sender proof or queue agreement.
    SenderProofRequired,
    /// A batch changed sender identity within one stream generation.
    SenderMismatch,
    /// Terminal queue credit disagreed with the last declared credit.
    QueueAgreement,
}

impl StreamStateError {
    /// Stable machine-readable code.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Message(_) => "stream_message_invalid",
            Self::MessageEncoding => "stream_message_encoding",
            Self::IdentityMismatch => "stream_identity_mismatch",
            Self::DuplicateOrReplay { .. } => "stream_duplicate_or_replay",
            Self::OutOfOrder { .. } => "stream_out_of_order",
            Self::SequenceExhausted => "stream_sequence_exhausted",
            Self::DuplicateRequestId { .. } => "stream_duplicate_request_id",
            Self::RequestLimit { .. } => "stream_request_limit",
            Self::StreamEventLimit { .. } => "stream_event_limit",
            Self::StreamByteLimit { .. } => "stream_byte_limit",
            Self::Lifecycle(_) => "stream_lifecycle",
            Self::DuplicateSample { .. } => "stream_duplicate_sample",
            Self::UnknownSample { .. } => "stream_unknown_sample",
            Self::SamplePhase { .. } => "stream_sample_phase",
            Self::SampleLimit { .. } => "stream_sample_limit",
            Self::AckOrder { .. } => "stream_ack_order",
            Self::AckRegression { .. } => "stream_ack_regression",
            Self::AckEventRegression { .. } => "stream_ack_event_regression",
            Self::AckByteRegression { .. } => "stream_ack_byte_regression",
            Self::AckExceedsAccepted => "stream_ack_exceeds_accepted",
            Self::CancellationRegression { .. } => "stream_cancellation_regression",
            Self::AcceptedEventCount { .. } => "stream_accepted_event_count",
            Self::AcceptedByteCount { .. } => "stream_accepted_byte_count",
            Self::CallbackOrdinal { .. } => "stream_callback_ordinal",
            Self::DeliveredOrdinal { .. } => "stream_delivered_ordinal",
            Self::RetryAfterStart => "stream_retry_after_start",
            Self::TerminalStatus { .. } => "stream_terminal_status",
            Self::TestEndedAbsence => "stream_test_ended_absence",
            Self::CompletionAccounting => "stream_completion_accounting",
            Self::SenderProofRequired => "stream_sender_proof_required",
            Self::SenderMismatch => "stream_sender_mismatch",
            Self::QueueAgreement => "stream_queue_agreement",
        }
    }
}

impl fmt::Display for StreamStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for StreamStateError {}

fn event_queue(event: &StreamEvent) -> Option<QueueCredit> {
    match event {
        StreamEvent::Ready(value) => Some(value.queue),
        StreamEvent::TestStarted(value) => Some(value.queue),
        StreamEvent::TestEnded(value) => Some(value.queue),
        StreamEvent::Terminal(value) => Some(value.queue),
        StreamEvent::Credit(value) => Some(value.queue),
        StreamEvent::SampleStarted(_)
        | StreamEvent::SampleOccurred(_)
        | StreamEvent::SampleStopped(_)
        | StreamEvent::Batch(_)
        | StreamEvent::WorkerFailure(_)
        | StreamEvent::Ack(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> BridgeIdentity {
        BridgeIdentity {
            profile: ProfileIdentity::new("jmeter-5.6.3", 2, Sha256Digest::default()),
            artifact: ArtifactIdentity {
                jmeter_archive_sha512: Sha512Digest::default(),
                jmeter_source_commit: "34a2785748e9e0b14702595e8682c387869deda3".into(),
                helper_source_sha256: Sha256Digest::default(),
                helper_build_sha256: Sha256Digest::default(),
                java_compiler: "javac-17".into(),
                java_runtime: "OpenJDK-17".into(),
                jmeter_rs_commit: "local".into(),
                platform_profile: "linux-x86_64".into(),
                target: "x86_64-unknown-linux-gnu".into(),
                os: "fixture".into(),
                dependencies: Vec::new(),
            },
            role: RmiRole::Worker,
            worker_id: "worker-a".into(),
            capabilities: vec![
                Capability::new("rmi", "1"),
                Capability::new("rmi.sender.standard.drain-proof", "1"),
            ],
            preservation: Preservation::default(),
        }
    }

    fn message(sequence: u64, event: StreamEvent) -> StreamMessage {
        StreamMessage::new(
            SchemaVersion::V1,
            "run-1",
            "worker-a",
            1,
            sequence,
            100 + sequence,
            event,
        )
    }

    fn queue() -> QueueCredit {
        QueueCredit::new(4, 4096)
    }

    fn failed_terminal(accounting: StreamAccounting, callback_ordinal: u64) -> Terminal {
        Terminal {
            status: TerminalStatus::Failed,
            failure: None,
            accounting,
            sender_proof: SenderDrainProof::Unavailable {
                sender: SenderMode::Standard,
                reason: SenderProofAbsenceReason::SenderFailed,
            },
            test_ended_callback_ordinal: Some(callback_ordinal),
            test_ended_absence_reason: None,
            router_finalization_digest: None,
            queue: queue(),
        }
    }

    // This helper keeps failure context explicit without using `unwrap`/`expect`.
    #[allow(clippy::panic)]
    fn must<T, E: fmt::Debug>(result: Result<T, E>, context: &str) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("{context}: {error:?}"),
        }
    }

    #[test]
    fn canonical_sample_started_vector_is_stable() {
        let expected = vec![
            74, 82, 77, 73, 1, 3, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 5, 114, 117, 110, 45, 49, 0, 0,
            0, 8, 119, 111, 114, 107, 101, 114, 45, 97, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
            0, 1, 0, 0, 0, 0, 0, 0, 0, 101, 1, 0, 0, 78, 148, 145, 79, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 9, 0, 1, 0, 0, 0, 3, 71,
            69, 84, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let message = message(
            1,
            StreamEvent::SampleStarted(SampleStarted {
                callback_invocation_ordinal: 1,
                delivered_event_ordinal: 1,
                delivery_kind: DeliveryKind::SampleOccurred,
                sample_id: 9,
                parent_id: None,
                label: Some("GET".into()),
                snapshot: SampleEventSnapshot::default(),
            }),
        );
        let encoded = must(RmiCodec::default().encode(&message), "vector encodes");
        assert_eq!(encoded, expected);
        assert_eq!(RmiCodec::default().decode_exact(&expected), Ok(message));
    }

    #[test]
    fn complete_sample_result_and_jtl_metadata_round_trip_losslessly() {
        let mut result = WireSampleResult {
            label: Some("sample".into()),
            success: Some(false),
            response_code: Some("500".into()),
            response_data: Some(vec![0, 0xff, 1]),
            flags: SampleFlags {
                stop_thread: true,
                logical_action: Some(LogicalAction::StopThread),
                ..SampleFlags::default()
            },
            variables: vec![
                WireVariable::absent("MISSING"),
                WireVariable::present("EMPTY", ""),
            ],
            assertions: vec![WireAssertion {
                name: "assert".into(),
                failure: true,
                error: false,
                failure_message: Some(String::new()),
                error_message: None,
            }],
            jtl: JtlMetadata {
                sample_element: Some("httpSample".into()),
                attributes: vec![JtlAttribute::new("unknown", "")],
                children: vec![JtlNode {
                    name: "opaque".into(),
                    attributes: vec![JtlAttribute::new("x", "y")],
                    text: Some(vec![0xff]),
                    children: Vec::new(),
                }],
                ..JtlMetadata::default()
            },
            ..WireSampleResult::default()
        };
        result.sub_results.push(WireSampleResult {
            label: Some("child".into()),
            elapsed: Some(4),
            ..WireSampleResult::default()
        });
        let message = message(
            1,
            StreamEvent::SampleOccurred(SampleOccurred {
                callback_invocation_ordinal: 1,
                delivered_event_ordinal: 1,
                delivery_kind: DeliveryKind::SampleOccurred,
                sample_id: 9,
                result: result.clone(),
                snapshot: SampleEventSnapshot {
                    result: Some(result),
                    ..SampleEventSnapshot::default()
                },
            }),
        );
        let codec = RmiCodec::default();
        let bytes = must(codec.encode(&message), "sample encodes");
        assert_eq!(must(codec.decode_exact(&bytes), "sample decodes"), message);
    }

    #[test]
    fn malformed_and_limit_inputs_fail_before_unbounded_allocation() {
        let codec = RmiCodec::default();
        let started_message = message(
            1,
            StreamEvent::SampleStarted(SampleStarted {
                callback_invocation_ordinal: 1,
                delivered_event_ordinal: 1,
                delivery_kind: DeliveryKind::SampleOccurred,
                sample_id: 1,
                parent_id: None,
                label: None,
                snapshot: SampleEventSnapshot::default(),
            }),
        );
        let bytes = must(codec.encode(&started_message), "message encodes");
        for length in 0..bytes.len() {
            assert!(matches!(
                codec.decode(&bytes[..length]),
                Ok(RmiDecodeResult::Incomplete { .. })
            ));
        }
        let mut unknown_kind = bytes.clone();
        unknown_kind[5] = 0xff;
        assert_eq!(
            codec.decode(&unknown_kind),
            Err(RmiDecodeError::UnknownEventKind(0xff))
        );
        let mut invalid_reserved = bytes.clone();
        invalid_reserved[13] = 1;
        assert_eq!(
            codec.decode(&invalid_reserved),
            Err(RmiDecodeError::UnknownFlags(1))
        );
        let sample = message(
            1,
            StreamEvent::SampleOccurred(SampleOccurred {
                callback_invocation_ordinal: 1,
                delivered_event_ordinal: 1,
                delivery_kind: DeliveryKind::SampleOccurred,
                sample_id: 1,
                result: WireSampleResult::default(),
                snapshot: SampleEventSnapshot::default(),
            }),
        );
        let mut unknown_sample_fields = must(codec.encode(&sample), "sample encodes");
        // Header + bounded envelope + callback metadata + sample ID points at
        // the result presence mask.  Set its high byte to an unknown field.
        unknown_sample_fields[96] = 0x80;
        assert!(matches!(
            codec.decode(&unknown_sample_fields),
            Err(RmiDecodeError::UnknownSampleFields(_))
        ));
        let frame_limited = RmiCodec::with_limits(RmiLimits {
            max_frame_bytes: RMI_HEADER_LEN,
            ..RmiLimits::default()
        });
        assert!(matches!(
            frame_limited.decode(&bytes),
            Err(RmiDecodeError::FrameTooLarge {
                declared: _,
                maximum: RMI_HEADER_LEN
            })
        ));

        let limits = RmiLimits {
            max_string_bytes: 3,
            ..RmiLimits::default()
        };
        let limited = must(RmiCodec::new(limits), "limits are valid");
        assert!(matches!(
            limited.encode(&started_message),
            Err(RmiEncodeError::Validation(RmiValidationError::Identity(
                IdentityError::TextTooLong {
                    field: "run id",
                    ..
                }
            )))
        ));
        let mut input = bytes.as_slice();
        assert!(limited.decode_next(&mut input).is_err());
        assert_eq!(input, bytes.as_slice());

        let mut duplicate_identity = identity();
        duplicate_identity
            .capabilities
            .push(Capability::new("rmi", "1"));
        assert_eq!(
            duplicate_identity.validate(RmiLimits::default()),
            Err(IdentityError::Duplicate("capability id"))
        );

        let jtl_limited = RmiLimits {
            max_sample_nodes: 1,
            ..RmiLimits::default()
        };
        let jtl_overflow = message(
            1,
            StreamEvent::SampleOccurred(SampleOccurred {
                callback_invocation_ordinal: 1,
                delivered_event_ordinal: 1,
                delivery_kind: DeliveryKind::SampleOccurred,
                sample_id: 1,
                result: WireSampleResult {
                    jtl: JtlMetadata {
                        children: vec![JtlNode::new("first"), JtlNode::new("second")],
                        ..JtlMetadata::default()
                    },
                    ..WireSampleResult::default()
                },
                snapshot: SampleEventSnapshot::default(),
            }),
        );
        assert!(matches!(
            RmiCodec::with_limits(jtl_limited).encode(&jtl_overflow),
            Err(RmiEncodeError::Validation(RmiValidationError::Sample(
                SampleValidationError::Count {
                    field: "JTL nodes",
                    actual: 2,
                    maximum: 1,
                }
            )))
        ));
    }

    #[test]
    fn queue_full_closed_and_cancellation_are_typed() {
        let limits = RmiLimits::default();
        let mut queue = must(
            QueueState::new(QueueCredit::new(1, 4), BackpressurePolicy::Reject, limits),
            "queue is valid",
        );
        assert_eq!(queue.try_accept(4, limits), Ok(QueueAdmission::Accepted));
        assert_eq!(queue.try_accept(1, limits), Ok(QueueAdmission::Full));
        assert_eq!(
            queue.credit.release(usize::MAX, limits),
            Err(QueueError::ReleaseOverflow)
        );
        queue.close();
        assert_eq!(queue.try_accept(1, limits), Err(QueueError::Closed));
        queue.cancel();
        assert_eq!(queue.try_accept(1, limits), Err(QueueError::Cancelled));
    }

    #[test]
    fn stream_order_replay_and_terminal_rules_are_exactly_once() {
        let limits = RmiLimits::default();
        let mut state = must(StreamState::new("run-1", "worker-a", 1, limits), "state");
        let ready = message(
            1,
            StreamEvent::Ready(Ready {
                identity: identity(),
                sender: SenderMode::Standard,
                queue: queue(),
                backpressure: BackpressurePolicy::Reject,
            }),
        );
        assert_eq!(state.accept(&ready), Ok(StreamAcceptance::Accepted));
        assert!(matches!(
            state.accept(&ready),
            Err(StreamStateError::DuplicateOrReplay { sequence: 1 })
        ));
        let started = message(
            2,
            StreamEvent::TestStarted(TestStarted {
                overload: LifecycleOverload::NoHost,
                host: HostPresence::Absent,
                callback_invocation_ordinal: 1,
                test_id: "fixture".into(),
                plan_sha256: Sha256Digest::default(),
                queue: queue(),
            }),
        );
        assert_eq!(state.accept(&started), Ok(StreamAcceptance::Accepted));
        let occurred_before_start = message(
            3,
            StreamEvent::SampleOccurred(SampleOccurred {
                callback_invocation_ordinal: 2,
                delivered_event_ordinal: 1,
                delivery_kind: DeliveryKind::SampleOccurred,
                sample_id: 7,
                result: WireSampleResult::default(),
                snapshot: SampleEventSnapshot::default(),
            }),
        );
        // A sender mode may deliver an occurrence without the optional start
        // callback; the explicit occurrence is retained rather than guessed.
        assert_eq!(
            state.accept(&occurred_before_start),
            Ok(StreamAcceptance::Accepted)
        );
        let skipped = message(
            5,
            StreamEvent::SampleStopped(SampleStopped {
                callback_invocation_ordinal: 3,
                delivered_event_ordinal: 2,
                delivery_kind: DeliveryKind::SampleOccurred,
                sample_id: 7,
                outcome: SampleStopOutcome::Completed,
                cancellation: Cancellation::None,
                snapshot: SampleEventSnapshot::default(),
            }),
        );
        assert!(matches!(
            state.accept(&skipped),
            Err(StreamStateError::OutOfOrder {
                expected: 4,
                actual: 5
            })
        ));
        assert_eq!(
            state.accept(&message(
                4,
                StreamEvent::SampleStopped(SampleStopped {
                    callback_invocation_ordinal: 3,
                    delivered_event_ordinal: 2,
                    delivery_kind: DeliveryKind::SampleOccurred,
                    sample_id: 7,
                    outcome: SampleStopOutcome::Completed,
                    cancellation: Cancellation::None,
                    snapshot: SampleEventSnapshot::default(),
                }),
            )),
            Ok(StreamAcceptance::Accepted)
        );
        assert!(matches!(
            state.accept(&skipped),
            Err(StreamStateError::CallbackOrdinal {
                expected: 4,
                actual: 3
            })
        ));
        let accounting = state.accounting();
        assert!(matches!(
            state.accept(&message(
                5,
                StreamEvent::TestEnded(TestEnded {
                    overload: LifecycleOverload::NoHost,
                    host: HostPresence::Absent,
                    callback_invocation_ordinal: 4,
                    accounting: StreamAccounting {
                        delivered_events: 99,
                        accepted_events: 99,
                        ..StreamAccounting::default()
                    },
                    queue: queue(),
                }),
            )),
            Err(StreamStateError::AcceptedEventCount {
                expected: 3,
                actual: 99
            })
        ));
        assert_eq!(
            state.accept(&message(
                5,
                StreamEvent::TestEnded(TestEnded {
                    overload: LifecycleOverload::NoHost,
                    host: HostPresence::Absent,
                    callback_invocation_ordinal: 4,
                    accounting: StreamAccounting {
                        delivered_events: 3,
                        accepted_events: 3,
                        delivered_bytes: accounting.delivered_bytes,
                        accepted_bytes: accounting.accepted_bytes,
                        ..StreamAccounting::default()
                    },
                    queue: queue(),
                })
            )),
            Ok(StreamAcceptance::Accepted)
        );
        let terminal = message(
            6,
            StreamEvent::Terminal(failed_terminal(state.accounting(), 4)),
        );
        assert_eq!(
            state.accept(&terminal),
            Ok(StreamAcceptance::TerminalAccepted)
        );
        assert!(state.is_terminal());
        assert!(matches!(
            state.accept(&message(
                7,
                StreamEvent::Terminal(failed_terminal(state.accounting(), 4)),
            )),
            Err(StreamStateError::Lifecycle(_))
        ));
    }

    #[test]
    fn optional_callback_phases_batch_credit_and_ack_are_lossless() {
        let limits = RmiLimits::default();
        let mut state = must(StreamState::new("run-1", "worker-a", 1, limits), "state");
        assert_eq!(
            state.accept(&message(
                1,
                StreamEvent::Ready(Ready {
                    identity: identity(),
                    sender: SenderMode::Standard,
                    queue: queue(),
                    backpressure: BackpressurePolicy::Reject,
                }),
            )),
            Ok(StreamAcceptance::Accepted)
        );
        assert_eq!(
            state.accept(&message(
                2,
                StreamEvent::TestStarted(TestStarted {
                    overload: LifecycleOverload::NoHost,
                    host: HostPresence::Absent,
                    callback_invocation_ordinal: 1,
                    test_id: "fixture".into(),
                    plan_sha256: Sha256Digest::default(),
                    queue: queue(),
                }),
            )),
            Ok(StreamAcceptance::Accepted)
        );
        let batch = StreamEvent::Batch(Batch {
            sender: SenderMode::Standard,
            callback_invocation_ordinal: 2,
            first_delivered_event_ordinal: 1,
            batch_id: 1,
            delivery_kind: DeliveryKind::ProcessBatch,
            event_count: 3,
            items: vec![
                BatchItem {
                    sequence: 3,
                    request_id: 301,
                    remaining_duration: RemainingDuration::from_millis(1_000),
                    cancellation: Cancellation::None,
                    event: SampleEvent::Started(SampleStarted {
                        callback_invocation_ordinal: 0,
                        delivered_event_ordinal: 0,
                        delivery_kind: DeliveryKind::ProcessBatch,
                        sample_id: 9,
                        parent_id: None,
                        label: Some("GET".into()),
                        snapshot: SampleEventSnapshot::default(),
                    }),
                },
                BatchItem {
                    sequence: 4,
                    request_id: 302,
                    remaining_duration: RemainingDuration::from_millis(1_000),
                    cancellation: Cancellation::None,
                    event: SampleEvent::Occurred(SampleOccurred {
                        callback_invocation_ordinal: 0,
                        delivered_event_ordinal: 0,
                        delivery_kind: DeliveryKind::ProcessBatch,
                        sample_id: 9,
                        result: WireSampleResult::default(),
                        snapshot: SampleEventSnapshot {
                            host: HostPresence::Present("worker-host".into()),
                            is_transaction: true,
                            ..SampleEventSnapshot::default()
                        },
                    }),
                },
                BatchItem {
                    sequence: 5,
                    request_id: 303,
                    remaining_duration: RemainingDuration::from_millis(1_000),
                    cancellation: Cancellation::None,
                    event: SampleEvent::Stopped(SampleStopped {
                        callback_invocation_ordinal: 0,
                        delivered_event_ordinal: 0,
                        delivery_kind: DeliveryKind::ProcessBatch,
                        sample_id: 9,
                        outcome: SampleStopOutcome::Completed,
                        cancellation: Cancellation::None,
                        snapshot: SampleEventSnapshot::default(),
                    }),
                },
            ],
        });
        let batch_message = message(3, batch.clone());
        let mut malformed_batch = batch.clone();
        if let StreamEvent::Batch(value) = &mut malformed_batch {
            value.event_count = 2;
        }
        assert!(matches!(
            RmiCodec::default().encode(&message(3, malformed_batch)),
            Err(RmiEncodeError::Validation(RmiValidationError::Event(
                "batch event count"
            )))
        ));
        let encoded = must(RmiCodec::default().encode(&batch_message), "batch encodes");
        assert_eq!(
            must(RmiCodec::default().decode_exact(&encoded), "batch decodes"),
            batch_message
        );
        assert_eq!(state.accept(&batch_message), Ok(StreamAcceptance::Accepted));
        assert_eq!(state.next_sequence(), 6);
        assert_eq!(
            state.accept(&message(6, StreamEvent::Credit(Credit { queue: queue() }),)),
            Ok(StreamAcceptance::Accepted)
        );
        assert_eq!(
            state.accept(&message(
                7,
                StreamEvent::Ack(Ack {
                    acknowledged_sequence: 5,
                    acknowledged_events: 3,
                    acknowledged_bytes: 128,
                }),
            )),
            Ok(StreamAcceptance::Accepted)
        );
        assert_eq!(state.next_sequence(), 8);
    }

    #[test]
    fn success_requires_test_end_sender_proof_and_two_dimensional_ack() {
        let limits = RmiLimits::default();
        let mut state = must(StreamState::new("run-1", "worker-a", 1, limits), "state");
        assert_eq!(
            state.accept(&message(
                1,
                StreamEvent::Ready(Ready {
                    identity: identity(),
                    sender: SenderMode::Standard,
                    queue: queue(),
                    backpressure: BackpressurePolicy::Reject,
                }),
            )),
            Ok(StreamAcceptance::Accepted)
        );
        assert_eq!(
            state.accept(&message(
                2,
                StreamEvent::TestStarted(TestStarted {
                    overload: LifecycleOverload::NoHost,
                    host: HostPresence::Absent,
                    callback_invocation_ordinal: 1,
                    test_id: "fixture".into(),
                    plan_sha256: Sha256Digest::default(),
                    queue: queue(),
                }),
            )),
            Ok(StreamAcceptance::Accepted)
        );
        assert_eq!(
            state.accept(&message(
                3,
                StreamEvent::SampleOccurred(SampleOccurred {
                    callback_invocation_ordinal: 2,
                    delivered_event_ordinal: 1,
                    delivery_kind: DeliveryKind::SampleOccurred,
                    sample_id: 10,
                    result: WireSampleResult::default(),
                    snapshot: SampleEventSnapshot::default(),
                }),
            )),
            Ok(StreamAcceptance::Accepted)
        );
        let before_end = state.accounting();
        assert_eq!(
            state.accept(&message(
                4,
                StreamEvent::TestEnded(TestEnded {
                    overload: LifecycleOverload::NoHost,
                    host: HostPresence::Absent,
                    callback_invocation_ordinal: 3,
                    accounting: before_end,
                    queue: queue(),
                }),
            )),
            Ok(StreamAcceptance::Accepted)
        );
        let before_ack = state.accounting();
        assert_eq!(
            state.accept(&message(
                5,
                StreamEvent::Ack(Ack {
                    acknowledged_sequence: 3,
                    acknowledged_events: before_ack.accepted_events,
                    acknowledged_bytes: before_ack.accepted_bytes,
                }),
            )),
            Ok(StreamAcceptance::Accepted)
        );
        let accounting = state.accounting();
        let proof = SenderDrainProof::Proven(SenderDrainEvidence {
            sender: SenderMode::Standard,
            generation: 1,
            final_delivered_event_ordinal: 1,
            emitted_events: accounting.delivered_events,
            accepted_events: accounting.accepted_events,
            acknowledged_events: accounting.acknowledged_events,
            emitted_bytes: accounting.delivered_bytes,
            accepted_bytes: accounting.accepted_bytes,
            acknowledged_bytes: accounting.acknowledged_bytes,
            pending_sender_events: 0,
            pending_disk_events: 0,
            completion_hook: "rmi.sender.standard.drain-proof".into(),
            proof_digest: Sha256Digest::default(),
        });
        let terminal = Terminal {
            status: TerminalStatus::Succeeded,
            failure: None,
            accounting,
            sender_proof: proof,
            test_ended_callback_ordinal: Some(3),
            test_ended_absence_reason: None,
            router_finalization_digest: Some(Sha256Digest::default()),
            queue: queue(),
        };
        assert_eq!(
            state.accept(&message(6, StreamEvent::Terminal(terminal))),
            Ok(StreamAcceptance::TerminalAccepted)
        );
        assert!(state.is_terminal());
    }

    #[test]
    fn failed_and_aborted_terminal_paths_record_absence_and_async_unavailability() {
        assert_eq!(
            SenderDrainProof::required(SenderMode::Asynch),
            SenderDrainProof::Required {
                sender: SenderMode::Asynch,
                reason: SenderProofRequirement::AsynchHelperOperation,
            }
        );
        assert_eq!(
            SenderDrainProof::unavailable_without_helper(SenderMode::StrippedAsynch),
            SenderDrainProof::Unavailable {
                sender: SenderMode::StrippedAsynch,
                reason: SenderProofAbsenceReason::HelperOperationUnavailable,
            }
        );

        let limits = RmiLimits::default();
        let mut state = must(StreamState::new("run-1", "worker-a", 1, limits), "state");
        assert_eq!(
            state.accept(&message(
                1,
                StreamEvent::Ready(Ready {
                    identity: identity(),
                    sender: SenderMode::Asynch,
                    queue: queue(),
                    backpressure: BackpressurePolicy::WaitUntilDeadline,
                }),
            )),
            Ok(StreamAcceptance::Accepted)
        );
        assert_eq!(
            state.accept(&message(
                2,
                StreamEvent::WorkerFailure(WorkerFailure {
                    worker_id: "worker-a".into(),
                    code: WorkerFailureCode::Unavailable,
                    phase: FailurePhase::Aborted,
                    retry: RetryDisposition::FinalNonRetryable {
                        phase: RetryPhase::Configure,
                        outcome_certainty: OutcomeCertainty::NotStarted,
                    },
                    message: Some("aborted before start".into()),
                }),
            )),
            Ok(StreamAcceptance::Accepted)
        );
        let terminal = Terminal {
            status: TerminalStatus::Aborted,
            failure: None,
            accounting: state.accounting(),
            sender_proof: SenderDrainProof::unavailable_without_helper(SenderMode::Asynch),
            test_ended_callback_ordinal: None,
            test_ended_absence_reason: Some(TestEndedAbsenceReason::AbortedBeforeCallback),
            router_finalization_digest: None,
            queue: queue(),
        };
        assert_eq!(
            state.accept(&message(3, StreamEvent::Terminal(terminal))),
            Ok(StreamAcceptance::TerminalAccepted)
        );
    }

    #[test]
    fn retry_is_typed_and_only_pre_start() {
        let retry = RetryDisposition::PreStartSafe {
            reason: RetryReason::WorkerUnavailable,
            next_attempt: 2,
        };
        let failure = WorkerFailure {
            worker_id: "worker-a".into(),
            code: WorkerFailureCode::Unavailable,
            phase: FailurePhase::Failed,
            retry,
            message: None,
        };
        let encoded = must(
            RmiCodec::default().encode(&message(1, StreamEvent::WorkerFailure(failure.clone()))),
            "retry failure encodes",
        );
        assert_eq!(
            must(
                RmiCodec::default().decode_exact(&encoded),
                "retry failure decodes"
            )
            .event,
            StreamEvent::WorkerFailure(failure.clone())
        );

        let limits = RmiLimits::default();
        let mut state = must(StreamState::new("run-1", "worker-a", 1, limits), "state");
        let ready = message(
            1,
            StreamEvent::Ready(Ready {
                identity: identity(),
                sender: SenderMode::Standard,
                queue: queue(),
                backpressure: BackpressurePolicy::Reject,
            }),
        );
        assert_eq!(state.accept(&ready), Ok(StreamAcceptance::Accepted));
        let started = message(
            2,
            StreamEvent::TestStarted(TestStarted {
                overload: LifecycleOverload::NoHost,
                host: HostPresence::Absent,
                callback_invocation_ordinal: 1,
                test_id: "fixture".into(),
                plan_sha256: Sha256Digest::default(),
                queue: queue(),
            }),
        );
        assert_eq!(state.accept(&started), Ok(StreamAcceptance::Accepted));
        assert_eq!(
            state.accept(&message(3, StreamEvent::WorkerFailure(failure.clone()))),
            Err(StreamStateError::RetryAfterStart)
        );
    }

    #[test]
    fn cancellation_is_monotonic_and_precludes_success() {
        let limits = RmiLimits::default();
        let mut state = must(StreamState::new("run-1", "worker-a", 1, limits), "state");
        assert_eq!(
            state.accept(&message(
                1,
                StreamEvent::Ready(Ready {
                    identity: identity(),
                    sender: SenderMode::Standard,
                    queue: queue(),
                    backpressure: BackpressurePolicy::Reject,
                }),
            )),
            Ok(StreamAcceptance::Accepted)
        );
        assert_eq!(
            state.accept(
                &message(
                    2,
                    StreamEvent::TestStarted(TestStarted {
                        overload: LifecycleOverload::NoHost,
                        host: HostPresence::Absent,
                        callback_invocation_ordinal: 1,
                        test_id: "fixture".into(),
                        plan_sha256: Sha256Digest::default(),
                        queue: queue(),
                    }),
                )
                .with_cancellation(Cancellation::Requested),
            ),
            Ok(StreamAcceptance::Accepted)
        );
        assert_eq!(
            state.accept(&message(3, StreamEvent::Credit(Credit { queue: queue() }),)),
            Err(StreamStateError::CancellationRegression {
                previous: Cancellation::Requested,
                actual: Cancellation::None,
            })
        );
        assert_eq!(
            state.accept(
                &message(
                    3,
                    StreamEvent::TestEnded(TestEnded {
                        overload: LifecycleOverload::NoHost,
                        host: HostPresence::Absent,
                        callback_invocation_ordinal: 2,
                        accounting: state.accounting(),
                        queue: queue(),
                    }),
                )
                .with_cancellation(Cancellation::Cancelled),
            ),
            Ok(StreamAcceptance::Accepted)
        );
        let accounting = state.accounting();
        let terminal = Terminal {
            status: TerminalStatus::Succeeded,
            failure: None,
            accounting: StreamAccounting {
                acknowledged_events: accounting.accepted_events,
                acknowledged_bytes: accounting.accepted_bytes,
                ..accounting
            },
            sender_proof: SenderDrainProof::Proven(SenderDrainEvidence {
                sender: SenderMode::Standard,
                generation: 1,
                final_delivered_event_ordinal: 0,
                emitted_events: accounting.delivered_events,
                accepted_events: accounting.accepted_events,
                acknowledged_events: accounting.accepted_events,
                emitted_bytes: accounting.delivered_bytes,
                accepted_bytes: accounting.accepted_bytes,
                acknowledged_bytes: accounting.accepted_bytes,
                pending_sender_events: 0,
                pending_disk_events: 0,
                completion_hook: "rmi.sender.standard.drain-proof".into(),
                proof_digest: Sha256Digest::default(),
            }),
            test_ended_callback_ordinal: Some(2),
            test_ended_absence_reason: None,
            router_finalization_digest: Some(Sha256Digest::default()),
            queue: queue(),
        };
        assert!(matches!(
            state.accept(
                &message(4, StreamEvent::Terminal(terminal))
                    .with_cancellation(Cancellation::Cancelled),
            ),
            Err(StreamStateError::TerminalStatus {
                expected: TerminalStatus::Cancelled,
                actual: TerminalStatus::Succeeded,
            })
        ));
    }

    #[test]
    fn stream_totals_are_bounded_and_rollback_on_overflow() {
        let limits = RmiLimits {
            max_stream_events: 1,
            ..RmiLimits::default()
        };
        let mut state = must(StreamState::new("run-1", "worker-a", 1, limits), "state");
        let ready = message(
            1,
            StreamEvent::Ready(Ready {
                identity: identity(),
                sender: SenderMode::Standard,
                queue: queue(),
                backpressure: BackpressurePolicy::Reject,
            }),
        );
        assert_eq!(state.accept(&ready), Ok(StreamAcceptance::Accepted));
        assert_eq!(
            state.accept(&message(
                2,
                StreamEvent::TestStarted(TestStarted {
                    overload: LifecycleOverload::NoHost,
                    host: HostPresence::Absent,
                    callback_invocation_ordinal: 1,
                    test_id: "fixture".into(),
                    plan_sha256: Sha256Digest::default(),
                    queue: queue(),
                }),
            )),
            Ok(StreamAcceptance::Accepted)
        );
        assert!(matches!(
            state.accept(&message(
                3,
                StreamEvent::SampleOccurred(SampleOccurred {
                    callback_invocation_ordinal: 2,
                    delivered_event_ordinal: 1,
                    delivery_kind: DeliveryKind::SampleOccurred,
                    sample_id: 1,
                    result: WireSampleResult::default(),
                    snapshot: SampleEventSnapshot::default(),
                }),
            )),
            Err(StreamStateError::StreamEventLimit { maximum: 1 })
        ));
        assert_eq!(state.next_sequence(), 3);
    }

    #[test]
    fn remaining_duration_and_diagnostic_wall_time_are_not_absolute_deadlines() {
        let original = message(
            1,
            StreamEvent::SampleStarted(SampleStarted {
                callback_invocation_ordinal: 1,
                delivered_event_ordinal: 1,
                delivery_kind: DeliveryKind::SampleOccurred,
                sample_id: 11,
                parent_id: None,
                label: None,
                snapshot: SampleEventSnapshot::default(),
            }),
        )
        .with_remaining_duration(RemainingDuration::from_millis(25))
        .with_diagnostic_wall_time(1_700_000_000_000);
        let codec = RmiCodec::default();
        let bytes = must(codec.encode(&original), "remaining duration encodes");
        let decoded = must(codec.decode_exact(&bytes), "remaining duration decodes");
        assert_eq!(decoded, original);
        assert_eq!(decoded.remaining_duration.as_millis(), Some(25));
        assert_eq!(decoded.diagnostic_wall_time, Some(1_700_000_000_000));
        let bounded = must(
            RmiCodec::new(RmiLimits {
                max_operation_duration_millis: 10,
                ..RmiLimits::default()
            }),
            "duration limit is valid",
        );
        assert!(matches!(
            bounded.encode(&original),
            Err(RmiEncodeError::Validation(RmiValidationError::Event(
                "remaining duration"
            )))
        ));
    }

    #[test]
    fn debug_output_redacts_profile_data_and_sample_bytes() {
        let message = message(
            1,
            StreamEvent::SampleOccurred(SampleOccurred {
                callback_invocation_ordinal: 1,
                delivered_event_ordinal: 1,
                delivery_kind: DeliveryKind::SampleOccurred,
                sample_id: 1,
                result: WireSampleResult {
                    response_data: Some(b"secret-response".to_vec()),
                    response_message: Some("secret-message".into()),
                    ..WireSampleResult::default()
                },
                snapshot: SampleEventSnapshot::default(),
            }),
        );
        let debug = format!("{message:?}");
        assert!(debug.contains("response_data_len: Some(15)"));
        assert!(!debug.contains("secret-response"));
        assert!(!debug.contains("secret-message"));
    }
}
