// SPDX-License-Identifier: Apache-2.0
//! Legacy fixture contracts for the pinned JVM scripting and plugin capability.
//!
//! This module intentionally does not know how to start a JVM, discover a
//! plugin, read a file, or execute a script. It is retained only for migration
//! diagnostics and historical fixture tests. It is not the canonical
//! `jvm-capability/2` execution contract; use `legacy_jvm_capability` only when
//! an explicitly selected migration fixture requires this provisional codec.
//! The canonical schema is `crate::jvm_capability_v2`.
//!
//! A provisional deterministic codec is included for local fixture vectors.
//! It is not a Java wire-compatibility claim and must not be presented as the
//! final worker transport until the next decision revision accepts that
//! boundary.  Source/JMX preservation is represented by
//! [`crate::legacy_jvm_capability::PreservedJmxSource`] and remains outside
//! executable operation payloads.

#![allow(missing_docs)]

use core::fmt;
use std::collections::BTreeSet;

use super::{Cancellation, Deadline, RequestId};

/// Name of the operation schema negotiated by the JVM worker.
pub const JVM_CAPABILITY_SCHEMA: &str = "jvm-capability/2";
/// Version of the operation schema encoded by this module.
pub const JVM_CAPABILITY_SCHEMA_VERSION: u16 = 2;
/// Compatibility spelling for the operation-schema version.
pub const JVM_OPERATION_SCHEMA_VERSION: u16 = JVM_CAPABILITY_SCHEMA_VERSION;
/// Active compatibility profile identity.
pub const JVM_PROFILE_ID: &str = "jmeter-5.6.3";
/// Active profile version from the pinned compatibility profile.
pub const JVM_PROFILE_VERSION: u32 = 2;
/// SHA-256 of the active profile bytes.
pub const JVM_PROFILE_SHA256_HEX: &str =
    "2f9aec07cb3720e443dae8933bde47c276b76c3a34524c225f3e9dc6abdacf65";
/// Pinned Apache JMeter release.
pub const PINNED_JMETER_VERSION: &str = "5.6.3";
/// Pinned Apache JMeter source commit.
pub const PINNED_JMETER_SOURCE_COMMIT: &str = "34a2785748e9e0b14702595e8682c387869deda3";
/// Pinned Apache JMeter archive SHA-512 in hexadecimal.
pub const PINNED_JMETER_ARCHIVE_SHA512_HEX: &str = "387fadca903ee0aa30e3f2115fdfedb3898b102e6b9fe7cc3942703094bd2e65b235df2b0c6d0d3248e74c9a7950a36e42625fd74425368342c12e40b0163076";
/// Minimum Java major version in the active profile.
pub const PINNED_JAVA_MINIMUM_MAJOR: u16 = 8;
/// Recommended Java major version in the active profile.
pub const PINNED_JAVA_RECOMMENDED_MAJOR: u16 = 17;
/// Pinned bundled BeanShell artifact path.
pub const PINNED_BSH_ARTIFACT: &str = "lib/bsh-2.0b6.jar";
/// Pinned bundled Groovy JSR223 artifact path.
pub const PINNED_GROOVY_ARTIFACT: &str = "lib/groovy-jsr223-3.0.20.jar";
/// Pinned bundled JEXL2 artifact path.
pub const PINNED_JEXL2_ARTIFACT: &str = "lib/commons-jexl-2.1.1.jar";
/// Pinned bundled JEXL3 artifact path.
pub const PINNED_JEXL3_ARTIFACT: &str = "lib/commons-jexl3-3.2.1.jar";
/// Pinned bundled Rhino function artifact path.
pub const PINNED_RHINO_ARTIFACT: &str = "lib/rhino-1.7.14.jar";
/// Pinned Java Sampler component artifact path.
pub const PINNED_JAVA_SAMPLER_ARTIFACT: &str = "lib/ext/ApacheJMeter_java.jar";
/// Pinned JUnit component artifact path.
pub const PINNED_JUNIT_ARTIFACT: &str = "lib/ext/ApacheJMeter_junit.jar";
/// Pinned JUnit runtime artifact path.
pub const PINNED_JUNIT_RUNTIME_ARTIFACT: &str = "lib/junit-4.13.2.jar";
/// Pinned BeanShell artifact SHA-256 from the fixture provenance.
pub const PINNED_BSH_SHA256_HEX: &str =
    "a17955976070c0573235ee662f2794a78082758b61accffce8d3f8aedcd91047";
/// Pinned Groovy JSR223 artifact SHA-256 from the fixture provenance.
pub const PINNED_GROOVY_SHA256_HEX: &str =
    "f5fd449d8ac64009c569dd6e81b431408b27eda75d6b54db2f9983442d579974";
/// Pinned Commons JEXL2 artifact SHA-256 from the fixture provenance.
pub const PINNED_JEXL2_SHA256_HEX: &str =
    "03c9a9fae5da78ce52c0bf24467cc37355b7e23196dff4839e2c0ff018a01306";
/// Pinned Commons JEXL3 artifact SHA-256 from the fixture provenance.
pub const PINNED_JEXL3_SHA256_HEX: &str =
    "0e40a3730b96bf6f2ebbf62552726c1655dba1abaf86ebc4bd14295feea240f6";
/// Pinned Rhino function artifact SHA-256 from the fixture provenance.
pub const PINNED_RHINO_SHA256_HEX: &str =
    "c9290b0d801bf0dbbbc4438e0f769b7650a0c5d04e6bb1aeb85775c0211b003";
/// Pinned Java Sampler artifact SHA-256 from the fixture provenance.
pub const PINNED_JAVA_SAMPLER_SHA256_HEX: &str =
    "db08dca730452d63bdc1c11e071713db87c0ee490804a022bb2cb702ac81fc08";
/// Pinned JUnit Sampler artifact SHA-256 from the fixture provenance.
pub const PINNED_JUNIT_SHA256_HEX: &str =
    "5e7a2c6166998bd1a2349fd94106cd5a7af1b30fe1cab4246d1884a27e2a2eaf";
/// Pinned JUnit runtime artifact SHA-256 from the fixture provenance.
pub const PINNED_JUNIT_RUNTIME_SHA256_HEX: &str =
    "8e495b634469d64fb8acfa3495a065cbacc8a0fff55ce1e31007be4c16dc57d3";
/// Four-byte marker for a provisional version-two JVM capability message.
pub const JVM_CAPABILITY_MAGIC: [u8; 4] = *b"JVC2";
/// Fixed envelope length in bytes.
pub const JVM_CAPABILITY_HEADER_LEN: usize = 64;
/// Hard maximum encoded message size, including the envelope.
pub const JVM_CAPABILITY_MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;
/// Hard maximum number of fields in one operation body.
pub const JVM_CAPABILITY_MAX_FIELDS: usize = 256;
/// Hard maximum bytes in one field value.
pub const JVM_CAPABILITY_MAX_FIELD_BYTES: usize = 1024 * 1024;
/// Hard maximum UTF-8 text bytes in one value.
pub const JVM_CAPABILITY_MAX_TEXT_BYTES: usize = 64 * 1024;
/// Hard maximum operation count retained by a session ledger.
pub const JVM_CAPABILITY_MAX_OPERATIONS: usize = 65_536;
/// Hard maximum result tree depth.
pub const JVM_CAPABILITY_MAX_RESULT_DEPTH: usize = 64;
/// Hard maximum result node count.
pub const JVM_CAPABILITY_MAX_RESULT_NODES: usize = 16_384;
/// Hard maximum plugin artifacts in one discovery result.
pub const JVM_CAPABILITY_MAX_PLUGIN_ARTIFACTS: usize = 4_096;
/// Hard maximum plugin aliases in one discovery result.
pub const JVM_CAPABILITY_MAX_PLUGIN_ALIASES: usize = 16_384;
/// Hard maximum classpath entries in one identity.
pub const JVM_CAPABILITY_MAX_CLASSPATH_ENTRIES: usize = 4_096;
/// Hard aggregate bound for classpath metadata and declared entries.
///
/// The classpath identity is carried inside the fixed-size capability
/// envelope, so its negotiated aggregate cannot exceed the largest possible
/// message body.
pub const JVM_CAPABILITY_MAX_CLASSPATH_BYTES: usize =
    JVM_CAPABILITY_MAX_MESSAGE_BYTES - JVM_CAPABILITY_HEADER_LEN;
/// Hard bound for a single variable/property collection.
pub const JVM_CAPABILITY_MAX_CONTEXT_ENTRIES: usize = 65_536;
/// Hard bound for diagnostics, output records, and assertions.
pub const JVM_CAPABILITY_MAX_DIAGNOSTICS: usize = 16_384;
/// Hard bound for retained stdout/stderr observations.
pub const JVM_CAPABILITY_MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
/// Hard bound for cache observations/entries.
pub const JVM_CAPABILITY_MAX_CACHE_ENTRIES: usize = 65_536;
/// Hard bound for close/drain time budgets.
pub const JVM_CAPABILITY_MAX_SHUTDOWN_MILLIS: u64 = 24 * 60 * 60 * 1_000;
/// Maximum finite operation budget accepted by this bounded schema (24 hours).
pub const JVM_CAPABILITY_MAX_DEADLINE_MILLIS: u64 = 24 * 60 * 60 * 1_000;

const FLAG_UNKNOWN_FIELDS: u8 = 0x01;
const FLAG_UNKNOWN_OPERATIONS: u8 = 0x02;
const FLAG_RESPONSE_ERROR: u8 = 0x04;
const KNOWN_FLAGS: u8 = FLAG_UNKNOWN_FIELDS | FLAG_UNKNOWN_OPERATIONS | FLAG_RESPONSE_ERROR;
const MAX_OPERATION_CODE: u16 = OperationCode::CloseRun as u16;
const MAX_HASH_TEXT_BYTES: usize = 128;

/// A node identity from the ordered JMX plan.
pub type NodeId = u64;
/// A virtual-user identity.
pub type UserId = u64;
/// A run identity.
pub type RunId = u64;
/// A lifecycle/context generation.
pub type ContextGeneration = u64;

/// A transport-independent remaining-time budget.
///
/// The schema never reads a clock or converts this value to wall time.  The
/// owning adapter decrements it at each boundary and fails closed when it
/// reaches zero.  This is deliberately distinct from the legacy framing
/// [`Deadline`] type, whose absolute timestamp is retained only for generic
/// bridge interoperability.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RemainingBudget(Option<u64>);

impl RemainingBudget {
    /// An unbounded budget is permitted only for local schema construction;
    /// production adapters should negotiate a finite value.
    pub const UNBOUNDED: Self = Self(None);

    /// Creates a finite millisecond budget.
    pub const fn from_millis(millis: u64) -> Self {
        Self(Some(millis))
    }

    /// Returns the remaining milliseconds, or `None` when unbounded.
    pub const fn as_millis(self) -> Option<u64> {
        self.0
    }

    /// Returns whether the finite budget is exhausted.
    pub const fn is_exhausted(self) -> bool {
        matches!(self.0, Some(0))
    }

    /// Returns a child budget bounded by the supplied amount.
    pub const fn child(self, maximum_millis: u64) -> Self {
        match self.0 {
            Some(current) => Self(Some(if current < maximum_millis {
                current
            } else {
                maximum_millis
            })),
            None => Self(Some(maximum_millis)),
        }
    }

    /// Consumes elapsed milliseconds without reading a clock.
    pub const fn consume(self, elapsed_millis: u64) -> Self {
        match self.0 {
            Some(current) => Self(Some(current.saturating_sub(elapsed_millis))),
            None => Self::UNBOUNDED,
        }
    }

    /// Validates the finite budget against the protocol maximum.
    pub const fn validate(self) -> Result<(), JvmCapabilityError> {
        match self.0 {
            Some(value) if value > JVM_CAPABILITY_MAX_DEADLINE_MILLIS => Err(
                JvmCapabilityError::new(JvmCapabilityErrorCode::DeadlineInvalid),
            ),
            _ => Ok(()),
        }
    }
}

impl Default for RemainingBudget {
    fn default() -> Self {
        Self::UNBOUNDED
    }
}

/// Opaque application-owned reference to a secret.
///
/// The handle has no conversion to a secret value and its bytes are never
/// included in ordinary formatting.  A bridge adapter resolves it through a
/// protected provider immediately before Java object construction.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SecretHandle([u8; 16]);

impl SecretHandle {
    /// Creates a handle from an application-owned opaque token.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the opaque token for a protected provider lookup.
    pub const fn as_bytes(self) -> [u8; 16] {
        self.0
    }
}

impl fmt::Debug for SecretHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretHandle(<redacted>)")
    }
}

/// A secret purpose and opaque handle, never a secret value.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    pub handle: SecretHandle,
    pub provider_identity: Sha256Digest,
    pub purpose: String,
    pub rights: u32,
    pub expiry: RemainingBudget,
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("handle", &self.handle)
            .field("provider_identity", &self.provider_identity)
            .field("purpose", &"<redacted>")
            .field("rights", &self.rights)
            .field("expiry", &self.expiry)
            .finish()
    }
}

/// Kind of live JVM object that may be leased by a future adapter.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum ObjectKind {
    Context = 1,
    Variables = 2,
    Properties = 3,
    Sampler = 4,
    PreviousResult = 5,
    CurrentResult = 6,
    Thread = 7,
    ThreadGroup = 8,
    Engine = 9,
    Logger = 10,
    Output = 11,
    Provider = 12,
}

/// Opaque rights and lease identity for one live JVM object.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ObjectHandle {
    pub handle_id: u64,
    pub object_kind: ObjectKind,
    pub owner_scope: u32,
    pub class_identity_sha256: Sha256Digest,
    pub classloader_generation: u64,
    pub rights: u32,
    pub lease_operations: u32,
}

impl fmt::Debug for ObjectHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObjectHandle")
            .field("handle_id", &self.handle_id)
            .field("object_kind", &self.object_kind)
            .field("owner_scope", &self.owner_scope)
            .field("class_identity_sha256", &self.class_identity_sha256)
            .field("classloader_generation", &self.classloader_generation)
            .field("rights", &self.rights)
            .field("lease_operations", &self.lease_operations)
            .finish()
    }
}

impl ObjectHandle {
    /// Validates the bounded handle identity before it enters a projection.
    pub fn validate(&self) -> Result<(), JvmCapabilityError> {
        if self.handle_id == 0 || self.lease_operations == 0 {
            Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::HandleInvalid,
            ))
        } else {
            Ok(())
        }
    }
}

fn encode_object_handle(value: &Option<ObjectHandle>) -> Result<Vec<u8>, JvmCapabilityError> {
    let mut writer = WireWriter::new();
    match value {
        Some(value) => {
            value.validate()?;
            writer.bool(true);
            writer.u64(value.handle_id);
            writer.u8(value.object_kind as u8);
            writer.u32(value.owner_scope);
            value.class_identity_sha256.encode_into(&mut writer);
            writer.u64(value.classloader_generation);
            writer.u32(value.rights);
            writer.u32(value.lease_operations);
        }
        None => writer.bool(false),
    }
    Ok(writer.finish())
}

fn decode_object_kind(value: u8) -> Result<ObjectKind, JvmCapabilityError> {
    match value {
        1 => Ok(ObjectKind::Context),
        2 => Ok(ObjectKind::Variables),
        3 => Ok(ObjectKind::Properties),
        4 => Ok(ObjectKind::Sampler),
        5 => Ok(ObjectKind::PreviousResult),
        6 => Ok(ObjectKind::CurrentResult),
        7 => Ok(ObjectKind::Thread),
        8 => Ok(ObjectKind::ThreadGroup),
        9 => Ok(ObjectKind::Engine),
        10 => Ok(ObjectKind::Logger),
        11 => Ok(ObjectKind::Output),
        12 => Ok(ObjectKind::Provider),
        _ => Err(JvmCapabilityError::new(
            JvmCapabilityErrorCode::HandleInvalid,
        )),
    }
}

fn decode_object_handle(bytes: &[u8]) -> Result<Option<ObjectHandle>, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let value = if reader.bool()? {
        let value = ObjectHandle {
            handle_id: reader.u64()?,
            object_kind: decode_object_kind(reader.u8()?)?,
            owner_scope: reader.u32()?,
            class_identity_sha256: Sha256Digest::decode(&mut reader)?,
            classloader_generation: reader.u64()?,
            rights: reader.u32()?,
            lease_operations: reader.u32()?,
        };
        value.validate()?;
        Some(value)
    } else {
        None
    };
    reader.finish()?;
    Ok(value)
}

/// Stable operation names in wire order.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
pub enum OperationCode {
    OpenRun = 1,
    DiscoverPlugins = 2,
    ExpandFunction = 3,
    ExecuteJsr223 = 4,
    JavaSamplerSetup = 5,
    JavaSamplerRun = 6,
    JavaSamplerTeardown = 7,
    JunitRun = 8,
    ExecutePluginElement = 9,
    ExpandPluginFunction = 10,
    CloseRun = 11,
}

impl OperationCode {
    /// Returns every known operation in canonical wire order.
    pub const fn all() -> [Self; 11] {
        [
            Self::OpenRun,
            Self::DiscoverPlugins,
            Self::ExpandFunction,
            Self::ExecuteJsr223,
            Self::JavaSamplerSetup,
            Self::JavaSamplerRun,
            Self::JavaSamplerTeardown,
            Self::JunitRun,
            Self::ExecutePluginElement,
            Self::ExpandPluginFunction,
            Self::CloseRun,
        ]
    }

    /// Returns the stable machine-readable operation name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OpenRun => "open_run",
            Self::DiscoverPlugins => "discover_plugins",
            Self::ExpandFunction => "expand_function",
            Self::ExecuteJsr223 => "execute_jsr223",
            Self::JavaSamplerSetup => "java_sampler_setup",
            Self::JavaSamplerRun => "java_sampler_run",
            Self::JavaSamplerTeardown => "java_sampler_teardown",
            Self::JunitRun => "junit_run",
            Self::ExecutePluginElement => "execute_plugin_element",
            Self::ExpandPluginFunction => "expand_plugin_function",
            Self::CloseRun => "close_run",
        }
    }

    fn from_wire(value: u16) -> Result<Self, JvmCapabilityError> {
        match value {
            1 => Ok(Self::OpenRun),
            2 => Ok(Self::DiscoverPlugins),
            3 => Ok(Self::ExpandFunction),
            4 => Ok(Self::ExecuteJsr223),
            5 => Ok(Self::JavaSamplerSetup),
            6 => Ok(Self::JavaSamplerRun),
            7 => Ok(Self::JavaSamplerTeardown),
            8 => Ok(Self::JunitRun),
            9 => Ok(Self::ExecutePluginElement),
            10 => Ok(Self::ExpandPluginFunction),
            11 => Ok(Self::CloseRun),
            _ => Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::UnknownOperation,
            )),
        }
    }
}

impl fmt::Debug for OperationCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl fmt::Display for OperationCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The direction of a capability envelope.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum JvmMessageKind {
    Request = 1,
    Response = 2,
}

impl JvmMessageKind {
    fn from_wire(value: u8) -> Result<Self, JvmCapabilityError> {
        match value {
            1 => Ok(Self::Request),
            2 => Ok(Self::Response),
            _ => Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::InvalidMessage,
            )),
        }
    }
}

/// Explicit operation phase carried independently from request/response kind.
///
/// The phase is a bounded state label for the owning adapter.  This module
/// does not infer Java execution or rollback from it.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum JvmOperationPhase {
    Created = 1,
    Handshaking = 2,
    Ready = 3,
    RunOpen = 4,
    Prepared = 5,
    Executing = 6,
    Proposed = 7,
    Committing = 8,
    Aborting = 9,
    Closing = 10,
    Poisoned = 11,
    Terminal = 12,
}

/// Short compatibility alias for callers that refer to the phase as `JvmPhase`.
pub type JvmPhase = JvmOperationPhase;

impl JvmOperationPhase {
    /// Returns the stable phase spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Handshaking => "handshaking",
            Self::Ready => "ready",
            Self::RunOpen => "run_open",
            Self::Prepared => "prepared",
            Self::Executing => "executing",
            Self::Proposed => "proposed",
            Self::Committing => "committing",
            Self::Aborting => "aborting",
            Self::Closing => "closing",
            Self::Poisoned => "poisoned",
            Self::Terminal => "terminal",
        }
    }

    fn from_wire(value: u8) -> Result<Self, JvmCapabilityError> {
        match value {
            1 => Ok(Self::Created),
            2 => Ok(Self::Handshaking),
            3 => Ok(Self::Ready),
            4 => Ok(Self::RunOpen),
            5 => Ok(Self::Prepared),
            6 => Ok(Self::Executing),
            7 => Ok(Self::Proposed),
            8 => Ok(Self::Committing),
            9 => Ok(Self::Aborting),
            10 => Ok(Self::Closing),
            11 => Ok(Self::Poisoned),
            12 => Ok(Self::Terminal),
            _ => Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::BridgeProtocolPhase,
            )),
        }
    }
}

fn validate_message_phase(
    kind: JvmMessageKind,
    operation: OperationCode,
    phase: JvmOperationPhase,
) -> Result<(), JvmCapabilityError> {
    let valid = match (kind, operation) {
        (JvmMessageKind::Request, OperationCode::OpenRun) => {
            phase == JvmOperationPhase::Handshaking
        }
        (JvmMessageKind::Response, OperationCode::OpenRun) => phase == JvmOperationPhase::Ready,
        (JvmMessageKind::Request, OperationCode::CloseRun) => phase == JvmOperationPhase::Closing,
        (JvmMessageKind::Response, OperationCode::CloseRun) => phase == JvmOperationPhase::Terminal,
        (JvmMessageKind::Request, _) => matches!(
            phase,
            JvmOperationPhase::Ready
                | JvmOperationPhase::RunOpen
                | JvmOperationPhase::Prepared
                | JvmOperationPhase::Executing
                | JvmOperationPhase::Proposed
                | JvmOperationPhase::Committing
                | JvmOperationPhase::Aborting
        ),
        (JvmMessageKind::Response, _) => matches!(
            phase,
            JvmOperationPhase::RunOpen
                | JvmOperationPhase::Proposed
                | JvmOperationPhase::Aborting
                | JvmOperationPhase::Poisoned
                | JvmOperationPhase::Terminal
        ),
    };
    if valid {
        Ok(())
    } else {
        Err(JvmCapabilityError::new(
            JvmCapabilityErrorCode::BridgeProtocolPhase,
        ))
    }
}

impl fmt::Display for JvmOperationPhase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Digest wrapper used for exact artifact and identity binding.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    /// The all-zero digest, useful only for deterministic test declarations.
    pub const ZERO: Self = Self([0; 32]);

    /// Creates a digest from raw bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Parses exactly 64 hexadecimal characters.
    pub fn from_hex(value: &str) -> Result<Self, JvmCapabilityError> {
        let bytes = decode_hex::<32>(value)?;
        Ok(Self(bytes))
    }

    /// Returns the raw digest bytes.
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }

    fn encode_into(&self, writer: &mut WireWriter) {
        writer.bytes(&self.0);
    }

    fn decode(reader: &mut WireReader<'_>) -> Result<Self, JvmCapabilityError> {
        let mut value = [0; 32];
        value.copy_from_slice(reader.bytes_exact(32)?);
        Ok(Self(value))
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Sha256Digest(<redacted>)")
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Digest wrapper used for the pinned JMeter archive identity.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Sha512Digest([u8; 64]);

impl Sha512Digest {
    /// The all-zero digest, useful only for deterministic test declarations.
    pub const ZERO: Self = Self([0; 64]);

    /// Creates a digest from raw bytes.
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Parses exactly 128 hexadecimal characters.
    pub fn from_hex(value: &str) -> Result<Self, JvmCapabilityError> {
        let bytes = decode_hex::<64>(value)?;
        Ok(Self(bytes))
    }

    /// Returns the raw digest bytes.
    pub const fn as_bytes(self) -> [u8; 64] {
        self.0
    }

    fn encode_into(&self, writer: &mut WireWriter) {
        writer.bytes(&self.0);
    }

    fn decode(reader: &mut WireReader<'_>) -> Result<Self, JvmCapabilityError> {
        let mut value = [0; 64];
        value.copy_from_slice(reader.bytes_exact(64)?);
        Ok(Self(value))
    }
}

impl fmt::Debug for Sha512Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Sha512Digest(<redacted>)")
    }
}

impl fmt::Display for Sha512Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Compatibility digest used by JMeter's inline compiled-script cache key.
/// It is an identity component only; it is not a security integrity claim.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Md5Digest([u8; 16]);

impl Md5Digest {
    /// The all-zero digest, useful only for deterministic test declarations.
    pub const ZERO: Self = Self([0; 16]);

    /// Creates a digest from raw bytes.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the raw digest bytes.
    pub const fn as_bytes(self) -> [u8; 16] {
        self.0
    }

    fn encode_into(&self, writer: &mut WireWriter) {
        writer.bytes(&self.0);
    }

    fn decode(reader: &mut WireReader<'_>) -> Result<Self, JvmCapabilityError> {
        let mut value = [0; 16];
        value.copy_from_slice(reader.bytes_exact(16)?);
        Ok(Self(value))
    }
}

impl fmt::Debug for Md5Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Md5Digest(<redacted>)")
    }
}

/// Stable typed errors returned by validation and wire decoding.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum JvmCapabilityErrorCode {
    BridgeProtocolVersion = 1,
    BridgeProtocolOrder = 2,
    BridgeLimit = 3,
    BridgeCancelled = 4,
    BridgeDeadlineExceeded = 5,
    BridgeWorkerCrashed = 6,
    BridgeContainmentLost = 7,
    ScriptEngineUnavailable = 8,
    ScriptSourceUnavailable = 9,
    ScriptConfigurationInvalid = 10,
    ScriptClasspathUnavailable = 11,
    ScriptClassUnavailable = 12,
    ScriptClassContractInvalid = 13,
    ScriptContextUnsupported = 14,
    ScriptEvaluationFailed = 15,
    PluginClasspathUnavailable = 16,
    PluginAliasAmbiguous = 17,
    PluginClassUnavailable = 18,
    PluginElementUnavailable = 19,
    PluginFunctionUnavailable = 20,
    SandboxDenied = 21,
    DuplicateRequestId = 22,
    DuplicateIdentity = 23,
    StaleContextGeneration = 24,
    AtomicDeltaRejected = 25,
    UnknownOperation = 26,
    UnknownField = 27,
    InvalidMessage = 28,
    InvalidIdentity = 29,
    RunNotOpen = 30,
    RunAlreadyOpen = 31,
    RunAlreadyClosed = 32,
    TerminalMessage = 33,
    MalformedUtf8 = 34,
    Truncated = 35,
    TrailingBytes = 36,
    CacheIdentityInvalid = 37,
    DeadlineInvalid = 38,
    BridgeProtocolPhase = 39,
    BridgeProtocolSequence = 40,
    BridgeProtocolDigest = 41,
    BridgeWorkerPoisoned = 42,
    TransactionInvalid = 43,
    TransactionConflict = 44,
    TransactionAbortUnsafe = 45,
    HandleInvalid = 46,
    ScriptValueTypeUnsupported = 47,
    SecretDenied = 48,
    ClasspathIdentityMismatch = 49,
    ProviderIdentityMismatch = 50,
}

impl JvmCapabilityErrorCode {
    /// Returns the stable machine-readable code used in diagnostics.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BridgeProtocolVersion => "bridge.protocol.version",
            Self::BridgeProtocolOrder => "bridge.protocol.order",
            Self::BridgeLimit => "bridge.limit",
            Self::BridgeCancelled => "bridge.cancelled",
            Self::BridgeDeadlineExceeded => "bridge.deadline.exceeded",
            Self::BridgeWorkerCrashed => "bridge.worker.crashed",
            Self::BridgeContainmentLost => "bridge.containment-lost",
            Self::ScriptEngineUnavailable => "script.engine.unavailable",
            Self::ScriptSourceUnavailable => "script.source.unavailable",
            Self::ScriptConfigurationInvalid => "script.configuration.invalid",
            Self::ScriptClasspathUnavailable => "script.classpath.unavailable",
            Self::ScriptClassUnavailable => "script.class.unavailable",
            Self::ScriptClassContractInvalid => "script.class.contract-invalid",
            Self::ScriptContextUnsupported => "script.context.unsupported",
            Self::ScriptEvaluationFailed => "script.evaluation.failed",
            Self::PluginClasspathUnavailable => "plugin.classpath.unavailable",
            Self::PluginAliasAmbiguous => "plugin.alias.ambiguous",
            Self::PluginClassUnavailable => "plugin.class.unavailable",
            Self::PluginElementUnavailable => "plugin.element.unavailable",
            Self::PluginFunctionUnavailable => "plugin.function.unavailable",
            Self::SandboxDenied => "sandbox.denied",
            Self::DuplicateRequestId => "bridge.request.duplicate",
            Self::DuplicateIdentity => "bridge.identity.duplicate",
            Self::StaleContextGeneration => "bridge.context.stale-generation",
            Self::AtomicDeltaRejected => "bridge.context.atomic-rejected",
            Self::UnknownOperation => "bridge.operation.unknown",
            Self::UnknownField => "bridge.field.unknown",
            Self::InvalidMessage => "bridge.message.invalid",
            Self::InvalidIdentity => "bridge.identity.invalid",
            Self::RunNotOpen => "bridge.run.not-open",
            Self::RunAlreadyOpen => "bridge.run.already-open",
            Self::RunAlreadyClosed => "bridge.run.already-closed",
            Self::TerminalMessage => "bridge.message.terminal",
            Self::MalformedUtf8 => "bridge.text.utf8",
            Self::Truncated => "bridge.message.truncated",
            Self::TrailingBytes => "bridge.message.trailing-bytes",
            Self::CacheIdentityInvalid => "script.cache.identity-invalid",
            Self::DeadlineInvalid => "bridge.deadline.invalid",
            Self::BridgeProtocolPhase => "bridge.protocol.phase",
            Self::BridgeProtocolSequence => "bridge.protocol.sequence",
            Self::BridgeProtocolDigest => "bridge.protocol.digest",
            Self::BridgeWorkerPoisoned => "bridge.worker.poisoned",
            Self::TransactionInvalid => "bridge.transaction.invalid",
            Self::TransactionConflict => "bridge.transaction.conflict",
            Self::TransactionAbortUnsafe => "bridge.transaction.abort-unsafe",
            Self::HandleInvalid => "bridge.handle.invalid",
            Self::ScriptValueTypeUnsupported => "script.value.type-unsupported",
            Self::SecretDenied => "script.secret.denied",
            Self::ClasspathIdentityMismatch => "bridge.classpath.identity-mismatch",
            Self::ProviderIdentityMismatch => "bridge.provider.identity-mismatch",
        }
    }
}

/// A typed schema error.  Diagnostic detail is intentionally private and is
/// never included by [`fmt::Debug`] or [`fmt::Display`].
#[derive(Clone, Eq, PartialEq)]
pub struct JvmCapabilityError {
    code: JvmCapabilityErrorCode,
    request_id: Option<RequestId>,
    operation: Option<OperationCode>,
    detail: Option<String>,
}

impl JvmCapabilityError {
    /// Creates an error with no retained human detail.
    pub const fn new(code: JvmCapabilityErrorCode) -> Self {
        Self {
            code,
            request_id: None,
            operation: None,
            detail: None,
        }
    }

    /// Attaches bounded internal context without exposing it in formatting.
    pub fn with_detail(code: JvmCapabilityErrorCode, detail: impl Into<String>) -> Self {
        let mut detail = detail.into();
        if detail.len() > JVM_CAPABILITY_MAX_TEXT_BYTES {
            detail.truncate(JVM_CAPABILITY_MAX_TEXT_BYTES);
        }
        Self {
            code,
            request_id: None,
            operation: None,
            detail: Some(detail),
        }
    }

    /// Returns the stable error code.
    pub const fn code(&self) -> JvmCapabilityErrorCode {
        self.code
    }

    /// Returns the stable error-code string.
    pub const fn code_str(&self) -> &'static str {
        self.code.as_str()
    }

    /// Returns the request ID attached by a codec/session, if any.
    pub const fn request_id(&self) -> Option<RequestId> {
        self.request_id
    }

    /// Returns the operation attached by a codec/session, if any.
    pub const fn operation(&self) -> Option<OperationCode> {
        self.operation
    }
}

impl fmt::Debug for JvmCapabilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JvmCapabilityError")
            .field("code", &self.code)
            .field("request_id", &self.request_id)
            .field("operation", &self.operation)
            .field("detail", &"<redacted>")
            .finish()
    }
}

impl fmt::Display for JvmCapabilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for JvmCapabilityError {}

/// Limits negotiated before `open_run`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JvmCapabilityLimits {
    pub max_message_bytes: usize,
    pub max_fields: usize,
    pub max_text_bytes: usize,
    pub max_operations: usize,
    pub max_in_flight: usize,
    pub max_variables: usize,
    pub max_properties: usize,
    pub max_result_depth: usize,
    pub max_result_nodes: usize,
    pub max_result_bytes: usize,
    pub max_script_source_bytes: usize,
    pub max_script_output_bytes: usize,
    pub max_classpath_entries: usize,
    pub max_classpath_bytes: usize,
    pub max_plugin_artifacts: usize,
    pub max_plugin_aliases: usize,
    pub max_plugin_dependencies: usize,
    pub max_diagnostics: usize,
    pub max_stdout_bytes: usize,
    pub max_stderr_bytes: usize,
    pub max_cache_entries: usize,
    pub max_shutdown_millis: u64,
}

impl Default for JvmCapabilityLimits {
    fn default() -> Self {
        Self {
            max_message_bytes: JVM_CAPABILITY_MAX_MESSAGE_BYTES,
            max_fields: JVM_CAPABILITY_MAX_FIELDS,
            max_text_bytes: JVM_CAPABILITY_MAX_TEXT_BYTES,
            max_operations: JVM_CAPABILITY_MAX_OPERATIONS,
            max_in_flight: 64,
            max_variables: 4_096,
            max_properties: 4_096,
            max_result_depth: JVM_CAPABILITY_MAX_RESULT_DEPTH,
            max_result_nodes: JVM_CAPABILITY_MAX_RESULT_NODES,
            max_result_bytes: 2 * 1024 * 1024,
            max_script_source_bytes: 512 * 1024,
            max_script_output_bytes: 512 * 1024,
            max_classpath_entries: JVM_CAPABILITY_MAX_CLASSPATH_ENTRIES,
            max_classpath_bytes: JVM_CAPABILITY_MAX_CLASSPATH_BYTES,
            max_plugin_artifacts: JVM_CAPABILITY_MAX_PLUGIN_ARTIFACTS,
            max_plugin_aliases: JVM_CAPABILITY_MAX_PLUGIN_ALIASES,
            max_plugin_dependencies: 16_384,
            max_diagnostics: 1_024,
            max_stdout_bytes: 256 * 1024,
            max_stderr_bytes: 256 * 1024,
            max_cache_entries: 4_096,
            max_shutdown_millis: 30_000,
        }
    }
}

impl JvmCapabilityLimits {
    /// Returns the largest field payload permitted by both negotiated message
    /// capacity and the schema's hard per-field ceiling.
    pub const fn max_field_bytes(self) -> usize {
        let body_bytes = self
            .max_message_bytes
            .saturating_sub(JVM_CAPABILITY_HEADER_LEN);
        if body_bytes < JVM_CAPABILITY_MAX_FIELD_BYTES {
            body_bytes
        } else {
            JVM_CAPABILITY_MAX_FIELD_BYTES
        }
    }

    /// Validates a negotiated declaration against hard bounds.
    pub fn validate(self) -> Result<(), JvmCapabilityError> {
        let invalid = self.max_message_bytes < JVM_CAPABILITY_HEADER_LEN
            || self.max_message_bytes > JVM_CAPABILITY_MAX_MESSAGE_BYTES
            || self.max_fields == 0
            || self.max_fields > JVM_CAPABILITY_MAX_FIELDS
            || self.max_text_bytes == 0
            || self.max_text_bytes > JVM_CAPABILITY_MAX_TEXT_BYTES
            || self.max_operations == 0
            || self.max_operations > JVM_CAPABILITY_MAX_OPERATIONS
            || self.max_in_flight == 0
            || self.max_in_flight > self.max_operations
            || self.max_variables == 0
            || self.max_properties == 0
            || self.max_variables > JVM_CAPABILITY_MAX_CONTEXT_ENTRIES
            || self.max_properties > JVM_CAPABILITY_MAX_CONTEXT_ENTRIES
            || self.max_result_depth == 0
            || self.max_result_depth > JVM_CAPABILITY_MAX_RESULT_DEPTH
            || self.max_result_nodes == 0
            || self.max_result_nodes > JVM_CAPABILITY_MAX_RESULT_NODES
            || self.max_result_bytes == 0
            || self.max_result_bytes > JVM_CAPABILITY_MAX_MESSAGE_BYTES
            || self.max_script_source_bytes == 0
            || self.max_script_source_bytes > JVM_CAPABILITY_MAX_MESSAGE_BYTES
            || self.max_script_output_bytes == 0
            || self.max_script_output_bytes > JVM_CAPABILITY_MAX_MESSAGE_BYTES
            || self.max_classpath_entries == 0
            || self.max_classpath_entries > JVM_CAPABILITY_MAX_CLASSPATH_ENTRIES
            || self.max_classpath_bytes == 0
            || self.max_classpath_bytes > JVM_CAPABILITY_MAX_CLASSPATH_BYTES
            || self.max_plugin_artifacts == 0
            || self.max_plugin_artifacts > JVM_CAPABILITY_MAX_PLUGIN_ARTIFACTS
            || self.max_plugin_aliases == 0
            || self.max_plugin_aliases > JVM_CAPABILITY_MAX_PLUGIN_ALIASES
            || self.max_plugin_dependencies == 0
            || self.max_plugin_dependencies > JVM_CAPABILITY_MAX_PLUGIN_ALIASES
            || self.max_diagnostics == 0
            || self.max_diagnostics > JVM_CAPABILITY_MAX_DIAGNOSTICS
            || self.max_stdout_bytes == 0
            || self.max_stdout_bytes > JVM_CAPABILITY_MAX_OUTPUT_BYTES
            || self.max_stderr_bytes == 0
            || self.max_stderr_bytes > JVM_CAPABILITY_MAX_OUTPUT_BYTES
            || self.max_cache_entries == 0
            || self.max_cache_entries > JVM_CAPABILITY_MAX_CACHE_ENTRIES
            || self.max_shutdown_millis == 0
            || self.max_shutdown_millis > JVM_CAPABILITY_MAX_SHUTDOWN_MILLIS;
        if invalid {
            Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit))
        } else {
            Ok(())
        }
    }
}

/// Opaque field retained only when the peer explicitly negotiated it.
#[derive(Clone, Eq, PartialEq)]
pub struct OpaqueField {
    pub tag: u16,
    pub value: Vec<u8>,
}

impl fmt::Debug for OpaqueField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueField")
            .field("tag", &self.tag)
            .field("bytes", &self.value.len())
            .finish()
    }
}

/// Unknown-operation payload retained only under explicit negotiation.
#[derive(Clone, Eq, PartialEq)]
pub struct UnknownOperation {
    pub code: u16,
    pub body: Vec<u8>,
}

impl fmt::Debug for UnknownOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UnknownOperation")
            .field("code", &self.code)
            .field("bytes", &self.body.len())
            .finish()
    }
}

/// Per-message unknown-operation/unknown-field preservation negotiation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct JvmPreservationNegotiation {
    pub preserve_unknown_operations: bool,
    pub preserve_unknown_fields: bool,
}

/// Codec configuration.  Strict decoding is the default.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct JvmCodecOptions {
    pub limits: JvmCapabilityLimits,
    pub preservation: JvmPreservationNegotiation,
}

impl JvmCodecOptions {
    /// Returns strict bounded options.
    pub const fn strict() -> Self {
        Self {
            limits: JvmCapabilityLimits {
                max_message_bytes: JVM_CAPABILITY_MAX_MESSAGE_BYTES,
                max_fields: JVM_CAPABILITY_MAX_FIELDS,
                max_text_bytes: JVM_CAPABILITY_MAX_TEXT_BYTES,
                max_operations: JVM_CAPABILITY_MAX_OPERATIONS,
                max_in_flight: 64,
                max_variables: 4_096,
                max_properties: 4_096,
                max_result_depth: JVM_CAPABILITY_MAX_RESULT_DEPTH,
                max_result_nodes: JVM_CAPABILITY_MAX_RESULT_NODES,
                max_result_bytes: 2 * 1024 * 1024,
                max_script_source_bytes: 512 * 1024,
                max_script_output_bytes: 512 * 1024,
                max_classpath_entries: JVM_CAPABILITY_MAX_CLASSPATH_ENTRIES,
                max_classpath_bytes: JVM_CAPABILITY_MAX_CLASSPATH_BYTES,
                max_plugin_artifacts: JVM_CAPABILITY_MAX_PLUGIN_ARTIFACTS,
                max_plugin_aliases: JVM_CAPABILITY_MAX_PLUGIN_ALIASES,
                max_plugin_dependencies: 16_384,
                max_diagnostics: 1_024,
                max_stdout_bytes: 256 * 1024,
                max_stderr_bytes: 256 * 1024,
                max_cache_entries: 4_096,
                max_shutdown_millis: 30_000,
            },
            preservation: JvmPreservationNegotiation {
                preserve_unknown_operations: false,
                preserve_unknown_fields: false,
            },
        }
    }

    /// Returns options with both opaque-preservation promises enabled.
    pub const fn preserving_unknowns() -> Self {
        let mut options = Self::strict();
        options.preservation = JvmPreservationNegotiation {
            preserve_unknown_operations: true,
            preserve_unknown_fields: true,
        };
        options
    }

    fn validate(self) -> Result<(), JvmCapabilityError> {
        self.limits.validate()
    }
}

/// A profile identity bound before a run opens.
#[derive(Clone, Eq, PartialEq)]
pub struct ProfileIdentity {
    pub id: String,
    pub version: u32,
    pub sha256: Sha256Digest,
}

impl fmt::Debug for ProfileIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProfileIdentity")
            .field("id", &self.id)
            .field("version", &self.version)
            .field("sha256", &self.sha256)
            .finish()
    }
}

/// Exact JMeter release identity.
#[derive(Clone, Eq, PartialEq)]
pub struct JmeterIdentity {
    pub version: String,
    pub source_commit: String,
    pub archive_sha512: Sha512Digest,
    pub signature_verified: bool,
}

impl fmt::Debug for JmeterIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JmeterIdentity")
            .field("version", &self.version)
            .field("source_commit", &self.source_commit)
            .field("archive_sha512", &self.archive_sha512)
            .field("signature_verified", &self.signature_verified)
            .finish()
    }
}

/// Exact JVM executable/runtime identity.
#[derive(Clone, Eq, PartialEq)]
pub struct JvmIdentity {
    pub executable_sha256: Sha256Digest,
    pub vendor: String,
    pub version: String,
    pub vm: String,
    pub major: u16,
    pub target_triple: String,
    pub os_image: String,
}

impl fmt::Debug for JvmIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JvmIdentity")
            .field("executable_sha256", &self.executable_sha256)
            .field("vendor", &self.vendor)
            .field("version", &self.version)
            .field("vm", &self.vm)
            .field("major", &self.major)
            .field("target_triple", &self.target_triple)
            .field("os_image", &"<redacted>")
            .finish()
    }
}

/// Exact helper source/build identity.
#[derive(Clone, Eq, PartialEq)]
pub struct HelperIdentity {
    pub source_sha256: Sha256Digest,
    pub build_sha256: Sha256Digest,
    pub compiler: String,
    pub operation_schema_sha256: Sha256Digest,
}

impl fmt::Debug for HelperIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HelperIdentity")
            .field("source_sha256", &self.source_sha256)
            .field("build_sha256", &self.build_sha256)
            .field("compiler", &self.compiler)
            .field("operation_schema_sha256", &self.operation_schema_sha256)
            .finish()
    }
}

/// The role of a classpath entry, retaining declared input order.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ClasspathRole {
    LibExt = 1,
    SearchPaths = 2,
    Lib = 3,
    UserClasspath = 4,
    PluginDependencyPaths = 5,
}

impl ClasspathRole {
    fn from_wire(value: u8) -> Result<Self, JvmCapabilityError> {
        match value {
            1 => Ok(Self::LibExt),
            2 => Ok(Self::SearchPaths),
            3 => Ok(Self::Lib),
            4 => Ok(Self::UserClasspath),
            5 => Ok(Self::PluginDependencyPaths),
            _ => Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::InvalidIdentity,
            )),
        }
    }
}

/// License/NOTICE accounting for an artifact.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum LicenseNoticeStatus {
    Verified = 1,
    Declared = 2,
    Missing = 3,
}

impl LicenseNoticeStatus {
    fn from_wire(value: u8) -> Result<Self, JvmCapabilityError> {
        match value {
            1 => Ok(Self::Verified),
            2 => Ok(Self::Declared),
            3 => Ok(Self::Missing),
            _ => Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::InvalidIdentity,
            )),
        }
    }
}

/// Script-engine/provider identity bound to one classpath generation.
#[derive(Clone, Eq, PartialEq)]
pub struct ProviderIdentity {
    pub name: String,
    pub version: String,
    pub artifact_sha256: Sha256Digest,
    pub service_descriptor_sha256: Option<Sha256Digest>,
    pub service_provider: Option<String>,
}

impl fmt::Debug for ProviderIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderIdentity")
            .field("name", &self.name)
            .field("version", &self.version)
            .field("artifact_sha256", &self.artifact_sha256)
            .field("service_descriptor_sha256", &self.service_descriptor_sha256)
            .field("service_provider", &self.service_provider)
            .finish()
    }
}

/// One ordered classpath member identity.
#[derive(Clone, Eq, PartialEq)]
pub struct ClasspathEntry {
    pub ordinal: u32,
    pub role: ClasspathRole,
    pub path_identity: Sha256Digest,
    pub content_sha256: Sha256Digest,
    pub byte_length: u64,
    pub version: String,
    pub provenance: String,
    pub license_notice: LicenseNoticeStatus,
    pub dependencies: Vec<u32>,
    pub provider: Option<ProviderIdentity>,
}

impl fmt::Debug for ClasspathEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClasspathEntry")
            .field("ordinal", &self.ordinal)
            .field("role", &self.role)
            .field("path_identity", &self.path_identity)
            .field("content_sha256", &self.content_sha256)
            .field("byte_length", &self.byte_length)
            .field("version", &self.version)
            .field("provenance", &"<redacted>")
            .field("license_notice", &self.license_notice)
            .field("dependencies", &self.dependencies)
            .finish()
    }
}

/// Complete ordered classpath identity.
#[derive(Clone, Eq, PartialEq)]
pub struct ClasspathIdentity {
    pub entries: Vec<ClasspathEntry>,
    pub aggregate_sha256: Sha256Digest,
}

impl fmt::Debug for ClasspathIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClasspathIdentity")
            .field("entries", &self.entries)
            .field("aggregate_sha256", &self.aggregate_sha256)
            .finish()
    }
}

/// All identities required before useful JVM work begins.
#[derive(Clone, Eq, PartialEq)]
pub struct CapabilityIdentity {
    pub profile: ProfileIdentity,
    pub jmeter: JmeterIdentity,
    pub jvm: JvmIdentity,
    pub helper: HelperIdentity,
    pub classpath: ClasspathIdentity,
    pub providers: Vec<ProviderIdentity>,
}

impl fmt::Debug for CapabilityIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityIdentity")
            .field("profile", &self.profile)
            .field("jmeter", &self.jmeter)
            .field("jvm", &self.jvm)
            .field("helper", &self.helper)
            .field("classpath", &self.classpath)
            .finish()
    }
}

impl CapabilityIdentity {
    /// Validates the bounded identity tuple before an open request is sent.
    pub fn validate(&self) -> Result<(), JvmCapabilityError> {
        if self.profile.id != JVM_PROFILE_ID
            || self.profile.version != JVM_PROFILE_VERSION
            || self.profile.sha256 != Sha256Digest::from_hex(JVM_PROFILE_SHA256_HEX)?
        {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::InvalidIdentity,
            ));
        }
        if self.jmeter.version != PINNED_JMETER_VERSION
            || self.jmeter.source_commit != PINNED_JMETER_SOURCE_COMMIT
            || self.jmeter.archive_sha512
                != Sha512Digest::from_hex(PINNED_JMETER_ARCHIVE_SHA512_HEX)?
        {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::InvalidIdentity,
            ));
        }
        validate_required_text(&self.jmeter.source_commit, MAX_HASH_TEXT_BYTES)?;
        if self.jvm.major < PINNED_JAVA_MINIMUM_MAJOR {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::InvalidIdentity,
            ));
        }
        for value in [
            &self.jvm.vendor,
            &self.jvm.version,
            &self.jvm.vm,
            &self.jvm.target_triple,
            &self.jvm.os_image,
            &self.helper.compiler,
        ] {
            validate_required_text(value, JVM_CAPABILITY_MAX_TEXT_BYTES)?;
        }
        if self.classpath.entries.len() > JVM_CAPABILITY_MAX_CLASSPATH_ENTRIES {
            return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
        }
        let mut ordinals = BTreeSet::new();
        let mut classpath_bytes = 0_u64;
        for entry in &self.classpath.entries {
            if !ordinals.insert(entry.ordinal) {
                return Err(JvmCapabilityError::new(
                    JvmCapabilityErrorCode::DuplicateIdentity,
                ));
            }
            validate_required_text(&entry.version, JVM_CAPABILITY_MAX_TEXT_BYTES)?;
            validate_text(&entry.provenance, JVM_CAPABILITY_MAX_TEXT_BYTES)?;
            classpath_bytes = classpath_bytes
                .checked_add(entry.byte_length)
                .ok_or_else(|| JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit))?;
            if entry.dependencies.len() > JVM_CAPABILITY_MAX_PLUGIN_ALIASES {
                return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
            }
            if let Some(provider) = &entry.provider {
                validate_provider_identity(provider)?;
            }
        }
        if classpath_bytes > JVM_CAPABILITY_MAX_CLASSPATH_BYTES as u64 {
            return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
        }
        if self.providers.len() > JVM_CAPABILITY_MAX_PLUGIN_ALIASES {
            return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
        }
        for provider in &self.providers {
            validate_provider_identity(provider)?;
        }
        Ok(())
    }

    fn validate_with_limits(&self, limits: &JvmCapabilityLimits) -> Result<(), JvmCapabilityError> {
        self.validate()?;
        if self.classpath.entries.len() > limits.max_classpath_entries {
            return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
        }
        let bytes = self
            .classpath
            .entries
            .iter()
            .try_fold(0_u64, |total, entry| total.checked_add(entry.byte_length))
            .ok_or_else(|| JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit))?;
        if bytes > limits.max_classpath_bytes as u64 {
            return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
        }
        Ok(())
    }
}

fn validate_provider_identity(value: &ProviderIdentity) -> Result<(), JvmCapabilityError> {
    validate_required_text(&value.name, JVM_CAPABILITY_MAX_TEXT_BYTES)?;
    validate_required_text(&value.version, JVM_CAPABILITY_MAX_TEXT_BYTES)?;
    if let Some(service_provider) = &value.service_provider {
        validate_text(service_provider, JVM_CAPABILITY_MAX_TEXT_BYTES)?;
    }
    Ok(())
}

/// Handle-bound root identity.  The actual path is intentionally not part of
/// this schema so credentials and machine-specific paths cannot leak.
#[derive(Clone, Eq, PartialEq)]
pub struct RootIdentity {
    pub kind: String,
    pub identity_sha256: Sha256Digest,
}

impl fmt::Debug for RootIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RootIdentity")
            .field("kind", &self.kind)
            .field("identity_sha256", &self.identity_sha256)
            .finish()
    }
}

/// A source/JMX subtree retained outside executable operations.
#[derive(Clone, Eq, PartialEq)]
pub struct PreservedJmxSource {
    pub node_id: NodeId,
    pub source_sha256: Sha256Digest,
    pub raw_subtree: Vec<u8>,
    pub unknown_fields: Vec<OpaqueField>,
}

impl fmt::Debug for PreservedJmxSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreservedJmxSource")
            .field("node_id", &self.node_id)
            .field("source_sha256", &self.source_sha256)
            .field("raw_subtree_bytes", &self.raw_subtree.len())
            .field("unknown_fields", &self.unknown_fields)
            .finish()
    }
}

impl PreservedJmxSource {
    /// Validates the retained source outside executable operation payloads.
    pub fn validate(&self, limits: &JvmCapabilityLimits) -> Result<(), JvmCapabilityError> {
        if self.raw_subtree.len() > limits.max_result_bytes
            || self.unknown_fields.len() > limits.max_fields
        {
            return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
        }
        for field in &self.unknown_fields {
            if field.tag == 0 || field.tag >= 254 || field.value.len() > limits.max_field_bytes() {
                return Err(JvmCapabilityError::new(
                    JvmCapabilityErrorCode::UnknownField,
                ));
            }
        }
        Ok(())
    }
}

/// Ordered variable/property entry used by a context projection.
#[derive(Clone, Eq, PartialEq)]
pub struct ContextEntry {
    pub key: String,
    pub value: String,
}

impl fmt::Debug for ContextEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContextEntry")
            .field("key", &self.key)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// Typed value that may cross the bounded context projection.
#[derive(Clone, Eq, PartialEq)]
pub enum ContextValue {
    Null,
    Text(String),
    Bytes(Vec<u8>),
    Bool(bool),
    I32(i32),
    I64(i64),
    F64Bits(u64),
    Secret(SecretReference),
    Object(ObjectHandle),
    List(Vec<ContextValue>),
    Map(Vec<ContextBinding>),
}

impl fmt::Debug for ContextValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => formatter.write_str("Null"),
            Self::Text(value) => formatter
                .debug_struct("Text")
                .field("bytes", &value.len())
                .field("value", &"<redacted>")
                .finish(),
            Self::Bytes(value) => formatter
                .debug_struct("Bytes")
                .field("bytes", &value.len())
                .finish(),
            Self::Bool(value) => formatter.debug_tuple("Bool").field(value).finish(),
            Self::I32(value) => formatter.debug_tuple("I32").field(value).finish(),
            Self::I64(value) => formatter.debug_tuple("I64").field(value).finish(),
            Self::F64Bits(_) => formatter.write_str("F64Bits(<redacted>)"),
            Self::Secret(_) => formatter.write_str("Secret(<redacted>)"),
            Self::Object(value) => formatter.debug_tuple("Object").field(value).finish(),
            Self::List(values) => formatter
                .debug_struct("List")
                .field("items", &values.len())
                .finish(),
            Self::Map(values) => formatter
                .debug_struct("Map")
                .field("entries", &values.len())
                .finish(),
        }
    }
}

/// A typed context binding retaining its key and value kind.
#[derive(Clone, Eq, PartialEq)]
pub struct ContextBinding {
    pub key: String,
    pub value: ContextValue,
}

impl fmt::Debug for ContextBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContextBinding")
            .field("key", &self.key)
            .field("value", &self.value)
            .finish()
    }
}

/// Identity fields made available to a JVM invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContextIdentities {
    pub run: RunId,
    pub user: UserId,
    pub thread_group: u64,
    pub thread: u64,
    pub iteration: u64,
    pub sample: u64,
    pub plan: NodeId,
}

/// One bounded assertion projection in a returned result.
#[derive(Clone, Eq, PartialEq)]
pub struct AssertionProjection {
    pub name: String,
    pub failure: bool,
    pub error: bool,
    pub failure_message: String,
}

impl fmt::Debug for AssertionProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AssertionProjection")
            .field("name", &self.name)
            .field("failure", &self.failure)
            .field("error", &self.error)
            .field("failure_message", &"<redacted>")
            .finish()
    }
}

/// A bounded projection of a JMeter sample result.
#[derive(Clone, Eq, PartialEq)]
pub struct SampleResultProjection {
    pub label: String,
    pub url: String,
    pub thread_name: String,
    pub worker_id: u32,
    pub success: bool,
    pub response_code: String,
    pub response_message: String,
    pub result_filename: Option<String>,
    pub sampler_data: Option<String>,
    pub data_type: Option<String>,
    pub data_encoding: Option<String>,
    pub content_type: Option<String>,
    pub location: Option<String>,
    pub timestamp_millis: Option<i64>,
    pub elapsed_millis: i64,
    pub latency_millis: i64,
    pub connect_millis: i64,
    pub idle_millis: Option<i64>,
    pub pause_millis: Option<i64>,
    pub start_millis: i64,
    pub end_millis: i64,
    pub sample_count: u64,
    pub error_count: u64,
    pub received_bytes: u64,
    pub sent_bytes: u64,
    pub header_bytes: u64,
    pub body_bytes: u64,
    pub response_bytes: u64,
    pub request_data: Vec<u8>,
    pub request_headers: String,
    pub response_headers: String,
    pub assertions: Vec<AssertionProjection>,
    pub file_marks: Vec<String>,
    pub group_threads: u64,
    pub all_threads: u64,
    pub stop_thread: bool,
    pub stop_test: bool,
    pub stop_test_now: bool,
    pub ignore: bool,
    pub next_iteration: bool,
    pub break_current_loop: bool,
    pub result_handle: Option<ObjectHandle>,
    pub depth: usize,
    pub node_count: usize,
    pub response_data: Vec<u8>,
}

impl fmt::Debug for SampleResultProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SampleResultProjection")
            .field("label", &"<redacted>")
            .field("url", &"<redacted>")
            .field("thread_name", &"<redacted>")
            .field("worker_id", &self.worker_id)
            .field("success", &self.success)
            .field("response_code", &self.response_code)
            .field("response_message", &"<redacted>")
            .field(
                "result_filename",
                &self.result_filename.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "sampler_data",
                &self.sampler_data.as_ref().map(|_| "<redacted>"),
            )
            .field("data_type", &self.data_type)
            .field("data_encoding", &self.data_encoding)
            .field("content_type", &self.content_type)
            .field("location", &self.location.as_ref().map(|_| "<redacted>"))
            .field("timestamp_millis", &self.timestamp_millis)
            .field("elapsed_millis", &self.elapsed_millis)
            .field("latency_millis", &self.latency_millis)
            .field("connect_millis", &self.connect_millis)
            .field("idle_millis", &self.idle_millis)
            .field("pause_millis", &self.pause_millis)
            .field("start_millis", &self.start_millis)
            .field("end_millis", &self.end_millis)
            .field("sample_count", &self.sample_count)
            .field("error_count", &self.error_count)
            .field("received_bytes", &self.received_bytes)
            .field("sent_bytes", &self.sent_bytes)
            .field("header_bytes", &self.header_bytes)
            .field("body_bytes", &self.body_bytes)
            .field("response_bytes", &self.response_bytes)
            .field("request_data_bytes", &self.request_data.len())
            .field("request_headers", &"<redacted>")
            .field("response_headers", &"<redacted>")
            .field("assertions", &self.assertions)
            .field("file_marks", &self.file_marks.len())
            .field("group_threads", &self.group_threads)
            .field("all_threads", &self.all_threads)
            .field("stop_thread", &self.stop_thread)
            .field("stop_test", &self.stop_test)
            .field("stop_test_now", &self.stop_test_now)
            .field("ignore", &self.ignore)
            .field("next_iteration", &self.next_iteration)
            .field("break_current_loop", &self.break_current_loop)
            .field("result_handle", &self.result_handle)
            .field("depth", &self.depth)
            .field("node_count", &self.node_count)
            .field("response_data_bytes", &self.response_data.len())
            .finish()
    }
}

/// Element-specific arguments and bindings sent to a worker.
#[derive(Clone, Eq, PartialEq)]
pub struct ElementContext {
    pub parameters: Vec<String>,
    pub args: Vec<ContextEntry>,
    pub file_name: Option<String>,
    pub label: String,
}

impl fmt::Debug for ElementContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ElementContext")
            .field("parameters", &"<redacted>")
            .field("args", &self.args)
            .field("file_name", &self.file_name.as_ref().map(|_| "<redacted>"))
            .field("label", &self.label)
            .finish()
    }
}

/// Bounded context projection sent to the helper.
#[derive(Clone, Eq, PartialEq)]
pub struct ContextSnapshot {
    pub identities: ContextIdentities,
    pub generation: ContextGeneration,
    pub user_generation: ContextGeneration,
    pub snapshot_digest: Sha256Digest,
    pub variables: Vec<ContextEntry>,
    pub properties: Vec<ContextEntry>,
    pub typed_variables: Vec<ContextBinding>,
    pub typed_properties: Vec<ContextBinding>,
    pub current_sampler: Option<String>,
    pub current_result: Option<SampleResultProjection>,
    pub previous_result: Option<SampleResultProjection>,
    pub element: ElementContext,
}

impl fmt::Debug for ContextSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContextSnapshot")
            .field("identities", &self.identities)
            .field("generation", &self.generation)
            .field("user_generation", &self.user_generation)
            .field("snapshot_digest", &self.snapshot_digest)
            .field("variables", &self.variables)
            .field("properties", &self.properties)
            .field("typed_variables", &self.typed_variables)
            .field("typed_properties", &self.typed_properties)
            .field(
                "current_sampler",
                &self.current_sampler.as_ref().map(|_| "<redacted>"),
            )
            .field("current_result", &self.current_result)
            .field("previous_result", &self.previous_result)
            .field("element", &self.element)
            .finish()
    }
}

/// A variable/property mutation in a returned context delta.
#[derive(Clone, Eq, PartialEq)]
pub enum ContextMutation {
    Set(ContextEntry),
    Delete(String),
}

/// Typed variable/property mutation retaining non-text Java bindings.
#[derive(Clone, Eq, PartialEq)]
pub enum TypedContextMutation {
    Set(ContextBinding),
    Delete(String),
}

impl fmt::Debug for TypedContextMutation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Set(value) => formatter.debug_tuple("Set").field(value).finish(),
            Self::Delete(value) => formatter.debug_tuple("Delete").field(value).finish(),
        }
    }
}

impl TypedContextMutation {
    fn key(&self) -> &str {
        match self {
            Self::Set(value) => &value.key,
            Self::Delete(value) => value,
        }
    }
}

/// The semantic kind of a returned delta.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum DeltaKind {
    Context = 1,
    Result = 2,
    Setup = 3,
    Teardown = 4,
}

/// Lifecycle outcome of a prepared delta.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DeltaPhase {
    Prepared,
    Committed,
    Aborted,
    Poisoned,
    Terminal,
}

impl ContextMutation {
    fn key(&self) -> &str {
        match self {
            Self::Set(entry) => &entry.key,
            Self::Delete(key) => key,
        }
    }
}

impl fmt::Debug for ContextMutation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Set(entry) => formatter.debug_tuple("Set").field(entry).finish(),
            Self::Delete(key) => formatter.debug_tuple("Delete").field(key).finish(),
        }
    }
}

/// A bounded patch to the current sample result.
#[derive(Clone, Eq, PartialEq)]
pub struct SampleResultPatch {
    pub result: Option<SampleResultProjection>,
    pub sub_results: Vec<SampleResultProjection>,
}

impl fmt::Debug for SampleResultPatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SampleResultPatch")
            .field("result", &self.result)
            .field("sub_results", &self.sub_results)
            .finish()
    }
}

/// A bounded output record emitted through the worker projection.
#[derive(Clone, Eq, PartialEq)]
pub struct OutputRecord {
    pub stream: String,
    pub value: String,
}

impl fmt::Debug for OutputRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutputRecord")
            .field("stream", &self.stream)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// A bounded structured diagnostic returned by a helper.
#[derive(Clone, Eq, PartialEq)]
pub struct DiagnosticRecord {
    pub code: JvmCapabilityErrorCode,
    pub message: String,
}

impl fmt::Debug for DiagnosticRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiagnosticRecord")
            .field("code", &self.code)
            .field("message", &"<redacted>")
            .finish()
    }
}

/// A cache key observed by JMeter's JSR223 implementation.
#[derive(Clone, Eq, PartialEq)]
pub enum ScriptCacheKey {
    StringScript {
        language: String,
        expanded_source_md5: Md5Digest,
        expanded_source_sha256: Sha256Digest,
        cache_key: String,
    },
    FileScript {
        language: String,
        path_identity: Sha256Digest,
        modified_unix_millis: u64,
    },
    None,
}

impl fmt::Debug for ScriptCacheKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StringScript {
                language,
                expanded_source_md5,
                expanded_source_sha256,
                cache_key: _,
            } => formatter
                .debug_struct("StringScript")
                .field("language", language)
                .field("expanded_source_md5", expanded_source_md5)
                .field("expanded_source_sha256", expanded_source_sha256)
                .field("cache_key", &"<redacted>")
                .finish(),
            Self::FileScript {
                language,
                path_identity,
                modified_unix_millis,
            } => formatter
                .debug_struct("FileScript")
                .field("language", language)
                .field("path_identity", path_identity)
                .field("modified_unix_millis", modified_unix_millis)
                .finish(),
            Self::None => formatter.write_str("None"),
        }
    }
}

/// Class-loader/cache epoch.  A key cannot cross an epoch.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CacheEpoch {
    pub epoch: u64,
    pub run_generation: ContextGeneration,
    pub classpath_identity: Sha256Digest,
    pub helper_identity: Sha256Digest,
    pub profile_identity: Sha256Digest,
    pub provider_identity: Sha256Digest,
}

impl CacheEpoch {
    /// Returns whether a cache request belongs to this exact identity epoch.
    pub fn matches(
        self,
        run_generation: ContextGeneration,
        classpath_identity: Sha256Digest,
        helper_identity: Sha256Digest,
        profile_identity: Sha256Digest,
    ) -> bool {
        self.matches_with_provider(
            run_generation,
            classpath_identity,
            helper_identity,
            profile_identity,
            Sha256Digest::ZERO,
        )
    }

    /// Returns whether a cache request belongs to this exact identity epoch,
    /// including the provider manifest identity.
    pub fn matches_with_provider(
        self,
        run_generation: ContextGeneration,
        classpath_identity: Sha256Digest,
        helper_identity: Sha256Digest,
        profile_identity: Sha256Digest,
        provider_identity: Sha256Digest,
    ) -> bool {
        self.run_generation == run_generation
            && self.classpath_identity == classpath_identity
            && self.helper_identity == helper_identity
            && self.profile_identity == profile_identity
            && self.provider_identity == provider_identity
    }
}

/// Cache request semantics, including JMeter's exact inline false switch.
#[derive(Clone, Eq, PartialEq)]
pub struct CacheRequest {
    pub key: ScriptCacheKey,
    pub inline_cache_setting: String,
    pub eligible: bool,
    pub epoch: CacheEpoch,
}

impl CacheRequest {
    /// JMeter's exact case-sensitive inline cache switch.
    pub fn inline_caching_disabled(&self) -> bool {
        self.inline_cache_setting == "false"
    }

    /// Validates the cache identity and bounded setting text.
    pub fn validate(&self, limits: &JvmCapabilityLimits) -> Result<(), JvmCapabilityError> {
        validate_cache_key(&self.key, limits)?;
        validate_text(&self.inline_cache_setting, limits.max_text_bytes)
    }
}

impl fmt::Debug for CacheRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CacheRequest")
            .field("key", &self.key)
            .field("inline_cache_setting", &"<redacted>")
            .field("eligible", &self.eligible)
            .field("epoch", &self.epoch)
            .finish()
    }
}

/// A cache observation returned by a helper.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheObservation {
    pub key: ScriptCacheKey,
    pub epoch: CacheEpoch,
    pub hit: bool,
    pub retained_entries: usize,
}

/// Script source supplied to an operation.  Its Debug implementation only
/// exposes a length and digest, never source text.
#[derive(Clone, Eq, PartialEq)]
pub enum ScriptSource {
    Inline {
        language: String,
        source: String,
    },
    File {
        language: String,
        path_identity: Sha256Digest,
        source: String,
        modified_unix_millis: u64,
    },
}

impl fmt::Debug for ScriptSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inline { language, source } => formatter
                .debug_struct("Inline")
                .field("language", language)
                .field("source_bytes", &source.len())
                .field("source", &"<redacted>")
                .finish(),
            Self::File {
                language,
                path_identity,
                source,
                modified_unix_millis,
            } => formatter
                .debug_struct("File")
                .field("language", language)
                .field("path_identity", path_identity)
                .field("source_bytes", &source.len())
                .field("modified_unix_millis", modified_unix_millis)
                .field("source", &"<redacted>")
                .finish(),
        }
    }
}

/// A plugin artifact descriptor preserving declaration and dependency order.
#[derive(Clone, Eq, PartialEq)]
pub struct PluginArtifact {
    pub ordinal: u32,
    pub role: ClasspathRole,
    pub path_identity: Sha256Digest,
    pub content_sha256: Sha256Digest,
    pub version: String,
    pub license_notice: LicenseNoticeStatus,
    pub dependencies: Vec<u32>,
    pub aliases: Vec<String>,
    pub capabilities: Vec<String>,
}

impl fmt::Debug for PluginArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginArtifact")
            .field("ordinal", &self.ordinal)
            .field("role", &self.role)
            .field("path_identity", &self.path_identity)
            .field("content_sha256", &self.content_sha256)
            .field("version", &self.version)
            .field("license_notice", &self.license_notice)
            .field("dependencies", &self.dependencies)
            .field("aliases", &self.aliases)
            .field("capabilities", &self.capabilities)
            .finish()
    }
}

/// A duplicate alias declaration, with source artifact and declaration order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginAlias {
    pub alias: String,
    pub artifact_ordinal: u32,
    pub declaration_ordinal: u32,
}

/// Explicit resolution result for a plugin alias.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AliasResolution {
    Missing,
    Unique { artifact_ordinal: u32 },
    Ambiguous { candidates: Vec<u32> },
}

/// Alias binding preserving all declarations and their order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AliasBinding {
    pub alias: String,
    pub declarations: Vec<PluginAlias>,
    pub resolution: AliasResolution,
}

/// Result of bounded plugin discovery.
#[derive(Clone, Eq, PartialEq)]
pub struct PluginDiscovery {
    pub artifacts: Vec<PluginArtifact>,
    pub aliases: Vec<AliasBinding>,
    pub declared_order: Vec<u32>,
    pub observed_order: Vec<u32>,
    pub resolution_order: Vec<u32>,
}

impl fmt::Debug for PluginDiscovery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginDiscovery")
            .field("artifacts", &self.artifacts)
            .field("aliases", &self.aliases)
            .field("declared_order", &self.declared_order)
            .field("observed_order", &self.observed_order)
            .field("resolution_order", &self.resolution_order)
            .finish()
    }
}

/// An immutable component identity used by operation payloads.
#[derive(Clone, Eq, PartialEq)]
pub struct ComponentIdentity {
    pub class_name: String,
    pub alias: Option<String>,
    pub gui_class: Option<String>,
}

impl fmt::Debug for ComponentIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ComponentIdentity")
            .field("class_name", &self.class_name)
            .field("alias", &self.alias)
            .field("gui_class", &self.gui_class)
            .finish()
    }
}

/// Java sampler/JUnit mode.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum JunitMode {
    Junit3 = 1,
    Junit4 = 2,
}

impl JunitMode {
    fn from_wire(value: u8) -> Result<Self, JvmCapabilityError> {
        match value {
            1 => Ok(Self::Junit3),
            2 => Ok(Self::Junit4),
            _ => Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::ScriptConfigurationInvalid,
            )),
        }
    }
}

/// Ordered Java sampler argument.
#[derive(Clone, Eq, PartialEq)]
pub struct SamplerArgument {
    pub name: String,
    pub value: String,
}

impl fmt::Debug for SamplerArgument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SamplerArgument")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// Run close reason.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum CloseReason {
    Completed = 1,
    Cancelled = 2,
    Failed = 3,
}

impl CloseReason {
    fn from_wire(value: u8) -> Result<Self, JvmCapabilityError> {
        match value {
            1 => Ok(Self::Completed),
            2 => Ok(Self::Cancelled),
            3 => Ok(Self::Failed),
            _ => Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::InvalidMessage,
            )),
        }
    }
}

/// Request to establish a worker run identity and negotiated limits.
#[derive(Clone, Eq, PartialEq)]
pub struct OpenRun {
    pub identity: CapabilityIdentity,
    pub roots: Vec<RootIdentity>,
    pub locale: String,
    pub timezone: String,
    pub charset: String,
    pub sandbox_identity: Option<Sha256Digest>,
    pub secret_references: Vec<SecretReference>,
}

impl fmt::Debug for OpenRun {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenRun")
            .field("identity", &self.identity)
            .field("roots", &self.roots)
            .field("locale", &self.locale)
            .field("timezone", &self.timezone)
            .field("charset", &self.charset)
            .field("sandbox_identity", &self.sandbox_identity)
            .finish()
    }
}

/// Request to discover plugin artifacts from explicitly declared roots.
#[derive(Clone, Eq, PartialEq)]
pub struct DiscoverPlugins {
    pub roots: Vec<ClasspathRole>,
    pub requested_capabilities: Vec<String>,
}

impl fmt::Debug for DiscoverPlugins {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiscoverPlugins")
            .field("roots", &self.roots)
            .field("requested_capabilities", &self.requested_capabilities)
            .finish()
    }
}

/// Request to expand a built-in or external function.
#[derive(Clone, Eq, PartialEq)]
pub struct ExpandFunction {
    pub function_name: String,
    pub arguments: Vec<String>,
    pub context: ContextSnapshot,
    pub cache_epoch: Option<CacheEpoch>,
}

impl fmt::Debug for ExpandFunction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExpandFunction")
            .field("function_name", &self.function_name)
            .field("arguments", &"<redacted>")
            .field("context", &self.context)
            .field("cache_epoch", &self.cache_epoch)
            .finish()
    }
}

/// Request to execute one JSR223 script invocation.
#[derive(Clone, Eq, PartialEq)]
pub struct ExecuteJsr223 {
    pub source: ScriptSource,
    pub cache: CacheRequest,
    pub context: ContextSnapshot,
}

impl fmt::Debug for ExecuteJsr223 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecuteJsr223")
            .field("source", &self.source)
            .field("cache", &self.cache)
            .field("context", &self.context)
            .finish()
    }
}

/// Request to construct and configure a JavaSamplerClient instance.
#[derive(Clone, Eq, PartialEq)]
pub struct JavaSamplerSetup {
    pub component: ComponentIdentity,
    pub class_name: String,
    pub arguments: Vec<SamplerArgument>,
    pub context: ContextSnapshot,
}

impl fmt::Debug for JavaSamplerSetup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JavaSamplerSetup")
            .field("component", &self.component)
            .field("class_name", &self.class_name)
            .field("arguments", &"<redacted>")
            .field("context", &self.context)
            .finish()
    }
}

/// Request to run an already configured Java sampler instance.
#[derive(Clone, Eq, PartialEq)]
pub struct JavaSamplerRun {
    pub component: ComponentIdentity,
    pub class_name: String,
    pub context: ContextSnapshot,
}

impl fmt::Debug for JavaSamplerRun {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JavaSamplerRun")
            .field("component", &self.component)
            .field("class_name", &self.class_name)
            .field("context", &self.context)
            .finish()
    }
}

/// Request to tear down an already configured Java sampler instance.
#[derive(Clone, Eq, PartialEq)]
pub struct JavaSamplerTeardown {
    pub component: ComponentIdentity,
    pub class_name: String,
    pub context: ContextSnapshot,
}

impl fmt::Debug for JavaSamplerTeardown {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JavaSamplerTeardown")
            .field("component", &self.component)
            .field("class_name", &self.class_name)
            .field("context", &self.context)
            .finish()
    }
}

/// Request to run a JUnit3 or JUnit4 test method.
#[derive(Clone, Eq, PartialEq)]
pub struct JunitRun {
    pub component: ComponentIdentity,
    pub class_name: String,
    pub mode: JunitMode,
    pub method: String,
    pub context: ContextSnapshot,
}

impl fmt::Debug for JunitRun {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JunitRun")
            .field("component", &self.component)
            .field("class_name", &self.class_name)
            .field("mode", &self.mode)
            .field("method", &self.method)
            .field("context", &self.context)
            .finish()
    }
}

/// Request to invoke a plugin-provided element.
#[derive(Clone, Eq, PartialEq)]
pub struct ExecutePluginElement {
    pub component: ComponentIdentity,
    pub artifact_ordinal: u32,
    pub class_name: String,
    pub properties: Vec<ContextEntry>,
    pub context: ContextSnapshot,
}

impl fmt::Debug for ExecutePluginElement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutePluginElement")
            .field("component", &self.component)
            .field("artifact_ordinal", &self.artifact_ordinal)
            .field("class_name", &self.class_name)
            .field("properties", &self.properties)
            .field("context", &self.context)
            .finish()
    }
}

/// Request to expand a plugin-provided function.
#[derive(Clone, Eq, PartialEq)]
pub struct ExpandPluginFunction {
    pub function_name: String,
    pub artifact_ordinal: u32,
    pub arguments: Vec<String>,
    pub context: ContextSnapshot,
}

impl fmt::Debug for ExpandPluginFunction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExpandPluginFunction")
            .field("function_name", &self.function_name)
            .field("artifact_ordinal", &self.artifact_ordinal)
            .field("arguments", &"<redacted>")
            .field("context", &self.context)
            .finish()
    }
}

/// Request to close the run and drain the worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CloseRun {
    pub reason: CloseReason,
    pub final_generation: ContextGeneration,
}

/// Context mutations and observations returned by a JVM invocation.
///
/// Callers validate the base generation and every member before selecting a
/// prepare/commit, abort, or poisoned outcome. This schema does not claim
/// rollback or transactional behavior for an adapter applying the projection.
#[derive(Clone, Eq, PartialEq)]
pub struct ContextDelta {
    pub kind: DeltaKind,
    pub base_generation: ContextGeneration,
    pub base_user_generation: ContextGeneration,
    pub variable_mutations: Vec<ContextMutation>,
    pub property_mutations: Vec<ContextMutation>,
    pub typed_variable_mutations: Vec<TypedContextMutation>,
    pub typed_property_mutations: Vec<TypedContextMutation>,
    pub sample_patch: SampleResultPatch,
    pub output: Vec<OutputRecord>,
    pub diagnostics: Vec<DiagnosticRecord>,
    pub cache_observations: Vec<CacheObservation>,
    pub class_loader_observations: Vec<String>,
    pub after_state_digest: Sha256Digest,
    pub proposal_digest: Sha256Digest,
    pub rollback: RollbackCapability,
}

/// Whether an adapter can safely return to the prior projected state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum RollbackCapability {
    NotExecuted,
    Journaled,
    Unsafe,
}

impl RollbackCapability {
    /// Returns whether the projected adapter state may safely return to the
    /// previous generation.
    pub const fn can_abort_cleanly(self) -> bool {
        matches!(self, Self::NotExecuted | Self::Journaled)
    }
}

/// A validated delta awaiting an explicit adapter decision.
///
/// Preparation validates bounds and generation.  Commit is a separate call;
/// this type intentionally does not promise rollback or transactional
/// semantics if an adapter is interrupted while applying mutations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedContextDelta {
    delta: ContextDelta,
    phase: DeltaPhase,
}

impl PreparedContextDelta {
    /// Returns the current preparation outcome.
    pub const fn phase(&self) -> DeltaPhase {
        self.phase
    }

    /// Returns the base generation selected during preparation.
    pub const fn base_generation(&self) -> ContextGeneration {
        self.delta.base_generation
    }

    /// Returns the validated projection without changing its phase.
    pub const fn delta(&self) -> &ContextDelta {
        &self.delta
    }

    /// Applies the prepared projection to a caller-owned snapshot.
    pub fn commit(&mut self, target: &mut ContextSnapshot) -> Result<(), JvmCapabilityError> {
        if self.phase != DeltaPhase::Prepared {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::TerminalMessage,
            ));
        }
        if target.generation != self.delta.base_generation {
            self.phase = DeltaPhase::Poisoned;
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::StaleContextGeneration,
            ));
        }
        let next_generation = match target.generation.checked_add(1) {
            Some(value) => value,
            None => {
                self.phase = DeltaPhase::Poisoned;
                return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
            }
        };
        apply_mutations(&mut target.variables, &self.delta.variable_mutations);
        apply_mutations(&mut target.properties, &self.delta.property_mutations);
        if let Some(result) = &self.delta.sample_patch.result {
            target.current_result = Some(result.clone());
        }
        target.generation = next_generation;
        self.phase = DeltaPhase::Committed;
        Ok(())
    }

    /// Abandons the prepared projection without applying it.
    pub fn abort(&mut self) -> Result<(), JvmCapabilityError> {
        if self.phase != DeltaPhase::Prepared {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::TerminalMessage,
            ));
        }
        if !self.can_abort_cleanly() {
            self.phase = DeltaPhase::Poisoned;
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::TransactionAbortUnsafe,
            ));
        }
        self.phase = DeltaPhase::Aborted;
        Ok(())
    }

    /// Records an adapter/worker failure after preparation.
    pub fn poison(&mut self) {
        if self.phase == DeltaPhase::Prepared {
            self.phase = DeltaPhase::Poisoned;
        }
    }

    /// Returns an error when an unsafe rollback declaration cannot be aborted.
    pub fn validate_abortability(&self) -> Result<(), JvmCapabilityError> {
        if self.can_abort_cleanly() {
            Ok(())
        } else {
            Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::TransactionAbortUnsafe,
            ))
        }
    }

    /// Marks the prepared outcome terminal after the owning adapter has
    /// drained its operation.  This records state only; it does not execute
    /// or release any JVM resource.
    pub fn terminal(&mut self) {
        self.phase = DeltaPhase::Terminal;
    }

    /// Returns whether the declared rollback capability permits an abort.
    pub const fn can_abort_cleanly(&self) -> bool {
        self.delta.rollback.can_abort_cleanly()
    }
}

impl fmt::Debug for ContextDelta {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContextDelta")
            .field("kind", &self.kind)
            .field("base_generation", &self.base_generation)
            .field("base_user_generation", &self.base_user_generation)
            .field("variable_mutations", &self.variable_mutations)
            .field("property_mutations", &self.property_mutations)
            .field("typed_variable_mutations", &self.typed_variable_mutations)
            .field("typed_property_mutations", &self.typed_property_mutations)
            .field("sample_patch", &self.sample_patch)
            .field("output", &self.output)
            .field("diagnostics", &self.diagnostics)
            .field("cache_observations", &self.cache_observations)
            .field("class_loader_observations", &self.class_loader_observations)
            .field("after_state_digest", &self.after_state_digest)
            .field("proposal_digest", &self.proposal_digest)
            .field("rollback", &self.rollback)
            .finish()
    }
}

impl ContextSnapshot {
    /// Validates a delta and returns an explicit preparation state.
    pub fn prepare_delta(
        &self,
        delta: ContextDelta,
        limits: &JvmCapabilityLimits,
    ) -> Result<PreparedContextDelta, JvmCapabilityError> {
        delta.validate_for(self, limits)?;
        Ok(PreparedContextDelta {
            delta,
            phase: DeltaPhase::Prepared,
        })
    }

    /// Applies a delta through the explicit prepare/commit path.
    ///
    /// This convenience method does not provide rollback or transactional
    /// guarantees; adapters that need an observable abort/poison outcome
    /// should retain [`PreparedContextDelta`] and choose the phase explicitly.
    pub fn apply_delta(
        &self,
        delta: &ContextDelta,
        limits: &JvmCapabilityLimits,
    ) -> Result<Self, JvmCapabilityError> {
        let mut next = self.clone();
        let mut prepared = self.prepare_delta(delta.clone(), limits)?;
        prepared.commit(&mut next)?;
        Ok(next)
    }
}

impl ContextDelta {
    /// Validates the complete delta without mutating the base context.
    pub fn validate_for(
        &self,
        base: &ContextSnapshot,
        limits: &JvmCapabilityLimits,
    ) -> Result<(), JvmCapabilityError> {
        limits.validate()?;
        if self.base_generation != base.generation {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::StaleContextGeneration,
            ));
        }
        if self.base_user_generation != base.user_generation {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::StaleContextGeneration,
            ));
        }
        validate_delta_for_limits(self, limits)
    }
}

/// The closed request operation union.
#[derive(Clone, Eq, PartialEq)]
pub enum JvmOperation {
    OpenRun(OpenRun),
    DiscoverPlugins(DiscoverPlugins),
    ExpandFunction(ExpandFunction),
    ExecuteJsr223(ExecuteJsr223),
    JavaSamplerSetup(JavaSamplerSetup),
    JavaSamplerRun(JavaSamplerRun),
    JavaSamplerTeardown(JavaSamplerTeardown),
    JunitRun(JunitRun),
    ExecutePluginElement(ExecutePluginElement),
    ExpandPluginFunction(ExpandPluginFunction),
    CloseRun(CloseRun),
}

impl JvmOperation {
    /// Returns the operation code for this payload.
    pub const fn code(&self) -> OperationCode {
        match self {
            Self::OpenRun(_) => OperationCode::OpenRun,
            Self::DiscoverPlugins(_) => OperationCode::DiscoverPlugins,
            Self::ExpandFunction(_) => OperationCode::ExpandFunction,
            Self::ExecuteJsr223(_) => OperationCode::ExecuteJsr223,
            Self::JavaSamplerSetup(_) => OperationCode::JavaSamplerSetup,
            Self::JavaSamplerRun(_) => OperationCode::JavaSamplerRun,
            Self::JavaSamplerTeardown(_) => OperationCode::JavaSamplerTeardown,
            Self::JunitRun(_) => OperationCode::JunitRun,
            Self::ExecutePluginElement(_) => OperationCode::ExecutePluginElement,
            Self::ExpandPluginFunction(_) => OperationCode::ExpandPluginFunction,
            Self::CloseRun(_) => OperationCode::CloseRun,
        }
    }
}

impl fmt::Debug for JvmOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OpenRun(value) => formatter.debug_tuple("OpenRun").field(value).finish(),
            Self::DiscoverPlugins(value) => formatter
                .debug_tuple("DiscoverPlugins")
                .field(value)
                .finish(),
            Self::ExpandFunction(value) => formatter
                .debug_tuple("ExpandFunction")
                .field(value)
                .finish(),
            Self::ExecuteJsr223(value) => {
                formatter.debug_tuple("ExecuteJsr223").field(value).finish()
            }
            Self::JavaSamplerSetup(value) => formatter
                .debug_tuple("JavaSamplerSetup")
                .field(value)
                .finish(),
            Self::JavaSamplerRun(value) => formatter
                .debug_tuple("JavaSamplerRun")
                .field(value)
                .finish(),
            Self::JavaSamplerTeardown(value) => formatter
                .debug_tuple("JavaSamplerTeardown")
                .field(value)
                .finish(),
            Self::JunitRun(value) => formatter.debug_tuple("JunitRun").field(value).finish(),
            Self::ExecutePluginElement(value) => formatter
                .debug_tuple("ExecutePluginElement")
                .field(value)
                .finish(),
            Self::ExpandPluginFunction(value) => formatter
                .debug_tuple("ExpandPluginFunction")
                .field(value)
                .finish(),
            Self::CloseRun(value) => formatter.debug_tuple("CloseRun").field(value).finish(),
        }
    }
}

/// A successful operation result returned by a worker.
#[derive(Clone, Eq, PartialEq)]
pub enum JvmOperationResult {
    RunOpened {
        generation: ContextGeneration,
    },
    Plugins(PluginDiscovery),
    FunctionExpanded {
        value: String,
        delta: ContextDelta,
    },
    Jsr223 {
        value: Option<String>,
        delta: ContextDelta,
    },
    JavaSamplerSetup {
        class_loader_generation: u64,
    },
    JavaSamplerRun {
        delta: ContextDelta,
    },
    JavaSamplerTeardown {
        delta: ContextDelta,
    },
    Junit {
        delta: ContextDelta,
    },
    PluginElement {
        delta: ContextDelta,
    },
    PluginFunctionExpanded {
        value: String,
        delta: ContextDelta,
    },
    Closed {
        generation: ContextGeneration,
        cache_entries: usize,
    },
}

impl fmt::Debug for JvmOperationResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RunOpened { generation } => formatter
                .debug_struct("RunOpened")
                .field("generation", generation)
                .finish(),
            Self::Plugins(value) => formatter.debug_tuple("Plugins").field(value).finish(),
            Self::FunctionExpanded { value, delta } => formatter
                .debug_struct("FunctionExpanded")
                .field("value_bytes", &value.len())
                .field("value", &"<redacted>")
                .field("delta", delta)
                .finish(),
            Self::Jsr223 { value, delta } => formatter
                .debug_struct("Jsr223")
                .field("value_bytes", &value.as_ref().map_or(0, String::len))
                .field("value", &"<redacted>")
                .field("delta", delta)
                .finish(),
            Self::JavaSamplerSetup {
                class_loader_generation,
            } => formatter
                .debug_struct("JavaSamplerSetup")
                .field("class_loader_generation", class_loader_generation)
                .finish(),
            Self::JavaSamplerRun { delta } => formatter
                .debug_struct("JavaSamplerRun")
                .field("delta", delta)
                .finish(),
            Self::JavaSamplerTeardown { delta } => formatter
                .debug_struct("JavaSamplerTeardown")
                .field("delta", delta)
                .finish(),
            Self::Junit { delta } => formatter
                .debug_struct("Junit")
                .field("delta", delta)
                .finish(),
            Self::PluginElement { delta } => formatter
                .debug_struct("PluginElement")
                .field("delta", delta)
                .finish(),
            Self::PluginFunctionExpanded { value, delta } => formatter
                .debug_struct("PluginFunctionExpanded")
                .field("value_bytes", &value.len())
                .field("value", &"<redacted>")
                .field("delta", delta)
                .finish(),
            Self::Closed {
                generation,
                cache_entries,
            } => formatter
                .debug_struct("Closed")
                .field("generation", generation)
                .field("cache_entries", cache_entries)
                .finish(),
        }
    }
}

/// A versioned JVM capability request envelope.
#[derive(Clone, Eq, PartialEq)]
pub struct JvmRequest {
    pub schema_version: u16,
    pub phase: JvmOperationPhase,
    pub request_id: RequestId,
    pub run_id: RunId,
    pub plan_node_id: NodeId,
    pub base_context_generation: ContextGeneration,
    pub deadline: Deadline,
    pub remaining_budget: RemainingBudget,
    pub cancellation: Cancellation,
    pub limits: JvmCapabilityLimits,
    pub operation: JvmOperation,
    pub unknown_fields: Vec<OpaqueField>,
}

impl fmt::Debug for JvmRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JvmRequest")
            .field("schema_version", &self.schema_version)
            .field("phase", &self.phase)
            .field("request_id", &self.request_id)
            .field("run_id", &self.run_id)
            .field("plan_node_id", &self.plan_node_id)
            .field("base_context_generation", &self.base_context_generation)
            .field("deadline", &self.deadline)
            .field("remaining_budget", &self.remaining_budget)
            .field("cancellation", &self.cancellation)
            .field("limits", &self.limits)
            .field("operation", &self.operation)
            .field("unknown_fields", &self.unknown_fields)
            .finish()
    }
}

/// A versioned JVM capability response envelope.
#[derive(Clone, Eq, PartialEq)]
pub struct JvmResponse {
    pub schema_version: u16,
    pub phase: JvmOperationPhase,
    pub request_id: RequestId,
    pub run_id: RunId,
    pub plan_node_id: NodeId,
    pub base_context_generation: ContextGeneration,
    pub deadline: Deadline,
    pub remaining_budget: RemainingBudget,
    pub cancellation: Cancellation,
    pub limits: JvmCapabilityLimits,
    pub operation: OperationCode,
    pub result: Result<JvmOperationResult, JvmCapabilityError>,
    pub unknown_fields: Vec<OpaqueField>,
}

impl fmt::Debug for JvmResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JvmResponse")
            .field("schema_version", &self.schema_version)
            .field("phase", &self.phase)
            .field("request_id", &self.request_id)
            .field("run_id", &self.run_id)
            .field("plan_node_id", &self.plan_node_id)
            .field("base_context_generation", &self.base_context_generation)
            .field("deadline", &self.deadline)
            .field("remaining_budget", &self.remaining_budget)
            .field("cancellation", &self.cancellation)
            .field("limits", &self.limits)
            .field("operation", &self.operation)
            .field(
                "result",
                &self
                    .result
                    .as_ref()
                    .map(|_| "<success>")
                    .unwrap_or("<error>"),
            )
            .field("unknown_fields", &self.unknown_fields)
            .finish()
    }
}

/// A strict request/response message union.
// Requests intentionally remain inline so callers can construct messages
// without an allocation-changing Box boundary; the wire codec is bounded and
// owns the larger payload buffers.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Eq, PartialEq)]
pub enum JvmMessage {
    Request(JvmRequest),
    Response(JvmResponse),
    UnknownOperation {
        kind: JvmMessageKind,
        phase: JvmOperationPhase,
        request_id: RequestId,
        run_id: RunId,
        plan_node_id: NodeId,
        base_context_generation: ContextGeneration,
        deadline: Deadline,
        remaining_budget: RemainingBudget,
        cancellation: Cancellation,
        limits: JvmCapabilityLimits,
        operation: UnknownOperation,
        unknown_fields: Vec<OpaqueField>,
    },
}

impl fmt::Debug for JvmMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request(request) => formatter.debug_tuple("Request").field(request).finish(),
            Self::Response(response) => formatter.debug_tuple("Response").field(response).finish(),
            Self::UnknownOperation {
                kind,
                phase,
                operation,
                ..
            } => formatter
                .debug_struct("UnknownOperation")
                .field("kind", kind)
                .field("phase", phase)
                .field("operation", operation)
                .finish(),
        }
    }
}

/// Lifecycle states enforced by [`JvmSession`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum JvmSessionPhase {
    Created,
    Handshaking,
    Ready,
    RunOpen,
    Operations,
    Closing,
    Failed,
    Poisoned,
    Terminal,
}

/// Terminal outcome recorded by an adapter after admission closes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum JvmTerminalOutcome {
    Completed,
    Cancelled,
    DeadlineExceeded,
    Failed,
    Poisoned,
}

/// Pure lifecycle ledger for one JVM worker run.
///
/// The ledger never starts or stops a worker.  It rejects duplicate request
/// IDs, stale context generations, invalid lifecycle order, and replies after
/// terminal state so an adapter can fail closed before applying a Java delta.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JvmSession {
    phase: JvmSessionPhase,
    terminal_outcome: Option<JvmTerminalOutcome>,
    run_id: Option<RunId>,
    generation: ContextGeneration,
    next_cache_epoch: u64,
    operations: usize,
    seen_requests: BTreeSet<RequestId>,
    pending: Vec<PendingRequest>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingRequest {
    request_id: RequestId,
    operation: OperationCode,
    run_id: RunId,
    base_generation: ContextGeneration,
}

impl Default for JvmSession {
    fn default() -> Self {
        Self::new()
    }
}

impl JvmSession {
    /// Creates a new, not-yet-open run ledger.
    pub const fn new() -> Self {
        Self {
            phase: JvmSessionPhase::Created,
            terminal_outcome: None,
            run_id: None,
            generation: 0,
            next_cache_epoch: 1,
            operations: 0,
            seen_requests: BTreeSet::new(),
            pending: Vec::new(),
        }
    }

    /// Returns the current lifecycle phase.
    pub const fn phase(&self) -> JvmSessionPhase {
        self.phase
    }

    /// Returns the terminal outcome recorded by the admission ledger.
    pub const fn terminal_outcome(&self) -> Option<JvmTerminalOutcome> {
        self.terminal_outcome
    }

    /// Returns the current context generation.
    pub const fn generation(&self) -> ContextGeneration {
        self.generation
    }

    /// Returns the active run identity, if opened.
    pub const fn run_id(&self) -> Option<RunId> {
        self.run_id
    }

    /// Returns the next cache epoch and advances it only when requested.
    pub fn allocate_cache_epoch(
        &mut self,
        classpath_identity: Sha256Digest,
        helper_identity: Sha256Digest,
        profile_identity: Sha256Digest,
    ) -> Result<CacheEpoch, JvmCapabilityError> {
        self.allocate_cache_epoch_with_provider(
            classpath_identity,
            helper_identity,
            profile_identity,
            Sha256Digest::ZERO,
        )
    }

    /// Allocates a cache epoch including the provider manifest identity.
    pub fn allocate_cache_epoch_with_provider(
        &mut self,
        classpath_identity: Sha256Digest,
        helper_identity: Sha256Digest,
        profile_identity: Sha256Digest,
        provider_identity: Sha256Digest,
    ) -> Result<CacheEpoch, JvmCapabilityError> {
        if self.phase != JvmSessionPhase::RunOpen && self.phase != JvmSessionPhase::Operations {
            return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::RunNotOpen));
        }
        let epoch = self.next_cache_epoch;
        self.next_cache_epoch = self
            .next_cache_epoch
            .checked_add(1)
            .ok_or_else(|| JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit))?;
        Ok(CacheEpoch {
            epoch,
            run_generation: self.generation,
            classpath_identity,
            helper_identity,
            profile_identity,
            provider_identity,
        })
    }

    /// Validates a request at a caller-supplied monotonic time and records it
    /// as pending.  No clock is read by this pure method.
    pub fn accept_request_at(
        &mut self,
        request: &JvmRequest,
        now_unix_millis: u64,
    ) -> Result<(), JvmCapabilityError> {
        if request.schema_version != JVM_CAPABILITY_SCHEMA_VERSION {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::BridgeProtocolVersion,
            ));
        }
        if request.request_id == 0 {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::InvalidIdentity,
            ));
        }
        request.remaining_budget.validate()?;
        if request.remaining_budget.as_millis().is_none() {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::DeadlineInvalid,
            ));
        }
        if matches!(
            request.phase,
            JvmOperationPhase::Poisoned | JvmOperationPhase::Terminal
        ) {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::TerminalMessage,
            ));
        }
        if self.phase == JvmSessionPhase::Terminal
            || self.phase == JvmSessionPhase::Failed
            || self.phase == JvmSessionPhase::Poisoned
            || self.phase == JvmSessionPhase::Closing
        {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::TerminalMessage,
            ));
        }
        if self.seen_requests.contains(&request.request_id) {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::DuplicateRequestId,
            ));
        }
        if self.pending.len() >= request.limits.max_in_flight {
            return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
        }
        if self.operations >= request.limits.max_operations
            || self.operations >= JVM_CAPABILITY_MAX_OPERATIONS
        {
            return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
        }
        if request.cancellation.is_active() {
            self.phase = JvmSessionPhase::Failed;
            self.terminal_outcome = Some(JvmTerminalOutcome::Cancelled);
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::BridgeCancelled,
            ));
        }
        if request.deadline.is_expired_at(now_unix_millis)
            || request.remaining_budget.is_exhausted()
        {
            self.phase = JvmSessionPhase::Failed;
            self.terminal_outcome = Some(JvmTerminalOutcome::DeadlineExceeded);
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::BridgeDeadlineExceeded,
            ));
        }
        request.limits.validate()?;
        let operation = request.operation.code();
        let phase_allowed = match operation {
            OperationCode::OpenRun => request.phase == JvmOperationPhase::Handshaking,
            OperationCode::CloseRun => request.phase == JvmOperationPhase::Closing,
            _ => matches!(
                request.phase,
                JvmOperationPhase::Ready
                    | JvmOperationPhase::RunOpen
                    | JvmOperationPhase::Prepared
                    | JvmOperationPhase::Executing
                    | JvmOperationPhase::Proposed
                    | JvmOperationPhase::Committing
                    | JvmOperationPhase::Aborting
            ),
        };
        if !phase_allowed {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::BridgeProtocolPhase,
            ));
        }
        match (&self.phase, operation) {
            (JvmSessionPhase::Created, OperationCode::OpenRun) => {
                if request.run_id == 0 {
                    return Err(JvmCapabilityError::new(
                        JvmCapabilityErrorCode::InvalidIdentity,
                    ));
                }
                if request.base_context_generation != 0 {
                    self.phase = JvmSessionPhase::Poisoned;
                    self.terminal_outcome = Some(JvmTerminalOutcome::Poisoned);
                    return Err(JvmCapabilityError::new(
                        JvmCapabilityErrorCode::StaleContextGeneration,
                    ));
                }
                if self.run_id.is_some() {
                    return Err(JvmCapabilityError::new(
                        JvmCapabilityErrorCode::RunAlreadyOpen,
                    ));
                }
                self.run_id = Some(request.run_id);
                self.phase = JvmSessionPhase::Handshaking;
            }
            (JvmSessionPhase::Created, _) => {
                return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::RunNotOpen));
            }
            (JvmSessionPhase::Handshaking, _) => {
                return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::RunNotOpen));
            }
            (_, OperationCode::OpenRun) => {
                return Err(JvmCapabilityError::new(
                    JvmCapabilityErrorCode::RunAlreadyOpen,
                ));
            }
            (_, OperationCode::CloseRun) => {
                if request.base_context_generation != self.generation {
                    self.phase = JvmSessionPhase::Poisoned;
                    self.terminal_outcome = Some(JvmTerminalOutcome::Poisoned);
                    return Err(JvmCapabilityError::new(
                        JvmCapabilityErrorCode::StaleContextGeneration,
                    ));
                }
                self.phase = JvmSessionPhase::Closing;
            }
            (_, _) => {
                if request.run_id != self.run_id.unwrap_or(0) {
                    return Err(JvmCapabilityError::new(
                        JvmCapabilityErrorCode::InvalidIdentity,
                    ));
                }
                if request.base_context_generation != self.generation {
                    self.phase = JvmSessionPhase::Poisoned;
                    self.terminal_outcome = Some(JvmTerminalOutcome::Poisoned);
                    return Err(JvmCapabilityError::new(
                        JvmCapabilityErrorCode::StaleContextGeneration,
                    ));
                }
                self.phase = JvmSessionPhase::Operations;
            }
        }
        self.seen_requests.insert(request.request_id);
        self.pending.push(PendingRequest {
            request_id: request.request_id,
            operation,
            run_id: request.run_id,
            base_generation: request.base_context_generation,
        });
        self.operations += 1;
        Ok(())
    }

    /// Validates a request without a clock check.
    pub fn accept_request(&mut self, request: &JvmRequest) -> Result<(), JvmCapabilityError> {
        self.accept_request_at(request, 0)
    }

    /// Records a response's accepted operation at the ledger level.
    /// Delta contents must additionally be checked with
    /// [`ContextSnapshot::apply_delta`] before the caller mutates runtime state.
    pub fn accept_response(&mut self, response: &JvmResponse) -> Result<(), JvmCapabilityError> {
        if self.phase == JvmSessionPhase::Terminal
            || self.phase == JvmSessionPhase::Failed
            || self.phase == JvmSessionPhase::Poisoned
        {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::TerminalMessage,
            ));
        }
        response.remaining_budget.validate()?;
        let response_phase_allowed = match response.operation {
            OperationCode::OpenRun => response.phase == JvmOperationPhase::Ready,
            OperationCode::CloseRun => response.phase == JvmOperationPhase::Terminal,
            _ => matches!(
                response.phase,
                JvmOperationPhase::Proposed
                    | JvmOperationPhase::RunOpen
                    | JvmOperationPhase::Aborting
                    | JvmOperationPhase::Poisoned
                    | JvmOperationPhase::Terminal
            ),
        };
        if !response_phase_allowed {
            self.phase = JvmSessionPhase::Failed;
            self.terminal_outcome = Some(JvmTerminalOutcome::Failed);
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::BridgeProtocolPhase,
            ));
        }
        let index = self
            .pending
            .iter()
            .position(|pending| pending.request_id == response.request_id)
            .ok_or_else(|| JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeProtocolOrder))?;
        let pending = self.pending.remove(index);
        if pending.operation != response.operation || pending.run_id != response.run_id {
            self.phase = JvmSessionPhase::Failed;
            self.terminal_outcome = Some(JvmTerminalOutcome::Failed);
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::BridgeProtocolOrder,
            ));
        }
        if response.base_context_generation != pending.base_generation {
            self.phase = JvmSessionPhase::Poisoned;
            self.terminal_outcome = Some(JvmTerminalOutcome::Poisoned);
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::StaleContextGeneration,
            ));
        }
        if let Err(error) = &response.result {
            let code = error.code();
            self.fail(code);
            return Err(error.clone());
        }
        if response.phase == JvmOperationPhase::Poisoned {
            self.phase = JvmSessionPhase::Poisoned;
            self.terminal_outcome = Some(JvmTerminalOutcome::Poisoned);
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::BridgeWorkerPoisoned,
            ));
        }
        if let Some(delta) = response_delta(&response.result)
            && delta.base_generation != self.generation
        {
            self.phase = JvmSessionPhase::Poisoned;
            self.terminal_outcome = Some(JvmTerminalOutcome::Poisoned);
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::StaleContextGeneration,
            ));
        }
        if response.operation == OperationCode::CloseRun {
            self.phase = JvmSessionPhase::Terminal;
            self.terminal_outcome = Some(JvmTerminalOutcome::Completed);
        } else if response.operation == OperationCode::OpenRun {
            self.phase = JvmSessionPhase::RunOpen;
        }
        Ok(())
    }

    /// Records a context generation after the adapter has explicitly
    /// committed the corresponding prepared delta.
    pub fn commit_generation(
        &mut self,
        base_generation: ContextGeneration,
    ) -> Result<ContextGeneration, JvmCapabilityError> {
        if self.phase == JvmSessionPhase::Terminal
            || self.phase == JvmSessionPhase::Failed
            || self.phase == JvmSessionPhase::Poisoned
        {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::TerminalMessage,
            ));
        }
        if base_generation != self.generation {
            self.phase = JvmSessionPhase::Poisoned;
            self.terminal_outcome = Some(JvmTerminalOutcome::Poisoned);
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::StaleContextGeneration,
            ));
        }
        self.generation = match self.generation.checked_add(1) {
            Some(value) => value,
            None => {
                self.phase = JvmSessionPhase::Poisoned;
                self.terminal_outcome = Some(JvmTerminalOutcome::Poisoned);
                return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
            }
        };
        Ok(self.generation)
    }

    /// Marks the worker generation terminal after a crash or containment loss.
    pub fn fail(&mut self, code: JvmCapabilityErrorCode) -> JvmCapabilityError {
        self.phase = if matches!(
            code,
            JvmCapabilityErrorCode::AtomicDeltaRejected
                | JvmCapabilityErrorCode::StaleContextGeneration
                | JvmCapabilityErrorCode::BridgeWorkerPoisoned
                | JvmCapabilityErrorCode::TransactionInvalid
                | JvmCapabilityErrorCode::TransactionConflict
                | JvmCapabilityErrorCode::TransactionAbortUnsafe
        ) {
            self.terminal_outcome = Some(JvmTerminalOutcome::Poisoned);
            JvmSessionPhase::Poisoned
        } else {
            self.terminal_outcome = Some(match code {
                JvmCapabilityErrorCode::BridgeCancelled => JvmTerminalOutcome::Cancelled,
                JvmCapabilityErrorCode::BridgeDeadlineExceeded => {
                    JvmTerminalOutcome::DeadlineExceeded
                }
                _ => JvmTerminalOutcome::Failed,
            });
            JvmSessionPhase::Failed
        };
        JvmCapabilityError::new(code)
    }
}

fn response_delta(
    result: &Result<JvmOperationResult, JvmCapabilityError>,
) -> Option<&ContextDelta> {
    match result {
        Ok(JvmOperationResult::FunctionExpanded { delta, .. })
        | Ok(JvmOperationResult::Jsr223 { delta, .. })
        | Ok(JvmOperationResult::JavaSamplerRun { delta })
        | Ok(JvmOperationResult::JavaSamplerTeardown { delta })
        | Ok(JvmOperationResult::Junit { delta })
        | Ok(JvmOperationResult::PluginElement { delta })
        | Ok(JvmOperationResult::PluginFunctionExpanded { delta, .. }) => Some(delta),
        _ => None,
    }
}

/// A bounded provisional codec for `jvm-capability/2` messages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JvmCodec {
    options: JvmCodecOptions,
}

impl Default for JvmCodec {
    fn default() -> Self {
        Self::new(JvmCodecOptions::strict())
    }
}

impl JvmCodec {
    /// Creates a codec after validating its negotiated limits.
    pub const fn new(options: JvmCodecOptions) -> Self {
        Self { options }
    }

    /// Returns the configured options.
    pub const fn options(self) -> JvmCodecOptions {
        self.options
    }

    /// Encodes one complete message.
    pub fn encode(&self, message: &JvmMessage) -> Result<Vec<u8>, JvmCapabilityError> {
        self.options.validate()?;
        let (
            kind,
            phase,
            request_id,
            run_id,
            plan_node_id,
            generation,
            deadline,
            remaining_budget,
            cancellation,
            limits,
            operation_code,
            fields,
            unknown_fields,
            raw_fields,
        ) = match message {
            JvmMessage::Request(request) => {
                if request.schema_version != JVM_CAPABILITY_SCHEMA_VERSION {
                    return Err(JvmCapabilityError::new(
                        JvmCapabilityErrorCode::BridgeProtocolVersion,
                    ));
                }
                let (fields, count) = encode_operation_fields(&request.operation, &request.limits)?;
                (
                    JvmMessageKind::Request,
                    request.phase,
                    request.request_id,
                    request.run_id,
                    request.plan_node_id,
                    request.base_context_generation,
                    request.deadline,
                    request.remaining_budget,
                    request.cancellation,
                    request.limits,
                    request.operation.code() as u16,
                    (fields, count),
                    request.unknown_fields.clone(),
                    None,
                )
            }
            JvmMessage::Response(response) => {
                if response.schema_version != JVM_CAPABILITY_SCHEMA_VERSION {
                    return Err(JvmCapabilityError::new(
                        JvmCapabilityErrorCode::BridgeProtocolVersion,
                    ));
                }
                let (fields, count) =
                    encode_result_fields(response.operation, &response.result, &response.limits)?;
                (
                    JvmMessageKind::Response,
                    response.phase,
                    response.request_id,
                    response.run_id,
                    response.plan_node_id,
                    response.base_context_generation,
                    response.deadline,
                    response.remaining_budget,
                    response.cancellation,
                    response.limits,
                    response.operation as u16,
                    (fields, count),
                    response.unknown_fields.clone(),
                    None,
                )
            }
            JvmMessage::UnknownOperation {
                kind,
                phase,
                request_id,
                run_id,
                plan_node_id,
                base_context_generation,
                deadline,
                remaining_budget,
                cancellation,
                limits,
                operation,
                unknown_fields: _,
            } => {
                if !self.options.preservation.preserve_unknown_operations {
                    return Err(JvmCapabilityError::new(
                        JvmCapabilityErrorCode::UnknownOperation,
                    ));
                }
                let parsed = decode_fields(
                    &operation.body,
                    self.options.limits.max_fields,
                    &self.options.limits,
                )?;
                if required_field(&parsed, 254).is_err() || required_field(&parsed, 255).is_err() {
                    return Err(JvmCapabilityError::new(
                        JvmCapabilityErrorCode::BridgeProtocolOrder,
                    ));
                }
                let opaque = parsed
                    .iter()
                    .filter(|(tag, _)| *tag < 254)
                    .map(|(tag, value)| OpaqueField {
                        tag: *tag,
                        value: value.clone(),
                    })
                    .collect::<Vec<_>>();
                (
                    *kind,
                    *phase,
                    *request_id,
                    *run_id,
                    *plan_node_id,
                    *base_context_generation,
                    *deadline,
                    *remaining_budget,
                    *cancellation,
                    *limits,
                    operation.code,
                    (operation.body.clone(), parsed.len() as u16),
                    opaque,
                    Some(()),
                )
            }
        };
        if request_id == 0 {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::InvalidIdentity,
            ));
        }
        if raw_fields.is_none() && operation_code > MAX_OPERATION_CODE {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::UnknownOperation,
            ));
        }
        if raw_fields.is_none() {
            let operation = OperationCode::from_wire(operation_code)?;
            validate_message_phase(kind, operation, phase)?;
        }
        limits.validate()?;
        remaining_budget.validate()?;
        let fields = if raw_fields.is_some() {
            fields
        } else {
            append_limits_and_unknown(
                fields.0,
                fields.1,
                &limits,
                remaining_budget,
                &unknown_fields,
                self.options,
            )?
        };
        if JVM_CAPABILITY_HEADER_LEN + fields.0.len() > limits.max_message_bytes
            || JVM_CAPABILITY_HEADER_LEN + fields.0.len() > self.options.limits.max_message_bytes
            || fields.0.len() > JVM_CAPABILITY_MAX_MESSAGE_BYTES - JVM_CAPABILITY_HEADER_LEN
        {
            return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
        }
        let mut output = Vec::with_capacity(JVM_CAPABILITY_HEADER_LEN + fields.0.len());
        output.extend_from_slice(&JVM_CAPABILITY_MAGIC);
        output.extend_from_slice(&JVM_CAPABILITY_SCHEMA_VERSION.to_be_bytes());
        output.push(kind as u8);
        let mut flags = 0;
        if !unknown_fields.is_empty() {
            flags |= FLAG_UNKNOWN_FIELDS;
        }
        if matches!(message, JvmMessage::UnknownOperation { .. }) {
            flags |= FLAG_UNKNOWN_OPERATIONS;
        }
        if matches!(
            message,
            JvmMessage::Response(JvmResponse { result: Err(_), .. })
        ) {
            flags |= FLAG_RESPONSE_ERROR;
        }
        output.push(flags);
        output.extend_from_slice(&operation_code.to_be_bytes());
        output.extend_from_slice(&request_id.to_be_bytes());
        output.extend_from_slice(&run_id.to_be_bytes());
        output.extend_from_slice(&plan_node_id.to_be_bytes());
        output.extend_from_slice(&generation.to_be_bytes());
        output.extend_from_slice(&deadline.as_unix_millis().unwrap_or(0).to_be_bytes());
        output.push(cancellation_to_wire(cancellation));
        output.push(phase as u8);
        output.extend_from_slice(&(fields.1).to_be_bytes());
        output.extend_from_slice(&(fields.0.len() as u32).to_be_bytes());
        output.extend_from_slice(&(unknown_fields.len() as u16).to_be_bytes());
        output.extend_from_slice(&0_u32.to_be_bytes());
        output.extend_from_slice(&fields.0);
        Ok(output)
    }

    /// Decodes one complete message and rejects trailing bytes.
    pub fn decode(&self, bytes: &[u8]) -> Result<JvmMessage, JvmCapabilityError> {
        self.options.validate()?;
        if bytes.len() > self.options.limits.max_message_bytes
            || bytes.len() > JVM_CAPABILITY_MAX_MESSAGE_BYTES
        {
            return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
        }
        if bytes.len() < JVM_CAPABILITY_HEADER_LEN {
            return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::Truncated));
        }
        if bytes[..4] != JVM_CAPABILITY_MAGIC {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::BridgeProtocolVersion,
            ));
        }
        let schema = read_u16_at(bytes, 4)?;
        if schema != JVM_CAPABILITY_SCHEMA_VERSION {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::BridgeProtocolVersion,
            ));
        }
        let kind = JvmMessageKind::from_wire(bytes[6])?;
        let flags = bytes[7];
        if flags & !KNOWN_FLAGS != 0 {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::UnknownField,
            ));
        }
        let operation_code = read_u16_at(bytes, 8)?;
        let phase = JvmOperationPhase::from_wire(bytes[51])?;
        let request_id = read_u64_at(bytes, 10)?;
        if request_id == 0 {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::InvalidIdentity,
            ));
        }
        let run_id = read_u64_at(bytes, 18)?;
        let plan_node_id = read_u64_at(bytes, 26)?;
        let generation = read_u64_at(bytes, 34)?;
        let deadline_value = read_u64_at(bytes, 42)?;
        let deadline = if deadline_value == 0 {
            Deadline::NONE
        } else {
            Deadline::at_unix_millis(deadline_value)
        };
        let cancellation = cancellation_from_wire(bytes[50])?;
        if read_u32_at(bytes, 60)? != 0 {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::BridgeProtocolOrder,
            ));
        }
        let field_count = read_u16_at(bytes, 52)? as usize;
        let body_len = read_u32_at(bytes, 54)? as usize;
        let unknown_count = read_u16_at(bytes, 58)? as usize;
        if JVM_CAPABILITY_HEADER_LEN + body_len > self.options.limits.max_message_bytes
            || body_len > JVM_CAPABILITY_MAX_MESSAGE_BYTES - JVM_CAPABILITY_HEADER_LEN
            || field_count > self.options.limits.max_fields
        {
            return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
        }
        if body_len > bytes.len().saturating_sub(JVM_CAPABILITY_HEADER_LEN) {
            return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::Truncated));
        }
        if JVM_CAPABILITY_HEADER_LEN + body_len != bytes.len() {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::TrailingBytes,
            ));
        }
        let fields = decode_fields(
            &bytes[JVM_CAPABILITY_HEADER_LEN..],
            field_count,
            &self.options.limits,
        )?;
        if unknown_count > fields.len() {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::BridgeProtocolOrder,
            ));
        }
        if (unknown_count != 0) != (flags & FLAG_UNKNOWN_FIELDS != 0) {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::BridgeProtocolOrder,
            ));
        }
        let operation = match OperationCode::from_wire(operation_code) {
            Ok(code) => code,
            Err(error) => {
                if !self.options.preservation.preserve_unknown_operations
                    || flags & FLAG_UNKNOWN_OPERATIONS == 0
                {
                    return Err(error);
                }
                let limits = decode_limits(required_field(&fields, 255)?)?;
                limits.validate()?;
                let remaining_budget = decode_budget(required_field(&fields, 254)?)?;
                remaining_budget.validate()?;
                let unknown_fields: Vec<OpaqueField> = fields
                    .iter()
                    .filter(|(tag, _)| *tag < 254)
                    .map(|(tag, value)| OpaqueField {
                        tag: *tag,
                        value: value.clone(),
                    })
                    .collect();
                if unknown_count != unknown_fields.len() {
                    return Err(JvmCapabilityError::new(
                        JvmCapabilityErrorCode::BridgeProtocolOrder,
                    ));
                }
                return Ok(JvmMessage::UnknownOperation {
                    kind,
                    phase,
                    request_id,
                    run_id,
                    plan_node_id,
                    base_context_generation: generation,
                    deadline,
                    remaining_budget,
                    cancellation,
                    limits,
                    operation: UnknownOperation {
                        code: operation_code,
                        body: bytes[JVM_CAPABILITY_HEADER_LEN..].to_vec(),
                    },
                    unknown_fields,
                });
            }
        };
        validate_message_phase(kind, operation, phase)?;
        if flags & FLAG_UNKNOWN_OPERATIONS != 0 {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::UnknownOperation,
            ));
        }
        let limits = decode_limits(required_field(&fields, 255)?)?;
        limits.validate()?;
        let remaining_budget = decode_budget(required_field(&fields, 254)?)?;
        remaining_budget.validate()?;
        if kind == JvmMessageKind::Request {
            let (operation, unknown_fields) =
                decode_operation_fields(operation, &fields, &limits, self.options.preservation)?;
            if unknown_count != unknown_fields.len() {
                return Err(JvmCapabilityError::new(
                    JvmCapabilityErrorCode::BridgeProtocolOrder,
                ));
            }
            Ok(JvmMessage::Request(JvmRequest {
                schema_version: schema,
                phase,
                request_id,
                run_id,
                plan_node_id,
                base_context_generation: generation,
                deadline,
                remaining_budget,
                cancellation,
                limits,
                operation,
                unknown_fields,
            }))
        } else {
            let (result, unknown_fields) = decode_result_fields(
                operation,
                &fields,
                &limits,
                self.options.preservation,
                flags & FLAG_RESPONSE_ERROR != 0,
            )?;
            if unknown_count != unknown_fields.len() {
                return Err(JvmCapabilityError::new(
                    JvmCapabilityErrorCode::BridgeProtocolOrder,
                ));
            }
            Ok(JvmMessage::Response(JvmResponse {
                schema_version: schema,
                phase,
                request_id,
                run_id,
                plan_node_id,
                base_context_generation: generation,
                deadline,
                remaining_budget,
                cancellation,
                limits,
                operation,
                result,
                unknown_fields,
            }))
        }
    }
}

struct WireWriter {
    bytes: Vec<u8>,
}

impl WireWriter {
    fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn i64(&mut self, value: i64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn bool(&mut self, value: bool) {
        self.u8(u8::from(value));
    }

    fn bytes(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    fn blob(&mut self, value: &[u8]) -> Result<(), JvmCapabilityError> {
        let length = u32::try_from(value.len())
            .map_err(|_| JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit))?;
        self.u32(length);
        self.bytes(value);
        Ok(())
    }

    fn string(&mut self, value: &str, limit: usize) -> Result<(), JvmCapabilityError> {
        validate_text(value, limit)?;
        self.blob(value.as_bytes())
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

struct WireReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> WireReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], JvmCapabilityError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or_else(|| JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit))?;
        if end > self.bytes.len() {
            return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::Truncated));
        }
        let value = &self.bytes[self.position..end];
        self.position = end;
        Ok(value)
    }

    fn bytes_exact(&mut self, length: usize) -> Result<&'a [u8], JvmCapabilityError> {
        self.take(length)
    }

    fn u8(&mut self) -> Result<u8, JvmCapabilityError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, JvmCapabilityError> {
        let mut value = [0; 2];
        value.copy_from_slice(self.take(2)?);
        Ok(u16::from_be_bytes(value))
    }

    fn u32(&mut self) -> Result<u32, JvmCapabilityError> {
        let mut value = [0; 4];
        value.copy_from_slice(self.take(4)?);
        Ok(u32::from_be_bytes(value))
    }

    fn u64(&mut self) -> Result<u64, JvmCapabilityError> {
        let mut value = [0; 8];
        value.copy_from_slice(self.take(8)?);
        Ok(u64::from_be_bytes(value))
    }

    fn i64(&mut self) -> Result<i64, JvmCapabilityError> {
        let mut value = [0; 8];
        value.copy_from_slice(self.take(8)?);
        Ok(i64::from_be_bytes(value))
    }

    fn bool(&mut self) -> Result<bool, JvmCapabilityError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::InvalidMessage,
            )),
        }
    }

    fn blob(&mut self, limit: usize) -> Result<Vec<u8>, JvmCapabilityError> {
        let length = self.u32()? as usize;
        if length > limit {
            return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
        }
        Ok(self.take(length)?.to_vec())
    }

    fn string(&mut self, limit: usize) -> Result<String, JvmCapabilityError> {
        let bytes = self.blob(limit)?;
        String::from_utf8(bytes)
            .map_err(|_| JvmCapabilityError::new(JvmCapabilityErrorCode::MalformedUtf8))
    }

    fn finish(self) -> Result<(), JvmCapabilityError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::TrailingBytes,
            ))
        }
    }
}

fn validate_text(value: &str, limit: usize) -> Result<(), JvmCapabilityError> {
    if value.len() > limit || value.len() > JVM_CAPABILITY_MAX_TEXT_BYTES {
        Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit))
    } else {
        Ok(())
    }
}

fn validate_required_text(value: &str, limit: usize) -> Result<(), JvmCapabilityError> {
    if value.is_empty() {
        return Err(JvmCapabilityError::new(
            JvmCapabilityErrorCode::InvalidIdentity,
        ));
    }
    validate_text(value, limit)
}

fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], JvmCapabilityError> {
    if value.len() != N * 2 {
        return Err(JvmCapabilityError::new(
            JvmCapabilityErrorCode::InvalidIdentity,
        ));
    }
    let mut result = [0; N];
    for (index, byte) in result.iter_mut().enumerate() {
        let start = index * 2;
        *byte =
            (hex_digit(value.as_bytes()[start])? << 4) | hex_digit(value.as_bytes()[start + 1])?;
    }
    Ok(result)
}

fn hex_digit(value: u8) -> Result<u8, JvmCapabilityError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(JvmCapabilityError::new(
            JvmCapabilityErrorCode::InvalidIdentity,
        )),
    }
}

fn read_u16_at(bytes: &[u8], start: usize) -> Result<u16, JvmCapabilityError> {
    let end = start
        .checked_add(2)
        .ok_or_else(|| JvmCapabilityError::new(JvmCapabilityErrorCode::Truncated))?;
    let value = bytes
        .get(start..end)
        .ok_or_else(|| JvmCapabilityError::new(JvmCapabilityErrorCode::Truncated))?;
    Ok(u16::from_be_bytes([value[0], value[1]]))
}

fn read_u32_at(bytes: &[u8], start: usize) -> Result<u32, JvmCapabilityError> {
    let end = start
        .checked_add(4)
        .ok_or_else(|| JvmCapabilityError::new(JvmCapabilityErrorCode::Truncated))?;
    let value = bytes
        .get(start..end)
        .ok_or_else(|| JvmCapabilityError::new(JvmCapabilityErrorCode::Truncated))?;
    Ok(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_u64_at(bytes: &[u8], start: usize) -> Result<u64, JvmCapabilityError> {
    let end = start
        .checked_add(8)
        .ok_or_else(|| JvmCapabilityError::new(JvmCapabilityErrorCode::Truncated))?;
    let value = bytes
        .get(start..end)
        .ok_or_else(|| JvmCapabilityError::new(JvmCapabilityErrorCode::Truncated))?;
    Ok(u64::from_be_bytes([
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ]))
}

fn validate_mutations_for_limits(
    values: &[ContextMutation],
    count_limit: usize,
    text_limit: usize,
) -> Result<(), JvmCapabilityError> {
    if values.len() > count_limit {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let mut keys = BTreeSet::new();
    for value in values {
        let key = value.key();
        validate_required_text(key, text_limit)?;
        if !keys.insert(key) {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::AtomicDeltaRejected,
            ));
        }
        if let ContextMutation::Set(entry) = value {
            validate_text(&entry.value, text_limit)?;
        }
    }
    Ok(())
}

fn validate_typed_mutations(
    values: &[TypedContextMutation],
    limits: &JvmCapabilityLimits,
) -> Result<(), JvmCapabilityError> {
    if values.len() > limits.max_variables {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let mut keys = BTreeSet::new();
    for value in values {
        validate_required_text(value.key(), limits.max_text_bytes)?;
        if !keys.insert(value.key()) {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::AtomicDeltaRejected,
            ));
        }
        if let TypedContextMutation::Set(binding) = value {
            validate_context_value(&binding.value, limits, 0, 0)?;
        }
    }
    Ok(())
}

fn apply_mutations(values: &mut Vec<ContextEntry>, mutations: &[ContextMutation]) {
    for mutation in mutations {
        match mutation {
            ContextMutation::Set(entry) => {
                if let Some(existing) = values.iter_mut().find(|value| value.key == entry.key) {
                    existing.value = entry.value.clone();
                } else {
                    values.push(entry.clone());
                }
            }
            ContextMutation::Delete(key) => values.retain(|value| value.key != *key),
        }
    }
}

fn validate_sample_projection(
    value: &SampleResultProjection,
    limits: &JvmCapabilityLimits,
) -> Result<(), JvmCapabilityError> {
    validate_text(&value.label, limits.max_text_bytes)?;
    validate_text(&value.url, limits.max_text_bytes)?;
    validate_text(&value.thread_name, limits.max_text_bytes)?;
    validate_text(&value.response_code, limits.max_text_bytes)?;
    validate_text(&value.response_message, limits.max_text_bytes)?;
    for text in [
        value.result_filename.as_ref(),
        value.sampler_data.as_ref(),
        value.data_type.as_ref(),
        value.data_encoding.as_ref(),
        value.content_type.as_ref(),
        value.location.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        validate_text(text, limits.max_text_bytes)?;
    }
    if value.request_data.len() > limits.max_result_bytes {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    if value.file_marks.len() > limits.max_diagnostics {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    for mark in &value.file_marks {
        validate_text(mark, limits.max_text_bytes)?;
    }
    validate_text(&value.request_headers, limits.max_result_bytes)?;
    validate_text(&value.response_headers, limits.max_result_bytes)?;
    if value.assertions.len() > limits.max_diagnostics {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    for assertion in &value.assertions {
        validate_text(&assertion.name, limits.max_text_bytes)?;
        validate_text(&assertion.failure_message, limits.max_text_bytes)?;
    }
    if value.depth > limits.max_result_depth
        || value.node_count > limits.max_result_nodes
        || value.response_data.len() > limits.max_result_bytes
    {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    Ok(())
}

fn validate_sample_patch(
    value: &SampleResultPatch,
    limits: &JvmCapabilityLimits,
) -> Result<(), JvmCapabilityError> {
    if let Some(result) = &value.result {
        validate_sample_projection(result, limits)?;
    }
    if value.sub_results.len() > limits.max_result_nodes {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    for result in &value.sub_results {
        validate_sample_projection(result, limits)?;
    }
    Ok(())
}

fn validate_context_snapshot(
    value: &ContextSnapshot,
    limits: &JvmCapabilityLimits,
) -> Result<(), JvmCapabilityError> {
    if value.variables.len() > limits.max_variables
        || value.properties.len() > limits.max_properties
        || value.typed_variables.len() > limits.max_variables
        || value.typed_properties.len() > limits.max_properties
        || value.element.parameters.len() > limits.max_variables
        || value.element.args.len() > limits.max_variables
    {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    validate_typed_bindings(&value.typed_variables, limits)?;
    validate_typed_bindings(&value.typed_properties, limits)?;
    for entry in value.variables.iter().chain(value.properties.iter()) {
        validate_required_text(&entry.key, limits.max_text_bytes)?;
        validate_text(&entry.value, limits.max_text_bytes)?;
    }
    if let Some(sampler) = &value.current_sampler {
        validate_text(sampler, limits.max_text_bytes)?;
    }
    for parameter in &value.element.parameters {
        validate_text(parameter, limits.max_text_bytes)?;
    }
    for entry in &value.element.args {
        validate_required_text(&entry.key, limits.max_text_bytes)?;
        validate_text(&entry.value, limits.max_text_bytes)?;
    }
    if let Some(file_name) = &value.element.file_name {
        validate_text(file_name, limits.max_text_bytes)?;
    }
    validate_text(&value.element.label, limits.max_text_bytes)?;
    if let Some(result) = &value.current_result {
        validate_sample_projection(result, limits)?;
    }
    if let Some(result) = &value.previous_result {
        validate_sample_projection(result, limits)?;
    }
    Ok(())
}

fn validate_typed_bindings(
    values: &[ContextBinding],
    limits: &JvmCapabilityLimits,
) -> Result<(), JvmCapabilityError> {
    let mut keys = BTreeSet::new();
    for binding in values {
        validate_required_text(&binding.key, limits.max_text_bytes)?;
        if !keys.insert(&binding.key) {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::DuplicateIdentity,
            ));
        }
        validate_context_value(&binding.value, limits, 0, 0)?;
    }
    Ok(())
}

fn validate_context_value(
    value: &ContextValue,
    limits: &JvmCapabilityLimits,
    depth: usize,
    nodes: usize,
) -> Result<(), JvmCapabilityError> {
    if depth > limits.max_result_depth || nodes >= limits.max_result_nodes {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let nodes = nodes + 1;
    match value {
        ContextValue::Null
        | ContextValue::Bool(_)
        | ContextValue::I32(_)
        | ContextValue::I64(_) => Ok(()),
        ContextValue::Text(value) => validate_text(value, limits.max_text_bytes),
        ContextValue::Bytes(value) => {
            if value.len() > limits.max_result_bytes {
                Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit))
            } else {
                Ok(())
            }
        }
        ContextValue::F64Bits(_) => Ok(()),
        ContextValue::Secret(value) => {
            validate_required_text(&value.purpose, limits.max_text_bytes)?;
            value.expiry.validate()
        }
        ContextValue::Object(value) => value.validate(),
        ContextValue::List(values) => {
            if values.len() > limits.max_result_nodes {
                return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
            }
            for (index, value) in values.iter().enumerate() {
                validate_context_value(value, limits, depth + 1, nodes.saturating_add(index))?;
            }
            Ok(())
        }
        ContextValue::Map(values) => {
            if values.len() > limits.max_result_nodes {
                return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
            }
            let mut keys = BTreeSet::new();
            for (index, binding) in values.iter().enumerate() {
                validate_required_text(&binding.key, limits.max_text_bytes)?;
                if !keys.insert(&binding.key) {
                    return Err(JvmCapabilityError::new(
                        JvmCapabilityErrorCode::DuplicateIdentity,
                    ));
                }
                validate_context_value(
                    &binding.value,
                    limits,
                    depth + 1,
                    nodes.saturating_add(index),
                )?;
            }
            Ok(())
        }
    }
}

fn validate_delta_for_limits(
    value: &ContextDelta,
    limits: &JvmCapabilityLimits,
) -> Result<(), JvmCapabilityError> {
    validate_mutations_for_limits(
        &value.variable_mutations,
        limits.max_variables,
        limits.max_text_bytes,
    )?;
    validate_typed_mutations(&value.typed_variable_mutations, limits)?;
    validate_typed_mutations(&value.typed_property_mutations, limits)?;
    validate_mutations_for_limits(
        &value.property_mutations,
        limits.max_properties,
        limits.max_text_bytes,
    )?;
    validate_sample_patch(&value.sample_patch, limits)?;
    if value.output.len() > limits.max_diagnostics
        || value.diagnostics.len() > limits.max_diagnostics
        || value.cache_observations.len() > limits.max_cache_entries
        || value.class_loader_observations.len() > limits.max_classpath_entries
    {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    for output in &value.output {
        validate_text(&output.stream, limits.max_text_bytes)?;
        validate_text(&output.value, limits.max_text_bytes)?;
    }
    for diagnostic in &value.diagnostics {
        validate_text(&diagnostic.message, limits.max_text_bytes)?;
    }
    for observation in &value.cache_observations {
        validate_cache_observation(observation, limits)?;
    }
    for loader in &value.class_loader_observations {
        validate_text(loader, limits.max_text_bytes)?;
    }
    Ok(())
}

fn validate_cache_key(
    value: &ScriptCacheKey,
    limits: &JvmCapabilityLimits,
) -> Result<(), JvmCapabilityError> {
    match value {
        ScriptCacheKey::StringScript {
            language,
            cache_key,
            ..
        } => {
            validate_text(language, limits.max_text_bytes)?;
            validate_text(cache_key, limits.max_text_bytes)?;
        }
        ScriptCacheKey::FileScript { language, .. } => {
            validate_text(language, limits.max_text_bytes)?;
        }
        ScriptCacheKey::None => {}
    }
    Ok(())
}

fn validate_cache_observation(
    value: &CacheObservation,
    limits: &JvmCapabilityLimits,
) -> Result<(), JvmCapabilityError> {
    validate_cache_key(&value.key, limits)?;
    if value.retained_entries > limits.max_cache_entries {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    Ok(())
}

fn cancellation_to_wire(value: Cancellation) -> u8 {
    match value {
        Cancellation::None => 0,
        Cancellation::Requested => 1,
        Cancellation::Cancelled => 2,
    }
}

fn cancellation_from_wire(value: u8) -> Result<Cancellation, JvmCapabilityError> {
    match value {
        0 => Ok(Cancellation::None),
        1 => Ok(Cancellation::Requested),
        2 => Ok(Cancellation::Cancelled),
        _ => Err(JvmCapabilityError::new(
            JvmCapabilityErrorCode::InvalidMessage,
        )),
    }
}

fn encode_fields(fields: Vec<(u16, Vec<u8>)>) -> Result<(Vec<u8>, u16), JvmCapabilityError> {
    if fields.len() > JVM_CAPABILITY_MAX_FIELDS {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let mut output = Vec::new();
    let mut previous = 0;
    for (tag, value) in fields {
        if tag == 0 || tag <= previous || value.len() > JVM_CAPABILITY_MAX_FIELD_BYTES {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::BridgeProtocolOrder,
            ));
        }
        previous = tag;
        output.extend_from_slice(&tag.to_be_bytes());
        output.extend_from_slice(
            &(u32::try_from(value.len())
                .map_err(|_| JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit))?)
            .to_be_bytes(),
        );
        output.extend_from_slice(&value);
    }
    let count = u16::try_from(previous_field_count(&output)?)
        .map_err(|_| JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit))?;
    Ok((output, count))
}

fn previous_field_count(bytes: &[u8]) -> Result<usize, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let mut count = 0;
    let mut previous = 0;
    while reader.remaining() != 0 {
        let tag = reader.u16()?;
        let length = reader.u32()? as usize;
        if tag == 0 || tag <= previous || length > JVM_CAPABILITY_MAX_FIELD_BYTES {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::BridgeProtocolOrder,
            ));
        }
        previous = tag;
        reader.take(length)?;
        count += 1;
    }
    Ok(count)
}

fn decode_fields(
    bytes: &[u8],
    field_count: usize,
    limits: &JvmCapabilityLimits,
) -> Result<Vec<(u16, Vec<u8>)>, JvmCapabilityError> {
    if field_count > limits.max_fields || field_count > JVM_CAPABILITY_MAX_FIELDS {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let mut reader = WireReader::new(bytes);
    let mut fields = Vec::with_capacity(field_count);
    let mut previous = 0;
    for _ in 0..field_count {
        let tag = reader.u16()?;
        let length = reader.u32()? as usize;
        if tag == 0 || tag <= previous || length > JVM_CAPABILITY_MAX_FIELD_BYTES {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::BridgeProtocolOrder,
            ));
        }
        previous = tag;
        fields.push((tag, reader.take(length)?.to_vec()));
    }
    reader.finish()?;
    Ok(fields)
}

fn encode_limits(value: &JvmCapabilityLimits) -> Vec<u8> {
    let values = [
        value.max_message_bytes,
        value.max_fields,
        value.max_text_bytes,
        value.max_operations,
        value.max_in_flight,
        value.max_variables,
        value.max_properties,
        value.max_result_depth,
        value.max_result_nodes,
        value.max_result_bytes,
        value.max_script_source_bytes,
        value.max_script_output_bytes,
        value.max_classpath_entries,
        value.max_classpath_bytes,
        value.max_plugin_artifacts,
        value.max_plugin_aliases,
        value.max_plugin_dependencies,
        value.max_diagnostics,
        value.max_stdout_bytes,
        value.max_stderr_bytes,
        value.max_cache_entries,
    ];
    let mut writer = WireWriter::new();
    for current in values {
        writer.u64(current as u64);
    }
    writer.u64(value.max_shutdown_millis);
    writer.finish()
}

fn encode_budget(value: RemainingBudget) -> Vec<u8> {
    match value.as_millis() {
        Some(millis) => {
            let mut bytes = vec![1];
            bytes.extend_from_slice(&millis.to_be_bytes());
            bytes
        }
        None => vec![0],
    }
}

fn decode_budget(bytes: &[u8]) -> Result<RemainingBudget, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let value = match reader.u8()? {
        0 => RemainingBudget::UNBOUNDED,
        1 => RemainingBudget::from_millis(reader.u64()?),
        _ => {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::DeadlineInvalid,
            ));
        }
    };
    reader.finish()?;
    Ok(value)
}

fn decode_limits(bytes: &[u8]) -> Result<JvmCapabilityLimits, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let mut values = [0_u64; 22];
    for value in &mut values {
        *value = reader.u64()?;
    }
    reader.finish()?;
    let to_usize = |value: u64| {
        usize::try_from(value)
            .map_err(|_| JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit))
    };
    Ok(JvmCapabilityLimits {
        max_message_bytes: to_usize(values[0])?,
        max_fields: to_usize(values[1])?,
        max_text_bytes: to_usize(values[2])?,
        max_operations: to_usize(values[3])?,
        max_in_flight: to_usize(values[4])?,
        max_variables: to_usize(values[5])?,
        max_properties: to_usize(values[6])?,
        max_result_depth: to_usize(values[7])?,
        max_result_nodes: to_usize(values[8])?,
        max_result_bytes: to_usize(values[9])?,
        max_script_source_bytes: to_usize(values[10])?,
        max_script_output_bytes: to_usize(values[11])?,
        max_classpath_entries: to_usize(values[12])?,
        max_classpath_bytes: to_usize(values[13])?,
        max_plugin_artifacts: to_usize(values[14])?,
        max_plugin_aliases: to_usize(values[15])?,
        max_plugin_dependencies: to_usize(values[16])?,
        max_diagnostics: to_usize(values[17])?,
        max_stdout_bytes: to_usize(values[18])?,
        max_stderr_bytes: to_usize(values[19])?,
        max_cache_entries: to_usize(values[20])?,
        max_shutdown_millis: values[21],
    })
}

fn append_limits_and_unknown(
    body: Vec<u8>,
    field_count: u16,
    limits: &JvmCapabilityLimits,
    budget: RemainingBudget,
    unknown_fields: &[OpaqueField],
    options: JvmCodecOptions,
) -> Result<(Vec<u8>, u16), JvmCapabilityError> {
    let mut fields = decode_fields(&body, field_count as usize, &options.limits)?;
    if fields
        .len()
        .saturating_add(unknown_fields.len())
        .saturating_add(2)
        > options.limits.max_fields
    {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let mut previous = fields.last().map_or(0, |field| field.0);
    let mut seen = BTreeSet::new();
    for field in unknown_fields {
        if !options.preservation.preserve_unknown_fields
            || field.tag == 0
            || field.tag <= previous
            || field.tag >= 254
            || field.value.len() > JVM_CAPABILITY_MAX_FIELD_BYTES
            || !seen.insert(field.tag)
        {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::UnknownField,
            ));
        }
        previous = field.tag;
        fields.push((field.tag, field.value.clone()));
    }
    fields.push((254, encode_budget(budget)));
    fields.push((255, encode_limits(limits)));
    encode_fields(fields)
}

fn required_field(fields: &[(u16, Vec<u8>)], tag: u16) -> Result<&[u8], JvmCapabilityError> {
    fields
        .iter()
        .find(|field| field.0 == tag)
        .map(|field| field.1.as_slice())
        .ok_or_else(|| JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeProtocolOrder))
}

fn check_known_fields(
    fields: &[(u16, Vec<u8>)],
    known: &[u16],
    options: JvmPreservationNegotiation,
) -> Result<Vec<OpaqueField>, JvmCapabilityError> {
    let known: BTreeSet<u16> = known.iter().copied().collect();
    let mut unknown = Vec::new();
    for (tag, value) in fields {
        if !known.contains(tag) {
            if !options.preserve_unknown_fields {
                return Err(JvmCapabilityError::new(
                    JvmCapabilityErrorCode::UnknownField,
                ));
            }
            unknown.push(OpaqueField {
                tag: *tag,
                value: value.clone(),
            });
        }
    }
    Ok(unknown)
}

fn encode_string_list(values: &[String], limit: usize) -> Result<Vec<u8>, JvmCapabilityError> {
    if values.len() > limit || values.len() > u16::MAX as usize {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let mut writer = WireWriter::new();
    writer.u16(values.len() as u16);
    for value in values {
        writer.string(value, JVM_CAPABILITY_MAX_TEXT_BYTES)?;
    }
    Ok(writer.finish())
}

fn decode_string_list(bytes: &[u8], limit: usize) -> Result<Vec<String>, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let count = reader.u16()? as usize;
    if count > limit {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(reader.string(JVM_CAPABILITY_MAX_TEXT_BYTES)?);
    }
    reader.finish()?;
    Ok(values)
}

fn encode_u32_list(values: &[u32], limit: usize) -> Result<Vec<u8>, JvmCapabilityError> {
    if values.len() > limit || values.len() > u16::MAX as usize {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let mut writer = WireWriter::new();
    writer.u16(values.len() as u16);
    for value in values {
        writer.u32(*value);
    }
    Ok(writer.finish())
}

fn decode_u32_list(bytes: &[u8], limit: usize) -> Result<Vec<u32>, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let count = reader.u16()? as usize;
    if count > limit {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(reader.u32()?);
    }
    reader.finish()?;
    Ok(values)
}

fn encode_context_entry(value: &ContextEntry) -> Result<Vec<u8>, JvmCapabilityError> {
    let mut writer = WireWriter::new();
    validate_required_text(&value.key, JVM_CAPABILITY_MAX_TEXT_BYTES)?;
    writer.string(&value.key, JVM_CAPABILITY_MAX_TEXT_BYTES)?;
    writer.string(&value.value, JVM_CAPABILITY_MAX_TEXT_BYTES)?;
    Ok(writer.finish())
}

fn decode_context_entry(bytes: &[u8]) -> Result<ContextEntry, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let value = ContextEntry {
        key: reader.string(JVM_CAPABILITY_MAX_TEXT_BYTES)?,
        value: reader.string(JVM_CAPABILITY_MAX_TEXT_BYTES)?,
    };
    reader.finish()?;
    Ok(value)
}

fn encode_context_entries(
    values: &[ContextEntry],
    limit: usize,
) -> Result<Vec<u8>, JvmCapabilityError> {
    if values.len() > limit || values.len() > u16::MAX as usize {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let mut writer = WireWriter::new();
    writer.u16(values.len() as u16);
    for value in values {
        writer.blob(&encode_context_entry(value)?)?;
    }
    Ok(writer.finish())
}

fn decode_context_entries(
    bytes: &[u8],
    limit: usize,
) -> Result<Vec<ContextEntry>, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let count = reader.u16()? as usize;
    if count > limit {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(decode_context_entry(
            &reader.blob(JVM_CAPABILITY_MAX_FIELD_BYTES)?,
        )?);
    }
    reader.finish()?;
    Ok(values)
}

fn encode_context_value(
    value: &ContextValue,
    limits: &JvmCapabilityLimits,
) -> Result<Vec<u8>, JvmCapabilityError> {
    validate_context_value(value, limits, 0, 0)?;
    let mut writer = WireWriter::new();
    match value {
        ContextValue::Null => writer.u8(0),
        ContextValue::Text(value) => {
            writer.u8(1);
            writer.string(value, limits.max_text_bytes)?;
        }
        ContextValue::Bytes(value) => {
            writer.u8(2);
            writer.blob(value)?;
        }
        ContextValue::Bool(value) => {
            writer.u8(3);
            writer.bool(*value);
        }
        ContextValue::I32(value) => {
            writer.u8(4);
            writer.bytes(&value.to_be_bytes());
        }
        ContextValue::I64(value) => {
            writer.u8(5);
            writer.i64(*value);
        }
        ContextValue::F64Bits(value) => {
            writer.u8(6);
            writer.u64(*value);
        }
        ContextValue::Secret(value) => {
            writer.u8(7);
            writer.blob(&encode_secret_references(std::slice::from_ref(value))?)?;
        }
        ContextValue::Object(value) => {
            writer.u8(8);
            writer.blob(&encode_object_handle(&Some(*value))?)?;
        }
        ContextValue::List(values) => {
            writer.u8(9);
            if values.len() > u16::MAX as usize {
                return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
            }
            writer.u16(values.len() as u16);
            for value in values {
                writer.blob(&encode_context_value(value, limits)?)?;
            }
        }
        ContextValue::Map(values) => {
            writer.u8(10);
            if values.len() > u16::MAX as usize {
                return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
            }
            writer.u16(values.len() as u16);
            for value in values {
                writer.string(&value.key, limits.max_text_bytes)?;
                writer.blob(&encode_context_value(&value.value, limits)?)?;
            }
        }
    }
    Ok(writer.finish())
}

fn decode_context_value(
    bytes: &[u8],
    limits: &JvmCapabilityLimits,
) -> Result<ContextValue, JvmCapabilityError> {
    decode_context_value_at(bytes, limits, 0, 0)
}

fn decode_context_value_at(
    bytes: &[u8],
    limits: &JvmCapabilityLimits,
    depth: usize,
    nodes: usize,
) -> Result<ContextValue, JvmCapabilityError> {
    if depth > limits.max_result_depth || nodes >= limits.max_result_nodes {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let next_nodes = nodes.saturating_add(1);
    let mut reader = WireReader::new(bytes);
    let value = match reader.u8()? {
        0 => ContextValue::Null,
        1 => ContextValue::Text(reader.string(limits.max_text_bytes)?),
        2 => ContextValue::Bytes(reader.blob(limits.max_result_bytes)?),
        3 => ContextValue::Bool(reader.bool()?),
        4 => {
            let mut raw = [0; 4];
            raw.copy_from_slice(reader.bytes_exact(4)?);
            ContextValue::I32(i32::from_be_bytes(raw))
        }
        5 => ContextValue::I64(reader.i64()?),
        6 => ContextValue::F64Bits(reader.u64()?),
        7 => {
            let values = decode_secret_references(&reader.blob(JVM_CAPABILITY_MAX_FIELD_BYTES)?)?;
            let value = values
                .into_iter()
                .next()
                .ok_or_else(|| JvmCapabilityError::new(JvmCapabilityErrorCode::SecretDenied))?;
            ContextValue::Secret(value)
        }
        8 => ContextValue::Object(
            decode_object_handle(&reader.blob(JVM_CAPABILITY_MAX_FIELD_BYTES)?)?
                .ok_or_else(|| JvmCapabilityError::new(JvmCapabilityErrorCode::HandleInvalid))?,
        ),
        9 => {
            let count = reader.u16()? as usize;
            if count > limits.max_result_nodes {
                return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
            }
            let mut values = Vec::with_capacity(count);
            for (index, _) in (0..count).enumerate() {
                values.push(decode_context_value_at(
                    &reader.blob(limits.max_result_bytes)?,
                    limits,
                    depth + 1,
                    next_nodes.saturating_add(index),
                )?);
            }
            ContextValue::List(values)
        }
        10 => {
            let count = reader.u16()? as usize;
            if count > limits.max_result_nodes {
                return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
            }
            let mut values = Vec::with_capacity(count);
            let mut keys = BTreeSet::new();
            for (index, _) in (0..count).enumerate() {
                let key = reader.string(limits.max_text_bytes)?;
                if !keys.insert(key.clone()) {
                    return Err(JvmCapabilityError::new(
                        JvmCapabilityErrorCode::DuplicateIdentity,
                    ));
                }
                let value = decode_context_value_at(
                    &reader.blob(limits.max_result_bytes)?,
                    limits,
                    depth + 1,
                    next_nodes.saturating_add(index),
                )?;
                values.push(ContextBinding { key, value });
            }
            ContextValue::Map(values)
        }
        _ => {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::ScriptValueTypeUnsupported,
            ));
        }
    };
    reader.finish()?;
    validate_context_value(&value, limits, depth, nodes)?;
    Ok(value)
}

fn encode_context_bindings(
    values: &[ContextBinding],
    limits: &JvmCapabilityLimits,
) -> Result<Vec<u8>, JvmCapabilityError> {
    validate_typed_bindings(values, limits)?;
    if values.len() > u16::MAX as usize {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let mut writer = WireWriter::new();
    writer.u16(values.len() as u16);
    for value in values {
        writer.string(&value.key, limits.max_text_bytes)?;
        writer.blob(&encode_context_value(&value.value, limits)?)?;
    }
    Ok(writer.finish())
}

fn decode_context_bindings(
    bytes: &[u8],
    limits: &JvmCapabilityLimits,
) -> Result<Vec<ContextBinding>, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let count = reader.u16()? as usize;
    if count > limits.max_variables {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let mut values = Vec::with_capacity(count);
    let mut keys = BTreeSet::new();
    for _ in 0..count {
        let key = reader.string(limits.max_text_bytes)?;
        if !keys.insert(key.clone()) {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::DuplicateIdentity,
            ));
        }
        let value = decode_context_value(&reader.blob(limits.max_result_bytes)?, limits)?;
        values.push(ContextBinding { key, value });
    }
    reader.finish()?;
    validate_typed_bindings(&values, limits)?;
    Ok(values)
}

fn encode_mutation(value: &ContextMutation) -> Result<Vec<u8>, JvmCapabilityError> {
    let mut writer = WireWriter::new();
    match value {
        ContextMutation::Set(entry) => {
            writer.u8(1);
            writer.blob(&encode_context_entry(entry)?)?;
        }
        ContextMutation::Delete(key) => {
            writer.u8(2);
            writer.string(key, JVM_CAPABILITY_MAX_TEXT_BYTES)?;
        }
    }
    Ok(writer.finish())
}

fn decode_mutation(bytes: &[u8]) -> Result<ContextMutation, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let mutation = match reader.u8()? {
        1 => ContextMutation::Set(decode_context_entry(
            &reader.blob(JVM_CAPABILITY_MAX_FIELD_BYTES)?,
        )?),
        2 => ContextMutation::Delete(reader.string(JVM_CAPABILITY_MAX_TEXT_BYTES)?),
        _ => {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::InvalidMessage,
            ));
        }
    };
    reader.finish()?;
    Ok(mutation)
}

fn encode_mutations(
    values: &[ContextMutation],
    limit: usize,
) -> Result<Vec<u8>, JvmCapabilityError> {
    if values.len() > limit || values.len() > u16::MAX as usize {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let mut writer = WireWriter::new();
    writer.u16(values.len() as u16);
    for value in values {
        writer.blob(&encode_mutation(value)?)?;
    }
    Ok(writer.finish())
}

fn decode_mutations(
    bytes: &[u8],
    limit: usize,
) -> Result<Vec<ContextMutation>, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let count = reader.u16()? as usize;
    if count > limit {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(decode_mutation(
            &reader.blob(JVM_CAPABILITY_MAX_FIELD_BYTES)?,
        )?);
    }
    reader.finish()?;
    Ok(values)
}

fn encode_typed_mutation(
    value: &TypedContextMutation,
    limits: &JvmCapabilityLimits,
) -> Result<Vec<u8>, JvmCapabilityError> {
    let mut writer = WireWriter::new();
    match value {
        TypedContextMutation::Set(binding) => {
            writer.u8(1);
            writer.string(&binding.key, limits.max_text_bytes)?;
            writer.blob(&encode_context_value(&binding.value, limits)?)?;
        }
        TypedContextMutation::Delete(key) => {
            writer.u8(2);
            writer.string(key, limits.max_text_bytes)?;
        }
    }
    Ok(writer.finish())
}

fn decode_typed_mutation(
    bytes: &[u8],
    limits: &JvmCapabilityLimits,
) -> Result<TypedContextMutation, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let value = match reader.u8()? {
        1 => TypedContextMutation::Set(ContextBinding {
            key: reader.string(limits.max_text_bytes)?,
            value: decode_context_value(&reader.blob(limits.max_result_bytes)?, limits)?,
        }),
        2 => TypedContextMutation::Delete(reader.string(limits.max_text_bytes)?),
        _ => {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::ScriptValueTypeUnsupported,
            ));
        }
    };
    reader.finish()?;
    Ok(value)
}

fn encode_typed_mutations(
    values: &[TypedContextMutation],
    limits: &JvmCapabilityLimits,
) -> Result<Vec<u8>, JvmCapabilityError> {
    validate_typed_mutations(values, limits)?;
    if values.len() > u16::MAX as usize {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let mut writer = WireWriter::new();
    writer.u16(values.len() as u16);
    for value in values {
        writer.blob(&encode_typed_mutation(value, limits)?)?;
    }
    Ok(writer.finish())
}

fn decode_typed_mutations(
    bytes: &[u8],
    limits: &JvmCapabilityLimits,
) -> Result<Vec<TypedContextMutation>, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let count = reader.u16()? as usize;
    if count > limits.max_variables {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(decode_typed_mutation(
            &reader.blob(limits.max_result_bytes)?,
            limits,
        )?);
    }
    reader.finish()?;
    validate_typed_mutations(&values, limits)?;
    Ok(values)
}

fn encode_sample_projection(
    value: &SampleResultProjection,
    limits: &JvmCapabilityLimits,
) -> Result<Vec<u8>, JvmCapabilityError> {
    if value.depth > limits.max_result_depth
        || value.node_count > limits.max_result_nodes
        || value.response_data.len() > limits.max_result_bytes
    {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let mut writer = WireWriter::new();
    writer.string(&value.label, limits.max_text_bytes)?;
    writer.string(&value.url, limits.max_text_bytes)?;
    writer.string(&value.thread_name, limits.max_text_bytes)?;
    writer.u32(value.worker_id);
    writer.bool(value.success);
    writer.string(&value.response_code, limits.max_text_bytes)?;
    writer.string(&value.response_message, limits.max_text_bytes)?;
    writer.blob(&encode_optional_text(
        &value.result_filename,
        limits.max_text_bytes,
    )?)?;
    writer.blob(&encode_optional_text(
        &value.sampler_data,
        limits.max_text_bytes,
    )?)?;
    writer.blob(&encode_optional_text(
        &value.data_type,
        limits.max_text_bytes,
    )?)?;
    writer.blob(&encode_optional_text(
        &value.data_encoding,
        limits.max_text_bytes,
    )?)?;
    writer.blob(&encode_optional_text(
        &value.content_type,
        limits.max_text_bytes,
    )?)?;
    writer.blob(&encode_optional_text(
        &value.location,
        limits.max_text_bytes,
    )?)?;
    writer.blob(&encode_optional_i64(value.timestamp_millis))?;
    writer.i64(value.elapsed_millis);
    writer.i64(value.latency_millis);
    writer.i64(value.connect_millis);
    writer.blob(&encode_optional_i64(value.idle_millis))?;
    writer.blob(&encode_optional_i64(value.pause_millis))?;
    writer.i64(value.start_millis);
    writer.i64(value.end_millis);
    writer.u64(value.sample_count);
    writer.u64(value.error_count);
    writer.u64(value.received_bytes);
    writer.u64(value.sent_bytes);
    writer.u64(value.header_bytes);
    writer.u64(value.body_bytes);
    writer.u64(value.response_bytes);
    writer.blob(&value.request_data)?;
    writer.string(&value.request_headers, limits.max_result_bytes)?;
    writer.string(&value.response_headers, limits.max_result_bytes)?;
    if value.assertions.len() > limits.max_diagnostics || value.assertions.len() > u16::MAX as usize
    {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    writer.u16(value.assertions.len() as u16);
    for assertion in &value.assertions {
        writer.string(&assertion.name, limits.max_text_bytes)?;
        writer.bool(assertion.failure);
        writer.bool(assertion.error);
        writer.string(&assertion.failure_message, limits.max_text_bytes)?;
    }
    writer.blob(&encode_string_list(
        &value.file_marks,
        limits.max_diagnostics,
    )?)?;
    writer.u64(value.group_threads);
    writer.u64(value.all_threads);
    writer.bool(value.stop_thread);
    writer.bool(value.stop_test);
    writer.bool(value.stop_test_now);
    writer.bool(value.ignore);
    writer.bool(value.next_iteration);
    writer.bool(value.break_current_loop);
    writer.blob(&encode_object_handle(&value.result_handle)?)?;
    writer.u16(
        u16::try_from(value.depth)
            .map_err(|_| JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit))?,
    );
    writer.u32(
        u32::try_from(value.node_count)
            .map_err(|_| JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit))?,
    );
    writer.blob(&value.response_data)?;
    Ok(writer.finish())
}

fn decode_sample_projection(
    bytes: &[u8],
    limits: &JvmCapabilityLimits,
) -> Result<SampleResultProjection, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let value = SampleResultProjection {
        label: reader.string(limits.max_text_bytes)?,
        url: reader.string(limits.max_text_bytes)?,
        thread_name: reader.string(limits.max_text_bytes)?,
        worker_id: reader.u32()?,
        success: reader.bool()?,
        response_code: reader.string(limits.max_text_bytes)?,
        response_message: reader.string(limits.max_text_bytes)?,
        result_filename: decode_optional_text(
            &reader.blob(limits.max_result_bytes)?,
            limits.max_text_bytes,
        )?,
        sampler_data: decode_optional_text(
            &reader.blob(limits.max_result_bytes)?,
            limits.max_text_bytes,
        )?,
        data_type: decode_optional_text(
            &reader.blob(limits.max_result_bytes)?,
            limits.max_text_bytes,
        )?,
        data_encoding: decode_optional_text(
            &reader.blob(limits.max_result_bytes)?,
            limits.max_text_bytes,
        )?,
        content_type: decode_optional_text(
            &reader.blob(limits.max_result_bytes)?,
            limits.max_text_bytes,
        )?,
        location: decode_optional_text(
            &reader.blob(limits.max_result_bytes)?,
            limits.max_text_bytes,
        )?,
        timestamp_millis: decode_optional_i64(&reader.blob(limits.max_result_bytes)?)?,
        elapsed_millis: reader.i64()?,
        latency_millis: reader.i64()?,
        connect_millis: reader.i64()?,
        idle_millis: decode_optional_i64(&reader.blob(limits.max_result_bytes)?)?,
        pause_millis: decode_optional_i64(&reader.blob(limits.max_result_bytes)?)?,
        start_millis: reader.i64()?,
        end_millis: reader.i64()?,
        sample_count: reader.u64()?,
        error_count: reader.u64()?,
        received_bytes: reader.u64()?,
        sent_bytes: reader.u64()?,
        header_bytes: reader.u64()?,
        body_bytes: reader.u64()?,
        response_bytes: reader.u64()?,
        request_data: reader.blob(limits.max_result_bytes)?,
        request_headers: reader.string(limits.max_result_bytes)?,
        response_headers: reader.string(limits.max_result_bytes)?,
        assertions: {
            let count = reader.u16()? as usize;
            if count > limits.max_diagnostics {
                return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
            }
            let mut values = Vec::with_capacity(count);
            for _ in 0..count {
                values.push(AssertionProjection {
                    name: reader.string(limits.max_text_bytes)?,
                    failure: reader.bool()?,
                    error: reader.bool()?,
                    failure_message: reader.string(limits.max_text_bytes)?,
                });
            }
            values
        },
        file_marks: decode_string_list(
            &reader.blob(limits.max_result_bytes)?,
            limits.max_diagnostics,
        )?,
        group_threads: reader.u64()?,
        all_threads: reader.u64()?,
        stop_thread: reader.bool()?,
        stop_test: reader.bool()?,
        stop_test_now: reader.bool()?,
        ignore: reader.bool()?,
        next_iteration: reader.bool()?,
        break_current_loop: reader.bool()?,
        result_handle: decode_object_handle(&reader.blob(limits.max_result_bytes)?)?,
        depth: reader.u16()? as usize,
        node_count: reader.u32()? as usize,
        response_data: reader.blob(limits.max_result_bytes)?,
    };
    if value.depth > limits.max_result_depth || value.node_count > limits.max_result_nodes {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    reader.finish()?;
    Ok(value)
}

fn encode_optional_projection(
    value: &Option<SampleResultProjection>,
    limits: &JvmCapabilityLimits,
) -> Result<Vec<u8>, JvmCapabilityError> {
    let mut writer = WireWriter::new();
    match value {
        Some(value) => {
            writer.bool(true);
            writer.blob(&encode_sample_projection(value, limits)?)?;
        }
        None => writer.bool(false),
    }
    Ok(writer.finish())
}

fn decode_optional_projection(
    bytes: &[u8],
    limits: &JvmCapabilityLimits,
) -> Result<Option<SampleResultProjection>, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let value = if reader.bool()? {
        Some(decode_sample_projection(
            &reader.blob(limits.max_result_bytes)?,
            limits,
        )?)
    } else {
        None
    };
    reader.finish()?;
    Ok(value)
}

fn encode_element_context(
    value: &ElementContext,
    limits: &JvmCapabilityLimits,
) -> Result<Vec<u8>, JvmCapabilityError> {
    if value.parameters.len() > limits.max_variables {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let mut writer = WireWriter::new();
    writer.blob(&encode_string_list(
        &value.parameters,
        limits.max_variables,
    )?)?;
    writer.blob(&encode_context_entries(&value.args, limits.max_variables)?)?;
    match &value.file_name {
        Some(file_name) => {
            writer.bool(true);
            writer.string(file_name, limits.max_text_bytes)?;
        }
        None => writer.bool(false),
    }
    writer.string(&value.label, limits.max_text_bytes)?;
    Ok(writer.finish())
}

fn decode_element_context(
    bytes: &[u8],
    limits: &JvmCapabilityLimits,
) -> Result<ElementContext, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let parameters =
        decode_string_list(&reader.blob(limits.max_result_bytes)?, limits.max_variables)?;
    let args =
        decode_context_entries(&reader.blob(limits.max_result_bytes)?, limits.max_variables)?;
    let file_name = if reader.bool()? {
        Some(reader.string(limits.max_text_bytes)?)
    } else {
        None
    };
    let label = reader.string(limits.max_text_bytes)?;
    reader.finish()?;
    Ok(ElementContext {
        parameters,
        args,
        file_name,
        label,
    })
}

fn encode_context_snapshot(
    value: &ContextSnapshot,
    limits: &JvmCapabilityLimits,
) -> Result<Vec<u8>, JvmCapabilityError> {
    validate_context_snapshot(value, limits)?;
    if value.variables.len() > limits.max_variables
        || value.properties.len() > limits.max_properties
    {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let mut writer = WireWriter::new();
    writer.u64(value.identities.run);
    writer.u64(value.identities.user);
    writer.u64(value.identities.thread_group);
    writer.u64(value.identities.thread);
    writer.u64(value.identities.iteration);
    writer.u64(value.identities.sample);
    writer.u64(value.identities.plan);
    writer.u64(value.generation);
    writer.u64(value.user_generation);
    value.snapshot_digest.encode_into(&mut writer);
    writer.blob(&encode_context_entries(
        &value.variables,
        limits.max_variables,
    )?)?;
    writer.blob(&encode_context_entries(
        &value.properties,
        limits.max_properties,
    )?)?;
    writer.blob(&encode_context_bindings(&value.typed_variables, limits)?)?;
    writer.blob(&encode_context_bindings(&value.typed_properties, limits)?)?;
    match &value.current_sampler {
        Some(sampler) => {
            writer.bool(true);
            writer.string(sampler, limits.max_text_bytes)?;
        }
        None => writer.bool(false),
    }
    writer.blob(&encode_optional_projection(&value.current_result, limits)?)?;
    writer.blob(&encode_optional_projection(&value.previous_result, limits)?)?;
    writer.blob(&encode_element_context(&value.element, limits)?)?;
    Ok(writer.finish())
}

fn decode_context_snapshot(
    bytes: &[u8],
    limits: &JvmCapabilityLimits,
) -> Result<ContextSnapshot, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let identities = ContextIdentities {
        run: reader.u64()?,
        user: reader.u64()?,
        thread_group: reader.u64()?,
        thread: reader.u64()?,
        iteration: reader.u64()?,
        sample: reader.u64()?,
        plan: reader.u64()?,
    };
    let generation = reader.u64()?;
    let user_generation = reader.u64()?;
    let snapshot_digest = Sha256Digest::decode(&mut reader)?;
    let variables =
        decode_context_entries(&reader.blob(limits.max_result_bytes)?, limits.max_variables)?;
    let properties = decode_context_entries(
        &reader.blob(limits.max_result_bytes)?,
        limits.max_properties,
    )?;
    let typed_variables = decode_context_bindings(&reader.blob(limits.max_result_bytes)?, limits)?;
    let typed_properties = decode_context_bindings(&reader.blob(limits.max_result_bytes)?, limits)?;
    let current_sampler = if reader.bool()? {
        Some(reader.string(limits.max_text_bytes)?)
    } else {
        None
    };
    let current_result =
        decode_optional_projection(&reader.blob(limits.max_result_bytes)?, limits)?;
    let previous_result =
        decode_optional_projection(&reader.blob(limits.max_result_bytes)?, limits)?;
    let element = decode_element_context(&reader.blob(limits.max_result_bytes)?, limits)?;
    reader.finish()?;
    let value = ContextSnapshot {
        identities,
        generation,
        user_generation,
        snapshot_digest,
        variables,
        properties,
        typed_variables,
        typed_properties,
        current_sampler,
        current_result,
        previous_result,
        element,
    };
    validate_context_snapshot(&value, limits)?;
    Ok(value)
}

fn encode_sample_patch(
    value: &SampleResultPatch,
    limits: &JvmCapabilityLimits,
) -> Result<Vec<u8>, JvmCapabilityError> {
    if value.sub_results.len() > limits.max_result_nodes {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let mut writer = WireWriter::new();
    writer.blob(&encode_optional_projection(&value.result, limits)?)?;
    if value.sub_results.len() > u32::MAX as usize {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    writer.u32(value.sub_results.len() as u32);
    for result in &value.sub_results {
        writer.blob(&encode_sample_projection(result, limits)?)?;
    }
    Ok(writer.finish())
}

fn decode_sample_patch(
    bytes: &[u8],
    limits: &JvmCapabilityLimits,
) -> Result<SampleResultPatch, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let result = decode_optional_projection(&reader.blob(limits.max_result_bytes)?, limits)?;
    let count = reader.u32()? as usize;
    if count > limits.max_result_nodes {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let mut sub_results = Vec::with_capacity(count);
    for _ in 0..count {
        sub_results.push(decode_sample_projection(
            &reader.blob(limits.max_result_bytes)?,
            limits,
        )?);
    }
    reader.finish()?;
    Ok(SampleResultPatch {
        result,
        sub_results,
    })
}

fn encode_output_records(
    values: &[OutputRecord],
    limits: &JvmCapabilityLimits,
) -> Result<Vec<u8>, JvmCapabilityError> {
    if values.len() > limits.max_diagnostics || values.len() > u16::MAX as usize {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let mut writer = WireWriter::new();
    writer.u16(values.len() as u16);
    for value in values {
        writer.string(&value.stream, limits.max_text_bytes)?;
        writer.string(&value.value, limits.max_text_bytes)?;
    }
    Ok(writer.finish())
}

fn decode_output_records(
    bytes: &[u8],
    limits: &JvmCapabilityLimits,
) -> Result<Vec<OutputRecord>, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let count = reader.u16()? as usize;
    if count > limits.max_diagnostics {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(OutputRecord {
            stream: reader.string(limits.max_text_bytes)?,
            value: reader.string(limits.max_text_bytes)?,
        });
    }
    reader.finish()?;
    Ok(values)
}

fn encode_diagnostics(
    values: &[DiagnosticRecord],
    limits: &JvmCapabilityLimits,
) -> Result<Vec<u8>, JvmCapabilityError> {
    if values.len() > limits.max_diagnostics || values.len() > u16::MAX as usize {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let mut writer = WireWriter::new();
    writer.u16(values.len() as u16);
    for value in values {
        writer.u16(value.code as u16);
        writer.string(&value.message, limits.max_text_bytes)?;
    }
    Ok(writer.finish())
}

fn decode_diagnostics(
    bytes: &[u8],
    limits: &JvmCapabilityLimits,
) -> Result<Vec<DiagnosticRecord>, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let count = reader.u16()? as usize;
    if count > limits.max_diagnostics {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        let code = decode_error_code(reader.u16()?)?;
        values.push(DiagnosticRecord {
            code,
            message: reader.string(limits.max_text_bytes)?,
        });
    }
    reader.finish()?;
    Ok(values)
}

fn encode_cache_epoch(value: &CacheEpoch, writer: &mut WireWriter) {
    writer.u64(value.epoch);
    writer.u64(value.run_generation);
    value.classpath_identity.encode_into(writer);
    value.helper_identity.encode_into(writer);
    value.profile_identity.encode_into(writer);
    value.provider_identity.encode_into(writer);
}

fn decode_cache_epoch(reader: &mut WireReader<'_>) -> Result<CacheEpoch, JvmCapabilityError> {
    Ok(CacheEpoch {
        epoch: reader.u64()?,
        run_generation: reader.u64()?,
        classpath_identity: Sha256Digest::decode(reader)?,
        helper_identity: Sha256Digest::decode(reader)?,
        profile_identity: Sha256Digest::decode(reader)?,
        provider_identity: Sha256Digest::decode(reader)?,
    })
}

fn encode_cache_key(value: &ScriptCacheKey) -> Result<Vec<u8>, JvmCapabilityError> {
    let mut writer = WireWriter::new();
    match value {
        ScriptCacheKey::StringScript {
            language,
            expanded_source_md5,
            expanded_source_sha256,
            cache_key,
        } => {
            writer.u8(1);
            writer.string(language, JVM_CAPABILITY_MAX_TEXT_BYTES)?;
            expanded_source_md5.encode_into(&mut writer);
            expanded_source_sha256.encode_into(&mut writer);
            writer.string(cache_key, JVM_CAPABILITY_MAX_TEXT_BYTES)?;
        }
        ScriptCacheKey::FileScript {
            language,
            path_identity,
            modified_unix_millis,
        } => {
            writer.u8(2);
            writer.string(language, JVM_CAPABILITY_MAX_TEXT_BYTES)?;
            path_identity.encode_into(&mut writer);
            writer.u64(*modified_unix_millis);
        }
        ScriptCacheKey::None => writer.u8(0),
    }
    Ok(writer.finish())
}

fn decode_cache_key(bytes: &[u8]) -> Result<ScriptCacheKey, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let key = match reader.u8()? {
        0 => ScriptCacheKey::None,
        1 => ScriptCacheKey::StringScript {
            language: reader.string(JVM_CAPABILITY_MAX_TEXT_BYTES)?,
            expanded_source_md5: Md5Digest::decode(&mut reader)?,
            expanded_source_sha256: Sha256Digest::decode(&mut reader)?,
            cache_key: reader.string(JVM_CAPABILITY_MAX_TEXT_BYTES)?,
        },
        2 => ScriptCacheKey::FileScript {
            language: reader.string(JVM_CAPABILITY_MAX_TEXT_BYTES)?,
            path_identity: Sha256Digest::decode(&mut reader)?,
            modified_unix_millis: reader.u64()?,
        },
        _ => {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::CacheIdentityInvalid,
            ));
        }
    };
    reader.finish()?;
    Ok(key)
}

fn encode_cache_request(
    value: &CacheRequest,
    limits: &JvmCapabilityLimits,
) -> Result<Vec<u8>, JvmCapabilityError> {
    value.validate(limits)?;
    let mut writer = WireWriter::new();
    writer.blob(&encode_cache_key(&value.key)?)?;
    writer.string(&value.inline_cache_setting, JVM_CAPABILITY_MAX_TEXT_BYTES)?;
    writer.bool(value.eligible);
    encode_cache_epoch(&value.epoch, &mut writer);
    Ok(writer.finish())
}

fn decode_cache_request(
    bytes: &[u8],
    limits: &JvmCapabilityLimits,
) -> Result<CacheRequest, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let key = decode_cache_key(&reader.blob(JVM_CAPABILITY_MAX_FIELD_BYTES)?)?;
    let inline_cache_setting = reader.string(JVM_CAPABILITY_MAX_TEXT_BYTES)?;
    let eligible = reader.bool()?;
    let epoch = decode_cache_epoch(&mut reader)?;
    reader.finish()?;
    let value = CacheRequest {
        key,
        inline_cache_setting,
        eligible,
        epoch,
    };
    value.validate(limits)?;
    Ok(value)
}

fn encode_cache_observations(
    values: &[CacheObservation],
    limits: &JvmCapabilityLimits,
) -> Result<Vec<u8>, JvmCapabilityError> {
    if values.len() > limits.max_cache_entries || values.len() > u16::MAX as usize {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let mut writer = WireWriter::new();
    writer.u16(values.len() as u16);
    for value in values {
        writer.blob(&encode_cache_key(&value.key)?)?;
        encode_cache_epoch(&value.epoch, &mut writer);
        writer.bool(value.hit);
        writer.u32(
            u32::try_from(value.retained_entries)
                .map_err(|_| JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit))?,
        );
    }
    Ok(writer.finish())
}

fn decode_cache_observations(
    bytes: &[u8],
    limits: &JvmCapabilityLimits,
) -> Result<Vec<CacheObservation>, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let count = reader.u16()? as usize;
    if count > limits.max_cache_entries {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(CacheObservation {
            key: decode_cache_key(&reader.blob(JVM_CAPABILITY_MAX_FIELD_BYTES)?)?,
            epoch: decode_cache_epoch(&mut reader)?,
            hit: reader.bool()?,
            retained_entries: reader.u32()? as usize,
        });
    }
    reader.finish()?;
    Ok(values)
}

fn encode_context_delta(
    value: &ContextDelta,
    limits: &JvmCapabilityLimits,
) -> Result<Vec<u8>, JvmCapabilityError> {
    validate_delta_for_limits(value, limits)?;
    let mut writer = WireWriter::new();
    writer.u8(value.kind as u8);
    writer.u64(value.base_generation);
    writer.u64(value.base_user_generation);
    writer.blob(&encode_mutations(
        &value.variable_mutations,
        limits.max_variables,
    )?)?;
    writer.blob(&encode_mutations(
        &value.property_mutations,
        limits.max_properties,
    )?)?;
    writer.blob(&encode_typed_mutations(
        &value.typed_variable_mutations,
        limits,
    )?)?;
    writer.blob(&encode_typed_mutations(
        &value.typed_property_mutations,
        limits,
    )?)?;
    writer.blob(&encode_sample_patch(&value.sample_patch, limits)?)?;
    writer.blob(&encode_output_records(&value.output, limits)?)?;
    writer.blob(&encode_diagnostics(&value.diagnostics, limits)?)?;
    writer.blob(&encode_cache_observations(
        &value.cache_observations,
        limits,
    )?)?;
    writer.blob(&encode_string_list(
        &value.class_loader_observations,
        limits.max_classpath_entries,
    )?)?;
    value.after_state_digest.encode_into(&mut writer);
    value.proposal_digest.encode_into(&mut writer);
    writer.u8(value.rollback as u8);
    Ok(writer.finish())
}

fn decode_context_delta(
    bytes: &[u8],
    limits: &JvmCapabilityLimits,
) -> Result<ContextDelta, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let value = ContextDelta {
        kind: decode_delta_kind(reader.u8()?)?,
        base_generation: reader.u64()?,
        base_user_generation: reader.u64()?,
        variable_mutations: decode_mutations(
            &reader.blob(limits.max_result_bytes)?,
            limits.max_variables,
        )?,
        property_mutations: decode_mutations(
            &reader.blob(limits.max_result_bytes)?,
            limits.max_properties,
        )?,
        typed_variable_mutations: decode_typed_mutations(
            &reader.blob(limits.max_result_bytes)?,
            limits,
        )?,
        typed_property_mutations: decode_typed_mutations(
            &reader.blob(limits.max_result_bytes)?,
            limits,
        )?,
        sample_patch: decode_sample_patch(&reader.blob(limits.max_result_bytes)?, limits)?,
        output: decode_output_records(&reader.blob(limits.max_result_bytes)?, limits)?,
        diagnostics: decode_diagnostics(&reader.blob(limits.max_result_bytes)?, limits)?,
        cache_observations: decode_cache_observations(
            &reader.blob(limits.max_result_bytes)?,
            limits,
        )?,
        class_loader_observations: decode_string_list(
            &reader.blob(limits.max_result_bytes)?,
            limits.max_classpath_entries,
        )?,
        after_state_digest: Sha256Digest::decode(&mut reader)?,
        proposal_digest: Sha256Digest::decode(&mut reader)?,
        rollback: decode_rollback_capability(reader.u8()?)?,
    };
    reader.finish()?;
    validate_delta_for_limits(&value, limits)?;
    Ok(value)
}

fn encode_script_source(
    value: &ScriptSource,
    limits: &JvmCapabilityLimits,
) -> Result<Vec<u8>, JvmCapabilityError> {
    let mut writer = WireWriter::new();
    match value {
        ScriptSource::Inline { language, source } => {
            writer.u8(1);
            writer.string(language, limits.max_text_bytes)?;
            if source.len() > limits.max_script_source_bytes {
                return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
            }
            writer.string(source, limits.max_script_source_bytes)?;
        }
        ScriptSource::File {
            language,
            path_identity,
            source,
            modified_unix_millis,
        } => {
            writer.u8(2);
            writer.string(language, limits.max_text_bytes)?;
            path_identity.encode_into(&mut writer);
            if source.len() > limits.max_script_source_bytes {
                return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
            }
            writer.string(source, limits.max_script_source_bytes)?;
            writer.u64(*modified_unix_millis);
        }
    }
    Ok(writer.finish())
}

fn decode_script_source(
    bytes: &[u8],
    limits: &JvmCapabilityLimits,
) -> Result<ScriptSource, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let source = match reader.u8()? {
        1 => ScriptSource::Inline {
            language: reader.string(limits.max_text_bytes)?,
            source: reader.string(limits.max_script_source_bytes)?,
        },
        2 => ScriptSource::File {
            language: reader.string(limits.max_text_bytes)?,
            path_identity: Sha256Digest::decode(&mut reader)?,
            source: reader.string(limits.max_script_source_bytes)?,
            modified_unix_millis: reader.u64()?,
        },
        _ => {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::ScriptSourceUnavailable,
            ));
        }
    };
    reader.finish()?;
    Ok(source)
}

fn encode_profile_identity(value: &ProfileIdentity) -> Result<Vec<u8>, JvmCapabilityError> {
    let mut writer = WireWriter::new();
    writer.string(&value.id, JVM_CAPABILITY_MAX_TEXT_BYTES)?;
    writer.u32(value.version);
    value.sha256.encode_into(&mut writer);
    Ok(writer.finish())
}

fn decode_profile_identity(bytes: &[u8]) -> Result<ProfileIdentity, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let value = ProfileIdentity {
        id: reader.string(JVM_CAPABILITY_MAX_TEXT_BYTES)?,
        version: reader.u32()?,
        sha256: Sha256Digest::decode(&mut reader)?,
    };
    reader.finish()?;
    Ok(value)
}

fn encode_jmeter_identity(value: &JmeterIdentity) -> Result<Vec<u8>, JvmCapabilityError> {
    let mut writer = WireWriter::new();
    writer.string(&value.version, JVM_CAPABILITY_MAX_TEXT_BYTES)?;
    writer.string(&value.source_commit, MAX_HASH_TEXT_BYTES)?;
    value.archive_sha512.encode_into(&mut writer);
    writer.bool(value.signature_verified);
    Ok(writer.finish())
}

fn decode_jmeter_identity(bytes: &[u8]) -> Result<JmeterIdentity, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let value = JmeterIdentity {
        version: reader.string(JVM_CAPABILITY_MAX_TEXT_BYTES)?,
        source_commit: reader.string(MAX_HASH_TEXT_BYTES)?,
        archive_sha512: Sha512Digest::decode(&mut reader)?,
        signature_verified: reader.bool()?,
    };
    reader.finish()?;
    Ok(value)
}

fn encode_jvm_identity(value: &JvmIdentity) -> Result<Vec<u8>, JvmCapabilityError> {
    let mut writer = WireWriter::new();
    value.executable_sha256.encode_into(&mut writer);
    writer.string(&value.vendor, JVM_CAPABILITY_MAX_TEXT_BYTES)?;
    writer.string(&value.version, JVM_CAPABILITY_MAX_TEXT_BYTES)?;
    writer.string(&value.vm, JVM_CAPABILITY_MAX_TEXT_BYTES)?;
    writer.u16(value.major);
    writer.string(&value.target_triple, MAX_HASH_TEXT_BYTES)?;
    writer.string(&value.os_image, JVM_CAPABILITY_MAX_TEXT_BYTES)?;
    Ok(writer.finish())
}

fn decode_jvm_identity(bytes: &[u8]) -> Result<JvmIdentity, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let value = JvmIdentity {
        executable_sha256: Sha256Digest::decode(&mut reader)?,
        vendor: reader.string(JVM_CAPABILITY_MAX_TEXT_BYTES)?,
        version: reader.string(JVM_CAPABILITY_MAX_TEXT_BYTES)?,
        vm: reader.string(JVM_CAPABILITY_MAX_TEXT_BYTES)?,
        major: reader.u16()?,
        target_triple: reader.string(MAX_HASH_TEXT_BYTES)?,
        os_image: reader.string(JVM_CAPABILITY_MAX_TEXT_BYTES)?,
    };
    reader.finish()?;
    Ok(value)
}

fn encode_helper_identity(value: &HelperIdentity) -> Result<Vec<u8>, JvmCapabilityError> {
    let mut writer = WireWriter::new();
    value.source_sha256.encode_into(&mut writer);
    value.build_sha256.encode_into(&mut writer);
    writer.string(&value.compiler, JVM_CAPABILITY_MAX_TEXT_BYTES)?;
    value.operation_schema_sha256.encode_into(&mut writer);
    Ok(writer.finish())
}

fn decode_helper_identity(bytes: &[u8]) -> Result<HelperIdentity, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let value = HelperIdentity {
        source_sha256: Sha256Digest::decode(&mut reader)?,
        build_sha256: Sha256Digest::decode(&mut reader)?,
        compiler: reader.string(JVM_CAPABILITY_MAX_TEXT_BYTES)?,
        operation_schema_sha256: Sha256Digest::decode(&mut reader)?,
    };
    reader.finish()?;
    Ok(value)
}

fn encode_provider_identity(value: &ProviderIdentity) -> Result<Vec<u8>, JvmCapabilityError> {
    let mut writer = WireWriter::new();
    writer.string(&value.name, JVM_CAPABILITY_MAX_TEXT_BYTES)?;
    writer.string(&value.version, JVM_CAPABILITY_MAX_TEXT_BYTES)?;
    value.artifact_sha256.encode_into(&mut writer);
    writer.blob(&optional_digest(&value.service_descriptor_sha256))?;
    match &value.service_provider {
        Some(provider) => {
            writer.bool(true);
            writer.string(provider, JVM_CAPABILITY_MAX_TEXT_BYTES)?;
        }
        None => writer.bool(false),
    }
    Ok(writer.finish())
}

fn decode_provider_identity(bytes: &[u8]) -> Result<ProviderIdentity, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let value = ProviderIdentity {
        name: reader.string(JVM_CAPABILITY_MAX_TEXT_BYTES)?,
        version: reader.string(JVM_CAPABILITY_MAX_TEXT_BYTES)?,
        artifact_sha256: Sha256Digest::decode(&mut reader)?,
        service_descriptor_sha256: decode_optional_digest(
            &reader.blob(JVM_CAPABILITY_MAX_FIELD_BYTES)?,
        )?,
        service_provider: if reader.bool()? {
            Some(reader.string(JVM_CAPABILITY_MAX_TEXT_BYTES)?)
        } else {
            None
        },
    };
    reader.finish()?;
    Ok(value)
}

fn encode_provider_list(values: &[ProviderIdentity]) -> Result<Vec<u8>, JvmCapabilityError> {
    if values.len() > JVM_CAPABILITY_MAX_PLUGIN_ALIASES || values.len() > u16::MAX as usize {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let mut writer = WireWriter::new();
    writer.u16(values.len() as u16);
    for value in values {
        writer.blob(&encode_provider_identity(value)?)?;
    }
    Ok(writer.finish())
}

fn decode_provider_list(bytes: &[u8]) -> Result<Vec<ProviderIdentity>, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let count = reader.u16()? as usize;
    if count > JVM_CAPABILITY_MAX_PLUGIN_ALIASES {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(decode_provider_identity(
            &reader.blob(JVM_CAPABILITY_MAX_FIELD_BYTES)?,
        )?);
    }
    reader.finish()?;
    Ok(values)
}

fn encode_classpath_entry(
    value: &ClasspathEntry,
    max_dependencies: usize,
) -> Result<Vec<u8>, JvmCapabilityError> {
    let mut writer = WireWriter::new();
    writer.u32(value.ordinal);
    writer.u8(value.role as u8);
    value.path_identity.encode_into(&mut writer);
    value.content_sha256.encode_into(&mut writer);
    writer.u64(value.byte_length);
    writer.string(&value.version, JVM_CAPABILITY_MAX_TEXT_BYTES)?;
    writer.string(&value.provenance, JVM_CAPABILITY_MAX_TEXT_BYTES)?;
    writer.u8(value.license_notice as u8);
    writer.blob(&encode_u32_list(&value.dependencies, max_dependencies)?)?;
    match &value.provider {
        Some(provider) => {
            writer.bool(true);
            writer.blob(&encode_provider_identity(provider)?)?;
        }
        None => writer.bool(false),
    }
    Ok(writer.finish())
}

fn decode_classpath_entry(
    bytes: &[u8],
    max_dependencies: usize,
) -> Result<ClasspathEntry, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let value = ClasspathEntry {
        ordinal: reader.u32()?,
        role: ClasspathRole::from_wire(reader.u8()?)?,
        path_identity: Sha256Digest::decode(&mut reader)?,
        content_sha256: Sha256Digest::decode(&mut reader)?,
        byte_length: reader.u64()?,
        version: reader.string(JVM_CAPABILITY_MAX_TEXT_BYTES)?,
        provenance: reader.string(JVM_CAPABILITY_MAX_TEXT_BYTES)?,
        license_notice: LicenseNoticeStatus::from_wire(reader.u8()?)?,
        dependencies: decode_u32_list(
            &reader.blob(JVM_CAPABILITY_MAX_FIELD_BYTES)?,
            max_dependencies,
        )?,
        provider: if reader.bool()? {
            Some(decode_provider_identity(
                &reader.blob(JVM_CAPABILITY_MAX_FIELD_BYTES)?,
            )?)
        } else {
            None
        },
    };
    reader.finish()?;
    Ok(value)
}

fn encode_classpath_identity(
    value: &ClasspathIdentity,
    limits: &JvmCapabilityLimits,
) -> Result<Vec<u8>, JvmCapabilityError> {
    if value.entries.len() > limits.max_classpath_entries
        || value.entries.len() > JVM_CAPABILITY_MAX_CLASSPATH_ENTRIES
    {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let mut ordinals = BTreeSet::new();
    let mut aggregate_bytes = 0usize;
    let mut writer = WireWriter::new();
    writer.u16(value.entries.len() as u16);
    for entry in &value.entries {
        if !ordinals.insert(entry.ordinal) {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::DuplicateIdentity,
            ));
        }
        aggregate_bytes = aggregate_bytes
            .checked_add(
                usize::try_from(entry.byte_length)
                    .map_err(|_| JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit))?,
            )
            .ok_or_else(|| JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit))?;
        if aggregate_bytes > limits.max_classpath_bytes
            || aggregate_bytes > JVM_CAPABILITY_MAX_CLASSPATH_BYTES
        {
            return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
        }
        writer.blob(&encode_classpath_entry(
            entry,
            limits.max_plugin_dependencies,
        )?)?;
    }
    value.aggregate_sha256.encode_into(&mut writer);
    let encoded = writer.finish();
    if encoded.len() > limits.max_classpath_bytes
        || encoded.len() > JVM_CAPABILITY_MAX_CLASSPATH_BYTES
    {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    Ok(encoded)
}

fn decode_classpath_identity(
    bytes: &[u8],
    limits: &JvmCapabilityLimits,
) -> Result<ClasspathIdentity, JvmCapabilityError> {
    if bytes.len() > limits.max_classpath_bytes || bytes.len() > JVM_CAPABILITY_MAX_CLASSPATH_BYTES
    {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let mut reader = WireReader::new(bytes);
    let count = reader.u16()? as usize;
    if count > limits.max_classpath_entries || count > JVM_CAPABILITY_MAX_CLASSPATH_ENTRIES {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let mut entries = Vec::with_capacity(count);
    let mut ordinals = BTreeSet::new();
    let mut aggregate_bytes = 0usize;
    for _ in 0..count {
        let entry = decode_classpath_entry(
            &reader.blob(JVM_CAPABILITY_MAX_FIELD_BYTES)?,
            limits.max_plugin_dependencies,
        )?;
        if !ordinals.insert(entry.ordinal) {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::DuplicateIdentity,
            ));
        }
        aggregate_bytes = aggregate_bytes
            .checked_add(
                usize::try_from(entry.byte_length)
                    .map_err(|_| JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit))?,
            )
            .ok_or_else(|| JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit))?;
        if aggregate_bytes > limits.max_classpath_bytes
            || aggregate_bytes > JVM_CAPABILITY_MAX_CLASSPATH_BYTES
        {
            return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
        }
        entries.push(entry);
    }
    let aggregate_sha256 = Sha256Digest::decode(&mut reader)?;
    reader.finish()?;
    Ok(ClasspathIdentity {
        entries,
        aggregate_sha256,
    })
}

fn encode_capability_identity(
    value: &CapabilityIdentity,
    limits: &JvmCapabilityLimits,
) -> Result<Vec<u8>, JvmCapabilityError> {
    value.validate_with_limits(limits)?;
    let mut writer = WireWriter::new();
    writer.blob(&encode_profile_identity(&value.profile)?)?;
    writer.blob(&encode_jmeter_identity(&value.jmeter)?)?;
    writer.blob(&encode_jvm_identity(&value.jvm)?)?;
    writer.blob(&encode_helper_identity(&value.helper)?)?;
    writer.blob(&encode_classpath_identity(&value.classpath, limits)?)?;
    writer.blob(&encode_provider_list(&value.providers)?)?;
    Ok(writer.finish())
}

fn decode_capability_identity(
    bytes: &[u8],
    limits: &JvmCapabilityLimits,
) -> Result<CapabilityIdentity, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let value = CapabilityIdentity {
        profile: decode_profile_identity(&reader.blob(JVM_CAPABILITY_MAX_FIELD_BYTES)?)?,
        jmeter: decode_jmeter_identity(&reader.blob(JVM_CAPABILITY_MAX_FIELD_BYTES)?)?,
        jvm: decode_jvm_identity(&reader.blob(JVM_CAPABILITY_MAX_FIELD_BYTES)?)?,
        helper: decode_helper_identity(&reader.blob(JVM_CAPABILITY_MAX_FIELD_BYTES)?)?,
        classpath: decode_classpath_identity(
            &reader.blob(JVM_CAPABILITY_MAX_FIELD_BYTES)?,
            limits,
        )?,
        providers: decode_provider_list(&reader.blob(JVM_CAPABILITY_MAX_FIELD_BYTES)?)?,
    };
    reader.finish()?;
    value.validate_with_limits(limits)?;
    Ok(value)
}

fn encode_root_identities(values: &[RootIdentity]) -> Result<Vec<u8>, JvmCapabilityError> {
    if values.len() > 64 || values.len() > u16::MAX as usize {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let mut writer = WireWriter::new();
    let mut identities = BTreeSet::new();
    writer.u16(values.len() as u16);
    for value in values {
        validate_required_text(&value.kind, JVM_CAPABILITY_MAX_TEXT_BYTES)?;
        if !identities.insert(value.identity_sha256) {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::DuplicateIdentity,
            ));
        }
        writer.string(&value.kind, JVM_CAPABILITY_MAX_TEXT_BYTES)?;
        value.identity_sha256.encode_into(&mut writer);
    }
    Ok(writer.finish())
}

fn decode_root_identities(bytes: &[u8]) -> Result<Vec<RootIdentity>, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let count = reader.u16()? as usize;
    if count > 64 {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let mut values = Vec::with_capacity(count);
    let mut identities = BTreeSet::new();
    for _ in 0..count {
        let value = RootIdentity {
            kind: reader.string(JVM_CAPABILITY_MAX_TEXT_BYTES)?,
            identity_sha256: Sha256Digest::decode(&mut reader)?,
        };
        validate_required_text(&value.kind, JVM_CAPABILITY_MAX_TEXT_BYTES)?;
        if !identities.insert(value.identity_sha256) {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::DuplicateIdentity,
            ));
        }
        values.push(value);
    }
    reader.finish()?;
    Ok(values)
}

fn encode_secret_references(values: &[SecretReference]) -> Result<Vec<u8>, JvmCapabilityError> {
    if values.len() > 64 || values.len() > u16::MAX as usize {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let mut writer = WireWriter::new();
    let mut handles = BTreeSet::new();
    writer.u16(values.len() as u16);
    for value in values {
        value.expiry.validate()?;
        validate_required_text(&value.purpose, JVM_CAPABILITY_MAX_TEXT_BYTES)?;
        if !handles.insert(value.handle) {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::DuplicateIdentity,
            ));
        }
        value
            .handle
            .as_bytes()
            .iter()
            .for_each(|byte| writer.u8(*byte));
        value.provider_identity.encode_into(&mut writer);
        writer.string(&value.purpose, JVM_CAPABILITY_MAX_TEXT_BYTES)?;
        writer.u32(value.rights);
        writer.blob(&encode_budget(value.expiry))?;
    }
    Ok(writer.finish())
}

fn decode_secret_references(bytes: &[u8]) -> Result<Vec<SecretReference>, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let count = reader.u16()? as usize;
    if count > 64 {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let mut values = Vec::with_capacity(count);
    let mut handles = BTreeSet::new();
    for _ in 0..count {
        let mut handle = [0; 16];
        handle.copy_from_slice(reader.bytes_exact(16)?);
        let provider_identity = Sha256Digest::decode(&mut reader)?;
        let purpose = reader.string(JVM_CAPABILITY_MAX_TEXT_BYTES)?;
        validate_required_text(&purpose, JVM_CAPABILITY_MAX_TEXT_BYTES)?;
        let rights = reader.u32()?;
        let expiry = decode_budget(&reader.blob(JVM_CAPABILITY_MAX_FIELD_BYTES)?)?;
        expiry.validate()?;
        if !handles.insert(handle) {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::DuplicateIdentity,
            ));
        }
        values.push(SecretReference {
            handle: SecretHandle::from_bytes(handle),
            provider_identity,
            purpose,
            rights,
            expiry,
        });
    }
    reader.finish()?;
    Ok(values)
}

fn encode_plugin_artifact(
    value: &PluginArtifact,
    max_dependencies: usize,
) -> Result<Vec<u8>, JvmCapabilityError> {
    if value.aliases.len() > JVM_CAPABILITY_MAX_PLUGIN_ALIASES
        || value.capabilities.len() > JVM_CAPABILITY_MAX_PLUGIN_ALIASES
    {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let mut writer = WireWriter::new();
    writer.u32(value.ordinal);
    writer.u8(value.role as u8);
    value.path_identity.encode_into(&mut writer);
    value.content_sha256.encode_into(&mut writer);
    writer.string(&value.version, JVM_CAPABILITY_MAX_TEXT_BYTES)?;
    writer.u8(value.license_notice as u8);
    writer.blob(&encode_u32_list(&value.dependencies, max_dependencies)?)?;
    writer.blob(&encode_string_list(
        &value.aliases,
        JVM_CAPABILITY_MAX_PLUGIN_ALIASES,
    )?)?;
    writer.blob(&encode_string_list(
        &value.capabilities,
        JVM_CAPABILITY_MAX_PLUGIN_ALIASES,
    )?)?;
    Ok(writer.finish())
}

fn decode_plugin_artifact(
    bytes: &[u8],
    max_dependencies: usize,
) -> Result<PluginArtifact, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let value = PluginArtifact {
        ordinal: reader.u32()?,
        role: ClasspathRole::from_wire(reader.u8()?)?,
        path_identity: Sha256Digest::decode(&mut reader)?,
        content_sha256: Sha256Digest::decode(&mut reader)?,
        version: reader.string(JVM_CAPABILITY_MAX_TEXT_BYTES)?,
        license_notice: LicenseNoticeStatus::from_wire(reader.u8()?)?,
        dependencies: decode_u32_list(
            &reader.blob(JVM_CAPABILITY_MAX_FIELD_BYTES)?,
            max_dependencies,
        )?,
        aliases: decode_string_list(
            &reader.blob(JVM_CAPABILITY_MAX_FIELD_BYTES)?,
            JVM_CAPABILITY_MAX_PLUGIN_ALIASES,
        )?,
        capabilities: decode_string_list(
            &reader.blob(JVM_CAPABILITY_MAX_FIELD_BYTES)?,
            JVM_CAPABILITY_MAX_PLUGIN_ALIASES,
        )?,
    };
    reader.finish()?;
    Ok(value)
}

fn encode_plugin_alias(value: &PluginAlias) -> Result<Vec<u8>, JvmCapabilityError> {
    let mut writer = WireWriter::new();
    writer.string(&value.alias, JVM_CAPABILITY_MAX_TEXT_BYTES)?;
    writer.u32(value.artifact_ordinal);
    writer.u32(value.declaration_ordinal);
    Ok(writer.finish())
}

fn decode_plugin_alias(bytes: &[u8]) -> Result<PluginAlias, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let value = PluginAlias {
        alias: reader.string(JVM_CAPABILITY_MAX_TEXT_BYTES)?,
        artifact_ordinal: reader.u32()?,
        declaration_ordinal: reader.u32()?,
    };
    reader.finish()?;
    Ok(value)
}

fn encode_alias_resolution(value: &AliasResolution) -> Result<Vec<u8>, JvmCapabilityError> {
    let mut writer = WireWriter::new();
    match value {
        AliasResolution::Missing => writer.u8(0),
        AliasResolution::Unique { artifact_ordinal } => {
            writer.u8(1);
            writer.u32(*artifact_ordinal);
        }
        AliasResolution::Ambiguous { candidates } => {
            writer.u8(2);
            writer.blob(&encode_u32_list(
                candidates,
                JVM_CAPABILITY_MAX_PLUGIN_ALIASES,
            )?)?;
        }
    }
    Ok(writer.finish())
}

fn decode_alias_resolution(bytes: &[u8]) -> Result<AliasResolution, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let value = match reader.u8()? {
        0 => AliasResolution::Missing,
        1 => AliasResolution::Unique {
            artifact_ordinal: reader.u32()?,
        },
        2 => AliasResolution::Ambiguous {
            candidates: decode_u32_list(
                &reader.blob(JVM_CAPABILITY_MAX_FIELD_BYTES)?,
                JVM_CAPABILITY_MAX_PLUGIN_ALIASES,
            )?,
        },
        _ => {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::InvalidMessage,
            ));
        }
    };
    reader.finish()?;
    Ok(value)
}

fn encode_alias_binding(value: &AliasBinding) -> Result<Vec<u8>, JvmCapabilityError> {
    if value.declarations.len() > JVM_CAPABILITY_MAX_PLUGIN_ALIASES {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    validate_required_text(&value.alias, JVM_CAPABILITY_MAX_TEXT_BYTES)?;
    let mut declaration_ordinals = BTreeSet::new();
    for declaration in &value.declarations {
        if declaration.alias != value.alias
            || !declaration_ordinals.insert(declaration.declaration_ordinal)
        {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::DuplicateIdentity,
            ));
        }
    }
    let mut writer = WireWriter::new();
    writer.string(&value.alias, JVM_CAPABILITY_MAX_TEXT_BYTES)?;
    writer.u16(value.declarations.len() as u16);
    for declaration in &value.declarations {
        writer.blob(&encode_plugin_alias(declaration)?)?;
    }
    writer.blob(&encode_alias_resolution(&value.resolution)?)?;
    Ok(writer.finish())
}

fn decode_alias_binding(bytes: &[u8]) -> Result<AliasBinding, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let alias = reader.string(JVM_CAPABILITY_MAX_TEXT_BYTES)?;
    validate_required_text(&alias, JVM_CAPABILITY_MAX_TEXT_BYTES)?;
    let count = reader.u16()? as usize;
    if count > JVM_CAPABILITY_MAX_PLUGIN_ALIASES {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let mut declarations = Vec::with_capacity(count);
    let mut declaration_ordinals = BTreeSet::new();
    for _ in 0..count {
        let declaration = decode_plugin_alias(&reader.blob(JVM_CAPABILITY_MAX_FIELD_BYTES)?)?;
        if declaration.alias != alias
            || !declaration_ordinals.insert(declaration.declaration_ordinal)
        {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::DuplicateIdentity,
            ));
        }
        declarations.push(declaration);
    }
    let resolution = decode_alias_resolution(&reader.blob(JVM_CAPABILITY_MAX_FIELD_BYTES)?)?;
    reader.finish()?;
    Ok(AliasBinding {
        alias,
        declarations,
        resolution,
    })
}

fn encode_plugin_discovery(
    value: &PluginDiscovery,
    limits: &JvmCapabilityLimits,
) -> Result<Vec<u8>, JvmCapabilityError> {
    if value.artifacts.len() > limits.max_plugin_artifacts
        || value.aliases.len() > limits.max_plugin_aliases
    {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let mut ordinals = BTreeSet::new();
    let mut writer = WireWriter::new();
    writer.u16(value.artifacts.len() as u16);
    for artifact in &value.artifacts {
        if !ordinals.insert(artifact.ordinal) {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::DuplicateIdentity,
            ));
        }
        writer.blob(&encode_plugin_artifact(
            artifact,
            limits.max_plugin_dependencies,
        )?)?;
    }
    writer.u16(value.aliases.len() as u16);
    for alias in &value.aliases {
        writer.blob(&encode_alias_binding(alias)?)?;
    }
    writer.blob(&encode_u32_list(
        &value.declared_order,
        limits.max_plugin_artifacts,
    )?)?;
    writer.blob(&encode_u32_list(
        &value.observed_order,
        limits.max_plugin_artifacts,
    )?)?;
    writer.blob(&encode_u32_list(
        &value.resolution_order,
        limits.max_plugin_artifacts,
    )?)?;
    let encoded = writer.finish();
    let max_body_bytes = limits
        .max_message_bytes
        .checked_sub(JVM_CAPABILITY_HEADER_LEN)
        .ok_or_else(|| JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit))?;
    if encoded.len() > max_body_bytes
        || encoded.len() > JVM_CAPABILITY_MAX_MESSAGE_BYTES - JVM_CAPABILITY_HEADER_LEN
    {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    Ok(encoded)
}

fn decode_plugin_discovery(
    bytes: &[u8],
    limits: &JvmCapabilityLimits,
) -> Result<PluginDiscovery, JvmCapabilityError> {
    let max_body_bytes = limits
        .max_message_bytes
        .checked_sub(JVM_CAPABILITY_HEADER_LEN)
        .ok_or_else(|| JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit))?;
    if bytes.len() > max_body_bytes
        || bytes.len() > JVM_CAPABILITY_MAX_MESSAGE_BYTES - JVM_CAPABILITY_HEADER_LEN
    {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let mut reader = WireReader::new(bytes);
    let artifact_count = reader.u16()? as usize;
    if artifact_count > limits.max_plugin_artifacts {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let mut artifacts = Vec::with_capacity(artifact_count);
    let mut ordinals = BTreeSet::new();
    for _ in 0..artifact_count {
        let artifact = decode_plugin_artifact(
            &reader.blob(JVM_CAPABILITY_MAX_FIELD_BYTES)?,
            limits.max_plugin_dependencies,
        )?;
        if !ordinals.insert(artifact.ordinal) {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::DuplicateIdentity,
            ));
        }
        artifacts.push(artifact);
    }
    let alias_count = reader.u16()? as usize;
    if alias_count > limits.max_plugin_aliases {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let mut aliases = Vec::with_capacity(alias_count);
    for _ in 0..alias_count {
        aliases.push(decode_alias_binding(
            &reader.blob(JVM_CAPABILITY_MAX_FIELD_BYTES)?,
        )?);
    }
    let declared_order = decode_u32_list(
        &reader.blob(JVM_CAPABILITY_MAX_FIELD_BYTES)?,
        limits.max_plugin_artifacts,
    )?;
    let observed_order = decode_u32_list(
        &reader.blob(JVM_CAPABILITY_MAX_FIELD_BYTES)?,
        limits.max_plugin_artifacts,
    )?;
    let resolution_order = decode_u32_list(
        &reader.blob(JVM_CAPABILITY_MAX_FIELD_BYTES)?,
        limits.max_plugin_artifacts,
    )?;
    reader.finish()?;
    Ok(PluginDiscovery {
        artifacts,
        aliases,
        declared_order,
        observed_order,
        resolution_order,
    })
}

fn encode_component_identity(value: &ComponentIdentity) -> Result<Vec<u8>, JvmCapabilityError> {
    let mut writer = WireWriter::new();
    writer.string(&value.class_name, JVM_CAPABILITY_MAX_TEXT_BYTES)?;
    match &value.alias {
        Some(alias) => {
            writer.bool(true);
            writer.string(alias, JVM_CAPABILITY_MAX_TEXT_BYTES)?;
        }
        None => writer.bool(false),
    }
    match &value.gui_class {
        Some(gui_class) => {
            writer.bool(true);
            writer.string(gui_class, JVM_CAPABILITY_MAX_TEXT_BYTES)?;
        }
        None => writer.bool(false),
    }
    Ok(writer.finish())
}

fn decode_component_identity(bytes: &[u8]) -> Result<ComponentIdentity, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let class_name = reader.string(JVM_CAPABILITY_MAX_TEXT_BYTES)?;
    let alias = if reader.bool()? {
        Some(reader.string(JVM_CAPABILITY_MAX_TEXT_BYTES)?)
    } else {
        None
    };
    let gui_class = if reader.bool()? {
        Some(reader.string(JVM_CAPABILITY_MAX_TEXT_BYTES)?)
    } else {
        None
    };
    reader.finish()?;
    Ok(ComponentIdentity {
        class_name,
        alias,
        gui_class,
    })
}

fn encode_sampler_arguments(values: &[SamplerArgument]) -> Result<Vec<u8>, JvmCapabilityError> {
    if values.len() > JVM_CAPABILITY_MAX_FIELDS || values.len() > u16::MAX as usize {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let mut writer = WireWriter::new();
    writer.u16(values.len() as u16);
    for value in values {
        writer.string(&value.name, JVM_CAPABILITY_MAX_TEXT_BYTES)?;
        writer.string(&value.value, JVM_CAPABILITY_MAX_TEXT_BYTES)?;
    }
    Ok(writer.finish())
}

fn decode_sampler_arguments(bytes: &[u8]) -> Result<Vec<SamplerArgument>, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let count = reader.u16()? as usize;
    if count > JVM_CAPABILITY_MAX_FIELDS {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(SamplerArgument {
            name: reader.string(JVM_CAPABILITY_MAX_TEXT_BYTES)?,
            value: reader.string(JVM_CAPABILITY_MAX_TEXT_BYTES)?,
        });
    }
    reader.finish()?;
    Ok(values)
}

fn encode_operation_fields(
    operation: &JvmOperation,
    limits: &JvmCapabilityLimits,
) -> Result<(Vec<u8>, u16), JvmCapabilityError> {
    let fields = match operation {
        JvmOperation::OpenRun(value) => {
            validate_open_run(value, limits)?;
            vec![
                (1, encode_capability_identity(&value.identity, limits)?),
                (2, encode_root_identities(&value.roots)?),
                (3, text_field(&value.locale, limits.max_text_bytes)?),
                (4, text_field(&value.timezone, limits.max_text_bytes)?),
                (5, text_field(&value.charset, limits.max_text_bytes)?),
                (6, optional_digest(&value.sandbox_identity)),
                (7, encode_secret_references(&value.secret_references)?),
            ]
        }
        JvmOperation::DiscoverPlugins(value) => vec![
            (1, encode_roles(&value.roots)?),
            (
                2,
                encode_string_list(&value.requested_capabilities, limits.max_plugin_aliases)?,
            ),
        ],
        JvmOperation::ExpandFunction(value) => vec![
            (1, text_field(&value.function_name, limits.max_text_bytes)?),
            (
                2,
                encode_string_list(&value.arguments, limits.max_variables)?,
            ),
            (3, encode_context_snapshot(&value.context, limits)?),
            (4, optional_cache_epoch(&value.cache_epoch)),
        ],
        JvmOperation::ExecuteJsr223(value) => vec![
            (1, encode_script_source(&value.source, limits)?),
            (2, encode_cache_request(&value.cache, limits)?),
            (3, encode_context_snapshot(&value.context, limits)?),
        ],
        JvmOperation::JavaSamplerSetup(value) => vec![
            (1, encode_component_identity(&value.component)?),
            (2, text_field(&value.class_name, limits.max_text_bytes)?),
            (3, encode_sampler_arguments(&value.arguments)?),
            (4, encode_context_snapshot(&value.context, limits)?),
        ],
        JvmOperation::JavaSamplerRun(value) => vec![
            (1, encode_component_identity(&value.component)?),
            (2, text_field(&value.class_name, limits.max_text_bytes)?),
            (3, encode_context_snapshot(&value.context, limits)?),
        ],
        JvmOperation::JavaSamplerTeardown(value) => vec![
            (1, encode_component_identity(&value.component)?),
            (2, text_field(&value.class_name, limits.max_text_bytes)?),
            (3, encode_context_snapshot(&value.context, limits)?),
        ],
        JvmOperation::JunitRun(value) => vec![
            (1, encode_component_identity(&value.component)?),
            (2, text_field(&value.class_name, limits.max_text_bytes)?),
            (3, vec![value.mode as u8]),
            (4, text_field(&value.method, limits.max_text_bytes)?),
            (5, encode_context_snapshot(&value.context, limits)?),
        ],
        JvmOperation::ExecutePluginElement(value) => vec![
            (1, encode_component_identity(&value.component)?),
            (2, u32_field(value.artifact_ordinal)),
            (3, text_field(&value.class_name, limits.max_text_bytes)?),
            (
                4,
                encode_context_entries(&value.properties, limits.max_properties)?,
            ),
            (5, encode_context_snapshot(&value.context, limits)?),
        ],
        JvmOperation::ExpandPluginFunction(value) => vec![
            (1, text_field(&value.function_name, limits.max_text_bytes)?),
            (2, u32_field(value.artifact_ordinal)),
            (
                3,
                encode_string_list(&value.arguments, limits.max_variables)?,
            ),
            (4, encode_context_snapshot(&value.context, limits)?),
        ],
        JvmOperation::CloseRun(value) => vec![
            (1, vec![value.reason as u8]),
            (2, u64_field(value.final_generation)),
        ],
    };
    encode_fields(fields)
}

fn text_field(value: &str, limit: usize) -> Result<Vec<u8>, JvmCapabilityError> {
    let mut writer = WireWriter::new();
    writer.string(value, limit)?;
    Ok(writer.finish())
}

fn u32_field(value: u32) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}

fn u64_field(value: u64) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}

fn optional_digest(value: &Option<Sha256Digest>) -> Vec<u8> {
    let mut writer = WireWriter::new();
    match value {
        Some(value) => {
            writer.bool(true);
            value.encode_into(&mut writer);
        }
        None => writer.bool(false),
    }
    writer.finish()
}

fn decode_optional_digest(bytes: &[u8]) -> Result<Option<Sha256Digest>, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let value = if reader.bool()? {
        Some(Sha256Digest::decode(&mut reader)?)
    } else {
        None
    };
    reader.finish()?;
    Ok(value)
}

fn optional_cache_epoch(value: &Option<CacheEpoch>) -> Vec<u8> {
    let mut writer = WireWriter::new();
    match value {
        Some(value) => {
            writer.bool(true);
            encode_cache_epoch(value, &mut writer);
        }
        None => writer.bool(false),
    }
    writer.finish()
}

fn decode_optional_cache_epoch(bytes: &[u8]) -> Result<Option<CacheEpoch>, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let value = if reader.bool()? {
        Some(decode_cache_epoch(&mut reader)?)
    } else {
        None
    };
    reader.finish()?;
    Ok(value)
}

fn encode_roles(values: &[ClasspathRole]) -> Result<Vec<u8>, JvmCapabilityError> {
    if values.len() > JVM_CAPABILITY_MAX_CLASSPATH_ENTRIES || values.len() > u16::MAX as usize {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let mut writer = WireWriter::new();
    writer.u16(values.len() as u16);
    for value in values {
        writer.u8(*value as u8);
    }
    Ok(writer.finish())
}

fn decode_roles(bytes: &[u8]) -> Result<Vec<ClasspathRole>, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let count = reader.u16()? as usize;
    if count > JVM_CAPABILITY_MAX_CLASSPATH_ENTRIES {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(ClasspathRole::from_wire(reader.u8()?)?);
    }
    reader.finish()?;
    Ok(values)
}

fn validate_open_run(
    value: &OpenRun,
    limits: &JvmCapabilityLimits,
) -> Result<(), JvmCapabilityError> {
    value.identity.validate_with_limits(limits)?;
    if value.locale != "en-US" || value.timezone != "UTC" || value.charset != "UTF-8" {
        return Err(JvmCapabilityError::new(
            JvmCapabilityErrorCode::InvalidIdentity,
        ));
    }
    if value.roots.len() > 64 {
        return Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit));
    }
    validate_text(&value.locale, limits.max_text_bytes)?;
    validate_text(&value.timezone, limits.max_text_bytes)?;
    validate_text(&value.charset, limits.max_text_bytes)?;
    Ok(())
}

fn decode_u32_field(bytes: &[u8]) -> Result<u32, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let value = reader.u32()?;
    reader.finish()?;
    Ok(value)
}

fn decode_u64_field(bytes: &[u8]) -> Result<u64, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let value = reader.u64()?;
    reader.finish()?;
    Ok(value)
}

fn decode_u8_field(bytes: &[u8]) -> Result<u8, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let value = reader.u8()?;
    reader.finish()?;
    Ok(value)
}

fn decode_delta_kind(value: u8) -> Result<DeltaKind, JvmCapabilityError> {
    match value {
        1 => Ok(DeltaKind::Context),
        2 => Ok(DeltaKind::Result),
        3 => Ok(DeltaKind::Setup),
        4 => Ok(DeltaKind::Teardown),
        _ => Err(JvmCapabilityError::new(
            JvmCapabilityErrorCode::InvalidMessage,
        )),
    }
}

fn decode_rollback_capability(value: u8) -> Result<RollbackCapability, JvmCapabilityError> {
    match value {
        0 => Ok(RollbackCapability::NotExecuted),
        1 => Ok(RollbackCapability::Journaled),
        2 => Ok(RollbackCapability::Unsafe),
        _ => Err(JvmCapabilityError::new(
            JvmCapabilityErrorCode::TransactionInvalid,
        )),
    }
}

fn decode_text_field(bytes: &[u8], limit: usize) -> Result<String, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let value = reader.string(limit)?;
    reader.finish()?;
    Ok(value)
}

fn decode_operation_fields(
    code: OperationCode,
    fields: &[(u16, Vec<u8>)],
    limits: &JvmCapabilityLimits,
    preservation: JvmPreservationNegotiation,
) -> Result<(JvmOperation, Vec<OpaqueField>), JvmCapabilityError> {
    let known = match code {
        OperationCode::OpenRun => &[1, 2, 3, 4, 5, 6, 7, 254, 255][..],
        OperationCode::DiscoverPlugins => &[1, 2, 254, 255][..],
        OperationCode::ExpandFunction => &[1, 2, 3, 4, 254, 255][..],
        OperationCode::ExecuteJsr223 => &[1, 2, 3, 254, 255][..],
        OperationCode::JavaSamplerSetup => &[1, 2, 3, 4, 254, 255][..],
        OperationCode::JavaSamplerRun => &[1, 2, 3, 254, 255][..],
        OperationCode::JavaSamplerTeardown => &[1, 2, 3, 254, 255][..],
        OperationCode::JunitRun => &[1, 2, 3, 4, 5, 254, 255][..],
        OperationCode::ExecutePluginElement => &[1, 2, 3, 4, 5, 254, 255][..],
        OperationCode::ExpandPluginFunction => &[1, 2, 3, 4, 254, 255][..],
        OperationCode::CloseRun => &[1, 2, 254, 255][..],
    };
    let unknown = check_known_fields(fields, known, preservation)?;
    let operation = match code {
        OperationCode::OpenRun => JvmOperation::OpenRun(OpenRun {
            identity: decode_capability_identity(required_field(fields, 1)?, limits)?,
            roots: decode_root_identities(required_field(fields, 2)?)?,
            locale: decode_text_field(required_field(fields, 3)?, limits.max_text_bytes)?,
            timezone: decode_text_field(required_field(fields, 4)?, limits.max_text_bytes)?,
            charset: decode_text_field(required_field(fields, 5)?, limits.max_text_bytes)?,
            sandbox_identity: decode_optional_digest(required_field(fields, 6)?)?,
            secret_references: decode_secret_references(required_field(fields, 7)?)?,
        }),
        OperationCode::DiscoverPlugins => JvmOperation::DiscoverPlugins(DiscoverPlugins {
            roots: decode_roles(required_field(fields, 1)?)?,
            requested_capabilities: decode_string_list(
                required_field(fields, 2)?,
                limits.max_plugin_aliases,
            )?,
        }),
        OperationCode::ExpandFunction => JvmOperation::ExpandFunction(ExpandFunction {
            function_name: decode_text_field(required_field(fields, 1)?, limits.max_text_bytes)?,
            arguments: decode_string_list(required_field(fields, 2)?, limits.max_variables)?,
            context: decode_context_snapshot(required_field(fields, 3)?, limits)?,
            cache_epoch: decode_optional_cache_epoch(required_field(fields, 4)?)?,
        }),
        OperationCode::ExecuteJsr223 => JvmOperation::ExecuteJsr223(ExecuteJsr223 {
            source: decode_script_source(required_field(fields, 1)?, limits)?,
            cache: decode_cache_request(required_field(fields, 2)?, limits)?,
            context: decode_context_snapshot(required_field(fields, 3)?, limits)?,
        }),
        OperationCode::JavaSamplerSetup => JvmOperation::JavaSamplerSetup(JavaSamplerSetup {
            component: decode_component_identity(required_field(fields, 1)?)?,
            class_name: decode_text_field(required_field(fields, 2)?, limits.max_text_bytes)?,
            arguments: decode_sampler_arguments(required_field(fields, 3)?)?,
            context: decode_context_snapshot(required_field(fields, 4)?, limits)?,
        }),
        OperationCode::JavaSamplerRun => JvmOperation::JavaSamplerRun(JavaSamplerRun {
            component: decode_component_identity(required_field(fields, 1)?)?,
            class_name: decode_text_field(required_field(fields, 2)?, limits.max_text_bytes)?,
            context: decode_context_snapshot(required_field(fields, 3)?, limits)?,
        }),
        OperationCode::JavaSamplerTeardown => {
            JvmOperation::JavaSamplerTeardown(JavaSamplerTeardown {
                component: decode_component_identity(required_field(fields, 1)?)?,
                class_name: decode_text_field(required_field(fields, 2)?, limits.max_text_bytes)?,
                context: decode_context_snapshot(required_field(fields, 3)?, limits)?,
            })
        }
        OperationCode::JunitRun => JvmOperation::JunitRun(JunitRun {
            component: decode_component_identity(required_field(fields, 1)?)?,
            class_name: decode_text_field(required_field(fields, 2)?, limits.max_text_bytes)?,
            mode: JunitMode::from_wire(decode_u8_field(required_field(fields, 3)?)?)?,
            method: decode_text_field(required_field(fields, 4)?, limits.max_text_bytes)?,
            context: decode_context_snapshot(required_field(fields, 5)?, limits)?,
        }),
        OperationCode::ExecutePluginElement => {
            JvmOperation::ExecutePluginElement(ExecutePluginElement {
                component: decode_component_identity(required_field(fields, 1)?)?,
                artifact_ordinal: decode_u32_field(required_field(fields, 2)?)?,
                class_name: decode_text_field(required_field(fields, 3)?, limits.max_text_bytes)?,
                properties: decode_context_entries(
                    required_field(fields, 4)?,
                    limits.max_properties,
                )?,
                context: decode_context_snapshot(required_field(fields, 5)?, limits)?,
            })
        }
        OperationCode::ExpandPluginFunction => {
            JvmOperation::ExpandPluginFunction(ExpandPluginFunction {
                function_name: decode_text_field(
                    required_field(fields, 1)?,
                    limits.max_text_bytes,
                )?,
                artifact_ordinal: decode_u32_field(required_field(fields, 2)?)?,
                arguments: decode_string_list(required_field(fields, 3)?, limits.max_variables)?,
                context: decode_context_snapshot(required_field(fields, 4)?, limits)?,
            })
        }
        OperationCode::CloseRun => JvmOperation::CloseRun(CloseRun {
            reason: CloseReason::from_wire(decode_u8_field(required_field(fields, 1)?)?)?,
            final_generation: decode_u64_field(required_field(fields, 2)?)?,
        }),
    };
    if let JvmOperation::OpenRun(value) = &operation {
        validate_open_run(value, limits)?;
    }
    Ok((operation, unknown))
}

fn encode_result_fields(
    operation: OperationCode,
    result: &Result<JvmOperationResult, JvmCapabilityError>,
    limits: &JvmCapabilityLimits,
) -> Result<(Vec<u8>, u16), JvmCapabilityError> {
    if let Err(error) = result {
        let mut writer = WireWriter::new();
        writer.u16(error.code as u16);
        writer.string(error.code.as_str(), limits.max_text_bytes)?;
        return encode_fields(vec![(1, writer.finish())]);
    }
    let result = result.as_ref().map_err(|_| unreachable!())?;
    let fields = match (operation, result) {
        (OperationCode::OpenRun, JvmOperationResult::RunOpened { generation }) => {
            vec![(1, u64_field(*generation))]
        }
        (OperationCode::DiscoverPlugins, JvmOperationResult::Plugins(value)) => {
            vec![(1, encode_plugin_discovery(value, limits)?)]
        }
        (OperationCode::ExpandFunction, JvmOperationResult::FunctionExpanded { value, delta }) => {
            vec![
                (1, text_field(value, limits.max_text_bytes)?),
                (2, encode_context_delta(delta, limits)?),
            ]
        }
        (OperationCode::ExecuteJsr223, JvmOperationResult::Jsr223 { value, delta }) => {
            vec![
                (1, encode_optional_text(value, limits.max_text_bytes)?),
                (2, encode_context_delta(delta, limits)?),
            ]
        }
        (
            OperationCode::JavaSamplerSetup,
            JvmOperationResult::JavaSamplerSetup {
                class_loader_generation,
            },
        ) => {
            vec![(1, u64_field(*class_loader_generation))]
        }
        (OperationCode::JavaSamplerRun, JvmOperationResult::JavaSamplerRun { delta })
        | (OperationCode::JavaSamplerTeardown, JvmOperationResult::JavaSamplerTeardown { delta })
        | (OperationCode::JunitRun, JvmOperationResult::Junit { delta })
        | (OperationCode::ExecutePluginElement, JvmOperationResult::PluginElement { delta }) => {
            vec![(1, encode_context_delta(delta, limits)?)]
        }
        (
            OperationCode::ExpandPluginFunction,
            JvmOperationResult::PluginFunctionExpanded { value, delta },
        ) => {
            vec![
                (1, text_field(value, limits.max_text_bytes)?),
                (2, encode_context_delta(delta, limits)?),
            ]
        }
        (
            OperationCode::CloseRun,
            JvmOperationResult::Closed {
                generation,
                cache_entries,
            },
        ) => {
            vec![
                (1, u64_field(*generation)),
                (
                    2,
                    u32_field(u32::try_from(*cache_entries).map_err(|_| {
                        JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit)
                    })?),
                ),
            ]
        }
        _ => {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::InvalidMessage,
            ));
        }
    };
    encode_fields(fields)
}

fn encode_optional_text(
    value: &Option<String>,
    limit: usize,
) -> Result<Vec<u8>, JvmCapabilityError> {
    let mut writer = WireWriter::new();
    match value {
        Some(value) => {
            writer.bool(true);
            writer.string(value, limit)?;
        }
        None => writer.bool(false),
    }
    Ok(writer.finish())
}

fn encode_optional_i64(value: Option<i64>) -> Vec<u8> {
    let mut writer = WireWriter::new();
    match value {
        Some(value) => {
            writer.bool(true);
            writer.bytes(&value.to_be_bytes());
        }
        None => writer.bool(false),
    }
    writer.finish()
}

fn decode_optional_i64(bytes: &[u8]) -> Result<Option<i64>, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let value = if reader.bool()? {
        let mut raw = [0; 8];
        raw.copy_from_slice(reader.bytes_exact(8)?);
        Some(i64::from_be_bytes(raw))
    } else {
        None
    };
    reader.finish()?;
    Ok(value)
}

fn decode_optional_text(bytes: &[u8], limit: usize) -> Result<Option<String>, JvmCapabilityError> {
    let mut reader = WireReader::new(bytes);
    let value = if reader.bool()? {
        Some(reader.string(limit)?)
    } else {
        None
    };
    reader.finish()?;
    Ok(value)
}

fn decode_error_code(value: u16) -> Result<JvmCapabilityErrorCode, JvmCapabilityError> {
    let code = match value {
        1 => JvmCapabilityErrorCode::BridgeProtocolVersion,
        2 => JvmCapabilityErrorCode::BridgeProtocolOrder,
        3 => JvmCapabilityErrorCode::BridgeLimit,
        4 => JvmCapabilityErrorCode::BridgeCancelled,
        5 => JvmCapabilityErrorCode::BridgeDeadlineExceeded,
        6 => JvmCapabilityErrorCode::BridgeWorkerCrashed,
        7 => JvmCapabilityErrorCode::BridgeContainmentLost,
        8 => JvmCapabilityErrorCode::ScriptEngineUnavailable,
        9 => JvmCapabilityErrorCode::ScriptSourceUnavailable,
        10 => JvmCapabilityErrorCode::ScriptConfigurationInvalid,
        11 => JvmCapabilityErrorCode::ScriptClasspathUnavailable,
        12 => JvmCapabilityErrorCode::ScriptClassUnavailable,
        13 => JvmCapabilityErrorCode::ScriptClassContractInvalid,
        14 => JvmCapabilityErrorCode::ScriptContextUnsupported,
        15 => JvmCapabilityErrorCode::ScriptEvaluationFailed,
        16 => JvmCapabilityErrorCode::PluginClasspathUnavailable,
        17 => JvmCapabilityErrorCode::PluginAliasAmbiguous,
        18 => JvmCapabilityErrorCode::PluginClassUnavailable,
        19 => JvmCapabilityErrorCode::PluginElementUnavailable,
        20 => JvmCapabilityErrorCode::PluginFunctionUnavailable,
        21 => JvmCapabilityErrorCode::SandboxDenied,
        22 => JvmCapabilityErrorCode::DuplicateRequestId,
        23 => JvmCapabilityErrorCode::DuplicateIdentity,
        24 => JvmCapabilityErrorCode::StaleContextGeneration,
        25 => JvmCapabilityErrorCode::AtomicDeltaRejected,
        26 => JvmCapabilityErrorCode::UnknownOperation,
        27 => JvmCapabilityErrorCode::UnknownField,
        28 => JvmCapabilityErrorCode::InvalidMessage,
        29 => JvmCapabilityErrorCode::InvalidIdentity,
        30 => JvmCapabilityErrorCode::RunNotOpen,
        31 => JvmCapabilityErrorCode::RunAlreadyOpen,
        32 => JvmCapabilityErrorCode::RunAlreadyClosed,
        33 => JvmCapabilityErrorCode::TerminalMessage,
        34 => JvmCapabilityErrorCode::MalformedUtf8,
        35 => JvmCapabilityErrorCode::Truncated,
        36 => JvmCapabilityErrorCode::TrailingBytes,
        37 => JvmCapabilityErrorCode::CacheIdentityInvalid,
        38 => JvmCapabilityErrorCode::DeadlineInvalid,
        39 => JvmCapabilityErrorCode::BridgeProtocolPhase,
        40 => JvmCapabilityErrorCode::BridgeProtocolSequence,
        41 => JvmCapabilityErrorCode::BridgeProtocolDigest,
        42 => JvmCapabilityErrorCode::BridgeWorkerPoisoned,
        43 => JvmCapabilityErrorCode::TransactionInvalid,
        44 => JvmCapabilityErrorCode::TransactionConflict,
        45 => JvmCapabilityErrorCode::TransactionAbortUnsafe,
        46 => JvmCapabilityErrorCode::HandleInvalid,
        47 => JvmCapabilityErrorCode::ScriptValueTypeUnsupported,
        48 => JvmCapabilityErrorCode::SecretDenied,
        49 => JvmCapabilityErrorCode::ClasspathIdentityMismatch,
        50 => JvmCapabilityErrorCode::ProviderIdentityMismatch,
        _ => {
            return Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::InvalidMessage,
            ));
        }
    };
    Ok(code)
}

fn decode_result_fields(
    operation: OperationCode,
    fields: &[(u16, Vec<u8>)],
    limits: &JvmCapabilityLimits,
    preservation: JvmPreservationNegotiation,
    is_error: bool,
) -> Result<
    (
        Result<JvmOperationResult, JvmCapabilityError>,
        Vec<OpaqueField>,
    ),
    JvmCapabilityError,
> {
    let known = &[1, 2, 254, 255][..];
    let unknown = check_known_fields(fields, known, preservation)?;
    if is_error {
        let bytes = required_field(fields, 1)?;
        let mut reader = WireReader::new(bytes);
        let code = decode_error_code(reader.u16()?)?;
        let _wire_code = reader.string(limits.max_text_bytes)?;
        reader.finish()?;
        return Ok((Err(JvmCapabilityError::new(code)), unknown));
    }
    let result = match operation {
        OperationCode::OpenRun => JvmOperationResult::RunOpened {
            generation: decode_u64_field(required_field(fields, 1)?)?,
        },
        OperationCode::DiscoverPlugins => JvmOperationResult::Plugins(decode_plugin_discovery(
            required_field(fields, 1)?,
            limits,
        )?),
        OperationCode::ExpandFunction => JvmOperationResult::FunctionExpanded {
            value: decode_text_field(required_field(fields, 1)?, limits.max_text_bytes)?,
            delta: decode_context_delta(required_field(fields, 2)?, limits)?,
        },
        OperationCode::ExecuteJsr223 => JvmOperationResult::Jsr223 {
            value: decode_optional_text(required_field(fields, 1)?, limits.max_text_bytes)?,
            delta: decode_context_delta(required_field(fields, 2)?, limits)?,
        },
        OperationCode::JavaSamplerSetup => JvmOperationResult::JavaSamplerSetup {
            class_loader_generation: decode_u64_field(required_field(fields, 1)?)?,
        },
        OperationCode::JavaSamplerRun => JvmOperationResult::JavaSamplerRun {
            delta: decode_context_delta(required_field(fields, 1)?, limits)?,
        },
        OperationCode::JavaSamplerTeardown => JvmOperationResult::JavaSamplerTeardown {
            delta: decode_context_delta(required_field(fields, 1)?, limits)?,
        },
        OperationCode::JunitRun => JvmOperationResult::Junit {
            delta: decode_context_delta(required_field(fields, 1)?, limits)?,
        },
        OperationCode::ExecutePluginElement => JvmOperationResult::PluginElement {
            delta: decode_context_delta(required_field(fields, 1)?, limits)?,
        },
        OperationCode::ExpandPluginFunction => JvmOperationResult::PluginFunctionExpanded {
            value: decode_text_field(required_field(fields, 1)?, limits.max_text_bytes)?,
            delta: decode_context_delta(required_field(fields, 2)?, limits)?,
        },
        OperationCode::CloseRun => JvmOperationResult::Closed {
            generation: decode_u64_field(required_field(fields, 1)?)?,
            cache_entries: decode_u32_field(required_field(fields, 2)?)? as usize,
        },
    };
    Ok((Ok(result), unknown))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> CapabilityIdentity {
        CapabilityIdentity {
            profile: ProfileIdentity {
                id: JVM_PROFILE_ID.to_owned(),
                version: 2,
                sha256: Sha256Digest::from_hex(JVM_PROFILE_SHA256_HEX).expect("profile digest"),
            },
            jmeter: JmeterIdentity {
                version: PINNED_JMETER_VERSION.to_owned(),
                source_commit: PINNED_JMETER_SOURCE_COMMIT.to_owned(),
                archive_sha512: Sha512Digest::from_hex(PINNED_JMETER_ARCHIVE_SHA512_HEX)
                    .expect("pinned archive digest"),
                signature_verified: false,
            },
            jvm: JvmIdentity {
                executable_sha256: Sha256Digest::ZERO,
                vendor: "fixture-vendor".to_owned(),
                version: "17.0.0".to_owned(),
                vm: "fixture-vm".to_owned(),
                major: 17,
                target_triple: "x86_64-unknown-linux-gnu".to_owned(),
                os_image: "fixture-os".to_owned(),
            },
            helper: HelperIdentity {
                source_sha256: Sha256Digest::ZERO,
                build_sha256: Sha256Digest::ZERO,
                compiler: "javac-17".to_owned(),
                operation_schema_sha256: Sha256Digest::ZERO,
            },
            classpath: ClasspathIdentity {
                entries: vec![ClasspathEntry {
                    ordinal: 0,
                    role: ClasspathRole::Lib,
                    path_identity: Sha256Digest::ZERO,
                    content_sha256: Sha256Digest::ZERO,
                    byte_length: 1,
                    version: PINNED_JMETER_VERSION.to_owned(),
                    provenance: "profile-pinned".to_owned(),
                    license_notice: LicenseNoticeStatus::Verified,
                    dependencies: vec![],
                    provider: Some(ProviderIdentity {
                        name: "Groovy".to_owned(),
                        version: "3.0.20".to_owned(),
                        artifact_sha256: Sha256Digest::ZERO,
                        service_descriptor_sha256: None,
                        service_provider: Some(
                            "org.codehaus.groovy.jsr223.GroovyScriptEngineFactory".to_owned(),
                        ),
                    }),
                }],
                aggregate_sha256: Sha256Digest::ZERO,
            },
            providers: vec![ProviderIdentity {
                name: "Groovy".to_owned(),
                version: "3.0.20".to_owned(),
                artifact_sha256: Sha256Digest::ZERO,
                service_descriptor_sha256: None,
                service_provider: Some(
                    "org.codehaus.groovy.jsr223.GroovyScriptEngineFactory".to_owned(),
                ),
            }],
        }
    }

    fn sample_result() -> SampleResultProjection {
        SampleResultProjection {
            label: "sample".to_owned(),
            url: "http://fixture.invalid/".to_owned(),
            thread_name: "thread-1".to_owned(),
            worker_id: 1,
            success: false,
            response_code: "500".to_owned(),
            response_message: "fixture failure".to_owned(),
            result_filename: Some("result.jtl".to_owned()),
            sampler_data: Some("fixture sampler data".to_owned()),
            data_type: Some("text".to_owned()),
            data_encoding: Some("UTF-8".to_owned()),
            content_type: Some("text/plain".to_owned()),
            location: Some("http://fixture.invalid/redirect".to_owned()),
            timestamp_millis: Some(9),
            elapsed_millis: 12,
            latency_millis: 7,
            connect_millis: 3,
            idle_millis: Some(1),
            pause_millis: Some(2),
            start_millis: 10,
            end_millis: 22,
            sample_count: 1,
            error_count: 1,
            received_bytes: 4,
            sent_bytes: 5,
            header_bytes: 6,
            body_bytes: 4,
            response_bytes: 4,
            request_data: vec![9, 8, 7],
            request_headers: "X-Fixture: request".to_owned(),
            response_headers: "X-Fixture: response".to_owned(),
            assertions: vec![AssertionProjection {
                name: "status".to_owned(),
                failure: true,
                error: false,
                failure_message: "expected 200".to_owned(),
            }],
            file_marks: vec!["fixture-result".to_owned()],
            group_threads: 1,
            all_threads: 1,
            stop_thread: false,
            stop_test: false,
            stop_test_now: false,
            ignore: false,
            next_iteration: false,
            break_current_loop: false,
            result_handle: Some(ObjectHandle {
                handle_id: 1,
                object_kind: ObjectKind::CurrentResult,
                owner_scope: 7,
                class_identity_sha256: Sha256Digest::ZERO,
                classloader_generation: 1,
                rights: 1,
                lease_operations: 10,
            }),
            depth: 2,
            node_count: 3,
            response_data: vec![1, 2, 3, 4],
        }
    }

    fn snapshot() -> ContextSnapshot {
        ContextSnapshot {
            identities: ContextIdentities {
                run: 7,
                user: 8,
                thread_group: 9,
                thread: 13,
                iteration: 10,
                sample: 11,
                plan: 12,
            },
            generation: 0,
            user_generation: 0,
            snapshot_digest: Sha256Digest::ZERO,
            variables: vec![ContextEntry {
                key: "answer".to_owned(),
                value: "".to_owned(),
            }],
            properties: vec![ContextEntry {
                key: "mode".to_owned(),
                value: "fixture".to_owned(),
            }],
            typed_variables: vec![ContextBinding {
                key: "typed".to_owned(),
                value: ContextValue::List(vec![
                    ContextValue::Null,
                    ContextValue::I64(7),
                    ContextValue::Object(ObjectHandle {
                        handle_id: 2,
                        object_kind: ObjectKind::Variables,
                        owner_scope: 7,
                        class_identity_sha256: Sha256Digest::ZERO,
                        classloader_generation: 1,
                        rights: 1,
                        lease_operations: 3,
                    }),
                ]),
            }],
            typed_properties: vec![],
            current_sampler: Some("sampler".to_owned()),
            current_result: None,
            previous_result: None,
            element: ElementContext {
                parameters: vec!["arg".to_owned()],
                args: vec![ContextEntry {
                    key: "name".to_owned(),
                    value: "value".to_owned(),
                }],
                file_name: None,
                label: "label".to_owned(),
            },
        }
    }

    fn delta() -> ContextDelta {
        ContextDelta {
            kind: DeltaKind::Context,
            base_generation: 0,
            base_user_generation: 0,
            variable_mutations: vec![ContextMutation::Set(ContextEntry {
                key: "written".to_owned(),
                value: "yes".to_owned(),
            })],
            property_mutations: vec![],
            typed_variable_mutations: vec![TypedContextMutation::Set(ContextBinding {
                key: "typed-write".to_owned(),
                value: ContextValue::I32(4),
            })],
            typed_property_mutations: vec![],
            sample_patch: SampleResultPatch {
                result: None,
                sub_results: vec![],
            },
            output: vec![OutputRecord {
                stream: "OUT".to_owned(),
                value: "marker".to_owned(),
            }],
            diagnostics: vec![],
            cache_observations: vec![],
            class_loader_observations: vec!["loader-1".to_owned()],
            after_state_digest: Sha256Digest::ZERO,
            proposal_digest: Sha256Digest::ZERO,
            rollback: RollbackCapability::Journaled,
        }
    }

    fn open_request(request_id: RequestId) -> JvmRequest {
        JvmRequest {
            schema_version: JVM_CAPABILITY_SCHEMA_VERSION,
            phase: JvmOperationPhase::Handshaking,
            request_id,
            run_id: 99,
            plan_node_id: 0,
            base_context_generation: 0,
            deadline: Deadline::at_unix_millis(100),
            remaining_budget: RemainingBudget::from_millis(1000),
            cancellation: Cancellation::None,
            limits: JvmCapabilityLimits::default(),
            operation: JvmOperation::OpenRun(OpenRun {
                identity: identity(),
                roots: vec![],
                locale: "en-US".to_owned(),
                timezone: "UTC".to_owned(),
                charset: "UTF-8".to_owned(),
                sandbox_identity: None,
                secret_references: vec![SecretReference {
                    handle: SecretHandle::from_bytes([7; 16]),
                    provider_identity: Sha256Digest::ZERO,
                    purpose: "fixture-password".to_owned(),
                    rights: 1,
                    expiry: RemainingBudget::from_millis(1_000),
                }],
            }),
            unknown_fields: vec![],
        }
    }

    fn jsr223_request(request_id: RequestId, generation: ContextGeneration) -> JvmRequest {
        let mut context = snapshot();
        context.generation = generation;
        JvmRequest {
            schema_version: JVM_CAPABILITY_SCHEMA_VERSION,
            phase: JvmOperationPhase::Prepared,
            request_id,
            run_id: 99,
            plan_node_id: 42,
            base_context_generation: generation,
            deadline: Deadline::NONE,
            remaining_budget: RemainingBudget::from_millis(1000),
            cancellation: Cancellation::None,
            limits: JvmCapabilityLimits::default(),
            operation: JvmOperation::ExecuteJsr223(ExecuteJsr223 {
                source: ScriptSource::Inline {
                    language: "groovy".to_owned(),
                    source: "vars.put('x', 'y')".to_owned(),
                },
                cache: CacheRequest {
                    key: ScriptCacheKey::StringScript {
                        language: "groovy".to_owned(),
                        expanded_source_md5: Md5Digest::ZERO,
                        expanded_source_sha256: Sha256Digest::ZERO,
                        cache_key: "".to_owned(),
                    },
                    inline_cache_setting: "".to_owned(),
                    eligible: true,
                    epoch: CacheEpoch {
                        epoch: 1,
                        run_generation: generation,
                        classpath_identity: Sha256Digest::ZERO,
                        helper_identity: Sha256Digest::ZERO,
                        profile_identity: Sha256Digest::ZERO,
                        provider_identity: Sha256Digest::ZERO,
                    },
                },
                context,
            }),
            unknown_fields: vec![],
        }
    }

    fn response_for(request: &JvmRequest) -> JvmResponse {
        let operation = request.operation.code();
        let result = match operation {
            OperationCode::OpenRun => Ok(JvmOperationResult::RunOpened { generation: 0 }),
            OperationCode::ExecuteJsr223 => Ok(JvmOperationResult::Jsr223 {
                value: Some("ok".to_owned()),
                delta: delta(),
            }),
            _ => Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::InvalidMessage,
            )),
        };
        JvmResponse {
            schema_version: JVM_CAPABILITY_SCHEMA_VERSION,
            phase: match operation {
                OperationCode::OpenRun => JvmOperationPhase::Ready,
                OperationCode::CloseRun => JvmOperationPhase::Terminal,
                _ => JvmOperationPhase::Proposed,
            },
            request_id: request.request_id,
            run_id: request.run_id,
            plan_node_id: request.plan_node_id,
            base_context_generation: request.base_context_generation,
            deadline: request.deadline,
            remaining_budget: request.remaining_budget,
            cancellation: Cancellation::None,
            limits: request.limits,
            operation,
            result,
            unknown_fields: vec![],
        }
    }

    #[test]
    fn operation_catalog_is_closed_and_versioned() {
        assert_eq!(JVM_CAPABILITY_SCHEMA, "jvm-capability/2");
        assert_eq!(OperationCode::all().len(), 11);
        assert_eq!(
            OperationCode::JavaSamplerSetup.as_str(),
            "java_sampler_setup"
        );
        assert_eq!(OperationCode::JavaSamplerRun.as_str(), "java_sampler_run");
        assert_eq!(
            OperationCode::JavaSamplerTeardown.as_str(),
            "java_sampler_teardown"
        );
        assert_eq!(OperationCode::JunitRun.as_str(), "junit_run");
    }

    #[test]
    fn request_round_trip_preserves_exact_wire_fields_and_empty_cache_setting() {
        let request = JvmMessage::Request(jsr223_request(1, 0));
        let codec = JvmCodec::default();
        let encoded = codec.encode(&request).expect("request encoding");
        assert_eq!(&encoded[..4], b"JVC2");
        assert_eq!(u16::from_be_bytes([encoded[4], encoded[5]]), 2);
        assert_eq!(encoded[6], JvmMessageKind::Request as u8);
        assert_eq!(encoded[51], JvmOperationPhase::Prepared as u8);
        assert_eq!(
            u16::from_be_bytes([encoded[8], encoded[9]]),
            OperationCode::ExecuteJsr223 as u16
        );
        assert_eq!(
            u64::from_be_bytes(encoded[10..18].try_into().expect("request ID")),
            1
        );
        let decoded = codec.decode(&encoded).expect("request decoding");
        assert_eq!(decoded, request);
    }

    #[test]
    fn operation_result_round_trip_and_redacted_debug() {
        let mut request = jsr223_request(1, 0);
        if let JvmOperation::ExecuteJsr223(operation) = &mut request.operation {
            operation.cache.inline_cache_setting = "inline-secret-setting".to_owned();
        }
        let response = JvmMessage::Response(response_for(&request));
        let encoded = encode_jvm_message(&response).expect("response encoding");
        let decoded = decode_jvm_message(&encoded).expect("response decoding");
        assert_eq!(decoded, response);
        let request_debug = format!("{request:?}");
        assert!(!request_debug.contains("inline-secret-setting"));
        let debug = format!("{response:?}");
        assert!(!debug.contains("vars.put"));
        assert!(!debug.contains("marker"));
    }

    #[test]
    fn strict_unknown_field_rejects_and_negotiated_preservation_round_trips() {
        let mut request = jsr223_request(1, 0);
        request.unknown_fields = vec![OpaqueField {
            tag: 20,
            value: vec![1, 2, 3],
        }];
        assert_eq!(
            JvmCodec::default().encode(&JvmMessage::Request(request.clone())),
            Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::UnknownField
            ))
        );
        let codec = JvmCodec::new(JvmCodecOptions::preserving_unknowns());
        let bytes = codec
            .encode(&JvmMessage::Request(request.clone()))
            .expect("preserving encode");
        assert_eq!(
            codec.decode(&bytes).expect("preserving decode"),
            JvmMessage::Request(request)
        );
    }

    #[test]
    fn operation_unknown_code_is_rejected_without_negotiation() {
        let request = JvmMessage::Request(open_request(1));
        let mut bytes = JvmCodec::default().encode(&request).expect("encoding");
        bytes[8..10].copy_from_slice(&99_u16.to_be_bytes());
        assert_eq!(
            JvmCodec::default().decode(&bytes),
            Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::UnknownOperation
            ))
        );
        bytes[7] |= FLAG_UNKNOWN_OPERATIONS | FLAG_UNKNOWN_FIELDS;
        bytes[58..60].copy_from_slice(&7_u16.to_be_bytes());
        let unknown = JvmCodec::new(JvmCodecOptions::preserving_unknowns())
            .decode(&bytes)
            .expect("unknown operation preservation");
        assert!(matches!(unknown, JvmMessage::UnknownOperation { .. }));
        bytes[58..60].copy_from_slice(&1_u16.to_be_bytes());
        assert_eq!(
            JvmCodec::new(JvmCodecOptions::preserving_unknowns()).decode(&bytes),
            Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::BridgeProtocolOrder
            ))
        );
    }

    #[test]
    fn truncation_trailing_bytes_and_count_boundaries_fail_closed() {
        let bytes = JvmCodec::default()
            .encode(&JvmMessage::Request(open_request(1)))
            .expect("encoding");
        for length in 0..bytes.len() {
            assert_eq!(
                JvmCodec::default().decode(&bytes[..length]),
                Err(JvmCapabilityError::new(JvmCapabilityErrorCode::Truncated))
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            JvmCodec::default().decode(&trailing),
            Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::TrailingBytes
            ))
        );
        let mut limits = JvmCapabilityLimits::default();
        limits.max_message_bytes = JVM_CAPABILITY_HEADER_LEN;
        assert_eq!(limits.max_field_bytes(), 0);
        limits.max_message_bytes = JVM_CAPABILITY_HEADER_LEN + 7;
        assert_eq!(limits.max_field_bytes(), 7);
        limits.max_message_bytes = JVM_CAPABILITY_MAX_MESSAGE_BYTES;
        assert_eq!(limits.max_field_bytes(), JVM_CAPABILITY_MAX_FIELD_BYTES);
        limits.max_message_bytes = JVM_CAPABILITY_HEADER_LEN;
        let error = JvmCodec::new(JvmCodecOptions {
            limits,
            preservation: JvmPreservationNegotiation::default(),
        })
        .encode(&JvmMessage::Request(open_request(1)));
        assert_eq!(
            error,
            Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit))
        );
    }

    #[test]
    fn context_delta_is_prepared_and_rejects_stale_or_duplicate_keys() {
        let base = snapshot();
        let mut invalid = delta();
        invalid
            .variable_mutations
            .push(ContextMutation::Delete("written".to_owned()));
        assert_eq!(
            base.apply_delta(&invalid, &JvmCapabilityLimits::default()),
            Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::AtomicDeltaRejected
            ))
        );
        assert_eq!(base.variables.len(), 1);
        let mut stale = delta();
        stale.base_generation = 9;
        assert_eq!(
            base.apply_delta(&stale, &JvmCapabilityLimits::default()),
            Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::StaleContextGeneration
            ))
        );
        let applied = base
            .apply_delta(&delta(), &JvmCapabilityLimits::default())
            .expect("valid delta");
        assert_eq!(applied.generation, 1);
        assert_eq!(applied.variables[1].key, "written");
    }

    #[test]
    fn prepared_delta_has_explicit_commit_abort_poison_and_terminal_phases() {
        let base = snapshot();
        let limits = JvmCapabilityLimits::default();
        let mut aborted = base.prepare_delta(delta(), &limits).expect("prepare delta");
        assert_eq!(aborted.phase(), DeltaPhase::Prepared);
        assert_eq!(aborted.delta(), &delta());
        aborted.abort().expect("abort prepared delta");
        assert_eq!(aborted.phase(), DeltaPhase::Aborted);
        assert_eq!(
            aborted.abort(),
            Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::TerminalMessage
            ))
        );

        let mut committed = snapshot()
            .prepare_delta(delta(), &limits)
            .expect("prepare delta");
        let mut next = snapshot();
        committed.commit(&mut next).expect("commit prepared delta");
        assert_eq!(committed.phase(), DeltaPhase::Committed);
        assert_eq!(next.generation, 1);
        committed.terminal();
        assert_eq!(committed.phase(), DeltaPhase::Terminal);

        let mut poisoned = snapshot()
            .prepare_delta(delta(), &limits)
            .expect("prepare delta");
        let mut stale_target = snapshot();
        stale_target.generation = 1;
        assert_eq!(
            poisoned.commit(&mut stale_target),
            Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::StaleContextGeneration
            ))
        );
        assert_eq!(poisoned.phase(), DeltaPhase::Poisoned);
    }

    #[test]
    fn remaining_budget_is_bounded_without_reading_a_clock_and_secrets_are_redacted() {
        assert_eq!(RemainingBudget::UNBOUNDED.child(25).as_millis(), Some(25));
        assert_eq!(
            RemainingBudget::from_millis(10).child(25).as_millis(),
            Some(10)
        );
        assert_eq!(
            RemainingBudget::from_millis(10).consume(7).as_millis(),
            Some(3)
        );
        assert!(RemainingBudget::from_millis(10).consume(10).is_exhausted());
        assert_eq!(
            RemainingBudget::UNBOUNDED.consume(u64::MAX),
            RemainingBudget::UNBOUNDED
        );

        let reference = SecretReference {
            handle: SecretHandle::from_bytes([7; 16]),
            provider_identity: Sha256Digest::ZERO,
            purpose: "password-value-must-not-leak".to_owned(),
            rights: 1,
            expiry: RemainingBudget::from_millis(1_000),
        };
        let debug = format!("{reference:?}");
        assert!(!debug.contains("password-value-must-not-leak"));
        assert!(!debug.contains("7"));
    }

    #[test]
    fn deadline_budget_ceiling_and_phase_kind_are_wire_checked() {
        let mut request = jsr223_request(1, 0);
        request.remaining_budget =
            RemainingBudget::from_millis(JVM_CAPABILITY_MAX_DEADLINE_MILLIS.saturating_add(1));
        assert_eq!(
            JvmCodec::default().encode(&JvmMessage::Request(request)),
            Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::DeadlineInvalid
            ))
        );
        let mut request = jsr223_request(2, 0);
        request.phase = JvmOperationPhase::Executing;
        let bytes = JvmCodec::default()
            .encode(&JvmMessage::Request(request.clone()))
            .expect("phase encoding");
        assert_eq!(bytes[6], JvmMessageKind::Request as u8);
        assert_eq!(bytes[51], JvmOperationPhase::Executing as u8);
        assert_eq!(
            JvmCodec::default().decode(&bytes),
            Ok(JvmMessage::Request(request))
        );
    }

    #[test]
    fn complete_result_projection_round_trips_and_depth_is_bounded() {
        let mut request = jsr223_request(1, 0);
        if let JvmOperation::ExecuteJsr223(operation) = &mut request.operation {
            operation.context.current_result = Some(sample_result());
            operation.context.previous_result = Some(sample_result());
        } else {
            panic!("fixture must be a JSR223 request");
        }
        let message = JvmMessage::Request(request.clone());
        let codec = JvmCodec::default();
        let encoded = codec.encode(&message).expect("result projection encoding");
        assert_eq!(
            codec.decode(&encoded).expect("result projection decoding"),
            message
        );

        if let JvmOperation::ExecuteJsr223(operation) = &mut request.operation {
            operation.context.current_result = Some(sample_result());
            operation
                .context
                .current_result
                .as_mut()
                .expect("result")
                .depth = JVM_CAPABILITY_MAX_RESULT_DEPTH + 1;
        }
        assert_eq!(
            codec.encode(&JvmMessage::Request(request)),
            Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit))
        );
    }

    #[test]
    fn typed_context_depth_and_node_limits_apply_during_decode() {
        let mut nested = ContextValue::Null;
        for _ in 0..4 {
            nested = ContextValue::List(vec![nested]);
        }
        let encoded = encode_context_value(&nested, &JvmCapabilityLimits::default())
            .expect("nested value encoding");
        let mut limits = JvmCapabilityLimits::default();
        limits.max_result_depth = 2;
        assert_eq!(
            decode_context_value(&encoded, &limits),
            Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit))
        );
    }

    #[test]
    fn duplicate_artifact_ordinals_are_rejected() {
        let discovery = PluginDiscovery {
            artifacts: vec![
                PluginArtifact {
                    ordinal: 1,
                    role: ClasspathRole::LibExt,
                    path_identity: Sha256Digest::ZERO,
                    content_sha256: Sha256Digest::ZERO,
                    version: "1".to_owned(),
                    license_notice: LicenseNoticeStatus::Declared,
                    dependencies: vec![],
                    aliases: vec!["a".to_owned()],
                    capabilities: vec![],
                },
                PluginArtifact {
                    ordinal: 1,
                    role: ClasspathRole::UserClasspath,
                    path_identity: Sha256Digest::ZERO,
                    content_sha256: Sha256Digest::ZERO,
                    version: "2".to_owned(),
                    license_notice: LicenseNoticeStatus::Declared,
                    dependencies: vec![],
                    aliases: vec!["b".to_owned()],
                    capabilities: vec![],
                },
            ],
            aliases: vec![],
            declared_order: vec![1, 1],
            observed_order: vec![1, 1],
            resolution_order: vec![1, 1],
        };
        assert_eq!(
            encode_plugin_discovery(&discovery, &JvmCapabilityLimits::default()),
            Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::DuplicateIdentity
            ))
        );
    }

    #[test]
    fn classpath_ordinals_and_negotiated_limits_are_enforced_on_encode() {
        let mut duplicate = open_request(1);
        if let JvmOperation::OpenRun(operation) = &mut duplicate.operation {
            let entry = operation.identity.classpath.entries[0].clone();
            operation.identity.classpath.entries.push(entry);
        }
        assert_eq!(
            JvmCodec::default().encode(&JvmMessage::Request(duplicate)),
            Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::DuplicateIdentity
            ))
        );

        let mut dependency_limited = open_request(2);
        dependency_limited.limits.max_plugin_dependencies = 1;
        if let JvmOperation::OpenRun(operation) = &mut dependency_limited.operation {
            operation.identity.classpath.entries[0].dependencies = vec![1, 2];
        }
        assert_eq!(
            JvmCodec::default().encode(&JvmMessage::Request(dependency_limited)),
            Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit))
        );

        let mut byte_limited = open_request(3);
        byte_limited.limits.max_classpath_bytes = 1;
        if let JvmOperation::OpenRun(operation) = &mut byte_limited.operation {
            operation.identity.classpath.entries[0].byte_length = 2;
        }
        assert_eq!(
            JvmCodec::default().encode(&JvmMessage::Request(byte_limited)),
            Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit))
        );

        let invalid = JvmCapabilityLimits {
            max_classpath_bytes: JVM_CAPABILITY_MAX_CLASSPATH_BYTES + 1,
            ..JvmCapabilityLimits::default()
        };
        assert_eq!(
            invalid.validate(),
            Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit))
        );
        let invalid = JvmCapabilityLimits {
            max_plugin_dependencies: JVM_CAPABILITY_MAX_PLUGIN_ALIASES + 1,
            ..JvmCapabilityLimits::default()
        };
        assert_eq!(
            invalid.validate(),
            Err(JvmCapabilityError::new(JvmCapabilityErrorCode::BridgeLimit))
        );
    }

    #[test]
    fn plugin_alias_ambiguity_preserves_all_ordered_candidates() {
        let discovery = PluginDiscovery {
            artifacts: vec![],
            aliases: vec![AliasBinding {
                alias: "OrderedSampler".to_owned(),
                declarations: vec![
                    PluginAlias {
                        alias: "OrderedSampler".to_owned(),
                        artifact_ordinal: 2,
                        declaration_ordinal: 0,
                    },
                    PluginAlias {
                        alias: "OrderedSampler".to_owned(),
                        artifact_ordinal: 1,
                        declaration_ordinal: 1,
                    },
                ],
                resolution: AliasResolution::Ambiguous {
                    candidates: vec![2, 1],
                },
            }],
            declared_order: vec![2, 1],
            observed_order: vec![1, 2],
            resolution_order: vec![2, 1],
        };
        let bytes = encode_plugin_discovery(&discovery, &JvmCapabilityLimits::default())
            .expect("plugin encoding");
        assert_eq!(
            decode_plugin_discovery(&bytes, &JvmCapabilityLimits::default())
                .expect("plugin decoding"),
            discovery
        );
    }

    #[test]
    fn session_enforces_lifecycle_duplicate_ids_generation_and_close() {
        let open = open_request(1);
        let mut session = JvmSession::new();
        session.accept_request_at(&open, 99).expect("open request");
        session
            .accept_response(&response_for(&open))
            .expect("open response");
        let run = jsr223_request(2, 0);
        session.accept_request(&run).expect("script request");
        session
            .accept_response(&response_for(&run))
            .expect("script response");
        session.commit_generation(0).expect("commit generation");
        assert_eq!(session.generation(), 1);
        assert_eq!(
            session.accept_request(&run),
            Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::DuplicateRequestId
            ))
        );
        let mut close = open_request(3);
        close.operation = JvmOperation::CloseRun(CloseRun {
            reason: CloseReason::Completed,
            final_generation: 1,
        });
        close.phase = JvmOperationPhase::Closing;
        close.base_context_generation = 1;
        session.accept_request(&close).expect("close request");
        let mut close_response = response_for(&close);
        close_response.result = Ok(JvmOperationResult::Closed {
            generation: 1,
            cache_entries: 0,
        });
        session
            .accept_response(&close_response)
            .expect("close response");
        assert_eq!(session.phase(), JvmSessionPhase::Terminal);
        assert_eq!(
            session.accept_request(&open_request(4)),
            Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::TerminalMessage
            ))
        );
    }

    #[test]
    fn cancellation_and_deadline_fail_the_worker_generation() {
        let mut cancelled = open_request(1);
        cancelled.cancellation = Cancellation::Requested;
        let mut session = JvmSession::new();
        assert_eq!(
            session.accept_request_at(&cancelled, 0),
            Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::BridgeCancelled
            ))
        );
        assert_eq!(session.phase(), JvmSessionPhase::Failed);
        let mut expired = open_request(1);
        expired.deadline = Deadline::at_unix_millis(10);
        let mut session = JvmSession::new();
        assert_eq!(
            session.accept_request_at(&expired, 10),
            Err(JvmCapabilityError::new(
                JvmCapabilityErrorCode::BridgeDeadlineExceeded
            ))
        );
    }
}

/// Convenience encoding function for callers that do not retain a codec.
pub fn encode_jvm_message(message: &JvmMessage) -> Result<Vec<u8>, JvmCapabilityError> {
    JvmCodec::default().encode(message)
}

/// Convenience decoding function using strict preservation rules.
pub fn decode_jvm_message(bytes: &[u8]) -> Result<JvmMessage, JvmCapabilityError> {
    JvmCodec::default().decode(bytes)
}
