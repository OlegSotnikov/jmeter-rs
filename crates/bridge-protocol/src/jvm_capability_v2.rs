// SPDX-License-Identifier: Apache-2.0
//! Pure data contracts for Decision 0005's `jvm-capability/2` boundary.
//!
//! This module deliberately contains no transport, clock, process, JVM, or
//! filesystem code.  It owns the canonical JVC2 envelope, the hello
//! transcript, bounded semantic execution replies, and the worker/run state
//! machine. The older [`crate::legacy_jvm_capability`] module is kept separate
//! for migration diagnostics and is not used by this schema.

#![allow(missing_docs)]

use core::fmt;
use core::num::{NonZeroU32, NonZeroU64};
use sha2::{Digest as ShaDigest, Sha256};
use std::collections::BTreeSet;

/// The negotiated operation schema name.
pub const JVM_CAPABILITY_V2_SCHEMA: &str = "jvm-capability/2";
/// The numeric schema version.
pub const JVM_CAPABILITY_V2_SCHEMA_VERSION: u16 = 2;
/// The canonical inner-envelope marker.
pub const JVM_CAPABILITY_V2_MAGIC: [u8; 4] = *b"JVC2";
/// The fixed inner-envelope size, including all digest fields.
pub const JVM_CAPABILITY_V2_HEADER_LEN: usize = 224;
/// The outer-frame ceiling also bounds a complete inner message.
pub const JVM_CAPABILITY_V2_OUTER_FRAME_MAX_BYTES: usize = 16 * 1024 * 1024;
/// The initial complete JVC2-message ceiling.
pub const JVM_CAPABILITY_V2_MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;
/// The maximum canonical field value.
pub const JVM_CAPABILITY_V2_MAX_FIELD_BYTES: usize = 1024 * 1024;
/// The maximum number of semantic fields in one message body.
pub const JVM_CAPABILITY_V2_MAX_FIELDS: usize = 256;
/// The maximum number of negotiated extension fields in one body.
pub const JVM_CAPABILITY_V2_MAX_EXTENSIONS: usize = 64;
/// The maximum UTF-8 value used by this schema.
pub const JVM_CAPABILITY_V2_MAX_TEXT_BYTES: usize = 64 * 1024;
/// The maximum script source value.
pub const JVM_CAPABILITY_V2_MAX_SCRIPT_BYTES: usize = 512 * 1024;
/// The maximum operation deadline.
pub const JVM_CAPABILITY_V2_MAX_DEADLINE_MILLIS: u64 = 24 * 60 * 60 * 1000;
/// The minimum extension tag.
pub const JVM_CAPABILITY_V2_EXTENSION_TAG_MIN: u16 = 0x8000;
/// The largest usable extension tag; `0xffff` is reserved.
pub const JVM_CAPABILITY_V2_EXTENSION_TAG_MAX: u16 = 0xfffe;

const FLAG_EXTENSIONS: u16 = 0x0001;
const FLAG_CANCELLATION: u16 = 0x0002;
const KNOWN_FLAGS: u16 = FLAG_EXTENSIONS | FLAG_CANCELLATION;
const DOMAIN_BODY: &[u8] = b"jvc2/body\0";
const DOMAIN_CHAIN_REQUEST: &[u8] = b"jvc2/chain/request\0";
const DOMAIN_CHAIN_RESPONSE: &[u8] = b"jvc2/chain/response\0";
const DOMAIN_CHAIN_CONTROL: &[u8] = b"jvc2/chain/control\0";
const DOMAIN_TRANSCRIPT: &[u8] = b"jvc2/hello-transcript\0";
const DOMAIN_IDENTITY: &[u8] = b"jvc2/identity\0";
const DOMAIN_REPLY: &[u8] = b"jvc2/reply\0";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum V2ErrorCode {
    Version = 1,
    Phase = 2,
    Sequence = 3,
    Digest = 4,
    UnknownField = 5,
    UnknownOperation = 6,
    InvalidMessage = 7,
    Limit = 8,
    Identity = 9,
    Transaction = 10,
    Conflict = 11,
    Poisoned = 12,
    Terminal = 13,
    Deadline = 14,
    Cancelled = 15,
    Handle = 16,
    Reply = 17,
    Utf8 = 18,
    Truncated = 19,
    TrailingBytes = 20,
}

impl V2ErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Version => "bridge.protocol.version",
            Self::Phase => "bridge.protocol.phase",
            Self::Sequence => "bridge.protocol.sequence",
            Self::Digest => "bridge.protocol.digest",
            Self::UnknownField => "bridge.protocol.unknown-field",
            Self::UnknownOperation => "bridge.protocol.unknown-operation",
            Self::InvalidMessage => "bridge.protocol.message.invalid",
            Self::Limit => "bridge.limit",
            Self::Identity => "bridge.identity.invalid",
            Self::Transaction => "bridge.transaction.invalid",
            Self::Conflict => "bridge.transaction.conflict",
            Self::Poisoned => "bridge.worker.poisoned",
            Self::Terminal => "bridge.terminal",
            Self::Deadline => "bridge.deadline.invalid",
            Self::Cancelled => "bridge.cancelled",
            Self::Handle => "bridge.handle.invalid",
            Self::Reply => "bridge.execution-reply.invalid",
            Self::Utf8 => "bridge.text.utf8",
            Self::Truncated => "bridge.message.truncated",
            Self::TrailingBytes => "bridge.message.trailing-bytes",
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct V2Error {
    code: V2ErrorCode,
    detail: Option<String>,
}

impl V2Error {
    pub const fn new(code: V2ErrorCode) -> Self {
        Self { code, detail: None }
    }

    pub fn with_detail(code: V2ErrorCode, detail: impl Into<String>) -> Self {
        let mut detail = detail.into();
        detail.truncate(JVM_CAPABILITY_V2_MAX_TEXT_BYTES);
        Self {
            code,
            detail: Some(detail),
        }
    }

    pub const fn code(&self) -> V2ErrorCode {
        self.code
    }
}

impl fmt::Debug for V2Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V2Error")
            .field("code", &self.code)
            .field("detail", &"<redacted>")
            .finish()
    }
}

impl fmt::Display for V2Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for V2Error {}

macro_rules! fixed_id {
    ($name:ident, $len:expr) => {
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; $len]);

        impl $name {
            pub const ZERO: Self = Self([0; $len]);

            pub const fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(self) -> [u8; $len] {
                self.0
            }

            pub fn is_zero(self) -> bool {
                self.0.iter().all(|byte| *byte == 0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(stringify!($name))
            }
        }
    };
}

fixed_id!(SessionId, 16);
fixed_id!(TransactionId, 16);
fixed_id!(RunId, 16);
fixed_id!(ObjectHandleId, 16);
fixed_id!(Nonce, 32);
fixed_id!(Sha256Digest, 32);

impl Sha256Digest {
    pub fn hash(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Self(hasher.finalize().into())
    }

    pub fn from_hex(value: &str) -> Result<Self, V2Error> {
        if value.len() != 64 {
            return Err(V2Error::new(V2ErrorCode::Identity));
        }
        let mut bytes = [0; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            let offset = index * 2;
            *byte = (hex_digit(value.as_bytes()[offset])? << 4)
                | hex_digit(value.as_bytes()[offset + 1])?;
        }
        Ok(Self(bytes))
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

pub type SnapshotDigest = Sha256Digest;
pub type ProposalDigest = Sha256Digest;
pub type ChainDigest = Sha256Digest;
pub type MatrixDigest = Sha256Digest;
pub type ModuleDigest = Sha256Digest;

fn hex_digit(value: u8) -> Result<u8, V2Error> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(V2Error::new(V2ErrorCode::Identity)),
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum MessageKind {
    Request = 1,
    Response = 2,
    Control = 3,
}

impl MessageKind {
    fn from_wire(value: u8) -> Result<Self, V2Error> {
        match value {
            1 => Ok(Self::Request),
            2 => Ok(Self::Response),
            3 => Ok(Self::Control),
            _ => Err(V2Error::new(V2ErrorCode::InvalidMessage)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum WirePhase {
    Hello = 1,
    Open = 2,
    Prepare = 3,
    Prepared = 4,
    Execute = 5,
    Proposed = 6,
    Commit = 7,
    Committed = 8,
    Abort = 9,
    Aborted = 10,
    Poison = 11,
    Close = 12,
    Error = 13,
    Terminal = 14,
}

impl WirePhase {
    fn from_wire(value: u8) -> Result<Self, V2Error> {
        match value {
            1 => Ok(Self::Hello),
            2 => Ok(Self::Open),
            3 => Ok(Self::Prepare),
            4 => Ok(Self::Prepared),
            5 => Ok(Self::Execute),
            6 => Ok(Self::Proposed),
            7 => Ok(Self::Commit),
            8 => Ok(Self::Committed),
            9 => Ok(Self::Abort),
            10 => Ok(Self::Aborted),
            11 => Ok(Self::Poison),
            12 => Ok(Self::Close),
            13 => Ok(Self::Error),
            14 => Ok(Self::Terminal),
            _ => Err(V2Error::new(V2ErrorCode::Phase)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum OperationKind {
    Hello = 0,
    OpenRun = 1,
    DiscoverProviders = 2,
    ExpandFunction = 3,
    ExecuteJsr223 = 4,
    JavaSamplerSetup = 5,
    JavaSamplerRun = 6,
    JavaSamplerTeardown = 7,
    JunitRun = 8,
    ExecutePluginElement = 9,
    ExpandPluginFunction = 10,
    ExecutePackage = 11,
    CloseRun = 12,
}

impl OperationKind {
    fn from_wire(value: u16) -> Result<Self, V2Error> {
        match value {
            0 => Ok(Self::Hello),
            1 => Ok(Self::OpenRun),
            2 => Ok(Self::DiscoverProviders),
            3 => Ok(Self::ExpandFunction),
            4 => Ok(Self::ExecuteJsr223),
            5 => Ok(Self::JavaSamplerSetup),
            6 => Ok(Self::JavaSamplerRun),
            7 => Ok(Self::JavaSamplerTeardown),
            8 => Ok(Self::JunitRun),
            9 => Ok(Self::ExecutePluginElement),
            10 => Ok(Self::ExpandPluginFunction),
            11 => Ok(Self::ExecutePackage),
            12 => Ok(Self::CloseRun),
            _ => Err(V2Error::new(V2ErrorCode::UnknownOperation)),
        }
    }

    fn is_transactional(self) -> bool {
        !matches!(self, Self::Hello | Self::OpenRun | Self::CloseRun)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum CancellationState {
    None = 0,
    Requested = 1,
    Stopped = 2,
    Poisoned = 3,
}

impl CancellationState {
    fn from_wire(value: u8) -> Result<Self, V2Error> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::Requested),
            2 => Ok(Self::Stopped),
            3 => Ok(Self::Poisoned),
            _ => Err(V2Error::new(V2ErrorCode::Cancelled)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum Role {
    Capability = 1,
    RmiController = 2,
    RmiWorker = 3,
    Http = 4,
}

impl Role {
    pub fn from_wire(value: u8) -> Result<Self, V2Error> {
        match value {
            1 => Ok(Self::Capability),
            2 => Ok(Self::RmiController),
            3 => Ok(Self::RmiWorker),
            4 => Ok(Self::Http),
            _ => Err(V2Error::new(V2ErrorCode::Identity)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum AuthorityExtent {
    Package = 1,
    WholeEngine = 2,
}

impl AuthorityExtent {
    pub fn from_wire(value: u8) -> Result<Self, V2Error> {
        match value {
            1 => Ok(Self::Package),
            2 => Ok(Self::WholeEngine),
            _ => Err(V2Error::new(V2ErrorCode::InvalidMessage)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum ControlAction {
    Continue = 1,
    StartNextIteration = 2,
    BreakCurrentLoop = 3,
    StopThread = 4,
    StopTestGraceful = 5,
    StopTestImmediate = 6,
}

impl ControlAction {
    fn from_wire(value: u8) -> Result<Self, V2Error> {
        match value {
            1 => Ok(Self::Continue),
            2 => Ok(Self::StartNextIteration),
            3 => Ok(Self::BreakCurrentLoop),
            4 => Ok(Self::StopThread),
            5 => Ok(Self::StopTestGraceful),
            6 => Ok(Self::StopTestImmediate),
            _ => Err(V2Error::new(V2ErrorCode::Reply)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum PhaseKind {
    RunOpen = 1,
    ProviderDiscovery = 2,
    FunctionExpansion = 3,
    TestStarted = 4,
    ThreadStarted = 5,
    SamplerSetup = 6,
    Configuration = 7,
    PreProcessor = 8,
    Timer = 9,
    Sampler = 10,
    PostProcessor = 11,
    Assertion = 12,
    Listener = 13,
    ResultRouting = 14,
    SamplerTeardown = 15,
    ThreadFinished = 16,
    TestFinished = 17,
    RunClose = 18,
}

impl PhaseKind {
    fn from_wire(value: u8) -> Result<Self, V2Error> {
        match value {
            1 => Ok(Self::RunOpen),
            2 => Ok(Self::ProviderDiscovery),
            3 => Ok(Self::FunctionExpansion),
            4 => Ok(Self::TestStarted),
            5 => Ok(Self::ThreadStarted),
            6 => Ok(Self::SamplerSetup),
            7 => Ok(Self::Configuration),
            8 => Ok(Self::PreProcessor),
            9 => Ok(Self::Timer),
            10 => Ok(Self::Sampler),
            11 => Ok(Self::PostProcessor),
            12 => Ok(Self::Assertion),
            13 => Ok(Self::Listener),
            14 => Ok(Self::ResultRouting),
            15 => Ok(Self::SamplerTeardown),
            16 => Ok(Self::ThreadFinished),
            17 => Ok(Self::TestFinished),
            18 => Ok(Self::RunClose),
            _ => Err(V2Error::new(V2ErrorCode::Reply)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum PhaseDisposition {
    Completed = 1,
    ZeroDelay = 2,
    NullResult = 3,
    FailedSample = 4,
    AssertionFailure = 5,
    AssertionError = 6,
    SwallowedCheckedError = 7,
    LoggedListenerError = 8,
    ThreadRuntimeFailure = 9,
    PinnedJavaSamplerFailure = 10,
}

impl PhaseDisposition {
    fn from_wire(value: u8) -> Result<Self, V2Error> {
        match value {
            1 => Ok(Self::Completed),
            2 => Ok(Self::ZeroDelay),
            3 => Ok(Self::NullResult),
            4 => Ok(Self::FailedSample),
            5 => Ok(Self::AssertionFailure),
            6 => Ok(Self::AssertionError),
            7 => Ok(Self::SwallowedCheckedError),
            8 => Ok(Self::LoggedListenerError),
            9 => Ok(Self::ThreadRuntimeFailure),
            10 => Ok(Self::PinnedJavaSamplerFailure),
            _ => Err(V2Error::new(V2ErrorCode::Reply)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum RollbackCapability {
    NotExecuted = 1,
    Journaled = 2,
    Unsafe = 3,
}

impl RollbackCapability {
    pub fn from_wire(value: u8) -> Result<Self, V2Error> {
        match value {
            1 => Ok(Self::NotExecuted),
            2 => Ok(Self::Journaled),
            3 => Ok(Self::Unsafe),
            _ => Err(V2Error::new(V2ErrorCode::Transaction)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum MayHaveExecuted {
    No = 1,
    Yes = 2,
    Unknown = 3,
}

impl MayHaveExecuted {
    fn from_wire(value: u8) -> Result<Self, V2Error> {
        match value {
            1 => Ok(Self::No),
            2 => Ok(Self::Yes),
            3 => Ok(Self::Unknown),
            _ => Err(V2Error::new(V2ErrorCode::Reply)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum PoisonReason {
    ExecutionUncertain = 1,
    ProtocolFailure = 2,
    DigestMismatch = 3,
    OutputLimit = 4,
    ContainmentLost = 5,
    CancelledAfterStart = 6,
    InvalidProposal = 7,
}

impl PoisonReason {
    fn from_wire(value: u8) -> Result<Self, V2Error> {
        match value {
            1 => Ok(Self::ExecutionUncertain),
            2 => Ok(Self::ProtocolFailure),
            3 => Ok(Self::DigestMismatch),
            4 => Ok(Self::OutputLimit),
            5 => Ok(Self::ContainmentLost),
            6 => Ok(Self::CancelledAfterStart),
            7 => Ok(Self::InvalidProposal),
            _ => Err(V2Error::new(V2ErrorCode::Poisoned)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum CloseMode {
    Normal = 1,
    ContainmentOnly = 2,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum TerminalOutcome {
    Success = 1,
    Failed = 2,
    Cancelled = 3,
    Poisoned = 4,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum ReferenceKind {
    Result = 1,
    Artifact = 2,
    Diagnostic = 3,
    ResponseBody = 4,
    File = 5,
}

impl ReferenceKind {
    fn from_wire(value: u8) -> Result<Self, V2Error> {
        match value {
            1 => Ok(Self::Result),
            2 => Ok(Self::Artifact),
            3 => Ok(Self::Diagnostic),
            4 => Ok(Self::ResponseBody),
            5 => Ok(Self::File),
            _ => Err(V2Error::new(V2ErrorCode::Reply)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DeadlineBudget(u64);

impl DeadlineBudget {
    pub fn from_millis(value: u64) -> Result<Self, V2Error> {
        if value > JVM_CAPABILITY_V2_MAX_DEADLINE_MILLIS {
            return Err(V2Error::new(V2ErrorCode::Deadline));
        }
        Ok(Self(value))
    }

    pub const fn remaining_millis(self) -> u64 {
        self.0
    }

    pub const fn expired(self) -> bool {
        self.0 == 0
    }

    pub const fn consume(self, elapsed_millis: u64) -> Self {
        Self(self.0.saturating_sub(elapsed_millis))
    }

    pub const fn child(self, maximum_millis: u64) -> Self {
        Self(if self.0 < maximum_millis {
            self.0
        } else {
            maximum_millis
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JvmCapabilityV2Limits {
    pub max_message_bytes: usize,
    pub max_fields: usize,
    pub max_extensions: usize,
    pub max_field_bytes: usize,
    pub max_text_bytes: usize,
    pub max_script_bytes: usize,
    pub max_operations: usize,
    pub max_phase_outcomes: usize,
    pub max_callbacks: usize,
    pub max_references: usize,
    pub max_diagnostics: usize,
    pub max_capabilities: usize,
    pub max_hello_text_bytes: usize,
    pub max_value_depth: usize,
    pub max_value_nodes: usize,
    pub max_active_handles: usize,
    pub max_handles_per_run: usize,
    pub max_lease_operations: usize,
}

impl Default for JvmCapabilityV2Limits {
    fn default() -> Self {
        Self {
            max_message_bytes: JVM_CAPABILITY_V2_MAX_MESSAGE_BYTES,
            max_fields: JVM_CAPABILITY_V2_MAX_FIELDS,
            max_extensions: JVM_CAPABILITY_V2_MAX_EXTENSIONS,
            max_field_bytes: JVM_CAPABILITY_V2_MAX_FIELD_BYTES,
            max_text_bytes: JVM_CAPABILITY_V2_MAX_TEXT_BYTES,
            max_script_bytes: JVM_CAPABILITY_V2_MAX_SCRIPT_BYTES,
            max_operations: 65_536,
            max_phase_outcomes: 16_384,
            max_callbacks: 16_384,
            max_references: 16_384,
            max_diagnostics: 1_024,
            max_capabilities: 256,
            max_hello_text_bytes: 4 * 1024,
            max_value_depth: 32,
            max_value_nodes: 8_192,
            max_active_handles: 8_192,
            max_handles_per_run: 65_536,
            max_lease_operations: 1_024,
        }
    }
}

impl JvmCapabilityV2Limits {
    pub fn validate(self) -> Result<(), V2Error> {
        let valid = self.max_message_bytes >= JVM_CAPABILITY_V2_HEADER_LEN
            && self.max_message_bytes <= JVM_CAPABILITY_V2_MAX_MESSAGE_BYTES
            && self.max_message_bytes <= JVM_CAPABILITY_V2_OUTER_FRAME_MAX_BYTES
            && self.max_fields > 0
            && self.max_fields <= JVM_CAPABILITY_V2_MAX_FIELDS
            && self.max_extensions <= JVM_CAPABILITY_V2_MAX_EXTENSIONS
            && self.max_field_bytes > 0
            && self.max_field_bytes <= JVM_CAPABILITY_V2_MAX_FIELD_BYTES
            && self.max_text_bytes > 0
            && self.max_text_bytes <= JVM_CAPABILITY_V2_MAX_TEXT_BYTES
            && self.max_script_bytes > 0
            && self.max_script_bytes <= JVM_CAPABILITY_V2_MAX_SCRIPT_BYTES
            && self.max_operations > 0
            && self.max_operations <= 65_536
            && self.max_phase_outcomes > 0
            && self.max_callbacks > 0
            && self.max_references > 0
            && self.max_diagnostics > 0
            && self.max_capabilities > 0
            && self.max_hello_text_bytes > 0
            && self.max_hello_text_bytes <= self.max_text_bytes
            && self.max_value_depth > 0
            && self.max_value_depth <= 32
            && self.max_value_nodes > 0
            && self.max_value_nodes <= 8_192
            && self.max_active_handles > 0
            && self.max_active_handles <= 8_192
            && self.max_handles_per_run > 0
            && self.max_handles_per_run <= 65_536
            && self.max_lease_operations > 0
            && self.max_lease_operations <= 1_024;
        if valid {
            Ok(())
        } else {
            Err(V2Error::new(V2ErrorCode::Limit))
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ProfileIdentity {
    pub id: String,
    pub version: u32,
    pub sha256: Sha256Digest,
}

#[derive(Clone, Eq, PartialEq)]
pub struct HelperIdentity {
    pub source_sha256: Sha256Digest,
    pub build_sha256: Sha256Digest,
    pub compiler: String,
    pub schema_sha256: Sha256Digest,
    pub role: Role,
    pub module_digest: ModuleDigest,
}

impl fmt::Debug for HelperIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HelperIdentity")
            .field("source_sha256", &self.source_sha256)
            .field("build_sha256", &self.build_sha256)
            .field("compiler", &self.compiler)
            .field("schema_sha256", &self.schema_sha256)
            .field("role", &self.role)
            .field("module_digest", &self.module_digest)
            .finish()
    }
}

impl ProfileIdentity {
    pub fn validate(&self, limits: JvmCapabilityV2Limits) -> Result<(), V2Error> {
        validate_text(&self.id, limits.max_hello_text_bytes)
    }
}

impl HelperIdentity {
    pub fn validate(&self, limits: JvmCapabilityV2Limits) -> Result<(), V2Error> {
        validate_text(&self.compiler, limits.max_hello_text_bytes)
    }

    pub fn canonical_digest(&self) -> Result<Sha256Digest, V2Error> {
        let mut writer = WireWriter::new();
        encode_helper_identity(self, &mut writer)?;
        Ok(domain_digest(DOMAIN_IDENTITY, &writer.finish()))
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum ObjectKind {
    Context = 1,
    Variables = 2,
    Properties = 3,
    Sampler = 4,
    PreviousSampler = 5,
    Result = 6,
    PreviousResult = 7,
    Thread = 8,
    ThreadGroup = 9,
    Engine = 10,
    SamplerContext = 11,
    Logger = 12,
    Output = 13,
    ParentResult = 14,
    SaveConfiguration = 15,
    ProviderObject = 16,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct HandleRights(u16);

impl HandleRights {
    pub const READ: Self = Self(0x0001);
    pub const WRITE: Self = Self(0x0002);
    pub const INVOKE: Self = Self(0x0004);
    pub const RELEASE: Self = Self(0x0008);

    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn bits(self) -> u16 {
        self.0
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn from_bits(bits: u16) -> Option<Self> {
        if bits & !(Self::READ.0 | Self::WRITE.0 | Self::INVOKE.0 | Self::RELEASE.0) == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandleOwner {
    pub role: Role,
    pub worker_id: u32,
    pub session_id: SessionId,
    pub run_id: RunId,
    pub run_generation: u64,
    pub class_loader_generation: u64,
    pub user_scope: Option<u64>,
    pub allocation_ordinal: NonZeroU32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectHandle {
    pub id: ObjectHandleId,
    pub kind: ObjectKind,
    pub owner: HandleOwner,
    pub class_identity_sha256: Sha256Digest,
    pub rights: HandleRights,
    pub lease_operations: u32,
}

impl ObjectHandle {
    pub fn validate(&self, limits: JvmCapabilityV2Limits) -> Result<(), V2Error> {
        if self.id == ObjectHandleId::ZERO
            || self.owner.session_id == SessionId::ZERO
            || self.owner.run_id == RunId::ZERO
            || self.owner.allocation_ordinal.get() == 0
            || self.lease_operations == 0
            || self.lease_operations as usize > limits.max_lease_operations
            || HandleRights::from_bits(self.rights.bits()).is_none()
        {
            return Err(V2Error::new(V2ErrorCode::Handle));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandleLedger {
    active: BTreeSet<ObjectHandleId>,
    allocated: usize,
}

impl Default for HandleLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl HandleLedger {
    pub const fn new() -> Self {
        Self {
            active: BTreeSet::new(),
            allocated: 0,
        }
    }

    pub fn allocate(
        &mut self,
        handle: &ObjectHandle,
        limits: JvmCapabilityV2Limits,
    ) -> Result<(), V2Error> {
        handle.validate(limits)?;
        if self.active.len() >= limits.max_active_handles
            || self.allocated >= limits.max_handles_per_run
            || !self.active.insert(handle.id)
        {
            return Err(V2Error::new(V2ErrorCode::Handle));
        }
        self.allocated = self
            .allocated
            .checked_add(1)
            .ok_or_else(|| V2Error::new(V2ErrorCode::Limit))?;
        Ok(())
    }

    pub fn release(&mut self, id: ObjectHandleId) -> Result<(), V2Error> {
        if id == ObjectHandleId::ZERO || !self.active.remove(&id) {
            return Err(V2Error::new(V2ErrorCode::Handle));
        }
        Ok(())
    }

    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    pub fn allocated_count(&self) -> usize {
        self.allocated
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretReference {
    pub handle: ObjectHandleId,
    pub provider_digest: Sha256Digest,
    pub purpose: String,
    pub expiry_budget: DeadlineBudget,
    pub rights: HandleRights,
}

impl SecretReference {
    pub fn validate(&self, limits: JvmCapabilityV2Limits) -> Result<(), V2Error> {
        if self.handle == ObjectHandleId::ZERO {
            return Err(V2Error::new(V2ErrorCode::Handle));
        }
        validate_text(&self.purpose, limits.max_text_bytes)?;
        if self.expiry_budget.expired() || HandleRights::from_bits(self.rights.bits()).is_none() {
            return Err(V2Error::new(V2ErrorCode::Handle));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BindingValue {
    Null,
    Text(String),
    Bytes(HandleFreeReference),
    Bool(bool),
    I32(i32),
    I64(i64),
    F64Bits(u64),
    Secret(SecretReference),
    Object(ObjectHandle),
    List(Vec<BindingValue>),
    Map(Vec<(String, BindingValue)>),
}

impl BindingValue {
    pub fn validate(&self, limits: JvmCapabilityV2Limits) -> Result<usize, V2Error> {
        self.validate_at(limits, 0)
    }

    fn validate_at(&self, limits: JvmCapabilityV2Limits, depth: usize) -> Result<usize, V2Error> {
        if depth > limits.max_value_depth {
            return Err(V2Error::new(V2ErrorCode::Limit));
        }
        let mut nodes = 1_usize;
        match self {
            Self::Text(value) => validate_text(value, limits.max_text_bytes)?,
            Self::Bytes(value) => value.validate()?,
            Self::Secret(value) => value.validate(limits)?,
            Self::Object(value) => value.validate(limits)?,
            Self::List(values) => {
                if values.len() > limits.max_value_nodes {
                    return Err(V2Error::new(V2ErrorCode::Limit));
                }
                for value in values {
                    nodes = nodes
                        .checked_add(value.validate_at(limits, depth + 1)?)
                        .ok_or_else(|| V2Error::new(V2ErrorCode::Limit))?;
                }
            }
            Self::Map(values) => {
                if values.len() > limits.max_value_nodes {
                    return Err(V2Error::new(V2ErrorCode::Limit));
                }
                let mut previous: Option<&str> = None;
                for (key, value) in values {
                    validate_text(key, limits.max_text_bytes)?;
                    if previous.is_some_and(|item| item >= key.as_str()) {
                        return Err(V2Error::new(V2ErrorCode::InvalidMessage));
                    }
                    previous = Some(key);
                    nodes = nodes
                        .checked_add(value.validate_at(limits, depth + 1)?)
                        .ok_or_else(|| V2Error::new(V2ErrorCode::Limit))?;
                }
            }
            Self::Null | Self::Bool(_) | Self::I32(_) | Self::I64(_) | Self::F64Bits(_) => {}
        }
        if nodes > limits.max_value_nodes {
            Err(V2Error::new(V2ErrorCode::Limit))
        } else {
            Ok(nodes)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Presence<T> {
    Absent,
    Present(T),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BindingEntry {
    pub key: String,
    pub value: BindingValue,
}

impl BindingEntry {
    pub fn validate(&self, limits: JvmCapabilityV2Limits) -> Result<usize, V2Error> {
        if self.key.is_empty() {
            return Err(V2Error::new(V2ErrorCode::Identity));
        }
        validate_text(&self.key, limits.max_text_bytes)?;
        self.value.validate(limits)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextSnapshot {
    pub run_id: RunId,
    pub user_id: u64,
    pub thread_group_id: u64,
    pub thread_id: u64,
    pub iteration: u64,
    pub sample: u64,
    pub plan_node: NodeId,
    pub run_generation: u64,
    pub user_generation: u64,
    pub snapshot_digest: SnapshotDigest,
    pub variables: Vec<BindingEntry>,
    pub properties: Vec<BindingEntry>,
    pub current_result: Presence<Sha256Digest>,
    pub previous_result: Presence<Sha256Digest>,
    pub handles: Vec<ObjectHandle>,
}

impl ContextSnapshot {
    pub fn validate(&self, limits: JvmCapabilityV2Limits) -> Result<(), V2Error> {
        limits.validate()?;
        if self.run_id == RunId::ZERO
            || self.variables.len() > 4_096
            || self.properties.len() > 4_096
            || self.handles.len() > limits.max_active_handles
        {
            return Err(V2Error::new(V2ErrorCode::Limit));
        }
        validate_bindings(&self.variables, limits)?;
        validate_bindings(&self.properties, limits)?;
        let mut ledger = HandleLedger::new();
        for handle in &self.handles {
            ledger.allocate(handle, limits)?;
        }
        Ok(())
    }
}

fn validate_bindings(
    values: &[BindingEntry],
    limits: JvmCapabilityV2Limits,
) -> Result<(), V2Error> {
    let mut keys = BTreeSet::new();
    for value in values {
        value.validate(limits)?;
        if !keys.insert(value.key.as_str()) {
            return Err(V2Error::new(V2ErrorCode::Identity));
        }
    }
    Ok(())
}

#[derive(Clone, Eq, PartialEq)]
pub struct HelloOffer {
    pub role: Role,
    pub profile: ProfileIdentity,
    pub helper: HelperIdentity,
    pub client_nonce: Nonce,
    pub offered_limits: JvmCapabilityV2Limits,
    pub capabilities: Vec<String>,
    pub matrix_digest: MatrixDigest,
}

#[derive(Clone, Eq, PartialEq)]
pub struct HelloAck {
    pub role: Role,
    pub helper: HelperIdentity,
    pub server_nonce: Nonce,
    pub selected_limits: JvmCapabilityV2Limits,
    pub matrix_digest: MatrixDigest,
    pub request_body_digest: Sha256Digest,
    pub transcript_digest: Sha256Digest,
}

impl HelloOffer {
    pub fn validate(&self) -> Result<(), V2Error> {
        self.offered_limits.validate()?;
        self.profile.validate(self.offered_limits)?;
        self.helper.validate(self.offered_limits)?;
        if self.client_nonce == Nonce::ZERO
            || self.capabilities.len() > self.offered_limits.max_capabilities
        {
            return Err(V2Error::new(V2ErrorCode::Identity));
        }
        validate_string_list(
            &self.capabilities,
            self.offered_limits.max_capabilities,
            self.offered_limits.max_hello_text_bytes,
        )
    }

    pub fn fields(&self) -> Result<Vec<Field>, V2Error> {
        self.validate()?;
        let limits = self.offered_limits;
        let mut helper = WireWriter::new();
        encode_helper_identity(&self.helper, &mut helper)?;
        let mut profile = WireWriter::new();
        encode_profile_identity(&self.profile, &mut profile)?;
        let mut fields = vec![
            Field::new(1, vec![self.role as u8])?,
            Field::new(2, profile.finish())?,
            Field::new(3, helper.finish())?,
            Field::new(4, self.client_nonce.as_bytes().to_vec())?,
            Field::new(5, encode_limits(&limits)?)?,
            Field::new(
                6,
                encode_string_list(
                    &self.capabilities,
                    limits.max_capabilities,
                    limits.max_hello_text_bytes,
                )?,
            )?,
            Field::new(7, self.matrix_digest.as_bytes().to_vec())?,
        ];
        fields.sort_by_key(|field| field.tag);
        Ok(fields)
    }
}

impl HelloAck {
    pub fn validate(&self) -> Result<(), V2Error> {
        self.selected_limits.validate()?;
        self.helper.validate(self.selected_limits)?;
        if self.server_nonce == Nonce::ZERO {
            return Err(V2Error::new(V2ErrorCode::Identity));
        }
        Ok(())
    }

    fn fields_without_transcript(&self) -> Result<Vec<Field>, V2Error> {
        self.validate()?;
        let mut helper = WireWriter::new();
        encode_helper_identity(&self.helper, &mut helper)?;
        Ok(vec![
            Field::new(1, vec![self.role as u8])?,
            Field::new(2, helper.finish())?,
            Field::new(3, self.server_nonce.as_bytes().to_vec())?,
            Field::new(4, encode_limits(&self.selected_limits)?)?,
            Field::new(5, self.matrix_digest.as_bytes().to_vec())?,
            Field::new(6, self.request_body_digest.as_bytes().to_vec())?,
        ])
    }

    pub fn fields(&self) -> Result<Vec<Field>, V2Error> {
        let mut fields = self.fields_without_transcript()?;
        fields.push(Field::new(7, self.transcript_digest.as_bytes().to_vec())?);
        Ok(fields)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HelloTranscript {
    pub digest: Sha256Digest,
}

impl HelloTranscript {
    pub fn compute(
        offer: &HelloOffer,
        ack: &HelloAck,
        request_body_digest: Sha256Digest,
        acknowledgement_body_digest_without_transcript: Sha256Digest,
    ) -> Result<Self, V2Error> {
        offer.validate()?;
        ack.validate()?;
        let mut writer = WireWriter::new();
        encode_hello_transcript_material(
            offer,
            ack,
            request_body_digest,
            acknowledgement_body_digest_without_transcript,
            &mut writer,
        )?;
        Ok(Self {
            digest: domain_digest(DOMAIN_TRANSCRIPT, &writer.finish()),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Field {
    pub tag: u16,
    pub value: Vec<u8>,
}

impl Field {
    pub fn new(tag: u16, value: Vec<u8>) -> Result<Self, V2Error> {
        if tag == 0
            || tag == 0x7fff
            || tag == 0xffff
            || value.len() > JVM_CAPABILITY_V2_MAX_FIELD_BYTES
        {
            return Err(V2Error::new(V2ErrorCode::Limit));
        }
        Ok(Self { tag, value })
    }

    pub fn extension(tag: u16, value: Vec<u8>) -> Result<Self, V2Error> {
        if !(JVM_CAPABILITY_V2_EXTENSION_TAG_MIN..=JVM_CAPABILITY_V2_EXTENSION_TAG_MAX)
            .contains(&tag)
        {
            return Err(V2Error::new(V2ErrorCode::UnknownField));
        }
        Self::new(tag, value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Envelope {
    pub message_kind: MessageKind,
    pub phase: WirePhase,
    pub operation: OperationKind,
    pub flags: u16,
    pub session_id: SessionId,
    pub transaction_id: TransactionId,
    pub request_id: u64,
    pub sequence: u64,
    pub run_id: RunId,
    pub plan_node_id: u64,
    pub run_generation: u64,
    pub user_generation: u64,
    pub diagnostic_wall_ms: Option<u64>,
    pub remaining_budget_ms: u64,
    pub cancellation: CancellationState,
    pub known_fields: Vec<Field>,
    pub extensions: Vec<Field>,
    pub previous_chain: ChainDigest,
    pub body_digest: Sha256Digest,
    pub chain_digest: ChainDigest,
}

impl Envelope {
    // The fixed argument list mirrors the JVC2 header field order exactly;
    // introducing a mutable builder would make omission of a mandatory wire
    // identity field easier. Keep the suppression at this schema boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        message_kind: MessageKind,
        phase: WirePhase,
        operation: OperationKind,
        session_id: SessionId,
        transaction_id: TransactionId,
        request_id: u64,
        sequence: u64,
        run_id: RunId,
        plan_node_id: u64,
        run_generation: u64,
        user_generation: u64,
        diagnostic_wall_ms: Option<u64>,
        remaining_budget_ms: u64,
        cancellation: CancellationState,
        known_fields: Vec<Field>,
        extensions: Vec<Field>,
        previous_chain: ChainDigest,
    ) -> Result<Self, V2Error> {
        if !extensions.is_empty() {
            return Err(V2Error::new(V2ErrorCode::UnknownField));
        }
        Self::new_with_extensions(
            message_kind,
            phase,
            operation,
            session_id,
            transaction_id,
            request_id,
            sequence,
            run_id,
            plan_node_id,
            run_generation,
            user_generation,
            diagnostic_wall_ms,
            remaining_budget_ms,
            cancellation,
            known_fields,
            extensions,
            previous_chain,
        )
    }

    // See `new`: these are the complete immutable header identities.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_extensions(
        message_kind: MessageKind,
        phase: WirePhase,
        operation: OperationKind,
        session_id: SessionId,
        transaction_id: TransactionId,
        request_id: u64,
        sequence: u64,
        run_id: RunId,
        plan_node_id: u64,
        run_generation: u64,
        user_generation: u64,
        diagnostic_wall_ms: Option<u64>,
        remaining_budget_ms: u64,
        cancellation: CancellationState,
        known_fields: Vec<Field>,
        extensions: Vec<Field>,
        previous_chain: ChainDigest,
    ) -> Result<Self, V2Error> {
        let mut envelope = Self {
            message_kind,
            phase,
            operation,
            flags: 0,
            session_id,
            transaction_id,
            request_id,
            sequence,
            run_id,
            plan_node_id,
            run_generation,
            user_generation,
            diagnostic_wall_ms,
            remaining_budget_ms,
            cancellation,
            known_fields,
            extensions,
            previous_chain,
            body_digest: Sha256Digest::ZERO,
            chain_digest: Sha256Digest::ZERO,
        };
        envelope.recompute()?;
        Ok(envelope)
    }

    pub fn recompute(&mut self) -> Result<(), V2Error> {
        validate_header(self)?;
        let body = canonical_body(
            &self.known_fields,
            &self.extensions,
            JvmCapabilityV2Limits::default(),
        )?;
        self.body_digest = body_digest(self, &body);
        self.chain_digest = chain_digest(
            self.message_kind,
            self.sequence,
            self.previous_chain,
            self.body_digest,
        );
        self.flags = if self.extensions.is_empty() {
            0
        } else {
            FLAG_EXTENSIONS
        };
        if self.cancellation != CancellationState::None {
            self.flags |= FLAG_CANCELLATION;
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, V2Error> {
        let mut canonical = self.clone();
        canonical.recompute()?;
        if canonical.body_digest != self.body_digest || canonical.chain_digest != self.chain_digest
        {
            return Err(V2Error::new(V2ErrorCode::Digest));
        }
        let body = canonical_body(
            &canonical.known_fields,
            &canonical.extensions,
            JvmCapabilityV2Limits::default(),
        )?;
        let total = JVM_CAPABILITY_V2_HEADER_LEN
            .checked_add(body.len())
            .ok_or_else(|| V2Error::new(V2ErrorCode::Limit))?;
        if total > JVM_CAPABILITY_V2_MAX_MESSAGE_BYTES {
            return Err(V2Error::new(V2ErrorCode::Limit));
        }
        let known_count = u16::try_from(canonical.known_fields.len())
            .map_err(|_| V2Error::new(V2ErrorCode::Limit))?;
        let extension_count = u16::try_from(canonical.extensions.len())
            .map_err(|_| V2Error::new(V2ErrorCode::Limit))?;
        let body_len = u32::try_from(body.len()).map_err(|_| V2Error::new(V2ErrorCode::Limit))?;
        let mut output = Vec::with_capacity(total);
        output.extend_from_slice(&JVM_CAPABILITY_V2_MAGIC);
        output.extend_from_slice(&JVM_CAPABILITY_V2_SCHEMA_VERSION.to_be_bytes());
        output.push(canonical.message_kind as u8);
        output.push(canonical.phase as u8);
        output.extend_from_slice(&canonical.flags.to_be_bytes());
        output.extend_from_slice(&(canonical.operation as u16).to_be_bytes());
        output.extend_from_slice(&canonical.session_id.as_bytes());
        output.extend_from_slice(&canonical.transaction_id.as_bytes());
        output.extend_from_slice(&canonical.request_id.to_be_bytes());
        output.extend_from_slice(&canonical.sequence.to_be_bytes());
        output.extend_from_slice(&canonical.run_id.as_bytes());
        output.extend_from_slice(&canonical.plan_node_id.to_be_bytes());
        output.extend_from_slice(&canonical.run_generation.to_be_bytes());
        output.extend_from_slice(&canonical.user_generation.to_be_bytes());
        output.extend_from_slice(&canonical.diagnostic_wall_ms.unwrap_or(0).to_be_bytes());
        output.extend_from_slice(&canonical.remaining_budget_ms.to_be_bytes());
        output.push(canonical.cancellation as u8);
        output.push(0);
        output.extend_from_slice(&known_count.to_be_bytes());
        output.extend_from_slice(&extension_count.to_be_bytes());
        output.extend_from_slice(&body_len.to_be_bytes());
        output.extend_from_slice(&canonical.body_digest.as_bytes());
        output.extend_from_slice(&canonical.previous_chain.as_bytes());
        output.extend_from_slice(&canonical.chain_digest.as_bytes());
        output.extend_from_slice(&0_u16.to_be_bytes());
        output.extend_from_slice(&body);
        Ok(output)
    }

    pub fn decode(bytes: &[u8], limits: JvmCapabilityV2Limits) -> Result<Self, V2Error> {
        Self::decode_with_extensions(bytes, limits, false)
    }

    pub fn decode_with_extensions(
        bytes: &[u8],
        limits: JvmCapabilityV2Limits,
        preserve_extensions: bool,
    ) -> Result<Self, V2Error> {
        limits.validate()?;
        if bytes.len() > limits.max_message_bytes
            || bytes.len() > JVM_CAPABILITY_V2_MAX_MESSAGE_BYTES
        {
            return Err(V2Error::new(V2ErrorCode::Limit));
        }
        if bytes.len() < JVM_CAPABILITY_V2_HEADER_LEN {
            return Err(V2Error::new(V2ErrorCode::Truncated));
        }
        if bytes[..4] != JVM_CAPABILITY_V2_MAGIC {
            return Err(V2Error::new(V2ErrorCode::Version));
        }
        let schema = read_u16(bytes, 4)?;
        if schema != JVM_CAPABILITY_V2_SCHEMA_VERSION {
            return Err(V2Error::new(V2ErrorCode::Version));
        }
        let message_kind = MessageKind::from_wire(bytes[6])?;
        let phase = WirePhase::from_wire(bytes[7])?;
        let flags = read_u16(bytes, 8)?;
        if flags & !KNOWN_FLAGS != 0 {
            return Err(V2Error::new(V2ErrorCode::InvalidMessage));
        }
        let operation = OperationKind::from_wire(read_u16(bytes, 10)?)?;
        let session_id = SessionId::from_bytes(read_array(bytes, 12)?);
        let transaction_id = TransactionId::from_bytes(read_array(bytes, 28)?);
        let request_id = read_u64(bytes, 44)?;
        let sequence = read_u64(bytes, 52)?;
        let run_id = RunId::from_bytes(read_array(bytes, 60)?);
        let plan_node_id = read_u64(bytes, 76)?;
        let run_generation = read_u64(bytes, 84)?;
        let user_generation = read_u64(bytes, 92)?;
        let diagnostic_wall_ms = match read_u64(bytes, 100)? {
            0 => None,
            value => Some(value),
        };
        let remaining_budget_ms = read_u64(bytes, 108)?;
        let cancellation = CancellationState::from_wire(bytes[116])?;
        if bytes[117] != 0 || read_u16(bytes, 222)? != 0 {
            return Err(V2Error::new(V2ErrorCode::InvalidMessage));
        }
        let known_count = read_u16(bytes, 118)? as usize;
        let extension_count = read_u16(bytes, 120)? as usize;
        let body_len = read_u32(bytes, 122)? as usize;
        if known_count > limits.max_fields
            || extension_count > limits.max_extensions
            || body_len
                > limits
                    .max_message_bytes
                    .saturating_sub(JVM_CAPABILITY_V2_HEADER_LEN)
            || body_len > JVM_CAPABILITY_V2_MAX_MESSAGE_BYTES - JVM_CAPABILITY_V2_HEADER_LEN
        {
            return Err(V2Error::new(V2ErrorCode::Limit));
        }
        let end = JVM_CAPABILITY_V2_HEADER_LEN
            .checked_add(body_len)
            .ok_or_else(|| V2Error::new(V2ErrorCode::Limit))?;
        if end > bytes.len() {
            return Err(V2Error::new(V2ErrorCode::Truncated));
        }
        if end != bytes.len() {
            return Err(V2Error::new(V2ErrorCode::TrailingBytes));
        }
        let expected_body_digest = Sha256Digest::from_bytes(read_array(bytes, 126)?);
        let previous_chain = Sha256Digest::from_bytes(read_array(bytes, 158)?);
        let expected_chain_digest = Sha256Digest::from_bytes(read_array(bytes, 190)?);
        let (known_fields, extensions) = decode_fields(
            &bytes[JVM_CAPABILITY_V2_HEADER_LEN..],
            known_count,
            extension_count,
            limits,
        )?;
        if !preserve_extensions && !extensions.is_empty() {
            return Err(V2Error::new(V2ErrorCode::UnknownField));
        }
        let mut envelope = Self {
            message_kind,
            phase,
            operation,
            flags,
            session_id,
            transaction_id,
            request_id,
            sequence,
            run_id,
            plan_node_id,
            run_generation,
            user_generation,
            diagnostic_wall_ms,
            remaining_budget_ms,
            cancellation,
            known_fields,
            extensions,
            previous_chain,
            body_digest: expected_body_digest,
            chain_digest: expected_chain_digest,
        };
        validate_header(&envelope)?;
        let body = canonical_body(&envelope.known_fields, &envelope.extensions, limits)?;
        if body_digest(&envelope, &body) != expected_body_digest {
            return Err(V2Error::new(V2ErrorCode::Digest));
        }
        if chain_digest(message_kind, sequence, previous_chain, expected_body_digest)
            != expected_chain_digest
        {
            return Err(V2Error::new(V2ErrorCode::Digest));
        }
        let expected_flags = if envelope.extensions.is_empty() {
            0
        } else {
            FLAG_EXTENSIONS
        } | if cancellation == CancellationState::None {
            0
        } else {
            FLAG_CANCELLATION
        };
        if flags != expected_flags {
            return Err(V2Error::new(V2ErrorCode::InvalidMessage));
        }
        envelope.flags = expected_flags;
        Ok(envelope)
    }
}

fn validate_header(envelope: &Envelope) -> Result<(), V2Error> {
    if envelope.flags & !KNOWN_FLAGS != 0
        || envelope.sequence == 0
        || envelope.remaining_budget_ms > JVM_CAPABILITY_V2_MAX_DEADLINE_MILLIS
    {
        return Err(V2Error::new(V2ErrorCode::InvalidMessage));
    }
    let hello = envelope.phase == WirePhase::Hello;
    if hello {
        if envelope.operation != OperationKind::Hello
            || envelope.transaction_id != TransactionId::ZERO
            || envelope.run_id != RunId::ZERO
            || envelope.request_id != 0
            || envelope.sequence != 1
        {
            return Err(V2Error::new(V2ErrorCode::Phase));
        }
        if envelope.message_kind == MessageKind::Request && envelope.session_id != SessionId::ZERO {
            return Err(V2Error::new(V2ErrorCode::Identity));
        }
        if envelope.message_kind == MessageKind::Response && envelope.session_id == SessionId::ZERO
        {
            return Err(V2Error::new(V2ErrorCode::Identity));
        }
    } else if envelope.operation == OperationKind::Hello
        || envelope.session_id == SessionId::ZERO
        || envelope.request_id == 0
    {
        return Err(V2Error::new(V2ErrorCode::Identity));
    }
    let transactional_phase = matches!(
        envelope.phase,
        WirePhase::Prepare
            | WirePhase::Prepared
            | WirePhase::Execute
            | WirePhase::Proposed
            | WirePhase::Commit
            | WirePhase::Committed
            | WirePhase::Abort
            | WirePhase::Aborted
    );
    if transactional_phase != (envelope.transaction_id != TransactionId::ZERO) {
        return Err(V2Error::new(V2ErrorCode::Transaction));
    }
    validate_phase_matrix(
        envelope.message_kind,
        envelope.phase,
        &envelope.known_fields,
    )
}

fn validate_phase_matrix(
    kind: MessageKind,
    phase: WirePhase,
    fields: &[Field],
) -> Result<(), V2Error> {
    let (required_start, required_end, allowed_end) = match (kind, phase) {
        (MessageKind::Request, WirePhase::Hello) => (1, 7, 7),
        (MessageKind::Response, WirePhase::Hello) => (1, 7, 7),
        (MessageKind::Request, WirePhase::Open) => (1, 2, 8),
        (MessageKind::Response, WirePhase::Open) => (1, 2, 8),
        (MessageKind::Request, WirePhase::Prepare) => (1, 5, 16),
        (MessageKind::Response, WirePhase::Prepared) => (1, 4, 8),
        (MessageKind::Request, WirePhase::Execute) => (1, 2, 8),
        (MessageKind::Response, WirePhase::Proposed) => (1, 1, 8),
        (MessageKind::Request, WirePhase::Commit) => (1, 2, 8),
        (MessageKind::Response, WirePhase::Committed) => (1, 2, 8),
        (MessageKind::Request, WirePhase::Abort) => (1, 2, 8),
        (MessageKind::Response, WirePhase::Aborted) => (1, 2, 8),
        (MessageKind::Control, WirePhase::Poison) => (1, 2, 8),
        (MessageKind::Request, WirePhase::Close) => (1, 2, 8),
        (MessageKind::Response, WirePhase::Close) => (1, 2, 8),
        (MessageKind::Response, WirePhase::Error) => (1, 2, 8),
        (MessageKind::Control, WirePhase::Terminal) => (1, 2, 8),
        _ => return Err(V2Error::new(V2ErrorCode::Phase)),
    };
    let mut required = BTreeSet::new();
    for tag in required_start..=required_end {
        required.insert(tag);
    }
    for field in fields {
        if field.tag == 0
            || field.tag >= JVM_CAPABILITY_V2_EXTENSION_TAG_MIN
            || field.tag > allowed_end
        {
            return Err(V2Error::new(V2ErrorCode::UnknownField));
        }
        required.remove(&field.tag);
    }
    if required.is_empty() {
        Ok(())
    } else {
        Err(V2Error::new(V2ErrorCode::InvalidMessage))
    }
}

fn canonical_body(
    fields: &[Field],
    extensions: &[Field],
    limits: JvmCapabilityV2Limits,
) -> Result<Vec<u8>, V2Error> {
    limits.validate()?;
    if fields.len() > limits.max_fields || extensions.len() > limits.max_extensions {
        return Err(V2Error::new(V2ErrorCode::Limit));
    }
    let mut output = Vec::new();
    let mut previous = 0_u16;
    for field in fields.iter().chain(extensions) {
        let extension = field.tag >= JVM_CAPABILITY_V2_EXTENSION_TAG_MIN;
        if field.tag == 0
            || field.tag == 0x7fff
            || field.tag == 0xffff
            || field.tag <= previous
            || (extension && field.tag < JVM_CAPABILITY_V2_EXTENSION_TAG_MIN)
            || (!extension && field.tag >= JVM_CAPABILITY_V2_EXTENSION_TAG_MIN)
            || field.value.len() > limits.max_field_bytes
        {
            return Err(V2Error::new(V2ErrorCode::UnknownField));
        }
        previous = field.tag;
        output.extend_from_slice(&field.tag.to_be_bytes());
        output.extend_from_slice(
            &(u32::try_from(field.value.len()).map_err(|_| V2Error::new(V2ErrorCode::Limit))?)
                .to_be_bytes(),
        );
        output.extend_from_slice(&field.value);
    }
    Ok(output)
}

fn body_digest(envelope: &Envelope, body: &[u8]) -> Sha256Digest {
    let mut material = Vec::with_capacity(16 + body.len());
    material.extend_from_slice(&JVM_CAPABILITY_V2_SCHEMA_VERSION.to_be_bytes());
    material.push(envelope.message_kind as u8);
    material.push(envelope.phase as u8);
    material.extend_from_slice(&(envelope.operation as u16).to_be_bytes());
    material.extend_from_slice(body);
    domain_digest(DOMAIN_BODY, &material)
}

fn chain_digest(
    kind: MessageKind,
    sequence: u64,
    previous: Sha256Digest,
    body: Sha256Digest,
) -> Sha256Digest {
    let domain = match kind {
        MessageKind::Request => DOMAIN_CHAIN_REQUEST,
        MessageKind::Response => DOMAIN_CHAIN_RESPONSE,
        MessageKind::Control => DOMAIN_CHAIN_CONTROL,
    };
    let mut material = Vec::with_capacity(8 + 64);
    material.extend_from_slice(&previous.as_bytes());
    material.extend_from_slice(&sequence.to_be_bytes());
    material.extend_from_slice(&body.as_bytes());
    domain_digest(domain, &material)
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn encode_profile_identity(
    value: &ProfileIdentity,
    writer: &mut WireWriter,
) -> Result<(), V2Error> {
    validate_text(&value.id, JVM_CAPABILITY_V2_MAX_TEXT_BYTES)?;
    writer.string(&value.id, JVM_CAPABILITY_V2_MAX_TEXT_BYTES)?;
    writer.u32(value.version);
    writer.bytes(&value.sha256.as_bytes());
    Ok(())
}

fn encode_helper_identity(value: &HelperIdentity, writer: &mut WireWriter) -> Result<(), V2Error> {
    value.validate(JvmCapabilityV2Limits::default())?;
    writer.bytes(&value.source_sha256.as_bytes());
    writer.bytes(&value.build_sha256.as_bytes());
    writer.string(&value.compiler, JVM_CAPABILITY_V2_MAX_TEXT_BYTES)?;
    writer.bytes(&value.schema_sha256.as_bytes());
    writer.u8(value.role as u8);
    writer.bytes(&value.module_digest.as_bytes());
    Ok(())
}

fn encode_hello_transcript_material(
    offer: &HelloOffer,
    ack: &HelloAck,
    request_body_digest: Sha256Digest,
    acknowledgement_body_digest_without_transcript: Sha256Digest,
    writer: &mut WireWriter,
) -> Result<(), V2Error> {
    writer.u8(offer.role as u8);
    writer.u8(ack.role as u8);
    writer.bytes(&offer.client_nonce.as_bytes());
    writer.bytes(&ack.server_nonce.as_bytes());
    writer.bytes(&offer.helper.canonical_digest()?.as_bytes());
    writer.bytes(&ack.helper.canonical_digest()?.as_bytes());
    writer.bytes(&offer.matrix_digest.as_bytes());
    writer.bytes(&ack.matrix_digest.as_bytes());
    writer.bytes(&request_body_digest.as_bytes());
    writer.bytes(&acknowledgement_body_digest_without_transcript.as_bytes());
    writer.blob(&encode_limits(&offer.offered_limits)?)?;
    writer.blob(&encode_limits(&ack.selected_limits)?)?;
    Ok(())
}

fn encode_limits(value: &JvmCapabilityV2Limits) -> Result<Vec<u8>, V2Error> {
    value.validate()?;
    let values = [
        value.max_message_bytes,
        value.max_fields,
        value.max_extensions,
        value.max_field_bytes,
        value.max_text_bytes,
        value.max_script_bytes,
        value.max_operations,
        value.max_phase_outcomes,
        value.max_callbacks,
        value.max_references,
        value.max_diagnostics,
        value.max_capabilities,
        value.max_hello_text_bytes,
        value.max_value_depth,
        value.max_value_nodes,
        value.max_active_handles,
        value.max_handles_per_run,
        value.max_lease_operations,
    ];
    let mut writer = WireWriter::new();
    for current in values {
        writer.u64(u64::try_from(current).map_err(|_| V2Error::new(V2ErrorCode::Limit))?);
    }
    Ok(writer.finish())
}

fn encode_string_list(
    values: &[String],
    limit: usize,
    text_limit: usize,
) -> Result<Vec<u8>, V2Error> {
    validate_string_list(values, limit, text_limit)?;
    let mut writer = WireWriter::new();
    writer.u16(u16::try_from(values.len()).map_err(|_| V2Error::new(V2ErrorCode::Limit))?);
    for value in values {
        writer.string(value, text_limit)?;
    }
    Ok(writer.finish())
}

fn validate_string_list(values: &[String], limit: usize, text_limit: usize) -> Result<(), V2Error> {
    if values.len() > limit || values.len() > u16::MAX as usize {
        return Err(V2Error::new(V2ErrorCode::Limit));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        validate_text(value, text_limit)?;
        if !seen.insert(value) {
            return Err(V2Error::new(V2ErrorCode::Identity));
        }
    }
    Ok(())
}

fn validate_text(value: &str, limit: usize) -> Result<(), V2Error> {
    if value.len() > limit || value.len() > JVM_CAPABILITY_V2_MAX_TEXT_BYTES {
        Err(V2Error::new(V2ErrorCode::Limit))
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeId(NonZeroU64);

impl NodeId {
    pub fn new(value: u64) -> Result<Self, V2Error> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or_else(|| V2Error::new(V2ErrorCode::Identity))
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct DomainQualifiedNode {
    pub domain: String,
    pub node_id: NodeId,
}

impl DomainQualifiedNode {
    pub fn validate(&self) -> Result<(), V2Error> {
        validate_text(&self.domain, JVM_CAPABILITY_V2_MAX_TEXT_BYTES)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeReference {
    Absent,
    Present(NodeId),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResultReference {
    Absent,
    Present {
        result_ordinal: NonZeroU32,
        projection_sha256: Sha256Digest,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiagnosticReference {
    Absent,
    Present {
        diagnostic_ordinal: NonZeroU32,
        diagnostic_sha256: Sha256Digest,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandleFreeReference {
    pub kind: ReferenceKind,
    pub ordinal: NonZeroU32,
    pub byte_length: u32,
    pub sha256: Sha256Digest,
}

impl HandleFreeReference {
    pub fn validate(&self) -> Result<(), V2Error> {
        if self.byte_length as usize > JVM_CAPABILITY_V2_MAX_FIELD_BYTES {
            Err(V2Error::new(V2ErrorCode::Limit))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhaseOutcome {
    pub phase_ordinal: NonZeroU32,
    pub source_node: NodeReference,
    pub phase_kind: PhaseKind,
    pub disposition: PhaseDisposition,
    pub result_reference: ResultReference,
    pub control_action: ControlAction,
    pub diagnostic_reference: DiagnosticReference,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FinalSnapshot {
    pub snapshot_digest: SnapshotDigest,
    pub run_generation: u64,
    pub user_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CallbackSnapshot {
    pub callback_ordinal: NonZeroU32,
    pub source_node: NodeReference,
    pub selected_variables_digest: Sha256Digest,
    pub result_reference: ResultReference,
    pub diagnostic_reference: DiagnosticReference,
    pub artifact_count: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiagnosticRecord {
    pub ordinal: NonZeroU32,
    pub code: String,
    pub diagnostic_sha256: Sha256Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Observation {
    pub ordinal: NonZeroU32,
    pub observation_digest: Sha256Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutionReply {
    SemanticComplete {
        phase_outcomes: Vec<PhaseOutcome>,
        final_snapshot: FinalSnapshot,
        event_snapshots: Vec<CallbackSnapshot>,
        result_graph: Vec<HandleFreeReference>,
        observations: Vec<Observation>,
        proposal_digest: ProposalDigest,
    },
    BridgeFailure {
        failure: BridgeFailureCode,
        may_have_executed: MayHaveExecuted,
        poison_reason: PoisonReason,
        diagnostics: Vec<DiagnosticRecord>,
    },
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum BridgeFailureCode {
    Protocol = 1,
    Deadline = 2,
    Cancelled = 3,
    WorkerCrashed = 4,
    OutputLimit = 5,
    ContainmentLost = 6,
    InvalidProposal = 7,
    Unsupported = 8,
}

impl BridgeFailureCode {
    fn from_wire(value: u16) -> Result<Self, V2Error> {
        match value {
            1 => Ok(Self::Protocol),
            2 => Ok(Self::Deadline),
            3 => Ok(Self::Cancelled),
            4 => Ok(Self::WorkerCrashed),
            5 => Ok(Self::OutputLimit),
            6 => Ok(Self::ContainmentLost),
            7 => Ok(Self::InvalidProposal),
            8 => Ok(Self::Unsupported),
            _ => Err(V2Error::new(V2ErrorCode::Reply)),
        }
    }
}

impl ExecutionReply {
    pub fn validate(&self, limits: JvmCapabilityV2Limits) -> Result<(), V2Error> {
        limits.validate()?;
        match self {
            Self::SemanticComplete {
                phase_outcomes,
                event_snapshots,
                result_graph,
                observations,
                ..
            } => {
                if phase_outcomes.is_empty() || phase_outcomes.len() > limits.max_phase_outcomes {
                    return Err(V2Error::new(V2ErrorCode::Reply));
                }
                validate_contiguous_ordinals(
                    phase_outcomes.iter().map(|value| value.phase_ordinal),
                )?;
                if event_snapshots.len() > limits.max_callbacks
                    || result_graph.len() > limits.max_references
                    || observations.len() > limits.max_references
                {
                    return Err(V2Error::new(V2ErrorCode::Limit));
                }
                validate_contiguous_ordinals(
                    event_snapshots.iter().map(|value| value.callback_ordinal),
                )?;
                for reference in result_graph {
                    reference.validate()?;
                }
                for outcome in phase_outcomes {
                    validate_phase_outcome(outcome)?;
                }
                Ok(())
            }
            Self::BridgeFailure { diagnostics, .. } => {
                if diagnostics.len() > limits.max_diagnostics {
                    return Err(V2Error::new(V2ErrorCode::Limit));
                }
                validate_contiguous_ordinals(diagnostics.iter().map(|value| value.ordinal))?;
                for diagnostic in diagnostics {
                    validate_text(&diagnostic.code, limits.max_text_bytes)?;
                }
                Ok(())
            }
        }
    }

    pub fn canonical_digest(
        &self,
        limits: JvmCapabilityV2Limits,
    ) -> Result<ProposalDigest, V2Error> {
        let bytes = encode_execution_reply(self, limits)?;
        Ok(domain_digest(DOMAIN_REPLY, &bytes))
    }
}

fn validate_contiguous_ordinals<I>(ordinals: I) -> Result<(), V2Error>
where
    I: IntoIterator<Item = NonZeroU32>,
{
    let mut expected = 1_u32;
    for ordinal in ordinals {
        if ordinal.get() != expected {
            return Err(V2Error::new(V2ErrorCode::Reply));
        }
        expected = expected
            .checked_add(1)
            .ok_or_else(|| V2Error::new(V2ErrorCode::Limit))?;
    }
    Ok(())
}

fn validate_phase_outcome(value: &PhaseOutcome) -> Result<(), V2Error> {
    if let NodeReference::Present(node) = value.source_node
        && node.get() == 0
    {
        return Err(V2Error::new(V2ErrorCode::Identity));
    }
    if let ResultReference::Present { result_ordinal, .. } = value.result_reference
        && result_ordinal.get() == 0
    {
        return Err(V2Error::new(V2ErrorCode::Reply));
    }
    if let DiagnosticReference::Present {
        diagnostic_ordinal, ..
    } = value.diagnostic_reference
        && diagnostic_ordinal.get() == 0
    {
        return Err(V2Error::new(V2ErrorCode::Reply));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrepareRequest {
    pub transaction_id: TransactionId,
    pub operation: OperationKind,
    pub authority_extent: Option<AuthorityExtent>,
    pub input_digest: Sha256Digest,
    pub base_snapshot_digest: SnapshotDigest,
    pub run_generation: u64,
    pub user_generation: u64,
    pub budget: DeadlineBudget,
}

impl PrepareRequest {
    pub fn validate(&self) -> Result<(), V2Error> {
        if self.transaction_id == TransactionId::ZERO || !self.operation.is_transactional() {
            return Err(V2Error::new(V2ErrorCode::Transaction));
        }
        if self.operation == OperationKind::ExecutePackage {
            if self.authority_extent.is_none() {
                return Err(V2Error::new(V2ErrorCode::Transaction));
            }
        } else if self.authority_extent.is_some() {
            return Err(V2Error::new(V2ErrorCode::Transaction));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedReceipt {
    pub transaction_id: TransactionId,
    pub operation: OperationKind,
    pub authority_extent: Option<AuthorityExtent>,
    pub rollback: RollbackCapability,
    pub base_snapshot_digest: SnapshotDigest,
    pub prepared_digest: Sha256Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitRequest {
    pub transaction_id: TransactionId,
    pub proposal_digest: ProposalDigest,
    pub expected_run_generation: u64,
    pub expected_user_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbortRequest {
    pub transaction_id: TransactionId,
    pub proposal_digest: Option<ProposalDigest>,
    pub rollback: RollbackCapability,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContainmentClose {
    pub reason: PoisonReason,
    pub skipped_callback_count: u32,
    pub accounted_resource_digest: Sha256Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionState {
    Created,
    Handshaking {
        client_nonce: Nonce,
    },
    Ready {
        session_id: SessionId,
    },
    RunOpen {
        run_id: RunId,
        whole_engine_used: bool,
    },
    Prepared {
        request: PrepareRequest,
    },
    Executing {
        request: PrepareRequest,
    },
    Proposed {
        request: PrepareRequest,
        proposal_digest: ProposalDigest,
    },
    Aborting {
        request: PrepareRequest,
        rollback: RollbackCapability,
    },
    Committing {
        request: PrepareRequest,
        proposal_digest: ProposalDigest,
    },
    Poisoned {
        reason: PoisonReason,
        may_have_executed: MayHaveExecuted,
    },
    Closing {
        mode: CloseMode,
    },
    Terminal {
        outcome: TerminalOutcome,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionLedger {
    state: SessionState,
    run_id: Option<RunId>,
    whole_engine_used: bool,
}

impl Default for SessionLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionLedger {
    pub const fn new() -> Self {
        Self {
            state: SessionState::Created,
            run_id: None,
            whole_engine_used: false,
        }
    }

    pub fn state(&self) -> &SessionState {
        &self.state
    }

    pub fn begin_hello(&mut self, client_nonce: Nonce) -> Result<(), V2Error> {
        if client_nonce == Nonce::ZERO || !matches!(self.state, SessionState::Created) {
            return Err(V2Error::new(V2ErrorCode::Phase));
        }
        self.state = SessionState::Handshaking { client_nonce };
        Ok(())
    }

    pub fn accept_hello(&mut self, session_id: SessionId) -> Result<(), V2Error> {
        if session_id == SessionId::ZERO || !matches!(self.state, SessionState::Handshaking { .. })
        {
            return Err(V2Error::new(V2ErrorCode::Phase));
        }
        self.state = SessionState::Ready { session_id };
        Ok(())
    }

    pub fn open_run(&mut self, run_id: RunId) -> Result<(), V2Error> {
        if run_id == RunId::ZERO || !matches!(self.state, SessionState::Ready { .. }) {
            return Err(V2Error::new(V2ErrorCode::Phase));
        }
        self.state = SessionState::RunOpen {
            run_id,
            whole_engine_used: false,
        };
        self.run_id = Some(run_id);
        self.whole_engine_used = false;
        Ok(())
    }

    pub fn prepare(&mut self, request: PrepareRequest) -> Result<(), V2Error> {
        request.validate()?;
        if !matches!(self.state, SessionState::RunOpen { .. }) {
            return Err(if matches!(self.state, SessionState::Poisoned { .. }) {
                V2Error::new(V2ErrorCode::Poisoned)
            } else {
                V2Error::new(V2ErrorCode::Phase)
            });
        }
        if request.operation == OperationKind::ExecutePackage
            && request.authority_extent == Some(AuthorityExtent::WholeEngine)
            && self.whole_engine_used
        {
            return Err(V2Error::new(V2ErrorCode::Conflict));
        }
        self.state = SessionState::Prepared { request };
        Ok(())
    }

    pub fn begin_execute(&mut self, transaction_id: TransactionId) -> Result<(), V2Error> {
        let SessionState::Prepared { request } = &self.state else {
            return Err(V2Error::new(V2ErrorCode::Phase));
        };
        if request.transaction_id != transaction_id {
            return Err(V2Error::new(V2ErrorCode::Conflict));
        }
        self.state = SessionState::Executing {
            request: request.clone(),
        };
        Ok(())
    }

    pub fn record_execution(
        &mut self,
        transaction_id: TransactionId,
        reply: &ExecutionReply,
    ) -> Result<(), V2Error> {
        let SessionState::Executing { request } = &self.state else {
            return Err(V2Error::new(V2ErrorCode::Phase));
        };
        if request.transaction_id != transaction_id {
            return Err(V2Error::new(V2ErrorCode::Conflict));
        }
        match reply {
            ExecutionReply::SemanticComplete {
                proposal_digest, ..
            } => {
                reply.validate(JvmCapabilityV2Limits::default())?;
                self.state = SessionState::Proposed {
                    request: request.clone(),
                    proposal_digest: *proposal_digest,
                };
                Ok(())
            }
            ExecutionReply::BridgeFailure {
                may_have_executed: MayHaveExecuted::No,
                ..
            } => {
                self.state = SessionState::Aborting {
                    request: request.clone(),
                    rollback: RollbackCapability::NotExecuted,
                };
                Ok(())
            }
            ExecutionReply::BridgeFailure {
                may_have_executed,
                poison_reason,
                ..
            } => {
                self.state = SessionState::Poisoned {
                    reason: *poison_reason,
                    may_have_executed: *may_have_executed,
                };
                Ok(())
            }
        }
    }

    pub fn commit(&mut self, request: CommitRequest) -> Result<(), V2Error> {
        let (prepared, proposal_digest) = match &self.state {
            SessionState::Proposed {
                request: prepared,
                proposal_digest,
            } => (prepared.clone(), *proposal_digest),
            _ => return Err(V2Error::new(V2ErrorCode::Phase)),
        };
        if prepared.transaction_id != request.transaction_id
            || proposal_digest != request.proposal_digest
            || prepared.run_generation != request.expected_run_generation
            || prepared.user_generation != request.expected_user_generation
        {
            return Err(V2Error::new(V2ErrorCode::Conflict));
        }
        let use_whole_engine = prepared.authority_extent == Some(AuthorityExtent::WholeEngine);
        self.state = SessionState::Committing {
            request: prepared.clone(),
            proposal_digest,
        };
        let run_id = self
            .run_id
            .ok_or_else(|| V2Error::new(V2ErrorCode::Identity))?;
        self.whole_engine_used |= use_whole_engine;
        self.state = SessionState::RunOpen {
            run_id,
            whole_engine_used: self.whole_engine_used,
        };
        Ok(())
    }

    pub fn abort(&mut self, request: AbortRequest) -> Result<(), V2Error> {
        let state = self.state.clone();
        match state {
            SessionState::Prepared { request: prepared }
                if prepared.transaction_id == request.transaction_id
                    && request.rollback == RollbackCapability::NotExecuted =>
            {
                self.state = SessionState::RunOpen {
                    run_id: self
                        .run_id
                        .ok_or_else(|| V2Error::new(V2ErrorCode::Identity))?,
                    whole_engine_used: self.whole_engine_used,
                };
                Ok(())
            }
            SessionState::Aborting {
                request: prepared,
                rollback,
            } if prepared.transaction_id == request.transaction_id
                && rollback == request.rollback =>
            {
                if request.rollback == RollbackCapability::Unsafe {
                    self.poison(PoisonReason::ExecutionUncertain, MayHaveExecuted::Unknown)?;
                } else {
                    self.state = SessionState::RunOpen {
                        run_id: self
                            .run_id
                            .ok_or_else(|| V2Error::new(V2ErrorCode::Identity))?,
                        whole_engine_used: self.whole_engine_used,
                    };
                }
                Ok(())
            }
            SessionState::Proposed {
                request: prepared,
                proposal_digest,
            } if prepared.transaction_id == request.transaction_id
                && request.proposal_digest == Some(proposal_digest)
                && request.rollback == RollbackCapability::Journaled =>
            {
                self.state = SessionState::RunOpen {
                    run_id: self
                        .run_id
                        .ok_or_else(|| V2Error::new(V2ErrorCode::Identity))?,
                    whole_engine_used: self.whole_engine_used,
                };
                Ok(())
            }
            _ => Err(V2Error::new(V2ErrorCode::Transaction)),
        }
    }

    pub fn poison(
        &mut self,
        reason: PoisonReason,
        may_have_executed: MayHaveExecuted,
    ) -> Result<(), V2Error> {
        if matches!(
            self.state,
            SessionState::Terminal { .. } | SessionState::Closing { .. }
        ) {
            return Err(V2Error::new(V2ErrorCode::Terminal));
        }
        self.state = SessionState::Poisoned {
            reason,
            may_have_executed,
        };
        Ok(())
    }

    pub fn begin_close(&mut self, mode: CloseMode) -> Result<(), V2Error> {
        match (&self.state, mode) {
            (SessionState::RunOpen { .. }, CloseMode::Normal)
            | (SessionState::Poisoned { .. }, CloseMode::ContainmentOnly) => {
                self.state = SessionState::Closing { mode };
                Ok(())
            }
            (SessionState::Poisoned { .. }, CloseMode::Normal) => {
                Err(V2Error::new(V2ErrorCode::Poisoned))
            }
            _ => Err(V2Error::new(V2ErrorCode::Phase)),
        }
    }

    pub fn finish_close(&mut self, outcome: TerminalOutcome) -> Result<(), V2Error> {
        let SessionState::Closing { mode } = self.state else {
            return Err(V2Error::new(V2ErrorCode::Phase));
        };
        if mode == CloseMode::ContainmentOnly && outcome == TerminalOutcome::Success {
            return Err(V2Error::new(V2ErrorCode::Poisoned));
        }
        self.state = SessionState::Terminal { outcome };
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SequenceDisposition {
    Accepted,
    Replay,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SequenceTracker {
    next_sequence: u64,
    last_request_id: u64,
    last_body_digest: Sha256Digest,
    last_chain_digest: ChainDigest,
}

impl Default for SequenceTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl SequenceTracker {
    pub const fn new() -> Self {
        Self {
            next_sequence: 1,
            last_request_id: 0,
            last_body_digest: Sha256Digest::ZERO,
            last_chain_digest: Sha256Digest::ZERO,
        }
    }

    pub const fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    pub fn accept(
        &mut self,
        sequence: u64,
        request_id: u64,
        body_digest: Sha256Digest,
        chain_digest: ChainDigest,
    ) -> Result<SequenceDisposition, V2Error> {
        if sequence == self.next_sequence {
            self.next_sequence = self
                .next_sequence
                .checked_add(1)
                .ok_or_else(|| V2Error::new(V2ErrorCode::Limit))?;
            self.last_request_id = request_id;
            self.last_body_digest = body_digest;
            self.last_chain_digest = chain_digest;
            return Ok(SequenceDisposition::Accepted);
        }
        if sequence.checked_add(1) == Some(self.next_sequence)
            && request_id == self.last_request_id
            && body_digest == self.last_body_digest
            && chain_digest == self.last_chain_digest
        {
            Ok(SequenceDisposition::Replay)
        } else {
            Err(V2Error::new(V2ErrorCode::Sequence))
        }
    }
}

pub fn encode_execution_reply(
    reply: &ExecutionReply,
    limits: JvmCapabilityV2Limits,
) -> Result<Vec<u8>, V2Error> {
    reply.validate(limits)?;
    let mut writer = WireWriter::new();
    match reply {
        ExecutionReply::SemanticComplete {
            phase_outcomes,
            final_snapshot,
            event_snapshots,
            result_graph,
            observations,
            proposal_digest,
        } => {
            writer.u8(1);
            writer.u32(
                u32::try_from(phase_outcomes.len())
                    .map_err(|_| V2Error::new(V2ErrorCode::Limit))?,
            );
            for outcome in phase_outcomes {
                encode_phase_outcome(outcome, &mut writer)?;
            }
            encode_final_snapshot(final_snapshot, &mut writer);
            writer.u32(
                u32::try_from(event_snapshots.len())
                    .map_err(|_| V2Error::new(V2ErrorCode::Limit))?,
            );
            for snapshot in event_snapshots {
                encode_callback_snapshot(snapshot, &mut writer);
            }
            writer.u32(
                u32::try_from(result_graph.len()).map_err(|_| V2Error::new(V2ErrorCode::Limit))?,
            );
            for reference in result_graph {
                encode_handle_free_reference(reference, &mut writer);
            }
            writer.u32(
                u32::try_from(observations.len()).map_err(|_| V2Error::new(V2ErrorCode::Limit))?,
            );
            for observation in observations {
                writer.u32(observation.ordinal.get());
                writer.bytes(&observation.observation_digest.as_bytes());
            }
            writer.bytes(&proposal_digest.as_bytes());
        }
        ExecutionReply::BridgeFailure {
            failure,
            may_have_executed,
            poison_reason,
            diagnostics,
        } => {
            writer.u8(2);
            writer.u16(*failure as u16);
            writer.u8(*may_have_executed as u8);
            writer.u8(*poison_reason as u8);
            writer.u32(
                u32::try_from(diagnostics.len()).map_err(|_| V2Error::new(V2ErrorCode::Limit))?,
            );
            for diagnostic in diagnostics {
                writer.u32(diagnostic.ordinal.get());
                writer.string(&diagnostic.code, limits.max_text_bytes)?;
                writer.bytes(&diagnostic.diagnostic_sha256.as_bytes());
            }
        }
    }
    Ok(writer.finish())
}

pub fn decode_execution_reply(
    bytes: &[u8],
    limits: JvmCapabilityV2Limits,
) -> Result<ExecutionReply, V2Error> {
    limits.validate()?;
    if bytes.len() > limits.max_field_bytes {
        return Err(V2Error::new(V2ErrorCode::Limit));
    }
    let mut reader = WireReader::new(bytes);
    let reply = match reader.u8()? {
        1 => {
            let phase_count = reader.count(limits.max_phase_outcomes)?;
            let mut phase_outcomes = Vec::with_capacity(phase_count);
            for _ in 0..phase_count {
                phase_outcomes.push(decode_phase_outcome(&mut reader)?);
            }
            let final_snapshot = decode_final_snapshot(&mut reader)?;
            let callback_count = reader.count(limits.max_callbacks)?;
            let mut event_snapshots = Vec::with_capacity(callback_count);
            for _ in 0..callback_count {
                event_snapshots.push(decode_callback_snapshot(&mut reader)?);
            }
            let result_count = reader.count(limits.max_references)?;
            let mut result_graph = Vec::with_capacity(result_count);
            for _ in 0..result_count {
                result_graph.push(decode_handle_free_reference(&mut reader)?);
            }
            let observation_count = reader.count(limits.max_references)?;
            let mut observations = Vec::with_capacity(observation_count);
            for _ in 0..observation_count {
                observations.push(Observation {
                    ordinal: nonzero_u32(reader.u32()?)?,
                    observation_digest: Sha256Digest::from_bytes(reader.array32()?),
                });
            }
            let proposal_digest = Sha256Digest::from_bytes(reader.array32()?);
            ExecutionReply::SemanticComplete {
                phase_outcomes,
                final_snapshot,
                event_snapshots,
                result_graph,
                observations,
                proposal_digest,
            }
        }
        2 => {
            let failure = BridgeFailureCode::from_wire(reader.u16()?)?;
            let may_have_executed = MayHaveExecuted::from_wire(reader.u8()?)?;
            let poison_reason = PoisonReason::from_wire(reader.u8()?)?;
            let diagnostic_count = reader.count(limits.max_diagnostics)?;
            let mut diagnostics = Vec::with_capacity(diagnostic_count);
            for _ in 0..diagnostic_count {
                diagnostics.push(DiagnosticRecord {
                    ordinal: nonzero_u32(reader.u32()?)?,
                    code: reader.string(limits.max_text_bytes)?,
                    diagnostic_sha256: Sha256Digest::from_bytes(reader.array32()?),
                });
            }
            ExecutionReply::BridgeFailure {
                failure,
                may_have_executed,
                poison_reason,
                diagnostics,
            }
        }
        _ => return Err(V2Error::new(V2ErrorCode::Reply)),
    };
    reader.finish()?;
    reply.validate(limits)?;
    Ok(reply)
}

fn encode_phase_outcome(value: &PhaseOutcome, writer: &mut WireWriter) -> Result<(), V2Error> {
    validate_phase_outcome(value)?;
    writer.u32(value.phase_ordinal.get());
    encode_node_reference(value.source_node, writer);
    writer.u8(value.phase_kind as u8);
    writer.u8(value.disposition as u8);
    encode_result_reference(value.result_reference, writer);
    writer.u8(value.control_action as u8);
    encode_diagnostic_reference(value.diagnostic_reference, writer);
    Ok(())
}

fn decode_phase_outcome(reader: &mut WireReader<'_>) -> Result<PhaseOutcome, V2Error> {
    let value = PhaseOutcome {
        phase_ordinal: nonzero_u32(reader.u32()?)?,
        source_node: decode_node_reference(reader)?,
        phase_kind: PhaseKind::from_wire(reader.u8()?)?,
        disposition: PhaseDisposition::from_wire(reader.u8()?)?,
        result_reference: decode_result_reference(reader)?,
        control_action: ControlAction::from_wire(reader.u8()?)?,
        diagnostic_reference: decode_diagnostic_reference(reader)?,
    };
    validate_phase_outcome(&value)?;
    Ok(value)
}

fn encode_final_snapshot(value: &FinalSnapshot, writer: &mut WireWriter) {
    writer.bytes(&value.snapshot_digest.as_bytes());
    writer.u64(value.run_generation);
    writer.u64(value.user_generation);
}

fn decode_final_snapshot(reader: &mut WireReader<'_>) -> Result<FinalSnapshot, V2Error> {
    Ok(FinalSnapshot {
        snapshot_digest: Sha256Digest::from_bytes(reader.array32()?),
        run_generation: reader.u64()?,
        user_generation: reader.u64()?,
    })
}

fn encode_callback_snapshot(value: &CallbackSnapshot, writer: &mut WireWriter) {
    writer.u32(value.callback_ordinal.get());
    encode_node_reference(value.source_node, writer);
    writer.bytes(&value.selected_variables_digest.as_bytes());
    encode_result_reference(value.result_reference, writer);
    encode_diagnostic_reference(value.diagnostic_reference, writer);
    writer.u16(value.artifact_count);
}

fn decode_callback_snapshot(reader: &mut WireReader<'_>) -> Result<CallbackSnapshot, V2Error> {
    Ok(CallbackSnapshot {
        callback_ordinal: nonzero_u32(reader.u32()?)?,
        source_node: decode_node_reference(reader)?,
        selected_variables_digest: Sha256Digest::from_bytes(reader.array32()?),
        result_reference: decode_result_reference(reader)?,
        diagnostic_reference: decode_diagnostic_reference(reader)?,
        artifact_count: reader.u16()?,
    })
}

fn encode_handle_free_reference(value: &HandleFreeReference, writer: &mut WireWriter) {
    writer.u8(value.kind as u8);
    writer.u32(value.ordinal.get());
    writer.u32(value.byte_length);
    writer.bytes(&value.sha256.as_bytes());
}

fn decode_handle_free_reference(
    reader: &mut WireReader<'_>,
) -> Result<HandleFreeReference, V2Error> {
    let value = HandleFreeReference {
        kind: ReferenceKind::from_wire(reader.u8()?)?,
        ordinal: nonzero_u32(reader.u32()?)?,
        byte_length: reader.u32()?,
        sha256: Sha256Digest::from_bytes(reader.array32()?),
    };
    value.validate()?;
    Ok(value)
}

fn encode_node_reference(value: NodeReference, writer: &mut WireWriter) {
    match value {
        NodeReference::Absent => writer.u8(0),
        NodeReference::Present(node) => {
            writer.u8(1);
            writer.u64(node.get());
        }
    }
}

fn decode_node_reference(reader: &mut WireReader<'_>) -> Result<NodeReference, V2Error> {
    match reader.u8()? {
        0 => Ok(NodeReference::Absent),
        1 => Ok(NodeReference::Present(NodeId::new(reader.u64()?)?)),
        _ => Err(V2Error::new(V2ErrorCode::Reply)),
    }
}

fn encode_result_reference(value: ResultReference, writer: &mut WireWriter) {
    match value {
        ResultReference::Absent => writer.u8(0),
        ResultReference::Present {
            result_ordinal,
            projection_sha256,
        } => {
            writer.u8(1);
            writer.u32(result_ordinal.get());
            writer.bytes(&projection_sha256.as_bytes());
        }
    }
}

fn decode_result_reference(reader: &mut WireReader<'_>) -> Result<ResultReference, V2Error> {
    match reader.u8()? {
        0 => Ok(ResultReference::Absent),
        1 => Ok(ResultReference::Present {
            result_ordinal: nonzero_u32(reader.u32()?)?,
            projection_sha256: Sha256Digest::from_bytes(reader.array32()?),
        }),
        _ => Err(V2Error::new(V2ErrorCode::Reply)),
    }
}

fn encode_diagnostic_reference(value: DiagnosticReference, writer: &mut WireWriter) {
    match value {
        DiagnosticReference::Absent => writer.u8(0),
        DiagnosticReference::Present {
            diagnostic_ordinal,
            diagnostic_sha256,
        } => {
            writer.u8(1);
            writer.u32(diagnostic_ordinal.get());
            writer.bytes(&diagnostic_sha256.as_bytes());
        }
    }
}

fn decode_diagnostic_reference(
    reader: &mut WireReader<'_>,
) -> Result<DiagnosticReference, V2Error> {
    match reader.u8()? {
        0 => Ok(DiagnosticReference::Absent),
        1 => Ok(DiagnosticReference::Present {
            diagnostic_ordinal: nonzero_u32(reader.u32()?)?,
            diagnostic_sha256: Sha256Digest::from_bytes(reader.array32()?),
        }),
        _ => Err(V2Error::new(V2ErrorCode::Reply)),
    }
}

pub fn build_hello_request(
    offer: &HelloOffer,
    remaining_budget_ms: u64,
) -> Result<Envelope, V2Error> {
    let fields = offer.fields()?;
    Envelope::new(
        MessageKind::Request,
        WirePhase::Hello,
        OperationKind::Hello,
        SessionId::ZERO,
        TransactionId::ZERO,
        0,
        1,
        RunId::ZERO,
        0,
        0,
        0,
        None,
        remaining_budget_ms,
        CancellationState::None,
        fields,
        Vec::new(),
        Sha256Digest::ZERO,
    )
}

pub fn build_hello_ack(
    request: &Envelope,
    offer: &HelloOffer,
    ack: &HelloAck,
    session_id: SessionId,
    remaining_budget_ms: u64,
) -> Result<Envelope, V2Error> {
    if request.message_kind != MessageKind::Request
        || request.phase != WirePhase::Hello
        || request.operation != OperationKind::Hello
        || request.body_digest != ack.request_body_digest
        || session_id == SessionId::ZERO
    {
        return Err(V2Error::new(V2ErrorCode::Identity));
    }
    let without_transcript = ack.fields_without_transcript()?;
    let without_body = canonical_body(&without_transcript, &[], ack.selected_limits)?;
    let without_digest = body_digest_for(
        WirePhase::Hello,
        MessageKind::Response,
        OperationKind::Hello,
        &without_body,
    );
    let transcript = HelloTranscript::compute(offer, ack, request.body_digest, without_digest)?;
    if transcript.digest != ack.transcript_digest {
        return Err(V2Error::new(V2ErrorCode::Digest));
    }
    Envelope::new(
        MessageKind::Response,
        WirePhase::Hello,
        OperationKind::Hello,
        session_id,
        TransactionId::ZERO,
        0,
        1,
        RunId::ZERO,
        0,
        0,
        0,
        None,
        remaining_budget_ms,
        CancellationState::None,
        ack.fields()?,
        Vec::new(),
        request.chain_digest,
    )
}

fn body_digest_for(
    phase: WirePhase,
    kind: MessageKind,
    operation: OperationKind,
    body: &[u8],
) -> Sha256Digest {
    let mut material = Vec::with_capacity(4 + body.len());
    material.extend_from_slice(&JVM_CAPABILITY_V2_SCHEMA_VERSION.to_be_bytes());
    material.push(kind as u8);
    material.push(phase as u8);
    material.extend_from_slice(&(operation as u16).to_be_bytes());
    material.extend_from_slice(body);
    domain_digest(DOMAIN_BODY, &material)
}

fn nonzero_u32(value: u32) -> Result<NonZeroU32, V2Error> {
    NonZeroU32::new(value).ok_or_else(|| V2Error::new(V2ErrorCode::Reply))
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

    fn bytes(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    fn blob(&mut self, value: &[u8]) -> Result<(), V2Error> {
        self.u32(u32::try_from(value.len()).map_err(|_| V2Error::new(V2ErrorCode::Limit))?);
        self.bytes(value);
        Ok(())
    }

    fn string(&mut self, value: &str, limit: usize) -> Result<(), V2Error> {
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

    fn take(&mut self, length: usize) -> Result<&'a [u8], V2Error> {
        let end = self
            .position
            .checked_add(length)
            .ok_or_else(|| V2Error::new(V2ErrorCode::Limit))?;
        if end > self.bytes.len() {
            return Err(V2Error::new(V2ErrorCode::Truncated));
        }
        let value = &self.bytes[self.position..end];
        self.position = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, V2Error> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, V2Error> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Result<u32, V2Error> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn u64(&mut self) -> Result<u64, V2Error> {
        let bytes = self.take(8)?;
        Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn array32(&mut self) -> Result<[u8; 32], V2Error> {
        let mut value = [0; 32];
        value.copy_from_slice(self.take(32)?);
        Ok(value)
    }

    fn string(&mut self, limit: usize) -> Result<String, V2Error> {
        let length = self.u32()? as usize;
        if length > limit || length > JVM_CAPABILITY_V2_MAX_TEXT_BYTES {
            return Err(V2Error::new(V2ErrorCode::Limit));
        }
        String::from_utf8(self.take(length)?.to_vec()).map_err(|_| V2Error::new(V2ErrorCode::Utf8))
    }

    fn count(&mut self, limit: usize) -> Result<usize, V2Error> {
        let value = self.u32()? as usize;
        if value > limit {
            return Err(V2Error::new(V2ErrorCode::Limit));
        }
        Ok(value)
    }

    fn finish(self) -> Result<(), V2Error> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(V2Error::new(V2ErrorCode::TrailingBytes))
        }
    }
}

fn decode_fields(
    bytes: &[u8],
    known_count: usize,
    extension_count: usize,
    limits: JvmCapabilityV2Limits,
) -> Result<(Vec<Field>, Vec<Field>), V2Error> {
    let total_count = known_count
        .checked_add(extension_count)
        .ok_or_else(|| V2Error::new(V2ErrorCode::Limit))?;
    if known_count > limits.max_fields || extension_count > limits.max_extensions {
        return Err(V2Error::new(V2ErrorCode::Limit));
    }
    let mut reader = WireReader::new(bytes);
    let mut known = Vec::with_capacity(known_count);
    let mut extensions = Vec::with_capacity(extension_count);
    let mut previous = 0_u16;
    for index in 0..total_count {
        let tag = reader.u16()?;
        let length = reader.u32()? as usize;
        if tag == 0
            || tag == 0x7fff
            || tag == 0xffff
            || tag <= previous
            || length > limits.max_field_bytes
        {
            return Err(V2Error::new(V2ErrorCode::UnknownField));
        }
        previous = tag;
        let field = Field::new(tag, reader.take(length)?.to_vec())?;
        if index < known_count {
            if tag >= JVM_CAPABILITY_V2_EXTENSION_TAG_MIN {
                return Err(V2Error::new(V2ErrorCode::UnknownField));
            }
            known.push(field);
        } else {
            if tag < JVM_CAPABILITY_V2_EXTENSION_TAG_MIN {
                return Err(V2Error::new(V2ErrorCode::UnknownField));
            }
            extensions.push(field);
        }
    }
    reader.finish()?;
    Ok((known, extensions))
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, V2Error> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| V2Error::new(V2ErrorCode::Truncated))?;
    let value = bytes
        .get(offset..end)
        .ok_or_else(|| V2Error::new(V2ErrorCode::Truncated))?;
    Ok(u16::from_be_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, V2Error> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| V2Error::new(V2ErrorCode::Truncated))?;
    let value = bytes
        .get(offset..end)
        .ok_or_else(|| V2Error::new(V2ErrorCode::Truncated))?;
    Ok(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, V2Error> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| V2Error::new(V2ErrorCode::Truncated))?;
    let value = bytes
        .get(offset..end)
        .ok_or_else(|| V2Error::new(V2ErrorCode::Truncated))?;
    Ok(u64::from_be_bytes([
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ]))
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], V2Error> {
    let end = offset
        .checked_add(N)
        .ok_or_else(|| V2Error::new(V2ErrorCode::Truncated))?;
    let value = bytes
        .get(offset..end)
        .ok_or_else(|| V2Error::new(V2ErrorCode::Truncated))?;
    let mut output = [0; N];
    output.copy_from_slice(value);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn helper(role: Role) -> HelperIdentity {
        HelperIdentity {
            source_sha256: Sha256Digest::from_bytes([1; 32]),
            build_sha256: Sha256Digest::from_bytes([2; 32]),
            compiler: "javac-17".to_owned(),
            schema_sha256: Sha256Digest::from_bytes([3; 32]),
            role,
            module_digest: Sha256Digest::from_bytes([4; 32]),
        }
    }

    fn offer() -> HelloOffer {
        HelloOffer {
            role: Role::Capability,
            profile: ProfileIdentity {
                id: "jmeter-5.6.3".to_owned(),
                version: 1,
                sha256: Sha256Digest::from_bytes([5; 32]),
            },
            helper: helper(Role::Capability),
            client_nonce: Nonce::from_bytes([6; 32]),
            offered_limits: JvmCapabilityV2Limits::default(),
            capabilities: vec!["jvm-capability/2".to_owned()],
            matrix_digest: Sha256Digest::from_bytes([7; 32]),
        }
    }

    fn reply() -> ExecutionReply {
        ExecutionReply::SemanticComplete {
            phase_outcomes: vec![PhaseOutcome {
                phase_ordinal: NonZeroU32::new(1).expect("nonzero"),
                source_node: NodeReference::Present(NodeId::new(7).expect("node")),
                phase_kind: PhaseKind::Sampler,
                disposition: PhaseDisposition::Completed,
                result_reference: ResultReference::Present {
                    result_ordinal: NonZeroU32::new(1).expect("nonzero"),
                    projection_sha256: Sha256Digest::from_bytes([8; 32]),
                },
                control_action: ControlAction::Continue,
                diagnostic_reference: DiagnosticReference::Absent,
            }],
            final_snapshot: FinalSnapshot {
                snapshot_digest: Sha256Digest::from_bytes([9; 32]),
                run_generation: 2,
                user_generation: 3,
            },
            event_snapshots: vec![CallbackSnapshot {
                callback_ordinal: NonZeroU32::new(1).expect("nonzero"),
                source_node: NodeReference::Absent,
                selected_variables_digest: Sha256Digest::from_bytes([10; 32]),
                result_reference: ResultReference::Absent,
                diagnostic_reference: DiagnosticReference::Absent,
                artifact_count: 0,
            }],
            result_graph: vec![HandleFreeReference {
                kind: ReferenceKind::Result,
                ordinal: NonZeroU32::new(1).expect("nonzero"),
                byte_length: 4,
                sha256: Sha256Digest::from_bytes([11; 32]),
            }],
            observations: vec![Observation {
                ordinal: NonZeroU32::new(1).expect("nonzero"),
                observation_digest: Sha256Digest::from_bytes([12; 32]),
            }],
            proposal_digest: Sha256Digest::from_bytes([13; 32]),
        }
    }

    #[test]
    fn hello_round_trip_binds_role_module_and_transcript() {
        let offer = offer();
        let request = build_hello_request(&offer, 1000).expect("hello request");
        assert_eq!(
            request.body_digest.to_string(),
            "d7de8e0f8cb54883b9192186c87c500b375a9b277e54dd15787275a24010191e"
        );
        assert_eq!(
            request.chain_digest.to_string(),
            "3657865c7fa11ec0a04c64f82ab3ef5ff5c7281a3efd16e98c265035b33cf1bc"
        );
        assert_eq!(&request.encode().expect("encode")[..4], b"JVC2");
        let decoded = Envelope::decode(
            &request.encode().expect("encode"),
            JvmCapabilityV2Limits::default(),
        )
        .expect("decode");
        assert_eq!(decoded, request);

        let mut ack = HelloAck {
            role: Role::Capability,
            helper: helper(Role::Capability),
            server_nonce: Nonce::from_bytes([14; 32]),
            selected_limits: JvmCapabilityV2Limits::default(),
            matrix_digest: offer.matrix_digest,
            request_body_digest: request.body_digest,
            transcript_digest: Sha256Digest::ZERO,
        };
        let without = ack.fields_without_transcript().expect("ack fields");
        let without_body = canonical_body(&without, &[], ack.selected_limits).expect("body");
        let without_digest = body_digest_for(
            WirePhase::Hello,
            MessageKind::Response,
            OperationKind::Hello,
            &without_body,
        );
        ack.transcript_digest =
            HelloTranscript::compute(&offer, &ack, request.body_digest, without_digest)
                .expect("transcript")
                .digest;
        let ack_envelope =
            build_hello_ack(&request, &offer, &ack, SessionId::from_bytes([15; 16]), 900)
                .expect("ack");
        let ack_decoded = Envelope::decode(
            &ack_envelope.encode().expect("encode"),
            JvmCapabilityV2Limits::default(),
        )
        .expect("decode");
        assert_eq!(ack_decoded, ack_envelope);
        assert_ne!(request.chain_digest, ack_envelope.chain_digest);
        assert_ne!(
            helper(Role::Capability).canonical_digest().expect("digest"),
            helper(Role::RmiWorker).canonical_digest().expect("digest")
        );
    }

    #[test]
    fn canonical_envelope_rejects_unknown_duplicate_and_digest_mutation() {
        let fields = vec![
            Field::new(1, vec![1]).expect("field"),
            Field::new(2, vec![2]).expect("field"),
            Field::new(3, vec![3]).expect("field"),
            Field::new(4, vec![4]).expect("field"),
            Field::new(5, vec![5]).expect("field"),
            Field::new(6, vec![6]).expect("field"),
            Field::new(7, vec![7]).expect("field"),
        ];
        let envelope = Envelope::new_with_extensions(
            MessageKind::Request,
            WirePhase::Hello,
            OperationKind::Hello,
            SessionId::ZERO,
            TransactionId::ZERO,
            0,
            1,
            RunId::ZERO,
            0,
            0,
            0,
            None,
            100,
            CancellationState::None,
            fields,
            vec![Field::extension(0x8000, vec![9]).expect("extension")],
            Sha256Digest::ZERO,
        )
        .expect("envelope");
        let mut bytes = envelope.encode().expect("encode");
        assert_eq!(
            Envelope::decode(&bytes, JvmCapabilityV2Limits::default())
                .expect_err("strict unknown extension")
                .code(),
            V2ErrorCode::UnknownField
        );
        assert_eq!(
            Envelope::decode_with_extensions(&bytes, JvmCapabilityV2Limits::default(), true)
                .expect("negotiated extension"),
            envelope
        );
        bytes[126] ^= 1;
        assert_eq!(
            Envelope::decode_with_extensions(&bytes, JvmCapabilityV2Limits::default(), true)
                .expect_err("digest error")
                .code(),
            V2ErrorCode::Digest
        );
    }

    #[test]
    fn semantic_failure_is_not_bridge_failure_and_reply_is_canonical() {
        let semantic = reply();
        let bytes =
            encode_execution_reply(&semantic, JvmCapabilityV2Limits::default()).expect("encode");
        let decoded =
            decode_execution_reply(&bytes, JvmCapabilityV2Limits::default()).expect("decode");
        assert_eq!(decoded, semantic);
        assert_ne!(
            semantic
                .canonical_digest(JvmCapabilityV2Limits::default())
                .expect("digest"),
            Sha256Digest::ZERO
        );

        let failure = ExecutionReply::BridgeFailure {
            failure: BridgeFailureCode::Deadline,
            may_have_executed: MayHaveExecuted::Yes,
            poison_reason: PoisonReason::ExecutionUncertain,
            diagnostics: vec![],
        };
        let failure_bytes =
            encode_execution_reply(&failure, JvmCapabilityV2Limits::default()).expect("encode");
        assert_eq!(
            decode_execution_reply(&failure_bytes, JvmCapabilityV2Limits::default())
                .expect("decode"),
            failure
        );
    }

    #[test]
    fn state_machine_requires_hello_prepare_commit_and_containment_close() {
        let mut ledger = SessionLedger::new();
        ledger
            .begin_hello(Nonce::from_bytes([1; 32]))
            .expect("hello");
        ledger
            .accept_hello(SessionId::from_bytes([2; 16]))
            .expect("ack");
        ledger.open_run(RunId::from_bytes([3; 16])).expect("open");
        let request = PrepareRequest {
            transaction_id: TransactionId::from_bytes([4; 16]),
            operation: OperationKind::ExecutePackage,
            authority_extent: Some(AuthorityExtent::WholeEngine),
            input_digest: Sha256Digest::from_bytes([5; 32]),
            base_snapshot_digest: Sha256Digest::from_bytes([6; 32]),
            run_generation: 1,
            user_generation: 1,
            budget: DeadlineBudget::from_millis(100).expect("budget"),
        };
        ledger.prepare(request.clone()).expect("prepare");
        ledger
            .begin_execute(request.transaction_id)
            .expect("execute");
        let semantic = reply();
        ledger
            .record_execution(request.transaction_id, &semantic)
            .expect("proposal");
        let proposal_digest = match ledger.state() {
            SessionState::Proposed {
                proposal_digest, ..
            } => *proposal_digest,
            state => panic!("unexpected state: {state:?}"),
        };
        ledger
            .commit(CommitRequest {
                transaction_id: request.transaction_id,
                proposal_digest,
                expected_run_generation: 1,
                expected_user_generation: 1,
            })
            .expect("commit");
        ledger
            .poison(PoisonReason::ContainmentLost, MayHaveExecuted::Yes)
            .expect("poison");
        assert_eq!(
            ledger
                .begin_close(CloseMode::Normal)
                .expect_err("normal close rejected")
                .code(),
            V2ErrorCode::Poisoned
        );
        ledger
            .begin_close(CloseMode::ContainmentOnly)
            .expect("containment close");
        assert_eq!(
            ledger
                .finish_close(TerminalOutcome::Success)
                .expect_err("poison cannot succeed")
                .code(),
            V2ErrorCode::Poisoned
        );
        ledger
            .finish_close(TerminalOutcome::Poisoned)
            .expect("terminal");
        assert!(matches!(
            ledger.state(),
            SessionState::Terminal {
                outcome: TerminalOutcome::Poisoned
            }
        ));
    }

    #[test]
    fn sequence_tracker_accepts_only_exact_replay() {
        let mut tracker = SequenceTracker::new();
        let body = Sha256Digest::from_bytes([1; 32]);
        let chain = Sha256Digest::from_bytes([2; 32]);
        assert_eq!(
            tracker.accept(1, 7, body, chain).expect("first"),
            SequenceDisposition::Accepted
        );
        assert_eq!(
            tracker.accept(1, 7, body, chain).expect("replay"),
            SequenceDisposition::Replay
        );
        assert_eq!(
            tracker
                .accept(1, 8, body, chain)
                .expect_err("mismatch")
                .code(),
            V2ErrorCode::Sequence
        );
        assert_eq!(
            tracker.accept(3, 8, body, chain).expect_err("gap").code(),
            V2ErrorCode::Sequence
        );
    }

    #[test]
    fn handles_are_scoped_and_callbacks_are_handle_free() {
        let handle = ObjectHandle {
            id: ObjectHandleId::from_bytes([20; 16]),
            kind: ObjectKind::Variables,
            owner: HandleOwner {
                role: Role::Capability,
                worker_id: 1,
                session_id: SessionId::from_bytes([21; 16]),
                run_id: RunId::from_bytes([22; 16]),
                run_generation: 1,
                class_loader_generation: 2,
                user_scope: Some(3),
                allocation_ordinal: NonZeroU32::new(1).expect("nonzero"),
            },
            class_identity_sha256: Sha256Digest::from_bytes([23; 32]),
            rights: HandleRights::READ,
            lease_operations: 10,
        };
        let mut ledger = HandleLedger::new();
        ledger
            .allocate(&handle, JvmCapabilityV2Limits::default())
            .expect("allocate");
        assert_eq!(ledger.active_count(), 1);
        assert_eq!(ledger.release(handle.id), Ok(()));
        assert_eq!(ledger.active_count(), 0);

        let snapshot = ContextSnapshot {
            run_id: handle.owner.run_id,
            user_id: 3,
            thread_group_id: 4,
            thread_id: 5,
            iteration: 6,
            sample: 7,
            plan_node: NodeId::new(8).expect("node"),
            run_generation: 1,
            user_generation: 1,
            snapshot_digest: Sha256Digest::from_bytes([24; 32]),
            variables: vec![BindingEntry {
                key: "empty".to_owned(),
                value: BindingValue::Text(String::new()),
            }],
            properties: vec![BindingEntry {
                key: "null".to_owned(),
                value: BindingValue::Null,
            }],
            current_result: Presence::Absent,
            previous_result: Presence::Present(Sha256Digest::from_bytes([25; 32])),
            handles: vec![handle],
        };
        snapshot
            .validate(JvmCapabilityV2Limits::default())
            .expect("snapshot");

        let callback = CallbackSnapshot {
            callback_ordinal: NonZeroU32::new(1).expect("nonzero"),
            source_node: NodeReference::Absent,
            selected_variables_digest: Sha256Digest::from_bytes([26; 32]),
            result_reference: ResultReference::Present {
                result_ordinal: NonZeroU32::new(1).expect("nonzero"),
                projection_sha256: Sha256Digest::from_bytes([27; 32]),
            },
            diagnostic_reference: DiagnosticReference::Absent,
            artifact_count: 1,
        };
        assert_eq!(callback.source_node, NodeReference::Absent);
        assert_eq!(callback.artifact_count, 1);
    }

    #[test]
    fn whole_engine_is_single_use_and_package_is_the_default_extent() {
        let mut ledger = SessionLedger::new();
        ledger
            .begin_hello(Nonce::from_bytes([30; 32]))
            .expect("hello");
        ledger
            .accept_hello(SessionId::from_bytes([31; 16]))
            .expect("ack");
        ledger.open_run(RunId::from_bytes([32; 16])).expect("open");
        let package = PrepareRequest {
            transaction_id: TransactionId::from_bytes([33; 16]),
            operation: OperationKind::ExecutePackage,
            authority_extent: Some(AuthorityExtent::Package),
            input_digest: Sha256Digest::from_bytes([34; 32]),
            base_snapshot_digest: Sha256Digest::from_bytes([35; 32]),
            run_generation: 0,
            user_generation: 0,
            budget: DeadlineBudget::from_millis(50).expect("budget"),
        };
        ledger.prepare(package.clone()).expect("package prepare");
        ledger
            .begin_execute(package.transaction_id)
            .expect("execute");
        ledger
            .record_execution(package.transaction_id, &reply())
            .expect("proposal");
        let digest = match ledger.state() {
            SessionState::Proposed {
                proposal_digest, ..
            } => *proposal_digest,
            _ => panic!("proposal expected"),
        };
        ledger
            .commit(CommitRequest {
                transaction_id: package.transaction_id,
                proposal_digest: digest,
                expected_run_generation: 0,
                expected_user_generation: 0,
            })
            .expect("package commit");
        let whole = PrepareRequest {
            transaction_id: TransactionId::from_bytes([36; 16]),
            operation: OperationKind::ExecutePackage,
            authority_extent: Some(AuthorityExtent::WholeEngine),
            input_digest: Sha256Digest::from_bytes([37; 32]),
            base_snapshot_digest: Sha256Digest::from_bytes([38; 32]),
            run_generation: 0,
            user_generation: 0,
            budget: DeadlineBudget::from_millis(50).expect("budget"),
        };
        ledger.prepare(whole.clone()).expect("whole prepare");
        ledger
            .begin_execute(whole.transaction_id)
            .expect("whole execute");
        ledger
            .record_execution(whole.transaction_id, &reply())
            .expect("whole proposal");
        let whole_digest = match ledger.state() {
            SessionState::Proposed {
                proposal_digest, ..
            } => *proposal_digest,
            _ => panic!("whole proposal expected"),
        };
        ledger
            .commit(CommitRequest {
                transaction_id: whole.transaction_id,
                proposal_digest: whole_digest,
                expected_run_generation: 0,
                expected_user_generation: 0,
            })
            .expect("whole commit");
        let second_whole = PrepareRequest {
            transaction_id: TransactionId::from_bytes([39; 16]),
            ..whole
        };
        assert_eq!(
            ledger
                .prepare(second_whole)
                .expect_err("second whole rejected")
                .code(),
            V2ErrorCode::Conflict
        );
    }
}
