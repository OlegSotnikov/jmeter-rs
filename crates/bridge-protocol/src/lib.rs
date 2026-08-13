// SPDX-License-Identifier: Apache-2.0
//! A small, versioned, bounded wire protocol for external workers.
//!
//! This crate deliberately owns only bytes and data contracts.  It does not
//! open a socket, start a process, know about a JVM, or expose a Rust ABI.
//! Workers are expected to communicate using [`FrameCodec`] over an explicitly
//! configured transport supplied by a higher-level crate.
//!
//! # Version 1 wire format
//!
//! Each frame starts with a 36-byte, big-endian header followed by metadata
//! and an opaque payload.  The header is:
//!
//! ```text
//!  0..4   magic              b"JMBP"
//!  4      protocol version   1
//!  5      message kind       see [`MessageKind`]
//!  6..8   flags              known cancellation/profile bits only
//!  8..16  request ID         u64
//! 16..24  deadline           absolute Unix milliseconds; zero means none
//! 24..26  profile length     u16, bytes in metadata
//! 26..28  capability count  u16, entries in metadata
//! 28..32  metadata length   u32
//! 32..36  payload length    u32
//! ```
//!
//! Metadata is the UTF-8 profile identifier (when present), followed by the
//! capability count of length-prefixed UTF-8 capability identifiers.  The
//! metadata length must exactly cover those fields; there is no padding or
//! implicit extension area in version 1.  A handshake payload may use the
//! structured [`Handshake`] declaration; operation payloads remain opaque to
//! the framing layer.  Kind-specific header semantics are checked as well:
//! handshakes use request ID zero and carry a profile, operation IDs are
//! non-zero, cancellation notifications carry `Requested`, and response-like
//! messages do not carry request metadata.
//!
//! [`FrameCodec::decode`] is non-consuming: it reports [`DecodeResult::Incomplete`]
//! until a whole frame is available, and reports how many bytes were consumed
//! for a complete frame.  This makes partial reads and concatenated frames
//! safe without a hidden unbounded buffer.  [`FrameCodec::decode_next`] is a
//! convenience for advancing a caller-owned slice only after a complete
//! frame has been validated.  The default decode policy permits trailing bytes
//! because they may be the next frame; [`FrameCodec::decode_exact`] explicitly
//! rejects them.
//!
//! Version and message-kind handling is intentionally fail-closed.  A version
//! 1 decoder rejects a different version, unknown kinds, unknown flags, and
//! malformed metadata rather than guessing at a newer layout.  A future
//! protocol version may negotiate a new header/layout during a handshake, but
//! must not be silently parsed by this implementation.  New payload fields
//! are the responsibility of the message-kind decoder and may be carried as
//! opaque bytes by this crate.  Limits are checked from the fixed header before
//! any payload, profile, or capability allocation occurs. Structured error
//! payloads are preflighted from the header's kind and payload length before
//! the body is waited for or copied.

use core::fmt;
use std::str;

/// Legacy bounded JVM fixture codec retained for migration diagnostics only.
///
/// This module is not the `jvm-capability/2` execution contract and is not
/// selected by the standalone application. Use [`jvm_capability_v2`] for the
/// canonical schema.
// Keep the implementation under a non-deprecated hidden name so its own
// test-harness paths do not trigger deprecation diagnostics. The public alias
// below retains the migration warning for callers.
#[allow(
    clippy::expect_used,
    clippy::field_reassign_with_default,
    clippy::items_after_test_module,
    clippy::panic
)]
#[path = "jvm_capability.rs"]
#[doc(hidden)]
pub mod legacy_jvm_capability_impl;

#[deprecated(
    note = "legacy provisional JVM codec; use `jvm_capability_v2` for the canonical schema"
)]
pub use legacy_jvm_capability_impl as legacy_jvm_capability;

/// Pure, canonical JVM capability version-two operation and transaction
/// schema. The legacy provisional codec remains available in
/// [`legacy_jvm_capability`] for migration diagnostics, but is not an
/// execution contract.
// JVC2's pure fixtures use explicit `expect`/`panic` assertions to identify
// which canonical-vector setup failed. They are test-only and do not weaken
// production decoding or execution paths.
#[allow(clippy::expect_used, clippy::panic)]
pub mod jvm_capability_v2;

/// Pure, bounded stream schema for the pinned Java RMI adapter.
pub mod rmi;

/// The four-byte version-1 framing marker.
pub const MAGIC: [u8; 4] = *b"JMBP";
/// The only protocol version understood by this crate.
pub const PROTOCOL_VERSION: u8 = 1;
/// Size of the fixed version-1 header in bytes.
pub const HEADER_LEN: usize = 36;
/// A conservative default maximum payload size.
pub const DEFAULT_MAX_PAYLOAD_LEN: usize = 1024 * 1024;
/// Backwards-friendly name for [`DEFAULT_MAX_PAYLOAD_LEN`].
pub const MAX_PAYLOAD_LEN: usize = DEFAULT_MAX_PAYLOAD_LEN;
/// Maximum encoded size of one complete frame, including its header.
///
/// This is an independent hard bound.  A caller may choose smaller per-field
/// limits, but cannot raise this aggregate ceiling by supplying custom
/// [`FrameLimits`].
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
/// Default aggregate encoded frame limit.
pub const DEFAULT_MAX_FRAME_BYTES: usize = MAX_FRAME_BYTES;
/// Largest message/payload bound representable by the hard frame cap when no
/// metadata bytes are present.
pub const MAX_MESSAGE_BYTES: usize = MAX_FRAME_BYTES - HEADER_LEN;
/// Maximum payload bytes that can be carried by an error frame with the
/// default structured-error message bound.
pub const MAX_ERROR_PAYLOAD_LEN: usize = ERROR_PAYLOAD_HEADER_LEN + MAX_ERROR_MESSAGE_LEN;
/// Maximum profile identifier length supported by version 1.
pub const MAX_PROFILE_LEN: usize = 256;
/// Maximum number of capability identifiers in one frame.
pub const MAX_CAPABILITIES: usize = 256;
/// Maximum UTF-8 capability identifier length.
pub const MAX_CAPABILITY_LEN: usize = 256;
/// Maximum metadata bytes supported by version 1.
pub const MAX_METADATA_LEN: usize = 64 * 1024;
/// Maximum UTF-8 message carried by a structured remote error.
pub const MAX_ERROR_MESSAGE_LEN: usize = 4096;

const FLAG_CANCEL_REQUESTED: u16 = 0x0001;
const FLAG_CANCELLED: u16 = 0x0002;
const FLAG_PROFILE_PRESENT: u16 = 0x0004;
const KNOWN_FLAGS: u16 = FLAG_CANCEL_REQUESTED | FLAG_CANCELLED | FLAG_PROFILE_PRESENT;
const ERROR_PAYLOAD_HEADER_LEN: usize = 5;
const ERROR_FLAG_RETRYABLE: u8 = 0x01;

// The payload is deliberately independent from the fixed frame header.  A
// payload magic and schema byte let a future implementation reject or
// preserve an extension without confusing it with an opaque operation body.
const HANDSHAKE_PAYLOAD_MAGIC: [u8; 4] = *b"JHS1";
const HANDSHAKE_PAYLOAD_VERSION: u8 = 1;
const HANDSHAKE_FIXED_PAYLOAD_LEN: usize = 37;
const HANDSHAKE_FLAG_SELECTED_VERSION: u8 = 0x01;
const HANDSHAKE_FLAG_PRESERVE_UNKNOWN_MESSAGES: u8 = 0x02;
const HANDSHAKE_FLAG_PRESERVE_UNKNOWN_FIELDS: u8 = 0x04;
const HANDSHAKE_FLAG_PRESERVE_OPAQUE_PAYLOADS: u8 = 0x08;
const HANDSHAKE_FLAG_PRESERVE_UNKNOWN_CAPABILITIES: u8 = 0x10;
const HANDSHAKE_KNOWN_FLAGS: u8 = HANDSHAKE_FLAG_SELECTED_VERSION
    | HANDSHAKE_FLAG_PRESERVE_UNKNOWN_MESSAGES
    | HANDSHAKE_FLAG_PRESERVE_UNKNOWN_FIELDS
    | HANDSHAKE_FLAG_PRESERVE_OPAQUE_PAYLOADS
    | HANDSHAKE_FLAG_PRESERVE_UNKNOWN_CAPABILITIES;
const MAX_IDENTITY_NAME_LEN: usize = 256;
const MAX_IDENTITY_VERSION_LEN: usize = 128;
const MAX_HANDSHAKE_MESSAGE_KINDS: usize = 32;
const MAX_HANDSHAKE_CAPABILITY_BYTES: usize = MAX_METADATA_LEN;

/// Validates a consumer-declared message bound against the hard frame cap.
///
/// This helper is intentionally independent of a caller's lower per-frame
/// limit so manifest/configuration crates cannot advertise a message size the
/// bridge can never encode or decode.
pub const fn validate_message_limit(maximum: usize) -> Result<(), FrameLimitsError> {
    if maximum > MAX_MESSAGE_BYTES {
        Err(FrameLimitsError::MessageExceedsFrame {
            message: maximum,
            frame: MAX_FRAME_BYTES,
        })
    } else {
        Ok(())
    }
}

/// Compatibility spelling for [`validate_message_limit`].
pub const fn validate_max_message_bytes(maximum: usize) -> Result<(), FrameLimitsError> {
    validate_message_limit(maximum)
}

/// Validates capability count, entry length, and aggregate-byte declarations
/// shared by plugin and worker manifests.
pub const fn validate_capability_limits(
    maximum_count: usize,
    maximum_length: usize,
    maximum_bytes: usize,
    metadata_limit: usize,
) -> Result<(), FrameLimitsError> {
    if maximum_count > MAX_CAPABILITIES || maximum_count > u16::MAX as usize {
        return Err(FrameLimitsError::CapabilityCount {
            declared: maximum_count,
            maximum: if MAX_CAPABILITIES < u16::MAX as usize {
                MAX_CAPABILITIES
            } else {
                u16::MAX as usize
            },
        });
    }
    if maximum_length > MAX_CAPABILITY_LEN || maximum_length > u16::MAX as usize {
        return Err(FrameLimitsError::CapabilityLength {
            declared: maximum_length,
            maximum: if MAX_CAPABILITY_LEN < u16::MAX as usize {
                MAX_CAPABILITY_LEN
            } else {
                u16::MAX as usize
            },
        });
    }
    // `metadata_limit` is a caller-specific lower bound, not an authority to
    // raise the version-1 hard cap.  Keep this helper safe when called without
    // the complete `FrameLimits::validate` path.
    if metadata_limit > MAX_METADATA_LEN {
        return Err(FrameLimitsError::CapabilityBytes {
            declared: metadata_limit,
            maximum: MAX_METADATA_LEN,
        });
    }
    if maximum_bytes > MAX_METADATA_LEN {
        return Err(FrameLimitsError::CapabilityBytes {
            declared: maximum_bytes,
            maximum: MAX_METADATA_LEN,
        });
    }
    if maximum_bytes > metadata_limit {
        return Err(FrameLimitsError::CapabilityBytes {
            declared: maximum_bytes,
            maximum: if metadata_limit < MAX_METADATA_LEN {
                metadata_limit
            } else {
                MAX_METADATA_LEN
            },
        });
    }
    Ok(())
}

/// A request or notification identity shared by one worker session.
pub type RequestId = u64;

/// A message kind recognized by version 1.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum MessageKind {
    /// Capability/profile negotiation message.
    Handshake = 1,
    /// A worker operation request.
    Request = 2,
    /// A successful operation response.
    Response = 3,
    /// A cancellation notification.
    Cancel = 4,
    /// A response carrying a [`RemoteError`].
    Error = 5,
}

impl MessageKind {
    /// Compatibility spelling for a handshake message.
    pub const HELLO: Self = Self::Handshake;
    /// Compatibility spelling for a request message.
    pub const CALL: Self = Self::Request;
    /// Compatibility spelling for a response message.
    pub const RESULT: Self = Self::Response;
    /// Compatibility spelling for a cancellation message.
    pub const CANCELLATION: Self = Self::Cancel;

    /// Returns every message kind defined by protocol version 1 in wire order.
    pub const fn all() -> [Self; 5] {
        [
            Self::Handshake,
            Self::Request,
            Self::Response,
            Self::Cancel,
            Self::Error,
        ]
    }

    fn from_wire(value: u8) -> Result<Self, DecodeError> {
        match value {
            1 => Ok(Self::Handshake),
            2 => Ok(Self::Request),
            3 => Ok(Self::Response),
            4 => Ok(Self::Cancel),
            5 => Ok(Self::Error),
            other => Err(DecodeError::UnknownMessageKind(other)),
        }
    }
}

impl fmt::Display for MessageKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Handshake => "handshake",
            Self::Request => "request",
            Self::Response => "response",
            Self::Cancel => "cancel",
            Self::Error => "error",
        })
    }
}

/// An inclusive range of protocol versions a peer can speak.
///
/// The framing header remains version 1 while this range is negotiated in a
/// structured handshake payload.  Keeping the range explicit prevents a
/// worker from treating an unknown version as the nearest known version.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProtocolVersionRange {
    /// Lowest supported protocol version, inclusive.
    pub minimum: u16,
    /// Highest supported protocol version, inclusive.
    pub maximum: u16,
}

/// Compatibility alias for callers that use the shorter name.
pub type VersionRange = ProtocolVersionRange;

impl ProtocolVersionRange {
    /// Creates a non-empty inclusive version range.
    pub const fn new(minimum: u16, maximum: u16) -> Result<Self, VersionRangeError> {
        if minimum == 0 || maximum == 0 || minimum > maximum {
            Err(VersionRangeError::Invalid { minimum, maximum })
        } else {
            Ok(Self { minimum, maximum })
        }
    }

    /// Creates a range containing one protocol version.
    pub const fn exact(version: u16) -> Result<Self, VersionRangeError> {
        Self::new(version, version)
    }

    /// Returns whether `version` is within this range.
    pub const fn contains(self, version: u16) -> bool {
        version >= self.minimum && version <= self.maximum
    }

    /// Returns the intersection with another range, if one exists.
    pub const fn intersect(self, other: Self) -> Option<Self> {
        let minimum = if self.minimum > other.minimum {
            self.minimum
        } else {
            other.minimum
        };
        let maximum = if self.maximum < other.maximum {
            self.maximum
        } else {
            other.maximum
        };
        if minimum <= maximum {
            Some(Self { minimum, maximum })
        } else {
            None
        }
    }

    /// Selects the highest common version, as required by the handshake.
    pub const fn select(self, other: Self) -> Option<u16> {
        match self.intersect(other) {
            Some(common) => Some(common.maximum),
            None => None,
        }
    }
}

/// A malformed or empty supported-version range.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum VersionRangeError {
    /// The range has a zero endpoint or its minimum is greater than maximum.
    Invalid {
        /// Lower endpoint supplied by the caller.
        minimum: u16,
        /// Upper endpoint supplied by the caller.
        maximum: u16,
    },
}

impl fmt::Display for VersionRangeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid { minimum, maximum } => write!(
                formatter,
                "invalid protocol version range {minimum}..={maximum}"
            ),
        }
    }
}

impl std::error::Error for VersionRangeError {}

/// The kind of peer represented by a handshake identity.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum PeerKind {
    /// A host or engine process.
    Worker = 1,
    /// An out-of-process plugin process.
    Plugin = 2,
}

impl PeerKind {
    fn from_wire(value: u8) -> Result<Self, HandshakeDecodeError> {
        match value {
            1 => Ok(Self::Worker),
            2 => Ok(Self::Plugin),
            other => Err(HandshakeDecodeError::UnknownPeerKind(other)),
        }
    }
}

impl fmt::Display for PeerKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Worker => "worker",
            Self::Plugin => "plugin",
        })
    }
}

/// Generic plugin/worker identity and version declaration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerIdentity {
    /// Whether this peer is a worker or plugin.
    pub kind: PeerKind,
    /// Stable product/component name, not a process ID.
    pub name: String,
    /// Component release/version string.
    pub version: String,
}

/// Compatibility alias for code that calls the declaration a component.
pub type ComponentIdentity = PeerIdentity;

impl PeerIdentity {
    /// Creates an identity declaration.
    pub fn new(kind: PeerKind, name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            kind,
            name: name.into(),
            version: version.into(),
        }
    }

    /// Creates a worker identity.
    pub fn worker(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self::new(PeerKind::Worker, name, version)
    }

    /// Creates a plugin identity.
    pub fn plugin(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self::new(PeerKind::Plugin, name, version)
    }

    fn validate(&self) -> Result<(), HandshakeEncodeError> {
        validate_handshake_text(&self.name, MAX_IDENTITY_NAME_LEN, "identity name")?;
        validate_handshake_text(&self.version, MAX_IDENTITY_VERSION_LEN, "identity version")?;
        Ok(())
    }
}

/// Preservation guarantees a peer promises for unknown protocol data.
///
/// These are peer-declared capabilities, not requests. Negotiation intersects
/// the two declarations, so a host never assumes a plugin will retain data
/// that it cannot preserve itself. Version 1 rejects unknown frame message
/// kinds and unknown structured-handshake fields; those two declarations are
/// therefore rejected by [`PreservationContract::validate`] because this
/// crate does not retain data it rejects.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PreservationContract {
    /// Whether the peer claims to retain unknown message kinds as opaque
    /// records. Version 1 cannot make this promise; validation rejects `true`.
    pub unknown_messages: bool,
    /// Whether the peer claims to retain unknown handshake fields. Version 1
    /// cannot make this promise; validation rejects `true`.
    pub unknown_fields: bool,
    /// Opaque operation payload bytes are retained without interpretation.
    pub opaque_payloads: bool,
    /// Unknown capability identifiers are retained in order.
    pub unknown_capabilities: bool,
}

/// A preservation promise that this crate cannot truthfully make.
///
/// Version 1 retains opaque operation payload bytes and capability identifiers,
/// but it rejects unknown message kinds and structured-handshake fields before
/// retaining them.  A caller may still construct this type directly for
/// inspection or compatibility with an older manifest format; the handshake
/// validation path rejects the unsupported promises before they can be
/// encoded or negotiated.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PreservationContractError {
    /// Unknown message kinds have no opaque representation in this crate.
    UnknownMessagesUnsupported,
    /// Unknown structured-handshake fields have no opaque representation in
    /// this crate.
    UnknownFieldsUnsupported,
}

impl PreservationContractError {
    /// Returns the stable machine-readable category.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnknownMessagesUnsupported => "unknown_messages_unsupported",
            Self::UnknownFieldsUnsupported => "unknown_fields_unsupported",
        }
    }
}

impl fmt::Display for PreservationContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnknownMessagesUnsupported => {
                "unknown message retention is unsupported without an opaque representation"
            }
            Self::UnknownFieldsUnsupported => {
                "unknown handshake-field retention is unsupported without an opaque representation"
            }
        })
    }
}

impl std::error::Error for PreservationContractError {}

/// Compatibility name for preservation capabilities negotiated by a peer.
pub type PreservationCapabilities = PreservationContract;

impl PreservationContract {
    /// A contract that retains every data category understood by this crate.
    ///
    /// Unknown message kinds and structured-handshake fields are intentionally
    /// false: this implementation rejects those inputs rather than retaining
    /// opaque records. Opaque operation payloads and unknown capability
    /// identifiers are retained and therefore remain true.
    pub const fn full() -> Self {
        Self {
            unknown_messages: false,
            unknown_fields: false,
            opaque_payloads: true,
            unknown_capabilities: true,
        }
    }

    /// Validates that this contract only advertises representations provided
    /// by version 1 of this crate.
    pub const fn validate(self) -> Result<(), PreservationContractError> {
        if self.unknown_messages {
            return Err(PreservationContractError::UnknownMessagesUnsupported);
        }
        if self.unknown_fields {
            return Err(PreservationContractError::UnknownFieldsUnsupported);
        }
        Ok(())
    }

    /// Intersects two contracts conservatively.
    pub const fn intersect(self, other: Self) -> Self {
        Self {
            // This crate has no opaque representation for either category.
            // Never let two manually assembled declarations manufacture a
            // negotiated promise that the wire implementation cannot keep.
            unknown_messages: false,
            unknown_fields: false,
            opaque_payloads: self.opaque_payloads && other.opaque_payloads,
            unknown_capabilities: self.unknown_capabilities && other.unknown_capabilities,
        }
    }
}

/// Aggregate bounds a peer is willing to accept after negotiation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandshakeLimits {
    /// Maximum encoded frame bytes, including the fixed header.
    pub max_frame_bytes: usize,
    /// Maximum kind-specific message/payload bytes.
    pub max_message_bytes: usize,
    /// Maximum metadata bytes in one frame.
    pub max_metadata_bytes: usize,
    /// Maximum capability identifiers in one frame.
    pub max_capabilities: usize,
    /// Maximum aggregate bytes occupied by capability identifiers.
    pub max_capability_bytes: usize,
}

/// Compatibility alias for the aggregate resource declaration.
pub type AggregateBounds = HandshakeLimits;

/// Compatibility alias for negotiated resource bounds.
pub type NegotiatedLimits = HandshakeLimits;

impl Default for HandshakeLimits {
    fn default() -> Self {
        Self {
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
            max_message_bytes: DEFAULT_MAX_PAYLOAD_LEN,
            max_metadata_bytes: MAX_METADATA_LEN,
            max_capabilities: MAX_CAPABILITIES,
            max_capability_bytes: MAX_HANDSHAKE_CAPABILITY_BYTES,
        }
    }
}

impl HandshakeLimits {
    /// Validates aggregate and wire-representable bounds.
    pub fn validate(self) -> Result<(), HandshakeLimitsError> {
        if self.max_frame_bytes < HEADER_LEN || self.max_frame_bytes > MAX_FRAME_BYTES {
            return Err(HandshakeLimitsError::FrameBytes {
                declared: self.max_frame_bytes,
                minimum: HEADER_LEN,
                maximum: MAX_FRAME_BYTES,
            });
        }
        let available = self.max_frame_bytes - HEADER_LEN;
        if self.max_message_bytes > available {
            return Err(HandshakeLimitsError::MessageExceedsFrame {
                message: self.max_message_bytes,
                frame: self.max_frame_bytes,
            });
        }
        if self.max_metadata_bytes > available || self.max_metadata_bytes > MAX_METADATA_LEN {
            return Err(HandshakeLimitsError::MetadataExceedsFrame {
                metadata: self.max_metadata_bytes,
                frame: self.max_frame_bytes,
            });
        }
        let aggregate = self
            .max_message_bytes
            .checked_add(self.max_metadata_bytes)
            .ok_or(HandshakeLimitsError::AggregateExceedsFrame {
                message: self.max_message_bytes,
                metadata: self.max_metadata_bytes,
                frame: self.max_frame_bytes,
            })?;
        if aggregate > available {
            return Err(HandshakeLimitsError::AggregateExceedsFrame {
                message: self.max_message_bytes,
                metadata: self.max_metadata_bytes,
                frame: self.max_frame_bytes,
            });
        }
        if self.max_capabilities > MAX_CAPABILITIES || self.max_capabilities > u16::MAX as usize {
            return Err(HandshakeLimitsError::CapabilityCount {
                declared: self.max_capabilities,
                maximum: MAX_CAPABILITIES.min(u16::MAX as usize),
            });
        }
        if self.max_capability_bytes > self.max_metadata_bytes {
            return Err(HandshakeLimitsError::CapabilityBytes {
                declared: self.max_capability_bytes,
                maximum: self.max_metadata_bytes,
            });
        }
        Ok(())
    }

    /// Returns the conservative intersection of two peer limits.
    pub fn intersect(self, other: Self) -> Result<Self, HandshakeLimitsError> {
        let result = Self {
            max_frame_bytes: self.max_frame_bytes.min(other.max_frame_bytes),
            max_message_bytes: self.max_message_bytes.min(other.max_message_bytes),
            max_metadata_bytes: self.max_metadata_bytes.min(other.max_metadata_bytes),
            max_capabilities: self.max_capabilities.min(other.max_capabilities),
            max_capability_bytes: self.max_capability_bytes.min(other.max_capability_bytes),
        };
        result.validate()?;
        Ok(result)
    }

    /// Converts negotiated generic bounds into checked framing limits.
    pub fn frame_limits(self) -> Result<FrameLimits, FrameLimitsError> {
        let limits = FrameLimits {
            max_payload_len: self.max_message_bytes,
            max_frame_bytes: self.max_frame_bytes,
            max_profile_len: MAX_PROFILE_LEN,
            max_capabilities: self.max_capabilities,
            max_capability_len: MAX_CAPABILITY_LEN,
            max_capability_bytes: self.max_capability_bytes,
            max_metadata_len: self.max_metadata_bytes,
            max_error_message_len: self.max_message_bytes.min(MAX_ERROR_MESSAGE_LEN),
        };
        limits.validate()?;
        Ok(limits)
    }
}

/// An impossible aggregate declaration in a handshake.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HandshakeLimitsError {
    /// The aggregate frame bound is below the header or above the hard cap.
    FrameBytes {
        /// Declared frame bound.
        declared: usize,
        /// Smallest valid frame bound.
        minimum: usize,
        /// Hard aggregate maximum.
        maximum: usize,
    },
    /// The message bound cannot fit inside the frame bound.
    MessageExceedsFrame {
        /// Declared message bound.
        message: usize,
        /// Declared frame bound.
        frame: usize,
    },
    /// The metadata bound cannot fit inside the frame bound.
    MetadataExceedsFrame {
        /// Declared metadata bound.
        metadata: usize,
        /// Declared frame bound.
        frame: usize,
    },
    /// The maximum payload and metadata cannot coexist within one frame.
    AggregateExceedsFrame {
        /// Declared payload/message bound.
        message: usize,
        /// Declared metadata bound.
        metadata: usize,
        /// Declared frame bound.
        frame: usize,
    },
    /// Capability count cannot be represented by the handshake wire format.
    CapabilityCount {
        /// Declared capability count.
        declared: usize,
        /// Maximum representable count.
        maximum: usize,
    },
    /// Capability bytes exceed the metadata aggregate bound.
    CapabilityBytes {
        /// Declared aggregate capability bytes.
        declared: usize,
        /// Maximum metadata bytes.
        maximum: usize,
    },
}

/// Stable category for handshake aggregate-limit failures.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum HandshakeLimitsErrorCode {
    /// Frame bound is outside the protocol range.
    FrameBytes = 1,
    /// Message bound is not usable with the frame bound.
    MessageExceedsFrame = 2,
    /// Metadata bound is not usable with the frame bound.
    MetadataExceedsFrame = 3,
    /// Capability count is not representable.
    CapabilityCount = 4,
    /// Capability bytes exceed metadata.
    CapabilityBytes = 5,
    /// Combined message and metadata bounds are not usable with the frame.
    AggregateExceedsFrame = 6,
}

impl HandshakeLimitsError {
    /// Returns a stable machine-readable category.
    pub const fn code(self) -> HandshakeLimitsErrorCode {
        match self {
            Self::FrameBytes { .. } => HandshakeLimitsErrorCode::FrameBytes,
            Self::MessageExceedsFrame { .. } => HandshakeLimitsErrorCode::MessageExceedsFrame,
            Self::MetadataExceedsFrame { .. } => HandshakeLimitsErrorCode::MetadataExceedsFrame,
            Self::AggregateExceedsFrame { .. } => HandshakeLimitsErrorCode::AggregateExceedsFrame,
            Self::CapabilityCount { .. } => HandshakeLimitsErrorCode::CapabilityCount,
            Self::CapabilityBytes { .. } => HandshakeLimitsErrorCode::CapabilityBytes,
        }
    }
}

impl fmt::Display for HandshakeLimitsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameBytes {
                declared,
                minimum,
                maximum,
            } => write!(
                formatter,
                "handshake max frame bytes {declared} outside {minimum}..={maximum}"
            ),
            Self::MessageExceedsFrame { message, frame } => write!(
                formatter,
                "handshake max message bytes {message} do not fit frame bound {frame}"
            ),
            Self::MetadataExceedsFrame { metadata, frame } => write!(
                formatter,
                "handshake max metadata bytes {metadata} do not fit frame bound {frame}"
            ),
            Self::AggregateExceedsFrame {
                message,
                metadata,
                frame,
            } => write!(
                formatter,
                "handshake max message bytes {message} plus metadata bytes {metadata} exceed frame bound {frame}"
            ),
            Self::CapabilityCount { declared, maximum } => write!(
                formatter,
                "handshake capability count {declared} exceeds maximum {maximum}"
            ),
            Self::CapabilityBytes { declared, maximum } => write!(
                formatter,
                "handshake capability bytes {declared} exceed maximum {maximum}"
            ),
        }
    }
}

impl std::error::Error for HandshakeLimitsError {}

/// A structured capability/profile handshake declaration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Handshake {
    /// Supported protocol-version range.
    pub versions: ProtocolVersionRange,
    /// Version selected by a response; `None` denotes an offer.
    pub selected_version: Option<u16>,
    /// Generic worker/plugin identity declaration.
    pub identity: PeerIdentity,
    /// Compatibility profile identifier.
    pub profile: String,
    /// Ordered capabilities offered by this peer.
    pub capabilities: Vec<String>,
    /// Message kinds this peer can receive and emit.
    pub supported_message_kinds: Vec<MessageKind>,
    /// Resource declarations used during negotiation.
    pub limits: HandshakeLimits,
    /// Unknown-data preservation promises.
    pub preservation: PreservationContract,
}

/// Compatibility alias for handshake offers.
pub type HandshakeOffer = Handshake;

impl Default for Handshake {
    fn default() -> Self {
        Self {
            versions: ProtocolVersionRange {
                minimum: PROTOCOL_VERSION as u16,
                maximum: PROTOCOL_VERSION as u16,
            },
            selected_version: None,
            identity: PeerIdentity::worker("unknown", "unknown"),
            profile: "unknown".to_owned(),
            capabilities: Vec::new(),
            supported_message_kinds: vec![
                MessageKind::Handshake,
                MessageKind::Request,
                MessageKind::Response,
                MessageKind::Cancel,
                MessageKind::Error,
            ],
            limits: HandshakeLimits::default(),
            preservation: PreservationContract::full(),
        }
    }
}

impl Handshake {
    /// Creates a declaration with default profile, message, limit, and
    /// preservation values.
    pub fn new(identity: PeerIdentity, versions: ProtocolVersionRange) -> Self {
        Self {
            identity,
            versions,
            ..Self::default()
        }
    }

    /// Creates a worker declaration for one compatibility profile.
    pub fn worker(
        name: impl Into<String>,
        version: impl Into<String>,
        profile: impl Into<String>,
    ) -> Self {
        Self {
            identity: PeerIdentity::worker(name, version),
            profile: profile.into(),
            ..Self::default()
        }
    }

    /// Creates a plugin declaration for one compatibility profile.
    pub fn plugin(
        name: impl Into<String>,
        version: impl Into<String>,
        profile: impl Into<String>,
    ) -> Self {
        Self {
            identity: PeerIdentity::plugin(name, version),
            profile: profile.into(),
            ..Self::default()
        }
    }

    /// Replaces the offered capabilities in deterministic order.
    pub fn with_capabilities<I, C>(mut self, capabilities: I) -> Self
    where
        I: IntoIterator<Item = C>,
        C: Into<String>,
    {
        self.capabilities = capabilities.into_iter().map(Into::into).collect();
        self
    }

    /// Returns the supported protocol-version range.
    pub const fn supported_versions(&self) -> ProtocolVersionRange {
        self.versions
    }

    /// Replaces the supported protocol-version range.
    pub const fn with_supported_versions(mut self, versions: ProtocolVersionRange) -> Self {
        self.versions = versions;
        self
    }

    /// Returns supported message kinds in declaration order.
    pub fn message_kinds(&self) -> &[MessageKind] {
        &self.supported_message_kinds
    }

    /// Replaces supported message kinds in declaration order.
    pub fn with_message_kinds<I>(self, kinds: I) -> Self
    where
        I: IntoIterator<Item = MessageKind>,
    {
        self.with_supported_message_kinds(kinds)
    }

    /// Replaces supported message kinds; compatibility spelling for generic
    /// worker/plugin declarations.
    pub fn with_supported_kinds<I>(self, kinds: I) -> Self
    where
        I: IntoIterator<Item = MessageKind>,
    {
        self.with_supported_message_kinds(kinds)
    }

    /// Returns the peer identity declaration.
    pub fn identity(&self) -> &PeerIdentity {
        &self.identity
    }

    /// Replaces supported message kinds in deterministic order.
    pub fn with_supported_message_kinds<I>(mut self, kinds: I) -> Self
    where
        I: IntoIterator<Item = MessageKind>,
    {
        self.supported_message_kinds = kinds.into_iter().collect();
        self
    }

    /// Replaces the peer's aggregate limits.
    pub const fn with_limits(mut self, limits: HandshakeLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Sets the selected version for a handshake response.
    pub const fn with_selected_version(mut self, version: u16) -> Self {
        self.selected_version = Some(version);
        self
    }

    /// Replaces the preservation contract.
    pub const fn with_preservation(mut self, preservation: PreservationContract) -> Self {
        self.preservation = preservation;
        self
    }

    /// Validates declarations before encoding or negotiation.
    pub fn validate(&self) -> Result<(), HandshakeEncodeError> {
        ProtocolVersionRange::new(self.versions.minimum, self.versions.maximum)
            .map_err(HandshakeEncodeError::InvalidVersionRange)?;
        if let Some(selected) = self.selected_version
            && !self.versions.contains(selected)
        {
            return Err(HandshakeEncodeError::SelectedVersionOutsideRange {
                selected,
                versions: self.versions,
            });
        }
        self.identity.validate()?;
        self.preservation
            .validate()
            .map_err(HandshakeEncodeError::UnsupportedPreservation)?;
        validate_handshake_text(&self.profile, MAX_PROFILE_LEN, "profile")?;
        if self.capabilities.len() > MAX_CAPABILITIES
            || self.capabilities.len() > self.limits.max_capabilities
        {
            return Err(HandshakeEncodeError::TooManyCapabilities {
                declared: self.capabilities.len(),
                maximum: MAX_CAPABILITIES.min(self.limits.max_capabilities),
            });
        }
        let mut capability_bytes = 0usize;
        for (index, capability) in self.capabilities.iter().enumerate() {
            validate_handshake_text(capability, MAX_CAPABILITY_LEN, "capability")?;
            if self.capabilities[..index]
                .iter()
                .any(|previous| previous == capability)
            {
                return Err(HandshakeEncodeError::DuplicateCapability { index });
            }
            capability_bytes = capability_bytes
                .checked_add(capability.len())
                .and_then(|value| value.checked_add(2))
                .ok_or(HandshakeEncodeError::LengthOverflow)?;
            if capability_bytes > self.limits.max_capability_bytes {
                return Err(HandshakeEncodeError::CapabilityBytesTooLarge {
                    declared: capability_bytes,
                    maximum: self.limits.max_capability_bytes,
                    index,
                });
            }
        }
        let metadata_bytes = self
            .profile
            .len()
            .checked_add(capability_bytes)
            .ok_or(HandshakeEncodeError::LengthOverflow)?;
        if metadata_bytes > self.limits.max_metadata_bytes {
            return Err(HandshakeEncodeError::MetadataBytesTooLarge {
                declared: metadata_bytes,
                maximum: self.limits.max_metadata_bytes,
            });
        }
        if self.supported_message_kinds.is_empty() {
            return Err(HandshakeEncodeError::NoMessageKinds);
        }
        if self.supported_message_kinds.len() > MAX_HANDSHAKE_MESSAGE_KINDS {
            return Err(HandshakeEncodeError::TooManyMessageKinds {
                declared: self.supported_message_kinds.len(),
                maximum: MAX_HANDSHAKE_MESSAGE_KINDS,
            });
        }
        if self
            .supported_message_kinds
            .iter()
            .enumerate()
            .any(|(index, kind)| self.supported_message_kinds[..index].contains(kind))
        {
            return Err(HandshakeEncodeError::DuplicateMessageKind);
        }
        self.limits
            .validate()
            .map_err(HandshakeEncodeError::InvalidLimits)
    }

    /// Encodes the structured handshake declaration into a bounded payload.
    pub fn encode_payload(&self) -> Result<Vec<u8>, HandshakeEncodeError> {
        self.validate()?;
        let name_len = self.identity.name.len();
        let version_len = self.identity.version.len();
        let mut payload = Vec::with_capacity(
            HANDSHAKE_FIXED_PAYLOAD_LEN
                .checked_add(name_len)
                .and_then(|value| value.checked_add(version_len))
                .and_then(|value| value.checked_add(self.supported_message_kinds.len()))
                .ok_or(HandshakeEncodeError::LengthOverflow)?,
        );
        payload.extend_from_slice(&HANDSHAKE_PAYLOAD_MAGIC);
        payload.push(HANDSHAKE_PAYLOAD_VERSION);
        let mut flags = 0;
        if self.selected_version.is_some() {
            flags |= HANDSHAKE_FLAG_SELECTED_VERSION;
        }
        if self.preservation.unknown_messages {
            flags |= HANDSHAKE_FLAG_PRESERVE_UNKNOWN_MESSAGES;
        }
        if self.preservation.unknown_fields {
            flags |= HANDSHAKE_FLAG_PRESERVE_UNKNOWN_FIELDS;
        }
        if self.preservation.opaque_payloads {
            flags |= HANDSHAKE_FLAG_PRESERVE_OPAQUE_PAYLOADS;
        }
        if self.preservation.unknown_capabilities {
            flags |= HANDSHAKE_FLAG_PRESERVE_UNKNOWN_CAPABILITIES;
        }
        payload.push(flags);
        push_u16(&mut payload, self.versions.minimum);
        push_u16(&mut payload, self.versions.maximum);
        push_u16(&mut payload, self.selected_version.unwrap_or(0));
        payload.push(self.identity.kind as u8);
        push_u16(&mut payload, name_len as u16);
        push_u16(&mut payload, version_len as u16);
        push_u16(&mut payload, self.supported_message_kinds.len() as u16);
        push_u32(&mut payload, self.limits.max_frame_bytes as u32);
        push_u32(&mut payload, self.limits.max_message_bytes as u32);
        push_u32(&mut payload, self.limits.max_metadata_bytes as u32);
        push_u16(&mut payload, self.limits.max_capabilities as u16);
        push_u32(&mut payload, self.limits.max_capability_bytes as u32);
        payload.extend_from_slice(self.identity.name.as_bytes());
        payload.extend_from_slice(self.identity.version.as_bytes());
        payload.extend(self.supported_message_kinds.iter().map(|kind| *kind as u8));
        if payload.len() > self.limits.max_message_bytes {
            return Err(HandshakeEncodeError::PayloadTooLarge {
                declared: payload.len(),
                maximum: self.limits.max_message_bytes,
            });
        }
        Ok(payload)
    }

    /// Builds a request-ID-zero handshake frame from this declaration.
    pub fn to_frame(&self) -> Result<Frame, EncodeError> {
        let payload = self.encode_payload().map_err(EncodeError::Handshake)?;
        let mut frame = Frame::handshake(0, self.profile.clone(), self.capabilities.clone());
        frame.payload = payload;
        Ok(frame)
    }

    /// Encodes this declaration through a bounded frame codec.
    pub fn encode_frame(&self, codec: &FrameCodec) -> Result<Vec<u8>, EncodeError> {
        codec.encode(&self.to_frame()?)
    }

    /// Decodes and validates a structured handshake frame.
    pub fn from_frame(frame: &Frame) -> Result<Self, HandshakeDecodeError> {
        if frame.kind != MessageKind::Handshake {
            return Err(HandshakeDecodeError::WrongMessageKind(frame.kind));
        }
        if frame.request_id != 0 {
            return Err(HandshakeDecodeError::RequestIdMustBeZero(frame.request_id));
        }
        if frame.cancellation != Cancellation::None {
            return Err(HandshakeDecodeError::InvalidCancellation(
                frame.cancellation,
            ));
        }
        let profile = frame
            .profile
            .clone()
            .ok_or(HandshakeDecodeError::MissingProfile)?;
        let mut handshake = Self::decode_payload(&frame.payload)?;
        handshake.profile = profile;
        handshake.capabilities = frame.capabilities.clone();
        handshake.validate().map_err(|error| match error {
            HandshakeEncodeError::DuplicateCapability { index } => {
                HandshakeDecodeError::DuplicateCapability { index }
            }
            error => HandshakeDecodeError::InvalidDeclaration(error),
        })?;
        Ok(handshake)
    }

    /// Decodes a handshake payload without the profile/capability metadata.
    pub fn decode_payload(payload: &[u8]) -> Result<Self, HandshakeDecodeError> {
        if payload.len() < HANDSHAKE_FIXED_PAYLOAD_LEN {
            return Err(HandshakeDecodeError::Truncated {
                minimum: HANDSHAKE_FIXED_PAYLOAD_LEN,
                actual: payload.len(),
            });
        }
        if payload[..4] != HANDSHAKE_PAYLOAD_MAGIC {
            return Err(HandshakeDecodeError::InvalidMagic {
                found: [payload[0], payload[1], payload[2], payload[3]],
            });
        }
        if payload[4] != HANDSHAKE_PAYLOAD_VERSION {
            return Err(HandshakeDecodeError::UnsupportedPayloadVersion(payload[4]));
        }
        let flags = payload[5];
        if flags & !HANDSHAKE_KNOWN_FLAGS != 0 {
            return Err(HandshakeDecodeError::UnknownFlags(
                flags & !HANDSHAKE_KNOWN_FLAGS,
            ));
        }
        if flags & HANDSHAKE_FLAG_PRESERVE_UNKNOWN_MESSAGES != 0 {
            return Err(HandshakeDecodeError::UnsupportedPreservation(
                PreservationContractError::UnknownMessagesUnsupported,
            ));
        }
        if flags & HANDSHAKE_FLAG_PRESERVE_UNKNOWN_FIELDS != 0 {
            return Err(HandshakeDecodeError::UnsupportedPreservation(
                PreservationContractError::UnknownFieldsUnsupported,
            ));
        }
        let minimum = read_u16(payload, 6);
        let maximum = read_u16(payload, 8);
        let versions = ProtocolVersionRange::new(minimum, maximum)
            .map_err(HandshakeDecodeError::InvalidVersionRange)?;
        let selected_wire = read_u16(payload, 10);
        let selected_version = if flags & HANDSHAKE_FLAG_SELECTED_VERSION != 0 {
            if selected_wire == 0 {
                return Err(HandshakeDecodeError::SelectedVersionMissing);
            }
            if !versions.contains(selected_wire) {
                return Err(HandshakeDecodeError::SelectedVersionOutsideRange {
                    selected: selected_wire,
                    versions,
                });
            }
            Some(selected_wire)
        } else {
            if selected_wire != 0 {
                return Err(HandshakeDecodeError::UnexpectedSelectedVersion(
                    selected_wire,
                ));
            }
            None
        };
        let kind = PeerKind::from_wire(payload[12])?;
        let name_len = read_u16(payload, 13) as usize;
        let version_len = read_u16(payload, 15) as usize;
        let kind_count = read_u16(payload, 17) as usize;
        let limits = HandshakeLimits {
            max_frame_bytes: read_u32(payload, 19) as usize,
            max_message_bytes: read_u32(payload, 23) as usize,
            max_metadata_bytes: read_u32(payload, 27) as usize,
            max_capabilities: read_u16(payload, 31) as usize,
            max_capability_bytes: read_u32(payload, 33) as usize,
        };
        let fixed_end = HANDSHAKE_FIXED_PAYLOAD_LEN;
        limits
            .validate()
            .map_err(HandshakeDecodeError::InvalidLimits)?;
        if name_len > MAX_IDENTITY_NAME_LEN {
            return Err(HandshakeDecodeError::IdentityNameTooLong(name_len));
        }
        if name_len == 0 {
            return Err(HandshakeDecodeError::InvalidDeclaration(
                HandshakeEncodeError::EmptyField("identity name"),
            ));
        }
        if version_len > MAX_IDENTITY_VERSION_LEN {
            return Err(HandshakeDecodeError::IdentityVersionTooLong(version_len));
        }
        if version_len == 0 {
            return Err(HandshakeDecodeError::InvalidDeclaration(
                HandshakeEncodeError::EmptyField("identity version"),
            ));
        }
        if kind_count > MAX_HANDSHAKE_MESSAGE_KINDS {
            return Err(HandshakeDecodeError::TooManyMessageKinds(kind_count));
        }
        if kind_count == 0 {
            return Err(HandshakeDecodeError::InvalidDeclaration(
                HandshakeEncodeError::NoMessageKinds,
            ));
        }
        let total = fixed_end
            .checked_add(name_len)
            .and_then(|value| value.checked_add(version_len))
            .and_then(|value| value.checked_add(kind_count))
            .ok_or(HandshakeDecodeError::LengthOverflow)?;
        if payload.len() != total {
            return Err(HandshakeDecodeError::LengthMismatch {
                declared: total,
                actual: payload.len(),
            });
        }
        if payload.len() > limits.max_message_bytes {
            return Err(HandshakeDecodeError::PayloadTooLarge {
                declared: payload.len(),
                maximum: limits.max_message_bytes,
            });
        }
        let name_end = fixed_end + name_len;
        let version_end = name_end + version_len;
        let name = str::from_utf8(&payload[fixed_end..name_end])
            .map_err(|_| HandshakeDecodeError::MalformedUtf8(HandshakeField::IdentityName))?
            .to_owned();
        let version = str::from_utf8(&payload[name_end..version_end])
            .map_err(|_| HandshakeDecodeError::MalformedUtf8(HandshakeField::IdentityVersion))?
            .to_owned();
        let mut supported_message_kinds = Vec::with_capacity(kind_count);
        for (index, wire) in payload[version_end..].iter().copied().enumerate() {
            let message_kind = MessageKind::from_wire(wire)
                .map_err(|_| HandshakeDecodeError::UnknownMessageKind { index, wire })?;
            if supported_message_kinds.contains(&message_kind) {
                return Err(HandshakeDecodeError::DuplicateMessageKind);
            }
            supported_message_kinds.push(message_kind);
        }
        let handshake = Self {
            versions,
            selected_version,
            identity: PeerIdentity::new(kind, name, version),
            profile: String::new(),
            capabilities: Vec::new(),
            supported_message_kinds,
            limits,
            preservation: PreservationContract {
                unknown_messages: flags & HANDSHAKE_FLAG_PRESERVE_UNKNOWN_MESSAGES != 0,
                unknown_fields: flags & HANDSHAKE_FLAG_PRESERVE_UNKNOWN_FIELDS != 0,
                opaque_payloads: flags & HANDSHAKE_FLAG_PRESERVE_OPAQUE_PAYLOADS != 0,
                unknown_capabilities: flags & HANDSHAKE_FLAG_PRESERVE_UNKNOWN_CAPABILITIES != 0,
            },
        };
        handshake
            .preservation
            .validate()
            .map_err(HandshakeDecodeError::UnsupportedPreservation)?;
        Ok(handshake)
    }

    /// Negotiates the implemented wire version, common message set,
    /// capabilities, and aggregate bounds with `peer`.
    pub fn negotiate(&self, peer: &Self) -> Result<NegotiatedHandshake, HandshakeError> {
        self.validate().map_err(HandshakeError::InvalidLocal)?;
        peer.validate().map_err(HandshakeError::InvalidPeer)?;
        if self.profile != peer.profile {
            return Err(HandshakeError::ProfileMismatch {
                local: self.profile.clone(),
                peer: peer.profile.clone(),
            });
        }
        let common_versions =
            self.versions
                .intersect(peer.versions)
                .ok_or(HandshakeError::NoCommonVersion {
                    local: self.versions,
                    peer: peer.versions,
                })?;
        let implemented_version = PROTOCOL_VERSION as u16;
        if !common_versions.contains(implemented_version) {
            return Err(HandshakeError::NoCommonVersion {
                local: self.versions,
                peer: peer.versions,
            });
        }
        let protocol_version = match (self.selected_version, peer.selected_version) {
            (Some(local), Some(remote)) if local != remote => {
                return Err(HandshakeError::SelectedVersionMismatch {
                    selected: remote,
                    negotiated: local,
                });
            }
            (Some(selected), _) | (_, Some(selected)) => {
                if !common_versions.contains(selected) {
                    return Err(HandshakeError::SelectedVersionMismatch {
                        selected,
                        negotiated: common_versions.maximum,
                    });
                }
                selected
            }
            (None, None) => implemented_version,
        };
        if protocol_version != implemented_version {
            return Err(HandshakeError::SelectedVersionMismatch {
                selected: protocol_version,
                negotiated: implemented_version,
            });
        }
        let supported_message_kinds = self
            .supported_message_kinds
            .iter()
            .copied()
            .filter(|kind| peer.supported_message_kinds.contains(kind))
            .collect::<Vec<_>>();
        if supported_message_kinds.is_empty() {
            return Err(HandshakeError::NoCommonMessageKinds);
        }
        let capabilities = self
            .capabilities
            .iter()
            .filter(|capability| peer.capabilities.iter().any(|other| other == *capability))
            .cloned()
            .collect::<Vec<_>>();
        if capabilities.is_empty()
            && (!self.capabilities.is_empty() || !peer.capabilities.is_empty())
        {
            return Err(HandshakeError::CapabilityMismatch {
                capability: self
                    .capabilities
                    .first()
                    .or_else(|| peer.capabilities.first())
                    .cloned()
                    .unwrap_or_default(),
            });
        }
        let limits = self
            .limits
            .intersect(peer.limits)
            .map_err(HandshakeError::InvalidNegotiatedLimits)?;
        Ok(NegotiatedHandshake {
            protocol_version,
            local_identity: self.identity.clone(),
            peer_identity: peer.identity.clone(),
            profile: self.profile.clone(),
            capabilities,
            supported_message_kinds,
            limits,
            preservation: self.preservation.intersect(peer.preservation),
        })
    }

    /// Returns a response declaration with the negotiated version selected.
    pub fn response_for(&self, peer: &Self) -> Result<Self, HandshakeError> {
        let negotiated = peer.negotiate(self)?;
        Ok(Self {
            versions: self.versions,
            selected_version: Some(negotiated.protocol_version),
            identity: self.identity.clone(),
            profile: self.profile.clone(),
            capabilities: negotiated.capabilities,
            supported_message_kinds: negotiated.supported_message_kinds,
            limits: negotiated.limits,
            preservation: negotiated.preservation,
        })
    }
}

/// Results of a successful handshake negotiation for the implemented wire
/// version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegotiatedHandshake {
    /// Implemented protocol version selected by the negotiation.
    pub protocol_version: u16,
    /// Local identity declaration.
    pub local_identity: PeerIdentity,
    /// Remote identity declaration.
    pub peer_identity: PeerIdentity,
    /// Negotiated profile identifier.
    pub profile: String,
    /// Capabilities present on both peers, in local offer order.
    pub capabilities: Vec<String>,
    /// Message kinds present on both peers, in local offer order.
    pub supported_message_kinds: Vec<MessageKind>,
    /// Conservative aggregate limits.
    pub limits: HandshakeLimits,
    /// Intersected preservation contract.
    pub preservation: PreservationContract,
}

/// Stable categories for structured-handshake encoding failures.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum HandshakeEncodeErrorCode {
    /// A version range is malformed.
    InvalidVersionRange = 1,
    /// A selected response version is outside its offer.
    SelectedVersionOutsideRange = 2,
    /// A required textual field is empty.
    EmptyField = 3,
    /// A textual field exceeds its bound.
    FieldTooLong = 4,
    /// Capability count exceeds its bound.
    TooManyCapabilities = 5,
    /// Capability aggregate exceeds its bound.
    CapabilityBytesTooLarge = 6,
    /// Profile plus capabilities exceed the metadata aggregate bound.
    MetadataBytesTooLarge = 7,
    /// No message kinds were declared.
    NoMessageKinds = 8,
    /// Message-kind count exceeds its bound.
    TooManyMessageKinds = 9,
    /// Message kinds were repeated.
    DuplicateMessageKind = 10,
    /// A bound is impossible or not representable.
    InvalidLimits = 11,
    /// Arithmetic overflow occurred while sizing the payload.
    LengthOverflow = 12,
    /// A handshake payload would exceed the codec's payload bound.
    PayloadTooLarge = 13,
    /// The declaration advertises unsupported unknown-data retention.
    UnsupportedPreservation = 14,
    /// A capability identifier appears more than once.
    DuplicateCapability = 15,
}

impl HandshakeEncodeErrorCode {
    /// Returns the stable numeric diagnostic code.
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    /// Returns the stable symbolic diagnostic code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidVersionRange => "invalid_version_range",
            Self::SelectedVersionOutsideRange => "selected_version_outside_range",
            Self::EmptyField => "empty_field",
            Self::FieldTooLong => "field_too_long",
            Self::TooManyCapabilities => "too_many_capabilities",
            Self::CapabilityBytesTooLarge => "capability_bytes_too_large",
            Self::DuplicateCapability => "duplicate_capability",
            Self::MetadataBytesTooLarge => "metadata_bytes_too_large",
            Self::NoMessageKinds => "no_message_kinds",
            Self::TooManyMessageKinds => "too_many_message_kinds",
            Self::DuplicateMessageKind => "duplicate_message_kind",
            Self::InvalidLimits => "invalid_limits",
            Self::LengthOverflow => "length_overflow",
            Self::PayloadTooLarge => "payload_too_large",
            Self::UnsupportedPreservation => "unsupported_preservation",
        }
    }
}

/// A failure while encoding a structured handshake declaration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HandshakeEncodeError {
    /// The version range is malformed.
    InvalidVersionRange(VersionRangeError),
    /// A selected version is not in the offered range.
    SelectedVersionOutsideRange {
        /// Version selected by the response.
        selected: u16,
        /// Offer range.
        versions: ProtocolVersionRange,
    },
    /// A bounded text field is empty.
    EmptyField(&'static str),
    /// A bounded text field is too long.
    FieldTooLong {
        /// Field label.
        field: &'static str,
        /// Declared byte count.
        declared: usize,
        /// Maximum byte count.
        maximum: usize,
    },
    /// Too many capability identifiers were declared.
    TooManyCapabilities {
        /// Declared count.
        declared: usize,
        /// Maximum count.
        maximum: usize,
    },
    /// Capability metadata exceeds its aggregate bound.
    CapabilityBytesTooLarge {
        /// Declared aggregate bytes.
        declared: usize,
        /// Maximum aggregate bytes.
        maximum: usize,
        /// Last capability index included in the count.
        index: usize,
    },
    /// A capability identifier appears more than once.
    DuplicateCapability {
        /// Zero-based index of the repeated identifier.
        index: usize,
    },
    /// Profile plus capability metadata exceeds its aggregate bound.
    MetadataBytesTooLarge {
        /// Aggregate metadata bytes.
        declared: usize,
        /// Maximum aggregate bytes.
        maximum: usize,
    },
    /// No supported message kinds were declared.
    NoMessageKinds,
    /// Too many supported message kinds were declared.
    TooManyMessageKinds {
        /// Declared count.
        declared: usize,
        /// Maximum count.
        maximum: usize,
    },
    /// A message kind appears more than once.
    DuplicateMessageKind,
    /// A declared aggregate bound is impossible.
    InvalidLimits(HandshakeLimitsError),
    /// Payload sizing overflowed `usize`.
    LengthOverflow,
    /// Encoded payload exceeds the selected codec limit.
    PayloadTooLarge {
        /// Encoded payload bytes.
        declared: usize,
        /// Maximum payload bytes.
        maximum: usize,
    },
    /// The declaration promises retention that this crate cannot provide.
    UnsupportedPreservation(PreservationContractError),
}

impl HandshakeEncodeError {
    /// Returns a stable machine-readable category.
    pub const fn code(&self) -> HandshakeEncodeErrorCode {
        match self {
            Self::InvalidVersionRange(_) => HandshakeEncodeErrorCode::InvalidVersionRange,
            Self::SelectedVersionOutsideRange { .. } => {
                HandshakeEncodeErrorCode::SelectedVersionOutsideRange
            }
            Self::EmptyField(_) => HandshakeEncodeErrorCode::EmptyField,
            Self::FieldTooLong { .. } => HandshakeEncodeErrorCode::FieldTooLong,
            Self::TooManyCapabilities { .. } => HandshakeEncodeErrorCode::TooManyCapabilities,
            Self::CapabilityBytesTooLarge { .. } => {
                HandshakeEncodeErrorCode::CapabilityBytesTooLarge
            }
            Self::DuplicateCapability { .. } => HandshakeEncodeErrorCode::DuplicateCapability,
            Self::MetadataBytesTooLarge { .. } => HandshakeEncodeErrorCode::MetadataBytesTooLarge,
            Self::NoMessageKinds => HandshakeEncodeErrorCode::NoMessageKinds,
            Self::TooManyMessageKinds { .. } => HandshakeEncodeErrorCode::TooManyMessageKinds,
            Self::DuplicateMessageKind => HandshakeEncodeErrorCode::DuplicateMessageKind,
            Self::InvalidLimits(_) => HandshakeEncodeErrorCode::InvalidLimits,
            Self::LengthOverflow => HandshakeEncodeErrorCode::LengthOverflow,
            Self::PayloadTooLarge { .. } => HandshakeEncodeErrorCode::PayloadTooLarge,
            Self::UnsupportedPreservation(_) => HandshakeEncodeErrorCode::UnsupportedPreservation,
        }
    }
}

impl fmt::Display for HandshakeEncodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidVersionRange(error) => error.fmt(formatter),
            Self::SelectedVersionOutsideRange { selected, versions } => write!(
                formatter,
                "selected handshake version {selected} is outside {}..={}",
                versions.minimum, versions.maximum
            ),
            Self::EmptyField(field) => write!(formatter, "handshake {field} is empty"),
            Self::FieldTooLong {
                field,
                declared,
                maximum,
            } => write!(
                formatter,
                "handshake {field} length {declared} exceeds {maximum}"
            ),
            Self::TooManyCapabilities { declared, maximum } => write!(
                formatter,
                "handshake capability count {declared} exceeds {maximum}"
            ),
            Self::CapabilityBytesTooLarge {
                declared,
                maximum,
                index,
            } => write!(
                formatter,
                "handshake capability bytes {declared} exceed {maximum} at index {index}"
            ),
            Self::DuplicateCapability { index } => {
                write!(
                    formatter,
                    "handshake capability[{index}] duplicates an earlier identifier"
                )
            }
            Self::MetadataBytesTooLarge { declared, maximum } => write!(
                formatter,
                "handshake metadata bytes {declared} exceed {maximum}"
            ),
            Self::NoMessageKinds => formatter.write_str("handshake has no supported message kinds"),
            Self::TooManyMessageKinds { declared, maximum } => write!(
                formatter,
                "handshake message-kind count {declared} exceeds {maximum}"
            ),
            Self::DuplicateMessageKind => formatter.write_str("handshake repeats a message kind"),
            Self::InvalidLimits(error) => error.fmt(formatter),
            Self::LengthOverflow => formatter.write_str("handshake payload length overflow"),
            Self::PayloadTooLarge { declared, maximum } => write!(
                formatter,
                "handshake payload length {declared} exceeds maximum {maximum}"
            ),
            Self::UnsupportedPreservation(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for HandshakeEncodeError {}

/// Field locations for malformed structured handshake payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandshakeField {
    /// Peer name.
    IdentityName,
    /// Peer release/version.
    IdentityVersion,
}

impl fmt::Display for HandshakeField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::IdentityName => "identity name",
            Self::IdentityVersion => "identity version",
        })
    }
}

/// Stable categories for structured-handshake decoding failures.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum HandshakeDecodeErrorCode {
    /// The frame is not a handshake.
    WrongMessageKind = 1,
    /// The handshake correlation ID is not zero.
    RequestId = 2,
    /// Profile metadata was omitted.
    MissingProfile = 3,
    /// The payload is shorter than its fixed prefix.
    Truncated = 4,
    /// Payload magic does not identify this schema.
    InvalidMagic = 5,
    /// Payload schema version is unknown.
    UnsupportedPayloadVersion = 6,
    /// Reserved payload flags were set.
    UnknownFlags = 7,
    /// A version range is malformed.
    InvalidVersionRange = 8,
    /// A selected version field is malformed.
    SelectedVersion = 9,
    /// Peer kind is unknown.
    UnknownPeerKind = 10,
    /// Identity text exceeds its bound.
    IdentityTooLong = 11,
    /// Message-kind declaration exceeds its bound.
    TooManyMessageKinds = 12,
    /// A payload field has an impossible length.
    LengthMismatch = 13,
    /// A bounded text field is malformed UTF-8.
    MalformedUtf8 = 14,
    /// A message kind is unknown.
    UnknownMessageKind = 15,
    /// A message kind appears more than once.
    DuplicateMessageKind = 16,
    /// Aggregate limits are impossible.
    InvalidLimits = 17,
    /// Length arithmetic overflowed.
    LengthOverflow = 18,
    /// A declaration fails semantic validation after decoding.
    InvalidDeclaration = 19,
    /// The encoded declaration exceeds the peer's message bound.
    PayloadTooLarge = 20,
    /// A handshake frame carries a cancellation state.
    InvalidCancellation = 21,
    /// The declaration advertises unsupported unknown-data retention.
    UnsupportedPreservation = 22,
    /// The frame violates the limits of the codec used to decode it.
    CodecViolation = 23,
    /// A capability identifier appears more than once.
    DuplicateCapability = 24,
}

impl HandshakeDecodeErrorCode {
    /// Returns the stable numeric diagnostic code.
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    /// Returns the stable symbolic diagnostic code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WrongMessageKind => "wrong_message_kind",
            Self::RequestId => "request_id",
            Self::MissingProfile => "missing_profile",
            Self::Truncated => "truncated",
            Self::InvalidMagic => "invalid_magic",
            Self::UnsupportedPayloadVersion => "unsupported_payload_version",
            Self::UnknownFlags => "unknown_flags",
            Self::InvalidVersionRange => "invalid_version_range",
            Self::SelectedVersion => "selected_version",
            Self::UnknownPeerKind => "unknown_peer_kind",
            Self::IdentityTooLong => "identity_too_long",
            Self::TooManyMessageKinds => "too_many_message_kinds",
            Self::LengthMismatch => "length_mismatch",
            Self::MalformedUtf8 => "malformed_utf8",
            Self::UnknownMessageKind => "unknown_message_kind",
            Self::DuplicateMessageKind => "duplicate_message_kind",
            Self::InvalidLimits => "invalid_limits",
            Self::LengthOverflow => "length_overflow",
            Self::InvalidDeclaration => "invalid_declaration",
            Self::PayloadTooLarge => "payload_too_large",
            Self::InvalidCancellation => "invalid_cancellation",
            Self::UnsupportedPreservation => "unsupported_preservation",
            Self::CodecViolation => "codec_violation",
            Self::DuplicateCapability => "duplicate_capability",
        }
    }
}

/// A failure while decoding a structured handshake declaration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HandshakeDecodeError {
    /// The frame kind was not `Handshake`.
    WrongMessageKind(MessageKind),
    /// Handshake frames use reserved request ID zero.
    RequestIdMustBeZero(RequestId),
    /// Handshake frames cannot carry cancellation flags.
    InvalidCancellation(Cancellation),
    /// Profile metadata was absent.
    MissingProfile,
    /// The payload is shorter than the fixed prefix.
    Truncated {
        /// Minimum bytes required.
        minimum: usize,
        /// Actual bytes supplied.
        actual: usize,
    },
    /// Payload magic did not match.
    InvalidMagic {
        /// Four bytes found in the payload.
        found: [u8; 4],
    },
    /// Payload schema version is unsupported.
    UnsupportedPayloadVersion(u8),
    /// Reserved payload flags were set.
    UnknownFlags(u8),
    /// Version range is malformed.
    InvalidVersionRange(VersionRangeError),
    /// A selected version is missing or inconsistent.
    SelectedVersionMissing,
    /// Selected version is outside the range.
    SelectedVersionOutsideRange {
        /// Selected version.
        selected: u16,
        /// Declared range.
        versions: ProtocolVersionRange,
    },
    /// A selected version was present without its flag.
    UnexpectedSelectedVersion(u16),
    /// Wire peer kind is unknown.
    UnknownPeerKind(u8),
    /// Identity name is too long.
    IdentityNameTooLong(usize),
    /// Identity version is too long.
    IdentityVersionTooLong(usize),
    /// Message-kind count is too high.
    TooManyMessageKinds(usize),
    /// Payload field lengths do not consume the payload.
    LengthMismatch {
        /// Expected payload bytes.
        declared: usize,
        /// Actual payload bytes.
        actual: usize,
    },
    /// Identity bytes are malformed UTF-8.
    MalformedUtf8(HandshakeField),
    /// A message kind byte is unknown.
    UnknownMessageKind {
        /// Zero-based message-kind index.
        index: usize,
        /// Unknown wire value.
        wire: u8,
    },
    /// A message kind appears more than once.
    DuplicateMessageKind,
    /// Aggregate limits are impossible.
    InvalidLimits(HandshakeLimitsError),
    /// Length arithmetic overflowed.
    LengthOverflow,
    /// Decoded fields fail semantic validation.
    InvalidDeclaration(HandshakeEncodeError),
    /// Encoded declaration exceeds its declared message bound.
    PayloadTooLarge {
        /// Encoded payload bytes.
        declared: usize,
        /// Maximum payload bytes.
        maximum: usize,
    },
    /// The declaration advertises unsupported unknown-data retention.
    UnsupportedPreservation(PreservationContractError),
    /// A capability identifier appears more than once in frame metadata.
    DuplicateCapability {
        /// Zero-based index of the repeated identifier.
        index: usize,
    },
    /// The frame does not satisfy the limits or semantic checks of a
    /// particular codec instance.
    CodecViolation(EncodeError),
}

impl HandshakeDecodeError {
    /// Returns a stable machine-readable category.
    pub const fn code(&self) -> HandshakeDecodeErrorCode {
        match self {
            Self::WrongMessageKind(_) => HandshakeDecodeErrorCode::WrongMessageKind,
            Self::RequestIdMustBeZero(_) => HandshakeDecodeErrorCode::RequestId,
            Self::InvalidCancellation(_) => HandshakeDecodeErrorCode::InvalidCancellation,
            Self::MissingProfile => HandshakeDecodeErrorCode::MissingProfile,
            Self::Truncated { .. } => HandshakeDecodeErrorCode::Truncated,
            Self::InvalidMagic { .. } => HandshakeDecodeErrorCode::InvalidMagic,
            Self::UnsupportedPayloadVersion(_) => {
                HandshakeDecodeErrorCode::UnsupportedPayloadVersion
            }
            Self::UnknownFlags(_) => HandshakeDecodeErrorCode::UnknownFlags,
            Self::InvalidVersionRange(_) => HandshakeDecodeErrorCode::InvalidVersionRange,
            Self::SelectedVersionMissing
            | Self::SelectedVersionOutsideRange { .. }
            | Self::UnexpectedSelectedVersion(_) => HandshakeDecodeErrorCode::SelectedVersion,
            Self::UnknownPeerKind(_) => HandshakeDecodeErrorCode::UnknownPeerKind,
            Self::IdentityNameTooLong(_) | Self::IdentityVersionTooLong(_) => {
                HandshakeDecodeErrorCode::IdentityTooLong
            }
            Self::TooManyMessageKinds(_) => HandshakeDecodeErrorCode::TooManyMessageKinds,
            Self::LengthMismatch { .. } => HandshakeDecodeErrorCode::LengthMismatch,
            Self::MalformedUtf8(_) => HandshakeDecodeErrorCode::MalformedUtf8,
            Self::UnknownMessageKind { .. } => HandshakeDecodeErrorCode::UnknownMessageKind,
            Self::DuplicateMessageKind => HandshakeDecodeErrorCode::DuplicateMessageKind,
            Self::InvalidLimits(_) => HandshakeDecodeErrorCode::InvalidLimits,
            Self::LengthOverflow => HandshakeDecodeErrorCode::LengthOverflow,
            Self::InvalidDeclaration(_) => HandshakeDecodeErrorCode::InvalidDeclaration,
            Self::PayloadTooLarge { .. } => HandshakeDecodeErrorCode::PayloadTooLarge,
            Self::UnsupportedPreservation(_) => HandshakeDecodeErrorCode::UnsupportedPreservation,
            Self::CodecViolation(_) => HandshakeDecodeErrorCode::CodecViolation,
            Self::DuplicateCapability { .. } => HandshakeDecodeErrorCode::DuplicateCapability,
        }
    }
}

impl fmt::Display for HandshakeDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongMessageKind(kind) => write!(formatter, "expected handshake, got {kind}"),
            Self::RequestIdMustBeZero(id) => {
                write!(formatter, "handshake request ID {id} is not zero")
            }
            Self::InvalidCancellation(actual) => {
                write!(
                    formatter,
                    "handshake has invalid cancellation state {actual:?}"
                )
            }
            Self::MissingProfile => formatter.write_str("handshake profile metadata is missing"),
            Self::Truncated { minimum, actual } => {
                write!(
                    formatter,
                    "handshake payload has {actual} bytes; {minimum} required"
                )
            }
            Self::InvalidMagic { found } => {
                write!(formatter, "invalid handshake payload magic: {found:02x?}")
            }
            Self::UnsupportedPayloadVersion(version) => {
                write!(formatter, "unsupported handshake payload version {version}")
            }
            Self::UnknownFlags(flags) => write!(formatter, "unknown handshake flags 0x{flags:02x}"),
            Self::InvalidVersionRange(error) => error.fmt(formatter),
            Self::SelectedVersionMissing => {
                formatter.write_str("handshake selected-version flag has no version")
            }
            Self::SelectedVersionOutsideRange { selected, versions } => write!(
                formatter,
                "handshake selected version {selected} is outside {}..={}",
                versions.minimum, versions.maximum
            ),
            Self::UnexpectedSelectedVersion(version) => {
                write!(
                    formatter,
                    "handshake selected version {version} lacks its flag"
                )
            }
            Self::UnknownPeerKind(kind) => write!(formatter, "unknown handshake peer kind {kind}"),
            Self::IdentityNameTooLong(length) => write!(
                formatter,
                "handshake identity name length {length} exceeds bound"
            ),
            Self::IdentityVersionTooLong(length) => write!(
                formatter,
                "handshake identity version length {length} exceeds bound"
            ),
            Self::TooManyMessageKinds(count) => write!(
                formatter,
                "handshake message-kind count {count} exceeds bound"
            ),
            Self::LengthMismatch { declared, actual } => write!(
                formatter,
                "handshake payload expects {declared} bytes, got {actual}"
            ),
            Self::MalformedUtf8(field) => write!(formatter, "malformed UTF-8 in handshake {field}"),
            Self::UnknownMessageKind { index, wire } => write!(
                formatter,
                "unknown handshake message kind {wire} at index {index}"
            ),
            Self::DuplicateMessageKind => formatter.write_str("handshake repeats a message kind"),
            Self::InvalidLimits(error) => error.fmt(formatter),
            Self::LengthOverflow => formatter.write_str("handshake payload length overflow"),
            Self::InvalidDeclaration(error) => error.fmt(formatter),
            Self::PayloadTooLarge { declared, maximum } => write!(
                formatter,
                "handshake payload length {declared} exceeds maximum {maximum}"
            ),
            Self::UnsupportedPreservation(error) => error.fmt(formatter),
            Self::DuplicateCapability { index } => {
                write!(
                    formatter,
                    "handshake capability[{index}] duplicates an earlier identifier"
                )
            }
            Self::CodecViolation(error) => write!(formatter, "invalid handshake frame: {error}"),
        }
    }
}

impl std::error::Error for HandshakeDecodeError {}

/// Stable categories for handshake negotiation failures.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum HandshakeErrorCode {
    /// Local declaration is invalid.
    InvalidLocal = 1,
    /// Peer declaration is invalid.
    InvalidPeer = 2,
    /// No common protocol version exists.
    UnsupportedVersion = 3,
    /// A selected response version disagrees with the negotiated version.
    SelectedVersionMismatch = 4,
    /// Profiles differ.
    ProfileMismatch = 5,
    /// No common message kind exists.
    UnsupportedMessageKind = 6,
    /// Aggregate limits cannot be intersected.
    LimitMismatch = 7,
    /// Required capability is absent.
    CapabilityMismatch = 8,
}

impl HandshakeErrorCode {
    /// Returns the stable numeric diagnostic code.
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    /// Returns the stable symbolic diagnostic code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidLocal => "invalid_local",
            Self::InvalidPeer => "invalid_peer",
            Self::UnsupportedVersion => "unsupported_version",
            Self::SelectedVersionMismatch => "selected_version_mismatch",
            Self::ProfileMismatch => "profile_mismatch",
            Self::UnsupportedMessageKind => "unsupported_message_kind",
            Self::LimitMismatch => "limit_mismatch",
            Self::CapabilityMismatch => "capability_mismatch",
        }
    }
}

/// A deterministic mismatch produced by handshake negotiation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HandshakeError {
    /// The local declaration is invalid.
    InvalidLocal(HandshakeEncodeError),
    /// The peer declaration is invalid.
    InvalidPeer(HandshakeEncodeError),
    /// Version ranges have no intersection.
    NoCommonVersion {
        /// Local range.
        local: ProtocolVersionRange,
        /// Peer range.
        peer: ProtocolVersionRange,
    },
    /// A selected response version disagrees with negotiation.
    SelectedVersionMismatch {
        /// Version selected by one peer.
        selected: u16,
        /// Version independently selected by the intersection.
        negotiated: u16,
    },
    /// Profiles differ.
    ProfileMismatch {
        /// Local profile.
        local: String,
        /// Peer profile.
        peer: String,
    },
    /// No common message kind exists.
    NoCommonMessageKinds,
    /// Intersected limits are invalid.
    InvalidNegotiatedLimits(HandshakeLimitsError),
    /// One side requires a capability the other side did not advertise.
    CapabilityMismatch {
        /// Capability identifier.
        capability: String,
    },
}

impl HandshakeError {
    /// Returns a stable machine-readable category.
    pub const fn code(&self) -> HandshakeErrorCode {
        match self {
            Self::InvalidLocal(_) => HandshakeErrorCode::InvalidLocal,
            Self::InvalidPeer(_) => HandshakeErrorCode::InvalidPeer,
            Self::NoCommonVersion { .. } => HandshakeErrorCode::UnsupportedVersion,
            Self::SelectedVersionMismatch { .. } => HandshakeErrorCode::SelectedVersionMismatch,
            Self::ProfileMismatch { .. } => HandshakeErrorCode::ProfileMismatch,
            Self::NoCommonMessageKinds => HandshakeErrorCode::UnsupportedMessageKind,
            Self::InvalidNegotiatedLimits(_) => HandshakeErrorCode::LimitMismatch,
            Self::CapabilityMismatch { .. } => HandshakeErrorCode::CapabilityMismatch,
        }
    }

    /// Converts this mismatch to a structured, bounded remote diagnostic.
    pub fn to_remote_error(&self) -> RemoteError {
        let code = match self.code() {
            HandshakeErrorCode::UnsupportedVersion => RemoteErrorCode::UnsupportedVersion,
            HandshakeErrorCode::ProfileMismatch => RemoteErrorCode::ProfileMismatch,
            HandshakeErrorCode::UnsupportedMessageKind => RemoteErrorCode::UnsupportedMessageKind,
            HandshakeErrorCode::CapabilityMismatch => RemoteErrorCode::CapabilityUnavailable,
            _ => RemoteErrorCode::ProtocolViolation,
        };
        RemoteError::new(code, false, self.to_string())
    }
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLocal(error) => write!(formatter, "invalid local handshake: {error}"),
            Self::InvalidPeer(error) => write!(formatter, "invalid peer handshake: {error}"),
            Self::NoCommonVersion { local, peer } => write!(
                formatter,
                "no common protocol version between {}..={} and {}..={}",
                local.minimum, local.maximum, peer.minimum, peer.maximum
            ),
            Self::SelectedVersionMismatch {
                selected,
                negotiated,
            } => write!(
                formatter,
                "selected protocol version {selected} differs from negotiated {negotiated}"
            ),
            Self::ProfileMismatch { local, peer } => {
                write!(
                    formatter,
                    "profiles do not match ({local:?} versus {peer:?})"
                )
            }
            Self::NoCommonMessageKinds => formatter.write_str("no common bridge message kinds"),
            Self::InvalidNegotiatedLimits(error) => {
                write!(formatter, "negotiated limits are invalid: {error}")
            }
            Self::CapabilityMismatch { capability } => {
                write!(
                    formatter,
                    "required capability is unavailable: {capability}"
                )
            }
        }
    }
}

impl std::error::Error for HandshakeError {}

fn validate_handshake_text(
    value: &str,
    maximum: usize,
    field: &'static str,
) -> Result<(), HandshakeEncodeError> {
    if value.is_empty() {
        return Err(HandshakeEncodeError::EmptyField(field));
    }
    if value.len() > maximum || value.len() > u16::MAX as usize {
        return Err(HandshakeEncodeError::FieldTooLong {
            field,
            declared: value.len(),
            maximum,
        });
    }
    Ok(())
}

/// An absolute deadline represented in Unix milliseconds.
///
/// The protocol carries a value, not a clock or a sleep operation.  The
/// process that owns the transport supplies the current time and decides how
/// to enforce the deadline.  Zero is reserved for [`Deadline::NONE`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Deadline(Option<u64>);

impl Deadline {
    /// No deadline is attached to the operation.
    pub const NONE: Self = Self(None);

    /// Creates a deadline at an absolute Unix-millisecond timestamp.
    ///
    /// A zero timestamp is reserved for no deadline and therefore returns
    /// [`Deadline::NONE`].  Callers needing to distinguish an invalid zero
    /// input should validate it before constructing the protocol value.
    pub const fn at_unix_millis(timestamp: u64) -> Self {
        if timestamp == 0 {
            Self::NONE
        } else {
            Self(Some(timestamp))
        }
    }

    /// Returns the absolute timestamp, or `None` when no deadline is set.
    pub const fn as_unix_millis(self) -> Option<u64> {
        self.0
    }

    /// Returns whether this deadline has elapsed at `now_unix_millis`.
    pub const fn is_expired_at(self, now_unix_millis: u64) -> bool {
        match self.0 {
            Some(deadline) => now_unix_millis >= deadline,
            None => false,
        }
    }
}

impl Default for Deadline {
    fn default() -> Self {
        Self::NONE
    }
}

/// Cancellation state carried in a frame header.
///
/// Version 1 uses mutually exclusive request and acknowledgement states.  A
/// peer sends [`Cancellation::Requested`] to ask an operation to stop and may
/// later send [`Cancellation::Cancelled`] to report that the stop took effect.
/// Setting both wire bits is rejected as an ambiguous header.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum Cancellation {
    /// No cancellation signal.
    #[default]
    None,
    /// The operation should stop if it is still running.
    Requested,
    /// The operation was cancelled.
    Cancelled,
}

impl Cancellation {
    /// Returns `true` for either cancellation state.
    pub const fn is_active(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// Stable categories for a message's kind-specific header invariants.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum FrameValidationCode {
    /// The request ID is zero when an operation ID is required, or non-zero
    /// when the handshake ID must be zero.
    RequestId = 1,
    /// Profile metadata is required or forbidden for the message kind.
    Profile = 2,
    /// Capability metadata is forbidden for the message kind.
    Capabilities = 3,
    /// The cancellation state does not match the message kind.
    Cancellation = 4,
    /// A zero-ID error does not carry a handshake negotiation code.
    HandshakeError = 5,
}

impl FrameValidationCode {
    /// Returns a stable symbolic name for diagnostics.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RequestId => "request_id",
            Self::Profile => "profile",
            Self::Capabilities => "capabilities",
            Self::Cancellation => "cancellation",
            Self::HandshakeError => "handshake_error",
        }
    }
}

/// A message kind's fields violate the version-1 bridge contract.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FrameValidationError {
    /// A handshake must use the reserved zero request ID.
    RequestIdMustBeZero {
        /// Message kind being validated.
        kind: MessageKind,
    },
    /// An operation or cancellation must identify a non-zero request.
    RequestIdMustBeNonZero {
        /// Message kind being validated.
        kind: MessageKind,
    },
    /// A handshake must carry profile metadata.
    ProfileRequired {
        /// Message kind being validated.
        kind: MessageKind,
    },
    /// This message kind does not carry profile metadata.
    ProfileNotAllowed {
        /// Message kind being validated.
        kind: MessageKind,
    },
    /// This message kind does not carry capability metadata.
    CapabilitiesNotAllowed {
        /// Message kind being validated.
        kind: MessageKind,
    },
    /// The cancellation state is not valid for this message kind.
    InvalidCancellation {
        /// Message kind being validated.
        kind: MessageKind,
        /// State found in the frame.
        actual: Cancellation,
    },
    /// A correlation-ID-zero error carries an operational code.
    HandshakeErrorCodeNotAllowed {
        /// Code found in the error payload.
        code: RemoteErrorCode,
    },
}

impl FrameValidationError {
    /// Returns a stable category suitable for protocol diagnostics.
    pub const fn code(self) -> FrameValidationCode {
        match self {
            Self::RequestIdMustBeZero { .. } | Self::RequestIdMustBeNonZero { .. } => {
                FrameValidationCode::RequestId
            }
            Self::ProfileRequired { .. } | Self::ProfileNotAllowed { .. } => {
                FrameValidationCode::Profile
            }
            Self::CapabilitiesNotAllowed { .. } => FrameValidationCode::Capabilities,
            Self::InvalidCancellation { .. } => FrameValidationCode::Cancellation,
            Self::HandshakeErrorCodeNotAllowed { .. } => FrameValidationCode::HandshakeError,
        }
    }
}

impl fmt::Display for FrameValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequestIdMustBeZero { kind } => {
                write!(formatter, "{kind} must use request ID zero")
            }
            Self::RequestIdMustBeNonZero { kind } => {
                write!(formatter, "{kind} must use a non-zero request ID")
            }
            Self::ProfileRequired { kind } => {
                write!(formatter, "{kind} requires profile metadata")
            }
            Self::ProfileNotAllowed { kind } => {
                write!(formatter, "{kind} does not allow profile metadata")
            }
            Self::CapabilitiesNotAllowed { kind } => {
                write!(formatter, "{kind} does not allow capability metadata")
            }
            Self::InvalidCancellation { kind, actual } => write!(
                formatter,
                "{kind} has invalid cancellation state {actual:?}"
            ),
            Self::HandshakeErrorCodeNotAllowed { code } => write!(
                formatter,
                "zero-ID handshake error cannot carry operational code {}",
                code.as_str()
            ),
        }
    }
}

impl std::error::Error for FrameValidationError {}

/// A complete version-1 message before framing.
///
/// The codec validates the kind-specific header contract before writing or
/// returning a frame. Handshakes use request ID zero and require a profile;
/// operation requests, responses, ordinary errors, and cancellation
/// notifications use non-zero request IDs. A structured negotiation error is
/// the deliberate exception: it may use reserved request ID zero. Requests
/// may carry an ordinary cancellation request flag, responses may carry only
/// the cancellation acknowledgement flag, and a [`MessageKind::Cancel`]
/// frame must carry [`Cancellation::Requested`].
/// Profile and capability metadata is accepted on handshakes and requests,
/// but rejected on responses, errors, and cancellation notifications. Payload
/// bytes remain opaque for every kind so newer workers can preserve extensions.
#[derive(Clone, Eq, PartialEq)]
pub struct Frame {
    /// Message discriminator.
    pub kind: MessageKind,
    /// Correlates requests, responses, and cancellation notifications.
    pub request_id: RequestId,
    /// Optional absolute deadline.
    pub deadline: Deadline,
    /// Cancellation state.
    pub cancellation: Cancellation,
    /// Optional profile identifier, normally populated on a handshake.
    pub profile: Option<String>,
    /// Ordered capability identifiers, normally populated on a handshake.
    pub capabilities: Vec<String>,
    /// Kind-specific opaque payload bytes.
    pub payload: Vec<u8>,
}

impl fmt::Debug for Frame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Frame")
            .field("kind", &self.kind)
            .field("request_id", &self.request_id)
            .field("deadline", &self.deadline)
            .field("cancellation", &self.cancellation)
            .field("profile", &self.profile)
            .field("capabilities", &self.capabilities)
            .field("payload_len", &self.payload.len())
            .field("payload", &"<redacted>")
            .finish()
    }
}

impl Frame {
    /// Creates a frame with no deadline, cancellation, profile, or
    /// capabilities.
    pub fn new(kind: MessageKind, request_id: RequestId, payload: Vec<u8>) -> Self {
        Self {
            kind,
            request_id,
            deadline: Deadline::NONE,
            cancellation: Cancellation::None,
            profile: None,
            capabilities: Vec::new(),
            payload,
        }
    }

    /// Creates a handshake frame with profile and capability fields.
    pub fn handshake(
        request_id: RequestId,
        profile: impl Into<String>,
        capabilities: Vec<String>,
    ) -> Self {
        let mut frame = Self::new(MessageKind::Handshake, request_id, Vec::new());
        frame.profile = Some(profile.into());
        frame.capabilities = capabilities;
        frame
    }

    /// Creates a structured handshake declaration frame with correlation ID
    /// zero.
    pub fn structured_handshake(handshake: &Handshake) -> Result<Self, EncodeError> {
        handshake.to_frame()
    }

    /// Creates an error frame using the default error-payload bound. A
    /// request ID of zero is accepted only for an explicit handshake
    /// negotiation error code; operational IDs remain non-zero.
    pub fn error(request_id: RequestId, error: RemoteError) -> Result<Self, EncodeError> {
        if request_id == 0 && !error.code.is_handshake_negotiation() {
            return Err(EncodeError::InvalidFrame(
                FrameValidationError::HandshakeErrorCodeNotAllowed { code: error.code },
            ));
        }
        Ok(Self::new(
            MessageKind::Error,
            request_id,
            error.encode_payload()?,
        ))
    }

    /// Creates a correlation-ID-zero error reserved for handshake
    /// negotiation. Ordinary operation responses still use non-zero IDs; the
    /// explicit negotiation-code set distinguishes this reserved path.
    pub fn handshake_error(error: RemoteError) -> Result<Self, EncodeError> {
        Self::error(0, error)
    }

    /// Sets an absolute deadline and returns the modified frame.
    pub fn with_deadline(mut self, deadline: Deadline) -> Self {
        self.deadline = deadline;
        self
    }

    /// Sets cancellation state and returns the modified frame.
    pub fn with_cancellation(mut self, cancellation: Cancellation) -> Self {
        self.cancellation = cancellation;
        self
    }

    /// Sets a profile identifier and returns the modified frame.
    pub fn with_profile(mut self, profile: impl Into<String>) -> Self {
        self.profile = Some(profile.into());
        self
    }

    /// Sets ordered capabilities and returns the modified frame.
    pub fn with_capabilities(mut self, capabilities: Vec<String>) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// Returns the opaque payload bytes through an explicit access path.
    ///
    /// The payload is deliberately omitted from [`Debug`] output. Callers
    /// that need the raw bytes must request them explicitly or serialize the
    /// frame with [`FrameCodec`].
    pub fn payload_bytes(&self) -> &[u8] {
        &self.payload
    }

    /// Returns `true` when the frame carries a cancellation signal.
    pub const fn is_cancellation_active(&self) -> bool {
        self.cancellation.is_active()
    }

    /// Decodes this frame's payload as a structured remote error.
    pub fn remote_error(&self) -> Result<RemoteError, RemoteErrorDecodeError> {
        if self.kind != MessageKind::Error {
            return Err(RemoteErrorDecodeError::WrongMessageKind(self.kind));
        }
        RemoteError::decode_payload(&self.payload)
    }
}

/// Bounds applied before allocations by [`FrameCodec`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameLimits {
    /// Maximum kind-specific payload bytes.
    pub max_payload_len: usize,
    /// Maximum encoded bytes in one complete frame, including its header.
    pub max_frame_bytes: usize,
    /// Maximum profile identifier bytes.
    pub max_profile_len: usize,
    /// Maximum capability identifiers per frame.
    pub max_capabilities: usize,
    /// Maximum bytes in one capability identifier.
    pub max_capability_len: usize,
    /// Maximum aggregate bytes occupied by capability identifiers, including
    /// their two-byte length prefixes.
    pub max_capability_bytes: usize,
    /// Maximum metadata bytes.
    pub max_metadata_len: usize,
    /// Maximum structured remote-error message bytes.
    pub max_error_message_len: usize,
}

impl FrameLimits {
    /// Creates limits with the supplied payload bound and version-1 metadata
    /// defaults.
    pub const fn new(max_payload_len: usize) -> Self {
        Self {
            max_payload_len,
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
            max_profile_len: MAX_PROFILE_LEN,
            max_capabilities: MAX_CAPABILITIES,
            max_capability_len: MAX_CAPABILITY_LEN,
            max_capability_bytes: MAX_HANDSHAKE_CAPABILITY_BYTES,
            max_metadata_len: MAX_METADATA_LEN,
            max_error_message_len: MAX_ERROR_MESSAGE_LEN,
        }
    }

    /// Validates all bounds before a codec is constructed.
    pub fn validate(self) -> Result<(), FrameLimitsError> {
        if self.max_frame_bytes < HEADER_LEN || self.max_frame_bytes > MAX_FRAME_BYTES {
            return Err(FrameLimitsError::FrameBytes {
                declared: self.max_frame_bytes,
                minimum: HEADER_LEN,
                maximum: MAX_FRAME_BYTES,
            });
        }
        let available = self.max_frame_bytes - HEADER_LEN;
        if self.max_payload_len > available {
            return Err(FrameLimitsError::MessageExceedsFrame {
                message: self.max_payload_len,
                frame: self.max_frame_bytes,
            });
        }
        if self.max_metadata_len > available || self.max_metadata_len > MAX_METADATA_LEN {
            return Err(FrameLimitsError::MetadataExceedsFrame {
                metadata: self.max_metadata_len,
                frame: self.max_frame_bytes,
            });
        }
        let aggregate = self
            .max_payload_len
            .checked_add(self.max_metadata_len)
            .ok_or(FrameLimitsError::AggregateExceedsFrame {
                message: self.max_payload_len,
                metadata: self.max_metadata_len,
                frame: self.max_frame_bytes,
            })?;
        if aggregate > available {
            return Err(FrameLimitsError::AggregateExceedsFrame {
                message: self.max_payload_len,
                metadata: self.max_metadata_len,
                frame: self.max_frame_bytes,
            });
        }
        if self.max_profile_len > MAX_PROFILE_LEN || self.max_profile_len > u16::MAX as usize {
            return Err(FrameLimitsError::ProfileBytes {
                declared: self.max_profile_len,
                maximum: MAX_PROFILE_LEN.min(u16::MAX as usize),
            });
        }
        if self.max_capabilities > MAX_CAPABILITIES || self.max_capabilities > u16::MAX as usize {
            return Err(FrameLimitsError::CapabilityCount {
                declared: self.max_capabilities,
                maximum: MAX_CAPABILITIES.min(u16::MAX as usize),
            });
        }
        if self.max_capability_len > MAX_CAPABILITY_LEN
            || self.max_capability_len > u16::MAX as usize
        {
            return Err(FrameLimitsError::CapabilityLength {
                declared: self.max_capability_len,
                maximum: MAX_CAPABILITY_LEN.min(u16::MAX as usize),
            });
        }
        if self.max_capability_bytes > self.max_metadata_len {
            return Err(FrameLimitsError::CapabilityBytes {
                declared: self.max_capability_bytes,
                maximum: self.max_metadata_len,
            });
        }
        if self.max_error_message_len > MAX_ERROR_MESSAGE_LEN
            || self.max_error_message_len > u16::MAX as usize
        {
            return Err(FrameLimitsError::ErrorMessage {
                declared: self.max_error_message_len,
                maximum: MAX_ERROR_MESSAGE_LEN.min(u16::MAX as usize),
            });
        }
        if self.max_payload_len > u32::MAX as usize || self.max_metadata_len > u32::MAX as usize {
            return Err(FrameLimitsError::WireLength {
                field: "payload or metadata",
                declared: self.max_payload_len.max(self.max_metadata_len),
            });
        }
        Ok(())
    }

    /// Creates checked framing limits from an explicit declaration.
    pub fn try_new(limits: Self) -> Result<Self, FrameLimitsError> {
        limits.validate()?;
        Ok(limits)
    }

    /// Creates checked framing limits for a message/payload bound using the
    /// protocol's default metadata and capability bounds.
    pub fn try_for_message_bytes(max_payload_len: usize) -> Result<Self, FrameLimitsError> {
        Self::try_new(Self::new(max_payload_len))
    }

    /// Converts framing bounds into the generic handshake declaration shape.
    pub const fn as_handshake_limits(self) -> HandshakeLimits {
        HandshakeLimits {
            max_frame_bytes: self.max_frame_bytes,
            max_message_bytes: self.max_payload_len,
            max_metadata_bytes: self.max_metadata_len,
            max_capabilities: self.max_capabilities,
            max_capability_bytes: self.max_capability_bytes,
        }
    }
}

/// Compatibility name for checked framing-limit construction failures.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FrameLimitsError {
    /// Aggregate frame bound is below the header or above the hard cap.
    FrameBytes {
        /// Declared aggregate bound.
        declared: usize,
        /// Smallest valid bound.
        minimum: usize,
        /// Hard maximum.
        maximum: usize,
    },
    /// Payload/message bytes cannot fit in the frame bound.
    MessageExceedsFrame {
        /// Declared payload bound.
        message: usize,
        /// Declared frame bound.
        frame: usize,
    },
    /// Metadata bytes cannot fit in the frame bound.
    MetadataExceedsFrame {
        /// Declared metadata bound.
        metadata: usize,
        /// Declared frame bound.
        frame: usize,
    },
    /// The maximum payload and metadata cannot coexist within one frame.
    AggregateExceedsFrame {
        /// Declared payload/message bound.
        message: usize,
        /// Declared metadata bound.
        metadata: usize,
        /// Declared frame bound.
        frame: usize,
    },
    /// Profile limit exceeds its wire or protocol bound.
    ProfileBytes {
        /// Declared profile bound.
        declared: usize,
        /// Maximum profile bound.
        maximum: usize,
    },
    /// Capability count exceeds its wire or protocol bound.
    CapabilityCount {
        /// Declared count.
        declared: usize,
        /// Maximum count.
        maximum: usize,
    },
    /// One capability length exceeds its wire or protocol bound.
    CapabilityLength {
        /// Declared length.
        declared: usize,
        /// Maximum length.
        maximum: usize,
    },
    /// Aggregate capability bytes exceed metadata.
    CapabilityBytes {
        /// Declared aggregate bytes.
        declared: usize,
        /// Maximum metadata bytes.
        maximum: usize,
    },
    /// Error message bound exceeds the structured-error wire bound.
    ErrorMessage {
        /// Declared message bound.
        declared: usize,
        /// Maximum message bound.
        maximum: usize,
    },
    /// A length bound cannot be represented in a u32 wire field.
    WireLength {
        /// Field label.
        field: &'static str,
        /// Declared bound.
        declared: usize,
    },
}

/// Stable category for framing aggregate-limit failures.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum FrameLimitsErrorCode {
    /// Aggregate frame bound is outside the protocol range.
    FrameBytes = 1,
    /// Payload bound is not usable with the frame bound.
    MessageExceedsFrame = 2,
    /// Metadata bound is not usable with the frame bound.
    MetadataExceedsFrame = 3,
    /// Profile bound is not representable.
    ProfileBytes = 4,
    /// Capability count is not representable.
    CapabilityCount = 5,
    /// Capability length is not representable.
    CapabilityLength = 6,
    /// Capability bytes exceed metadata.
    CapabilityBytes = 7,
    /// Error message bound is not representable.
    ErrorMessage = 8,
    /// A u32 wire length cannot represent the bound.
    WireLength = 9,
    /// Combined payload and metadata bounds are not usable with the frame.
    AggregateExceedsFrame = 10,
}

impl FrameLimitsError {
    /// Returns a stable machine-readable category.
    pub const fn code(self) -> FrameLimitsErrorCode {
        match self {
            Self::FrameBytes { .. } => FrameLimitsErrorCode::FrameBytes,
            Self::MessageExceedsFrame { .. } => FrameLimitsErrorCode::MessageExceedsFrame,
            Self::MetadataExceedsFrame { .. } => FrameLimitsErrorCode::MetadataExceedsFrame,
            Self::AggregateExceedsFrame { .. } => FrameLimitsErrorCode::AggregateExceedsFrame,
            Self::ProfileBytes { .. } => FrameLimitsErrorCode::ProfileBytes,
            Self::CapabilityCount { .. } => FrameLimitsErrorCode::CapabilityCount,
            Self::CapabilityLength { .. } => FrameLimitsErrorCode::CapabilityLength,
            Self::CapabilityBytes { .. } => FrameLimitsErrorCode::CapabilityBytes,
            Self::ErrorMessage { .. } => FrameLimitsErrorCode::ErrorMessage,
            Self::WireLength { .. } => FrameLimitsErrorCode::WireLength,
        }
    }
}

impl fmt::Display for FrameLimitsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameBytes {
                declared,
                minimum,
                maximum,
            } => write!(
                formatter,
                "frame limit {declared} outside {minimum}..={maximum}"
            ),
            Self::MessageExceedsFrame { message, frame } => {
                write!(
                    formatter,
                    "payload limit {message} exceeds frame limit {frame}"
                )
            }
            Self::MetadataExceedsFrame { metadata, frame } => write!(
                formatter,
                "metadata limit {metadata} exceeds available frame bytes in {frame}"
            ),
            Self::AggregateExceedsFrame {
                message,
                metadata,
                frame,
            } => write!(
                formatter,
                "payload limit {message} plus metadata limit {metadata} exceed frame limit {frame}"
            ),
            Self::ProfileBytes { declared, maximum } => {
                write!(formatter, "profile limit {declared} exceeds {maximum}")
            }
            Self::CapabilityCount { declared, maximum } => {
                write!(
                    formatter,
                    "capability count limit {declared} exceeds {maximum}"
                )
            }
            Self::CapabilityLength { declared, maximum } => {
                write!(
                    formatter,
                    "capability length limit {declared} exceeds {maximum}"
                )
            }
            Self::CapabilityBytes { declared, maximum } => write!(
                formatter,
                "capability aggregate limit {declared} exceeds {maximum}"
            ),
            Self::ErrorMessage { declared, maximum } => write!(
                formatter,
                "error message limit {declared} exceeds {maximum}"
            ),
            Self::WireLength { field, declared } => {
                write!(
                    formatter,
                    "{field} limit {declared} is not representable on wire"
                )
            }
        }
    }
}

impl std::error::Error for FrameLimitsError {}

impl Default for FrameLimits {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_PAYLOAD_LEN)
    }
}

/// Stateless encoder/decoder with explicit resource bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameCodec {
    limits: FrameLimits,
}

impl FrameCodec {
    /// Creates a codec with a custom payload limit and default metadata
    /// limits.  A zero payload limit is valid and permits metadata-only
    /// handshakes.
    pub const fn new(max_payload_len: usize) -> Self {
        Self {
            limits: FrameLimits::new(max_payload_len),
        }
    }

    /// Creates a codec after rejecting impossible resource bounds.
    pub fn try_new(max_payload_len: usize) -> Result<Self, FrameLimitsError> {
        Self::try_with_limits(FrameLimits::new(max_payload_len))
    }

    /// Creates a codec from all explicit limits without changing them.
    ///
    /// This compatibility constructor retains its historical infallible
    /// signature.  It does not normalize or silently weaken a declaration;
    /// [`FrameCodec::try_with_limits`] is the checked constructor and all
    /// encode/decode operations reject invalid limits before processing data.
    pub const fn with_limits(limits: FrameLimits) -> Self {
        Self { limits }
    }

    /// Creates a codec after validating every supplied resource bound.
    ///
    /// [`FrameCodec::with_limits`] remains available for source compatibility
    /// with earlier callers.  New code should use this checked constructor so
    /// an impossible aggregate bound is rejected before a transport starts.
    pub fn try_with_limits(limits: FrameLimits) -> Result<Self, FrameLimitsError> {
        limits.validate()?;
        Ok(Self { limits })
    }

    /// Compatibility spelling for checked construction from negotiated
    /// limits.
    pub fn from_limits(limits: FrameLimits) -> Result<Self, FrameLimitsError> {
        Self::try_with_limits(limits)
    }

    /// Builds a codec from generic negotiated aggregate limits.
    pub fn from_handshake_limits(limits: HandshakeLimits) -> Result<Self, FrameLimitsError> {
        Self::try_with_limits(limits.frame_limits()?)
    }

    /// Returns the configured bounds.
    pub const fn limits(self) -> FrameLimits {
        self.limits
    }

    /// Returns the largest one-frame byte length representable by these
    /// limits, or `None` if the configured values overflow `usize`.
    pub fn max_frame_len(self) -> Option<usize> {
        if self.limits.validate().is_err() {
            return None;
        }
        let field_sum = HEADER_LEN
            .checked_add(self.limits.max_metadata_len.min(MAX_METADATA_LEN))?
            .checked_add(self.limits.max_payload_len.min(u32::MAX as usize))?;
        Some(
            field_sum
                .min(self.limits.max_frame_bytes)
                .min(MAX_FRAME_BYTES),
        )
    }

    /// Encodes one complete frame.
    pub fn encode(&self, frame: &Frame) -> Result<Vec<u8>, EncodeError> {
        self.limits.validate().map_err(EncodeError::InvalidLimits)?;
        let (metadata_len, payload_len) = self.validate_frame(frame)?;
        let total_len = HEADER_LEN
            .checked_add(metadata_len)
            .and_then(|length| length.checked_add(payload_len))
            .ok_or(EncodeError::LengthOverflow)?;
        if total_len > self.limits.max_frame_bytes || total_len > MAX_FRAME_BYTES {
            return Err(EncodeError::FrameTooLarge {
                declared: total_len,
                maximum: self.limits.max_frame_bytes.min(MAX_FRAME_BYTES),
            });
        }
        let profile_len = frame.profile.as_ref().map_or(0, String::len);
        let capability_count = frame.capabilities.len();

        let mut bytes = Vec::with_capacity(total_len);
        bytes.extend_from_slice(&MAGIC);
        bytes.push(PROTOCOL_VERSION);
        bytes.push(frame.kind as u8);

        let mut flags = 0;
        match frame.cancellation {
            Cancellation::None => {}
            Cancellation::Requested => flags |= FLAG_CANCEL_REQUESTED,
            Cancellation::Cancelled => flags |= FLAG_CANCELLED,
        }
        if frame.profile.is_some() {
            flags |= FLAG_PROFILE_PRESENT;
        }
        push_u16(&mut bytes, flags);
        push_u64(&mut bytes, frame.request_id);
        push_u64(
            &mut bytes,
            frame
                .deadline
                .as_unix_millis()
                .map_or(0, |timestamp| timestamp),
        );
        push_u16(&mut bytes, profile_len as u16);
        push_u16(&mut bytes, capability_count as u16);
        push_u32(&mut bytes, metadata_len as u32);
        push_u32(&mut bytes, payload_len as u32);

        if let Some(profile) = &frame.profile {
            bytes.extend_from_slice(profile.as_bytes());
        }
        for capability in &frame.capabilities {
            push_u16(&mut bytes, capability.len() as u16);
            bytes.extend_from_slice(capability.as_bytes());
        }
        bytes.extend_from_slice(&frame.payload);
        debug_assert_eq!(bytes.len(), total_len);
        Ok(bytes)
    }

    /// Decodes the first frame in `input` without consuming the input slice.
    ///
    /// On success, [`DecodeResult::Complete::consumed`] identifies the exact
    /// prefix belonging to the frame.  Any bytes after that prefix remain
    /// available for the next call.
    pub fn decode(&self, input: &[u8]) -> Result<DecodeResult, DecodeError> {
        self.limits.validate().map_err(DecodeError::InvalidLimits)?;
        if input.len() < HEADER_LEN {
            return Ok(DecodeResult::Incomplete {
                needed: HEADER_LEN - input.len(),
            });
        }

        if input[..MAGIC.len()] != MAGIC {
            return Err(DecodeError::InvalidMagic {
                found: [input[0], input[1], input[2], input[3]],
            });
        }
        let version = input[4];
        if version != PROTOCOL_VERSION {
            return Err(DecodeError::UnsupportedVersion(version));
        }
        let kind = MessageKind::from_wire(input[5])?;
        let flags = read_u16(input, 6);
        if flags & !KNOWN_FLAGS != 0 {
            return Err(DecodeError::UnknownFlags(flags & !KNOWN_FLAGS));
        }
        if flags & FLAG_CANCEL_REQUESTED != 0 && flags & FLAG_CANCELLED != 0 {
            return Err(DecodeError::InvalidCancellationFlags);
        }

        let request_id = read_u64(input, 8);
        let deadline_wire = read_u64(input, 16);
        let profile_len = read_u16(input, 24) as usize;
        let capability_count = read_u16(input, 26) as usize;
        let metadata_len = read_u32(input, 28) as usize;
        let payload_len = read_u32(input, 32) as usize;

        if payload_len > self.limits.max_payload_len {
            return Err(DecodeError::PayloadTooLarge {
                declared: payload_len,
                maximum: self.limits.max_payload_len,
            });
        }
        if kind == MessageKind::Error {
            let maximum = ERROR_PAYLOAD_HEADER_LEN
                .checked_add(self.limits.max_error_message_len.min(MAX_ERROR_MESSAGE_LEN))
                .ok_or(DecodeError::LengthOverflow)?;
            if payload_len > maximum {
                return Err(DecodeError::ErrorPayloadTooLarge {
                    declared: payload_len,
                    maximum,
                });
            }
        }
        if metadata_len > self.limits.max_metadata_len || metadata_len > MAX_METADATA_LEN {
            return Err(DecodeError::MetadataTooLarge {
                declared: metadata_len,
                maximum: self.limits.max_metadata_len.min(MAX_METADATA_LEN),
            });
        }
        if profile_len > self.limits.max_profile_len || profile_len > MAX_PROFILE_LEN {
            return Err(DecodeError::ProfileTooLong {
                declared: profile_len,
                maximum: self.limits.max_profile_len.min(MAX_PROFILE_LEN),
            });
        }
        if capability_count > self.limits.max_capabilities || capability_count > MAX_CAPABILITIES {
            return Err(DecodeError::TooManyCapabilities {
                declared: capability_count,
                maximum: self.limits.max_capabilities.min(MAX_CAPABILITIES),
            });
        }

        let total_len = HEADER_LEN
            .checked_add(metadata_len)
            .and_then(|length| length.checked_add(payload_len))
            .ok_or(DecodeError::LengthOverflow)?;
        if total_len > self.limits.max_frame_bytes || total_len > MAX_FRAME_BYTES {
            return Err(DecodeError::FrameTooLarge {
                declared: total_len,
                maximum: self.limits.max_frame_bytes.min(MAX_FRAME_BYTES),
            });
        }
        if input.len() < total_len {
            return Ok(DecodeResult::Incomplete {
                needed: total_len - input.len(),
            });
        }
        let payload_start = HEADER_LEN + metadata_len;

        let profile_present = flags & FLAG_PROFILE_PRESENT != 0;
        if profile_present != (profile_len != 0) {
            return Err(DecodeError::ProfileFlagMismatch {
                flag_present: profile_present,
                length: profile_len,
            });
        }

        let metadata = &input[HEADER_LEN..HEADER_LEN + metadata_len];
        let mut offset = 0usize;
        let profile_bytes = if profile_len == 0 {
            None
        } else {
            let end = offset
                .checked_add(profile_len)
                .ok_or(DecodeError::LengthOverflow)?;
            if end > metadata.len() {
                return Err(DecodeError::MetadataLengthMismatch {
                    declared: metadata_len,
                    consumed: end,
                });
            }
            let bytes = &metadata[offset..end];
            str::from_utf8(bytes).map_err(|_| DecodeError::MalformedUtf8 {
                field: Utf8Field::Profile,
            })?;
            offset = end;
            Some(bytes)
        };

        // Validate every capability before any owned value or payload is
        // allocated.  The second pass below performs the owned conversion.
        let mut capability_bytes = 0usize;
        for index in 0..capability_count {
            let length_end = offset.checked_add(2).ok_or(DecodeError::LengthOverflow)?;
            if length_end > metadata.len() {
                return Err(DecodeError::MetadataLengthMismatch {
                    declared: metadata_len,
                    consumed: length_end,
                });
            }
            let capability_len = read_u16(metadata, offset) as usize;
            offset = length_end;
            if capability_len == 0 {
                return Err(DecodeError::EmptyCapability { index });
            }
            if capability_len > self.limits.max_capability_len
                || capability_len > MAX_CAPABILITY_LEN
            {
                return Err(DecodeError::CapabilityTooLong {
                    index,
                    declared: capability_len,
                    maximum: self.limits.max_capability_len.min(MAX_CAPABILITY_LEN),
                });
            }
            let end = offset
                .checked_add(capability_len)
                .ok_or(DecodeError::LengthOverflow)?;
            if end > metadata.len() {
                return Err(DecodeError::MetadataLengthMismatch {
                    declared: metadata_len,
                    consumed: end,
                });
            }
            str::from_utf8(&metadata[offset..end]).map_err(|_| DecodeError::MalformedUtf8 {
                field: Utf8Field::Capability { index },
            })?;
            let current = &metadata[offset..end];
            let mut previous_offset = profile_len;
            for _ in 0..index {
                let previous_length_end = previous_offset
                    .checked_add(2)
                    .ok_or(DecodeError::LengthOverflow)?;
                let previous_length = read_u16(metadata, previous_offset) as usize;
                let previous_start = previous_length_end;
                let previous_end = previous_start
                    .checked_add(previous_length)
                    .ok_or(DecodeError::LengthOverflow)?;
                if &metadata[previous_start..previous_end] == current {
                    return Err(DecodeError::DuplicateCapability { index });
                }
                previous_offset = previous_end;
            }
            offset = end;
            capability_bytes = capability_bytes
                .checked_add(2)
                .and_then(|value| value.checked_add(capability_len))
                .ok_or(DecodeError::LengthOverflow)?;
            if capability_bytes > self.limits.max_capability_bytes {
                return Err(DecodeError::CapabilityBytesTooLarge {
                    declared: capability_bytes,
                    maximum: self.limits.max_capability_bytes,
                });
            }
        }
        if offset != metadata.len() {
            return Err(DecodeError::MetadataLengthMismatch {
                declared: metadata_len,
                consumed: offset,
            });
        }

        let cancellation = if flags & FLAG_CANCEL_REQUESTED != 0 {
            Cancellation::Requested
        } else if flags & FLAG_CANCELLED != 0 {
            Cancellation::Cancelled
        } else {
            Cancellation::None
        };
        let handshake_error_code = if kind == MessageKind::Error && request_id == 0 {
            handshake_error_payload_code(
                &input[payload_start..payload_start + payload_len],
                self.limits.max_error_message_len,
            )
        } else {
            None
        };
        validate_wire_semantics(
            kind,
            request_id,
            profile_present,
            capability_count,
            cancellation,
            handshake_error_code,
        )
        .map_err(DecodeError::InvalidFrame)?;

        // All header lengths and UTF-8 fields are validated before allocating
        // owned values.  This is the important resource-boundary invariant.
        let profile = match profile_bytes {
            Some(bytes) => Some(
                str::from_utf8(bytes)
                    .map_err(|_| DecodeError::MalformedUtf8 {
                        field: Utf8Field::Profile,
                    })?
                    .to_owned(),
            ),
            None => None,
        };
        let mut capabilities = Vec::with_capacity(capability_count);
        let mut capability_offset = profile_len;
        for _ in 0..capability_count {
            let capability_len = read_u16(metadata, capability_offset) as usize;
            capability_offset += 2;
            let end = capability_offset + capability_len;
            // The validation pass proves these indexes and UTF-8 conversions.
            capabilities.push(
                str::from_utf8(&metadata[capability_offset..end])
                    .map_err(|_| DecodeError::MalformedUtf8 {
                        field: Utf8Field::Capability {
                            index: capabilities.len(),
                        },
                    })?
                    .to_owned(),
            );
            capability_offset = end;
        }
        let payload = input[payload_start..payload_start + payload_len].to_vec();
        Ok(DecodeResult::Complete {
            frame: Frame {
                kind,
                request_id,
                deadline: Deadline(if deadline_wire == 0 {
                    None
                } else {
                    Some(deadline_wire)
                }),
                cancellation,
                profile,
                capabilities,
                payload,
            },
            consumed: total_len,
        })
    }

    /// Advances `input` only when a complete frame is decoded.
    ///
    /// `Ok(None)` leaves the slice untouched and means more bytes are needed.
    pub fn decode_next(&self, input: &mut &[u8]) -> Result<Option<Frame>, DecodeError> {
        let original = *input;
        match self.decode(original)? {
            DecodeResult::Incomplete { .. } => Ok(None),
            DecodeResult::Complete { frame, consumed } => {
                *input = &original[consumed..];
                Ok(Some(frame))
            }
        }
    }

    /// Decodes one frame and rejects any bytes after it.
    pub fn decode_exact(&self, input: &[u8]) -> Result<Frame, DecodeError> {
        match self.decode(input)? {
            DecodeResult::Incomplete { needed } => Err(DecodeError::Incomplete { needed }),
            DecodeResult::Complete { frame, consumed } if consumed == input.len() => Ok(frame),
            DecodeResult::Complete { consumed, .. } => Err(DecodeError::TrailingBytes {
                count: input.len() - consumed,
            }),
        }
    }

    /// Applies an explicit trailing-byte policy to a decode operation.
    pub fn decode_with_policy(
        &self,
        input: &[u8],
        policy: TrailingPolicy,
    ) -> Result<DecodeResult, DecodeError> {
        let result = self.decode(input)?;
        if let (TrailingPolicy::Reject, DecodeResult::Complete { consumed, .. }) = (policy, &result)
            && *consumed != input.len()
        {
            return Err(DecodeError::TrailingBytes {
                count: input.len() - *consumed,
            });
        }
        Ok(result)
    }

    /// Builds a structured error frame after applying the codec's payload
    /// bound.
    pub fn error_frame(
        &self,
        request_id: RequestId,
        error: RemoteError,
    ) -> Result<Frame, EncodeError> {
        let frame = Frame::new(
            MessageKind::Error,
            request_id,
            error.encode_payload_with_limit(self.limits.max_error_message_len)?,
        );
        self.validate_frame(&frame)?;
        Ok(frame)
    }

    /// Decodes a frame's structured remote error with this codec's message
    /// bound.  Generic frame decoding intentionally leaves payload semantics
    /// to the caller; this helper applies the stricter error-message limit.
    pub fn decode_remote_error(
        &self,
        frame: &Frame,
    ) -> Result<RemoteError, RemoteErrorDecodeError> {
        if frame.kind != MessageKind::Error {
            return Err(RemoteErrorDecodeError::WrongMessageKind(frame.kind));
        }
        RemoteError::decode_payload_with_limit(&frame.payload, self.limits.max_error_message_len)
    }

    /// Encodes a structured handshake through this codec's bounds.
    pub fn encode_handshake(&self, handshake: &Handshake) -> Result<Vec<u8>, EncodeError> {
        handshake.encode_frame(self)
    }

    /// Decodes a structured handshake frame through this codec's bounds.
    pub fn decode_handshake(&self, frame: &Frame) -> Result<Handshake, HandshakeDecodeError> {
        // Keep the direct frame API subject to exactly the same instance
        // limits as byte decoding.  A caller can construct `Frame` values
        // without going through `decode`, so delegating straight to
        // `Handshake::from_frame` would otherwise bypass every codec bound.
        self.limits.validate().map_err(|error| {
            HandshakeDecodeError::CodecViolation(EncodeError::InvalidLimits(error))
        })?;
        if frame.kind != MessageKind::Handshake {
            return Handshake::from_frame(frame);
        }
        if frame.cancellation != Cancellation::None {
            return Err(HandshakeDecodeError::InvalidCancellation(
                frame.cancellation,
            ));
        }
        let (metadata_len, payload_len) = match self.validate_frame(frame) {
            Ok(lengths) => lengths,
            Err(
                EncodeError::InvalidFrame(_)
                | EncodeError::EmptyProfile
                | EncodeError::EmptyCapability { .. },
            ) => {
                // Preserve the structured-handshake diagnostics exposed by
                // the direct decoder for semantic errors; only codec-bound
                // failures belong to `CodecViolation`.
                return Handshake::from_frame(frame);
            }
            Err(EncodeError::DuplicateCapability { index }) => {
                return Err(HandshakeDecodeError::DuplicateCapability { index });
            }
            Err(error) => return Err(HandshakeDecodeError::CodecViolation(error)),
        };
        let total_len = HEADER_LEN
            .checked_add(metadata_len)
            .and_then(|length| length.checked_add(payload_len))
            .ok_or(HandshakeDecodeError::CodecViolation(
                EncodeError::LengthOverflow,
            ))?;
        if total_len > self.limits.max_frame_bytes || total_len > MAX_FRAME_BYTES {
            return Err(HandshakeDecodeError::CodecViolation(
                EncodeError::FrameTooLarge {
                    declared: total_len,
                    maximum: self.limits.max_frame_bytes.min(MAX_FRAME_BYTES),
                },
            ));
        }
        Handshake::from_frame(frame)
    }

    fn validate_frame(&self, frame: &Frame) -> Result<(usize, usize), EncodeError> {
        validate_frame_semantics(frame, self.limits.max_error_message_len)
            .map_err(EncodeError::InvalidFrame)?;
        let payload_len = frame.payload.len();
        if payload_len > self.limits.max_payload_len || payload_len > u32::MAX as usize {
            return Err(EncodeError::PayloadTooLarge {
                declared: payload_len,
                maximum: self.limits.max_payload_len.min(u32::MAX as usize),
            });
        }

        let profile_len = match &frame.profile {
            None => 0,
            Some(profile) => {
                let length = profile.len();
                if length == 0 {
                    return Err(EncodeError::EmptyProfile);
                }
                if length > self.limits.max_profile_len || length > MAX_PROFILE_LEN {
                    return Err(EncodeError::ProfileTooLong {
                        declared: length,
                        maximum: self.limits.max_profile_len.min(MAX_PROFILE_LEN),
                    });
                }
                if length > u16::MAX as usize {
                    return Err(EncodeError::ProfileTooLong {
                        declared: length,
                        maximum: u16::MAX as usize,
                    });
                }
                length
            }
        };

        let capability_count = frame.capabilities.len();
        if capability_count > self.limits.max_capabilities || capability_count > MAX_CAPABILITIES {
            return Err(EncodeError::TooManyCapabilities {
                declared: capability_count,
                maximum: self.limits.max_capabilities.min(MAX_CAPABILITIES),
            });
        }
        let mut metadata_len = profile_len;
        let mut capability_bytes = 0usize;
        for (index, capability) in frame.capabilities.iter().enumerate() {
            let length = capability.len();
            if length == 0 {
                return Err(EncodeError::EmptyCapability { index });
            }
            if length > self.limits.max_capability_len || length > MAX_CAPABILITY_LEN {
                return Err(EncodeError::CapabilityTooLong {
                    index,
                    declared: length,
                    maximum: self.limits.max_capability_len.min(MAX_CAPABILITY_LEN),
                });
            }
            if length > u16::MAX as usize {
                return Err(EncodeError::CapabilityTooLong {
                    index,
                    declared: length,
                    maximum: u16::MAX as usize,
                });
            }
            if frame.capabilities[..index]
                .iter()
                .any(|previous| previous == capability)
            {
                return Err(EncodeError::DuplicateCapability { index });
            }
            metadata_len = metadata_len
                .checked_add(2)
                .and_then(|value| value.checked_add(length))
                .ok_or(EncodeError::LengthOverflow)?;
            capability_bytes = capability_bytes
                .checked_add(2)
                .and_then(|value| value.checked_add(length))
                .ok_or(EncodeError::LengthOverflow)?;
            if capability_bytes > self.limits.max_capability_bytes {
                return Err(EncodeError::CapabilityBytesTooLarge {
                    declared: capability_bytes,
                    maximum: self.limits.max_capability_bytes,
                });
            }
        }
        if metadata_len > self.limits.max_metadata_len
            || metadata_len > MAX_METADATA_LEN
            || metadata_len > u32::MAX as usize
        {
            return Err(EncodeError::MetadataTooLarge {
                declared: metadata_len,
                maximum: self.limits.max_metadata_len.min(MAX_METADATA_LEN),
            });
        }
        Ok((metadata_len, payload_len))
    }
}

fn validate_frame_semantics(
    frame: &Frame,
    max_error_message_len: usize,
) -> Result<(), FrameValidationError> {
    let handshake_error_code = if frame.kind == MessageKind::Error && frame.request_id == 0 {
        handshake_error_payload_code(&frame.payload, max_error_message_len)
    } else {
        None
    };
    validate_wire_semantics(
        frame.kind,
        frame.request_id,
        frame.profile.is_some(),
        frame.capabilities.len(),
        frame.cancellation,
        handshake_error_code,
    )
}

fn validate_wire_semantics(
    kind: MessageKind,
    request_id: RequestId,
    profile_present: bool,
    capability_count: usize,
    cancellation: Cancellation,
    handshake_error_code: Option<RemoteErrorCode>,
) -> Result<(), FrameValidationError> {
    match kind {
        MessageKind::Handshake => {
            if request_id != 0 {
                return Err(FrameValidationError::RequestIdMustBeZero { kind });
            }
            if !profile_present {
                return Err(FrameValidationError::ProfileRequired { kind });
            }
            if cancellation != Cancellation::None {
                return Err(FrameValidationError::InvalidCancellation {
                    kind,
                    actual: cancellation,
                });
            }
        }
        MessageKind::Request => {
            if request_id == 0 {
                return Err(FrameValidationError::RequestIdMustBeNonZero { kind });
            }
            if cancellation == Cancellation::Cancelled {
                return Err(FrameValidationError::InvalidCancellation {
                    kind,
                    actual: cancellation,
                });
            }
        }
        MessageKind::Response => {
            if request_id == 0 {
                return Err(FrameValidationError::RequestIdMustBeNonZero { kind });
            }
            if profile_present {
                return Err(FrameValidationError::ProfileNotAllowed { kind });
            }
            if capability_count != 0 {
                return Err(FrameValidationError::CapabilitiesNotAllowed { kind });
            }
            if cancellation == Cancellation::Requested {
                return Err(FrameValidationError::InvalidCancellation {
                    kind,
                    actual: cancellation,
                });
            }
        }
        MessageKind::Cancel => {
            if request_id == 0 {
                return Err(FrameValidationError::RequestIdMustBeNonZero { kind });
            }
            if profile_present {
                return Err(FrameValidationError::ProfileNotAllowed { kind });
            }
            if capability_count != 0 {
                return Err(FrameValidationError::CapabilitiesNotAllowed { kind });
            }
            if cancellation != Cancellation::Requested {
                return Err(FrameValidationError::InvalidCancellation {
                    kind,
                    actual: cancellation,
                });
            }
        }
        MessageKind::Error => {
            if request_id == 0 {
                match handshake_error_code {
                    Some(code) if code.is_handshake_negotiation() => {}
                    Some(code) => {
                        return Err(FrameValidationError::HandshakeErrorCodeNotAllowed { code });
                    }
                    None => return Err(FrameValidationError::RequestIdMustBeNonZero { kind }),
                }
            }
            if profile_present {
                return Err(FrameValidationError::ProfileNotAllowed { kind });
            }
            if capability_count != 0 {
                return Err(FrameValidationError::CapabilitiesNotAllowed { kind });
            }
            if cancellation != Cancellation::None {
                return Err(FrameValidationError::InvalidCancellation {
                    kind,
                    actual: cancellation,
                });
            }
        }
    }
    Ok(())
}

/// Returns the code from a structured handshake-error payload without
/// allocating its diagnostic text. The framing layer uses the code to keep
/// correlation ID zero reserved for negotiation failures.
fn handshake_error_payload_code(payload: &[u8], maximum: usize) -> Option<RemoteErrorCode> {
    validate_remote_error_payload(payload, maximum).ok()
}

impl Default for FrameCodec {
    fn default() -> Self {
        Self::with_limits(FrameLimits::default())
    }
}

/// Whether bytes after a decoded frame are accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrailingPolicy {
    /// Accept trailing bytes and report the first-frame length.
    Allow,
    /// Reject any bytes after the first complete frame.
    Reject,
}

/// Result of a non-consuming decode attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecodeResult {
    /// A frame was decoded and `consumed` bytes belong to it.
    Complete {
        /// Decoded frame.
        frame: Frame,
        /// Number of input bytes consumed by this frame.
        consumed: usize,
    },
    /// More bytes are needed.  No input was consumed.
    Incomplete {
        /// Minimum additional bytes needed based on the fixed header.
        needed: usize,
    },
}

impl DecodeResult {
    /// Returns the decoded frame, if complete.
    pub fn frame(&self) -> Option<&Frame> {
        match self {
            Self::Complete { frame, .. } => Some(frame),
            Self::Incomplete { .. } => None,
        }
    }

    /// Returns the complete-frame byte count, if complete.
    pub const fn consumed(&self) -> Option<usize> {
        match self {
            Self::Complete { consumed, .. } => Some(*consumed),
            Self::Incomplete { .. } => None,
        }
    }

    /// Returns `true` when the input ended before one complete frame.
    pub const fn is_incomplete(&self) -> bool {
        matches!(self, Self::Incomplete { .. })
    }
}

/// Field location for malformed UTF-8 diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Utf8Field {
    /// Profile identifier.
    Profile,
    /// Capability identifier at the given zero-based index.
    Capability {
        /// Zero-based capability index.
        index: usize,
    },
    /// Structured remote-error message.
    RemoteErrorMessage,
}

impl fmt::Display for Utf8Field {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Profile => formatter.write_str("profile"),
            Self::Capability { index } => write!(formatter, "capability[{index}]"),
            Self::RemoteErrorMessage => formatter.write_str("remote-error message"),
        }
    }
}

/// Stable machine category for framing decode failures.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum DecodeErrorCode {
    /// Magic bytes did not match.
    InvalidMagic = 1,
    /// Protocol version is not supported.
    UnsupportedVersion = 2,
    /// Message kind is not supported.
    UnknownMessageKind = 3,
    /// A reserved flag was set.
    UnknownFlags = 4,
    /// Profile presence flag and length disagree.
    ProfileFlagMismatch = 5,
    /// Payload exceeds configured bounds.
    PayloadTooLarge = 6,
    /// Metadata exceeds configured bounds.
    MetadataTooLarge = 7,
    /// Profile exceeds configured bounds.
    ProfileTooLong = 8,
    /// Capability count exceeds configured bounds.
    TooManyCapabilities = 9,
    /// Capability exceeds configured bounds.
    CapabilityTooLong = 10,
    /// Metadata length does not match its fields.
    MetadataLengthMismatch = 11,
    /// A bounded UTF-8 field is malformed.
    MalformedUtf8 = 12,
    /// Cancellation flags are ambiguous.
    InvalidCancellationFlags = 13,
    /// Length arithmetic overflowed.
    LengthOverflow = 14,
    /// Exact decoding found trailing bytes.
    TrailingBytes = 15,
    /// Exact decoding ended before a frame was complete.
    Incomplete = 16,
    /// A capability field was empty.
    EmptyCapability = 17,
    /// Message fields do not match the selected message kind.
    InvalidFrame = 18,
    /// A configured bound is impossible or exceeds the protocol cap.
    InvalidLimits = 19,
    /// The complete frame exceeds the aggregate frame bound.
    FrameTooLarge = 20,
    /// An error payload exceeds the preflight structured-error bound.
    ErrorPayloadTooLarge = 21,
    /// Aggregate capability bytes exceed their independent bound.
    CapabilityBytesTooLarge = 22,
    /// A capability identifier appears more than once.
    DuplicateCapability = 23,
}

/// A bounded framing decode failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecodeError {
    /// The first four bytes were not [`MAGIC`].
    InvalidMagic {
        /// The four bytes found in the input.
        found: [u8; 4],
    },
    /// The version byte is not [`PROTOCOL_VERSION`].
    UnsupportedVersion(u8),
    /// The message kind byte is unknown.
    UnknownMessageKind(u8),
    /// One or more reserved flag bits were set.
    UnknownFlags(u16),
    /// Cancellation bits are both set.
    InvalidCancellationFlags,
    /// Profile flag and profile length disagree.
    ProfileFlagMismatch {
        /// Whether the profile-presence flag was set.
        flag_present: bool,
        /// Declared profile byte length.
        length: usize,
    },
    /// Payload length exceeds the codec bound.
    PayloadTooLarge {
        /// Declared payload byte length.
        declared: usize,
        /// Configured payload maximum.
        maximum: usize,
    },
    /// Metadata length exceeds the codec bound.
    MetadataTooLarge {
        /// Declared metadata byte length.
        declared: usize,
        /// Configured metadata maximum.
        maximum: usize,
    },
    /// Profile length exceeds the codec bound.
    ProfileTooLong {
        /// Declared profile byte length.
        declared: usize,
        /// Configured profile maximum.
        maximum: usize,
    },
    /// Capability count exceeds the codec bound.
    TooManyCapabilities {
        /// Declared capability count.
        declared: usize,
        /// Configured capability maximum.
        maximum: usize,
    },
    /// Capability length exceeds the codec bound.
    CapabilityTooLong {
        /// Zero-based capability index.
        index: usize,
        /// Declared byte length.
        declared: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// A capability was empty.
    EmptyCapability {
        /// Zero-based capability index.
        index: usize,
    },
    /// Message fields do not match the selected message kind.
    InvalidFrame(FrameValidationError),
    /// The codec limits are impossible and therefore cannot be used safely.
    InvalidLimits(FrameLimitsError),
    /// Complete frame bytes exceed the aggregate frame bound.
    FrameTooLarge {
        /// Declared complete-frame byte length.
        declared: usize,
        /// Maximum complete-frame byte length.
        maximum: usize,
    },
    /// Error payload bytes exceed the fixed prefix plus message bound.
    ErrorPayloadTooLarge {
        /// Declared payload byte length.
        declared: usize,
        /// Maximum error payload byte length.
        maximum: usize,
    },
    /// Aggregate capability bytes exceed their independent bound.
    CapabilityBytesTooLarge {
        /// Declared aggregate bytes.
        declared: usize,
        /// Maximum aggregate bytes.
        maximum: usize,
    },
    /// A capability identifier appears more than once in frame metadata.
    DuplicateCapability {
        /// Zero-based index of the repeated identifier.
        index: usize,
    },
    /// Metadata's declared byte count disagrees with its fields.
    MetadataLengthMismatch {
        /// Declared metadata byte length.
        declared: usize,
        /// Bytes consumed while parsing metadata fields.
        consumed: usize,
    },
    /// A profile, capability, or other bounded field is not UTF-8.
    MalformedUtf8 {
        /// Field containing invalid bytes.
        field: Utf8Field,
    },
    /// Header length arithmetic overflowed.
    LengthOverflow,
    /// Exact decoding found bytes after the first frame.
    TrailingBytes {
        /// Number of bytes after the first complete frame.
        count: usize,
    },
    /// Exact decoding needs more input.
    Incomplete {
        /// Minimum additional bytes needed.
        needed: usize,
    },
}

impl DecodeError {
    /// Returns a stable category suitable for logs and protocol diagnostics.
    pub const fn code(&self) -> DecodeErrorCode {
        match self {
            Self::InvalidMagic { .. } => DecodeErrorCode::InvalidMagic,
            Self::UnsupportedVersion(_) => DecodeErrorCode::UnsupportedVersion,
            Self::UnknownMessageKind(_) => DecodeErrorCode::UnknownMessageKind,
            Self::UnknownFlags(_) => DecodeErrorCode::UnknownFlags,
            Self::InvalidCancellationFlags => DecodeErrorCode::InvalidCancellationFlags,
            Self::ProfileFlagMismatch { .. } => DecodeErrorCode::ProfileFlagMismatch,
            Self::PayloadTooLarge { .. } => DecodeErrorCode::PayloadTooLarge,
            Self::MetadataTooLarge { .. } => DecodeErrorCode::MetadataTooLarge,
            Self::ProfileTooLong { .. } => DecodeErrorCode::ProfileTooLong,
            Self::TooManyCapabilities { .. } => DecodeErrorCode::TooManyCapabilities,
            Self::CapabilityTooLong { .. } => DecodeErrorCode::CapabilityTooLong,
            Self::EmptyCapability { .. } => DecodeErrorCode::EmptyCapability,
            Self::InvalidFrame(_) => DecodeErrorCode::InvalidFrame,
            Self::InvalidLimits(_) => DecodeErrorCode::InvalidLimits,
            Self::FrameTooLarge { .. } => DecodeErrorCode::FrameTooLarge,
            Self::ErrorPayloadTooLarge { .. } => DecodeErrorCode::ErrorPayloadTooLarge,
            Self::CapabilityBytesTooLarge { .. } => DecodeErrorCode::CapabilityBytesTooLarge,
            Self::DuplicateCapability { .. } => DecodeErrorCode::DuplicateCapability,
            Self::MetadataLengthMismatch { .. } => DecodeErrorCode::MetadataLengthMismatch,
            Self::MalformedUtf8 { .. } => DecodeErrorCode::MalformedUtf8,
            Self::LengthOverflow => DecodeErrorCode::LengthOverflow,
            Self::TrailingBytes { .. } => DecodeErrorCode::TrailingBytes,
            Self::Incomplete { .. } => DecodeErrorCode::Incomplete,
        }
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic { found } => write!(formatter, "invalid bridge magic: {found:02x?}"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported bridge protocol version {version}")
            }
            Self::UnknownMessageKind(kind) => {
                write!(formatter, "unknown bridge message kind {kind}")
            }
            Self::UnknownFlags(flags) => write!(formatter, "unknown bridge flags 0x{flags:04x}"),
            Self::InvalidCancellationFlags => formatter.write_str("ambiguous cancellation flags"),
            Self::ProfileFlagMismatch {
                flag_present,
                length,
            } => write!(
                formatter,
                "profile presence flag {flag_present} disagrees with length {length}"
            ),
            Self::PayloadTooLarge { declared, maximum } => write!(
                formatter,
                "payload length {declared} exceeds maximum {maximum}"
            ),
            Self::MetadataTooLarge { declared, maximum } => write!(
                formatter,
                "metadata length {declared} exceeds maximum {maximum}"
            ),
            Self::ProfileTooLong { declared, maximum } => write!(
                formatter,
                "profile length {declared} exceeds maximum {maximum}"
            ),
            Self::TooManyCapabilities { declared, maximum } => write!(
                formatter,
                "capability count {declared} exceeds maximum {maximum}"
            ),
            Self::CapabilityTooLong {
                index,
                declared,
                maximum,
            } => write!(
                formatter,
                "capability[{index}] length {declared} exceeds maximum {maximum}"
            ),
            Self::EmptyCapability { index } => write!(formatter, "capability[{index}] is empty"),
            Self::InvalidFrame(error) => write!(formatter, "invalid bridge frame: {error}"),
            Self::InvalidLimits(error) => write!(formatter, "invalid bridge frame limits: {error}"),
            Self::FrameTooLarge { declared, maximum } => write!(
                formatter,
                "frame length {declared} exceeds maximum {maximum}"
            ),
            Self::ErrorPayloadTooLarge { declared, maximum } => write!(
                formatter,
                "error payload length {declared} exceeds maximum {maximum}"
            ),
            Self::CapabilityBytesTooLarge { declared, maximum } => write!(
                formatter,
                "capability bytes {declared} exceed maximum {maximum}"
            ),
            Self::DuplicateCapability { index } => {
                write!(
                    formatter,
                    "capability[{index}] duplicates an earlier identifier"
                )
            }
            Self::MetadataLengthMismatch { declared, consumed } => write!(
                formatter,
                "metadata length {declared} does not match consumed fields {consumed}"
            ),
            Self::MalformedUtf8 { field } => write!(formatter, "malformed UTF-8 in {field}"),
            Self::LengthOverflow => formatter.write_str("bridge frame length overflow"),
            Self::TrailingBytes { count } => {
                write!(formatter, "{count} trailing bridge frame bytes")
            }
            Self::Incomplete { needed } => write!(
                formatter,
                "bridge frame is incomplete; {needed} more bytes needed"
            ),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Stable machine category for framing encode failures.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum EncodeErrorCode {
    /// Payload exceeds configured bounds.
    PayloadTooLarge = 1,
    /// Metadata exceeds configured bounds.
    MetadataTooLarge = 2,
    /// Profile exceeds configured bounds.
    ProfileTooLong = 3,
    /// Capability count exceeds configured bounds.
    TooManyCapabilities = 4,
    /// Capability exceeds configured bounds.
    CapabilityTooLong = 5,
    /// Profile is empty while marked present.
    EmptyProfile = 6,
    /// Capability is empty.
    EmptyCapability = 7,
    /// Length arithmetic overflowed.
    LengthOverflow = 8,
    /// Structured error message exceeds its bound.
    ErrorMessageTooLong = 9,
    /// Message fields do not match the selected message kind.
    InvalidFrame = 10,
    /// An `Unknown` code collides with a code defined by this version.
    ReservedRemoteErrorCode = 11,
    /// Complete frame bytes exceed the aggregate frame bound.
    FrameTooLarge = 12,
    /// Aggregate capability bytes exceed their independent bound.
    CapabilityBytesTooLarge = 13,
    /// A configured bound is impossible or exceeds the protocol cap.
    InvalidLimits = 14,
    /// Structured handshake declaration could not be encoded.
    Handshake = 15,
    /// A capability identifier appears more than once.
    DuplicateCapability = 16,
}

/// A bounded framing encode failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EncodeError {
    /// Payload length exceeds the codec bound.
    PayloadTooLarge {
        /// Declared payload byte length.
        declared: usize,
        /// Configured payload maximum.
        maximum: usize,
    },
    /// Metadata length exceeds the codec bound.
    MetadataTooLarge {
        /// Declared metadata byte length.
        declared: usize,
        /// Configured metadata maximum.
        maximum: usize,
    },
    /// Profile length exceeds the codec bound.
    ProfileTooLong {
        /// Declared profile byte length.
        declared: usize,
        /// Configured profile maximum.
        maximum: usize,
    },
    /// Capability count exceeds the codec bound.
    TooManyCapabilities {
        /// Declared capability count.
        declared: usize,
        /// Configured capability maximum.
        maximum: usize,
    },
    /// Capability length exceeds the codec bound.
    CapabilityTooLong {
        /// Zero-based capability index.
        index: usize,
        /// Byte length.
        declared: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// Profile identifier was empty.
    EmptyProfile,
    /// Capability identifier was empty.
    EmptyCapability {
        /// Zero-based capability index.
        index: usize,
    },
    /// Message fields do not match the selected message kind.
    InvalidFrame(FrameValidationError),
    /// Length arithmetic overflowed.
    LengthOverflow,
    /// Structured remote-error message exceeds its bound.
    ErrorMessageTooLong {
        /// Declared UTF-8 message byte length.
        declared: usize,
        /// Hard message maximum.
        maximum: usize,
    },
    /// An unknown remote-error code cannot use a value already assigned by
    /// this protocol version.
    ReservedRemoteErrorCode {
        /// Colliding wire value.
        value: u16,
    },
    /// Complete frame bytes exceed the aggregate frame bound.
    FrameTooLarge {
        /// Encoded complete-frame byte length.
        declared: usize,
        /// Maximum complete-frame byte length.
        maximum: usize,
    },
    /// Aggregate capability bytes exceed their independent bound.
    CapabilityBytesTooLarge {
        /// Aggregate capability bytes.
        declared: usize,
        /// Maximum aggregate bytes.
        maximum: usize,
    },
    /// A capability identifier appears more than once in frame metadata.
    DuplicateCapability {
        /// Zero-based index of the repeated identifier.
        index: usize,
    },
    /// Codec limits are impossible and cannot be used safely.
    InvalidLimits(FrameLimitsError),
    /// Structured handshake declaration failed validation or sizing.
    Handshake(HandshakeEncodeError),
}

impl EncodeError {
    /// Returns a stable category suitable for diagnostics.
    pub const fn code(&self) -> EncodeErrorCode {
        match self {
            Self::PayloadTooLarge { .. } => EncodeErrorCode::PayloadTooLarge,
            Self::MetadataTooLarge { .. } => EncodeErrorCode::MetadataTooLarge,
            Self::ProfileTooLong { .. } => EncodeErrorCode::ProfileTooLong,
            Self::TooManyCapabilities { .. } => EncodeErrorCode::TooManyCapabilities,
            Self::CapabilityTooLong { .. } => EncodeErrorCode::CapabilityTooLong,
            Self::EmptyProfile => EncodeErrorCode::EmptyProfile,
            Self::EmptyCapability { .. } => EncodeErrorCode::EmptyCapability,
            Self::InvalidFrame(_) => EncodeErrorCode::InvalidFrame,
            Self::LengthOverflow => EncodeErrorCode::LengthOverflow,
            Self::ErrorMessageTooLong { .. } => EncodeErrorCode::ErrorMessageTooLong,
            Self::ReservedRemoteErrorCode { .. } => EncodeErrorCode::ReservedRemoteErrorCode,
            Self::FrameTooLarge { .. } => EncodeErrorCode::FrameTooLarge,
            Self::CapabilityBytesTooLarge { .. } => EncodeErrorCode::CapabilityBytesTooLarge,
            Self::DuplicateCapability { .. } => EncodeErrorCode::DuplicateCapability,
            Self::InvalidLimits(_) => EncodeErrorCode::InvalidLimits,
            Self::Handshake(_) => EncodeErrorCode::Handshake,
        }
    }
}

impl fmt::Display for EncodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadTooLarge { declared, maximum } => write!(
                formatter,
                "payload length {declared} exceeds maximum {maximum}"
            ),
            Self::MetadataTooLarge { declared, maximum } => write!(
                formatter,
                "metadata length {declared} exceeds maximum {maximum}"
            ),
            Self::ProfileTooLong { declared, maximum } => write!(
                formatter,
                "profile length {declared} exceeds maximum {maximum}"
            ),
            Self::TooManyCapabilities { declared, maximum } => write!(
                formatter,
                "capability count {declared} exceeds maximum {maximum}"
            ),
            Self::CapabilityTooLong {
                index,
                declared,
                maximum,
            } => write!(
                formatter,
                "capability[{index}] length {declared} exceeds maximum {maximum}"
            ),
            Self::EmptyProfile => formatter.write_str("profile identifier is empty"),
            Self::EmptyCapability { index } => write!(formatter, "capability[{index}] is empty"),
            Self::InvalidFrame(error) => write!(formatter, "invalid bridge frame: {error}"),
            Self::LengthOverflow => formatter.write_str("bridge frame length overflow"),
            Self::ErrorMessageTooLong { declared, maximum } => write!(
                formatter,
                "error message length {declared} exceeds maximum {maximum}"
            ),
            Self::ReservedRemoteErrorCode { value } => write!(
                formatter,
                "unknown remote-error code 0x{value:04x} collides with a reserved code"
            ),
            Self::FrameTooLarge { declared, maximum } => write!(
                formatter,
                "frame length {declared} exceeds maximum {maximum}"
            ),
            Self::CapabilityBytesTooLarge { declared, maximum } => write!(
                formatter,
                "capability bytes {declared} exceed maximum {maximum}"
            ),
            Self::DuplicateCapability { index } => {
                write!(
                    formatter,
                    "capability[{index}] duplicates an earlier identifier"
                )
            }
            Self::InvalidLimits(error) => write!(formatter, "invalid bridge frame limits: {error}"),
            Self::Handshake(error) => write!(formatter, "invalid structured handshake: {error}"),
        }
    }
}

impl std::error::Error for EncodeError {}

/// Stable machine-readable errors returned by a worker.
///
/// Numeric values are wire values and must not be renumbered.  Unknown values
/// decode as [`RemoteErrorCode::Unknown`] so a newer worker's diagnostic is
/// retained without being mistaken for a known condition. An
/// [`RemoteErrorCode::Unknown`] value that collides with an assigned code is
/// rejected while encoding; this prevents an `Unknown` value from changing
/// identity after a decode.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RemoteErrorCode {
    /// Framing or protocol violation.
    ProtocolViolation,
    /// Peer does not support the requested version.
    UnsupportedVersion,
    /// Peer does not support the requested message kind.
    UnsupportedMessageKind,
    /// Request payload is invalid.
    InvalidRequest,
    /// Request payload is invalid UTF-8 or otherwise malformed.
    InvalidPayload,
    /// Requested profile is not available.
    ProfileMismatch,
    /// Requested capability is unavailable.
    CapabilityUnavailable,
    /// Worker process or service is unavailable.
    WorkerUnavailable,
    /// Worker terminated unexpectedly.
    WorkerCrashed,
    /// Worker rejected a resource quota.
    WorkerLimitExceeded,
    /// Operation exceeded its deadline.
    DeadlineExceeded,
    /// Operation was cancelled.
    Cancelled,
    /// Worker encountered an internal invariant failure.
    Internal,
    /// A code introduced by a newer protocol implementation.
    Unknown(u16),
}

impl RemoteErrorCode {
    /// Returns the stable wire number.
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::ProtocolViolation => 0x0001,
            Self::UnsupportedVersion => 0x0002,
            Self::UnsupportedMessageKind => 0x0003,
            Self::InvalidRequest => 0x0100,
            Self::InvalidPayload => 0x0101,
            Self::ProfileMismatch => 0x0102,
            Self::CapabilityUnavailable => 0x0200,
            Self::WorkerUnavailable => 0x0201,
            Self::WorkerCrashed => 0x0202,
            Self::WorkerLimitExceeded => 0x0203,
            Self::DeadlineExceeded => 0x0300,
            Self::Cancelled => 0x0301,
            Self::Internal => 0x7fff,
            Self::Unknown(value) => value,
        }
    }

    /// Converts a wire number while preserving unknown values.
    pub const fn from_u16(value: u16) -> Self {
        match value {
            0x0001 => Self::ProtocolViolation,
            0x0002 => Self::UnsupportedVersion,
            0x0003 => Self::UnsupportedMessageKind,
            0x0100 => Self::InvalidRequest,
            0x0101 => Self::InvalidPayload,
            0x0102 => Self::ProfileMismatch,
            0x0200 => Self::CapabilityUnavailable,
            0x0201 => Self::WorkerUnavailable,
            0x0202 => Self::WorkerCrashed,
            0x0203 => Self::WorkerLimitExceeded,
            0x0300 => Self::DeadlineExceeded,
            0x0301 => Self::Cancelled,
            0x7fff => Self::Internal,
            other => Self::Unknown(other),
        }
    }

    /// Returns a stable symbolic name for diagnostics.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProtocolViolation => "protocol_violation",
            Self::UnsupportedVersion => "unsupported_version",
            Self::UnsupportedMessageKind => "unsupported_message_kind",
            Self::InvalidRequest => "invalid_request",
            Self::InvalidPayload => "invalid_payload",
            Self::ProfileMismatch => "profile_mismatch",
            Self::CapabilityUnavailable => "capability_unavailable",
            Self::WorkerUnavailable => "worker_unavailable",
            Self::WorkerCrashed => "worker_crashed",
            Self::WorkerLimitExceeded => "worker_limit_exceeded",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::Cancelled => "cancelled",
            Self::Internal => "internal",
            Self::Unknown(_) => "unknown",
        }
    }

    /// Returns whether this code is reserved for a correlation-ID-zero
    /// handshake negotiation failure.
    pub const fn is_handshake_negotiation(self) -> bool {
        matches!(
            self,
            Self::ProtocolViolation
                | Self::UnsupportedVersion
                | Self::UnsupportedMessageKind
                | Self::ProfileMismatch
                | Self::CapabilityUnavailable
        )
    }
}

/// A structured, bounded error returned by a worker.
#[derive(Clone, Eq, PartialEq)]
pub struct RemoteError {
    /// Stable machine-readable error code.
    pub code: RemoteErrorCode,
    /// Whether retrying the same request may succeed.
    pub retryable: bool,
    /// Human diagnostic text, never used as a compatibility key.
    pub message: String,
}

impl RemoteError {
    /// Creates a worker error value.
    pub fn new(code: RemoteErrorCode, retryable: bool, message: impl Into<String>) -> Self {
        Self {
            code,
            retryable,
            message: message.into(),
        }
    }

    /// Creates an error only when its message can be represented by the
    /// structured-error wire bound.
    pub fn try_new(
        code: RemoteErrorCode,
        retryable: bool,
        message: impl Into<String>,
    ) -> Result<Self, EncodeError> {
        let error = Self::new(code, retryable, message);
        if error.message.len() > MAX_ERROR_MESSAGE_LEN {
            return Err(EncodeError::ErrorMessageTooLong {
                declared: error.message.len(),
                maximum: MAX_ERROR_MESSAGE_LEN,
            });
        }
        Ok(error)
    }

    /// Returns whether the message can be encoded with the default hard bound.
    pub fn message_is_bounded(&self) -> bool {
        self.message.len() <= MAX_ERROR_MESSAGE_LEN
    }

    /// Returns a redacted representation suitable for diagnostics.
    ///
    /// Human text may contain credentials, script source, URLs, or worker
    /// output.  The protocol therefore exposes only the stable code and
    /// retryability through formatting; callers that need the original text
    /// must handle the field explicitly and apply their own policy.
    pub fn redacted_message(&self) -> &'static str {
        "<redacted>"
    }

    /// Serializes the structured error payload using the version-1 hard
    /// message bound.
    pub fn encode_payload(&self) -> Result<Vec<u8>, EncodeError> {
        self.encode_payload_with_limit(MAX_ERROR_MESSAGE_LEN)
    }

    fn encode_payload_with_limit(&self, maximum: usize) -> Result<Vec<u8>, EncodeError> {
        if let RemoteErrorCode::Unknown(value) = self.code
            && RemoteErrorCode::from_u16(value) != RemoteErrorCode::Unknown(value)
        {
            return Err(EncodeError::ReservedRemoteErrorCode { value });
        }
        let length = self.message.len();
        if length > maximum || length > MAX_ERROR_MESSAGE_LEN || length > u16::MAX as usize {
            return Err(EncodeError::ErrorMessageTooLong {
                declared: length,
                maximum: maximum.min(MAX_ERROR_MESSAGE_LEN).min(u16::MAX as usize),
            });
        }
        let mut payload = Vec::with_capacity(ERROR_PAYLOAD_HEADER_LEN + length);
        push_u16(&mut payload, self.code.as_u16());
        payload.push(if self.retryable {
            ERROR_FLAG_RETRYABLE
        } else {
            0
        });
        push_u16(&mut payload, length as u16);
        payload.extend_from_slice(self.message.as_bytes());
        Ok(payload)
    }

    /// Parses a structured error payload without interpreting human text as a
    /// machine code.
    pub fn decode_payload(payload: &[u8]) -> Result<Self, RemoteErrorDecodeError> {
        Self::decode_payload_with_limit(payload, MAX_ERROR_MESSAGE_LEN)
    }

    fn decode_payload_with_limit(
        payload: &[u8],
        maximum: usize,
    ) -> Result<Self, RemoteErrorDecodeError> {
        let code = validate_remote_error_payload(payload, maximum)?;
        let flags = payload[2];
        let message_bytes = &payload[ERROR_PAYLOAD_HEADER_LEN..];
        let message = str::from_utf8(message_bytes)
            .map_err(|_| RemoteErrorDecodeError::MalformedUtf8)?
            .to_owned();
        Ok(Self {
            code,
            retryable: flags & ERROR_FLAG_RETRYABLE != 0,
            message,
        })
    }
}

impl fmt::Debug for RemoteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteError")
            .field("code", &self.code)
            .field("retryable", &self.retryable)
            .field("message", &self.redacted_message())
            .finish()
    }
}

impl fmt::Display for RemoteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "remote error {} (retryable: {}): {}",
            self.code.as_str(),
            self.retryable,
            self.redacted_message()
        )
    }
}

/// Error while decoding a structured remote-error payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RemoteErrorDecodeError {
    /// The frame is not an error frame.
    WrongMessageKind(MessageKind),
    /// Payload is shorter than the fixed error prefix.
    Truncated {
        /// Minimum payload length for the fixed prefix.
        minimum: usize,
        /// Actual payload length.
        actual: usize,
    },
    /// Reserved error flags were set.
    UnknownFlags(u8),
    /// Message length exceeds its hard bound.
    MessageTooLong {
        /// Declared UTF-8 message byte length.
        declared: usize,
        /// Hard message maximum.
        maximum: usize,
    },
    /// Message length does not consume the entire payload.
    LengthMismatch {
        /// Declared UTF-8 message byte length.
        declared: usize,
        /// Actual bytes after the fixed prefix.
        actual: usize,
    },
    /// Message bytes are not UTF-8.
    MalformedUtf8,
}

/// Stable machine category for structured remote-error decode failures.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum RemoteErrorDecodeErrorCode {
    /// The payload was attached to the wrong frame kind.
    WrongMessageKind = 1,
    /// The fixed prefix was truncated.
    Truncated = 2,
    /// Reserved flags were set.
    UnknownFlags = 3,
    /// The declared text exceeds its bound.
    MessageTooLong = 4,
    /// The declared text does not consume the payload.
    LengthMismatch = 5,
    /// The text is not UTF-8.
    MalformedUtf8 = 6,
}

impl RemoteErrorDecodeErrorCode {
    /// Returns the stable numeric diagnostic code.
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    /// Returns the stable symbolic diagnostic code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WrongMessageKind => "wrong_message_kind",
            Self::Truncated => "truncated",
            Self::UnknownFlags => "unknown_flags",
            Self::MessageTooLong => "message_too_long",
            Self::LengthMismatch => "length_mismatch",
            Self::MalformedUtf8 => "malformed_utf8",
        }
    }
}

impl RemoteErrorDecodeError {
    /// Returns a stable machine-readable category.
    pub const fn code(&self) -> RemoteErrorDecodeErrorCode {
        match self {
            Self::WrongMessageKind(_) => RemoteErrorDecodeErrorCode::WrongMessageKind,
            Self::Truncated { .. } => RemoteErrorDecodeErrorCode::Truncated,
            Self::UnknownFlags(_) => RemoteErrorDecodeErrorCode::UnknownFlags,
            Self::MessageTooLong { .. } => RemoteErrorDecodeErrorCode::MessageTooLong,
            Self::LengthMismatch { .. } => RemoteErrorDecodeErrorCode::LengthMismatch,
            Self::MalformedUtf8 => RemoteErrorDecodeErrorCode::MalformedUtf8,
        }
    }
}

impl fmt::Display for RemoteErrorDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongMessageKind(kind) => write!(formatter, "expected error frame, got {kind}"),
            Self::Truncated { minimum, actual } => write!(
                formatter,
                "error payload has {actual} bytes; {minimum} required"
            ),
            Self::UnknownFlags(flags) => {
                write!(formatter, "unknown remote-error flags 0x{flags:02x}")
            }
            Self::MessageTooLong { declared, maximum } => write!(
                formatter,
                "error message length {declared} exceeds maximum {maximum}"
            ),
            Self::LengthMismatch { declared, actual } => write!(
                formatter,
                "error message length {declared} does not match payload bytes {actual}"
            ),
            Self::MalformedUtf8 => formatter.write_str("malformed UTF-8 in remote-error message"),
        }
    }
}

impl std::error::Error for RemoteErrorDecodeError {}

/// Validates a structured error payload without allocating its message.
///
/// Header and length checks call this helper before any owned error text or
/// frame payload is copied. The returned code is sufficient for the
/// correlation-ID-zero handshake invariant.
fn validate_remote_error_payload(
    payload: &[u8],
    maximum: usize,
) -> Result<RemoteErrorCode, RemoteErrorDecodeError> {
    if payload.len() < ERROR_PAYLOAD_HEADER_LEN {
        return Err(RemoteErrorDecodeError::Truncated {
            minimum: ERROR_PAYLOAD_HEADER_LEN,
            actual: payload.len(),
        });
    }
    let code = RemoteErrorCode::from_u16(read_u16(payload, 0));
    let flags = payload[2];
    if flags & !ERROR_FLAG_RETRYABLE != 0 {
        return Err(RemoteErrorDecodeError::UnknownFlags(
            flags & !ERROR_FLAG_RETRYABLE,
        ));
    }
    let message_len = read_u16(payload, 3) as usize;
    if message_len > maximum || message_len > MAX_ERROR_MESSAGE_LEN {
        return Err(RemoteErrorDecodeError::MessageTooLong {
            declared: message_len,
            maximum: maximum.min(MAX_ERROR_MESSAGE_LEN),
        });
    }
    let expected = ERROR_PAYLOAD_HEADER_LEN.checked_add(message_len).ok_or(
        RemoteErrorDecodeError::LengthMismatch {
            declared: message_len,
            actual: payload.len().saturating_sub(ERROR_PAYLOAD_HEADER_LEN),
        },
    )?;
    if payload.len() != expected {
        return Err(RemoteErrorDecodeError::LengthMismatch {
            declared: message_len,
            actual: payload.len() - ERROR_PAYLOAD_HEADER_LEN,
        });
    }
    str::from_utf8(&payload[ERROR_PAYLOAD_HEADER_LEN..])
        .map_err(|_| RemoteErrorDecodeError::MalformedUtf8)?;
    Ok(code)
}

fn push_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn push_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

#[cfg(test)]
// Test assertions intentionally use `expect` so a failed fixture reports the
// operation that was expected to be valid; production code has no such calls.
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn sample_frame() -> Frame {
        Frame::new(MessageKind::Request, 42, b"hello".to_vec())
            .with_deadline(Deadline::at_unix_millis(1_700_000_000_123))
            .with_cancellation(Cancellation::Requested)
            .with_profile("jmeter-5.6.3")
            .with_capabilities(vec!["script:groovy".into(), "sampler:java".into()])
    }

    #[test]
    fn round_trip_preserves_all_fields() {
        let codec = FrameCodec::default();
        let frame = sample_frame();
        let encoded = codec.encode(&frame).expect("sample frame encodes");
        assert_eq!(&encoded[..4], b"JMBP");
        assert_eq!(encoded[4], PROTOCOL_VERSION);
        let decoded = codec.decode_exact(&encoded).expect("sample frame decodes");
        assert_eq!(decoded, frame);
    }

    #[test]
    fn canonical_wire_vector_covers_deadline_boundaries() {
        let codec = FrameCodec::default();
        let frame = Frame::new(MessageKind::Request, 0x0102_0304_0506_0708, vec![0xa5])
            .with_deadline(Deadline::at_unix_millis(u64::MAX));
        let expected = [
            0x4a, 0x4d, 0x42, 0x50, // JMBP
            0x01, 0x02, // version, request kind
            0x00, 0x00, // flags
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // request ID
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // deadline
            0x00, 0x00, // profile length
            0x00, 0x00, // capability count
            0x00, 0x00, 0x00, 0x00, // metadata length
            0x00, 0x00, 0x00, 0x01, // payload length
            0xa5,
        ];
        assert_eq!(codec.encode(&frame).expect("wire vector encodes"), expected);
        assert_eq!(
            codec.decode_exact(&expected).expect("wire vector decodes"),
            frame
        );

        assert_eq!(Deadline::at_unix_millis(0), Deadline::NONE);
        let deadline = Deadline::at_unix_millis(u64::MAX);
        assert!(!deadline.is_expired_at(u64::MAX - 1));
        assert!(deadline.is_expired_at(u64::MAX));
    }

    #[test]
    fn handshake_round_trip_with_empty_payload() {
        let codec = FrameCodec::default();
        let frame = Frame::handshake(
            0,
            "jmeter-5.6.3",
            vec!["script:groovy".into(), "plugin:v1".into()],
        );
        let bytes = codec.encode(&frame).expect("handshake encodes");
        assert_eq!(
            codec.decode_exact(&bytes).expect("handshake decodes"),
            frame
        );
    }

    #[test]
    fn opaque_payload_round_trips_for_every_kind_and_allowed_cancellation() {
        let codec = FrameCodec::default();
        let payload = vec![0x00, 0xff, 0x10, 0x00, 0xfe, b'J', b'M', b'B', b'P'];
        let frames = [
            Frame {
                kind: MessageKind::Handshake,
                request_id: 0,
                deadline: Deadline::NONE,
                cancellation: Cancellation::None,
                profile: Some("jmeter-5.6.3".to_owned()),
                capabilities: vec!["opaque:payload".to_owned()],
                payload: payload.clone(),
            },
            Frame::new(MessageKind::Request, 1, payload.clone()),
            Frame::new(MessageKind::Request, 2, payload.clone())
                .with_cancellation(Cancellation::Requested),
            Frame::new(MessageKind::Response, 1, payload.clone()),
            Frame::new(MessageKind::Response, 2, payload.clone())
                .with_cancellation(Cancellation::Cancelled),
            Frame::new(MessageKind::Cancel, 2, payload.clone())
                .with_cancellation(Cancellation::Requested),
            Frame::new(MessageKind::Error, 3, payload.clone()),
        ];

        assert_eq!(
            frames.iter().map(|frame| frame.kind).collect::<Vec<_>>(),
            vec![
                MessageKind::Handshake,
                MessageKind::Request,
                MessageKind::Request,
                MessageKind::Response,
                MessageKind::Response,
                MessageKind::Cancel,
                MessageKind::Error,
            ]
        );
        assert_eq!(
            frames
                .iter()
                .map(|frame| frame.cancellation)
                .collect::<Vec<_>>(),
            vec![
                Cancellation::None,
                Cancellation::None,
                Cancellation::Requested,
                Cancellation::None,
                Cancellation::Cancelled,
                Cancellation::Requested,
                Cancellation::None,
            ]
        );

        for frame in frames {
            let encoded = codec.encode(&frame).expect("opaque frame encodes");
            assert_eq!(
                codec.decode_exact(&encoded).expect("opaque frame decodes"),
                frame
            );
        }
    }

    #[test]
    fn frame_debug_redacts_opaque_payload_until_explicit_access() {
        let frame = Frame::new(MessageKind::Request, 42, b"secret payload".to_vec());
        let debug = format!("{frame:?}");

        assert!(debug.contains("payload_len: 14"));
        assert!(debug.contains("payload: \"<redacted>\""));
        assert!(!debug.contains("secret payload"));
        assert_eq!(frame.payload_bytes(), b"secret payload");
    }

    #[test]
    fn structured_remote_error_round_trip_and_unknown_code() {
        let codec = FrameCodec::default();
        let error = RemoteError::new(RemoteErrorCode::Unknown(0x4321), true, "engine unavailable");
        let frame = codec
            .error_frame(99, error.clone())
            .expect("error frame builds");
        let bytes = codec.encode(&frame).expect("error frame encodes");
        let decoded = codec.decode_exact(&bytes).expect("error frame decodes");
        assert_eq!(
            decoded.remote_error().expect("error payload decodes"),
            error
        );
        assert_eq!(
            codec
                .decode_remote_error(&decoded)
                .expect("codec error decode"),
            error
        );
    }

    #[test]
    fn custom_error_message_limit_is_checked_before_error_payload_encoding() {
        let limits = FrameLimits {
            max_error_message_len: 3,
            ..FrameLimits::default()
        };
        let codec = FrameCodec::with_limits(limits);
        let error = RemoteError::new(RemoteErrorCode::Internal, false, "four");
        assert_eq!(
            codec.error_frame(1, error),
            Err(EncodeError::ErrorMessageTooLong {
                declared: 4,
                maximum: 3
            })
        );
    }

    #[test]
    fn every_partial_prefix_is_non_consuming() {
        let codec = FrameCodec::default();
        let encoded = codec.encode(&sample_frame()).expect("encodes");
        for length in 0..encoded.len() {
            let mut input = &encoded[..length];
            assert_eq!(codec.decode_next(&mut input).expect("partial decode"), None);
            assert_eq!(input.len(), length, "prefix {length} was consumed");
        }
        let mut input = encoded.as_slice();
        assert!(
            codec
                .decode_next(&mut input)
                .expect("complete decode")
                .is_some()
        );
        assert!(input.is_empty());
    }

    #[test]
    fn concatenated_frames_report_consumed_prefix() {
        let codec = FrameCodec::default();
        let first = codec
            .encode(&Frame::new(MessageKind::Request, 1, vec![1]))
            .expect("first encodes");
        let second = codec
            .encode(&Frame::new(MessageKind::Response, 1, vec![2, 3]))
            .expect("second encodes");
        let concatenated = [first.as_slice(), second.as_slice()].concat();
        let mut input = concatenated.as_slice();
        let decoded_first = codec
            .decode_next(&mut input)
            .expect("first decodes")
            .expect("first exists");
        let decoded_second = codec
            .decode_next(&mut input)
            .expect("second decodes")
            .expect("second exists");
        assert_eq!(decoded_first.payload, vec![1]);
        assert_eq!(decoded_second.payload, vec![2, 3]);
        assert!(input.is_empty());
    }

    #[test]
    fn concatenated_frames_decode_from_deterministic_fragments() {
        let codec = FrameCodec::default();
        let frames = [
            Frame::handshake(0, "jmeter-5.6.3", vec!["fragmented".to_owned()]),
            Frame::new(MessageKind::Request, 11, vec![0, 1, 2, 0xff])
                .with_cancellation(Cancellation::Requested),
            Frame::new(MessageKind::Response, 11, vec![3, 4, 5, 0xfe])
                .with_cancellation(Cancellation::Cancelled),
            Frame::new(MessageKind::Cancel, 11, vec![6, 7, 8])
                .with_cancellation(Cancellation::Requested),
            Frame::new(MessageKind::Error, 11, vec![9, 10, 11, 0xfd]),
        ];
        let encoded = frames
            .iter()
            .map(|frame| codec.encode(frame).expect("fragmented frame encodes"))
            .collect::<Vec<_>>();
        let wire = encoded.concat();
        let chunk_sizes = [1, 2, 5, 13, 3, 29, 7, 17, 4, 31];
        let mut input = Vec::new();
        let mut decoded = Vec::new();
        let mut offset = 0;
        let mut chunk_index = 0;

        while offset < wire.len() {
            let chunk_len = chunk_sizes[chunk_index % chunk_sizes.len()];
            let end = (offset + chunk_len).min(wire.len());
            input.extend_from_slice(&wire[offset..end]);
            offset = end;
            chunk_index += 1;

            loop {
                let mut available = input.as_slice();
                let Some(frame) = codec
                    .decode_next(&mut available)
                    .expect("fragmented input decodes")
                else {
                    break;
                };
                let consumed = input.len() - available.len();
                input.drain(..consumed);
                decoded.push(frame);
            }
        }

        while !input.is_empty() {
            let mut available = input.as_slice();
            let Some(frame) = codec
                .decode_next(&mut available)
                .expect("final fragmented input decodes")
            else {
                break;
            };
            let consumed = input.len() - available.len();
            input.drain(..consumed);
            decoded.push(frame);
        }

        assert!(input.is_empty());
        assert_eq!(decoded, frames);
    }

    #[test]
    fn trailing_policy_is_explicit() {
        let codec = FrameCodec::default();
        let mut bytes = codec
            .encode(&Frame::new(MessageKind::Request, 1, Vec::new()))
            .expect("encodes");
        bytes.extend_from_slice(b"tail");
        assert!(matches!(
            codec.decode(&bytes).expect("allowing decode"),
            DecodeResult::Complete { consumed, .. } if consumed + 4 == bytes.len()
        ));
        assert_eq!(
            codec.decode_exact(&bytes),
            Err(DecodeError::TrailingBytes { count: 4 })
        );
        assert!(matches!(
            codec
                .decode_with_policy(&bytes, TrailingPolicy::Allow)
                .expect("allow policy"),
            DecodeResult::Complete { .. }
        ));
        assert_eq!(
            codec.decode_with_policy(&bytes, TrailingPolicy::Reject),
            Err(DecodeError::TrailingBytes { count: 4 })
        );
    }

    #[test]
    fn message_kind_semantics_are_enforced_on_encode() {
        let codec = FrameCodec::default();
        let cases = [
            (
                Frame::new(MessageKind::Handshake, 1, Vec::new()),
                FrameValidationError::RequestIdMustBeZero {
                    kind: MessageKind::Handshake,
                },
            ),
            (
                Frame::new(MessageKind::Handshake, 0, Vec::new()),
                FrameValidationError::ProfileRequired {
                    kind: MessageKind::Handshake,
                },
            ),
            (
                Frame::handshake(0, "jmeter-5.6.3", Vec::new())
                    .with_cancellation(Cancellation::Requested),
                FrameValidationError::InvalidCancellation {
                    kind: MessageKind::Handshake,
                    actual: Cancellation::Requested,
                },
            ),
            (
                Frame::new(MessageKind::Request, 0, Vec::new()),
                FrameValidationError::RequestIdMustBeNonZero {
                    kind: MessageKind::Request,
                },
            ),
            (
                Frame::new(MessageKind::Cancel, 1, Vec::new()),
                FrameValidationError::InvalidCancellation {
                    kind: MessageKind::Cancel,
                    actual: Cancellation::None,
                },
            ),
            (
                Frame::new(MessageKind::Cancel, 1, Vec::new())
                    .with_cancellation(Cancellation::Requested)
                    .with_profile("jmeter-5.6.3"),
                FrameValidationError::ProfileNotAllowed {
                    kind: MessageKind::Cancel,
                },
            ),
            (
                Frame::new(MessageKind::Response, 1, Vec::new())
                    .with_cancellation(Cancellation::Requested),
                FrameValidationError::InvalidCancellation {
                    kind: MessageKind::Response,
                    actual: Cancellation::Requested,
                },
            ),
            (
                Frame::new(MessageKind::Error, 0, Vec::new()),
                FrameValidationError::RequestIdMustBeNonZero {
                    kind: MessageKind::Error,
                },
            ),
        ];

        for (frame, expected) in cases {
            assert_eq!(
                codec.encode(&frame),
                Err(EncodeError::InvalidFrame(expected)),
                "unexpected result for {frame:?}"
            );
        }

        let cancel_with_payload =
            Frame::new(MessageKind::Cancel, 1, vec![1]).with_cancellation(Cancellation::Requested);
        assert_eq!(
            codec.decode_exact(&codec.encode(&cancel_with_payload).expect("cancel encodes")),
            Ok(cancel_with_payload)
        );
    }

    #[test]
    fn message_kind_semantics_are_enforced_on_decode() {
        let codec = FrameCodec::default();
        let encoded = codec
            .encode(&Frame::new(MessageKind::Request, 1, Vec::new()))
            .expect("valid request encodes");

        let mut handshake_with_operation_id = encoded.clone();
        handshake_with_operation_id[5] = MessageKind::Handshake as u8;
        assert_eq!(
            codec.decode(&handshake_with_operation_id),
            Err(DecodeError::InvalidFrame(
                FrameValidationError::RequestIdMustBeZero {
                    kind: MessageKind::Handshake,
                },
            ))
        );

        let mut request_with_zero_id = encoded.clone();
        request_with_zero_id[8..16].fill(0);
        assert_eq!(
            codec.decode(&request_with_zero_id),
            Err(DecodeError::InvalidFrame(
                FrameValidationError::RequestIdMustBeNonZero {
                    kind: MessageKind::Request,
                },
            ))
        );

        let cancel = codec
            .encode(
                &Frame::new(MessageKind::Cancel, 1, Vec::new())
                    .with_cancellation(Cancellation::Requested),
            )
            .expect("valid cancellation encodes");
        let mut cancellation_without_request = cancel;
        cancellation_without_request[7] &= !(FLAG_CANCEL_REQUESTED as u8);
        assert_eq!(
            codec.decode(&cancellation_without_request),
            Err(DecodeError::InvalidFrame(
                FrameValidationError::InvalidCancellation {
                    kind: MessageKind::Cancel,
                    actual: Cancellation::None,
                },
            ))
        );
    }

    #[test]
    fn invalid_fixed_headers_are_rejected() {
        let codec = FrameCodec::default();
        let encoded = codec
            .encode(&Frame::new(MessageKind::Request, 1, vec![9]))
            .expect("encodes");

        let mut invalid_magic = encoded.clone();
        invalid_magic[0] ^= 1;
        assert!(matches!(
            codec.decode(&invalid_magic),
            Err(DecodeError::InvalidMagic { .. })
        ));

        let mut invalid_version = encoded.clone();
        invalid_version[4] = PROTOCOL_VERSION + 1;
        assert_eq!(
            codec.decode(&invalid_version),
            Err(DecodeError::UnsupportedVersion(PROTOCOL_VERSION + 1))
        );

        let mut invalid_kind = encoded.clone();
        invalid_kind[5] = 0xff;
        assert_eq!(
            codec.decode(&invalid_kind),
            Err(DecodeError::UnknownMessageKind(0xff))
        );

        let mut invalid_flags = encoded.clone();
        invalid_flags[6] = 0x80;
        assert_eq!(
            codec.decode(&invalid_flags),
            Err(DecodeError::UnknownFlags(0x8000))
        );

        let mut ambiguous_cancel = encoded.clone();
        ambiguous_cancel[7] |= 0x03;
        assert_eq!(
            codec.decode(&ambiguous_cancel),
            Err(DecodeError::InvalidCancellationFlags)
        );
    }

    #[test]
    fn invalid_lengths_and_utf8_are_rejected_before_allocation() {
        let codec = FrameCodec::new(3);
        let encoded = codec
            .encode(&Frame::new(MessageKind::Request, 1, vec![1, 2, 3]))
            .expect("boundary payload encodes");

        let mut oversize_payload = encoded.clone();
        oversize_payload[35] = 4;
        assert_eq!(
            codec.decode(&oversize_payload),
            Err(DecodeError::PayloadTooLarge {
                declared: 4,
                maximum: 3
            })
        );

        let mut oversize_metadata = encoded.clone();
        oversize_metadata[29] = 1;
        oversize_metadata[31] = 1;
        assert!(matches!(
            codec.decode(&oversize_metadata),
            Err(DecodeError::MetadataTooLarge { .. })
        ));

        let mut profile_flag = codec
            .encode(&Frame::new(MessageKind::Request, 1, Vec::new()))
            .expect("encodes");
        profile_flag[7] |= (FLAG_PROFILE_PRESENT & 0xff) as u8;
        assert!(matches!(
            codec.decode(&profile_flag),
            Err(DecodeError::ProfileFlagMismatch { .. })
        ));

        let mut malformed_profile = codec
            .encode(&Frame::new(MessageKind::Request, 1, Vec::new()).with_profile("p"))
            .expect("profile encodes");
        malformed_profile[HEADER_LEN] = 0xff;
        assert_eq!(
            codec.decode(&malformed_profile),
            Err(DecodeError::MalformedUtf8 {
                field: Utf8Field::Profile
            })
        );

        let mut malformed_capability = codec
            .encode(
                &Frame::new(MessageKind::Request, 1, Vec::new())
                    .with_capabilities(vec!["cap".into()]),
            )
            .expect("capability encodes");
        malformed_capability[HEADER_LEN + 2] = 0xff;
        assert_eq!(
            codec.decode(&malformed_capability),
            Err(DecodeError::MalformedUtf8 {
                field: Utf8Field::Capability { index: 0 }
            })
        );

        let mut truncated_metadata = codec
            .encode(
                &Frame::new(MessageKind::Request, 1, Vec::new())
                    .with_capabilities(vec!["cap".into()]),
            )
            .expect("capability encodes");
        truncated_metadata[31] = 1;
        assert!(matches!(
            codec.decode(&truncated_metadata),
            Err(DecodeError::MetadataLengthMismatch { .. })
        ));

        let mut bad_metadata_length = codec
            .encode(&Frame::new(MessageKind::Request, 1, Vec::new()).with_profile("p"))
            .expect("profile encodes");
        bad_metadata_length[31] = bad_metadata_length[31].wrapping_add(1);
        assert!(matches!(
            codec.decode(&bad_metadata_length),
            Ok(DecodeResult::Incomplete { .. })
        ));
    }

    #[test]
    fn exact_max_payload_is_accepted_and_one_over_is_rejected() {
        let codec = FrameCodec::new(8);
        let accepted = Frame::new(MessageKind::Request, 1, vec![0; 8]);
        let bytes = codec.encode(&accepted).expect("maximum payload encodes");
        assert_eq!(
            codec.decode_exact(&bytes).expect("maximum decodes"),
            accepted
        );
        let rejected = Frame::new(MessageKind::Request, 1, vec![0; 9]);
        assert!(matches!(
            codec.encode(&rejected),
            Err(EncodeError::PayloadTooLarge {
                declared: 9,
                maximum: 8
            })
        ));
    }

    #[test]
    fn profile_and_capability_limits_are_exact() {
        let limits = FrameLimits {
            max_profile_len: 2,
            max_capabilities: 1,
            max_capability_len: 2,
            ..FrameLimits::default()
        };
        let codec = FrameCodec::with_limits(limits);
        let accepted = Frame::new(MessageKind::Handshake, 0, Vec::new())
            .with_profile("ab")
            .with_capabilities(vec!["cd".into()]);
        let bytes = codec.encode(&accepted).expect("metadata maximums encode");
        assert_eq!(
            codec
                .decode_exact(&bytes)
                .expect("metadata maximums decode"),
            accepted
        );

        assert!(matches!(
            codec.encode(&accepted.clone().with_profile("abc")),
            Err(EncodeError::ProfileTooLong {
                declared: 3,
                maximum: 2
            })
        ));
        assert!(matches!(
            codec.encode(&accepted.clone().with_capabilities(vec!["cde".into()])),
            Err(EncodeError::CapabilityTooLong {
                index: 0,
                declared: 3,
                maximum: 2
            })
        ));
        assert!(matches!(
            codec.encode(&accepted.with_capabilities(vec!["c".into(), "d".into()])),
            Err(EncodeError::TooManyCapabilities {
                declared: 2,
                maximum: 1
            })
        ));
    }

    #[test]
    fn remote_error_payload_rejects_malformed_fields() {
        assert_eq!(
            RemoteError::decode_payload(&[]),
            Err(RemoteErrorDecodeError::Truncated {
                minimum: ERROR_PAYLOAD_HEADER_LEN,
                actual: 0
            })
        );
        let mut unknown_flags = vec![0, 1, 2, 0, 0];
        assert_eq!(
            RemoteError::decode_payload(&unknown_flags),
            Err(RemoteErrorDecodeError::UnknownFlags(2))
        );
        unknown_flags[2] = 0;
        unknown_flags[4] = 1;
        assert_eq!(
            RemoteError::decode_payload(&unknown_flags),
            Err(RemoteErrorDecodeError::LengthMismatch {
                declared: 1,
                actual: 0
            })
        );
        let mut invalid_utf8 = vec![0, 1, 0, 0, 1, 0xff];
        assert_eq!(
            RemoteError::decode_payload(&invalid_utf8),
            Err(RemoteErrorDecodeError::MalformedUtf8)
        );
        invalid_utf8[2] = 0x80;
        assert_eq!(
            RemoteError::decode_payload(&invalid_utf8),
            Err(RemoteErrorDecodeError::UnknownFlags(0x80))
        );
    }

    #[test]
    fn malformed_and_short_inputs_are_bounded_and_non_consuming() {
        let codec = FrameCodec::new(32);
        for length in 0..HEADER_LEN {
            let bytes = vec![0; length];
            assert_eq!(
                codec.decode(&bytes),
                Ok(DecodeResult::Incomplete {
                    needed: HEADER_LEN - length
                })
            );
            let mut input = bytes.as_slice();
            assert_eq!(codec.decode_next(&mut input).expect("short decode"), None);
            assert_eq!(input.len(), length);
        }

        let valid = codec
            .encode(&Frame::new(MessageKind::Request, 7, b"bytes".to_vec()))
            .expect("valid request encodes");
        let mut declared_payload_is_truncated = valid[..HEADER_LEN].to_vec();
        declared_payload_is_truncated[32..36].copy_from_slice(&6_u32.to_be_bytes());
        assert_eq!(
            codec.decode(&declared_payload_is_truncated),
            Ok(DecodeResult::Incomplete { needed: 6 })
        );

        let mut oversized = valid[..HEADER_LEN].to_vec();
        oversized[32..36].copy_from_slice(&33_u32.to_be_bytes());
        assert_eq!(
            codec.decode(&oversized),
            Err(DecodeError::PayloadTooLarge {
                declared: 33,
                maximum: 32,
            })
        );

        let mut malformed_magic = valid;
        malformed_magic[..4].copy_from_slice(b"NOPE");
        let mut input = malformed_magic.as_slice();
        assert!(matches!(
            codec.decode_next(&mut input),
            Err(DecodeError::InvalidMagic { .. })
        ));
        assert_eq!(input.len(), malformed_magic.len());
    }

    #[test]
    fn unknown_remote_error_code_cannot_collide_with_known_wire_values() {
        let error = RemoteError::new(RemoteErrorCode::Unknown(0x0100), false, "collision");
        assert_eq!(
            error.encode_payload(),
            Err(EncodeError::ReservedRemoteErrorCode { value: 0x0100 })
        );
        assert_eq!(
            Frame::error(7, error),
            Err(EncodeError::ReservedRemoteErrorCode { value: 0x0100 })
        );
        assert_eq!(
            RemoteErrorCode::from_u16(0x0100),
            RemoteErrorCode::InvalidRequest
        );
    }

    #[test]
    fn structured_handshake_round_trip_constrains_to_implemented_wire_version() {
        let versions = ProtocolVersionRange::new(1, 3).expect("valid range");
        let host = Handshake::worker("host", "1.2.3", "jmeter-5.6.3")
            .with_capabilities(["SCRIPT-001", "PLUG-001"])
            .with_supported_message_kinds([
                MessageKind::Handshake,
                MessageKind::Request,
                MessageKind::Response,
                MessageKind::Error,
            ]);
        let plugin = Handshake::plugin("groovy", "4.0.0", "jmeter-5.6.3")
            .with_capabilities(["SCRIPT-001"])
            .with_supported_message_kinds([
                MessageKind::Handshake,
                MessageKind::Request,
                MessageKind::Response,
                MessageKind::Error,
            ]);
        let host = Handshake { versions, ..host };
        let plugin = Handshake {
            versions: ProtocolVersionRange::new(1, 4).expect("valid range"),
            ..plugin
        };

        let frame = host.to_frame().expect("handshake frame");
        let codec = FrameCodec::default();
        let encoded = codec.encode(&frame).expect("handshake wire encoding");
        let decoded = codec
            .decode_exact(&encoded)
            .expect("handshake wire decoding");
        let decoded = Handshake::from_frame(&decoded).expect("structured handshake decoding");
        assert_eq!(decoded.identity, host.identity);
        assert_eq!(decoded.profile, host.profile);
        assert_eq!(decoded.capabilities, host.capabilities);
        assert_eq!(decoded.versions, host.versions);

        let negotiated = host.negotiate(&plugin).expect("common handshake");
        assert_eq!(versions.select(plugin.versions), Some(3));
        assert_eq!(negotiated.protocol_version, PROTOCOL_VERSION as u16);
        assert_eq!(negotiated.capabilities, vec!["SCRIPT-001"]);
        assert_eq!(
            negotiated.supported_message_kinds,
            vec![
                MessageKind::Handshake,
                MessageKind::Request,
                MessageKind::Response,
                MessageKind::Error,
            ]
        );
        assert_eq!(negotiated.preservation, PreservationContract::full());
    }

    #[test]
    fn handshake_mismatches_are_explicit_and_stable() {
        let mut left = Handshake::worker("host", "1", "profile");
        let mut right = Handshake::plugin("plugin", "1", "profile");
        left.versions = ProtocolVersionRange::new(1, 1).expect("range");
        right.versions = ProtocolVersionRange::new(2, 2).expect("range");
        assert!(matches!(
            left.negotiate(&right),
            Err(HandshakeError::NoCommonVersion { .. })
        ));

        left.versions = ProtocolVersionRange::new(1, 3).expect("range");
        right.versions = ProtocolVersionRange::new(2, 4).expect("range");
        assert!(matches!(
            left.negotiate(&right),
            Err(HandshakeError::NoCommonVersion { .. })
        ));

        right.versions = ProtocolVersionRange::new(1, 2).expect("range");
        left.selected_version = Some(1);
        right.selected_version = Some(2);
        assert!(matches!(
            left.negotiate(&right),
            Err(HandshakeError::SelectedVersionMismatch { .. })
        ));

        right.selected_version = None;
        right.profile = "other-profile".to_owned();
        assert!(matches!(
            left.negotiate(&right),
            Err(HandshakeError::ProfileMismatch { .. })
        ));

        right.profile = left.profile.clone();
        right.supported_message_kinds = vec![MessageKind::Handshake];
        left.supported_message_kinds = vec![MessageKind::Request];
        assert_eq!(
            left.negotiate(&right),
            Err(HandshakeError::NoCommonMessageKinds)
        );

        left.supported_message_kinds = vec![MessageKind::Handshake];
        right.supported_message_kinds = vec![MessageKind::Handshake];
        left.capabilities = vec!["SCRIPT-001".to_owned()];
        right.capabilities = vec!["PLUG-001".to_owned()];
        assert!(matches!(
            left.negotiate(&right),
            Err(HandshakeError::CapabilityMismatch { .. })
        ));
    }

    #[test]
    fn unknown_handshake_payload_fields_fail_closed_without_allocation() {
        let handshake = Handshake::worker("worker", "1", "profile");
        let full = PreservationContract::full();
        assert!(!full.unknown_messages);
        assert!(!full.unknown_fields);
        assert!(full.opaque_payloads);
        assert!(full.unknown_capabilities);

        let encoded = handshake
            .encode_payload()
            .expect("handshake payload encoding");
        let preservation_flags = HANDSHAKE_FLAG_PRESERVE_UNKNOWN_MESSAGES
            | HANDSHAKE_FLAG_PRESERVE_UNKNOWN_FIELDS
            | HANDSHAKE_FLAG_PRESERVE_OPAQUE_PAYLOADS
            | HANDSHAKE_FLAG_PRESERVE_UNKNOWN_CAPABILITIES;
        assert_eq!(
            encoded[5] & preservation_flags,
            HANDSHAKE_FLAG_PRESERVE_OPAQUE_PAYLOADS | HANDSHAKE_FLAG_PRESERVE_UNKNOWN_CAPABILITIES
        );
        assert_eq!(
            Handshake::decode_payload(&encoded)
                .expect("handshake decoding")
                .preservation,
            full
        );

        let mut payload = handshake
            .encode_payload()
            .expect("handshake payload encoding");
        payload[5] |= 0x80;
        assert_eq!(
            Handshake::decode_payload(&payload),
            Err(HandshakeDecodeError::UnknownFlags(0x80))
        );

        let mut payload = handshake.encode_payload().expect("payload encoding");
        let name_len = handshake.identity.name.len();
        let version_len = handshake.identity.version.len();
        let first_kind = HANDSHAKE_FIXED_PAYLOAD_LEN + name_len + version_len;
        payload[first_kind] = 0xff;
        assert_eq!(
            Handshake::decode_payload(&payload),
            Err(HandshakeDecodeError::UnknownMessageKind {
                index: 0,
                wire: 0xff,
            })
        );

        let mut payload = handshake.encode_payload().expect("payload encoding");
        payload[17..19].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(matches!(
            Handshake::decode_payload(&payload),
            Err(HandshakeDecodeError::TooManyMessageKinds(_))
        ));
    }

    #[test]
    fn handshake_payload_decode_rejects_empty_identity_and_kind_set() {
        let handshake = Handshake::worker("worker", "1", "profile");
        let encoded = handshake.encode_payload().expect("payload encoding");

        let mut empty_name = encoded.clone();
        empty_name[13..15].copy_from_slice(&0_u16.to_be_bytes());
        assert_eq!(
            Handshake::decode_payload(&empty_name),
            Err(HandshakeDecodeError::InvalidDeclaration(
                HandshakeEncodeError::EmptyField("identity name"),
            ))
        );

        let mut empty_version = encoded.clone();
        empty_version[15..17].copy_from_slice(&0_u16.to_be_bytes());
        assert_eq!(
            Handshake::decode_payload(&empty_version),
            Err(HandshakeDecodeError::InvalidDeclaration(
                HandshakeEncodeError::EmptyField("identity version"),
            ))
        );

        let mut no_kinds = encoded;
        no_kinds[17..19].copy_from_slice(&0_u16.to_be_bytes());
        assert_eq!(
            Handshake::decode_payload(&no_kinds),
            Err(HandshakeDecodeError::InvalidDeclaration(
                HandshakeEncodeError::NoMessageKinds,
            ))
        );
    }

    #[test]
    fn duplicate_capabilities_are_rejected_with_stable_errors() {
        let duplicate =
            Handshake::worker("worker", "1", "profile").with_capabilities(["PLUG-001", "PLUG-001"]);
        let expected_handshake_error = HandshakeEncodeError::DuplicateCapability { index: 1 };
        assert_eq!(duplicate.validate(), Err(expected_handshake_error.clone()));
        assert_eq!(
            expected_handshake_error.code(),
            HandshakeEncodeErrorCode::DuplicateCapability
        );
        assert_eq!(expected_handshake_error.code().as_u16(), 15);
        assert_eq!(
            expected_handshake_error.code().as_str(),
            "duplicate_capability"
        );
        assert_eq!(
            duplicate.encode_payload(),
            Err(expected_handshake_error.clone())
        );
        assert_eq!(
            duplicate.to_frame(),
            Err(EncodeError::Handshake(expected_handshake_error.clone()))
        );

        let valid_peer = Handshake::plugin("plugin", "1", "profile");
        assert_eq!(
            duplicate.negotiate(&valid_peer),
            Err(HandshakeError::InvalidLocal(
                expected_handshake_error.clone()
            ))
        );
        assert_eq!(
            valid_peer.negotiate(&duplicate),
            Err(HandshakeError::InvalidPeer(expected_handshake_error))
        );

        let codec = FrameCodec::default();
        let duplicate_frame = Frame {
            payload: Handshake::worker("worker", "1", "profile")
                .encode_payload()
                .expect("structured handshake payload"),
            ..Frame::handshake(
                0,
                "profile",
                vec!["PLUG-001".to_owned(), "PLUG-001".to_owned()],
            )
        };
        let encode_error = codec
            .encode(&duplicate_frame)
            .expect_err("duplicate frame must not encode");
        assert_eq!(encode_error, EncodeError::DuplicateCapability { index: 1 });
        assert_eq!(encode_error.code(), EncodeErrorCode::DuplicateCapability);
        assert_eq!(encode_error.code() as u16, 16);
        assert_eq!(
            Handshake::from_frame(&duplicate_frame),
            Err(HandshakeDecodeError::DuplicateCapability { index: 1 })
        );
        assert_eq!(
            codec.decode_handshake(&duplicate_frame),
            Err(HandshakeDecodeError::DuplicateCapability { index: 1 })
        );

        let unique_frame = Frame::handshake(
            0,
            "profile",
            vec!["PLUG-001".to_owned(), "PLUG-002".to_owned()],
        );
        let mut encoded = codec
            .encode(&unique_frame)
            .expect("unique capability frame encodes");
        let second_capability_start = HEADER_LEN + "profile".len() + 2 + "PLUG-001".len() + 2;
        encoded[second_capability_start..second_capability_start + "PLUG-002".len()]
            .copy_from_slice(b"PLUG-001");
        let decode_error = codec
            .decode_exact(&encoded)
            .expect_err("duplicate capability wire data must not decode");
        assert_eq!(decode_error, DecodeError::DuplicateCapability { index: 1 });
        assert_eq!(decode_error.code(), DecodeErrorCode::DuplicateCapability);
        assert_eq!(decode_error.code() as u16, 23);
    }

    #[test]
    fn decoded_handshake_payload_successes_preserve_structural_invariants() {
        let handshake = Handshake::plugin("plugin", "1", "profile").with_capabilities(["PLUG-001"]);
        let payload = handshake.encode_payload().expect("payload encoding");
        let decoded = Handshake::decode_payload(&payload).expect("payload decoding");

        // This is the invariant exercised by the bridge fuzz target: a
        // successful payload decode must never manufacture an unusable
        // identity or a declaration with no message kinds.
        assert!(!decoded.identity.name.is_empty());
        assert!(!decoded.identity.version.is_empty());
        assert!(!decoded.supported_message_kinds.is_empty());
        assert!(decoded.identity.validate().is_ok());
        assert!(decoded.preservation.validate().is_ok());
        assert!(decoded.limits.validate().is_ok());
    }

    #[test]
    fn direct_handshake_frame_decode_rejects_cancellation_state() {
        let handshake = Handshake::worker("worker", "1", "profile");
        let frame = handshake
            .to_frame()
            .expect("structured handshake frame")
            .with_cancellation(Cancellation::Requested);
        assert_eq!(
            Handshake::from_frame(&frame),
            Err(HandshakeDecodeError::InvalidCancellation(
                Cancellation::Requested,
            ))
        );
        assert_eq!(
            FrameCodec::default().decode_handshake(&frame),
            Err(HandshakeDecodeError::InvalidCancellation(
                Cancellation::Requested,
            ))
        );

        let mut payload = Handshake::worker("worker", "1", "profile")
            .encode_payload()
            .expect("payload encoding");
        payload[5] |= HANDSHAKE_FLAG_PRESERVE_UNKNOWN_MESSAGES;
        let invalid_flags = Frame::handshake(0, "profile", Vec::new());
        let invalid_flags = Frame {
            payload,
            ..invalid_flags
        };
        assert_eq!(
            Handshake::from_frame(&invalid_flags),
            Err(HandshakeDecodeError::UnsupportedPreservation(
                PreservationContractError::UnknownMessagesUnsupported,
            ))
        );
    }

    #[test]
    fn decode_handshake_applies_codec_instance_limits_to_direct_frames() {
        let handshake =
            Handshake::worker("worker", "1", "profile").with_capabilities(["capability"]);
        let frame = handshake.to_frame().expect("structured handshake frame");

        let payload_limited = FrameCodec::new(frame.payload.len() - 1);
        assert!(matches!(
            payload_limited.decode_handshake(&frame),
            Err(HandshakeDecodeError::CodecViolation(
                EncodeError::PayloadTooLarge { .. }
            ))
        ));

        let profile_limited = FrameCodec::with_limits(FrameLimits {
            max_profile_len: frame.profile.as_ref().expect("profile").len() - 1,
            ..FrameLimits::default()
        });
        assert!(matches!(
            profile_limited.decode_handshake(&frame),
            Err(HandshakeDecodeError::CodecViolation(
                EncodeError::ProfileTooLong { .. }
            ))
        ));

        let capability_limited = FrameCodec::with_limits(FrameLimits {
            max_capability_len: frame.capabilities[0].len() - 1,
            ..FrameLimits::default()
        });
        assert!(matches!(
            capability_limited.decode_handshake(&frame),
            Err(HandshakeDecodeError::CodecViolation(
                EncodeError::CapabilityTooLong { .. }
            ))
        ));

        let count_limited = FrameCodec::with_limits(FrameLimits {
            max_capabilities: 0,
            max_capability_bytes: 0,
            ..FrameLimits::default()
        });
        assert!(matches!(
            count_limited.decode_handshake(&frame),
            Err(HandshakeDecodeError::CodecViolation(
                EncodeError::TooManyCapabilities { .. }
            ))
        ));

        let capability_bytes_limited = FrameCodec::with_limits(FrameLimits {
            max_capability_bytes: frame.capabilities[0].len() + 1,
            ..FrameLimits::default()
        });
        assert!(matches!(
            capability_bytes_limited.decode_handshake(&frame),
            Err(HandshakeDecodeError::CodecViolation(
                EncodeError::CapabilityBytesTooLarge { .. }
            ))
        ));

        let metadata_frame = Handshake::worker("worker", "1", "profile")
            .to_frame()
            .expect("structured handshake frame without capabilities");
        let metadata_limited = FrameCodec::with_limits(FrameLimits {
            max_metadata_len: metadata_frame.profile.as_ref().expect("profile").len() - 1,
            max_capability_bytes: 0,
            ..FrameLimits::default()
        });
        let metadata_result = metadata_limited.decode_handshake(&metadata_frame);
        assert!(
            matches!(
                &metadata_result,
                Err(HandshakeDecodeError::CodecViolation(
                    EncodeError::MetadataTooLarge { .. }
                ))
            ),
            "unexpected metadata-limit result: {metadata_result:?}"
        );
    }

    #[test]
    fn unsupported_preservation_cannot_be_encoded_or_negotiated() {
        let unsupported = PreservationContract {
            unknown_messages: true,
            unknown_fields: false,
            opaque_payloads: true,
            unknown_capabilities: true,
        };
        assert_eq!(
            unsupported.validate(),
            Err(PreservationContractError::UnknownMessagesUnsupported)
        );
        let handshake = Handshake::worker("worker", "1", "profile").with_preservation(unsupported);
        assert_eq!(
            handshake.encode_payload(),
            Err(HandshakeEncodeError::UnsupportedPreservation(
                PreservationContractError::UnknownMessagesUnsupported,
            ))
        );
        assert!(matches!(
            handshake.negotiate(&Handshake::worker("peer", "1", "profile")),
            Err(HandshakeError::InvalidLocal(
                HandshakeEncodeError::UnsupportedPreservation(
                    PreservationContractError::UnknownMessagesUnsupported
                )
            ))
        ));
        assert_eq!(
            unsupported.intersect(unsupported),
            PreservationContract {
                unknown_messages: false,
                unknown_fields: false,
                opaque_payloads: true,
                unknown_capabilities: true,
            }
        );

        let mut payload = Handshake::worker("worker", "1", "profile")
            .encode_payload()
            .expect("payload encoding");
        payload[5] |= HANDSHAKE_FLAG_PRESERVE_UNKNOWN_FIELDS;
        assert_eq!(
            Handshake::decode_payload(&payload),
            Err(HandshakeDecodeError::UnsupportedPreservation(
                PreservationContractError::UnknownFieldsUnsupported,
            ))
        );
    }

    #[test]
    fn impossible_limits_are_rejected_and_hard_frame_bound_is_independent() {
        let impossible = FrameLimits {
            max_payload_len: 200,
            max_frame_bytes: HEADER_LEN + 100,
            ..FrameLimits::default()
        };
        assert!(matches!(
            FrameCodec::try_with_limits(impossible),
            Err(FrameLimitsError::MessageExceedsFrame { .. })
        ));

        let aggregate = FrameLimits {
            max_payload_len: 60,
            max_metadata_len: 50,
            max_frame_bytes: HEADER_LEN + 100,
            ..FrameLimits::default()
        };
        assert!(matches!(
            FrameCodec::try_with_limits(aggregate),
            Err(FrameLimitsError::AggregateExceedsFrame { .. })
        ));

        let handshake_aggregate = HandshakeLimits {
            max_message_bytes: 60,
            max_metadata_bytes: 50,
            max_frame_bytes: HEADER_LEN + 100,
            ..HandshakeLimits::default()
        };
        assert!(matches!(
            handshake_aggregate.validate(),
            Err(HandshakeLimitsError::AggregateExceedsFrame { .. })
        ));

        assert_eq!(validate_message_limit(MAX_MESSAGE_BYTES), Ok(()));
        assert!(matches!(
            validate_message_limit(MAX_MESSAGE_BYTES + 1),
            Err(FrameLimitsError::MessageExceedsFrame { .. })
        ));
        assert_eq!(validate_capability_limits(2, 8, 20, 20), Ok(()));
        assert!(matches!(
            validate_capability_limits(MAX_CAPABILITIES + 1, 8, 20, 20),
            Err(FrameLimitsError::CapabilityCount { .. })
        ));
        assert_eq!(
            validate_capability_limits(
                MAX_CAPABILITIES,
                MAX_CAPABILITY_LEN,
                MAX_METADATA_LEN,
                MAX_METADATA_LEN,
            ),
            Ok(())
        );
        assert!(matches!(
            validate_capability_limits(
                MAX_CAPABILITIES,
                MAX_CAPABILITY_LEN,
                MAX_METADATA_LEN + 1,
                MAX_METADATA_LEN + 1,
            ),
            Err(FrameLimitsError::CapabilityBytes {
                maximum: MAX_METADATA_LEN,
                ..
            })
        ));
        assert!(matches!(
            validate_capability_limits(0, 0, 0, MAX_METADATA_LEN + 1),
            Err(FrameLimitsError::CapabilityBytes { declared, maximum })
                if declared == MAX_METADATA_LEN + 1 && maximum == MAX_METADATA_LEN
        ));

        let beyond_hard_cap = FrameLimits {
            max_frame_bytes: MAX_FRAME_BYTES + 1,
            ..FrameLimits::default()
        };
        assert!(matches!(
            FrameCodec::try_with_limits(beyond_hard_cap),
            Err(FrameLimitsError::FrameBytes { .. })
        ));

        let limits = FrameLimits {
            max_frame_bytes: HEADER_LEN + 8,
            max_payload_len: 4,
            max_metadata_len: 4,
            max_capability_bytes: 0,
            ..FrameLimits::default()
        };
        let codec = FrameCodec::try_with_limits(limits).expect("small valid limits");
        let frame = Frame::new(MessageKind::Request, 1, vec![0; 4]).with_profile("abcd");
        assert_eq!(
            codec
                .encode(&frame)
                .expect("aggregate boundary encodes")
                .len(),
            HEADER_LEN + 8
        );
    }

    #[test]
    fn handshake_errors_use_zero_only_for_explicit_negotiation_codes() {
        let codec = FrameCodec::default();
        let handshake_error = Frame::handshake_error(RemoteError::new(
            RemoteErrorCode::UnsupportedVersion,
            false,
            "peer versions do not overlap; secret=do-not-print",
        ))
        .expect("handshake error frame");
        let bytes = codec
            .encode(&handshake_error)
            .expect("zero-ID error encodes");
        let decoded = codec.decode_exact(&bytes).expect("zero-ID error decodes");
        assert_eq!(decoded.request_id, 0);
        assert_eq!(
            codec.decode_remote_error(&decoded).expect("error payload"),
            RemoteError::new(
                RemoteErrorCode::UnsupportedVersion,
                false,
                "peer versions do not overlap; secret=do-not-print"
            )
        );

        let malformed = Frame::new(MessageKind::Error, 0, Vec::new());
        assert!(matches!(
            codec.encode(&malformed),
            Err(EncodeError::InvalidFrame(
                FrameValidationError::RequestIdMustBeNonZero {
                    kind: MessageKind::Error
                }
            ))
        ));

        assert_eq!(
            Frame::handshake_error(RemoteError::new(
                RemoteErrorCode::WorkerCrashed,
                false,
                "worker crashed during handshake",
            )),
            Err(EncodeError::InvalidFrame(
                FrameValidationError::HandshakeErrorCodeNotAllowed {
                    code: RemoteErrorCode::WorkerCrashed,
                }
            ))
        );

        let raw_non_negotiation = Frame::new(
            MessageKind::Error,
            0,
            RemoteError::new(RemoteErrorCode::WorkerCrashed, false, "worker crashed")
                .encode_payload()
                .expect("structured error payload"),
        );
        assert_eq!(
            codec.encode(&raw_non_negotiation),
            Err(EncodeError::InvalidFrame(
                FrameValidationError::HandshakeErrorCodeNotAllowed {
                    code: RemoteErrorCode::WorkerCrashed,
                }
            ))
        );
        let mut encoded_non_negotiation = codec
            .encode(
                &Frame::error(
                    7,
                    RemoteError::new(RemoteErrorCode::WorkerCrashed, false, "worker crashed"),
                )
                .expect("operational error frame"),
            )
            .expect("operational error encoding");
        encoded_non_negotiation[8..16].fill(0);
        assert_eq!(
            codec.decode(&encoded_non_negotiation),
            Err(DecodeError::InvalidFrame(
                FrameValidationError::HandshakeErrorCodeNotAllowed {
                    code: RemoteErrorCode::WorkerCrashed,
                }
            ))
        );

        let operation = Frame::error(
            0,
            RemoteError::new(RemoteErrorCode::WorkerCrashed, false, "worker crashed"),
        )
        .expect_err("operational code cannot use zero ID");
        assert_eq!(
            operation,
            EncodeError::InvalidFrame(FrameValidationError::HandshakeErrorCodeNotAllowed {
                code: RemoteErrorCode::WorkerCrashed,
            })
        );
        let operation = Frame::error(
            7,
            RemoteError::new(RemoteErrorCode::WorkerCrashed, false, "worker crashed"),
        )
        .expect("operational error frame");
        assert_eq!(
            codec
                .decode_exact(&codec.encode(&operation).expect("operation encoding"))
                .expect("operation decoding")
                .request_id,
            7
        );
    }

    #[test]
    fn error_payload_is_preflighted_before_waiting_for_body() {
        let codec = FrameCodec::default();
        let mut header = vec![0; HEADER_LEN];
        header[..4].copy_from_slice(&MAGIC);
        header[4] = PROTOCOL_VERSION;
        header[5] = MessageKind::Error as u8;
        header[32..36].copy_from_slice(&(MAX_ERROR_PAYLOAD_LEN as u32 + 1).to_be_bytes());
        // The payload is intentionally absent. Header inspection alone must
        // reject it rather than returning Incomplete or allocating.
        assert!(matches!(
            codec.decode(&header),
            Err(DecodeError::ErrorPayloadTooLarge { .. })
        ));
    }

    #[test]
    fn remote_error_debug_display_and_decode_code_redact_message() {
        let error = RemoteError::new(
            RemoteErrorCode::Internal,
            true,
            "password=secret-value and script source",
        );
        let debug = format!("{error:?}");
        let display = format!("{error}");
        assert!(!debug.contains("secret-value"));
        assert!(!display.contains("secret-value"));
        assert_eq!(
            RemoteError::decode_payload(&[0, 1, 0, 0]),
            Err(RemoteErrorDecodeError::Truncated {
                minimum: ERROR_PAYLOAD_HEADER_LEN,
                actual: 4
            })
        );
        assert_eq!(
            RemoteErrorDecodeError::MalformedUtf8.code(),
            RemoteErrorDecodeErrorCode::MalformedUtf8
        );
        assert!(
            RemoteError::try_new(
                RemoteErrorCode::Internal,
                false,
                "x".repeat(MAX_ERROR_MESSAGE_LEN + 1)
            )
            .is_err()
        );
    }
}
