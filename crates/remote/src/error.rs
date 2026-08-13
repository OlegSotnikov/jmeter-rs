// SPDX-License-Identifier: Apache-2.0
//! Stable errors for the Rust-native remote boundary.

use core::fmt;

/// The largest diagnostic context that a failure frame will carry after
/// sanitization.  The wire field limit may be larger for other protocol
/// fields, but failure context has its own deliberately small ceiling.
pub const MAX_WIRE_FAILURE_MESSAGE_BYTES: usize = 512;

const REDACTED_FAILURE_CONTEXT: &str = "<redacted>";
const MAX_FAILURE_SCAN_BYTES: usize = 64 * 1024;

/// Produces a bounded failure context suitable for a remote wire message.
///
/// Error values retain their original text for an explicit local diagnostic
/// consumer, but a peer must never receive credentials, paths, bearer-like
/// tokens, or control characters from that text.  Suspicious contexts are
/// replaced in full rather than trying to redact individual substrings; this
/// prevents a truncated or malformed path/token from leaking a suffix.
pub(crate) fn sanitize_wire_failure_message(message: &str, maximum: usize) -> String {
    let maximum = maximum.min(MAX_WIRE_FAILURE_MESSAGE_BYTES);
    if maximum == 0 {
        return String::new();
    }

    let scan_len = message.len().min(MAX_FAILURE_SCAN_BYTES);
    let scan = String::from_utf8_lossy(&message.as_bytes()[..scan_len]);
    if failure_context_is_sensitive(&scan) {
        return truncate_utf8(REDACTED_FAILURE_CONTEXT, maximum);
    }

    // Keep ordinary diagnostic context useful while making it safe for
    // line-oriented adapters and logs.  Do not allocate in proportion to an
    // attacker-controlled message: only the bounded prefix is retained.
    let mut sanitized = String::with_capacity(scan.len().min(maximum));
    for character in scan.chars() {
        if sanitized.len() >= maximum {
            break;
        }
        let character = if character.is_control() {
            ' '
        } else {
            character
        };
        let encoded = character.len_utf8();
        if sanitized.len().saturating_add(encoded) > maximum {
            break;
        }
        sanitized.push(character);
    }
    sanitized
}

fn failure_context_is_sensitive(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();

    // These markers cover both key/value forms (`token=...`) and prose such
    // as an exception that embeds a credential or authorization header.
    const SENSITIVE_MARKERS: &[&str] = &[
        "password",
        "passwd",
        "secret",
        "token",
        "authorization",
        "bearer",
        "cookie",
        "credential",
        "api_key",
        "apikey",
        "access_key",
        "private_key",
        "session",
    ];
    if SENSITIVE_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
    {
        return true;
    }

    // Absolute Unix/UNC paths, URL-like values, and Windows drive paths are
    // local deployment details and may contain secrets in path components.
    if lower.contains('/') || lower.contains('\\') || lower.contains("://") {
        return true;
    }
    let bytes = lower.as_bytes();
    bytes
        .windows(2)
        .any(|window| window[0].is_ascii_alphabetic() && window[1] == b':')
}

fn truncate_utf8(value: &str, maximum: usize) -> String {
    if value.len() <= maximum {
        return value.to_owned();
    }
    let end = value
        .char_indices()
        .take_while(|(index, character)| index.saturating_add(character.len_utf8()) <= maximum)
        .map(|(index, character)| index + character.len_utf8())
        .last()
        .unwrap_or(0);
    value[..end].to_owned()
}

/// Machine-readable operation categories used by the remote protocol.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RemoteErrorCode {
    /// The message was malformed or violated a protocol invariant.
    Protocol,
    /// The message or one of its fields exceeded a configured bound.
    ResourceLimit,
    /// A requested compatibility profile was not available.
    ProfileMismatch,
    /// A worker cannot satisfy a local data/dependency reference.
    CapabilityUnavailable,
    /// A message was sent in the wrong lifecycle state.
    InvalidState,
    /// A worker or coordinator failed an operation.
    WorkerFailure,
    /// A sample was received twice with different contents.
    ConflictingDuplicate,
    /// A result event failed domain validation.
    InvalidSample,
    /// A sample sender queue cannot accept more data yet.
    Backpressure,
    /// A cancellation or stop request was applied.
    Cancelled,
    /// A request reached its deadline before it was applied.
    DeadlineExceeded,
    /// A transport adapter attempted to cross the remote boundary without an
    /// explicit request context. Wire messages do not carry this
    /// policy, so adapters must supply it out of band.
    ContextUnavailable,
    /// An internal invariant was violated.
    Internal,
    /// A code introduced by a newer remote protocol implementation.
    Unknown(u16),
}

impl RemoteErrorCode {
    /// Returns the stable diagnostic code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Protocol => "remote.protocol",
            Self::ResourceLimit => "remote.resource-limit",
            Self::ProfileMismatch => "remote.profile-mismatch",
            Self::CapabilityUnavailable => "remote.capability-unavailable",
            Self::InvalidState => "remote.invalid-state",
            Self::WorkerFailure => "remote.worker-failure",
            Self::ConflictingDuplicate => "remote.conflicting-duplicate",
            Self::InvalidSample => "remote.invalid-sample",
            Self::Backpressure => "remote.backpressure",
            Self::Cancelled => "remote.cancelled",
            Self::DeadlineExceeded => "remote.deadline-exceeded",
            Self::ContextUnavailable => "remote.context-unavailable",
            Self::Internal => "remote.internal",
            Self::Unknown(_) => "remote.unknown",
        }
    }
}

impl fmt::Display for RemoteErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A bounded, structured failure exchanged by a coordinator and worker.
#[derive(Clone, Eq, PartialEq)]
pub struct RemoteError {
    /// Stable machine-readable category.
    pub code: RemoteErrorCode,
    /// Whether retrying the operation may succeed.
    pub retryable: bool,
    /// Human-readable diagnostic text. It is never used as a compatibility
    /// key and is exposed only through [`Self::message`]; formatting an error
    /// never includes its contents.
    message: String,
}

impl RemoteError {
    /// Creates a structured failure.
    pub fn new(code: RemoteErrorCode, retryable: bool, message: impl Into<String>) -> Self {
        Self {
            code,
            retryable,
            message: message.into(),
        }
    }

    /// Creates a non-retryable state error.
    pub fn state(message: impl Into<String>) -> Self {
        Self::new(RemoteErrorCode::InvalidState, false, message)
    }

    /// Returns the stable string code.
    pub const fn stable_code(&self) -> &'static str {
        self.code.as_str()
    }

    /// Returns the raw diagnostic text for an explicit, local diagnostic
    /// consumer.  Callers must not place this value on a wire, in telemetry,
    /// or in a persisted artifact. `Debug` and `Display` intentionally expose
    /// only its length.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns the raw diagnostic text under an explicit local-only name.
    /// This is an alias for [`Self::message`] for adapters that distinguish
    /// local diagnostics from wire-safe context in their API.
    pub fn raw_message(&self) -> &str {
        self.message()
    }

    /// Returns bounded, sanitized context suitable for a wire failure.
    /// Stable error identity remains in [`Self::code`] and `retryable`; this
    /// context is never used as a compatibility key.
    pub fn wire_message(&self, maximum: usize) -> String {
        sanitize_wire_failure_message(&self.message, maximum)
    }

    /// Alias for [`Self::wire_message`] for explicit redaction call sites.
    pub fn sanitized_message(&self, maximum: usize) -> String {
        self.wire_message(maximum)
    }

    /// Returns a bounded, redacted copy suitable for retaining at a remote
    /// state-machine boundary.  The original error remains available to its
    /// local owner; state machines must not retain untrusted peer context.
    pub fn sanitized_copy(&self, maximum: usize) -> Self {
        Self::new(self.code, self.retryable, self.wire_message(maximum))
    }

    /// Returns the diagnostic byte length without exposing its contents.
    pub const fn message_len(&self) -> usize {
        self.message.len()
    }
}

impl fmt::Display for RemoteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} (retryable={}, message_len={})",
            self.code,
            self.retryable,
            self.message.len()
        )
    }
}

impl fmt::Debug for RemoteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteError")
            .field("code", &self.code)
            .field("retryable", &self.retryable)
            .field("message_len", &self.message.len())
            .finish()
    }
}

impl std::error::Error for RemoteError {}

/// Failures raised by the bounded message codec.
#[derive(Clone, Eq, PartialEq)]
pub enum ProtocolError {
    /// The input ended before the fixed header or a declared field completed.
    Incomplete {
        /// Number of bytes still needed.
        needed: usize,
    },
    /// The protocol marker was not present.
    InvalidMagic {
        /// Four bytes found at the input start.
        found: [u8; 4],
    },
    /// The message version is not supported.
    UnsupportedVersion(u16),
    /// The message kind is not recognized.
    UnknownMessageKind(u8),
    /// A reserved header byte was non-zero.
    UnknownFlags(u8),
    /// The declared payload is too large.
    MessageTooLarge {
        /// Declared message length.
        declared: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// A field exceeds the configured bound.
    FieldTooLarge {
        /// Logical field name.
        field: &'static str,
        /// Declared field length.
        declared: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// The codec was constructed with a zero or unrepresentable bound.
    InvalidLimits,
    /// Length arithmetic overflowed or the header disagreed with the input.
    LengthMismatch {
        /// Length declared by the message.
        declared: usize,
        /// Length observed in the input.
        actual: usize,
    },
    /// A bounded UTF-8 field was malformed.
    InvalidUtf8 {
        /// Logical field name.
        field: &'static str,
    },
    /// A bounded enum or boolean had an unknown wire value.
    InvalidValue {
        /// Logical field name.
        field: &'static str,
        /// Wire value that was rejected.
        value: u64,
    },
    /// A map contained the same key more than once.
    DuplicateProperty(String),
    /// A sample result violated the result model's invariants.
    InvalidSample(String),
    /// A caller supplied a result feature which this wire version cannot
    /// represent without loss.
    UnsupportedCapability(&'static str),
    /// A trailing byte sequence was supplied to exact decoding.
    TrailingBytes {
        /// Number of bytes after the complete message.
        count: usize,
    },
}

impl fmt::Debug for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Incomplete { needed } => formatter
                .debug_struct("ProtocolError::Incomplete")
                .field("needed", needed)
                .finish(),
            Self::InvalidMagic { found } => formatter
                .debug_struct("ProtocolError::InvalidMagic")
                .field("found", found)
                .finish(),
            Self::UnsupportedVersion(version) => formatter
                .debug_tuple("ProtocolError::UnsupportedVersion")
                .field(version)
                .finish(),
            Self::UnknownMessageKind(kind) => formatter
                .debug_tuple("ProtocolError::UnknownMessageKind")
                .field(kind)
                .finish(),
            Self::UnknownFlags(flags) => formatter
                .debug_tuple("ProtocolError::UnknownFlags")
                .field(flags)
                .finish(),
            Self::MessageTooLarge { declared, maximum } => formatter
                .debug_struct("ProtocolError::MessageTooLarge")
                .field("declared", declared)
                .field("maximum", maximum)
                .finish(),
            Self::FieldTooLarge {
                field,
                declared,
                maximum,
            } => formatter
                .debug_struct("ProtocolError::FieldTooLarge")
                .field("field", field)
                .field("declared", declared)
                .field("maximum", maximum)
                .finish(),
            Self::InvalidLimits => formatter.write_str("ProtocolError::InvalidLimits"),
            Self::LengthMismatch { declared, actual } => formatter
                .debug_struct("ProtocolError::LengthMismatch")
                .field("declared", declared)
                .field("actual", actual)
                .finish(),
            Self::InvalidUtf8 { field } => formatter
                .debug_struct("ProtocolError::InvalidUtf8")
                .field("field", field)
                .finish(),
            Self::InvalidValue { field, value } => formatter
                .debug_struct("ProtocolError::InvalidValue")
                .field("field", field)
                .field("value", value)
                .finish(),
            Self::DuplicateProperty(name) => formatter
                .debug_struct("ProtocolError::DuplicateProperty")
                .field("name_len", &name.len())
                .finish(),
            Self::InvalidSample(message) => formatter
                .debug_struct("ProtocolError::InvalidSample")
                .field("message_len", &message.len())
                .finish(),
            Self::UnsupportedCapability(capability) => formatter
                .debug_tuple("ProtocolError::UnsupportedCapability")
                .field(capability)
                .finish(),
            Self::TrailingBytes { count } => formatter
                .debug_struct("ProtocolError::TrailingBytes")
                .field("count", count)
                .finish(),
        }
    }
}

impl ProtocolError {
    /// Returns the stable category for this codec failure.
    pub const fn code(&self) -> RemoteErrorCode {
        match self {
            Self::Incomplete { .. }
            | Self::InvalidMagic { .. }
            | Self::UnsupportedVersion(_)
            | Self::UnknownMessageKind(_)
            | Self::UnknownFlags(_)
            | Self::LengthMismatch { .. }
            | Self::InvalidUtf8 { .. }
            | Self::InvalidValue { .. }
            | Self::DuplicateProperty(_)
            | Self::TrailingBytes { .. } => RemoteErrorCode::Protocol,
            Self::UnsupportedCapability(_) => RemoteErrorCode::CapabilityUnavailable,
            Self::InvalidSample(_) => RemoteErrorCode::InvalidSample,
            Self::MessageTooLarge { .. } | Self::FieldTooLarge { .. } | Self::InvalidLimits => {
                RemoteErrorCode::ResourceLimit
            }
        }
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Incomplete { needed } => {
                write!(formatter, "incomplete message; need {needed} bytes")
            }
            Self::InvalidMagic { found } => {
                write!(formatter, "invalid remote message magic {found:?}")
            }
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported remote protocol version {version}")
            }
            Self::UnknownMessageKind(kind) => {
                write!(formatter, "unknown remote message kind {kind}")
            }
            Self::UnknownFlags(flags) => {
                write!(formatter, "unknown remote message flags {flags:#x}")
            }
            Self::MessageTooLarge { declared, maximum } => {
                write!(
                    formatter,
                    "remote message length {declared} exceeds {maximum}"
                )
            }
            Self::FieldTooLarge {
                field,
                declared,
                maximum,
            } => {
                write!(
                    formatter,
                    "remote {field} length {declared} exceeds {maximum}"
                )
            }
            Self::InvalidLimits => write!(formatter, "remote codec limits are invalid"),
            Self::LengthMismatch { declared, actual } => {
                write!(
                    formatter,
                    "remote length declares {declared} bytes, input has {actual}"
                )
            }
            Self::InvalidUtf8 { field } => write!(formatter, "remote {field} is not UTF-8"),
            Self::InvalidValue { field, value } => {
                write!(formatter, "remote {field} has invalid value {value}")
            }
            Self::DuplicateProperty(_) => write!(formatter, "remote property is duplicated"),
            Self::InvalidSample(message) => {
                write!(
                    formatter,
                    "invalid remote sample (message_len={})",
                    message.len()
                )
            }
            Self::UnsupportedCapability(capability) => {
                write!(formatter, "remote capability {capability} is unavailable")
            }
            Self::TrailingBytes { count } => {
                write!(formatter, "remote message has {count} trailing bytes")
            }
        }
    }
}

impl std::error::Error for ProtocolError {}
