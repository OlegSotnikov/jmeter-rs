// SPDX-License-Identifier: Apache-2.0
//! Stable errors for the Rust-native remote boundary.

use core::fmt;

/// The largest diagnostic context that a failure frame will carry after
/// sanitization.  The wire field limit may be larger for other protocol
/// fields, but failure context has its own deliberately small ceiling.
pub const MAX_WIRE_FAILURE_MESSAGE_BYTES: usize = 512;

/// The largest diagnostic message retained by a remote wire failure.
///
/// Local errors may retain their original text for an explicit diagnostic
/// consumer.  Any copy crossing the remote boundary must use the redacted
/// wire projection and this bound.
pub const MAX_REMOTE_ERROR_MESSAGE_BYTES: usize = MAX_WIRE_FAILURE_MESSAGE_BYTES;

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
    // Control bytes are not valid diagnostic context.  Replacing one byte in
    // place could leave a malicious prefix/suffix pair meaningful to a
    // line-oriented consumer, so redact the whole context instead.
    if message.chars().any(char::is_control) {
        return true;
    }

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
    // A Windows drive path has a separator after the drive colon.  Matching
    // every `letter:` sequence would redact ordinary prose such as
    // `operation: failed` and make diagnostics needlessly opaque.
    let bytes = lower.as_bytes();
    bytes.windows(3).any(|window| {
        window[0].is_ascii_alphabetic() && window[1] == b':' && matches!(window[2], b'/' | b'\\')
    })
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

/// Retry/terminal classification for one remote operation.
///
/// The classification belongs to the error occurrence, not just its code:
/// for example, a resource limit can be retryable when a bounded queue may
/// drain, but terminal when the configured limit itself is invalid.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RemoteRetryability {
    /// A bounded retry may make progress without changing the request.
    Retryable,
    /// Retrying the same operation cannot make progress safely.
    Terminal,
}

impl RemoteRetryability {
    /// Returns whether this classification permits a retry.
    pub const fn is_retryable(self) -> bool {
        matches!(self, Self::Retryable)
    }

    /// Returns the stable diagnostic spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Retryable => "retryable",
            Self::Terminal => "terminal",
        }
    }
}

impl fmt::Display for RemoteRetryability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
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
    /// Every error code defined by this protocol revision.
    ///
    /// [`RemoteErrorCode::Unknown`] is intentionally excluded: it represents
    /// a value introduced by a newer peer and therefore cannot be part of the
    /// closed vocabulary of this revision.
    pub const ALL: &[Self] = &[
        Self::Protocol,
        Self::ResourceLimit,
        Self::ProfileMismatch,
        Self::CapabilityUnavailable,
        Self::InvalidState,
        Self::WorkerFailure,
        Self::ConflictingDuplicate,
        Self::InvalidSample,
        Self::Backpressure,
        Self::Cancelled,
        Self::DeadlineExceeded,
        Self::ContextUnavailable,
        Self::Internal,
    ];

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

    /// Parses a stable code without accepting localized display text.
    ///
    /// Unknown numeric values have no stable string representation beyond
    /// `remote.unknown`, so callers must keep their numeric wire value when
    /// forwarding one of them.
    pub fn from_stable_code(value: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|code| code.as_str() == value)
    }

    /// Returns whether this code denotes a resource/capacity boundary.
    pub const fn is_limit(self) -> bool {
        matches!(self, Self::ResourceLimit | Self::Backpressure)
    }
}

impl fmt::Display for RemoteErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A structured failure exchanged by a coordinator and worker.
///
/// Its local diagnostic text may remain available to the owner, but every
/// wire/state-machine projection must use [`Self::wire_message`] or
/// [`Self::sanitized_copy`].
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

    /// Creates a retryable failure with an explicit occurrence-level
    /// classification.
    pub fn retryable_error(code: RemoteErrorCode, message: impl Into<String>) -> Self {
        Self::new(code, true, message)
    }

    /// Creates a terminal failure with an explicit occurrence-level
    /// classification.
    pub fn terminal(code: RemoteErrorCode, message: impl Into<String>) -> Self {
        Self::new(code, false, message)
    }

    /// Returns the stable string code.
    pub const fn stable_code(&self) -> &'static str {
        self.code.as_str()
    }

    /// Returns the typed retry/terminal classification for this occurrence.
    pub const fn retryability(&self) -> RemoteRetryability {
        if self.retryable {
            RemoteRetryability::Retryable
        } else {
            RemoteRetryability::Terminal
        }
    }

    /// Returns whether a bounded retry may make progress.
    pub const fn is_retryable(&self) -> bool {
        self.retryable
    }

    /// Alias for callers that use the positive/verb-style spelling.
    pub const fn retryable(&self) -> bool {
        self.is_retryable()
    }

    /// Returns whether the error is terminal for this operation.
    pub const fn is_terminal(&self) -> bool {
        !self.retryable
    }

    /// Returns the raw diagnostic text for an explicit, local diagnostic
    /// consumer. Callers must not place this value on a wire, in telemetry,
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

    /// Returns the default bounded, redaction-safe diagnostic context.
    pub fn redacted_message(&self) -> String {
        self.wire_message(MAX_WIRE_FAILURE_MESSAGE_BYTES)
    }

    /// Returns whether the local message is within the default wire byte
    /// bound. Redaction may still replace a sensitive message.
    pub const fn message_is_bounded(&self) -> bool {
        self.message.len() <= MAX_REMOTE_ERROR_MESSAGE_BYTES
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

    /// Returns the occurrence-level retry/terminal classification.
    ///
    /// Only an incomplete frame is retryable at this layer: an adapter may
    /// still receive the missing bytes.  Once a complete frame violates a
    /// protocol, limit, or value invariant, retrying the same bytes cannot
    /// make progress safely.
    pub const fn retryability(&self) -> RemoteRetryability {
        match self {
            Self::Incomplete { .. } => RemoteRetryability::Retryable,
            Self::InvalidMagic { .. }
            | Self::UnsupportedVersion(_)
            | Self::UnknownMessageKind(_)
            | Self::UnknownFlags(_)
            | Self::MessageTooLarge { .. }
            | Self::FieldTooLarge { .. }
            | Self::InvalidLimits
            | Self::LengthMismatch { .. }
            | Self::InvalidUtf8 { .. }
            | Self::InvalidValue { .. }
            | Self::DuplicateProperty(_)
            | Self::InvalidSample(_)
            | Self::UnsupportedCapability(_)
            | Self::TrailingBytes { .. } => RemoteRetryability::Terminal,
        }
    }

    /// Returns whether a bounded retry may make progress.
    pub const fn is_retryable(&self) -> bool {
        self.retryability().is_retryable()
    }

    /// Returns whether this codec failure is terminal for the current bytes.
    pub const fn is_terminal(&self) -> bool {
        !self.is_retryable()
    }

    /// Returns bounded, redaction-safe text for a local diagnostic boundary.
    pub fn redacted_message(&self) -> String {
        sanitize_wire_failure_message(&self.to_string(), MAX_WIRE_FAILURE_MESSAGE_BYTES)
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

impl From<ProtocolError> for RemoteError {
    fn from(error: ProtocolError) -> Self {
        let code = error.code();
        let retryable = error.is_retryable();
        let message = error.redacted_message();
        Self::new(code, retryable, message)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)] // Error tests use expect for explicit assertion context.
mod tests {
    use super::*;

    #[test]
    fn stable_codes_are_closed_ascii_and_round_trip() {
        assert!(!RemoteErrorCode::ALL.is_empty());
        for (index, code) in RemoteErrorCode::ALL.iter().enumerate() {
            let spelling = code.as_str();
            assert!(spelling.is_ascii());
            assert!(spelling.starts_with("remote."));
            assert_eq!(RemoteErrorCode::from_stable_code(spelling), Some(*code));
            assert_eq!(code.to_string(), spelling);
            assert!(
                RemoteErrorCode::ALL[..index]
                    .iter()
                    .all(|previous| previous.as_str() != spelling)
            );
        }
        assert_eq!(RemoteErrorCode::from_stable_code("remote.unknown"), None);
        assert_eq!(RemoteErrorCode::from_stable_code("worker failed"), None);
    }

    #[test]
    fn retryability_is_typed_and_terminal_is_its_complement() {
        let retryable = RemoteError::retryable_error(RemoteErrorCode::Backpressure, "queue full");
        assert_eq!(retryable.retryability(), RemoteRetryability::Retryable);
        assert!(retryable.is_retryable());
        assert!(!retryable.is_terminal());
        assert_eq!(retryable.retryability().to_string(), "retryable");

        let terminal = RemoteError::terminal(RemoteErrorCode::InvalidState, "closed");
        assert_eq!(terminal.retryability(), RemoteRetryability::Terminal);
        assert!(!terminal.is_retryable());
        assert!(terminal.is_terminal());
        assert_eq!(terminal.retryability().to_string(), "terminal");
    }

    #[test]
    fn incomplete_protocol_frames_are_retryable_but_invalid_frames_are_terminal() {
        let incomplete = ProtocolError::Incomplete { needed: 4 };
        assert!(incomplete.is_retryable());
        assert!(!incomplete.is_terminal());

        let invalid = ProtocolError::InvalidMagic { found: *b"NOPE" };
        assert!(!invalid.is_retryable());
        assert!(invalid.is_terminal());
        let converted = RemoteError::from(incomplete);
        assert_eq!(converted.code, RemoteErrorCode::Protocol);
        assert!(converted.is_retryable());
    }

    #[test]
    fn wire_diagnostics_redact_secrets_paths_controls_and_boundaries() {
        for sensitive in [
            "password=secret-value",
            "https://user:password@example.invalid/report",
            "/tmp/run-secret/report.jtl",
            "C:\\private\\run.jmx",
            "line\nwith-control",
        ] {
            let error = RemoteError::terminal(RemoteErrorCode::WorkerFailure, sensitive);
            assert_eq!(error.redacted_message(), REDACTED_FAILURE_CONTEXT);
        }

        let ordinary = RemoteError::terminal(RemoteErrorCode::WorkerFailure, "operation: failed");
        assert_eq!(ordinary.redacted_message(), "operation: failed");

        let raw = "x".repeat(MAX_REMOTE_ERROR_MESSAGE_BYTES * 4);
        let diagnostic = RemoteError::terminal(RemoteErrorCode::Internal, raw);
        assert!(!diagnostic.message_is_bounded());
        assert!(diagnostic.redacted_message().len() <= MAX_WIRE_FAILURE_MESSAGE_BYTES);
    }

    #[test]
    fn formatting_never_echoes_untrusted_error_text() {
        let secret = "credential=remote-secret";
        let error = RemoteError::terminal(RemoteErrorCode::Internal, secret);
        assert!(!error.to_string().contains(secret));
        assert!(!format!("{error:?}").contains(secret));

        let duplicate = ProtocolError::DuplicateProperty(secret.to_owned());
        assert!(!duplicate.to_string().contains(secret));
        assert!(!format!("{duplicate:?}").contains(secret));
    }
}
