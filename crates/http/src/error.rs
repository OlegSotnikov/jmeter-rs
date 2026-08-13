// SPDX-License-Identifier: Apache-2.0
//! Stable errors for the HTTP semantic boundary.

use core::fmt;

/// The phase in which an injected transport observed a timeout.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TimeoutPhase {
    /// The complete operation exceeded its deadline.
    Overall,
    /// Establishing a connection exceeded its deadline.
    Connect,
    /// Writing request bytes exceeded its deadline.
    Write,
    /// Reading response bytes exceeded its deadline.
    Read,
    /// A TLS handshake exceeded its deadline.
    Tls,
}

/// A transport failure reported by an injected transport.
#[derive(Clone, Eq, PartialEq)]
pub enum TransportError {
    /// Name resolution failed.
    Dns(String),
    /// A connection could not be established.
    Connect(String),
    /// Request bytes could not be written.
    Write(String),
    /// Response bytes could not be read.
    Read(String),
    /// The peer returned malformed protocol data.
    Protocol(String),
    /// The transport was reset or closed before completion.
    Reset(String),
    /// A transport-specific timeout occurred.
    Timeout(TimeoutPhase),
    /// The operation was cancelled through the explicit cancellation token.
    Cancelled,
    /// The transport capability is not available in this build/profile.
    Unsupported(String),
    /// A transport resource bound was reached.
    ResourceLimit(String),
    /// An adapter supplied an invalid request.
    InvalidRequest(String),
    /// A transport adapter supplied a stable code and diagnostic detail.
    ///
    /// The detail is bounded and redacted in `Debug`/`Display`; adapters must
    /// not force callers to choose between useful typed failures and leaking
    /// credentials in diagnostics.
    Adapter {
        /// Adapter-local stable code.
        code: String,
        /// Bounded diagnostic detail.
        message: String,
    },
}

impl fmt::Debug for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dns(message) => formatter
                .debug_tuple("Dns")
                .field(&redacted(message))
                .finish(),
            Self::Connect(message) => formatter
                .debug_tuple("Connect")
                .field(&redacted(message))
                .finish(),
            Self::Write(message) => formatter
                .debug_tuple("Write")
                .field(&redacted(message))
                .finish(),
            Self::Read(message) => formatter
                .debug_tuple("Read")
                .field(&redacted(message))
                .finish(),
            Self::Protocol(message) => formatter
                .debug_tuple("Protocol")
                .field(&redacted(message))
                .finish(),
            Self::Reset(message) => formatter
                .debug_tuple("Reset")
                .field(&redacted(message))
                .finish(),
            Self::Timeout(phase) => formatter.debug_tuple("Timeout").field(phase).finish(),
            Self::Cancelled => formatter.write_str("Cancelled"),
            Self::Unsupported(message) => formatter
                .debug_tuple("Unsupported")
                .field(&redacted(message))
                .finish(),
            Self::ResourceLimit(message) => formatter
                .debug_tuple("ResourceLimit")
                .field(&redacted(message))
                .finish(),
            Self::InvalidRequest(message) => formatter
                .debug_tuple("InvalidRequest")
                .field(&redacted(message))
                .finish(),
            Self::Adapter { code, message } => formatter
                .debug_struct("Adapter")
                .field("code", &bounded(code))
                .field("message", &redacted(message))
                .finish(),
        }
    }
}

impl TransportError {
    /// Creates a bounded adapter error with an explicit local code.
    pub fn adapter(code: impl Into<String>, message: impl Into<String>) -> Self {
        let code = code.into();
        let message = message.into();
        if code.is_empty()
            || code.len() > 128
            || !code
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Self::Adapter {
                code: "invalid-adapter-code".to_owned(),
                message: "adapter supplied an invalid error code".to_owned(),
            };
        }
        Self::Adapter {
            code,
            message: bounded(&message),
        }
    }

    /// Returns the adapter-local code when this is an adapter error.
    #[must_use]
    pub fn adapter_code(&self) -> Option<&str> {
        match self {
            Self::Adapter { code, .. } => Some(code),
            _ => None,
        }
    }

    /// Returns the stable machine-readable transport code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Dns(_) => "http.transport.dns",
            Self::Connect(_) => "http.transport.connect",
            Self::Write(_) => "http.transport.write",
            Self::Read(_) => "http.transport.read",
            Self::Protocol(_) => "http.transport.protocol",
            Self::Reset(_) => "http.transport.reset",
            Self::Timeout(_) => "http.transport.timeout",
            Self::Cancelled => "http.transport.cancelled",
            Self::Unsupported(_) => "http.transport.unsupported",
            Self::ResourceLimit(_) => "http.transport.resource-limit",
            Self::InvalidRequest(_) => "http.transport.invalid-request",
            Self::Adapter { .. } => "http.transport.adapter",
        }
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dns(message)
            | Self::Connect(message)
            | Self::Write(message)
            | Self::Read(message)
            | Self::Protocol(message)
            | Self::Reset(message)
            | Self::Unsupported(message)
            | Self::ResourceLimit(message)
            | Self::InvalidRequest(message) => {
                write!(formatter, "{}: {}", self.code(), redacted(message))
            }
            Self::Adapter { code, message } => {
                write!(formatter, "{}:{code}: {}", self.code(), redacted(message))
            }
            Self::Timeout(phase) => write!(formatter, "{}: {phase:?}", self.code()),
            Self::Cancelled => formatter.write_str(self.code()),
        }
    }
}

impl std::error::Error for TransportError {}

/// Errors produced while constructing or executing an HTTP request.
#[derive(Clone, Eq, PartialEq)]
pub enum HttpError {
    /// A URL was empty, malformed, or used an unsupported scheme.
    InvalidUrl(String),
    /// A method name was empty or contained invalid bytes.
    InvalidMethod(String),
    /// A header name or value violated HTTP field syntax.
    InvalidHeader(String),
    /// A request or response exceeded a configured bound.
    ResourceLimit(String),
    /// The request body exceeded its configured bound.
    RequestBodyLimit {
        /// Actual body length.
        actual: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// The response body exceeded its configured bound.
    ResponseBodyLimit {
        /// Actual body length.
        actual: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// A transport capability failed.
    Transport(TransportError),
    /// An operation exceeded a configured deadline.
    Timeout(TimeoutPhase),
    /// The operation was cancelled through the explicit cancellation token.
    Cancelled,
    /// Timeout configuration was missing a finite overall deadline or had an
    /// invalid duration.
    InvalidTimeout(String),
    /// A redirect response did not contain a usable location.
    InvalidRedirect(String),
    /// The redirect limit was reached.
    RedirectLimit {
        /// Configured maximum number of redirects.
        maximum: usize,
    },
    /// A redirect would cross an origin and credentials were not allowed.
    RedirectOriginDenied,
    /// A proxy configuration is invalid or cannot route the URL.
    Proxy(String),
    /// TLS policy is invalid or unsupported by the selected transport.
    Tls(String),
    /// Cookie parsing or matching failed.
    Cookie(String),
    /// Cache metadata is invalid or exceeds a bound.
    Cache(String),
    /// Authentication configuration or challenge handling failed.
    Authentication(String),
    /// The requested HTTP capability is intentionally not implemented.
    Unsupported(String),
}

impl fmt::Debug for HttpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUrl(message) => formatter
                .debug_tuple("InvalidUrl")
                .field(&bounded(message))
                .finish(),
            Self::InvalidMethod(message) => formatter
                .debug_tuple("InvalidMethod")
                .field(&bounded(message))
                .finish(),
            Self::InvalidHeader(message) => formatter
                .debug_tuple("InvalidHeader")
                .field(&bounded(message))
                .finish(),
            Self::ResourceLimit(message) => formatter
                .debug_tuple("ResourceLimit")
                .field(&bounded(message))
                .finish(),
            Self::RequestBodyLimit { actual, maximum } => formatter
                .debug_struct("RequestBodyLimit")
                .field("actual", actual)
                .field("maximum", maximum)
                .finish(),
            Self::ResponseBodyLimit { actual, maximum } => formatter
                .debug_struct("ResponseBodyLimit")
                .field("actual", actual)
                .field("maximum", maximum)
                .finish(),
            Self::Transport(error) => formatter.debug_tuple("Transport").field(error).finish(),
            Self::Timeout(phase) => formatter.debug_tuple("Timeout").field(phase).finish(),
            Self::Cancelled => formatter.write_str("Cancelled"),
            Self::InvalidTimeout(message) => formatter
                .debug_tuple("InvalidTimeout")
                .field(&bounded(message))
                .finish(),
            Self::InvalidRedirect(message) => formatter
                .debug_tuple("InvalidRedirect")
                .field(&bounded(message))
                .finish(),
            Self::RedirectLimit { maximum } => formatter
                .debug_struct("RedirectLimit")
                .field("maximum", maximum)
                .finish(),
            Self::RedirectOriginDenied => formatter.write_str("RedirectOriginDenied"),
            Self::Proxy(message) => formatter
                .debug_tuple("Proxy")
                .field(&bounded(message))
                .finish(),
            Self::Tls(message) => formatter
                .debug_tuple("Tls")
                .field(&bounded(message))
                .finish(),
            Self::Cookie(message) => formatter
                .debug_tuple("Cookie")
                .field(&bounded(message))
                .finish(),
            Self::Cache(message) => formatter
                .debug_tuple("Cache")
                .field(&bounded(message))
                .finish(),
            Self::Authentication(message) => formatter
                .debug_tuple("Authentication")
                .field(&bounded(message))
                .finish(),
            Self::Unsupported(message) => formatter
                .debug_tuple("Unsupported")
                .field(&bounded(message))
                .finish(),
        }
    }
}

fn bounded(value: &str) -> String {
    const MAX_DEBUG_BYTES: usize = 256;
    if value.len() <= MAX_DEBUG_BYTES {
        return value.to_owned();
    }
    let mut end = MAX_DEBUG_BYTES;
    while !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    format!("{}…", &value[..end])
}

fn redacted(_value: &str) -> String {
    // Transport adapters receive request targets, headers, and credentials in
    // the same operation.  A message supplied by an arbitrary adapter cannot
    // be classified safely as public: even a value that does not contain a
    // familiar key name may be a bare Basic token, base64 credential, or a
    // tenant-specific secret.  Keep the stable error code and phase as the
    // diagnostic contract and never echo adapter text.
    "<redacted transport detail>".to_owned()
}

impl HttpError {
    /// Creates a bounded-resource error.
    #[must_use]
    pub fn resource_limit(message: impl Into<String>) -> Self {
        Self::ResourceLimit(message.into())
    }

    /// Returns the stable machine-readable code for this error.
    #[must_use]
    pub const fn stable_code(&self) -> &'static str {
        match self {
            Self::InvalidUrl(_) => "http.invalid-url",
            Self::InvalidMethod(_) => "http.invalid-method",
            Self::InvalidHeader(_) => "http.invalid-header",
            Self::ResourceLimit(_) => "http.resource-limit",
            Self::RequestBodyLimit { .. } => "http.request-body-limit",
            Self::ResponseBodyLimit { .. } => "http.response-body-limit",
            Self::Transport(error) => error.code(),
            Self::Timeout(_) => "http.timeout",
            Self::Cancelled => "http.cancelled",
            Self::InvalidTimeout(_) => "http.invalid-timeout",
            Self::InvalidRedirect(_) => "http.invalid-redirect",
            Self::RedirectLimit { .. } => "http.redirect-limit",
            Self::RedirectOriginDenied => "http.redirect-origin-denied",
            Self::Proxy(_) => "http.proxy",
            Self::Tls(_) => "http.tls",
            Self::Cookie(_) => "http.cookie",
            Self::Cache(_) => "http.cache",
            Self::Authentication(_) => "http.authentication",
            Self::Unsupported(_) => "http.unsupported",
        }
    }
}

impl fmt::Display for HttpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUrl(message)
            | Self::InvalidMethod(message)
            | Self::InvalidHeader(message)
            | Self::ResourceLimit(message)
            | Self::InvalidRedirect(message)
            | Self::Proxy(message)
            | Self::Tls(message)
            | Self::Cookie(message)
            | Self::Cache(message)
            | Self::Authentication(message)
            | Self::Unsupported(message)
            | Self::InvalidTimeout(message) => {
                write!(formatter, "{}: {message}", self.stable_code())
            }
            Self::RequestBodyLimit { actual, maximum } => write!(
                formatter,
                "{}: {actual} bytes exceeds {maximum}",
                self.stable_code()
            ),
            Self::ResponseBodyLimit { actual, maximum } => write!(
                formatter,
                "{}: {actual} bytes exceeds {maximum}",
                self.stable_code()
            ),
            Self::Transport(error) => error.fmt(formatter),
            Self::Timeout(phase) => write!(formatter, "{}: {phase:?}", self.stable_code()),
            Self::Cancelled => formatter.write_str(self.stable_code()),
            Self::RedirectLimit { maximum } => {
                write!(formatter, "{}: maximum {maximum}", self.stable_code())
            }
            Self::RedirectOriginDenied => formatter.write_str(self.stable_code()),
        }
    }
}

impl std::error::Error for HttpError {}

impl From<TransportError> for HttpError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}
