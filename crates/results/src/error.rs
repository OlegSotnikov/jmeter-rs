// SPDX-License-Identifier: Apache-2.0
//! Stable errors returned by the result model.

use core::fmt;

/// Maximum bytes retained by one free-form result-error context value.
///
/// Result errors can be created from untrusted JTL/XML/CSV input.  Context is
/// therefore bounded before it is retained, even though its formatted forms
/// redact the value.  The bound is deliberately small because context is
/// diagnostic only and must never become a second payload store.
pub const MAX_RESULT_ERROR_CONTEXT_BYTES: usize = 256;

/// Maximum contextual wrappers classified or formatted from one error.
///
/// [`ResultError::with_context`] flattens normal construction to one wrapper,
/// but the public enum can still be constructed directly.  This bound keeps
/// adversarial nested values from turning code/display/error reporting into a
/// recursive resource exhaustion path.
pub const MAX_RESULT_ERROR_CONTEXT_DEPTH: usize = 16;

const REDACTED: &str = "<redacted>";

/// Stable machine-readable categories for result-model errors.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ResultErrorCode {
    /// A supplied value cannot be represented by the domain type.
    InvalidInput,
    /// A timing relation is inconsistent.
    InvalidTiming,
    /// A count or timestamp arithmetic operation overflowed.
    Overflow,
    /// A hierarchy exceeds a caller-provided resource limit.
    HierarchyLimit,
    /// A hierarchy or aggregate violates a structural invariant.
    InvalidHierarchy,
    /// An assertion contains an invalid combination of outcomes.
    InvalidAssertion,
    /// Context nesting exceeded the diagnostic traversal bound.
    ContextLimit,
}

impl ResultErrorCode {
    /// Returns the stable wire/log code for this category.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInput => "results.invalid_input",
            Self::InvalidTiming => "results.invalid_timing",
            Self::Overflow => "results.overflow",
            Self::HierarchyLimit => "results.hierarchy_limit",
            Self::InvalidHierarchy => "results.invalid_hierarchy",
            Self::InvalidAssertion => "results.invalid_assertion",
            Self::ContextLimit => "results.context_limit",
        }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn stable_code(self) -> &'static str {
        self.as_str()
    }

    /// Returns whether this category is a bounded resource failure.
    #[must_use]
    pub const fn is_limit(self) -> bool {
        matches!(self, Self::HierarchyLimit | Self::ContextLimit)
    }
}

impl fmt::Display for ResultErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A result field involved in a validation or arithmetic error.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ResultField {
    /// A wall-clock timestamp.
    Timestamp,
    /// A sample elapsed duration.
    Elapsed,
    /// Time until the first response byte.
    Latency,
    /// Time spent establishing a connection.
    Connect,
    /// Time attributed to idle periods.
    Idle,
    /// Received byte count.
    ReceivedBytes,
    /// Sent byte count.
    SentBytes,
    /// Number of samples represented by a result.
    SampleCount,
    /// Number of errors represented by a result.
    ErrorCount,
    /// Active-thread count.
    ThreadCount,
    /// A sample label.
    Label,
    /// An assertion result.
    Assertion,
    /// A nested result.
    SubResults,
}

impl fmt::Display for ResultField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Timestamp => "timestamp",
            Self::Elapsed => "elapsed",
            Self::Latency => "latency",
            Self::Connect => "connect",
            Self::Idle => "idle",
            Self::ReceivedBytes => "received_bytes",
            Self::SentBytes => "sent_bytes",
            Self::SampleCount => "sample_count",
            Self::ErrorCount => "error_count",
            Self::ThreadCount => "thread_count",
            Self::Label => "label",
            Self::Assertion => "assertion",
            Self::SubResults => "sub_results",
        };
        formatter.write_str(name)
    }
}

/// The timing relation which failed validation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TimingViolation {
    /// The end wall timestamp precedes the start wall timestamp.
    EndBeforeStart,
    /// Elapsed time exceeds the measured start-to-end wall span.
    ElapsedExceedsWallSpan,
    /// Latency exceeds elapsed time.
    LatencyExceedsElapsed,
    /// Connect time exceeds elapsed time.
    ConnectExceedsElapsed,
    /// Idle time exceeds elapsed time.
    IdleExceedsElapsed,
}

impl fmt::Display for TimingViolation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::EndBeforeStart => "end precedes start",
            Self::ElapsedExceedsWallSpan => "elapsed exceeds wall span",
            Self::LatencyExceedsElapsed => "latency exceeds elapsed",
            Self::ConnectExceedsElapsed => "connect exceeds elapsed",
            Self::IdleExceedsElapsed => "idle exceeds elapsed",
        };
        formatter.write_str(text)
    }
}

/// A hierarchy resource limit which was exceeded.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HierarchyLimit {
    /// Maximum node depth.
    Depth,
    /// Maximum number of nodes.
    Nodes,
}

impl fmt::Display for HierarchyLimit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Depth => "depth",
            Self::Nodes => "nodes",
        })
    }
}

/// An input field that could not be accepted.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum InputField {
    /// A negative duration or count supplied through a signed wire value.
    NegativeNumber(ResultField),
    /// A hierarchy limit was zero.
    EmptyLimit,
    /// A value was not valid for its domain representation.
    Value(ResultField),
}

impl fmt::Display for InputField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NegativeNumber(field) => write!(formatter, "negative {field}"),
            Self::EmptyLimit => formatter.write_str("empty hierarchy limit"),
            Self::Value(field) => write!(formatter, "invalid {field}"),
        }
    }
}

/// A failure while constructing bounded result-error context.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ResultContextError {
    /// A free-form context value exceeded the retained diagnostic bound.
    ValueTooLong {
        /// Stable context field name.
        field: &'static str,
        /// Supplied byte length.
        actual: usize,
        /// Maximum retained byte length.
        maximum: usize,
    },
}

impl ResultContextError {
    /// Returns the bounded context field that was rejected.
    #[must_use]
    pub const fn field(self) -> &'static str {
        match self {
            Self::ValueTooLong { field, .. } => field,
        }
    }

    /// Alias retained for callers that prefer an explicit field-name method.
    #[must_use]
    pub const fn field_name(self) -> &'static str {
        self.field()
    }

    /// Returns the supplied byte length.
    #[must_use]
    pub const fn actual(self) -> usize {
        match self {
            Self::ValueTooLong { actual, .. } => actual,
        }
    }

    /// Returns the maximum retained byte length.
    #[must_use]
    pub const fn maximum(self) -> usize {
        match self {
            Self::ValueTooLong { maximum, .. } => maximum,
        }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ValueTooLong { .. } => "results.context_value_too_long",
        }
    }

    /// Alias emphasizing that this value is the stable code.
    #[must_use]
    pub const fn stable_code(self) -> &'static str {
        self.code()
    }
}

impl fmt::Display for ResultContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ValueTooLong {
                field,
                actual,
                maximum,
            } => write!(
                formatter,
                "{}: {field} is {actual} bytes (maximum {maximum})",
                self.code()
            ),
        }
    }
}

impl std::error::Error for ResultContextError {}

/// A bounded source location attached to a result error.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct ResultSourceContext {
    name: String,
    line: Option<usize>,
    column: Option<usize>,
    byte_offset: Option<usize>,
}

impl ResultSourceContext {
    /// Creates a source context with a bounded source name.
    pub fn new(name: impl Into<String>) -> Result<Self, ResultContextError> {
        let name = name.into();
        if name.len() > MAX_RESULT_ERROR_CONTEXT_BYTES {
            return Err(ResultContextError::ValueTooLong {
                field: "source",
                actual: name.len(),
                maximum: MAX_RESULT_ERROR_CONTEXT_BYTES,
            });
        }
        Ok(Self {
            name,
            line: None,
            column: None,
            byte_offset: None,
        })
    }

    /// Adds source coordinates without retaining source payload bytes in
    /// formatted diagnostics.
    #[must_use]
    pub const fn with_position(
        mut self,
        line: Option<usize>,
        column: Option<usize>,
        byte_offset: Option<usize>,
    ) -> Self {
        self.line = line;
        self.column = column;
        self.byte_offset = byte_offset;
        self
    }

    /// Returns the source name for a trusted local diagnostic consumer.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the optional source line.
    #[must_use]
    pub const fn line(&self) -> Option<usize> {
        self.line
    }

    /// Returns the optional source column.
    #[must_use]
    pub const fn column(&self) -> Option<usize> {
        self.column
    }

    /// Returns the optional source byte offset.
    #[must_use]
    pub const fn byte_offset(&self) -> Option<usize> {
        self.byte_offset
    }
}

impl fmt::Debug for ResultSourceContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResultSourceContext")
            .field("name", &REDACTED)
            .field("name_len", &self.name.len())
            .field("line", &self.line)
            .field("column", &self.column)
            .field("byte_offset", &self.byte_offset)
            .finish()
    }
}

impl fmt::Display for ResultSourceContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("source ")?;
        formatter.write_str(REDACTED)?;
        if let Some(line) = self.line {
            write!(formatter, ":{line}")?;
            if let Some(column) = self.column {
                write!(formatter, ":{column}")?;
            }
        }
        if let Some(byte_offset) = self.byte_offset {
            write!(formatter, " (byte {byte_offset})")?;
        }
        Ok(())
    }
}

/// Bounded source/run/sample context attached to a result error.
#[derive(Clone, Default, Eq, Hash, PartialEq)]
pub struct ResultErrorContext {
    operation: Option<&'static str>,
    source: Option<ResultSourceContext>,
    run_id: Option<String>,
    user_id: Option<String>,
    sample_id: Option<String>,
    thread_name: Option<String>,
}

impl ResultErrorContext {
    /// Creates an empty context.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            operation: None,
            source: None,
            run_id: None,
            user_id: None,
            sample_id: None,
            thread_name: None,
        }
    }

    /// Attaches a stable operation name.
    #[must_use]
    pub const fn with_operation(mut self, operation: &'static str) -> Self {
        self.operation = Some(operation);
        self
    }

    /// Attaches a bounded source location.
    #[must_use]
    pub fn with_source(mut self, source: ResultSourceContext) -> Self {
        self.source = Some(source);
        self
    }

    /// Attaches a bounded run identity.
    pub fn try_with_run_id(self, value: impl Into<String>) -> Result<Self, ResultContextError> {
        self.try_with_text("run_id", value, |context, value| {
            context.run_id = Some(value)
        })
    }

    /// Attaches a bounded virtual-user identity.
    pub fn try_with_user_id(self, value: impl Into<String>) -> Result<Self, ResultContextError> {
        self.try_with_text("user_id", value, |context, value| {
            context.user_id = Some(value)
        })
    }

    /// Attaches a bounded sample identity.
    pub fn try_with_sample_id(self, value: impl Into<String>) -> Result<Self, ResultContextError> {
        self.try_with_text("sample_id", value, |context, value| {
            context.sample_id = Some(value)
        })
    }

    /// Attaches a bounded virtual-user/thread name.
    pub fn try_with_thread_name(
        self,
        value: impl Into<String>,
    ) -> Result<Self, ResultContextError> {
        self.try_with_text("thread_name", value, |context, value| {
            context.thread_name = Some(value)
        })
    }

    fn try_with_text(
        mut self,
        field: &'static str,
        value: impl Into<String>,
        set: impl FnOnce(&mut Self, String),
    ) -> Result<Self, ResultContextError> {
        let value = value.into();
        if value.len() > MAX_RESULT_ERROR_CONTEXT_BYTES {
            return Err(ResultContextError::ValueTooLong {
                field,
                actual: value.len(),
                maximum: MAX_RESULT_ERROR_CONTEXT_BYTES,
            });
        }
        set(&mut self, value);
        Ok(self)
    }

    /// Returns the stable operation name, if attached.
    #[must_use]
    pub const fn operation(&self) -> Option<&'static str> {
        self.operation
    }

    /// Returns the source location, if attached.
    #[must_use]
    pub fn source(&self) -> Option<&ResultSourceContext> {
        self.source.as_ref()
    }

    /// Returns the trusted run identity, if attached.
    #[must_use]
    pub fn run_id(&self) -> Option<&str> {
        self.run_id.as_deref()
    }

    /// Returns the trusted virtual-user identity, if attached.
    #[must_use]
    pub fn user_id(&self) -> Option<&str> {
        self.user_id.as_deref()
    }

    /// Returns the trusted sample identity, if attached.
    #[must_use]
    pub fn sample_id(&self) -> Option<&str> {
        self.sample_id.as_deref()
    }

    /// Returns the trusted thread name, if attached.
    #[must_use]
    pub fn thread_name(&self) -> Option<&str> {
        self.thread_name.as_deref()
    }

    /// Returns whether no context was attached.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.operation.is_none()
            && self.source.is_none()
            && self.run_id.is_none()
            && self.user_id.is_none()
            && self.sample_id.is_none()
            && self.thread_name.is_none()
    }

    fn merge(self, newer: Self) -> Self {
        Self {
            operation: newer.operation.or(self.operation),
            source: newer.source.or(self.source),
            run_id: newer.run_id.or(self.run_id),
            user_id: newer.user_id.or(self.user_id),
            sample_id: newer.sample_id.or(self.sample_id),
            thread_name: newer.thread_name.or(self.thread_name),
        }
    }
}

impl fmt::Debug for ResultErrorContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResultErrorContext")
            .field("operation", &self.operation)
            .field("source", &self.source)
            .field("run_id", &self.run_id.as_ref().map(String::len))
            .field("user_id", &self.user_id.as_ref().map(String::len))
            .field("sample_id", &self.sample_id.as_ref().map(String::len))
            .field("thread_name", &self.thread_name.as_ref().map(String::len))
            .finish()
    }
}

impl fmt::Display for ResultErrorContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut wrote = false;
        if let Some(operation) = self.operation {
            write!(formatter, "operation={operation}")?;
            wrote = true;
        }
        if let Some(source) = &self.source {
            if wrote {
                formatter.write_str(", ")?;
            }
            source.fmt(formatter)?;
            wrote = true;
        }
        for (name, value) in [
            ("run_id", self.run_id.as_ref()),
            ("user_id", self.user_id.as_ref()),
            ("sample_id", self.sample_id.as_ref()),
            ("thread_name", self.thread_name.as_ref()),
        ] {
            if let Some(value) = value {
                if wrote {
                    formatter.write_str(", ")?;
                }
                write!(formatter, "{name}={REDACTED}({} bytes)", value.len())?;
                wrote = true;
            }
        }
        if !wrote {
            formatter.write_str("no context")?;
        }
        Ok(())
    }
}

/// Retry classification for a result-model error.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ResultRetryability {
    /// A bounded retry may make progress without changing the result payload.
    Retryable,
    /// Retrying the same invalid result cannot make progress.
    Terminal,
}

impl ResultRetryability {
    /// Returns whether a retry may make progress.
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        matches!(self, Self::Retryable)
    }

    /// Returns the stable diagnostic spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Retryable => "retryable",
            Self::Terminal => "terminal",
        }
    }
}

impl fmt::Display for ResultRetryability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A legacy assertion validation marker retained for API compatibility.
///
/// JMeter's XML wire flags are independent, so the current result model does
/// not emit this violation for a failure+error combination.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AssertionViolation {
    /// Legacy marker for a result carrying both failure and error flags.
    FailureAndError,
}

impl fmt::Display for AssertionViolation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::FailureAndError => "assertion is both failure and error",
        })
    }
}

/// Errors returned by checked result construction, validation, and
/// aggregation.
#[derive(Clone, Eq, Hash, PartialEq)]
pub enum ResultError {
    /// A signed or otherwise invalid input value was supplied.
    InvalidInput {
        /// The invalid input field.
        field: InputField,
    },
    /// A timing invariant was violated.
    InvalidTiming {
        /// The violated timing relation.
        violation: TimingViolation,
    },
    /// Arithmetic exceeded the representation of a result field.
    Overflow {
        /// The field whose arithmetic overflowed.
        field: ResultField,
    },
    /// A hierarchy exceeded an explicit bound.
    HierarchyLimitExceeded {
        /// The bound that was exceeded.
        limit: HierarchyLimit,
        /// The observed value.
        actual: usize,
        /// The configured maximum.
        maximum: usize,
    },
    /// A hierarchy-level invariant was violated.
    InvalidHierarchy {
        /// The field identifying the structural violation.
        field: ResultField,
    },
    /// An assertion-level invariant was violated.
    InvalidAssertion {
        /// The assertion violation.
        violation: AssertionViolation,
    },
    /// A bounded diagnostic context wrapper.
    Context {
        /// The underlying result error.
        source: Box<ResultError>,
        /// Source/run/sample context for the failure.
        context: Box<ResultErrorContext>,
    },
    /// Context nesting exceeded the diagnostic traversal bound.
    ContextLimit {
        /// Observed wrapper depth.
        actual: usize,
        /// Maximum permitted wrapper depth.
        maximum: usize,
    },
}

impl ResultError {
    /// Returns the stable machine-readable category.
    pub fn code(&self) -> ResultErrorCode {
        let mut current = self;
        for depth in 0..=MAX_RESULT_ERROR_CONTEXT_DEPTH {
            match current {
                Self::Context { source, .. } if depth < MAX_RESULT_ERROR_CONTEXT_DEPTH => {
                    current = source;
                }
                Self::Context { .. } => return ResultErrorCode::ContextLimit,
                Self::InvalidInput { .. } => return ResultErrorCode::InvalidInput,
                Self::InvalidTiming { .. } => return ResultErrorCode::InvalidTiming,
                Self::Overflow { .. } => return ResultErrorCode::Overflow,
                Self::HierarchyLimitExceeded { .. } => return ResultErrorCode::HierarchyLimit,
                Self::InvalidHierarchy { .. } => return ResultErrorCode::InvalidHierarchy,
                Self::InvalidAssertion { .. } => return ResultErrorCode::InvalidAssertion,
                Self::ContextLimit { .. } => return ResultErrorCode::ContextLimit,
            }
        }
        ResultErrorCode::ContextLimit
    }

    /// Returns the stable machine-readable string code.
    pub fn stable_code(&self) -> &'static str {
        self.code().as_str()
    }

    /// Returns whether retrying the same operation may make progress.
    #[must_use]
    pub fn retryability(&self) -> ResultRetryability {
        ResultRetryability::Terminal
    }

    /// Returns whether retrying the same operation may make progress.
    #[must_use]
    pub fn retryable(&self) -> bool {
        self.retryability().is_retryable()
    }

    /// Returns whether this error is retryable.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        self.retryable()
    }

    /// Returns whether this error represents a finite resource bound.
    #[must_use]
    pub fn is_limit(&self) -> bool {
        self.code().is_limit()
    }

    /// Returns the outermost bounded context, if present.
    #[must_use]
    pub fn context(&self) -> Option<&ResultErrorContext> {
        match self {
            Self::Context { context, .. } => Some(context.as_ref()),
            _ => None,
        }
    }

    /// Returns the attached source location, if present.
    #[must_use]
    pub fn source_context(&self) -> Option<&ResultSourceContext> {
        self.context().and_then(ResultErrorContext::source)
    }

    /// Returns the underlying error for a context wrapper, if present.
    #[must_use]
    pub fn source_error(&self) -> Option<&ResultError> {
        if self.context_depth() > MAX_RESULT_ERROR_CONTEXT_DEPTH {
            return None;
        }
        match self {
            Self::Context { source, .. } => Some(source),
            _ => None,
        }
    }

    /// Attaches bounded context, flattening repeated wrappers into one
    /// context object.  The error remains terminal: context cannot make an
    /// invalid result safe to retry. Context values are already checked by
    /// their constructors, so attaching one cannot fail.
    #[must_use]
    pub fn with_context(self, context: ResultErrorContext) -> Self {
        if context.is_empty() {
            return self;
        }
        let (source, context) = match self {
            Self::Context {
                source,
                context: previous,
            } => (*source, previous.merge(context)),
            other => (other, context),
        };
        Self::Context {
            source: Box::new(source),
            context: Box::new(context),
        }
    }

    /// Returns the number of nested context wrappers without recursion.
    #[must_use]
    pub fn context_depth(&self) -> usize {
        let mut depth = 0usize;
        let mut current = self;
        while let Self::Context { source, .. } = current {
            if depth == MAX_RESULT_ERROR_CONTEXT_DEPTH {
                return MAX_RESULT_ERROR_CONTEXT_DEPTH.saturating_add(1);
            }
            depth += 1;
            current = source;
        }
        depth
    }
}

impl fmt::Debug for ResultError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResultError")
            .field("code", &self.stable_code())
            .field("retryability", &self.retryability())
            .field("context_depth", &self.context_depth())
            .finish()
    }
}

impl fmt::Display for ResultError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput { field } => write!(formatter, "{}: {field}", self.code()),
            Self::InvalidTiming { violation } => {
                write!(formatter, "{}: {violation}", self.code())
            }
            Self::Overflow { field } => write!(formatter, "{}: {field}", self.code()),
            Self::HierarchyLimitExceeded {
                limit,
                actual,
                maximum,
            } => write!(
                formatter,
                "{}: {limit} {actual} exceeds {maximum}",
                self.code()
            ),
            Self::InvalidHierarchy { field } => write!(formatter, "{}: {field}", self.code()),
            Self::InvalidAssertion { violation } => {
                write!(formatter, "{}: {violation}", self.code())
            }
            Self::Context { context, .. } => write!(formatter, "{}: {context}", self.code()),
            Self::ContextLimit { actual, maximum } => write!(
                formatter,
                "{}: context depth {actual} exceeds {maximum}",
                self.code()
            ),
        }
    }
}

impl std::error::Error for ResultError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if self.context_depth() > MAX_RESULT_ERROR_CONTEXT_DEPTH {
            return None;
        }
        match self {
            Self::Context { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "error tests use explicit assertion context"
)]
mod tests {
    use super::*;

    const SECRET: &str = "authorization=Bearer result-secret-payload";

    #[test]
    fn stable_codes_are_borrowed_and_pure_errors_are_terminal() {
        let errors = [
            ResultError::InvalidInput {
                field: InputField::EmptyLimit,
            },
            ResultError::InvalidTiming {
                violation: TimingViolation::EndBeforeStart,
            },
            ResultError::Overflow {
                field: ResultField::Elapsed,
            },
            ResultError::HierarchyLimitExceeded {
                limit: HierarchyLimit::Nodes,
                actual: 2,
                maximum: 1,
            },
            ResultError::InvalidHierarchy {
                field: ResultField::SubResults,
            },
            ResultError::InvalidAssertion {
                violation: AssertionViolation::FailureAndError,
            },
        ];

        for error in &errors {
            assert_eq!(error.code().as_str(), error.stable_code());
            assert!(!error.retryable());
            assert!(!error.is_retryable());
        }

        assert!(ResultErrorCode::HierarchyLimit.is_limit());
        assert_eq!(
            ResultErrorCode::InvalidInput.stable_code(),
            "results.invalid_input"
        );
    }

    #[test]
    fn context_is_queryable_but_formatted_values_are_redacted() {
        let source = ResultSourceContext::new(SECRET)
            .expect("short source context")
            .with_position(Some(7), Some(3), Some(42));
        let context = ResultErrorContext::new()
            .with_operation("decode_jtl")
            .with_source(source.clone())
            .try_with_run_id(SECRET)
            .expect("short run identity")
            .try_with_sample_id(SECRET)
            .expect("short sample identity");
        let error = ResultError::InvalidInput {
            field: InputField::Value(ResultField::Label),
        }
        .with_context(context);

        assert_eq!(error.code(), ResultErrorCode::InvalidInput);
        assert_eq!(error.context_depth(), 1);
        assert_eq!(
            error.context().and_then(ResultErrorContext::source),
            Some(&source)
        );
        assert_eq!(
            error.source_error().map(ResultError::code),
            Some(ResultErrorCode::InvalidInput)
        );
        assert!(std::error::Error::source(&error).is_some());

        let merged = ResultError::InvalidInput {
            field: InputField::Value(ResultField::Label),
        }
        .with_context(
            ResultErrorContext::new()
                .try_with_run_id("run-1")
                .expect("short run identity"),
        )
        .with_context(
            ResultErrorContext::new()
                .try_with_sample_id("sample-1")
                .expect("short sample identity"),
        );
        assert_eq!(merged.context_depth(), 1);
        assert_eq!(
            merged.context().and_then(ResultErrorContext::run_id),
            Some("run-1")
        );
        assert_eq!(
            merged.context().and_then(ResultErrorContext::sample_id),
            Some("sample-1")
        );

        let display = error.to_string();
        let debug = format!("{error:?}");
        assert!(display.contains("results.invalid_input"));
        assert!(display.contains("<redacted>"));
        assert!(!display.contains(SECRET));
        assert!(!debug.contains(SECRET));
        assert!(debug.contains("results.invalid_input"));
    }

    #[test]
    fn context_values_are_bounded_before_retention() {
        let long = "x".repeat(MAX_RESULT_ERROR_CONTEXT_BYTES + 1);

        let source_error = ResultSourceContext::new(long.clone()).expect_err("source is bounded");
        assert_eq!(source_error.code(), "results.context_value_too_long");
        assert_eq!(
            source_error.to_string(),
            format!(
                "results.context_value_too_long: source is {} bytes (maximum {})",
                MAX_RESULT_ERROR_CONTEXT_BYTES + 1,
                MAX_RESULT_ERROR_CONTEXT_BYTES,
            )
        );

        let identity_error = ResultErrorContext::new()
            .try_with_thread_name(long)
            .expect_err("thread identity is bounded");
        assert_eq!(identity_error.code(), "results.context_value_too_long");
        assert_eq!(identity_error.field_name(), "thread_name");
    }

    #[test]
    fn directly_nested_context_has_a_bounded_code_and_display() {
        let mut error = ResultError::InvalidInput {
            field: InputField::Value(ResultField::Label),
        };
        for _ in 0..(MAX_RESULT_ERROR_CONTEXT_DEPTH + 2) {
            error = ResultError::Context {
                source: Box::new(error),
                context: Box::new(ResultErrorContext::new().with_operation("decode_jtl")),
            };
        }

        assert_eq!(error.code(), ResultErrorCode::ContextLimit);
        assert!(error.is_limit());
        assert!(error.to_string().len() < 1024);
        assert!(format!("{error:?}").len() < 256);
    }
}
