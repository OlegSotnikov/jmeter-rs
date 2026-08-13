// SPDX-License-Identifier: Apache-2.0
//! Stable errors returned by the result model.

use core::fmt;

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
        }
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
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
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
}

impl ResultError {
    /// Returns the stable machine-readable category.
    pub const fn code(self) -> ResultErrorCode {
        match self {
            Self::InvalidInput { .. } => ResultErrorCode::InvalidInput,
            Self::InvalidTiming { .. } => ResultErrorCode::InvalidTiming,
            Self::Overflow { .. } => ResultErrorCode::Overflow,
            Self::HierarchyLimitExceeded { .. } => ResultErrorCode::HierarchyLimit,
            Self::InvalidHierarchy { .. } => ResultErrorCode::InvalidHierarchy,
            Self::InvalidAssertion { .. } => ResultErrorCode::InvalidAssertion,
        }
    }

    /// Returns the stable machine-readable string code.
    pub const fn stable_code(self) -> &'static str {
        self.code().as_str()
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
        }
    }
}

impl std::error::Error for ResultError {}
