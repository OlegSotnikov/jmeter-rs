// SPDX-License-Identifier: Apache-2.0
//! Immutable sample-event snapshots and identity values.

use std::collections::BTreeMap;
use std::fmt;

use crate::{SampleResult, ValidationLimits};

/// Hard upper bound for one textual event identity.
///
/// Event snapshots are retained in bounded result queues.  Keeping this
/// bound here (rather than relying on a sink's queue size) prevents a single
/// untrusted run/host value from consuming an otherwise finite queue.
pub const MAX_EVENT_IDENTITY_BYTES: usize = 64 * 1024;
/// Hard upper bound for one textual result field or selected-variable value.
pub const MAX_EVENT_TEXT_BYTES: usize = 1024 * 1024;
/// Hard upper bound for one request/response payload in an event snapshot.
pub const MAX_EVENT_DATA_BYTES: usize = 8 * 1024 * 1024;
/// Hard upper bound for selected variables in one event snapshot.
pub const MAX_EVENT_VARIABLES: usize = 4096;
/// Hard upper bound for the estimated in-memory event snapshot size.
pub const MAX_EVENT_BYTES: usize = 16 * 1024 * 1024;

/// Bounded resource policy for an immutable [`SampleEvent`] snapshot.
///
/// `SampleResult` already bounds hierarchy depth and node count through
/// [`ValidationLimits`].  These limits cover the other untrusted dimensions:
/// identities, selected variables, dynamic result fields, payload bytes, and
/// the aggregate snapshot size.  The fields are public so an application can
/// select a stricter profile without adding a dependency on a runtime or
/// codec crate; [`EventLimits::validate`] rejects zero or unsafe values.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct EventLimits {
    /// Maximum bytes in a run or host identity.
    pub max_identity_bytes: usize,
    /// Maximum bytes in a thread name.
    pub max_thread_name_bytes: usize,
    /// Maximum bytes in a thread-group name.
    pub max_thread_group_bytes: usize,
    /// Maximum number of selected variables.
    pub max_variables: usize,
    /// Maximum bytes in one selected-variable name.
    pub max_variable_name_bytes: usize,
    /// Maximum bytes in one selected-variable value.
    pub max_variable_value_bytes: usize,
    /// Maximum bytes in one textual result field (label, headers, URL, and so
    /// on).
    pub max_result_text_bytes: usize,
    /// Maximum bytes in one request or response data field.
    pub max_result_data_bytes: usize,
    /// Maximum estimated bytes retained by one complete event snapshot.
    pub max_event_bytes: usize,
}

impl Default for EventLimits {
    fn default() -> Self {
        Self {
            max_identity_bytes: 4 * 1024,
            max_thread_name_bytes: MAX_EVENT_TEXT_BYTES,
            max_thread_group_bytes: MAX_EVENT_TEXT_BYTES,
            max_variables: MAX_EVENT_VARIABLES,
            max_variable_name_bytes: MAX_EVENT_TEXT_BYTES,
            max_variable_value_bytes: MAX_EVENT_TEXT_BYTES,
            max_result_text_bytes: MAX_EVENT_TEXT_BYTES,
            max_result_data_bytes: MAX_EVENT_DATA_BYTES,
            max_event_bytes: MAX_EVENT_BYTES,
        }
    }
}

impl EventLimits {
    /// Creates a policy with the supplied aggregate event-size bound and the
    /// remaining defaults.
    pub fn new(max_event_bytes: usize) -> Result<Self, SampleEventError> {
        let limits = Self {
            max_event_bytes,
            ..Self::default()
        };
        limits.validate()?;
        Ok(limits)
    }

    /// Validates all configured bounds against the hard resource policy.
    pub fn validate(self) -> Result<(), SampleEventError> {
        let values = [
            (
                "max_identity_bytes",
                self.max_identity_bytes,
                MAX_EVENT_IDENTITY_BYTES,
            ),
            (
                "max_thread_name_bytes",
                self.max_thread_name_bytes,
                MAX_EVENT_TEXT_BYTES,
            ),
            (
                "max_thread_group_bytes",
                self.max_thread_group_bytes,
                MAX_EVENT_TEXT_BYTES,
            ),
            ("max_variables", self.max_variables, MAX_EVENT_VARIABLES),
            (
                "max_variable_name_bytes",
                self.max_variable_name_bytes,
                MAX_EVENT_TEXT_BYTES,
            ),
            (
                "max_variable_value_bytes",
                self.max_variable_value_bytes,
                MAX_EVENT_TEXT_BYTES,
            ),
            (
                "max_result_text_bytes",
                self.max_result_text_bytes,
                MAX_EVENT_TEXT_BYTES,
            ),
            (
                "max_result_data_bytes",
                self.max_result_data_bytes,
                MAX_EVENT_DATA_BYTES,
            ),
            ("max_event_bytes", self.max_event_bytes, MAX_EVENT_BYTES),
        ];
        for (field, actual, maximum) in values {
            if actual == 0 || actual > maximum {
                return Err(SampleEventError::InvalidLimit {
                    field,
                    actual,
                    maximum,
                });
            }
        }
        Ok(())
    }

    /// Returns a copy with a stricter aggregate event-size bound.
    pub fn with_max_event_bytes(mut self, maximum: usize) -> Result<Self, SampleEventError> {
        self.max_event_bytes = maximum;
        self.validate()?;
        Ok(self)
    }

    /// Returns a copy with a stricter selected-variable count bound.
    pub fn with_max_variables(mut self, maximum: usize) -> Result<Self, SampleEventError> {
        self.max_variables = maximum;
        self.validate()?;
        Ok(self)
    }
}

/// A bounded, redacted validation error for event snapshots.
///
/// Dynamic result data is never copied into the diagnostic.  Callers can use
/// [`SampleEventError::stable_code`] for machine handling and the size fields
/// for resource reporting.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum SampleEventError {
    /// A configured event bound is zero or exceeds its hard maximum.
    InvalidLimit {
        /// Bound name.
        field: &'static str,
        /// Supplied value.
        actual: usize,
        /// Hard maximum.
        maximum: usize,
    },
    /// An identity exceeded its configured bound.
    IdentityTooLong {
        /// Identity field name.
        field: &'static str,
        /// Observed bytes.
        actual: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// A textual event field exceeded its configured bound.
    TextTooLong {
        /// Field name.
        field: &'static str,
        /// Observed bytes.
        actual: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// A request/response payload exceeded its configured bound.
    DataTooLong {
        /// Field name.
        field: &'static str,
        /// Observed bytes.
        actual: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// The selected-variable count exceeded its configured bound.
    VariablesLimitExceeded {
        /// Observed count.
        actual: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// The aggregate event snapshot exceeded its configured bound.
    EventSizeLimitExceeded {
        /// Estimated retained bytes.
        actual: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// Computing the bounded retained-size estimate overflowed before a
    /// limit comparison could be made.
    EventSizeOverflow,
    /// The result hierarchy or timing model rejected the snapshot.
    Result(crate::ResultError),
}

impl SampleEventError {
    /// Returns the stable machine-readable error code.
    pub fn stable_code(&self) -> &'static str {
        match self {
            Self::InvalidLimit { .. } => "results.event.invalid_limit",
            Self::IdentityTooLong { .. } => "results.event.identity_limit",
            Self::TextTooLong { .. } => "results.event.text_limit",
            Self::DataTooLong { .. } => "results.event.data_limit",
            Self::VariablesLimitExceeded { .. } => "results.event.variables_limit",
            Self::EventSizeLimitExceeded { .. } => "results.event.size_limit",
            Self::EventSizeOverflow => "results.event.size_overflow",
            Self::Result(error) => error.clone().stable_code(),
        }
    }

    /// Returns the underlying result-model error, if this is a hierarchy or
    /// timing failure.
    pub fn result_error(&self) -> Option<crate::ResultError> {
        match self {
            Self::Result(error) => Some(error.clone()),
            _ => None,
        }
    }

    /// Maps a bounded event error into the legacy result error used by the
    /// existing snapshot APIs.  New callers should retain the richer error
    /// from [`SampleEvent::snapshot_with_event_limits`].
    fn into_result_error(self) -> crate::ResultError {
        match self {
            Self::Result(error) => error,
            Self::InvalidLimit { .. } => crate::ResultError::InvalidInput {
                field: crate::InputField::EmptyLimit,
            },
            Self::IdentityTooLong {
                actual, maximum, ..
            }
            | Self::TextTooLong {
                actual, maximum, ..
            }
            | Self::DataTooLong {
                actual, maximum, ..
            }
            | Self::VariablesLimitExceeded { actual, maximum }
            | Self::EventSizeLimitExceeded { actual, maximum } => {
                crate::ResultError::HierarchyLimitExceeded {
                    limit: crate::HierarchyLimit::Nodes,
                    actual,
                    maximum,
                }
            }
            Self::EventSizeOverflow => crate::ResultError::Overflow {
                field: crate::ResultField::SubResults,
            },
        }
    }
}

impl fmt::Display for SampleEventError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit {
                field,
                actual,
                maximum,
            } => write!(
                formatter,
                "{}: {field} {actual} exceeds {maximum}",
                self.stable_code()
            ),
            Self::IdentityTooLong {
                field,
                actual,
                maximum,
            }
            | Self::TextTooLong {
                field,
                actual,
                maximum,
            }
            | Self::DataTooLong {
                field,
                actual,
                maximum,
            } => write!(
                formatter,
                "{}: {field} is {actual} bytes, maximum {maximum}",
                self.stable_code()
            ),
            Self::VariablesLimitExceeded { actual, maximum }
            | Self::EventSizeLimitExceeded { actual, maximum } => write!(
                formatter,
                "{}: {actual} exceeds {maximum}",
                self.stable_code()
            ),
            Self::EventSizeOverflow => formatter.write_str(self.stable_code()),
            Self::Result(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for SampleEventError {}

impl From<crate::ResultError> for SampleEventError {
    fn from(value: crate::ResultError) -> Self {
        Self::Result(value)
    }
}

/// Run identity captured with a result event.
#[derive(Clone, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RunIdentity {
    value: String,
    present: bool,
}

impl RunIdentity {
    /// Creates a run identity without applying a boundary policy.
    ///
    /// This constructor is retained for wire-decoder compatibility. Runtime
    /// and sink boundaries should use [`RunIdentity::try_new`] or validate the
    /// value with their selected [`EventLimits`].
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            present: true,
        }
    }

    /// Creates an absent run identity without converting absence into an
    /// empty string.
    pub const fn absent() -> Self {
        Self {
            value: String::new(),
            present: false,
        }
    }

    /// Creates a bounded, non-empty run identity.
    pub fn try_new(value: impl AsRef<str>) -> Result<Self, SampleEventError> {
        let value = value.as_ref();
        if value.is_empty() {
            return Err(SampleEventError::IdentityTooLong {
                field: "run-id-empty",
                actual: 0,
                maximum: MAX_EVENT_IDENTITY_BYTES,
            });
        }
        if value.len() > MAX_EVENT_IDENTITY_BYTES {
            return Err(SampleEventError::IdentityTooLong {
                field: "run-id",
                actual: value.len(),
                maximum: MAX_EVENT_IDENTITY_BYTES,
            });
        }
        Ok(Self {
            value: value.to_owned(),
            present: true,
        })
    }

    /// Validates this identity against an explicit byte bound.
    pub fn validate_with_limit(&self, maximum: usize) -> Result<(), SampleEventError> {
        if maximum == 0 {
            return Err(SampleEventError::InvalidLimit {
                field: "run-id",
                actual: maximum,
                maximum: MAX_EVENT_IDENTITY_BYTES,
            });
        }
        if self.value.len() > maximum {
            return Err(SampleEventError::IdentityTooLong {
                field: "run-id",
                actual: self.value.len(),
                maximum,
            });
        }
        Ok(())
    }

    /// Returns whether the identity is empty.
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    /// Returns whether the run identity field was present.
    pub const fn is_present(&self) -> bool {
        self.present
    }

    /// Returns the run identity text.
    pub fn as_str(&self) -> &str {
        &self.value
    }

    /// Consumes the identity and returns its text.
    pub fn into_string(self) -> String {
        self.value
    }
}

impl From<String> for RunIdentity {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for RunIdentity {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl fmt::Debug for RunIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RunIdentity")
            .field("present", &self.present)
            .field("len", &self.value.len())
            .finish()
    }
}

/// Short alias for [`RunIdentity`].
pub type RunId = RunIdentity;

/// Host identity captured with a result event.
#[derive(Clone, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HostIdentity {
    value: String,
    present: bool,
}

impl HostIdentity {
    /// Creates a host identity without applying a boundary policy.
    ///
    /// Empty values remain representable because an absent `hn` JTL field is
    /// distinct from a present-empty field. A strict runtime boundary can use
    /// [`HostIdentity::try_new`].
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            present: true,
        }
    }

    /// Creates an absent host identity without converting absence into an
    /// empty string.
    pub const fn absent() -> Self {
        Self {
            value: String::new(),
            present: false,
        }
    }

    /// Creates a bounded, non-empty host identity.
    pub fn try_new(value: impl AsRef<str>) -> Result<Self, SampleEventError> {
        let value = value.as_ref();
        if value.is_empty() {
            return Err(SampleEventError::IdentityTooLong {
                field: "host-id-empty",
                actual: 0,
                maximum: MAX_EVENT_IDENTITY_BYTES,
            });
        }
        if value.len() > MAX_EVENT_IDENTITY_BYTES {
            return Err(SampleEventError::IdentityTooLong {
                field: "host-id",
                actual: value.len(),
                maximum: MAX_EVENT_IDENTITY_BYTES,
            });
        }
        Ok(Self {
            value: value.to_owned(),
            present: true,
        })
    }

    /// Validates this identity against an explicit byte bound.
    pub fn validate_with_limit(&self, maximum: usize) -> Result<(), SampleEventError> {
        if maximum == 0 {
            return Err(SampleEventError::InvalidLimit {
                field: "host-id",
                actual: maximum,
                maximum: MAX_EVENT_IDENTITY_BYTES,
            });
        }
        if self.value.len() > maximum {
            return Err(SampleEventError::IdentityTooLong {
                field: "host-id",
                actual: self.value.len(),
                maximum,
            });
        }
        Ok(())
    }

    /// Returns whether the identity is empty.
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    /// Returns whether the host identity field was present.
    pub const fn is_present(&self) -> bool {
        self.present
    }

    /// Returns the host identity text.
    pub fn as_str(&self) -> &str {
        &self.value
    }

    /// Consumes the identity and returns its text.
    pub fn into_string(self) -> String {
        self.value
    }
}

impl From<String> for HostIdentity {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for HostIdentity {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl fmt::Debug for HostIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostIdentity")
            .field("present", &self.present)
            .field("len", &self.value.len())
            .finish()
    }
}

/// Short alias for [`HostIdentity`].
pub type HostId = HostIdentity;

/// Thread and optional thread-group identity captured with an event.
#[derive(Clone, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ThreadIdentity {
    name: String,
    name_present: bool,
    group: Option<String>,
    number: Option<u64>,
}

impl ThreadIdentity {
    /// Creates a thread identity with no group or numeric index.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            name_present: true,
            group: None,
            number: None,
        }
    }

    /// Creates a thread identity with an optional group and number.
    pub fn with_group(name: impl Into<String>, group: Option<String>, number: Option<u64>) -> Self {
        Self {
            name: name.into(),
            name_present: true,
            group,
            number,
        }
    }

    /// Creates a thread identity whose name field was absent on the source
    /// event.  Access through [`ThreadIdentity::name`] remains an empty string
    /// for source compatibility; [`ThreadIdentity::name_field`] retains the
    /// wire distinction.
    pub const fn without_name() -> Self {
        Self {
            name: String::new(),
            name_present: false,
            group: None,
            number: None,
        }
    }

    /// Validates thread identity text against explicit event bounds.
    pub fn validate_with_limits(&self, limits: EventLimits) -> Result<(), SampleEventError> {
        limits.validate()?;
        if self.name.len() > limits.max_thread_name_bytes {
            return Err(SampleEventError::TextTooLong {
                field: "thread-name",
                actual: self.name.len(),
                maximum: limits.max_thread_name_bytes,
            });
        }
        if let Some(group) = &self.group
            && group.len() > limits.max_thread_group_bytes
        {
            return Err(SampleEventError::TextTooLong {
                field: "thread-group",
                actual: group.len(),
                maximum: limits.max_thread_group_bytes,
            });
        }
        Ok(())
    }

    /// Returns the thread name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the optional wire thread-name field.
    pub fn name_field(&self) -> Option<&str> {
        self.name_present.then_some(self.name.as_str())
    }

    /// Returns whether the thread-name field was present.
    pub const fn has_name(&self) -> bool {
        self.name_present
    }

    /// Returns the optional thread-group name.
    pub fn group(&self) -> Option<&str> {
        self.group.as_deref()
    }

    /// Returns the optional numeric thread index.
    pub const fn number(&self) -> Option<u64> {
        self.number
    }

    /// Sets the optional thread-group name.
    pub fn set_group(&mut self, value: Option<String>) {
        self.group = value;
    }

    /// Sets a present thread name, including a present empty name.
    pub fn set_name(&mut self, value: impl Into<String>) {
        self.name = value.into();
        self.name_present = true;
    }

    /// Clears the thread-name field while retaining empty convenience access.
    pub fn clear_name(&mut self) {
        self.name.clear();
        self.name_present = false;
    }

    /// Sets the optional numeric thread index.
    pub const fn set_number(&mut self, value: Option<u64>) {
        self.number = value;
    }

    fn try_estimated_bytes(&self) -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_add(self.name.len())?
            .checked_add(self.group.as_ref().map_or(0, String::len))
    }
}

impl From<String> for ThreadIdentity {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for ThreadIdentity {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl fmt::Debug for ThreadIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ThreadIdentity")
            .field("name_present", &self.name_present)
            .field("name_len", &self.name.len())
            .field("group_len", &self.group.as_ref().map(String::len))
            .field("number", &self.number)
            .finish()
    }
}

/// Short alias for [`ThreadIdentity`].
pub type ThreadId = ThreadIdentity;

/// A selected sample variable value at listener-notification time.
#[derive(Clone, Eq, Hash, PartialEq)]
pub enum VariableValue {
    /// The variable was selected but absent in the thread's variable scope.
    Absent,
    /// The variable was present, including a present empty string.
    Present(String),
}

impl VariableValue {
    /// Creates a present variable value.
    pub fn present(value: impl Into<String>) -> Self {
        Self::Present(value.into())
    }

    /// Creates an absent selected-variable value.
    pub const fn absent() -> Self {
        Self::Absent
    }

    /// Returns the present value, if any.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Absent => None,
            Self::Present(value) => Some(value),
        }
    }

    /// Returns whether this is a present empty value.
    pub fn is_present_empty(&self) -> bool {
        matches!(self, Self::Present(value) if value.is_empty())
    }
}

impl fmt::Debug for VariableValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Absent => formatter.write_str("VariableValue::Absent"),
            Self::Present(value) => formatter
                .debug_struct("VariableValue::Present")
                .field("len", &value.len())
                .finish(),
        }
    }
}

impl From<String> for VariableValue {
    fn from(value: String) -> Self {
        Self::Present(value)
    }
}

impl From<&str> for VariableValue {
    fn from(value: &str) -> Self {
        Self::Present(value.to_owned())
    }
}

impl From<Option<String>> for VariableValue {
    fn from(value: Option<String>) -> Self {
        match value {
            Some(value) => Self::Present(value),
            None => Self::Absent,
        }
    }
}

impl From<Option<&str>> for VariableValue {
    fn from(value: Option<&str>) -> Self {
        match value {
            Some(value) => Self::Present(value.to_owned()),
            None => Self::Absent,
        }
    }
}

/// Deterministically ordered selected variables captured in a sample event.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct VariableSnapshot {
    values: BTreeMap<String, VariableValue>,
    /// Listener configuration is an ordered array in JMeter and may contain
    /// duplicate names.  Keep the occurrence sequence alongside the map used
    /// for name lookup and backwards-compatible deterministic iteration.
    ordered: Vec<(String, VariableValue)>,
}

impl VariableSnapshot {
    /// Creates an empty variable snapshot.
    pub const fn new() -> Self {
        Self {
            values: BTreeMap::new(),
            ordered: Vec::new(),
        }
    }

    /// Inserts a selected variable, retaining present-empty versus absent.
    pub fn insert<V>(&mut self, name: impl Into<String>, value: V) -> Option<VariableValue>
    where
        V: Into<VariableValue>,
    {
        let name = name.into();
        let value = value.into();
        let previous = self.values.insert(name.clone(), value.clone());
        if let Some(existing) = self.ordered.iter_mut().rev().find(|(key, _)| key == &name) {
            existing.1 = value;
        } else {
            self.ordered.push((name, value));
        }
        previous
    }

    /// Appends one selected-variable occurrence in listener configuration
    /// order.  Duplicate names are retained; name lookup returns the latest
    /// occurrence, matching JMeter's parallel name/value arrays.
    pub fn insert_occurrence<V>(&mut self, name: impl Into<String>, value: V)
    where
        V: Into<VariableValue>,
    {
        let name = name.into();
        let value = value.into();
        self.values.insert(name.clone(), value.clone());
        self.ordered.push((name, value));
    }

    /// Inserts a selected variable marked absent.
    pub fn insert_absent(&mut self, name: impl Into<String>) -> Option<VariableValue> {
        self.insert(name, VariableValue::Absent)
    }

    /// Returns a selected variable's snapshot value.
    pub fn get(&self, name: &str) -> Option<&VariableValue> {
        self.values.get(name)
    }

    /// Returns whether a variable name was selected, including when its value
    /// is absent.
    pub fn contains(&self, name: &str) -> bool {
        self.values.contains_key(name)
    }

    /// Returns the number of selected variables.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Returns whether no variables were selected.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Iterates variables in deterministic name order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &VariableValue)> {
        self.values
            .iter()
            .map(|(name, value)| (name.as_str(), value))
    }

    /// Iterates selected-variable occurrences in listener configuration order,
    /// including duplicate names.
    pub fn iter_occurrences(&self) -> impl Iterator<Item = (&str, &VariableValue)> {
        self.ordered
            .iter()
            .map(|(name, value)| (name.as_str(), value))
    }

    /// Returns the number of configured variable occurrences.  This can be
    /// greater than [`VariableSnapshot::len`] when duplicate names were
    /// supplied by `sample_variables`.
    pub fn occurrence_len(&self) -> usize {
        self.ordered.len()
    }

    /// Returns the underlying ordered map for read-only inspection.
    pub fn as_map(&self) -> &BTreeMap<String, VariableValue> {
        &self.values
    }

    /// Validates selected-variable count and text bounds without changing the
    /// deterministic name ordering supplied by the snapshot.
    pub fn validate_with_limits(&self, limits: EventLimits) -> Result<(), SampleEventError> {
        limits.validate()?;
        if self.ordered.len() > limits.max_variables {
            return Err(SampleEventError::VariablesLimitExceeded {
                actual: self.ordered.len(),
                maximum: limits.max_variables,
            });
        }
        for (name, value) in &self.ordered {
            if name.len() > limits.max_variable_name_bytes {
                return Err(SampleEventError::TextTooLong {
                    field: "sample-variable-name",
                    actual: name.len(),
                    maximum: limits.max_variable_name_bytes,
                });
            }
            if let VariableValue::Present(value) = value
                && value.len() > limits.max_variable_value_bytes
            {
                return Err(SampleEventError::TextTooLong {
                    field: "sample-variable-value",
                    actual: value.len(),
                    maximum: limits.max_variable_value_bytes,
                });
            }
        }
        Ok(())
    }

    /// Returns a saturating estimate of the bytes held by names and values.
    /// This is used only for a resource admission check.
    pub fn estimated_bytes(&self) -> usize {
        match self.try_estimated_bytes() {
            Some(value) => value,
            None => usize::MAX,
        }
    }

    /// Returns a checked retained-size estimate for admission checks.
    pub fn try_estimated_bytes(&self) -> Option<usize> {
        let map_bytes = self
            .values
            .iter()
            .try_fold(0usize, |total, (name, value)| {
                let value_bytes = value.as_str().map_or(0, str::len);
                total
                    .checked_add(std::mem::size_of::<String>())?
                    .checked_add(std::mem::size_of::<VariableValue>())?
                    .checked_add(name.len())?
                    .checked_add(value_bytes)
            })?;
        let ordered_bytes = self
            .ordered
            .iter()
            .try_fold(0usize, |total, (name, value)| {
                let value_bytes = value.as_str().map_or(0, str::len);
                total
                    .checked_add(std::mem::size_of::<String>())?
                    .checked_add(std::mem::size_of::<VariableValue>())?
                    .checked_add(name.len())?
                    .checked_add(value_bytes)
            })?;
        map_bytes.checked_add(ordered_bytes)
    }
}

impl fmt::Debug for VariableSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VariableSnapshot")
            .field("entries", &self.values.len())
            .field("occurrences", &self.ordered.len())
            .finish()
    }
}

impl From<&VariableSnapshot> for VariableSnapshot {
    fn from(value: &VariableSnapshot) -> Self {
        value.clone()
    }
}

impl FromIterator<(String, Option<String>)> for VariableSnapshot {
    fn from_iter<T: IntoIterator<Item = (String, Option<String>)>>(iter: T) -> Self {
        let mut snapshot = Self::new();
        for (name, value) in iter {
            snapshot.insert(name, value);
        }
        snapshot
    }
}

impl FromIterator<(String, String)> for VariableSnapshot {
    fn from_iter<T: IntoIterator<Item = (String, String)>>(iter: T) -> Self {
        let mut snapshot = Self::new();
        for (name, value) in iter {
            snapshot.insert(name, value);
        }
        snapshot
    }
}

impl From<BTreeMap<String, String>> for VariableSnapshot {
    fn from(value: BTreeMap<String, String>) -> Self {
        value.into_iter().collect()
    }
}

impl From<BTreeMap<String, Option<String>>> for VariableSnapshot {
    fn from(value: BTreeMap<String, Option<String>>) -> Self {
        value.into_iter().collect()
    }
}

impl FromIterator<(String, VariableValue)> for VariableSnapshot {
    fn from_iter<T: IntoIterator<Item = (String, VariableValue)>>(iter: T) -> Self {
        let mut snapshot = Self::new();
        for (name, value) in iter {
            snapshot.insert(name, value);
        }
        snapshot
    }
}

/// Transaction-boundary state captured with a sample event.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TransactionState {
    /// This event starts a transaction.
    Start,
    /// This event ends a transaction.
    End,
}

/// An append-only result notification snapshot.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct SampleEvent {
    result: SampleResult,
    run: RunIdentity,
    thread: ThreadIdentity,
    host: HostIdentity,
    variables: VariableSnapshot,
    transaction_state: Option<TransactionState>,
    /// JMeter's event-level transaction marker.  `None` represents a source
    /// that did not expose the marker; `Some(false)` is an ordinary event.
    transaction_sample_event: Option<bool>,
}

impl fmt::Debug for SampleEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SampleEvent")
            .field("result", &self.result)
            .field("run", &self.run)
            .field("thread", &self.thread)
            .field("host", &self.host)
            .field("variables", &self.variables)
            .field("transaction_state", &self.transaction_state)
            .field("transaction_sample_event", &self.transaction_sample_event)
            .finish()
    }
}

impl SampleEvent {
    /// Creates an event from an owned result without re-validating it.
    ///
    /// Runtime code should normally use [`SampleEvent::try_new`] or
    /// [`SampleEvent::snapshot`] so invalid input is rejected at the boundary.
    pub fn new(
        result: SampleResult,
        run: impl Into<RunIdentity>,
        thread: impl Into<ThreadIdentity>,
        host: impl Into<HostIdentity>,
        variables: impl Into<VariableSnapshot>,
    ) -> Self {
        Self {
            result,
            run: run.into(),
            thread: thread.into(),
            host: host.into(),
            variables: variables.into(),
            transaction_state: None,
            transaction_sample_event: Some(false),
        }
    }

    /// Creates and validates an event from an owned result.
    pub fn try_new(
        result: SampleResult,
        run: impl Into<RunIdentity>,
        thread: impl Into<ThreadIdentity>,
        host: impl Into<HostIdentity>,
        variables: impl Into<VariableSnapshot>,
        limits: impl Into<ValidationLimits>,
    ) -> crate::Result<Self> {
        let limits = limits.into();
        Self::try_new_with_event_limits(
            result,
            run,
            thread,
            host,
            variables,
            limits,
            EventLimits::default(),
        )
        .map_err(SampleEventError::into_result_error)
    }

    /// Creates and validates an event with independent hierarchy and event
    /// resource limits.  This is the preferred constructor at runtime and
    /// sink boundaries because it preserves the typed event-limit error.
    pub fn try_new_with_event_limits(
        result: SampleResult,
        run: impl Into<RunIdentity>,
        thread: impl Into<ThreadIdentity>,
        host: impl Into<HostIdentity>,
        variables: impl Into<VariableSnapshot>,
        result_limits: impl Into<ValidationLimits>,
        event_limits: EventLimits,
    ) -> Result<Self, SampleEventError> {
        let run = run.into();
        let thread = thread.into();
        let host = host.into();
        let variables = variables.into();
        validate_event_parts(EventValidation {
            result: &result,
            run: &run,
            thread: &thread,
            host: &host,
            variables: &variables,
            result_limits: result_limits.into(),
            event_limits,
            wire_timing: false,
        })?;
        Ok(Self {
            result,
            run,
            thread,
            host,
            variables,
            transaction_state: None,
            transaction_sample_event: Some(false),
        })
    }

    /// Clones a result and variable selection at listener-notification time.
    /// Later mutation of either source cannot affect this event.
    pub fn snapshot(
        result: &SampleResult,
        run: impl Into<RunIdentity>,
        thread: impl Into<ThreadIdentity>,
        host: impl Into<HostIdentity>,
        variables: impl Into<VariableSnapshot>,
    ) -> crate::Result<Self> {
        Self::snapshot_with_limits(
            result,
            run,
            thread,
            host,
            variables,
            ValidationLimits::default(),
        )
    }

    /// Snapshot variant with an explicit hierarchy bound.
    pub fn snapshot_with_limits(
        result: &SampleResult,
        run: impl Into<RunIdentity>,
        thread: impl Into<ThreadIdentity>,
        host: impl Into<HostIdentity>,
        variables: impl Into<VariableSnapshot>,
        limits: impl Into<ValidationLimits>,
    ) -> crate::Result<Self> {
        Self::snapshot_with_event_limits(
            result,
            run,
            thread,
            host,
            variables,
            limits,
            EventLimits::default(),
        )
        .map_err(SampleEventError::into_result_error)
    }

    /// Clones a notification-time event and applies both result hierarchy and
    /// complete event resource bounds.
    pub fn snapshot_with_event_limits(
        result: &SampleResult,
        run: impl Into<RunIdentity>,
        thread: impl Into<ThreadIdentity>,
        host: impl Into<HostIdentity>,
        variables: impl Into<VariableSnapshot>,
        result_limits: impl Into<ValidationLimits>,
        event_limits: EventLimits,
    ) -> Result<Self, SampleEventError> {
        let run = run.into();
        let thread = thread.into();
        let host = host.into();
        let variables = variables.into();
        validate_event_parts(EventValidation {
            result,
            run: &run,
            thread: &thread,
            host: &host,
            variables: &variables,
            result_limits: result_limits.into(),
            event_limits,
            wire_timing: false,
        })?;
        Ok(Self {
            result: result.clone(),
            run,
            thread,
            host,
            variables,
            transaction_state: None,
            transaction_sample_event: Some(false),
        })
    }

    /// Returns the immutable result snapshot.
    pub fn result(&self) -> &SampleResult {
        &self.result
    }

    /// Alias for [`SampleEvent::result`].
    pub fn sample_result(&self) -> &SampleResult {
        self.result()
    }

    /// Returns the run identity.
    pub fn run(&self) -> &RunIdentity {
        &self.run
    }

    /// Alias for [`SampleEvent::run`].
    pub fn run_id(&self) -> &RunIdentity {
        self.run()
    }

    /// Returns the thread/group identity.
    pub fn thread(&self) -> &ThreadIdentity {
        &self.thread
    }

    /// Alias for [`SampleEvent::thread`].
    pub fn thread_identity(&self) -> &ThreadIdentity {
        self.thread()
    }

    /// Returns the JTL thread-name field carried by the result, if present.
    /// Event-level identity remains the authoritative listener metadata; this
    /// accessor is a convenience for codecs that must preserve per-node XML.
    pub fn thread_name(&self) -> Option<&str> {
        self.result
            .thread_name()
            .or_else(|| self.thread.name_field())
    }

    /// Returns the host identity.
    pub fn host(&self) -> &HostIdentity {
        &self.host
    }

    /// Alias for [`SampleEvent::host`].
    pub fn host_identity(&self) -> &HostIdentity {
        self.host()
    }

    /// Returns the selected variable snapshot.
    pub fn variables(&self) -> &VariableSnapshot {
        &self.variables
    }

    /// Returns optional transaction-boundary state.
    pub const fn transaction_state(&self) -> Option<TransactionState> {
        self.transaction_state
    }

    /// Returns JMeter's event-level transaction marker.  This is independent
    /// from the optional start/end boundary extension represented by
    /// [`TransactionState`].
    pub const fn is_transaction_sample_event(&self) -> Option<bool> {
        self.transaction_sample_event
    }

    /// Sets the event-level transaction marker.
    pub const fn set_transaction_sample_event(&mut self, value: Option<bool>) {
        self.transaction_sample_event = value;
    }

    /// Returns a new event carrying JMeter's transaction marker.
    pub fn with_transaction_sample_event(mut self, value: Option<bool>) -> Self {
        self.transaction_sample_event = value;
        self
    }

    /// Returns a new event with transaction state attached.
    pub fn with_transaction_state(mut self, state: Option<TransactionState>) -> Self {
        self.transaction_state = state;
        self.transaction_sample_event = Some(state.is_some());
        self
    }

    /// Validates the result hierarchy held by this event.
    pub fn validate(&self, limits: impl Into<ValidationLimits>) -> crate::Result<()> {
        self.result.validate_with_limits(limits)
    }

    /// Validates the complete immutable event snapshot, including selected
    /// variables, identity fields, every result/sub-result field, and its
    /// bounded aggregate size.
    pub fn validate_with_limits(
        &self,
        result_limits: impl Into<ValidationLimits>,
        event_limits: EventLimits,
    ) -> Result<(), SampleEventError> {
        validate_event_parts(EventValidation {
            result: &self.result,
            run: &self.run,
            thread: &self.thread,
            host: &self.host,
            variables: &self.variables,
            result_limits: result_limits.into(),
            event_limits,
            wire_timing: false,
        })
    }

    /// Returns a saturating estimate of the complete owned event snapshot.
    ///
    /// This includes metadata, selected variables, every nested result,
    /// assertion, payload, and retained JTL extension.  It is intentionally
    /// conservative and is suitable for bounded queue accounting.
    pub fn estimated_bytes(&self) -> usize {
        match self.try_estimated_bytes() {
            Ok(value) => value,
            Err(_) => usize::MAX,
        }
    }

    /// Returns a checked retained-size estimate for the complete event.
    /// Overflow is reported explicitly rather than being converted into a
    /// plausible byte count.
    pub fn try_estimated_bytes(&self) -> Result<usize, SampleEventError> {
        try_estimated_event_bytes(
            &self.result,
            &self.run,
            &self.thread,
            &self.host,
            &self.variables,
        )
        .ok_or(SampleEventError::EventSizeOverflow)
    }

    /// Validates a wire-loaded event while retaining independent JTL timing
    /// components that may violate execution-time inequalities.
    pub(crate) fn validate_wire(&self, limits: impl Into<ValidationLimits>) -> crate::Result<()> {
        let limits = limits.into();
        validate_event_parts(EventValidation {
            result: &self.result,
            run: &self.run,
            thread: &self.thread,
            host: &self.host,
            variables: &self.variables,
            result_limits: limits,
            event_limits: EventLimits::default(),
            wire_timing: true,
        })
        .map_err(SampleEventError::into_result_error)
    }

    /// Retains root-level XML extensions discovered after this event's sample.
    pub(crate) fn add_wire_xml_root_children_after(
        &mut self,
        children: impl IntoIterator<Item = crate::result::XmlOpaqueChild>,
    ) {
        self.result.add_wire_xml_root_children_after(children);
    }

    /// Consumes the event and returns its result snapshot.
    pub fn into_result(self) -> SampleResult {
        self.result
    }
}

struct EventValidation<'a> {
    result: &'a SampleResult,
    run: &'a RunIdentity,
    thread: &'a ThreadIdentity,
    host: &'a HostIdentity,
    variables: &'a VariableSnapshot,
    result_limits: ValidationLimits,
    event_limits: EventLimits,
    wire_timing: bool,
}

fn validate_event_parts(parts: EventValidation<'_>) -> Result<(), SampleEventError> {
    parts.event_limits.validate()?;
    if parts.wire_timing {
        parts
            .result
            .validate_wire_with_limits(parts.result_limits)?;
    } else {
        parts.result.validate_with_limits(parts.result_limits)?;
    }
    parts
        .run
        .validate_with_limit(parts.event_limits.max_identity_bytes)?;
    parts
        .host
        .validate_with_limit(parts.event_limits.max_identity_bytes)?;
    parts.thread.validate_with_limits(parts.event_limits)?;
    parts.variables.validate_with_limits(parts.event_limits)?;
    validate_result_payload(parts.result, parts.event_limits)?;
    let bytes = try_estimated_event_bytes(
        parts.result,
        parts.run,
        parts.thread,
        parts.host,
        parts.variables,
    )
    .ok_or(SampleEventError::EventSizeOverflow)?;
    if bytes > parts.event_limits.max_event_bytes {
        return Err(SampleEventError::EventSizeLimitExceeded {
            actual: bytes,
            maximum: parts.event_limits.max_event_bytes,
        });
    }
    Ok(())
}

fn try_estimated_event_bytes(
    result: &SampleResult,
    run: &RunIdentity,
    thread: &ThreadIdentity,
    host: &HostIdentity,
    variables: &VariableSnapshot,
) -> Option<usize> {
    std::mem::size_of::<SampleEvent>()
        .checked_add(run.as_str().len())?
        .checked_add(host.as_str().len())?
        .checked_add(thread.try_estimated_bytes()?)?
        .checked_add(variables.try_estimated_bytes()?)?
        .checked_add(try_estimated_result_bytes(result)?)
}

fn validate_result_payload(
    root: &SampleResult,
    limits: EventLimits,
) -> Result<(), SampleEventError> {
    let mut pending = vec![root];
    while let Some(result) = pending.pop() {
        validate_text_field(result.label_field(), "label", limits.max_result_text_bytes)?;
        validate_text_field(
            result.response_code(),
            "response-code",
            limits.max_result_text_bytes,
        )?;
        validate_text_field(
            result.response_message(),
            "response-message",
            limits.max_result_text_bytes,
        )?;
        validate_text_field(
            result.failure_message(),
            "failure-message",
            limits.max_result_text_bytes,
        )?;
        if let Some(value) = result.data_type() {
            validate_text(value.as_wire(), "data-type", limits.max_result_text_bytes)?;
        }
        if let Some(value) = result.data_encoding() {
            validate_text(
                value.as_str(),
                "data-encoding",
                limits.max_result_text_bytes,
            )?;
        }
        validate_text_field(
            result.content_type(),
            "content-type",
            limits.max_result_text_bytes,
        )?;
        validate_data_field(
            result.request_data(),
            "request-data",
            limits.max_result_data_bytes,
        )?;
        validate_data_field(
            result.response_data(),
            "response-data",
            limits.max_result_data_bytes,
        )?;
        validate_text_field(
            result.request_headers().map(crate::HeaderBlock::as_str),
            "request-headers",
            limits.max_result_text_bytes,
        )?;
        validate_text_field(
            result.response_headers().map(crate::HeaderBlock::as_str),
            "response-headers",
            limits.max_result_text_bytes,
        )?;
        validate_text_field(
            result.sampler_data(),
            "sampler-data",
            limits.max_result_text_bytes,
        )?;
        validate_text_field(
            result.response_file(),
            "response-file",
            limits.max_result_text_bytes,
        )?;
        validate_text_field(result.url(), "url", limits.max_result_text_bytes)?;
        validate_text_field(
            result.wire_thread_name(),
            "wire-thread-name",
            limits.max_thread_name_bytes,
        )?;
        validate_text_field(result.wire_host(), "wire-host", limits.max_identity_bytes)?;
        result.wire_variables().validate_with_limits(limits)?;

        for assertion in result.assertions() {
            validate_text(
                assertion.name(),
                "assertion-name",
                limits.max_result_text_bytes,
            )?;
            validate_text_field(
                assertion.failure_message(),
                "assertion-failure-message",
                limits.max_result_text_bytes,
            )?;
            validate_text_field(
                assertion.error_message(),
                "assertion-error-message",
                limits.max_result_text_bytes,
            )?;
            validate_opaque_attributes(assertion.wire_xml_attributes(), limits)?;
            for child in assertion.wire_xml_children() {
                validate_opaque_child(child, limits)?;
            }
        }
        validate_opaque_attributes(result.wire_xml_attributes(), limits)?;
        validate_opaque_attributes(result.wire_xml_root_attributes(), limits)?;
        for child in result
            .wire_xml_children()
            .iter()
            .chain(result.wire_xml_root_children())
            .chain(result.wire_xml_root_children_after())
        {
            validate_opaque_child(child, limits)?;
        }
        pending.extend(result.sub_results());
    }
    Ok(())
}

fn validate_text_field(
    value: Option<&str>,
    field: &'static str,
    maximum: usize,
) -> Result<(), SampleEventError> {
    if let Some(value) = value {
        validate_text(value, field, maximum)?;
    }
    Ok(())
}

fn validate_text(value: &str, field: &'static str, maximum: usize) -> Result<(), SampleEventError> {
    if value.len() > maximum {
        return Err(SampleEventError::TextTooLong {
            field,
            actual: value.len(),
            maximum,
        });
    }
    Ok(())
}

fn validate_data_field(
    value: Option<&crate::SampleData>,
    field: &'static str,
    maximum: usize,
) -> Result<(), SampleEventError> {
    if let Some(value) = value
        && value.len() > maximum
    {
        return Err(SampleEventError::DataTooLong {
            field,
            actual: value.len(),
            maximum,
        });
    }
    Ok(())
}

fn validate_opaque_attributes(
    attributes: &[(String, String)],
    limits: EventLimits,
) -> Result<(), SampleEventError> {
    for (name, value) in attributes {
        validate_text(name, "xml-extension-name", limits.max_result_text_bytes)?;
        validate_text(value, "xml-extension-value", limits.max_result_text_bytes)?;
    }
    Ok(())
}

fn validate_opaque_child(
    root: &crate::result::XmlOpaqueChild,
    limits: EventLimits,
) -> Result<(), SampleEventError> {
    let mut pending = vec![root];
    while let Some(child) = pending.pop() {
        validate_text(
            &child.name,
            "xml-extension-name",
            limits.max_result_text_bytes,
        )?;
        validate_opaque_attributes(&child.attributes, limits)?;
        for part in &child.content {
            match part {
                crate::result::XmlOpaquePart::Text(value) => {
                    validate_text(value, "xml-extension-text", limits.max_result_text_bytes)?;
                }
                crate::result::XmlOpaquePart::Child(child) => pending.push(child),
            }
        }
    }
    Ok(())
}

fn try_estimated_result_bytes(root: &SampleResult) -> Option<usize> {
    let mut bytes = 0usize;
    let mut pending = vec![root];
    while let Some(result) = pending.pop() {
        add_estimate(&mut bytes, std::mem::size_of::<SampleResult>())?;
        add_estimate(&mut bytes, result.label_field().map_or(0, str::len))?;
        add_estimate(&mut bytes, result.response_code().map_or(0, str::len))?;
        add_estimate(&mut bytes, result.response_message().map_or(0, str::len))?;
        add_estimate(&mut bytes, result.failure_message().map_or(0, str::len))?;
        add_estimate(
            &mut bytes,
            result.data_type().map_or(0, |value| value.as_wire().len()),
        )?;
        add_estimate(
            &mut bytes,
            result
                .data_encoding()
                .map_or(0, |value| value.as_str().len()),
        )?;
        add_estimate(&mut bytes, result.content_type().map_or(0, str::len))?;
        add_estimate(
            &mut bytes,
            result.request_data().map_or(0, crate::SampleData::len),
        )?;
        add_estimate(
            &mut bytes,
            result.response_data().map_or(0, crate::SampleData::len),
        )?;
        add_estimate(
            &mut bytes,
            result
                .request_headers()
                .map_or(0, |value| value.as_str().len()),
        )?;
        add_estimate(
            &mut bytes,
            result
                .response_headers()
                .map_or(0, |value| value.as_str().len()),
        )?;
        add_estimate(&mut bytes, result.sampler_data().map_or(0, str::len))?;
        add_estimate(&mut bytes, result.response_file().map_or(0, str::len))?;
        add_estimate(&mut bytes, result.url().map_or(0, str::len))?;
        add_estimate(&mut bytes, result.wire_thread_name().map_or(0, str::len))?;
        add_estimate(&mut bytes, result.wire_host().map_or(0, str::len))?;
        add_estimate(&mut bytes, result.wire_variables().try_estimated_bytes()?)?;
        for assertion in result.assertions() {
            add_estimate(&mut bytes, std::mem::size_of::<crate::AssertionResult>())?;
            add_estimate(&mut bytes, assertion.name().len())?;
            add_estimate(&mut bytes, assertion.failure_message().map_or(0, str::len))?;
            add_estimate(&mut bytes, assertion.error_message().map_or(0, str::len))?;
            add_estimate(
                &mut bytes,
                try_estimated_attributes_bytes(assertion.wire_xml_attributes())?,
            )?;
            add_estimate(
                &mut bytes,
                try_estimated_children_bytes(assertion.wire_xml_children())?,
            )?;
        }
        add_estimate(
            &mut bytes,
            try_estimated_attributes_bytes(result.wire_xml_attributes())?,
        )?;
        add_estimate(
            &mut bytes,
            try_estimated_attributes_bytes(result.wire_xml_root_attributes())?,
        )?;
        add_estimate(
            &mut bytes,
            try_estimated_children_bytes(result.wire_xml_children())?,
        )?;
        add_estimate(
            &mut bytes,
            try_estimated_children_bytes(result.wire_xml_root_children())?,
        )?;
        add_estimate(
            &mut bytes,
            try_estimated_children_bytes(result.wire_xml_root_children_after())?,
        )?;
        pending.extend(result.sub_results());
    }
    Some(bytes)
}

fn add_estimate(total: &mut usize, value: usize) -> Option<()> {
    *total = total.checked_add(value)?;
    Some(())
}

fn try_estimated_attributes_bytes(attributes: &[(String, String)]) -> Option<usize> {
    attributes.iter().try_fold(0usize, |total, (name, value)| {
        total
            .checked_add(std::mem::size_of::<(String, String)>())?
            .checked_add(name.len())?
            .checked_add(value.len())
    })
}

fn try_estimated_children_bytes(children: &[crate::result::XmlOpaqueChild]) -> Option<usize> {
    let mut bytes = 0usize;
    let mut pending: Vec<&crate::result::XmlOpaqueChild> = children.iter().collect();
    while let Some(child) = pending.pop() {
        add_estimate(
            &mut bytes,
            std::mem::size_of::<crate::result::XmlOpaqueChild>(),
        )?;
        add_estimate(&mut bytes, child.name.len())?;
        add_estimate(
            &mut bytes,
            try_estimated_attributes_bytes(&child.attributes)?,
        )?;
        for part in &child.content {
            add_estimate(
                &mut bytes,
                std::mem::size_of::<crate::result::XmlOpaquePart>(),
            )?;
            if let crate::result::XmlOpaquePart::Text(value) = part {
                add_estimate(&mut bytes, value.len())?;
            } else if let crate::result::XmlOpaquePart::Child(child) = part {
                pending.push(child);
            }
        }
    }
    Some(bytes)
}

// Test fixtures use `expect` at setup/assertion boundaries so failures retain
// the operation name; production event paths remain explicitly fallible.
#[allow(clippy::expect_used)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AssertionResult, ElapsedTime, SampleData, SampleResult};

    #[test]
    fn snapshot_copies_nested_result_and_event_metadata() {
        let mut result = SampleResult::new("parent");
        result.set_response_code(Some("200".to_owned()));
        result.set_response_data(Some(SampleData::from(vec![1, 2, 3])));
        result.set_response_headers_text("x-test: before");
        result
            .add_assertion(AssertionResult::failed(
                "assertion",
                Some("before".to_owned()),
            ))
            .expect("test assertion is valid");
        let mut child = SampleResult::new("child");
        child.set_response_message(Some("nested before".to_owned()));
        result
            .add_sub_result(child, ValidationLimits::default())
            .expect("test child is within hierarchy limits");

        let run = RunIdentity::new("run-before");
        let host = HostIdentity::new("host-before");
        let thread =
            ThreadIdentity::with_group("thread-before", Some("group-before".to_owned()), Some(3));
        let mut variables = VariableSnapshot::new();
        variables.insert("selected", "before");

        let event = SampleEvent::snapshot(
            &result,
            run.clone(),
            thread.clone(),
            host.clone(),
            variables.clone(),
        )
        .expect("snapshot should be valid");

        result.set_label("parent-after");
        result.set_response_code(Some("500".to_owned()));
        result.set_response_data(Some(SampleData::from(vec![9, 9, 9])));
        result.set_response_headers_text("x-test: after");

        let mut changed_thread = thread;
        changed_thread.set_group(Some("group-after".to_owned()));
        changed_thread.set_number(Some(9));
        variables.insert("selected", "after");

        assert_eq!(event.result().label(), "parent");
        assert_eq!(event.result().response_code(), Some("200"));
        assert_eq!(
            event.result().response_data().map(SampleData::as_bytes),
            Some([1, 2, 3].as_slice())
        );
        assert_eq!(
            event.result().assertions()[0].failure_message(),
            Some("before")
        );
        assert_eq!(
            event.result().sub_results()[0].response_message(),
            Some("nested before")
        );
        assert_eq!(event.thread().group(), Some("group-before"));
        assert_eq!(event.thread().number(), Some(3));
        assert_eq!(
            event
                .variables()
                .get("selected")
                .and_then(VariableValue::as_str),
            Some("before")
        );
        assert_eq!(event.run().as_str(), run.as_str());
        assert_eq!(event.host().as_str(), host.as_str());
    }

    #[test]
    fn selected_variables_preserve_order_and_absence() {
        let mut variables = VariableSnapshot::new();
        variables.insert_absent("missing");
        variables.insert("z", "");
        variables.insert("a", "value");

        let names: Vec<_> = variables.iter().map(|(name, _)| name).collect();
        assert_eq!(names, ["a", "missing", "z"]);
        assert!(matches!(
            variables.get("missing"),
            Some(VariableValue::Absent)
        ));
        assert!(
            variables
                .get("z")
                .is_some_and(VariableValue::is_present_empty)
        );
    }

    #[test]
    fn event_limits_reject_selected_variable_and_payload_overflow() {
        let mut variables = VariableSnapshot::new();
        variables.insert("too-large", "12345");
        let limits = EventLimits {
            max_variable_value_bytes: 4,
            ..EventLimits::default()
        };
        let variable_error = SampleEvent::snapshot_with_event_limits(
            &SampleResult::new("sample"),
            "run",
            "thread",
            "host",
            variables,
            ValidationLimits::default(),
            limits,
        )
        .expect_err("oversized selected variable must be rejected");
        assert!(matches!(
            variable_error,
            SampleEventError::TextTooLong {
                field: "sample-variable-value",
                ..
            }
        ));

        let mut result = SampleResult::new("sample");
        result.set_response_data(Some(SampleData::from(vec![1, 2, 3, 4, 5])));
        let limits = EventLimits {
            max_result_data_bytes: 4,
            ..EventLimits::default()
        };
        let data_error = SampleEvent::snapshot_with_event_limits(
            &result,
            "run",
            "thread",
            "host",
            VariableSnapshot::new(),
            ValidationLimits::default(),
            limits,
        )
        .expect_err("oversized response data must be rejected");
        assert!(matches!(
            data_error,
            SampleEventError::DataTooLong {
                field: "response-data",
                ..
            }
        ));
    }

    #[test]
    fn event_limits_reject_aggregate_snapshot_size() {
        let mut result = SampleResult::new("sample");
        result.set_response_data(Some(SampleData::from(vec![1; 256])));
        let limits = EventLimits {
            max_event_bytes: 128,
            ..EventLimits::default()
        };
        let error = SampleEvent::snapshot_with_event_limits(
            &result,
            "run",
            "thread",
            "host",
            VariableSnapshot::new(),
            ValidationLimits::default(),
            limits,
        )
        .expect_err("aggregate event size must be bounded");
        assert!(matches!(
            error,
            SampleEventError::EventSizeLimitExceeded { .. }
        ));
    }

    #[test]
    fn wire_validation_does_not_apply_execution_timing_inequalities() {
        let wire_timing = crate::SampleTiming::from_wire_parts(
            None,
            None,
            None,
            Some(ElapsedTime::from_millis(1)),
            Some(crate::Latency::from_millis(2)),
            None,
            None,
        );
        let mut result = SampleResult::new("wire");
        result.set_timing_from_wire(wire_timing);
        let event = SampleEvent::new(
            result,
            "run",
            ThreadIdentity::new("thread"),
            "host",
            VariableSnapshot::new(),
        );
        assert!(event.validate_wire(ValidationLimits::default()).is_ok());
    }

    #[test]
    fn strict_identity_constructors_reject_empty_and_oversized_values() {
        assert!(matches!(
            RunIdentity::try_new(""),
            Err(SampleEventError::IdentityTooLong { actual: 0, .. })
        ));
        assert!(matches!(
            HostIdentity::try_new(""),
            Err(SampleEventError::IdentityTooLong { actual: 0, .. })
        ));
        assert!(matches!(
            RunIdentity::try_new("x".repeat(MAX_EVENT_IDENTITY_BYTES + 1)),
            Err(SampleEventError::IdentityTooLong { .. })
        ));
    }

    #[test]
    fn variable_occurrences_preserve_configuration_order_and_duplicates() {
        let mut variables = VariableSnapshot::new();
        variables.insert_occurrence("first", "one");
        variables.insert_occurrence("first", "two");
        variables.insert_occurrence("empty", "");
        variables.insert_occurrence("missing", VariableValue::Absent);

        let occurrences: Vec<_> = variables
            .iter_occurrences()
            .map(|(name, value)| (name, value.as_str()))
            .collect();
        assert_eq!(
            occurrences,
            [
                ("first", Some("one")),
                ("first", Some("two")),
                ("empty", Some("")),
                ("missing", None),
            ]
        );
        assert_eq!(variables.occurrence_len(), 4);
        assert_eq!(variables.len(), 3);
        assert_eq!(
            variables.get("first").and_then(VariableValue::as_str),
            Some("two")
        );
    }

    #[test]
    fn transaction_marker_keeps_ordinary_false_distinct_from_unknown() {
        let mut event = SampleEvent::new(
            SampleResult::new("sample"),
            "run",
            "thread",
            "host",
            VariableSnapshot::new(),
        );
        assert_eq!(event.is_transaction_sample_event(), Some(false));
        event.set_transaction_sample_event(None);
        assert_eq!(event.is_transaction_sample_event(), None);
        let transaction = event.with_transaction_state(Some(TransactionState::End));
        assert_eq!(transaction.transaction_state(), Some(TransactionState::End));
        assert_eq!(transaction.is_transaction_sample_event(), Some(true));
    }

    #[test]
    fn identity_presence_preserves_absent_and_present_empty() {
        let absent_run = RunIdentity::absent();
        let empty_run = RunIdentity::new("");
        assert!(!absent_run.is_present());
        assert!(empty_run.is_present());
        assert_eq!(absent_run.as_str(), empty_run.as_str());

        let absent_thread = ThreadIdentity::without_name();
        let empty_thread = ThreadIdentity::new("");
        assert!(!absent_thread.has_name());
        assert!(empty_thread.has_name());
        assert_eq!(absent_thread.name_field(), None);
        assert_eq!(empty_thread.name_field(), Some(""));

        let absent_host = HostIdentity::absent();
        let empty_host = HostIdentity::new("");
        assert!(!absent_host.is_present());
        assert!(empty_host.is_present());
    }
}
