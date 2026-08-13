// SPDX-License-Identifier: Apache-2.0
//! Immutable sample-event snapshots and identity values.

use std::collections::BTreeMap;
use std::fmt;

use crate::{SampleResult, ValidationLimits};

/// Run identity captured with a result event.
#[derive(Clone, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RunIdentity(String);

impl RunIdentity {
    /// Creates a run identity. Empty values are retained for wire fidelity.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the run identity text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the identity and returns its text.
    pub fn into_string(self) -> String {
        self.0
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
            .field("len", &self.0.len())
            .finish()
    }
}

/// Short alias for [`RunIdentity`].
pub type RunId = RunIdentity;

/// Host identity captured with a result event.
#[derive(Clone, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HostIdentity(String);

impl HostIdentity {
    /// Creates a host identity. Empty values are retained for wire fidelity.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the host identity text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the identity and returns its text.
    pub fn into_string(self) -> String {
        self.0
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
            .field("len", &self.0.len())
            .finish()
    }
}

/// Short alias for [`HostIdentity`].
pub type HostId = HostIdentity;

/// Thread and optional thread-group identity captured with an event.
#[derive(Clone, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ThreadIdentity {
    name: String,
    group: Option<String>,
    number: Option<u64>,
}

impl ThreadIdentity {
    /// Creates a thread identity with no group or numeric index.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            group: None,
            number: None,
        }
    }

    /// Creates a thread identity with an optional group and number.
    pub fn with_group(name: impl Into<String>, group: Option<String>, number: Option<u64>) -> Self {
        Self {
            name: name.into(),
            group,
            number,
        }
    }

    /// Returns the thread name.
    pub fn name(&self) -> &str {
        &self.name
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

    /// Sets the optional numeric thread index.
    pub const fn set_number(&mut self, value: Option<u64>) {
        self.number = value;
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
}

impl VariableSnapshot {
    /// Creates an empty variable snapshot.
    pub const fn new() -> Self {
        Self {
            values: BTreeMap::new(),
        }
    }

    /// Inserts a selected variable, retaining present-empty versus absent.
    pub fn insert<V>(&mut self, name: impl Into<String>, value: V) -> Option<VariableValue>
    where
        V: Into<VariableValue>,
    {
        self.values.insert(name.into(), value.into())
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

    /// Returns the underlying ordered map for read-only inspection.
    pub fn as_map(&self) -> &BTreeMap<String, VariableValue> {
        &self.values
    }
}

impl fmt::Debug for VariableSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VariableSnapshot")
            .field("entries", &self.values.len())
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
        let variables = variables.into();
        result.validate_with_limits(limits)?;
        Ok(Self::new(result, run, thread, host, variables))
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
        let variables = variables.into();
        let limits = limits.into();
        result.validate_with_limits(limits)?;
        Ok(Self::new(result.clone(), run, thread, host, variables))
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

    /// Returns a new event with transaction state attached.
    pub fn with_transaction_state(mut self, state: Option<TransactionState>) -> Self {
        self.transaction_state = state;
        self
    }

    /// Validates the result hierarchy held by this event.
    pub fn validate(&self, limits: impl Into<ValidationLimits>) -> crate::Result<()> {
        self.result.validate_with_limits(limits)
    }

    /// Validates a wire-loaded event while retaining independent JTL timing
    /// components that may violate execution-time inequalities.
    pub(crate) fn validate_wire(&self, limits: impl Into<ValidationLimits>) -> crate::Result<()> {
        self.result.validate_wire_with_limits(limits)
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
