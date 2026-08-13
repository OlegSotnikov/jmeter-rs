// SPDX-License-Identifier: Apache-2.0
//! Versioned, bounded Rust-native remote messages.
//!
//! This is deliberately a separate protocol from Java RMI. It only defines
//! data and an in-memory codec; transports, process supervision, and sockets
//! belong to adapters outside this crate.

use std::{collections::BTreeMap, fmt};

use jmeter_rs_results::{
    AssertionResult, DataEncoding, DataType, ElapsedTime, HeaderBlock, LogicalAction, SampleData,
    SampleEvent, SampleResult, SampleTiming, ThreadIdentity, TransactionState, ValidationLimits,
    VariableSnapshot, WallTimestamp,
};

use crate::error::{
    MAX_WIRE_FAILURE_MESSAGE_BYTES, ProtocolError, RemoteError, sanitize_wire_failure_message,
};

/// Four-byte marker for the Rust-native remote protocol.
pub const REMOTE_MAGIC: [u8; 4] = *b"JMRP";
/// Version of the remote message layout.
///
/// Version two adds generation identity to failure messages and an exclusive
/// sample watermark to stop acknowledgements.  A peer must reject older
/// layouts rather than guessing whether a terminal frame was complete.
pub const REMOTE_PROTOCOL_VERSION: u16 = 2;
/// Fixed header length in bytes.
pub const REMOTE_HEADER_LEN: usize = 20;
/// Conservative default message limit, including the header.
pub const DEFAULT_MAX_MESSAGE_BYTES: usize = 1024 * 1024;
/// Maximum supported protocol version by this implementation.
pub const MAX_REMOTE_PROTOCOL_VERSION: u16 = REMOTE_PROTOCOL_VERSION;
/// Stable capability identifier returned when a result contains JTL metadata
/// that this protocol version cannot represent without loss.
pub const RESULT_WIRE_METADATA_CAPABILITY: &str = "remote.result-wire-metadata";

// Control request IDs occupy the lower 63 bits. Worker sample envelopes use
// the high-bit namespace and encode worker identity plus a worker-local
// monotonic ordinal, so a sample envelope can never alias a control request
// or another worker's sample envelope.
pub(crate) const SAMPLE_ENVELOPE_NAMESPACE: u64 = 1 << 63;
pub(crate) const SAMPLE_ENVELOPE_ORDINAL_MASK: u64 = (1 << 31) - 1;

/// A logical run-generation identifier shared by all workers.
///
/// Coordinators and workers consume a generation at most once; callers must
/// allocate a fresh value for a later run, even after an immediate stop.
pub type RunId = u64;
/// An identifier for a request/envelope.
pub type RequestId = u64;

/// An absolute Unix-millisecond deadline supplied by the transport adapter.
///
/// The pure remote core does not read a clock.  Callers pass the current value
/// to [`RemoteRequestContext::check`] (or one of the `*_with_context` state
/// methods) so deadline behavior remains deterministic and executor-neutral.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct RemoteDeadline(Option<u64>);

impl RemoteDeadline {
    /// No deadline is attached to the request.
    pub const NONE: Self = Self(None);

    /// Creates an absolute Unix-millisecond deadline. Zero means no deadline.
    pub const fn at_unix_millis(timestamp: u64) -> Self {
        if timestamp == 0 {
            Self::NONE
        } else {
            Self(Some(timestamp))
        }
    }

    /// Returns the absolute timestamp, if present.
    pub const fn as_unix_millis(self) -> Option<u64> {
        self.0
    }

    /// Returns whether the deadline has elapsed at the supplied time.
    pub const fn is_expired_at(self, now_unix_millis: u64) -> bool {
        match self.0 {
            Some(deadline) => now_unix_millis >= deadline,
            None => false,
        }
    }
}

/// Cancellation state supplied by a transport/runtime adapter.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum RemoteCancellation {
    /// No cancellation signal is active.
    #[default]
    None,
    /// The operation should stop before applying work.
    Requested,
    /// The operation was already cancelled by its owner.
    Cancelled,
}

impl RemoteCancellation {
    /// Returns whether either cancellation state is active.
    pub const fn is_active(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// Typed deadline/cancellation policy at the pure-core boundary.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct RemoteRequestContext {
    deadline: RemoteDeadline,
    cancellation: RemoteCancellation,
}

impl RemoteRequestContext {
    /// Creates a context with no deadline or cancellation.
    pub const fn new() -> Self {
        Self {
            deadline: RemoteDeadline::NONE,
            cancellation: RemoteCancellation::None,
        }
    }

    /// Attaches an absolute deadline.
    pub const fn with_deadline(mut self, deadline: RemoteDeadline) -> Self {
        self.deadline = deadline;
        self
    }

    /// Attaches a cancellation state.
    pub const fn with_cancellation(mut self, cancellation: RemoteCancellation) -> Self {
        self.cancellation = cancellation;
        self
    }

    /// Returns the configured deadline.
    pub const fn deadline(self) -> RemoteDeadline {
        self.deadline
    }

    /// Returns the configured cancellation state.
    pub const fn cancellation(self) -> RemoteCancellation {
        self.cancellation
    }

    /// Requires an adapter-supplied context. Wire envelopes do not carry
    /// deadline or cancellation fields, so a transport must keep this value
    /// alongside the wire bytes and pass it to the state-machine boundary.
    pub fn require(context: Option<Self>) -> Result<Self, RemoteError> {
        context.ok_or_else(|| {
            RemoteError::new(
                crate::RemoteErrorCode::ContextUnavailable,
                false,
                "remote transport context is required for versioned wire messages",
            )
        })
    }

    /// Checks the policy without reading a clock or mutating state.
    pub fn check(self, now_unix_millis: u64) -> Result<(), RemoteError> {
        if self.cancellation.is_active() {
            return Err(RemoteError::new(
                crate::RemoteErrorCode::Cancelled,
                false,
                "remote operation was cancelled before application",
            ));
        }
        if self.deadline.is_expired_at(now_unix_millis) {
            return Err(RemoteError::new(
                crate::RemoteErrorCode::DeadlineExceeded,
                false,
                "remote operation deadline elapsed before application",
            ));
        }
        Ok(())
    }
}

/// Short aliases used by transport adapters.
pub type Deadline = RemoteDeadline;
/// Short aliases used by transport adapters.
pub type Cancellation = RemoteCancellation;

/// Default bound for one UTF-8 or byte field in a remote message.
pub const DEFAULT_MAX_FIELD_BYTES: usize = 64 * 1024;
const DEFAULT_MAX_PLAN_BYTES: usize = 512 * 1024;
const DEFAULT_MAX_PROPERTIES: usize = 4096;
const DEFAULT_MAX_REFERENCES: usize = 1024;
const DEFAULT_MAX_CAPABILITIES: usize = 256;
const DEFAULT_MAX_SAMPLE_DEPTH: usize = 64;
const DEFAULT_MAX_SAMPLE_NODES: usize = 16_384;
const DEFAULT_MAX_SAMPLES: usize = 100_000;
const DEFAULT_MAX_WORKERS: usize = 64;
// Fail-fast control messages are bounded independently from worker selection.
// The default allows one stop event per selected worker; adapters may choose a
// smaller bound when their control queue has a tighter budget.
const DEFAULT_MAX_CONTROL_EVENTS: usize = DEFAULT_MAX_WORKERS;
const DEFAULT_MAX_PLAN_REFERENCES: usize = DEFAULT_MAX_REFERENCES.saturating_mul(2);
const DEFAULT_MAX_PLAN_REFERENCE_BYTES: usize = 512 * 1024;
const DEFAULT_MAX_PROPERTY_BYTES: usize = 512 * 1024;
const DEFAULT_MAX_RESOURCE_ENTRIES: usize = 4_096;
const DEFAULT_MAX_RESOURCE_BYTES: usize = 512 * 1024;
const DEFAULT_MAX_CONFIGURATION_BYTES: usize = 2 * 1024 * 1024;

/// A stable numeric worker identity.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WorkerId(u32);

impl WorkerId {
    /// Creates an identity. Zero is valid and useful for deterministic tests.
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the numeric identity.
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

/// Builds a globally unique sample-envelope request ID from a worker and its
/// worker-local monotonic ordinal. Control request IDs are restricted to the
/// lower 63-bit namespace by the coordinator.
pub fn sample_envelope_request_id(
    worker: WorkerId,
    ordinal: u64,
) -> Result<RequestId, RemoteError> {
    if ordinal == 0 || ordinal > SAMPLE_ENVELOPE_ORDINAL_MASK {
        return Err(RemoteError::new(
            crate::RemoteErrorCode::ResourceLimit,
            false,
            "worker sample-envelope ID space exhausted",
        ));
    }
    Ok(SAMPLE_ENVELOPE_NAMESPACE | (u64::from(worker.as_u32()) << 31) | ordinal)
}

/// Returns whether a request ID belongs to the sample-envelope namespace.
pub const fn is_sample_envelope_request_id(request_id: RequestId) -> bool {
    request_id & SAMPLE_ENVELOPE_NAMESPACE != 0 && request_id & SAMPLE_ENVELOPE_ORDINAL_MASK != 0
}

pub(crate) const fn uses_sample_envelope_namespace(request_id: RequestId) -> bool {
    request_id & SAMPLE_ENVELOPE_NAMESPACE != 0
}

/// Extracts the worker identity encoded in a valid sample-envelope ID.
pub const fn sample_envelope_worker(request_id: RequestId) -> Option<WorkerId> {
    if !is_sample_envelope_request_id(request_id) {
        None
    } else {
        Some(WorkerId::new(
            ((request_id & !SAMPLE_ENVELOPE_NAMESPACE) >> 31) as u32,
        ))
    }
}

impl From<u32> for WorkerId {
    fn from(value: u32) -> Self {
        Self::new(value)
    }
}

/// A compatibility profile advertised by both sides of a Rust-native session.
#[derive(Clone, Eq, PartialEq)]
pub struct ProfileDescriptor {
    id: String,
    version: String,
    capabilities: Vec<String>,
}

impl fmt::Debug for ProfileDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProfileDescriptor")
            .field("id_len", &self.id.len())
            .field("version_len", &self.version.len())
            .field("capability_count", &self.capabilities.len())
            .finish()
    }
}

impl ProfileDescriptor {
    /// Creates a profile descriptor with no extra capabilities.
    pub fn new(id: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            version: version.into(),
            capabilities: Vec::new(),
        }
    }

    /// Adds a capability while retaining insertion order.
    pub fn with_capabilities(mut self, capabilities: Vec<String>) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// Returns the profile identifier.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the profile version.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Returns advertised capabilities in wire order.
    pub fn capabilities(&self) -> &[String] {
        &self.capabilities
    }

    /// Validates profile metadata before a coordinator or worker retains it.
    /// This mirrors the codec checks so an in-memory adapter cannot bypass
    /// field/count bounds by constructing a profile directly.
    pub fn validate_with_limits(&self, limits: RemoteLimits) -> Result<(), RemoteError> {
        limits.validate()?;
        if self.id.len() > limits.max_field_bytes() || self.version.len() > limits.max_field_bytes()
        {
            return Err(RemoteError::new(
                crate::RemoteErrorCode::ResourceLimit,
                false,
                "remote profile identifier exceeds its field bound",
            ));
        }
        if self.capabilities.len() > limits.max_capabilities {
            return Err(RemoteError::new(
                crate::RemoteErrorCode::ResourceLimit,
                false,
                "remote profile capability count exceeded its bound",
            ));
        }
        for capability in &self.capabilities {
            if capability.len() > limits.max_field_bytes() {
                return Err(RemoteError::new(
                    crate::RemoteErrorCode::ResourceLimit,
                    false,
                    "remote profile capability exceeds its field bound",
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn supports(&self, requested: &Self) -> bool {
        self.id == requested.id
            && self.version == requested.version
            && requested
                .capabilities
                .iter()
                .all(|capability| self.capabilities.iter().any(|item| item == capability))
    }
}

/// Compatibility alias for callers that use the shorter profile name.
pub type Profile = ProfileDescriptor;

/// A data file reference deliberately sent without file contents.
#[derive(Clone, Eq, PartialEq)]
pub struct DataReference {
    path: String,
    kind: String,
}

impl fmt::Debug for DataReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DataReference")
            .field("path_len", &self.path.len())
            .field("kind_len", &self.kind.len())
            .finish()
    }
}

impl DataReference {
    /// Creates a worker-local data reference.
    pub fn new(path: impl Into<String>, kind: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            kind: kind.into(),
        }
    }

    /// Returns the worker-local path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the semantic reference kind (for example `csv` or `script`).
    pub fn kind(&self) -> &str {
        &self.kind
    }
}

/// A dependency reference deliberately sent without a JAR or other payload.
#[derive(Clone, Eq, PartialEq)]
pub struct DependencyReference {
    name: String,
    version: String,
}

impl fmt::Debug for DependencyReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DependencyReference")
            .field("name_len", &self.name.len())
            .field("version_len", &self.version.len())
            .finish()
    }
}

impl DependencyReference {
    /// Creates a worker-local dependency reference.
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
        }
    }

    /// Returns the dependency name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the declared version.
    pub fn version(&self) -> &str {
        &self.version
    }
}

/// An immutable plan transfer. Data and dependency contents are never fields
/// of this type: only worker-local references are transferred.
#[derive(Clone, Eq, PartialEq)]
pub struct PlanDescriptor {
    jmx: Vec<u8>,
    data_references: Vec<DataReference>,
    dependencies: Vec<DependencyReference>,
}

impl fmt::Debug for PlanDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PlanDescriptor")
            .field("jmx_len", &self.jmx.len())
            .field("data_reference_count", &self.data_references.len())
            .field("dependency_count", &self.dependencies.len())
            .finish()
    }
}

impl PlanDescriptor {
    /// Creates a plan containing JMX bytes and no local references.
    pub fn new(jmx: impl Into<Vec<u8>>) -> Self {
        Self {
            jmx: jmx.into(),
            data_references: Vec::new(),
            dependencies: Vec::new(),
        }
    }

    /// Adds worker-local references without transferring their contents.
    pub fn with_references(
        mut self,
        data_references: Vec<DataReference>,
        dependencies: Vec<DependencyReference>,
    ) -> Self {
        self.data_references = data_references;
        self.dependencies = dependencies;
        self
    }

    /// Returns the transferred JMX bytes.
    pub fn jmx(&self) -> &[u8] {
        &self.jmx
    }

    /// Returns paths that must already exist on each worker.
    pub fn data_references(&self) -> &[DataReference] {
        &self.data_references
    }

    /// Returns dependencies that must already be installed on each worker.
    pub fn dependencies(&self) -> &[DependencyReference] {
        &self.dependencies
    }

    /// Validates plan size, reference count, and aggregate bytes before a
    /// coordinator or worker retains the value. This is independent of codec
    /// framing so callers cannot bypass bounds with an in-memory message.
    pub fn validate_with_limits(
        &self,
        limits: RemoteConfigurationLimits,
    ) -> Result<(), RemoteError> {
        if !limits.is_valid() {
            return Err(RemoteError::new(
                crate::RemoteErrorCode::ResourceLimit,
                false,
                "remote configuration limits must be non-zero",
            ));
        }
        if self.jmx.len() > limits.max_plan_bytes {
            return Err(RemoteError::new(
                crate::RemoteErrorCode::ResourceLimit,
                false,
                "remote JMX plan exceeds its configured byte bound",
            ));
        }
        let reference_count = self
            .data_references
            .len()
            .checked_add(self.dependencies.len())
            .ok_or_else(|| {
                RemoteError::new(
                    crate::RemoteErrorCode::ResourceLimit,
                    false,
                    "remote plan reference count overflowed",
                )
            })?;
        if reference_count > limits.max_plan_references {
            return Err(RemoteError::new(
                crate::RemoteErrorCode::ResourceLimit,
                false,
                "remote plan reference count exceeded its configured bound",
            ));
        }
        let reference_bytes = self
            .data_references
            .iter()
            .try_fold(0usize, |total, reference| {
                total
                    .checked_add(reference.path.len())
                    .and_then(|total| total.checked_add(reference.kind.len()))
                    .ok_or_else(|| {
                        RemoteError::new(
                            crate::RemoteErrorCode::ResourceLimit,
                            false,
                            "remote plan reference bytes overflowed",
                        )
                    })
            })?
            .checked_add(
                self.dependencies
                    .iter()
                    .try_fold(0usize, |total, dependency| {
                        total
                            .checked_add(dependency.name.len())
                            .and_then(|total| total.checked_add(dependency.version.len()))
                            .ok_or_else(|| {
                                RemoteError::new(
                                    crate::RemoteErrorCode::ResourceLimit,
                                    false,
                                    "remote plan reference bytes overflowed",
                                )
                            })
                    })?,
            )
            .ok_or_else(|| {
                RemoteError::new(
                    crate::RemoteErrorCode::ResourceLimit,
                    false,
                    "remote plan reference bytes overflowed",
                )
            })?;
        if reference_bytes > limits.max_plan_reference_bytes {
            return Err(RemoteError::new(
                crate::RemoteErrorCode::ResourceLimit,
                false,
                "remote plan reference bytes exceeded their configured bound",
            ));
        }
        let configuration_bytes = self.jmx.len().checked_add(reference_bytes).ok_or_else(|| {
            RemoteError::new(
                crate::RemoteErrorCode::ResourceLimit,
                false,
                "remote plan configuration bytes overflowed",
            )
        })?;
        if configuration_bytes > limits.max_configuration_bytes {
            return Err(RemoteError::new(
                crate::RemoteErrorCode::ResourceLimit,
                false,
                "remote plan configuration bytes exceeded their configured bound",
            ));
        }
        Ok(())
    }

    pub(crate) fn configuration_byte_len(&self) -> Result<usize, RemoteError> {
        let reference_bytes = self
            .data_references
            .iter()
            .try_fold(0usize, |total, reference| {
                total
                    .checked_add(reference.path.len())
                    .and_then(|total| total.checked_add(reference.kind.len()))
                    .ok_or_else(|| {
                        RemoteError::new(
                            crate::RemoteErrorCode::ResourceLimit,
                            false,
                            "remote plan reference bytes overflowed",
                        )
                    })
            })?
            .checked_add(
                self.dependencies
                    .iter()
                    .try_fold(0usize, |total, dependency| {
                        total
                            .checked_add(dependency.name.len())
                            .and_then(|total| total.checked_add(dependency.version.len()))
                            .ok_or_else(|| {
                                RemoteError::new(
                                    crate::RemoteErrorCode::ResourceLimit,
                                    false,
                                    "remote plan reference bytes overflowed",
                                )
                            })
                    })?,
            )
            .ok_or_else(|| {
                RemoteError::new(
                    crate::RemoteErrorCode::ResourceLimit,
                    false,
                    "remote plan reference bytes overflowed",
                )
            })?;
        self.jmx.len().checked_add(reference_bytes).ok_or_else(|| {
            RemoteError::new(
                crate::RemoteErrorCode::ResourceLimit,
                false,
                "remote plan configuration bytes overflowed",
            )
        })
    }
}

/// Compatibility alias for callers that use the shorter plan name.
pub type Plan = PlanDescriptor;

/// Ordered run-scoped properties shared with a worker.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct PropertySet {
    values: BTreeMap<String, String>,
}

impl fmt::Debug for PropertySet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PropertySet")
            .field("entry_count", &self.values.len())
            .field(
                "total_key_value_bytes",
                &self
                    .values
                    .iter()
                    .map(|(name, value)| name.len().saturating_add(value.len()))
                    .sum::<usize>(),
            )
            .finish()
    }
}

impl PropertySet {
    /// Creates an empty property set.
    pub const fn new() -> Self {
        Self {
            values: BTreeMap::new(),
        }
    }

    /// Inserts a property. Duplicate names replace the previous value.
    pub fn insert(&mut self, name: impl Into<String>, value: impl Into<String>) -> Option<String> {
        self.values.insert(name.into(), value.into())
    }

    /// Returns a property value.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }

    /// Returns properties in deterministic key order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.values
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
    }

    /// Returns the number of properties.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Returns whether no properties are present.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Returns the ordered map for read-only validation.
    pub fn as_map(&self) -> &BTreeMap<String, String> {
        &self.values
    }

    /// Validates property count and aggregate bytes before a coordinator or
    /// worker retains the value.
    pub fn validate_with_limits(
        &self,
        limits: RemoteConfigurationLimits,
    ) -> Result<(), RemoteError> {
        if !limits.is_valid() {
            return Err(RemoteError::new(
                crate::RemoteErrorCode::ResourceLimit,
                false,
                "remote configuration limits must be non-zero",
            ));
        }
        if self.values.len() > limits.max_properties {
            return Err(RemoteError::new(
                crate::RemoteErrorCode::ResourceLimit,
                false,
                "remote property count exceeded its configured bound",
            ));
        }
        let property_bytes = self
            .values
            .iter()
            .try_fold(0usize, |total, (name, value)| {
                total
                    .checked_add(name.len())
                    .and_then(|total| total.checked_add(value.len()))
                    .ok_or_else(|| {
                        RemoteError::new(
                            crate::RemoteErrorCode::ResourceLimit,
                            false,
                            "remote property bytes overflowed",
                        )
                    })
            })?;
        if property_bytes > limits.max_property_bytes
            || property_bytes > limits.max_configuration_bytes
        {
            return Err(RemoteError::new(
                crate::RemoteErrorCode::ResourceLimit,
                false,
                "remote property bytes exceeded their configured bound",
            ));
        }
        Ok(())
    }

    pub(crate) fn configuration_byte_len(&self) -> Result<usize, RemoteError> {
        self.values.iter().try_fold(0usize, |total, (name, value)| {
            total
                .checked_add(name.len())
                .and_then(|total| total.checked_add(value.len()))
                .ok_or_else(|| {
                    RemoteError::new(
                        crate::RemoteErrorCode::ResourceLimit,
                        false,
                        "remote property bytes overflowed",
                    )
                })
        })
    }
}

pub(crate) fn validate_configuration(
    plan: &PlanDescriptor,
    properties: &PropertySet,
    limits: RemoteConfigurationLimits,
) -> Result<(), RemoteError> {
    plan.validate_with_limits(limits)?;
    properties.validate_with_limits(limits)?;
    let total = plan
        .configuration_byte_len()?
        .checked_add(properties.configuration_byte_len()?)
        .ok_or_else(|| {
            RemoteError::new(
                crate::RemoteErrorCode::ResourceLimit,
                false,
                "remote configuration bytes overflowed",
            )
        })?;
    if total > limits.max_configuration_bytes() {
        return Err(RemoteError::new(
            crate::RemoteErrorCode::ResourceLimit,
            false,
            "remote plan and property bytes exceeded their aggregate bound",
        ));
    }
    Ok(())
}

/// Compatibility alias for callers that use the shorter properties name.
pub type Properties = PropertySet;

/// Stop severity sent to a running worker.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum StopMode {
    /// Finish an interruptible operation and flush retained samples.
    Graceful,
    /// Stop at the next boundary, preserving only samples already delivered;
    /// queued samples are cancelled.
    Immediate,
}

impl StopMode {
    /// Returns whether this stop permits queued samples to drain.
    pub const fn drains_samples(self) -> bool {
        matches!(self, Self::Graceful)
    }

    /// Returns the monotonic cancellation severity represented by the mode.
    pub const fn severity(self) -> u8 {
        match self {
            Self::Graceful => 1,
            Self::Immediate => 2,
        }
    }
}

/// Failure policy for a multi-worker coordinator.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum FailurePolicy {
    /// Keep healthy workers running when one worker fails.
    #[default]
    Continue,
    /// Fail the run when any selected worker fails.
    FailFast,
}

/// Sample sender modes represented by the JMeter distributed surface.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SampleSenderMode {
    /// Deliver each sample synchronously.
    Standard,
    /// Hold samples until an explicit flush (normally test end).
    Hold,
    /// Flush after the configured sample count.
    Batch {
        /// Samples per batch.
        size: usize,
    },
    /// Aggregate samples statistically. The pure core reports this mode as an
    /// unavailable capability until an aggregation adapter is supplied.
    Statistical {
        /// Samples per retained statistical batch.
        size: usize,
    },
    /// Deliver each sample after stripping response payload bytes.
    Stripped,
    /// Batch mode with payload stripping.
    StrippedBatch {
        /// Samples per stripped batch.
        size: usize,
    },
    /// Bounded asynchronous queue.
    Asynch {
        /// Maximum queued samples.
        capacity: usize,
    },
    /// Bounded asynchronous queue with payload stripping.
    StrippedAsynch {
        /// Maximum queued stripped samples.
        capacity: usize,
    },
    /// Persist samples through a bounded disk store. The pure core reports
    /// this mode as unavailable until a filesystem adapter is supplied.
    DiskStore {
        /// Maximum samples a filesystem-backed adapter may retain.
        capacity: usize,
    },
    /// Persist stripped samples through a bounded disk store. The pure core
    /// reports this mode as unavailable until a filesystem adapter is supplied.
    StrippedDiskStore {
        /// Maximum stripped samples a filesystem-backed adapter may retain.
        capacity: usize,
    },
}

impl SampleSenderMode {
    /// Stable capability identifier for an unavailable sender mode.
    pub const fn unsupported_capability_id(self) -> Option<&'static str> {
        match self {
            Self::Statistical { .. } => Some("remote.sample-sender.statistical"),
            Self::Asynch { .. } | Self::StrippedAsynch { .. } => {
                Some("remote.sample-sender.asynchronous")
            }
            Self::DiskStore { .. } | Self::StrippedDiskStore { .. } => {
                Some("remote.sample-sender.disk-store")
            }
            Self::Standard
            | Self::Hold
            | Self::Batch { .. }
            | Self::Stripped
            | Self::StrippedBatch { .. } => None,
        }
    }

    /// Returns the stable typed failure used when an adapter has not supplied
    /// an implementation for this sender mode.
    pub fn unsupported_error(self) -> Option<RemoteError> {
        self.unsupported_capability_id().map(|capability| {
            RemoteError::new(
                crate::RemoteErrorCode::CapabilityUnavailable,
                false,
                format!("sender capability {capability} is unavailable"),
            )
        })
    }

    /// Returns a batch mode after rejecting a zero threshold.
    pub const fn batch(size: usize) -> Option<Self> {
        if size == 0 {
            None
        } else {
            Some(Self::Batch { size })
        }
    }

    /// Returns whether this mode strips response payload bytes.
    pub const fn is_stripped(self) -> bool {
        matches!(
            self,
            Self::Stripped
                | Self::StrippedBatch { .. }
                | Self::StrippedAsynch { .. }
                | Self::StrippedDiskStore { .. }
        )
    }

    /// Returns the configured queue/batch bound, if the mode has one.
    pub const fn capacity(self) -> Option<usize> {
        match self {
            Self::Batch { size } | Self::Statistical { size } | Self::StrippedBatch { size } => {
                Some(size)
            }
            Self::Asynch { capacity }
            | Self::StrippedAsynch { capacity }
            | Self::DiskStore { capacity }
            | Self::StrippedDiskStore { capacity } => Some(capacity),
            Self::Standard | Self::Hold | Self::Stripped => None,
        }
    }

    /// Returns whether an invalid zero bound is present.
    pub const fn has_zero_bound(self) -> bool {
        matches!(self.capacity(), Some(0))
    }

    /// Returns whether this crate has a complete deterministic implementation
    /// for the mode. Modes requiring statistical reduction, asynchronous
    /// scheduling, or filesystem persistence remain explicit capabilities for
    /// a future adapter instead of silently behaving like another mode.
    pub const fn execution_supported(self) -> bool {
        matches!(
            self,
            Self::Standard
                | Self::Hold
                | Self::Batch { .. }
                | Self::Stripped
                | Self::StrippedBatch { .. }
        )
    }

    /// Returns a stable capability description for an unsupported mode.
    pub const fn unsupported_capability(self) -> Option<&'static str> {
        match self {
            Self::Statistical { .. } => Some("statistical sender aggregation"),
            Self::Asynch { .. } | Self::StrippedAsynch { .. } => {
                Some("asynchronous sender scheduling")
            }
            Self::DiskStore { .. } | Self::StrippedDiskStore { .. } => {
                Some("disk-store sender persistence")
            }
            Self::Standard
            | Self::Hold
            | Self::Batch { .. }
            | Self::Stripped
            | Self::StrippedBatch { .. } => None,
        }
    }
}

/// A globally unique sample key within one remote run.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SampleKey {
    worker: WorkerId,
    sequence: u64,
}

impl SampleKey {
    /// Creates a key from a worker and its monotonic sample sequence.
    pub const fn new(worker: WorkerId, sequence: u64) -> Self {
        Self { worker, sequence }
    }

    /// Returns the worker component.
    pub const fn worker(self) -> WorkerId {
        self.worker
    }

    /// Returns the worker-local sequence.
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
}

/// A result event plus an explicit worker sequence. Arrival order is kept
/// separately by the coordinator and must not be inferred from this key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteSample {
    run_id: RunId,
    key: SampleKey,
    event: SampleEvent,
}

impl RemoteSample {
    /// Creates a sample emitted by a worker.
    pub fn new(run_id: RunId, worker: WorkerId, sequence: u64, event: SampleEvent) -> Self {
        Self {
            run_id,
            key: SampleKey::new(worker, sequence),
            event,
        }
    }

    /// Returns the run identity.
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// Returns the stable deduplication key.
    pub const fn key(&self) -> SampleKey {
        self.key
    }

    /// Returns the worker identity.
    pub const fn worker(&self) -> WorkerId {
        self.key.worker()
    }

    /// Returns the worker-local sequence.
    pub const fn sequence(&self) -> u64 {
        self.key.sequence()
    }

    /// Returns the immutable event snapshot.
    pub fn event(&self) -> &SampleEvent {
        &self.event
    }

    /// Consumes the sample and returns its event.
    pub fn into_event(self) -> SampleEvent {
        self.event
    }
}

/// Message acknowledgement stage.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AckStage {
    /// Profile was accepted.
    Profile,
    /// Plan was accepted.
    Plan,
    /// Properties were accepted.
    Properties,
    /// Worker entered the running state.
    Started,
    /// Worker entered the stopped state.
    Stopped,
}

/// A typed Rust-native remote message.
#[allow(clippy::large_enum_variant)] // SampleEvent is an intentionally complete immutable snapshot.
#[derive(Clone, Eq, PartialEq)]
pub enum RemoteMessage {
    /// Profile negotiation/configuration.
    Profile {
        /// Requested compatibility profile.
        profile: ProfileDescriptor,
    },
    /// Full JMX plan transfer and worker-local references.
    Plan {
        /// Complete plan and worker-local references.
        plan: PlanDescriptor,
    },
    /// Run-scoped properties.
    Properties {
        /// Run-scoped properties.
        properties: PropertySet,
    },
    /// Start a full copy of the plan on one worker.
    Start {
        /// Run identity.
        run_id: RunId,
        /// Logical threads to create on this worker.
        thread_count: u32,
        /// Result sender/backpressure mode.
        sender_mode: SampleSenderMode,
    },
    /// Stop a run with explicit graceful-drain or immediate-cancellation
    /// semantics.
    Stop {
        /// Run identity.
        run_id: RunId,
        /// Graceful or immediate stop severity.
        mode: StopMode,
    },
    /// A worker result sample.
    Sample {
        /// Immutable worker result snapshot.
        sample: RemoteSample,
    },
    /// A lifecycle acknowledgement.
    Ack {
        /// Worker that completed the stage.
        worker: WorkerId,
        /// Completed lifecycle stage.
        stage: AckStage,
        /// Run identity for run-scoped stages.
        run_id: Option<RunId>,
        /// Logical thread count for start/stop stages.
        thread_count: Option<u32>,
        /// Exclusive worker sample sequence watermark for a graceful stop.
        /// Other acknowledgement stages leave this field absent.
        sample_watermark: Option<u64>,
    },
    /// A worker/coordinator failure with stable code.
    Failure {
        /// Worker that failed.
        worker: WorkerId,
        /// Run generation associated with the failure. Configuration failures
        /// before a run starts use `None`.
        run_id: Option<RunId>,
        /// Structured failure.
        error: RemoteError,
    },
}

impl fmt::Debug for RemoteMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("RemoteMessage");
        match self {
            Self::Profile { profile } => debug.field("kind", &"Profile").field("profile", profile),
            Self::Plan { plan } => debug.field("kind", &"Plan").field("plan", plan),
            Self::Properties { properties } => debug
                .field("kind", &"Properties")
                .field("properties", properties),
            Self::Start {
                run_id,
                thread_count,
                sender_mode,
            } => debug
                .field("kind", &"Start")
                .field("run_id", run_id)
                .field("thread_count", thread_count)
                .field("sender_mode", sender_mode),
            Self::Stop { run_id, mode } => debug
                .field("kind", &"Stop")
                .field("run_id", run_id)
                .field("mode", mode),
            Self::Sample { sample } => debug.field("kind", &"Sample").field("sample", sample),
            Self::Ack {
                worker,
                stage,
                run_id,
                thread_count,
                sample_watermark,
            } => debug
                .field("kind", &"Ack")
                .field("worker", worker)
                .field("stage", stage)
                .field("run_id", run_id)
                .field("thread_count", thread_count)
                .field("sample_watermark", sample_watermark),
            Self::Failure {
                worker,
                run_id,
                error,
            } => debug
                .field("kind", &"Failure")
                .field("worker", worker)
                .field("run_id", run_id)
                .field("error", error),
        };
        debug.finish()
    }
}

impl RemoteMessage {
    /// Returns the discriminant used in the current body header.
    pub const fn kind(&self) -> MessageKind {
        match self {
            Self::Profile { .. } => MessageKind::Profile,
            Self::Plan { .. } => MessageKind::Plan,
            Self::Properties { .. } => MessageKind::Properties,
            Self::Start { .. } => MessageKind::Start,
            Self::Stop { .. } => MessageKind::Stop,
            Self::Sample { .. } => MessageKind::Sample,
            Self::Ack { .. } => MessageKind::Ack,
            Self::Failure { .. } => MessageKind::Failure,
        }
    }
}

/// Message discriminants in the current wire header.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum MessageKind {
    /// Profile message.
    Profile = 1,
    /// Plan message.
    Plan = 2,
    /// Properties message.
    Properties = 3,
    /// Start message.
    Start = 4,
    /// Stop message.
    Stop = 5,
    /// Sample message.
    Sample = 6,
    /// Acknowledgement message.
    Ack = 7,
    /// Failure message.
    Failure = 8,
}

impl MessageKind {
    fn from_wire(value: u8) -> Result<Self, ProtocolError> {
        match value {
            1 => Ok(Self::Profile),
            2 => Ok(Self::Plan),
            3 => Ok(Self::Properties),
            4 => Ok(Self::Start),
            5 => Ok(Self::Stop),
            6 => Ok(Self::Sample),
            7 => Ok(Self::Ack),
            8 => Ok(Self::Failure),
            other => Err(ProtocolError::UnknownMessageKind(other)),
        }
    }
}

/// The message and field limits shared by a sender and its codec.
///
/// A sender must be created from the same value as the codec used by its
/// adapter.  Keeping the two wire dimensions together prevents the old
/// mismatch where `SenderConfig::max_sample_bytes` widened fields beyond the
/// codec's 64 KiB field bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WireLimits {
    max_message_bytes: usize,
    max_field_bytes: usize,
}

impl WireLimits {
    /// Creates validated wire limits.  The message bound includes the fixed
    /// [`REMOTE_HEADER_LEN`] bytes; a field bound is independently limited by
    /// the four-byte length prefix and cannot be zero.
    pub const fn new(max_message_bytes: usize, max_field_bytes: usize) -> Option<Self> {
        if max_message_bytes < REMOTE_HEADER_LEN
            || max_field_bytes == 0
            || max_field_bytes > u32::MAX as usize
            || max_message_bytes.saturating_sub(REMOTE_HEADER_LEN) > u32::MAX as usize
        {
            None
        } else {
            Some(Self {
                max_message_bytes,
                max_field_bytes,
            })
        }
    }

    /// Creates validated wire limits with a typed error for adapter setup.
    pub fn try_new(max_message_bytes: usize, max_field_bytes: usize) -> Result<Self, RemoteError> {
        Self::new(max_message_bytes, max_field_bytes).ok_or_else(|| {
            RemoteError::new(
                crate::RemoteErrorCode::ResourceLimit,
                false,
                "remote wire limits must be non-zero and representable",
            )
        })
    }

    /// Creates the default field bound for a message size.
    pub const fn for_message_bytes(max_message_bytes: usize) -> Option<Self> {
        let payload = max_message_bytes.saturating_sub(REMOTE_HEADER_LEN);
        let field = if payload < DEFAULT_MAX_FIELD_BYTES {
            payload
        } else {
            DEFAULT_MAX_FIELD_BYTES
        };
        Self::new(max_message_bytes, field)
    }

    /// Returns the total bound, including the fixed header.
    pub const fn max_message_bytes(self) -> usize {
        self.max_message_bytes
    }

    /// Returns the maximum size of one length-prefixed field.
    pub const fn max_field_bytes(self) -> usize {
        self.max_field_bytes
    }

    /// Replaces the total message bound.  Callers that construct limits from
    /// untrusted configuration must use [`Self::try_new`] or [`Self::validate`]
    /// before creating a transport.
    pub const fn with_max_message_bytes(mut self, value: usize) -> Self {
        self.max_message_bytes = value;
        self
    }

    /// Replaces the field bound.  Validation is explicit at the codec/sender
    /// boundary so this builder remains usable in const configuration code.
    pub const fn with_max_field_bytes(mut self, value: usize) -> Self {
        self.max_field_bytes = value;
        self
    }

    /// Validates representability before a codec or sender retains data.
    pub fn validate(self) -> Result<(), RemoteError> {
        Self::new(self.max_message_bytes, self.max_field_bytes)
            .map(|_| ())
            .ok_or_else(|| {
                RemoteError::new(
                    crate::RemoteErrorCode::ResourceLimit,
                    false,
                    "remote wire limits must be non-zero and representable",
                )
            })
    }

    pub(crate) const fn is_valid(self) -> bool {
        self.max_message_bytes >= REMOTE_HEADER_LEN
            && self.max_field_bytes != 0
            && self.max_field_bytes <= u32::MAX as usize
            && self.max_message_bytes.saturating_sub(REMOTE_HEADER_LEN) <= u32::MAX as usize
    }
}

impl Default for WireLimits {
    fn default() -> Self {
        Self {
            max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
            max_field_bytes: DEFAULT_MAX_FIELD_BYTES,
        }
    }
}

/// Finite bounds applied to configuration before values enter a coordinator,
/// worker, or codec. These limits cover selected workers, plan references,
/// properties, worker-local resources, queued control events, and aggregate
/// configuration bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteConfigurationLimits {
    max_workers: usize,
    max_control_events: usize,
    max_plan_bytes: usize,
    max_plan_references: usize,
    max_plan_reference_bytes: usize,
    max_properties: usize,
    max_property_bytes: usize,
    max_resource_entries: usize,
    max_resource_bytes: usize,
    max_configuration_bytes: usize,
}

impl RemoteConfigurationLimits {
    /// Creates finite defaults for pre-codec coordinator and worker input.
    pub const fn new() -> Self {
        Self {
            max_workers: DEFAULT_MAX_WORKERS,
            max_control_events: DEFAULT_MAX_CONTROL_EVENTS,
            max_plan_bytes: DEFAULT_MAX_PLAN_BYTES,
            max_plan_references: DEFAULT_MAX_PLAN_REFERENCES,
            max_plan_reference_bytes: DEFAULT_MAX_PLAN_REFERENCE_BYTES,
            max_properties: DEFAULT_MAX_PROPERTIES,
            max_property_bytes: DEFAULT_MAX_PROPERTY_BYTES,
            max_resource_entries: DEFAULT_MAX_RESOURCE_ENTRIES,
            max_resource_bytes: DEFAULT_MAX_RESOURCE_BYTES,
            max_configuration_bytes: DEFAULT_MAX_CONFIGURATION_BYTES,
        }
    }

    /// Sets the maximum number of selected workers.
    pub const fn with_max_workers(mut self, value: usize) -> Self {
        self.max_workers = value;
        self
    }

    /// Sets the maximum number of queued coordinator control events.
    pub const fn with_max_control_events(mut self, value: usize) -> Self {
        self.max_control_events = value;
        self
    }

    /// Sets the maximum JMX plan byte count.
    pub const fn with_max_plan_bytes(mut self, value: usize) -> Self {
        self.max_plan_bytes = value;
        self
    }

    /// Sets the aggregate data/dependency reference count.
    pub const fn with_max_plan_references(mut self, value: usize) -> Self {
        self.max_plan_references = value;
        self
    }

    /// Sets the aggregate data/dependency reference byte count.
    pub const fn with_max_plan_reference_bytes(mut self, value: usize) -> Self {
        self.max_plan_reference_bytes = value;
        self
    }

    /// Sets the maximum property count.
    pub const fn with_max_properties(mut self, value: usize) -> Self {
        self.max_properties = value;
        self
    }

    /// Sets the aggregate property name/value byte count.
    pub const fn with_max_property_bytes(mut self, value: usize) -> Self {
        self.max_property_bytes = value;
        self
    }

    /// Sets the aggregate worker-local resource entry count.
    pub const fn with_max_resource_entries(mut self, value: usize) -> Self {
        self.max_resource_entries = value;
        self
    }

    /// Sets the aggregate worker-local resource name/path byte count.
    pub const fn with_max_resource_bytes(mut self, value: usize) -> Self {
        self.max_resource_bytes = value;
        self
    }

    /// Sets the total plan/property configuration byte count.
    pub const fn with_max_configuration_bytes(mut self, value: usize) -> Self {
        self.max_configuration_bytes = value;
        self
    }

    /// Returns the worker bound.
    pub const fn max_workers(self) -> usize {
        self.max_workers
    }

    /// Returns the maximum number of queued coordinator control events.
    pub const fn max_control_events(self) -> usize {
        self.max_control_events
    }

    /// Returns the JMX plan byte bound.
    pub const fn max_plan_bytes(self) -> usize {
        self.max_plan_bytes
    }

    /// Returns the aggregate plan reference count bound.
    pub const fn max_plan_references(self) -> usize {
        self.max_plan_references
    }

    /// Returns the aggregate plan reference byte bound.
    pub const fn max_plan_reference_bytes(self) -> usize {
        self.max_plan_reference_bytes
    }

    /// Returns the property count bound.
    pub const fn max_properties(self) -> usize {
        self.max_properties
    }

    /// Returns the aggregate property byte bound.
    pub const fn max_property_bytes(self) -> usize {
        self.max_property_bytes
    }

    /// Returns the worker-local resource entry bound.
    pub const fn max_resource_entries(self) -> usize {
        self.max_resource_entries
    }

    /// Returns the worker-local resource byte bound.
    pub const fn max_resource_bytes(self) -> usize {
        self.max_resource_bytes
    }

    /// Returns the total plan/property byte bound.
    pub const fn max_configuration_bytes(self) -> usize {
        self.max_configuration_bytes
    }

    pub(crate) const fn is_valid(self) -> bool {
        self.max_workers != 0
            && self.max_control_events != 0
            && self.max_plan_bytes != 0
            && self.max_plan_references != 0
            && self.max_plan_reference_bytes != 0
            && self.max_properties != 0
            && self.max_property_bytes != 0
            && self.max_resource_entries != 0
            && self.max_resource_bytes != 0
            && self.max_configuration_bytes != 0
    }
}

impl Default for RemoteConfigurationLimits {
    fn default() -> Self {
        Self::new()
    }
}

/// An encoded message with its request correlation ID.
#[derive(Clone, Eq, PartialEq)]
pub struct RemoteEnvelope {
    /// Request/correlation identity.
    pub request_id: RequestId,
    /// Typed message body.
    pub message: RemoteMessage,
}

impl fmt::Debug for RemoteEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteEnvelope")
            .field("request_id", &self.request_id)
            .field("message", &self.message)
            .finish()
    }
}

impl RemoteEnvelope {
    /// Creates an envelope.
    pub const fn new(request_id: RequestId, message: RemoteMessage) -> Self {
        Self {
            request_id,
            message,
        }
    }
}

/// Explicit resource limits applied before message allocations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteLimits {
    wire: WireLimits,
    max_plan_bytes: usize,
    max_properties: usize,
    max_references: usize,
    max_capabilities: usize,
    max_sample_depth: usize,
    max_sample_nodes: usize,
    max_samples: usize,
    configuration: RemoteConfigurationLimits,
}

impl RemoteLimits {
    /// Creates defaults with a custom total message bound.
    pub const fn new(max_message_bytes: usize) -> Self {
        let payload = max_message_bytes.saturating_sub(REMOTE_HEADER_LEN);
        let field = if payload < DEFAULT_MAX_FIELD_BYTES {
            payload
        } else {
            DEFAULT_MAX_FIELD_BYTES
        };
        Self {
            wire: WireLimits {
                max_message_bytes,
                max_field_bytes: field,
            },
            max_plan_bytes: DEFAULT_MAX_PLAN_BYTES,
            max_properties: DEFAULT_MAX_PROPERTIES,
            max_references: DEFAULT_MAX_REFERENCES,
            max_capabilities: DEFAULT_MAX_CAPABILITIES,
            max_sample_depth: DEFAULT_MAX_SAMPLE_DEPTH,
            max_sample_nodes: DEFAULT_MAX_SAMPLE_NODES,
            max_samples: DEFAULT_MAX_SAMPLES,
            configuration: RemoteConfigurationLimits::new(),
        }
    }

    /// Creates limits with a validated message bound.
    pub fn try_new(max_message_bytes: usize) -> Result<Self, RemoteError> {
        let limits = Self::new(max_message_bytes);
        limits.validate().map(|()| limits)
    }

    /// Returns the total message bound, including the fixed header.
    pub const fn max_message_bytes(self) -> usize {
        self.wire.max_message_bytes()
    }

    /// Returns the maximum size of one length-prefixed field.
    pub const fn max_field_bytes(self) -> usize {
        self.wire.max_field_bytes()
    }

    /// Returns the shared message/field source used by codecs and senders.
    pub const fn wire_limits(self) -> WireLimits {
        self.wire
    }

    /// Creates limits from one validated wire source while retaining the
    /// other protocol bounds from this value.
    pub const fn with_wire_limits(mut self, wire: WireLimits) -> Self {
        self.wire = wire;
        self
    }

    /// Validates all wire and hierarchy limits before adapter setup.
    pub fn validate(self) -> Result<(), RemoteError> {
        if !self.is_valid() {
            return Err(RemoteError::new(
                crate::RemoteErrorCode::ResourceLimit,
                false,
                "remote limits must be non-zero and representable",
            ));
        }
        Ok(())
    }

    pub(crate) const fn is_valid(self) -> bool {
        if !self.wire.is_valid()
            || self.max_plan_bytes == 0
            || self.max_properties == 0
            || self.max_references == 0
            || self.max_capabilities == 0
            || self.max_sample_depth == 0
            || self.max_sample_nodes == 0
            || self.max_samples == 0
            || !self.configuration.is_valid()
        {
            return false;
        }
        true
    }

    /// Sets the maximum UTF-8 or byte field size.
    pub const fn with_max_field_bytes(mut self, value: usize) -> Self {
        self.wire = self.wire.with_max_field_bytes(value);
        self
    }

    /// Sets the maximum transferred plan size.
    pub const fn with_max_plan_bytes(mut self, value: usize) -> Self {
        self.max_plan_bytes = value;
        self.configuration = self.configuration.with_max_plan_bytes(value);
        self
    }

    /// Sets the maximum property count.
    pub const fn with_max_properties(mut self, value: usize) -> Self {
        self.max_properties = value;
        self.configuration = self.configuration.with_max_properties(value);
        self
    }

    /// Sets the maximum references and capabilities per message.
    pub const fn with_max_references(mut self, value: usize) -> Self {
        self.max_references = value;
        self.configuration = self
            .configuration
            .with_max_plan_references(value.saturating_mul(2));
        self
    }

    /// Sets aggregate pre-codec configuration bounds used for plan and
    /// property messages. Worker count is consumed by coordinators; the
    /// remaining fields are also enforced by this codec.
    pub const fn with_configuration_limits(mut self, limits: RemoteConfigurationLimits) -> Self {
        self.configuration = limits;
        self
    }

    /// Returns aggregate pre-codec configuration bounds.
    pub const fn configuration_limits(self) -> RemoteConfigurationLimits {
        self.configuration
    }

    /// Sets the maximum number of advertised capabilities.
    pub const fn with_max_capabilities(mut self, value: usize) -> Self {
        self.max_capabilities = value;
        self
    }

    /// Sets the maximum number of samples accepted by a sender created from
    /// these limits.
    pub const fn with_max_samples(mut self, value: usize) -> Self {
        self.max_samples = value;
        self
    }

    /// Returns the configured sample bound.
    pub const fn max_samples(self) -> usize {
        self.max_samples
    }

    /// Returns the maximum number of repeated fields/references in one
    /// message.
    pub const fn max_references(self) -> usize {
        self.max_references
    }

    /// Returns the maximum result hierarchy depth.
    pub const fn max_sample_depth(self) -> usize {
        self.max_sample_depth
    }

    /// Returns the maximum result hierarchy node count.
    pub const fn max_sample_nodes(self) -> usize {
        self.max_sample_nodes
    }

    /// Sets bounded result hierarchy limits.
    pub const fn with_sample_limits(mut self, depth: usize, nodes: usize) -> Self {
        self.max_sample_depth = depth;
        self.max_sample_nodes = nodes;
        self
    }
}

impl Default for RemoteLimits {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_MESSAGE_BYTES)
    }
}

/// Stateless bounded encoder/decoder for versioned remote envelopes.
///
/// The raw [`Self::encode`] and [`Self::decode`] methods are intentionally
/// serialization-only and never advance coordinator/worker state. A
/// transport adapter must use the context-checking wrappers and then invoke a
/// `*_with_context` state method; wire bytes cannot supply that context
/// themselves.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteCodec {
    limits: RemoteLimits,
}

impl RemoteCodec {
    /// Creates a codec with explicit bounds.
    pub const fn new(limits: RemoteLimits) -> Self {
        Self { limits }
    }

    /// Creates a codec after validating every configured bound.
    pub fn try_new(limits: RemoteLimits) -> Result<Self, RemoteError> {
        limits.validate().map(|()| Self::new(limits))
    }

    /// Returns configured bounds.
    pub const fn limits(self) -> RemoteLimits {
        self.limits
    }

    /// Returns the message/field limits shared with a sender configured from
    /// this codec.
    pub const fn wire_limits(self) -> WireLimits {
        self.limits.wire_limits()
    }

    /// Encodes an envelope into one complete bounded message.
    ///
    /// This method is serialization-only: it does not apply the message to a
    /// worker or coordinator and it cannot carry deadline/cancellation
    /// context. A transport adapter must retain its request context beside
    /// the returned bytes and use [`Self::encode_for_adapter`] at the state
    /// boundary.
    pub fn encode(&self, envelope: &RemoteEnvelope) -> Result<Vec<u8>, ProtocolError> {
        validate_codec_limits(self.limits)?;
        if envelope.request_id == 0 {
            return Err(ProtocolError::InvalidValue {
                field: "request id",
                value: 0,
            });
        }
        let is_sample = matches!(&envelope.message, RemoteMessage::Sample { .. });
        if (is_sample && !is_sample_envelope_request_id(envelope.request_id))
            || (!is_sample && uses_sample_envelope_namespace(envelope.request_id))
        {
            return Err(ProtocolError::InvalidValue {
                field: "request id namespace",
                value: envelope.request_id,
            });
        }
        if let RemoteMessage::Sample { sample } = &envelope.message
            && sample_envelope_worker(envelope.request_id) != Some(sample.worker())
        {
            return Err(ProtocolError::InvalidValue {
                field: "sample request worker",
                value: envelope.request_id,
            });
        }
        let mut writer = Writer::new(self.payload_limit());
        encode_message(&mut writer, &envelope.message, self.limits)?;
        let payload = writer.finish();
        let total =
            REMOTE_HEADER_LEN
                .checked_add(payload.len())
                .ok_or(ProtocolError::MessageTooLarge {
                    declared: usize::MAX,
                    maximum: self.limits.max_message_bytes(),
                })?;
        if total > self.limits.max_message_bytes() {
            return Err(ProtocolError::MessageTooLarge {
                declared: total,
                maximum: self.limits.max_message_bytes(),
            });
        }
        let mut bytes = Vec::with_capacity(total);
        bytes.extend_from_slice(&REMOTE_MAGIC);
        bytes.extend_from_slice(&REMOTE_PROTOCOL_VERSION.to_be_bytes());
        bytes.push(envelope.message.kind() as u8);
        bytes.push(0);
        bytes.extend_from_slice(&envelope.request_id.to_be_bytes());
        let payload_len =
            u32::try_from(payload.len()).map_err(|_| ProtocolError::MessageTooLarge {
                declared: payload.len(),
                maximum: self.payload_limit(),
            })?;
        bytes.extend_from_slice(&payload_len.to_be_bytes());
        bytes.extend_from_slice(&payload);
        Ok(bytes)
    }

    /// Encodes a message for a transport adapter after requiring and checking
    /// its out-of-band context. This protocol intentionally does not serialize
    /// deadline/cancellation fields; adapters must retain the returned
    /// context alongside the bytes and pass it to the receiving state method.
    pub fn encode_for_adapter(
        &self,
        envelope: &RemoteEnvelope,
        context: Option<RemoteRequestContext>,
        now_unix_millis: u64,
    ) -> Result<Vec<u8>, RemoteError> {
        let context = RemoteRequestContext::require(context)?;
        context.check(now_unix_millis)?;
        self.encode(envelope)
            .map_err(|error| RemoteError::new(error.code(), false, error.to_string()))
    }

    /// Measures a sample envelope without cloning its immutable result tree.
    /// The size calculation uses the exact same bounded encoder as
    /// [`RemoteCodec::encode`], but only retains the payload length.  Sender
    /// backpressure uses this path so a large hierarchy is not copied merely
    /// to account for its retained bytes.
    pub(crate) fn encoded_sample_len(
        &self,
        request_id: RequestId,
        sample: &RemoteSample,
    ) -> Result<usize, ProtocolError> {
        validate_codec_limits(self.limits)?;
        if request_id == 0
            || !is_sample_envelope_request_id(request_id)
            || sample_envelope_worker(request_id) != Some(sample.worker())
        {
            return Err(ProtocolError::InvalidValue {
                field: "request id namespace",
                value: request_id,
            });
        }
        let mut writer = Writer::new(self.payload_limit());
        encode_sample(&mut writer, sample, self.limits)?;
        let payload = writer.finish();
        let total =
            REMOTE_HEADER_LEN
                .checked_add(payload.len())
                .ok_or(ProtocolError::MessageTooLarge {
                    declared: usize::MAX,
                    maximum: self.limits.max_message_bytes(),
                })?;
        if total > self.limits.max_message_bytes() {
            return Err(ProtocolError::MessageTooLarge {
                declared: total,
                maximum: self.limits.max_message_bytes(),
            });
        }
        Ok(total)
    }

    /// Decodes exactly one bounded envelope and rejects trailing bytes.
    ///
    /// This is also serialization-only. Decoding does not drive a state
    /// transition; adapters must require context and call the corresponding
    /// `*_with_context` state method before applying the decoded envelope.
    pub fn decode(&self, input: &[u8]) -> Result<RemoteEnvelope, ProtocolError> {
        validate_codec_limits(self.limits)?;
        if input.len() < REMOTE_HEADER_LEN {
            return Err(ProtocolError::Incomplete {
                needed: REMOTE_HEADER_LEN - input.len(),
            });
        }
        if input[..4] != REMOTE_MAGIC {
            return Err(ProtocolError::InvalidMagic {
                found: [input[0], input[1], input[2], input[3]],
            });
        }
        let version = u16::from_be_bytes([input[4], input[5]]);
        if version != REMOTE_PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(version));
        }
        if input[7] != 0 {
            return Err(ProtocolError::UnknownFlags(input[7]));
        }
        let kind = MessageKind::from_wire(input[6])?;
        let request_id = u64::from_be_bytes(input[8..16].try_into().map_err(|_| {
            ProtocolError::LengthMismatch {
                declared: 16,
                actual: input.len(),
            }
        })?);
        if request_id == 0 {
            return Err(ProtocolError::InvalidValue {
                field: "request id",
                value: 0,
            });
        }
        let is_sample = kind == MessageKind::Sample;
        if (is_sample && !is_sample_envelope_request_id(request_id))
            || (!is_sample && uses_sample_envelope_namespace(request_id))
        {
            return Err(ProtocolError::InvalidValue {
                field: "request id namespace",
                value: request_id,
            });
        }
        let payload_len = u32::from_be_bytes(input[16..20].try_into().map_err(|_| {
            ProtocolError::LengthMismatch {
                declared: 20,
                actual: input.len(),
            }
        })?) as usize;
        let total =
            REMOTE_HEADER_LEN
                .checked_add(payload_len)
                .ok_or(ProtocolError::MessageTooLarge {
                    declared: usize::MAX,
                    maximum: self.limits.max_message_bytes(),
                })?;
        if total > self.limits.max_message_bytes() {
            return Err(ProtocolError::MessageTooLarge {
                declared: total,
                maximum: self.limits.max_message_bytes(),
            });
        }
        if input.len() < total {
            return Err(ProtocolError::Incomplete {
                needed: total - input.len(),
            });
        }
        if input.len() > total {
            return Err(ProtocolError::TrailingBytes {
                count: input.len() - total,
            });
        }
        let mut reader = Reader::new(&input[REMOTE_HEADER_LEN..total]);
        let message = decode_message(&mut reader, kind, self.limits)?;
        if let RemoteMessage::Sample { sample } = &message
            && sample_envelope_worker(request_id) != Some(sample.worker())
        {
            return Err(ProtocolError::InvalidValue {
                field: "sample request worker",
                value: request_id,
            });
        }
        reader.finish()?;
        Ok(RemoteEnvelope {
            request_id,
            message,
        })
    }

    /// Decodes a message for a transport adapter after requiring and checking
    /// its out-of-band context. The context is not inferred from wire bytes
    /// bytes and must be supplied by the adapter.
    pub fn decode_for_adapter(
        &self,
        input: &[u8],
        context: Option<RemoteRequestContext>,
        now_unix_millis: u64,
    ) -> Result<RemoteEnvelope, RemoteError> {
        let context = RemoteRequestContext::require(context)?;
        context.check(now_unix_millis)?;
        self.decode(input)
            .map_err(|error| RemoteError::new(error.code(), false, error.to_string()))
    }

    fn payload_limit(self) -> usize {
        self.limits
            .max_message_bytes()
            .saturating_sub(REMOTE_HEADER_LEN)
    }
}

impl Default for RemoteCodec {
    fn default() -> Self {
        Self::new(RemoteLimits::default())
    }
}

/// Compatibility aliases for protocol naming used by adapters.
pub type Message = RemoteMessage;
/// Compatibility alias for the envelope.
pub type Envelope = RemoteEnvelope;
/// Compatibility alias for the codec.
pub type Codec = RemoteCodec;

fn validate_codec_limits(limits: RemoteLimits) -> Result<(), ProtocolError> {
    let wire = limits.wire_limits();
    if !wire.is_valid() {
        if wire.max_message_bytes() < REMOTE_HEADER_LEN {
            return Err(ProtocolError::MessageTooLarge {
                declared: wire.max_message_bytes(),
                maximum: REMOTE_HEADER_LEN,
            });
        }
        return Err(ProtocolError::FieldTooLarge {
            field: "wire field",
            declared: wire.max_field_bytes(),
            maximum: u32::MAX as usize,
        });
    }
    if !limits.is_valid() {
        return Err(ProtocolError::InvalidLimits);
    }
    Ok(())
}

struct Writer {
    bytes: Vec<u8>,
    maximum: usize,
}

impl Writer {
    fn new(maximum: usize) -> Self {
        Self {
            bytes: Vec::new(),
            maximum,
        }
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }

    fn append(&mut self, bytes: &[u8]) -> Result<(), ProtocolError> {
        self.ensure(bytes.len())?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn ensure(&self, additional: usize) -> Result<(), ProtocolError> {
        let length =
            self.bytes
                .len()
                .checked_add(additional)
                .ok_or(ProtocolError::MessageTooLarge {
                    declared: usize::MAX,
                    maximum: self.maximum,
                })?;
        if length > self.maximum {
            return Err(ProtocolError::MessageTooLarge {
                declared: length,
                maximum: self.maximum,
            });
        }
        Ok(())
    }

    fn put_u8(&mut self, value: u8) -> Result<(), ProtocolError> {
        self.ensure(1)?;
        self.bytes.push(value);
        Ok(())
    }

    fn put_u16(&mut self, value: u16) -> Result<(), ProtocolError> {
        self.ensure(2)?;
        self.bytes.extend_from_slice(&value.to_be_bytes());
        Ok(())
    }

    fn put_u32(&mut self, value: u32) -> Result<(), ProtocolError> {
        self.ensure(4)?;
        self.bytes.extend_from_slice(&value.to_be_bytes());
        Ok(())
    }

    fn put_u64(&mut self, value: u64) -> Result<(), ProtocolError> {
        self.ensure(8)?;
        self.bytes.extend_from_slice(&value.to_be_bytes());
        Ok(())
    }

    fn put_i64(&mut self, value: i64) -> Result<(), ProtocolError> {
        self.ensure(8)?;
        self.bytes.extend_from_slice(&value.to_be_bytes());
        Ok(())
    }

    fn put_bool(&mut self, value: bool) -> Result<(), ProtocolError> {
        self.put_u8(u8::from(value))
    }

    fn put_bytes(&mut self, bytes: &[u8]) -> Result<(), ProtocolError> {
        let length = u32::try_from(bytes.len()).map_err(|_| ProtocolError::FieldTooLarge {
            field: "bytes",
            declared: bytes.len(),
            maximum: u32::MAX as usize,
        })?;
        self.put_u32(length)?;
        self.ensure(bytes.len())?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn put_string(
        &mut self,
        value: &str,
        field: &'static str,
        maximum: usize,
    ) -> Result<(), ProtocolError> {
        if value.len() > maximum {
            return Err(ProtocolError::FieldTooLarge {
                field,
                declared: value.len(),
                maximum,
            });
        }
        self.put_bytes(value.as_bytes())
    }

    fn put_optional_string(
        &mut self,
        value: Option<&str>,
        field: &'static str,
        maximum: usize,
    ) -> Result<(), ProtocolError> {
        match value {
            Some(value) => {
                self.put_bool(true)?;
                self.put_string(value, field, maximum)
            }
            None => self.put_bool(false),
        }
    }

    fn put_optional_bytes(
        &mut self,
        value: Option<&[u8]>,
        field: &'static str,
        maximum: usize,
    ) -> Result<(), ProtocolError> {
        match value {
            Some(value) => {
                if value.len() > maximum {
                    return Err(ProtocolError::FieldTooLarge {
                        field,
                        declared: value.len(),
                        maximum,
                    });
                }
                self.put_bool(true)?;
                self.put_bytes(value)
            }
            None => self.put_bool(false),
        }
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ProtocolError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(ProtocolError::LengthMismatch {
                declared: length,
                actual: self.remaining(),
            })?;
        if end > self.bytes.len() {
            return Err(ProtocolError::Incomplete {
                needed: end - self.bytes.len(),
            });
        }
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, ProtocolError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ProtocolError> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| ProtocolError::Incomplete { needed: 2 })?,
        ))
    }

    fn u32(&mut self) -> Result<u32, ProtocolError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| ProtocolError::Incomplete { needed: 4 })?,
        ))
    }

    fn u64(&mut self) -> Result<u64, ProtocolError> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| ProtocolError::Incomplete { needed: 8 })?,
        ))
    }

    fn i64(&mut self) -> Result<i64, ProtocolError> {
        Ok(i64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| ProtocolError::Incomplete { needed: 8 })?,
        ))
    }

    fn bool(&mut self, field: &'static str) -> Result<bool, ProtocolError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            value => Err(ProtocolError::InvalidValue {
                field,
                value: u64::from(value),
            }),
        }
    }

    fn bytes(&mut self, field: &'static str, maximum: usize) -> Result<Vec<u8>, ProtocolError> {
        let length = self.u32()? as usize;
        if length > maximum {
            return Err(ProtocolError::FieldTooLarge {
                field,
                declared: length,
                maximum,
            });
        }
        Ok(self.take(length)?.to_vec())
    }

    fn string(&mut self, field: &'static str, maximum: usize) -> Result<String, ProtocolError> {
        let bytes = self.bytes(field, maximum)?;
        String::from_utf8(bytes).map_err(|_| ProtocolError::InvalidUtf8 { field })
    }

    fn optional_string(
        &mut self,
        field: &'static str,
        maximum: usize,
    ) -> Result<Option<String>, ProtocolError> {
        if self.bool(field)? {
            self.string(field, maximum).map(Some)
        } else {
            Ok(None)
        }
    }

    fn optional_bytes(
        &mut self,
        field: &'static str,
        maximum: usize,
    ) -> Result<Option<Vec<u8>>, ProtocolError> {
        if self.bool(field)? {
            self.bytes(field, maximum).map(Some)
        } else {
            Ok(None)
        }
    }

    fn finish(&self) -> Result<(), ProtocolError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(ProtocolError::TrailingBytes {
                count: self.remaining(),
            })
        }
    }
}

fn encode_message(
    writer: &mut Writer,
    message: &RemoteMessage,
    limits: RemoteLimits,
) -> Result<(), ProtocolError> {
    match message {
        RemoteMessage::Profile { profile } => encode_profile(writer, profile, limits),
        RemoteMessage::Plan { plan } => encode_plan(writer, plan, limits),
        RemoteMessage::Properties { properties } => encode_properties(writer, properties, limits),
        RemoteMessage::Start {
            run_id,
            thread_count,
            sender_mode,
        } => {
            writer.put_u64(*run_id)?;
            writer.put_u32(*thread_count)?;
            encode_sender_mode(writer, *sender_mode)
        }
        RemoteMessage::Stop { run_id, mode } => {
            writer.put_u64(*run_id)?;
            writer.put_u8(match mode {
                StopMode::Graceful => 0,
                StopMode::Immediate => 1,
            })
        }
        RemoteMessage::Sample { sample } => encode_sample(writer, sample, limits),
        RemoteMessage::Ack {
            worker,
            stage,
            run_id,
            thread_count,
            sample_watermark,
        } => {
            writer.put_u32(worker.as_u32())?;
            writer.put_u8(ack_stage_to_wire(*stage))?;
            put_optional_u64(writer, *run_id)?;
            put_optional_u32(writer, *thread_count)?;
            put_optional_u64(writer, *sample_watermark)
        }
        RemoteMessage::Failure {
            worker,
            run_id,
            error,
        } => {
            writer.put_u32(worker.as_u32())?;
            put_optional_u64(writer, *run_id)?;
            writer.put_u16(error_code_to_wire(error.code)?)?;
            writer.put_bool(error.retryable)?;
            let message = error.wire_message(limits.max_field_bytes());
            writer.put_string(&message, "error message", limits.max_field_bytes())
        }
    }
}

fn decode_message(
    reader: &mut Reader<'_>,
    kind: MessageKind,
    limits: RemoteLimits,
) -> Result<RemoteMessage, ProtocolError> {
    match kind {
        MessageKind::Profile => {
            decode_profile(reader, limits).map(|profile| RemoteMessage::Profile { profile })
        }
        MessageKind::Plan => decode_plan(reader, limits).map(|plan| RemoteMessage::Plan { plan }),
        MessageKind::Properties => decode_properties(reader, limits)
            .map(|properties| RemoteMessage::Properties { properties }),
        MessageKind::Start => {
            let run_id = reader.u64()?;
            let thread_count = reader.u32()?;
            let sender_mode = decode_sender_mode(reader)?;
            Ok(RemoteMessage::Start {
                run_id,
                thread_count,
                sender_mode,
            })
        }
        MessageKind::Stop => {
            let run_id = reader.u64()?;
            let mode = match reader.u8()? {
                0 => StopMode::Graceful,
                1 => StopMode::Immediate,
                value => {
                    return Err(ProtocolError::InvalidValue {
                        field: "stop mode",
                        value: u64::from(value),
                    });
                }
            };
            Ok(RemoteMessage::Stop { run_id, mode })
        }
        MessageKind::Sample => {
            decode_sample(reader, limits).map(|sample| RemoteMessage::Sample { sample })
        }
        MessageKind::Ack => {
            let worker = WorkerId::new(reader.u32()?);
            let stage = ack_stage_from_wire(reader.u8()?)?;
            let run_id = read_optional_u64(reader)?;
            let thread_count = read_optional_u32(reader)?;
            let sample_watermark = read_optional_u64(reader)?;
            Ok(RemoteMessage::Ack {
                worker,
                stage,
                run_id,
                thread_count,
                sample_watermark,
            })
        }
        MessageKind::Failure => {
            let worker = WorkerId::new(reader.u32()?);
            let run_id = read_optional_u64(reader)?;
            let code = error_code_from_wire(reader.u16()?);
            let retryable = reader.bool("retryable")?;
            let message = reader.string(
                "error message",
                limits.max_field_bytes().min(MAX_WIRE_FAILURE_MESSAGE_BYTES),
            )?;
            let message = sanitize_wire_failure_message(&message, MAX_WIRE_FAILURE_MESSAGE_BYTES);
            Ok(RemoteMessage::Failure {
                worker,
                run_id,
                error: RemoteError::new(code, retryable, message),
            })
        }
    }
}

fn encode_profile(
    writer: &mut Writer,
    profile: &ProfileDescriptor,
    limits: RemoteLimits,
) -> Result<(), ProtocolError> {
    writer.put_string(&profile.id, "profile id", limits.max_field_bytes())?;
    writer.put_string(
        &profile.version,
        "profile version",
        limits.max_field_bytes(),
    )?;
    put_count(
        writer,
        profile.capabilities.len(),
        limits.max_capabilities,
        "capabilities",
    )?;
    for capability in &profile.capabilities {
        writer.put_string(capability, "capability", limits.max_field_bytes())?;
    }
    Ok(())
}

fn decode_profile(
    reader: &mut Reader<'_>,
    limits: RemoteLimits,
) -> Result<ProfileDescriptor, ProtocolError> {
    let id = reader.string("profile id", limits.max_field_bytes())?;
    let version = reader.string("profile version", limits.max_field_bytes())?;
    let count = read_count(reader, limits.max_capabilities, "capabilities")?;
    let mut capabilities = Vec::with_capacity(count);
    for _ in 0..count {
        capabilities.push(reader.string("capability", limits.max_field_bytes())?);
    }
    Ok(ProfileDescriptor::new(id, version).with_capabilities(capabilities))
}

fn encode_plan(
    writer: &mut Writer,
    plan: &PlanDescriptor,
    limits: RemoteLimits,
) -> Result<(), ProtocolError> {
    let configuration = limits.configuration;
    if plan.jmx.len() > limits.max_plan_bytes || plan.jmx.len() > configuration.max_plan_bytes {
        return Err(ProtocolError::FieldTooLarge {
            field: "plan",
            declared: plan.jmx.len(),
            maximum: limits.max_plan_bytes.min(configuration.max_plan_bytes),
        });
    }
    let reference_count = plan
        .data_references
        .len()
        .checked_add(plan.dependencies.len())
        .ok_or(ProtocolError::FieldTooLarge {
            field: "plan references",
            declared: usize::MAX,
            maximum: configuration.max_plan_references,
        })?;
    if reference_count > configuration.max_plan_references {
        return Err(ProtocolError::FieldTooLarge {
            field: "plan references",
            declared: reference_count,
            maximum: configuration.max_plan_references,
        });
    }
    let reference_bytes = plan
        .data_references
        .iter()
        .try_fold(0usize, |total, reference| {
            total
                .checked_add(reference.path.len())
                .and_then(|total| total.checked_add(reference.kind.len()))
                .ok_or(ProtocolError::FieldTooLarge {
                    field: "plan reference bytes",
                    declared: usize::MAX,
                    maximum: configuration.max_plan_reference_bytes,
                })
        })?
        .checked_add(
            plan.dependencies
                .iter()
                .try_fold(0usize, |total, dependency| {
                    total
                        .checked_add(dependency.name.len())
                        .and_then(|total| total.checked_add(dependency.version.len()))
                        .ok_or(ProtocolError::FieldTooLarge {
                            field: "plan reference bytes",
                            declared: usize::MAX,
                            maximum: configuration.max_plan_reference_bytes,
                        })
                })?,
        )
        .ok_or(ProtocolError::FieldTooLarge {
            field: "plan reference bytes",
            declared: usize::MAX,
            maximum: configuration.max_plan_reference_bytes,
        })?;
    if reference_bytes > configuration.max_plan_reference_bytes {
        return Err(ProtocolError::FieldTooLarge {
            field: "plan reference bytes",
            declared: reference_bytes,
            maximum: configuration.max_plan_reference_bytes,
        });
    }
    let plan_bytes =
        plan.jmx
            .len()
            .checked_add(reference_bytes)
            .ok_or(ProtocolError::FieldTooLarge {
                field: "plan configuration bytes",
                declared: usize::MAX,
                maximum: configuration.max_configuration_bytes,
            })?;
    if plan_bytes > configuration.max_configuration_bytes {
        return Err(ProtocolError::FieldTooLarge {
            field: "plan configuration bytes",
            declared: plan_bytes,
            maximum: configuration.max_configuration_bytes,
        });
    }
    writer.put_bytes(&plan.jmx)?;
    put_count(
        writer,
        plan.data_references.len(),
        limits.max_references,
        "data references",
    )?;
    for reference in &plan.data_references {
        writer.put_string(
            &reference.path,
            "data reference path",
            limits.max_field_bytes(),
        )?;
        writer.put_string(
            &reference.kind,
            "data reference kind",
            limits.max_field_bytes(),
        )?;
    }
    put_count(
        writer,
        plan.dependencies.len(),
        limits.max_references,
        "dependencies",
    )?;
    for dependency in &plan.dependencies {
        writer.put_string(
            &dependency.name,
            "dependency name",
            limits.max_field_bytes(),
        )?;
        writer.put_string(
            &dependency.version,
            "dependency version",
            limits.max_field_bytes(),
        )?;
    }
    Ok(())
}

fn decode_plan(
    reader: &mut Reader<'_>,
    limits: RemoteLimits,
) -> Result<PlanDescriptor, ProtocolError> {
    let configuration = limits.configuration;
    let jmx = reader.bytes(
        "plan",
        limits.max_plan_bytes.min(configuration.max_plan_bytes),
    )?;
    let data_count = read_count(reader, limits.max_references, "data references")?;
    if data_count > configuration.max_plan_references {
        return Err(ProtocolError::FieldTooLarge {
            field: "plan references",
            declared: data_count,
            maximum: configuration.max_plan_references,
        });
    }
    let mut data_references = Vec::with_capacity(data_count);
    let mut reference_bytes = 0usize;
    for _ in 0..data_count {
        let path = reader.string("data reference path", limits.max_field_bytes())?;
        let kind = reader.string("data reference kind", limits.max_field_bytes())?;
        reference_bytes = reference_bytes
            .checked_add(path.len())
            .and_then(|total| total.checked_add(kind.len()))
            .ok_or(ProtocolError::FieldTooLarge {
                field: "plan reference bytes",
                declared: usize::MAX,
                maximum: configuration.max_plan_reference_bytes,
            })?;
        if reference_bytes > configuration.max_plan_reference_bytes {
            return Err(ProtocolError::FieldTooLarge {
                field: "plan reference bytes",
                declared: reference_bytes,
                maximum: configuration.max_plan_reference_bytes,
            });
        }
        data_references.push(DataReference::new(path, kind));
    }
    let dependency_count = read_count(reader, limits.max_references, "dependencies")?;
    let reference_count =
        data_count
            .checked_add(dependency_count)
            .ok_or(ProtocolError::FieldTooLarge {
                field: "plan references",
                declared: usize::MAX,
                maximum: configuration.max_plan_references,
            })?;
    if reference_count > configuration.max_plan_references {
        return Err(ProtocolError::FieldTooLarge {
            field: "plan references",
            declared: reference_count,
            maximum: configuration.max_plan_references,
        });
    }
    let mut dependencies = Vec::with_capacity(dependency_count);
    for _ in 0..dependency_count {
        let name = reader.string("dependency name", limits.max_field_bytes())?;
        let version = reader.string("dependency version", limits.max_field_bytes())?;
        reference_bytes = reference_bytes
            .checked_add(name.len())
            .and_then(|total| total.checked_add(version.len()))
            .ok_or(ProtocolError::FieldTooLarge {
                field: "plan reference bytes",
                declared: usize::MAX,
                maximum: configuration.max_plan_reference_bytes,
            })?;
        if reference_bytes > configuration.max_plan_reference_bytes {
            return Err(ProtocolError::FieldTooLarge {
                field: "plan reference bytes",
                declared: reference_bytes,
                maximum: configuration.max_plan_reference_bytes,
            });
        }
        dependencies.push(DependencyReference::new(name, version));
    }
    let configuration_bytes =
        jmx.len()
            .checked_add(reference_bytes)
            .ok_or(ProtocolError::FieldTooLarge {
                field: "plan configuration bytes",
                declared: usize::MAX,
                maximum: configuration.max_configuration_bytes,
            })?;
    if configuration_bytes > configuration.max_configuration_bytes {
        return Err(ProtocolError::FieldTooLarge {
            field: "plan configuration bytes",
            declared: configuration_bytes,
            maximum: configuration.max_configuration_bytes,
        });
    }
    Ok(PlanDescriptor::new(jmx).with_references(data_references, dependencies))
}

fn encode_properties(
    writer: &mut Writer,
    properties: &PropertySet,
    limits: RemoteLimits,
) -> Result<(), ProtocolError> {
    let configuration = limits.configuration;
    if properties.values.len() > configuration.max_properties {
        return Err(ProtocolError::FieldTooLarge {
            field: "properties",
            declared: properties.values.len(),
            maximum: configuration.max_properties,
        });
    }
    let property_bytes = properties
        .values
        .iter()
        .try_fold(0usize, |total, (name, value)| {
            total
                .checked_add(name.len())
                .and_then(|total| total.checked_add(value.len()))
                .ok_or(ProtocolError::FieldTooLarge {
                    field: "property bytes",
                    declared: usize::MAX,
                    maximum: configuration.max_property_bytes,
                })
        })?;
    if property_bytes > configuration.max_property_bytes
        || property_bytes > configuration.max_configuration_bytes
    {
        return Err(ProtocolError::FieldTooLarge {
            field: "property bytes",
            declared: property_bytes,
            maximum: configuration
                .max_property_bytes
                .min(configuration.max_configuration_bytes),
        });
    }
    put_count(
        writer,
        properties.values.len(),
        limits.max_properties,
        "properties",
    )?;
    for (name, value) in &properties.values {
        writer.put_string(name, "property name", limits.max_field_bytes())?;
        writer.put_string(value, "property value", limits.max_field_bytes())?;
    }
    Ok(())
}

fn decode_properties(
    reader: &mut Reader<'_>,
    limits: RemoteLimits,
) -> Result<PropertySet, ProtocolError> {
    let configuration = limits.configuration;
    let count = read_count(
        reader,
        limits.max_properties.min(configuration.max_properties),
        "properties",
    )?;
    let mut properties = PropertySet::new();
    let mut property_bytes = 0usize;
    for _ in 0..count {
        let name = reader.string("property name", limits.max_field_bytes())?;
        let value = reader.string("property value", limits.max_field_bytes())?;
        property_bytes = property_bytes
            .checked_add(name.len())
            .and_then(|total| total.checked_add(value.len()))
            .ok_or(ProtocolError::FieldTooLarge {
                field: "property bytes",
                declared: usize::MAX,
                maximum: configuration.max_property_bytes,
            })?;
        if property_bytes > configuration.max_property_bytes
            || property_bytes > configuration.max_configuration_bytes
        {
            return Err(ProtocolError::FieldTooLarge {
                field: "property bytes",
                declared: property_bytes,
                maximum: configuration
                    .max_property_bytes
                    .min(configuration.max_configuration_bytes),
            });
        }
        if properties.insert(name.clone(), value).is_some() {
            return Err(ProtocolError::DuplicateProperty(name));
        }
    }
    Ok(properties)
}

fn encode_sender_mode(writer: &mut Writer, mode: SampleSenderMode) -> Result<(), ProtocolError> {
    if mode.has_zero_bound() {
        return Err(ProtocolError::InvalidValue {
            field: "sample sender bound",
            value: 0,
        });
    }
    match mode {
        SampleSenderMode::Standard => writer.put_u8(0),
        SampleSenderMode::Hold => writer.put_u8(1),
        SampleSenderMode::Batch { size } => {
            writer.put_u8(2)?;
            writer.put_u64(size as u64)
        }
        SampleSenderMode::Statistical { size } => {
            writer.put_u8(3)?;
            writer.put_u64(size as u64)
        }
        SampleSenderMode::Stripped => writer.put_u8(4),
        SampleSenderMode::StrippedBatch { size } => {
            writer.put_u8(5)?;
            writer.put_u64(size as u64)
        }
        SampleSenderMode::Asynch { capacity } => {
            writer.put_u8(6)?;
            writer.put_u64(capacity as u64)
        }
        SampleSenderMode::StrippedAsynch { capacity } => {
            writer.put_u8(7)?;
            writer.put_u64(capacity as u64)
        }
        SampleSenderMode::DiskStore { capacity } => {
            writer.put_u8(8)?;
            writer.put_u64(capacity as u64)
        }
        SampleSenderMode::StrippedDiskStore { capacity } => {
            writer.put_u8(9)?;
            writer.put_u64(capacity as u64)
        }
    }
}

fn decode_sender_mode(reader: &mut Reader<'_>) -> Result<SampleSenderMode, ProtocolError> {
    let kind = reader.u8()?;
    let mode = match kind {
        0 => SampleSenderMode::Standard,
        1 => SampleSenderMode::Hold,
        2 => SampleSenderMode::Batch {
            size: read_usize(reader, "batch size")?,
        },
        3 => SampleSenderMode::Statistical {
            size: read_usize(reader, "statistical size")?,
        },
        4 => SampleSenderMode::Stripped,
        5 => SampleSenderMode::StrippedBatch {
            size: read_usize(reader, "stripped batch size")?,
        },
        6 => SampleSenderMode::Asynch {
            capacity: read_usize(reader, "asynchronous capacity")?,
        },
        7 => SampleSenderMode::StrippedAsynch {
            capacity: read_usize(reader, "stripped asynchronous capacity")?,
        },
        8 => SampleSenderMode::DiskStore {
            capacity: read_usize(reader, "disk-store capacity")?,
        },
        9 => SampleSenderMode::StrippedDiskStore {
            capacity: read_usize(reader, "stripped disk-store capacity")?,
        },
        value => {
            return Err(ProtocolError::InvalidValue {
                field: "sample sender mode",
                value: u64::from(value),
            });
        }
    };
    if mode.has_zero_bound() {
        return Err(ProtocolError::InvalidValue {
            field: "sample sender bound",
            value: 0,
        });
    }
    Ok(mode)
}

fn encode_sample(
    writer: &mut Writer,
    sample: &RemoteSample,
    limits: RemoteLimits,
) -> Result<(), ProtocolError> {
    // Encode the event into a bounded probe first.  Decoding that probe and
    // comparing the public result value catches private JTL metadata which
    // the schema does not carry (aliases, opaque XML extensions,
    // per-node metadata, and assertion extensions).  Returning a typed
    // capability error is preferable to silently canonicalizing such input.
    let mut event_writer = Writer::new(writer.maximum);
    encode_event(&mut event_writer, sample.event(), limits)?;
    let event_bytes = event_writer.finish();
    let mut event_reader = Reader::new(&event_bytes);
    let decoded_event = decode_event(&mut event_reader, limits)?;
    event_reader.finish()?;
    if decoded_event != *sample.event() {
        return Err(ProtocolError::UnsupportedCapability(
            RESULT_WIRE_METADATA_CAPABILITY,
        ));
    }
    writer.put_u64(sample.run_id)?;
    writer.put_u32(sample.worker().as_u32())?;
    writer.put_u64(sample.sequence())?;
    writer.append(&event_bytes)
}

fn decode_sample(
    reader: &mut Reader<'_>,
    limits: RemoteLimits,
) -> Result<RemoteSample, ProtocolError> {
    let run_id = reader.u64()?;
    let worker = WorkerId::new(reader.u32()?);
    let sequence = reader.u64()?;
    let event = decode_event(reader, limits)?;
    Ok(RemoteSample::new(run_id, worker, sequence, event))
}

fn encode_event(
    writer: &mut Writer,
    event: &SampleEvent,
    limits: RemoteLimits,
) -> Result<(), ProtocolError> {
    let validation = ValidationLimits::new(limits.max_sample_depth, limits.max_sample_nodes)
        .map_err(|error| ProtocolError::InvalidSample(error.to_string()))?;
    event
        .result()
        .validate_wire_with_limits(validation)
        .map_err(|error| ProtocolError::InvalidSample(error.to_string()))?;
    writer.put_string(
        event.run().as_str(),
        "run identity",
        limits.max_field_bytes(),
    )?;
    writer.put_string(
        event.thread().name(),
        "thread name",
        limits.max_field_bytes(),
    )?;
    writer.put_optional_string(
        event.thread().group(),
        "thread group",
        limits.max_field_bytes(),
    )?;
    put_optional_u64(writer, event.thread().number())?;
    writer.put_string(
        event.host().as_str(),
        "host identity",
        limits.max_field_bytes(),
    )?;
    put_count(
        writer,
        event.variables().len(),
        limits.max_references,
        "sample variables",
    )?;
    for (name, value) in event.variables().iter() {
        writer.put_string(name, "sample variable name", limits.max_field_bytes())?;
        match value.as_str() {
            Some(value) => {
                writer.put_bool(true)?;
                writer.put_string(value, "sample variable value", limits.max_field_bytes())?;
            }
            None => writer.put_bool(false)?,
        }
    }
    writer.put_u8(match event.transaction_state() {
        None => 0,
        Some(TransactionState::Start) => 1,
        Some(TransactionState::End) => 2,
    })?;
    encode_result(writer, event.result(), limits, 1)
}

fn decode_event(
    reader: &mut Reader<'_>,
    limits: RemoteLimits,
) -> Result<SampleEvent, ProtocolError> {
    let run = reader.string("run identity", limits.max_field_bytes())?;
    let thread_name = reader.string("thread name", limits.max_field_bytes())?;
    let thread_group = reader.optional_string("thread group", limits.max_field_bytes())?;
    let thread_number = read_optional_u64(reader)?;
    let host = reader.string("host identity", limits.max_field_bytes())?;
    let variable_count = read_count(reader, limits.max_references, "sample variables")?;
    let mut variables = VariableSnapshot::new();
    for _ in 0..variable_count {
        let name = reader.string("sample variable name", limits.max_field_bytes())?;
        let value = if reader.bool("sample variable present")? {
            Some(reader.string("sample variable value", limits.max_field_bytes())?)
        } else {
            None
        };
        if variables.insert(name, value).is_some() {
            return Err(ProtocolError::DuplicateProperty(
                "sample variable".to_owned(),
            ));
        }
    }
    let transaction_state = match reader.u8()? {
        0 => None,
        1 => Some(TransactionState::Start),
        2 => Some(TransactionState::End),
        value => {
            return Err(ProtocolError::InvalidValue {
                field: "transaction state",
                value: u64::from(value),
            });
        }
    };
    let mut nodes = 0usize;
    let result = decode_result(reader, limits, 1, &mut nodes)?;
    let thread = ThreadIdentity::with_group(thread_name, thread_group, thread_number);
    // The result was validated by `decode_result` with wire timing semantics;
    // constructing the event without runtime validation preserves independent
    // JTL latency/connect/idle fields exactly as received.
    let event = SampleEvent::new(result, run, thread, host, variables);
    Ok(event.with_transaction_state(transaction_state))
}

fn encode_result(
    writer: &mut Writer,
    result: &SampleResult,
    limits: RemoteLimits,
    depth: usize,
) -> Result<(), ProtocolError> {
    if depth > limits.max_sample_depth {
        return Err(ProtocolError::FieldTooLarge {
            field: "sample depth",
            declared: depth,
            maximum: limits.max_sample_depth,
        });
    }
    writer.put_bool(result.has_label())?;
    if result.has_label() {
        writer.put_string(result.label(), "sample label", limits.max_field_bytes())?;
    }
    encode_timing(writer, result.timing())?;
    put_optional_bool(writer, result.success())?;
    writer.put_optional_string(
        result.response_code(),
        "response code",
        limits.max_field_bytes(),
    )?;
    writer.put_optional_string(
        result.response_message(),
        "response message",
        limits.max_field_bytes(),
    )?;
    writer.put_optional_string(
        result.failure_message(),
        "failure message",
        limits.max_field_bytes(),
    )?;
    match result.data_type() {
        Some(value) => {
            writer.put_bool(true)?;
            writer.put_string(value.as_wire(), "data type", limits.max_field_bytes())?;
        }
        None => writer.put_bool(false)?,
    }
    match result.data_encoding() {
        Some(value) => {
            writer.put_bool(true)?;
            writer.put_string(value.as_str(), "data encoding", limits.max_field_bytes())?;
        }
        None => writer.put_bool(false)?,
    }
    writer.put_optional_bytes(
        result.request_data().map(SampleData::as_bytes),
        "request data",
        limits.max_field_bytes(),
    )?;
    writer.put_optional_bytes(
        result.response_data().map(SampleData::as_bytes),
        "response data",
        limits.max_field_bytes(),
    )?;
    writer.put_optional_string(
        result.request_headers().map(HeaderBlock::as_str),
        "request headers",
        limits.max_field_bytes(),
    )?;
    writer.put_optional_string(
        result.response_headers().map(HeaderBlock::as_str),
        "response headers",
        limits.max_field_bytes(),
    )?;
    writer.put_optional_string(
        result.sampler_data(),
        "sampler data",
        limits.max_field_bytes(),
    )?;
    writer.put_optional_string(
        result.response_file(),
        "response file",
        limits.max_field_bytes(),
    )?;
    writer.put_optional_string(result.url(), "url", limits.max_field_bytes())?;
    put_optional_u64(writer, result.received_bytes().map(|value| value.as_u64()))?;
    put_optional_u64(writer, result.sent_bytes().map(|value| value.as_u64()))?;
    put_optional_u64(writer, result.group_threads().map(|value| value.as_u64()))?;
    put_optional_u64(writer, result.all_threads().map(|value| value.as_u64()))?;
    put_optional_u64(writer, result.sample_count().map(|value| value.as_u64()))?;
    put_optional_u64(writer, result.error_count().map(|value| value.as_u64()))?;
    put_count(
        writer,
        result.assertions().len(),
        limits.max_references,
        "assertions",
    )?;
    for assertion in result.assertions() {
        writer.put_string(assertion.name(), "assertion name", limits.max_field_bytes())?;
        writer.put_u8(match (assertion.is_failure(), assertion.is_error()) {
            (false, false) => 0,
            (true, false) => 1,
            (false, true) => 2,
            (true, true) => 3,
        })?;
        writer.put_optional_string(
            assertion.failure_message(),
            "assertion failure",
            limits.max_field_bytes(),
        )?;
        writer.put_optional_string(
            assertion.error_message(),
            "assertion error",
            limits.max_field_bytes(),
        )?;
    }
    put_count(
        writer,
        result.sub_results().len(),
        limits.max_references,
        "sub-results",
    )?;
    for child in result.sub_results() {
        encode_result(writer, child, limits, depth + 1)?;
    }
    writer.put_bool(result.stop_thread())?;
    writer.put_bool(result.stop_test())?;
    writer.put_bool(result.stop_test_now())?;
    writer.put_bool(result.start_next_loop())?;
    writer.put_u8(match result.logical_action() {
        None => 0,
        Some(LogicalAction::Continue) => 1,
        Some(LogicalAction::StartNextIteration) => 2,
        Some(LogicalAction::StopThread) => 3,
        Some(LogicalAction::StopTest) => 4,
        Some(LogicalAction::StopTestNow) => 5,
    })?;
    writer.put_bool(result.ignored())
}

fn decode_result(
    reader: &mut Reader<'_>,
    limits: RemoteLimits,
    depth: usize,
    nodes: &mut usize,
) -> Result<SampleResult, ProtocolError> {
    if depth > limits.max_sample_depth {
        return Err(ProtocolError::FieldTooLarge {
            field: "sample depth",
            declared: depth,
            maximum: limits.max_sample_depth,
        });
    }
    *nodes = nodes.checked_add(1).ok_or(ProtocolError::FieldTooLarge {
        field: "sample nodes",
        declared: usize::MAX,
        maximum: limits.max_sample_nodes,
    })?;
    if *nodes > limits.max_sample_nodes {
        return Err(ProtocolError::FieldTooLarge {
            field: "sample nodes",
            declared: *nodes,
            maximum: limits.max_sample_nodes,
        });
    }
    let has_label = reader.bool("sample label present")?;
    let mut result = if has_label {
        SampleResult::new(reader.string("sample label", limits.max_field_bytes())?)
    } else {
        SampleResult::without_label()
    };
    let timing = decode_timing(reader)?;
    result.set_timing_from_wire(timing);
    result.set_success(read_optional_bool(reader)?);
    result.set_response_code(reader.optional_string("response code", limits.max_field_bytes())?);
    result.set_response_message(
        reader.optional_string("response message", limits.max_field_bytes())?,
    );
    result
        .set_failure_message(reader.optional_string("failure message", limits.max_field_bytes())?);
    if reader.bool("data type present")? {
        result.set_data_type(Some(DataType::from_wire(
            reader.string("data type", limits.max_field_bytes())?,
        )));
    }
    if reader.bool("data encoding present")? {
        result.set_data_encoding(Some(DataEncoding::new(
            reader.string("data encoding", limits.max_field_bytes())?,
        )));
    }
    result.set_request_data(
        reader
            .optional_bytes("request data", limits.max_field_bytes())?
            .map(SampleData::new),
    );
    result.set_response_data(
        reader
            .optional_bytes("response data", limits.max_field_bytes())?
            .map(SampleData::new),
    );
    result.set_request_headers(
        reader
            .optional_string("request headers", limits.max_field_bytes())?
            .map(HeaderBlock::new),
    );
    result.set_response_headers(
        reader
            .optional_string("response headers", limits.max_field_bytes())?
            .map(HeaderBlock::new),
    );
    result.set_sampler_data(reader.optional_string("sampler data", limits.max_field_bytes())?);
    result.set_response_file(reader.optional_string("response file", limits.max_field_bytes())?);
    result.set_url(reader.optional_string("url", limits.max_field_bytes())?);
    result.set_received_bytes(read_optional_u64(reader)?.map(Into::into));
    result.set_sent_bytes(read_optional_u64(reader)?.map(Into::into));
    result.set_group_threads(read_optional_u64(reader)?.map(Into::into));
    result.set_all_threads(read_optional_u64(reader)?.map(Into::into));
    result.set_sample_count(read_optional_u64(reader)?.map(Into::into));
    result.set_error_count(read_optional_u64(reader)?.map(Into::into));
    let assertion_count = read_count(reader, limits.max_references, "assertions")?;
    for _ in 0..assertion_count {
        let name = reader.string("assertion name", limits.max_field_bytes())?;
        let (failure_flag, error_flag) = match reader.u8()? {
            0 => (false, false),
            1 => (true, false),
            2 => (false, true),
            3 => (true, true),
            value => {
                return Err(ProtocolError::InvalidValue {
                    field: "assertion outcome",
                    value: u64::from(value),
                });
            }
        };
        let failure_message =
            reader.optional_string("assertion failure", limits.max_field_bytes())?;
        let error_message = reader.optional_string("assertion error", limits.max_field_bytes())?;
        result
            .try_add_assertion(
                AssertionResult::from_flags(
                    name,
                    failure_flag,
                    error_flag,
                    failure_message,
                    error_message,
                )
                .map_err(|error| ProtocolError::InvalidSample(error.to_string()))?,
            )
            .map_err(|error| ProtocolError::InvalidSample(error.to_string()))?;
    }
    let child_count = read_count(reader, limits.max_references, "sub-results")?;
    let mut children = Vec::with_capacity(child_count);
    for _ in 0..child_count {
        children.push(decode_result(reader, limits, depth + 1, nodes)?);
    }
    result
        .try_add_sub_results_raw(
            children,
            ValidationLimits::new(limits.max_sample_depth, limits.max_sample_nodes)
                .map_err(|error| ProtocolError::InvalidSample(error.to_string()))?,
        )
        .map_err(|error| ProtocolError::InvalidSample(error.to_string()))?;
    let stop_thread = reader.bool("stop thread")?;
    let stop_test = reader.bool("stop test")?;
    let stop_test_now = reader.bool("stop test now")?;
    let start_next_loop = reader.bool("start next loop")?;
    let logical_action = match reader.u8()? {
        0 => None,
        1 => Some(LogicalAction::Continue),
        2 => Some(LogicalAction::StartNextIteration),
        3 => Some(LogicalAction::StopThread),
        4 => Some(LogicalAction::StopTest),
        5 => Some(LogicalAction::StopTestNow),
        value => {
            return Err(ProtocolError::InvalidValue {
                field: "logical action",
                value: u64::from(value),
            });
        }
    };
    let ignored = reader.bool("ignored")?;
    result.set_stop_thread(stop_thread);
    result.set_stop_test(stop_test);
    result.set_stop_test_now(stop_test_now);
    result.set_start_next_loop(start_next_loop);
    result.set_logical_action(logical_action);
    result.set_ignored(ignored);
    result
        .validate_wire_with_limits(
            ValidationLimits::new(limits.max_sample_depth, limits.max_sample_nodes)
                .map_err(|error| ProtocolError::InvalidSample(error.to_string()))?,
        )
        .map_err(|error| ProtocolError::InvalidSample(error.to_string()))?;
    Ok(result)
}

fn encode_timing(writer: &mut Writer, timing: &SampleTiming) -> Result<(), ProtocolError> {
    put_optional_i64(writer, timing.timestamp().map(WallTimestamp::as_millis))?;
    put_optional_i64(writer, timing.start().map(WallTimestamp::as_millis))?;
    put_optional_i64(writer, timing.end().map(WallTimestamp::as_millis))?;
    put_optional_u64(writer, timing.elapsed().map(ElapsedTime::as_millis))?;
    put_optional_u64(writer, timing.latency().map(|value| value.as_millis()))?;
    put_optional_u64(writer, timing.connect().map(|value| value.as_millis()))?;
    put_optional_u64(writer, timing.idle().map(|value| value.as_millis()))
}

fn decode_timing(reader: &mut Reader<'_>) -> Result<SampleTiming, ProtocolError> {
    let timestamp = read_optional_i64(reader)?.map(WallTimestamp::from_millis);
    let start = read_optional_i64(reader)?.map(WallTimestamp::from_millis);
    let end = read_optional_i64(reader)?.map(WallTimestamp::from_millis);
    let elapsed = read_optional_u64(reader)?.map(ElapsedTime::from_millis);
    let latency = read_optional_u64(reader)?.map(jmeter_rs_results::Latency::from_millis);
    let connect = read_optional_u64(reader)?.map(jmeter_rs_results::ConnectTime::from_millis);
    let idle = read_optional_u64(reader)?.map(jmeter_rs_results::IdleTime::from_millis);
    Ok(SampleTiming::from_wire_parts(
        timestamp, start, end, elapsed, latency, connect, idle,
    ))
}

fn put_count(
    writer: &mut Writer,
    value: usize,
    maximum: usize,
    field: &'static str,
) -> Result<(), ProtocolError> {
    if value > maximum {
        return Err(ProtocolError::FieldTooLarge {
            field,
            declared: value,
            maximum,
        });
    }
    writer.put_u32(
        u32::try_from(value).map_err(|_| ProtocolError::FieldTooLarge {
            field,
            declared: value,
            maximum: maximum.min(u32::MAX as usize),
        })?,
    )
}

fn read_count(
    reader: &mut Reader<'_>,
    maximum: usize,
    field: &'static str,
) -> Result<usize, ProtocolError> {
    let value = reader.u32()? as usize;
    if value > maximum {
        return Err(ProtocolError::FieldTooLarge {
            field,
            declared: value,
            maximum,
        });
    }
    Ok(value)
}

fn put_optional_u64(writer: &mut Writer, value: Option<u64>) -> Result<(), ProtocolError> {
    match value {
        Some(value) => {
            writer.put_bool(true)?;
            writer.put_u64(value)
        }
        None => writer.put_bool(false),
    }
}

fn read_optional_u64(reader: &mut Reader<'_>) -> Result<Option<u64>, ProtocolError> {
    if reader.bool("optional u64")? {
        reader.u64().map(Some)
    } else {
        Ok(None)
    }
}

fn put_optional_u32(writer: &mut Writer, value: Option<u32>) -> Result<(), ProtocolError> {
    match value {
        Some(value) => {
            writer.put_bool(true)?;
            writer.put_u32(value)
        }
        None => writer.put_bool(false),
    }
}

fn read_optional_u32(reader: &mut Reader<'_>) -> Result<Option<u32>, ProtocolError> {
    if reader.bool("optional u32")? {
        reader.u32().map(Some)
    } else {
        Ok(None)
    }
}

fn put_optional_i64(writer: &mut Writer, value: Option<i64>) -> Result<(), ProtocolError> {
    match value {
        Some(value) => {
            writer.put_bool(true)?;
            writer.put_i64(value)
        }
        None => writer.put_bool(false),
    }
}

fn read_optional_i64(reader: &mut Reader<'_>) -> Result<Option<i64>, ProtocolError> {
    if reader.bool("optional i64")? {
        reader.i64().map(Some)
    } else {
        Ok(None)
    }
}

fn put_optional_bool(writer: &mut Writer, value: Option<bool>) -> Result<(), ProtocolError> {
    match value {
        None => writer.put_u8(0),
        Some(false) => writer.put_u8(1),
        Some(true) => writer.put_u8(2),
    }
}

fn read_optional_bool(reader: &mut Reader<'_>) -> Result<Option<bool>, ProtocolError> {
    match reader.u8()? {
        0 => Ok(None),
        1 => Ok(Some(false)),
        2 => Ok(Some(true)),
        value => Err(ProtocolError::InvalidValue {
            field: "optional bool",
            value: u64::from(value),
        }),
    }
}

fn read_usize(reader: &mut Reader<'_>, field: &'static str) -> Result<usize, ProtocolError> {
    let value = reader.u64()?;
    usize::try_from(value).map_err(|_| ProtocolError::FieldTooLarge {
        field,
        declared: usize::MAX,
        maximum: usize::MAX,
    })
}

fn ack_stage_to_wire(stage: AckStage) -> u8 {
    match stage {
        AckStage::Profile => 0,
        AckStage::Plan => 1,
        AckStage::Properties => 2,
        AckStage::Started => 3,
        AckStage::Stopped => 4,
    }
}

fn ack_stage_from_wire(value: u8) -> Result<AckStage, ProtocolError> {
    match value {
        0 => Ok(AckStage::Profile),
        1 => Ok(AckStage::Plan),
        2 => Ok(AckStage::Properties),
        3 => Ok(AckStage::Started),
        4 => Ok(AckStage::Stopped),
        value => Err(ProtocolError::InvalidValue {
            field: "ack stage",
            value: u64::from(value),
        }),
    }
}

fn error_code_to_wire(code: crate::RemoteErrorCode) -> Result<u16, ProtocolError> {
    let value = match code {
        crate::RemoteErrorCode::Protocol => 1,
        crate::RemoteErrorCode::ResourceLimit => 2,
        crate::RemoteErrorCode::ProfileMismatch => 3,
        crate::RemoteErrorCode::CapabilityUnavailable => 4,
        crate::RemoteErrorCode::InvalidState => 5,
        crate::RemoteErrorCode::WorkerFailure => 6,
        crate::RemoteErrorCode::ConflictingDuplicate => 7,
        crate::RemoteErrorCode::InvalidSample => 8,
        crate::RemoteErrorCode::Backpressure => 9,
        crate::RemoteErrorCode::Cancelled => 10,
        crate::RemoteErrorCode::Internal => 11,
        crate::RemoteErrorCode::DeadlineExceeded => 12,
        crate::RemoteErrorCode::ContextUnavailable => 13,
        crate::RemoteErrorCode::Unknown(value) => {
            if (1..=13).contains(&value) {
                return Err(ProtocolError::InvalidValue {
                    field: "remote error code",
                    value: u64::from(value),
                });
            }
            value
        }
    };
    Ok(value)
}

fn error_code_from_wire(value: u16) -> crate::RemoteErrorCode {
    match value {
        1 => crate::RemoteErrorCode::Protocol,
        2 => crate::RemoteErrorCode::ResourceLimit,
        3 => crate::RemoteErrorCode::ProfileMismatch,
        4 => crate::RemoteErrorCode::CapabilityUnavailable,
        5 => crate::RemoteErrorCode::InvalidState,
        6 => crate::RemoteErrorCode::WorkerFailure,
        7 => crate::RemoteErrorCode::ConflictingDuplicate,
        8 => crate::RemoteErrorCode::InvalidSample,
        9 => crate::RemoteErrorCode::Backpressure,
        10 => crate::RemoteErrorCode::Cancelled,
        11 => crate::RemoteErrorCode::Internal,
        12 => crate::RemoteErrorCode::DeadlineExceeded,
        13 => crate::RemoteErrorCode::ContextUnavailable,
        value => crate::RemoteErrorCode::Unknown(value),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)] // Test fixtures use expect for assertion-context failures.
mod tests {
    use super::*;

    fn event(label: &str) -> SampleEvent {
        SampleEvent::new(
            SampleResult::new(label),
            "run",
            ThreadIdentity::with_group("thread", Some("group".to_owned()), Some(1)),
            "worker",
            VariableSnapshot::from_iter([(String::from("v"), String::from("value"))]),
        )
    }

    #[test]
    fn envelope_round_trips_all_configuration_fields() {
        let plan = PlanDescriptor::new(b"<testPlan/>".to_vec()).with_references(
            vec![DataReference::new("data.csv", "csv")],
            vec![DependencyReference::new("driver", "1")],
        );
        let mut properties = PropertySet::new();
        properties.insert("k", "v");
        let messages = [
            RemoteMessage::Profile {
                profile: ProfileDescriptor::new("jmeter-5.6.3", "1"),
            },
            RemoteMessage::Plan { plan },
            RemoteMessage::Properties { properties },
            RemoteMessage::Start {
                run_id: 9,
                thread_count: 4,
                sender_mode: SampleSenderMode::StrippedBatch { size: 2 },
            },
            RemoteMessage::Stop {
                run_id: 9,
                mode: StopMode::Graceful,
            },
            RemoteMessage::Sample {
                sample: RemoteSample::new(9, WorkerId::new(2), 3, event("sample")),
            },
            RemoteMessage::Ack {
                worker: WorkerId::new(2),
                stage: AckStage::Started,
                run_id: Some(9),
                thread_count: Some(4),
                sample_watermark: None,
            },
            RemoteMessage::Failure {
                worker: WorkerId::new(2),
                run_id: Some(9),
                error: RemoteError::new(crate::RemoteErrorCode::Unknown(4095), true, "retry"),
            },
        ];
        let codec = RemoteCodec::default();
        for (request_id, message) in messages.into_iter().enumerate() {
            let request_id = match &message {
                RemoteMessage::Sample { sample } => {
                    sample_envelope_request_id(sample.worker(), sample.sequence() + 1)
                        .expect("sample envelope ID")
                }
                _ => request_id as u64 + 1,
            };
            let envelope = RemoteEnvelope::new(request_id, message);
            let encoded = codec.encode(&envelope).expect("encode");
            assert_eq!(codec.decode(&encoded).expect("decode"), envelope);
        }
    }

    #[test]
    fn codec_rejects_version_trailing_and_oversize_before_allocating_payload() {
        let codec = RemoteCodec::new(RemoteLimits::new(64));
        let envelope = RemoteEnvelope::new(
            1,
            RemoteMessage::Plan {
                plan: PlanDescriptor::new(vec![1; 20]),
            },
        );
        let encoded = codec.encode(&envelope).expect("small plan encodes");
        let mut version = encoded.clone();
        version[5] = (REMOTE_PROTOCOL_VERSION + 1) as u8;
        assert!(matches!(
            codec.decode(&version),
            Err(ProtocolError::UnsupportedVersion(version))
                if version == REMOTE_PROTOCOL_VERSION + 1
        ));
        let mut trailing = encoded.clone();
        trailing.push(1);
        assert!(matches!(
            codec.decode(&trailing),
            Err(ProtocolError::TrailingBytes { count: 1 })
        ));
        let mut oversized = encoded;
        oversized[16..20].copy_from_slice(&(u32::MAX).to_be_bytes());
        assert!(matches!(
            codec.decode(&oversized),
            Err(ProtocolError::MessageTooLarge { .. })
        ));
    }

    #[test]
    fn sender_modes_encode_nonzero_bounds_only() {
        let codec = RemoteCodec::default();
        for mode in [
            SampleSenderMode::Batch { size: 0 },
            SampleSenderMode::Asynch { capacity: 0 },
            SampleSenderMode::DiskStore { capacity: 0 },
        ] {
            let result = codec.encode(&RemoteEnvelope::new(
                1,
                RemoteMessage::Start {
                    run_id: 1,
                    thread_count: 1,
                    sender_mode: mode,
                },
            ));
            assert!(matches!(
                result,
                Err(ProtocolError::InvalidValue {
                    field: "sample sender bound",
                    value: 0
                })
            ));
        }
    }

    #[test]
    fn plan_wire_contains_jmx_and_references_but_no_dependency_payload() {
        let plan = PlanDescriptor::new(b"<testPlan/>".to_vec()).with_references(
            vec![DataReference::new("worker.csv", "csv")],
            vec![DependencyReference::new("driver", "1")],
        );
        let encoded = RemoteCodec::default()
            .encode(&RemoteEnvelope::new(1, RemoteMessage::Plan { plan }))
            .expect("plan encodes");
        assert!(
            encoded
                .windows(b"worker.csv".len())
                .any(|window| window == b"worker.csv")
        );
        assert!(
            encoded
                .windows(b"driver".len())
                .any(|window| window == b"driver")
        );
        assert!(
            !encoded
                .windows(b"dependency-payload".len())
                .any(|window| window == b"dependency-payload")
        );
    }

    #[test]
    fn assertion_failure_and_error_flags_survive_remote_round_trip() {
        let mut result = SampleResult::new("assertions");
        result
            .try_add_assertion(
                AssertionResult::from_flags(
                    "both",
                    true,
                    true,
                    Some("failure".to_owned()),
                    Some("error".to_owned()),
                )
                .expect("assertion"),
            )
            .expect("assertion is retained");
        let event = SampleEvent::new(
            result,
            "run",
            ThreadIdentity::new("thread"),
            "worker",
            VariableSnapshot::new(),
        );
        let sample = RemoteSample::new(1, WorkerId::new(1), 1, event);
        let envelope = RemoteEnvelope::new(
            sample_envelope_request_id(sample.worker(), sample.sequence() + 1)
                .expect("sample namespace"),
            RemoteMessage::Sample { sample },
        );
        let codec = RemoteCodec::default();
        let decoded = codec.decode(&codec.encode(&envelope).expect("encode"));
        let RemoteMessage::Sample { sample } = decoded.expect("decode").message else {
            return;
        };
        let assertion = sample
            .event()
            .result()
            .assertions()
            .first()
            .expect("assertion");
        assert!(assertion.is_failure());
        assert!(assertion.is_error());
        assert_eq!(assertion.failure_message(), Some("failure"));
        assert_eq!(assertion.error_message(), Some("error"));
    }

    #[test]
    fn noncanonical_jtl_wire_metadata_returns_typed_capability_error() {
        let fixtures = [
            br#"<testResults version="1.2" customRoot="root"><httpSample tn="root-thread" hn="root-host" plugin__root="root"><sample tn="child-thread" hn="child-host" plugin__child="child"><pluginData/></sample></httpSample><rootExtension/></testResults>"#.as_slice(),
            br#"<testResults version="1.2"><sample><assertionResult class="plugin.Assertion"><name>check</name><failure>false</failure><error>false</error><pluginAssertionChild/></assertionResult></sample></testResults>"#.as_slice(),
        ];
        for fixture in fixtures {
            let configuration = jmeter_rs_results::XmlDecodeConfiguration::new()
                .with_reject_unknown_attributes(false);
            let events = jmeter_rs_results::decode_xml_with_configuration(
                fixture,
                jmeter_rs_results::JtlLimits::default(),
                configuration,
            )
            .expect("noncanonical metadata fixture decodes");
            let sample = RemoteSample::new(1, WorkerId::new(1), 1, events[0].clone());
            let envelope = RemoteEnvelope::new(
                sample_envelope_request_id(sample.worker(), sample.sequence()).expect("sample ID"),
                RemoteMessage::Sample { sample },
            );
            let error = RemoteCodec::default()
                .encode(&envelope)
                .expect_err("metadata must not be silently discarded");
            assert!(matches!(
                error,
                ProtocolError::UnsupportedCapability(RESULT_WIRE_METADATA_CAPABILITY)
            ));
            assert_eq!(error.code(), crate::RemoteErrorCode::CapabilityUnavailable);
            assert_eq!(
                error.to_string(),
                "remote capability remote.result-wire-metadata is unavailable"
            );
        }
    }

    #[test]
    fn unknown_error_codes_cannot_alias_known_wire_codes() {
        let result = RemoteCodec::default().encode(&RemoteEnvelope::new(
            1,
            RemoteMessage::Failure {
                worker: WorkerId::new(1),
                run_id: None,
                error: RemoteError::new(crate::RemoteErrorCode::Unknown(1), false, "bad code"),
            },
        ));
        assert!(matches!(
            result,
            Err(ProtocolError::InvalidValue {
                field: "remote error code",
                value: 1
            })
        ));
    }

    #[test]
    fn invalid_sample_protocol_errors_keep_the_sample_code() {
        assert_eq!(
            ProtocolError::InvalidSample("bad timing".to_owned()).code(),
            crate::RemoteErrorCode::InvalidSample
        );
    }

    #[test]
    fn deadline_error_code_is_stable_on_the_failure_wire() {
        let envelope = RemoteEnvelope::new(
            1,
            RemoteMessage::Failure {
                worker: WorkerId::new(1),
                run_id: None,
                error: RemoteError::new(
                    crate::RemoteErrorCode::DeadlineExceeded,
                    false,
                    "deadline",
                ),
            },
        );
        let codec = RemoteCodec::default();
        let decoded = codec
            .decode(&codec.encode(&envelope).expect("deadline encodes"))
            .expect("deadline decodes");
        let RemoteMessage::Failure { error, .. } = decoded.message else {
            return;
        };
        assert_eq!(error.code, crate::RemoteErrorCode::DeadlineExceeded);
    }

    #[test]
    fn adapter_codec_requires_out_of_band_context() {
        let envelope = RemoteEnvelope::new(
            1,
            RemoteMessage::Profile {
                profile: ProfileDescriptor::new("profile", "version"),
            },
        );
        let codec = RemoteCodec::default();
        assert!(matches!(
            codec.encode_for_adapter(&envelope, None, 0),
            Err(error) if error.code == crate::RemoteErrorCode::ContextUnavailable
        ));
        let expired = RemoteRequestContext::new().with_deadline(RemoteDeadline::at_unix_millis(10));
        assert!(matches!(
            codec.encode_for_adapter(&envelope, Some(expired), 10),
            Err(error) if error.code == crate::RemoteErrorCode::DeadlineExceeded
        ));
        let context = RemoteRequestContext::new();
        let bytes = codec
            .encode_for_adapter(&envelope, Some(context), 0)
            .expect("adapter context permits encoding");
        assert_eq!(
            codec
                .decode_for_adapter(&bytes, Some(context), 0)
                .expect("adapter context permits decoding"),
            envelope
        );
    }

    #[test]
    fn configuration_codec_bounds_apply_before_retaining_plan_or_properties() {
        let configuration = RemoteConfigurationLimits::new()
            .with_max_plan_bytes(3)
            .with_max_property_bytes(3)
            .with_max_configuration_bytes(3);
        let codec =
            RemoteCodec::new(RemoteLimits::default().with_configuration_limits(configuration));
        assert!(matches!(
            codec.encode(&RemoteEnvelope::new(
                1,
                RemoteMessage::Plan {
                    plan: PlanDescriptor::new(b"four".to_vec()),
                },
            )),
            Err(ProtocolError::FieldTooLarge { .. })
        ));
        let mut properties = PropertySet::new();
        properties.insert("key", "value");
        assert!(matches!(
            codec.encode(&RemoteEnvelope::new(
                1,
                RemoteMessage::Properties { properties },
            )),
            Err(ProtocolError::FieldTooLarge { .. })
        ));
    }

    #[test]
    fn remote_debug_is_redacted_and_bounded() {
        let secret = "configuration-secret";
        let plan = PlanDescriptor::new(secret.as_bytes().to_vec()).with_references(
            vec![DataReference::new("/secret/path", "csv")],
            vec![DependencyReference::new("secret-driver", "secret-version")],
        );
        let mut properties = PropertySet::new();
        properties.insert("password", secret);
        let envelope = RemoteEnvelope::new(1, RemoteMessage::Properties { properties });
        let output = format!(
            "{:?}{:?}{:?}{:?}",
            plan,
            envelope,
            RemoteError::new(crate::RemoteErrorCode::Internal, false, secret),
            SampleSenderMode::Standard,
        );
        assert!(!output.contains(secret));
        assert!(!output.contains("/secret/path"));
        assert!(!output.contains("secret-driver"));
        assert!(output.len() < 2048);
        let display = RemoteError::new(crate::RemoteErrorCode::Internal, false, secret).to_string();
        assert!(!display.contains(secret));
        assert!(display.contains("message_len"));
    }

    #[test]
    fn wire_limits_are_explicitly_validated_and_shared() {
        let wire = WireLimits::new(1024, 64).expect("finite wire limits");
        let limits = RemoteLimits::default().with_wire_limits(wire);
        assert_eq!(limits.wire_limits(), wire);
        assert!(limits.validate().is_ok());
        assert!(WireLimits::new(REMOTE_HEADER_LEN - 1, 1).is_none());
        assert!(WireLimits::new(REMOTE_HEADER_LEN, 0).is_none());
        assert!(RemoteLimits::new(REMOTE_HEADER_LEN - 1).validate().is_err());
        assert!(RemoteCodec::try_new(limits).is_ok());
    }

    #[test]
    fn codec_rejects_invalid_non_wire_limits_explicitly() {
        let limits = RemoteLimits::default().with_max_plan_bytes(0);
        let envelope = RemoteEnvelope::new(
            1,
            RemoteMessage::Profile {
                profile: ProfileDescriptor::new("profile", "version"),
            },
        );
        assert!(matches!(
            RemoteCodec::new(limits).encode(&envelope),
            Err(ProtocolError::InvalidLimits)
        ));
    }

    #[test]
    fn failure_wire_context_is_bounded_and_redacts_secret_path_and_token() {
        let raw =
            "connect failed path=/srv/jmeter/secret-plan.jmx token=token-value password=hunter2";
        let error = RemoteError::new(crate::RemoteErrorCode::WorkerFailure, true, raw);
        assert_eq!(error.raw_message(), raw);
        let wire = WireLimits::new(1024, 64).expect("wire limits");
        let codec = RemoteCodec::new(RemoteLimits::default().with_wire_limits(wire));
        let envelope = RemoteEnvelope::new(
            1,
            RemoteMessage::Failure {
                worker: WorkerId::new(4),
                run_id: None,
                error,
            },
        );
        let encoded = codec.encode(&envelope).expect("failure encodes");
        assert!(encoded.len() <= 1024);
        let decoded = codec.decode(&encoded).expect("failure decodes");
        assert!(matches!(&decoded.message, RemoteMessage::Failure { .. }));
        let RemoteMessage::Failure { error, .. } = decoded.message else {
            return;
        };
        assert_eq!(error.message(), "<redacted>");
        assert_eq!(error.code, crate::RemoteErrorCode::WorkerFailure);
        assert!(error.retryable);
        assert!(
            !encoded
                .windows(b"token-value".len())
                .any(|window| window == b"token-value")
        );
        assert!(
            !encoded
                .windows(b"/srv/jmeter".len())
                .any(|window| window == b"/srv/jmeter")
        );
    }

    #[test]
    fn failure_wire_context_truncates_without_leaking_a_long_suffix() {
        let raw = "ordinary diagnostic ".to_owned() + &"x".repeat(4096);
        let error = RemoteError::new(crate::RemoteErrorCode::Internal, false, raw.clone());
        let wire = WireLimits::new(1024, 40).expect("wire limits");
        let codec = RemoteCodec::new(RemoteLimits::default().with_wire_limits(wire));
        let encoded = codec
            .encode(&RemoteEnvelope::new(
                1,
                RemoteMessage::Failure {
                    worker: WorkerId::new(1),
                    run_id: None,
                    error,
                },
            ))
            .expect("failure encodes");
        let decoded = codec.decode(&encoded).expect("decode");
        assert!(matches!(&decoded.message, RemoteMessage::Failure { .. }));
        let RemoteMessage::Failure { error, .. } = decoded.message else {
            return;
        };
        assert!(error.message_len() <= 40);
        assert_eq!(error.raw_message(), &raw[..error.message_len()]);
    }

    #[test]
    fn sample_messages_require_the_high_bit_request_namespace() {
        let sample = RemoteSample::new(1, WorkerId::new(3), 1, event("sample"));
        let codec = RemoteCodec::default();
        assert!(matches!(
            codec.encode(&RemoteEnvelope::new(
                4,
                RemoteMessage::Sample {
                    sample: sample.clone()
                },
            )),
            Err(ProtocolError::InvalidValue {
                field: "request id namespace",
                ..
            })
        ));
        let id = sample_envelope_request_id(sample.worker(), sample.sequence() + 1)
            .expect("sample namespace");
        assert!(
            codec
                .decode(
                    &codec
                        .encode(&RemoteEnvelope::new(id, RemoteMessage::Sample { sample },))
                        .expect("sample encode")
                )
                .is_ok()
        );
    }

    #[test]
    fn sample_namespace_correlation_identifies_the_emitting_worker() {
        let sample = RemoteSample::new(1, WorkerId::new(3), 1, event("sample"));
        let wrong_worker_id =
            sample_envelope_request_id(WorkerId::new(4), 1).expect("sample namespace");
        assert!(matches!(
            RemoteCodec::default().encode(&RemoteEnvelope::new(
                wrong_worker_id,
                RemoteMessage::Sample { sample },
            )),
            Err(ProtocolError::InvalidValue {
                field: "sample request worker",
                ..
            })
        ));
    }

    #[test]
    fn wire_timing_preserves_independent_component_values() {
        let mut result = SampleResult::new("wire-timing");
        result.set_timing_from_wire(SampleTiming::from_wire_parts(
            Some(WallTimestamp::from_millis(100)),
            Some(WallTimestamp::from_millis(100)),
            Some(WallTimestamp::from_millis(101)),
            Some(ElapsedTime::from_millis(1)),
            Some(jmeter_rs_results::Latency::from_millis(3)),
            Some(jmeter_rs_results::ConnectTime::from_millis(4)),
            Some(jmeter_rs_results::IdleTime::from_millis(5)),
        ));
        let sample = RemoteSample::new(
            1,
            WorkerId::new(8),
            1,
            SampleEvent::new(
                result,
                "run",
                ThreadIdentity::new("thread"),
                "worker",
                VariableSnapshot::new(),
            ),
        );
        let request_id = sample_envelope_request_id(sample.worker(), 1).expect("sample ID");
        let decoded = RemoteCodec::default()
            .decode(
                &RemoteCodec::default()
                    .encode(&RemoteEnvelope::new(
                        request_id,
                        RemoteMessage::Sample { sample },
                    ))
                    .expect("wire sample encodes"),
            )
            .expect("wire sample decodes");
        let sample = match decoded.message {
            RemoteMessage::Sample { sample } => sample,
            other => {
                assert_eq!(other.kind(), MessageKind::Sample);
                return;
            }
        };
        let timing = sample.event().result().timing();
        assert_eq!(timing.elapsed().map(ElapsedTime::as_millis), Some(1));
        assert_eq!(timing.latency().map(|value| value.as_millis()), Some(3));
        assert_eq!(timing.connect().map(|value| value.as_millis()), Some(4));
        assert_eq!(timing.idle().map(|value| value.as_millis()), Some(5));
    }

    #[test]
    fn wide_result_hierarchy_round_trips_in_wire_order() {
        let mut result = SampleResult::new("parent");
        let children = (0..32)
            .map(|index| SampleResult::new(format!("child-{index}")))
            .collect::<Vec<_>>();
        result
            .try_add_sub_results_raw(children, ValidationLimits::new(8, 64).expect("limits"))
            .expect("children fit the bound");
        let sample = RemoteSample::new(
            1,
            WorkerId::new(9),
            1,
            SampleEvent::new(
                result,
                "run",
                ThreadIdentity::new("thread"),
                "worker",
                VariableSnapshot::new(),
            ),
        );
        let request_id = sample_envelope_request_id(sample.worker(), 1).expect("sample ID");
        let codec = RemoteCodec::default();
        let decoded = codec
            .decode(
                &codec
                    .encode(&RemoteEnvelope::new(
                        request_id,
                        RemoteMessage::Sample { sample },
                    ))
                    .expect("hierarchy encodes"),
            )
            .expect("hierarchy decodes");
        let sample = match decoded.message {
            RemoteMessage::Sample { sample } => sample,
            other => {
                assert_eq!(other.kind(), MessageKind::Sample);
                return;
            }
        };
        let labels = sample
            .event()
            .result()
            .sub_results()
            .iter()
            .map(|child| child.label().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(labels.first().map(String::as_str), Some("child-0"));
        assert_eq!(labels.last().map(String::as_str), Some("child-31"));
        assert_eq!(labels.len(), 32);
    }
}
