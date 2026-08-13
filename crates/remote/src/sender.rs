// SPDX-License-Identifier: Apache-2.0
//! Deterministic in-memory sample sender and backpressure state.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt,
};

use jmeter_rs_results::{
    ByteCount, ConnectTime, ElapsedTime, ErrorCount, Latency, SampleCount, SampleData, SampleEvent,
    SampleResult, SampleTiming, ValidationLimits, WallTimestamp,
};

use crate::error::{RemoteError, RemoteErrorCode};
use crate::protocol::{
    RemoteCodec, RemoteLimits, RemoteSample, SampleKey, SampleSenderMode, WireLimits,
    sample_envelope_request_id,
};

/// How a sender reports a queue operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendOutcome {
    /// The sample was delivered immediately.
    Delivered,
    /// The sample was accepted into a bounded queue.
    Queued,
    /// The sample was accepted and a batch was flushed.
    QueuedAndFlushed,
    /// The sample key was already accepted and was ignored as an exact duplicate.
    Duplicate,
}

/// The field used to partition a statistical sender's aggregate table.
///
/// JMeter 5.6.3 defaults to the thread group.  The thread-name option is
/// retained because it is part of the upstream `key_on_threadname` property
/// and is useful to adapters that reproduce a configured Java run.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum StatisticalKeyMode {
    /// Group samples by label and thread group.
    #[default]
    ThreadGroup,
    /// Group samples by label and thread name.
    ThreadName,
}

/// A descriptor for a user supplied Java/plugin sample sender.
///
/// The descriptor is deliberately only metadata.  This crate has no JVM or
/// plugin invocation capability, so a custom sender must be delegated through
/// an explicitly negotiated adapter.  It must never be treated as one of the
/// built-in Rust senders merely because its class name is known.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CustomSenderDescriptor {
    class_name: String,
    capability: String,
}

impl CustomSenderDescriptor {
    /// Creates a descriptor from the exact configured class name and the
    /// adapter capability required to construct it.
    pub fn new(class_name: impl Into<String>, capability: impl Into<String>) -> Option<Self> {
        let class_name = class_name.into();
        let capability = capability.into();
        if class_name.is_empty() || capability.is_empty() {
            None
        } else {
            Some(Self {
                class_name,
                capability,
            })
        }
    }

    /// Returns the exact configured class name.
    pub fn class_name(&self) -> &str {
        &self.class_name
    }

    /// Returns the capability token required by the external adapter.
    pub fn capability(&self) -> &str {
        &self.capability
    }
}

/// A sender descriptor that keeps custom/plugin senders at an explicit
/// capability boundary.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum SenderDescriptor {
    /// One of the built-in Rust-native sender modes.
    BuiltIn(SampleSenderMode),
    /// A Java/plugin sender that needs an external adapter.
    Custom(CustomSenderDescriptor),
}

impl SenderDescriptor {
    /// Returns a built-in descriptor.
    pub const fn built_in(mode: SampleSenderMode) -> Self {
        Self::BuiltIn(mode)
    }

    /// Returns a typed capability error for a custom sender descriptor.
    pub fn require_capability(&self) -> Result<(), RemoteError> {
        if let Self::Custom(descriptor) = self {
            return Err(RemoteError::new(
                RemoteErrorCode::CapabilityUnavailable,
                false,
                format!(
                    "custom sender {} requires capability {}",
                    descriptor.class_name(),
                    descriptor.capability()
                ),
            ));
        }
        Ok(())
    }
}

/// A scheduler capability used by adapters to drive asynchronous senders.
///
/// The pure sender never creates a task or sleeps.  An adapter may record a
/// wake request and call [`SampleSender::flush_pending_samples`] or
/// [`SampleSender::poll`] when that wake is applied.
pub trait SenderScheduler {
    /// Records that the sender should be polled at the supplied logical time.
    fn schedule(&mut self, at_ms: u64) -> Result<(), RemoteError>;

    /// Cancels a previously scheduled poll.
    fn cancel(&mut self) -> Result<(), RemoteError>;
}

/// A deterministic scheduler useful for tests and executor adapters.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ManualSenderScheduler {
    scheduled_at_ms: Option<u64>,
    cancelled: bool,
}

impl ManualSenderScheduler {
    /// Creates an idle scheduler.
    pub const fn new() -> Self {
        Self {
            scheduled_at_ms: None,
            cancelled: false,
        }
    }

    /// Returns the next requested wake time, if any.
    pub const fn scheduled_at_ms(&self) -> Option<u64> {
        self.scheduled_at_ms
    }

    /// Returns whether cancellation was requested.
    pub const fn is_cancelled(&self) -> bool {
        self.cancelled
    }
}

impl SenderScheduler for ManualSenderScheduler {
    fn schedule(&mut self, at_ms: u64) -> Result<(), RemoteError> {
        self.scheduled_at_ms = Some(at_ms);
        self.cancelled = false;
        Ok(())
    }

    fn cancel(&mut self) -> Result<(), RemoteError> {
        self.scheduled_at_ms = None;
        self.cancelled = true;
        Ok(())
    }
}

/// A bounded sample store capability.
///
/// `DiskStore` implements this trait and is intentionally supplied to a
/// sender by the caller.  The core does not open files, discover paths, or
/// invoke a filesystem implicitly.  An application filesystem adapter can
/// implement this trait while preserving the same atomic append/drain
/// contract.
pub trait SampleStore: Clone {
    /// Returns whether this store represents an explicit persistent-store
    /// capability rather than the sender's ordinary in-memory queue.
    const PERSISTENT: bool;

    /// Appends one immutable sample and its encoded size.
    fn append(&mut self, sample: RemoteSample, encoded_bytes: usize) -> Result<(), RemoteError>;

    /// Replays and removes all samples in append order.
    fn drain(&mut self) -> Vec<RemoteSample>;

    /// Discards queued samples and returns them to the caller for cancellation
    /// accounting.
    fn abort(&mut self) -> Vec<RemoteSample>;

    /// Returns the number of stored samples.
    fn len(&self) -> usize;

    /// Returns whether no samples are currently stored.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns encoded bytes retained by the store.
    fn bytes(&self) -> usize;
}

/// The default non-persistent store.  It is not used for disk sender modes;
/// attempting to send a disk mode without an explicit [`DiskStore`] returns a
/// capability error.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MemorySampleStore;

impl SampleStore for MemorySampleStore {
    const PERSISTENT: bool = false;

    fn append(&mut self, _sample: RemoteSample, _encoded_bytes: usize) -> Result<(), RemoteError> {
        Err(RemoteError::new(
            RemoteErrorCode::CapabilityUnavailable,
            false,
            "disk sender requires an injected persistent sample store",
        ))
    }

    fn drain(&mut self) -> Vec<RemoteSample> {
        Vec::new()
    }

    fn abort(&mut self) -> Vec<RemoteSample> {
        Vec::new()
    }

    fn len(&self) -> usize {
        0
    }

    fn bytes(&self) -> usize {
        0
    }
}

/// A deterministic bounded persistent-store adapter.
///
/// This type deliberately models the observable disk-store contract without
/// touching the host filesystem.  Production code can provide a filesystem
/// implementation of [`SampleStore`]; tests can use this adapter to exercise
/// ordering, byte limits, flush, and cancellation deterministically.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiskStore {
    samples: VecDeque<RemoteSample>,
    bytes: usize,
    max_samples: usize,
    max_bytes: usize,
}

impl DiskStore {
    /// Creates a bounded store. Zero limits are rejected so a successful
    /// sender can never silently discard a sample.
    pub fn new(max_samples: usize, max_bytes: usize) -> Option<Self> {
        if max_samples == 0 || max_bytes == 0 {
            None
        } else {
            Some(Self {
                samples: VecDeque::new(),
                bytes: 0,
                max_samples,
                max_bytes,
            })
        }
    }

    /// Creates a store with the sender's default finite bounds.
    pub fn with_defaults() -> Self {
        Self::new(1024, 1024 * 1024).unwrap_or_else(|| Self {
            samples: VecDeque::new(),
            bytes: 0,
            max_samples: 1,
            max_bytes: 1,
        })
    }

    /// Returns the configured sample limit.
    pub const fn max_samples(&self) -> usize {
        self.max_samples
    }

    /// Returns the configured encoded-byte limit.
    pub const fn max_bytes(&self) -> usize {
        self.max_bytes
    }
}

impl Default for DiskStore {
    fn default() -> Self {
        Self::with_defaults()
    }
}

impl SampleStore for DiskStore {
    const PERSISTENT: bool = true;

    fn append(&mut self, sample: RemoteSample, encoded_bytes: usize) -> Result<(), RemoteError> {
        let next_bytes = self.bytes.checked_add(encoded_bytes).ok_or_else(|| {
            RemoteError::new(
                RemoteErrorCode::ResourceLimit,
                false,
                "disk-store byte accounting overflowed",
            )
        })?;
        if self.samples.len() >= self.max_samples || next_bytes > self.max_bytes {
            return Err(RemoteError::new(
                RemoteErrorCode::Backpressure,
                true,
                "disk-store capacity exhausted",
            ));
        }
        self.samples.push_back(sample);
        self.bytes = next_bytes;
        Ok(())
    }

    fn drain(&mut self) -> Vec<RemoteSample> {
        self.bytes = 0;
        self.samples.drain(..).collect()
    }

    fn abort(&mut self) -> Vec<RemoteSample> {
        self.drain()
    }

    fn len(&self) -> usize {
        self.samples.len()
    }

    fn bytes(&self) -> usize {
        self.bytes
    }
}

/// A deterministic sender configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SenderConfig {
    mode: SampleSenderMode,
    capacity: usize,
    /// Complete codec limits used for sender sizing.  Keeping this value
    /// intact means sender acceptance and adapter encoding use one source.
    wire_codec_limits: RemoteLimits,
    max_retained_bytes: usize,
    max_disk_bytes: usize,
    max_samples: usize,
    result_depth: usize,
    result_nodes: usize,
    max_references: usize,
    batch_time_ms: Option<u64>,
    statistical_key: StatisticalKeyMode,
    strip_also_on_error: bool,
    strip_depth: usize,
}

impl SenderConfig {
    /// Creates a configuration. `capacity` is the hard pending/delivered
    /// queue bound; a zero value is rejected so no mode can silently drop a
    /// sample.
    pub const fn new(
        mode: SampleSenderMode,
        capacity: usize,
        max_sample_bytes: usize,
    ) -> Option<Self> {
        if capacity == 0 || max_sample_bytes == 0 || mode.has_zero_bound() {
            return None;
        }
        let wire_codec_limits = RemoteLimits::new(max_sample_bytes);
        if !wire_codec_limits.wire_limits().is_valid() {
            return None;
        }
        let per_sample_retained = max_sample_bytes.saturating_mul(2);
        Some(Self {
            mode,
            capacity,
            wire_codec_limits,
            // A deduplication snapshot and a queued/delivered copy are both
            // retained.  Reserve for both so the byte ceiling does not cut a
            // bounded queue in half merely because samples reach the encoded
            // size limit.
            max_retained_bytes: capacity.saturating_mul(per_sample_retained),
            max_disk_bytes: capacity.saturating_mul(max_sample_bytes),
            max_samples: if capacity.saturating_mul(1024) > capacity {
                capacity.saturating_mul(1024)
            } else {
                capacity
            },
            result_depth: 64,
            result_nodes: 16_384,
            max_references: 1_024,
            batch_time_ms: None,
            statistical_key: StatisticalKeyMode::ThreadGroup,
            strip_also_on_error: true,
            // DataStrippingSampleSender in JMeter 5.6.3 visits the root and
            // at most three descendant levels (its initial level is 3).
            strip_depth: 4,
        })
    }

    /// Creates a configuration with typed setup errors for invalid bounds.
    pub fn try_new(
        mode: SampleSenderMode,
        capacity: usize,
        max_sample_bytes: usize,
    ) -> Result<Self, RemoteError> {
        if mode.has_zero_bound() || capacity == 0 || max_sample_bytes == 0 {
            return Err(RemoteError::new(
                RemoteErrorCode::ResourceLimit,
                false,
                "sender bounds must be non-zero",
            ));
        }
        let limits = RemoteLimits::try_new(max_sample_bytes)?;
        Self::from_limits_and_codec(mode, capacity, limits).ok_or_else(|| {
            RemoteError::new(
                RemoteErrorCode::ResourceLimit,
                false,
                "invalid sender configuration",
            )
        })
    }

    /// Creates a configuration from protocol limits and a sender mode.
    pub const fn from_limits(mode: SampleSenderMode, limits: RemoteLimits) -> Option<Self> {
        Self::from_limits_and_codec(mode, limits.max_samples(), limits)
    }

    /// Creates a configuration from the exact codec limits used by a sender.
    /// The returned configuration retains all sample hierarchy/reference
    /// bounds instead of reconstructing them from a message-size shorthand.
    pub const fn from_limits_and_codec(
        mode: SampleSenderMode,
        capacity: usize,
        limits: RemoteLimits,
    ) -> Option<Self> {
        if capacity == 0 || !limits.is_valid() || mode.has_zero_bound() {
            return None;
        }
        let per_sample_retained = limits.max_message_bytes().saturating_mul(2);
        Some(Self {
            mode,
            capacity,
            wire_codec_limits: limits,
            max_retained_bytes: capacity.saturating_mul(per_sample_retained),
            max_disk_bytes: capacity.saturating_mul(limits.max_message_bytes()),
            max_samples: limits.max_samples(),
            result_depth: limits.max_sample_depth(),
            result_nodes: limits.max_sample_nodes(),
            max_references: limits.max_references(),
            batch_time_ms: None,
            statistical_key: StatisticalKeyMode::ThreadGroup,
            strip_also_on_error: true,
            strip_depth: 4,
        })
    }

    /// Creates a configuration from one explicitly validated message/field
    /// source and the default non-wire protocol bounds.
    pub fn from_wire_limits(
        mode: SampleSenderMode,
        capacity: usize,
        wire: WireLimits,
    ) -> Option<Self> {
        let limits = RemoteLimits::default().with_wire_limits(wire);
        Self::from_limits_and_codec(mode, capacity, limits)
    }

    /// Creates a configuration from one wire source with a typed setup error.
    pub fn try_from_wire_limits(
        mode: SampleSenderMode,
        capacity: usize,
        wire: WireLimits,
    ) -> Result<Self, RemoteError> {
        Self::from_wire_limits(mode, capacity, wire).ok_or_else(|| {
            RemoteError::new(
                RemoteErrorCode::ResourceLimit,
                false,
                "sender wire limits or queue bounds are invalid",
            )
        })
    }

    /// Sets the maximum number of samples retained for deduplication.
    pub const fn with_max_samples(mut self, value: usize) -> Option<Self> {
        if value == 0 {
            None
        } else {
            self.max_samples = value;
            Some(self)
        }
    }

    /// Sets result hierarchy limits used by stripping.
    pub const fn with_result_limits(mut self, depth: usize, nodes: usize) -> Option<Self> {
        if depth == 0 || nodes == 0 {
            None
        } else {
            self.result_depth = depth;
            self.result_nodes = nodes;
            self.wire_codec_limits = self.wire_codec_limits.with_sample_limits(depth, nodes);
            Some(self)
        }
    }

    /// Sets a total retained-byte bound across queued, delivered, and
    /// deduplication snapshots.
    pub const fn with_max_retained_bytes(mut self, value: usize) -> Option<Self> {
        if value == 0 {
            None
        } else {
            self.max_retained_bytes = value;
            Some(self)
        }
    }

    /// Replaces the complete codec limits used for sender sizing.
    pub fn with_codec_limits(mut self, limits: RemoteLimits) -> Option<Self> {
        if !limits.is_valid() {
            return None;
        }
        self.wire_codec_limits = limits;
        self.result_depth = limits.max_sample_depth();
        self.result_nodes = limits.max_sample_nodes();
        self.max_references = limits.max_references();
        Some(self)
    }

    /// Sets the bounded encoded-byte budget for an injected disk store.
    pub const fn with_max_disk_bytes(mut self, value: usize) -> Option<Self> {
        if value == 0 {
            None
        } else {
            self.max_disk_bytes = value;
            Some(self)
        }
    }

    /// Enables a deterministic time threshold for batch modes.
    pub const fn with_batch_time_ms(mut self, value: u64) -> Option<Self> {
        if value == 0 {
            None
        } else {
            self.batch_time_ms = Some(value);
            Some(self)
        }
    }

    /// Selects the statistical aggregation key dimension.
    pub const fn with_statistical_key(mut self, value: StatisticalKeyMode) -> Self {
        self.statistical_key = value;
        self
    }

    /// Controls whether stripped senders clear response data for failed
    /// samples. JMeter defaults this property to true.
    pub const fn with_strip_also_on_error(mut self, value: bool) -> Self {
        self.strip_also_on_error = value;
        self
    }

    /// Sets the maximum result depth whose response payload is stripped.
    pub const fn with_strip_depth(mut self, value: usize) -> Option<Self> {
        if value == 0 {
            None
        } else {
            self.strip_depth = value;
            Some(self)
        }
    }

    /// Returns the mode.
    pub const fn mode(self) -> SampleSenderMode {
        self.mode
    }

    /// Returns the pending/delivered queue capacity.
    pub const fn capacity(self) -> usize {
        self.capacity
    }

    /// Returns the total retained-byte bound.
    pub const fn max_retained_bytes(self) -> usize {
        self.max_retained_bytes
    }

    /// Returns the encoded-byte budget for an injected disk store.
    pub const fn max_disk_bytes(self) -> usize {
        self.max_disk_bytes
    }

    /// Returns the maximum encoded size of one sample.
    pub const fn max_sample_bytes(self) -> usize {
        self.wire_codec_limits.max_message_bytes()
    }

    /// Returns the maximum encoded field size used by the sender codec.
    pub const fn max_field_bytes(self) -> usize {
        self.wire_codec_limits.max_field_bytes()
    }

    /// Returns the complete codec limits used by sender acceptance checks.
    pub const fn codec_limits(self) -> RemoteLimits {
        self.wire_codec_limits
    }

    /// Returns the maximum number of deduplication snapshots.
    pub const fn max_samples(self) -> usize {
        self.max_samples
    }

    /// Returns the deterministic batch time threshold, if configured.
    pub const fn batch_time_ms(self) -> Option<u64> {
        self.batch_time_ms
    }

    /// Returns the statistical aggregation key dimension.
    pub const fn statistical_key(self) -> StatisticalKeyMode {
        self.statistical_key
    }

    /// Returns whether response data is stripped from failed results too.
    pub const fn strip_also_on_error(self) -> bool {
        self.strip_also_on_error
    }

    /// Returns the maximum result depth whose response payload is stripped.
    pub const fn strip_depth(self) -> usize {
        self.strip_depth
    }
}

/// A bounded sender state machine. It never silently drops a sample: when a
/// queue is full it returns [`RemoteErrorCode::Backpressure`] without changing
/// queue or deduplication state; callers that need to retry should retain a
/// clone of the immutable sample before calling this consuming API.
#[derive(Clone)]
pub struct SampleSender<S: SampleStore = MemorySampleStore> {
    config: SenderConfig,
    store: S,
    pending: Vec<RemoteSample>,
    delivered: Vec<RemoteSample>,
    seen: BTreeMap<SampleKey, RemoteSample>,
    statistical_groups: BTreeMap<StatisticalGroupKey, usize>,
    retained_bytes: usize,
    pending_bytes: usize,
    delivered_bytes: usize,
    clock_ms: u64,
    batch_started_at_ms: Option<u64>,
    statistical_sample_count: u64,
    closed: bool,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct StatisticalGroupKey {
    label: String,
    dimension: String,
}

impl<S: SampleStore> fmt::Debug for SampleSender<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SampleSender")
            .field("mode", &self.config.mode)
            .field("capacity", &self.config.capacity)
            .field("pending_len", &self.pending.len())
            .field("store_len", &self.store.len())
            .field("delivered_len", &self.delivered.len())
            .field("seen_len", &self.seen.len())
            .field("retained_bytes", &self.retained_bytes)
            .field("closed", &self.closed)
            .field("clock_ms", &self.clock_ms)
            .finish()
    }
}

impl SampleSender<MemorySampleStore> {
    /// Creates a sender with an explicit mode and finite bounds.
    pub fn new(config: SenderConfig) -> Self {
        Self::with_store(config, MemorySampleStore)
    }

    /// Creates a sender using the protocol's finite defaults.
    pub fn with_mode(mode: SampleSenderMode) -> Option<Self> {
        SenderConfig::new(mode, 1024, 1024 * 1024).map(Self::new)
    }
}

impl<S: SampleStore> SampleSender<S> {
    /// Creates a sender with an explicit bounded store capability.
    pub fn with_store(config: SenderConfig, store: S) -> Self {
        Self {
            config,
            store,
            pending: Vec::new(),
            delivered: Vec::new(),
            seen: BTreeMap::new(),
            statistical_groups: BTreeMap::new(),
            retained_bytes: 0,
            pending_bytes: 0,
            delivered_bytes: 0,
            clock_ms: 0,
            batch_started_at_ms: None,
            statistical_sample_count: 0,
            closed: false,
        }
    }

    /// Returns the configured sender mode.
    pub const fn mode(&self) -> SampleSenderMode {
        self.config.mode()
    }

    /// Returns the number of queued samples awaiting flush.
    pub fn pending_len(&self) -> usize {
        if self.uses_disk_store() {
            self.store.len()
        } else {
            self.pending.len()
        }
    }

    /// Returns delivered samples in deterministic delivery order.
    pub fn delivered(&self) -> &[RemoteSample] {
        &self.delivered
    }

    /// Returns keys that still identify samples in the in-memory pending
    /// queue.  Statistical senders replace source samples with one aggregate
    /// entry, so callers retaining per-sample envelope correlations must use
    /// this view rather than the sender's deduplication table.  Persistent
    /// stores are not introspectable through the deliberately small store
    /// trait; the worker state machine rejects those modes before a run.
    pub(crate) fn pending_sample_keys(&self) -> BTreeSet<SampleKey> {
        if self.uses_disk_store() {
            return BTreeSet::new();
        }
        self.pending.iter().map(RemoteSample::key).collect()
    }

    /// Returns whether the sender has been flushed/closed.
    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    /// Returns bytes retained by the sender's pending, delivered, and
    /// deduplication snapshots.
    pub const fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    /// Returns the sender-local retained-byte ceiling.
    pub const fn max_retained_bytes(&self) -> usize {
        self.config.max_retained_bytes
    }

    /// Returns the configured encoded-byte ceiling for disk persistence.
    pub const fn max_disk_bytes(&self) -> usize {
        self.config.max_disk_bytes
    }

    /// Returns the number of bytes retained by the injected store.
    pub fn disk_bytes(&self) -> usize {
        self.store.bytes()
    }

    /// Returns whether this sender is configured for a persistent store.
    pub fn uses_disk_store(&self) -> bool {
        matches!(
            self.mode(),
            SampleSenderMode::DiskStore { .. } | SampleSenderMode::StrippedDiskStore { .. }
        )
    }

    /// Returns the configured descriptor for a built-in sender.
    pub fn descriptor(&self) -> SenderDescriptor {
        SenderDescriptor::built_in(self.mode())
    }

    /// Requests that an injected scheduler call [`Self::poll`] at a logical
    /// time chosen by the adapter.  No task, timer, or thread is created by
    /// this method.
    pub fn schedule_poll<C: SenderScheduler>(
        &self,
        scheduler: &mut C,
        at_ms: u64,
    ) -> Result<(), RemoteError> {
        if self.closed {
            return Err(RemoteError::new(
                RemoteErrorCode::InvalidState,
                false,
                "cannot schedule a closed sample sender",
            ));
        }
        scheduler.schedule(at_ms)
    }

    /// Cancels a previously requested scheduler poll through the injected
    /// scheduler capability.
    pub fn cancel_poll<C: SenderScheduler>(&self, scheduler: &mut C) -> Result<(), RemoteError> {
        scheduler.cancel()
    }

    /// Rejects a custom sender descriptor at the Rust-native boundary.
    pub fn require_descriptor(descriptor: &SenderDescriptor) -> Result<(), RemoteError> {
        descriptor.require_capability()
    }

    /// Replaces the sender's deduplication bound when it still covers all
    /// accepted samples.
    pub fn set_max_samples(&mut self, maximum: usize) -> Result<(), RemoteError> {
        if maximum == 0 || maximum < self.seen.len() {
            return Err(RemoteError::new(
                RemoteErrorCode::ResourceLimit,
                false,
                "sender sample bound must cover accepted samples",
            ));
        }
        self.config.max_samples = maximum;
        Ok(())
    }

    /// Replaces the sender-local retained-byte ceiling.
    ///
    /// Coordinators use this to account for their own immutable sample
    /// snapshots and the sender's copies under one total budget.
    pub fn set_max_retained_bytes(&mut self, maximum: usize) -> Result<(), RemoteError> {
        if maximum == 0 || maximum < self.retained_bytes {
            return Err(RemoteError::new(
                RemoteErrorCode::ResourceLimit,
                false,
                "sender retained-byte bound must cover current data",
            ));
        }
        self.config.max_retained_bytes = maximum;
        Ok(())
    }

    /// Accepts a sample according to the selected mode.
    pub fn send(&mut self, sample: RemoteSample) -> Result<SendOutcome, RemoteError> {
        if self.closed {
            return Err(RemoteError::new(
                RemoteErrorCode::InvalidState,
                false,
                "sample sender is closed",
            ));
        }
        if self.uses_disk_store() && !S::PERSISTENT {
            return Err(RemoteError::new(
                RemoteErrorCode::CapabilityUnavailable,
                false,
                "disk sender requires an injected persistent sample store",
            ));
        }
        if let Some(previous) = self.seen.get(&sample.key()) {
            if previous == &sample {
                return Ok(SendOutcome::Duplicate);
            }
            return Err(RemoteError::new(
                RemoteErrorCode::ConflictingDuplicate,
                false,
                format!(
                    "sample {:?} was already accepted with different contents",
                    sample.key()
                ),
            ));
        }
        if self.seen.len() >= self.config.max_samples {
            return Err(RemoteError::new(
                RemoteErrorCode::ResourceLimit,
                false,
                "sample deduplication bound exhausted",
            ));
        }
        // Check queue capacity before validating or stripping the hierarchy;
        // a full sender must not copy a large result just to reject it.  A
        // statistical update to an existing key replaces one aggregate slot,
        // so it remains admissible even when the pending table is full.
        let statistical_key = matches!(self.mode(), SampleSenderMode::Statistical { .. })
            .then(|| self.statistical_key(&sample));
        let statistical_slot_exists = statistical_key
            .as_ref()
            .is_some_and(|key| self.statistical_groups.contains_key(key));
        if !statistical_slot_exists {
            self.ensure_queue_space()?;
        }
        let validation_limits =
            ValidationLimits::new(self.config.result_depth, self.config.result_nodes).map_err(
                |error| RemoteError::new(RemoteErrorCode::InvalidSample, false, error.to_string()),
            )?;
        sample
            .event()
            .result()
            .validate_wire_with_limits(validation_limits)
            .map_err(|error| {
                RemoteError::new(RemoteErrorCode::InvalidSample, false, error.to_string())
            })?;
        let original = sample.clone();
        let sample = if self.mode().is_stripped() {
            strip_sample(
                sample,
                self.config.result_depth,
                self.config.result_nodes,
                self.config.strip_depth,
                self.config.strip_also_on_error,
            )?
        } else {
            sample
        };
        let encoded_size = encoded_sample_size(&sample, self.config)?;
        let original_size = encoded_sample_size(&original, self.config)?;
        let mode = self.mode();
        if matches!(
            mode,
            SampleSenderMode::DiskStore { .. } | SampleSenderMode::StrippedDiskStore { .. }
        ) && self
            .store
            .bytes()
            .checked_add(encoded_size)
            .is_none_or(|bytes| bytes > self.config.max_disk_bytes)
        {
            return Err(RemoteError::new(
                RemoteErrorCode::ResourceLimit,
                true,
                "disk-store byte bound exhausted",
            ));
        }
        let retained = self.retained_after_add(original_size, encoded_size)?;
        match mode {
            SampleSenderMode::Standard | SampleSenderMode::Stripped => {
                self.ensure_queue_space()?;
                self.ensure_retained(retained)?;
                let delivered_bytes =
                    self.delivered_bytes
                        .checked_add(encoded_size)
                        .ok_or_else(|| {
                            RemoteError::new(
                                RemoteErrorCode::ResourceLimit,
                                false,
                                "sender delivered-byte accounting overflowed",
                            )
                        })?;
                self.seen.insert(original.key(), original);
                self.retained_bytes = retained;
                self.delivered_bytes = delivered_bytes;
                self.delivered.push(sample);
                Ok(SendOutcome::Delivered)
            }
            SampleSenderMode::Hold
            | SampleSenderMode::Batch { .. }
            | SampleSenderMode::StrippedBatch { .. } => {
                self.ensure_queue_space()?;
                self.ensure_retained(retained)?;
                let pending_bytes =
                    self.pending_bytes
                        .checked_add(encoded_size)
                        .ok_or_else(|| {
                            RemoteError::new(
                                RemoteErrorCode::ResourceLimit,
                                false,
                                "sender pending-byte accounting overflowed",
                            )
                        })?;
                self.seen.insert(original.key(), original);
                self.retained_bytes = retained;
                self.pending_bytes = pending_bytes;
                self.pending.push(sample);
                self.start_batch_timer_if_needed();
                let flush = self.batch_count_due() || self.batch_time_due();
                if flush {
                    self.flush_pending_for_threshold();
                    Ok(SendOutcome::QueuedAndFlushed)
                } else {
                    Ok(SendOutcome::Queued)
                }
            }
            SampleSenderMode::Statistical { .. } => {
                self.send_statistical(original, sample, original_size, encoded_size)
            }
            SampleSenderMode::Asynch { .. } | SampleSenderMode::StrippedAsynch { .. } => {
                self.ensure_queue_space()?;
                self.ensure_retained(retained)?;
                let pending_bytes =
                    self.pending_bytes
                        .checked_add(encoded_size)
                        .ok_or_else(|| {
                            RemoteError::new(
                                RemoteErrorCode::ResourceLimit,
                                false,
                                "sender pending-byte accounting overflowed",
                            )
                        })?;
                self.seen.insert(original.key(), original);
                self.retained_bytes = retained;
                self.pending_bytes = pending_bytes;
                self.pending.push(sample);
                self.start_batch_timer_if_needed();
                // An asynchronous sender only requests a scheduler poll.  It
                // does not create a thread or flush inline, which keeps queue
                // order deterministic and makes full-queue backpressure
                // observable to the caller.
                Ok(SendOutcome::Queued)
            }
            SampleSenderMode::DiskStore { .. } | SampleSenderMode::StrippedDiskStore { .. } => {
                self.ensure_queue_space()?;
                self.ensure_retained(retained)?;
                self.store.append(sample, encoded_size)?;
                self.seen.insert(original.key(), original);
                self.retained_bytes = retained;
                self.pending_bytes = self.store.bytes();
                self.start_batch_timer_if_needed();
                Ok(SendOutcome::Queued)
            }
        }
    }

    /// Flushes all retained samples in insertion order.
    pub fn flush(&mut self) -> Vec<RemoteSample> {
        self.flush_pending();
        self.drain_delivered()
    }

    /// Moves queued samples to the delivered queue without draining it. This
    /// is used by coordinators that expose delivery through a later poll.
    pub fn flush_pending_samples(&mut self) {
        self.flush_pending();
    }

    /// Polls an asynchronous sender (or explicitly flushes any sender) and
    /// returns the newly delivered samples.  This is the scheduler boundary:
    /// callers decide when a poll runs, so this method never starts a thread.
    pub fn poll(&mut self) -> Vec<RemoteSample> {
        self.flush_pending();
        self.drain_delivered()
    }

    /// Drains newly delivered samples, leaving historical delivery empty.
    pub fn drain_delivered(&mut self) -> Vec<RemoteSample> {
        self.retained_bytes = self.retained_bytes.saturating_sub(self.delivered_bytes);
        self.delivered_bytes = 0;
        core::mem::take(&mut self.delivered)
    }

    /// Closes the sender after flushing pending samples.
    pub fn close(&mut self) -> Vec<RemoteSample> {
        self.flush_pending();
        self.closed = true;
        self.drain_delivered()
    }

    /// Immediately cancels the sender. Pending samples are returned to the
    /// caller as dropped work; already delivered samples remain drainable.
    pub fn abort(&mut self) -> Vec<RemoteSample> {
        self.closed = true;
        self.batch_started_at_ms = None;
        self.statistical_sample_count = 0;
        // Pending samples are no longer retryable after an immediate stop.
        // Release both their queue copies and their dedup snapshots; retain
        // only already-delivered history until the caller drains it.
        self.seen.clear();
        self.retained_bytes = self.delivered_bytes;
        self.pending_bytes = 0;
        self.statistical_groups.clear();
        let mut dropped = if self.uses_disk_store() {
            self.store.abort()
        } else {
            Vec::new()
        };
        dropped.extend(core::mem::take(&mut self.pending));
        dropped
    }

    /// Advances the deterministic sender clock and flushes a time-expired
    /// batch. Wall-clock sleeping is intentionally outside this crate.
    pub fn advance_time(&mut self, now_ms: u64) -> Result<Vec<RemoteSample>, RemoteError> {
        if now_ms < self.clock_ms {
            return Err(RemoteError::state("sender clock moved backwards"));
        }
        self.clock_ms = now_ms;
        self.flush_if_time_due();
        Ok(self.drain_delivered())
    }

    /// Alias for deterministic adapters that model a clock tick.
    pub fn tick(&mut self, now_ms: u64) -> Result<Vec<RemoteSample>, RemoteError> {
        self.advance_time(now_ms)
    }

    /// Sends a sample at an injected logical time.
    pub fn send_at(
        &mut self,
        sample: RemoteSample,
        now_ms: u64,
    ) -> Result<SendOutcome, RemoteError> {
        if now_ms < self.clock_ms {
            return Err(RemoteError::state("sender clock moved backwards"));
        }
        self.clock_ms = now_ms;
        self.send(sample)
    }

    fn retained_after_add(
        &self,
        original_size: usize,
        encoded_size: usize,
    ) -> Result<usize, RemoteError> {
        let additional = original_size.checked_add(encoded_size).ok_or_else(|| {
            RemoteError::new(
                RemoteErrorCode::ResourceLimit,
                false,
                "sender retained-byte bound overflowed",
            )
        })?;
        self.retained_bytes.checked_add(additional).ok_or_else(|| {
            RemoteError::new(
                RemoteErrorCode::ResourceLimit,
                false,
                "sender retained-byte bound overflowed",
            )
        })
    }

    fn ensure_retained(&self, retained: usize) -> Result<(), RemoteError> {
        if retained > self.config.max_retained_bytes {
            Err(RemoteError::new(
                RemoteErrorCode::ResourceLimit,
                false,
                "sender retained-byte bound exhausted",
            ))
        } else {
            Ok(())
        }
    }

    fn statistical_key(&self, sample: &RemoteSample) -> StatisticalGroupKey {
        let result = sample.event().result();
        let dimension = match self.config.statistical_key {
            StatisticalKeyMode::ThreadGroup => sample.event().thread().group().unwrap_or(""),
            StatisticalKeyMode::ThreadName => sample.event().thread().name(),
        };
        StatisticalGroupKey {
            label: result.label().to_owned(),
            dimension: dimension.to_owned(),
        }
    }

    fn send_statistical(
        &mut self,
        original: RemoteSample,
        incoming: RemoteSample,
        original_size: usize,
        incoming_size: usize,
    ) -> Result<SendOutcome, RemoteError> {
        let key = self.statistical_key(&original);
        // Compute every fallible accounting step before mutating the sender.
        // This keeps a rejected aggregate update retryable and preserves the
        // no-partial-admission invariant at the u64 boundary.
        let next_statistical_sample_count = self
            .statistical_sample_count
            .checked_add(1)
            .ok_or_else(|| {
                RemoteError::new(
                    RemoteErrorCode::ResourceLimit,
                    false,
                    "statistical sample count overflowed",
                )
            })?;
        if let Some(&index) = self.statistical_groups.get(&key) {
            let previous = self.pending.get(index).ok_or_else(|| {
                RemoteError::new(
                    RemoteErrorCode::Internal,
                    false,
                    "statistical group index was not retained",
                )
            })?;
            let previous_size = encoded_sample_size(previous, self.config)?;
            let aggregate = aggregate_samples(
                previous,
                &incoming,
                ValidationLimits::new(self.config.result_depth, self.config.result_nodes).map_err(
                    |error| {
                        RemoteError::new(RemoteErrorCode::InvalidSample, false, error.to_string())
                    },
                )?,
            )?;
            let aggregate_size = encoded_sample_size(&aggregate, self.config)?;
            let retained = self
                .retained_bytes
                .checked_add(original_size)
                .and_then(|value| value.checked_sub(previous_size))
                .and_then(|value| value.checked_add(aggregate_size))
                .ok_or_else(|| {
                    RemoteError::new(
                        RemoteErrorCode::ResourceLimit,
                        false,
                        "sender statistical retained-byte accounting overflowed",
                    )
                })?;
            self.ensure_retained(retained)?;
            let pending_bytes = self
                .pending_bytes
                .checked_sub(previous_size)
                .and_then(|value| value.checked_add(aggregate_size))
                .ok_or_else(|| {
                    RemoteError::new(
                        RemoteErrorCode::Internal,
                        false,
                        "statistical pending-byte accounting underflowed",
                    )
                })?;
            self.pending[index] = aggregate;
            self.pending_bytes = pending_bytes;
            self.seen.insert(original.key(), original);
            self.retained_bytes = retained;
        } else {
            self.ensure_queue_space()?;
            let retained = self.retained_after_add(original_size, incoming_size)?;
            self.ensure_retained(retained)?;
            let pending_bytes = self
                .pending_bytes
                .checked_add(incoming_size)
                .ok_or_else(|| {
                    RemoteError::new(
                        RemoteErrorCode::ResourceLimit,
                        false,
                        "sender pending-byte accounting overflowed",
                    )
                })?;
            let index = self.pending.len();
            self.pending.push(incoming);
            self.pending_bytes = pending_bytes;
            self.statistical_groups.insert(key, index);
            self.seen.insert(original.key(), original);
            self.retained_bytes = retained;
        }
        self.start_batch_timer_if_needed();
        self.statistical_sample_count = next_statistical_sample_count;
        if self.batch_count_due() || self.batch_time_due() {
            self.flush_pending_for_threshold();
            Ok(SendOutcome::QueuedAndFlushed)
        } else {
            Ok(SendOutcome::Queued)
        }
    }

    fn ensure_queue_space(&self) -> Result<(), RemoteError> {
        let pending_slots = if self.uses_disk_store() {
            self.store.len()
        } else {
            self.pending.len()
        };
        let retained_slots = pending_slots.saturating_add(self.delivered.len());
        if retained_slots >= self.config.capacity {
            Err(RemoteError::new(
                RemoteErrorCode::Backpressure,
                true,
                format!(
                    "sample sender retained queue is full at {}",
                    self.config.capacity
                ),
            ))
        } else {
            Ok(())
        }
    }

    fn flush_pending(&mut self) {
        self.batch_started_at_ms = None;
        self.statistical_sample_count = 0;
        if self.uses_disk_store() {
            let persisted = self.store.drain();
            self.delivered_bytes = self.delivered_bytes.saturating_add(self.pending_bytes);
            self.pending_bytes = 0;
            self.delivered.extend(persisted);
        } else {
            self.delivered_bytes = self.delivered_bytes.saturating_add(self.pending_bytes);
            self.pending_bytes = 0;
            self.delivered.append(&mut self.pending);
        }
        self.statistical_groups.clear();
    }

    fn batch_count_due(&self) -> bool {
        match self.mode() {
            SampleSenderMode::Statistical { size } => {
                u64::try_from(size).map_or(true, |bound| self.statistical_sample_count >= bound)
            }
            SampleSenderMode::Batch { size } | SampleSenderMode::StrippedBatch { size } => {
                self.pending.len() >= size
            }
            _ => false,
        }
    }

    fn batch_time_due(&self) -> bool {
        if !matches!(
            self.mode(),
            SampleSenderMode::Batch { .. }
                | SampleSenderMode::Statistical { .. }
                | SampleSenderMode::StrippedBatch { .. }
        ) {
            return false;
        }
        // JMeter checks the elapsed threshold when a sample arrives.  An
        // empty batch has nothing to deliver and must not be flushed merely
        // because its previous deadline elapsed.
        if self.pending.is_empty() {
            return false;
        }
        self.config.batch_time_ms.is_some_and(|threshold| {
            self.batch_started_at_ms
                // BatchSampleSender and StatisticalSampleSender use the
                // strict source condition `batchSendTime < now`, so a tick
                // exactly on the deadline does not flush yet.
                .is_some_and(|started| self.clock_ms.saturating_sub(started) > threshold)
        })
    }

    fn flush_if_time_due(&mut self) {
        if self.batch_time_due() {
            self.flush_pending_for_threshold();
        }
    }

    fn start_batch_timer_if_needed(&mut self) {
        if self.batch_started_at_ms.is_none() {
            self.batch_started_at_ms = Some(self.clock_ms);
        }
    }

    /// Flushes a threshold-triggered batch and starts the next timer from the
    /// flush instant. JMeter resets the time threshold after either the count
    /// or time threshold fires, even when no later sample arrives until after
    /// that deadline.
    fn flush_pending_for_threshold(&mut self) {
        self.flush_pending();
        if self.config.batch_time_ms.is_some() {
            self.batch_started_at_ms = Some(self.clock_ms);
        }
    }
}

fn sample_count_for_aggregation(result: &SampleResult) -> u64 {
    result.sample_count().map_or(1, SampleCount::as_u64)
}

fn error_count_for_aggregation(result: &SampleResult) -> u64 {
    // JMeter's StatisticalSampleResult counts unsuccessful incoming results,
    // rather than trusting a pre-existing aggregate error_count field.  A
    // field may already represent several samples, but the sender receives
    // one event and must add exactly one error for that event's outcome.
    u64::from(!result.success().unwrap_or(true))
}

fn checked_sum_u64(first: u64, second: u64, message: &'static str) -> Result<u64, RemoteError> {
    first
        .checked_add(second)
        .ok_or_else(|| RemoteError::new(RemoteErrorCode::ResourceLimit, false, message))
}

fn checked_sum_elapsed(
    first: Option<ElapsedTime>,
    second: Option<ElapsedTime>,
) -> Result<ElapsedTime, RemoteError> {
    checked_sum_u64(
        first.map_or(0, ElapsedTime::as_millis),
        second.map_or(0, ElapsedTime::as_millis),
        "statistical elapsed-time aggregation overflowed",
    )
    .map(ElapsedTime::from_millis)
}

fn checked_sum_latency(
    first: Option<Latency>,
    second: Option<Latency>,
) -> Result<Latency, RemoteError> {
    checked_sum_u64(
        first.map_or(0, Latency::as_millis),
        second.map_or(0, Latency::as_millis),
        "statistical latency aggregation overflowed",
    )
    .map(Latency::from_millis)
}

fn checked_sum_connect(
    first: Option<ConnectTime>,
    second: Option<ConnectTime>,
) -> Result<ConnectTime, RemoteError> {
    checked_sum_u64(
        first.map_or(0, ConnectTime::as_millis),
        second.map_or(0, ConnectTime::as_millis),
        "statistical connect-time aggregation overflowed",
    )
    .map(ConnectTime::from_millis)
}

fn checked_sum_bytes(
    first: Option<ByteCount>,
    second: Option<ByteCount>,
) -> Result<ByteCount, RemoteError> {
    checked_sum_u64(
        first.map_or(0, ByteCount::as_u64),
        second.map_or(0, ByteCount::as_u64),
        "statistical byte aggregation overflowed",
    )
    .map(ByteCount::from_u64)
}

fn checked_sum_sample_counts(
    first: &SampleResult,
    second: &SampleResult,
) -> Result<SampleCount, RemoteError> {
    checked_sum_u64(
        sample_count_for_aggregation(first),
        sample_count_for_aggregation(second),
        "statistical sample-count aggregation overflowed",
    )
    .map(SampleCount::from_u64)
}

fn checked_sum_errors(first: u64, second: u64) -> Result<ErrorCount, RemoteError> {
    checked_sum_u64(
        first,
        second,
        "statistical error-count aggregation overflowed",
    )
    .map(ErrorCount::from_u64)
}

fn minimum_timestamp(
    first: Option<WallTimestamp>,
    second: Option<WallTimestamp>,
) -> Option<WallTimestamp> {
    match (first, second) {
        (Some(first), Some(second)) => Some(first.min(second)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn maximum_timestamp(
    first: Option<WallTimestamp>,
    second: Option<WallTimestamp>,
) -> Option<WallTimestamp> {
    match (first, second) {
        (Some(first), Some(second)) => Some(first.max(second)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn aggregate_samples(
    previous: &RemoteSample,
    incoming: &RemoteSample,
    limits: ValidationLimits,
) -> Result<RemoteSample, RemoteError> {
    let first = previous.event().result();
    let second = incoming.event().result();
    let mut result = if first.has_label() {
        SampleResult::new(first.label())
    } else {
        SampleResult::without_label()
    };
    let start = minimum_timestamp(first.start_time(), second.start_time());
    let end = maximum_timestamp(first.end_time(), second.end_time());
    // StatisticalSampleResult overrides getTimeStamp() to return the
    // aggregate end time.  Do not carry through the source samples' saved
    // timestamp mode (which may be start-time based or an explicitly loaded
    // legacy value).
    let timestamp = end;
    let timing = SampleTiming::from_wire_parts(
        timestamp,
        start,
        end,
        Some(checked_sum_elapsed(first.elapsed(), second.elapsed())?),
        Some(checked_sum_latency(first.latency(), second.latency())?),
        Some(checked_sum_connect(
            first.connect_time(),
            second.connect_time(),
        )?),
        None,
    );
    result.set_timing_from_wire(timing);
    let first_success = first.success().unwrap_or(true);
    let second_success = second.success().unwrap_or(true);
    result.set_successful(first_success && second_success);
    result.set_received_bytes(Some(checked_sum_bytes(
        first.received_bytes(),
        second.received_bytes(),
    )?));
    result.set_sent_bytes(Some(checked_sum_bytes(
        first.sent_bytes(),
        second.sent_bytes(),
    )?));
    result.set_sample_count(Some(checked_sum_sample_counts(first, second)?));
    result.set_error_count(Some(checked_sum_errors(
        error_count_for_aggregation(first),
        error_count_for_aggregation(second),
    )?));
    result.validate_wire_with_limits(limits).map_err(|error| {
        RemoteError::new(RemoteErrorCode::InvalidSample, false, error.to_string())
    })?;
    let event = SampleEvent::new(
        result,
        previous.event().run().clone(),
        previous.event().thread().clone(),
        previous.event().host().clone(),
        // StatisticalSampleSender creates its wrapper with the two-argument
        // SampleEvent constructor. It therefore has no sampled-variable
        // values and is not marked as a transaction event, even when the
        // source event that first created the aggregate was one.
        jmeter_rs_results::VariableSnapshot::new(),
    );
    Ok(RemoteSample::new(
        previous.run_id(),
        previous.worker(),
        previous.sequence(),
        event,
    ))
}

fn encoded_sample_size(sample: &RemoteSample, config: SenderConfig) -> Result<usize, RemoteError> {
    // This is intentionally the exact codec source retained by the sender;
    // rebuilding limits from `max_sample_bytes` would widen fields and
    // repeated-value bounds beyond a configured `RemoteCodec`.
    let limits = config.wire_codec_limits;
    // Sizing only needs a valid sample-namespace ID. It must not couple the
    // byte-accounting path to the sample sequence, which may legitimately be
    // at its upper bound while the worker's envelope ordinal is independent.
    let request_id = sample_envelope_request_id(sample.worker(), 1)?;
    let encoded_len = RemoteCodec::new(limits)
        .encoded_sample_len(request_id, sample)
        .map_err(|error| RemoteError::new(error.code(), false, error.to_string()))?;
    if encoded_len > config.max_sample_bytes() {
        return Err(RemoteError::new(
            RemoteErrorCode::ResourceLimit,
            false,
            format!(
                "encoded sample size {} exceeds {}",
                encoded_len,
                config.max_sample_bytes()
            ),
        ));
    }
    Ok(encoded_len)
}

fn strip_sample(
    sample: RemoteSample,
    max_depth: usize,
    max_nodes: usize,
    strip_depth: usize,
    strip_also_on_error: bool,
) -> Result<RemoteSample, RemoteError> {
    let event = sample.event();
    // DataStrippingSampleSender decides whether to invoke stripContent once,
    // from the root result. If an unsuccessful root is retained by policy,
    // its successful/failed descendants are retained as well; the policy is
    // not evaluated independently for each result node. We still walk the
    // unstripped tree so protocol encoding canonicalizes fallback fields
    // (for example, an absent error count derived from `successful=false`)
    // without returning an unsupported wire-metadata error.
    let should_strip = strip_also_on_error || event.result().success().unwrap_or(true);
    let limits = ValidationLimits::new(max_depth, max_nodes).map_err(|error| {
        RemoteError::new(RemoteErrorCode::InvalidSample, false, error.to_string())
    })?;
    let mut nodes = 0;
    let result = strip_result_owned(
        event.result(),
        limits,
        1,
        strip_depth,
        should_strip,
        &mut nodes,
    )?;
    result.validate_wire_with_limits(limits).map_err(|error| {
        RemoteError::new(RemoteErrorCode::InvalidSample, false, error.to_string())
    })?;
    let stripped = SampleEvent::new(
        result,
        event.run().clone(),
        event.thread().clone(),
        event.host().clone(),
        event.variables().clone(),
    )
    .with_transaction_state(event.transaction_state());
    Ok(RemoteSample::new(
        sample.run_id(),
        sample.worker(),
        sample.sequence(),
        stripped,
    ))
}

fn strip_result_owned(
    source: &SampleResult,
    limits: ValidationLimits,
    depth: usize,
    strip_depth: usize,
    strip_payloads: bool,
    nodes: &mut usize,
) -> Result<SampleResult, RemoteError> {
    if depth > limits.max_depth() {
        return Err(RemoteError::new(
            RemoteErrorCode::ResourceLimit,
            false,
            "sample hierarchy depth exceeded",
        ));
    }
    *nodes = nodes.checked_add(1).ok_or_else(|| {
        RemoteError::new(
            RemoteErrorCode::ResourceLimit,
            false,
            "sample hierarchy node bound overflowed",
        )
    })?;
    if *nodes > limits.max_nodes() {
        return Err(RemoteError::new(
            RemoteErrorCode::ResourceLimit,
            false,
            "sample hierarchy node bound exceeded",
        ));
    }

    let mut result = if source.has_label() {
        SampleResult::new(source.label())
    } else {
        SampleResult::without_label()
    };
    result.set_timing_from_wire(source.timing().clone());
    result.set_success(source.success());
    result.set_response_code(source.response_code().map(str::to_owned));
    result.set_response_message(source.response_message().map(str::to_owned));
    result.set_failure_message(source.failure_message().map(str::to_owned));
    result.set_data_type(source.data_type().cloned());
    result.set_data_encoding(source.data_encoding().cloned());
    // JMeter's stripped sender removes response payload bytes while leaving
    // request metadata available to listeners. It writes a present empty
    // response even when the source response was absent and retains the
    // received-byte counter. The default traversal is the root plus three
    // descendant levels; deeper children remain structurally intact.
    result.set_request_data(source.request_data().cloned());
    if strip_payloads && depth <= strip_depth {
        result.set_response_data(Some(SampleData::empty()));
    } else {
        result.set_response_data(source.response_data().cloned());
    }
    result.set_request_headers(source.request_headers().cloned());
    result.set_response_headers(source.response_headers().cloned());
    result.set_sampler_data(source.sampler_data().map(str::to_owned));
    result.set_response_file(source.response_file().map(str::to_owned));
    result.set_url(source.url().map(str::to_owned));
    // SampleResult#getBytesAsLong() returns zero when no byte count was set,
    // and stripResponse writes that value back as a present field.
    if strip_payloads {
        result.set_received_bytes(Some(
            source
                .received_bytes()
                .unwrap_or_else(|| ByteCount::from_u64(0)),
        ));
    } else {
        result.set_received_bytes(source.received_bytes());
    }
    result.set_sent_bytes(source.sent_bytes());
    result.set_group_threads(source.group_threads());
    result.set_all_threads(source.all_threads());
    result.set_sample_count(source.sample_count());
    result.set_error_count(source.error_count());
    for assertion in source.assertions() {
        result
            .try_add_assertion(assertion.clone())
            .map_err(|error| {
                RemoteError::new(RemoteErrorCode::InvalidSample, false, error.to_string())
            })?;
    }
    result.set_stop_thread(source.stop_thread());
    result.set_stop_test(source.stop_test());
    result.set_stop_test_now(source.stop_test_now());
    result.set_start_next_loop(source.start_next_loop());
    result.set_logical_action(source.logical_action());
    result.set_ignored(source.ignored());

    let mut children = Vec::with_capacity(source.sub_results().len());
    for child in source.sub_results() {
        let child = if !strip_payloads || depth < strip_depth {
            strip_result_owned(child, limits, depth + 1, strip_depth, strip_payloads, nodes)?
        } else {
            child.clone()
        };
        children.push(child);
    }
    result
        .try_add_sub_results_raw(children, limits)
        .map_err(|error| {
            RemoteError::new(RemoteErrorCode::InvalidSample, false, error.to_string())
        })?;
    Ok(result)
}

#[cfg(test)]
#[allow(clippy::expect_used)] // Test fixtures use expect for assertion-context failures.
mod tests {
    use super::*;
    use crate::protocol::{
        RemoteEnvelope, RemoteLimits, RemoteMessage, RemoteSample, WireLimits, WorkerId,
        sample_envelope_request_id,
    };
    use jmeter_rs_results::{
        SampleData, SampleEvent, SampleResult, ThreadIdentity, ValidationLimits, VariableSnapshot,
    };

    fn sample(sequence: u64) -> RemoteSample {
        let event = SampleEvent::new(
            SampleResult::new("sample"),
            "run",
            ThreadIdentity::new("thread"),
            "worker",
            VariableSnapshot::new(),
        );
        RemoteSample::new(1, WorkerId::new(1), sequence, event)
    }

    fn sample_with_response_bytes(sequence: u64, size: usize) -> RemoteSample {
        let mut result = SampleResult::new("wire-boundary");
        result.set_response_data(Some(SampleData::new(vec![b'x'; size])));
        let event = SampleEvent::new(
            result,
            "run",
            ThreadIdentity::new("thread"),
            "worker",
            VariableSnapshot::new(),
        );
        RemoteSample::new(1, WorkerId::new(1), sequence, event)
    }

    fn sample_envelope(sample: RemoteSample) -> RemoteEnvelope {
        let request_id = sample_envelope_request_id(sample.worker(), 1).expect("sample ID");
        RemoteEnvelope::new(request_id, RemoteMessage::Sample { sample })
    }

    fn sample_at_wire_size(target: usize, field_limit: usize, sequence: u64) -> RemoteSample {
        let sizing_wire = WireLimits::new(
            target.saturating_add(1024 * 1024),
            target.saturating_add(1024 * 1024),
        )
        .expect("sizing wire limits");
        let sizing_limits = RemoteLimits::default().with_wire_limits(sizing_wire);
        let codec = RemoteCodec::new(sizing_limits);
        let mut low = 0usize;
        let mut high = target;
        let mut sample = None;
        while low <= high {
            let response_size = low + (high - low) / 2;
            let candidate = sample_with_response_bytes(sequence, response_size);
            let encoded_len = codec
                .encode(&sample_envelope(candidate.clone()))
                .expect("sample fits sizing bounds")
                .len();
            if encoded_len == target {
                sample = Some(candidate);
                break;
            }
            if encoded_len < target {
                low = response_size.saturating_add(1);
            } else {
                high = response_size.saturating_sub(1);
            }
        }
        let sample = sample.expect("response payload can reach exact wire size");
        let wire = WireLimits::new(target, field_limit).expect("target wire limits");
        let limits = RemoteLimits::default().with_wire_limits(wire);
        let encoded = RemoteCodec::new(limits)
            .encode(&sample_envelope(sample.clone()))
            .expect("target sample encodes");
        assert_eq!(encoded.len(), target);
        sample
    }

    #[test]
    fn standard_delivers_and_duplicate_is_explicit() {
        let config = SenderConfig::new(SampleSenderMode::Standard, 4, 1000).expect("config");
        let mut sender = SampleSender::new(config);
        assert_eq!(sender.send(sample(1)), Ok(SendOutcome::Delivered));
        // Sender-level replay is idempotent too; changed contents with the
        // same key remain an explicit conflicting-duplicate error.
        assert_eq!(sender.send(sample(1)), Ok(SendOutcome::Duplicate));
    }

    #[test]
    fn standard_delivery_capacity_backpressures_until_drained() {
        let config = SenderConfig::new(SampleSenderMode::Standard, 1, 1000).expect("config");
        let mut sender = SampleSender::new(config);
        assert_eq!(sender.send(sample(1)), Ok(SendOutcome::Delivered));
        assert!(matches!(
            sender.send(sample(2)),
            Err(error) if error.code == RemoteErrorCode::Backpressure
        ));
        assert_eq!(sender.drain_delivered().len(), 1);
        assert_eq!(sender.send(sample(2)), Ok(SendOutcome::Delivered));
    }

    #[test]
    fn batch_flushes_in_arrival_order_and_full_queue_backpressures() {
        let config =
            SenderConfig::new(SampleSenderMode::Batch { size: 3 }, 3, 1000).expect("config");
        let mut sender = SampleSender::new(config);
        assert_eq!(sender.send(sample(1)), Ok(SendOutcome::Queued));
        assert_eq!(sender.send(sample(2)), Ok(SendOutcome::Queued));
        assert_eq!(sender.send(sample(3)), Ok(SendOutcome::QueuedAndFlushed));
        assert_eq!(
            sender
                .delivered()
                .iter()
                .map(|item| item.sequence())
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn hold_requires_explicit_flush_and_close_is_terminal() {
        let config = SenderConfig::new(SampleSenderMode::Hold, 2, 1000).expect("config");
        let mut sender = SampleSender::new(config);
        assert_eq!(sender.send(sample(1)), Ok(SendOutcome::Queued));
        assert_eq!(sender.pending_len(), 1);
        assert_eq!(sender.close().len(), 1);
        assert!(
            matches!(sender.send(sample(2)), Err(error) if error.code == RemoteErrorCode::InvalidState)
        );
    }

    #[test]
    fn a_full_queue_reports_backpressure_without_accepting_the_sample() {
        let config = SenderConfig::new(SampleSenderMode::Hold, 1, 1000).expect("config");
        let mut sender = SampleSender::new(config);
        assert_eq!(sender.send(sample(1)), Ok(SendOutcome::Queued));
        assert!(matches!(
            sender.send(sample(2)),
            Err(error)
                if error.code == RemoteErrorCode::Backpressure && error.retryable
        ));
        assert_eq!(sender.pending_len(), 1);
        assert_eq!(sender.close().len(), 1);
    }

    #[test]
    fn stripped_mode_retains_metadata_and_request_data_but_clears_response_data() {
        let mut child = SampleResult::new("child");
        child.set_request_data(Some(SampleData::new(b"child request".to_vec())));
        child.set_response_data(Some(SampleData::new(b"child response".to_vec())));
        let mut result = SampleResult::new("parent");
        result.set_request_data(Some(SampleData::new(b"parent request".to_vec())));
        result.set_response_data(Some(SampleData::new(b"parent response".to_vec())));
        result
            .try_add_sub_result_raw(child, ValidationLimits::new(8, 8).expect("limits"))
            .expect("child hierarchy");
        let event = SampleEvent::new(
            result,
            "run",
            ThreadIdentity::new("thread"),
            "worker",
            VariableSnapshot::new(),
        );
        let mut sender = SampleSender::new(
            SenderConfig::new(SampleSenderMode::Stripped, 4, 1000).expect("config"),
        );
        assert_eq!(
            sender.send(RemoteSample::new(1, WorkerId::new(1), 1, event)),
            Ok(SendOutcome::Delivered)
        );
        let stripped = sender.drain_delivered().pop().expect("sample");
        let result = stripped.event().result();
        assert_eq!(
            result.request_data().expect("request data").as_bytes(),
            b"parent request"
        );
        assert_eq!(
            result
                .received_bytes()
                .expect("stripping materializes bytes")
                .as_u64(),
            0
        );
        assert_eq!(
            result.response_data().expect("present response").as_bytes(),
            b""
        );
        let child = result.sub_results().first().expect("child");
        assert_eq!(
            child.request_data().expect("child request").as_bytes(),
            b"child request"
        );
        assert_eq!(
            child.response_data().expect("child response").as_bytes(),
            b""
        );
    }

    #[test]
    fn stripped_dedup_compares_original_sample_contents() {
        let config = SenderConfig::new(SampleSenderMode::Stripped, 4, 1000).expect("config");
        let mut sender = SampleSender::new(config);
        assert_eq!(sender.send(sample(1)), Ok(SendOutcome::Delivered));
        let mut changed = sample(1);
        let mut result = changed.event().result().clone();
        result.set_response_data(Some(SampleData::new(b"changed".to_vec())));
        changed = RemoteSample::new(
            1,
            WorkerId::new(1),
            1,
            SampleEvent::new(
                result,
                "run",
                ThreadIdentity::new("thread"),
                "worker",
                VariableSnapshot::new(),
            ),
        );
        assert!(matches!(
            sender.send(changed),
            Err(error) if error.code == RemoteErrorCode::ConflictingDuplicate
        ));
    }

    #[test]
    fn batch_time_threshold_flushes_with_an_injected_clock() {
        let config = SenderConfig::new(SampleSenderMode::Batch { size: 99 }, 99, 1000)
            .expect("config")
            .with_batch_time_ms(10)
            .expect("time threshold");
        let mut sender = SampleSender::new(config);
        assert_eq!(sender.send_at(sample(1), 5), Ok(SendOutcome::Queued));
        assert!(sender.tick(14).expect("tick").is_empty());
        // JMeter's source check is strict (`batchSendTime < now`), so the
        // exact deadline is still part of the current batch.
        assert!(sender.tick(15).expect("exact deadline").is_empty());
        let flushed = sender.tick(16).expect("threshold");
        assert_eq!(flushed.len(), 1);
        assert_eq!(flushed[0].sequence(), 1);
    }

    #[test]
    fn batch_time_expiry_includes_the_arriving_sample() {
        let config = SenderConfig::new(SampleSenderMode::Batch { size: 10 }, 10, 1000)
            .expect("config")
            .with_batch_time_ms(10)
            .expect("time threshold");
        let mut sender = SampleSender::new(config);
        assert_eq!(sender.send_at(sample(1), 0), Ok(SendOutcome::Queued));

        // BatchSampleSender appends the event before checking its absolute
        // deadline, so an event that arrives after expiry is delivered with
        // the prior batch rather than causing a pre-admission flush.
        assert_eq!(
            sender.send_at(sample(2), 11),
            Ok(SendOutcome::QueuedAndFlushed)
        );
        assert_eq!(
            sender
                .drain_delivered()
                .iter()
                .map(RemoteSample::sequence)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
    }

    #[test]
    fn batch_timer_resets_after_count_flush() {
        let config = SenderConfig::new(SampleSenderMode::Batch { size: 2 }, 2, 1000)
            .expect("config")
            .with_batch_time_ms(10)
            .expect("time threshold");
        let mut sender = SampleSender::new(config);
        assert_eq!(sender.send_at(sample(1), 0), Ok(SendOutcome::Queued));
        assert_eq!(
            sender.send_at(sample(2), 5),
            Ok(SendOutcome::QueuedAndFlushed)
        );
        assert_eq!(sender.drain_delivered().len(), 2);

        // The count-triggered flush starts the next deadline at t=5. A
        // sample arriving at t=20 therefore flushes immediately; restarting
        // from that sample would incorrectly retain it until t=30.
        assert_eq!(
            sender.send_at(sample(3), 20),
            Ok(SendOutcome::QueuedAndFlushed)
        );
        assert_eq!(
            sender
                .drain_delivered()
                .iter()
                .map(RemoteSample::sequence)
                .collect::<Vec<_>>(),
            vec![3]
        );
    }

    #[test]
    fn sender_acceptance_is_atomic_at_64k_and_1m_codec_boundaries() {
        for target in [64 * 1024, 1024 * 1024] {
            let field_limit = target;
            let wire = WireLimits::new(target, field_limit).expect("wire limits");
            let limits = RemoteLimits::default()
                .with_wire_limits(wire)
                .with_max_samples(8)
                .with_sample_limits(8, 64)
                .with_max_references(64);
            let config = SenderConfig::from_limits_and_codec(SampleSenderMode::Standard, 2, limits)
                .expect("sender config");
            let mut sender = SampleSender::new(config);
            let exact = sample_at_wire_size(target, field_limit, 1);
            let exact_envelope = sample_envelope(exact.clone());
            assert_eq!(
                sender.send(exact),
                Ok(SendOutcome::Delivered),
                "exact {}-byte sample must be accepted",
                target
            );
            assert!(RemoteCodec::new(limits).encode(&exact_envelope).is_ok());

            let over = sample_at_wire_size(target + 1, field_limit, 2);
            let before = (
                sender.pending_len(),
                sender.delivered().len(),
                sender.retained_bytes(),
            );
            assert!(matches!(
                sender.send(over),
                Err(error) if error.code == RemoteErrorCode::ResourceLimit
            ));
            assert_eq!(
                (
                    sender.pending_len(),
                    sender.delivered().len(),
                    sender.retained_bytes()
                ),
                before,
                "over-bound rejection must not mutate sender state"
            );
        }
    }

    #[test]
    fn custom_field_limit_is_shared_by_sender_and_codec() {
        let wire = WireLimits::new(8 * 1024, 32).expect("custom wire limits");
        let limits = RemoteLimits::default().with_wire_limits(wire);
        let config = SenderConfig::from_limits_and_codec(SampleSenderMode::Standard, 2, limits)
            .expect("custom sender config");
        let mut sender = SampleSender::new(config);
        let mut oversized = sample(1);
        let mut result = oversized.event().result().clone();
        result.set_response_message(Some("x".repeat(33)));
        oversized = RemoteSample::new(
            1,
            WorkerId::new(1),
            1,
            SampleEvent::new(
                result,
                "run",
                ThreadIdentity::new("thread"),
                "worker",
                VariableSnapshot::new(),
            ),
        );
        let envelope = sample_envelope(oversized.clone());
        assert!(matches!(
            RemoteCodec::new(limits).encode(&envelope),
            Err(crate::ProtocolError::FieldTooLarge {
                field: "response message",
                ..
            })
        ));
        assert!(matches!(
            sender.send(oversized),
            Err(error) if error.code == RemoteErrorCode::ResourceLimit
        ));
        assert!(sender.delivered().is_empty());
    }

    #[test]
    fn statistical_mode_aggregates_by_label_and_thread_group() {
        let config = SenderConfig::new(SampleSenderMode::Statistical { size: 2 }, 2, 1000)
            .expect("bounded config");
        let mut sender = SampleSender::new(config);
        assert_eq!(sender.send(sample(1)), Ok(SendOutcome::Queued));
        assert_eq!(sender.send(sample(2)), Ok(SendOutcome::QueuedAndFlushed));
        let aggregate = sender.delivered().first().expect("aggregate");
        assert_eq!(aggregate.sequence(), 1);
        assert_eq!(
            aggregate
                .event()
                .result()
                .sample_count()
                .expect("sample count")
                .as_u64(),
            2
        );
        assert_eq!(
            aggregate
                .event()
                .result()
                .error_count()
                .expect("error count")
                .as_u64(),
            0
        );
    }

    #[test]
    fn statistical_timestamp_is_aggregate_end_not_source_timestamp() {
        let config = SenderConfig::new(SampleSenderMode::Statistical { size: 2 }, 2, 1000)
            .expect("bounded config");
        let mut first_result = SampleResult::new("sample");
        first_result.set_timing_from_wire(SampleTiming::from_wire_parts(
            Some(WallTimestamp::from_millis(10_000)),
            Some(WallTimestamp::from_millis(100)),
            Some(WallTimestamp::from_millis(150)),
            Some(ElapsedTime::from_millis(50)),
            Some(Latency::from_millis(5)),
            Some(ConnectTime::from_millis(2)),
            None,
        ));
        let mut second_result = SampleResult::new("sample");
        second_result.set_timing_from_wire(SampleTiming::from_wire_parts(
            Some(WallTimestamp::from_millis(20_000)),
            Some(WallTimestamp::from_millis(200)),
            Some(WallTimestamp::from_millis(300)),
            Some(ElapsedTime::from_millis(100)),
            Some(Latency::from_millis(7)),
            Some(ConnectTime::from_millis(3)),
            None,
        ));
        let first = RemoteSample::new(
            1,
            WorkerId::new(1),
            1,
            SampleEvent::new(
                first_result,
                "run",
                ThreadIdentity::new("thread"),
                "worker",
                VariableSnapshot::new(),
            ),
        );
        let second = RemoteSample::new(
            1,
            WorkerId::new(1),
            2,
            SampleEvent::new(
                second_result,
                "run",
                ThreadIdentity::new("thread"),
                "worker",
                VariableSnapshot::new(),
            ),
        );
        let mut sender = SampleSender::new(config);
        assert_eq!(sender.send(first), Ok(SendOutcome::Queued));
        assert_eq!(sender.send(second), Ok(SendOutcome::QueuedAndFlushed));
        assert_eq!(
            sender
                .delivered()
                .first()
                .expect("aggregate")
                .event()
                .result()
                .timestamp()
                .map(WallTimestamp::as_millis),
            Some(300)
        );
    }

    #[test]
    fn statistical_wrapper_drops_sample_variables_and_transaction_marker() {
        let config = SenderConfig::new(SampleSenderMode::Statistical { size: 2 }, 2, 1000)
            .expect("bounded config");
        let mut variables = VariableSnapshot::new();
        variables.insert("selected", "first");
        let first_event = SampleEvent::new(
            SampleResult::new("sample"),
            "run",
            ThreadIdentity::new("thread"),
            "worker",
            variables,
        )
        .with_transaction_state(Some(jmeter_rs_results::TransactionState::Start));
        let second_event = SampleEvent::new(
            SampleResult::new("sample"),
            "run",
            ThreadIdentity::new("thread"),
            "worker",
            VariableSnapshot::new(),
        );
        let mut sender = SampleSender::new(config);
        assert_eq!(
            sender.send(RemoteSample::new(1, WorkerId::new(1), 1, first_event)),
            Ok(SendOutcome::Queued)
        );
        assert_eq!(
            sender.send(RemoteSample::new(1, WorkerId::new(1), 2, second_event)),
            Ok(SendOutcome::QueuedAndFlushed)
        );
        let aggregate = sender.delivered().first().expect("aggregate");
        assert!(aggregate.event().variables().is_empty());
        assert_eq!(aggregate.event().transaction_state(), None);
    }

    #[test]
    fn statistical_pending_keys_retain_only_aggregate_correlations() {
        let config = SenderConfig::new(SampleSenderMode::Statistical { size: 3 }, 3, 1000)
            .expect("bounded config");
        let mut sender = SampleSender::new(config);
        assert_eq!(sender.send(sample(1)), Ok(SendOutcome::Queued));
        assert_eq!(sender.send(sample(2)), Ok(SendOutcome::Queued));

        // The sender's deduplication table contains both source samples, but
        // only the first sample key identifies the aggregate retained for
        // delivery. A worker correlation table must not retain source-only
        // keys (2, and later 3) as if they were wire envelopes.
        let pending = sender.pending_sample_keys();
        assert_eq!(
            pending,
            [SampleKey::new(WorkerId::new(1), 1)].into_iter().collect()
        );
        assert_eq!(sender.send(sample(3)), Ok(SendOutcome::QueuedAndFlushed));
        assert!(sender.pending_sample_keys().is_empty());
    }

    #[test]
    fn statistical_mode_counts_unsuccessful_events_once() {
        let config = SenderConfig::new(SampleSenderMode::Statistical { size: 2 }, 2, 1000)
            .expect("bounded config");
        let mut failed = SampleResult::new("sample");
        failed.set_successful(false);
        failed.set_error_count(Some(ErrorCount::from_u64(17)));
        let first = RemoteSample::new(
            1,
            WorkerId::new(1),
            1,
            SampleEvent::new(
                failed,
                "run",
                ThreadIdentity::new("thread"),
                "worker",
                VariableSnapshot::new(),
            ),
        );
        let mut successful = SampleResult::new("sample");
        successful.set_successful(true);
        successful.set_error_count(Some(ErrorCount::from_u64(23)));
        let second = RemoteSample::new(
            1,
            WorkerId::new(1),
            2,
            SampleEvent::new(
                successful,
                "run",
                ThreadIdentity::new("thread"),
                "worker",
                VariableSnapshot::new(),
            ),
        );
        let mut sender = SampleSender::new(config);
        assert_eq!(sender.send(first), Ok(SendOutcome::Queued));
        assert_eq!(sender.send(second), Ok(SendOutcome::QueuedAndFlushed));
        assert_eq!(
            sender
                .delivered()
                .first()
                .expect("aggregate")
                .event()
                .result()
                .error_count()
                .expect("error count")
                .as_u64(),
            1
        );
    }

    #[test]
    fn statistical_mode_keeps_distinct_thread_names_when_configured() {
        let config = SenderConfig::new(SampleSenderMode::Statistical { size: 2 }, 2, 1000)
            .expect("bounded config")
            .with_statistical_key(StatisticalKeyMode::ThreadName);
        let first = sample(1);
        let second = RemoteSample::new(
            1,
            WorkerId::new(1),
            2,
            SampleEvent::new(
                SampleResult::new("sample"),
                "run",
                ThreadIdentity::new("other-thread"),
                "worker",
                VariableSnapshot::new(),
            ),
        );
        let mut sender = SampleSender::new(config);
        assert_eq!(sender.send(first), Ok(SendOutcome::Queued));
        assert_eq!(sender.send(second), Ok(SendOutcome::QueuedAndFlushed));
        assert_eq!(sender.pending_len(), 0);
        assert_eq!(sender.delivered().len(), 2);
    }

    #[test]
    fn asynchronous_modes_wait_for_an_explicit_scheduler_poll() {
        for mode in [
            SampleSenderMode::Asynch { capacity: 2 },
            SampleSenderMode::StrippedAsynch { capacity: 2 },
        ] {
            let config = SenderConfig::new(mode, 2, 1000).expect("bounded config");
            let mut sender = SampleSender::new(config);
            assert_eq!(sender.send(sample(1)), Ok(SendOutcome::Queued));
            assert_eq!(sender.send(sample(2)), Ok(SendOutcome::Queued));
            assert!(matches!(
                sender.send(sample(3)),
                Err(error) if error.code == RemoteErrorCode::Backpressure && error.retryable
            ));
            let delivered = sender.poll();
            assert_eq!(
                delivered
                    .iter()
                    .map(RemoteSample::sequence)
                    .collect::<Vec<_>>(),
                vec![1, 2]
            );
        }
    }

    #[test]
    fn asynchronous_abort_returns_every_queued_sample_without_delivery() {
        let config = SenderConfig::new(SampleSenderMode::Asynch { capacity: 3 }, 3, 1000)
            .expect("bounded config");
        let mut sender = SampleSender::new(config);
        assert_eq!(sender.send(sample(1)), Ok(SendOutcome::Queued));
        assert_eq!(sender.send(sample(2)), Ok(SendOutcome::Queued));
        let dropped = sender.abort();
        assert_eq!(
            dropped
                .iter()
                .map(RemoteSample::sequence)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert!(sender.delivered().is_empty());
        assert_eq!(sender.pending_len(), 0);
        assert!(sender.is_closed());
    }

    #[test]
    fn disk_modes_require_an_injected_store_and_replay_in_order() {
        let memory_config = SenderConfig::new(SampleSenderMode::DiskStore { capacity: 2 }, 2, 1000)
            .expect("bounded config");
        let mut memory_sender = SampleSender::new(memory_config);
        assert!(matches!(
            memory_sender.send(sample(1)),
            Err(error) if error.code == RemoteErrorCode::CapabilityUnavailable
        ));

        for mode in [
            SampleSenderMode::DiskStore { capacity: 2 },
            SampleSenderMode::StrippedDiskStore { capacity: 2 },
        ] {
            let config = SenderConfig::new(mode, 2, 1000)
                .expect("bounded config")
                .with_max_disk_bytes(10_000)
                .expect("disk bound");
            let store = DiskStore::new(2, 10_000).expect("store");
            let mut sender = SampleSender::with_store(config, store);
            assert_eq!(sender.send(sample(1)), Ok(SendOutcome::Queued));
            assert_eq!(sender.send(sample(2)), Ok(SendOutcome::Queued));
            assert_eq!(sender.pending_len(), 2);
            let delivered = sender.close();
            assert_eq!(
                delivered
                    .iter()
                    .map(RemoteSample::sequence)
                    .collect::<Vec<_>>(),
                vec![1, 2]
            );
            assert_eq!(sender.disk_bytes(), 0);
        }
    }

    #[test]
    fn disk_store_limit_rejection_is_atomic_and_retryable() {
        let config = SenderConfig::new(SampleSenderMode::DiskStore { capacity: 2 }, 2, 1000)
            .expect("bounded config");
        let store = DiskStore::new(2, 1).expect("one-byte store");
        let mut sender = SampleSender::with_store(config, store);
        let result = sender.send(sample(1));
        assert!(matches!(
            result,
            Err(error) if error.code == RemoteErrorCode::Backpressure && error.retryable
        ));
        assert_eq!(sender.pending_len(), 0);
        assert_eq!(sender.retained_bytes(), 0);
        assert!(sender.delivered().is_empty());
    }

    #[test]
    fn stripped_sender_honors_strip_on_error_property() {
        let mut result = SampleResult::new("failed");
        result.set_successful(false);
        result.set_error_count(Some(ErrorCount::from_u64(1)));
        result.set_response_data(Some(SampleData::new(b"error body".to_vec())));
        let event = SampleEvent::new(
            result,
            "run",
            ThreadIdentity::new("thread"),
            "worker",
            VariableSnapshot::new(),
        );
        let sample = RemoteSample::new(1, WorkerId::new(1), 1, event);
        let config = SenderConfig::new(SampleSenderMode::Stripped, 2, 1000)
            .expect("bounded config")
            .with_strip_also_on_error(false);
        let mut sender = SampleSender::new(config);
        let sent = sender.send(sample);
        assert_eq!(sent, Ok(SendOutcome::Delivered));
        let delivered = sender.drain_delivered().pop().expect("sample");
        assert_eq!(
            delivered
                .event()
                .result()
                .response_data()
                .expect("error payload retained")
                .as_bytes(),
            b"error body"
        );
    }

    #[test]
    fn stripped_sender_applies_error_policy_from_root() {
        let mut child = SampleResult::new("failed-child");
        child.set_successful(false);
        child.set_error_count(Some(ErrorCount::from_u64(1)));
        child.set_response_data(Some(SampleData::new(b"child error".to_vec())));
        let mut root = SampleResult::new("successful-root");
        root.set_successful(true);
        root.set_error_count(Some(ErrorCount::from_u64(0)));
        root.set_response_data(Some(SampleData::new(b"root body".to_vec())));
        root.try_add_sub_result_raw(child, ValidationLimits::new(8, 8).expect("limits"))
            .expect("child");
        let sample = RemoteSample::new(
            1,
            WorkerId::new(1),
            1,
            SampleEvent::new(
                root,
                "run",
                ThreadIdentity::new("thread"),
                "worker",
                VariableSnapshot::new(),
            ),
        );
        let config = SenderConfig::new(SampleSenderMode::Stripped, 2, 10_000)
            .expect("bounded config")
            .with_strip_also_on_error(false);
        let mut sender = SampleSender::new(config);
        let sent = sender.send(sample);
        assert_eq!(sent, Ok(SendOutcome::Delivered));
        let result = sender
            .drain_delivered()
            .pop()
            .expect("sample")
            .into_event()
            .into_result();
        assert_eq!(
            result.response_data().expect("root payload").as_bytes(),
            b""
        );
        assert_eq!(
            result
                .sub_results()
                .first()
                .expect("child")
                .response_data()
                .expect("child payload")
                .as_bytes(),
            b""
        );
    }

    #[test]
    fn stripped_sender_retains_failed_root_tree_when_error_stripping_is_disabled() {
        let mut child = SampleResult::new("successful-child");
        child.set_successful(true);
        child.set_error_count(Some(ErrorCount::from_u64(0)));
        child.set_response_data(Some(SampleData::new(b"child body".to_vec())));
        let mut root = SampleResult::new("failed-root");
        root.set_successful(false);
        root.set_error_count(Some(ErrorCount::from_u64(1)));
        root.set_response_data(Some(SampleData::new(b"root error".to_vec())));
        root.try_add_sub_result_raw(child, ValidationLimits::new(8, 8).expect("limits"))
            .expect("child");
        let original = RemoteSample::new(
            1,
            WorkerId::new(1),
            1,
            SampleEvent::new(
                root,
                "run",
                ThreadIdentity::new("thread"),
                "worker",
                VariableSnapshot::new(),
            ),
        );
        let config = SenderConfig::new(SampleSenderMode::Stripped, 2, 10_000)
            .expect("config")
            .with_strip_also_on_error(false);
        let mut sender = SampleSender::new(config);
        let sent = sender.send(original.clone());
        assert_eq!(sent, Ok(SendOutcome::Delivered));
        let retained = sender.drain_delivered().pop().expect("sample");
        assert_eq!(
            retained
                .event()
                .result()
                .response_data()
                .expect("root error payload")
                .as_bytes(),
            b"root error"
        );
        assert_eq!(
            retained
                .event()
                .result()
                .sub_results()
                .first()
                .expect("child")
                .response_data()
                .expect("child payload")
                .as_bytes(),
            b"child body"
        );
    }

    #[test]
    fn stripped_sender_clears_only_the_configured_result_depth() {
        let mut deepest = SampleResult::new("depth-4");
        deepest.set_response_data(Some(SampleData::new(b"deep".to_vec())));
        for depth in (0..4).rev() {
            let mut parent = SampleResult::new(format!("depth-{depth}"));
            parent.set_response_data(Some(SampleData::new(b"payload".to_vec())));
            parent
                .try_add_sub_result_raw(deepest, ValidationLimits::new(16, 32).expect("limits"))
                .expect("nested result");
            deepest = parent;
        }
        let sample = RemoteSample::new(
            1,
            WorkerId::new(1),
            1,
            SampleEvent::new(
                deepest,
                "run",
                ThreadIdentity::new("thread"),
                "worker",
                VariableSnapshot::new(),
            ),
        );
        let config =
            SenderConfig::new(SampleSenderMode::Stripped, 2, 10_000).expect("bounded config");
        let mut sender = SampleSender::new(config);
        assert_eq!(sender.send(sample), Ok(SendOutcome::Delivered));
        let mut result = sender
            .drain_delivered()
            .pop()
            .expect("sample")
            .into_event()
            .into_result();
        for _ in 0..4 {
            assert_eq!(
                result.response_data().expect("stripped payload").as_bytes(),
                b""
            );
            result = result.sub_results().first().expect("next depth").clone();
        }
        assert_eq!(
            result.response_data().expect("deep payload").as_bytes(),
            b"deep"
        );
    }

    #[test]
    fn manual_scheduler_is_explicit_and_cancellable() {
        let config = SenderConfig::new(SampleSenderMode::Asynch { capacity: 1 }, 1, 1000)
            .expect("bounded config");
        let sender = SampleSender::new(config);
        let mut scheduler = ManualSenderScheduler::new();
        sender.schedule_poll(&mut scheduler, 42).expect("schedule");
        assert_eq!(scheduler.scheduled_at_ms(), Some(42));
        sender.cancel_poll(&mut scheduler).expect("cancel");
        assert_eq!(scheduler.scheduled_at_ms(), None);
        assert!(scheduler.is_cancelled());
    }

    #[test]
    fn custom_sender_descriptor_is_not_a_native_success_path() {
        let descriptor =
            CustomSenderDescriptor::new("org.example.CustomSampleSender", "jvm.sample-sender")
                .expect("descriptor");
        let descriptor = SenderDescriptor::Custom(descriptor);
        let error = SampleSender::<MemorySampleStore>::require_descriptor(&descriptor)
            .expect_err("custom sender must require an adapter");
        assert_eq!(error.code, RemoteErrorCode::CapabilityUnavailable);
    }

    #[test]
    fn every_supported_sender_mode_has_a_deterministic_delivery_path() {
        for mode in [
            SampleSenderMode::Standard,
            SampleSenderMode::Hold,
            SampleSenderMode::Batch { size: 2 },
            SampleSenderMode::Stripped,
            SampleSenderMode::StrippedBatch { size: 2 },
        ] {
            let capacity = mode.capacity().unwrap_or(2);
            let config = SenderConfig::new(mode, capacity, 1000).expect("bounded config");
            let mut sender = SampleSender::new(config);
            let first = sender.send(sample(1)).expect("first sample");
            match mode {
                SampleSenderMode::Standard | SampleSenderMode::Stripped => {
                    assert_eq!(first, SendOutcome::Delivered);
                }
                SampleSenderMode::Hold => assert_eq!(first, SendOutcome::Queued),
                SampleSenderMode::Batch { .. } | SampleSenderMode::StrippedBatch { .. } => {
                    assert_eq!(first, SendOutcome::Queued);
                    assert_eq!(sender.send(sample(2)), Ok(SendOutcome::QueuedAndFlushed));
                }
                _ => continue,
            }
            if matches!(mode, SampleSenderMode::Hold) {
                assert_eq!(sender.close().len(), 1);
            } else {
                assert_eq!(
                    sender.drain_delivered().len(),
                    1 + usize::from(mode.capacity() == Some(2))
                );
            }
        }
    }
}
