// SPDX-License-Identifier: Apache-2.0
//! Deterministic coordinator and worker lifecycle state machines.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt,
};

use crate::error::{MAX_WIRE_FAILURE_MESSAGE_BYTES, RemoteError, RemoteErrorCode};
use crate::protocol::{
    AckStage, FailurePolicy, PlanDescriptor, ProfileDescriptor, PropertySet, RemoteCodec,
    RemoteConfigurationLimits, RemoteEnvelope, RemoteLimits, RemoteMessage, RemoteRequestContext,
    RemoteSample, RequestId, RunId, SampleKey, SampleSenderMode, StopMode, WorkerId,
    is_sample_envelope_request_id, sample_envelope_request_id, sample_envelope_worker,
    uses_sample_envelope_namespace, validate_configuration,
};
use crate::sender::{SampleSender, SendOutcome, SenderConfig};

const DEFAULT_MAX_RETAINED_BYTES: usize = 4096usize.saturating_mul(1024).saturating_mul(1024);

fn validate_run_id(run_id: RunId) -> Result<(), RemoteError> {
    if run_id == 0 {
        return Err(RemoteError::new(
            RemoteErrorCode::Protocol,
            false,
            "run generation must be non-zero",
        ));
    }
    Ok(())
}

/// Worker lifecycle state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum WorkerPhase {
    /// No profile, plan, or properties have been accepted.
    Idle,
    /// Profile/plan/properties were accepted and the worker can start.
    Ready,
    /// The worker is executing its full plan copy.
    Running,
    /// A stop request is being completed.
    Stopping,
    /// The run ended normally.
    Stopped,
    /// The worker failed and will not accept further run messages.
    Failed,
}

/// Coordinator lifecycle state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CoordinatorPhase {
    /// No worker configuration has been dispatched.
    Idle,
    /// Profile, plan, and properties are being acknowledged.
    Configuring,
    /// Every non-failed selected worker is ready to start.
    Ready,
    /// Start messages are in flight.
    Starting,
    /// At least one worker is running.
    Running,
    /// Stop messages are in flight.
    Stopping,
    /// All healthy workers stopped and pending samples were flushed.
    Stopped,
    /// The run cannot continue under the selected failure policy.
    Failed,
}

/// Bounded lifecycle retry policy. The initial request counts as attempt one;
/// a policy of three permits at most two explicitly requested retries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    max_attempts: u32,
}

impl RetryPolicy {
    /// Creates a policy with a finite, non-zero attempt bound.
    pub const fn new(max_attempts: u32) -> Option<Self> {
        if max_attempts == 0 {
            None
        } else {
            Some(Self { max_attempts })
        }
    }

    /// Returns the total number of attempts allowed for one lifecycle stage.
    pub const fn max_attempts(self) -> u32 {
        self.max_attempts
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self { max_attempts: 3 }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StopCause {
    User(StopMode),
    FailFast,
}

#[derive(Clone, Debug)]
struct PendingRequest {
    worker: WorkerId,
    stage: AckStage,
    attempt: u32,
    message: RemoteMessage,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CompletedRequest {
    worker: WorkerId,
    stage: AckStage,
    run_id: Option<RunId>,
    thread_count: Option<u32>,
    sample_watermark: Option<u64>,
}

/// Local references available on a worker. No filesystem is accessed here.
#[derive(Clone, Eq, PartialEq)]
pub struct WorkerResources {
    data_references: BTreeSet<(String, String)>,
    dependencies: BTreeSet<(String, String)>,
    limits: RemoteConfigurationLimits,
}

impl fmt::Debug for WorkerResources {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkerResources")
            .field("data_reference_count", &self.data_references.len())
            .field("dependency_count", &self.dependencies.len())
            .field(
                "resource_bytes",
                &self.resource_bytes().map_or(usize::MAX, |bytes| bytes),
            )
            .finish()
    }
}

impl Default for WorkerResources {
    fn default() -> Self {
        Self::new()
    }
}

impl WorkerResources {
    /// Creates empty worker-local resources.
    pub const fn new() -> Self {
        Self {
            data_references: BTreeSet::new(),
            dependencies: BTreeSet::new(),
            limits: RemoteConfigurationLimits::new(),
        }
    }

    /// Creates empty resources with explicit finite bounds.
    pub fn with_limits(limits: RemoteConfigurationLimits) -> Result<Self, RemoteError> {
        if !limits.is_valid() {
            return Err(RemoteError::new(
                RemoteErrorCode::ResourceLimit,
                false,
                "remote configuration limits must be non-zero",
            ));
        }
        Ok(Self {
            data_references: BTreeSet::new(),
            dependencies: BTreeSet::new(),
            limits,
        })
    }

    /// Adds an untyped available data path.
    ///
    /// A plan reference with a non-empty kind must use
    /// [`Self::add_data_reference`] so capability identity cannot be reduced
    /// to the path alone.
    pub fn add_data_path(&mut self, path: impl Into<String>) -> Result<(), RemoteError> {
        self.add_data_reference(path, "")
    }

    /// Adds an available data path with its semantic reference kind.
    pub fn add_data_reference(
        &mut self,
        path: impl Into<String>,
        kind: impl Into<String>,
    ) -> Result<(), RemoteError> {
        let reference = (path.into(), kind.into());
        if self.data_references.contains(&reference) {
            return Ok(());
        }
        let bytes = reference
            .0
            .len()
            .checked_add(reference.1.len())
            .ok_or_else(|| {
                RemoteError::new(
                    RemoteErrorCode::ResourceLimit,
                    false,
                    "worker resource bytes overflowed",
                )
            })?;
        self.ensure_capacity(bytes)?;
        self.data_references.insert(reference);
        Ok(())
    }

    /// Adds an installed dependency.
    pub fn add_dependency(
        &mut self,
        name: impl Into<String>,
        version: impl Into<String>,
    ) -> Result<(), RemoteError> {
        let dependency = (name.into(), version.into());
        if self.dependencies.contains(&dependency) {
            return Ok(());
        }
        let bytes = dependency
            .0
            .len()
            .checked_add(dependency.1.len())
            .ok_or_else(|| {
                RemoteError::new(
                    RemoteErrorCode::ResourceLimit,
                    false,
                    "worker resource bytes overflowed",
                )
            })?;
        self.ensure_capacity(bytes)?;
        self.dependencies.insert(dependency);
        Ok(())
    }

    /// Applies resource bounds without exceeding existing entries.
    pub fn set_limits(&mut self, limits: RemoteConfigurationLimits) -> Result<(), RemoteError> {
        if !limits.is_valid() {
            return Err(RemoteError::new(
                RemoteErrorCode::ResourceLimit,
                false,
                "remote configuration limits must be non-zero",
            ));
        }
        self.validate_with_limits(limits)?;
        self.limits = limits;
        Ok(())
    }

    /// Validates current resource entries against explicit finite limits.
    pub fn validate_with_limits(
        &self,
        limits: RemoteConfigurationLimits,
    ) -> Result<(), RemoteError> {
        if !limits.is_valid() {
            return Err(RemoteError::new(
                RemoteErrorCode::ResourceLimit,
                false,
                "remote configuration limits must be non-zero",
            ));
        }
        if self.resource_count()? > limits.max_resource_entries()
            || self.resource_bytes()? > limits.max_resource_bytes()
        {
            return Err(RemoteError::new(
                RemoteErrorCode::ResourceLimit,
                false,
                "worker resources exceed the requested bounds",
            ));
        }
        Ok(())
    }

    fn resource_count(&self) -> Result<usize, RemoteError> {
        self.data_references
            .len()
            .checked_add(self.dependencies.len())
            .ok_or_else(|| {
                RemoteError::new(
                    RemoteErrorCode::ResourceLimit,
                    false,
                    "worker resource count overflowed",
                )
            })
    }

    fn resource_bytes(&self) -> Result<usize, RemoteError> {
        self.data_references
            .iter()
            .try_fold(0usize, |total, (path, kind)| {
                total
                    .checked_add(path.len())
                    .and_then(|total| total.checked_add(kind.len()))
                    .ok_or_else(|| {
                        RemoteError::new(
                            RemoteErrorCode::ResourceLimit,
                            false,
                            "worker resource bytes overflowed",
                        )
                    })
            })?
            .checked_add(
                self.dependencies
                    .iter()
                    .try_fold(0usize, |total, (name, version)| {
                        total
                            .checked_add(name.len())
                            .and_then(|total| total.checked_add(version.len()))
                            .ok_or_else(|| {
                                RemoteError::new(
                                    RemoteErrorCode::ResourceLimit,
                                    false,
                                    "worker resource bytes overflowed",
                                )
                            })
                    })?,
            )
            .ok_or_else(|| {
                RemoteError::new(
                    RemoteErrorCode::ResourceLimit,
                    false,
                    "worker resource bytes overflowed",
                )
            })
    }

    fn ensure_capacity(&self, additional_bytes: usize) -> Result<(), RemoteError> {
        let entries = self.resource_count()?.checked_add(1).ok_or_else(|| {
            RemoteError::new(
                RemoteErrorCode::ResourceLimit,
                false,
                "worker resource count overflowed",
            )
        })?;
        let bytes = self
            .resource_bytes()?
            .checked_add(additional_bytes)
            .ok_or_else(|| {
                RemoteError::new(
                    RemoteErrorCode::ResourceLimit,
                    false,
                    "worker resource bytes overflowed",
                )
            })?;
        if entries > self.limits.max_resource_entries() || bytes > self.limits.max_resource_bytes()
        {
            return Err(RemoteError::new(
                RemoteErrorCode::ResourceLimit,
                false,
                "worker resource bound exhausted",
            ));
        }
        Ok(())
    }

    /// Returns whether every plan-local reference is available.
    fn satisfies(&self, plan: &PlanDescriptor) -> Result<(), RemoteError> {
        for reference in plan.data_references() {
            if !self
                .data_references
                .contains(&(reference.path().to_owned(), reference.kind().to_owned()))
            {
                return Err(RemoteError::new(
                    RemoteErrorCode::CapabilityUnavailable,
                    false,
                    format!("worker lacks data reference {}", reference.path()),
                ));
            }
        }
        for dependency in plan.dependencies() {
            if !self.dependencies.contains(&(
                dependency.name().to_owned(),
                dependency.version().to_owned(),
            )) {
                return Err(RemoteError::new(
                    RemoteErrorCode::CapabilityUnavailable,
                    false,
                    format!(
                        "worker lacks dependency {}@{}",
                        dependency.name(),
                        dependency.version()
                    ),
                ));
            }
        }
        Ok(())
    }
}

/// A deterministic worker-side state machine.
pub struct RemoteWorker {
    id: WorkerId,
    advertised_profile: ProfileDescriptor,
    accepted_profile: Option<ProfileDescriptor>,
    plan: Option<PlanDescriptor>,
    properties: Option<PropertySet>,
    resources: WorkerResources,
    configuration_limits: RemoteConfigurationLimits,
    wire_codec_limits: RemoteLimits,
    phase: WorkerPhase,
    run_id: Option<RunId>,
    // A run ID is a logical generation, not a reusable transport sequence.
    // Retaining the last consumed generation prevents a delayed start/stop
    // from an older configuration from resurrecting or cancelling a newer
    // stopped worker.
    last_run_id: Option<RunId>,
    consumed_run_ids: BTreeSet<RunId>,
    consumed_run_order: VecDeque<RunId>,
    // Configuration request identity provides a bounded stale-frame guard
    // for Profile/Plan/Properties, whose wire bodies intentionally carry no
    // run generation. Coordinator request IDs are monotonic and globally
    // unique; a lower ID from a retired configuration can therefore never
    // replace a newer staged plan.
    profile_request_id: Option<RequestId>,
    thread_count: u32,
    sender_mode: Option<SampleSenderMode>,
    sender: Option<SampleSender>,
    batch_time_ms: Option<u64>,
    next_sequence: u64,
    // Exclusive prefix of worker sequences released by the sender. An
    // immediate stop may cancel samples accepted by a Hold/Batch sender, so
    // this is intentionally distinct from `next_sequence`.
    delivered_watermark: u64,
    next_sample_envelope_ordinal: u64,
    sample_envelope_ids: BTreeMap<SampleKey, RequestId>,
    failure: Option<RemoteError>,
}

impl fmt::Debug for RemoteWorker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteWorker")
            .field("id", &self.id)
            .field("phase", &self.phase)
            .field("run_id", &self.run_id)
            .field("last_run_id", &self.last_run_id)
            .field("consumed_run_count", &self.consumed_run_ids.len())
            .field("profile_request_id", &self.profile_request_id)
            .field("thread_count", &self.thread_count)
            .field("delivered_watermark", &self.delivered_watermark)
            .field("sender_mode", &self.sender_mode)
            .field("has_plan", &self.plan.is_some())
            .field(
                "property_count",
                &self.properties.as_ref().map(PropertySet::len),
            )
            .field("resources", &self.resources)
            .field(
                "pending_sample_correlations",
                &self.sample_envelope_ids.len(),
            )
            .field("failure", &self.failure)
            .finish()
    }
}

impl RemoteWorker {
    /// Creates a worker that advertises one exact compatibility profile.
    pub fn new(id: WorkerId, profile: ProfileDescriptor) -> Self {
        Self {
            id,
            advertised_profile: profile,
            accepted_profile: None,
            plan: None,
            properties: None,
            resources: WorkerResources::new(),
            configuration_limits: RemoteConfigurationLimits::default(),
            wire_codec_limits: RemoteLimits::default(),
            phase: WorkerPhase::Idle,
            run_id: None,
            last_run_id: None,
            consumed_run_ids: BTreeSet::new(),
            consumed_run_order: VecDeque::new(),
            profile_request_id: None,
            thread_count: 0,
            sender_mode: None,
            sender: None,
            batch_time_ms: None,
            next_sequence: 0,
            delivered_watermark: 0,
            next_sample_envelope_ordinal: 1,
            sample_envelope_ids: BTreeMap::new(),
            failure: None,
        }
    }

    /// Replaces worker-local references used for plan capability checks after
    /// checking them against this worker's current resource bounds. Resource
    /// capabilities are immutable once configuration reaches `Ready`; a new
    /// profile/configuration cycle must begin from `Idle` before they can be
    /// replaced.
    pub fn set_resources(&mut self, resources: WorkerResources) -> Result<(), RemoteError> {
        if self.phase != WorkerPhase::Idle {
            return Err(RemoteError::state(
                "worker resources are immutable after configuration became ready",
            ));
        }
        resources.validate_with_limits(self.configuration_limits)?;
        if let Some(plan) = &self.plan {
            resources.satisfies(plan)?;
        }
        self.resources = resources;
        Ok(())
    }

    /// Sets finite bounds for configuration and worker-local resources.
    pub fn set_configuration_limits(
        &mut self,
        limits: RemoteConfigurationLimits,
    ) -> Result<(), RemoteError> {
        if self.phase != WorkerPhase::Idle {
            return Err(RemoteError::state(
                "worker configuration limits are immutable after configuration became ready",
            ));
        }
        if !limits.is_valid() {
            return Err(RemoteError::new(
                RemoteErrorCode::ResourceLimit,
                false,
                "remote configuration limits must be non-zero",
            ));
        }
        if let (Some(plan), Some(properties)) = (&self.plan, &self.properties) {
            validate_configuration(plan, properties, limits)?;
        } else {
            if let Some(plan) = &self.plan {
                plan.validate_with_limits(limits)?;
            }
            if let Some(properties) = &self.properties {
                properties.validate_with_limits(limits)?;
            }
        }
        self.resources.set_limits(limits)?;
        self.configuration_limits = limits;
        Ok(())
    }

    /// Returns configuration and worker-local resource bounds.
    pub const fn configuration_limits(&self) -> RemoteConfigurationLimits {
        self.configuration_limits
    }

    /// Sets the exact message, field, and result bounds shared by this
    /// worker's sender and its transport codec.  Wire limits are immutable
    /// once configuration leaves `Idle` so a running sender cannot be paired
    /// with a different encoder after accepting samples.
    pub fn set_codec_limits(&mut self, limits: RemoteLimits) -> Result<(), RemoteError> {
        if self.phase != WorkerPhase::Idle {
            return Err(RemoteError::state(
                "worker codec limits are immutable after configuration began",
            ));
        }
        limits.validate()?;
        self.advertised_profile.validate_with_limits(limits)?;
        if let Some(profile) = &self.accepted_profile {
            profile.validate_with_limits(limits)?;
        }
        self.wire_codec_limits = limits;
        self.trim_consumed_run_ids();
        Ok(())
    }

    /// Returns the validated bounds shared by the worker sender and codec.
    pub const fn codec_limits(&self) -> RemoteLimits {
        self.wire_codec_limits
    }

    /// Returns worker identity.
    pub const fn id(&self) -> WorkerId {
        self.id
    }

    /// Returns the profile accepted during configuration.
    pub fn profile(&self) -> Option<&ProfileDescriptor> {
        self.accepted_profile.as_ref()
    }

    /// Returns current worker phase.
    pub const fn phase(&self) -> WorkerPhase {
        self.phase
    }

    /// Returns the configured logical thread count.
    pub const fn thread_count(&self) -> u32 {
        self.thread_count
    }

    /// Returns the failure, if this worker is terminally failed.
    pub fn failure(&self) -> Option<&RemoteError> {
        self.failure.as_ref()
    }

    /// Returns the accepted plan, if configuration completed.
    pub fn plan(&self) -> Option<&PlanDescriptor> {
        self.plan.as_ref()
    }

    /// Returns the worker's run-scoped properties.
    pub fn properties(&self) -> Option<&PropertySet> {
        self.properties.as_ref()
    }

    /// Returns the active run identity.
    pub const fn run_id(&self) -> Option<RunId> {
        self.run_id
    }

    /// Returns the configured sender mode.
    pub const fn sender_mode(&self) -> Option<SampleSenderMode> {
        self.sender_mode
    }

    /// Configures an injected batch-time threshold for the next sender.
    /// Adapters advance it with [`Self::advance_time`]; this core never reads
    /// a wall clock.
    pub fn set_batch_time_ms(&mut self, threshold: u64) -> Result<(), RemoteError> {
        if threshold == 0 {
            return Err(RemoteError::new(
                RemoteErrorCode::ResourceLimit,
                false,
                "batch time threshold must be non-zero",
            ));
        }
        self.batch_time_ms = Some(threshold);
        Ok(())
    }

    /// Applies one coordinator message and returns deterministic responses.
    pub fn apply(&mut self, envelope: RemoteEnvelope) -> Result<Vec<RemoteEnvelope>, RemoteError> {
        if envelope.request_id == 0 || uses_sample_envelope_namespace(envelope.request_id) {
            return Err(RemoteError::new(
                RemoteErrorCode::Protocol,
                false,
                "worker control message used an invalid request ID namespace",
            ));
        }
        if self.phase == WorkerPhase::Failed {
            return Err(self
                .failure
                .clone()
                .unwrap_or_else(|| RemoteError::state("worker is failed")));
        }
        let request_id = envelope.request_id;
        match envelope.message {
            RemoteMessage::Profile { profile } => self.accept_profile(request_id, profile),
            RemoteMessage::Plan { plan } => self.accept_plan(request_id, plan),
            RemoteMessage::Properties { properties } => {
                self.accept_properties(request_id, properties)
            }
            RemoteMessage::Start {
                run_id,
                thread_count,
                sender_mode,
            } => self.start(request_id, run_id, thread_count, sender_mode),
            RemoteMessage::Stop { run_id, mode } => self.stop(request_id, run_id, mode),
            _ => Err(RemoteError::state(
                "worker received a coordinator-invalid message",
            )),
        }
    }

    /// Applies a coordinator message after checking a typed deadline and
    /// cancellation policy supplied by the transport/runtime adapter.
    pub fn apply_with_context(
        &mut self,
        envelope: RemoteEnvelope,
        context: RemoteRequestContext,
        now_unix_millis: u64,
    ) -> Result<Vec<RemoteEnvelope>, RemoteError> {
        context.check(now_unix_millis)?;
        self.apply(envelope)
    }

    /// Emits one worker sample. The sequence is assigned monotonically and
    /// the returned envelopes are suitable for the coordinator.
    pub fn emit_sample(
        &mut self,
        event: jmeter_rs_results::SampleEvent,
    ) -> Result<Vec<RemoteEnvelope>, RemoteError> {
        if self.phase != WorkerPhase::Running {
            return Err(RemoteError::state("worker is not running"));
        }
        let run_id = self
            .run_id
            .ok_or_else(|| RemoteError::state("worker has no active run"))?;
        let sequence = self.next_sequence;
        let next_sequence = sequence.checked_add(1).ok_or_else(|| {
            RemoteError::new(
                RemoteErrorCode::ResourceLimit,
                false,
                "worker sample sequence exhausted",
            )
        })?;
        let envelope_ordinal = self.next_sample_envelope_ordinal;
        let envelope_request_id = sample_envelope_request_id(self.id, envelope_ordinal)?;
        let next_envelope_ordinal = envelope_ordinal.checked_add(1).ok_or_else(|| {
            RemoteError::new(
                RemoteErrorCode::ResourceLimit,
                false,
                "worker sample-envelope ID space exhausted",
            )
        })?;
        let sample = RemoteSample::new(run_id, self.id, sequence, event);
        if self.sample_envelope_ids.len() >= self.wire_codec_limits.max_samples() {
            return Err(RemoteError::new(
                RemoteErrorCode::ResourceLimit,
                true,
                "worker sample-envelope correlation bound exhausted",
            ));
        }
        let sender = self
            .sender
            .as_mut()
            .ok_or_else(|| RemoteError::state("worker sender is missing"))?;
        sender.send(sample.clone())?;
        self.next_sequence = next_sequence;
        self.next_sample_envelope_ordinal = next_envelope_ordinal;
        self.sample_envelope_ids
            .insert(sample.key(), envelope_request_id);
        let (pending_keys, delivered) = {
            let pending_keys = sender.pending_sample_keys();
            let delivered = sender.drain_delivered();
            (pending_keys, delivered)
        };
        self.note_delivered_samples(&delivered);
        self.prune_sample_envelope_ids(&pending_keys, &delivered);
        self.envelopes_for_delivered(delivered)
    }

    /// Emits a sample after checking a typed deadline/cancellation policy
    /// supplied by the transport/runtime adapter.
    pub fn emit_sample_with_context(
        &mut self,
        event: jmeter_rs_results::SampleEvent,
        context: RemoteRequestContext,
        now_unix_millis: u64,
    ) -> Result<Vec<RemoteEnvelope>, RemoteError> {
        context.check(now_unix_millis)?;
        self.emit_sample(event)
    }

    /// Advances the worker sender's injected logical clock and returns any
    /// samples released by a configured batch time threshold.  No wall-clock
    /// or executor access occurs in the pure remote core.
    pub fn advance_time(&mut self, now_ms: u64) -> Result<Vec<RemoteEnvelope>, RemoteError> {
        if !matches!(self.phase, WorkerPhase::Running | WorkerPhase::Stopping) {
            return Err(RemoteError::state(
                "worker time can advance only for an active run",
            ));
        }
        let sender = self
            .sender
            .as_mut()
            .ok_or_else(|| RemoteError::state("worker sender is missing"))?;
        let delivered = sender.advance_time(now_ms)?;
        let pending_keys = sender.pending_sample_keys();
        self.note_delivered_samples(&delivered);
        self.prune_sample_envelope_ids(&pending_keys, &delivered);
        self.envelopes_for_delivered(delivered)
    }

    /// Alias for deterministic adapters that model a sender clock tick.
    pub fn tick(&mut self, now_ms: u64) -> Result<Vec<RemoteEnvelope>, RemoteError> {
        self.advance_time(now_ms)
    }

    fn envelopes_for_delivered(
        &mut self,
        delivered: Vec<RemoteSample>,
    ) -> Result<Vec<RemoteEnvelope>, RemoteError> {
        delivered
            .into_iter()
            .map(|sample| {
                let request_id =
                    self.sample_envelope_ids
                        .remove(&sample.key())
                        .ok_or_else(|| {
                            RemoteError::new(
                                RemoteErrorCode::Internal,
                                false,
                                "delivered sample had no envelope correlation",
                            )
                        })?;
                Ok(RemoteEnvelope::new(
                    request_id,
                    RemoteMessage::Sample { sample },
                ))
            })
            .collect()
    }

    fn prune_sample_envelope_ids(
        &mut self,
        pending_keys: &BTreeSet<SampleKey>,
        delivered: &[RemoteSample],
    ) {
        let delivered_keys = delivered
            .iter()
            .map(RemoteSample::key)
            .collect::<BTreeSet<_>>();
        self.sample_envelope_ids
            .retain(|key, _| pending_keys.contains(key) || delivered_keys.contains(key));
    }

    fn note_delivered_samples(&mut self, delivered: &[RemoteSample]) {
        for sample in delivered {
            // Native sender modes preserve sequence order. Taking the
            // maximum also keeps this accounting monotonic if an adapter
            // replays an already-delivered batch before the envelope is
            // consumed by its transport.
            self.delivered_watermark = self
                .delivered_watermark
                .max(sample.sequence().saturating_add(1));
        }
    }

    fn remember_run_id(&mut self, run_id: RunId) {
        if self.consumed_run_ids.insert(run_id) {
            self.consumed_run_order.push_back(run_id);
        }
        self.trim_consumed_run_ids();
    }

    fn trim_consumed_run_ids(&mut self) {
        while self.consumed_run_ids.len() > self.wire_codec_limits.max_samples() {
            let Some(oldest) = self.consumed_run_order.pop_front() else {
                break;
            };
            self.consumed_run_ids.remove(&oldest);
        }
    }

    fn accept_profile(
        &mut self,
        request_id: u64,
        profile: ProfileDescriptor,
    ) -> Result<Vec<RemoteEnvelope>, RemoteError> {
        if self
            .profile_request_id
            .is_some_and(|previous| request_id < previous)
        {
            return Err(RemoteError::new(
                RemoteErrorCode::Cancelled,
                false,
                "profile belongs to a retired configuration generation",
            ));
        }
        self.advertised_profile
            .validate_with_limits(self.wire_codec_limits)?;
        profile.validate_with_limits(self.wire_codec_limits)?;
        if matches!(self.phase, WorkerPhase::Idle | WorkerPhase::Ready)
            && self.accepted_profile.as_ref() == Some(&profile)
        {
            self.profile_request_id = Some(request_id);
            return Ok(vec![self.ack(request_id, AckStage::Profile, None, None)]);
        }
        if !matches!(self.phase, WorkerPhase::Idle | WorkerPhase::Stopped) {
            return Err(RemoteError::state("profile must precede a running worker"));
        }
        if !self.advertised_profile.supports(&profile) {
            return Err(RemoteError::new(
                RemoteErrorCode::ProfileMismatch,
                false,
                format!(
                    "worker {} does not support profile {}",
                    self.id.as_u32(),
                    profile.id()
                ),
            ));
        }
        self.accepted_profile = Some(profile);
        self.profile_request_id = Some(request_id);
        self.plan = None;
        self.properties = None;
        self.run_id = None;
        self.sender = None;
        self.sender_mode = None;
        self.next_sequence = 0;
        self.delivered_watermark = 0;
        self.sample_envelope_ids.clear();
        self.thread_count = 0;
        self.phase = WorkerPhase::Idle;
        self.recompute_ready();
        Ok(vec![self.ack(request_id, AckStage::Profile, None, None)])
    }

    fn accept_plan(
        &mut self,
        request_id: u64,
        plan: PlanDescriptor,
    ) -> Result<Vec<RemoteEnvelope>, RemoteError> {
        if self
            .profile_request_id
            .is_some_and(|profile_request_id| request_id < profile_request_id)
        {
            return Err(RemoteError::new(
                RemoteErrorCode::Cancelled,
                false,
                "plan belongs to a retired configuration generation",
            ));
        }
        if self.accepted_profile.is_none()
            || !matches!(self.phase, WorkerPhase::Idle | WorkerPhase::Ready)
        {
            return Err(RemoteError::state(
                "plan requires an accepted profile before start",
            ));
        }
        plan.validate_with_limits(self.configuration_limits)?;
        if matches!(self.phase, WorkerPhase::Idle | WorkerPhase::Ready)
            && self.plan.as_ref() == Some(&plan)
        {
            return Ok(vec![self.ack(request_id, AckStage::Plan, None, None)]);
        }
        if self.phase == WorkerPhase::Ready {
            return Err(RemoteError::state(
                "worker plan cannot change after configuration became ready",
            ));
        }
        self.resources.satisfies(&plan)?;
        self.plan = Some(plan);
        self.recompute_ready();
        Ok(vec![self.ack(request_id, AckStage::Plan, None, None)])
    }

    fn accept_properties(
        &mut self,
        request_id: u64,
        properties: PropertySet,
    ) -> Result<Vec<RemoteEnvelope>, RemoteError> {
        if self
            .profile_request_id
            .is_some_and(|profile_request_id| request_id < profile_request_id)
        {
            return Err(RemoteError::new(
                RemoteErrorCode::Cancelled,
                false,
                "properties belong to a retired configuration generation",
            ));
        }
        if self.accepted_profile.is_none()
            || self.plan.is_none()
            || !matches!(self.phase, WorkerPhase::Idle | WorkerPhase::Ready)
        {
            return Err(RemoteError::state("properties require profile and plan"));
        }
        if let Some(plan) = &self.plan {
            validate_configuration(plan, &properties, self.configuration_limits)?;
        } else {
            properties.validate_with_limits(self.configuration_limits)?;
        }
        if matches!(self.phase, WorkerPhase::Idle | WorkerPhase::Ready)
            && self.properties.as_ref() == Some(&properties)
        {
            return Ok(vec![self.ack(request_id, AckStage::Properties, None, None)]);
        }
        if self.phase == WorkerPhase::Ready {
            return Err(RemoteError::state(
                "worker properties cannot change after configuration became ready",
            ));
        }
        self.properties = Some(properties);
        self.recompute_ready();
        Ok(vec![self.ack(request_id, AckStage::Properties, None, None)])
    }

    fn start(
        &mut self,
        request_id: u64,
        run_id: RunId,
        thread_count: u32,
        mode: SampleSenderMode,
    ) -> Result<Vec<RemoteEnvelope>, RemoteError> {
        validate_run_id(run_id)?;
        if self.phase == WorkerPhase::Running
            && self.run_id == Some(run_id)
            && self.thread_count == thread_count
            && self.sender_mode == Some(mode)
        {
            // A retry with a fresh request ID after a lost ACK must not start
            // a second sender or reset the worker's sample sequence.
            return Ok(vec![self.ack(
                request_id,
                AckStage::Started,
                Some(run_id),
                Some(thread_count),
            )]);
        }
        if self.phase == WorkerPhase::Ready
            && self
                .last_run_id
                .is_some_and(|last_run_id| run_id == last_run_id)
        {
            return Err(RemoteError::state(
                "worker run generation is stale or already consumed",
            ));
        }
        if self.phase == WorkerPhase::Ready && self.consumed_run_ids.contains(&run_id) {
            return Err(RemoteError::state(
                "worker run generation was already consumed",
            ));
        }
        if thread_count == 0 {
            return Err(RemoteError::new(
                RemoteErrorCode::ResourceLimit,
                false,
                "thread count must be non-zero",
            ));
        }
        if !mode.execution_supported() {
            return Err(mode.unsupported_error().unwrap_or_else(|| {
                RemoteError::new(
                    RemoteErrorCode::CapabilityUnavailable,
                    false,
                    "sender mode is unavailable in the Rust-native remote core",
                )
            }));
        }
        if self.phase != WorkerPhase::Ready {
            return Err(RemoteError::state(
                "worker start requires ready configuration",
            ));
        }
        let plan = self
            .plan
            .as_ref()
            .ok_or_else(|| RemoteError::state("worker start has no configured plan"))?;
        // Recheck all worker-local data/dependency references immediately
        // before the first run mutation. The public resource setter rejects
        // post-Ready changes, but this guard also protects the state boundary
        // if capabilities are supplied by an internal adapter.
        self.resources.satisfies(plan)?;
        let capacity = mode.capacity().unwrap_or(4096);
        let config = SenderConfig::from_limits_and_codec(mode, capacity, self.wire_codec_limits)
            .ok_or_else(|| {
                RemoteError::new(
                    RemoteErrorCode::ResourceLimit,
                    false,
                    "worker sender codec limits are invalid",
                )
            })?;
        let config = self
            .batch_time_ms
            .map_or(Some(config), |threshold| {
                config.with_batch_time_ms(threshold)
            })
            .ok_or_else(|| {
                RemoteError::new(
                    RemoteErrorCode::ResourceLimit,
                    false,
                    "batch time threshold must be non-zero",
                )
            })?;
        self.run_id = Some(run_id);
        self.last_run_id = Some(run_id);
        self.remember_run_id(run_id);
        self.thread_count = thread_count;
        self.sender_mode = Some(mode);
        self.sender = Some(SampleSender::new(config));
        self.next_sequence = 0;
        self.delivered_watermark = 0;
        self.sample_envelope_ids.clear();
        self.phase = WorkerPhase::Running;
        Ok(vec![self.ack(
            request_id,
            AckStage::Started,
            Some(run_id),
            Some(thread_count),
        )])
    }

    fn stop(
        &mut self,
        request_id: u64,
        run_id: RunId,
        mode: StopMode,
    ) -> Result<Vec<RemoteEnvelope>, RemoteError> {
        validate_run_id(run_id)?;
        if self.run_id.is_none() && self.phase == WorkerPhase::Ready {
            // A worker can be reconfigured for a new run while a stop frame
            // from the previous generation is still in flight.  Treating
            // that stale frame as a pre-start cancellation would move the
            // freshly configured worker to `Stopped` and could make the next
            // start appear to have been cancelled by the old run.  A
            // pre-start stop is valid only for a generation that has not
            // already been consumed by this worker.
            if self
                .last_run_id
                .is_some_and(|last_run_id| run_id == last_run_id)
            {
                return Err(RemoteError::new(
                    RemoteErrorCode::Cancelled,
                    false,
                    "worker stop belongs to a stale or already-consumed run generation",
                ));
            }
            if self.consumed_run_ids.contains(&run_id) {
                return Err(RemoteError::new(
                    RemoteErrorCode::Cancelled,
                    false,
                    "worker stop belongs to a stale or already-consumed run generation",
                ));
            }
            // Immediate cancellation may race a start request that has not
            // reached this worker.  Turn that race into an idempotent stop
            // acknowledgement instead of resurrecting the run later.
            self.phase = WorkerPhase::Stopped;
            self.run_id = Some(run_id);
            self.last_run_id = Some(run_id);
            self.remember_run_id(run_id);
            self.thread_count = 0;
            self.sender_mode = None;
            self.sender = None;
            return Ok(vec![self.ack_with_watermark(
                request_id,
                AckStage::Stopped,
                Some(run_id),
                Some(0),
                Some(0),
            )]);
        }
        if self.run_id != Some(run_id) {
            return Err(RemoteError::state(
                "worker stop does not match the active run",
            ));
        }
        if self.phase == WorkerPhase::Stopped {
            // Repeated stop delivery is idempotent. A later immediate stop
            // cannot restore samples already flushed by an earlier graceful
            // stop, but it must still complete its own request rather than
            // leaving the coordinator waiting forever.
            return Ok(vec![self.ack_with_watermark(
                request_id,
                AckStage::Stopped,
                Some(run_id),
                Some(self.thread_count),
                Some(self.delivered_watermark),
            )]);
        }
        if !matches!(self.phase, WorkerPhase::Running | WorkerPhase::Stopping) {
            return Err(RemoteError::state(
                "worker stop does not match the active run",
            ));
        }
        self.phase = WorkerPhase::Stopping;
        let mut responses = Vec::new();
        if let Some(sender) = self.sender.as_mut() {
            let dropped = if mode.drains_samples() {
                Vec::new()
            } else {
                sender.abort()
            };
            for sample in dropped {
                self.sample_envelope_ids.remove(&sample.key());
            }
            let delivered = if mode.drains_samples() {
                sender.close()
            } else {
                sender.drain_delivered()
            };
            self.note_delivered_samples(&delivered);
            self.prune_sample_envelope_ids(&BTreeSet::new(), &delivered);
            for sample in delivered {
                let sample_request_id =
                    self.sample_envelope_ids
                        .remove(&sample.key())
                        .ok_or_else(|| {
                            RemoteError::new(
                                RemoteErrorCode::Internal,
                                false,
                                "stopped sample had no envelope correlation",
                            )
                        })?;
                responses.push(RemoteEnvelope::new(
                    sample_request_id,
                    RemoteMessage::Sample { sample },
                ));
            }
        }
        self.phase = WorkerPhase::Stopped;
        responses.push(self.ack_with_watermark(
            request_id,
            AckStage::Stopped,
            Some(run_id),
            Some(self.thread_count),
            Some(if mode.drains_samples() {
                self.next_sequence
            } else {
                self.delivered_watermark
            }),
        ));
        Ok(responses)
    }

    fn recompute_ready(&mut self) {
        if self.accepted_profile.is_some()
            && self.plan.is_some()
            && self.properties.is_some()
            && matches!(self.phase, WorkerPhase::Idle | WorkerPhase::Ready)
        {
            self.phase = WorkerPhase::Ready;
        }
    }

    fn ack(
        &self,
        request_id: u64,
        stage: AckStage,
        run_id: Option<RunId>,
        thread_count: Option<u32>,
    ) -> RemoteEnvelope {
        self.ack_with_watermark(request_id, stage, run_id, thread_count, None)
    }

    fn ack_with_watermark(
        &self,
        request_id: u64,
        stage: AckStage,
        run_id: Option<RunId>,
        thread_count: Option<u32>,
        sample_watermark: Option<u64>,
    ) -> RemoteEnvelope {
        RemoteEnvelope::new(
            request_id,
            RemoteMessage::Ack {
                worker: self.id,
                stage,
                run_id,
                thread_count,
                sample_watermark,
            },
        )
    }
}

/// A worker status retained by the coordinator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerRecord {
    /// Worker identity.
    pub worker: WorkerId,
    /// Current lifecycle phase.
    pub phase: WorkerPhase,
    /// Configured logical thread count.
    pub thread_count: u32,
    /// Last terminal failure, if any.
    pub failure: Option<RemoteError>,
}

/// The result of recording a sample at a coordinator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordOutcome {
    /// A new sample was accepted by the sender.
    Accepted(SendOutcome),
    /// An exact duplicate was ignored idempotently.
    Duplicate,
}

/// A deterministic multi-worker coordinator. It does not own a transport;
/// callers pass envelopes to workers and feed responses back with [`Self::apply`].
pub struct RemoteCoordinator {
    profile: ProfileDescriptor,
    plan: Option<PlanDescriptor>,
    properties: Option<PropertySet>,
    configuration_limits: RemoteConfigurationLimits,
    wire_codec_limits: RemoteLimits,
    workers: BTreeMap<WorkerId, WorkerRecord>,
    config_acks: BTreeMap<WorkerId, BTreeSet<AckStage>>,
    phase: CoordinatorPhase,
    failure_policy: FailurePolicy,
    run_id: Option<RunId>,
    last_run_id: Option<RunId>,
    consumed_run_ids: BTreeSet<RunId>,
    consumed_run_order: VecDeque<RunId>,
    configured_threads: u32,
    sender_mode: Option<SampleSenderMode>,
    sender: Option<SampleSender>,
    batch_time_ms: Option<u64>,
    accepted: BTreeMap<SampleKey, RemoteSample>,
    accepted_sizes: BTreeMap<SampleKey, usize>,
    sample_requests: BTreeMap<RequestId, SampleKey>,
    accepted_bytes: usize,
    arrival_order: Vec<SampleKey>,
    max_samples: usize,
    max_retained_bytes: usize,
    retry_policy: RetryPolicy,
    stop_cause: Option<StopCause>,
    /// Graceful-stop watermarks received from workers. A worker remains in
    /// `Stopping` until every sequence below its exclusive watermark has
    /// arrived, so reordered sample/ACK delivery cannot close the run early.
    stop_watermarks: BTreeMap<WorkerId, u64>,
    control_outbox: Vec<RemoteEnvelope>,
    next_request_id: RequestId,
    pending_requests: BTreeMap<RequestId, PendingRequest>,
    invalid_requests: BTreeSet<RequestId>,
    completed_requests: BTreeMap<RequestId, CompletedRequest>,
}

impl fmt::Debug for RemoteCoordinator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteCoordinator")
            .field("phase", &self.phase)
            .field("run_id", &self.run_id)
            .field("last_run_id", &self.last_run_id)
            .field("consumed_run_count", &self.consumed_run_ids.len())
            .field("worker_count", &self.workers.len())
            .field("healthy_worker_count", &self.healthy_worker_count())
            .field("has_plan", &self.plan.is_some())
            .field(
                "property_count",
                &self.properties.as_ref().map(PropertySet::len),
            )
            .field("accepted_sample_count", &self.accepted.len())
            .field("retained_bytes", &self.retained_bytes())
            .field("pending_request_count", &self.pending_requests.len())
            .field("invalid_request_count", &self.invalid_requests.len())
            .field("completed_request_count", &self.completed_requests.len())
            .field("retry_policy", &self.retry_policy)
            .field("failure_policy", &self.failure_policy)
            .finish()
    }
}

impl RemoteCoordinator {
    /// Creates an idle coordinator for one compatibility profile.
    pub fn new(profile: ProfileDescriptor) -> Self {
        Self {
            profile,
            plan: None,
            properties: None,
            configuration_limits: RemoteConfigurationLimits::default(),
            wire_codec_limits: RemoteLimits::default(),
            workers: BTreeMap::new(),
            config_acks: BTreeMap::new(),
            phase: CoordinatorPhase::Idle,
            failure_policy: FailurePolicy::Continue,
            run_id: None,
            last_run_id: None,
            consumed_run_ids: BTreeSet::new(),
            consumed_run_order: VecDeque::new(),
            configured_threads: 0,
            sender_mode: None,
            sender: None,
            batch_time_ms: None,
            accepted: BTreeMap::new(),
            accepted_sizes: BTreeMap::new(),
            sample_requests: BTreeMap::new(),
            accepted_bytes: 0,
            arrival_order: Vec::new(),
            max_samples: 100_000,
            max_retained_bytes: DEFAULT_MAX_RETAINED_BYTES,
            retry_policy: RetryPolicy::default(),
            stop_cause: None,
            stop_watermarks: BTreeMap::new(),
            control_outbox: Vec::new(),
            next_request_id: 1,
            pending_requests: BTreeMap::new(),
            invalid_requests: BTreeSet::new(),
            completed_requests: BTreeMap::new(),
        }
    }

    /// Sets partial-failure behavior.
    pub fn set_failure_policy(&mut self, policy: FailurePolicy) {
        self.failure_policy = policy;
    }

    /// Sets the bounded lifecycle retry policy.
    pub fn set_retry_policy(&mut self, policy: RetryPolicy) {
        self.retry_policy = policy;
    }

    /// Sets finite bounds for workers and pre-codec configuration values.
    pub fn set_configuration_limits(
        &mut self,
        limits: RemoteConfigurationLimits,
    ) -> Result<(), RemoteError> {
        if self.phase != CoordinatorPhase::Idle {
            return Err(RemoteError::state(
                "coordinator configuration limits are immutable after configuration begins",
            ));
        }
        if !limits.is_valid() {
            return Err(RemoteError::new(
                RemoteErrorCode::ResourceLimit,
                false,
                "remote configuration limits must be non-zero",
            ));
        }
        if self.workers.len() > limits.max_workers() {
            return Err(RemoteError::new(
                RemoteErrorCode::ResourceLimit,
                false,
                "selected workers exceed the requested bound",
            ));
        }
        if self.control_outbox.len() > limits.max_control_events() {
            return Err(RemoteError::new(
                RemoteErrorCode::ResourceLimit,
                false,
                "queued control events exceed the requested bound",
            ));
        }
        if let (Some(plan), Some(properties)) = (&self.plan, &self.properties) {
            validate_configuration(plan, properties, limits)?;
        } else {
            if let Some(plan) = &self.plan {
                plan.validate_with_limits(limits)?;
            }
            if let Some(properties) = &self.properties {
                properties.validate_with_limits(limits)?;
            }
        }
        self.configuration_limits = limits;
        Ok(())
    }

    /// Returns pre-codec worker/configuration bounds.
    pub const fn configuration_limits(&self) -> RemoteConfigurationLimits {
        self.configuration_limits
    }

    /// Sets the exact message, field, and result bounds shared by the
    /// coordinator sender and its transport codec.  Changing these bounds
    /// after a run has begun would invalidate retained-byte accounting, so it
    /// is only allowed before the first start request.
    pub fn set_codec_limits(&mut self, limits: RemoteLimits) -> Result<(), RemoteError> {
        if self.phase != CoordinatorPhase::Idle
            || self.run_id.is_some()
            || self.sender.is_some()
            || !self.accepted.is_empty()
        {
            return Err(RemoteError::state(
                "coordinator codec limits are immutable after a run begins",
            ));
        }
        limits.validate()?;
        self.profile.validate_with_limits(limits)?;
        if self.max_samples > limits.max_samples() {
            return Err(RemoteError::new(
                RemoteErrorCode::ResourceLimit,
                false,
                "codec sample bound is below the coordinator sample bound",
            ));
        }
        self.wire_codec_limits = limits;
        Ok(())
    }

    /// Returns the validated bounds shared by the coordinator sender and
    /// codec accounting path.
    pub const fn codec_limits(&self) -> RemoteLimits {
        self.wire_codec_limits
    }

    /// Returns the configured lifecycle retry policy.
    pub const fn retry_policy(&self) -> RetryPolicy {
        self.retry_policy
    }

    /// Returns the number of currently pending lifecycle requests.
    pub fn pending_request_count(&self) -> usize {
        self.pending_requests.len()
    }

    /// Returns pending request metadata for deterministic adapters.
    pub fn request_attempt(&self, request_id: RequestId) -> Option<u32> {
        self.pending_requests
            .get(&request_id)
            .map(|request| request.attempt)
    }

    /// Drains fail-fast stop requests generated by a worker failure.
    pub fn drain_control_messages(&mut self) -> Vec<RemoteEnvelope> {
        core::mem::take(&mut self.control_outbox)
    }

    /// Retries a pending lifecycle request with a fresh globally unique
    /// request ID. The superseded request becomes stale and can no longer
    /// mutate worker state when its delayed acknowledgement arrives.
    pub fn retry_request(&mut self, request_id: RequestId) -> Result<RemoteEnvelope, RemoteError> {
        let pending = self.pending_requests.remove(&request_id).ok_or_else(|| {
            RemoteError::new(
                RemoteErrorCode::InvalidState,
                false,
                "request is not pending or has already been completed",
            )
        })?;
        if pending.attempt >= self.retry_policy.max_attempts {
            self.pending_requests.insert(request_id, pending);
            return Err(RemoteError::new(
                RemoteErrorCode::ResourceLimit,
                false,
                "request retry attempt bound exhausted",
            ));
        }
        let next_attempt = pending.attempt + 1;
        let message = pending.message.clone();
        let replacement = match self.envelope(message) {
            Ok(envelope) => envelope,
            Err(error) => {
                self.pending_requests.insert(request_id, pending);
                return Err(error);
            }
        };
        self.invalid_requests.insert(request_id);
        self.trim_request_history();
        self.pending_requests.insert(
            replacement.request_id,
            PendingRequest {
                worker: pending.worker,
                stage: pending.stage,
                attempt: next_attempt,
                message: replacement.message.clone(),
            },
        );
        Ok(replacement)
    }

    /// Retries a lifecycle request after checking a typed deadline and
    /// cancellation policy supplied by the transport/runtime adapter.
    pub fn retry_request_with_context(
        &mut self,
        request_id: RequestId,
        context: RemoteRequestContext,
        now_unix_millis: u64,
    ) -> Result<RemoteEnvelope, RemoteError> {
        context.check(now_unix_millis)?;
        self.retry_request(request_id)
    }

    /// Sets the deduplication/retention bound.
    pub fn set_max_samples(&mut self, maximum: usize) -> Result<(), RemoteError> {
        if maximum == 0 {
            return Err(RemoteError::new(
                RemoteErrorCode::ResourceLimit,
                false,
                "sample bound must be non-zero",
            ));
        }
        if maximum > self.wire_codec_limits.max_samples() {
            return Err(RemoteError::new(
                RemoteErrorCode::ResourceLimit,
                false,
                "sample bound exceeds the negotiated codec sample bound",
            ));
        }
        if maximum < self.accepted.len() {
            return Err(RemoteError::new(
                RemoteErrorCode::ResourceLimit,
                false,
                "sample bound cannot be lower than retained samples",
            ));
        }
        if let Some(sender) = self.sender.as_mut() {
            sender.set_max_samples(maximum)?;
        }
        self.max_samples = maximum;
        self.trim_request_history();
        Ok(())
    }

    /// Sets the coordinator's retained sample-byte bound. This covers the
    /// immutable accepted snapshot in addition to the sender's own queue
    /// bound, so an adapter cannot retain an unbounded second copy.
    pub fn set_max_retained_bytes(&mut self, maximum: usize) -> Result<(), RemoteError> {
        let sender_bytes = self.sender.as_ref().map_or(0, SampleSender::retained_bytes);
        let total = self
            .accepted_bytes
            .checked_add(sender_bytes)
            .ok_or_else(|| {
                RemoteError::new(
                    RemoteErrorCode::ResourceLimit,
                    false,
                    "retained sample-byte bound overflowed",
                )
            })?;
        if maximum == 0 || maximum < total {
            return Err(RemoteError::new(
                RemoteErrorCode::ResourceLimit,
                false,
                "retained sample-byte bound must cover accepted and sender samples",
            ));
        }
        if let Some(sender) = self.sender.as_mut() {
            let remaining = maximum - self.accepted_bytes;
            if remaining == 0 {
                if sender.retained_bytes() != 0 {
                    return Err(RemoteError::new(
                        RemoteErrorCode::ResourceLimit,
                        false,
                        "retained sample-byte bound leaves no room for sender data",
                    ));
                }
            } else {
                sender.set_max_retained_bytes(remaining)?;
            }
        }
        self.max_retained_bytes = maximum;
        Ok(())
    }

    /// Returns the coordinator's retained sample-byte bound.
    pub const fn max_retained_bytes(&self) -> usize {
        self.max_retained_bytes
    }

    /// Returns the coordinator-wide deduplication bound.
    pub const fn max_samples(&self) -> usize {
        self.max_samples
    }

    /// Returns the encoded-byte estimate retained by accepted sample
    /// snapshots.
    pub const fn retained_sample_bytes(&self) -> usize {
        self.accepted_bytes
    }

    /// Returns bytes retained by both accepted snapshots and the sender's
    /// pending/delivered/deduplication copies under the unified budget.
    pub fn retained_bytes(&self) -> usize {
        self.accepted_bytes
            .saturating_add(self.sender.as_ref().map_or(0, SampleSender::retained_bytes))
    }

    /// Registers a selected worker in stable identity order.
    pub fn add_worker(&mut self, worker: WorkerId) -> Result<(), RemoteError> {
        if self.phase != CoordinatorPhase::Idle {
            return Err(RemoteError::state(
                "workers are immutable after configuration begins",
            ));
        }
        if self.workers.contains_key(&worker) {
            return Err(RemoteError::new(
                RemoteErrorCode::Protocol,
                false,
                "worker identity is duplicated",
            ));
        }
        if self.workers.len() >= self.configuration_limits.max_workers() {
            return Err(RemoteError::new(
                RemoteErrorCode::ResourceLimit,
                false,
                "remote worker bound exhausted",
            ));
        }
        self.workers.insert(
            worker,
            WorkerRecord {
                worker,
                phase: WorkerPhase::Idle,
                thread_count: 0,
                failure: None,
            },
        );
        self.config_acks.insert(worker, BTreeSet::new());
        Ok(())
    }

    /// Returns coordinator phase.
    pub const fn phase(&self) -> CoordinatorPhase {
        self.phase
    }

    /// Returns worker records in numeric identity order.
    pub fn workers(&self) -> impl Iterator<Item = &WorkerRecord> {
        self.workers.values()
    }

    /// Returns one worker record by identity.
    pub fn worker(&self, worker: WorkerId) -> Option<&WorkerRecord> {
        self.workers.get(&worker)
    }

    /// Returns the configured compatibility profile.
    pub fn profile(&self) -> &ProfileDescriptor {
        &self.profile
    }

    /// Returns the transferred plan, if configuration has begun.
    pub fn plan(&self) -> Option<&PlanDescriptor> {
        self.plan.as_ref()
    }

    /// Returns the run-scoped properties, if configuration has begun.
    pub fn properties(&self) -> Option<&PropertySet> {
        self.properties.as_ref()
    }

    /// Returns the active run identity.
    pub const fn run_id(&self) -> Option<RunId> {
        self.run_id
    }

    /// Returns the selected sender mode.
    pub const fn sender_mode(&self) -> Option<SampleSenderMode> {
        self.sender_mode
    }

    /// Configures an injected batch-time threshold for the next sender.
    /// Adapters advance worker clocks explicitly; this core never reads time.
    pub fn set_batch_time_ms(&mut self, threshold: u64) -> Result<(), RemoteError> {
        if threshold == 0 {
            return Err(RemoteError::new(
                RemoteErrorCode::ResourceLimit,
                false,
                "batch time threshold must be non-zero",
            ));
        }
        self.batch_time_ms = Some(threshold);
        Ok(())
    }

    /// Returns the run's configured thread count per worker.
    pub const fn configured_threads(&self) -> u32 {
        self.configured_threads
    }

    /// Returns the exact multiplied logical thread count across healthy workers.
    pub fn total_threads(&self) -> Result<u64, RemoteError> {
        let healthy = self
            .workers
            .values()
            .filter(|record| record.phase != WorkerPhase::Failed)
            .count() as u64;
        u64::from(self.configured_threads)
            .checked_mul(healthy)
            .ok_or_else(|| {
                RemoteError::new(
                    RemoteErrorCode::ResourceLimit,
                    false,
                    "thread multiplication overflow",
                )
            })
    }

    /// Dispatches profile, plan, and properties to every selected worker.
    pub fn configure(
        &mut self,
        plan: PlanDescriptor,
        properties: PropertySet,
    ) -> Result<Vec<RemoteEnvelope>, RemoteError> {
        self.profile.validate_with_limits(self.wire_codec_limits)?;
        if !self.configuration_limits.is_valid() {
            return Err(RemoteError::new(
                RemoteErrorCode::ResourceLimit,
                false,
                "remote configuration limits must be non-zero",
            ));
        }
        validate_configuration(&plan, &properties, self.configuration_limits)?;
        if !matches!(
            self.phase,
            CoordinatorPhase::Idle | CoordinatorPhase::Stopped
        ) {
            return Err(RemoteError::state(
                "configuration can only begin from idle or stopped",
            ));
        }
        if self.phase == CoordinatorPhase::Stopped
            && self
                .sender
                .as_ref()
                .is_some_and(|sender| sender.pending_len() != 0 || !sender.delivered().is_empty())
        {
            return Err(RemoteError::state(
                "drain delivered samples before starting a new configuration",
            ));
        }
        if !self.pending_requests.is_empty() {
            return Err(RemoteError::state(
                "complete pending lifecycle acknowledgements before reconfiguration",
            ));
        }
        if self.workers.is_empty() {
            return Err(RemoteError::new(
                RemoteErrorCode::InvalidState,
                false,
                "no remote workers selected",
            ));
        }
        let workers = self
            .workers
            .values()
            .filter(|record| record.phase != WorkerPhase::Failed)
            .map(|record| record.worker)
            .collect::<Vec<_>>();
        if workers.is_empty() {
            return Err(RemoteError::new(
                RemoteErrorCode::InvalidState,
                false,
                "no healthy remote workers selected",
            ));
        }
        let request_count = workers.len().checked_mul(3).ok_or_else(|| {
            RemoteError::new(
                RemoteErrorCode::ResourceLimit,
                false,
                "configuration request count overflowed",
            )
        })?;
        self.ensure_control_ids(request_count)?;
        self.plan = Some(plan.clone());
        self.properties = Some(properties.clone());
        self.run_id = None;
        self.configured_threads = 0;
        self.sender_mode = None;
        self.sender = None;
        self.accepted.clear();
        self.accepted_sizes.clear();
        self.sample_requests.clear();
        self.accepted_bytes = 0;
        self.arrival_order.clear();
        self.pending_requests.clear();
        self.stop_cause = None;
        self.stop_watermarks.clear();
        self.control_outbox.clear();
        self.phase = CoordinatorPhase::Configuring;
        let mut messages = Vec::new();
        for worker in workers {
            let profile = self.envelope(RemoteMessage::Profile {
                profile: self.profile.clone(),
            })?;
            self.register_pending(&profile, worker, AckStage::Profile, 1);
            messages.push(profile);
            let transferred_plan = self.envelope(RemoteMessage::Plan { plan: plan.clone() })?;
            self.register_pending(&transferred_plan, worker, AckStage::Plan, 1);
            messages.push(transferred_plan);
            let properties_message = self.envelope(RemoteMessage::Properties {
                properties: properties.clone(),
            })?;
            self.register_pending(&properties_message, worker, AckStage::Properties, 1);
            messages.push(properties_message);
            if let Some(record) = self.workers.get_mut(&worker)
                && record.phase != WorkerPhase::Failed
            {
                record.phase = WorkerPhase::Idle;
                record.thread_count = 0;
            }
            self.config_acks.insert(worker, BTreeSet::new());
        }
        Ok(messages)
    }

    /// Configures a run after checking a typed deadline and cancellation
    /// policy supplied by the transport/runtime adapter.
    pub fn configure_with_context(
        &mut self,
        plan: PlanDescriptor,
        properties: PropertySet,
        context: RemoteRequestContext,
        now_unix_millis: u64,
    ) -> Result<Vec<RemoteEnvelope>, RemoteError> {
        context.check(now_unix_millis)?;
        self.configure(plan, properties)
    }

    /// Marks a worker ready after its ordered profile/plan/properties
    /// acknowledgements have all been observed. This explicit helper is useful
    /// to deterministic in-memory adapters that route acknowledgements in a
    /// different container than [`Self::apply`].
    pub fn configuration_complete(&mut self, worker: WorkerId) -> Result<(), RemoteError> {
        let stages = self.config_acks.get(&worker).ok_or_else(|| {
            RemoteError::new(
                RemoteErrorCode::Protocol,
                false,
                "unknown worker configuration",
            )
        })?;
        if ![AckStage::Profile, AckStage::Plan, AckStage::Properties]
            .iter()
            .all(|stage| stages.contains(stage))
        {
            return Err(RemoteError::state(
                "worker configuration acknowledgements are incomplete",
            ));
        }
        let record = self
            .workers
            .get_mut(&worker)
            .ok_or_else(|| RemoteError::new(RemoteErrorCode::Protocol, false, "unknown worker"))?;
        if record.phase == WorkerPhase::Idle {
            record.phase = WorkerPhase::Ready;
        }
        self.recompute_phase_after_configuration();
        Ok(())
    }

    /// Records a worker failure without requiring a wire envelope.
    pub fn worker_failed(
        &mut self,
        worker: WorkerId,
        error: RemoteError,
    ) -> Result<(), RemoteError> {
        self.fail_worker(worker, self.run_id, error)
    }

    /// Records a failure for an explicitly identified run generation.
    pub fn worker_failed_for_run(
        &mut self,
        worker: WorkerId,
        run_id: RunId,
        error: RemoteError,
    ) -> Result<(), RemoteError> {
        self.fail_worker(worker, Some(run_id), error)
    }

    /// Dispatches one start request to each non-failed ready worker.
    pub fn start(
        &mut self,
        run_id: RunId,
        thread_count: u32,
        mode: SampleSenderMode,
    ) -> Result<Vec<RemoteEnvelope>, RemoteError> {
        validate_run_id(run_id)?;
        if self.phase != CoordinatorPhase::Ready {
            return Err(RemoteError::state("start requires ready workers"));
        }
        if self
            .last_run_id
            .is_some_and(|last_run_id| run_id == last_run_id)
        {
            return Err(RemoteError::state(
                "run generation is stale or already consumed by the coordinator",
            ));
        }
        if self.consumed_run_ids.contains(&run_id) {
            return Err(RemoteError::state(
                "run generation was already consumed by the coordinator",
            ));
        }
        if thread_count == 0 {
            return Err(RemoteError::new(
                RemoteErrorCode::ResourceLimit,
                false,
                "thread count must be non-zero",
            ));
        }
        if !mode.execution_supported() {
            return Err(mode.unsupported_error().unwrap_or_else(|| {
                RemoteError::new(
                    RemoteErrorCode::CapabilityUnavailable,
                    false,
                    "sender mode is unavailable in the Rust-native remote core",
                )
            }));
        }
        if mode.has_zero_bound() {
            return Err(RemoteError::new(
                RemoteErrorCode::ResourceLimit,
                false,
                "sender mode bound must be non-zero",
            ));
        }
        let workers = self
            .workers
            .values()
            .filter(|record| record.phase == WorkerPhase::Ready)
            .map(|record| record.worker)
            .collect::<Vec<_>>();
        self.ensure_control_ids(workers.len())?;
        let capacity = mode.capacity().unwrap_or(4096);
        let sender_config =
            SenderConfig::from_limits_and_codec(mode, capacity, self.wire_codec_limits)
                .ok_or_else(|| {
                    RemoteError::new(
                        RemoteErrorCode::ResourceLimit,
                        false,
                        "coordinator sender codec limits are invalid",
                    )
                })?
                .with_max_samples(self.max_samples)
                .ok_or_else(|| {
                    RemoteError::new(
                        RemoteErrorCode::ResourceLimit,
                        false,
                        "coordinator sender sample bound is invalid",
                    )
                })?
                .with_max_retained_bytes(self.max_retained_bytes)
                .ok_or_else(|| {
                    RemoteError::new(
                        RemoteErrorCode::ResourceLimit,
                        false,
                        "coordinator sender retained-byte bound is invalid",
                    )
                })?;
        let sender_config = self
            .batch_time_ms
            .map_or(Some(sender_config), |threshold| {
                sender_config.with_batch_time_ms(threshold)
            })
            .ok_or_else(|| {
                RemoteError::new(
                    RemoteErrorCode::ResourceLimit,
                    false,
                    "batch time threshold must be non-zero",
                )
            })?;
        self.run_id = Some(run_id);
        self.last_run_id = Some(run_id);
        if self.consumed_run_ids.insert(run_id) {
            self.consumed_run_order.push_back(run_id);
        }
        self.trim_consumed_run_ids();
        self.configured_threads = thread_count;
        self.sender_mode = Some(mode);
        self.sender = Some(SampleSender::new(sender_config));
        self.accepted.clear();
        self.accepted_sizes.clear();
        self.sample_requests.clear();
        self.accepted_bytes = 0;
        self.arrival_order.clear();
        self.stop_cause = None;
        self.stop_watermarks.clear();
        self.phase = CoordinatorPhase::Starting;
        let mut messages = Vec::new();
        for worker in workers {
            let start = self.envelope(RemoteMessage::Start {
                run_id,
                thread_count,
                sender_mode: mode,
            })?;
            self.register_pending(&start, worker, AckStage::Started, 1);
            messages.push(start);
        }
        Ok(messages)
    }

    /// Starts a run after checking a typed deadline/cancellation policy
    /// supplied by the transport/runtime adapter.
    pub fn start_with_context(
        &mut self,
        run_id: RunId,
        thread_count: u32,
        mode: SampleSenderMode,
        context: RemoteRequestContext,
        now_unix_millis: u64,
    ) -> Result<Vec<RemoteEnvelope>, RemoteError> {
        context.check(now_unix_millis)?;
        self.start(run_id, thread_count, mode)
    }

    /// Dispatches a stop request to every running worker. An immediate stop
    /// is also valid while starts are in flight: not-yet-started workers are
    /// cancelled locally and stale start acknowledgements are rejected.
    pub fn stop(&mut self, mode: StopMode) -> Result<Vec<RemoteEnvelope>, RemoteError> {
        let run_id = self
            .run_id
            .ok_or_else(|| RemoteError::state("no active remote run"))?;
        let was_starting = self.phase == CoordinatorPhase::Starting;
        if !matches!(
            self.phase,
            CoordinatorPhase::Starting | CoordinatorPhase::Running | CoordinatorPhase::Stopping
        ) {
            return Err(RemoteError::state("stop requires an active remote run"));
        }
        if was_starting && mode != StopMode::Immediate {
            return Err(RemoteError::state(
                "only immediate stop is valid while workers are starting",
            ));
        }
        let escalating = matches!(
            self.stop_cause,
            Some(StopCause::User(previous)) if mode.severity() > previous.severity()
        );
        if self.phase == CoordinatorPhase::Stopping && !escalating {
            // A stop request is already in flight. Re-emitting the same (or a
            // weaker) request would create duplicate ACKs and make a delayed
            // response indistinguishable from a live request.
            return Ok(Vec::new());
        }
        let workers = self
            .workers
            .values()
            .filter(|record| {
                if was_starting {
                    matches!(
                        record.phase,
                        WorkerPhase::Ready | WorkerPhase::Running | WorkerPhase::Stopping
                    )
                } else {
                    matches!(record.phase, WorkerPhase::Running | WorkerPhase::Stopping)
                }
            })
            .map(|record| record.worker)
            .collect::<Vec<_>>();
        self.ensure_control_ids(workers.len())?;
        if was_starting {
            self.cancel_pending_start_requests();
        }
        if escalating {
            self.cancel_pending_stop_requests();
        }
        match self.stop_cause {
            None => self.stop_cause = Some(StopCause::User(mode)),
            Some(StopCause::User(previous)) if mode.severity() > previous.severity() => {
                self.stop_cause = Some(StopCause::User(mode));
            }
            Some(StopCause::User(_)) | Some(StopCause::FailFast) => {}
        }
        self.phase = CoordinatorPhase::Stopping;
        for record in self.workers.values_mut() {
            if record.phase == WorkerPhase::Failed {
                continue;
            }
            // A graceful stop must leave every selected worker in the
            // watermark-waiting state.  Keeping a running record as Running
            // would make a later satisfied watermark unable to complete it.
            if (was_starting && record.phase == WorkerPhase::Ready)
                || (!was_starting
                    && matches!(record.phase, WorkerPhase::Running | WorkerPhase::Stopping))
            {
                record.phase = WorkerPhase::Stopping;
            }
        }
        let mut messages = Vec::with_capacity(workers.len());
        for worker in workers {
            let stop = self.envelope(RemoteMessage::Stop { run_id, mode })?;
            self.register_pending(&stop, worker, AckStage::Stopped, 1);
            messages.push(stop);
        }
        self.recompute_phase();
        Ok(messages)
    }

    /// Stops the run after checking a typed deadline/cancellation policy
    /// supplied by the transport/runtime adapter.
    pub fn stop_with_context(
        &mut self,
        mode: StopMode,
        context: RemoteRequestContext,
        now_unix_millis: u64,
    ) -> Result<Vec<RemoteEnvelope>, RemoteError> {
        context.check(now_unix_millis)?;
        self.stop(mode)
    }

    /// Applies an acknowledgement, sample, or worker failure.
    pub fn apply(
        &mut self,
        envelope: RemoteEnvelope,
    ) -> Result<Option<RecordOutcome>, RemoteError> {
        let is_sample = matches!(&envelope.message, RemoteMessage::Sample { .. });
        if envelope.request_id == 0
            || (is_sample && !is_sample_envelope_request_id(envelope.request_id))
            || (!is_sample && uses_sample_envelope_namespace(envelope.request_id))
        {
            return Err(RemoteError::new(
                RemoteErrorCode::Protocol,
                false,
                "coordinator message used an invalid request ID namespace",
            ));
        }
        match envelope.message {
            RemoteMessage::Ack {
                worker,
                stage,
                run_id,
                thread_count,
                sample_watermark,
            } => {
                self.apply_ack(
                    envelope.request_id,
                    worker,
                    stage,
                    run_id,
                    thread_count,
                    sample_watermark,
                )?;
                Ok(None)
            }
            RemoteMessage::Sample { sample } => {
                if sample_envelope_worker(envelope.request_id) != Some(sample.worker()) {
                    return Err(RemoteError::new(
                        RemoteErrorCode::Protocol,
                        false,
                        "sample envelope request ID does not identify its worker",
                    ));
                }
                if let Some(previous_key) = self.sample_requests.get(&envelope.request_id)
                    && *previous_key != sample.key()
                {
                    return Err(RemoteError::new(
                        RemoteErrorCode::Protocol,
                        false,
                        "sample envelope request ID was reused for another sample",
                    ));
                }
                let key = sample.key();
                let outcome = self.record_sample(sample)?;
                self.sample_requests.insert(envelope.request_id, key);
                self.trim_sample_request_history();
                Ok(Some(outcome))
            }
            RemoteMessage::Failure {
                worker,
                run_id,
                error,
            } => {
                self.fail_worker(worker, run_id, error)?;
                Ok(None)
            }
            _ => Err(RemoteError::state(
                "coordinator received a worker-invalid message",
            )),
        }
    }

    /// Applies a worker response after checking a typed deadline and
    /// cancellation policy supplied by the transport/runtime adapter.
    pub fn apply_with_context(
        &mut self,
        envelope: RemoteEnvelope,
        context: RemoteRequestContext,
        now_unix_millis: u64,
    ) -> Result<Option<RecordOutcome>, RemoteError> {
        context.check(now_unix_millis)?;
        self.apply(envelope)
    }

    /// Records a worker sample, preserving arrival order and deduplicating by
    /// `(worker, sequence)` before applying sender backpressure.
    pub fn record_sample(&mut self, sample: RemoteSample) -> Result<RecordOutcome, RemoteError> {
        validate_run_id(sample.run_id())?;
        if !matches!(
            self.phase,
            CoordinatorPhase::Running | CoordinatorPhase::Stopping
        ) {
            return Err(RemoteError::new(
                RemoteErrorCode::Cancelled,
                false,
                "sample arrived after the coordinator stopped accepting results",
            ));
        }
        if self.run_id != Some(sample.run_id()) {
            return Err(RemoteError::new(
                RemoteErrorCode::Protocol,
                false,
                "sample run does not match coordinator run",
            ));
        }
        let record = self.workers.get(&sample.worker()).ok_or_else(|| {
            RemoteError::new(
                RemoteErrorCode::Protocol,
                false,
                "sample came from an unknown worker",
            )
        })?;
        if record.phase == WorkerPhase::Failed {
            return Err(RemoteError::new(
                RemoteErrorCode::Cancelled,
                false,
                "sample came from a failed worker",
            ));
        }
        if let Some(&watermark) = self.stop_watermarks.get(&sample.worker())
            && sample.sequence() >= watermark
        {
            return Err(RemoteError::new(
                RemoteErrorCode::Cancelled,
                false,
                "sample arrived beyond the worker stop watermark",
            ));
        }
        if !matches!(
            record.phase,
            WorkerPhase::Running | WorkerPhase::Stopping | WorkerPhase::Stopped
        ) {
            return Err(RemoteError::state(
                "sample came from a worker that did not start",
            ));
        }
        if let Some(previous) = self.accepted.get(&sample.key()) {
            if previous == &sample {
                return Ok(RecordOutcome::Duplicate);
            }
            return Err(RemoteError::new(
                RemoteErrorCode::ConflictingDuplicate,
                false,
                format!("sample key {:?} changed contents", sample.key()),
            ));
        }
        if self.accepted.len() >= self.max_samples {
            return Err(RemoteError::new(
                RemoteErrorCode::ResourceLimit,
                false,
                "coordinator sample bound exhausted",
            ));
        }
        let sample_bytes = RemoteCodec::new(self.wire_codec_limits)
            .encoded_sample_len(sample_envelope_request_id(sample.worker(), 1)?, &sample)
            .map_err(|error| RemoteError::new(error.code(), false, error.to_string()))?;
        let retained_bytes = self
            .accepted_bytes
            .checked_add(sample_bytes)
            .ok_or_else(|| {
                RemoteError::new(
                    RemoteErrorCode::ResourceLimit,
                    false,
                    "coordinator retained sample-byte bound overflowed",
                )
            })?;
        if retained_bytes > self.max_retained_bytes {
            return Err(RemoteError::new(
                RemoteErrorCode::ResourceLimit,
                false,
                "coordinator retained sample-byte bound exhausted",
            ));
        }
        let sender = self
            .sender
            .as_mut()
            .ok_or_else(|| RemoteError::state("sample sender is not configured"))?;
        let sender_limit = self
            .max_retained_bytes
            .checked_sub(retained_bytes)
            .ok_or_else(|| {
                RemoteError::new(
                    RemoteErrorCode::ResourceLimit,
                    false,
                    "coordinator sender-byte budget underflowed",
                )
            })?;
        if sender_limit == 0 || sender.retained_bytes() > sender_limit {
            return Err(RemoteError::new(
                RemoteErrorCode::ResourceLimit,
                false,
                "coordinator sender-byte budget exhausted",
            ));
        }
        let previous_sender_limit = sender.max_retained_bytes();
        sender.set_max_retained_bytes(sender_limit)?;
        let key = sample.key();
        let outcome = match sender.send(sample.clone()) {
            Ok(outcome) => outcome,
            Err(error) => {
                // A rejected sample must not leave a tighter external budget
                // behind for a later retry.
                if let Err(restore_error) = sender.set_max_retained_bytes(previous_sender_limit) {
                    return Err(RemoteError::new(
                        RemoteErrorCode::Internal,
                        false,
                        format!(
                            "failed to restore coordinator sender-byte budget after rejection: {restore_error}"
                        ),
                    ));
                }
                return Err(error);
            }
        };
        self.accepted.insert(key, sample);
        self.accepted_sizes.insert(key, sample_bytes);
        self.accepted_bytes = retained_bytes;
        self.arrival_order.push(key);
        self.recompute_phase();
        Ok(RecordOutcome::Accepted(outcome))
    }

    /// Records a sample after checking a typed deadline/cancellation policy
    /// supplied by the transport/runtime adapter.
    pub fn record_sample_with_context(
        &mut self,
        sample: RemoteSample,
        context: RemoteRequestContext,
        now_unix_millis: u64,
    ) -> Result<RecordOutcome, RemoteError> {
        context.check(now_unix_millis)?;
        self.record_sample(sample)
    }

    /// Returns accepted samples in observed arrival order.
    pub fn arrival_samples(&self) -> Vec<&RemoteSample> {
        self.arrival_order
            .iter()
            .filter_map(|key| self.accepted.get(key))
            .collect()
    }

    /// Returns accepted samples in explicit worker/sequence order, which is
    /// distinct from arrival order and therefore never inferred implicitly.
    pub fn execution_order_samples(&self) -> Vec<&RemoteSample> {
        self.accepted.values().collect()
    }

    /// Drains sender-delivered samples in mode order.
    pub fn drain_delivered_samples(&mut self) -> Vec<RemoteSample> {
        self.sender
            .as_mut()
            .map_or_else(Vec::new, SampleSender::drain_delivered)
    }

    /// Advances the coordinator sender's injected logical clock and returns
    /// samples released by a configured batch-time threshold.  The returned
    /// samples were already accepted; this only changes delivery visibility.
    pub fn advance_time(&mut self, now_ms: u64) -> Result<Vec<RemoteSample>, RemoteError> {
        if !matches!(
            self.phase,
            CoordinatorPhase::Running | CoordinatorPhase::Stopping | CoordinatorPhase::Stopped
        ) {
            return Err(RemoteError::state(
                "coordinator time can advance only for an active run",
            ));
        }
        let sender = self
            .sender
            .as_mut()
            .ok_or_else(|| RemoteError::state("sample sender is not configured"))?;
        sender.advance_time(now_ms)
    }

    /// Alias for deterministic adapters that model a sender clock tick.
    pub fn tick(&mut self, now_ms: u64) -> Result<Vec<RemoteSample>, RemoteError> {
        self.advance_time(now_ms)
    }

    /// Returns healthy worker count used for thread multiplication.
    pub fn healthy_worker_count(&self) -> usize {
        self.workers
            .values()
            .filter(|record| record.phase != WorkerPhase::Failed)
            .count()
    }

    fn trim_consumed_run_ids(&mut self) {
        while self.consumed_run_ids.len() > self.wire_codec_limits.max_samples() {
            let Some(oldest) = self.consumed_run_order.pop_front() else {
                break;
            };
            self.consumed_run_ids.remove(&oldest);
        }
    }

    fn apply_ack(
        &mut self,
        request_id: RequestId,
        worker: WorkerId,
        stage: AckStage,
        run_id: Option<RunId>,
        thread_count: Option<u32>,
        sample_watermark: Option<u64>,
    ) -> Result<(), RemoteError> {
        if self.invalid_requests.contains(&request_id) {
            return Err(RemoteError::new(
                RemoteErrorCode::Cancelled,
                false,
                "ack belongs to a cancelled or superseded request",
            ));
        }
        if self
            .workers
            .get(&worker)
            .is_some_and(|record| record.phase == WorkerPhase::Failed)
        {
            return Err(RemoteError::new(
                RemoteErrorCode::Cancelled,
                false,
                "ack came from a failed worker",
            ));
        }
        if let Some(completed) = self.completed_requests.get(&request_id) {
            if completed.worker == worker
                && completed.stage == stage
                && completed.run_id == run_id
                && completed.thread_count == thread_count
                && completed.sample_watermark == sample_watermark
            {
                return Ok(());
            }
            return Err(RemoteError::new(
                RemoteErrorCode::Protocol,
                false,
                "ack request ID was reused by another worker",
            ));
        }
        let pending = self.pending_requests.get(&request_id).ok_or_else(|| {
            RemoteError::new(
                RemoteErrorCode::Protocol,
                false,
                "ack request ID is unknown",
            )
        })?;
        if pending.worker != worker || pending.stage != stage {
            return Err(RemoteError::new(
                RemoteErrorCode::Protocol,
                false,
                "ack does not match its request ID",
            ));
        }
        if !self.workers.contains_key(&worker) {
            return Err(RemoteError::new(
                RemoteErrorCode::Protocol,
                false,
                "ack came from an unknown worker",
            ));
        }
        match stage {
            AckStage::Profile | AckStage::Plan | AckStage::Properties => {
                if self.phase != CoordinatorPhase::Configuring {
                    return Err(RemoteError::state(
                        "configuration ack arrived outside configuring",
                    ));
                }
                if run_id.is_some() || thread_count.is_some() || sample_watermark.is_some() {
                    return Err(RemoteError::new(
                        RemoteErrorCode::Protocol,
                        false,
                        "configuration ack carried run-scoped fields",
                    ));
                }
                // The worker becomes ready once all three acks have been
                // observed. Keep this compact per-record state by using phase
                // only after a complete triplet, while duplicate acks are
                // harmless and deterministic.
                let stages = self.config_acks.entry(worker).or_default();
                let required = match stage {
                    AckStage::Profile => &[][..],
                    AckStage::Plan => &[AckStage::Profile][..],
                    AckStage::Properties => &[AckStage::Profile, AckStage::Plan][..],
                    AckStage::Started | AckStage::Stopped => &[][..],
                };
                if !required.iter().all(|item| stages.contains(item)) {
                    return Err(RemoteError::state(
                        "configuration acknowledgement arrived out of order",
                    ));
                }
                stages.insert(stage);
                if self.config_acks.get(&worker).is_some_and(|stages| {
                    [AckStage::Profile, AckStage::Plan, AckStage::Properties]
                        .iter()
                        .all(|item| stages.contains(item))
                }) && let Some(record) = self.workers.get_mut(&worker)
                {
                    record.phase = WorkerPhase::Ready;
                }
            }
            AckStage::Started => {
                if let Some(run_id) = run_id {
                    validate_run_id(run_id)?;
                }
                if self.phase != CoordinatorPhase::Starting
                    || run_id != self.run_id
                    || thread_count != Some(self.configured_threads)
                    || sample_watermark.is_some()
                {
                    return Err(RemoteError::state(
                        "start ack does not match coordinator start",
                    ));
                }
                if let Some(record) = self.workers.get_mut(&worker) {
                    record.phase = WorkerPhase::Running;
                    record.thread_count = self.configured_threads;
                }
            }
            AckStage::Stopped => {
                if let Some(run_id) = run_id {
                    validate_run_id(run_id)?;
                }
                if run_id != self.run_id || sample_watermark.is_none() {
                    return Err(RemoteError::new(
                        RemoteErrorCode::Protocol,
                        false,
                        "stop ack must carry the active run and sample watermark",
                    ));
                }
                let watermark = sample_watermark.ok_or_else(|| {
                    RemoteError::new(
                        RemoteErrorCode::Protocol,
                        false,
                        "stop ack sample watermark is missing",
                    )
                })?;
                if watermark > self.max_samples as u64 {
                    return Err(RemoteError::new(
                        RemoteErrorCode::ResourceLimit,
                        false,
                        "stop ack sample watermark exceeds coordinator sample bound",
                    ));
                }
                if self
                    .accepted
                    .keys()
                    .any(|key| key.worker() == worker && key.sequence() >= watermark)
                {
                    return Err(RemoteError::new(
                        RemoteErrorCode::Protocol,
                        false,
                        "stop ack watermark precedes an accepted worker sample",
                    ));
                }
                let prestart = self
                    .workers
                    .get(&worker)
                    .is_some_and(|record| record.thread_count == 0)
                    && thread_count == Some(0);
                let worker_stopped = self
                    .workers
                    .get(&worker)
                    .is_some_and(|record| record.phase == WorkerPhase::Stopped);
                if !(self.phase == CoordinatorPhase::Stopping
                    || (self.phase == CoordinatorPhase::Stopped && worker_stopped))
                    || run_id != self.run_id
                    || (!prestart && thread_count != Some(self.configured_threads))
                {
                    return Err(RemoteError::state(
                        "stop ack does not match coordinator stop",
                    ));
                }
                // The watermark is useful for both stop severities.  For a
                // graceful stop it tells us which prefix must still arrive;
                // for an immediate stop it is the exclusive upper bound of
                // samples that were already admitted by the worker.  Keeping
                // it in both cases makes ACK/sample reordering safe: a
                // delayed sample that was cancelled by an immediate stop is
                // rejected instead of being counted after the terminal
                // decision, while an already-delivered sample remains
                // admissible.
                self.stop_watermarks.insert(worker, watermark);
                let satisfied = self.stop_watermark_satisfied(worker, watermark);
                if satisfied && let Some(record) = self.workers.get_mut(&worker) {
                    record.phase = WorkerPhase::Stopped;
                }
            }
        }
        self.recompute_phase();
        self.recompute_phase_after_configuration();
        self.pending_requests.remove(&request_id);
        self.completed_requests.insert(
            request_id,
            CompletedRequest {
                worker,
                stage,
                run_id,
                thread_count,
                sample_watermark,
            },
        );
        self.trim_request_history();
        Ok(())
    }

    fn fail_worker(
        &mut self,
        worker: WorkerId,
        run_id: Option<RunId>,
        error: RemoteError,
    ) -> Result<(), RemoteError> {
        if let Some(run_id) = run_id {
            validate_run_id(run_id)?;
        }
        if run_id != self.run_id {
            return Err(RemoteError::new(
                RemoteErrorCode::Cancelled,
                false,
                "failure belongs to a stale remote run generation",
            ));
        }
        if matches!(
            self.phase,
            CoordinatorPhase::Stopped | CoordinatorPhase::Failed
        ) && self
            .workers
            .get(&worker)
            .is_some_and(|record| record.phase != WorkerPhase::Failed)
        {
            return Err(RemoteError::new(
                RemoteErrorCode::Cancelled,
                false,
                "failure arrived after the coordinator reached a terminal state",
            ));
        }
        if self
            .workers
            .get(&worker)
            .is_some_and(|record| record.phase == WorkerPhase::Stopped)
        {
            return Err(RemoteError::new(
                RemoteErrorCode::Cancelled,
                false,
                "failure arrived after the worker reached a terminal state",
            ));
        }
        let already_failed = self
            .workers
            .get(&worker)
            .ok_or_else(|| {
                RemoteError::new(
                    RemoteErrorCode::Protocol,
                    false,
                    "failure came from an unknown worker",
                )
            })?
            .phase
            == WorkerPhase::Failed;
        if already_failed {
            // Failure notifications are retried by transports. Once a worker
            // is terminally failed, the first notification already cancelled
            // its requests and (for FailFast) emitted the stop controls.
            return Ok(());
        }
        if self.failure_policy == FailurePolicy::FailFast {
            // Validate the complete fail-fast transition before mutating the
            // worker record, request maps, or control outbox.
            self.ensure_fail_fast_stop_capacity(Some(worker))?;
        }
        let record = self.workers.get_mut(&worker).ok_or_else(|| {
            RemoteError::new(
                RemoteErrorCode::Protocol,
                false,
                "failure came from an unknown worker",
            )
        })?;
        record.phase = WorkerPhase::Failed;
        record.failure = Some(error.sanitized_copy(MAX_WIRE_FAILURE_MESSAGE_BYTES));
        let cancelled = self
            .pending_requests
            .iter()
            .filter_map(|(request_id, pending)| (pending.worker == worker).then_some(*request_id))
            .collect::<Vec<_>>();
        for request_id in cancelled {
            self.pending_requests.remove(&request_id);
            self.invalid_requests.insert(request_id);
        }
        self.trim_request_history();
        if self.failure_policy == FailurePolicy::FailFast {
            if self.stop_cause != Some(StopCause::FailFast) {
                self.cancel_all_pending_requests();
                self.begin_fail_fast_stop()?;
            } else {
                // Keep stop acknowledgements for still-healthy workers
                // pending. A later worker failure must not invalidate the
                // first fail-fast batch, or those workers could stop without
                // ever allowing the coordinator to reach its terminal phase.
                self.recompute_phase();
            }
        } else {
            self.recompute_phase();
        }
        Ok(())
    }

    fn begin_fail_fast_stop(&mut self) -> Result<(), RemoteError> {
        if self.stop_cause == Some(StopCause::FailFast) {
            // A second worker failure in the same fail-fast generation must
            // not enqueue another copy of every stop request.
            return Ok(());
        }
        if self.run_id.is_none()
            || !matches!(
                self.phase,
                CoordinatorPhase::Starting | CoordinatorPhase::Running | CoordinatorPhase::Stopping
            )
        {
            self.phase = CoordinatorPhase::Failed;
            return Ok(());
        }
        // This is repeated after the worker record is marked failed so the
        // exact set that will be enqueued is checked before any stop ID or
        // outbox mutation.
        self.ensure_fail_fast_stop_capacity(None)?;
        let run_id = self
            .run_id
            .ok_or_else(|| RemoteError::state("fail-fast stop has no run"))?;
        let workers = self
            .workers
            .values()
            .filter(|record| {
                matches!(
                    record.phase,
                    WorkerPhase::Ready | WorkerPhase::Running | WorkerPhase::Stopping
                )
            })
            .map(|record| record.worker)
            .collect::<Vec<_>>();
        self.ensure_control_ids(workers.len())?;
        self.stop_cause = Some(StopCause::FailFast);
        self.phase = CoordinatorPhase::Stopping;
        for worker in workers {
            let stop = self.envelope(RemoteMessage::Stop {
                run_id,
                mode: StopMode::Immediate,
            })?;
            self.register_pending(&stop, worker, AckStage::Stopped, 1);
            self.control_outbox.push(stop);
        }
        for record in self.workers.values_mut() {
            if record.phase == WorkerPhase::Ready {
                record.phase = WorkerPhase::Stopping;
            }
        }
        if self
            .workers
            .values()
            .filter(|record| record.phase != WorkerPhase::Failed)
            .all(|record| record.phase == WorkerPhase::Stopped)
        {
            self.phase = CoordinatorPhase::Failed;
        }
        Ok(())
    }

    /// Preflights one fail-fast stop batch. The caller may exclude the worker
    /// that is about to be marked failed; after that mutation the same worker
    /// naturally drops out of the healthy target set. No state is changed by
    /// this check, so a full outbox or exhausted ID range leaves the caller's
    /// worker/request state untouched.
    fn ensure_fail_fast_stop_capacity(
        &self,
        excluding: Option<WorkerId>,
    ) -> Result<(), RemoteError> {
        if self.stop_cause == Some(StopCause::FailFast)
            || self.run_id.is_none()
            || !matches!(
                self.phase,
                CoordinatorPhase::Starting | CoordinatorPhase::Running | CoordinatorPhase::Stopping
            )
        {
            return Ok(());
        }
        let stop_count = self
            .workers
            .values()
            .filter(|record| Some(record.worker) != excluding)
            .filter(|record| {
                matches!(
                    record.phase,
                    WorkerPhase::Ready | WorkerPhase::Running | WorkerPhase::Stopping
                )
            })
            .count();
        self.ensure_control_ids(stop_count)?;
        let required = self
            .control_outbox
            .len()
            .checked_add(stop_count)
            .ok_or_else(|| {
                RemoteError::new(
                    RemoteErrorCode::ResourceLimit,
                    false,
                    "fail-fast control outbox length overflowed",
                )
            })?;
        if required > self.configuration_limits.max_control_events() {
            return Err(RemoteError::new(
                RemoteErrorCode::ResourceLimit,
                false,
                "fail-fast control outbox bound exhausted",
            ));
        }
        Ok(())
    }

    fn cancel_all_pending_requests(&mut self) {
        let pending = self.pending_requests.keys().copied().collect::<Vec<_>>();
        self.pending_requests.clear();
        self.invalid_requests.extend(pending);
        self.trim_request_history();
    }

    fn cancel_pending_stop_requests(&mut self) {
        let cancelled = self
            .pending_requests
            .iter()
            .filter_map(|(request_id, pending)| {
                (pending.stage == AckStage::Stopped).then_some(*request_id)
            })
            .collect::<Vec<_>>();
        for request_id in cancelled {
            self.pending_requests.remove(&request_id);
            self.invalid_requests.insert(request_id);
        }
        self.trim_request_history();
    }

    fn cancel_pending_start_requests(&mut self) {
        let cancelled = self
            .pending_requests
            .iter()
            .filter_map(|(request_id, pending)| {
                (pending.stage == AckStage::Started).then_some(*request_id)
            })
            .collect::<Vec<_>>();
        for request_id in cancelled {
            self.pending_requests.remove(&request_id);
            self.invalid_requests.insert(request_id);
        }
        self.trim_request_history();
    }

    fn trim_request_history(&mut self) {
        while self.invalid_requests.len() > self.max_samples {
            let Some(request_id) = self.invalid_requests.iter().next().copied() else {
                break;
            };
            self.invalid_requests.remove(&request_id);
        }
        while self.completed_requests.len() > self.max_samples {
            let Some(request_id) = self.completed_requests.keys().next().copied() else {
                break;
            };
            self.completed_requests.remove(&request_id);
        }
        self.trim_sample_request_history();
    }

    fn trim_sample_request_history(&mut self) {
        while self.sample_requests.len() > self.max_samples {
            let Some(request_id) = self.sample_requests.keys().next().copied() else {
                break;
            };
            self.sample_requests.remove(&request_id);
        }
    }

    fn ensure_control_ids(&self, count: usize) -> Result<(), RemoteError> {
        const MAX_CONTROL_REQUEST_ID: u64 = (1 << 63) - 1;
        if count == 0 {
            return Ok(());
        }
        if self.next_request_id == 0
            || self.next_request_id > MAX_CONTROL_REQUEST_ID
            || u64::try_from(count - 1)
                .ok()
                .and_then(|offset| self.next_request_id.checked_add(offset))
                .is_none_or(|last| last > MAX_CONTROL_REQUEST_ID)
        {
            return Err(RemoteError::new(
                RemoteErrorCode::ResourceLimit,
                false,
                "coordinator control request ID space exhausted",
            ));
        }
        Ok(())
    }

    fn recompute_phase(&mut self) {
        self.advance_graceful_stop_workers();
        let healthy = self.healthy_worker_count();
        if healthy == 0 && !self.workers.is_empty() {
            let dropped = self
                .sender
                .as_mut()
                .map_or_else(Vec::new, SampleSender::abort);
            self.remove_discarded_samples(&dropped);
            self.phase = CoordinatorPhase::Failed;
            return;
        }
        match self.phase {
            CoordinatorPhase::Configuring => self.recompute_phase_after_configuration(),
            CoordinatorPhase::Starting => {
                if self
                    .workers
                    .values()
                    .filter(|record| record.phase != WorkerPhase::Failed)
                    .all(|record| record.phase == WorkerPhase::Running)
                {
                    self.phase = CoordinatorPhase::Running;
                }
            }
            CoordinatorPhase::Stopping
                if self
                    .workers
                    .values()
                    .filter(|record| record.phase != WorkerPhase::Failed)
                    .all(|record| record.phase == WorkerPhase::Stopped) =>
            {
                let dropped = if let Some(sender) = self.sender.as_mut() {
                    if matches!(self.stop_cause, Some(StopCause::FailFast))
                        || matches!(self.stop_cause, Some(StopCause::User(StopMode::Immediate)))
                    {
                        sender.abort()
                    } else {
                        sender.flush_pending_samples();
                        Vec::new()
                    }
                } else {
                    Vec::new()
                };
                self.remove_discarded_samples(&dropped);
                self.phase = if matches!(self.stop_cause, Some(StopCause::FailFast)) {
                    CoordinatorPhase::Failed
                } else {
                    CoordinatorPhase::Stopped
                };
            }
            _ => {}
        }
    }

    fn stop_watermark_satisfied(&self, worker: WorkerId, watermark: u64) -> bool {
        let mut count = 0usize;
        for key in self.accepted.keys().filter(|key| key.worker() == worker) {
            if key.sequence() >= watermark {
                return false;
            }
            count = count.saturating_add(1);
        }
        usize::try_from(watermark).is_ok_and(|expected| count == expected)
    }

    fn advance_graceful_stop_workers(&mut self) {
        if !matches!(
            self.stop_cause,
            Some(StopCause::User(StopMode::Graceful | StopMode::Immediate))
        ) {
            return;
        }
        let completed = self
            .stop_watermarks
            .iter()
            .filter_map(|(&worker, &watermark)| {
                self.stop_watermark_satisfied(worker, watermark)
                    .then_some(worker)
            })
            .collect::<Vec<_>>();
        for worker in completed {
            if let Some(record) = self.workers.get_mut(&worker)
                && record.phase == WorkerPhase::Stopping
            {
                record.phase = WorkerPhase::Stopped;
            }
        }
    }

    fn recompute_phase_after_configuration(&mut self) {
        if self.phase != CoordinatorPhase::Configuring {
            return;
        }
        let ready_or_failed = self
            .workers
            .values()
            .filter(|record| record.phase != WorkerPhase::Failed)
            .all(|record| record.phase == WorkerPhase::Ready);
        if ready_or_failed && self.healthy_worker_count() > 0 {
            self.phase = CoordinatorPhase::Ready;
        }
    }

    fn remove_discarded_samples(&mut self, discarded: &[RemoteSample]) {
        for sample in discarded {
            if self.accepted.remove(&sample.key()).is_some()
                && let Some(bytes) = self.accepted_sizes.remove(&sample.key())
            {
                self.accepted_bytes = self.accepted_bytes.saturating_sub(bytes);
            }
            self.sample_requests.retain(|_, key| *key != sample.key());
        }
        if !discarded.is_empty() {
            let keys = discarded
                .iter()
                .map(RemoteSample::key)
                .collect::<BTreeSet<_>>();
            self.arrival_order.retain(|key| !keys.contains(key));
        }
    }

    fn register_pending(
        &mut self,
        envelope: &RemoteEnvelope,
        worker: WorkerId,
        stage: AckStage,
        attempt: u32,
    ) {
        self.pending_requests.insert(
            envelope.request_id,
            PendingRequest {
                worker,
                stage,
                attempt,
                message: envelope.message.clone(),
            },
        );
    }

    fn envelope(&mut self, message: RemoteMessage) -> Result<RemoteEnvelope, RemoteError> {
        if self.next_request_id == 0 || self.next_request_id > (1 << 63) - 1 {
            return Err(RemoteError::new(
                RemoteErrorCode::ResourceLimit,
                false,
                "coordinator control request ID space exhausted",
            ));
        }
        let request_id = self.next_request_id;
        self.next_request_id = if request_id == (1 << 63) - 1 {
            0
        } else {
            request_id + 1
        };
        Ok(RemoteEnvelope::new(request_id, message))
    }
}

/// Compatibility aliases for concise adapter code.
pub type Coordinator = RemoteCoordinator;
/// Compatibility alias for concise adapter code.
pub type Worker = RemoteWorker;

#[cfg(test)]
#[allow(clippy::expect_used)] // Test fixtures use expect for assertion-context failures.
mod tests {
    use super::*;
    use crate::protocol::{ProfileDescriptor, PropertySet, SampleSenderMode};
    use jmeter_rs_results::{SampleEvent, SampleResult, ThreadIdentity, VariableSnapshot};

    fn profile() -> ProfileDescriptor {
        ProfileDescriptor::new("jmeter-5.6.3", "1")
    }

    fn event(label: &str) -> SampleEvent {
        SampleEvent::new(
            SampleResult::new(label),
            "run",
            ThreadIdentity::new("thread"),
            "host",
            VariableSnapshot::new(),
        )
    }

    fn configure(coordinator: &mut RemoteCoordinator, worker: &mut RemoteWorker) {
        let mut properties = PropertySet::new();
        properties.insert("mode", "test");
        let messages = coordinator
            .configure(PlanDescriptor::new(b"plan".to_vec()), properties)
            .expect("configure");
        for message in messages {
            let responses = worker.apply(message).expect("worker apply");
            for response in responses {
                coordinator.apply(response).expect("coordinator ack");
            }
        }
        // Configuration acks are ordered profile, plan, properties. The
        // coordinator's complete helper makes that explicit for callers.
        coordinator
            .configuration_complete(worker.id())
            .expect("ready");
    }

    #[test]
    fn worker_and_coordinator_use_the_same_custom_codec_limits() {
        let wire = crate::protocol::WireLimits::new(8 * 1024, 32).expect("wire limits");
        let limits = RemoteLimits::default().with_wire_limits(wire);
        let mut coordinator = RemoteCoordinator::new(profile());
        let mut worker = RemoteWorker::new(WorkerId::new(1), profile());
        coordinator
            .set_codec_limits(limits)
            .expect("coordinator codec limits");
        worker
            .set_codec_limits(limits)
            .expect("worker codec limits");
        coordinator.add_worker(worker.id()).expect("worker");
        configure(&mut coordinator, &mut worker);
        assert!(matches!(
            coordinator.set_codec_limits(RemoteLimits::default()),
            Err(error) if error.code == RemoteErrorCode::InvalidState
        ));
        assert!(matches!(
            worker.set_codec_limits(RemoteLimits::default()),
            Err(error) if error.code == RemoteErrorCode::InvalidState
        ));
        for start in coordinator
            .start(41, 1, SampleSenderMode::Standard)
            .expect("start")
        {
            for response in worker.apply(start).expect("worker start") {
                coordinator.apply(response).expect("start ack");
            }
        }

        let mut oversized = SampleResult::new("oversized");
        oversized.set_response_message(Some("x".repeat(33)));
        let oversized_event = SampleEvent::new(
            oversized,
            "run",
            ThreadIdentity::new("thread"),
            "host",
            VariableSnapshot::new(),
        );
        assert!(matches!(
            worker.emit_sample(oversized_event.clone()),
            Err(error) if error.code == RemoteErrorCode::ResourceLimit
        ));
        let direct = RemoteSample::new(41, worker.id(), 0, oversized_event);
        assert!(matches!(
            coordinator.record_sample(direct),
            Err(error) if error.code == RemoteErrorCode::ResourceLimit
        ));
        assert_eq!(coordinator.codec_limits(), limits);
        assert_eq!(worker.codec_limits(), limits);
    }

    #[test]
    fn worker_runs_full_thread_count_and_stop_is_ordered() {
        let mut coordinator = RemoteCoordinator::new(profile());
        let mut worker = RemoteWorker::new(WorkerId::new(1), profile());
        coordinator.add_worker(worker.id()).expect("worker");
        configure(&mut coordinator, &mut worker);
        let starts = coordinator
            .start(7, 3, SampleSenderMode::Standard)
            .expect("start");
        for start in starts {
            for response in worker.apply(start).expect("worker start") {
                coordinator.apply(response).expect("start ack");
            }
        }
        assert_eq!(coordinator.phase(), CoordinatorPhase::Running);
        assert_eq!(coordinator.total_threads().expect("threads"), 3);
        for response in worker.emit_sample(event("one")).expect("sample") {
            coordinator.apply(response).expect("sample");
        }
        let stop = coordinator.stop(StopMode::Graceful).expect("stop");
        for request in stop {
            for response in worker.apply(request).expect("worker stop") {
                coordinator.apply(response).expect("stop response");
            }
        }
        assert_eq!(coordinator.phase(), CoordinatorPhase::Stopped);
        assert_eq!(coordinator.arrival_samples().len(), 1);
    }

    #[test]
    fn partial_failure_continues_and_multiplies_only_healthy_workers() {
        let mut coordinator = RemoteCoordinator::new(profile());
        let mut first = RemoteWorker::new(WorkerId::new(1), profile());
        let mut second = RemoteWorker::new(WorkerId::new(2), profile());
        coordinator.add_worker(first.id()).expect("worker");
        coordinator.add_worker(second.id()).expect("worker");
        // Configuration is dispatched independently to each worker.
        let mut properties = PropertySet::new();
        properties.insert("k", "v");
        let messages = coordinator
            .configure(PlanDescriptor::new(b"plan".to_vec()), properties)
            .expect("configure");
        for (index, message) in messages.into_iter().enumerate() {
            let target = if index < 3 { &mut first } else { &mut second };
            for response in target.apply(message).expect("worker apply") {
                coordinator.apply(response).expect("ack");
            }
        }
        coordinator
            .configuration_complete(first.id())
            .expect("first ready");
        coordinator
            .configuration_complete(second.id())
            .expect("second ready");
        coordinator
            .worker_failed(
                second.id(),
                RemoteError::new(RemoteErrorCode::WorkerFailure, true, "gone"),
            )
            .expect("failure");
        assert_eq!(coordinator.healthy_worker_count(), 1);
        coordinator
            .start(9, 3, SampleSenderMode::Standard)
            .expect("healthy worker can start");
        assert_eq!(coordinator.total_threads().expect("threads"), 3);
    }

    #[test]
    fn arrival_order_is_preserved_separately_from_execution_order_and_duplicates_are_idempotent() {
        let mut coordinator = RemoteCoordinator::new(profile());
        let mut worker = RemoteWorker::new(WorkerId::new(1), profile());
        coordinator.add_worker(worker.id()).expect("worker");
        configure(&mut coordinator, &mut worker);
        for start in coordinator
            .start(7, 1, SampleSenderMode::Standard)
            .expect("start")
        {
            for response in worker.apply(start).expect("worker start") {
                coordinator.apply(response).expect("start ack");
            }
        }

        let second = RemoteSample::new(7, worker.id(), 2, event("second"));
        let first = RemoteSample::new(7, worker.id(), 1, event("first"));
        assert_eq!(
            coordinator.record_sample(second.clone()),
            Ok(RecordOutcome::Accepted(SendOutcome::Delivered))
        );
        assert_eq!(
            coordinator.record_sample(first.clone()),
            Ok(RecordOutcome::Accepted(SendOutcome::Delivered))
        );
        assert_eq!(
            coordinator.record_sample(second),
            Ok(RecordOutcome::Duplicate)
        );
        let arrival = coordinator.arrival_samples();
        assert_eq!(arrival[0].event().result().label(), "second");
        assert_eq!(arrival[1].event().result().label(), "first");
        let execution = coordinator.execution_order_samples();
        assert_eq!(execution[0].sequence(), 1);
        assert_eq!(execution[1].sequence(), 2);

        let conflicting = RemoteSample::new(7, worker.id(), 1, event("changed"));
        assert!(matches!(
            coordinator.record_sample(conflicting),
            Err(error) if error.code == RemoteErrorCode::ConflictingDuplicate
        ));
    }

    #[test]
    fn coordinator_retained_bytes_are_bounded_before_accepting_a_sample() {
        let mut coordinator = RemoteCoordinator::new(profile());
        let mut worker = RemoteWorker::new(WorkerId::new(1), profile());
        coordinator.add_worker(worker.id()).expect("worker");
        configure(&mut coordinator, &mut worker);
        for start in coordinator
            .start(10, 1, SampleSenderMode::Standard)
            .expect("start")
        {
            for response in worker.apply(start).expect("worker start") {
                coordinator.apply(response).expect("start ack");
            }
        }
        coordinator
            .set_max_retained_bytes(1)
            .expect("bound can be lowered before samples");
        assert!(matches!(
            coordinator.record_sample(RemoteSample::new(
                10,
                worker.id(),
                1,
                event("too large"),
            )),
            Err(error) if error.code == RemoteErrorCode::ResourceLimit
        ));
        assert!(coordinator.arrival_samples().is_empty());
    }

    #[test]
    fn coordinator_rejects_sample_request_id_reuse_for_another_key() {
        let mut coordinator = RemoteCoordinator::new(profile());
        let mut worker = RemoteWorker::new(WorkerId::new(1), profile());
        coordinator.add_worker(worker.id()).expect("worker");
        configure(&mut coordinator, &mut worker);
        for start in coordinator
            .start(10, 1, SampleSenderMode::Standard)
            .expect("start")
        {
            for response in worker.apply(start).expect("worker start") {
                coordinator.apply(response).expect("start ack");
            }
        }
        let id = sample_envelope_request_id(worker.id(), 1).expect("sample ID");
        coordinator
            .apply(RemoteEnvelope::new(
                id,
                RemoteMessage::Sample {
                    sample: RemoteSample::new(10, worker.id(), 1, event("one")),
                },
            ))
            .expect("first sample");
        assert!(matches!(
            coordinator.apply(RemoteEnvelope::new(
                id,
                RemoteMessage::Sample {
                    sample: RemoteSample::new(10, worker.id(), 2, event("two")),
                },
            )),
            Err(error) if error.code == RemoteErrorCode::Protocol
        ));
    }

    #[test]
    fn worker_batch_delivery_keeps_each_sample_sequence_in_its_envelope() {
        let mut coordinator = RemoteCoordinator::new(profile());
        let mut worker = RemoteWorker::new(WorkerId::new(1), profile());
        coordinator.add_worker(worker.id()).expect("worker");
        configure(&mut coordinator, &mut worker);
        for start in coordinator
            .start(8, 1, SampleSenderMode::Batch { size: 2 })
            .expect("start")
        {
            for response in worker.apply(start).expect("worker start") {
                coordinator.apply(response).expect("start ack");
            }
        }
        assert!(worker.emit_sample(event("one")).expect("sample").is_empty());
        let delivered = worker.emit_sample(event("two")).expect("sample");
        assert_eq!(
            delivered
                .iter()
                .map(|envelope| envelope.request_id)
                .collect::<Vec<_>>(),
            vec![delivered[0].request_id, delivered[0].request_id + 1,]
        );
        assert!(
            delivered
                .iter()
                .all(|envelope| envelope.request_id >> 63 == 1)
        );
    }

    #[test]
    fn graceful_stop_uses_sample_namespace_for_flushed_samples_not_stop_id() {
        let mut coordinator = RemoteCoordinator::new(profile());
        let mut worker = RemoteWorker::new(WorkerId::new(1), profile());
        coordinator.add_worker(worker.id()).expect("worker");
        configure(&mut coordinator, &mut worker);
        for start in coordinator
            .start(11, 1, SampleSenderMode::Hold)
            .expect("start")
        {
            for response in worker.apply(start).expect("worker start") {
                coordinator.apply(response).expect("start ack");
            }
        }
        assert!(
            worker
                .emit_sample(event("held"))
                .expect("sample")
                .is_empty()
        );
        let stop = coordinator.stop(StopMode::Graceful).expect("stop");
        let stop_id = stop[0].request_id;
        let responses = worker.apply(stop[0].clone()).expect("worker stop");
        let sample_id = responses
            .iter()
            .find_map(|response| {
                matches!(response.message, RemoteMessage::Sample { .. })
                    .then_some(response.request_id)
            })
            .expect("flushed sample");
        assert_ne!(sample_id, stop_id);
        assert_eq!(sample_id >> 63, 1);
        for response in responses {
            coordinator.apply(response).expect("stop response");
        }
        assert_eq!(coordinator.phase(), CoordinatorPhase::Stopped);
    }

    #[test]
    fn immediate_stop_drops_worker_queue_but_returns_only_already_delivered_samples() {
        let mut coordinator = RemoteCoordinator::new(profile());
        let mut worker = RemoteWorker::new(WorkerId::new(1), profile());
        coordinator.add_worker(worker.id()).expect("worker");
        configure(&mut coordinator, &mut worker);
        for start in coordinator
            .start(12, 1, SampleSenderMode::Hold)
            .expect("start")
        {
            for response in worker.apply(start).expect("worker start") {
                coordinator.apply(response).expect("start ack");
            }
        }
        assert!(
            worker
                .emit_sample(event("queued"))
                .expect("sample")
                .is_empty()
        );
        let stop = coordinator.stop(StopMode::Immediate).expect("stop");
        let responses = worker.apply(stop[0].clone()).expect("worker stop");
        assert!(
            responses
                .iter()
                .all(|response| !matches!(response.message, RemoteMessage::Sample { .. }))
        );
        for response in responses {
            coordinator.apply(response).expect("stop response");
        }
        assert!(coordinator.arrival_samples().is_empty());
        assert_eq!(coordinator.phase(), CoordinatorPhase::Stopped);
    }

    #[test]
    fn immediate_stop_waits_for_already_delivered_sample_when_ack_arrives_first() {
        let mut coordinator = RemoteCoordinator::new(profile());
        let mut worker = RemoteWorker::new(WorkerId::new(1), profile());
        coordinator.add_worker(worker.id()).expect("worker");
        configure(&mut coordinator, &mut worker);
        for start in coordinator
            .start(121, 1, SampleSenderMode::Standard)
            .expect("start")
        {
            for response in worker.apply(start).expect("worker start") {
                coordinator.apply(response).expect("start ack");
            }
        }
        let sample = worker
            .emit_sample(event("already-delivered"))
            .expect("sample")
            .into_iter()
            .next()
            .expect("sample envelope");
        let stop = coordinator.stop(StopMode::Immediate).expect("stop");
        let responses = worker.apply(stop[0].clone()).expect("worker stop");
        let ack = responses
            .iter()
            .find(|response| matches!(response.message, RemoteMessage::Ack { .. }))
            .cloned()
            .expect("stop ack");
        coordinator.apply(ack).expect("ack first");
        assert_eq!(coordinator.phase(), CoordinatorPhase::Stopping);
        coordinator.apply(sample).expect("sample after ack");
        assert_eq!(coordinator.phase(), CoordinatorPhase::Stopped);
        assert_eq!(coordinator.arrival_samples().len(), 1);
    }

    #[test]
    fn immediate_stop_escalation_supersedes_graceful_request_without_stale_ack_resurrection() {
        let mut coordinator = RemoteCoordinator::new(profile());
        let mut worker = RemoteWorker::new(WorkerId::new(1), profile());
        coordinator.add_worker(worker.id()).expect("worker");
        configure(&mut coordinator, &mut worker);
        for start in coordinator
            .start(13, 1, SampleSenderMode::Standard)
            .expect("start")
        {
            for response in worker.apply(start).expect("worker start") {
                coordinator.apply(response).expect("start ack");
            }
        }

        let graceful = coordinator.stop(StopMode::Graceful).expect("graceful stop");
        let immediate = coordinator.stop(StopMode::Immediate).expect("escalate");
        assert_eq!(immediate.len(), 1);
        assert!(matches!(
            immediate[0].message,
            RemoteMessage::Stop {
                mode: StopMode::Immediate,
                ..
            }
        ));

        let stale = worker.apply(graceful[0].clone()).expect("old stop applies");
        for response in stale {
            assert!(matches!(
                coordinator.apply(response),
                Err(error) if error.code == RemoteErrorCode::Cancelled
            ));
        }
        for response in worker
            .apply(immediate[0].clone())
            .expect("new stop applies")
        {
            coordinator.apply(response).expect("immediate ack");
        }
        assert_eq!(coordinator.phase(), CoordinatorPhase::Stopped);
    }

    #[test]
    fn missing_worker_local_reference_is_a_capability_error_and_never_transfers_contents() {
        let mut worker = RemoteWorker::new(WorkerId::new(1), profile());
        let profile_request = RemoteEnvelope::new(1, RemoteMessage::Profile { profile: profile() });
        worker.apply(profile_request).expect("profile");
        let plan = PlanDescriptor::new(b"<testPlan/>".to_vec()).with_references(
            vec![crate::protocol::DataReference::new("worker.csv", "csv")],
            vec![crate::protocol::DependencyReference::new("driver", "1")],
        );
        let error = worker
            .apply(RemoteEnvelope::new(2, RemoteMessage::Plan { plan }))
            .expect_err("missing local data must reject plan");
        assert_eq!(error.code, RemoteErrorCode::CapabilityUnavailable);
    }

    #[test]
    fn fail_fast_marks_the_coordinator_terminal() {
        let mut coordinator = RemoteCoordinator::new(profile());
        coordinator.set_failure_policy(FailurePolicy::FailFast);
        let worker = WorkerId::new(1);
        coordinator.add_worker(worker).expect("worker");
        coordinator
            .worker_failed(
                worker,
                RemoteError::new(RemoteErrorCode::WorkerFailure, false, "failed"),
            )
            .expect("failure");
        assert_eq!(coordinator.phase(), CoordinatorPhase::Failed);
        assert!(matches!(
            coordinator.start(1, 1, SampleSenderMode::Standard),
            Err(error) if error.code == RemoteErrorCode::InvalidState
        ));
    }

    #[test]
    fn control_request_ids_are_nonzero_and_exhaustion_is_fallible() {
        let mut coordinator = RemoteCoordinator::new(profile());
        coordinator.next_request_id = (1 << 63) - 1;
        let envelope = coordinator
            .envelope(RemoteMessage::Stop {
                run_id: 1,
                mode: StopMode::Immediate,
            })
            .expect("last control ID remains usable");
        assert_ne!(envelope.request_id, 0);
        assert_eq!(coordinator.next_request_id, 0);
        assert!(matches!(
            coordinator.envelope(RemoteMessage::Stop {
                run_id: 1,
                mode: StopMode::Immediate,
            }),
            Err(error) if error.code == RemoteErrorCode::ResourceLimit
        ));
    }

    #[test]
    fn sample_envelope_ids_fail_before_worker_ordinal_wraparound() {
        let mut coordinator = RemoteCoordinator::new(profile());
        let mut worker = RemoteWorker::new(WorkerId::new(7), profile());
        coordinator.add_worker(worker.id()).expect("worker");
        configure(&mut coordinator, &mut worker);
        for start in coordinator
            .start(14, 1, SampleSenderMode::Standard)
            .expect("start")
        {
            for response in worker.apply(start).expect("worker start") {
                coordinator.apply(response).expect("start ack");
            }
        }
        worker.next_sample_envelope_ordinal = (1 << 31) - 1;
        let last = worker.emit_sample(event("last")).expect("last ID");
        assert_eq!(last.len(), 1);
        assert_ne!(last[0].request_id, 0);
        assert_eq!(last[0].request_id >> 63, 1);
        assert!(matches!(
            worker.emit_sample(event("exhausted")),
            Err(error) if error.code == RemoteErrorCode::ResourceLimit
        ));
    }

    #[test]
    fn retry_uses_a_fresh_id_and_stale_ack_is_rejected() {
        let mut coordinator = RemoteCoordinator::new(profile());
        let mut worker = RemoteWorker::new(WorkerId::new(1), profile());
        coordinator.add_worker(worker.id()).expect("worker");
        let messages = coordinator
            .configure(PlanDescriptor::new(b"plan".to_vec()), PropertySet::new())
            .expect("configure");
        let original = messages[0].clone();
        let replacement = coordinator
            .retry_request(original.request_id)
            .expect("retry");
        assert_ne!(replacement.request_id, original.request_id);
        assert_eq!(coordinator.request_attempt(replacement.request_id), Some(2));
        let stale = worker
            .apply(original)
            .expect("worker applies stale request");
        let stale_ack = stale.into_iter().next().expect("stale ack");
        assert!(matches!(
            coordinator.apply(stale_ack),
            Err(error) if error.code == RemoteErrorCode::Cancelled
        ));
    }

    #[test]
    fn retry_after_worker_applied_start_does_not_reset_worker_state() {
        let mut coordinator = RemoteCoordinator::new(profile());
        let mut worker = RemoteWorker::new(WorkerId::new(1), profile());
        coordinator.add_worker(worker.id()).expect("worker");
        configure(&mut coordinator, &mut worker);
        let start = coordinator
            .start(15, 1, SampleSenderMode::Standard)
            .expect("start")
            .into_iter()
            .next()
            .expect("start request");

        // Apply the first request but deliberately drop its acknowledgement.
        worker.apply(start.clone()).expect("worker applies start");
        let first = worker.emit_sample(event("before-retry")).expect("sample");
        assert_eq!(
            first[0].message,
            RemoteMessage::Sample {
                sample: RemoteSample::new(15, worker.id(), 0, event("before-retry")),
            }
        );

        let replacement = coordinator
            .retry_request(start.request_id)
            .expect("bounded retry");
        for response in worker.apply(replacement).expect("idempotent start retry") {
            coordinator.apply(response).expect("start acknowledgement");
        }
        assert_eq!(coordinator.phase(), CoordinatorPhase::Running);
        let second = worker.emit_sample(event("after-retry")).expect("sample");
        let sample = match &second[0].message {
            RemoteMessage::Sample { sample } => sample,
            other => {
                assert_eq!(other.kind(), crate::MessageKind::Sample);
                return;
            }
        };
        assert_eq!(sample.sequence(), 1);
    }

    #[test]
    fn worker_batch_time_threshold_uses_injected_clock_and_keeps_sample_ids() {
        let mut coordinator = RemoteCoordinator::new(profile());
        let mut worker = RemoteWorker::new(WorkerId::new(1), profile());
        coordinator.add_worker(worker.id()).expect("worker");
        configure(&mut coordinator, &mut worker);
        worker.set_batch_time_ms(10).expect("time threshold");
        coordinator
            .set_batch_time_ms(10)
            .expect("coordinator time threshold");
        let starts = coordinator
            .start(17, 1, SampleSenderMode::Batch { size: 4 })
            .expect("start");
        for start in starts {
            for response in worker.apply(start).expect("worker start") {
                coordinator.apply(response).expect("start ack");
            }
        }
        assert!(
            worker
                .emit_sample(event("timed"))
                .expect("sample")
                .is_empty()
        );
        assert!(worker.advance_time(10).expect("at threshold").is_empty());
        let released = worker.advance_time(11).expect("threshold");
        assert_eq!(released.len(), 1);
        let request_id = released[0].request_id;
        assert!(crate::is_sample_envelope_request_id(request_id));
        coordinator.apply(released[0].clone()).expect("sample");
        assert!(
            coordinator
                .advance_time(10)
                .expect("at coordinator threshold")
                .is_empty()
        );
        assert_eq!(
            coordinator
                .advance_time(11)
                .expect("coordinator threshold")
                .len(),
            1
        );
    }

    #[test]
    fn stale_start_from_a_retired_run_generation_cannot_resurrect_worker() {
        let mut coordinator = RemoteCoordinator::new(profile());
        let mut worker = RemoteWorker::new(WorkerId::new(1), profile());
        coordinator.add_worker(worker.id()).expect("worker");
        configure(&mut coordinator, &mut worker);
        let stale_start = coordinator
            .start(19, 1, SampleSenderMode::Standard)
            .expect("start")
            .into_iter()
            .next()
            .expect("start request");
        for response in worker.apply(stale_start.clone()).expect("worker start") {
            coordinator.apply(response).expect("start ack");
        }
        let stop = coordinator.stop(StopMode::Immediate).expect("stop");
        for response in worker.apply(stop[0].clone()).expect("worker stop") {
            coordinator.apply(response).expect("stop ack");
        }
        configure(&mut coordinator, &mut worker);
        assert!(matches!(
            worker.apply(stale_start),
            Err(error) if error.code == RemoteErrorCode::InvalidState
        ));
        assert!(matches!(
            coordinator.start(19, 1, SampleSenderMode::Standard),
            Err(error) if error.code == RemoteErrorCode::InvalidState
        ));
        let next_start = coordinator
            .start(20, 1, SampleSenderMode::Standard)
            .expect("new run");
        for response in worker
            .apply(next_start[0].clone())
            .expect("new worker start")
        {
            coordinator.apply(response).expect("new start ack");
        }
        assert_eq!(worker.run_id(), Some(20));
    }

    #[test]
    fn stale_stop_from_a_retired_run_generation_cannot_cancel_new_configuration() {
        let mut worker = RemoteWorker::new(WorkerId::new(1), profile());
        worker
            .apply(RemoteEnvelope::new(
                1,
                RemoteMessage::Profile { profile: profile() },
            ))
            .expect("profile");
        worker
            .apply(RemoteEnvelope::new(
                2,
                RemoteMessage::Plan {
                    plan: PlanDescriptor::new(b"plan".to_vec()),
                },
            ))
            .expect("plan");
        worker
            .apply(RemoteEnvelope::new(
                3,
                RemoteMessage::Properties {
                    properties: PropertySet::new(),
                },
            ))
            .expect("properties");
        worker
            .apply(RemoteEnvelope::new(
                4,
                RemoteMessage::Start {
                    run_id: 24,
                    thread_count: 1,
                    sender_mode: SampleSenderMode::Standard,
                },
            ))
            .expect("start");
        worker
            .apply(RemoteEnvelope::new(
                5,
                RemoteMessage::Stop {
                    run_id: 24,
                    mode: StopMode::Immediate,
                },
            ))
            .expect("stop");

        // Reconfiguration retires the old run but deliberately retains its
        // consumed generation as a stale-frame guard.
        worker
            .apply(RemoteEnvelope::new(
                6,
                RemoteMessage::Profile { profile: profile() },
            ))
            .expect("new profile");
        worker
            .apply(RemoteEnvelope::new(
                7,
                RemoteMessage::Plan {
                    plan: PlanDescriptor::new(b"new-plan".to_vec()),
                },
            ))
            .expect("new plan");
        worker
            .apply(RemoteEnvelope::new(
                8,
                RemoteMessage::Properties {
                    properties: PropertySet::new(),
                },
            ))
            .expect("new properties");
        assert_eq!(worker.phase(), WorkerPhase::Ready);

        assert!(matches!(
            worker.apply(RemoteEnvelope::new(
                9,
                RemoteMessage::Stop {
                    run_id: 24,
                    mode: StopMode::Immediate,
                },
            )),
            Err(error) if error.code == RemoteErrorCode::Cancelled
        ));
        assert_eq!(worker.phase(), WorkerPhase::Ready);
        worker
            .apply(RemoteEnvelope::new(
                10,
                RemoteMessage::Start {
                    run_id: 25,
                    thread_count: 1,
                    sender_mode: SampleSenderMode::Standard,
                },
            ))
            .expect("new run remains startable");
    }

    #[test]
    fn stale_configuration_frames_cannot_replace_a_new_plan_generation() {
        let mut worker = RemoteWorker::new(WorkerId::new(1), profile());
        worker
            .apply(RemoteEnvelope::new(
                1,
                RemoteMessage::Profile { profile: profile() },
            ))
            .expect("profile");
        worker
            .apply(RemoteEnvelope::new(
                2,
                RemoteMessage::Plan {
                    plan: PlanDescriptor::new(b"old-plan".to_vec()),
                },
            ))
            .expect("old plan");
        worker
            .apply(RemoteEnvelope::new(
                3,
                RemoteMessage::Properties {
                    properties: PropertySet::new(),
                },
            ))
            .expect("old properties");
        worker
            .apply(RemoteEnvelope::new(
                4,
                RemoteMessage::Start {
                    run_id: 27,
                    thread_count: 1,
                    sender_mode: SampleSenderMode::Standard,
                },
            ))
            .expect("old start");
        worker
            .apply(RemoteEnvelope::new(
                5,
                RemoteMessage::Stop {
                    run_id: 27,
                    mode: StopMode::Immediate,
                },
            ))
            .expect("old stop");

        worker
            .apply(RemoteEnvelope::new(
                10,
                RemoteMessage::Profile { profile: profile() },
            ))
            .expect("new profile");
        worker
            .apply(RemoteEnvelope::new(
                11,
                RemoteMessage::Plan {
                    plan: PlanDescriptor::new(b"new-plan".to_vec()),
                },
            ))
            .expect("new plan");
        worker
            .apply(RemoteEnvelope::new(
                12,
                RemoteMessage::Properties {
                    properties: PropertySet::new(),
                },
            ))
            .expect("new properties");
        assert_eq!(worker.plan().expect("plan").jmx(), b"new-plan");
        assert_eq!(worker.phase(), WorkerPhase::Ready);

        assert!(matches!(
            worker.apply(RemoteEnvelope::new(
                1,
                RemoteMessage::Profile { profile: profile() },
            )),
            Err(error) if error.code == RemoteErrorCode::Cancelled
        ));
        assert!(matches!(
            worker.apply(RemoteEnvelope::new(
                2,
                RemoteMessage::Plan {
                    plan: PlanDescriptor::new(b"old-plan".to_vec()),
                },
            )),
            Err(error) if error.code == RemoteErrorCode::Cancelled
        ));
        assert_eq!(worker.plan().expect("plan").jmx(), b"new-plan");
        assert_eq!(worker.phase(), WorkerPhase::Ready);
    }

    #[test]
    fn immediate_stop_watermark_excludes_sender_queue_not_released() {
        let mut worker = RemoteWorker::new(WorkerId::new(1), profile());
        worker
            .apply(RemoteEnvelope::new(
                1,
                RemoteMessage::Profile { profile: profile() },
            ))
            .expect("profile");
        worker
            .apply(RemoteEnvelope::new(
                2,
                RemoteMessage::Plan {
                    plan: PlanDescriptor::new(b"plan".to_vec()),
                },
            ))
            .expect("plan");
        worker
            .apply(RemoteEnvelope::new(
                3,
                RemoteMessage::Properties {
                    properties: PropertySet::new(),
                },
            ))
            .expect("properties");
        worker
            .apply(RemoteEnvelope::new(
                4,
                RemoteMessage::Start {
                    run_id: 26,
                    thread_count: 1,
                    sender_mode: SampleSenderMode::Hold,
                },
            ))
            .expect("start");
        assert!(
            worker
                .emit_sample(event("cancelled"))
                .expect("sample")
                .is_empty()
        );

        let responses = worker
            .apply(RemoteEnvelope::new(
                5,
                RemoteMessage::Stop {
                    run_id: 26,
                    mode: StopMode::Immediate,
                },
            ))
            .expect("immediate stop");
        let watermark = responses.iter().find_map(|response| {
            if let RemoteMessage::Ack {
                stage: AckStage::Stopped,
                sample_watermark,
                ..
            } = &response.message
            {
                *sample_watermark
            } else {
                None
            }
        });
        assert_eq!(watermark, Some(0));
    }

    #[test]
    fn immediate_stop_cancels_starting_workers_before_they_run() {
        let mut coordinator = RemoteCoordinator::new(profile());
        let mut worker = RemoteWorker::new(WorkerId::new(1), profile());
        coordinator.add_worker(worker.id()).expect("worker");
        configure(&mut coordinator, &mut worker);
        let start = coordinator
            .start(16, 1, SampleSenderMode::Standard)
            .expect("start")
            .into_iter()
            .next()
            .expect("start request");

        let stop = coordinator
            .stop(StopMode::Immediate)
            .expect("stop while starting");
        assert_eq!(stop.len(), 1);
        for response in worker.apply(stop[0].clone()).expect("pre-start stop") {
            coordinator.apply(response).expect("stop acknowledgement");
        }
        assert_eq!(coordinator.phase(), CoordinatorPhase::Stopped);
        assert!(matches!(
            worker.apply(start),
            Err(error) if error.code == RemoteErrorCode::InvalidState
        ));
    }

    #[test]
    fn coordinator_accounts_sender_and_snapshot_bytes_under_one_bound() {
        let mut coordinator = RemoteCoordinator::new(profile());
        let mut worker = RemoteWorker::new(WorkerId::new(1), profile());
        coordinator.add_worker(worker.id()).expect("worker");
        configure(&mut coordinator, &mut worker);
        for start in coordinator
            .start(17, 1, SampleSenderMode::Standard)
            .expect("start")
        {
            for response in worker.apply(start).expect("worker start") {
                coordinator.apply(response).expect("start ack");
            }
        }
        let sample = RemoteSample::new(17, worker.id(), 1, event("bounded"));
        let sample_bytes = RemoteCodec::default()
            .encoded_sample_len(
                sample_envelope_request_id(worker.id(), 1).expect("sample ID"),
                &sample,
            )
            .expect("sample size");
        coordinator
            .set_max_retained_bytes(sample_bytes.saturating_mul(2).saturating_sub(1))
            .expect("bound");
        assert!(matches!(
            coordinator.record_sample(sample),
            Err(error) if error.code == RemoteErrorCode::ResourceLimit
        ));
        assert!(coordinator.arrival_samples().is_empty());
    }

    #[test]
    fn context_deadline_and_cancellation_are_checked_without_a_clock_dependency() {
        let mut coordinator = RemoteCoordinator::new(profile());
        let mut worker = RemoteWorker::new(WorkerId::new(1), profile());
        coordinator.add_worker(worker.id()).expect("worker");
        configure(&mut coordinator, &mut worker);
        let deadline =
            RemoteRequestContext::new().with_deadline(crate::Deadline::at_unix_millis(10));
        assert!(matches!(
            coordinator.start_with_context(
                18,
                1,
                SampleSenderMode::Standard,
                deadline,
                10,
            ),
            Err(error) if error.code == RemoteErrorCode::DeadlineExceeded
        ));
        let cancelled =
            RemoteRequestContext::new().with_cancellation(crate::Cancellation::Requested);
        assert!(matches!(
            worker.apply_with_context(
                RemoteEnvelope::new(
                    100,
                    RemoteMessage::Profile { profile: profile() },
                ),
                cancelled,
                0,
            ),
            Err(error) if error.code == RemoteErrorCode::Cancelled
        ));
    }

    #[test]
    fn zero_run_generation_is_rejected_at_lifecycle_boundaries() {
        let mut coordinator = RemoteCoordinator::new(profile());
        let mut worker = RemoteWorker::new(WorkerId::new(1), profile());
        coordinator.add_worker(worker.id()).expect("worker");
        configure(&mut coordinator, &mut worker);
        assert!(matches!(
            coordinator.start(0, 1, SampleSenderMode::Standard),
            Err(error) if error.code == RemoteErrorCode::Protocol
        ));
        assert!(matches!(
            worker.apply(RemoteEnvelope::new(
                100,
                RemoteMessage::Start {
                    run_id: 0,
                    thread_count: 1,
                    sender_mode: SampleSenderMode::Standard,
                },
            )),
            Err(error) if error.code == RemoteErrorCode::Protocol
        ));
        assert!(matches!(
            coordinator.record_sample(RemoteSample::new(0, worker.id(), 0, event("invalid"))),
            Err(error) if error.code == RemoteErrorCode::Protocol
        ));
        assert_eq!(coordinator.phase(), CoordinatorPhase::Ready);
        assert_eq!(worker.phase(), WorkerPhase::Ready);
    }

    #[test]
    fn retry_attempts_are_finite_and_the_last_request_remains_pending() {
        let mut coordinator = RemoteCoordinator::new(profile());
        coordinator.set_retry_policy(RetryPolicy::new(2).expect("bounded policy"));
        coordinator.add_worker(WorkerId::new(1)).expect("worker");
        let messages = coordinator
            .configure(PlanDescriptor::new(b"plan".to_vec()), PropertySet::new())
            .expect("configure");
        let replacement = coordinator
            .retry_request(messages[0].request_id)
            .expect("one retry");
        assert!(matches!(
            coordinator.retry_request(replacement.request_id),
            Err(error) if error.code == RemoteErrorCode::ResourceLimit
        ));
        assert_eq!(coordinator.request_attempt(replacement.request_id), Some(2));
    }

    #[test]
    fn failed_worker_invalidates_all_pending_acks() {
        let mut coordinator = RemoteCoordinator::new(profile());
        let mut worker = RemoteWorker::new(WorkerId::new(1), profile());
        coordinator.add_worker(worker.id()).expect("worker");
        let messages = coordinator
            .configure(PlanDescriptor::new(b"plan".to_vec()), PropertySet::new())
            .expect("configure");
        let stale_ack = worker
            .apply(messages[0].clone())
            .expect("worker applies before failure")
            .into_iter()
            .next()
            .expect("profile ack");
        coordinator
            .worker_failed(
                worker.id(),
                RemoteError::new(RemoteErrorCode::WorkerFailure, false, "lost"),
            )
            .expect("failure");
        assert_eq!(coordinator.pending_request_count(), 0);
        assert!(matches!(
            coordinator.apply(stale_ack),
            Err(error) if error.code == RemoteErrorCode::Cancelled
        ));
        assert_eq!(
            coordinator.worker(worker.id()).expect("record").phase,
            WorkerPhase::Failed
        );
    }

    #[test]
    fn fail_fast_failure_emits_immediate_stops_for_healthy_workers() {
        let mut coordinator = RemoteCoordinator::new(profile());
        coordinator.set_failure_policy(FailurePolicy::FailFast);
        let mut first = RemoteWorker::new(WorkerId::new(1), profile());
        let mut second = RemoteWorker::new(WorkerId::new(2), profile());
        coordinator.add_worker(first.id()).expect("worker");
        coordinator.add_worker(second.id()).expect("worker");
        let mut properties = PropertySet::new();
        properties.insert("k", "v");
        let messages = coordinator
            .configure(PlanDescriptor::new(b"plan".to_vec()), properties)
            .expect("configure");
        for (index, message) in messages.into_iter().enumerate() {
            let target = if index < 3 { &mut first } else { &mut second };
            for response in target.apply(message).expect("worker apply") {
                coordinator.apply(response).expect("ack");
            }
        }
        coordinator
            .configuration_complete(first.id())
            .expect("first ready");
        coordinator
            .configuration_complete(second.id())
            .expect("second ready");
        let starts = coordinator
            .start(7, 1, SampleSenderMode::Standard)
            .expect("start");
        for (index, start) in starts.into_iter().enumerate() {
            let target = if index == 0 { &mut first } else { &mut second };
            for response in target.apply(start).expect("worker start") {
                coordinator.apply(response).expect("start ack");
            }
        }
        coordinator
            .worker_failed(
                first.id(),
                RemoteError::new(RemoteErrorCode::WorkerFailure, false, "failed"),
            )
            .expect("failure");
        let queued = coordinator.control_outbox.len();
        coordinator
            .worker_failed(
                first.id(),
                RemoteError::new(RemoteErrorCode::WorkerFailure, false, "duplicate failure"),
            )
            .expect("duplicate failure is idempotent");
        assert_eq!(coordinator.control_outbox.len(), queued);
        let controls = coordinator.drain_control_messages();
        assert!(controls.iter().any(|message| {
            matches!(
                message.message,
                RemoteMessage::Stop {
                    mode: StopMode::Immediate,
                    ..
                }
            )
        }));
    }

    #[test]
    fn fail_fast_outbox_capacity_preflight_preserves_failure_state() {
        let mut coordinator = RemoteCoordinator::new(profile());
        coordinator.set_failure_policy(FailurePolicy::FailFast);
        coordinator
            .set_configuration_limits(RemoteConfigurationLimits::new().with_max_control_events(1))
            .expect("limits");
        let mut failed = RemoteWorker::new(WorkerId::new(1), profile());
        let mut healthy = RemoteWorker::new(WorkerId::new(2), profile());
        coordinator.add_worker(failed.id()).expect("worker");
        coordinator.add_worker(healthy.id()).expect("worker");
        let messages = coordinator
            .configure(PlanDescriptor::new(b"plan".to_vec()), PropertySet::new())
            .expect("configure");
        for (index, message) in messages.into_iter().enumerate() {
            let target = if index < 3 { &mut failed } else { &mut healthy };
            for response in target.apply(message).expect("worker apply") {
                coordinator.apply(response).expect("ack");
            }
        }
        coordinator
            .configuration_complete(failed.id())
            .expect("failed ready");
        coordinator
            .configuration_complete(healthy.id())
            .expect("healthy ready");
        for (index, start) in coordinator
            .start(21, 1, SampleSenderMode::Standard)
            .expect("start")
            .into_iter()
            .enumerate()
        {
            let target = if index == 0 {
                &mut failed
            } else {
                &mut healthy
            };
            for response in target.apply(start).expect("worker start") {
                coordinator.apply(response).expect("start ack");
            }
        }

        // Simulate one already queued control event. The next fail-fast stop
        // batch would exceed the configured bound and must fail before the
        // worker/request state changes.
        coordinator.control_outbox.push(RemoteEnvelope::new(
            900,
            RemoteMessage::Stop {
                run_id: 21,
                mode: StopMode::Immediate,
            },
        ));
        let pending_before = coordinator.pending_request_count();
        let error = coordinator
            .worker_failed(
                failed.id(),
                RemoteError::new(RemoteErrorCode::WorkerFailure, false, "failed"),
            )
            .expect_err("full control outbox must reject fail-fast transition");
        assert_eq!(error.code, RemoteErrorCode::ResourceLimit);
        assert_eq!(coordinator.control_outbox.len(), 1);
        assert_eq!(coordinator.pending_request_count(), pending_before);
        assert_eq!(
            coordinator.worker(failed.id()).expect("worker").phase,
            WorkerPhase::Running
        );
        assert_eq!(coordinator.phase(), CoordinatorPhase::Running);
    }

    #[test]
    fn later_fail_fast_failure_keeps_other_stop_ack_pending() {
        let mut coordinator = RemoteCoordinator::new(profile());
        coordinator.set_failure_policy(FailurePolicy::FailFast);
        let mut first = RemoteWorker::new(WorkerId::new(1), profile());
        let mut second = RemoteWorker::new(WorkerId::new(2), profile());
        let mut third = RemoteWorker::new(WorkerId::new(3), profile());
        coordinator.add_worker(first.id()).expect("worker");
        coordinator.add_worker(second.id()).expect("worker");
        coordinator.add_worker(third.id()).expect("worker");
        let messages = coordinator
            .configure(PlanDescriptor::new(b"plan".to_vec()), PropertySet::new())
            .expect("configure");
        for (index, message) in messages.into_iter().enumerate() {
            let target = match index / 3 {
                0 => &mut first,
                1 => &mut second,
                _ => &mut third,
            };
            for response in target.apply(message).expect("worker apply") {
                coordinator.apply(response).expect("ack");
            }
        }
        for worker in [first.id(), second.id(), third.id()] {
            coordinator.configuration_complete(worker).expect("ready");
        }
        let starts = coordinator
            .start(23, 1, SampleSenderMode::Standard)
            .expect("start");
        for (index, start) in starts.into_iter().enumerate() {
            let target = match index {
                0 => &mut first,
                1 => &mut second,
                _ => &mut third,
            };
            for response in target.apply(start).expect("worker start") {
                coordinator.apply(response).expect("start ack");
            }
        }
        coordinator
            .worker_failed(
                first.id(),
                RemoteError::new(RemoteErrorCode::WorkerFailure, false, "first failed"),
            )
            .expect("first failure");
        assert_eq!(coordinator.pending_request_count(), 2);
        let controls = coordinator.drain_control_messages();
        assert_eq!(controls.len(), 2);

        coordinator
            .worker_failed(
                second.id(),
                RemoteError::new(RemoteErrorCode::WorkerFailure, false, "second failed"),
            )
            .expect("second failure");
        assert_eq!(coordinator.pending_request_count(), 1);
        assert_eq!(coordinator.phase(), CoordinatorPhase::Stopping);

        // The second stop was invalidated with the failed worker; the third
        // worker's original stop remains the only valid pending acknowledgement.
        for response in third.apply(controls[1].clone()).expect("third stop") {
            coordinator.apply(response).expect("third stop ack");
        }
        assert_eq!(coordinator.phase(), CoordinatorPhase::Failed);
    }

    #[test]
    fn ready_worker_resources_are_immutable_and_start_rechecks_capabilities() {
        let mut worker = RemoteWorker::new(WorkerId::new(1), profile());
        let mut resources = WorkerResources::new();
        resources
            .add_data_reference("worker.csv", "csv")
            .expect("data path");
        resources.add_dependency("driver", "1").expect("dependency");
        worker.set_resources(resources).expect("resources");
        worker
            .apply(RemoteEnvelope::new(
                1,
                RemoteMessage::Profile { profile: profile() },
            ))
            .expect("profile");
        let plan = PlanDescriptor::new(b"plan".to_vec()).with_references(
            vec![crate::protocol::DataReference::new("worker.csv", "csv")],
            vec![crate::protocol::DependencyReference::new("driver", "1")],
        );
        worker
            .apply(RemoteEnvelope::new(
                2,
                RemoteMessage::Plan { plan: plan.clone() },
            ))
            .expect("plan");
        worker
            .apply(RemoteEnvelope::new(
                3,
                RemoteMessage::Properties {
                    properties: PropertySet::new(),
                },
            ))
            .expect("properties");
        assert_eq!(worker.phase(), WorkerPhase::Ready);
        assert!(matches!(
            worker.set_resources(WorkerResources::new()),
            Err(error) if error.code == RemoteErrorCode::InvalidState
        ));
        assert!(matches!(
            worker.set_configuration_limits(RemoteConfigurationLimits::new()),
            Err(error) if error.code == RemoteErrorCode::InvalidState
        ));

        // Exercise the start boundary independently of the public setter: an
        // internal capability provider cannot bypass the final revalidation.
        worker.resources = WorkerResources::new();
        let error = worker
            .apply(RemoteEnvelope::new(
                4,
                RemoteMessage::Start {
                    run_id: 22,
                    thread_count: 1,
                    sender_mode: SampleSenderMode::Standard,
                },
            ))
            .expect_err("missing plan resources must reject start");
        assert_eq!(error.code, RemoteErrorCode::CapabilityUnavailable);
        assert_eq!(worker.phase(), WorkerPhase::Ready);
        assert_eq!(worker.run_id(), None);
        assert_eq!(worker.plan(), Some(&plan));
    }

    #[test]
    fn fail_fast_starting_failure_stops_ready_workers_before_stale_start() {
        let mut coordinator = RemoteCoordinator::new(profile());
        coordinator.set_failure_policy(FailurePolicy::FailFast);
        let mut failed = RemoteWorker::new(WorkerId::new(1), profile());
        let mut healthy = RemoteWorker::new(WorkerId::new(2), profile());
        coordinator.add_worker(failed.id()).expect("worker");
        coordinator.add_worker(healthy.id()).expect("worker");
        let mut properties = PropertySet::new();
        properties.insert("k", "v");
        let messages = coordinator
            .configure(PlanDescriptor::new(b"plan".to_vec()), properties)
            .expect("configure");
        for (index, message) in messages.into_iter().enumerate() {
            let target = if index < 3 { &mut failed } else { &mut healthy };
            for response in target.apply(message).expect("worker apply") {
                coordinator.apply(response).expect("ack");
            }
        }
        coordinator
            .configuration_complete(failed.id())
            .expect("failed ready");
        coordinator
            .configuration_complete(healthy.id())
            .expect("healthy ready");
        let starts = coordinator
            .start(8, 2, SampleSenderMode::Standard)
            .expect("start");
        let stale_start = starts.get(1).cloned().expect("healthy start request");
        coordinator
            .worker_failed(
                failed.id(),
                RemoteError::new(RemoteErrorCode::WorkerFailure, false, "failed"),
            )
            .expect("failure");
        let controls = coordinator.drain_control_messages();
        let stop = controls
            .iter()
            .find(|message| {
                matches!(
                    message.message,
                    RemoteMessage::Stop {
                        mode: StopMode::Immediate,
                        ..
                    }
                )
            })
            .cloned()
            .expect("healthy stop");
        assert_eq!(healthy.phase(), WorkerPhase::Ready);
        for response in healthy.apply(stop).expect("stop ready worker") {
            coordinator.apply(response).expect("stop acknowledgement");
        }
        assert_eq!(coordinator.phase(), CoordinatorPhase::Failed);
        assert!(matches!(
            healthy.apply(stale_start),
            Err(error) if error.code == RemoteErrorCode::InvalidState
        ));
    }

    #[test]
    fn ready_worker_rejects_differing_delayed_plan_and_properties() {
        let mut worker = RemoteWorker::new(WorkerId::new(1), profile());
        worker
            .apply(RemoteEnvelope::new(
                1,
                RemoteMessage::Profile { profile: profile() },
            ))
            .expect("profile");
        worker
            .apply(RemoteEnvelope::new(
                2,
                RemoteMessage::Plan {
                    plan: PlanDescriptor::new(b"current-plan".to_vec()),
                },
            ))
            .expect("plan");
        let mut current = PropertySet::new();
        current.insert("current", "value");
        worker
            .apply(RemoteEnvelope::new(
                3,
                RemoteMessage::Properties {
                    properties: current.clone(),
                },
            ))
            .expect("properties");
        assert_eq!(worker.phase(), WorkerPhase::Ready);

        let delayed_plan = worker.apply(RemoteEnvelope::new(
            4,
            RemoteMessage::Plan {
                plan: PlanDescriptor::new(b"stale-plan".to_vec()),
            },
        ));
        assert!(matches!(
            delayed_plan,
            Err(error) if error.code == RemoteErrorCode::InvalidState
        ));
        let mut stale = PropertySet::new();
        stale.insert("stale", "value");
        let delayed_properties = worker.apply(RemoteEnvelope::new(
            5,
            RemoteMessage::Properties { properties: stale },
        ));
        assert!(matches!(
            delayed_properties,
            Err(error) if error.code == RemoteErrorCode::InvalidState
        ));
        assert_eq!(worker.plan().expect("plan").jmx(), b"current-plan");
        assert_eq!(worker.properties(), Some(&current));
    }

    #[test]
    fn configuration_and_resource_bounds_apply_before_retention() {
        let limits = RemoteConfigurationLimits::new()
            .with_max_workers(1)
            .with_max_plan_bytes(4)
            .with_max_property_bytes(4)
            .with_max_configuration_bytes(4)
            .with_max_resource_entries(1)
            .with_max_resource_bytes(3);
        let mut coordinator = RemoteCoordinator::new(profile());
        coordinator
            .set_configuration_limits(limits)
            .expect("valid limits");
        coordinator
            .add_worker(WorkerId::new(1))
            .expect("first worker");
        assert!(matches!(
            coordinator.add_worker(WorkerId::new(2)),
            Err(error) if error.code == RemoteErrorCode::ResourceLimit
        ));
        assert!(matches!(
            coordinator.configure(PlanDescriptor::new(b"too-large".to_vec()), PropertySet::new()),
            Err(error) if error.code == RemoteErrorCode::ResourceLimit
        ));
        let mut properties = PropertySet::new();
        properties.insert("k", "v");
        assert!(matches!(
            coordinator.configure(PlanDescriptor::new(b"123".to_vec()), properties),
            Err(error) if error.code == RemoteErrorCode::ResourceLimit
        ));

        let mut resources = WorkerResources::with_limits(limits).expect("resource limits");
        resources.add_data_path("abc").expect("first resource");
        assert!(matches!(
            resources.add_data_path("d"),
            Err(error) if error.code == RemoteErrorCode::ResourceLimit
        ));
    }

    #[test]
    fn worker_and_coordinator_debug_do_not_expose_configuration() {
        let secret = "state-secret";
        let mut worker = RemoteWorker::new(WorkerId::new(1), profile());
        worker
            .apply(RemoteEnvelope::new(
                1,
                RemoteMessage::Profile { profile: profile() },
            ))
            .expect("profile");
        worker
            .apply(RemoteEnvelope::new(
                2,
                RemoteMessage::Plan {
                    plan: PlanDescriptor::new(secret.as_bytes().to_vec()),
                },
            ))
            .expect("plan");
        let mut properties = PropertySet::new();
        properties.insert("password", secret);
        worker
            .apply(RemoteEnvelope::new(
                3,
                RemoteMessage::Properties { properties },
            ))
            .expect("properties");
        let worker_debug = format!("{worker:?}");
        assert!(!worker_debug.contains(secret));
        assert!(worker_debug.len() < 2048);

        let mut coordinator = RemoteCoordinator::new(profile());
        coordinator.add_worker(worker.id()).expect("worker");
        coordinator
            .configure(
                PlanDescriptor::new(secret.as_bytes().to_vec()),
                PropertySet::new(),
            )
            .expect("configuration");
        let coordinator_debug = format!("{coordinator:?}");
        assert!(!coordinator_debug.contains(secret));
        assert!(coordinator_debug.len() < 2048);
    }

    #[test]
    fn coordinator_rejects_worker_addition_after_configuration_begins() {
        let mut coordinator = RemoteCoordinator::new(profile());
        coordinator.add_worker(WorkerId::new(1)).expect("worker");
        coordinator
            .configure(PlanDescriptor::new(b"plan".to_vec()), PropertySet::new())
            .expect("configure");
        assert!(matches!(
            coordinator.add_worker(WorkerId::new(2)),
            Err(error) if error.code == RemoteErrorCode::InvalidState
        ));
    }

    #[test]
    fn unsupported_sender_modes_fail_before_coordinator_or_worker_running() {
        let mut coordinator = RemoteCoordinator::new(profile());
        let mut worker = RemoteWorker::new(WorkerId::new(1), profile());
        coordinator.add_worker(worker.id()).expect("worker");
        configure(&mut coordinator, &mut worker);
        for mode in [
            SampleSenderMode::Statistical { size: 2 },
            SampleSenderMode::Asynch { capacity: 2 },
            SampleSenderMode::StrippedAsynch { capacity: 2 },
            SampleSenderMode::DiskStore { capacity: 2 },
            SampleSenderMode::StrippedDiskStore { capacity: 2 },
        ] {
            assert!(matches!(
                coordinator.start(9, 1, mode),
                Err(error) if error.code == RemoteErrorCode::CapabilityUnavailable
            ));
            assert_eq!(coordinator.phase(), CoordinatorPhase::Ready);
            assert!(matches!(
                worker.apply(RemoteEnvelope::new(
                    99,
                    RemoteMessage::Start {
                        run_id: 9,
                        thread_count: 1,
                        sender_mode: mode,
                    },
                )),
                Err(error) if error.code == RemoteErrorCode::CapabilityUnavailable
            ));
            assert_eq!(worker.phase(), WorkerPhase::Ready);
        }
    }

    #[test]
    fn stale_failure_generation_is_rejected_without_mutating_terminal_state() {
        let mut coordinator = RemoteCoordinator::new(profile());
        let mut worker = RemoteWorker::new(WorkerId::new(1), profile());
        coordinator.add_worker(worker.id()).expect("worker");
        configure(&mut coordinator, &mut worker);
        for start in coordinator
            .start(11, 1, SampleSenderMode::Standard)
            .expect("start")
        {
            for response in worker.apply(start).expect("worker start") {
                coordinator.apply(response).expect("start ack");
            }
        }
        assert!(matches!(
            coordinator.apply(RemoteEnvelope::new(
                900,
                RemoteMessage::Failure {
                    worker: worker.id(),
                    run_id: Some(10),
                    error: RemoteError::new(RemoteErrorCode::WorkerFailure, false, "stale"),
                },
            )),
            Err(error) if error.code == RemoteErrorCode::Cancelled
        ));
        assert_eq!(coordinator.phase(), CoordinatorPhase::Running);
        assert_eq!(
            coordinator.worker(worker.id()).expect("record").phase,
            WorkerPhase::Running
        );
    }

    #[test]
    fn failure_after_one_worker_stops_cannot_reopen_that_worker() {
        let mut coordinator = RemoteCoordinator::new(profile());
        let mut first = RemoteWorker::new(WorkerId::new(1), profile());
        let mut second = RemoteWorker::new(WorkerId::new(2), profile());
        coordinator.add_worker(first.id()).expect("worker");
        coordinator.add_worker(second.id()).expect("worker");
        let messages = coordinator
            .configure(PlanDescriptor::new(b"plan".to_vec()), PropertySet::new())
            .expect("configure");
        for (index, message) in messages.into_iter().enumerate() {
            let target = if index < 3 { &mut first } else { &mut second };
            for response in target.apply(message).expect("worker apply") {
                coordinator.apply(response).expect("configuration ack");
            }
        }
        coordinator
            .configuration_complete(first.id())
            .expect("first ready");
        coordinator
            .configuration_complete(second.id())
            .expect("second ready");
        let starts = coordinator
            .start(14, 1, SampleSenderMode::Standard)
            .expect("start");
        for (index, start) in starts.into_iter().enumerate() {
            let target = if index == 0 { &mut first } else { &mut second };
            for response in target.apply(start).expect("worker start") {
                coordinator.apply(response).expect("start ack");
            }
        }
        let stops = coordinator.stop(StopMode::Graceful).expect("stop");
        let first_responses = first.apply(stops[0].clone()).expect("first stop");
        for response in first_responses {
            coordinator.apply(response).expect("first stop response");
        }
        assert_eq!(
            coordinator.worker(first.id()).expect("first record").phase,
            WorkerPhase::Stopped
        );
        assert_eq!(coordinator.phase(), CoordinatorPhase::Stopping);
        assert!(matches!(
            coordinator.worker_failed_for_run(
                first.id(),
                14,
                RemoteError::new(RemoteErrorCode::WorkerFailure, false, "late"),
            ),
            Err(error) if error.code == RemoteErrorCode::Cancelled
        ));
        assert_eq!(coordinator.phase(), CoordinatorPhase::Stopping);
    }

    #[test]
    fn graceful_stop_watermark_waits_for_reordered_samples() {
        let mut coordinator = RemoteCoordinator::new(profile());
        let mut worker = RemoteWorker::new(WorkerId::new(1), profile());
        coordinator.add_worker(worker.id()).expect("worker");
        configure(&mut coordinator, &mut worker);
        for start in coordinator
            .start(12, 1, SampleSenderMode::Standard)
            .expect("start")
        {
            for response in worker.apply(start).expect("worker start") {
                coordinator.apply(response).expect("start ack");
            }
        }
        let sample = worker
            .emit_sample(event("late-arrival"))
            .expect("sample")
            .into_iter()
            .next()
            .expect("sample envelope");
        let stop = coordinator.stop(StopMode::Graceful).expect("stop");
        let responses = worker.apply(stop[0].clone()).expect("worker stop");
        let ack = responses
            .iter()
            .find(|response| matches!(response.message, RemoteMessage::Ack { .. }))
            .cloned()
            .expect("stop ack");
        coordinator.apply(ack).expect("watermark ack");
        assert_eq!(coordinator.phase(), CoordinatorPhase::Stopping);
        coordinator.apply(sample).expect("reordered sample");
        assert_eq!(coordinator.phase(), CoordinatorPhase::Stopped);
        assert_eq!(coordinator.arrival_samples().len(), 1);
        assert!(matches!(
            coordinator.worker_failed_for_run(
                worker.id(),
                12,
                RemoteError::new(RemoteErrorCode::WorkerFailure, false, "late"),
            ),
            Err(error) if error.code == RemoteErrorCode::Cancelled
        ));
        assert_eq!(coordinator.phase(), CoordinatorPhase::Stopped);
    }

    #[test]
    fn graceful_stop_is_permutation_safe_and_duplicate_idempotent() {
        let mut coordinator = RemoteCoordinator::new(profile());
        let mut worker = RemoteWorker::new(WorkerId::new(1), profile());
        coordinator.add_worker(worker.id()).expect("worker");
        configure(&mut coordinator, &mut worker);
        for start in coordinator
            .start(13, 1, SampleSenderMode::Standard)
            .expect("start")
        {
            for response in worker.apply(start).expect("worker start") {
                coordinator.apply(response).expect("start ack");
            }
        }
        let samples = (0..3)
            .flat_map(|index| {
                worker
                    .emit_sample(event(&format!("sample-{index}")))
                    .expect("sample")
            })
            .collect::<Vec<_>>();
        assert_eq!(samples.len(), 3);

        let stop = coordinator.stop(StopMode::Graceful).expect("stop");
        let responses = worker.apply(stop[0].clone()).expect("worker stop");
        let ack = responses
            .into_iter()
            .find(|response| matches!(response.message, RemoteMessage::Ack { .. }))
            .expect("stop ack");
        coordinator.apply(ack).expect("watermark ack");
        assert_eq!(coordinator.phase(), CoordinatorPhase::Stopping);

        // Reverse arrival order, then replay one accepted sample before the
        // final missing sequence arrives. The watermark is satisfied only by
        // the complete prefix 0..3, while the replay remains a no-op.
        assert!(matches!(
            coordinator.apply(samples[2].clone()),
            Ok(Some(RecordOutcome::Accepted(SendOutcome::Delivered)))
        ));
        assert!(matches!(
            coordinator.apply(samples[1].clone()),
            Ok(Some(RecordOutcome::Accepted(SendOutcome::Delivered)))
        ));
        assert!(matches!(
            coordinator.apply(samples[1].clone()),
            Ok(Some(RecordOutcome::Duplicate))
        ));
        assert_eq!(coordinator.phase(), CoordinatorPhase::Stopping);
        assert!(matches!(
            coordinator.apply(samples[0].clone()),
            Ok(Some(RecordOutcome::Accepted(SendOutcome::Delivered)))
        ));
        assert_eq!(coordinator.phase(), CoordinatorPhase::Stopped);
    }

    #[test]
    fn data_reference_kind_is_part_of_worker_capability_identity() {
        let mut resources = WorkerResources::new();
        resources
            .add_data_reference("worker.csv", "csv")
            .expect("resource");
        let mut worker = RemoteWorker::new(WorkerId::new(1), profile());
        worker.set_resources(resources).expect("resources");
        worker
            .apply(RemoteEnvelope::new(
                1,
                RemoteMessage::Profile { profile: profile() },
            ))
            .expect("profile");
        let plan = PlanDescriptor::new(b"plan".to_vec()).with_references(
            vec![crate::protocol::DataReference::new("worker.csv", "script")],
            Vec::new(),
        );
        assert!(matches!(
            worker.apply(RemoteEnvelope::new(2, RemoteMessage::Plan { plan })),
            Err(error) if error.code == RemoteErrorCode::CapabilityUnavailable
        ));
    }
}
