// SPDX-License-Identifier: Apache-2.0
//! Bounded run observation and constant-memory summaries.
//!
//! Observation is deliberately separate from result routing.  The router
//! owns delivery and durability of immutable result envelopes; this module
//! owns the diagnostic view of the lifecycle.  Summary mode never constructs
//! an [`EngineEvent`] for a sample, so a production run does not clone a
//! `SampleResult` merely to count it.

use std::fmt;
use std::mem::size_of;
use std::num::NonZeroUsize;
use std::sync::Arc;

use jmeter_rs_results::{HostIdentity, SampleEvent, SampleResult, ThreadIdentity};

use crate::lifecycle::EngineEvent;
use crate::{ControlSignal, SampleFailure};

/// The version-one observation policy.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum RunObservationPolicyV1 {
    /// Keep checked aggregate counters and no ordered event payloads.
    #[default]
    Summary,
    /// Keep an ordered trace under both finite count and byte limits.
    FullTrace {
        /// Maximum number of retained lifecycle events.
        max_events: NonZeroUsize,
        /// Maximum conservative retained bytes.
        max_bytes: NonZeroUsize,
    },
}

impl RunObservationPolicyV1 {
    /// Creates a finite full-trace policy from checked limits.
    #[must_use]
    pub const fn full_trace(max_events: NonZeroUsize, max_bytes: NonZeroUsize) -> Self {
        Self::FullTrace {
            max_events,
            max_bytes,
        }
    }

    /// Returns whether this policy retains ordered events.
    #[must_use]
    pub const fn retains_trace(self) -> bool {
        matches!(self, Self::FullTrace { .. })
    }

    /// Returns the configured event limit, if this is a full trace.
    #[must_use]
    pub const fn max_events(self) -> Option<NonZeroUsize> {
        match self {
            Self::Summary => None,
            Self::FullTrace { max_events, .. } => Some(max_events),
        }
    }

    /// Returns the configured byte limit, if this is a full trace.
    #[must_use]
    pub const fn max_bytes(self) -> Option<NonZeroUsize> {
        match self {
            Self::Summary => None,
            Self::FullTrace { max_bytes, .. } => Some(max_bytes),
        }
    }
}

/// Terminal state retained by a run summary.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum RunObservationTerminalState {
    /// No run has started for this engine generation.
    #[default]
    NotStarted,
    /// A run is currently emitting lifecycle observations.
    Running,
    /// The run reached its normal terminal boundary.
    Completed,
    /// The run failed at the engine or observation boundary.
    Failed,
    /// The returned run future was dropped or cancellation unwound it.
    CancelledDropped,
}

/// Stable errors raised by the observation resource boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObservationError {
    /// A second run was started before the current run reached a terminal
    /// state.
    AlreadyRunning,
    /// An event was emitted outside the running state.
    NotRunning {
        /// Current terminal state.
        state: RunObservationTerminalState,
    },
    /// A checked summary counter could not be incremented.
    CounterOverflow {
        /// Stable counter identifier.
        counter: &'static str,
    },
    /// The full trace reached its event-count limit.
    EventLimitExceeded {
        /// Count after the rejected event would have been admitted.
        actual: usize,
        /// Configured finite maximum.
        maximum: usize,
    },
    /// The full trace reached its conservative byte limit.
    ByteLimitExceeded {
        /// Bytes after the rejected event would have been admitted.
        actual: usize,
        /// Configured finite maximum.
        maximum: usize,
    },
    /// Retained-byte arithmetic overflowed.
    ByteOverflow,
    /// The trace vector could not reserve one bounded event slot.
    AllocationFailure,
}

impl ObservationError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::AlreadyRunning => "runtime.observation.already-running",
            Self::NotRunning { .. } => "runtime.observation.not-running",
            Self::CounterOverflow { .. } => "runtime.observation.counter-overflow",
            Self::EventLimitExceeded { .. } => "runtime.observation.event-limit",
            Self::ByteLimitExceeded { .. } => "runtime.observation.byte-limit",
            Self::ByteOverflow => "runtime.observation.byte-overflow",
            Self::AllocationFailure => "runtime.observation.allocation",
        }
    }
}

impl fmt::Display for ObservationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyRunning | Self::ByteOverflow | Self::AllocationFailure => {
                formatter.write_str(self.code())
            }
            Self::NotRunning { state } => write!(formatter, "{}: state={state:?}", self.code()),
            Self::CounterOverflow { counter } => {
                write!(formatter, "{}: counter={counter}", self.code())
            }
            Self::EventLimitExceeded { actual, maximum }
            | Self::ByteLimitExceeded { actual, maximum } => {
                write!(formatter, "{}: {actual} exceeds {maximum}", self.code())
            }
        }
    }
}

impl std::error::Error for ObservationError {}

/// Checked, fixed-size counters for one run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunObservationSummaryV1 {
    /// All lifecycle and sample observation events.
    pub total_events: u64,
    /// Sample observation events, including null-result events.
    pub sample_events: u64,
    /// Sample events carrying an owned `SampleResult`.
    pub materialized_samples: u64,
    /// Sample events whose result was absent.
    pub null_result_samples: u64,
    /// Materialized samples whose success was exactly `Some(true)`.
    pub successful_samples: u64,
    /// Materialized samples whose success was exactly `Some(false)`.
    pub failed_samples: u64,
    /// Materialized samples whose success field was absent.
    pub unknown_success_samples: u64,
    /// Explicit sampler failures, independent of result success.
    pub explicit_sample_failures: u64,
    /// Test-start lifecycle events.
    pub test_started: u64,
    /// Mode-start lifecycle events.
    pub mode_started: u64,
    /// Group-start lifecycle events.
    pub groups_started: u64,
    /// Virtual users started.
    pub users_started: u64,
    /// Root iterations completed.
    pub iterations: u64,
    /// Virtual users finished.
    pub users_finished: u64,
    /// Group-finish lifecycle events.
    pub groups_finished: u64,
    /// Test-finish lifecycle events.
    pub test_finished: u64,
    /// Materialized samples emitted by transaction controllers.
    pub transaction_samples: u64,
    /// Highest control signal observed in the run.
    pub highest_control_signal: ControlSignal,
    /// Terminal lifecycle state.
    pub terminal_state: RunObservationTerminalState,
}

impl Default for RunObservationSummaryV1 {
    fn default() -> Self {
        Self {
            total_events: 0,
            sample_events: 0,
            materialized_samples: 0,
            null_result_samples: 0,
            successful_samples: 0,
            failed_samples: 0,
            unknown_success_samples: 0,
            explicit_sample_failures: 0,
            test_started: 0,
            mode_started: 0,
            groups_started: 0,
            users_started: 0,
            iterations: 0,
            users_finished: 0,
            groups_finished: 0,
            test_finished: 0,
            transaction_samples: 0,
            highest_control_signal: ControlSignal::Continue,
            terminal_state: RunObservationTerminalState::NotStarted,
        }
    }
}

impl RunObservationSummaryV1 {
    /// Returns the application-compatible count of materialized samples.
    #[must_use]
    pub const fn samples(&self) -> u64 {
        self.materialized_samples
    }

    /// Returns the application-compatible count of failed materialized
    /// samples.  An explicit failure without a result is not included.
    #[must_use]
    pub const fn sample_failures(&self) -> u64 {
        self.failed_samples
    }
}

fn checked_increment(value: &mut u64, counter: &'static str) -> Result<(), ObservationError> {
    *value = value
        .checked_add(1)
        .ok_or(ObservationError::CounterOverflow { counter })?;
    Ok(())
}

fn update_summary_event(
    summary: &mut RunObservationSummaryV1,
    event: &EngineEvent,
) -> Result<(), ObservationError> {
    checked_increment(&mut summary.total_events, "total_events")?;
    match event {
        EngineEvent::TestStarted => checked_increment(&mut summary.test_started, "test_started")?,
        EngineEvent::ModeStarted(_) => {
            checked_increment(&mut summary.mode_started, "mode_started")?
        }
        EngineEvent::GroupStarted { .. } => {
            checked_increment(&mut summary.groups_started, "groups_started")?
        }
        EngineEvent::UserStarted { .. } => {
            checked_increment(&mut summary.users_started, "users_started")?
        }
        EngineEvent::Sample { .. } => {
            // The full event path is only used after the summary update has
            // been checked.  Sample-specific counters are applied by
            // `update_summary_sample` so Summary mode can borrow the result.
            checked_increment(&mut summary.sample_events, "sample_events")?
        }
        EngineEvent::Iteration { .. } => checked_increment(&mut summary.iterations, "iterations")?,
        EngineEvent::UserFinished { .. } => {
            checked_increment(&mut summary.users_finished, "users_finished")?
        }
        EngineEvent::GroupFinished { .. } => {
            checked_increment(&mut summary.groups_finished, "groups_finished")?
        }
        EngineEvent::TestFinished { signal } => {
            checked_increment(&mut summary.test_finished, "test_finished")?;
            summary.highest_control_signal = summary.highest_control_signal.combine(*signal);
        }
    }
    Ok(())
}

fn update_summary_sample(
    summary: &mut RunObservationSummaryV1,
    result: Option<&SampleResult>,
    failure: Option<&SampleFailure>,
    signal: ControlSignal,
    transaction: bool,
) -> Result<(), ObservationError> {
    // `sample_events` is incremented here for the borrowed sample path and
    // not by `update_summary_event`.
    checked_increment(&mut summary.total_events, "total_events")?;
    checked_increment(&mut summary.sample_events, "sample_events")?;
    summary.highest_control_signal = summary.highest_control_signal.combine(signal);
    if let Some(result) = result {
        checked_increment(&mut summary.materialized_samples, "materialized_samples")?;
        match result.success() {
            Some(true) => checked_increment(&mut summary.successful_samples, "successful_samples")?,
            Some(false) => checked_increment(&mut summary.failed_samples, "failed_samples")?,
            None => checked_increment(
                &mut summary.unknown_success_samples,
                "unknown_success_samples",
            )?,
        }
        if transaction {
            checked_increment(&mut summary.transaction_samples, "transaction_samples")?;
        }
    } else {
        checked_increment(&mut summary.null_result_samples, "null_result_samples")?;
    }
    if failure.is_some() {
        checked_increment(
            &mut summary.explicit_sample_failures,
            "explicit_sample_failures",
        )?;
    }
    Ok(())
}

fn estimate_result_bytes(result: &SampleResult) -> Result<usize, ObservationError> {
    // `SampleEvent::estimated_bytes` traverses every public and retained JTL
    // extension field, including nested results.  The temporary event is
    // constructed only in FullTrace mode; Summary mode never clones this
    // payload.
    let event = SampleEvent::new(
        result.clone(),
        RunIdentityForObservation::run(),
        ThreadIdentityForObservation::thread(),
        HostIdentityForObservation::host(),
        jmeter_rs_results::VariableSnapshot::new(),
    );
    let bytes = event.estimated_bytes();
    if bytes == usize::MAX {
        Err(ObservationError::ByteOverflow)
    } else {
        Ok(bytes)
    }
}

// These tiny wrappers keep the estimator's diagnostic identities fixed and
// avoid allocating a new temporary String at every call site.  The event
// constructor still owns the values, so the estimate remains conservative.
struct RunIdentityForObservation;
impl RunIdentityForObservation {
    fn run() -> jmeter_rs_results::RunIdentity {
        jmeter_rs_results::RunIdentity::new("observation")
    }
}
struct ThreadIdentityForObservation;
impl ThreadIdentityForObservation {
    fn thread() -> ThreadIdentity {
        ThreadIdentity::new("observation")
    }
}
struct HostIdentityForObservation;
impl HostIdentityForObservation {
    fn host() -> HostIdentity {
        HostIdentity::new("observation")
    }
}

fn estimate_event_bytes(event: &EngineEvent) -> Result<usize, ObservationError> {
    let mut bytes = size_of::<EngineEvent>();
    if let EngineEvent::Sample {
        result, failure, ..
    } = event
    {
        if let Some(result) = result {
            bytes = bytes
                .checked_add(estimate_result_bytes(result)?)
                .ok_or(ObservationError::ByteOverflow)?;
        }
        if let Some(failure) = failure {
            bytes = bytes
                .checked_add(size_of::<SampleFailure>())
                .and_then(|value| value.checked_add(failure.message.len()))
                .ok_or(ObservationError::ByteOverflow)?;
            if let Some(result) = failure.result.as_ref() {
                bytes = bytes
                    .checked_add(estimate_result_bytes(result)?)
                    .ok_or(ObservationError::ByteOverflow)?;
            }
        }
    }
    Ok(bytes)
}

/// A run-owned mutable observation state.  Runtime scheduler clones share the
/// same instance through an `Arc<Mutex<_>>`.
#[derive(Debug)]
pub(crate) struct ObservationState {
    policy: RunObservationPolicyV1,
    summary: RunObservationSummaryV1,
    trace: Vec<EngineEvent>,
    retained_bytes: usize,
    frozen_trace: Arc<[EngineEvent]>,
}

impl ObservationState {
    pub(crate) fn new(policy: RunObservationPolicyV1) -> Self {
        Self {
            policy,
            summary: RunObservationSummaryV1::default(),
            trace: Vec::new(),
            retained_bytes: 0,
            frozen_trace: Arc::from(Vec::<EngineEvent>::new().into_boxed_slice()),
        }
    }

    pub(crate) fn policy(&self) -> RunObservationPolicyV1 {
        self.policy
    }

    pub(crate) fn set_policy(
        &mut self,
        policy: RunObservationPolicyV1,
    ) -> Result<(), ObservationError> {
        if self.summary.terminal_state == RunObservationTerminalState::Running {
            return Err(ObservationError::AlreadyRunning);
        }
        self.policy = policy;
        Ok(())
    }

    pub(crate) fn begin_run(&mut self) -> Result<(), ObservationError> {
        if self.summary.terminal_state == RunObservationTerminalState::Running {
            return Err(ObservationError::AlreadyRunning);
        }
        self.summary = RunObservationSummaryV1 {
            terminal_state: RunObservationTerminalState::Running,
            ..RunObservationSummaryV1::default()
        };
        self.trace.clear();
        self.retained_bytes = 0;
        self.frozen_trace = Arc::from(Vec::<EngineEvent>::new().into_boxed_slice());
        Ok(())
    }

    pub(crate) fn record_event(&mut self, event: EngineEvent) -> Result<(), ObservationError> {
        self.ensure_running()?;
        let mut next = self.summary.clone();
        update_summary_event(&mut next, &event)?;
        if let EngineEvent::Sample {
            result,
            failure,
            signal,
            ..
        } = &event
        {
            update_sample_fields(&mut next, result.as_ref(), failure.as_ref(), *signal, false)?;
        }
        let retained = if self.policy.retains_trace() {
            Some(event)
        } else {
            None
        };
        self.commit(next, retained)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "sample observation keeps lifecycle identities and borrowed payload facts explicit"
    )]
    pub(crate) fn record_sample(
        &mut self,
        group_id: jmeter_rs_model::NodeId,
        thread_number: usize,
        sampler_id: jmeter_rs_model::NodeId,
        result: Option<&SampleResult>,
        failure: Option<&SampleFailure>,
        signal: ControlSignal,
        transaction: bool,
    ) -> Result<(), ObservationError> {
        self.ensure_running()?;
        let mut next = self.summary.clone();
        update_summary_sample(&mut next, result, failure, signal, transaction)?;
        let event = match self.policy {
            RunObservationPolicyV1::Summary => None,
            RunObservationPolicyV1::FullTrace { .. } => {
                if self.trace.len() >= self.policy.max_events().map_or(0, NonZeroUsize::get) {
                    let maximum = self.policy.max_events().map_or(0, NonZeroUsize::get);
                    return Err(ObservationError::EventLimitExceeded {
                        actual: self.trace.len().saturating_add(1),
                        maximum,
                    });
                }
                Some(EngineEvent::Sample {
                    group_id,
                    thread_number,
                    sampler_id,
                    result: result.cloned(),
                    failure: failure.cloned(),
                    signal,
                })
            }
        };
        self.commit(next, event)
    }

    fn ensure_running(&self) -> Result<(), ObservationError> {
        if self.summary.terminal_state == RunObservationTerminalState::Running {
            Ok(())
        } else {
            Err(ObservationError::NotRunning {
                state: self.summary.terminal_state,
            })
        }
    }

    fn commit(
        &mut self,
        summary: RunObservationSummaryV1,
        event: Option<EngineEvent>,
    ) -> Result<(), ObservationError> {
        let Some(event) = event else {
            self.summary = summary;
            return Ok(());
        };
        let maximum_events = self.policy.max_events().map_or(0, NonZeroUsize::get);
        if self.trace.len() >= maximum_events {
            return Err(ObservationError::EventLimitExceeded {
                actual: self.trace.len().saturating_add(1),
                maximum: maximum_events,
            });
        }
        let event_bytes = estimate_event_bytes(&event)?;
        let maximum = self.policy.max_bytes().map_or(0, NonZeroUsize::get);
        let retained = self
            .retained_bytes
            .checked_add(event_bytes)
            .ok_or(ObservationError::ByteOverflow)?;
        if retained > maximum {
            return Err(ObservationError::ByteLimitExceeded {
                actual: retained,
                maximum,
            });
        }
        self.trace
            .try_reserve(1)
            .map_err(|_| ObservationError::AllocationFailure)?;
        self.trace.push(event);
        self.retained_bytes = retained;
        self.summary = summary;
        Ok(())
    }

    pub(crate) fn finish(&mut self, terminal: RunObservationTerminalState) {
        self.summary.terminal_state = terminal;
        let trace = std::mem::take(&mut self.trace).into_boxed_slice();
        self.frozen_trace = Arc::from(trace);
    }

    pub(crate) fn mark_cancelled(&mut self) {
        if self.summary.terminal_state == RunObservationTerminalState::Running {
            self.finish(RunObservationTerminalState::CancelledDropped);
        }
    }

    pub(crate) fn summary(&self) -> RunObservationSummaryV1 {
        self.summary.clone()
    }

    pub(crate) fn trace(&self) -> Arc<[EngineEvent]> {
        if self.summary.terminal_state == RunObservationTerminalState::Running {
            // A report is only published after finish.  Returning an empty
            // immutable trace here keeps inspection read-only and bounded.
            Arc::from(Vec::<EngineEvent>::new().into_boxed_slice())
        } else {
            Arc::clone(&self.frozen_trace)
        }
    }
}

fn update_sample_fields(
    summary: &mut RunObservationSummaryV1,
    result: Option<&SampleResult>,
    failure: Option<&SampleFailure>,
    signal: ControlSignal,
    transaction: bool,
) -> Result<(), ObservationError> {
    // `record_event` has already counted total/sample events.  This helper
    // only updates the sample payload counters.
    summary.highest_control_signal = summary.highest_control_signal.combine(signal);
    if let Some(result) = result {
        checked_increment(&mut summary.materialized_samples, "materialized_samples")?;
        match result.success() {
            Some(true) => checked_increment(&mut summary.successful_samples, "successful_samples")?,
            Some(false) => checked_increment(&mut summary.failed_samples, "failed_samples")?,
            None => checked_increment(
                &mut summary.unknown_success_samples,
                "unknown_success_samples",
            )?,
        }
        if transaction {
            checked_increment(&mut summary.transaction_samples, "transaction_samples")?;
        }
    } else {
        checked_increment(&mut summary.null_result_samples, "null_result_samples")?;
    }
    if failure.is_some() {
        checked_increment(
            &mut summary.explicit_sample_failures,
            "explicit_sample_failures",
        )?;
    }
    Ok(())
}

/// Shared immutable trace allocation used by engine reports.
pub type RunObservationTraceV1 = Arc<[EngineEvent]>;

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "observation fixtures use assertion-context setup"
)]
mod tests {
    use super::*;
    use jmeter_rs_model::NodeId;

    fn nonzero(value: usize) -> NonZeroUsize {
        NonZeroUsize::new(value).expect("test bound must be nonzero")
    }

    fn full_trace(max_events: usize, max_bytes: usize) -> ObservationState {
        ObservationState::new(RunObservationPolicyV1::full_trace(
            nonzero(max_events),
            nonzero(max_bytes),
        ))
    }

    fn result(success: Option<bool>, label: &str) -> SampleResult {
        let mut result = SampleResult::new(label);
        result.set_success(success);
        result
    }

    #[test]
    fn summary_counts_success_failure_unknown_null_and_explicit_failure() {
        let mut state = ObservationState::new(RunObservationPolicyV1::Summary);
        state.begin_run().expect("begin");
        state
            .record_sample(
                NodeId::new(1),
                1,
                NodeId::new(2),
                Some(&result(Some(true), "success")),
                None,
                ControlSignal::Continue,
                false,
            )
            .expect("success");
        let failed = result(Some(false), "failed");
        let explicit = SampleFailure::new(NodeId::new(2), "sample failure");
        state
            .record_sample(
                NodeId::new(1),
                1,
                NodeId::new(2),
                Some(&failed),
                Some(&explicit),
                ControlSignal::StopThread,
                false,
            )
            .expect("failed");
        let unknown = result(None, "unknown");
        state
            .record_sample(
                NodeId::new(1),
                1,
                NodeId::new(2),
                Some(&unknown),
                None,
                ControlSignal::Continue,
                false,
            )
            .expect("unknown");
        state
            .record_sample(
                NodeId::new(1),
                1,
                NodeId::new(2),
                None,
                Some(&explicit),
                ControlSignal::NextLoop,
                false,
            )
            .expect("null");
        state.finish(RunObservationTerminalState::Completed);

        let summary = state.summary();
        assert_eq!(summary.total_events, 4);
        assert_eq!(summary.sample_events, 4);
        assert_eq!(summary.materialized_samples, 3);
        assert_eq!(summary.null_result_samples, 1);
        assert_eq!(summary.successful_samples, 1);
        assert_eq!(summary.failed_samples, 1);
        assert_eq!(summary.unknown_success_samples, 1);
        assert_eq!(summary.explicit_sample_failures, 2);
        assert_eq!(summary.highest_control_signal, ControlSignal::StopThread);
        assert_eq!(summary.samples(), 3);
        assert_eq!(summary.sample_failures(), 1);
        assert_eq!(
            summary.terminal_state,
            RunObservationTerminalState::Completed
        );
        assert!(state.trace().is_empty());
    }

    #[test]
    fn summary_counts_ignored_result_as_materialized_sample() {
        let mut state = ObservationState::new(RunObservationPolicyV1::Summary);
        state.begin_run().expect("begin");
        let mut ignored = result(Some(true), "ignored");
        ignored.set_ignored(true);
        state
            .record_sample(
                NodeId::new(1),
                1,
                NodeId::new(2),
                Some(&ignored),
                None,
                ControlSignal::Continue,
                false,
            )
            .expect("ignored sample");
        state.finish(RunObservationTerminalState::Completed);

        let summary = state.summary();
        assert_eq!(summary.samples(), 1);
        assert_eq!(summary.sample_failures(), 0);
        assert_eq!(summary.successful_samples, 1);
        assert!(state.trace().is_empty());
    }

    #[test]
    fn every_non_sample_lifecycle_variant_counts_once() {
        let mut state = ObservationState::new(RunObservationPolicyV1::Summary);
        state.begin_run().expect("begin");
        for event in [
            EngineEvent::TestStarted,
            EngineEvent::ModeStarted(crate::EngineMode::Main),
            EngineEvent::GroupStarted {
                id: NodeId::new(1),
                kind: crate::GroupKind::Main,
            },
            EngineEvent::UserStarted {
                group_id: NodeId::new(1),
                thread_number: 1,
                lifecycle_id: 1,
            },
            EngineEvent::Iteration {
                group_id: NodeId::new(1),
                thread_number: 1,
                iteration: 0,
            },
            EngineEvent::UserFinished {
                group_id: NodeId::new(1),
                thread_number: 1,
                lifecycle_id: 1,
            },
            EngineEvent::GroupFinished {
                id: NodeId::new(1),
                kind: crate::GroupKind::Main,
            },
            EngineEvent::TestFinished {
                signal: ControlSignal::Continue,
            },
        ] {
            state.record_event(event).expect("lifecycle event");
        }
        let summary = state.summary();
        assert_eq!(summary.total_events, 8);
        assert_eq!(summary.test_started, 1);
        assert_eq!(summary.mode_started, 1);
        assert_eq!(summary.groups_started, 1);
        assert_eq!(summary.users_started, 1);
        assert_eq!(summary.iterations, 1);
        assert_eq!(summary.users_finished, 1);
        assert_eq!(summary.groups_finished, 1);
        assert_eq!(summary.test_finished, 1);
        assert_eq!(summary.sample_events, 0);
    }

    #[test]
    fn full_trace_count_boundary_is_atomic_and_typed() {
        let mut state = full_trace(2, 4 * 1024 * 1024);
        state.begin_run().expect("begin");
        state.record_event(EngineEvent::TestStarted).expect("first");
        state
            .record_sample(
                NodeId::new(1),
                1,
                NodeId::new(2),
                Some(&result(Some(true), "sample")),
                None,
                ControlSignal::Continue,
                false,
            )
            .expect("second");
        let before = state.summary();
        let error = state
            .record_event(EngineEvent::TestFinished {
                signal: ControlSignal::Continue,
            })
            .expect_err("count boundary");
        assert_eq!(error.code(), "runtime.observation.event-limit");
        assert_eq!(
            error.to_string(),
            "runtime.observation.event-limit: 3 exceeds 2"
        );
        assert_eq!(state.summary(), before);
        state.finish(RunObservationTerminalState::Failed);
        assert_eq!(
            state.summary().terminal_state,
            RunObservationTerminalState::Failed
        );
        assert_eq!(state.trace().len(), 2);
    }

    #[test]
    fn full_trace_byte_boundary_is_exact_and_atomic() {
        let sample = EngineEvent::Sample {
            group_id: NodeId::new(1),
            thread_number: 1,
            sampler_id: NodeId::new(2),
            result: Some(result(Some(true), "sample")),
            failure: None,
            signal: ControlSignal::Continue,
        };
        let bytes = estimate_event_bytes(&sample).expect("estimate");
        let mut state = full_trace(2, bytes);
        state.begin_run().expect("begin");
        state
            .record_sample(
                NodeId::new(1),
                1,
                NodeId::new(2),
                sample_result_ref(&sample),
                None,
                ControlSignal::Continue,
                false,
            )
            .expect("exact byte boundary");
        let before = state.summary();
        let error = state
            .record_sample(
                NodeId::new(1),
                1,
                NodeId::new(2),
                sample_result_ref(&sample),
                None,
                ControlSignal::Continue,
                false,
            )
            .expect_err("byte boundary");
        assert_eq!(error.code(), "runtime.observation.byte-limit");
        assert_eq!(state.summary(), before);
        state.finish(RunObservationTerminalState::Failed);
        assert_eq!(state.trace().len(), 1);
    }

    fn sample_result_ref(event: &EngineEvent) -> Option<&SampleResult> {
        match event {
            EngineEvent::Sample { result, .. } => result.as_ref(),
            _ => None,
        }
    }

    #[test]
    fn repeated_runs_reset_summary_and_trace() {
        let mut state = full_trace(4, 4 * 1024 * 1024);
        state.begin_run().expect("first begin");
        state
            .record_event(EngineEvent::TestStarted)
            .expect("first event");
        state.finish(RunObservationTerminalState::Completed);
        assert_eq!(state.summary().total_events, 1);
        assert_eq!(state.trace().len(), 1);

        state.begin_run().expect("second begin");
        assert_eq!(state.summary().total_events, 0);
        assert_eq!(
            state.summary().terminal_state,
            RunObservationTerminalState::Running
        );
        assert!(state.trace().is_empty());
        state.finish(RunObservationTerminalState::Completed);
    }

    #[test]
    fn dropped_state_is_cancelled_and_trace_is_frozen() {
        let mut state = full_trace(2, 4 * 1024 * 1024);
        state.begin_run().expect("begin");
        state.record_event(EngineEvent::TestStarted).expect("event");
        state.mark_cancelled();
        let summary = state.summary();
        assert_eq!(
            summary.terminal_state,
            RunObservationTerminalState::CancelledDropped
        );
        assert_eq!(state.trace().len(), 1);
    }

    #[test]
    fn summary_can_exceed_former_count_ceiling_without_retaining_events() {
        let maximum = 1_000_001;
        let mut state = ObservationState::new(RunObservationPolicyV1::Summary);
        state.begin_run().expect("begin");
        for _ in 0..maximum {
            state
                .record_event(EngineEvent::Iteration {
                    group_id: NodeId::new(1),
                    thread_number: 1,
                    iteration: 0,
                })
                .expect("bounded lifecycle event");
        }
        assert_eq!(state.summary().total_events, maximum as u64);
        assert_eq!(state.summary().iterations, maximum as u64);
        state.finish(RunObservationTerminalState::Completed);
        assert!(state.trace().is_empty());
    }
}
