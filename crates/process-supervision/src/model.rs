// SPDX-License-Identifier: Apache-2.0
//! Pure state model and fake backend used by deterministic supervisor tests.
//!
//! The model mints opaque tokens; it never accepts or emits a numeric process
//! identifier.  Consequently model/failure-injection tests cannot signal a
//! real process even when a test is run on a developer workstation.

use crate::error::{ErrorCategory, ErrorCode, SupervisionError};

/// Fixed automatic cleanup bound required by Decision 0001 revision 4.
pub(crate) const AUTOMATIC_ATTEMPTS: u8 = 3;
/// Per-attempt work budget required by Decision 0001 revision 4.
pub(crate) const ATTEMPT_BUDGET_MILLIS: u64 = 250;
/// Maximum interruptible service tick.
pub(crate) const SERVICE_TICK_MILLIS: u64 = 10;

/// Normative slot states.  Resource ownership is kept separately in the
/// supervisor slot; a state transition never moves a resource into a task.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum SlotState {
    Free = 0,
    Reserved = 1,
    LaunchQueued = 2,
    Creating = 3,
    ChildOwned = 4,
    ContainmentReady = 5,
    HandoffPending = 6,
    Active = 7,
    CleanupRequested = 8,
    Observing = 9,
    Terminating = 10,
    RootWaitable = 11,
    Reaping = 12,
    HandlesClosing = 13,
    Complete = 14,
    ContainmentLost = 15,
    Quarantined = 16,
    Retired = 17,
}

impl SlotState {
    /// Whether a state retains a slot generation/ownership reservation.
    pub(crate) const fn occupied(self) -> bool {
        !matches!(self, Self::Free | Self::Retired)
    }

    /// Returns whether the requested state edge is normative.
    #[allow(clippy::match_like_matches_macro)]
    pub(crate) const fn can_transition(self, next: Self) -> bool {
        use SlotState::*;
        match (self, next) {
            (Free, Reserved) => true,
            // Every occupied state can be degraded without first relying on
            // a best-effort cleanup edge.  In particular, a panic or
            // containment proof failure may be discovered while a request is
            // still queued or while activation is being handed off.
            (
                Reserved,
                LaunchQueued | Creating | CleanupRequested | ContainmentLost | Quarantined,
            ) => true,
            (LaunchQueued, Creating | CleanupRequested | ContainmentLost | Quarantined) => true,
            (Creating, ChildOwned | CleanupRequested | ContainmentLost | Quarantined) => true,
            (ChildOwned, ContainmentReady | CleanupRequested | ContainmentLost | Quarantined) => {
                true
            }
            (
                ContainmentReady,
                HandoffPending | CleanupRequested | ContainmentLost | Quarantined,
            ) => true,
            (HandoffPending, Active | CleanupRequested | ContainmentLost | Quarantined) => true,
            (Active, CleanupRequested | Observing | ContainmentLost | Quarantined) => true,
            (
                CleanupRequested,
                Observing | Terminating | RootWaitable | Reaping | HandlesClosing | ContainmentLost
                | Quarantined,
            ) => true,
            (
                Observing,
                CleanupRequested | Terminating | RootWaitable | Reaping | ContainmentLost
                | Quarantined,
            ) => true,
            (Terminating, RootWaitable | Reaping | ContainmentLost | Quarantined) => true,
            (RootWaitable, Reaping | HandlesClosing | ContainmentLost | Quarantined) => true,
            (Reaping, CleanupRequested | HandlesClosing | ContainmentLost | Quarantined) => true,
            (HandlesClosing, CleanupRequested | Complete | ContainmentLost | Quarantined) => true,
            (ContainmentLost, CleanupRequested | RootWaitable | Complete | Quarantined) => true,
            (Complete, Free | Retired) => true,
            (Quarantined, CleanupRequested | Quarantined) => true,
            (Retired, Retired) => true,
            _ => false,
        }
    }
}

/// Global admission lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Admission {
    Open,
    Closing,
    Draining,
    StopRequested,
    StopAcknowledged,
    Joined,
}

impl Admission {
    /// Returns whether a new reservation can be linearized.
    pub(crate) const fn accepts(self) -> bool {
        matches!(self, Self::Open)
    }

    /// Returns whether the lifecycle edge is valid.
    pub(crate) const fn can_transition(self, next: Self) -> bool {
        use Admission::*;
        matches!(
            (self, next),
            (Open, Closing)
                | (Closing, Draining)
                | (Draining, StopRequested)
                | (StopRequested, StopAcknowledged)
                | (StopAcknowledged, Joined)
                | (Joined, Joined)
        )
    }
}

/// Opaque fake root token.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct FakeRoot(u32);

/// Opaque fake containment token.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct FakeContainment(u32);

/// Failure points available to pure fake tests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FakeFailure {
    Create,
    Containment,
    Observe,
    Signal,
    Reap,
    Close,
    PanicAfterCreate,
}

/// A finite fake platform.  It records only bounded event counters and opaque
/// token identity; no OS process API is reachable from this type.
#[derive(Clone, Debug)]
pub(crate) struct FakeBackend {
    next_root: u32,
    next_containment: u32,
    failure: Option<FakeFailure>,
    create_count: u8,
    observe_count: u8,
    signal_count: u8,
    reap_count: u8,
    close_count: u8,
}

impl Default for FakeBackend {
    fn default() -> Self {
        Self {
            next_root: 2,
            next_containment: 1,
            failure: None,
            create_count: 0,
            observe_count: 0,
            signal_count: 0,
            reap_count: 0,
            close_count: 0,
        }
    }
}

impl FakeBackend {
    /// Injects one deterministic failure at the selected boundary.
    pub(crate) fn fail_at(&mut self, failure: FakeFailure) {
        self.failure = Some(failure);
    }

    /// Mints a root and containment token without touching an OS.
    pub(crate) fn create(&mut self) -> Result<(FakeRoot, FakeContainment), SupervisionError> {
        self.create_count = self.create_count.saturating_add(1);
        if self.failure == Some(FakeFailure::Create) {
            self.failure = None;
            return Err(SupervisionError::setup(
                ErrorCode::SpawnFailed,
                "fake create failure",
            ));
        }
        let root = FakeRoot(self.next_root);
        let containment = FakeContainment(self.next_containment);
        self.next_root = self.next_root.saturating_add(1).max(2);
        self.next_containment = self.next_containment.saturating_add(1).max(1);
        Ok((root, containment))
    }

    /// Runs the fake containment proof.
    pub(crate) fn prove(
        &mut self,
        _root: FakeRoot,
        _containment: FakeContainment,
    ) -> Result<(), SupervisionError> {
        if self.failure == Some(FakeFailure::Containment) {
            self.failure = None;
            return Err(SupervisionError::new(
                ErrorCode::ContainmentLost,
                ErrorCategory::Containment,
                false,
                "fake containment proof failed",
            ));
        }
        Ok(())
    }

    /// Performs one fake observe operation.
    pub(crate) fn observe(&mut self, _root: FakeRoot) -> Result<bool, SupervisionError> {
        self.observe_count = self.observe_count.saturating_add(1);
        if self.failure == Some(FakeFailure::Observe) {
            self.failure = None;
            return Err(SupervisionError::new(
                ErrorCode::ReaperContractLost,
                ErrorCategory::Reaping,
                false,
                "fake sole-reaper observation failed",
            ));
        }
        Ok(false)
    }

    /// Performs one fake signal operation.
    pub(crate) fn signal(
        &mut self,
        _root: FakeRoot,
        _containment: FakeContainment,
    ) -> Result<(), SupervisionError> {
        self.signal_count = self.signal_count.saturating_add(1);
        if self.failure == Some(FakeFailure::Signal) {
            self.failure = None;
            return Err(SupervisionError::cleanup(
                ErrorCode::ProcessGroupSignalFailed,
                "fake signal failure",
            ));
        }
        Ok(())
    }

    /// Performs one fake exact-root reap.
    pub(crate) fn reap(&mut self, _root: FakeRoot) -> Result<(), SupervisionError> {
        self.reap_count = self.reap_count.saturating_add(1);
        if self.failure == Some(FakeFailure::Reap) {
            self.failure = None;
            return Err(SupervisionError::cleanup(
                ErrorCode::WaitFailed,
                "fake reap failure",
            ));
        }
        Ok(())
    }

    /// Performs one fake handle close while retaining ownership on failure.
    pub(crate) fn close(&mut self, _containment: FakeContainment) -> Result<(), SupervisionError> {
        self.close_count = self.close_count.saturating_add(1);
        if self.failure == Some(FakeFailure::Close) {
            self.failure = None;
            return Err(SupervisionError::cleanup(
                ErrorCode::HandleCloseFailed,
                "fake close failure retains token",
            ));
        }
        Ok(())
    }

    /// Returns fixed event counters for assertions.
    pub(crate) const fn counts(&self) -> (u8, u8, u8, u8, u8) {
        (
            self.create_count,
            self.observe_count,
            self.signal_count,
            self.reap_count,
            self.close_count,
        )
    }
}

/// A finite fake state-machine harness used by tests and future Loom models.
#[derive(Clone, Debug)]
pub(crate) struct Model<const CAPACITY: usize> {
    states: [SlotState; CAPACITY],
    generations: [u64; CAPACITY],
    admission: Admission,
}

impl<const CAPACITY: usize> Default for Model<CAPACITY> {
    fn default() -> Self {
        Self {
            states: [SlotState::Free; CAPACITY],
            generations: [0; CAPACITY],
            admission: Admission::Open,
        }
    }
}

impl<const CAPACITY: usize> Model<CAPACITY> {
    /// Reserves the first free slot and advances its generation.
    pub(crate) fn reserve(&mut self) -> Result<(usize, u64), SupervisionError> {
        if !self.admission.accepts() {
            return Err(SupervisionError::setup(
                ErrorCode::AdmissionClosed,
                "fake admission is closed",
            ));
        }
        for index in 0..CAPACITY {
            if self.states[index] == SlotState::Free {
                let Some(generation) = self.generations[index].checked_add(1) else {
                    self.states[index] = SlotState::Retired;
                    continue;
                };
                if generation == 0 {
                    self.states[index] = SlotState::Retired;
                    continue;
                }
                self.generations[index] = generation;
                self.states[index] = SlotState::Reserved;
                return Ok((index, generation));
            }
        }
        Err(SupervisionError::cleanup(
            ErrorCode::ReaperCapacity,
            "fake fixed capacity is full",
        ))
    }

    /// Applies one checked state transition.
    pub(crate) fn transition(
        &mut self,
        index: usize,
        generation: u64,
        next: SlotState,
    ) -> Result<(), SupervisionError> {
        if index >= CAPACITY || self.generations[index] != generation || generation == 0 {
            return Err(SupervisionError::setup(
                ErrorCode::StaleOwnershipToken,
                "fake generation is stale",
            ));
        }
        let current = self.states[index];
        if !current.can_transition(next) {
            return Err(SupervisionError::new(
                ErrorCode::InvariantViolation,
                ErrorCategory::Internal,
                false,
                "invalid fake slot transition",
            ));
        }
        self.states[index] = next;
        Ok(())
    }

    /// Closes admission in one linearized model transition.
    pub(crate) fn close_admission(&mut self) -> Result<(), SupervisionError> {
        if !self.admission.can_transition(Admission::Closing) {
            return Err(SupervisionError::new(
                ErrorCode::AdmissionClosed,
                ErrorCategory::Shutdown,
                false,
                "fake admission was already closed",
            ));
        }
        self.admission = Admission::Closing;
        Ok(())
    }

    /// Returns the model admission state.
    pub(crate) const fn admission(&self) -> Admission {
        self.admission
    }

    /// Returns a state for pure assertions.
    pub(crate) const fn state(&self, index: usize) -> Option<SlotState> {
        if index < CAPACITY {
            Some(self.states[index])
        } else {
            None
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn state_edges_are_explicit_and_invalid_edges_fail_closed() {
        assert!(SlotState::Reserved.can_transition(SlotState::LaunchQueued));
        assert!(SlotState::HandoffPending.can_transition(SlotState::Active));
        assert!(SlotState::Complete.can_transition(SlotState::Free));
        assert!(!SlotState::Free.can_transition(SlotState::Active));
        assert!(!SlotState::Active.can_transition(SlotState::Free));

        // A failure can be discovered at every resource-bearing phase.  The
        // model must therefore permit both degraded terminal paths without
        // requiring an intermediate best-effort transition.
        let occupied = [
            SlotState::Reserved,
            SlotState::LaunchQueued,
            SlotState::Creating,
            SlotState::ChildOwned,
            SlotState::ContainmentReady,
            SlotState::HandoffPending,
            SlotState::Active,
            SlotState::CleanupRequested,
            SlotState::Observing,
            SlotState::Terminating,
            SlotState::RootWaitable,
            SlotState::Reaping,
            SlotState::HandlesClosing,
        ];
        for state in occupied {
            assert!(
                state.can_transition(SlotState::ContainmentLost),
                "{state:?}"
            );
            assert!(state.can_transition(SlotState::Quarantined), "{state:?}");
        }
    }

    #[test]
    fn fake_backend_failures_are_opaque_and_bounded() {
        let mut fake = FakeBackend::default();
        fake.fail_at(FakeFailure::Containment);
        let (root, token) = fake.create().expect("fake create");
        assert_eq!(
            fake.prove(root, token)
                .expect_err("containment failure")
                .code(),
            ErrorCode::ContainmentLost
        );
        assert_eq!(fake.counts().0, 1);
    }

    #[test]
    fn model_rejects_stale_generation_and_capacity_overflow() {
        let mut model = Model::<1>::default();
        let (index, generation) = model.reserve().expect("reserve");
        assert_eq!(
            model
                .transition(index, generation + 1, SlotState::LaunchQueued)
                .expect_err("stale token")
                .code(),
            ErrorCode::StaleOwnershipToken
        );
        assert_eq!(
            model.reserve().expect_err("capacity").code(),
            ErrorCode::ReaperCapacity
        );
    }

    #[test]
    fn model_closes_admission_before_new_reservation() {
        let mut model = Model::<2>::default();
        model.close_admission().expect("close");
        assert_eq!(model.admission(), Admission::Closing);
        assert_eq!(
            model.reserve().expect_err("closed").code(),
            ErrorCode::AdmissionClosed
        );
    }

    #[test]
    fn every_shutdown_edge_is_linearized() {
        let edges = [
            (Admission::Open, Admission::Closing),
            (Admission::Closing, Admission::Draining),
            (Admission::Draining, Admission::StopRequested),
            (Admission::StopRequested, Admission::StopAcknowledged),
            (Admission::StopAcknowledged, Admission::Joined),
        ];
        for (from, to) in edges {
            assert!(from.can_transition(to));
        }
        assert!(!Admission::Joined.can_transition(Admission::Open));
    }

    #[test]
    fn fake_failure_points_have_stable_codes() {
        let points = [
            (FakeFailure::Create, ErrorCode::SpawnFailed),
            (FakeFailure::Observe, ErrorCode::ReaperContractLost),
            (FakeFailure::Signal, ErrorCode::ProcessGroupSignalFailed),
            (FakeFailure::Reap, ErrorCode::WaitFailed),
            (FakeFailure::Close, ErrorCode::HandleCloseFailed),
        ];
        for (failure, expected) in points {
            let mut fake = FakeBackend::default();
            fake.fail_at(failure);
            let created = fake.create();
            if failure == FakeFailure::Create {
                assert_eq!(created.expect_err("create failure").code(), expected);
                continue;
            }
            let (root, token) = created.expect("fake create");
            let result = match failure {
                FakeFailure::Observe => fake.observe(root).map(|_| ()),
                FakeFailure::Signal => fake.signal(root, token),
                FakeFailure::Reap => fake.reap(root),
                FakeFailure::Close => fake.close(token),
                FakeFailure::Create | FakeFailure::Containment | FakeFailure::PanicAfterCreate => {
                    Ok(())
                }
            };
            assert_eq!(result.expect_err("injected failure").code(), expected);
        }
    }

    #[test]
    fn panic_boundary_drop_probe_is_bounded_and_observable() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        #[derive(Debug)]
        struct DropProbe(Arc<AtomicUsize>);

        impl Drop for DropProbe {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let drops = Arc::new(AtomicUsize::new(0));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe({
            let drops = Arc::clone(&drops);
            move || {
                let mut fake = FakeBackend::default();
                let (root, containment) = fake.create().expect("fake create");
                let _handoff = (DropProbe(drops), root, containment);
                panic!("injected post-create panic");
            }
        }));
        assert!(result.is_err());
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn cleanup_retry_and_quarantine_edges_never_free_ownership() {
        assert!(SlotState::CleanupRequested.can_transition(SlotState::Observing));
        assert!(SlotState::Observing.can_transition(SlotState::Quarantined));
        assert!(SlotState::Quarantined.can_transition(SlotState::CleanupRequested));
        assert!(!SlotState::Quarantined.can_transition(SlotState::Free));
    }
}
