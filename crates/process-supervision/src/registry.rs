// SPDX-License-Identifier: Apache-2.0
//! One process-global fixed ownership root.
//!
//! The root is initialized exactly once and is never held by `Arc`, a
//! destructible registry, a leaked allocation, or a caller token.  Slots keep
//! every root/token in place.  The joinable service is the only production
//! thread that launches or cleans platform resources; caller `Drop` performs
//! only atomic stores.

use crate::error::{ErrorCategory, ErrorCode, SupervisionError};
use crate::model::{Admission, SlotState};
use crate::platform::{self, CreateFailure, PlatformToken, RootHandle};
use crate::policy::{PolicyKind, PurposeMarker};
use crate::process::{
    CancellationToken, CleanupAttempt, DEFAULT_CLEANUP_TIMEOUT, ExitInfo, PreparedProcess,
    SERVICE_POLL_INTERVAL, cleanup_owned, is_containment_failure,
};
use crate::spec::{LaunchSpec, SpawnSpec};
use std::array;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::Instant;

/// Maximum process-global slot capacity.
pub const MAX_REGISTRY_CAPACITY: usize = 64;
/// Default capacity selected by repository adapters.
pub const DEFAULT_REGISTRY_CAPACITY: usize = 16;
const ERROR_SNAPSHOT_CAPACITY: usize = 32;
const SERVICE_NOT_STARTED: u8 = 0;
const SERVICE_RUNNING: u8 = 1;
const SERVICE_FAILED: u8 = 2;
const SERVICE_STOPPED: u8 = 3;

// The fixed array is process-global and initialized once.  Keeping the
// aggregate in one heap allocation avoids overflowing the small stack of a
// caller that wins initialization; the allocation is never replaced, leaked,
// or manually destroyed while the process-global OnceLock is live.
static GLOBAL: OnceLock<Box<Supervisor>> = OnceLock::new();

/// One retained bounded error snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ErrorSnapshot {
    pub(crate) sequence: u64,
    pub(crate) code: ErrorCode,
    pub(crate) category: ErrorCategory,
    pub(crate) retryable: bool,
    pub(crate) message: String,
}

/// Fixed-size diagnostic view.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ErrorSnapshotSet {
    entries: [Option<ErrorSnapshot>; ERROR_SNAPSHOT_CAPACITY],
    length: usize,
}

impl ErrorSnapshotSet {
    fn empty() -> Self {
        Self {
            entries: array::from_fn(|_| None),
            length: 0,
        }
    }

    pub(crate) const fn len(&self) -> usize {
        self.length
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &ErrorSnapshot> {
        self.entries[..self.length]
            .iter()
            .filter_map(Option::as_ref)
    }
}

/// Bounded aggregate state; counts are snapshots and never imply ownership
/// has disappeared while a slot lock is busy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RegistryStatus {
    pub(crate) capacity: usize,
    pub(crate) admission_closed: bool,
    pub(crate) reserved: usize,
    pub(crate) active: usize,
    pub(crate) abandoned: usize,
    pub(crate) retrying: usize,
    pub(crate) quarantined: usize,
    pub(crate) pending: usize,
    pub(crate) handle_pending: usize,
    pub(crate) error_count: usize,
    pub(crate) retired: usize,
    pub(crate) service_running: bool,
    pub(crate) service_failed: bool,
}

/// One explicit bounded drain pass result.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct DrainReport {
    pub(crate) inspected: usize,
    pub(crate) completed: usize,
    pub(crate) retained: usize,
    pub(crate) quarantined: usize,
    pub(crate) failures: usize,
}

/// Shutdown state returned after one absolute deadline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ShutdownReport {
    pub(crate) admission_closed: bool,
    pub(crate) complete: bool,
    pub(crate) reserved: usize,
    pub(crate) quarantined: usize,
    pub(crate) handle_pending: usize,
    pub(crate) service_joined: bool,
    pub(crate) service_failed: bool,
    pub(crate) error_count: usize,
}

struct Slot {
    generation: u64,
    retired: bool,
    state: SlotState,
    kind: PolicyKind,
    root: Option<RootHandle>,
    token: Option<PlatformToken>,
    tree_error: Option<SupervisionError>,
    terminal_error: Option<SupervisionError>,
    exit: Option<ExitInfo>,
    attempts: u8,
}

/// Retains the first terminal diagnostic for a generation while allowing one
/// bounded secondary detail.  In particular, containment/setup failures must
/// remain visible after exact-root fallback and successful handle closure.
fn remember_terminal(slot: &mut Slot, error: SupervisionError) {
    slot.terminal_error = Some(match slot.terminal_error.take() {
        Some(previous) => previous.with_secondary(error),
        None => error,
    });
}

impl Slot {
    fn free() -> Self {
        Self {
            generation: 0,
            retired: false,
            state: SlotState::Free,
            kind: PolicyKind::ExactChild,
            root: None,
            token: None,
            tree_error: None,
            terminal_error: None,
            exit: None,
            attempts: 0,
        }
    }

    fn occupied(&self) -> bool {
        self.state.occupied() || self.root.is_some() || self.token.is_some()
    }

    fn reset_for_reservation(&mut self, generation: u64, kind: PolicyKind) {
        self.generation = generation;
        self.retired = false;
        self.state = SlotState::Reserved;
        self.kind = kind;
        self.root = None;
        self.token = None;
        self.tree_error = None;
        self.terminal_error = None;
        self.exit = None;
        self.attempts = 0;
    }
}

struct ErrorLog {
    entries: [Option<ErrorSnapshot>; ERROR_SNAPSHOT_CAPACITY],
    next: usize,
    length: usize,
    sequence: u64,
}

impl ErrorLog {
    fn new() -> Self {
        Self {
            entries: array::from_fn(|_| None),
            next: 0,
            length: 0,
            sequence: 0,
        }
    }

    fn push(&mut self, error: &SupervisionError) {
        self.sequence = self.sequence.saturating_add(1);
        self.entries[self.next] = Some(ErrorSnapshot {
            sequence: self.sequence,
            code: error.code(),
            category: error.category(),
            retryable: error.retryable(),
            message: error.message().to_owned(),
        });
        self.next = (self.next + 1) % ERROR_SNAPSHOT_CAPACITY;
        self.length = self.length.saturating_add(1).min(ERROR_SNAPSHOT_CAPACITY);
    }

    fn snapshot(&self) -> ErrorSnapshotSet {
        let mut result = ErrorSnapshotSet::empty();
        let start = if self.length == ERROR_SNAPSHOT_CAPACITY {
            self.next
        } else {
            0
        };
        for offset in 0..self.length {
            result.entries[offset] =
                self.entries[(start + offset) % ERROR_SNAPSHOT_CAPACITY].clone();
        }
        result.length = self.length;
        result
    }
}

struct LaunchRequest {
    index: usize,
    generation: u64,
    spec: LaunchSpec,
    cancellation: CancellationToken,
}

struct RootControl {
    admission: Admission,
    capacity: usize,
    free: [bool; MAX_REGISTRY_CAPACITY],
    generations: [u64; MAX_REGISTRY_CAPACITY],
    queue: [Option<LaunchRequest>; MAX_REGISTRY_CAPACITY],
    queue_len: usize,
    owned: usize,
    shutdown_epoch: u64,
}

impl RootControl {
    fn new(capacity: usize) -> Self {
        Self {
            admission: Admission::Open,
            capacity,
            free: [true; MAX_REGISTRY_CAPACITY],
            generations: [0; MAX_REGISTRY_CAPACITY],
            queue: array::from_fn(|_| None),
            queue_len: 0,
            owned: 0,
            shutdown_epoch: 0,
        }
    }
}

struct ServiceControl {
    join: Option<JoinHandle<()>>,
}

/// The static process-global ownership root.
pub(crate) struct Supervisor {
    control: Mutex<RootControl>,
    slots: [Mutex<Slot>; MAX_REGISTRY_CAPACITY],
    abandoned_generation: [AtomicU64; MAX_REGISTRY_CAPACITY],
    cleanup_generation: [AtomicU64; MAX_REGISTRY_CAPACITY],
    work_epoch: AtomicU64,
    admission_closed: AtomicBool,
    wake_lock: Mutex<()>,
    wake: Condvar,
    errors: Mutex<ErrorLog>,
    service_state: AtomicU8,
    service_stop: AtomicBool,
    service_ack: AtomicBool,
    service: Mutex<ServiceControl>,
    poisoned: AtomicBool,
}

impl Supervisor {
    fn new(capacity: usize) -> Box<Self> {
        Box::new(Self {
            control: Mutex::new(RootControl::new(capacity)),
            slots: array::from_fn(|_| Mutex::new(Slot::free())),
            abandoned_generation: array::from_fn(|_| AtomicU64::new(0)),
            cleanup_generation: array::from_fn(|_| AtomicU64::new(0)),
            work_epoch: AtomicU64::new(0),
            admission_closed: AtomicBool::new(false),
            wake_lock: Mutex::new(()),
            wake: Condvar::new(),
            errors: Mutex::new(ErrorLog::new()),
            service_state: AtomicU8::new(SERVICE_NOT_STARTED),
            service_stop: AtomicBool::new(false),
            service_ack: AtomicBool::new(false),
            service: Mutex::new(ServiceControl { join: None }),
            poisoned: AtomicBool::new(false),
        })
    }

    fn lock_control(&self) -> MutexGuard<'_, RootControl> {
        match self.control.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                self.poisoned.store(true, Ordering::Release);
                poisoned.into_inner()
            }
        }
    }

    fn lock_slot(&self, index: usize) -> MutexGuard<'_, Slot> {
        match self.slots[index].lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                self.poisoned.store(true, Ordering::Release);
                poisoned.into_inner()
            }
        }
    }

    fn try_slot(&self, index: usize) -> Option<MutexGuard<'_, Slot>> {
        match self.slots[index].try_lock() {
            Ok(guard) => Some(guard),
            Err(std::sync::TryLockError::WouldBlock) => None,
            Err(std::sync::TryLockError::Poisoned(poisoned)) => {
                self.poisoned.store(true, Ordering::Release);
                Some(poisoned.into_inner())
            }
        }
    }

    fn record_error(&self, error: SupervisionError) {
        match self.errors.lock() {
            Ok(mut log) => log.push(&error),
            Err(poisoned) => {
                self.poisoned.store(true, Ordering::Release);
                poisoned.into_inner().push(&error);
            }
        }
    }

    fn ensure_service(&'static self) -> Result<(), SupervisionError> {
        let mut service = match self.service.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                self.poisoned.store(true, Ordering::Release);
                poisoned.into_inner()
            }
        };
        if self.service_state.load(Ordering::Acquire) == SERVICE_FAILED {
            return Err(SupervisionError::new(
                ErrorCode::ServiceStartFailed,
                ErrorCategory::Setup,
                false,
                "global process-supervision service is failed",
            ));
        }
        if self.admission_closed.load(Ordering::Acquire) {
            return Err(SupervisionError::setup(
                ErrorCode::AdmissionClosed,
                "process-supervision service cannot start after admission closed",
            ));
        }
        if service.join.is_some() {
            return Ok(());
        }
        self.service_stop.store(false, Ordering::Release);
        self.service_ack.store(false, Ordering::Release);
        // Publish the lifecycle state before starting the thread.  A very
        // short-lived service can otherwise set STOPPED/FAILED and race with
        // this function's post-spawn RUNNING store, leaving the root claiming
        // a live service after its join handle has already terminated.
        self.service_state.store(SERVICE_RUNNING, Ordering::Release);
        let join = thread::Builder::new()
            .name("jmeter-process-supervision".to_owned())
            .spawn(move || self.service_main())
            .map_err(|error| {
                self.service_state.store(SERVICE_FAILED, Ordering::Release);
                crate::error::io_error(
                    ErrorCode::ServiceStartFailed,
                    ErrorCategory::Setup,
                    "start process-supervision service",
                    &error,
                )
            })?;
        service.join = Some(join);
        Ok(())
    }

    fn service_main(&'static self) {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            loop {
                let _ = self.service_pass(false, Instant::now() + DEFAULT_CLEANUP_TIMEOUT);
                if self.service_stop.load(Ordering::Acquire) && self.zero_owned() {
                    break;
                }
                let guard = match self.wake_lock.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => {
                        self.poisoned.store(true, Ordering::Release);
                        poisoned.into_inner()
                    }
                };
                let _ = self.wake.wait_timeout(guard, SERVICE_POLL_INTERVAL);
            }
        }));
        if result.is_err() {
            self.service_state.store(SERVICE_FAILED, Ordering::Release);
            self.record_error(SupervisionError::new(
                ErrorCode::ServiceFailed,
                ErrorCategory::Internal,
                false,
                "global process-supervision service panicked; slot ownership retained",
            ));
        } else {
            self.service_state.store(SERVICE_STOPPED, Ordering::Release);
        }
        self.service_ack.store(true, Ordering::Release);
        self.wake.notify_all();
    }

    fn zero_owned(&self) -> bool {
        self.lock_control().owned == 0
    }

    fn reserve(&'static self) -> Result<Reservation, SupervisionError> {
        let (index, generation) = {
            let mut control = self.lock_control();
            if !control.admission.accepts() {
                return Err(SupervisionError::setup(
                    ErrorCode::AdmissionClosed,
                    "process-supervision admission is closed",
                ));
            }
            let mut selected = None;
            for index in 0..control.capacity {
                if control.free[index] {
                    let next = control.generations[index].checked_add(1);
                    if let Some(generation) = next.filter(|generation| *generation != 0) {
                        control.free[index] = false;
                        control.generations[index] = generation;
                        control.owned = control.owned.saturating_add(1);
                        selected = Some((index, generation));
                    }
                    if selected.is_some() {
                        break;
                    }
                }
            }
            selected.ok_or_else(|| {
                SupervisionError::cleanup(
                    ErrorCode::ReaperCapacity,
                    "all fixed process-supervision slots are occupied or retired",
                )
            })?
        };
        let mut slot = self.lock_slot(index);
        slot.reset_for_reservation(generation, PolicyKind::ExactChild);
        self.abandoned_generation[index].store(0, Ordering::Release);
        self.cleanup_generation[index].store(0, Ordering::Release);
        Ok(Reservation {
            supervisor: self,
            index,
            generation,
            active: true,
        })
    }

    fn enqueue<P: PurposeMarker>(
        &'static self,
        reservation: &Reservation,
        spec: SpawnSpec<P>,
        cancellation: CancellationToken,
    ) -> Result<(), SupervisionError> {
        spec.validate()?;
        let mut control = self.lock_control();
        if !control.admission.accepts() {
            return Err(SupervisionError::setup(
                ErrorCode::AdmissionClosed,
                "process-supervision admission closed before launch queueing",
            ));
        }
        if control.queue_len >= control.capacity {
            return Err(SupervisionError::cleanup(
                ErrorCode::QueueFull,
                "bounded process-supervision launch queue is full",
            ));
        }
        let request = LaunchRequest {
            index: reservation.index,
            generation: reservation.generation,
            spec: spec.into(),
            cancellation,
        };
        if let Some(index) = control.queue.iter().position(Option::is_none) {
            control.queue[index] = Some(request);
            control.queue_len += 1;
            drop(control);
            self.work_epoch.fetch_add(1, Ordering::AcqRel);
            self.wake.notify_all();
            Ok(())
        } else {
            Err(SupervisionError::cleanup(
                ErrorCode::QueueFull,
                "bounded process-supervision launch queue has no empty cell",
            ))
        }
    }

    fn pop_request(&self) -> Option<LaunchRequest> {
        let mut control = self.lock_control();
        let index = (0..control.capacity).find(|index| control.queue[*index].is_some())?;
        let request = control.queue[index].take();
        control.queue_len = control.queue_len.saturating_sub(1);
        request
    }

    fn service_pass(&'static self, explicit: bool, deadline: Instant) -> DrainReport {
        if let Some(request) = self.pop_request() {
            self.launch_request(request);
        }
        if self.lock_control().admission != Admission::Open {
            for index in 0..self.capacity() {
                let generation = self.slot_generation(index);
                if generation != 0 {
                    self.abandoned_generation[index].store(generation, Ordering::Release);
                }
            }
        }
        let mut report = DrainReport::default();
        for index in 0..self.capacity() {
            let Some(mut slot) = self.try_slot(index) else {
                report.retained += 1;
                continue;
            };
            if !slot.occupied() {
                continue;
            }
            report.inspected += 1;
            let generation = slot.generation;
            if slot.state == SlotState::Complete {
                let terminal = slot.terminal_error.clone();
                drop(slot);
                self.release_slot(index, generation, terminal);
                report.completed += 1;
                continue;
            }
            let abandoned = self.abandoned_generation[index].load(Ordering::Acquire) == generation;
            let requested = self.cleanup_generation[index].load(Ordering::Acquire) == generation;
            if abandoned
                && slot.state != SlotState::Complete
                && slot.state != SlotState::Free
                && slot.state != SlotState::Retired
                && slot.state != SlotState::Quarantined
                && slot.state.can_transition(SlotState::CleanupRequested)
            {
                slot.state = SlotState::CleanupRequested;
            }
            if slot.state == SlotState::Active
                && !requested
                && !abandoned
                && let Some(root) = slot.root.as_mut()
            {
                match platform::observe(root) {
                    Ok(crate::process::RootObservation::Waitable(exit)) => {
                        slot.exit = Some(exit);
                        slot.state = SlotState::RootWaitable;
                    }
                    Ok(crate::process::RootObservation::Live) => continue,
                    Err(error) => {
                        slot.tree_error = Some(error.clone());
                        slot.state = SlotState::ContainmentLost;
                    }
                }
            }
            if explicit && slot.state == SlotState::Quarantined {
                slot.state = SlotState::CleanupRequested;
                slot.attempts = 0;
            }
            if !matches!(
                slot.state,
                SlotState::CleanupRequested
                    | SlotState::RootWaitable
                    | SlotState::ContainmentLost
                    | SlotState::Quarantined
            ) {
                report.retained += 1;
                continue;
            }
            let outcome = self.cleanup_slot(&mut slot, deadline);
            match outcome {
                Ok(()) => {
                    report.completed += 1;
                    if slot.state == SlotState::Complete && (abandoned || explicit) {
                        // Slot state is complete; actual free-bit release is
                        // performed after this lock is dropped.
                    }
                }
                Err(error) => {
                    report.failures += 1;
                    if slot.state == SlotState::Quarantined {
                        report.quarantined += 1;
                    } else {
                        report.retained += 1;
                    }
                    self.record_error(error);
                }
            }
            // Complete means the exact root and every platform resource have
            // reached a known terminal state.  Capacity may be released even
            // while a caller still holds its now-stale capability; generation
            // validation prevents that capability from acting on a later
            // reservation.
            let release = slot.state == SlotState::Complete;
            let terminal = slot.terminal_error.clone();
            drop(slot);
            if release {
                self.release_slot(index, generation, terminal);
            }
        }
        report
    }

    // The error deliberately carries the pre-reserved slot's exact root and
    // platform token by value.  Boxing it here would add an allocation at the
    // panic-sensitive handoff boundary and could lose those resources if the
    // allocation failed; keep the large error explicit and bounded instead.
    #[allow(clippy::result_large_err)]
    fn launch_request(&'static self, request: LaunchRequest) {
        let index = request.index;
        let generation = request.generation;
        let mut slot = self.lock_slot(index);
        if slot.generation != generation || slot.state != SlotState::Reserved {
            drop(slot);
            return;
        }
        if request.cancellation.is_cancelled()
            || self.abandoned_generation[index].load(Ordering::Acquire) == generation
        {
            slot.terminal_error = Some(SupervisionError::cancelled(
                "launch was cancelled before useful work began",
            ));
            // Keep the normative lifecycle edge even though no OS resource
            // was created: Reserved -> CleanupRequested -> HandlesClosing ->
            // Complete.  Directly publishing Complete would bypass the same
            // ownership proof used for a setup failure with a returned root.
            slot.state = SlotState::CleanupRequested;
            let _ = self.cleanup_slot(&mut slot, Instant::now());
            let terminal = slot.terminal_error.clone();
            drop(slot);
            self.release_slot(index, generation, terminal);
            return;
        }
        slot.state = SlotState::LaunchQueued;
        slot.kind = request.spec.kind();
        slot.state = SlotState::Creating;
        let launch = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            platform::create_root(&request.spec)
        }))
        .unwrap_or_else(|_| {
            Err(SupervisionError::new(
                ErrorCode::HandoffFailed,
                ErrorCategory::Internal,
                false,
                "launch backend panicked before root handoff",
            )
            .into())
        });
        match launch {
            Ok((root, token)) => {
                // Immediate handoff into the pre-reserved slot: no logging,
                // allocation, callback, or second OS call occurs first.
                slot.root = Some(root);
                slot.token = token;
                slot.state = SlotState::ChildOwned;
                let kind = slot.kind;
                let slot_ref: &mut Slot = &mut slot;
                let (root_slot, token_slot) = (&mut slot_ref.root, &mut slot_ref.token);
                let validation = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    match root_slot.as_mut() {
                        Some(root) => platform::validate(root, token_slot, kind),
                        None => Err(SupervisionError::new(
                            ErrorCode::HandoffFailed,
                            ErrorCategory::Setup,
                            false,
                            "root handoff did not leave an exact root in the reserved slot",
                        )),
                    }
                }))
                .unwrap_or_else(|_| {
                    Err(SupervisionError::new(
                        ErrorCode::HandoffFailed,
                        ErrorCategory::Internal,
                        false,
                        "containment backend panicked during root handoff",
                    ))
                });
                match validation {
                    Ok(()) => {
                        slot.state = SlotState::ContainmentReady;
                        slot.state = SlotState::HandoffPending;
                        if request.cancellation.is_cancelled()
                            || self.admission_closed.load(Ordering::Acquire)
                        {
                            slot.state = SlotState::CleanupRequested;
                        }
                    }
                    Err(error) => {
                        remember_terminal(&mut slot, error.clone());
                        if is_containment_failure(&error) || slot.kind.requires_tree() {
                            slot.tree_error = Some(error.clone());
                            slot.state = SlotState::ContainmentLost;
                        } else {
                            slot.state = SlotState::CleanupRequested;
                        }
                    }
                }
            }
            Err(CreateFailure { error, root, token }) => {
                slot.root = root;
                slot.token = token;
                remember_terminal(&mut slot, error.clone());
                if slot.root.is_some() || slot.token.is_some() {
                    if is_containment_failure(&error) || slot.kind.requires_tree() {
                        slot.tree_error = Some(error.clone());
                    }
                    slot.state = SlotState::CleanupRequested;
                    self.record_error(error);
                } else {
                    slot.state = SlotState::CleanupRequested;
                    let _ = self.cleanup_slot(&mut slot, Instant::now());
                    drop(slot);
                    self.record_error(error);
                    self.release_slot(index, generation, None);
                }
                return;
            }
        }
        self.wake.notify_all();
    }

    fn cleanup_slot(&self, slot: &mut Slot, deadline: Instant) -> Result<(), SupervisionError> {
        if slot.state == SlotState::ContainmentLost {
            slot.state = SlotState::CleanupRequested;
        }
        let root_waitable = slot.state == SlotState::RootWaitable;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let Some(root) = slot.root.as_mut() else {
                slot.state = SlotState::HandlesClosing;
                return CleanupAttempt::reaped();
            };
            slot.state = if root_waitable {
                SlotState::Reaping
            } else {
                SlotState::Observing
            };
            cleanup_owned(
                root,
                slot.kind,
                &mut slot.token,
                &mut slot.tree_error,
                deadline,
            )
        }));
        let attempt = match result {
            Ok(attempt) => attempt,
            Err(_) => {
                slot.state = SlotState::Quarantined;
                let error = SupervisionError::new(
                    ErrorCode::InvariantViolation,
                    ErrorCategory::Internal,
                    false,
                    "cleanup panicked; root/token remain in their slot",
                );
                remember_terminal(slot, error.clone());
                return Err(error);
            }
        };
        if attempt.state == crate::error::CleanupState::Retained {
            let error = attempt.error.unwrap_or_else(|| {
                SupervisionError::cleanup(
                    ErrorCode::CleanupTimedOut,
                    "bounded cleanup retained slot ownership",
                )
            });
            slot.attempts = slot.attempts.saturating_add(1);
            if slot.attempts >= crate::process::MAX_AUTOMATIC_ATTEMPTS {
                slot.state = SlotState::Quarantined;
                let terminal = SupervisionError::new(
                    ErrorCode::Quarantined,
                    ErrorCategory::Cleanup,
                    true,
                    "automatic cleanup attempts exhausted; slot remains quarantined",
                )
                .with_secondary(error.clone());
                remember_terminal(slot, terminal.clone());
                return Err(error.with_secondary(terminal));
            }
            slot.state = if is_containment_failure(&error) {
                SlotState::ContainmentLost
            } else {
                SlotState::CleanupRequested
            };
            return Err(error);
        }
        if !root_waitable {
            slot.state = SlotState::RootWaitable;
            slot.state = SlotState::Reaping;
        }
        slot.state = SlotState::HandlesClosing;
        if let Some(token) = slot.token.as_mut()
            && let Err(error) = platform::close_token(token)
        {
            slot.attempts = slot.attempts.saturating_add(1);
            slot.state = if slot.attempts >= crate::process::MAX_AUTOMATIC_ATTEMPTS {
                let terminal = SupervisionError::new(
                    ErrorCode::Quarantined,
                    ErrorCategory::Cleanup,
                    true,
                    "automatic handle-close attempts exhausted; slot remains quarantined",
                )
                .with_secondary(error.clone());
                remember_terminal(slot, terminal);
                SlotState::Quarantined
            } else {
                SlotState::CleanupRequested
            };
            return Err(error);
        }
        #[cfg(windows)]
        if let Some(root) = slot.root.as_mut()
            && let Err(error) = platform::close_root(root)
        {
            slot.attempts = slot.attempts.saturating_add(1);
            slot.state = if slot.attempts >= crate::process::MAX_AUTOMATIC_ATTEMPTS {
                let terminal = SupervisionError::new(
                    ErrorCode::Quarantined,
                    ErrorCategory::Cleanup,
                    true,
                    "automatic root-handle close attempts exhausted; slot remains quarantined",
                )
                .with_secondary(error.clone());
                remember_terminal(slot, terminal);
                SlotState::Quarantined
            } else {
                SlotState::CleanupRequested
            };
            return Err(error);
        }
        slot.exit = slot
            .exit
            .or_else(|| slot.root.as_ref().and_then(platform::root_exit));
        slot.root = None;
        slot.token = None;
        slot.state = SlotState::Complete;
        // A setup/containment/close diagnostic is terminal information about
        // this generation.  Successful reaping must not erase it: repeated
        // cleanup calls need to return the same diagnostic even after the
        // exact child and platform handles have left the slot.
        if let Some(error) = attempt.error {
            remember_terminal(slot, error);
        }
        slot.attempts = 0;
        Ok(())
    }

    fn release_slot(&self, index: usize, generation: u64, terminal: Option<SupervisionError>) {
        let mut slot = self.lock_slot(index);
        if slot.generation != generation || slot.state != SlotState::Complete {
            return;
        }
        if terminal.is_some() {
            slot.terminal_error = terminal;
        }
        slot.state = if generation == u64::MAX {
            slot.retired = true;
            SlotState::Retired
        } else {
            SlotState::Free
        };
        let retired = slot.state == SlotState::Retired;
        drop(slot);
        let mut control = self.lock_control();
        if control.generations[index] == generation && !control.free[index] && !retired {
            control.free[index] = true;
            control.owned = control.owned.saturating_sub(1);
        }
        if retired && control.generations[index] == generation && !control.free[index] {
            control.owned = control.owned.saturating_sub(1);
        }
        self.abandoned_generation[index].store(0, Ordering::Release);
        self.cleanup_generation[index].store(0, Ordering::Release);
        drop(control);
        self.wake.notify_all();
    }

    fn slot_generation(&self, index: usize) -> u64 {
        self.lock_slot(index).generation
    }

    fn capacity(&self) -> usize {
        self.lock_control().capacity
    }

    pub(crate) fn mark_abandoned(&self, index: usize, generation: u64) {
        if index < MAX_REGISTRY_CAPACITY {
            self.abandoned_generation[index].store(generation, Ordering::Release);
            self.work_epoch.fetch_add(1, Ordering::AcqRel);
        }
    }

    fn mark_cleanup(&self, index: usize, generation: u64) {
        if index < MAX_REGISTRY_CAPACITY {
            self.cleanup_generation[index].store(generation, Ordering::Release);
            self.work_epoch.fetch_add(1, Ordering::AcqRel);
            self.wake.notify_all();
        }
    }

    fn await_launch(
        &'static self,
        index: usize,
        generation: u64,
        deadline: Instant,
    ) -> Result<PreparedProcess, SupervisionError> {
        loop {
            {
                let slot = self.lock_slot(index);
                if slot.generation != generation {
                    return Err(SupervisionError::setup(
                        ErrorCode::StaleOwnershipToken,
                        "launch generation became stale",
                    ));
                }
                if matches!(
                    slot.state,
                    SlotState::HandoffPending | SlotState::ContainmentReady
                ) {
                    return Ok(PreparedProcess {
                        inner: crate::process::SlotProcess {
                            supervisor: self,
                            index,
                            generation,
                            kind: slot.kind,
                        },
                    });
                }
                if let Some(error) = slot.terminal_error.clone() {
                    return Err(error);
                }
                if matches!(
                    slot.state,
                    SlotState::Complete | SlotState::Free | SlotState::Retired
                ) {
                    return Err(SupervisionError::new(
                        ErrorCode::HandoffFailed,
                        ErrorCategory::Setup,
                        false,
                        "launch completed without an active capability",
                    ));
                }
            }
            if Instant::now() >= deadline {
                self.mark_abandoned(index, generation);
                return Err(SupervisionError::cleanup(
                    ErrorCode::CleanupTimedOut,
                    "launch setup deadline expired; service retains the reserved slot",
                ));
            }
            let guard = match self.wake_lock.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            let remaining = deadline.saturating_duration_since(Instant::now());
            let _ = self
                .wake
                .wait_timeout(guard, remaining.min(SERVICE_POLL_INTERVAL));
        }
    }

    pub(crate) fn request_cleanup(
        &'static self,
        index: usize,
        generation: u64,
        deadline: Instant,
    ) -> Result<(), SupervisionError> {
        if index >= self.capacity() {
            return Err(SupervisionError::setup(
                ErrorCode::StaleOwnershipToken,
                "cleanup token index is stale",
            ));
        }
        {
            let slot = self.lock_slot(index);
            if slot.generation != generation {
                return Err(SupervisionError::setup(
                    ErrorCode::StaleOwnershipToken,
                    "cleanup token generation is stale",
                ));
            }
            if let Some(error) = slot.terminal_error.clone() {
                return Err(error);
            }
            if slot.state == SlotState::Complete {
                let terminal = slot.terminal_error.clone();
                drop(slot);
                self.release_slot(index, generation, terminal);
                return Ok(());
            }
            if !slot.occupied() {
                return Ok(());
            }
        }
        self.mark_cleanup(index, generation);
        loop {
            {
                let slot = self.lock_slot(index);
                if slot.generation != generation {
                    return Err(SupervisionError::setup(
                        ErrorCode::StaleOwnershipToken,
                        "cleanup generation became stale",
                    ));
                }
                if let Some(error) = slot.terminal_error.clone() {
                    return Err(error);
                }
                if slot.state == SlotState::Complete {
                    let terminal = slot.terminal_error.clone();
                    drop(slot);
                    self.release_slot(index, generation, terminal);
                    return Ok(());
                }
                if !slot.occupied() {
                    return Ok(());
                }
            }
            if Instant::now() >= deadline {
                return Err(SupervisionError::cleanup(
                    ErrorCode::CleanupTimedOut,
                    "cleanup deadline expired while service retained ownership",
                ));
            }
            let guard = match self.wake_lock.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            let remaining = deadline.saturating_duration_since(Instant::now());
            let _ = self
                .wake
                .wait_timeout(guard, remaining.min(SERVICE_POLL_INTERVAL));
        }
    }

    pub(crate) fn cached_exit(
        &self,
        index: usize,
        generation: u64,
    ) -> Result<Option<ExitInfo>, SupervisionError> {
        if index >= self.capacity() {
            return Err(SupervisionError::setup(
                ErrorCode::StaleOwnershipToken,
                "exit token index is stale",
            ));
        }
        let slot = self.lock_slot(index);
        if slot.generation != generation {
            return Err(SupervisionError::setup(
                ErrorCode::StaleOwnershipToken,
                "exit token generation is stale",
            ));
        }
        Ok(slot.exit)
    }

    pub(crate) fn activate(
        &'static self,
        index: usize,
        generation: u64,
        kind: PolicyKind,
    ) -> Result<PolicyKind, SupervisionError> {
        let mut slot = self.lock_slot(index);
        if slot.generation != generation {
            return Err(SupervisionError::setup(
                ErrorCode::StaleOwnershipToken,
                "activation token generation is stale",
            ));
        }
        if slot.kind != kind {
            return Err(SupervisionError::new(
                ErrorCode::InvariantViolation,
                ErrorCategory::Internal,
                false,
                "activation purpose does not match the reserved slot",
            ));
        }
        if slot.state == SlotState::Active {
            return Ok(kind);
        }
        if !matches!(
            slot.state,
            SlotState::HandoffPending | SlotState::ContainmentReady
        ) {
            return Err(SupervisionError::new(
                ErrorCode::AdmissionClosed,
                ErrorCategory::Setup,
                false,
                "useful-work activation was not available in the slot",
            ));
        }
        if self.admission_closed.load(Ordering::Acquire) {
            slot.state = SlotState::CleanupRequested;
            return Err(SupervisionError::new(
                ErrorCode::AdmissionClosed,
                ErrorCategory::Setup,
                false,
                "shutdown closed admission before useful-work activation",
            ));
        }
        slot.state = SlotState::Active;
        drop(slot);
        self.wake.notify_all();
        Ok(kind)
    }

    pub(crate) fn drain(&'static self, deadline: Instant) -> DrainReport {
        self.work_epoch.fetch_add(1, Ordering::AcqRel);
        self.service_pass(true, deadline)
    }

    pub(crate) fn status(&self) -> RegistryStatus {
        let capacity = self.capacity();
        let admission_closed = !self.lock_control().admission.accepts();
        let mut result = RegistryStatus {
            capacity,
            admission_closed,
            reserved: 0,
            active: 0,
            abandoned: 0,
            retrying: 0,
            quarantined: 0,
            pending: 0,
            handle_pending: 0,
            error_count: self.error_count(),
            retired: 0,
            service_running: self.service_state.load(Ordering::Acquire) == SERVICE_RUNNING,
            service_failed: self.service_state.load(Ordering::Acquire) == SERVICE_FAILED
                || self.poisoned.load(Ordering::Acquire),
        };
        for index in 0..capacity {
            let Some(slot) = self.try_slot(index) else {
                result.reserved += 1;
                result.pending += 1;
                continue;
            };
            if slot.occupied() {
                result.reserved += 1;
            }
            match slot.state {
                SlotState::Active => result.active += 1,
                SlotState::CleanupRequested | SlotState::Observing | SlotState::RootWaitable => {
                    result.pending += 1;
                    if self.abandoned_generation[index].load(Ordering::Acquire) == slot.generation {
                        result.abandoned += 1;
                    } else {
                        result.retrying += 1;
                    }
                }
                SlotState::ContainmentLost => {
                    result.pending += 1;
                    result.retrying += 1;
                }
                SlotState::Quarantined => {
                    result.pending += 1;
                    result.quarantined += 1;
                }
                SlotState::Reserved
                | SlotState::LaunchQueued
                | SlotState::Creating
                | SlotState::ChildOwned
                | SlotState::ContainmentReady
                | SlotState::HandoffPending
                | SlotState::Terminating
                | SlotState::Reaping
                | SlotState::HandlesClosing => result.pending += 1,
                SlotState::Free => {}
                SlotState::Complete => {}
                SlotState::Retired => result.retired += 1,
            }
            if slot.root.is_some() || slot.token.is_some() {
                result.handle_pending += 1;
            }
        }
        result
    }

    fn error_count(&self) -> usize {
        match self.errors.lock() {
            Ok(log) => log.length,
            Err(poisoned) => poisoned.into_inner().length,
        }
    }

    pub(crate) fn errors(&self) -> ErrorSnapshotSet {
        match self.errors.lock() {
            Ok(log) => log.snapshot(),
            Err(poisoned) => poisoned.into_inner().snapshot(),
        }
    }

    pub(crate) fn shutdown(
        &'static self,
        deadline: Instant,
    ) -> Result<ShutdownReport, SupervisionError> {
        {
            let mut control = self.lock_control();
            if control.admission == Admission::Joined {
                drop(control);
                return Ok(self.shutdown_report(true));
            }
            if control.admission == Admission::Open {
                // The atomic gate is the activation linearization point.  Set
                // it while root control is held, before publishing Closing,
                // so an activation that observes `false` is ordered before
                // shutdown and an activation that observes `true` cannot
                // return useful work after admission closes.
                self.admission_closed.store(true, Ordering::Release);
                control.admission = Admission::Closing;
                control.shutdown_epoch = control.shutdown_epoch.saturating_add(1);
            }
        }
        self.work_epoch.fetch_add(1, Ordering::AcqRel);
        self.wake.notify_all();
        while Instant::now() < deadline {
            if self.zero_owned() && self.lock_control().queue_len == 0 {
                break;
            }
            let guard = match self.wake_lock.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            let remaining = deadline.saturating_duration_since(Instant::now());
            let _ = self
                .wake
                .wait_timeout(guard, remaining.min(SERVICE_POLL_INTERVAL));
        }
        if !self.zero_owned() {
            let error = SupervisionError::new(
                ErrorCode::ShutdownIncomplete,
                ErrorCategory::Shutdown,
                true,
                "shutdown deadline expired while slot ownership remained",
            );
            self.record_error(error.clone());
            return Err(error);
        }
        let service_started = {
            let service = match self.service.lock() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    self.poisoned.store(true, Ordering::Release);
                    poisoned.into_inner()
                }
            };
            service.join.is_some()
        };
        if !service_started {
            // A root constructed for a pure/model test may be shut down
            // before admission ever starts the service.  There is no join
            // handle to await; acknowledge the stop transition directly
            // while retaining the same single global lifecycle state.
            self.service_state.store(SERVICE_STOPPED, Ordering::Release);
            self.service_ack.store(true, Ordering::Release);
            let mut control = self.lock_control();
            if control.admission.can_transition(Admission::Draining) {
                control.admission = Admission::Draining;
            }
            if control.admission.can_transition(Admission::StopRequested) {
                control.admission = Admission::StopRequested;
            }
            if control
                .admission
                .can_transition(Admission::StopAcknowledged)
            {
                control.admission = Admission::StopAcknowledged;
            }
            if control.admission.can_transition(Admission::Joined) {
                control.admission = Admission::Joined;
            }
            drop(control);
            return Ok(self.shutdown_report(true));
        }
        self.service_stop.store(true, Ordering::Release);
        self.wake.notify_all();
        while !self.service_ack.load(Ordering::Acquire) && Instant::now() < deadline {
            let guard = match self.wake_lock.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            let remaining = deadline.saturating_duration_since(Instant::now());
            let _ = self
                .wake
                .wait_timeout(guard, remaining.min(SERVICE_POLL_INTERVAL));
        }
        if !self.service_ack.load(Ordering::Acquire) {
            return Err(SupervisionError::new(
                ErrorCode::ShutdownIncomplete,
                ErrorCategory::Shutdown,
                true,
                "shutdown service acknowledgement did not arrive",
            ));
        }
        let join = {
            let mut service = match self.service.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            service.join.take()
        };
        if let Some(join) = join
            && join.join().is_err()
        {
            self.service_state.store(SERVICE_FAILED, Ordering::Release);
            return Err(SupervisionError::new(
                ErrorCode::ServiceFailed,
                ErrorCategory::Internal,
                false,
                "global service join panicked",
            ));
        }
        {
            let mut control = self.lock_control();
            if control.admission.can_transition(Admission::Draining) {
                control.admission = Admission::Draining;
            }
            if control.admission.can_transition(Admission::StopRequested) {
                control.admission = Admission::StopRequested;
            }
            if control
                .admission
                .can_transition(Admission::StopAcknowledged)
            {
                control.admission = Admission::StopAcknowledged;
            }
            if control.admission.can_transition(Admission::Joined) {
                control.admission = Admission::Joined;
            }
        }
        Ok(self.shutdown_report(true))
    }

    fn shutdown_report(&self, joined: bool) -> ShutdownReport {
        let status = self.status();
        ShutdownReport {
            admission_closed: status.admission_closed,
            complete: status.reserved == 0 && joined,
            reserved: status.reserved,
            quarantined: status.quarantined,
            handle_pending: status.handle_pending,
            service_joined: joined,
            service_failed: status.service_failed,
            error_count: status.error_count,
        }
    }

    pub(crate) fn spawn<P: PurposeMarker>(
        &'static self,
        spec: SpawnSpec<P>,
        cancellation: CancellationToken,
    ) -> Result<PreparedProcess, SupervisionError> {
        let reservation = self.reserve()?;
        let deadline = spec.deadline();
        let index = reservation.index;
        let generation = reservation.generation;
        if let Err(error) = self.enqueue(&reservation, spec, cancellation) {
            let mut reservation = reservation;
            reservation.active = false;
            self.cancel_reservation(index, generation, error.clone());
            return Err(error);
        }
        let mut reservation = reservation;
        reservation.active = false;
        self.await_launch(index, generation, deadline.instant())
    }

    fn cancel_reservation(&self, index: usize, generation: u64, error: SupervisionError) {
        let mut slot = self.lock_slot(index);
        if slot.generation != generation || slot.state != SlotState::Reserved {
            return;
        }
        slot.terminal_error = Some(error.clone());
        slot.state = SlotState::CleanupRequested;
        let _ = self.cleanup_slot(&mut slot, Instant::now());
        drop(slot);
        self.record_error(error.clone());
        self.release_slot(index, generation, Some(error));
    }
}

/// A copyable view of the one static supervisor.  It owns no state and cannot
/// be configured with a different capacity after initialization.
#[derive(Clone, Copy)]
pub(crate) struct ReaperRegistry {
    supervisor: &'static Supervisor,
}

impl ReaperRegistry {
    pub(crate) fn new(capacity: usize) -> Result<Self, SupervisionError> {
        validate_capacity(capacity)?;
        let supervisor = GLOBAL.get_or_init(|| Supervisor::new(capacity)).as_ref();
        if supervisor.capacity() != capacity {
            return Err(SupervisionError::new(
                ErrorCode::ConfigurationMismatch,
                ErrorCategory::Setup,
                false,
                "process-supervision global capacity differs from the first configuration",
            ));
        }
        supervisor.ensure_service()?;
        Ok(Self { supervisor })
    }

    pub(crate) fn default_global() -> Result<Self, SupervisionError> {
        Self::new(DEFAULT_REGISTRY_CAPACITY)
    }

    pub(crate) fn spawn<P: PurposeMarker>(
        &self,
        spec: SpawnSpec<P>,
        cancellation: CancellationToken,
    ) -> Result<PreparedProcess, SupervisionError> {
        self.supervisor.spawn(spec, cancellation)
    }

    pub(crate) fn drain(&self, deadline: Instant) -> DrainReport {
        self.supervisor.drain(deadline)
    }

    pub(crate) fn status(&self) -> RegistryStatus {
        self.supervisor.status()
    }

    pub(crate) fn errors(&self) -> ErrorSnapshotSet {
        self.supervisor.errors()
    }

    pub(crate) fn shutdown(&self, deadline: Instant) -> Result<ShutdownReport, SupervisionError> {
        self.supervisor.shutdown(deadline)
    }
}

/// A pre-reserved slot.  Dropping it marks abandonment atomically; the
/// service owns any queued/root resource and performs the eventual cleanup.
pub(crate) struct Reservation {
    supervisor: &'static Supervisor,
    index: usize,
    generation: u64,
    active: bool,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if self.active {
            self.supervisor.mark_abandoned(self.index, self.generation);
        }
    }
}

fn validate_capacity(capacity: usize) -> Result<(), SupervisionError> {
    if capacity == 0 || capacity > MAX_REGISTRY_CAPACITY {
        return Err(SupervisionError::setup(
            ErrorCode::Configuration,
            "process-supervision capacity is outside the fixed bound",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::model::{FakeBackend, FakeFailure, Model};

    #[test]
    fn capacity_and_generation_are_bounded_without_global_overwrite() {
        let mut model = Model::<1>::default();
        let (_, generation) = model.reserve().expect("first reservation");
        assert_eq!(
            model.reserve().expect_err("fixed capacity").code(),
            ErrorCode::ReaperCapacity
        );
        assert!(
            model
                .transition(0, generation + 1, SlotState::Active)
                .is_err()
        );
    }

    #[test]
    fn fake_cleanup_failures_are_observable_and_do_not_use_numeric_targets() {
        let mut fake = FakeBackend::default();
        fake.fail_at(FakeFailure::Signal);
        let (root, token) = fake.create().expect("fake root");
        assert_eq!(
            fake.signal(root, token).expect_err("signal failure").code(),
            ErrorCode::ProcessGroupSignalFailed
        );
        assert_eq!(fake.counts().2, 1);
    }

    #[test]
    fn error_ring_is_fixed_and_oldest_entries_are_bounded() {
        let supervisor = Supervisor::new(1);
        for _ in 0..(ERROR_SNAPSHOT_CAPACITY + 4) {
            supervisor.record_error(SupervisionError::setup(ErrorCode::HandoffFailed, "bounded"));
        }
        assert_eq!(supervisor.errors().len(), ERROR_SNAPSHOT_CAPACITY);
        assert_eq!(supervisor.errors().iter().count(), ERROR_SNAPSHOT_CAPACITY);
    }

    #[test]
    fn model_shutdown_closes_admission_before_reservation() {
        let mut model = Model::<1>::default();
        model.close_admission().expect("close admission");
        assert_eq!(
            model.reserve().expect_err("closed admission").code(),
            ErrorCode::AdmissionClosed
        );
    }

    #[test]
    fn poisoned_control_is_recovered_without_losing_bounded_status() {
        let supervisor = Supervisor::new(1);
        let control = &supervisor.control;
        std::thread::scope(|scope| {
            let join = scope.spawn(|| {
                let _guard = control.lock().expect("unpoisoned control");
                panic!("injected control poison");
            });
            assert!(join.join().is_err());
        });
        let status = supervisor.status();
        assert!(status.service_failed);
        assert_eq!(status.capacity, 1);
    }

    #[test]
    fn global_init_drop_and_shutdown_are_linearized_without_processes() {
        use std::time::Duration;

        let first = std::thread::spawn(|| ReaperRegistry::new(DEFAULT_REGISTRY_CAPACITY));
        let second = std::thread::spawn(|| ReaperRegistry::new(DEFAULT_REGISTRY_CAPACITY));
        let third = std::thread::spawn(|| ReaperRegistry::new(DEFAULT_REGISTRY_CAPACITY));
        let fourth = std::thread::spawn(|| ReaperRegistry::new(DEFAULT_REGISTRY_CAPACITY));
        let registries = [
            first.join().expect("init thread").expect("first init"),
            second.join().expect("init thread").expect("second init"),
            third.join().expect("init thread").expect("third init"),
            fourth.join().expect("init thread").expect("fourth init"),
        ];

        let reservation = registries[0]
            .supervisor
            .reserve()
            .expect("reserved slot for drop probe");
        let index = reservation.index;
        let generation = reservation.generation;
        drop(reservation);
        let report = registries[0].drain(Instant::now() + Duration::from_millis(250));
        assert!(report.completed <= 1);
        assert_eq!(registries[0].supervisor.slot_generation(index), generation);
        assert_eq!(registries[0].status().reserved, 0);

        let deadline = Instant::now() + Duration::from_secs(1);
        let r0 = registries[0];
        let r1 = registries[1];
        let r2 = registries[2];
        let r3 = registries[3];
        let shutdowns = [
            std::thread::spawn(move || r0.shutdown(deadline)),
            std::thread::spawn(move || r1.shutdown(deadline)),
            std::thread::spawn(move || r2.shutdown(deadline)),
            std::thread::spawn(move || r3.shutdown(deadline)),
        ];
        for shutdown in shutdowns {
            assert!(shutdown.join().expect("shutdown thread").is_ok());
        }
    }
}
