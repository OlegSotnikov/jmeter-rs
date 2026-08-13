// SPDX-License-Identifier: Apache-2.0
//! Slot capabilities, cancellation, and bounded cleanup result types.

use crate::error::{CleanupState, ErrorCategory, ErrorCode, SupervisionError};
use crate::platform::{self, PlatformToken, RootHandle};
use crate::policy::PolicyKind;
use crate::registry::Supervisor;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Fixed automatic cleanup budget for an abandoned slot.
pub const DEFAULT_CLEANUP_TIMEOUT: Duration = Duration::from_millis(250);
/// Fixed service wake interval.  The service remains interruptible below the
/// ADR's ten-millisecond maximum tick.
pub(crate) const SERVICE_POLL_INTERVAL: Duration = Duration::from_millis(10);
/// Automatic attempts before a slot becomes quarantined.
pub(crate) const MAX_AUTOMATIC_ATTEMPTS: u8 = 3;

/// Cooperative cancellation source.  It carries no process ownership; the
/// static supervisor remains the sole owner of roots and platform tokens.
#[derive(Clone, Debug, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    /// Creates a non-cancelled token.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests cancellation monotonically.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    /// Returns whether cancellation was requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

/// A private cleanup operation result; ownership is never moved to a local
/// task while this value is being computed.
#[derive(Debug)]
pub(crate) struct CleanupAttempt {
    pub(crate) state: CleanupState,
    pub(crate) error: Option<SupervisionError>,
}

impl CleanupAttempt {
    pub(crate) const fn reaped() -> Self {
        Self {
            state: CleanupState::Reaped,
            error: None,
        }
    }

    pub(crate) fn retained(error: SupervisionError) -> Self {
        Self {
            state: CleanupState::Retained,
            error: Some(error),
        }
    }
}

/// Observed exact-root state used by the in-place service state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RootObservation {
    Live,
    Waitable(ExitInfo),
}

/// Bounded platform-independent exit detail.  The public edge never exposes
/// a platform `Child`, PID, or handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExitInfo {
    pub(crate) code: i32,
    pub(crate) signaled: bool,
}

/// The private slot capability shared by the prepared and active phases.  It
/// stores only an index/generation and sealed kind; the process and every
/// platform token remain in the static slot.  It is intentionally not
/// `Clone`.
pub(crate) struct SlotProcess {
    pub(crate) supervisor: &'static Supervisor,
    pub(crate) index: usize,
    pub(crate) generation: u64,
    pub(crate) kind: PolicyKind,
}

impl core::fmt::Debug for SlotProcess {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SlotProcess")
            .field("slot", &self.index)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

impl Drop for SlotProcess {
    fn drop(&mut self) {
        // Strictly atomic-only: no lock, allocation, Condvar, wait, signal,
        // formatting, or OS call.  The service notices the epoch on its
        // bounded tick and retains all resources in the static slot.
        self.supervisor.mark_abandoned(self.index, self.generation);
    }
}

impl SlotProcess {
    /// Requests bounded supervisor-owned cleanup.
    pub(crate) fn cleanup(&self, deadline: Instant) -> Result<(), SupervisionError> {
        self.supervisor
            .request_cleanup(self.index, self.generation, deadline)
    }

    /// Attempts cleanup while preserving the stable cancellation result.
    pub(crate) fn cleanup_with_cancellation(
        &self,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<(), SupervisionError> {
        let result = self.cleanup(deadline);
        if cancellation.is_cancelled() {
            let cancelled = SupervisionError::cancelled(
                "cleanup was cancelled after the supervisor retained ownership",
            );
            return match result {
                Ok(()) => Err(cancelled),
                Err(error) => Err(cancelled.with_secondary(error)),
            };
        }
        result
    }

    /// Returns cached exit detail without exposing a numeric process target.
    pub(crate) fn exit_info(&self) -> Result<Option<ExitInfo>, SupervisionError> {
        self.supervisor.cached_exit(self.index, self.generation)
    }
}

/// Prepared capability before the adapter's identity handshake.  It has the
/// same constant-time Drop semantics as the active capability and can become
/// active only through the supervisor's linearized admission gate.
pub(crate) struct PreparedProcess {
    pub(crate) inner: SlotProcess,
}

/// Active useful-work capability.  Both lifecycle phases are single-owner and
/// non-`Clone`; neither token contains a child, PID, group, Job, or handle.
pub(crate) struct ActiveProcess {
    pub(crate) inner: SlotProcess,
}

impl PreparedProcess {
    pub(crate) fn activate(self) -> Result<ActiveProcess, SupervisionError> {
        let PreparedProcess { inner } = self;
        inner
            .supervisor
            .activate(inner.index, inner.generation, inner.kind)?;
        Ok(ActiveProcess { inner })
    }
}

impl ActiveProcess {
    pub(crate) fn cleanup(&self, deadline: Instant) -> Result<(), SupervisionError> {
        self.inner.cleanup(deadline)
    }

    pub(crate) fn cleanup_with_cancellation(
        &self,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<(), SupervisionError> {
        self.inner.cleanup_with_cancellation(deadline, cancellation)
    }

    pub(crate) fn exit_info(&self) -> Result<Option<ExitInfo>, SupervisionError> {
        self.inner.exit_info()
    }
}

/// Computes a bounded absolute deadline without overflowing.
pub(crate) fn deadline_after(timeout: Duration) -> Instant {
    Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now)
}

/// Performs one in-place cleanup operation.  The caller retains mutable
/// references to the slot's root and token for the complete operation.
pub(crate) fn cleanup_owned(
    root: &mut RootHandle,
    kind: PolicyKind,
    token: &mut Option<PlatformToken>,
    tree_failure: &mut Option<SupervisionError>,
    deadline: Instant,
) -> CleanupAttempt {
    let attempt = platform::cleanup(root, token, kind, deadline);
    if let Some(tree_error) = tree_failure.as_ref().cloned() {
        preserve_tree_error(tree_error, attempt)
    } else {
        attempt
    }
}

/// Keep a containment failure primary even when exact-root fallback reaps.
pub(crate) fn preserve_tree_error(
    tree_error: SupervisionError,
    exact: CleanupAttempt,
) -> CleanupAttempt {
    match exact.state {
        CleanupState::Reaped => CleanupAttempt {
            state: CleanupState::Reaped,
            error: Some(match exact.error {
                Some(error) => tree_error.with_secondary(error),
                None => tree_error,
            }),
        },
        CleanupState::Retained => CleanupAttempt {
            state: CleanupState::Retained,
            error: Some(tree_error.with_secondary(exact.error.unwrap_or_else(|| {
                SupervisionError::cleanup(
                    ErrorCode::CleanupTimedOut,
                    "exact-root fallback remains owned",
                )
            }))),
        },
    }
}

/// Whether the diagnostic is a terminal tree-identity failure.
pub(crate) const fn is_containment_failure(error: &SupervisionError) -> bool {
    matches!(
        error.code(),
        ErrorCode::ContainmentLost
            | ErrorCode::ContainmentAmbiguous
            | ErrorCode::ReaperContractLost
            | ErrorCode::ProcessGroupMismatch
            | ErrorCode::InvalidProcessGroupId
    ) || matches!(error.category(), ErrorCategory::Containment)
}

/// Fixed retry helper used by pure tests.  It is deliberately not used by
/// caller `Drop`; the production service owns retry scheduling.
#[cfg(test)]
pub(crate) fn bounded_attempts(mut f: impl FnMut() -> bool) -> bool {
    for _ in 0..MAX_AUTOMATIC_ATTEMPTS {
        if f() {
            return true;
        }
    }
    false
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn tree_diagnostic_remains_primary_after_exact_root_reap() {
        let tree = SupervisionError::new(
            ErrorCode::ContainmentLost,
            ErrorCategory::Containment,
            false,
            "tree proof lost",
        );
        let exact = CleanupAttempt {
            state: CleanupState::Reaped,
            error: Some(SupervisionError::cleanup(
                ErrorCode::WaitFailed,
                "exact wait detail",
            )),
        };
        let result = preserve_tree_error(tree, exact);
        assert_eq!(result.state, CleanupState::Reaped);
        assert_eq!(
            result.error.expect("diagnostic").code(),
            ErrorCode::ContainmentLost
        );
    }
}
