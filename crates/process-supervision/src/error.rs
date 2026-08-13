// SPDX-License-Identifier: Apache-2.0
//! Stable, bounded diagnostics for the process-supervision boundary.

use core::fmt;
use std::error::Error;

/// Maximum bytes retained for one human diagnostic.  Stable error codes are
/// the compatibility surface; text is only bounded context.
pub(crate) const MAX_DIAGNOSTIC_BYTES: usize = 512;

/// Machine-readable process-supervision failures.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum ErrorCode {
    /// The launch description or supervisor capacity is invalid.
    Configuration = 1,
    /// The process-tree primitive is not available on this target.
    UnsupportedPlatform = 2,
    /// The fixed ownership root has no free slot.
    ReaperCapacity = 3,
    /// A second global capacity disagrees with the first configuration.
    ConfigurationMismatch = 4,
    /// Admission closed before the request became useful work.
    AdmissionClosed = 5,
    /// The bounded service could not start or stopped unexpectedly.
    ServiceStartFailed = 6,
    /// The service panicked; all slot ownership remains observable.
    ServiceFailed = 7,
    /// A slot lock was poisoned; ownership was retained in place.
    RegistryPoisoned = 8,
    /// A request could not enter the fixed launch queue.
    QueueFull = 9,
    /// A resource could not be installed in its pre-reserved slot.
    HandoffFailed = 10,
    /// The platform rejected exact process creation.
    SpawnFailed = 11,
    /// The root exited before containment was proven.
    RootExitedBeforeTreeCleanup = 12,
    /// A process group or Job no longer proves containment.
    ContainmentLost = 13,
    /// A lookup or validation result was ambiguous.
    ContainmentAmbiguous = 14,
    /// A process-group/root identity is reserved or invalid.
    InvalidProcessGroupId = 15,
    /// The root process-group lookup failed.
    ProcessGroupLookupFailed = 16,
    /// The observed group did not equal the retained root identity.
    ProcessGroupMismatch = 17,
    /// The safe process-group operation failed.
    ProcessGroupSignalFailed = 18,
    /// Exact-child termination failed.
    ExactChildSignalFailed = 19,
    /// The sole reaper returned an unexpected error.
    ReaperContractLost = 20,
    /// Exact-root observation/reaping failed.
    WaitFailed = 21,
    /// A bounded cleanup deadline expired.
    CleanupTimedOut = 22,
    /// The fixed automatic budget was exhausted; ownership is quarantined.
    Quarantined = 23,
    /// A retained platform token could not be closed.
    HandleCloseFailed = 24,
    /// Windows cannot prove whether a raw handle close took effect.
    HandleStateUnknown = 25,
    /// The caller supplied a stale slot generation.
    StaleOwnershipToken = 26,
    /// The operation was cancelled; cleanup remains supervisor-owned.
    Cancelled = 27,
    /// Shutdown reached its deadline with ownership/service state retained.
    ShutdownIncomplete = 28,
    /// An internal state transition was invalid.
    InvariantViolation = 29,
    /// An exact root has been reaped but a tree diagnostic remains primary.
    GroupCleanupCompleted = 30,
    /// Windows Job creation/configuration failed.
    JobCreateFailed = 31,
    /// Windows Job assignment failed.
    JobAssignmentFailed = 32,
    /// Windows Job termination failed.
    JobTerminationFailed = 33,
    /// Windows suspended-thread resume did not prove count one.
    ThreadResumeFailed = 34,
}

impl ErrorCode {
    /// Returns the stable machine spelling for this code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Configuration => "process_supervision.configuration",
            Self::UnsupportedPlatform => "process_supervision.unsupported_platform",
            Self::ReaperCapacity => "process_supervision.reaper_capacity",
            Self::ConfigurationMismatch => "process_supervision.configuration_mismatch",
            Self::AdmissionClosed => "process_supervision.admission_closed",
            Self::ServiceStartFailed => "process_supervision.service_start_failed",
            Self::ServiceFailed => "process_supervision.service_failed",
            Self::RegistryPoisoned => "process_supervision.registry_poisoned",
            Self::QueueFull => "process_supervision.queue_full",
            Self::HandoffFailed => "process_supervision.handoff_failed",
            Self::SpawnFailed => "process_supervision.spawn_failed",
            Self::RootExitedBeforeTreeCleanup => {
                "process_supervision.root_exited_before_tree_cleanup"
            }
            Self::ContainmentLost => "process_supervision.containment_lost",
            Self::ContainmentAmbiguous => "process_supervision.containment_ambiguous",
            Self::InvalidProcessGroupId => "process_supervision.invalid_process_group_id",
            Self::ProcessGroupLookupFailed => "process_supervision.process_group_lookup_failed",
            Self::ProcessGroupMismatch => "process_supervision.process_group_mismatch",
            Self::ProcessGroupSignalFailed => "process_supervision.process_group_signal_failed",
            Self::ExactChildSignalFailed => "process_supervision.exact_child_signal_failed",
            Self::ReaperContractLost => "process_supervision.reaper_contract_lost",
            Self::WaitFailed => "process_supervision.wait_failed",
            Self::CleanupTimedOut => "process_supervision.cleanup_timed_out",
            Self::Quarantined => "process_supervision.quarantined",
            Self::HandleCloseFailed => "process_supervision.handle_close_failed",
            Self::HandleStateUnknown => "process_supervision.handle_state_unknown",
            Self::StaleOwnershipToken => "process_supervision.stale_ownership_token",
            Self::Cancelled => "process_supervision.cancelled",
            Self::ShutdownIncomplete => "process_supervision.shutdown_incomplete",
            Self::InvariantViolation => "process_supervision.invariant_violation",
            Self::GroupCleanupCompleted => "process_supervision.group_cleanup_completed",
            Self::JobCreateFailed => "process_supervision.job_create_failed",
            Self::JobAssignmentFailed => "process_supervision.job_assignment_failed",
            Self::JobTerminationFailed => "process_supervision.job_termination_failed",
            Self::ThreadResumeFailed => "process_supervision.thread_resume_failed",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Bounded high-level category used by adapters and diagnostics.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ErrorCategory {
    /// Admission, launch, or state setup failed.
    Setup,
    /// The process-tree ownership proof was lost or ambiguous.
    Containment,
    /// Exact-root observation or reaping failed.
    Reaping,
    /// The bounded cleanup service still owns a resource.
    Cleanup,
    /// The caller requested cancellation.
    Cancellation,
    /// Global shutdown could not reach zero ownership in time.
    Shutdown,
    /// The target cannot provide the requested primitive.
    Unsupported,
    /// An implementation invariant failed.
    Internal,
}

/// A one-level bounded secondary diagnostic.  Keeping a summary rather than a
/// recursively boxed error prevents a failure storm from becoming unbounded
/// storage while preserving the primary tree/containment code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErrorSummary {
    /// Stable secondary code.
    pub code: ErrorCode,
    /// Secondary category.
    pub category: ErrorCategory,
    /// Whether the secondary operation can be retried.
    pub retryable: bool,
    /// Bounded secondary detail.
    pub message: String,
}

/// A typed, bounded process-supervision error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupervisionError {
    code: ErrorCode,
    category: ErrorCategory,
    retryable: bool,
    message: String,
    os_error: Option<i32>,
    secondary: Option<ErrorSummary>,
}

impl SupervisionError {
    /// Creates a bounded typed error.
    #[must_use]
    pub fn new(
        code: ErrorCode,
        category: ErrorCategory,
        retryable: bool,
        message: impl AsRef<str>,
    ) -> Self {
        Self {
            code,
            category,
            retryable,
            message: bounded_message(message.as_ref()),
            os_error: None,
            secondary: None,
        }
    }

    /// Creates a terminal setup error.
    #[must_use]
    pub fn setup(code: ErrorCode, message: impl AsRef<str>) -> Self {
        Self::new(code, ErrorCategory::Setup, false, message)
    }

    /// Creates a retryable cleanup error.
    #[must_use]
    pub fn cleanup(code: ErrorCode, message: impl AsRef<str>) -> Self {
        Self::new(code, ErrorCategory::Cleanup, true, message)
    }

    /// Creates the stable cancellation result.
    #[must_use]
    pub fn cancelled(message: impl AsRef<str>) -> Self {
        Self::new(
            ErrorCode::Cancelled,
            ErrorCategory::Cancellation,
            false,
            message,
        )
    }

    /// Returns the stable machine code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        self.code
    }

    /// Returns the broad category.
    #[must_use]
    pub const fn category(&self) -> ErrorCategory {
        self.category
    }

    /// Returns whether a bounded retry may make progress.
    #[must_use]
    pub const fn retryable(&self) -> bool {
        self.retryable
    }

    /// Returns bounded human context.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns an OS code when the platform supplied one.
    #[must_use]
    pub const fn os_error(&self) -> Option<i32> {
        self.os_error
    }

    /// Returns the bounded secondary summary, if any.
    #[must_use]
    pub fn secondary(&self) -> Option<&ErrorSummary> {
        self.secondary.as_ref()
    }

    /// Attaches an OS code without changing the stable category.
    #[must_use]
    pub const fn with_os_error(mut self, value: i32) -> Self {
        self.os_error = Some(value);
        self
    }

    /// Retains one bounded secondary failure while preserving this primary.
    #[must_use]
    pub fn with_secondary(mut self, error: SupervisionError) -> Self {
        self.secondary = Some(ErrorSummary {
            code: error.code,
            category: error.category,
            retryable: error.retryable,
            message: error.message,
        });
        self
    }
}

impl fmt::Display for SupervisionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for SupervisionError {}

/// Result state of one in-place cleanup attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CleanupState {
    /// The exact root was reaped and all platform ownership is closable.
    Reaped,
    /// At least one owned resource remains in the slot.
    Retained,
}

/// Bounded human text copied from an OS/library diagnostic.
pub(crate) fn bounded_message(message: &str) -> String {
    if message.len() <= MAX_DIAGNOSTIC_BYTES {
        return message.to_owned();
    }
    let mut end = MAX_DIAGNOSTIC_BYTES.saturating_sub(3);
    while end > 0 && !message.is_char_boundary(end) {
        end -= 1;
    }
    let mut result = message[..end].to_owned();
    result.push('…');
    result
}

/// Maps an I/O error without retaining an unbounded source string.
pub(crate) fn io_error(
    code: ErrorCode,
    category: ErrorCategory,
    context: &str,
    error: &std::io::Error,
) -> SupervisionError {
    let mut result = SupervisionError::new(code, category, true, context);
    result.message = bounded_message(&format!("{context}: {error}"));
    result.retryable = matches!(category, ErrorCategory::Cleanup | ErrorCategory::Reaping);
    result.os_error = error.raw_os_error();
    result
}
