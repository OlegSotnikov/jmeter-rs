// SPDX-License-Identifier: Apache-2.0
//! Unix retained-root ownership boundary.
//!
//! The supervisor is the sole reaper.  Every observation uses
//! `rustix::process::waitid(P_PID, WEXITED | WNOHANG | WNOWAIT)`, retaining a
//! waitable zombie until the final validated group operation has completed.
//! No `Child::try_wait`, `Child::wait`, `waitpid(-1)`, or broad wait is used.

use crate::error::{CleanupState, ErrorCategory, ErrorCode, SupervisionError};
use crate::platform::CreateFailure;
use crate::policy::PolicyKind;
use crate::process::{CleanupAttempt, ExitInfo, RootObservation};
use crate::spec::LaunchSpec;
use rustix::process::{Pid, Signal, WaitId, WaitIdOptions, getpgid, kill_process_group, waitid};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::Instant;

/// Root process and its exact identity.  The `Child` remains in this cell
/// until rustix has reaped it; it never crosses the slot capability boundary.
#[derive(Debug)]
pub(crate) struct UnixRoot {
    pub(crate) child: Child,
    pub(crate) pid: u32,
    pub(crate) waitable: bool,
    pub(crate) reaped: bool,
    pub(crate) exit: Option<ExitInfo>,
}

/// A validated process-group token.  Construction is private and requires
/// equality with the still-owned root PID and a value greater than one.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct ValidatedProcessGroup(i32);

impl ValidatedProcessGroup {
    pub(crate) fn raw(self) -> i32 {
        self.0
    }
}

/// Unix process-group ownership stored in the slot.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct UnixProcessGroupToken {
    pub(crate) root_pid: u32,
    pub(crate) group: ValidatedProcessGroup,
}

pub(crate) type RootHandle = UnixRoot;
pub(crate) type PlatformToken = UnixProcessGroupToken;

/// Builds the internal command only after the private typed specification has
/// passed validation.  `process_group(0)` is the sole process-group creation
/// request; no shell or external utility is involved.
// The failure carries the exact `Child` by value so a fallible allocation is
// not introduced between spawn and reserved-slot handoff.
#[allow(clippy::result_large_err)]
pub(crate) fn create_root(
    spec: &LaunchSpec,
) -> Result<(RootHandle, Option<PlatformToken>), CreateFailure> {
    spec.validate()?;
    let mut command = Command::new(spec.executable.as_str());
    command.args(spec.arguments.iter());
    command.current_dir(spec.working_root.as_str());
    command.env_clear();
    for (key, value) in spec.environment.iter() {
        command.env(key, value);
    }
    command.stdin(Stdio::null());
    command.stdout(Stdio::null());
    command.stderr(Stdio::null());
    if spec.kind().requires_tree() {
        // SAFETY: `process_group(0)` is the standard-library safe wrapper for
        // the child-side setpgid operation.  It asks the newly-created root
        // to lead only its own group; no numeric signal target is formed.
        command.process_group(0);
    }
    let child = command.spawn().map_err(|error| {
        let mut result = SupervisionError::new(
            ErrorCode::SpawnFailed,
            ErrorCategory::Setup,
            false,
            "internal command spawn failed",
        );
        result = result.with_os_error(error.raw_os_error().unwrap_or(0));
        CreateFailure::without_resources(result)
    })?;
    let pid = child.id();
    let root = UnixRoot {
        child,
        pid,
        waitable: false,
        reaped: false,
        exit: None,
    };
    Ok((root, None))
}

/// Proves the process-group token while the exact root is retained in the
/// slot.  Root exit, ECHILD, mismatch, and reserved identities fail closed.
pub(crate) fn validate(
    root: &mut RootHandle,
    token: &mut Option<PlatformToken>,
    kind: PolicyKind,
) -> Result<(), SupervisionError> {
    if kind == PolicyKind::ExactChild {
        return Ok(());
    }
    let root_pid = validate_process_group_id(root.pid)?;
    match observe(root)? {
        RootObservation::Live => {}
        RootObservation::Waitable(_) => {
            return Err(SupervisionError::new(
                ErrorCode::RootExitedBeforeTreeCleanup,
                ErrorCategory::Containment,
                false,
                "root became waitable before process-group ownership was proven",
            ));
        }
    }
    let group = getpgid_for_root(root_pid)?;
    let validated = validate_group_id(group, root.pid)?;
    *token = Some(UnixProcessGroupToken {
        root_pid: root.pid,
        group: validated,
    });
    Ok(())
}

/// Observes the exact root with `WNOWAIT`, preserving its PID/PGID identity.
pub(crate) fn observe(root: &mut RootHandle) -> Result<RootObservation, SupervisionError> {
    if root.reaped || root.waitable {
        return Ok(RootObservation::Waitable(root.exit.unwrap_or(ExitInfo {
            code: 0,
            signaled: false,
        })));
    }
    let pid = pid_for_root(root.pid)?;
    let options = WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT;
    match waitid(WaitId::Pid(pid), options) {
        Ok(None) => Ok(RootObservation::Live),
        Ok(Some(status)) => {
            let info = exit_info(status.exited(), status.exit_status().unwrap_or(0));
            root.waitable = true;
            root.exit = Some(info);
            Ok(RootObservation::Waitable(info))
        }
        Err(error) if error == rustix::io::Errno::CHILD => Err(SupervisionError::new(
            ErrorCode::ReaperContractLost,
            ErrorCategory::Containment,
            false,
            "waitid reported ECHILD for the retained exact root",
        )
        .with_os_error(error.raw_os_error())),
        Err(error) => Err(SupervisionError::new(
            ErrorCode::WaitFailed,
            ErrorCategory::Reaping,
            true,
            "waitid exact-root observation failed",
        )
        .with_os_error(error.raw_os_error())),
    }
}

/// Returns a cached root exit without issuing another wait operation.
pub(crate) fn root_exit(root: &RootHandle) -> Option<ExitInfo> {
    root.exit
}

/// Performs one bounded in-place cleanup pass.
pub(crate) fn cleanup(
    root: &mut RootHandle,
    token: &mut Option<PlatformToken>,
    kind: PolicyKind,
    deadline: Instant,
) -> CleanupAttempt {
    match kind {
        PolicyKind::ExactChild => cleanup_exact(root, deadline),
        PolicyKind::ProcessTree => cleanup_tree(root, token, deadline),
    }
}

/// Closes a Unix token.  The group number is invalidated by dropping the
/// fixed token only after exact-root reaping has succeeded.
pub(crate) fn close_token(_: &mut PlatformToken) -> Result<(), SupervisionError> {
    Ok(())
}

fn cleanup_exact(root: &mut RootHandle, deadline: Instant) -> CleanupAttempt {
    match observe(root) {
        Ok(RootObservation::Waitable(_)) => return reap_root(root, deadline),
        Ok(RootObservation::Live) => {}
        Err(error) => return CleanupAttempt::retained(error),
    }
    if let Err(error) = root.child.kill() {
        let signal_error = SupervisionError::new(
            ErrorCode::ExactChildSignalFailed,
            ErrorCategory::Reaping,
            true,
            "exact-child termination failed",
        )
        .with_os_error(error.raw_os_error().unwrap_or(0));
        return match observe(root) {
            Ok(RootObservation::Waitable(_)) => {
                let reap = reap_root(root, deadline);
                preserve(signal_error, reap)
            }
            Ok(RootObservation::Live) => CleanupAttempt::retained(signal_error),
            Err(observe_error) => {
                CleanupAttempt::retained(signal_error.with_secondary(observe_error))
            }
        };
    }
    reap_root(root, deadline)
}

fn cleanup_tree(
    root: &mut RootHandle,
    token: &mut Option<PlatformToken>,
    deadline: Instant,
) -> CleanupAttempt {
    let Some(token_value) = token.as_ref().copied() else {
        // Containment setup can fail before a token is installed.  The exact
        // Child remains in the slot and is still eligible for the safe
        // waitid/Child fallback; preserve the tree failure separately.
        return fallback_exact(
            root,
            deadline,
            SupervisionError::new(
                ErrorCode::ContainmentAmbiguous,
                ErrorCategory::Containment,
                false,
                "process-tree slot has no validated process-group token",
            ),
        );
    };
    if token_value.root_pid != root.pid {
        return fallback_exact(
            root,
            deadline,
            SupervisionError::new(
                ErrorCode::ContainmentLost,
                ErrorCategory::Containment,
                false,
                "retained process-group token does not belong to the exact root",
            ),
        );
    }
    match observe(root) {
        Ok(RootObservation::Waitable(_)) => {
            let tree = SupervisionError::new(
                ErrorCode::RootExitedBeforeTreeCleanup,
                ErrorCategory::Containment,
                false,
                "root exited before a validated group signal",
            );
            return preserve(tree, reap_root(root, deadline));
        }
        Ok(RootObservation::Live) => {}
        Err(error) => return CleanupAttempt::retained(error),
    }
    if let Err(error) = validate_group_against_root(root, token_value) {
        return fallback_exact(root, deadline, error);
    }
    // Adjacent exact-root observation immediately before the only group
    // signal.  A waitable root never receives a numeric group operation.
    match observe(root) {
        Ok(RootObservation::Waitable(_)) => {
            let tree = SupervisionError::new(
                ErrorCode::RootExitedBeforeTreeCleanup,
                ErrorCategory::Containment,
                false,
                "root exited during group revalidation",
            );
            preserve(tree, reap_root(root, deadline))
        }
        Ok(RootObservation::Live) => {
            match pid_for_group(token_value.group).and_then(|group| {
                kill_process_group(group, Signal::KILL).map_err(|error| {
                    SupervisionError::new(
                        ErrorCode::ProcessGroupSignalFailed,
                        ErrorCategory::Containment,
                        true,
                        "validated process-group signal failed",
                    )
                    .with_os_error(error.raw_os_error())
                })
            }) {
                Ok(()) => wait_after_group_signal(root, deadline),
                Err(error) => fallback_exact(root, deadline, error),
            }
        }
        Err(error) => CleanupAttempt::retained(error),
    }
}

fn wait_after_group_signal(root: &mut RootHandle, deadline: Instant) -> CleanupAttempt {
    loop {
        match observe(root) {
            Ok(RootObservation::Waitable(_)) => {
                let reaped = reap_root(root, deadline);
                return match reaped.state {
                    CleanupState::Reaped => CleanupAttempt {
                        state: CleanupState::Reaped,
                        error: Some(SupervisionError::new(
                            ErrorCode::GroupCleanupCompleted,
                            ErrorCategory::Containment,
                            false,
                            "validated observed process group cleanup reaped the root",
                        )),
                    },
                    CleanupState::Retained => reaped,
                };
            }
            Ok(RootObservation::Live) if Instant::now() < deadline => {
                std::thread::yield_now();
            }
            Ok(RootObservation::Live) => {
                return CleanupAttempt::retained(SupervisionError::cleanup(
                    ErrorCode::CleanupTimedOut,
                    "group cleanup deadline expired while root remained live",
                ));
            }
            Err(error) => return CleanupAttempt::retained(error),
        }
    }
}

fn reap_root(root: &mut RootHandle, deadline: Instant) -> CleanupAttempt {
    if root.reaped {
        return CleanupAttempt::reaped();
    }
    let pid = match pid_for_root(root.pid) {
        Ok(pid) => pid,
        Err(error) => return CleanupAttempt::retained(error),
    };
    loop {
        let options = WaitIdOptions::EXITED | WaitIdOptions::NOHANG;
        match waitid(WaitId::Pid(pid), options) {
            Ok(Some(status)) => {
                root.waitable = true;
                root.exit = Some(exit_info(
                    status.exited(),
                    status.exit_status().unwrap_or(0),
                ));
                root.reaped = true;
                return CleanupAttempt::reaped();
            }
            Ok(None) if Instant::now() < deadline => std::thread::yield_now(),
            Ok(None) => {
                return CleanupAttempt::retained(SupervisionError::cleanup(
                    ErrorCode::CleanupTimedOut,
                    "exact-root reap deadline expired",
                ));
            }
            Err(error) if error == rustix::io::Errno::CHILD => {
                return CleanupAttempt::retained(SupervisionError::new(
                    ErrorCode::ReaperContractLost,
                    ErrorCategory::Reaping,
                    false,
                    "exact-root reap returned ECHILD",
                ));
            }
            Err(error) => {
                return CleanupAttempt::retained(
                    SupervisionError::new(
                        ErrorCode::WaitFailed,
                        ErrorCategory::Reaping,
                        true,
                        "exact-root reap failed",
                    )
                    .with_os_error(error.raw_os_error()),
                );
            }
        }
    }
}

fn fallback_exact(
    root: &mut RootHandle,
    deadline: Instant,
    tree_error: SupervisionError,
) -> CleanupAttempt {
    match observe(root) {
        Ok(RootObservation::Waitable(_)) => preserve(tree_error, reap_root(root, deadline)),
        Ok(RootObservation::Live) => {
            if let Err(error) = root.child.kill() {
                let exact = SupervisionError::new(
                    ErrorCode::ExactChildSignalFailed,
                    ErrorCategory::Reaping,
                    true,
                    "exact-child fallback termination failed",
                )
                .with_os_error(error.raw_os_error().unwrap_or(0));
                // Re-observe immediately around a direct-child failure.  The
                // kill may have raced an ordinary root exit; only a fresh
                // exact-root waitid result can distinguish that case without
                // treating a stale numeric PID as owned.
                let adjacent = match observe(root) {
                    Ok(RootObservation::Waitable(_)) => reap_root(root, deadline),
                    Ok(RootObservation::Live) => CleanupAttempt::retained(exact),
                    Err(observe_error) => {
                        CleanupAttempt::retained(exact.with_secondary(observe_error))
                    }
                };
                return preserve(tree_error, adjacent);
            }
            preserve(tree_error, reap_root(root, deadline))
        }
        Err(error) => preserve(tree_error, CleanupAttempt::retained(error)),
    }
}

fn preserve(primary: SupervisionError, secondary: CleanupAttempt) -> CleanupAttempt {
    match secondary.state {
        CleanupState::Reaped => CleanupAttempt {
            state: CleanupState::Reaped,
            error: Some(match secondary.error {
                Some(error) => primary.with_secondary(error),
                None => primary,
            }),
        },
        CleanupState::Retained => {
            CleanupAttempt::retained(primary.with_secondary(secondary.error.unwrap_or_else(|| {
                SupervisionError::cleanup(ErrorCode::CleanupTimedOut, "exact fallback retained")
            })))
        }
    }
}

fn getpgid_for_root(root_pid: i32) -> Result<i32, SupervisionError> {
    let pid = pid_for_root(root_pid as u32)?;
    getpgid(Some(pid))
        .map(|value| value.as_raw_pid())
        .map_err(|error| {
            if error == rustix::io::Errno::CHILD {
                SupervisionError::new(
                    ErrorCode::ReaperContractLost,
                    ErrorCategory::Containment,
                    false,
                    "getpgid returned ECHILD for the retained root",
                )
            } else {
                SupervisionError::new(
                    ErrorCode::ProcessGroupLookupFailed,
                    ErrorCategory::Containment,
                    true,
                    "getpgid failed for the retained root",
                )
                .with_os_error(error.raw_os_error())
            }
        })
}

fn validate_group_against_root(
    root: &RootHandle,
    token: UnixProcessGroupToken,
) -> Result<(), SupervisionError> {
    let root_pid = validate_process_group_id(root.pid)?;
    if token.root_pid != root.pid {
        return Err(SupervisionError::new(
            ErrorCode::ContainmentLost,
            ErrorCategory::Containment,
            false,
            "group token root identity changed",
        ));
    }
    let observed = getpgid_for_root(root_pid)?;
    let validated = validate_group_id(observed, root.pid)?;
    if validated.raw() != token.group.raw() {
        return Err(SupervisionError::new(
            ErrorCode::ProcessGroupMismatch,
            ErrorCategory::Containment,
            false,
            "revalidated group no longer equals the retained token",
        ));
    }
    Ok(())
}

fn pid_for_root(root_pid: u32) -> Result<Pid, SupervisionError> {
    let raw = validate_process_group_id(root_pid)?;
    Pid::from_raw(raw).ok_or_else(|| {
        SupervisionError::new(
            ErrorCode::InvalidProcessGroupId,
            ErrorCategory::Containment,
            false,
            "root PID is not a valid positive rustix PID",
        )
    })
}

fn pid_for_group(group: ValidatedProcessGroup) -> Result<Pid, SupervisionError> {
    Pid::from_raw(group.raw()).ok_or_else(|| {
        SupervisionError::new(
            ErrorCode::InvalidProcessGroupId,
            ErrorCategory::Containment,
            false,
            "validated process-group token could not be represented by rustix",
        )
    })
}

fn exit_info(exited: bool, code: i32) -> ExitInfo {
    ExitInfo {
        code,
        signaled: !exited,
    }
}

/// Validates a root PID without issuing an OS operation.
pub(crate) fn validate_process_group_id(root_pid: u32) -> Result<i32, SupervisionError> {
    let value = i32::try_from(root_pid).map_err(|_| {
        SupervisionError::setup(
            ErrorCode::InvalidProcessGroupId,
            "root PID does not fit a private positive process-group token",
        )
    })?;
    if value <= 1 {
        return Err(SupervisionError::new(
            ErrorCode::InvalidProcessGroupId,
            ErrorCategory::Containment,
            false,
            "process-group target 0 or 1 is forbidden",
        ));
    }
    Ok(value)
}

/// Validates equality between observed PGID and the exact root PID.
pub(crate) fn validate_group_id(
    group: i32,
    root_pid: u32,
) -> Result<ValidatedProcessGroup, SupervisionError> {
    let root = validate_process_group_id(root_pid)?;
    if group <= 1 {
        return Err(SupervisionError::new(
            ErrorCode::InvalidProcessGroupId,
            ErrorCategory::Containment,
            false,
            "observed process-group value is reserved",
        ));
    }
    if group != root {
        return Err(SupervisionError::new(
            ErrorCode::ProcessGroupMismatch,
            ErrorCategory::Containment,
            false,
            "observed process group does not equal the exact root PID",
        ));
    }
    Ok(ValidatedProcessGroup(group))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn reserved_and_mismatched_group_values_are_rejected_without_os_calls() {
        assert!(validate_process_group_id(0).is_err());
        assert!(validate_process_group_id(1).is_err());
        assert!(validate_group_id(-1, 2).is_err());
        assert!(validate_group_id(0, 2).is_err());
        assert!(validate_group_id(1, 2).is_err());
        assert_eq!(validate_group_id(7, 7).expect("valid").raw(), 7);
        assert_eq!(
            validate_group_id(7, 8).expect_err("mismatch").code(),
            ErrorCode::ProcessGroupMismatch
        );
    }
}
