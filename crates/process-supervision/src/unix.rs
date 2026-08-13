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
use std::sync::OnceLock;
use std::time::Instant;

/// The only signal state accepted by the retained-root protocol.
///
/// The application/bootstrap boundary owns this contract.  The supervisor
/// deliberately does not install a process-global handler or change a
/// caller-owned mask.  In particular, `SA_NOCLDWAIT` must be proven absent;
/// observing a default-looking `/proc` disposition is not enough because
/// `/proc` does not expose that flag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SigchldState {
    disposition: SigchldDisposition,
    blocked: bool,
    /// `Some(false)` is the only accepted value.  `None` means the target
    /// could not expose `SA_NOCLDWAIT` through a safe API.
    no_cldwait: Option<bool>,
}

impl SigchldState {
    const fn accepted() -> Self {
        Self {
            disposition: SigchldDisposition::Default,
            blocked: false,
            no_cldwait: Some(false),
        }
    }
}

/// Disposition classes observable without installing a handler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SigchldDisposition {
    Default,
    Ignored,
    Caught,
}

/// A point at which the sole-reaper contract must be revalidated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ContractOperation {
    Initialization,
    Observation,
    GroupValidation,
    GroupSignal,
    ExactChildSignal,
    FinalReap,
}

impl ContractOperation {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Initialization => "initialization",
            Self::Observation => "exact-root observation",
            Self::GroupValidation => "process-group validation",
            Self::GroupSignal => "process-group signal",
            Self::ExactChildSignal => "exact-child signal",
            Self::FinalReap => "final exact-root reap",
        }
    }
}

/// Safe signal-state reads can fail independently of `waitid`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ContractReadError {
    Unreadable,
    Echild,
    Os(i32),
}

/// Recorded process-global contract for one retained root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReaperContract {
    expected: SigchldState,
}

impl ReaperContract {
    /// Captures the explicitly accepted application/bootstrap state.  No
    /// process-global signal disposition is installed here.
    fn capture() -> Result<Self, SupervisionError> {
        let expected = SigchldState::accepted();
        let observed = read_sigchld_state();
        verify_sigchld_state(expected, observed, ContractOperation::Initialization)?;
        Ok(Self { expected })
    }

    fn verify_current(self, operation: ContractOperation) -> Result<(), SupervisionError> {
        verify_sigchld_state(self.expected, read_sigchld_state(), operation)
    }
}

static PROCESS_REAPER_CONTRACT: OnceLock<Result<ReaperContract, SupervisionError>> =
    OnceLock::new();

fn process_reaper_contract() -> Result<ReaperContract, SupervisionError> {
    PROCESS_REAPER_CONTRACT
        .get_or_init(ReaperContract::capture)
        .clone()
}

fn verify_root_contract(
    root: &RootHandle,
    operation: ContractOperation,
) -> Result<(), SupervisionError> {
    root.contract.verify_current(operation)
}

/// Converts a signal-state read into the existing stable reaper error.  The
/// diagnostic names the operation but never includes unbounded OS text.
fn contract_lost(operation: ContractOperation, detail: &'static str) -> SupervisionError {
    SupervisionError::new(
        ErrorCode::ReaperContractLost,
        ErrorCategory::Reaping,
        false,
        format!("{detail} before {}", operation.as_str()),
    )
}

/// Compares a read state with the explicitly owned contract.  This pure seam
/// is used by failure-injection tests so a lost contract can be proven to
/// block an operation without creating a process or sending a signal.
fn verify_sigchld_state(
    expected: SigchldState,
    observed: Result<SigchldState, ContractReadError>,
    operation: ContractOperation,
) -> Result<(), SupervisionError> {
    match observed {
        Ok(state) if state == expected => Ok(()),
        Ok(SigchldState {
            no_cldwait: None, ..
        }) => Err(contract_lost(
            operation,
            "SA_NOCLDWAIT state is unreadable through the safe platform API",
        )),
        Ok(_) => Err(contract_lost(
            operation,
            "SIGCHLD disposition, SA_NOCLDWAIT, or mask changed",
        )),
        Err(ContractReadError::Echild) => Err(contract_lost(
            operation,
            "SIGCHLD contract read observed ECHILD",
        )
        .with_os_error(rustix::io::Errno::CHILD.raw_os_error())),
        Err(ContractReadError::Unreadable) => {
            Err(contract_lost(operation, "SIGCHLD contract is unreadable"))
        }
        Err(ContractReadError::Os(error)) => {
            Err(contract_lost(operation, "SIGCHLD contract read failed").with_os_error(error))
        }
    }
}

/// Reads the calling supervisor thread's SIGCHLD state without changing it.
///
/// Linux exposes disposition classes and the blocked mask in `/proc`, but it
/// does not expose `SA_NOCLDWAIT`.  We return `None` for that field so the
/// explicit comparison above rejects the state.  rustix 1.1.4's only
/// sigaction inspection API is its unsafe experimental runtime API; enabling
/// it here would violate the crate's no-unsafe policy.  Non-Linux Unix has no
/// equivalent safe public API in the pinned dependency and fails closed.
#[cfg(target_os = "linux")]
fn read_sigchld_state() -> Result<SigchldState, ContractReadError> {
    let status = std::fs::read_to_string("/proc/thread-self/status")
        .map_err(|error| ContractReadError::Os(error.raw_os_error().unwrap_or(0)))?;
    let blocked = signal_bit(&status, "SigBlk")?;
    let ignored = signal_bit(&status, "SigIgn")?;
    let caught = signal_bit(&status, "SigCgt")?;
    let disposition = match (ignored, caught) {
        (true, false) => SigchldDisposition::Ignored,
        (false, true) => SigchldDisposition::Caught,
        (false, false) => SigchldDisposition::Default,
        (true, true) => return Err(ContractReadError::Unreadable),
    };
    Ok(SigchldState {
        disposition,
        blocked,
        no_cldwait: None,
    })
}

#[cfg(not(target_os = "linux"))]
fn read_sigchld_state() -> Result<SigchldState, ContractReadError> {
    Err(ContractReadError::Unreadable)
}

#[cfg(target_os = "linux")]
fn signal_bit(status: &str, field: &str) -> Result<bool, ContractReadError> {
    let value = status
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            (name == field).then_some(value.trim())
        })
        .ok_or(ContractReadError::Unreadable)?;
    let mask = u128::from_str_radix(value, 16).map_err(|_| ContractReadError::Unreadable)?;
    let bit =
        usize::try_from(Signal::CHILD.as_raw() - 1).map_err(|_| ContractReadError::Unreadable)?;
    if bit >= u128::BITS as usize {
        return Err(ContractReadError::Unreadable);
    }
    Ok((mask & (1u128 << bit)) != 0)
}

/// Root process and its exact identity.  The `Child` remains in this cell
/// until rustix has reaped it; it never crosses the slot capability boundary.
#[derive(Debug)]
pub(crate) struct UnixRoot {
    pub(crate) child: Child,
    pub(crate) pid: u32,
    pub(crate) waitable: bool,
    pub(crate) reaped: bool,
    pub(crate) exit: Option<ExitInfo>,
    contract: ReaperContract,
}

/// A validated process-group token.  Construction is private and requires
/// equality with the still-owned root PID and a value greater than one.
#[derive(Debug, Eq, Hash, PartialEq)]
pub(crate) struct ValidatedProcessGroup(i32);

impl ValidatedProcessGroup {
    pub(crate) fn raw(&self) -> i32 {
        self.0
    }
}

/// Unix process-group ownership stored in the slot.
#[derive(Debug, Eq, Hash, PartialEq)]
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
    // The application/bootstrap boundary must establish the accepted
    // process-global state before any supervisor child is created.  No
    // handler or mask is installed implicitly here.
    let contract = process_reaper_contract()?;
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
        contract,
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
    verify_root_contract(root, ContractOperation::Observation)?;
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
    // The group lookup and identity validation are one contract-sensitive
    // sequence.  Revalidate immediately before either numeric group value is
    // accepted for the retained token.
    verify_root_contract(root, ContractOperation::GroupValidation)?;
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
    verify_root_contract(root, ContractOperation::Observation)?;
    if root.reaped || root.waitable {
        return root.exit.map(RootObservation::Waitable).ok_or_else(|| {
            SupervisionError::new(
                ErrorCode::InvariantViolation,
                ErrorCategory::Internal,
                false,
                "waitable exact root has no cached exit status",
            )
        });
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
    if let Err(error) = verify_root_contract(root, ContractOperation::ExactChildSignal) {
        return CleanupAttempt::retained(error);
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
    let Some(token_value) = token.as_ref() else {
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
        if error.code() == ErrorCode::ReaperContractLost {
            // A sole-reaper contract failure is stronger than ordinary
            // containment loss: do not fall back to a numeric exact-child
            // signal while ownership/reaping is uncertain.
            return CleanupAttempt::retained(error);
        }
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
            if let Err(error) = verify_root_contract(root, ContractOperation::GroupSignal) {
                return CleanupAttempt::retained(error);
            }
            match pid_for_group(&token_value.group).and_then(|group| {
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
                    // A validated group cleanup is a successful operation.
                    // Capability grade belongs in diagnostics/telemetry, not
                    // in the lifecycle result: surfacing a success marker as
                    // an error would make callers report a reaped child as a
                    // failed cleanup and would block terminal acknowledgment.
                    CleanupState::Reaped => CleanupAttempt::reaped(),
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
    // Establish the WNOWAIT ownership barrier before the destructive reap,
    // including after an exact-child kill.  A direct WNOHANG reap without a
    // prior waitable observation could allow an external reaper or a changed
    // SIGCHLD contract to invalidate the retained identity.
    loop {
        match observe(root) {
            Ok(RootObservation::Waitable(_)) => break,
            Ok(RootObservation::Live) if Instant::now() < deadline => {
                std::thread::yield_now();
            }
            Ok(RootObservation::Live) => {
                return CleanupAttempt::retained(SupervisionError::cleanup(
                    ErrorCode::CleanupTimedOut,
                    "exact-root observation deadline expired before reap",
                ));
            }
            Err(error) => return CleanupAttempt::retained(error),
        }
    }

    let pid = match pid_for_root(root.pid) {
        Ok(pid) => pid,
        Err(error) => return CleanupAttempt::retained(error),
    };
    // This check is deliberately adjacent to the destructive exact reap;
    // the earlier WNOWAIT observation alone cannot prove that the caller has
    // not changed the SIGCHLD contract in the meantime.
    if let Err(error) = verify_root_contract(root, ContractOperation::FinalReap) {
        return CleanupAttempt::retained(error);
    }
    let options = WaitIdOptions::EXITED | WaitIdOptions::NOHANG;
    match waitid(WaitId::Pid(pid), options) {
        Ok(Some(status)) => {
            let observed = exit_info(status.exited(), status.exit_status().unwrap_or(0));
            if root.exit != Some(observed) {
                return CleanupAttempt::retained(SupervisionError::new(
                    ErrorCode::ReaperContractLost,
                    ErrorCategory::Reaping,
                    false,
                    "exact-root reap status differed from the retained observation",
                ));
            }
            root.waitable = true;
            root.reaped = true;
            CleanupAttempt::reaped()
        }
        Ok(None) => CleanupAttempt::retained(SupervisionError::new(
            ErrorCode::WaitFailed,
            ErrorCategory::Reaping,
            true,
            "exact-root reap returned no retained waitable status",
        )),
        Err(error) if error == rustix::io::Errno::CHILD => {
            CleanupAttempt::retained(SupervisionError::new(
                ErrorCode::ReaperContractLost,
                ErrorCategory::Reaping,
                false,
                "exact-root reap returned ECHILD",
            ))
        }
        Err(error) => CleanupAttempt::retained(
            SupervisionError::new(
                ErrorCode::WaitFailed,
                ErrorCategory::Reaping,
                true,
                "exact-root reap failed",
            )
            .with_os_error(error.raw_os_error()),
        ),
    }
}

fn fallback_exact(
    root: &mut RootHandle,
    deadline: Instant,
    tree_error: SupervisionError,
) -> CleanupAttempt {
    if tree_error.code() == ErrorCode::ReaperContractLost {
        // A changed/unreadable SIGCHLD contract quarantines the retained root;
        // even an exact-child fallback must not use a numeric signal or reap.
        return CleanupAttempt::retained(tree_error);
    }
    match observe(root) {
        Ok(RootObservation::Waitable(_)) => preserve(tree_error, reap_root(root, deadline)),
        Ok(RootObservation::Live) => {
            if let Err(error) = verify_root_contract(root, ContractOperation::ExactChildSignal) {
                return CleanupAttempt::retained(tree_error.with_secondary(error));
            }
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
    token: &UnixProcessGroupToken,
) -> Result<(), SupervisionError> {
    verify_root_contract(root, ContractOperation::GroupValidation)?;
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

fn pid_for_group(group: &ValidatedProcessGroup) -> Result<Pid, SupervisionError> {
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

#[cfg(test)]
fn run_if_contract_valid<T>(
    expected: SigchldState,
    observed: Result<SigchldState, ContractReadError>,
    operation: ContractOperation,
    action: impl FnOnce() -> T,
) -> Result<T, SupervisionError> {
    verify_sigchld_state(expected, observed, operation)?;
    Ok(action())
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
    fn changed_contract_blocks_observation_group_validation_signal_and_reap() {
        let expected = SigchldState::accepted();
        let changed_states = [
            SigchldState {
                disposition: SigchldDisposition::Caught,
                blocked: false,
                no_cldwait: Some(false),
            },
            SigchldState {
                disposition: SigchldDisposition::Default,
                blocked: true,
                no_cldwait: Some(false),
            },
        ];
        let operations = [
            ContractOperation::Observation,
            ContractOperation::GroupValidation,
            ContractOperation::GroupSignal,
            ContractOperation::FinalReap,
        ];
        for changed in changed_states {
            for operation in operations {
                let mut attempted = false;
                let error = run_if_contract_valid(expected, Ok(changed), operation, || {
                    attempted = true;
                })
                .expect_err("changed SIGCHLD contract must fail closed");
                assert_eq!(error.code(), ErrorCode::ReaperContractLost);
                assert!(!attempted, "{operation:?} reached its numeric operation");
            }
        }
    }

    #[test]
    fn unreadable_and_echild_contract_reads_block_every_numeric_operation() {
        let expected = SigchldState::accepted();
        let operations = [
            ContractOperation::Observation,
            ContractOperation::GroupValidation,
            ContractOperation::GroupSignal,
            ContractOperation::FinalReap,
        ];
        for read_error in [ContractReadError::Unreadable, ContractReadError::Echild] {
            for operation in operations {
                let mut attempted = false;
                let error = run_if_contract_valid(expected, Err(read_error), operation, || {
                    attempted = true;
                })
                .expect_err("lost SIGCHLD contract must fail closed");
                assert_eq!(error.code(), ErrorCode::ReaperContractLost);
                if read_error == ContractReadError::Echild {
                    assert_eq!(
                        error.os_error(),
                        Some(rustix::io::Errno::CHILD.raw_os_error())
                    );
                }
                assert!(!attempted, "{operation:?} reached its numeric operation");
            }
        }
    }

    #[test]
    fn unavailable_no_cldwait_state_is_unreadable_and_fails_closed() {
        let expected = SigchldState::accepted();
        let observed = SigchldState {
            disposition: SigchldDisposition::Default,
            blocked: false,
            no_cldwait: None,
        };
        let error = verify_sigchld_state(expected, Ok(observed), ContractOperation::Initialization)
            .expect_err("SA_NOCLDWAIT must be proven before accepting the contract");
        assert_eq!(error.code(), ErrorCode::ReaperContractLost);
        assert!(error.message().contains("unreadable"));
    }

    #[test]
    fn accepted_contract_allows_the_pure_operation_gate() {
        let mut attempted = false;
        run_if_contract_valid(
            SigchldState::accepted(),
            Ok(SigchldState::accepted()),
            ContractOperation::Observation,
            || {
                attempted = true;
            },
        )
        .expect("accepted SIGCHLD contract");
        assert!(attempted);
    }

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
