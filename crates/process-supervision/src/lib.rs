// SPDX-License-Identifier: Apache-2.0
//! Private executor-neutral exact-child/process-tree supervision.
//!
//! Revision 4 deliberately keeps launch descriptions, purpose markers,
//! process roots, and platform tokens private.  The only cross-thread caller
//! capability is a single-owner slot/generation token; its `Drop` is
//! constant-time and atomic-only.  Pure fake/model tests are the ordinary
//! verification layer.  Real process, signal, namespace, JVM, and platform
//! lifecycle evidence is a separate release gate.

#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
// The launch/registry/platform modules are intentionally private until the
// separately reviewed caller migrations land.  Keep their complete staged
// state machine compiled and testable without treating unreferenced internal
// seams as a production warning in this transition crate.
#![allow(dead_code)]

mod error;
mod model;
mod platform;
mod policy;
mod process;
mod registry;
mod spec;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
#[allow(unsafe_code)]
mod windows;

pub use error::{ErrorCategory, ErrorCode, ErrorSummary, SupervisionError};
pub use process::{CancellationToken, DEFAULT_CLEANUP_TIMEOUT};

/// Fallible result alias for internal adapter seams.
pub type Result<T> = core::result::Result<T, SupervisionError>;

/// Reports whether accepted runtime process-tree evidence exists on this
/// target.  Linux is currently the only target with the approved evidence;
/// macOS and Windows remain compile-checked and fail closed.
#[must_use]
pub const fn process_tree_supported() -> bool {
    cfg!(target_os = "linux")
}

/// Pure validation of a root PID for Unix process-group use.
#[cfg(unix)]
pub fn validate_process_group_id(root_pid: u32) -> Result<i32> {
    unix::validate_process_group_id(root_pid)
}

/// Pure validation of a group/root identity pair on Unix.
#[cfg(unix)]
pub fn validate_group_id(group: i32, root_pid: u32) -> Result<i32> {
    unix::validate_group_id(group, root_pid).map(|token| token.raw())
}

/// Non-Unix process-group validation fails closed.
#[cfg(not(unix))]
pub fn validate_process_group_id(_: u32) -> Result<i32> {
    Err(SupervisionError::new(
        ErrorCode::UnsupportedPlatform,
        ErrorCategory::Unsupported,
        false,
        "Unix process groups are unsupported on this target",
    ))
}

/// Non-Unix process-group validation fails closed.
#[cfg(not(unix))]
pub fn validate_group_id(_: i32, _: u32) -> Result<i32> {
    Err(SupervisionError::new(
        ErrorCode::UnsupportedPlatform,
        ErrorCategory::Unsupported,
        false,
        "Unix process groups are unsupported on this target",
    ))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::model::{Admission, Model, SlotState};
    use crate::process::bounded_attempts;

    #[test]
    fn stable_codes_include_cancellation_and_shutdown() {
        assert_eq!(
            ErrorCode::Cancelled.as_str(),
            "process_supervision.cancelled"
        );
        assert_eq!(
            ErrorCode::ShutdownIncomplete.as_str(),
            "process_supervision.shutdown_incomplete"
        );
        assert_eq!(
            SupervisionError::cancelled("test").code(),
            ErrorCode::Cancelled
        );
    }

    #[test]
    fn cancellation_is_monotonic_and_has_a_stable_code() {
        let token = CancellationToken::new();
        assert!(!token.is_cancelled());
        token.cancel();
        token.cancel();
        assert!(token.is_cancelled());
        assert_eq!(
            SupervisionError::cancelled("cancelled").code(),
            ErrorCode::Cancelled
        );
    }

    #[test]
    fn automatic_attempts_are_fixed_and_terminate() {
        let mut attempts = 0;
        assert!(!bounded_attempts(|| {
            attempts += 1;
            false
        }));
        assert_eq!(attempts, 3);
    }

    #[test]
    fn fake_model_checks_stale_generation_and_linearized_admission() {
        let mut model = Model::<2>::default();
        let (index, generation) = model.reserve().expect("reserve");
        assert!(
            model
                .transition(index, generation, SlotState::LaunchQueued)
                .is_ok()
        );
        assert_eq!(
            model
                .transition(index, generation + 1, SlotState::Creating)
                .expect_err("stale generation")
                .code(),
            ErrorCode::StaleOwnershipToken
        );
        model.close_admission().expect("close");
        assert_eq!(model.admission(), Admission::Closing);
        assert_eq!(
            model.reserve().expect_err("admission closed").code(),
            ErrorCode::AdmissionClosed
        );
    }

    #[cfg(unix)]
    #[test]
    fn pure_group_identity_validation_never_signals() {
        assert!(validate_process_group_id(0).is_err());
        assert!(validate_process_group_id(1).is_err());
        assert_eq!(validate_group_id(7, 7).expect("valid group"), 7);
        assert_eq!(
            validate_group_id(7, 8).expect_err("mismatch").code(),
            ErrorCode::ProcessGroupMismatch
        );
    }

    #[cfg(unix)]
    #[test]
    fn process_tree_capability_is_linux_only() {
        #[cfg(target_os = "linux")]
        assert!(process_tree_supported());
        #[cfg(not(target_os = "linux"))]
        assert!(!process_tree_supported());
    }

    #[cfg(all(unix, target_os = "linux"))]
    #[test]
    #[ignore = "real process-group evidence requires the independently audited namespace wrapper"]
    fn process_tree_cleanup_is_namespace_scoped() {
        let namespace = std::fs::read_link("/proc/self/ns/pid").expect("self namespace");
        let pid_one = std::fs::read_link("/proc/1/ns/pid").expect("PID 1 namespace");
        assert_eq!(namespace, pid_one);
        let host_namespace = std::env::var("JMT_HOST_PID_NAMESPACE").expect("host namespace proof");
        assert_ne!(namespace.display().to_string(), host_namespace);
        let user_namespace = std::fs::read_link("/proc/self/ns/user").expect("self user namespace");
        let host_user_namespace =
            std::env::var("JMT_HOST_USER_NAMESPACE").expect("host user namespace proof");
        assert_ne!(user_namespace.display().to_string(), host_user_namespace);
        let status = std::fs::read_to_string("/proc/self/status").expect("status");
        let pid_one_status = std::fs::read_to_string("/proc/1/status").expect("PID 1 status");
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").expect("mountinfo");
        let uid_map = std::fs::read_to_string("/proc/self/uid_map").expect("uid map");
        let gid_map = std::fs::read_to_string("/proc/self/gid_map").expect("gid map");
        assert!(
            mountinfo
                .lines()
                .any(|line| line.contains(" - proc /proc "))
        );
        assert!(
            uid_map
                .lines()
                .any(|line| line.split_whitespace().take(2).eq(["0", "0"]))
        );
        assert!(
            gid_map
                .lines()
                .any(|line| line.split_whitespace().take(2).eq(["0", "0"]))
        );
        let mut nspid_count = 0usize;
        let mut namespace_pid = None;
        if let Some(fields) = status
            .lines()
            .find_map(|line| line.strip_prefix("NSpid:").map(str::split_whitespace))
        {
            for value in fields {
                nspid_count += 1;
                namespace_pid = Some(value);
            }
        }
        assert!(nspid_count >= 2, "nested NSpid identity is required");
        let namespace_pid = namespace_pid
            .and_then(|value| value.parse::<u32>().ok())
            .expect("namespace PID");
        assert!(
            namespace_pid > 1,
            "the test is a nested child of namespace PID 1"
        );
        let mut pid_one_namespace_pid = None;
        if let Some(fields) = pid_one_status
            .lines()
            .find_map(|line| line.strip_prefix("NSpid:").map(str::split_whitespace))
        {
            for value in fields {
                pid_one_namespace_pid = Some(value);
            }
        }
        assert_eq!(pid_one_namespace_pid, Some("1"));
        let proof =
            std::env::var("JMT_PID_NAMESPACE_PROOF_TOKEN").expect("namespace wrapper proof token");
        let prefix = format!("jmeter-rs-pidns-v1:{}:1:", namespace.display());
        let nonce = proof.strip_prefix(&prefix).expect("bound proof token");
        assert_eq!(nonce.len(), 36);
        let _namespace_proof_complete = proof;
    }
}
