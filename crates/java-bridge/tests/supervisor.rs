// SPDX-License-Identifier: Apache-2.0
#![allow(missing_docs)] // Integration-test functions are not library API.
#![allow(clippy::expect_used)] // Failures include explicit test assertion context.

use jmeter_rs_java_bridge::{
    BridgeErrorCode, CallOptions, ProcessGroupPolicy, Supervisor, Worker, WorkerConfig,
};
use std::env;
use std::path::PathBuf;
use std::time::Duration;

fn fake_worker() -> PathBuf {
    let path = env::var_os("CARGO_BIN_EXE_jmeter-rs-java-bridge-fake-worker")
        .or_else(|| env::var_os("CARGO_BIN_EXE_jmeter_rs_java_bridge_fake_worker"))
        .expect("Cargo supplies the fake worker binary path");
    PathBuf::from(path)
}

fn config(mode: &str, capabilities: &[&str]) -> WorkerConfig {
    let root = env::current_dir()
        .expect("test current directory")
        .canonicalize()
        .expect("canonical test directory");
    WorkerConfig::new(fake_worker(), root, "jmeter-5.6.3")
        .with_env("BRIDGE_FAKE_MODE", mode)
        .with_capabilities(capabilities.iter().copied())
        // Ordinary integration tests must not deliver process-group signals.
        .with_process_group_policy(ProcessGroupPolicy::ChildOnly)
        .with_timeouts(
            Duration::from_secs(2),
            Duration::from_secs(2),
            Duration::from_secs(2),
            Duration::from_millis(100),
        )
}

#[test]
fn handshake_call_and_partial_frames_round_trip() {
    let worker = Supervisor::new()
        .start(config("partial", &["SCRIPT-001"]))
        .expect("partial worker handshake");
    assert_eq!(worker.info().profile, "jmeter-5.6.3");
    assert!(worker.info().supports("SCRIPT-001"));
    assert_eq!(worker.call(b"payload").expect("echo response"), b"payload");
}

#[test]
fn missing_capability_and_bad_version_fail_closed() {
    let missing = Supervisor::new()
        .start(config("missing_capability", &["SCRIPT-001"]))
        .expect_err("missing capability must fail");
    assert_eq!(missing.code(), BridgeErrorCode::CapabilityUnavailable);

    let version = Supervisor::new()
        .start(config("bad_version", &[]))
        .expect_err("bad version must fail");
    assert_eq!(version.code(), BridgeErrorCode::ProtocolViolation);
}

#[test]
fn crash_and_oversized_output_are_structured_errors() {
    let crashed = Supervisor::new()
        .start(config("crash", &[]))
        .expect("crash worker handshake");
    let error = crashed
        .call_with_timeout(b"payload", Duration::from_secs(1))
        .expect_err("crash must fail the call");
    assert_eq!(error.code(), BridgeErrorCode::WorkerCrashed);

    let oversized = Supervisor::new()
        .start(config("oversized_stdout", &[]).with_limits(4096, 4096, 4096, 256))
        .expect("oversized worker handshake");
    let error = oversized
        .call_with_timeout(b"payload", Duration::from_secs(1))
        .expect_err("oversized response must fail");
    assert_eq!(error.code(), BridgeErrorCode::ResourceLimit);
}

#[test]
fn timeout_sends_cancel_and_closes_worker() {
    let worker = Supervisor::new()
        .start(config("timeout", &[]))
        .expect("timeout worker handshake");
    let error = worker
        .call_with_options(
            b"payload",
            CallOptions::with_timeout(Duration::from_millis(40)),
        )
        .expect_err("timeout must fail");
    assert_eq!(error.code(), BridgeErrorCode::DeadlineExceeded);
    assert!(worker.is_closed());
}

#[test]
fn no_read_worker_does_not_block_request_deadline() {
    let worker = Supervisor::new()
        .start(config("no_read", &[]).with_limits(4 * 1024 * 1024, 4096, 4096, 2 * 1024 * 1024))
        .expect("no-read worker handshake");
    let started = std::time::Instant::now();
    let error = worker
        .call_with_options(
            vec![b'x'; 1_000_000],
            CallOptions::with_timeout(Duration::from_millis(40)),
        )
        .expect_err("no-read worker must time out");
    assert_eq!(error.code(), BridgeErrorCode::DeadlineExceeded);
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(worker.is_closed());
}

#[test]
fn remote_error_and_stderr_are_redacted() {
    let remote = Supervisor::new()
        .start(config("remote_error", &[]))
        .expect("remote error worker handshake");
    let error = remote.call(b"payload").expect_err("remote error expected");
    assert_eq!(error.code(), BridgeErrorCode::CapabilityUnavailable);
    assert_eq!(
        error
            .remote_error()
            .expect("structured remote error")
            .code
            .as_str(),
        "capability_unavailable"
    );

    let stderr = Supervisor::new()
        .start(config("stderr_secret", &[]).with_redacted_value("secret-value"))
        .expect("stderr worker handshake");
    assert_eq!(
        stderr.call(b"payload").expect("stderr response"),
        b"payload"
    );
    let report = stderr.stderr();
    assert!(report.redacted() || !report.text().contains("secret-value"));
    assert!(!report.text().contains("secret-value"));
}

#[test]
fn explicit_shutdown_is_idempotent() {
    let worker: Worker = Supervisor::new()
        .start(config("echo", &[]))
        .expect("echo worker handshake");
    worker.shutdown().expect("first shutdown");
    worker.shutdown().expect("second shutdown");
    assert!(worker.is_closed());
}

#[cfg(unix)]
#[test]
#[ignore = "process-group signalling requires the PID namespace script"]
fn process_group_cleanup_is_namespace_scoped() {
    let namespace = std::fs::read_link("/proc/self/ns/pid").expect("self PID namespace");
    let user_namespace = std::fs::read_link("/proc/self/ns/user").expect("self user namespace");
    let pid_one_user_namespace =
        std::fs::read_link("/proc/1/ns/user").expect("namespace PID 1 user identity");
    assert_eq!(user_namespace, pid_one_user_namespace);
    let pid_one_namespace = std::fs::read_link("/proc/1/ns/pid").expect("namespace PID 1 identity");
    assert_eq!(namespace, pid_one_namespace);
    let status = std::fs::read_to_string("/proc/self/status").expect("self status");
    let nspid_fields = status
        .lines()
        .find_map(|line| line.strip_prefix("NSpid:").map(str::split_whitespace))
        .map_or(0, Iterator::count);
    assert!(nspid_fields >= 2, "test must run in a nested PID namespace");
    let pid_one_status = std::fs::read_to_string("/proc/1/status").expect("PID 1 status");
    let pid_one_nspid = pid_one_status
        .lines()
        .find_map(|line| line.strip_prefix("NSpid:").map(str::split_whitespace))
        .and_then(|mut values| values.next_back())
        .and_then(|value| value.parse::<u32>().ok());
    assert_eq!(pid_one_nspid, Some(1));
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").expect("mountinfo");
    assert!(
        mountinfo
            .lines()
            .any(|line| line.contains(" - proc /proc "))
    );
    let uid_map = std::fs::read_to_string("/proc/self/uid_map").expect("uid map");
    let uid_fields = uid_map.split_whitespace().collect::<Vec<_>>();
    assert!(uid_fields.len() >= 3 && uid_fields[0] == "0" && uid_fields[1] == "0");
    let gid_map = std::fs::read_to_string("/proc/self/gid_map").expect("gid map");
    let gid_fields = gid_map.split_whitespace().collect::<Vec<_>>();
    assert!(gid_fields.len() >= 3 && gid_fields[0] == "0" && gid_fields[1] == "0");
    let proof = std::env::var("JMT_PID_NAMESPACE_PROOF_TOKEN")
        .expect("run this test through the verified PID namespace wrapper");
    let prefix = format!("jmeter-rs-pidns-v1:{}:1:", namespace.display());
    let nonce = proof
        .strip_prefix(&prefix)
        .expect("namespace proof token is missing or bound to another namespace");
    assert_eq!(nonce.len(), 36, "namespace proof nonce is malformed");
    assert!(
        nonce
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-'),
        "namespace proof nonce is malformed",
    );
    let _namespace_proof_complete = proof;
    let worker = Supervisor::new()
        .start(config("echo", &[]).with_process_group_policy(ProcessGroupPolicy::Required))
        .expect("echo worker handshake");
    worker.shutdown().expect("owned process-group cleanup");
    assert!(worker.is_closed());
}
