// SPDX-License-Identifier: Apache-2.0
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    missing_docs,
    reason = "integration tests assert deterministic fixture setup"
)]

use jmeter_rs_plugin_host::{
    CancellationToken, CapabilityKind, CapabilityReference, CleanupPolicy, DiscoveryConfig,
    JmxElementMetadata, PluginErrorCode, PluginId, PluginManifest, PluginRegistry, PluginRequest,
    PluginSupervisor, PluginVersion, ProcessPolicy, ResourceLimits, SupervisorConfig,
};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "jmeter-rs-plugin-supervisor-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).expect("temporary plugin directory");
        Self(path)
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn request() -> PluginRequest {
    PluginRequest {
        capability: CapabilityReference::new(CapabilityKind::Element, "example.element"),
        jmx: JmxElementMetadata::unknown("plugin.Unknown", b"<unknown/>".to_vec()),
        input: Vec::new(),
        extensions: BTreeMap::new(),
    }
}

fn setup(mode: &str, directory: &Path) -> PluginSupervisor {
    setup_with_policy(mode, directory, CleanupPolicy::ExactChild, 1)
}

fn setup_with_policy(
    mode: &str,
    directory: &Path,
    cleanup_policy: CleanupPolicy,
    max_concurrent_requests: usize,
) -> PluginSupervisor {
    let source = PathBuf::from(env!("CARGO_BIN_EXE_plugin-host-test-helper"));
    let helper = directory.join("plugin-helper");
    fs::copy(source, &helper).expect("copy helper executable");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(&helper)
            .expect("helper metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&helper, permissions).expect("helper executable permissions");
    }
    let mut manifest = PluginManifest::new(
        PluginId::parse("example.plugin").expect("plugin ID"),
        PluginVersion::parse("1.0.0").expect("version"),
        &helper,
    );
    manifest.profiles = vec!["jmeter-5.6.3".to_owned()];
    manifest
        .capabilities
        .elements
        .push(jmeter_rs_plugin_host::CapabilityDeclaration::new(
            "example.element",
        ));
    manifest.preservation.unknown_elements = true;
    manifest.preservation.unknown_properties = true;
    manifest.preservation.raw_subtree = true;
    manifest.limits = ResourceLimits {
        startup_timeout_ms: 1_000,
        request_timeout_ms: 100,
        max_output_bytes: 1024 * 1024,
        max_concurrent_requests,
        ..ResourceLimits::default()
    };
    fs::write(
        directory.join("plugin.json"),
        serde_json::to_vec(&manifest).expect("manifest JSON"),
    )
    .expect("manifest write");
    let registry =
        PluginRegistry::discover(&DiscoveryConfig::new(directory)).expect("plugin discovery");
    let descriptor = registry.plugins()[0].clone();
    let process = ProcessPolicy::new(directory)
        .with_argument(mode)
        .with_cleanup_policy(cleanup_policy);
    let config = SupervisorConfig {
        profile: "jmeter-5.6.3".to_owned(),
        process,
    };
    PluginSupervisor::new(descriptor, config).expect("supervisor setup")
}

#[test]
fn helper_response_is_correlated_and_unknown_jmx_is_retained() {
    let directory = TempDirectory::new();
    let supervisor = setup("normal", &directory.0);
    let response = supervisor.invoke(&request()).expect("worker response");
    assert_eq!(response.output, b"ok");
}

#[test]
fn handshake_mismatches_are_stable() {
    for (mode, expected) in [
        ("protocol", PluginErrorCode::ProtocolMismatch),
        ("profile", PluginErrorCode::ProfileMismatch),
        ("capability", PluginErrorCode::CapabilityMismatch),
        ("preservation", PluginErrorCode::CapabilityMismatch),
    ] {
        let directory = TempDirectory::new();
        let error = setup(mode, &directory.0)
            .invoke(&request())
            .expect_err("mismatch must fail");
        assert_eq!(error.code(), expected, "mode {mode}");
    }
}

#[test]
fn partial_oversize_crash_and_timeout_are_mapped() {
    let cases = [
        ("partial", PluginErrorCode::WorkerProtocol),
        ("oversize", PluginErrorCode::WorkerOutputLimit),
        ("crash", PluginErrorCode::WorkerCrashed),
        ("timeout", PluginErrorCode::WorkerTimeout),
    ];
    for (mode, expected) in cases {
        let directory = TempDirectory::new();
        let error = setup(mode, &directory.0)
            .invoke(&request())
            .expect_err("worker failure must fail");
        assert_eq!(error.code(), expected, "mode {mode}");
    }
}

#[test]
fn no_read_worker_cannot_block_stdin_writer() {
    let directory = TempDirectory::new();
    let supervisor = setup("no-read", &directory.0);
    let mut request = request();
    request.input = vec![b'x'; 128 * 1024];
    let started = Instant::now();
    let error = supervisor
        .invoke(&request)
        .expect_err("no-read worker must hit the bounded write/operation deadline");
    assert_eq!(error.code(), PluginErrorCode::WorkerTimeout);
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn pre_cancelled_request_is_mapped_and_worker_is_reaped() {
    let directory = TempDirectory::new();
    let supervisor = setup("timeout", &directory.0);
    let token = CancellationToken::new();
    token.cancel();
    let error = supervisor
        .invoke_with_cancellation(&request(), &token)
        .expect_err("cancelled request must fail");
    assert_eq!(error.code(), PluginErrorCode::WorkerCancelled);
}

#[test]
fn worker_is_cleaned_up_after_success() {
    let directory = TempDirectory::new();
    let response = setup("cleanup", &directory.0)
        .invoke(&request())
        .expect("response before exact-child cleanup");
    #[cfg(not(target_os = "linux"))]
    let _ = response;
    #[cfg(target_os = "linux")]
    {
        let pid = response
            .metadata
            .get("worker_pid")
            .and_then(serde_json::Value::as_u64)
            .expect("helper identity pid") as u32;
        let start_time = response
            .metadata
            .get("worker_start_time")
            .and_then(serde_json::Value::as_u64)
            .expect("helper identity start time");
        let stat = Path::new("/proc").join(pid.to_string()).join("stat");
        if stat.exists() {
            assert_ne!(process_start_time(pid), Some(start_time));
        }
    }
}

#[test]
fn concurrent_invocations_have_independent_cleanup() {
    let directory = TempDirectory::new();
    let supervisor = Arc::new(setup_with_policy(
        "normal",
        &directory.0,
        CleanupPolicy::ExactChild,
        4,
    ));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let supervisor = Arc::clone(&supervisor);
        handles.push(thread::spawn(move || {
            supervisor
                .invoke(&request())
                .expect("concurrent worker response");
        }));
    }
    for handle in handles {
        handle.join().expect("concurrent invocation join");
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "process-group signalling requires tests/pid_namespace.sh"]
fn process_group_cleanup_is_namespace_scoped() {
    let host_namespace = std::env::var("PLUGIN_HOST_HOST_PID_NAMESPACE")
        .expect("run this test through tests/pid_namespace.sh");
    let current_namespace = fs::read_link("/proc/self/ns/pid")
        .expect("current PID namespace")
        .display()
        .to_string();
    assert_ne!(host_namespace, current_namespace);
    let user_namespace = fs::read_link("/proc/self/ns/user").expect("self user namespace");
    let pid_one_user_namespace =
        fs::read_link("/proc/1/ns/user").expect("namespace PID 1 user identity");
    assert_eq!(user_namespace, pid_one_user_namespace);
    let pid_one_namespace = fs::read_link("/proc/1/ns/pid").expect("namespace PID 1 identity");
    assert_eq!(current_namespace, pid_one_namespace.display().to_string());
    let status = fs::read_to_string("/proc/self/status").expect("PID namespace status");
    let nspid = status
        .lines()
        .find_map(|line| line.strip_prefix("NSpid:").map(str::split_whitespace))
        .map(|values| values.collect::<Vec<_>>())
        .expect("NSpid field");
    assert!(nspid.len() >= 2, "NSpid must prove a nested namespace");
    let pid_one_status = fs::read_to_string("/proc/1/status").expect("PID 1 status");
    let pid_one_nspid = pid_one_status
        .lines()
        .find_map(|line| line.strip_prefix("NSpid:").map(str::split_whitespace))
        .map(|values| values.collect::<Vec<_>>())
        .expect("PID 1 NSpid field");
    assert_eq!(
        pid_one_nspid.last().copied(),
        Some("1"),
        "NSpid must prove namespace PID 1",
    );
    let mountinfo = fs::read_to_string("/proc/self/mountinfo").expect("mountinfo");
    assert!(
        mountinfo
            .lines()
            .any(|line| line.contains(" - proc /proc "))
    );
    let uid_map = fs::read_to_string("/proc/self/uid_map").expect("uid map");
    let uid_fields = uid_map.split_whitespace().collect::<Vec<_>>();
    assert!(uid_fields.len() >= 3 && uid_fields[0] == "0" && uid_fields[1] == "0");
    let gid_map = fs::read_to_string("/proc/self/gid_map").expect("gid map");
    let gid_fields = gid_map.split_whitespace().collect::<Vec<_>>();
    assert!(gid_fields.len() >= 3 && gid_fields[0] == "0" && gid_fields[1] == "0");
    let proof = std::env::var("JMT_PID_NAMESPACE_PROOF_TOKEN")
        .expect("run this test through the verified PID namespace wrapper");
    let prefix = format!("jmeter-rs-pidns-v1:{}:1:", current_namespace);
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

    let directory = TempDirectory::new();
    let response = setup_with_policy("grandchild", &directory.0, CleanupPolicy::ProcessGroup, 1)
        .invoke(&request())
        .expect("group worker response");
    let pid = response
        .metadata
        .get("grandchild_pid")
        .and_then(serde_json::Value::as_u64)
        .expect("grandchild identity pid") as u32;
    let start_time = response
        .metadata
        .get("grandchild_start_time")
        .and_then(serde_json::Value::as_u64)
        .expect("grandchild identity start time");
    let stat = Path::new("/proc").join(pid.to_string()).join("stat");
    if stat.exists() {
        assert_ne!(process_start_time(pid), Some(start_time));
    }
}

#[cfg(target_os = "linux")]
fn process_start_time(pid: u32) -> Option<u64> {
    let text = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let close = text.rfind(')')?;
    text.get(close + 2..)?
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}
