// SPDX-License-Identifier: Apache-2.0
//! Small process-level checks for the public binary boundary.

#![allow(
    clippy::expect_used,
    reason = "subprocess setup failures should identify the failed smoke-test launch"
)]

use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const PROCESS_DEADLINE: Duration = Duration::from_secs(5);

fn run_cli(argument: &str) -> Output {
    let binary = env!("CARGO_BIN_EXE_jmeter-rs");
    let mut child = Command::new(binary)
        .arg(argument)
        .env_clear()
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("binary should start");
    let deadline = Instant::now() + PROCESS_DEADLINE;
    let mut completed = false;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) => {
                completed = true;
                break;
            }
            Ok(None) => std::thread::yield_now(),
            Err(_) => break,
        }
    }
    if !completed {
        // Re-check the exact child before the only escalation.  This keeps
        // the deterministic test deadline from leaking a child while never
        // addressing a stale PID or a process group.
        match child.try_wait() {
            Ok(Some(_)) => completed = true,
            Ok(None) => {
                if child.kill().is_ok() {
                    completed = true;
                } else if matches!(child.try_wait(), Ok(Some(_))) {
                    // The direct-child escalation raced with normal exit;
                    // the second observation proves the owned child is done.
                    completed = true;
                }
            }
            Err(_) => {}
        }
    }
    let output = collect_child_output(child);
    assert!(
        completed,
        "CLI process exceeded its deterministic poll deadline"
    );
    output
}

fn collect_child_output(child: Child) -> Output {
    child
        .wait_with_output()
        .expect("CLI child should be reaped with output")
}

#[test]
fn help_and_version_are_successful_information_actions() {
    let help = run_cli("--help");
    assert!(help.status.success());
    let help_text = String::from_utf8_lossy(&help.stdout);
    assert!(help_text.contains("To run Apache JMeter in NON_GUI mode"));

    let version = run_cli("--version");
    assert!(version.status.success());
    assert!(String::from_utf8_lossy(&version.stdout).contains("5.6.3"));
}

#[test]
fn malformed_invocation_reports_usage_without_starting_an_engine() {
    let output = run_cli("--not-a-jmeter-option");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cli.unknown-option"));
}
