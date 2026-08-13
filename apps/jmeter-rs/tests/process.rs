// SPDX-License-Identifier: Apache-2.0
//! Checks for the public CLI boundary.
//!
//! The ordinary checks exercise the parser and exit contract directly.
//! Launching the binary is deliberately opt-in: process tests are ignored by
//! default and require the namespace wrapper used for containment evidence.

#![allow(
    clippy::expect_used,
    reason = "subprocess setup failures should identify the failed smoke-test launch"
)]

use std::ffi::{OsStr, OsString};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const PROCESS_DEADLINE: Duration = Duration::from_secs(5);
const PROCESS_TEST_NAMESPACE_ENV: &str = "JMETER_RS_PROCESS_TEST_NAMESPACE";

fn require_namespace_scoped_process_test() {
    assert_eq!(
        std::env::var_os(PROCESS_TEST_NAMESPACE_ENV).as_deref(),
        Some(OsStr::new("1")),
        concat!(
            "process smoke tests require an explicit PID-namespace runner; set ",
            "JMETER_RS_PROCESS_TEST_NAMESPACE=1 only inside that runner",
        ),
    );

    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status")
            .expect("Linux PID namespace status must be readable");
        let namespace_ids = status
            .lines()
            .find_map(|line| line.strip_prefix("NSpid:\t"))
            .or_else(|| status.lines().find_map(|line| line.strip_prefix("NSpid:")))
            .expect("Linux must expose NSpid for namespace-scoped process tests");
        assert!(
            namespace_ids.split_whitespace().count() >= 2,
            "process smoke tests must run in a nested PID namespace",
        );
    }

    #[cfg(not(target_os = "linux"))]
    {
        panic!(
            "process smoke tests require the audited Linux PID-namespace runner "
                "on this repository baseline"
        );
    }
}

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
    let help = jmeter_rs::parse_os([OsString::from("--help")])
        .expect("--help should parse without a process or environment");
    assert_eq!(help.action, jmeter_rs::Action::Help);
    assert!(jmeter_rs::help_text().contains("To run Apache JMeter in NON_GUI mode"));

    let version = jmeter_rs::parse_os([OsString::from("--version")])
        .expect("--version should parse without a process or environment");
    assert_eq!(version.action, jmeter_rs::Action::Version);
    assert!(jmeter_rs::version_text().contains("5.6.3"));
}

#[test]
fn malformed_invocation_reports_usage_without_starting_an_engine() {
    let error = jmeter_rs::parse_os([OsString::from("--not-a-jmeter-option")])
        .expect_err("unknown options must be rejected by the pure parser");
    assert_eq!(error.code(), "cli.unknown-option");
    assert_eq!(error.exit_class(), jmeter_rs::ExitClass::UsageError);
    assert_eq!(error.exit_code(), 2);
    assert!(error.to_string().contains("unknown option"));
}

#[test]
fn repeatable_options_and_last_paths_are_deterministic_without_a_process() {
    let invocation = jmeter_rs::parse_os([
        OsString::from("-n"),
        OsString::from("-t"),
        OsString::from("LAST"),
        OsString::from("-l"),
        OsString::from("LAST.jtl"),
        OsString::from("-jLAST.log"),
        OsString::from("-qfirst.properties"),
        OsString::from("-q"),
        OsString::from("second.properties"),
    ])
    .expect("repeatable options and LAST paths should parse");

    assert_eq!(invocation.action, jmeter_rs::Action::Execute);
    assert_eq!(invocation.options.mode, jmeter_rs::RunMode::NonGui);
    assert_eq!(
        invocation.options.addprop,
        ["first.properties", "second.properties"]
    );
    assert_eq!(
        invocation.options.testfile.as_ref().map(|path| path.kind),
        Some(jmeter_rs::PathKind::Last)
    );
    assert_eq!(
        invocation.options.logfile.as_ref().map(|path| path.kind),
        Some(jmeter_rs::PathKind::Last)
    );
    assert_eq!(
        invocation
            .options
            .jmeterlogfile
            .as_ref()
            .map(|path| path.kind),
        Some(jmeter_rs::PathKind::LastLiteral)
    );
}

#[test]
fn report_only_load_output_conflict_is_typed_without_starting_an_engine() {
    let error = jmeter_rs::parse_os([
        OsString::from("-g"),
        OsString::from("input.jtl"),
        OsString::from("-l"),
        OsString::from("result.jtl"),
    ])
    .expect_err("report-only mode must reject load-test output options");

    assert_eq!(error.code(), "cli.incompatible-options");
    assert_eq!(error.exit_class(), jmeter_rs::ExitClass::UsageError);
    assert_eq!(error.exit_code(), 2);
    assert!(matches!(
        error,
        jmeter_rs::CliError::IncompatibleOptions {
            reason: jmeter_rs::CombinationError::ReportOnlyConflict,
            ..
        }
    ));
}

#[test]
fn exit_classes_have_stable_process_statuses() {
    let expected = [
        (jmeter_rs::ExitClass::Success, "ok", 0),
        (jmeter_rs::ExitClass::SampleFailure, "sample.failure", 0),
        (jmeter_rs::ExitClass::UsageError, "cli.usage", 2),
        (
            jmeter_rs::ExitClass::ConfigurationError,
            "config.invalid",
            78,
        ),
        (
            jmeter_rs::ExitClass::UnsupportedCapability,
            "capability.unavailable",
            78,
        ),
        (jmeter_rs::ExitClass::Fatal, "fatal", 1),
        (jmeter_rs::ExitClass::RemoteFailure, "remote.failure", 1),
        (jmeter_rs::ExitClass::InternalError, "internal.error", 70),
    ];

    for (class, code, status) in expected {
        assert_eq!(class.code(), code);
        assert_eq!(class.exit_code(), status);
    }
}

#[test]
#[ignore = "process launch evidence requires an explicit PID-namespace runner"]
fn help_and_version_are_successful_process_actions() {
    require_namespace_scoped_process_test();

    let help = run_cli("--help");
    assert_eq!(help.status.code(), Some(0));
    assert!(help.stderr.is_empty());
    let help_text = String::from_utf8_lossy(&help.stdout);
    assert!(help_text.contains("To run Apache JMeter in NON_GUI mode"));

    let version = run_cli("--version");
    assert_eq!(version.status.code(), Some(0));
    assert!(version.stderr.is_empty());
    assert!(String::from_utf8_lossy(&version.stdout).contains("5.6.3"));
}

#[test]
#[ignore = "process launch evidence requires an explicit PID-namespace runner"]
fn malformed_process_invocation_reports_usage_without_engine_start() {
    require_namespace_scoped_process_test();

    let output = run_cli("--not-a-jmeter-option");
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cli.unknown-option"));
}
