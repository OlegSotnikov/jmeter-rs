// SPDX-License-Identifier: Apache-2.0
//! Deterministic application/report adapter integration coverage.

#![allow(
    clippy::expect_used,
    reason = "integration fixtures use assertion-context setup"
)]

use std::fs::{self, File};

use jmeter_rs::{LaunchEnvironment, RunCategory, execute_invocation, parse};
use jmeter_rs_results::{
    HostIdentity, SampleEvent, SampleResult, SampleSaveConfiguration, ThreadIdentity,
    VariableSnapshot, WallTimestamp, write_csv, write_xml,
};

#[test]
fn report_only_uses_the_typed_report_adapter_and_writes_bounded_outputs() {
    let root =
        std::env::temp_dir().join(format!("jmeter-rs-report-adapter-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("test root");

    let mut result = SampleResult::new("adapter-fixture");
    result.set_timestamp(Some(WallTimestamp::from_millis(1_000)));
    result.set_successful(true);
    let event = SampleEvent::new(
        result,
        "report-test",
        ThreadIdentity::new("thread-1"),
        HostIdentity::new("localhost"),
        VariableSnapshot::new(),
    );
    let mut input = File::create(root.join("input.jtl")).expect("input JTL");
    write_csv(&mut input, [&event], SampleSaveConfiguration::default())
        .expect("write deterministic input JTL");

    let invocation = parse(["-g", "input.jtl", "-o", "dashboard"]).expect("report CLI");
    let outcome = execute_invocation(
        &invocation,
        &LaunchEnvironment::new(&root).with_now_millis(0),
    )
    .expect("report adapter succeeds");

    assert_eq!(outcome.category, RunCategory::Normal);
    assert_eq!(outcome.samples, 1);
    assert_eq!(outcome.sample_failures, 0);
    assert!(root.join("dashboard/index.html").is_file());
    assert!(root.join("dashboard/data.json").is_file());
    assert!(root.join("jmeter.log").is_file());

    fs::remove_dir_all(&root).expect("test cleanup");
}

#[test]
fn report_only_uses_an_explicit_replace_mode_and_publishes_one_directory() {
    let root =
        std::env::temp_dir().join(format!("jmeter-rs-report-replace-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("test root");

    let event = SampleEvent::new(
        SampleResult::new("replace-fixture"),
        "report-test",
        ThreadIdentity::new("thread-1"),
        HostIdentity::new("localhost"),
        VariableSnapshot::new(),
    );
    let mut input = File::create(root.join("input.jtl")).expect("input JTL");
    write_csv(&mut input, [&event], SampleSaveConfiguration::default())
        .expect("write deterministic input JTL");

    fs::create_dir(root.join("dashboard")).expect("old dashboard");
    fs::write(root.join("dashboard/keep.txt"), b"old").expect("old dashboard marker");
    let refused = execute_invocation(
        &parse(["-g", "input.jtl", "-o", "dashboard"]).expect("report CLI"),
        &LaunchEnvironment::new(&root),
    )
    .expect_err("non-empty output requires explicit replacement");
    assert_eq!(refused.code(), "io.output");
    assert!(root.join("dashboard/keep.txt").is_file());

    let outcome = execute_invocation(
        &parse(["-g", "input.jtl", "-o", "dashboard", "-f"]).expect("replace CLI"),
        &LaunchEnvironment::new(&root),
    )
    .expect("replacement report succeeds");
    assert_eq!(outcome.samples, 1);
    assert!(root.join("dashboard/index.html").is_file());
    assert!(root.join("dashboard/data.json").is_file());
    assert!(!root.join("dashboard/keep.txt").exists());
    assert!(
        fs::read_dir(&root)
            .expect("root entries")
            .filter_map(Result::ok)
            .all(|entry| !entry
                .file_name()
                .to_string_lossy()
                .starts_with(".jmeter-rs-dashboard-"))
    );

    fs::remove_dir_all(&root).expect("test cleanup");
}

#[test]
fn report_only_decodes_xml_using_the_resolved_save_configuration() {
    let root = std::env::temp_dir().join(format!("jmeter-rs-report-xml-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("test root");

    let event = SampleEvent::new(
        SampleResult::new("xml-fixture"),
        "report-test",
        ThreadIdentity::new("thread-1"),
        HostIdentity::new("localhost"),
        VariableSnapshot::new(),
    );
    let mut input = File::create(root.join("input.jtl")).expect("input JTL");
    write_xml(&mut input, [&event], SampleSaveConfiguration::xml())
        .expect("write deterministic XML JTL");

    let invocation = parse([
        "-g",
        "input.jtl",
        "-o",
        "dashboard",
        "-J",
        "jmeter.save.saveservice.output_format=xml",
    ])
    .expect("XML report CLI");
    let outcome = execute_invocation(&invocation, &LaunchEnvironment::new(&root))
        .expect("XML report adapter succeeds");
    assert_eq!(outcome.samples, 1);
    assert!(root.join("dashboard/index.html").is_file());
    assert!(root.join("dashboard/data.json").is_file());

    fs::remove_dir_all(&root).expect("test cleanup");
}

#[test]
fn report_only_without_output_folder_is_an_explicit_oracle_boundary() {
    let root = std::env::temp_dir().join(format!(
        "jmeter-rs-report-default-output-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("test root");
    fs::write(root.join("input.jtl"), b"timeStamp,elapsed,label\n").expect("input JTL");

    let error = execute_invocation(
        &parse(["-g", "input.jtl"]).expect("report CLI"),
        &LaunchEnvironment::new(&root),
    )
    .expect_err("unproven report default must not become a guessed directory");
    assert_eq!(error.code(), "capability.unavailable");
    assert!(error.to_string().contains("report-output-default"));

    fs::remove_dir_all(&root).expect("test cleanup");
}

#[test]
fn unsupported_mode_flushes_a_typed_capability_diagnostic_to_the_run_log() {
    let root =
        std::env::temp_dir().join(format!("jmeter-rs-capability-log-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("test root");

    let invocation = parse(std::iter::empty::<&str>()).expect("default GUI invocation");
    let error = execute_invocation(
        &invocation,
        &LaunchEnvironment::new(&root).with_now_millis(0),
    )
    .expect_err("GUI remains an explicit capability boundary");
    assert_eq!(error.code(), "capability.unavailable");
    assert_eq!(error.exit_class().exit_code(), 78);

    let log = fs::read_to_string(root.join("jmeter.log")).expect("capability log");
    assert!(log.contains("Apache JMeter 5.6.3"));
    assert!(log.contains("locale=en-US"));

    fs::remove_dir_all(&root).expect("test cleanup");
}
