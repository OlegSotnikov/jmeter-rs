// SPDX-License-Identifier: Apache-2.0
//! Deterministic application/report adapter integration coverage.

#![allow(
    clippy::expect_used,
    reason = "integration fixtures use assertion-context setup"
)]

use std::fs::{self, File};
use std::io::Write;

use jmeter_rs::{EnvironmentView, LaunchEnvironment, RunCategory, execute_invocation, parse};
use jmeter_rs_results::{
    HostIdentity, SampleEvent, SampleResult, SampleSaveConfiguration, ThreadIdentity,
    VariableSnapshot, WallTimestamp, write_csv, write_xml,
};

const REPORT_FIXTURE_XML: &[u8] = include_bytes!(
    "../../../compat/fixtures/jmeter-5.6.3/reports/aggregate-dashboard/inputs/aggregate.xml"
);
const REPORT_FIXTURE_CSV: &[u8] = include_bytes!(
    "../../../compat/fixtures/jmeter-5.6.3/reports/aggregate-dashboard/inputs/aggregate.csv"
);
const REPORT_FIXTURE_PROPERTIES: &[u8] = include_bytes!(
    "../../../compat/fixtures/jmeter-5.6.3/reports/aggregate-dashboard/report.properties"
);

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
fn report_only_streams_input_larger_than_the_legacy_config_limit() {
    let root = std::env::temp_dir().join(format!(
        "jmeter-rs-report-streaming-input-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("test root");

    let events = (0..2_048)
        .map(|index| {
            let mut result = SampleResult::new("streaming-fixture");
            result.set_timestamp(Some(WallTimestamp::from_millis(index as i64)));
            result.set_successful(true);
            SampleEvent::new(
                result,
                "report-test",
                ThreadIdentity::new("thread-1"),
                HostIdentity::new("localhost"),
                VariableSnapshot::new(),
            )
        })
        .collect::<Vec<_>>();
    let mut input = File::create(root.join("input.jtl")).expect("input JTL");
    write_csv(&mut input, events, SampleSaveConfiguration::default())
        .expect("write streaming input JTL");
    input.flush().expect("flush streaming input JTL");
    assert!(
        fs::metadata(root.join("input.jtl"))
            .expect("input metadata")
            .len()
            > 64 * 1024,
        "fixture must exceed the old whole-file configuration bound"
    );

    let invocation = parse(["-g", "input.jtl", "-o", "dashboard"]).expect("report CLI");
    let outcome = execute_invocation(&invocation, &LaunchEnvironment::new(&root))
        .expect("streaming report input succeeds");
    assert_eq!(outcome.samples, 2_048);
    assert_eq!(outcome.sample_failures, 0);
    assert!(root.join("dashboard/index.html").is_file());
    assert!(root.join("dashboard/data.json").is_file());

    fs::remove_dir_all(&root).expect("test cleanup");
}

#[test]
fn report_only_rejects_load_result_and_plan_options_at_parse_time() {
    let with_result_log = parse(["-g", "input.jtl", "-l", "results.jtl"])
        .expect_err("report-only cannot select a load-test result log");
    assert_eq!(with_result_log.code(), "cli.incompatible-options");
    assert!(with_result_log.to_string().contains("report-only-conflict"));

    let with_plan = parse(["-g", "input.jtl", "-t", "plan.jmx"])
        .expect_err("report-only cannot select a test plan");
    assert_eq!(with_plan.code(), "cli.incompatible-options");
    assert!(with_plan.to_string().contains("report-only-needs-only-jtl"));
}

#[test]
fn report_only_is_deterministic_for_the_static_corpus_without_java_or_network() {
    let root = std::env::temp_dir().join(format!("jmeter-rs-report-static-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("test root");
    fs::write(root.join("aggregate.xml"), REPORT_FIXTURE_XML).expect("fixture XML");
    fs::write(root.join("aggregate.csv"), REPORT_FIXTURE_CSV).expect("fixture CSV");
    fs::write(root.join("report.properties"), REPORT_FIXTURE_PROPERTIES)
        .expect("fixture properties");

    // Java/classpath names are deliberately outside the application
    // environment allowlist.  Report-only mode must remain a native,
    // in-process operation and must not discover or launch a JVM.
    let environment = EnvironmentView::from_pairs([
        ("JAVA_HOME", "/unavailable/java"),
        ("CLASSPATH", "/unavailable/classpath"),
        ("LANG", "en-US"),
        ("TZ", "UTC"),
    ]);
    assert_eq!(environment.get("JAVA_HOME"), None);
    assert_eq!(environment.get("CLASSPATH"), None);
    let launch = LaunchEnvironment::new(&root).with_environment(environment);
    let invocation = parse([
        "-g",
        "aggregate.xml",
        "-q",
        "report.properties",
        "-o",
        "dashboard-a",
    ])
    .expect("static report CLI");
    let input_before = fs::read(root.join("aggregate.xml")).expect("read fixture XML");
    let first = execute_invocation(&invocation, &launch).expect("static report succeeds");
    assert_eq!(first.category, RunCategory::SampleFailure);
    assert_eq!(first.samples, 7);
    assert_eq!(first.sample_failures, 2);
    assert_eq!(
        fs::read(root.join("aggregate.xml")).expect("read input after first"),
        input_before
    );

    let second_invocation = parse([
        "-g",
        "aggregate.xml",
        "-q",
        "report.properties",
        "-o",
        "dashboard-b",
    ])
    .expect("second static report CLI");
    let second = execute_invocation(&second_invocation, &launch).expect("second report succeeds");
    assert_eq!(second.samples, first.samples);
    assert_eq!(second.sample_failures, first.sample_failures);

    let csv_invocation =
        parse(["-g", "aggregate.csv", "-o", "dashboard-csv"]).expect("CSV static report CLI");
    let csv = execute_invocation(&csv_invocation, &launch).expect("CSV report succeeds");
    assert_eq!(csv.samples, first.samples);
    assert_eq!(csv.sample_failures, first.sample_failures);

    for name in ["index.html", "data.json"] {
        let first_bytes = fs::read(root.join("dashboard-a").join(name)).expect("first output");
        let second_bytes = fs::read(root.join("dashboard-b").join(name)).expect("second output");
        assert_eq!(
            first_bytes, second_bytes,
            "report output {name} is nondeterministic"
        );
        assert_eq!(
            first_bytes,
            fs::read(root.join("dashboard-csv").join(name)).expect("CSV report output"),
            "CSV and XML report output {name} differs"
        );
        assert!(
            first_bytes.len() <= 64 * 1024,
            "report output {name} exceeded its bound"
        );
    }
    let data = fs::read_to_string(root.join("dashboard-a/data.json")).expect("dashboard data");
    assert!(data.contains("\"sample_count\":7"));
    assert!(data.contains("\"error_count\":2"));
    assert!(data.contains("api/cache"));
    assert!(
        fs::read_dir(&root)
            .expect("root entries")
            .filter_map(Result::ok)
            .all(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                !name.starts_with(".jmeter-rs-dashboard-stage")
                    && !name.starts_with(".jmeter-rs-dashboard-old")
            })
    );

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
fn report_only_rejects_explicit_format_mismatch_without_replacing_dashboard() {
    let root = std::env::temp_dir().join(format!(
        "jmeter-rs-report-format-mismatch-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("dashboard")).expect("test root");
    fs::write(
        root.join("input.jtl"),
        b"timeStamp,elapsed,label\n0,1,mismatch\n",
    )
    .expect("CSV input");
    fs::write(root.join("dashboard/index.html"), b"old-index").expect("published index");
    fs::write(root.join("dashboard/data.json"), b"old-data").expect("published data");
    fs::write(root.join("dashboard/keep.txt"), b"published-generation").expect("published marker");

    let error = execute_invocation(
        &parse([
            "-g",
            "input.jtl",
            "-o",
            "dashboard",
            "-f",
            "-J",
            "jmeter.save.saveservice.output_format=xml",
        ])
        .expect("report CLI"),
        &LaunchEnvironment::new(&root),
    )
    .expect_err("CSV input must not be decoded with explicitly configured XML");
    assert_eq!(error.code(), "app.report-input.format-mismatch");
    assert_eq!(
        fs::read(root.join("dashboard/index.html")).expect("index"),
        b"old-index"
    );
    assert_eq!(
        fs::read(root.join("dashboard/data.json")).expect("data"),
        b"old-data"
    );
    assert_eq!(
        fs::read(root.join("dashboard/keep.txt")).expect("marker"),
        b"published-generation"
    );
    assert!(!root.join("jmeter.log").exists());
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
fn malformed_report_input_keeps_the_published_generation_and_cleans_staging() {
    let root =
        std::env::temp_dir().join(format!("jmeter-rs-report-malformed-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("dashboard")).expect("test root");
    fs::write(
        root.join("input.jtl"),
        b"timeStamp,elapsed,label\n0,1,valid\n\"unterminated",
    )
    .expect("malformed JTL");
    fs::write(root.join("dashboard/index.html"), b"old-index").expect("published index");
    fs::write(root.join("dashboard/data.json"), b"old-data").expect("published data");
    fs::write(root.join("dashboard/keep.txt"), b"published-generation").expect("published marker");
    let before_index = fs::read(root.join("dashboard/index.html")).expect("read published index");
    let before_data = fs::read(root.join("dashboard/data.json")).expect("read published data");
    let before = fs::read(root.join("dashboard/keep.txt")).expect("read published marker");

    let error = execute_invocation(
        &parse(["-g", "input.jtl", "-o", "dashboard", "-f"]).expect("report CLI"),
        &LaunchEnvironment::new(&root),
    )
    .expect_err("malformed JTL must fail before publication");
    assert_eq!(error.code(), "results.jtl.csv");
    assert_eq!(
        fs::read(root.join("dashboard/keep.txt")).expect("read marker after"),
        before
    );
    assert_eq!(
        fs::read(root.join("dashboard/index.html")).expect("read index after"),
        before_index
    );
    assert_eq!(
        fs::read(root.join("dashboard/data.json")).expect("read data after"),
        before_data
    );
    assert!(
        !root.join("jmeter.log").exists(),
        "malformed input must not publish a logger side effect"
    );
    assert!(
        fs::read_dir(&root)
            .expect("root entries")
            .filter_map(Result::ok)
            .all(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                !name.starts_with(".jmeter-rs-dashboard-stage")
                    && !name.starts_with(".jmeter-rs-dashboard-old")
            })
    );

    fs::remove_dir_all(&root).expect("test cleanup");
}

#[test]
fn report_input_prefix_limit_is_rejected_before_output_replacement() {
    let root = std::env::temp_dir().join(format!("jmeter-rs-report-bound-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("dashboard")).expect("test root");
    fs::write(root.join("input.jtl"), vec![b' '; 64 * 1024 + 1]).expect("oversized JTL");
    fs::write(root.join("dashboard/keep.txt"), b"published-generation").expect("published marker");

    let error = execute_invocation(
        &parse(["-g", "input.jtl", "-o", "dashboard", "-f"]).expect("report CLI"),
        &LaunchEnvironment::new(&root),
    )
    .expect_err("ambiguous oversized prefix must fail closed");
    assert_eq!(error.code(), "app.report-input.prefix-limit");
    assert_eq!(
        fs::read(root.join("dashboard/keep.txt")).expect("published marker after bound"),
        b"published-generation"
    );
    assert!(
        fs::read_dir(&root)
            .expect("root entries")
            .filter_map(Result::ok)
            .all(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                !name.starts_with(".jmeter-rs-dashboard-stage")
                    && !name.starts_with(".jmeter-rs-dashboard-old")
            })
    );

    fs::remove_dir_all(&root).expect("test cleanup");
}

#[test]
fn report_at_end_missing_plan_is_rejected_before_publication() {
    let root = std::env::temp_dir().join(format!("jmeter-rs-report-at-end-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("test root");

    let error = execute_invocation(
        &parse([
            "-n",
            "-t",
            "plan.jmx",
            "-l",
            "results.jtl",
            "-e",
            "-o",
            "dashboard",
        ])
        .expect("report-at-end CLI"),
        &LaunchEnvironment::new(&root),
    )
    .expect_err("post-run reporting remains an explicit router boundary");
    assert_eq!(error.code(), "config.missing-source");
    assert!(error.to_string().contains("plan.jmx"));
    assert!(!root.join("results.jtl").exists());
    assert!(!root.join("dashboard").exists());
    assert!(!root.join("java").exists());
    assert!(!root.join("jmeter").exists());
    assert!(!root.join("jmeter.log").exists());
    assert!(
        fs::read_dir(&root)
            .expect("root entries")
            .filter_map(Result::ok)
            .all(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                !name.starts_with(".jmeter-rs-dashboard-stage")
                    && !name.starts_with(".jmeter-rs-dashboard-old")
            })
    );

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
fn unsupported_mode_is_rejected_before_log_creation() {
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

    assert!(!root.join("jmeter.log").exists());
    assert!(
        fs::read_dir(&root)
            .expect("root entries")
            .filter_map(Result::ok)
            .all(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                !name.starts_with(".jmeter-rs-dashboard-stage")
                    && !name.starts_with(".jmeter-rs-dashboard-old")
            })
    );

    fs::remove_dir_all(&root).expect("test cleanup");
}
