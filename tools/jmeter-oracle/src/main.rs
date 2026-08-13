// SPDX-License-Identifier: Apache-2.0
//! Command-line entry point for the pinned JMeter oracle harness.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use jmeter_oracle::{
    CompareFormat, CompareLimits, CompareOptions, ErrorCode, OracleError, OracleRunner, RunRequest,
    RunnerLimits, compare_case_artifacts, metadata_json, parse_positive_u64, validation_json,
    verify_artifact,
};

const USAGE: &str = "\
jmeter-oracle validate --profile PATH --case PATH [options]
jmeter-oracle dry-run  --profile PATH --case PATH --jmeter PATH [options]
jmeter-oracle run      --profile PATH --case PATH --jmeter PATH --java PATH --artifact PATH [options]
jmeter-oracle compare  --profile PATH --case PATH --actual PATH [options]

Options:
  --profile PATH              pinned compatibility profile (required)
  --case PATH                 oracle case manifest (required)
  --fixture-dir PATH          case fixture root (default: case manifest parent)
  --jmeter PATH               absolute JMeter launcher path
  --java PATH                 absolute Java executable path
  --artifact PATH             supplied JMeter ZIP; never downloaded
  --output-dir PATH           explicit artifact/workspace root
  --variant N                 zero-based command-template selection
  --timeout-ms N              child deadline in milliseconds
  --max-output-bytes N        bound for each child output pipe
  --max-artifact-bytes N      bound for each JTL/log artifact
  --actual PATH               actual bounded JTL or neutral JSON projection
  --expected PATH             expected projection (default: case execution.expected)
  --format FORMAT             csv, xml, json, or jmx-semantic input hint
  --max-events N              maximum top-level events in compare mode
  --max-depth N               maximum XML nesting depth in compare mode
  --max-diff-count N          maximum structured differences
  --max-human-diff-bytes N    maximum concise diff bytes
  --json                      pretty JSON output
  --help                      show this help

validate checks profile/case references and fixture digests. dry-run builds
commands but does not launch Java/JMeter. run requires a verified archive and
explicit Java/JMeter paths. compare emits a bounded structured/human diff and
returns a comparison-mismatch error when semantic fields differ.
";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Validate,
    DryRun,
    Run,
    Compare,
}

fn main() -> ExitCode {
    match run_cli() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("jmeter-oracle error: {}", error.diagnostic());
            ExitCode::from(exit_code(error.code()))
        }
    }
}

fn run_cli() -> Result<(), OracleError> {
    let mut arguments = std::env::args().skip(1);
    let Some(mode) = arguments.next() else {
        print!("{}", USAGE);
        return Err(OracleError::new_for_cli(
            ErrorCode::Configuration,
            "a mode is required",
        ));
    };
    if mode == "--help" || mode == "-h" {
        print!("{}", USAGE);
        return Ok(());
    }
    let mode = match mode.as_str() {
        "validate" => Mode::Validate,
        "dry-run" => Mode::DryRun,
        "run" => Mode::Run,
        "compare" => Mode::Compare,
        other => {
            return Err(OracleError::new_for_cli(
                ErrorCode::Configuration,
                format!("unknown mode '{}'", other),
            ));
        }
    };
    let mut profile = None;
    let mut case_file = None;
    let mut fixture_dir = None;
    let mut jmeter = None;
    let mut java = None;
    let mut artifact = None;
    let mut output_dir = None;
    let mut actual = None;
    let mut expected = None;
    let mut compare_format = None;
    let mut variant = None;
    let mut limits = RunnerLimits::default();
    let mut compare_limits = CompareLimits::default();
    let mut json = false;
    while let Some(argument) = arguments.next() {
        if argument == "--help" || argument == "-h" {
            print!("{}", USAGE);
            return Ok(());
        }
        if argument == "--json" {
            json = true;
            continue;
        }
        let value = |name: &str,
                     arguments: &mut std::iter::Skip<std::env::Args>|
         -> Result<String, OracleError> {
            arguments.next().ok_or_else(|| {
                OracleError::new_for_cli(
                    ErrorCode::Configuration,
                    format!("{} requires a value", name),
                )
            })
        };
        match argument.as_str() {
            "--profile" => profile = Some(PathBuf::from(value("--profile", &mut arguments)?)),
            "--case" => case_file = Some(PathBuf::from(value("--case", &mut arguments)?)),
            "--fixture-dir" => {
                fixture_dir = Some(PathBuf::from(value("--fixture-dir", &mut arguments)?))
            }
            "--jmeter" => jmeter = Some(PathBuf::from(value("--jmeter", &mut arguments)?)),
            "--java" => java = Some(PathBuf::from(value("--java", &mut arguments)?)),
            "--artifact" => artifact = Some(PathBuf::from(value("--artifact", &mut arguments)?)),
            "--output-dir" => {
                output_dir = Some(PathBuf::from(value("--output-dir", &mut arguments)?))
            }
            "--actual" => actual = Some(PathBuf::from(value("--actual", &mut arguments)?)),
            "--expected" => expected = Some(PathBuf::from(value("--expected", &mut arguments)?)),
            "--format" => {
                let raw = value("--format", &mut arguments)?;
                compare_format = Some(match raw.to_ascii_lowercase().as_str() {
                    "csv" | "jtl-csv" => CompareFormat::Csv,
                    "xml" | "jtl-xml" => CompareFormat::Xml,
                    "json" | "neutral-json" => CompareFormat::Json,
                    "jmx" | "jmx-semantic" => CompareFormat::JmxSemantic,
                    _ => {
                        return Err(OracleError::new_for_cli(
                            ErrorCode::Configuration,
                            "--format must be csv, xml, json, or jmx-semantic",
                        ));
                    }
                });
            }
            "--variant" => {
                let raw = value("--variant", &mut arguments)?;
                variant = Some(raw.parse::<usize>().map_err(|_| {
                    OracleError::new_for_cli(
                        ErrorCode::Configuration,
                        "--variant must be a zero-based unsigned integer",
                    )
                })?);
            }
            "--timeout-ms" => {
                let millis =
                    parse_positive_u64(&value("--timeout-ms", &mut arguments)?, "--timeout-ms")?;
                limits.timeout = Duration::from_millis(millis);
            }
            "--max-output-bytes" => {
                let bytes = parse_positive_u64(
                    &value("--max-output-bytes", &mut arguments)?,
                    "--max-output-bytes",
                )?;
                limits.max_process_output_bytes = usize::try_from(bytes).map_err(|_| {
                    OracleError::new_for_cli(ErrorCode::Configuration, "output bound is too large")
                })?;
            }
            "--max-artifact-bytes" => {
                let bytes = parse_positive_u64(
                    &value("--max-artifact-bytes", &mut arguments)?,
                    "--max-artifact-bytes",
                )?;
                limits.max_artifact_bytes = bytes;
                compare_limits.max_input_bytes = bytes;
            }
            "--max-events" => {
                let value =
                    parse_positive_u64(&value("--max-events", &mut arguments)?, "--max-events")?;
                compare_limits.max_events = usize::try_from(value).map_err(|_| {
                    OracleError::new_for_cli(ErrorCode::Configuration, "event bound is too large")
                })?;
            }
            "--max-depth" => {
                let value =
                    parse_positive_u64(&value("--max-depth", &mut arguments)?, "--max-depth")?;
                compare_limits.max_depth = usize::try_from(value).map_err(|_| {
                    OracleError::new_for_cli(ErrorCode::Configuration, "depth bound is too large")
                })?;
            }
            "--max-diff-count" => {
                let value = parse_positive_u64(
                    &value("--max-diff-count", &mut arguments)?,
                    "--max-diff-count",
                )?;
                compare_limits.max_diff_count = usize::try_from(value).map_err(|_| {
                    OracleError::new_for_cli(ErrorCode::Configuration, "diff bound is too large")
                })?;
            }
            "--max-human-diff-bytes" => {
                let value = parse_positive_u64(
                    &value("--max-human-diff-bytes", &mut arguments)?,
                    "--max-human-diff-bytes",
                )?;
                compare_limits.max_human_diff_bytes = usize::try_from(value).map_err(|_| {
                    OracleError::new_for_cli(
                        ErrorCode::Configuration,
                        "human diff bound is too large",
                    )
                })?;
            }
            other => {
                return Err(OracleError::new_for_cli(
                    ErrorCode::Configuration,
                    format!("unknown option '{}'", other),
                ));
            }
        }
    }
    let profile = profile.ok_or_else(|| {
        OracleError::new_for_cli(ErrorCode::Configuration, "--profile is required")
    })?;
    let case_file = case_file
        .ok_or_else(|| OracleError::new_for_cli(ErrorCode::Configuration, "--case is required"))?;
    let fixture_dir = fixture_dir.unwrap_or_else(|| {
        case_file
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))
    });
    let fixture = OracleRunner::validate(&profile, &case_file, fixture_dir)?;
    let artifact_metadata = match artifact {
        Some(path) => Some(verify_artifact(fixture.profile(), path)?),
        None => None,
    };
    match mode {
        Mode::Validate => {
            let report = validation_json(&fixture, artifact_metadata.as_ref());
            print_report(&report, json)?;
        }
        Mode::DryRun => {
            let jmeter = jmeter.ok_or_else(|| {
                OracleError::new_for_cli(
                    ErrorCode::Configuration,
                    "--jmeter is required for dry-run",
                )
            })?;
            let request = RunRequest {
                fixture,
                jmeter_path: jmeter,
                java_path: java,
                artifact: artifact_metadata,
                output_root: output_dir,
                limits,
                template_index: variant,
            };
            let report = OracleRunner.dry_run(&request)?;
            print_report(&report, json)?;
        }
        Mode::Run => {
            let jmeter = jmeter.ok_or_else(|| {
                OracleError::new_for_cli(ErrorCode::Configuration, "--jmeter is required for run")
            })?;
            let java = java.ok_or_else(|| {
                OracleError::new_for_cli(ErrorCode::Configuration, "--java is required for run")
            })?;
            let artifact = artifact_metadata.ok_or_else(|| {
                OracleError::new_for_cli(ErrorCode::Configuration, "--artifact is required for run")
            })?;
            let request = RunRequest {
                fixture,
                jmeter_path: jmeter,
                java_path: Some(java),
                artifact: Some(artifact),
                output_root: output_dir,
                limits,
                template_index: variant,
            };
            let report = OracleRunner.run(&request)?;
            print_report(&report, json)?;
        }
        Mode::Compare => {
            let actual = actual.ok_or_else(|| {
                OracleError::new_for_cli(
                    ErrorCode::Configuration,
                    "--actual is required for compare",
                )
            })?;
            let mut options = CompareOptions::with_policies(
                fixture.case().normalization_policy_refs().iter().cloned(),
            );
            options.format = compare_format;
            options.limits = compare_limits;
            let report = compare_case_artifacts(&fixture, actual, expected, &options)?;
            let equal = report.equal;
            let human_diff = report.human_diff.clone();
            print_report(&report, json)?;
            if !equal {
                return Err(OracleError::new_for_cli(
                    ErrorCode::ComparisonMismatch,
                    human_diff,
                ));
            }
        }
    }
    Ok(())
}

fn print_report<T: serde::Serialize>(value: &T, json_output: bool) -> Result<(), OracleError> {
    if json_output {
        println!("{}", metadata_json(value)?);
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(value).map_err(|error| OracleError::new_for_cli(
                ErrorCode::Internal,
                format!("serialize report: {}", error)
            ))?
        );
    }
    Ok(())
}

fn exit_code(code: ErrorCode) -> u8 {
    match code {
        ErrorCode::Configuration
        | ErrorCode::ManifestJson
        | ErrorCode::ManifestSchema
        | ErrorCode::ManifestMismatch => 64,
        ErrorCode::UnsupportedPlatform => 78,
        ErrorCode::Timeout => 124,
        ErrorCode::OutputLimit => 125,
        _ => 1,
    }
}
