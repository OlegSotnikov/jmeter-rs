// SPDX-License-Identifier: Apache-2.0
//! The `jmeter-rs` command-line application.
//!
//! Thin process edge for the bounded CLI/configuration/runtime adapters.

use std::env;
use std::process::ExitCode;

use jmeter_rs::{Action, LaunchEnvironment, execute_invocation};

fn main() -> ExitCode {
    match jmeter_rs::parse_os(env::args_os().skip(1)) {
        Ok(invocation) => match invocation.action {
            Action::Options => {
                print!("{}", jmeter_rs::options_text());
                ExitCode::SUCCESS
            }
            Action::Help => {
                print!("{}", jmeter_rs::help_text());
                ExitCode::SUCCESS
            }
            Action::Version => {
                print!("{}", jmeter_rs::version_text());
                ExitCode::SUCCESS
            }
            Action::Execute => {
                let launch = match LaunchEnvironment::from_process() {
                    Ok(launch) => launch,
                    Err(error) => {
                        eprintln!("jmeter-rs: ERROR[{}] {error}", error.code());
                        return ExitCode::from(error.exit_class().exit_code());
                    }
                };
                match execute_invocation(&invocation, &launch) {
                    Ok(outcome) => {
                        if outcome.sample_failures > 0 {
                            eprintln!(
                                "jmeter-rs: {} sample failure(s); process status remains successful",
                                outcome.sample_failures
                            );
                        }
                        ExitCode::from(outcome.category.exit_class().exit_code())
                    }
                    Err(error) => {
                        eprintln!("jmeter-rs: ERROR[{}] {error}", error.code());
                        ExitCode::from(error.exit_class().exit_code())
                    }
                }
            }
        },
        Err(error) => {
            eprintln!("jmeter-rs: ERROR[{}] {error}", error.code());
            ExitCode::from(error.exit_code())
        }
    }
}
