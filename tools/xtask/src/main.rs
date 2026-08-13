// SPDX-License-Identifier: Apache-2.0
//! Reproducible repository checks and generated-profile tasks.

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;
use xtask::{Command, Options, ProfileReferencesAction, PropertyInventoryAction};

fn main() -> ExitCode {
    let mut arguments = env::args().skip(1);
    let Some(command_name) = arguments.next() else {
        print_usage();
        return ExitCode::from(2);
    };
    let command = match command_name.as_str() {
        "profile-check" => Command::ProfileCheck,
        "fixture-check" => Command::FixtureCheck,
        "workspace-check" => Command::WorkspaceCheck,
        "policy-check" | "determinism-check" => Command::PolicyCheck,
        "external-acceptance" => Command::ExternalAcceptance,
        "http-acceptance" => Command::HttpAcceptance,
        "gui-acceptance" => Command::GuiAcceptanceCheck,
        "property-inventory" => Command::PropertyInventory,
        "profile-references" => Command::ProfileReferences,
        "help" | "--help" | "-h" => {
            print_usage();
            return ExitCode::SUCCESS;
        }
        _ => {
            eprintln!("ERROR[XTASK-USAGE] unknown command {command_name:?}");
            print_usage();
            return ExitCode::from(2);
        }
    };

    let root = match env::current_dir() {
        Ok(root) => root,
        Err(error) => {
            eprintln!("ERROR[XTASK-IO] cannot determine current directory: {error}");
            return ExitCode::from(1);
        }
    };
    let mut options = Options::new(root);
    let mut parse_error = None;
    while let Some(argument) = arguments.next() {
        let (name, inline_value) = argument
            .split_once('=')
            .map_or((argument.as_str(), None), |(name, value)| {
                (name, Some(value))
            });
        let value = match inline_value {
            Some(value) => Some(value.to_owned()),
            None => match name {
                "--root" | "--profile" | "--fixtures" | "--manifest" | "--source" | "--output" => {
                    arguments.next()
                }
                _ => None,
            },
        };
        match name {
            "--root" => match value {
                Some(value) => options.root = PathBuf::from(value),
                None => parse_error = Some("--root requires a path"),
            },
            "--profile" => match value {
                Some(value) => options.profile = Some(PathBuf::from(value)),
                None => parse_error = Some("--profile requires a path"),
            },
            "--fixtures" => match value {
                Some(value) => options.fixtures = Some(PathBuf::from(value)),
                None => parse_error = Some("--fixtures requires a path"),
            },
            "--source" if command == Command::PropertyInventory => match value {
                Some(value) => options.property_inventory_source = Some(PathBuf::from(value)),
                None => parse_error = Some("--source requires a path"),
            },
            "--output" if command == Command::PropertyInventory => match value {
                Some(value) => options.property_inventory_output = Some(PathBuf::from(value)),
                None => parse_error = Some("--output requires a path"),
            },
            "--manifest" if command == Command::ExternalAcceptance => match value {
                Some(value) => options.external_acceptance_manifest = Some(PathBuf::from(value)),
                None => parse_error = Some("--manifest requires a path"),
            },
            "--check" if command == Command::ExternalAcceptance => {}
            "--check" if command == Command::HttpAcceptance => {
                if options.http_acceptance_check {
                    parse_error = Some("HTTP acceptance check was specified more than once");
                } else {
                    options.http_acceptance_check = true;
                }
            }
            "--check" if command == Command::GuiAcceptanceCheck => {}
            "--generate" if command == Command::PropertyInventory => {
                if options.property_inventory_action.is_some() {
                    parse_error = Some("property inventory action was specified more than once");
                } else {
                    options.property_inventory_action = Some(PropertyInventoryAction::Generate);
                }
            }
            "--check" if command == Command::PropertyInventory => {
                if options.property_inventory_action.is_some() {
                    parse_error = Some("property inventory action was specified more than once");
                } else {
                    options.property_inventory_action = Some(PropertyInventoryAction::Check);
                }
            }
            "generate" if command == Command::PropertyInventory => {
                if options.property_inventory_action.is_some() {
                    parse_error = Some("property inventory action was specified more than once");
                } else {
                    options.property_inventory_action = Some(PropertyInventoryAction::Generate);
                }
            }
            "check" if command == Command::PropertyInventory => {
                if options.property_inventory_action.is_some() {
                    parse_error = Some("property inventory action was specified more than once");
                } else {
                    options.property_inventory_action = Some(PropertyInventoryAction::Check);
                }
            }
            "--generate" if command == Command::ProfileReferences => {
                if options.profile_reference_action.is_some() {
                    parse_error = Some("profile reference action was specified more than once");
                } else {
                    options.profile_reference_action = Some(ProfileReferencesAction::Generate);
                }
            }
            "--check" if command == Command::ProfileReferences => {
                if options.profile_reference_action.is_some() {
                    parse_error = Some("profile reference action was specified more than once");
                } else {
                    options.profile_reference_action = Some(ProfileReferencesAction::Check);
                }
            }
            "generate" if command == Command::ProfileReferences => {
                if options.profile_reference_action.is_some() {
                    parse_error = Some("profile reference action was specified more than once");
                } else {
                    options.profile_reference_action = Some(ProfileReferencesAction::Generate);
                }
            }
            "check" if command == Command::ProfileReferences => {
                if options.profile_reference_action.is_some() {
                    parse_error = Some("profile reference action was specified more than once");
                } else {
                    options.profile_reference_action = Some(ProfileReferencesAction::Check);
                }
            }
            "--help" | "-h" => {
                print_usage();
                return ExitCode::SUCCESS;
            }
            _ => parse_error = Some("unknown option; use --help for usage"),
        }
        if parse_error.is_some() {
            break;
        }
    }
    if let Some(error) = parse_error {
        eprintln!("ERROR[XTASK-USAGE] {error}");
        return ExitCode::from(2);
    }

    let diagnostics = xtask::run(command, &options);
    if diagnostics.is_empty() {
        println!("xtask: {command_name} passed");
        ExitCode::SUCCESS
    } else {
        for diagnostic in diagnostics {
            eprintln!("{diagnostic}");
        }
        ExitCode::from(1)
    }
}

fn print_usage() {
    eprintln!(
        "usage: cargo xtask <profile-check|fixture-check|workspace-check|policy-check|external-acceptance|http-acceptance|gui-acceptance|property-inventory|profile-references> [--root PATH] [--profile PATH] [--fixtures PATH] [--manifest PATH]\n       cargo xtask property-inventory [--generate|--check] [--source PATH] [--output PATH]\n       cargo xtask external-acceptance --check [--manifest PATH]\n       cargo xtask http-acceptance --check [--root PATH] [--profile PATH] [--fixtures PATH]\n       cargo xtask gui-acceptance --check [--root PATH] [--profile PATH] [--fixtures PATH]\n       cargo xtask profile-references [--generate|--check]"
    );
}
