// SPDX-License-Identifier: Apache-2.0
//! Reproducible repository checks and generated-profile tasks.

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;
use xtask::{Command, Options, ProfileReferencesAction, PropertyInventoryAction};

const EXIT_USAGE: u8 = 2;
const USAGE: &str = "usage: cargo xtask <profile-check|fixture-check|workspace-check|policy-check|determinism-check|external-acceptance|http-acceptance|gui-acceptance|property-inventory|profile-references> [--root PATH] [--profile PATH] [--fixtures PATH] [--manifest PATH]\n       cargo xtask property-inventory [--generate|--check] [--source PATH] [--output PATH]\n       cargo xtask external-acceptance --check [--manifest PATH]\n       cargo xtask http-acceptance --check [--root PATH] [--profile PATH] [--fixtures PATH]\n       cargo xtask gui-acceptance --check [--root PATH] [--profile PATH] [--fixtures PATH]\n       cargo xtask profile-references [--generate|--check]";

#[derive(Debug)]
enum ParseOutcome {
    Help,
    Run {
        command_name: String,
        command: Command,
        options: Options,
    },
}

fn main() -> ExitCode {
    let arguments: Vec<String> = match env::args_os()
        .skip(1)
        .map(|argument| argument.into_string())
        .collect()
    {
        Ok(arguments) => arguments,
        Err(_) => {
            eprintln!("ERROR[XTASK-USAGE] arguments must be valid UTF-8");
            print_usage(false);
            return ExitCode::from(EXIT_USAGE);
        }
    };
    if arguments.is_empty() {
        print_usage(false);
        return ExitCode::from(EXIT_USAGE);
    }
    if matches!(arguments[0].as_str(), "help" | "--help" | "-h") {
        print_usage(true);
        return ExitCode::SUCCESS;
    }

    let root = match env::current_dir() {
        Ok(root) => root,
        Err(error) => {
            eprintln!("ERROR[XTASK-IO] cannot determine current directory: {error}");
            return ExitCode::from(1);
        }
    };
    let parsed = match parse_arguments(&arguments, root) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("ERROR[XTASK-USAGE] {error}");
            print_usage(false);
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let ParseOutcome::Run {
        command_name,
        command,
        options,
    } = parsed
    else {
        print_usage(true);
        return ExitCode::SUCCESS;
    };

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

fn parse_arguments(arguments: &[String], root: PathBuf) -> Result<ParseOutcome, String> {
    let Some(command_name) = arguments.first() else {
        return Err("a command is required; use --help for usage".to_owned());
    };
    let Some(command) = command_from_name(command_name) else {
        return Err(format!(
            "unknown command {command_name:?}; use --help for usage"
        ));
    };
    let mut options = Options::new(root);
    let mut seen_check = false;

    let mut index = 1;
    while index < arguments.len() {
        let argument = &arguments[index];
        if argument == "--help" || argument == "-h" {
            return Ok(ParseOutcome::Help);
        }
        if argument.starts_with("--help=") {
            return Err("--help does not take a value".to_owned());
        }

        let (name, inline_value) = argument
            .split_once('=')
            .map_or((argument.as_str(), None), |(name, value)| {
                (name, Some(value))
            });
        match name {
            "--root" => {
                let value = option_value(arguments, &mut index, inline_value, "--root")?;
                options.root = PathBuf::from(value);
            }
            "--profile" => {
                let value = option_value(arguments, &mut index, inline_value, "--profile")?;
                options.profile = Some(PathBuf::from(value));
            }
            "--fixtures" => {
                let value = option_value(arguments, &mut index, inline_value, "--fixtures")?;
                options.fixtures = Some(PathBuf::from(value));
            }
            "--source" if command == Command::PropertyInventory => {
                let value = option_value(arguments, &mut index, inline_value, "--source")?;
                options.property_inventory_source = Some(PathBuf::from(value));
            }
            "--output" if command == Command::PropertyInventory => {
                let value = option_value(arguments, &mut index, inline_value, "--output")?;
                options.property_inventory_output = Some(PathBuf::from(value));
            }
            "--manifest" if command == Command::ExternalAcceptance => {
                let value = option_value(arguments, &mut index, inline_value, "--manifest")?;
                options.external_acceptance_manifest = Some(PathBuf::from(value));
            }
            "--check"
                if matches!(
                    command,
                    Command::ExternalAcceptance
                        | Command::HttpAcceptance
                        | Command::GuiAcceptanceCheck
                        | Command::PropertyInventory
                        | Command::ProfileReferences
                ) =>
            {
                reject_inline_value(inline_value, "--check")?;
                if command == Command::HttpAcceptance && options.http_acceptance_check {
                    return Err("HTTP acceptance check was specified more than once".to_owned());
                }
                if command == Command::PropertyInventory || command == Command::ProfileReferences {
                    set_action(&mut options, command, Action::Check)?;
                } else if seen_check {
                    return Err("--check was specified more than once".to_owned());
                } else {
                    seen_check = true;
                    if command == Command::HttpAcceptance {
                        options.http_acceptance_check = true;
                    }
                }
            }
            "--generate"
                if command == Command::PropertyInventory
                    || command == Command::ProfileReferences =>
            {
                reject_inline_value(inline_value, "--generate")?;
                set_action(&mut options, command, Action::Generate)?;
            }
            "generate" if command == Command::PropertyInventory => {
                set_action(&mut options, command, Action::Generate)?;
            }
            "check" if command == Command::PropertyInventory => {
                set_action(&mut options, command, Action::Check)?;
            }
            "generate" if command == Command::ProfileReferences => {
                set_action(&mut options, command, Action::Generate)?;
            }
            "check" if command == Command::ProfileReferences => {
                set_action(&mut options, command, Action::Check)?;
            }
            _ => return Err("unknown option; use --help for usage".to_owned()),
        }
        index += 1;
    }

    if matches!(
        command,
        Command::ExternalAcceptance | Command::GuiAcceptanceCheck
    ) && !seen_check
    {
        return Err(format!("{command_name} requires --check"));
    }

    Ok(ParseOutcome::Run {
        command_name: command_name.clone(),
        command,
        options,
    })
}

#[derive(Clone, Copy)]
enum Action {
    Generate,
    Check,
}

fn command_from_name(name: &str) -> Option<Command> {
    Some(match name {
        "profile-check" => Command::ProfileCheck,
        "fixture-check" => Command::FixtureCheck,
        "workspace-check" => Command::WorkspaceCheck,
        "policy-check" | "determinism-check" => Command::PolicyCheck,
        "external-acceptance" => Command::ExternalAcceptance,
        "http-acceptance" => Command::HttpAcceptance,
        "gui-acceptance" => Command::GuiAcceptanceCheck,
        "property-inventory" => Command::PropertyInventory,
        "profile-references" => Command::ProfileReferences,
        _ => return None,
    })
}

fn option_value(
    arguments: &[String],
    index: &mut usize,
    inline_value: Option<&str>,
    name: &str,
) -> Result<String, String> {
    let value = if let Some(value) = inline_value {
        value.to_owned()
    } else {
        let next_index = index.saturating_add(1);
        let Some(value) = arguments.get(next_index) else {
            return Err(format!("{name} requires a path"));
        };
        if value.starts_with('-') {
            return Err(format!("{name} requires a path"));
        }
        *index = next_index;
        value.clone()
    };
    if value.is_empty() {
        return Err(format!("{name} requires a path"));
    }
    Ok(value)
}

fn reject_inline_value(inline_value: Option<&str>, name: &str) -> Result<(), String> {
    if inline_value.is_some() {
        return Err(format!("{name} does not take a value"));
    }
    Ok(())
}

fn set_action(options: &mut Options, command: Command, action: Action) -> Result<(), String> {
    let duplicate = match command {
        Command::PropertyInventory => options.property_inventory_action.is_some(),
        Command::ProfileReferences => options.profile_reference_action.is_some(),
        _ => return Err("internal error: command does not support an action".to_owned()),
    };
    if duplicate {
        let error = match command {
            Command::PropertyInventory => "property inventory action was specified more than once",
            Command::ProfileReferences => "profile reference action was specified more than once",
            _ => "internal error: command does not support an action",
        };
        return Err(error.to_owned());
    }
    match (command, action) {
        (Command::PropertyInventory, Action::Generate) => {
            options.property_inventory_action = Some(PropertyInventoryAction::Generate);
        }
        (Command::PropertyInventory, Action::Check) => {
            options.property_inventory_action = Some(PropertyInventoryAction::Check);
        }
        (Command::ProfileReferences, Action::Generate) => {
            options.profile_reference_action = Some(ProfileReferencesAction::Generate);
        }
        (Command::ProfileReferences, Action::Check) => {
            options.profile_reference_action = Some(ProfileReferencesAction::Check);
        }
        _ => return Err("internal error: action does not match command".to_owned()),
    }
    Ok(())
}

fn print_usage(stdout: bool) {
    if stdout {
        println!("{USAGE}");
    } else {
        eprintln!("{USAGE}");
    }
}

#[cfg(test)]
mod tests {
    use super::{ParseOutcome, parse_arguments};
    use std::path::PathBuf;
    use xtask::{Command, ProfileReferencesAction, PropertyInventoryAction};

    fn parse(arguments: &[&str]) -> Result<ParseOutcome, String> {
        let arguments = arguments
            .iter()
            .map(|argument| (*argument).to_owned())
            .collect::<Vec<_>>();
        parse_arguments(&arguments, PathBuf::from("/repo"))
    }

    #[test]
    fn every_library_command_has_a_cli_dispatch() {
        let cases = [
            (&["profile-check"][..], Command::ProfileCheck),
            (&["fixture-check"][..], Command::FixtureCheck),
            (&["workspace-check"][..], Command::WorkspaceCheck),
            (&["policy-check"][..], Command::PolicyCheck),
            (
                &["external-acceptance", "--check"][..],
                Command::ExternalAcceptance,
            ),
            (&["http-acceptance"][..], Command::HttpAcceptance),
            (
                &["gui-acceptance", "--check"][..],
                Command::GuiAcceptanceCheck,
            ),
            (&["property-inventory"][..], Command::PropertyInventory),
            (&["profile-references"][..], Command::ProfileReferences),
        ];
        for (arguments, expected) in cases {
            let Ok(ParseOutcome::Run { command, .. }) = parse(arguments) else {
                panic!("{arguments:?} did not parse");
            };
            assert_eq!(command, expected, "{arguments:?}");
        }
        let Ok(ParseOutcome::Run { command, .. }) = parse(&["determinism-check"]) else {
            panic!("determinism-check did not parse");
        };
        assert_eq!(command, Command::PolicyCheck);
    }

    #[test]
    fn help_is_a_successful_parse_outcome() {
        assert!(matches!(
            parse(&["profile-check", "--help"]),
            Ok(ParseOutcome::Help)
        ));
        assert!(matches!(
            parse(&["profile-check", "-h"]),
            Ok(ParseOutcome::Help)
        ));
    }

    #[test]
    fn common_and_command_specific_options_are_dispatched() {
        let Ok(ParseOutcome::Run {
            command, options, ..
        }) = parse(&[
            "external-acceptance",
            "--root=/workspace",
            "--profile",
            "profile.json",
            "--fixtures",
            "fixtures",
            "--manifest=manifest.json",
            "--check",
        ])
        else {
            panic!("external acceptance options did not parse");
        };
        assert_eq!(command, Command::ExternalAcceptance);
        assert_eq!(options.root, PathBuf::from("/workspace"));
        assert_eq!(options.profile, Some(PathBuf::from("profile.json")));
        assert_eq!(options.fixtures, Some(PathBuf::from("fixtures")));
        assert_eq!(
            options.external_acceptance_manifest,
            Some(PathBuf::from("manifest.json"))
        );

        let Ok(ParseOutcome::Run { options, .. }) = parse(&[
            "property-inventory",
            "--source",
            "source",
            "--output=output",
            "--generate",
        ]) else {
            panic!("property inventory options did not parse");
        };
        assert_eq!(
            options.property_inventory_action,
            Some(PropertyInventoryAction::Generate)
        );
        assert_eq!(
            options.property_inventory_source,
            Some(PathBuf::from("source"))
        );
        assert_eq!(
            options.property_inventory_output,
            Some(PathBuf::from("output"))
        );

        let Ok(ParseOutcome::Run { options, .. }) = parse(&["profile-references", "check"]) else {
            panic!("profile references action did not parse");
        };
        assert_eq!(
            options.profile_reference_action,
            Some(ProfileReferencesAction::Check)
        );
        assert!(parse(&["external-acceptance"]).is_err());
        assert!(parse(&["gui-acceptance"]).is_err());
    }

    #[test]
    fn check_is_explicit_for_http_and_repeated_actions_are_rejected() {
        let Ok(ParseOutcome::Run { options, .. }) = parse(&["http-acceptance", "--check"]) else {
            panic!("HTTP check did not parse");
        };
        assert!(options.http_acceptance_check);
        let Ok(ParseOutcome::Run {
            command_name,
            command,
            options,
        }) = parse(&["http-acceptance"])
        else {
            panic!("HTTP command without check did not parse");
        };
        assert_eq!(command_name, "http-acceptance");
        assert_eq!(command, Command::HttpAcceptance);
        assert!(!options.http_acceptance_check);
        assert!(parse(&["http-acceptance", "--check", "--check"]).is_err());
        assert!(parse(&["property-inventory", "--check", "--generate"]).is_err());
        assert!(parse(&["profile-references", "check", "--check"]).is_err());
    }

    #[test]
    fn missing_values_and_option_values_are_usage_errors() {
        for arguments in [
            &["profile-check", "--root"][..],
            &["profile-check", "--profile", "--fixtures"][..],
            &["profile-check", "--fixtures="][..],
            &["property-inventory", "--check=value"][..],
            &["profile-check", "--help=value"][..],
        ] {
            assert!(parse(arguments).is_err(), "{arguments:?}");
        }
        let Ok(ParseOutcome::Run { options, .. }) =
            parse(&["profile-check", "--root", "one", "--root", "two"])
        else {
            panic!("repeated root options did not parse");
        };
        assert_eq!(options.root, PathBuf::from("two"));
        assert!(parse(&["unknown-command"]).is_err());
        assert!(parse(&["profile-check", "--check"]).is_err());
    }
}
