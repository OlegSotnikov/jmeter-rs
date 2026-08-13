// SPDX-License-Identifier: Apache-2.0
//! The `jmeter-rs` command-line application.
//!
//! Thin process edge for the bounded CLI/configuration/runtime adapters.

use std::env;
use std::ffi::OsString;
use std::fmt;
use std::io::{self, Write};
use std::process::ExitCode;

use jmeter_rs::{Action, LaunchEnvironment, execute_invocation};

fn main() -> ExitCode {
    run(env::args_os().skip(1))
}

fn run<I, S>(arguments: I) -> ExitCode
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    match jmeter_rs::parse_os(arguments) {
        Ok(invocation) => match invocation.action {
            Action::Options => write_stdout(&jmeter_rs::options_text()),
            Action::Help => write_stdout(&jmeter_rs::help_text()),
            Action::Version => write_stdout(&jmeter_rs::version_text()),
            Action::Execute => {
                let launch = match LaunchEnvironment::from_process() {
                    Ok(launch) => launch,
                    Err(error) => {
                        write_diagnostic(error.code(), &error);
                        return ExitCode::from(error.exit_class().exit_code());
                    }
                };
                match execute_invocation(&invocation, &launch) {
                    Ok(outcome) => {
                        if outcome.sample_failures > 0 {
                            write_stderr_message(&SampleFailureNotice {
                                failures: outcome.sample_failures,
                            });
                        }
                        ExitCode::from(outcome.category.exit_class().exit_code())
                    }
                    Err(error) => {
                        write_diagnostic(error.code(), &error);
                        ExitCode::from(error.exit_class().exit_code())
                    }
                }
            }
        },
        Err(error) => {
            write_diagnostic(error.code(), &error);
            ExitCode::from(error.exit_code())
        }
    }
}

fn write_stdout(text: &str) -> ExitCode {
    match write_text(io::stdout().lock(), text) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            write_diagnostic(
                "io.output",
                &OutputError {
                    stream: "stdout",
                    error,
                },
            );
            ExitCode::from(jmeter_rs::ExitClass::Fatal.exit_code())
        }
    }
}

fn write_text<W: Write>(mut writer: W, text: &str) -> io::Result<()> {
    writer.write_all(text.as_bytes())?;
    writer.flush()
}

fn write_diagnostic(code: &str, error: &impl fmt::Display) {
    // Diagnostics are best effort: a closed stderr (for example, a caller
    // that redirected it to a closed pipe) must not turn a typed application
    // error into a formatting panic.
    let mut stderr = io::stderr().lock();
    let _ = write!(stderr, "jmeter-rs: ERROR[{code}] {error}\n");
    let _ = stderr.flush();
}

fn write_stderr_message(message: &impl fmt::Display) {
    let mut stderr = io::stderr().lock();
    let _ = write!(stderr, "jmeter-rs: {message}\n");
    let _ = stderr.flush();
}

struct SampleFailureNotice {
    failures: usize,
}

impl fmt::Display for SampleFailureNotice {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} sample failure(s); process status remains successful",
            self.failures
        )
    }
}

struct OutputError {
    stream: &'static str,
    error: io::Error,
}

impl fmt::Display for OutputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "failed to write {0}: {1}",
            self.stream, self.error
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{OutputError, write_text};
    use std::io::{self, Write};

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn output_write_failures_are_returned_instead_of_panicking() {
        let result = write_text(FailingWriter, "help");
        assert_eq!(
            result.map_err(|error| error.kind()),
            Err(io::ErrorKind::BrokenPipe)
        );
    }

    #[test]
    fn output_diagnostic_does_not_include_unrelated_values() {
        let diagnostic = OutputError {
            stream: "stdout",
            error: io::Error::new(io::ErrorKind::BrokenPipe, "closed"),
        }
        .to_string();
        assert_eq!(diagnostic, "failed to write stdout: closed");
    }
}
