// SPDX-License-Identifier: Apache-2.0
//! The bounded Apache JMeter 5.6.3 command-line and application boundary.
//!
//! Parsing and configuration planning are deterministic and side-effect free;
//! the explicit runner adapter then loads only allowlisted files, initializes
//! bounded native logging/reporting, and invokes the current local runtime
//! APIs. GUI, JVM, plugin, and RMI execution remain typed capability errors
//! because they are outside the bounded native local/report adapter for the
//! active `jmeter-5.6.3` profile.

#![forbid(unsafe_code)]

mod config;
mod runner;

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::{Path, PathBuf};

#[cfg(all(test, unix))]
use std::os::unix::ffi::OsStringExt;

/// The Apache JMeter release whose command-line vocabulary this crate models.
pub const JMETER_COMPATIBILITY_VERSION: &str = "5.6.3";

/// The release profile used by the command-line boundary.
pub const JMETER_COMPATIBILITY_PROFILE: &str = "jmeter-5.6.3";

pub use config::{
    ConfigError, ConfigFileNames, ConfigFsPolicy, ConfigLimits, ConfigLoader, ConfigNamespace,
    ConfigPlan, ConfigSource, ConfigWarning, DecodeMode, JavaString, LoggingConfig,
    LoggingDirective, PropertyMap, PropertyOperation, PropertyOperationKind, PropertyProvenance,
    PropertyValue, RemovalProvenance, ResolvedConfig, ResolvedProperty, SymlinkPolicy,
};
pub use runner::{
    ENVIRONMENT_ALLOWLIST, EnvironmentView, LaunchEnvironment, RunCategory, RunError, RunOutcome,
    execute_invocation,
};

/// A command-line option, including its canonical short and long spellings.
///
/// The table is the single source for parsing, repeatability checks, and the
/// pinned Apache Commons CLI-compatible options rendering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OptionSpec {
    /// Stable identity used by the parser and configuration plan.
    pub id: OptionId,
    /// Short spelling without the leading dash, if one exists.
    pub short: Option<&'static str>,
    /// Long spelling without the leading two dashes, if one exists.
    pub long: &'static str,
    /// Whether the option consumes one argument.
    pub takes_value: bool,
    /// Whether the option may occur more than once.
    pub repeatable: bool,
    /// Human-readable argument shape used by generated help.
    pub value_hint: Option<&'static str>,
    /// Concise description of the option's observable purpose.
    pub description: &'static str,
}

/// Stable identities for all documented Apache JMeter 5.6.3 options.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OptionId {
    /// `-?`/`--?`.
    Help,
    /// `-h`/`--help`.
    HelpLong,
    /// `-v`/`--version`.
    Version,
    /// `-p`/`--propfile`.
    Propfile,
    /// `-q`/`--addprop`.
    Addprop,
    /// `-t`/`--testfile`.
    Testfile,
    /// `-l`/`--logfile`.
    Logfile,
    /// `-i`/`--jmeterlogconf`.
    Jmeterlogconf,
    /// `-j`/`--jmeterlogfile`.
    Jmeterlogfile,
    /// `-n`/`--nongui`.
    Nongui,
    /// `-s`/`--server`.
    Server,
    /// `-E`/`--proxyScheme`.
    ProxyScheme,
    /// `-H`/`--proxyHost`.
    ProxyHost,
    /// `-P`/`--proxyPort`.
    ProxyPort,
    /// `-N`/`--nonProxyHosts`.
    NonProxyHosts,
    /// `-u`/`--username`.
    Username,
    /// `-a`/`--password`.
    Password,
    /// `-J`/`--jmeterproperty`.
    Jmeterproperty,
    /// `-G`/`--globalproperty`.
    Globalproperty,
    /// `-D`/`--systemproperty`.
    Systemproperty,
    /// `-S`/`--systemPropertyFile`.
    SystemPropertyFile,
    /// `-f`/`--forceDeleteResultFile`.
    ForceDeleteResultFile,
    /// `-L`/`--loglevel`.
    Loglevel,
    /// `-r`/`--runremote`.
    Runremote,
    /// `-R`/`--remotestart`.
    Remotestart,
    /// `-d`/`--homedir`.
    Homedir,
    /// `-X`/`--remoteexit`.
    Remoteexit,
    /// `-g`/`--reportonly`.
    Reportonly,
    /// `-e`/`--reportatendofloadtests`.
    Reportatendofloadtests,
    /// `-o`/`--reportoutputfolder`.
    Reportoutputfolder,
}

impl OptionId {
    /// Returns the canonical short spelling, without a leading dash.
    #[must_use]
    pub const fn short(self) -> Option<&'static str> {
        option_spec(self).short
    }

    /// Returns the canonical long spelling, without leading dashes.
    #[must_use]
    pub const fn long(self) -> &'static str {
        option_spec(self).long
    }

    /// Returns the canonical display name, preferring the short spelling.
    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self.short() {
            Some(short) => short,
            None => self.long(),
        }
    }

    /// Returns whether this option consumes an argument.
    #[must_use]
    pub const fn takes_value(self) -> bool {
        option_spec(self).takes_value
    }

    /// Returns whether this option can be repeated.
    #[must_use]
    pub const fn repeatable(self) -> bool {
        option_spec(self).repeatable
    }
}

/// The complete documented option table in generated-help order.
pub const OPTION_TABLE: &[OptionSpec] = &[
    OptionSpec {
        id: OptionId::Help,
        short: Some("?"),
        long: "?",
        takes_value: false,
        repeatable: false,
        value_hint: None,
        description: "print command line options and exit",
    },
    OptionSpec {
        id: OptionId::HelpLong,
        short: Some("h"),
        long: "help",
        takes_value: false,
        repeatable: false,
        value_hint: None,
        description: "print usage information and exit",
    },
    OptionSpec {
        id: OptionId::Version,
        short: Some("v"),
        long: "version",
        takes_value: false,
        repeatable: false,
        value_hint: None,
        description: "print the version information and exit",
    },
    OptionSpec {
        id: OptionId::Propfile,
        short: Some("p"),
        long: "propfile",
        takes_value: true,
        repeatable: false,
        value_hint: Some("FILE"),
        description: "the jmeter property file to use",
    },
    OptionSpec {
        id: OptionId::Addprop,
        short: Some("q"),
        long: "addprop",
        takes_value: true,
        repeatable: true,
        value_hint: Some("FILE"),
        description: "additional JMeter property file(s)",
    },
    OptionSpec {
        id: OptionId::Testfile,
        short: Some("t"),
        long: "testfile",
        takes_value: true,
        repeatable: false,
        value_hint: Some("FILE|LAST"),
        description: "the jmeter test(.jmx) file to run. \"-t LAST\" will load last used file",
    },
    OptionSpec {
        id: OptionId::Logfile,
        short: Some("l"),
        long: "logfile",
        takes_value: true,
        repeatable: false,
        value_hint: Some("FILE|LAST"),
        description: "the file to log samples to",
    },
    OptionSpec {
        id: OptionId::Jmeterlogconf,
        short: Some("i"),
        long: "jmeterlogconf",
        takes_value: true,
        repeatable: false,
        value_hint: Some("FILE"),
        description: "jmeter logging configuration file (log4j2.xml)",
    },
    OptionSpec {
        id: OptionId::Jmeterlogfile,
        short: Some("j"),
        long: "jmeterlogfile",
        takes_value: true,
        repeatable: false,
        value_hint: Some("FILE|LAST"),
        description: "jmeter run log file (jmeter.log)",
    },
    OptionSpec {
        id: OptionId::Nongui,
        short: Some("n"),
        long: "nongui",
        takes_value: false,
        repeatable: false,
        value_hint: None,
        description: "run JMeter in nongui mode",
    },
    OptionSpec {
        id: OptionId::Server,
        short: Some("s"),
        long: "server",
        takes_value: false,
        repeatable: false,
        value_hint: None,
        description: "run the JMeter server",
    },
    OptionSpec {
        id: OptionId::ProxyScheme,
        short: Some("E"),
        long: "proxyScheme",
        takes_value: true,
        repeatable: false,
        value_hint: Some("SCHEME"),
        description: "Set a proxy scheme to use for the proxy server",
    },
    OptionSpec {
        id: OptionId::ProxyHost,
        short: Some("H"),
        long: "proxyHost",
        takes_value: true,
        repeatable: false,
        value_hint: Some("HOST"),
        description: "Set a proxy server for JMeter to use",
    },
    OptionSpec {
        id: OptionId::ProxyPort,
        short: Some("P"),
        long: "proxyPort",
        takes_value: true,
        repeatable: false,
        value_hint: Some("PORT"),
        description: "Set proxy server port for JMeter to use",
    },
    OptionSpec {
        id: OptionId::NonProxyHosts,
        short: Some("N"),
        long: "nonProxyHosts",
        takes_value: true,
        repeatable: false,
        value_hint: Some("PATTERNS"),
        description: "Set nonproxy host list (e.g. *.apache.org|localhost)",
    },
    OptionSpec {
        id: OptionId::Username,
        short: Some("u"),
        long: "username",
        takes_value: true,
        repeatable: false,
        value_hint: Some("USER"),
        description: "Set username for proxy server that JMeter is to use",
    },
    OptionSpec {
        id: OptionId::Password,
        short: Some("a"),
        long: "password",
        takes_value: true,
        repeatable: false,
        value_hint: Some("PASSWORD"),
        description: "Set password for proxy server that JMeter is to use",
    },
    OptionSpec {
        id: OptionId::Jmeterproperty,
        short: Some("J"),
        long: "jmeterproperty",
        takes_value: true,
        repeatable: true,
        value_hint: Some("KEY=VALUE"),
        description: "Define additional JMeter properties",
    },
    OptionSpec {
        id: OptionId::Globalproperty,
        short: Some("G"),
        long: "globalproperty",
        takes_value: true,
        repeatable: true,
        value_hint: Some("KEY=VALUE|FILE"),
        description: "Define Global properties (sent to servers)\n\t\te.g. -Gport=123 or -Gglobal.properties",
    },
    OptionSpec {
        id: OptionId::Systemproperty,
        short: Some("D"),
        long: "systemproperty",
        takes_value: true,
        repeatable: true,
        value_hint: Some("KEY=VALUE"),
        description: "Define additional system properties",
    },
    OptionSpec {
        id: OptionId::SystemPropertyFile,
        short: Some("S"),
        long: "systemPropertyFile",
        takes_value: true,
        repeatable: true,
        value_hint: Some("FILE"),
        description: "additional system property file(s)",
    },
    OptionSpec {
        id: OptionId::ForceDeleteResultFile,
        short: Some("f"),
        long: "forceDeleteResultFile",
        takes_value: false,
        repeatable: false,
        value_hint: None,
        description: "force delete existing results files and web report folder if present before starting the test",
    },
    OptionSpec {
        id: OptionId::Loglevel,
        short: Some("L"),
        long: "loglevel",
        takes_value: true,
        repeatable: true,
        value_hint: Some("[CATEGORY=]LEVEL"),
        description: "[category=]level e.g. jorphan=INFO, jmeter.util=DEBUG or com.example.foo=WARN",
    },
    OptionSpec {
        id: OptionId::Runremote,
        short: Some("r"),
        long: "runremote",
        takes_value: false,
        repeatable: false,
        value_hint: None,
        description: "Start remote servers (as defined in remote_hosts)",
    },
    OptionSpec {
        id: OptionId::Remotestart,
        short: Some("R"),
        long: "remotestart",
        takes_value: true,
        repeatable: false,
        value_hint: Some("HOSTS"),
        description: "Start these remote servers (overrides remote_hosts)",
    },
    OptionSpec {
        id: OptionId::Homedir,
        short: Some("d"),
        long: "homedir",
        takes_value: true,
        repeatable: false,
        value_hint: Some("DIR"),
        description: "the jmeter home directory to use",
    },
    OptionSpec {
        id: OptionId::Remoteexit,
        short: Some("X"),
        long: "remoteexit",
        takes_value: false,
        repeatable: false,
        value_hint: None,
        description: "Exit the remote servers at end of test (non-GUI)",
    },
    OptionSpec {
        id: OptionId::Reportonly,
        short: Some("g"),
        long: "reportonly",
        takes_value: true,
        repeatable: false,
        value_hint: Some("JTL"),
        description: "generate report dashboard only, from a test results file",
    },
    OptionSpec {
        id: OptionId::Reportatendofloadtests,
        short: Some("e"),
        long: "reportatendofloadtests",
        takes_value: false,
        repeatable: false,
        value_hint: None,
        description: "generate report dashboard after load test",
    },
    OptionSpec {
        id: OptionId::Reportoutputfolder,
        short: Some("o"),
        long: "reportoutputfolder",
        takes_value: true,
        repeatable: false,
        value_hint: Some("DIR"),
        description: "output folder for report dashboard",
    },
];

/// Returns the complete option table.
#[must_use]
pub const fn option_table() -> &'static [OptionSpec] {
    OPTION_TABLE
}

const fn option_spec(id: OptionId) -> OptionSpec {
    match id {
        OptionId::Help => OPTION_TABLE[0],
        OptionId::HelpLong => OPTION_TABLE[1],
        OptionId::Version => OPTION_TABLE[2],
        OptionId::Propfile => OPTION_TABLE[3],
        OptionId::Addprop => OPTION_TABLE[4],
        OptionId::Testfile => OPTION_TABLE[5],
        OptionId::Logfile => OPTION_TABLE[6],
        OptionId::Jmeterlogconf => OPTION_TABLE[7],
        OptionId::Jmeterlogfile => OPTION_TABLE[8],
        OptionId::Nongui => OPTION_TABLE[9],
        OptionId::Server => OPTION_TABLE[10],
        OptionId::ProxyScheme => OPTION_TABLE[11],
        OptionId::ProxyHost => OPTION_TABLE[12],
        OptionId::ProxyPort => OPTION_TABLE[13],
        OptionId::NonProxyHosts => OPTION_TABLE[14],
        OptionId::Username => OPTION_TABLE[15],
        OptionId::Password => OPTION_TABLE[16],
        OptionId::Jmeterproperty => OPTION_TABLE[17],
        OptionId::Globalproperty => OPTION_TABLE[18],
        OptionId::Systemproperty => OPTION_TABLE[19],
        OptionId::SystemPropertyFile => OPTION_TABLE[20],
        OptionId::ForceDeleteResultFile => OPTION_TABLE[21],
        OptionId::Loglevel => OPTION_TABLE[22],
        OptionId::Runremote => OPTION_TABLE[23],
        OptionId::Remotestart => OPTION_TABLE[24],
        OptionId::Homedir => OPTION_TABLE[25],
        OptionId::Remoteexit => OPTION_TABLE[26],
        OptionId::Reportonly => OPTION_TABLE[27],
        OptionId::Reportatendofloadtests => OPTION_TABLE[28],
        OptionId::Reportoutputfolder => OPTION_TABLE[29],
    }
}

/// The mode selected by the parsed options.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunMode {
    /// No mode flag was supplied; this is JMeter's GUI/default mode.
    Gui,
    /// `-n`/`--nongui` was supplied.
    NonGui,
    /// `-s`/`--server` was supplied.
    Server,
    /// `-g`/`--reportonly` was supplied.
    ReportOnly,
}

impl RunMode {
    /// Returns the stable mode label used in diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Gui => "gui",
            Self::NonGui => "non-gui",
            Self::Server => "server",
            Self::ReportOnly => "report-only",
        }
    }
}

impl fmt::Display for RunMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The parser's top-level action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    /// Parse and print the pinned option catalog (`-?`), then succeed.
    Options,
    /// Parse and print the pinned help resource (`-h`), then succeed.
    Help,
    /// Parse and print version information, then succeed.
    Version,
    /// Continue to a process/engine adapter.
    Execute,
}

/// Compatibility alias for callers that prefer `CliAction` terminology.
pub type CliAction = Action;

/// Stable process exit classes used by the binary and process adapters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExitClass {
    /// The requested non-execution action completed successfully.
    Success,
    /// The engine completed and recorded one or more failed samples.
    SampleFailure,
    /// The command line grammar or option combination was invalid.
    UsageError,
    /// A valid command could not be configured without performing execution.
    ConfigurationError,
    /// The selected capability lies outside the bounded native local/report
    /// adapter for the active compatibility profile.
    UnsupportedCapability,
    /// A fatal startup, local runtime, or report operation failed.
    Fatal,
    /// A remote adapter failed or remains unavailable.
    RemoteFailure,
    /// An unexpected internal invariant failed.
    InternalError,
}

impl ExitClass {
    /// Returns a stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Success => "ok",
            Self::SampleFailure => "sample.failure",
            Self::UsageError => "cli.usage",
            Self::ConfigurationError => "config.invalid",
            Self::UnsupportedCapability => "capability.unavailable",
            Self::Fatal => "fatal",
            Self::RemoteFailure => "remote.failure",
            Self::InternalError => "internal.error",
        }
    }

    /// Returns the conventional process status for this class.
    #[must_use]
    pub const fn exit_code(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::SampleFailure => 0,
            Self::UsageError => 2,
            Self::ConfigurationError => 78,
            Self::UnsupportedCapability => 78,
            Self::Fatal => 1,
            Self::RemoteFailure => 1,
            Self::InternalError => 70,
        }
    }
}

impl fmt::Display for ExitClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

/// A parser or semantic-validation error with a stable category.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CliError {
    /// An option that requires an argument was not followed by one.
    MissingValue {
        /// Option identity.
        option: OptionId,
        /// Exact spelling supplied by the caller.
        spelling: String,
    },
    /// An option spelling is not in [`OPTION_TABLE`].
    UnknownOption {
        /// Exact token supplied by the caller.
        token: String,
    },
    /// A positional token was left after option processing.
    UnexpectedArgument {
        /// Exact token supplied by the caller.
        argument: String,
    },
    /// A singleton option appeared more than once.
    DuplicateOption {
        /// Option identity.
        option: OptionId,
        /// Exact spelling of the duplicate occurrence.
        spelling: String,
    },
    /// A boolean option was written with an argument.
    UnexpectedValue {
        /// Option identity.
        option: OptionId,
        /// Exact spelling supplied by the caller.
        spelling: String,
    },
    /// A key/value or logging-level value was malformed.
    InvalidValue {
        /// Option identity.
        option: OptionId,
        /// Value (redacted when the option is the proxy password).
        value: String,
        /// Stable reason identifier.
        reason: ValueError,
    },
    /// Two or more otherwise valid options cannot be used together.
    IncompatibleOptions {
        /// Stable option identities in encounter order.
        options: Vec<OptionId>,
        /// Concise diagnostic reason.
        reason: CombinationError,
    },
    /// An input argument could not be represented as UTF-8 by the safe parser.
    NonUnicodeArgument,
    /// An internal table invariant was violated.
    InvalidOptionTable,
}

/// Stable reasons for malformed option values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValueError {
    /// A required value was empty.
    Empty,
    /// A property assignment did not contain a non-empty key and `=`.
    MissingAssignment,
    /// A logging level did not contain a non-empty level.
    MissingLogLevel,
    /// A path-like value cannot be empty.
    EmptyPath,
}

impl ValueError {
    /// Stable reason code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::MissingAssignment => "missing-assignment",
            Self::MissingLogLevel => "missing-log-level",
            Self::EmptyPath => "empty-path",
        }
    }
}

impl fmt::Display for ValueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

/// Stable reasons for invalid option combinations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CombinationError {
    /// `-n` needs a plan (except for report-only, which is a different mode).
    NonGuiNeedsTestfile,
    /// `-e` needs a result file.
    ReportAtEndNeedsLogfile,
    /// Report generation after a load test is only meaningful in non-GUI mode.
    ReportAtEndNeedsNonGui,
    /// `-g` and ordinary load-test mode cannot be combined.
    ReportOnlyConflict,
    /// Report-only mode cannot receive a test plan.
    ReportOnlyNeedsOnlyJtl,
    /// Report output has no report-generation source.
    ReportOutputNeedsReport,
    /// Remote flags require a local CLI load test.
    RemoteNeedsNonGui,
    /// Server mode cannot be combined with a local test run.
    ServerConflict,
    /// GUI/server/report-only/non-GUI are mutually exclusive mode selectors.
    MultipleModes,
    /// A proxy host and port must be supplied together.
    ProxyNeedsHostAndPort,
}

impl CombinationError {
    /// Stable reason code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NonGuiNeedsTestfile => "nongui-needs-testfile",
            Self::ReportAtEndNeedsLogfile => "report-at-end-needs-logfile",
            Self::ReportAtEndNeedsNonGui => "report-at-end-needs-nongui",
            Self::ReportOnlyConflict => "report-only-conflict",
            Self::ReportOnlyNeedsOnlyJtl => "report-only-needs-only-jtl",
            Self::ReportOutputNeedsReport => "report-output-needs-report",
            Self::RemoteNeedsNonGui => "remote-needs-nongui",
            Self::ServerConflict => "server-conflict",
            Self::MultipleModes => "multiple-modes",
            Self::ProxyNeedsHostAndPort => "proxy-needs-host-and-port",
        }
    }
}

impl fmt::Display for CombinationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl CliError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingValue { .. } => "cli.missing-value",
            Self::UnknownOption { .. } => "cli.unknown-option",
            Self::UnexpectedArgument { .. } => "cli.unexpected-argument",
            Self::DuplicateOption { .. } => "cli.duplicate-option",
            Self::UnexpectedValue { .. } => "cli.unexpected-value",
            Self::InvalidValue { .. } => "cli.invalid-value",
            Self::IncompatibleOptions { .. } => "cli.incompatible-options",
            Self::NonUnicodeArgument => "cli.non-unicode-argument",
            Self::InvalidOptionTable => "internal.invalid-option-table",
        }
    }

    /// Returns the stable process exit class for this error.
    #[must_use]
    pub const fn exit_class(&self) -> ExitClass {
        match self {
            Self::InvalidOptionTable => ExitClass::InternalError,
            _ => ExitClass::UsageError,
        }
    }

    /// Returns the conventional process exit status for this error.
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        self.exit_class().exit_code()
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingValue { spelling, .. } => {
                write!(formatter, "{spelling} requires an argument")
            }
            Self::UnknownOption { token } => write!(formatter, "unknown option {token:?}"),
            Self::UnexpectedArgument { argument } => {
                write!(formatter, "unexpected argument {argument:?}")
            }
            Self::DuplicateOption { spelling, .. } => {
                write!(formatter, "option {spelling:?} may not be repeated")
            }
            Self::UnexpectedValue { spelling, .. } => {
                write!(formatter, "option {spelling:?} does not take an argument")
            }
            Self::InvalidValue {
                option,
                value,
                reason,
            } => {
                if *option == OptionId::Password {
                    write!(formatter, "invalid value for --password ({reason})")
                } else {
                    write!(
                        formatter,
                        "invalid value {value:?} for --{} ({reason})",
                        option.long()
                    )
                }
            }
            Self::IncompatibleOptions { options, reason } => {
                write!(formatter, "incompatible options ")?;
                for (index, option) in options.iter().enumerate() {
                    if index != 0 {
                        formatter.write_str(" and ")?;
                    }
                    write!(formatter, "--{}", option.long())?;
                }
                write!(formatter, " ({reason})")
            }
            Self::NonUnicodeArgument => formatter.write_str("an argument is not valid UTF-8"),
            Self::InvalidOptionTable => formatter.write_str("the option table is inconsistent"),
        }
    }
}

impl std::error::Error for CliError {}

/// An exact option occurrence in the order supplied by the user.
#[derive(Clone, Eq, PartialEq)]
pub struct OptionOccurrence {
    /// Stable option identity.
    pub id: OptionId,
    /// Exact option token spelling (`-J`, `--jmeterproperty`, or attached
    /// spelling's option prefix).
    pub spelling: String,
    /// Exact argument string, if present.
    pub value: Option<String>,
    /// Exact one- or two-argument payload before normalization.
    pub arguments: Vec<String>,
    /// Zero-based index of the option token in the input argument vector.
    pub index: usize,
    /// Whether the option's value is a secret and must be redacted by
    /// formatting implementations.
    pub sensitive: bool,
}

impl OptionOccurrence {
    /// Returns the actual value; formatting the occurrence never exposes it
    /// when [`Self::sensitive`] is true.
    #[must_use]
    pub fn value(&self) -> Option<&str> {
        self.value.as_deref()
    }
}

impl fmt::Debug for OptionOccurrence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sensitive = self.sensitive || occurrence_value_is_sensitive(self.id, self.value());
        let mut debug = formatter.debug_struct("OptionOccurrence");
        debug.field("id", &self.id);
        debug.field("spelling", &self.spelling);
        if sensitive {
            debug.field("value", &"<redacted>");
            debug.field("arguments", &"<redacted>");
        } else {
            debug.field("value", &self.value);
            debug.field("arguments", &self.arguments);
        }
        debug.field("index", &self.index);
        debug.field("sensitive", &self.sensitive);
        debug.finish()
    }
}

/// An exact `KEY=VALUE` assignment from `-J`, `-D`, or an equivalent source.
#[derive(Clone, Eq, PartialEq)]
pub struct PropertyAssignment {
    /// Exact key before the first equals sign.
    pub key: String,
    /// Exact value after the first equals sign; additional equals signs are
    /// retained.
    pub value: String,
    /// Exact user string, retained for diagnostics and round-tripping.
    pub raw: String,
}

impl PropertyAssignment {
    fn parse(option: OptionId, value: String) -> Result<Self, CliError> {
        let Some((key, property_value)) = value.split_once('=') else {
            return Err(CliError::InvalidValue {
                option,
                value,
                reason: ValueError::MissingAssignment,
            });
        };
        if key.is_empty() {
            return Err(CliError::InvalidValue {
                option,
                value,
                reason: ValueError::MissingAssignment,
            });
        }
        Ok(Self {
            key: key.to_owned(),
            value: property_value.to_owned(),
            raw: value,
        })
    }

    /// Returns whether this key is conventionally a proxy password property.
    #[must_use]
    pub fn is_sensitive(&self) -> bool {
        is_sensitive_key(&self.key)
    }
}

impl fmt::Debug for PropertyAssignment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("PropertyAssignment");
        debug.field("key", &self.key);
        if self.is_sensitive() {
            debug.field("value", &"<redacted>");
            debug.field("raw", &"<redacted>");
        } else {
            debug.field("value", &self.value);
            debug.field("raw", &self.raw);
        }
        debug.finish()
    }
}

impl fmt::Display for PropertyAssignment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_sensitive() {
            write!(formatter, "{}=<redacted>", self.key)
        } else {
            formatter.write_str(&self.raw)
        }
    }
}

/// A `-G`/`--globalproperty` value, which can be an assignment or a file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GlobalProperty {
    /// A global key/value assignment.
    Assignment(PropertyAssignment),
    /// A properties file path, retained without filesystem access.
    File {
        /// Exact user path.
        path: String,
    },
}

impl GlobalProperty {
    fn parse(value: String) -> Result<Self, CliError> {
        if value.is_empty() {
            return Err(CliError::InvalidValue {
                option: OptionId::Globalproperty,
                value,
                reason: ValueError::Empty,
            });
        }
        // The Java launcher distinguishes a non-empty assignment from the
        // file form by the RHS.  Thus `-Gfoo=` names a property file `foo`;
        // the separator is grammar, not part of the file name.
        let assignment_value_is_nonempty = value
            .split_once('=')
            .is_some_and(|(_, property_value)| !property_value.is_empty());
        if assignment_value_is_nonempty {
            PropertyAssignment::parse(OptionId::Globalproperty, value).map(Self::Assignment)
        } else {
            let path = value
                .split_once('=')
                .map_or(value.as_str(), |(path, _)| path)
                .to_owned();
            if path.is_empty() {
                return Err(CliError::InvalidValue {
                    option: OptionId::Globalproperty,
                    value,
                    reason: ValueError::Empty,
                });
            }
            Ok(Self::File { path })
        }
    }

    /// Returns the exact input spelling.
    #[must_use]
    pub fn raw(&self) -> &str {
        match self {
            Self::Assignment(assignment) => &assignment.raw,
            Self::File { path } => path,
        }
    }
}

/// A path-like argument and its special `LAST` interpretation.
#[derive(Clone, Eq, PartialEq)]
pub struct PathArgument {
    /// Exact user string.
    pub raw: String,
    /// Whether the value requests GUI last-plan resolution.
    pub kind: PathKind,
}

/// Special interpretation of a path argument.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathKind {
    /// The value is an ordinary path.
    Explicit,
    /// The exact token was `LAST`; resolution is deferred to an explicit
    /// persistence capability.
    Last,
    /// `-j`/`--jmeterlogfile` retains the LAST spelling for the NewDriver
    /// call-site; the source launcher does not pass it through `processLAST`.
    LastLiteral,
}

impl PathArgument {
    fn new(value: String) -> Result<Self, CliError> {
        if value.is_empty() {
            return Err(CliError::InvalidValue {
                option: OptionId::Testfile,
                value,
                reason: ValueError::EmptyPath,
            });
        }
        let kind = if value == "LAST" {
            PathKind::Last
        } else {
            PathKind::Explicit
        };
        Ok(Self { raw: value, kind })
    }

    fn new_log(value: String) -> Result<Self, CliError> {
        if value.is_empty() {
            return Err(CliError::InvalidValue {
                option: OptionId::Logfile,
                value,
                reason: ValueError::EmptyPath,
            });
        }
        let kind = if matches!(value.as_str(), "LAST" | "LAST.jtl") {
            PathKind::Last
        } else {
            PathKind::Explicit
        };
        Ok(Self { raw: value, kind })
    }

    fn new_jmeter_log(value: String) -> Result<Self, CliError> {
        if value.is_empty() {
            return Err(CliError::InvalidValue {
                option: OptionId::Jmeterlogfile,
                value,
                reason: ValueError::EmptyPath,
            });
        }
        let kind = if matches!(value.as_str(), "LAST" | "LAST.log") {
            PathKind::LastLiteral
        } else {
            PathKind::Explicit
        };
        Ok(Self { raw: value, kind })
    }

    /// Returns the exact user string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// Returns whether this value requests deferred `LAST` resolution.
    #[must_use]
    pub const fn is_last(&self) -> bool {
        matches!(self.kind, PathKind::Last | PathKind::LastLiteral)
    }

    /// Resolves a deferred `LAST` target against an explicitly supplied
    /// recent JMX path.  This pure helper mirrors JMeter's `processLAST`: a
    /// `LAST` or `LAST<suffix>` marker replaces a case-insensitive `.JMX`
    /// extension with `suffix`; a non-JMX recent path leaves the marker
    /// unresolved.  Ordinary explicit paths are returned unchanged.
    #[must_use]
    pub fn resolve_last_against(&self, recent_jmx: &Path, suffix: &str) -> Option<PathBuf> {
        if !matches!(self.kind, PathKind::Last) {
            return Some(PathBuf::from(&self.raw));
        }
        if self.raw != "LAST" && self.raw != format!("LAST{suffix}") {
            return Some(PathBuf::from(&self.raw));
        }
        let recent = recent_jmx.to_str()?;
        if !recent
            .get(recent.len().saturating_sub(4)..)?
            .eq_ignore_ascii_case(".jmx")
        {
            return None;
        }
        let stem_end = recent.len().saturating_sub(4);
        let mut resolved = String::with_capacity(stem_end + suffix.len());
        resolved.push_str(&recent[..stem_end]);
        resolved.push_str(suffix);
        Some(PathBuf::from(resolved))
    }
}

impl fmt::Debug for PathArgument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PathArgument")
            .field("raw", &self.raw)
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for PathArgument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.raw)
    }
}

/// Proxy options collected without applying process system properties.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct ProxyOptions {
    /// Optional proxy scheme (`http.proxyScheme`).
    pub scheme: Option<String>,
    /// Optional proxy host (`http.proxyHost`/`https.proxyHost`).
    pub host: Option<String>,
    /// Optional proxy port (`http.proxyPort`/`https.proxyPort`).
    pub port: Option<String>,
    /// Optional pipe-separated non-proxy host patterns.
    pub non_proxy_hosts: Option<String>,
    /// Optional proxy username.
    pub username: Option<String>,
    /// Optional proxy password.  Never rendered by [`fmt::Debug`] or
    /// [`fmt::Display`].
    pub password: Option<String>,
}

impl fmt::Debug for ProxyOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyOptions")
            .field("scheme", &self.scheme)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("non_proxy_hosts", &self.non_proxy_hosts)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl fmt::Display for ProxyOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "proxy(scheme={:?}, host={:?}, port={:?}, non_proxy_hosts={:?}, username={:?}, password=<redacted>)",
            self.scheme, self.host, self.port, self.non_proxy_hosts, self.username
        )
    }
}

/// A parsed logging level, retaining the exact user string.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogLevel {
    /// Exact value supplied to `-L`.
    pub raw: String,
    /// Optional logger category before the first equals sign.
    pub category: Option<String>,
    /// Logger level after the first equals sign, or the whole value.
    pub level: String,
}

impl LogLevel {
    fn parse(value: String) -> Result<Self, CliError> {
        if value.is_empty() {
            return Err(CliError::InvalidValue {
                option: OptionId::Loglevel,
                value,
                reason: ValueError::Empty,
            });
        }
        let (category, level) = match value.split_once('=') {
            Some((category, level)) if category.is_empty() || level.is_empty() => {
                return Err(CliError::InvalidValue {
                    option: OptionId::Loglevel,
                    value,
                    reason: ValueError::MissingLogLevel,
                });
            }
            Some((category, level)) => (Some(category.to_owned()), level.to_owned()),
            None => (None, value.clone()),
        };
        Ok(Self {
            raw: value,
            category,
            level,
        })
    }
}

/// Parsed proxy and remote controls.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RemoteOptions {
    /// Whether `-r` selected all configured remote hosts.
    pub run_remote: bool,
    /// Exact `-R` comma-separated host list, if supplied.
    pub remote_start: Option<String>,
    /// Whether `-X` requests remote shutdown after the run.
    pub remote_exit: bool,
}

/// Parsed options and derived mode.
#[derive(Clone, Eq, PartialEq)]
pub struct CliOptions {
    /// Selected execution mode.
    pub mode: RunMode,
    /// Whether the parser should take a non-execution action.
    pub action: Action,
    /// Primary JMeter property file (`-p`).
    pub propfile: Option<String>,
    /// Additional JMeter property files (`-q`), in user order.
    pub addprop: Vec<String>,
    /// Test plan path (`-t`), with deferred `LAST` interpretation.
    pub testfile: Option<PathArgument>,
    /// Result JTL path (`-l`), with deferred `LAST` interpretation.
    pub logfile: Option<PathArgument>,
    /// Log4j2 configuration path (`-i`).
    pub jmeterlogconf: Option<String>,
    /// JMeter run log path (`-j`), with deferred `LAST` interpretation.
    pub jmeterlogfile: Option<PathArgument>,
    /// Proxy settings collected from `-E/-H/-P/-N/-u/-a`.
    pub proxy: ProxyOptions,
    /// Local JMeter properties (`-J`), in user order.
    pub jmeter_properties: Vec<PropertyAssignment>,
    /// Remote/global properties (`-G`), in user order.
    pub global_properties: Vec<GlobalProperty>,
    /// System properties (`-D`), in user order.
    pub system_properties: Vec<PropertyAssignment>,
    /// Additional Java system-property files (`-S`), in user order.
    pub system_property_files: Vec<String>,
    /// Logging level overrides (`-L`), in user order.
    pub log_levels: Vec<LogLevel>,
    /// Force-delete result/report output before execution.
    pub force_delete_result_file: bool,
    /// Remote selection flags.
    pub remote: RemoteOptions,
    /// Report-only input JTL (`-g`).
    pub report_only_file: Option<String>,
    /// Generate a dashboard after a load test (`-e`).
    pub report_at_end: bool,
    /// Dashboard output directory (`-o`).
    pub report_output_folder: Option<String>,
    /// JMeter home directory (`-d`).
    pub home_dir: Option<String>,
    /// Exact occurrences in input order.
    pub occurrences: Vec<OptionOccurrence>,
    /// The explicit `--` terminator was present.
    pub option_terminator: bool,
}

impl fmt::Debug for CliOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("CliOptions");
        debug.field("mode", &self.mode);
        debug.field("action", &self.action);
        debug.field("propfile", &self.propfile);
        debug.field("addprop", &self.addprop);
        debug.field("testfile", &self.testfile);
        debug.field("logfile", &self.logfile);
        debug.field("jmeterlogconf", &self.jmeterlogconf);
        debug.field("jmeterlogfile", &self.jmeterlogfile);
        debug.field("proxy", &self.proxy);
        debug.field("jmeter_properties", &self.jmeter_properties);
        debug.field("global_properties", &self.global_properties);
        debug.field("system_properties", &self.system_properties);
        debug.field("system_property_files", &self.system_property_files);
        debug.field("log_levels", &self.log_levels);
        debug.field("force_delete_result_file", &self.force_delete_result_file);
        debug.field("remote", &self.remote);
        debug.field("report_only_file", &self.report_only_file);
        debug.field("report_at_end", &self.report_at_end);
        debug.field("report_output_folder", &self.report_output_folder);
        debug.field("home_dir", &self.home_dir);
        debug.field("occurrences", &self.occurrences);
        debug.field("option_terminator", &self.option_terminator);
        debug.finish()
    }
}

impl fmt::Display for CliOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "mode={}, action={:?}, testfile={:?}, logfile={:?}, proxy={}, occurrences={}",
            self.mode,
            self.action,
            self.testfile,
            self.logfile,
            self.proxy,
            self.occurrences.len()
        )
    }
}

impl CliOptions {
    /// Returns true when this is GUI/default mode.
    #[must_use]
    pub const fn is_gui(&self) -> bool {
        matches!(self.mode, RunMode::Gui)
    }

    /// Returns true when this is non-GUI/CLI mode.
    #[must_use]
    pub const fn is_nongui(&self) -> bool {
        matches!(self.mode, RunMode::NonGui)
    }

    /// Returns true when this is server mode.
    #[must_use]
    pub const fn is_server(&self) -> bool {
        matches!(self.mode, RunMode::Server)
    }

    /// Returns true when this is report-only mode.
    #[must_use]
    pub const fn is_report_only(&self) -> bool {
        matches!(self.mode, RunMode::ReportOnly)
    }

    /// Returns true when `-e` requests report generation after a load test.
    #[must_use]
    pub const fn report_at_end_of_load_tests(&self) -> bool {
        self.report_at_end
    }

    /// Builds the deterministic effect plan represented by these options.
    #[must_use]
    pub fn configuration_plan(&self) -> ConfigurationPlan {
        ConfigurationPlan::from_options(self)
    }
}

/// A parsed CLI invocation, including its deferred configuration plan.
#[derive(Clone, Eq, PartialEq)]
pub struct CliInvocation {
    /// Parsed option values.
    pub options: CliOptions,
    /// Action selected by help/version flags.
    pub action: Action,
    /// Deterministic ordered configuration/effect description.
    pub configuration: ConfigurationPlan,
}

impl fmt::Debug for CliInvocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CliInvocation")
            .field("options", &self.options)
            .field("action", &self.action)
            .field("configuration", &self.configuration)
            .finish()
    }
}

impl fmt::Display for CliInvocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.options.fmt(formatter)
    }
}

impl CliInvocation {
    /// Returns true when the invocation is a successful help/version action.
    #[must_use]
    pub const fn is_information_action(&self) -> bool {
        matches!(
            self.action,
            Action::Options | Action::Help | Action::Version
        )
    }

    /// Returns the selected mode.
    #[must_use]
    pub const fn mode(&self) -> RunMode {
        self.options.mode
    }
}

/// Compatibility alias for callers that call the parsed value `Cli`.
pub type Cli = CliInvocation;

/// Compatibility alias for callers that call the parsed value `ParsedCli`.
pub type ParsedCli = CliInvocation;

/// The source role of a property load in [`ConfigurationPlan`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PropertySource {
    /// The explicitly selected primary file from `-p`.
    ExplicitPrimary {
        /// Exact user path.
        path: String,
    },
    /// The default `jmeter.properties` source.
    DefaultPrimary,
    /// The default `user.properties` source.
    DefaultUser,
    /// The default `system.properties` source.
    DefaultSystem,
    /// A `-q` additional JMeter property file.
    AdditionalJmeter {
        /// Exact user path.
        path: String,
        /// Original occurrence index.
        occurrence: usize,
    },
    /// An `-S` additional system-property file.
    AdditionalSystem {
        /// Exact user path.
        path: String,
        /// Original occurrence index.
        occurrence: usize,
    },
    /// A `-G` global-property file.
    Global {
        /// Exact user path.
        path: String,
        /// Original occurrence index.
        occurrence: usize,
    },
}

/// A deferred log target.  The application runner resolves `LAST` only when
/// the launch environment supplies an explicit recent-project path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LogTarget {
    /// The default JMeter log target.
    Default,
    /// An explicit or deferred user target.
    Selected(PathArgument),
}

/// Ordered effect description consumed by the application edge.
#[derive(Clone, Eq, PartialEq)]
pub enum ConfigurationStep {
    /// Load the primary property source.
    LoadProperties {
        /// Source role and exact path where applicable.
        source: PropertySource,
    },
    /// Select the JMeter run log before logger initialization.
    SelectJmeterLog {
        /// Default or user-selected target.
        target: LogTarget,
    },
    /// Initialize logging from the optional Log4j2 file and selected target.
    InitializeLogging {
        /// `-i` path, if supplied.
        config_file: Option<String>,
        /// The selected run-log target.
        target: LogTarget,
    },
    /// Load the default user property source.
    LoadUserProperties {
        /// Source role.
        source: PropertySource,
    },
    /// Load the default system property source.
    LoadSystemProperties {
        /// Source role.
        source: PropertySource,
    },
    /// Apply a local JMeter property assignment.
    ApplyJmeterProperty {
        /// Exact assignment.
        assignment: PropertyAssignment,
        /// Original occurrence index.
        occurrence: usize,
    },
    /// Apply or load a global property.
    ApplyGlobalProperty {
        /// Assignment or file source.
        property: GlobalProperty,
        /// Original occurrence index.
        occurrence: usize,
    },
    /// Apply a system property assignment.
    ApplySystemProperty {
        /// Exact assignment.
        assignment: PropertyAssignment,
        /// Original occurrence index.
        occurrence: usize,
    },
    /// Apply a proxy setting to the local system-property adapter.
    ApplyProxy {
        /// Exact property key.
        key: &'static str,
        /// Exact value; password values are redacted by the plan formatter.
        value: String,
        /// Whether the value is sensitive.
        sensitive: bool,
        /// Original occurrence index.
        occurrence: usize,
    },
    /// Apply a logging level override.
    ApplyLogLevel {
        /// Parsed logging level.
        level: LogLevel,
        /// Original occurrence index.
        occurrence: usize,
    },
    /// Select the plan/result/report paths for the explicit local
    /// engine/report adapters.  This step performs no filesystem access.
    SelectInputs {
        /// Test plan path, if any.
        testfile: Option<PathArgument>,
        /// Result path, if any.
        logfile: Option<PathArgument>,
        /// Report-only input, if any.
        report_only_file: Option<String>,
        /// Dashboard output path, if any.
        report_output_folder: Option<String>,
    },
}

impl fmt::Debug for ConfigurationStep {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApplyProxy {
                key,
                value,
                sensitive,
                occurrence,
            } => {
                let value = if *sensitive {
                    "<redacted>"
                } else {
                    value.as_str()
                };
                formatter
                    .debug_struct("ApplyProxy")
                    .field("key", key)
                    .field("value", &value)
                    .field("sensitive", sensitive)
                    .field("occurrence", occurrence)
                    .finish()
            }
            Self::LoadProperties { source } => formatter
                .debug_struct("LoadProperties")
                .field("source", source)
                .finish(),
            Self::SelectJmeterLog { target } => formatter
                .debug_struct("SelectJmeterLog")
                .field("target", target)
                .finish(),
            Self::InitializeLogging {
                config_file,
                target,
            } => formatter
                .debug_struct("InitializeLogging")
                .field("config_file", config_file)
                .field("target", target)
                .finish(),
            Self::LoadUserProperties { source } => formatter
                .debug_struct("LoadUserProperties")
                .field("source", source)
                .finish(),
            Self::LoadSystemProperties { source } => formatter
                .debug_struct("LoadSystemProperties")
                .field("source", source)
                .finish(),
            Self::ApplyJmeterProperty {
                assignment,
                occurrence,
            } => formatter
                .debug_struct("ApplyJmeterProperty")
                .field("assignment", assignment)
                .field("occurrence", occurrence)
                .finish(),
            Self::ApplyGlobalProperty {
                property,
                occurrence,
            } => formatter
                .debug_struct("ApplyGlobalProperty")
                .field("property", property)
                .field("occurrence", occurrence)
                .finish(),
            Self::ApplySystemProperty {
                assignment,
                occurrence,
            } => formatter
                .debug_struct("ApplySystemProperty")
                .field("assignment", assignment)
                .field("occurrence", occurrence)
                .finish(),
            Self::ApplyLogLevel { level, occurrence } => formatter
                .debug_struct("ApplyLogLevel")
                .field("level", level)
                .field("occurrence", occurrence)
                .finish(),
            Self::SelectInputs {
                testfile,
                logfile,
                report_only_file,
                report_output_folder,
            } => formatter
                .debug_struct("SelectInputs")
                .field("testfile", testfile)
                .field("logfile", logfile)
                .field("report_only_file", report_only_file)
                .field("report_output_folder", report_output_folder)
                .finish(),
        }
    }
}

/// A deterministic sequence of configuration steps.  It is deliberately
/// descriptive rather than executable: no file, environment, logger, or
/// process operation occurs while creating one.
#[derive(Clone, Eq, PartialEq)]
pub struct ConfigurationPlan {
    /// Ordered steps in the exact order an application adapter must consider.
    pub steps: Vec<ConfigurationStep>,
}

impl fmt::Debug for ConfigurationPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfigurationPlan")
            .field("steps", &self.steps)
            .finish()
    }
}

impl ConfigurationPlan {
    fn from_options(options: &CliOptions) -> Self {
        let mut steps = Vec::new();
        let primary = match &options.propfile {
            Some(path) => PropertySource::ExplicitPrimary { path: path.clone() },
            None => PropertySource::DefaultPrimary,
        };
        steps.push(ConfigurationStep::LoadProperties { source: primary });

        let log_target = options
            .jmeterlogfile
            .clone()
            .map_or(LogTarget::Default, LogTarget::Selected);
        steps.push(ConfigurationStep::SelectJmeterLog {
            target: log_target.clone(),
        });
        steps.push(ConfigurationStep::InitializeLogging {
            config_file: options.jmeterlogconf.clone(),
            target: log_target,
        });
        steps.push(ConfigurationStep::LoadUserProperties {
            source: PropertySource::DefaultUser,
        });
        steps.push(ConfigurationStep::LoadSystemProperties {
            source: PropertySource::DefaultSystem,
        });

        for occurrence in &options.occurrences {
            match occurrence.id {
                OptionId::Addprop => {
                    if let Some(path) = occurrence.value.clone() {
                        steps.push(ConfigurationStep::LoadProperties {
                            source: PropertySource::AdditionalJmeter {
                                path,
                                occurrence: occurrence.index,
                            },
                        });
                    }
                }
                OptionId::SystemPropertyFile => {
                    if let Some(path) = occurrence.value.clone() {
                        steps.push(ConfigurationStep::LoadProperties {
                            source: PropertySource::AdditionalSystem {
                                path,
                                occurrence: occurrence.index,
                            },
                        });
                    }
                }
                OptionId::Jmeterproperty => {
                    if let Some(value) = occurrence.value.clone()
                        && let Ok(assignment) = PropertyAssignment::parse(occurrence.id, value)
                    {
                        steps.push(ConfigurationStep::ApplyJmeterProperty {
                            assignment,
                            occurrence: occurrence.index,
                        });
                    }
                }
                OptionId::Globalproperty => {
                    if let Some(value) = occurrence.value.clone()
                        && let Ok(property) = GlobalProperty::parse(value)
                    {
                        steps.push(ConfigurationStep::ApplyGlobalProperty {
                            property,
                            occurrence: occurrence.index,
                        });
                    }
                }
                OptionId::Systemproperty => {
                    if let Some(value) = occurrence.value.clone()
                        && let Ok(assignment) = PropertyAssignment::parse(occurrence.id, value)
                    {
                        steps.push(ConfigurationStep::ApplySystemProperty {
                            assignment,
                            occurrence: occurrence.index,
                        });
                    }
                }
                OptionId::Loglevel => {
                    if let Some(value) = occurrence.value.clone()
                        && let Ok(level) = LogLevel::parse(value)
                    {
                        steps.push(ConfigurationStep::ApplyLogLevel {
                            level,
                            occurrence: occurrence.index,
                        });
                    }
                }
                // Proxy flags are applied after the property loop by
                // `setProxy`; append them below in that fixed startup phase
                // rather than treating their argv position as precedence.
                OptionId::ProxyScheme
                | OptionId::ProxyHost
                | OptionId::ProxyPort
                | OptionId::NonProxyHosts
                | OptionId::Username
                | OptionId::Password => {}
                _ => {}
            }
        }

        let proxy_occurrence = |id| {
            options
                .occurrences
                .iter()
                .find(|occurrence| occurrence.id == id)
                .map(|occurrence| occurrence.index)
        };
        if let (Some(value), Some(occurrence)) = (
            options.proxy.username.clone(),
            proxy_occurrence(OptionId::Username),
        ) {
            steps.push(ConfigurationStep::ApplyProxy {
                key: "http.proxyUser",
                value,
                sensitive: false,
                occurrence,
            });
        }
        if options.proxy.username.is_some()
            && let (Some(value), Some(occurrence)) = (
                options.proxy.password.clone(),
                proxy_occurrence(OptionId::Password),
            )
        {
            steps.push(ConfigurationStep::ApplyProxy {
                key: "http.proxyPass",
                value,
                sensitive: true,
                occurrence,
            });
        }
        if let (Some(value), Some(occurrence)) = (
            options.proxy.host.clone(),
            proxy_occurrence(OptionId::ProxyHost),
        ) {
            steps.push(ConfigurationStep::ApplyProxy {
                key: "http.proxyHost/https.proxyHost",
                value,
                sensitive: false,
                occurrence,
            });
        }
        if let (Some(value), Some(occurrence)) = (
            options.proxy.port.clone(),
            proxy_occurrence(OptionId::ProxyPort),
        ) {
            steps.push(ConfigurationStep::ApplyProxy {
                key: "http.proxyPort/https.proxyPort",
                value,
                sensitive: false,
                occurrence,
            });
        }
        if options.proxy.host.is_some()
            && options.proxy.port.is_some()
            && let (Some(value), Some(occurrence)) = (
                options
                    .proxy
                    .scheme
                    .clone()
                    .filter(|value| !value.trim().is_empty()),
                proxy_occurrence(OptionId::ProxyScheme),
            )
        {
            steps.push(ConfigurationStep::ApplyProxy {
                key: "http.proxyScheme",
                value,
                sensitive: false,
                occurrence,
            });
        }
        if let (Some(value), Some(occurrence)) = (
            options.proxy.non_proxy_hosts.clone(),
            proxy_occurrence(OptionId::NonProxyHosts),
        ) {
            steps.push(ConfigurationStep::ApplyProxy {
                key: "http.nonProxyHosts/https.nonProxyHosts",
                value,
                sensitive: false,
                occurrence,
            });
        }

        steps.push(ConfigurationStep::SelectInputs {
            testfile: options.testfile.clone(),
            logfile: options.logfile.clone(),
            report_only_file: options.report_only_file.clone(),
            report_output_folder: options.report_output_folder.clone(),
        });
        Self { steps }
    }

    /// Returns the ordered steps.
    #[must_use]
    pub fn steps(&self) -> &[ConfigurationStep] {
        &self.steps
    }

    /// Returns only property loading/apply steps, retaining their order.
    #[must_use = "iterate the ordered property/configuration steps"]
    pub fn property_steps(&self) -> impl Iterator<Item = &ConfigurationStep> {
        self.steps.iter().filter(|step| {
            matches!(
                step,
                ConfigurationStep::LoadProperties { .. }
                    | ConfigurationStep::LoadUserProperties { .. }
                    | ConfigurationStep::LoadSystemProperties { .. }
                    | ConfigurationStep::ApplyJmeterProperty { .. }
                    | ConfigurationStep::ApplyGlobalProperty { .. }
                    | ConfigurationStep::ApplySystemProperty { .. }
                    | ConfigurationStep::ApplyProxy { .. }
                    | ConfigurationStep::ApplyLogLevel { .. }
            )
        })
    }
}

/// Parses arguments excluding the executable name.
pub fn parse<I, S>(arguments: I) -> Result<CliInvocation, CliError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    parse_strings(
        arguments
            .into_iter()
            .map(|argument| argument.as_ref().to_owned())
            .collect(),
    )
}

/// Parses an argument slice excluding the executable name.
pub fn parse_strings(arguments: Vec<String>) -> Result<CliInvocation, CliError> {
    let occurrences = parse_occurrences(&arguments)?;
    let mut options = build_options(occurrences)?;
    options.option_terminator = arguments.iter().any(|argument| argument == "--");
    let action = options.action;
    let configuration = options.configuration_plan();
    Ok(CliInvocation {
        options,
        action,
        configuration,
    })
}

/// Parses OS arguments excluding the executable name.  Values must be valid
/// UTF-8 because JMeter property names, paths, and diagnostics are strings at
/// this boundary; non-UTF-8 input fails explicitly instead of being lossy.
pub fn parse_os<I, S>(arguments: I) -> Result<CliInvocation, CliError>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let mut strings = Vec::new();
    for argument in arguments {
        let argument: OsString = argument.into();
        let Some(argument) = argument.to_str() else {
            return Err(CliError::NonUnicodeArgument);
        };
        strings.push(argument.to_owned());
    }
    parse_strings(strings)
}

/// Generates help text from [`OPTION_TABLE`].
#[must_use]
pub fn help_text() -> String {
    let mut output = ascii_art_text();
    output.push('\n');
    output.push_str(include_str!("resources/help.txt"));
    output.push('\n');
    output
}

/// Renders the pinned option catalog used by the `-?` action.
#[must_use]
pub fn options_text() -> String {
    let mut output = ascii_art_text();
    output.push('\n');
    for spec in OPTION_TABLE {
        output.push('\t');
        if let Some(short) = spec.short.filter(|value| value.len() == 1) {
            output.push('-');
            output.push_str(short);
            output.push_str(", ");
        }
        output.push_str("--");
        output.push_str(spec.long);
        if spec.takes_value {
            output.push_str(" <argument>");
            if matches!(
                spec.id,
                OptionId::Jmeterproperty
                    | OptionId::Globalproperty
                    | OptionId::Systemproperty
                    | OptionId::Loglevel
            ) {
                output.push_str("=<value>");
            }
        }
        output.push('\n');
        let mut description = spec.description;
        while description.len() > 60 {
            output.push_str("\t\t");
            output.push_str(&description[..60]);
            output.push('\n');
            description = &description[60..];
        }
        output.push_str("\t\t");
        output.push_str(description);
        output.push('\n');
    }
    output.push('\n');
    output
}

/// Generates version text for the binary.
#[must_use]
pub fn version_text() -> String {
    let mut output = ascii_art_text();
    output.push('\n');
    output
}

fn ascii_art_text() -> String {
    include_str!("resources/jmeter_as_ascii_art.txt")
        .replace("@VERSION@", JMETER_COMPATIBILITY_VERSION)
        .replace("@YEAR@", "2024")
}

fn lookup_long(name: &str) -> Option<OptionId> {
    OPTION_TABLE
        .iter()
        .find(|spec| spec.long == name)
        .map(|spec| spec.id)
}

fn lookup_short(name: &str) -> Option<OptionId> {
    if name == "?" {
        return Some(OptionId::Help);
    }
    OPTION_TABLE
        .iter()
        .find(|spec| spec.short == Some(name))
        .map(|spec| spec.id)
}

fn occurrence_value_is_sensitive(id: OptionId, value: Option<&str>) -> bool {
    if id == OptionId::Password {
        return true;
    }
    if !matches!(
        id,
        OptionId::Jmeterproperty | OptionId::Globalproperty | OptionId::Systemproperty
    ) {
        return false;
    }
    let Some((key, _)) = value.and_then(|value| value.split_once('=')) else {
        return false;
    };
    is_sensitive_key(key)
}

/// Shared conservative property-key redaction policy used by both the
/// parser and filesystem-backed resolver.  Matching is case-insensitive and
/// recognizes token/secret/credential families in addition to password
/// aliases, including dotted, dashed, and underscored names.
fn is_sensitive_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.ends_with("password")
        || key.ends_with("passwd")
        || key.ends_with("secret")
        || key.ends_with("token")
        || key.ends_with("credential")
        || key.ends_with("credentials")
        || key.ends_with("proxypass")
        || key.ends_with("proxy.password")
        || key.split(['.', '_', '-']).any(|segment| {
            matches!(
                segment,
                "password" | "passwd" | "secret" | "token" | "credential" | "credentials"
            )
        })
}

fn parse_occurrences(arguments: &[String]) -> Result<Vec<OptionOccurrence>, CliError> {
    let mut occurrences = Vec::new();
    let mut index = 0;
    let mut terminated = false;
    while index < arguments.len() {
        let token = &arguments[index];
        if terminated {
            return Err(CliError::UnexpectedArgument {
                argument: token.clone(),
            });
        }
        if token == "--" {
            terminated = true;
            index += 1;
            continue;
        }
        if token == "-" || !token.starts_with('-') {
            return Err(CliError::UnexpectedArgument {
                argument: token.clone(),
            });
        }
        if let Some(long_token) = token.strip_prefix("--") {
            let (name, attached) = long_token
                .split_once('=')
                .map_or((long_token, None), |(name, value)| (name, Some(value)));
            let Some(id) = lookup_long(name) else {
                return Err(CliError::UnknownOption {
                    token: token.clone(),
                });
            };
            let spec = option_spec(id);
            let (value, consumed_next, arguments_used) = consume_value(
                &spec,
                id,
                token,
                attached.map(str::to_owned),
                arguments.get(index + 1),
            )?;
            let sensitive = occurrence_value_is_sensitive(id, value.as_deref());
            occurrences.push(OptionOccurrence {
                id,
                spelling: token.clone(),
                value,
                arguments: arguments_used,
                index,
                sensitive,
            });
            index += 1 + consumed_next;
            continue;
        }

        let short_token = token.strip_prefix('-').unwrap_or(token);
        let first = short_token.get(0..1).unwrap_or_default();
        let Some(first_id) = lookup_short(first) else {
            return Err(CliError::UnknownOption {
                token: token.clone(),
            });
        };
        let first_spec = option_spec(first_id);
        if first_spec.takes_value {
            let remainder = short_token.get(first.len()..).unwrap_or_default();
            let attached = (!remainder.is_empty())
                .then(|| remainder.strip_prefix('=').unwrap_or(remainder).to_owned());
            let (value, consumed_next, arguments_used) = consume_value(
                &first_spec,
                first_id,
                token,
                attached,
                arguments.get(index + 1),
            )?;
            let sensitive = occurrence_value_is_sensitive(first_id, value.as_deref());
            occurrences.push(OptionOccurrence {
                id: first_id,
                spelling: token.clone(),
                value,
                arguments: arguments_used,
                index,
                sensitive,
            });
            index += 1 + consumed_next;
            continue;
        }

        // Commons CLI accepts compact clusters of flag options.  We accept
        // them only for flags, never by swallowing the value of an option.
        for (offset, character) in short_token.char_indices() {
            let next_offset = offset + character.len_utf8();
            let spelling = format!("-{}", character);
            let name = character.to_string();
            let Some(id) = lookup_short(&name) else {
                return Err(CliError::UnknownOption { token: spelling });
            };
            let spec = option_spec(id);
            if spec.takes_value {
                return Err(CliError::UnknownOption {
                    token: token.clone(),
                });
            }
            if next_offset < short_token.len() && id == OptionId::Help {
                // `-?x` is not a valid flag cluster; retaining the exact
                // token in the error makes this deterministic and safe.
                return Err(CliError::UnknownOption {
                    token: token.clone(),
                });
            }
            occurrences.push(OptionOccurrence {
                id,
                spelling,
                value: None,
                arguments: Vec::new(),
                index,
                sensitive: false,
            });
        }
        index += 1;
    }
    Ok(occurrences)
}

fn consume_value(
    spec: &OptionSpec,
    id: OptionId,
    spelling: &str,
    attached: Option<String>,
    next: Option<&String>,
) -> Result<(Option<String>, usize, Vec<String>), CliError> {
    if !spec.takes_value {
        if attached.is_some() {
            return Err(CliError::UnexpectedValue {
                option: id,
                spelling: spelling.to_owned(),
            });
        }
        return Ok((None, 0, Vec::new()));
    }
    let two_arguments = matches!(
        id,
        OptionId::Jmeterproperty
            | OptionId::Globalproperty
            | OptionId::Systemproperty
            | OptionId::Loglevel
    );
    if let Some(value) = attached {
        if value.is_empty() {
            return Err(CliError::InvalidValue {
                option: id,
                value,
                reason: ValueError::Empty,
            });
        }
        if two_arguments {
            let arguments = value.split_once('=').map_or_else(
                || vec![value.clone(), String::new()],
                |(first, second)| vec![first.to_owned(), second.to_owned()],
            );
            if arguments.first().is_none_or(String::is_empty) {
                return Err(CliError::InvalidValue {
                    option: id,
                    value,
                    reason: ValueError::MissingAssignment,
                });
            }
            return Ok((Some(normalize_two_argument(id, &arguments)), 0, arguments));
        }
        return Ok((Some(value.clone()), 0, vec![value]));
    }
    let Some(next) = next else {
        return Err(CliError::MissingValue {
            option: id,
            spelling: spelling.to_owned(),
        });
    };
    if next == "--" {
        return Err(CliError::MissingValue {
            option: id,
            spelling: spelling.to_owned(),
        });
    }
    if next.is_empty() {
        return Err(CliError::InvalidValue {
            option: id,
            value: next.clone(),
            reason: ValueError::Empty,
        });
    }
    if !two_arguments {
        return Ok((Some(next.clone()), 1, vec![next.clone()]));
    }
    let first = next.clone();
    let arguments = if two_arguments {
        first.split_once('=').map_or_else(
            || vec![first.clone(), String::new()],
            |(key, value)| vec![key.to_owned(), value.to_owned()],
        )
    } else {
        vec![first]
    };
    if two_arguments && arguments.first().is_none_or(String::is_empty) {
        return Err(CliError::InvalidValue {
            option: id,
            value: next.clone(),
            reason: ValueError::MissingAssignment,
        });
    }
    Ok((
        Some(if two_arguments {
            normalize_two_argument(id, &arguments)
        } else {
            arguments[0].clone()
        }),
        1,
        arguments,
    ))
}

fn normalize_two_argument(id: OptionId, arguments: &[String]) -> String {
    let first = arguments.first().map(String::as_str).unwrap_or_default();
    let second = arguments.get(1).map(String::as_str).unwrap_or_default();
    if first.contains('=') || (id == OptionId::Loglevel && second.is_empty()) {
        first.to_owned()
    } else {
        format!("{first}={second}")
    }
}

fn build_options(occurrences: Vec<OptionOccurrence>) -> Result<CliOptions, CliError> {
    if OPTION_TABLE.len() != 30 {
        return Err(CliError::InvalidOptionTable);
    }
    let mut action = Action::Execute;
    let mut action_id = None;
    let mut mode_flag = None;
    let mut options = CliOptions {
        mode: RunMode::Gui,
        action,
        propfile: None,
        addprop: Vec::new(),
        testfile: None,
        logfile: None,
        jmeterlogconf: None,
        jmeterlogfile: None,
        proxy: ProxyOptions::default(),
        jmeter_properties: Vec::new(),
        global_properties: Vec::new(),
        system_properties: Vec::new(),
        system_property_files: Vec::new(),
        log_levels: Vec::new(),
        force_delete_result_file: false,
        remote: RemoteOptions::default(),
        report_only_file: None,
        report_at_end: false,
        report_output_folder: None,
        home_dir: None,
        occurrences,
        option_terminator: false,
    };

    let mut seen_singletons = Vec::new();
    for occurrence in &options.occurrences {
        let id = occurrence.id;
        if !id.repeatable() {
            if seen_singletons.contains(&id) {
                return Err(CliError::DuplicateOption {
                    option: id,
                    spelling: occurrence.spelling.clone(),
                });
            }
            seen_singletons.push(id);
        }
        match id {
            OptionId::Help => {
                set_action(&mut action, &mut action_id, Action::Options, id)?;
            }
            OptionId::HelpLong => {
                set_action(&mut action, &mut action_id, Action::Help, id)?;
            }
            OptionId::Version => {
                set_action(&mut action, &mut action_id, Action::Version, id)?;
            }
            OptionId::Propfile => options.propfile = Some(required_value(occurrence)?),
            OptionId::Addprop => options.addprop.push(required_value(occurrence)?),
            OptionId::Testfile => {
                options.testfile = Some(PathArgument::new(required_value(occurrence)?)?);
            }
            OptionId::Logfile => {
                options.logfile = Some(PathArgument::new_log(required_value(occurrence)?)?);
            }
            OptionId::Jmeterlogconf => options.jmeterlogconf = Some(required_value(occurrence)?),
            OptionId::Jmeterlogfile => {
                options.jmeterlogfile =
                    Some(PathArgument::new_jmeter_log(required_value(occurrence)?)?);
            }
            OptionId::Nongui => set_mode(&mut mode_flag, OptionId::Nongui)?,
            OptionId::Server => set_mode(&mut mode_flag, OptionId::Server)?,
            OptionId::ProxyScheme => options.proxy.scheme = Some(required_value(occurrence)?),
            OptionId::ProxyHost => options.proxy.host = Some(required_value(occurrence)?),
            OptionId::ProxyPort => options.proxy.port = Some(required_value(occurrence)?),
            OptionId::NonProxyHosts => {
                options.proxy.non_proxy_hosts = Some(required_value(occurrence)?);
            }
            OptionId::Username => options.proxy.username = Some(required_value(occurrence)?),
            OptionId::Password => options.proxy.password = Some(required_value(occurrence)?),
            OptionId::Jmeterproperty => options
                .jmeter_properties
                .push(PropertyAssignment::parse(id, required_value(occurrence)?)?),
            OptionId::Globalproperty => options
                .global_properties
                .push(GlobalProperty::parse(required_value(occurrence)?)?),
            OptionId::Systemproperty => options
                .system_properties
                .push(PropertyAssignment::parse(id, required_value(occurrence)?)?),
            OptionId::SystemPropertyFile => options
                .system_property_files
                .push(required_value(occurrence)?),
            OptionId::ForceDeleteResultFile => options.force_delete_result_file = true,
            OptionId::Loglevel => options
                .log_levels
                .push(LogLevel::parse(required_value(occurrence)?)?),
            OptionId::Runremote => options.remote.run_remote = true,
            OptionId::Remotestart => {
                options.remote.remote_start = Some(required_value(occurrence)?);
            }
            OptionId::Homedir => options.home_dir = Some(required_value(occurrence)?),
            OptionId::Remoteexit => options.remote.remote_exit = true,
            OptionId::Reportonly => {
                options.report_only_file = Some(required_value(occurrence)?);
                set_mode(&mut mode_flag, OptionId::Reportonly)?;
            }
            OptionId::Reportatendofloadtests => options.report_at_end = true,
            OptionId::Reportoutputfolder => {
                options.report_output_folder = Some(required_value(occurrence)?);
            }
        }
    }

    options.action = action;
    options.mode = match mode_flag {
        Some(OptionId::Nongui) => RunMode::NonGui,
        Some(OptionId::Server) => RunMode::Server,
        Some(OptionId::Reportonly) => RunMode::ReportOnly,
        None => RunMode::Gui,
        Some(_) => return Err(CliError::InvalidOptionTable),
    };
    validate_combinations(&options)?;
    Ok(options)
}

fn required_value(occurrence: &OptionOccurrence) -> Result<String, CliError> {
    occurrence
        .value
        .clone()
        .ok_or_else(|| CliError::MissingValue {
            option: occurrence.id,
            spelling: occurrence.spelling.clone(),
        })
}

fn set_action(
    action: &mut Action,
    action_id: &mut Option<OptionId>,
    requested: Action,
    id: OptionId,
) -> Result<(), CliError> {
    // JMeter checks these selectors in fixed priority order after parsing:
    // version, then long help, then the options/help alias.  Do not let argv
    // order make `-? -v` behave differently from `-v -?`.
    let priority = |value: Action| match value {
        Action::Execute => 0_u8,
        Action::Options => 1,
        Action::Help => 2,
        Action::Version => 3,
    };
    if action_id.is_none() || priority(requested) > priority(*action) {
        *action = requested;
        *action_id = Some(id);
    }
    Ok(())
}

fn set_mode(mode: &mut Option<OptionId>, id: OptionId) -> Result<(), CliError> {
    if let Some(previous) = *mode
        && previous != id
    {
        return Err(CliError::IncompatibleOptions {
            options: vec![previous, id],
            reason: CombinationError::MultipleModes,
        });
    }
    *mode = Some(id);
    Ok(())
}

fn validate_combinations(options: &CliOptions) -> Result<(), CliError> {
    // Proxy host/port validation occurs during JMeter startup before its
    // informational action branches, so malformed proxy pairs do not become
    // silently accepted merely because `--version`/`--help` was selected.
    if options.proxy.host.is_some() != options.proxy.port.is_some() {
        return Err(CliError::IncompatibleOptions {
            options: vec![OptionId::ProxyHost, OptionId::ProxyPort],
            reason: CombinationError::ProxyNeedsHostAndPort,
        });
    }

    let remote_selected = options.remote.run_remote
        || options.remote.remote_start.is_some()
        || options.remote.remote_exit;
    // JMeter performs this mode guard immediately after Commons CLI parsing,
    // before the later version/help/options display branches.  Retaining it
    // here means `-? -r` and `-h -X` do not silently hide an invalid mode.
    if remote_selected && !options.is_nongui() && !options.is_report_only() {
        let mut conflicts = vec![OptionId::Nongui];
        if options.remote.run_remote {
            conflicts.push(OptionId::Runremote);
        }
        if options.remote.remote_start.is_some() {
            conflicts.push(OptionId::Remotestart);
        }
        if options.remote.remote_exit {
            conflicts.push(OptionId::Remoteexit);
        }
        return Err(CliError::IncompatibleOptions {
            options: conflicts,
            reason: CombinationError::RemoteNeedsNonGui,
        });
    }
    if options.is_report_only()
        && (options.logfile.is_some()
            || options.remote.run_remote
            || options.remote.remote_start.is_some())
    {
        let mut conflicts = vec![OptionId::Reportonly];
        if options.logfile.is_some() {
            conflicts.push(OptionId::Logfile);
        }
        if options.remote.run_remote {
            conflicts.push(OptionId::Runremote);
        }
        if options.remote.remote_start.is_some() {
            conflicts.push(OptionId::Remotestart);
        }
        return Err(CliError::IncompatibleOptions {
            options: conflicts,
            reason: CombinationError::ReportOnlyConflict,
        });
    }
    if matches!(
        options.action,
        Action::Options | Action::Help | Action::Version
    ) {
        return Ok(());
    }

    if options.is_nongui() && options.testfile.is_none() {
        return Err(CliError::IncompatibleOptions {
            options: vec![OptionId::Nongui],
            reason: CombinationError::NonGuiNeedsTestfile,
        });
    }

    if options.report_at_end && !options.is_report_only() {
        if options.logfile.is_none() {
            return Err(CliError::IncompatibleOptions {
                options: vec![OptionId::Reportatendofloadtests],
                reason: CombinationError::ReportAtEndNeedsLogfile,
            });
        }
        if !options.is_nongui() {
            return Err(CliError::IncompatibleOptions {
                options: vec![OptionId::Reportatendofloadtests],
                reason: CombinationError::ReportAtEndNeedsNonGui,
            });
        }
    }

    if !options.is_report_only() && options.report_only_file.is_some() {
        return Err(CliError::IncompatibleOptions {
            options: vec![OptionId::Reportonly],
            reason: CombinationError::ReportOnlyNeedsOnlyJtl,
        });
    }

    if options.report_output_folder.is_some() && !options.is_report_only() && !options.report_at_end
    {
        return Err(CliError::IncompatibleOptions {
            options: vec![OptionId::Reportoutputfolder],
            reason: CombinationError::ReportOutputNeedsReport,
        });
    }

    if remote_selected && !options.is_nongui() && !options.is_report_only() {
        let mut conflicts = vec![OptionId::Nongui];
        if options.remote.run_remote {
            conflicts.push(OptionId::Runremote);
        }
        if options.remote.remote_start.is_some() {
            conflicts.push(OptionId::Remotestart);
        }
        if options.remote.remote_exit {
            conflicts.push(OptionId::Remoteexit);
        }
        return Err(CliError::IncompatibleOptions {
            options: conflicts,
            reason: CombinationError::RemoteNeedsNonGui,
        });
    }
    if options.is_server()
        && (options.testfile.is_some()
            || options.logfile.is_some()
            || options.remote.run_remote
            || options.remote.remote_start.is_some()
            || options.remote.remote_exit
            || options.report_at_end
            || options.report_output_folder.is_some())
    {
        return Err(CliError::IncompatibleOptions {
            options: vec![OptionId::Server],
            reason: CombinationError::ServerConflict,
        });
    }
    Ok(())
}

/// Renders a redacted diagnostic for an arbitrary displayable value.
///
/// This helper is primarily useful to process adapters that want to include
/// parsed options in a structured diagnostic without accidentally formatting
/// proxy credentials.  It returns the same output as `Display` for the
/// redacting types in this module.
#[must_use]
pub fn redacted_debug(options: &CliOptions) -> String {
    format!("{options:?}")
}

/// Convert a platform argument to UTF-8 for callers that want the same
/// explicit policy as [`parse_os`].
pub fn os_to_string(value: &OsStr) -> Result<String, CliError> {
    value
        .to_str()
        .map(str::to_owned)
        .ok_or(CliError::NonUnicodeArgument)
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "parser tests use explicit assertion setup"
)]
mod tests {
    use super::*;

    fn parse_ok(arguments: &[&str]) -> CliInvocation {
        parse(arguments.iter().map(|value| (*value).to_owned())).expect("arguments parse")
    }

    #[test]
    fn option_table_contains_every_documented_option_once() {
        assert_eq!(OPTION_TABLE.len(), 30);
        let mut ids = OPTION_TABLE.iter().map(|spec| spec.id).collect::<Vec<_>>();
        ids.sort_by_key(|id| *id as u8);
        ids.dedup();
        assert_eq!(ids.len(), OPTION_TABLE.len());
        assert!(OPTION_TABLE.iter().any(|spec| spec.short == Some("E")));
        assert!(
            OPTION_TABLE
                .iter()
                .any(|spec| spec.long == "systemPropertyFile")
        );
        assert!(OPTION_TABLE.iter().any(|spec| spec.short == Some("?")));
    }

    #[test]
    fn all_short_and_long_options_parse_with_values_or_flags() {
        let invocation = parse_ok(&[
            "-?",
            "-h",
            "-v",
            "-p",
            "p",
            "-q",
            "q",
            "-t",
            "t",
            "-l",
            "l",
            "-i",
            "i",
            "-j",
            "j",
            "-n",
            "-E",
            "http",
            "-H",
            "host",
            "-P",
            "8080",
            "-N",
            "localhost",
            "-u",
            "user",
            "-a",
            "secret",
            "-J",
            "one=1",
            "-G",
            "two=2",
            "-D",
            "three=3",
            "-S",
            "system",
            "-f",
            "-L",
            "DEBUG",
            "-r",
            "-R",
            "one,two",
            "-d",
            "home",
            "-X",
            "-e",
            "-o",
            "out",
        ]);
        assert_eq!(invocation.options.occurrences.len(), 28);
        assert_eq!(invocation.options.proxy.password.as_deref(), Some("secret"));
    }

    #[test]
    fn repeatable_values_keep_exact_order_and_equals_after_first() {
        let invocation = parse_ok(&[
            "-n",
            "-t",
            "plan.jmx",
            "-l",
            "result.jtl",
            "-qfirst",
            "-q",
            "second",
            "-Jx=a=b",
            "--jmeterproperty",
            "y=☃",
            "-Gfile.properties",
            "-Gz=last",
            "-Dk=v",
            "-Dk=last",
            "-Sone",
            "--systemPropertyFile=two",
            "-Lfoo=DEBUG",
            "-LINFO",
        ]);
        assert_eq!(invocation.options.addprop, ["first", "second"]);
        assert_eq!(invocation.options.jmeter_properties[0].raw, "x=a=b");
        assert_eq!(invocation.options.jmeter_properties[1].value, "☃");
        assert_eq!(invocation.options.system_property_files, ["one", "two"]);
        assert_eq!(
            invocation
                .options
                .occurrences
                .iter()
                .filter(|occurrence| occurrence.id == OptionId::Jmeterproperty)
                .map(|occurrence| occurrence.value())
                .collect::<Vec<_>>(),
            vec![Some("x=a=b"), Some("y=☃")]
        );
    }

    #[test]
    fn long_equals_and_attached_short_forms_are_equivalent() {
        let separate = parse_ok(&["-n", "-t", "plan", "-l", "result", "-J", "x=y"]);
        let attached = parse_ok(&[
            "--nongui",
            "--testfile=plan",
            "--logfile=result",
            "--jmeterproperty=x=y",
        ]);
        assert_eq!(separate.options.mode, attached.options.mode);
        assert_eq!(separate.options.testfile, attached.options.testfile);
        assert_eq!(separate.options.logfile, attached.options.logfile);
        assert_eq!(
            separate.options.jmeter_properties,
            attached.options.jmeter_properties
        );
    }

    #[test]
    fn last_is_preserved_and_marked_only_for_plan_and_logs() {
        let invocation = parse_ok(&["-t", "LAST", "-l", "LAST.jtl", "-jLAST.log"]);
        assert!(
            invocation
                .options
                .testfile
                .as_ref()
                .is_some_and(PathArgument::is_last)
        );
        assert!(
            invocation
                .options
                .logfile
                .as_ref()
                .is_some_and(PathArgument::is_last)
        );
        assert!(
            invocation
                .options
                .jmeterlogfile
                .as_ref()
                .is_some_and(PathArgument::is_last)
        );
        let recent = Path::new("/tmp/RecentPlan.JmX");
        assert_eq!(
            invocation
                .options
                .logfile
                .as_ref()
                .and_then(|path| path.resolve_last_against(recent, ".jtl")),
            Some(PathBuf::from("/tmp/RecentPlan.jtl"))
        );
        assert_eq!(
            invocation
                .options
                .jmeterlogfile
                .as_ref()
                .and_then(|path| path.resolve_last_against(recent, ".log")),
            Some(PathBuf::from("LAST.log"))
        );
        let report = parse_ok(&["-g", "LAST"]);
        assert_eq!(report.options.report_only_file.as_deref(), Some("LAST"));
    }

    #[test]
    fn unicode_values_and_keys_are_not_normalized() {
        let invocation = parse_ok(&[
            "--nongui",
            "--testfile",
            "测试计划.jmx",
            "--logfile",
            "résultat.jtl",
            "--jmeterproperty",
            "ключ=значение=☃",
        ]);
        assert_eq!(
            invocation
                .options
                .testfile
                .as_ref()
                .map(PathArgument::as_str),
            Some("测试计划.jmx")
        );
        assert_eq!(
            invocation.options.jmeter_properties[0].raw,
            "ключ=значение=☃"
        );
    }

    #[test]
    fn malformed_values_are_typed_and_stable() {
        let removal = parse_ok(&["-J", "missing"]);
        assert_eq!(removal.options.jmeter_properties[0].raw, "missing=");
        for argument in ["-J=", "-D=", "-G=", "-L="] {
            assert!(matches!(
                parse_ok_err(&[argument]),
                CliError::InvalidValue {
                    reason: ValueError::Empty,
                    ..
                }
            ));
        }
        let missing = parse_ok_err(&["--testfile"]);
        assert!(matches!(
            missing,
            CliError::MissingValue {
                option: OptionId::Testfile,
                ..
            }
        ));
        let unknown = parse_ok_err(&["--not-an-option"]);
        assert_eq!(unknown.exit_code(), 2);
    }

    #[test]
    fn property_and_loglevel_separate_forms_consume_exactly_one_token() {
        for option in ["-J", "-G", "-D", "-L"] {
            let error = parse_ok_err(&[option, "key=value", "orphan"]);
            assert!(matches!(
                error,
                CliError::UnexpectedArgument { argument } if argument == "orphan"
            ));
        }
        let property = parse_ok(&["-J", "key=value"]);
        assert_eq!(property.options.jmeter_properties[0].raw, "key=value");
        let loglevel = parse_ok(&["-L", "org.apache.jmeter=DEBUG"]);
        assert_eq!(
            loglevel.options.log_levels[0].raw,
            "org.apache.jmeter=DEBUG"
        );
    }

    fn parse_ok_err(arguments: &[&str]) -> CliError {
        parse(arguments.iter().map(|value| (*value).to_owned())).expect_err("arguments fail")
    }

    #[test]
    fn mode_and_report_combinations_are_rejected() {
        assert!(matches!(
            parse_ok_err(&["-n"]),
            CliError::IncompatibleOptions {
                reason: CombinationError::NonGuiNeedsTestfile,
                ..
            }
        ));
        assert!(matches!(
            parse_ok_err(&["-n", "-t", "plan", "-e"]),
            CliError::IncompatibleOptions {
                reason: CombinationError::ReportAtEndNeedsLogfile,
                ..
            }
        ));
        assert!(
            parse_ok(&["-n", "-t", "plan", "-l", "result", "-e"])
                .options
                .report_at_end
        );
        let report_with_plan = parse_ok(&["-g", "input.jtl", "-t", "plan"]);
        assert_eq!(report_with_plan.options.mode, RunMode::ReportOnly);
        assert_eq!(
            report_with_plan
                .options
                .testfile
                .as_ref()
                .map(PathArgument::as_str),
            Some("plan")
        );
        let report_with_end = parse_ok(&["-g", "input.jtl", "-e", "-o", "out"]);
        assert!(report_with_end.options.report_at_end);
        assert!(
            parse_ok(&["-g", "input.jtl", "-X"])
                .options
                .remote
                .remote_exit
        );
        assert!(matches!(
            parse_ok_err(&["-o", "out"]),
            CliError::IncompatibleOptions {
                reason: CombinationError::ReportOutputNeedsReport,
                ..
            }
        ));
        assert!(
            parse_ok(&["-n", "-t", "plan", "-X"])
                .options
                .remote
                .remote_exit
        );
        assert!(matches!(
            parse_ok_err(&["-X"]),
            CliError::IncompatibleOptions {
                reason: CombinationError::RemoteNeedsNonGui,
                ..
            }
        ));
        for arguments in [
            vec!["-g", "input.jtl", "-n"],
            vec!["-g", "input.jtl", "-r"],
            vec!["-g", "input.jtl", "-R", "host"],
            vec!["-g", "input.jtl", "-l", "result.jtl"],
        ] {
            assert!(matches!(
                parse_ok_err(&arguments),
                CliError::IncompatibleOptions { .. }
            ));
        }
    }

    #[test]
    fn configuration_plan_is_ordered_and_has_no_io() {
        let invocation = parse_ok(&[
            "-p",
            "primary",
            "-j",
            "run.log",
            "-q",
            "additional",
            "-J",
            "local=value",
            "-G",
            "global=value",
            "-D",
            "system=value",
            "-S",
            "system-file",
            "-L",
            "root=DEBUG",
            "-n",
            "-t",
            "plan",
            "-l",
            "result",
        ]);
        let steps = invocation.configuration.steps();
        assert!(matches!(
            steps[0],
            ConfigurationStep::LoadProperties {
                source: PropertySource::ExplicitPrimary { .. }
            }
        ));
        assert!(matches!(
            steps[1],
            ConfigurationStep::SelectJmeterLog { .. }
        ));
        assert!(matches!(
            steps[2],
            ConfigurationStep::InitializeLogging { .. }
        ));
        assert!(matches!(
            steps[3],
            ConfigurationStep::LoadUserProperties { .. }
        ));
        assert!(matches!(
            steps[4],
            ConfigurationStep::LoadSystemProperties { .. }
        ));
        let property_steps = invocation
            .configuration
            .property_steps()
            .collect::<Vec<_>>();
        assert!(property_steps.iter().any(|step| matches!(
            step,
            ConfigurationStep::LoadProperties {
                source: PropertySource::AdditionalJmeter { .. }
            }
        )));
        assert!(matches!(
            property_steps.last(),
            Some(ConfigurationStep::ApplyLogLevel { .. })
        ));
        assert!(matches!(
            steps.last(),
            Some(ConfigurationStep::SelectInputs { .. })
        ));
    }

    #[test]
    fn proxy_password_is_redacted_from_debug_and_display() {
        let invocation = parse_ok(&["-a", "super-secret", "-J", "http.proxyPass=other-secret"]);
        let debug = format!("{:?}", invocation);
        let display = invocation.to_string();
        assert!(!debug.contains("super-secret"));
        assert!(!debug.contains("other-secret"));
        assert!(!display.contains("super-secret"));
        assert!(debug.contains("<redacted>"));
        assert!(display.contains("<redacted>"));
        assert_eq!(
            invocation.options.proxy.password.as_deref(),
            Some("super-secret")
        );
    }

    #[test]
    fn help_and_version_actions_skip_execution_combination_checks() {
        let help = parse_ok(&["--help", "-n"]);
        assert_eq!(help.action, Action::Help);
        let version = parse_ok(&["--version", "-n"]);
        assert_eq!(version.action, Action::Version);
        assert!(help_text().contains("To run Apache JMeter in NON_GUI mode"));
        assert!(options_text().contains("--systemPropertyFile"));
        assert!(options_text().contains("-?, --?"));
        assert!(version_text().contains("5.6.3"));
        assert!(matches!(
            parse_ok_err(&["--version", "-H", "proxy"]),
            CliError::IncompatibleOptions {
                reason: CombinationError::ProxyNeedsHostAndPort,
                ..
            }
        ));
    }

    #[test]
    fn terminator_and_positionals_fail_closed() {
        let terminator = parse_ok(&["--"]);
        assert!(terminator.options.option_terminator);
        assert!(matches!(
            parse_ok_err(&["--", "-n"]),
            CliError::UnexpectedArgument { argument } if argument == "-n"
        ));
        assert!(matches!(
            parse_ok_err(&["plan.jmx"]),
            CliError::UnexpectedArgument { argument } if argument == "plan.jmx"
        ));
    }

    #[test]
    fn non_unicode_os_argument_is_an_explicit_error() {
        #[cfg(unix)]
        let argument = OsString::from_vec(vec![0xff]);
        #[cfg(unix)]
        let error = parse_os([argument]).expect_err("invalid unicode must fail");
        #[cfg(unix)]
        assert_eq!(error, CliError::NonUnicodeArgument);
    }

    #[test]
    fn duplicate_singletons_are_rejected_but_repeats_are_allowed() {
        assert!(matches!(
            parse_ok_err(&["-t", "one", "-t", "two"]),
            CliError::DuplicateOption {
                option: OptionId::Testfile,
                ..
            }
        ));
        assert!(parse_ok(&["-q", "one", "-q", "two"]).options.addprop == ["one", "two"]);
    }
}
