// SPDX-License-Identifier: Apache-2.0
//! Explicit process-edge adapters for the JMeter-compatible CLI.
//!
//! The parser and configuration resolver are deliberately independent of
//! process state.  This module is the small application edge that supplies a
//! checked working directory, an allowlisted environment view, bounded file
//! reads, logging, the local runtime adapter, and the report adapter.  Java,
//! RMI, plugins, and GUI startup remain typed capability boundaries.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll, Waker};
use std::time::{SystemTime, UNIX_EPOCH};

use jmeter_rs_jmx::SemanticDocument;
use jmeter_rs_model::{NodeId, TestElement};
use jmeter_rs_report::{DashboardConfig, DashboardReport, ReportError, ReportInterval};
use jmeter_rs_results::{
    AssertionResults, CliMode, CsvDecoder, JavaValue, JtlError, JtlFormat, JtlLimits, LineEnding,
    MAX_SAVE_CONFIG_CANDIDATES, MAX_SAVE_CONFIG_FIELDS, MAX_SAVE_CONFIG_OPERATIONS,
    MAX_SAVE_CONFIG_OPERATIONS_PER_FIELD, MAX_SAVE_CONFIG_TEXT_BYTES,
    MAX_SAVE_CONFIG_TOTAL_VALUE_BYTES, SampleEvent, SampleResult, SampleSaveConfiguration,
    SaveConfigError, SaveConfigLimits, SaveConfigOperation, SaveConfigPrecedence,
    SaveConfigResolution, SaveConfigResolver, SaveConfigSource, SaveConfigSourceKind, SaveField,
    SaveFieldId, SaveOperationKind, SaveWireFormat, TimestampFormat, XmlDecodeConfiguration,
    XmlDecoder,
};
use jmeter_rs_runtime::{
    CompiledPackages, ComponentFuture, ControllerError, ControllerNode, ControllerProgram,
    EngineEvent, EnginePlan, LoopCount, RuntimeCapabilities, RuntimeEngine, SamplePackage, Sampler,
    SamplerOutput, ThreadGroupPlan,
};

#[cfg(test)]
use crate::config::ensure_bound_directory;
use crate::config::{
    bound_metadata, metadata_identity, open_bound_append, open_bound_create_new,
    open_bound_directory, remove_bound_file, remove_bound_tree, rename_bound,
};
use crate::{
    Action, CliInvocation, ConfigError, ConfigFsPolicy, ConfigLimits, ConfigLoader,
    ConfigNamespace, ConfigPlan, ConfigSource, ExitClass, JavaString, PathArgument, PathKind,
    PropertyMap, PropertyOperation, PropertyOperationKind, PropertyProvenance, ResolvedConfig,
    ResolvedProperty, RunMode,
};

const MAX_LOG_BYTES: usize = 64 * 1024;
const MAX_CONFIG_FILE_BYTES: usize = 64 * 1024;
const MAX_CONFIG_TOTAL_BYTES: usize = 256 * 1024;
const MAX_JTL_BYTES: usize = 64 * 1024;
const MAX_REPORT_BYTES: usize = 64 * 1024;
const MAX_DIAGNOSTIC_BYTES: usize = 64 * 1024;
const MAX_OUTPUT_ENTRIES: usize = 100_000;
const DEFAULT_REPORT_DIRECTORY: &str = "report";
const DEFAULT_JMETER_LOG: &str = "jmeter.log";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutputOpenMode {
    CreateNew,
    #[allow(
        dead_code,
        reason = "the run-owned router will use explicit replacement after integration"
    )]
    ReplaceExisting,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReportOutputMode {
    CreateNew,
    ReplaceExisting,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ReportStats {
    samples: usize,
    failed: usize,
}

struct PreparedReportTarget {
    path: PathBuf,
    root: PathBuf,
    existing_identity: Option<(u64, u64)>,
    mode: ReportOutputMode,
}
// RuntimeCapabilities currently exposes Rust strings while configuration
// preserves Java UTF-16 keys.  Keep a tagged, deterministic projection for
// malformed keys rather than using JavaString::escaped(), whose diagnostic
// spelling can collide with a literal backslash key.  The collision resolver
// below also protects the tagged namespace from an operator-supplied key.
const WTF16_RUNTIME_KEY_PREFIX: &str = "\u{0000}jmeter-rs.wtf16:";

/// Environment names that may influence this process edge.
pub const ENVIRONMENT_ALLOWLIST: &[&str] = &[
    "JMETER_HOME",
    "JMETER_LANGUAGE",
    "LANG",
    "LC_ALL",
    "PWD",
    "TZ",
];

/// A bounded, explicit view of process environment variables.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EnvironmentView {
    values: BTreeMap<String, String>,
}

impl EnvironmentView {
    /// Builds an allowlisted environment from arbitrary pairs.
    #[must_use]
    pub fn from_pairs<I, K, V>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        let mut values = BTreeMap::new();
        for (key, value) in pairs {
            let key = key.into();
            if ENVIRONMENT_ALLOWLIST.contains(&key.as_str()) {
                values.insert(key, value.into());
            }
        }
        Self { values }
    }

    /// Reads only the explicit allowlist from the host process.
    #[must_use]
    pub fn from_process() -> Self {
        Self::from_pairs(
            ENVIRONMENT_ALLOWLIST
                .iter()
                .filter_map(|name| env::var(name).ok().map(|value| ((*name).to_owned(), value))),
        )
    }

    /// Returns one allowlisted value.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }

    /// Returns deterministic environment entries.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.values
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
    }
}

/// Explicit process inputs used by [`execute_invocation`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchEnvironment {
    /// Working directory used for every relative path.
    pub cwd: PathBuf,
    /// Optional JMeter home selected by `-d` or allowlisted `JMETER_HOME`.
    pub jmeter_home: Option<PathBuf>,
    /// Requested locale label.  It is retained and never applied globally.
    pub locale: String,
    /// Requested timezone label.  It is retained and used by filename dates.
    pub timezone: String,
    /// Allowlisted environment values.
    pub environment: EnvironmentView,
    /// Clock value used for date-pattern expansion.
    pub now_millis: i64,
    /// Optional recent-project capability used by `LAST`.
    pub recent_jmx: Option<PathBuf>,
}

impl LaunchEnvironment {
    /// Creates deterministic launch inputs.
    #[must_use]
    pub fn new(cwd: impl Into<PathBuf>) -> Self {
        Self {
            cwd: cwd.into(),
            jmeter_home: None,
            locale: "en-US".to_owned(),
            timezone: "UTC".to_owned(),
            environment: EnvironmentView::default(),
            now_millis: 0,
            recent_jmx: None,
        }
    }

    /// Builds launch inputs from the host, using only the allowlisted names.
    pub fn from_process() -> Result<Self, RunError> {
        let cwd = env::current_dir().map_err(|error| RunError::io("current directory", error))?;
        let environment = EnvironmentView::from_process();
        let locale = environment
            .get("JMETER_LANGUAGE")
            .or_else(|| environment.get("LC_ALL"))
            .or_else(|| environment.get("LANG"))
            .unwrap_or("en-US")
            .to_owned();
        let timezone = environment.get("TZ").unwrap_or("UTC").to_owned();
        Ok(Self {
            jmeter_home: environment.get("JMETER_HOME").map(PathBuf::from),
            now_millis: current_millis()?,
            locale,
            timezone,
            environment,
            cwd,
            recent_jmx: None,
        })
    }

    /// Sets the explicit environment view.
    #[must_use]
    pub fn with_environment(mut self, environment: EnvironmentView) -> Self {
        self.environment = environment;
        self
    }

    /// Sets the locale label supplied to the native application adapter.
    #[must_use]
    pub fn with_locale(mut self, locale: impl Into<String>) -> Self {
        self.locale = locale.into();
        self
    }

    /// Sets the timezone label used for deterministic filename expansion.
    #[must_use]
    pub fn with_timezone(mut self, timezone: impl Into<String>) -> Self {
        self.timezone = timezone.into();
        self
    }

    /// Sets the date clock used by logging.
    #[must_use]
    pub const fn with_now_millis(mut self, now_millis: i64) -> Self {
        self.now_millis = now_millis;
        self
    }

    /// Sets the recent-project path used by `LAST` resolution.
    #[must_use]
    pub fn with_recent_jmx(mut self, path: impl Into<PathBuf>) -> Self {
        self.recent_jmx = Some(path.into());
        self
    }
}

/// High-level outcome category for a completed invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunCategory {
    /// No samples failed and the selected action completed.
    Normal,
    /// One or more sample results failed; JMeter keeps the process status
    /// successful unless startup/reporting itself fails.
    SampleFailure,
    /// A fatal local startup, engine, or report error occurred.
    Fatal,
    /// A remote adapter failed or remains unavailable.
    Remote,
}

impl RunCategory {
    /// Returns the process exit class for the category.
    #[must_use]
    pub const fn exit_class(self) -> ExitClass {
        match self {
            Self::Normal => ExitClass::Success,
            Self::SampleFailure => ExitClass::SampleFailure,
            Self::Fatal => ExitClass::Fatal,
            Self::Remote => ExitClass::RemoteFailure,
        }
    }
}

/// Completed local/report invocation information.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunOutcome {
    /// Selected mode.
    pub mode: RunMode,
    /// Normal/sample-failure/fatal/remote category.
    pub category: RunCategory,
    /// Number of emitted sample results.
    pub samples: usize,
    /// Number of failed sample results.
    pub sample_failures: usize,
    /// Result file written by a local run, if requested.
    pub result_file: Option<PathBuf>,
    /// Dashboard directory written by a report action, if requested.
    pub report_directory: Option<PathBuf>,
    /// Run log path selected by the logging adapter.
    pub log_file: Option<PathBuf>,
}

/// Typed failure returned by the application edge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunError {
    /// Bounded configuration loading failed.
    Configuration(ConfigError),
    /// The selected JMX syntax/semantic plan could not be decoded.
    Jmx {
        /// Bounded parser diagnostic.
        message: String,
    },
    /// A capability outside the bounded native local/report adapter is
    /// required for the active compatibility profile.
    Unsupported {
        /// Stable capability label.
        capability: String,
        /// Bounded capability diagnostic.
        message: String,
    },
    /// A remote adapter is selected, but the bounded app layer has no RMI
    /// implementation for the active compatibility profile.
    Remote {
        /// Stable remote capability label.
        capability: String,
        /// Bounded remote diagnostic.
        message: String,
    },
    /// A bounded local output/report write failed.
    Io {
        /// Path associated with the operation.
        path: PathBuf,
        /// Bounded I/O diagnostic.
        message: String,
    },
    /// The local runtime rejected a valid plan.
    Runtime {
        /// Stable runtime diagnostic code.
        code: String,
        /// Bounded runtime diagnostic.
        message: String,
    },
    /// Report input or aggregation failed.
    Report {
        /// Stable code from the report/JTL adapter.
        code: &'static str,
        /// Bounded human-readable report diagnostic.
        message: String,
    },
}

impl RunError {
    fn io(path: impl Into<PathBuf>, error: io::Error) -> Self {
        let path = path.into();
        if error.kind() == io::ErrorKind::Unsupported {
            return Self::unsupported(
                "descriptor-bound-filesystem",
                format!("{}: {error}", path.display()),
            );
        }
        Self::Io {
            path,
            message: bounded(error.to_string(), MAX_DIAGNOSTIC_BYTES),
        }
    }

    fn from_config(error: ConfigError) -> Self {
        if error.is_unsupported() {
            return Self::unsupported("descriptor-bound-filesystem", error.to_string());
        }
        Self::Configuration(error)
    }

    fn unsupported(capability: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Unsupported {
            capability: bounded(capability.into(), 256),
            message: bounded(message.into(), MAX_DIAGNOSTIC_BYTES),
        }
    }

    fn remote(capability: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Remote {
            capability: bounded(capability.into(), 256),
            message: bounded(message.into(), MAX_DIAGNOSTIC_BYTES),
        }
    }

    /// Returns the stable diagnostic code.
    #[must_use]
    pub fn code(&self) -> &str {
        match self {
            Self::Configuration(error) => error.code(),
            Self::Jmx { .. } => "jmx.load",
            Self::Unsupported { .. } => "capability.unavailable",
            Self::Remote { .. } => "remote.unavailable",
            Self::Io { .. } => "io.output",
            Self::Runtime { code, .. } => code,
            Self::Report { code, .. } => code,
        }
    }

    /// Returns the mapped process exit class.
    #[must_use]
    pub const fn exit_class(&self) -> ExitClass {
        match self {
            Self::Configuration(_) => ExitClass::ConfigurationError,
            Self::Unsupported { .. } => ExitClass::UnsupportedCapability,
            Self::Remote { .. } => ExitClass::RemoteFailure,
            Self::Jmx { .. } | Self::Io { .. } | Self::Runtime { .. } | Self::Report { .. } => {
                ExitClass::Fatal
            }
        }
    }
}

impl std::fmt::Display for RunError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Configuration(error) => error.fmt(formatter),
            Self::Jmx { message }
            | Self::Io { message, .. }
            | Self::Runtime { message, .. }
            | Self::Report { message, .. } => formatter.write_str(message),
            Self::Unsupported {
                capability,
                message,
            }
            | Self::Remote {
                capability,
                message,
            } => write!(formatter, "{capability}: {message}"),
        }
    }
}

impl std::error::Error for RunError {}

/// Executes a parsed invocation through explicit local/report adapters.
pub fn execute_invocation(
    invocation: &CliInvocation,
    launch: &LaunchEnvironment,
) -> Result<RunOutcome, RunError> {
    if !matches!(invocation.action, Action::Execute) {
        return Ok(RunOutcome {
            mode: invocation.mode(),
            category: RunCategory::Normal,
            samples: 0,
            sample_failures: 0,
            result_file: None,
            report_directory: None,
            log_file: None,
        });
    }

    let cwd = fs::canonicalize(&launch.cwd).map_err(|error| RunError::io(&launch.cwd, error))?;
    let selected_home = invocation
        .options
        .home_dir
        .as_deref()
        .map(PathBuf::from)
        .or_else(|| launch.jmeter_home.clone());
    let selected_home = selected_home.map(|home| {
        if home.is_absolute() {
            home
        } else {
            cwd.join(home)
        }
    });
    let mut plan = ConfigPlan::from_invocation(invocation).with_base_dir(&cwd);
    if let Some(home) = selected_home {
        plan = plan.with_jmeter_home(home);
    }
    let mut fs_policy = ConfigFsPolicy::new(&cwd);
    if let Some(home) = plan.jmeter_home.as_deref() {
        fs_policy = fs_policy.with_additional_root(home.join("bin"));
    }
    let loader = ConfigLoader::for_conformance(&cwd)
        .with_fs_policy(fs_policy)
        .with_working_dir(&cwd)
        .with_limits(
            ConfigLimits::standard()
                .with_max_file_bytes(MAX_CONFIG_FILE_BYTES)
                .with_max_total_file_bytes(MAX_CONFIG_TOTAL_BYTES),
        );
    let resolved = plan.resolve(&loader).map_err(RunError::from_config)?;
    let mut logger = RunLogger::initialize(invocation, &resolved, launch)?;

    let execution = match invocation.mode() {
        RunMode::Gui => Err(RunError::unsupported(
            "gui",
            "GUI startup is outside the bounded native local/report adapter for profile jmeter-5.6.3",
        )),
        RunMode::Server => Err(RunError::unsupported(
            "server-jvm-rmi",
            "server mode is outside the bounded native local/report adapter for profile jmeter-5.6.3",
        )),
        RunMode::ReportOnly => report_only(invocation, launch, &loader, &resolved, &mut logger),
        RunMode::NonGui => {
            if invocation.options.remote.run_remote
                || invocation.options.remote.remote_start.is_some()
                || invocation.options.remote.remote_exit
            {
                Err(RunError::remote(
                    "remote-rmi",
                    "remote execution is outside the bounded native local/report adapter for profile jmeter-5.6.3",
                ))
            } else if invocation.options.logfile.is_some()
                || invocation.options.report_at_end
                || invocation.options.force_delete_result_file
            {
                Err(result_router_boundary())
            } else {
                local_run(invocation, launch, &loader, &resolved, &mut logger)
            }
        }
    };

    match (execution, logger.finish()) {
        (Ok(outcome), Ok(())) => Ok(outcome),
        (Ok(_), Err(log_error)) => Err(log_error),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(_log_error)) if matches!(&error, RunError::Unsupported { .. }) => {
            // Preserve the first typed capability boundary.  In particular,
            // a non-Linux descriptor-bound log flush must not turn an already
            // typed GUI/remote/filesystem refusal into a generic fatal code.
            Err(error)
        }
        (Err(_error), Err(log_error)) if matches!(&log_error, RunError::Unsupported { .. }) => {
            // Logging uses the same descriptor-bound filesystem contract as
            // the primary operation; expose that unsupported target rather
            // than hiding it inside an execution.logging wrapper.
            Err(log_error)
        }
        (Err(error), Err(log_error)) => Err(RunError::Runtime {
            code: "execution.logging".to_owned(),
            message: bounded(
                format!("execution failed: {error}; logging failed: {log_error}"),
                MAX_DIAGNOSTIC_BYTES,
            ),
        }),
    }
}

fn report_only(
    invocation: &CliInvocation,
    launch: &LaunchEnvironment,
    loader: &ConfigLoader,
    resolved: &ResolvedConfig,
    logger: &mut RunLogger,
) -> Result<RunOutcome, RunError> {
    let raw = invocation
        .options
        .report_only_file
        .as_deref()
        .ok_or_else(|| RunError::Report {
            code: "report.input",
            message: "report-only input is missing".to_owned(),
        })?;
    let path = resolve_checked_path(&launch.cwd, raw)?;
    let bytes = loader.read_file(&path).map_err(RunError::from_config)?;
    let input_format = observe_jtl_format(bytes.as_slice());
    let save_configuration = save_configuration(resolved, input_format)?;
    if invocation.options.report_output_folder.is_none() {
        return Err(RunError::unsupported(
            "report-output-default",
            "report-only output without -o is not applied until the pinned JMeter output-directory oracle is available",
        ));
    }
    let mode = if invocation.options.force_delete_result_file {
        ReportOutputMode::ReplaceExisting
    } else {
        ReportOutputMode::CreateNew
    };
    let directory = prepare_report_target(
        invocation.options.report_output_folder.as_deref(),
        launch,
        mode,
    )?;
    let stats = write_report_dashboard(&directory, bytes.as_slice(), save_configuration.wire())?;
    logger.info(&format!(
        "report input={} samples={}",
        path.display(),
        stats.samples
    ));
    Ok(RunOutcome {
        mode: RunMode::ReportOnly,
        category: if stats.failed == 0 {
            RunCategory::Normal
        } else {
            RunCategory::SampleFailure
        },
        samples: stats.samples,
        sample_failures: stats.failed,
        result_file: None,
        report_directory: Some(directory.path.clone()),
        log_file: logger.path.clone(),
    })
}

/// The complete save-configuration result used by the report adapter.
///
/// The codec configuration is accompanied by the resolver output rather than
/// replacing it.  In particular, unknown save-service properties remain in
/// the bounded resolution and are not silently discarded just because the
/// current CSV/XML codec has no typed field for them.
struct ResolvedSaveConfiguration {
    wire: SampleSaveConfiguration,
    _resolution: SaveConfigResolution,
}

impl ResolvedSaveConfiguration {
    fn wire(&self) -> &SampleSaveConfiguration {
        &self.wire
    }
}

/// Inputs retained while adapting the application's ordered configuration
/// plan into the results-layer resolver.
enum SaveConfigurationInput<'a> {
    Operation(&'a PropertyOperation),
    Effective(&'a ResolvedProperty),
    Removal {
        key: &'a str,
        provenance: &'a PropertyProvenance,
    },
}

fn save_configuration(
    resolved: &ResolvedConfig,
    observed_format: SaveWireFormat,
) -> Result<ResolvedSaveConfiguration, RunError> {
    let wire_format = configured_save_wire_format(resolved, observed_format);
    let precedence = SaveConfigPrecedence::new(
        "jmeter-5.6.3",
        [
            SaveConfigSourceKind::CliMode,
            SaveConfigSourceKind::RunProperties,
            SaveConfigSourceKind::PlanSaveConfig,
            SaveConfigSourceKind::ReportInputMetadata,
            SaveConfigSourceKind::FormatObservation,
        ],
    )
    .map_err(save_config_error)?;
    let limits = SaveConfigLimits::new(
        MAX_SAVE_CONFIG_FIELDS,
        MAX_SAVE_CONFIG_OPERATIONS_PER_FIELD,
        MAX_SAVE_CONFIG_OPERATIONS,
        MAX_SAVE_CONFIG_CANDIDATES,
        MAX_SAVE_CONFIG_TEXT_BYTES,
        MAX_SAVE_CONFIG_TOTAL_VALUE_BYTES,
    )
    .map_err(save_config_error)?;
    let mut resolver =
        SaveConfigResolver::new(precedence, wire_format, limits).map_err(save_config_error)?;

    for inputs in ordered_save_configuration_inputs(resolved).values() {
        for input in inputs {
            push_save_configuration_input(&mut resolver, input)?;
        }
    }

    // Report-only format observation is an explicit low-precedence source. It
    // supplies a format when no run property selects one, while a configured
    // output_format (including an explicit remove) remains authoritative.
    let output_format = match observed_format {
        SaveWireFormat::Csv => "csv",
        SaveWireFormat::Xml => "xml",
        SaveWireFormat::Properties | SaveWireFormat::Unknown => {
            return Err(RunError::Report {
                code: "save-config.ambiguous",
                message: "report input has no supported CSV or XML format observation".to_owned(),
            });
        }
    };
    resolver
        .push_raw(
            SaveField::known(SaveFieldId::OutputFormat),
            SaveConfigSource::FormatObservation {
                format: observed_format,
            },
            SaveOperationKind::Apply,
            output_format,
        )
        .map_err(save_config_error)?;
    resolver
        .push(
            SaveField::known(SaveFieldId::OutputFormat),
            SaveConfigSource::CliMode {
                mode: CliMode::ReportOnly,
            },
            SaveConfigOperation::absent(),
        )
        .map_err(save_config_error)?;

    let resolution = resolver.resolve().map_err(save_config_error)?;
    let mut wire = match wire_format {
        SaveWireFormat::Csv => SampleSaveConfiguration::csv(),
        SaveWireFormat::Xml => SampleSaveConfiguration::xml(),
        SaveWireFormat::Properties | SaveWireFormat::Unknown => {
            return Err(RunError::Report {
                code: "save-config.ambiguous",
                message: "report input has no supported CSV or XML wire configuration".to_owned(),
            });
        }
    };
    for field in resolution.fields() {
        apply_save_field(&mut wire, field)?;
    }
    wire.validate().map_err(save_configuration_jtl_error)?;
    Ok(ResolvedSaveConfiguration {
        wire,
        _resolution: resolution,
    })
}

fn configured_save_wire_format(
    resolved: &ResolvedConfig,
    observed_format: SaveWireFormat,
) -> SaveWireFormat {
    match resolved
        .jmeter
        .get_value("jmeter.save.saveservice.output_format")
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("csv") => SaveWireFormat::Csv,
        Some("xml") => SaveWireFormat::Xml,
        _ => observed_format,
    }
}

fn ordered_save_configuration_inputs(
    resolved: &ResolvedConfig,
) -> BTreeMap<usize, Vec<SaveConfigurationInput<'_>>> {
    let mut inputs = BTreeMap::new();
    let mut operation_keys = BTreeSet::new();

    for operation in &resolved.operations {
        if operation.namespace != ConfigNamespace::Jmeter {
            continue;
        }
        let Some(key) = operation.key.as_deref() else {
            continue;
        };
        if !is_save_configuration_key(key) {
            continue;
        }
        if matches!(
            operation.kind,
            PropertyOperationKind::Assignment
                | PropertyOperationKind::Proxy
                | PropertyOperationKind::Remove
        ) {
            operation_keys.insert((operation.order, key.to_owned()));
            inputs
                .entry(operation.order)
                .or_insert_with(Vec::new)
                .push(SaveConfigurationInput::Operation(operation));
        }
    }

    // A file-load operation carries no individual key/value in the ordered
    // plan.  Reintroduce the effective file entries at their winning loader
    // operation so that source order remains meaningful without flattening
    // the complete PropertyMap through the codec's default constructor.
    for (key, property) in resolved.jmeter.iter() {
        if !is_save_configuration_key(key)
            || operation_keys.contains(&(property.provenance.operation, key.clone()))
        {
            continue;
        }
        inputs
            .entry(property.provenance.operation)
            .or_insert_with(Vec::new)
            .push(SaveConfigurationInput::Effective(property));
    }

    // Keep explicit removals observable even for a manually assembled
    // ResolvedConfig whose operation list does not carry the corresponding
    // remove operation.
    if let Some(removals) = resolved.removals.get(&ConfigNamespace::Jmeter) {
        for (key, provenance) in removals {
            if !is_save_configuration_key(key) {
                continue;
            }
            for source in provenance {
                if operation_keys.contains(&(source.operation, key.clone())) {
                    continue;
                }
                inputs
                    .entry(source.operation)
                    .or_insert_with(Vec::new)
                    .push(SaveConfigurationInput::Removal {
                        key,
                        provenance: source,
                    });
            }
        }
    }
    inputs
}

fn is_save_configuration_key(key: &str) -> bool {
    SaveFieldId::from_property_name(key).is_some()
        || key.starts_with("jmeter.save.saveservice.")
        || key.starts_with("sampleresult.")
}

fn push_save_configuration_input(
    resolver: &mut SaveConfigResolver,
    input: &SaveConfigurationInput<'_>,
) -> Result<(), RunError> {
    let (key, operation, ordinal) = match input {
        SaveConfigurationInput::Operation(property_operation) => {
            let key = property_operation
                .key
                .as_deref()
                .ok_or_else(|| save_config_invalid("missing property key"))?;
            let ordinal =
                save_source_ordinal(&property_operation.source, property_operation.order)?;
            let save_operation = match property_operation.kind {
                PropertyOperationKind::Assignment | PropertyOperationKind::Proxy => {
                    let value = property_operation
                        .value
                        .as_ref()
                        .ok_or_else(|| save_config_invalid("property operation has no value"))?;
                    if value.as_str().is_empty() {
                        SaveConfigOperation::present_empty()
                    } else {
                        SaveConfigOperation::apply_raw(
                            &SaveField::from_property_name(key).map_err(save_config_error)?,
                            value.as_str(),
                        )
                        .map_err(save_config_error)?
                    }
                }
                PropertyOperationKind::Remove => SaveConfigOperation::remove(),
                PropertyOperationKind::LoadFile | PropertyOperationKind::Logging => return Ok(()),
            };
            (key, save_operation, ordinal)
        }
        SaveConfigurationInput::Effective(property) => {
            let field = SaveField::from_property_name(&property.key).map_err(save_config_error)?;
            let operation = if property.as_str().is_empty() {
                SaveConfigOperation::present_empty()
            } else {
                SaveConfigOperation::apply_raw(&field, property.as_str())
                    .map_err(save_config_error)?
            };
            (
                property.key.as_str(),
                operation,
                save_source_ordinal(&property.provenance.source, property.provenance.operation)?,
            )
        }
        SaveConfigurationInput::Removal { key, provenance } => (
            *key,
            SaveConfigOperation::remove(),
            save_source_ordinal(&provenance.source, provenance.operation)?,
        ),
    };
    let field = SaveField::from_property_name(key).map_err(save_config_error)?;
    resolver
        .push(
            field,
            SaveConfigSource::RunProperties { ordinal },
            operation,
        )
        .map(|_| ())
        .map_err(save_config_error)
}

fn save_source_ordinal(source: &ConfigSource, operation: usize) -> Result<u32, RunError> {
    let ordinal = match source {
        ConfigSource::AdditionalJmeter { occurrence, .. }
        | ConfigSource::AdditionalSystem { occurrence, .. }
        | ConfigSource::Global { occurrence, .. }
        | ConfigSource::CommandLine { occurrence, .. } => *occurrence,
        ConfigSource::DefaultPrimary { .. }
        | ConfigSource::ExplicitPrimary { .. }
        | ConfigSource::DefaultUser { .. }
        | ConfigSource::DefaultSystem { .. } => operation,
    };
    u32::try_from(ordinal)
        .map_err(|_| save_config_invalid("configuration source ordinal exceeds the resolver bound"))
}

fn apply_save_field(
    configuration: &mut SampleSaveConfiguration,
    field: &jmeter_rs_results::SaveFieldResolution,
) -> Result<(), RunError> {
    let Some(field_id) = field.field().known_id() else {
        // Unknown fields are retained by SaveConfigResolution.  The current
        // codec has no typed representation, so carrying them in the wrapper
        // is the only lossless application-side behavior.
        return Ok(());
    };
    let Some(presence) = field.final_presence() else {
        return Ok(());
    };
    if matches!(presence, jmeter_rs_results::FieldPresence::Absent) {
        return Ok(());
    }
    match field_id {
        SaveFieldId::OutputFormat => {
            let value = resolved_string(field)?;
            configuration.set_format(match value.to_ascii_lowercase().as_str() {
                "csv" => JtlFormat::Csv,
                "xml" => JtlFormat::Xml,
                _ => return Err(save_config_invalid("output format is not csv or xml")),
            });
        }
        SaveFieldId::TimestampFormat => {
            let value = resolved_string(field)?;
            configuration.set_timestamp_format(match value.to_ascii_lowercase().as_str() {
                "none" => TimestampFormat::None,
                "ms" => TimestampFormat::Milliseconds,
                _ => TimestampFormat::JavaDateFormat(value),
            });
        }
        SaveFieldId::PrintFieldNames => configuration.set_print_field_names(resolved_bool(field)?),
        SaveFieldId::Delimiter => configuration
            .set_delimiter_str(&resolved_string(field)?)
            .map_err(save_configuration_jtl_error)?,
        SaveFieldId::Time => configuration.set_time(resolved_bool(field)?),
        SaveFieldId::Latency => configuration.set_latency(resolved_bool(field)?),
        SaveFieldId::ConnectTime => configuration.set_connect_time(resolved_bool(field)?),
        SaveFieldId::Timestamp => configuration.set_timestamp(resolved_bool(field)?),
        SaveFieldId::Successful => configuration.set_success(resolved_bool(field)?),
        SaveFieldId::Label => configuration.set_label(resolved_bool(field)?),
        SaveFieldId::ResponseCode => configuration.set_response_code(resolved_bool(field)?),
        SaveFieldId::ResponseMessage => configuration.set_response_message(resolved_bool(field)?),
        SaveFieldId::ThreadName => configuration.set_thread_name(resolved_bool(field)?),
        SaveFieldId::DataType => configuration.set_data_type(resolved_bool(field)?),
        SaveFieldId::Encoding => configuration.set_encoding(resolved_bool(field)?),
        SaveFieldId::Assertions | SaveFieldId::AssertionResults => {
            let value = resolved_string(field)?;
            configuration.set_assertion_results(parse_assertion_results(&value)?);
        }
        SaveFieldId::Subresults => configuration.set_subresults(resolved_bool(field)?),
        SaveFieldId::ResponseData => configuration.set_response_data(resolved_bool(field)?),
        SaveFieldId::ResponseDataOnError => {
            configuration.set_response_data_on_error(resolved_bool(field)?)
        }
        SaveFieldId::SamplerData => configuration.set_sampler_data(resolved_bool(field)?),
        SaveFieldId::ResponseHeaders => configuration.set_response_headers(resolved_bool(field)?),
        SaveFieldId::RequestHeaders => configuration.set_request_headers(resolved_bool(field)?),
        SaveFieldId::Bytes => configuration.set_bytes(resolved_bool(field)?),
        SaveFieldId::SentBytes => configuration.set_sent_bytes(resolved_bool(field)?),
        SaveFieldId::Url => configuration.set_url(resolved_bool(field)?),
        SaveFieldId::Filename => configuration.set_filename(resolved_bool(field)?),
        SaveFieldId::Hostname => configuration.set_hostname(resolved_bool(field)?),
        SaveFieldId::ThreadCounts => configuration.set_thread_counts(resolved_bool(field)?),
        SaveFieldId::SampleCount => configuration.set_sample_count(resolved_bool(field)?),
        SaveFieldId::IdleTime => configuration.set_idle_time(resolved_bool(field)?),
        SaveFieldId::AssertionFailureMessage => {
            configuration.set_assertion_results_failure_message(resolved_bool(field)?)
        }
        SaveFieldId::SampleVariables => configuration
            .set_sample_variables(resolved_string_list(field)?)
            .map_err(save_configuration_jtl_error)?,
        SaveFieldId::TimestampStart => configuration.set_timestamp_start(resolved_bool(field)?),
        SaveFieldId::UseNanoTime => configuration.set_use_nano_time(resolved_bool(field)?),
        SaveFieldId::NanoThreadSleep => configuration.set_nano_thread_sleep(resolved_long(field)?),
        SaveFieldId::SubresultsDisableRenaming => {
            configuration.set_subresults_disable_renaming(resolved_bool(field)?)
        }
        SaveFieldId::DefaultEncoding => {
            configuration.set_default_encoding(Some(resolved_string(field)?));
        }
        SaveFieldId::Autoflush => configuration.set_autoflush(resolved_bool(field)?),
        SaveFieldId::XmlPi | SaveFieldId::BasePrefix => {
            return Err(RunError::unsupported(
                "jtl-save-configuration",
                "the selected save configuration requires an unsupported XML policy",
            ));
        }
        SaveFieldId::LineEnding => {
            let value = resolved_string(field)?;
            configuration.set_line_ending(parse_line_ending(&value)?);
        }
    }
    Ok(())
}

fn resolved_bool(field: &jmeter_rs_results::SaveFieldResolution) -> Result<bool, RunError> {
    match field.java_value() {
        Some(JavaValue::Boolean(value))
            if field.final_presence() == Some(jmeter_rs_results::FieldPresence::Present) =>
        {
            Ok(*value)
        }
        _ => Err(save_config_invalid("save field requires a boolean value")),
    }
}

fn resolved_long(field: &jmeter_rs_results::SaveFieldResolution) -> Result<i64, RunError> {
    match field.java_value() {
        Some(JavaValue::Long(value))
            if field.final_presence() == Some(jmeter_rs_results::FieldPresence::Present) =>
        {
            Ok(*value)
        }
        _ => Err(save_config_invalid("save field requires a long value")),
    }
}

fn resolved_string(field: &jmeter_rs_results::SaveFieldResolution) -> Result<String, RunError> {
    match field.final_presence() {
        Some(jmeter_rs_results::FieldPresence::PresentEmpty) => Ok(String::new()),
        Some(jmeter_rs_results::FieldPresence::Present) => match field.java_value() {
            Some(JavaValue::String(value)) => Ok(value.clone()),
            _ => Err(save_config_invalid("save field requires a string value")),
        },
        _ => Err(save_config_invalid("save field is not present")),
    }
}

fn resolved_string_list(
    field: &jmeter_rs_results::SaveFieldResolution,
) -> Result<Vec<String>, RunError> {
    match field.final_presence() {
        Some(jmeter_rs_results::FieldPresence::PresentEmpty) => Ok(Vec::new()),
        Some(jmeter_rs_results::FieldPresence::Present) => match field.java_value() {
            Some(JavaValue::StringList(values)) => Ok(values.clone()),
            _ => Err(save_config_invalid(
                "save field requires a string-list value",
            )),
        },
        _ => Err(save_config_invalid("save field is not present")),
    }
}

fn parse_assertion_results(value: &str) -> Result<AssertionResults, RunError> {
    match value.to_ascii_lowercase().as_str() {
        "true" | "all" => Ok(AssertionResults::All),
        "false" | "none" => Ok(AssertionResults::None),
        "first" => Ok(AssertionResults::First),
        _ => Err(save_config_invalid(
            "assertion result selection is unsupported",
        )),
    }
}

fn parse_line_ending(value: &str) -> Result<LineEnding, RunError> {
    match value.to_ascii_lowercase().as_str() {
        "lf" | "\\n" => Ok(LineEnding::Lf),
        "crlf" | "\\r\\n" => Ok(LineEnding::CrLf),
        "cr" | "\\r" => Ok(LineEnding::Cr),
        _ => Err(save_config_invalid("line-ending selection is unsupported")),
    }
}

fn observe_jtl_format(input: &[u8]) -> SaveWireFormat {
    let input = input.strip_prefix(b"\xef\xbb\xbf").unwrap_or(input);
    if input
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
        == Some(b'<')
    {
        SaveWireFormat::Xml
    } else {
        SaveWireFormat::Csv
    }
}

fn save_config_error(error: SaveConfigError) -> RunError {
    RunError::Report {
        code: error.stable_code(),
        message: bounded(error.to_string(), MAX_DIAGNOSTIC_BYTES),
    }
}

fn save_configuration_jtl_error(error: JtlError) -> RunError {
    if error.stable_code() == "results.jtl.unsupported" {
        RunError::unsupported(
            "jtl-save-configuration",
            "the selected save configuration requires an unsupported capability",
        )
    } else {
        RunError::Report {
            code: "jtl.save-config",
            message: format!("save configuration rejected ({})", error.stable_code()),
        }
    }
}

fn save_config_invalid(message: &'static str) -> RunError {
    RunError::Report {
        code: "jtl.save-config",
        message: message.to_owned(),
    }
}

fn result_router_boundary() -> RunError {
    RunError::unsupported(
        "result-router",
        "CLI result output and report-at-end require the run-owned result router; the application seam is not wired until prepared sink outputs are available",
    )
}

fn jtl_limits() -> JtlLimits {
    JtlLimits {
        max_input_bytes: MAX_JTL_BYTES,
        max_output_bytes: MAX_JTL_BYTES,
        max_record_bytes: MAX_JTL_BYTES,
        max_attribute_bytes: MAX_JTL_BYTES,
        max_nodes: MAX_OUTPUT_ENTRIES,
        max_samples: MAX_OUTPUT_ENTRIES,
        ..JtlLimits::default()
    }
}

fn local_run(
    invocation: &CliInvocation,
    launch: &LaunchEnvironment,
    loader: &ConfigLoader,
    resolved: &ResolvedConfig,
    logger: &mut RunLogger,
) -> Result<RunOutcome, RunError> {
    let test = invocation
        .options
        .testfile
        .as_ref()
        .ok_or_else(|| RunError::Runtime {
            code: "runtime.no-test-plan".to_owned(),
            message: "non-GUI runs require a test plan".to_owned(),
        })?;
    let test_path = resolve_path_argument(test, ".jmx", launch)?;
    let source = loader
        .read_file(&test_path)
        .map_err(RunError::from_config)?;
    let document = SemanticDocument::from_bytes(&source).map_err(|error| RunError::Jmx {
        message: bounded(error.to_string(), MAX_DIAGNOSTIC_BYTES),
    })?;
    let (engine_plan, packages) = compile_local_plan(&document)?;
    // One property map belongs to the complete local run.  RuntimeEngine
    // clones these capabilities for each virtual user and group, preserving
    // the same Arc-backed property view instead of rebuilding a map per
    // ThreadGroup.  Iterate the exact Java map: the legacy `entries`
    // projection is lossy for unpaired-surrogate keys.
    // RuntimeCapabilities models JMeter's local `props` namespace.  System
    // and remote/global maps remain separate configuration namespaces until
    // their explicit adapters exist; merging them here would change
    // precedence and leak remote-only settings into local expressions.
    let properties = Arc::new(RwLock::new(runtime_properties(&resolved.jmeter)));
    let mut engine = RuntimeEngine::new(
        engine_plan,
        RuntimeCapabilities::default().with_properties(properties),
        "jmeter-rs",
        "localhost",
    );
    let report = block_on(engine.run()).map_err(|error| RunError::Runtime {
        code: error.code().to_owned(),
        message: bounded(error.to_string(), MAX_DIAGNOSTIC_BYTES),
    })?;
    let (samples, failed) = engine_sample_counts(&report.events)?;
    logger.info(&format!(
        "local plan={} packages={} samples={} failures={}",
        test_path.display(),
        packages,
        samples,
        failed
    ));
    Ok(RunOutcome {
        mode: RunMode::NonGui,
        category: if failed == 0 {
            RunCategory::Normal
        } else {
            RunCategory::SampleFailure
        },
        samples,
        sample_failures: failed,
        // CLI result persistence is owned by the run-level router.  The
        // application deliberately refuses -l above until that prepared
        // output seam is wired; a local engine run therefore never claims a
        // result path was written.
        result_file: None,
        report_directory: None,
        log_file: logger.path.clone(),
    })
}

/// Projects the exact resolved JMeter property namespace into the current
/// runtime capability boundary.
///
/// The runtime API intentionally accepts `BTreeMap<String, String>` today,
/// while Java properties are UTF-16 and may contain unpaired surrogates.  A
/// valid Java key keeps its normal UTF-8 spelling so ordinary `${__P(name)}`
/// lookups retain JMeter behavior.  A malformed key receives a tagged UTF-16
/// spelling; if an operator supplied key already occupies that spelling, a
/// deterministic numeric suffix keeps both exact keys visible rather than
/// silently overwriting one of them.  Values use the existing escaped
/// projection only when Rust cannot represent their UTF-16 units; values do
/// not participate in map-key identity.
fn runtime_properties(properties: &PropertyMap) -> BTreeMap<String, String> {
    let mut projected = BTreeMap::new();
    let mut occupied = BTreeMap::<String, JavaString>::new();
    for (java_key, property) in properties.iter_java() {
        let base = runtime_property_key(java_key);
        let mut key = base.clone();
        let mut suffix = 0_u64;
        while occupied
            .get(&key)
            .is_some_and(|existing| existing != java_key)
        {
            suffix = suffix.saturating_add(1);
            key = format!("{base}:{suffix}");
        }
        occupied.insert(key.clone(), java_key.clone());
        let value = property
            .value
            .java_string()
            .to_utf8()
            .unwrap_or_else(|| property.value.java_string().escaped());
        projected.insert(key, value);
    }
    projected
}

fn runtime_property_key(key: &JavaString) -> String {
    if let Some(value) = key.to_utf8()
        && !value.starts_with(WTF16_RUNTIME_KEY_PREFIX)
    {
        return value;
    }
    let mut encoded = String::from(WTF16_RUNTIME_KEY_PREFIX);
    for unit in key.units() {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{unit:04X}");
    }
    encoded
}

fn compile_local_plan(document: &SemanticDocument) -> Result<(EnginePlan, usize), RunError> {
    let tree = document.tree();
    // Opaque elements are retained by the JMX layer for lossless persistence,
    // but they are not executable native components.  Reject every enabled
    // opaque node before selecting groups so an unknown controller cannot be
    // mistaken for a transparent container.
    for id in tree.preorder_ids() {
        let node = tree.node(id).map_err(|error| RunError::Jmx {
            message: bounded(error.to_string(), MAX_DIAGNOSTIC_BYTES),
        })?;
        let class = node.value().test_class();
        if node.value().is_enabled()
            && class != "ThreadGroup"
            && (class == "SetupThreadGroup"
                || class == "PostThreadGroup"
                || class == "TearDownThreadGroup"
                || class == "TearDownOnShutdown"
                || class.ends_with("ThreadGroup"))
        {
            return Err(RunError::unsupported(
                "runtime.lifecycle-group",
                format!(
                    "enabled lifecycle group {class:?} is not implemented by the bounded native local adapter"
                ),
            ));
        }
        if node.value().is_enabled() && document.is_opaque(id) {
            return Err(RunError::unsupported(
                "jmx.opaque-element",
                format!(
                    "enabled element {:?} ({:?}) is outside the bounded native local adapter",
                    node.value().name(),
                    node.value().test_class()
                ),
            ));
        }
    }
    let mut plan = EnginePlan::new();
    let mut groups = 0_usize;
    for id in tree.preorder_ids() {
        let node = tree.node(id).map_err(|error| RunError::Jmx {
            message: bounded(error.to_string(), MAX_DIAGNOSTIC_BYTES),
        })?;
        if node.value().test_class() != "ThreadGroup" || !node.value().is_enabled() {
            continue;
        }
        let mut package_adapters = Vec::new();
        let controller = controller_for(document, id, &mut package_adapters)?;
        let element = node.value();
        let threads = positive_usize_property(element, "ThreadGroup.num_threads", 1)?;
        let packages =
            CompiledPackages::from_packages(package_adapters.drain(..)).map_err(|error| {
                RunError::Runtime {
                    code: "runtime.packages".to_owned(),
                    message: bounded(error.to_string(), MAX_DIAGNOSTIC_BYTES),
                }
            })?;
        let group = ThreadGroupPlan::new(
            id,
            element.name(),
            threads,
            ControllerProgram::compile(controller).map_err(controller_error)?,
            packages,
        )
        .map_err(|error| RunError::Runtime {
            code: error.code().to_owned(),
            message: bounded(error.to_string(), MAX_DIAGNOSTIC_BYTES),
        })?;
        plan.push_group(group).map_err(|error| RunError::Runtime {
            code: error.code().to_owned(),
            message: bounded(error.to_string(), MAX_DIAGNOSTIC_BYTES),
        })?;
        groups = groups.saturating_add(1);
    }
    if groups == 0 {
        return Err(RunError::Runtime {
            code: "runtime.no-thread-group".to_owned(),
            message: "the test plan contains no enabled ThreadGroup".to_owned(),
        });
    }
    Ok((plan, groups))
}

fn controller_for(
    document: &SemanticDocument,
    id: NodeId,
    packages: &mut Vec<SamplePackage>,
) -> Result<ControllerNode, RunError> {
    let tree = document.tree();
    let node = tree.node(id).map_err(|error| RunError::Jmx {
        message: bounded(error.to_string(), MAX_DIAGNOSTIC_BYTES),
    })?;
    let mut children = Vec::new();
    for child_id in node.children().iter().copied() {
        let child = tree.node(child_id).map_err(|error| RunError::Jmx {
            message: bounded(error.to_string(), MAX_DIAGNOSTIC_BYTES),
        })?;
        if !child.value().is_enabled() {
            continue;
        }
        let class = child.value().test_class();
        if class == "ResponseAssertion" {
            return Err(RunError::unsupported(
                "assertion.ResponseAssertion",
                "an enabled ResponseAssertion must be attached to a supported sampler",
            ));
        }
        if class == "DebugSampler" {
            let mut failed = false;
            for assertion_id in child.children().iter().copied() {
                let assertion = tree.node(assertion_id).map_err(|error| RunError::Jmx {
                    message: bounded(error.to_string(), MAX_DIAGNOSTIC_BYTES),
                })?;
                if assertion.value().test_class() == "ResponseAssertion"
                    && assertion.value().is_enabled()
                {
                    failed = true;
                    break;
                }
            }
            packages.push(SamplePackage::new(
                child_id,
                Arc::new(DebugSamplerAdapter {
                    label: child.value().name().to_owned(),
                    failed,
                }),
            ));
            children.push(ControllerNode::sample(child_id.get()));
            continue;
        }
        if class == "LoopController" {
            let loops = integer_property(child.value(), "LoopController.loops", 1)?;
            let count = LoopCount::from_jmeter(loops).map_err(|error| RunError::Runtime {
                code: error.code().to_owned(),
                message: bounded(error.to_string(), MAX_DIAGNOSTIC_BYTES),
            })?;
            let nested = controller_for(document, child_id, packages)?;
            children.push(match nested {
                ControllerNode::Simple { children, .. } => {
                    ControllerNode::loop_controller(child_id.get(), count, children)
                }
                other => ControllerNode::loop_controller(child_id.get(), count, vec![other]),
            });
            continue;
        }
        if matches!(class, "GenericController" | "TestPlan" | "ThreadGroup") {
            children.push(controller_for(document, child_id, packages)?);
            continue;
        }
        if child.children().is_empty() {
            return Err(RunError::unsupported(
                format!("sampler.{class}"),
                format!(
                    "sampler class {class:?} is outside the bounded native local adapter for profile jmeter-5.6.3"
                ),
            ));
        }
        return Err(RunError::unsupported(
            format!("controller.{class}"),
            format!("controller class {class:?} is outside the bounded native local adapter"),
        ));
    }
    Ok(ControllerNode::simple(id.get(), children))
}

fn controller_error(error: ControllerError) -> RunError {
    RunError::Runtime {
        code: "runtime.controller".to_owned(),
        message: bounded(error.to_string(), MAX_DIAGNOSTIC_BYTES),
    }
}

fn string_property(element: &TestElement, name: &str) -> Result<Option<String>, RunError> {
    let Some(value) = element.property(name) else {
        return Ok(None);
    };
    value
        .as_str()
        .map(|value| Some(value.to_owned()))
        .map_err(|error| RunError::Runtime {
            code: "runtime.invalid-property-type".to_owned(),
            message: bounded(
                format!("property {name} is not a string: {error}"),
                MAX_DIAGNOSTIC_BYTES,
            ),
        })
}

fn positive_usize_property(
    element: &TestElement,
    name: &str,
    default: usize,
) -> Result<usize, RunError> {
    let Some(value) = string_property(element, name)? else {
        return Ok(default);
    };
    value.parse::<usize>().map_err(|_| RunError::Runtime {
        code: "runtime.invalid-property".to_owned(),
        message: bounded(
            format!("property {name} must be an unsigned integer, got {value:?}"),
            MAX_DIAGNOSTIC_BYTES,
        ),
    })
}

fn integer_property(element: &TestElement, name: &str, default: i64) -> Result<i64, RunError> {
    let Some(value) = string_property(element, name)? else {
        return Ok(default);
    };
    value.parse::<i64>().map_err(|_| RunError::Runtime {
        code: "runtime.invalid-property".to_owned(),
        message: bounded(
            format!("property {name} must be an integer, got {value:?}"),
            MAX_DIAGNOSTIC_BYTES,
        ),
    })
}

struct DebugSamplerAdapter {
    label: String,
    failed: bool,
}

impl Sampler for DebugSamplerAdapter {
    fn sample<'a>(
        &'a self,
        _context: &'a mut jmeter_rs_runtime::SampleContext<'_>,
    ) -> ComponentFuture<'a, SamplerOutput> {
        Box::pin(std::future::ready(Ok({
            let mut result = SampleResult::new(self.label.clone());
            result.set_successful(!self.failed);
            if self.failed {
                result.set_failure_message(Some("response assertion failed".to_owned()));
            }
            SamplerOutput::result(result)
        })))
    }
}

fn engine_sample_counts(events: &[EngineEvent]) -> Result<(usize, usize), RunError> {
    let mut samples = 0_usize;
    let mut failed = 0_usize;
    for event in events {
        let EngineEvent::Sample {
            result: Some(result),
            ..
        } = event
        else {
            continue;
        };
        if samples >= MAX_OUTPUT_ENTRIES {
            return Err(RunError::Runtime {
                code: "runtime.output-limit".to_owned(),
                message: format!(
                    "sample output exceeds the bounded entry limit {MAX_OUTPUT_ENTRIES}"
                ),
            });
        }
        samples = samples.saturating_add(1);
        if result.success() == Some(false) {
            failed = failed.saturating_add(1);
        }
    }
    Ok((samples, failed))
}

#[cfg(test)]
fn report_directory(
    raw: Option<&str>,
    launch: &LaunchEnvironment,
    mode: ReportOutputMode,
) -> Result<PathBuf, RunError> {
    let path = resolve_checked_path(&launch.cwd, raw.unwrap_or(DEFAULT_REPORT_DIRECTORY))?;
    let root = fs::canonicalize(&launch.cwd).map_err(|error| RunError::io(&launch.cwd, error))?;
    match bound_metadata(&path, Some(&root)) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(RunError::Io {
                    path,
                    message: "report output directory must not be a symbolic link".to_owned(),
                });
            }
            if !metadata.is_dir() {
                return Err(RunError::Io {
                    path,
                    message: "report output path is not a directory".to_owned(),
                });
            }
            let directory = open_bound_directory(&path, Some(&root))
                .map_err(|error| RunError::io(&path, error))?;
            let canonical = directory.canonical().to_owned();
            if canonical == root || canonical.parent().is_none() {
                return Err(RunError::Io {
                    path,
                    message: "refusing to delete the working or filesystem root".to_owned(),
                });
            }
            let is_empty = fs::read_dir(directory.path())
                .map_err(|error| RunError::io(&path, error))?
                .next()
                .is_none();
            if !is_empty && matches!(mode, ReportOutputMode::CreateNew) {
                return Err(RunError::Io {
                    path,
                    message: "report output directory is not empty; use -f to replace it"
                        .to_owned(),
                });
            }
            if matches!(mode, ReportOutputMode::ReplaceExisting) {
                remove_report_directory(&path, &root)?;
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(RunError::io(&path, error)),
    }
    ensure_bound_directory(&path, &root).map_err(|error| RunError::io(&path, error))?;
    let metadata =
        bound_metadata(&path, Some(&root)).map_err(|error| RunError::io(&path, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(RunError::Io {
            path,
            message: "report output directory changed during creation".to_owned(),
        });
    }
    Ok(path)
}

#[cfg(test)]
fn remove_report_directory(path: &Path, root: &Path) -> Result<(), RunError> {
    let metadata = bound_metadata(path, Some(root)).map_err(|error| RunError::io(path, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(RunError::Io {
            path: path.to_owned(),
            message: "report output directory changed before deletion".to_owned(),
        });
    }
    let expected_identity = metadata_identity(&metadata);
    let parent = path.parent().unwrap_or(root);
    let parent_directory =
        open_bound_directory(parent, Some(root)).map_err(|error| RunError::io(parent, error))?;
    let source_name = path.file_name().ok_or_else(|| RunError::Io {
        path: path.to_owned(),
        message: "report output path has no directory name".to_owned(),
    })?;
    let bound_path = parent_directory.child(source_name);
    let canonical = fs::canonicalize(&bound_path).map_err(|error| RunError::io(path, error))?;
    if canonical == root || canonical.parent().is_none() || !canonical.starts_with(root) {
        return Err(RunError::Io {
            path: path.to_owned(),
            message: "refusing to delete a broad or out-of-root directory".to_owned(),
        });
    }
    // Move the already-validated directory entry to a fresh sibling before
    // deleting it.  The rename is atomic on the supported local filesystems:
    // if another actor swaps the user path for a symlink between validation
    // and deletion, only that symlink entry is moved and the target is never
    // recursively followed.  A bounded collision loop avoids replacement of
    // an attacker-created destination.
    let mut quarantine = None;
    for attempt in 0..8_u8 {
        let candidate = parent.join(format!(
            ".jmeter-rs-delete-{}-{attempt}",
            std::process::id()
        ));
        let candidate_name = candidate.file_name().ok_or_else(|| RunError::Io {
            path: candidate.clone(),
            message: "report deletion candidate has no name".to_owned(),
        })?;
        let candidate_bound = parent_directory.child(candidate_name);
        match fs::create_dir(&candidate_bound) {
            Ok(()) => match rename_bound(path, &candidate, root) {
                Ok(()) => {
                    quarantine = Some(candidate);
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    let _ = fs::remove_dir(&candidate_bound);
                    continue;
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(RunError::io(path, error)),
            },
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(RunError::io(&candidate, error)),
        }
    }
    let quarantine = quarantine.ok_or_else(|| RunError::Io {
        path: path.to_owned(),
        message: "could not reserve a safe report deletion name".to_owned(),
    })?;
    let quarantine_name = quarantine.file_name().ok_or_else(|| RunError::Io {
        path: quarantine.clone(),
        message: "report deletion quarantine has no name".to_owned(),
    })?;
    let quarantine_bound = parent_directory.child(quarantine_name);
    let moved = fs::symlink_metadata(&quarantine_bound)
        .map_err(|error| RunError::io(&quarantine, error))?;
    if moved.file_type().is_symlink() || !moved.is_dir() {
        return Err(RunError::Io {
            path: quarantine,
            message: "report deletion target changed to a non-directory".to_owned(),
        });
    }
    let quarantine_canonical =
        fs::canonicalize(&quarantine_bound).map_err(|error| RunError::io(&quarantine, error))?;
    if !quarantine_canonical.starts_with(root) {
        return Err(RunError::Io {
            path: quarantine,
            message: "report deletion target changed or escaped the allowed root".to_owned(),
        });
    }
    remove_bound_tree(&quarantine, root, expected_identity)
        .map_err(|error| RunError::io(&quarantine, error))
}

fn prepare_report_target(
    raw: Option<&str>,
    launch: &LaunchEnvironment,
    mode: ReportOutputMode,
) -> Result<PreparedReportTarget, RunError> {
    let path = resolve_checked_path(&launch.cwd, raw.unwrap_or(DEFAULT_REPORT_DIRECTORY))?;
    let root = fs::canonicalize(&launch.cwd).map_err(|error| RunError::io(&launch.cwd, error))?;
    let parent = path.parent().unwrap_or(root.as_path());
    // Open the parent before inspecting the target.  This keeps the target
    // lookup rooted and gives non-Linux callers the explicit descriptor-bound
    // capability error instead of a path-based approximation.
    let parent_directory =
        open_bound_directory(parent, Some(&root)).map_err(|error| RunError::io(parent, error))?;
    let existing_identity = match bound_metadata(&path, Some(&root)) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(RunError::Io {
                    path,
                    message: "report output path must be a regular directory".to_owned(),
                });
            }
            let directory = open_bound_directory(&path, Some(&root))
                .map_err(|error| RunError::io(&path, error))?;
            if directory.canonical() == root || directory.canonical().parent().is_none() {
                return Err(RunError::Io {
                    path,
                    message: "refusing to publish over the working or filesystem root".to_owned(),
                });
            }
            let is_empty = fs::read_dir(directory.path())
                .map_err(|error| RunError::io(&path, error))?
                .next()
                .is_none();
            if !is_empty && matches!(mode, ReportOutputMode::CreateNew) {
                return Err(RunError::Io {
                    path,
                    message: "report output directory is not empty; use -f to replace it"
                        .to_owned(),
                });
            }
            metadata_identity(&metadata)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(RunError::io(&path, error)),
    };
    // Keep this local binding alive through the preflight.  It also makes the
    // parent-bound lookup above explicit to reviewers and future platform
    // implementations.
    let _ = parent_directory;
    Ok(PreparedReportTarget {
        path,
        root,
        existing_identity,
        mode,
    })
}

fn write_report_dashboard(
    target: &PreparedReportTarget,
    input: &[u8],
    save_configuration: &SampleSaveConfiguration,
) -> Result<ReportStats, RunError> {
    let interval = ReportInterval::from_millis(0, 86_400_000).map_err(report_error)?;
    let config = DashboardConfig::new(interval).map_err(report_error)?;
    let mut dashboard = DashboardReport::new(config);
    let mut stats = ReportStats::default();

    match save_configuration.format() {
        JtlFormat::Csv => {
            let mut decoder =
                CsvDecoder::with_limits(input, save_configuration.clone(), jtl_limits())
                    .map_err(jtl_error)?;
            while let Some(event) = decoder.next_event().map_err(jtl_error)? {
                add_report_event(&mut dashboard, &mut stats, event)?;
            }
        }
        JtlFormat::Xml => {
            let configuration = XmlDecodeConfiguration::new()
                .with_sample_variables(save_configuration.sample_variables())
                .map_err(jtl_error)?;
            let mut decoder = XmlDecoder::with_configuration(input, jtl_limits(), configuration)
                .map_err(jtl_error)?;
            while let Some(event) = decoder.next_event().map_err(jtl_error)? {
                add_report_event(&mut dashboard, &mut stats, event)?;
            }
        }
    }

    let html_text = dashboard.to_html().map_err(report_error)?;
    let json_text = dashboard.to_json().map_err(report_error)?;
    if html_text.len() > MAX_REPORT_BYTES || json_text.len() > MAX_REPORT_BYTES {
        return Err(RunError::Report {
            code: "report.output_limit",
            message: "dashboard output exceeds the bounded report limit".to_owned(),
        });
    }
    publish_staged_dashboard(target, &html_text, &json_text)?;
    Ok(stats)
}

fn add_report_event(
    dashboard: &mut DashboardReport,
    stats: &mut ReportStats,
    event: SampleEvent,
) -> Result<(), RunError> {
    if stats.samples >= MAX_OUTPUT_ENTRIES {
        return Err(RunError::Report {
            code: "report.input_limit",
            message: "report input exceeds the bounded sample limit".to_owned(),
        });
    }
    if event.result().success() == Some(false) {
        stats.failed = stats.failed.saturating_add(1);
    }
    stats.samples = stats.samples.saturating_add(1);
    dashboard.add_event(&event).map_err(report_error)
}

fn reserve_sibling_directory(
    parent: &Path,
    root: &Path,
    prefix: &str,
) -> Result<PathBuf, RunError> {
    let parent_directory =
        open_bound_directory(parent, Some(root)).map_err(|error| RunError::io(parent, error))?;
    for attempt in 0..8_u8 {
        let candidate = parent.join(format!("{prefix}-{}-{attempt}", std::process::id()));
        let name = candidate.file_name().ok_or_else(|| RunError::Io {
            path: candidate.clone(),
            message: "staging candidate has no directory name".to_owned(),
        })?;
        match fs::create_dir(parent_directory.child(name)) {
            Ok(()) => return Ok(candidate),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(RunError::io(&candidate, error)),
        }
    }
    Err(RunError::Io {
        path: parent.to_owned(),
        message: "could not reserve a bounded staging name".to_owned(),
    })
}

fn write_staged_dashboard_file(path: &Path, content: &str, root: &Path) -> Result<(), RunError> {
    let mut file = open_output(path, OutputOpenMode::CreateNew, root)?;
    file.write_all(content.as_bytes())
        .map_err(|error| RunError::io(path, error))?;
    file.flush().map_err(|error| RunError::io(path, error))
}

fn cleanup_staged_dashboard(
    stage: &Path,
    root: &Path,
    identity: Option<(u64, u64)>,
    primary: RunError,
) -> RunError {
    match remove_bound_tree(stage, root, identity) {
        Ok(()) => primary,
        Err(cleanup) => RunError::Runtime {
            code: "report.staging-cleanup".to_owned(),
            message: bounded(
                format!("{primary}; staging cleanup failed: {cleanup}"),
                MAX_DIAGNOSTIC_BYTES,
            ),
        },
    }
}

fn cleanup_bound_report_directory(
    path: &Path,
    root: &Path,
    identity: Option<(u64, u64)>,
    primary: RunError,
) -> RunError {
    match remove_bound_tree(path, root, identity) {
        Ok(()) => primary,
        Err(cleanup) => RunError::Runtime {
            code: "report.publication-cleanup".to_owned(),
            message: bounded(
                format!("{primary}; publication cleanup failed: {cleanup}"),
                MAX_DIAGNOSTIC_BYTES,
            ),
        },
    }
}

fn rollback_report_quarantine(
    quarantine: &Path,
    target: &Path,
    root: &Path,
    primary: RunError,
) -> RunError {
    match rename_bound(quarantine, target, root) {
        Ok(()) => primary,
        Err(restore) => RunError::Runtime {
            code: "report.publication-rollback".to_owned(),
            message: bounded(
                format!("{primary}; restoring previous output failed: {restore}"),
                MAX_DIAGNOSTIC_BYTES,
            ),
        },
    }
}

fn publish_staged_dashboard(
    target: &PreparedReportTarget,
    html: &str,
    json: &str,
) -> Result<(), RunError> {
    let parent = target.path.parent().unwrap_or(target.root.as_path());
    let stage = reserve_sibling_directory(parent, &target.root, ".jmeter-rs-dashboard-stage")?;
    let stage_metadata = match bound_metadata(&stage, Some(&target.root)) {
        Ok(metadata) => metadata,
        Err(error) => {
            return Err(cleanup_staged_dashboard(
                &stage,
                &target.root,
                None,
                RunError::io(&stage, error),
            ));
        }
    };
    let stage_identity = metadata_identity(&stage_metadata);
    if let Err(error) = write_staged_dashboard_file(&stage.join("index.html"), html, &target.root) {
        return Err(cleanup_staged_dashboard(
            &stage,
            &target.root,
            stage_identity,
            error,
        ));
    }
    if let Err(error) = write_staged_dashboard_file(&stage.join("data.json"), json, &target.root) {
        return Err(cleanup_staged_dashboard(
            &stage,
            &target.root,
            stage_identity,
            error,
        ));
    }

    let mode_name = match target.mode {
        ReportOutputMode::CreateNew => "create-new",
        ReportOutputMode::ReplaceExisting => "replace-existing",
    };
    let current = match bound_metadata(&target.path, Some(&target.root)) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(cleanup_staged_dashboard(
                    &stage,
                    &target.root,
                    stage_identity,
                    RunError::Io {
                        path: target.path.clone(),
                        message: format!("report target changed during {mode_name} publication"),
                    },
                ));
            }
            metadata_identity(&metadata)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(cleanup_staged_dashboard(
                &stage,
                &target.root,
                stage_identity,
                RunError::io(&target.path, error),
            ));
        }
    };
    if current != target.existing_identity {
        return Err(cleanup_staged_dashboard(
            &stage,
            &target.root,
            stage_identity,
            RunError::Io {
                path: target.path.clone(),
                message: format!("report target changed during {mode_name} publication"),
            },
        ));
    }

    let quarantine = if target.existing_identity.is_some() {
        let quarantine =
            match reserve_sibling_directory(parent, &target.root, ".jmeter-rs-dashboard-old") {
                Ok(quarantine) => quarantine,
                Err(error) => {
                    return Err(cleanup_staged_dashboard(
                        &stage,
                        &target.root,
                        stage_identity,
                        error,
                    ));
                }
            };
        let quarantine_metadata = match bound_metadata(&quarantine, Some(&target.root)) {
            Ok(metadata) => metadata,
            Err(error) => {
                return Err(cleanup_staged_dashboard(
                    &stage,
                    &target.root,
                    stage_identity,
                    RunError::io(&quarantine, error),
                ));
            }
        };
        let quarantine_identity = metadata_identity(&quarantine_metadata);
        if let Err(error) = rename_bound(&target.path, &quarantine, &target.root) {
            let primary = cleanup_bound_report_directory(
                &quarantine,
                &target.root,
                quarantine_identity,
                RunError::io(&target.path, error),
            );
            return Err(cleanup_staged_dashboard(
                &stage,
                &target.root,
                stage_identity,
                primary,
            ));
        }
        let moved = match bound_metadata(&quarantine, Some(&target.root)) {
            Ok(metadata) => metadata,
            Err(error) => {
                let primary = rollback_report_quarantine(
                    &quarantine,
                    &target.path,
                    &target.root,
                    RunError::io(&quarantine, error),
                );
                return Err(cleanup_staged_dashboard(
                    &stage,
                    &target.root,
                    stage_identity,
                    primary,
                ));
            }
        };
        if moved.file_type().is_symlink()
            || !moved.is_dir()
            || metadata_identity(&moved) != target.existing_identity
        {
            let primary = rollback_report_quarantine(
                &quarantine,
                &target.path,
                &target.root,
                RunError::Io {
                    path: target.path.clone(),
                    message: "report target changed before quarantine publication".to_owned(),
                },
            );
            return Err(cleanup_staged_dashboard(
                &stage,
                &target.root,
                stage_identity,
                primary,
            ));
        }
        Some(quarantine)
    } else {
        None
    };

    if let Err(error) = rename_bound(&stage, &target.path, &target.root) {
        let restore_error = quarantine
            .as_ref()
            .and_then(|old| rename_bound(old, &target.path, &target.root).err());
        let primary = match restore_error {
            Some(restore) => RunError::Runtime {
                code: "report.publication-rollback".to_owned(),
                message: bounded(
                    format!(
                        "dashboard publication failed: {error}; restoring previous output failed: {restore}"
                    ),
                    MAX_DIAGNOSTIC_BYTES,
                ),
            },
            None => RunError::io(&target.path, error),
        };
        return Err(cleanup_staged_dashboard(
            &stage,
            &target.root,
            stage_identity,
            primary,
        ));
    }

    if let Some(quarantine) = quarantine
        && let Err(error) = remove_bound_tree(&quarantine, &target.root, target.existing_identity)
    {
        return Err(RunError::Runtime {
            code: "report.publication-cleanup".to_owned(),
            message: bounded(
                format!("dashboard published; previous output cleanup failed: {error}"),
                MAX_DIAGNOSTIC_BYTES,
            ),
        });
    }
    Ok(())
}

fn report_error(error: ReportError) -> RunError {
    RunError::Report {
        code: error.stable_code(),
        message: bounded(error.to_string(), MAX_DIAGNOSTIC_BYTES),
    }
}

fn jtl_error(error: JtlError) -> RunError {
    let message = bounded(error.to_string(), MAX_DIAGNOSTIC_BYTES);
    if error.stable_code() == "results.jtl.unsupported" {
        RunError::unsupported("jtl-report-input", message)
    } else {
        RunError::Report {
            code: error.stable_code(),
            message,
        }
    }
}

fn resolve_path_argument(
    argument: &PathArgument,
    suffix: &str,
    launch: &LaunchEnvironment,
) -> Result<PathBuf, RunError> {
    if matches!(argument.kind, PathKind::Last) {
        let recent = launch.recent_jmx.as_deref().ok_or_else(|| {
            RunError::unsupported(
                "recent-project",
                "LAST requires an explicit recent-project path for the bounded native local adapter in profile jmeter-5.6.3",
            )
        })?;
        let resolved = argument
            .resolve_last_against(recent, suffix)
            .ok_or_else(|| {
                RunError::unsupported(
                    "recent-project",
                    "recent plan is not a JMX file for the bounded native local adapter in profile jmeter-5.6.3",
                )
            })?;
        let resolved = resolved.to_str().ok_or_else(|| {
            RunError::unsupported(
                "recent-project",
                "recent plan path is not valid UTF-8 for the bounded native local adapter in profile jmeter-5.6.3",
            )
        })?;
        return resolve_checked_path(&launch.cwd, resolved);
    }
    resolve_checked_path(&launch.cwd, argument.as_str())
}

fn resolve_checked_path(root: &Path, raw: &str) -> Result<PathBuf, RunError> {
    let candidate = if Path::new(raw).is_absolute() {
        PathBuf::from(raw)
    } else {
        root.join(raw)
    };
    if candidate.as_os_str().len() > 16 * 1024 {
        return Err(RunError::Io {
            path: candidate,
            message: "path exceeds the bounded CLI path limit".to_owned(),
        });
    }
    let root = fs::canonicalize(root).map_err(|error| RunError::io(root, error))?;
    if contains_symlink(&candidate).map_err(|error| RunError::io(&candidate, error))? {
        return Err(RunError::Io {
            path: candidate,
            message: "symbolic links are denied by the CLI filesystem policy".to_owned(),
        });
    }
    let check = match fs::symlink_metadata(&candidate) {
        Ok(_) => fs::canonicalize(&candidate).map_err(|error| RunError::io(&candidate, error))?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = candidate.parent().unwrap_or(root.as_path());
            fs::canonicalize(parent).map_err(|error| RunError::io(parent, error))?
        }
        Err(error) => return Err(RunError::io(&candidate, error)),
    };
    if check != root && !check.starts_with(root.join("")) {
        return Err(RunError::Io {
            path: candidate,
            message: format!("path is outside allowed root {}", root.display()),
        });
    }
    Ok(candidate)
}

fn open_output(path: &Path, mode: OutputOpenMode, root: &Path) -> Result<File, RunError> {
    if matches!(mode, OutputOpenMode::ReplaceExisting) {
        match bound_metadata(path, Some(root)) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(RunError::Io {
                    path: path.to_owned(),
                    message: "refusing to replace a symbolic-link output".to_owned(),
                });
            }
            Ok(metadata) if !metadata.is_file() => {
                return Err(RunError::Io {
                    path: path.to_owned(),
                    message: "refusing to replace a non-file output".to_owned(),
                });
            }
            Ok(_) => remove_bound_file(path, root).map_err(|error| RunError::io(path, error))?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(RunError::io(path, error)),
        }
    }
    open_bound_create_new(path, root).map_err(|error| RunError::io(path, error))
}

fn contains_symlink(path: &Path) -> io::Result<bool> {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(Path::new(std::path::MAIN_SEPARATOR_STR)),
            Component::CurDir => {}
            Component::ParentDir => current.push(".."),
            Component::Normal(value) => current.push(value),
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Ok(true),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        }
    }
    Ok(false)
}

struct RunLogger {
    path: Option<PathBuf>,
    root: PathBuf,
    lines: Vec<String>,
    truncated: bool,
}

impl RunLogger {
    fn initialize(
        invocation: &CliInvocation,
        resolved: &crate::ResolvedConfig,
        launch: &LaunchEnvironment,
    ) -> Result<Self, RunError> {
        if invocation.options.jmeterlogconf.is_some() {
            return Err(RunError::unsupported(
                "logging.config",
                "-i/--jmeterlogconf is not applied by the bounded native adapter for profile jmeter-5.6.3",
            ));
        }
        if !resolved.logging.directives.is_empty() {
            return Err(RunError::unsupported(
                "logging.level",
                "-L/--loglevel is not applied by the bounded native adapter for profile jmeter-5.6.3",
            ));
        }
        let raw = invocation
            .options
            .jmeterlogfile
            .as_ref()
            .map(|path| path.as_str())
            .unwrap_or(DEFAULT_JMETER_LOG);
        let raw = if matches!(
            invocation
                .options
                .jmeterlogfile
                .as_ref()
                .map(|path| path.kind),
            Some(PathKind::LastLiteral)
        ) {
            raw.to_owned()
        } else {
            expand_date_filename_in_timezone(raw, launch.now_millis, &launch.timezone)?
        };
        let path = resolve_checked_path(&launch.cwd, &raw)?;
        let mut logger = Self {
            path: Some(path),
            root: fs::canonicalize(&launch.cwd)
                .map_err(|error| RunError::io(&launch.cwd, error))?,
            lines: Vec::new(),
            truncated: false,
        };
        logger.info(&format!(
            "Apache JMeter {} locale={} timezone={}",
            crate::JMETER_COMPATIBILITY_VERSION,
            launch.locale,
            launch.timezone,
        ));
        for warning in &resolved.warnings {
            logger.warn(&format!("{}: {warning}", warning.code()));
        }
        for directive in &resolved.logging.directives {
            let category = directive.category.as_deref().map_or_else(
                || "root".to_owned(),
                |value| {
                    if value.starts_with("jmeter") || value.starts_with("jorphan") {
                        format!("org.apache.{value}")
                    } else {
                        value.to_owned()
                    }
                },
            );
            if !valid_level(&directive.level) {
                logger.warn(&format!(
                    "invalid log level category={category} level=<redacted>"
                ));
            } else {
                logger.info(&format!(
                    "log-level category={category} level={}",
                    directive.level
                ));
            }
        }
        Ok(logger)
    }

    fn info(&mut self, message: &str) {
        self.push("INFO", message);
    }

    fn warn(&mut self, message: &str) {
        self.push("WARN", message);
    }

    fn push(&mut self, category: &str, message: &str) {
        if self.lines.len() >= 4096 {
            self.truncated = true;
            return;
        }
        let line = format!("{category} {message}");
        let total: usize = self.lines.iter().map(String::len).sum();
        if total.saturating_add(line.len()).saturating_add(1) <= MAX_LOG_BYTES {
            self.lines.push(line);
        } else {
            self.truncated = true;
        }
    }

    fn finish(&self) -> Result<(), RunError> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        if self.truncated {
            return Err(RunError::Runtime {
                code: "execution.logging-limit".to_owned(),
                message: "run log diagnostics exceeded the bounded line or byte limit".to_owned(),
            });
        }
        let pending_bytes = self.lines.iter().try_fold(0_u64, |total, line| {
            let line_bytes = u64::try_from(line.len().saturating_add(1)).ok()?;
            total.checked_add(line_bytes)
        });
        let Some(pending_bytes) = pending_bytes else {
            return Err(RunError::Io {
                path: path.clone(),
                message: "run log size calculation overflowed".to_owned(),
            });
        };
        let max_bytes = match u64::try_from(MAX_LOG_BYTES) {
            Ok(value) => value,
            Err(_) => {
                return Err(RunError::Io {
                    path: path.clone(),
                    message: "run log size bound is not representable".to_owned(),
                });
            }
        };
        let mut file =
            open_bound_append(path, &self.root).map_err(|error| RunError::io(path, error))?;
        let metadata = file.metadata().map_err(|error| RunError::io(path, error))?;
        if !metadata.is_file() {
            return Err(RunError::Io {
                path: path.clone(),
                message: "refusing to append to a non-file log".to_owned(),
            });
        }
        let existing_bytes = metadata.len();
        if existing_bytes > max_bytes || pending_bytes > max_bytes.saturating_sub(existing_bytes) {
            return Err(RunError::Io {
                path: path.clone(),
                message: "run log exceeds the bounded output limit".to_owned(),
            });
        }
        for line in &self.lines {
            writeln!(file, "{line}").map_err(|error| RunError::io(path, error))?;
        }
        file.flush().map_err(|error| RunError::io(path, error))
    }
}

fn valid_level(value: &str) -> bool {
    matches!(
        value.to_ascii_uppercase().as_str(),
        "OFF" | "FATAL" | "ERROR" | "WARN" | "WARNING" | "INFO" | "DEBUG" | "TRACE" | "ALL"
    )
}

#[cfg(test)]
fn expand_date_filename(value: &str, millis: i64) -> String {
    expand_date_filename_in_timezone(value, millis, "UTC").expect("UTC is supported")
}

fn expand_date_filename_in_timezone(
    value: &str,
    millis: i64,
    timezone: &str,
) -> Result<String, RunError> {
    let offset = timezone_offset_seconds(timezone)?;
    let mut output = String::new();
    let mut rest = value;
    while let Some(start) = rest.find('\'') {
        output.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let Some(end) = after.find('\'') else {
            return Ok(value.to_owned());
        };
        output.push_str(&format_date_pattern(
            &after[..end],
            millis.saturating_add(offset.saturating_mul(1_000)),
        ));
        rest = &after[end + 1..];
    }
    output.push_str(rest);
    Ok(output)
}

fn timezone_offset_seconds(value: &str) -> Result<i64, RunError> {
    let normalized = value.trim();
    if normalized.eq_ignore_ascii_case("utc") || normalized.eq_ignore_ascii_case("gmt") {
        return Ok(0);
    }

    // Only fixed offsets are implemented at this application boundary.  A
    // named zone requires a timezone database/capability; it must never be
    // silently treated as UTC.  Compare the ASCII prefix before slicing so a
    // malformed/non-ASCII value cannot panic at a byte boundary.
    let offset = normalized
        .as_bytes()
        .get(..3)
        .filter(|prefix| prefix.eq_ignore_ascii_case(b"UTC") || prefix.eq_ignore_ascii_case(b"GMT"))
        .map_or(normalized, |_| &normalized[3..]);
    let sign = match offset.as_bytes().first().copied() {
        Some(b'+') => 1_i64,
        Some(b'-') => -1_i64,
        _ => return Err(unsupported_timezone()),
    };
    let digits = &offset[1..];
    let (hours, minutes) = digits
        .split_once(':')
        .map_or((digits, "0"), |(h, m)| (h, m));
    let Ok(hours) = hours.parse::<u8>() else {
        return Err(unsupported_timezone());
    };
    let Ok(minutes) = minutes.parse::<u8>() else {
        return Err(unsupported_timezone());
    };
    if hours > 23 || minutes > 59 {
        return Err(unsupported_timezone());
    }
    let seconds = i64::from(hours) * 3_600 + i64::from(minutes) * 60;
    Ok(sign * seconds)
}

fn unsupported_timezone() -> RunError {
    RunError::unsupported(
        "timezone",
        "timezone is unsupported or malformed; value=<redacted>",
    )
}

fn format_date_pattern(pattern: &str, millis: i64) -> String {
    let seconds = millis.div_euclid(1_000);
    let days = seconds.div_euclid(86_400);
    let day_seconds = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = day_seconds / 3_600;
    let minute = (day_seconds % 3_600) / 60;
    let second = day_seconds % 60;
    let milli = millis.rem_euclid(1_000);
    let mut output = String::new();
    let mut index = 0;
    while index < pattern.len() {
        let rest = &pattern[index..];
        let token = ["yyyy", "yy", "MM", "dd", "HH", "mm", "ss", "SSS"]
            .iter()
            .find(|token| rest.starts_with(*token));
        if let Some(token) = token {
            let rendered = match *token {
                "yyyy" => format!("{year:04}"),
                "yy" => format!("{:02}", year.rem_euclid(100)),
                "MM" => format!("{month:02}"),
                "dd" => format!("{day:02}"),
                "HH" => format!("{hour:02}"),
                "mm" => format!("{minute:02}"),
                "ss" => format!("{second:02}"),
                "SSS" => format!("{milli:03}"),
                _ => String::new(),
            };
            output.push_str(&rendered);
            index += token.len();
        } else if let Some(character) = rest.chars().next() {
            output.push(character);
            index += character.len_utf8();
        } else {
            break;
        }
    }
    output
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 }.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096).div_euclid(365);
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2).div_euclid(153);
    let day = doy - (153 * mp + 2).div_euclid(5) + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = y + i64::from(month <= 2);
    (year, month, day)
}

fn current_millis() -> Result<i64, RunError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| RunError::Runtime {
            code: "environment.clock".to_owned(),
            message: bounded(error.to_string(), MAX_DIAGNOSTIC_BYTES),
        })?;
    i64::try_from(duration.as_millis()).map_err(|error| RunError::Runtime {
        code: "environment.clock".to_owned(),
        message: bounded(error.to_string(), MAX_DIAGNOSTIC_BYTES),
    })
}

fn bounded(mut value: String, limit: usize) -> String {
    if value.len() <= limit {
        return value;
    }
    let mut end = limit;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
    value
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = Box::pin(future);
    loop {
        match Pin::new(&mut future).poll(&mut context) {
            Poll::Ready(value) => return value,
            Poll::Pending => std::hint::spin_loop(),
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "filesystem fixtures use assertion-context setup"
)]
mod tests {
    use super::*;
    use jmeter_rs_runtime::ExecutionContext;

    #[test]
    fn environment_view_keeps_only_the_explicit_allowlist() {
        let environment = EnvironmentView::from_pairs([
            ("TZ", "UTC"),
            ("JMETER_HOME", "/opt/jmeter"),
            ("PATH", "/should/not/be-visible"),
            ("SECRET_TOKEN", "hidden"),
        ]);
        assert_eq!(environment.get("TZ"), Some("UTC"));
        assert_eq!(environment.get("JMETER_HOME"), Some("/opt/jmeter"));
        assert_eq!(environment.get("PATH"), None);
        assert_eq!(environment.get("SECRET_TOKEN"), None);
        assert_eq!(environment.get("JAVA_HOME"), None);
        assert_eq!(environment.get("CLASSPATH"), None);
    }

    #[test]
    fn run_categories_map_sample_failures_and_remote_failures_distinctly() {
        assert_eq!(RunCategory::Normal.exit_class(), ExitClass::Success);
        assert_eq!(
            RunCategory::SampleFailure.exit_class(),
            ExitClass::SampleFailure
        );
        assert_eq!(RunCategory::Fatal.exit_class(), ExitClass::Fatal);
        assert_eq!(RunCategory::Remote.exit_class(), ExitClass::RemoteFailure);
        assert_eq!(RunCategory::SampleFailure.exit_class().exit_code(), 0);
        assert_eq!(RunCategory::Remote.exit_class().exit_code(), 1);
    }

    #[test]
    fn report_errors_keep_the_report_crate_stable_code_and_fatal_mapping() {
        let error = report_error(ReportError::Serialization);
        assert_eq!(error.code(), "report.serialization");
        assert_eq!(error.exit_class(), ExitClass::Fatal);
        assert!(error.to_string().contains("report.serialization"));
    }

    #[test]
    fn save_configuration_retains_ordered_provenance_unknowns_empty_and_remove() {
        let mut plan = ConfigPlan::new();
        plan.push_assignment(
            ConfigNamespace::Jmeter,
            "jmeter.save.saveservice.label",
            "false",
            10,
        );
        plan.push_assignment(
            ConfigNamespace::Jmeter,
            "jmeter.save.saveservice.label",
            "true",
            11,
        );
        plan.push_assignment(
            ConfigNamespace::Jmeter,
            "jmeter.save.saveservice.sample_variables",
            "",
            12,
        );
        plan.push_assignment(
            ConfigNamespace::Jmeter,
            "jmeter.save.saveservice.future_switch",
            "opaque",
            13,
        );
        plan.push_assignment_or_remove(
            ConfigNamespace::Jmeter,
            "jmeter.save.saveservice.response_message",
            "",
            14,
        );
        let resolved = ConfigLoader::new()
            .resolve(&plan)
            .expect("inline save properties resolve");

        let configuration = save_configuration(&resolved, SaveWireFormat::Csv)
            .expect("save properties resolve through the results resolver");
        let label = configuration
            ._resolution
            .field(&SaveField::known(SaveFieldId::Label))
            .expect("label resolution");
        assert_eq!(label.operations().len(), 2);
        assert_eq!(label.java_value(), Some(&JavaValue::Boolean(true)));
        assert_eq!(
            label.provenance().map(|provenance| provenance.source()),
            Some(SaveConfigSource::RunProperties { ordinal: 11 })
        );
        assert!(configuration.wire().save_label());

        let sample_variables = configuration
            ._resolution
            .field(&SaveField::known(SaveFieldId::SampleVariables))
            .expect("sample variable resolution");
        assert_eq!(
            sample_variables.final_presence(),
            Some(jmeter_rs_results::FieldPresence::PresentEmpty)
        );

        let unknown = configuration
            ._resolution
            .unresolved_fields()
            .find(|field| {
                field.field().unknown_name() == Some("jmeter.save.saveservice.future_switch")
            })
            .expect("unknown save property is retained");
        assert_eq!(unknown.operations().len(), 1);

        let removed = configuration
            ._resolution
            .field(&SaveField::known(SaveFieldId::ResponseMessage))
            .expect("removed response-message resolution");
        assert_eq!(
            removed.final_presence(),
            Some(jmeter_rs_results::FieldPresence::Absent)
        );
        assert_eq!(
            removed
                .provenance()
                .map(|provenance| provenance.operation()),
            Some(SaveOperationKind::Remove)
        );
    }

    #[test]
    fn runtime_property_projection_keeps_exact_surrogate_keys_distinct() {
        let properties = ConfigLoader::new()
            .parse_bytes(
                b"\\uD800=surrogate\n\\\\uD800=literal\n",
                crate::config::ConfigSource::ExplicitPrimary {
                    path: PathBuf::from("collision.properties"),
                },
            )
            .expect("properties decode");
        let surrogate = JavaString::from_units(vec![0xD800]);
        let literal = JavaString::from_str(r"\uD800");
        let projected = runtime_properties(&properties);
        let surrogate_key = runtime_property_key(&surrogate);
        let literal_key = runtime_property_key(&literal);
        assert_ne!(surrogate_key, literal_key);
        assert_eq!(
            projected.get(&surrogate_key).map(String::as_str),
            Some("surrogate")
        );
        assert_eq!(
            projected.get(&literal_key).map(String::as_str),
            Some("literal")
        );
        assert_eq!(projected.len(), 2);
    }

    #[test]
    fn resolved_cli_properties_are_run_shared_across_group_contexts() {
        let base = std::env::temp_dir().join(format!(
            "jmeter-rs-runtime-properties-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).expect("property fixture directory");
        fs::write(
            base.join("primary.properties"),
            b"shared=primary\nprimary.only=yes\n",
        )
        .expect("primary properties");
        fs::write(base.join("extra.properties"), b"shared=extra\nq.only=yes\n")
            .expect("additional properties");
        let invocation = crate::parse([
            "-p",
            "primary.properties",
            "-q",
            "extra.properties",
            "-J",
            "shared=cli",
            "-n",
            "-t",
            "plan.jmx",
        ])
        .expect("CLI invocation");
        let plan = ConfigPlan::from_invocation(&invocation).with_base_dir(&base);
        let resolved = ConfigLoader::rooted(&base)
            .resolve(&plan)
            .expect("resolved CLI properties");
        assert_eq!(resolved.jmeter.get_value("shared"), Some("cli"));
        assert_eq!(resolved.jmeter.get_value("q.only"), Some("yes"));

        let properties = Arc::new(RwLock::new(runtime_properties(&resolved.jmeter)));
        let root = ExecutionContext::with_capabilities(
            RuntimeCapabilities::default().with_properties(Arc::clone(&properties)),
        );
        let functions = jmeter_rs_expr::BuiltinFunctions::new();
        let first_group = root.clone_for_user();
        let second_group = root.clone_for_user();
        assert_eq!(first_group.property("shared"), Some("cli".to_owned()));
        assert_eq!(second_group.property("shared"), Some("cli".to_owned()));
        assert_eq!(first_group.property("q.only"), Some("yes".to_owned()));
        assert_eq!(
            first_group
                .evaluate_expression("${__P(shared)}", &functions)
                .expect("first group expression property"),
            "cli"
        );
        assert_eq!(
            second_group
                .evaluate_expression("${__P(shared)}", &functions)
                .expect("second group expression property"),
            "cli"
        );
        first_group.set_property("run.shared", "updated");
        assert_eq!(
            second_group.property("run.shared"),
            Some("updated".to_owned())
        );
        fs::remove_dir_all(&base).expect("property fixture cleanup");
    }

    #[test]
    fn enabled_opaque_plan_elements_fail_before_native_compilation() {
        let source = String::from_utf8_lossy(include_bytes!(
            "../../../compat/fixtures/jmeter-5.6.3/cli-matrix/inputs/cli-plan.jmx"
        ))
        .replace("DebugSampler", "UnknownController");
        let document = SemanticDocument::from_bytes(source.as_bytes()).expect("fixture parses");
        let error = compile_local_plan(&document).expect_err("opaque execution must fail closed");
        assert_eq!(error.code(), "capability.unavailable");
        assert!(error.to_string().contains("jmx.opaque-element"));
    }

    #[test]
    fn enabled_lifecycle_groups_fail_before_native_compilation() {
        let source = String::from_utf8_lossy(include_bytes!(
            "../../../compat/fixtures/jmeter-5.6.3/cli-matrix/inputs/cli-plan.jmx"
        ))
        .replacen(
            "testclass=\"ThreadGroup\"",
            "testclass=\"SetupThreadGroup\"",
            1,
        );
        let document = SemanticDocument::from_bytes(source.as_bytes()).expect("fixture parses");
        let error =
            compile_local_plan(&document).expect_err("lifecycle groups must not be skipped");
        assert_eq!(error.code(), "capability.unavailable");
        assert!(error.to_string().contains("runtime.lifecycle-group"));
    }

    #[test]
    fn unattached_assertions_fail_instead_of_becoming_transparent_containers() {
        let source = String::from_utf8_lossy(include_bytes!(
            "../../../compat/fixtures/jmeter-5.6.3/cli-matrix/inputs/cli-plan.jmx"
        ))
        .replace(
            "<DebugSampler guiclass=\"TestBeanGUI\" testclass=\"DebugSampler\"",
            "<ResponseAssertion guiclass=\"TestBeanGUI\" testclass=\"ResponseAssertion\"",
        )
        .replace("</DebugSampler>", "</ResponseAssertion>");
        let document = SemanticDocument::from_bytes(source.as_bytes()).expect("fixture parses");
        let error = compile_local_plan(&document)
            .expect_err("an unattached assertion must not be silently skipped");
        assert_eq!(error.code(), "capability.unavailable");
        assert!(error.to_string().contains("assertion.ResponseAssertion"));
    }

    #[test]
    fn supported_fixture_compiles_every_enabled_main_group() {
        let source =
            include_bytes!("../../../compat/fixtures/jmeter-5.6.3/cli-matrix/inputs/cli-plan.jmx");
        let document = SemanticDocument::from_bytes(source).expect("fixture parses");
        let (plan, packages) = compile_local_plan(&document).expect("native fixture compiles");
        assert_eq!(plan.groups.len(), 1);
        assert_eq!(packages, 1);
    }

    #[test]
    fn date_pattern_expansion_is_deterministic() {
        assert_eq!(
            expand_date_filename("jmeter-'yyyyMMdd-HHmmss'.log", 0),
            "jmeter-19700101-000000.log"
        );
        assert_eq!(
            expand_date_filename("LAST.log", 0),
            "LAST.log",
            "a literal log path must not be treated as a date pattern"
        );
        assert_eq!(
            expand_date_filename_in_timezone("run-'yyyyMMdd-HHmmss'.log", 0, "UTC+02:00")
                .expect("fixed UTC offset is supported"),
            "run-19700101-020000.log"
        );
    }

    #[test]
    fn timezone_offsets_keep_supported_fixed_forms() {
        assert_eq!(timezone_offset_seconds("UTC"), Ok(0));
        assert_eq!(timezone_offset_seconds("gmt"), Ok(0));
        assert_eq!(timezone_offset_seconds("UTC+02:00"), Ok(7_200));
        assert_eq!(timezone_offset_seconds("gmt-05:30"), Ok(-19_800));
        assert_eq!(timezone_offset_seconds("+01:15"), Ok(4_500));
    }

    #[test]
    fn timezone_named_malformed_and_overflow_values_fail_without_fallback() {
        for value in [
            "America/Los_Angeles",
            "UTC+",
            "UTC+01:60",
            "UTC+24:00",
            "UTC+999999999999999999999999999999999999999999999999999999",
        ] {
            let error = timezone_offset_seconds(value)
                .expect_err("unsupported timezone input must not fall back to UTC");
            assert_eq!(error.code(), "capability.unavailable");
            assert_eq!(error.exit_class(), ExitClass::UnsupportedCapability);
        }
    }

    #[test]
    fn timezone_errors_redact_the_requested_value() {
        let value = "America/Secret_Valley";
        let error = timezone_offset_seconds(value).expect_err("named timezone must fail closed");
        assert!(error.to_string().contains("<redacted>"));
        assert!(format!("{error:?}").contains("<redacted>"));
        assert!(!error.to_string().contains(value));
        assert!(!format!("{error:?}").contains(value));

        let expansion = expand_date_filename_in_timezone("run-'yyyy'.log", 0, value)
            .expect_err("date expansion must preserve the typed timezone error");
        assert_eq!(expansion.code(), "capability.unavailable");
        assert!(!expansion.to_string().contains(value));
    }

    #[test]
    fn checked_paths_reject_escape_and_bound_long_input() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let outside = resolve_checked_path(root, "../").expect_err("parent escape must fail");
        assert!(matches!(outside, RunError::Io { .. }));

        let long = "x".repeat(16 * 1024 + 1);
        let bounded = resolve_checked_path(root, &long).expect_err("long path must be bounded");
        assert!(matches!(bounded, RunError::Io { .. }));
    }

    #[test]
    fn invalid_log_levels_are_rejected_without_echoing_the_value() {
        assert!(valid_level("DEBUG"));
        assert!(valid_level("warning"));
        assert!(!valid_level("definitely-not-a-level"));
    }

    #[test]
    fn unapplied_logging_options_are_typed_capability_failures() {
        for (arguments, code) in [
            (
                ["-n", "-t", "plan.jmx", "-i", "logging.properties"],
                "capability.unavailable",
            ),
            (
                ["-n", "-t", "plan.jmx", "-L", "root=DEBUG"],
                "capability.unavailable",
            ),
        ] {
            let invocation = crate::parse(arguments).expect("logging option parses");
            let resolved = ConfigLoader::new()
                .resolve(&ConfigPlan::from_invocation(&invocation))
                .expect("inline logging plan resolves");
            let error = match RunLogger::initialize(
                &invocation,
                &resolved,
                &LaunchEnvironment::new(env!("CARGO_MANIFEST_DIR")),
            ) {
                Ok(_) => panic!("unapplied logging option must not report success"),
                Err(error) => error,
            };
            assert_eq!(error.code(), code);
        }
    }

    #[test]
    fn result_output_waits_for_the_run_owned_router() {
        let error = result_router_boundary();
        assert_eq!(error.code(), "capability.unavailable");
        assert!(error.to_string().contains("result-router"));
    }

    #[test]
    fn logger_limit_is_a_typed_failure_instead_of_silent_diagnostic_loss() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let logger = RunLogger {
            path: Some(root.join("never-created.log")),
            root,
            lines: Vec::new(),
            truncated: true,
        };
        let error = logger
            .finish()
            .expect_err("truncated diagnostics must fail");
        assert_eq!(error.code(), "execution.logging-limit");
    }

    #[test]
    fn forced_report_deletion_rejects_cwd_root_and_symlink_targets() {
        let base =
            std::env::temp_dir().join(format!("jmeter-rs-runner-deletion-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join("work/report")).expect("test report directory");
        fs::write(base.join("work/report/keep.txt"), b"fixture").expect("test report file");
        let launch = LaunchEnvironment::new(base.join("work"));

        let cwd_error = report_directory(Some("."), &launch, ReportOutputMode::ReplaceExisting)
            .expect_err("force deletion must never target the working directory");
        assert!(matches!(cwd_error, RunError::Io { .. }));
        assert!(base.join("work/report/keep.txt").exists());

        let broad_error = report_directory(Some(".."), &launch, ReportOutputMode::ReplaceExisting)
            .expect_err("parent/broad working-directory targets must fail closed");
        assert!(matches!(broad_error, RunError::Io { .. }));
        let filesystem_root_error =
            report_directory(Some("/"), &launch, ReportOutputMode::ReplaceExisting)
                .expect_err("filesystem root targets must fail closed");
        assert!(matches!(filesystem_root_error, RunError::Io { .. }));

        let report = report_directory(Some("report"), &launch, ReportOutputMode::ReplaceExisting)
            .expect("safe child report");
        assert_eq!(report, base.join("work/report"));
        assert!(!base.join("work/report/keep.txt").exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            fs::create_dir_all(base.join("work/real")).expect("real directory");
            fs::write(base.join("work/real/keep.txt"), b"fixture").expect("real file");
            symlink("real", base.join("work/link")).expect("symlink");
            let symlink_error =
                report_directory(Some("link"), &launch, ReportOutputMode::ReplaceExisting)
                    .expect_err("symlink replacement must fail closed");
            assert!(matches!(symlink_error, RunError::Io { .. }));
            assert!(base.join("work/real/keep.txt").exists());

            // Model the TOCTOU boundary explicitly: a path that was intended
            // to be a directory has been replaced by a symlink before the
            // deletion helper gets its final metadata check.  The helper must
            // reject the link itself and never follow it to `real`.
            fs::create_dir_all(base.join("work/replaced")).expect("replacement directory");
            fs::remove_dir_all(base.join("work/replaced")).expect("replacement setup");
            symlink("real", base.join("work/replaced")).expect("replacement symlink");
            let root = fs::canonicalize(base.join("work")).expect("canonical test root");
            let replacement_error = remove_report_directory(&base.join("work/replaced"), &root)
                .expect_err("TOCTOU symlink replacement must fail closed");
            assert!(matches!(replacement_error, RunError::Io { .. }));
            assert!(base.join("work/real/keep.txt").exists());
        }

        fs::remove_dir_all(&base).expect("test directory cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn output_creation_rejects_parent_and_final_symlink_swaps() {
        use std::os::unix::fs::symlink;

        let base = std::env::temp_dir().join(format!(
            "jmeter-rs-runner-output-links-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join("work/real")).expect("real output root");
        fs::create_dir_all(base.join("outside")).expect("outside output root");
        let root = fs::canonicalize(base.join("work")).expect("canonical output root");

        symlink("real", base.join("work/final-link")).expect("final output symlink");
        let final_error = open_output(
            &base.join("work/final-link/result.jtl"),
            OutputOpenMode::CreateNew,
            &root,
        )
        .expect_err("final symlink must not redirect output");
        assert_eq!(final_error.code(), "io.output");
        assert!(!base.join("outside/result.jtl").exists());

        symlink("../outside", base.join("work/parent-link")).expect("parent output symlink");
        let parent_error = open_output(
            &base.join("work/parent-link/result.jtl"),
            OutputOpenMode::CreateNew,
            &root,
        )
        .expect_err("parent symlink must not redirect output");
        assert_eq!(parent_error.code(), "io.output");
        assert!(!base.join("outside/result.jtl").exists());

        fs::remove_dir_all(&base).expect("output link test cleanup");
    }
}
