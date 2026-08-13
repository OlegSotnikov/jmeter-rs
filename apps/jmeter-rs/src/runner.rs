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
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::net::IpAddr;
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
#[cfg(test)]
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
#[cfg(test)]
use std::task::{Context, Poll, Wake, Waker};
#[cfg(test)]
use std::time::Instant;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jmeter_rs_http::{
    ClientConfig, ClientLimits, DecompressionPolicy, HttpClient, HttpVersionPolicy, Method,
    ProxyPolicy, RedirectPolicy, Request, RetryPolicy, SampleResultProjectionOptions,
    TimeoutConfig, TlsConfig, Url,
};
use jmeter_rs_http_native::{NativeHttpTransport, NativeTransportLimits};
use jmeter_rs_jmx::SemanticDocument;
use jmeter_rs_model::{NodeId, PropertyValue, TestElement};
use jmeter_rs_report::{
    DashboardConfig, DashboardReport, ReportError, ReportField, ReportInterval,
};
use jmeter_rs_results::{
    AssertionResults, CliMode, CsvDecoder, DataLimits, JavaValue, JtlError, JtlFormat, JtlLimits,
    LineEnding, MAX_JTL_ATTRIBUTE_BYTES, MAX_JTL_INPUT_BYTES, MAX_JTL_NODES, MAX_JTL_OUTPUT_BYTES,
    MAX_JTL_RECORD_BYTES, MAX_JTL_SAMPLES, MAX_SAVE_CONFIG_CANDIDATES, MAX_SAVE_CONFIG_FIELDS,
    MAX_SAVE_CONFIG_OPERATIONS, MAX_SAVE_CONFIG_OPERATIONS_PER_FIELD, MAX_SAVE_CONFIG_TEXT_BYTES,
    MAX_SAVE_CONFIG_TOTAL_VALUE_BYTES, SampleEvent, SampleResult, SampleSaveConfiguration,
    SaveConfigError, SaveConfigLimits, SaveConfigOperation, SaveConfigPrecedence,
    SaveConfigResolution, SaveConfigResolver, SaveConfigSource, SaveConfigSourceKind, SaveField,
    SaveFieldId, SaveOperationKind, SaveWireFormat, TimestampFormat, TimestampSource,
    XmlDecodeConfiguration, XmlDecoder,
};
use jmeter_rs_runtime::{
    Assertion, CompiledPackages, CompiledPlanDraft, CompiledScopePlan, ComponentCategory,
    ComponentFactoryRegistry, ComponentFuture, Configuration, Deadline, Digest32, EnginePlan,
    FactoryComponent, ImplementationPathIdentity, InitialVariables, Listener, MonotonicInstant,
    PlanCompileError, PlanCompiler, PlanPathContext, PlanPathManifest, Postprocessor, Preprocessor,
    ProviderIdentity, RunObservationSummaryV1, SamplePackage, Sampler, SamplerFactory,
    SamplerOutput, ScopeCompileError, ScopeCompiler, ScopeComponent, ScopeComponentFactory,
    ScopeFactoryError, ScopePackageAssembler, ScopePlan, SemanticSource, SourceIdentity,
    ThreadGroupPlan, Timer,
};

#[cfg(test)]
use jmeter_rs_runtime::{
    ResultRouter, ResultSinkSpec, RunObservationPolicyV1, RuntimeCapabilities, RuntimeEngine,
    SinkId, SinkLimits,
};

use crate::builtin_factories::build_builtin_scope_factories;
#[cfg(test)]
use crate::config::ensure_bound_directory;
use crate::config::{
    bound_metadata, metadata_identity, open_bound_append, open_bound_create_new,
    open_bound_directory, open_bound_read, remove_bound_file, remove_bound_tree, rename_bound,
};
use crate::http_worker::{HttpOperation, HttpWorkerSubmitter, OperationDeadline, PoolError};
#[cfg(test)]
use crate::http_worker::{HttpWorkerPool, OperationClockAdapter, PoolLimits};
#[cfg(test)]
use crate::jtl_sink::JtlSinkLimits;
use crate::jtl_sink::{JtlSinkError, JtlSinkOwner};
use crate::native_http_plan::compile_native_v2_http_plan;
use crate::native_http_run::MAX_NATIVE_HTTP_CA_BYTES;
use crate::native_v2_request::NativeV2RequestMapper;
use crate::native_v2_request::PreparedNativeV2RequestMap;
use crate::native_v2_sampler::{NATIVE_V2_HTTP_TEST_CLASSES, NativeV2ScopeFactory};
use crate::report_input::{ReportInput, ReportInputError};
use crate::time_driver::TimeDriverHandle;
use crate::{
    Action, CliInvocation, ConfigError, ConfigFsPolicy, ConfigLimits, ConfigLoader,
    ConfigNamespace, ConfigPlan, ConfigSource, ExitClass, HTTP_NATIVE_V1_CAPABILITY,
    HTTP_NATIVE_V2_CAPABILITY, HttpCapabilitySelector, HttpCapabilitySelectorError, JavaString,
    PathArgument, PathKind, PropertyMap, PropertyOperation, PropertyOperationKind,
    PropertyProvenance, ResolvedConfig, ResolvedProperty, RunMode, standalone_manifest_identity,
    standalone_runtime_capability_set,
};

const MAX_LOG_BYTES: usize = 64 * 1024;
const MAX_CONFIG_FILE_BYTES: usize = 64 * 1024;
const MAX_CONFIG_TOTAL_BYTES: usize = 256 * 1024;
const MAX_REPORT_BYTES: usize = 64 * 1024;
const MAX_DIAGNOSTIC_BYTES: usize = 64 * 1024;
/// Explicit report aggregation retention bound.  This policy applies only to
/// dashboard/report decoding; it is not a result sink or JTL output limit.
const MAX_REPORT_AGGREGATION_ENTRIES: usize = 100_000;
/// Maximum number of future polls in one application-edge execution.
///
/// A future that keeps waking itself is a bounded executor failure rather
/// than permission to monopolize the CLI thread indefinitely.
#[cfg(test)]
const MAX_EXECUTOR_POLLS: usize = 1_000_000;
/// Maximum number of wake notifications accepted by one execution.
///
/// This is independent from the poll bound so a provider that emits a wake
/// storm from one poll cannot accumulate unbounded wake state.
#[cfg(test)]
const MAX_EXECUTOR_WAKES: usize = 1_000_000;
/// Default no-wake protection when a plan has no explicit runtime/network
/// deadline.  Explicit finite deadlines replace this interval when larger.
#[cfg(test)]
const DEFAULT_EXECUTOR_IDLE: Duration = Duration::from_secs(1);
/// The largest configured idle deadline accepted by the application adapter.
///
/// HTTP admission bounds connect/response timeouts to 24 hours.  Runtime
/// group schedules may be longer, so `executor_policy_for_plan` raises the
/// effective idle window to the largest admitted schedule and rejects a plan
/// that cannot be represented by this finite policy.
#[cfg(test)]
const MAX_EXECUTOR_IDLE: Duration = Duration::from_secs(7 * 24 * 60 * 60 + 1);
/// Small allowance for deadline/wake handoff and timer granularity.
#[cfg(test)]
const EXECUTOR_IDLE_GRACE: Duration = Duration::from_secs(1);
const DEFAULT_REPORT_DIRECTORY: &str = "report";
const DEFAULT_JMETER_LOG: &str = "jmeter.log";

const HTTP_NATIVE_CAPABILITY: &str = "http.native/1";
const HTTP_COMPATIBILITY_PACK_REQUIRED: &str = "http.compatibility-pack-required";
const HTTP_NATIVE_INVALID_FIELD: &str = "http.native.invalid-field";
const HTTP_NATIVE_UNSUPPORTED_FIELD: &str = "http.native.unsupported-field";
const HTTP_NATIVE_UNSUPPORTED_MANAGER: &str = "http.native.unsupported-manager";
const HTTP_NATIVE_MULTIPART_UNSUPPORTED: &str = "http.native.multipart-unsupported";
const HTTP_NATIVE_FILES_UNSUPPORTED: &str = "http.native.files-unsupported";
const HTTP_NATIVE_AUTO_REDIRECTS: &str = "http.native.auto-redirects";
const HTTP_NATIVE_REDIRECTS: &str = "http.native.redirects-unsupported";
const HTTP_NATIVE_HOSTNAME: &str = "http.native.hostname-unsupported";
const HTTP_NATIVE_DYNAMIC_FIELD: &str = "http.native.dynamic-field";
const HTTP_NATIVE_KEEPALIVE: &str = "http.native.keepalive-unsupported";
const HTTP_NATIVE_EMBEDDED_RESOURCES: &str = "http.native.embedded-resources";
const HTTP_NATIVE_TLS_STORE: &str = "http.native.tls-store-unsupported";
const HTTP_NATIVE_CUSTOM_RESOLVER: &str = "http.native.custom-resolver";
const HTTP_NATIVE_SOURCE_IMPLEMENTATION: &str = "http.native.source-implementation-unsupported";
const HTTP_NATIVE_DEFAULTS: &str = "http.native.request-defaults-unsupported";
const HTTP_NATIVE_REQUEST_BODY: &str = "http.native.request-body-unsupported";

const DEFAULT_HTTP_IMPLEMENTATION: &str = "HttpClient4";
const DEFAULT_HTTP_PROTOCOL: &str = "http";
const DEFAULT_HTTP_METHOD: &str = "GET";
const DEFAULT_HTTP_CONTENT_ENCODING: &str = "UTF-8";
const DEFAULT_HTTP_FOLLOW_REDIRECTS: bool = true;
const DEFAULT_HTTP_AUTO_REDIRECTS: bool = false;
const DEFAULT_HTTP_KEEPALIVE: bool = true;
// JMeter permits omitted/zero phase timeout properties. The native provider
// always supplies finite values so the synchronous socket edge cannot inherit
// an unbounded phase from that representation.
const DEFAULT_NATIVE_HTTP_OVERALL_TIMEOUT: Duration = Duration::from_secs(120);
const DEFAULT_NATIVE_HTTP_PHASE_TIMEOUT: Duration = Duration::from_secs(30);
// Keep individual native response projections bounded independently from the
// streaming JTL sink queue and its run-total output policy.
const NATIVE_HTTP_RESPONSE_HEAD_BYTES: usize = 16 * 1024;
const NATIVE_HTTP_RESPONSE_BODY_BYTES: usize = 16 * 1024;
const MAX_HTTP_DOMAIN_BYTES: usize = 255;
const MAX_HTTP_PATH_BYTES: usize = 64 * 1024;
const MAX_HTTP_FIELD_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OutputOpenMode {
    CreateNew,
    ReplaceExisting,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReportOutputMode {
    CreateNew,
    ReplaceExisting,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ReportStats {
    pub(crate) samples: usize,
    pub(crate) failed: usize,
}

/// The one descriptor-bound report input admitted during report-only
/// preflight.  Keeping the replayable reader and its resolved save
/// configuration together prevents a second path lookup after logger setup.
struct PreparedReportInput {
    path: PathBuf,
    input: ReportInput<BufReader<File>>,
    save_configuration: ResolvedSaveConfiguration,
}

pub(crate) struct PreparedReportTarget {
    path: PathBuf,
    root: PathBuf,
    existing_identity: Option<(u64, u64)>,
    mode: ReportOutputMode,
}

impl PreparedReportTarget {
    pub(crate) fn path(&self) -> PathBuf {
        self.path.clone()
    }
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
    /// Optional JMeter home selected explicitly by `-d/--homedir`.
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
            // A standalone run must not discover JMeter/application assets
            // through ambient JMETER_HOME.  `-d/--homedir` is the only
            // explicit home selection; the allowlisted environment remains
            // observable for diagnostics but cannot alter native routing.
            jmeter_home: None,
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

/// Exact bounded cleanup owner categories retained alongside a primary run
/// error.  The transaction never flattens cleanup failures into an
/// untyped diagnostic string.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CleanupCategory {
    Engine,
    Jtl,
    HttpPool,
    NativeHttp,
    TimeDriver,
    Staging,
    Report,
    Logging,
}

impl CleanupCategory {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Engine => "engine",
            Self::Jtl => "jtl",
            Self::HttpPool => "http-pool",
            Self::NativeHttp => "native-http",
            Self::TimeDriver => "time-driver",
            Self::Staging => "staging",
            Self::Report => "report",
            Self::Logging => "logging",
        }
    }
}

/// One bounded cleanup diagnostic retained by a transaction error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CleanupFailure {
    /// Exact run-owned resource category that failed during cleanup.
    pub category: CleanupCategory,
    /// Stable bounded cleanup diagnostic code.
    pub code: String,
}

/// A bounded native request candidate produced by application admission.
///
/// This is intentionally smaller than the full HTTP protocol model.  It is
/// the exact subset that the application can decode without opening a
/// transport: origin spelling, request method/path, protocol, and the
/// explicit semantic policy flags. A candidate is never treated as an
/// executed sample; it is consumed exactly once by the app-owned native
/// sampler factory after whole-plan admission.
#[derive(Clone, Debug, Eq, PartialEq)]
struct NativeHttpRequestCandidate {
    domain: String,
    port: Option<u16>,
    protocol: String,
    path: String,
    method: String,
    content_encoding: String,
    follow_redirects: bool,
    auto_redirects: bool,
    use_keepalive: bool,
    concurrent_pool: Option<u16>,
    connect_timeout_ms: Option<u64>,
    response_timeout_ms: Option<u64>,
}

/// One HTTP node's immutable, source-preserving admission record.
#[derive(Clone, Debug, Eq, PartialEq)]
struct HttpNodeAdmission {
    node_id: NodeId,
    /// Exact `HTTPSampler.implementation` spelling, or the pinned JMeter
    /// default when the source omitted that property.
    source_implementation: String,
    /// Whether `source_implementation` came from the source-format default.
    source_implementation_defaulted: bool,
    /// Exact source-provider capability identity retained for evidence.
    source_capability: String,
    /// Independently named provider selected by the direct command-line
    /// selector.
    executed_capability: &'static str,
    request: NativeHttpRequestCandidate,
    /// Canonical typed request built during whole-plan admission. Factories
    /// and samplers clone this value; they never reinterpret JMX fields.
    prepared_request: Request,
    /// Fully explicit client policy admitted alongside the typed request.
    client_config: ClientConfig,
    /// Native parser/transport limits aligned with the admitted client.
    transport_limits: NativeTransportLimits,
}

/// Complete HTTP admission output for one plan.
///
/// The application keeps this structure separate from the generic runtime
/// `PlanPathManifest`: the built-in runtime compiler currently labels HTTP
/// samplers with its generic native path.  HTTP provider substitution is an
/// application-owned decision and must not be mistaken for a runnable
/// transport path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CompiledHttpAdmission {
    selector: HttpCapabilitySelector,
    nodes: Vec<HttpNodeAdmission>,
}

impl CompiledHttpAdmission {
    pub(crate) fn has_http(&self) -> bool {
        !self.nodes.is_empty()
    }

    pub(crate) fn node_ids(&self) -> BTreeSet<NodeId> {
        self.nodes.iter().map(|node| node.node_id).collect()
    }

    pub(crate) fn transport_limits(&self) -> Option<NativeTransportLimits> {
        self.nodes.first().map(|node| node.transport_limits)
    }

    pub(crate) fn log_summary(&self) -> String {
        let source_capabilities = self
            .nodes
            .iter()
            .map(|node| node.source_capability.as_str())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(",");
        let executed_capabilities = self
            .nodes
            .iter()
            .map(|node| node.executed_capability)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(",");
        bounded(
            format!(
                "http nodes={} source-providers={} executed={}",
                self.nodes.len(),
                source_capabilities,
                executed_capabilities
            ),
            MAX_DIAGNOSTIC_BYTES,
        )
    }
}

/// The provider identity frozen by pure executable-plan admission.
///
/// This is deliberately narrower than the source HTTP implementation spelling:
/// source provenance remains in [`CompiledHttpAdmission`] or the NativeV2
/// request map, while this identity describes the executable capability that
/// a later resource binding must match exactly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExecutableCapabilityIdentity {
    /// The standalone native capability set with no HTTP provider.
    Standalone,
    /// The explicitly selected NativeV1 provider.
    NativeV1,
    /// The explicitly selected NativeV2 provider.
    NativeV2,
}

impl ExecutableCapabilityIdentity {
    /// Returns the stable capability identity used by binding diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Standalone => "standalone-native",
            Self::NativeV1 => HTTP_NATIVE_V1_CAPABILITY,
            Self::NativeV2 => HTTP_NATIVE_V2_CAPABILITY,
        }
    }
}

/// Immutable resource facts emitted by pure admission.
///
/// These are requirements, not handles.  In particular, constructing this
/// value cannot create a thread, socket, resolver, file, logger, or clock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExecutableResourceRequirements {
    /// The exact executable provider required by this recipe, if any.
    pub provider: Option<ExecutableCapabilityIdentity>,
    /// Whether at least one HTTP sampler is enabled.
    pub has_http: bool,
    /// Whether the selected provider needs a worker-pool submission handle.
    pub needs_http_pool: bool,
    /// Whether the selected provider needs the run-owned time handle.
    pub needs_time_driver: bool,
    /// Whether at least one admitted origin needs explicit DNS resolution.
    pub has_hostname: bool,
    /// Whether at least one admitted origin needs explicit TLS.
    pub has_https: bool,
    /// Exact parser/transport limits promised by admission.
    pub transport_limits: Option<NativeTransportLimits>,
}

/// Exact typed owners/factories consumed by [`AdmittedExecutableRecipe`]
/// binding.
///
/// The transaction owner constructs this value only after pure admission has
/// returned successfully.  Each optional field is an exact owner or frozen
/// factory; `bind_resources` never creates a placeholder when one is absent.
#[derive(Clone)]
pub(crate) struct ExecutableResourceBindings {
    /// Plan identity used to prevent recipe reuse across source plans.
    pub plan_digest: Digest32,
    /// Capability identity used to prevent provider reclassification.
    pub capability: ExecutableCapabilityIdentity,
    /// Run-owned NativeV1 worker submission handle.
    pub http_pool: Option<NativeHttpPoolHandle>,
    /// Run-owned NativeV2 factory, already joined to exact provider owners.
    pub native_v2_factory: Option<NativeV2ScopeFactory>,
    /// Frozen concrete native transport for NativeV1.
    pub native_http_transport: Option<NativeHttpTransport>,
    /// Run-owned monotonic time handle.
    pub time_driver: Option<TimeDriverHandle>,
    /// Immutable result projection required by native samplers.
    pub projection: Option<SampleResultProjectionOptions>,
}

impl std::fmt::Debug for ExecutableResourceBindings {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExecutableResourceBindings")
            .field("plan_digest", &self.plan_digest)
            .field("capability", &self.capability)
            .field("http_pool", &self.http_pool.is_some())
            .field("native_v2_factory", &self.native_v2_factory.is_some())
            .field(
                "native_http_transport",
                &self
                    .native_http_transport
                    .as_ref()
                    .map(NativeHttpTransport::capability_id),
            )
            .field("time_driver", &self.time_driver.is_some())
            .field("projection", &self.projection.is_some())
            .finish()
    }
}

/// One sampler recipe retained after pure component/factory admission.
///
/// HTTP samplers intentionally retain only their source node identity here;
/// their concrete sampler factory is created only by `bind_resources` after
/// the exact transport owner is supplied.  No fake transport-backed sampler
/// exists in an admitted recipe.
enum AdmittedSamplerRecipe {
    /// A DebugSampler with validated immutable source fields.
    Debug { label: String, failed: bool },
    /// A decoded non-HTTP sampler whose factory is pure and owner-free.
    Decoded(Arc<dyn Sampler>),
    /// A NativeV1 sampler joined by node identity at binding.  The label is
    /// retained here so binding does not reinterpret the source component.
    NativeV1 { node_id: NodeId, label: String },
    /// A NativeV2 sampler joined by node identity at binding.
    NativeV2(NodeId),
}

impl std::fmt::Debug for AdmittedSamplerRecipe {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Debug { label, failed } => formatter
                .debug_struct("Debug")
                .field("label_bytes", &label.len())
                .field("failed", failed)
                .finish(),
            Self::Decoded(_) => formatter.write_str("Decoded"),
            Self::NativeV1 { node_id, label } => formatter
                .debug_struct("NativeV1")
                .field("node_id", node_id)
                .field("label_bytes", &label.len())
                .finish(),
            Self::NativeV2(node_id) => formatter.debug_tuple("NativeV2").field(node_id).finish(),
        }
    }
}

/// A fully decoded scope recipe.  All source-derived validation and factory
/// decoding occurs before this value is returned from admission.
struct AdmittedScopeRecipe {
    sampler_id: NodeId,
    sampler_component: ScopeComponent,
    sampler: AdmittedSamplerRecipe,
    configurations: Vec<Arc<dyn Configuration>>,
    preprocessors: Vec<Arc<dyn Preprocessor>>,
    timers: Vec<Arc<dyn Timer>>,
    postprocessors: Vec<Arc<dyn Postprocessor>>,
    assertions: Vec<Arc<dyn Assertion>>,
    listeners: Vec<Arc<dyn Listener>>,
}

impl std::fmt::Debug for AdmittedScopeRecipe {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdmittedScopeRecipe")
            .field("sampler_id", &self.sampler_id)
            .field("sampler", &self.sampler)
            .field("configuration_count", &self.configurations.len())
            .field("preprocessor_count", &self.preprocessors.len())
            .field("timer_count", &self.timers.len())
            .field("postprocessor_count", &self.postprocessors.len())
            .field("assertion_count", &self.assertions.len())
            .field("listener_count", &self.listeners.len())
            .finish()
    }
}

impl Clone for AdmittedScopeRecipe {
    fn clone(&self) -> Self {
        Self {
            sampler_id: self.sampler_id,
            sampler_component: self.sampler_component.clone(),
            sampler: match &self.sampler {
                AdmittedSamplerRecipe::Debug { label, failed } => AdmittedSamplerRecipe::Debug {
                    label: label.clone(),
                    failed: *failed,
                },
                AdmittedSamplerRecipe::Decoded(value) => {
                    AdmittedSamplerRecipe::Decoded(Arc::clone(value))
                }
                AdmittedSamplerRecipe::NativeV1 { node_id, label } => {
                    AdmittedSamplerRecipe::NativeV1 {
                        node_id: *node_id,
                        label: label.clone(),
                    }
                }
                AdmittedSamplerRecipe::NativeV2(node_id) => {
                    AdmittedSamplerRecipe::NativeV2(*node_id)
                }
            },
            configurations: self.configurations.clone(),
            preprocessors: self.preprocessors.clone(),
            timers: self.timers.clone(),
            postprocessors: self.postprocessors.clone(),
            assertions: self.assertions.clone(),
            listeners: self.listeners.clone(),
        }
    }
}

/// Pure executable-plan admission output required by Decision 0012.
///
/// The recipe contains no thread, socket, file, logger, resolver, worker,
/// or `TimeDriver` handle.  It is safe to construct and inspect in a pure
/// deterministic test, and it is reusable only when the binding supplies the
/// same plan and capability identity.
pub(crate) struct AdmittedExecutableRecipe {
    plan_digest: Digest32,
    capability: ExecutableCapabilityIdentity,
    manifest: PlanPathManifest,
    draft: CompiledPlanDraft,
    initial_variables: InitialVariables,
    scopes: Vec<AdmittedScopeRecipe>,
    http_v1: Option<CompiledHttpAdmission>,
    native_v2: Option<PreparedNativeV2RequestMap>,
    requirements: ExecutableResourceRequirements,
}

impl std::fmt::Debug for AdmittedExecutableRecipe {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdmittedExecutableRecipe")
            .field("plan_digest", &self.plan_digest)
            .field("capability", &self.capability)
            .field("manifest_entries", &self.manifest.len())
            .field("scope_count", &self.scopes.len())
            .field("requirements", &self.requirements)
            .finish()
    }
}

impl Clone for AdmittedExecutableRecipe {
    fn clone(&self) -> Self {
        Self {
            plan_digest: self.plan_digest,
            capability: self.capability,
            manifest: self.manifest.clone(),
            draft: self.draft.clone(),
            initial_variables: self.initial_variables.clone(),
            scopes: self.scopes.clone(),
            http_v1: self.http_v1.clone(),
            native_v2: self.native_v2.clone(),
            requirements: self.requirements,
        }
    }
}

impl AdmittedExecutableRecipe {
    /// Returns the immutable plan identity used by binding.
    #[must_use]
    pub const fn plan_digest(&self) -> Digest32 {
        self.plan_digest
    }

    /// Returns the executable capability identity used by binding.
    #[must_use]
    pub const fn capability_identity(&self) -> ExecutableCapabilityIdentity {
        self.capability
    }

    /// Returns the complete implementation-path manifest, including paths
    /// whose concrete HTTP provider is represented by the app-owned recipe.
    #[must_use]
    pub const fn implementation_manifest(&self) -> &PlanPathManifest {
        &self.manifest
    }

    /// Returns exact immutable resource requirements discovered by admission.
    #[must_use]
    pub const fn resource_requirements(&self) -> ExecutableResourceRequirements {
        self.requirements
    }

    /// Binds exact already-created owners/factories and constructs the engine
    /// plan.  No JMX/property decoding or provider selection occurs here.
    pub(crate) fn bind_resources(
        &self,
        resources: &ExecutableResourceBindings,
    ) -> Result<(EnginePlan, usize), RunError> {
        if resources.plan_digest != self.plan_digest {
            return Err(RunError::Runtime {
                code: "runtime.executable-bind.plan-mismatch".to_owned(),
                message: "resource owners belong to a different admitted plan".to_owned(),
            });
        }
        if resources.capability != self.capability {
            return Err(RunError::Runtime {
                code: "runtime.executable-bind.capability-mismatch".to_owned(),
                message: format!(
                    "resource capability {} does not match admitted {}",
                    resources.capability.as_str(),
                    self.capability.as_str()
                ),
            });
        }
        self.validate_bindings(resources)?;
        let packages = self
            .scopes
            .iter()
            .map(|scope| self.bind_scope(scope, resources))
            .collect::<Result<Vec<_>, _>>()
            .map_err(scope_compile_error)
            .and_then(|packages| {
                CompiledPackages::from_packages(packages).map_err(|source| {
                    scope_compile_error(ScopeCompileError::PackageAssembly { source })
                })
            })?;
        let package_count = packages.len();
        let mut plan = EnginePlan::new();
        plan.serialize_thread_groups = self.draft.serialize_thread_groups;
        plan.teardown_on_shutdown = self.draft.teardown_on_shutdown;
        // The typed variable seed was fully validated during pure admission;
        // binding only transfers that immutable recipe into the new plan.
        plan.set_initial_variables(self.initial_variables.clone());
        for group_draft in &self.draft.groups {
            let group = ThreadGroupPlan::new_logic(
                group_draft.id,
                group_draft.name.clone(),
                group_draft.threads,
                group_draft.controller.clone(),
                packages.clone(),
            )
            .map_err(|error| RunError::Runtime {
                code: error.code().to_owned(),
                message: bounded(error.to_string(), MAX_DIAGNOSTIC_BYTES),
            })?
            .with_kind(group_draft.kind)
            .with_schedule(group_draft.schedule)
            .with_error_policy(group_draft.on_sample_error)
            .with_same_user_on_next_iteration(group_draft.same_user_on_next_iteration);
            plan.push_group(group).map_err(|error| RunError::Runtime {
                code: error.code().to_owned(),
                message: bounded(error.to_string(), MAX_DIAGNOSTIC_BYTES),
            })?;
        }
        Ok((plan, package_count))
    }

    fn validate_bindings(&self, resources: &ExecutableResourceBindings) -> Result<(), RunError> {
        if !self.requirements.has_http {
            if resources.native_http_transport.is_some()
                || resources.native_v2_factory.is_some()
                || resources.http_pool.is_some()
            {
                return Err(RunError::Runtime {
                    code: "runtime.executable-bind.unused-owner".to_owned(),
                    message: "HTTP owners were supplied for a plan without HTTP".to_owned(),
                });
            }
            return Ok(());
        }
        if self.requirements.needs_time_driver && resources.time_driver.is_none() {
            return Err(RunError::Runtime {
                code: "runtime.executable-bind.time-driver-missing".to_owned(),
                message: "admitted HTTP plan has no matching time-driver owner".to_owned(),
            });
        }
        match self.capability {
            ExecutableCapabilityIdentity::NativeV1 => {
                let Some(transport) = resources.native_http_transport.as_ref() else {
                    return Err(RunError::Runtime {
                        code: "runtime.executable-bind.transport-missing".to_owned(),
                        message: "NativeV1 transport owner is missing".to_owned(),
                    });
                };
                if !transport.is_v1()
                    || self.requirements.transport_limits != Some(*transport.limits())
                {
                    return Err(RunError::Runtime {
                        code: "runtime.executable-bind.transport-mismatch".to_owned(),
                        message: "NativeV1 transport identity or limits do not match admission"
                            .to_owned(),
                    });
                }
                if self.requirements.needs_http_pool
                    && !resources
                        .http_pool
                        .as_ref()
                        .is_some_and(native_http_pool_is_bound)
                {
                    return Err(RunError::Runtime {
                        code: "runtime.executable-bind.http-pool-missing".to_owned(),
                        message: "NativeV1 worker-pool owner is missing".to_owned(),
                    });
                }
                if resources.projection.is_none() {
                    return Err(RunError::Runtime {
                        code: "runtime.executable-bind.projection-missing".to_owned(),
                        message: "NativeV1 result projection is missing".to_owned(),
                    });
                }
                if resources.native_v2_factory.is_some() {
                    return Err(RunError::Runtime {
                        code: "runtime.executable-bind.provider-mismatch".to_owned(),
                        message: "NativeV2 factory supplied to NativeV1 recipe".to_owned(),
                    });
                }
            }
            ExecutableCapabilityIdentity::NativeV2 => {
                if resources.native_v2_factory.is_none() {
                    return Err(RunError::Runtime {
                        code: "runtime.executable-bind.native-v2-factory-missing".to_owned(),
                        message: "NativeV2 factory owner is missing".to_owned(),
                    });
                }
                if resources.native_http_transport.is_some() {
                    return Err(RunError::Runtime {
                        code: "runtime.executable-bind.provider-mismatch".to_owned(),
                        message: "NativeV1 transport supplied to NativeV2 recipe".to_owned(),
                    });
                }
                if resources.projection.is_none() {
                    return Err(RunError::Runtime {
                        code: "runtime.executable-bind.projection-missing".to_owned(),
                        message: "NativeV2 result projection is missing".to_owned(),
                    });
                }
            }
            ExecutableCapabilityIdentity::Standalone => {
                return Err(RunError::Runtime {
                    code: "runtime.executable-bind.provider-mismatch".to_owned(),
                    message: "HTTP requirements have no executable provider identity".to_owned(),
                });
            }
        }
        Ok(())
    }

    fn bind_scope(
        &self,
        scope: &AdmittedScopeRecipe,
        resources: &ExecutableResourceBindings,
    ) -> Result<SamplePackage, ScopeCompileError> {
        let (sampler, sampler_factory): (Arc<dyn Sampler>, Arc<dyn SamplerFactory>) =
            match &scope.sampler {
                AdmittedSamplerRecipe::Debug { label, failed } => {
                    let factory = Arc::new(DebugSamplerFactory {
                        label: label.clone(),
                        failed: *failed,
                    });
                    (factory.create(), factory)
                }
                AdmittedSamplerRecipe::Decoded(value) => {
                    let factory = Arc::new(StaticSamplerFactory(Arc::clone(value)));
                    (factory.create(), factory)
                }
                AdmittedSamplerRecipe::NativeV1 { node_id, label } => {
                    let admission = self
                        .http_v1
                        .as_ref()
                        .and_then(|admission| {
                            admission.nodes.iter().find(|node| node.node_id == *node_id)
                        })
                        .ok_or_else(|| ScopeCompileError::Factory {
                            source: ScopeFactoryError::Decode {
                                node_id: *node_id,
                                path: scope.sampler_component.path.clone(),
                                test_class: scope.sampler_component.binding.test_class.clone(),
                                category: ComponentCategory::Sampler,
                                detail: "NativeV1 sampler recipe is missing its admitted node"
                                    .to_owned(),
                            },
                        })?;
                    let transport = resources.native_http_transport.clone().ok_or_else(|| {
                        ScopeCompileError::Factory {
                            source: ScopeFactoryError::Decode {
                                node_id: *node_id,
                                path: scope.sampler_component.path.clone(),
                                test_class: scope.sampler_component.binding.test_class.clone(),
                                category: ComponentCategory::Sampler,
                                detail: "NativeV1 transport owner is missing".to_owned(),
                            },
                        }
                    })?;
                    let pool =
                        resources
                            .http_pool
                            .clone()
                            .ok_or_else(|| ScopeCompileError::Factory {
                                source: ScopeFactoryError::Decode {
                                    node_id: *node_id,
                                    path: scope.sampler_component.path.clone(),
                                    test_class: scope.sampler_component.binding.test_class.clone(),
                                    category: ComponentCategory::Sampler,
                                    detail: "NativeV1 worker-pool owner is missing".to_owned(),
                                },
                            })?;
                    let time_driver = resources.time_driver.clone().ok_or_else(|| {
                        ScopeCompileError::Factory {
                            source: ScopeFactoryError::Decode {
                                node_id: *node_id,
                                path: scope.sampler_component.path.clone(),
                                test_class: scope.sampler_component.binding.test_class.clone(),
                                category: ComponentCategory::Sampler,
                                detail: "NativeV1 time-driver owner is missing".to_owned(),
                            },
                        }
                    })?;
                    let projection =
                        resources
                            .projection
                            .clone()
                            .ok_or_else(|| ScopeCompileError::Factory {
                                source: ScopeFactoryError::Decode {
                                    node_id: *node_id,
                                    path: scope.sampler_component.path.clone(),
                                    test_class: scope.sampler_component.binding.test_class.clone(),
                                    category: ComponentCategory::Sampler,
                                    detail: "NativeV1 result projection is missing".to_owned(),
                                },
                            })?;
                    let factory = NativeHttpSamplerFactory::try_new_bound(
                        admission.clone(),
                        label.clone(),
                        pool,
                        transport,
                        time_driver,
                        projection,
                    )
                    .map_err(|detail| ScopeCompileError::Factory {
                        source: ScopeFactoryError::Decode {
                            node_id: *node_id,
                            path: scope.sampler_component.path.clone(),
                            test_class: scope.sampler_component.binding.test_class.clone(),
                            category: ComponentCategory::Sampler,
                            detail,
                        },
                    })?;
                    let factory = Arc::new(factory);
                    (factory.create(), factory)
                }
                AdmittedSamplerRecipe::NativeV2(node_id) => {
                    let Some(prepared) = self
                        .native_v2
                        .as_ref()
                        .and_then(|map| map.sampler(*node_id))
                    else {
                        return Err(ScopeCompileError::Factory {
                            source: ScopeFactoryError::Decode {
                                node_id: *node_id,
                                path: scope.sampler_component.path.clone(),
                                test_class: scope.sampler_component.binding.test_class.clone(),
                                category: ComponentCategory::Sampler,
                                detail: "NativeV2 sampler recipe is missing its prepared entry"
                                    .to_owned(),
                            },
                        });
                    };
                    // The lower factory API accepts a scope component so it
                    // can enforce its own typed owner invariant.  Feed it a
                    // component reconstructed from the already-admitted V2
                    // recipe, rather than asking it to parse/validate JMX at
                    // binding time.
                    let mut binding_component = scope.sampler_component.clone();
                    binding_component.path = prepared.source_path().to_vec();
                    binding_component.element.metadata.name = prepared.name().to_owned();
                    binding_component
                        .element
                        .properties
                        .remove("HTTPSampler.implementation");
                    if let Some(provider) = prepared.source_provider().static_wire_name() {
                        binding_component.element.set_property(
                            "HTTPSampler.implementation",
                            PropertyValue::string(provider),
                        );
                    }
                    let factory = resources
                        .native_v2_factory
                        .as_ref()
                        .ok_or_else(|| ScopeCompileError::Factory {
                            source: ScopeFactoryError::Decode {
                                node_id: *node_id,
                                path: scope.sampler_component.path.clone(),
                                test_class: scope.sampler_component.binding.test_class.clone(),
                                category: ComponentCategory::Sampler,
                                detail: "NativeV2 factory owner is missing".to_owned(),
                            },
                        })?
                        .sampler_factory_for(&binding_component)
                        .map_err(|error| ScopeCompileError::Factory {
                            source: ScopeFactoryError::Decode {
                                node_id: *node_id,
                                path: scope.sampler_component.path.clone(),
                                test_class: scope.sampler_component.binding.test_class.clone(),
                                category: ComponentCategory::Sampler,
                                detail: error.to_string(),
                            },
                        })?;
                    let factory = Arc::new(factory);
                    (factory.create(), factory)
                }
            };
        Ok(SamplePackage::builder(scope.sampler_id, sampler)
            .configurations(scope.configurations.clone())
            .preprocessors(scope.preprocessors.clone())
            .timers(scope.timers.clone())
            .postprocessors(scope.postprocessors.clone())
            .assertions(scope.assertions.clone())
            .listeners(scope.listeners.clone())
            .sampler_factory(sampler_factory)
            .build())
    }
}

fn native_http_pool_is_bound(handle: &NativeHttpPoolHandle) -> bool {
    handle.lock().map_or(false, |submitter| submitter.is_some())
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
    /// A selector supplied through the command line was invalid for the
    /// application-owned HTTP provider boundary.
    HttpSelector(HttpCapabilitySelectorError),
    /// A plan reached the application-owned HTTP admission boundary but is
    /// not executable by the currently wired native transport seam.
    Http {
        /// Stable HTTP admission/availability code.
        code: String,
        /// Bounded HTTP admission diagnostic.
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
    /// A primary failure plus every cleanup category observed while closing
    /// the exact run owners.
    Cleanup {
        /// The first failure that made the run unsuccessful.
        primary: Box<RunError>,
        /// Bounded cleanup failures observed while unwinding the run.
        cleanup: Vec<CleanupFailure>,
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

    pub(crate) fn from_config(error: ConfigError) -> Self {
        if error.is_unsupported() {
            return Self::unsupported("descriptor-bound-filesystem", error.to_string());
        }
        Self::Configuration(error)
    }

    pub(crate) fn unsupported(capability: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Unsupported {
            capability: bounded(capability.into(), 256),
            message: bounded(message.into(), MAX_DIAGNOSTIC_BYTES),
        }
    }

    pub(crate) fn http(code: &'static str, message: impl Into<String>) -> Self {
        Self::Http {
            code: code.to_owned(),
            message: bounded(message.into(), MAX_DIAGNOSTIC_BYTES),
        }
    }

    fn selector(error: HttpCapabilitySelectorError) -> Self {
        Self::HttpSelector(error)
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
            Self::HttpSelector(error) => error.code(),
            Self::Http { code, .. } => code,
            Self::Remote { .. } => "remote.unavailable",
            Self::Io { .. } => "io.output",
            Self::Runtime { code, .. } => code,
            Self::Report { code, .. } => code,
            Self::Cleanup { primary, .. } => primary.code(),
        }
    }

    /// Returns the mapped process exit class.
    #[must_use]
    pub const fn exit_class(&self) -> ExitClass {
        match self {
            Self::Configuration(_) => ExitClass::ConfigurationError,
            Self::Unsupported { .. } => ExitClass::UnsupportedCapability,
            Self::HttpSelector(_) => ExitClass::UsageError,
            Self::Http { .. } => ExitClass::UnsupportedCapability,
            Self::Remote { .. } => ExitClass::RemoteFailure,
            Self::Jmx { .. } | Self::Io { .. } | Self::Runtime { .. } | Self::Report { .. } => {
                ExitClass::Fatal
            }
            Self::Cleanup { primary, .. } => primary.exit_class(),
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
            Self::Cleanup { primary, cleanup } => {
                write!(formatter, "{primary}; cleanup=")?;
                for (index, failure) in cleanup.iter().enumerate() {
                    if index != 0 {
                        formatter.write_str(",")?;
                    }
                    write!(formatter, "{}:{}", failure.category.as_str(), failure.code)?;
                }
                Ok(())
            }
            Self::HttpSelector(error) => error.fmt(formatter),
            Self::Http { code, message } => write!(formatter, "{code}: {message}"),
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

    // Admission is deliberately performed before canonicalizing the working
    // directory, resolving property files, or constructing a logger.  GUI,
    // JVM/RMI, and unsupported report routes therefore cannot leave a log or
    // any other observable output behind when the standalone binary rejects
    // them.  Native local execution continues through the full plan
    // preflight before a result sink is started.
    let http_selector = invocation
        .resolve_http_capability_selector()
        .map_err(RunError::selector)?;
    preflight_invocation(invocation)?;

    let cwd = fs::canonicalize(&launch.cwd).map_err(|error| RunError::io(&launch.cwd, error))?;
    let selected_home = invocation.options.home_dir.as_deref().map(PathBuf::from);
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

    match invocation.mode() {
        RunMode::Gui => Err(RunError::unsupported(
            "gui",
            "GUI startup is outside the bounded native local/report adapter for profile jmeter-5.6.3",
        )),
        RunMode::Server => Err(RunError::unsupported(
            "server-jvm-rmi",
            "server mode is outside the bounded native local/report adapter for profile jmeter-5.6.3",
        )),
        RunMode::ReportOnly => {
            let prepared_input = preflight_report_only(invocation, launch, &resolved)?;
            let mut logger = RunLogger::initialize(invocation, &resolved, launch)?;
            let result = report_only(invocation, launch, prepared_input, &mut logger);
            match result {
                Ok(outcome) => logger.finish().map(|()| outcome),
                // The logger is intentionally not finalized for a report
                // failure.  Initialization is in-memory; dropping it here
                // leaves no observable log beside an input/decode/output
                // failure, just as the dashboard transaction leaves the old
                // generation visible.
                Err(error) => Err(error),
            }
        }
        RunMode::NonGui => {
            if invocation.options.remote.run_remote
                || invocation.options.remote.remote_start.is_some()
                || invocation.options.remote.remote_exit
            {
                Err(RunError::remote(
                    "remote-rmi",
                    "remote execution is outside the bounded native local/report adapter for profile jmeter-5.6.3",
                ))
            } else {
                local_run(invocation, launch, &loader, &resolved, http_selector)
            }
        }
    }
}

fn preflight_report_only(
    invocation: &CliInvocation,
    launch: &LaunchEnvironment,
    resolved: &ResolvedConfig,
) -> Result<PreparedReportInput, RunError> {
    let raw = invocation
        .options
        .report_only_file
        .as_deref()
        .ok_or_else(|| RunError::Report {
            code: "report.input",
            message: "report-only input is missing".to_owned(),
        })?;
    let path = resolve_checked_path(&launch.cwd, raw)?;
    let root = fs::canonicalize(&launch.cwd).map_err(|error| RunError::io(&launch.cwd, error))?;
    let configured_format = configured_report_input_format(resolved);
    let (input, input_format) = open_report_input(&path, &root, configured_format)?;
    let save_configuration = save_configuration(resolved, save_wire_format(input_format))?;
    reconcile_report_format(input_format, save_configuration.wire())?;
    let mode = if invocation.options.force_delete_result_file {
        ReportOutputMode::ReplaceExisting
    } else {
        ReportOutputMode::CreateNew
    };
    let _ = prepare_report_target(
        invocation.options.report_output_folder.as_deref(),
        launch,
        mode,
    )?;
    Ok(PreparedReportInput {
        path,
        input,
        save_configuration,
    })
}

fn preflight_invocation(invocation: &CliInvocation) -> Result<(), RunError> {
    match invocation.mode() {
        RunMode::Gui => Err(RunError::unsupported(
            "gui",
            "GUI startup is outside the bounded native local/report adapter for profile jmeter-5.6.3",
        )),
        RunMode::Server => Err(RunError::unsupported(
            "server-jvm-rmi",
            "server mode is outside the bounded native local/report adapter for profile jmeter-5.6.3",
        )),
        RunMode::ReportOnly if invocation.options.report_output_folder.is_none() => {
            Err(RunError::unsupported(
                "report-output-default",
                "report-only output without -o is not applied until the pinned JMeter output-directory oracle is available",
            ))
        }
        RunMode::ReportOnly => Ok(()),
        RunMode::NonGui => {
            if invocation.options.remote.run_remote
                || invocation.options.remote.remote_start.is_some()
                || invocation.options.remote.remote_exit
            {
                Err(RunError::remote(
                    "remote-rmi",
                    "remote execution is outside the bounded native local/report adapter for profile jmeter-5.6.3",
                ))
            } else if invocation.options.jmeterlogconf.is_some()
                || !invocation.options.log_levels.is_empty()
            {
                Err(RunError::unsupported(
                    "logging.config",
                    "the selected logging adapter is outside the bounded native local adapter for profile jmeter-5.6.3",
                ))
            } else if invocation.options.report_at_end && invocation.options.logfile.is_none() {
                Err(RunError::unsupported(
                    "result-router",
                    "report-at-end requires a result output path before the native run can be admitted",
                ))
            } else {
                Ok(())
            }
        }
    }
}

fn report_only(
    invocation: &CliInvocation,
    launch: &LaunchEnvironment,
    prepared: PreparedReportInput,
    logger: &mut RunLogger,
) -> Result<RunOutcome, RunError> {
    let PreparedReportInput {
        path,
        input,
        save_configuration,
    } = prepared;
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
    let stats = write_report_dashboard(&directory, input, save_configuration.wire())?;
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

/// Opens an already-resolved report input through the descriptor-bound
/// filesystem policy and performs only the bounded format probe.  The probe
/// is replayed by [`ReportInput`] so the decoder can continue from byte zero
/// without a second path lookup or a whole-file allocation.
fn open_report_input(
    path: &Path,
    root: &Path,
    configured_format: Option<JtlFormat>,
) -> Result<(ReportInput<BufReader<File>>, JtlFormat), RunError> {
    let metadata = bound_metadata(path, Some(root)).map_err(|error| RunError::io(path, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(RunError::Io {
            path: path.to_owned(),
            message: "report input must be a regular file".to_owned(),
        });
    }
    let file =
        open_bound_read(path, &[root.to_owned()]).map_err(|error| RunError::io(path, error))?;
    let metadata = file.metadata().map_err(|error| RunError::io(path, error))?;
    if !metadata.is_file() {
        return Err(RunError::Io {
            path: path.to_owned(),
            message: "report input must be a regular file".to_owned(),
        });
    }
    detect_report_input(BufReader::new(file), configured_format)
}

fn detect_report_input<R: Read>(
    reader: R,
    configured_format: Option<JtlFormat>,
) -> Result<(ReportInput<R>, JtlFormat), RunError> {
    let input = ReportInput::new(reader, configured_format).map_err(report_input_error)?;
    let format = input.format();
    Ok((input, format))
}

fn report_input_error(error: ReportInputError) -> RunError {
    let message = match error.io_kind() {
        Some(kind) => format!("{}: {kind:?}", error),
        None => error.to_string(),
    };
    RunError::Report {
        code: error.code(),
        message: bounded(message, MAX_DIAGNOSTIC_BYTES),
    }
}

fn configured_report_input_format(resolved: &ResolvedConfig) -> Option<JtlFormat> {
    match configured_save_wire_format(resolved, SaveWireFormat::Unknown) {
        SaveWireFormat::Csv => Some(JtlFormat::Csv),
        SaveWireFormat::Xml => Some(JtlFormat::Xml),
        SaveWireFormat::Properties | SaveWireFormat::Unknown => None,
    }
}

const fn save_wire_format(format: JtlFormat) -> SaveWireFormat {
    match format {
        JtlFormat::Csv => SaveWireFormat::Csv,
        JtlFormat::Xml => SaveWireFormat::Xml,
    }
}

fn reconcile_report_format(
    observed: JtlFormat,
    configuration: &SampleSaveConfiguration,
) -> Result<(), RunError> {
    if configuration.format() == observed {
        return Ok(());
    }
    Err(report_input_error(ReportInputError::FormatMismatch {
        configured: configuration.format(),
        observed,
    }))
}

/// Generates the report from the exact result handle after the run-owned JTL
/// sink has finalized and published it. The caller retains that descriptor
/// below the sink/pool finalization boundary, so report decoding cannot race a
/// still-live writer or accidentally follow a replaced result path.
pub(crate) fn report_from_published_result(
    target: &PreparedReportTarget,
    result: &mut PreparedResultTarget,
    resolved: &ResolvedConfig,
) -> Result<ReportStats, RunError> {
    let diagnostic_path = result.path.clone();
    let mut report_reader = result.take_report_reader()?;
    report_reader
        .seek(SeekFrom::Start(0))
        .map_err(|error| RunError::io(&diagnostic_path, error))?;
    let configured_format = configured_report_input_format(resolved);
    let (input, input_format) =
        detect_report_input(BufReader::new(report_reader), configured_format)?;
    let save_configuration = save_configuration(resolved, save_wire_format(input_format))?;
    reconcile_report_format(input_format, save_configuration.wire())?;
    write_report_dashboard(target, input, save_configuration.wire())
}

/// The complete save-configuration result used by the report adapter.
///
/// The codec configuration is accompanied by the resolver output rather than
/// replacing it.  In particular, unknown save-service properties remain in
/// the bounded resolution and are not silently discarded just because the
/// current CSV/XML codec has no typed field for them.
pub(crate) struct ResolvedSaveConfiguration {
    wire: SampleSaveConfiguration,
    _resolution: SaveConfigResolution,
}

impl ResolvedSaveConfiguration {
    pub(crate) fn wire(&self) -> &SampleSaveConfiguration {
        &self.wire
    }
}

/// Builds the explicit HTTP result projection for one admitted save policy.
/// Production samplers must receive this value; using the HTTP crate's
/// convenience default here would silently ignore JMeter save-service flags.
pub(crate) fn sample_result_projection(
    configuration: &ResolvedSaveConfiguration,
) -> SampleResultProjectionOptions {
    let wire = configuration.wire();
    SampleResultProjectionOptions {
        data_limits: DataLimits::default_bounded(),
        include_response_data: wire.save_response_data(),
        include_response_headers: wire.save_response_headers(),
        timestamp_source: if wire.timestamp_start() {
            TimestampSource::Start
        } else {
            TimestampSource::End
        },
        include_request_metadata: wire.save_request_headers()
            || wire.save_sampler_data()
            || wire.save_url(),
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

pub(crate) fn save_configuration(
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

pub(crate) fn configured_save_wire_format(
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

fn jtl_limits() -> JtlLimits {
    JtlLimits {
        // Report decoding has an explicit finite input/aggregation policy.
        // It is intentionally independent from the run-owned streaming sink:
        // a persistent JTL may grow beyond both the old 64 KiB whole-run cap
        // and the codec's bounded convenience output ceiling.
        max_input_bytes: MAX_JTL_INPUT_BYTES,
        max_output_bytes: MAX_JTL_OUTPUT_BYTES,
        max_record_bytes: MAX_JTL_RECORD_BYTES,
        max_attribute_bytes: MAX_JTL_ATTRIBUTE_BYTES,
        max_nodes: MAX_REPORT_AGGREGATION_ENTRIES.min(MAX_JTL_NODES),
        max_samples: MAX_REPORT_AGGREGATION_ENTRIES.min(MAX_JTL_SAMPLES),
        ..JtlLimits::default()
    }
}

/// Validates the checked-in standalone projection and performs whole-plan
/// path admission before any logger, output sink, listener, or engine setup.
/// The projection is embedded at build time; no ambient capability file is
/// read or discovered at runtime.
pub(crate) fn preflight_native_plan(
    document: &SemanticDocument,
    source: &[u8],
    http_selector: HttpCapabilitySelector,
) -> Result<CompiledHttpAdmission, RunError> {
    let http_admission = compile_http_admission(document, http_selector)?;
    preflight_native_plan_with_http_ids(document, source, &http_admission.node_ids())?;
    Ok(http_admission)
}

/// Performs the generic standalone capability admission after an application
/// HTTP compiler has produced its exact source NodeId set.  NativeV1 and
/// NativeV2 use different pure HTTP compilers, but every non-HTTP path passes
/// through this same atomic manifest boundary.
pub(crate) fn preflight_native_plan_with_http_ids(
    document: &SemanticDocument,
    source: &[u8],
    http_ids: &BTreeSet<NodeId>,
) -> Result<(), RunError> {
    standalone_plan_manifest(document, source, http_ids).map(|_| ())
}

/// Builds and atomically admits the complete standalone implementation-path
/// manifest.  HTTP entries remain in the returned manifest for accounting;
/// only non-HTTP entries are checked against the generic runtime capability
/// set because the application-owned HTTP recipes carry their own provider
/// identities.
fn standalone_plan_manifest(
    document: &SemanticDocument,
    source: &[u8],
    http_ids: &BTreeSet<NodeId>,
) -> Result<PlanPathManifest, RunError> {
    let identity = standalone_manifest_identity()
        .map_err(|error| RunError::unsupported(error.code(), error.to_string()))?;
    let plan_digest = Digest32::sha256(source);
    let provider = ProviderIdentity::new("standalone-native", "1").map_err(|error| {
        RunError::unsupported(
            "capability-set",
            format!("provider identity is invalid ({error})"),
        )
    })?;
    let context = PlanPathContext::new(
        identity.profile().clone(),
        plan_digest,
        provider,
        identity.capability_set_digest(),
    )
    .map_err(|error| RunError::unsupported("capability-set", error.to_string()))?;
    let tree = document.tree();
    let opaque = tree
        .preorder_ids()
        .into_iter()
        .filter(|id| document.is_opaque(*id) && !http_ids.contains(id))
        .collect::<BTreeSet<_>>();
    let source_view = SemanticSource::new(tree).with_opaque(&opaque);
    let manifest = PlanCompiler::builtins()
        .preflight_paths(&source_view, &context)
        .map_err(|error| RunError::unsupported("plan-admission", error.to_string()))?;
    if let Some(source) = manifest
        .opaque_sources()
        .iter()
        .find(|source| !source.node_id().is_some_and(|id| http_ids.contains(&id)))
    {
        return Err(RunError::unsupported(
            "jmx.opaque-element",
            format!("enabled opaque source is not executable: {source:?}"),
        ));
    }
    let capabilities = standalone_runtime_capability_set(plan_digest)
        .map_err(|error| RunError::unsupported(error.code(), error.to_string()))?;
    // PlanCompiler's built-in registry intentionally labels the HTTP sampler
    // with its generic `runtime.local-plan` path.  Keep that path out of the
    // generic native admission set and let the application-owned HTTP record
    // carry the explicit provider substitution instead.  Every non-HTTP path
    // is still checked atomically against the complete standalone set.
    let non_http_entries = manifest
        .entries()
        .iter()
        .filter(|entry| !is_http_path_entry(entry, &http_ids))
        .cloned()
        .collect::<Vec<_>>();
    capabilities.admit(non_http_entries).map_err(|error| {
        RunError::unsupported("plan-admission", format!("{}: {error}", error.code()))
    })?;
    Ok(manifest)
}

fn is_http_path_entry(entry: &ImplementationPathIdentity, http_ids: &BTreeSet<NodeId>) -> bool {
    match &entry.source {
        SourceIdentity::Node { node_id } => http_ids.contains(node_id),
        SourceIdentity::RunLevel { .. } => false,
    }
}

fn compile_http_admission(
    document: &SemanticDocument,
    selector: HttpCapabilitySelector,
) -> Result<CompiledHttpAdmission, RunError> {
    let tree = document.tree();
    let ids = tree.preorder_ids();
    let http_ids = ids
        .iter()
        .copied()
        .filter(|id| {
            tree.node(*id).ok().is_some_and(|node| {
                node.value().is_enabled() && is_http_sampler_class(node.value().test_class())
            })
        })
        .collect::<Vec<_>>();
    if http_ids.is_empty() {
        return Ok(CompiledHttpAdmission {
            selector,
            nodes: Vec::new(),
        });
    }

    // The standalone HTTP candidate intentionally has no manager state yet.
    // Detect every active manager before decoding samplers so a manager can
    // never be silently ignored by the provider substitution.
    for id in ids.iter().copied() {
        let node = tree.node(id).map_err(|error| RunError::Jmx {
            message: bounded(error.to_string(), MAX_DIAGNOSTIC_BYTES),
        })?;
        let element = node.value();
        if !element.is_enabled() {
            continue;
        }
        if is_http_tls_store_class(element.test_class()) {
            return Err(RunError::http(
                HTTP_NATIVE_TLS_STORE,
                format!("enabled HTTP TLS-store element at node {id} is not represented"),
            ));
        }
        if is_http_dns_manager_class(element.test_class()) {
            if property_bool(element, "DNSCacheManager.isCustomResolver", id)?.unwrap_or(false) {
                return Err(RunError::http(
                    HTTP_NATIVE_CUSTOM_RESOLVER,
                    format!("custom DNS resolver at node {id} is not represented"),
                ));
            }
            return Err(RunError::http(
                HTTP_NATIVE_UNSUPPORTED_MANAGER,
                format!("enabled DNS cache manager at node {id} is not represented"),
            ));
        }
        if is_http_manager_class(element.test_class()) {
            return Err(RunError::http(
                HTTP_NATIVE_UNSUPPORTED_MANAGER,
                format!(
                    "enabled HTTP manager at node {id} ({}) is not represented",
                    element.test_class()
                ),
            ));
        }
    }

    // Request Defaults are deliberately rejected in this bootstrap.  The
    // generic scope compiler can classify ConfigTestElement, but the app
    // factory has no scope-correct configuration implementation and must not
    // accidentally apply a global default to a nested sampler.
    for id in ids.iter().copied() {
        let node = tree.node(id).map_err(|error| RunError::Jmx {
            message: bounded(error.to_string(), MAX_DIAGNOSTIC_BYTES),
        })?;
        let element = node.value();
        if !element.is_enabled() || !is_http_request_defaults_class(element.test_class()) {
            continue;
        }
        return Err(RunError::http(
            HTTP_NATIVE_DEFAULTS,
            format!(
                "enabled ConfigTestElement at node {id} requires scope-correct defaults support"
            ),
        ));
    }

    let mut nodes = Vec::with_capacity(http_ids.len());
    for id in http_ids {
        let node = tree.node(id).map_err(|error| RunError::Jmx {
            message: bounded(error.to_string(), MAX_DIAGNOSTIC_BYTES),
        })?;
        let sampler = node.value();
        if has_unsupported_http_extensions(sampler) {
            return Err(RunError::http(
                HTTP_NATIVE_UNSUPPORTED_FIELD,
                format!("HTTP node {id} has opaque sampler extensions"),
            ));
        }
        validate_http_properties(id, sampler, false)?;
        let source = decode_http_source(id, sampler, None)?;
        if selector == HttpCapabilitySelector::Absent {
            return Err(RunError::http(
                HTTP_COMPATIBILITY_PACK_REQUIRED,
                format!(
                    "HTTP node {id} selects {} ({}) and requires the optional compatibility pack",
                    source.implementation, source.capability
                ),
            ));
        }
        let request = decode_native_http_request(id, sampler, None)?;
        let prepared_request = native_http_request(&request).map_err(|error| {
            RunError::http(
                error.stable_code(),
                format!("HTTP node {id} request cannot be represented by native HTTP"),
            )
        })?;
        let transport_limits = native_http_transport_limits();
        let client_config =
            native_http_client_config(&request, transport_limits).map_err(|error| {
                RunError::http(
                    error.stable_code(),
                    format!("HTTP node {id} client policy cannot be represented by native HTTP"),
                )
            })?;
        nodes.push(HttpNodeAdmission {
            node_id: id,
            source_implementation: source.implementation,
            source_implementation_defaulted: source.defaulted,
            source_capability: source.capability,
            executed_capability: HTTP_NATIVE_CAPABILITY,
            request,
            prepared_request,
            client_config,
            transport_limits,
        });
    }

    Ok(CompiledHttpAdmission { selector, nodes })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HttpSourceSelection {
    implementation: String,
    defaulted: bool,
    capability: String,
}

fn is_http_sampler_class(class: &str) -> bool {
    matches!(
        class.rsplit('.').next(),
        Some("HTTPSamplerProxy" | "HTTPHC4Impl")
    )
}

fn is_http_request_defaults_class(class: &str) -> bool {
    matches!(class.rsplit('.').next(), Some("ConfigTestElement"))
}

fn is_http_dns_manager_class(class: &str) -> bool {
    matches!(class.rsplit('.').next(), Some("DNSCacheManager"))
}

fn is_http_tls_store_class(class: &str) -> bool {
    matches!(
        class.rsplit('.').next(),
        Some("SSLManager" | "KeystoreConfig" | "KeystoreConfiguration" | "KeyStoreConfig")
    )
}

fn is_http_manager_class(class: &str) -> bool {
    matches!(
        class.rsplit('.').next(),
        Some(
            "HeaderManager"
                | "HTTPHeaderManager"
                | "CookieManager"
                | "CacheManager"
                | "AuthManager"
        )
    )
}

fn has_unsupported_http_extensions(element: &TestElement) -> bool {
    element.opaque_extensions.iter().any(|extension| {
        extension.type_name != "xml:raw"
            || extension.raw.iter().any(|byte| !byte.is_ascii_whitespace())
    })
}

fn decode_http_source(
    id: NodeId,
    sampler: &TestElement,
    defaults: Option<&TestElement>,
) -> Result<HttpSourceSelection, RunError> {
    let source = sampler
        .property("HTTPSampler.implementation")
        .or_else(|| defaults.and_then(|element| element.property("HTTPSampler.implementation")));
    let defaulted = source.is_none();
    let implementation = match source {
        Some(value) => property_string(value, "HTTPSampler.implementation", id)?,
        None => DEFAULT_HTTP_IMPLEMENTATION.to_owned(),
    };
    if implementation.is_empty() {
        return Err(RunError::http(
            HTTP_NATIVE_SOURCE_IMPLEMENTATION,
            format!("HTTP node {id} has an empty implementation selection"),
        ));
    }
    let capability = match implementation.as_str() {
        "Java" => "http.jmeter-java/5.6.3",
        "HttpClient4" => "http.jmeter-httpclient4/5.6.3",
        _ => {
            return Err(RunError::http(
                HTTP_NATIVE_SOURCE_IMPLEMENTATION,
                format!("HTTP node {id} has an unsupported source implementation"),
            ));
        }
    };
    Ok(HttpSourceSelection {
        implementation,
        defaulted,
        capability: capability.to_owned(),
    })
}

fn validate_http_properties(
    id: NodeId,
    element: &TestElement,
    defaults: bool,
) -> Result<(), RunError> {
    if !defaults && has_unsupported_http_extensions(element) {
        return Err(RunError::http(
            HTTP_NATIVE_UNSUPPORTED_FIELD,
            format!("HTTP node {id} has opaque sampler extensions"),
        ));
    }
    if defaults && has_unsupported_http_extensions(element) {
        return Err(RunError::http(
            HTTP_NATIVE_DEFAULTS,
            format!("HTTP Request Defaults at node {id} has opaque extensions"),
        ));
    }
    for entry in element.properties.iter() {
        let name = entry.name.as_str();
        if name == "HTTPsampler.Arguments" {
            validate_http_arguments(id, &entry.value)?;
            continue;
        }
        if name == "HTTPSampler.auto_redirects" {
            if property_bool_value(&entry.value, name, id)? {
                return Err(RunError::http(
                    HTTP_NATIVE_AUTO_REDIRECTS,
                    format!("HTTP node {id} enables automatic client redirects"),
                ));
            }
            continue;
        }
        if name == "HTTPSampler.DO_MULTIPART_POST" {
            if property_bool_value(&entry.value, name, id)? {
                return Err(RunError::http(
                    HTTP_NATIVE_MULTIPART_UNSUPPORTED,
                    format!("HTTP node {id} enables multipart request construction"),
                ));
            }
            continue;
        }
        if name == "HTTPSampler.files" || name.ends_with("HTTPFileArg") {
            return Err(RunError::http(
                HTTP_NATIVE_FILES_UNSUPPORTED,
                format!("HTTP node {id} contains a file request field"),
            ));
        }
        if name == "HTTPSampler.embedded_url_re" || name == "HTTPSampler.embedded_url_exclude_re" {
            let value = property_string(&entry.value, name, id)?;
            if !value.is_empty() {
                return Err(RunError::http(
                    HTTP_NATIVE_EMBEDDED_RESOURCES,
                    format!("HTTP node {id} enables embedded-resource extraction"),
                ));
            }
            continue;
        }
        if name == "HTTPSampler.concurrentDwn" || name == "HTTPSampler.image_parser" {
            if property_bool_value(&entry.value, name, id)? {
                return Err(RunError::http(
                    HTTP_NATIVE_EMBEDDED_RESOURCES,
                    format!("HTTP node {id} enables embedded-resource handling"),
                ));
            }
            continue;
        }
        if name.starts_with("HTTPSampler.proxy")
            || name == "HTTPSampler.nonProxyHosts"
            || name == "HTTPSampler.sourceIp"
            || name == "HTTPSampler.sourceIpType"
        {
            return Err(RunError::http(
                HTTP_NATIVE_UNSUPPORTED_FIELD,
                format!("HTTP node {id} has an unsupported route field"),
            ));
        }
        if name.to_ascii_lowercase().contains("keystore")
            || name.to_ascii_lowercase().contains("truststore")
            || name.to_ascii_lowercase().contains("ssl")
        {
            return Err(RunError::http(
                HTTP_NATIVE_TLS_STORE,
                format!("HTTP node {id} has an unsupported TLS-store field"),
            ));
        }
        if name == "HTTPSampler.postBodyRaw" {
            if property_bool_value(&entry.value, name, id)? {
                return Err(RunError::http(
                    HTTP_NATIVE_REQUEST_BODY,
                    format!("HTTP node {id} enables a raw request body"),
                ));
            }
            continue;
        }
        if !is_supported_http_field(name, defaults) {
            return Err(RunError::http(
                HTTP_NATIVE_UNSUPPORTED_FIELD,
                format!("HTTP node {id} has an unsupported active field"),
            ));
        }
    }
    Ok(())
}

fn is_supported_http_field(name: &str, defaults: bool) -> bool {
    // Request Defaults and HTTPSamplerProxy intentionally share only this
    // scalar wire subset.  `defaults` is kept explicit in the signature so a
    // future field cannot accidentally become accepted on both boundaries.
    let _ = defaults;
    matches!(
        name,
        "HTTPSampler.domain"
            | "HTTPSampler.port"
            | "HTTPSampler.protocol"
            | "HTTPSampler.method"
            | "HTTPSampler.contentEncoding"
            | "HTTPSampler.path"
            | "HTTPSampler.implementation"
            | "HTTPSampler.connect_timeout"
            | "HTTPSampler.response_timeout"
            | "HTTPSampler.follow_redirects"
            | "HTTPSampler.use_keepalive"
            | "HTTPSampler.concurrentPool"
    )
}

fn validate_http_arguments(id: NodeId, value: &PropertyValue) -> Result<(), RunError> {
    let element = value.as_element().map_err(|error| {
        RunError::http(
            HTTP_NATIVE_REQUEST_BODY,
            format!("HTTP node {id} has an invalid argument descriptor ({error})"),
        )
    })?;
    if !element.opaque_extensions.is_empty() {
        return Err(RunError::http(
            HTTP_NATIVE_REQUEST_BODY,
            format!("HTTP node {id} has opaque request arguments"),
        ));
    }
    for entry in element.properties.iter() {
        if entry.name != "Arguments.arguments" {
            return Err(RunError::http(
                HTTP_NATIVE_REQUEST_BODY,
                format!("HTTP node {id} has an unsupported argument field"),
            ));
        }
        let arguments = entry.value.as_collection().map_err(|error| {
            RunError::http(
                HTTP_NATIVE_REQUEST_BODY,
                format!("HTTP node {id} has an invalid argument collection ({error})"),
            )
        })?;
        if arguments.iter().any(|argument| {
            argument
                .as_element()
                .ok()
                .is_some_and(|argument| argument.name.rsplit('.').next() == Some("HTTPFileArg"))
        }) {
            return Err(RunError::http(
                HTTP_NATIVE_FILES_UNSUPPORTED,
                format!("HTTP node {id} contains a file argument"),
            ));
        }
        if !arguments.is_empty() {
            return Err(RunError::http(
                HTTP_NATIVE_REQUEST_BODY,
                format!("HTTP node {id} has request arguments"),
            ));
        }
    }
    Ok(())
}

fn effective_http_property<'a>(
    sampler: &'a TestElement,
    defaults: Option<&'a TestElement>,
    name: &str,
) -> Option<&'a PropertyValue> {
    sampler
        .property(name)
        .or_else(|| defaults.and_then(|element| element.property(name)))
}

fn decode_native_http_request(
    id: NodeId,
    sampler: &TestElement,
    defaults: Option<&TestElement>,
) -> Result<NativeHttpRequestCandidate, RunError> {
    let domain = effective_http_property(sampler, defaults, "HTTPSampler.domain")
        .map(|value| property_string(value, "HTTPSampler.domain", id))
        .transpose()?
        .unwrap_or_default();
    if domain.is_empty()
        || domain.len() > MAX_HTTP_DOMAIN_BYTES
        || domain.contains(char::is_whitespace)
    {
        return Err(RunError::http(
            HTTP_NATIVE_INVALID_FIELD,
            format!("HTTP node {id} requires a bounded origin domain"),
        ));
    }
    if domain.parse::<IpAddr>().is_err() {
        return Err(RunError::http(
            HTTP_NATIVE_HOSTNAME,
            format!("HTTP node {id} requires a numeric IPv4 or IPv6 origin"),
        ));
    }
    let protocol = effective_http_property(sampler, defaults, "HTTPSampler.protocol")
        .map(|value| property_string(value, "HTTPSampler.protocol", id))
        .transpose()?
        .unwrap_or_else(|| DEFAULT_HTTP_PROTOCOL.to_owned());
    if !protocol.eq_ignore_ascii_case("http") {
        return Err(RunError::http(
            HTTP_NATIVE_INVALID_FIELD,
            format!("HTTP node {id} requires plain HTTP/1.1"),
        ));
    }
    let method = effective_http_property(sampler, defaults, "HTTPSampler.method")
        .map(|value| property_string(value, "HTTPSampler.method", id))
        .transpose()?
        .unwrap_or_else(|| DEFAULT_HTTP_METHOD.to_owned());
    if !matches!(method.as_str(), "GET" | "HEAD" | "DELETE" | "OPTIONS") {
        return Err(RunError::http(
            HTTP_NATIVE_INVALID_FIELD,
            format!("HTTP node {id} uses a method outside the no-body subset"),
        ));
    }
    let content_encoding =
        effective_http_property(sampler, defaults, "HTTPSampler.contentEncoding")
            .map(|value| property_string(value, "HTTPSampler.contentEncoding", id))
            .transpose()?
            .unwrap_or_else(|| DEFAULT_HTTP_CONTENT_ENCODING.to_owned());
    if !content_encoding.eq_ignore_ascii_case(DEFAULT_HTTP_CONTENT_ENCODING) {
        return Err(RunError::http(
            HTTP_NATIVE_INVALID_FIELD,
            format!("HTTP node {id} uses an unsupported request encoding"),
        ));
    }
    let raw_path = effective_http_property(sampler, defaults, "HTTPSampler.path")
        .map(|value| property_string(value, "HTTPSampler.path", id))
        .transpose()?
        .unwrap_or_default();
    if raw_path.len() > MAX_HTTP_PATH_BYTES
        || raw_path.contains(char::is_control)
        // URL fragments are retained by the protocol model but are never
        // sent in an origin-form request target. Reject them at admission so
        // the adapter cannot silently drop a JMeter path suffix.
        || raw_path.contains('#')
        || (!raw_path.is_empty() && !raw_path.starts_with('/'))
    {
        return Err(RunError::http(
            HTTP_NATIVE_INVALID_FIELD,
            format!("HTTP node {id} has an invalid request path"),
        ));
    }
    let path = if raw_path.is_empty() {
        "/".to_owned()
    } else {
        raw_path
    };
    let port = effective_http_property(sampler, defaults, "HTTPSampler.port")
        .map(|value| property_port(value, "HTTPSampler.port", id))
        .transpose()?;
    let follow_redirects =
        effective_http_property(sampler, defaults, "HTTPSampler.follow_redirects")
            .map(|value| property_bool_value(value, "HTTPSampler.follow_redirects", id))
            .transpose()?
            .unwrap_or(DEFAULT_HTTP_FOLLOW_REDIRECTS);
    let auto_redirects = effective_http_property(sampler, defaults, "HTTPSampler.auto_redirects")
        .map(|value| property_bool_value(value, "HTTPSampler.auto_redirects", id))
        .transpose()?
        .unwrap_or(DEFAULT_HTTP_AUTO_REDIRECTS);
    if auto_redirects {
        return Err(RunError::http(
            HTTP_NATIVE_AUTO_REDIRECTS,
            format!("HTTP node {id} enables automatic client redirects"),
        ));
    }
    if follow_redirects {
        return Err(RunError::http(
            HTTP_NATIVE_REDIRECTS,
            format!("HTTP node {id} enables redirect history not represented by native HTTP"),
        ));
    }
    let use_keepalive = effective_http_property(sampler, defaults, "HTTPSampler.use_keepalive")
        .map(|value| property_bool_value(value, "HTTPSampler.use_keepalive", id))
        .transpose()?
        .unwrap_or(DEFAULT_HTTP_KEEPALIVE);
    if !use_keepalive {
        return Err(RunError::http(
            HTTP_NATIVE_KEEPALIVE,
            format!("HTTP node {id} disables keep-alive semantics not represented by native HTTP"),
        ));
    }
    let concurrent_pool =
        if effective_http_property(sampler, defaults, "HTTPSampler.concurrentPool").is_some() {
            return Err(RunError::http(
                HTTP_NATIVE_UNSUPPORTED_FIELD,
                format!("HTTP node {id} configures embedded-resource concurrency"),
            ));
        } else {
            None
        };
    let connect_timeout_ms =
        effective_http_property(sampler, defaults, "HTTPSampler.connect_timeout")
            .map(|value| property_timeout(value, "HTTPSampler.connect_timeout", id))
            .transpose()?;
    let response_timeout_ms =
        effective_http_property(sampler, defaults, "HTTPSampler.response_timeout")
            .map(|value| property_timeout(value, "HTTPSampler.response_timeout", id))
            .transpose()?;
    Ok(NativeHttpRequestCandidate {
        domain,
        port,
        protocol,
        path,
        method,
        content_encoding,
        follow_redirects,
        auto_redirects,
        use_keepalive,
        concurrent_pool,
        connect_timeout_ms,
        response_timeout_ms,
    })
}

fn property_string(value: &PropertyValue, name: &str, id: NodeId) -> Result<String, RunError> {
    let value = value.as_str().map_err(|error| {
        RunError::http(
            HTTP_NATIVE_INVALID_FIELD,
            format!("HTTP node {id} field {name} is not a bounded string ({error})"),
        )
    })?;
    if value.len() > MAX_HTTP_FIELD_BYTES || value.chars().any(char::is_control) {
        return Err(RunError::http(
            HTTP_NATIVE_INVALID_FIELD,
            format!("HTTP node {id} field {name} exceeds its bound"),
        ));
    }
    if value.contains("${") {
        return Err(RunError::http(
            HTTP_NATIVE_DYNAMIC_FIELD,
            format!("HTTP node {id} field {name} contains an unexpanded expression"),
        ));
    }
    Ok(value.to_owned())
}

fn property_bool_value(value: &PropertyValue, name: &str, id: NodeId) -> Result<bool, RunError> {
    if let Ok(value) = value.as_bool() {
        return Ok(value);
    }
    if let Ok(value) = value.as_str() {
        return match value {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err(RunError::http(
                HTTP_NATIVE_INVALID_FIELD,
                format!("HTTP node {id} field {name} is not true or false"),
            )),
        };
    }
    Err(RunError::http(
        HTTP_NATIVE_INVALID_FIELD,
        format!("HTTP node {id} field {name} is not boolean"),
    ))
}

fn property_bool(element: &TestElement, name: &str, id: NodeId) -> Result<Option<bool>, RunError> {
    element
        .property(name)
        .map(|value| property_bool_value(value, name, id))
        .transpose()
}

fn property_u64(value: &PropertyValue, name: &str, id: NodeId) -> Result<u64, RunError> {
    if let Ok(value) = value.as_i32() {
        return u64::try_from(i64::from(value)).map_err(|_| {
            RunError::http(
                HTTP_NATIVE_INVALID_FIELD,
                format!("HTTP node {id} field {name} is negative"),
            )
        });
    }
    if let Ok(value) = value.as_i64() {
        return u64::try_from(value).map_err(|_| {
            RunError::http(
                HTTP_NATIVE_INVALID_FIELD,
                format!("HTTP node {id} field {name} is negative"),
            )
        });
    }
    if let Ok(value) = value.as_str() {
        return value.parse::<u64>().map_err(|_| {
            RunError::http(
                HTTP_NATIVE_INVALID_FIELD,
                format!("HTTP node {id} field {name} is not an unsigned integer"),
            )
        });
    }
    Err(RunError::http(
        HTTP_NATIVE_INVALID_FIELD,
        format!("HTTP node {id} field {name} is not an unsigned integer"),
    ))
}

fn property_port(value: &PropertyValue, name: &str, id: NodeId) -> Result<u16, RunError> {
    let value = property_u64(value, name, id)?;
    if value == 0 {
        return Err(RunError::http(
            HTTP_NATIVE_INVALID_FIELD,
            format!("HTTP node {id} field {name} must be non-zero"),
        ));
    }
    u16::try_from(value).map_err(|_| {
        RunError::http(
            HTTP_NATIVE_INVALID_FIELD,
            format!("HTTP node {id} field {name} is outside the port range"),
        )
    })
}

fn property_timeout(value: &PropertyValue, name: &str, id: NodeId) -> Result<u64, RunError> {
    let value = property_u64(value, name, id)?;
    if value > 86_400_000 {
        return Err(RunError::http(
            HTTP_NATIVE_INVALID_FIELD,
            format!("HTTP node {id} field {name} exceeds the timeout bound"),
        ));
    }
    Ok(value)
}

#[cfg(test)]
struct NativeHttpPoolGuard {
    pool: Option<HttpWorkerPool>,
    handle: NativeHttpPoolHandle,
}

#[cfg(test)]
impl NativeHttpPoolGuard {
    fn new(pool: HttpWorkerPool, handle: NativeHttpPoolHandle) -> Self {
        Self {
            pool: Some(pool),
            handle,
        }
    }

    fn empty(handle: NativeHttpPoolHandle) -> Self {
        Self { pool: None, handle }
    }

    fn finalize(&mut self) -> Result<(), RunError> {
        let Some(pool) = self.pool.take() else {
            return Ok(());
        };
        *self
            .handle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        pool.finalize()
            .map(|_| ())
            .map_err(|error| RunError::Runtime {
                code: error.code().to_owned(),
                message: bounded(
                    "native HTTP worker pool finalization failed".to_owned(),
                    MAX_DIAGNOSTIC_BYTES,
                ),
            })
    }
}

#[cfg(test)]
impl Drop for NativeHttpPoolGuard {
    fn drop(&mut self) {
        let _ = self.finalize();
    }
}

pub(crate) fn jtl_sink_error(error: JtlSinkError) -> RunError {
    RunError::Runtime {
        code: error.code().to_owned(),
        message: bounded(error.to_string(), MAX_DIAGNOSTIC_BYTES),
    }
}

/// Finishes or cancels the one run-owned writer and always drops the owner
/// only after its exact worker has been joined.  The owner itself is
/// deliberately `!Send`; only its submitter is placed in the router.
pub(crate) fn cleanup_jtl_owner(
    owner: &mut Option<JtlSinkOwner>,
    cancel: bool,
) -> Result<(), RunError> {
    let Some(owner_ref) = owner.as_ref() else {
        return Ok(());
    };
    let result = if cancel {
        owner_ref.cancel_and_join().map(|_| ())
    } else {
        owner_ref.finalize().map(|_| ())
    };
    // `finalize`/`cancel_and_join` have reaped the exact thread on every
    // normal path.  Drop the owner after that boundary so its defensive Drop
    // implementation cannot race a report reader or publication step.
    let _ = owner.take();
    result.map_err(jtl_sink_error)
}

const MAX_RESULT_STAGING_ATTEMPTS: u64 = 64;
static NEXT_RESULT_STAGING_ID: AtomicU64 = AtomicU64::new(0);

/// A result file is never written at the user-visible path. The staging entry
/// and final target share a parent directory, so publication is one
/// same-filesystem rename after the writer has finished and the exact staging
/// inode has been synchronized. Identity snapshots are the final path
/// admission boundary: a parent or previous-target replacement fails closed.
pub(crate) struct PreparedResultTarget {
    path: PathBuf,
    root: PathBuf,
    stage: PathBuf,
    parent: PathBuf,
    parent_identity: Option<(u64, u64)>,
    existing_identity: Option<(u64, u64)>,
    stage_identity: Option<(u64, u64)>,
    sync_file: Option<File>,
    /// Read-only descriptor bound to the exact staging inode.  It remains
    /// valid after publication because the final switch is a same-filesystem
    /// rename; report-at-end consumes this handle instead of reopening the
    /// published path.
    report_reader: Option<File>,
    published: bool,
}

impl PreparedResultTarget {
    pub(crate) fn prepare(
        path: &Path,
        mode: OutputOpenMode,
        cwd: &Path,
    ) -> Result<(Self, File), RunError> {
        let root = fs::canonicalize(cwd).map_err(|error| RunError::io(cwd, error))?;
        let parent = path
            .parent()
            .ok_or_else(|| RunError::io(path, invalid_path_error("result has no parent")))?
            .to_owned();
        let parent_directory = open_bound_directory(&parent, Some(&root))
            .map_err(|error| RunError::io(&parent, error))?;
        let parent_identity = metadata_identity(
            &fs::metadata(parent_directory.path()).map_err(|error| RunError::io(&parent, error))?,
        );

        let existing_identity = match bound_metadata(path, Some(&root)) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(RunError::Io {
                    path: path.to_owned(),
                    message: "result output must not be a symbolic link".to_owned(),
                });
            }
            Ok(metadata) if !metadata.is_file() => {
                return Err(RunError::Io {
                    path: path.to_owned(),
                    message: "result output must be a regular file".to_owned(),
                });
            }
            Ok(_) if matches!(mode, OutputOpenMode::CreateNew) => {
                return Err(RunError::Io {
                    path: path.to_owned(),
                    message: "result output already exists; use -f to replace it".to_owned(),
                });
            }
            Ok(metadata) => metadata_identity(&metadata),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(RunError::io(path, error)),
        };

        let serial = NEXT_RESULT_STAGING_ID.fetch_add(1, Ordering::Relaxed);
        let process = std::process::id();
        let mut last_collision = false;
        for attempt in 0..MAX_RESULT_STAGING_ATTEMPTS {
            let stage = parent.join(format!(
                ".jmeter-rs-result-{process}-{serial}-{attempt}.tmp"
            ));
            let file = match open_bound_create_new(&stage, &root) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    last_collision = true;
                    continue;
                }
                Err(error) => return Err(RunError::io(&stage, error)),
            };
            let stage_identity = match file.metadata() {
                Ok(metadata) => metadata_identity(&metadata),
                Err(error) => {
                    drop(file);
                    let primary = RunError::io(&stage, error);
                    return match cleanup_staging_path(&stage, &root, None) {
                        Ok(()) => Err(primary),
                        Err(cleanup) => Err(RunError::Runtime {
                            code: "execution.jtl-staging-cleanup".to_owned(),
                            message: bounded(
                                format!(
                                    "staging metadata failed: {primary}; staging cleanup failed: {cleanup}"
                                ),
                                MAX_DIAGNOSTIC_BYTES,
                            ),
                        }),
                    };
                }
            };
            // `open_bound_create_new` intentionally returns the writer with
            // write-only access. Open a separate descriptor-bound read handle
            // before the sink starts, and verify that it is the same inode as
            // the newly-created stage. This is the exact handle retained for
            // report-at-end; the final target is never reopened by path.
            let report_reader = match open_bound_read(&stage, std::slice::from_ref(&root)) {
                Ok(reader) => match reader.metadata() {
                    Ok(metadata) if metadata_identity(&metadata) == stage_identity => reader,
                    Ok(_) => {
                        drop(reader);
                        let primary = RunError::Io {
                            path: stage.clone(),
                            message: "result report handle changed during staging admission"
                                .to_owned(),
                        };
                        drop(file);
                        return match cleanup_staging_path(&stage, &root, stage_identity) {
                            Ok(()) => Err(primary),
                            Err(cleanup) => Err(RunError::Runtime {
                                code: "execution.jtl-staging-cleanup".to_owned(),
                                message: bounded(
                                    format!(
                                        "report handle admission failed: {primary}; staging cleanup failed: {cleanup}"
                                    ),
                                    MAX_DIAGNOSTIC_BYTES,
                                ),
                            }),
                        };
                    }
                    Err(error) => {
                        drop(reader);
                        let primary = RunError::io(&stage, error);
                        drop(file);
                        return match cleanup_staging_path(&stage, &root, stage_identity) {
                            Ok(()) => Err(primary),
                            Err(cleanup) => Err(RunError::Runtime {
                                code: "execution.jtl-staging-cleanup".to_owned(),
                                message: bounded(
                                    format!(
                                        "report handle metadata failed: {primary}; staging cleanup failed: {cleanup}"
                                    ),
                                    MAX_DIAGNOSTIC_BYTES,
                                ),
                            }),
                        };
                    }
                },
                Err(error) => {
                    let primary = RunError::io(&stage, error);
                    drop(file);
                    return match cleanup_staging_path(&stage, &root, stage_identity) {
                        Ok(()) => Err(primary),
                        Err(cleanup) => Err(RunError::Runtime {
                            code: "execution.jtl-staging-cleanup".to_owned(),
                            message: bounded(
                                format!(
                                    "report handle open failed: {primary}; staging cleanup failed: {cleanup}"
                                ),
                                MAX_DIAGNOSTIC_BYTES,
                            ),
                        }),
                    };
                }
            };
            let sync_file = match file.try_clone() {
                Ok(sync_file) => sync_file,
                Err(error) => {
                    drop(file);
                    let cleanup = cleanup_staging_path(&stage, &root, stage_identity);
                    return match cleanup {
                        Ok(()) => Err(RunError::io(&stage, error)),
                        Err(cleanup) => Err(RunError::Runtime {
                            code: "execution.jtl-staging-cleanup".to_owned(),
                            message: bounded(
                                format!(
                                    "staging handle clone failed: {error}; staging cleanup failed: {cleanup}"
                                ),
                                MAX_DIAGNOSTIC_BYTES,
                            ),
                        }),
                    };
                }
            };
            return Ok((
                Self {
                    path: path.to_owned(),
                    root,
                    stage,
                    parent,
                    parent_identity,
                    existing_identity,
                    stage_identity,
                    sync_file: Some(sync_file),
                    report_reader: Some(report_reader),
                    published: false,
                },
                file,
            ));
        }

        let message = if last_collision {
            format!(
                "could not reserve a private result staging file after {MAX_RESULT_STAGING_ATTEMPTS} attempts"
            )
        } else {
            "could not reserve a private result staging file".to_owned()
        };
        Err(RunError::Io {
            path: parent,
            message: bounded(message, MAX_DIAGNOSTIC_BYTES),
        })
    }

    pub(crate) fn publish(&mut self) -> Result<(), RunError> {
        if self.published {
            return Ok(());
        }
        let sync_file = self.sync_file.take().ok_or_else(|| RunError::Runtime {
            code: "execution.jtl-publication".to_owned(),
            message: "result staging handle was already closed".to_owned(),
        })?;
        sync_file
            .sync_all()
            .map_err(|error| RunError::io(&self.stage, error))?;
        // A buffered flush alone is not sufficient publication durability;
        // close this exact clone before revalidation and rename.
        drop(sync_file);
        self.revalidate_for_publish()?;
        rename_bound(&self.stage, &self.path, &self.root)
            .map_err(|error| RunError::io(&self.path, error))?;
        self.published = true;
        Ok(())
    }

    pub(crate) fn take_report_reader(&mut self) -> Result<File, RunError> {
        if !self.published {
            return Err(RunError::Runtime {
                code: "execution.jtl-publication".to_owned(),
                message: "report-at-end requested before result publication".to_owned(),
            });
        }
        self.report_reader.take().ok_or_else(|| RunError::Runtime {
            code: "execution.jtl-publication".to_owned(),
            message: "exact published result handle was already consumed".to_owned(),
        })
    }

    pub(crate) fn cleanup(&mut self) -> Result<(), RunError> {
        self.sync_file.take();
        self.report_reader.take();
        if self.published {
            return Ok(());
        }
        cleanup_staging_path(&self.stage, &self.root, self.stage_identity)
    }

    fn revalidate_for_publish(&self) -> Result<(), RunError> {
        let parent_directory = open_bound_directory(&self.parent, Some(&self.root))
            .map_err(|error| RunError::io(&self.parent, error))?;
        let current_parent_identity = metadata_identity(
            &fs::metadata(parent_directory.path())
                .map_err(|error| RunError::io(&self.parent, error))?,
        );
        if self.parent_identity.is_some() && current_parent_identity != self.parent_identity {
            return Err(RunError::Io {
                path: self.parent.clone(),
                message: "result output parent changed before publication".to_owned(),
            });
        }

        match bound_metadata(&self.stage, Some(&self.root)) {
            Ok(metadata)
                if metadata.file_type().is_symlink()
                    || !metadata.is_file()
                    || (self.stage_identity.is_some()
                        && metadata_identity(&metadata) != self.stage_identity) =>
            {
                return Err(RunError::Io {
                    path: self.stage.clone(),
                    message: "result staging entry changed before publication".to_owned(),
                });
            }
            Ok(_) => {}
            Err(error) => return Err(RunError::io(&self.stage, error)),
        }

        match (
            self.existing_identity,
            bound_metadata(&self.path, Some(&self.root)),
        ) {
            (Some(expected), Ok(metadata))
                if !metadata.file_type().is_symlink()
                    && metadata.is_file()
                    && metadata_identity(&metadata) == Some(expected) => {}
            (None, Err(error)) if error.kind() == io::ErrorKind::NotFound => {}
            (Some(_), Err(error)) if error.kind() == io::ErrorKind::NotFound => {
                return Err(RunError::Io {
                    path: self.path.clone(),
                    message: "previous result output disappeared before publication".to_owned(),
                });
            }
            _ => {
                return Err(RunError::Io {
                    path: self.path.clone(),
                    message: "result output changed before publication".to_owned(),
                });
            }
        }
        Ok(())
    }
}

impl Drop for PreparedResultTarget {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

fn invalid_path_error(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn cleanup_staging_path(
    path: &Path,
    root: &Path,
    expected_identity: Option<(u64, u64)>,
) -> Result<(), RunError> {
    match bound_metadata(path, Some(root)) {
        Ok(metadata)
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || (expected_identity.is_some()
                    && metadata_identity(&metadata) != expected_identity) =>
        {
            Err(RunError::Io {
                path: path.to_owned(),
                message: "result staging entry changed during cleanup".to_owned(),
            })
        }
        Ok(_) => remove_bound_file(path, root).map_err(|error| RunError::io(path, error)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(RunError::io(path, error)),
    }
}

#[cfg(test)]
fn cleanup_prepared_target(target: &mut Option<PreparedResultTarget>) -> Result<(), RunError> {
    let Some(mut target) = target.take() else {
        return Ok(());
    };
    target.cleanup()
}

#[cfg(test)]
fn combine_execution_errors(
    primary: Option<RunError>,
    secondary: RunError,
    code: &'static str,
    label: &'static str,
) -> Option<RunError> {
    Some(match primary {
        Some(primary) => RunError::Runtime {
            code: code.to_owned(),
            message: bounded(
                format!("primary={primary}; {label} cleanup failed: {secondary}"),
                MAX_DIAGNOSTIC_BYTES,
            ),
        },
        None => secondary,
    })
}

fn local_run(
    invocation: &CliInvocation,
    launch: &LaunchEnvironment,
    loader: &ConfigLoader,
    resolved: &ResolvedConfig,
    http_selector: HttpCapabilitySelector,
) -> Result<RunOutcome, RunError> {
    crate::run_transaction::run_local(invocation, launch, loader, resolved, http_selector)
}

#[cfg(test)]
pub(crate) fn local_run_legacy(
    invocation: &CliInvocation,
    launch: &LaunchEnvironment,
    loader: &ConfigLoader,
    resolved: &ResolvedConfig,
    http_selector: HttpCapabilitySelector,
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
    let http_admission = preflight_native_plan(&document, &source, http_selector)?;
    let http_pool_handle = Arc::new(Mutex::new(None));
    let (engine_plan, packages) = compile_local_plan_with_http(
        &document,
        Some(&http_admission),
        Arc::clone(&http_pool_handle),
    )?;
    let executor_policy = executor_policy_for_plan(&engine_plan, &http_admission)?;

    // Resolve every output target only after the complete JMX tree has been
    // classified and compiled. This is the standalone admission boundary: an
    // unsupported sampler/controller cannot create a result staging entry or
    // reserve a report folder.
    let result_path = invocation
        .options
        .logfile
        .as_ref()
        .map(|argument| resolve_path_argument(argument, ".jtl", launch))
        .transpose()?;
    let report_target = if invocation.options.report_at_end {
        Some(prepare_report_target(
            invocation.options.report_output_folder.as_deref(),
            launch,
            if invocation.options.force_delete_result_file {
                ReportOutputMode::ReplaceExisting
            } else {
                ReportOutputMode::CreateNew
            },
        )?)
    } else {
        None
    };

    // Resolve the save configuration before reserving the private staging
    // entry. The final target is never opened for writing by the run sink.
    let run_save_configuration = result_path
        .as_ref()
        .map(|_| configured_save_wire_format(resolved, SaveWireFormat::Csv))
        .map_or(Ok(None), |format| {
            save_configuration(resolved, format).map(|configuration| Some(configuration.wire))
        })?;
    let mut prepared_result = None;
    let mut jtl_owner = None;
    let result_router = if let (Some(path), Some(save_configuration)) =
        (result_path.as_ref(), run_save_configuration)
    {
        let mode = if invocation.options.force_delete_result_file {
            OutputOpenMode::ReplaceExisting
        } else {
            OutputOpenMode::CreateNew
        };
        let (mut prepared, file) = PreparedResultTarget::prepare(path, mode, &launch.cwd)?;
        let sink_limits = JtlSinkLimits::default();
        let owner = match JtlSinkOwner::new(Box::new(file), save_configuration, sink_limits) {
            Ok(owner) => owner,
            Err(error) => {
                let primary = jtl_sink_error(error);
                let cleanup = prepared.cleanup();
                return match cleanup {
                    Ok(()) => Err(primary),
                    Err(secondary) => Err(RunError::Runtime {
                        code: "execution.jtl-staging-cleanup".to_owned(),
                        message: bounded(
                            format!("primary={primary}; staging cleanup failed: {secondary}"),
                            MAX_DIAGNOSTIC_BYTES,
                        ),
                    }),
                };
            }
        };
        let router_limits = SinkLimits::new(sink_limits.max_items, sink_limits.max_bytes);
        let submitter = owner.submitter();
        let router = match ResultRouter::new(
            "jmeter-rs",
            [ResultSinkSpec::new(
                SinkId::new(1),
                router_limits,
                Arc::new(submitter),
            )],
        ) {
            Ok(router) => router,
            Err(error) => {
                let primary = RunError::Runtime {
                    code: "runtime.result-router".to_owned(),
                    message: bounded(error.to_string(), MAX_DIAGNOSTIC_BYTES),
                };
                let mut owner = Some(owner);
                let mut cleanup_error = None;
                if let Err(cleanup) = cleanup_jtl_owner(&mut owner, true) {
                    cleanup_error = combine_execution_errors(
                        cleanup_error,
                        cleanup,
                        "execution.cleanup",
                        "result sink",
                    );
                }
                if let Err(cleanup) = prepared.cleanup() {
                    cleanup_error = combine_execution_errors(
                        cleanup_error,
                        cleanup,
                        "execution.cleanup",
                        "result staging",
                    );
                }
                return match cleanup_error {
                    Some(secondary) => Err(RunError::Runtime {
                        code: "execution.cleanup".to_owned(),
                        message: bounded(
                            format!("primary={primary}; cleanup failed: {secondary}"),
                            MAX_DIAGNOSTIC_BYTES,
                        ),
                    }),
                    None => Err(primary),
                };
            }
        };
        jtl_owner = Some(owner);
        prepared_result = Some(prepared);
        Some(router)
    } else {
        None
    };

    // Worker threads are created only after complete plan/factory and output
    // target preflight. The handle is already captured by fresh per-user
    // sampler factories, but remains empty until this atomic boundary.
    let http_pool_guard = if http_admission.has_http() {
        // This reference path is no longer used by production dispatch. Keep
        // its test/reference construction explicit until all callers migrate
        // to the run-owned TimeDriver adapter.
        let legacy_clock = Arc::new(OperationClockAdapter::new(|| Ok(MonotonicInstant::zero())));
        let pool = match HttpWorkerPool::new(PoolLimits::default(), legacy_clock) {
            Ok(pool) => pool,
            Err(error) => {
                let primary =
                    RunError::http(error.code(), "native HTTP worker pool could not start");
                let mut cleanup_error = None;
                if let Err(cleanup) = cleanup_jtl_owner(&mut jtl_owner, true) {
                    cleanup_error = combine_execution_errors(
                        cleanup_error,
                        cleanup,
                        "execution.cleanup",
                        "result sink",
                    );
                }
                if let Err(cleanup) = cleanup_prepared_target(&mut prepared_result) {
                    cleanup_error = combine_execution_errors(
                        cleanup_error,
                        cleanup,
                        "execution.cleanup",
                        "result staging",
                    );
                }
                return match cleanup_error {
                    Some(secondary) => Err(RunError::Runtime {
                        code: "execution.cleanup".to_owned(),
                        message: bounded(
                            format!("primary={primary}; cleanup failed: {secondary}"),
                            MAX_DIAGNOSTIC_BYTES,
                        ),
                    }),
                    None => Err(primary),
                };
            }
        };
        let submitter = pool.submitter();
        *http_pool_handle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(submitter);
        NativeHttpPoolGuard::new(pool, http_pool_handle)
    } else {
        NativeHttpPoolGuard::empty(http_pool_handle)
    };

    // Logger initialization is intentionally after plan and output admission.
    // A capability/path rejection above therefore cannot create or append a
    // run log while reporting the refusal.
    let mut http_pool_guard = http_pool_guard;
    let mut logger = match RunLogger::initialize(invocation, resolved, launch) {
        Ok(logger) => logger,
        Err(error) => {
            let sink_error = cleanup_jtl_owner(&mut jtl_owner, true);
            let pool_error = http_pool_guard.finalize();
            let mut primary = Some(error);
            if let Err(cleanup) = sink_error {
                primary =
                    combine_execution_errors(primary, cleanup, "execution.cleanup", "result sink");
            }
            if let Err(cleanup) = pool_error {
                primary =
                    combine_execution_errors(primary, cleanup, "execution.cleanup", "HTTP pool");
            }
            if let Err(cleanup) = cleanup_prepared_target(&mut prepared_result) {
                primary = combine_execution_errors(
                    primary,
                    cleanup,
                    "execution.cleanup",
                    "result staging",
                );
            }
            return Err(primary.unwrap_or_else(|| RunError::Runtime {
                code: "execution.cleanup".to_owned(),
                message: "logger initialization cleanup failed".to_owned(),
            }));
        }
    };

    if !http_admission.nodes.is_empty() {
        let source_capabilities = http_admission
            .nodes
            .iter()
            .map(|node| node.source_capability.as_str())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(",");
        logger.info(&bounded(
            format!(
                "http nodes={} source-providers={} executed={}",
                http_admission.nodes.len(),
                source_capabilities,
                HTTP_NATIVE_CAPABILITY
            ),
            MAX_DIAGNOSTIC_BYTES,
        ));
    }

    let engine_result = {
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
        )
        .with_observation_policy(RunObservationPolicyV1::Summary);
        if let Some(router) = result_router {
            engine.set_result_router(Some(router));
        }
        if executor_policy == ExecutorPolicy::production() {
            block_on(engine.run())
        } else {
            block_on_with_policy(engine.run(), executor_policy)
        }
    };

    let mut primary = None;
    let mut outcome = None;
    match engine_result {
        Err(error) => {
            // The executor rejected/dropped the engine future.  This is an
            // abort, not a successful run: cancel admission and join without
            // enqueueing a synthetic finish command.
            primary = Some(error);
            if let Err(cleanup) = cleanup_jtl_owner(&mut jtl_owner, true) {
                primary =
                    combine_execution_errors(primary, cleanup, "execution.cleanup", "result sink");
            }
        }
        Ok(Err(error)) => {
            primary = Some(RunError::Runtime {
                code: error.code().to_owned(),
                message: bounded(error.to_string(), MAX_DIAGNOSTIC_BYTES),
            });
            if let Err(cleanup) = cleanup_jtl_owner(&mut jtl_owner, true) {
                primary =
                    combine_execution_errors(primary, cleanup, "execution.cleanup", "result sink");
            }
        }
        Ok(Ok(report)) => {
            if let Err(cleanup) = cleanup_jtl_owner(&mut jtl_owner, false) {
                primary =
                    combine_execution_errors(primary, cleanup, "execution.cleanup", "result sink");
            }
            // The result pool is part of successful execution. Join it before
            // syncing or publishing JTL bytes so a late worker cleanup error
            // can never accompany a visible success-looking output.
            if primary.is_none()
                && let Err(cleanup) = http_pool_guard.finalize()
            {
                primary =
                    combine_execution_errors(primary, cleanup, "execution.cleanup", "HTTP pool");
            }
            if primary.is_none()
                && let Some(target) = prepared_result.as_mut()
                && let Err(error) = target.publish()
            {
                primary = Some(error);
            }
            if primary.is_none() {
                match engine_summary_counts(&report.summary) {
                    Ok((samples, failed)) => {
                        logger.info(&format!(
                            "local plan={} packages={} samples={} failures={}",
                            test_path.display(),
                            packages,
                            samples,
                            failed
                        ));
                        let report_directory = if let Some(target) = report_target {
                            match prepared_result.as_mut() {
                                Some(result) => {
                                    match report_from_published_result(&target, result, resolved) {
                                        Ok(stats) => {
                                            logger.info(&format!(
                                                "report input={} samples={}",
                                                result.path.display(),
                                                stats.samples
                                            ));
                                            Ok(Some(target.path))
                                        }
                                        Err(error) => Err(error),
                                    }
                                }
                                None => Err(RunError::Runtime {
                                    code: "runtime.report-input".to_owned(),
                                    message: "report-at-end requires a published result handle"
                                        .to_owned(),
                                }),
                            }
                        } else {
                            Ok(None)
                        };
                        match report_directory {
                            Ok(report_directory) => {
                                outcome = Some(RunOutcome {
                                    mode: RunMode::NonGui,
                                    category: if failed == 0 {
                                        RunCategory::Normal
                                    } else {
                                        RunCategory::SampleFailure
                                    },
                                    samples,
                                    sample_failures: failed,
                                    result_file: result_path,
                                    report_directory,
                                    log_file: logger.path.clone(),
                                });
                            }
                            Err(error) => primary = Some(error),
                        }
                    }
                    Err(error) => primary = Some(error),
                }
            }
        }
    }

    // Failed or cancelled runs retain any previous target and remove only the
    // private staging inode, after the sink worker has been joined.
    if let Err(cleanup) = cleanup_prepared_target(&mut prepared_result) {
        primary = combine_execution_errors(primary, cleanup, "execution.cleanup", "result staging");
    }

    if let Err(cleanup) = http_pool_guard.finalize() {
        primary = combine_execution_errors(primary, cleanup, "execution.cleanup", "HTTP pool");
    }
    if let Err(cleanup) = logger.finish() {
        primary = combine_execution_errors(primary, cleanup, "execution.cleanup", "logging");
    }
    match (primary, outcome) {
        (Some(error), _) => Err(error),
        (None, Some(outcome)) => Ok(outcome),
        (None, None) => Err(RunError::Runtime {
            code: "execution.incomplete".to_owned(),
            message: "run completed without an outcome".to_owned(),
        }),
    }
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
pub(crate) fn runtime_properties(properties: &PropertyMap) -> BTreeMap<String, String> {
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

/// Performs the complete pure executable-plan admission phase.
///
/// `http_admission` and `native_v2_map` are mutually exclusive, already-pure
/// provider recipes.  Passing neither is valid for a plan without HTTP.  The
/// function performs opaque-node checks, implementation-path admission,
/// controller/scope compilation, scope coverage, lifecycle validation, and
/// exact component/factory decoding.  It does not construct any run owner.
pub(crate) fn admit_executable_plan(
    document: &SemanticDocument,
    source: &[u8],
    http_admission: Option<&CompiledHttpAdmission>,
    native_v2_map: Option<&PreparedNativeV2RequestMap>,
) -> Result<AdmittedExecutableRecipe, RunError> {
    if http_admission.is_some() && native_v2_map.is_some() {
        return Err(RunError::Runtime {
            code: "runtime.executable-admission.provider-conflict".to_owned(),
            message: "NativeV1 and NativeV2 recipes cannot be admitted together".to_owned(),
        });
    }
    let http_ids = http_admission
        .map(CompiledHttpAdmission::node_ids)
        .or_else(|| {
            native_v2_map.map(|map| {
                map.samplers()
                    .iter()
                    .map(|sampler| sampler.node_id())
                    .collect::<BTreeSet<_>>()
            })
        })
        .unwrap_or_default();
    let manifest = standalone_plan_manifest(document, source, &http_ids)?;
    let draft = PlanCompiler::builtins()
        .compile_tree(document.tree())
        .map_err(plan_compile_error)?;
    if draft.groups.is_empty() {
        return Err(RunError::Runtime {
            code: "runtime.no-thread-group".to_owned(),
            message: "the test plan contains no enabled lifecycle thread group".to_owned(),
        });
    }
    let initial_variables = draft
        .initial_variables_typed()
        .map_err(|error| RunError::Runtime {
            code: error.code().to_owned(),
            message: bounded(error.to_string(), MAX_DIAGNOSTIC_BYTES),
        })?;
    let scope_compiler = ScopeCompiler::builtins();
    let scope_plan = scope_compiler
        .compile(document.tree())
        .map_err(scope_compile_error)?;
    validate_scope_coverage(document, &scope_compiler, &scope_plan)?;

    let capability = if http_admission.is_some_and(CompiledHttpAdmission::has_http) {
        ExecutableCapabilityIdentity::NativeV1
    } else if native_v2_map.is_some_and(|map| map.requirements().has_http) {
        ExecutableCapabilityIdentity::NativeV2
    } else {
        ExecutableCapabilityIdentity::Standalone
    };
    let mut factories = build_builtin_scope_factories().into_runtime_registry();
    factories
        .register("DebugSampler", Arc::new(DebugSamplerScopeFactory))
        .map_err(|source| scope_compile_error(ScopeCompileError::Factory { source }))?;
    let scopes = scope_plan
        .iter()
        .map(|(_, scope)| admit_scope_recipe(scope, &factories, http_admission, native_v2_map))
        .collect::<Result<Vec<_>, _>>()?;

    let requirements = match (http_admission, native_v2_map) {
        (Some(admission), None) => ExecutableResourceRequirements {
            provider: admission
                .has_http()
                .then_some(ExecutableCapabilityIdentity::NativeV1),
            has_http: admission.has_http(),
            needs_http_pool: admission.has_http(),
            needs_time_driver: admission.has_http(),
            has_hostname: false,
            has_https: false,
            transport_limits: admission.transport_limits(),
        },
        (None, Some(map)) => {
            let map_requirements = map.requirements();
            ExecutableResourceRequirements {
                provider: map_requirements
                    .has_http
                    .then_some(ExecutableCapabilityIdentity::NativeV2),
                has_http: map_requirements.has_http,
                needs_http_pool: map_requirements.has_http,
                needs_time_driver: map_requirements.has_http,
                has_hostname: map_requirements.has_hostname,
                has_https: map_requirements.has_https,
                transport_limits: map_requirements.has_http.then_some(*map.transport_limits()),
            }
        }
        (None, None) => ExecutableResourceRequirements {
            provider: None,
            has_http: false,
            needs_http_pool: false,
            needs_time_driver: false,
            has_hostname: false,
            has_https: false,
            transport_limits: None,
        },
        (Some(_), Some(_)) => {
            return Err(RunError::Runtime {
                code: "runtime.executable-admission.provider-conflict".to_owned(),
                message: "NativeV1 and NativeV2 recipes cannot be admitted together".to_owned(),
            });
        }
    };
    if requirements.has_http && requirements.transport_limits.is_none() {
        return Err(RunError::Runtime {
            code: "runtime.executable-admission.requirements-incomplete".to_owned(),
            message: "HTTP admission did not provide exact transport limits".to_owned(),
        });
    }
    Ok(AdmittedExecutableRecipe {
        plan_digest: Digest32::sha256(source),
        capability,
        manifest,
        draft,
        initial_variables,
        scopes,
        http_v1: http_admission.cloned(),
        native_v2: native_v2_map.cloned(),
        requirements,
    })
}

fn admit_scope_recipe(
    scope: &ScopePlan,
    factories: &ComponentFactoryRegistry,
    http_admission: Option<&CompiledHttpAdmission>,
    native_v2_map: Option<&PreparedNativeV2RequestMap>,
) -> Result<AdmittedScopeRecipe, RunError> {
    let sampler_component = scope.sampler_node().clone();
    let sampler = if let Some(admission) = http_admission
        && is_http_sampler_class(&sampler_component.binding.test_class)
    {
        if admission
            .nodes
            .iter()
            .any(|node| node.node_id == sampler_component.node_id)
        {
            AdmittedSamplerRecipe::NativeV1 {
                node_id: sampler_component.node_id,
                label: sampler_component.element.name().to_owned(),
            }
        } else {
            return Err(RunError::Runtime {
                code: "runtime.executable-admission.http-node-missing".to_owned(),
                message: "scope HTTP sampler is absent from the admitted V1 recipe".to_owned(),
            });
        }
    } else if let Some(map) = native_v2_map
        && NATIVE_V2_HTTP_TEST_CLASSES.contains(&sampler_component.binding.test_class.as_str())
    {
        let Some(prepared) = map.sampler(sampler_component.node_id) else {
            return Err(RunError::Runtime {
                code: "runtime.executable-admission.native-v2-node-missing".to_owned(),
                message: "scope HTTP sampler is absent from the admitted V2 recipe".to_owned(),
            });
        };
        if prepared.source_path() != sampler_component.path
            || prepared.name() != sampler_component.element.name()
            || prepared.executed_provider() != HTTP_NATIVE_V2_CAPABILITY
        {
            return Err(RunError::Runtime {
                code: "runtime.executable-admission.native-v2-identity".to_owned(),
                message: "scope HTTP sampler does not match its admitted V2 identity".to_owned(),
            });
        }
        AdmittedSamplerRecipe::NativeV2(sampler_component.node_id)
    } else if is_http_sampler_class(&sampler_component.binding.test_class) {
        return Err(RunError::unsupported(
            "http.native.selection-required",
            "enabled HTTP sampler has no matching pure provider recipe",
        ));
    } else {
        let product =
            decode_scope_component(&sampler_component, ComponentCategory::Sampler, factories)
                .map_err(scope_compile_error)?;
        let value = match product {
            FactoryComponent::Sampler(value) => value,
            other => {
                return Err(scope_compile_error(scope_factory_category_mismatch(
                    &sampler_component,
                    ComponentCategory::Sampler,
                    other.category(),
                )));
            }
        };
        if sampler_component.binding.test_class == "DebugSampler" {
            AdmittedSamplerRecipe::Debug {
                label: sampler_component.element.name().to_owned(),
                failed: scope
                    .assertion_nodes()
                    .iter()
                    .any(|component| component.binding.test_class == "ResponseAssertion"),
            }
        } else {
            AdmittedSamplerRecipe::Decoded(value)
        }
    };
    let configurations = decode_configurations(scope.configuration_nodes(), factories)
        .map_err(scope_compile_error)?;
    let preprocessors =
        decode_preprocessors(scope.preprocessor_nodes(), factories).map_err(scope_compile_error)?;
    let timers = decode_timers(scope.timer_nodes(), factories).map_err(scope_compile_error)?;
    let postprocessors = decode_postprocessors(scope.postprocessor_nodes(), factories)
        .map_err(scope_compile_error)?;
    let assertions =
        decode_assertions(scope.assertion_nodes(), factories).map_err(scope_compile_error)?;
    let listeners =
        decode_listeners(scope.listener_nodes(), factories).map_err(scope_compile_error)?;
    Ok(AdmittedScopeRecipe {
        sampler_id: scope.sampler_id,
        sampler_component,
        sampler,
        configurations,
        preprocessors,
        timers,
        postprocessors,
        assertions,
        listeners,
    })
}

#[cfg(test)]
fn compile_local_plan(document: &SemanticDocument) -> Result<(EnginePlan, usize), RunError> {
    compile_local_plan_with_http(document, None, Arc::new(Mutex::new(None)))
}

#[cfg(test)]
fn compile_local_plan_with_http(
    document: &SemanticDocument,
    http_admission: Option<&CompiledHttpAdmission>,
    http_pool: NativeHttpPoolHandle,
) -> Result<(EnginePlan, usize), RunError> {
    compile_local_plan_with_resources(
        document,
        http_admission,
        None,
        BTreeSet::new(),
        http_pool,
        None,
        None,
        None,
    )
}

pub(crate) fn compile_local_plan_with_resources(
    document: &SemanticDocument,
    http_admission: Option<&CompiledHttpAdmission>,
    native_v2_factory: Option<&NativeV2ScopeFactory>,
    native_v2_ids: BTreeSet<NodeId>,
    http_pool: NativeHttpPoolHandle,
    native_http_transport: Option<NativeHttpTransport>,
    time_driver: Option<TimeDriverHandle>,
    projection: Option<SampleResultProjectionOptions>,
) -> Result<(EnginePlan, usize), RunError> {
    // This legacy adapter has no source bytes in its historical signature.
    // Keep its identity explicit and stable; production callers should use
    // `admit_executable_plan` with the exact JMX bytes so the source digest is
    // part of the reusable recipe identity.
    let legacy_source = b"runner.compile_local_plan_with_resources/1";
    let native_v2_map = if native_v2_factory.is_some() || !native_v2_ids.is_empty() {
        let compiled = compile_native_v2_http_plan(document)
            .map_err(|error| RunError::unsupported(error.code(), error.to_string()))?;
        let map = NativeV2RequestMapper::new()
            .prepare(&compiled)
            .map_err(|error| RunError::unsupported(error.code(), error.to_string()))?;
        let actual_ids = map
            .samplers()
            .iter()
            .map(|sampler| sampler.node_id())
            .collect::<BTreeSet<_>>();
        if actual_ids != native_v2_ids {
            return Err(RunError::Runtime {
                code: "runtime.executable-bind.native-v2-identity".to_owned(),
                message: "NativeV2 factory IDs do not match the pure request map".to_owned(),
            });
        }
        Some(map)
    } else {
        None
    };
    let recipe = admit_executable_plan(
        document,
        legacy_source,
        http_admission,
        native_v2_map.as_ref(),
    )?;
    let resources = ExecutableResourceBindings {
        plan_digest: recipe.plan_digest(),
        capability: recipe.capability_identity(),
        http_pool: if recipe.resource_requirements().needs_http_pool {
            Some(http_pool)
        } else {
            None
        },
        native_v2_factory: native_v2_factory.cloned(),
        native_http_transport,
        time_driver,
        projection,
    };
    recipe.bind_resources(&resources)
}

fn plan_compile_error(error: PlanCompileError) -> RunError {
    let message = bounded(error.to_string(), MAX_DIAGNOSTIC_BYTES);
    match &error {
        PlanCompileError::UnsupportedOpaque { .. } | PlanCompileError::UnsupportedClass { .. } => {
            RunError::unsupported("jmx.opaque-element", message)
        }
        PlanCompileError::UnsupportedFeature { capability_id, .. } => {
            RunError::unsupported(capability_id.clone(), message)
        }
        PlanCompileError::UnsupportedProperty { .. } => {
            RunError::unsupported(error.code(), message)
        }
        _ => RunError::Runtime {
            code: error.code().to_owned(),
            message,
        },
    }
}

fn scope_compile_error(error: ScopeCompileError) -> RunError {
    let message = bounded(error.to_string(), MAX_DIAGNOSTIC_BYTES);
    match &error {
        ScopeCompileError::Unsupported(component) => RunError::unsupported(
            component
                .capability_id
                .as_deref()
                .unwrap_or("runtime.scope.unsupported"),
            message,
        ),
        ScopeCompileError::Factory { source }
            if source.code() == "runtime.scope.missing-factory" =>
        {
            RunError::unsupported(source.code(), message)
        }
        _ => RunError::Runtime {
            code: error.code().to_owned(),
            message,
        },
    }
}

fn validate_scope_coverage(
    document: &SemanticDocument,
    compiler: &ScopeCompiler,
    scope_plan: &CompiledScopePlan,
) -> Result<(), RunError> {
    let mut represented = BTreeSet::new();
    for (_, scope) in scope_plan.iter() {
        represented.insert(scope.sampler_id);
        represented.extend(
            scope
                .configuration_nodes()
                .iter()
                .map(|component| component.node_id),
        );
        represented.extend(
            scope
                .preprocessor_nodes()
                .iter()
                .map(|component| component.node_id),
        );
        represented.extend(
            scope
                .timer_nodes()
                .iter()
                .map(|component| component.node_id),
        );
        represented.extend(
            scope
                .postprocessor_nodes()
                .iter()
                .map(|component| component.node_id),
        );
        represented.extend(
            scope
                .assertion_nodes()
                .iter()
                .map(|component| component.node_id),
        );
        represented.extend(
            scope
                .listener_nodes()
                .iter()
                .map(|component| component.node_id),
        );
    }

    for id in document.tree().preorder_ids() {
        let node = document.tree().node(id).map_err(|error| RunError::Jmx {
            message: bounded(error.to_string(), MAX_DIAGNOSTIC_BYTES),
        })?;
        if !node.value().is_enabled() || represented.contains(&id) || document.is_opaque(id) {
            continue;
        }
        let Some(binding) = compiler.registry().get(node.value().test_class()) else {
            continue;
        };
        if !matches!(
            binding.category,
            ComponentCategory::Configuration
                | ComponentCategory::Preprocessor
                | ComponentCategory::Timer
                | ComponentCategory::Sampler
                | ComponentCategory::Postprocessor
                | ComponentCategory::Assertion
                | ComponentCategory::Listener
        ) {
            continue;
        }
        return Err(RunError::unsupported(
            format!(
                "{}.{}",
                category_name(binding.category),
                node.value().test_class()
            ),
            format!(
                "enabled {} {:?} is not attached to an executable native sampler",
                category_name(binding.category),
                node.value().test_class()
            ),
        ));
    }
    Ok(())
}

const fn category_name(category: ComponentCategory) -> &'static str {
    match category {
        ComponentCategory::Configuration => "configuration",
        ComponentCategory::Preprocessor => "preprocessor",
        ComponentCategory::Timer => "timer",
        ComponentCategory::Sampler => "sampler",
        ComponentCategory::Postprocessor => "postprocessor",
        ComponentCategory::Assertion => "assertion",
        ComponentCategory::Listener => "listener",
        ComponentCategory::Controller => "controller",
        ComponentCategory::Lifecycle => "lifecycle",
        ComponentCategory::Replaceable => "replaceable",
    }
}

pub(crate) type NativeHttpPoolHandle = Arc<Mutex<Option<HttpWorkerSubmitter>>>;

struct LocalScopeAssembler {
    factories: ComponentFactoryRegistry,
    http_admissions: BTreeMap<NodeId, HttpNodeAdmission>,
    http_pool: NativeHttpPoolHandle,
    native_v2_factory: Option<NativeV2ScopeFactory>,
    native_http_transport: Option<NativeHttpTransport>,
    time_driver: Option<TimeDriverHandle>,
    projection: Option<SampleResultProjectionOptions>,
}

impl LocalScopeAssembler {
    fn with_resources(
        admission: Option<&CompiledHttpAdmission>,
        native_v2_factory: Option<NativeV2ScopeFactory>,
        http_pool: NativeHttpPoolHandle,
        native_http_transport: Option<NativeHttpTransport>,
        time_driver: Option<TimeDriverHandle>,
        projection: Option<SampleResultProjectionOptions>,
    ) -> Result<Self, ScopeFactoryError> {
        let mut factories = build_builtin_scope_factories().into_runtime_registry();
        // The app owns the only native samplers in this standalone wave. The
        // registry is deliberately explicit: runtime classification never
        // implies that a concrete app factory exists.
        factories.register("DebugSampler", Arc::new(DebugSamplerScopeFactory))?;
        let http_admissions = admission
            .map(|value| {
                value
                    .nodes
                    .iter()
                    .cloned()
                    .map(|node| (node.node_id, node))
                    .collect::<BTreeMap<_, _>>()
            })
            .unwrap_or_default();
        if !http_admissions.is_empty() {
            let factory = NativeHttpScopeFactory {
                admissions: http_admissions.clone(),
                pool: Arc::clone(&http_pool),
                transport: native_http_transport.clone(),
                time_driver: time_driver.clone(),
                projection: projection.clone(),
            };
            factories.register("HTTPHC4Impl", Arc::new(factory.clone()))?;
            factories.register("HTTPSamplerProxy", Arc::new(factory.clone()))?;
            factories.register(
                "org.apache.jmeter.protocol.http.sampler.HTTPSamplerProxy",
                Arc::new(factory),
            )?;
        }
        if let Some(factory) = native_v2_factory.as_ref() {
            for class in NATIVE_V2_HTTP_TEST_CLASSES {
                factories.register(*class, Arc::new(factory.clone()))?;
            }
        }
        Ok(Self {
            factories,
            http_admissions,
            http_pool,
            native_v2_factory,
            native_http_transport,
            time_driver,
            projection,
        })
    }
}

impl ScopePackageAssembler for LocalScopeAssembler {
    fn assemble(&self, scope: &ScopePlan) -> Result<SamplePackage, ScopeCompileError> {
        let sampler = decode_scope_component(
            scope.sampler_node(),
            ComponentCategory::Sampler,
            &self.factories,
        )?;
        let sampler_category = sampler.category();
        let FactoryComponent::Sampler(sampler) = sampler else {
            return Err(scope_factory_category_mismatch(
                scope.sampler_node(),
                ComponentCategory::Sampler,
                sampler_category,
            ));
        };

        let configurations = decode_configurations(scope.configuration_nodes(), &self.factories)?;
        let preprocessors = decode_preprocessors(scope.preprocessor_nodes(), &self.factories)?;
        let timers = decode_timers(scope.timer_nodes(), &self.factories)?;
        let postprocessors = decode_postprocessors(scope.postprocessor_nodes(), &self.factories)?;
        let assertions = decode_assertions(scope.assertion_nodes(), &self.factories)?;
        let listeners = decode_listeners(scope.listener_nodes(), &self.factories)?;

        let failed = scope
            .assertion_nodes()
            .iter()
            .any(|component| component.binding.test_class == "ResponseAssertion");
        let label = scope.sampler_node().element.name().to_owned();
        let mut builder = SamplePackage::builder(scope.sampler_id, sampler)
            .configurations(configurations)
            .preprocessors(preprocessors)
            .timers(timers)
            .postprocessors(postprocessors)
            .assertions(assertions)
            .listeners(listeners);
        if scope.sampler_node().binding.test_class == "DebugSampler" {
            builder = builder.sampler_factory(Arc::new(DebugSamplerFactory { label, failed }));
        } else if self.native_v2_factory.as_ref().is_some_and(|_| {
            NATIVE_V2_HTTP_TEST_CLASSES.contains(&scope.sampler_node().binding.test_class.as_str())
        }) {
            let factory = self
                .native_v2_factory
                .as_ref()
                .ok_or_else(|| ScopeCompileError::Factory {
                    source: ScopeFactoryError::Decode {
                        node_id: scope.sampler_id,
                        path: scope.sampler_node().path.clone(),
                        test_class: scope.sampler_node().binding.test_class.clone(),
                        category: ComponentCategory::Sampler,
                        detail: "NativeV2 factory was not admitted".to_owned(),
                    },
                })?
                .sampler_factory_for(scope.sampler_node())
                .map_err(|error| ScopeCompileError::Factory {
                    source: ScopeFactoryError::Decode {
                        node_id: scope.sampler_id,
                        path: scope.sampler_node().path.clone(),
                        test_class: scope.sampler_node().binding.test_class.clone(),
                        category: ComponentCategory::Sampler,
                        detail: error.to_string(),
                    },
                })?;
            builder = builder.sampler_factory(Arc::new(factory));
        } else if is_http_sampler_class(&scope.sampler_node().binding.test_class) {
            let admission = self.http_admissions.get(&scope.sampler_id).ok_or_else(|| {
                ScopeCompileError::Factory {
                    source: ScopeFactoryError::Decode {
                        node_id: scope.sampler_id,
                        path: scope.sampler_node().path.clone(),
                        test_class: scope.sampler_node().binding.test_class.clone(),
                        category: ComponentCategory::Sampler,
                        detail: "HTTP sampler was not present in complete admission".to_owned(),
                    },
                }
            })?;
            let pool = Arc::clone(&self.http_pool);
            let factory = NativeHttpSamplerFactory::try_new(
                admission.clone(),
                label,
                pool,
                self.native_http_transport.clone(),
                self.time_driver.clone(),
                self.projection.clone(),
            )
            .map_err(|detail| ScopeCompileError::Factory {
                source: ScopeFactoryError::Decode {
                    node_id: scope.sampler_id,
                    path: scope.sampler_node().path.clone(),
                    test_class: scope.sampler_node().binding.test_class.clone(),
                    category: ComponentCategory::Sampler,
                    detail,
                },
            })?;
            builder = builder.sampler_factory(Arc::new(factory));
        }
        Ok(builder.build())
    }
}

#[derive(Clone)]
struct NativeHttpScopeFactory {
    admissions: BTreeMap<NodeId, HttpNodeAdmission>,
    pool: NativeHttpPoolHandle,
    transport: Option<NativeHttpTransport>,
    time_driver: Option<TimeDriverHandle>,
    projection: Option<SampleResultProjectionOptions>,
}

impl ScopeComponentFactory for NativeHttpScopeFactory {
    fn create(&self, component: &ScopeComponent) -> Result<FactoryComponent, ScopeFactoryError> {
        let admission =
            self.admissions
                .get(&component.node_id)
                .ok_or_else(|| ScopeFactoryError::Decode {
                    node_id: component.node_id,
                    path: component.path.clone(),
                    test_class: component.binding.test_class.clone(),
                    category: ComponentCategory::Sampler,
                    detail: "HTTP sampler was not present in complete admission".to_owned(),
                })?;
        let factory = NativeHttpSamplerFactory::try_new(
            admission.clone(),
            component.element.name().to_owned(),
            Arc::clone(&self.pool),
            self.transport.clone(),
            self.time_driver.clone(),
            self.projection.clone(),
        )
        .map_err(|detail| ScopeFactoryError::Decode {
            node_id: component.node_id,
            path: component.path.clone(),
            test_class: component.binding.test_class.clone(),
            category: ComponentCategory::Sampler,
            detail,
        })?;
        Ok(FactoryComponent::Sampler(factory.create()))
    }
}

#[derive(Clone)]
struct NativeHttpSamplerFactory {
    request: Request,
    label: String,
    pool: NativeHttpPoolHandle,
    config: ClientConfig,
    transport: Option<NativeHttpTransport>,
    time_driver: Option<TimeDriverHandle>,
    projection: Option<SampleResultProjectionOptions>,
}

impl NativeHttpSamplerFactory {
    fn try_new_bound(
        admission: HttpNodeAdmission,
        label: String,
        pool: NativeHttpPoolHandle,
        transport: NativeHttpTransport,
        time_driver: TimeDriverHandle,
        projection: SampleResultProjectionOptions,
    ) -> Result<Self, String> {
        if !native_http_pool_is_bound(&pool) {
            return Err("runtime.executable-bind.http-pool-missing".to_owned());
        }
        if transport.capability_id() != admission.executed_capability
            || transport.limits() != &admission.transport_limits
        {
            return Err("runtime.executable-bind.transport-mismatch".to_owned());
        }
        Ok(Self {
            request: admission.prepared_request,
            label,
            pool,
            config: admission.client_config,
            transport: Some(transport),
            time_driver: Some(time_driver),
            projection: Some(projection),
        })
    }

    fn try_new(
        admission: HttpNodeAdmission,
        label: String,
        pool: NativeHttpPoolHandle,
        transport: Option<NativeHttpTransport>,
        time_driver: Option<TimeDriverHandle>,
        projection: Option<SampleResultProjectionOptions>,
    ) -> Result<Self, String> {
        // Validate the exact transport/client pair at factory construction,
        // before an engine can create a user or submit work.  A production
        // transaction supplies the frozen run-owned transport.  The None
        // form is retained only for the pre-resource compile/reference seam
        // and can never execute a successful sample.
        if let Some(transport_ref) = transport.as_ref() {
            HttpClient::new(transport_ref.clone(), admission.client_config.clone())
                .map_err(|error| error.stable_code().to_owned())?;
        }
        Ok(Self {
            request: admission.prepared_request,
            label,
            pool,
            config: admission.client_config,
            transport,
            time_driver,
            projection,
        })
    }
}

impl SamplerFactory for NativeHttpSamplerFactory {
    fn create(&self) -> Arc<dyn Sampler> {
        let client = self
            .transport
            .as_ref()
            .ok_or_else(|| "http.native.transport-not-installed".to_owned())
            .and_then(|transport| {
                HttpClient::new(transport.clone(), self.config.clone())
                    .map_err(|error| error.stable_code().to_owned())
            })
            .map(|client| Arc::new(Mutex::new(client)));
        match client {
            Ok(client) => Arc::new(NativeHttpSampler {
                request: self.request.clone(),
                label: self.label.clone(),
                pool: Arc::clone(&self.pool),
                client: Some(client),
                time_driver: self.time_driver.clone(),
                projection: self.projection.clone(),
                init_error: None,
            }),
            Err(_error) => Arc::new(NativeHttpSampler {
                request: self.request.clone(),
                label: self.label.clone(),
                pool: Arc::clone(&self.pool),
                client: None,
                time_driver: self.time_driver.clone(),
                projection: self.projection.clone(),
                init_error: Some("http.native.client-init"),
            }),
        }
    }
}

fn native_http_transport_limits() -> NativeTransportLimits {
    let mut limits = NativeTransportLimits::default();
    limits.max_response_head_bytes = NATIVE_HTTP_RESPONSE_HEAD_BYTES;
    limits.max_response_body_bytes = NATIVE_HTTP_RESPONSE_BODY_BYTES;
    limits.max_response_total_bytes =
        NATIVE_HTTP_RESPONSE_HEAD_BYTES.saturating_add(NATIVE_HTTP_RESPONSE_BODY_BYTES);
    limits.max_header_aggregate_bytes = NATIVE_HTTP_RESPONSE_HEAD_BYTES;
    // These aggregate response sections are validated against the same
    // response ceiling; retaining their larger library defaults would make
    // an otherwise bounded client fail during factory construction.
    limits.max_informational_bytes = limits.max_response_total_bytes;
    limits.max_trailer_aggregate_bytes = limits.max_response_total_bytes;
    limits
}

struct NativeHttpSampler {
    request: Request,
    label: String,
    pool: NativeHttpPoolHandle,
    client: Option<Arc<Mutex<HttpClient<NativeHttpTransport>>>>,
    time_driver: Option<TimeDriverHandle>,
    projection: Option<SampleResultProjectionOptions>,
    init_error: Option<&'static str>,
}

impl Sampler for NativeHttpSampler {
    fn sample<'a>(
        &'a self,
        context: &'a mut jmeter_rs_runtime::SampleContext<'_>,
    ) -> ComponentFuture<'a, SamplerOutput> {
        let sampler_id = context.sampler_id();
        let cancellation = context.execution().cancellation_token().clone();
        let request = self.request.clone();
        let label = self.label.clone();
        let pool = Arc::clone(&self.pool);
        let client = self.client.clone();
        let time_driver = self.time_driver.clone();
        let projection = self.projection.clone();
        let init_error = self.init_error;
        Box::pin(async move {
            if let Some(code) = init_error {
                return Ok(native_http_failure(sampler_id, &label, code));
            }
            let Some(client) = client else {
                return Ok(native_http_failure(
                    sampler_id,
                    &label,
                    "http.native.client-init",
                ));
            };
            let pool = {
                let guard = pool
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                guard.clone()
            };
            let Some(pool) = pool else {
                return Ok(native_http_failure(
                    sampler_id,
                    &label,
                    "http.pool.not-installed",
                ));
            };
            let Some(time_driver) = time_driver else {
                return Ok(native_http_failure(
                    sampler_id,
                    &label,
                    "http.time-driver.not-installed",
                ));
            };
            let now = match time_driver.try_now() {
                Ok(reading) => MonotonicInstant::from_duration(reading.monotonic),
                Err(_) => {
                    return Ok(native_http_failure(
                        sampler_id,
                        &label,
                        "http.time-driver.unavailable",
                    ));
                }
            };
            let deadline =
                match OperationDeadline::after_at(now, DEFAULT_NATIVE_HTTP_OVERALL_TIMEOUT) {
                    Ok(deadline) => deadline,
                    Err(error) => return Ok(native_http_pool_failure(sampler_id, &label, error)),
                };
            let registration = match time_driver.register_http_wait(
                Deadline::at(deadline.instant()),
                sampler_id.get(),
                &cancellation,
            ) {
                Ok(registration) => registration,
                Err(error) => {
                    return Ok(native_http_failure(sampler_id, &label, error.code()));
                }
            };
            let mut operation = match HttpOperation::from_shared_client(client, request) {
                Ok(operation) => match pool.submit_with_deadline(operation, deadline) {
                    Ok(operation) => operation,
                    Err(error) => {
                        drop(registration);
                        return Ok(native_http_pool_failure(sampler_id, &label, error));
                    }
                },
                Err(error) => {
                    drop(registration);
                    return Ok(native_http_pool_failure(sampler_id, &label, error));
                }
            };
            let result = std::future::poll_fn(|poll_context| {
                cancellation.register_waker(poll_context.waker());
                if cancellation.is_cancelled() {
                    operation.cancel();
                }
                Pin::new(&mut operation).poll(poll_context)
            })
            .await;
            drop(registration);
            match result {
                Ok(result) => {
                    let Some(projection) = projection.as_ref() else {
                        return Ok(native_http_failure(
                            sampler_id,
                            &label,
                            "http.result-projection.not-installed",
                        ));
                    };
                    match result.to_sample_result(label.clone(), projection) {
                        Ok(result) => Ok(SamplerOutput::result(result)),
                        Err(error) => {
                            Ok(native_http_failure(sampler_id, &label, error.stable_code()))
                        }
                    }
                }
                Err(error) => Ok(native_http_failure(sampler_id, &label, error.stable_code())),
            }
        })
    }
}

fn native_http_failure(sampler_id: NodeId, label: &str, code: &str) -> SamplerOutput {
    let mut result = SampleResult::new(label.to_owned());
    result.set_successful(false);
    result.set_failure_message(Some(format!("native HTTP operation failed ({code})")));
    SamplerOutput::failure(
        jmeter_rs_runtime::SampleFailure::new(
            sampler_id,
            format!("native HTTP operation failed ({code})"),
        )
        .with_result(result),
    )
}

fn native_http_pool_failure(sampler_id: NodeId, label: &str, error: PoolError) -> SamplerOutput {
    native_http_failure(sampler_id, label, error.code())
}

fn native_http_request(
    candidate: &NativeHttpRequestCandidate,
) -> Result<Request, jmeter_rs_http::HttpError> {
    let ip = candidate.domain.parse::<IpAddr>().map_err(|_| {
        jmeter_rs_http::HttpError::Unsupported("numeric origin required".to_owned())
    })?;
    let port = candidate.port.unwrap_or(80);
    let authority = match ip {
        IpAddr::V4(value) => format!("{value}:{port}"),
        IpAddr::V6(value) => format!("[{value}]:{port}"),
    };
    let url = Url::parse(format!("http://{authority}{}", candidate.path))?;
    let method = Method::parse(candidate.method.clone())?;
    let request = Request::new(method, url);
    Ok(request)
}

fn native_http_client_config(
    candidate: &NativeHttpRequestCandidate,
    limits: NativeTransportLimits,
) -> Result<ClientConfig, jmeter_rs_http::HttpError> {
    let phase_timeout = |value: Option<u64>| {
        value
            .filter(|value| *value != 0)
            .map_or(DEFAULT_NATIVE_HTTP_PHASE_TIMEOUT, Duration::from_millis)
    };
    let config = ClientConfig {
        redirects: RedirectPolicy {
            follow: false,
            maximum: 0,
            allow_cross_origin: false,
            forward_authorization: false,
            maximum_retained_bytes: 1024 * 1024,
        },
        proxy: ProxyPolicy::default(),
        tls: TlsConfig::default(),
        http_version: HttpVersionPolicy::Http11Only,
        decompression: DecompressionPolicy::Disabled,
        retries: RetryPolicy {
            maximum_transparent_retries: 0,
            maximum_auth_challenges: 0,
        },
        timeouts: TimeoutConfig {
            overall: Some(DEFAULT_NATIVE_HTTP_OVERALL_TIMEOUT),
            connect: Some(phase_timeout(candidate.connect_timeout_ms)),
            write: Some(phase_timeout(candidate.response_timeout_ms)),
            read: Some(phase_timeout(candidate.response_timeout_ms)),
            tls: Some(phase_timeout(candidate.connect_timeout_ms)),
        },
        limits: ClientLimits {
            max_request_body_bytes: limits.max_request_body_bytes,
            max_response_body_bytes: limits.max_response_body_bytes,
            max_header_fields: limits.max_header_count,
            max_header_bytes: limits.max_header_aggregate_bytes,
            ..ClientLimits::default()
        },
        cookies_enabled: false,
        cache_enabled: false,
        auth_enabled: false,
        headers_enabled: false,
        retry_basic_challenge: false,
    };
    config.validate().map(|()| config)
}

struct DebugSamplerScopeFactory;

impl ScopeComponentFactory for DebugSamplerScopeFactory {
    fn create(&self, component: &ScopeComponent) -> Result<FactoryComponent, ScopeFactoryError> {
        for entry in component.element.properties.iter() {
            if !matches!(
                entry.name.as_str(),
                "displayJMeterProperties" | "displayJMeterVariables" | "displaySystemProperties"
            ) {
                return Err(ScopeFactoryError::Decode {
                    node_id: component.node_id,
                    path: component.path.clone(),
                    test_class: component.binding.test_class.clone(),
                    category: ComponentCategory::Sampler,
                    detail: format!("unsupported DebugSampler property {:?}", entry.name),
                });
            }
            entry
                .value
                .as_bool()
                .map_err(|error| ScopeFactoryError::Decode {
                    node_id: component.node_id,
                    path: component.path.clone(),
                    test_class: component.binding.test_class.clone(),
                    category: ComponentCategory::Sampler,
                    detail: format!("property {:?} must be boolean: {error}", entry.name),
                })?;
        }
        Ok(FactoryComponent::Sampler(Arc::new(DebugSamplerAdapter {
            label: component.element.name().to_owned(),
            failed: false,
        })))
    }
}

fn decode_scope_component(
    component: &ScopeComponent,
    expected: ComponentCategory,
    factories: &ComponentFactoryRegistry,
) -> Result<FactoryComponent, ScopeCompileError> {
    let Some(factory) = factories.get(&component.binding.test_class) else {
        return Err(ScopeCompileError::Factory {
            source: ScopeFactoryError::MissingFactory {
                node_id: component.node_id,
                path: component.path.clone(),
                test_class: component.binding.test_class.clone(),
                category: expected,
            },
        });
    };
    let product = factory
        .create(component)
        .map_err(|source| ScopeCompileError::Factory { source })?;
    if product.category() != expected {
        return Err(scope_factory_category_mismatch(
            component,
            expected,
            product.category(),
        ));
    }
    Ok(product)
}

macro_rules! define_scope_decoder {
    ($name:ident, $trait_name:ident, $variant:ident, $category:expr) => {
        fn $name(
            components: &[ScopeComponent],
            factories: &ComponentFactoryRegistry,
        ) -> Result<Vec<Arc<dyn $trait_name>>, ScopeCompileError> {
            components
                .iter()
                .map(|component| {
                    let product = decode_scope_component(component, $category, factories)?;
                    match product {
                        FactoryComponent::$variant(value) => Ok(value),
                        other => Err(scope_factory_category_mismatch(
                            component,
                            $category,
                            other.category(),
                        )),
                    }
                })
                .collect()
        }
    };
}

define_scope_decoder!(
    decode_configurations,
    Configuration,
    Configuration,
    ComponentCategory::Configuration
);
define_scope_decoder!(
    decode_preprocessors,
    Preprocessor,
    Preprocessor,
    ComponentCategory::Preprocessor
);
define_scope_decoder!(decode_timers, Timer, Timer, ComponentCategory::Timer);
define_scope_decoder!(
    decode_postprocessors,
    Postprocessor,
    Postprocessor,
    ComponentCategory::Postprocessor
);
define_scope_decoder!(
    decode_assertions,
    Assertion,
    Assertion,
    ComponentCategory::Assertion
);
define_scope_decoder!(
    decode_listeners,
    Listener,
    Listener,
    ComponentCategory::Listener
);

fn scope_factory_category_mismatch(
    component: &ScopeComponent,
    expected: ComponentCategory,
    actual: ComponentCategory,
) -> ScopeCompileError {
    ScopeCompileError::Factory {
        source: ScopeFactoryError::CategoryMismatch {
            node_id: component.node_id,
            path: component.path.clone(),
            expected,
            actual,
        },
    }
}

struct DebugSamplerAdapter {
    label: String,
    failed: bool,
}

struct DebugSamplerFactory {
    label: String,
    failed: bool,
}

/// Owner-free sampler factory used by an admitted package recipe for
/// components whose concrete implementation is immutable and has no run
/// resource dependency.
#[derive(Clone)]
struct StaticSamplerFactory(Arc<dyn Sampler>);

impl SamplerFactory for StaticSamplerFactory {
    fn create(&self) -> Arc<dyn Sampler> {
        Arc::clone(&self.0)
    }
}

impl SamplerFactory for DebugSamplerFactory {
    fn create(&self) -> Arc<dyn Sampler> {
        Arc::new(DebugSamplerAdapter {
            label: self.label.clone(),
            failed: self.failed,
        })
    }
}

impl Sampler for DebugSamplerAdapter {
    fn sample<'a>(
        &'a self,
        context: &'a mut jmeter_rs_runtime::SampleContext<'_>,
    ) -> ComponentFuture<'a, SamplerOutput> {
        let label = expand_debug_label(&self.label, context.execution());
        let mut result = SampleResult::new(label);
        result.set_successful(!self.failed);
        if self.failed {
            result.set_failure_message(Some("response assertion failed".to_owned()));
        }
        Box::pin(std::future::ready(Ok(SamplerOutput::result(result))))
    }
}

fn expand_debug_label(label: &str, context: &jmeter_rs_runtime::ExecutionContext) -> String {
    let mut expanded = String::with_capacity(label.len());
    let mut remainder = label;
    while let Some(start) = remainder.find("${") {
        expanded.push_str(&remainder[..start]);
        let expression = &remainder[start + 2..];
        let Some(end) = expression.find('}') else {
            expanded.push_str(&remainder[start..]);
            return expanded;
        };
        let name = &expression[..end];
        if name.is_empty() || name.contains(['{', '}']) {
            expanded.push_str(&remainder[start..start + 2 + end + 1]);
        } else if let Some(value) = context.variable(name) {
            expanded.push_str(&value);
        } else {
            expanded.push_str(&remainder[start..start + 2 + end + 1]);
        }
        remainder = &expression[end + 1..];
    }
    expanded.push_str(remainder);
    expanded
}

pub(crate) fn engine_summary_counts(
    summary: &RunObservationSummaryV1,
) -> Result<(usize, usize), RunError> {
    let samples = usize::try_from(summary.materialized_samples).map_err(|_| RunError::Runtime {
        code: "runtime.observation.counter-conversion".to_owned(),
        message: "sample count exceeds the application counter width".to_owned(),
    })?;
    let failed = usize::try_from(summary.failed_samples).map_err(|_| RunError::Runtime {
        code: "runtime.observation.counter-conversion".to_owned(),
        message: "sample failure count exceeds the application counter width".to_owned(),
    })?;
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

pub(crate) fn prepare_report_target(
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

fn write_report_dashboard<R: Read>(
    target: &PreparedReportTarget,
    input: R,
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
    let samples = stats
        .samples
        .checked_add(1)
        .ok_or_else(|| report_counter_overflow(ReportField::SampleCount))?;
    if samples > MAX_REPORT_AGGREGATION_ENTRIES {
        return Err(RunError::Report {
            code: "report.input_limit",
            message: format!(
                "report aggregation exceeds the bounded sample limit {MAX_REPORT_AGGREGATION_ENTRIES}"
            ),
        });
    }
    let failed = if event.result().success() == Some(false) {
        stats
            .failed
            .checked_add(1)
            .ok_or_else(|| report_counter_overflow(ReportField::ErrorCount))?
    } else {
        stats.failed
    };
    stats.samples = samples;
    stats.failed = failed;
    dashboard.add_event(&event).map_err(report_error)
}

fn report_counter_overflow(field: ReportField) -> RunError {
    report_error(ReportError::Overflow { field })
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

pub(crate) fn resolve_path_argument(
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

pub(crate) fn resolve_checked_path(root: &Path, raw: &str) -> Result<PathBuf, RunError> {
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

/// Reads one already-validated NativeV2 CA token through the rooted bounded
/// descriptor capability.  The complete byte handoff occurs before any
/// provider owner, worker pool, output target, logger, or engine is created.
pub(crate) fn read_native_ca_bytes(path: &Path, cwd: &Path) -> Result<Vec<u8>, RunError> {
    let root = fs::canonicalize(cwd).map_err(|error| RunError::io(cwd, error))?;
    let mut file = open_bound_read(path, std::slice::from_ref(&root))
        .map_err(|error| RunError::io(path, error))?;
    let metadata = file.metadata().map_err(|error| RunError::io(path, error))?;
    if !metadata.is_file() {
        return Err(RunError::Io {
            path: path.to_owned(),
            message: "NativeV2 CA input must be a regular file".to_owned(),
        });
    }
    let length = usize::try_from(metadata.len()).map_err(|_| {
        RunError::http(
            "app.native-http.ca-input-limit",
            "NativeV2 CA input length exceeds the bounded handoff",
        )
    })?;
    if length == 0 || length > MAX_NATIVE_HTTP_CA_BYTES {
        return Err(RunError::http(
            "app.native-http.ca-input-limit",
            "NativeV2 CA input exceeds the bounded handoff",
        ));
    }
    let mut bytes = Vec::with_capacity(length);
    file.read_to_end(&mut bytes)
        .map_err(|error| RunError::io(path, error))?;
    if bytes.len() != length || bytes.len() > MAX_NATIVE_HTTP_CA_BYTES {
        return Err(RunError::http(
            "app.native-http.ca-input-limit",
            "NativeV2 CA input changed during bounded read",
        ));
    }
    Ok(bytes)
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

pub(crate) struct RunLogger {
    path: Option<PathBuf>,
    root: PathBuf,
    lines: Vec<String>,
    truncated: bool,
}

impl RunLogger {
    pub(crate) fn initialize(
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

    pub(crate) fn info(&mut self, message: &str) {
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

    pub(crate) fn path(&self) -> Option<PathBuf> {
        self.path.clone()
    }

    pub(crate) fn finish(&self) -> Result<(), RunError> {
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

/// Bounded policy for the application-edge future adapter.
///
/// `idle_limit` is the maximum time spent waiting for a wake after a future
/// returns `Pending` without already arranging one.  A zero value is useful
/// for deterministic tests: it checks the wake contract without sleeping.
/// Poll and wake limits are always nonzero and capped, so a malformed policy
/// cannot turn the adapter into an unbounded loop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(test)]
struct ExecutorPolicy {
    poll_limit: usize,
    wake_limit: usize,
    idle_limit: Duration,
}

#[cfg(test)]
impl ExecutorPolicy {
    fn new(poll_limit: usize, wake_limit: usize, idle_limit: Duration) -> Result<Self, RunError> {
        if poll_limit == 0 || poll_limit > MAX_EXECUTOR_POLLS {
            return Err(RunError::Runtime {
                code: "runtime.executor-policy".to_owned(),
                message: format!(
                    "executor poll limit must be in 1..={MAX_EXECUTOR_POLLS}, got {poll_limit}"
                ),
            });
        }
        if wake_limit == 0 || wake_limit > MAX_EXECUTOR_WAKES {
            return Err(RunError::Runtime {
                code: "runtime.executor-policy".to_owned(),
                message: format!(
                    "executor wake limit must be in 1..={MAX_EXECUTOR_WAKES}, got {wake_limit}"
                ),
            });
        }
        if idle_limit > MAX_EXECUTOR_IDLE {
            return Err(RunError::Runtime {
                code: "runtime.executor-idle".to_owned(),
                message: format!(
                    "executor idle limit exceeds the bounded maximum of {:?}",
                    MAX_EXECUTOR_IDLE
                ),
            });
        }
        Ok(Self {
            poll_limit,
            wake_limit,
            idle_limit,
        })
    }

    fn production() -> Self {
        // These constants are validated by construction and kept separate
        // from `new` so the production path cannot accidentally accept an
        // operator-provided unbounded policy.
        Self {
            poll_limit: MAX_EXECUTOR_POLLS,
            wake_limit: MAX_EXECUTOR_WAKES,
            idle_limit: DEFAULT_EXECUTOR_IDLE + EXECUTOR_IDLE_GRACE,
        }
    }
}

/// One current-thread wake registration.
///
/// The signal intentionally stores only the exact thread handle and bounded
/// wake bookkeeping.  It does not retain the future, a `Context`, or any
/// caller-owned value (including secrets).  `Thread::unpark` has a one-bit
/// token; the generation counter closes the race where a wake occurs just
/// before the executor starts waiting.
#[cfg(test)]
struct WakeSignal {
    thread: std::thread::Thread,
    state: Mutex<WakeState>,
    wake_limit: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg(test)]
struct WakeState {
    generation: u64,
    wake_count: usize,
    wake_limit_reached: bool,
}

#[cfg(test)]
impl WakeSignal {
    fn new(thread: std::thread::Thread, wake_limit: usize) -> Self {
        Self {
            thread,
            state: Mutex::new(WakeState::default()),
            wake_limit,
        }
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, WakeState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn signal(&self) {
        let thread = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.wake_count < self.wake_limit {
                state.wake_count += 1;
            } else {
                state.wake_limit_reached = true;
            }
            // The bounded wake limit prevents this counter from wrapping in a
            // real run, so a wrapping increment is only a defensive fallback.
            state.generation = state.generation.wrapping_add(1);
            self.thread.clone()
        };
        // Unlock before unparking.  A wake racing with the waiter's generation
        // check either observes the new generation or leaves the thread token
        // set for `park_timeout`.
        thread.unpark();
    }

    fn generation(&self) -> u64 {
        self.lock_state().generation
    }

    fn wake_limit_reached(&self) -> bool {
        self.lock_state().wake_limit_reached
    }

    /// Waits until the generation changes or the finite idle duration expires.
    /// Spurious returns from `park_timeout` are absorbed here rather than
    /// converted into an immediate repoll (which would recreate a busy spin).
    fn wait_for_wake(&self, observed_generation: u64, idle_limit: Duration) -> bool {
        let Some(deadline) = Instant::now().checked_add(idle_limit) else {
            return false;
        };
        loop {
            if self.generation() != observed_generation {
                return true;
            }
            let now = Instant::now();
            let Some(remaining) = deadline.checked_duration_since(now) else {
                return false;
            };
            if remaining.is_zero() {
                return false;
            }
            std::thread::park_timeout(remaining);
        }
    }
}

#[cfg(test)]
impl Wake for WakeSignal {
    fn wake(self: Arc<Self>) {
        self.signal();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.signal();
    }
}

#[cfg(test)]
fn executor_runtime_error(code: &'static str, message: impl Into<String>) -> RunError {
    RunError::Runtime {
        code: code.to_owned(),
        message: bounded(message.into(), MAX_DIAGNOSTIC_BYTES),
    }
}

#[cfg(test)]
fn max_duration(current: Duration, candidate: Duration) -> Duration {
    if candidate > current {
        candidate
    } else {
        current
    }
}

/// Derives the finite production idle window from admitted runtime and HTTP
/// configuration.  The window is per pending/no-wake interval; repeated
/// progress remains bounded by the poll and wake budgets.
#[cfg(test)]
fn executor_policy_for_plan(
    plan: &EnginePlan,
    http_admission: &CompiledHttpAdmission,
) -> Result<ExecutorPolicy, RunError> {
    let mut idle_limit = DEFAULT_EXECUTOR_IDLE;
    for group in &plan.groups {
        // A delayed ramp can remain quiet for both phases consecutively. Use
        // the checked sum so the executor does not time out between the end
        // of the delay and the first ramp wake.
        let delay_and_ramp = group
            .schedule
            .delay
            .checked_add(group.schedule.ramp_up)
            .ok_or_else(|| {
                executor_runtime_error(
                    "runtime.executor-idle",
                    "thread-group delay and ramp-up exceed the finite executor bound",
                )
            })?;
        idle_limit = max_duration(idle_limit, delay_and_ramp);
        if let Some(duration) = group.schedule.duration {
            idle_limit = max_duration(idle_limit, duration);
        }
    }
    for node in &http_admission.nodes {
        // The native client turns absent/zero JMeter phase fields into these
        // finite provider defaults. The executor must wait at least through
        // that overall operation bound, rather than deriving idleness from
        // only the optional source fields.
        idle_limit = max_duration(idle_limit, DEFAULT_NATIVE_HTTP_OVERALL_TIMEOUT);
        idle_limit = max_duration(idle_limit, DEFAULT_NATIVE_HTTP_PHASE_TIMEOUT);
        if let Some(timeout_ms) = node.request.connect_timeout_ms
            && timeout_ms != 0
        {
            idle_limit = max_duration(idle_limit, Duration::from_millis(timeout_ms));
        }
        if let Some(timeout_ms) = node.request.response_timeout_ms
            && timeout_ms != 0
        {
            idle_limit = max_duration(idle_limit, Duration::from_millis(timeout_ms));
        }
    }
    let idle_limit = idle_limit.checked_add(EXECUTOR_IDLE_GRACE).ok_or_else(|| {
        executor_runtime_error(
            "runtime.executor-idle",
            "configured runtime/network deadline cannot be represented by the executor",
        )
    })?;
    ExecutorPolicy::new(MAX_EXECUTOR_POLLS, MAX_EXECUTOR_WAKES, idle_limit)
}

#[cfg(test)]
fn block_on<F: std::future::Future>(future: F) -> Result<F::Output, RunError> {
    block_on_with_policy(future, ExecutorPolicy::production())
}

#[cfg(test)]
fn block_on_with_policy<F: std::future::Future>(
    future: F,
    policy: ExecutorPolicy,
) -> Result<F::Output, RunError> {
    // Revalidate even internally-created policies.  This keeps the helper
    // safe when a future call site later accepts a configuration-derived
    // policy and makes the test seam exercise the same validation path.
    let policy = ExecutorPolicy::new(policy.poll_limit, policy.wake_limit, policy.idle_limit)?;
    let signal = Arc::new(WakeSignal::new(std::thread::current(), policy.wake_limit));
    let waker = Waker::from(Arc::clone(&signal));
    let mut context = Context::from_waker(&waker);
    let mut future = Box::pin(future);
    let mut polls = 0_usize;

    loop {
        if polls >= policy.poll_limit {
            return Err(executor_runtime_error(
                "runtime.executor-poll-limit",
                format!("executor poll budget exceeded ({})", policy.poll_limit),
            ));
        }
        if signal.wake_limit_reached() {
            return Err(executor_runtime_error(
                "runtime.executor-wake-limit",
                format!("executor wake budget exceeded ({})", policy.wake_limit),
            ));
        }
        polls += 1;
        let poll_generation = signal.generation();
        match Pin::new(&mut future).poll(&mut context) {
            Poll::Ready(value) => {
                if signal.wake_limit_reached() {
                    return Err(executor_runtime_error(
                        "runtime.executor-wake-limit",
                        format!("executor wake budget exceeded ({})", policy.wake_limit),
                    ));
                }
                return Ok(value);
            }
            Poll::Pending => {
                if signal.wake_limit_reached() {
                    return Err(executor_runtime_error(
                        "runtime.executor-wake-limit",
                        format!("executor wake budget exceeded ({})", policy.wake_limit),
                    ));
                }
                // A synchronous wake during `poll` is observed before any
                // wait.  This is the critical wake-before-wait race closure.
                if signal.generation() != poll_generation {
                    continue;
                }
                if policy.idle_limit.is_zero()
                    || !signal.wait_for_wake(poll_generation, policy.idle_limit)
                {
                    return Err(executor_runtime_error(
                        "runtime.executor-idle",
                        format!(
                            "future remained pending without a wake for {:?}",
                            policy.idle_limit
                        ),
                    ));
                }
            }
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
    use jmeter_rs_runtime::{EngineEvent, ExecutionContext, GroupKind};
    use std::future::Future;
    use std::io::Read;
    use std::net::TcpListener;
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::{self, Receiver, SyncSender};
    use std::thread;

    fn run_document(document: &SemanticDocument) -> jmeter_rs_runtime::EngineReport {
        let (plan, _) = compile_local_plan(document).expect("document compiles");
        let mut engine = RuntimeEngine::new(
            plan,
            RuntimeCapabilities::default(),
            "runner-test",
            "localhost",
        )
        .with_observation_policy(RunObservationPolicyV1::full_trace(
            std::num::NonZeroUsize::new(100_000).expect("finite trace event bound"),
            std::num::NonZeroUsize::new(128 * 1024 * 1024).expect("finite trace byte bound"),
        ));
        block_on(engine.run())
            .expect("engine future completes")
            .expect("compiled document runs")
    }

    fn sample_labels(report: &jmeter_rs_runtime::EngineReport) -> Vec<String> {
        report
            .events
            .iter()
            .filter_map(|event| match event {
                EngineEvent::Sample {
                    result: Some(result),
                    ..
                } => Some(result.label().to_owned()),
                _ => None,
            })
            .collect()
    }

    struct SynchronousWakeFuture {
        polled: bool,
    }

    impl Future for SynchronousWakeFuture {
        type Output = usize;

        fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
            let future = self.as_mut().get_mut();
            if future.polled {
                Poll::Ready(2)
            } else {
                future.polled = true;
                // The wake is deliberately issued before the executor can
                // enter its wait path.
                context.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    struct CrossThreadWakeFuture {
        ready: Arc<AtomicBool>,
        registered: bool,
        waker_sender: SyncSender<Waker>,
        poll_barrier: Arc<Barrier>,
    }

    impl Future for CrossThreadWakeFuture {
        type Output = &'static str;

        fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
            let future = self.as_mut().get_mut();
            if future.ready.load(Ordering::Acquire) {
                return Poll::Ready("cross-thread-wake");
            }
            if !future.registered {
                future.registered = true;
                future
                    .waker_sender
                    .send(context.waker().clone())
                    .expect("executor test receives the registered waker");
                // The test's receiver establishes that this poll has handed
                // off the exact waker before it is released to return Pending.
                future.poll_barrier.wait();
            }
            if future.ready.load(Ordering::Acquire) {
                Poll::Ready("cross-thread-wake")
            } else {
                Poll::Pending
            }
        }
    }

    struct WakeStormFuture {
        wake_calls_per_poll: usize,
    }

    impl Future for WakeStormFuture {
        type Output = ();

        fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
            for _ in 0..self.wake_calls_per_poll {
                context.waker().wake_by_ref();
            }
            Poll::Pending
        }
    }

    fn http_sampler_xml(
        class: &str,
        implementation: Option<&str>,
        extra_properties: &str,
    ) -> String {
        let implementation = implementation.map_or_else(String::new, |value| {
            format!("<stringProp name=\"HTTPSampler.implementation\">{value}</stringProp>")
        });
        let auto_redirects = if extra_properties.contains("name=\"HTTPSampler.auto_redirects\"") {
            String::new()
        } else {
            "<boolProp name=\"HTTPSampler.auto_redirects\">false</boolProp>".to_owned()
        };
        format!(
            "<{} guiclass=\"HttpTestSampleGui\" testclass=\"{}\" testname=\"HTTP candidate\" enabled=\"true\">\n\
              <stringProp name=\"HTTPSampler.domain\">127.0.0.1</stringProp>\n\
              <stringProp name=\"HTTPSampler.protocol\">http</stringProp>\n\
              <stringProp name=\"HTTPSampler.path\">/</stringProp>\n\
              <stringProp name=\"HTTPSampler.method\">GET</stringProp>\n\
              <boolProp name=\"HTTPSampler.follow_redirects\">false</boolProp>\n\
              {auto_redirects}\n\
              <boolProp name=\"HTTPSampler.use_keepalive\">true</boolProp>\n\
              {implementation}\n\
              {extra_properties}\n\
            </{}>",
            class, class, class
        )
    }

    fn http_plan(
        class: &str,
        implementation: Option<&str>,
        extra_properties: &str,
        include_debug: bool,
    ) -> String {
        let source = String::from_utf8_lossy(include_bytes!(
            "../../../compat/fixtures/jmeter-5.6.3/cli-matrix/inputs/cli-plan.jmx"
        ))
        .to_string();
        let marker = "        <DebugSampler guiclass=\"TestBeanGUI\" testclass=\"DebugSampler\" testname=\"cli-matrix-sample\" enabled=\"true\">\n          <boolProp name=\"displayJMeterProperties\">false</boolProp>\n          <boolProp name=\"displayJMeterVariables\">false</boolProp>\n          <boolProp name=\"displaySystemProperties\">false</boolProp>\n        </DebugSampler>\n        <hashTree/>";
        assert!(source.contains(marker), "fixture marker changed");
        let sampler = http_sampler_xml(class, implementation, extra_properties);
        let replacement = if include_debug {
            format!("{sampler}\n        <hashTree/>\n{marker}")
        } else {
            format!("{sampler}\n        <hashTree/>")
        };
        source.replace(marker, &replacement)
    }

    fn parsed_http_plan(
        class: &str,
        implementation: Option<&str>,
        extra_properties: &str,
        include_debug: bool,
    ) -> SemanticDocument {
        SemanticDocument::from_bytes(
            http_plan(class, implementation, extra_properties, include_debug).as_bytes(),
        )
        .expect("HTTP fixture parses")
    }

    fn http_plan_with_port(
        class: &str,
        implementation: Option<&str>,
        extra_properties: &str,
        include_debug: bool,
        port: u16,
    ) -> String {
        let source = http_plan(class, implementation, extra_properties, include_debug);
        let needle = "<stringProp name=\"HTTPSampler.domain\">127.0.0.1</stringProp>\n";
        let replacement =
            format!("{needle}              <intProp name=\"HTTPSampler.port\">{port}</intProp>\n");
        source.replace(needle, &replacement)
    }

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
    fn report_counter_overflow_is_typed_instead_of_saturating() {
        let interval = ReportInterval::from_millis(0, 86_400_000).expect("report interval");
        let config = DashboardConfig::new(interval).expect("dashboard config");
        let mut dashboard = DashboardReport::new(config);
        let mut stats = ReportStats {
            samples: usize::MAX,
            failed: 0,
        };
        let event = SampleEvent::new(
            SampleResult::new("counter-overflow"),
            "runner-test",
            jmeter_rs_results::ThreadIdentity::new("thread-1"),
            jmeter_rs_results::HostIdentity::new("localhost"),
            jmeter_rs_results::VariableSnapshot::new(),
        );
        let error = add_report_event(&mut dashboard, &mut stats, event)
            .expect_err("sample counter overflow must fail closed");
        assert_eq!(error.code(), "report.overflow");
        assert_eq!(stats.samples, usize::MAX);
        assert_eq!(stats.failed, 0);

        let mut failed_stats = ReportStats {
            samples: 0,
            failed: usize::MAX,
        };
        let mut failed_result = SampleResult::new("counter-overflow-failed");
        failed_result.set_successful(false);
        let failed_event = SampleEvent::new(
            failed_result,
            "runner-test",
            jmeter_rs_results::ThreadIdentity::new("thread-1"),
            jmeter_rs_results::HostIdentity::new("localhost"),
            jmeter_rs_results::VariableSnapshot::new(),
        );
        let failed_error = add_report_event(&mut dashboard, &mut failed_stats, failed_event)
            .expect_err("failure counter overflow must fail closed");
        assert_eq!(failed_error.code(), "report.overflow");
        assert_eq!(failed_stats.samples, 0);
        assert_eq!(failed_stats.failed, usize::MAX);
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
    fn http_without_selector_requires_the_preserved_provider_pack() {
        let document = parsed_http_plan("HTTPSamplerProxy", Some("HttpClient4"), "", false);
        let source = http_plan("HTTPSamplerProxy", Some("HttpClient4"), "", false);
        let error =
            preflight_native_plan(&document, source.as_bytes(), HttpCapabilitySelector::Absent)
                .expect_err("JMeter HTTP provider must not silently become native");
        assert_eq!(error.code(), HTTP_COMPATIBILITY_PACK_REQUIRED);
        assert!(error.to_string().contains("http.jmeter-httpclient4/5.6.3"));
    }

    #[test]
    fn http_native_admission_preserves_source_provider_and_default() {
        let explicit_source = http_plan("HTTPSamplerProxy", Some("Java"), "", false);
        let explicit_document =
            SemanticDocument::from_bytes(explicit_source.as_bytes()).expect("explicit fixture");
        let explicit = preflight_native_plan(
            &explicit_document,
            explicit_source.as_bytes(),
            HttpCapabilitySelector::NativeV1,
        )
        .expect("explicit native HTTP candidate");
        assert_eq!(explicit.nodes.len(), 1);
        assert_eq!(explicit.nodes[0].source_implementation, "Java");
        assert!(!explicit.nodes[0].source_implementation_defaulted);
        assert_eq!(
            explicit.nodes[0].source_capability,
            "http.jmeter-java/5.6.3"
        );
        assert_eq!(
            explicit.nodes[0].executed_capability,
            HTTP_NATIVE_CAPABILITY
        );
        assert_eq!(explicit.nodes[0].request.method, "GET");

        let default_source = http_plan("HTTPHC4Impl", None, "", false);
        let default_document =
            SemanticDocument::from_bytes(default_source.as_bytes()).expect("default fixture");
        let defaulted = preflight_native_plan(
            &default_document,
            default_source.as_bytes(),
            HttpCapabilitySelector::NativeV1,
        )
        .expect("default native HTTP candidate");
        assert_eq!(
            defaulted.nodes[0].source_implementation,
            DEFAULT_HTTP_IMPLEMENTATION
        );
        assert!(defaulted.nodes[0].source_implementation_defaulted);
        assert_eq!(
            defaulted.nodes[0].source_capability,
            "http.jmeter-httpclient4/5.6.3"
        );
        assert_eq!(
            defaulted.nodes[0].executed_capability,
            HTTP_NATIVE_CAPABILITY
        );
    }

    #[test]
    fn pure_executable_admission_decodes_mixed_plan_without_resource_owners() {
        let source = http_plan("HTTPSamplerProxy", Some("Java"), "", true);
        let document = SemanticDocument::from_bytes(source.as_bytes()).expect("mixed plan parses");
        let http = preflight_native_plan(
            &document,
            source.as_bytes(),
            HttpCapabilitySelector::NativeV1,
        )
        .expect("HTTP admission is pure");
        let recipe = admit_executable_plan(&document, source.as_bytes(), Some(&http), None)
            .expect("mixed executable recipe admits before owners");
        assert_eq!(
            recipe.capability_identity(),
            ExecutableCapabilityIdentity::NativeV1
        );
        assert!(recipe.resource_requirements().has_http);
        assert!(recipe.resource_requirements().needs_http_pool);
        assert!(!recipe.resource_requirements().has_hostname);
        assert!(!recipe.resource_requirements().has_https);
        assert_eq!(
            recipe.resource_requirements().transport_limits,
            http.transport_limits()
        );
        assert!(recipe.implementation_manifest().len() >= 3);
    }

    #[test]
    fn pure_admission_rejects_no_thread_group_before_binding() {
        let source = http_plan("HTTPSamplerProxy", Some("Java"), "", true).replace(
            "testclass=\"ThreadGroup\" testname=\"CLI matrix user\" enabled=\"true\"",
            "testclass=\"ThreadGroup\" testname=\"CLI matrix user\" enabled=\"false\"",
        );
        let document = SemanticDocument::from_bytes(source.as_bytes()).expect("plan parses");
        let http = preflight_native_plan(
            &document,
            source.as_bytes(),
            HttpCapabilitySelector::NativeV1,
        )
        .expect("HTTP admission remains pure");
        let error = admit_executable_plan(&document, source.as_bytes(), Some(&http), None)
            .expect_err("missing thread group must fail in pure admission");
        assert_eq!(error.code(), "runtime.no-thread-group");
    }

    #[test]
    fn pure_admission_rejects_enabled_opaque_tail_before_binding() {
        let source = http_plan("HTTPSamplerProxy", Some("Java"), "", true).replace(
            "<DebugSampler guiclass=\"TestBeanGUI\" testclass=\"DebugSampler\" testname=\"cli-matrix-sample\" enabled=\"true\">",
            "<UnknownSampler guiclass=\"TestBeanGUI\" testclass=\"UnknownSampler\" testname=\"opaque-tail\" enabled=\"true\">",
        ).replace("</DebugSampler>", "</UnknownSampler>");
        let document = SemanticDocument::from_bytes(source.as_bytes()).expect("plan parses");
        let http = compile_http_admission(&document, HttpCapabilitySelector::NativeV1)
            .expect("HTTP-only admission remains pure");
        let error = admit_executable_plan(&document, source.as_bytes(), Some(&http), None)
            .expect_err("enabled opaque tail must fail before binding");
        assert_eq!(error.code(), "capability.unavailable");
        assert!(error.to_string().contains("jmx.opaque-element"));
    }

    #[test]
    fn disabled_opaque_sampler_is_retained_but_not_admitted_as_executable() {
        let source = http_plan("HTTPSamplerProxy", Some("Java"), "", true)
            .replace(
                "<DebugSampler guiclass=\"TestBeanGUI\" testclass=\"DebugSampler\" testname=\"cli-matrix-sample\" enabled=\"true\">",
                "<UnknownSampler guiclass=\"TestBeanGUI\" testclass=\"UnknownSampler\" testname=\"disabled-opaque\" enabled=\"false\">",
            )
            .replace("</DebugSampler>", "</UnknownSampler>");
        let document = SemanticDocument::from_bytes(source.as_bytes()).expect("plan parses");
        let http = preflight_native_plan(
            &document,
            source.as_bytes(),
            HttpCapabilitySelector::NativeV1,
        )
        .expect("disabled opaque sampler does not affect HTTP admission");
        let recipe = admit_executable_plan(&document, source.as_bytes(), Some(&http), None)
            .expect("disabled opaque sampler is preserved outside executable recipe");
        assert!(recipe.resource_requirements().has_http);
    }

    #[test]
    fn binding_rejects_mismatched_recipe_identity_without_reclassification() {
        let source = http_plan("HTTPSamplerProxy", Some("Java"), "", false);
        let document = SemanticDocument::from_bytes(source.as_bytes()).expect("plan parses");
        let http = preflight_native_plan(
            &document,
            source.as_bytes(),
            HttpCapabilitySelector::NativeV1,
        )
        .expect("HTTP admission");
        let recipe = admit_executable_plan(&document, source.as_bytes(), Some(&http), None)
            .expect("pure recipe");
        let resources = ExecutableResourceBindings {
            plan_digest: Digest32::sha256(b"different-plan"),
            capability: ExecutableCapabilityIdentity::NativeV1,
            http_pool: None,
            native_v2_factory: None,
            native_http_transport: None,
            time_driver: None,
            projection: None,
        };
        let error = recipe
            .bind_resources(&resources)
            .expect_err("different plan identity must fail before binding");
        assert_eq!(error.code(), "runtime.executable-bind.plan-mismatch");
    }

    #[test]
    fn binding_owner_free_recipe_builds_engine_plan_without_reclassification() {
        let source =
            include_bytes!("../../../compat/fixtures/jmeter-5.6.3/cli-matrix/inputs/cli-plan.jmx");
        let document = SemanticDocument::from_bytes(source).expect("fixture parses");
        let recipe = admit_executable_plan(&document, source, None, None)
            .expect("non-HTTP recipe admits purely");
        let resources = ExecutableResourceBindings {
            plan_digest: recipe.plan_digest(),
            capability: recipe.capability_identity(),
            http_pool: None,
            native_v2_factory: None,
            native_http_transport: None,
            time_driver: None,
            projection: None,
        };
        let (plan, packages) = recipe
            .bind_resources(&resources)
            .expect("matching owner-free binding succeeds");
        assert!(packages > 0);
        assert_eq!(plan.groups.len(), 1);
    }

    #[test]
    fn native_http_request_brackets_numeric_ipv6_authority() {
        let candidate = NativeHttpRequestCandidate {
            domain: "::1".to_owned(),
            port: Some(8080),
            protocol: "http".to_owned(),
            path: "/".to_owned(),
            method: "GET".to_owned(),
            content_encoding: DEFAULT_HTTP_CONTENT_ENCODING.to_owned(),
            follow_redirects: false,
            auto_redirects: false,
            use_keepalive: true,
            concurrent_pool: None,
            connect_timeout_ms: None,
            response_timeout_ms: None,
        };
        let request = native_http_request(&candidate).expect("numeric IPv6 request");
        assert_eq!(request.url().authority(), "[::1]:8080");
        assert_eq!(request.wire_target(), "/");
    }

    #[test]
    fn native_http_transport_errors_are_failed_samples_and_finalize_pool() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("error loopback listener");
        let port = listener
            .local_addr()
            .expect("error loopback address")
            .port();
        let barrier = Arc::new(Barrier::new(2));
        let (done_sender, done_receiver) = mpsc::sync_channel(1);
        let server_barrier = Arc::clone(&barrier);
        let server = thread::spawn(move || {
            server_barrier.wait();
            let (_stream, _) = listener.accept().expect("error HTTP connection");
            done_sender.send(()).expect("error server completion");
        });
        barrier.wait();
        let base = std::env::temp_dir().join(format!(
            "jmeter-rs-http-transport-admission-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).expect("HTTP admission fixture directory");
        fs::write(
            base.join("plan.jmx"),
            http_plan_with_port("HTTPSamplerProxy", Some("HttpClient4"), "", false, port),
        )
        .expect("HTTP plan");
        let invocation = crate::parse([
            "-n",
            "-t",
            "plan.jmx",
            "-Jjmeter-rs.http.capability=http.native/1",
            "-l",
            "results.jtl",
            "-j",
            "run.log",
            "-e",
            "-o",
            "report",
        ])
        .expect("native HTTP invocation");
        let outcome = execute_invocation(&invocation, &LaunchEnvironment::new(&base))
            .expect("network failure is sample data");
        done_receiver.recv().expect("error server completed");
        server.join().expect("error server join");
        assert_eq!(outcome.category, RunCategory::SampleFailure);
        assert_eq!(outcome.samples, 1);
        assert_eq!(outcome.sample_failures, 1);
        let jtl = fs::read_to_string(base.join("results.jtl")).expect("failed sample JTL");
        assert!(jtl.contains("HTTP candidate"));
        assert!(jtl.contains("false"));
        let log = fs::read_to_string(base.join("run.log")).expect("native HTTP run log");
        assert!(log.contains("http.jmeter-httpclient4/5.6.3"));
        assert!(log.contains("http.native/1"));
        assert!(base.join("report/index.html").is_file());
        fs::remove_dir_all(&base).expect("HTTP admission fixture cleanup");
    }

    #[test]
    fn selector_errors_are_stable_and_resolved_before_filesystem_access() {
        let launch = LaunchEnvironment::new(
            std::env::temp_dir().join("jmeter-rs-http-selector-no-such-directory"),
        );
        let repeated = crate::parse([
            "-n",
            "-t",
            "plan.jmx",
            "-Jjmeter-rs.http.capability=http.native/1",
            "-Jjmeter-rs.http.capability=http.native/1",
        ])
        .expect("repeated selector parses");
        let repeated_error = execute_invocation(&repeated, &launch)
            .expect_err("repeated selector must fail before cwd access");
        assert_eq!(repeated_error.code(), "http.selector.repeated");
        assert_eq!(repeated_error.exit_class(), ExitClass::UsageError);

        let unknown = crate::parse([
            "-n",
            "-t",
            "plan.jmx",
            "-Jjmeter-rs.http.capability=http.native/3",
        ])
        .expect("unknown selector parses");
        let unknown_error = execute_invocation(&unknown, &launch)
            .expect_err("unknown selector must fail before cwd access");
        assert_eq!(unknown_error.code(), "http.selector.unknown");
        assert_eq!(unknown_error.exit_class(), ExitClass::UsageError);
    }

    #[test]
    fn native_http_unsupported_field_wins_before_transport_unavailable() {
        let base = std::env::temp_dir().join(format!(
            "jmeter-rs-http-unsupported-field-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).expect("HTTP unsupported fixture directory");
        fs::write(
            base.join("plan.jmx"),
            http_plan(
                "HTTPSamplerProxy",
                Some("HttpClient4"),
                "<boolProp name=\"HTTPSampler.auto_redirects\">true</boolProp>",
                true,
            ),
        )
        .expect("HTTP unsupported plan");
        let invocation = crate::parse([
            "-n",
            "-t",
            "plan.jmx",
            "-Jjmeter-rs.http.capability=http.native/1",
            "-l",
            "results.jtl",
            "-j",
            "run.log",
            "-e",
            "-o",
            "report",
        ])
        .expect("native HTTP unsupported invocation");
        let error = execute_invocation(&invocation, &LaunchEnvironment::new(&base))
            .expect_err("automatic redirects must be rejected");
        assert_eq!(error.code(), HTTP_NATIVE_AUTO_REDIRECTS);
        assert!(!base.join("results.jtl").exists());
        assert!(!base.join("run.log").exists());
        assert!(!base.join("report").exists());
        fs::remove_dir_all(&base).expect("HTTP unsupported fixture cleanup");
    }

    #[test]
    fn mixed_debug_and_http_runs_both_scope_mapped_samplers() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("mixed loopback listener");
        let port = listener
            .local_addr()
            .expect("mixed loopback address")
            .port();
        let barrier = Arc::new(Barrier::new(2));
        let (done_sender, done_receiver) = mpsc::sync_channel(1);
        let server_barrier = Arc::clone(&barrier);
        let server = thread::spawn(move || {
            server_barrier.wait();
            let (mut stream, _) = listener.accept().expect("mixed HTTP connection");
            let mut request = [0_u8; 1024];
            let read = stream.read(&mut request).expect("mixed request");
            assert!(read > 0);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
                .expect("mixed response");
            stream.flush().expect("mixed response flush");
            done_sender.send(()).expect("mixed server completion");
        });
        barrier.wait();
        let base = std::env::temp_dir().join(format!(
            "jmeter-rs-http-mixed-admission-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).expect("mixed HTTP fixture directory");
        fs::write(
            base.join("plan.jmx"),
            http_plan_with_port("HTTPSamplerProxy", Some("Java"), "", true, port),
        )
        .expect("mixed HTTP plan");
        let invocation = crate::parse([
            "-n",
            "-t",
            "plan.jmx",
            "-Jjmeter-rs.http.capability=http.native/1",
            "-l",
            "results.jtl",
            "-j",
            "run.log",
            "-e",
            "-o",
            "report",
        ])
        .expect("mixed HTTP invocation");
        let outcome = execute_invocation(&invocation, &LaunchEnvironment::new(&base))
            .expect("mixed plan should execute each admitted sampler");
        done_receiver.recv().expect("mixed server completed");
        server.join().expect("mixed server join");
        assert_eq!(outcome.samples, 2);
        assert_eq!(outcome.sample_failures, 0);
        let jtl = fs::read_to_string(base.join("results.jtl")).expect("mixed JTL");
        assert!(jtl.contains("HTTP candidate"));
        assert!(jtl.contains("cli-matrix-sample"));
        fs::remove_dir_all(&base).expect("mixed HTTP fixture cleanup");
    }

    #[test]
    fn native_http_loopback_response_is_projected_to_jtl() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
        let port = listener.local_addr().expect("loopback address").port();
        let barrier = Arc::new(Barrier::new(2));
        let (done_sender, done_receiver) = mpsc::sync_channel(1);
        let server_barrier = Arc::clone(&barrier);
        let server = thread::spawn(move || {
            server_barrier.wait();
            let (mut stream, _) = listener.accept().expect("one native HTTP connection");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let read = stream.read(&mut buffer).expect("read request head");
                assert!(read > 0, "client closed before request head");
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
                assert!(request.len() <= 16 * 1024, "request head bound");
            }
            assert!(request.starts_with(b"GET / HTTP/1.1\r\n"));
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: keep-alive\r\n\r\nhello, native",
                )
                .expect("write loopback response");
            stream.flush().expect("flush loopback response");
            done_sender.send(()).expect("report server completion");
        });
        barrier.wait();

        let base =
            std::env::temp_dir().join(format!("jmeter-rs-http-loopback-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).expect("loopback fixture directory");
        fs::write(
            base.join("plan.jmx"),
            http_plan_with_port("HTTPSamplerProxy", Some("Java"), "", false, port),
        )
        .expect("loopback HTTP plan");
        let invocation = crate::parse([
            "-n",
            "-t",
            "plan.jmx",
            "-Jjmeter-rs.http.capability=http.native/1",
            "-Jjmeter.save.saveservice.output_format=xml",
            "-Jjmeter.save.saveservice.response_data=true",
            "-l",
            "results.jtl",
            "-j",
            "run.log",
        ])
        .expect("loopback invocation");
        let outcome = execute_invocation(&invocation, &LaunchEnvironment::new(&base))
            .expect("loopback HTTP run");
        done_receiver.recv().expect("server completed before join");
        server.join().expect("loopback server join");
        assert_eq!(outcome.samples, 1);
        assert_eq!(outcome.sample_failures, 0);
        let jtl = fs::read_to_string(base.join("results.jtl")).expect("loopback JTL");
        assert!(jtl.contains("HTTP candidate"));
        assert!(jtl.contains("hello, native"));
        assert!(jtl.contains("200"));
        fs::remove_dir_all(&base).expect("loopback fixture cleanup");
    }

    #[test]
    fn native_http_rejects_hostname_and_https_before_outputs() {
        let cases = [
            (
                "hostname",
                http_plan("HTTPSamplerProxy", Some("Java"), "", false)
                    .replace("127.0.0.1", "localhost"),
                HTTP_NATIVE_HOSTNAME,
            ),
            (
                "https",
                http_plan("HTTPSamplerProxy", Some("Java"), "", false).replace(
                    "<stringProp name=\"HTTPSampler.protocol\">http</stringProp>",
                    "<stringProp name=\"HTTPSampler.protocol\">https</stringProp>",
                ),
                HTTP_NATIVE_INVALID_FIELD,
            ),
        ];
        for (name, source, expected_code) in cases {
            let base = std::env::temp_dir().join(format!(
                "jmeter-rs-http-reject-{name}-{}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&base);
            fs::create_dir_all(&base).expect("rejection fixture directory");
            fs::write(base.join("plan.jmx"), source).expect("rejection plan");
            let invocation = crate::parse([
                "-n",
                "-t",
                "plan.jmx",
                "-Jjmeter-rs.http.capability=http.native/1",
                "-l",
                "results.jtl",
                "-j",
                "run.log",
            ])
            .expect("rejection invocation");
            let error = execute_invocation(&invocation, &LaunchEnvironment::new(&base))
                .expect_err("unsupported origin must reject atomically");
            assert_eq!(error.code(), expected_code);
            assert!(!base.join("results.jtl").exists());
            assert!(!base.join("run.log").exists());
            fs::remove_dir_all(&base).expect("rejection fixture cleanup");
        }
    }

    #[test]
    fn unsupported_native_plan_is_rejected_before_output_or_log_creation() {
        let base =
            std::env::temp_dir().join(format!("jmeter-rs-runner-admission-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).expect("admission fixture directory");
        let source = String::from_utf8_lossy(include_bytes!(
            "../../../compat/fixtures/jmeter-5.6.3/cli-matrix/inputs/cli-plan.jmx"
        ))
        .replace("DebugSampler", "UnknownSampler");
        fs::write(base.join("plan.jmx"), source.as_bytes()).expect("unsupported JMX fixture");
        fs::write(base.join("result.jtl"), b"keep-result").expect("existing result fixture");
        fs::write(base.join("run.log"), b"keep-log").expect("existing log fixture");
        let invocation = crate::parse([
            "-n",
            "-t",
            "plan.jmx",
            "-l",
            "result.jtl",
            "-j",
            "run.log",
            "-f",
        ])
        .expect("native invocation");
        let error = execute_invocation(&invocation, &LaunchEnvironment::new(&base))
            .expect_err("unknown executable node must fail closed");
        assert_eq!(error.code(), "capability.unavailable");
        assert_eq!(
            fs::read(base.join("result.jtl")).expect("result after refusal"),
            b"keep-result"
        );
        assert_eq!(
            fs::read(base.join("run.log")).expect("log after refusal"),
            b"keep-log"
        );
        fs::remove_dir_all(&base).expect("admission fixture cleanup");
    }

    #[test]
    fn unsupported_mode_is_rejected_before_working_directory_access() {
        let launch = LaunchEnvironment::new(
            std::env::temp_dir().join("jmeter-rs-runner-path-that-does-not-exist"),
        );
        // A remote selector is an unavailable external capability.  The
        // preflight must win before the launch path is canonicalized.
        let invocation = crate::parse(["-n", "-t", "plan.jmx", "-r"]).expect("remote invocation");
        let error = execute_invocation(&invocation, &launch)
            .expect_err("remote capability must fail before path access");
        assert_eq!(error.code(), "remote.unavailable");
    }

    #[test]
    fn gui_capability_is_rejected_before_log_creation() {
        let base = std::env::temp_dir().join(format!(
            "jmeter-rs-runner-gui-admission-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).expect("GUI admission fixture directory");
        let invocation = crate::parse(std::iter::empty::<&str>()).expect("default GUI invocation");
        let error = execute_invocation(&invocation, &LaunchEnvironment::new(&base))
            .expect_err("GUI capability must fail closed");
        assert_eq!(error.code(), "capability.unavailable");
        assert!(!base.join("jmeter.log").exists());
        fs::remove_dir_all(&base).expect("GUI admission fixture cleanup");
    }

    #[test]
    fn admitted_native_plan_runs_and_routes_bounded_jtl() {
        let base = std::env::temp_dir().join(format!(
            "jmeter-rs-runner-native-route-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).expect("native route fixture directory");
        fs::write(
            base.join("plan.jmx"),
            include_bytes!("../../../compat/fixtures/jmeter-5.6.3/cli-matrix/inputs/cli-plan.jmx"),
        )
        .expect("native route JMX fixture");
        let invocation =
            crate::parse(["-n", "-t", "plan.jmx", "-l", "results.jtl", "-j", "run.log"])
                .expect("native route invocation");
        let outcome = execute_invocation(&invocation, &LaunchEnvironment::new(&base))
            .expect("admitted native plan runs");
        assert_eq!(outcome.samples, 1);
        assert_eq!(outcome.sample_failures, 0);
        assert_eq!(outcome.result_file, Some(base.join("results.jtl")));
        let jtl = fs::read_to_string(base.join("results.jtl")).expect("read routed JTL");
        assert!(jtl.contains("cli-matrix-sample"));
        assert!(base.join("run.log").is_file());
        fs::remove_dir_all(&base).expect("native route fixture cleanup");
    }

    #[test]
    fn admitted_native_plan_publishes_report_at_end_from_routed_jtl() {
        let base = std::env::temp_dir().join(format!(
            "jmeter-rs-runner-native-report-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).expect("native report fixture directory");
        fs::write(
            base.join("plan.jmx"),
            include_bytes!("../../../compat/fixtures/jmeter-5.6.3/cli-matrix/inputs/cli-plan.jmx"),
        )
        .expect("native report JMX fixture");
        let invocation = crate::parse([
            "-n",
            "-t",
            "plan.jmx",
            "-l",
            "results.jtl",
            "-e",
            "-o",
            "dashboard",
        ])
        .expect("native report invocation");
        let outcome = execute_invocation(&invocation, &LaunchEnvironment::new(&base))
            .expect("admitted native report run");
        assert_eq!(outcome.samples, 1);
        assert_eq!(outcome.report_directory, Some(base.join("dashboard")));
        assert!(base.join("results.jtl").is_file());
        assert!(base.join("dashboard/index.html").is_file());
        assert!(base.join("dashboard/data.json").is_file());
        fs::remove_dir_all(&base).expect("native report fixture cleanup");
    }

    #[test]
    fn lifecycle_groups_compile_and_run_in_setup_main_teardown_order() {
        let source = include_bytes!(
            "../../../compat/fixtures/jmeter-5.6.3/controllers-full/lifecycle-groups/plan.jmx"
        );
        let document = SemanticDocument::from_bytes(source).expect("fixture parses");
        let (plan, packages) = compile_local_plan(&document).expect("lifecycle groups compile");
        assert_eq!(plan.groups.len(), 3);
        assert_eq!(packages, 3);
        assert_eq!(plan.groups[0].kind, GroupKind::Setup);
        assert_eq!(plan.groups[1].kind, GroupKind::Main);
        assert_eq!(plan.groups[2].kind, GroupKind::Teardown);

        let report = run_document(&document);
        let started = report
            .events
            .iter()
            .filter_map(|event| match event {
                EngineEvent::GroupStarted { kind, .. } => Some(*kind),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            started,
            vec![GroupKind::Setup, GroupKind::Main, GroupKind::Teardown]
        );
        assert_eq!(
            sample_labels(&report),
            vec!["setup-marker", "main-marker", "teardown-marker"]
        );
    }

    #[test]
    fn nested_builtin_controllers_preserve_order_and_disabled_branches() {
        let source = include_bytes!(
            "../../../compat/fixtures/jmeter-5.6.3/controllers-full/basic-traversal/plan.jmx"
        );
        let document = SemanticDocument::from_bytes(source).expect("fixture parses");
        let report = run_document(&document);
        let labels = sample_labels(&report);
        // The nested finite loop is beneath a synthetic OnceOnly boundary. Its
        // state persists when the outer loop advances, so its two samples are
        // emitted only during the first outer visit.
        assert_eq!(
            labels,
            vec![
                "simple-before-${__jm__Thread iterations__idx}",
                "simple-after",
                "finite-${__jm__Finite nested loop__idx}",
                "finite-${__jm__Finite nested loop__idx}",
                "once-only",
                "interleave-a",
                "simple-before-${__jm__Thread iterations__idx}",
                "simple-after",
                "interleave-b",
            ]
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>(),
        );
        assert!(
            !labels
                .iter()
                .any(|label| label.contains("disabled-must-not-run"))
        );
        assert!(
            !labels
                .iter()
                .any(|label| label.contains("zero-must-not-run"))
        );
    }

    #[test]
    fn initial_variables_are_seeded_before_debug_sampler_expression_context() {
        let source = String::from_utf8_lossy(include_bytes!(
            "../../../compat/fixtures/jmeter-5.6.3/cli-matrix/inputs/cli-plan.jmx"
        ))
        .replace(
            "testname=\"cli-matrix-sample\"",
            "testname=\"${cli_matrix_marker}\"",
        );
        let document = SemanticDocument::from_bytes(source.as_bytes()).expect("fixture parses");
        let (plan, _) = compile_local_plan(&document).expect("initial-variable plan compiles");
        assert_eq!(
            plan.initial_variables().get("cli_matrix_marker"),
            Some("static-fixture")
        );
        let report = run_document(&document);
        assert_eq!(sample_labels(&report), vec!["static-fixture"]);
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
    fn executor_immediate_ready_future_completes_without_waiting() {
        let policy = ExecutorPolicy::new(4, 4, Duration::ZERO).expect("valid test policy");
        let value = block_on_with_policy(std::future::ready(17_u32), policy)
            .expect("immediate-ready future completes");
        assert_eq!(value, 17);
    }

    #[test]
    fn executor_observes_synchronous_wake_before_waiting() {
        let policy = ExecutorPolicy::new(4, 4, Duration::ZERO).expect("valid test policy");
        let value = block_on_with_policy(SynchronousWakeFuture { polled: false }, policy)
            .expect("synchronous wake must repoll before the idle check");
        assert_eq!(value, 2);
    }

    #[test]
    fn executor_observes_cross_thread_wake_with_exact_join() {
        let (waker_sender, waker_receiver): (SyncSender<Waker>, Receiver<Waker>) =
            mpsc::sync_channel(1);
        let ready = Arc::new(AtomicBool::new(false));
        let poll_barrier = Arc::new(Barrier::new(2));
        let future = CrossThreadWakeFuture {
            ready: Arc::clone(&ready),
            registered: false,
            waker_sender,
            poll_barrier: Arc::clone(&poll_barrier),
        };
        let policy = ExecutorPolicy::new(16, 16, Duration::from_secs(1))
            .expect("valid cross-thread test policy");
        let worker = thread::spawn(move || block_on_with_policy(future, policy));

        // Receiving the waker is the exact handoff point; no wall-clock sleep
        // is used to guess whether the worker has reached Pending.
        let waker = waker_receiver
            .recv()
            .expect("worker registers a waker before waiting");
        poll_barrier.wait();
        ready.store(true, Ordering::Release);
        waker.wake();

        let result = worker.join().expect("executor worker joins exactly once");
        assert_eq!(
            result.expect("cross-thread wake completes"),
            "cross-thread-wake"
        );
    }

    #[test]
    fn executor_idle_policy_rejects_never_woken_pending() {
        let policy = ExecutorPolicy::new(4, 4, Duration::ZERO).expect("valid idle test policy");
        let error = block_on_with_policy(std::future::pending::<()>(), policy)
            .expect_err("a never-ready future must hit the finite idle policy");
        assert_eq!(error.code(), "runtime.executor-idle");
    }

    #[test]
    fn executor_wake_storm_is_bounded_separately_from_polls() {
        let policy = ExecutorPolicy::new(64, 3, Duration::ZERO).expect("valid storm policy");
        let error = block_on_with_policy(
            WakeStormFuture {
                wake_calls_per_poll: 4,
            },
            policy,
        )
        .expect_err("wake storm must hit its finite wake budget");
        assert_eq!(error.code(), "runtime.executor-wake-limit");
    }

    #[test]
    fn executor_self_waking_future_hits_poll_bound() {
        let policy = ExecutorPolicy::new(3, 64, Duration::ZERO).expect("valid poll policy");
        let error = block_on_with_policy(
            WakeStormFuture {
                wake_calls_per_poll: 1,
            },
            policy,
        )
        .expect_err("self-waking future must hit its finite poll budget");
        assert_eq!(error.code(), "runtime.executor-poll-limit");
    }

    #[test]
    fn executor_policy_rejects_unbounded_poll_and_wake_limits() {
        let poll_error = ExecutorPolicy::new(0, 1, Duration::ZERO)
            .expect_err("zero poll budget must be rejected");
        assert_eq!(poll_error.code(), "runtime.executor-policy");
        let wake_error = ExecutorPolicy::new(1, 0, Duration::ZERO)
            .expect_err("zero wake budget must be rejected");
        assert_eq!(wake_error.code(), "runtime.executor-policy");
        let idle_error = ExecutorPolicy::new(1, 1, MAX_EXECUTOR_IDLE + Duration::from_secs(1))
            .expect_err("idle bound above the finite cap must be rejected");
        assert_eq!(idle_error.code(), "runtime.executor-idle");
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

    #[test]
    fn staged_result_is_not_visible_before_publication_and_cleans_on_abort() {
        let serial = NEXT_RESULT_STAGING_ID.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!(
            "jmeter-rs-runner-staging-abort-{}-{serial}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        let work = base.join("work");
        fs::create_dir_all(&work).expect("staging test directory");
        let target = work.join("results.jtl");
        let (mut prepared, mut writer) =
            PreparedResultTarget::prepare(&target, OutputOpenMode::CreateNew, &work)
                .expect("private staging file");
        writer.write_all(b"partial result").expect("staging write");
        assert!(!target.exists(), "partial output must stay private");
        assert!(
            fs::read_dir(&work)
                .expect("staging directory read")
                .flatten()
                .any(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".jmeter-rs-result-"))
        );

        drop(writer);
        prepared.cleanup().expect("abort staging cleanup");
        assert!(!target.exists(), "aborted run must not publish a target");
        assert!(
            !fs::read_dir(&work)
                .expect("staging directory read")
                .flatten()
                .any(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".jmeter-rs-result-"))
        );
        fs::remove_dir_all(&base).expect("staging test cleanup");
    }

    #[test]
    fn staged_result_preserves_previous_target_when_publication_revalidation_fails() {
        let serial = NEXT_RESULT_STAGING_ID.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!(
            "jmeter-rs-runner-staging-preserve-{}-{serial}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        let work = base.join("work");
        fs::create_dir_all(&work).expect("staging test directory");
        let target = work.join("results.jtl");
        fs::write(&target, b"previous").expect("previous result");
        let (mut prepared, mut writer) =
            PreparedResultTarget::prepare(&target, OutputOpenMode::ReplaceExisting, &work)
                .expect("private replacement staging file");
        writer.write_all(b"replacement").expect("staging write");
        drop(writer);

        // A target replacement between admission and publication must fail
        // closed; the replacement remains visible and the private stage is
        // removed by the caller's cleanup boundary.
        let replacement = work.join("operator-replacement.jtl");
        fs::write(&replacement, b"operator replacement").expect("replacement target");
        fs::remove_file(&target).expect("swap previous target");
        fs::rename(&replacement, &target).expect("install replacement target");
        let error = prepared
            .publish()
            .expect_err("changed target must block publication");
        assert_eq!(error.code(), "io.output");
        assert_eq!(
            fs::read(&target).expect("replacement remains"),
            b"operator replacement"
        );
        prepared.cleanup().expect("staging cleanup");
        assert!(
            !fs::read_dir(&work)
                .expect("staging directory read")
                .flatten()
                .any(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".jmeter-rs-result-"))
        );
        fs::remove_dir_all(&base).expect("staging test cleanup");
    }

    #[test]
    fn report_only_retains_input_handle_across_path_replacement() {
        let base = std::env::temp_dir().join(format!(
            "jmeter-rs-runner-report-input-handle-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).expect("report input test directory");
        let input_path = base.join("input.jtl");
        fs::write(
            &input_path,
            b"timeStamp,elapsed,label\n0,1,retained-input\n",
        )
        .expect("valid report input");
        let replacement = base.join("replacement.jtl");
        let invocation =
            crate::parse(["-g", "input.jtl", "-o", "dashboard"]).expect("report invocation");
        let launch = LaunchEnvironment::new(&base);
        let plan = ConfigPlan::from_invocation(&invocation).with_base_dir(&base);
        let resolved = ConfigLoader::rooted(&base)
            .resolve(&plan)
            .expect("report configuration");

        let prepared =
            preflight_report_only(&invocation, &launch, &resolved).expect("report input preflight");
        fs::write(&replacement, b"malformed replacement input").expect("replacement report input");
        fs::rename(&replacement, &input_path).expect("replace report input path");

        let mut logger =
            RunLogger::initialize(&invocation, &resolved, &launch).expect("report logger");
        let outcome = report_only(&invocation, &launch, prepared, &mut logger)
            .expect("retained report input remains readable");
        logger.finish().expect("report logger finish");
        assert_eq!(outcome.samples, 1);
        let dashboard =
            fs::read_to_string(base.join("dashboard/data.json")).expect("dashboard data");
        assert!(dashboard.contains("retained-input"));
        assert!(!dashboard.contains("malformed replacement input"));
        fs::remove_dir_all(&base).expect("report input test cleanup");
    }

    #[test]
    fn published_result_report_handle_survives_target_replacement() {
        let serial = NEXT_RESULT_STAGING_ID.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!(
            "jmeter-rs-runner-exact-report-handle-{}-{serial}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        let work = base.join("work");
        fs::create_dir_all(&work).expect("exact-handle test directory");
        let target = work.join("results.jtl");
        let (mut prepared, mut writer) =
            PreparedResultTarget::prepare(&target, OutputOpenMode::CreateNew, &work)
                .expect("private staging file");
        writer
            .write_all(b"exact-staged-result")
            .expect("staging write");
        drop(writer);
        prepared.publish().expect("result publication");

        let handle = prepared
            .report_reader
            .as_ref()
            .expect("retained report handle");
        assert_eq!(
            metadata_identity(&handle.metadata().expect("handle metadata")),
            metadata_identity(&fs::metadata(&target).expect("published metadata")),
            "report handle must identify the published staging inode"
        );

        let replacement = work.join("operator-replacement.jtl");
        fs::write(&replacement, b"path-replacement").expect("replacement result");
        fs::rename(&replacement, &target).expect("replace published path");

        let mut report_reader = prepared
            .take_report_reader()
            .expect("exact report handle after publication");
        let mut bytes = Vec::new();
        report_reader
            .read_to_end(&mut bytes)
            .expect("read exact report handle");
        assert_eq!(bytes, b"exact-staged-result");
        assert_eq!(
            fs::read(&target).expect("replacement path"),
            b"path-replacement"
        );
        prepared.cleanup().expect("exact-handle cleanup");
        fs::remove_dir_all(&base).expect("exact-handle test cleanup");
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
