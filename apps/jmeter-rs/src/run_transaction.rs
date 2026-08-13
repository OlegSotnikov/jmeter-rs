// SPDX-License-Identifier: Apache-2.0
//! Consuming transaction for one standalone local run.
//!
//! The command-line edge is intentionally split into typed, consuming
//! phases.  Pure plan/request admission happens before a worker, output sink,
//! logger, or engine is created.  Once a run owner exists, every error path
//! goes through the same finalization sequence and reports bounded cleanup
//! categories alongside the primary failure.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use jmeter_rs_http::SampleResultProjectionOptions;
use jmeter_rs_http_native::NativeTransportLimits;
use jmeter_rs_jmx::SemanticDocument;
use jmeter_rs_model::NodeId;
use jmeter_rs_report::ReportInterval;
use jmeter_rs_results::{DataLimits, RunIdentity, SaveWireFormat, TimestampSource};
use jmeter_rs_runtime::{
    CancellationToken, DurabilityBoundary, EmptyEnvironment, EmptyFileSystem, EnginePlan,
    FullPolicy, PlanDomain, QualifiedSinkId, ResultClockError, ResultDeliveryBudget,
    ResultDeliveryBudgetConfig, ResultOperationScope, ResultOperationWindows, RetryBudget,
    RunObservationPolicyV1, RuntimeCapabilities, RuntimeEngine, SinkLimits, SinkPlanGeneration,
    TypedResultRouter, TypedResultRouterAdapter, TypedRouterError, TypedRouterIdentity, TypedRunId,
    TypedSinkAdapter, TypedSinkPlan, WorkerGeneration, WorkerId, ZeroRandom,
};

use crate::current_thread_executor::{CurrentThreadExecutor, CurrentThreadExecutorError};
use crate::http_worker::{
    HttpWorkerPool, OperationClockAdapter, OperationClockError, PoolError, PoolLimits,
};
use crate::jtl_sink::{JtlSinkLimits, JtlSinkOwner, TypedJtlSinkAdapter};
use crate::native_http_plan::compile_native_v2_http_plan;
use crate::native_http_run::{
    NativeHttpRunError, NativeHttpRunOwner, NativeHttpRunRecipe, NativeHttpRunRequirements,
};
use crate::native_v2_request::{NativeV2RequestMapper, PreparedNativeV2RequestMap};
use crate::native_v2_sampler::NativeV2ScopeFactory;
use crate::report_policy::admit_report_policy;
use crate::runner::{
    AdmittedExecutableRecipe, CleanupCategory, CleanupFailure, CompiledHttpAdmission,
    ExecutableResourceBindings, LaunchEnvironment, OutputOpenMode, PreparedReportTarget,
    PreparedResultTarget, ReportOutputMode, RunCategory, RunError, RunLogger, RunOutcome,
    admit_executable_plan, cleanup_jtl_owner, configured_save_wire_format, engine_summary_counts,
    jtl_sink_error, preflight_native_plan, preflight_native_plan_with_http_ids,
    prepare_report_target, read_native_ca_bytes, report_from_published_result,
    resolve_checked_path, resolve_path_argument, runtime_properties, sample_result_projection,
    save_configuration,
};
use crate::time_driver::{TimeDriver, TimeDriverError, TimeDriverHandle, TimeDriverLimits};
use crate::{
    CliInvocation, ConfigLoader, HttpCapabilitySelector, HttpNativeV2Properties, ResolvedConfig,
    RunMode,
};

/// The result operation windows are per-operation liveness bounds.  They are
/// deliberately independent of the duration of the load test itself.
const RESULT_OPERATION_WINDOW: Duration = Duration::from_secs(30);
const RESULT_FINALIZATION_WINDOW: Duration = Duration::from_secs(60);
const RESULT_RETRY_ATTEMPTS: u32 = 64;
/// A CLI `-l` sink is not a JMX node.  It still needs a nonzero qualified
/// collector identity so typed routing cannot fall back to a numeric sink ID.
const CLI_RESULT_SINK_NODE_ID: u64 = u64::MAX;
const RESULT_SINK_PLAN_GENERATION: u64 = 1;
const RESULT_RUN_GENERATION: u64 = 1;
const RESULT_WORKER_ID: u64 = 1;
const RESULT_WORKER_GENERATION: u64 = 1;

/// Parsed invocation; this state has no owned file, thread, output, or logger.
struct ParsedInvocation<'a> {
    invocation: &'a CliInvocation,
    launch: &'a LaunchEnvironment,
    loader: &'a ConfigLoader,
    resolved: &'a ResolvedConfig,
    selector: HttpCapabilitySelector,
}

/// Semantic source loaded from the descriptor-bound input capability.
struct LoadedInputs<'a> {
    parsed: ParsedInvocation<'a>,
    source: Vec<u8>,
    document: SemanticDocument,
}

enum HttpAdmission {
    None,
    V1(CompiledHttpAdmission),
    V2(PreparedNativeV2RequestMap),
}

fn admitted_router_identity(
    source: &[u8],
) -> Result<(TypedRouterIdentity, QualifiedSinkId), RunError> {
    let capabilities = crate::STANDALONE_NATIVE_CAPABILITIES
        .iter()
        .map(|(id, version)| ((*id).to_owned(), version.to_string()))
        .collect::<Vec<_>>();
    let domain = PlanDomain::from_canonical_plan_and_profile_text(
        source,
        b"local",
        crate::JMETER_COMPATIBILITY_PROFILE,
        crate::JMETER_COMPATIBILITY_PROFILE_VERSION.to_string(),
        capabilities,
    )
    .map_err(|error| RunError::Runtime {
        code: "runtime.result-identity.plan-domain".to_owned(),
        message: error.to_string(),
    })?;
    let typed_run =
        TypedRunId::from_run_identity(&RunIdentity::new("jmeter-rs")).map_err(|error| {
            RunError::Runtime {
                code: "runtime.result-identity.run".to_owned(),
                message: error.to_string(),
            }
        })?;
    let run_generation =
        jmeter_rs_runtime::RunGeneration::new(RESULT_RUN_GENERATION).map_err(|error| {
            RunError::Runtime {
                code: "runtime.result-identity.run-generation".to_owned(),
                message: error.to_string(),
            }
        })?;
    let worker = WorkerId::new(RESULT_WORKER_ID).map_err(|error| RunError::Runtime {
        code: "runtime.result-identity.worker".to_owned(),
        message: error.to_string(),
    })?;
    let worker_generation =
        WorkerGeneration::new(RESULT_WORKER_GENERATION).map_err(|error| RunError::Runtime {
            code: "runtime.result-identity.worker-generation".to_owned(),
            message: error.to_string(),
        })?;
    let sink_plan_generation =
        SinkPlanGeneration::new(RESULT_SINK_PLAN_GENERATION).map_err(|error| {
            RunError::Runtime {
                code: "runtime.result-identity.sink-generation".to_owned(),
                message: error.to_string(),
            }
        })?;
    let identity =
        TypedRouterIdentity::new(domain, typed_run, run_generation, worker, worker_generation);
    let collector = identity
        .node(NodeId::new(CLI_RESULT_SINK_NODE_ID))
        .map_err(|error| RunError::Runtime {
            code: "runtime.result-identity.collector".to_owned(),
            message: error.to_string(),
        })?;
    let sink_id = QualifiedSinkId::from_parts(typed_run, sink_plan_generation, collector);
    Ok((identity, sink_id))
}

impl HttpAdmission {
    fn requirements(&self) -> NativeHttpRunRequirements {
        match self {
            Self::None => NativeHttpRunRequirements::new(false, false, false),
            Self::V1(admission) => {
                NativeHttpRunRequirements::new(admission.has_http(), false, false)
            }
            Self::V2(map) => {
                let requirements = map.requirements();
                NativeHttpRunRequirements::new(
                    requirements.has_http,
                    requirements.has_hostname,
                    requirements.has_https,
                )
            }
        }
    }
}

/// Pure complete-plan admission.  The V2 map is prepared before any owner,
/// output target, or logger exists; direct CA bytes are read in the following
/// transition, after selector/requirement facts are immutable.
struct AdmittedRun<'a> {
    loaded: LoadedInputs<'a>,
    admission: HttpAdmission,
    recipe: AdmittedExecutableRecipe,
    router_identity: TypedRouterIdentity,
    sink_id: QualifiedSinkId,
    v2_properties: HttpNativeV2Properties,
    ca_bytes: Option<Vec<u8>>,
    result_path: Option<std::path::PathBuf>,
    report_policy: Option<crate::report_policy::AdmittedReportPolicy>,
    save_configuration: Option<crate::runner::ResolvedSaveConfiguration>,
    projection: SampleResultProjectionOptions,
}

/// All run-owned resources created in the mandated order.
struct PreparedResources<'a> {
    admitted: AdmittedRun<'a>,
    time_driver: TimeDriver,
    time_handle: TimeDriverHandle,
    native_http: Option<NativeHttpRunOwner>,
    http_pool: Option<HttpWorkerPool>,
    result_target: Option<PreparedResultTarget>,
    report_target: Option<PreparedReportTarget>,
    jtl_owner: Option<JtlSinkOwner>,
    typed_router: Option<TypedResultRouterAdapter>,
    logger: Option<RunLogger>,
    engine_plan: EnginePlan,
}

/// Engine execution owns the exact future and all prepared owners.
struct RunningRun<'a> {
    resources: PreparedResources<'a>,
    engine: RuntimeEngine,
}

struct FinalizedRun<'a> {
    resources: PreparedResources<'a>,
    report_counts: (usize, usize),
}

/// Public module entry point used by `runner::local_run`.
pub(crate) fn run_local(
    invocation: &CliInvocation,
    launch: &LaunchEnvironment,
    loader: &ConfigLoader,
    resolved: &ResolvedConfig,
    selector: HttpCapabilitySelector,
) -> Result<RunOutcome, RunError> {
    let parsed = ParsedInvocation {
        invocation,
        launch,
        loader,
        resolved,
        selector,
    };
    let loaded = parsed.load()?;
    let admitted = loaded.admit()?;
    let prepared = admitted.prepare()?;
    let running = prepared.start_engine()?;
    let finalized = running.finalize()?;
    finalized.publish()
}

impl<'a> ParsedInvocation<'a> {
    fn load(self) -> Result<LoadedInputs<'a>, RunError> {
        let test = self
            .invocation
            .options
            .testfile
            .as_ref()
            .ok_or_else(|| RunError::Runtime {
                code: "runtime.no-test-plan".to_owned(),
                message: "non-GUI runs require a test plan".to_owned(),
            })?;
        let test_path = resolve_path_argument(test, ".jmx", self.launch)?;
        let source = self
            .loader
            .read_file(&test_path)
            .map_err(RunError::from_config)?;
        let document = SemanticDocument::from_bytes(&source).map_err(|error| RunError::Jmx {
            message: error.to_string(),
        })?;
        Ok(LoadedInputs {
            parsed: self,
            source,
            document,
        })
    }
}

impl<'a> LoadedInputs<'a> {
    fn admit(self) -> Result<AdmittedRun<'a>, RunError> {
        let selector = self.parsed.selector;
        let admission = match selector {
            HttpCapabilitySelector::NativeV1 | HttpCapabilitySelector::Absent => {
                let admission = preflight_native_plan(&self.document, &self.source, selector)?;
                if admission.has_http() {
                    HttpAdmission::V1(admission)
                } else {
                    HttpAdmission::None
                }
            }
            HttpCapabilitySelector::NativeV2 => {
                let compiled = compile_native_v2_http_plan(&self.document)
                    .map_err(|error| RunError::unsupported(error.code(), error.to_string()))?;
                let map = NativeV2RequestMapper::new()
                    .prepare(&compiled)
                    .map_err(|error| RunError::unsupported(error.code(), error.to_string()))?;
                let ids = map
                    .samplers()
                    .iter()
                    .map(|sampler| sampler.node_id())
                    .collect::<BTreeSet<_>>();
                preflight_native_plan_with_http_ids(&self.document, &self.source, &ids)?;
                if map.requirements().has_http {
                    HttpAdmission::V2(map)
                } else {
                    HttpAdmission::None
                }
            }
        };

        // Complete owner-free executable admission happens before CA bytes,
        // output targets, loggers, workers, or the runtime engine exist.
        let recipe = admit_executable_plan(
            &self.document,
            &self.source,
            match &admission {
                HttpAdmission::V1(admission) => Some(admission),
                HttpAdmission::None | HttpAdmission::V2(_) => None,
            },
            match &admission {
                HttpAdmission::V2(map) => Some(map),
                HttpAdmission::None | HttpAdmission::V1(_) => None,
            },
        )?;
        let (router_identity, sink_id) = admitted_router_identity(&self.source)?;

        let v2_properties = self
            .parsed
            .invocation
            .resolve_http_native_v2_properties()
            .map_err(|error| RunError::http(error.code(), error.to_string()))?;
        if !selector.is_native_v2() && !v2_properties.is_empty() {
            return Err(RunError::http(
                "app.native-http.v2-properties-unused",
                "NativeV2 DNS/CA properties require the exact NativeV2 selector",
            ));
        }
        let requirements = admission.requirements();
        if !requirements.has_http && !v2_properties.is_empty() {
            return Err(RunError::http(
                "app.native-http.v2-properties-unused",
                "NativeV2 DNS/CA properties were supplied without an HTTP plan",
            ));
        }

        // Explicit CA bytes precede every owner/output side effect.  An
        // unused CA token is rejected before touching the filesystem.
        let ca_bytes = if let Some(ca) = v2_properties.tls_ca_file.as_ref() {
            if !requirements.has_https {
                return Err(RunError::http(
                    "app.native-http.ca-material-unused",
                    "NativeV2 CA material is unused by the admitted plan",
                ));
            }
            let path = resolve_checked_path(self.parsed.launch.cwd.as_path(), ca.path().as_str())?;
            Some(read_native_ca_bytes(&path, &self.parsed.launch.cwd)?)
        } else {
            None
        };

        let result_path = self
            .parsed
            .invocation
            .options
            .logfile
            .as_ref()
            .map(|argument| resolve_path_argument(argument, ".jtl", self.parsed.launch))
            .transpose()?;
        let report_policy = if self.parsed.invocation.options.report_at_end {
            let interval =
                ReportInterval::from_millis(0, 86_400_000).map_err(|error| RunError::Report {
                    code: error.stable_code(),
                    message: error.to_string(),
                })?;
            Some(
                admit_report_policy(self.parsed.resolved, interval)
                    .map_err(|error| RunError::unsupported(error.code(), error.to_string()))?,
            )
        } else {
            None
        };
        let save_configuration = result_path
            .as_ref()
            .map(|_| configured_save_wire_format(self.parsed.resolved, SaveWireFormat::Csv))
            .map_or(Ok(None), |format| {
                save_configuration(self.parsed.resolved, format).map(Some)
            })?;
        let projection = save_configuration
            .as_ref()
            .map(sample_result_projection)
            .unwrap_or(SampleResultProjectionOptions {
                data_limits: DataLimits::default_bounded(),
                include_response_data: false,
                include_response_headers: false,
                timestamp_source: TimestampSource::Start,
                include_request_metadata: false,
            });
        Ok(AdmittedRun {
            loaded: self,
            admission,
            recipe,
            router_identity,
            sink_id,
            v2_properties,
            ca_bytes,
            result_path,
            report_policy,
            save_configuration,
            projection,
        })
    }
}

impl<'a> AdmittedRun<'a> {
    fn prepare(self) -> Result<PreparedResources<'a>, RunError> {
        // Preparation order is an observable safety contract: time first,
        // then the exact provider owner, then workers, then private outputs.
        let time_driver =
            TimeDriver::new(TimeDriverLimits::default()).map_err(|error| RunError::Runtime {
                code: error.code().to_owned(),
                message: error.to_string(),
            })?;
        let time_handle = time_driver.handle();
        let requirements = self.recipe.resource_requirements();
        let native_http = if requirements.has_http {
            let transport_limits = match &self.admission {
                HttpAdmission::V1(admission) => admission
                    .transport_limits()
                    .unwrap_or_else(NativeTransportLimits::default),
                HttpAdmission::V2(map) => *map.transport_limits(),
                HttpAdmission::None => NativeTransportLimits::default(),
            };
            let recipe = match NativeHttpRunRecipe::with_limits(
                self.loaded.parsed.selector,
                NativeHttpRunRequirements::new(
                    requirements.has_http,
                    requirements.has_hostname,
                    requirements.has_https,
                ),
                self.v2_properties.clone(),
                self.ca_bytes.clone(),
                transport_limits,
            ) {
                Ok(recipe) => recipe,
                Err(error) => {
                    return Err(cleanup_prepared(
                        RunError::http(error.code(), error.to_string()),
                        time_driver,
                        None,
                        None,
                    ));
                }
            };
            match NativeHttpRunOwner::new(recipe) {
                Ok(owner) => Some(owner),
                Err(error) => {
                    let mut primary = RunError::http(error.code(), error.to_string());
                    if let Err(cleanup) = time_driver.finalize() {
                        primary = transaction_error(
                            primary,
                            vec![cleanup_failure(CleanupCategory::TimeDriver, cleanup.code())],
                        );
                    }
                    return Err(primary);
                }
            }
        } else {
            None
        };

        let http_pool_handle = Arc::new(Mutex::new(None));
        let http_pool = if requirements.needs_http_pool {
            let clock_handle = time_handle.clone();
            let clock = Arc::new(OperationClockAdapter::new(move || {
                match clock_handle.try_now() {
                    Ok(reading) => Ok(jmeter_rs_runtime::MonotonicInstant::from_duration(
                        reading.monotonic,
                    )),
                    Err(TimeDriverError::ClockMovedBackward { .. }) => {
                        Err(OperationClockError::Reversed)
                    }
                    Err(_) => Err(OperationClockError::Unavailable),
                }
            }));
            let pool = match HttpWorkerPool::new(PoolLimits::default(), clock) {
                Ok(pool) => pool,
                Err(error) => {
                    let mut primary = RunError::http(error.code(), error.to_string());
                    if let Some(mut owner) = native_http {
                        if let Err(cleanup) = owner.finalize() {
                            primary = transaction_error(
                                primary,
                                vec![cleanup_failure(CleanupCategory::NativeHttp, cleanup.code())],
                            );
                        }
                    }
                    if let Err(cleanup) = time_driver.finalize() {
                        primary = transaction_error(
                            primary,
                            vec![cleanup_failure(CleanupCategory::TimeDriver, cleanup.code())],
                        );
                    }
                    return Err(primary);
                }
            };
            let submitter = pool.submitter();
            *http_pool_handle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(submitter);
            Some(pool)
        } else {
            None
        };

        // The complete plan/factory graph was admitted before any owner was
        // created. Binding below only consumes that immutable recipe and the
        // exact owners; it performs no source decoding or provider selection.
        let native_v2_factory = match (&self.admission, native_http.as_ref(), http_pool.as_ref()) {
            (HttpAdmission::V2(map), Some(owner), Some(pool)) => {
                match NativeV2ScopeFactory::try_new(
                    map.clone(),
                    owner,
                    pool.submitter(),
                    time_handle.clone(),
                    self.projection.clone(),
                ) {
                    Ok(factory) => Some(factory),
                    Err(error) => {
                        return Err(cleanup_prepared(
                            RunError::unsupported(error.code(), error.to_string()),
                            time_driver,
                            native_http,
                            http_pool,
                        ));
                    }
                }
            }
            (HttpAdmission::V2(_), _, _) => {
                return Err(cleanup_prepared(
                    RunError::Runtime {
                        code: "app.native-http.v2.owner-missing".to_owned(),
                        message: "NativeV2 factory admission lacks its exact owners".to_owned(),
                    },
                    time_driver,
                    native_http,
                    http_pool,
                ));
            }
            _ => None,
        };
        let bindings = ExecutableResourceBindings {
            plan_digest: self.recipe.plan_digest(),
            capability: self.recipe.capability_identity(),
            http_pool: requirements
                .needs_http_pool
                .then_some(Arc::clone(&http_pool_handle)),
            native_v2_factory,
            native_http_transport: native_http.as_ref().map(NativeHttpRunOwner::transport),
            time_driver: requirements
                .needs_time_driver
                .then_some(time_handle.clone()),
            projection: requirements.has_http.then_some(self.projection.clone()),
        };
        let (engine_plan, _) = match self.recipe.bind_resources(&bindings) {
            Ok(plan) => plan,
            Err(error) => {
                return Err(cleanup_prepared(error, time_driver, native_http, http_pool));
            }
        };

        let output_mode = if self
            .loaded
            .parsed
            .invocation
            .options
            .force_delete_result_file
        {
            OutputOpenMode::ReplaceExisting
        } else {
            OutputOpenMode::CreateNew
        };
        let mut result_target = None;
        let mut jtl_owner = None;
        if let (Some(path), Some(configuration)) =
            (self.result_path.as_ref(), self.save_configuration.as_ref())
        {
            let (target, file) = match PreparedResultTarget::prepare(
                path,
                output_mode,
                &self.loaded.parsed.launch.cwd,
            ) {
                Ok(value) => value,
                Err(error) => {
                    return Err(cleanup_prepared(error, time_driver, native_http, http_pool));
                }
            };
            let sink_limits = JtlSinkLimits::default();
            let owner = match JtlSinkOwner::new(
                Box::new(file),
                configuration.wire().clone(),
                sink_limits,
            ) {
                Ok(owner) => owner,
                Err(error) => {
                    let primary = jtl_sink_error(error);
                    let mut target = Some(target);
                    let mut sink = None;
                    return Err(cleanup_partial(
                        primary,
                        &mut target,
                        &mut sink,
                        native_http,
                        http_pool,
                        time_driver,
                    ));
                }
            };
            result_target = Some(target);
            jtl_owner = Some(owner);
        }

        let report_target = if self.report_policy.is_some() {
            let mode = if self
                .loaded
                .parsed
                .invocation
                .options
                .force_delete_result_file
            {
                ReportOutputMode::ReplaceExisting
            } else {
                ReportOutputMode::CreateNew
            };
            match prepare_report_target(
                self.loaded
                    .parsed
                    .invocation
                    .options
                    .report_output_folder
                    .as_deref(),
                self.loaded.parsed.launch,
                mode,
            ) {
                Ok(target) => Some(target),
                Err(error) => {
                    let mut result = result_target;
                    let mut sink = jtl_owner;
                    let primary = cleanup_partial(
                        error,
                        &mut result,
                        &mut sink,
                        native_http,
                        http_pool,
                        time_driver,
                    );
                    return Err(primary);
                }
            }
        } else {
            None
        };

        let logger = match RunLogger::initialize(
            self.loaded.parsed.invocation,
            self.loaded.parsed.resolved,
            self.loaded.parsed.launch,
        ) {
            Ok(logger) => Some(logger),
            Err(error) => {
                let mut result = result_target;
                let mut sink = jtl_owner;
                return Err(cleanup_partial(
                    error,
                    &mut result,
                    &mut sink,
                    native_http,
                    http_pool,
                    time_driver,
                ));
            }
        };
        Ok(PreparedResources {
            admitted: self,
            time_driver,
            time_handle,
            native_http,
            http_pool,
            result_target,
            report_target,
            jtl_owner,
            typed_router: None,
            logger,
            engine_plan,
        })
    }
}

fn build_typed_router(
    owner: &JtlSinkOwner,
    time_handle: &TimeDriverHandle,
    cancellation: &CancellationToken,
    identity: TypedRouterIdentity,
    sink_id: QualifiedSinkId,
) -> Result<TypedResultRouterAdapter, RunError> {
    let clock_handle = time_handle.clone();
    let clock = Arc::new(move || match clock_handle.try_now() {
        Ok(reading) => Ok(jmeter_rs_runtime::MonotonicInstant::from_duration(
            reading.monotonic,
        )),
        Err(TimeDriverError::ClockMovedBackward { previous, current }) => {
            Err(ResultClockError::Reversed {
                previous: jmeter_rs_runtime::MonotonicInstant::from_duration(previous),
                current: jmeter_rs_runtime::MonotonicInstant::from_duration(current),
            })
        }
        Err(TimeDriverError::ClockOverflow { .. }) => Err(ResultClockError::Overflow),
        Err(_) => Err(ResultClockError::Unavailable),
    });
    let budget = ResultDeliveryBudget::new(
        clock,
        Arc::new(cancellation.clone()),
        ResultDeliveryBudgetConfig::new(
            ResultOperationScope::sink_set(identity.run(), sink_id.sink_plan_generation()),
            ResultOperationWindows::uniform(RESULT_OPERATION_WINDOW, RESULT_FINALIZATION_WINDOW),
            RESULT_RETRY_ATTEMPTS,
            None,
        ),
    )
    .map_err(|error| typed_router_error(TypedRouterError::Budget(error)))?;
    let sink_limits = JtlSinkLimits::default();
    let finalization_steps =
        sink_limits
            .max_items
            .checked_add(2)
            .ok_or_else(|| RunError::Runtime {
                code: "runtime.result-router.finalization-limit".to_owned(),
                message: "result sink finalization bound overflowed".to_owned(),
            })?;
    let router_limits = SinkLimits::with_finalization(
        sink_limits.max_items,
        sink_limits.max_bytes,
        finalization_steps,
    );
    let sink_plan = TypedSinkPlan::with_boundary(
        sink_id,
        router_limits,
        FullPolicy::FailRun,
        DurabilityBoundary::FormatWritten,
    );
    let router = TypedResultRouter::new(
        identity.run(),
        identity.run_generation(),
        RetryBudget::new(RESULT_RETRY_ATTEMPTS),
        [sink_plan],
    )
    .map_err(typed_router_error)?;
    let sink_adapter: Arc<dyn TypedSinkAdapter> =
        Arc::new(TypedJtlSinkAdapter::new(owner.submitter(), sink_id));
    // The registrar is the same run-owned time-driver capability consumed by
    // the current-thread executor. It registers exact Provider waits into
    // the driver's registry and never installs the unavailable/no-op
    // compatibility registrar.
    let wait_registrar = Arc::new(time_handle.clone());
    TypedResultRouterAdapter::new_with_liveness(
        router,
        identity,
        [(sink_id, sink_adapter)],
        budget,
        wait_registrar,
    )
    .map_err(typed_router_error)
}

impl<'a> PreparedResources<'a> {
    fn start_engine(mut self) -> Result<RunningRun<'a>, RunError> {
        if let Some(logger) = self.logger.as_mut() {
            if self.admitted.recipe.resource_requirements().has_http {
                match &self.admitted.admission {
                    HttpAdmission::V1(admission) => logger.info(&admission.log_summary()),
                    HttpAdmission::V2(map) => logger.info(&format!(
                        "http nodes={} source-providers=native-v2 executed={}",
                        map.samplers().len(),
                        map.provider()
                    )),
                    HttpAdmission::None => {}
                }
            }
        }
        let properties = Arc::new(RwLock::new(runtime_properties(
            &self.admitted.loaded.parsed.resolved.jmeter,
        )));
        let capabilities = RuntimeCapabilities::new(
            Arc::new(self.time_handle.clone()),
            Arc::new(self.time_handle.clone()),
            Arc::new(ZeroRandom),
            Arc::new(EmptyFileSystem),
            Arc::new(EmptyEnvironment),
        )
        .with_scheduler(Arc::new(self.time_handle.clone()))
        .with_properties(properties);
        let mut engine = RuntimeEngine::new(
            self.engine_plan.clone(),
            capabilities,
            "jmeter-rs",
            "localhost",
        )
        .with_observation_policy(RunObservationPolicyV1::Summary);

        // The typed adapter is assembled only after the complete recipe has
        // been admitted and the private output handle exists. Its budget is
        // bound to this exact engine cancellation source and this run's
        // monotonic driver; there is no legacy numeric router on this path.
        if let Some(owner) = self.jtl_owner.as_ref() {
            let typed_router = match build_typed_router(
                owner,
                &self.time_handle,
                engine.cancellation(),
                self.admitted.router_identity,
                self.admitted.sink_id,
            ) {
                Ok(router) => router,
                Err(primary) => return Err(cleanup_prepared_resources(self, primary)),
            };
            self.typed_router = Some(typed_router.clone());
            engine = engine.with_typed_result_router(typed_router);
        }
        Ok(RunningRun {
            resources: self,
            engine,
        })
    }
}

impl<'a> RunningRun<'a> {
    fn finalize(mut self) -> Result<FinalizedRun<'a>, RunError> {
        let cancellation = self.engine.cancellation().clone();
        let future = self.engine.run();
        let executor = CurrentThreadExecutor::from_runtime_engine(
            future,
            self.resources.time_driver.wait_registry(),
            self.resources.time_handle.clone(),
            cancellation,
        );
        let execution = executor.run().map_err(executor_error);
        let mut resources = self.resources;
        let (mut primary, counts) = match execution {
            Ok(Ok(report)) => match engine_summary_counts(&report.summary) {
                Ok(counts) => (None, Some(counts)),
                Err(error) => (Some(error), None),
            },
            Ok(Err(error)) => (
                Some(RunError::Runtime {
                    code: error.code().to_owned(),
                    message: error.to_string(),
                }),
                None,
            ),
            Err(error) => (Some(error), None),
        };

        let Some(counts) = counts else {
            let primary = primary.unwrap_or_else(|| RunError::Runtime {
                code: "runtime.engine.no-result".to_owned(),
                message: "runtime engine completed without a report".to_owned(),
            });
            return Err(finalize_failure(primary, resources));
        };
        if let Some(primary) = primary.take() {
            return Err(finalize_failure(primary, resources));
        }

        if let Some(logger) = resources.logger.as_mut() {
            logger.info(&format!(
                "local plan samples={} failures={}",
                counts.0, counts.1
            ));
        }
        if let Err(error) = cleanup_jtl_owner(&mut resources.jtl_owner, false) {
            record_cleanup_error(&mut primary, error, CleanupCategory::Jtl);
        }
        if let Some(pool) = resources.http_pool.take()
            && let Err(error) = pool.finalize()
        {
            record_cleanup_error(
                &mut primary,
                pool_cleanup_error(error),
                CleanupCategory::HttpPool,
            );
        }
        if let Some(owner) = resources.native_http.as_mut()
            && let Err(error) = owner.finalize()
        {
            record_cleanup_error(
                &mut primary,
                native_http_cleanup_error(error),
                CleanupCategory::NativeHttp,
            );
        }
        if let Err(error) = resources.time_driver.finalize() {
            record_cleanup_error(
                &mut primary,
                time_driver_cleanup_error(error),
                CleanupCategory::TimeDriver,
            );
        }

        // Logger completion is an owner cleanup boundary too.  It precedes
        // publication so a logging failure can never leave a visible result
        // that the transaction would otherwise report as successful.
        if let Some(logger) = resources.logger.as_ref()
            && let Err(error) = logger.finish()
        {
            record_cleanup_error(&mut primary, error, CleanupCategory::Logging);
        }

        // Publication is attempted only after every owner cleanup above has
        // succeeded.  A cleanup failure is therefore fail-closed with no
        // user-visible result switch.
        if publication_allowed(primary.as_ref())
            && let Some(target) = resources.result_target.as_mut()
            && let Err(error) = target.publish()
        {
            record_cleanup_error(&mut primary, error, CleanupCategory::Staging);
        }
        if let (Some(report_target), Some(result_target)) = (
            resources.report_target.as_ref(),
            resources.result_target.as_mut(),
        ) {
            if publication_allowed(primary.as_ref()) {
                if let Err(error) = report_from_published_result(
                    report_target,
                    result_target,
                    resources.admitted.loaded.parsed.resolved,
                ) {
                    primary = Some(error);
                }
            }
        }
        if let Err(error) = cleanup_result_target(&mut resources.result_target) {
            record_cleanup_error(&mut primary, error, CleanupCategory::Staging);
        }
        if let Some(primary) = primary {
            return Err(primary);
        }
        let report_counts = counts;
        Ok(FinalizedRun {
            resources,
            report_counts,
        })
    }
}

impl<'a> FinalizedRun<'a> {
    fn publish(self) -> Result<RunOutcome, RunError> {
        let resources = self.resources;
        let (samples, failed) = self.report_counts;
        let result_file = resources.admitted.result_path.clone();
        let report_directory = resources.report_target.as_ref().map(|target| target.path());
        let log_file = resources.logger.as_ref().and_then(RunLogger::path);
        Ok(RunOutcome {
            mode: RunMode::NonGui,
            category: if failed == 0 {
                RunCategory::Normal
            } else {
                RunCategory::SampleFailure
            },
            samples,
            sample_failures: failed,
            result_file,
            report_directory,
            log_file,
        })
    }
}

fn executor_error(error: CurrentThreadExecutorError) -> RunError {
    RunError::Runtime {
        code: error.code().to_owned(),
        message: error.to_string(),
    }
}

fn typed_router_error(error: TypedRouterError) -> RunError {
    RunError::Runtime {
        code: "runtime.result-router".to_owned(),
        message: error.to_string(),
    }
}

fn pool_cleanup_error(error: PoolError) -> RunError {
    let message = error.to_string();
    RunError::Runtime {
        code: error.code().to_owned(),
        message,
    }
}

fn native_http_cleanup_error(error: NativeHttpRunError) -> RunError {
    let message = error.to_string();
    RunError::Runtime {
        code: error.code().to_owned(),
        message,
    }
}

fn time_driver_cleanup_error(error: TimeDriverError) -> RunError {
    let message = error.to_string();
    RunError::Runtime {
        code: error.code().to_owned(),
        message,
    }
}

fn cleanup_failure(category: CleanupCategory, code: &str) -> CleanupFailure {
    CleanupFailure {
        category,
        code: code.to_owned(),
    }
}

fn publication_allowed(primary: Option<&RunError>) -> bool {
    primary.is_none()
}

fn record_cleanup_error(
    primary: &mut Option<RunError>,
    error: RunError,
    category: CleanupCategory,
) {
    let code = error.code().to_owned();
    if let Some(existing) = primary.take() {
        *primary = Some(transaction_error(
            existing,
            vec![cleanup_failure(category, &code)],
        ));
    } else {
        *primary = Some(RunError::Cleanup {
            primary: Box::new(error),
            cleanup: vec![cleanup_failure(category, &code)],
        });
    }
}

fn transaction_error(primary: RunError, cleanup: Vec<CleanupFailure>) -> RunError {
    if cleanup.is_empty() {
        return primary;
    }
    match primary {
        RunError::Cleanup {
            primary,
            cleanup: mut existing,
        } => {
            existing.extend(cleanup);
            RunError::Cleanup {
                primary,
                cleanup: existing,
            }
        }
        primary => RunError::Cleanup {
            primary: Box::new(primary),
            cleanup,
        },
    }
}

fn cleanup_result_target(target: &mut Option<PreparedResultTarget>) -> Result<(), RunError> {
    let Some(target) = target.as_mut() else {
        return Ok(());
    };
    // A successfully published target has no private staging entry; a failed
    // transaction removes only the exact still-private staging inode.
    target.cleanup()
}

fn finalize_failure<'a>(primary: RunError, mut resources: PreparedResources<'a>) -> RunError {
    let mut result = primary;
    // The async finish boundary is attempted by `RunningRun::finalize` even
    // when engine execution failed.  This synchronous cancellation is the
    // final safety net for watchdog/drop paths and is idempotent after a
    // successful finish.
    if let Some(router) = resources.typed_router.as_ref()
        && let Err(error) = router.cancel()
    {
        result = append_cleanup_to_result(result, typed_router_error(error), CleanupCategory::Jtl);
    }
    if let Err(error) = cleanup_jtl_owner(&mut resources.jtl_owner, true) {
        result = append_cleanup_to_result(result, error, CleanupCategory::Jtl);
    }
    if let Some(pool) = resources.http_pool.take()
        && let Err(error) = pool.finalize()
    {
        result =
            append_cleanup_to_result(result, pool_cleanup_error(error), CleanupCategory::HttpPool);
    }
    if let Some(owner) = resources.native_http.as_mut()
        && let Err(error) = owner.finalize()
    {
        result = append_cleanup_to_result(
            result,
            native_http_cleanup_error(error),
            CleanupCategory::NativeHttp,
        );
    }
    if let Err(error) = resources.time_driver.finalize() {
        result = append_cleanup_to_result(
            result,
            time_driver_cleanup_error(error),
            CleanupCategory::TimeDriver,
        );
    }
    if let Err(error) = cleanup_result_target(&mut resources.result_target) {
        result = append_cleanup_to_result(result, error, CleanupCategory::Staging);
    }
    if let Some(logger) = resources.logger.as_ref()
        && let Err(error) = logger.finish()
    {
        result = append_cleanup_to_result(result, error, CleanupCategory::Logging);
    }
    result
}

fn append_cleanup_to_result(
    primary: RunError,
    error: RunError,
    category: CleanupCategory,
) -> RunError {
    let code = error.code().to_owned();
    transaction_error(primary, vec![cleanup_failure(category, &code)])
}

fn cleanup_partial<'a>(
    primary: RunError,
    result_target: &mut Option<PreparedResultTarget>,
    jtl_owner: &mut Option<JtlSinkOwner>,
    mut native_http: Option<NativeHttpRunOwner>,
    http_pool: Option<HttpWorkerPool>,
    time_driver: TimeDriver,
) -> RunError {
    let mut result = primary;
    if let Err(error) = cleanup_jtl_owner(jtl_owner, true) {
        result = transaction_error(
            result,
            vec![cleanup_failure(CleanupCategory::Jtl, error.code())],
        );
    }
    if let Some(pool) = http_pool
        && let Err(error) = pool.finalize()
    {
        result = transaction_error(
            result,
            vec![cleanup_failure(CleanupCategory::HttpPool, error.code())],
        );
    }
    if let Some(owner) = native_http.as_mut()
        && let Err(error) = owner.finalize()
    {
        result = transaction_error(
            result,
            vec![cleanup_failure(CleanupCategory::NativeHttp, error.code())],
        );
    }
    if let Err(error) = time_driver.finalize() {
        result = transaction_error(
            result,
            vec![cleanup_failure(CleanupCategory::TimeDriver, error.code())],
        );
    }
    if let Err(error) = cleanup_result_target(result_target) {
        result = transaction_error(
            result,
            vec![cleanup_failure(CleanupCategory::Staging, error.code())],
        );
    }
    result
}

fn cleanup_prepared<'a>(
    primary: RunError,
    time_driver: TimeDriver,
    native_http: Option<NativeHttpRunOwner>,
    http_pool: Option<HttpWorkerPool>,
) -> RunError {
    cleanup_partial(
        primary,
        &mut None,
        &mut None,
        native_http,
        http_pool,
        time_driver,
    )
}

fn cleanup_prepared_resources<'a>(resources: PreparedResources<'a>, primary: RunError) -> RunError {
    finalize_failure(primary, resources)
}

#[cfg(test)]
mod tests {
    use super::{CleanupCategory, RunError, publication_allowed, record_cleanup_error};

    #[test]
    fn sink_primary_and_cleanup_are_ordered_and_block_publication() {
        let mut result = Some(RunError::Runtime {
            code: "runtime.engine.sample".to_owned(),
            message: "sample failed".to_owned(),
        });
        record_cleanup_error(
            &mut result,
            RunError::Runtime {
                code: "runtime.result-router".to_owned(),
                message: "sink finish failed".to_owned(),
            },
            CleanupCategory::Jtl,
        );
        record_cleanup_error(
            &mut result,
            RunError::Runtime {
                code: "execution.jtl-publication".to_owned(),
                message: "staging cleanup failed".to_owned(),
            },
            CleanupCategory::Staging,
        );

        assert!(!publication_allowed(result.as_ref()));
        let RunError::Cleanup { primary, cleanup } = result.expect("aggregate") else {
            panic!("cleanup diagnostics must be retained");
        };
        assert_eq!(primary.code(), "runtime.engine.sample");
        assert_eq!(cleanup.len(), 2);
        assert_eq!(cleanup[0].category, CleanupCategory::Jtl);
        assert_eq!(cleanup[0].code, "runtime.result-router");
        assert_eq!(cleanup[1].category, CleanupCategory::Staging);
        assert_eq!(cleanup[1].code, "execution.jtl-publication");
    }

    #[test]
    fn first_cleanup_failure_keeps_its_category_without_a_primary() {
        let mut result = None;
        record_cleanup_error(
            &mut result,
            RunError::Runtime {
                code: "runtime.result-router".to_owned(),
                message: "sink cleanup failed".to_owned(),
            },
            CleanupCategory::Jtl,
        );
        let RunError::Cleanup { primary, cleanup } = result.expect("aggregate") else {
            panic!("first cleanup must be categorized");
        };
        assert_eq!(primary.code(), "runtime.result-router");
        assert_eq!(
            cleanup.as_slice(),
            &[super::CleanupFailure {
                category: CleanupCategory::Jtl,
                code: "runtime.result-router".to_owned(),
            }]
        );
    }
}
