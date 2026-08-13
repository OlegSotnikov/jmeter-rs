// SPDX-License-Identifier: Apache-2.0
//! NativeV2 HTTP sampler and factory boundary.
//!
//! This module is intentionally a narrow application seam.  Request
//! preparation remains in [`crate::native_v2_request`], the immutable
//! provider remains owned by [`crate::native_http_run::NativeHttpRunOwner`],
//! and blocking protocol work remains behind [`crate::http_worker`].  The
//! sampler only joins those capabilities to the executor-neutral runtime:
//! one virtual-user client, one absolute operation deadline, one runtime wait
//! registration, and one bounded result projection.

#![forbid(unsafe_code)]
#![allow(
    clippy::module_name_repetitions,
    reason = "the application boundary names its NativeV2 factory and sampler types explicitly"
)]

use std::fmt;
use std::future::{self, Future};
use std::panic::{self, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use jmeter_rs_http::{HttpClient, SampleResultProjectionOptions};
use jmeter_rs_http_native::NativeHttpTransport;
use jmeter_rs_model::NodeId;
use jmeter_rs_results::SampleResult;
use jmeter_rs_runtime::{
    CancellationToken, ComponentCategory, ComponentError, ComponentFuture, ControlSignal, Deadline,
    FactoryComponent, MonotonicInstant, SampleContext, SampleFailure, Sampler, SamplerFactory,
    SamplerOutput, Scheduler, ScopeComponent, ScopeComponentFactory, ScopeFactoryError,
    WakeRegistration,
};

use crate::http_worker::{
    HttpOperation, HttpOperationFuture, HttpWorkerSubmitter, OperationDeadline, PoolError,
};
use crate::native_http_plan::NativeV2SourceProvider;
use crate::native_http_run::NativeHttpRunOwner;
use crate::native_v2_request::{
    NATIVE_V2_REQUEST_CAPABILITY, PreparedNativeV2RequestMap, PreparedNativeV2Sampler,
};
use crate::time_driver::TimeDriverHandle;

/// The exact source aliases accepted by the NativeV2 request mapper.
///
/// `HTTPHC4Impl` and other HTTP-looking aliases are deliberately absent:
/// accepting a class which the mapper did not prepare would create a provider
/// fallback at the runtime boundary.
pub const NATIVE_V2_HTTP_TEST_CLASSES: &[&str] = &[
    "HTTPSamplerProxy",
    "org.apache.jmeter.protocol.http.sampler.HTTPSamplerProxy",
];

/// Stable, bounded errors raised while joining a prepared map to a run.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum NativeV2FactoryError {
    /// The map or an entry selected a provider other than NativeV2.
    ProviderMismatch,
    /// The owner and prepared map selected different immutable transport
    /// limits.
    TransportLimitsMismatch,
    /// Whole-plan requirements do not match the run-owned subordinate
    /// capabilities.
    RequirementsMismatch,
    /// The map's count or duration invariant is not valid at this seam.
    MapInvariant,
    /// A map entry contains an invalid source identity.
    EntryInvariant,
    /// A requested source node has no prepared entry.
    NodeNotPrepared,
    /// The component's source path does not equal the prepared path.
    SourcePathMismatch,
    /// The component's source name does not equal the prepared name.
    SourceNameMismatch,
    /// The component's source provider provenance does not equal the prepared
    /// provenance.
    SourceProviderMismatch,
    /// The source class is not one of the exact NativeV2 aliases.
    TestClassUnsupported,
    /// The runtime package/context sampler identity drifted from the
    /// prepared source identity.
    SamplerIdentityMismatch,
    /// A fresh per-user semantic client could not be constructed.
    ClientInit,
}

impl NativeV2FactoryError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ProviderMismatch => "app.native-http.v2.factory-provider",
            Self::TransportLimitsMismatch => "app.native-http.v2.factory-transport-limits",
            Self::RequirementsMismatch => "app.native-http.v2.factory-requirements",
            Self::MapInvariant => "app.native-http.v2.factory-map-invariant",
            Self::EntryInvariant => "app.native-http.v2.factory-entry-invariant",
            Self::NodeNotPrepared => "app.native-http.v2.factory-node",
            Self::SourcePathMismatch => "app.native-http.v2.factory-source-path",
            Self::SourceNameMismatch => "app.native-http.v2.factory-source-name",
            Self::SourceProviderMismatch => "app.native-http.v2.factory-source-provider",
            Self::TestClassUnsupported => "app.native-http.v2.factory-test-class",
            Self::SamplerIdentityMismatch => "app.native-http.v2.factory-sampler-identity",
            Self::ClientInit => "app.native-http.v2.factory-client-init",
        }
    }
}

impl fmt::Display for NativeV2FactoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for NativeV2FactoryError {}

/// Factory-backed NativeV2 scope hook.
///
/// One instance is owned by a run assembler.  It has no global registry and
/// never chooses a provider from a request.  The assembler registers this
/// same exact hook under each entry in [`NATIVE_V2_HTTP_TEST_CLASSES`] that it
/// explicitly admits.
#[derive(Clone)]
pub struct NativeV2ScopeFactory {
    map: Arc<PreparedNativeV2RequestMap>,
    transport: NativeHttpTransport,
    submitter: HttpWorkerSubmitter,
    time_driver: TimeDriverHandle,
    projection: SampleResultProjectionOptions,
}

impl fmt::Debug for NativeV2ScopeFactory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeV2ScopeFactory")
            .field("provider", &self.map.provider())
            .field("sampler_count", &self.map.samplers().len())
            .field("transport_capability", &self.transport.capability_id())
            .field("projection", &self.projection)
            .finish()
    }
}

impl NativeV2ScopeFactory {
    /// Validates a prepared map against the exact run-owned NativeV2
    /// transport and retains a cloneable submission/time capability.
    pub fn try_new(
        map: PreparedNativeV2RequestMap,
        owner: &NativeHttpRunOwner,
        submitter: HttpWorkerSubmitter,
        time_driver: TimeDriverHandle,
        projection: SampleResultProjectionOptions,
    ) -> Result<Self, NativeV2FactoryError> {
        let map = Arc::new(map);
        validate_run_map(&map, owner)?;
        Ok(Self {
            map,
            transport: owner.transport(),
            submitter,
            time_driver,
            projection,
        })
    }

    /// Returns a per-sampler factory after checking the complete source
    /// identity carried by a runtime scope component.
    pub fn sampler_factory_for(
        &self,
        component: &ScopeComponent,
    ) -> Result<NativeV2SamplerFactory, NativeV2FactoryError> {
        let prepared = validate_component(&self.map, component)?;
        NativeV2SamplerFactory::from_prepared(
            prepared,
            self.transport.clone(),
            self.submitter.clone(),
            self.time_driver.clone(),
            self.projection.clone(),
        )
    }
}

impl ScopeComponentFactory for NativeV2ScopeFactory {
    fn create(&self, component: &ScopeComponent) -> Result<FactoryComponent, ScopeFactoryError> {
        let factory = self
            .sampler_factory_for(component)
            .map_err(|error| factory_decode_error(component, error))?;
        // Scope compilation needs one concrete sampler for its immutable
        // template.  The central package assembler can retain `factory` from
        // `sampler_factory_for` and install it as the package's per-user
        // `SamplerFactory`; this initial value is never used as shared user
        // state by that path.
        Ok(FactoryComponent::Sampler(factory.create()))
    }
}

/// Per-sampler factory retained by an immutable package template.
///
/// Every [`SamplerFactory::create`] call constructs a fresh
/// `HttpClient<NativeHttpTransport>` and a fresh mutex around it.  The
/// transport itself is only a clone of the provider frozen by the run owner;
/// no client or provider is looked up globally.
#[derive(Clone)]
pub struct NativeV2SamplerFactory {
    prepared: PreparedNativeV2Sampler,
    transport: NativeHttpTransport,
    submitter: HttpWorkerSubmitter,
    time_driver: TimeDriverHandle,
    projection: SampleResultProjectionOptions,
}

impl fmt::Debug for NativeV2SamplerFactory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeV2SamplerFactory")
            .field("node_id", &self.prepared.node_id())
            .field("source_path", &self.prepared.source_path())
            .field("provider", &self.prepared.provider())
            .field("projection", &self.projection)
            .finish()
    }
}

impl NativeV2SamplerFactory {
    fn from_prepared(
        prepared: &PreparedNativeV2Sampler,
        transport: NativeHttpTransport,
        submitter: HttpWorkerSubmitter,
        time_driver: TimeDriverHandle,
        projection: SampleResultProjectionOptions,
    ) -> Result<Self, NativeV2FactoryError> {
        if prepared.executed_provider() != NATIVE_V2_REQUEST_CAPABILITY
            || prepared.source_path().is_empty()
            || prepared.source_path().last().copied() != Some(prepared.node_id())
            || !prepared.node_id().is_valid()
            || prepared
                .source_path()
                .iter()
                .any(|node_id| !node_id.is_valid())
        {
            return Err(NativeV2FactoryError::EntryInvariant);
        }
        if transport.capability_id() != NATIVE_V2_REQUEST_CAPABILITY
            || transport.limits() != prepared.transport_limits()
        {
            return Err(NativeV2FactoryError::TransportLimitsMismatch);
        }
        HttpClient::new(transport.clone(), prepared.client_config().clone())
            .map_err(|_| NativeV2FactoryError::ClientInit)?;
        Ok(Self {
            prepared: prepared.clone(),
            transport,
            submitter,
            time_driver,
            projection,
        })
    }
}

impl SamplerFactory for NativeV2SamplerFactory {
    fn create(&self) -> Arc<dyn Sampler> {
        Arc::new(self.create_native())
    }
}

impl NativeV2SamplerFactory {
    fn create_native(&self) -> NativeV2Sampler {
        let client = HttpClient::new(
            self.transport.clone(),
            self.prepared.client_config().clone(),
        )
        .map(|client| Arc::new(Mutex::new(client)))
        .map_err(|_| NativeV2FactoryError::ClientInit);
        match client {
            Ok(client) => NativeV2Sampler {
                prepared: self.prepared.clone(),
                client: Some(client),
                init_error: None,
                submitter: self.submitter.clone(),
                time_driver: self.time_driver.clone(),
                projection: self.projection.clone(),
            },
            Err(error) => NativeV2Sampler {
                prepared: self.prepared.clone(),
                client: None,
                init_error: Some(error.code()),
                submitter: self.submitter.clone(),
                time_driver: self.time_driver.clone(),
                projection: self.projection.clone(),
            },
        }
    }
}

/// One isolated virtual-user NativeV2 sampler.
pub struct NativeV2Sampler {
    prepared: PreparedNativeV2Sampler,
    client: Option<Arc<Mutex<HttpClient<NativeHttpTransport>>>>,
    init_error: Option<&'static str>,
    submitter: HttpWorkerSubmitter,
    time_driver: TimeDriverHandle,
    projection: SampleResultProjectionOptions,
}

impl fmt::Debug for NativeV2Sampler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeV2Sampler")
            .field("node_id", &self.prepared.node_id())
            .field("source_path", &self.prepared.source_path())
            .field("provider", &self.prepared.provider())
            .field("client_present", &self.client.is_some())
            .field("init_error", &self.init_error)
            .finish()
    }
}

impl Sampler for NativeV2Sampler {
    fn sample<'a>(
        &'a self,
        context: &'a mut SampleContext<'_>,
    ) -> ComponentFuture<'a, SamplerOutput> {
        let sampler_id = context.sampler_id();
        if let Err(error) = validate_sampler_identity(sampler_id, self.prepared.node_id()) {
            return Box::pin(future::ready(Err(error)));
        }
        let cancellation = context.execution().cancellation_token().clone();
        let Some(client) = self.client.clone() else {
            let output = failed_sample(
                sampler_id,
                self.prepared.name(),
                self.init_error
                    .unwrap_or(NativeV2FactoryError::ClientInit.code()),
            );
            return Box::pin(future::ready(Ok(output)));
        };

        let started = start_operation(
            sampler_id,
            self.prepared.clone(),
            client,
            self.submitter.clone(),
            self.time_driver.clone(),
            self.projection.clone(),
            cancellation,
        );
        match started {
            Ok(operation) => Box::pin(operation),
            Err(error) => Box::pin(future::ready(Err(error))),
        }
    }
}

/// The nonblocking state machine joining one operation and one exact runtime
/// wake registration.
struct NativeV2SampleFuture {
    sampler_id: NodeId,
    label: String,
    operation: Option<HttpOperationFuture>,
    registration: Option<WakeRegistration>,
    deadline: OperationDeadline,
    cancellation: CancellationToken,
    time_driver: TimeDriverHandle,
    projection: SampleResultProjectionOptions,
}

fn start_operation(
    sampler_id: NodeId,
    prepared: PreparedNativeV2Sampler,
    client: Arc<Mutex<HttpClient<NativeHttpTransport>>>,
    submitter: HttpWorkerSubmitter,
    time_driver: TimeDriverHandle,
    projection: SampleResultProjectionOptions,
    cancellation: CancellationToken,
) -> Result<NativeV2SampleFuture, ComponentError> {
    let now = time_driver
        .try_now()
        .map_err(|error| ComponentError::failure(error.code()))?;
    let now = MonotonicInstant::from_duration(now.monotonic);
    let (deadline, wait_deadline) = establish_deadline(now, prepared.overall_operation_duration())?;
    let registration = time_driver
        .register_http_wait(wait_deadline, wait_key(prepared.node_id()), &cancellation)
        .map_err(|error| ComponentError::failure(error.code()))?;
    let operation = match HttpOperation::from_shared_client(client, prepared.request().clone()) {
        Ok(operation) => operation,
        Err(error) => {
            let primary = pool_component_error(error);
            return retire_after_admission_failure(&time_driver, registration, primary);
        }
    };
    let operation = match submitter.submit_with_deadline(operation, deadline) {
        Ok(operation) => operation,
        Err(error) => {
            let primary = pool_component_error(error);
            return retire_after_admission_failure(&time_driver, registration, primary);
        }
    };

    Ok(NativeV2SampleFuture {
        sampler_id,
        label: prepared.name().to_owned(),
        operation: Some(operation),
        registration: Some(registration),
        deadline,
        cancellation,
        time_driver,
        projection,
    })
}

/// Establishes the one absolute deadline shared by worker admission and the
/// runtime HTTP wait.  Keeping this conversion in one narrow seam makes it
/// impossible for queue delay to cause either side to refresh a relative
/// timeout independently.
fn establish_deadline(
    now: MonotonicInstant,
    duration: Duration,
) -> Result<(OperationDeadline, Deadline), ComponentError> {
    let operation = OperationDeadline::after_at(now, duration).map_err(pool_component_error)?;
    Ok((operation, Deadline::at(operation.instant())))
}

fn retire_after_admission_failure(
    time_driver: &TimeDriverHandle,
    registration: WakeRegistration,
    primary: ComponentError,
) -> Result<NativeV2SampleFuture, ComponentError> {
    let cleanup = retire_registration(time_driver, registration);
    match cleanup {
        Ok(()) => Err(primary),
        Err(cleanup) => Err(combine_errors(primary, cleanup)),
    }
}

impl Future for NativeV2SampleFuture {
    type Output = Result<SamplerOutput, ComponentError>;

    fn poll(self: Pin<&mut Self>, task_context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.cancellation.register_waker(task_context.waker());

        let now = match this.time_driver.try_now() {
            Ok(reading) => MonotonicInstant::from_duration(reading.monotonic),
            Err(error) => {
                this.cancel_and_drop_operation();
                let primary = ComponentError::failure(error.code());
                return Poll::Ready(this.with_cleanup(primary));
            }
        };

        // A control signal observed in the same poll as a deadline has
        // precedence. Returning a component control error is what prevents
        // the runtime pipeline from entering postprocessors with a private
        // cancellation represented as an ordinary failed sample.
        let signal = this.cancellation.signal();
        if signal != ControlSignal::Continue {
            this.cancel_and_drop_operation();
            return Poll::Ready(this.with_cleanup(ComponentError::Control(signal)));
        }

        if this.deadline.expired(now) {
            this.cancel_and_drop_operation();
            let primary = ComponentError::failure(NativeV2HttpError::Timeout.code());
            return Poll::Ready(this.with_cleanup_or_sample(primary, "http.timeout"));
        }

        let Some(operation) = this.operation.as_mut() else {
            let primary = ComponentError::failure("app.native-http.v2.operation-missing");
            return Poll::Ready(this.with_cleanup(primary));
        };
        match Pin::new(operation).poll(task_context) {
            Poll::Pending => {
                // A deadline wake can be consumed by the driver between the
                // authoritative time read and this poll.  Do not return
                // Pending while its exact registration is absent.
                let registration_active = this.registration.as_ref().is_some_and(|registration| {
                    this.time_driver.is_registration_active(registration.id())
                });
                let woke = this.cancellation.take_wake();
                if woke || !registration_active {
                    task_context.waker().wake_by_ref();
                }
                Poll::Pending
            }
            Poll::Ready(result) => {
                // The operation future owns the worker reservation until it
                // is dropped.  Take and drop it before publishing the result
                // and before attempting registration retirement.
                let operation = this.operation.take();
                drop(operation);
                let cleanup = this.retire_registration();
                let (output, sample_primary) = match result {
                    Ok(http_result) => {
                        match http_result.to_sample_result(this.label.clone(), &this.projection) {
                            Ok(result) => (Ok(SamplerOutput::result(result)), None),
                            Err(error) => (Err(ComponentError::failure(error.stable_code())), None),
                        }
                    }
                    Err(error) => {
                        let code = error.stable_code();
                        (
                            Ok(failed_sample(this.sampler_id, &this.label, code)),
                            Some(ComponentError::failure(code)),
                        )
                    }
                };
                Poll::Ready(match (output, sample_primary, cleanup) {
                    (Ok(output), _, Ok(())) => Ok(output),
                    (Err(primary), _, Ok(())) => Err(primary),
                    (Ok(_output), Some(primary), Err(cleanup)) => {
                        Err(combine_errors(primary, cleanup))
                    }
                    (Ok(_output), None, Err(cleanup)) => Err(cleanup),
                    (Err(primary), _, Err(cleanup)) => Err(combine_errors(primary, cleanup)),
                })
            }
        }
    }
}

impl NativeV2SampleFuture {
    fn cancel_and_drop_operation(&mut self) {
        if let Some(operation) = self.operation.as_ref() {
            operation.cancel();
        }
        drop(self.operation.take());
    }

    fn retire_registration(&mut self) -> Result<(), ComponentError> {
        let Some(registration) = self.registration.take() else {
            return Ok(());
        };
        retire_registration(&self.time_driver, registration)
    }

    fn with_cleanup(&mut self, primary: ComponentError) -> Result<SamplerOutput, ComponentError> {
        match self.retire_registration() {
            Ok(()) => Err(primary),
            Err(cleanup) => Err(combine_errors(primary, cleanup)),
        }
    }

    fn with_cleanup_or_sample(
        &mut self,
        primary: ComponentError,
        sample_code: &'static str,
    ) -> Result<SamplerOutput, ComponentError> {
        match self.retire_registration() {
            Ok(()) => Ok(failed_sample(self.sampler_id, &self.label, sample_code)),
            Err(cleanup) => Err(combine_errors(primary, cleanup)),
        }
    }
}

impl Drop for NativeV2SampleFuture {
    fn drop(&mut self) {
        // Drop is a best-effort safety net only.  Every successful poll path
        // retires explicitly above; destructor cleanup cannot publish an
        // apparently successful sample or hide a cleanup failure.
        let _ = panic::catch_unwind(AssertUnwindSafe(|| {
            self.cancel_and_drop_operation();
        }));
        let _ = panic::catch_unwind(AssertUnwindSafe(|| {
            if let Some(registration) = self.registration.take() {
                let _ = retire_registration(&self.time_driver, registration);
            }
        }));
    }
}

fn retire_registration(
    time_driver: &TimeDriverHandle,
    registration: WakeRegistration,
) -> Result<(), ComponentError> {
    let result = Scheduler::cancel(time_driver, &registration)
        .map(|_| ())
        .map_err(|error| ComponentError::failure(error.code()));
    drop(registration);
    result
}

fn validate_run_map(
    map: &PreparedNativeV2RequestMap,
    owner: &NativeHttpRunOwner,
) -> Result<(), NativeV2FactoryError> {
    if map.provider() != NATIVE_V2_REQUEST_CAPABILITY
        || owner.identity().capability_id() != NATIVE_V2_REQUEST_CAPABILITY
    {
        return Err(NativeV2FactoryError::ProviderMismatch);
    }
    let transport = owner.transport();
    if transport.capability_id() != NATIVE_V2_REQUEST_CAPABILITY
        || transport.limits() != map.transport_limits()
    {
        return Err(NativeV2FactoryError::TransportLimitsMismatch);
    }
    let requirements = map.requirements();
    if !requirements.has_http
        || requirements.sampler_count != map.samplers().len()
        || map.samplers().is_empty()
        || map.overall_operation_duration().is_zero()
    {
        return Err(NativeV2FactoryError::MapInvariant);
    }
    if requirements.has_hostname != owner.identity().subordinate().explicit_dns
        || requirements.has_https != owner.identity().subordinate().explicit_tls
    {
        return Err(NativeV2FactoryError::RequirementsMismatch);
    }
    for prepared in map.samplers() {
        if prepared.executed_provider() != NATIVE_V2_REQUEST_CAPABILITY
            || prepared.transport_limits() != map.transport_limits()
            || prepared.source_path().is_empty()
            || prepared.source_path().last().copied() != Some(prepared.node_id())
        {
            return Err(NativeV2FactoryError::EntryInvariant);
        }
    }
    Ok(())
}

fn validate_component<'a>(
    map: &'a PreparedNativeV2RequestMap,
    component: &ScopeComponent,
) -> Result<&'a PreparedNativeV2Sampler, NativeV2FactoryError> {
    if component.binding.category != ComponentCategory::Sampler
        || component.element.test_class() != component.binding.test_class
        || !NATIVE_V2_HTTP_TEST_CLASSES
            .iter()
            .any(|class| *class == component.binding.test_class)
    {
        return Err(NativeV2FactoryError::TestClassUnsupported);
    }
    let Some(prepared) = map.sampler(component.node_id) else {
        return Err(NativeV2FactoryError::NodeNotPrepared);
    };
    if component.path != prepared.source_path() {
        return Err(NativeV2FactoryError::SourcePathMismatch);
    }
    if component.element.name() != prepared.name() {
        return Err(NativeV2FactoryError::SourceNameMismatch);
    }
    let source_provider = component_source_provider(component);
    if source_provider.as_ref() != Some(prepared.source_provider()) {
        return Err(NativeV2FactoryError::SourceProviderMismatch);
    }
    Ok(prepared)
}

fn validate_sampler_identity(observed: NodeId, prepared: NodeId) -> Result<(), ComponentError> {
    if observed == prepared {
        Ok(())
    } else {
        Err(ComponentError::failure(
            NativeV2FactoryError::SamplerIdentityMismatch.code(),
        ))
    }
}

fn component_source_provider(component: &ScopeComponent) -> Option<NativeV2SourceProvider> {
    let Some(value) = component.element.property("HTTPSampler.implementation") else {
        return Some(NativeV2SourceProvider::JmeterDefaultHttpClient4);
    };
    let Ok(value) = value.as_string() else {
        return None;
    };
    match value {
        "Java" => Some(NativeV2SourceProvider::Java),
        "HttpClient4" => Some(NativeV2SourceProvider::HttpClient4),
        _ => None,
    }
}

fn factory_decode_error(
    component: &ScopeComponent,
    error: NativeV2FactoryError,
) -> ScopeFactoryError {
    ScopeFactoryError::Decode {
        node_id: component.node_id,
        path: component.path.clone(),
        test_class: component.binding.test_class.clone(),
        category: ComponentCategory::Sampler,
        detail: error.code().to_owned(),
    }
}

fn wait_key(node_id: NodeId) -> u64 {
    // The mapper validates that a prepared NodeId is nonzero. Retaining the
    // exact opaque document-local value avoids a second wrapping/hash domain
    // and is collision-free within one prepared source document.
    node_id.get()
}

fn pool_component_error(error: PoolError) -> ComponentError {
    ComponentError::failure(error.code())
}

fn combine_errors(primary: ComponentError, secondary: ComponentError) -> ComponentError {
    ComponentError::Combined {
        primary: Box::new(primary),
        secondary: Box::new(secondary),
    }
}

fn failed_sample(sampler_id: NodeId, label: &str, code: &'static str) -> SamplerOutput {
    let mut result = SampleResult::new(label);
    result.set_successful(false);
    result.set_failure_message(Some(code.to_owned()));
    SamplerOutput::failure(SampleFailure::new(sampler_id, code).with_result(result))
}

/// Closed categories used for direct deadline/cancellation projection.
#[derive(Clone, Copy)]
enum NativeV2HttpError {
    Timeout,
}

impl NativeV2HttpError {
    const fn code(self) -> &'static str {
        match self {
            Self::Timeout => "http.timeout",
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::panic,
        clippy::unwrap_used,
        reason = "tests construct bounded local fixtures and assert setup invariants"
    )]

    use super::*;
    use crate::http_worker::{
        HttpWorkerPool, MAX_HTTP_RETAINED_BYTES, OperationClockAdapter, OperationClockError,
        PoolLimits, ShutdownBehavior,
    };
    use crate::native_http_plan::{NativeV2HttpCompileError, compile_native_v2_http_plan};
    use crate::native_http_run::{NativeHttpRunRecipe, NativeHttpRunRequirements};
    use crate::time_driver::{TimeDriver, TimeDriverLimits};
    use crate::{HttpCapabilitySelector, HttpNativeV2Properties};
    use jmeter_rs_http::{ClientConfig, HttpClient, Request};
    use jmeter_rs_http_native::NativeTransport;
    use jmeter_rs_jmx::{SemanticPlan, SemanticRootMetadata, Span};
    use jmeter_rs_model::{ElementTree, PropertyValue, TestElement};
    use jmeter_rs_runtime::ComponentBinding;

    #[test]
    fn wait_keys_are_nonzero_and_node_derived() {
        let first = wait_key(NodeId::new(1));
        let second = wait_key(NodeId::new(2));
        assert_eq!(first, 1);
        assert_eq!(second, 2);
        assert_ne!(first, second);
    }

    #[test]
    fn worker_and_runtime_wait_receive_one_exact_absolute_deadline() {
        let now = MonotonicInstant::from_duration(Duration::from_secs(11));
        let (operation, wait) =
            establish_deadline(now, Duration::from_secs(7)).expect("finite deadline");
        assert_eq!(operation.instant(), wait.instant());
        assert!(!operation.expired(MonotonicInstant::from_duration(Duration::from_secs(17))));
        assert!(operation.expired(MonotonicInstant::from_duration(Duration::from_secs(18))));
    }

    #[test]
    fn explicit_registration_retirement_is_visible_without_a_sleep() {
        let driver =
            TimeDriver::new(TimeDriverLimits::new(4).expect("limits")).expect("time driver");
        let handle = driver.handle();
        let token = CancellationToken::new();
        let registration = handle
            .register_http_wait(
                Deadline::at(MonotonicInstant::from_duration(Duration::from_secs(3_600))),
                wait_key(NodeId::new(9)),
                &token,
            )
            .expect("registration");
        let id = registration.id();
        assert!(handle.is_registration_active(id));
        retire_registration(&handle, registration).expect("explicit retirement");
        assert!(!handle.is_registration_active(id));
        assert_eq!(handle.diagnostics().active_registrations, 0);
        driver.finalize().expect("driver finalization");
    }

    #[test]
    fn dropping_registration_retires_the_exact_wait() {
        let driver =
            TimeDriver::new(TimeDriverLimits::new(4).expect("limits")).expect("time driver");
        let handle = driver.handle();
        let token = CancellationToken::new();
        let registration = handle
            .register_http_wait(
                Deadline::at(MonotonicInstant::from_duration(Duration::from_secs(3_600))),
                wait_key(NodeId::new(10)),
                &token,
            )
            .expect("registration");
        let id = registration.id();
        assert!(handle.is_registration_active(id));
        drop(registration);
        assert!(!handle.is_registration_active(id));
        driver.finalize().expect("driver finalization");
    }

    #[test]
    fn dropping_sampler_state_retires_its_owned_registration() {
        let driver =
            TimeDriver::new(TimeDriverLimits::new(4).expect("limits")).expect("time driver");
        let handle = driver.handle();
        let token = CancellationToken::new();
        let registration = handle
            .register_http_wait(
                Deadline::at(MonotonicInstant::from_duration(Duration::from_secs(3_600))),
                wait_key(NodeId::new(12)),
                &token,
            )
            .expect("registration");
        let id = registration.id();
        let (deadline, _) =
            establish_deadline(MonotonicInstant::zero(), Duration::from_secs(1)).expect("deadline");
        let state = NativeV2SampleFuture {
            sampler_id: NodeId::new(12),
            label: "sample".to_owned(),
            operation: None,
            registration: Some(registration),
            deadline,
            cancellation: token,
            time_driver: handle.clone(),
            projection: SampleResultProjectionOptions::default(),
        };
        drop(state);
        assert!(!handle.is_registration_active(id));
        driver.finalize().expect("driver finalization");
    }

    fn poll_control_signal(signal: ControlSignal) -> ComponentError {
        let driver =
            TimeDriver::new(TimeDriverLimits::new(4).expect("limits")).expect("time driver");
        let handle = driver.handle();
        let token = CancellationToken::new();
        token.request(signal);
        let deadline =
            OperationDeadline::after_at(MonotonicInstant::zero(), Duration::from_secs(3_600))
                .expect("deadline");
        let registration = handle
            .register_http_wait(
                Deadline::at(deadline.instant()),
                wait_key(NodeId::new(13)),
                &token,
            )
            .expect("registration");
        let id = registration.id();
        let mut state = NativeV2SampleFuture {
            sampler_id: NodeId::new(13),
            label: "sample".to_owned(),
            operation: None,
            registration: Some(registration),
            deadline,
            cancellation: token,
            time_driver: handle.clone(),
            projection: SampleResultProjectionOptions::default(),
        };
        let waker = std::task::Waker::noop();
        let mut task_context = Context::from_waker(waker);
        let error = match Pin::new(&mut state).poll(&mut task_context) {
            Poll::Ready(Err(error)) => error,
            other => panic!("control signal poll returned {other:?}"),
        };
        assert!(!handle.is_registration_active(id));
        driver.finalize().expect("driver finalization");
        error
    }

    #[test]
    fn in_flight_control_signals_abort_without_a_private_cancelled_sample() {
        for signal in [
            ControlSignal::StopThread,
            ControlSignal::StopTestGraceful,
            ControlSignal::StopTestImmediate,
        ] {
            let error = poll_control_signal(signal);
            assert!(matches!(error, ComponentError::Control(observed) if observed == signal));
        }
    }

    #[test]
    fn control_signal_wins_when_observed_at_an_expired_deadline() {
        let driver =
            TimeDriver::new(TimeDriverLimits::new(4).expect("limits")).expect("time driver");
        let handle = driver.handle();
        let token = CancellationToken::new();
        token.request(ControlSignal::StopThread);
        let deadline =
            OperationDeadline::after_at(MonotonicInstant::zero(), Duration::from_nanos(1))
                .expect("deadline");
        let registration = handle
            .register_http_wait(
                Deadline::at(deadline.instant()),
                wait_key(NodeId::new(14)),
                &token,
            )
            .expect("registration");
        let mut state = NativeV2SampleFuture {
            sampler_id: NodeId::new(14),
            label: "sample".to_owned(),
            operation: None,
            registration: Some(registration),
            deadline,
            cancellation: token,
            time_driver: handle.clone(),
            projection: SampleResultProjectionOptions::default(),
        };
        let waker = std::task::Waker::noop();
        let mut task_context = Context::from_waker(waker);
        let error = match Pin::new(&mut state).poll(&mut task_context) {
            Poll::Ready(Err(error)) => error,
            other => panic!("control/deadline poll returned {other:?}"),
        };
        assert!(matches!(
            error,
            ComponentError::Control(ControlSignal::StopThread)
        ));
        driver.finalize().expect("driver finalization");
    }

    #[test]
    fn driver_retired_deadline_still_projects_a_timeout_sample() {
        let driver =
            TimeDriver::new(TimeDriverLimits::new(4).expect("limits")).expect("time driver");
        let handle = driver.handle();
        let token = CancellationToken::new();
        let deadline =
            OperationDeadline::after_at(MonotonicInstant::zero(), Duration::from_nanos(1))
                .expect("deadline");
        let registration = handle
            .register_http_wait(
                Deadline::at(deadline.instant()),
                wait_key(NodeId::new(15)),
                &token,
            )
            .expect("registration");
        let id = registration.id();
        Scheduler::cancel(&handle, &registration).expect("driver retirement");
        assert!(!handle.is_registration_active(id));
        let mut state = NativeV2SampleFuture {
            sampler_id: NodeId::new(15),
            label: "sample".to_owned(),
            operation: None,
            registration: Some(registration),
            deadline,
            cancellation: token,
            time_driver: handle.clone(),
            projection: SampleResultProjectionOptions::default(),
        };
        let waker = std::task::Waker::noop();
        let mut task_context = Context::from_waker(waker);
        let output = match Pin::new(&mut state).poll(&mut task_context) {
            Poll::Ready(Ok(output)) => output,
            other => panic!("expired poll returned {other:?}"),
        };
        assert_eq!(
            output
                .result
                .as_ref()
                .and_then(SampleResult::failure_message),
            Some("http.timeout")
        );
        driver.finalize().expect("driver finalization");
    }

    #[test]
    fn execution_identity_drift_is_a_typed_component_failure() {
        let error = validate_sampler_identity(NodeId::new(22), NodeId::new(23))
            .expect_err("identity drift");
        assert_eq!(error.code(), "runtime.component.failure");
        assert!(
            error
                .to_string()
                .contains("app.native-http.v2.factory-sampler-identity")
        );
    }

    #[test]
    fn cancellation_reaches_the_exact_http_operation_without_waiting() {
        let client = Arc::new(Mutex::new(
            HttpClient::new(
                NativeTransport::with_defaults().expect("native transport"),
                ClientConfig::default(),
            )
            .expect("native client"),
        ));
        let operation = HttpOperation::from_shared_client(
            client,
            Request::get("http://127.0.0.1:1/").expect("loopback request"),
        )
        .expect("operation");
        let pool = HttpWorkerPool::new(
            PoolLimits::new(
                1,
                4,
                MAX_HTTP_RETAINED_BYTES,
                ShutdownBehavior::CancelQueued,
            )
            .expect("pool limits"),
            Arc::new(OperationClockAdapter::new(|| Ok(MonotonicInstant::zero()))),
        )
        .expect("worker pool");
        let deadline =
            OperationDeadline::after_at(MonotonicInstant::zero(), Duration::from_secs(10))
                .expect("deadline");
        let future = pool
            .submitter()
            .submit_with_deadline(operation, deadline)
            .expect("submission");
        future.cancel();
        assert!(future.is_cancelled());
        drop(future);
        pool.finalize().expect("worker finalization");
    }

    fn prepared_numeric_fixture() -> (PreparedNativeV2RequestMap, TestElement, NodeId, Vec<NodeId>)
    {
        let root =
            SemanticRootMetadata::new("jmeterTestPlan", Vec::new(), Span::new(0, 0).expect("span"));
        let mut tree = ElementTree::new();
        let test_plan = tree
            .insert_root(TestElement::named("TestPlan", "TestPlanGui", "plan"))
            .expect("root");
        let mut sampler = TestElement::named("HTTPSamplerProxy", "HttpGui", "sample");
        sampler.set_property("HTTPSampler.domain", PropertyValue::string("127.0.0.1"));
        sampler.set_property("HTTPSampler.protocol", PropertyValue::string("http"));
        sampler.set_property("HTTPSampler.path", PropertyValue::string("/"));
        sampler.set_property("HTTPSampler.method", PropertyValue::string("GET"));
        sampler.set_property(
            "HTTPSampler.follow_redirects",
            PropertyValue::boolean(false),
        );
        let sampler_id = tree
            .insert(Some(test_plan), sampler.clone())
            .expect("sampler");
        let plan = SemanticPlan::new(root, tree);
        let compiled = compile_native_v2_http_plan(&plan).expect("native plan");
        let source = compiled.samplers().first().expect("compiled sampler");
        let map = crate::native_v2_request::NativeV2RequestMapper::new()
            .prepare(&compiled)
            .expect("prepared map");
        (map, sampler, sampler_id, source.path.clone())
    }

    fn numeric_plan_for_class(class: &str) -> SemanticPlan {
        let root =
            SemanticRootMetadata::new("jmeterTestPlan", Vec::new(), Span::new(0, 0).expect("span"));
        let mut tree = ElementTree::new();
        let test_plan = tree
            .insert_root(TestElement::named("TestPlan", "TestPlanGui", "plan"))
            .expect("root");
        let mut sampler = TestElement::named(class, "HttpGui", "sample");
        sampler.set_property("HTTPSampler.domain", PropertyValue::string("127.0.0.1"));
        sampler.set_property("HTTPSampler.protocol", PropertyValue::string("http"));
        sampler.set_property("HTTPSampler.path", PropertyValue::string("/"));
        sampler.set_property("HTTPSampler.method", PropertyValue::string("GET"));
        sampler.set_property(
            "HTTPSampler.follow_redirects",
            PropertyValue::boolean(false),
        );
        tree.insert(Some(test_plan), sampler).expect("sampler");
        SemanticPlan::new(root, tree)
    }

    #[test]
    fn mapper_and_factory_aliases_are_exactly_aligned() {
        for class in NATIVE_V2_HTTP_TEST_CLASSES {
            let compiled = compile_native_v2_http_plan(&numeric_plan_for_class(class))
                .expect("admitted exact NativeV2 alias");
            assert_eq!(compiled.samplers().len(), 1);
        }
        for class in [
            "HTTPHC4Impl",
            "org.apache.jmeter.protocol.http.sampler.HTTPHC4Impl",
        ] {
            let error = compile_native_v2_http_plan(&numeric_plan_for_class(class))
                .expect_err("legacy HTTP class must not fall through to NativeV2");
            assert!(matches!(
                error,
                NativeV2HttpCompileError::UnsupportedElement { .. }
            ));
        }
    }

    #[test]
    fn sampler_factory_creates_isolated_clients_for_each_virtual_user() {
        let (map, element, node_id, path) = prepared_numeric_fixture();
        let v1_owner = NativeHttpRunOwner::new(
            NativeHttpRunRecipe::new(
                HttpCapabilitySelector::NativeV1,
                NativeHttpRunRequirements::new(true, false, false),
                HttpNativeV2Properties::default(),
                None,
            )
            .expect("V1 run recipe"),
        )
        .expect("V1 run owner");
        let owner = NativeHttpRunOwner::new(
            NativeHttpRunRecipe::new(
                HttpCapabilitySelector::NativeV2,
                NativeHttpRunRequirements::new(true, false, false),
                HttpNativeV2Properties::default(),
                None,
            )
            .expect("run recipe"),
        )
        .expect("run owner");
        let driver =
            TimeDriver::new(TimeDriverLimits::new(8).expect("time limits")).expect("driver");
        let handle = driver.handle();
        let clock_handle = handle.clone();
        let clock = Arc::new(OperationClockAdapter::new(move || {
            clock_handle
                .try_now()
                .map(|reading| MonotonicInstant::from_duration(reading.monotonic))
                .map_err(|_| OperationClockError::Unavailable)
        }));
        let pool = HttpWorkerPool::new(
            PoolLimits::new(
                1,
                4,
                MAX_HTTP_RETAINED_BYTES,
                ShutdownBehavior::CancelQueued,
            )
            .expect("pool limits"),
            clock,
        )
        .expect("worker pool");
        assert!(matches!(
            NativeV2ScopeFactory::try_new(
                map.clone(),
                &v1_owner,
                pool.submitter(),
                handle.clone(),
                SampleResultProjectionOptions::default(),
            ),
            Err(NativeV2FactoryError::ProviderMismatch)
        ));
        let scope_factory = NativeV2ScopeFactory::try_new(
            map,
            &owner,
            pool.submitter(),
            handle,
            SampleResultProjectionOptions::default(),
        )
        .expect("scope factory");
        let component = ScopeComponent {
            node_id,
            path,
            element,
            binding: ComponentBinding::native(
                "HTTPSamplerProxy",
                ComponentCategory::Sampler,
                "runtime.HTTPSamplerProxy",
            ),
        };
        let mut wrong_path = component.clone();
        wrong_path.path[0] = NodeId::new(99);
        assert!(matches!(
            scope_factory.sampler_factory_for(&wrong_path),
            Err(NativeV2FactoryError::SourcePathMismatch)
        ));
        let mut wrong_node = component.clone();
        wrong_node.node_id = NodeId::new(99);
        assert!(matches!(
            scope_factory.sampler_factory_for(&wrong_node),
            Err(NativeV2FactoryError::NodeNotPrepared)
        ));
        let mut wrong_provider = component.clone();
        wrong_provider
            .element
            .set_property("HTTPSampler.implementation", PropertyValue::string("Java"));
        assert!(matches!(
            scope_factory.sampler_factory_for(&wrong_provider),
            Err(NativeV2FactoryError::SourceProviderMismatch)
        ));
        let mut unsupported_alias = component.clone();
        unsupported_alias.element.metadata.test_class = "HTTPHC4Impl".to_owned();
        unsupported_alias.binding.test_class = "HTTPHC4Impl".to_owned();
        assert!(matches!(
            scope_factory.sampler_factory_for(&unsupported_alias),
            Err(NativeV2FactoryError::TestClassUnsupported)
        ));
        let sampler_factory = scope_factory
            .sampler_factory_for(&component)
            .expect("sampler factory");
        let first = sampler_factory.create_native();
        let second = sampler_factory.create_native();
        let first_client = first
            .client
            .as_ref()
            .map(|client| Arc::as_ptr(client) as usize);
        let second_client = second
            .client
            .as_ref()
            .map(|client| Arc::as_ptr(client) as usize);
        assert!(first_client.is_some());
        assert_ne!(first_client, second_client);
        pool.finalize().expect("worker finalization");
        driver.finalize().expect("driver finalization");
    }

    #[test]
    fn an_expired_wait_wakes_without_parking_the_test_executor() {
        let driver =
            TimeDriver::new(TimeDriverLimits::new(4).expect("limits")).expect("time driver");
        let handle = driver.handle();
        let now = handle.try_now().expect("clock");
        let token = CancellationToken::new();
        let registration = handle
            .register_http_wait(
                Deadline::at(MonotonicInstant::from_duration(now.monotonic)),
                wait_key(NodeId::new(11)),
                &token,
            )
            .expect("registration");
        // The deadline is already due at admission.  The test fixture models
        // the driver's exact delivery edge synchronously so it cannot race a
        // background worker or rely on wall-clock sleeping.
        token.wake();
        assert!(token.is_wake_ready());
        drop(registration);
        driver.finalize().expect("driver finalization");
    }

    #[test]
    fn only_mapper_http_aliases_are_admitted() {
        assert!(NATIVE_V2_HTTP_TEST_CLASSES.contains(&"HTTPSamplerProxy"));
        assert!(
            NATIVE_V2_HTTP_TEST_CLASSES
                .contains(&"org.apache.jmeter.protocol.http.sampler.HTTPSamplerProxy")
        );
        assert!(!NATIVE_V2_HTTP_TEST_CLASSES.contains(&"HTTPHC4Impl"));
    }

    #[test]
    fn source_provider_provenance_is_read_without_execution_fallback() {
        let mut element = TestElement::named("HTTPSamplerProxy", "HttpGui", "sample");
        let component = |element: TestElement| ScopeComponent {
            node_id: NodeId::new(1),
            path: vec![NodeId::new(1)],
            element,
            binding: ComponentBinding::native(
                "HTTPSamplerProxy",
                ComponentCategory::Sampler,
                "runtime.HTTPSamplerProxy",
            ),
        };
        assert_eq!(
            component_source_provider(&component(element.clone())),
            Some(NativeV2SourceProvider::JmeterDefaultHttpClient4)
        );
        element.set_property("HTTPSampler.implementation", PropertyValue::string("Java"));
        assert_eq!(
            component_source_provider(&component(element.clone())),
            Some(NativeV2SourceProvider::Java)
        );
        element.set_property(
            "HTTPSampler.implementation",
            PropertyValue::string("unrecognized-provider"),
        );
        assert_eq!(component_source_provider(&component(element)), None);
    }

    #[test]
    fn cleanup_diagnostic_keeps_the_primary_code() {
        let combined = combine_errors(
            ComponentError::failure("http.pool.full"),
            ComponentError::failure("runtime.scheduler.unknown-wake"),
        );
        assert!(matches!(
            combined,
            ComponentError::Combined { ref primary, ref secondary }
                if primary.code() == "runtime.component.failure"
                    && secondary.code() == "runtime.component.failure"
        ));
        assert!(combined.to_string().contains("runtime.component.combined"));
    }

    #[test]
    fn failed_samples_retain_only_the_stable_code() {
        let output = failed_sample(NodeId::new(7), "sample", "http.transport.read");
        let failure = output.failure.expect("failure output");
        assert_eq!(failure.message, "http.transport.read");
        assert_eq!(
            failure.result.expect("failed result").failure_message(),
            Some("http.transport.read")
        );
    }
}
