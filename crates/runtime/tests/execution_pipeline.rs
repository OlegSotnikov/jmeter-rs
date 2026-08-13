// SPDX-License-Identifier: Apache-2.0
//! Deterministic integration coverage for the executor-neutral sampler phase.

#![allow(
    clippy::expect_used,
    clippy::manual_noop_waker,
    reason = "integration assertions make deterministic setup failures explicit"
)]

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use jmeter_rs_expr::{BuiltinFunctions, FunctionContext, FunctionError, FunctionResolver};
use jmeter_rs_model::NodeId;
use jmeter_rs_results::{AssertionResult, SampleEvent, SampleResult};
use jmeter_rs_runtime::{
    Assertion, CapabilityFuture, Clock, ClockReading, ComponentError, ComponentFuture,
    Configuration, ExecutionContext, ExecutionPipeline, ExpressionStateCleanup, FileSystem,
    ImmediateSleeper, Listener, PackageCompileError, PackageCompiler, PackageLifecycle,
    PackageLifecycleFactory, Phase, PipelineError, Postprocessor, Preprocessor, RandomSource,
    RuntimeCapabilities, SampleContext, SampleFailure, SamplePackage, Sampler, SamplerFactory,
    SamplerOutput, Sleeper, Timer,
};

fn block_on<F: Future>(future: F) -> F::Output {
    // Every test future is ready immediately. The loop still drives a normal
    // Future contract and never sleeps the host thread.
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

#[derive(Clone, Default)]
struct Trace(Arc<Mutex<Vec<String>>>);

impl Trace {
    fn push(&self, value: impl Into<String>) {
        self.0.lock().expect("trace lock").push(value.into());
    }

    fn values(&self) -> Vec<String> {
        self.0.lock().expect("trace lock").clone()
    }
}

#[derive(Clone, Copy, Default)]
struct FakeClock;

impl Clock for FakeClock {
    fn now(&self) -> ClockReading {
        ClockReading {
            wall: jmeter_rs_results::WallTimestamp::from_millis(10),
            monotonic: Duration::from_millis(10),
        }
    }
}

struct AdvancingClock {
    millis: AtomicU64,
}

impl AdvancingClock {
    fn new() -> Self {
        Self {
            millis: AtomicU64::new(0),
        }
    }

    fn advance_to(&self, millis: u64) {
        self.millis.store(millis, Ordering::SeqCst);
    }
}

impl Clock for AdvancingClock {
    fn now(&self) -> ClockReading {
        let millis = self.millis.load(Ordering::SeqCst);
        ClockReading {
            wall: jmeter_rs_results::WallTimestamp::from_millis(
                i64::try_from(millis).unwrap_or(i64::MAX),
            ),
            monotonic: Duration::from_millis(millis),
        }
    }
}

#[derive(Clone)]
struct FakeSleeper {
    trace: Trace,
}

impl Sleeper for FakeSleeper {
    fn sleep<'a>(&'a self, duration: Duration) -> CapabilityFuture<'a, ()> {
        let trace = self.trace.clone();
        Box::pin(async move {
            trace.push(format!("sleep:{}", duration.as_millis()));
            Ok(())
        })
    }
}

#[derive(Clone, Copy, Default)]
struct FakeRandom;

impl RandomSource for FakeRandom {
    fn next_u64(&self) -> Result<u64, jmeter_rs_runtime::CapabilityError> {
        Ok(7)
    }

    fn clone_for_user(&self) -> Arc<dyn RandomSource> {
        Arc::new(Self)
    }
}

struct StatefulRandom {
    next: Arc<AtomicU64>,
}

impl RandomSource for StatefulRandom {
    fn next_u64(&self) -> Result<u64, jmeter_rs_runtime::CapabilityError> {
        Ok(self.next.fetch_add(1, Ordering::SeqCst))
    }

    fn clone_for_user(&self) -> Arc<dyn RandomSource> {
        Arc::new(Self {
            next: Arc::new(AtomicU64::new(0)),
        })
    }
}

#[derive(Clone, Copy, Default)]
struct FakeFileSystem;

impl FileSystem for FakeFileSystem {
    fn read(&self, _path: &str) -> Result<Vec<u8>, jmeter_rs_runtime::CapabilityError> {
        Ok(Vec::new())
    }
}

#[derive(Clone, Copy, Default)]
struct FakeEnvironment;

impl jmeter_rs_runtime::Environment for FakeEnvironment {
    fn get(&self, _name: &str) -> Option<String> {
        None
    }
}

#[derive(Clone, Copy, Default)]
struct ProbeEnvironment;

impl jmeter_rs_runtime::Environment for ProbeEnvironment {
    fn get(&self, name: &str) -> Option<String> {
        match name {
            "HOSTNAME" => Some("runtime-host".to_owned()),
            "HOST_IP" => Some("192.0.2.1".to_owned()),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Default)]
struct ProbeFileSystem;

impl FileSystem for ProbeFileSystem {
    fn read(&self, path: &str) -> Result<Vec<u8>, jmeter_rs_runtime::CapabilityError> {
        if path == "allowlisted.txt" {
            Ok(b"runtime-file".to_vec())
        } else {
            Err(jmeter_rs_runtime::CapabilityError::unsupported(path))
        }
    }
}

#[derive(Clone, Copy, Default)]
struct CapabilityProbe;

impl FunctionResolver for CapabilityProbe {
    fn resolve_function(
        &self,
        name: &str,
        _arguments: &[String],
        context: &FunctionContext<'_>,
    ) -> Result<Option<String>, FunctionError> {
        if name != "__probe" {
            return Ok(None);
        }
        let random = context
            .random_source()
            .ok_or_else(|| FunctionError::unsupported("random adapter missing"))?
            .next_u64();
        let millis = context
            .clock()
            .ok_or_else(|| FunctionError::unsupported("clock adapter missing"))?
            .now_millis()?;
        let file = context
            .file_capability()
            .ok_or_else(|| FunctionError::unsupported("file adapter missing"))?
            .read_to_string("allowlisted.txt", Some("UTF-8"))?;
        let host = context
            .host_resolver()
            .ok_or_else(|| FunctionError::unsupported("host adapter missing"))?
            .machine_name()?;
        let thread = context
            .execution_context()
            .ok_or_else(|| FunctionError::unsupported("execution adapter missing"))?
            .thread_num()
            .unwrap_or_default();
        Ok(Some(format!("{random}|{millis}|{file}|{host}|{thread}")))
    }
}

#[derive(Clone, Default)]
struct NamespaceProbe;

impl FunctionResolver for NamespaceProbe {
    fn resolve_function(
        &self,
        name: &str,
        _arguments: &[String],
        context: &FunctionContext<'_>,
    ) -> Result<Option<String>, FunctionError> {
        if name == "__namespace" {
            Ok(Some(context.function_occurrence().namespace().to_string()))
        } else {
            Ok(None)
        }
    }
}

#[derive(Clone, Copy, Default)]
struct StringFileSystem;

impl FileSystem for StringFileSystem {
    fn read(&self, path: &str) -> Result<Vec<u8>, jmeter_rs_runtime::CapabilityError> {
        (path == "data.txt")
            .then_some(b"first\nsecond\n".to_vec())
            .ok_or_else(|| jmeter_rs_runtime::CapabilityError::unsupported(path))
    }
}

#[derive(Clone, Copy, Default)]
struct FailingExpressionCleanup;

impl ExpressionStateCleanup for FailingExpressionCleanup {
    fn clear_for_lifecycle(&self, _lifecycle_id: u64) -> Result<(), ComponentError> {
        Err(ComponentError::failure("expression cleanup failed"))
    }
}

struct NamespaceSampler {
    values: Arc<Mutex<Vec<String>>>,
}

impl Sampler for NamespaceSampler {
    fn sample<'a>(
        &'a self,
        context: &'a mut SampleContext<'_>,
    ) -> ComponentFuture<'a, SamplerOutput> {
        let value = context
            .execution()
            .evaluate_expression("${__namespace}", &NamespaceProbe)
            .map_err(|error| ComponentError::failure(error.to_string()));
        let values = Arc::clone(&self.values);
        Box::pin(std::future::ready(value.map(|value| {
            values
                .lock()
                .expect("namespace values lock")
                .push(value.clone());
            SamplerOutput::result(SampleResult::new(value))
        })))
    }
}

#[derive(Clone, Copy, Default)]
struct FailingRandom;

impl RandomSource for FailingRandom {
    fn next_u64(&self) -> Result<u64, jmeter_rs_runtime::CapabilityError> {
        Err(jmeter_rs_runtime::CapabilityError::failure("random failed"))
    }

    fn clone_for_user(&self) -> Arc<dyn RandomSource> {
        Arc::new(Self)
    }
}

fn capabilities(trace: &Trace) -> RuntimeCapabilities {
    RuntimeCapabilities::new(
        Arc::new(FakeClock),
        Arc::new(FakeSleeper {
            trace: trace.clone(),
        }),
        Arc::new(FakeRandom),
        Arc::new(FakeFileSystem),
        Arc::new(FakeEnvironment),
    )
}

struct Config {
    trace: Trace,
    name: &'static str,
    fail: bool,
}

struct StopConfig {
    trace: Trace,
    signal: jmeter_rs_runtime::ControlSignal,
}

impl Configuration for StopConfig {
    fn apply<'a>(&'a self, _context: &'a mut SampleContext<'_>) -> ComponentFuture<'a, ()> {
        Box::pin(async move {
            self.trace.push("config-stop");
            Err(ComponentError::Control(self.signal))
        })
    }
}

struct CleanupFailure {
    trace: Trace,
}

impl PackageLifecycle for CleanupFailure {
    fn finish<'a>(&'a self, _context: &'a mut ExecutionContext) -> ComponentFuture<'a, ()> {
        Box::pin(async move {
            self.trace.push("finish");
            Ok(())
        })
    }

    fn cleanup<'a>(&'a self, _context: &'a mut ExecutionContext) -> ComponentFuture<'a, ()> {
        Box::pin(async move {
            self.trace.push("cleanup");
            Err(ComponentError::failure("cleanup failed"))
        })
    }
}

struct PendingSampler;

impl Sampler for PendingSampler {
    fn sample<'a>(
        &'a self,
        _context: &'a mut SampleContext<'_>,
    ) -> ComponentFuture<'a, SamplerOutput> {
        Box::pin(std::future::pending())
    }
}

struct LongTraceSampler;

impl Sampler for LongTraceSampler {
    fn sample<'a>(
        &'a self,
        context: &'a mut SampleContext<'_>,
    ) -> ComponentFuture<'a, SamplerOutput> {
        Box::pin(async move {
            context.record(Phase::Sampler, "this trace detail is too long")?;
            Ok(SamplerOutput::no_result())
        })
    }
}

struct DropLifecycle {
    trace: Trace,
}

impl PackageLifecycle for DropLifecycle {
    fn finish<'a>(&'a self, _context: &'a mut ExecutionContext) -> ComponentFuture<'a, ()> {
        Box::pin(std::future::ready(Ok(())))
    }

    fn cleanup<'a>(&'a self, _context: &'a mut ExecutionContext) -> ComponentFuture<'a, ()> {
        Box::pin(std::future::ready(Ok(())))
    }

    fn cancel(&self) -> Result<(), ComponentError> {
        self.trace.push("cancel");
        Err(ComponentError::failure("cancel cleanup failed"))
    }
}

struct FreshSamplerFactory;

struct FreshSampler {
    calls: Arc<AtomicU64>,
}

impl Sampler for FreshSampler {
    fn sample<'a>(
        &'a self,
        _context: &'a mut SampleContext<'_>,
    ) -> ComponentFuture<'a, SamplerOutput> {
        Box::pin(async move {
            let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            Ok(SamplerOutput::result(SampleResult::new(call.to_string())))
        })
    }
}

impl SamplerFactory for FreshSamplerFactory {
    fn create(&self) -> Arc<dyn Sampler> {
        Arc::new(FreshSampler {
            calls: Arc::new(AtomicU64::new(0)),
        })
    }
}

struct FreshLifecycleFactory {
    trace: Trace,
}

impl PackageLifecycleFactory for FreshLifecycleFactory {
    fn create(&self) -> Arc<dyn PackageLifecycle> {
        Arc::new(Lifecycle {
            trace: self.trace.clone(),
        })
    }
}

impl Configuration for Config {
    fn apply<'a>(&'a self, context: &'a mut SampleContext<'_>) -> ComponentFuture<'a, ()> {
        Box::pin(async move {
            self.trace.push(self.name);
            if self.fail {
                return Err(ComponentError::failure(self.name));
            }
            context.set_request_value(self.name, "merged");
            Ok(())
        })
    }
}

struct Pre {
    trace: Trace,
    fail: bool,
}

impl Preprocessor for Pre {
    fn process<'a>(&'a self, context: &'a mut SampleContext<'_>) -> ComponentFuture<'a, ()> {
        Box::pin(async move {
            self.trace.push("pre");
            if self.fail {
                return Err(ComponentError::failure("pre"));
            }
            context.execution_mut().set_variable("pre", "done");
            Ok(())
        })
    }
}

struct FakeTimer {
    trace: Trace,
    delay: Duration,
    fail: bool,
}

struct ModifiableTimer {
    trace: Trace,
    delay: Duration,
    modifiable: bool,
}

impl Timer for ModifiableTimer {
    fn delay<'a>(&'a self, _context: &'a mut SampleContext<'_>) -> ComponentFuture<'a, Duration> {
        Box::pin(async move {
            self.trace
                .push(format!("timer: {}", self.delay.as_millis()));
            Ok(self.delay)
        })
    }

    fn is_modifiable(&self) -> bool {
        self.modifiable
    }
}

impl Timer for FakeTimer {
    fn delay<'a>(&'a self, _context: &'a mut SampleContext<'_>) -> ComponentFuture<'a, Duration> {
        Box::pin(async move {
            self.trace.push(format!("timer:{}", self.delay.as_millis()));
            if self.fail {
                return Err(ComponentError::failure("timer"));
            }
            Ok(self.delay)
        })
    }
}

struct FakeSampler {
    trace: Trace,
    output: SamplerOutput,
    fail: bool,
}

impl Sampler for FakeSampler {
    fn sample<'a>(
        &'a self,
        context: &'a mut SampleContext<'_>,
    ) -> ComponentFuture<'a, SamplerOutput> {
        Box::pin(async move {
            self.trace.push("sampler");
            if self.fail {
                return Err(ComponentError::failure("sampler"));
            }
            if self.output.result.is_some() {
                let mut result = self.output.result.clone().expect("test result");
                if let Some(label) = context.request_value("config") {
                    result.set_label(label);
                }
                return Ok(SamplerOutput {
                    result: Some(result),
                    failure: self.output.failure.clone(),
                    signal: self.output.signal,
                });
            }
            Ok(self.output.clone())
        })
    }
}

struct Post {
    trace: Trace,
    fail: bool,
}

impl Postprocessor for Post {
    fn process<'a>(&'a self, _context: &'a mut SampleContext<'_>) -> ComponentFuture<'a, ()> {
        Box::pin(async move {
            self.trace.push("post");
            if self.fail {
                return Err(ComponentError::failure("post"));
            }
            Ok(())
        })
    }
}

struct FakeAssertion {
    trace: Trace,
    result: AssertionResult,
    fail: bool,
}

impl Assertion for FakeAssertion {
    fn evaluate<'a>(
        &'a self,
        _context: &'a mut SampleContext<'_>,
    ) -> ComponentFuture<'a, AssertionResult> {
        Box::pin(async move {
            self.trace.push("assert");
            if self.fail {
                return Err(ComponentError::failure("assert"));
            }
            Ok(self.result.clone())
        })
    }
}

struct FakeListener {
    trace: Trace,
    fail: bool,
}

impl Listener for FakeListener {
    fn on_event<'a>(&'a self, event: &'a SampleEvent) -> ComponentFuture<'a, ()> {
        Box::pin(async move {
            self.trace
                .push(format!("listener:{}", event.result().label()));
            if self.fail {
                return Err(ComponentError::failure("listener"));
            }
            Ok(())
        })
    }
}

struct Lifecycle {
    trace: Trace,
}

impl PackageLifecycle for Lifecycle {
    fn finish<'a>(&'a self, _context: &'a mut ExecutionContext) -> ComponentFuture<'a, ()> {
        Box::pin(async move {
            self.trace.push("finish");
            Ok(())
        })
    }

    fn cleanup<'a>(&'a self, _context: &'a mut ExecutionContext) -> ComponentFuture<'a, ()> {
        Box::pin(async move {
            self.trace.push("cleanup");
            Ok(())
        })
    }
}

fn normal_package(trace: &Trace, result: SamplerOutput) -> SamplePackage {
    SamplePackage::builder(
        NodeId::new(7),
        Arc::new(FakeSampler {
            trace: trace.clone(),
            output: result,
            fail: false,
        }),
    )
    .configurations(vec![Arc::new(Config {
        trace: trace.clone(),
        name: "config",
        fail: false,
    })])
    .preprocessors(vec![Arc::new(Pre {
        trace: trace.clone(),
        fail: false,
    })])
    .timers(vec![
        Arc::new(FakeTimer {
            trace: trace.clone(),
            delay: Duration::from_millis(2),
            fail: false,
        }),
        Arc::new(FakeTimer {
            trace: trace.clone(),
            delay: Duration::from_millis(3),
            fail: false,
        }),
    ])
    .postprocessors(vec![Arc::new(Post {
        trace: trace.clone(),
        fail: false,
    })])
    .assertions(vec![Arc::new(FakeAssertion {
        trace: trace.clone(),
        result: AssertionResult::passed("ok"),
        fail: false,
    })])
    .listeners(vec![Arc::new(FakeListener {
        trace: trace.clone(),
        fail: false,
    })])
    .lifecycle(Arc::new(Lifecycle {
        trace: trace.clone(),
    }))
    .build()
}

fn make_context(trace: &Trace) -> ExecutionContext {
    let mut context = ExecutionContext::with_capabilities(capabilities(trace));
    context.set_sample_variables(["pre"]);
    context
}

fn base_package(trace: &Trace, sampler_id: u64) -> SamplePackage {
    SamplePackage::new(
        NodeId::new(sampler_id),
        Arc::new(FakeSampler {
            trace: trace.clone(),
            output: SamplerOutput::result(SampleResult::new("sample")),
            fail: false,
        }),
    )
    .with_lifecycle(Arc::new(Lifecycle {
        trace: trace.clone(),
    }))
}

#[test]
fn phase_order_timer_sum_listener_snapshot_and_lifecycle_are_deterministic() {
    let trace = Trace::default();
    let package = normal_package(&trace, SamplerOutput::result(SampleResult::new("original")));
    let mut context = make_context(&trace);
    let report =
        block_on(ExecutionPipeline::execute(&package, &mut context)).expect("pipeline succeeds");

    assert_eq!(
        trace.values(),
        vec![
            "config",
            "pre",
            "timer:2",
            "timer:3",
            "sleep:5",
            "sampler",
            "post",
            "assert",
            "listener:merged",
            "finish",
            "cleanup",
        ]
    );
    assert_eq!(
        report.result.as_ref().map(SampleResult::label),
        Some("merged")
    );
    assert_eq!(
        report.event.as_ref().map(|event| event.result().label()),
        Some("merged")
    );
    assert_eq!(
        report
            .event
            .as_ref()
            .and_then(|event| event.variables().get("pre"))
            .and_then(|value| value.as_str()),
        Some("done")
    );
    assert_eq!(
        context.trace().events().first().map(|event| event.phase),
        Some(Phase::Configuration)
    );
    assert_eq!(
        context.trace().events().last().map(|event| event.phase),
        Some(Phase::Cleanup)
    );
    assert!(context.cancellation_error().is_none());
}

#[test]
fn null_sampler_result_skips_post_assertion_and_listener() {
    let trace = Trace::default();
    let package = normal_package(&trace, SamplerOutput::no_result());
    let mut context = make_context(&trace);
    let report = block_on(package.execute(&mut context)).expect("null result is valid");
    assert!(report.result.is_none());
    assert!(report.event.is_none());
    assert_eq!(
        trace.values(),
        vec![
            "config", "pre", "timer:2", "timer:3", "sleep:5", "sampler", "finish", "cleanup"
        ]
    );
}

#[test]
fn assertion_failure_is_result_data_and_reaches_listener() {
    let trace = Trace::default();
    let package = SamplePackage::builder(
        NodeId::new(7),
        Arc::new(FakeSampler {
            trace: trace.clone(),
            output: SamplerOutput::result(SampleResult::new("sample")),
            fail: false,
        }),
    )
    .assertions(vec![Arc::new(FakeAssertion {
        trace: trace.clone(),
        result: AssertionResult::failed("bad", Some("no".to_owned())),
        fail: false,
    })])
    .listeners(vec![Arc::new(FakeListener {
        trace: trace.clone(),
        fail: false,
    })])
    .build();
    let mut context = make_context(&trace);
    let report =
        block_on(package.execute(&mut context)).expect("assertion failure is not engine error");
    let result = report.result.expect("result");
    assert_eq!(result.success(), Some(false));
    assert_eq!(result.assertions().len(), 1);
    assert_eq!(report.event.expect("event").result().assertions().len(), 1);
}

#[test]
fn phase_failures_are_typed_and_cleanup_still_runs() {
    let trace = Trace::default();
    let package = SamplePackage::builder(
        NodeId::new(9),
        Arc::new(FakeSampler {
            trace: trace.clone(),
            output: SamplerOutput::result(SampleResult::new("sample")),
            fail: false,
        }),
    )
    .preprocessors(vec![Arc::new(Pre {
        trace: trace.clone(),
        fail: true,
    })])
    .lifecycle(Arc::new(Lifecycle {
        trace: trace.clone(),
    }))
    .build();
    let mut context = make_context(&trace);
    let error = block_on(package.execute(&mut context)).expect_err("preprocessor failure");
    assert!(matches!(error, PipelineError::Preprocessor { .. }));
    assert_eq!(trace.values(), vec!["pre", "cleanup"]);
}

#[test]
fn cancellation_stops_before_sampler_but_still_finishes_and_cleans_up() {
    let trace = Trace::default();
    let package = SamplePackage::builder(
        NodeId::new(13),
        Arc::new(FakeSampler {
            trace: trace.clone(),
            output: SamplerOutput::result(SampleResult::new("must-not-run")),
            fail: false,
        }),
    )
    .configurations(vec![Arc::new(StopConfig {
        trace: trace.clone(),
        signal: jmeter_rs_runtime::ControlSignal::StopThread,
    })])
    .preprocessors(vec![Arc::new(Pre {
        trace: trace.clone(),
        fail: false,
    })])
    .lifecycle(Arc::new(Lifecycle {
        trace: trace.clone(),
    }))
    .build();
    let mut context = make_context(&trace);

    let report = block_on(package.execute(&mut context)).expect("control is an outcome");

    assert_eq!(report.signal, jmeter_rs_runtime::ControlSignal::StopThread);
    assert!(report.result.is_none());
    assert!(report.event.is_none());
    assert_eq!(trace.values(), vec!["config-stop", "finish", "cleanup"]);
    assert_eq!(
        context
            .trace()
            .events()
            .iter()
            .map(|event| event.phase)
            .collect::<Vec<_>>(),
        vec![Phase::Configuration, Phase::Finish, Phase::Cleanup]
    );
}

#[test]
fn cleanup_failure_is_typed_after_successful_phases() {
    let trace = Trace::default();
    let package = SamplePackage::new(
        NodeId::new(14),
        Arc::new(FakeSampler {
            trace: trace.clone(),
            output: SamplerOutput::no_result(),
            fail: false,
        }),
    )
    .with_lifecycle(Arc::new(CleanupFailure {
        trace: trace.clone(),
    }));
    let mut context = make_context(&trace);

    let error = block_on(package.execute(&mut context)).expect_err("cleanup failure");

    assert!(matches!(error, PipelineError::Cleanup { .. }));
    assert_eq!(trace.values(), vec!["sampler", "finish", "cleanup"]);
    assert_eq!(
        context
            .trace()
            .events()
            .iter()
            .map(|event| event.phase)
            .collect::<Vec<_>>(),
        vec![Phase::Sampler, Phase::Finish, Phase::Cleanup]
    );
}

#[test]
fn every_component_phase_reports_its_own_failure_category() {
    let cases = [
        ("configuration", 1_u64),
        ("preprocessor", 2_u64),
        ("timer", 3_u64),
        ("sampler", 4_u64),
        ("postprocessor", 5_u64),
        ("assertion", 6_u64),
        ("listener", 7_u64),
    ];
    for (phase, sampler_id) in cases {
        let trace = Trace::default();
        let mut package = base_package(&trace, sampler_id);
        match phase {
            "configuration" => {
                package = package.with_configurations(vec![Arc::new(Config {
                    trace: trace.clone(),
                    name: "config",
                    fail: true,
                })]);
            }
            "preprocessor" => {
                package = package.with_preprocessors(vec![Arc::new(Pre {
                    trace: trace.clone(),
                    fail: true,
                })]);
            }
            "timer" => {
                package = package.with_timers(vec![Arc::new(FakeTimer {
                    trace: trace.clone(),
                    delay: Duration::from_millis(1),
                    fail: true,
                })]);
            }
            "sampler" => {
                package = SamplePackage::new(
                    NodeId::new(sampler_id),
                    Arc::new(FakeSampler {
                        trace: trace.clone(),
                        output: SamplerOutput::no_result(),
                        fail: true,
                    }),
                )
                .with_lifecycle(Arc::new(Lifecycle {
                    trace: trace.clone(),
                }));
            }
            "postprocessor" => {
                package = package.with_postprocessors(vec![Arc::new(Post {
                    trace: trace.clone(),
                    fail: true,
                })]);
            }
            "assertion" => {
                package = package.with_assertions(vec![Arc::new(FakeAssertion {
                    trace: trace.clone(),
                    result: AssertionResult::passed("assert"),
                    fail: true,
                })]);
            }
            "listener" => {
                package = package.with_listeners(vec![Arc::new(FakeListener {
                    trace: trace.clone(),
                    fail: true,
                })]);
            }
            _ => continue,
        }
        let mut context = make_context(&trace);
        let error = block_on(package.execute(&mut context)).expect_err("phase failure");
        let matched = match phase {
            "configuration" => matches!(error, PipelineError::Configuration { .. }),
            "preprocessor" => matches!(error, PipelineError::Preprocessor { .. }),
            "timer" => matches!(error, PipelineError::Timer { .. }),
            "sampler" => matches!(error, PipelineError::Sampler { .. }),
            "postprocessor" => matches!(error, PipelineError::Postprocessor { .. }),
            "assertion" => matches!(error, PipelineError::Assertion { .. }),
            "listener" => matches!(error, PipelineError::Listener { .. }),
            _ => false,
        };
        assert!(matched, "unexpected error for {phase}: {error}");
        assert_eq!(trace.values().last().map(String::as_str), Some("cleanup"));
    }
}

#[test]
fn sample_failure_control_and_timer_overflow_remain_distinct() {
    let trace = Trace::default();
    let failure = SampleFailure::new(NodeId::new(7), "connection refused");
    let package = normal_package(&trace, SamplerOutput::failure(failure.clone()));
    let mut context = make_context(&trace);
    let report = block_on(package.execute(&mut context)).expect("sample failure is data");
    assert_eq!(report.sample_failure, Some(failure));

    let overflow = SamplePackage::builder(
        NodeId::new(8),
        Arc::new(FakeSampler {
            trace: trace.clone(),
            output: SamplerOutput::no_result(),
            fail: false,
        }),
    )
    .timers(vec![
        Arc::new(FakeTimer {
            trace: trace.clone(),
            delay: Duration::MAX,
            fail: false,
        }),
        Arc::new(FakeTimer {
            trace: trace.clone(),
            delay: Duration::from_nanos(1),
            fail: false,
        }),
    ])
    .build();
    let mut context = make_context(&trace);
    let error = block_on(overflow.execute(&mut context)).expect_err("checked timer sum");
    assert!(
        matches!(error, PipelineError::TimerOverflow { sampler_id } if sampler_id == NodeId::new(8))
    );
}

#[test]
fn control_signal_is_monotonic_and_context_clones_are_isolated() {
    let trace = Trace::default();
    let package = SamplePackage::builder(
        NodeId::new(7),
        Arc::new(FakeSampler {
            trace: trace.clone(),
            output: SamplerOutput::no_result()
                .with_signal(jmeter_rs_runtime::ControlSignal::StopThread),
            fail: false,
        }),
    )
    .build();
    let mut context = make_context(&trace);
    context.request_control(jmeter_rs_runtime::ControlSignal::StopTestGraceful);
    let report = block_on(package.execute(&mut context)).expect("control is an outcome");
    assert_eq!(
        report.signal,
        jmeter_rs_runtime::ControlSignal::StopTestGraceful
    );

    let mut first = ExecutionContext::new();
    first.set_variable("x", "one");
    let mut second = first.clone_for_user();
    second.set_variable("x", "two");
    assert_eq!(first.variable("x"), Some("one".to_owned()));
    assert_eq!(second.variable("x"), Some("two".to_owned()));
}

#[test]
fn context_clone_starts_with_an_independent_empty_trace() {
    let trace = Trace::default();
    let package = base_package(&trace, 15);
    let mut original = make_context(&trace);
    block_on(package.execute(&mut original)).expect("original execution");
    let original_trace = original.trace().events().to_vec();

    let mut clone = original.clone_for_user();
    assert!(clone.trace().events().is_empty());
    block_on(package.execute(&mut clone)).expect("cloned execution");

    assert_eq!(original.trace().events(), original_trace.as_slice());
    assert_eq!(clone.trace().events(), original_trace.as_slice());
}

#[test]
fn package_compiler_is_identity_keyed_and_rejects_duplicates() {
    let trace = Trace::default();
    let first = normal_package(&trace, SamplerOutput::no_result());
    let duplicate = normal_package(&trace, SamplerOutput::no_result());
    let error = PackageCompiler::compile_default([first.clone(), duplicate])
        .expect_err("duplicate model identity");
    assert_eq!(
        error,
        PackageCompileError::DuplicateSampler {
            sampler_id: NodeId::new(7)
        }
    );
    let second = SamplePackage::new(
        NodeId::new(8),
        Arc::new(FakeSampler {
            trace,
            output: SamplerOutput::no_result(),
            fail: false,
        }),
    );
    let packages = PackageCompiler::compile_default([first, second]).expect("identity map");
    assert_eq!(packages.len(), 2);
    assert!(packages.get(NodeId::new(8)).is_some());
}

#[test]
fn listener_scope_and_order_are_package_local() {
    let trace = Trace::default();
    let first = SamplePackage::builder(
        NodeId::new(11),
        Arc::new(FakeSampler {
            trace: trace.clone(),
            output: SamplerOutput::result(SampleResult::new("first")),
            fail: false,
        }),
    )
    .listeners(vec![
        Arc::new(FakeListener {
            trace: trace.clone(),
            fail: false,
        }),
        Arc::new(FakeListener {
            trace: trace.clone(),
            fail: false,
        }),
    ])
    .build();
    let second = SamplePackage::builder(
        NodeId::new(12),
        Arc::new(FakeSampler {
            trace: trace.clone(),
            output: SamplerOutput::result(SampleResult::new("second")),
            fail: false,
        }),
    )
    .listeners(vec![Arc::new(FakeListener {
        trace: trace.clone(),
        fail: false,
    })])
    .build();
    let mut first_context = make_context(&trace);
    let mut second_context = make_context(&trace);
    block_on(first.execute(&mut first_context)).expect("first listener scope");
    block_on(second.execute(&mut second_context)).expect("second listener scope");
    assert_eq!(
        trace
            .values()
            .into_iter()
            .filter(|value| value.starts_with("listener:"))
            .collect::<Vec<_>>(),
        vec![
            "listener:first".to_owned(),
            "listener:first".to_owned(),
            "listener:second".to_owned(),
        ]
    );
}

#[test]
fn dropped_pending_pipeline_runs_sync_cancel_hook_and_retains_error() {
    let trace = Trace::default();
    let package = SamplePackage::new(NodeId::new(30), Arc::new(PendingSampler)).with_lifecycle(
        Arc::new(DropLifecycle {
            trace: trace.clone(),
        }),
    );
    let mut context = make_context(&trace);
    let mut pending = package.execute(&mut context);
    let waker = Waker::noop();
    let mut task_context = Context::from_waker(waker);
    assert!(matches!(
        Pin::new(&mut pending).poll(&mut task_context),
        Poll::Pending
    ));
    drop(pending);

    assert_eq!(trace.values(), vec!["cancel"]);
    assert!(matches!(
        context.cancellation_error(),
        Some(ComponentError::Failure(message)) if message == "cancel cleanup failed"
    ));
}

#[test]
fn dropped_pending_pipeline_without_cancel_hook_is_explicitly_reported() {
    let trace = Trace::default();
    let package = SamplePackage::new(NodeId::new(35), Arc::new(PendingSampler)).with_lifecycle(
        Arc::new(Lifecycle {
            trace: trace.clone(),
        }),
    );
    let mut context = make_context(&trace);
    let pending = package.execute(&mut context);
    drop(pending);
    assert!(matches!(
        context.cancellation_error(),
        Some(ComponentError::Unsupported(message))
            if message == "synchronous cancellation cleanup is not implemented"
    ));
}

#[test]
fn pending_pipeline_deadline_is_deterministic_and_cancellation_safe() {
    let trace = Trace::default();
    let clock = Arc::new(AdvancingClock::new());
    let capabilities = RuntimeCapabilities::default().with_clock(clock.clone());
    let package = SamplePackage::new(NodeId::new(36), Arc::new(PendingSampler)).with_lifecycle(
        Arc::new(DropLifecycle {
            trace: trace.clone(),
        }),
    );
    let mut context = ExecutionContext::with_capabilities(capabilities);
    context.set_deadline(Some(Duration::from_millis(5)));
    let mut pending = package.execute(&mut context);
    let waker = Waker::noop();
    let mut task_context = Context::from_waker(waker);
    assert!(matches!(
        Pin::new(&mut pending).poll(&mut task_context),
        Poll::Pending
    ));
    clock.advance_to(5);
    let result = Pin::new(&mut pending).poll(&mut task_context);
    assert!(matches!(
        result,
        Poll::Ready(Err(PipelineError::Combined { primary, cleanup }))
            if matches!(*primary, PipelineError::DeadlineExceeded { sampler_id } if sampler_id == NodeId::new(36))
                && matches!(*cleanup, PipelineError::Cleanup { sampler_id, .. } if sampler_id == NodeId::new(36))
    ));
    drop(pending);
    assert_eq!(trace.values(), vec!["cancel"]);
    assert!(matches!(
        context.cancellation_error(),
        Some(ComponentError::Failure(message)) if message == "cancel cleanup failed"
    ));
}

#[test]
fn cleanup_error_is_combined_with_primary_phase_error() {
    let trace = Trace::default();
    let package = SamplePackage::builder(
        NodeId::new(31),
        Arc::new(FakeSampler {
            trace: trace.clone(),
            output: SamplerOutput::no_result(),
            fail: false,
        }),
    )
    .preprocessors(vec![Arc::new(Pre {
        trace: trace.clone(),
        fail: true,
    })])
    .lifecycle(Arc::new(CleanupFailure {
        trace: trace.clone(),
    }))
    .build();
    let mut context = make_context(&trace);
    let error = block_on(package.execute(&mut context)).expect_err("both failures are retained");
    assert!(matches!(error, PipelineError::Combined { .. }));
    assert_eq!(trace.values(), vec!["pre", "cleanup"]);
}

#[test]
fn timer_factor_scales_only_modifiable_timers() {
    let trace = Trace::default();
    let package = SamplePackage::builder(
        NodeId::new(32),
        Arc::new(FakeSampler {
            trace: trace.clone(),
            output: SamplerOutput::no_result(),
            fail: false,
        }),
    )
    .timers(vec![
        Arc::new(ModifiableTimer {
            trace: trace.clone(),
            delay: Duration::from_millis(2),
            modifiable: true,
        }),
        Arc::new(ModifiableTimer {
            trace: trace.clone(),
            delay: Duration::from_millis(3),
            modifiable: false,
        }),
    ])
    .build();
    let mut context = make_context(&trace);
    context.set_timer_factor(2.0).expect("valid factor");
    block_on(package.execute(&mut context)).expect("factorized timers");
    assert!(trace.values().iter().any(|value| value == "sleep:7"));
}

#[test]
fn context_clone_shares_properties_and_test_stop_but_isolates_user_stop_loop_and_random_state() {
    let random = Arc::new(StatefulRandom {
        next: Arc::new(AtomicU64::new(0)),
    });
    let capabilities = RuntimeCapabilities::default().with_random(random);
    let mut first = ExecutionContext::with_capabilities(capabilities);
    first.set_property("run", "one");
    let second = first.clone_for_user();
    second.set_property("run", "two");
    assert_eq!(first.property("run").as_deref(), Some("two"));
    assert_eq!(first.capabilities().random().next_u64().expect("random"), 0);
    assert_eq!(
        second.capabilities().random().next_u64().expect("random"),
        0
    );

    first.request_control(jmeter_rs_runtime::ControlSignal::NextLoop);
    assert_eq!(
        first.control_signal(),
        jmeter_rs_runtime::ControlSignal::NextLoop
    );
    assert_eq!(
        second.control_signal(),
        jmeter_rs_runtime::ControlSignal::Continue
    );
    assert_eq!(
        first.take_control_signal(),
        jmeter_rs_runtime::ControlSignal::NextLoop
    );
    assert_eq!(
        first.take_control_signal(),
        jmeter_rs_runtime::ControlSignal::Continue
    );

    first.request_control(jmeter_rs_runtime::ControlSignal::StopThread);
    assert_eq!(
        first.control_signal(),
        jmeter_rs_runtime::ControlSignal::StopThread
    );
    assert_eq!(
        second.control_signal(),
        jmeter_rs_runtime::ControlSignal::Continue
    );
    first.request_control(jmeter_rs_runtime::ControlSignal::StopTestGraceful);
    assert_eq!(
        second.control_signal(),
        jmeter_rs_runtime::ControlSignal::StopTestGraceful
    );
}

#[test]
fn evaluate_expression_uses_injected_runtime_capabilities() {
    let capabilities = RuntimeCapabilities::new(
        Arc::new(FakeClock),
        Arc::new(ImmediateSleeper),
        Arc::new(FakeRandom),
        Arc::new(ProbeFileSystem),
        Arc::new(ProbeEnvironment),
    );
    let mut context = ExecutionContext::with_capabilities(capabilities);
    context.set_thread(jmeter_rs_results::ThreadIdentity::with_group(
        "thread",
        Some("group".to_owned()),
        Some(7),
    ));

    let value = context
        .evaluate_expression("${__probe}", &CapabilityProbe)
        .expect("injected capabilities are available");
    assert_eq!(value, "7|10|runtime-file|runtime-host|7");
}

#[test]
fn evaluate_expression_surfaces_random_capability_failures() {
    let capabilities = RuntimeCapabilities::default().with_random(Arc::new(FailingRandom));
    let context = ExecutionContext::with_capabilities(capabilities);
    let error = context
        .evaluate_expression("${__probe}", &CapabilityProbe)
        .expect_err("random failure must not become zero");
    assert!(matches!(
        error,
        jmeter_rs_expr::EvaluationError::Function {
            source: FunctionError::Execution(message),
            ..
        } if message == "random failed"
    ));
}

#[test]
fn runtime_expression_namespace_is_stable_for_a_sampler_field() {
    let mut context = ExecutionContext::new();
    let functions = NamespaceProbe;
    context.set_expression_field_namespace("runtime.plan.sampler", NodeId::new(77), "sampler");
    let first = context
        .evaluate_expression("${__namespace}", &functions)
        .expect("namespace probe");
    let second = context
        .evaluate_expression("${__namespace}", &functions)
        .expect("namespace probe repeats");
    assert_eq!(first, second);
    assert_ne!(first, "0");
    context.set_expression_field_namespace("runtime.plan.sampler", NodeId::new(78), "sampler");
    let other = context
        .evaluate_expression("${__namespace}", &functions)
        .expect("other sampler namespace");
    assert_ne!(first, other);
}

#[test]
fn execution_pipeline_assigns_sampler_field_namespace_before_evaluation() {
    let values = Arc::new(Mutex::new(Vec::new()));
    let package = SamplePackage::builder(
        NodeId::new(99),
        Arc::new(NamespaceSampler {
            values: Arc::clone(&values),
        }),
    )
    .build();
    let mut context = ExecutionContext::new();
    block_on(ExecutionPipeline::execute(&package, &mut context)).expect("pipeline");
    let values = values.lock().expect("namespace values lock").clone();
    assert_eq!(values.len(), 1);
    assert_ne!(values[0], "0");
}

#[test]
fn runtime_file_adapter_keys_cursors_by_structural_occurrence() {
    let capabilities = RuntimeCapabilities::default().with_filesystem(Arc::new(StringFileSystem));
    let mut context = ExecutionContext::with_capabilities(capabilities);
    context.set_expression_field_namespace("runtime.plan.sampler", NodeId::new(88), "sampler");
    let functions = BuiltinFunctions::new();
    assert_eq!(
        context
            .evaluate_expression(
                "${__StringFromFile(data.txt,A)}:${__StringFromFile(data.txt,B)}",
                &functions,
            )
            .expect("first file expansion"),
        "first:first"
    );
    assert_eq!(
        context
            .evaluate_expression(
                "${__StringFromFile(data.txt,A)}:${__StringFromFile(data.txt,B)}",
                &functions,
            )
            .expect("second file expansion"),
        "second:second"
    );
}

#[test]
fn evaluate_expression_property_setter_does_not_deadlock_property_resolver() {
    let context = ExecutionContext::new();
    let functions = BuiltinFunctions::new();
    let value = context
        .evaluate_expression("${__setProperty(name,value)}:${__P(name)}", &functions)
        .expect("property capability");
    assert_eq!(value, ":value");
    assert_eq!(context.property("name").as_deref(), Some("value"));
}

#[test]
fn evaluate_expression_uses_lifecycle_identity_and_cleans_stateful_functions() {
    let mut context = ExecutionContext::new();
    context.set_lifecycle_id(Some(77));
    context.set_thread(jmeter_rs_results::ThreadIdentity::with_group(
        "thread",
        Some("group".to_owned()),
        Some(1),
    ));
    context.set_iteration_id(Some(0));
    let functions = BuiltinFunctions::new();
    assert_eq!(
        context
            .evaluate_expression("${__counter(true)}", &functions)
            .expect("first counter"),
        "1"
    );
    assert_eq!(
        context
            .evaluate_expression("${__counter(true)}", &functions)
            .expect("second counter"),
        "2"
    );
    context.set_iteration_id(Some(1));
    assert_eq!(
        context
            .evaluate_expression("${__counter(true)}", &functions)
            .expect("next iteration counter"),
        "3"
    );
    assert_eq!(
        context
            .evaluate_expression("${__counter(true)}:${__counter(true)}", &functions)
            .expect("distinct counter occurrences"),
        "4:1"
    );
    context
        .clear_expression_state(&functions)
        .expect("counter cleanup");
    assert_eq!(
        context
            .evaluate_expression("${__counter(true)}", &functions)
            .expect("counter after lifecycle cleanup"),
        "1"
    );
}

#[test]
fn configured_expression_cleanup_runs_without_ambient_registry_access() {
    let functions = Arc::new(BuiltinFunctions::new());
    let capabilities = RuntimeCapabilities::default().with_expression_cleanup(functions.clone());
    let mut context = ExecutionContext::with_capabilities(capabilities);
    context.set_lifecycle_id(Some(91));
    context.set_thread(jmeter_rs_results::ThreadIdentity::with_group(
        "thread",
        Some("group".to_owned()),
        Some(1),
    ));
    context.set_iteration_id(Some(0));
    assert_eq!(
        context
            .evaluate_expression("${__counter(true)}", functions.as_ref())
            .expect("counter"),
        "1"
    );
    context
        .cleanup_expression_state()
        .expect("configured counter cleanup");
    assert_eq!(
        context
            .evaluate_expression("${__counter(true)}", functions.as_ref())
            .expect("counter after cleanup"),
        "1"
    );
}

#[test]
fn expression_cleanup_failure_is_returned_as_a_typed_runtime_error() {
    let capabilities =
        RuntimeCapabilities::default().with_expression_cleanup(Arc::new(FailingExpressionCleanup));
    let mut context = ExecutionContext::with_capabilities(capabilities);
    context.set_lifecycle_id(Some(123));
    let error = context
        .cleanup_expression_state()
        .expect_err("cleanup failure must be propagated");
    assert_eq!(error.code(), "runtime.component.failure");
    assert_eq!(
        error.to_string(),
        "runtime.component.failure: expression cleanup failed"
    );
}

#[test]
fn runtime_counter_adapter_keeps_global_sequence_between_user_identities() {
    let functions = BuiltinFunctions::new();
    let mut first = ExecutionContext::new();
    first.set_lifecycle_id(Some(1));
    first.set_thread(jmeter_rs_results::ThreadIdentity::with_group(
        "first",
        Some("group".to_owned()),
        Some(1),
    ));
    first.set_expression_field_namespace("runtime.plan.sampler", NodeId::new(301), "sampler");
    first.set_iteration_id(Some(0));
    assert_eq!(
        first
            .evaluate_expression("${__counter(false)}", &functions)
            .expect("first global counter"),
        "1"
    );

    let mut second = ExecutionContext::new();
    second.set_lifecycle_id(Some(2));
    second.set_thread(jmeter_rs_results::ThreadIdentity::with_group(
        "second",
        Some("group".to_owned()),
        Some(2),
    ));
    second.set_expression_field_namespace("runtime.plan.sampler", NodeId::new(301), "sampler");
    second.set_iteration_id(Some(0));
    assert_eq!(
        second
            .evaluate_expression("${__counter(false)}", &functions)
            .expect("second global counter"),
        "2"
    );
}

#[test]
fn per_user_package_factories_do_not_share_sampler_state() {
    let trace = Trace::default();
    let package = SamplePackage::builder(
        NodeId::new(33),
        Arc::new(FreshSampler {
            calls: Arc::new(AtomicU64::new(0)),
        }),
    )
    .sampler_factory(Arc::new(FreshSamplerFactory))
    .lifecycle_factory(Arc::new(FreshLifecycleFactory {
        trace: trace.clone(),
    }))
    .build();
    let first = package.clone_for_user().expect("first user package");
    let second = package.clone_for_user().expect("second user package");
    let mut first_context = make_context(&trace);
    let mut second_context = make_context(&trace);
    let first_report = block_on(first.execute(&mut first_context)).expect("first sample");
    let second_report = block_on(second.execute(&mut second_context)).expect("second sample");
    assert_eq!(
        first_report.result.as_ref().map(SampleResult::label),
        Some("1")
    );
    assert_eq!(
        second_report.result.as_ref().map(SampleResult::label),
        Some("1")
    );
}

#[test]
fn required_package_lookup_reports_missing_identity() {
    let packages = PackageCompiler::compile_default(std::iter::empty()).expect("empty map");
    assert_eq!(
        packages
            .require(NodeId::new(99))
            .expect_err("missing package"),
        PackageCompileError::MissingPackage {
            sampler_id: NodeId::new(99)
        }
    );
}

#[test]
fn trace_detail_bound_is_enforced_without_truncation() {
    let mut context = ExecutionContext::new();
    context.set_trace_limits(4, 15);
    let package = SamplePackage::new(NodeId::new(34), Arc::new(LongTraceSampler));
    let actual = block_on(package.execute(&mut context)).expect_err("trace bound");
    assert!(matches!(
        actual,
        PipelineError::Sampler {
            source: ComponentError::ResourceLimit(message),
            ..
        } if message == "execution trace detail capacity"
    ));
}
