// SPDX-License-Identifier: Apache-2.0
//! Deterministic built-in timer adapters.
//!
//! A timer only computes the delay for one sampler invocation.  Sleeping is
//! owned by the execution pipeline's injected [`crate::Sleeper`].  This
//! module consequently has no dependency on an executor, a host clock, or a
//! host random-number generator.  Timers which need run-wide state expose a
//! small, typed capability seam instead of silently pretending that a
//! per-user copy is a serialized run-wide implementation.

use std::collections::VecDeque;
use std::fmt;
use std::future::{self, Future};
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use crate::{ComponentError, ComponentFuture, SampleContext, SchedulerError, Timer, TimerFactory};

// A Duration can represent more than u64 nanoseconds.  The timer protocol
// deliberately uses a bounded nanosecond representation so conversion and
// accumulation never silently saturate.
const MAX_RANDOM_ATTEMPTS: usize = 128;
const MAX_PRECISE_ARRIVALS_PER_WINDOW: u64 = 65_536;
const MAX_PRECISE_WINDOW_ADVANCES: usize = 65_536;
const MAX_TIMER_NAME_BYTES: usize = 4_096;

fn lock<T>(value: &Mutex<T>) -> MutexGuard<'_, T> {
    value
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn ready<T: 'static>(value: Result<T, ComponentError>) -> ComponentFuture<'static, T> {
    Box::pin(future::ready(value))
}

fn duration_from_nanos(value: u128) -> Result<Duration, ComponentError> {
    let nanos = u64::try_from(value)
        .map_err(|_| ComponentError::resource_limit("timer duration nanoseconds"))?;
    Ok(Duration::from_nanos(nanos))
}

fn duration_nanos(value: Duration) -> Result<u64, ComponentError> {
    u64::try_from(value.as_nanos())
        .map_err(|_| ComponentError::resource_limit("timer duration nanoseconds"))
}

fn next_random(source: &dyn crate::RandomSource) -> Result<u64, ComponentError> {
    source.next_u64().map_err(ComponentError::from)
}

/// Samples one value uniformly from `[0, upper)` without modulo bias.
///
/// `RandomSource` supplies the complete 64-bit domain.  Rejection sampling
/// uses the largest multiple of `upper` contained in that domain and has a
/// finite attempt bound so a broken/adversarial source cannot loop forever.
fn uniform_below(source: &dyn crate::RandomSource, upper: u64) -> Result<u64, ComponentError> {
    if upper == 0 {
        // Java's random timer still evaluates its random expression for a
        // zero range.  Consume one value to preserve stream position.
        let _ = next_random(source)?;
        return Ok(0);
    }
    let rejection = (0u64.wrapping_sub(upper)) % upper;
    for _ in 0..MAX_RANDOM_ATTEMPTS {
        let value = next_random(source)?;
        if value >= rejection {
            return Ok(value % upper);
        }
    }
    Err(ComponentError::resource_limit(
        "timer random rejection-attempt bound",
    ))
}

fn random_unit_half_open(value: u64) -> f64 {
    (value >> 11) as f64 / 9_007_199_254_740_992.0
}

fn duration_from_float_nanos(value: f64) -> Result<Duration, ComponentError> {
    if !value.is_finite() {
        return Err(ComponentError::resource_limit(
            "non-finite timer distribution result",
        ));
    }
    if value <= 0.0 {
        return Ok(Duration::ZERO);
    }
    // `u64::MAX as f64` rounds to 2^64.  Comparing against the exact power
    // of two keeps the cast below the representable Duration bound.
    if value >= 18_446_744_073_709_551_616.0 {
        return Err(ComponentError::resource_limit(
            "timer distribution duration overflow",
        ));
    }
    duration_from_nanos(value.floor() as u128)
}

/// Converts a Java `double` to the `long` value used by JMeter's random
/// timers.  Java narrows toward zero, maps NaN to zero, and saturates values
/// outside the `long` range.  The caller applies JMeter's `Math.abs` before
/// invoking this helper.
fn java_long_from_double(value: f64) -> i64 {
    const LONG_BOUND: f64 = 9_223_372_036_854_775_808.0; // 2^63

    if value.is_nan() {
        0
    } else if value >= LONG_BOUND {
        i64::MAX
    } else if value <= -LONG_BOUND {
        i64::MIN
    } else {
        value as i64
    }
}

/// Applies JMeter's `Math.abs` and Java `double`-to-`long` conversion to a
/// delay expressed in milliseconds, then converts it to the runtime's
/// bounded nanosecond representation.
fn jmeter_delay_from_millis(raw: f64) -> Result<Duration, ComponentError> {
    let millis = java_long_from_double(raw.abs());
    if millis <= 0 {
        return Ok(Duration::ZERO);
    }
    let nanos = u128::from(millis as u64)
        .checked_mul(1_000_000)
        .ok_or_else(|| ComponentError::resource_limit("timer delay milliseconds"))?;
    duration_from_nanos(nanos)
}

fn duration_as_millis(value: Duration) -> f64 {
    value.as_secs_f64() * 1_000.0
}

/// Evaluates JMeter's Uniform Random Timer expression. `minimum` is the
/// constant offset and `maximum - minimum` is the random range, matching the
/// compiler's representation of `ConstantTimer.delay` and `RandomTimer.range`.
fn jmeter_uniform_duration(
    source: &dyn crate::RandomSource,
    minimum: Duration,
    maximum: Duration,
) -> Result<Duration, ComponentError> {
    let range = maximum
        .checked_sub(minimum)
        .ok_or_else(|| ComponentError::failure("timer maximum precedes minimum"))?;
    let random = random_unit_half_open(next_random(source)?);
    let raw_millis = random * duration_as_millis(range) + duration_as_millis(minimum);
    jmeter_delay_from_millis(raw_millis)
}

fn jmeter_gaussian_duration(
    normal: f64,
    offset: Duration,
    deviation: Duration,
) -> Result<Duration, ComponentError> {
    let raw_millis = normal * duration_as_millis(deviation) + duration_as_millis(offset);
    jmeter_delay_from_millis(raw_millis)
}

/// A fixed additive delay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConstantTimer {
    delay: Duration,
    modifiable: bool,
}

impl ConstantTimer {
    /// Creates a JMeter Constant Timer.
    ///
    /// JMeter 5.6.3 does not mark `ConstantTimer` as a `ModifiableTimer`, so
    /// the pipeline's `timer.factor` does not scale this value.
    #[must_use]
    pub const fn new(delay: Duration) -> Self {
        Self {
            delay,
            modifiable: false,
        }
    }

    /// Creates a constant timer that explicitly participates in the runtime
    /// factor. This is useful for a profile-specific extension, not for the
    /// built-in JMeter Constant Timer.
    #[must_use]
    pub const fn modifiable(delay: Duration) -> Self {
        Self {
            delay,
            modifiable: true,
        }
    }

    /// Creates a timer that is not affected by the pipeline timer factor.
    #[must_use]
    pub const fn fixed(delay: Duration) -> Self {
        Self {
            delay,
            modifiable: false,
        }
    }

    /// Returns the configured delay.
    #[must_use]
    pub const fn delay_value(self) -> Duration {
        self.delay
    }
}

impl Timer for ConstantTimer {
    fn delay<'a>(&'a self, _context: &'a mut SampleContext<'_>) -> ComponentFuture<'a, Duration> {
        ready(Ok(self.delay))
    }

    fn is_modifiable(&self) -> bool {
        self.modifiable
    }
}

impl TimerFactory for ConstantTimer {
    fn create(&self) -> Arc<dyn Timer> {
        Arc::new(*self)
    }
}

/// A JMeter Uniform Random Timer.
///
/// `minimum` is the constant delay offset and `maximum - minimum` is the
/// random-delay range.  JMeter evaluates the expression in floating-point
/// milliseconds, applies `Math.abs`, and then narrows to a Java `long`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UniformRandomTimer {
    minimum: Duration,
    maximum: Duration,
}

impl UniformRandomTimer {
    /// Creates a uniform timer. Invalid intervals are reported when sampled.
    #[must_use]
    pub const fn new(minimum: Duration, maximum: Duration) -> Self {
        Self { minimum, maximum }
    }

    /// Returns the configured offset and offset-plus-range endpoint.
    #[must_use]
    pub const fn interval(self) -> (Duration, Duration) {
        (self.minimum, self.maximum)
    }
}

impl Timer for UniformRandomTimer {
    fn delay<'a>(&'a self, context: &'a mut SampleContext<'_>) -> ComponentFuture<'a, Duration> {
        ready(jmeter_uniform_duration(
            context.execution().capabilities().random(),
            self.minimum,
            self.maximum,
        ))
    }
}

impl TimerFactory for UniformRandomTimer {
    fn create(&self) -> Arc<dyn Timer> {
        Arc::new(*self)
    }
}

/// A Gaussian delay using an injected deterministic random stream.
#[derive(Debug)]
pub struct GaussianRandomTimer {
    mean: Duration,
    deviation: Duration,
    spare: Arc<Mutex<Option<f64>>>,
}

impl Clone for GaussianRandomTimer {
    fn clone(&self) -> Self {
        // A cloned virtual-user timer starts a fresh Java-style Gaussian
        // cache; sharing the spare variate would couple two user streams.
        Self::new(self.mean, self.deviation)
    }
}

impl GaussianRandomTimer {
    /// Creates a Gaussian timer with non-negative mean and deviation.
    #[must_use]
    pub fn new(mean: Duration, deviation: Duration) -> Self {
        Self {
            mean,
            deviation,
            spare: Arc::new(Mutex::new(None)),
        }
    }

    /// Returns the configured mean and standard deviation.
    #[must_use]
    pub const fn parameters(&self) -> (Duration, Duration) {
        (self.mean, self.deviation)
    }
}

fn gaussian_normal(
    source: &dyn crate::RandomSource,
    spare: &mut Option<f64>,
) -> Result<f64, ComponentError> {
    if let Some(value) = spare.take() {
        return Ok(value);
    }
    for _ in 0..MAX_RANDOM_ATTEMPTS {
        let first = next_random(source)?;
        let second = next_random(source)?;
        // java.util.Random.nextGaussian uses the polar form of Box-Muller and
        // caches the second variate.  The half-open unit values avoid an
        // endpoint equal to one while preserving a possible zero.
        let unit_a = 2.0 * random_unit_half_open(first) - 1.0;
        let unit_b = 2.0 * random_unit_half_open(second) - 1.0;
        let square = unit_a * unit_a + unit_b * unit_b;
        if square > 0.0 && square < 1.0 {
            let multiplier = (-2.0 * square.ln() / square).sqrt();
            *spare = Some(unit_b * multiplier);
            return Ok(unit_a * multiplier);
        }
    }
    Err(ComponentError::resource_limit(
        "Gaussian timer rejection-attempt bound",
    ))
}

impl Timer for GaussianRandomTimer {
    fn delay<'a>(&'a self, context: &'a mut SampleContext<'_>) -> ComponentFuture<'a, Duration> {
        let source = context.execution().capabilities().random();
        let mut spare = lock(&self.spare);
        let normal = gaussian_normal(source, &mut spare);
        ready(normal.and_then(|normal| jmeter_gaussian_duration(normal, self.mean, self.deviation)))
    }
}

impl TimerFactory for GaussianRandomTimer {
    fn create(&self) -> Arc<dyn Timer> {
        Arc::new(Self::new(self.mean, self.deviation))
    }
}

/// A Poisson/exponential random timer.
///
/// The one-argument constructor is retained for compatibility with the
/// original runtime API and represents an exponential interval with no base
/// delay.  [`Self::with_base_and_range`] corresponds to JMeter's base delay
/// plus `RandomTimer.range` form used by the 5.6.3 fixtures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PoissonRandomTimer {
    base: Duration,
    range: Duration,
}

impl PoissonRandomTimer {
    /// Creates a Poisson timer whose mean interval is `mean`.
    #[must_use]
    pub const fn new(mean: Duration) -> Self {
        Self {
            base: Duration::ZERO,
            range: mean,
        }
    }

    /// Creates a JMeter-style timer with a base delay and exponential range.
    #[must_use]
    pub const fn with_base_and_range(base: Duration, range: Duration) -> Self {
        Self { base, range }
    }

    /// Returns the configured exponential mean/range.
    #[must_use]
    pub const fn mean(self) -> Duration {
        self.range
    }

    /// Returns the configured base and range.
    #[must_use]
    pub const fn parameters(self) -> (Duration, Duration) {
        (self.base, self.range)
    }
}

fn poisson_delay(
    source: &dyn crate::RandomSource,
    base: Duration,
    range: Duration,
) -> Result<Duration, ComponentError> {
    let random = next_random(source)?;
    let unit = random_unit_half_open(random);
    let extra = duration_from_float_nanos(-(1.0 - unit).ln() * range.as_nanos() as f64)?;
    base.checked_add(extra)
        .ok_or_else(|| ComponentError::resource_limit("Poisson timer duration"))
}

impl Timer for PoissonRandomTimer {
    fn delay<'a>(&'a self, context: &'a mut SampleContext<'_>) -> ComponentFuture<'a, Duration> {
        let source = context.execution().capabilities().random();
        ready(poisson_delay(source, self.base, self.range))
    }
}

impl TimerFactory for PoissonRandomTimer {
    fn create(&self) -> Arc<dyn Timer> {
        Arc::new(*self)
    }
}

/// Calculation modes named by JMeter's `ConstantThroughputTimer.Mode` enum.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConstantThroughputMode {
    /// Pace each virtual user independently.
    ThisThreadOnly,
    /// Divide the target among all active threads, with per-thread targets.
    AllActiveThreads,
    /// Divide the target among active threads in the current thread group.
    AllActiveThreadsInCurrentThreadGroup,
    /// Use one run-wide target among all active threads.
    AllActiveThreadsShared,
    /// Use one thread-group target among active group threads.
    AllActiveThreadsInCurrentThreadGroupShared,
}

impl ConstantThroughputMode {
    /// JMeter's serialized name for the shared all-active mode.
    #[allow(non_upper_case_globals)]
    pub const AllActiveThreads_Shared: Self = Self::AllActiveThreadsShared;

    /// JMeter's serialized name for the shared thread-group mode.
    #[allow(non_upper_case_globals)]
    pub const AllActiveThreadsInCurrentThreadGroup_Shared: Self =
        Self::AllActiveThreadsInCurrentThreadGroupShared;

    /// Returns the exact JMeter serialized mode name.
    #[must_use]
    pub const fn jmeter_name(self) -> &'static str {
        match self {
            Self::ThisThreadOnly => "ThisThreadOnly",
            Self::AllActiveThreads => "AllActiveThreads",
            Self::AllActiveThreadsInCurrentThreadGroup => "AllActiveThreadsInCurrentThreadGroup",
            Self::AllActiveThreadsShared => "AllActiveThreads_Shared",
            Self::AllActiveThreadsInCurrentThreadGroupShared => {
                "AllActiveThreadsInCurrentThreadGroup_Shared"
            }
        }
    }
}

/// Descriptive alias for [`ConstantThroughputMode`].
pub type ConstantThroughputCalculationMode = ConstantThroughputMode;

/// State and identity supplied to a run-wide throughput implementation.
#[derive(Clone, Debug)]
pub struct ThroughputRequest {
    mode: ConstantThroughputMode,
    period: Duration,
    now: Duration,
    thread_name: String,
    thread_group: Option<String>,
    thread_number: Option<u64>,
    lifecycle_id: Option<u64>,
}

impl ThroughputRequest {
    /// Returns the requested JMeter calculation mode.
    #[must_use]
    pub const fn mode(&self) -> ConstantThroughputMode {
        self.mode
    }

    /// Returns the target sample period.
    #[must_use]
    pub const fn period(&self) -> Duration {
        self.period
    }

    /// Returns the injected monotonic reading at reservation time.
    #[must_use]
    pub const fn now(&self) -> Duration {
        self.now
    }

    /// Returns the virtual-user thread name.
    #[must_use]
    pub fn thread_name(&self) -> &str {
        &self.thread_name
    }

    /// Returns the optional thread-group name.
    #[must_use]
    pub fn thread_group(&self) -> Option<&str> {
        self.thread_group.as_deref()
    }

    /// Returns the optional numeric thread index.
    #[must_use]
    pub const fn thread_number(&self) -> Option<u64> {
        self.thread_number
    }

    /// Returns the lifecycle identity, when the engine supplied one.
    #[must_use]
    pub const fn lifecycle_id(&self) -> Option<u64> {
        self.lifecycle_id
    }
}

/// External run capability for the four Constant Throughput modes that need
/// active-thread accounting or a serialized run-wide target.
pub trait ThroughputCoordinator: Send + Sync {
    /// Atomically reserves the next target for one invocation.
    fn reserve(&self, request: &ThroughputRequest) -> Result<Duration, ComponentError>;
}

#[derive(Debug, Default)]
struct ThroughputState {
    next: Option<Duration>,
}

/// A Constant Throughput Timer.
pub struct ConstantThroughputTimer {
    period: Duration,
    mode: ConstantThroughputMode,
    state: Arc<Mutex<ThroughputState>>,
    coordinator: Option<Arc<dyn ThroughputCoordinator>>,
}

impl Clone for ConstantThroughputTimer {
    fn clone(&self) -> Self {
        // A direct clone represents a fresh virtual-user timer.  Sharing the
        // target cursor would turn this-thread pacing into an accidental
        // run-wide coordinator.
        Self {
            period: self.period,
            mode: self.mode,
            state: Arc::new(Mutex::new(ThroughputState::default())),
            coordinator: self.coordinator.clone(),
        }
    }
}

impl fmt::Debug for ConstantThroughputTimer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConstantThroughputTimer")
            .field("period", &self.period)
            .field("mode", &self.mode)
            .field("has_coordinator", &self.coordinator.is_some())
            .finish()
    }
}

impl ConstantThroughputTimer {
    /// Creates a timer targeting `samples_per_minute` in this-thread mode.
    pub fn new(samples_per_minute: f64) -> Result<Self, ComponentError> {
        Self::from_rate(
            samples_per_minute,
            ConstantThroughputMode::ThisThreadOnly,
            None,
        )
    }

    /// Creates a timer for an explicit JMeter calculation mode.
    pub fn new_with_mode(
        samples_per_minute: f64,
        mode: ConstantThroughputMode,
        coordinator: Option<Arc<dyn ThroughputCoordinator>>,
    ) -> Result<Self, ComponentError> {
        Self::from_rate(samples_per_minute, mode, coordinator)
    }

    /// Alias for [`Self::new_with_mode`] using JMeter's terminology.
    pub fn for_mode(
        samples_per_minute: f64,
        mode: ConstantThroughputMode,
        coordinator: Option<Arc<dyn ThroughputCoordinator>>,
    ) -> Result<Self, ComponentError> {
        Self::new_with_mode(samples_per_minute, mode, coordinator)
    }

    /// Creates a timer for a non-local mode with its run coordinator.
    pub fn with_coordinator(
        samples_per_minute: f64,
        mode: ConstantThroughputMode,
        coordinator: Arc<dyn ThroughputCoordinator>,
    ) -> Result<Self, ComponentError> {
        Self::from_rate(samples_per_minute, mode, Some(coordinator))
    }

    fn from_rate(
        samples_per_minute: f64,
        mode: ConstantThroughputMode,
        coordinator: Option<Arc<dyn ThroughputCoordinator>>,
    ) -> Result<Self, ComponentError> {
        if !samples_per_minute.is_finite() || samples_per_minute <= 0.0 {
            return Err(ComponentError::failure(
                "constant throughput must be positive and finite",
            ));
        }
        let seconds = 60.0 / samples_per_minute;
        let period = Duration::try_from_secs_f64(seconds)
            .map_err(|_| ComponentError::resource_limit("constant throughput period"))?;
        if period.is_zero() {
            return Err(ComponentError::resource_limit(
                "constant throughput period precision",
            ));
        }
        Ok(Self {
            period,
            mode,
            state: Arc::new(Mutex::new(ThroughputState::default())),
            coordinator,
        })
    }

    /// Returns the target period.
    #[must_use]
    pub const fn period(&self) -> Duration {
        self.period
    }

    /// Returns the configured calculation mode.
    #[must_use]
    pub const fn mode(&self) -> ConstantThroughputMode {
        self.mode
    }
}

impl Timer for ConstantThroughputTimer {
    fn delay<'a>(&'a self, context: &'a mut SampleContext<'_>) -> ComponentFuture<'a, Duration> {
        let now = context.execution().capabilities().clock().now().monotonic;
        if self.mode != ConstantThroughputMode::ThisThreadOnly {
            let Some(coordinator) = self.coordinator.as_ref() else {
                return ready(Err(ComponentError::unsupported(
                    "constant throughput mode requires a run coordinator",
                )));
            };
            let thread = context.execution().thread();
            if thread.name().len() > MAX_TIMER_NAME_BYTES
                || thread
                    .group()
                    .is_some_and(|group| group.len() > MAX_TIMER_NAME_BYTES)
            {
                return ready(Err(ComponentError::resource_limit(
                    "throughput participant identity",
                )));
            }
            let request = ThroughputRequest {
                mode: self.mode,
                period: self.period,
                now,
                thread_name: thread.name().to_owned(),
                thread_group: thread.group().map(str::to_owned),
                thread_number: thread.number(),
                lifecycle_id: context.execution().lifecycle_id(),
            };
            return ready(
                coordinator
                    .reserve(&request)
                    .and_then(|delay| duration_nanos(delay).map(|_| delay)),
            );
        }

        let mut state = lock(&self.state);
        let delay = state.next.map_or(Duration::ZERO, |next| {
            next.checked_sub(now).map_or(Duration::ZERO, |delay| delay)
        });
        let base = state.next.map_or(now, |next| next.max(now));
        let next = match base.checked_add(self.period) {
            Some(next) => next,
            None => {
                return ready(Err(ComponentError::resource_limit(
                    "throughput target time",
                )));
            }
        };
        state.next = Some(next);
        ready(Ok(delay))
    }

    // Constant Throughput Timer is not a ModifiableTimer in JMeter 5.6.3.
    fn is_modifiable(&self) -> bool {
        false
    }
}

impl TimerFactory for ConstantThroughputTimer {
    fn create(&self) -> Arc<dyn Timer> {
        Arc::new(Self {
            period: self.period,
            mode: self.mode,
            state: Arc::new(Mutex::new(ThroughputState::default())),
            coordinator: self.coordinator.clone(),
        })
    }
}

#[derive(Debug)]
struct PreciseState {
    origin: Option<Duration>,
    window: u64,
    fraction: f64,
    arrivals: VecDeque<Duration>,
}

impl Default for PreciseState {
    fn default() -> Self {
        Self {
            origin: None,
            window: 0,
            fraction: 0.0,
            arrivals: VecDeque::new(),
        }
    }
}

/// A precise-throughput timer using fixed-count Poisson arrivals per period.
///
/// Conditional on a period's exact arrival count, sorted independent uniform
/// offsets are the Poisson-process arrival distribution.  This gives JMeter's
/// precise count guarantee without an unbounded arrival queue or a statistical
/// approximation of the configured target.
#[derive(Debug)]
pub struct PreciseThroughputTimer {
    throughput: f64,
    throughput_period: Duration,
    duration: Option<Duration>,
    batch_size: u64,
    batch_thread_delay: Duration,
    exact_limit: u64,
    allowed_throughput_surplus: f64,
    random_seed: Option<u64>,
    state: Arc<Mutex<PreciseState>>,
}

impl Clone for PreciseThroughputTimer {
    fn clone(&self) -> Self {
        // Arrival queues and fractional carry are per-user state.  A clone
        // therefore keeps configuration/capabilities but starts a fresh
        // schedule rather than sharing a serialized cursor.
        Self {
            throughput: self.throughput,
            throughput_period: self.throughput_period,
            duration: self.duration,
            batch_size: self.batch_size,
            batch_thread_delay: self.batch_thread_delay,
            exact_limit: self.exact_limit,
            allowed_throughput_surplus: self.allowed_throughput_surplus,
            random_seed: self.random_seed,
            state: Arc::new(Mutex::new(PreciseState::default())),
        }
    }
}

impl PreciseThroughputTimer {
    /// Creates a precise timer with no finite end (throughput per period).
    pub fn new(throughput: f64, throughput_period: Duration) -> Result<Self, ComponentError> {
        Self::with_duration(throughput, throughput_period, None)
    }

    /// Creates a precise timer with an optional finite active duration.
    pub fn with_duration(
        throughput: f64,
        throughput_period: Duration,
        duration: Option<Duration>,
    ) -> Result<Self, ComponentError> {
        let period_nanos = duration_nanos(throughput_period)?;
        if !throughput.is_finite() || throughput <= 0.0 {
            return Err(ComponentError::failure(
                "precise throughput must be positive and finite",
            ));
        }
        if period_nanos == 0 {
            return Err(ComponentError::failure(
                "precise throughput period must be positive",
            ));
        }
        if throughput.ceil() > MAX_PRECISE_ARRIVALS_PER_WINDOW as f64 {
            return Err(ComponentError::resource_limit(
                "precise throughput arrivals per period",
            ));
        }
        Ok(Self {
            throughput,
            throughput_period,
            duration,
            batch_size: 1,
            batch_thread_delay: Duration::ZERO,
            exact_limit: 0,
            allowed_throughput_surplus: 1.0,
            random_seed: None,
            state: Arc::new(Mutex::new(PreciseState::default())),
        })
    }

    /// Alias for [`Self::with_duration`].
    pub fn new_with_duration(
        throughput: f64,
        throughput_period: Duration,
        duration: Option<Duration>,
    ) -> Result<Self, ComponentError> {
        Self::with_duration(throughput, throughput_period, duration)
    }

    /// Sets the bounded batch size used by the JMeter timer.
    pub fn with_batch_size(mut self, batch_size: u64) -> Result<Self, ComponentError> {
        if batch_size == 0 || batch_size > MAX_PRECISE_ARRIVALS_PER_WINDOW {
            return Err(ComponentError::failure("precise throughput batch size"));
        }
        self.batch_size = batch_size;
        Ok(self)
    }

    /// Adds the configured inter-batch thread delay.
    #[must_use]
    pub const fn with_batch_thread_delay(mut self, delay: Duration) -> Self {
        self.batch_thread_delay = delay;
        self
    }

    /// Retains JMeter's deprecated exact-limit setting with a finite bound.
    /// The exact-count scheduler keeps its own hard bound and never uses this
    /// legacy setting to permit an unbounded queue.
    pub fn with_exact_limit(mut self, exact_limit: u64) -> Result<Self, ComponentError> {
        if exact_limit > MAX_PRECISE_ARRIVALS_PER_WINDOW {
            return Err(ComponentError::resource_limit(
                "precise throughput exact-limit",
            ));
        }
        self.exact_limit = exact_limit;
        Ok(self)
    }

    /// Retains JMeter's deprecated allowed-surplus setting.  The exact-count
    /// scheduler does not loosen its configured per-period target because of
    /// this legacy compatibility field.
    pub fn with_allowed_throughput_surplus(
        mut self,
        allowed_throughput_surplus: f64,
    ) -> Result<Self, ComponentError> {
        if !allowed_throughput_surplus.is_finite() || allowed_throughput_surplus < 0.0 {
            return Err(ComponentError::failure(
                "precise throughput allowed surplus",
            ));
        }
        self.allowed_throughput_surplus = allowed_throughput_surplus;
        Ok(self)
    }

    /// Records the explicit JMeter random seed metadata.  Random values still
    /// come only from the injected runtime [`crate::RandomSource`].
    #[must_use]
    pub const fn with_random_seed(mut self, seed: u64) -> Self {
        self.random_seed = Some(seed);
        self
    }

    /// Returns the configured throughput per period.
    #[must_use]
    pub const fn throughput(&self) -> f64 {
        self.throughput
    }

    /// Returns the configured period.
    #[must_use]
    pub const fn throughput_period(&self) -> Duration {
        self.throughput_period
    }

    /// Returns the optional finite active duration.
    #[must_use]
    pub const fn duration(&self) -> Option<Duration> {
        self.duration
    }

    /// Returns the optional recorded seed.
    #[must_use]
    pub const fn random_seed(&self) -> Option<u64> {
        self.random_seed
    }

    /// Returns JMeter's deprecated exact-limit setting.
    #[must_use]
    pub const fn exact_limit(&self) -> u64 {
        self.exact_limit
    }

    /// Returns JMeter's deprecated allowed-surplus setting.
    #[must_use]
    pub const fn allowed_throughput_surplus(&self) -> f64 {
        self.allowed_throughput_surplus
    }

    fn window_start(
        origin: Duration,
        period: Duration,
        window: u64,
    ) -> Result<Duration, ComponentError> {
        let origin_nanos = u128::from(duration_nanos(origin)?);
        let period_nanos = u128::from(duration_nanos(period)?);
        let offset = period_nanos
            .checked_mul(u128::from(window))
            .ok_or_else(|| ComponentError::resource_limit("precise throughput window"))?;
        duration_from_nanos(
            origin_nanos
                .checked_add(offset)
                .ok_or_else(|| ComponentError::resource_limit("precise throughput window"))?,
        )
    }

    fn arrivals_for_window(&self, state: &mut PreciseState) -> Result<u64, ComponentError> {
        let base = self.throughput.floor() as u64;
        let fraction = self.throughput - base as f64;
        state.fraction += fraction;
        let extra = if state.fraction >= 1.0 {
            state.fraction -= 1.0;
            1
        } else {
            0
        };
        let count = base
            .checked_add(extra)
            .ok_or_else(|| ComponentError::resource_limit("precise throughput arrivals"))?;
        if count > MAX_PRECISE_ARRIVALS_PER_WINDOW {
            return Err(ComponentError::resource_limit(
                "precise throughput arrivals per period",
            ));
        }
        Ok(count)
    }

    fn fill_next_window(
        &self,
        state: &mut PreciseState,
        source: &dyn crate::RandomSource,
    ) -> Result<(), ComponentError> {
        let origin = state
            .origin
            .ok_or_else(|| ComponentError::failure("precise throughput origin missing"))?;
        let start = Self::window_start(origin, self.throughput_period, state.window)?;
        if let Some(duration) = self.duration {
            let end = origin
                .checked_add(duration)
                .ok_or_else(|| ComponentError::resource_limit("precise throughput end"))?;
            if start >= end {
                state.arrivals.clear();
                state.window = state
                    .window
                    .checked_add(1)
                    .ok_or_else(|| ComponentError::resource_limit("precise throughput window"))?;
                return Ok(());
            }
        }

        let count = self.arrivals_for_window(state)?;
        if count == 0 {
            state.window = state
                .window
                .checked_add(1)
                .ok_or_else(|| ComponentError::resource_limit("precise throughput window"))?;
            return Ok(());
        }
        let period_nanos = duration_nanos(self.throughput_period)?;
        let mut offsets = Vec::with_capacity(count as usize);
        for _ in 0..count {
            offsets.push(uniform_below(source, period_nanos)?);
        }
        offsets.sort_unstable();
        for (index, offset) in offsets.into_iter().enumerate() {
            let mut offset = duration_from_nanos(u128::from(offset))?;
            if self.batch_size > 0 && index > 0 && (index as u64).is_multiple_of(self.batch_size) {
                offset = offset
                    .checked_add(self.batch_thread_delay)
                    .ok_or_else(|| ComponentError::resource_limit("precise batch delay"))?;
            }
            let target = start
                .checked_add(offset)
                .ok_or_else(|| ComponentError::resource_limit("precise throughput arrival"))?;
            if let Some(duration) = self.duration {
                let end = origin
                    .checked_add(duration)
                    .ok_or_else(|| ComponentError::resource_limit("precise throughput end"))?;
                if target >= end {
                    continue;
                }
            }
            if state.arrivals.len() >= MAX_PRECISE_ARRIVALS_PER_WINDOW as usize {
                return Err(ComponentError::resource_limit(
                    "precise throughput arrival queue",
                ));
            }
            state.arrivals.push_back(target);
        }
        state.window = state
            .window
            .checked_add(1)
            .ok_or_else(|| ComponentError::resource_limit("precise throughput window"))?;
        Ok(())
    }
}

impl Timer for PreciseThroughputTimer {
    fn delay<'a>(&'a self, context: &'a mut SampleContext<'_>) -> ComponentFuture<'a, Duration> {
        let now = context.execution().capabilities().clock().now().monotonic;
        let source = context.execution().capabilities().random();
        let mut state = lock(&self.state);
        let result = (|| {
            if state.origin.is_none() {
                state.origin = Some(now);
            }
            for _ in 0..MAX_PRECISE_WINDOW_ADVANCES {
                if let Some(target) = state.arrivals.pop_front() {
                    return Ok(target
                        .checked_sub(now)
                        .map_or(Duration::ZERO, |delay| delay));
                }
                let before = state.window;
                self.fill_next_window(&mut state, source)?;
                if state.arrivals.is_empty() && state.window == before {
                    return Err(ComponentError::resource_limit(
                        "precise throughput window state",
                    ));
                }
                if let Some(duration) = self.duration {
                    let origin = state
                        .origin
                        .ok_or_else(|| ComponentError::failure("precise throughput origin"))?;
                    let end = origin
                        .checked_add(duration)
                        .ok_or_else(|| ComponentError::resource_limit("precise throughput end"))?;
                    if state.window > 0
                        && Self::window_start(origin, self.throughput_period, state.window)? >= end
                        && state.arrivals.is_empty()
                    {
                        return Ok(Duration::ZERO);
                    }
                }
            }
            Err(ComponentError::resource_limit(
                "precise throughput window-advance bound",
            ))
        })();
        ready(result)
    }

    // Precise Throughput Timer is not a ModifiableTimer in JMeter 5.6.3.
    fn is_modifiable(&self) -> bool {
        false
    }
}

impl TimerFactory for PreciseThroughputTimer {
    fn create(&self) -> Arc<dyn Timer> {
        Arc::new(Self {
            throughput: self.throughput,
            throughput_period: self.throughput_period,
            duration: self.duration,
            batch_size: self.batch_size,
            batch_thread_delay: self.batch_thread_delay,
            exact_limit: self.exact_limit,
            allowed_throughput_surplus: self.allowed_throughput_surplus,
            random_seed: self.random_seed,
            state: Arc::new(Mutex::new(PreciseState::default())),
        })
    }
}

/// The configured participant-count policy for a synchronizing barrier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SynchronizingGroupSize {
    /// Resolve the barrier size from the current thread group at admission.
    ///
    /// This is the representation of the upstream `groupSize=0` sentinel; it
    /// is never an explicit zero-participant barrier.
    CurrentThreadGroup,
    /// Use this explicit, validated number of participants.
    Explicit(NonZeroUsize),
}

impl SynchronizingGroupSize {
    fn from_configured(value: usize) -> Result<Self, ComponentError> {
        match NonZeroUsize::new(value) {
            None => Ok(Self::CurrentThreadGroup),
            Some(value) if value.get() <= MAX_PRECISE_ARRIVALS_PER_WINDOW as usize => {
                Ok(Self::Explicit(value))
            }
            Some(_) => Err(ComponentError::resource_limit(
                "synchronizing timer group size",
            )),
        }
    }

    const fn explicit(self) -> Option<NonZeroUsize> {
        match self {
            Self::CurrentThreadGroup => None,
            Self::Explicit(value) => Some(value),
        }
    }

    const fn is_current_thread_group(self) -> bool {
        matches!(self, Self::CurrentThreadGroup)
    }
}

/// A request submitted to an executor-neutral synchronizing barrier.
#[derive(Clone, Debug)]
pub struct SynchronizingRequest {
    name: String,
    group_size: SynchronizingGroupSize,
    timeout: Duration,
    now: Duration,
    participant: String,
    thread_name: String,
    thread_group: Option<String>,
    thread_number: Option<u64>,
    lifecycle_id: Option<u64>,
}

impl SynchronizingRequest {
    /// Returns the barrier name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the explicit group size, or `None` for the upstream
    /// `groupSize=0` current-thread-group sentinel. In the latter mode the
    /// coordinator must derive a participant count from a valid request group.
    #[must_use]
    pub const fn group_size(&self) -> Option<NonZeroUsize> {
        self.group_size.explicit()
    }

    /// Returns whether the upstream `groupSize=0` sentinel selected
    /// current-thread-group resolution.
    #[must_use]
    pub const fn uses_current_thread_group(&self) -> bool {
        self.group_size.is_current_thread_group()
    }

    /// Returns the configured timeout, where zero means no timeout.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Returns the injected monotonic arrival time.
    #[must_use]
    pub const fn now(&self) -> Duration {
        self.now
    }

    /// Returns the stable virtual-user participant identity.
    #[must_use]
    pub fn participant(&self) -> &str {
        &self.participant
    }

    /// Returns the virtual-user thread name.
    #[must_use]
    pub fn thread_name(&self) -> &str {
        &self.thread_name
    }

    /// Returns the optional current thread group.
    #[must_use]
    pub fn thread_group(&self) -> Option<&str> {
        self.thread_group.as_deref()
    }

    /// Returns the optional numeric thread index.
    #[must_use]
    pub const fn thread_number(&self) -> Option<u64> {
        self.thread_number
    }

    /// Returns the lifecycle identity, when supplied by the engine.
    #[must_use]
    pub const fn lifecycle_id(&self) -> Option<u64> {
        self.lifecycle_id
    }
}

/// Result of a synchronizing barrier arrival.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SynchronizingOutcome {
    /// The configured group arrived and was released.
    Released,
    /// The timeout elapsed before the configured group arrived.
    TimedOut,
}

/// External run capability for a synchronizing timer.
pub trait SynchronizingCoordinator: Send + Sync {
    /// Polls one arrival.  A pending result must arrange to wake the supplied
    /// waker when another participant arrives or the barrier expires.
    fn poll_arrival(
        &self,
        request: &SynchronizingRequest,
        waker: &Waker,
    ) -> Poll<Result<SynchronizingOutcome, ComponentError>>;

    /// Notifies the coordinator that an in-flight arrival was cancelled.
    fn cancel(&self, _request: &SynchronizingRequest) {}

    /// Releases coordinator-side reservation state after a completed arrival.
    fn complete(&self, _request: &SynchronizingRequest, _outcome: SynchronizingOutcome) {}
}

/// A synchronizing barrier timer.
#[derive(Clone)]
pub struct SynchronizingTimer {
    name: String,
    group_size: SynchronizingGroupSize,
    timeout: Duration,
    coordinator: Option<Arc<dyn SynchronizingCoordinator>>,
}

impl fmt::Debug for SynchronizingTimer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SynchronizingTimer")
            .field("name", &self.name)
            .field("group_size", &self.group_size)
            .field("timeout", &self.timeout)
            .field("has_coordinator", &self.coordinator.is_some())
            .finish()
    }
}

impl SynchronizingTimer {
    /// Creates an explicitly external synchronization timer with a
    /// one-participant barrier and no coordinator.
    ///
    /// This constructor does not select the upstream `groupSize=0`
    /// current-thread-group sentinel; use [`Self::with_group`] with zero when
    /// that policy is required.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            group_size: SynchronizingGroupSize::Explicit(NonZeroUsize::MIN),
            timeout: Duration::ZERO,
            coordinator: None,
        }
    }

    /// Creates a barrier with the upstream group-size setting and timeout.
    ///
    /// A raw `group_size` of zero is the upstream `groupSize=0` sentinel: the
    /// coordinator must resolve a non-empty current thread group and its
    /// participant count at admission. It is not accepted as an explicit
    /// zero-participant barrier.
    pub fn with_group(
        name: impl Into<String>,
        group_size: usize,
        timeout: Duration,
    ) -> Result<Self, ComponentError> {
        let name = name.into();
        let group_size = SynchronizingGroupSize::from_configured(group_size)?;
        validate_sync_config(&name, group_size, timeout)?;
        Ok(Self {
            name,
            group_size,
            timeout,
            coordinator: None,
        })
    }

    /// Creates a barrier backed by an executor-neutral run coordinator.
    ///
    /// As with [`Self::with_group`], a raw `group_size` of zero selects the
    /// upstream current-thread-group sentinel and requires a valid group
    /// identity in each [`SampleContext`] at admission.
    pub fn with_coordinator(
        name: impl Into<String>,
        group_size: usize,
        timeout: Duration,
        coordinator: Arc<dyn SynchronizingCoordinator>,
    ) -> Result<Self, ComponentError> {
        let mut timer = Self::with_group(name, group_size, timeout)?;
        timer.coordinator = Some(coordinator);
        Ok(timer)
    }

    /// Alias for [`Self::with_coordinator`].
    pub fn new_with_coordinator(
        name: impl Into<String>,
        group_size: usize,
        timeout: Duration,
        coordinator: Arc<dyn SynchronizingCoordinator>,
    ) -> Result<Self, ComponentError> {
        Self::with_coordinator(name, group_size, timeout, coordinator)
    }

    /// Returns the barrier name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the explicit group size, or `None` for the upstream
    /// `groupSize=0` current-thread-group sentinel.
    #[must_use]
    pub const fn group_size(&self) -> Option<NonZeroUsize> {
        self.group_size.explicit()
    }

    /// Returns whether the upstream `groupSize=0` sentinel selected
    /// current-thread-group resolution.
    #[must_use]
    pub const fn uses_current_thread_group(&self) -> bool {
        self.group_size.is_current_thread_group()
    }

    /// Returns the timeout, where zero means no timeout.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }
}

fn validate_sync_config(
    name: &str,
    group_size: SynchronizingGroupSize,
    _timeout: Duration,
) -> Result<(), ComponentError> {
    if name.is_empty() || name.len() > MAX_TIMER_NAME_BYTES {
        return Err(ComponentError::failure("invalid synchronizing timer name"));
    }
    if let SynchronizingGroupSize::Explicit(value) = group_size
        && value.get() > MAX_PRECISE_ARRIVALS_PER_WINDOW as usize
    {
        return Err(ComponentError::resource_limit(
            "synchronizing timer group size",
        ));
    }
    Ok(())
}

fn sync_request(
    timer: &SynchronizingTimer,
    context: &SampleContext<'_>,
) -> Result<SynchronizingRequest, ComponentError> {
    validate_sync_config(&timer.name, timer.group_size, timer.timeout)?;
    let execution = context.execution();
    let now = execution.capabilities().clock().now().monotonic;
    let thread = execution.thread();
    let thread_group = thread.group();
    if timer.group_size.is_current_thread_group()
        && !thread_group.is_some_and(|group| !group.is_empty())
    {
        return Err(ComponentError::unsupported(
            "synchronizing timer current-thread-group mode requires a non-empty thread-group identity for participant-count resolution",
        ));
    }
    let group = thread_group.unwrap_or("");
    let participant_parts = group
        .len()
        .checked_add(thread.name().len())
        .and_then(|length| length.checked_add(64))
        .ok_or_else(|| ComponentError::resource_limit("synchronizing participant identity"))?;
    if participant_parts > MAX_TIMER_NAME_BYTES {
        return Err(ComponentError::resource_limit(
            "synchronizing participant identity",
        ));
    }
    let participant = format!(
        "{}:{}:{}:{}",
        group,
        thread.name(),
        thread.number().map_or(0, |number| number),
        execution
            .lifecycle_id()
            .map_or(0, |lifecycle_id| lifecycle_id)
    );
    if participant.len() > MAX_TIMER_NAME_BYTES {
        return Err(ComponentError::resource_limit(
            "synchronizing participant identity",
        ));
    }
    Ok(SynchronizingRequest {
        name: timer.name.clone(),
        group_size: timer.group_size,
        timeout: timer.timeout,
        now,
        participant,
        thread_name: thread.name().to_owned(),
        thread_group: thread_group.map(str::to_owned),
        thread_number: thread.number(),
        lifecycle_id: execution.lifecycle_id(),
    })
}

struct SynchronizingDelayFuture<'a, 'ctx> {
    coordinator: Arc<dyn SynchronizingCoordinator>,
    request: SynchronizingRequest,
    context: &'a mut SampleContext<'ctx>,
    registration: Option<crate::WakeRegistration>,
    completed: bool,
}

impl SynchronizingDelayFuture<'_, '_> {
    fn cancel_registration(&mut self) {
        if let Some(registration) = self.registration.take() {
            let _ = self.context.execution().scheduler().cancel(&registration);
        }
    }

    fn finish(
        &mut self,
        result: Result<Duration, ComponentError>,
        outcome: Option<SynchronizingOutcome>,
    ) -> Poll<Result<Duration, ComponentError>> {
        self.cancel_registration();
        if let Some(outcome) = outcome {
            self.coordinator.complete(&self.request, outcome);
        } else {
            self.coordinator.cancel(&self.request);
        }
        self.completed = true;
        Poll::Ready(result)
    }
}

impl Future for SynchronizingDelayFuture<'_, '_> {
    type Output = Result<Duration, ComponentError>;

    fn poll(self: Pin<&mut Self>, poll_context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let signal = this.context.execution().control_signal();
        if signal.is_stop() {
            return this.finish(Err(ComponentError::Control(signal)), None);
        }
        // The scheduler wake belongs to this barrier's timeout
        // registration. Let a coordinator that observed the final
        // participant win a same-tick race; otherwise a pending coordinator
        // has reached the exact timeout outcome.
        let timeout_wake = this.context.execution().cancellation_token().take_wake();
        match this
            .coordinator
            .poll_arrival(&this.request, poll_context.waker())
        {
            Poll::Ready(Ok(outcome)) => this.finish(Ok(Duration::ZERO), Some(outcome)),
            Poll::Ready(Err(error)) => this.finish(Err(error), None),
            Poll::Pending => {
                if timeout_wake {
                    return this.finish(Ok(Duration::ZERO), Some(SynchronizingOutcome::TimedOut));
                }
                // Cancellation is an independent wake source from the
                // barrier coordinator and must release an in-flight arrival.
                this.context
                    .execution()
                    .cancellation_token()
                    .register_waker(poll_context.waker());
                if this.registration.is_none() && !this.request.timeout.is_zero() {
                    match this.context.execution().register_wake_after(
                        this.request.timeout,
                        stable_timer_key(&this.request.name),
                    ) {
                        Ok(registration) => this.registration = Some(registration),
                        Err(SchedulerError::Unsupported(_)) => {
                            // A coordinator may own its own wake source.  It
                            // remains responsible for waking the supplied
                            // waker when no scheduler capability is present.
                        }
                        Err(SchedulerError::Capacity { .. })
                        | Err(SchedulerError::DeadlineOverflow { .. }) => {
                            return this.finish(
                                Err(ComponentError::resource_limit(
                                    "synchronizing timer timeout wake",
                                )),
                                None,
                            );
                        }
                        Err(_) => {
                            return this.finish(
                                Err(ComponentError::failure(
                                    "synchronizing timer wake registration",
                                )),
                                None,
                            );
                        }
                    }
                }
                Poll::Pending
            }
        }
    }
}

impl Drop for SynchronizingDelayFuture<'_, '_> {
    fn drop(&mut self) {
        if !self.completed {
            self.cancel_registration();
            self.coordinator.cancel(&self.request);
            self.completed = true;
        }
    }
}

fn stable_timer_key(value: &str) -> u64 {
    // FNV-1a is only a scheduler ordering key; it is not used for random
    // choice or security.  Wrapping hash arithmetic cannot affect duration
    // correctness.
    value
        .bytes()
        .fold(14_695_981_039_346_656_037u64, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(1_099_511_628_211)
        })
}

impl Timer for SynchronizingTimer {
    fn delay<'a>(&'a self, context: &'a mut SampleContext<'_>) -> ComponentFuture<'a, Duration> {
        let Some(coordinator) = self.coordinator.as_ref() else {
            return ready(Err(ComponentError::unsupported(
                "synchronizing timer requires an external barrier capability",
            )));
        };
        let request = match sync_request(self, context) {
            Ok(request) => request,
            Err(error) => return ready(Err(error)),
        };
        Box::pin(SynchronizingDelayFuture {
            coordinator: Arc::clone(coordinator),
            request,
            context,
            registration: None,
            completed: false,
        })
    }

    // Synchronizing Timer is not a ModifiableTimer in JMeter 5.6.3.
    fn is_modifiable(&self) -> bool {
        false
    }
}

impl TimerFactory for SynchronizingTimer {
    fn create(&self) -> Arc<dyn Timer> {
        Arc::new(self.clone())
    }
}

/// A timer backed by a JVM or scripting/plugin adapter not present in the
/// active profile.
#[derive(Clone, Debug)]
pub struct UnsupportedTimer {
    capability_id: String,
}

impl UnsupportedTimer {
    /// Creates an explicit unsupported timer adapter.
    #[must_use]
    pub fn new(capability_id: impl Into<String>) -> Self {
        Self {
            capability_id: capability_id.into(),
        }
    }
}

impl Timer for UnsupportedTimer {
    fn delay<'a>(&'a self, _context: &'a mut SampleContext<'_>) -> ComponentFuture<'a, Duration> {
        ready(Err(ComponentError::unsupported(self.capability_id.clone())))
    }

    fn is_modifiable(&self) -> bool {
        false
    }
}

impl TimerFactory for UnsupportedTimer {
    fn create(&self) -> Arc<dyn Timer> {
        Arc::new(self.clone())
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "timer invariant tests use explicit deterministic setup"
)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct SequenceRandom {
        values: Arc<Mutex<VecDeque<u64>>>,
    }

    impl SequenceRandom {
        fn new(values: impl IntoIterator<Item = u64>) -> Self {
            Self {
                values: Arc::new(Mutex::new(values.into_iter().collect())),
            }
        }

        fn remaining(&self) -> usize {
            lock(&self.values).len()
        }
    }

    impl crate::RandomSource for SequenceRandom {
        fn next_u64(&self) -> Result<u64, crate::CapabilityError> {
            lock(&self.values)
                .pop_front()
                .ok_or_else(|| crate::CapabilityError::failure("random sequence exhausted"))
        }

        fn clone_for_user(&self) -> Arc<dyn crate::RandomSource> {
            Arc::new(Self::new(lock(&self.values).iter().copied()))
        }
    }

    #[test]
    fn uniform_range_is_half_open_and_rejection_is_bounded() {
        let source = SequenceRandom::new([u64::MAX, 0, 10, 7]);
        assert_eq!(uniform_below(&source, 5).expect("sample"), 0);
        assert_eq!(uniform_below(&source, 5).expect("sample"), 0);
        assert_eq!(
            jmeter_uniform_duration(
                &source,
                Duration::from_millis(10),
                Duration::from_millis(10),
            )
            .expect("zero range"),
            Duration::from_millis(10)
        );
        let adversarial = SequenceRandom::new(vec![0; MAX_RANDOM_ATTEMPTS]);
        assert!(matches!(
            uniform_below(&adversarial, (1u64 << 63) + 1),
            Err(ComponentError::ResourceLimit(_))
        ));
    }

    #[test]
    fn uniform_rejects_reversed_intervals() {
        let source = SequenceRandom::new([0]);
        assert!(matches!(
            jmeter_uniform_duration(&source, Duration::from_millis(2), Duration::from_millis(1)),
            Err(ComponentError::Failure(_))
        ));
    }

    #[test]
    fn uniform_uses_float_milliseconds_then_java_long_truncation() {
        let source = SequenceRandom::new([1u64 << 63]);
        assert_eq!(
            jmeter_uniform_duration(&source, Duration::from_millis(7), Duration::from_millis(10),)
                .expect("uniform delay"),
            Duration::from_millis(8)
        );

        let source = SequenceRandom::new([0]);
        assert_eq!(
            jmeter_uniform_duration(&source, Duration::from_millis(7), Duration::from_millis(10),)
                .expect("zero variate"),
            Duration::from_millis(7)
        );
    }

    #[test]
    fn jmeter_random_delay_applies_abs_before_fractional_truncation() {
        assert_eq!(
            jmeter_delay_from_millis(-8.75).expect("negative raw delay"),
            Duration::from_millis(8)
        );
        assert_eq!(
            jmeter_gaussian_duration(-1.25, Duration::ZERO, Duration::from_millis(2))
                .expect("negative gaussian delay"),
            Duration::from_millis(2)
        );

        let source = SequenceRandom::new([1u64 << 62, 1u64 << 63]);
        let mut spare = None;
        let normal = gaussian_normal(&source, &mut spare).expect("negative normal");
        assert!(normal < 0.0);
        assert_eq!(
            jmeter_gaussian_duration(normal, Duration::ZERO, Duration::from_millis(10))
                .expect("negative gaussian raw delay"),
            Duration::from_millis(16)
        );
    }

    #[test]
    fn jmeter_random_delay_preserves_java_nonfinite_and_runtime_bounds() {
        assert_eq!(java_long_from_double(f64::NAN), 0, "Java casts NaN to zero");
        assert_eq!(
            java_long_from_double(f64::INFINITY),
            i64::MAX,
            "Java saturates an overflowing positive double"
        );
        assert_eq!(
            jmeter_delay_from_millis(f64::NAN).expect("NaN delay"),
            Duration::ZERO
        );
        assert!(matches!(
            jmeter_delay_from_millis(f64::INFINITY),
            Err(ComponentError::ResourceLimit(_))
        ));
        assert!(matches!(
            jmeter_delay_from_millis(f64::MAX),
            Err(ComponentError::ResourceLimit(_))
        ));
    }

    #[test]
    fn gaussian_spare_value_is_consumed_without_another_random_draw() {
        let source = SequenceRandom::new([u64::MAX / 2, u64::MAX / 4]);
        let mut spare = None;
        let first = gaussian_normal(&source, &mut spare).expect("first normal");
        assert!(first.is_finite());
        assert!(spare.is_some());
        assert_eq!(source.remaining(), 0);
        let second = gaussian_normal(&source, &mut spare).expect("cached normal");
        assert!(second.is_finite());
        assert_eq!(source.remaining(), 0);

        // The timer factory starts a fresh cache for the next virtual user;
        // Gaussian timers are modifiable in JMeter 5.6.3.
        let timer = GaussianRandomTimer::new(Duration::from_millis(10), Duration::ZERO);
        let clone = <GaussianRandomTimer as TimerFactory>::create(&timer);
        assert!(clone.is_modifiable());
    }

    #[test]
    fn gaussian_rejection_is_bounded_and_jmeter_negative_delay_is_absolute() {
        let source = SequenceRandom::new(vec![0; MAX_RANDOM_ATTEMPTS * 2]);
        let mut spare = None;
        assert!(matches!(
            gaussian_normal(&source, &mut spare),
            Err(ComponentError::ResourceLimit(_))
        ));
        assert_eq!(jmeter_delay_from_millis(-1.0), Ok(Duration::from_millis(1)));
    }

    #[test]
    fn poisson_always_keeps_its_base_and_has_checked_parameters() {
        let timer = PoissonRandomTimer::with_base_and_range(
            Duration::from_millis(20),
            Duration::from_millis(5),
        );
        assert_eq!(
            timer.parameters(),
            (Duration::from_millis(20), Duration::from_millis(5))
        );
        assert_eq!(
            PoissonRandomTimer::new(Duration::from_millis(5))
                .parameters()
                .0,
            Duration::ZERO
        );
        let source = SequenceRandom::new([0, u64::MAX]);
        assert_eq!(
            poisson_delay(&source, Duration::from_millis(20), Duration::from_millis(5))
                .expect("zero variate"),
            Duration::from_millis(20)
        );
        assert!(
            poisson_delay(&source, Duration::from_millis(20), Duration::from_millis(5))
                .expect("upper variate")
                >= Duration::from_millis(20)
        );
        assert!(matches!(
            poisson_delay(
                &SequenceRandom::new([u64::MAX]),
                Duration::MAX,
                Duration::from_nanos(1)
            ),
            Err(ComponentError::ResourceLimit(_))
        ));
    }

    #[test]
    fn constant_throughput_starts_immediately_and_then_uses_checked_period() {
        let timer = ConstantThroughputTimer::new(6_000.0).expect("valid rate");
        assert_eq!(timer.period(), Duration::from_millis(10));
        assert_eq!(timer.mode(), ConstantThroughputMode::ThisThreadOnly);
        assert!(!timer.is_modifiable());
        let mut state = lock(&timer.state);
        let now = Duration::ZERO;
        let first = state.next.map_or(Duration::ZERO, |next| {
            next.checked_sub(now).unwrap_or_default()
        });
        let base = state.next.map_or(now, |next| next.max(now));
        state.next = base.checked_add(timer.period());
        assert_eq!(first, Duration::ZERO);
        assert_eq!(state.next, Some(Duration::from_millis(10)));
    }

    #[test]
    fn stateful_timer_clones_start_independent_user_schedules() {
        let throughput = ConstantThroughputTimer::new(60.0).expect("valid rate");
        lock(&throughput.state).next = Some(Duration::from_secs(1));
        let throughput_clone = throughput.clone();
        assert_eq!(lock(&throughput_clone.state).next, None);

        let precise =
            PreciseThroughputTimer::new(1.0, Duration::from_secs(1)).expect("valid precise timer");
        lock(&precise.state).origin = Some(Duration::from_secs(2));
        let precise_clone = precise.clone();
        assert_eq!(lock(&precise_clone.state).origin, None);
    }

    #[test]
    fn non_local_throughput_modes_require_typed_run_capability() {
        let timer = ConstantThroughputTimer::new_with_mode(
            60.0,
            ConstantThroughputMode::AllActiveThreadsShared,
            None,
        )
        .expect("valid rate");
        assert_eq!(timer.mode(), ConstantThroughputMode::AllActiveThreadsShared);
        assert_eq!(
            ConstantThroughputMode::AllActiveThreads_Shared,
            ConstantThroughputMode::AllActiveThreadsShared
        );
        assert_eq!(timer.mode().jmeter_name(), "AllActiveThreads_Shared");
        assert!(timer.coordinator.is_none());
        assert!(matches!(
            ConstantThroughputTimer::new(f64::MAX),
            Err(ComponentError::ResourceLimit(_))
        ));
    }

    #[test]
    fn precise_timer_rejects_unbounded_arrival_configuration() {
        assert!(matches!(
            PreciseThroughputTimer::new(65_537.0, Duration::from_secs(1)),
            Err(ComponentError::ResourceLimit(_))
        ));
        assert!(matches!(
            PreciseThroughputTimer::new(1.0, Duration::ZERO),
            Err(ComponentError::Failure(_))
        ));
    }

    #[test]
    fn precise_timer_generates_exact_bounded_count_per_window() {
        let timer =
            PreciseThroughputTimer::new(4.0, Duration::from_secs(1)).expect("valid precise timer");
        let mut state = PreciseState {
            origin: Some(Duration::ZERO),
            ..PreciseState::default()
        };
        // Zero is rejected for this non-power-of-two nanosecond range by
        // rejection sampling.  Max is always in the accepted tail while
        // remaining deterministic.
        let source = SequenceRandom::new([u64::MAX; 4]);
        timer
            .fill_next_window(&mut state, &source)
            .expect("window generation");
        assert_eq!(state.arrivals.len(), 4);
        assert_eq!(state.window, 1);
        assert!(
            state
                .arrivals
                .iter()
                .all(|target| *target < Duration::from_secs(1))
        );
        assert!(
            state
                .arrivals
                .iter()
                .zip(state.arrivals.iter().skip(1))
                .all(|(left, right)| left <= right)
        );

        let finite = PreciseThroughputTimer::with_duration(
            4.0,
            Duration::from_secs(1),
            Some(Duration::from_millis(500)),
        )
        .expect("finite timer");
        let mut finite_state = PreciseState {
            origin: Some(Duration::ZERO),
            ..PreciseState::default()
        };
        finite
            .fill_next_window(&mut finite_state, &SequenceRandom::new([u64::MAX; 4]))
            .expect("finite window generation");
        assert!(finite_state.arrivals.is_empty());
    }

    #[derive(Default)]
    struct RecordingThroughput {
        requests: Mutex<Vec<ThroughputRequest>>,
    }

    impl ThroughputCoordinator for RecordingThroughput {
        fn reserve(&self, request: &ThroughputRequest) -> Result<Duration, ComponentError> {
            lock(&self.requests).push(request.clone());
            Ok(Duration::from_millis(3))
        }
    }

    #[test]
    fn throughput_request_keeps_explicit_mode_and_user_scope() {
        let coordinator = RecordingThroughput::default();
        let request = ThroughputRequest {
            mode: ConstantThroughputMode::AllActiveThreadsInCurrentThreadGroupShared,
            period: Duration::from_millis(20),
            now: Duration::from_millis(7),
            thread_name: "group 1-2".to_owned(),
            thread_group: Some("group".to_owned()),
            thread_number: Some(2),
            lifecycle_id: Some(9),
        };
        assert_eq!(
            coordinator.reserve(&request).expect("reservation"),
            Duration::from_millis(3)
        );
        let recorded = lock(&coordinator.requests);
        assert_eq!(
            recorded[0].mode(),
            ConstantThroughputMode::AllActiveThreadsInCurrentThreadGroupShared
        );
        assert_eq!(recorded[0].thread_group(), Some("group"));
        assert_eq!(recorded[0].thread_number(), Some(2));
        assert_eq!(recorded[0].lifecycle_id(), Some(9));
    }

    struct ImmediateBarrier {
        outcome: SynchronizingOutcome,
        completed: Mutex<Vec<SynchronizingOutcome>>,
    }

    impl SynchronizingCoordinator for ImmediateBarrier {
        fn poll_arrival(
            &self,
            _request: &SynchronizingRequest,
            _waker: &Waker,
        ) -> Poll<Result<SynchronizingOutcome, ComponentError>> {
            Poll::Ready(Ok(self.outcome))
        }

        fn complete(&self, _request: &SynchronizingRequest, outcome: SynchronizingOutcome) {
            lock(&self.completed).push(outcome);
        }
    }

    #[test]
    fn synchronizing_capability_distinguishes_release_and_timeout() {
        let barrier = ImmediateBarrier {
            outcome: SynchronizingOutcome::TimedOut,
            completed: Mutex::new(Vec::new()),
        };
        let request = SynchronizingRequest {
            name: "gate".to_owned(),
            group_size: SynchronizingGroupSize::Explicit(
                NonZeroUsize::new(2).expect("literal two is non-zero"),
            ),
            timeout: Duration::from_millis(80),
            now: Duration::ZERO,
            participant: "group:user:1".to_owned(),
            thread_name: "user".to_owned(),
            thread_group: Some("group".to_owned()),
            thread_number: Some(1),
            lifecycle_id: Some(1),
        };
        let waker = Waker::noop();
        assert_eq!(
            barrier.poll_arrival(&request, waker),
            Poll::Ready(Ok(SynchronizingOutcome::TimedOut))
        );
        barrier.complete(&request, SynchronizingOutcome::TimedOut);
        assert_eq!(
            lock(&barrier.completed).as_slice(),
            &[SynchronizingOutcome::TimedOut]
        );
        assert_eq!(request.thread_name(), "user");
        assert_eq!(request.thread_number(), Some(1));
        assert_eq!(request.group_size(), NonZeroUsize::new(2));
        assert!(!request.uses_current_thread_group());
    }

    #[derive(Default)]
    struct GroupSizeRecorder {
        observed: Mutex<Vec<Option<NonZeroUsize>>>,
        groups: Mutex<Vec<Option<String>>>,
    }

    impl SynchronizingCoordinator for GroupSizeRecorder {
        fn poll_arrival(
            &self,
            request: &SynchronizingRequest,
            _waker: &Waker,
        ) -> Poll<Result<SynchronizingOutcome, ComponentError>> {
            lock(&self.observed).push(request.group_size());
            lock(&self.groups).push(request.thread_group().map(str::to_owned));
            Poll::Ready(Ok(SynchronizingOutcome::Released))
        }
    }

    struct NoopSampler;

    impl crate::Sampler for NoopSampler {
        fn sample<'a>(
            &'a self,
            _context: &'a mut crate::SampleContext<'_>,
        ) -> crate::ComponentFuture<'a, crate::SamplerOutput> {
            Box::pin(future::ready(Ok(crate::SamplerOutput::no_result())))
        }
    }

    fn poll_ready<F: Future>(future: F) -> F::Output {
        let waker = Waker::noop();
        let mut poll_context = Context::from_waker(waker);
        let mut future = Box::pin(future);
        match future.as_mut().poll(&mut poll_context) {
            Poll::Ready(value) => value,
            Poll::Pending => unreachable!("deterministic timer pipeline unexpectedly pending"),
        }
    }

    fn run_synchronizing_timer(
        timer: SynchronizingTimer,
        thread: jmeter_rs_results::ThreadIdentity,
    ) -> Result<crate::ExecutionReport, crate::PipelineError> {
        let package =
            crate::SamplePackage::new(jmeter_rs_model::NodeId::new(1), Arc::new(NoopSampler))
                .with_timers(vec![Arc::new(timer)]);
        let mut context = crate::ExecutionContext::new();
        context.set_thread(thread);
        poll_ready(package.execute(&mut context))
    }

    #[test]
    fn synchronizing_current_group_fails_closed_without_context_group() {
        for thread in [
            jmeter_rs_results::ThreadIdentity::new("thread"),
            jmeter_rs_results::ThreadIdentity::with_group("thread", Some(String::new()), Some(1)),
        ] {
            let recorder = Arc::new(GroupSizeRecorder::default());
            let timer =
                SynchronizingTimer::with_coordinator("gate", 0, Duration::ZERO, recorder.clone())
                    .expect("zero means current thread group");
            let error = run_synchronizing_timer(timer, thread)
                .expect_err("missing thread group must reject current-group admission");
            assert!(matches!(
                error,
                crate::PipelineError::Timer {
                    source: ComponentError::Unsupported(message),
                    ..
                } if message == "synchronizing timer current-thread-group mode requires a non-empty thread-group identity for participant-count resolution"
            ));
            assert!(lock(&recorder.observed).is_empty());
            assert!(lock(&recorder.groups).is_empty());
        }
    }

    #[test]
    fn synchronizing_current_group_uses_context_group_for_admission() {
        let recorder = Arc::new(GroupSizeRecorder::default());
        let timer =
            SynchronizingTimer::with_coordinator("gate", 0, Duration::ZERO, recorder.clone())
                .expect("zero means current thread group");
        let report = run_synchronizing_timer(
            timer,
            jmeter_rs_results::ThreadIdentity::with_group(
                "thread",
                Some("group".to_owned()),
                Some(1),
            ),
        )
        .expect("valid current group admits");
        assert_eq!(report.timer_delay, Duration::ZERO);
        assert_eq!(lock(&recorder.observed).as_slice(), &[None]);
        assert_eq!(
            lock(&recorder.groups).as_slice(),
            &[Some("group".to_owned())]
        );
    }

    #[test]
    fn synchronizing_explicit_group_does_not_require_context_group() {
        let recorder = Arc::new(GroupSizeRecorder::default());
        let timer =
            SynchronizingTimer::with_coordinator("gate", 2, Duration::ZERO, recorder.clone())
                .expect("explicit group size");
        run_synchronizing_timer(timer, jmeter_rs_results::ThreadIdentity::new("thread"))
            .expect("explicit group admission");
        assert_eq!(lock(&recorder.observed).as_slice(), &[NonZeroUsize::new(2)]);
        assert_eq!(lock(&recorder.groups).as_slice(), &[None]);
    }

    #[test]
    fn synchronizing_zero_group_size_is_deferred_for_coordinator_admission() {
        let recorder = Arc::new(GroupSizeRecorder::default());
        let timer =
            SynchronizingTimer::with_coordinator("gate", 0, Duration::ZERO, recorder.clone())
                .expect("zero means current thread group");
        assert_eq!(timer.group_size(), None);
        assert!(timer.uses_current_thread_group());

        let request = SynchronizingRequest {
            name: timer.name.clone(),
            group_size: timer.group_size,
            timeout: timer.timeout,
            now: Duration::ZERO,
            participant: "group:user:1".to_owned(),
            thread_name: "user".to_owned(),
            thread_group: Some("group".to_owned()),
            thread_number: Some(1),
            lifecycle_id: Some(1),
        };
        assert_eq!(
            recorder.poll_arrival(&request, Waker::noop()),
            Poll::Ready(Ok(SynchronizingOutcome::Released))
        );
        assert_eq!(lock(&recorder.observed).as_slice(), &[None]);
        assert_eq!(
            lock(&recorder.groups).as_slice(),
            &[Some("group".to_owned())]
        );
        assert!(request.uses_current_thread_group());
    }

    #[test]
    fn synchronizing_timer_validates_group_and_timeout_shape() {
        assert!(SynchronizingTimer::with_group("gate", 2, Duration::from_millis(80)).is_ok());
        assert!(SynchronizingTimer::with_group("gate", 0, Duration::ZERO).is_ok());
        assert!(SynchronizingTimer::with_group("", 2, Duration::ZERO).is_err());
        assert!(!SynchronizingTimer::new("gate").is_modifiable());
    }

    #[test]
    fn synchronizing_outcomes_are_explicit_not_silent_serialization() {
        assert_eq!(
            SynchronizingOutcome::Released,
            SynchronizingOutcome::Released
        );
        assert_ne!(
            SynchronizingOutcome::Released,
            SynchronizingOutcome::TimedOut
        );
        assert!(SynchronizingTimer::new("external").coordinator.is_none());
    }

    #[test]
    fn timer_factor_participation_matches_modifiable_contract() {
        assert!(!ConstantTimer::new(Duration::from_millis(1)).is_modifiable());
        assert!(ConstantTimer::modifiable(Duration::from_millis(1)).is_modifiable());
        assert!(!ConstantTimer::fixed(Duration::from_millis(1)).is_modifiable());
        assert!(UniformRandomTimer::new(Duration::ZERO, Duration::from_nanos(1)).is_modifiable());
        assert!(
            !ConstantThroughputTimer::new(60.0)
                .expect("valid rate")
                .is_modifiable()
        );
        assert!(
            !PreciseThroughputTimer::new(1.0, Duration::from_secs(1))
                .expect("valid precise timer")
                .is_modifiable()
        );
    }
}
