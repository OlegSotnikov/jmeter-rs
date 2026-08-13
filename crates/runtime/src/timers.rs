// SPDX-License-Identifier: Apache-2.0
//! Deterministic built-in timer adapters.
//!
//! A timer only computes the delay for one sampler invocation.  Sleeping is
//! owned by the execution pipeline's injected [`crate::Sleeper`].  This
//! module consequently has no dependency on an executor, a host clock, or a
//! host random-number generator.  Timers which need run-wide state expose a
//! small, typed capability seam instead of silently pretending that a
//! per-user copy is a serialized run-wide implementation.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::future::{self, Future};
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use crate::{
    ComponentError, ComponentFuture, Deadline, MonotonicInstant, SampleContext, SchedulerError,
    Timer, TimerFactory,
};

// Keep random retry loops and generated queues bounded. Duration arithmetic
// itself uses the full representation supported by `std::time::Duration` and
// fails explicitly on overflow.
const MAX_RANDOM_ATTEMPTS: usize = 128;
const MAX_POISSON_LAMBDA: i64 = i32::MAX as i64;
const MAX_PRECISE_ARRIVALS_PER_WINDOW: u64 = 65_536;
const MAX_PRECISE_SCOPES: usize = 65_536;
const MAX_SYNCHRONIZING_PARTICIPANTS: usize = 65_536;
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
    let seconds = value / 1_000_000_000;
    let nanos = u32::try_from(value % 1_000_000_000)
        .map_err(|_| ComponentError::resource_limit("timer duration nanoseconds"))?;
    let seconds = u64::try_from(seconds)
        .map_err(|_| ComponentError::resource_limit("timer duration seconds"))?;
    Ok(Duration::new(seconds, nanos))
}

fn duration_nanos(value: Duration) -> u128 {
    value.as_nanos()
}

fn next_random(source: &dyn crate::RandomSource) -> Result<u64, ComponentError> {
    source.next_u64().map_err(ComponentError::from)
}

/// Samples one value uniformly from `[0, upper)` without modulo bias.
///
/// `RandomSource` supplies the complete 64-bit domain.  Rejection sampling
/// uses the largest multiple of `upper` contained in that domain and has a
/// finite attempt bound so a broken/adversarial source cannot loop forever.
#[cfg(test)]
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
/// delay expressed in milliseconds, then converts it to a `Duration` without
/// introducing a smaller runtime lifetime ceiling.
fn jmeter_delay_from_millis(raw: f64) -> Result<Duration, ComponentError> {
    let millis = java_long_from_double(raw.abs());
    if millis <= 0 {
        return Ok(Duration::ZERO);
    }
    Ok(Duration::from_millis(millis as u64))
}

/// Implements `Math.round` for the non-negative doubles used by JMeter's
/// timer properties. Java rounds to the nearest integral value (ties toward
/// positive infinity) and saturates at `Long.MAX_VALUE`; Rust's float casts
/// have different edge behavior, so keep the conversion explicit.
fn java_round_nonnegative(value: f64) -> Result<i64, ComponentError> {
    if value.is_nan() || value <= 0.0 {
        return Ok(0);
    }
    const LONG_BOUND: f64 = 9_223_372_036_854_775_808.0; // 2^63
    if value >= LONG_BOUND - 0.5 {
        return Ok(i64::MAX);
    }
    let rounded = (value + 0.5).floor();
    i64::try_from(rounded as u64)
        .map_err(|_| ComponentError::resource_limit("timer rounded integer"))
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

/// A JMeter Poisson random timer.
///
/// The one-argument constructor is retained for compatibility with the
/// original runtime API and represents a zero-base Poisson range.  [`Self::with_base_and_range`]
/// corresponds to JMeter's base delay plus `RandomTimer.range` form used by
/// the 5.6.3 fixtures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PoissonRandomTimer {
    base: Duration,
    range: Duration,
}

impl PoissonRandomTimer {
    /// Creates a Poisson timer whose range is `mean` milliseconds.
    #[must_use]
    pub const fn new(mean: Duration) -> Self {
        Self {
            base: Duration::ZERO,
            range: mean,
        }
    }

    /// Creates a JMeter-style timer with a base delay and Poisson range.
    #[must_use]
    pub const fn with_base_and_range(base: Duration, range: Duration) -> Self {
        Self { base, range }
    }

    /// Returns the configured Poisson range.
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

fn poisson_log_factorial(value: i64) -> f64 {
    if value <= 1 {
        0.0
    } else if value <= 254 {
        (2..=value).map(|item| (item as f64).ln()).sum()
    } else {
        let x = value as f64 + 1.0;
        (x - 0.5) * x.ln() - x + 0.5 * (2.0 * std::f64::consts::PI).ln() + 1.0 / (12.0 * x)
    }
}

/// Generates the integer Poisson variate used by JMeter's
/// `PoissonRandomTimer`. The low-lambda path is Knuth's product method; the
/// high-lambda path is the rejection method used by the pinned source. The
/// attempt bound prevents a hostile injected random source from looping
/// forever.
fn poisson_random(source: &dyn crate::RandomSource, lambda: i64) -> Result<i64, ComponentError> {
    if !(0..=MAX_POISSON_LAMBDA).contains(&lambda) {
        return Err(ComponentError::resource_limit("Poisson timer lambda"));
    }
    if lambda <= 30 {
        let limit = (-(lambda as f64)).exp();
        let mut probability = 1.0;
        for count in 1..=MAX_RANDOM_ATTEMPTS {
            probability *= random_unit_half_open(next_random(source)?);
            if probability <= limit {
                return i64::try_from(count - 1)
                    .map_err(|_| ComponentError::resource_limit("Poisson timer variate"));
            }
        }
        return Err(ComponentError::resource_limit(
            "Poisson timer rejection-attempt bound",
        ));
    }

    let lambda_float = lambda as f64;
    let c = 0.767 - 3.36 / lambda_float;
    let beta = std::f64::consts::PI / (3.0 * lambda_float).sqrt();
    let alpha = beta * lambda_float;
    let k = c.ln() - lambda_float - beta.ln();
    for _ in 0..MAX_RANDOM_ATTEMPTS {
        let unit = random_unit_half_open(next_random(source)?);
        if unit <= 0.0 {
            continue;
        }
        let x = (alpha - ((1.0 - unit) / unit).ln()) / beta;
        if !x.is_finite() {
            continue;
        }
        let n = (x + 0.5).floor() as i64;
        if n < 0 {
            continue;
        }
        let second = random_unit_half_open(next_random(source)?);
        let y = alpha - beta * x;
        let denominator = (1.0 + y.exp()).powi(2);
        let lhs = y + (second / denominator).ln();
        let rhs = k + (n as f64) * lambda_float.ln() - poisson_log_factorial(n);
        if lhs <= rhs {
            return Ok(n);
        }
    }
    Err(ComponentError::resource_limit(
        "Poisson timer rejection-attempt bound",
    ))
}

fn poisson_delay(
    source: &dyn crate::RandomSource,
    base: Duration,
    range: Duration,
) -> Result<Duration, ComponentError> {
    // JMeter rounds RandomTimer.range in milliseconds before narrowing it to
    // an int for randomPoisson(). Values outside that domain are rejected.
    let rounded_range = java_round_nonnegative(duration_as_millis(range))?;
    if rounded_range > MAX_POISSON_LAMBDA {
        return Err(ComponentError::resource_limit("Poisson timer lambda"));
    }
    let variate = poisson_random(source, rounded_range)?;
    let base_millis = java_long_from_double(duration_as_millis(base));
    let total_millis = base_millis
        .checked_add(variate)
        .ok_or_else(|| ComponentError::resource_limit("Poisson timer duration"))?;
    if total_millis < 0 {
        return Err(ComponentError::resource_limit("Poisson timer duration"));
    }
    Ok(Duration::from_millis(total_millis as u64))
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
    /// Creates a request for a run-scoped throughput coordinator.
    ///
    /// The request is intentionally a value object: validation of participant
    /// identity and duration bounds belongs to the selected coordinator so a
    /// custom adapter can apply its own profile limits.
    #[must_use]
    pub fn new(
        mode: ConstantThroughputMode,
        period: Duration,
        now: Duration,
        thread_name: impl Into<String>,
        thread_group: Option<String>,
        thread_number: Option<u64>,
        lifecycle_id: Option<u64>,
    ) -> Self {
        Self {
            mode,
            period,
            now,
            thread_name: thread_name.into(),
            thread_group,
            thread_number,
            lifecycle_id,
        }
    }

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
        // JMeter computes Math.round(60000 / rate), in whole milliseconds.
        // Preserve that observable precision instead of retaining fractional
        // nanoseconds in the native representation.
        let milliseconds = java_round_nonnegative(60_000.0 / samples_per_minute)?;
        let period = Duration::from_millis(
            u64::try_from(milliseconds)
                .map_err(|_| ComponentError::resource_limit("constant throughput period"))?,
        );
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
                || thread.name().chars().any(char::is_control)
                || thread.group().is_some_and(|group| {
                    group.len() > MAX_TIMER_NAME_BYTES || group.chars().any(char::is_control)
                })
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
            return ready(coordinator.reserve(&request));
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

#[derive(Debug, Default)]
struct PreciseState {
    origin: Option<Duration>,
    window: u64,
    arrivals: VecDeque<Duration>,
}

/// Scope key for JMeter's static precise-throughput event producer.
///
/// JMeter keys the producer by thread-group identity and resets it for a new
/// test run. A standalone context without a group has no such shared owner,
/// so retain the virtual-user identity as a deterministic fallback.
#[derive(Clone, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
struct PreciseScopeKey {
    run_id: String,
    thread_group: Option<String>,
    thread_name: Option<String>,
    thread_number: Option<u64>,
    lifecycle_id: Option<u64>,
}

#[derive(Debug, Default)]
struct PreciseStateStore {
    scopes: BTreeMap<PreciseScopeKey, PreciseState>,
}

/// A precise-throughput timer using JMeter's fixed-count Poisson arrival
/// generator. The upstream timer shares one generated event stream for a
/// thread group; clones therefore retain the same bounded state cursor.
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
    state: Arc<Mutex<PreciseStateStore>>,
}

impl Clone for PreciseThroughputTimer {
    fn clone(&self) -> Self {
        // JMeter's EventProducer is shared by all timer clones in one thread
        // group. Keep that cursor shared; unlike most per-user components,
        // this timer intentionally coordinates arrivals across users.
        Self {
            throughput: self.throughput,
            throughput_period: self.throughput_period,
            duration: self.duration,
            batch_size: self.batch_size,
            batch_thread_delay: self.batch_thread_delay,
            exact_limit: self.exact_limit,
            allowed_throughput_surplus: self.allowed_throughput_surplus,
            random_seed: self.random_seed,
            state: Arc::clone(&self.state),
        }
    }
}

impl PreciseThroughputTimer {
    /// Creates a precise timer with no finite end (throughput per period).
    pub fn new(throughput: f64, throughput_period: Duration) -> Result<Self, ComponentError> {
        Self::with_duration(throughput, throughput_period, None)
    }

    /// Creates a precise timer with an optional event-generation duration.
    pub fn with_duration(
        throughput: f64,
        throughput_period: Duration,
        duration: Option<Duration>,
    ) -> Result<Self, ComponentError> {
        let period_nanos = duration_nanos(throughput_period);
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
        if duration.is_some_and(|value| value.is_zero()) {
            return Err(ComponentError::failure(
                "precise throughput generation duration must be positive",
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
            state: Arc::new(Mutex::new(PreciseStateStore::default())),
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

    /// Retains the configured inter-batch delay property. JMeter 5.6.3's
    /// `ConstantPoissonProcessGenerator` stores this value but does not apply
    /// it when producing events.
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

    /// Returns the optional event-generation duration.
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
        let origin_nanos = duration_nanos(origin);
        let period_nanos = duration_nanos(period);
        let offset = period_nanos
            .checked_mul(u128::from(window))
            .ok_or_else(|| ComponentError::resource_limit("precise throughput window"))?;
        duration_from_nanos(
            origin_nanos
                .checked_add(offset)
                .ok_or_else(|| ComponentError::resource_limit("precise throughput window"))?,
        )
    }

    fn arrivals_for_window(&self, _state: &mut PreciseState) -> Result<u64, ComponentError> {
        // ConstantPoissonProcessGenerator creates ceil(rate * duration)
        // events for every generation window. There is no fractional carry
        // between windows; each window independently has the exact rounded
        // count promised by the configured generation duration.
        let generation_duration = self.generation_duration();
        let count_float = self.throughput * generation_duration.as_secs_f64()
            / self.throughput_period.as_secs_f64();
        if !count_float.is_finite() || count_float <= 0.0 {
            return Err(ComponentError::resource_limit(
                "precise throughput arrivals per period",
            ));
        }
        // The upstream generator divides the rate by batchSize before taking
        // ceil, then returns each generated offset batchSize times.
        let generated = (count_float / self.batch_size as f64).ceil();
        if generated > MAX_PRECISE_ARRIVALS_PER_WINDOW as f64
            || generated * self.batch_size as f64 > MAX_PRECISE_ARRIVALS_PER_WINDOW as f64
        {
            return Err(ComponentError::resource_limit(
                "precise throughput arrivals per period",
            ));
        }
        Ok(generated as u64)
    }

    fn generation_duration(&self) -> Duration {
        // JMeter's `duration` controls how far each generated event block
        // extends. If omitted by the Rust convenience constructor, one
        // throughput period is the bounded equivalent.
        self.duration.unwrap_or(self.throughput_period)
    }

    fn scope_key(context: &SampleContext<'_>) -> Result<PreciseScopeKey, ComponentError> {
        let execution = context.execution();
        let run_id = execution.run().as_str();
        let thread = execution.thread();
        let thread_group = thread.group();
        if thread.name().is_empty() || thread_group.is_some_and(str::is_empty) {
            return Err(ComponentError::resource_limit(
                "precise throughput scope identity",
            ));
        }
        let exceeds_limit =
            |value: &str| value.len() > MAX_TIMER_NAME_BYTES || value.chars().any(char::is_control);
        if exceeds_limit(run_id)
            || thread_group.is_some_and(exceeds_limit)
            || (thread_group.is_none() && exceeds_limit(thread.name()))
        {
            return Err(ComponentError::resource_limit(
                "precise throughput scope identity",
            ));
        }
        Ok(PreciseScopeKey {
            run_id: run_id.to_owned(),
            thread_group: thread_group.map(str::to_owned),
            thread_name: thread_group.is_none().then(|| thread.name().to_owned()),
            thread_number: thread_group.is_none().then(|| thread.number()).flatten(),
            lifecycle_id: thread_group
                .is_none()
                .then(|| execution.lifecycle_id())
                .flatten(),
        })
    }

    fn state_for_scope(
        store: &mut PreciseStateStore,
        key: PreciseScopeKey,
    ) -> Result<&mut PreciseState, ComponentError> {
        if !store.scopes.contains_key(&key) && store.scopes.len() >= MAX_PRECISE_SCOPES {
            return Err(ComponentError::resource_limit(
                "precise throughput scope registry",
            ));
        }
        Ok(store.scopes.entry(key).or_default())
    }

    fn fill_next_window(
        &self,
        state: &mut PreciseState,
        source: &dyn crate::RandomSource,
    ) -> Result<(), ComponentError> {
        let origin = state
            .origin
            .ok_or_else(|| ComponentError::failure("precise throughput origin missing"))?;
        let generation_duration = self.generation_duration();
        let start = Self::window_start(origin, generation_duration, state.window)?;

        let count = self.arrivals_for_window(state)?;
        if count == 0 {
            state.window = state
                .window
                .checked_add(1)
                .ok_or_else(|| ComponentError::resource_limit("precise throughput window"))?;
            return Ok(());
        }
        let generation_millis = duration_as_millis(generation_duration);
        if !generation_millis.is_finite() || generation_millis >= 9_223_372_036_854_775_808.0 {
            return Err(ComponentError::resource_limit(
                "precise throughput generation duration",
            ));
        }
        let mut offsets = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let random = random_unit_half_open(next_random(source)?);
            let offset = java_long_from_double(random * generation_millis);
            let offset = u64::try_from(offset)
                .map_err(|_| ComponentError::resource_limit("precise throughput arrival"))?;
            offsets.push(offset);
        }
        offsets.sort_unstable();
        let batch_size = usize::try_from(self.batch_size)
            .map_err(|_| ComponentError::resource_limit("precise throughput batch size"))?;
        for offset in offsets {
            // `ConstantPoissonProcessGenerator` samples in seconds and the
            // timer narrows `nextEvent * 1000` to a Java long. The generated
            // integer therefore denotes milliseconds, not nanoseconds.
            let offset = Duration::from_millis(offset);
            let target = start
                .checked_add(offset)
                .ok_or_else(|| ComponentError::resource_limit("precise throughput arrival"))?;
            for _ in 0..batch_size {
                if state.arrivals.len() >= MAX_PRECISE_ARRIVALS_PER_WINDOW as usize {
                    return Err(ComponentError::resource_limit(
                        "precise throughput arrival queue",
                    ));
                }
                state.arrivals.push_back(target);
            }
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
        let key = match Self::scope_key(context) {
            Ok(key) => key,
            Err(error) => return ready(Err(error)),
        };
        let mut store = lock(&self.state);
        let state = match Self::state_for_scope(&mut store, key) {
            Ok(state) => state,
            Err(error) => return ready(Err(error)),
        };
        let result = (|| {
            if state.origin.is_none() {
                state.origin = Some(now);
            }
            if let Some(target) = state.arrivals.pop_front() {
                return Ok(target
                    .checked_sub(now)
                    .map_or(Duration::ZERO, |delay| delay));
            }
            self.fill_next_window(state, source)?;
            state
                .arrivals
                .pop_front()
                .map(|target| {
                    target
                        .checked_sub(now)
                        .map_or(Duration::ZERO, |delay| delay)
                })
                .ok_or_else(|| ComponentError::resource_limit("precise throughput window state"))
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
            state: Arc::clone(&self.state),
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
            Some(value) if value.get() <= MAX_SYNCHRONIZING_PARTICIPANTS => {
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
    /// Creates a request for a synchronizing coordinator.
    ///
    /// A zero `group_size` retains JMeter's `groupSize=0` sentinel and asks
    /// the coordinator to resolve the participant count from the current
    /// thread group. It is never treated as a zero-participant barrier.
    #[allow(
        clippy::too_many_arguments,
        reason = "preserve the public compatibility constructor's explicit request fields"
    )]
    pub fn new(
        name: impl Into<String>,
        group_size: usize,
        timeout: Duration,
        participant: impl Into<String>,
        thread_name: impl Into<String>,
        thread_group: Option<String>,
        thread_number: Option<u64>,
        lifecycle_id: Option<u64>,
        now: Duration,
    ) -> Result<Self, ComponentError> {
        let name = name.into();
        let participant = participant.into();
        let thread_name = thread_name.into();
        if participant.is_empty()
            || thread_name.is_empty()
            || participant.len() > MAX_TIMER_NAME_BYTES
            || thread_name.len() > MAX_TIMER_NAME_BYTES
            || thread_name.chars().any(char::is_control)
            || participant.chars().any(char::is_control)
            || thread_group.as_deref().is_some_and(|group| {
                group.len() > MAX_TIMER_NAME_BYTES || group.chars().any(char::is_control)
            })
        {
            return Err(ComponentError::resource_limit(
                "synchronizing participant identity",
            ));
        }
        if group_size == 0
            && !thread_group
                .as_deref()
                .is_some_and(|group| !group.is_empty())
        {
            return Err(ComponentError::unsupported(
                "synchronizing timer current-thread-group mode requires a non-empty thread-group identity for participant-count resolution",
            ));
        }
        if now.checked_add(timeout).is_none() {
            return Err(ComponentError::resource_limit(
                "synchronizing timer timeout deadline",
            ));
        }
        let group_size = SynchronizingGroupSize::from_configured(group_size)?;
        validate_sync_config(&name, group_size, timeout)?;
        Ok(Self {
            name,
            group_size,
            timeout,
            now,
            participant,
            thread_name,
            thread_group,
            thread_number,
            lifecycle_id,
        })
    }

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
    if name.is_empty() || name.len() > MAX_TIMER_NAME_BYTES || name.chars().any(char::is_control) {
        return Err(ComponentError::failure("invalid synchronizing timer name"));
    }
    if let SynchronizingGroupSize::Explicit(value) = group_size
        && value.get() > MAX_SYNCHRONIZING_PARTICIPANTS
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
    if now.checked_add(timer.timeout).is_none() {
        return Err(ComponentError::resource_limit(
            "synchronizing timer timeout deadline",
        ));
    }
    let thread = execution.thread();
    let thread_group = thread.group();
    if timer.group_size.is_current_thread_group()
        && !thread_group.is_some_and(|group| !group.is_empty())
    {
        return Err(ComponentError::unsupported(
            "synchronizing timer current-thread-group mode requires a non-empty thread-group identity for participant-count resolution",
        ));
    }
    if thread.name().chars().any(char::is_control)
        || thread_group.is_some_and(|group| group.chars().any(char::is_control))
    {
        return Err(ComponentError::resource_limit(
            "synchronizing participant identity",
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
    let configured_group_size = timer.group_size.explicit().map_or(0, NonZeroUsize::get);
    SynchronizingRequest::new(
        timer.name.clone(),
        configured_group_size,
        timer.timeout,
        participant,
        thread.name().to_owned(),
        thread_group.map(str::to_owned),
        thread.number(),
        execution.lifecycle_id(),
        now,
    )
}

struct SynchronizingDelayFuture<'a, 'ctx> {
    coordinator: Arc<dyn SynchronizingCoordinator>,
    request: SynchronizingRequest,
    context: &'a mut SampleContext<'ctx>,
    registration: Option<crate::WakeRegistration>,
    completed: bool,
}

impl SynchronizingDelayFuture<'_, '_> {
    fn cancel_registration(&mut self) -> Result<(), SchedulerError> {
        if let Some(registration) = self.registration.take() {
            self.context
                .execution()
                .scheduler()
                .cancel(&registration)
                .map(|_| ())
        } else {
            Ok(())
        }
    }

    fn finish(
        &mut self,
        result: Result<Duration, ComponentError>,
        outcome: Option<SynchronizingOutcome>,
    ) -> Poll<Result<Duration, ComponentError>> {
        let cancellation = self
            .cancel_registration()
            .err()
            .map(scheduler_component_error);
        if let Some(outcome) = outcome {
            self.coordinator.complete(&self.request, outcome);
        } else {
            self.coordinator.cancel(&self.request);
        }
        self.completed = true;
        let result = match cancellation {
            None => result,
            Some(error) => match result {
                Ok(_) => Err(error),
                Err(primary) => Err(ComponentError::Combined {
                    primary: Box::new(primary),
                    secondary: Box::new(error),
                }),
            },
        };
        Poll::Ready(result)
    }
}

fn scheduler_component_error(error: SchedulerError) -> ComponentError {
    match error {
        SchedulerError::Capacity { .. }
        | SchedulerError::DeadlineOverflow { .. }
        | SchedulerError::WakeIdOverflow => {
            ComponentError::resource_limit("synchronizing timer wake cancellation")
        }
        SchedulerError::Unsupported(message) => ComponentError::unsupported(message),
        other => ComponentError::failure(format!("synchronizing timer wake cancellation: {other}")),
    }
}

impl Future for SynchronizingDelayFuture<'_, '_> {
    type Output = Result<Duration, ComponentError>;

    fn poll(self: Pin<&mut Self>, poll_context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let signal = this.context.execution().control_signal();
        if signal != crate::ControlSignal::Continue {
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
                    let deadline = match Deadline::after(
                        MonotonicInstant::from_duration(this.request.now),
                        this.request.timeout,
                    ) {
                        Some(deadline) => deadline,
                        None => {
                            return this.finish(
                                Err(ComponentError::resource_limit(
                                    "synchronizing timer timeout deadline",
                                )),
                                None,
                            );
                        }
                    };
                    match this.context.execution().scheduler().register_wake(
                        deadline,
                        stable_timer_key(&this.request.name),
                        this.context.execution().cancellation_token(),
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
            let _ = self.cancel_registration();
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
    fn duration_conversion_uses_the_full_std_duration_domain() {
        let maximum = Duration::MAX;
        assert_eq!(
            duration_from_nanos(maximum.as_nanos()).expect("maximum duration"),
            maximum
        );
        assert!(matches!(
            duration_from_nanos(maximum.as_nanos().checked_add(1).expect("u128 room")),
            Err(ComponentError::ResourceLimit(_))
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
    fn java_round_matches_constant_throughput_millisecond_precision() {
        assert_eq!(java_round_nonnegative(1_000.4).expect("round"), 1_000);
        assert_eq!(java_round_nonnegative(1_000.5).expect("round tie"), 1_001);
        assert_eq!(
            ConstantThroughputTimer::new(3_600.0)
                .expect("rate")
                .period(),
            Duration::from_millis(17)
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
        assert_eq!(
            jmeter_delay_from_millis(f64::INFINITY).expect("Java long saturation"),
            Duration::from_millis(i64::MAX as u64)
        );
        assert_eq!(
            jmeter_delay_from_millis(f64::MAX).expect("Java long saturation"),
            Duration::from_millis(i64::MAX as u64)
        );
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
        let source = SequenceRandom::new([0, u64::MAX, 0]);
        assert_eq!(
            poisson_delay(&source, Duration::from_millis(20), Duration::from_millis(5))
                .expect("zero variate"),
            Duration::from_millis(20)
        );
        assert_eq!(
            poisson_delay(&source, Duration::from_millis(20), Duration::from_millis(5))
                .expect("one-count variate"),
            Duration::from_millis(21)
        );
        assert!(matches!(
            poisson_delay(
                &SequenceRandom::new([u64::MAX, 0]),
                Duration::from_millis(i64::MAX as u64),
                Duration::from_millis(1)
            ),
            Err(ComponentError::ResourceLimit(_))
        ));
    }

    #[test]
    fn poisson_high_lambda_uses_log_lambda_rejection_bound() {
        assert_eq!(
            poisson_random(&SequenceRandom::new([1u64 << 63, 1u64 << 63]), 31)
                .expect("accepted high-lambda sample"),
            31
        );
        assert_eq!(
            poisson_delay(
                &SequenceRandom::new([1u64 << 63, 1u64 << 63]),
                Duration::ZERO,
                Duration::from_millis(31),
            )
            .expect("high-lambda timer sample"),
            Duration::from_millis(31)
        );
        assert!(matches!(
            poisson_random(
                &SequenceRandom::new(vec![u64::MAX; MAX_RANDOM_ATTEMPTS * 2]),
                31,
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
        lock(&precise.state)
            .scopes
            .entry(PreciseScopeKey::default())
            .or_default()
            .origin = Some(Duration::from_secs(2));
        let precise_clone = precise.clone();
        assert_eq!(
            lock(&precise_clone.state)
                .scopes
                .get(&PreciseScopeKey::default())
                .and_then(|state| state.origin),
            Some(Duration::from_secs(2))
        );
    }

    #[test]
    fn precise_scope_state_is_shared_by_group_but_separate_between_groups() {
        let mut store = PreciseStateStore::default();
        let group_a_user_1 = PreciseScopeKey {
            run_id: "run".to_owned(),
            thread_group: Some("group-a".to_owned()),
            thread_name: None,
            thread_number: None,
            lifecycle_id: None,
        };
        let group_a_user_2 = PreciseScopeKey {
            run_id: "run".to_owned(),
            thread_group: Some("group-a".to_owned()),
            thread_name: None,
            thread_number: None,
            lifecycle_id: None,
        };
        let group_b = PreciseScopeKey {
            thread_group: Some("group-b".to_owned()),
            ..group_a_user_1.clone()
        };
        PreciseThroughputTimer::state_for_scope(&mut store, group_a_user_1)
            .expect("group scope")
            .origin = Some(Duration::from_secs(1));
        assert_eq!(
            PreciseThroughputTimer::state_for_scope(&mut store, group_a_user_2)
                .expect("same group scope")
                .origin,
            Some(Duration::from_secs(1))
        );
        assert_eq!(
            PreciseThroughputTimer::state_for_scope(&mut store, group_b)
                .expect("different group scope")
                .origin,
            None
        );
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
        let timer = PreciseThroughputTimer::new(65_537.0, Duration::from_secs(1))
            .expect("constructor defers count bound to generation");
        let mut state = PreciseState {
            origin: Some(Duration::ZERO),
            ..PreciseState::default()
        };
        assert!(matches!(
            timer.fill_next_window(&mut state, &SequenceRandom::new([])),
            Err(ComponentError::ResourceLimit(_))
        ));
        assert!(matches!(
            PreciseThroughputTimer::new(1.0, Duration::ZERO),
            Err(ComponentError::Failure(_))
        ));
        assert!(matches!(
            PreciseThroughputTimer::with_duration(
                1.0,
                Duration::from_secs(1),
                Some(Duration::ZERO)
            ),
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
        // A midpoint source makes the Java millisecond-to-Duration boundary
        // observable: an incorrect nanosecond conversion would yield 500ns.
        let source = SequenceRandom::new([1u64 << 63; 4]);
        timer
            .fill_next_window(&mut state, &source)
            .expect("window generation");
        assert_eq!(state.arrivals.len(), 4);
        assert_eq!(state.window, 1);
        assert!(
            state
                .arrivals
                .iter()
                .all(|target| *target == Duration::from_millis(500))
        );
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

        let generation_block = PreciseThroughputTimer::with_duration(
            4.0,
            Duration::from_secs(1),
            Some(Duration::from_millis(500)),
        )
        .expect("generation block");
        let mut block_state = PreciseState {
            origin: Some(Duration::ZERO),
            ..PreciseState::default()
        };
        generation_block
            .fill_next_window(&mut block_state, &SequenceRandom::new([1u64 << 63; 2]))
            .expect("generation window");
        assert_eq!(block_state.arrivals.len(), 2);
        assert!(
            block_state
                .arrivals
                .iter()
                .all(|target| *target == Duration::from_millis(250))
        );
        assert!(
            block_state
                .arrivals
                .iter()
                .all(|target| *target < Duration::from_millis(500))
        );
    }

    #[test]
    fn precise_timer_batches_each_generated_offset_without_extra_delay() {
        let timer = PreciseThroughputTimer::with_duration(
            4.0,
            Duration::from_secs(1),
            Some(Duration::from_secs(1)),
        )
        .expect("precise timer")
        .with_batch_size(2)
        .expect("batch size")
        .with_batch_thread_delay(Duration::from_secs(10));
        let mut state = PreciseState {
            origin: Some(Duration::ZERO),
            ..PreciseState::default()
        };
        timer
            .fill_next_window(&mut state, &SequenceRandom::new([1u64 << 63; 2]))
            .expect("window generation");
        assert_eq!(state.arrivals.len(), 4);
        assert_eq!(state.arrivals[0], state.arrivals[1]);
        assert_eq!(state.arrivals[2], state.arrivals[3]);
        assert_eq!(state.arrivals[0], Duration::from_millis(500));
        assert!(state.arrivals[1] < Duration::from_secs(1));
    }

    #[test]
    fn precise_timer_ceils_each_generation_window_without_fractional_carry() {
        let timer =
            PreciseThroughputTimer::new(1.5, Duration::from_secs(1)).expect("precise timer");
        let source = SequenceRandom::new([1u64 << 62; 4]);
        let mut state = PreciseState {
            origin: Some(Duration::ZERO),
            ..PreciseState::default()
        };
        timer
            .fill_next_window(&mut state, &source)
            .expect("first generation window");
        assert_eq!(state.arrivals.len(), 2);
        state.arrivals.clear();
        timer
            .fill_next_window(&mut state, &source)
            .expect("second generation window");
        assert_eq!(state.arrivals.len(), 2);
        assert_eq!(state.window, 2);
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

    #[derive(Clone, Copy)]
    struct FixedClock(Duration);

    impl crate::Clock for FixedClock {
        fn now(&self) -> crate::ClockReading {
            crate::ClockReading {
                wall: jmeter_rs_results::WallTimestamp::from_millis(0),
                monotonic: self.0,
            }
        }
    }

    #[derive(Default)]
    struct PendingBarrier {
        completed: Mutex<Vec<SynchronizingOutcome>>,
        cancelled: Mutex<usize>,
    }

    impl SynchronizingCoordinator for PendingBarrier {
        fn poll_arrival(
            &self,
            _request: &SynchronizingRequest,
            _waker: &Waker,
        ) -> Poll<Result<SynchronizingOutcome, ComponentError>> {
            Poll::Pending
        }

        fn cancel(&self, _request: &SynchronizingRequest) {
            *lock(&self.cancelled) += 1;
        }

        fn complete(&self, _request: &SynchronizingRequest, outcome: SynchronizingOutcome) {
            lock(&self.completed).push(outcome);
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
    fn synchronizing_timeout_registers_at_injected_absolute_deadline() {
        let scheduler = Arc::new(crate::DeterministicScheduler::new(
            crate::MonotonicInstant::zero(),
            4,
        ));
        let capabilities = crate::RuntimeCapabilities::default()
            .with_clock(Arc::new(FixedClock(Duration::from_millis(500))))
            .with_scheduler(scheduler.clone());
        let mut execution = crate::ExecutionContext::with_capabilities(capabilities);
        execution.set_thread(jmeter_rs_results::ThreadIdentity::with_group(
            "thread",
            Some("group".to_owned()),
            Some(1),
        ));
        let coordinator = Arc::new(PendingBarrier::default());
        let timer = SynchronizingTimer::with_coordinator(
            "gate",
            2,
            Duration::from_secs(1),
            coordinator.clone(),
        )
        .expect("barrier");
        let package =
            crate::SamplePackage::new(jmeter_rs_model::NodeId::new(1), Arc::new(NoopSampler))
                .with_timers(vec![Arc::new(timer)]);
        let mut future = package.execute(&mut execution);
        let waker = Waker::noop();
        let mut poll_context = Context::from_waker(waker);
        assert!(matches!(
            Pin::new(&mut future).poll(&mut poll_context),
            Poll::Pending
        ));
        assert_eq!(
            scheduler
                .next_deadline()
                .expect("timeout registration")
                .instant()
                .as_duration(),
            Duration::from_millis(1_500)
        );

        scheduler
            .advance_to(crate::MonotonicInstant::from_duration(Duration::from_secs(
                1,
            )))
            .expect("advance before deadline");
        assert!(matches!(
            Pin::new(&mut future).poll(&mut poll_context),
            Poll::Pending
        ));
        scheduler
            .advance_to(crate::MonotonicInstant::from_duration(
                Duration::from_millis(1_500),
            ))
            .expect("advance to deadline");
        assert!(matches!(
            Pin::new(&mut future).poll(&mut poll_context),
            Poll::Ready(Ok(_))
        ));
        assert_eq!(
            lock(&coordinator.completed).as_slice(),
            &[SynchronizingOutcome::TimedOut]
        );
        assert_eq!(*lock(&coordinator.cancelled), 0);
    }

    #[test]
    fn synchronizing_pending_drop_cancels_registration_and_arrival() {
        let scheduler = Arc::new(crate::DeterministicScheduler::new(
            crate::MonotonicInstant::zero(),
            4,
        ));
        let capabilities = crate::RuntimeCapabilities::default().with_scheduler(scheduler.clone());
        let mut execution = crate::ExecutionContext::with_capabilities(capabilities);
        execution.set_thread(jmeter_rs_results::ThreadIdentity::new("thread"));
        let coordinator = Arc::new(PendingBarrier::default());
        let timer = SynchronizingTimer::with_coordinator(
            "gate",
            2,
            Duration::from_secs(1),
            coordinator.clone(),
        )
        .expect("barrier");
        let package =
            crate::SamplePackage::new(jmeter_rs_model::NodeId::new(1), Arc::new(NoopSampler))
                .with_timers(vec![Arc::new(timer)]);
        let mut future = package.execute(&mut execution);
        let waker = Waker::noop();
        let mut poll_context = Context::from_waker(waker);
        assert!(matches!(
            Pin::new(&mut future).poll(&mut poll_context),
            Poll::Pending
        ));
        assert!(scheduler.next_deadline().is_some());
        drop(future);
        assert!(scheduler.next_deadline().is_none());
        assert_eq!(*lock(&coordinator.cancelled), 1);
    }

    #[test]
    fn synchronizing_pending_control_signal_returns_explicit_cancellation() {
        let mut execution = crate::ExecutionContext::new();
        execution.set_thread(jmeter_rs_results::ThreadIdentity::new("thread"));
        let token = execution.cancellation_token().clone();
        let coordinator = Arc::new(PendingBarrier::default());
        let timer =
            SynchronizingTimer::with_coordinator("gate", 2, Duration::ZERO, coordinator.clone())
                .expect("barrier");
        let package =
            crate::SamplePackage::new(jmeter_rs_model::NodeId::new(1), Arc::new(NoopSampler))
                .with_timers(vec![Arc::new(timer)]);
        let mut future = package.execute(&mut execution);
        let waker = Waker::noop();
        let mut poll_context = Context::from_waker(waker);
        assert!(matches!(
            Pin::new(&mut future).poll(&mut poll_context),
            Poll::Pending
        ));

        token.request(crate::ControlSignal::NextLoop);
        assert!(matches!(
            Pin::new(&mut future).poll(&mut poll_context),
            Poll::Ready(Ok(_))
        ));
        assert_eq!(*lock(&coordinator.cancelled), 1);
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
    fn synchronizing_request_constructor_enforces_group_identity_mode() {
        assert!(matches!(
            SynchronizingRequest::new(
                "gate",
                0,
                Duration::ZERO,
                "participant",
                "thread",
                None,
                Some(1),
                Some(2),
                Duration::ZERO,
            ),
            Err(ComponentError::Unsupported(_))
        ));
        assert!(matches!(
            SynchronizingRequest::new(
                "gate",
                2,
                Duration::ZERO,
                "participant\n",
                "thread",
                None,
                Some(1),
                Some(2),
                Duration::ZERO,
            ),
            Err(ComponentError::ResourceLimit(_))
        ));
        assert!(matches!(
            SynchronizingRequest::new(
                "gate",
                2,
                Duration::from_nanos(1),
                "participant",
                "thread",
                None,
                Some(1),
                Some(2),
                Duration::MAX,
            ),
            Err(ComponentError::ResourceLimit(_))
        ));
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
