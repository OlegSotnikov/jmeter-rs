// SPDX-License-Identifier: Apache-2.0
//! Executor-neutral deterministic capabilities for tests and oracle tools.
//!
//! The support crate deliberately uses only the standard library.  Its clock,
//! sleeper, random source, and trace types are small capability seams that can
//! be passed to runtime tests without bringing a production executor into the
//! semantic core.  All stateful handles use shared ownership explicitly:
//! cloning a capability shares its state, while [`random::DeterministicRandom::scoped`]
//! creates a new, independently seeded stream.
//!
//! No API in this crate sleeps the host thread or reads the host clock.  Time
//! advances only when a test asks the virtual clock to advance.

pub mod canonical;
pub mod clock;
pub mod error;
pub mod fixture;
pub mod random;
pub mod scheduler;
pub mod trace;
pub mod transport;

pub use canonical::{
    CanonicalError, CanonicalEventSize, CanonicalEventStream, CanonicalField,
    CanonicalFieldDiagnostic, CanonicalLimits, CanonicalRecord, CanonicalRecordDiagnostic,
    CanonicalStreamLimits, CanonicalTextDirection, CanonicalTextLimits, CanonicalTextOptions,
    canonicalize_text,
};

pub use clock::{
    ClockComponent, ClockError, ClockSnapshot, FakeSleeper, MonotonicInstant, TimerAdvanceError,
    TimerError, TimerEvent, TimerHandle, TimerId, TimerLeakError, TimerLifecycleEvent,
    TimerRegistration, TimerReplayLog, TimerState, VirtualClock, WallTime,
};
pub use error::{ErrorCode, StableError};
pub use fixture::{
    FixtureArtifact, FixtureArtifactDiagnostic, FixtureBuilder, FixtureCase, FixtureCaseBuilder,
    FixtureCaseDiagnostic, FixtureError, FixtureLimits, FixtureMetadata, FixtureMetadataDiagnostic,
    FixtureOrigin, FixtureProvenance,
};
pub use random::{DeterministicRandom, RandomError, RandomLimits, RandomSeed, RandomSource};
pub use scheduler::{
    DeterministicScheduler, ScheduledTask, SchedulerAdvanceError, SchedulerError, SchedulerEvent,
    SchedulerLeakError, SchedulerLimits, SchedulerReplayLog, SchedulerTaskState,
    SchedulerWakeOutcome, SchedulerWatchdogError, SchedulerWatchdogLimits, SchedulerWatchdogReport,
    TaskHandle, TaskId,
};
/// Alias emphasizing a seeded source in a fixture manifest.
pub type SeededRandom = DeterministicRandom;
/// Alias for a stream derived for one logical scope.
pub type ScopedRandom = DeterministicRandom;
pub use trace::{
    EventTrace, ReplayCursor, ReplayError, ReplayLog, TraceError, TraceEvent, TraceEventData,
    TraceEventDataDiagnostic, TraceEventDiagnostic, TraceLimits,
};
/// Alias for a bounded logical-event recorder.
pub type TraceRecorder = EventTrace;
/// Alias for a replay cursor over a recorded event stream.
pub type TraceReplay = ReplayCursor;
pub use transport::{
    FakeTransport, FakeTransportBuilder, TransportBodyDirection, TransportCapacityKind,
    TransportError, TransportEvent, TransportEventDiagnostic, TransportExchange,
    TransportExchangeDiagnostic, TransportHeader, TransportHeaderDiagnostic,
    TransportHeaderDirection, TransportLeakError, TransportLimits, TransportRequest,
    TransportRequestDiagnostic, TransportResponseBuilder, TransportResponsePlan,
    TransportResponsePlanDiagnostic, TransportStep, TransportStepDiagnostic,
};

/// A common error wrapper for callers that combine more than one test
/// capability in a single helper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TestSupportError {
    /// An error from the virtual clock.
    Clock(ClockError),
    /// An error from timer registration or cancellation.
    Timer(TimerError),
    /// A sleeper owner found an active timer or failed drop cancellation.
    TimerLeak(TimerLeakError),
    /// An error from random range validation.
    Random(RandomError),
    /// An error while recording or loading a trace.
    Trace(TraceError),
    /// An error while consuming a replay stream.
    Replay(ReplayError),
    /// An error from the deterministic scheduler.
    Scheduler(SchedulerError),
    /// A scheduler owner found an active task or failed drop cancellation.
    SchedulerLeak(SchedulerLeakError),
    /// An error while advancing and draining the deterministic scheduler.
    SchedulerAdvance(SchedulerAdvanceError),
    /// An error from deterministic deadlock/starvation/runaway detection.
    SchedulerWatchdog(SchedulerWatchdogError),
    /// An error from the in-memory scripted transport.
    Transport(TransportError),
    /// A transport owner found an active exchange or failed drop cancellation.
    TransportLeak(TransportLeakError),
    /// An error from bounded fixture construction.
    Fixture(FixtureError),
    /// An error from bounded canonicalization.
    Canonical(CanonicalError),
}

impl TestSupportError {
    /// Returns the stable machine-readable code for this error.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::Clock(error) => (*error).code(),
            Self::Timer(error) => (*error).code(),
            Self::TimerLeak(error) => (*error).code(),
            Self::Random(error) => (*error).code(),
            Self::Trace(error) => error.code(),
            Self::Replay(error) => error.code(),
            Self::Scheduler(error) => (*error).code(),
            Self::SchedulerLeak(error) => (*error).code(),
            Self::SchedulerAdvance(error) => (*error).code(),
            Self::SchedulerWatchdog(error) => error.code(),
            Self::Transport(error) => error.code(),
            Self::TransportLeak(error) => (*error).code(),
            Self::Fixture(error) => error.code(),
            Self::Canonical(error) => error.code(),
        }
    }
}

impl std::fmt::Display for TestSupportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Clock(error) => error.fmt(formatter),
            Self::Timer(error) => error.fmt(formatter),
            Self::TimerLeak(error) => error.fmt(formatter),
            Self::Random(error) => error.fmt(formatter),
            Self::Trace(error) => error.fmt(formatter),
            Self::Replay(error) => error.fmt(formatter),
            Self::Scheduler(error) => error.fmt(formatter),
            Self::SchedulerLeak(error) => error.fmt(formatter),
            Self::SchedulerAdvance(error) => error.fmt(formatter),
            Self::SchedulerWatchdog(error) => error.fmt(formatter),
            Self::Transport(error) => error.fmt(formatter),
            Self::TransportLeak(error) => error.fmt(formatter),
            Self::Fixture(error) => error.fmt(formatter),
            Self::Canonical(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for TestSupportError {}

impl StableError for TestSupportError {
    fn code(&self) -> ErrorCode {
        Self::code(self)
    }
}

impl From<ClockError> for TestSupportError {
    fn from(error: ClockError) -> Self {
        Self::Clock(error)
    }
}

impl From<TimerError> for TestSupportError {
    fn from(error: TimerError) -> Self {
        Self::Timer(error)
    }
}

impl From<TimerAdvanceError> for TestSupportError {
    fn from(error: TimerAdvanceError) -> Self {
        match error {
            TimerAdvanceError::Clock(error) => Self::Clock(error),
            TimerAdvanceError::Timer(error) => Self::Timer(error),
        }
    }
}

impl From<TimerLeakError> for TestSupportError {
    fn from(error: TimerLeakError) -> Self {
        Self::TimerLeak(error)
    }
}

impl From<RandomError> for TestSupportError {
    fn from(error: RandomError) -> Self {
        Self::Random(error)
    }
}

impl From<TraceError> for TestSupportError {
    fn from(error: TraceError) -> Self {
        Self::Trace(error)
    }
}

impl From<ReplayError> for TestSupportError {
    fn from(error: ReplayError) -> Self {
        Self::Replay(error)
    }
}

impl From<SchedulerError> for TestSupportError {
    fn from(error: SchedulerError) -> Self {
        Self::Scheduler(error)
    }
}

impl From<SchedulerLeakError> for TestSupportError {
    fn from(error: SchedulerLeakError) -> Self {
        Self::SchedulerLeak(error)
    }
}

impl From<SchedulerAdvanceError> for TestSupportError {
    fn from(error: SchedulerAdvanceError) -> Self {
        Self::SchedulerAdvance(error)
    }
}

impl From<SchedulerWatchdogError> for TestSupportError {
    fn from(error: SchedulerWatchdogError) -> Self {
        Self::SchedulerWatchdog(error)
    }
}

impl From<TransportError> for TestSupportError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

impl From<TransportLeakError> for TestSupportError {
    fn from(error: TransportLeakError) -> Self {
        Self::TransportLeak(error)
    }
}

impl From<FixtureError> for TestSupportError {
    fn from(error: FixtureError) -> Self {
        Self::Fixture(error)
    }
}

impl From<CanonicalError> for TestSupportError {
    fn from(error: CanonicalError) -> Self {
        Self::Canonical(error)
    }
}
