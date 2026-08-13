// SPDX-License-Identifier: Apache-2.0
//! Run-scoped semantic progress and bounded wait registration.
//!
//! This module is deliberately executor-neutral.  A [`ProgressOwner`] and a
//! [`WaitRegistry`] may be shared by scheduler clones, while their read-only
//! handles retain only the bounded state needed by an application executor.
//! No engine future, sample result, request data, or other run payload is
//! retained here.

use std::collections::BTreeMap;
use std::fmt;
use std::num::NonZeroU64;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::Waker;

use crate::scheduler::{Deadline, MonotonicInstant};

const REGISTRATION_ACTIVE: u8 = 0;
const REGISTRATION_RETIRED: u8 = 1;
const REGISTRATION_SHUTDOWN: u8 = 2;

/// A bounded upper bound for one opaque identity before a registry-specific
/// limit is applied.
pub const MAX_OPAQUE_WAIT_IDENTITY_BYTES: usize = 256;

/// The default maximum number of live wait registrations in one run.
pub const DEFAULT_WAIT_REGISTRATION_CAPACITY: usize = 65_536;

/// The default maximum identity/diagnostic bytes accepted for one item.
pub const DEFAULT_WAIT_ITEM_DIAGNOSTIC_BYTES: usize = 1_024;

/// The default aggregate diagnostic-byte budget for one run.
pub const DEFAULT_WAIT_TOTAL_DIAGNOSTIC_BYTES: usize = 1_048_576;

fn lock_unpoisoned<T>(value: &Mutex<T>) -> MutexGuard<'_, T> {
    value
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn next_generation(current: NonZeroU64) -> Option<NonZeroU64> {
    current.get().checked_add(1).and_then(NonZeroU64::new)
}

fn discard_panic_payload(payload: Box<dyn std::any::Any + Send>) {
    if let Err(second_payload) = catch_unwind(AssertUnwindSafe(|| drop(payload))) {
        std::mem::forget(second_payload);
    }
}

fn catch_notification(action: impl FnOnce(), saw_panic: &mut bool) {
    if let Err(payload) = catch_unwind(AssertUnwindSafe(action)) {
        // A panic payload is foreign input too; do not let a panic-on-drop
        // payload escape while converting the event to a typed error.
        discard_panic_payload(payload);
        *saw_panic = true;
    }
}

#[derive(Debug)]
struct SafeWaker {
    waker: Option<Waker>,
}

impl SafeWaker {
    fn new(waker: Waker) -> Self {
        Self { waker: Some(waker) }
    }

    fn wake_by_ref(&self) {
        if let Some(waker) = self.waker.as_ref() {
            waker.wake_by_ref();
        }
    }
}

impl Drop for SafeWaker {
    fn drop(&mut self) {
        if let Some(waker) = self.waker.take()
            && let Err(payload) = catch_unwind(AssertUnwindSafe(|| drop(waker)))
        {
            discard_panic_payload(payload);
        }
    }
}

fn clone_waker(waker: &Waker) -> Result<Arc<SafeWaker>, WaitRegistryError> {
    match catch_unwind(AssertUnwindSafe(|| waker.clone())) {
        Ok(waker) => Ok(Arc::new(SafeWaker::new(waker))),
        Err(payload) => {
            discard_panic_payload(payload);
            Err(WaitRegistryError::NotificationPanic)
        }
    }
}

/// The terminal state of one run's semantic progress.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum ProgressTerminalState {
    /// The run is accepting semantic progress.
    #[default]
    Running,
    /// The run reached its normal terminal boundary.
    Completed,
    /// The run failed at an engine or capability boundary.
    Failed,
    /// The run was cancelled or its future was dropped.
    Cancelled,
}

impl ProgressTerminalState {
    /// Returns whether this state is terminal.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Running)
    }

    /// Returns whether this state accepts semantic progress.
    #[must_use]
    pub const fn is_running(self) -> bool {
        matches!(self, Self::Running)
    }
}

/// A read-only point-in-time view of one run's semantic progress.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProgressSnapshot {
    /// Checked, non-zero semantic progress generation.
    pub generation: NonZeroU64,
    /// Current run terminal state.
    pub terminal: ProgressTerminalState,
}

impl ProgressSnapshot {
    /// Returns the initial snapshot for a new run.
    #[must_use]
    pub const fn initial() -> Self {
        Self {
            generation: NonZeroU64::MIN,
            terminal: ProgressTerminalState::Running,
        }
    }

    /// Returns whether this snapshot is terminal.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        self.terminal.is_terminal()
    }
}

/// Stable errors raised by the semantic progress owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProgressError {
    /// The generation could not advance without wrapping.
    GenerationOverflow,
    /// Progress was requested after the run reached a terminal state.
    NotRunning {
        /// State observed when progress was requested.
        state: ProgressTerminalState,
    },
    /// A terminal transition was requested after another terminal transition.
    AlreadyTerminal {
        /// Existing terminal state.
        current: ProgressTerminalState,
        /// Requested terminal state.
        requested: ProgressTerminalState,
    },
    /// A caller attempted to use `Running` as a terminal transition.
    InvalidTerminal {
        /// The invalid requested state.
        requested: ProgressTerminalState,
    },
}

impl ProgressError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::GenerationOverflow => "runtime.progress.generation-overflow",
            Self::NotRunning { .. } => "runtime.progress.not-running",
            Self::AlreadyTerminal { .. } => "runtime.progress.already-terminal",
            Self::InvalidTerminal { .. } => "runtime.progress.invalid-terminal",
        }
    }
}

impl fmt::Display for ProgressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GenerationOverflow => formatter.write_str(self.code()),
            Self::NotRunning { state } => write!(formatter, "{}: state={state:?}", self.code()),
            Self::AlreadyTerminal { current, requested } => write!(
                formatter,
                "{}: current={current:?}, requested={requested:?}",
                self.code()
            ),
            Self::InvalidTerminal { requested } => {
                write!(formatter, "{}: requested={requested:?}", self.code())
            }
        }
    }
}

impl std::error::Error for ProgressError {}

#[derive(Debug)]
struct ProgressMutable {
    snapshot: ProgressSnapshot,
}

#[derive(Debug)]
struct ProgressInner {
    state: Mutex<ProgressMutable>,
}

/// The run-owned mutable semantic progress state.
///
/// Cloning this owner shares the same run state.  Use [`ProgressOwner::handle`]
/// when a component should receive only read access.
#[derive(Clone, Debug)]
pub struct ProgressOwner {
    inner: Arc<ProgressInner>,
}

/// A read-only handle for a run's semantic progress.
///
/// The handle contains no engine future, result payload, or executor task.
#[derive(Clone, Debug)]
pub struct ProgressHandle {
    inner: Arc<ProgressInner>,
}

impl Default for ProgressOwner {
    fn default() -> Self {
        Self::new()
    }
}

impl ProgressOwner {
    /// Creates a new running progress owner at generation one.
    ///
    /// A caller creates one owner per run.  There is intentionally no reset
    /// operation: a handle retained from an earlier run can never observe a
    /// later run through the same shared allocation.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(ProgressInner {
                state: Mutex::new(ProgressMutable {
                    snapshot: ProgressSnapshot::initial(),
                }),
            }),
        }
    }

    /// Returns a read-only handle sharing this run's state.
    #[must_use]
    pub fn handle(&self) -> ProgressHandle {
        ProgressHandle {
            inner: Arc::clone(&self.inner),
        }
    }

    /// Returns the current snapshot.
    #[must_use]
    pub fn snapshot(&self) -> ProgressSnapshot {
        self.handle().snapshot()
    }

    /// Advances semantic progress by exactly one checked generation.
    ///
    /// Waker activity alone is not semantic progress and must not call this
    /// method.  A failed advance leaves the previous snapshot unchanged.
    pub fn advance(&self) -> Result<ProgressSnapshot, ProgressError> {
        let mut state = lock_unpoisoned(&self.inner.state);
        if !state.snapshot.terminal.is_running() {
            return Err(ProgressError::NotRunning {
                state: state.snapshot.terminal,
            });
        }
        let generation =
            next_generation(state.snapshot.generation).ok_or(ProgressError::GenerationOverflow)?;
        state.snapshot.generation = generation;
        Ok(state.snapshot)
    }

    /// Records a terminal transition after the run has been progressing.
    ///
    /// Terminal transitions are monotonic: only `Running` may transition to a
    /// terminal state, and a second transition is rejected.
    pub fn transition_terminal(
        &self,
        terminal: ProgressTerminalState,
    ) -> Result<ProgressSnapshot, ProgressError> {
        if !terminal.is_terminal() {
            return Err(ProgressError::InvalidTerminal {
                requested: terminal,
            });
        }
        let mut state = lock_unpoisoned(&self.inner.state);
        if !state.snapshot.terminal.is_running() {
            return Err(ProgressError::AlreadyTerminal {
                current: state.snapshot.terminal,
                requested: terminal,
            });
        }
        let generation =
            next_generation(state.snapshot.generation).ok_or(ProgressError::GenerationOverflow)?;
        state.snapshot.generation = generation;
        state.snapshot.terminal = terminal;
        Ok(state.snapshot)
    }

    /// Records normal completion.
    pub fn complete(&self) -> Result<ProgressSnapshot, ProgressError> {
        self.transition_terminal(ProgressTerminalState::Completed)
    }

    /// Records failure.
    pub fn fail(&self) -> Result<ProgressSnapshot, ProgressError> {
        self.transition_terminal(ProgressTerminalState::Failed)
    }

    /// Records cancellation.
    pub fn cancel(&self) -> Result<ProgressSnapshot, ProgressError> {
        self.transition_terminal(ProgressTerminalState::Cancelled)
    }

    #[cfg(test)]
    fn with_generation(generation: NonZeroU64) -> Self {
        Self {
            inner: Arc::new(ProgressInner {
                state: Mutex::new(ProgressMutable {
                    snapshot: ProgressSnapshot {
                        generation,
                        terminal: ProgressTerminalState::Running,
                    },
                }),
            }),
        }
    }
}

impl ProgressHandle {
    /// Returns the current snapshot without granting mutation access.
    #[must_use]
    pub fn snapshot(&self) -> ProgressSnapshot {
        lock_unpoisoned(&self.inner.state).snapshot
    }

    /// Returns the current terminal state.
    #[must_use]
    pub fn terminal(&self) -> ProgressTerminalState {
        self.snapshot().terminal
    }

    /// Returns the current checked generation.
    #[must_use]
    pub fn generation(&self) -> NonZeroU64 {
        self.snapshot().generation
    }
}

/// A bounded opaque identity for a wait owner.
///
/// The bytes are an identity token only.  Callers must not put request data,
/// hostnames, credentials, certificates, or other secrets in this value.
/// Debug output reveals only its bounded length.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct OpaqueWaitIdentity {
    bytes: Box<[u8]>,
}

impl fmt::Debug for OpaqueWaitIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueWaitIdentity")
            .field("len", &self.bytes.len())
            .finish()
    }
}

/// Stable errors raised while constructing an opaque wait identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitIdentityError {
    /// The identity exceeded the module's hard bound.
    TooLong {
        /// Supplied byte count.
        actual: usize,
        /// Hard maximum byte count.
        maximum: usize,
    },
    /// The bounded identity allocation failed.
    AllocationFailure,
}

impl WaitIdentityError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::TooLong { .. } => "runtime.wait.identity-too-long",
            Self::AllocationFailure => "runtime.wait.identity-allocation",
        }
    }
}

impl fmt::Display for WaitIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong { actual, maximum } => {
                write!(formatter, "{}: {actual} exceeds {maximum}", self.code())
            }
            Self::AllocationFailure => formatter.write_str(self.code()),
        }
    }
}

impl std::error::Error for WaitIdentityError {}

impl OpaqueWaitIdentity {
    /// Creates an opaque identity from bounded caller-provided bytes.
    pub fn new(bytes: &[u8]) -> Result<Self, WaitIdentityError> {
        if bytes.len() > MAX_OPAQUE_WAIT_IDENTITY_BYTES {
            return Err(WaitIdentityError::TooLong {
                actual: bytes.len(),
                maximum: MAX_OPAQUE_WAIT_IDENTITY_BYTES,
            });
        }
        let mut owned = Vec::new();
        owned
            .try_reserve(bytes.len())
            .map_err(|_| WaitIdentityError::AllocationFailure)?;
        owned.extend_from_slice(bytes);
        Ok(Self {
            bytes: owned.into_boxed_slice(),
        })
    }

    /// Creates an identity from a small numeric owner token.
    #[must_use]
    pub fn from_u64(value: u64) -> Self {
        Self {
            bytes: value.to_be_bytes().into(),
        }
    }

    /// Creates an identity from UTF-8 text intended as a non-secret label.
    pub fn from_label(label: &str) -> Result<Self, WaitIdentityError> {
        Self::new(label.as_bytes())
    }

    /// Returns the bounded identity length without exposing its bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns whether this identity has no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Returns the identity bytes for exact owner-side comparison.
    ///
    /// The registry never includes these bytes in diagnostics.  Callers must
    /// uphold the no-secrets contract stated on [`OpaqueWaitIdentity`].
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// The typed runtime owner of a wait registration.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum WaitOwnerClass {
    /// A runtime sleeper or timer future.
    Sleeper,
    /// A scheduler deadline or ramp-up wait.
    Scheduler,
    /// A dynamically computed timer.
    DynamicTimer,
    /// A synchronization/barrier wait.
    Barrier,
    /// A throughput/concurrency limiter wait.
    Throughput,
    /// An HTTP queue or operation wait.
    Http,
    /// A DNS provider wait.
    Dns,
    /// A TLS provider wait.
    Tls,
    /// A bounded provider queue wait.
    Queue,
    /// An explicitly admitted external provider wait.
    Provider,
    /// A caller-defined wait that carries no textual identity.
    Other,
}

impl WaitOwnerClass {
    /// Returns a stable owner-class code for diagnostics.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Sleeper => "sleeper",
            Self::Scheduler => "scheduler",
            Self::DynamicTimer => "dynamic-timer",
            Self::Barrier => "barrier",
            Self::Throughput => "throughput",
            Self::Http => "http",
            Self::Dns => "dns",
            Self::Tls => "tls",
            Self::Queue => "queue",
            Self::Provider => "provider",
            Self::Other => "other",
        }
    }
}

/// The kind of notification delivered to a registry observer or registration
/// waiter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitNotificationKind {
    /// The registry gained its first finite deadline.
    FirstDeadline,
    /// A new or updated registration moved the earliest deadline earlier.
    EarlierDeadline,
    /// A registration count or non-earliest wait changed.
    GenerationChanged,
    /// The run-owned registry shut down and retired all entries.
    Shutdown,
}

/// A lock-free-dispatch notification carrying only bounded registry facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitNotification {
    /// Why the registry generation changed.
    pub kind: WaitNotificationKind,
    /// Snapshot after the state mutation.
    pub snapshot: WaitSnapshot,
}

/// A callback invoked after the wait-registry lock has been released.
///
/// The callback must not retain run payloads, request data, or secrets.  If a
/// callback panics, the registry still attempts every exact callback and
/// waker, then returns [`WaitRegistryError::NotificationPanic`].
pub type WaitNotificationCallback = Arc<dyn Fn(WaitNotification) + Send + Sync + 'static>;

struct SafeCallback {
    callback: Option<WaitNotificationCallback>,
}

impl SafeCallback {
    fn new(callback: WaitNotificationCallback) -> Self {
        Self {
            callback: Some(callback),
        }
    }

    fn invoke(&self, notification: WaitNotification, saw_panic: &mut bool) {
        if let Some(callback) = self.callback.as_ref() {
            catch_notification(|| callback(notification), saw_panic);
        }
    }
}

impl Drop for SafeCallback {
    fn drop(&mut self) {
        if let Some(callback) = self.callback.take()
            && let Err(payload) = catch_unwind(AssertUnwindSafe(|| drop(callback)))
        {
            discard_panic_payload(payload);
        }
    }
}

/// An optional exact waiter notification attached to one registration.
///
/// A notifier must contain only a bounded callback/waker identity; it must
/// not capture run payloads or secrets.  A supplied waker must identify only
/// the exact executor wait state and checked generations; it must not retain
/// the run future, result payloads, request data, or secrets. Callback panics
/// are contained until all wakers have been attempted, then reported as
/// [`WaitRegistryError::NotificationPanic`] by the registry operation.
#[derive(Clone, Default)]
pub struct WaitNotifier {
    callback: Option<Arc<SafeCallback>>,
    waker: Option<Arc<SafeWaker>>,
}

impl fmt::Debug for WaitNotifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WaitNotifier")
            .field("callback", &self.callback.is_some())
            .field("waker", &self.waker.is_some())
            .finish()
    }
}

impl WaitNotifier {
    /// Creates an empty notifier.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            callback: None,
            waker: None,
        }
    }

    /// Creates a notifier containing one executor waker.
    pub fn from_waker(waker: &Waker) -> Result<Self, WaitRegistryError> {
        Ok(Self {
            callback: None,
            waker: Some(clone_waker(waker)?),
        })
    }

    /// Creates a notifier containing one callback.
    #[must_use]
    pub fn from_callback<F>(callback: F) -> Self
    where
        F: Fn(WaitNotification) + Send + Sync + 'static,
    {
        Self {
            callback: Some(Arc::new(SafeCallback::new(Arc::new(callback)))),
            waker: None,
        }
    }

    /// Adds/replaces the exact waiter waker.
    pub fn with_waker(mut self, waker: &Waker) -> Result<Self, WaitRegistryError> {
        self.waker = Some(clone_waker(waker)?);
        Ok(self)
    }

    /// Adds/replaces the exact waiter callback.
    #[must_use]
    pub fn with_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn(WaitNotification) + Send + Sync + 'static,
    {
        self.callback = Some(Arc::new(SafeCallback::new(Arc::new(callback))));
        self
    }

    fn notify(&self, notification: WaitNotification, saw_panic: &mut bool) {
        if let Some(callback) = self.callback.as_ref() {
            callback.invoke(notification, saw_panic);
        }
        if let Some(waker) = self.waker.as_ref() {
            catch_notification(|| waker.wake_by_ref(), saw_panic);
        }
    }
}

/// The bounded limits for one run's wait registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitRegistryConfig {
    /// Maximum number of simultaneously live registrations.
    pub max_registrations: usize,
    /// Maximum opaque-identity bytes accepted for one registration.
    pub max_identity_bytes: usize,
    /// Maximum identity plus caller diagnostic bytes for one registration.
    pub max_diagnostic_bytes_per_item: usize,
    /// Maximum identity plus caller diagnostic bytes retained by the run.
    pub max_diagnostic_bytes_total: usize,
}

impl Default for WaitRegistryConfig {
    fn default() -> Self {
        Self {
            max_registrations: DEFAULT_WAIT_REGISTRATION_CAPACITY,
            max_identity_bytes: MAX_OPAQUE_WAIT_IDENTITY_BYTES,
            max_diagnostic_bytes_per_item: DEFAULT_WAIT_ITEM_DIAGNOSTIC_BYTES,
            max_diagnostic_bytes_total: DEFAULT_WAIT_TOTAL_DIAGNOSTIC_BYTES,
        }
    }
}

impl WaitRegistryConfig {
    /// Creates limits with a per-item identity bound equal to the item byte
    /// bound.  Use [`Self::with_identity_limit`] for a stricter identity cap.
    #[must_use]
    pub const fn new(
        max_registrations: usize,
        max_diagnostic_bytes_per_item: usize,
        max_diagnostic_bytes_total: usize,
    ) -> Self {
        Self {
            max_registrations,
            max_identity_bytes: max_diagnostic_bytes_per_item,
            max_diagnostic_bytes_per_item,
            max_diagnostic_bytes_total,
        }
    }

    /// Creates all four limits explicitly.
    #[must_use]
    pub const fn with_limits(
        max_registrations: usize,
        max_identity_bytes: usize,
        max_diagnostic_bytes_per_item: usize,
        max_diagnostic_bytes_total: usize,
    ) -> Self {
        Self {
            max_registrations,
            max_identity_bytes,
            max_diagnostic_bytes_per_item,
            max_diagnostic_bytes_total,
        }
    }

    /// Returns a copy with a stricter opaque identity limit.
    #[must_use]
    pub const fn with_identity_limit(mut self, maximum: usize) -> Self {
        self.max_identity_bytes = maximum;
        self
    }

    /// Returns a copy with a different per-item diagnostic limit.
    #[must_use]
    pub const fn with_item_limit(mut self, maximum: usize) -> Self {
        self.max_diagnostic_bytes_per_item = maximum;
        self
    }

    /// Returns a copy with a different aggregate diagnostic limit.
    #[must_use]
    pub const fn with_total_limit(mut self, maximum: usize) -> Self {
        self.max_diagnostic_bytes_total = maximum;
        self
    }
}

/// A finite absolute wait registration request.
#[derive(Clone)]
pub struct WaitRegistrationSpec {
    owner: WaitOwnerClass,
    identity: OpaqueWaitIdentity,
    deadline: MonotonicInstant,
    diagnostic_bytes: usize,
    notifier: WaitNotifier,
}

impl fmt::Debug for WaitRegistrationSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WaitRegistrationSpec")
            .field("owner", &self.owner)
            .field("identity_len", &self.identity.len())
            .field("deadline", &self.deadline)
            .field("diagnostic_bytes", &self.diagnostic_bytes)
            .field("notifier", &self.notifier)
            .finish()
    }
}

impl WaitRegistrationSpec {
    /// Creates a registration for a finite absolute monotonic instant.
    #[must_use]
    pub fn new(
        owner: WaitOwnerClass,
        identity: OpaqueWaitIdentity,
        deadline: MonotonicInstant,
    ) -> Self {
        Self {
            owner,
            identity,
            deadline,
            diagnostic_bytes: 0,
            notifier: WaitNotifier::new(),
        }
    }

    /// Creates a registration from the shared scheduler deadline type.
    #[must_use]
    pub fn from_deadline(
        owner: WaitOwnerClass,
        identity: OpaqueWaitIdentity,
        deadline: Deadline,
    ) -> Self {
        Self::new(owner, identity, deadline.instant())
    }

    /// Returns a copy with bounded caller-supplied diagnostic bytes accounted.
    #[must_use]
    pub const fn with_diagnostic_bytes(mut self, bytes: usize) -> Self {
        self.diagnostic_bytes = bytes;
        self
    }

    /// Returns a copy with an exact waiter waker.
    pub fn with_waker(mut self, waker: &Waker) -> Result<Self, WaitRegistryError> {
        self.notifier = self.notifier.with_waker(waker)?;
        Ok(self)
    }

    /// Returns a copy with an exact waiter callback.
    #[must_use]
    pub fn with_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn(WaitNotification) + Send + Sync + 'static,
    {
        self.notifier = self.notifier.with_callback(callback);
        self
    }

    /// Returns a copy with an exact waiter notifier.
    #[must_use]
    pub fn with_notifier(mut self, notifier: WaitNotifier) -> Self {
        self.notifier = notifier;
        self
    }

    /// Returns the typed owner class.
    #[must_use]
    pub const fn owner(&self) -> WaitOwnerClass {
        self.owner
    }

    /// Returns the opaque identity.
    #[must_use]
    pub fn identity(&self) -> &OpaqueWaitIdentity {
        &self.identity
    }

    /// Returns the absolute deadline.
    #[must_use]
    pub const fn deadline(&self) -> MonotonicInstant {
        self.deadline
    }

    /// Returns additional caller diagnostic bytes, excluding identity bytes.
    #[must_use]
    pub const fn diagnostic_bytes(&self) -> usize {
        self.diagnostic_bytes
    }
}

/// A checked, non-zero, never-reused wait-registration ID.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WaitRegistrationId(NonZeroU64);

impl WaitRegistrationId {
    /// Creates an ID, rejecting the reserved zero value.
    #[must_use]
    pub const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Returns the numeric ID.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// Returns the non-zero representation.
    #[must_use]
    pub const fn as_nonzero(self) -> NonZeroU64 {
        self.0
    }
}

/// The wait-registry snapshot visible to an executor.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct WaitSnapshot {
    /// Number of currently live registrations.
    pub registrations: usize,
    /// Earliest finite absolute monotonic deadline, if one exists.
    pub earliest_deadline: Option<MonotonicInstant>,
    /// Checked wait-state generation.
    pub generation: NonZeroU64,
}

impl WaitSnapshot {
    /// Returns the initial empty snapshot.
    #[must_use]
    pub const fn initial() -> Self {
        Self {
            registrations: 0,
            earliest_deadline: None,
            generation: NonZeroU64::MIN,
        }
    }
}

/// Stable errors raised by bounded wait registration and retirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitRegistryError {
    /// The registry reached its live-item capacity.
    Capacity {
        /// Configured item limit.
        limit: usize,
    },
    /// The opaque identity exceeded the registry-specific bound.
    IdentityLimitExceeded {
        /// Supplied identity length.
        actual: usize,
        /// Configured identity limit.
        maximum: usize,
    },
    /// One item exceeded its diagnostic-byte budget.
    DiagnosticItemLimitExceeded {
        /// Bytes requested by the item, including identity bytes.
        actual: usize,
        /// Configured item limit.
        maximum: usize,
    },
    /// The aggregate diagnostic-byte budget would be exceeded.
    DiagnosticTotalLimitExceeded {
        /// Aggregate bytes after the rejected item.
        actual: usize,
        /// Configured aggregate limit.
        maximum: usize,
    },
    /// Diagnostic-byte arithmetic overflowed.
    DiagnosticBytesOverflow,
    /// The wait generation could not advance without wrapping.
    GenerationOverflow,
    /// The checked non-zero ID space was exhausted.
    IdOverflow,
    /// The registry has been shut down and accepts no new entries.
    Shutdown,
    /// Shutdown was requested a second time.
    AlreadyShutdown,
    /// A requested ID does not exist in this registry.
    UnknownRegistration {
        /// Unknown registration ID.
        id: WaitRegistrationId,
    },
    /// A registration belongs to another registry.
    ForeignRegistration {
        /// Foreign registration ID.
        id: WaitRegistrationId,
    },
    /// A registration was already retired or shutdown.
    AlreadyRetired {
        /// Retired registration ID.
        id: WaitRegistrationId,
    },
    /// An update attempted to move an absolute deadline later.
    DeadlineReversal {
        /// Registration being updated.
        id: WaitRegistrationId,
        /// Existing earlier deadline.
        current: MonotonicInstant,
        /// Requested later deadline.
        requested: MonotonicInstant,
    },
    /// A bounded registry allocation failed.
    AllocationFailure,
    /// A callback or custom waker panicked while being cloned or notified.
    NotificationPanic,
    /// Internal accounting did not match the retained entries.
    AccountingInvariant,
}

impl WaitRegistryError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Capacity { .. } => "runtime.wait.capacity",
            Self::IdentityLimitExceeded { .. } => "runtime.wait.identity-limit",
            Self::DiagnosticItemLimitExceeded { .. } => "runtime.wait.diagnostic-item-limit",
            Self::DiagnosticTotalLimitExceeded { .. } => "runtime.wait.diagnostic-total-limit",
            Self::DiagnosticBytesOverflow => "runtime.wait.diagnostic-overflow",
            Self::GenerationOverflow => "runtime.wait.generation-overflow",
            Self::IdOverflow => "runtime.wait.id-overflow",
            Self::Shutdown => "runtime.wait.shutdown",
            Self::AlreadyShutdown => "runtime.wait.already-shutdown",
            Self::UnknownRegistration { .. } => "runtime.wait.unknown-registration",
            Self::ForeignRegistration { .. } => "runtime.wait.foreign-registration",
            Self::AlreadyRetired { .. } => "runtime.wait.already-retired",
            Self::DeadlineReversal { .. } => "runtime.wait.deadline-reversal",
            Self::AllocationFailure => "runtime.wait.allocation",
            Self::NotificationPanic => "runtime.wait.notification-panic",
            Self::AccountingInvariant => "runtime.wait.accounting-invariant",
        }
    }
}

impl fmt::Display for WaitRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Capacity { limit } => write!(formatter, "{}: limit {limit}", self.code()),
            Self::IdentityLimitExceeded { actual, maximum }
            | Self::DiagnosticItemLimitExceeded { actual, maximum }
            | Self::DiagnosticTotalLimitExceeded { actual, maximum } => {
                write!(formatter, "{}: {actual} exceeds {maximum}", self.code())
            }
            Self::DiagnosticBytesOverflow
            | Self::GenerationOverflow
            | Self::IdOverflow
            | Self::Shutdown
            | Self::AlreadyShutdown
            | Self::AllocationFailure
            | Self::NotificationPanic
            | Self::AccountingInvariant => formatter.write_str(self.code()),
            Self::UnknownRegistration { id }
            | Self::ForeignRegistration { id }
            | Self::AlreadyRetired { id } => write!(formatter, "{}: id={}", self.code(), id.get()),
            Self::DeadlineReversal {
                id,
                current,
                requested,
            } => write!(
                formatter,
                "{}: id={}, current={current:?}, requested={requested:?}",
                self.code(),
                id.get()
            ),
        }
    }
}

impl std::error::Error for WaitRegistryError {}

#[derive(Debug)]
struct WaitEntry {
    owner: WaitOwnerClass,
    identity: OpaqueWaitIdentity,
    deadline: MonotonicInstant,
    diagnostic_bytes: usize,
    notifier: Arc<WaitNotifier>,
    status: Arc<AtomicU8>,
}

struct WaitState {
    config: WaitRegistryConfig,
    entries: BTreeMap<WaitRegistrationId, WaitEntry>,
    next_id: Option<NonZeroU64>,
    generation: NonZeroU64,
    earliest_deadline: Option<MonotonicInstant>,
    diagnostic_bytes: usize,
    shutdown: bool,
    callback: Option<Arc<SafeCallback>>,
    waker: Option<Arc<SafeWaker>>,
}

impl fmt::Debug for WaitState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WaitState")
            .field("config", &self.config)
            .field("registrations", &self.entries.len())
            .field("next_id", &self.next_id)
            .field("generation", &self.generation)
            .field("earliest_deadline", &self.earliest_deadline)
            .field("diagnostic_bytes", &self.diagnostic_bytes)
            .field("shutdown", &self.shutdown)
            .field("callback", &self.callback.is_some())
            .field("waker", &self.waker.is_some())
            .finish()
    }
}

#[derive(Debug)]
struct WaitRegistryInner {
    state: Mutex<WaitState>,
}

/// An owner of a bounded run-scoped wait registry.
#[derive(Clone)]
pub struct WaitRegistry {
    inner: Arc<WaitRegistryInner>,
}

/// A read-only handle for wait counts, earliest deadline, and generation.
#[derive(Clone)]
pub struct WaitRegistryHandle {
    inner: Arc<WaitRegistryInner>,
}

impl fmt::Debug for WaitRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WaitRegistry")
            .field("snapshot", &self.snapshot())
            .field("shutdown", &self.is_shutdown())
            .finish()
    }
}

impl fmt::Debug for WaitRegistryHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WaitRegistryHandle")
            .field("snapshot", &self.snapshot())
            .field("shutdown", &self.is_shutdown())
            .finish()
    }
}

impl Default for WaitRegistry {
    fn default() -> Self {
        Self::new(WaitRegistryConfig::default())
    }
}

impl WaitRegistry {
    /// Creates an empty registry with finite limits.
    #[must_use]
    pub fn new(config: WaitRegistryConfig) -> Self {
        Self {
            inner: Arc::new(WaitRegistryInner {
                state: Mutex::new(WaitState {
                    config,
                    entries: BTreeMap::new(),
                    next_id: Some(NonZeroU64::MIN),
                    generation: NonZeroU64::MIN,
                    earliest_deadline: None,
                    diagnostic_bytes: 0,
                    shutdown: false,
                    callback: None,
                    waker: None,
                }),
            }),
        }
    }

    /// Creates a registry with one observer callback.
    #[must_use]
    pub fn with_callback<F>(config: WaitRegistryConfig, callback: F) -> Self
    where
        F: Fn(WaitNotification) + Send + Sync + 'static,
    {
        let registry = Self::new(config);
        let callback = Arc::new(SafeCallback::new(Arc::new(callback)));
        lock_unpoisoned(&registry.inner.state).callback = Some(callback);
        registry
    }

    /// Creates a registry with one executor-level waker.
    pub fn with_waker(
        config: WaitRegistryConfig,
        waker: &Waker,
    ) -> Result<Self, WaitRegistryError> {
        let registry = Self::new(config);
        registry.set_waker(waker)?;
        Ok(registry)
    }

    /// Returns a read-only handle.
    #[must_use]
    pub fn handle(&self) -> WaitRegistryHandle {
        WaitRegistryHandle {
            inner: Arc::clone(&self.inner),
        }
    }

    /// Returns the current bounded snapshot.
    #[must_use]
    pub fn snapshot(&self) -> WaitSnapshot {
        lock_unpoisoned(&self.inner.state).snapshot()
    }

    /// Returns the retained identity/diagnostic byte count.
    #[must_use]
    pub fn diagnostic_bytes(&self) -> usize {
        lock_unpoisoned(&self.inner.state).diagnostic_bytes
    }

    /// Returns whether shutdown has retired all entries.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        lock_unpoisoned(&self.inner.state).shutdown
    }

    /// Installs/replaces the executor-level callback.
    ///
    /// Returns [`WaitRegistryError::Shutdown`] after finalization; the
    /// supplied callback is not retained.
    pub fn set_callback<F>(&self, callback: F) -> Result<(), WaitRegistryError>
    where
        F: Fn(WaitNotification) + Send + Sync + 'static,
    {
        let callback = Arc::new(SafeCallback::new(Arc::new(callback)));
        let mut state = lock_unpoisoned(&self.inner.state);
        if state.shutdown {
            drop(state);
            drop(callback);
            return Err(WaitRegistryError::Shutdown);
        }
        let replaced = state.callback.replace(callback);
        drop(state);
        drop(replaced);
        Ok(())
    }

    /// Installs/replaces the executor-level callback from an existing Arc.
    ///
    /// Returns [`WaitRegistryError::Shutdown`] after finalization; the
    /// supplied callback is not retained.
    pub fn set_callback_arc(
        &self,
        callback: Option<WaitNotificationCallback>,
    ) -> Result<(), WaitRegistryError> {
        let callback = callback.map(|callback| Arc::new(SafeCallback::new(callback)));
        let mut state = lock_unpoisoned(&self.inner.state);
        if state.shutdown {
            drop(state);
            drop(callback);
            return Err(WaitRegistryError::Shutdown);
        }
        let replaced = match callback {
            Some(callback) => state.callback.replace(callback),
            None => state.callback.take(),
        };
        drop(state);
        drop(replaced);
        Ok(())
    }

    /// Removes the executor-level callback.
    ///
    /// Returns [`WaitRegistryError::Shutdown`] after finalization.
    pub fn clear_callback(&self) -> Result<(), WaitRegistryError> {
        let mut state = lock_unpoisoned(&self.inner.state);
        if state.shutdown {
            return Err(WaitRegistryError::Shutdown);
        }
        let removed = state.callback.take();
        drop(state);
        drop(removed);
        Ok(())
    }

    /// Installs/replaces the executor-level waker.
    ///
    /// Returns [`WaitRegistryError::Shutdown`] after finalization; the
    /// supplied waker is not retained.
    pub fn set_waker(&self, waker: &Waker) -> Result<(), WaitRegistryError> {
        if lock_unpoisoned(&self.inner.state).shutdown {
            return Err(WaitRegistryError::Shutdown);
        }
        let waker = clone_waker(waker)?;
        let mut state = lock_unpoisoned(&self.inner.state);
        if state.shutdown {
            drop(state);
            drop(waker);
            return Err(WaitRegistryError::Shutdown);
        }
        let replaced = state.waker.replace(waker);
        drop(state);
        drop(replaced);
        Ok(())
    }

    /// Removes the executor-level waker.
    ///
    /// Returns [`WaitRegistryError::Shutdown`] after finalization.
    pub fn clear_waker(&self) -> Result<(), WaitRegistryError> {
        let mut state = lock_unpoisoned(&self.inner.state);
        if state.shutdown {
            return Err(WaitRegistryError::Shutdown);
        }
        let removed = state.waker.take();
        drop(state);
        drop(removed);
        Ok(())
    }

    /// Registers one finite absolute wait.
    pub fn register(
        &self,
        spec: WaitRegistrationSpec,
    ) -> Result<WaitRegistration, WaitRegistryError> {
        let identity_bytes = spec.identity.len();
        let item_bytes = identity_bytes
            .checked_add(spec.diagnostic_bytes)
            .ok_or(WaitRegistryError::DiagnosticBytesOverflow)?;
        let mut state = lock_unpoisoned(&self.inner.state);
        if state.shutdown {
            return Err(WaitRegistryError::Shutdown);
        }
        if identity_bytes > state.config.max_identity_bytes {
            return Err(WaitRegistryError::IdentityLimitExceeded {
                actual: identity_bytes,
                maximum: state.config.max_identity_bytes,
            });
        }
        if item_bytes > state.config.max_diagnostic_bytes_per_item {
            return Err(WaitRegistryError::DiagnosticItemLimitExceeded {
                actual: item_bytes,
                maximum: state.config.max_diagnostic_bytes_per_item,
            });
        }
        if state.entries.len() >= state.config.max_registrations {
            return Err(WaitRegistryError::Capacity {
                limit: state.config.max_registrations,
            });
        }
        let total_bytes = state
            .diagnostic_bytes
            .checked_add(item_bytes)
            .ok_or(WaitRegistryError::DiagnosticBytesOverflow)?;
        if total_bytes > state.config.max_diagnostic_bytes_total {
            return Err(WaitRegistryError::DiagnosticTotalLimitExceeded {
                actual: total_bytes,
                maximum: state.config.max_diagnostic_bytes_total,
            });
        }
        let generation =
            next_generation(state.generation).ok_or(WaitRegistryError::GenerationOverflow)?;
        let id = state
            .next_id
            .ok_or(WaitRegistryError::IdOverflow)
            .map(WaitRegistrationId)?;
        let was_empty = state.earliest_deadline.is_none();
        let earlier = state
            .earliest_deadline
            .is_some_and(|earliest| spec.deadline < earliest);
        let earliest_deadline = match state.earliest_deadline {
            Some(earliest) => Some(earliest.min(spec.deadline)),
            None => Some(spec.deadline),
        };
        let status = Arc::new(AtomicU8::new(REGISTRATION_ACTIVE));
        let entry = WaitEntry {
            owner: spec.owner,
            identity: spec.identity,
            deadline: spec.deadline,
            diagnostic_bytes: item_bytes,
            notifier: Arc::new(spec.notifier),
            status: Arc::clone(&status),
        };
        let notify_entry = was_empty || earlier;
        state.entries.insert(id, entry);
        state.next_id = id.get().checked_add(1).and_then(NonZeroU64::new);
        state.generation = generation;
        state.earliest_deadline = earliest_deadline;
        state.diagnostic_bytes = total_bytes;
        let notification = WaitNotification {
            kind: if was_empty {
                WaitNotificationKind::FirstDeadline
            } else if earlier {
                WaitNotificationKind::EarlierDeadline
            } else {
                WaitNotificationKind::GenerationChanged
            },
            snapshot: state.snapshot(),
        };
        // These are Arc clones of panic-safe wrappers, so capturing them
        // while the mutation lock is held cannot invoke executor code. The
        // actual callbacks/waker run only after the lock is released.
        let dispatch = WaitDispatch {
            callback: state.callback.clone(),
            waker: state.waker.clone(),
            entry: if notify_entry {
                state.entries.get(&id).map(|entry| entry.notifier.clone())
            } else {
                None
            },
            entries: Vec::new(),
            notification,
        };
        drop(state);
        // Install the Drop guard before dispatch. Notification code may
        // panic; the guard must still retire this entry before the typed
        // error is returned.
        let registration = WaitRegistration {
            registry: Arc::clone(&self.inner),
            id,
            status,
        };
        dispatch.dispatch()?;
        Ok(registration)
    }

    /// Registers one wait and attaches an exact waiter waker.
    pub fn register_with_waker(
        &self,
        spec: WaitRegistrationSpec,
        waker: &Waker,
    ) -> Result<WaitRegistration, WaitRegistryError> {
        self.register(spec.with_waker(waker)?)
    }

    /// Registers one wait and attaches an exact waiter callback.
    pub fn register_with_callback<F>(
        &self,
        spec: WaitRegistrationSpec,
        callback: F,
    ) -> Result<WaitRegistration, WaitRegistryError>
    where
        F: Fn(WaitNotification) + Send + Sync + 'static,
    {
        self.register(spec.with_callback(callback))
    }

    /// Retires an exact registration belonging to this registry.
    pub fn retire(&self, registration: &WaitRegistration) -> Result<(), WaitRegistryError> {
        if !Arc::ptr_eq(&self.inner, &registration.registry) {
            return Err(WaitRegistryError::ForeignRegistration {
                id: registration.id,
            });
        }
        self.retire_exact(registration.id, Some(&registration.status))
    }

    /// Retires an ID directly, returning an explicit unknown-ID error.
    pub fn retire_id(&self, id: WaitRegistrationId) -> Result<(), WaitRegistryError> {
        self.retire_exact(id, None)
    }

    fn retire_exact(
        &self,
        id: WaitRegistrationId,
        status: Option<&Arc<AtomicU8>>,
    ) -> Result<(), WaitRegistryError> {
        self.retire_exact_with_policy(id, status, false)
    }

    fn retire_exact_with_policy(
        &self,
        id: WaitRegistrationId,
        status: Option<&Arc<AtomicU8>>,
        allow_generation_exhaustion_cleanup: bool,
    ) -> Result<(), WaitRegistryError> {
        let mut state = lock_unpoisoned(&self.inner.state);
        if state.shutdown {
            if status.is_some_and(|value| value.load(Ordering::Acquire) != REGISTRATION_ACTIVE) {
                return Err(WaitRegistryError::AlreadyRetired { id });
            }
            return Err(WaitRegistryError::Shutdown);
        }
        let Some(entry) = state.entries.get(&id) else {
            if status.is_some_and(|value| value.load(Ordering::Acquire) != REGISTRATION_ACTIVE) {
                return Err(WaitRegistryError::AlreadyRetired { id });
            }
            return Err(WaitRegistryError::UnknownRegistration { id });
        };
        if entry.status.load(Ordering::Acquire) != REGISTRATION_ACTIVE {
            return Err(WaitRegistryError::AlreadyRetired { id });
        }
        if entry.diagnostic_bytes > state.diagnostic_bytes {
            return Err(WaitRegistryError::AccountingInvariant);
        }
        let generation = match next_generation(state.generation) {
            Some(generation) => Some(generation),
            None if allow_generation_exhaustion_cleanup => None,
            None => return Err(WaitRegistryError::GenerationOverflow),
        };
        let removed = state
            .entries
            .remove(&id)
            .ok_or(WaitRegistryError::UnknownRegistration { id })?;
        removed
            .status
            .store(REGISTRATION_RETIRED, Ordering::Release);
        state.diagnostic_bytes -= removed.diagnostic_bytes;
        state.earliest_deadline = state.entries.values().map(|entry| entry.deadline).min();
        let dispatch = generation.map(|generation| {
            state.generation = generation;
            let notification = WaitNotification {
                kind: WaitNotificationKind::GenerationChanged,
                snapshot: state.snapshot(),
            };
            WaitDispatch {
                callback: state.callback.clone(),
                waker: state.waker.clone(),
                entry: None,
                entries: Vec::new(),
                notification,
            }
        });
        drop(state);
        if let Some(dispatch) = dispatch {
            dispatch.dispatch()?;
        }
        Ok(())
    }

    /// Tightens an exact registration's deadline.
    ///
    /// Absolute deadlines may stay equal or move earlier, but may never move
    /// later.  This prevents queue delay or a provider phase from refreshing
    /// an already-admitted operation deadline.
    pub fn update_deadline(
        &self,
        registration: &WaitRegistration,
        deadline: MonotonicInstant,
    ) -> Result<WaitSnapshot, WaitRegistryError> {
        if !Arc::ptr_eq(&self.inner, &registration.registry) {
            return Err(WaitRegistryError::ForeignRegistration {
                id: registration.id,
            });
        }
        let mut state = lock_unpoisoned(&self.inner.state);
        if state.shutdown {
            if registration.status.load(Ordering::Acquire) != REGISTRATION_ACTIVE {
                return Err(WaitRegistryError::AlreadyRetired {
                    id: registration.id,
                });
            }
            return Err(WaitRegistryError::Shutdown);
        }
        let entry = state.entries.get(&registration.id).ok_or({
            WaitRegistryError::AlreadyRetired {
                id: registration.id,
            }
        })?;
        if entry.status.load(Ordering::Acquire) != REGISTRATION_ACTIVE {
            return Err(WaitRegistryError::AlreadyRetired {
                id: registration.id,
            });
        }
        if deadline > entry.deadline {
            return Err(WaitRegistryError::DeadlineReversal {
                id: registration.id,
                current: entry.deadline,
                requested: deadline,
            });
        }
        if deadline == entry.deadline {
            return Ok(state.snapshot());
        }
        let generation =
            next_generation(state.generation).ok_or(WaitRegistryError::GenerationOverflow)?;
        let previous_earliest = state.earliest_deadline;
        let entry = state
            .entries
            .get_mut(&registration.id)
            .ok_or(WaitRegistryError::AccountingInvariant)?;
        entry.deadline = deadline;
        let entry_notifier = Some(entry.notifier.clone());
        state.earliest_deadline = state.entries.values().map(|value| value.deadline).min();
        let earliest_changed = state.earliest_deadline < previous_earliest;
        state.generation = generation;
        let notification = WaitNotification {
            kind: if earliest_changed {
                WaitNotificationKind::EarlierDeadline
            } else {
                WaitNotificationKind::GenerationChanged
            },
            snapshot: state.snapshot(),
        };
        let snapshot = notification.snapshot;
        let dispatch = WaitDispatch {
            callback: state.callback.clone(),
            waker: state.waker.clone(),
            entry: entry_notifier,
            entries: Vec::new(),
            notification,
        };
        drop(state);
        dispatch.dispatch()?;
        Ok(snapshot)
    }

    /// Shuts down this registry, retiring and notifying every live waiter.
    ///
    /// The operation is all-or-nothing with respect to checked generation and
    /// bounded notification allocation.  Repeating shutdown returns an
    /// explicit error and never retains a prior registration payload.
    pub fn shutdown(&self) -> Result<WaitSnapshot, WaitRegistryError> {
        let mut state = lock_unpoisoned(&self.inner.state);
        if state.shutdown {
            return Err(WaitRegistryError::AlreadyShutdown);
        }
        let generation =
            next_generation(state.generation).ok_or(WaitRegistryError::GenerationOverflow)?;
        let mut entries = Vec::new();
        entries
            .try_reserve(state.entries.len())
            .map_err(|_| WaitRegistryError::AllocationFailure)?;
        for entry in state.entries.values() {
            entries.push(entry.notifier.clone());
        }
        for entry in state.entries.values() {
            entry.status.store(REGISTRATION_SHUTDOWN, Ordering::Release);
        }
        state.entries.clear();
        state.diagnostic_bytes = 0;
        state.earliest_deadline = None;
        state.shutdown = true;
        state.generation = generation;
        let notification = WaitNotification {
            kind: WaitNotificationKind::Shutdown,
            snapshot: state.snapshot(),
        };
        let snapshot = notification.snapshot;
        let dispatch = WaitDispatch {
            // Finalization must not keep an executor task or run owner alive
            // after the registry has retired every entry.
            callback: state.callback.take(),
            waker: state.waker.take(),
            entry: None,
            entries,
            notification,
        };
        drop(state);
        dispatch.dispatch()?;
        Ok(snapshot)
    }

    #[cfg(test)]
    fn with_generation(config: WaitRegistryConfig, generation: NonZeroU64) -> Self {
        let registry = Self::new(config);
        lock_unpoisoned(&registry.inner.state).generation = generation;
        registry
    }

    #[cfg(test)]
    fn with_next_id(config: WaitRegistryConfig, next_id: Option<NonZeroU64>) -> Self {
        let registry = Self::new(config);
        lock_unpoisoned(&registry.inner.state).next_id = next_id;
        registry
    }
}

impl WaitRegistryHandle {
    /// Returns the current bounded snapshot.
    #[must_use]
    pub fn snapshot(&self) -> WaitSnapshot {
        lock_unpoisoned(&self.inner.state).snapshot()
    }

    /// Returns whether the owner has shut down the registry.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        lock_unpoisoned(&self.inner.state).shutdown
    }

    /// Returns the retained identity/diagnostic byte count.
    #[must_use]
    pub fn diagnostic_bytes(&self) -> usize {
        lock_unpoisoned(&self.inner.state).diagnostic_bytes
    }
}

impl WaitState {
    fn snapshot(&self) -> WaitSnapshot {
        WaitSnapshot {
            registrations: self.entries.len(),
            earliest_deadline: self.earliest_deadline,
            generation: self.generation,
        }
    }
}

/// A live RAII registration.  Dropping it retires exactly its own ID.
pub struct WaitRegistration {
    registry: Arc<WaitRegistryInner>,
    id: WaitRegistrationId,
    status: Arc<AtomicU8>,
}

impl fmt::Debug for WaitRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WaitRegistration")
            .field("id", &self.id)
            .field("active", &self.is_active())
            .finish()
    }
}

impl WaitRegistration {
    /// Returns this registration's exact non-zero ID.
    #[must_use]
    pub const fn id(&self) -> WaitRegistrationId {
        self.id
    }

    /// Returns whether this exact entry is still live.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status.load(Ordering::Acquire) == REGISTRATION_ACTIVE
    }

    /// Returns the typed owner while the entry is retained.
    #[must_use]
    pub fn owner(&self) -> Option<WaitOwnerClass> {
        let state = lock_unpoisoned(&self.registry.state);
        state.entries.get(&self.id).map(|entry| entry.owner)
    }

    /// Returns the opaque identity while the entry is retained.
    #[must_use]
    pub fn identity(&self) -> Option<OpaqueWaitIdentity> {
        let state = lock_unpoisoned(&self.registry.state);
        state
            .entries
            .get(&self.id)
            .map(|entry| entry.identity.clone())
    }

    /// Returns the exact deadline while the entry is retained.
    #[must_use]
    pub fn deadline(&self) -> Option<MonotonicInstant> {
        let state = lock_unpoisoned(&self.registry.state);
        state.entries.get(&self.id).map(|entry| entry.deadline)
    }

    /// Retires the exact registration.  Repeated calls return an explicit
    /// [`WaitRegistryError::AlreadyRetired`] error.
    pub fn retire(&self) -> Result<(), WaitRegistryError> {
        let registry = WaitRegistry {
            inner: Arc::clone(&self.registry),
        };
        registry.retire(self)
    }

    /// Completes this wait and retires its exact registration.
    pub fn complete(&self) -> Result<(), WaitRegistryError> {
        self.retire()
    }

    /// Tightens this registration's absolute deadline.
    pub fn update_deadline(
        &self,
        deadline: MonotonicInstant,
    ) -> Result<WaitSnapshot, WaitRegistryError> {
        let registry = WaitRegistry {
            inner: Arc::clone(&self.registry),
        };
        registry.update_deadline(self, deadline)
    }
}

impl Drop for WaitRegistration {
    fn drop(&mut self) {
        if self.status.load(Ordering::Acquire) != REGISTRATION_ACTIVE {
            return;
        }
        let registry = WaitRegistry {
            inner: Arc::clone(&self.registry),
        };
        if let Err(payload) = catch_unwind(AssertUnwindSafe(|| {
            let _ = registry.retire_exact_with_policy(self.id, Some(&self.status), true);
        })) {
            discard_panic_payload(payload);
        }
    }
}

struct WaitDispatch {
    callback: Option<Arc<SafeCallback>>,
    waker: Option<Arc<SafeWaker>>,
    entry: Option<Arc<WaitNotifier>>,
    entries: Vec<Arc<WaitNotifier>>,
    notification: WaitNotification,
}

impl WaitDispatch {
    fn dispatch(self) -> Result<(), WaitRegistryError> {
        let notification = self.notification;
        let mut saw_panic = false;
        if let Some(callback) = self.callback {
            callback.invoke(notification, &mut saw_panic);
        }
        if let Some(waker) = self.waker {
            catch_notification(|| waker.wake_by_ref(), &mut saw_panic);
        }
        if let Some(entry) = self.entry {
            entry.notify(notification, &mut saw_panic);
        }
        for entry in self.entries {
            entry.notify(notification, &mut saw_panic);
        }
        if saw_panic {
            Err(WaitRegistryError::NotificationPanic)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "progress tests use assertion-context and bounded deterministic setup"
)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Wake, Waker};

    fn instant(value: u64) -> MonotonicInstant {
        MonotonicInstant::from_duration(std::time::Duration::from_nanos(value))
    }

    fn identity(value: u64) -> OpaqueWaitIdentity {
        OpaqueWaitIdentity::from_u64(value)
    }

    #[derive(Debug)]
    struct CountingWake {
        wakes: Arc<AtomicUsize>,
    }

    impl Wake for CountingWake {
        fn wake(self: Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::AcqRel);
        }
    }

    #[derive(Debug)]
    struct PanickingWake;

    impl Wake for PanickingWake {
        fn wake(self: Arc<Self>) {
            panic!("test waker panic");
        }
    }

    fn counting_waker(wakes: &Arc<AtomicUsize>) -> Waker {
        Waker::from(Arc::new(CountingWake {
            wakes: Arc::clone(wakes),
        }))
    }

    fn panicking_waker() -> Waker {
        Waker::from(Arc::new(PanickingWake))
    }

    #[test]
    fn progress_generations_are_checked_and_terminal_is_monotonic() {
        let owner = ProgressOwner::new();
        let handle = owner.handle();
        assert_eq!(handle.snapshot(), ProgressSnapshot::initial());
        assert_eq!(owner.advance().expect("advance").generation.get(), 2);
        let completed = owner.complete().expect("complete");
        assert_eq!(completed.terminal, ProgressTerminalState::Completed);
        assert_eq!(completed.generation.get(), 3);
        assert_eq!(handle.snapshot(), completed);
        assert_eq!(
            owner.advance(),
            Err(ProgressError::NotRunning {
                state: ProgressTerminalState::Completed
            })
        );
        assert_eq!(
            owner.fail(),
            Err(ProgressError::AlreadyTerminal {
                current: ProgressTerminalState::Completed,
                requested: ProgressTerminalState::Failed,
            })
        );
        let cancelled = ProgressOwner::new();
        assert_eq!(
            cancelled.cancel().expect("cancel"),
            ProgressSnapshot {
                generation: NonZeroU64::new(2).expect("generation"),
                terminal: ProgressTerminalState::Cancelled,
            }
        );
    }

    #[test]
    fn progress_generation_overflow_is_not_silent() {
        let owner = ProgressOwner::with_generation(NonZeroU64::new(u64::MAX).expect("nonzero"));
        assert_eq!(owner.advance(), Err(ProgressError::GenerationOverflow));
        assert_eq!(owner.snapshot().terminal, ProgressTerminalState::Running);
        assert_eq!(owner.complete(), Err(ProgressError::GenerationOverflow));
        assert_eq!(owner.snapshot().terminal, ProgressTerminalState::Running);
        assert_eq!(owner.cancel(), Err(ProgressError::GenerationOverflow));
    }

    #[test]
    fn wait_snapshot_and_earliest_deadline_changes_are_checked() {
        let registry = WaitRegistry::new(WaitRegistryConfig::with_limits(4, 16, 32, 64));
        let first = registry
            .register(WaitRegistrationSpec::new(
                WaitOwnerClass::Sleeper,
                identity(1),
                instant(20),
            ))
            .expect("first registration");
        assert_eq!(first.id().get(), 1);
        assert_eq!(registry.snapshot().registrations, 1);
        assert_eq!(registry.snapshot().earliest_deadline, Some(instant(20)));
        let second = registry
            .register(WaitRegistrationSpec::new(
                WaitOwnerClass::Scheduler,
                identity(2),
                instant(30),
            ))
            .expect("second registration");
        assert_eq!(registry.snapshot().earliest_deadline, Some(instant(20)));
        let generation_before = registry.snapshot().generation;
        let earlier = second.update_deadline(instant(10)).expect("earlier");
        assert_eq!(earlier.earliest_deadline, Some(instant(10)));
        assert!(earlier.generation > generation_before);
        assert_eq!(
            second.update_deadline(instant(11)),
            Err(WaitRegistryError::DeadlineReversal {
                id: second.id(),
                current: instant(10),
                requested: instant(11),
            })
        );
        drop(first);
        drop(second);
        assert_eq!(registry.snapshot().registrations, 0);
        assert_eq!(registry.snapshot().earliest_deadline, None);
    }

    #[test]
    fn wait_capacity_item_and_aggregate_bytes_are_bounded() {
        let registry = WaitRegistry::new(WaitRegistryConfig::with_limits(1, 8, 4, 6));
        let first = registry
            .register(WaitRegistrationSpec::new(
                WaitOwnerClass::Http,
                OpaqueWaitIdentity::new(&[1, 2]).expect("identity"),
                instant(1),
            ))
            .expect("first");
        assert_eq!(registry.diagnostic_bytes(), 2);
        assert_eq!(
            registry
                .register(WaitRegistrationSpec::new(
                    WaitOwnerClass::Http,
                    OpaqueWaitIdentity::new(&[3]).expect("identity"),
                    instant(2),
                ))
                .map(|_| ()),
            Err(WaitRegistryError::Capacity { limit: 1 })
        );
        drop(first);

        let too_large_item = WaitRegistrationSpec::new(
            WaitOwnerClass::Http,
            OpaqueWaitIdentity::new(&[1, 2, 3]).expect("identity"),
            instant(3),
        )
        .with_diagnostic_bytes(2);
        assert_eq!(
            registry.register(too_large_item).map(|_| ()),
            Err(WaitRegistryError::DiagnosticItemLimitExceeded {
                actual: 5,
                maximum: 4,
            })
        );

        let one = registry
            .register(WaitRegistrationSpec::new(
                WaitOwnerClass::Queue,
                OpaqueWaitIdentity::new(&[1, 2, 3]).expect("identity"),
                instant(4),
            ))
            .expect("one");
        assert_eq!(
            registry
                .register(WaitRegistrationSpec::new(
                    WaitOwnerClass::Queue,
                    OpaqueWaitIdentity::new(&[4, 5, 6]).expect("identity"),
                    instant(5),
                ))
                .map(|_| ()),
            Err(WaitRegistryError::Capacity { limit: 1 })
        );
        drop(one);

        let registry = WaitRegistry::new(WaitRegistryConfig::with_limits(4, 8, 8, 5));
        let one = registry
            .register(WaitRegistrationSpec::new(
                WaitOwnerClass::Queue,
                OpaqueWaitIdentity::new(&[1, 2, 3]).expect("identity"),
                instant(4),
            ))
            .expect("one");
        assert_eq!(
            registry
                .register(WaitRegistrationSpec::new(
                    WaitOwnerClass::Queue,
                    OpaqueWaitIdentity::new(&[4, 5, 6]).expect("identity"),
                    instant(5),
                ))
                .map(|_| ()),
            Err(WaitRegistryError::DiagnosticTotalLimitExceeded {
                actual: 6,
                maximum: 5,
            })
        );
        drop(one);
    }

    #[test]
    fn wait_ids_are_checked_and_never_reused() {
        let registry = WaitRegistry::new(WaitRegistryConfig::with_limits(2, 16, 16, 32));
        let first = registry
            .register(WaitRegistrationSpec::new(
                WaitOwnerClass::Provider,
                identity(1),
                instant(1),
            ))
            .expect("first");
        let id = first.id();
        first.retire().expect("retire");
        assert_eq!(
            first.retire(),
            Err(WaitRegistryError::AlreadyRetired { id })
        );
        let second = registry
            .register(WaitRegistrationSpec::new(
                WaitOwnerClass::Provider,
                identity(2),
                instant(2),
            ))
            .expect("second");
        assert_eq!(second.id().get(), id.get() + 1);
        assert_eq!(
            registry.retire_id(id),
            Err(WaitRegistryError::UnknownRegistration { id })
        );

        let max = WaitRegistry::with_generation(
            WaitRegistryConfig::with_limits(2, 16, 16, 32),
            NonZeroU64::new(u64::MAX).expect("nonzero"),
        );
        assert_eq!(
            max.register(WaitRegistrationSpec::new(
                WaitOwnerClass::Provider,
                OpaqueWaitIdentity::new(&[3]).expect("identity"),
                instant(3),
            ))
            .map(|_| ()),
            Err(WaitRegistryError::GenerationOverflow)
        );
        drop(second);
    }

    #[test]
    fn wait_id_maximum_is_allocated_once_then_exhausted() {
        let registry = WaitRegistry::with_next_id(
            WaitRegistryConfig::with_limits(2, 16, 16, 32),
            NonZeroU64::new(u64::MAX),
        );
        let registration = registry
            .register(WaitRegistrationSpec::new(
                WaitOwnerClass::Provider,
                identity(1),
                instant(1),
            ))
            .expect("maximum ID remains representable");
        assert_eq!(registration.id().get(), u64::MAX);
        registration.retire().expect("retire maximum ID");
        assert_eq!(
            registry
                .register(WaitRegistrationSpec::new(
                    WaitOwnerClass::Provider,
                    identity(2),
                    instant(2),
                ))
                .map(|_| ()),
            Err(WaitRegistryError::IdOverflow)
        );
    }

    #[test]
    fn raii_drop_still_retires_when_generation_is_exhausted() {
        let registry = WaitRegistry::new(WaitRegistryConfig::with_limits(1, 16, 16, 32));
        let registration = registry
            .register(WaitRegistrationSpec::new(
                WaitOwnerClass::Sleeper,
                identity(1),
                instant(1),
            ))
            .expect("registration");
        lock_unpoisoned(&registry.inner.state).generation = NonZeroU64::new(u64::MAX).expect("max");
        drop(registration);
        assert_eq!(registry.snapshot().registrations, 0);
        assert_eq!(registry.snapshot().generation.get(), u64::MAX);
    }

    #[test]
    fn foreign_retirement_is_rejected_without_touching_owner() {
        let a = WaitRegistry::new(WaitRegistryConfig::with_limits(2, 16, 16, 32));
        let b = WaitRegistry::new(WaitRegistryConfig::with_limits(2, 16, 16, 32));
        let registration = a
            .register(WaitRegistrationSpec::new(
                WaitOwnerClass::Barrier,
                identity(1),
                instant(4),
            ))
            .expect("registration");
        assert_eq!(
            b.retire(&registration),
            Err(WaitRegistryError::ForeignRegistration {
                id: registration.id(),
            })
        );
        assert_eq!(a.snapshot().registrations, 1);
        registration.retire().expect("owner retirement");
    }

    #[test]
    fn raii_drop_retires_exact_entry_and_updates_earliest() {
        let registry = WaitRegistry::new(WaitRegistryConfig::with_limits(4, 16, 32, 64));
        let first = registry
            .register(WaitRegistrationSpec::new(
                WaitOwnerClass::Sleeper,
                identity(1),
                instant(1),
            ))
            .expect("first");
        let second = registry
            .register(WaitRegistrationSpec::new(
                WaitOwnerClass::Sleeper,
                identity(2),
                instant(2),
            ))
            .expect("second");
        drop(first);
        assert_eq!(registry.snapshot().registrations, 1);
        assert_eq!(registry.snapshot().earliest_deadline, Some(instant(2)));
        assert_eq!(second.identity(), Some(identity(2)));
        drop(second);
        assert_eq!(
            registry.snapshot(),
            WaitSnapshot {
                registrations: 0,
                earliest_deadline: None,
                generation: NonZeroU64::new(5).expect("generation")
            }
        );
    }

    #[test]
    fn shutdown_wakes_exact_waiters_and_retains_no_entry_payload() {
        let registry = WaitRegistry::new(WaitRegistryConfig::with_limits(4, 64, 64, 128));
        let first_wakes = Arc::new(AtomicUsize::new(0));
        let second_wakes = Arc::new(AtomicUsize::new(0));
        let first_waker = counting_waker(&first_wakes);
        let second_waker = counting_waker(&second_wakes);
        let first = registry
            .register(
                WaitRegistrationSpec::new(WaitOwnerClass::Dns, identity(11), instant(10))
                    .with_waker(&first_waker)
                    .expect("first waker"),
            )
            .expect("first");
        let second = registry
            .register(
                WaitRegistrationSpec::new(WaitOwnerClass::Tls, identity(12), instant(20))
                    .with_waker(&second_waker)
                    .expect("second waker"),
            )
            .expect("second");
        assert!(first.identity().is_some());
        assert!(second.identity().is_some());
        registry.shutdown().expect("shutdown");
        assert_eq!(first_wakes.load(Ordering::Acquire), 2);
        assert_eq!(second_wakes.load(Ordering::Acquire), 1);
        assert_eq!(registry.snapshot().registrations, 0);
        assert_eq!(registry.snapshot().earliest_deadline, None);
        assert_eq!(registry.diagnostic_bytes(), 0);
        assert!(first.identity().is_none());
        assert!(second.identity().is_none());
        assert_eq!(
            first.retire(),
            Err(WaitRegistryError::AlreadyRetired { id: first.id() })
        );
        drop(first);
        drop(second);
    }

    #[test]
    fn callback_reentrancy_observes_unlocked_state() {
        let registry_slot = Arc::new(Mutex::new(None::<WaitRegistry>));
        let callback_count = Arc::new(AtomicUsize::new(0));
        let slot_for_callback = Arc::clone(&registry_slot);
        let count_for_callback = Arc::clone(&callback_count);
        let registry = WaitRegistry::with_callback(
            WaitRegistryConfig::with_limits(2, 16, 16, 32),
            move |notification| {
                count_for_callback.fetch_add(1, Ordering::AcqRel);
                let registry = slot_for_callback
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone()
                    .expect("registry installed");
                assert_eq!(registry.snapshot(), notification.snapshot);
            },
        );
        *registry_slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(registry.clone());
        let registration = registry
            .register(WaitRegistrationSpec::new(
                WaitOwnerClass::Scheduler,
                identity(7),
                instant(7),
            ))
            .expect("registration");
        assert_eq!(callback_count.load(Ordering::Acquire), 1);
        registration.retire().expect("retire");
        assert_eq!(callback_count.load(Ordering::Acquire), 2);
    }

    #[test]
    fn callback_and_waker_receive_earlier_deadline_and_shutdown() {
        let callback_count = Arc::new(AtomicUsize::new(0));
        let callback_count_clone = Arc::clone(&callback_count);
        let registry = WaitRegistry::new(WaitRegistryConfig::with_limits(4, 16, 32, 64));
        registry
            .set_callback(move |_| {
                callback_count_clone.fetch_add(1, Ordering::AcqRel);
            })
            .expect("registry callback");
        let wakes = Arc::new(AtomicUsize::new(0));
        let waker = counting_waker(&wakes);
        registry.set_waker(&waker).expect("registry waker");
        let registration = registry
            .register(WaitRegistrationSpec::new(
                WaitOwnerClass::DynamicTimer,
                identity(1),
                instant(20),
            ))
            .expect("registration");
        assert_eq!(callback_count.load(Ordering::Acquire), 1);
        assert_eq!(wakes.load(Ordering::Acquire), 1);
        registration.update_deadline(instant(10)).expect("earlier");
        assert_eq!(callback_count.load(Ordering::Acquire), 2);
        assert_eq!(wakes.load(Ordering::Acquire), 2);
        registry.shutdown().expect("shutdown");
        assert_eq!(callback_count.load(Ordering::Acquire), 3);
        assert_eq!(wakes.load(Ordering::Acquire), 3);
        drop(registration);
    }

    #[test]
    fn post_shutdown_notifier_mutation_is_typed() {
        let registry = WaitRegistry::new(WaitRegistryConfig::with_limits(2, 16, 16, 32));
        registry.set_callback(|_| {}).expect("initial callback");
        registry.clear_callback().expect("clear callback");
        registry
            .set_callback_arc(Some(Arc::new(|_| {})))
            .expect("callback arc");

        let wakes = Arc::new(AtomicUsize::new(0));
        let waker = counting_waker(&wakes);
        registry.set_waker(&waker).expect("initial waker");
        registry.clear_waker().expect("clear waker");
        registry.set_callback(|_| {}).expect("shutdown callback");
        registry.set_waker(&waker).expect("shutdown waker");
        registry.shutdown().expect("shutdown");

        assert_eq!(
            registry.set_callback(|_| {}),
            Err(WaitRegistryError::Shutdown)
        );
        assert_eq!(
            registry.set_callback_arc(Some(Arc::new(|_| {}))),
            Err(WaitRegistryError::Shutdown)
        );
        assert_eq!(registry.set_waker(&waker), Err(WaitRegistryError::Shutdown));
        assert_eq!(registry.clear_callback(), Err(WaitRegistryError::Shutdown));
        assert_eq!(registry.clear_waker(), Err(WaitRegistryError::Shutdown));
    }

    #[test]
    fn callback_panic_does_not_skip_exact_wake_or_leave_registration_live() {
        let registry = WaitRegistry::new(WaitRegistryConfig::with_limits(2, 16, 16, 32));
        let wakes = Arc::new(AtomicUsize::new(0));
        let waker = counting_waker(&wakes);
        let result = registry.register(
            WaitRegistrationSpec::new(WaitOwnerClass::Sleeper, identity(1), instant(1))
                .with_waker(&waker)
                .expect("registration waker")
                .with_callback(|_| panic!("test callback panic")),
        );
        assert!(matches!(result, Err(WaitRegistryError::NotificationPanic)));
        assert_eq!(wakes.load(Ordering::Acquire), 1);
        assert_eq!(registry.snapshot().registrations, 0);
        assert_eq!(registry.diagnostic_bytes(), 0);
    }

    #[test]
    fn waker_panic_returns_typed_error_and_drains_other_waiters() {
        let registry = WaitRegistry::new(WaitRegistryConfig::with_limits(4, 16, 16, 32));
        let first = registry
            .register(WaitRegistrationSpec::new(
                WaitOwnerClass::Sleeper,
                identity(1),
                instant(1),
            ))
            .expect("first registration");
        let panic_waker = panicking_waker();
        let second = registry
            .register(
                WaitRegistrationSpec::new(WaitOwnerClass::Sleeper, identity(2), instant(2))
                    .with_waker(&panic_waker)
                    .expect("panic waker"),
            )
            .expect("second registration");
        let normal_wakes = Arc::new(AtomicUsize::new(0));
        let normal_waker = counting_waker(&normal_wakes);
        let third = registry
            .register(
                WaitRegistrationSpec::new(WaitOwnerClass::Sleeper, identity(3), instant(3))
                    .with_waker(&normal_waker)
                    .expect("normal waker"),
            )
            .expect("third registration");

        let result = registry.shutdown();
        assert!(matches!(result, Err(WaitRegistryError::NotificationPanic)));
        assert_eq!(normal_wakes.load(Ordering::Acquire), 1);
        assert_eq!(registry.snapshot().registrations, 0);
        assert!(!first.is_active());
        assert!(!second.is_active());
        assert!(!third.is_active());
    }

    #[test]
    fn callback_panic_shutdown_returns_typed_error_and_drains_other_callbacks() {
        let registry = WaitRegistry::new(WaitRegistryConfig::with_limits(4, 16, 16, 64));
        let first = registry
            .register(WaitRegistrationSpec::new(
                WaitOwnerClass::Sleeper,
                identity(1),
                instant(1),
            ))
            .expect("first registration");
        let second = registry
            .register(
                WaitRegistrationSpec::new(WaitOwnerClass::Sleeper, identity(2), instant(2))
                    .with_callback(|_| panic!("test callback panic")),
            )
            .expect("second registration");
        let callback_runs = Arc::new(AtomicUsize::new(0));
        let callback_runs_clone = Arc::clone(&callback_runs);
        let third = registry
            .register(
                WaitRegistrationSpec::new(WaitOwnerClass::Sleeper, identity(3), instant(3))
                    .with_callback(move |_| {
                        callback_runs_clone.fetch_add(1, Ordering::AcqRel);
                    }),
            )
            .expect("third registration");

        let result = registry.shutdown();
        assert!(matches!(result, Err(WaitRegistryError::NotificationPanic)));
        assert_eq!(callback_runs.load(Ordering::Acquire), 1);
        assert_eq!(registry.snapshot().registrations, 0);
        assert!(!first.is_active());
        assert!(!second.is_active());
        assert!(!third.is_active());
    }

    #[test]
    fn handles_are_read_only_and_do_not_hold_payloads_after_shutdown() {
        let registry = WaitRegistry::new(WaitRegistryConfig::with_limits(1, 16, 16, 32));
        let handle = registry.handle();
        let registration = registry
            .register(WaitRegistrationSpec::new(
                WaitOwnerClass::Other,
                OpaqueWaitIdentity::new(&[1, 2, 3]).expect("identity"),
                instant(3),
            ))
            .expect("registration");
        assert_eq!(handle.snapshot().registrations, 1);
        registry.shutdown().expect("shutdown");
        assert_eq!(handle.snapshot().registrations, 0);
        assert_eq!(handle.diagnostic_bytes(), 0);
        assert!(registration.identity().is_none());
        drop(registration);
    }

    #[test]
    fn wait_registry_handle_can_be_used_from_a_waker_without_lock_reentry() {
        #[derive(Debug)]
        struct HandleWake {
            handle: WaitRegistryHandle,
            observed: Arc<AtomicUsize>,
        }
        impl Wake for HandleWake {
            fn wake(self: Arc<Self>) {
                self.observed
                    .store(self.handle.snapshot().registrations, Ordering::Release);
            }
        }

        let registry = WaitRegistry::new(WaitRegistryConfig::with_limits(1, 16, 16, 32));
        let observed = Arc::new(AtomicUsize::new(99));
        let waker = Waker::from(Arc::new(HandleWake {
            handle: registry.handle(),
            observed: Arc::clone(&observed),
        }));
        registry.set_waker(&waker).expect("registry waker");
        let registration = registry
            .register(WaitRegistrationSpec::new(
                WaitOwnerClass::Sleeper,
                identity(1),
                instant(1),
            ))
            .expect("registration");
        assert_eq!(observed.load(Ordering::Acquire), 1);
        drop(registration);
        assert_eq!(observed.load(Ordering::Acquire), 0);
        let _ = Context::from_waker(&waker);
    }
}
