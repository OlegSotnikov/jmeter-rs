// SPDX-License-Identifier: Apache-2.0
//! Executor-neutral sample-monitor and sampler-interruption contracts.
//!
//! A sample monitor is a lifecycle component immediately around one sampler
//! invocation.  This module intentionally does not decide how time advances,
//! how a wake is scheduled, or how an operation is cancelled.  Those choices
//! are injected through [`SampleMonitorRegistrationRegistrar`] and
//! [`SamplerInterrupt`].  The state held here is per virtual user or per
//! sampler instance; there is no process-wide registry.

#![allow(
    missing_docs,
    reason = "the public vocabulary is documented by this module and its contracts"
)]

use std::collections::BTreeSet;
use std::fmt;
use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};

use jmeter_rs_model::NodeId;

use crate::mutation::InvocationGeneration;
use crate::result_router::UserIdentity;
use crate::scheduler::Deadline;

/// Maximum number of monitor entries retained by a compiled monitor plan.
pub const DEFAULT_MAX_SAMPLE_MONITORS: usize = 256;
/// Maximum number of registrations retained by one per-user monitor set.
pub const DEFAULT_MAX_SAMPLE_REGISTRATIONS: usize = 256;
/// Maximum number of diagnostics retained by one per-user monitor set.
pub const DEFAULT_MAX_SAMPLE_DIAGNOSTICS: usize = 64;
/// Maximum aggregate diagnostic bytes retained by one per-user monitor set.
pub const DEFAULT_MAX_SAMPLE_DIAGNOSTIC_BYTES: usize = 16 * 1024;
/// Maximum source-path nodes retained in one monitor metadata record.
pub const MAX_SAMPLE_MONITOR_PATH_NODES: usize = 256;
/// Maximum class-identity bytes retained in one monitor metadata record.
pub const MAX_SAMPLE_MONITOR_CLASS_BYTES: usize = 1_024;
/// Maximum diagnostic detail bytes retained in one diagnostic.
pub const MAX_SAMPLE_MONITOR_DETAIL_BYTES: usize = 4 * 1024;

const REGISTRATION_ACTIVE: u8 = 0;
const REGISTRATION_RETIRING: u8 = 1;
const REGISTRATION_RETIRED: u8 = 2;

fn lock<T>(value: &Mutex<T>) -> MutexGuard<'_, T> {
    value
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn bounded_text(value: &str, maximum: usize) -> String {
    if value.len() <= maximum {
        return value.to_owned();
    }
    let mut end = maximum;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

fn discard_panic_payload(payload: Box<dyn std::any::Any + Send>) {
    let _ = catch_unwind(AssertUnwindSafe(|| drop(payload)));
}

/// Stable identity validation failures for the monitor boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SampleMonitorIdentityError {
    /// A required node identity was zero.
    ZeroNode { field: &'static str },
    /// A required user lifecycle identity was zero.
    ZeroUserLifecycle,
    /// A required user group identity was zero.
    ZeroUserGroup,
    /// A required user thread number was zero.
    ZeroUserThread,
    /// A required invocation generation was invalid.
    InvalidGeneration,
}

impl SampleMonitorIdentityError {
    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ZeroNode { .. } => "runtime.sample-monitor.identity.zero-node",
            Self::ZeroUserLifecycle => "runtime.sample-monitor.identity.zero-user-lifecycle",
            Self::ZeroUserGroup => "runtime.sample-monitor.identity.zero-user-group",
            Self::ZeroUserThread => "runtime.sample-monitor.identity.zero-user-thread",
            Self::InvalidGeneration => "runtime.sample-monitor.identity.invalid-generation",
        }
    }
}

impl fmt::Display for SampleMonitorIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroNode { field } => write!(formatter, "{}: {field}", self.code()),
            Self::ZeroUserLifecycle
            | Self::ZeroUserGroup
            | Self::ZeroUserThread
            | Self::InvalidGeneration => formatter.write_str(self.code()),
        }
    }
}

impl std::error::Error for SampleMonitorIdentityError {}

/// Exact identity of one sampler invocation.
///
/// The sampler node, virtual-user identity, and invocation generation are a
/// single comparison key.  A generation from another sampler or user is not
/// interchangeable with this value, even when its numeric value matches.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SampleInvocationIdentity {
    sampler_id: NodeId,
    user: UserIdentity,
    generation: InvocationGeneration,
}

impl SampleInvocationIdentity {
    /// Creates an exact, assigned invocation identity.
    pub fn new(
        sampler_id: NodeId,
        user: UserIdentity,
        generation: InvocationGeneration,
    ) -> Result<Self, SampleMonitorIdentityError> {
        if sampler_id.is_zero() {
            return Err(SampleMonitorIdentityError::ZeroNode {
                field: "sampler-id",
            });
        }
        if user.lifecycle_id == 0 {
            return Err(SampleMonitorIdentityError::ZeroUserLifecycle);
        }
        if user.group_id.is_zero() {
            return Err(SampleMonitorIdentityError::ZeroUserGroup);
        }
        if user.thread_number == 0 {
            return Err(SampleMonitorIdentityError::ZeroUserThread);
        }
        if generation.get() == 0 {
            return Err(SampleMonitorIdentityError::InvalidGeneration);
        }
        Ok(Self {
            sampler_id,
            user,
            generation,
        })
    }

    /// Returns the exact sampler node identity.
    #[must_use]
    pub const fn sampler_id(self) -> NodeId {
        self.sampler_id
    }

    /// Returns the exact virtual-user identity.
    #[must_use]
    pub const fn user(self) -> UserIdentity {
        self.user
    }

    /// Returns the exact invocation generation.
    #[must_use]
    pub const fn generation(self) -> InvocationGeneration {
        self.generation
    }
}

/// Source metadata retained for one enabled monitor.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SampleMonitorMetadata {
    source_node: NodeId,
    source_path: Box<[NodeId]>,
    class_identity: String,
    order: usize,
}

impl SampleMonitorMetadata {
    /// Creates bounded source metadata in the compiler-discovered order.
    pub fn new(
        source_node: NodeId,
        source_path: Vec<NodeId>,
        class_identity: impl Into<String>,
        order: usize,
    ) -> Result<Self, SampleMonitorError> {
        if source_node.is_zero() {
            return Err(SampleMonitorError::InvalidIdentity {
                field: "monitor-source-node",
            });
        }
        if source_path.is_empty() {
            return Err(SampleMonitorError::InvalidMetadata {
                field: "monitor-source-path",
            });
        }
        if source_path.len() > MAX_SAMPLE_MONITOR_PATH_NODES {
            return Err(SampleMonitorError::LimitExceeded {
                kind: "monitor-source-path",
                actual: source_path.len(),
                maximum: MAX_SAMPLE_MONITOR_PATH_NODES,
            });
        }
        if source_path.last().copied() != Some(source_node)
            || source_path.iter().any(|node| node.is_zero())
        {
            return Err(SampleMonitorError::InvalidMetadata {
                field: "monitor-source-path",
            });
        }
        let class_identity = class_identity.into();
        if class_identity.is_empty() {
            return Err(SampleMonitorError::InvalidMetadata {
                field: "monitor-class-identity",
            });
        }
        if class_identity.len() > MAX_SAMPLE_MONITOR_CLASS_BYTES {
            return Err(SampleMonitorError::LimitExceeded {
                kind: "monitor-class-identity",
                actual: class_identity.len(),
                maximum: MAX_SAMPLE_MONITOR_CLASS_BYTES,
            });
        }
        if class_identity.chars().any(char::is_control) {
            return Err(SampleMonitorError::InvalidMetadata {
                field: "monitor-class-identity",
            });
        }
        Ok(Self {
            source_node,
            source_path: source_path.into_boxed_slice(),
            class_identity,
            order,
        })
    }

    /// Returns the source node identity.
    #[must_use]
    pub const fn source_node(&self) -> NodeId {
        self.source_node
    }

    /// Returns the ordered source path.
    #[must_use]
    pub fn source_path(&self) -> &[NodeId] {
        &self.source_path
    }

    /// Returns the upstream class identity.
    #[must_use]
    pub fn class_identity(&self) -> &str {
        &self.class_identity
    }

    /// Returns the compiler-discovered collection order.
    #[must_use]
    pub const fn order(&self) -> usize {
        self.order
    }
}

/// A closed reason for a sampler-local interrupt request.
///
/// `SampleTimeout` is deliberately not a preprocessor or a run-control
/// signal.  `StopTestImmediate` is a separate reason even when an adapter
/// eventually cancels the same low-level operation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum InterruptReason {
    /// Interrupt only the active sample because a sample monitor expired.
    SampleTimeout,
    /// Interrupt the active sample as part of an immediate test stop.
    StopTestImmediate,
}

impl InterruptReason {
    /// Returns a stable reason code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::SampleTimeout => "sample-timeout",
            Self::StopTestImmediate => "stop-test-immediate",
        }
    }
}

/// A request sent only to the exact active sampler invocation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct InterruptRequest {
    invocation: SampleInvocationIdentity,
    reason: InterruptReason,
}

impl InterruptRequest {
    /// Creates a request with an exact invocation identity and closed reason.
    #[must_use]
    pub const fn new(invocation: SampleInvocationIdentity, reason: InterruptReason) -> Self {
        Self { invocation, reason }
    }

    /// Returns the exact invocation identity.
    #[must_use]
    pub const fn invocation(self) -> SampleInvocationIdentity {
        self.invocation
    }

    /// Returns the closed interrupt reason.
    #[must_use]
    pub const fn reason(self) -> InterruptReason {
        self.reason
    }
}

/// Typed outcomes of an interrupt request.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum InterruptOutcome {
    /// The exact active invocation accepted the interrupt request.
    Accepted,
    /// No sampler invocation is active on this per-sampler handle.
    Inactive,
    /// The request identity does not match the active invocation.
    Stale,
    /// An interrupt was already attempted for this active invocation.
    Repeated,
    /// This sampler does not expose an interrupt capability.
    Unsupported,
}

impl InterruptOutcome {
    /// Returns whether the request was accepted by the active sampler.
    #[must_use]
    pub const fn is_accepted(self) -> bool {
        matches!(self, Self::Accepted)
    }
}

/// The result of ending an active invocation on an interrupt handle.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum InterruptEndOutcome {
    /// The exact active invocation was retired.
    Ended,
    /// No invocation was active.
    Inactive,
    /// A different invocation remained active.
    Stale,
}

/// Stable failures from the sampler-local interruption operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SamplerInterruptError {
    /// The injected sampler operation returned a bounded diagnostic failure.
    Operation { diagnostic: SampleMonitorDiagnostic },
    /// The injected operation panicked while being invoked or polled.
    OperationPanicked,
}

impl SamplerInterruptError {
    /// Returns a stable machine-readable code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Operation { .. } => "runtime.sampler-interrupt.operation",
            Self::OperationPanicked => "runtime.sampler-interrupt.operation-panicked",
        }
    }
}

impl fmt::Display for SamplerInterruptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Operation { diagnostic } => write!(formatter, "{}: {diagnostic}", self.code()),
            Self::OperationPanicked => formatter.write_str(self.code()),
        }
    }
}

impl std::error::Error for SamplerInterruptError {}

/// An executor-neutral future returned by a sampler interrupt capability.
pub type SamplerInterruptFuture<'a> =
    Pin<Box<dyn Future<Output = Result<InterruptOutcome, SamplerInterruptError>> + Send + 'a>>;

/// A per-sampler capability that can interrupt one exact operation.
pub trait SamplerInterrupt: Send + Sync {
    /// Requests interruption of the operation identified by `request`.
    fn interrupt<'a>(&'a self, request: InterruptRequest) -> SamplerInterruptFuture<'a>;
}

/// Explicitly selected sampler interrupt capability.
#[derive(Clone)]
pub enum SamplerInterruptCapability {
    /// A concrete per-sampler interrupt operation.
    Supported(Arc<dyn SamplerInterrupt>),
    /// The sampler is not interruptible in this execution path.
    Unsupported,
}

impl fmt::Debug for SamplerInterruptCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SamplerInterruptCapability")
            .field(&matches!(self, Self::Supported(_)))
            .finish()
    }
}

impl SamplerInterruptCapability {
    /// Wraps a concrete interrupt operation.
    #[must_use]
    pub fn supported(value: Arc<dyn SamplerInterrupt>) -> Self {
        Self::Supported(value)
    }

    /// Returns the explicit unsupported capability.
    #[must_use]
    pub const fn unsupported() -> Self {
        Self::Unsupported
    }

    /// Returns whether a concrete operation is available.
    #[must_use]
    pub const fn is_supported(&self) -> bool {
        matches!(self, Self::Supported(_))
    }
}

/// A factory for independent per-user sampler interrupt capabilities.
pub trait SamplerInterruptFactory: Send + Sync {
    /// Creates the capability for one virtual-user identity.
    fn create_for_user(&self, user: UserIdentity) -> SamplerInterruptCapability;
}

#[derive(Clone, Copy, Debug)]
struct ActiveInterrupt {
    invocation: SampleInvocationIdentity,
    attempted: bool,
}

#[derive(Debug, Default)]
struct InterruptState {
    active: Option<ActiveInterrupt>,
}

/// Stable failures while activating a sampler invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterruptActivationError {
    /// The handle already owns a different active invocation.
    AlreadyActive {
        /// Existing exact invocation identity.
        active: SampleInvocationIdentity,
        /// Requested exact invocation identity.
        requested: SampleInvocationIdentity,
    },
}

impl InterruptActivationError {
    /// Returns a stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        "runtime.sampler-interrupt.already-active"
    }
}

impl fmt::Display for InterruptActivationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for InterruptActivationError {}

/// A per-sampler interruption handle with exact invocation state.
///
/// The handle is intentionally scoped to one sampler instance.  It cannot
/// discover another sampler, change run cancellation severity, or turn an
/// unsupported operation into a successful interrupt.
#[derive(Clone)]
pub struct SamplerInterruptHandle {
    capability: SamplerInterruptCapability,
    state: Arc<Mutex<InterruptState>>,
}

impl fmt::Debug for SamplerInterruptHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SamplerInterruptHandle")
            .field("supported", &self.capability.is_supported())
            .field("active", &self.active_invocation())
            .finish()
    }
}

impl SamplerInterruptHandle {
    /// Creates a handle from an explicit supported or unsupported capability.
    #[must_use]
    pub fn new(capability: SamplerInterruptCapability) -> Self {
        Self {
            capability,
            state: Arc::new(Mutex::new(InterruptState::default())),
        }
    }

    /// Creates an explicitly unsupported handle.
    #[must_use]
    pub fn unsupported() -> Self {
        Self::new(SamplerInterruptCapability::Unsupported)
    }

    /// Returns whether a concrete operation was injected.
    #[must_use]
    pub const fn is_supported(&self) -> bool {
        self.capability.is_supported()
    }

    /// Activates one exact sampler invocation.
    pub fn begin(
        &self,
        invocation: SampleInvocationIdentity,
    ) -> Result<(), InterruptActivationError> {
        let mut state = lock(&self.state);
        if let Some(active) = state.active {
            return Err(InterruptActivationError::AlreadyActive {
                active: active.invocation,
                requested: invocation,
            });
        }
        state.active = Some(ActiveInterrupt {
            invocation,
            attempted: false,
        });
        Ok(())
    }

    /// Ends one exact sampler invocation.
    pub fn end(&self, invocation: SampleInvocationIdentity) -> InterruptEndOutcome {
        let mut state = lock(&self.state);
        match state.active {
            None => InterruptEndOutcome::Inactive,
            Some(active) if active.invocation != invocation => InterruptEndOutcome::Stale,
            Some(_) => {
                state.active = None;
                InterruptEndOutcome::Ended
            }
        }
    }

    /// Returns the active exact invocation, if any.
    #[must_use]
    pub fn active_invocation(&self) -> Option<SampleInvocationIdentity> {
        lock(&self.state).active.map(|active| active.invocation)
    }

    /// Requests one sampler-local interrupt with typed identity outcomes.
    pub fn request_interrupt(&self, request: InterruptRequest) -> SamplerInterruptFuture<'_> {
        Box::pin(self.request_interrupt_async(request))
    }

    /// Alias emphasizing that the request is a capability call, not run
    /// cancellation.
    pub fn interrupt(&self, request: InterruptRequest) -> SamplerInterruptFuture<'_> {
        self.request_interrupt(request)
    }

    async fn request_interrupt_async(
        &self,
        request: InterruptRequest,
    ) -> Result<InterruptOutcome, SamplerInterruptError> {
        if !self.capability.is_supported() {
            return Ok(InterruptOutcome::Unsupported);
        }

        let capability = {
            let mut state = lock(&self.state);
            let Some(active) = state.active.as_mut() else {
                return Ok(InterruptOutcome::Inactive);
            };
            if active.invocation != request.invocation {
                return Ok(InterruptOutcome::Stale);
            }
            if active.attempted {
                return Ok(InterruptOutcome::Repeated);
            }
            // Reserve the one request before yielding to the injected future.
            // A second concurrent caller therefore receives `Repeated`.
            active.attempted = true;
            match &self.capability {
                SamplerInterruptCapability::Supported(capability) => Arc::clone(capability),
                SamplerInterruptCapability::Unsupported => {
                    return Ok(InterruptOutcome::Unsupported);
                }
            }
        };

        let future = catch_unwind(AssertUnwindSafe(|| capability.interrupt(request))).map_err(
            |payload| {
                discard_panic_payload(payload);
                SamplerInterruptError::OperationPanicked
            },
        )?;
        PanicSafeFuture::new(future)
            .await
            .map_err(|()| SamplerInterruptError::OperationPanicked)?
    }
}

/// A bounded diagnostic retained by this module.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SampleMonitorDiagnostic {
    code: &'static str,
    detail: String,
}

impl SampleMonitorDiagnostic {
    /// Creates a diagnostic with bounded detail.
    #[must_use]
    pub fn new(code: &'static str, detail: &str) -> Self {
        Self {
            code,
            detail: bounded_text(detail, MAX_SAMPLE_MONITOR_DETAIL_BYTES),
        }
    }

    /// Returns the stable diagnostic code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// Returns bounded diagnostic detail.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// Returns the retained UTF-8 byte count.
    #[must_use]
    pub const fn byte_len(&self) -> usize {
        self.detail.len()
    }
}

impl fmt::Debug for SampleMonitorDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SampleMonitorDiagnostic")
            .field("code", &self.code)
            .field("detail_bytes", &self.detail.len())
            .finish()
    }
}

impl fmt::Display for SampleMonitorDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.detail.is_empty() {
            formatter.write_str(self.code)
        } else {
            write!(formatter, "{}: {}", self.code, self.detail)
        }
    }
}

/// Stable registration-retirement failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistrationError {
    /// The registration ID was zero.
    InvalidId,
    /// The owner rejected retirement with a bounded diagnostic.
    OwnerRejected { diagnostic: SampleMonitorDiagnostic },
    /// The owner panicked; the panic was contained and the handle remains
    /// retryable for an explicit caller.
    OwnerPanicked,
    /// A registrar returned a handle for a different invocation or monitor.
    WrongIdentity,
}

impl RegistrationError {
    /// Returns a stable machine-readable code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidId => "runtime.sample-monitor.registration.invalid-id",
            Self::OwnerRejected { .. } => "runtime.sample-monitor.registration.owner-rejected",
            Self::OwnerPanicked => "runtime.sample-monitor.registration.owner-panicked",
            Self::WrongIdentity => "runtime.sample-monitor.registration.wrong-identity",
        }
    }
}

impl fmt::Display for RegistrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OwnerRejected { diagnostic } => {
                write!(formatter, "{}: {diagnostic}", self.code())
            }
            _ => formatter.write_str(self.code()),
        }
    }
}

impl std::error::Error for RegistrationError {}

/// A nonzero registration identity allocated by an injected registrar.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RegistrationId(u64);

impl RegistrationId {
    /// Creates a checked nonzero registration ID.
    pub fn new(value: u64) -> Result<Self, RegistrationError> {
        if value == 0 {
            Err(RegistrationError::InvalidId)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the numeric registration ID.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Result of one explicit registration retirement call.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RegistrationRetireOutcome {
    /// The injected owner removed this registration.
    Retired,
    /// The handle had already been retired, or the owner reported it absent.
    AlreadyRetired,
}

/// An owner of one bounded registration ID.
pub trait RegistrationRetirer: Send + Sync {
    /// Retires exactly `id`; it must not discover or signal unrelated work.
    fn retire(&self, id: RegistrationId) -> Result<RegistrationRetireOutcome, RegistrationError>;
}

impl<F> RegistrationRetirer for F
where
    F: Fn(RegistrationId) -> Result<RegistrationRetireOutcome, RegistrationError> + Send + Sync,
{
    fn retire(&self, id: RegistrationId) -> Result<RegistrationRetireOutcome, RegistrationError> {
        self(id)
    }
}

/// A finite wake-registration request supplied by a sample monitor.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SampleMonitorRegistrationRequest {
    invocation: SampleInvocationIdentity,
    monitor_node: NodeId,
    monitor_order: usize,
    deadline: Deadline,
    reason: InterruptReason,
}

impl SampleMonitorRegistrationRequest {
    /// Creates a request for one exact monitor and sampler invocation.
    #[must_use]
    pub const fn new(
        invocation: SampleInvocationIdentity,
        monitor_node: NodeId,
        monitor_order: usize,
        deadline: Deadline,
        reason: InterruptReason,
    ) -> Self {
        Self {
            invocation,
            monitor_node,
            monitor_order,
            deadline,
            reason,
        }
    }

    /// Returns the exact sampler invocation.
    #[must_use]
    pub const fn invocation(self) -> SampleInvocationIdentity {
        self.invocation
    }

    /// Returns the exact source monitor node.
    #[must_use]
    pub const fn monitor_node(self) -> NodeId {
        self.monitor_node
    }

    /// Returns source collection order metadata.
    #[must_use]
    pub const fn monitor_order(self) -> usize {
        self.monitor_order
    }

    /// Returns the absolute injected deadline.
    #[must_use]
    pub const fn deadline(self) -> Deadline {
        self.deadline
    }

    /// Returns the exact interrupt reason.
    #[must_use]
    pub const fn reason(self) -> InterruptReason {
        self.reason
    }
}

/// A linear registration handle.
///
/// Explicit [`Self::retire`] is authoritative and retryable after a bounded
/// owner failure.  [`Drop`] performs one panic-contained best-effort attempt
/// only; it cannot report or hide an explicit cleanup failure.
pub struct SampleMonitorRegistration {
    id: RegistrationId,
    request: SampleMonitorRegistrationRequest,
    owner: Arc<dyn RegistrationRetirer>,
    status: AtomicU8,
    attempts: AtomicU64,
}

impl fmt::Debug for SampleMonitorRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SampleMonitorRegistration")
            .field("id", &self.id)
            .field("request", &self.request)
            .field("active", &self.is_active())
            .finish()
    }
}

impl SampleMonitorRegistration {
    /// Creates a registration owned by one exact retirement callback.
    #[must_use]
    pub fn new(
        id: RegistrationId,
        request: SampleMonitorRegistrationRequest,
        owner: Arc<dyn RegistrationRetirer>,
    ) -> Self {
        Self {
            id,
            request,
            owner,
            status: AtomicU8::new(REGISTRATION_ACTIVE),
            attempts: AtomicU64::new(0),
        }
    }

    /// Returns the exact registration identity.
    #[must_use]
    pub const fn id(&self) -> RegistrationId {
        self.id
    }

    /// Returns the exact bounded registration request.
    #[must_use]
    pub const fn request(&self) -> SampleMonitorRegistrationRequest {
        self.request
    }

    /// Returns whether explicit retirement is still required.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status.load(Ordering::Acquire) != REGISTRATION_RETIRED
    }

    /// Returns the number of explicit/drop retirement attempts.
    #[must_use]
    pub fn retirement_attempts(&self) -> u64 {
        self.attempts.load(Ordering::Acquire)
    }

    /// Retires the exact registration once, with retry after owner failure.
    pub fn retire(&self) -> Result<RegistrationRetireOutcome, RegistrationError> {
        if self
            .status
            .compare_exchange(
                REGISTRATION_ACTIVE,
                REGISTRATION_RETIRING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return Ok(RegistrationRetireOutcome::AlreadyRetired);
        }
        let _ = self
            .attempts
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            });
        let result = catch_unwind(AssertUnwindSafe(|| self.owner.retire(self.id)));
        match result {
            Ok(Ok(outcome)) => {
                self.status.store(REGISTRATION_RETIRED, Ordering::Release);
                Ok(outcome)
            }
            Ok(Err(error)) => {
                self.status.store(REGISTRATION_ACTIVE, Ordering::Release);
                Err(error)
            }
            Err(payload) => {
                discard_panic_payload(payload);
                self.status.store(REGISTRATION_ACTIVE, Ordering::Release);
                Err(RegistrationError::OwnerPanicked)
            }
        }
    }
}

impl Drop for SampleMonitorRegistration {
    fn drop(&mut self) {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            let _ = self.retire();
        }));
    }
}

/// A registration capability injected by the scheduler/application edge.
pub trait SampleMonitorRegistrationRegistrar: Send + Sync {
    /// Registers one finite request and returns its linear retirement handle.
    fn register(
        &self,
        request: SampleMonitorRegistrationRequest,
    ) -> Result<SampleMonitorRegistration, RegistrationError>;
}

impl<F> SampleMonitorRegistrationRegistrar for F
where
    F: Fn(SampleMonitorRegistrationRequest) -> Result<SampleMonitorRegistration, RegistrationError>
        + Send
        + Sync,
{
    fn register(
        &self,
        request: SampleMonitorRegistrationRequest,
    ) -> Result<SampleMonitorRegistration, RegistrationError> {
        self(request)
    }
}

/// Context supplied to one monitor hook.
#[derive(Clone, Copy)]
pub struct SampleMonitorHookContext<'a> {
    invocation: SampleInvocationIdentity,
    metadata: &'a SampleMonitorMetadata,
    interrupt: &'a SamplerInterruptHandle,
    registrar: &'a dyn SampleMonitorRegistrationRegistrar,
}

impl<'a> fmt::Debug for SampleMonitorHookContext<'a> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SampleMonitorHookContext")
            .field("invocation", &self.invocation)
            .field("monitor", &self.metadata.source_node())
            .finish()
    }
}

impl<'a> SampleMonitorHookContext<'a> {
    fn new(
        invocation: SampleInvocationIdentity,
        metadata: &'a SampleMonitorMetadata,
        interrupt: &'a SamplerInterruptHandle,
        registrar: &'a dyn SampleMonitorRegistrationRegistrar,
    ) -> Self {
        Self {
            invocation,
            metadata,
            interrupt,
            registrar,
        }
    }

    /// Returns the exact active invocation identity.
    #[must_use]
    pub const fn invocation(self) -> SampleInvocationIdentity {
        self.invocation
    }

    /// Returns source metadata for this monitor.
    #[must_use]
    pub fn metadata(self) -> &'a SampleMonitorMetadata {
        self.metadata
    }

    /// Returns the per-sampler interrupt handle.
    #[must_use]
    pub fn interrupt(self) -> &'a SamplerInterruptHandle {
        self.interrupt
    }

    /// Returns the injected finite-registration capability.
    #[must_use]
    pub fn registrar(self) -> &'a dyn SampleMonitorRegistrationRegistrar {
        self.registrar
    }
}

/// Result of one monitor start hook.
#[derive(Default)]
pub struct SampleMonitorStart {
    registrations: Vec<SampleMonitorRegistration>,
    diagnostics: Vec<SampleMonitorDiagnostic>,
    registration_overflowed: bool,
    diagnostic_overflowed: bool,
}

impl fmt::Debug for SampleMonitorStart {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SampleMonitorStart")
            .field("registrations", &self.registrations.len())
            .field("diagnostics", &self.diagnostics.len())
            .field("registration_overflowed", &self.registration_overflowed)
            .field("diagnostic_overflowed", &self.diagnostic_overflowed)
            .finish()
    }
}

impl SampleMonitorStart {
    /// Returns an empty successful start result.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            registrations: Vec::new(),
            diagnostics: Vec::new(),
            registration_overflowed: false,
            diagnostic_overflowed: false,
        }
    }

    /// Adds one registration for lifecycle ownership.
    pub fn push_registration(&mut self, registration: SampleMonitorRegistration) {
        if self.registrations.len() < DEFAULT_MAX_SAMPLE_REGISTRATIONS {
            self.registrations.push(registration);
        } else {
            self.registration_overflowed = true;
            drop(registration);
        }
    }

    /// Adds one bounded diagnostic.
    pub fn push_diagnostic(&mut self, diagnostic: SampleMonitorDiagnostic) {
        if self.diagnostics.len() < DEFAULT_MAX_SAMPLE_DIAGNOSTICS {
            self.diagnostics.push(diagnostic);
        } else {
            self.diagnostic_overflowed = true;
        }
    }

    /// Returns whether the hard registration bound was exceeded.
    #[must_use]
    pub const fn registration_overflowed(&self) -> bool {
        self.registration_overflowed
    }

    /// Returns whether the hard diagnostic bound was exceeded.
    #[must_use]
    pub const fn diagnostic_overflowed(&self) -> bool {
        self.diagnostic_overflowed
    }

    fn into_parts(
        self,
    ) -> (
        Vec<SampleMonitorRegistration>,
        Vec<SampleMonitorDiagnostic>,
        bool,
        bool,
    ) {
        (
            self.registrations,
            self.diagnostics,
            self.registration_overflowed,
            self.diagnostic_overflowed,
        )
    }
}

/// An executor-neutral monitor hook future.
pub type SampleMonitorFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, SampleMonitorError>> + Send + 'a>>;

/// A per-user sample monitor instance.
pub trait SampleMonitor: Send + Sync {
    /// Runs immediately before the sampler operation.
    fn sample_starting<'a>(
        &'a self,
        context: SampleMonitorHookContext<'a>,
    ) -> SampleMonitorFuture<'a, SampleMonitorStart>;

    /// Runs from the sampler's finally path before result-dependent phases.
    fn sample_ended<'a>(
        &'a self,
        context: SampleMonitorHookContext<'a>,
    ) -> SampleMonitorFuture<'a, ()>;
}

/// A factory for independent per-user monitor instances.
pub trait SampleMonitorFactory: Send + Sync {
    /// Creates the monitor instance for one exact virtual-user identity.
    fn create_for_user(
        &self,
        user: UserIdentity,
    ) -> Result<Arc<dyn SampleMonitor>, SampleMonitorError>;
}

/// A source metadata/factory pair in compiler-discovered order.
pub struct SampleMonitorFactorySpec {
    metadata: SampleMonitorMetadata,
    factory: Arc<dyn SampleMonitorFactory>,
}

impl fmt::Debug for SampleMonitorFactorySpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SampleMonitorFactorySpec")
            .field("metadata", &self.metadata)
            .finish_non_exhaustive()
    }
}

impl SampleMonitorFactorySpec {
    /// Creates one source-ordered factory specification.
    #[must_use]
    pub fn new(metadata: SampleMonitorMetadata, factory: Arc<dyn SampleMonitorFactory>) -> Self {
        Self { metadata, factory }
    }

    /// Returns source metadata.
    #[must_use]
    pub const fn metadata(&self) -> &SampleMonitorMetadata {
        &self.metadata
    }
}

/// Bounded monitor-plan limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SampleMonitorLimits {
    /// Maximum monitor entries in one plan.
    pub max_monitors: usize,
    /// Maximum live/accepted registrations in one user set.
    pub max_registrations: usize,
    /// Maximum retained diagnostics in one user set.
    pub max_diagnostics: usize,
    /// Maximum aggregate diagnostic bytes in one user set.
    pub max_diagnostic_bytes: usize,
}

impl Default for SampleMonitorLimits {
    fn default() -> Self {
        Self {
            max_monitors: DEFAULT_MAX_SAMPLE_MONITORS,
            max_registrations: DEFAULT_MAX_SAMPLE_REGISTRATIONS,
            max_diagnostics: DEFAULT_MAX_SAMPLE_DIAGNOSTICS,
            max_diagnostic_bytes: DEFAULT_MAX_SAMPLE_DIAGNOSTIC_BYTES,
        }
    }
}

impl SampleMonitorLimits {
    fn validate(self) -> Result<(), SampleMonitorError> {
        // Zero is a valid finite capacity: it admits an empty plan or a
        // monitor set which is not allowed to retain registrations or
        // diagnostics.  No arithmetic or allocation relies on a non-zero
        // capacity.
        let _ = self;
        Ok(())
    }
}

/// Accounting retained for one monitor lifecycle.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SampleMonitorAccounting {
    /// Number of start hooks invoked.
    pub start_hooks: usize,
    /// Number of end hooks invoked.
    pub end_hooks: usize,
    /// Number of registrations accepted by monitor starts.
    pub registrations: usize,
    /// Number of explicit/drop retirement attempts.
    pub retirement_attempts: usize,
    /// Number of successful/absent retirement outcomes.
    pub retired_registrations: usize,
    /// Number of retirement failures preserved in cleanup reports.
    pub retirement_failures: usize,
    /// Number of diagnostics retained.
    pub diagnostics: usize,
    /// Aggregate diagnostic bytes retained.
    pub diagnostic_bytes: usize,
}

impl SampleMonitorAccounting {
    fn increment(value: &mut usize, field: &'static str) -> Result<(), SampleMonitorError> {
        *value = value
            .checked_add(1)
            .ok_or(SampleMonitorError::AccountingOverflow { field })?;
        Ok(())
    }

    fn start_hook(&mut self) -> Result<(), SampleMonitorError> {
        Self::increment(&mut self.start_hooks, "start-hooks")
    }

    fn end_hook(&mut self) -> Result<(), SampleMonitorError> {
        Self::increment(&mut self.end_hooks, "end-hooks")
    }

    fn registration(&mut self) -> Result<(), SampleMonitorError> {
        Self::increment(&mut self.registrations, "registrations")
    }

    fn retirement_attempt(&mut self) -> Result<(), SampleMonitorError> {
        Self::increment(&mut self.retirement_attempts, "retirement-attempts")
    }

    fn retired(&mut self) -> Result<(), SampleMonitorError> {
        Self::increment(&mut self.retired_registrations, "retired-registrations")
    }

    fn retirement_failure(&mut self) -> Result<(), SampleMonitorError> {
        Self::increment(&mut self.retirement_failures, "retirement-failures")
    }

    fn diagnostic(
        &mut self,
        diagnostic: &SampleMonitorDiagnostic,
        limits: SampleMonitorLimits,
    ) -> Result<(), SampleMonitorError> {
        let count =
            self.diagnostics
                .checked_add(1)
                .ok_or(SampleMonitorError::AccountingOverflow {
                    field: "diagnostics",
                })?;
        let bytes = self
            .diagnostic_bytes
            .checked_add(diagnostic.byte_len())
            .ok_or(SampleMonitorError::AccountingOverflow {
                field: "diagnostic-bytes",
            })?;
        if count > limits.max_diagnostics {
            return Err(SampleMonitorError::LimitExceeded {
                kind: "diagnostics",
                actual: count,
                maximum: limits.max_diagnostics,
            });
        }
        if bytes > limits.max_diagnostic_bytes {
            return Err(SampleMonitorError::LimitExceeded {
                kind: "diagnostic-bytes",
                actual: bytes,
                maximum: limits.max_diagnostic_bytes,
            });
        }
        self.diagnostics = count;
        self.diagnostic_bytes = bytes;
        Ok(())
    }
}

/// Stable failures raised by monitor construction, identity, hooks, or bounds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SampleMonitorError {
    /// A required identity was invalid.
    InvalidIdentity { field: &'static str },
    /// A metadata value was malformed.
    InvalidMetadata { field: &'static str },
    /// Limits were zero or otherwise unusable.
    InvalidLimits { field: &'static str },
    /// A bounded resource limit was exceeded.
    LimitExceeded {
        /// Stable bounded-resource identifier.
        kind: &'static str,
        /// Attempted count/bytes.
        actual: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// A checked accounting counter overflowed.
    AccountingOverflow { field: &'static str },
    /// A factory returned an explicit failure.
    FactoryFailed { diagnostic: SampleMonitorDiagnostic },
    /// A factory panicked; its panic was contained.
    FactoryPanicked,
    /// A hook returned an explicit failure.
    HookFailed { diagnostic: SampleMonitorDiagnostic },
    /// A hook panicked; its panic was contained.
    HookPanicked,
    /// A registration boundary failed.
    Registration(RegistrationError),
}

impl SampleMonitorError {
    /// Returns a stable machine-readable code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidIdentity { .. } => "runtime.sample-monitor.identity.invalid",
            Self::InvalidMetadata { .. } => "runtime.sample-monitor.metadata.invalid",
            Self::InvalidLimits { .. } => "runtime.sample-monitor.limits.invalid",
            Self::LimitExceeded { .. } => "runtime.sample-monitor.limit",
            Self::AccountingOverflow { .. } => "runtime.sample-monitor.accounting-overflow",
            Self::FactoryFailed { .. } => "runtime.sample-monitor.factory-failed",
            Self::FactoryPanicked => "runtime.sample-monitor.factory-panicked",
            Self::HookFailed { .. } => "runtime.sample-monitor.hook-failed",
            Self::HookPanicked => "runtime.sample-monitor.hook-panicked",
            Self::Registration(error) => error.code(),
        }
    }
}

impl fmt::Display for SampleMonitorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentity { field }
            | Self::InvalidMetadata { field }
            | Self::InvalidLimits { field } => write!(formatter, "{}: {field}", self.code()),
            Self::LimitExceeded {
                kind,
                actual,
                maximum,
            } => write!(formatter, "{}: {kind} {actual}>{maximum}", self.code()),
            Self::AccountingOverflow { field } => write!(formatter, "{}: {field}", self.code()),
            Self::FactoryFailed { diagnostic } | Self::HookFailed { diagnostic } => {
                write!(formatter, "{}: {diagnostic}", self.code())
            }
            Self::FactoryPanicked | Self::HookPanicked => formatter.write_str(self.code()),
            Self::Registration(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for SampleMonitorError {}

/// A source-ordered monitor plan.
#[derive(Debug)]
pub struct SampleMonitorPlan {
    specs: Vec<SampleMonitorFactorySpec>,
    limits: SampleMonitorLimits,
}

impl SampleMonitorPlan {
    /// Creates a monitor plan with default finite bounds.
    pub fn new(specs: Vec<SampleMonitorFactorySpec>) -> Result<Self, SampleMonitorError> {
        Self::with_limits(specs, SampleMonitorLimits::default())
    }

    /// Creates a monitor plan with explicit finite bounds.
    pub fn with_limits(
        specs: Vec<SampleMonitorFactorySpec>,
        limits: SampleMonitorLimits,
    ) -> Result<Self, SampleMonitorError> {
        limits.validate()?;
        if specs.len() > limits.max_monitors {
            return Err(SampleMonitorError::LimitExceeded {
                kind: "monitors",
                actual: specs.len(),
                maximum: limits.max_monitors,
            });
        }
        let mut nodes = BTreeSet::new();
        for spec in &specs {
            if !nodes.insert(spec.metadata.source_node()) {
                return Err(SampleMonitorError::InvalidMetadata {
                    field: "duplicate-monitor-node",
                });
            }
        }
        Ok(Self { specs, limits })
    }

    /// Returns the source-ordered monitor specifications.
    #[must_use]
    pub fn specs(&self) -> &[SampleMonitorFactorySpec] {
        &self.specs
    }

    /// Returns the active finite limits.
    #[must_use]
    pub const fn limits(&self) -> SampleMonitorLimits {
        self.limits
    }

    /// Instantiates independent monitor state for one virtual user.
    pub fn instantiate_for_user(
        &self,
        user: UserIdentity,
    ) -> Result<SampleMonitorInstances, SampleMonitorError> {
        if user.lifecycle_id == 0 || user.group_id.is_zero() || user.thread_number == 0 {
            return Err(SampleMonitorError::InvalidIdentity {
                field: "monitor-user",
            });
        }
        let mut entries = Vec::new();
        if entries.try_reserve(self.specs.len()).is_err() {
            return Err(SampleMonitorError::LimitExceeded {
                kind: "monitor-allocation",
                actual: self.specs.len(),
                maximum: self.limits.max_monitors,
            });
        }
        for spec in &self.specs {
            let factory_result =
                catch_unwind(AssertUnwindSafe(|| spec.factory.create_for_user(user)));
            let monitor = match factory_result {
                Ok(Ok(monitor)) => monitor,
                Ok(Err(error)) => return Err(error),
                Err(payload) => {
                    discard_panic_payload(payload);
                    return Err(SampleMonitorError::FactoryPanicked);
                }
            };
            entries.push(MonitorEntry {
                metadata: spec.metadata.clone(),
                monitor,
                started: false,
                registrations: Vec::new(),
            });
        }
        Ok(SampleMonitorInstances {
            user,
            limits: self.limits,
            entries,
            active: None,
            accounting: SampleMonitorAccounting::default(),
        })
    }
}

struct MonitorEntry {
    metadata: SampleMonitorMetadata,
    monitor: Arc<dyn SampleMonitor>,
    started: bool,
    registrations: Vec<SampleMonitorRegistration>,
}

impl fmt::Debug for MonitorEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MonitorEntry")
            .field("metadata", &self.metadata)
            .field("started", &self.started)
            .field("registrations", &self.registrations.len())
            .finish_non_exhaustive()
    }
}

/// Cleanup phase attached to a bounded cleanup failure.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SampleMonitorCleanupPhase {
    /// The monitor end hook failed or panicked.
    EndHook,
    /// An injected registration owner failed to retire an exact registration.
    RegistrationRetirement,
}

/// One bounded secondary cleanup failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SampleMonitorCleanupFailure {
    /// Monitor source node associated with the cleanup attempt.
    pub monitor_node: NodeId,
    /// Cleanup phase which failed.
    pub phase: SampleMonitorCleanupPhase,
    /// Bounded failure detail.
    pub error: SampleMonitorError,
}

/// Bounded secondary cleanup accounting.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SampleMonitorCleanup {
    failures: Vec<SampleMonitorCleanupFailure>,
    omitted_failures: usize,
}

impl SampleMonitorCleanup {
    /// Returns retained cleanup failures in source/attempt order.
    #[must_use]
    pub fn failures(&self) -> &[SampleMonitorCleanupFailure] {
        &self.failures
    }

    /// Returns the number of failures omitted by the diagnostic bound.
    #[must_use]
    pub const fn omitted_failures(&self) -> usize {
        self.omitted_failures
    }

    /// Returns whether cleanup was fully successful.
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.failures.is_empty() && self.omitted_failures == 0
    }

    fn push(&mut self, failure: SampleMonitorCleanupFailure, maximum: usize) {
        if self.failures.len() < maximum {
            self.failures.push(failure);
        } else {
            self.omitted_failures = self.omitted_failures.saturating_add(1);
        }
    }
}

/// Result of ending a monitor collection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SampleMonitorEndReport {
    /// End lifecycle classification.
    pub status: MonitorEndStatus,
    /// Number of successfully ended monitor hooks.
    pub ended_monitors: usize,
    /// Ordered monitor metadata whose end hooks ran.
    pub ended: Vec<SampleMonitorMetadata>,
    /// Bounded secondary cleanup failures; never a replacement for a sampler
    /// primary failure held by the caller.
    pub cleanup: SampleMonitorCleanup,
    /// Bounded diagnostics emitted by end hooks.
    pub diagnostics: Vec<SampleMonitorDiagnostic>,
    /// Accounting after the end lifecycle.
    pub accounting: SampleMonitorAccounting,
}

/// End lifecycle classification.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MonitorEndStatus {
    /// The exact active invocation was ended.
    Ended,
    /// There was no active monitor invocation.
    Inactive,
    /// A different invocation remained active and was not cleaned up.
    Stale,
}

/// Start failures preserve the primary hook/factory failure and retain cleanup
/// failures as bounded secondary information.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SampleMonitorLifecycleError {
    /// The monitor collection already owns an active invocation.
    AlreadyActive {
        /// Existing exact invocation identity.
        active: SampleInvocationIdentity,
        /// Requested exact invocation identity.
        requested: SampleInvocationIdentity,
    },
    /// The sampler interrupt handle was not activated for this invocation.
    InterruptInactive {
        /// Invocation that could not be started.
        invocation: SampleInvocationIdentity,
    },
    /// The sampler interrupt handle belongs to another invocation.
    InterruptStale {
        /// Requested invocation identity.
        requested: SampleInvocationIdentity,
        /// Active invocation identity.
        active: SampleInvocationIdentity,
    },
    /// A monitor start failed; prior monitor cleanup was still attempted.
    StartFailed {
        /// Source node whose start failed.
        monitor_node: NodeId,
        /// Primary start failure, preserved exactly.
        primary: Box<SampleMonitorError>,
        /// Secondary cleanup failures.
        cleanup: SampleMonitorCleanup,
    },
    /// A lifecycle operation hit a bounded resource/invariant error.
    Contract(SampleMonitorError),
}

impl SampleMonitorLifecycleError {
    /// Returns a stable machine-readable code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::AlreadyActive { .. } => "runtime.sample-monitor.already-active",
            Self::InterruptInactive { .. } => "runtime.sample-monitor.interrupt-inactive",
            Self::InterruptStale { .. } => "runtime.sample-monitor.interrupt-stale",
            Self::StartFailed { .. } => "runtime.sample-monitor.start-failed",
            Self::Contract(error) => error.code(),
        }
    }

    /// Returns the preserved primary start failure, if any.
    #[must_use]
    pub fn primary(&self) -> Option<&SampleMonitorError> {
        match self {
            Self::StartFailed { primary, .. } => Some(primary),
            _ => None,
        }
    }

    /// Returns bounded secondary cleanup information, if any.
    #[must_use]
    pub fn cleanup(&self) -> Option<&SampleMonitorCleanup> {
        match self {
            Self::StartFailed { cleanup, .. } => Some(cleanup),
            _ => None,
        }
    }
}

impl fmt::Display for SampleMonitorLifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyActive { .. }
            | Self::InterruptInactive { .. }
            | Self::InterruptStale { .. } => formatter.write_str(self.code()),
            Self::StartFailed {
                monitor_node,
                primary,
                cleanup,
            } => write!(
                formatter,
                "{}: monitor={monitor_node}, primary={primary}, cleanup_failures={}",
                self.code(),
                cleanup.failures.len() + cleanup.omitted_failures
            ),
            Self::Contract(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for SampleMonitorLifecycleError {}

/// A per-user, source-ordered collection of monitor instances.
pub struct SampleMonitorInstances {
    user: UserIdentity,
    limits: SampleMonitorLimits,
    entries: Vec<MonitorEntry>,
    active: Option<SampleInvocationIdentity>,
    accounting: SampleMonitorAccounting,
}

impl fmt::Debug for SampleMonitorInstances {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SampleMonitorInstances")
            .field("user", &self.user)
            .field("active", &self.active)
            .field("entries", &self.entries)
            .field("accounting", &self.accounting)
            .finish()
    }
}

impl SampleMonitorInstances {
    /// Returns the virtual-user identity owning these instances.
    #[must_use]
    pub const fn user(&self) -> UserIdentity {
        self.user
    }

    /// Returns source-ordered metadata for all enabled monitors.
    #[must_use]
    pub fn metadata(&self) -> Vec<SampleMonitorMetadata> {
        self.entries
            .iter()
            .map(|entry| entry.metadata.clone())
            .collect()
    }

    /// Returns the currently active monitor invocation, if any.
    #[must_use]
    pub const fn active_invocation(&self) -> Option<SampleInvocationIdentity> {
        self.active
    }

    /// Returns bounded lifecycle accounting.
    #[must_use]
    pub const fn accounting(&self) -> SampleMonitorAccounting {
        self.accounting
    }

    /// Starts every monitor in exact source collection order.
    pub async fn sample_starting(
        &mut self,
        invocation: SampleInvocationIdentity,
        interrupt: &SamplerInterruptHandle,
        registrar: &dyn SampleMonitorRegistrationRegistrar,
    ) -> Result<SampleMonitorStartReport, SampleMonitorLifecycleError> {
        if let Some(active) = self.active {
            return Err(SampleMonitorLifecycleError::AlreadyActive {
                active,
                requested: invocation,
            });
        }
        match interrupt.active_invocation() {
            None => {
                return Err(SampleMonitorLifecycleError::InterruptInactive { invocation });
            }
            Some(active) if active != invocation => {
                return Err(SampleMonitorLifecycleError::InterruptStale {
                    requested: invocation,
                    active,
                });
            }
            Some(_) => {}
        }
        if self
            .entries
            .iter()
            .any(|entry| !entry.registrations.is_empty())
        {
            return Err(SampleMonitorLifecycleError::Contract(
                SampleMonitorError::LimitExceeded {
                    kind: "unretired-registrations",
                    actual: self
                        .entries
                        .iter()
                        .map(|entry| entry.registrations.len())
                        .sum(),
                    maximum: 0,
                },
            ));
        }
        self.active = Some(invocation);
        let mut started = Vec::new();
        let mut diagnostics = Vec::new();
        for index in 0..self.entries.len() {
            let metadata = self.entries[index].metadata.clone();
            let monitor = Arc::clone(&self.entries[index].monitor);
            let context =
                SampleMonitorHookContext::new(invocation, &metadata, interrupt, registrar);
            let hook_result = invoke_start(Arc::as_ref(&monitor), context).await;
            self.accounting
                .start_hook()
                .map_err(SampleMonitorLifecycleError::Contract)?;
            let start = match hook_result {
                Ok(start) => start,
                Err(primary) => {
                    let cleanup = self.cleanup_started(invocation, interrupt, registrar).await;
                    self.active = None;
                    return Err(SampleMonitorLifecycleError::StartFailed {
                        monitor_node: metadata.source_node(),
                        primary: Box::new(primary),
                        cleanup,
                    });
                }
            };
            let (registrations, hook_diagnostics, registration_overflowed, diagnostic_overflowed) =
                start.into_parts();
            if registration_overflowed || diagnostic_overflowed {
                let primary = SampleMonitorError::LimitExceeded {
                    kind: if registration_overflowed {
                        "start-registrations"
                    } else {
                        "start-diagnostics"
                    },
                    actual: if registration_overflowed {
                        DEFAULT_MAX_SAMPLE_REGISTRATIONS.saturating_add(1)
                    } else {
                        DEFAULT_MAX_SAMPLE_DIAGNOSTICS.saturating_add(1)
                    },
                    maximum: if registration_overflowed {
                        DEFAULT_MAX_SAMPLE_REGISTRATIONS
                    } else {
                        DEFAULT_MAX_SAMPLE_DIAGNOSTICS
                    },
                };
                let cleanup = self.cleanup_started(invocation, interrupt, registrar).await;
                self.active = None;
                return Err(SampleMonitorLifecycleError::StartFailed {
                    monitor_node: metadata.source_node(),
                    primary: Box::new(primary),
                    cleanup,
                });
            }
            for diagnostic in hook_diagnostics {
                if let Err(error) = self.record_diagnostic(&diagnostic, &mut diagnostics) {
                    let cleanup = self.cleanup_started(invocation, interrupt, registrar).await;
                    self.active = None;
                    return Err(SampleMonitorLifecycleError::StartFailed {
                        monitor_node: metadata.source_node(),
                        primary: Box::new(error),
                        cleanup,
                    });
                }
            }
            let live_registrations = self
                .entries
                .iter()
                .try_fold(0usize, |count, entry| {
                    count.checked_add(entry.registrations.len())
                })
                .unwrap_or(usize::MAX);
            if live_registrations
                .checked_add(registrations.len())
                .is_none_or(|count| count > self.limits.max_registrations)
            {
                let primary = SampleMonitorError::LimitExceeded {
                    kind: "registrations",
                    actual: live_registrations.saturating_add(registrations.len()),
                    maximum: self.limits.max_registrations,
                };
                let cleanup = self.cleanup_started(invocation, interrupt, registrar).await;
                self.active = None;
                return Err(SampleMonitorLifecycleError::StartFailed {
                    monitor_node: metadata.source_node(),
                    primary: Box::new(primary),
                    cleanup,
                });
            }
            for registration in registrations {
                let request = registration.request();
                if request.invocation() != invocation
                    || request.monitor_node() != metadata.source_node()
                    || request.monitor_order() != metadata.order()
                {
                    let primary =
                        SampleMonitorError::Registration(RegistrationError::WrongIdentity);
                    let cleanup = self.cleanup_started(invocation, interrupt, registrar).await;
                    self.active = None;
                    return Err(SampleMonitorLifecycleError::StartFailed {
                        monitor_node: metadata.source_node(),
                        primary: Box::new(primary),
                        cleanup,
                    });
                }
                self.entries[index].registrations.push(registration);
                if let Err(error) = self.accounting.registration() {
                    let cleanup = self.cleanup_started(invocation, interrupt, registrar).await;
                    self.active = None;
                    return Err(SampleMonitorLifecycleError::StartFailed {
                        monitor_node: metadata.source_node(),
                        primary: Box::new(error),
                        cleanup,
                    });
                }
            }
            self.entries[index].started = true;
            started.push(metadata);
        }
        Ok(SampleMonitorStartReport {
            started_monitors: started.len(),
            started,
            registrations: self.accounting.registrations,
            diagnostics,
            accounting: self.accounting,
        })
    }

    /// Ends every successfully started monitor in exact source order.
    ///
    /// Cleanup failures are returned as bounded secondary information.  The
    /// caller remains responsible for preserving any sampler primary error.
    pub async fn sample_ended(
        &mut self,
        invocation: SampleInvocationIdentity,
        interrupt: &SamplerInterruptHandle,
        registrar: &dyn SampleMonitorRegistrationRegistrar,
    ) -> Result<SampleMonitorEndReport, SampleMonitorLifecycleError> {
        match self.active {
            None => {
                return Ok(SampleMonitorEndReport {
                    status: MonitorEndStatus::Inactive,
                    ended_monitors: 0,
                    ended: Vec::new(),
                    cleanup: SampleMonitorCleanup::default(),
                    diagnostics: Vec::new(),
                    accounting: self.accounting,
                });
            }
            Some(active) if active != invocation => {
                return Ok(SampleMonitorEndReport {
                    status: MonitorEndStatus::Stale,
                    ended_monitors: 0,
                    ended: Vec::new(),
                    cleanup: SampleMonitorCleanup::default(),
                    diagnostics: Vec::new(),
                    accounting: self.accounting,
                });
            }
            Some(_) => {}
        }
        let mut ended = Vec::new();
        let diagnostics = Vec::new();
        let mut cleanup = SampleMonitorCleanup::default();
        for index in 0..self.entries.len() {
            if !self.entries[index].started {
                continue;
            }
            let metadata = self.entries[index].metadata.clone();
            let monitor = Arc::clone(&self.entries[index].monitor);
            let context =
                SampleMonitorHookContext::new(invocation, &metadata, interrupt, registrar);
            let hook_result = invoke_end(Arc::as_ref(&monitor), context).await;
            self.accounting
                .end_hook()
                .map_err(SampleMonitorLifecycleError::Contract)?;
            match hook_result {
                Ok(()) => {
                    ended.push(metadata.clone());
                }
                Err(error) => cleanup.push(
                    SampleMonitorCleanupFailure {
                        monitor_node: metadata.source_node(),
                        phase: SampleMonitorCleanupPhase::EndHook,
                        error,
                    },
                    self.limits.max_diagnostics,
                ),
            }
        }
        let registration_cleanup = self.retire_registrations_internal(&mut cleanup);
        if registration_cleanup {
            // The exact failures have already been retained in `cleanup`.
        }
        for entry in &mut self.entries {
            entry.started = false;
        }
        self.active = None;
        Ok(SampleMonitorEndReport {
            status: MonitorEndStatus::Ended,
            ended_monitors: ended.len(),
            ended,
            cleanup,
            diagnostics,
            accounting: self.accounting,
        })
    }

    /// Explicitly retires all registrations still owned by this user set.
    pub fn retire_registrations(&mut self) -> SampleMonitorCleanup {
        let mut cleanup = SampleMonitorCleanup::default();
        let _ = self.retire_registrations_internal(&mut cleanup);
        cleanup
    }

    fn record_diagnostic(
        &mut self,
        diagnostic: &SampleMonitorDiagnostic,
        retained: &mut Vec<SampleMonitorDiagnostic>,
    ) -> Result<(), SampleMonitorError> {
        self.accounting.diagnostic(diagnostic, self.limits)?;
        retained.push(diagnostic.clone());
        Ok(())
    }

    fn retire_registrations_internal(&mut self, cleanup: &mut SampleMonitorCleanup) -> bool {
        let mut had_failure = false;
        for entry in &mut self.entries {
            let monitor_node = entry.metadata.source_node();
            let mut index = 0;
            while index < entry.registrations.len() {
                let registration = &entry.registrations[index];
                let _ = self.accounting.retirement_attempt();
                match registration.retire() {
                    Ok(_) => {
                        let _ = self.accounting.retired();
                        entry.registrations.remove(index);
                    }
                    Err(error) => {
                        let _ = self.accounting.retirement_failure();
                        cleanup.push(
                            SampleMonitorCleanupFailure {
                                monitor_node,
                                phase: SampleMonitorCleanupPhase::RegistrationRetirement,
                                error: SampleMonitorError::Registration(error),
                            },
                            self.limits.max_diagnostics,
                        );
                        had_failure = true;
                        index += 1;
                    }
                }
            }
        }
        had_failure
    }

    async fn cleanup_started(
        &mut self,
        invocation: SampleInvocationIdentity,
        interrupt: &SamplerInterruptHandle,
        registrar: &dyn SampleMonitorRegistrationRegistrar,
    ) -> SampleMonitorCleanup {
        let mut cleanup = SampleMonitorCleanup::default();
        for index in 0..self.entries.len() {
            if !self.entries[index].started {
                continue;
            }
            let metadata = self.entries[index].metadata.clone();
            let monitor = Arc::clone(&self.entries[index].monitor);
            let context =
                SampleMonitorHookContext::new(invocation, &metadata, interrupt, registrar);
            let hook_result = invoke_end(Arc::as_ref(&monitor), context).await;
            let _ = self.accounting.end_hook();
            if let Err(error) = hook_result {
                cleanup.push(
                    SampleMonitorCleanupFailure {
                        monitor_node: metadata.source_node(),
                        phase: SampleMonitorCleanupPhase::EndHook,
                        error,
                    },
                    self.limits.max_diagnostics,
                );
            }
        }
        let _ = self.retire_registrations_internal(&mut cleanup);
        for entry in &mut self.entries {
            entry.started = false;
        }
        cleanup
    }
}

impl Drop for SampleMonitorInstances {
    fn drop(&mut self) {
        // Registration handles perform their own panic-contained best-effort
        // retirement.  Drain entries explicitly so a foreign monitor Drop
        // panic cannot prevent later registration handles from being dropped.
        for mut entry in self.entries.drain(..) {
            for registration in entry.registrations.drain(..) {
                let _ = catch_unwind(AssertUnwindSafe(|| drop(registration)));
            }
            let monitor = entry.monitor;
            let _ = catch_unwind(AssertUnwindSafe(|| drop(monitor)));
        }
    }
}

/// Start report retaining source order and bounded accounting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SampleMonitorStartReport {
    /// Number of monitor start hooks which completed successfully.
    pub started_monitors: usize,
    /// Ordered metadata for successfully started monitors.
    pub started: Vec<SampleMonitorMetadata>,
    /// Number of registrations accepted by this and earlier starts.
    pub registrations: usize,
    /// Bounded diagnostics emitted by start hooks.
    pub diagnostics: Vec<SampleMonitorDiagnostic>,
    /// Accounting after the start lifecycle.
    pub accounting: SampleMonitorAccounting,
}

struct PanicSafeFuture<F> {
    future: F,
}

impl<F> PanicSafeFuture<F> {
    fn new(future: F) -> Self {
        Self { future }
    }
}

impl<F> Future for PanicSafeFuture<F>
where
    F: Future + Unpin,
{
    type Output = Result<F::Output, ()>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        match catch_unwind(AssertUnwindSafe(|| {
            Pin::new(&mut self.future).poll(context)
        })) {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(output)) => Poll::Ready(Ok(output)),
            Err(payload) => {
                discard_panic_payload(payload);
                Poll::Ready(Err(()))
            }
        }
    }
}

async fn invoke_start<'a>(
    monitor: &'a dyn SampleMonitor,
    context: SampleMonitorHookContext<'a>,
) -> Result<SampleMonitorStart, SampleMonitorError> {
    let future =
        catch_unwind(AssertUnwindSafe(|| monitor.sample_starting(context))).map_err(|payload| {
            discard_panic_payload(payload);
            SampleMonitorError::HookPanicked
        })?;
    PanicSafeFuture::new(future)
        .await
        .map_err(|()| SampleMonitorError::HookPanicked)?
}

async fn invoke_end<'a>(
    monitor: &'a dyn SampleMonitor,
    context: SampleMonitorHookContext<'a>,
) -> Result<(), SampleMonitorError> {
    let future =
        catch_unwind(AssertUnwindSafe(|| monitor.sample_ended(context))).map_err(|payload| {
            discard_panic_payload(payload);
            SampleMonitorError::HookPanicked
        })?;
    PanicSafeFuture::new(future)
        .await
        .map_err(|()| SampleMonitorError::HookPanicked)?
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "deterministic monitor state-machine fixtures"
)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::future;
    use std::sync::atomic::AtomicBool;

    fn block_on<F: Future>(future: F) -> F::Output {
        let mut context = Context::from_waker(std::task::Waker::noop());
        let mut future = Box::pin(future);
        for _ in 0..32 {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(value) => return value,
                Poll::Pending => {}
            }
        }
        panic!("deterministic fixture future did not complete")
    }

    fn user(lifecycle_id: u64, thread_number: u64, iteration: u64) -> UserIdentity {
        UserIdentity::new(lifecycle_id, NodeId::new(10), thread_number, iteration)
    }

    fn invocation(
        sampler_id: u64,
        identity: UserIdentity,
        generation: u64,
    ) -> SampleInvocationIdentity {
        SampleInvocationIdentity::new(
            NodeId::new(sampler_id),
            identity,
            InvocationGeneration::try_new(generation).expect("generation"),
        )
        .expect("invocation")
    }

    fn metadata(node: u64, order: usize, class: &str) -> SampleMonitorMetadata {
        SampleMonitorMetadata::new(
            NodeId::new(node),
            vec![NodeId::new(1), NodeId::new(node)],
            class,
            order,
        )
        .expect("metadata")
    }

    #[derive(Default)]
    struct FakeInterrupt {
        outcomes: Mutex<VecDeque<InterruptOutcome>>,
        requests: Mutex<Vec<InterruptRequest>>,
    }

    impl SamplerInterrupt for FakeInterrupt {
        fn interrupt<'a>(&'a self, request: InterruptRequest) -> SamplerInterruptFuture<'a> {
            self.requests.lock().expect("request lock").push(request);
            let outcome = self
                .outcomes
                .lock()
                .expect("outcome lock")
                .pop_front()
                .unwrap_or(InterruptOutcome::Accepted);
            Box::pin(future::ready(Ok(outcome)))
        }
    }

    #[derive(Default)]
    struct Retirer {
        active: Mutex<BTreeSet<RegistrationId>>,
        attempts: Mutex<Vec<RegistrationId>>,
        fail_once: AtomicBool,
        panic: AtomicBool,
    }

    impl RegistrationRetirer for Retirer {
        fn retire(
            &self,
            id: RegistrationId,
        ) -> Result<RegistrationRetireOutcome, RegistrationError> {
            self.attempts.lock().expect("attempt lock").push(id);
            if self.panic.swap(false, Ordering::AcqRel) {
                panic!("retirer panic")
            }
            if self.fail_once.swap(false, Ordering::AcqRel) {
                return Err(RegistrationError::OwnerRejected {
                    diagnostic: SampleMonitorDiagnostic::new("fixture.cleanup", "temporary"),
                });
            }
            if self.active.lock().expect("active lock").remove(&id) {
                Ok(RegistrationRetireOutcome::Retired)
            } else {
                Ok(RegistrationRetireOutcome::AlreadyRetired)
            }
        }
    }

    struct Registrar {
        next: AtomicU64,
        owner: Arc<Retirer>,
        requests: Mutex<Vec<SampleMonitorRegistrationRequest>>,
    }

    impl Registrar {
        fn new(owner: Arc<Retirer>) -> Self {
            Self {
                next: AtomicU64::new(1),
                owner,
                requests: Mutex::new(Vec::new()),
            }
        }
    }

    impl SampleMonitorRegistrationRegistrar for Registrar {
        fn register(
            &self,
            request: SampleMonitorRegistrationRequest,
        ) -> Result<SampleMonitorRegistration, RegistrationError> {
            let id = RegistrationId::new(self.next.fetch_add(1, Ordering::AcqRel))?;
            self.owner.active.lock().expect("active lock").insert(id);
            self.requests.lock().expect("request lock").push(request);
            Ok(SampleMonitorRegistration::new(
                id,
                request,
                Arc::clone(&self.owner) as Arc<dyn RegistrationRetirer>,
            ))
        }
    }

    struct FakeMonitor {
        metadata_node: NodeId,
        order: usize,
        start_nodes: Arc<Mutex<Vec<NodeId>>>,
        end_nodes: Arc<Mutex<Vec<NodeId>>>,
        fail_start: bool,
        fail_end: bool,
        register: bool,
    }

    impl SampleMonitor for FakeMonitor {
        fn sample_starting<'a>(
            &'a self,
            context: SampleMonitorHookContext<'a>,
        ) -> SampleMonitorFuture<'a, SampleMonitorStart> {
            self.start_nodes
                .lock()
                .expect("start log")
                .push(context.metadata().source_node());
            if self.fail_start {
                return Box::pin(future::ready(Err(SampleMonitorError::HookFailed {
                    diagnostic: SampleMonitorDiagnostic::new("fixture.start", "primary"),
                })));
            }
            let mut start = SampleMonitorStart::empty();
            if self.register {
                let request = SampleMonitorRegistrationRequest::new(
                    context.invocation(),
                    self.metadata_node,
                    self.order,
                    Deadline::at(crate::MonotonicInstant::zero()),
                    InterruptReason::SampleTimeout,
                );
                let registration = context.registrar().register(request).expect("registration");
                start.push_registration(registration);
            }
            Box::pin(future::ready(Ok(start)))
        }

        fn sample_ended<'a>(
            &'a self,
            context: SampleMonitorHookContext<'a>,
        ) -> SampleMonitorFuture<'a, ()> {
            self.end_nodes
                .lock()
                .expect("end log")
                .push(context.metadata().source_node());
            if self.fail_end {
                Box::pin(future::ready(Err(SampleMonitorError::HookFailed {
                    diagnostic: SampleMonitorDiagnostic::new("fixture.end", "cleanup"),
                })))
            } else {
                Box::pin(future::ready(Ok(())))
            }
        }
    }

    struct HookPanicMonitor {
        panic_start: bool,
        panic_end: bool,
    }

    impl SampleMonitor for HookPanicMonitor {
        fn sample_starting<'a>(
            &'a self,
            _context: SampleMonitorHookContext<'a>,
        ) -> SampleMonitorFuture<'a, SampleMonitorStart> {
            if self.panic_start {
                panic!("start hook panic")
            }
            Box::pin(future::ready(Ok(SampleMonitorStart::empty())))
        }

        fn sample_ended<'a>(
            &'a self,
            _context: SampleMonitorHookContext<'a>,
        ) -> SampleMonitorFuture<'a, ()> {
            if self.panic_end {
                panic!("end hook panic")
            }
            Box::pin(future::ready(Ok(())))
        }
    }

    struct FakeFactory {
        monitor: Option<Arc<dyn SampleMonitor>>,
        panic: bool,
    }

    impl SampleMonitorFactory for FakeFactory {
        fn create_for_user(
            &self,
            _user: UserIdentity,
        ) -> Result<Arc<dyn SampleMonitor>, SampleMonitorError> {
            if self.panic {
                panic!("factory panic")
            }
            self.monitor
                .as_ref()
                .cloned()
                .ok_or_else(|| SampleMonitorError::FactoryFailed {
                    diagnostic: SampleMonitorDiagnostic::new("fixture.factory", "missing monitor"),
                })
        }
    }

    fn factory(monitor: Arc<dyn SampleMonitor>) -> Arc<dyn SampleMonitorFactory> {
        Arc::new(FakeFactory {
            monitor: Some(monitor),
            panic: false,
        })
    }

    fn supported_handle() -> (SamplerInterruptHandle, Arc<FakeInterrupt>) {
        let operation = Arc::new(FakeInterrupt::default());
        let handle = SamplerInterruptHandle::new(SamplerInterruptCapability::supported(
            Arc::clone(&operation) as Arc<dyn SamplerInterrupt>,
        ));
        (handle, operation)
    }

    #[test]
    fn interrupt_state_rejects_stale_repeated_inactive_wrong_identity_and_unsupported() {
        let (handle, operation) = supported_handle();
        let first = invocation(20, user(1, 1, 0), 1);
        let wrong_sampler = invocation(21, user(1, 1, 0), 1);
        let wrong_user = invocation(20, user(2, 1, 0), 1);
        let stale_generation = invocation(20, user(1, 1, 0), 2);
        handle.begin(first).expect("begin");
        assert_eq!(
            block_on(handle.request_interrupt(InterruptRequest::new(
                wrong_sampler,
                InterruptReason::SampleTimeout,
            ))),
            Ok(InterruptOutcome::Stale)
        );
        assert_eq!(
            block_on(handle.request_interrupt(InterruptRequest::new(
                stale_generation,
                InterruptReason::StopTestImmediate,
            ))),
            Ok(InterruptOutcome::Stale)
        );
        assert_eq!(
            block_on(handle.request_interrupt(InterruptRequest::new(
                wrong_user,
                InterruptReason::SampleTimeout,
            ))),
            Ok(InterruptOutcome::Stale)
        );
        assert_eq!(
            block_on(
                handle.request_interrupt(InterruptRequest::new(
                    first,
                    InterruptReason::SampleTimeout,
                ))
            ),
            Ok(InterruptOutcome::Accepted)
        );
        assert_eq!(
            block_on(
                handle.request_interrupt(InterruptRequest::new(
                    first,
                    InterruptReason::SampleTimeout,
                ))
            ),
            Ok(InterruptOutcome::Repeated)
        );
        assert_eq!(operation.requests.lock().expect("requests").len(), 1);
        assert_eq!(handle.end(first), InterruptEndOutcome::Ended);
        assert_eq!(
            block_on(handle.request_interrupt(InterruptRequest::new(
                first,
                InterruptReason::StopTestImmediate,
            ))),
            Ok(InterruptOutcome::Inactive)
        );

        let unsupported = SamplerInterruptHandle::unsupported();
        unsupported.begin(first).expect("unsupported begin");
        assert_eq!(
            block_on(unsupported.request_interrupt(InterruptRequest::new(
                first,
                InterruptReason::StopTestImmediate,
            ))),
            Ok(InterruptOutcome::Unsupported)
        );
    }

    #[test]
    fn registration_retirement_is_linear_idempotent_retryable_and_drop_safe() {
        let owner = Arc::new(Retirer::default());
        let request = SampleMonitorRegistrationRequest::new(
            invocation(20, user(1, 1, 0), 1),
            NodeId::new(30),
            0,
            Deadline::at(crate::MonotonicInstant::zero()),
            InterruptReason::SampleTimeout,
        );
        let id = RegistrationId::new(1).expect("id");
        owner.active.lock().expect("active").insert(id);
        let registration = SampleMonitorRegistration::new(
            id,
            request,
            Arc::clone(&owner) as Arc<dyn RegistrationRetirer>,
        );
        assert_eq!(
            registration.retire(),
            Ok(RegistrationRetireOutcome::Retired)
        );
        assert_eq!(
            registration.retire(),
            Ok(RegistrationRetireOutcome::AlreadyRetired)
        );
        assert_eq!(registration.retirement_attempts(), 1);
        assert_eq!(owner.attempts.lock().expect("attempts").len(), 1);

        let id = RegistrationId::new(2).expect("id");
        owner.active.lock().expect("active").insert(id);
        let retry = SampleMonitorRegistration::new(
            id,
            request,
            Arc::clone(&owner) as Arc<dyn RegistrationRetirer>,
        );
        owner.fail_once.store(true, Ordering::Release);
        assert!(retry.retire().is_err());
        assert!(retry.is_active());
        assert_eq!(retry.retire(), Ok(RegistrationRetireOutcome::Retired));
        drop(retry);
        assert_eq!(owner.attempts.lock().expect("attempts").len(), 3);
    }

    #[test]
    fn monitors_are_per_user_and_start_end_in_source_order_with_metadata() {
        let start_nodes = Arc::new(Mutex::new(Vec::new()));
        let end_nodes = Arc::new(Mutex::new(Vec::new()));
        let owner = Arc::new(Retirer::default());
        let registrar = Registrar::new(Arc::clone(&owner));
        let first = Arc::new(FakeMonitor {
            metadata_node: NodeId::new(30),
            order: 7,
            start_nodes: Arc::clone(&start_nodes),
            end_nodes: Arc::clone(&end_nodes),
            fail_start: false,
            fail_end: false,
            register: true,
        });
        let second = Arc::new(FakeMonitor {
            metadata_node: NodeId::new(40),
            order: 9,
            start_nodes: Arc::clone(&start_nodes),
            end_nodes: Arc::clone(&end_nodes),
            fail_start: false,
            fail_end: false,
            register: true,
        });
        let plan = SampleMonitorPlan::with_limits(
            vec![
                SampleMonitorFactorySpec::new(metadata(30, 7, "first"), factory(first)),
                SampleMonitorFactorySpec::new(metadata(40, 9, "second"), factory(second)),
            ],
            SampleMonitorLimits {
                max_registrations: 2,
                ..SampleMonitorLimits::default()
            },
        )
        .expect("plan");
        let mut instances = plan.instantiate_for_user(user(1, 1, 0)).expect("instances");
        let (interrupt, _) = supported_handle();
        let current = invocation(20, user(1, 1, 0), 1);
        interrupt.begin(current).expect("interrupt begin");
        let report =
            block_on(instances.sample_starting(current, &interrupt, &registrar)).expect("start");
        assert_eq!(
            report
                .started
                .iter()
                .map(|item| item.source_node())
                .collect::<Vec<_>>(),
            vec![NodeId::new(30), NodeId::new(40)]
        );
        assert_eq!(report.registrations, 2);
        let ended = block_on(instances.sample_ended(current, &interrupt, &registrar)).expect("end");
        assert_eq!(ended.status, MonitorEndStatus::Ended);
        assert!(ended.cleanup.is_clean());
        assert_eq!(
            *start_nodes.lock().expect("start nodes"),
            vec![NodeId::new(30), NodeId::new(40)]
        );
        assert_eq!(
            *end_nodes.lock().expect("end nodes"),
            vec![NodeId::new(30), NodeId::new(40)]
        );
        assert_eq!(owner.active.lock().expect("active").len(), 0);

        let repeat = invocation(20, user(1, 1, 0), 2);
        interrupt.end(current);
        interrupt.begin(repeat).expect("repeat interrupt begin");
        block_on(instances.sample_starting(repeat, &interrupt, &registrar)).expect("repeat start");
        block_on(instances.sample_ended(repeat, &interrupt, &registrar)).expect("repeat end");
        assert_eq!(owner.active.lock().expect("active").len(), 0);

        let second_user = user(2, 1, 0);
        let mut second_instances = plan
            .instantiate_for_user(second_user)
            .expect("second instances");
        assert_ne!(instances.user(), second_instances.user());
        interrupt.end(repeat);
        let next = invocation(20, second_user, 1);
        interrupt.begin(next).expect("second interrupt begin");
        block_on(second_instances.sample_starting(next, &interrupt, &registrar)).expect("start");
        block_on(second_instances.sample_ended(next, &interrupt, &registrar)).expect("end");
    }

    #[test]
    fn stale_monitor_end_does_not_retire_active_registration() {
        let owner = Arc::new(Retirer::default());
        let registrar = Registrar::new(Arc::clone(&owner));
        let monitor = Arc::new(FakeMonitor {
            metadata_node: NodeId::new(30),
            order: 0,
            start_nodes: Arc::new(Mutex::new(Vec::new())),
            end_nodes: Arc::new(Mutex::new(Vec::new())),
            fail_start: false,
            fail_end: false,
            register: true,
        });
        let plan = SampleMonitorPlan::new(vec![SampleMonitorFactorySpec::new(
            metadata(30, 0, "monitor"),
            factory(monitor),
        )])
        .expect("plan");
        let mut instances = plan.instantiate_for_user(user(1, 1, 0)).expect("instances");
        let (interrupt, _) = supported_handle();
        let current = invocation(20, user(1, 1, 0), 1);
        let stale = invocation(20, user(1, 1, 0), 2);
        interrupt.begin(current).expect("begin");
        block_on(instances.sample_starting(current, &interrupt, &registrar)).expect("start");
        let report =
            block_on(instances.sample_ended(stale, &interrupt, &registrar)).expect("stale");
        assert_eq!(report.status, MonitorEndStatus::Stale);
        assert_eq!(owner.active.lock().expect("active").len(), 1);
        let report =
            block_on(instances.sample_ended(current, &interrupt, &registrar)).expect("end");
        assert_eq!(report.status, MonitorEndStatus::Ended);
        assert_eq!(owner.active.lock().expect("active").len(), 0);
    }

    #[test]
    fn start_failure_preserves_primary_and_reports_cleanup_failure() {
        let owner = Arc::new(Retirer::default());
        let registrar = Registrar::new(Arc::clone(&owner));
        let first = Arc::new(FakeMonitor {
            metadata_node: NodeId::new(30),
            order: 0,
            start_nodes: Arc::new(Mutex::new(Vec::new())),
            end_nodes: Arc::new(Mutex::new(Vec::new())),
            fail_start: false,
            fail_end: false,
            register: true,
        });
        let second = Arc::new(FakeMonitor {
            metadata_node: NodeId::new(40),
            order: 1,
            start_nodes: Arc::new(Mutex::new(Vec::new())),
            end_nodes: Arc::new(Mutex::new(Vec::new())),
            fail_start: true,
            fail_end: false,
            register: false,
        });
        let plan = SampleMonitorPlan::new(vec![
            SampleMonitorFactorySpec::new(metadata(30, 0, "first"), factory(first)),
            SampleMonitorFactorySpec::new(metadata(40, 1, "second"), factory(second)),
        ])
        .expect("plan");
        let mut instances = plan.instantiate_for_user(user(1, 1, 0)).expect("instances");
        let (interrupt, _) = supported_handle();
        let current = invocation(20, user(1, 1, 0), 1);
        interrupt.begin(current).expect("begin");
        owner.fail_once.store(true, Ordering::Release);
        let error = block_on(instances.sample_starting(current, &interrupt, &registrar))
            .expect_err("start must fail");
        assert_eq!(error.code(), "runtime.sample-monitor.start-failed");
        assert!(matches!(
            error.primary(),
            Some(SampleMonitorError::HookFailed { diagnostic })
                if diagnostic.code() == "fixture.start"
        ));
        assert_eq!(error.cleanup().expect("cleanup").failures().len(), 1);
        assert!(instances.active_invocation().is_none());
        assert!(instances.retire_registrations().is_clean());
    }

    #[test]
    fn panic_in_factory_and_registration_owner_is_contained() {
        let panic_factory: Arc<dyn SampleMonitorFactory> = Arc::new(FakeFactory {
            monitor: None,
            panic: true,
        });
        let plan = SampleMonitorPlan::new(vec![SampleMonitorFactorySpec::new(
            metadata(30, 0, "panic"),
            panic_factory,
        )])
        .expect("plan");
        assert_eq!(
            plan.instantiate_for_user(user(1, 1, 0))
                .expect_err("panic factory"),
            SampleMonitorError::FactoryPanicked
        );

        let owner = Arc::new(Retirer::default());
        let request = SampleMonitorRegistrationRequest::new(
            invocation(20, user(1, 1, 0), 1),
            NodeId::new(30),
            0,
            Deadline::at(crate::MonotonicInstant::zero()),
            InterruptReason::SampleTimeout,
        );
        let id = RegistrationId::new(1).expect("id");
        owner.active.lock().expect("active").insert(id);
        owner.panic.store(true, Ordering::Release);
        let registration = SampleMonitorRegistration::new(
            id,
            request,
            Arc::clone(&owner) as Arc<dyn RegistrationRetirer>,
        );
        assert_eq!(registration.retire(), Err(RegistrationError::OwnerPanicked));
        assert!(registration.is_active());
        assert_eq!(
            registration.retire(),
            Ok(RegistrationRetireOutcome::Retired)
        );
    }

    #[test]
    fn panic_in_monitor_hooks_is_contained_and_end_cleanup_continues() {
        let owner = Arc::new(Retirer::default());
        let registrar = Registrar::new(Arc::clone(&owner));
        let monitor = Arc::new(HookPanicMonitor {
            panic_start: false,
            panic_end: true,
        });
        let plan = SampleMonitorPlan::new(vec![SampleMonitorFactorySpec::new(
            metadata(30, 0, "hook-panic"),
            factory(monitor),
        )])
        .expect("plan");
        let mut instances = plan.instantiate_for_user(user(1, 1, 0)).expect("instances");
        let (interrupt, _) = supported_handle();
        let current = invocation(20, user(1, 1, 0), 1);
        interrupt.begin(current).expect("begin");
        block_on(instances.sample_starting(current, &interrupt, &registrar)).expect("start");
        let report =
            block_on(instances.sample_ended(current, &interrupt, &registrar)).expect("end");
        assert_eq!(report.status, MonitorEndStatus::Ended);
        assert_eq!(report.cleanup.failures().len(), 1);
        assert!(matches!(
            &report.cleanup.failures()[0].error,
            SampleMonitorError::HookPanicked
        ));

        let panic_start: Arc<dyn SampleMonitor> = Arc::new(HookPanicMonitor {
            panic_start: true,
            panic_end: false,
        });
        let plan = SampleMonitorPlan::new(vec![SampleMonitorFactorySpec::new(
            metadata(31, 0, "start-panic"),
            factory(panic_start),
        )])
        .expect("plan");
        let mut instances = plan.instantiate_for_user(user(1, 1, 0)).expect("instances");
        let next = invocation(20, user(1, 1, 0), 2);
        interrupt.end(current);
        interrupt.begin(next).expect("next begin");
        let error = block_on(instances.sample_starting(next, &interrupt, &registrar))
            .expect_err("panic start");
        assert!(matches!(
            error.primary(),
            Some(SampleMonitorError::HookPanicked)
        ));
    }
}
