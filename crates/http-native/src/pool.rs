// SPDX-License-Identifier: Apache-2.0
//! Executor-neutral ownership state for the planned `http.native/3` pool.
//!
//! This module deliberately does not know how a connection is opened, read,
//! written, or closed.  The application/transport adapter supplies an opaque
//! connection value and explicit monotonic facts.  The pool only owns bounded
//! admission, lease identity, FIFO ordering, and the state transitions that
//! decide whether a connection may be reused.  In particular, no operation in
//! this module retries an acquisition or silently falls back to another key.
//!
//! `Drop` on a lease or connection permit only performs an in-memory state
//! transition.  It never invokes [`ConnectionCleanup::cleanup`].  Cleanup is
//! an explicit, bounded adapter operation so that a failed cleanup remains
//! observable as a quarantine/poisoning error rather than being reported as a
//! successful request.
//!
//! The `Rc<RefCell<_>>` owner is intentional: this is a single-executor-thread
//! state machine for one native I/O owner and is deliberately not `Send` or
//! `Sync`.  A native adapter must keep one pool inside that owner; cross-thread
//! sharing belongs at an explicit bounded protocol boundary rather than in
//! this state layer.

use core::fmt;
use core::num::{NonZeroU64, NonZeroUsize};
use core::ops::{Deref, DerefMut};
use std::cell::{RefCell, RefMut};
use std::collections::VecDeque;
use std::mem;
use std::rc::Rc;

/// Hard upper bound for the number of live connection slots in one pool.
pub const MAX_POOL_LIVE: usize = 1_024;
/// Hard upper bound for queued acquisition requests in one pool.
pub const MAX_POOL_QUEUE: usize = 4_096;

/// A cleanup failure that returns ownership of the connection to the caller.
///
/// Returning the connection is important: a failed cleanup remains owned by
/// the pool in quarantine and is never dropped as an implicit success path.
pub struct CleanupFailure<C, E> {
    /// The connection whose cleanup failed.
    pub connection: C,
    /// Adapter-specific cleanup error.
    pub error: E,
}

/// Contract implemented by the concrete transport connection owner.
///
/// The pool does not call this method from `Drop`, and it never retries it.
/// An implementation must return the connection in [`CleanupFailure`] when
/// cleanup cannot prove that ownership was released.
pub trait ConnectionCleanup: Sized {
    /// Typed adapter cleanup error.
    type Error;

    /// Consume the connection and prove that its owned resource was closed.
    fn cleanup(self) -> Result<(), CleanupFailure<Self, Self::Error>>;
}

/// Stable pool state/error categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PoolError<E = ()> {
    /// A capacity or TTL/idle bound was zero, inverted, or above the hard
    /// module bound.
    InvalidCapacity,
    /// An opaque identity was constructed from the forbidden zero value.
    InvalidIdentity,
    /// Connection facts had an impossible order or freshness value.
    InvalidFacts,
    /// The caller supplied a proof for a different connection lease.
    InvalidReuseProof,
    /// A supplied monotonic tick moved backwards.
    ClockReversed,
    /// A checked nonzero identifier could not be allocated.
    IdExhausted,
    /// A checked nonzero generation could not be allocated.
    GenerationExhausted,
    /// The bounded acquisition queue is full.
    QueueFull,
    /// The queue ticket is unknown, consumed, or belongs to another key.
    TicketInvalid,
    /// Global live/reservation capacity is full.
    CapacityFull,
    /// Per-route live/reservation capacity is full.
    RouteCapacityFull,
    /// Global or per-route idle capacity is full.
    IdleCapacityFull,
    /// The pool is draining or has rejected new work.
    ShuttingDown,
    /// The pool has completed finalization.
    Closed,
    /// A cleanup failure poisoned the pool; no fallback is permitted.
    Poisoned,
    /// A lease/permit token no longer names the live slot it was issued for.
    LeaseInvalid,
    /// An operation was attempted after a lease or cleanup token was released.
    LeaseReleased,
    /// The connection is stale or outside an explicit TTL/idle bound.
    ConnectionExpired,
    /// The connection's explicit freshness fact is not reusable.
    ConnectionStale,
    /// The connection is still owned by an active lease during shutdown.
    ShutdownPending,
    /// Cleanup was already attempted for this quarantined resource.
    CleanupAlreadyAttempted,
    /// An internal state transition could not preserve the slot invariant.
    Invariant,
    /// Adapter cleanup returned its typed failure.
    Cleanup {
        /// Connection identity whose cleanup failed.
        connection_id: ConnectionId,
        /// Adapter-specific failure value.
        error: E,
    },
}

impl<E> PoolError<E> {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidCapacity => "http.pool.invalid-capacity",
            Self::InvalidIdentity => "http.pool.invalid-identity",
            Self::InvalidFacts => "http.pool.invalid-facts",
            Self::InvalidReuseProof => "http.pool.invalid-reuse-proof",
            Self::ClockReversed => "http.pool.clock-reversed",
            Self::IdExhausted => "http.pool.id-overflow",
            Self::GenerationExhausted => "http.pool.generation-overflow",
            Self::QueueFull => "http.pool.queue-full",
            Self::TicketInvalid => "http.pool.ticket-invalid",
            Self::CapacityFull => "http.pool.capacity-full",
            Self::RouteCapacityFull => "http.pool.route-capacity-full",
            Self::IdleCapacityFull => "http.pool.idle-capacity-full",
            Self::ShuttingDown => "http.pool.shutting-down",
            Self::Closed => "http.pool.closed",
            Self::Poisoned => "http.pool.poisoned",
            Self::LeaseInvalid => "http.pool.lease-invalid",
            Self::LeaseReleased => "http.pool.lease-released",
            Self::ConnectionExpired => "http.pool.connection-expired",
            Self::ConnectionStale => "http.pool.connection-stale",
            Self::ShutdownPending => "http.pool.shutdown-pending",
            Self::CleanupAlreadyAttempted => "http.pool.cleanup-already-attempted",
            Self::Invariant => "http.pool.invariant",
            Self::Cleanup { .. } => "http.pool.cleanup",
        }
    }
}

impl<E> fmt::Display for PoolError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl<E: fmt::Debug> std::error::Error for PoolError<E> {}

/// Opaque nonzero route identity.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RouteIdentity(NonZeroU64);

impl RouteIdentity {
    /// Construct an identity from a nonzero opaque value.
    pub fn new(value: u64) -> Result<Self, PoolError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or(PoolError::InvalidIdentity)
    }

    /// Construct an identity from an already checked nonzero value.
    #[must_use]
    pub const fn from_nonzero(value: NonZeroU64) -> Self {
        Self(value)
    }
}

impl fmt::Debug for RouteIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RouteIdentity(..)")
    }
}

/// Opaque nonzero origin identity.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OriginIdentity(NonZeroU64);

impl OriginIdentity {
    /// Construct an identity from a nonzero opaque value.
    pub fn new(value: u64) -> Result<Self, PoolError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or(PoolError::InvalidIdentity)
    }

    /// Construct an identity from an already checked nonzero value.
    #[must_use]
    pub const fn from_nonzero(value: NonZeroU64) -> Self {
        Self(value)
    }
}

impl fmt::Debug for OriginIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OriginIdentity(..)")
    }
}

/// Opaque nonzero TLS policy/identity.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TlsIdentity(NonZeroU64);

impl TlsIdentity {
    /// Construct an identity from a nonzero opaque value.
    pub fn new(value: u64) -> Result<Self, PoolError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or(PoolError::InvalidIdentity)
    }

    /// Construct an identity from an already checked nonzero value.
    #[must_use]
    pub const fn from_nonzero(value: NonZeroU64) -> Self {
        Self(value)
    }
}

impl fmt::Debug for TlsIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TlsIdentity(..)")
    }
}

/// Immutable key for one pool partition.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PoolKey {
    route: RouteIdentity,
    origin: OriginIdentity,
    tls: TlsIdentity,
}

impl PoolKey {
    /// Build an immutable origin/route/TLS partition key.
    #[must_use]
    pub const fn new(route: RouteIdentity, origin: OriginIdentity, tls: TlsIdentity) -> Self {
        Self { route, origin, tls }
    }

    /// Return the opaque route identity.
    #[must_use]
    pub const fn route(self) -> RouteIdentity {
        self.route
    }

    /// Return the opaque origin identity.
    #[must_use]
    pub const fn origin(self) -> OriginIdentity {
        self.origin
    }

    /// Return the opaque TLS identity.
    #[must_use]
    pub const fn tls(self) -> TlsIdentity {
        self.tls
    }
}

impl fmt::Debug for PoolKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PoolKey")
            .field("route", &self.route)
            .field("origin", &self.origin)
            .field("tls", &self.tls)
            .finish()
    }
}

/// A caller-supplied monotonic reading.  It is not a wall-clock timestamp.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Tick(u64);

impl Tick {
    /// Construct a monotonic tick; zero is a valid deterministic epoch.
    #[must_use]
    pub const fn from_raw(value: u64) -> Self {
        Self(value)
    }

    /// Inspect the tick for adapter-side arithmetic.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Explicit connection freshness supplied by the transport adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Freshness {
    /// The connection passed the adapter's protocol freshness checks.
    Fresh,
    /// The adapter observed a stale connection.
    Stale,
    /// The adapter could not prove freshness.
    Unknown,
}

/// Facts needed to decide whether a connection may be reused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionFacts {
    created_at: Tick,
    last_used_at: Tick,
    freshness: Freshness,
}

impl ConnectionFacts {
    /// Build explicit connection age/idle/freshness facts.
    pub fn new(
        created_at: Tick,
        last_used_at: Tick,
        freshness: Freshness,
    ) -> Result<Self, PoolError> {
        if last_used_at < created_at {
            return Err(PoolError::InvalidFacts);
        }
        Ok(Self {
            created_at,
            last_used_at,
            freshness,
        })
    }

    /// Return the connection creation tick.
    #[must_use]
    pub const fn created_at(self) -> Tick {
        self.created_at
    }

    /// Return the last-use tick.
    #[must_use]
    pub const fn last_used_at(self) -> Tick {
        self.last_used_at
    }

    /// Return the explicit adapter freshness fact.
    #[must_use]
    pub const fn freshness(self) -> Freshness {
        self.freshness
    }
}

/// Connection lifecycle reasons that request an explicit close operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloseReason {
    /// Caller proved a complete close/framing boundary and requests cleanup.
    Explicit,
    /// The response body was not consumed to a framing boundary.
    Unread,
    /// The transport failed while the lease was active.
    Failed,
    /// The operation was cancelled.
    Cancelled,
    /// The connection exceeded a configured TTL or idle bound.
    Expired,
    /// Pool shutdown owns the close decision.
    Shutdown,
}

/// Reasons for retaining a connection in bounded quarantine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuarantineReason {
    /// A lease was dropped before explicit finalization.
    Dropped,
    /// The body was unread or framing was not proven complete.
    Unread,
    /// The operation failed.
    Failed,
    /// The operation was cancelled.
    Cancelled,
    /// The connection was expired or stale.
    Expired,
    /// A reuse proof did not validate.
    InvalidReuseProof,
    /// Idle capacity could not retain the connection.
    IdleCapacity,
    /// Pool shutdown retained the resource for explicit finalization.
    Shutdown,
    /// A cleanup failure left ownership uncertain.
    CleanupFailure,
}

/// A proof minted from one active lease after the caller consumed the response
/// framing boundary.  Its fields are private so it cannot be transferred to a
/// different connection or route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReuseProof {
    token: LeaseToken,
    facts: ConnectionFacts,
}

/// A checked connection identity.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConnectionId(NonZeroU64);

impl ConnectionId {
    /// Construct a connection identity from a checked value.
    #[must_use]
    pub const fn from_nonzero(value: NonZeroU64) -> Self {
        Self(value)
    }
}

impl fmt::Debug for ConnectionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConnectionId(..)")
    }
}

/// A checked lease generation.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Generation(NonZeroU64);

impl Generation {
    /// Construct a generation from a checked value.
    #[must_use]
    pub const fn from_nonzero(value: NonZeroU64) -> Self {
        Self(value)
    }
}

impl fmt::Debug for Generation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Generation(..)")
    }
}

/// A checked FIFO acquisition request identity.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RequestId(NonZeroU64);

impl RequestId {
    /// Construct a request identity from a checked value.
    #[must_use]
    pub const fn from_nonzero(value: NonZeroU64) -> Self {
        Self(value)
    }
}

impl fmt::Debug for RequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RequestId(..)")
    }
}

/// Token returned when an acquisition must wait for bounded capacity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcquireTicket {
    id: RequestId,
    key: PoolKey,
}

impl AcquireTicket {
    /// Return the checked request identity.
    #[must_use]
    pub const fn id(self) -> RequestId {
        self.id
    }

    /// Return the immutable partition key.
    #[must_use]
    pub const fn key(self) -> PoolKey {
        self.key
    }
}

/// Token returned while the adapter establishes a new connection.  Dropping
/// it releases only the reserved slot and never claims that a connection was
/// opened.
pub struct ConnectPermit<C: ConnectionCleanup> {
    pool: Rc<RefCell<PoolInner<C>>>,
    slot: usize,
    reservation: Reservation,
    active: bool,
}

impl<C: ConnectionCleanup> fmt::Debug for ConnectPermit<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectPermit")
            .field("connection_id", &self.reservation.connection_id)
            .field("active", &self.active)
            .finish()
    }
}

impl<C: ConnectionCleanup> ConnectPermit<C> {
    /// Return the reserved connection identity.
    #[must_use]
    pub const fn connection_id(&self) -> ConnectionId {
        self.reservation.connection_id
    }

    /// Return the immutable key being connected.
    #[must_use]
    pub const fn key(&self) -> PoolKey {
        self.reservation.key
    }

    /// Complete the one reserved connection attempt and acquire its lease.
    ///
    /// Invalid facts quarantine the supplied connection and return an error;
    /// they never turn into a successful lease with guessed defaults.
    pub fn complete(
        mut self,
        connection: C,
        facts: ConnectionFacts,
        now: Tick,
    ) -> Result<Lease<C>, PoolError<C::Error>> {
        let pool = Rc::clone(&self.pool);
        let slot = self.slot;
        let reservation = self.reservation;
        let result = pool
            .try_borrow_mut()
            .map_err(|_| PoolError::Invariant)?
            .complete_connection(slot, reservation, connection, facts, now);
        self.active = false;
        match result {
            Ok(()) => Ok(Lease {
                pool: Rc::clone(&self.pool),
                slot,
                token: LeaseToken {
                    connection_id: reservation.connection_id,
                    generation: reservation.generation,
                    key: reservation.key,
                },
                active: true,
            }),
            Err(error) => Err(error),
        }
    }

    /// Cancel the reservation without manufacturing a connection or success.
    pub fn cancel(mut self) -> Result<(), PoolError<C::Error>> {
        let result = self
            .pool
            .try_borrow_mut()
            .map_err(|_| PoolError::Invariant)?
            .cancel_reservation(self.slot, self.reservation);
        self.active = false;
        result
    }
}

impl<C: ConnectionCleanup> Drop for ConnectPermit<C> {
    fn drop(&mut self) {
        if self.active {
            if let Ok(mut pool) = self.pool.try_borrow_mut() {
                let _ = pool.cancel_reservation(self.slot, self.reservation);
            }
            self.active = false;
        }
    }
}

/// One linear lease over one concrete connection slot.
pub struct Lease<C: ConnectionCleanup> {
    pool: Rc<RefCell<PoolInner<C>>>,
    slot: usize,
    token: LeaseToken,
    active: bool,
}

impl<C: ConnectionCleanup> fmt::Debug for Lease<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Lease")
            .field("connection_id", &self.token.connection_id)
            .field("generation", &self.token.generation)
            .field("active", &self.active)
            .finish()
    }
}

impl<C: ConnectionCleanup> Lease<C> {
    /// Return this lease's checked connection identity.
    #[must_use]
    pub const fn connection_id(&self) -> ConnectionId {
        self.token.connection_id
    }

    /// Return this lease's checked generation.
    #[must_use]
    pub const fn generation(&self) -> Generation {
        self.token.generation
    }

    /// Return the immutable pool key.
    #[must_use]
    pub const fn key(&self) -> PoolKey {
        self.token.key
    }

    /// Return an opaque token useful for diagnostics/stale-token tests.
    #[must_use]
    pub const fn token(&self) -> LeaseToken {
        self.token
    }

    /// Borrow the concrete connection while the lease remains active.
    pub fn connection_mut(&self) -> Result<ConnectionGuard<'_, C>, PoolError<C::Error>> {
        let inner = self
            .pool
            .try_borrow_mut()
            .map_err(|_| PoolError::Invariant)?;
        ConnectionGuard::new(inner, self.slot, self.token)
    }

    /// Mint a linear proof after the adapter consumed the response framing
    /// boundary and supplied fresh age/idle facts.
    pub fn prove_reuse(&self, facts: ConnectionFacts) -> Result<ReuseProof, PoolError> {
        if facts.freshness != Freshness::Fresh {
            return Err(match facts.freshness {
                Freshness::Fresh => PoolError::InvalidFacts,
                Freshness::Stale | Freshness::Unknown => PoolError::ConnectionStale,
            });
        }
        Ok(ReuseProof {
            token: self.token,
            facts,
        })
    }

    /// Finalize this lease according to an explicit close/reuse decision.
    pub fn finalize(
        mut self,
        disposition: LeaseDisposition,
        now: Tick,
    ) -> Result<ReleaseOutcome, PoolError<C::Error>> {
        let result = self
            .pool
            .try_borrow_mut()
            .map_err(|_| PoolError::Invariant)
            .and_then(|mut pool| pool.release_lease(self.slot, self.token, disposition, now));
        if result.is_err()
            && let Ok(mut pool) = self.pool.try_borrow_mut()
        {
            pool.abandon_lease(self.slot, self.token, QuarantineReason::Dropped);
        }
        self.active = false;
        result
    }

    /// Complete with a reuse proof.
    pub fn reuse(
        self,
        proof: ReuseProof,
        now: Tick,
    ) -> Result<ReleaseOutcome, PoolError<C::Error>> {
        self.finalize(LeaseDisposition::Reuse(proof), now)
    }

    /// Explicitly close the connection with a typed cleanup result.
    pub fn close(
        self,
        reason: CloseReason,
        now: Tick,
    ) -> Result<ReleaseOutcome, PoolError<C::Error>> {
        self.finalize(LeaseDisposition::Close(reason), now)
    }

    /// Move the connection to quarantine without invoking cleanup.
    pub fn quarantine(
        self,
        reason: QuarantineReason,
        now: Tick,
    ) -> Result<ReleaseOutcome, PoolError<C::Error>> {
        self.finalize(LeaseDisposition::Quarantine(reason), now)
    }
}

impl<C: ConnectionCleanup> Drop for Lease<C> {
    fn drop(&mut self) {
        if self.active {
            if let Ok(mut pool) = self.pool.try_borrow_mut() {
                pool.abandon_lease(self.slot, self.token, QuarantineReason::Dropped);
            }
            self.active = false;
        }
    }
}

/// A short-lived mutable guard over a concrete connection.  It keeps the
/// state borrow alive so no pool operation can race the transport mutation.
pub struct ConnectionGuard<'a, C: ConnectionCleanup> {
    connection: RefMut<'a, C>,
}

impl<'a, C: ConnectionCleanup> ConnectionGuard<'a, C> {
    fn new(
        inner: RefMut<'a, PoolInner<C>>,
        slot: usize,
        token: LeaseToken,
    ) -> Result<ConnectionGuard<'a, C>, PoolError<C::Error>> {
        let mapped = RefMut::filter_map(inner, |pool| match pool.slots.get_mut(slot) {
            Some(Slot::Occupied(entry))
                if entry.connection_id == token.connection_id
                    && entry.generation == token.generation
                    && entry.key == token.key
                    && entry.state == EntryState::Leased =>
            {
                Some(&mut entry.connection)
            }
            Some(Slot::Vacant | Slot::Connecting(_) | Slot::Occupied(_)) | None => None,
        });
        match mapped {
            Ok(connection) => Ok(Self { connection }),
            Err(_) => Err(PoolError::LeaseInvalid),
        }
    }
}

impl<C: ConnectionCleanup> Deref for ConnectionGuard<'_, C> {
    type Target = C;

    fn deref(&self) -> &Self::Target {
        &self.connection
    }
}

impl<C: ConnectionCleanup> DerefMut for ConnectionGuard<'_, C> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.connection
    }
}

/// A linear token identifying one lease generation and immutable key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LeaseToken {
    connection_id: ConnectionId,
    generation: Generation,
    key: PoolKey,
}

impl LeaseToken {
    /// Return the checked connection identity.
    #[must_use]
    pub const fn connection_id(self) -> ConnectionId {
        self.connection_id
    }

    /// Return the checked generation.
    #[must_use]
    pub const fn generation(self) -> Generation {
        self.generation
    }

    /// Return the immutable key.
    #[must_use]
    pub const fn key(self) -> PoolKey {
        self.key
    }
}

/// Explicit release decision; no default/retry/fallback variant exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeaseDisposition {
    /// Return only a connection with a valid consume-to-reuse proof.
    Reuse(ReuseProof),
    /// Invoke the adapter cleanup contract exactly once.
    Close(CloseReason),
    /// Retain ownership for a later explicit finalization call.
    Quarantine(QuarantineReason),
}

/// Result of releasing an active lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseOutcome {
    /// Connection is available for a future same-key acquisition.
    Idle,
    /// Connection was handed to the FIFO head and awaits that ticket's poll.
    Assigned(AcquireTicket),
    /// Cleanup proved that the resource was closed.
    Closed,
    /// Connection remains owned in quarantine.
    Quarantined(ConnectionId),
}

/// Result of attempting to acquire from a bounded pool.
pub enum AcquireResult<C: ConnectionCleanup> {
    /// A reusable idle connection was leased.
    Reused(Lease<C>),
    /// The caller owns one bounded connection-establishment reservation.
    Connect(ConnectPermit<C>),
    /// The request was appended to the FIFO queue.
    Queued(AcquireTicket),
}

/// Result of polling a FIFO ticket.
pub enum PollResult<C: ConnectionCleanup> {
    /// A preceding ticket or capacity condition still blocks this request.
    Waiting,
    /// A reusable connection was leased.
    Reused(Lease<C>),
    /// A new connection reservation is now available.
    Connect(ConnectPermit<C>),
}

/// Pool lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PoolState {
    /// New acquisition and explicit finalization are allowed.
    Open,
    /// New acquisition is rejected; existing leases must drain.
    Draining,
    /// All owned resources and queue state are finalized.
    Closed,
    /// A cleanup/invariant failure requires operator-visible handling.
    Poisoned,
}

/// Observable bounded pool accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PoolSnapshot {
    /// Lifecycle state.
    pub state: PoolState,
    /// Occupied connection slots, including leased, idle, assigned, and
    /// quarantined resources.  Connecting reservations are separate.
    pub live: usize,
    /// Idle reusable slots.
    pub idle: usize,
    /// Active leases.
    pub leased: usize,
    /// Idle slots assigned to a FIFO ticket but not yet polled.
    pub assigned: usize,
    /// Slots awaiting explicit cleanup.
    pub quarantined: usize,
    /// Connection-establishment reservations.
    pub connecting: usize,
    /// FIFO acquisition requests.
    pub queued: usize,
    /// Tickets cancelled by shutdown or explicit cancellation.
    pub cancelled_waiters: usize,
}

/// Per-route accounting, including pending connection reservations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteSnapshot {
    /// Occupied connection slots for the route.
    pub live: usize,
    /// Idle reusable slots for the route.
    pub idle: usize,
    /// Active leases for the route.
    pub leased: usize,
    /// Quarantined slots for the route.
    pub quarantined: usize,
    /// Connection-establishment reservations for the route.
    pub connecting: usize,
}

/// Initial shutdown accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShutdownStart {
    /// Number of queued tickets cancelled.
    pub cancelled_waiters: usize,
    /// Number of connection reservations released.
    pub cancelled_connections: usize,
    /// Number of slots moved to quarantine for explicit cleanup.
    pub quarantined: usize,
}

/// Final shutdown accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShutdownReport {
    /// Number of queued requests cancelled during shutdown.
    pub cancelled_waiters: usize,
    /// Number of resources whose cleanup completed.
    pub finalized_connections: usize,
}

/// Bounded pool policy.  All time values are injected monotonic ticks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PoolConfig {
    max_global_live: NonZeroUsize,
    max_route_live: NonZeroUsize,
    max_global_idle: usize,
    max_route_idle: usize,
    max_queue: usize,
    connection_ttl: NonZeroU64,
    idle_ttl: NonZeroU64,
}

impl PoolConfig {
    /// Construct checked global/route/idle/queue bounds and finite TTLs.
    pub fn new(
        max_global_live: usize,
        max_route_live: usize,
        max_global_idle: usize,
        max_route_idle: usize,
        max_queue: usize,
        connection_ttl: u64,
        idle_ttl: u64,
    ) -> Result<Self, PoolError> {
        let Some(max_global_live) = NonZeroUsize::new(max_global_live) else {
            return Err(PoolError::InvalidCapacity);
        };
        let Some(max_route_live) = NonZeroUsize::new(max_route_live) else {
            return Err(PoolError::InvalidCapacity);
        };
        let Some(connection_ttl) = NonZeroU64::new(connection_ttl) else {
            return Err(PoolError::InvalidCapacity);
        };
        let Some(idle_ttl) = NonZeroU64::new(idle_ttl) else {
            return Err(PoolError::InvalidCapacity);
        };
        if max_global_live.get() > MAX_POOL_LIVE
            || max_route_live.get() > max_global_live.get()
            || max_global_idle > max_global_live.get()
            || max_route_idle > max_route_live.get()
            || max_route_idle > max_global_idle
            || max_queue > MAX_POOL_QUEUE
        {
            return Err(PoolError::InvalidCapacity);
        }
        Ok(Self {
            max_global_live,
            max_route_live,
            max_global_idle,
            max_route_idle,
            max_queue,
            connection_ttl,
            idle_ttl,
        })
    }

    /// Maximum occupied global connection slots.
    #[must_use]
    pub const fn max_global_live(self) -> usize {
        self.max_global_live.get()
    }

    /// Maximum occupied/reserved slots for one route.
    #[must_use]
    pub const fn max_route_live(self) -> usize {
        self.max_route_live.get()
    }

    /// Maximum idle global connections.
    #[must_use]
    pub const fn max_global_idle(self) -> usize {
        self.max_global_idle
    }

    /// Maximum idle connections for one route.
    #[must_use]
    pub const fn max_route_idle(self) -> usize {
        self.max_route_idle
    }

    /// Maximum FIFO queue entries.
    #[must_use]
    pub const fn max_queue(self) -> usize {
        self.max_queue
    }

    /// Connection TTL in injected ticks.
    #[must_use]
    pub const fn connection_ttl(self) -> u64 {
        self.connection_ttl.get()
    }

    /// Idle TTL in injected ticks.
    #[must_use]
    pub const fn idle_ttl(self) -> u64 {
        self.idle_ttl.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EntryState {
    Idle,
    Leased,
    Assigned(RequestId),
    Quarantined {
        reason: QuarantineReason,
        cleanup_attempted: bool,
    },
}

struct ConnectionEntry<C> {
    connection_id: ConnectionId,
    generation: Generation,
    key: PoolKey,
    facts: ConnectionFacts,
    state: EntryState,
    connection: C,
}

#[derive(Clone, Copy)]
struct Reservation {
    connection_id: ConnectionId,
    generation: Generation,
    key: PoolKey,
}

enum Slot<C> {
    Vacant,
    Connecting(Reservation),
    Occupied(ConnectionEntry<C>),
}

struct Waiter {
    ticket: AcquireTicket,
}

enum AcquireState {
    Reused {
        slot: usize,
        token: LeaseToken,
    },
    Connect {
        slot: usize,
        reservation: Reservation,
    },
    Queued(AcquireTicket),
}

enum PollState {
    Waiting,
    Reused {
        slot: usize,
        token: LeaseToken,
    },
    Connect {
        slot: usize,
        reservation: Reservation,
    },
}

/// Internal fixed-capacity state owned by [`ConnectionPool`].
struct PoolInner<C: ConnectionCleanup> {
    config: PoolConfig,
    slots: Vec<Slot<C>>,
    waiters: VecDeque<Waiter>,
    state: PoolState,
    next_connection_id: Option<NonZeroU64>,
    next_generation: Option<NonZeroU64>,
    next_request_id: Option<NonZeroU64>,
    cancelled_waiters: usize,
    shutdown_cancelled_waiters: Option<usize>,
}

impl<C: ConnectionCleanup> fmt::Debug for PoolInner<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PoolInner")
            .field("config", &self.config)
            .field("state", &self.state)
            .field("snapshot", &self.snapshot())
            .finish()
    }
}

impl<C: ConnectionCleanup> PoolInner<C> {
    /// Create fixed-capacity internal state.
    fn new(config: PoolConfig) -> Self {
        let slots = (0..config.max_global_live())
            .map(|_| Slot::Vacant)
            .collect();
        let waiters = VecDeque::with_capacity(config.max_queue());
        Self {
            config,
            slots,
            waiters,
            state: PoolState::Open,
            next_connection_id: NonZeroU64::new(1),
            next_generation: NonZeroU64::new(1),
            next_request_id: NonZeroU64::new(1),
            cancelled_waiters: 0,
            shutdown_cancelled_waiters: None,
        }
    }

    /// Return current bounded accounting.
    #[must_use]
    pub fn snapshot(&self) -> PoolSnapshot {
        let mut live = 0;
        let mut idle = 0;
        let mut leased = 0;
        let mut assigned = 0;
        let mut quarantined = 0;
        let mut connecting = 0;
        for slot in &self.slots {
            match slot {
                Slot::Vacant => {}
                Slot::Connecting(_) => connecting += 1,
                Slot::Occupied(entry) => {
                    live += 1;
                    match entry.state {
                        EntryState::Idle => idle += 1,
                        EntryState::Leased => leased += 1,
                        EntryState::Assigned(_) => assigned += 1,
                        EntryState::Quarantined { .. } => quarantined += 1,
                    }
                }
            }
        }
        PoolSnapshot {
            state: self.state,
            live,
            idle,
            leased,
            assigned,
            quarantined,
            connecting,
            queued: self.waiters.len(),
            cancelled_waiters: self.cancelled_waiters,
        }
    }

    /// Return route-partitioned bounded accounting.
    #[must_use]
    pub fn route_snapshot(&self, key: PoolKey) -> RouteSnapshot {
        let mut result = RouteSnapshot {
            live: 0,
            idle: 0,
            leased: 0,
            quarantined: 0,
            connecting: 0,
        };
        for slot in &self.slots {
            match slot {
                Slot::Vacant => {}
                Slot::Connecting(reservation) if reservation.key.route() == key.route() => {
                    result.connecting += 1;
                }
                Slot::Connecting(_) => {}
                Slot::Occupied(entry) if entry.key.route() == key.route() => {
                    result.live += 1;
                    match entry.state {
                        EntryState::Idle => result.idle += 1,
                        EntryState::Leased => result.leased += 1,
                        EntryState::Assigned(_) => {}
                        EntryState::Quarantined { .. } => result.quarantined += 1,
                    }
                }
                Slot::Occupied(_) => {}
            }
        }
        result
    }

    /// Return the state of a token, rejecting stale ID/generation pairs.
    pub fn token_state(&self, token: LeaseToken) -> Result<ConnectionState, PoolError<C::Error>> {
        let Some((_, entry)) = self.find_entry(token.connection_id) else {
            return Err(PoolError::LeaseInvalid);
        };
        if entry.generation != token.generation || entry.key != token.key {
            return Err(PoolError::LeaseInvalid);
        }
        Ok(match entry.state {
            EntryState::Idle => ConnectionState::Idle,
            EntryState::Leased => ConnectionState::Leased,
            EntryState::Assigned(_) => ConnectionState::Assigned,
            EntryState::Quarantined { .. } => ConnectionState::Quarantined,
        })
    }

    /// Begin one bounded acquisition.  Existing queued requests always win
    /// over a new request, preserving FIFO fairness even when another key has
    /// an idle connection.
    fn acquire_state(
        &mut self,
        key: PoolKey,
        now: Tick,
    ) -> Result<AcquireState, PoolError<C::Error>> {
        self.ensure_open()?;
        self.quarantine_expired_idle(key, now)?;
        if !self.waiters.is_empty() {
            return self.enqueue(key).map(AcquireState::Queued);
        }
        if let Some(slot) = self.take_idle(key, now)? {
            let token = self.lease_idle(slot)?;
            return Ok(AcquireState::Reused { slot, token });
        }
        match self.reserve_slot(key) {
            Ok(reservation) => {
                let slot = self
                    .find_connecting(reservation.connection_id)
                    .ok_or(PoolError::Invariant)?;
                Ok(AcquireState::Connect { slot, reservation })
            }
            Err(PoolError::CapacityFull | PoolError::RouteCapacityFull) => {
                self.enqueue(key).map(AcquireState::Queued)
            }
            Err(error) => Err(error),
        }
    }

    /// Poll exactly one FIFO ticket.  A non-head ticket remains pending and
    /// cannot bypass an earlier request.
    fn poll_state(
        &mut self,
        ticket: AcquireTicket,
        now: Tick,
    ) -> Result<PollState, PoolError<C::Error>> {
        self.ensure_open()?;
        let Some(index) = self
            .waiters
            .iter()
            .position(|waiter| waiter.ticket == ticket)
        else {
            return Err(PoolError::TicketInvalid);
        };
        if index != 0 {
            return Ok(PollState::Waiting);
        }
        self.quarantine_expired_idle(ticket.key, now)?;
        if let Some(slot) = self.find_assigned(ticket) {
            let generation = self.allocate_generation()?;
            self.set_leased_generation(slot, ticket, generation)?;
            let _ = self.waiters.pop_front();
            let connection_id =
                ticket_from_slot_id(self.slots.get(slot).ok_or(PoolError::Invariant)?)?;
            let token = LeaseToken {
                connection_id,
                generation,
                key: ticket.key,
            };
            return Ok(PollState::Reused { slot, token });
        }
        if let Some(slot) = self.take_idle(ticket.key, now)? {
            let token = self.lease_idle(slot)?;
            let _ = self.waiters.pop_front();
            return Ok(PollState::Reused { slot, token });
        }
        match self.reserve_slot(ticket.key) {
            Ok(reservation) => {
                let slot = self
                    .find_connecting(reservation.connection_id)
                    .ok_or(PoolError::Invariant)?;
                let _ = self.waiters.pop_front();
                Ok(PollState::Connect { slot, reservation })
            }
            Err(PoolError::CapacityFull | PoolError::RouteCapacityFull) => Ok(PollState::Waiting),
            Err(error) => Err(error),
        }
    }

    /// Cancel an exact queued ticket.  A handed-off connection returns to
    /// idle only when the configured idle bounds still permit it; otherwise it
    /// is quarantined for explicit cleanup.
    pub fn cancel(&mut self, ticket: AcquireTicket) -> Result<(), PoolError<C::Error>> {
        self.ensure_not_closed()?;
        let Some(index) = self
            .waiters
            .iter()
            .position(|waiter| waiter.ticket == ticket)
        else {
            return Err(PoolError::TicketInvalid);
        };
        let _ = self.waiters.remove(index);
        self.cancelled_waiters = self
            .cancelled_waiters
            .checked_add(1)
            .ok_or(PoolError::Invariant)?;
        if let Some(slot) = self.find_assigned(ticket) {
            let idle_ok = self.idle_capacity_available(ticket.key);
            let slot_state = self.slots.get_mut(slot).ok_or(PoolError::Invariant)?;
            let Slot::Occupied(entry) = slot_state else {
                return Err(PoolError::Invariant);
            };
            entry.state = if idle_ok {
                EntryState::Idle
            } else {
                EntryState::Quarantined {
                    reason: QuarantineReason::IdleCapacity,
                    cleanup_attempted: false,
                }
            };
        }
        Ok(())
    }

    /// Explicitly finalize one quarantined connection.  Cleanup is attempted
    /// at most once; a failure poisons the pool and retains the resource.
    pub fn finalize_connection(
        &mut self,
        connection_id: ConnectionId,
    ) -> Result<ReleaseOutcome, PoolError<C::Error>> {
        let Some(slot) = self.find_slot(connection_id) else {
            return Err(PoolError::LeaseInvalid);
        };
        self.finalize_quarantine_slot(slot).map(|closed| {
            if closed {
                ReleaseOutcome::Closed
            } else {
                ReleaseOutcome::Quarantined(connection_id)
            }
        })
    }

    /// Mark an owned idle/assigned connection for explicit cleanup.
    pub fn quarantine_connection(
        &mut self,
        connection_id: ConnectionId,
        reason: QuarantineReason,
    ) -> Result<(), PoolError<C::Error>> {
        let Some(slot) = self.find_slot(connection_id) else {
            return Err(PoolError::LeaseInvalid);
        };
        let slot_state = self.slots.get_mut(slot).ok_or(PoolError::Invariant)?;
        let Slot::Occupied(entry) = slot_state else {
            return Err(PoolError::LeaseInvalid);
        };
        if matches!(entry.state, EntryState::Leased) {
            return Err(PoolError::LeaseInvalid);
        }
        if matches!(
            entry.state,
            EntryState::Quarantined {
                cleanup_attempted: true,
                ..
            }
        ) {
            return Err(PoolError::CleanupAlreadyAttempted);
        }
        entry.state = EntryState::Quarantined {
            reason,
            cleanup_attempted: false,
        };
        Ok(())
    }

    /// Transition to draining and retain every owned resource for explicit
    /// finalization.  Idle/assigned resources are quarantined; active leases
    /// remain leased until their RAII owner closes or drops them.
    pub fn shutdown(&mut self) -> Result<ShutdownStart, PoolError<C::Error>> {
        match self.state {
            PoolState::Open => {}
            PoolState::Draining => return Err(PoolError::ShuttingDown),
            PoolState::Closed => return Err(PoolError::Closed),
            PoolState::Poisoned => return Err(PoolError::Poisoned),
        }
        self.state = PoolState::Draining;
        let cancelled_waiters = self.waiters.len();
        self.waiters.clear();
        self.cancelled_waiters = self
            .cancelled_waiters
            .checked_add(cancelled_waiters)
            .ok_or(PoolError::Invariant)?;
        self.shutdown_cancelled_waiters = Some(cancelled_waiters);
        let mut cancelled_connections = 0;
        let mut quarantined = 0;
        for slot in &mut self.slots {
            match slot {
                Slot::Vacant => {}
                Slot::Connecting(_) => {
                    *slot = Slot::Vacant;
                    cancelled_connections += 1;
                }
                Slot::Occupied(entry) => match entry.state {
                    EntryState::Idle | EntryState::Assigned(_) => {
                        entry.state = EntryState::Quarantined {
                            reason: QuarantineReason::Shutdown,
                            cleanup_attempted: false,
                        };
                        quarantined += 1;
                    }
                    EntryState::Leased | EntryState::Quarantined { .. } => {}
                },
            }
        }
        Ok(ShutdownStart {
            cancelled_waiters,
            cancelled_connections,
            quarantined,
        })
    }

    /// Finalize all shutdown-owned quarantined resources and close the pool.
    /// No cleanup retry occurs after a typed adapter failure.
    pub fn finalize_shutdown(&mut self) -> Result<ShutdownReport, PoolError<C::Error>> {
        match self.state {
            PoolState::Open => return Err(PoolError::ShuttingDown),
            PoolState::Closed => return Err(PoolError::Closed),
            PoolState::Poisoned => return Err(PoolError::Poisoned),
            PoolState::Draining => {}
        }
        let leased = self.snapshot().leased;
        if leased != 0 {
            return Err(PoolError::ShutdownPending);
        }
        let mut finalized_connections = 0;
        for slot in 0..self.slots.len() {
            if self.slot_is_quarantined(slot)? && self.finalize_quarantine_slot(slot)? {
                finalized_connections += 1;
            }
        }
        if self.snapshot().live != 0 || self.snapshot().connecting != 0 {
            return Err(PoolError::ShutdownPending);
        }
        self.state = PoolState::Closed;
        Ok(ShutdownReport {
            cancelled_waiters: self.shutdown_cancelled_waiters.unwrap_or(0),
            finalized_connections,
        })
    }

    fn ensure_open(&self) -> Result<(), PoolError<C::Error>> {
        match self.state {
            PoolState::Open => Ok(()),
            PoolState::Draining => Err(PoolError::ShuttingDown),
            PoolState::Closed => Err(PoolError::Closed),
            PoolState::Poisoned => Err(PoolError::Poisoned),
        }
    }

    fn ensure_not_closed(&self) -> Result<(), PoolError<C::Error>> {
        match self.state {
            PoolState::Closed => Err(PoolError::Closed),
            PoolState::Poisoned => Err(PoolError::Poisoned),
            PoolState::Open | PoolState::Draining => Ok(()),
        }
    }

    fn allocate_connection_id(&mut self) -> Result<ConnectionId, PoolError<C::Error>> {
        let Some(value) = self.next_connection_id.take() else {
            return Err(PoolError::IdExhausted);
        };
        self.next_connection_id = value.get().checked_add(1).and_then(NonZeroU64::new);
        Ok(ConnectionId(value))
    }

    fn allocate_generation(&mut self) -> Result<Generation, PoolError<C::Error>> {
        let Some(value) = self.next_generation.take() else {
            return Err(PoolError::GenerationExhausted);
        };
        self.next_generation = value.get().checked_add(1).and_then(NonZeroU64::new);
        Ok(Generation(value))
    }

    fn allocate_request_id(&mut self) -> Result<RequestId, PoolError<C::Error>> {
        let Some(value) = self.next_request_id.take() else {
            return Err(PoolError::IdExhausted);
        };
        self.next_request_id = value.get().checked_add(1).and_then(NonZeroU64::new);
        Ok(RequestId(value))
    }

    fn enqueue(&mut self, key: PoolKey) -> Result<AcquireTicket, PoolError<C::Error>> {
        if self.waiters.len() >= self.config.max_queue() {
            return Err(PoolError::QueueFull);
        }
        let ticket = AcquireTicket {
            id: self.allocate_request_id()?,
            key,
        };
        self.waiters.push_back(Waiter { ticket });
        Ok(ticket)
    }

    fn find_slot(&self, connection_id: ConnectionId) -> Option<usize> {
        self.slots.iter().position(|slot| match slot {
            Slot::Occupied(entry) => entry.connection_id == connection_id,
            Slot::Connecting(reservation) => reservation.connection_id == connection_id,
            Slot::Vacant => false,
        })
    }

    fn find_entry(&self, connection_id: ConnectionId) -> Option<(usize, &ConnectionEntry<C>)> {
        self.slots
            .iter()
            .enumerate()
            .find_map(|(index, slot)| match slot {
                Slot::Occupied(entry) if entry.connection_id == connection_id => {
                    Some((index, entry))
                }
                Slot::Vacant | Slot::Connecting(_) | Slot::Occupied(_) => None,
            })
    }

    fn find_connecting(&self, connection_id: ConnectionId) -> Option<usize> {
        self.slots.iter().position(|slot| match slot {
            Slot::Connecting(reservation) => reservation.connection_id == connection_id,
            Slot::Vacant | Slot::Occupied(_) => false,
        })
    }

    fn find_assigned(&self, ticket: AcquireTicket) -> Option<usize> {
        self.slots.iter().position(|slot| match slot {
            Slot::Occupied(entry) => {
                entry.key == ticket.key && entry.state == EntryState::Assigned(ticket.id)
            }
            Slot::Vacant | Slot::Connecting(_) => false,
        })
    }

    fn reserve_slot(&mut self, key: PoolKey) -> Result<Reservation, PoolError<C::Error>> {
        let snapshot = self.snapshot();
        let occupied_or_reserved = snapshot
            .live
            .checked_add(snapshot.connecting)
            .ok_or(PoolError::Invariant)?;
        if occupied_or_reserved >= self.config.max_global_live() {
            return Err(PoolError::CapacityFull);
        }
        let route = self.route_snapshot(key);
        let route_occupied_or_reserved = route
            .live
            .checked_add(route.connecting)
            .ok_or(PoolError::Invariant)?;
        if route_occupied_or_reserved >= self.config.max_route_live() {
            return Err(PoolError::RouteCapacityFull);
        }
        let slot = self
            .slots
            .iter()
            .position(|candidate| matches!(candidate, Slot::Vacant))
            .ok_or(PoolError::Invariant)?;
        let reservation = Reservation {
            connection_id: self.allocate_connection_id()?,
            generation: self.allocate_generation()?,
            key,
        };
        self.slots[slot] = Slot::Connecting(Reservation {
            connection_id: reservation.connection_id,
            generation: reservation.generation,
            key: reservation.key,
        });
        Ok(reservation)
    }

    fn cancel_reservation(
        &mut self,
        slot: usize,
        reservation: Reservation,
    ) -> Result<(), PoolError<C::Error>> {
        let slot_state = self.slots.get_mut(slot).ok_or(PoolError::Invariant)?;
        match slot_state {
            Slot::Connecting(current)
                if current.connection_id == reservation.connection_id
                    && current.generation == reservation.generation
                    && current.key == reservation.key =>
            {
                *slot_state = Slot::Vacant;
                Ok(())
            }
            Slot::Connecting(_) => Err(PoolError::LeaseInvalid),
            Slot::Vacant | Slot::Occupied(_) => Err(PoolError::LeaseReleased),
        }
    }

    fn complete_connection(
        &mut self,
        slot: usize,
        reservation: Reservation,
        connection: C,
        facts: ConnectionFacts,
        now: Tick,
    ) -> Result<(), PoolError<C::Error>> {
        let slot_state = self.slots.get_mut(slot).ok_or(PoolError::Invariant)?;
        let current = match mem::replace(slot_state, Slot::Vacant) {
            Slot::Connecting(current)
                if current.connection_id == reservation.connection_id
                    && current.generation == reservation.generation
                    && current.key == reservation.key =>
            {
                current
            }
            other => {
                *slot_state = other;
                return Err(PoolError::LeaseInvalid);
            }
        };
        let entry = ConnectionEntry {
            connection_id: current.connection_id,
            generation: current.generation,
            key: current.key,
            facts,
            state: EntryState::Leased,
            connection,
        };
        let validity = Self::facts_validity(entry.facts, now, self.config);
        if validity != FactsValidity::Eligible {
            let error = validity.error();
            let reason = validity.quarantine_reason();
            *slot_state = Slot::Occupied(ConnectionEntry {
                state: EntryState::Quarantined {
                    reason,
                    cleanup_attempted: false,
                },
                ..entry
            });
            return Err(error);
        }
        *slot_state = Slot::Occupied(entry);
        Ok(())
    }

    fn lease_idle(&mut self, slot: usize) -> Result<LeaseToken, PoolError<C::Error>> {
        let generation = self.allocate_generation()?;
        let slot_state = self.slots.get_mut(slot).ok_or(PoolError::Invariant)?;
        let Slot::Occupied(entry) = slot_state else {
            return Err(PoolError::Invariant);
        };
        if entry.state != EntryState::Idle {
            return Err(PoolError::LeaseInvalid);
        }
        entry.state = EntryState::Leased;
        entry.generation = generation;
        Ok(LeaseToken {
            connection_id: entry.connection_id,
            generation,
            key: entry.key,
        })
    }

    fn set_leased_generation(
        &mut self,
        slot: usize,
        ticket: AcquireTicket,
        generation: Generation,
    ) -> Result<(), PoolError<C::Error>> {
        let slot_state = self.slots.get_mut(slot).ok_or(PoolError::Invariant)?;
        let Slot::Occupied(entry) = slot_state else {
            return Err(PoolError::Invariant);
        };
        if entry.key != ticket.key || entry.state != EntryState::Assigned(ticket.id) {
            return Err(PoolError::LeaseInvalid);
        }
        entry.generation = generation;
        entry.state = EntryState::Leased;
        Ok(())
    }

    fn take_leased(
        &mut self,
        slot: usize,
        token: LeaseToken,
    ) -> Result<ConnectionEntry<C>, PoolError<C::Error>> {
        let slot_state = self.slots.get_mut(slot).ok_or(PoolError::LeaseInvalid)?;
        let entry = match mem::replace(slot_state, Slot::Vacant) {
            Slot::Occupied(entry)
                if entry.connection_id == token.connection_id
                    && entry.generation == token.generation
                    && entry.key == token.key
                    && entry.state == EntryState::Leased =>
            {
                entry
            }
            other => {
                *slot_state = other;
                return Err(PoolError::LeaseInvalid);
            }
        };
        Ok(entry)
    }

    fn release_lease(
        &mut self,
        slot: usize,
        token: LeaseToken,
        disposition: LeaseDisposition,
        now: Tick,
    ) -> Result<ReleaseOutcome, PoolError<C::Error>> {
        let mut entry = self.take_leased(slot, token)?;
        match disposition {
            LeaseDisposition::Reuse(proof) => {
                if proof.token != token {
                    self.put_quarantine(slot, entry, QuarantineReason::InvalidReuseProof)?;
                    return Err(PoolError::InvalidReuseProof);
                }
                if self.state != PoolState::Open {
                    self.put_quarantine(slot, entry, QuarantineReason::Shutdown)?;
                    return Err(PoolError::ShuttingDown);
                }
                let validity = Self::facts_validity(proof.facts, now, self.config);
                if validity != FactsValidity::Eligible {
                    self.put_quarantine(slot, entry, validity.quarantine_reason())?;
                    return Err(validity.error());
                }
                let idle_generation = match self.allocate_generation() {
                    Ok(generation) => generation,
                    Err(error) => {
                        self.put_quarantine(slot, entry, QuarantineReason::InvalidReuseProof)?;
                        return Err(error);
                    }
                };
                entry.facts = proof.facts;
                entry.generation = idle_generation;
                if let Some(waiter) = self.waiters.front()
                    && waiter.ticket.key == entry.key
                {
                    let ticket = waiter.ticket;
                    entry.state = EntryState::Assigned(ticket.id);
                    self.slots[slot] = Slot::Occupied(entry);
                    return Ok(ReleaseOutcome::Assigned(ticket));
                }
                if self.idle_capacity_available(entry.key) {
                    entry.state = EntryState::Idle;
                    self.slots[slot] = Slot::Occupied(entry);
                    Ok(ReleaseOutcome::Idle)
                } else {
                    self.put_quarantine(slot, entry, QuarantineReason::IdleCapacity)?;
                    Ok(ReleaseOutcome::Quarantined(token.connection_id))
                }
            }
            LeaseDisposition::Quarantine(reason) => {
                self.put_quarantine(slot, entry, reason)?;
                Ok(ReleaseOutcome::Quarantined(token.connection_id))
            }
            LeaseDisposition::Close(_reason) => {
                let connection_id = entry.connection_id;
                match entry.connection.cleanup() {
                    Ok(()) => Ok(ReleaseOutcome::Closed),
                    Err(failure) => {
                        self.state = PoolState::Poisoned;
                        self.slots[slot] = Slot::Occupied(ConnectionEntry {
                            connection_id,
                            generation: entry.generation,
                            key: entry.key,
                            facts: entry.facts,
                            state: EntryState::Quarantined {
                                reason: QuarantineReason::CleanupFailure,
                                cleanup_attempted: true,
                            },
                            connection: failure.connection,
                        });
                        Err(PoolError::Cleanup {
                            connection_id,
                            error: failure.error,
                        })
                    }
                }
            }
        }
    }

    fn put_quarantine(
        &mut self,
        slot: usize,
        entry: ConnectionEntry<C>,
        reason: QuarantineReason,
    ) -> Result<(), PoolError<C::Error>> {
        if slot >= self.slots.len() {
            return Err(PoolError::Invariant);
        }
        self.slots[slot] = Slot::Occupied(ConnectionEntry {
            state: EntryState::Quarantined {
                reason,
                cleanup_attempted: false,
            },
            ..entry
        });
        Ok(())
    }

    fn abandon_lease(&mut self, slot: usize, token: LeaseToken, reason: QuarantineReason) {
        if let Some(Slot::Occupied(entry)) = self.slots.get_mut(slot)
            && entry.connection_id == token.connection_id
            && entry.generation == token.generation
            && entry.key == token.key
            && entry.state == EntryState::Leased
        {
            entry.state = EntryState::Quarantined {
                reason,
                cleanup_attempted: false,
            };
        }
    }

    fn idle_capacity_available(&self, key: PoolKey) -> bool {
        let snapshot = self.snapshot();
        if snapshot.idle >= self.config.max_global_idle() {
            return false;
        }
        self.route_snapshot(key).idle < self.config.max_route_idle()
    }

    fn take_idle(&mut self, key: PoolKey, now: Tick) -> Result<Option<usize>, PoolError<C::Error>> {
        for slot in 0..self.slots.len() {
            let Some(entry) = self.occupied_entry(slot) else {
                continue;
            };
            if entry.key != key || entry.state != EntryState::Idle {
                continue;
            }
            match Self::facts_validity(entry.facts, now, self.config) {
                FactsValidity::Eligible => return Ok(Some(slot)),
                invalid => {
                    let reason = invalid.quarantine_reason();
                    let slot_state = self.slots.get_mut(slot).ok_or(PoolError::Invariant)?;
                    let Slot::Occupied(entry) = slot_state else {
                        return Err(PoolError::Invariant);
                    };
                    entry.state = EntryState::Quarantined {
                        reason,
                        cleanup_attempted: false,
                    };
                    if invalid == FactsValidity::Reversed {
                        return Err(invalid.error());
                    }
                }
            }
        }
        Ok(None)
    }

    fn occupied_entry(&self, slot: usize) -> Option<&ConnectionEntry<C>> {
        match self.slots.get(slot) {
            Some(Slot::Occupied(entry)) => Some(entry),
            Some(Slot::Vacant | Slot::Connecting(_)) | None => None,
        }
    }

    fn quarantine_expired_idle(
        &mut self,
        key: PoolKey,
        now: Tick,
    ) -> Result<(), PoolError<C::Error>> {
        let _ = self.take_idle(key, now)?;
        Ok(())
    }

    fn slot_is_quarantined(&self, slot: usize) -> Result<bool, PoolError<C::Error>> {
        let Some(slot_state) = self.slots.get(slot) else {
            return Err(PoolError::Invariant);
        };
        match slot_state {
            Slot::Occupied(entry) => Ok(matches!(entry.state, EntryState::Quarantined { .. })),
            Slot::Vacant | Slot::Connecting(_) => Ok(false),
        }
    }

    fn finalize_quarantine_slot(&mut self, slot: usize) -> Result<bool, PoolError<C::Error>> {
        let slot_state = self.slots.get_mut(slot).ok_or(PoolError::Invariant)?;
        let entry = match mem::replace(slot_state, Slot::Vacant) {
            Slot::Occupied(entry) if matches!(entry.state, EntryState::Quarantined { .. }) => entry,
            other => {
                *slot_state = other;
                return Err(PoolError::LeaseInvalid);
            }
        };
        let cleanup_attempted = match entry.state {
            EntryState::Quarantined {
                cleanup_attempted, ..
            } => cleanup_attempted,
            EntryState::Idle | EntryState::Leased | EntryState::Assigned(_) => false,
        };
        if cleanup_attempted {
            *slot_state = Slot::Occupied(entry);
            return Err(PoolError::CleanupAlreadyAttempted);
        }
        let connection_id = entry.connection_id;
        match entry.connection.cleanup() {
            Ok(()) => Ok(true),
            Err(failure) => {
                self.state = PoolState::Poisoned;
                *slot_state = Slot::Occupied(ConnectionEntry {
                    connection_id,
                    generation: entry.generation,
                    key: entry.key,
                    facts: entry.facts,
                    state: EntryState::Quarantined {
                        reason: QuarantineReason::CleanupFailure,
                        cleanup_attempted: true,
                    },
                    connection: failure.connection,
                });
                Err(PoolError::Cleanup {
                    connection_id,
                    error: failure.error,
                })
            }
        }
    }

    fn facts_validity(facts: ConnectionFacts, now: Tick, config: PoolConfig) -> FactsValidity {
        if facts.last_used_at < facts.created_at || now < facts.created_at {
            return FactsValidity::Reversed;
        }
        let Some(age) = now.get().checked_sub(facts.created_at.get()) else {
            return FactsValidity::Reversed;
        };
        let Some(idle) = now.get().checked_sub(facts.last_used_at.get()) else {
            return FactsValidity::Reversed;
        };
        if age > config.connection_ttl() || idle > config.idle_ttl() {
            return FactsValidity::Expired;
        }
        match facts.freshness {
            Freshness::Fresh => FactsValidity::Eligible,
            Freshness::Stale | Freshness::Unknown => FactsValidity::Stale,
        }
    }
}

/// Shared owner for the bounded pool state.
///
/// The state machine is executor-neutral but intentionally single-owner:
/// `Rc<RefCell<_>>` makes this type non-`Send`/non-`Sync`. Keep one pool inside
/// one native I/O executor/worker owner; cross-thread sharing belongs at an
/// explicit bounded protocol boundary rather than in this state layer.
pub struct ConnectionPool<C: ConnectionCleanup> {
    config: PoolConfig,
    inner: Rc<RefCell<PoolInner<C>>>,
}

impl<C: ConnectionCleanup> fmt::Debug for ConnectionPool<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner
            .try_borrow()
            .map_err(|_| fmt::Error)
            .and_then(|inner| inner.fmt(formatter))
    }
}

impl<C: ConnectionCleanup> ConnectionPool<C> {
    /// Create a fixed-capacity executor-neutral pool.
    pub fn new(config: PoolConfig) -> Result<Self, PoolError<C::Error>> {
        Ok(Self {
            config,
            inner: Rc::new(RefCell::new(PoolInner::new(config))),
        })
    }

    /// Return the immutable policy.
    #[must_use]
    pub fn config(&self) -> PoolConfig {
        self.config
    }

    /// Return current bounded accounting.
    #[must_use = "inspect the pool accounting or handle the invariant error"]
    pub fn snapshot(&self) -> Result<PoolSnapshot, PoolError<C::Error>> {
        self.inner
            .try_borrow()
            .map(|inner| inner.snapshot())
            .map_err(|_| PoolError::Invariant)
    }

    /// Return route-partitioned accounting.
    #[must_use = "inspect the route accounting or handle the invariant error"]
    pub fn route_snapshot(&self, key: PoolKey) -> Result<RouteSnapshot, PoolError<C::Error>> {
        self.inner
            .try_borrow()
            .map(|inner| inner.route_snapshot(key))
            .map_err(|_| PoolError::Invariant)
    }

    /// Return the state of a token, rejecting stale ID/generation pairs.
    pub fn token_state(&self, token: LeaseToken) -> Result<ConnectionState, PoolError<C::Error>> {
        self.inner
            .try_borrow()
            .map_err(|_| PoolError::Invariant)
            .and_then(|inner| inner.token_state(token))
    }

    /// Begin one bounded acquisition.
    pub fn acquire(
        &self,
        key: PoolKey,
        now: Tick,
    ) -> Result<AcquireResult<C>, PoolError<C::Error>> {
        let state = self
            .inner
            .try_borrow_mut()
            .map_err(|_| PoolError::Invariant)
            .and_then(|mut inner| inner.acquire_state(key, now))?;
        Ok(self.wrap_acquire(state))
    }

    /// Poll one exact FIFO ticket.
    pub fn poll(
        &self,
        ticket: AcquireTicket,
        now: Tick,
    ) -> Result<PollResult<C>, PoolError<C::Error>> {
        let state = self
            .inner
            .try_borrow_mut()
            .map_err(|_| PoolError::Invariant)
            .and_then(|mut inner| inner.poll_state(ticket, now))?;
        Ok(self.wrap_poll(state))
    }

    /// Cancel one exact FIFO ticket.
    pub fn cancel(&self, ticket: AcquireTicket) -> Result<(), PoolError<C::Error>> {
        self.inner
            .try_borrow_mut()
            .map_err(|_| PoolError::Invariant)
            .and_then(|mut inner| inner.cancel(ticket))
    }

    /// Finalize one quarantined connection.
    pub fn finalize_connection(
        &self,
        connection_id: ConnectionId,
    ) -> Result<ReleaseOutcome, PoolError<C::Error>> {
        self.inner
            .try_borrow_mut()
            .map_err(|_| PoolError::Invariant)
            .and_then(|mut inner| inner.finalize_connection(connection_id))
    }

    /// Mark one non-leased connection for explicit cleanup.
    pub fn quarantine_connection(
        &self,
        connection_id: ConnectionId,
        reason: QuarantineReason,
    ) -> Result<(), PoolError<C::Error>> {
        self.inner
            .try_borrow_mut()
            .map_err(|_| PoolError::Invariant)
            .and_then(|mut inner| inner.quarantine_connection(connection_id, reason))
    }

    /// Begin bounded shutdown and quarantine all idle/assigned resources.
    pub fn shutdown(&self) -> Result<ShutdownStart, PoolError<C::Error>> {
        self.inner
            .try_borrow_mut()
            .map_err(|_| PoolError::Invariant)
            .and_then(|mut inner| inner.shutdown())
    }

    /// Explicitly finalize all shutdown-owned resources.
    pub fn finalize_shutdown(&self) -> Result<ShutdownReport, PoolError<C::Error>> {
        self.inner
            .try_borrow_mut()
            .map_err(|_| PoolError::Invariant)
            .and_then(|mut inner| inner.finalize_shutdown())
    }

    fn wrap_acquire(&self, state: AcquireState) -> AcquireResult<C> {
        match state {
            AcquireState::Reused { slot, token } => AcquireResult::Reused(Lease {
                pool: Rc::clone(&self.inner),
                slot,
                token,
                active: true,
            }),
            AcquireState::Connect { slot, reservation } => AcquireResult::Connect(ConnectPermit {
                pool: Rc::clone(&self.inner),
                slot,
                reservation,
                active: true,
            }),
            AcquireState::Queued(ticket) => AcquireResult::Queued(ticket),
        }
    }

    fn wrap_poll(&self, state: PollState) -> PollResult<C> {
        match state {
            PollState::Waiting => PollResult::Waiting,
            PollState::Reused { slot, token } => PollResult::Reused(Lease {
                pool: Rc::clone(&self.inner),
                slot,
                token,
                active: true,
            }),
            PollState::Connect { slot, reservation } => PollResult::Connect(ConnectPermit {
                pool: Rc::clone(&self.inner),
                slot,
                reservation,
                active: true,
            }),
        }
    }
}

impl<C: ConnectionCleanup> ConnectionPool<C> {
    #[cfg(test)]
    fn set_next_ids_for_test(
        &self,
        connection: Option<NonZeroU64>,
        generation: Option<NonZeroU64>,
        request: Option<NonZeroU64>,
    ) {
        let mut inner = self.inner.try_borrow_mut().expect("test state borrow");
        inner.next_connection_id = connection;
        inner.next_generation = generation;
        inner.next_request_id = request;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FactsValidity {
    Eligible,
    Reversed,
    Expired,
    Stale,
}

impl FactsValidity {
    const fn error<E>(self) -> PoolError<E> {
        match self {
            Self::Eligible => PoolError::Invariant,
            Self::Reversed => PoolError::ClockReversed,
            Self::Expired => PoolError::ConnectionExpired,
            Self::Stale => PoolError::ConnectionStale,
        }
    }

    const fn quarantine_reason(self) -> QuarantineReason {
        match self {
            Self::Eligible => QuarantineReason::InvalidReuseProof,
            Self::Reversed | Self::Expired | Self::Stale => QuarantineReason::Expired,
        }
    }
}

/// Public connection state used by deterministic assertions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionState {
    /// Connection establishment slot is reserved but no resource exists yet.
    Connecting,
    /// Connection is held by one active lease.
    Leased,
    /// Connection is reusable and idle.
    Idle,
    /// Connection is assigned to a FIFO ticket.
    Assigned,
    /// Connection remains owned pending explicit cleanup.
    Quarantined,
}

fn ticket_from_slot_id<C, E>(slot: &Slot<C>) -> Result<ConnectionId, PoolError<E>> {
    match slot {
        Slot::Occupied(entry) => Ok(entry.connection_id),
        Slot::Vacant | Slot::Connecting(_) => Err(PoolError::Invariant),
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::panic,
        reason = "fixed in-memory fixtures use expect at assertion boundaries"
    )]

    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;

    #[derive(Debug)]
    struct FakeConnection {
        id: u8,
        cleaned: Rc<Cell<usize>>,
        fail_cleanup: bool,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct FakeCleanupError;

    impl ConnectionCleanup for FakeConnection {
        type Error = FakeCleanupError;

        fn cleanup(self) -> Result<(), CleanupFailure<Self, Self::Error>> {
            if self.fail_cleanup {
                Err(CleanupFailure {
                    connection: self,
                    error: FakeCleanupError,
                })
            } else {
                self.cleaned.set(self.cleaned.get() + 1);
                Ok(())
            }
        }
    }

    fn config() -> PoolConfig {
        PoolConfig::new(2, 2, 2, 2, 4, 10, 4).expect("valid config")
    }

    fn single_config() -> PoolConfig {
        PoolConfig::new(1, 1, 1, 1, 4, 10, 4).expect("single-slot config")
    }

    fn key(route: u64, origin: u64, tls: u64) -> PoolKey {
        PoolKey::new(
            RouteIdentity::new(route).expect("route"),
            OriginIdentity::new(origin).expect("origin"),
            TlsIdentity::new(tls).expect("tls"),
        )
    }

    fn facts(created: u64, last_used: u64) -> ConnectionFacts {
        ConnectionFacts::new(
            Tick::from_raw(created),
            Tick::from_raw(last_used),
            Freshness::Fresh,
        )
        .expect("facts")
    }

    fn connection(id: u8, cleaned: &Rc<Cell<usize>>) -> FakeConnection {
        FakeConnection {
            id,
            cleaned: Rc::clone(cleaned),
            fail_cleanup: false,
        }
    }

    fn active(
        pool: &ConnectionPool<FakeConnection>,
        partition: PoolKey,
        cleaned: &Rc<Cell<usize>>,
        id: u8,
    ) -> Lease<FakeConnection> {
        let result = pool.acquire(partition, Tick::from_raw(0)).expect("acquire");
        let AcquireResult::Connect(permit) = result else {
            panic!("new pool must request one connection");
        };
        permit
            .complete(connection(id, cleaned), facts(0, 0), Tick::from_raw(0))
            .expect("complete")
    }

    #[test]
    fn bounds_and_opaque_zero_identities_are_checked() {
        assert_eq!(
            PoolConfig::new(0, 1, 0, 0, 0, 1, 1),
            Err(PoolError::InvalidCapacity)
        );
        assert_eq!(
            PoolConfig::new(1, 2, 0, 0, 0, 1, 1),
            Err(PoolError::InvalidCapacity)
        );
        assert_eq!(
            PoolConfig::new(1, 1, 2, 0, 0, 1, 1),
            Err(PoolError::InvalidCapacity)
        );
        assert_eq!(RouteIdentity::new(0), Err(PoolError::InvalidIdentity));
        assert_eq!(OriginIdentity::new(0), Err(PoolError::InvalidIdentity));
        assert_eq!(TlsIdentity::new(0), Err(PoolError::InvalidIdentity));
        assert_eq!(
            ConnectionFacts::new(Tick::from_raw(2), Tick::from_raw(1), Freshness::Fresh),
            Err(PoolError::InvalidFacts)
        );
    }

    #[test]
    fn new_connection_has_one_lease_and_drop_quarantines_without_cleanup() {
        let cleaned = Rc::new(Cell::new(0));
        let partition = key(1, 2, 3);
        let pool = ConnectionPool::new(single_config()).expect("pool");
        let lease = active(&pool, partition, &cleaned, 1);
        assert_eq!(
            pool.snapshot().expect("snapshot"),
            PoolSnapshot {
                state: PoolState::Open,
                live: 1,
                idle: 0,
                leased: 1,
                assigned: 0,
                quarantined: 0,
                connecting: 0,
                queued: 0,
                cancelled_waiters: 0
            }
        );
        let id = lease.connection_id();
        drop(lease);
        assert_eq!(cleaned.get(), 0);
        assert_eq!(pool.snapshot().expect("snapshot").quarantined, 1);
        assert_eq!(pool.finalize_connection(id), Ok(ReleaseOutcome::Closed));
        assert_eq!(cleaned.get(), 1);
        assert_eq!(pool.snapshot().expect("snapshot").live, 0);
    }

    #[test]
    fn reentrant_snapshot_borrow_returns_typed_invariant_without_mutation() {
        let cleaned = Rc::new(Cell::new(0));
        let partition = key(1, 2, 3);
        let pool = ConnectionPool::new(single_config()).expect("pool");
        let lease = active(&pool, partition, &cleaned, 1);
        let before = pool.snapshot().expect("snapshot");
        let guard = lease.connection_mut().expect("connection guard");

        assert_eq!(pool.snapshot(), Err(PoolError::Invariant));
        assert_eq!(pool.route_snapshot(partition), Err(PoolError::Invariant));

        drop(guard);
        assert_eq!(pool.snapshot().expect("snapshot"), before);
        assert_eq!(
            pool.route_snapshot(partition)
                .expect("route snapshot")
                .leased,
            1
        );
    }

    #[test]
    fn consume_to_reuse_preserves_key_and_updates_idle_facts() {
        let cleaned = Rc::new(Cell::new(0));
        let partition = key(1, 2, 3);
        let pool = ConnectionPool::new(single_config()).expect("pool");
        let lease = active(&pool, partition, &cleaned, 1);
        let proof = lease.prove_reuse(facts(0, 1)).expect("proof");
        assert_eq!(
            lease.reuse(proof, Tick::from_raw(1)),
            Ok(ReleaseOutcome::Idle)
        );
        assert_eq!(pool.snapshot().expect("snapshot").idle, 1);
        let result = pool.acquire(partition, Tick::from_raw(2)).expect("reuse");
        let AcquireResult::Reused(lease) = result else {
            panic!("idle connection was not reused");
        };
        assert_eq!(lease.key(), partition);
        assert_eq!(lease.connection_mut().expect("connection").id, 1);
        let proof = lease.prove_reuse(facts(0, 2)).expect("proof");
        assert_eq!(
            lease.reuse(proof, Tick::from_raw(2)),
            Ok(ReleaseOutcome::Idle)
        );
        assert_eq!(cleaned.get(), 0);
    }

    #[test]
    fn fifo_handoff_does_not_bypass_waiters() {
        let cleaned = Rc::new(Cell::new(0));
        let partition = key(1, 2, 3);
        let pool = ConnectionPool::new(single_config()).expect("pool");
        let lease = active(&pool, partition, &cleaned, 1);
        let AcquireResult::Queued(first) =
            pool.acquire(partition, Tick::from_raw(1)).expect("queue")
        else {
            panic!("first request should queue");
        };
        let AcquireResult::Queued(second) =
            pool.acquire(partition, Tick::from_raw(1)).expect("queue")
        else {
            panic!("second request should queue");
        };
        let first_connection_id = lease.connection_id();
        let proof = lease.prove_reuse(facts(0, 1)).expect("proof");
        assert_eq!(
            lease.reuse(proof, Tick::from_raw(1)),
            Ok(ReleaseOutcome::Assigned(first))
        );
        let PollResult::Reused(first_lease) = pool.poll(first, Tick::from_raw(1)).expect("poll")
        else {
            panic!("first ticket not served");
        };
        assert!(matches!(
            pool.poll(second, Tick::from_raw(1)).expect("poll"),
            PollResult::Waiting
        ));
        let proof = first_lease.prove_reuse(facts(0, 1)).expect("proof");
        assert_eq!(
            first_lease.reuse(proof, Tick::from_raw(1)),
            Ok(ReleaseOutcome::Assigned(second))
        );
        let PollResult::Reused(second_lease) = pool.poll(second, Tick::from_raw(1)).expect("poll")
        else {
            panic!("second ticket not served");
        };
        assert_eq!(second_lease.connection_id(), first_connection_id);
        let proof = second_lease.prove_reuse(facts(0, 1)).expect("proof");
        assert_eq!(
            second_lease.reuse(proof, Tick::from_raw(1)),
            Ok(ReleaseOutcome::Idle)
        );
    }

    #[test]
    fn cancellation_releases_queue_and_assigned_handoff() {
        let cleaned = Rc::new(Cell::new(0));
        let partition = key(1, 2, 3);
        let pool = ConnectionPool::new(single_config()).expect("pool");
        let lease = active(&pool, partition, &cleaned, 1);
        let AcquireResult::Queued(ticket) =
            pool.acquire(partition, Tick::from_raw(1)).expect("queue")
        else {
            panic!("request should queue");
        };
        let proof = lease.prove_reuse(facts(0, 1)).expect("proof");
        assert_eq!(
            lease.reuse(proof, Tick::from_raw(1)),
            Ok(ReleaseOutcome::Assigned(ticket))
        );
        pool.cancel(ticket).expect("cancel");
        assert_eq!(pool.snapshot().expect("snapshot").queued, 0);
        assert_eq!(pool.snapshot().expect("snapshot").idle, 1);
    }

    #[test]
    fn dropping_a_connect_permit_releases_only_its_reservation() {
        let cleaned = Rc::new(Cell::new(0));
        let partition = key(1, 2, 3);
        let pool: ConnectionPool<FakeConnection> = ConnectionPool::new(config()).expect("pool");
        let result = pool.acquire(partition, Tick::from_raw(0)).expect("acquire");
        let AcquireResult::Connect(permit) = result else {
            panic!("first acquisition should reserve a connection");
        };
        let reserved_id = permit.connection_id();
        drop(permit);
        assert_eq!(pool.snapshot().expect("snapshot").connecting, 0);
        assert_eq!(pool.snapshot().expect("snapshot").live, 0);
        let result = pool
            .acquire(partition, Tick::from_raw(0))
            .expect("acquire again");
        let AcquireResult::Connect(permit) = result else {
            panic!("reservation was not released");
        };
        assert_ne!(permit.connection_id(), reserved_id);
        drop(permit);
        assert_eq!(cleaned.get(), 0);
    }

    #[test]
    fn cancelled_lease_is_quarantined_until_explicit_cleanup() {
        let cleaned = Rc::new(Cell::new(0));
        let partition = key(1, 2, 3);
        let pool = ConnectionPool::new(config()).expect("pool");
        let lease = active(&pool, partition, &cleaned, 1);
        let id = lease.connection_id();
        assert_eq!(
            lease.quarantine(QuarantineReason::Cancelled, Tick::from_raw(0)),
            Ok(ReleaseOutcome::Quarantined(id))
        );
        assert_eq!(pool.snapshot().expect("snapshot").quarantined, 1);
        assert_eq!(pool.finalize_connection(id), Ok(ReleaseOutcome::Closed));
        assert_eq!(cleaned.get(), 1);
        assert_eq!(pool.finalize_connection(id), Err(PoolError::LeaseInvalid));
    }

    #[test]
    fn stale_generation_is_rejected_after_idle_transition() {
        let cleaned = Rc::new(Cell::new(0));
        let partition = key(1, 2, 3);
        let pool = ConnectionPool::new(config()).expect("pool");
        let lease = active(&pool, partition, &cleaned, 1);
        let stale = lease.token();
        let proof = lease.prove_reuse(facts(0, 1)).expect("proof");
        lease.reuse(proof, Tick::from_raw(1)).expect("idle");
        assert_eq!(pool.token_state(stale), Err(PoolError::LeaseInvalid));
        let AcquireResult::Reused(lease) =
            pool.acquire(partition, Tick::from_raw(1)).expect("reuse")
        else {
            panic!("reuse");
        };
        assert_ne!(lease.generation(), stale.generation());
        let proof = lease.prove_reuse(facts(0, 1)).expect("proof");
        lease.reuse(proof, Tick::from_raw(1)).expect("idle");
    }

    #[test]
    fn reversed_tick_quarantines_and_returns_a_typed_clock_error() {
        let cleaned = Rc::new(Cell::new(0));
        let partition = key(1, 2, 3);
        let pool = ConnectionPool::new(config()).expect("pool");
        let result = pool.acquire(partition, Tick::from_raw(5)).expect("acquire");
        let AcquireResult::Connect(permit) = result else {
            panic!("new connection should reserve");
        };
        let lease = permit
            .complete(connection(1, &cleaned), facts(5, 5), Tick::from_raw(5))
            .expect("complete");
        let id = lease.connection_id();
        let proof = lease.prove_reuse(facts(5, 5)).expect("proof");
        lease.reuse(proof, Tick::from_raw(5)).expect("idle");
        assert!(matches!(
            pool.acquire(partition, Tick::from_raw(4)),
            Err(PoolError::ClockReversed)
        ));
        assert_eq!(pool.snapshot().expect("snapshot").quarantined, 1);
        pool.finalize_connection(id).expect("cleanup");
    }

    #[test]
    fn ttl_idle_and_freshness_fail_closed_to_quarantine() {
        let cleaned = Rc::new(Cell::new(0));
        let partition = key(1, 2, 3);
        let pool = ConnectionPool::new(config()).expect("pool");
        let lease = active(&pool, partition, &cleaned, 1);
        let proof = lease.prove_reuse(facts(0, 0)).expect("proof");
        lease.reuse(proof, Tick::from_raw(0)).expect("idle");
        match pool
            .acquire(partition, Tick::from_raw(11))
            .expect("bounded capacity")
        {
            AcquireResult::Connect(permit) => drop(permit),
            AcquireResult::Queued(ticket) => pool.cancel(ticket).expect("cancel queued request"),
            AcquireResult::Reused(_) => panic!("expired connection was reused"),
        }
        assert_eq!(pool.snapshot().expect("snapshot").live, 1);
        let token = pool
            .inner
            .try_borrow()
            .expect("pool state")
            .slots
            .iter()
            .find_map(|slot| match slot {
                Slot::Occupied(entry) => Some(entry.connection_id),
                Slot::Vacant | Slot::Connecting(_) => None,
            })
            .expect("quarantined id");
        pool.finalize_connection(token).expect("cleanup");
        assert_eq!(cleaned.get(), 1);
    }

    #[test]
    fn capacity_is_bounded_globally_and_per_route() {
        let cleaned = Rc::new(Cell::new(0));
        let pool = ConnectionPool::new(PoolConfig::new(2, 1, 2, 1, 2, 10, 10).expect("config"))
            .expect("pool");
        let first_key = key(1, 2, 3);
        let second_key = key(2, 3, 4);
        let first = active(&pool, first_key, &cleaned, 1);
        let second = active(&pool, second_key, &cleaned, 2);
        assert_eq!(
            pool.route_snapshot(first_key).expect("route snapshot").live,
            1
        );
        assert_eq!(
            pool.route_snapshot(second_key)
                .expect("route snapshot")
                .live,
            1
        );
        let AcquireResult::Queued(ticket) =
            pool.acquire(first_key, Tick::from_raw(0)).expect("queue")
        else {
            panic!("route cap should queue");
        };
        assert!(matches!(
            pool.poll(ticket, Tick::from_raw(0)).expect("poll"),
            PollResult::Waiting
        ));
        drop(first);
        drop(second);
        assert_eq!(pool.snapshot().expect("snapshot").quarantined, 2);
    }

    #[test]
    fn cleanup_failure_poisoning_is_typed_and_not_retried() {
        let cleaned = Rc::new(Cell::new(0));
        let partition = key(1, 2, 3);
        let pool = ConnectionPool::new(config()).expect("pool");
        let result = pool.acquire(partition, Tick::from_raw(0)).expect("acquire");
        let AcquireResult::Connect(permit) = result else {
            panic!("connect");
        };
        let lease = permit
            .complete(
                FakeConnection {
                    id: 9,
                    cleaned: Rc::clone(&cleaned),
                    fail_cleanup: true,
                },
                facts(0, 0),
                Tick::from_raw(0),
            )
            .expect("complete");
        let id = lease.connection_id();
        let error = lease
            .close(CloseReason::Failed, Tick::from_raw(0))
            .expect_err("cleanup must fail");
        assert!(matches!(error, PoolError::Cleanup { connection_id, .. } if connection_id == id));
        assert_eq!(
            pool.snapshot().expect("snapshot").state,
            PoolState::Poisoned
        );
        assert_eq!(
            pool.finalize_connection(id),
            Err(PoolError::CleanupAlreadyAttempted)
        );
        assert!(matches!(
            pool.acquire(partition, Tick::from_raw(0)),
            Err(PoolError::Poisoned)
        ));
    }

    #[test]
    fn shutdown_waits_for_active_lease_then_finalizes_quarantine() {
        let cleaned = Rc::new(Cell::new(0));
        let partition = key(1, 2, 3);
        let pool = ConnectionPool::new(config()).expect("pool");
        let lease = active(&pool, partition, &cleaned, 1);
        let start = pool.shutdown().expect("shutdown");
        assert_eq!(
            start,
            ShutdownStart {
                cancelled_waiters: 0,
                cancelled_connections: 0,
                quarantined: 0
            }
        );
        assert_eq!(pool.finalize_shutdown(), Err(PoolError::ShutdownPending));
        drop(lease);
        let report = pool.finalize_shutdown().expect("finalize");
        assert_eq!(report.finalized_connections, 1);
        assert_eq!(pool.snapshot().expect("snapshot").state, PoolState::Closed);
        assert_eq!(cleaned.get(), 1);
        assert_eq!(pool.finalize_shutdown(), Err(PoolError::Closed));
    }

    #[test]
    fn checked_identifier_overflow_does_not_wrap_or_succeed_twice() {
        let cleaned = Rc::new(Cell::new(0));
        let partition = key(1, 2, 3);
        let pool = ConnectionPool::new(config()).expect("pool");
        pool.set_next_ids_for_test(
            NonZeroU64::new(u64::MAX),
            NonZeroU64::new(1),
            NonZeroU64::new(1),
        );
        let permit = match pool.acquire(partition, Tick::from_raw(0)).expect("max id") {
            AcquireResult::Connect(permit) => permit,
            AcquireResult::Reused(_) | AcquireResult::Queued(_) => panic!("expected connect"),
        };
        permit
            .complete(connection(1, &cleaned), facts(0, 0), Tick::from_raw(0))
            .expect("complete");
        assert!(matches!(
            pool.acquire(partition, Tick::from_raw(0)),
            Err(PoolError::IdExhausted)
        ));
        let other: ConnectionPool<FakeConnection> = ConnectionPool::new(config()).expect("pool");
        other.set_next_ids_for_test(NonZeroU64::new(1), None, NonZeroU64::new(1));
        assert!(matches!(
            other.acquire(partition, Tick::from_raw(0)),
            Err(PoolError::GenerationExhausted)
        ));
    }

    #[test]
    fn close_reason_never_makes_unread_connection_reusable() {
        let cleaned = Rc::new(Cell::new(0));
        let partition = key(1, 2, 3);
        let pool = ConnectionPool::new(config()).expect("pool");
        let lease = active(&pool, partition, &cleaned, 1);
        assert_eq!(
            lease.close(CloseReason::Unread, Tick::from_raw(0)),
            Ok(ReleaseOutcome::Closed)
        );
        assert_eq!(cleaned.get(), 1);
        assert!(matches!(
            pool.acquire(partition, Tick::from_raw(0)),
            Ok(AcquireResult::Connect(_))
        ));
    }
}
