# Decision 0015: result-sink operation liveness and wait ownership

Status: accepted architecture; implementation and oracle evidence pending
Date: 2026-08-13
Compatibility features: `ELEM-004`, `JTL-001`, `JTL-002`, `JTL-003`,
`JTL-004`, `JTL-005`, `TEST-001`, `TEST-005`

## Context

The standalone runtime drives executor-neutral futures on one application
thread. Decision 0011 requires every production future that can remain pending
without immediate semantic progress to own a finite wait registration. The
JTL writer is a run-owned worker: an adapter enqueues a command and its future
waits for a completion produced on that worker.

An integration trace exposed a concrete ownership gap. Native HTTP correctly
retired its `Http` wait after producing a sample, then result routing enqueued
the sample in the JTL writer. The JTL completion future stored a waker and
returned `Pending`, but owned no run wait registration. The executor therefore
reported `runtime.executor.stalled` before the writer's nondeterministic later
wake. Extending the executor grace or retaining the completed HTTP wait would
hide the missing owner and make provider liveness timing-dependent.

The first typed-router implementation also placed one arbitrary absolute
deadline on the complete run and tied mutable budget borrows to sink futures.
That would reject an otherwise healthy multi-day load test when the deadline
elapsed, and its borrow shape makes sequential asynchronous operations
difficult to express. A load-test duration and the maximum time allowed for
one blocked sink operation are different policies.

## Decision

### One run-owned budget authority, finite operation leases

The application supplies one `ResultDeliveryBudget` authority when it prepares
the run. The authority is shared by the runtime router and every result-sink
adapter, is never cloned into independent accounting state, and contains:

- the exact run cancellation source;
- a fallible monotonic clock in the same epoch as the production time driver;
- a checked, shared retry/attempt ledger;
- admitted nonzero operation windows and finalization policy; and
- an optional explicit whole-run deadline, only when the invocation or
  platform profile actually supplies one.

Creating the authority does not start a fixed implicit maximum run duration.
A representable schedule or soak run may continue for days or months. Before
one semantic sink operation can return `Pending`, the authority creates one
linear `ResultOperationLease` for that operation:

```text
Start(sink)
AdmissionBackpressure(event, sink-set)
Process(event, sink)
Flush(sink)
Finish(sink)
Recovery(transaction)
```

The lease binds the run, sink, operation kind, opaque nonzero operation
identity, attempt ledger, cancellation source, and one checked finite absolute
deadline. The deadline is established once from the admitted operation window
and current run monotonic reading, narrowed by an explicit whole-run or
finalization deadline when present. A poll, wake, queue transition, retry, or
phase change cannot refresh it. Retries reuse the lease and consume the shared
attempt ledger. Sequential events may receive distinct process leases; they do
not receive distinct retry budgets.

When finalization begins, the authority establishes one finite finalization
deadline. Draining already accepted events, all flushes, all finishes, owner
joins, and result-staging closure are capped by that same deadline. An event's
existing earlier deadline remains earlier. Immediate cancellation may narrow
the admitted finalization policy but never turn accepted work into success.
Sampling cancellation also cannot disable mandatory cleanup: finalization and
recovery leases remain usable after the execution-cancellation bit is raised,
while they still observe the fixed finalization deadline and a distinct
immediate cleanup-abort policy when one was explicitly admitted. A normal
process/admission lease continues to fail immediately on run cancellation.

The authority is shared through an `Arc`-owned run capability with checked
internal accounting. A sink future owns its operation lease rather than
borrowing one mutable budget across an `.await`. This keeps the API
executor-neutral, prevents lifetime aliasing, and makes it impossible for a
per-user clone to reset time or attempts. Runtime must not store an arbitrary
`budget_ticks` default in a router adapter.

### One fallible monotonic domain

Operation deadlines use the runtime `MonotonicInstant` domain supplied by the
run's production time driver. The operation clock returns a typed error; the
result path must not use a lossy clock read, wall time, `std::time::Instant`,
`unwrap_or(u64::MAX)`, saturating subtraction, or `now + remaining` deadline
reconstruction. Checked conversion failure, clock reversal, or unavailable
time fails the operation and run with a stable typed error.

An external worker receives only a finite remaining duration rounded down at
the protocol boundary. A process-local absolute instant never crosses a wire.

### Every pending sink operation owns its wait

The generic run wait registry remains the authoritative liveness inventory.
It is physically driven by the application time owner and is not embedded in
the pure delivery ledger. The application exposes a narrow provider-wait
registration capability that accepts an already-established absolute
deadline, `WaitOwnerClass::Provider`, and a bounded opaque numeric identity.
`WaitOwnerClass::Queue` is reserved for a separately modeled queue-capacity
wait. No event label, path, hostname, payload, certificate, or secret enters a
wait identity.

An effectful sink future follows this poll protocol:

1. inspect its completion and return immediately if ready;
2. check cancellation and the operation lease's absolute deadline;
3. register the executor waker with cancellation;
4. create or update its exact RAII provider-wait registration before it can
   return `Pending`;
5. recheck completion, cancellation, and deadline to close the
   completion-versus-registration race; and
6. return `Pending` only while the exact registration is live.

Completion, error, timeout, cancellation, and explicit owner finalization
retire the registration before returning. Dropping the future retires the
exact registration as a safety net. The writer completion wakes its stored
waker; the time driver wakes at the lease deadline; cancellation wakes through
the budget authority. `poll` performs no file I/O, blocking wait, or join.

A self-wake, unrelated provider registration, completed HTTP wait, arbitrary
executor grace, or fake timer is not a substitute. A production future that
cannot provide this ownership is unavailable in the standalone path.

### Typed JTL adapter and durability

The application owns `JtlSinkOwner`, including the private staging-file
handle, encoder worker, exact join handle, and finalization gate. A cloneable
`TypedJtlSinkAdapter` contains only the submission handle. The consuming
runtime passes the application-owned provider-wait registrar to each sink
operation. The one run-owned budget authority allocates the checked opaque
operation identity, and the adapter uses the identity carried by the exact
`ResultOperationLease` for its provider-wait registration; it must not create
a second identity domain. Runtime stores the adapter behind the typed sink
contract; neither runtime nor the adapter reopens a path or reconstructs an
event.

The pure typed router owns transactional all-sink reservation, queue limits,
delivery order, identity, and ledger transitions. The JTL worker's bounded
handoff reservation is subordinate to that admission and cannot independently
drop or account for an event.

The sink lifecycle is:

```text
start readiness handshake before sampling
-> process the original DeliveryLease envelope
-> FIFO flush
-> encoder finish/format close
-> application joins the exact worker
-> application syncs and publishes private staging
```

For the current encoder, a successful per-event completion truthfully earns
`DurabilityBoundary::FormatWritten`: the complete record was accepted by the
format writer. It does not earn `Flushed` or `Synced`. Final flush/format close,
descriptor synchronization, parent-directory durability, identity
revalidation, and atomic publication remain application-owned finalization
facts.

An I/O or encoder failure after command execution has begun is an unknown
outcome and is not retried unless that sink later proves an idempotent
acknowledgement. A failure proven before execution may use a typed permanent or
retryable outcome under the shared lease and attempt ledger. Budget,
cancellation, unknown-outcome, persistence, and configuration errors remain
distinct; they are not flattened into `InvalidConfiguration`.

Adapter `finish` and every exact owner cleanup run before the pure router can
enter its successful `Finished` state. One adapter failure does not suppress
bounded finish attempts for other started adapters. Finalization preserves the
primary error and every bounded secondary cleanup error, and publication is
possible only if the ledger conserves every selected/accepted event and all
required durability stages succeed.

### Application integration

The consuming run transaction constructs the typed sink plan, qualified
identities, budget authority, wait registrar, and JTL adapter after complete
whole-plan admission and private output preparation. It installs that exact
typed router in `RuntimeEngine`; production code does not select the legacy
numeric router.

Success ordering is:

```text
engine execution
-> stop typed admission and drain under the finalization deadline
-> flush/finish typed sinks
-> join JTL and other exact owners
-> close and sync staging
-> publish result
-> generate/publish an optional report from the exact finalized handle
```

Every failure cancels the run future, retires waits, finalizes owners in the
declared reverse order, preserves private staging as non-success, and retains
typed cleanup diagnostics. A cleanup failure prevents publication. The
current-thread executor is unchanged except for regression coverage.

## Rejected alternatives

- One implicit absolute deadline created at run start is rejected because it
  imposes an unrelated maximum test duration.
- A new timeout for every poll, retry, or queue transition is rejected because
  perpetual activity could prevent expiry.
- A mutable budget borrow held across every sink future is rejected because it
  couples unrelated operations and creates avoidable lifetime aliasing.
- Registering the completed HTTP operation on behalf of JTL is rejected
  because wait ownership would be false.
- Blocking on a condition variable in the runtime thread is rejected because
  it prevents cancellation and all other progress.
- Relaxing `runtime.executor.stalled` is rejected because it converts a
  deterministic ownership defect into a timing race.

## Verification requirements

Deterministic tests use gated workers, channels/barriers, and manual clocks;
they never rely on arbitrary sleeps. Required coverage includes:

- HTTP wait retirement followed by a pending JTL completion with one live
  `Provider` registration and successful cross-thread wake;
- completion-before-registration and completion-after-registration races;
- deadline, cancellation, future drop, worker failure, and time-driver
  shutdown leaving zero live registrations;
- checked operation-ID, clock, deadline, and attempt exhaustion;
- retry preserving one lease deadline and one idempotency key;
- a progressing run longer than the per-operation window without a false
  run-duration failure;
- one finalization deadline shared by drain, flush, finish, and owner join;
- truthful `FormatWritten` acknowledgement and rejection of false
  `Flushed`/`Synced` claims;
- primary plus cleanup errors, no publication on cleanup failure, and prior
  output preservation; and
- typed-router identity, original-envelope, ordering, ledger-conservation,
  and exact-worker-reap integration tests.

Passing these tests proves the Rust ownership/liveness contract only. Pinned
Apache JMeter 5.6.3 differential evidence remains required for `ELEM-004` and
`JTL-001..005`, and cross-platform/performance/soak evidence remains required
for `TEST-005`.

Acceptance after implementation includes:

```text
cargo fmt --all -- --check
cargo test --locked -p jmeter-rs-results --all-targets
cargo test --locked -p jmeter-rs-runtime --all-targets
cargo test --locked -p jmeter-rs-report --all-targets
cargo test --locked -p jmeter-rs --all-targets
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo run --locked -p xtask -- profile-check
cargo run --locked -p xtask -- fixture-check
```

## Consequences

Sink latency becomes explicit, finite, and observable without limiting the
duration of healthy load generation. The current-thread executor retains a
strict liveness invariant, the runtime ledger stays pure, and the application
owns worker waits and filesystem durability at the correct boundary. The
typed lease API also removes the lifetime pressure caused by one mutable
budget borrow spanning unrelated asynchronous operations.
