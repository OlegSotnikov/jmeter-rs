# Decision 0011: production time, progress, and bounded wait driving

Status: accepted architecture; implementation and oracle evidence pending
Date: 2026-08-13
Compatibility features: `ELEM-001`, `ELEM-003`, `ELEM-007`, `TEST-001`,
`TEST-005`

## Context

The runtime is executor-neutral and expresses delays, scheduler deadlines, and
provider operations as futures. Its deterministic defaults intentionally use
an epoch clock and immediately-ready sleeper. Those defaults are suitable for
pure unit tests but are not a production implementation of JMeter timing.

The initial standalone adapter polled the engine on the calling thread and
derived one idle timeout from static plan fields. It also imposed cumulative
poll/wake limits and an arbitrary seven-day maximum. This has four problems:

- a valid long schedule can be rejected solely because its duration is large;
- dynamic timer, synchronization, throughput, DNS, TLS, queue, and provider
  waits cannot all be reconstructed from static plan fields;
- a long but progressing run can exhaust cumulative poll or wake counters; and
- accepting a large idle timeout makes a genuinely broken, non-waking future
  difficult to diagnose promptly.

The application needs real monotonic time and bounded waits without adding an
async runtime to pure crates or creating one OS thread per virtual user, timer,
or request.

## Decision

The Java-free application owns one run-scoped production time driver. It
provides one coherent monotonic clock, wall/monotonic readings, sleeper, and
scheduler implementation to `RuntimeCapabilities`. It may use one exactly
owned timer thread, platform timer facility, or an application event loop, but
it may not spawn one thread per registration or rely on ambient async runtime
state. Its queue, retained registrations, diagnostic bytes, and wake work are
bounded. Owner finalization cancels outstanding registrations, wakes their
exact futures, joins the exact driver worker, and reports typed failure.

Deterministic tests use the existing manually advanced clock/scheduler or an
equivalent injected driver. Correctness tests never wait for arbitrary wall
time.

### One time domain

All production runtime deadlines use the same injected monotonic epoch. Wall
time is read only for observable timestamps. Delay, ramp, timer, scheduler,
HTTP queue/overall operation, DNS, TLS, cancellation, and executor-driver
calculations never compare `std::time::Instant`, wall timestamps, and runtime
`Duration` epochs without an explicit application-edge conversion captured at
run start.

`GroupSchedule` owns a checked startup-bound operation. It constructs the same
`RampSchedule` used for execution and computes the maximum actual user offset,
not a second approximation. Delay plus offset, group start plus offset, and
duration end use checked arithmetic. Overflow is a stable invalid-schedule
error; saturation is forbidden. A representable eight-day or multi-month wait
is valid and is not rejected by a product-defined duration ceiling.

### Progress and waits are explicit

One run-owned driver state exposes two independent facts to the application
executor:

```text
ProgressSnapshot {
    generation: NonZeroU64,
    terminal: running | completed | failed | cancelled,
}

WaitSnapshot {
    registrations: usize,
    earliest_deadline: Option<MonotonicInstant>,
    generation: NonZeroU64,
}
```

The progress generation advances with checked arithmetic on semantic engine
progress: lifecycle transitions, user/iteration completion, sample/result
completion, monotonic control-signal escalation, and terminal-state changes.
Waker notifications alone are not progress. Progress state is reset for each
`RuntimeEngine::run`, shared by scheduler clones, and exposed through a
read-only handle that does not retain the engine future or result payloads.

Every production future that can remain pending without immediate semantic
progress owns an RAII wait registration before returning `Pending`. A
registration contains a typed owner class, opaque bounded identity, and finite
absolute monotonic deadline. It contains no request body, secret, hostname,
certificate, or user data. Dropping or completing the future removes the exact
registration; cancellation wakes and retires it. Registration IDs use checked
nonzero allocation and are never reused within a run.

Runtime sleeper and scheduler adapters register timer deadlines. Dynamic
timers and barriers register their actual computed deadline. The native HTTP
sampler registers the already-established absolute queue/overall operation
deadline; DNS and TLS do not extend it. Provider APIs that cannot declare a
finite wake or deadline are unavailable in the standalone compatibility path.

Run-owned result workers follow
[`Decision 0015`](0015-result-sink-operation-liveness.md). A JTL or other
cross-thread completion future registers the already-established finite result
operation deadline as `WaitOwnerClass::Provider`; a separately modeled
queue-capacity wait uses `Queue`. It cannot retain a completed HTTP wait, mint
a polling grace, or return `Pending` while the registry is empty. Result
operation leases share cancellation and retry accounting across the run but do
not create an implicit maximum test duration.

The registry has finite item and aggregate diagnostic bounds. Capacity,
unknown removal, double retirement, deadline reversal, and ID exhaustion are
typed invariant/resource errors and cancel the run. An error path cannot leave
a live unowned timer or socket operation.

### Current-thread executor

The standalone current-thread executor closes the wake-before-wait race using
a generation counter and the thread's unpark token. The counter uses checked
nonzero arithmetic; overflow is a typed executor error rather than wrapping.

Poll and wake-storm budgets are consecutive no-progress budgets, not lifetime
run ceilings. After each poll, the executor compares the run progress and wait
generations:

- semantic progress resets both budgets;
- a legitimate wait-registration change resets the poll budget but not the
  semantic-progress accounting;
- repeated self-wakes with neither progress nor wait change consume the
  bounded wake-storm budget; and
- a future returning `Pending` with no registered wait gets one bounded
  register/wake race window, then fails as `runtime.executor.stalled`.

When waits exist, the executor parks until an exact waker notification or the
earliest registered deadline plus a small fixed driver-delivery grace. At the
deadline it repolls once so the owning future can observe timeout. If neither
the future nor driver retires/advances the expired wait, the executor reports a
typed stalled-provider error and requests immediate engine cancellation before
dropping the run future. The grace bounds driver delivery latency; it is not a
maximum permitted test duration.

A later registered earlier deadline must wake the executor so it recomputes
the park interval. Spurious unparks are absorbed unless a wake, progress, or
wait generation changed. Mutexes are never held while polling a future,
unparking, invoking a cancellation callback, or joining a worker.

The runtime's concurrent join may visit each bounded task once per parent
poll. It must not impose a cumulative poll ceiling on a progressing run. Its
no-progress protection uses the same run progress/wait state, while task-count
and per-turn work remain separately bounded.

### Provider deadlines

The executor does not recompute provider timeouts from raw JMX fields. Each
provider publishes the effective absolute deadline selected during admission,
after applying its own defaults and caps. The native HTTP absolute deadline is
created before queue submission and is preserved through connect, DNS, TLS,
write, read, and cleanup. Queue delay never refreshes it.

Cancellation severity remains monotonic. Executor watchdog failure first
raises `StopTestImmediate`, then drops the polled future, then application
owners cancel and exactly join JTL, HTTP, DNS, TLS/timer, and other run-owned
workers under their existing lifecycle contracts. A watchdog must not publish
private result staging as success.

## Rejected alternatives

- A large global idle timeout is rejected because it cannot represent dynamic
  waits and turns duration policy into a compatibility restriction.
- Unlimited parking is rejected because a broken capability can orphan a run.
- Lifetime poll/wake counters are rejected because work volume is not lack of
  progress.
- One sleeper thread per virtual user or timer is rejected because concurrency
  then scales OS resources with workload size.
- Tokio or another executor in `runtime` is rejected because it reverses the
  pure-core dependency boundary.
- Reconstructing effective HTTP deadlines from source fields is rejected
  because provider defaults/caps are authoritative after admission.
- Saturating schedule arithmetic is rejected because it silently changes
  observable start and stop time.

## Compatibility and evidence

This decision defines production execution behavior but does not promote any
profile row. Required deterministic evidence includes:

- exact checked delay/ramp offsets and overflow boundaries;
- representable schedules longer than seven days without wall-clock sleeping;
- manual-clock dynamic timer, throughput, synchronization, and group-duration
  waits;
- a bounded production-driver test proving one driver owner and many
  registrations without per-wait threads;
- earlier-deadline registration, synchronous wake, cross-thread wake, spurious
  unpark, cancellation, and exact owner-finalization races;
- many polls and wakes with semantic progress, contrasted with bounded
  no-progress self-wake and missing-registration failures;
- one absolute native HTTP deadline across queue and all transport phases; and
- failure-path proof that private JTL output is not published and every exact
  worker owner is finalized.
