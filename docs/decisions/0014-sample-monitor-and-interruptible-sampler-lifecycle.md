# Decision 0014: sample monitors and interruptible sampler lifecycle

Status: accepted architecture; implementation and oracle evidence pending
Date: 2026-08-13
Compatibility features: `ELEM-001`, `ELEM-008`, `TEST-001`
Related features: `ELEM-003`, `ELEM-007`, `TEST-005`

## Context

JMeter 5.6.3's `SampleTimeout` is not a preprocessor or an ordinary timer. The
pinned `JMeterThread` discovers `SampleMonitor` elements from the test tree and
invokes every monitor immediately around the sampler call. Preprocessors and
the accumulated timer delay have already run when `sampleStarting` is called;
`sampleEnded` is called from the sampler's `finally` path before
postprocessors, assertions, and listeners.

The pinned `SampleTimeout` refetches `InterruptTimer.timeout` for every sample,
does nothing for a non-positive value or a sampler that is not
`Interruptible`, schedules one interrupt attempt, and cancels the exact pending
task when the sample or thread ends. Its callback asks the sampler to interrupt
the current operation. It does not itself convert the timeout into a stop-test
signal or prescribe the sampler's eventual `SampleResult`.

The relevant pinned sources are:

- [`JMeterThread`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/core/src/main/java/org/apache/jmeter/threads/JMeterThread.java)
- [`SampleMonitor`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/core/src/main/java/org/apache/jmeter/samplers/SampleMonitor.java)
- [`Interruptible`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/core/src/main/java/org/apache/jmeter/samplers/Interruptible.java)
- [`SampleTimeout`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/components/src/main/java/org/apache/jmeter/modifiers/SampleTimeout.java)

Treating `SampleTimeout` as a scoped preprocessor would start its deadline too
early, make its placement semantics wrong, and allow later timer delay to
consume the sampling window. Reusing the run's severity-ordered cancellation
token would incorrectly turn a sample-local interrupt attempt into
`StopThread` or `StopTest`.

## Decision

### A separate monitor category

Runtime adds a distinct `SampleMonitor` component category and registry/factory
contract. It is neither a preprocessor nor a timer. Plan compilation produces
one ordered enabled monitor collection for each virtual user from the complete
plan scan. Monitor instances are per-user mutable state; registrations are
never shared between users. Source `NodeId`, source path, class identity, and
collection order remain explicit.

The execution protocol becomes:

```text
configuration -> preprocessors -> summed timers
              -> monitor start hooks -> sampler -> monitor end hooks
              -> postprocessors -> assertions -> immutable listener event
```

The sampler and all successfully started monitors form one finally-protected
region. End hooks run for sampler success, sampler error, cancellation, panic
containment, and future drop. End hooks finish before any result-dependent
phase. A null result still skips postprocessors, assertions, and listeners.
Cleanup preserves the primary failure and reports bounded secondary cleanup
categories; it never fabricates a successful sample.

The pinned implementation invokes monitor start and end collections in their
discovered forward order. That order is retained for the native baseline.
Disabled-tree behavior, unusual plugin monitors, and an exception from one
monitor remain oracle-gated; a native failure always performs bounded cleanup
of registrations it already owns.

### A sample-local interrupt capability

Runtime owns an executor-neutral `SamplerInterrupt` domain capability. A
sampler explicitly exposes either one per-user handle or `Unsupported`; the
pipeline never infers interruptibility from a class name. An interrupt request
contains the exact sampler `NodeId`, user identity, and checked invocation
generation, plus a closed reason such as `SampleTimeout` or
`StopTestImmediate`. Stale, inactive, repeated, unsupported, and accepted
requests are distinct typed outcomes.

The handle may affect only the exact active invocation established by that
sampler instance. It cannot discover a sampler by name, retain an unbounded
operation registry, signal a process, or mutate run control. The sampler owns
the mapping from an accepted interrupt to its transport/operation cancellation
and eventual result. Native HTTP cancels the exact in-flight operation and
wakes its future; bridge-backed samplers carry the reason and invocation
identity over the negotiated bounded protocol.

Immediate test stop may both raise the severity-ordered run control signal and
request interruption of the active sampler. `SampleTimeout` requests only the
sample-local interrupt. These remain separate axes even if a concrete sampler
uses the same low-level operation cancellation primitive.

### Timeout monitor lifecycle

The compiled timeout monitor retains the exact timeout expression and evaluates
it for every invocation after preprocessors and timer delay, against that
user's current variables and properties. JMeter 5.6.3 long-conversion behavior
is an oracle requirement; malformed or unsupported expression behavior must
not be guessed or silently defaulted.

For a positive checked millisecond value and an interruptible sampler, the
monitor reads the run-owned monotonic clock once and registers one finite
absolute wake with the Decision 0011 scheduler. The callback validates the
same sampler and invocation generation, performs at most one interrupt
request, and wakes the sampler future. Queue admission, registration count,
duration arithmetic, callbacks, diagnostics, and cleanup are bounded. No
private executor thread, arbitrary wall-clock sleep, deadline refresh, or
ambient global scheduler is allowed.

Non-positive timeouts and explicitly non-interruptible samplers create no
registration and remain observable in deterministic trace tests. Sample end,
thread end, cancellation, construction failure, and owner finalization retire
the exact registration. Retirement is idempotent but accounting is checked;
drop is only a panic-contained safety net and cannot hide an explicit cleanup
failure.

Multiple timeout monitors retain source order and independent exact
registrations, matching the upstream possibility that more than one monitor
can request interruption of the same sample. Scheduler capacity is admitted
before execution from the maximum enabled user/monitor concurrency; saturation
is a typed run failure, never a dropped timeout.

## Compatibility and evidence

This decision corrects the component boundary but does not verify `ELEM-008`
or any sampler. Native evidence must include:

- trace tests proving monitor start occurs after preprocessors and timer delay,
  and monitor end occurs before postprocessors on every exit path;
- per-sample expression reevaluation, zero/negative, malformed, overflow, and
  non-interruptible cases;
- multiple monitors, users, iterations, disabled nodes, and exact source order;
- timeout-versus-completion and timeout-versus-stop races with a manual clock;
- stale/repeated invocation rejection, prompt operation wakeup, and exact
  registration retirement without arbitrary sleeps;
- Native HTTP loopback tests for an accepted interrupt and bounded cleanup;
- negotiated bridge round trips before any JVM sampler is described as
  interruptible through this seam; and
- pinned JMeter 5.6.3 differential traces for timeout parsing, ordering,
  races, and the sampler-visible result.

Ordinary unit tests can prove the Rust lifecycle and safety invariants but do
not promote a profile row. Unknown/plugin monitor classes remain preserved and
fail whole-plan admission unless their explicit compatibility-pack capability
is negotiated.

## Rejected alternatives

- Keeping `SampleTimeout` as a preprocessor is rejected because its deadline
  would include the wrong phases and its plan scope would be false.
- Converting timeout expiry directly to a failed sample is rejected because
  upstream only asks the sampler to interrupt and the sampler owns the result.
- Reusing the run cancellation token is rejected because timeout is not a
  stop-thread or stop-test severity.
- Giving every sampler a default successful interrupt is rejected because
  non-interruptible behavior is observable.
- A global background thread or timer per timeout is rejected because it
  bypasses run ownership, finite scheduler admission, deterministic time, and
  exact finalization.

## Consequences

Runtime gains one explicit lifecycle seam and one sample-local interrupt
capability. `SampleTimeout` can then be implemented without distorting normal
processor ordering, and the same interrupt handle can support correctly
identified immediate-stop requests. Samplers that cannot prove a bounded
interrupt path remain explicitly non-interruptible rather than approximating
success.
