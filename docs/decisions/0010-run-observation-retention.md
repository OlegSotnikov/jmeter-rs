# Decision 0010: bounded run observation and constant-memory summaries

Status: accepted architecture; implementation and oracle evidence pending
Date: 2026-08-13
Compatibility features: `ELEM-003`, `ELEM-004`, `JTL-001`, `JTL-002`,
`JTL-003`, `JTL-004`, `JTL-005`, `TEST-001`, `TEST-005`

## Context

Result routing and diagnostic observation are different responsibilities. A
run-owned result router delivers every selected `SampleEvent` to JTL and other
compatibility sinks under Decision 0003. The runtime also exposes lifecycle
events for tests and diagnostics. Retaining those events is not required to
make a result durable and must not become an unbounded second result store.

The initial runtime retained every `EngineEvent` in a count-bounded vector.
Sample events cloned complete `SampleResult` payloads, the vector had no byte
budget, and run completion cloned the complete vector again. A normal long
load test could therefore consume memory proportional to its sample count and
eventually fail at an arbitrary event ceiling even when its streaming JTL sink
was healthy.

The standalone product needs constant-memory production summaries, while
deterministic runtime tests still need ordered full traces. Silent diagnostic
truncation is not acceptable evidence, and an observation policy must never
change result-router admission, ordering, durability, or failure behavior.

## Decision

Runtime owns a versioned, executor-neutral observation policy. Version 1 has
two modes:

```text
RunObservationPolicyV1::Summary
RunObservationPolicyV1::FullTrace {
    max_events: NonZeroUsize,
    max_bytes: NonZeroUsize,
}
```

`Summary` is the production and constructor default. It retains no ordered
`EngineEvent` payloads and no `SampleResult` clones. It maintains only checked,
fixed-size counters and terminal state. `FullTrace` is an explicit test/debug
capability. It retains ordered events within both declared count and
conservative retained-byte limits; reaching either limit fails the run with a
typed stable observation resource error. It never truncates, evicts, or
silently changes to summary mode.

A future diagnostic ring is a separately versioned, explicitly
non-compatibility policy. If introduced, it must expose sequence gaps and exact
dropped event/byte counts and may not support JTL or conformance evidence. It
is not part of version 1.

### Summary contract

`RunObservationSummaryV1` records checked counters for:

- total observation events and sample events;
- materialized, null-result, successful, failed, and unknown-success sample
  results;
- explicit `SampleFailure` occurrences independently of result success;
- iteration and lifecycle event kinds, including users started and finished;
- transaction-origin samples when that origin is available at emission;
- the highest `ControlSignal`; and
- a terminal state distinguishing not started, running, completed, failed,
  and cancelled/dropped.

The standalone application's existing outcome meanings remain stable:
`samples` counts sample events with a materialized result, and
`sample_failures` counts those whose `SampleResult.success` is exactly false.
An explicit `SampleFailure` without such a result remains a separate diagnostic
counter. Changing these meanings requires pinned JMeter evidence.

Every counter uses checked arithmetic. Overflow is a typed run failure, never
saturation or wrapping. Diagnostics contain stable codes and bounded redacted
details. Summary updates and optional trace admission are one atomic
observation commit: a rejected trace event cannot leave partially updated
observation state.

### Lifecycle and ownership

Observation state is run-owned and reset before each `RuntimeEngine::run`.
Repeated runs never inherit prior counters, terminal state, or trace events.
Scheduler clones share the current run's exact observation owner; they do not
clone counters or traces.

Dropping the run future records cancellation before child futures are unwound.
A normal completion records its final control signal. Runtime or observation
failure records failed terminal state. The post-run summary remains available
through a read-only snapshot even when `run` returns an error.

In full-trace mode, completion freezes the bounded trace into one shared
immutable allocation used by both the engine snapshot and `EngineReport`.
Completion must not deep-clone all events or `SampleResult` payloads. Starting
a subsequent run releases that prior run's engine-owned reference; an already
returned report may continue to own its immutable reference.

Observation accepts borrowed event facts and materializes an owned
`EngineEvent` only in full-trace mode. In particular, summary mode must not
clone a sample merely to discard it. Retained-byte accounting is conservative,
checked, includes nested sample/result data and owned strings/collections, and
is tested at exact boundaries. An unaccounted event variant fails closed until
its estimator is defined.

### Result routing remains authoritative

Decisions 0003 and 0016 are authoritative. The engine routes one immutable
result revision exactly once for each compiled snapshot-observer occurrence;
several observers around a mutable listener effect may capture distinct
revisions of one root sample. Summary and full-trace diagnostic observation
run beside that path and cannot:

- drop, duplicate, reorder, reconstruct, or acknowledge a result event;
- make a routed sample durable;
- hide a sink-full, sink-failure, cancellation, or finalization error; or
- substitute trace events for JTL or listener output.

If observation fails after a result has entered a private sink, the run fails
and normal sink cancellation/finalization plus staging-publication rules apply.
No partial output becomes a successful publication.

### Application policy

The Java-free `jmeter-rs` CLI explicitly selects `Summary`. It derives
`RunOutcome.samples` and `RunOutcome.sample_failures` from the returned summary
instead of scanning retained events. Runtime tests that assert event order
select a finite `FullTrace` policy explicitly. Test helpers must choose limits
large enough for the stated case but may not use an unlimited sentinel.

Streaming JTL input for report-only and report-at-end is a separate application
edge. It must use a bounded prefix and incremental decoder rather than a
whole-file configuration read; raising the configuration-file limit does not
solve observation retention and is not authorized by this decision.

## Rejected alternatives

- Keeping one million events is rejected because a count does not bound bytes
  and valid long runs still fail.
- Raising or removing the count limit is rejected because it worsens memory
  safety without changing the ownership error.
- Treating the JTL queue as the trace is rejected because sink durability and
  diagnostic inspection have different lifecycles and failure semantics.
- Silent oldest/newest-event eviction is rejected for version 1 because it can
  conceal gaps and produce false compatibility evidence.
- Deep-cloning a bounded full trace at completion is rejected because one
  shared immutable trace provides the same ownership without a second payload.

## Compatibility and evidence

This decision changes resource behavior and internal observation APIs; it does
not claim JMeter conformance. The active compatibility profile remains
unchanged until exact oracle fixtures and required platform evidence pass.

Required deterministic evidence includes:

- a summary-only run exceeding the former event-count ceiling with exact
  counters and no retained trace;
- exact full-trace count and retained-byte boundary failures;
- successful, failed, unknown-success, null-result, explicit-failure, ignored,
  and transaction-result counter cases;
- repeated runs with independent summaries;
- concurrent groups with schedule-independent aggregate counters;
- engine error, sink-full, sink failure, and dropped-future terminal states;
- proof that summary mode does not clone or retain sample payloads; and
- a Java-free run whose JTL exceeds the old whole-file report input limit and
  is processed incrementally.
