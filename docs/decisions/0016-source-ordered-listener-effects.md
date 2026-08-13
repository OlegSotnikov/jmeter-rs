# Decision 0016: source-ordered listener effects and immutable observations

Status: accepted architecture; implementation and oracle evidence pending
Date: 2026-08-13
Compatibility features: `ELEM-003`, `ELEM-004`, `ELEM-005`, `ELEM-008`,
`JTL-001`, `JTL-002`, `TEST-001`

## Context

Apache JMeter 5.6.3 classifies `ResultAction` as a `SampleListener`, not a
postprocessor. Its listener notifier invokes the compiled listener list
synchronously in order and gives every entry the same live `SampleResult`
reference. An earlier listener can therefore mutate result/control fields that
a later listener sees. A `ResultCollector` serializes the current state during
its callback, so these two source orders are observably different:

```text
ResultAction -> ResultCollector   # collector sees the action fields
ResultCollector -> ResultAction   # collector retains the pre-action row
```

The pinned notifier catches a listener `RuntimeException`, records it, and
continues with later listeners. Result-action fields are consumed only after
notification returns. A failing assertion precedes notification and can make
`ResultAction` fire. Null or ignored samples skip listeners.

The original Rust design treated listeners as immutable callbacks after one
final snapshot and classified `ResultAction` as a postprocessor. That cannot
reproduce source order, assertion-triggered action, or collector-before-action
behavior. Allowing arbitrary live mutation inside asynchronous sinks would,
however, destroy Rust ownership, rollback, and persistence guarantees.

## Decision

### One compiled ordered listener program

Scope compilation produces one bounded, source-ordered listener program for
each ordinary and transaction sample package. Every enabled entry has exact
plan-domain identity, source path, upstream class, instance identity, and
position. The closed entry kinds are:

```text
NativeEffect       # bounded typed mutation, for example ResultAction
SnapshotObserver   # ResultCollector/report/other immutable Rust sink
ExternalAuthority  # negotiated JVM/plugin listener authority
```

`ResultAction` is registered only as `NativeEffect`. It is never a
postprocessor. A listener-looking unknown class fails whole-plan admission or
uses an explicitly negotiated external authority; it is never ignored or
treated as a generic observer.

Listener programs retain instance identity in addition to source `NodeId`.
This is required for transaction-controller filtering: when the same listener
instance belongs to the transaction package, the child package does not also
notify that instance. Equal-looking clones or same-named nodes are not the
same instance.

### Live result, atomic effects, immutable observer revisions

After postprocessors and assertions, runtime retains one generation-tracked
live result/control record while it walks the listener program. A native effect
receives a read-only view of the current generation and returns a bounded
proposal:

```text
ListenerEffect {
  base_result_generation,
  result_patch,
  control_patch,
  bounded_diagnostics,
}
```

Runtime validates the complete proposal and commits it atomically. Later
entries see every earlier committed effect. A stale, malformed, or rejected
proposal mutates nothing. Native listener code never receives an unrestricted
mutable reference, filesystem/network capability, or sink handle.

At each `SnapshotObserver` position, runtime deep-snapshots the current result,
selected variables, thread/host identity, and transaction metadata. It admits
that immutable revision only to the observer/sink represented by that entry.
Asynchronous writer work may continue later, but it consumes the captured
revision; a later listener can neither change nor rewrite it. Source-position
snapshot and bounded router admission are ordered listener operations. Sink
processing latency is not a global sequential callback.

One sampler notification may therefore create zero, one, or several immutable
observer revisions. Each envelope binds:

- the root sample identity;
- listener-program identity and source position;
- observer/sink identity;
- live-result generation at capture;
- complete immutable payload and digest; and
- a unique run sequence/event identity.

Two revisions of one sample are not duplicates. Deduplication cannot collapse
them by sample ID, label, time, or payload equality. An observer encountered
before a later effect keeps its earlier revision permanently.

### ResultAction and control consumption

For an unsuccessful current result, native `ResultAction` applies the pinned
precedence:

```text
StopTestNow
> StopTest
> StopThread
> StartNextThreadLoop
> StartNextIterationOfCurrentLoop
> BreakCurrentLoop
```

It preserves separate stop-thread, stop-test, stop-test-now, next-thread-loop,
next-current-loop, and break-current-loop fields. Loop-local actions are not
collapsed into the severity-ordered run cancellation signal. A successful
sample creates no action effect.

Assertions run before the listener program, so an assertion-induced failure
is visible to `ResultAction`. Runtime consumes the final stop/logical fields
only after every listener entry has run and every observer revision has been
accounted for by router admission. The controller then applies and resets the
loop-local action at the exact active loop boundary. No-active-loop behavior
and nested-loop precedence remain pinned-oracle requirements.

The result collector filter is the pinned four-row expression:

```text
(!errorOnly && !successOnly)
|| (successful && successOnly)
|| (!successful && errorOnly)
```

Both flags set therefore select no sample. Filtering is evaluated against the
revision visible at that collector's exact position.

### Listener failures and external mutation

Pinned listener exceptions do not suppress later entries. A recoverable native
listener-domain failure records a bounded diagnostic, commits no invalid
proposal, and continues. A snapshot-observer admission or writer failure is
also retained while later safe listener entries run; the compatibility run
ultimately fails and publishes no success artifact because a selected result
was not durably accounted for. Cancellation, poisoned state, resource
invariant failure, or identity corruption may stop immediately because safe
continuation is no longer established.

Arbitrary JVM/plugin listeners execute only inside the negotiated authority
boundary. Its versioned reply distinguishes:

```text
Committed(final state, optional caught-exception diagnostic)
NoMutation(optional caught-exception diagnostic)
Uncertain(worker/process failure)
```

This permits a Java listener that mutates and then throws to expose its final
state to later listeners, as the pinned notifier does. `Uncertain` commits no
guessed Rust delta, poisons the authority/run, and fails closed. The bridge
must carry every result/control presence field, generation, listener identity,
diagnostic bound, and payload digest before this path is available.

### Null, ignored, transaction, and lifecycle behavior

- A null sampler result creates no listener program invocation or sink event.
- A result already ignored before result phases skips assertions/listeners as
  pinned; a postprocessor that sets ignore also prevents notification.
- Ordinary sampler order is postprocessors, assertions, listener program,
  router accounting, then control consumption.
- A transaction aggregate runs its aggregate assertions and its own listener
  program. It has no invented transaction-postprocessor phase.
- Child versus aggregate notification uses listener instance identity, not
  class/name equality.
- Transaction aggregate action consumption is oracle-gated until a pinned
  trace establishes the exact outer-controller behavior.

### Relationship to result routing and observation

Decision 0003 owns immutable revision routing, ledger conservation,
backpressure, durability, and output publication. This decision owns the
source-ordered point at which each revision is captured and targeted.
Decision 0010 diagnostic observation remains separate and cannot substitute
for any listener entry or sink acknowledgement.

Architecture's append-only rule applies once an observer revision is captured:
no listener can mutate an already-persisted or queued revision. It does not
prohibit typed effects on the generation-tracked live result before a later
observer position.

## Rejected alternatives

- Keeping `ResultAction` as a postprocessor is rejected because assertion
  failure and source listener order would be wrong.
- One final snapshot sent to every collector is rejected because collectors on
  opposite sides of an effect observe different states.
- Giving native listeners `&mut SampleResult` is rejected because partial
  mutation, panic, and capability effects would bypass atomic validation.
- Reordering all effects before all sinks is rejected because it changes valid
  JMX source order.
- Making asynchronous sink workers mutate live results is rejected because
  later scheduling would determine semantics.
- Treating a listener exception or sink loss as successful continuation is
  rejected; later notification may continue, but the run retains the failure.

## Verification requirements

Deterministic runtime/application tests cover:

- failed sampler with `ResultAction` and collector in both source orders;
- successful sampler followed by failing assertion and then `ResultAction`;
- every action value, precedence, reset, nested-loop, and no-loop case;
- one effect visible to the next, stale/malformed effect rollback, and later
  listener continuation;
- collector errors and native listener errors not suppressing later safe
  entries, while the run still fails and does not publish;
- null, initially ignored, and postprocessor-ignored samples;
- root, inner, sibling, setup, main, teardown, and insertion-sensitive scope;
- both-filter-flags truth table at different result revisions;
- multiple immutable revisions retaining their original contents;
- transaction child/aggregate instance suppression and aggregate assertions;
- bridge round trips for committed-with-exception, no mutation, uncertainty,
  every presence field, generation, identity, and bound; and
- result-ledger conservation with several observer revisions of one sample.

Pinned Apache JMeter 5.6.3 differential traces are required before profile
promotion. In particular, they must prove source order, exception continuation,
all action values, transaction behavior, scope order, and collector filtering.

## Consequences

Rust keeps immutable queued/persisted events and bounded asynchronous sinks,
while reproducing JMeter's mutable source-ordered listener observations. The
live mutation window is explicit, atomic, and ends before control consumption.
Event identity becomes an observer occurrence rather than an assumption that
one sampler always produces exactly one universally visible snapshot.
