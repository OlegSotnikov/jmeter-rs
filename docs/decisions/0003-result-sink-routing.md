# Decision 0003: run-level result sinks and output routing

Status: accepted architecture, revision 5; implementation and oracle evidence pending
Date: 2026-08-13  
Compatibility features: `ELEM-004`, `REPORT-001`, `REPORT-002`, `JTL-001`,
`JTL-002`, `JTL-003`, `JTL-004`, `JTL-005`

## Context

JMeter `ResultCollector` elements are listeners with run-lifetime state. They
can write JTL, maintain Aggregate/Summary/Graph state, filter successful or
failed samples, and consume synthetic transaction-controller samples. They
are not ordinary per-virtual-user components. A collector may be a sibling of
a thread group, multiple collectors may refer to one output path, and the CLI
`-l`, `-e`, and `-g` modes interact with the same result formats.

The source JMX contains exact upstream names and a nested
`SampleSaveConfiguration` object. The results crate already owns the JTL data
model and codecs, while the report crate owns listener and dashboard
algorithms. Filesystem resolution and CLI modes are effectful application
concerns. Combining these responsibilities in a per-user listener clone would
duplicate writers, lose run ordering, and make cancellation or finalization
implicit.

## Decision

Result persistence and reporting use a run-owned, executor-neutral routing
layer. A result collector is compiled into typed immutable configuration, but
its mutable sink state exists once per run unless pinned JMeter evidence proves
a narrower scope for a particular listener.

Responsibility remains divided as follows:

| Concern | Owner |
| --- | --- |
| Ordered JMX properties, unknown fields, and raw `saveConfig` payload | `model` and `jmx` |
| Executable `ResultCollectorConfig`, run sink plan, event envelope, ordering, and lifecycle | `runtime` |
| `SampleSaveConfiguration`, JTL CSV/XML codecs, and wire limits | `results` |
| Aggregate, Summary, Graph, dashboard algorithms, and report sink adapters | `report` |
| Property/date/base-path resolution, output creation, CLI `-l`/`-e`/`-g`, and executor adapters | `apps/jmeter-rs` |

`runtime` does not depend on `report`, the filesystem, Tokio, or a concrete
JTL writer. `report` may implement runtime sink contracts and depend on
`runtime` and `results`, following the existing dependency direction. No new
crate is introduced by this decision.

### Compilation and preservation

The compiler recognizes an exact `ResultCollector` test class and retains its
node identity, source path, GUI class, name, enabled state, raw filename,
filter flags, listener timestamp policy, and complete save-configuration
payload. Known GUI classes are classified explicitly:

- `SimpleDataWriter` is a JTL/file sink;
- `StatVisualizer`, `SummaryReport`, and `GraphVisualizer` are their distinct
  listener/report sinks;
- an enabled unknown or unsupported visualizer returns a stable capability
  error rather than becoming a generic writer or disappearing.

Unknown properties and object children remain in the lossless source model.
The executable decoder accepts only profile-proven aliases and values. Save
configuration is a per-field provenance program, not one merged options blob:

```text
SaveFieldResolution {
  field, ordered source operations, final presence, final Java value,
  selected wire representation, provenance
}
```

Operations retain apply, replace, remove, absent, and present-empty in source
order. Plan-local `saveConfig`, `jmeter.save.saveservice.*`, CLI mode, report
input metadata, and format-specific header/root observations remain distinct
sources. Precedence is applied only where the pinned profile defines it.
Missing configuration is resolved from the explicit run property view; it
never silently becomes a Rust default or infers settings from the first data
row. A reader without enough metadata returns `save-config.ambiguous` and the
candidate interpretations, rather than choosing a convenient format. Malformed
values, wrong object classes, and enabled unsupported fields fail with typed,
redacted configuration errors.

Every enabled collector is discovered by the ordered scope compiler, including
collectors below a Test Plan, thread group, controller, sampler scope, setup
group, or teardown group. Placement compiles to an immutable source-scope
predicate over envelope `NodeId`/plan ancestry. Mutable listener state is one
run-owned instance for that collector identity; placement does not clone a
writer or aggregate per virtual user. Root-level collectors use the root
predicate. The exact upstream inclusion rules for each non-root placement are
oracle-gated, and an unproven placement returns a typed unsupported-scope error
rather than being promoted to root scope or silently skipped.

An enabled listener-looking node that the registry cannot classify is an
explicit compile error with its raw class, GUI class, `NodeId`, and path.
Generic controller recursion is not permission to ignore an unknown listener.
Disabled collectors are preserved and do not start a sink.

### Event contract and ordering

Under [`Decision 0016`](0016-source-ordered-listener-effects.md), the engine
emits one immutable envelope at each compiled snapshot-observer position in
the source-ordered listener program. A single sampler may therefore produce
several immutable revisions targeted at different collectors; an earlier
revision cannot be rewritten by a later listener effect. Each envelope
contains:

- a monotonic run sequence assigned exactly once to that observer revision;
- the complete result/event snapshot;
- source `NodeId` and ordered plan path;
- run, group, virtual-user, thread, and sample identities;
- listener-program identity, observer identity/source position, and captured
  live-result generation; and
- explicit origin metadata distinguishing a sampler from a transaction
  controller, including controller identity and parentage where applicable.

Every identity is domain qualified. A source reference is
`PlanNodeRef { plan_domain, node_id }`; a numeric `NodeId` is never compared
across a controller plan, imported module, remote worker plan, regenerated
plan, or another run. The envelope also carries nonzero typed `RunId`,
`RunGeneration`, `WorkerId`, `WorkerGeneration`, `EventId`, and
`SinkPlanGeneration`. Zero, an empty string, or a fabricated
`SampleIdentity(0)` is not a sentinel for missing metadata. Absence is an
explicit enum variant and is rejected where the sink contract requires an
identity.

Identity constructors reject zero, empty, over-limit, and non-canonical
encodings. In memory, run/worker/generation/node/sequence identities are typed
fixed-width integers or fixed opaque bytes; wire/storage encodings are
canonical big-endian bytes with explicit schema-version, type, and domain tags.
`PlanDomain` is the SHA-256 of the canonical immutable executable-plan identity,
import/module domain, active profile identity, and selected capability-set
identity, not a user label. `EventId` binds run/generation/worker/sequence and
the SHA-256 of the complete immutable `SampleEvent` canonical projection,
including every presence bit, result/subresult/assertion field, selected
variable, source identity, and event metadata; no selected-field subset is
legal. `SinkId` binds run, sink-plan generation, and collector node. Equality
requires the complete typed value. Same-number values in different types or
domains never compare equal, and a repeated identity with different bound data
is `result.identity.collision`.

Sinks consume this original envelope. The application must not reconstruct a
second event from partial engine output, and report code must not infer a
transaction controller from a label. Nested sub-results remain part of their
root event and are serialized according to the effective save configuration;
they are not independently treated as listener notifications unless the
pinned oracle establishes such an event.

The router preserves listener-observer revision order. Sharing an output
cannot create duplicates: deduplication, where the upstream contract requires
it, uses the observer occurrence, run sequence, and bound sink identity, never
equality of sample ID, label, time, payload, or result data. Two revisions of
one root sample are distinct semantic events.

One event has one immutable payload digest. Remote or retried delivery retains
the same domain-qualified `EventId`; it does not mint a second semantic event.
An identity collision with different payload, source, generation, or digest is
a run-failing invariant error rather than a duplicate to discard.

### Bounded delivery and lifecycle

Every sink declares finite event, byte, and finalization limits. Admission has
typed `accepted`, `full`, `closed`, `cancelled`, and `failed` outcomes. The
compatibility path applies backpressure or fails the run according to an
explicit policy; it never silently drops an event. Per-sink isolation prevents
a slow report adapter from silently corrupting a file sink, while all queue
and task capacities remain fixed by trusted run configuration.

Admission records a per-event, per-sink delivery ledger. Its dispositions are:

```text
NotAdmitted | Queued | Processing | Durable | DiagnosedDrop | Failed
```

`DiagnosedDrop` is permitted only for a separately selected non-compatibility
policy whose evidence names the dropped event and stable reason. The
compatibility policy never selects it. For every routed event and selected
sink, exactly one terminal disposition is accounted for:

```text
selected = not_admitted + durable + diagnosed_drop + failed_after_admission
accepted = durable + diagnosed_drop + failed_after_admission
```

No terminal count may exceed the selected/accepted count, and ledger state is
monotonic. A sender acknowledgement does not mean durable unless the sink
contract defines and proves that durability boundary. Memory reclamation is
allowed only after the terminal disposition and its bounded diagnostic have
been retained in the run finalization report.

Legal transitions are closed:

```text
Selected -> NotAdmitted(Full|Closed|Cancelled|FailedBeforeAdmission)
Selected -> Queued -> Processing -> Durable
Selected -> Queued -> Processing -> DiagnosedDrop(non-compatibility only)
Selected -> Queued|Processing -> FailedAfterAdmission
```

`DiagnosedDrop` is post-admission only. A policy that elects not to queue an
event records `NotAdmitted`; it cannot relabel rejection as a diagnosed drop.

`NotAdmitted` is terminal for that admission attempt but never counted as
accepted. A compatibility run fails if any selected sink is not admitted.
Cancellation/deadline with queued work transitions each accepted item to an
explicit failure disposition; it never clears a queue without ledger entries.
The ledger records transition ordinal, event/sink identity, bounded byte count,
remaining budget, stable reason, and acknowledgement/durability token digest.

Each sink selects a typed full policy: `Backpressure(deadline)`, `FailRun`, or
the explicitly non-compatible `DiagnosedDrop`. Backpressure consumes the run's
single remaining operation/finalization budget; it has no independent reset
timeout. Cancellation cannot turn a full queue into apparent acceptance.

Result-operation liveness follows
[`Decision 0015`](0015-result-sink-operation-liveness.md). The application
creates one run-owned budget authority before sink startup. It shares the
run's fallible monotonic domain, cancellation source, and checked retry ledger,
but it does not impose an implicit maximum duration on the complete load test.
Each semantic start, admission-backpressure, process, flush, finish, or
recovery operation owns one finite linear lease whose absolute deadline cannot
be refreshed by polling, retry, or phase transition. Finalization establishes
one shared deadline that caps drain, flush, finish, and exact owner cleanup.

Every effectful sink future that can return `Pending` owns an exact RAII wait
registration before doing so. Cancellation and the time driver wake it, and
completion, timeout, error, cancellation, or drop retires it. A cross-process
sink receives a rounded-down finite remaining duration, never a process-local
instant. A bare future without an operation lease, cancellation wake, and wait
registration cannot implement a compatibility sink.

The lifecycle is:

```text
resolve and validate every output -> start all sinks
-> setup groups -> main groups -> teardown groups
-> stop admission -> drain accepted events -> flush -> finish/close
-> publish the run outcome
```

Startup is transactional: sampling does not begin until every enabled sink and
output has been validated and started. If one start fails, already-started
sinks are finalized within a bound and the run fails. `autoflush` changes
per-record flushing only; normal finish always flushes, and XML finish attempts
the closing root. On engine, sampler, or cancellation failure, the primary
error is retained and every sink finalization failure is reported as bounded,
redacted structured context. Immediate stop may shorten the drain deadline,
but accepted events are either durably accounted for or produce an explicit
sink-finalization error.

Dropping a future, router handle, or application adapter cannot convert queued
events into success. Cancellation releases permits and closes resources. No
correctness test relies on a wall-clock sleep; deterministic fake sinks and an
injected scheduler exercise full, close, cancellation, and finalization races.

Finalization is transactional at the run-outcome boundary. It returns a bounded
`FinalizationReport` containing every sink's selected, not-admitted, admitted,
durable, diagnosed-drop, and failed-after-admission counts; first/last event
IDs; format close/flush and publication outcomes; incomplete event references;
and redacted secondary
errors. The primary run error remains primary. The run cannot publish success
until all conservation equations validate and every accepted event has a
terminal disposition.

A sink contract declares its durability boundary (`MemoryProcessed`,
`FormatWritten`, `Flushed`, `Synced`, `RemoteAcknowledged`, or a separately
versioned boundary). Only an acknowledgement bound to event/sink identity,
payload digest, durability boundary, and the observed attempt ordinal can
advance the ledger. Retries reuse an idempotency key of `{EventId, SinkId,
payload_digest, durability_boundary}`; the key excludes attempt ordinal even
though the acknowledgement records it. Attempts consume the same finalization
budget and cannot reorder later events for the same ordered sink. A sink
without a proven idempotent acknowledgement is never retried after an unknown
outcome.

Per-sink queues and workers are isolated and scheduled by a deterministic
bounded round-robin arbiter. One full sink cannot consume another sink's
capacity, but a revision's compatibility admission is transactional across
all sinks selected by that exact observer entry: reservations are acquired in
stable `SinkId` order and either all commit or all roll back before any worker
observes the revision. Source-position snapshot and admission remain ordered;
actual sink processing is never a global sequential callback and cannot mutate
the live result seen by later listener entries.

### Output identity and conflicts

The application resolves a filename once at run startup from the explicit
property view, injected launch time/timezone, JMX/base-prefix semantics, and
configured filesystem roots. It validates symlink and containment policy
before creating or deleting a file. `LAST` is applied only in CLI positions
where the pinned oracle proves it. Ambient cwd, home directory, locale, clock,
or environment is not consulted implicitly.

A run output registry is keyed by a handle-bound canonical identity, not a
string path alone. It protects the open/create operation against path races.
The application abstraction is split into:

```text
OutputRequest {
  logical sink identity, rooted path token, mode, format, append policy,
  save/filter/header/root/flush/finalization policies, and finite limits
}

PreparedOutput {
  opaque open handle, stable file identity, parent-directory handle,
  preflight observation, staging identity, and publication state
}
```

Only the application constructs `PreparedOutput`; runtime/results/report code
cannot reopen a path. The implementation resolves each path relative to the
explicit JMX/plan or CLI base required by the profile, opens its parent and
target without following an unchecked final link, compares the opened file's
identity rather than a pre-open string, and revalidates containment and parent
identity at publication. Platform-specific file IDs, case behavior, Unicode,
symlink/junction/reparse points, alternate streams, hard links, and parent-swap
races are tested. A platform that cannot uphold the selected policy returns an
unsupported filesystem capability.

Path resolution is selected from an explicit domain matrix and recorded in the
output identity:

| Source | Input domain | Output domain |
| --- | --- | --- |
| JMX `ResultCollector.filename` | not applicable | profile-proven plan/JMX base |
| normal-run CLI `-l` | not applicable | launch working-directory capability |
| report-only CLI `-g` | launch working-directory capability | not applicable |
| report-at-end CLI `-e -o` | run result handle | launch working-directory capability |
| JTL `responseFile` | JTL-source directory capability when enabled | not applicable |

The labels in this table are domain types, not string concatenation rules. A
future oracle finding may parameterize a row, but no caller may substitute cwd,
the plan directory, home, or another source silently. `LAST`, base-prefix, and
date substitutions are applied only in their proven row and before the path is
bound to a handle.

Two logical sinks may share one physical writer only when pinned JMeter
evidence proves the sharing behavior and their format, save configuration,
filtering, append, header/root, flush, and ownership policies are compatible.
Otherwise the run fails before sampling with a stable output-conflict error.
The CLI `-l` target and plan collectors participate in the same registry.
One writer owns one CSV header or XML root and one final close.

This conservative conflict error is not itself a JMeter compatibility claim.
If the pinned oracle demonstrates deterministic first-writer, append, or other
behavior for a conflict, the implementation and this decision must be revised
or parameterized to reproduce that behavior rather than normalize it away.

Output modes are explicit: create-new, truncate-after-approved-force,
oracle-proven append, or report-input read-only. No call site passes a generic
boolean `force`. Preflight reads only the bounded prefix/suffix needed to
validate the selected format and append state. CSV append validates or emits
the effective header exactly once. XML append validates the existing root and
bounded tail, removes/replaces only the proven closing marker, and restores a
valid closing root during finalization; malformed or incompatible input fails
before sampling. An append operation never guesses the source save
configuration.

Append is copy-on-write. The application never mutates the published CSV/XML
in place. It opens and validates the exact source handle, streams its bounded
semantic content plus new events into a private same-filesystem generation,
finishes the format, syncs according to the durability policy, then switches
visibility atomically. An append transaction records source and parent file
identities, source length/digest, staging generation, format, save
configuration digest, last durable event ID, and publication state. Startup
recovery can classify and either finish or quarantine an interrupted
transaction without guessing. If the platform cannot bind and replace the
target under the selected identity policy, append is unavailable.

The append journal is canonical `result-append/1` with transaction/run/sink
and source/staging/parent handle identities, format and save-configuration
digests, source length/SHA-256, staging length/SHA-256, last durable event ID,
durability policy, and state:

```text
Prepared -> Writing -> FormatClosed -> Synced -> Publishing -> Published
          -> Recovered
Prepared|Writing|FormatClosed|Synced|Publishing -> Quarantined
```

Each transition is write-ahead, checksummed, and synced under the selected
policy before the side effect it authorizes. Recovery accepts no unknown state,
identity change, digest mismatch, or partial record; it preserves the last
published generation and reports bounded quarantine state.

`Publishing` is the write-ahead visibility intent and contains exact source,
staging, target, and parent identities plus expected pre/post lengths and
digests. `Published` is recorded only after the visibility switch and parent
durability are observed and revalidated. Recovery may finish a `Publishing`
record only when the target is still the exact source with intact staging, or
already the exact expected published generation; any other identity or digest
quarantines the transaction and retains the previous proven generation.

New outputs and reports are written to private same-filesystem staging handles.
Finish flushes and closes semantic format state before publication. Publication
is an application-owned transaction: every staged artifact is validated and
synced under the configured durability policy, then atomically renamed where
the platform guarantees it. A multi-file dashboard uses a staged directory or
generation plus one atomic visibility switch; writing `index.html` and
`data.json` independently is forbidden. If true all-artifact atomicity is not
available, the capability fails before sampling or uses a documented
generation-manifest protocol whose incomplete generation is never selected as
current. Failure preserves the previous published output and returns bounded
cleanup diagnostics for staging artifacts.

A dashboard always uses immutable generations plus one shared visibility
token. All HTML, JSON, assets, metadata, and graph payloads belong to the same
generation manifest and carry content digests. `current` is a small
handle-bound manifest/token replaced only after every artifact is durable. A
reader resolves the token once and never mixes files from different
generations. Recovery validates the token and generation manifest, retains the
last complete generation, and quarantines incomplete or unreferenced staging
state within a finite retention budget. Reopening paths independently or
publishing `index.html` as a proxy for completion is forbidden.

The canonical `dashboard-generation/1` manifest binds run/report/generation,
profile and report-config digests, the source input identity/length/SHA-256,
every relative artifact name/type/length/SHA-256, total count/bytes,
creation-source identity, and completion state. The
`dashboard-current/1` token binds exactly one completed manifest digest and
generation. Artifact names are bounded relative tokens, never paths supplied
by report data. Publication writes/syncs the manifest last within the
generation, then atomically replaces and syncs the current token. Recovery and
readers reject incomplete, unknown-version, digest-mismatched, or over-limit
generations.

### Filters, reports, and CLI modes

`ResultCollector.error_logging` and `ResultCollector.success_only` are stored
as separate typed flags and applied to the root event before serialization or
listener aggregation. A filter is not executable until the pinned oracle has
materialized the complete four-row truth table (`false/false`, `true/false`,
`false/true`, `true/true`) and the treatment of successful/failed transaction
samples, sub-results, ignored results, and zero-count synthetic samples. Until
then the compiler returns `result-filter.unverified` for any affected
collector; it never assumes the flags are complements or defaults to all
events. Once proven, the table is versioned data selected by profile identity,
not scattered boolean conditionals.

Aggregate, Summary, and Graph collectors retain independent state even when
they have no filename. They consume explicit controller metadata. Listener
percentile algorithms remain separate from dashboard algorithms; weighted
sample/error counts are not substituted for row-based dashboard counts.

Report-only `-g` parses the selected CSV or XML input using its actual save
configuration and never compiles or starts the JMX plan. `-e` consumes the
same logical filtered stream as the result file from that run. Neither mode
uses an unbounded in-memory vector. Report output is bounded, deterministic
under the explicit environment, and atomically published by the application.

## Rejected alternatives

- Cloning a concrete `ResultCollector` and file writer per virtual user:
  rejected because listener state and outputs are run resources.
- Making `runtime` depend on JTL filesystem writers or `report`: rejected
  because it reverses the dependency graph and introduces effects into the
  deterministic core.
- Reconstructing `SampleEvent` in the CLI: rejected because it can lose phase,
  variable, controller, and ordering information.
- An unbounded channel or post-run `Vec<SampleEvent>`: rejected because a load
  generator must bound retention and make backpressure observable.
- Silently selecting one of two incompatible writers: rejected until exact
  pinned behavior is proven and represented explicitly.

## Verification requirements

Pure `results` tests cover every save switch and alias, missing versus empty
object values, CSV/XML ordering, assertions, sub-results, response-on-error,
header/root finalization, atomic event writes, and input/output limits.

Deterministic `runtime` tests cover root and nested listener scope, exact
event order, one run sink across multiple users, full/closed/cancelled queues,
startup rollback, finish after every stop path, controller metadata, and no
duplicate delivery. Bounded interleaving tests cover admission versus close,
cancellation versus flush, and permit release.

The router model test enumerates all legal delivery-ledger transitions and
checks conservation after every transition, cancellation point, queue-full
policy, sink failure, retry, duplicate event, close race, and finalization.
Generated cases domain-qualify plan/run/worker/event identities and prove that
same-number IDs from different domains never alias. Injected failures exercise
every state before and after admission; a successful finalization with an
unaccounted accepted event is impossible.

`report` tests use the deterministic `FX-REPORT-001` corpus to distinguish
weighted listener totals from dashboard rows and cover Aggregate, Summary,
Graph, APDEX, percentiles, windows, timestamps, controller exclusion, empty
input, and deterministic error ties.

Application integration tests cover malformed/unknown collector properties,
disabled collectors, filters including both flags, multiple collectors,
same/different output conflicts, path/date/base-prefix handling, deletion and
symlink races, `-l`, `-e`, and CSV/XML `-g`. Raw artifacts remain available for
diagnostic comparison outside committed fixtures.

Save-configuration tests cover every field through every ordered source
operation, including absent/null/present-empty/remove, repeated sources, and an
ambiguous report input. Filesystem tests inject failures at every copy-on-write
append and dashboard generation step, then run recovery and prove the old
generation remains visible, an incomplete generation is never selected, and a
reader cannot mix generation members. Platform lanes exercise handle identity,
parent replacement, hard links, symlinks/junctions/reparse points, Unicode and
case behavior without relying on ambient cwd or home.

Pinned Apache JMeter 5.6.3 differential evidence is required for every filter,
listener mapping, conflict, JTL, and report compatibility claim. Required
fixtures are `FX-JTL-001` and `FX-REPORT-001`, with `NORM-JTL-001`,
`NORM-STRUCTURE-001`, `NORM-REPORT-001`, `NORM-TIME-001`, and applicable
configuration/environment policies. Unit tests or this decision cannot promote
any profile row.

Acceptance after implementation includes:

```text
cargo fmt --all -- --check
cargo test -p jmeter-rs-results --locked
cargo test -p jmeter-rs-runtime --locked
cargo test -p jmeter-rs-report --locked
cargo test -p jmeter-rs --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo run --locked -p xtask -- profile-check
cargo run --locked -p xtask -- fixture-check
```

The pinned oracle, cross-platform, performance, and soak gates run only after
the shared process-supervision boundary is approved and the required isolated
environment is available.

## Consequences

Result delivery becomes an explicit run lifecycle with measurable pressure and
failure rather than incidental callbacks. Core scheduling stays deterministic,
JTL and report algorithms keep their existing owners, and the application owns
all filesystem and executor effects. The design requires a new runtime routing
module and adapters in existing crates, but no new crate or dependency cycle.
