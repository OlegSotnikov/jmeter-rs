# jmeter-rs architecture

Status: binding architecture for the first conformance baseline  
Compatibility profile: Apache JMeter 5.6.3  
Canonical repository: <https://github.com/OlegSotnikov/jmeter-rs>

This project is an independent Rust implementation of JMeter's observable
contracts. It is not a source translation. Upstream documentation, a pinned
JMeter distribution, and differential tests define compatibility; Java class
structure does not define the Rust design.

## 1. Product contract

Compatibility is always stated as a tuple:

```text
(jmeter-rs commit, conformance profile, platform profile, capability set)
```

The initial conformance profile is
[`compat/profiles/jmeter-5.6.3.json`](../compat/profiles/jmeter-5.6.3.json).
A feature is compatible only after its profile entry points to passing,
version-pinned evidence. Loading an unsupported element must retain enough
information to round-trip it and execution must return a stable unsupported-
capability error. It must never silently omit, reinterpret, or approximate an
unknown element.

The native Rust engine is the preferred execution path. Behavior whose actual
contract is arbitrary Java bytecode, a JSR223 engine, Java RMI, or a third-
party JAR crosses a versioned JVM worker boundary. That boundary is part of
full-profile compatibility, not an excuse to claim that native Rust implements
Java semantics.

The primary distribution is one `jmeter-rs` Rust executable. It has no Java
runtime, JMeter distribution, helper process, or language-runtime prerequisite
for every capability declared native. Profile data, aliases, defaults, and
other read-only runtime assets needed by that capability set are embedded or
generated into the executable. Operating-system libraries and explicitly
requested remote services are not sidecar application artifacts. Exact
Java-bytecode behavior is available only through the separately provisioned,
opt-in compatibility pack described by
[`Decision 0009`](decisions/0009-standalone-rust-product-and-compatibility-pack.md).
The pack is never installed, downloaded, or selected implicitly.

GUI rendering is not required for the first engine milestone. GUI-authored
JMX persistence is required from the start: headless operations must preserve
GUI classes, unknown elements, and extension data. Full GUI compatibility uses
the explicit hybrid boundary in
[`Decision 0002`](decisions/0002-hybrid-gui-compatibility.md): Rust owns
headless persistence and mode policy, while pinned Swing/Preferences behavior
and GUI-triggered execution are delegated to the exact JMeter JVM worker and
proven per platform. GUI evidence also requires the profile to declare the JVM
and, where applicable, plugin boundaries; an OS-only row cannot prove it.
Implementation and runtime evidence for that GUI adapter are deferred until
after the standalone headless milestone. Deferral does not remove
`GUI-001..003` from the full profile or turn a capability error into GUI
compatibility.

## 2. Architectural rules

1. Observable JMeter 5.6.3 behavior wins over convenience and over assumptions
   inferred from Java internals.
2. Plan syntax, semantic meaning, and executable state are separate models.
3. Ordered tree position and node identity are first-class; names are not
   identities and sibling order is never stored in an unordered map.
4. The pure semantic core does not depend on Tokio, an HTTP client, a JVM, the
   filesystem, wall-clock time, ambient environment variables, or global
   randomness.
5. All effects enter through explicit capabilities: clock, sleeper, random
   source, transport, filesystem, environment, process/JVM worker, scheduler,
   and result sink.
6. A virtual user's variables, controller state, cookies, cache, authentication
   state, and element clones are isolated unless the JMeter contract explicitly
   makes state global. JMeter properties are run-scoped shared state.
7. Graceful stop, immediate stop, thread stop, next-loop, and sample failure
   are distinct typed signals.
8. Result events are append-only snapshots. Before each source-position
   observer captures its revision, a bounded typed listener effect may mutate
   the generation-tracked live result as defined by Decision 0016. No listener
   can mutate an already-captured or persisted revision, and asynchronous sink
   work cannot determine later listener semantics.
9. External and plugin protocols are versioned, bounded, cancellable, and
   crash-isolated. Rust's unstable native ABI is not a plugin contract.
10. No compatibility row becomes `verified` from a unit test alone; it needs
    the evidence named by the profile and, where applicable, the pinned Java
    oracle.

## 3. Workspace boundaries

The workspace uses these top-level boundaries. A crate may begin as a minimal
shell, but its responsibility must not migrate across a boundary without an
architecture decision record.

| Path | Responsibility |
| --- | --- |
| `apps/jmeter-rs` | Thin user-facing CLI, process lifecycle, signals, exit codes |
| `crates/model` | Typed properties, ordered identity tree, document metadata, semantic plan |
| `crates/jmx` | Bounded XML syntax layer, aliases/upgrades, lossless load/edit/save |
| `crates/expr` | Variables, properties, function parsing/evaluation and registries |
| `crates/runtime` | Scope compiler, execution packages, controller state machines, virtual-user lifecycle |
| `crates/results` | Sample/result model, events, JTL CSV/XML, aggregation primitives |
| `crates/http` | HTTP sampler and explicit cookie/cache/auth/header/proxy/TLS state |
| `crates/http-native` | Native sockets, explicit DNS, rustls, proxy handshakes, pooling, streaming and concrete decompression |
| `crates/report` | Listener aggregates, dashboard data model and report generation |
| `crates/remote` | Rust-native remote protocol and orchestration; never presented as Java RMI |
| `crates/bridge-protocol` | Versioned, bounded wire messages shared with external workers |
| `crates/java-bridge` | JVM worker supervision and JMeter/Java capability delegation |
| `crates/plugin-host` | Out-of-process native plugin discovery, handshake, quotas and supervision |
| `crates/observe` | Structured diagnostics, metrics, redaction and correlation IDs |
| `crates/test-support` | Fake clock/scheduler/transport, local fixtures, canonicalizers, trace assertions |
| `crates/process-supervision` | Private cross-platform exact-child/process-tree ownership and bounded reaping |
| `tools/jmeter-oracle` | Pinned Java JMeter acquisition, execution, normalization and differential comparison |
| `tools/xtask` | Reproducible repository checks and generated-profile tasks |

The allowed dependency flow is:

```text
model <- jmx
model <- expr
model + expr + results <- runtime
runtime + results <- http/report/remote/java-bridge/plugin-host
http <- http-native
process-supervision <- java-bridge/plugin-host/jmeter-oracle
all required libraries <- apps/jmeter-rs
test-support <- tests and tools only
```

Release construction additionally enforces the product boundary: the
standalone executable may link the native crates but cannot link, embed, spawn,
or discover a JVM/JMeter helper. The optional compatibility pack is reached
only through the application-owned capability router and the versioned bridge;
pure and native edge crates never depend on it in reverse. A build-time feature
may remove bridge client code, but enabling bridge client code by itself never
changes a native execution path or makes Java a runtime prerequisite.

`model`, `jmx`, `expr`, and `results` must compile without Tokio. `runtime`
defines executor-neutral state machines and capability traits. Production
Tokio adapters live at runtime/application edges. Protocol crates may depend
on the contracts they implement, but core crates must not depend back on a
protocol crate. `test-support` must never be a normal production dependency.
`process-supervision` is a private edge crate used only by subprocess-owning
adapters and tools; it must not become a dependency of a pure core crate. Its
production backend is one process-global, fixed-capacity ownership root. A
reserved global slot—not a caller handle or destructible registry—owns each
exact child and platform token immediately after spawn. Caller drop, bounded
cleanup failure, service failure, or destruction order therefore cannot lose
the resource. Admission, retries, drain, quarantine, and shutdown are bounded
and observable as specified by Decision 0001.

Crates are private by default. Publishing a library or stabilizing a public
API requires an explicit decision record and semver policy. Adding a new crate
also requires a short decision record; module boundaries are preferred until
independent features, dependencies, or release cadence justify a crate.

## 4. Plan representations

There are three representations with explicit conversions:

### Syntax document

The JMX layer retains XML declaration and encoding, comments, processing
instructions, namespace and attribute details, whitespace/raw spans where
promised, root versions, unknown nodes, and extension payloads. Parsing is
streaming and bounded by input size, depth, node count, attribute count, and
text length. It never resolves an external entity or executes a class named by
the document.

### Semantic plan

The semantic model contains an ordered identity tree. Every node has a
document-local `NodeId`, exact `testclass`/`guiclass`, name, enabled state,
insertion-ordered typed properties, ordered children, source location, and an
opaque extension representation. Duplicate-looking nodes remain distinct.
Known fields may have typed accessors, but the exact upstream property name and
original value remain the wire contract.

Parsing produces diagnostics without destroying syntax. Validation is a
separate pass. An unsupported-but-well-formed element can be inspected and
saved; compiling it for execution returns a typed capability error.

### Executable plan

Compilation removes disabled executable branches, resolves replaceable
elements, binds functions at the correct phase, computes scope, and creates
immutable execution packages keyed by `NodeId`. A package contains its sampler
or controller action plus applicable configuration, preprocessors, timers,
postprocessors, assertions, and listeners in verified order. Compilation does
not perform network I/O and does not mutate the source document.

Each virtual user receives independent mutable execution state derived from
the executable plan. Re-running a plan creates fresh state; recovery must not
leak values from a prior run.

## 5. Component model and registries

Components are discovered through explicit registries, not a central match
statement and not arbitrary dynamic loading. A registry entry declares:

- profile-specific aliases and upstream class names;
- component category and capability ID;
- property decoder/validator;
- compiler hook and runtime factory;
- external capability requirements;
- conformance fixture IDs.

Runtime component contracts are object-safe and executor-neutral. Asynchronous
operations return a standard `Future` through the contract; traits do not
expose Tokio types. Factories build per-user state where JMeter clones state
per thread and shared run state only where the upstream contract is global.

The execution phase protocol is fixed:

```text
configuration -> preprocessors -> summed timers -> sampler
              -> postprocessors -> assertions
              -> source-ordered listener effects/observer snapshots
              -> control consumption/results
```

A sampler may return no result; in that case the downstream result phases are
skipped as JMeter does. Same-category and scope ordering are profile behavior
and require oracle traces before being treated as stable.

Processor, extractor, response/request-view, invocation-delta, and result-action
ownership follows
[`Decision 0008`](decisions/0008-processors-extractors-and-mutation.md).
Runtime owns the dependency-free domain contracts; HTTP and bridge protocols
consume versioned projections and never become dependencies of runtime.

Sample monitors and sample-local interruption follow
[`Decision 0014`](decisions/0014-sample-monitor-and-interruptible-sampler-lifecycle.md).
They form a distinct lifecycle category immediately around sampler invocation;
they are not preprocessors, timers, or run-control cancellation signals.

Listener mutation and observation follow
[`Decision 0016`](decisions/0016-source-ordered-listener-effects.md). Runtime
walks one source-ordered listener program after assertions. Typed effects may
atomically update the live result/control generation; each observer captures
its own immutable revision at its exact position. Control is consumed only
after the chain and router admissions complete.

Expression evaluation and stateful built-ins follow
[`Decision 0017`](decisions/0017-expression-sessions-and-function-state.md).
One run-owned authority creates identity-bound ordered sessions at each
component getter/lifecycle boundary; it is not cloned per user or replaced by
an immutable snapshot resolver. Capability effects are journaled,
transactional, or explicitly irreversible, and uncertain external effects
poison the exact run rather than becoming a false rollback or fallback.

## 6. Runtime and scheduling

`runtime` is a set of deterministic state machines. The production adapter may
use async I/O and a bounded blocking pool; one OS thread per virtual user is not
an architectural requirement. Compatibility concerns logical user isolation,
ordering, lifecycle, timing fields, and stop behavior—not Java's thread
implementation technique.

A run owns immutable configuration, shared properties, component registries,
resource policy, cancellation hierarchy, and result routing. A virtual-user
context owns variables, iteration/controller state, current/previous sample,
random streams, and protocol session state.

All time calculations distinguish monotonic duration from wall timestamps.
All timers and deadlines use an injected clock/sleeper. Random streams are
seedable and scoped so adding an unrelated user or function does not silently
perturb every stream. Production scheduling need not be deterministic, but a
deterministic adapter must record and replay logical wake/cancel/order events.

Cancellation severity is monotonic:

```text
continue < next-loop < stop-thread < stop-test-graceful < stop-test-immediate
```

Components receive cancellation and deadlines explicitly. Every bounded queue
has documented full and closed behavior. Cancellation must release permits,
files, sockets, tasks, and child processes.

Production time and future driving follow
[`Decision 0011`](decisions/0011-runtime-progress-and-wait-driving.md). The
application supplies one run-owned bounded clock/sleeper/scheduler driver;
epoch/immediate capabilities remain deterministic test defaults only. Pending
production futures register finite absolute waits, while the current-thread
executor applies progress-relative stall budgets. Long representable schedules
are valid, cumulative work is not mistaken for a stall, and schedule arithmetic
never saturates silently.

The application composes plan admission, native providers, production time,
result staging, and reporting as the consuming ownership state machine in
[`Decision 0012`](decisions/0012-standalone-run-ownership-transaction.md).
Feature-specific decoders and factories remain narrow registered modules;
the runner owns their effect order and exact reverse finalization, but does not
become an ambient service locator or duplicate their parsing logic. Visible
result/report publication is possible only from a successfully finalized run.

Engine lifecycle preserves setup, main, and teardown phases; serialized thread
groups are an execution policy, not a special controller. Exact start/end and
failure ordering remains oracle-gated until traced by fixtures.

Run diagnostics and production result delivery are separate contracts under
[`Decision 0010`](decisions/0010-run-observation-retention.md). The standalone
runtime uses a constant-memory checked summary and retains no per-sample event
trace. Ordered full traces are an explicit, count-and-byte-bounded test/debug
capability; no mode may silently truncate compatibility observations or replace
the result router.

## 7. Results and persistence

`SampleResult` represents the full hierarchy and timing vocabulary needed by
JTL, listeners, transactions, and remote transfer. It does not use one generic
duration for elapsed, latency, connect, idle, and timestamp. Assertion results,
request/response data, byte counters, thread counts, stop/logical flags, and
sub-results remain distinct.

At listener notification, a `SampleEvent` snapshots selected variables and
identity fields. Sinks consume events through explicit bounded queues. A slow
sink follows a configured backpressure/failure policy; it may not silently
drop compatibility results.

CSV and XML are separate codecs parameterized by the profile's save
configuration. A neutral event representation is used for differential
comparison, while raw artifacts are retained for diagnosis. Normalizers may
change only fields listed in the profile and each rule needs a test proving it
cannot hide a semantic difference.

Result collectors follow the run-lifetime ownership and routing contract in
[`Decision 0003`](decisions/0003-result-sink-routing.md). Runtime owns bounded
executor-neutral event routing and explicit sampler/controller metadata;
`results` owns save configuration and JTL codecs; `report` owns listener and
dashboard algorithms; and the application owns path resolution, files, CLI
modes, and executor adapters. A collector or output writer is never silently
cloned per virtual user, an accepted event is never silently dropped, and an
output conflict is resolved only by profile-proven behavior.

Cross-thread sink completion and operation deadlines follow
[`Decision 0015`](decisions/0015-result-sink-operation-liveness.md). One
run-owned authority shares cancellation and retry accounting, while each
semantic sink operation owns one finite non-refreshing lease and one exact
RAII wait registration whenever it is pending. This bounds blocked writers
without imposing an arbitrary maximum duration on a healthy load test.

## 8. Protocols, JVM behavior, and extensions

HTTP owns request construction and per-user cookie/cache/authentication state
behind a transport capability. Client-library defaults—ambient proxies,
redirects, decompression, TLS roots, retries, HTTP version—are disabled or made
explicit. Correctness tests use deterministic local servers and wire traces.
The native transport edge, exact HttpClient4/Java delegation, JSSE/JKS split,
proxy, recorder, and mirror boundaries follow
[`Decision 0006`](decisions/0006-http-transport-tls-proxy-boundaries.md). A
native transport is never an implicit fallback for a JMX-selected JMeter
implementation.

For the bootstrap standalone executable, native HTTP is selected only by one
explicit direct command-line property whose value is the exact
`http.native/1` or `http.native/2` identity. This plan-wide operator choice may
substitute the independently named native provider for preserved JMX
`HttpClient4` or `Java` selections, but the compiled manifest and evidence keep
both identities and make no Java-provider compatibility claim. Without that
selector, the JMX/default provider remains authoritative and requires its
optional pack. Selection and complete feature admission occur before network,
logging, result, report, or runtime side effects.

The bootstrap `NativeV1` provider is a bounded synchronous HTTP/1.1 edge. It
uses exact-pinned Mio only to create and readiness-poll one nonblocking connect
attempt, with an `Arc<Waker>` for prompt cancellation; post-connect I/O and the
repository framing implementation remain synchronous. Repeated short
`connect_timeout` calls are forbidden because they create multiple attempts.
The application runs the complete operation only through a bounded blocking
worker pool, so runtime future polling never performs DNS or socket I/O inline.
Queue saturation, cancellation, deadline expiry, readiness events, shutdown,
and result delivery are typed and finite. A general async transport, pooling,
and HTTP/2 remain separate versioned provider increments, not silent
implementation swaps.

`http.native/2` is a distinct direct HTTP/1.1 increment for hostname HTTP and
rustls HTTPS. Its first policy is deliberately explicit: hostname plans supply
one direct bounded numeric-nameserver property and HTTPS plans supply one
direct root-contained PEM CA-file property. The application owns one bounded
resolver lifetime and one immutable TLS configuration for the run; DNS/TLS
work remains inside the bounded HTTP worker path. URL authority, HTTP Host,
TLS server name, and numeric peer address are separate domain values. Platform
DNS, platform roots, embedded web roots, proxies, pooling, decompression, and
HTTP/2 require separately named capabilities and never alter `/1` or `/2`
silently.

The ordinary-CLI single-binary path follows
[`Decision 0013`](decisions/0013-native-http-v3-and-drop-in-resolution.md).
`http.native/3` is a new capability rather than an expansion of `/1` or `/2`.
It may add bodies, scoped managers, redirects, decompression, pooling, and
explicit proxies after those behaviors pass their own bounded implementation
and evidence gates. A versioned `http.execution/auto/1` resolver may translate
an otherwise-supported JMX Java/default/HttpClient4 selection to `/3` without
an extra CLI property only after every enabled HTTP feature is covered by the
closed `/3` manifest and the pinned differential matrix passes. The manifest
and results retain both the source provider and executed native provider.
Auto-resolution never means that native wire behavior is relabeled as Java or
HttpClient4 behavior, and any uncovered field rejects the whole plan before
side effects.

The JVM bridge and plugin host use subprocesses by default. Their framed
protocol includes protocol version, profile/capability set, request ID,
deadline, cancellation, maximum message size, and structured error code. The
host applies an environment allowlist, filesystem/network policy, output and
resource limits, and process-group cleanup. A worker crash fails the affected
operation without corrupting engine memory.

Cross-platform process ownership is centralized by
[`Decision 0001`](decisions/0001-shared-process-supervision.md). Java, JMeter,
and plugin workers require its process-tree policy; unsupported platforms fail
with a typed capability error rather than silently downgrading to direct-child
cleanup.

Every executable plan is classified before the first sampler, listener,
processor, script, or setup callback runs. Classification produces an ordered
per-node implementation-path manifest and one of two closed outcomes:

```text
standalone-native
optional-compatibility-pack-required
```

A mixed plan cannot run its native prefix and fail later when a Java-only node
is reached. In standalone mode, any required compatibility-pack node rejects
the complete run with a typed, source-located capability error before useful
work. In compatibility-pack mode, the exact negotiated path is recorded for
every node; no node may move between Rust and Java after admission, and no
missing Java capability may fall back to a merely similar Rust component.

Java plugins, Java samplers, JUnit, BeanShell, Groovy/JSR223, drivers, and Java
RMI are delegated only through a worker built from the exact profile classpath.
An unavailable worker is a stable unavailable-capability result. JNI and an
in-process Rust dynamic-library ABI are outside the initial architecture.
The scripting, class-loading, and Java-plugin lifecycle, identity, atomic-delta,
and evidence contract is defined by
[`Decision 0005`](decisions/0005-pinned-jvm-scripting-and-plugins.md). Java JAR
discovery never falls through to the native executable `plugin-host`.

FTP, JDBC, LDAP, TCP, JMS, mail, database-driver, OS-process, access-log, and
deprecated external sampler paths follow
[`Decision 0007`](decisions/0007-external-samplers-services-and-drivers.md).
Every path is explicitly named and identity-bound; native clients and pinned
Java/provider paths are separate capabilities with no fallback between them.

The Rust-native remote protocol is independently versioned and can reproduce
distributed execution semantics. It must never be described as wire-compatible
with Java RMI. Drop-in `-r`/`-R`/`-G`/`-X` and server compatibility use the
explicit pinned JVM controller/worker boundary in
[`Decision 0004`](decisions/0004-pinned-java-rmi-adapter.md); native remote mode
has separate naming and cannot be an implicit fallback.

## 9. Errors, observability, and security

Library boundaries return typed errors with stable machine codes. Categories
include configuration, plan syntax, plan semantics, unsupported capability,
schedule/cancellation, transport, sampler, assertion, script, plugin/bridge,
persistence, and internal invariant. Human messages and source chains are
diagnostic data, not compatibility keys.

Every error carries available plan path/`NodeId`, run/user/sample identity,
operation, retryability, and redacted context. Panics indicate bugs, never user
input. Production paths do not use `unwrap`, `expect`, `todo`, or `unimplemented`
for reachable input.

Untrusted JMX, data, responses, scripts, and plugins are bounded. Filesystem
access uses canonicalized configured roots; process spawning never invokes a
shell; network and environment inheritance are explicit; secrets never enter
logs, metrics, oracle artifacts, snapshots, or high-cardinality labels.

## 10. Conformance and release gates

Every implementation change names one or more compatibility IDs. Its evidence
is proportionate to the boundary:

- unit tests for pure invariants and all error branches;
- property tests for round trips and state-machine invariants;
- fuzz targets for untrusted parsers and framed protocols;
- deterministic model tests for cancellation, queues, and shared state;
- local integration tests for I/O, TLS, proxies, workers, and process exits;
- end-to-end CLI tests for public behavior;
- differential tests against the pinned Java oracle for every compatibility
  claim;
- benchmarks and soak/leak tests for hot or long-running paths.

An implementation PR does not edit a profile row to `verified` unless the
named evidence exists and passes in CI. Expected external capabilities remain
`external` until an adapter and pinned fixture pass. Rust-only tests may run
when Java is unavailable during local development, but release conformance
must fail closed when its oracle is unavailable.

The first product milestone is the standalone headless executable. It is
complete only when the model, JMX, results, expression, controller/runtime
lifecycle, HTTP, local reporting, and local CLI oracle matrix passes for its
declared native capability projection, the one-artifact/no-Java gates pass on
every release target, and every non-native plan fails before side effects.
External services, native remote execution, and the optional JVM compatibility
pack advance as independent visible capabilities. GUI implementation is
postponed behind the standalone milestone. The full 52-row profile remains a
separate, stricter completion claim and is not reduced by milestone ordering.

## 11. Change control

Decisions that change dependency direction, representation boundaries,
execution phase order, state ownership, plugin/bridge isolation, compatibility
meaning, or public API require a short record under `docs/decisions/`. A record
states context, decision, alternatives, compatibility effect, migration, and
test impact.

Ordinary crate-internal implementation choices do not need a decision record.
When upstream behavior is unknown, add an oracle case and document the result;
do not encode a Rust-specific guess as architecture.

## Evidence behind this architecture

- [Compatibility surface](research/compatibility-surface.md)
- [Upstream execution semantics](research/upstream-semantics.md)
- [Rust engineering and testing strategy](research/rust-testing-strategy.md)
- [Repository and publication baseline](research/repository-baseline.md)
