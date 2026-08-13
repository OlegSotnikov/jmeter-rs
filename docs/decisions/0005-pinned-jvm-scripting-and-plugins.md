# Decision 0005: pinned JVM scripting, class loading, and Java plugins

Status: accepted architecture, revision 5; implementation and external evidence pending  
Date: 2026-08-13  
Compatibility features: `FUNC-003`, `SCRIPT-001`, `SCRIPT-002`, `PLUG-001`,
`PLUG-002`, `PLUG-003`; preservation impact: `JMX-004`  
External boundaries: `EXT-JVM-001`, `EXT-PLUGIN-001`

## Context

BeanShell, Groovy and other JSR223 engines, JEXL, Rhino-backed functions, Java
Sampler, JUnit, user classes, and arbitrary JMeter plugins expose live Java
object identity, JMeter lifecycle objects, Java static and class-loader state,
and arbitrary side effects. A copied string map or a Rust reimplementation of
an engine cannot reproduce that contract.

Pinned JMeter 5.6.3 binds scripts to live `JMeterContext`, `JMeterVariables`,
global `Properties`, sampler, previous result, logger, `System.out`, and broad
mutable `SampleResult` graphs. Variables can contain arbitrary Java objects.
Pre/postprocessors and listeners may mutate live state before or even after a
checked error. Runtime exceptions, cancellation, bridge failure, or worker
death can occur after those mutations or after filesystem, network, static,
thread, or plugin effects. Rejecting a later Rust delta cannot roll the JVM
back.

Revision 1 therefore overstated atomicity and underspecified the wire. Revision
2 separates an exact JVM-authority mode from a deliberately restricted
projection mode, defines `jvm-capability/2`, and makes every uncertain executed
operation terminal for its worker/run generation.

The current script and plugin fixtures are original static contracts. They
have not executed JMeter, a JVM, a user class, or a plugin artifact and are not
conformance evidence.

## Decision

Exact Java behavior is delegated to a separately supervised JVM worker built
against the pinned Apache JMeter 5.6.3 distribution. The worker uses the
bounded bridge frame and a strict `jvm-capability/2` schema. Version 1 remains
decode-only for diagnostics during migration and is never accepted as an
exact execution capability.

Responsibilities are fixed:

- `model` and `jmx` preserve script text, class names, aliases, properties,
  unknown fields, and hash-tree companions without loading code;
- `expr` and `runtime` select an explicit native, JVM-authority, or restricted
  projection capability and never infer one from a class-like string;
- `bridge-protocol` owns the closed, bounded, canonical operation schema and
  pure transaction/state validation;
- `java-bridge` owns typed requests, identity, deadlines, cancellation,
  terminal/crash mapping, and the bounded blocking-pool edge;
- one original helper under `tools/jmeter-jvm-adapter/` owns pinned JMeter/JVM
  object construction, Java execution, and class loading;
- Decision 0004 uses role-specific modules in this same helper generation for
  RMI controller/worker behavior; it does not create a similar second
  class-loader universe;
- `plugin-host` remains the native executable-plugin host and never discovers
  Java JARs or claims JMeter Java-plugin compatibility;
- the application owns roots, protected secret providers, limits, worker
  lifetime, containment, and capability wiring.

JNI, an in-process JVM, source translation, a Rust ABI plugin fallback, and
ambient classpath discovery are outside this path. Adding one requires a
separate decision and cannot become an implicit fallback.

## Exact JVM authority and restricted projection

The exact path executes the whole Java-owned compatibility unit while its live
objects remain authoritative. For a JSR223 element embedded in a sampler
package, that unit includes the phase-time expansion, applicable Java
preprocessors/timers/sampler/postprocessors/assertions/listeners whose shared
object identity or side effects cannot be projected safely, and final control
action. Rust does not persist or publish the result until the Java listener
chain has completed. `SampleEvent` selected-variable data is captured at the
pinned notification point, while its live `SampleResult` is finalized only
after the Java listeners that may mutate it have run.

The exact worker returns one final bounded snapshot and operation outcome. It
does not promise rollback. If transport, deadline, cancellation, framing,
validation, output limit, or worker failure occurs after Java code may have
started, the worker is poisoned and quarantined, the run generation is
terminalized, the operation is not retried, and no Rust delta is committed.
The outcome explicitly states that external/static/JVM-side effects may have
occurred. Starting a replacement JVM inside that run cannot restore Java
identity and is forbidden.

Restricted projection mode is a separately named capability for trusted,
explicitly bounded operations that use only representable values and a
journaled mutation surface. It requires a prepare/execute/proposal/commit or
abort protocol. Unsupported object identity, mutation, output, or side effect
fails before execution when possible. If execution has begun and the worker
cannot prove a complete journal or safe abort, it is poisoned just like exact
mode. Arbitrary Groovy, Java Sampler, JUnit, or plugin code cannot be statically
declared projection-safe and uses JVM authority.

A Java semantic failure is not automatically a bridge failure. Checked
JSR223 sampler errors, assertion errors, timer-zero behavior, swallowed
processor/listener errors, JUnit failures, and pinned JavaSampler failed-result
paths may return normal JMeter outcomes when the entire Java unit and final
state are known. A missing JavaSampler class uses the pinned
`ErrorSamplerClient` failed-result behavior in the exact path; the typed
capability error remains available to preflight/support reporting and must not
replace that runtime result once exact execution was selected.

The wire makes this distinction closed and mandatory:

```text
ExecutionReply =
    SemanticComplete { phase_outcomes, final_snapshot, event_snapshots,
                       result_graph, observations, proposal_digest }
  | BridgeFailure { failure, may_have_executed, poison_reason,
                    bounded_diagnostics }

PhaseOutcome = {
  phase_ordinal, source_node, phase_kind, disposition, result_reference,
  control_action, diagnostic_reference
}
PhaseDisposition = Completed | ZeroDelay | NullResult | FailedSample |
                   AssertionFailure | AssertionError |
                   SwallowedCheckedError | LoggedListenerError |
                   ThreadRuntimeFailure | PinnedJavaSamplerFailure

PhaseKind = RunOpen | ProviderDiscovery | FunctionExpansion |
            TestStarted | ThreadStarted | SamplerSetup | Configuration |
            PreProcessor | Timer | Sampler | PostProcessor | Assertion |
            Listener | ResultRouting | SamplerTeardown | ThreadFinished |
            TestFinished | RunClose

ControlAction = Continue | StartNextIteration | BreakCurrentLoop |
                StopThread | StopTestGraceful | StopTestImmediate

source_node = Absent | Present(DomainQualifiedNode)
result_reference = Absent | Present({ result_ordinal: u32,
                                      projection_sha256: [u8; 32] })
diagnostic_reference = Absent | Present({ diagnostic_ordinal: u32,
                                          diagnostic_sha256: [u8; 32] })
```

`SemanticComplete` is a successful protocol response even when JMeter marks a
sample unsuccessful or swallows/logs an element error. It returns to `RunOpen`
only after the complete Java authority unit and snapshot are known and
validated. `BridgeFailure` never contains a partial semantic snapshot to
commit. A failure with `may_have_executed != No` poisons the worker and run
generation. Schema validation forbids representing the same reply as both a
semantic outcome and a bridge failure. `phase_outcomes` is a nonempty bounded
ordered vector in exact execution order, so timer-zero, sampler failure,
swallowed processor/listener errors, assertion outcomes, and a logical action
can coexist. `control_action` is an explicit typed field and does not consume
the disposition slot. Every `PhaseKind` and `PhaseDisposition` is closed by the
schema; there is no catch-all `PinnedElementOutcome`. Uncaught runtime failures
are classified at the JMeter-thread/test lifecycle boundary and include the
complete known final state or become a poisoned `BridgeFailure`.

`DomainQualifiedNode` is the same bounded plan-domain/document/node identity
used by the runtime contracts; zero is never a node sentinel. Provider
discovery and test/thread start/end are phase outcomes whenever they complete
semantically. Handshake/framing failures are protocol `Error`/`BridgeFailure`
records, never fabricated semantic phase outcomes. Result and diagnostic
ordinals are nonzero and index the ordered bounded vectors in the same reply;
their digests bind the canonical referenced entry. An absent reference is
encoded explicitly and is not an all-zero digest.

The exact authority unit is the maximal contiguous Java-owned execution region
that shares live JMeter objects, Java static state, or lifecycle state.
It includes thread/test callbacks needed by the selected Java elements,
applicable configuration/pre/timer/sampler/post/assertion/listener phases,
notification-time `SampleEvent` selected-variable snapshots, transaction-
controller parent aggregation that can mutate result graphs, and any RMI
callback/sender handoff selected for that Java run. Rust publishes no child,
parent, listener event, variable snapshot, or result from that region until the
unit returns `SemanticComplete`. If a plan would interleave Rust and Java inside
one such region, compilation rejects it as `script.authority.mixed-boundary`
unless a separate oracle-proven cut point exists. Object handles, snapshots,
and transactions never cross an RMI controller/worker JVM process.

`open_run` begins the authoritative test-wide Java lifecycle for one worker:
class-loader construction, provider discovery, test-state listeners, static
caches/registries, run properties, engine/thread-group lifecycle, and all
per-user sampler clones. `close_run` owns test-ended callbacks, JavaSampler's
global teardown registry, JSR223 static-cache invalidation, remaining test-
state listeners, and final class-loader/handle accounting. A per-user package
transaction is serialized within that run but cannot independently close or
reset shared state. If arbitrary Java code requires cross-user concurrency or
ordering that the one-transaction bridge cannot reproduce, exact compilation
selects `execute_package { authority_extent: WholeEngine }` or rejects the
mixed plan; there is no unnamed whole-engine operation. `WholeEngine` transfers
one complete compiled plan and lifecycle policy to the worker, which owns the
pinned setup/main/teardown groups, user concurrency, callbacks, result
notification, stop actions, and close ordering for that run. Rust supplies
only bounded input capabilities and receives ordered callback snapshots plus
the final handle-free projection. The prepare digest covers the complete plan,
classpath, lifecycle/concurrency policy, roots, properties, and capability
identity; the proposal digest covers every ordered callback, terminal result,
control outcome, and final state. Per-user `execute_package` uses
`authority_extent: Package` and remains serialized. A plan needing whole-engine
authority cannot be split into package transactions or publish intermediate
Rust results.

## Lifecycle and operation state machine

One worker generation serves one run identity and processes one mutating
transaction at a time. Transport multiplexing does not make Java static state,
class loaders, contexts, sampler instances, or global properties concurrent.

Closed operations are:

```text
open_run
discover_providers
expand_function
execute_jsr223
java_sampler_setup
java_sampler_run
java_sampler_teardown
junit_run
execute_plugin_element
expand_plugin_function
execute_package
close_run
```

`execute_package` has the mandatory closed field
`authority_extent = Package | WholeEngine`. `WholeEngine` is legal only once
per open run, owns every user and lifecycle callback, and is terminal with
respect to further useful operations; `Package` follows the ordinary
one-transaction rule. `discover_providers` maps to `ProviderDiscovery`, and
`open_run`/`close_run` map to the corresponding lifecycle phases. `Hello` is a
wire phase, not a semantic operation and cannot execute Java code.

Every mutating invocation follows:

```text
Created -> Handshaking -> Ready -> RunOpen
RunOpen -> Prepared(transaction) -> Executing(transaction)
        -> Proposed(transaction) -> Committing -> RunOpen
Prepared -> Aborting -> RunOpen
Proposed -> Aborting(journaled) -> RunOpen
Executing/Proposed -> Poisoned when outcome or rollback is uncertain
RunOpen -> Closing -> Terminal
Poisoned -> Closing -> Terminal
```

The only legal transition back from execution is a validated
`SemanticComplete` proposal and commit. A complete Java semantic failure is not
the `Err` branch of a transport response and does not terminalize the session.
A `BridgeFailure` with no proof of non-execution transitions to `Poisoned`.
The session admits exactly one mutating transaction and therefore has no map of
concurrently pending mutating requests; read-only discovery can be pipelined
only under a separately negotiated immutable-operation capability.

Provider discovery is mutating by default because service loading/scanning can
load classes and run constructors or static initializers. It is serialized
inside `open_run` and never uses the pipelined immutable-operation exception.
A future immutable discovery mode requires a proof-bearing provider manifest
and a separate decision; merely naming an operation “read-only” is insufficient.

`open_run`, provider discovery, and immutable class-loader construction occur
exactly once before RMI `Ready` when composed with Decision 0004. No useful
operation precedes them. `close_run` is exactly once, stops admission, drains
accepted work, closes sampler instances/class loaders, reports cache and
handle state, and emits exactly one terminal outcome. EOF, a duplicate
terminal, any response after terminal, or an unaccounted transaction is a
protocol failure. Close idempotence is permitted only for the exact same
request/body digest.

Normal `close_run` invokes the pinned Java teardown/test-ended callbacks and
records each as a semantic phase before final accounting. A poisoned run uses
`close_run { mode: ContainmentOnly }`: it admits no Java/plugin/user callback,
performs only supervisor-owned descriptor, process, artifact, handle-ledger,
and quarantine accounting, records the skipped callback set, and terminates as
failure. It cannot claim JMeter test-ended semantics or return to `RunOpen`.
If containment-only close cannot prove all owned resources accounted for, the
worker remains quarantined and the terminal report says so; replacement never
repairs the poisoned run.

## `jvm-capability/2` wire contract

The `JVC2` inner envelope is canonical, big-endian, and carried inside the
existing bounded bridge frame. It contains:

```text
magic/schema/message kind/phase/operation/flags
session ID, request ID, transaction ID, per-direction sequence
run ID, plan node ID, run generation, user generation
diagnostic absolute wall deadline, remaining monotonic budget
known-field count, extension count, body length and SHA-256
previous-chain/body chain SHA-256, zero reserved bytes
```

Request IDs are nonzero after hello. Session/transaction IDs are fixed-width
opaque values. Sequence begins at one in each direction and increases exactly
once per message. Canonical body fields are length-delimited TLVs: known tags
increase strictly, duplicates are rejected, negotiated extension tags occupy
a separate range, and reserved tags cannot appear on the wire. Primitive
types are fixed-width signed/unsigned integers, strict booleans, opaque IDs,
SHA digests, exact IEEE-754 bits, validated non-normalized UTF-8, and bounded
bytes. Absent, null, and present-empty have distinct discriminants. Repeated
collections encode one ordered field with an explicit count.

The body digest covers schema, operation, phase, and canonical fields. The
chain digest covers the preceding chain, direction, sequence, and body digest.
A duplicate request is replayable only when request ID, sequence, operation,
transaction ID, body digest, and chain digest all match a bounded cached
request. Otherwise it is an order/replay failure. A response echoes every
request identity and the request body digest.

Strict mode rejects every unknown field before execution. Negotiated extension
mode retains bounded raw extension TLVs without interpreting them. Unknown
operations and phases are never executed. They may be forwarded only under an
explicit exact extension capability; otherwise the whole operation is
rejected. Unknown JMX/plugin data remains in the lossless model and is referred
to by source node/digest rather than copied into an unbounded executable body.

The compile-time complete-frame ceiling is 16 MiB. The fixed inner envelope
and outer framing are included in that ceiling; checked arithmetic determines
the maximum body. No schema field may allocate before its declared length,
collection count, depth, and aggregate budget have been validated.

Digest domains are ASCII constants followed by one zero byte and canonical
length-delimited data: `jvc2/body`, `jvc2/chain/request`,
`jvc2/chain/response`, `jvc2/snapshot`, `jvc2/proposal`, `jvc2/identity`, and
`jvc2/terminal`. A phase matrix in the schema source lists every required,
optional, and forbidden tag for each operation/message/phase. Missing required,
duplicate, or forbidden tags fail encoding and decoding. The matrix is part of
the golden-vector identity and is frozen before an execution encoder is
enabled; an unspecified field is forbidden rather than implicitly optional.

The initial client `Hello` request has zero session/transaction/run IDs,
request ID zero, request-direction sequence one, an all-zero previous-chain,
and a nonzero 32-byte client nonce. Its `transcript` field is explicitly absent.
Its chain digest is computed normally over that zero predecessor. The server
`Hello` acknowledgement has a newly assigned nonzero session ID, request ID
zero, response-direction sequence one, previous-chain equal to the request
chain, a nonzero independent server nonce, and a present canonical transcript
digest.

Transcript construction is non-circular. First compute `request_body_sha256`
from the complete request. Then encode the acknowledgement with its transcript
field explicitly absent and compute `ack_pretranscript_body_sha256`. The
transcript is `SHA-256("jvc2/hello-transcript\0" || canonical(client_nonce,
server_nonce, client_role_module, server_role_module, offered_limits,
selected_limits, schema_matrix_digest, request_body_sha256,
ack_pretranscript_body_sha256))`. Insert that transcript into the final
acknowledgement and compute its ordinary body/chain digests. A decoder repeats
both encodings and comparisons; zeroing the field rather than encoding absence
is invalid. Golden vectors freeze the exact absent discriminant, field tags,
lengths, order, domain separator, pretranscript digest, final body digest, and
chain. Thereafter request IDs begin at one and each direction's next sequence
is two. Pre-session object handles, run state, capability use, and execution
are forbidden. A retried hello creates a new nonce/transcript/session; it is
never replayed as useful work.

The operation/phase matrix is:

| Phase | Required semantic body | Forbidden semantic body |
| --- | --- | --- |
| `Hello` request/ack | role/module, profile/helper/schema identity, client request: nonce plus absent transcript; server ack: independent nonce plus present transcript; offered/required limits and capabilities | run state, handles, executable source, proposal |
| `Open` request | run/root/classpath/provider identity, lifecycle policy, initial typed state digest | user transaction, result/proposal |
| `Open` ack | observed complete identity, class-loader generation, provider observations, run snapshot digest | executable result/proposal |
| `Prepare` request | operation-specific input, source/authority identity, base snapshot/generations, transaction ID | result, after-state, commit fields |
| `Prepared` ack | transaction/base digest, admitted authority region, rollback capability, budget observation | Java result, mutations |
| `Execute` request | exact prepared digest and finite budget/cancellation | changed input, commit/abort fields |
| `Proposed` reply | exactly one `ExecutionReply`, complete proposal/candidate/after-state digests when semantic-complete | commit acknowledgement |
| `Commit` request | proposal digest and expected/current generations | new mutations or Java execution input |
| `Committed` ack | resulting generations/state digest and publication barrier | partial state or new proposal |
| `Abort` request | transaction/proposal digest when present, typed reason | executable input or commit fields |
| `Aborted` ack | `NotExecuted` or complete `Journaled` rollback proof and resulting base digest | success result after unknown execution |
| `Poison` | primary reason, execution certainty, last sequence/digests | reusable state claim |
| `Close` request/ack | run generation, final transaction/handle/cache/output accounting, close reason/proof | new useful operation |
| `Error` | stable bridge/configuration error, certainty, redacted bounded diagnostics | semantic Java outcome or partial state to commit |
| `Terminal` | exactly one closed outcome, final chain/identity/accounting digest | any reusable handle or pending transaction |

Each operation has one generated closed input union used only in `Prepare` (or
`Open`/`Close` for those lifecycle operations). `execute_package` is the exact
whole-region operation; element-specific operations are permitted only when
their authority boundary is independently closed. The schema assigns fixed tag
numbers and required-field bitsets to this matrix, and the complete table/hash
is included in helper identity.

## Context snapshots and Java object identity

`ContextSnapshot` contains exact run/user/thread-group/thread/iteration/sample/
plan identities, run and user generations, sampling/recording state, a
canonical snapshot digest, typed variables and serialized run properties,
sampler-context values, element parameters/arguments/file/label, and complete
bounded current/previous result projections.

Live Java identity is represented by opaque leased `ObjectHandle` values:

```text
ObjectHandle {
    handle_id, object_kind, owner_scope,
    class_identity_sha256, classloader_generation,
    rights, lease_operations,
}
```

`owner_scope` is a closed tuple of helper role/module, worker and session,
run ID/generation, class-loader generation, user/thread scope where applicable,
and allocation ordinal. Rights never widen during a lease. A handle from
another role, RMI process, run/generation, or loader is invalid even when its
numeric ID and class digest match. RMI callback/event DTOs are handle-free and
contain only complete bounded value projections.

The handle-free callback projection replaces every result/artifact/object
handle with a closed value reference `{ kind, ordinal, byte_length, sha256 }`
whose ordinal indexes an immutable bounded artifact/result vector transferred
with the same callback batch. Parent and save-configuration relationships use
typed ordinals and explicit absence, not handles or numeric-zero sentinels.
Artifact bytes remain behind application-owned roots and are published only
after digest/length validation. No callback value can later resolve a worker
object or extend a lease.

Handles cover `ctx`, `vars`, `props`, current/previous sampler,
current/previous result, thread, thread group, engine, sampler context, logger,
`OUT`, parent/save configuration, and provider-specific objects. They are
valid only in their worker/session/class-loader generation and cannot be
dereferenced or inferred by Rust. The helper asserts identities such as
`sampler == ctx.currentSampler`, `prev == ctx.previousResult`, and
`vars == ctx.variables`.

Binding values are typed:

```text
Null | Text | Bytes | Bool | I32 | I64 | F64Bits |
SecretReference | ObjectHandle | BoundedList | BoundedMap
```

An unsupported arbitrary Java value returns `script.context.unsupported`; it
is never stringified, silently removed, or hashed by `toString`. Handles have
finite active/run counts and leases and are released explicitly at scope end.

Secret references contain only opaque identity, provider digest, bounded
purpose, expiry budget, and rights. Secret bytes do not cross this protocol,
enter canonical digests, or appear in diagnostics. Resolution uses the
protected one-shot supervisor channel from Decisions 0001/0004; if unavailable
the capability fails closed.

## Complete result and delta projection

The bounded `SampleResultProjection` preserves absent versus empty and includes:

- label, response code/message, thread name, result filename, sampler data,
  request/response headers, data type/encoding, content type, URL/location;
- timestamp, start/end, elapsed, idle, pause, latency, and connect as signed
  values so invalid/negative wire input is preserved for validation;
- sample count, bytes, header/body sizes, sent bytes, group/all thread counts;
- success, stop-thread, stop-test, stop-test-now, ignore, and every distinct
  logical action including next iteration and break-current-loop;
- response bytes inline under the limit or as a length/digest-bound artifact
  handle; ordered assertion results; ordered recursive sub-results; file
  marks; parent/save-config handles; sub-result index; result object handle.

Assertion results preserve optional name/message plus independent failure and
error flags. Worker identity belongs to event metadata, not `SampleResult`.
Depth/node counts are validation data, not semantic fields. Derived Java
internals remain reachable only through an appropriate handle and are not
invented as serialized result data.

A transaction proposal contains its identity and operation, base snapshot
digest and generations, semantic outcome, ordered variable/property mutations,
typed handle creates/releases, a complete result patch, assertions and
sub-result mutation modes, ordered OUT and diagnostics, cache/class-loader
observations, rollback capability, canonical after-state digest, and proposal
digest.

The protocol has distinct canonical bodies and acknowledgements for
`Prepare`, `Prepared`, `Execute`, `Proposed`, `Commit`, `Committed`, `Abort`,
`Aborted`, `Poison`, and `Terminal`. Each carries the session, transaction,
operation, request/sequence, base/proposal/chain digests, expected and resulting
generations, finite remaining budget, and only the fields legal for that phase.
An `Execute` reply is either the closed `ExecutionReply::SemanticComplete` or
`BridgeFailure`; a generic `Result<T, E>` is not the execution wire contract.
Version 1 requests and encoders are rejected for execution before prepare.

Rust never mutates live context while validating a proposal. It first validates
all identities, bounds, unique keys, handles, operation rules, and complete
candidate state in separate bounded storage; recomputes the after-state digest
from the base plus proposal; and checks generation advance. Commit is one
replacement of a single versioned `ProjectedRunState` containing user context,
variables, run properties, current/previous results, event snapshots, the
handle ledger, output/diagnostic ledger, and class-loader/cache observations.
Generation overflow or a compare-and-swap conflict fails before replacement.
An implementation that stores run properties separately must instead use a
durable write-ahead journal with recovery proof and cannot acknowledge commit
until both records are atomically recoverable. Failure between records poisons
the run and may never return success. No earlier write, result mutation, or
sub-result append can survive a rejected proposal. This atomicity covers only
Rust's negotiated projection, never arbitrary JVM or external effects.

`Commit` carries the exact proposal digest and expected generations. `Abort`
carries transaction ID, proposal digest when present, and reason. Only
`NotExecuted` or a complete `Journaled` proposal may safely return to
`RunOpen`; an `Unsafe` rollback capability poisons the worker.

## Deadlines, cancellation, and sequencing

Rust owns one absolute monotonic operation deadline across queue admission,
supervisor setup, handshake, open, request write, Java execution, reply read,
validation, commit/abort, close, and cleanup. A wire message carries the
remaining budget sampled immediately before serialization plus an absolute
wall-clock deadline only for diagnostics/skew bounding. Process-local monotonic
values are never compared across processes.

The receiver caps a local monotonic timer by the received remaining budget and
the diagnostic wall deadline with at most the negotiated five-second skew
allowance. It may shorten but never extend the caller's budget. Every queue,
write, execution, cancellation wake, validation, and cleanup phase consumes the
same budget; a retry or phase cannot reset it. Production operations require a
finite deadline and have a 24-hour protocol maximum.

Cancellation identifies request and transaction and returns one of
`NotStarted`, `Interrupting`, `Stopped`, or `Poisoned`. Cancellation before
execution may abort cleanly. Once Java code may have run, timeout/cancellation
poisons the worker unless the complete journal proves safe rollback. Late
success cannot turn cancellation or timeout into success. No mutating
operation is automatically retried.

## Artifact, class-loader, and provider identity

The identity handshake binds:

- canonical profile ID/version/bytes/hash;
- closed helper `role` (`capability`, `rmi-controller`, `rmi-worker`, or the
  separately versioned HTTP role) and its role-specific `module_digest`;
- JMeter version/source commit/archive SHA-512 and the Apache signature
  verification state; exact execution remains unavailable while the active
  profile records `signature_verified: false`;
- absolute Java executable identity and SHA-256, vendor/version/VM/major,
  target and OS;
- helper source/build/compiler/schema identities;
- every ordered classpath entry with ordinal, role, handle-bound canonical
  path identity, content SHA-256, byte length, version/provenance,
  license/NOTICE state, dependencies, and class-loader role;
- ordered provider/plugin manifests and aliases with implementation classes,
  artifact ordinals/hashes, service-descriptor digest, capabilities, and
  class-loader generation;
- roots, sandbox/policy digests, locale, timezone, charset, environment/JVM
  option allowlist, and every negotiated limit.

Sharing `tools/jmeter-jvm-adapter/` source/build lineage never shares a JVM
process, static state, loader, session, handle table, transaction ledger, or
terminal state between roles. Frames and handles are role/module bound; a
capability session rejects RMI or HTTP module identities even when all common
source/build hashes match.

JMeter base classes, bundled engines, user classes, plugin components, and
dependencies retain their pinned loader roles. Cache and handle state never
cross a profile, helper, classpath, provider, run, or lifecycle generation.
ServiceLoader results precede scanned classes where pinned source does so;
observed enumeration and resolution order remain separately recorded rather
than globally sorted for convenience. Missing/broken providers and alias
collisions are retained as bounded observations.

For the pinned SaveService/provider alias table, discovery order is
authoritative: each valid later mapping for the exact alias replaces the
earlier selected mapping while every candidate and collision diagnostic
remains in the observation ledger. A malformed later entry does not erase the
last valid winner. Plugin-defined resolution that differs from this rule is
unavailable until its exact ordered policy is separately identified and
evidenced; neither Rust map order nor sorted order chooses a winner.

The bundled baseline includes BeanShell 2.0b6, Groovy JSR223 3.0.20, JEXL2
2.1.1, JEXL3 3.2.1, Rhino 1.7.14 for the JavaScript function, JMeter's Java and
JUnit sampler JARs, and JUnit 4.13.2. Exact per-artifact hashes come from
observed pinned provenance. Rhino's bundled function capability is not a
JSR223 provider unless a separate pinned provider is present.

## Pinned script cache and Java element lifecycle

The helper preserves pinned JMeter cache quirks rather than designing a new
cache:

- one static Caffeine cache has the resolved finite size, default 100;
- a nonempty file name wins and uses language, absolute path, and observed
  modification identity;
- inline caching is disabled only by exact case-sensitive `"false"`;
- eligible inline cache identity is the element's one-time MD5 of expanded
  source, computed once until test end; it does not include language, engine,
  class loader, or run;
- BeanShell is excluded from compiled reuse even when `Compilable`;
- test end invalidates the static cache and clears the element MD5.

One-worker-per-run intentionally isolates cross-run static cache state. That
is not claimed identical to reusing a JMeter JVM across runs until the pinned
oracle matrix proves the selected deployment lifecycle.

JavaSampler owns one client instance per sampler clone/user. It loads at test
start, initializes lazily, calls setup once, constructs a fresh
`JavaSamplerContext` for every sample, replaces the stored context, calls run,
and tears down with the most recent context through the pinned identity
registry. Ordered arguments retain insertion order and first duplicate-name
value. A null result skips downstream phases. Arbitrary instance/static state
remains JVM-authoritative.

JUnit3 and JUnit4 are distinct modes. Default lifecycle creates one test object
per user/thread; `createOneInstancePerSample=true` creates one per invocation.
Constructor selection, setup before `sampleStart`, teardown after `sampleEnd`,
assertion/error mapping, configured codes/messages, and failed initialization
follow pinned source and oracle evidence. Setup/teardown remain outside measured
sample time.

## Files, diagnostics, and containment

Plan/include/data/script/user-class/plugin/JMeter-home/preferences/log/result/
temporary roots are explicit handle-bound capabilities. Traversal, symlink,
junction/reparse, device, alternate-stream, hard-link, case/Unicode alias, and
parent-swap attacks fail closed. File identity is revalidated at consumption.

Scripts, variables, properties, classpaths, exception text, raw OUT, and
plugin data are sensitive. Ordinary errors retain stable codes, identities,
counts, and digests only. Private raw diagnostics are bounded, access-limited,
and rejected from evidence if secret scanning fails. No secret, script source,
raw request/result payload, or classpath path appears in ordinary `Debug`,
logs, metrics, argv, environment, manifests, or evidence.

Before any user element can execute, the supervisor binds the operating-system
stdout and stderr descriptors/handles to separate bounded capture pipes, then
the helper replaces `System.out`/`OUT` with the stdout capture stream. Thus
direct writes through `FileDescriptor.out`, a stream retained before
`System.setOut`, and ordinary native stdout still reach the same bounded OS
capture. Framing uses a third inherited protected descriptor/handle and cannot
share stdout or stderr. The exact inherited-handle allowlist is part of helper
identity; duplicate/redirect/reopen attempts outside it are containment
violations. Capture records binary chunks with ordinals and a digest; no string
conversion happens before the byte budget is enforced. Overflow after Java may
have started is a `BridgeFailure { may_have_executed: Yes }` and poisons the
worker. Code able to escape the capture through native descriptor duplication
is unavailable unless the external sandbox independently prevents it.

Run properties/bindings carry a secret-taint bit derived from the application
secret registry. A tainted value is never encoded in `ContextSnapshot`, OUT,
diagnostics, a digest, or an event; Java receives it only through a purpose-
bound opaque handle/protected channel. Taint validation covers every outbound
surface: response/request bodies and headers, sampler data, result filenames,
assertion names/messages, recursive subresults, selected variables, result and
artifact handles, file marks, callback/event snapshots, plugin/provider output,
exception text and causes, OUT/stderr, and private diagnostic artifacts.
Before canonical encoding, each value is classified `Public`, `Sensitive`, or
`SecretReference`; only public bytes may be content-hashed.

Bridge-owned adapters propagate the taint ID through every value constructed
from a resolved secret and refuse publication. Captured and projected bytes
are additionally scanned incrementally for the registered exact value and the
bounded canonical encodings declared by its provider before entering any
ordinary ledger. A match quarantines the private artifact and poisons an
already-executed operation. Arbitrary Java/plugin code that must receive secret
bytes but cannot participate in this taint contract is a named unavailable
capability; fingerprint scanning alone is not claimed to prove arbitrary
derived-secret noninterference. Reassigning `System.out`, replacing the capture
stream, writing protocol bytes to it, or bypassing the OS capture is a bridge
integrity failure.

Each Java/RMI callback captures its complete bounded result projection and
selected-variable snapshot at callback invocation, before any later listener
can mutate the live result. The final result graph is separately captured after
the whole authority region. Callback snapshots therefore remain ordered
observations and are not reconstructed from the final graph.

Every worker uses `ProcessTree` and the useful-work gate from Decision 0001.
No JVM worker is enabled until the shared supervisor and caller migration pass
independent safety audit on that platform. Untrusted scripts/plugins/classes
also require independently tested CPU, memory, thread, filesystem, and network
containment. Without it only the trusted pinned fixture corpus may execute.

## Bounds and errors

Negotiated maxima cover complete frame/body/field/extension sizes, fields,
text, script source, result depth/nodes/data/assertions/file marks, variables,
properties, object handles and leases, value-tree depth/nodes, diagnostics,
OUT chunks/bytes, classpath/provider/plugin entries and metadata, aliases,
operations/session, replay cache, and operation/close time. Schema v2 protocol
maxima are finite; a session may negotiate lower, never higher. Any excess
rejects the whole operation without truncating semantic data.

Stable error families include:

```text
bridge.protocol.version/phase/sequence/digest/unknown-field/unknown-operation
bridge.limit/deadline.exceeded/cancelled/worker.crashed/containment-lost
bridge.worker.poisoned/transaction.invalid/transaction.conflict
bridge.transaction.abort-unsafe/handle.invalid/context.stale-generation
script.engine.unavailable/source.unavailable/configuration.invalid
script.classpath.unavailable/class.unavailable/class.contract-invalid
script.context.unsupported/value.type-unsupported/evaluation.failed
script.secret.denied/plugin.classpath.unavailable/plugin.alias.ambiguous
plugin.class.unavailable/plugin.element.unavailable/plugin.function.unavailable
bridge.classpath.identity-mismatch/bridge.provider.identity-mismatch
sandbox.denied
```

Human exception text is bounded sensitive diagnostic context, not a
compatibility key. The original JMX node, raw properties, and subtree remain
preserved after every error.

## Verification requirements

Pure tests cover exact golden wire vectors; canonical digest/sequence chains;
every operation/message/phase; absent/null/empty values; unknown strict and
negotiated extension fields; duplicates/truncation/trailing bytes; all
count/byte/depth boundaries; full signed result projections; handle rights,
lease, identity, and stale generation; prepare/propose/commit/abort; candidate
state atomicity including generation overflow; terminal uniqueness; deadline
budget monotonicity; cancellation poisoning; cache/provider/classpath identity;
and redacted diagnostics. Property tests cover canonical encode/decode and
state-machine invariants. Fuzz targets decode bytes/state transitions only and
never start a process, JVM, or script.

Mock-worker tests cover partial frames, backpressure, crash, timeout,
cancellation at every phase, invalid/partial proposal, semantic Java failure,
poisoning, restart rejection, cache epochs, class-loader changes, handle leaks,
and bounded stdout/stderr. They cannot establish Java compatibility.

External differential evidence runs the exact signed JMeter artifact under
separately recorded Java 8 and Java 17 rows. It covers:

- all external functions with argument escaping, phase expansion, side
  effects, and error paths;
- every JSR223 live binding and object-identity assertion; live result and
  listener mutation; checked/swallowed/runtime exceptions; null results;
- inline/file cache identities and quirks, exact `false`, BeanShell exclusion,
  cache eviction and cross-run behavior;
- positive/negative JavaSampler and JUnit3/JUnit4 classes and exact lifecycle;
- plugin/service/scanned discovery ordering, dependencies, aliases, missing and
  duplicate classes/functions, and opaque subtree preservation;
- worker crash, deadline, cancellation, output/handle limits, redaction,
  containment, and zero leaked processes/handles/files.

Every positive plugin or user-class fixture pins original source/artifact,
version, hash, license, NOTICE, dependencies, and redistribution decision. Raw
oracle artifacts remain outside Git. Static fixture checks, Rust tests, schema
implementation, helper compilation, or a mock worker cannot promote a profile
row.

Acceptance after implementation includes:

```text
cargo fmt --all -- --check
cargo test -p jmeter-rs-bridge-protocol --all-targets --locked
cargo test -p jmeter-rs-java-bridge --all-targets --locked
cargo clippy -p jmeter-rs-bridge-protocol -p jmeter-rs-java-bridge \
  --all-targets --all-features --locked -- -D warnings
cargo run --locked -p xtask -- profile-check
cargo run --locked -p xtask -- fixture-check
python3 .github/scripts/check-process-supervision-migration.py
```

Release conformance additionally requires pinned-JMeter Java 8/17, fuzz,
cross-platform worker lifecycle, security, performance, and soak/leak lanes.
An unavailable artifact, signature, JVM, engine/plugin, sandbox, supervisor,
or external lane is a named missing capability, never a pass.

## Consequences

Full-profile compatibility includes an explicit JVM dependency for these
surfaces. The exact path keeps the whole Java-owned unit authoritative rather
than pretending a Rust delta can undo arbitrary JVM effects. The restricted
projection path remains useful only where its bounded journal can be proven.
This adds IPC and operational cost but makes uncertainty, object identity,
classpath state, and failure semantics explicit.
