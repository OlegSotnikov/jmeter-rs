# Decision 0004: pinned Java RMI compatibility adapter

Status: accepted architecture, revision 4; implementation and external evidence pending  
Date: 2026-08-13  
Compatibility features: `CLI-001`, `CLI-002`, `CLI-003`, `CFG-001`,
`DIST-001`, `DIST-002`, `DIST-003`, `DIST-004`, `TEST-002`, `TEST-004`  
External boundaries: `EXT-JVM-001`, `EXT-RMI-001`, `EXT-TLS-001`,
`EXT-OS-001`

## Context

Apache JMeter distributed execution uses Java RMI object serialization,
registry bindings, JMeter engine classes, SSL socket factories, reverse result
callbacks, and Java `SampleSender` implementations. Matching sample counts over
a Rust protocol is not Java RMI compatibility. The project already has a
Rust-native remote protocol, which is valuable for Rust deployments but cannot
be advertised as JMeter RMI wire compatibility.

The pinned JMeter behavior sends the complete prepared plan to every selected
worker. Each worker executes the whole plan, so thread counts multiply by the
number of workers. Data files, scripts, drivers, plugin JARs, certificates, and
other dependencies are not transferred. `-r`, `-R`, `-G`, `-X`, retry and
continue-on-failure properties, RMI ports, SSL, stop behavior, and sample sender
modes are all observable contracts.

## Decision

Java RMI compatibility is implemented by a small original Java helper compiled
against and executed with the exact pinned Apache JMeter 5.6.3 distribution.
The helper invokes pinned public/package APIs directly; it does not reimplement
RMI serialization in Rust and does not use reflection to mask API drift. The
helper has two explicit roles:

- `controller` owns JMeter's `DistributedRunner` and `ClientJMeterEngine`
  paths, plan serialization, global-property propagation, retries, listener
  callbacks, stop, and remote exit;
- `worker` owns `RemoteJMeterEngineImpl`, its registry binding, worker-local
  `FileServer`, `StandardJMeterEngine`, and Java sample-sender behavior.

The RMI and scripting/plugin paths use one JVM-adapter source package under
`tools/jmeter-jvm-adapter/`, with role-specific modules. Shared source/build
lineage does not mean shared JVM state. Every `capability`, `rmi-controller`,
and `rmi-worker` role has a distinct JVM process, schema/session, role and
module digest, class-loader instance/generation, object-handle table,
transaction ledger, Java static state, and terminal outcome. Decision 0005 is
the authority for each immutable class-loader generation, ordered classpath
manifest, plugin/user-class discovery, and JVM lifecycle. RMI execution and
Java elements within one process use that process's generation; frames,
handles, result events, or terminal state never cross roles. A second JVM with
a merely similar classpath cannot stand in for the same Java static, cache, or
object state. Shared code is limited to manifests, identity checks, root/secret
capabilities, and lifecycle utilities.

Rust owns CLI/config validation, capability negotiation, private roots,
worker-local staging, port and secret policy, process ownership, bridge bounds,
deadlines/cancellation, event normalization, result routing, and final status.
It does not call `JMeter.main` as the bridge session: CLI-owned process exit and
unstructured logs are retained only as a separate differential oracle route.

The Rust-native `crates/remote` protocol remains independently named and
versioned. JMeter-compatible `-r`, `-R`, `-G`, `-X`, and server mode select this
RMI adapter. A Rust-native mode requires a distinct explicit option/capability;
there is no fallback between the two after launch.

## Source, build, and identity

Original helper source lives under `tools/jmeter-jvm-adapter/` and is licensed
as project code. Generated classes/JARs, JMeter distributions, keystores, and
raw run output remain outside Git. A reproducible build uses an absolute,
identity-checked Java compiler, a clean environment, a fixed source encoding,
stable archive ordering/timestamps, and the exact ordered JMeter classpath.

The generic transport hello is followed by a role-bound identity exchange:

```text
TransportHello
  -> RmiIdentityHello
  -> RmiIdentityAck
  -> StageManifest / StageAck
  -> Ready
  -> Configure
  -> Start
  -> callback stream
  -> Stop / Drain
  -> optional RemoteExit
  -> Terminal
```

Before useful execution, `RmiIdentityHello` binds:

- protocol, operation-schema, event-stream, preservation, and secret-channel
  versions;
- a fresh run/session ID, worker ID, role, lifecycle generation, nonce, and
  transcript digest so a stale helper cannot attach to another run;
- profile ID/version and canonical profile SHA-256;
- JMeter archive SHA-512, source commit, Apache signature-verification state,
  and every ordered classpath member SHA-256; exact execution is unavailable
  while the active profile records `signature_verified: false`;
- helper source/build SHA-256 and Java compiler/runtime vendor and version;
- role, worker ID, jmeter-rs commit, platform profile, OS and target;
- plugin/driver identity, version, hash, license, NOTICE, and classpath order;
- complete ordered classpath entries with their roles and one aggregate
  classpath digest, including manifest `Class-Path` expansion and runtime
  modules as defined by Decision 0005;
- controller and worker root identities plus the staging-manifest digest;
- every negotiated registry, engine, client, and callback endpoint; advertised
  hostname; TLS mode/provider and peer certificate fingerprints; exact sender
  mode and sender properties;
- queue/message/output limits, locale, timezone, charset, sandbox identity,
  required capabilities, and offered capabilities.

The acknowledgement covers the nonce and canonical transcript. Rust compares
the complete observed identity with the expected manifest; capability
selection is exact and required capabilities must all be present. Set
intersection is not permission to downgrade TLS, sender, class-loader, or
callback behavior. Any mismatch fails before plan transfer. Ambient JAR
discovery is forbidden. The helper source may reference upstream APIs but must
not copy Apache source.

The canonical helper wire is `rmi-bridge/3` inside the shared 16 MiB frame.
Its fixed big-endian envelope binds role/module, session/run/worker/lifecycle
generation, message kind, phase, nonzero request ID, per-direction sequence,
finite remaining nanoseconds, cancellation, body length/SHA-256, previous
chain, and chain SHA-256. Known TLV tags increase strictly; duplicate, unknown
strict, trailing, over-limit, zero-duration, digest, transcript, role, or
generation mismatches fail before execution. Closed controls are exactly
`IdentityHello/Ack`, `StageManifest/Blob/Ack`, `Ready`, `Configure/Ack`,
`Start/Ack`, `CreditGrant`, callback events, `EventAck`, `WorkerFailure`,
`Stop/Ack`, `SenderDrainProof`, `Drain/Ack`, `RemoteExit/Ack`, and `Terminal`.

`BridgeIdentityV3` contains every identity item above; a shorter generic
profile/artifact tuple is invalid. `Ready` carries the selected `RmiLimits`,
complete stage-manifest digest, root/classpath/TLS/sender digests, and zero
pending work. Each staged entry binds logical ID, kind, authorized root slot,
rights, length, SHA-256, and blob ordinal; no ambient path is a stage identity.
`ConfigureAck` and `StartAck` separately state admitted/not-admitted plus the
resulting generation and canonical configuration/start digests, allowing Rust
alone to prove the pre-start retry boundary.

## Bridge sessions and streaming

The bounded bridge protocol gains a versioned stream operation; an ordinary
request/response frame is not treated as an unbounded event channel. Control
request IDs, transport-frame sequence numbers, and callback-event ordinals are
three separate identity domains. Every stream has a run/session ID,
role/worker ID, lifecycle generation, sender identity, and exactly one terminal
frame.

The helper preserves the callbacks that the selected pinned
`SampleSender` actually delivers to `RemoteSampleListener`; it does not invent
an idealized sampler lifecycle. Callback-invocation order and delivered-event
order are separate domains. The closed callback set is:

```text
TestStarted { overload, host_presence, callback_invocation_ordinal }
SampleStarted { callback_invocation_ordinal, delivered_event_ordinal,
                sample_id, event }
SampleOccurred { callback_invocation_ordinal, delivered_event_ordinal,
                 sample_id, event }
ProcessBatch { callback_invocation_ordinal, first_delivered_event_ordinal,
               batch_id, nonempty_ordered_events }
SampleStopped { callback_invocation_ordinal, delivered_event_ordinal,
                sample_id, event }
TestEnded { overload, host_presence, callback_invocation_ordinal }
```

`LifecycleOverload` is exactly `NoHost` or `HostArgument`. `NoHost` requires an
absent host. For the pinned `String` overload, `HostArgument` rejects absent;
it preserves present-empty, and permits null only after an oracle/source case
proves that exact call. The helper records which Java overload ran; it never
fills a missing host from worker identity. `TestEnded` carries no invented
outcome field—the Java callback has none; adapter outcome classification lives
only in the terminal. `ProcessBatch` is a first-class callback invocation, not
synthetic repeated `SampleOccurred` calls. Its invocation ordinal advances by
one, while its delivered-event ordinal advances by the number of items.

`SampleEventSnapshot` contains the notification-time host, thread/group
identity, selected variables, transaction-event state, and the complete
bounded `SampleResult` projection carried by that `SampleEvent`: hierarchy,
assertions, timing fields, byte
counters, request/response metadata and data, encoding, filenames, URLs,
thread counts, stop flags, and sub-results. Absent and present-empty fields are
distinct. A null/missing result is legal only if a pinned source/oracle case
proves that callback form; otherwise it is `rmi.stream.invalid-sample-event`.
Rust never reconstructs an event from later mutable state.

`sampleStarted`, `sampleOccurred`, and `sampleStopped` are tracked independently.
A sender mode may deliver only a subset; absence is not filled with a synthetic
callback. Duplicate callback identities and duplicate phases for one identity
fail the stream. Arrival order is retained separately from sample execution
identity. `TestStarted` and `TestEnded` retain the callback host.

A transport frame increments `frame_sequence` once. An event batch is nonempty
and declares one callback-invocation ordinal,
`first_delivered_event_ordinal`, and `event_count`; item event ordinals are
derived and contiguous. Callback state advances by one and delivered-event
state advances by `event_count`. A batch may not mix run, worker, generation,
or sender identities. Empty, gapped, replayed, or overlapping ordinals in
either domain are protocol errors.

The wire also has control events:

```text
Ready | ConfigureAck | StartAck | CreditGrant | EventAck |
WorkerFailure | StopAck | SenderDrainProof | DrainAck |
RemoteExitAck | Terminal
```

Credits are two-dimensional `(event_count, encoded_bytes)`. The helper reserves
both before enqueueing a callback. Rust releases credit only after it has
validated the complete event and the run-owned result router has accepted it.
Exhaustion waits only until the run's existing deadline or produces
`rmi.stream.queue_full`, initiates bounded stop/drain, and fails the run. No
callback is dropped or treated as successful because a queue is full.

`EventAck` carries the worker, generation, highest contiguous delivered-event
ordinal, newly accepted event count, newly accepted encoded bytes, cumulative
accepted event/byte counts, and router-admission digest. It never acknowledges
only a transport frame. Direction and ownership are closed by message type:
only Rust grants/replenishes credit and acknowledges admission; only the helper
consumes credit and emits callbacks. Counts, bytes, and ordinals must all agree
or the stream fails.

Each credit reservation follows the closed ledger
`Available -> ReservedByHelper -> FrameReceived -> Validated ->
RouterAccepted -> Acknowledged -> Replenished`. Event and byte dimensions move
together using checked arithmetic. Validation failure, router rejection,
cancellation, or stream failure transitions the reservation to an accounted
non-success terminal and never replenishes it as accepted credit. The
router-admission digest binds worker/generation, every contiguous event ID and
complete immutable payload digest, accepted counts/bytes, and the result-router
generation. Delivered and accepted are never advanced by the same implicit
assignment; only the explicit router result advances acceptance.

No field is silently truncated. A field, body, plan, or hierarchy beyond a
negotiated limit fails with a stable resource error. Large bounded blobs use
an explicit begin/chunk/end stream with total length and SHA-256; no chunk may
exceed the negotiated message size, a partial blob is never exposed, and its
aggregate reservation is acquired before the first chunk. Unknown fields are
accepted only under an explicitly negotiated preservation version; otherwise
the handshake or message fails.

`RmiLimits` is mandatory in every session and records separate maxima for
frame/message/metadata bytes, total plan/blob bytes, total stream events and
bytes, in-flight samples, batch events and bytes, result depth/nodes/body bytes,
properties and key/value bytes, classpath/root entries and path bytes, disk
sender bytes, diagnostics, stdout/stderr, retries, retry delay, and total
operation duration. The bridge's compile-time frame ceiling is 16 MiB and its
default per-message ceiling is 1 MiB; an RMI session may negotiate only equal
or smaller frame values. Every other limit has a checked protocol maximum and
an explicit manifest value—zero or omission is not an unbounded default.

`RemainingDuration` is a nonzero `u64` count of nanoseconds rounded down at
send time and capped at 24 hours; no `NONE`, zero, negative, wall-clock, or
process-local monotonic sentinel is legal. The receiver creates an earlier-or-
equal local monotonic deadline with checked arithmetic. Every retry, control,
callback, drain, remote-exit, and cleanup phase consumes the same parent
deadline.

The helper-to-Rust queue and every per-stream byte budget are finite. A full
queue is a typed run failure that initiates bounded stop/drain; it is never a
silent sample drop. JMeter's own asynchronous sender queue remains separate.
Terminal success is published only after all accepted events and the JMeter
end callback have crossed the bridge. Cancellation and EOF cannot become a
successful terminal state.

Rust owns the one authoritative monotonic operation deadline. Wire messages
carry only the remaining duration at send time plus diagnostic wall time;
monotonic clock values are never compared across processes. A receiver creates
a local deadline no later than that remaining duration, while Rust still stops
accepting success at its original deadline. Queue admission, staging, RMI
calls, callbacks, validation, drain, remote exit, and cleanup do not reset the
budget.

## Controller and worker contract

The controller receives bounded JMX bytes, their SHA-256, a logical script/base
token, an ordered effective local property view, an effective global `-G` map,
selected workers, sender configuration, and limits. Blob transfer is complete
and hash-verified before the plan becomes visible. It loads the JMX into a
JMeter `HashTree`, then uses pinned engine classes to configure and start the
selected workers.

CLI/config projection is typed and source-aware:

- `-r` uses the effective `remote_hosts` property;
- `-R` replaces that list and never merges with it;
- `-G` contributes only to the effective global map sent by JMeter's global
  property path; `-Gname=` retains the pinned file-versus-assignment meaning;
- `-J` remains local JMeter properties and is not promoted to workers;
- `-D` remains local JVM/system properties except for settings explicitly
  decoded into typed worker/RMI configuration;
- `-X` requests remote exit only after the required callback and drain policy;
- `-s` starts the pinned worker role without a test plan.

`RmiConfig` retains each value's source and covers remote hosts, registry,
engine/client/callback ports, advertised hostname, SSL/stores/providers,
`client.tries`, retry delay, continue-on-failure, sender mode and thresholds,
queue/disk limits, `server.exitaftertest`, and stop policy. Duplicate/removal
and source precedence are resolved before the bridge and checked by worker-side
probes. An unknown property remains available to the pinned Java path or causes
a typed unsupported-property result; Rust never silently ignores it.

Each worker receives the full plan through Java RMI, with the pinned script and
base metadata. It resolves files and classes only from its own declared root
and classpath. No bridge or controller fallback supplies a missing CSV file,
script, JAR, key, certificate, or plugin. Client decoys are tested explicitly.
A missing worker-local resource is a worker failure with preserved identity,
not a fabricated sample or local execution.

Rust-owned fixture workers have predeclared, handle-validated roots. Their
`StageManifest` lists every worker-local input and its hash before `Ready`;
staging is complete before configure and never occurs as a missing-file
fallback. Standard operator-managed JMeter servers remain interoperable RMI
peers, but Rust cannot attest their process, roots, or classpath through stock
RMI. They therefore require an operator-supplied manifest and authenticated
network policy and cannot be used as conformance evidence unless an external
attestation matches the complete expected identity.

The adapter uses JMeter's retry implementation exactly. It does not wrap
non-idempotent configure/start calls in a second Rust retry loop. Pinned
`client.tries=3` means three total attempts; the configured retry delay occurs
between them. With `continue_on_fail=false`, a remaining failed worker fails
the run and stops configured peers. With it true, execution continues only if
at least one worker is healthy, while every failed worker remains observable.
Each pre-start retry has a fresh request ID and lifecycle generation and
consumes the same operation deadline. A configure/start result with unknown
outcome is not retryable, and no worker JVM is silently replaced after useful
execution begins.

Retryability is a closed disposition, never a peer-controlled boolean:

```text
RetryDisposition = PreStartSafe { reason, next_attempt } |
                   FinalNonRetryable { phase, outcome_certainty } |
                   PoisonedUnknownOutcome
```

Only Rust may derive `PreStartSafe`, and only while the state machine proves
that configure/start useful work did not begin. A helper `WorkerFailure` can
report observations but cannot authorize a retry. After configure admission,
start admission, any callback, or any unknown outcome, retry is impossible.

## Ports and network isolation

Every endpoint is explicit. For `N` Rust-owned workers and worker index
`i in 0..N`, the fixture topology is:

```text
worker registry i     = base + i
worker engine i       = base + N + i
client.rmi.localport  = base + 2N
controller callback i = base + 2N + 1 + i
fixture stop control  = base + 3N + 1
```

The stop-control endpoint is fixture-only and is not presented as a production
JMeter RMI endpoint. For `N=2` this preserves offsets `base+0` through
`base+7`. `N`, every addition, the full inclusive port range, uniqueness, and
endpoint cardinality are validated before Java side effects.

Conformance fixtures bind only loopback and set
`java.rmi.server.hostname=127.0.0.1`. A private network namespace or equivalent
exclusive CI network boundary removes competing binders. Merely probing and
releasing ports is not called a reservation. A platform-specific socket
activation design may claim atomic reservation only after the pinned RMI
socket factories demonstrably adopt the exact prebound sockets. Otherwise the
isolated namespace is the conformance mechanism. Without isolation,
production accepts operator-specified ports and reports bind conflicts; it may
retry a fresh block only before any configure/start side effect and within the
same deadline.

RMI deserialization is not exposed to an untrusted network. Non-loopback use
requires mutual authenticated TLS with certificate pinning, an explicit
firewall/network-sandbox capability, an allowlisted peer set, a declared
advertised hostname/address, and recorded risk acceptance. No public listener
or ambient hostname is selected by default.

## TLS and secrets

JMeter's pinned default RMI SSL behavior is preserved. Plain mode explicitly
sets the documented disable property on every participant; TLS failure never
falls back to plain transport.

TLS mode uses per-run generated JKS material with separately staged controller
and worker identities. Keystore/truststore type, handle-bound file identity,
aliases, provider, certificate fingerprints/validity, and keytool/runtime
versions are recorded. Secret values are represented outside the JVM only as
opaque `SecretRef { provider_id, secret_id, purpose, one_shot }` capabilities.
An application-owned `SecretProvider` resolves a reference only after process
ownership and the identity handshake are established and immediately before
the Java TLS/RMI object is constructed.

Secret transfer is a distinct supervisor-owned OS capability: a one-shot,
length-delimited record is supplied through an already installed inherited
Unix descriptor or Windows handle. The record is bound to the run, lifecycle
generation, purpose, peer identity, and handshake transcript. The handle has
one exact owner and is included in supervisor cleanup accounting. Secret bytes,
secret-bearing paths, and provider internals never enter argv, ordinary
environment variables, property maps, bridge metadata, logs, diagnostics,
manifests, or evidence. Only an opaque capability slot may appear in a typed
native launch specification; it is never stringified for a shell or generic
`Command`. The helper reads the record once, closes the capability, and clears
temporary buffers where practical. A protected backing object is unlinked
after opening on Unix; Windows uses a private ACL and delete-on-close semantics.
The JVM's unavoidable in-memory password/property lifetime is documented.

Known password, token, keystore-password, and private-key properties, plus keys
explicitly classified as secret by the application, are removed from ordinary
`-G`/`-D` maps and replaced by purpose-bound secret references. The helper may
populate the corresponding Java property only from that reference. An
unclassified value which is required to be secret is a typed configuration
failure, not a redacted ordinary value. If the target platform or process
supervisor cannot install and account for the protected channel, the adapter
returns `rmi.secret_channel.unsupported`; it never falls back to a pathname,
argv, or environment transfer. Secret-bearing errors cross only as stable
redacted codes.

Missing stores, wrong aliases/passwords, untrusted certificates, hostname or
TLS/plain mismatches, and provider differences fail closed. Keytool execution,
when needed, uses the shared process supervisor and its isolated capability;
no shell script or ambient `PATH` lookup is used.

## Sample sender modes

Sender behavior remains in the exact pinned JMeter classes. The adapter sets
properties and observes callbacks; it does not substitute a Rust sender in the
RMI path. The factory aliases, compared case-insensitively without trimming,
are exactly:

- `Standard`, `Batch`, `Statistical`;
- `Stripped`, `StrippedBatch`;
- `Asynch`, `StrippedAsynch`;
- `DiskStore`, `StrippedDiskStore`.

The default is `StrippedBatch`. An unknown value takes the pinned
`Class.forName` path and must expose a public constructor accepting
`RemoteSampleListener`; lookup, constructor, construction, and cast failures
remain distinct pinned failures wrapped by the factory. The core JAR contains
`HoldSampleSender`, but `Hold` has no factory alias and its listener constructor
is package-private. Consequently both `Hold` and its core FQCN are unsupported
in this pinned distribution; a separately pinned custom provider with the
required public constructor is a distinct manifest-bound capability.

`sample_sender_client_configured=true` selects client-supplied sender
properties; false selects the corresponding server-side thresholds/queue/
strip properties while the mode itself remains client-resolved. The pinned
defaults and disabling values are preserved exactly, including
`num_sample_threshold=100`, `time_threshold=60000`,
`key_on_threadname=false`, `asynch.batch.queue.size=100`, and
`sample_sender_strip_also_on_error=true`.

Batch boundaries and delivery kind (`sampleOccurred` versus `processBatch`) are
observable and retained. Batch/end flush, stripping, statistical grouping,
order, disk cleanup, queue pressure, callback failures, and response-data
behavior require mode-specific oracle evidence. Pinned Java sender internals
are not uniformly bounded or no-drop: their logged loss/block/failure behavior
is itself compatibility data. The bridge's bounded no-drop guarantee begins
only after a callback enters the helper and must not be misreported as a Java
sender guarantee. The Rust-native sender implementation may share neutral
result tests but cannot prove these Java sender rows.

`SenderDrainProof` is a positive, mode-specific helper observation containing
sender identity, lifecycle generation, final delivered-event ordinal,
cumulative emitted/accepted/acknowledged event and byte counts, pending queue
and disk counts, completion-hook identity, and proof digest. Standard,
batch/statistical, stripped, and disk modes each require a source-reviewed hook
that observes their actual completion boundary. For `Asynch` and
`StrippedAsynch`, the pinned `TestEnded` callback occurs before the final
sentinel is consumed and the daemon is not joined. Therefore those two modes
remain `rmi.sender.drain-proof-unavailable` until a separately reviewed pinned
helper integration point can positively observe sentinel consumption and
sender-thread termination. Delay, queue-size polling, EOF, `TestEnded`, or
quiescence is never proof. The ADR does not authorize a guessed hook.

The wire union is closed:

```text
SenderDrainProof =
  Proven { mode, helper_role, module_digest, lifecycle_generation,
           reviewed_hook_capability_digest, final_delivered_event_ordinal,
           cumulative_counts_and_bytes, pending_queue: 0, pending_disk: 0,
           proof_digest }
| Unavailable { mode, helper_role, module_digest, lifecycle_generation,
                reason }
```

`Proven` is valid only when the exact mode/hook capability was negotiated in
the identity transcript, the hook digest is on the profile's reviewed
allowlist, and the final ordinal/counts match the callback and acknowledgement
ledgers. A `Proven` record for `Asynch`/`StrippedAsynch` is rejected until that
specific reviewed capability exists; arbitrary hook text is never identity.
Success requires `Proven`. Every non-success terminal carries `Unavailable`
with a closed reason rather than omitting or guessing proof.

The stream lifecycle includes
`Running -> TestEndedObserved -> DrainingAfterTestEnded -> Drained`. Ordinary
modes may reach `Drained` directly when their reviewed hook proves completion.
Only a negotiated sender-specific late-callback rule may accept callbacks in
`DrainingAfterTestEnded`; they must use the same generation, contiguous next
ordinals, reserved credit, and expected callback kind before the final proof.
For the current profile no Asynch late-drain hook is accepted, so those modes
fail capability negotiation before useful execution. This state exists so a
future reviewed hook can model the pinned final post-`TestEnded` batch without
misclassifying it as a frame-after-terminal error.

## Stop, shutdown, and failure

Control mapping is exact and typed:

- graceful shutdown calls `DistributedRunner.shutdown` / `stopTest(false)`;
- immediate stop calls `DistributedRunner.stop` / `stopTest(true)`;
- `-X` calls `DistributedRunner.exit` / remote `rexit` only after the run's
  required result delivery policy;
- a process-supervisor kill is last-resort cleanup after a deadline, never a
  semantic substitute for any of those operations.

Graceful stop waits for the pinned sender and test-ended callback within its
deadline. Immediate stop has its own expected delivery contract. Primary run,
worker, bridge, sender-drain, teardown, and process-cleanup errors are retained
as bounded structured fields; one does not overwrite another. No placeholder
sample represents a failed worker.

Cancellation state is monotonic and idempotent:

```text
none -> graceful -> immediate
none -> timeout
```

Once immediate cancellation or timeout is observed, success is impossible.
Graceful cancellation may succeed only when the actual `TestEnded`, the
sender-mode-specific completion proof, all accepted callbacks and blobs, all
acknowledgements, and all sender/bridge queues have completed without a worker,
queue, bridge, cleanup, or containment error. `TestEnded` alone is not a drain
proof for `Asynch`: the pinned sender calls it before enqueueing its final
sentinel and does not join its daemon worker. The adapter must obtain a positive
mode-specific completion observation from its pinned integration point; it may
not infer drain from delay or quiescence. Immediate and timeout paths always
produce their own non-success terminal outcomes even if late callbacks arrive.
A failed worker stops normal event admission; healthy workers continue only
when the resolved `continue_on_fail` policy permits it.

Every worker stream emits exactly one terminal frame. Its outcome is closed:

```text
Succeeded {
  test_ended_callback, sender_drain_proof, last_callback_invocation,
  delivered_events, accepted_events, acknowledged_events,
  delivered_bytes, accepted_bytes, acknowledged_bytes,
  pending_bridge_events: 0, pending_sender_events: 0,
  pending_blobs: 0, router_finalization_digest, remote_exit_state
}
Failed | Cancelled | TimedOut | Crashed | Aborted | ProtocolError {
  test_ended_absence_reason, sender_proof_absence_reason,
  last_frame_sequence, last_callback_invocation, last_delivered_event,
  delivered/accepted/acknowledged counts and bytes,
  pending counts, primary_error, bounded_secondary_errors
}
```

The stream state has explicit `Failed`, `Cancelled`, `TimedOut`, `Crashed`,
`Aborted`, and `ProtocolError` phases. `Aborted` is legal only before
configure/start admission with a Rust-owned non-execution proof;
`ProtocolError` records the violated frame/phase/identity rule and is poisoned
when useful work may have begun. `WorkerFailure` transitions into the matching
non-success state and is rejected after a terminal. Only `Succeeded` requires
and permits a positive success proof. For every
success, delivered, accepted, and acknowledged event and byte totals agree,
the sender and bridge queues are empty, all blobs are complete, the result
router has finalized, and `TestEnded` plus `SenderDrainProof` identities match
the same generation. No missing field defaults to zero or success.

EOF before terminal,
duplicate terminal, a terminal with unaccounted accepted events, or any frame
after terminal is a protocol failure. A successful terminal requires the
actual end callback and the completion proof above. A failed, cancelled,
timed-out, crashed, aborted, or protocol-error terminal may omit `TestEnded`
only when it records the explicit absence reason and the required
`SenderDrainProof::Unavailable`. Bounded primary and secondary errors retain run,
worker, bridge, sender, teardown, and cleanup failures without overwriting one
another. A failure after configure/start or with an unknown execution outcome
is not retryable and cannot be replaced by a new JVM inside the run.

Every controller and worker JVM occupies a process-global supervisor slot with
the sealed `ProcessTree` purpose. Java/RMI launch remains locked until Decision
0001 and all three caller migrations pass independent safety audit on the
target platform. Stdout is bridge framing only; logs/stderr are bounded and
redacted. All normal and fatal paths request semantic stop where possible,
then bounded exact cleanup and reap. `ShutdownIncomplete` prevents success.

The RMI launcher accepts a `PreparedProcess<RmiRole>` only for bounded setup
hello and identity/transcript traffic permitted by Decision 0001. It has no
constructor from `Command`, argv strings, raw PID/PGID, raw handles, or a
generic worker config. Before activation, StageManifest/blob transfer, secret
delivery, plan/property/configuration data, RMI configure/start, callbacks, and
all useful Java work are forbidden. After the complete identity handshake
succeeds, the adapter asks the supervisor to activate; only the returned
`ActiveProcess<RmiRole>` can receive protected secrets, staging content, or any
useful operation. Activation is linearized with supervisor shutdown. Loss of
containment before or after activation is terminal. There is no
local/direct-child cleanup path.

## Files, environment, and security

The launcher clears the environment and sets only absolute Java/JMeter roots,
fresh user/prefs/temp/work/output roots, locale/timezone/charset, loopback
network settings, and explicitly approved runtime values. It rejects loader
injection, ambient classpath, Java option, proxy, credential, and shell
variables. Paths are handle-bound and race-checked. Worker roots, data,
plugins, and stores are distinct from the controller root.

Inputs, plan/tree depth and count, properties, frames, queues, result
hierarchies, response bytes, streams, logs, retries, ports, processes, files,
disk sender storage, deadlines, and diagnostics all have negotiated hard caps.
RMI/process ownership is not a security sandbox; hostile plans, plugins, or
workers require an external CPU/memory/thread/file/network sandbox. Without it,
only the trusted pinned fixture set is eligible for conformance execution.

## Rejected alternatives

- Implement Java serialization/RMI directly in Rust: rejected as a fragile,
  unsafe duplication of pinned JVM behavior.
- Present `crates/remote` as RMI compatible: rejected because its wire and
  lifecycle contracts are intentionally different.
- Launch `jmeter-server` shell scripts: rejected because executable identity,
  argv, environment, framing, and ownership would be indirect.
- Invoke `JMeter.main` as the long-lived bridge: rejected because its process
  exit/log protocol is not a bounded bidirectional session.
- Transfer missing data or dependencies for convenience: rejected because it
  changes JMeter's worker-filesystem contract.
- Silently disable SSL or replace an unsupported sender: rejected as a hidden
  compatibility failure.

## Verification requirements

Pure tests cover schemas, identity/transcript binding, classpath composition,
state machines, option/property projection, exact worker multiplication,
independent callback phases, batch boundaries and contiguous accounting,
two-dimensional credit reserve/release, stream ordering/terminal rules, all
limits, queue-full, retry/continue truth tables, stop transitions, and missing
worker resources. Secret tests prove that values, secret-bearing paths, and
provider internals cannot enter argv, ordinary environment/property maps,
frames, diagnostics, or evidence, and that unavailable protected transfer
fails closed. Fake helpers cover partial frames, crash, cancellation, timeouts,
late terminal frames, duplicate/out-of-order sequences, terminal-without-drain,
frames after terminal, and cleanup without starting Java.

The external `FX-DIST-001` matrix runs at least two pinned worker JVMs in an
isolated loopback environment and covers:

- `-r`, `-R`, `-G`, and `-X`, exact thread multiplication and worker identity;
- full plan transfer and positive/negative worker-local data, classpath,
  script, driver, and plugin cases with controller decoys;
- plain and JKS TLS, every port, reverse connection/firewall failures, wrong
  key/trust/alias/password/provider/hostname combinations;
- every factory alias including lower-case spelling; client/server property
  selection; thresholds, grouping, ordering, stripping, batching, end flush,
  disk cleanup, callback failures, and backpressure; explicit failures for
  empty/unknown mode, `Hold`, and the core `HoldSampleSender` FQCN;
- unavailable worker with both continue policies and exact retry count/delay;
- graceful, immediate, remote-exit, crash, bridge-limit, and supervisor-
  cleanup outcomes.

The JVM matrix covers the pinned supported Java baselines, including Java 8 and
Java 17, and rejects a helper, JMeter archive, signature record, classpath,
provider, or class-loader-generation mismatch before useful work. Signed
artifact verification is a required gate rather than diagnostic metadata.

Every run records the complete identity handshake, port block, worker roots,
staged-file hashes, certificate fingerprints, exact argv/environment policy,
sample/lifecycle streams, JTL/log artifacts, exit/reap/containment report, and
raw bounded diagnostic diff outside Git. Only profile-authorized fields are
normalized; worker identity, data contents, global properties, labels, result
fields, sender transformations, failure classes, and exit outcomes remain.

Decision 0001's namespace/Windows/macOS safety lanes, cross-platform targets,
security tests, performance under every sender, and long-running two-worker
soak/leak tests are release gates. Static fixtures, helper compilation, a green
Rust-native remote test, or this ADR cannot promote any profile row.

## Consequences

Drop-in Java RMI behavior remains explicit and truthful while the native Rust
transport can evolve independently. The approach adds an original Java helper
and streaming bridge surface, plus an external JVM/TLS test matrix. Native
headless execution remains Java-free when RMI and other JVM capabilities are
not requested.
