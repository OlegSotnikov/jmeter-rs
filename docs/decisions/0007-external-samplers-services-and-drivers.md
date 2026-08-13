# Decision 0007: external samplers, services, and driver adapters

Status: accepted architecture, revision 2; implementation and external evidence pending  
Date: 2026-08-13  
Compatibility features: `ELEM-001` external paths, `ELEM-002`, `ELEM-009`,
`TEST-002`, `TEST-004`  
External boundaries: `EXT-JVM-001`, `EXT-SERVICE-001`, `EXT-OS-001`,
`EXT-PLUGIN-001`

## Context

JMeter samplers include protocol clients, Java/provider objects, operating-
system processes, and deprecated aliases. Their observable behavior depends on
specific drivers, services, JVM libraries, filesystem inputs, and lifecycle
state. A native Rust client can be valuable without being the same capability
as JMeter's Java/provider implementation. Missing services, drivers, classes,
or plugins must never become a fabricated sample or a different native
sampler.

HTTP is governed by Decision 0006. Java object identity, scripts, Java Request,
and JUnit are governed by Decision 0005. This record defines how the remaining
external sampler families compose those boundaries with deterministic local
service fixtures and Decision 0001 process ownership.

## Decision

Every executable sampler carries an explicit implementation-path identity.
Selection happens at compilation from the source class, profile, and declared
capability; it is never inferred from which adapter is installed. There is no
fallback after selection.

| Family | JMeter-compatible path | Separately named native path |
| --- | --- | --- |
| FTP, LDAP, TCP | pinned provider/JVM adapter where provider behavior is observable | `native.ftp/1`, `native.ldap/1`, `native.tcp/1` |
| JDBC | pinned JVM plus exact JDBC driver | vendor-specific native driver capability only |
| Java Request, JUnit | Decision 0005 JVM authority | none for arbitrary Java classes |
| JMS | pinned JVM plus exact JMS client/provider and broker | no profile fallback |
| Mail reader/SMTP | pinned JVM plus exact mail provider and local service | separately evidenced native mail capability |
| MongoDB, Neo4j/Bolt | pinned JVM plus exact driver and local service | separately evidenced native driver capability |
| OS Process | native OS adapter through Decision 0001 only | `native.os-process/1` after exact semantics/evidence |
| Access Log | bounded native parser only for an explicitly pinned parser | `native.access-log/1`; user parser classes use JVM authority |
| BSF/JSR223 and legacy script aliases | Decision 0005 JVM authority | none |
| deprecated report/Mongo aliases | lossless syntax/alias handling plus named adapter where executable | no implicit substitute |

A native path cannot verify the corresponding Java/provider row unless the
profile explicitly names that path and its differential evidence. Unknown or
plugin classes remain losslessly preserved and compile to a stable capability
error unless an exact manifest-bound provider claims them.

The `native.*` names in this record are reserved design identities, not active
profile capabilities. Until the profile declares a name, schema/version,
implementation digest, and fixtures, compilation reports it unavailable and
cannot select it merely because code is registered. For `ELEM-009`, BSF and
other script aliases use only Decision 0005, deprecated MongoDB uses its exact
declared driver path, and legacy report aliases that have no executable pinned
contract remain opaque preservation records rather than adapters.

`runtime` owns the dependency-free selection types
`ImplementationPathIdentity { family, path_id, schema_version,
capability_digest }`, `RuntimeCapabilitySet`, and a `ComponentBinding` that
contains exactly one requested path. Its factory registry reports support for
that exact identity; a generic `external: true` marker is insufficient. A
selected HTTP path is consumed by `http`, while JVM/non-JVM wire crates carry
versioned mirrors of the runtime identity. `runtime` never depends on `http` or
`bridge-protocol`, and those mirrors must round-trip every field before the
adapter can be advertised.

## Adapter and protocol contract

Non-JVM adapters use `external-capability/1`, a canonical bounded envelope
inside the shared bridge frame. JVM samplers use `jvm-capability/2`; this
decision does not create a second Java protocol. In particular Java paths map
provider discovery to Decision 0005 `discover_providers` and execution to
`execute_package` or the named Java/JUnit operations; they never encode an
`external-capability/1` request.

The envelope binds profile ID/version/hash, adapter kind/ID/version/build and
source hashes, selected implementation path, run/plan-domain/node/user/
iteration/sample/session/transaction/generation identities, per-direction
sequence and digest chain, finite remaining budget, cancellation state, and
negotiated limits. Its closed operations are:

```text
open_run | discover | configure | setup | sample | teardown | close_run
```

Bodies contain bounded ordered typed arguments and properties, opaque endpoint
and service/provider references, an explicit request projection, and either a
complete `SampleResultProjection`/sub-result tree or a typed failure. Arbitrary
URLs, shell strings, ambient paths, raw credentials, and unbounded provider
metadata are not protocol types. Unknown fields/operations are rejected unless
a negotiated preservation extension retains them without execution.

`external-capability/1` has magic `EXC1`, schema `u16=1`, fixed big-endian
integers, strict booleans, fixed 16-byte IDs, 32-byte SHA-256 values, explicit
presence discriminants, and canonical TLVs whose known tags increase strictly.
Its outer frame ceiling is 16 MiB and complete inner-message ceiling is 4 MiB;
it permits at most 256 fields, 1 MiB per field, 4,096 arguments/properties, a
64-level/16,384-node result tree, 8 MiB aggregate result payload through
digest-bound artifacts, 1,024 diagnostics of 4 KiB each, and one mutating
transaction. Negotiation may lower but never raise these values. Sequence and
body/chain digest rules match Decision 0005's canonical rules with distinct
`exc1/*` domains. Unknown operation, phase, enum, duplicate tag, trailing byte,
limit, identity, or digest mismatch fails before execution.

The closed response is either `SemanticComplete { result_projection,
phase_outcomes, observations, proposal_digest }` or `AdapterFailure {
code, may_have_dispatched, poison_reason, diagnostics }`. Java/provider
semantic failures retain Decision 0005's semantic-result mapping; they are not
collapsed into generic capability errors. Every terminal carries accepted,
completed, failed, cancelled, byte, handle, and artifact accounting plus the
final chain/identity digest, and exactly one terminal is legal.

The lifecycle is:

```text
Created -> Handshaking -> Ready -> RunOpen
RunOpen -> Prepared -> Executing -> Result/Proposed -> RunOpen
Prepared -> Aborting -> RunOpen
Executing or uncertain result -> Poisoned -> Closing -> Terminal
RunOpen -> Closing -> Terminal
```

Per-run and per-user setup/teardown ownership is explicit. One mutating Java
transaction is admitted at a time. Queue admission, setup, execution, reply
validation, result routing, teardown, and cleanup consume one monotonic parent
budget; retries cannot reset it. Cancellation before execution may abort. Once
an external side effect may have occurred, timeout, cancellation, crash, or an
unknown result poisons the operation/worker and forbids automatic retry. A
retry is legal only before dispatch when Rust-owned state proves the prior
attempt was not dispatched, the operation is declared replayable, and the
original absolute budget remains. Java, driver, service, and OS-process work is
never retried after dispatch or an uncertain outcome, regardless of claimed
idempotence.

Stable failures distinguish profile/identity mismatch, adapter/service/
provider/class unavailable, configuration, deadline phase, cancellation,
worker crash, resource limit, protocol violation, uncertain side effect,
poisoned state, teardown, and containment loss. Diagnostics carry bounded
domain-qualified source context and no secrets.

## Identity, services, and secrets

Before `Ready`, the application verifies the active profile, signed pinned
JMeter provenance state, JVM executable and runtime where applicable, helper
build, every ordered classpath entry, driver/provider/plugin artifacts,
licenses/NOTICE/dependencies, class-loader generation, target triple/OS image,
local service image/protocol identity, roots, locale/timezone/charset,
environment policy, and every negotiated limit. Missing or extra artifacts,
provider collisions, duplicate aliases, or a signature state that does not
meet the execution policy fail before useful work.

The verified identity is the exact active profile ID, profile version,
canonical profile SHA-256, declared JMeter filename and archive/source/signing
endpoints, nonzero artifact/helper/schema/classpath/provider digests, and a
successful signature-verification record bound to the accepted Apache key.
`signature_verified: false`, a zero digest, a filename/end-point mismatch, or
an unbound helper role makes JMeter/JVM execution unavailable. The current
profile intentionally records `signature_verified: false`; therefore no
current JVM external-sampler run may perform useful work or produce evidence.

Every adapter identity declares one closed concurrency policy:
`RunSerial`, `PerUserSerial`, or `BoundedParallel(nonzero u32)`, plus its setup,
sample, teardown, cancellation, and dispatch boundary. Cancellation before
dispatch removes queued work; after dispatch it requests adapter-specific
interruption but cannot produce success unless the complete semantic result is
known. Each accepted invocation has one terminal accounting record. An adapter
without a declared and tested policy is unavailable.

Fixture services are local, deterministic, version/digest pinned, and bound to
an isolated allowlisted network. Public services and ambient credentials are
never correctness fixtures. Endpoint references separate address identity from
secret material. Every response, queue, retry, file, diagnostic, provider
record, and retained byte count is finite.

Secrets use the opaque purpose/right/lease-bound references and one-shot
protected supervisor channel from Decisions 0001 and 0005. Secret bytes never
enter argv, ordinary environment, bridge bodies/digests, logs, metrics,
snapshots, or committed evidence. Missing protected transfer is an unavailable
capability, never an environment/path fallback.

## OS-process and worker ownership

Every subprocess adapter accepts only a typed, activated Decision 0001
supervisor capability. Direct `Command`, `Child`, shell invocation, `.kill()`,
external signal utilities, raw PID/PGID/handle access, and adapter-local cleanup
fallbacks are prohibited. The OS Process sampler uses typed executable/file
capabilities, ordered bounded arguments, a cleared allowlisted environment,
bounded stdio, one parent budget, and exact result/exit projection. Platform
tree semantics and argument/encoding behavior require separate OS evidence.

No external sampler or helper launches until shared-supervisor implementation,
caller migration, and independent platform safety evidence pass. Lack of that
gate is a stable unavailable capability and never permits direct-child mode.

## Evidence and verification

`FX-ELEMENTS-EXTERNAL-001` is partitioned by FTP, JDBC, Java, LDAP, TCP, JMS,
mail, MongoDB, Bolt, JUnit, OS Process, Access Log, BSF, and legacy aliases.
Every observed case records exact service image, driver/provider/plugin/JVM
artifacts and provenance, profile/repository/lockfile/toolchain/platform hashes,
filesystem/network/secret/supervisor policy, selected capability path, and raw
bounded JTL/log/wire/process artifacts outside Git. It covers positive,
unavailable, wrong-provider, timeout, cancellation, crash, malformed/oversized,
redaction, and proof of no fallback. `TEST-004` composes applicable cases with
Decision 0004's RMI/TLS matrix.

Pure schema/state tests cover every operation/transition, absent/null/empty,
limits, sequences/digests, cancellation, uncertain outcomes, setup/teardown,
redaction, and terminal uniqueness. Property/fuzz tests decode and model state
without opening services or processes. Deterministic integration tests use only
local injected or contained fixtures. Cross-platform, security, performance,
and soak/leak lanes are required for release.

An executable `xtask external-acceptance --check` validates a manifest for
every family/path and refuses success unless positive, unavailable,
wrong-identity, timeout, cancellation, crash, malformed/oversized, redaction,
no-fallback, setup/teardown, and terminal-accounting cases are declared with
raw-artifact locations and exact identities. A separate
`xtask external-acceptance --run-contained` may execute only after the shared
supervisor, network/service isolation, secret channel, and signature gates are
green. The static check never converts a descriptor into an observation.

Acceptance after implementation includes:

```text
cargo fmt --all -- --check
cargo test -p jmeter-rs-bridge-protocol --all-targets --locked
cargo test -p jmeter-rs-runtime --all-targets --locked
cargo test -p jmeter-rs-java-bridge --all-targets --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo run --locked -p xtask -- profile-check
cargo run --locked -p xtask -- fixture-check
cargo run --locked -p xtask -- external-acceptance --check
python3 .github/scripts/check-process-supervision-migration.py
```

Static unavailable descriptors and unit tests do not verify any external row.

## Consequences

The Rust engine can add fast native protocol clients without mislabeling them
as Java/provider behavior. Full-profile compatibility remains possible through
explicit pinned JVM, service, driver, plugin, and OS adapters, while every
missing or unsafe boundary fails visibly and preserves the source plan.
