# Decision 0008: processors, extractors, and atomic mutation boundaries

Status: accepted architecture, revision 2; implementation and oracle evidence pending  
Date: 2026-08-13  
Compatibility feature: `ELEM-008`  
Related features: `ELEM-003`, `ELEM-005`, `JTL-001`, `JTL-002`  
External boundaries when selected: `EXT-JVM-001`, `EXT-SERVICE-001`,
`EXT-PLUGIN-001`

## Context

Preprocessors, postprocessors, and extractors sit inside JMeter's observable
execution pipeline. Some are pure bounded transformations; others depend on
Java scripting, JDBC, HTML/XML/JSON/JMES providers, plugins, filesystem-backed
responses, or HTTP request details. They can mutate variables, properties,
requests, results, sub-results, control actions, and diagnostics. Applying part
of a mutation or silently selecting a convenient native parser would corrupt
subsequent samples while appearing successful.

The original profile described `ELEM-008` as core-only, while the declared
surface and static corpus include JVM scripts, JDBC, legacy BSF, and plugin
processors. The profile now records the corrected aggregate external boundary;
that correction is not verification.

## Decision

`ELEM-008` is a phase and mutation contract, not a promise that every processor
is native. Selection is explicit and has no fallback.

Native-first candidates are bounded `UserParameters`, `RegExUserParameters`,
`SampleTimeout` through an injected scheduler/cancellation seam,
`URLRewritingModifier` through the neutral request-patch seam,
`BoundaryExtractor`, `ResultAction`, and `DebugPostProcessor`. A native
`RegexExtractor` requires exact pinned regex semantics and cannot reuse a
known-incomplete assertion subset as conformance.

Pinned JVM/provider paths include Anchor/HTML Link Parser, CSS/HTML, XPath1/2,
JSONPath, JMESPath, BeanShell/JSR223/BSF, JDBC processors, and unknown/plugin
processors unless a separately named, versioned native provider earns its own
evidence. Provider/parser identity is part of the capability and fixture tuple.

The pipeline remains:

```text
configuration -> preprocessors -> summed timers -> sampler
              -> postprocessors -> assertions -> immutable listener event
```

A null sampler result skips result-dependent downstream phases. Exact same-
category/scope ordering remains oracle-gated and is recorded as source-node
identities rather than inferred from labels or class names.

## Response and request views

Runtime owns and exposes an executor-neutral `ResponseResolver` capability. A processor
never reads response bytes ad hoc or opens `SampleResult.result_file_name`.
`ResponseView` preserves:

```text
body: Missing | Present(BoundedBytes)
raw_headers: Missing | Present(BoundedBytes)
source: Body | Headers | AllowlistedFile(FileCapability)
encoding/data-type/media-type and bounded response metadata
```

Missing and present-empty are distinct. `useHeaders` selects raw headers; body
processors do not substitute headers. No lossy UTF-8 conversion, ambient path
read, or network fetch is allowed. File input is an application-authorized,
length/digest-bound handle. The required negotiated JVM bridge projection must
preserve the same presence and capability distinctions before that path is
available.

`AllowlistedFile` is opt-in per compiled processor and fixture; no processor
may infer it from a nonempty result filename or read an ambient path. JTL
`responseFile` resolution and fallback belong to `JTL-002` and do not create a
processor input capability. Claiming file-backed processor behavior adds the
`EXT-OS-001` profile boundary and platform evidence; without that declaration,
the only legal source is an already-authorized injected handle.

Runtime also owns a neutral, bounded, ordered `RequestPatch`, so it does not
depend on the HTTP crate:

```text
RequestPatch {
  base_request_generation, base_request_digest,
  optional typed URL and method replacement,
  body operation preserving missing/present-empty,
  ordered add/remove header operations preserving duplicates
}
```

`base_request_generation` belongs only to the typed request state and cannot be
substituted with the invocation/user-context generation. URL replacement uses
typed scheme, authority/host/port, path-segment, and ordered query-field
components with explicit raw/encoded presence; it is not an unconstrained
string or lossy parse/reformat cycle.

Processors cannot open transport or mutate cookie/cache/auth state. The HTTP
adapter validates and applies this patch to its typed request. A stale base or
invalid patch rejects the whole processor invocation.

`ResponseResolver`, `ResponseView`, and `RequestPatch` are dependency-free
runtime domain contracts. HTTP consumes typed patches; `bridge-protocol`
carries only versioned wire mirrors and runtime never imports either crate.
The currently provisional `jvm-capability/2` projection does not preserve all
response missing-versus-present-empty cases and has no request-patch field.
Exact external processor execution therefore remains unavailable until a
negotiated schema extension carries versioned `ResponseView`, `RequestPatch`,
and `NextLoop`/`BreakCurrentLoop` fields and round-trips every field, presence
discriminant, limit, generation, and digest; no existing v2 message may be
interpreted as an implicit empty response, no-op patch, or next-loop action.

## Atomic invocation delta

Each processor stages one bounded `InvocationDelta`:

```text
InvocationDelta {
  base_generation,
  ordered variable and property mutations,
  optional RequestPatch,
  result/sub-result/assertion/control patch,
  bounded output and diagnostics,
  after-state and proposal digests
}
```

Validation constructs a complete candidate context in separate bounded
storage. It checks identities, generations, unique mutation keys, ordered
operations, count/value/result-tree/request/diagnostic/output limits, handles,
and generation overflow. Commit replaces one versioned context record exactly
once. A parse/provider/argument error, missing/present-empty mismatch,
unsupported syntax, no-match outcome where the configured element treats it
as failure, limit, deadline, cancellation, stale generation, or bridge/worker failure
leaves the invocation state unchanged. Earlier successfully committed
processors remain visible to later processors; this is not whole-chain
rollback.

JVM projection composes the `jvm-capability/2` prepare/execute/propose/commit
contract in Decision 0005. Arbitrary JVM effects are not roll-backable; an
uncertain executed operation poisons the worker/run and commits no Rust delta.
Unknown JMX/plugin data remains in the lossless model.

A configured no-match/default result is a successful semantic outcome only
when the exact element policy says so; it may stage the configured default,
empty value, match-count variable, or stale-variable cleanup. Malformed input,
unsupported provider/syntax, stale state, limits, deadline, cancellation,
bridge uncertainty, and internal invariants are never reclassified as
no-match and never receive the configured default.

## Result actions

An enabled `ResultAction` is registered as a postprocessor, never a listener.
It runs after the sampler result exists, after earlier applicable
postprocessors in proven scope order, and before assertions and immutable event
snapshot. The existing disabled root-level static fixture is preservation-only
and is not an executable placement oracle. Native immutable-event listeners
observe the mutated result and cannot mutate it or initiate control; a generic
runtime listener adapter that can return an error is not thereby an
`ELEM-008` control surface. Exact live Java/plugin listener mutation remains
inside Decision 0005's authority region. The controller consumes the action
only after event/result routing accounts for the event.

Control is typed:

- `NextLoop` skips the remainder of the innermost active iteration and begins
  its next iteration;
- `BreakCurrentLoop` exits the innermost active loop and resumes after it.

They are distinct result/wire/controller values. `BreakCurrentLoop` is a
loop-local directive, not another severity-ordered runtime `ControlSignal`;
`ELEM-003` owns its interpretation, nested-loop precedence, reset behavior,
and interaction with sampler/result actions. The current JVM boolean projection
is insufficient to prove the runtime, result, remote, or RMI contracts. Nested
and no-active-loop behavior, action visibility in listeners/JTL, and exact
consumption timing remain pinned-oracle questions; no implementation may encode
break as next-loop or guess the no-loop case.

## Bounds, errors, and identity

Inputs are bounded before allocation and incrementally while parsing. The
fixture minima include 4,096 response/regex bytes, 4,096 regex steps, eight
capture groups, 32 matches (16 in the negative case), eight JSON/JMES
expressions (four negative), 64 variables, and 4,096 bytes per value, while
production hard maxima remain finite and identity-bound.

Stable outcomes distinguish missing response, present-empty response, no
match, malformed input, invalid arguments, unsupported syntax/provider,
resource limit, stale generation, deadline/cancellation, capability unavailable,
worker poisoned, and internal invariant. No truncation or silent default can
become success. Errors carry bounded domain-qualified plan/node/processor/
invocation context and redact source values.

## Profile and evidence correction

Related ownership is explicit: `ELEM-003` owns controller/action interpretation
and loop precedence; `ELEM-005` owns property decoding, scope, and precedence;
`JTL-001`/`JTL-002` own result serialization, presence, and `responseFile`
behavior. `ELEM-008` consumes those contracts and cannot promote them. Existing
controller fixtures do not prove `ResultAction` or `BreakCurrentLoop`, so both
remain oracle-gated.

The aggregate `ELEM-008` row must become `staged/external`, status `external`,
and require `FX-ELEMENTS-CORE-001`, `FX-ELEMENTS-EXTERNAL-001`,
`FX-SCRIPT-001`, and `FX-PLUGIN-001`, with JVM/service/plugin boundaries and
`NORM-EXTERNAL-001`. The core processor fixture itself remains a boundary-free
native/preservation case; aggregate external scope does not turn a direct core
case into external evidence. `EXT-OS-001` is added only if the profile claims
file-backed response behavior rather than an injected file capability.

`FX-ELEMENTS-EXTERNAL-001` must contain explicit JVM/service processor cases
in addition to sampler/deprecated cases. Its catalog-level OS boundary belongs
to other aggregate family cases and is not an `ELEM-008` claim.
`FX-SCRIPT-001` and `FX-PLUGIN-001` each require an explicit processor
invocation with ordered before/after state and failure evidence; generic engine
or plugin discovery cases do not satisfy this feature. All such cases remain
not-run until the corresponding adapter and pinned oracle are available.

This is a scope correction, not a compatibility promotion. All evidence
remains planned/external until the pinned oracle runs.

Oracle evidence records Java/provider/artifact/classpath identities, target
triple/OS, locale/UTC/UTF-8, explicit properties and roots, response corpus,
ordered variable/request/result/action/event snapshots, raw bounded JTL/log
diagnostics outside Git, and the selected capability path. Required questions
include same-category ordering, stale-variable cleanup, defaults/no-match,
binary/encoding/file behavior, regex templates/random match/capture numbering,
provider malformed-input semantics, JDBC/script lifecycle, URL rewrite
interaction, action semantics, and Java 8 versus 17 behavior.

Pure unit/model/property tests cover every native transformation, state commit
and rollback branch, missing/empty distinctions, request ordering, nested
control actions, bounds, and candidate-state atomicity. Fuzz targets cover
extractor and response-parser inputs without I/O. External JVM/provider cases
wait for Decision 0001 supervision and Decisions 0005/0007 adapters.

Acceptance after implementation includes:

```text
cargo fmt --all -- --check
cargo test -p jmeter-rs-runtime --all-targets --locked
cargo test -p jmeter-rs-bridge-protocol --all-targets --locked
cargo clippy -p jmeter-rs-runtime -p jmeter-rs-bridge-protocol \
  --all-targets --all-features --locked -- -D warnings
cargo run --locked -p xtask -- profile-check
cargo run --locked -p xtask -- fixture-check
```

## Consequences

Rust owns fast, testable mutation state machines while provider-specific and
arbitrary Java behavior remains available through explicit bounded adapters.
Atomic per-invocation state prevents partial corruption, and the profile tells
the truth about the external portion of the surface.
