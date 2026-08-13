# Decision 0008: processors, extractors, and atomic mutation boundaries

Status: accepted architecture, revision 3; implementation and oracle evidence pending
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

The result-dependent pipeline follows Decision 0016:

```text
configuration -> preprocessors -> summed timers -> sampler
              -> postprocessors -> assertions
              -> source-ordered listener effects/observer snapshots
              -> control consumption
```

A null sampler result skips result-dependent downstream phases. Exact same-
category/scope ordering remains oracle-gated and is recorded as source-node
identities rather than inferred from labels or class names.

## Response and request views

Runtime owns an executor-neutral, scope-aware `ResponseResolver`. A processor
never reads response fields ad hoc or opens `SampleResult.result_file_name`.
Missing and present-empty remain distinct at every boundary.

The exact response scopes are:

```text
ResponseScope::Current       # JMX wire value parent/default
ResponseScope::Subresults    # children
ResponseScope::All
ResponseScope::Variable { name }
```

For sample scopes, `All` returns the current sample first and then descendants
in pinned depth-first order. The profile must oracle-pin JMeter 5.6.3's finite
recursive edge rather than replacing it with unbounded traversal. Variable
scope reads exactly the named variable and bypasses sample target selection;
a missing variable and a present-empty variable are different outcomes.

The closed response targets are:

```text
Body
ResponseHeaders
RequestHeaders
Url
ResponseCode
ResponseMessage
BodyUnescapedHtml4
BodyAsDocumentText
AllowlistedFile(FileCapability)
```

A bounded response record retains raw body bytes, response headers, request
headers, URL, response code/message, encoding, data type, media type, and
opaque result-file metadata with independent `Missing | Present` presence.
Raw source text uses a bounded type that preserves CR, LF, controls, and
malformed source bytes; the generic control-rejecting configuration-text type
is not reused. URL, code, message, and request headers come from the captured
sample result, not the outgoing request builder.

Conceptually, resolution is:

```text
resolve(snapshot, scope, target, response_limits)
  -> NoCurrentResult
   | Variable(Missing | Present(BoundedSourceText))
   | Samples { ordered bounded records/projections }
```

No-current-result is distinct from an empty response. Body processors never
substitute headers or metadata. Raw bytes are retained unchanged. Text body
decoding uses the declared encoding when present/nonempty, otherwise the
explicit profile default; malformed sequences use replacement semantics.
Unknown encodings use an explicitly selected provider or pinned fallback and
never inherit the native host default. HTML4 unescaping, Tika document text,
XPath/XML/Tidy, Jayway JSONPath, JMESPath, and Jsoup/Jodd behavior remain
versioned provider capabilities until independently evidenced native
implementations exist.

`result_file_name` remains opaque metadata. `AllowlistedFile` is opt-in per
compiled processor and fixture; no processor infers it from that metadata or
reads an ambient path. The authorized capability binds a declared length and
digest, is rejected against the configured file limit before resolution, and
is verified again afterward. JTL `responseFile` resolution belongs to
`JTL-002` and does not create a processor input capability.

Response limits are separate from scalar mutation limits. They independently
bound body bytes, request/response headers, URL/code/message, decoded text,
variable bytes, scope item count/depth, file input, document provider
input/output, regex steps/groups/matches, JSON expressions/results, parser
nodes, and provider output. Bounds reject before allocation or incrementally;
there is no silent truncation.

The negotiated bridge projection must round-trip scope, target, ordered sample
origin, every raw field and presence discriminant, decode policy, provider
identity, limits, file capability generation/length/digest, and no-current-
result versus empty-result outcomes before an external extractor path is
available.

Claiming filesystem-backed processor behavior adds `EXT-OS-001` and platform
evidence; an already-authorized in-memory/file handle alone does not authorize
ambient path access.

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
storage. It checks identities, generations, ordered mutation semantics,
count/value/result-tree/request/diagnostic/output limits, handles, and
generation overflow. Source-order duplicate variable operations may be
visible inside an expression session and collapse only to their proven final
state; they cannot be rejected or sorted merely because a map key repeats.
Commit replaces one versioned context record exactly once.

Processor outcomes distinguish `Commit`, `CommitWithDiagnostic`, and `Abort`.
If pinned JMeter behavior initializes a default, match count, assertion, or
other state before catching malformed input, the native/provider result stages
that complete observable final state as `CommitWithDiagnostic`; Rust does not
erase it by applying a generic rollback rule. Infrastructure uncertainty,
unsupported provider/syntax, stale generation, resource limit, deadline,
cancellation, or untrusted bridge/worker failure is `Abort`, leaves Rust state
unchanged, and may poison the authority when external effects are uncertain.
The distinction is component- and profile-proven, never inferred by treating
every error as no-match. Earlier successfully committed processors remain
visible to later processors; this is not whole-chain rollback.

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

ResultAction follows
[`Decision 0016`](0016-source-ordered-listener-effects.md). Pinned JMeter
implements it as a `SampleListener`; it is registered in the source-ordered
listener program and never as a postprocessor. Assertions therefore run first,
and a collector before versus after the action may capture different immutable
revisions of the same sample.

For an unsuccessful result, its closed precedence is `StopTestNow`,
`StopTest`, `StopThread`, `StartNextThreadLoop`,
`StartNextIterationOfCurrentLoop`, then `BreakCurrentLoop`. Stop fields and
loop-local actions remain separate typed result/control values.
`BreakCurrentLoop` is not another severity-ordered runtime `ControlSignal`;
`ELEM-003` owns nested-loop interpretation, reset, and the no-active-loop case.
The controller consumes final action state only after the complete listener
program and every observer admission. The current JVM boolean projection is
insufficient until it round-trips every action and listener revision.

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
