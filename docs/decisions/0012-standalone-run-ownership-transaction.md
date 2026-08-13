# Decision 0012: standalone run ownership transaction

Status: accepted architecture; implementation and evidence pending
Date: 2026-08-13
Compatibility features: `CLI-001`, `CLI-002`, `CLI-003`, `ELEM-001`,
`ELEM-003`, `ELEM-004`, `ELEM-007`, `JTL-001..005`, `REPORT-001`,
`REPORT-002`, `TEST-001`, `TEST-005`

## Context

The standalone application must combine configuration and JMX input, native
HTTP/DNS/TLS, production time, result routing, JTL persistence, logging, and
report generation without turning the CLI runner into an implicit service
locator or a collection of unrelated cleanup branches. Several of these
resources own threads, queues, file descriptors, private staging entries, or
immutable security policy. A failure after partial setup must not publish a
success-looking artifact or leave an owner running.

Whole-plan capability admission is already required before observable output
or workload I/O. Decisions 0003, 0006, 0009, 0010, and 0011 separately define
result, HTTP, product, observation, and time contracts. This decision defines
how the application composes them into one Rust ownership transaction.

## Decision

The standalone application uses a typed, single-run state machine. Each
transition consumes its prior state; a later state cannot be constructed by
setting independent booleans or by looking up ambient global resources.

```text
ParsedInvocation
  -> LoadedInputs
  -> AdmittedRun
  -> PreparedResources
  -> RunningRun
  -> FinalizedRun
  -> PublishedOutcome
```

`LoadedInputs` may own bounded input handles or immutable bytes read through
the application filesystem capability. It has no output target, logger,
network resource, worker, or runtime future. `AdmittedRun` contains the exact
profile/capability-set/plan/provider identities, compiled packages, effective
save/report policy, and closed resource recipes. Construction accounts for
every enabled node and all direct selector properties. Supplying an unused
security- or network-policy property is an admission error, not permission to
guess a future use.

Effectful factories use two explicit phases. Pure compilation produces an
`AdmittedExecutableRecipe` containing the controller/group draft, ordered
scope program, decoded component recipes, complete implementation-path
manifest, resource requirements, and every source-derived value needed to
construct per-user packages. Only after that value is complete may the
application create time, DNS, TLS, HTTP, JTL, or other owners. A later
`bind_resources` pass consumes exact typed owner handles and turns the admitted
recipes into runtime factories/packages; it performs no JMX/property parsing,
class selection, capability fallback, or new unsupported-feature decision.
Failure to bind a promised exact owner is a typed construction/invariant error
and triggers reverse cleanup before outputs exist. A provider cannot require
starting its worker merely to discover whether the plan is supported.

The application is split into narrow modules for plan admission, native HTTP
resource preparation, production time, result-output ownership, report input
and publication, and the top-level run state machine. Feature decoders and
factories enter through explicit registries with typed identities. The
top-level runner orders them; it does not reimplement their parsers or choose
providers from request details. Pure crates remain unaware of paths, files,
threads, process environment, or CLI syntax.

### Preparation and side-effect order

Preparation follows this order:

1. parse the invocation and direct selector occurrences without I/O;
2. resolve bounded input paths and read configuration/JMX inputs through exact
   handles;
3. compile the complete semantic plan and freeze its implementation-path
   manifest;
4. validate all resource recipes, read explicit public CA material through an
   exact root-contained handle, and build immutable TLS policy;
5. create run-owned production time and, only when required, explicit DNS and
   bounded HTTP worker owners;
6. reserve private result/report staging targets, create the run-owned typed
   result-delivery budget and wait registrar, and start every typed sink;
7. initialize logging and start the engine.

Steps 4 through 6 are allowed only after whole-plan admission. Reading the CA
precedes output creation and network activity. A resolver actor may be created
after its complete configuration is validated, but it performs no query until
the engine submits an admitted request. A plan containing only numeric HTTP
origins does not start a DNS actor. A plan containing no HTTPS does not load or
retain a TLS configuration. A supplied-but-unused DNS or CA property fails
closed.

Every prepared owner is stored immediately in the consuming state. No raw
thread handle, file descriptor, queue permit, resolver handle, or staging path
exists between creation and ownership transfer. Construction failure
explicitly finalizes already-created owners in reverse order and combines a
cleanup error with the primary typed error without replacing it.

### Execution and finalization

Production execution never uses the runtime's epoch clock, immediate sleeper,
or immediate scheduler. The engine receives one coherent run-owned time
capability and constant-memory observation policy. Provider choice is frozen:
`http.native/1` cannot be upgraded and `http.native/2` cannot fall back.

Finalization is explicit and consumes `RunningRun`. On success or failure it:

1. requests engine cancellation when required and drops/finishes the exact run
   future;
2. stops typed result admission, drains and finishes every sink under the one
   finalization deadline, then closes and joins the JTL owner so no result can
   arrive later;
3. closes and joins the HTTP worker pool;
4. shuts down and joins DNS, time, and any other provider owners;
5. flushes and synchronizes private output handles;
6. validates staging identities again;
7. publishes the result atomically only for a successful finalized run;
8. streams any report from an exact finalized result handle into private
   dashboard staging and atomically publishes the dashboard.

An owner may provide a non-failing constant-time `Drop` fallback that requests
cancellation, but compatibility success is available only after explicit
finalization reports every join/flush result. A `Drop` implementation must not
hide a failure, block without the owner's finite provider contract, perform
broad cleanup, or publish output.

Report failure after successful result publication leaves the new result and
the previous dashboard visible and returns a fatal report outcome. Changing
that behavior to all-or-nothing result-plus-dashboard publication requires a
separate compatibility decision and oracle evidence. Every earlier failure
preserves previous visible result/dashboard targets and removes only exact
private staging entries.

### Current-thread executor boundary

The application executor consumes the progress and wait snapshots from
Decision 0011. It does not infer one idle timeout from JMX fields or count
lifetime polls as a resource limit. Its waker owns only an exact run-thread
handle and checked generations; it retains neither the run future nor result
payloads. Executor watchdog failure first raises immediate cancellation, then
hands cleanup to the same ownership transaction. It cannot bypass sink or
provider finalization.

### Bounds and diagnostics

Every recipe, owner registry, queue, input prefix, CA bundle, JTL record,
report aggregate, diagnostic, and cleanup-error chain has an explicit finite
bound. Counters use checked arithmetic. Diagnostics identify stable capability
and phase codes while excluding raw request data, hostnames, DNS answers,
certificate bytes, secret values, and machine-specific paths. Exact paths may
remain in local operator-facing I/O errors but never enter capability identity
or committed compatibility evidence.

## Rejected alternatives

- Independent optional owner fields in one long runner function are rejected
  because invalid combinations and skipped cleanup remain representable.
- Starting workers during sampler factory cloning is rejected because setup
  would scale with users and precede atomic admission.
- Relying on `Drop` as the successful join path is rejected because errors
  cannot be returned from `Drop`.
- Reopening a published result by arbitrary path is rejected because it loses
  the exact-handle and identity guarantee.
- A global resolver, timer runtime, HTTP pool, logger, or property map is
  rejected because state and teardown would leak across runs.
- Publishing JTL before all worker owners finish is rejected because late
  cleanup failure would accompany a visible success-looking result.

## Compatibility and evidence

This decision promotes no profile row. Required deterministic evidence
includes every construction failure boundary, exact reverse cleanup order,
primary-plus-cleanup error preservation, supplied-but-unused property
rejection, no DNS owner for numeric-only plans, no TLS state for HTTP-only
plans, one timer owner for many waits, cancellation during every run phase,
late worker failure before publication, descriptor replacement races, prior
target preservation, streaming report input, and repeated runs proving no
cross-run owner or state retention.

Acceptance includes the narrow package tests first, then standalone app and
workspace format/lint/test/policy gates. Pinned JMeter oracle evidence remains
required for compatibility claims; passing ownership tests proves safety and
architecture, not JMeter equivalence.

## Consequences

The CLI remains a small composition edge even as native capability breadth
grows. Rust ownership makes illegal lifecycle states difficult to express,
provider resources have one exact teardown path, and every visible artifact is
published only from a finalized state. Feature owners can implement disjoint
modules without weakening atomic admission or inventing their own cleanup
order.
