# Decision 0017: run-owned expression sessions and function state

Status: accepted architecture; implementation and oracle evidence pending
Date: 2026-08-13
Compatibility features: `ELEM-005`, `ELEM-008`, `FUNC-001`, `FUNC-002`,
`TEST-001`

## Context

JMeter expressions are not universally substituted at plan load. Function-
bearing properties are compiled and execute when a component reads their
string value. Evaluation is left-to-right, function arguments are left-to-
right, and stateful functions retain occurrence-specific state. Cache behavior
depends on running-version state, whether sampling has started, the
`function.cache.per.iteration` property, and the current iteration.

`UserParameters` makes this timing directly observable. Under one lock shared
by its clones, it evaluates one name, evaluates its paired value, writes the
variable immediately, and then proceeds. Later pairs see earlier writes, and
duplicate names are last-write-wins. A single immutable snapshot and a sorted
map cannot reproduce that behavior. `per_iteration=true` runs from the nearest
controller's iteration callback, not from every preprocessor invocation.

Test-plan `Arguments` have a different contract: source-order first wins, a
first-seen dynamic name can be evaluated once for lookup and again for
insertion, and the value of a duplicate is not evaluated. `RegExUserParameters`
also has observable early-return points before later property evaluation.

The existing optional app `ExpressionResolver<InvocationSnapshot>` cannot
carry live overlay writes, occurrence/field identity, lifecycle/cache state,
or capability effects. Cloning `BuiltinFunctions` currently creates fresh
counter state, while the product needs one run-owned authority. Runtime's
generic checkpoint covers variables/properties/request/result but not random
draws, counters, file cursors, logging, script/JVM calls, or external writes;
claiming those effects were rolled back would be false.

## Decision

### One run-owned expression authority

Each admitted run owns one `Arc<ExpressionRuntime>` containing the exact
profile function registry, compiled-field cache policy, bounded native state,
and explicit capability router. Virtual users, component factories, and
iteration callbacks clone only the `Arc`; they never clone independent counter
or file-cursor state. A new run receives a fresh authority, and user/run
finalization explicitly clears the state defined by each function's pinned
scope.

The application installs this same authority in runtime expression evaluation,
component factories, lifecycle cleanup, and external-function routing. Missing
capabilities are typed failures. No evaluator consults ambient filesystem,
environment, host, clock, randomness, script engine, or global singleton.

The concrete registry's ordinary `Clone` must not silently reset mutable
state. Either it is not `Clone`, or cloning its public handle shares the same
run authority explicitly. Tests must distinguish a shared handle from a fresh
run registry.

### Compiled fields and read-time evaluation

A function-bearing property compiles to an immutable `ExpressionField` that
retains exact source text, field namespace, structural function occurrences,
source property identity, and cache policy. It has explicit lifecycle state:

```text
RawBeforeRunningVersion
RunningBeforeSampling
RunningDuringSampling { iteration identity }
Finished
```

Before running-version mode, a string read returns the raw source as pinned.
With caching disabled, or before sampling has started, each read evaluates.
With per-iteration caching enabled during sampling, the field caches by the
complete iteration/lifecycle identity. A field read never fabricates a cache
key from a label, source offset hash, or thread schedule.

Component decoders control when and how often fields are read. The central
evaluator does not pre-evaluate all configuration. This preserves, among other
cases, the double dynamic-name read and skipped duplicate value in test-plan
`Arguments`, and the early return in `RegExUserParameters`.

### Ordered expression sessions

Every evaluation occurs in a bounded `ExpressionSession` bound to run, user,
lifecycle, iteration, component, phase, field namespace, invocation
generation, and sampling-start state. A session contains:

- an immutable base variable/property view;
- an ordered mutable overlay visible to subsequent reads in the session;
- exact structural `FunctionOccurrence` identities;
- an ordered effect journal;
- capability transactions or authority tokens; and
- checked input, output, call-depth, call-count, mutation, and diagnostic
  limits.

Compound text and arguments evaluate left-to-right. A component may evaluate
several fields in one session and publish intermediate overlay writes between
them. Duplicate source mutations remain ordered and visible; only the final
commit projection may collapse them to a final key/value state when no
intermediate history escapes.

`UserParameters` holds its clone-shared component lock across selection of the
row, sequential name/value evaluation, every overlay write, validation, and
commit. Each pair is zipped in source order. Later pairs see prior writes, and
the final duplicate wins. Lock poisoning is a typed failure; recovering the
inner value and continuing is forbidden.

### Effect classes and exact failure outcomes

Every function capability declares one effect class:

```text
Pure
JournaledNative        # variables, properties, counters, random, file cursor
TransactionalExternal  # explicit prepare/commit/abort protocol
IrreversibleExternal   # log/file write/script/JVM/unknown side effect
```

Native mutable capabilities expose session-local proposals or checkpoints, so
the authority can publish exactly the prefix/state required by the pinned
outcome. The system does not pretend that every function failure is atomic:
JMeter may retain earlier variable writes, counter advances, random draws,
file-cursor movement, or partial expression text after a caught evaluation
error. A versioned component/function policy classifies the completed session:

```text
Commit(value, effects)
CommitWithDiagnostic(partial value/effect prefix)
AbortBeforeEffects(error)
UncertainAfterExternalEffect(error)
```

`CommitWithDiagnostic` is used only when pinned behavior proves the observable
prefix/final state. `AbortBeforeEffects` publishes nothing. An uncertain
irreversible or external operation publishes no guessed Rust delta, poisons
the exact authority/run, and makes later evaluation fail with a stable
poisoned-state error. It is never relabeled as no-match, empty value, or
successful rollback.

Random streams, counters, file cursors, and property/variable overlays are
included in the native journal. An irreversible capability must be rejected
before execution when the selected compatibility path lacks a protocol capable
of reporting the final state. Mutex/registry/capability poisoning and checked
generation exhaustion fail closed; `into_inner`, `ok()?`, saturation, and
silent `None` are not legal recovery policies.

### Lifecycle callbacks

Runtime exposes a general, identity-bound `LoopIterationListener` program
associated with the nearest controller as JMeter does. It runs at the proven
iteration boundary before the affected sampler's preprocessing. The listener
program is separate from sample listeners and result routing.

`UserParameters(per_iteration=true)` evaluates exactly from this callback and
its normal `process` is a no-op. With `per_iteration=false`, it evaluates on
every preprocessor invocation. Component clone/shared-lock identity, nearest
controller identity, iteration identity, and callback order are part of the
compiled plan.

Test-plan user variables execute in an explicit plan-start/precompile session
before virtual-user sampling. They are then copied into each user's initial
state according to JMeter first-wins rules; they are not reevaluated per user
unless the pinned field contract says so.

### External functions

BeanShell, Groovy, JavaScript/Rhino, JEXL, plugins, response-provider
functions, and arbitrary Java behavior use the negotiated JVM/plugin authority.
The request carries the compiled field and occurrence identity, lifecycle and
cache state, bounded current overlay, capability manifest, deadline,
cancellation, and effect generation. The reply distinguishes committed final
state, committed prefix with a caught diagnostic, no effect, and uncertain
execution. A worker crash or protocol ambiguity poisons the authority; no
native function or literal fallback is selected.

## Rejected alternatives

- One immutable invocation snapshot per component is rejected because later
  fields cannot see earlier writes.
- Eagerly substituting every configuration field at compile time is rejected
  because getter timing and cache behavior are observable.
- Cloning `BuiltinFunctions` per user is rejected because it resets run-shared
  state and changes counter/file behavior.
- Rolling back only variables while claiming random/counter/file/script
  effects were rolled back is rejected as false atomicity.
- Always committing every partial failure is rejected because infrastructure
  failures and uncertain external effects are not JMeter semantic outcomes.
- Recovering poisoned locks is rejected because state consistency is no longer
  established.
- Implementing `per_iteration` as an ordinary preprocessor is rejected because
  callback count and timing differ.

## Verification requirements

Deterministic tests cover:

- all 49 names with exact case, arguments, occurrence identity, and required
  capability classification;
- compound and nested argument left-to-right order;
- `UserParameters` sequential visibility, duplicate last-wins, short/long
  zipped rows, shared clone lock, and poison handling;
- `per_iteration` exactly once at the nearest controller boundary versus
  per-preprocessor execution;
- test-plan `Arguments` dynamic first-name double evaluation, first-wins, and
  skipped duplicate values;
- `RegExUserParameters` early no-op and exact getter/effect order;
- running-version, sampling-start, cache-disabled, and per-iteration cache
  state transitions;
- one shared run registry, user cleanup, fresh-run reset, and concurrent
  bounded state;
- ordered journal commits for variables, properties, counters, random, and
  file cursors;
- `CommitWithDiagnostic`, abort-before-effect, uncertain/poisoned external
  effect, stale generation, cancellation, limits, and every poison path; and
- bridge round trips for occurrence, cache, overlay, effect journal,
  generation, outcome discriminant, bounds, and redaction.

Pinned Apache JMeter 5.6.3 differential evidence is required for read counts,
partial-expression behavior, function cache policy, stateful effects,
iteration timing, Java 8/17 differences, and external engines. Unit tests alone
do not promote `FUNC-001`, `FUNC-002`, `ELEM-005`, or `ELEM-008`.

## Consequences

Expression timing becomes an explicit compiled-field and lifecycle contract,
while stateful effects have one run authority and truthful failure semantics.
Components can reproduce sequential JMeter evaluation without exposing live
runtime maps or claiming rollback of effects that cannot be reversed.
