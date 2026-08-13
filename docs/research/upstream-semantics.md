# Apache JMeter upstream semantics (v1)

This document is a clean-room behavioral map for `jmeter-rs`. It describes
observable contracts to reproduce, not code to copy. It contains no Rust
implementation. The compatibility claim must always name a JMeter release,
JVM, component class path, and property profile; “compatible with JMeter” is
not a sufficiently precise test target.

## Baseline and reading guide

The repository currently declares Apache JMeter **5.6.3** as its first
compatibility profile in [`compat/profiles/jmeter-5.6.3.json`](../../compat/profiles/jmeter-5.6.3.json).
That profile pins release source commit
[`34a2785748e9e0b14702595e8682c387869deda3`](https://github.com/apache/jmeter/tree/34a2785748e9e0b14702595e8682c387869deda3).
The initial source reading also used the then-current Apache source snapshot
[`ad6ecbd175a1bc24dae56e999d10f020c0c80a42`](https://github.com/apache/jmeter/tree/ad6ecbd175a1bc24dae56e999d10f020c0c80a42)
to locate implementation details. Those snapshots are not interchangeable:
release conformance must run the exact profile artifact and source, and any
difference found between them becomes a version-specific compatibility note.

The official [test-plan execution-order manual](https://jmeter.apache.org/usermanual/test_plan.html)
is the normative high-level description. The Apache source links below are
the normative detail for the pinned implementation. Source behavior that is
not documented as an API guarantee is an oracle-test target rather than a
Rust design assumption.

## Primary references

Only Apache/JMeter primary material is used here:

* [JMeter test plan and execution order](https://jmeter.apache.org/usermanual/test_plan.html)
* [Component reference](https://jmeter.apache.org/usermanual/component_reference.html)
* [Listeners and result files](https://jmeter.apache.org/usermanual/listeners.html)
* [Properties reference](https://jmeter.apache.org/usermanual/properties_reference.html)
* [Remote testing](https://jmeter.apache.org/usermanual/remote-test.html)
* [Getting started and non-GUI operation](https://jmeter.apache.org/usermanual/get-started.html)
* [JMeter 5.6.3 source tree](https://github.com/apache/jmeter/tree/34a2785748e9e0b14702595e8682c387869deda3)
* [SaveService aliases](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/bin/saveservice.properties)
* [SaveService upgrades](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/bin/upgrade.properties)

The most useful implementation entry points are:

* [`HashTree`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/jorphan/src/main/java/org/apache/jorphan/collections/HashTree.java)
  and [`ListedHashTree`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/jorphan/src/main/java/org/apache/jorphan/collections/ListedHashTree.java)
* [`TestElement`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/core/src/main/kotlin/org/apache/jmeter/testelement/TestElement.kt),
  [`AbstractTestElement`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/core/src/main/java/org/apache/jmeter/testelement/AbstractTestElement.java),
  and [`TestPlan`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/core/src/main/java/org/apache/jmeter/testelement/TestPlan.java)
* [`SaveService`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/core/src/main/java/org/apache/jmeter/save/SaveService.java),
  [`ScriptWrapper`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/core/src/main/java/org/apache/jmeter/save/ScriptWrapper.java),
  [`ScriptWrapperConverter`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/core/src/main/java/org/apache/jmeter/save/converters/ScriptWrapperConverter.java),
  and [`NameUpdater`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/core/src/main/java/org/apache/jmeter/util/NameUpdater.java)
* [`StandardJMeterEngine`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/core/src/main/java/org/apache/jmeter/engine/StandardJMeterEngine.java),
  [`PreCompiler`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/core/src/main/java/org/apache/jmeter/engine/PreCompiler.java),
  and [`TurnElementsOn`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/core/src/main/java/org/apache/jmeter/engine/TurnElementsOn.java)
* [`TestCompiler`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/core/src/main/java/org/apache/jmeter/threads/TestCompiler.java),
  [`JMeterThread`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/core/src/main/java/org/apache/jmeter/threads/JMeterThread.java),
  and [`ThreadGroup`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/core/src/main/java/org/apache/jmeter/threads/ThreadGroup.java)
* [`SampleResult`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/core/src/main/java/org/apache/jmeter/samplers/SampleResult.java),
  [`SampleEvent`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/core/src/main/java/org/apache/jmeter/samplers/SampleEvent.java),
  and [`ResultCollector`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/components/src/main/java/org/apache/jmeter/listeners/ResultCollector.java)
* [`HTTPSamplerBase`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/protocol/http/src/main/java/org/apache/jmeter/protocol/http/sampler/HTTPSamplerBase.java),
  [`CookieManager`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/protocol/http/src/main/java/org/apache/jmeter/protocol/http/control/CookieManager.java),
  [`CacheManager`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/protocol/http/control/CacheManager.java),
  and [`AuthManager`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/protocol/http/src/main/java/org/apache/jmeter/protocol/http/control/AuthManager.java)
* [`RemoteJMeterEngineImpl`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/core/src/main/java/org/apache/jmeter/engine/RemoteJMeterEngineImpl.java),
  [`ClientJMeterEngine`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/core/src/main/java/org/apache/jmeter/engine/ClientJMeterEngine.java),
  and [`DistributedRunner`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/core/src/main/java/org/apache/jmeter/engine/DistributedRunner.java)

The source paths are links rather than copied source. The implementation is
Apache's; this document extracts behavior and names boundaries for an
independent implementation.

## Behavioral contract at a glance

For a normal local run, the externally visible pipeline is:

```text
JMX -> aliases/converters -> ordered test tree
    -> disabled/replacable-element preparation
    -> per-test variable/function preparation
    -> per-thread controller/compiler state
    -> config -> pre-processors -> timers -> sampler
    -> post-processors -> assertions -> listeners/result sinks
```

The contract has several non-obvious consequences:

1. A plan is a tree, not a flat list. A controller determines sampler order;
   the nearest applicable scope supplies configuration and listeners.
2. Variables belong to a thread. JMeter properties are process-global. A
   remote worker has its own property space and filesystem.
3. A sampler can produce a parent result plus sub-results, or no result. A
   null result skips post-processors, assertions, and listener notification.
4. Timers delay a sampler and are additive within the applicable scope. They
   are not independent background tasks.
5. Error policy is a thread-group policy applied after a sample; “stop test”
   and “stop test now” are observably different.
6. A distributed plan is executed in full by every remote server. Remote
   execution is replication, not automatic thread sharding.
7. JMX compatibility is a serialization contract, including aliases,
   historical aliases, property order, encoding, and tree order—not merely a
   parser for the element names visible in the GUI.

## Upstream module map and proposed Rust boundaries

The following decomposition preserves upstream concepts while avoiding Java
class-loader coupling. A boundary is a recommendation, not a promise that
every upstream package becomes a Rust crate.

| Upstream responsibility | Primary source area | Rust boundary | Compatibility reason |
| --- | --- | --- | --- |
| Test elements and typed properties | `org.apache.jmeter.testelement` | `model` | Names, enabled state, running-version snapshots, and property order are shared by every component. |
| Ordered/identity test tree | `org.apache.jorphan.collections` | `tree` | Traversal and duplicate identity behavior affect compilation and JMX. |
| Alias/converter/upgrade loading | `org.apache.jmeter.save` and `bin/*.properties` | `jmx` | Keep versioned wire compatibility separate from runtime behavior. |
| Element preparation and scope compilation | `engine`, `threads.TestCompiler` | `compile` | Build immutable per-sampler execution packages from a plan. |
| Engine, thread groups, and cancellation | `engine`, `threads` | `engine` | Own lifecycle, scheduler, group policy, and interruption contracts. |
| Controllers | `controllers` | `controllers` | Stateful iteration/selection must be isolated and testable with a virtual clock. |
| Sampler/timer/processor/assertion contracts | `samplers`, `timers`, `preprocessors`, `postprocessors`, `assertions` | `execution` plus component crates | Keep the phase protocol stable while components remain replaceable. |
| Sample result/event and sinks | `samplers`, `listeners`, `reporters` | `results` | Result hierarchy and save configuration are a compatibility surface. |
| HTTP protocol state | `protocol/http` | `http` | Cookie/cache/auth/header state must have explicit per-thread ownership. |
| Remote execution and sample transport | `engine`, `samplers` | `remote` | Rust-native transport is possible, but Java RMI is a separate adapter. |
| Plugins/scripts/drivers | classpath and component modules | `adapters` | External capabilities must be declared, versioned, and never silently emulated. |

Recommended dependency direction is `model/tree` -> `jmx` and `compile` ->
`engine`/`execution` -> `results`; `http` and external adapters depend on
the sampler/result contracts, not on the engine's concrete scheduler.

This is a conceptual upstream decomposition. The binding workspace names and
dependency direction are maintained in [the architecture document](../architecture.md);
the names in this research table must not be read as a promise that separate
`tree`, `compile`, `engine`, or `execution` crates exist.

## Test elements, properties, and tree semantics

### TestElement state

The core element keys include `TestElement.name`, `TestElement.gui_class`,
`TestElement.enabled`, `TestElement.test_class`, and
`TestPlan.comments`. `AbstractTestElement` stores properties in an insertion-
preserving map. Property values are typed (string, boolean, integer, long,
double, collection, map, object, or nested element property), and an element
may have temporary properties that are not serialized.

The following invariants are required:

* A property is addressed by its exact upstream name; Rust field names are
  not the wire contract.
* Property insertion order is retained for normalized JMX output and can be
  observed by converters and plugins.
* Cloning copies property values and creates an independent per-thread
  element state. Runtime-only state must not leak between thread clones.
* `setRunningVersion` snapshots the element's test-start state;
  `recoverRunningVersion` restores it. This is used when a compiled package
  is finished and when a plan is reused.
* `enabled=false` is not equivalent to an element that was never present;
  engine preparation removes disabled elements from the executable subtree.
  Serialization still preserves the element and its disabled property.

`TestPlan` additionally owns user-defined variables, functional-mode and
serialization flags, teardown-on-shutdown, and base/classpath setup. Test
start/finish opens and closes JMeter's file-server context. These settings
must not be accidentally treated as ordinary sampler scope.

### HashTree and ListedHashTree

`HashTree` is a map from an object key to a child tree. The current upstream
implementation uses identity-based key semantics; two distinct element
instances that compare equal can therefore be separate branches. `add` merges
into an existing identity branch, while `set` replaces its child subtree.
Traversal is depth-first and invokes visitor callbacks when entering and
leaving nodes.

`HashTree` itself does not provide a portable ordering guarantee. JMX uses
`ListedHashTree`, which retains insertion order in a separate list and returns
that order from `list()`/`getArray()`. Runtime code frequently expects a
listed tree for deterministic component lookup. A Rust tree should make the
choice explicit rather than relying on a hash-map iteration accident.

The invariants to preserve are:

* each node has one key and one child tree;
* adding the same identity key merges children, while replacing a key can
  change the path identity;
* listed traversal is preorder/depth-first with child insertion order;
* an empty leaf still has enter/leave traversal semantics;
* duplicate-looking nodes are not deduplicated by name or serialized
  equality;
* the JMX representation alternates a node element and its child `hashTree`.

Whether an unordered `HashTree` is ever intentionally exposed by a given
component is not an API contract. Treat exact ordering in those cases as an
oracle target.

## JMX and SaveService compatibility

### Wire shape

`SaveService` loads aliases and converters from
[`bin/saveservice.properties`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/bin/saveservice.properties).
The XML wrapper is a `jmeterTestPlan`/`ScriptWrapper` with a root
`hashTree`. The script wrapper converter writes a JMX `version="1.2"`
attribute, a SaveService properties version, the JMeter version, and then the
alternating node/child-tree sequence.

Common structural aliases include `jmeterTestPlan`, `hashTree`, `boolProp`,
`collectionProp`, `doubleProp`, `elementProp`, `intProp`, `longProp`,
`mapProp`, `objProp`, and `stringProp`. Component aliases map GUI and test
class names to runtime classes. Multiple historical aliases can map to the
same class; loading must accept them, while saving uses the configured
primary alias.

The compatibility invariants are:

* accepted aliases are the profile's alias table, not only today's class
  names;
* a well-formed element with an unknown class is retained as an opaque,
  diagnosable placeholder so its subtree can round-trip; malformed structure
  or missing required `guiclass`/`testclass` information produces a stable load
  error. Neither case may silently drop or reinterpret the subtree;
* the alternating `element`, `hashTree`, `element`, `hashTree` structure is
  preserved;
* the order of nodes and properties is retained unless a documented
  normalization pass changes it;
* null property values are encoded as empty values in the legacy converter;
* version 1.0 property/string values use UTF-8 URL encoding, while later
  versions use the corresponding plain representation;
* the current file encoding is UTF-8 and root metadata is versioned;
* SaveService conversion is profile-dependent and must not execute arbitrary
  code while merely parsing an untrusted plan.

`NameUpdater` applies [`bin/upgrade.properties`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/bin/upgrade.properties)
to historical class names, GUI/test-class attributes, property names, and
some property values. A mapping to an empty name means that the old property
is intentionally dropped. This table is part of the profile and must be
versioned like a schema migration.

### Serialization test obligations

The JMX layer needs fixtures for a minimal plan, duplicate names, disabled
nodes, nested controllers, every structural property type, non-ASCII values,
legacy aliases, old version strings, an unknown class, a missing subtree, and
malformed XML. Each fixture should be tested in both directions:

1. load Java JMeter output and execute it;
2. save a loaded plan and compare a documented normalized form;
3. load Rust output in the pinned Java JMeter and execute it;
4. assert that an expected rejection is the same class of failure.

Do not byte-compare timestamps, root version/JMeter metadata, or other fields
that Java deliberately rewrites. Do compare class aliases, property values,
tree order, and semantic node identity. The Java upstream
[`TestSaveService`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/core/src/test/java/org/apache/jmeter/save/TestSaveService.java)
and related converter tests are useful fixture sources.

## Engine and test lifecycle

`StandardJMeterEngine` configures one test tree, finds the `TestPlan`, reads
serialization and teardown flags, and prepares the tree. At run time the
observable sequence is:

1. initialize sample-variable names and test context;
2. run a pre-compiler over the tree;
3. set running-version snapshots and notify test-state listeners of start;
4. identify setup, main, and teardown thread groups;
5. compile sampler packages and start setup groups;
6. wait for setup groups (serialized groups are waited one at a time);
7. start main groups, respecting the serialized flag;
8. wait for main completion or cancellation;
9. start teardown groups if applicable;
10. notify listeners of test end and clear the test context.

The exact ordering of setup/main/teardown notifications and the behavior when
one group fails must be captured by a local engine trace fixture. A teardown
group can be configured to run on shutdown; an immediate stop can bypass it
depending on the stop path and flag.

`PreCompiler` has two meanings. On a local engine it replaces functions and
variables in elements and initializes TestPlan/Arguments variables. On the
remote client it primarily prepares client-side result collectors and a
read-only variable view; remote samplers must evaluate their values on the
server. This difference is important: applying client substitution to the
whole remotely executed tree changes semantics.

The engine's disabled-element pass removes disabled elements and expands
replaceable controllers before normal compilation. Include/Module and other
replaceable elements therefore require a resolved executable subtree, not a
runtime “skip” bit alone.

## Thread groups, scheduling, and cancellation

### Thread construction

Each thread gets a clone of the executable tree, a thread-local
`JMeterVariables`, a `JMeterContext`, a thread number/name, and a controller
state. The top controller initializes once per thread. The thread traverses
the compiler before sampling and notifies `ThreadListener`s at start and
finish.

JMeter variables are not shared between threads. JMeter properties are
process-wide. A same-user-on-next-iteration option controls whether
per-user state such as HTTP cookies is retained between iterations.

### Ramp-up and scheduler

For a non-delayed group, the first thread starts immediately and later
threads are spread across the ramp-up interval. With ten threads and a
100-second ramp, the tenth thread is scheduled around 90 seconds after the
first. Actual startup accounts for elapsed time; it is not simply ten sleeps
of 10 seconds. Delayed start uses a starter mechanism and can use daemon
threads.

The scheduler's delay and duration are evaluated between samples. A sampler
already waiting on network I/O is not guaranteed to be interrupted by an
ordinary duration boundary. Timer delay can carry a thread over its end time.
Invalid negative/ill-formed scheduling values result in a test-stop error.

The `serialized` TestPlan option sequences thread groups, not the individual
threads inside one group. Group-local concurrency remains concurrent.

### Error and stop policy

After a sample, the thread group `on_sample_error` policy can continue, start
the next loop, stop the current thread, stop the test after current samples,
or stop the test immediately. A sampler/result can also set stop-thread,
stop-test, stop-test-now, or a logical action. These flags are not equivalent
to an assertion failure: a failed assertion normally changes result status,
then the group policy decides what to do.

Graceful test stop asks groups/threads to finish at a safe boundary. Immediate
stop asks interruptible samplers to stop and may interrupt JVM threads; it has
different wait and process-exit behavior, especially in non-GUI mode. A Rust
engine needs separate cancellation tokens for graceful and immediate stop,
and a component-facing interruption hook. Never implement both as one
boolean.

## Per-sampler execution protocol

`TestCompiler` traverses the tree and builds a `SamplePackage` for each
sampler. The package contains the sampler and applicable configuration
elements, timers, pre-processors, post-processors, assertions, listeners,
and controller/transaction context. Ancestor scopes are collected while
walking the path; configuration elements are merged into the sampler unless
the component opts out of merging. Compiler maps are identity-based so a
same-named sampler in another branch has independent scope.

For each controller-selected sampler, `JMeterThread` performs this protocol:

1. set current sampler/thread context;
2. merge/apply configuration elements;
3. run applicable pre-processors;
4. evaluate and add all applicable timers (timer delays are additive);
5. sample if the thread is still running;
6. if the result is non-null, update timing/thread counts and sub-results;
7. run post-processors;
8. run assertions, including their configured result scopes;
9. notify applicable sample listeners/result sinks;
10. finish compiler package state and apply stop/logical-action flags.

If the sampler returns `null`, steps 6–9 are skipped. This is observable for
flow-control and special samplers. Listener notification is therefore not a
simple “sampler called” event.

The documented high-level order is configuration, pre-processors, timers,
sampler, post-processors, assertions, and listeners. Within each category,
scope and tree order are relevant; exact nearest/outer ordering in obscure
plugin combinations is not a stable public API and belongs in an oracle
fixture.

### Component contracts

* **Sampler:** performs one operation and returns a `SampleResult` (possibly
  with sub-results). Flow-control samplers may return no result.
* **Controller:** `next`/done state selects the next sampler and owns
  iteration state. It may emit logical actions or replace its subtree.
* **Timer:** returns a delay; applicable timers are summed. A modifiable
  timer is affected by the timer factor property; a non-modifiable timer is
  not.
* **Pre/post-processor:** mutates variables/request/result state at its phase.
* **Assertion:** evaluates a result and appends an assertion result; an
  assertion failure changes success status and can trigger group error policy.
* **Listener:** observes sample events at the listener's scope. It must not
  become a hidden scheduler dependency.

## Controllers and special execution elements

`GenericController` walks an ordered child list recursively. `LoopController`
uses `-1` for forever, zero for no iterations, and stores a per-controller
index under a `__jm__<name>__idx` variable. Nested loops multiply visits.
The Thread Group's own loop setting is a separate boundary around the top
controller.

If/While/OnceOnly/Interleave/Random/RandomOrder/Throughput and transaction
controllers are stateful; a clone must not share their counters. The If
Controller can evaluate once or at every iteration, and conditions can use
the last-sample-success state. While conditions can therefore change as
assertions run.

Transaction Controller creates an aggregate transaction result from child
samplers (with optional timers and parent/sub-result behavior). Module and
Include controllers resolve/replace subtrees before execution. A controller
that is disabled or unresolved is not safely represented by “return no
sample” because it changes sibling ordering and scope.

At minimum, controller unit tests need nested loop, zero/forever loop,
logical-action, random-seed, transaction, module/include, and error-policy
fixtures. Random and concurrent controller output should be compared as
invariants or under a fixed seed, not as an accidental order.

## Sample results, events, and listeners

### SampleResult invariants

`SampleResult` carries label, response code/message, success, request/response
data and headers, data type/encoding, start/end/elapsed/idle/latency/connect
times, byte counts, thread/group counts, assertions, sub-results, stop flags,
logical actions, and an ignore flag. `sampleStart`/`sampleEnd` and the
configured clock mode determine timestamps; elapsed time accounts for idle
time. Strings/data are represented as non-null values in normal serialization.

Adding a sub-result updates the parent's end time and aggregate byte counts.
Upstream normally renames child labels to a parent/index form unless
functional mode or the sub-result-renaming property disables it. This makes
result hierarchy and label normalization a compatibility surface.

`SampleEvent` captures the result, thread/group identity, variables selected
by `sample_variables`, host identity, and transaction-event state at
notification time. It is not a live view of later-mutated variables.

### Result sinks and save formats

`ResultCollector` shares output files by canonical path, writes XML headers or
CSV field names according to `SampleSaveConfiguration`, filters by success or
error mode, avoids duplicate writes of the same marked result, and closes
XML with a final `</testResults>` at test end. It can append to an existing
JTL after removing/replacing its closing marker. The listener's scope controls
which events it receives.

Official [`properties_reference.html`](https://jmeter.apache.org/usermanual/properties_reference.html)
defines the `jmeter.save.saveservice.*` fields. The profile must record each
field set, timestamp mode, XML/CSV mode, response-data policy, hostname
policy, and `sample_variables`. CSV and XML are not interchangeable: response
data, assertions, sub-results, and timestamps have different representations.

Remote sample senders include Standard (synchronous), Hold, Batch,
Statistical, Stripped, StrippedBatch, asynchronous, DiskStore, and
StrippedDiskStore modes. The default is a stripped/batched mode in supported
JMeter releases; batch size/time thresholds and flush-at-test-end are
properties. Stripping removes response payloads (and, depending on mode,
error detail) recursively while retaining result metadata and byte counts.

Result-format tests must compare normalized field sets, not only a parsed
“success” boolean. Include empty values, absent values, assertion children,
sub-result labels, parent/transaction rows, append behavior, and batch flush.

## HTTP sampler and per-thread protocol state

The HTTP implementation is a separate protocol boundary. `HTTPSamplerBase`
selects a Java or HttpClient4 implementation, handles redirects and embedded
resources, and coordinates cookie/cache/header/auth managers. Exact wire
behavior depends on implementation, JDK/HTTP library, TLS provider, proxy,
and properties; do not infer it from a single successful request.

The HTTP contract to model is:

* success codes are in the upstream success range (normally 200–399);
* redirects have method-specific behavior (301/302/303 can become GET while
  307/308 preserve the method) and a bounded redirect count;
* embedded resources can be fetched serially or by a bounded pool; resource
  failures and parent success are property-controlled;
* response data, headers, latency, connect time, bytes, and sub-result labels
  are all recorded with upstream conventions;
* cache hits can avoid a network sampler while still producing a result or
  special path according to the implementation;
* the implementation choice, retries, parser, proxy, and TLS settings belong
  in the profile.

### CookieManager

Cookies are scoped to a thread (or to an explicitly controlled shared mode),
cloned from initial test state, and selected by domain/path/secure policy.
Matching name/path/domain entries are replaced; expiry/deletion and empty
values follow the configured cookie policy. `clearEachIteration`,
`controlledByThreadGroup`, and same-user settings decide when the initial
collection is restored. The cookie implementation/policy is configurable and
must be recorded.

The manager constructs a `Cookie` header according to the selected handler,
parses `Set-Cookie` responses, and can expose cookies as variables. Tests need
host-only vs domain, path precedence, secure/non-secure, expiry/deletion,
duplicate names, and iteration-reset fixtures.

### CacheManager

Cache entries are generally per-thread and keyed by URL, with a configurable
maximum (the upstream default is 5000 entries). Cache reset is controlled by
iteration and thread-group settings. The manager honors method eligibility,
`Expires`, `Cache-Control`/`max-age`, `ETag`, `Last-Modified`, and `Vary`
semantics subject to the `useExpires` and related properties. Conditional
headers can turn a request into a revalidation rather than a full download.
Embedded-resource concurrency may require a proxy/shared cache policy.

Tests need fresh, stale, revalidated, non-cacheable, max-size-eviction, and
iteration-reset cases. Timing-sensitive expiration must use a virtual clock
or a tolerance and compare the network-visible request trace.

### AuthManager and related managers

Auth entries contain URL, user/password, domain/realm, and mechanism (BASIC,
DIGEST, KERBEROS, and historical combinations). URL matching is prefix-based
with explicit/default-port handling; current code's first matching entry and
specificity behavior should be treated as a versioned oracle, not guessed.
Credential-file formats also have backward-compatible variants. Kerberos and
TLS state depend on the JVM/security provider and are external adapters.

Header managers merge into requests. Cookie, cache, and auth managers have
special scope/selection behavior. The manual explicitly says that multiple
managers of the same special type can have an unspecified winner; do not
invent a deterministic selection rule and advertise it as JMeter behavior.

## Remote/RMI execution

The official [remote-test manual](https://jmeter.apache.org/usermanual/remote-test.html)
defines Java RMI orchestration:

* the client sends the plan to each selected server;
* every server executes the full plan, so six servers and 1000 configured
  threads produce approximately 6000 threads;
* data files are not sent; worker paths and base directories must already be
  available on each server;
* registry and dynamic engine ports, `remote_hosts`, `-R`, `-G`, `-X`, SSL,
  and reverse sample-result connections are property-controlled;
* client-side listeners receive worker results through a selected sample
  sender mode.

`ClientJMeterEngine` clones/prepares listeners and sends configuration,
properties, base directory, and script name. `RemoteJMeterEngineImpl` owns a
single active configuration and starts a `StandardJMeterEngine` on the server.
`DistributedRunner` handles multiple workers, retries, continue-on-failure,
stop, and optional remote exit.

Java RMI object serialization, registry naming, SSL socket factories, and
Java-specific sample sender wire classes are not naturally interoperable with
a Rust process. A Rust-native remote protocol should therefore be a distinct
adapter with explicit versioning. Direct Rust-to-Java-RMI interoperability is
an unknown until a bridge is specified; do not silently claim it from a
matching sample count.

Remote oracle fixtures need at least two pinned Java workers, server-local
data files, each sample-sender mode, worker failure/retry, SSL, properties
propagation, and stop behavior. Compare normalized event streams and worker
identity; never assume the result arrival order is execution order.

## Decomposition and implementation order

The clean-room implementation should be staged at boundaries where each
piece can be tested without a live network:

1. **Model/tree:** typed property map, identity/listed tree, clone and running
   version, enabled state, visitor traversal.
2. **JMX:** alias registry, versioned XML converters, upgrade mappings,
   normalized round-trip, negative parsing, and safe class policy.
3. **Execution contracts:** sampler/result/timer/processor/assertion/listener
   traits and an immutable compiled package representation.
4. **Controllers:** deterministic state machines and a virtual-clock thread
   loop; no protocol code yet.
5. **Engine:** setup/main/teardown groups, ramp/scheduler, cancellation,
   error policy, thread-local context, and test-state notifications.
6. **Results:** `SampleResult` hierarchy, event dispatch, XML/CSV sinks, and
   local deterministic listener tests.
7. **HTTP:** one selected implementation first, then cookie/cache/auth/header
   managers, redirects, embedded resources, and protocol-specific adapters.
8. **Remote:** Rust-native worker protocol, then an explicitly separate Java
   RMI bridge if interoperability is a product requirement.
9. **Plugins/scripts/drivers:** capability manifests, versioned adapters, and
   stable unavailable-capability errors.

This ordering prevents HTTP or remote details from defining the core lifecycle
and keeps every boundary usable by a fake sampler in integration tests.

## Conformance, unit, integration, and oracle tests

No one test category is sufficient for JMeter compatibility.

### Unit tests

Use deterministic, side-effect-free tests for:

* property types, insertion order, clone independence, temporary properties,
  and running-version recovery;
* identity vs listed tree merge/replace/remove/traversal behavior;
* aliases, upgrade mappings, URL encoding, converter edge cases, and root
  metadata normalization;
* controller counters, nested loops, logical actions, condition state, and
  transaction aggregation;
* timer summation/factor and scheduler calculations with a virtual clock;
* sample timing, sub-result aggregation/renaming, assertion status, ignore
  and stop flags;
* cookie matching/reset, cache freshness/revalidation/eviction, and auth URL
  selection;
* CSV/XML field selection and append/finalization rules.

### Local integration tests

Run a one-process plan with fake samplers, timers, processors, assertions, and
listeners. Assert the complete trace for configuration → pre → timer →
sampler → post → assertion → listener, plus setup/main/teardown order,
serialized groups, ramp/scheduler, disabled/replaced elements, nested
controllers, transactions, null results, and every stop policy. Use a fake
clock and deterministic sampler results; wall-clock durations should only be
tested as bounded scheduling behavior.

Run a local deterministic HTTP server for redirects, cookies, cache headers,
auth challenges, embedded resources, connection failures, and response
metadata. Include one fixture per HTTP implementation selected by the profile.

### Java oracle/golden tests

For every compatibility claim, run the same fixture with the pinned Java
JMeter artifact and Rust, recording:

* JMX load/save normalized form;
* sampler/controller trace and event hierarchy;
* labels, response code/message, success, assertion results, ignore/stop
  flags, byte counts, and sub-result order;
* thread/group names, iteration values, and selected sample variables;
* result XML/CSV fields and append behavior;
* remote worker identities and normalized arrival events.

Normalize only declared nondeterminism: timestamps, hostnames, random values
when a seed cannot be controlled, connection IDs, and concurrent arrival
order. Keep raw artifacts for diagnosis. A test that merely checks that both
engines return HTTP 200 is not an oracle for JMeter semantics.

The Apache test suite contains useful behavior targets, including
[`TestSaveService`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/core/src/test/java/org/apache/jmeter/save/TestSaveService.java),
[`TestTestCompiler`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/core/src/test/java/org/apache/jmeter/threads/TestTestCompiler.java),
[`TestLoopController`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/core/src/test/java/org/apache/jmeter/control/TestLoopController.java),
[`TestIfController`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/components/src/test/java/org/apache/jmeter/control/TestIfController.java),
and [`TestJMeterThread`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/core/src/test/java/org/apache/jmeter/threads/TestJMeterThread.java).
Confirm paths against the exact profile source before importing a fixture;
test names and paths can move between releases.

## Explicit unknowns and required oracle work

These items are intentionally unresolved in v1. They must not be silently
filled in by a Rust-specific guess:

1. **Release drift.** The source reading included an Apache HEAD snapshot,
   while the initial profile is 5.6.3. Build a release-pinned semantic diff
   and run all golden fixtures against the exact release.
2. **Unordered tree iteration.** `HashTree` identity-map iteration is not a
   stable ordering contract. Determine, per component, whether Java happens
   to expose that order; use a golden fixture if it matters.
3. **Same-category scope order.** Manuals state scope/type/tree ordering, but
   plugin and compiler accumulation can expose subtle nearest/outer order.
   Trace nested config/timer/assertion/listener combinations against Java.
4. **SaveService extension surface.** Third-party aliases, converters,
   object properties, XStream security allowlists, and plugin class loading
   need a declared capability policy and negative fixtures.
5. **Controller resolution.** Module and Include path resolution, base
   directory changes, GUI/non-GUI differences, and recursive replacement
   edge cases require Java fixtures.
6. **Scripting and dynamic classes.** BeanShell, JSR223/Groovy, Java
   functions, and arbitrary plugins depend on the JVM/classpath. They are
   external adapters until a bridge and sandbox policy are specified.
7. **RMI compatibility.** Rust-native transport semantics can be specified,
   but Java RMI registry/object/SSL and sample-sender interoperability need a
   concrete bridge design and a two-process oracle.
8. **HTTP library details.** Java vs HttpClient4, parser versions, connection
   pooling, retries, proxy, TLS provider, redirect edge cases, and malformed
   headers can differ. Use a local wire-trace server for each selected
   implementation.
9. **Concurrency and clocks.** Ramp timing, scheduler races, asynchronous
   embedded-resource order, batch flush, and random controller selection are
   nondeterministic. Compare invariants/tolerances or supply deterministic
   hooks; never bake one observed interleaving into the core contract.
10. **Failure text and timestamp precision.** Exact response messages,
    exception formatting, nano-time mode, and empty-vs-absent result fields
    vary by JVM and protocol implementation. Record them as profile-specific
    golden fields only where users need byte compatibility.
11. **Manager multiplicity.** The documented winner when multiple cookie,
    cache, or auth managers are in scope is unspecified. Preserve the
    documented behavior boundary and test the Java release rather than
    inventing a guarantee.
12. **Shutdown/process exit.** Daemon thread timing, interruption of blocked
    samplers, `server.exitaftertest`, and GUI/non-GUI system-exit behavior
    require isolated process tests; do not exercise destructive exit paths in
    ordinary unit tests.
13. **Optional protocols.** JDBC/JMS/LDAP/FTP/TCP/mail and database drivers
    are external capabilities. Each needs a pinned driver/service fixture;
    absence must be reported as unavailable, not treated as compatibility.

The first implementation milestone is complete only when the model/JMX/local
engine oracle matrix is passing. HTTP, remote, and plugin claims remain
separate profile entries until their corresponding unknowns have evidence.
