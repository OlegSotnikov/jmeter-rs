# Rust engineering and testing strategy

This document is the Rust-side engineering and verification contract for a
JMeter-compatible load-test engine. It defines boundaries, seams, evidence, and
release gates for the implementation work.

The gates below describe the intended target, not the current release status.
The binding crate ledger is [the architecture document](../architecture.md).
Current automation and its deliberate gaps are summarized in the repository's
[automation policy](../../.github/README.md); no target lane below is evidence
of a compatibility claim by itself.

The compatibility target must always name an Apache JMeter distribution (and
therefore its Java version, plugins, property files, and defaults). “Compatible
with JMeter” without that tuple is not a testable claim. The JMeter user guide
and API documentation are behavioral references; the running JMeter
distribution is the oracle for behavior not fully specified in prose.

The canonical publication repository is
[OlegSotnikov/jmeter-rs](https://github.com/OlegSotnikov/jmeter-rs). Keep
architecture/research documents, source, fixtures, and CI policy in that
repository; release artifacts should identify the source commit, Rust
toolchain, JMeter profile, and dependency lock hash. Repository automation must
not fetch an unpinned “latest” JMeter or plugin at release time.

## 1. Compatibility contract

Use three explicit levels for every feature:

1. **Conformant**: the Rust engine and the pinned JMeter oracle produce the same
   observable behavior for the declared profile, modulo fields marked
   nondeterministic by the comparison manifest.
2. **Compatible with a documented difference**: the feature is implemented, but
   an intentional difference is recorded with a reason, scope, and test. This
   level is not a basis for claiming full compatibility.
3. **Unsupported**: loading or execution fails with a stable, actionable
   diagnostic. An unknown element must never silently become a different
   element.

The release profile is a versioned manifest containing:

- JMeter distribution version and the digest algorithm/value declared by the
  profile (the current 5.6.3 profile uses SHA-512);
- Java runtime vendor/version and operating-system image;
- enabled JMeter properties, user.properties, system.properties, and plugin
  JAR checksums;
- locale, timezone, default charset, hostname policy, and environment
  allowlist;
- random seed and clock mode;
- supported samplers/controllers/configuration elements/functions;
- fields ignored or compared with tolerances in the oracle;
- expected unsupported elements and intentional differences.

The project can aim for 100% compatibility only relative to such a declared
profile. Java plugins, Groovy/JSR223 scripts, OS TLS stores, network timing,
and third-party JARs make an unconditional claim impossible to verify.
Compatibility gates should therefore be exhaustive over the declared feature
profile and explicit about the boundary.

JMeter test plans are ordered and hierarchical: controller order affects sample
order, while configuration elements, timers, assertions, and listeners scope
over descendants. Preserve both relationships in the model and test them
independently. See the [JMeter test-plan documentation](https://jmeter.apache.org/usermanual/test_plan.html).

## 2. Workspace and module boundaries

Start with a virtual Cargo workspace. Keep public data contracts small and
make the dependency graph point inward toward deterministic, runtime-agnostic
code:

| Workspace member | Responsibility | Must not depend on |
| --- | --- | --- |
| apps/jmeter-rs | CLI, process exit codes, config loading, signal handling, feature reporting | internal implementation details of protocol or plugin crates |
| crates/model | lossless/semantic test-plan and result data types, stable IDs, source locations | Tokio, HTTP clients, Java/JNI |
| crates/xml | streaming JMX/JTL parsing and writing, lexical preservation, limits | execution runtime |
| crates/expr | variable/property/function parsing and evaluation | network and filesystem side effects |
| crates/runtime | plan validation, controller state machines, virtual-user lifecycle, timers, cancellation, sample tree | concrete HTTP/TLS client |
| crates/scheduler | production scheduler plus deterministic test scheduler adapter | JMX parser and CLI |
| crates/http | HTTP sampler semantics, connection pooling, cookies, redirects, proxy and TLS configuration | JMX tree traversal |
| crates/results | SampleResult-like event model, JTL CSV/XML serialization, aggregation | CLI formatting |
| crates/plugins-api | versioned wire-level plugin protocol and capability descriptions | Rust ABI assumptions |
| crates/plugins-host | process supervision, handshake, quotas, restart and crash mapping | unsafe plugin implementation |
| crates/java-bridge | optional JMeter/JVM delegation protocol; no Java semantics in core | core execution policy |
| crates/observe | tracing, metrics, redaction, event sinks | test-plan semantics |
| crates/security | path/environment/resource policy, allowlists, limits | direct command-shell execution |
| crates/test-support | fake clock, deterministic scheduler, fake transport, local servers, canonicalizers | production binaries |
| tools/jmeter-oracle | pinned JMeter runner, plan matrix, JTL normalization/comparison | application runtime |

The names are recommendations, not an API promise. The important invariants
are:

- model, xml, and expr compile and test without an async runtime;
- runtime code receives capabilities through traits or narrow structs;
- transport, filesystem, clock, random source, plugin invocation, and result
  sinks can all be replaced in tests;
- the CLI is thin enough that most behavior can be tested without spawning a
  process;
- feature-specific dependencies are optional Cargo features, not unconditional
  dependencies of the model.

The recommendations in this table predate the binding workspace ledger. Use
`docs/architecture.md` for current paths (`jmx`, `runtime`,
`bridge-protocol`, and `plugin-host`); names such as `xml`, `scheduler`,
`plugins-api`, and `plugins-host` below are conceptual responsibilities, not
additional current crates.

Keep unsafe out of the core. If an FFI or platform API is necessary, isolate
it in a small crate with a safe wrapper, an audit note, and dedicated sanitizer
and failure tests. Configure workspace lints so accidental unsafe code is
visible; permit it only in the audited boundary.

## 3. Rust version, toolchain, and dependency reproducibility

Cargo supports a package-level rust-version field for declaring MSRV and using
it in diagnostics and dependency selection. The [Cargo Rust-version reference](https://doc.rust-lang.org/stable/cargo/reference/rust-version.html)
also recommends choosing an explicit support policy. Use that field in every
published library crate and keep it synchronized with CI.

Recommended policy:

- Pin an exact stable toolchain in rust-toolchain.toml for development and
  release builds, including rustfmt and clippy; add llvm-tools-preview only to
  jobs that need coverage or sanitizers.
- Select the edition and then choose the lowest MSRV actually supported by the
  dependency graph. If Edition 2024 is selected, its required toolchain is a
  hard lower bound; do not claim an older MSRV.
- Run a dedicated MSRV cargo check/test job, a pinned-stable full test job, and
  a latest-stable job. A new toolchain is not automatically a compatibility
  change, so the latest job should identify warnings and behavior changes
  before the pinned toolchain is advanced.
- Commit Cargo.lock for all binaries and the oracle/test tools. Run CI with
  --locked; update dependencies in reviewed, reproducible changes.
- Prefer the Rust 2024 resolver behavior when the chosen MSRV permits it, and
  verify the resolved graph under the MSRV. Cargo's [workspace documentation](https://doc.rust-lang.org/stable/cargo/reference/workspaces.html)
  and [CI guide](https://doc.rust-lang.org/stable/cargo/guide/continuous-integration.html)
  describe workspace lints, shared lockfiles, and MSRV checks.
- Do not make a nightly feature a production requirement. Nightly is for
  fuzzing, Miri, selected model tests, and sanitizers; nightly failures must
  produce a reproducible issue artifact.

Record the compiler, linker, target triple, JDK, OS image, and dependency lock
hash in every conformance and performance result. Use UTC, a fixed locale,
SOURCE_DATE_EPOCH where applicable, and an explicit environment allowlist.

## 4. Async execution, threads, and deterministic scheduling

JMeter virtual users are logical users with independent variables and lifecycle
state. They do not need one OS thread each. The production engine should use
async I/O tasks for mostly-waiting samplers and bounded blocking pools for
CPU-heavy or blocking work. A Java/Groovy/plugin call must never block an async
worker indefinitely.

Use a Tokio adapter at the application edge. Tokio's current-thread runtime is
useful for deterministic tests, while the multi-thread work-stealing runtime is
appropriate for production I/O; these are documented choices in [Tokio's runtime guide](https://docs.rs/tokio/latest/tokio/runtime/).
Do not make runtime queue order an undocumented compatibility guarantee. The
core state machines should expose an executor-neutral interface.

Required capability seams:

- Clock: wall time for timestamps and monotonic time for durations;
- Sleeper/Timer: virtual time advance and interval ticks;
- RandomSource: seeded deterministic values with separately scoped streams for
  plan, thread group, virtual user, and function invocation;
- Scheduler: submit, wake, cancel, join, and record a logical event ID;
- Transport: request/response stream with controlled partial reads, delays,
  resets, and connection reuse;
- FileSystem and Environment: explicit roots, properties, file contents, and
  environment values;
- PluginInvoker: in-process fake, subprocess implementation, timeout and crash
  injection;
- SampleSink: in-memory assertion sink, bounded queue, and disk sink.

The deterministic scheduler must be a test implementation, not a promise that
production Tokio scheduling is deterministic. It should:

- advance only when no runnable event can make progress;
- order equal-deadline events by a documented stable key (logical sequence,
  virtual-user ID, then insertion sequence);
- record every wake, timer, cancellation, and queue operation;
- expose a replay log and seed;
- detect deadlock, starvation, runaway task creation, and queue overflow;
- support scripted failures at each I/O boundary.

Every timer and retry path must be testable without sleeping. Tokio provides
paused time and start_paused test support in its [testing guide](https://tokio.rs/tokio/topics/testing),
but use the project Clock seam for core semantics so tests do not depend on a
Tokio feature. Assert both logical timing (which event becomes eligible) and
wall-clock policy (timeouts and cancellation).

Treat backpressure as behavior. Result sinks, plugin pipes, response bodies,
and scheduler queues have explicit capacity and a test for the full/closed
case. Cancellation must leave no leaked task, socket, file descriptor, process,
or result reservation. Test cancellation at every await boundary where the
operation can be dropped.

## 5. JMX/JTL XML streaming and round-trip preservation

JMeter's SaveService loads and saves JMX trees, and JTL XML has a separate
sample-result format. See the [SaveService API](https://jmeter.apache.org/api/org/apache/jmeter/save/SaveService.html)
and [JMeter listener/JTL documentation](https://jmeter.apache.org/usermanual/listeners.html).
Do not assume a JMX file is merely a convenient serialization of a Rust
struct.

Use two representations:

1. A semantic AST for execution: known element kind, ordered children,
   properties, typed values, source path, and extension payload.
2. A lossless document representation for load-edit-save: XML events or byte
   spans for declaration, comments, processing instructions, namespace
   declarations, attribute order, whitespace, CDATA/entity spelling, unknown
   attributes/elements, and untouched subtrees.

quick-xml is a reasonable streaming reader/writer candidate: its [current documentation](https://docs.rs/quick-xml)
describes a StAX-like event API and Tokio support. Its MIT license is
permissive. It must not be treated as a byte-for-byte round-trip engine by
itself; a writer may normalize quoting, escaping, whitespace, or empty-element
syntax. Preserve original raw spans for unchanged regions and use a canonical
writer only for changed semantic nodes. Serde derives are useful for auxiliary
formats, but a generic XML serde mapping will usually lose the extension and
lexical information required by JMX round-trip compatibility.

Parsing policy:

- stream from Read/AsyncRead and enforce byte, depth, attribute-count,
  attribute-length, text-length, and total-node limits before allocation;
- reject or preserve unknown elements according to the compatibility profile;
- never resolve external entities or fetch network resources while parsing;
- retain source byte offsets and a JMX tree path in diagnostics;
- distinguish malformed XML, valid-but-unknown JMeter element, invalid property
  value, and unsupported execution feature;
- reject duplicate attributes and malformed encodings according to the XML
  parser's strict mode;
- parse JMeter aliases and Java class names as data, not as executable code.

Round-trip test categories:

- parse -> write with no edits: lexical equality for fixture regions where
  preservation is promised, otherwise canonical semantic equality;
- parse -> mutate one property -> write: only the intended node and required
  parent metadata may change;
- unknown plugin elements and attributes survive an edit to a sibling;
- comments, processing instructions, CDATA, entities, mixed whitespace, empty
  elements, namespaces, UTF-8 BOM, and non-ASCII values survive;
- malformed/truncated/oversized inputs return bounded errors and never panic or
  allocate without limit;
- JTL XML and CSV outputs round-trip through the result model while preserving
  selected fields and nested sample ordering.

Maintain a canonical comparison format for tests: sorted only where JMeter
defines a map, never where it defines ordered children; normalized line endings
and timestamps only when the manifest says so. Keep a raw diff for debugging.

## 6. HTTP, TLS, and proxy strategy

Make HTTP behavior a protocol crate behind a transport trait. The compatibility
surface includes more than status and body: method/body construction, duplicate
headers, cookies, redirects, authentication, URL encoding, DNS, connection
reuse, HTTP/1.1 versus HTTP/2, proxy routing, timeouts, TLS handshake, response
decompression, embedded-resource parsing, local bind, and byte/latency
accounting.

Recommended starting point:

- use hyper when exact HTTP behavior, streaming, or low-level connection
  control is needed; its [documentation](https://docs.rs/hyper/latest/hyper/)
  describes it as a low-level async HTTP/1 and HTTP/2 building block;
- use reqwest only behind the project transport adapter when its convenient
  client features match the required semantics. Its [documentation](https://docs.rs/reqwest/latest/reqwest/)
  explicitly notes system proxies are enabled by default and exposes optional
  TLS, cookie, decompression, SOCKS, and HTTP/2 features;
- default to rustls for a self-contained TLS stack, but expose a native-TLS
  option only where matching the platform/JVM trust store is required. Rustls
  supports TLS 1.2/1.3 and selectable crypto providers; see its [crypto provider documentation](https://docs.rs/rustls/latest/rustls/crypto/);
- represent proxy selection explicitly. Do not accidentally inherit
  HTTP_PROXY, HTTPS_PROXY, or ALL_PROXY in conformance runs. If the
  compatibility profile says environment proxies apply, test that behavior
  explicitly and record the environment.

HTTP integration tests must use local deterministic servers. Cover:

- normal HTTP/1.1, chunked response, trailers, empty body, large streaming
  body, partial reads/writes, connection close and reuse;
- redirects (method-preserving and method-changing cases), cookies,
  duplicate/combined headers, form/multipart bodies, compression, and
  response encoding;
- TLS with a generated local CA, expired/not-yet-valid/wrong-name chains,
  client certificates, SNI, TLS versions, ALPN, and trust-all/verify modes;
- HTTP proxy, HTTPS CONNECT proxy, proxy authentication, no-proxy matching,
  proxy failure, and proxy timeout;
- DNS failure, connection refusal, connect/read/overall timeout, cancellation,
  remote reset, malformed protocol, and response-size limit;
- deterministic embedded-resource extraction using fixed HTML/CSS fixtures.

For every sampler result, define which clock points determine timeStamp,
elapsed, latency, connect, idle, bytes, and sentBytes. Compare those fields
with exact values only on a controlled local server; otherwise use explicit
tolerance and verify semantic event order.

## 7. Plugins, ABI, and Java/Groovy/JSR223 compatibility

Rust's native ABI is not a stable plugin ABI. The [Rustonomicon FFI chapter](https://doc.rust-lang.org/nomicon/ffi.html)
explains the required care at foreign boundaries. Never pass Rust trait
objects, String, Vec, or references across independently compiled dynamic
libraries as a compatibility contract.

Use a versioned wire protocol and process boundary as the default plugin
contract:

- handshake includes protocol version, plugin identity/version, capabilities,
  supported message types, and maximum message size;
- messages use length framing, explicit encoding/version, request ID,
  cancellation, deadline, and bounded response data;
- plugin process receives an allowlisted working directory and environment;
  no shell interpolation; executable path and JAR path are resolved before
  spawn;
- host enforces startup, per-call, CPU/wall-clock, memory/output, and restart
  limits; maps exit, signal, protocol, and timeout causes into stable errors;
- plugin cannot corrupt the engine's heap or crash unrelated virtual users;
- capability negotiation prevents a newer plugin from being mistaken for an
  older one.

Options and tradeoffs:

| Option | Use | Risk |
| --- | --- | --- |
| Subprocess wire protocol | Default for Java and untrusted/third-party plugins | IPC overhead; protocol must be versioned and tested |
| Stable C ABI dynamic library | Carefully vetted native plugins | unsafe ownership, allocator/unwind/platform hazards; requires ABI conformance suite |
| abi_stable-style Rust ABI layer | Only after a measured need | extra dependency and runtime contract; still needs versioning, security review, and maintenance ownership |
| JNI in the Rust process | Optional expert mode | JVM lifecycle/thread attachment, unsafe FFI, classloader leaks, JVM crash isolation, and difficult sanitizer coverage |
| WASI/Wasm component | Rust-native sandboxed plugins | Java/JMeter plugin compatibility is not provided; WASI feature and host support evolve |

For exact JMeter Java plugin behavior, delegate to a real JVM with the pinned
JMeter classpath. A pure-Rust reimplementation of Java class loading,
BeanShell/Groovy/JSR223 engines, Java object identity, and JMeter context
objects is not a compatibility strategy.

Supported Java modes should be explicit:

1. Oracle/delegation mode: run the complete JMeter plan in the pinned JVM.
2. Java-plugin worker: Rust executes compatible native elements and asks a JVM
   worker to execute a Java sampler/plugin over the wire.
3. JNI mode: opt-in in-process bridge for deployments that accept JVM crash
   risk.
4. Rust-native mode: documented subset with no claim that arbitrary Java
   plugins or scripts execute.

JSR223/Groovy compatibility tests must run the same script under the same
JMeter/JVM classpath and compare variables, properties, sample results, logs,
exceptions, script caching, and state persistence. JMeter documents compiled
script caching recommendations in its [best-practices guide](https://jmeter.apache.org/usermanual/best-practices.html)
and function/variable behavior in [Functions and Variables](https://jmeter.apache.org/usermanual/functions).
Unsupported scripts must identify the missing engine/classpath capability; do
not silently translate Groovy into another language.

## 8. Error taxonomy and compatibility semantics

Define a typed public error taxonomy with stable machine-readable codes and
human context. At minimum:

- Config: invalid CLI, property, environment, or feature combination;
- PlanParse: malformed XML, encoding, lexical, or size-limit failure;
- PlanModel: unknown/unsupported element, invalid property, or invalid scope;
- Schedule: timer, deadline, cancellation, deadlock, or concurrency-limit
  failure;
- Transport: DNS, connect, protocol, TLS, proxy, read/write, or timeout;
- Sampler: sampler-specific failure that should become a failed sample;
- Assertion: assertion mismatch, usually represented inside the sample;
- Script: Java/Groovy/JSR223 compile, runtime, or context failure;
- Plugin: handshake, capability, protocol, crash, quota, or version error;
- Persistence: JTL/result sink or filesystem failure;
- Internal: violated invariant or bug, with a correlation ID.

Each error should carry operation, stable code, source JMX path, sample ID,
virtual-user/thread name, retryable/terminal classification, cause chain, and
redacted diagnostic fields. Do not compare localized display messages in tests.

Distinguish process-fatal errors from sample failures. A refused HTTP
connection generally creates a failed sample and lets the plan continue
according to controller policy. An invalid plan, corrupted result sink, or
security policy violation may terminate the run. The mapping must be covered
by oracle tests.

Use thiserror or equivalent for typed library errors and an application error
wrapper for context/backtraces. Avoid returning a single erased error from
every library API. Backtraces are useful in diagnostics but must not contain
secrets or become part of conformance equality.

## 9. Observability

Instrument the same logical identifiers used by the result model:

- run ID, plan hash, profile ID, thread group, virtual-user ID, iteration,
  controller path, sample ID, parent sample ID, plugin ID, and transport
  connection ID;
- spans for plan load, thread lifecycle, controller execution, timer wait,
  sampler, assertion, script/plugin call, and result persistence;
- counters for starts, completions, failures by stable category, cancellations,
  retries, queue overflow, plugin restarts, and dropped telemetry;
- histograms for schedule delay, queue wait, connect, TLS, latency, elapsed,
  response size, and plugin call duration.

Do not put raw URLs, request bodies, cookies, authorization headers, script
source, or unbounded user IDs into high-cardinality labels. Redaction must be
central and tested. Keep a lossless per-sample result path separate from
diagnostic telemetry, because production telemetry may be sampled or disabled.

tracing is a mature structured diagnostics facade; its [documentation](https://docs.rs/tracing/latest/tracing/)
explains async-aware spans and events. A metrics facade can be added behind
observe; record the chosen exporter and its license in the dependency ledger.
Test observability with an in-memory subscriber/recorder: every sample has one
start/end, errors have one category, spans close on cancellation, and secret
fields never appear.

## 10. Security and resource limits

Treat JMX, scripts, plugin JARs, data files, responses, and result files as
potentially hostile inputs. Load testing tools often have the ability to reach
arbitrary networks and execute scripts, so secure defaults matter.

- require explicit roots/allowlists for plans, includes, CSV data, response
  files, keystores, scripts, and plugin directories;
- canonicalize paths before checking containment; test traversal, symlink,
  junction, device, and race cases on supported operating systems;
- do not invoke a shell for OS commands; use an absolute executable path and
  explicit arguments/environment. Rust's std::process::Command provides the
  process builder and pipes, but its [documentation](https://doc.rust-lang.org/std/process/struct.Command.html)
  also notes platform-specific path and environment behavior;
- cap plan size, XML depth/nodes, thread groups/users, queue sizes, response
  bytes, result retention, script output, and plugin messages;
- make SSRF-like access an explicit operator choice, with optional private
  address/metadata-service deny rules;
- redact secrets from logs, crash reports, JTLs, tracing fields, and oracle
  artifacts; test redaction with generated secret-like strings;
- use TLS verification by default in the Rust engine. The pinned JMeter
  research baseline documents a different default for HTTP samplers, so this
  is an intentional security default rather than a compatibility claim until
  the profile's configured behavior has evidence. Trust-all is test-only or
  explicitly operator-selected;
- isolate Java/plugin workers and set timeouts and OS resource controls where
  available. Before signalling, check the owned child with `try_wait`; use
  direct-child termination as the safe fallback, and permit group signalling
  only through a safe wrapper after validating a live PGID greater than one.
  Reap the exact child on success, error, timeout, and cancellation paths;
- run cargo audit/RustSec and cargo deny check for advisories, bans, licenses,
  and sources. RustSec describes these checks at [rustsec.org](https://rustsec.org/);
  cargo-deny's [license](https://embarkstudios.github.io/cargo-deny/checks/licenses/index.html)
  and [source](https://embarkstudios.github.io/cargo-deny/checks/sources/index.html)
  checks are useful but do not replace human license review.

Security tests must include malformed plans, decompression/response bombs,
oversized headers, deep controller trees, pathological regex/XPath inputs,
plugin protocol desynchronization, child-process hangs, secret leakage, and
file descriptor/process exhaustion.

## 11. Test layers and required evidence

Every behavior has a test at the lowest layer that can prove it and at least
one end-to-end test for the public contract. The following is the minimum
matrix.

### Unit tests

Run on every change, deterministic and fast. Cover:

- model invariants, stable IDs, ordering and scope;
- XML event parsing, aliases, limits, location diagnostics, canonicalization;
- expression/function parsing, escaping, nested evaluation, variable versus
  property scope, undefined-value behavior, and random/time seams;
- controller state machines, loops, conditions, timers, assertions, retries,
  result-tree nesting, and thread lifecycle;
- HTTP request construction, header/cookie/redirect policy, byte accounting,
  TLS/proxy configuration validation, and error mapping;
- plugin framing/handshake/version negotiation and resource-policy validation;
- JTL CSV/XML field selection and error/result serialization;
- redaction and stable error codes.

Unit tests should not bind a real port, use wall-clock sleeps, read the ambient
environment, or depend on a real JVM.

### Property-based tests

Use proptest (or an equivalent with a documented decision) for:

- arbitrary valid model -> serialize -> parse semantic equality;
- lossless XML edits preserve unknown nodes and untouched byte spans;
- arbitrary expression/function strings never panic and obey parser progress;
- controller execution preserves parent/child and ordering invariants;
- sample aggregation is associative where JMeter defines aggregation as such;
- generated HTTP requests obey the configured size/header/body limits;
- config merge and property precedence are idempotent and deterministic.

Persist every failing seed and minimized case under a versioned corpus. Avoid
asserting a property that merely restates the implementation; use independent
invariants or the oracle for semantics. Proptest's [reference documentation](https://docs.rs/proptest/latest/proptest/)
covers shrinking and reproducible strategies.

### Fuzz tests

Use cargo-fuzz/libFuzzer on nightly for parser and boundary crates. The Rust
Fuzz Book tooling supports minimizing inputs and coverage; see the
[cargo-fuzz repository](https://github.com/rust-fuzz/cargo-fuzz).

Targets:

- JMX/JTL XML byte streams;
- expression/function scanner;
- CSV and result-field parser;
- plugin frame decoder and malformed handshake;
- HTTP header/status/body framing and decompression limits;
- path/property/config loader;
- script output and Java-worker protocol (opaque bytes).

The invariant is no undefined behavior, panic, unbounded allocation, infinite
loop, or process hang within resource limits. Fuzz targets must not perform
network access or execute supplied scripts. Check in minimized regressions and
record the toolchain/flags.

### Model/concurrency tests

Use a deterministic scheduler for the runtime state machine and loom for small
shared-state components: cancellation, queue closure, result sink
backpressure, timer registration, virtual-user counters, and plugin supervisor
state. Loom explores interleavings, but its own documentation lists model
limitations; a passing Loom run is evidence for the modeled state space, not a
proof of all executions. See the [Loom docs](https://docs.rs/loom/latest/loom/).

Keep models finite (for example, two users, two samples, one failure) and
assert invariants such as no duplicate completion, no lost result, no task
after cancellation, and no permit leak. Run model tests in a separate job with
the required configuration flag; do not accidentally compile Loom atomics into
production.

Run Miri for unsafe wrappers, pointer/FFI adapters, and selected pure core
tests. Run AddressSanitizer/ThreadSanitizer or platform-supported equivalents
for native/FFI and process/transport boundary tests. Sanitizers are
complementary: they do not replace the type system, model tests, or the oracle.

### Integration tests

Use local deterministic services and temporary directories. Cover the complete
transport, TLS, proxy, filesystem, plugin process, result sink, and signal
boundary. Test multiple runtime configurations (current-thread and
multi-thread) and feature combinations. A failed child process must be
observable without hanging the test runner.

### Differential/oracle tests

Run the same plan and controlled fixture against JMeter and Rust, then compare
normalized event streams. Differential tests are the primary compatibility
evidence for execution semantics, functions, controllers, sample fields,
scripts, and JTL output.

### End-to-end tests

Spawn the Rust CLI exactly as users do. Exercise plan load, property and
environment overrides, logging, output files, exit status, graceful stop,
forced stop, plugin worker startup, and report/result generation. Include a
small smoke matrix in pull requests and the full profile on release/nightly
jobs.

### Performance and capacity tests

Use Criterion for isolated parser, expression, scheduler, request-building,
serialization, and aggregation benchmarks. Criterion is statistics-driven and
compares a baseline; see its [API docs](https://docs.rs/criterion/latest/criterion/)
and [analysis guide](https://bheisler.github.io/criterion.rs/book/analysis.html).

Use a separate macro benchmark harness for:

- maximum idle virtual users;
- closed-loop and open-loop request rates;
- ramp-up/ramp-down;
- HTTP/1.1 and HTTP/2 connection reuse;
- result sinks enabled/disabled and bounded;
- plugin/JVM calls;
- response sizes and embedded resources.

Pin CPU topology, governor, OS image, network fixture, compiler profile,
allocator, and data set. Compare Rust with JMeter only when the plan,
semantics, network, result retention, and observability settings match. Track
throughput, p50/p95/p99 schedule and sample latency, CPU, RSS, allocations,
open FDs, task count, and dropped results. Never optimize away a semantic
field merely to win a benchmark.

### Soak, leak, and race tests

Run scheduled 1-hour and release 8/24-hour tests with a fixed deterministic
fixture and a second realistic local service. Assert no unbounded RSS,
allocator growth, thread/task/process/FD leak, queue growth, or result
corruption. Exercise repeated start/stop, cancellation, plugin restart, TLS
reconnect, and result rotation. Capture periodic counters and a final
comparison to the first hour.

Run race/model/sanitizer jobs on all unsafe or shared-state changes. For pure
safe Rust, race failures still matter at the protocol and semantic level:
use deterministic replay and Loom where shared memory is used.

## 12. Java JMeter oracle harness

The oracle harness is a separate tool and dependency boundary. It must not
become a second implementation of JMeter behavior.

### Inputs

Each case directory contains:

- plan.jmx and optional include/data files;
- a case manifest with JMeter profile ID, expected features, seed, properties,
  environment allowlist, locale/timezone/charset, and comparison policy;
- a local fixture-server recipe or an offline deterministic transport trace;
- expected support status and known differences.

Acquire the JMeter distribution from the official release source, verify the
recorded digest, and run with its documented CLI. JMeter's command line
supports non-GUI execution (-n), test plan (-t), result log (-l), and JMeter
log (-j); see the [official getting-started and CLI documentation](https://jmeter.apache.org/usermanual/get-started.html).

The harness should invoke a command equivalent to:

~~~text
jmeter -n -t plan.jmx -l oracle.jtl -j oracle.log
~~~

Use an absolute executable path, a clean environment, a temporary working
directory, and a timeout. Store the exact command (with secrets removed) and
the distribution/JDK hashes in the artifact.

### Execution

For deterministic comparisons:

- prefer local HTTP/TLS/proxy fixtures or a recorded transport adapter;
- freeze clock and seed where the JMeter feature permits it;
- use the same property files, plan path, data files, locale, timezone,
  charset, and plugin classpath;
- set JMeter result-save properties deliberately so both sides emit the same
  fields; JMeter documents the CSV and XML fields in its [listeners guide](https://jmeter.apache.org/usermanual/listeners.html)
  and property names in the [properties reference](https://jmeter.apache.org/usermanual/properties_reference.html);
- run Java/Groovy/JSR223 cases only in an image that has the required engine and
  JARs; record classpath hashes.

### Comparison

Parse JTL CSV/XML into a neutral event stream. Compare:

- sample tree shape, parent/child ordering, labels, thread names, and sample
  counts;
- success, response code/message, assertion failures, and error category;
- body, headers, URL, cookies, encoding, and sampler data when deterministic;
- elapsed/latency/connect/idle/bytes with exact equality for local controlled
  fixtures and declared tolerances otherwise;
- variable/property side effects and script/plugin output;
- process exit status and fatal versus sample-failure mapping.

Normalize only fields declared nondeterministic: timestamps, hostnames,
ephemeral ports, random values when an oracle cannot seed them, and
environment-dependent TLS details. Emit both a structured diff and the raw
JTL/logs. A normalization rule must have a test proving it does not hide a
semantic difference.

The harness must support a “JMeter unavailable” developer mode that skips
oracle cases with a clear reason, but release conformance jobs must fail if the
declared oracle cannot run. A Rust-only test passing is never a substitute for
an unavailable oracle case.

## 13. Fixtures, corpus, and provenance

Every fixture has a provenance record:

- source URL/repository, commit or release, author/license, and retrieval date;
- whether it is original, generated, minimized from fuzzing, or copied from
  Apache/JMeter;
- exact license text/notice obligations and whether redistribution is allowed;
- input profile, expected output, and any redaction or transformation.

Do not commit customer plans, credentials, private keys, live domains, or
unlicensed JMeter/plugin samples. Prefer small original fixtures and generated
certificates. Apache JMeter distribution files and third-party plugin JARs
must be downloaded in CI or stored only when redistribution and NOTICE
requirements are understood. Keep private/copyright-sensitive corpora in a
separate CI artifact store with access controls.

Generated fixtures must record the generator version and seed. Fuzz corpora
must be minimized but not over-normalized. A fixture deleted because it is
redundant should leave its bug/regression ID in the changelog.

## 14. CI and release matrix

This is a target matrix, not a report that all lanes currently run. The current
repository automation has a pinned Rust 1.97.1 format/check/test/clippy lane
on Linux, Windows, and macOS, repository validators, and dependency/security
checks. It defines a manual/scheduled pinned-JMeter fixture-smoke workflow, but
that workflow is unconditionally disabled pending the shared process-
supervision gate; current automation does not execute Java or JMeter. It does
not yet provide the MSRV/latest/nightly, Miri, sanitizer, Loom, long-soak, or
release-provenance lanes listed below. If enabled, the oracle smoke path would
not compare Rust output or promote profile rows.

Pull request fast lane:

- format check;
- MSRV cargo check --workspace --all-targets;
- pinned-stable unit/integration tests with --locked;
- clippy with workspace policy;
- XML/property tests at a bounded case count;
- local HTTP/TLS/proxy/plugin integration smoke tests;
- cargo deny check and RustSec audit;
- one small CLI end-to-end case.

Required merge/release lane:

- Linux x86_64 (glibc) and musl, Windows, and macOS; add Linux ARM64 when
  supported deployment includes it;
- MSRV, pinned stable, latest stable, and nightly test configurations;
- all supported feature combinations, including no-Java/no-TLS/minimal builds;
- current-thread and multi-thread runtimes;
- unit, integration, full oracle/differential, end-to-end, and result-format
  compatibility suites;
- Miri, sanitizers, Loom/model tests, and fuzz smoke runs in dedicated jobs;
- JDK versions declared by the selected JMeter profile (at least its lower
  bound and the current supported LTS);
- cross-compilation/build reproducibility and clean-environment CLI test.

Scheduled lane:

- long fuzzing with retained corpus;
- Criterion/macro performance on pinned runners;
- 1/8/24-hour soak and leak checks;
- latest JMeter release/profile discovery;
- dependency update, advisory, license, and source audits.

Cache dependencies by lockfile and toolchain, not by an untracked “latest”
directory. Upload failed seeds, minimized inputs, oracle JTL/logs, replay logs,
sanitizer reports, and benchmark metadata as artifacts. A flaky test is a
failed test until it is quarantined with an owner, issue, deterministic
reproducer, and expiry date.

## 15. Recommended crate ledger

This is a shortlist, not permission to add dependencies without review. Before
adding a crate, record its exact version, MSRV, license expression, transitive
native dependencies, release activity, security history, and fallback plan.
Run cargo-deny with include-dev = true so test-only crates are reviewed too.

| Crate/tool | Proposed role | License and maintenance risk | Rule |
| --- | --- | --- | --- |
| Tokio | production async I/O/runtime and test utilities | MIT; active, but rolling MSRV and scheduler details are implementation behavior | hide behind runtime adapter; test current-thread and multi-thread |
| hyper | exact low-level HTTP/1/HTTP/2 | MIT; active and widely used; defaults/features can evolve | pin features and wrap in transport trait |
| reqwest | optional ergonomic HTTP client | MIT/Apache-2.0; active; ambient proxy/TLS defaults can change behavior | use only through explicit config and conformance tests |
| rustls | TLS | Apache-2.0/MIT/ISC; active security-sensitive project; provider/API changes need review | pin provider/trust policy and run local certificate matrix |
| quick-xml | streaming XML reader/writer | MIT; active, but lexical round-trip is not its promise | combine with raw-span preservation; fuzz parser |
| serde | auxiliary data formats and wire messages | MIT/Apache-2.0; mature | do not use a lossy XML derive as the JMX preservation layer |
| proptest | property generation/shrinking | MIT/Apache-2.0; close to feature-complete/passively maintained and has its own MSRV | pin compatible release; persist seeds; retain hand cases |
| loom | bounded concurrency model tests | MIT; active but explicitly incomplete C11 modeling | use only for finite models and document limitations |
| cargo-fuzz/libFuzzer | fuzz tooling | MIT/Apache-2.0 for tooling, with upstream LLVM components carrying their own terms | nightly/Unix constraints; keep corpus and flags |
| criterion | microbenchmarks | verify current permissive license at adoption; mature but benchmark API/runner limitations apply | use for trends, not absolute production capacity |
| tracing | structured spans/events | MIT; active | keep labels bounded and redacted |
| jni (optional) | JVM/JNI bridge | verify current license/MSRV and JNI/JVM support at adoption | isolate in optional crate; subprocess remains default |
| cargo-deny/cargo-audit | dependency policy and advisories | tooling is permissively licensed; advisory data and license detection are not complete | combine automation with human review |

The project should avoid adding a large XML DOM, a browser engine, an embedded
JavaScript VM, or a Rust dynamic-plugin ABI crate merely to make a single test
pass. Each would enlarge the compatibility and security surface. If one is
required, add it behind a feature and document its version/behavior oracle.

## 16. Definition of done for a feature

A feature is not complete when it compiles. It is complete when:

- its semantic behavior and intentional limits are documented;
- the model/parser/runtime boundaries remain respected;
- unit and property tests cover edge cases and invariants;
- malformed and resource-exhaustion inputs are bounded;
- at least one local integration test exercises real I/O if applicable;
- the JMeter oracle case exists for every claimed compatible profile;
- JTL/result and observability behavior is checked;
- cancellation, retry, error mapping, and security policy are tested;
- performance impact is measured when the feature is in a hot path;
- fixture provenance and dependency/license entries are recorded.

## References

- [Cargo Rust-version field and MSRV policy](https://doc.rust-lang.org/stable/cargo/reference/rust-version.html)
- [Cargo workspaces](https://doc.rust-lang.org/stable/cargo/reference/workspaces.html)
- [Cargo continuous integration guidance](https://doc.rust-lang.org/stable/cargo/guide/continuous-integration.html)
- [Tokio runtime](https://docs.rs/tokio/latest/tokio/runtime/)
- [Tokio testing and paused time](https://tokio.rs/tokio/topics/testing)
- [quick-xml streaming reader/writer](https://docs.rs/quick-xml)
- [JMeter test-plan semantics](https://jmeter.apache.org/usermanual/test_plan.html)
- [JMeter functions and variables](https://jmeter.apache.org/usermanual/functions)
- [JMeter component reference](https://jmeter.apache.org/usermanual/component_reference.html)
- [JMeter SaveService API](https://jmeter.apache.org/api/org/apache/jmeter/save/SaveService.html)
- [JMeter CLI/getting started](https://jmeter.apache.org/usermanual/get-started.html)
- [JMeter listeners and JTL formats](https://jmeter.apache.org/usermanual/listeners.html)
- [JMeter properties reference](https://jmeter.apache.org/usermanual/properties_reference.html)
- [Rust std::process::Command](https://doc.rust-lang.org/std/process/struct.Command.html)
- [Rustonomicon FFI](https://doc.rust-lang.org/nomicon/ffi.html)
- [hyper](https://docs.rs/hyper/latest/hyper/)
- [reqwest](https://docs.rs/reqwest/latest/reqwest/)
- [rustls crypto providers](https://docs.rs/rustls/latest/rustls/crypto/)
- [proptest](https://docs.rs/proptest/latest/proptest/)
- [Loom](https://docs.rs/loom/latest/loom/)
- [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz)
- [Criterion](https://docs.rs/criterion/latest/criterion/)
- [tracing](https://docs.rs/tracing/latest/tracing/)
- [RustSec](https://rustsec.org/)
- [cargo-deny license checks](https://embarkstudios.github.io/cargo-deny/checks/licenses/index.html)
- [cargo-deny source checks](https://embarkstudios.github.io/cargo-deny/checks/sources/index.html)
