# Performance harness design

This directory is the plan-only performance boundary for `jmeter-rs`. It
defines reproducible micro, macro, and soak configurations, resource and
threshold schemas, and a self-validating dry-run orchestrator. It does not
start a benchmark, fixture service, Java worker, container, shell, network
connection, or arbitrary child process.

The current scope is deliberately limited to `TEST-005` (cross-platform and
performance regression gates) in the `jmeter-5.6.3` compatibility profile. The
configs point at small repository fixtures and record their SHA-256 identity;
they do not claim performance or compatibility evidence. A dry-run result has
empty measurements, unevaluated thresholds, and an explicit safety envelope.

## Files

* `schema/config.schema.json` (version 3) defines the closed configuration
  contract. `execution.mode` is `dry-run-only`, process start is disabled,
  network is offline, and every future child/container entry is disabled.
* `schema/result.schema.json` (version 3) defines metadata, planned actions,
  measurements, threshold accounting, leak samples, and safety counters. A
  dry-run cannot report a threshold as passed.
* `schema/future-evidence.schema.json` (version 1) is deliberately separate:
  it is a reservation for a reviewed execution adapter and is emitted only as
  `status: not-generated` inside a dry-run result.
* `schema/collected-evidence.schema.json` (version 2) is the strict future
  evidence contract. A completed document requires a 40-hex source commit,
  immutable executable/runtime/image digests, bounded metrics and histograms,
  threshold observations, leak horizon, fixture/case bindings, and artifact
  links. `orchestrator.py` also performs cross-document validation against the
  selected config and fixture catalog. It is never emitted by this tool.
* `fixture-catalog.json` and `schema/fixture-catalog.schema.json` bind every
  performance fixture ID used here to a real checked-in path and case
  manifest. The catalog does not promote planned profile rows to evidence.
* `configs/micro.json` is a bounded parser/serialization micro plan.
* `configs/macro.json` is a bounded offline scheduler/controller macro plan.
* `configs/soak-1h.json`, `configs/soak-8h.json`, and `configs/soak-24h.json`
  are the scheduled soak modes. Their durations are exactly 3,600, 28,800,
  and 86,400 seconds; they remain dry-run declarations until a separately
  reviewed execution adapter exists.
* `orchestrator.py` performs strict stdlib-only parsing and emits a
  deterministic plan/result. There is intentionally no `run` subcommand.

## Commands

Run these from the repository root:

```sh
python3 tools/perf/orchestrator.py self-test
python3 tools/perf/orchestrator.py validate
python3 tools/perf/orchestrator.py dry-run --config tools/perf/configs/micro.json \
  --output tools/perf/artifacts/perf/dry-run-result.json
```

`self-test` loads every config, checks fixture/case digests and compatibility
references, verifies deterministic output twice, rejects duplicate-key,
non-finite, and oversized-integer JSON, exercises raw/depth/node/list/string/
hash/path/deadline/metric/unit/relationship/artifact limits, and proves that
unsafe mode and enabled-child mutations are rejected.
`validate` performs the same checks without producing a result. `dry-run` only
reads bounded files, hashes declared input, validates the generated result
against the result contract, and renders JSON; it does not invoke
`subprocess`, a shell, a socket, a JMeter launcher, a fixture server, or a
container runtime.

The output path is an explicit ordinary file path directly beneath the
configured `tools/perf` artifact root. The harness creates missing artifact
directories, rejects symlink components, uses an exact parent directory handle
plus exclusive no-follow creation, enforces `max_bytes` before and during the
write, and refuses to overwrite an existing result. Do not point it at a
source fixture or a broad directory. CI should move the JSON to its diagnostic
artifact store after validation.

## Reproducibility and metadata

Each config fixes the profile/fixture IDs and case paths, seed, `en-US` locale,
UTC timezone, UTF-8, target triple, a pinned (but not present) OS image
reference, Rust toolchain reference,
Cargo.lock SHA-256, `SOURCE_DATE_EPOCH`, an empty environment allowlist, an
ephemeral run root policy, and a controlled/monotonic clock mode. Every plan
also enumerates six truthful future OS/architecture rows (Linux, Windows, and
macOS × x86_64/aarch64); each row is `future-planned`, uses an immutable
`@sha256:` image reference, has only a hash of that textual reference, and has
a null observed artifact digest until collected. The selected reproducibility
image must exactly match its matrix row.
The dry-run renderer does
not read ambient environment, hostname, current time, random state, or tool
versions, so identical config bytes produce identical `config_sha256`, plan,
and result JSON.

Results also carry the fixture and case-manifest paths/digests, schema-pinned
orchestrator ID, and whether the source is a working tree or a committed
checkout. This working
tree is intentionally reported as `working-tree`; it is not conformance or
release evidence. A future completed run must replace it with the exact
40-hex commit identity in the collected-evidence document. Textual reference
hashes (executable/image/runtime/path identity) are distinct from immutable
artifact digests (observed bytes). JSON loading rejects duplicate object keys,
NaN/Infinity, oversized integers/input, excessive depth/nodes, and oversized
strings, lists, extension objects, and operation parameter objects. File hashes
are capped before reading.

Future collected results must add the exact compiler/JVM/platform/dependency
metadata and measured values under a versioned execution schema. Missing
required resource metrics, unavailable leak counters, and missing threshold
inputs must fail; they must not be normalized into a pass.

## Metric and threshold design

Micro plans measure operation elapsed time, completion/failure/drop/overflow
counters, RSS,
open file descriptors, threads, tasks, CPU time, allocations, dropped results,
and queue overflows. Macro plans additionally model schedule delay, result
bytes, queue depth, and sample failures. Soak modes sample RSS, FDs, threads,
tasks, CPU time, allocations, and queue depth at a declared interval with
warmup, steady-state, and final windows.

Thresholds are typed by metric, operator, value, unit, and scope, and every
metric reference must resolve to exactly one declared unit. Each configuration
includes p95/p99 elapsed and schedule-delay ceilings, a throughput floor,
minimum completion/sample baselines, and no-drop/queue-overflow rules. Leak
rules compare the final window against a declared stable baseline with both
absolute and relative growth ceilings. Every p95/p99 metric must name a
histogram carrying that percentile. Workload duration, warmup/ramp-up,
closed-loop/open-loop target-rate relationships, iteration horizons, sample
budgets, leak windows, and final-sample horizons are cross-validated.
The required final sample and fail-on-missing policies prevent a short or
incomplete run from being reported as healthy.

## Future execution boundary and ownership rules

The current orchestrator must remain a parser/planner. If a separately
reviewed adapter eventually executes plans, it must preserve these invariants:

1. Every child is spawned from an absolute, pre-resolved executable and an
   explicit argument vector with `shell=false`; never interpolate a shell
   command or inherit an ambient environment.
2. The returned `std::process::Child` (or equivalent owned handle) is the
   identity. Before any signal, call `try_wait`; if it has exited, do not
   signal. On success, error, timeout, and cancellation, wait/reap that exact
   child. Direct-child termination is the default.
3. Group signalling is disabled by this design. If a future platform wrapper
   needs it, it must validate a PGID greater than one derived from the still
   live, unreaped owned child and establish ownership by construction; values
   `-1`, `0`, and `1` are never targets.
4. A container runtime, if later enabled, must return a created container ID.
   Cleanup may use only that exact ID after validating its shape. It must not
   select by image, name, label, user, ancestor, or broad pattern. A failed
   create yields no cleanup target.
5. Process/container output, queues, response bodies, and result artifacts are
   bounded. Cancellation must release permits and reap owned children. A
   missing resource sample or unbounded queue is a failed run.
6. Ordinary correctness tests must use offline deterministic fixtures. Any
   test that truly signals a process group belongs in a verified PID namespace
   and must be excluded from the ordinary test command.

These rules mirror the repository process-safety contract and are represented
in every config's `execution` section so a future adapter cannot silently
weaken them. Future executable paths and runtimes are absolute and carry a
deterministic hash of the textual reference plus a null artifact digest.
Future container images use an immutable `@sha256:` reference, while their
reference hash and observed artifact digest remain separate fields. They are marked
`future-pinned-not-present` and remain disabled, so these declarations do not
claim that an artifact was downloaded or run.

## Acceptance and evidence

The configs are design artifacts, not performance evidence. A future result
may be considered an evidence candidate only when it validates against
`collected-evidence.schema.json` and records the exact source commit, runner,
toolchain, target/image/executable/runtime artifact digests, fixture/case
manifest digests, bounded raw artifacts, resource samples, histogram-backed
percentiles, and threshold evaluation. The profile remains unverified until
its named oracle/performance evidence exists.
