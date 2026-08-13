<!-- SPDX-License-Identifier: Apache-2.0 -->

# Future HTTP-sampler runner contract

This is a declarative contract for a future pinned differential runner.  It
is not an executable script and this static fixture has not started Python,
JMeter, Java, a network client, or a child process.

## Materialized values and fresh run root

The runner must create a new effective-user-owned mode-0700 directory for each
case invocation.  The directory must not exist before creation and is the only
location for `ready.json`, `outcome.json`, `trace.jsonl`, `oracle.jtl`, and
`oracle.log`:

```text
<materialized:fixture.run-root>/
  ready.json
  outcome.json
  trace.jsonl
  oracle.jtl
  oracle.log
```

Angle-bracket values in the command vectors are runner bindings, not literal
arguments.  The required bindings are:

| binding | materialization | validation |
|---|---|---|
| `<materialized:fixture.run-root>` | newly created case-local directory | mode 0700, empty before startup, no `..` escape |
| `<materialized:fixture.server-python>` | absolute runner-manifest CPython executable | Python >=3.10; exact interpreter version, executable SHA-256, zlib compile/runtime versions, zlib module path/SHA-256 recorded before start; no inherited `PATH` lookup |
| `<materialized:jmeter-executable>` | absolute executable from the pinned JMeter distribution | Apache JMeter 5.6.3 artifact and PGP/digest gates pass before use |
| `<materialized:fixture.server.port>` | `ready.json#/port` after atomic rename | integer 1024..65535, host exactly `127.0.0.1`, child still live |

The JMeter port binding is therefore a formally materialized value from the
ready document, not an unresolved placeholder.  Static validation never
resolves any binding or creates the run root.

## Exact runtime identity and compression gate

Before starting `server.py`, the future runner must record a runtime manifest
next to the run metadata with these exact values: CPython implementation and
full version, the absolute `sys.executable` path and its SHA-256, and the
zlib compile-time version (`ZLIB_VERSION`), runtime version
(`ZLIB_RUNTIME_VERSION`), module origin, and module-file SHA-256.  The
materialized values in `command.runtime_recording` are bindings for this
manifest, not evidence in this static fixture.  Missing, ambiguous, or
changed identity values make the run ineligible for oracle comparison.

The gzip and deflate wire/decoded digests in `core/trace-contract.json` are
candidate values with status `conditional-unobserved`.  The runner may compare
them only after every runtime identity above is present and matches the
recorded candidate gate; until then it must retain the hashes as unobserved
and must not promote the run or synthesize a passing result.

## Startup and readiness

The runner starts the fixture as one exact argument vector, with no shell:

```text
<materialized:fixture.server-python> ../server.py
  --host 127.0.0.1 --port 0 --max-requests 21
  --idle-timeout-ms 5000 --session-timeout-ms 30000
  --trace <materialized:fixture.run-root>/trace.jsonl
  --ready <materialized:fixture.run-root>/ready.json
  --outcome <materialized:fixture.run-root>/outcome.json
```

The runner owns the exact child handle returned by this spawn.  It must poll
that handle with `try_wait` while waiting at most 10,000 monotonic
milliseconds for `ready.json`; a child exit, stale/non-atomic ready path,
invalid JSON, wrong schema, non-loopback host, or out-of-range port is a
readiness failure.  The ready document is accepted only after the file has
been atomically renamed into the fresh run root and contains the complete
server limits from `server.py`, including pre-parser, request/response header,
query, form/multipart field (typed 413 rejection), body, chunk/trailer, trace,
worker, and lifecycle bounds.

Only after readiness does the runner materialize the port and start JMeter as
another exact child vector:

```text
<materialized:jmeter-executable> -Dfile.encoding=UTF-8 -n -q oracle.properties
  -Joracle.port=<materialized:fixture.server.port>
  -t plan.jmx
  -l <materialized:fixture.run-root>/oracle.jtl
  -j <materialized:fixture.run-root>/oracle.log
```

The runner sets `LANG=en_US.UTF-8`, `LC_ALL=en_US.UTF-8`, `TZ=UTC`, and an
explicit UTF-8 default charset, while denying ambient proxy and credential
variables.  JMeter, Python, and Java versions, executable paths, artifact
hashes, target triple, and OS image are recorded as run metadata.

## Completion and exact-child ownership

The one-thread/one-iteration plan must emit exactly 21 top-level JTL samples
and 21 trace events in the order declared in `core/expected/semantic.json`.
The fixture's normal completion is `outcome.json` with
`shutdown_reason=request-budget`, `complete=true`, 21 completed requests, 21
trace events, and server exit code 0.  A pre-network failure or incomplete JMeter run must stop
through the bounded idle/session watchdog or a bounded fixture error and must
produce `complete=false`, a declared non-success shutdown reason, and server
exit code 3.  It must never be reclassified as a successful 21-sample run.
The `/reset` vector is a transport descriptor only: platform-specific
`SO_LINGER` behavior is recorded as observed transport metadata, never
converted into a fabricated JTL response code; if the pinned platform cannot
provide the reset action (the fixture tries the portable `ii` and `hh` linger
layouts), the case remains incomplete rather than silently passing.

On every success, error, timeout, and cancellation path the runner polls
`try_wait`, waits/reaps the exact owned JMeter and fixture children, and keeps
their exit statuses distinct from JTL sample success.  If an external
deadline requires escalation, only the still-live exact child handle may be
escalated through the repository process-supervision policy; no PID lookup,
negative signal target, shell cleanup, process-name search, or process-group
heuristic is permitted.

`outcome.json` is written after handlers are joined and the trace is closed,
using the same bounded temporary-file, flush, fsync, atomic-rename procedure
as `ready.json`.  It is the authoritative fixture completion descriptor for
the future runner; static metadata keeps process exits and observed sample
counts null until that runner actually executes.  A complete trace uses the
stable transport descriptors declared by `core/trace-contract.json`: partial
responses expose `kind=truncated-response`, `declared_content_length`,
`received_wire_bytes`, and `connection_action=half-close`; reset probes expose
`kind=connection-reset`, `response_started=false`,
`connection_action=SO_LINGER reset best effort`, and an observed
`linger_layout`; timeout probes expose `kind=response-timeout`,
`server_delay_ms`, and `sampler_timeout_ms`.
