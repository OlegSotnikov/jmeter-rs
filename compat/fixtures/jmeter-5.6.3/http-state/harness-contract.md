<!-- SPDX-License-Identifier: Apache-2.0 -->

# Future HTTP-state harness contract

This document is a startup and lifecycle contract for a future differential
harness.  It is deliberately not an execution script.  The checked-in cases
remain `not-run` with null process exits and no generated trace, JTL, log, or
ready file.

## Exact child and endpoint

For one case, the harness resolves the declared case working directory and
`server_path` (`compat/fixtures/jmeter-5.6.3/http-state/<case>/../server.py`)
before constructing an argument vector (no shell) equivalent to the following:

```text
python3 ../server.py --host 127.0.0.1 --port 0 --max-requests <request-cap> \
  [--expected-requests <expected-request-count>] \
  --idle-timeout-ms 5000 --session-timeout-ms 30000 \
  --trace <run-dir>/trace.jsonl --ready <run-dir>/ready.json
```

The server path is interpreted relative to that case directory, not the
repository process directory.  The JMeter child receives the allocated port
only through the declared `-Joracle.port=<server-port>` injection.  No
ambient `oracle.port`, inherited proxy, or public network endpoint is
permitted.

The harness owns the exact `Child` returned by that invocation.  It does not
discover a process by name, PID, process group, image, user, or port, and a
PID is never an authority for readiness or completion.  The fixture accepts
port `0` or an explicitly assigned 1024..65535 port and always binds to
`127.0.0.1`.  The ready document is accepted only after an atomic rename and
must contain exactly the fixture protocol, loopback host, allocated
1024..65535 port, configured request cap, and optional exact request count.
A stale ready path is an
error; the harness creates a fresh run directory and reads the bounded file
after rename.

The harness verifies the child is still live with its owned handle while
waiting for readiness.  It captures the child's stdout and stderr into the
run directory with the declared 8 MiB aggregate bound; these files are local
ignored diagnostics, never checked-in evidence.  It then supplies the port to
the JMeter properties, keeps all network access on loopback, and expects no
more than the declared request cap.  The cap is a trace-safety upper bound;
cases with a pinned exact count also use that exact count as the normal
same-process completion condition.  Each case records planned request,
redirect-hop, challenge, cache, and cookie counts in `expected/contract.json`;
unresolved auth challenge counts remain explicitly unobserved until the oracle
runs.

## Bounded completion

The future harness starts two monotonic watchdogs: readiness is bounded before
the first request, and the fixture's 5000 ms idle / 30000 ms session limits are
bounded after startup.  A normal case must complete with the expected request
count when `--expected-requests` is supplied, after which `server.py` finishes
the final response and closes its own listener and trace file.  Cases without
a pinned exact count remain bounded by the request cap and idle/session
watchdogs until the oracle supplies that count.  A case that sends fewer
requests than a supplied exact count is classified as a bounded idle/session
outcome, not as success.  A case that would exceed the cap is classified as a
fixture protocol failure; it must not increase the cap or continue after a
partial trace.

On every path the harness polls `try_wait` on the exact owned child, waits for
that same child, and records the exit status only when a child was actually
started.  Readiness failure, static validation, and not-run cases retain a
null exit.  Graceful same-process completion is the normal shutdown path; this
fixture contract authorizes no broad cleanup, PID-derived signal, shell
command, or process-group operation.

## First-class `http-trace` projection

The expected files use the supported future `jmeter-rs.http-trace` schema
(`format: http-trace`), encoded as bounded JSONL.  Each event contains
`sequence`, `method`, `path`, sorted query fields, selected request headers,
`request_headers_sha256`, request body length/SHA-256, and a response object
with status, ordered response headers, `headers_sha256`, body length/SHA-256,
and wire body length.  Header duplicates remain ordered lists.  Authorization
is projected only as `<scheme> <redacted>`; cookie and body values are
observable state, never credentials.  Body and header digests are required
trace fields and are not normalization exclusions.  The response-header
field cap is 128 and the response-header byte cap is 64 KiB; request and
response bodies are each capped at 1 MiB, records at 128 KiB, and the complete
trace at 8 MiB.

JMeter result projection is limited to label, URL, method, response
code/message, success, request/response headers, bytes, sent bytes, and
response data.  Timestamp, elapsed, latency, connect time, idle time,
ephemeral ports, and JVM object identity are ignored only because the
normalization policy names them.  `case.json` and `provenance.json` carry
SHA-256 references for `server.py`, this harness contract, and each expected
contract; a future harness must verify those references before startup.
