<!-- SPDX-License-Identifier: Apache-2.0 -->

# HTTP sampler fixture corpus

This is an original, loopback-only fixture for the HTTP portion of
`FX-ELEMENTS-CORE-001`, and covers only the HTTP slice of `ELEM-001`.  It does
not claim support for external samplers or for any separate test-harness
checklist row; those rows are tracked independently in the profile.

`core/plan.jmx` is a hand-authored JMeter 5.6.3 plan.  Its exactly 21 samplers
cover method and body construction, duplicate headers, success-boundary status
codes, chunked/closed/reused connections, compression, response encodings,
and partial/reset/timeout failures.  This case deliberately does not claim
redirect or embedded-resource coverage; those vectors require a separate
fixture case.  The plan explicitly selects JMeter's `HttpClient4`
implementation so its PATCH-with-body vector is not sent through the legacy
Java implementation.  The properties pin HttpClient4 retries to zero and
disable request-sent retry.
The plan's unmaterialized port fallback is `0` (invalid for a client
connection); a valid run must inject the ready-document port through the
runner contract.
`core/oracle.properties` pins the save-service fields and response limits used
by the plan.  `expected/semantic.json` uses the comparator-supported `jtl-xml`
projection schema.  It is a static JTL contract only; it is not a JMeter
result and must not be treated as oracle evidence.  The linked
`core/trace-contract.json` input carries the richer static protocol contract
(ordered trace events, body digests/effective form and multipart projections,
duplicate headers, response body/data/header projections, connection reuse,
and transport/compression/encoding mappings) without adding unsupported keys to
the comparator expectation envelope.

## Fixture server contract

`server.py` uses only Python's standard library and never makes an outbound
request or reads proxy environment variables.  It accepts only
`127.0.0.1`, port `0` (OS-selected ephemeral) or ports `1024..65535`, and a
required finite `--max-requests` budget (`1..10000`).  This case supplies 21,
one slot for each plan sampler.  The fixture stops normally only after all 21
bounded trace events have completed; the idle/session watchdogs stop an
incomplete run without waiting indefinitely for that count.
The lifecycle also has bounded idle and total-session watchdogs, so a JMeter
startup failure, malformed request, or half-open session cannot leave the
fixture waiting for an exact request count.  Request lines, targets, headers,
bodies, chunk framing, trace events, and trace bytes are bounded.  Invalid
framing, duplicate length/transfer headers, oversized bodies, invalid chunk
extensions/trailers, forbidden trailer field names, and truncated input fail
closed instead of being silently truncated.  At most 32 request workers are
admitted at once.
Form and multipart entities are parsed before request admission: more than 16
form fields or more than 2 multipart fields receives typed HTTP 413, while
malformed form syntax receives HTTP 400.  These are hard parser limits, not
trace-projection limits.

The stdlib `BaseHTTPRequestHandler` pre-parser accepts at most 65,536 bytes per
line (its bounded `readline` probes one extra byte) and accepts at most 100
header lines before this fixture's checks run; the ready metadata reports both
the accepted cap and probe limit.  The effective target, body, chunk, and
trace limits are then enforced by this fixture.

When the hard cap, idle timeout, session timeout, or a bounded trace error is
reached, the server asks its own `serve_forever` loop to stop from a helper
thread, then the main thread waits for request handlers, closes the trace, and
publishes `outcome.json`.  Normal completion has `shutdown_reason`
`request-budget` and exit code 0.  Incomplete idle/session/bounded-error
completion has `complete=false` and exit code 3.  The fixture has no PID file,
process lookup, shell, signal, or process-group cleanup operation; the parent
runner owns each exact child handle and performs any outer lifecycle policy.

The invocation shape below is documentation only and is not run by static
validation:

```text
<materialized:fixture.server-python> ../server.py --host 127.0.0.1 --port 0 \
  --max-requests 21 --idle-timeout-ms 5000 --session-timeout-ms 30000 \
  --trace <materialized:fixture.run-root>/trace.jsonl \
  --ready <materialized:fixture.run-root>/ready.json \
  --outcome <materialized:fixture.run-root>/outcome.json
```

The complete startup/readiness/exact-child/reap/port-materialization contract
is [`runner-contract.md`](runner-contract.md).  The runner must create a new
mode-0700 run root, start the absolute manifest-pinned CPython executable,
accept `ready.json` only after bounded atomic publication while the exact
child is live, materialize the port from `ready.json#/port`, and then start
JMeter.  The server rejects missing/non-shared output parents and an
unresolved port token.
Before starting the server, the future runner must record the exact CPython
version and executable SHA-256 plus zlib compile/runtime versions, module path,
and module SHA-256.  Compression wire/decoded hashes are explicitly
`conditional-unobserved` until that runtime gate is complete; this static
fixture contains no observed compression result.

The ready and outcome documents are published through temporary sibling files,
flush, `fsync`, atomic rename, and (where supported) parent-directory
`fsync`.  They report the actual bound port, every parser/body/chunk/trace/
worker/lifecycle limit, and the shutdown policy.  Trace targets retain only an
allowlisted route path and query count; unrecognized paths are replaced with a
placeholder.  Request and response bytes retain lengths and SHA-256 digests;
the known form is also recorded as effective non-secret form bytes, while
multipart records only effective field descriptors plus wire length/digest.
Raw arbitrary bodies are never retained.  Authorization, cookie, token, secret,
password, credential, API-key, session, and matching custom header values are
structurally redacted, and header values outside the small non-secret diagnostic
allowlists are redacted as well.  Duplicate request/response headers remain
ordered lists, and response `body`/`data` projections retain the same
digest-only facts.

## Static acceptance

From the repository root, these checks parse files only.  They do not start
the server, JMeter, Java, a network client, or a process-lifecycle test:

```sh
python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("compat/fixtures/jmeter-5.6.3/http-sampler/server.py").read_text(encoding="utf-8"))'
python3 -m json.tool compat/fixtures/jmeter-5.6.3/http-sampler/core/case.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/http-sampler/core/provenance.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/http-sampler/core/expected/semantic.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/http-sampler/core/trace-contract.json >/dev/null
python3 -c 'import xml.etree.ElementTree as ET; ET.parse("compat/fixtures/jmeter-5.6.3/http-sampler/core/plan.jmx")'
```

Pinned JMeter differential execution and the live local-server lifecycle
remain unrun external evidence.  No compatibility profile row is promoted by
this static fixture handoff.
