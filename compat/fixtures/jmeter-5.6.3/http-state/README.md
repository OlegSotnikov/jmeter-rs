<!-- SPDX-License-Identifier: Apache-2.0 -->

# HTTP state fixture corpus

This directory is an original, local-only corpus for the HTTP state boundary
in the Apache JMeter 5.6.3 profile.  The plans exercise configuration scope
and HTTP sampler behavior for cookies, cache metadata/revalidation, redirects,
authentication challenges, and merged request headers.  The HTTP state rows
are primarily `ELEM-005` (configuration elements and scope) and the HTTP
portion of `ELEM-001` (HTTP sampler); assertion, timer, and processor claims
remain in their dedicated fixture families.

Authentication usernames/passwords are visibly labeled dummy corpus values,
not credentials: the Basic and Digest prefix cases use fixed placeholders,
and `server.py` redacts every Authorization value before writing a trace.

`server.py` is stdlib-only and binds to `127.0.0.1`.  It is a synchronous
single-request server so trace sequence order is deterministic.  `--port`
accepts `0` (OS-selected ephemeral) or 1024..65535; `--max-requests` accepts
only 1..10000 (the default budget is 256), and the optional
`--expected-requests` uses the same bound for exact same-process completion.
Request and response bodies are
bounded to 1 MiB, request targets to 8 KiB, request headers to 64 KiB/128
fields, response headers to 128 fields/64 KiB, query fields to 32, individual
trace records to 128 KiB, and total trace output to 8 MiB.  Idle and session
timeouts are bounded to 100..300000 ms and 1000..600000 ms respectively.  The
optional ready file contains protocol, loopback host, allocated port, request
budget, and optional exact request count only; it is written by flush/fsync plus
an atomic same-directory rename and never contains process metadata.

When an exact request count is supplied, the handler marks a stop flag after
completing the final response.  The same serving process returns to its bounded
request loop and closes the trace and listening socket in `finally`.  Without
an exact count, the finite request cap and bounded idle
or session watchdog remain fail-safe until the pinned oracle supplies one.  The
exact future-child startup,
readiness, expected-request, and graceful-reap contract is in
[`harness-contract.md`](harness-contract.md).  There is no signal, process
lookup, shell, or broad cleanup path.

The manifests are not-run oracle cases.  They intentionally do not include a
JMeter result or a generated trace: the pinned Java oracle must be run by the
conformance harness before any expectation can be promoted to evidence.  A
null process exit is intentional; no server, JMeter, Java, or fixture child
has been started for this checked-in corpus.

Each `expected/contract.json` is a planned `jmeter-rs.http-trace` contract,
not a topology-only shortcut.  Its bounded JSONL event schema names planned
request, redirect-hop, auth-challenge, cache, and cookie counts, plus request
and response body/header SHA-256 fields.  Basic/Digest challenge response
counts remain unobserved until the pinned oracle runs.  Body and header digests are
observable and therefore are not normalization exclusions.  Every case and
provenance manifest pins SHA-256 values for the server, harness contract, and
its expected contract; unresolved oracle observations remain explicitly
`not-run-static` with null process exit.

Static validation from the repository root:

```sh
find compat/fixtures/jmeter-5.6.3/http-state -name '*.json' -print0 \
  | xargs -0 -n1 jq empty
git diff --check -- compat/fixtures/jmeter-5.6.3/http-state
sha256sum compat/fixtures/jmeter-5.6.3/http-state/*/plan.jmx \
  compat/fixtures/jmeter-5.6.3/http-state/*/oracle.properties \
  compat/fixtures/jmeter-5.6.3/http-state/server.py \
  compat/fixtures/jmeter-5.6.3/http-state/harness-contract.md \
  compat/fixtures/jmeter-5.6.3/http-state/*/expected/contract.json
```

These checks parse and hash files only.  They do not start this server, JMeter,
Java, or any other process and do not terminate a process.
