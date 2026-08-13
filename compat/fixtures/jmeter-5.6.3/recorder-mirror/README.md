<!-- SPDX-License-Identifier: Apache-2.0 -->

# HTTP Mirror Server corpus (PROXY-003)

This is an original, bounded request/response corpus for the Apache JMeter
5.6.3 HTTP Mirror Server.  It covers the mirror's observable wire contract:

- the `HttpMirrorControl` defaults and start/stop lifecycle;
- the `HTTP/1.0` response status line and always-present `Content-Type` header;
- reflection of request octets, including a binary request body;
- `redirect` and `status` query parameters;
- `X-ResponseStatus`, `X-SetHeaders`, `X-SetCookie`, and
  `X-ResponseLength` request headers; and
- query status taking precedence over `X-ResponseStatus`.

The mirror is a local test service, not the outbound HTTP proxy and not the
HTTP(S) Test Script Recorder.  The corpus therefore has no public endpoint,
certificate, key, credential, JMX result, or downloaded JMeter distribution.
The upstream `HttpMirrorServer` calls `new ServerSocket(port)` without a bind
address, so a future run must supply a network namespace or firewall policy;
this corpus makes no loopback-only bind claim.
The two Java files under `tools/` are original, non-production probes.  They
are intentionally not compiled or run by this fixture handoff.

## Files

`case.json` is the manifest for `PROXY-003` and the shared
`FX-PROXY-TLS-001` fixture family.  `inputs/requests.json` contains eight
wire vectors with explicit byte limits.  `expected/semantic.json` records the
stable response descriptors, and `expected/api.json` records the small public
API surface used by the probes.  `provenance.json` pins the upstream source
revision and Apache JMeter artifact without copying upstream source.

## Source contract

The descriptors are derived from the Apache JMeter 5.6.3 sources at commit
`34a2785748e9e0b14702595e8682c387869deda3`:

- `HttpMirrorControl` defaults to port `8081`, pool size `0`, and queue size
  `25`; `startHttpMirror()` owns a server and `stopHttpMirror()` joins it for
  at most one second.
- `HttpMirrorServer` emits `HTTP/1.0`, handles each request in a worker (or a
  bounded executor when configured), and closes the connection after the
  response.  Its `run()` method binds the configured port using the platform
  wildcard address; the future driver owns isolation and must fail closed if
  the bind or readiness check fails.
- `HttpMirrorThread` reflects the received request bytes.  It emits
  `Content-Type: text/plain`, turns `redirect=<location>` into `302 Temporary
  Redirect` plus `Location`, lets `status=<code message>` override the status
  header, emits pipe-separated `X-SetHeaders` lines, emits `X-SetCookie` as a
  `Set-Cookie` line, and truncates the initially reflected bytes for
  `X-ResponseLength`.

These statements describe the oracle target; this static corpus does not
claim that a Rust implementation or an oracle run has passed.

## Bounds and safety

The manifest fixes eight observed cases plus three planned edge cases, 1,024
wire bytes per request, 256 body bytes, 16 request headers, 16 response
headers, two worker threads, and a queue of four.  Redirects are descriptors
only and are limited to one hop.  No vector uses `X-Sleep`, chunked transfer
encoding, an absolute URL, credentials, or a public/unrelated destination.
The harness accepts only the exact server bounds `2`/`4`, an explicit
unprivileged port, and a hold time no greater than five seconds; it checks
bounded readiness, reports `getException()`/bind failure as nonzero, and
asserts owned-thread shutdown in a `finally` block.

The three planned vectors cover executor saturation (seven bounded clients),
case-insensitive helper headers, and a client write-half close before the HTTP
header delimiter.  They are descriptors only until the future driver performs
the flow recorded in `case.json`: isolate the wildcard-bound socket, compile
the two probes into ignored temporary classes, run the API probe, start the
bounded harness, replay observed vectors, replay the planned edge vectors,
stop the owned server, and compare the semantic descriptor.  No future step
may substitute a public service or an unbounded network client.

## Static validation

From the repository root, the handoff checks are:

```sh
python3 -m json.tool compat/fixtures/jmeter-5.6.3/recorder-mirror/case.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/recorder-mirror/provenance.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/recorder-mirror/inputs/requests.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/recorder-mirror/expected/api.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/recorder-mirror/expected/semantic.json >/dev/null
git diff --check -- compat/fixtures/jmeter-5.6.3/recorder-mirror
```

Running a Java compiler, JMeter, the mirror, or a network client is a later
oracle/integration step and is deliberately outside this static handoff.
