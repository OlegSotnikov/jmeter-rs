<!-- SPDX-License-Identifier: Apache-2.0 -->

# Proxy, recorder, mirror, and TLS fixture corpus

This is an original, local-only fixture family for `FX-PROXY-TLS-001`.  It
provides the deterministic origin routes and proxy protocol surface needed by
`PROXY-001`, `PROXY-002`, `PROXY-003`, `TLS-001`, and `TLS-002`. Broader
`TEST-002`/`TEST-004` integration suites own their aggregate JVM/plugin/RMI
boundaries and are not claimed by this case manifest.

The checked-in files contain no certificate, private key, JKS, raw JTL, raw
trace, credential, downloaded JMeter artifact, or browser capture.  A runner
creates a temporary run root, generates local certificate material there with
the pinned external toolchain, starts the server as an owned child, and removes
the run root after the child is reaped.  `ready.json` contains a typed
readiness object, schema, loopback host, bounded limits, and listener ports; it
is not a PID authority.  The parent must retain and supervise its child handle
rather than discovering a process from this file.  The ready path must be
absent in the fresh private run root; the fixture rejects a stale path before
publishing.

The run root must be an existing directory owned by the effective user with
mode `0700`.  If proxy authentication is enabled, pass the non-secret username
and exactly one explicit secret capability: `--proxy-secret-file` names a
regular effective-user-owned `0600` file below the run root, or
`--proxy-secret-env` names an explicitly requested environment variable.  The
old password command-line option is intentionally unsupported by the
fixture-server capability.  Secret values are bounded, are never put in traces
or diagnostics, and are never written back to disk.  The server retains the
validated secret only in memory for Basic-auth comparisons while its owned
process is running; it is dropped when that process exits.

## Coverage contract

The server has four opt-in listeners.  Omitted ports do not start a listener;
`0` requests an ephemeral unprivileged port and `1024..65535` permits an
explicit port.  Every listener binds to `127.0.0.1`.

| listener/route | observable contract |
| --- | --- |
| `http` origin | `/redirect` returns a fixed `302` and `/final` is its target; `/binary` returns fixed binary bytes; `/headers` returns `X-Fixture-Header: stable`; other paths return a fixed UTF-8 body |
| `https` origin | The same routes over TLS 1.2-or-later, ALPN `http/1.1`, with an optional runtime client-CA requirement |
| `proxy` | Absolute-form HTTP forwarding and loopback-only `CONNECT`; forwarding is allowed only to the origins that the server started or to explicit loopback `--allow-upstream` entries |
| `proxy_tls` | The same proxy contract over a runtime TLS listener |

Request lines, headers, bodies, response copies, CONNECT relays, worker
threads, session duration, trace bytes, and ready-document bytes are bounded.
Chunked request
bodies, duplicate request headers, unsupported HTTP versions, non-numeric
upstream hosts, non-loopback destinations, and HTTPS absolute-form proxy
requests fail closed; HTTPS must use `CONNECT`.

Each accepted connection receives one absolute monotonic deadline.  The same
deadline covers worker-admitted TLS handshake, request parsing, upstream
connect, response/relay reads, response writes, and handler cleanup. TLS
handshakes consume the bounded worker budget rather than blocking the accept
loop. On shutdown listeners stop accepting, active handlers are joined under a
grace deadline, and their sockets are closed only if that deadline expires;
the trace is closed only after the join attempt. A trace overflow or write/
flush/close failure latches a global failure and produces a nonzero server
outcome.

Trace events record status, route, method, path, body length, bounded relay
counts, and negotiated TLS metadata.  They never record request bodies,
authorization values, certificate paths, keys, or process identifiers.  A
trace limit is an explicit fixture failure rather than silent output loss.

## Static corpus files

* `plan.jmx` is an original sampler plan for fixed redirect, binary, header,
  and HTTPS routes.  Port and proxy values are supplied by the external runner.
* `oracle.properties` and `oracle-direct-tls.properties` contain deterministic
  save-service and HTTP/TLS settings only; runtime certificate paths are not
  checked in.
* `case.json` identifies the profile rows, bounded invocation templates, exact
  external boundaries, a typed future-driver/action contract, fixture and
  recorder readiness/port materialization rules, typed JVM keystore/client
  materialization, absolute tool-path requirements, resolved-argv evidence
  requirements, and a typed `not-run` execution status with a null process
  exit; it makes no success claim for the unavailable external oracle.
* `expected/semantic.json` is a case contract for protocol-visible vectors,
  not a fabricated JMeter result.  It must be replaced or supplemented by a
  pinned oracle comparison before any profile row can become `verified`.  Its
  `jmx-semantic` format is deliberately declarative until a protocol comparator
  exists; the generic JTL comparator must not consume it.
* `provenance.json` records the original authorship, Apache JMeter 5.6.3 pin,
  environment policy, and the absence of committed secrets or public-network
  traffic.

## Future runner contract

`case.json` is the typed source of truth for future actions.  Every action is
`planned` and unobserved until an external runner records evidence.  The runner
must create the private run root, generate only local runtime certificates,
start one exact fixture child, validate the typed `readiness` object, start and
validate the exact recorder child when selected, resolve every
`<http-port>`, `<https-port>`, `<proxy-port>`, `<proxy-tls-port>`, and
`<recorder-port>` token from the declared readiness sources, reject unresolved
tokens, and persist redacted resolved argv metadata before spawning JMeter. It
must invoke `<jmeter-home>/bin/jmeter` and `<python-home>/bin/python3` through
absolute materialized paths, clear the environment, set only the declared
locale/TZ/Java-home values, and deny PATH and ambient proxy inheritance.

The resolved-argv record is ignored runtime evidence, not a checked-in fixture.
It must include the case/template ID, fixture and recorder ready-file digests,
resolved ports, full argv with secret values redacted, absolute tool paths and
versions, environment keys, Java metadata, working directory, and a digest. A
missing listener, stale ready path, unresolved placeholder, PATH lookup,
non-loopback target, or failed readiness check is a fixture failure before the
oracle process starts.

The server command shape below is documentation only; it is not run by static
validation.  `RUN_ROOT` must already exist and be a private temporary
directory.  Certificate paths are runtime-generated files below that root.

```text
<python-home>/bin/python3 scripts/fixture_server.py \
  --run-root RUN_ROOT --ready-file ready.json --trace-file trace.jsonl \
  --http-port 0 --https-port 0 --proxy-port 0 \
  --server-cert runtime/server.crt --server-key runtime/server.key \
  --proxy-user fixture --proxy-secret-file runtime/proxy.secret
```

The parent waits for `ready.json`, validates its `readiness` object and reported
ports, and, for recorder vectors, validates the recorder's separate loopback
readiness and `<recorder-port>` materialization. For the direct client-
certificate vector it materializes a JKS client keystore and truststore below
the run root and injects their paths through typed JVM properties; passwords
remain protected capabilities. The parent passes materialized values to the
JMeter oracle, and then performs graceful child shutdown through the owned
process handle with a bounded wait.
No fixture code reads a PID from disk or signals a process selected by name,
PID, or process group.

For TLS-002, the external runner creates `proxyserver.jks` and any client
material under the same temporary root with the pinned JDK keytool; password
values are supplied through the runner's protected secret channel and never
appear in a manifest, trace, or log. Typed `<protected-secret>` placeholders
may identify runtime injection points in an argument template, but are replaced
only inside the protected runner and redacted before evidence. The planned command contract
is:

    <pinned-keytool> -genkeypair -alias fixture -keyalg RSA -keysize 2048 \
      -sigalg SHA256withRSA -keystore RUN_ROOT/runtime/proxyserver.jks \
      -storetype JKS -validity 7 -dname "CN=127.0.0.1" \
      -ext "SAN=ip:127.0.0.1" -storepass <protected-secret> \
      -keypass <protected-secret>

The exact JDK/keytool/provider versions, generated certificate fingerprints,
trust-store settings, and redacted argv must be recorded at the external run.
The command is documentation for the external adapter, not a repository
acceptance step.  The generated JKS, key, certificate, and secret are temporary
ignored inputs. The client-certificate server vector starts both HTTP and
HTTPS origins so the shared sampler plan cannot fall through to an ambient
port 80; the runner must materialize both `<http-port>` and `<https-port>`
before JMeter starts.

## Descriptor-only coverage

The semantic contract remains unobserved and covers the full declared surfaces:

* `PROXY-001`: `-E/-H/-P/-N/-u/-a`, corresponding HTTP/HTTPS proxy properties,
  absolute-form forwarding, CONNECT, no-proxy bypass, Basic-auth missing/
  invalid/valid cases, unlisted/DNS/non-loopback denial, proxy failure, and
  bounded timeout behavior.
* `PROXY-002`: recorder bind/startup, CONNECT and HTTPS interception, URL and
  content-type filters, suggested exclusions, Cookie/Authorization removal,
  pauses, binary request files, generated JMX topology, and replay through the
  local fixture.  Generated JMX and browser captures remain runtime-only.
* `PROXY-003`: the sibling `recorder-mirror` case remains the source-derived
  HTTP/1.0 mirror corpus and explicitly requires the
  `run-recorder-mirror-isolated` namespace/firewall action because the upstream
  mirror binds wildcard.
* `TLS-001`: TLS 1.2/1.3 versus rejected older protocols, ALPN, SNI and
  wrong-name/expired certificates, default/local-trust/trust-all modes, valid
  and rejected client certificates, and SSL Manager/Keystore Configuration
  controls.
* `TLS-002`: `proxy.cert.directory`, `proxy.cert.file`, JKS type, alias,
  dynamic-key and seven-day validity behavior, plus the pinned keytool command
  shape and protected-password policy.

None of these vectors is evidence until the external action contract produces
an exact JMeter 5.6.3 run and a bounded local differential result.

## Static acceptance

From the repository root, these checks do not execute Python fixture code,
Java/JMeter, OpenSSL, a network client, or a process lifecycle:

```sh
python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("compat/fixtures/jmeter-5.6.3/proxy-tls/scripts/fixture_server.py").read_text(encoding="utf-8"))'
python3 -m json.tool compat/fixtures/jmeter-5.6.3/proxy-tls/case.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/proxy-tls/provenance.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/proxy-tls/expected/semantic.json >/dev/null
python3 -c 'import xml.etree.ElementTree as ET; ET.parse("compat/fixtures/jmeter-5.6.3/proxy-tls/plan.jmx")'
```

The external browser/recorder, proxy, TLS, and pinned JMeter checks remain
unrun external evidence for the profile.
