# Decision 0013: Native HTTP v3 and ordinary-CLI provider resolution

Status: accepted architecture; implementation and evidence pending
Date: 2026-08-13
Compatibility features: `CLI-001`, `ELEM-001`, `ELEM-004`, `ELEM-005`,
`TLS-001`, `PROXY-001`, `TEST-001`, `TEST-005`

## Context

The first two native HTTP capabilities deliberately require an explicit
`-Jjmeter-rs.http.capability` property. This makes provider substitution
visible while the native subset is small, but it is not an ordinary JMeter
CLI experience. A useful standalone product must eventually run an admitted
headless JMX plan without requiring that extra project-specific option.

The JMX source still names `Java`, `HttpClient4`, or an upstream default.
Those names select implementations whose retries, malformed-wire tolerance,
multipart spelling, cookies, authentication, pooling, proxy, TLS, compression,
embedded parsing, timings, and byte counters can differ. Replacing the source
name with `native` or describing Rust output as exact Java/HttpClient4 output
would be a false compatibility claim.

Native v2 also lacks the behavior used by many customer plans: request bodies,
Header/Cookie/Cache/Auth managers, redirects, decompression, connection reuse,
proxies, and embedded resources. Adding those behaviors to `/2` would change a
previously closed capability silently.

## Decision

Introduce `http.native/3` as a separately versioned, Java-free HTTP/1.1
capability. `/1` and `/2` remain immutable. Initially `/3` is explicitly
selected and experimental. It becomes eligible for ordinary CLI resolution
only after the gates in this record pass.

The planned `/3` scope is:

- bounded replayable byte, raw, URL-encoded form, multipart, and
  capability-mediated file request bodies;
- branch-scoped Header, Cookie, Cache, and Auth manager plans with isolated
  per-user mutable state and explicit iteration reset policy;
- semantic redirects with bounded history, replay checks, and cross-origin
  sensitive-header policy;
- streaming gzip, deflate, and Brotli decoding with separate wire, decoded,
  and ratio limits;
- bounded direct HTTP/HTTPS connection reuse and pooling; and
- explicit HTTP forward proxy and HTTPS CONNECT routes without ambient proxy
  discovery.

Embedded-resource parsing and scheduling use a subordinate
`http.embedded/1` identity because parser choice, normalization, ordering, and
parallel timing require their own evidence. HTTP/2, transparent retries,
Digest/NTLM/Kerberos, client private keys, platform roots, ambient DNS/proxy,
JSSE/JKS/PKCS12/PKCS11, and provider-specific malformed-wire tolerance remain
outside `/3` until separately versioned.

### Ordinary CLI resolution

Introduce the run-level resolver identity `http.execution/auto/1`. When the
operator supplies no native selector, it may map a source Java, HttpClient4,
or upstream-default sampler to `http.native/3` only when all of the following
are true:

1. one complete plan scan has classified every enabled HTTP sampler, manager,
   body, assertion, extractor, redirect, proxy, TLS, and embedded-resource
   requirement;
2. every requirement has one exact `/3` or subordinate implementation path;
3. the requested generic behavior is inside the verified standalone
   capability projection; and
4. no source property depends on a known provider-specific behavior that the
   native matrix has classified as different or unevidenced.

Resolution is all-or-nothing and precedes CA reads, DNS actors, sockets,
logging, outputs, reports, time drivers, and runtime setup. An unknown,
unsupported, ambiguous, duplicate-manager, or unevidenced feature returns a
typed source-located capability error. The resolver never falls back between
native versions or to a compatibility pack after admission.

An explicit `/1`, `/2`, or `/3` selector remains an exact override for
diagnostics, migration, and capability-specific tests. It does not weaken
whole-plan admission.

Every compiled path and observable result records at least:

```text
source_provider: http.jmeter-java/5.6.3 |
                 http.jmeter-httpclient4/5.6.3 |
                 upstream-default-with-pinned-resolution
resolver:         http.execution/auto/1 | explicit-selector/1
executed_provider:http.native/3
subordinates:     explicit DNS/TLS/proxy/decompression/embedded identities
```

The source provider is preserved losslessly. Native evidence never promotes a
Java- or HttpClient4-specific claim merely because auto-resolution was used.

### Ownership and dependency direction

`crates/http` owns pure body planning, replayability, manager state,
redirect/cache/auth decisions, state deltas, and result projection. It remains
free of Tokio, sockets, DNS, filesystem, TLS, and concrete codecs.

`crates/http-native` owns connectors, explicit DNS, rustls, proxy handshakes,
HTTP/1.1 pooling, response streaming, and concrete decompression. The app owns
the executor, filesystem capabilities, public CA input, secret references,
provider recipes, worker lifetimes, and the consuming run transaction from
Decision 0012. A file body is an already-authorized bounded handle, never a
path opened by an HTTP crate. Credentials are application secret references,
not plaintext retained in shared core state.

One absolute operation deadline covers queueing, pool acquisition, DNS,
connect, proxy, TLS, write, read, decompression, semantic commit, routing, and
cleanup. No phase resets it. All pending phases own Decision 0011 wait
registrations. Dropping a body/future releases exact permits and closes or
quarantines an unread connection; it cannot return an unframed connection to
the pool. Queues, pool entries, connections, headers, bodies, redirects,
decompression ratio, manager state, embedded candidates, diagnostic bytes,
and cleanup work are finite and use checked accounting.

No convenience client may enable ambient DNS/proxy/roots, transparent retry,
automatic redirect, automatic decompression, or an unbounded pool. A new
dependency is accepted only after its exact version, disabled defaults,
features, MSRV, licenses, native build risk, cancellation behavior, and reason
for use are recorded in third-party provenance.

## Compatibility and enablement gates

Auto-resolution remains disabled in production until:

- unit and state-machine tests cover bodies, manager scope and isolation,
  redirects, cache/auth/cookies, replay failures, pooling, decompression,
  proxy routes, cancellation, limits, and exact finalization;
- deterministic loopback integration tests cover HTTP and HTTPS without public
  services, ambient credentials, wall-clock sleeps, or broad cleanup;
- pinned JMeter 5.6.3 Java and HttpClient4 differential runs separately
  classify every claimed generic behavior and every accepted difference;
- unknown or uncovered JMX data rejects before all observable side effects;
- result/provider identity proves source and execution identities cannot be
  confused;
- one-binary/no-Java release gates pass on every declared target; and
- the standalone capability projection explicitly records the supported
  cases and remaining provider-specific non-equivalences.

Passing Rust tests alone does not enable auto-resolution or promote a profile
row. Until the matrix is complete, ordinary source-selected samplers continue
to require their declared provider, and `/3` requires explicit selection.

## Rejected alternatives

- Expanding `/2` is rejected because it would silently change a closed
  capability.
- Treating missing selection as unconditional native fallback is rejected
  because unsupported prefixes could execute before a later failure.
- Relabeling native output as Java or HttpClient4 is rejected because provider
  behavior is observable.
- Using an environment-aware convenience client is rejected because it makes
  DNS, proxy, roots, retries, and pooling ambient.
- Requiring the extra selector forever is rejected as the final product UX;
  it remains the safe bootstrap and explicit override.
- Enabling auto mode from implementation coverage alone is rejected; pinned
  differential evidence is the compatibility boundary.

## Consequences

The initial `/1` and `/2` work remains stable while agents can build `/3` in
independent pure and native layers. Once the gates pass, the single Rust binary
can accept ordinary supported JMeter CLI/JMX workloads without an extra flag,
while diagnostics and evidence honestly distinguish source semantics from the
provider that executed them. Plans needing arbitrary Java/provider-specific
behavior still fail explicitly or use the optional compatibility pack; they
never acquire a hidden JVM or approximate success.
