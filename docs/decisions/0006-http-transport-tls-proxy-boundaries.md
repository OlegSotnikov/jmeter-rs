# Decision 0006: HTTP transport, TLS, proxy, recorder, and mirror boundaries

Status: accepted architecture, revision 5; implementation and external evidence pending  
Date: 2026-08-13  
Compatibility features: `ELEM-001`, `ELEM-005`, `PROXY-001`, `PROXY-002`,
`PROXY-003`, `TLS-001`, `TLS-002`, `TEST-002`, `TEST-004`  
External boundaries: `EXT-JVM-001`, `EXT-SERVICE-001`, `EXT-TLS-001`,
`EXT-OS-001`

## Context

JMeter 5.6.3 HTTP behavior is not one request/response function. It includes
method and entity construction, duplicate headers, per-user cookies/cache/auth,
redirects, embedded resources, DNS, connection pooling, proxies, TLS, response
streaming/decompression, byte and timing fields, recorder-generated JMX, and a
mirror server. The selected upstream Java or HttpClient4 implementation, JVM,
Apache HttpComponents version, JSSE provider, properties, and platform affect
observable results.

The existing `crates/http` is deliberately pure and owns protocol semantics
behind an injected synchronous transport used by deterministic tests. It does
not open sockets or provide production TLS. Putting Tokio, Hyper, DNS, rustls,
filesystem, or environment access into that crate would violate the dependency
and determinism rules. Conversely, presenting a native Rust client as the
exact JMeter HttpClient4 implementation would be a false compatibility claim.

## Decision

HTTP execution has three explicit, wire-stable capability paths:

1. `NativeV1` / `http.native/1`: an independently named native Rust transport
   for plans and deployments that select it explicitly;
2. `JmeterHttpClient4V563` / `http.jmeter-httpclient4/5.6.3` and
   `JmeterJavaV563` / `http.jmeter-java/5.6.3`: pinned JVM worker paths for
   exact implementation-specific compatibility;
3. typed unavailable/unsupported results when the requested path is absent.

There is no fallback between these paths. A JMX sampler selecting HttpClient4
or Java is not silently executed by Hyper. A native transport result can earn
native-capability evidence, but it cannot by itself verify the profile's
HttpClient4 fixture. The compatibility profile and every evidence artifact
record the selected capability.

Add one private edge crate, `crates/http-native`, because its executor,
network, TLS, cryptography, resolver, compression, and platform dependencies
have a distinct security and release boundary. It depends inward on
`jmeter-rs-http`; the application/runtime edge depends on both. It never
becomes a dependency of `model`, `jmx`, `expr`, `results`, or `runtime`.

Ownership is fixed:

- `model`/`jmx`: lossless sampler, manager, SSL/keystore, recorder, mirror, and
  unknown property persistence;
- `runtime`: executor-neutral sampler lifecycle, cancellation, result routing,
  and capability selection;
- `http`: request/state/redirect/manager semantics and sync/async transport
  traits, without concrete I/O;
- `http-native`: sockets, DNS adapters, HTTP framing/pooling, native proxy,
  decompression, and rustls;
- `java-bridge`: pinned HttpClient4/Java, JSSE, SSL Manager, Keystore
  Configuration, JKS/PKCS12/PKCS11, and recorder/keytool behavior;
- application edge: explicit roots, properties, proxy/environment policy,
  secrets, executor, output paths, and capability wiring;
- test support: deterministic fake transports, local services, clocks, and
  protocol captures.

Capability selection is part of the compiled sampler and evidence identity.
It is not inferred from which adapter happens to be registered. The application
binds exactly one requested identifier to exactly one implementation after
validating its complete identity. Aliases, case folding, and a missing
selection are accepted only when pinned JMeter evidence defines them.

## Executor-neutral streaming contract

`crates/http` retains its synchronous transport for bounded deterministic
fakes and adds an async sibling expressed only with standard-library futures.
The caller owns all retained response buffers:

The normative Rust-neutral signatures are lifetime-bound; an implementation
may spell the object-safe aliases differently but may not weaken their
ownership:

```text
send<'a>(&'a mut self, request: &'a Request, context: &'a AttemptContext,
         budget: &'a OperationBudget, cancellation: &'a dyn Cancellation)
  -> Pin<Box<dyn Future<Output = Result<AsyncResponse<'a>, TransportError>>
             + Send + 'a>>

read_chunk<'a>(&'a mut self, destination: &'a mut [u8],
               budget: &'a OperationBudget,
               cancellation: &'a dyn Cancellation)
  -> Pin<Box<dyn Future<Output = Result<ReadChunk, TransportError>>
             + Send + 'a>>

AsyncResponse<'a> = opaque linear owner of {
  head: ResponseHead,
  body_and_lease: ResponseLeaseBody<'a>
}
ReadChunk = Data { written: NonZeroUsize } | End { trailers }
```

`AsyncResponse` exposes `head()`, `body_mut()`, and a consuming asynchronous
`close(self, budget, cancellation)` operation; it never exposes, splits,
replaces, or independently moves the body and lease. `ResponseLeaseBody` is a
private non-`Clone`, non-`Copy` state cell. A response can be returned to a
pool only by consuming `End` or a successful explicit close that proves the
framing boundary; every other path permanently marks that connection
non-reusable.

`written` may never exceed `destination.len()`, and an empty destination is an
input error. The adapter cannot transfer ownership of a newly allocated chunk
to the core. Trailers are a bounded ordered header collection with explicit
presence; they are not silently folded into response headers.

Every async operation has an exclusive borrow lifetime covering the adapter,
request/context, destination buffer, budget, and cancellation capability; its
future cannot outlive a borrowed value. `AsyncTransport` and its send future
are `Send`. `AsyncResponseBody` is `Send` but need not be `Sync`. Only one send
may mutably borrow one transport and only one read may be pending for one body.
The adapter writes only the initialized prefix `0..written`, never retains the
buffer address after resolution/drop, and never exposes bytes written after
cancellation as `Data`.

Response-body state is closed:

```text
Fresh -> Reading -> Fresh       (Data)
Fresh -> Ended                  (End with Absent/Present trailers)
Fresh -> Failed | Cancelled     (terminal error)
```

Dropping a pending read transitions to cancelled/aborted. Concurrent reads,
reads after end, and reads after abort fail deterministically. `End` owns the
one bounded trailer collection and is terminal. Consuming `End`, explicitly
closing an unread body, or dropping `AsyncResponse` invokes exactly one
bounded lease-release path. Explicit close consumes the caller's existing
budget. `Drop` is constant-time and nonblocking: it atomically marks the lease
aborted/non-reusable, releases the local admission permit exactly once, and
enqueues at most one already-reserved cleanup token to the owning adapter; it
does not allocate, wait, lock an unbounded mutex, or return the connection to
the pool. Failure to enqueue the pre-reserved token quarantines the connection
and is observed by adapter finalization. A fully consumed reusable connection returns to
the pool only after validation; an unread, failed, cancelled, over-limit, or
dropped body closes or quarantines it before releasing the permit. The body
cannot outlive the lease. Stable state errors are `http.body.empty-buffer`,
`http.body.concurrent-read`, `http.body.after-end`, and
`http.body.aborted`; lease errors are `http.response.lease-invalid`,
`http.response.lease-released`, `http.response.close-cancelled`, and
`http.response.close-deadline`; none is mapped to end-of-stream or success.

Request bodies use an explicit replay contract:

```text
BodySource = Empty | Bytes(BoundedBytes) | File(FileCapability) |
             OneShot(BoundedBodyReader)
Replayability = Replayable | OneShot
```

`Empty` is distinct from a present zero-length entity. A `FileCapability` is
an already-authorized, bounded application handle; the HTTP crates never open
a path. Redirects, authentication handshakes, or retries that require replay
fail before replay when the source is `OneShot`. They never substitute an
empty body or reuse a partially consumed reader.

`BoundedBytes` is immutable/replayable. `FileCapability` contains an opaque
authorized handle, fixed byte limit/digest, and explicit replay right.
`BoundedBodyReader` is `Send`, non-cloneable, one-shot, and becomes leased when
dispatch begins. A dropped/partially consumed source is terminal and cannot be
replaced or replayed.

The semantic client performs redirects, manager updates, cache decisions,
result construction, and aggregate accounting. The adapter performs exactly
one transport attempt and does not follow redirects, retry requests, mutate
cookies/cache/auth, or inherit ambient policy. Dropping a future cancels its
socket/DNS/TLS/body work and releases pool permits; cancellation explicitly
wakes every blocked phase.

One `OperationBudget` with one absolute local monotonic deadline is created
before queue admission. Queue wait, DNS, pool wait, connect, proxy handshake,
TLS, request write, response headers, response body, decompression, state
commit, result routing, and cleanup all consume it. Each phase receives the
earlier of its configured cap and the remaining overall budget. A phase never
resets or extends the overall deadline, retries consume the same budget, and
`remaining == 0` means expired rather than unbounded. Cross-process messages
carry only a finite remaining duration sampled immediately before write; a
process-local monotonic instant is never serialized and wall time is diagnostic
only. Cancellation severity is monotonic and every blocked phase must wake.

`OperationBudget` contains one finite local monotonic deadline and exposes only
`remaining(now)`, `phase_deadline(now, phase_cap)`, and cancellation state. At
a cross-process handoff, the sender samples remaining time immediately before
write and subtracts a finite manifest-declared handoff reservation. The
receiver creates `receiver_now + min(grant, receiver_cap)` and may shorten but
never extend it. Zero rejects before useful work. Every relay repeats the same
subtraction/clamp; if handoff latency cannot be bounded the capability is
unavailable. Evidence records grant, reservation, receiver clamp, and expired
phase, while Rust retains the original authoritative deadline.

All serialized durations are unsigned nanoseconds. A sender rounds remaining
time down and a configured reservation up, using checked arithmetic; it sends
`grant = remaining_ns - reservation_ns` only when the result is nonzero. The
receiver cap is a negotiated nonzero `u64` nanosecond duration no greater than
24 hours. Its local deadline uses checked addition and rounds toward earlier
expiry. Reservation identity, cap, units, and rounding rules are covered by
the capability digest. A local monotonic source that reverses, stops while an
operation remains runnable, or cannot represent the derived deadline returns
`http.budget.clock-invalid`; it never freezes or extends a grant.

Handoff allocation is linear rather than a repeated calculation.
`reserve_handoff(&mut self, now, reservation, receiver_cap)` returns one
non-`Clone` `HandoffGrant { budget_id: [u8; 16], grant_ordinal: NonZeroU64,
grant_ns: NonZeroU64, reservation_ns: u64, receiver_cap_ns: NonZeroU64,
identity_digest: [u8; 32] }` and advances the parent's spent/reserved ledger
before the token can be serialized. The token is consumed by exactly one frame
write and acknowledged by the exact receiver/session. It can be returned only
when the transport proves that no byte of the frame was dispatched; otherwise
expiry or an unknown write outcome consumes it. Concurrent handoffs therefore
cannot reuse one remaining grant. Relay grants repeat this rule with a new
ordinal and the same budget ID.

A phase cap is `Absent` (no additional cap) or a nonzero `u64` nanosecond
duration; zero never means disabled or unlimited. The injected monotonic
clock/scheduler is itself a capability: registering an earlier deadline must
either arrange a wake, advance under the deterministic test scheduler, or
return `http.budget.clock-stalled`. The core never diagnoses a stall by
wall-clock sleeps or an arbitrary poll count. Reversal, a provider-declared
stalled wake, and unrepresentable arithmetic are distinct stable budget errors.

The adapter returns one canonical immutable `http.attempt/1` record per
transport attempt:

```text
AttemptRecordV1 {
  source_context, operation_id, attempt_index,
  capability_identity, route_identity,
  request_observation, informational_responses, response_observation,
  proxy_tls_identity, origin_tls_identity, connection_observation,
  phase_observations, byte_counters, budget_observation, outcome
}
```

It contains the selected capability and route identities; ordered request and
response headers including duplicates; every informational response; status,
reason presence, protocol version, framing, compression and trailer metadata;
proxy and origin TLS identities; connection-reuse identity; phase timings; and
all byte counters. A counter is `Known(value)` or `Unavailable(reason)`, never a
guessed zero. The record retains whether bytes were written or received so a
retry decision is auditable. The semantic layer, not the transport, maps this
record into a `SampleResult` and state delta.

The canonical record uses fixed-width big-endian integers, strict booleans,
length-delimited bytes, explicit presence discriminants, and strictly
increasing field tags. Its exact top-level tags are:

| Tag | Field/type |
| ---: | --- |
| 1 | `source_context: ErrorContextV1` |
| 2 | `operation_id: [u8; 16]` |
| 3 | `attempt_index: NonZeroU32` |
| 4 | `capability_identity: SchemaIdentity` |
| 5 | `route_identity: RouteIdentityV1` |
| 6 | `request_observation: RequestObservationV1` |
| 7 | `informational_responses: Ordered<ResponseHeadObservationV1>` |
| 8 | `response_observation: Presence<ResponseObservationV1>` |
| 9 | `proxy_tls_identity: TlsObservationV1` |
| 10 | `origin_tls_identity: TlsObservationV1` |
| 11 | `connection_observation: ConnectionObservationV1` |
| 12 | `phase_observations: Ordered<PhaseObservationV1>` |
| 13 | `byte_counters: Ordered<CounterObservationV1>` |
| 14 | `budget_observation: BudgetObservationV1` |
| 15 | `outcome: AttemptOutcome` |
| 16 | `diagnostics: Ordered<DiagnosticRecordV1>` |

`SchemaIdentity` tags are `(1 schema_id: ASCII<=64, 2 version: NonZeroU32,
3 sha256: [u8;32])`. Every ordered item has tag 1 `ordinal: NonZeroU32` before
its value fields. `ObservedHeaderV1` uses tags `(1 ordinal, 2 name:
ObservationValue, 3 value: ObservationValue)`; both header name and value are
classified, so a secret-bearing custom name is not leaked. Request-observation
tags are `(1 method: ObservationValue, 2 target: ObservationValue, 3 protocol,
4 ordered_headers, 5 body_presence, 6 body, 7 framing, 8 write_state)`.
Response-head tags are `(1 ordinal, 2 status: u16, 3 reason_presence,
4 reason: ObservationValue, 5 protocol, 6 ordered_headers, 7 framing)`.
Response-observation extends that head with tags `(8 compression, 9 body,
10 trailer_presence, 11 ordered_trailers, 12 completion_state)`.

`BodyObservationV1` tags are `(1 presence, 2 classification, 3 length,
4 public_content_digest_presence, 5 public_content_sha256, 6 wire_form,
7 replayability)`. Tag 5 is required exactly when the body is public and
present, including present-empty; otherwise it is forbidden. TLS tags are
`(1 state, 2 provider_identity, 3 protocol, 4 cipher, 5 ordered_peer_public_
fingerprints, 6 reuse_state)`. Route tags are `(1 variant, 2 proxy_endpoint_id,
3 origin_endpoint_id, 4 policy_digest)`; endpoint IDs are opaque non-secret
16-byte compile-time identities, never host/path hashes. Connection tags are
`(1 state, 2 pool_identity, 3 connection_identity, 4 reuse_ordinal)` and use
non-secret opaque identities. Phase tags are `(1 ordinal, 2 phase, 3 status,
4 duration)`; counter tags are `(1 ordinal, 2 counter_kind, 3 observation)`;
budget tags are `(1 budget_id, 2 grant_ordinal, 3 start_remaining_ns,
4 end_remaining_ns, 5 reservation_ns, 6 receiver_cap_ns, 7 expiry_phase)`.
Presence forbids the value tag when absent. No nested record accepts a tag not
listed here unless a future negotiated schema version defines it.

`ProtocolVersion = Http10 | Http11 | Http2`; unsupported wire versions produce
a protocol failure rather than an `Other` value. `Framing = NoBody |
ContentLength | Chunked | CloseDelimited | Http2Data | Tunnel`;
`Compression = Identity | Gzip | Deflate | Brotli | Unsupported`;
`TlsState = NotUsed | Observed | Unavailable`; `RouteVariant = Direct |
ForwardProxy | ConnectTunnel | TlsForwardProxy`; `ConnectionState = New |
Reused | Closed | Unavailable`; `PhaseStatus = Completed | Failed | TimedOut |
Cancelled | Skipped`. Counter kinds are closed over request/response header,
body, entity, decoded, sent, received, and connection-wire bytes. Canonical
collection order is wire/phase order, never map order. Hard maxima are 4 MiB
per complete record, 1,024 headers, 1 MiB aggregate header bytes, 32
informational responses, 256 trailers, 32 phase observations, 32 counters, and
64 bounded diagnostics.

`UnavailableReason` is closed over `NotObserved`, `ProtocolDoesNotExpose`,
`CapabilityDoesNotExpose`, `CancelledBeforeObservation`,
`FailedBeforeObservation`, and `Redacted`; arbitrary text is diagnostic data,
not an enum value. `AttemptOutcome` is closed over `ResponseComplete`,
`TransportFailure`, `ProtocolFailure`, `TimedOut`, `Cancelled`,
`ResourceLimit`, and `CapabilityUnavailable`.

`Phase` is closed over queue, DNS, pool, proxy connect, connect, proxy TLS,
origin TLS, request headers/body, response headers/body, decompression, state
commit, result routing, and cleanup. Timing is `Known(finite)` or
`Unavailable(fixed_reason)`. Bodies, header values, cookies, credentials, URL
queries, and paths use a mandatory classification made before encoding:

```text
ObservationValue = Public(BoundedBytes)
                 | Sensitive { length, reason }
                 | SecretReference { provider_identity, purpose, length }
```

`SensitiveReason = Credential | Cookie | Token | UrlQuery | UrlPath |
RequestBodyPolicy | ResponseBodyPolicy | CertificatePath | UserClassified |
UpstreamClassified`. `SecretPurpose = ProxyCredential | OriginCredential |
ClientPrivateKey | StorePassword | SessionToken | RequestPayload |
ResponsePayload`. A future purpose requires a negotiated schema version, not
free text. `provider_identity` is `SchemaIdentity` with an ASCII schema ID and
nonzero digest; it identifies the non-secret provider implementation, never a
secret value or secret-derived hash. Sensitive/secret lengths are `u64`, and
reasons/purposes are one-byte closed discriminants.

Only `Public` bytes may enter a content digest. Sensitive and secret bytes are
never hashed into the record, even indirectly; their canonical form contains
only the closed reason or non-secret reference metadata and length. A public
request/response body retains absent/present-empty, effective form/framing,
length, and content digest. A classified sensitive/secret body retains those
presence and framing fields but no content digest. Reason phrases and trailers
also retain absence versus present-empty. Connection state is `New`, `Reused`,
`Closed`, or `Unavailable` with bounded non-secret identity digests.
Schema/enum/count/byte limits are validated before allocation; unknown
versions and values fail closed.

Canonical digest domains are ASCII plus one zero byte:
`http.attempt/1`, `http.identity/1`, `http.public-body/1`,
`http.state-base/1`, `http.state-delta/1`, `http.state-candidate/1`,
`http.route/1`, and `http.budget-grant/1`. Each preimage is the schema/version
plus canonical length-delimited fields. Only `Public` content appears in a
content-digest preimage. A non-secret identity digest is derived from explicit
public manifest fields; raw URLs, hosts, paths, headers, credentials, cookies,
secret references, and secret-derived values are forbidden from identity
preimages.

## Native HTTP behavior

The first native implementation is low-level Hyper plus an explicit connector;
Reqwest is not used because its convenient redirects, proxies, retries,
decompression, TLS, and environment defaults obscure the required contract.
Exact dependency versions and features are selected only after the current
official-source freshness audit and recorded in third-party provenance.

The default JMeter 5.6.3 comparison path is HTTP/1.1. Native HTTP/2 is a
separate policy (`Http11Only`, `Negotiated`, or `Http2Only`) and is not enabled
opportunistically. ALPN, prior knowledge, h2 connection semantics, and empty
HTTP/2 reason phrases are explicit. Pool keys include origin, route/proxy,
local bind, TLS identity/policy, HTTP version policy, and relevant connection
properties. Pool counts, idle duration, acquisition wait, per-host and global
connections, and retained bytes are bounded.

Request rules preserve ordered duplicate headers and explicit Host behavior.
The transport does not synthesize forbidden defaults. Automatic client retries
are disabled. Retry ownership is closed: the semantic layer owns redirects,
profile-approved authentication challenges, and explicit body replay;
`http-native` performs no transparent retry; one HttpClient4 worker operation
performs one transport attempt and must set and verify
`httpclient4.retrycount=0` and
`httpclient4.request_sent_retry_enabled=false`. If effective values cannot be
proved, that path returns `http.capability.retry-policy`. Every semantic retry
uses the original budget and a new `AttemptRecord`. A future transport retry
may exist only under a separately accepted bounded policy proving no bytes were
sent and exact JMeter permission; sent POST/PATCH/entity requests are never
transparently replayed.

Every concrete worker/client is configured and then interrogated before useful
execution: automatic redirect handling, target/proxy authentication handling,
and client-library retries are disabled. A redirect or authentication exchange
is represented as a new semantic request and a distinct attempt record. If the
library performs an unobserved hop, challenge, or retry, the capability is
rejected as `http.capability.automation-enabled`; the bytes are never folded
into one apparent attempt.

Response parsing bounds status line, header count/bytes, informational
responses, trailers, chunk framing/extensions, compressed bytes, decoded
bytes, and total redirect/embedded-resource retention. Malformed or unsupported
syntax is a typed protocol result, never silently repaired. Duplicate headers
remain ordered. Whether trailers and post-decompression headers appear in the
JMeter projection is oracle-gated.

`http.parser-limits/1` is part of capability identity and has finite active and
hard maxima for request target/authority/status/reason; header count/name/value/
aggregate bytes; informational count/aggregate bytes; trailer count/name/
value/aggregate bytes; chunk-size line, extension count/bytes and declaration;
wire body and content-length arithmetic; compressed input, decoded output,
expansion ratio and codec state; URL-encoded field count/bytes; multipart part,
boundary, part-header/body bytes; redirect count/retained bytes; embedded
candidate count/depth/concurrency/retained bytes; and trace/diagnostic count/
bytes. Limits apply incrementally before allocating lines, headers, chunks,
decompressed data, or multipart projections. Malformed/conflicting framing,
invalid chunk extension/trailer, and each limit family have distinct stable
codes.

The normative hard-max table is part of `http.parser-limits/1`; active values
are nonzero and may only be lower:

| Category | Hard maximum |
| --- | ---: |
| request target / authority / status line / reason | 64 KiB / 8 KiB / 8 KiB / 4 KiB |
| headers | 1,024 fields; 8 KiB name; 64 KiB value; 1 MiB aggregate |
| informational responses | 32; 256 KiB aggregate |
| trailers | 256 fields; 8 KiB name; 64 KiB value; 256 KiB aggregate |
| chunk framing / extensions | 8 KiB line; 16,777,216 chunks/message; 128 extensions/chunk; 8 KiB extensions/chunk; 64 KiB aggregate extensions/message |
| wire request / wire response / decoded response | 64 MiB / 256 MiB / 512 MiB |
| decompression expansion / codec state | ratio 1,000:1; 512 MiB output; 1 MiB retained codec state |
| URL-encoded fields | 4,096 fields; 1 MiB aggregate |
| multipart | 1,024 parts; 256-byte boundary; 256 KiB headers/part; 256 MiB body/part |
| redirects | 64 hops; 64 MiB retained metadata and bodies |
| embedded resources | 4,096 candidates; depth 32; concurrency 256; 512 MiB retained |
| trace / diagnostics | 16,384 records; 4 MiB aggregate; 4 KiB diagnostic text |

Counts, sizes, and ratios use checked unsigned arithmetic. Content-Length and
chunk declarations may not exceed the relevant wire-body maximum even when no
bytes have yet arrived. This table is the compile-time ceiling, not a promise
to retain those amounts by default; current native defaults remain lower where
already declared.

Every active `ParserLimitsV1` vector contains every value in the table in this
exact order, with schema/version and one aggregate SHA-256; omission is invalid.
Stable limit codes are closed over `request-target`, `authority`, `status-line`,
`reason`, `header-count`, `header-name`, `header-value`, `header-aggregate`,
`informational-count`, `informational-aggregate`, `trailer-count`,
`trailer-name`, `trailer-value`, `trailer-aggregate`, `chunk-line`,
`chunk-count`, `chunk-extension-count`, `chunk-extension-bytes-per-chunk`,
`chunk-extension-aggregate`, `wire-request-body`, `wire-response-body`,
`content-length`, `compressed-input`, `decoded-output`, `expansion-ratio`,
`codec-state`, `url-field-count`, `url-field-bytes`, `multipart-part-count`,
`multipart-boundary`, `multipart-part-headers`, `multipart-part-body`,
`redirect-count`, `redirect-retained`, `embedded-candidate-count`,
`embedded-depth`, `embedded-concurrency`, `embedded-retained`, `trace-count`,
`trace-bytes`, `diagnostic-count`, `diagnostic-text`, and
`diagnostic-aggregate`. The extension aggregate is per complete message; the
per-chunk extension limit is separate. Unknown codes cannot be emitted or
normalized to generic `resource-limit` in canonical evidence.

Decompression is explicit per codec. Wire-compressed, entity, decoded, header,
sent, and received byte counts remain separate internal fields until the pinned
oracle establishes each JMeter projection. Expansion ratio and decoded-output
limits apply incrementally; the adapter never collects an unbounded body before
checking them.

## DNS and HTTP state

Resolution is an injected `DnsResolver` capability. Conformance runs never
read resolver configuration, proxy variables, or a process-global cache
implicitly. Direct connections resolve the origin. A forward proxy resolves
the proxy; CONNECT target resolution follows the explicit proxy policy. Native
system resolution is an operator-selected adapter and records its identity;
deterministic tests use loopback literals or a fake resolver.

The pure core owns bounded per-user cookie, cache, authentication, DNS, and
header state. Configuration elements are decoded into typed ordered
descriptors; JMX data itself does not leak into the transport. Iteration and
thread-group reset policies are explicit lifecycle calls.

Every attempt starts from `(base_generation, immutable_state_view)` and stages
one canonical `http.state-delta/1`. The adapter cannot mutate user state.
The one versioned `HttpUserStateV1` aggregate contains cookie, cache,
authentication-challenge, DNS, header, and connection-observation ledgers. Its
closed delta operations are:

```text
CookieUpsert | CookieDelete | CookieClear
CacheUpsert | CacheDelete | CacheInvalidate
AuthChallengeUpsert | AuthChallengeDelete | AuthChallengeClear
DnsUpsert | DnsDelete | DnsClear
HeaderReplace | HeaderAppend | HeaderRemove
ConnectionObserve | ConnectionForget
```

The delta top-level tags are `(1 schema_identity, 2 base_generation:
NonZeroU64, 3 base_digest, 4 policy_identity, 5 ordered_operations,
6 candidate_generation, 7 candidate_digest)`. Each operation is `(1 ordinal:
NonZeroU32, 2 operation_discriminant, 3 manager_key, 4 presence, 5 value,
6 source_attempt_index)`. Ordinals are contiguous from one; duplicate manager
keys are legal only for different ordered operations, and operations apply
strictly in ordinal order. Manager keys have closed typed schemas (cookie
domain/path/name; cache method+normalized public URI identity+Vary key; auth
route/realm/scheme; DNS canonical host; header classified name; connection
pool/connection identity) with finite fields and no secret-derived digest.
The base, delta, and candidate digests use the declared `http.state-*` domains.

Each operation carries a typed manager key and ordered value with explicit
missing/present-empty semantics. Aggregate replacement uses one
`CompareAndSwap { base_generation, base_digest, candidate_digest }`; there is
no independent manager commit. Validation builds the entire bounded candidate
before any state change. Commit compares the current generation and digest to
the base, applies every operation atomically, and checked-increments once;
conflict or overflow applies nothing.

A completed final response follows the policy chosen before dispatch: `NoCommit`
discards its delta; `CommitBeforeNextAttempt` is invalid for a terminal
response; `CommitOnFinalSuccess` commits once before result routing only when
the semantic response is the selected final success; `DeterministicMerge`
commits the validated merged candidate before routing. Thus the generic
"final response commits" rule never overrides the declared mode. A redirect
may use only `NoCommit`, `CommitBeforeNextAttempt`, or `DeterministicMerge` and
creates a new attempt/generation after any commit. An authentication challenge
is a distinct attempt and may commit only `AuthChallenge*`, explicitly
profile-authorized cookie/cache operations, and deterministic DNS/connection
observations; it cannot commit an arbitrary final-response delta.

`304` handling is one ordered atomic cache operation: locate the exact base
representation including Vary key, merge only profile-authorized response
metadata in observed header order, retain the existing entity/body identity,
recompute freshness/validators and candidate digest, then `CacheUpsert` the
whole representation. Missing/ambiguous base, Vary mismatch, invalid metadata,
or overflow rejects the entire delta; it never creates an empty cached body.
Transport/malformed/timeout/cancellation/unsupported/replay/limit failures
commit nothing; cache invalidation is a delta operation rather than an
out-of-band error mutation. Before dispatch, each redirect, authentication,
and embedded-resource policy declares one closed commit mode: `NoCommit`,
`CommitBeforeNextAttempt`, `CommitOnFinalSuccess`, or
`DeterministicMerge(merge_schema_digest)`. The merge schema declares a total
order `(parent_attempt, embedded_discovery_ordinal, resource_attempt,
operation_ordinal)` and a closed per-manager conflict reducer; absent reducer
coverage makes parallel merge unavailable and forces serialized execution. A mode cannot change after the
first attempt. Embedded resource state is serialized deterministically or uses
that negotiated conflict-free merge contract—never implicit last-writer-wins.
Every decision is recorded in the attempt stream.

Manager behavior that the JMeter manual declares unspecified—such as multiple
special managers of the same type—remains oracle-gated or explicitly
unsupported. Native Basic and explicitly configured bearer-like headers may be
supported. Digest, NTLM, Kerberos/SPNEGO, credential files, and provider-bound
auth require a separately proven native adapter or the pinned JVM path. They
never silently become Basic.

## Redirects and embedded resources

The semantic core handles one hop at a time. Redirect count and retained hop
bytes are bounded. 301/302/303 method changes and 307/308 preservation are
profile behavior; cross-origin hops remove Host, Authorization,
Proxy-Authorization, Cookie, and entity headers under the explicit policy.
Proxy credentials never reach the origin or survive an ineligible redirect.

Embedded resources use a bounded parser/candidate set and an application-edge
concurrency capability. Parent/sub-result order, URL resolution, frame depth,
failure propagation, connection/state sharing, and aggregate timing/bytes are
oracle-gated. A full worker/queue is an explicit sample or resource error; it
does not silently omit a resource.

## Proxy behavior

Proxy selection is a typed route, never implicit `HTTP_PROXY`, `HTTPS_PROXY`,
`ALL_PROXY`, or `NO_PROXY`. If CLI/system properties request environment-like
proxy behavior, the application materializes and records the exact values
through the configuration precedence model.

HTTP targets use absolute-form requests. HTTPS targets use CONNECT followed by
TLS to the origin; an HTTPS proxy first establishes TLS to the proxy. Proxy and
origin TLS/auth identities are separate. CONNECT response, relay, proxy auth,
no-proxy matching, body and header limits, deadlines, and error stages are
observable. HTTP/2 extended CONNECT is unsupported until separately specified.

## TLS and secrets

Native TLS uses rustls with an exact pinned provider and feature set. It
supports only explicitly declared TLS 1.2/1.3, SNI, ALPN, verification mode,
DER/PEM trust roots, and DER/PEM client identity. Deterministic tests use an
explicit generated local CA. Platform roots are a separately selected
capability whose provider/OS identity is recorded; they are never a fixture
default. Trust-all exists only as an explicit compatibility/security policy.

Native rustls does not claim JSSE/JKS semantics. These paths are delegated to
the pinned JVM worker:

- exact JMeter default trust-all behavior and JSSE/provider details;
- SSL Manager and Keystore Configuration;
- JKS, PKCS12, PKCS11, alias/index/provider ordering, and preload timing;
- cached/shared per-thread SSL-context behavior and iteration reset;
- client-certificate selection rules;
- recorder CA/host-certificate generation and keytool;
- Java RMI SSL, which remains governed by Decision 0004.

An adapter may not convert a Java store and select a convenient first key
without proving every observable alias/provider rule. Unsupported store types
return a stable capability error and retain their source configuration.

Secrets cross only an application-owned `SecretRef`/`SecretProvider` boundary.
An ephemeral secret value is bounded, zeroized where practical, and has no
serialization or revealing `Debug`. Passwords, authorization values, private
keys, cookies, tokens, raw URLs/queries, and certificate paths never appear in
argv, ordinary environment maps, bridge frames, traces, metrics, snapshots, or
committed evidence. The application passes protected handles/files/channels to
the selected adapter and removes generated material only after exact owned
children are reaped.

A `SecretRef` is opaque and provider-bound; it carries a purpose, rights,
finite lease, and non-secret provider identity. HTTP configuration types do not
contain plaintext proxy or origin credentials. Proxy authentication and origin
authentication use different reference types and ledgers, and proxy TLS and
origin TLS use different trust/client-identity objects. A JVM worker receives
secret material only through the one-shot protected descriptor/handle channel
defined by the shared JVM-adapter contract. Secret bytes are forbidden in both
the generic bridge frame and the typed `jvm-capability/2` body or digest.

Every TLS evidence record includes JMeter and Java identity where applicable,
JSSE or rustls version/provider/backend, configured and negotiated protocols,
cipher, SNI/ALPN, store types/aliases, and certificate fingerprints without
private material. Provider differences are part of the evidence tuple, not a
normalization excuse.

The HttpClient4/Java/JSSE/JKS paths are useful JVM work and therefore cannot
start until Decision 0001's shared process supervisor is accepted, all direct
process-owning callers have migrated, and its independent platform audit has
passed. They use the role-bound shared source package from Decisions 0004 and
0005, but have a distinct HTTP role, schema, session, class-loader generation,
object table, and terminal state. No direct `Command`, public raw process ID,
shell, PATH lookup, external signal utility, or local cleanup fallback is
permitted. Failure of that gate is `http.capability.process-supervision`, not a
native fallback.

## Recorder and mirror

The HTTP(S) Test Script Recorder is an application-edge intercepting service,
not a mode of the outbound sampler transport. A pure recorder module owns
bounded request normalization, filtering, header removal, grouping, pause
markers, binary-file descriptors, and a lossless recorder IR. The application
owns listeners, CONNECT relays, roots, files, TLS termination, browser/session
policy, and transactional JMX publication.

Recorder output is constructed through the ordinary lossless JMX/model layer.
Cookie and Authorization removal, target-controller insertion, sampler naming,
include/exclude and content-type filters, suggested exclusions, pauses, body
placement, and generated topology are exact oracle contracts. An unknown
request/property cannot be silently discarded.

Exact JMeter recorder certificates—JKS defaults, seven-day validity, dynamic
per-host keys, aliases, keytool discovery, and browser trust material—use the
pinned JVM/keytool adapter. A native rustls recorder is an independently named
capability, never evidence for TLS-002. Recorder startup requires a private
run root, loopback/allowlisted bind and upstream policy, explicit port
reservation/readiness, bounded sessions, and transactional output. External
network recording is denied unless an operator explicitly expands the policy.

The mirror server is a separate bounded local service. Native mirror mode may
implement the pinned HTTP/1.0 request echo/binary/header/redirect contract.
Wildcard bind or compatibility execution requires an isolated network
namespace/firewall capability. It is never confused with an outbound proxy or
recorder.

## Errors, limits, and security

Stable errors identify at least DNS, pool, connect, proxy, TLS, write, read,
framing, decompression, timeout phase, cancellation, body replay, state,
resource limit, unsupported implementation/auth/store, recorder, and mirror
failure. They include source `NodeId`/path and sampler identity but no secret or
unbounded response text. Operational transport failures produce failed samples
where JMeter does; unavailable implementation/security capabilities fail before
useful execution. Exact mapping is differential evidence.

Every error and attempt carries canonical `http.error-context/1`:

```text
ErrorContextV1 {
  source_node: Unknown | DomainQualifiedNode,
  plan_path: BoundedDomainQualifiedNodePath,
  sampler_identity, capability_identity, attempt_index,
  embedded_resource_index: Absent | Present(u32),
  phase, stable_error_code, diagnostics
}

DomainQualifiedNode = {
  plan_domain: PlanDomainId, document_id: [u8; 32], node_id: NonZeroU64
}
PlanDomainId = { schema: "plan-domain/1", value: BoundedUtf8 }
SamplerIdentity = { run_id: [u8; 16], user_id: u64,
                    iteration: u64, sample_id: NonZeroU64 }
CapabilityIdentity = { schema_id: BoundedAscii, version: NonZeroU32,
                       sha256: [u8; 32] }
DiagnosticRecordV1 = { ordinal: NonZeroU32, code: HttpDiagnosticCode,
                       visibility: PublicRedacted, message: BoundedUtf8 }
```

`StableHttpErrorCode` is a closed ASCII enum covering `dns`, `pool`, `connect`,
`proxy`, `tls`, `write`, `read`, `framing`, `decompression`, every
`http.limit.*` code above, `timeout`, `cancelled`, `body-replay`, `body-state`,
`response-lease`, `state-conflict`, `unsupported-implementation`,
`unsupported-auth`, `unsupported-store`, `automation-enabled`,
`budget-invalid`, `recorder`, `mirror`, and `internal-invariant`, each with a
fixed numeric discriminant and canonical dotted spelling. Unknown/custom text
cannot occupy this field. A detailed provider error is a diagnostic, not a new
stable code.

`HttpDiagnosticCode` is closed over `Provider`, `ProtocolDetail`,
`LimitObservation`, `IdentityMismatch`, `Cleanup`, and `SecondaryFailure`.
`PublicRedacted` is the only ordinary diagnostic visibility. Its message is
validated UTF-8, at most 4 KiB, has classified values replaced before storage,
and cannot contain raw URL/path/header/body/certificate/credential data.
Diagnostic encoding uses tags `(1 ordinal, 2 code, 3 visibility, 4 message)`;
the aggregate count/bytes are checked before allocation.

`PlanDomainId.value`, schema identifiers, and canonical stable-code spellings
are at most 256 bytes; a path has at most 128 nodes and 16 KiB canonical bytes;
`attempt_index` is nonzero `u32`; phase is the closed `Phase` enum;
diagnostics contain at most 64 records, 4 KiB each, and 64 KiB aggregate.
Diagnostics are redacted and excluded from equality/compatibility keys. The
path is a bounded source-node sequence, never a URL/filesystem path. The
HTTP crate treats these identities as opaque and does not depend on JMX/model.
Missing context is `Unknown`, never a zero or empty-string sentinel. State
conflicts, replay failures, bridge responses, and final sample mapping retain
the same context. Raw URLs/queries, credentials, bodies, and certificate paths
are excluded.

Path canonicalization is exact: all nodes use the same `plan_domain` and
`document_id`, node IDs are nonzero, adjacent duplicates are forbidden, the
last node equals `source_node` when known, and `Unknown` requires an empty path.
Document IDs, plan domains, sampler/capability IDs, and route/connection/TLS
identity digests derive only from canonical public profile/plan/manifest fields
under their declared domains. Secret bytes, secret references, classified
values, URLs, endpoints, paths, headers, and response/request contents are
forbidden from those identity preimages.

All queues, connection pools, requests, headers, bodies, redirect hops,
embedded resources, DNS entries, cookies, cache entries/bytes, auth entries,
TLS material, certificates, decompression, proxy relays, recorder sessions,
trace output, generated files, diagnostics, retries, and deadlines are finite.
A limit failure never truncates a semantic result into apparent success.

Network correctness tests bind only explicit loopback addresses, use no public
services or ambient credentials, and fail closed on DNS/non-loopback targets.
SSRF policy, metadata/private-address denial, filesystem containment, and
external sandboxing are explicit deployment capabilities rather than hidden
transport heuristics.

## Dependency decision

The new edge crate may use exact-pinned Hyper, Hyper-util, Tokio,
http-body-util, rustls, Tokio-rustls, and narrowly enabled async compression.
Optional platform-root or custom DNS crates require separate features. Default
features are disabled and only required HTTP/client/runtime/TLS/codec features
are enabled. Rustls's cryptographic provider is selected exactly; OpenSSL,
native-tls, AWS-LC, ambient system proxy, and resolver-system-config features
are not pulled in accidentally.

Before adding these packages, `docs/third-party-provenance.md` records purpose,
exact current stable version, features, license, MSRV, build scripts, native C
or assembly risk, transitives, security cadence, and why existing crates/std
are insufficient. The dependency freshness audit must verify versions from
official sources on the change date. A dependency update changes the native
capability identity and reruns the full HTTP/TLS matrix.

## Verification requirements

Pure unit/property/model tests cover request construction, ordered duplicate
headers, state/manager merge and reset, redirect transformations, route/no-proxy
selection, cache/auth challenge state, byte arithmetic, bounds, cancellation,
and no-drop invariants. Fuzz targets cover URLs, headers, status/framing,
chunking, compression descriptors, proxy requests, filters, and recorder IR;
they do not open sockets.

Deterministic loopback integration tests cover HTTP/1.1 framing, partial I/O,
reuse/close, 1xx, chunking/trailers, malformed responses, gzip/deflate limits,
DNS errors, every timeout/cancellation phase, redirects, cookies, cache,
conditional requests, Basic challenges, proxy absolute form, CONNECT, HTTPS
proxy, proxy auth isolation, TLS 1.2/1.3, SNI, ALPN, wrong/expired names,
explicit trust, trust-all, and client certificates. No correctness assertion
uses arbitrary sleeps.

Pinned differential tests run the same local plan through JMeter HttpClient4,
JMeter Java where supported, and the explicitly named native path. They compare
wire traces and neutral results including method/body/header order, sub-result
tree, response data, success/error, redirect behavior, state, timeStamp,
elapsed/latency/connect/idle, sent/received/body/header bytes, and connection
reuse. Only profile-declared fields may be normalized.

An executable `xtask http-acceptance --check` owns the static matrix and refuses
to pass unless every required capability, case, exact dependency/provider
identity, raw diagnostic location, and expected artifact is declared. It does
not execute public network services and it does not convert planned descriptors
into observations. The command and `crates/http-native` do not yet exist; their
absence is an explicit implementation gap, not an omitted acceptance step.

The checker requires the `http.attempt/1`, `http.state-delta/1`,
`http.error-context/1`, `http.parser-limits/1`, body-state/replay, and budget-
handoff schema identities; all finite parser categories; retry ownership and
exact HttpClient4 values; redaction and known/unavailable counter rules; and
redirect/authentication/embedded transaction-boundary declarations.

Recorder evidence covers filters, header stripping, grouping, pauses, binary
files, generated JMX, replay, CONNECT interception, dynamic/static
certificates, JKS/keytool failures, browser trust, cancellation, and atomic
publication. Mirror evidence covers its exact HTTP/1.0/binary/redirect/header
contract in isolation. Cross-platform lanes cover Linux, Windows, and macOS;
Java 8 and 17/provider rows remain distinct.

Acceptance after implementation includes:

```text
cargo fmt --all -- --check
cargo test -p jmeter-rs-http --all-targets --locked
cargo test -p jmeter-rs-http-native --all-targets --locked
cargo clippy -p jmeter-rs-http -p jmeter-rs-http-native \
  --all-targets --all-features --locked -- -D warnings
cargo run --locked -p xtask -- http-acceptance --check
cargo run --locked -p xtask -- profile-check
cargo run --locked -p xtask -- fixture-check
cargo deny check --all-features
cargo audit --deny warnings
```

The local integration, fuzz, sanitizer, cross-platform, pinned JVM/oracle,
performance, and soak commands are separately reproducible CI lanes. A missing
service, certificate provider, JVM, process-containment, browser, network
isolation, or platform lane is a named missing capability, never a pass. Static
fixture checks and native tests cannot promote an HttpClient4/JSSE/JKS row.

## Consequences

Native HTTP can be fast, memory-safe, bounded, and Rust-aligned without
misrepresenting provider-specific JMeter behavior. Exact HttpClient4, Java,
JSSE, JKS, and recorder workflows remain available through explicit pinned JVM
adapters. The separation increases adapter and evidence work but keeps ambient
library defaults, security tradeoffs, and compatibility claims visible.
