# TEST-003 fuzzing groundwork

This directory is a standalone `cargo-fuzz` workspace for the JMeter 5.6.3
compatibility profile. It is intentionally not a member of the application
workspace: `libfuzzer-sys` builds a bundled native C++ libFuzzer runtime by
default and its upstream 0.4.13 support is Linux-only. That native path needs
a C++ compiler and standard library; it must not enter ordinary workspace
builds or cross-platform gates. Campaign execution with `cargo fuzz` also
requires a separately pinned nightly toolchain, which is not selected by this
manifest and has not been run here.

The targets are parser and boundary checks only. They do not open sockets,
read files, inherit environment values, start child processes, invoke a shell,
load Java classes, or execute scripts. Every target keeps conversions and
synthetic allocations behind an explicit bound. JMX and bridge inputs above
their target bound are passed intact to the bounded decoder only to assert an
explicit rejection; neither target truncates an oversized input. The JMX and
JTL codecs retain their own depth/node/field limits as a second boundary.

## Targets

| target | boundary | input bound | seed directory |
| --- | --- | ---: | --- |
| `jmx_xml` | JMX syntax retention, opaque/dropped inventories, bounded semantic canonical round trip | 256 KiB (512 KiB writer cap) | `corpus/jmx_xml` |
| `jtl_csv` | JTL CSV decode, typed input limits, configured/unknown-header projection | 256 KiB (16 KiB records, 128 samples) | `corpus/jtl_csv` |
| `jtl_xml` | JTL XML decode, typed input limits, full wire-model projection | 256 KiB (16 KiB text, 128 samples) | `corpus/jtl_xml` |
| `jtl_model` | generated bounded SampleEvent/SampleResult CSV/XML conservation, save switches, and opaque-child retention | 256 KiB (depth 4, 64 nodes, 16 KiB records) | none (in-memory generator) |
| `expr` | expression scanner/evaluator with undefined, limit, and progress probes | 64 KiB (256 expansions) | `corpus/expr` |
| `bridge` | complete-frame and structured-handshake round trips | 256 KiB (64 KiB payload) | `corpus/bridge` |
| `bridge_rmi` | pure Rust RMI stream codec, lifecycle/order state, sender modes, credit/ack, terminals, and bounds | 256 KiB (64 KiB negotiated frame, 96 generated steps) | `corpus/bridge_rmi` |
| `property_config` | bounded save-service property semantics and unknown-key contract | 64 KiB (64 lines, 2 KiB/line) | `corpus/property_config` |
| `save_config` | generated save-service precedence/provenance model, typed operations, unknown fields, and canonical identity | 64 KiB (8 fields, 48 operations, bounded values) | `corpus/save_config` |
| `http_policy` | URL normalization, duplicate headers, cookie matching/lifecycle | 64 KiB (4 KiB policy fields) | none (synthetic) |
| `plugin_json` | process-free plugin request JSON preflight and typed message limits | 64 KiB (48 KiB raw fields, 32 KiB message) | none (synthetic) |
| `remote` | bounded remote envelopes and worker lifecycle state | 64 KiB (4 KiB fields, 128 KiB messages) | none (synthetic) |
| `runtime` | finite controller traversal and deterministic scheduler state | 64 KiB (8 children, 8 wakes) | none (synthetic) |

The target-level invariant IDs and source-side coverage declarations are
recorded in each target source file and in the machine-readable evidence
descriptor under `campaign/`. JMX source bytes,
opaque element bytes, and upgrade properties explicitly marked as dropped are
checked through separate inventories. CSV and XML JTL use format-specific
wire projections, with every enabled column/attribute/child/assertion/value
included; fields that the format cannot represent are not claimed as coverage.
`jtl_model` supplies an independent generated-model projection in addition to
the arbitrary-byte parser targets, and checks an injected unknown XML child
without touching the filesystem.
The XML target also compares the complete public event model so opaque
attributes/children, element identity, nested metadata, and
absent-versus-empty fields cannot disappear. Bridge checks a complete decoded
frame's consumed prefix and then round-trips all decoded metadata and payload
bytes, including a structured handshake, and has deterministic unknown-kind,
unknown-flag, and preservation-contract probes. `http_policy`, `remote`, and
`runtime` stay at pure in-memory boundaries. `plugin_json` calls the public
preflight validator, whose bounded writer runs before serde allocates an
encoded request, and round-trips the PLUG-003 unknown-JMX preservation
contract through the public handshake API. The property target does not make a
no-drop claim: the
current `SampleSaveConfiguration` API intentionally ignores unrelated keys,
and `CONFIG-UNKNOWN-IGNORED-001` compares that contract with a recognized-only
projection.
`save_config` keeps an independently generated source-operation inventory and
checks precedence selection, absent versus present-empty state, bounded
ambiguity diagnostics, unknown-property retention, and repeatable canonical
bytes/digests without filesystem or process access.

Every target source declares `MAX_INPUT_BYTES`, a source-side inventory or
property-coverage statement, and `//! I/O policy: none`. The repository
`cargo xtask policy-check` statically cross-checks those declarations against
the closed Cargo target registry, verifies the declared corpus/no-corpus mode,
and rejects filesystem, process, environment, or network I/O markers. A
corpus README is documentation, not a seed; every actual seed must be listed
in `corpus/PROVENANCE.md`.

## Fuzz-only dependencies

The standalone manifest keeps `libfuzzer-sys = 0.4.13` exact and separate from
the product workspace; it is the only fuzz-native dependency and builds the
bundled C++ libFuzzer support through `cc`. The added path dependencies are
the existing Apache-2.0, Rust 1.97.1 MSRV pure boundaries: `http` for URL,
header, and cookie policy; `plugin-host` for JSON preflight (bringing its
existing `serde`/`serde_json`, `nix`, and `sha2` graph); `remote` for bounded
codec/state; and `runtime` for controller/scheduler state. No optional
feature, network client, Java binding, process helper, or new native
dependency is enabled by these targets. The standalone lock records the
exact transitive versions and licenses; the application lock is unchanged.

## Corpus provenance

All checked-in seeds are original, hand-authored, deterministic inputs created
for this repository on 2026-08-12. They are small enough to inspect in code
review and use only synthetic names, values, and the reserved
`example.invalid` domain. No JMeter distribution, plugin, customer plan,
credential, private key, or upstream fixture is copied into this corpus. The
repository Apache-2.0 license covers these original seeds.

Seeds intentionally include valid minimal documents, unknown/opaque extension
data, quoting and Unicode, malformed/truncated XML, depth and numeric limits,
malformed CSV, undefined expressions, bridge message variants, and
recognized/unknown save-service properties. They are starting coverage, not
conformance evidence; long fuzz runs and minimized regressions belong in CI
artifacts and should record the actual nightly toolchain, cargo-fuzz/libFuzzer
version, flags, invariant IDs, and profile ID.

## Toolchain and evidence pin

`Cargo.toml` pins `libfuzzer-sys` exactly to `0.4.13`; this is the dependency
version selected for this standalone scaffold and is recorded in the lockfile
when the current local Cargo registry can resolve it. This repository does not
assert a nightly or cargo-fuzz version, because those runner versions are
environment-specific and have not been executed here. A future campaign must
fill the actual values in `campaign/evidence.example.json` (or a copied result
record) and set the linked invariant statuses from `planned` to `observed` or
`failed`.

The fuzz-only `deny.toml` preserves the root wildcard, source, advisory, and
ban policy while allowing NCSA for the bundled libFuzzer sources. It does not
expand the root product dependency policy; fuzz artifacts remain outside the
application workspace and product release graph.

## Static validation

The repository task that adds this scaffold runs only source/manifest checks:

```sh
cargo metadata --manifest-path fuzz/Cargo.toml --offline --locked --format-version 1
cargo check --manifest-path fuzz/Cargo.toml --offline --locked --bins
rustfmt --check fuzz/fuzz_targets/*.rs
python3 -m json.tool fuzz/campaign/evidence.schema.json
python3 -m json.tool fuzz/campaign/evidence.example.json
```

No `cargo fuzz` command is run as part of this scaffold. Once a nightly
toolchain and pinned `cargo-fuzz` are available, a separate CI job may run the
targets with bounded corpus/artifact directories and retain minimized inputs
under the provenance policy.
