<!-- SPDX-License-Identifier: Apache-2.0 -->

# Third-party provenance

This is the current release provenance and license ledger for third-party
material intentionally present in the source tree. It was checked on
2026-08-13 from the active compatibility profile, the current manifests and
lockfile, the current dependency policy, the generated data headers, and the
pinned local Apache JMeter distribution. The historical research documents are
not the source for the dependency facts below.

## Apache JMeter registry data

The two files below are derived from Apache JMeter 5.6.3 and are embedded by
`crates/jmx/src/registry.rs`. They are the registry-data form of the Apache
JMeter source-derived material intentionally redistributed by the jmeter-rs
source tree; the generated CFG-002 property inventory is documented below:

- `crates/jmx/data/saveservice-5.6.3.properties`
- `crates/jmx/data/upgrade-5.6.3.properties`

The source pin is Apache JMeter `rel/v5.6.3` at commit
`34a2785748e9e0b14702595e8682c387869deda3`. The pinned source files are
`bin/saveservice.properties` and `bin/upgrade.properties`, respectively. The
corresponding local source copies used for this record are in the ignored
oracle extraction at
`jmeter-oracle-cache/apache-jmeter-5.6.3/bin/`. The local extraction and any
JMeter distribution archive are oracle/cache material, not release content.

### Hashes and transformation

The `source LF SHA-256` value is also the `embedded body SHA-256`: it hashes the
entire upstream file after line-ending normalization, including the upstream
Apache license header. The generated-file hash is over the complete local data
file after LF normalization. All hashes are SHA-256.

| Generated file | Pinned source path | Raw source bytes | Raw source SHA-256 | Source LF / embedded body bytes | Source LF / embedded body SHA-256 | Metadata prefix bytes | Metadata prefix SHA-256 | Generated LF bytes | Generated LF SHA-256 |
| --- | --- | ---: | --- | ---: | --- | ---: | --- | ---: | --- |
| `crates/jmx/data/saveservice-5.6.3.properties` | `bin/saveservice.properties` | 25,672 | `fcc28aeaced4c0e170e7a89089f6e9492f70be30b4c5aadbf6bbdefa660ad5a9` | 25,237 | `4d510edae46db11575a5d4c67327eefa676bdb4bb43b1baa05228deda4e13c1b` | 409 | `c8f5a107f0c8a1c4dbbc01bd12cd0ccb0f8cfc9b8787d4743002778e65b405d6` | 25,646 | `eca06d3b962db3966e91f5670e1d28e9b1b08b4c82cd52f2730a4eb80da838e2` |
| `crates/jmx/data/upgrade-5.6.3.properties` | `bin/upgrade.properties` | 7,481 | `43295cd0904ab61daf47dd9de780007beaabc617aadd01c7a19a42a9286ff3f2` | 7,356 | `c9fab3dfdb4b71b1ae07281044060448fdae154ef1a041faf266ebfb74f142ff` | 401 | `7aaf92ed1627e9e28b4e5d7552c444a425d5e3fbbc5fbd9f573142d0b0dc919d` | 7,757 | `ca4be70124d06d75425d25e5993a587d7263e4561563395c82d1fb002568b831` |

The reproducible transformation is:

```text
generated file = four-line metadata prefix + LF-normalize(pinned source file)
```

The source extraction uses CRLF for all 435 `saveservice.properties` lines and
all 125 `upgrade.properties` lines. The generated files use LF. Apart from
that line-ending conversion, the source suffix is byte-for-byte unchanged:
there are no key, value, ordering, or whitespace edits in the registry data.
The four-line prefix identifies the commit, source URL, reproduction command,
retrieval date, and repository license/notice files. The generated files also
retain the complete upstream Apache-2.0 header in their unchanged source
suffix. The prefix is a modification notice, not an ASF-generated-file claim.

The source links represented by the generated headers are:

- <https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/bin/saveservice.properties>
- <https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/bin/upgrade.properties>

### License, notice, and redistribution decision

The derived registry data are redistributed under Apache License 2.0 with the
upstream license header retained. The root `LICENSE` supplies the Apache-2.0
terms, and the root `NOTICE` retains the applicable ASF attribution from the
pinned JMeter distribution:

- Apache JMeter
- Copyright 1998-2024 The Apache Software Foundation
- the distribution's statement that the product includes software developed
  at the Apache Software Foundation

The root `NOTICE` is a standalone jmeter-rs notice file. It copies only the
short ASF attribution excerpt above from the pinned distribution's standalone
JMeter `NOTICE`: the product name, copyright line, and two-line
ASF-development attribution. It is not a copy of the complete JMeter NOTICE
and is not a substitute for the full notices of a JMeter distribution. The
complete JMeter `NOTICE`, JMeter `LICENSE`, and third-party JAR notices are not
copied into this repository because the JMeter distribution itself is not
redistributed. The attribution above applies to the two derived registry files
and the generated CFG-002 inventory described below. jmeter-rs is an independent
project and this attribution does not imply
ASF affiliation, sponsorship, endorsement, or ownership of the original
jmeter-rs implementation.

The redistribution boundary is therefore:

- **Included:** the two small, transformed Apache JMeter registry data files
  under `crates/jmx/data`, with their source pin, Apache-2.0 header, modification
  note, and root NOTICE attribution.
- **Excluded:** the downloaded JMeter archive and extracted distribution,
  JMeter binaries and third-party JARs, keys or signatures, raw oracle output,
  logs, and dependency caches. These remain local oracle/cache material and
  must not be added to a release.

If a future release bundles a JMeter distribution or any of its third-party
JARs, this narrow registry record is insufficient: the complete corresponding
JMeter license, NOTICE, and third-party notice set must travel with that
bundle, after a separate redistribution review.

## CFG-002 property inventory

`compat/inventory/jmeter-5.6.3/properties.json` is a generated, selected
source inventory for compatibility row `CFG-002`. It is inventory data, not a
copy of the JMeter distribution and not conformance evidence; the active
profile row remains `planned` with `inventory_status: TODO`.

The generator reads exactly these six regular files from the ignored local
extraction. They are Apache JMeter 5.6.3 `rel/v5.6.3` sources at commit
`34a2785748e9e0b14702595e8682c387869deda3`:

| Local source path | Pinned Apache source URL |
| --- | --- |
| `jmeter-oracle-cache/apache-jmeter-5.6.3/bin/jmeter.properties` | <https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/bin/jmeter.properties> |
| `jmeter-oracle-cache/apache-jmeter-5.6.3/bin/reportgenerator.properties` | <https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/bin/reportgenerator.properties> |
| `jmeter-oracle-cache/apache-jmeter-5.6.3/bin/saveservice.properties` | <https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/bin/saveservice.properties> |
| `jmeter-oracle-cache/apache-jmeter-5.6.3/bin/system.properties` | <https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/bin/system.properties> |
| `jmeter-oracle-cache/apache-jmeter-5.6.3/bin/upgrade.properties` | <https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/bin/upgrade.properties> |
| `jmeter-oracle-cache/apache-jmeter-5.6.3/bin/user.properties` | <https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/bin/user.properties> |

The pinned source artifact is `apache-jmeter-5.6.3.zip` with SHA-512
`387fadca903ee0aa30e3f2115fdfedb3898b102e6b9fe7cc3942703094bd2e65b235df2b0c6d0d3248e74c9a7950a36e42625fd74425368342c12e40b0163076`.
The six source files carry Apache License 2.0 headers that refer to the pinned
distribution's top-level `LICENSE` and `NOTICE`. The generated inventory is
redistributed under the repository's Apache-2.0 terms in
[`LICENSE`](../LICENSE), with the short Apache JMeter attribution in
[`NOTICE`](../NOTICE); the review record is this document.

### Transformation and modification notice

Rebuild with the command recorded in the generated metadata:

```sh
cargo xtask property-inventory --generate
cargo xtask property-inventory --check
```

The bounded, offline transformation reads raw bytes, records each source
file's SHA-256 and size, parses declaration candidates in physical order, and
serializes stable pretty JSON with a trailing line feed. It preserves duplicate
occurrences, empty defaults, active/commented state, source spelling, and
continuation spans. A family is copied only from deterministic bounded comment
context; consumer and sensitivity classifications remain unresolved when the
source does not establish them. It does not retrieve or unpack the archive,
decode Java properties, merge effective values, invoke Java/JMeter, or copy the
source files wholesale. The generated metadata and selected declaration text
are therefore a modified, machine-readable inventory, not upstream source
files; the modification notice and source hashes remain in `properties.json`.

### Redistribution review

The review decision is to redistribute only the generated inventory metadata
and selected declaration spelling from the six pinned properties files under
Apache-2.0, with the root NOTICE attribution. The complete JMeter archive and
extraction, binaries, third-party JARs, complete upstream `LICENSE`/`NOTICE`
and third-party notice bundle, raw oracle output, logs, credentials, and
dependency caches are excluded. A future release that bundles any of those
materials requires a separate redistribution review. This inventory's
provenance metadata names `LICENSE`, `NOTICE`, and this document as the review
documents so the decision is reproducible without copying upstream notice text.

## Current dependency and license ledger

The root workspace currently has 18 workspace package records and 186 registry
package records in `Cargo.lock` (204 `[[package]]` records total). Workspace
package metadata inherits `license = "Apache-2.0"` and `publish = false` from
the root `Cargo.toml`; path dependencies are internal and are not repeated in
the external ledger.

This section is the current dependency record, checked against the manifests,
both lockfiles, and the local Cargo registry metadata on 2026-08-13. The
research file `docs/research/dependency-baseline.md` is a historical,
pre-integration snapshot; its broad ranges and package counts are not current
release evidence. Direct external declarations below are exact pins. The
selected versions were checked against the official crates.io API on
2026-08-13 UTC; the API records and the exact lock checksums are listed below.

### Direct external declarations

The versions in the “lock” column are the currently selected versions in the
root lockfile. A manifest range is recorded separately where it is not exact.

| Manifest | Direct external declaration | Current lock version and license fact |
| --- | --- | --- |
| `crates/java-bridge/Cargo.toml` (historical concurrent entry) | `nix = "=0.31.3"`, `default-features = false`, `process` and `signal` | Historical `nix 0.31.3` record; the active manifest now uses the internal process-supervision path crate (see note below) |
| `crates/plugin-host/Cargo.toml` | `nix = "=0.31.3"`, `default-features = false`, `fs`, `process`, `signal`; `serde = "=1.0.229"`, `default-features = false`, `derive`/`std`; `serde_json = "=1.0.151"`, `default-features = false`, `std`; `sha2 = "=0.11.0"`, `default-features = false` | `nix 0.31.3` (MIT, MSRV 1.69); `serde 1.0.229` and `serde_json 1.0.151` (MIT OR Apache-2.0, MSRVs 1.56 and 1.71); `sha2 0.11.0` (MIT OR Apache-2.0, MSRV 1.85); no native compiler dependency |
| `tools/jmeter-oracle/Cargo.toml` | `serde = "=1.0.229"`, `default-features = false`, `derive`/`std`; `serde_json = "=1.0.151"`, `default-features = false`, `std`; `sha2 = "=0.11.0"`, `default-features = false`; `nix = "=0.31.3"`, `default-features = false`, `fs`, `process`, `signal` | Same selected versions and licenses/MSRVs as above; `nix` is MIT/MSRV 1.69; no native compiler dependency |
| `crates/process-supervision/Cargo.toml` | Unix: `rustix = "=1.1.4"`, `default-features = false`, `std`/`process`; Windows: `windows-sys = "=0.61.2"`, `default-features = false`, `Win32_Foundation`, `Win32_Security`, `Win32_System_JobObjects`, `Win32_System_Pipes`, `Win32_System_Threading` | `rustix 1.1.4` (Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT, MSRV 1.63, Rust-only cfg/backend build helper); `windows-sys 0.61.2` (MIT OR Apache-2.0, MSRV 1.71, no build script); Windows-only `windows-link 0.2.1` (MIT OR Apache-2.0, MSRV 1.71, no build script) |
| `tools/xtask/Cargo.toml` | `serde_json = "=1.0.151"`, `default-features = false`, `std`; `sha2 = "=0.11.0"`, `default-features = false`; `toml = "=1.1.4"`, `default-features = false`, `parse`/`serde` | `serde_json 1.0.151`, `sha2 0.11.0`, `toml 1.1.4+spec-1.1.0` (MIT OR Apache-2.0; MSRVs 1.71, 1.85, and 1.85); no native compiler dependency |

The current `crates/java-bridge/Cargo.toml` uses the internal
`jmeter-rs-process-supervision` path crate and does not directly declare `nix`;
the `nix` entry above is retained as historical provenance from the concurrent
process-boundary pass. The official registry verification below reflects the
active manifests, including `crates/bridge-protocol/Cargo.toml`'s pure
`sha2` dependency.

The HTTP-native edge has the following additional direct registry
declarations. The feature column is the manifest declaration (not Cargo's
expanded transitive feature closure); the checksum is the exact root-lock
archive checksum. `runtime` means the package can be part of a product
binary, while `dev-only` means it is reachable only through the HTTP-native
or application test dependency graphs.

| Manifest | Exact declaration and selected features | Locked checksum | License; published MSRV | Cargo source; upstream repository | Release role |
| --- | --- | --- | --- | --- | --- |
| `crates/http-native/Cargo.toml` | `rustls = "=0.23.43"`, `default-features = false`, `ring`, `std`, `tls12` | `0283386ce02abc0151e1761d08802dfe86c173b0b494af5cbc086574e453da06` | Apache-2.0 OR ISC OR MIT; 1.71 | `registry+https://github.com/rust-lang/crates.io-index`; [rustls](https://github.com/rustls/rustls) | runtime |
| `crates/http-native/Cargo.toml` `[dev-dependencies]` | `rcgen = "=0.14.9"`, `default-features = false`, `crypto`, `ring` | `091e7a8e7d86e6feb87a27ce8e2cba29d49eff9507afeebefab7eeb2ca667fb4` | MIT OR Apache-2.0; 1.88 | `registry+https://github.com/rust-lang/crates.io-index`; [rcgen](https://github.com/rustls/rcgen) | dev-only; local certificate fixtures only |
| `apps/jmeter-rs/Cargo.toml` `[dev-dependencies]` | `rcgen = "=0.14.9"`, `default-features = false`, `crypto`, `ring` | `091e7a8e7d86e6feb87a27ce8e2cba29d49eff9507afeebefab7eeb2ca667fb4` | MIT OR Apache-2.0; 1.88 | `registry+https://github.com/rust-lang/crates.io-index`; [rcgen](https://github.com/rustls/rcgen) | dev-only; ephemeral native HTTP run-owner CA generation; no persisted key/certificate |
| `crates/http-native/Cargo.toml` | `hickory-resolver = "=0.26.1"`, `default-features = false`, `tokio` | `f0d58d28879ceecde6607729660c2667a081ccdc082e082675042793960f178c` | MIT OR Apache-2.0; 1.88 | `registry+https://github.com/rust-lang/crates.io-index`; [hickory-dns](https://github.com/hickory-dns/hickory-dns) | runtime; explicit numeric UDP DNS only |
| `crates/http-native/Cargo.toml` | `mio = { version = "=1.2.2", default-features = false, features = ["os-poll", "net"] }` | `30d65c71f1ce40ab09135ce117d742b9f8a19ff91a41a8b57ed50bc2de59c427` | MIT; 1.71; `build = false` (no build script/native compiler) | `registry+https://github.com/rust-lang/crates.io-index`; [Mio](https://github.com/tokio-rs/mio) | runtime; one nonblocking connect attempt/cancellation readiness edge; not an async runtime/provider |
| `crates/http-native/Cargo.toml` | `async-compression = "=0.4.43"`, `default-features = false`, `tokio`, `gzip`, `zlib`, `deflate`, `brotli` | `3976abdc8fe7d1133d43d304afd42abdf5bc3e1319d263d223bde07b5efc4be8` | MIT OR Apache-2.0; 1.83; `build = false` (Rust-only codec adapters) | `registry+https://github.com/rust-lang/crates.io-index`; [async-compression](https://github.com/Nullus157/async-compression) | runtime; bounded caller-owned response decompression; no automatic/ambient codec selection |
| `crates/http-native/Cargo.toml` | `tokio = "=1.53.1"`, `default-features = false`, `io-util`, `macros`, `net`, `sync`, `time` | `202caea871b69668250d242070849eb495be178ed697a3e98aebce5bc81a0bed` | MIT; 1.71 | `registry+https://github.com/rust-lang/crates.io-index`; [Tokio](https://github.com/tokio-rs/tokio) | runtime; bounded actor and explicit async codec I/O/deadline support |

#### Official crates.io currency verification

The following official crates.io API records were queried on 2026-08-13 UTC.
For each listed package, `max_stable_version` matched the exact locked pin and
the selected version record reported `yanked: false`; the API's
`rust_version`, license, repository, and checksum fields were also checked.
`registry+https://github.com/rust-lang/crates.io-index` is the Cargo source for
every row. “Runtime” means reachable from a product binary; “tooling” means a
test/oracle/xtask binary; “dev-only” means reachable only through
`[dev-dependencies]`.

| Package | Active manifest role and exact features | Locked version / checksum | Official latest-stable API; MSRV; license; upstream | Runtime-vs-dev |
| --- | --- | --- | --- | --- |
| `serde` | plugin-host + oracle; `=1.0.229`, defaults off, `derive`, `std` | `1.0.229` / `4148590afebada386688f18773da617792bf2ef03ffc1e4cbd2b1d45b023e0ba` | [API](https://crates.io/api/v1/crates/serde); 1.56; MIT OR Apache-2.0; [serde-rs/serde](https://github.com/serde-rs/serde) | runtime + tooling |
| `serde_json` | plugin-host + oracle + xtask; `=1.0.151`, defaults off, `std` | `1.0.151` / `c841b55ecdae098c80dcae9cf767f6f8a0c2cdb3416bbef72181df4d0fe73f14` | [API](https://crates.io/api/v1/crates/serde_json); 1.71; MIT OR Apache-2.0; [serde-rs/json](https://github.com/serde-rs/json) | runtime + tooling |
| `sha2` | bridge-protocol + plugin-host + oracle + xtask; `=0.11.0`, defaults off | `0.11.0` / `446ba717509524cb3f22f17ecc096f10f4822d76ab5c0b9822c5f9c284e825f4` | [API](https://crates.io/api/v1/crates/sha2); 1.85; MIT OR Apache-2.0; [RustCrypto/hashes](https://github.com/RustCrypto/hashes) | runtime + tooling |
| `nix` | plugin-host + oracle; `=0.31.3`, defaults off, `fs`, `process`, `signal` | `0.31.3` / `cf20d2fde8ff38632c426f1165ed7436270b44f199fc55284c38276f9db47c3d` | [API](https://crates.io/api/v1/crates/nix); 1.69; MIT; [nix-rust/nix](https://github.com/nix-rust/nix) | runtime + tooling |
| `rustix` | process-supervision Unix target; `=1.1.4`, defaults off, `std`, `process` | `1.1.4` / `b6fe4565b9518b83ef4f91bb47ce29620ca828bd32cb7e408f0062e9930ba190` | [API](https://crates.io/api/v1/crates/rustix); 1.63; Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT; [bytecodealliance/rustix](https://github.com/bytecodealliance/rustix) | runtime |
| `windows-sys` | process-supervision Windows target; `=0.61.2`, defaults off, `Win32_Foundation`, `Win32_Security`, `Win32_System_JobObjects`, `Win32_System_Pipes`, `Win32_System_Threading` | `0.61.2` / `ae137229bcbd6cdf0f7b80a31df61766145077ddf49416a728b02cb3921ff3fc` | [API](https://crates.io/api/v1/crates/windows-sys); 1.71; MIT OR Apache-2.0; [microsoft/windows-rs](https://github.com/microsoft/windows-rs) | runtime, Windows-only |
| `hickory-resolver` | http-native runtime; `=0.26.1`, defaults off, `tokio` | `0.26.1` / `f0d58d28879ceecde6607729660c2667a081ccdc082e082675042793960f178c` | [API](https://crates.io/api/v1/crates/hickory-resolver); 1.88; MIT OR Apache-2.0; [hickory-dns/hickory-dns](https://github.com/hickory-dns/hickory-dns) | runtime |
| `mio` | http-native runtime; `=1.2.2`, defaults off, `os-poll`, `net` | `1.2.2` / `30d65c71f1ce40ab09135ce117d742b9f8a19ff91a41a8b57ed50bc2de59c427` | [API](https://crates.io/api/v1/crates/mio); 1.71; MIT; [tokio-rs/mio](https://github.com/tokio-rs/mio) | runtime |
| `rustls` | http-native runtime; `=0.23.43`, defaults off, `ring`, `std`, `tls12` | `0.23.43` / `0283386ce02abc0151e1761d08802dfe86c173b0b494af5cbc086574e453da06` | [API](https://crates.io/api/v1/crates/rustls); 1.71; Apache-2.0 OR ISC OR MIT; [rustls/rustls](https://github.com/rustls/rustls) | runtime |
| `async-compression` | http-native runtime; `=0.4.43`, defaults off, `tokio`, `gzip`, `zlib`, `deflate`, `brotli` | `0.4.43` / `3976abdc8fe7d1133d43d304afd42abdf5bc3e1319d263d223bde07b5efc4be8` | [API](https://crates.io/api/v1/crates/async-compression); 1.83; MIT OR Apache-2.0; [Nullus157/async-compression](https://github.com/Nullus157/async-compression) | runtime |
| `tokio` | http-native runtime; `=1.53.1`, defaults off, `io-util`, `macros`, `net`, `sync`, `time` | `1.53.1` / `202caea871b69668250d242070849eb495be178ed697a3e98aebce5bc81a0bed` | [API](https://crates.io/api/v1/crates/tokio); 1.71; MIT; [tokio-rs/tokio](https://github.com/tokio-rs/tokio) | runtime |
| `toml` | xtask; `=1.1.4`, defaults off, `parse`, `serde` | `1.1.4+spec-1.1.0` / `3aace63f4bbcdfc2c965b059de67119c89c4017a70d633be6c104910f67056f5` | [API](https://crates.io/api/v1/crates/toml); 1.85; MIT OR Apache-2.0; [toml-rs/toml](https://github.com/toml-rs/toml) | tooling |
| `rcgen` | http-native + app run-owner tests; `=0.14.9`, defaults off, `crypto`, `ring` | `0.14.9` / `091e7a8e7d86e6feb87a27ce8e2cba29d49eff9507afeebefab7eeb2ca667fb4` | [API](https://crates.io/api/v1/crates/rcgen); 1.88; MIT OR Apache-2.0; [rustls/rcgen](https://github.com/rustls/rcgen) | dev-only; ephemeral in-memory certificate generation, no runtime/native product path |
| `rustls-webpki` | transitive rustls runtime closure; `rustls` `0.23.43` requires `^0.103.5`; active `alloc`, `ring`, `std` | `0.103.14` / `0527518605e68109d875e248ea259b6758801cf165e4b2c2733ae3b51f12535a` | [API](https://crates.io/api/v1/crates/rustls-webpki); 1.71; ISC; [rustls/webpki releases](https://github.com/rustls/webpki/releases) | runtime |
| `ring` | rustls runtime provider and rcgen test provider; `0.17.14` | `0.17.14` / `a4689e6c2294d81e88dc6261c768b63bc4fcdb852be6d1352498b114f61383b7` | [API](https://crates.io/api/v1/crates/ring); 1.66; Apache-2.0 AND ISC; [briansmith/ring](https://github.com/briansmith/ring) | runtime + dev-only |
| `cc` | ring build dependency; `1.4.2` | `1.4.2` / `5d262e149917187838d5b42777c8253bcb64500067342904e7d429499a6f277e` | [API](https://crates.io/api/v1/crates/cc); 1.64; MIT OR Apache-2.0; [rust-lang/cc-rs](https://github.com/rust-lang/cc-rs) | runtime build |

The `rustls-webpki` API reports `0.103.14` as the latest stable release on
the `0.103` line and `yanked: false`; no later stable `0.103.x` record exists
in that official version list (the newer `0.104.0-alpha.7` is a prerelease).
Its `^0.103.5` requirement from rustls `0.23.43` admits `0.103.14`, while its
MSRV remains 1.71. The targeted reproducible refresh was
`cargo update -p rustls-webpki --precise 0.103.14`; an audit downgrade to
`0.103.13` changed only the two version/checksum lines, and rerunning the
targeted command restored the exact `0.103.14` lock snapshot.

The preceding direct-dependency tables record the active Rust-1.97.1-compatible
pins. The transitive `rustls-webpki` record was advanced from `0.103.13` to
the current compatible `0.103.14` with the targeted command
`cargo update -p rustls-webpki --precise 0.103.14`; its new checksum is
`0527518605e68109d875e248ea259b6758801cf165e4b2c2733ae3b51f12535a`.
This is a package-currency observation dated 2026-08-13, not a claim that a
future registry release cannot supersede these versions.

The normal HTTP-native path selects rustls's `ring` provider and explicitly
enables `std` and TLS 1.2; it does not enable rustls defaults, AWS-LC,
OpenSSL, `native-tls`, or resolver/system-configuration features. The DNS
path selects Hickory's `tokio` feature with all defaults disabled and uses
only configured numeric UDP nameservers; system-config/resolv-conf/hosts-file,
IDNA search discovery, DoH/DoT, HTTPS, QUIC, and resolver TLS features are not
selected. Hickory's lock-only optional JNI/OS configuration records are not
active in the selected feature graph. Tokio supplies the single actor runtime;
the resolver does not create a runtime or thread per request. `rcgen` is
dev-only and is not linked by a product binary. Both the http-native and app
run-owner tests generate certificates in memory and retain no private key or
certificate fixture. Its `crypto`/`ring` features pull a second, test-only
certificate-generation branch through the packages
identified below; they do not change the runtime provider. The active feature
closure and normal/build/dev distinction were checked with
`cargo tree --locked -e features -p jmeter-rs-http-native`.
That tree records active `rustls` features `ring`, `std`, and `tls12`, active
`rustls-webpki` features `alloc`, `ring`, and `std`, active
`rustls-pki-types` features `alloc`, `default`, and `std`, the ring
`alloc`/`default`/`dev_urandom_fallback` closure, and dev-only rcgen
`crypto`/`ring`. Optional AWS-LC, rcgen PEM, rcgen
x509-parser, and other unselected branches remain lock-only records where
applicable.

Mio is intentionally narrower than the other HTTP-native runtime dependencies:
it is used only for the one admitted nonblocking connect attempt and its
cancellation readiness wake. `std::net` remains sufficient for post-connect
I/O, but std alone does not provide the portable readiness registration and
`Waker` needed to wait on that single in-flight connect without repeatedly
starting short attempts. The direct declaration's exact `os-poll`/`net`
features do not turn Mio into an async runtime or HTTP provider. Tokio's
selected `net` feature also unifies Mio's `os-ext` feature in Cargo's expanded
closure; no Mio API beyond this connect edge is used. Mio has no build script,
C/C++ or assembly compiler boundary, and only target-specific system bindings
(`libc` on Unix/hermit/WASI, `windows-sys` on Windows, and `wasi` on WASI).

`rustls-pemfile 2.2.0` was removed from the HTTP-native manifest on
2026-08-13 because it was unused and its repository is archived; [RustSec
records it as unmaintained under RUSTSEC-2025-0134](https://rustsec.org/advisories/RUSTSEC-2025-0134)
(see the [upstream archive announcement](https://github.com/rustls/pemfile/issues/61)).
Future TLS code should use the `rustls::pki_types` DER/PEM APIs, including
[`PemObject`](https://docs.rs/rustls-pki-types/latest/rustls_pki_types/pem/trait.PemObject.html),
if needed. The package is no longer in the active manifest or lockfile, so
this advisory is absent from the remaining dependency graph.

Default features are disabled on every production direct registry dependency;
the manifests opt into only the platform, serialization, hashing, TOML, DNS, or
HTTP/TLS features shown above. Published MSRVs observed in the selected root
packages are below the workspace MSRV 1.97.1. `nix` has a Rust cfg-alias build
helper, and `rustix` has a Rust-only cfg/backend build helper; neither
introduces a C/C++ compiler or system-library build boundary. `windows-sys`
has no build script. `ring 0.17.14` has an Apache-2.0 AND ISC license and a
`build.rs` that uses `cc 1.4.2` to compile its bundled C/assembly crypto
sources; this is the only new runtime native-compiler boundary. Its target
risk is build-toolchain and target-specific bundled assembly selection: each
release target must provide the compiler/toolchain and platform support that
`cc`/`ring` require, and cross-compilation must not be inferred from a host
build. The HTTP native graph has no OpenSSL, AWS-LC, `native-tls`, `pkg-config`,
`bindgen`, or `cmake` package or feature path. The expected `windows-sys 0.52.0`/`0.61.2`
duplication comes from ring versus rustix/process supervision; the 0.52 target
support crates are runtime-only target-specific transitives. The selected
Hickory UDP/Tokio path has no required native compiler or system
library build step; optional JNI and OS resolver records are lock-only because
the system-config feature is disabled. The root lockfile
has no Git or unknown-registry source.

The standalone `fuzz/Cargo.toml` is a separate cargo-fuzz workspace. It now
declares `rust-version = "1.97.1"`, `license = "Apache-2.0"`, and the exact
direct pin `libfuzzer-sys = "=0.4.13"`. Its default `link_libfuzzer` feature is
intentional: the package's build script compiles the bundled C++17 libFuzzer
runtime and links the platform C++ standard library (normally `stdc++` on
Linux). This native compiler boundary is isolated from the product workspace;
the separately pinned nightly required by cargo-fuzz remains tooling policy,
not the package MSRV.

The standalone fuzz lock currently contains 41 package records: ten local
path packages and 31 registry packages. The fuzz package declares only the
direct registry pin `libfuzzer-sys = "=0.4.13"` in `fuzz/Cargo.toml`; every
other registry row below is transitive through that package or through the
fuzz target's path dependency `jmeter-rs-plugin-host`. This direct-versus-
transitive distinction is relative to the standalone fuzz manifest, not to
the individual path-package manifests. Every registry row is sourced from
crates.io, has the exact checksum recorded in `fuzz/Cargo.lock`, and is
reference-only (`ref-only`): no registry archive, crate source, or third-party
license file is vendored in this repository. The ten path packages inherit
the workspace's Apache-2.0 metadata and are not third-party records.

The Cargo source for every row is exactly
`registry+https://github.com/rust-lang/crates.io-index`; the repository link in
the final column is the package manifest's upstream repository, not a Git
dependency. License expressions and versions below were read from the current
Cargo package metadata for the locked records. The checksum is the exact
Cargo lockfile checksum (SHA-256 of the registry package archive).

| Manifest relationship | Fuzz registry package / locked version | Published MSRV | Cargo lock checksum | License expression | Dependency path | Purpose / selected role | Cargo source; upstream repository |
| --- | --- | --- | --- | --- | --- | --- | --- |
| transitive | `arbitrary 1.4.2` | 1.63 | `c3d036a3c4ab069c7b410a2ce876bd74808d2d0888a82667669f8e783a898bf1` | MIT OR Apache-2.0 | `libfuzzer-sys` | Structured fuzz-input generation trait | `registry+https://github.com/rust-lang/crates.io-index`; [arbitrary](https://github.com/rust-fuzz/arbitrary/) |
| transitive | `bitflags 2.13.1` | 1.56 | `b588b76d00fde79687d7646a9b5bdf3cc0f655e0bbd080335a95d7e96f3587da` | MIT OR Apache-2.0 | `plugin-host` → `nix` | Flag-type macros used by `nix` | `registry+https://github.com/rust-lang/crates.io-index`; [bitflags](https://github.com/bitflags/bitflags) |
| transitive | `block-buffer 0.12.1` | 1.85 | `d2f6c7dbe95a6ed67ad9f18e57daf93a2f034c524b99fd2b76d18fdfeb6660aa` | MIT OR Apache-2.0 | `plugin-host` → `sha2` → `digest` | Block-processing buffers used by `digest` | `registry+https://github.com/rust-lang/crates.io-index`; [utils](https://github.com/RustCrypto/utils) |
| transitive | `cc 1.4.2` | 1.64 | `5d262e149917187838d5b42777c8253bcb64500067342904e7d429499a6f277e` | MIT OR Apache-2.0 | `libfuzzer-sys` | Build helper for bundled libFuzzer native code | `registry+https://github.com/rust-lang/crates.io-index`; [cc-rs](https://github.com/rust-lang/cc-rs) |
| transitive | `cfg-if 1.0.4` | 1.32 | `9330f8b2ff13f34540b44e946ef35111825727b38d33286ef986142615121801` | MIT OR Apache-2.0 | `plugin-host` → `nix`/`sha2`; `cc` → `jobserver` → `getrandom` | Portable compile-time configuration selection | `registry+https://github.com/rust-lang/crates.io-index`; [cfg-if](https://github.com/rust-lang/cfg-if) |
| transitive | `cfg_aliases 0.2.2` | not declared | `f079e83a288787bcd14a6aea84cee5c87a67c5a3e660c30f557a3d24761b3527` | MIT | `plugin-host` → `nix` (build) | `nix` build-script cfg alias helper | `registry+https://github.com/rust-lang/crates.io-index`; [cfg_aliases](https://github.com/katharostech/cfg_aliases) |
| transitive | `cpufeatures 0.3.0` | 1.85 | `8b2a41393f66f16b0823bb79094d54ac5fbd34ab292ddafb9a0456ac9f87d201` | MIT OR Apache-2.0 | `plugin-host` → `sha2` | Runtime CPU-feature detection used by SHA-2 | `registry+https://github.com/rust-lang/crates.io-index`; [utils](https://github.com/RustCrypto/utils) |
| transitive | `crypto-common 0.2.2` | 1.85 | `ce6e4c961d6cd6c9a86db418387425e8bdeaf05b3c8bc1411e6dca4c252f1453` | MIT OR Apache-2.0 | `plugin-host` → `sha2` → `digest` | Common cryptographic algorithm traits | `registry+https://github.com/rust-lang/crates.io-index`; [traits](https://github.com/RustCrypto/traits) |
| transitive | `digest 0.11.3` | 1.85 | `f1dd6dbb5841937940781866fa1281a1ff7bd3bf827091440879f9994983d5c2` | MIT OR Apache-2.0 | `plugin-host` → `sha2` | Hash/MAC digest traits used by SHA-2 | `registry+https://github.com/rust-lang/crates.io-index`; [traits](https://github.com/RustCrypto/traits) |
| transitive | `find-msvc-tools 0.1.10` | 1.64 | `26b73573e6edcd2af0cdf47bd6cb58f0b3839491263c314eaad1ccf24430e1de` | MIT OR Apache-2.0 | `libfuzzer-sys` → `cc` | Windows tool discovery used by `cc` | `registry+https://github.com/rust-lang/crates.io-index`; [cc-rs](https://github.com/rust-lang/cc-rs) |
| transitive | `getrandom 0.4.3` | 1.85 | `300e883d756b2e4ec94e02791f39b04b522276138852cfc41d9fb7e904106099` | MIT OR Apache-2.0 | `libfuzzer-sys` → `cc` → `jobserver` | Target-specific system entropy support for `jobserver` | `registry+https://github.com/rust-lang/crates.io-index`; [getrandom](https://github.com/rust-random/getrandom) |
| transitive | `hybrid-array 0.4.14` | 1.85 | `707114b52a152fa7bdb290cd7cd5912d9467273b6d74e21b8d81aca1f8533f6b` | MIT OR Apache-2.0 | `plugin-host` → `sha2` → `digest` | Array types used by `digest`/`crypto-common` | `registry+https://github.com/rust-lang/crates.io-index`; [hybrid-array](https://github.com/RustCrypto/hybrid-array) |
| transitive | `itoa 1.0.18` | 1.68 | `8f42a60cbdf9a97f5d2305f08a87dc4e09308d1276d28c869c684d7777685682` | MIT OR Apache-2.0 | `plugin-host` → `serde_json` | Integer formatting used by `serde_json` | `registry+https://github.com/rust-lang/crates.io-index`; [itoa](https://github.com/dtolnay/itoa) |
| transitive | `jobserver 0.1.35` | 1.85 | `1c00acbd29eabad4a2392fa0e921c874934dbbf4194312ad20f04a0ed67a3cb3` | MIT OR Apache-2.0 | `libfuzzer-sys` → `cc` | GNU Make jobserver coordination for `cc` | `registry+https://github.com/rust-lang/crates.io-index`; [jobserver-rs](https://github.com/rust-lang/jobserver-rs) |
| transitive | `libc 0.2.189` | 1.65 | `3eaf3ede3fee6db1a4c2ee091bf8a8b4dccdc6d17f656fb07896ee72867612f2` | MIT OR Apache-2.0 | `plugin-host` → `nix`; `libfuzzer-sys` → `cc` | Platform FFI declarations used by build/runtime helpers | `registry+https://github.com/rust-lang/crates.io-index`; [libc](https://github.com/rust-lang/libc) |
| direct | `libfuzzer-sys 0.4.13` | not declared | `a9fd2f41a1cba099f79a0b6b6c35656cf7c03351a7bae8ff0f28f25270f929d2` | (MIT OR Apache-2.0) AND NCSA | `fuzz/Cargo.toml` | libFuzzer wrapper; default feature bundles C++17 runtime/link | `registry+https://github.com/rust-lang/crates.io-index`; [libfuzzer](https://github.com/rust-fuzz/libfuzzer) |
| transitive | `memchr 2.8.3` | 1.61 | `cf8baf1c55e62ffcace7a9f06f4bd9cd3f0c4beb022d3b367256b91b87513d98` | Unlicense OR MIT | `plugin-host` → `serde_json` | Fast byte search used by `serde_json` | `registry+https://github.com/rust-lang/crates.io-index`; [memchr](https://github.com/BurntSushi/memchr) |
| transitive | `nix 0.31.3` | 1.69 | `cf20d2fde8ff38632c426f1165ed7436270b44f199fc55284c38276f9db47c3d` | MIT | `plugin-host` | Rust-friendly Unix APIs used by plugin-host | `registry+https://github.com/rust-lang/crates.io-index`; [nix](https://github.com/nix-rust/nix) |
| transitive | `proc-macro2 1.0.107` | 1.71 | `985e7ec9bb745e6ce6535b544d84d6cd6f7ad8bd711c398938ae983b91a766d9` | MIT OR Apache-2.0 | `plugin-host` → `serde_derive` | Proc-macro token API used by derive macros | `registry+https://github.com/rust-lang/crates.io-index`; [proc-macro2](https://github.com/dtolnay/proc-macro2) |
| transitive | `quote 1.0.47` | 1.71 | `1fbf4db142a473a8d80c26bbf18454ed458bf8d26c8219c331daecfdbd079001` | MIT OR Apache-2.0 | `plugin-host` → `serde_derive` | `quote!` quasi-quoting used by derive macros | `registry+https://github.com/rust-lang/crates.io-index`; [quote](https://github.com/dtolnay/quote) |
| transitive | `r-efi 6.0.0` | 1.68 | `f8dcc9c7d52a811697d2151c701e0d08956f92b0e24136cf4cf27b57a6a0d9bf` | MIT OR Apache-2.0 OR LGPL-2.1-or-later | `libfuzzer-sys` → `cc` → `jobserver` → `getrandom` | UEFI constants for target-specific `getrandom` support | `registry+https://github.com/rust-lang/crates.io-index`; [r-efi](https://github.com/r-efi/r-efi) |
| transitive | `serde 1.0.229` | 1.56 | `4148590afebada386688f18773da617792bf2ef03ffc1e4cbd2b1d45b023e0ba` | MIT OR Apache-2.0 | `plugin-host` | Serialization framework used by plugin-host | `registry+https://github.com/rust-lang/crates.io-index`; [serde](https://github.com/serde-rs/serde) |
| transitive | `serde_core 1.0.229` | 1.56 | `67dca2c9c51e58a4791a4b1ed58308b39c64224d349a935ab5039aa360942a48` | MIT OR Apache-2.0 | `plugin-host` → `serde`/`serde_json` | Serde traits shared by `serde` and `serde_json` | `registry+https://github.com/rust-lang/crates.io-index`; [serde](https://github.com/serde-rs/serde) |
| transitive | `serde_derive 1.0.229` | 1.71 | `e7a5d71263a5a7d47b41f6b3f06ba276f10cc18b0931f1799f710578e2309348` | MIT OR Apache-2.0 | `plugin-host` → `serde` | `Serialize`/`Deserialize` derive macros | `registry+https://github.com/rust-lang/crates.io-index`; [serde](https://github.com/serde-rs/serde) |
| transitive | `serde_json 1.0.151` | 1.71 | `c841b55ecdae098c80dcae9cf767f6f8a0c2cdb3416bbef72181df4d0fe73f14` | MIT OR Apache-2.0 | `plugin-host` | JSON serialization used by plugin-host preflight | `registry+https://github.com/rust-lang/crates.io-index`; [json](https://github.com/serde-rs/json) |
| transitive | `sha2 0.11.0` | 1.85 | `446ba717509524cb3f22f17ecc096f10f4822d76ab5c0b9822c5f9c284e825f4` | MIT OR Apache-2.0 | `plugin-host` | SHA-2 hashing used by plugin-host preflight | `registry+https://github.com/rust-lang/crates.io-index`; [hashes](https://github.com/RustCrypto/hashes) |
| transitive | `shlex 2.0.1` | 1.46 | `f8fadd59c855ef2080decdef8ff161eb6661b86933c9d82e5ba29dc602a55aba` | MIT OR Apache-2.0 | `libfuzzer-sys` → `cc` | Shell-word parsing helper used by `cc` (no shell execution) | `registry+https://github.com/rust-lang/crates.io-index`; [rust-shlex](https://github.com/comex/rust-shlex) |
| transitive | `syn 3.0.3` | 1.71 | `53e9bae58849f64dfa4f5d5ae372c8341f7305f82a3868709269343628b659a3` | MIT OR Apache-2.0 | `plugin-host` → `serde_derive` | Rust parser used by derive macros | `registry+https://github.com/rust-lang/crates.io-index`; [syn](https://github.com/dtolnay/syn) |
| transitive | `typenum 1.20.1` | 1.41 | `b6f5e870be6c3b371b77fe0ee0bafb859fa4964b4404c27de1d380043c4dda20` | MIT OR Apache-2.0 | `plugin-host` → `sha2` → `digest` | Type-level numbers used by `hybrid-array` | `registry+https://github.com/rust-lang/crates.io-index`; [typenum](https://github.com/paholg/typenum) |
| transitive | `unicode-ident 1.0.24` | 1.71 | `e6e4313cd5fcd3dad5cafa179702e2b244f760991f45397d14d4ebf38247da75` | (MIT OR Apache-2.0) AND Unicode-3.0 | `plugin-host` → `serde_derive` → `syn`/`proc-macro2` | Unicode XID_Start/XID_Continue tables used by proc-macro parsing | `registry+https://github.com/rust-lang/crates.io-index`; [unicode-ident](https://github.com/dtolnay/unicode-ident) |
| transitive | `zmij 1.0.23` | 1.71 | `29666d0abbfad1e3dc4dcf6144730dd3a3ab225bbbdac83319345b1b44ccfc1b` | MIT | `plugin-host` → `serde_json` | Double-to-string conversion used by `serde_json` | `registry+https://github.com/rust-lang/crates.io-index`; [zmij](https://github.com/dtolnay/zmij) |

The fuzz lock's declared MSRVs are all compatible with Rust 1.97.1; the
`cfg_aliases` and `libfuzzer-sys` records do not declare an MSRV, which is why
the package-level MSRV is explicit in the standalone manifest. `NCSA` is
allowed only by `fuzz/deny.toml` for the bundled libFuzzer sources; the product
policy does not allow it. The `Unicode-3.0` allowance is narrower:
`unicode-ident 1.0.24`
declares `(MIT OR Apache-2.0) AND Unicode-3.0` in current `cargo metadata
--locked` output, so the license policy must name that exact additional
expression component. No broad license wildcard or unreviewed license family
is allowed. The fuzz workspace is an engineering/test artifact, not part of a
product binary or release notice set.

### Selected registry expressions observed locally

The following are the license expressions declared by the selected registry
source manifests available in the local Cargo cache at the time of this audit:

- `MIT OR Apache-2.0`: `bitflags 2.13.1`, `block-buffer 0.12.1`, `cfg-if
  1.0.4`, `cpufeatures 0.3.0`, `crypto-common 0.2.2`, `digest 0.11.3`,
  `errno 0.3.14`, `hybrid-array 0.4.14`, `itoa 1.0.18`, `libc 0.2.189`,
  `proc-macro2 1.0.107`,
  `quote 1.0.47`, `serde 1.0.229`, `serde_core 1.0.229`, `serde_derive
  1.0.229`, `serde_json 1.0.151`, `serde_spanned 1.1.1`, `sha2 0.11.0`,
  `syn 3.0.3`, `toml 1.1.4+spec-1.1.0`, `toml_datetime 1.1.1+spec-1.1.0`,
  `toml_parser 1.1.3+spec-1.1.0`, `typenum 1.20.1`, `windows-link 0.2.1`,
  and `windows-sys 0.61.2`.
- `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT`: `linux-raw-sys
  0.12.1` and `rustix 1.1.4`.
- `MIT`: `cfg_aliases 0.2.2`, `nix 0.31.3`, `winnow 1.0.4`, and `zmij 1.0.23`.
- `Unlicense OR MIT`: `memchr 2.8.3`.
- `(MIT OR Apache-2.0) AND Unicode-3.0`: `unicode-ident 1.0.24`.
- `Apache-2.0 AND ISC`: `ring 0.17.14`.
- `Apache-2.0 OR ISC OR MIT`: `rustls 0.23.43`.
- `ISC`: `rustls-webpki 0.103.14` and `untrusted 0.9.0`.
- `BSD-3-Clause`: `subtle 2.6.1`.
- `MIT`: `data-encoding 2.11.0`, `nom 7.1.3`, and `synstructure 0.13.2`.
- `MIT/Apache-2.0` (Cargo metadata spelling): `asn1-rs-impl 0.2.0`,
  `minimal-lexical 0.2.1`, and `rusticata-macros 4.1.0`.
- `Apache-2.0 OR MIT` (Cargo metadata spelling): `autocfg 1.5.1`,
  `bit-vec 0.9.1`, `windows-sys 0.52.0` and its eight target packages,
  `windows-targets 0.52.6`, and `zeroize 1.9.0`.
- `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT`: `wasi
  0.11.1+wasi-snapshot-preview1`.
- The remaining HTTP-native graph additions (`asn1-rs 0.7.2`, `asn1-rs-derive
  0.6.0`, `cc 1.4.2`, `der-parser 10.0.0`, `deranged 0.5.8`, `displaydoc
  0.2.7`, `find-msvc-tools 0.1.10`, `getrandom 0.2.17`, `lazy_static 1.5.0`,
  `num-bigint 0.4.8`, `num-conv 0.2.2`, `num-integer 0.1.47`, `num-traits
  0.2.19`, `oid-registry 0.8.1`, `once_cell 1.21.4`, `powerfmt 0.2.0`,
  `rcgen 0.14.9`, `rustls-pki-types 1.15.1`, `shlex 2.0.1`, `syn 2.0.119`,
  `thiserror 2.0.20`, `thiserror-impl 2.0.20`, `time 0.3.55`, `time-core
  0.1.9`, `time-macros 0.2.32`, `x509-parser 0.18.1`, and `yasna 0.6.0`)
  declare `MIT OR Apache-2.0`.
- The DNS graph additionally contains `Unicode-3.0` ICU4X records, `Zlib OR
  Apache-2.0 OR MIT` tinyvec records, and lock-only `LGPL-2.1-or-later` as an
  alternative r-efi expression; the selected runtime branch remains covered
  by the existing Apache-2.0, MIT, and Unicode-3.0 policy allowlist.
- The decompression graph additionally contains `BSD-3-Clause` allocator
  records, `BSD-3-Clause AND MIT` Brotli, `BSD-3-Clause/MIT` Brotli decoder,
  `0BSD OR MIT OR Apache-2.0` adler2, `MIT OR Zlib OR Apache-2.0` miniz_oxide,
  and `MIT` simd-adler32; every selected runtime expression has an allowed
  Apache-2.0, BSD-3-Clause, MIT, or permitted OR branch.

All 186 selected root registry package manifests were available in the local
Cargo source cache for this static pass. The expressions above are exact
metadata from those selected manifests; they are not inferred from manifest
comments. `nix 0.31.3` is MIT, `cfg_aliases 0.2.2` is MIT, and the selected
`bitflags`, `libc`, and `serde_spanned` releases are MIT OR Apache-2.0. The
root `deny.toml` allowlist therefore includes ISC for ring, rustls-webpki, and
untrusted, and BSD-3-Clause for subtle; these are the exact additional
expressions emitted by `cargo deny` for the selected graph, not broad
wildcards.

The current root `deny.toml` allowlist is Apache-2.0, BSD-3-Clause, ISC, MIT,
and Unicode-3.0;
`fuzz/deny.toml` permits the same three expressions and adds NCSA only for the
bundled libFuzzer sources. Registry sources are restricted to crates.io,
unknown registries and Git sources are denied, and wildcard dependencies are
denied. This document records the policy and observed metadata; a release
still requires the configured dependency, advisory, and license checks,
including review of any package whose metadata is not available in the local
cache.

### Per-package source and release presence

Every root-lock registry row below has Cargo source
`registry+https://github.com/rust-lang/crates.io-index`. The URL in the second
column is the upstream repository URL recorded by the selected package
manifest; it is a provenance link, not a Git dependency. `ref-only` means that
the jmeter-rs source release contains only its manifest/lock reference: no
registry archive, crate source, or third-party license file is vendored here.
The binary column identifies where compiled code can occur. A runtime entry is
not a claim that every binary contains that package; it names the workspace
consumer(s) that can contain it.

The obligation shorthand is: `dual` means retain the package copyright notice
and the selected MIT or Apache-2.0 license text; `MIT` means retain the MIT
text and copyright notice; `Unlicense/MIT` means retain the selected branch's
notice/text; `dual + Unicode` means the dual-license obligations plus the
Unicode-3.0 notice/text; and `dual + NCSA` adds the NCSA notice/text. ISC and
BSD-3-Clause rows require their respective license text and copyright notices
in a release notice bundle. The current tree has the project Apache-2.0
`LICENSE`, but no generated bundle of these third-party notices. Any binary
release containing a runtime row must produce and ship the applicable
third-party notices before distribution.

### HTTP-native TLS graph additions (52 registry records)

The following rows are the 52 registry records added by the HTTP-native edge
relative to the prior 33-record root graph. Each checksum is from the active
`Cargo.lock`, each license/MSRV/repository is from the selected local Cargo
package manifest, and every source is the crates.io registry shown above;
repository links are provenance links, not Git dependencies. `runtime` and
`runtime build` rows can occur in a product build; `dev-only` rows are active
only through `rcgen` and its local-certificate test branch; `lock-only
optional` rows are retained in Cargo.lock for optional dependency resolution
but are not active with the selected `crypto`/`ring` feature set.

| Package / selected version | Cargo lock checksum | License; published MSRV | Upstream repository | Runtime-vs-dev role |
| --- | --- | --- | --- | --- |
| `asn1-rs 0.7.2` | `b7f43a50ac4fdca5df8e885c21b835997f0a1cdee65494a6847694a98652d9d8` | MIT OR Apache-2.0; 1.68 | [rusticata/asn1-rs](https://github.com/rusticata/asn1-rs.git) | lock-only optional via x509-parser |
| `asn1-rs-derive 0.6.0` | `3109e49b1e4909e9db6515a30c633684d68cdeaa252f215214cb4fa1a5bfee2c` | MIT OR Apache-2.0; MSRV not declared | [rusticata/asn1-rs](https://github.com/rusticata/asn1-rs.git) | lock-only optional proc macro |
| `asn1-rs-impl 0.2.0` | `7b18050c2cd6fe86c3a76584ef5e0baf286d038cda203eb6223df2cc413565f7` | MIT/Apache-2.0; MSRV not declared | [rusticata/asn1-rs](https://github.com/rusticata/asn1-rs.git) | lock-only optional proc macro |
| `autocfg 1.5.1` | `f2032f911046de80f0a198e0901378627c33f59ea0ac00e363d481118bd70a53` | Apache-2.0 OR MIT; 1.0 | [cuviper/autocfg](https://github.com/cuviper/autocfg) | lock-only optional build helper |
| `bit-vec 0.9.1` | `b71798fca2c1fe1086445a7258a4bc81e6e49dcd24c8d0dd9a1e57395b603f51` | Apache-2.0 OR MIT; 1.82 | [contain-rs/bit-vec](https://github.com/contain-rs/bit-vec) | lock-only optional via yasna |
| `cc 1.4.2` | `5d262e149917187838d5b42777c8253bcb64500067342904e7d429499a6f277e` | MIT OR Apache-2.0; 1.64.0 | [rust-lang/cc-rs](https://github.com/rust-lang/cc-rs) | runtime build helper via ring; compiles bundled C/assembly |
| `data-encoding 2.11.0` | `a4ae5f15dda3c708c0ade84bfee31ccab44a3da4f88015ed22f63732abe300c8` | MIT; 1.48 | [ia0/data-encoding](https://github.com/ia0/data-encoding) | lock-only optional via x509-parser |
| `der-parser 10.0.0` | `07da5016415d5a3c4dd39b11ed26f915f52fc4e0dc197d87908bc916e51bc1a6` | MIT OR Apache-2.0; 1.63 | [rusticata/der-parser](https://github.com/rusticata/der-parser.git) | lock-only optional via x509-parser |
| `deranged 0.5.8` | `7cd812cc2bc1d69d4764bd80df88b4317eaef9e773c75226407d9bc0876b211c` | MIT OR Apache-2.0; 1.85.0 | [jhpratt/deranged](https://github.com/jhpratt/deranged) | dev-only via time |
| `displaydoc 0.2.7` | `c6232dd377dcc64799954cbd3a9bb882e9cdc1308ccd87b1c098f1fb2eaf82a8` | MIT OR Apache-2.0; 1.71.0 | [yaahc/displaydoc](https://github.com/yaahc/displaydoc) | lock-only optional proc macro |
| `find-msvc-tools 0.1.10` | `26b73573e6edcd2af0cdf47bd6cb58f0b3839491263c314eaad1ccf24430e1de` | MIT OR Apache-2.0; 1.64.0 | [rust-lang/cc-rs](https://github.com/rust-lang/cc-rs) | runtime build helper via cc |
| `getrandom 0.2.17` | `ff2abc00be7fca6ebc474524697ae276ad847ad0a6b3faa4bcb027e9a4614ad0` | MIT OR Apache-2.0; MSRV not declared | [rust-random/getrandom](https://github.com/rust-random/getrandom) | runtime via ring |
| `lazy_static 1.5.0` | `bbd2bcb4c963f2ddae06a2efc7e9f3591312473c50c6685e1f298068316e66fe` | MIT OR Apache-2.0; MSRV not declared | [rust-lang-nursery/lazy-static.rs](https://github.com/rust-lang-nursery/lazy-static.rs) | lock-only optional via x509-parser |
| `minimal-lexical 0.2.1` | `68354c5c6bd36d73ff3feceb05efa59b6acb7626617f4962be322a825e61f79a` | MIT/Apache-2.0; MSRV not declared | [Alexhuszagh/minimal-lexical](https://github.com/Alexhuszagh/minimal-lexical) | lock-only optional via nom |
| `nom 7.1.3` | `d273983c5a657a70a3e8f2a01329822f3b8c8172b73826411a55751e404a0a4a` | MIT; 1.48 | [Geal/nom](https://github.com/Geal/nom) | lock-only optional via x509-parser |
| `num-bigint 0.4.8` | `c89e69e7e0f03bea5ef08013795c25018e101932225a656383bd384495ecc367` | MIT OR Apache-2.0; 1.60 | [rust-num/num-bigint](https://github.com/rust-num/num-bigint) | lock-only optional via x509-parser |
| `num-conv 0.2.2` | `521739c6d2bac4aa25192232afe6841231376b2b26d4d9fae5ecf8ca5772e441` | MIT OR Apache-2.0; 1.57.0 | [jhpratt/num-conv](https://github.com/jhpratt/num-conv) | dev-only active via time |
| `num-integer 0.1.47` | `7ce2d95d4b3734dc35aa2f45e1aa22cd416814592a4f9d9205e11affd5b8e10b` | MIT OR Apache-2.0; 1.31 | [rust-num/num-integer](https://github.com/rust-num/num-integer) | lock-only optional via x509-parser |
| `num-traits 0.2.19` | `071dfc062690e90b734c0b2273ce72ad0ffa95f0c74596bc250dcfd960262841` | MIT OR Apache-2.0; 1.60 | [rust-num/num-traits](https://github.com/rust-num/num-traits) | lock-only optional via x509-parser |
| `oid-registry 0.8.1` | `12f40cff3dde1b6087cc5d5f5d4d65712f34016a03ed60e9c08dcc392736b5b7` | MIT OR Apache-2.0; 1.63 | [rusticata/oid-registry](https://github.com/rusticata/oid-registry.git) | lock-only optional via x509-parser |
| `once_cell 1.21.4` | `9f7c3e4beb33f85d45ae3e3a1792185706c8e16d043238c593331cc7cd313b50` | MIT OR Apache-2.0; 1.65 | [matklad/once_cell](https://github.com/matklad/once_cell) | runtime via rustls |
| `powerfmt 0.2.0` | `439ee305def115ba05938db6eb1644ff94165c5ab5e9420d1c1bcedbba909391` | MIT OR Apache-2.0; 1.67.0 | [jhpratt/powerfmt](https://github.com/jhpratt/powerfmt) | dev-only active via time |
| `rcgen 0.14.9` | `091e7a8e7d86e6feb87a27ce8e2cba29d49eff9507afeebefab7eeb2ca667fb4` | MIT OR Apache-2.0; 1.88 | [rustls/rcgen](https://github.com/rustls/rcgen) | dev-only direct certificate fixtures; ephemeral in-memory app/http-native tests |
| `ring 0.17.14` | `a4689e6c2294d81e88dc6261c768b63bc4fcdb852be6d1352498b114f61383b7` | Apache-2.0 AND ISC; 1.66.0 | [briansmith/ring](https://github.com/briansmith/ring) | runtime via rustls; also dev-only via rcgen |
| `rusticata-macros 4.1.0` | `faf0c4a6ece9950b9abdb62b1cfcf2a68b3b67a10ba445b3bb85be2a293d0632` | MIT/Apache-2.0; MSRV not declared | [rusticata/rusticata-macros](https://github.com/rusticata/rusticata-macros.git) | lock-only optional proc macro |
| `rustls 0.23.43` | `0283386ce02abc0151e1761d08802dfe86c173b0b494af5cbc086574e453da06` | Apache-2.0 OR ISC OR MIT; 1.71 | [rustls/rustls](https://github.com/rustls/rustls) | runtime direct |
| `rustls-pki-types 1.15.1` | `2f4925028c7eb5d1fcdaf196971378ed9d2c1c4efc7dc5d011256f76c99c0a96` | MIT OR Apache-2.0; 1.60 | [rustls/pki-types](https://github.com/rustls/pki-types) | runtime via rustls; dev via rcgen |
| `rustls-webpki 0.103.14` | `0527518605e68109d875e248ea259b6758801cf165e4b2c2733ae3b51f12535a` | ISC; 1.71 | [rustls/webpki](https://github.com/rustls/webpki) | runtime via rustls |
| `shlex 2.0.1` | `f8fadd59c855ef2080decdef8ff161eb6661b86933c9d82e5ba29dc602a55aba` | MIT OR Apache-2.0; 1.46.0 | [comex/rust-shlex](https://github.com/comex/rust-shlex) | runtime build helper via cc |
| `subtle 2.6.1` | `13c2bddecc57b384dee18652358fb23172facb8a2c51ccc10d74c157bdea3292` | BSD-3-Clause; MSRV not declared | [dalek-cryptography/subtle](https://github.com/dalek-cryptography/subtle) | runtime via rustls |
| `syn 2.0.119` | `872831b642d1a07999a962a351ed35b955ea2cfc8f3862091e2a240a84f17297` | MIT OR Apache-2.0; 1.71 | [dtolnay/syn](https://github.com/dtolnay/syn) | lock-only optional proc macro |
| `synstructure 0.13.2` | `728a70f3dbaf5bab7f0c4b1ac8d7ae5ea60a4b5549c8a5914361c99147a709d2` | MIT; MSRV not declared | [mystor/synstructure](https://github.com/mystor/synstructure) | lock-only optional proc macro |
| `thiserror 2.0.20` | `ec86235f5fcc2a73650310756d2ac5b138a5780bbbdfae3eeccec992c435ba4f` | MIT OR Apache-2.0; 1.71 | [dtolnay/thiserror](https://github.com/dtolnay/thiserror) | lock-only optional via x509-parser |
| `thiserror-impl 2.0.20` | `bc04cd3e1236dd4a98afca4569f2deb3f120e5422a4023be2cb683f8486292af` | MIT OR Apache-2.0; 1.71 | [dtolnay/thiserror](https://github.com/dtolnay/thiserror) | lock-only optional proc macro |
| `time 0.3.55` | `cdb87b95ec50ddfa440816d227a17b2ccbdda963a316a727fda0fc4334f7d134` | MIT OR Apache-2.0; 1.88.0 | [time-rs/time](https://github.com/time-rs/time) | dev-only active via rcgen |
| `time-core 0.1.9` | `9e1c906769ad99c88eaa54e728060edef082f8e358ff32030cb7c7d315e81109` | MIT OR Apache-2.0; 1.88.0 | [time-rs/time](https://github.com/time-rs/time) | dev-only active via time |
| `time-macros 0.2.32` | `7e689342a48d2ea927c87ea50cabf8594854bf940e9310208848d680d668ed85` | MIT OR Apache-2.0; 1.88.0 | [time-rs/time](https://github.com/time-rs/time) | lock-only optional proc macro |
| `untrusted 0.9.0` | `8ecb6da28b8a351d773b68d5825ac39017e680750f980f3a1a85cd8dd28a47c1` | ISC; MSRV not declared | [briansmith/untrusted](https://github.com/briansmith/untrusted) | runtime via ring/webpki |
| `wasi 0.11.1+wasi-snapshot-preview1` | `ccf3ec651a847eb01de73ccad15eb7d99f80485de043efb2f370cd654f4ea44b` | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT; MSRV not declared | [bytecodealliance/wasi](https://github.com/bytecodealliance/wasi) | runtime target-specific via getrandom |
| `windows-sys 0.52.0` | `282be5f36a8ce781fad8c8ae18fa3f9beff57ec1b52cb3de0789201425d9a33d` | MIT OR Apache-2.0; 1.56 | [microsoft/windows-rs](https://github.com/microsoft/windows-rs) | runtime target-specific via ring |
| `windows-targets 0.52.6` | `9b724f72796e036ab90c1021d4780d4d3d648aca59e491e6b98e725b84e99973` | MIT OR Apache-2.0; 1.56 | [microsoft/windows-rs](https://github.com/microsoft/windows-rs) | runtime target-specific via windows-sys 0.52 |
| `windows_aarch64_gnullvm 0.52.6` | `32a4622180e7a0ec044bb555404c800bc9fd9ec262ec147edd5989ccd0c02cd3` | MIT OR Apache-2.0; 1.56 | [microsoft/windows-rs](https://github.com/microsoft/windows-rs) | runtime target-specific |
| `windows_aarch64_msvc 0.52.6` | `09ec2a7bb152e2252b53fa7803150007879548bc709c039df7627cabbd05d469` | MIT OR Apache-2.0; 1.56 | [microsoft/windows-rs](https://github.com/microsoft/windows-rs) | runtime target-specific |
| `windows_i686_gnu 0.52.6` | `8e9b5ad5ab802e97eb8e295ac6720e509ee4c243f69d781394014ebfe8bbfa0b` | MIT OR Apache-2.0; 1.56 | [microsoft/windows-rs](https://github.com/microsoft/windows-rs) | runtime target-specific |
| `windows_i686_gnullvm 0.52.6` | `0eee52d38c090b3caa76c563b86c3a4bd71ef1a819287c19d586d7334ae8ed66` | MIT OR Apache-2.0; 1.56 | [microsoft/windows-rs](https://github.com/microsoft/windows-rs) | runtime target-specific |
| `windows_i686_msvc 0.52.6` | `240948bc05c5e7c6dabba28bf89d89ffce3e303022809e73deaefe4f6ec56c66` | MIT OR Apache-2.0; 1.56 | [microsoft/windows-rs](https://github.com/microsoft/windows-rs) | runtime target-specific |
| `windows_x86_64_gnu 0.52.6` | `147a5c80aabfbf0c7d901cb5895d1de30ef2907eb21fbbab29ca94c5b08b1a78` | MIT OR Apache-2.0; 1.56 | [microsoft/windows-rs](https://github.com/microsoft/windows-rs) | runtime target-specific |
| `windows_x86_64_gnullvm 0.52.6` | `24d5b23dc417412679681396f2b49f3de8c1473deb516bd34410872eff51ed0d` | MIT OR Apache-2.0; 1.56 | [microsoft/windows-rs](https://github.com/microsoft/windows-rs) | runtime target-specific |
| `windows_x86_64_msvc 0.52.6` | `589f6da84c646204747d1270a2a5661ea66ed1cced2631d546fdfb155959f9ec` | MIT OR Apache-2.0; 1.56 | [microsoft/windows-rs](https://github.com/microsoft/windows-rs) | runtime target-specific |
| `x509-parser 0.18.1` | `d43b0f71ce057da06bc0851b23ee24f3f86190b07203dd8f567d0b706a185202` | MIT OR Apache-2.0; 1.67.1 | [rusticata/x509-parser](https://github.com/rusticata/x509-parser.git) | lock-only optional via rcgen |
| `yasna 0.6.0` | `b5f6765e852b9b4dc8e2a76843e4d64d1cea8e79bcde0b6901aea8e7c7f08282` | MIT OR Apache-2.0; 1.60 | [qnighy/yasna.rs](https://github.com/qnighy/yasna.rs) | dev-only active via rcgen |
| `zeroize 1.9.0` | `e13c156562582aa81c60cb29407084cdb54c4164760106ab78e6c5b0858cf64e` | Apache-2.0 OR MIT; 1.85 | [RustCrypto/utils](https://github.com/RustCrypto/utils) | runtime via rustls-pki-types |

### HTTP-native decompression graph additions (12 registry records)

These rows are the 12 registry records newly reachable from the explicit
`async-compression` increment and not already listed in the TLS or DNS graph
tables above. The direct dependency disables all default features and enables
only Tokio plus gzip, zlib, raw deflate, and Brotli adapters. The selected
flate2 path is Rust-only (`rust_backend`/miniz_oxide); `crc32fast` has a small
Rust build script for target-feature selection but does not compile a native
codec or require a system library.

| Package / selected version | Cargo lock checksum | License; published MSRV | Upstream repository | Runtime-vs-dev role |
| --- | --- | --- | --- | --- |
| `adler2 2.0.1` | `320119579fcad9c21884f5c4861d16174d0e06250625266f50fe6898340abefa` | 0BSD OR MIT OR Apache-2.0; MSRV not declared | [oyvindln/adler2](https://github.com/oyvindln/adler2) | runtime via flate2/miniz_oxide |
| `async-compression 0.4.43` | `3976abdc8fe7d1133d43d304afd42abdf5bc3e1319d263d223bde07b5efc4be8` | MIT OR Apache-2.0; 1.83; `build = false` | [Nullus157/async-compression](https://github.com/Nullus157/async-compression) | runtime direct; Tokio codec adapter |
| `alloc-no-stdlib 2.0.4` | `cc7bb162ec39d46ab1ca8c77bf72e890535becd1751bb45f64c597edb4c8c6b3` | BSD-3-Clause; MSRV not declared | [dropbox/rust-alloc-no-stdlib](https://github.com/dropbox/rust-alloc-no-stdlib) | runtime via Brotli |
| `alloc-stdlib 0.2.4` | `0e76a019e91224d279006ff972f1e984179a6e9feb050adba6ce8274aef23195` | BSD-3-Clause; MSRV not declared | [dropbox/rust-alloc-no-stdlib](https://github.com/dropbox/rust-alloc-no-stdlib) | runtime via Brotli |
| `brotli 8.0.4` | `5cc91aac060a7a1e25823bdccbfb6af1875b88f17c6daac97894eed8207166b3` | BSD-3-Clause AND MIT; 1.59.0 | [dropbox/rust-brotli](https://github.com/dropbox/rust-brotli) | runtime via selected Brotli feature |
| `brotli-decompressor 5.0.3` | `3a32acac15fe1967bc3986b2a6347dffc965602354ea6f450ad07e8bfd253583` | BSD-3-Clause/MIT; MSRV not declared | [dropbox/rust-brotli-decompressor](https://github.com/dropbox/rust-brotli-decompressor) | runtime via Brotli |
| `compression-codecs 0.4.38` | `ce2548391e9c1929c21bf6aa2680af86fe4c1b33e6cea9ac1cfeec0bd11218cf` | MIT OR Apache-2.0; 1.83; `build = false` | [Nullus157/async-compression](https://github.com/Nullus157/async-compression) | runtime via async-compression |
| `compression-core 0.4.32` | `cc14f565cf027a105f7a44ccf9e5b424348421a1d8952a8fc9d499d313107789` | MIT OR Apache-2.0; MSRV not declared; `build = false` | [Nullus157/async-compression](https://github.com/Nullus157/async-compression) | runtime via async-compression |
| `crc32fast 1.5.0` | `9481c1c90cbf2ac953f07c8d4a58aa3945c425b7185c9154d67a65e4230da511` | MIT OR Apache-2.0; 1.63; Rust-only `build.rs` target-feature probe | [srijs/rust-crc32fast](https://github.com/srijs/rust-crc32fast) | runtime via flate2; no native compiler |
| `flate2 1.1.9` | `843fba2746e448b37e26a819579957415c8cef339bf08564fe8b7ddbd959573c` | MIT OR Apache-2.0; 1.67.0; `build = false` | [rust-lang/flate2-rs](https://github.com/rust-lang/flate2-rs) | runtime via selected Rust backend |
| `miniz_oxide 0.8.9` | `1fa76a2c86f704bdb222d66965fb3d63269ce38518b83cb0575fca855ebb6316` | MIT OR Zlib OR Apache-2.0; MSRV not declared; `build = false` | [Frommi/miniz_oxide](https://github.com/Frommi/miniz_oxide/tree/master/miniz_oxide) | runtime via flate2 |
| `simd-adler32 0.3.10` | `3a219298ac11a56ea9a6d2120044824d6f01aeb034955e7af7bc16858527deea` | MIT; MSRV not declared; `build = false` | [mcountryman/simd-adler32](https://github.com/mcountryman/simd-adler32) | runtime via miniz_oxide |

### HTTP-native DNS graph additions (89 registry records)

These rows are the 89 registry records newly reachable from the explicit
Hickory/Tokio DNS increment that are not already listed in the TLS graph
above. Checksums and metadata are taken from the active lockfile and local
Cargo manifests on 2026-08-13. Runtime rows are in the selected
Hickory/Tokio feature closure; lock-only rows are retained by optional
dependency metadata but are not active. In particular, the JNI and
platform/system-configuration rows below are lock-only and do not enable JVM
or OS resolver discovery.

| Package / selected version | Cargo lock checksum | License; published MSRV | Upstream repository | Runtime-vs-lock role |
| --- | --- | --- | --- | --- |
| `async-trait 0.1.92` | `82f6aeea286b8eb4dd3431a1be1b59d290ace00f5bfd8e2a159bc2a05e2c1667` | MIT OR Apache-2.0; 1.71 | [https://github.com/dtolnay/async-trait](https://github.com/dtolnay/async-trait) | runtime via selected Hickory/Tokio feature closure |
| `bumpalo 3.20.3` | `72f5acc6cb2ba439de613abc23857ec3d78374d8ed5ac84e9d11336e87da8649` | MIT OR Apache-2.0; 1.71.1 | [https://github.com/fitzgen/bumpalo](https://github.com/fitzgen/bumpalo) | lock-only optional Hickory branch |
| `bytes 1.12.1` | `fc652a48c352aef3ea3aed32080501cf3ef6ed5da78602a020c991775b0aff04` | MIT; 1.57 | [https://github.com/tokio-rs/bytes](https://github.com/tokio-rs/bytes) | runtime via selected Hickory/Tokio feature closure |
| `chacha20 0.10.1` | `d524456ba66e72eb8b115ff89e01e497f8e6d11d78b70b1aa13c0fbd97540a81` | MIT OR Apache-2.0; 1.85 | [https://github.com/RustCrypto/stream-ciphers](https://github.com/RustCrypto/stream-ciphers) | runtime via selected Hickory/Tokio feature closure |
| `combine 4.6.7` | `ba5a308b75df32fe02788e748662718f03fde005016435c444eea572398219fd` | MIT; MSRV not declared | [https://github.com/Marwes/combine](https://github.com/Marwes/combine) | lock-only optional Hickory branch |
| `critical-section 1.2.0` | `790eea4361631c5e7d22598ecd5723ff611904e3344ce8720784c93e3d83d40b` | MIT OR Apache-2.0; MSRV not declared | [https://github.com/rust-embedded/critical-section](https://github.com/rust-embedded/critical-section) | runtime via selected Hickory/Tokio feature closure |
| `crossbeam-channel 0.5.16` | `d85363c37faeca707aef026efa9f3b34d077bce547e48f770770625c6013679e` | MIT OR Apache-2.0; 1.60 | [https://github.com/crossbeam-rs/crossbeam](https://github.com/crossbeam-rs/crossbeam) | runtime via selected Hickory/Tokio feature closure |
| `crossbeam-epoch 0.9.20` | `2d6914041f254d6e9176c01941b21115dcfb7089e55135a35411081bd106ef3f` | MIT OR Apache-2.0; 1.61 | [https://github.com/crossbeam-rs/crossbeam](https://github.com/crossbeam-rs/crossbeam) | runtime via selected Hickory/Tokio feature closure |
| `crossbeam-utils 0.8.22` | `61803da095bee82a81bb1a452ecc25d3b2f1416d1897eb86430c6159ef717c17` | MIT OR Apache-2.0; 1.60 | [https://github.com/crossbeam-rs/crossbeam](https://github.com/crossbeam-rs/crossbeam) | runtime via selected Hickory/Tokio feature closure |
| `either 1.17.0` | `9e5e8f6c15a24b9a3ee5efec809ccd006d3b30e8b3bb63c39af737c7f87daa1d` | MIT OR Apache-2.0; 1.63.0 | [https://github.com/rayon-rs/either](https://github.com/rayon-rs/either) | runtime via selected Hickory/Tokio feature closure |
| `equivalent 1.0.2` | `877a4ace8713b0bcf2a4e7eec82529c029f1d0619886d18145fea96c3ffe5c0f` | Apache-2.0 OR MIT; 1.6 | [https://github.com/indexmap-rs/equivalent](https://github.com/indexmap-rs/equivalent) | runtime via selected Hickory/Tokio feature closure |
| `form_urlencoded 1.2.2` | `cb4cb245038516f5f85277875cdaa4f7d2c9a0fa0468de06ed190163b1581fcf` | MIT OR Apache-2.0; 1.51 | [https://github.com/servo/rust-url](https://github.com/servo/rust-url) | runtime via selected Hickory/Tokio feature closure |
| `futures-channel 0.3.34` | `b1f9e3d69d39e4862ffed03ed071a76f9a13ba1d9109d355b0f0aa6b15e393c4` | MIT OR Apache-2.0; 1.71 | [https://github.com/rust-lang/futures-rs](https://github.com/rust-lang/futures-rs) | runtime via selected Hickory/Tokio feature closure |
| `futures-core 0.3.34` | `92d699e522242e69e3003b94ecc1f960f3a5e015aa7c5d7486e65ad01dd94f5e` | MIT OR Apache-2.0; 1.36 | [https://github.com/rust-lang/futures-rs](https://github.com/rust-lang/futures-rs) | runtime via selected Hickory/Tokio feature closure |
| `futures-io 0.3.34` | `53c0fa8157de1303bfffdaa1cc2a673bfffb60102f76b0ef4441659124373fed` | MIT OR Apache-2.0; 1.36 | [https://github.com/rust-lang/futures-rs](https://github.com/rust-lang/futures-rs) | runtime via selected Hickory/Tokio feature closure |
| `futures-macro 0.3.34` | `9fb9654ba8355388abeb8dcb4fc62f511300867002afc858860463bdd9fe0c44` | MIT OR Apache-2.0; 1.71 | [https://github.com/rust-lang/futures-rs](https://github.com/rust-lang/futures-rs) | runtime via selected Hickory/Tokio feature closure |
| `futures-task 0.3.34` | `cd417de3d1d015fc3bfd2b1ea46dfc7bab72ef86f1cc7cc9c78e728b34a6d1fd` | MIT OR Apache-2.0; 1.71 | [https://github.com/rust-lang/futures-rs](https://github.com/rust-lang/futures-rs) | runtime via selected Hickory/Tokio feature closure |
| `futures-util 0.3.34` | `0d50a92467f8ba5dd6e3ee5d4bd04d73ab2e4e1c44474a0674821dfce14b79bc` | MIT OR Apache-2.0; 1.71 | [https://github.com/rust-lang/futures-rs](https://github.com/rust-lang/futures-rs) | runtime via selected Hickory/Tokio feature closure |
| `getrandom 0.4.3` | `300e883d756b2e4ec94e02791f39b04b522276138852cfc41d9fb7e904106099` | MIT OR Apache-2.0; 1.85 | [https://github.com/rust-random/getrandom](https://github.com/rust-random/getrandom) | runtime via selected Hickory/Tokio feature closure |
| `hickory-net 0.26.1` | `e2295ed2f9c31e471e1428a8f88a3f0e1f4b27c15049592138d1eebe9c35b183` | MIT OR Apache-2.0; 1.88 | [https://github.com/hickory-dns/hickory-dns](https://github.com/hickory-dns/hickory-dns) | runtime via selected Hickory/Tokio feature closure |
| `hickory-proto 0.26.1` | `0bab31817bfb44672a252e97fe81cd0c18d1b2cf892108922f6818820df8c643` | MIT OR Apache-2.0; 1.88 | [https://github.com/hickory-dns/hickory-dns](https://github.com/hickory-dns/hickory-dns) | runtime via selected Hickory/Tokio feature closure |
| `hickory-resolver 0.26.1` | `f0d58d28879ceecde6607729660c2667a081ccdc082e082675042793960f178c` | MIT OR Apache-2.0; 1.88 | [https://github.com/hickory-dns/hickory-dns](https://github.com/hickory-dns/hickory-dns) | runtime via selected Hickory/Tokio feature closure |
| `icu_collections 2.2.0` | `2984d1cd16c883d7935b9e07e44071dca8d917fd52ecc02c04d5fa0b5a3f191c` | Unicode-3.0; 1.86 | [https://github.com/unicode-org/icu4x](https://github.com/unicode-org/icu4x) | runtime via selected Hickory/Tokio feature closure |
| `icu_locale_core 2.2.0` | `92219b62b3e2b4d88ac5119f8904c10f8f61bf7e95b640d25ba3075e6cac2c29` | Unicode-3.0; 1.86 | [https://github.com/unicode-org/icu4x](https://github.com/unicode-org/icu4x) | runtime via selected Hickory/Tokio feature closure |
| `icu_normalizer 2.2.0` | `c56e5ee99d6e3d33bd91c5d85458b6005a22140021cc324cea84dd0e72cff3b4` | Unicode-3.0; 1.86 | [https://github.com/unicode-org/icu4x](https://github.com/unicode-org/icu4x) | runtime via selected Hickory/Tokio feature closure |
| `icu_normalizer_data 2.2.0` | `da3be0ae77ea334f4da67c12f149704f19f81d1adf7c51cf482943e84a2bad38` | Unicode-3.0; 1.86 | [https://github.com/unicode-org/icu4x](https://github.com/unicode-org/icu4x) | runtime via selected Hickory/Tokio feature closure |
| `icu_properties 2.2.0` | `bee3b67d0ea5c2cca5003417989af8996f8604e34fb9ddf96208a033901e70de` | Unicode-3.0; 1.86 | [https://github.com/unicode-org/icu4x](https://github.com/unicode-org/icu4x) | runtime via selected Hickory/Tokio feature closure |
| `icu_properties_data 2.2.0` | `8e2bbb201e0c04f7b4b3e14382af113e17ba4f63e2c9d2ee626b720cbce54a14` | Unicode-3.0; 1.86 | [https://github.com/unicode-org/icu4x](https://github.com/unicode-org/icu4x) | runtime via selected Hickory/Tokio feature closure |
| `icu_provider 2.2.0` | `139c4cf31c8b5f33d7e199446eff9c1e02decfc2f0eec2c8d71f65befa45b421` | Unicode-3.0; 1.86 | [https://github.com/unicode-org/icu4x](https://github.com/unicode-org/icu4x) | runtime via selected Hickory/Tokio feature closure |
| `idna 1.1.0` | `3b0875f23caa03898994f6ddc501886a45c7d3d62d04d2d90788d47be1b1e4de` | MIT OR Apache-2.0; 1.57 | [https://github.com/servo/rust-url/](https://github.com/servo/rust-url/) | runtime via selected Hickory/Tokio feature closure |
| `idna_adapter 1.2.2` | `cb68373c0d6620ef8105e855e7745e18b0d00d3bdb07fb532e434244cdb9a714` | Apache-2.0 OR MIT; 1.86 | [https://github.com/hsivonen/idna_adapter](https://github.com/hsivonen/idna_adapter) | runtime via selected Hickory/Tokio feature closure |
| `ipnet 2.12.1` | `6a756c3fac73139e83f14c2d742155dd2b78d3ee56597b419a0579b7bdd6dd78` | MIT OR Apache-2.0; MSRV not declared | [https://github.com/krisprice/ipnet](https://github.com/krisprice/ipnet) | runtime via selected Hickory/Tokio feature closure |
| `jni 0.22.4` | `5efd9a482cf3a427f00d6b35f14332adc7902ce91efb778580e180ff90fa3498` | MIT OR Apache-2.0; 1.85.0 | [https://github.com/jni-rs/jni-rs](https://github.com/jni-rs/jni-rs) | lock-only optional Hickory branch |
| `jni-macros 0.22.4` | `a00109accc170f0bdb141fed3e393c565b6f5e072365c3bd58f5b062591560a3` | MIT OR Apache-2.0; MSRV not declared | [https://github.com/jni-rs/jni-rs](https://github.com/jni-rs/jni-rs) | lock-only optional Hickory branch |
| `jni-sys 0.4.1` | `c6377a88cb3910bee9b0fa88d4f42e1d2da8e79915598f65fb0c7ee14c878af2` | MIT OR Apache-2.0; 1.76.0 | [https://github.com/jni-rs/jni-sys](https://github.com/jni-rs/jni-sys) | lock-only optional Hickory branch |
| `jni-sys-macros 0.4.1` | `38c0b942f458fe50cdac086d2f946512305e5631e720728f2a61aabcd47a6264` | MIT OR Apache-2.0; MSRV not declared | [https://github.com/jni-rs/jni-sys](https://github.com/jni-rs/jni-sys) | lock-only optional Hickory branch |
| `js-sys 0.3.104` | `0e0c1080212aad755ea003d18543e8768dd432c48819efd73a7bf1e39b7a5a3a` | MIT OR Apache-2.0; 1.77 | [https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/js-sys](https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/js-sys) | lock-only optional Hickory branch |
| `litemap 0.8.2` | `92daf443525c4cce67b150400bc2316076100ce0b3686209eb8cf3c31612e6f0` | Unicode-3.0; 1.82 | [https://github.com/unicode-org/icu4x](https://github.com/unicode-org/icu4x) | runtime via selected Hickory/Tokio feature closure |
| `lock_api 0.4.14` | `224399e74b87b5f3557511d98dff8b14089b3dadafcab6bb93eab67d3aace965` | MIT OR Apache-2.0; 1.71.0 | [https://github.com/Amanieu/parking_lot](https://github.com/Amanieu/parking_lot) | runtime via selected Hickory/Tokio feature closure |
| `log 0.4.33` | `0ceec5bc11778974d1bcb055b18002eba7f4b3518b6a0081b3af5f21666da9ad` | MIT OR Apache-2.0; 1.71.0 | [https://github.com/rust-lang/log](https://github.com/rust-lang/log) | lock-only optional Hickory branch |
| `mio 1.2.2` | `30d65c71f1ce40ab09135ce117d742b9f8a19ff91a41a8b57ed50bc2de59c427` | MIT; 1.71 | [https://github.com/tokio-rs/mio](https://github.com/tokio-rs/mio) | runtime direct; one nonblocking connect/cancellation readiness edge (also reachable through selected Hickory/Tokio closure) |
| `moka 0.12.16` | `4293f18e7567a1caf3c584855554377025c65e0aa445344d04171f5ad63d19b9` | (MIT OR Apache-2.0) AND Apache-2.0; 1.71.1 | [https://github.com/moka-rs/moka](https://github.com/moka-rs/moka) | runtime via selected Hickory/Tokio feature closure |
| `parking_lot 0.12.5` | `93857453250e3077bd71ff98b6a65ea6621a19bb0f559a85248955ac12c45a1a` | MIT OR Apache-2.0; 1.71 | [https://github.com/Amanieu/parking_lot](https://github.com/Amanieu/parking_lot) | runtime via selected Hickory/Tokio feature closure |
| `parking_lot_core 0.9.12` | `2621685985a2ebf1c516881c026032ac7deafcda1a2c9b7850dc81e3dfcb64c1` | MIT OR Apache-2.0; 1.71.0 | [https://github.com/Amanieu/parking_lot](https://github.com/Amanieu/parking_lot) | runtime via selected Hickory/Tokio feature closure |
| `percent-encoding 2.3.2` | `9b4f627cb1b25917193a259e49bdad08f671f8d9708acfd5fe0a8c1455d87220` | MIT OR Apache-2.0; 1.51 | [https://github.com/servo/rust-url/](https://github.com/servo/rust-url/) | runtime via selected Hickory/Tokio feature closure |
| `pin-project-lite 0.2.17` | `a89322df9ebe1c1578d689c92318e070967d1042b512afbe49518723f4e6d5cd` | Apache-2.0 OR MIT; 1.37 | [https://github.com/taiki-e/pin-project-lite](https://github.com/taiki-e/pin-project-lite) | runtime via selected Hickory/Tokio feature closure |
| `portable-atomic 1.15.0` | `05c8b63e8d9609db387f0324918f81d68fe27748f084ef092fb35954d0539a85` | Apache-2.0 OR MIT; 1.34 | [https://github.com/taiki-e/portable-atomic](https://github.com/taiki-e/portable-atomic) | runtime via selected Hickory/Tokio feature closure |
| `potential_utf 0.1.5` | `0103b1cef7ec0cf76490e969665504990193874ea05c85ff9bab8b911d0a0564` | Unicode-3.0; 1.82 | [https://github.com/unicode-org/icu4x](https://github.com/unicode-org/icu4x) | runtime via selected Hickory/Tokio feature closure |
| `prefix-trie 0.8.4` | `4cf6e3177f0684016a5c209b00882e15f8bdd3f3bb48f0491df10cd102d0c6e7` | MIT OR Apache-2.0; 1.71.1 | [https://github.com/tiborschneider/prefix-trie](https://github.com/tiborschneider/prefix-trie) | runtime via selected Hickory/Tokio feature closure |
| `r-efi 6.0.0` | `f8dcc9c7d52a811697d2151c701e0d08956f92b0e24136cf4cf27b57a6a0d9bf` | MIT OR Apache-2.0 OR LGPL-2.1-or-later; 1.68 | [https://github.com/r-efi/r-efi](https://github.com/r-efi/r-efi) | lock-only optional Hickory branch |
| `rand 0.10.2` | `c7f5fa3a058cd35567ef9bfa5e75732bee0f9e4c55fa90477bef2dfcdbc4be80` | MIT OR Apache-2.0; 1.85 | [https://github.com/rust-random/rand](https://github.com/rust-random/rand) | runtime via selected Hickory/Tokio feature closure |
| `rand_core 0.10.1` | `63b8176103e19a2643978565ca18b50549f6101881c443590420e4dc998a3c69` | MIT OR Apache-2.0; 1.85 | [https://github.com/rust-random/rand_core](https://github.com/rust-random/rand_core) | runtime via selected Hickory/Tokio feature closure |
| `redox_syscall 0.5.18` | `ed2bf2547551a7053d6fdfafda3f938979645c44812fbfcda098faae3f1a362d` | MIT; MSRV not declared | [https://gitlab.redox-os.org/redox-os/syscall](https://gitlab.redox-os.org/redox-os/syscall) | lock-only optional Hickory branch |
| `rustc_version 0.4.1` | `cfcb3a22ef46e85b45de6ee7e79d063319ebb6594faafcf1c225ea92ab6e9b92` | MIT OR Apache-2.0; 1.32 | [https://github.com/djc/rustc-version-rs](https://github.com/djc/rustc-version-rs) | lock-only optional Hickory branch |
| `rustversion 1.0.23` | `cf54715a573b99ac80df0bc206da022bcd442c974952c7b9720069370852e21f` | MIT OR Apache-2.0; 1.31 | [https://github.com/dtolnay/rustversion](https://github.com/dtolnay/rustversion) | lock-only optional Hickory branch |
| `same-file 1.0.6` | `93fc1dc3aaa9bfed95e02e6eadabb4baf7e3078b0bd1b4d7b6b0b68378900502` | Unlicense/MIT; MSRV not declared | [https://github.com/BurntSushi/same-file](https://github.com/BurntSushi/same-file) | lock-only optional Hickory branch |
| `scopeguard 1.2.0` | `94143f37725109f92c262ed2cf5e59bce7498c01bcc1502d7b9afe439a4e9f49` | MIT OR Apache-2.0; MSRV not declared | [https://github.com/bluss/scopeguard](https://github.com/bluss/scopeguard) | runtime via selected Hickory/Tokio feature closure |
| `semver 1.0.28` | `8a7852d02fc848982e0c167ef163aaff9cd91dc640ba85e263cb1ce46fae51cd` | MIT OR Apache-2.0; 1.68 | [https://github.com/dtolnay/semver](https://github.com/dtolnay/semver) | lock-only optional Hickory branch |
| `simd_cesu8 1.2.0` | `11031e251abf8611c80f460e19dbdeb54a66db918e49c65a7065b46ac7aec520` | Apache-2.0 OR MIT; 1.85.0 | [https://github.com/seancroach/simd_cesu8](https://github.com/seancroach/simd_cesu8) | lock-only optional Hickory branch |
| `simdutf8 0.1.5` | `e3a9fe34e3e7a50316060351f37187a3f546bce95496156754b601a5fa71b76e` | MIT OR Apache-2.0; MSRV not declared | [https://github.com/rusticstuff/simdutf8](https://github.com/rusticstuff/simdutf8) | lock-only optional Hickory branch |
| `slab 0.4.12` | `0c790de23124f9ab44544d7ac05d60440adc586479ce501c1d6d7da3cd8c9cf5` | MIT; 1.51 | [https://github.com/tokio-rs/slab](https://github.com/tokio-rs/slab) | runtime via selected Hickory/Tokio feature closure |
| `smallvec 1.15.2` | `8ed6a63f02c8539c91a8685a86f4099661ba3da017932f6ebbea6de3f0fa7c90` | MIT OR Apache-2.0; MSRV not declared | [https://github.com/servo/rust-smallvec](https://github.com/servo/rust-smallvec) | runtime via selected Hickory/Tokio feature closure |
| `socket2 0.6.5` | `c3d1e2c7f27f8d4cb10542a02c49005dbd6e93095799d6f3be745fae9f8fedd4` | MIT OR Apache-2.0; 1.70 | [https://github.com/rust-lang/socket2](https://github.com/rust-lang/socket2) | runtime via selected Hickory/Tokio feature closure |
| `stable_deref_trait 1.2.1` | `6ce2be8dc25455e1f91df71bfa12ad37d7af1092ae736f3a6cd0e37bc7810596` | MIT OR Apache-2.0; MSRV not declared | [https://github.com/storyyeller/stable_deref_trait](https://github.com/storyyeller/stable_deref_trait) | runtime via selected Hickory/Tokio feature closure |
| `tagptr 0.2.0` | `7b2093cf4c8eb1e67749a6762251bc9cd836b6fc171623bd0a9d324d37af2417` | MIT/Apache-2.0; MSRV not declared | [https://github.com/oliver-giersch/tagptr.git](https://github.com/oliver-giersch/tagptr.git) | runtime via selected Hickory/Tokio feature closure |
| `tinystr 0.8.3` | `c8323304221c2a851516f22236c5722a72eaa19749016521d6dff0824447d96d` | Unicode-3.0; 1.82 | [https://github.com/unicode-org/icu4x](https://github.com/unicode-org/icu4x) | runtime via selected Hickory/Tokio feature closure |
| `tinyvec 1.12.0` | `bb4ebadaa0af04fab11ae01eb5f9fdb5f9c5b875506e210e71c07873528baa7f` | Zlib OR Apache-2.0 OR MIT; MSRV not declared | [https://github.com/Lokathor/tinyvec](https://github.com/Lokathor/tinyvec) | runtime via selected Hickory/Tokio feature closure |
| `tinyvec_macros 0.1.1` | `1f3ccbac311fea05f86f61904b462b55fb3df8837a366dfc601a0161d0532f20` | MIT OR Apache-2.0 OR Zlib; MSRV not declared | [https://github.com/Soveu/tinyvec_macros](https://github.com/Soveu/tinyvec_macros) | runtime via selected Hickory/Tokio feature closure |
| `tokio 1.53.1` | `202caea871b69668250d242070849eb495be178ed697a3e98aebce5bc81a0bed` | MIT; 1.71 | [https://github.com/tokio-rs/tokio](https://github.com/tokio-rs/tokio) | runtime via selected Hickory/Tokio feature closure |
| `tokio-macros 2.7.2` | `78773a2a397f451582ce068015985c33193cf6dea8b74d2a639fe457b2f07b0e` | MIT; 1.71 | [https://github.com/tokio-rs/tokio](https://github.com/tokio-rs/tokio) | runtime via selected Hickory/Tokio feature closure |
| `tracing 0.1.44` | `63e71662fa4b2a2c3a26f570f037eb95bb1f85397f3cd8076caed2f026a6d100` | MIT; 1.65.0 | [https://github.com/tokio-rs/tracing](https://github.com/tokio-rs/tracing) | runtime via selected Hickory/Tokio feature closure |
| `tracing-core 0.1.36` | `db97caf9d906fbde555dd62fa95ddba9eecfd14cb388e4f491a66d74cd5fb79a` | MIT; 1.65.0 | [https://github.com/tokio-rs/tracing](https://github.com/tokio-rs/tracing) | runtime via selected Hickory/Tokio feature closure |
| `url 2.5.8` | `ff67a8a4397373c3ef660812acab3268222035010ab8680ec4215f38ba3d0eed` | MIT OR Apache-2.0; 1.63 | [https://github.com/servo/rust-url](https://github.com/servo/rust-url) | runtime via selected Hickory/Tokio feature closure |
| `utf8_iter 1.0.4` | `b6c140620e7ffbb22c2dee59cafe6084a59b5ffc27a8859a5f0d494b5d52b6be` | Apache-2.0 OR MIT; MSRV not declared | [https://github.com/hsivonen/utf8_iter](https://github.com/hsivonen/utf8_iter) | runtime via selected Hickory/Tokio feature closure |
| `uuid 1.24.0` | `bf3923a6f5c4c6382e0b653c4117f48d631ea17f38ed86e2a828e6f7412f5239` | Apache-2.0 OR MIT; 1.85.0 | [https://github.com/uuid-rs/uuid](https://github.com/uuid-rs/uuid) | runtime via selected Hickory/Tokio feature closure |
| `walkdir 2.5.0` | `29790946404f91d9c5d06f9874efddea1dc06c5efe94541a7d6863108e3a5e4b` | Unlicense/MIT; MSRV not declared | [https://github.com/BurntSushi/walkdir](https://github.com/BurntSushi/walkdir) | lock-only optional Hickory branch |
| `wasm-bindgen 0.2.127` | `1b70935747edd64d89de3efa29d73789b806c15798f8e7dca4d8ac356b50ce70` | MIT OR Apache-2.0; 1.77 | [https://github.com/wasm-bindgen/wasm-bindgen](https://github.com/wasm-bindgen/wasm-bindgen) | lock-only optional Hickory branch |
| `wasm-bindgen-macro 0.2.127` | `77775f8f3f7217702089053b94958f8f54061a3f663417df76e19cbdcca29bc1` | MIT OR Apache-2.0; 1.77 | [https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/macro](https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/macro) | lock-only optional Hickory branch |
| `wasm-bindgen-macro-support 0.2.127` | `e11d33f857dc2fb11b8bc75aee111aa9cbeb12cd9f25efd3d4c2a3dd4e235284` | MIT OR Apache-2.0; 1.77 | [https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/macro-support](https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/macro-support) | lock-only optional Hickory branch |
| `wasm-bindgen-shared 0.2.127` | `7ef64dbcc55df09c7e5a46182d181c2cfa3e925f3da937ea764728b4bbb9dcbf` | MIT OR Apache-2.0; 1.77 | [https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/shared](https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/shared) | lock-only optional Hickory branch |
| `winapi-util 0.1.11` | `c2a7b1c03c876122aa43f3020e6c3c3ee5c05081c9a00739faf7503aeba10d22` | Unlicense OR MIT; MSRV not declared | [https://github.com/BurntSushi/winapi-util](https://github.com/BurntSushi/winapi-util) | lock-only optional Hickory branch |
| `writeable 0.6.3` | `1ffae5123b2d3fc086436f8834ae3ab053a283cfac8fe0a0b8eaae044768a4c4` | Unicode-3.0; 1.82 | [https://github.com/unicode-org/icu4x](https://github.com/unicode-org/icu4x) | runtime via selected Hickory/Tokio feature closure |
| `yoke 0.8.3` | `709fe23a0424b6a435d82152b1bd3fdfb0833487d5fa90d05d42762a9891fef5` | Unicode-3.0; 1.82 | [https://github.com/unicode-org/icu4x](https://github.com/unicode-org/icu4x) | runtime via selected Hickory/Tokio feature closure |
| `yoke-derive 0.8.2` | `de844c262c8848816172cef550288e7dc6c7b7814b4ee56b3e1553f275f1858e` | Unicode-3.0; MSRV not declared | [https://github.com/unicode-org/icu4x](https://github.com/unicode-org/icu4x) | runtime via selected Hickory/Tokio feature closure |
| `zerofrom 0.1.8` | `0ec05a11813ea801ff6d75110ad09cd0824ddba17dfe17128ea0d5f68e6c5272` | Unicode-3.0; 1.71.1 | [https://github.com/unicode-org/icu4x](https://github.com/unicode-org/icu4x) | runtime via selected Hickory/Tokio feature closure |
| `zerofrom-derive 0.1.7` | `11532158c46691caf0f2593ea8358fed6bbf68a0315e80aae9bd41fbade684a1` | Unicode-3.0; 1.71.1 | [https://github.com/unicode-org/icu4x](https://github.com/unicode-org/icu4x) | runtime via selected Hickory/Tokio feature closure |
| `zerotrie 0.2.4` | `0f9152d31db0792fa83f70fb2f83148effb5c1f5b8c7686c3459e361d9bc20bf` | Unicode-3.0; 1.82 | [https://github.com/unicode-org/icu4x](https://github.com/unicode-org/icu4x) | runtime via selected Hickory/Tokio feature closure |
| `zerovec 0.11.6` | `90f911cbc359ab6af17377d242225f4d75119aec87ea711a880987b18cd7b239` | Unicode-3.0; 1.83 | [https://github.com/unicode-org/icu4x](https://github.com/unicode-org/icu4x) | runtime via selected Hickory/Tokio feature closure |
| `zerovec-derive 0.11.3` | `625dc425cab0dca6dc3c3319506e6593dcb08a9f387ea3b284dbd52a92c40555` | Unicode-3.0; MSRV not declared | [https://github.com/unicode-org/icu4x](https://github.com/unicode-org/icu4x) | runtime via selected Hickory/Tokio feature closure |

| Package / selected version | Registry / upstream URL | License / attribution obligation | Source release | Binary release |
| --- | --- | --- | --- | --- |
| `bitflags 2.13.1` | crates.io; [bitflags/bitflags](https://github.com/bitflags/bitflags) | MIT OR Apache-2.0; `dual` | ref-only | runtime via `nix` in java-bridge, plugin-host, and oracle binaries and via `rustix` in Unix process-supervision binaries |
| `block-buffer 0.12.1` | crates.io; [RustCrypto/utils](https://github.com/RustCrypto/utils) | MIT OR Apache-2.0; `dual` | ref-only | runtime via `sha2` in oracle and xtask binaries |
| `cfg-if 1.0.4` | crates.io; [rust-lang/cfg-if](https://github.com/rust-lang/cfg-if) | MIT OR Apache-2.0; `dual` | ref-only | runtime via `nix`/`sha2` consumers |
| `cfg_aliases 0.2.2` | crates.io; [katharostech/cfg_aliases](https://github.com/katharostech/cfg_aliases) | MIT; `MIT` | ref-only | nix build script only; not in final binaries |
| `cpufeatures 0.3.0` | crates.io; [RustCrypto/utils](https://github.com/RustCrypto/utils) | MIT OR Apache-2.0; `dual` | ref-only | runtime via `sha2` in oracle and xtask binaries |
| `crypto-common 0.2.2` | crates.io; [RustCrypto/traits](https://github.com/RustCrypto/traits) | MIT OR Apache-2.0; `dual` | ref-only | runtime via `sha2` in oracle and xtask binaries |
| `digest 0.11.3` | crates.io; [RustCrypto/traits](https://github.com/RustCrypto/traits) | MIT OR Apache-2.0; `dual` | ref-only | runtime via `sha2` in oracle and xtask binaries |
| `errno 0.3.14` | crates.io; [lambda-fairy/rust-errno](https://github.com/lambda-fairy/rust-errno) | MIT OR Apache-2.0; `dual` | ref-only | runtime via `rustix` in process-supervision binaries |
| `hybrid-array 0.4.14` | crates.io; [RustCrypto/hybrid-array](https://github.com/RustCrypto/hybrid-array) | MIT OR Apache-2.0; `dual` | ref-only | runtime via `sha2` in oracle and xtask binaries |
| `itoa 1.0.18` | crates.io; [dtolnay/itoa](https://github.com/dtolnay/itoa) | MIT OR Apache-2.0; `dual` | ref-only | runtime via `serde_json` in plugin-host, oracle, and xtask binaries |
| `libc 0.2.189` | crates.io; [rust-lang/libc](https://github.com/rust-lang/libc) | MIT OR Apache-2.0; `dual` | ref-only | runtime via `nix` in java-bridge, plugin-host, and oracle binaries and via `rustix` in Unix process-supervision binaries |
| `linux-raw-sys 0.12.1` | crates.io; [sunfishcode/linux-raw-sys](https://github.com/sunfishcode/linux-raw-sys) | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT; `dual` | ref-only | runtime via `rustix` on Unix process-supervision targets |
| `memchr 2.8.3` | crates.io; [BurntSushi/memchr](https://github.com/BurntSushi/memchr) | Unlicense OR MIT; `Unlicense/MIT` | ref-only | runtime via `serde_json` in plugin-host, oracle, and xtask binaries |
| `nix 0.31.3` | crates.io; [nix-rust/nix](https://github.com/nix-rust/nix) | MIT; `MIT` | ref-only | runtime in java-bridge, plugin-host, and oracle binaries |
| `proc-macro2 1.0.107` | crates.io; [dtolnay/proc-macro2](https://github.com/dtolnay/proc-macro2) | MIT OR Apache-2.0; `dual` | ref-only | proc-macro build only; not in final binaries |
| `quote 1.0.47` | crates.io; [dtolnay/quote](https://github.com/dtolnay/quote) | MIT OR Apache-2.0; `dual` | ref-only | proc-macro build only; not in final binaries |
| `rustix 1.1.4` | crates.io; [bytecodealliance/rustix](https://github.com/bytecodealliance/rustix) | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT; `dual` | ref-only | runtime in Unix process-supervision binaries only |
| `serde 1.0.229` | crates.io; [serde-rs/serde](https://github.com/serde-rs/serde) | MIT OR Apache-2.0; `dual` | ref-only | runtime in plugin-host, oracle, and xtask binaries |
| `serde_core 1.0.229` | crates.io; [serde-rs/serde](https://github.com/serde-rs/serde) | MIT OR Apache-2.0; `dual` | ref-only | runtime via `serde`/`serde_json` in plugin-host, oracle, and xtask binaries |
| `serde_derive 1.0.229` | crates.io; [serde-rs/serde](https://github.com/serde-rs/serde) | MIT OR Apache-2.0; `dual` | ref-only | proc-macro build only; not in final binaries |
| `serde_json 1.0.151` | crates.io; [serde-rs/json](https://github.com/serde-rs/json) | MIT OR Apache-2.0; `dual` | ref-only | runtime in plugin-host, oracle, and xtask binaries |
| `serde_spanned 1.1.1` | crates.io; [toml-rs/toml](https://github.com/toml-rs/toml) | MIT OR Apache-2.0; `dual` | ref-only | runtime via `toml` in xtask binaries |
| `sha2 0.11.0` | crates.io; [RustCrypto/hashes](https://github.com/RustCrypto/hashes) | MIT OR Apache-2.0; `dual` | ref-only | runtime in oracle and xtask binaries |
| `syn 3.0.3` | crates.io; [dtolnay/syn](https://github.com/dtolnay/syn) | MIT OR Apache-2.0; `dual` | ref-only | proc-macro build only; not in final binaries |
| `toml 1.1.4+spec-1.1.0` | crates.io; [toml-rs/toml](https://github.com/toml-rs/toml) | MIT OR Apache-2.0; `dual` | ref-only | runtime in xtask binaries |
| `toml_datetime 1.1.1+spec-1.1.0` | crates.io; [toml-rs/toml](https://github.com/toml-rs/toml) | MIT OR Apache-2.0; `dual` | ref-only | runtime via `toml` in xtask binaries |
| `toml_parser 1.1.3+spec-1.1.0` | crates.io; [toml-rs/toml](https://github.com/toml-rs/toml) | MIT OR Apache-2.0; `dual` | ref-only | runtime via `toml` in xtask binaries |
| `typenum 1.20.1` | crates.io; [paholg/typenum](https://github.com/paholg/typenum) | MIT OR Apache-2.0; `dual` | ref-only | runtime through `sha2` in oracle and xtask binaries |
| `unicode-ident 1.0.24` | crates.io; [dtolnay/unicode-ident](https://github.com/dtolnay/unicode-ident) | (MIT OR Apache-2.0) AND Unicode-3.0; `dual + Unicode` | ref-only | proc-macro build only; not in final binaries |
| `windows-link 0.2.1` | crates.io; [microsoft/windows-rs](https://github.com/microsoft/windows-rs) | MIT OR Apache-2.0; `dual` | ref-only | runtime via `windows-sys` in Windows process-supervision binaries |
| `windows-sys 0.61.2` | crates.io; [microsoft/windows-rs](https://github.com/microsoft/windows-rs) | MIT OR Apache-2.0; `dual` | ref-only | runtime in Windows process-supervision binaries only |
| `winnow 1.0.4` | crates.io; [winnow-rs/winnow](https://github.com/winnow-rs/winnow) | MIT; `MIT` | ref-only | runtime via `toml` in xtask binaries |
| `zmij 1.0.23` | crates.io; [dtolnay/zmij](https://github.com/dtolnay/zmij) | MIT; `MIT` | ref-only | runtime via `serde_json` in plugin-host, oracle, and xtask binaries |

The baseline table above contains the prior 33 registry records; the
HTTP-native TLS, decompression, and DNS additions tables contain 52, 12, and
89 newly introduced records respectively, for 153 additions and 186 registry
records in the active root product lock. The 31 registry records in the standalone fuzz table
are intentionally separate; their exact versions,
checksums, license expressions, dependency paths, purposes, and sources are
recorded there. If fuzz artifacts are ever distributed, the NCSA,
Unicode-3.0, and all other applicable notices must be reviewed separately;
they are outside the product release boundary.

### Dependency verification on 2026-08-13

The following checks were run against the active root graph after the targeted
webpki update and removal of the unused `rustls-pemfile` dependency:

- `cargo metadata --locked --format-version 1`: passed; 204 lock package
  records (18 workspace, 186 registry).
- `cargo tree --locked -e features -p jmeter-rs-http-native`: passed; the
  selected rustls `ring`/`std`/`tls12`, rcgen `crypto`/`ring`, and
  Hickory `tokio` closure was inspected; system-config/JNI and DoH/DoT/TLS/
  QUIC resolver features are absent.
- `cargo tree --locked -d`: passed; the `getrandom`, `syn`, and
  target-specific `windows-sys` duplicate-version families are expected
  rustls/Hickory/process-supervision cross-edge duplication.
- `cargo deny check`: passed; no advisories remain in the active graph, and
  bans, licenses, and sources passed, including the ISC and BSD-3-Clause
  additions.
  Installed cargo-deny 0.20.2 rejects the Decision 0006-era
  `cargo deny check --all-features` spelling, so the supported command above
  is the exact check result.

The advisory is recorded rather than suppressed. No profile row is promoted
by these dependency checks.

## Static verification

The hashes and body-preservation claim can be rechecked without downloading or
executing JMeter by reading the ignored local source extraction and the two
tracked generated files:

```python
from hashlib import sha256
from pathlib import Path

root = Path(".")
commit = "34a2785748e9e0b14702595e8682c387869deda3"
expected = {
    "saveservice": {
        "raw": "fcc28aeaced4c0e170e7a89089f6e9492f70be30b4c5aadbf6bbdefa660ad5a9",
        "body": "4d510edae46db11575a5d4c67327eefa676bdb4bb43b1baa05228deda4e13c1b",
        "prefix": "c8f5a107f0c8a1c4dbbc01bd12cd0ccb0f8cfc9b8787d4743002778e65b405d6",
        "generated": "eca06d3b962db3966e91f5670e1d28e9b1b08b4c82cd52f2730a4eb80da838e2",
    },
    "upgrade": {
        "raw": "43295cd0904ab61daf47dd9de780007beaabc617aadd01c7a19a42a9286ff3f2",
        "body": "c9fab3dfdb4b71b1ae07281044060448fdae154ef1a041faf266ebfb74f142ff",
        "prefix": "7aaf92ed1627e9e28b4e5d7552c444a425d5e3fbbc5fbd9f573142d0b0dc919d",
        "generated": "ca4be70124d06d75425d25e5993a587d7263e4561563395c82d1fb002568b831",
    },
}
for name in ("saveservice", "upgrade"):
    source = (root / "jmeter-oracle-cache" / "apache-jmeter-5.6.3" /
              "bin" / f"{name}.properties").read_bytes()
    normalized = source.replace(b"\r\n", b"\n")
    generated = (root / "crates" / "jmx" / "data" /
                 f"{name}-5.6.3.properties").read_bytes()
    generated_lf = generated.replace(b"\r\n", b"\n")
    prefix = generated_lf[:-len(normalized)]
    assert sha256(source).hexdigest() == expected[name]["raw"]
    assert sha256(normalized).hexdigest() == expected[name]["body"]
    assert sha256(prefix).hexdigest() == expected[name]["prefix"]
    assert sha256(generated_lf).hexdigest() == expected[name]["generated"]
    assert generated_lf == prefix + normalized
    assert commit
```

The command above is intentionally an invariant check rather than a download,
packaging, or JMeter process invocation. The hashes in the table are the
expected values for the pinned local source and generated files.
