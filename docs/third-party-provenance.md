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

The root workspace currently has 17 workspace package records and 33 registry
package records in `Cargo.lock` (50 `[[package]]` records total). Workspace
package metadata inherits `license = "Apache-2.0"` and `publish = false` from
the root `Cargo.toml`; path dependencies are internal and are not repeated in
the external ledger.

This section is the current dependency record, checked against the manifests,
both lockfiles, and the local Cargo registry metadata on 2026-08-13. The
research file `docs/research/dependency-baseline.md` is a historical,
pre-integration snapshot; its broad ranges and package counts are not current
release evidence. Direct external declarations below are exact pins. The
selected versions are the latest Rust-1.97.1-compatible versions available in
the local sparse index/cache at this audit date; that is an offline repository
observation, not a claim about a remote registry query.

### Direct external declarations

The versions in the “lock” column are the currently selected versions in the
root lockfile. A manifest range is recorded separately where it is not exact.

| Manifest | Direct external declaration | Current lock version and license fact |
| --- | --- | --- |
| `crates/java-bridge/Cargo.toml` | `nix = "=0.31.3"`, `default-features = false`, `process` and `signal` | `nix 0.31.3`; MIT, published MSRV 1.69; Rust-only cfg build helper, no C/C++ build |
| `crates/plugin-host/Cargo.toml` | `nix = "=0.31.3"`, `default-features = false`, `fs`, `process`, `signal`; `serde = "=1.0.229"`, `default-features = false`, `derive`/`std`; `serde_json = "=1.0.151"`, `default-features = false`, `std`; `sha2 = "=0.11.0"`, `default-features = false` | `nix 0.31.3` (MIT, MSRV 1.69); `serde 1.0.229` and `serde_json 1.0.151` (MIT OR Apache-2.0, MSRVs 1.56 and 1.71); `sha2 0.11.0` (MIT OR Apache-2.0, MSRV 1.85); no native compiler dependency |
| `tools/jmeter-oracle/Cargo.toml` | `serde = "=1.0.229"`, `default-features = false`, `derive`/`std`; `serde_json = "=1.0.151"`, `default-features = false`, `std`; `sha2 = "=0.11.0"`, `default-features = false`; `nix = "=0.31.3"`, `default-features = false`, `fs`, `process`, `signal` | Same selected versions and licenses/MSRVs as above; `nix` is MIT/MSRV 1.69; no native compiler dependency |
| `crates/process-supervision/Cargo.toml` | Unix: `rustix = "=1.1.4"`, `default-features = false`, `std`/`process`; Windows: `windows-sys = "=0.61.2"`, `default-features = false`, `Win32_Foundation`, `Win32_Security`, `Win32_System_JobObjects`, `Win32_System_Pipes`, `Win32_System_Threading` | `rustix 1.1.4` (Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT, MSRV 1.63, Rust-only cfg/backend build helper); `windows-sys 0.61.2` (MIT OR Apache-2.0, MSRV 1.71, no build script); Windows-only `windows-link 0.2.1` (MIT OR Apache-2.0, MSRV 1.71, no build script) |
| `tools/xtask/Cargo.toml` | `serde_json = "=1.0.151"`, `default-features = false`, `std`; `sha2 = "=0.11.0"`, `default-features = false`; `toml = "=1.1.4"`, `default-features = false`, `parse`/`serde` | `serde_json 1.0.151`, `sha2 0.11.0`, `toml 1.1.4+spec-1.1.0` (MIT OR Apache-2.0; MSRVs 1.71, 1.85, and 1.85); no native compiler dependency |

Default features are disabled on every production direct registry dependency;
the manifests opt into only the platform, serialization, hashing, or TOML
features shown above. Published MSRVs observed in the selected root packages
are below 1.97.1. `nix` has a Rust cfg-alias build helper, and `rustix` has a
Rust-only cfg/backend build helper; neither introduces a C/C++ compiler or
system-library build boundary. `windows-sys` has no build script. The root
lockfile has no duplicate registry versions and no Git or unknown-registry
source.

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

All 33 selected root registry package manifests were available in the local
Cargo source cache for this static pass. The expressions above are exact
metadata from those selected manifests; they are not inferred from manifest
comments. `nix 0.31.3` is MIT, `cfg_aliases 0.2.2` is MIT, and the selected
`bitflags`, `libc`, and `serde_spanned` releases are MIT OR Apache-2.0.

The current root `deny.toml` allowlist is Apache-2.0, MIT, and Unicode-3.0;
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
Unicode-3.0 notice/text; and `dual + NCSA` adds the NCSA notice/text. The
current tree has the project Apache-2.0 `LICENSE`, but no generated bundle of
these third-party notices. Any binary release containing a runtime row must
produce and ship the applicable third-party notices before distribution.

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

The table above contains the 33 registry records in the root product lock.
The 31 registry records in the standalone fuzz table are intentionally
separate; their exact versions, checksums, license expressions, dependency
paths, purposes, and sources are recorded there. If fuzz artifacts are ever
distributed, the NCSA, Unicode-3.0, and all other applicable notices must be
reviewed separately; they are outside the product release boundary.

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
