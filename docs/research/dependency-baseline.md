# Rust dependency baseline

Status: historical snapshot checked 2026-08-12 (UTC) against the then-pinned
Rust 1.97.1 toolchain. Refresh this report from the current manifests and lock
file before using it as release or dependency evidence.

> Historical snapshot notice: the detailed inventory and lock-graph analysis
> below describe the pre-integration workspace state. The current workspace
> has additional crate manifests and a different resolved dependency graph;
> this document is retained for provenance, not as a current inventory.

This is the dependency baseline for compatibility ID `TEST-001` (the
reproducible test/tooling harness). It covers every direct dependency declared
by a workspace member. It does not authorize changing a member manifest; the
workspace policy owner must review any constraint exception below.

## Method and policy

The historical inventory was obtained from all `Cargo.toml` files under
`apps/`, `crates/`, and `tools/`. At that snapshot only
`tools/jmeter-oracle` and `tools/xtask` declared external dependencies. The
current workspace also contains dependency declarations in library crates such
as `crates/plugin-host` and `crates/java-bridge`; the table below must not be
treated as their inventory.

For each direct crate, the crates.io API and sparse index were queried on
2026-08-12. The API's `max_stable_version` and version record were used to
identify the latest non-yanked stable release; prereleases were excluded.
The authoritative records are linked in the table. Cargo's resolver was then
checked with Rust 1.97.1 using `cargo metadata --locked`,
`cargo update --dry-run --locked`, and `cargo tree --workspace --locked
--all-features`.

That snapshot workspace kept resolver version 3, an exact Rust 1.97.1 toolchain, a
committed lockfile, and `--locked` CI checks. Wildcard requirements remain
forbidden by `deny.toml`; optional features are selected explicitly at each
call site. No dependency below has a native build script or a required
system-library boundary in the selected feature set.

## Direct dependency inventory

| Member and declaration | Selected lock version | Latest stable from crates.io | Rust requirement | Features in use | License | Assessment |
| --- | --- | --- | --- | --- | --- | --- |
| `tools/jmeter-oracle`: `serde = { version = "1.0", features = ["derive"] }` ([API](https://crates.io/api/v1/crates/serde)) | `1.0.229` | `1.0.229` ([version](https://crates.io/api/v1/crates/serde/1.0.229)) | `1.56` | `derive` (default `std`) | `MIT OR Apache-2.0` | Requirement permits and resolves the latest stable 1.0 release. Proc-macro dependency is Rust-only. |
| `tools/jmeter-oracle`: `serde_json = "1.0"` ([API](https://crates.io/api/v1/crates/serde_json)) | `1.0.151` | `1.0.151` ([version](https://crates.io/api/v1/crates/serde_json/1.0.151)) | `1.71` | default `std` | `MIT OR Apache-2.0` | Requirement permits and resolves the latest stable 1.0 release. Selected graph uses `itoa`, `memchr`, `serde_core`, and `zmij`; no native library. |
| `tools/jmeter-oracle`: `sha2 = "0.10"` ([API](https://crates.io/api/v1/crates/sha2)) | `0.10.9` | `0.11.0` ([version](https://crates.io/api/v1/crates/sha2/0.11.0)) | `0.11.0`: `1.85`; `0.10.9` does not publish a `rust_version` field | default `std` | `MIT OR Apache-2.0` | **Constraint exception.** `^0.10` intentionally selects the newest 0.10 release but does not permit the newest stable major, 0.11.0. The member owner must decide whether the SHA-2 API and lockfile transition can be made; this task leaves the manifest unchanged. |
| `tools/xtask`: `serde_json = { version = "1.0.151", default-features = false, features = ["std"] }` ([API](https://crates.io/api/v1/crates/serde_json)) | `1.0.151` | `1.0.151` ([version](https://crates.io/api/v1/crates/serde_json/1.0.151)) | `1.71` | `std`; default features disabled explicitly | `MIT OR Apache-2.0` | Requirement permits and resolves the latest stable 1.0 release. The explicit feature set avoids accidental feature expansion. |
| `tools/xtask`: `sha2 = { version = "0.11.0", default-features = false }` ([API](https://crates.io/api/v1/crates/sha2)) | `0.11.0` | `0.11.0` ([version](https://crates.io/api/v1/crates/sha2/0.11.0)) | `1.85` | no default features | `MIT OR Apache-2.0` | Requirement permits and resolves the latest stable 0.11 release. The selected graph is Rust-only (`cfg-if`, `cpufeatures`, `digest`) and has no assembly/native dependency. |
| `tools/xtask`: `toml = { version = "1.1.4", default-features = false, features = ["parse", "serde"] }` ([API](https://crates.io/api/v1/crates/toml)) | `1.1.4+spec-1.1.0` | `1.1.4+spec-1.1.0` ([version](https://crates.io/api/v1/crates/toml/1.1.4%2Bspec-1.1.0)) | `1.85` | `parse`, `serde`; defaults disabled | `MIT OR Apache-2.0` | Requirement permits and resolves the latest stable release. Cargo ignores build metadata for version matching; the selected release's parser graph is Rust-only. Display/debug, `anstream`, `anstyle`, `foldhash`, and `indexmap` features are not selected. |

All selected latest stable releases have an MSRV no greater than Rust 1.85.0
where crates.io publishes one, so they are compatible with the workspace's
Rust 1.97.1 MSRV/toolchain. The absence of a `rust_version` field on
`sha2` 0.10.9 is recorded rather than treated as evidence of a lower MSRV;
the pinned lockfile and Rust 1.97.1 build are the compatibility check for that
legacy branch.

## Lock graph, duplicates, and risk review

The historical lock graph had 48 package records. The only
duplicate-version families are the expected SHA-2 major-version split:

```text
sha2          0.10.9, 0.11.0
digest        0.10.7, 0.11.3
block-buffer  0.10.4, 0.12.1
crypto-common 0.1.7, 0.2.2
cpufeatures   0.2.17, 0.3.0
```

At the time, the split was caused by the oracle member's `sha2 = "0.10"` constraint and the
xtask member's `sha2 = "0.11.0"` constraint. `deny.toml` therefore reports
multiple versions as a warning while denying wildcard requirements. Once the
oracle owner reviews the major-version transition, the duplicate families
should be rechecked; they must not be removed by hand-editing `Cargo.lock`.

The selected direct dependencies are pure Rust and use permissive
`MIT OR Apache-2.0` licensing. No direct dependency enables a C compiler,
system TLS library, shell, filesystem watcher, network client, or JVM. The
oracle's SHA-2 use is for pinned artifact digests, while xtask uses SHA-256
for fixture identity; those are data-integrity boundaries, not cryptographic
authentication claims. Advisory, license, and source checks remain required
in CI; this document does not promote any dependency to a security-approved
status by itself.

## Reproducibility evidence

Observed with the exact binaries from the historical pinned toolchain:

```text
rustc 1.97.1 (8bab26f4f 2026-07-14)
cargo 1.97.1 (c980f4866 2026-06-30)
```

`cargo update --dry-run --locked` reported:

```text
Locking 0 packages to latest Rust 1.97.1 compatible versions
warning: not updating lockfile due to dry run
```

The verbose update probe identified the two remaining newer compatible
records: `generic-array 0.14.9` is blocked because the selected
`crypto-common 0.1.7` dependency pins `generic-array = 0.14.7`, and
`sha2 0.11.0` is outside the oracle's declared `^0.10` range. These are
transitive/manifest constraints, not stale lockfile edits; Cargo must retain
the versions required by the graph until their owners change the constraints.

After the `sha2 0.10` constraint exception was recorded and reported, the
historical `cargo update` completed with the same zero-package update result
and regenerated that snapshot's lockfile. The lockfile was then checked with
`cargo metadata --locked`, `cargo tree --duplicates`, and the workspace
test/lint gates. Never hand-edit checksums or dependency edges.

## Historical review queue

The following items were open in the historical snapshot and must be
re-evaluated against the current workspace before release:

1. The `tools/jmeter-oracle` owner had to explicitly decide whether to widen or
   raise `sha2 = "0.10"` to the latest stable 0.11 line. The historical
   baseline did not edit that member manifest.
2. After that decision, refresh `Cargo.lock` with Cargo and verify that the
   duplicate families above are either eliminated or intentionally documented.
3. Run `cargo deny check` with development dependencies included
   (`deny.toml` sets `exclude-dev = false`); review advisories, licenses, bans,
   and sources separately.
   The historical run was blocked by the concurrent `crates/jmx` path dependency
   on `jmeter-rs-model` without a package version; cargo-deny classified that
   as a wildcard dependency. The JMX/member owner must add the intended
   workspace version constraint (or record an architecture-approved policy)
   before the deny gate can pass. The SHA-2 duplicate warnings are expected
   until the oracle constraint decision is made.
