<!-- SPDX-License-Identifier: Apache-2.0 -->

# Repository automation policy

The workflows under `.github/workflows/` are part of the compatibility and
security boundary. Every third-party action is pinned to the full commit SHA
for its current stable release; the release tag is retained as an adjacent
comment for review. Pin verification is performed against the action's
official GitHub repository (`git ls-remote --tags` or the official release
page), not an untrusted mirror.

The initial pins, checked on 2026-08-12 UTC, are:

| Action (primary source) | Stable release | Commit |
| --- | --- | --- |
| [`actions/checkout`](https://github.com/actions/checkout/releases/tag/v7.0.1) | `v7.0.1` | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| [`actions/cache`](https://github.com/actions/cache/releases/tag/v6.1.0) | `v6.1.0` | `55cc8345863c7cc4c66a329aec7e433d2d1c52a9` |
| [`actions/upload-artifact`](https://github.com/actions/upload-artifact/releases/tag/v7.0.1) | `v7.0.1` | `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` |
| [`actions-rust-lang/setup-rust-toolchain`](https://github.com/actions-rust-lang/setup-rust-toolchain/releases/tag/v1.17.0) | `v1.17.0` | `166cdcfd11aee3cb47222f9ddb555ce30ddb9659` |
| [`actions/setup-java`](https://github.com/actions/setup-java/releases/tag/v5.7.0) | `v5.7.0` | `b6effb05e454b25005698d916606bdc6ffcbf961` |
| [`actions/dependency-review-action`](https://github.com/actions/dependency-review-action/releases/tag/v5.0.0) | `v5.0.0` | `a1d282b36b6f3519aa1f3fc636f609c47dddb294` |
| [`EmbarkStudios/cargo-deny-action`](https://github.com/EmbarkStudios/cargo-deny-action/releases/tag/v2.1.1) | `v2.1.1` | `3c6349835b2b7b196a839186cb8b78e02f7b5f25` |

Rust CI currently runs the exact stable Rust/Cargo toolchain `1.97.1`, including
the `rustfmt` and `clippy` components where needed. It is the stable channel
published by Rust on 2026-07-16. The workspace MSRV is also `1.97.1`; this is a
pinned-stable lane, not a separate MSRV or floating latest-stable lane. The
Linux, Windows, and macOS jobs use explicit hosted image labels and do not
share caches across operating systems, architectures, lockfiles, or toolchain
files.

The dependency lane pins `rust-version: "1.97.1"` for cargo-deny, installs
`cargo-audit` `0.22.2` with `--locked`, and retains the pinned cargo-deny action
release (`cargo-deny` `0.20.2`). The process-safety job contains the direct
ADR-0001 shared-supervisor acceptance commands and remains fail-closed until
the shared crate and lock entry exist, every namespace wrapper (including the
shared crate wrapper) proves its private PID identity, and all three callers
have migrated to the shared owner. Ordinary group tests never signal a process
group; ignored group tests require the verified PID-namespace wrappers and
remain fail-closed when wrapper proofs are absent. The migration assertion
rejects caller-local `killpg`/`nix` process-signal supervisors and requires a
path dependency on `jmeter-rs-process-supervision`.
The current wrapper audit is intentionally blocking until the oracle and
shared-crate wrappers add nested PID/PID 1 proof and the Java bridge wrapper
uses a locked Cargo invocation.

Repository policy checks invoke xtask explicitly with Cargo's locked package
runner; the `.cargo/config.toml` `xtask` alias is not a CI entry point:

```text
cargo run --locked --package xtask -- workspace-check
cargo run --locked --package xtask -- profile-check
cargo run --locked --package xtask -- fixture-check
cargo run --locked --package xtask -- policy-check
RUSTDOCFLAGS=-Dwarnings cargo doc --workspace --all-features --locked --no-deps
```

The standalone fuzz lane is static-only. It checks the separate fuzz
workspace's locked metadata, bounded target compilation, and rustfmt, then
checks its `fuzz/deny.toml` graph and `fuzz/Cargo.lock` with exact cargo-fuzz
`0.12.0`, cargo-deny `0.20.2`, cargo-audit `0.22.2`, and
libfuzzer-sys `0.4.13` pins. It never runs `cargo fuzz`, libFuzzer, a campaign,
or a fuzz artifact-producing command; campaign/nightly execution remains
planned.

PID-namespace wrappers have a narrow, statically auditable launcher contract.
A POSIX shell may perform only bounded preflight (resolve `unshare`, prove a
nested `NSpid` and namespace PID 1, and validate exact arguments), then it
must `exec cargo test --locked ... -- --ignored`. The wrapper may not invoke a
signal/process utility, broad cleanup command, shell fallback, or external
process limiter. CI audits executable wrapper text, not comments, and fails
closed until every wrapper proves the contract. This documents the launcher
design without weakening the repository's process-safety rules; namespace
execution remains after the static audit and migration gate.

The JMeter fixture-smoke workflow is unconditionally disabled pending that
shared supervisor gate. It does not execute Java or JMeter in the current
automation. Its future path is retained only through `jmeter-oracle run`; an
external process-limit wrapper or direct launcher is not an accepted substitute. Before that
lane can be enabled, its artifact manifest must contain the source commit,
dirty-tree state captured before any generated output, immutable OS image
digest, Cargo.lock SHA-256, and the runner's actual locale/timezone/environment
values. All generated manifests, logs, fixture results, caches, and Cargo
outputs belong under `RUNNER_TEMP`; a workspace cleanliness check fails if any
generated file escapes that root. A fixture smoke artifact is not differential
conformance evidence and never promotes a profile row to `verified`.

Pull requests and pushes run the Rust quality and dependency/security lanes;
the disabled fixture-smoke workflow is scheduled/manual only and has no
pull-request secrets.

## Lane status matrix

The following matrix is a policy inventory, not evidence that planned lanes
run today. `planned` means prerequisites and a dedicated workflow remain to be
implemented; `disabled` means a definition may exist but is not executable in
current automation.

| Lane | Status | Required prerequisite before activation |
| --- | --- | --- |
| Pinned stable Rust 1.97.1 | current | Existing Linux/Windows/macOS quality jobs |
| Separate MSRV | planned | Dedicated MSRV command/job, even though current workspace MSRV is 1.97.1 |
| Latest stable Rust | planned | Explicitly selected and recorded toolchain; never an untracked `latest` cache |
| Nightly | planned | Dedicated nightly selection and failure reporting; no production dependency |
| Miri | planned | Declared nightly/tooling lane and unsafe-boundary scope |
| Sanitizers | planned | Platform-supported sanitizer toolchain and isolated process tests |
| Loom/model tests | planned | Bounded model configuration and deterministic evidence |
| Fuzz smoke | planned | Pinned fuzz toolchain, corpus, bounds, and retained failure artifact |
| Container fixtures | planned | Pinned image digest, allowlisted mounts, network policy, and resource caps |
| Distributed/RMI fixtures | disabled | Pinned Java workers, ports, keystores, sender modes, and safe cleanup |
| Recorder/TLS fixtures | disabled | Local deterministic service, certificate provenance, keytool/JDK evidence |
| Performance/soak | planned | Pinned runner/data set, bounded retention, and leak/process evidence |
| Linux musl | planned | Explicit musl target/toolchain and compatible fixture coverage |
| Linux ARM64 | planned | ARM64 runner or pinned cross-build/runtime evidence |
| Java 8 compatibility | planned | Pinned Java 8 runtime and profile-specific evidence |
| Full differential oracle | disabled | Shared supervisor gate, verified archive, manifests, and comparison fixtures |
| Release provenance | planned | Clean checkout, signed manifest/attestation, checksums, and lock/toolchain metadata |

The signature check additionally requires Apache signer fingerprint
`C4923F9ABFB2F1A06F08E88BAC214CAA0612B399` (Milamber), as observed from the
profile's `.asc` artifact and official `KEYS` file.

Dependabot proposes Cargo and workflow-action updates. Reviewers must replace
updated action tags with their full commit SHAs and update the release comment
and this inventory after verifying the official source. CodeQL is not enabled
yet: the initial security lane is the RustSec audit, cargo-deny license/source
policy, dependency review, and repository-specific validators; a CodeQL job can
be added after its Rust analysis support and required repository settings are
confirmed.
