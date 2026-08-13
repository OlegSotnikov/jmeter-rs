<!-- SPDX-License-Identifier: Apache-2.0 -->

# Contributing to jmeter-rs

`jmeter-rs` is early experimental software. Contributions should build
reproducible evidence for a declared Apache JMeter profile; they must not turn
an untested behavior into a compatibility claim.

## Before changing code

Read the [binding architecture](docs/architecture.md), the [Rust testing and
conformance strategy](docs/research/rust-testing-strategy.md), the
[compatibility profile](compat/README.md), and the [compatibility
surface](docs/research/compatibility-surface.md). Keep public behavior, test
evidence, and compatibility-matrix status aligned.

For each behavior change:

1. Write or update a focused test first. Use unit tests for deterministic
   parsing and state-machine rules, property/fuzz tests for input boundaries,
   local integration fixtures for I/O, and differential tests when comparing
   with Apache JMeter.
2. Identify the relevant compatibility-matrix row. Do not mark a row verified
   without the evidence required by that row and a pinned JMeter profile.
3. Make tests deterministic: use local services or recorded fixtures, explicit
   seeds and clocks, bounded timeouts, and no production endpoints or ambient
   credentials.
4. Record fixture provenance, license/notice obligations, profile versions,
   hashes, and any normalization or intentional difference.

Do not copy Apache JMeter or plugin files, plans, result corpora, or other
third-party fixtures into this repository unless their source, version,
license, redistribution permission, attribution, and compatibility purpose
have been reviewed. Prefer small original or generated fixtures. A fixture
that is useful for an oracle run may still be incompatible with this source
distribution's licensing or safety requirements.

## Rust and repository checks

Before submitting a change, run the applicable checks below. These local
checks do not launch Java or Apache JMeter:

```sh
python3 -m json.tool compat/profiles/jmeter-5.6.3.json >/dev/null
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo xtask workspace-check
cargo xtask profile-check
cargo xtask fixture-check
```

Run dependency/security checks when their pinned tools are available:

```sh
cargo deny check
cargo audit --locked
```

Use locked dependency resolution in CI. The separate JMeter lane is defined
as manual/scheduled oracle smoke work, but is currently disabled; current
automation does not launch Java or Apache JMeter. If enabled, its output is
not differential evidence and cannot promote a profile row to `verified`
without the named comparison and fixture evidence. Release conformance must
fail closed when the pinned oracle is unavailable.

Never commit credentials, private keys, customer data, unredacted URLs,
unreviewed JMX plans, generated load results, or downloaded JMeter archives.

Keep changes focused, explain observable behavior and test evidence in the
pull request, and call out unsupported elements or known differences instead
of silently mapping them to another behavior.

## Pull request checklist

- [ ] The change has a focused regression or behavior test.
- [ ] The test uses a pinned, reproducible fixture or explicitly documents why
      it is not an oracle case.
- [ ] The compatibility row/status and evidence references are accurate; no
      row is marked `verified` without its profile evidence.
- [ ] New fixtures have provenance and license/notice review.
- [ ] Formatting, linting, and relevant tests pass without secrets or live
      service dependencies.
- [ ] Documentation does not promise unsupported or unverified compatibility.
