<!-- SPDX-License-Identifier: Apache-2.0 -->

# jmeter-rs

An early, experimental Rust project exploring compatibility with [Apache
JMeter](https://jmeter.apache.org/) test plans and result formats.

This project does not claim compatibility with Apache JMeter yet. The name
Apache JMeter is used nominatively: jmeter-rs is independent and is not
affiliated with, sponsored by, or endorsed by the Apache Software Foundation.

## Project documents

- [Architecture and Rust guidelines](docs/architecture.md) *(binding design)*
- [Compatibility profile and validation rules](compat/README.md)
- [JMeter 5.6.3 profile](compat/profiles/jmeter-5.6.3.json)
- [Compatibility surface and conformance matrix](docs/research/compatibility-surface.md)
- [Repository and publication baseline](docs/research/repository-baseline.md)
- [Rust testing and conformance strategy](docs/research/rust-testing-strategy.md)
- [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md)

## Current implementation status

The repository is an experimental Rust implementation, not a supported JMeter
engine. The current command provides bounded native local execution for enabled
`ThreadGroup`/`TestPlan` trees containing `GenericController`, `LoopController`,
and `DebugSampler` nodes (with response assertions), plus CSV report-only
dashboard processing; Java/JSR223, plugins, RMI, GUI, unsupported
samplers/controllers, and other capabilities outside that adapter return stable
typed unsupported-capability errors. The JMeter 5.6.3 profile contains 52
intentionally unverified rows: 33 `planned` and 19 `external`. No row is a
compatibility claim.

The intended first product is one Java-free Rust CLI executable for the
declared native capability projection. Exact arbitrary Java scripts, classes,
plugins, legacy Java RMI, and the postponed Swing GUI remain an optional
compatibility-pack surface; they are never a hidden prerequisite or fallback
for native plans. See
[Decision 0009](docs/decisions/0009-standalone-rust-product-and-compatibility-pack.md).

The pinned-oracle workflow is defined for future artifact verification and
fixture smoke, but is currently disabled pending the shared process-supervision
gate. Current automation does not execute Java or JMeter. If enabled, its
smoke output would still not compare Rust behavior with JMeter or promote a
profile row to `verified`; Java, plugins, remote services, GUI behavior, and
arbitrary JMX plans remain outside any supported-release claim.

There is no supported release or compatibility guarantee at this stage.
