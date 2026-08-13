<!-- SPDX-License-Identifier: Apache-2.0 -->

# Pinned oracle harness corpus

This is the source-only corpus for `FX-HARNESS-001` and the harness portions
of `TEST-001`, `TEST-002`, and `TEST-004`. It defines bounded data contracts
for a future oracle runner: the Apache JMeter archive and OpenPGP pins,
repository/toolchain hashes, platform and environment policy, external
classpath/plugin/service declarations, raw-artifact locations, comparison
reports, and unavailable-oracle outcomes.

Nothing in this directory is execution evidence. No Java, JMeter, plugin,
service, container, network client, or subprocess was started while creating
these files. `evidence-unavailable.json` deliberately records that distinction
and keeps process exit, sample counts, observed digests, and raw output absent.
The source fixture is present (`source_fixture_present: true`), but oracle
evidence is not materialized (`oracle_evidence_materialized: false`) and the
run remains `not-run-static`; null observed values must stay null until a real
run records them.

Coverage is mapped per feature rather than treated as one boundary union:

| ID | normalization policies | external boundaries |
|---|---|---|
| `TEST-001` | `NORM-ENV-001`, `NORM-SECURITY-001` | none |
| `TEST-002` | `NORM-EXTERNAL-001`, `NORM-ENV-001`, `NORM-SECURITY-001` | JVM, service, TLS, plugin |
| `TEST-004` | `NORM-EXTERNAL-001`, `NORM-SECURITY-001`, `NORM-TIME-001` | RMI, TLS, service |

Environment metadata is consistent across the manifest, case, evidence, and
provenance: `LANG=C`, `LC_ALL=C`, `TZ=UTC`, and the fixed `PATH` are the only
allowed process variables; the profile/JVM locale remains explicit `en-US`,
with UTF-8 as the default charset. The C process locale and en-US JVM locale
are deliberately separate contracts and neither is an observed value here.
The manifest records the profile's `SOURCE_DATE_EPOCH` requirement as
`required-before-run`; the static case, evidence, and provenance retain a null
value because no run was materialized.

## Layout and ownership

`case.json` and `provenance.json` use the repository's existing fixture
manifest/provenance contracts owned by `tools/xtask`; this corpus does not add
or replace validator code. The custom documents are data consumed by those
validators and by a future harness:

| file | purpose |
|---|---|
| `manifest.json` | bounded run-input contract, per-ID coverage, and reproducibility pins |
| `evidence-unavailable.json` | fail-closed result when the oracle has not run |
| `normalized-diff-example.json` | comparator-shaped diff example, explicitly not evidence |
| `schemas/manifest.schema.json` | JSON Schema for `manifest.json` |
| `schemas/evidence.schema.json` | strict JSON Schema for evidence and comparison outcomes |
| `schemas/normalized-diff.schema.json` | standalone schema for the comparator's bounded diff |

The pinned artifact is Apache JMeter `5.6.3`, source commit
`34a2785748e9e0b14702595e8682c387869deda3`, and SHA-512
`387fadca903ee0aa30e3f2115fdfedb3898b102e6b9fe7cc3942703094bd2e65b235df2b0c6d0d3248e74c9a7950a36e42625fd74425368342c12e40b0163076`.
The archive, SHA-512 sidecar, detached signature, keyring, logs, JTLs,
normalized diffs, plugin/service images, and any generated certificates are referenced under ignored
`oracle-runs/` or CI artifact storage only; none are checked in.

Before an oracle can be unpacked or executed, the future runner must pass both
`GATE-ARTIFACT-SHA512-001` and `GATE-PGP-SIGNATURE-001`. The latter imports the
official Apache `KEYS` file and requires a `VALIDSIG` status line for
`C4923F9ABFB2F1A06F08E88BAC214CAA0612B399`; the detached-signature check is a
harness input contract, not merely workflow prose. A failed or unrun gate is
fail-closed.

The normalized-diff schema mirrors `tools/jmeter-oracle/src/compare.rs`:
differences use only `path`, `kind`, `expected`, and `actual`; normalized fields
are listed separately using comparator paths such as `sample.ts` and
`sample.host`, while debug-line patterns are carried separately as wildcard
patterns. Labels, response codes, assertion outcomes, ordering, tree shape,
and observable bytes are never implicitly normalized. Raw JTL, log,
process-output, structured-diff, and raw-diff files each carry an explicit
manifest bound and remain outside Git.

## Static checks

From the repository root, the safe checks for this corpus are:

```sh
python3 -m json.tool compat/fixtures/jmeter-5.6.3/harness/case.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/harness/provenance.json >/dev/null
for file in compat/fixtures/jmeter-5.6.3/harness/manifest.json \
  compat/fixtures/jmeter-5.6.3/harness/evidence-unavailable.json \
  compat/fixtures/jmeter-5.6.3/harness/normalized-diff-example.json \
  compat/fixtures/jmeter-5.6.3/harness/schemas/*.json; do
  python3 -m json.tool "$file" >/dev/null
done
cargo xtask fixture-check --profile compat/profiles/jmeter-5.6.3.json \
  --fixtures compat/fixtures/jmeter-5.6.3/harness
git diff --check -- compat/fixtures/jmeter-5.6.3/harness
```

The `xtask` invocation is profile-wide: when pointed at this single family it
also reports missing sibling fixture families (and any pre-existing profile
catalog diagnostics). The directory-scoped JSON checks above are the syntax
portion of the harness acceptance checks; the schema and SHA-256 references
are checked by the deterministic fixture validation lane. These commands
validate syntax, containment, and SHA-256 references only. A
successful static check does not verify an artifact signature or promote any
profile feature. A later release lane must acquire the exact archive, pass both
artifact gates, run the declared adapter in an isolated environment, retain
bounded raw artifacts outside Git, and then write an evidence document with the
observed jmeter-rs source commit, Cargo.lock/toolchain hashes, and runtime
metadata.
