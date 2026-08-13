# Compatibility profiles

This directory contains machine-readable compatibility declarations for
`jmeter-rs`. The initial profile is pinned to Apache JMeter 5.6.3 and is a
scope and evidence contract, not an implementation claim:

- [jmeter-5.6.3.json](profiles/jmeter-5.6.3.json)

## Pinned upstream

The profile pins the Apache JMeter `rel/v5.6.3` release and source commit
`34a2785748e9e0b14702595e8682c387869deda3`. The oracle artifact is
`apache-jmeter-5.6.3.zip` from the Apache archive:

<https://archive.apache.org/dist/jmeter/binaries/apache-jmeter-5.6.3.zip>

The official SHA-512 sidecar is:

<https://archive.apache.org/dist/jmeter/binaries/apache-jmeter-5.6.3.zip.sha512>

The recorded SHA-512 is:

```text
387fadca903ee0aa30e3f2115fdfedb3898b102e6b9fe7cc3942703094bd2e65b235df2b0c6d0d3248e74c9a7950a36e42625fd74425368342c12e40b0163076
```

The digest was checked on 2026-08-12 by downloading the ZIP and the official
sidecar, then comparing `sha512sum` output. This is digest verification only;
it does not authenticate the signing key. The profile also records Apache's
signature and key URLs. Release automation must verify the PGP signature in
addition to the SHA-512 digest when importing the artifact. Until that check
has been recorded, the artifact is not release provenance evidence.

The baseline requires Java 8 or later, with Java 17 or later recommended by
Apache. Every oracle run must record the exact Java vendor/version, target
triple, OS image, locale, timezone, charset, properties, plugin/engine
artifacts, and dependency hashes.

## Matrix semantics

`features` contains every checklist ID in
`docs/research/compatibility-surface.md` exactly once. The initial 52 entries
are intentionally unverified:

- `planned` (33): in the declared target, but no conformance evidence exists.
- `external` (19): requires a declared JVM, plugin, driver, service, TLS, RMI,
  OS, or other external boundary; no support is implied.
- `verified`: reserved for evidence-backed conformance updates.
- `blocked`: reserved for a reproducible blocker recorded by the project.

Each feature names its required oracle fixture IDs and normalization policy
references. Feature records may also identify external runtime boundaries.
The profile's fixture catalog is a list of required fixture families; an entry
with `materialized: false` is an unmaterialized requirement, not an existing
test, and its catalog status remains `planned` or `external` as declared.
Source-only case directories may exist while a family is being designed, but
their static expectations and command templates are not conformance evidence.

Catalog boundary IDs describe the aggregate external scope of a fixture family.
An individual case lists only the boundaries it directly exercises, so its list
may be a subset; the executed family evidence must cover every catalog boundary
before materialization. Likewise, a case may add normalization policies for
cross-cutting safety or environment invariants beyond its feature rows. Those
extra policies become additional gates and do not replace any feature policy.

The profile locale, timezone, and charset are baseline values. A case may use a
different explicit value when that variation is the behavior under test, but
the runner must materialize and record it rather than inherit the host. Random
seeds are mandatory where JMeter exposes a deterministic seed; an unseedable
surface records `null` and a reason instead of inventing reproducibility.

The profile deliberately does not claim unconditional compatibility with every
JMeter plugin, Java script engine, remote service, OS facility, or arbitrary
JMX plan. A feature can be promoted only after the pinned oracle, declared
adapter versions, fixture provenance, and required tests exist. Update the
feature's `status` and its evidence reference together; do not silently remove
a checklist row. The research table's `inventory_status` is a separate source
marker and remains `TODO` until implementation evidence exists. Profile feature
statuses use lowercase `planned`, `external`, `verified`, and `blocked`.

## Validation

The profile uses JSON only and can be checked with tools available on a normal
Python installation:

```sh
python3 -m json.tool compat/profiles/jmeter-5.6.3.json >/dev/null
```

For a stronger inventory/reference check, run this from the repository root:

```sh
python3 - <<'PY'
import json
import re
from pathlib import Path

source = Path("docs/research/compatibility-surface.md").read_text()
profile = json.loads(Path("compat/profiles/jmeter-5.6.3.json").read_text())
inventory = re.findall(
    r"^\| ((?:CLI|CFG|JMX|JTL|ELEM|FUNC|SCRIPT|REPORT|DIST|PROXY|TLS|PLUG|GUI|TEST)-\d{3}) \|",
    source,
    re.MULTILINE,
)
features = [item["id"] for item in profile["features"]]
assert len(inventory) == len(set(inventory))
assert len(features) == len(set(features))
assert set(inventory) == set(features)
fixture_ids = {item["id"] for item in profile["oracle_fixture_catalog"]}
policy_ids = {item["id"] for item in profile["normalization_policies"]}
boundary_ids = {item["id"] for item in profile["external_runtime_boundaries"]}
assert all(set(item["required_oracle_fixture_ids"]) <= fixture_ids for item in profile["features"])
assert all(set(item["normalization_policy_refs"]) <= policy_ids for item in profile["features"])
assert all(set(item["external_runtime_boundary_ids"]) <= boundary_ids for item in profile["features"])
print(f"validated {len(features)} checklist IDs")
PY
```

The validation commands check syntax, inventory completeness, uniqueness, and
cross-references. They do not establish implementation conformance; that
requires the differential, golden, integration, external-adapter, fuzz, and
cross-platform evidence named by the profile and research strategy.
