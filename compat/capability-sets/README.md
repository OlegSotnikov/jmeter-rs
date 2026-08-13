# Capability-set projections

This directory contains machine-readable projections of the active
compatibility profile. A projection is a deterministic, fail-closed inventory
for one product capability set; it is not a second JMeter profile and it does
not change the parent profile's feature status or evidence contract.

[`standalone-native.json`](standalone-native.json) is the Decision 0009
projection for the one-artifact Rust product. It is pinned to
`compat/profiles/jmeter-5.6.3.json` by path, schema identity, profile identity,
profile version, and SHA-256. It also repeats the pinned JMeter 5.6.3 source
commit and oracle artifact SHA-512 so a consumer can reject a mismatched
projection before using it. The checked-in JSON is suitable for an
`include_bytes!` consumer; no build script or runtime discovery is implied.

## Projection semantics

The parent profile remains authoritative for all 52 feature rows, required
fixtures, normalization policies, external boundaries, and status vocabulary.
The projection repeats each parent row in the same order and points to one or
more deterministic case records. A case is assigned exactly one partition:

- `native`: a bounded Rust implementation boundary is present in the current
  tree. This is an implementation inventory only; it is deliberately marked
  `not-promoted` and is not a JMeter compatibility claim.
- `optional-pack`: exact Java/JVM/plugin/RMI/provider behavior requires an
  explicitly selected, identity-checked compatibility pack. It is not
  provisioned or selected implicitly by this file.
- `unavailable`: the current standalone product rejects or defers the case.
  Whole-plan admission must fail before setup or observable side effects; a
  native prefix must not run before an unavailable case is discovered.

Partitioning is intentionally finer than a profile row. For example, JMX
opaque preservation can be a native case while plugin execution in the same
row remains optional-pack; an HTTP policy contract can be a native library
boundary while JMX HTTP sampler execution remains unavailable until wired.
No partition promotes a parent row. The JSON's `claim_status` values and
`counts.promoted_parent_rows`/`verified_parent_rows` are explicit guards.

GUI-001..003 remain in the parent profile. GUI-authored JMX preservation is a
headless native case where named, while Swing/Preferences/editor/runtime
behavior is `unavailable` with `gui_runtime: deferred`; the future exact path
is named `compat.jvm.gui@1`. Deferral does not remove GUI rows or count them
as implemented.

The `capabilities` array is a path-level inventory. Native paths use the
Decision 0009 `native.<versioned-capability>` naming family; optional JVM and
RMI paths use `compat.jvm.<versioned-capability>` and
`compat.rmi.<versioned-capability>`; unavailable paths use
`unavailable.<stable-reason>`. Capability records do not assert that a path is
currently admitted or evidence-backed. `runtime_selectable` is therefore
false for deferred, optional, unavailable, and evidence-only records.

Every case points to parent evidence through `evidence_refs`. Native cases
require pinned-oracle comparison, deterministic Rust evidence, and isolated
no-Java/no-helper evidence as applicable. Optional-pack cases require signed
artifact, helper, JVM, classpath/provider identity, bridge-limit, crash,
cancellation, and differential evidence. Unavailable cases require stable
error, source-location, no-side-effect, and lossless-preservation checks.

## Validation

Run these checks from the repository root. They validate syntax, parent
identity, exact 52-row coverage/order, case and capability references,
partition vocabulary, deterministic ordering, explicit no-promotion guards,
and the informational counts. They do not establish conformance.

```sh
python3 -m json.tool compat/capability-sets/standalone-native.json >/dev/null
python3 - <<'PY'
import hashlib
import json
from pathlib import Path

parent_path = Path("compat/profiles/jmeter-5.6.3.json")
projection_path = Path("compat/capability-sets/standalone-native.json")
parent_bytes = parent_path.read_bytes()
parent = json.loads(parent_bytes)
projection = json.loads(projection_path.read_text(encoding="utf-8"))

assert projection["schema_id"] == "jmeter-rs.capability-set-projection"
assert projection["schema_version"] == 1
assert projection["capability_set_id"] == "standalone-native"
assert projection["projection_kind"] == "profile-projection"
parent_ref = projection["parent_profile"]
assert parent_ref["path"] == str(parent_path)
assert parent_ref["sha256"] == hashlib.sha256(parent_bytes).hexdigest()
assert parent_ref["schema_id"] == parent["schema_id"]
assert parent_ref["schema_version"] == parent["schema_version"]
assert parent_ref["profile_id"] == parent["profile_id"] == "jmeter-5.6.3"
assert parent_ref["profile_version"] == parent["profile_version"]
assert parent_ref["profile_date"] == parent["profile_date"]
assert parent_ref["upstream"]["source_commit"] == parent["upstream"]["source_commit"]
assert parent_ref["upstream"]["artifact_sha512"] == parent["upstream"]["artifact"]["digest"]

parent_features = parent["features"]
projection_features = projection["features"]
assert len(parent_features) == len(projection_features) == projection["counts"]["feature_rows"] == 52
assert [row["id"] for row in projection_features] == [row["id"] for row in parent_features]
assert all(row["claim_status"] == "not-promoted" for row in projection_features)
assert projection["counts"]["promoted_parent_rows"] == 0
assert projection["counts"]["verified_parent_rows"] == 0
assert projection["claim_policy"]["row_promotion"] == "forbidden"

partitions = {"native", "optional-pack", "unavailable"}
capabilities = projection["capabilities"]
capability_ids = [item["path_id"] for item in capabilities]
assert capability_ids == sorted(capability_ids)
assert len(capability_ids) == len(set(capability_ids)) == projection["counts"]["capability_records"]
assert all(item["partition"] in partitions for item in capabilities)
capability_by_id = {item["path_id"]: item for item in capabilities}

cases = projection["cases"]
case_ids = [item["case_id"] for item in cases]
assert len(case_ids) == len(set(case_ids)) == projection["counts"]["case_records"]
parent_order = {item["id"]: index for index, item in enumerate(parent_features)}
assert cases == sorted(cases, key=lambda item: (parent_order[item["feature_id"]], item["case_id"]))
assert all(item["partition"] in partitions for item in cases)
assert all(item["claim_status"] == "not-promoted" for item in cases)
assert all(item["capability_id"] in capability_by_id for item in cases)
assert all(item["feature_id"] in parent_order for item in cases)
case_by_id = {item["case_id"]: item for item in cases}

for index, row in enumerate(projection_features):
    assert row["parent_profile_index"] == index
    assert row["parent_status"] == parent_features[index]["status"]
    assert row["case_ids"] == sorted(row["case_ids"])
    assert row["case_ids"]
    assert all(case_by_id[case_id]["feature_id"] == row["id"] for case_id in row["case_ids"])

expected_case_counts = {partition: 0 for partition in partitions}
expected_feature_counts = {partition: 0 for partition in partitions}
for item in cases:
    expected_case_counts[item["partition"]] += 1
for row in projection_features:
    row_partitions = {case_by_id[case_id]["partition"] for case_id in row["case_ids"]}
    for partition in row_partitions:
        expected_feature_counts[partition] += 1
assert projection["counts"]["case_records_by_partition"] == expected_case_counts
assert projection["counts"]["feature_rows_with_partition"] == expected_feature_counts
assert sum(expected_case_counts.values()) == len(cases)
assert all(ref in {item["id"] for item in projection["evidence_requirements"]}
           for item in cases for ref in item["evidence_refs"])
print(f"validated standalone-native projection: {len(parent_features)} rows, {len(cases)} cases, {len(capabilities)} capabilities")
PY
```

These checks intentionally do not compare source-code line counts, successful
parsing, or local unit-test counts with support. The parent profile can only
be promoted by the repository's conformance workflow after the exact named
evidence exists and passes.
