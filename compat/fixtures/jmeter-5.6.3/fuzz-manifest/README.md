<!-- SPDX-License-Identifier: Apache-2.0 -->

# FX-FUZZ-001 static campaign manifest

This directory is the planned `FX-FUZZ-001` fixture for `TEST-003` in the
Apache JMeter 5.6.3 profile. It is an index, not a second fuzz workspace: the
target source and seed bytes remain under `fuzz/`, and `case.json` records
repository-relative paths plus SHA-256 values for every referenced target,
seed, workspace file, campaign contract, and provenance document.

The current source of truth is:

| reference | role |
| --- | --- |
| `fuzz/Cargo.toml` and `fuzz/Cargo.lock` | standalone cargo-fuzz workspace and pinned `libfuzzer-sys = 0.4.13` |
| `fuzz/Cargo.toml` `[[bin]]` entries and `fuzz/fuzz_targets/*.rs` | ten bounded parser/boundary targets and 29 source-declared invariant IDs |
| `fuzz/corpus/*` | 34 original synthetic seed inputs |
| `fuzz/README.md` | target bounds and static fuzzing policy |
| `fuzz/campaign/*` | repository campaign contract and its planned example |
| `fuzz/corpus/PROVENANCE.md` | seed origin, purpose, license, and per-input bounds |

The canonical `fuzz/campaign/evidence.schema.json` remains the owner-facing
campaign descriptor, but is intentionally weaker: it permits a generic target
selection, a partial invariant list, an unexpanded corpus manifest, and
unresolved artifact paths. The fixture-local
`expected/campaign-evidence.schema.json` is the strict review contract for this
case. It freezes all ten target source hashes/bounds, the exact 29
source-declared invariant IDs and target mapping, the exact 34 path/hash/size
seed set and per-target aggregates, and the planned-state transitions. The two
schemas are both indexed by `case.json`; neither is silently treated as the
other. The canonical README/schema remain weaker and are indexed as
provenance; the local manifest is the current Cargo target inventory without
editing `fuzz/**`.

The source comments also name `JTL-XML-WIRE-PROBE-001` and `PLUG-003` as
sub-probes or preservation-contract identifiers. They remain visible in the
owned source and its hash, but are not top-level TEST-003 invariant IDs; the
fixture therefore records the exact 29 campaign invariants requested by the
current target inventory and does not silently promote those subordinate IDs.

The fixture is explicitly `planned; not-run`. No fuzz campaign, nightly
toolchain, Cargo command, Java/JMeter process, shell, or subprocess was used
to create it. The profile row stays `planned`; source hashes are integrity
references, not compatibility evidence.

## Future bounded evidence

`expected/campaign-evidence.schema.json` is a formal JSON Schema for a future
per-target campaign record. `expected/campaign-evidence.example.json` validates
against that schema while explicitly declaring `planned`, `not_run: true`,
zero outcome counts, no artifacts, and `not-run` runner/timestamp metadata. A
real run record must identify the exact source revision, nightly toolchain,
cargo-fuzz/libFuzzer versions, non-shell argv, limits, seed settings, and UTC
timestamps. It must report accepted inputs, bounded rejects, crashes,
hangs/timeouts, sanitizer findings, and resource-limit failures for all ten
targets and all 29 invariant IDs. The four newly indexed target corpus
directories are absent by design and therefore have explicit zero seed and
zero byte aggregates; absence is not fabricated campaign evidence.

The declared preservation/projection checks cover source-byte and semantic JMX
preservation, configured JTL CSV/XML projections, bridge frame round trips,
and bounded parser behavior. `CONFIG-UNKNOWN-IGNORED-001` is intentionally
different: the current property API ignores unrelated keys and compares the
mixed stream with its recognized-only projection. It is not a no-drop claim.
The campaign safety contract also requires no panic/undefined behavior,
unbounded allocation, infinite loop, hang, network access, script execution,
Java loading, or child process within the limits.

Crash, hang, timeout, sanitizer, OOM, resource-limit, minimized-input, and
regression records must follow the schema's artifact definition: bounded
relative paths and byte lengths, lowercase SHA-256, target/profile/campaign
identity, reproducer source and exact tool versions/flags, limits, diagnostic
classification, and retention reason. Every `artifact_ids` entry names a
unique definition whose path, kind, hash, size, campaign, target, and
toolchain are held in the top-level `artifacts` array. Definitions must have
unique IDs and unique paths, every definition must be referenced exactly once
across the invariant/target/outcome joins, and every reference must resolve to
one definition. The array is capped at 64 entries of at most 1 MiB each (a 64
MiB aggregate ceiling). A static link check rejects duplicate definition IDs,
duplicate paths, unlinked or unknown IDs, or any reference whose
hash/size/kind/path/campaign/toolchain does not equal its definition. Raw campaign output belongs only under the ignored
`oracle-runs/fuzz-manifest/<campaign>/<target>/` directory. A minimized input
is not added to `fuzz/corpus/` or this fixture without a new provenance record.

`expected/campaign-evidence.negative.json` contains adversarial mutation
recipes for the planned example, independent count/meta-validation vectors, and
artifact-link vectors. The static check must reject every recipe. The link
vectors cover unresolved IDs, duplicate definition IDs, duplicate paths,
unlinked definitions, hash mismatch, campaign/toolchain mismatch, and the
aggregate artifact ceiling. The count vectors cover
`accepted_inputs + rejected_inputs <= executions`. These are required joins,
not optional documentation: standard Draft 2020-12 JSON Schema cannot compare
arbitrary values across two arrays or express arithmetic over object fields, so
the repository static/xtask validator must run alongside Draft validation before
campaign evidence is accepted. The schema's `x-static-meta-validation` keyword
records that requirement for tooling that can surface extension metadata.

## Static validation

These checks only parse JSON, validate the planned example against the formal
schema, and compare declared source hashes. They do not invoke Cargo,
fuzzing, Java, JMeter, a shell, or a subprocess:

```sh
python3 -m json.tool compat/fixtures/jmeter-5.6.3/fuzz-manifest/case.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/fuzz-manifest/provenance.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/fuzz-manifest/expected/campaign-evidence.schema.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/fuzz-manifest/expected/campaign-evidence.example.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/fuzz-manifest/expected/campaign-evidence.negative.json >/dev/null
python3 - <<'PY'
import copy
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from jsonschema import Draft202012Validator

root = Path.cwd()
case_dir = root / "compat/fixtures/jmeter-5.6.3/fuzz-manifest"
def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        assert key not in result, key
        result[key] = value
    return result

def load_unique(path):
    return json.loads(path.read_text(), object_pairs_hook=reject_duplicate_keys)

case = load_unique(case_dir / "case.json")
schema_path = case_dir / "expected/campaign-evidence.schema.json"
example_path = case_dir / "expected/campaign-evidence.example.json"
negative_path = case_dir / "expected/campaign-evidence.negative.json"
schema = load_unique(schema_path)
planned = load_unique(example_path)
negative = load_unique(negative_path)
assert case["execution"]["status"] == "planned; not-run"
assert case["fixture_family_id"] == "FX-FUZZ-001"
assert case["conformance_ids"] == ["TEST-003"]
Draft202012Validator.check_schema(schema)
Draft202012Validator(schema).validate(planned)
invalid = json.loads(example_path.read_text())
invalid["invariants"][0]["status"] = "observed"
assert list(Draft202012Validator(schema).iter_errors(invalid)), "not-run record accepted observed invariant"
assert planned["status"] == "planned"
assert planned["not_run"] is True
assert planned["outcome"]["status"] == "not_run"
assert planned["outcome"]["counts"]["executions"] == 0
assert planned["artifacts"] == []
assert all(target["status"] == "not_run" and target["seed"] is None and target["flags"] == [] and target["artifact_ids"] == [] and target["counts"]["executions"] == 0 for target in planned["target_outcomes"])

def pointer(document, pointer_value):
    parts = pointer_value.lstrip("/").split("/") if pointer_value else []
    current = document
    for part in parts[:-1]:
        part = part.replace("~1", "/").replace("~0", "~")
        current = current[int(part)] if isinstance(current, list) else current[part]
    if not parts:
        return None, None
    part = parts[-1].replace("~1", "/").replace("~0", "~")
    return current, int(part) if isinstance(current, list) else part

for vector in negative["negative_test_vectors"]:
    mutated = copy.deepcopy(planned)
    for operation in vector["operations"]:
        if operation["op"] == "set":
            parent, key = pointer(mutated, operation["path"])
            parent[key] = copy.deepcopy(operation["value"])
        elif operation["op"] == "copy":
            source, source_key = pointer(mutated, operation["from"])
            parent, key = pointer(mutated, operation["path"])
            parent[key] = copy.deepcopy(source[source_key])
        else:
            raise AssertionError(operation["op"])
    assert list(Draft202012Validator(schema).iter_errors(mutated)), vector["id"]

def artifact_links_are_valid(vector):
    definitions = vector["definitions"]
    identifiers = [item["artifact_id"] for item in definitions]
    paths = [item["path"] for item in definitions]
    if len(definitions) > 64 or len(identifiers) != len(set(identifiers)) or len(paths) != len(set(paths)):
        return False
    if vector.get("declared_definition_count", len(definitions)) > 64:
        return False
    if vector.get("declared_total_size_bytes", sum(item["size_bytes"] for item in definitions)) > 67108864:
        return False
    by_id = {item["artifact_id"]: item for item in definitions}
    fields = ("campaign_id", "target", "kind", "path", "sha256", "size_bytes", "toolchain")
    references = vector["references"]
    reference_ids = [reference["artifact_id"] for reference in references]
    if len(reference_ids) != len(set(reference_ids)) or set(reference_ids) != set(by_id):
        return False
    return all(reference["artifact_id"] in by_id and all(reference[field] == by_id[reference["artifact_id"]][field] for field in fields) for reference in references)

for vector in negative["artifact_link_vectors"]:
    assert not artifact_links_are_valid(vector), vector["id"]

def validate_artifact_record(record):
    definitions = record["artifacts"]
    by_id = {item["artifact_id"]: item for item in definitions}
    assert len(definitions) <= 64
    configuration = record["campaign"]["configuration"]
    assert len(by_id) == len(definitions)
    assert sum(item["size_bytes"] for item in definitions) <= configuration["max_total_artifact_bytes"]
    assert all(item["size_bytes"] <= configuration["max_single_artifact_bytes"] for item in definitions)
    paths = [item["path"] for item in definitions]
    assert len(paths) == len(set(paths))
    for artifact_id, item in by_id.items():
        assert artifact_id == item["artifact_id"]
        assert item["campaign_id"] == record["campaign"]["campaign_id"]
        assert item["toolchain"]["rust"] == record["runner"]["toolchain"]
        assert item["toolchain"]["cargo_fuzz"] == record["runner"]["cargo_fuzz"]
        assert item["toolchain"]["libfuzzer_sys"] == record["runner"]["libfuzzer_sys"]
        assert item["toolchain"]["flags"] == record["runner"]["flags"]
    references = []
    for invariant in record["invariants"]:
        references.extend((artifact_id, invariant["target"]) for artifact_id in invariant["evidence"]["artifact_ids"])
    for outcome in record["target_outcomes"]:
        references.extend((artifact_id, outcome["target"]) for artifact_id in outcome["artifact_ids"])
    references.extend((artifact_id, None) for artifact_id in record["outcome"]["artifacts"])
    references.extend((artifact_id, None) for artifact_id in record["outcome"]["minimization"]["artifact_ids"])
    reference_ids = [artifact_id for artifact_id, _ in references]
    assert len(reference_ids) == len(set(reference_ids))
    assert set(reference_ids) == set(by_id)
    for artifact_id, target in references:
        assert artifact_id in by_id
        if target is not None:
            assert by_id[artifact_id]["target"] == target

def validate_counts(counts, execution_limit):
    assert counts["executions"] <= execution_limit
    assert counts["accepted_inputs"] + counts["rejected_inputs"] <= counts["executions"]

for target in planned["target_outcomes"]:
    validate_counts(target["counts"], planned["campaign"]["configuration"]["runs_per_target"])
validate_counts(planned["outcome"]["counts"], planned["campaign"]["configuration"]["runs_per_target"] * len(planned["targets"]))
for vector in negative["meta_validation_vectors"]:
    try:
        validate_counts(vector["counts"], planned["campaign"]["configuration"]["runs_per_target"] * len(planned["targets"]))
    except AssertionError:
        pass
    else:
        raise AssertionError(vector["id"])

validate_artifact_record(planned)

for vector in negative["artifact_record_mutation_vectors"]:
    mutated = copy.deepcopy(planned)
    for operation in vector["operations"]:
        parent, key = pointer(mutated, operation["path"])
        parent[key] = copy.deepcopy(operation["value"])
    try:
        validate_artifact_record(mutated)
    except AssertionError:
        pass
    else:
        raise AssertionError(vector["id"])

for section in ("workspace", "documentation", "campaign_contracts", "fixture_contracts", "targets", "corpus"):
    for ref in case["source_references"][section]:
        path = root / ref["path"]
        assert path.is_file(), ref["path"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == ref["sha256"], ref["path"]
for ref in case["inputs"] + case["expected"]:
    path = case_dir / ref["path"]
    assert path.is_file(), ref["path"]
    assert hashlib.sha256(path.read_bytes()).hexdigest() == ref["sha256"], ref["path"]
provenance = load_unique(case_dir / "provenance.json")
fixture_hashes = {ref["path"]: ref["sha256"] for ref in case["source_references"]["fixture_contracts"]}
for ref in provenance["source_references"]["fixture_contract"].items():
    if ref[0].endswith("_path"):
        assert ref[1] in fixture_hashes
    elif ref[0].endswith("_sha256"):
        matching_path = ref[0].replace("_sha256", "_path")
        assert fixture_hashes[provenance["source_references"]["fixture_contract"][matching_path]] == ref[1]
targets = case["source_references"]["targets"]
corpus = case["source_references"]["corpus"]
assert {target["target"] for target in targets} == {
    "jmx_xml", "jtl_csv", "jtl_xml", "expr", "bridge", "property_config",
    "http_policy", "plugin_json", "remote", "runtime"
}
assert len(targets) == 10
cargo_bins = re.findall(r'(?ms)^\[\[bin\]\]\s*name = "([^"]+)"\s*path = "([^"]+)"', (root / "fuzz/Cargo.toml").read_text())
assert {(name, "fuzz/" + path) for name, path in cargo_bins} == {(target["target"], target["path"]) for target in targets}
target_index = {target["target"]: target for target in targets}
assert {target["target"] for target in planned["targets"]} == set(target_index)
invariant_index = {item["invariant_id"]: item["target"] for item in case["target_invariants"]}
assert len(case["target_invariants"]) == 29
assert len(invariant_index) == 29
assert "NO-DROP-CONFIG-001" not in invariant_index
for target in planned["targets"]:
    source = target_index[target["target"]]
    assert target["source_path"] == source["path"]
    assert target["source_sha256"] == source["sha256"]
    assert target["corpus_directory"] == source["corpus_directory"]
    assert target["bounds"] == source["bounds"]
    assert target["invariant_ids"] == source["invariant_ids"]
    assert target["corpus_seed_count"] == source["corpus_seed_count"]
    assert target["corpus_bytes"] == source["corpus_bytes"]
    assert all(invariant_index[invariant_id] == target["target"] for invariant_id in target["invariant_ids"])
    corpus_directory = root / source["corpus_directory"]
    if source["corpus_seed_count"] == 0 and corpus_directory.exists():
        assert not any(path.is_file() for path in corpus_directory.rglob("*")), target["target"]
    source_ids = set(re.findall(r'`([A-Z][A-Z0-9-]+-\d{3})`', (root / source["path"]).read_text()))
    source_ids -= {"JTL-XML-WIRE-PROBE-001", "PLUG-003"}
    assert source_ids == set(source["invariant_ids"]), target["target"]
assert len(corpus) == 34
for ref in corpus:
    path = root / ref["path"]
    assert path.is_file(), ref["path"]
    assert path.stat().st_size == ref["size_bytes"]
    assert hashlib.sha256(path.read_bytes()).hexdigest() == ref["sha256"], ref["path"]
physical_corpus = {
    path for path in (root / "fuzz/corpus").rglob("*")
    if path.is_file() and path.name != "PROVENANCE.md"
}
assert physical_corpus == {root / ref["path"] for ref in corpus}
assert len(planned["corpus"]["seeds"]) == 34
assert len(planned["invariants"]) == 29
assert {item["invariant_id"] for item in planned["invariants"]} == set(invariant_index)
assert all(invariant_index[item["invariant_id"]] == item["target"] for item in planned["invariants"])
assert len(planned["target_outcomes"]) == 10
assert {item["target"] for item in planned["target_outcomes"]} == set(target_index)
assert all(item["invariant_ids"] == target_index[item["target"]]["invariant_ids"] for item in planned["target_outcomes"])
source_seeds = {(seed["target"], seed["path"]): seed for seed in corpus}
assert len(source_seeds) == 34
assert {(seed["target"], seed["path"]) for seed in planned["corpus"]["seeds"]} == set(source_seeds)
provenance_ref = next(ref for ref in case["source_references"]["documentation"] if ref["path"] == "fuzz/corpus/PROVENANCE.md")
assert planned["corpus"]["provenance_path"] == provenance_ref["path"]
assert planned["corpus"]["provenance_sha256"] == provenance_ref["sha256"]
for seed in planned["corpus"]["seeds"]:
    source = source_seeds[(seed["target"], seed["path"])]
    assert seed["sha256"] == source["sha256"]
    assert seed["size_bytes"] == source["size_bytes"]
target_counts = Counter(seed["target"] for seed in corpus)
target_bytes = Counter()
for seed in corpus:
    target_bytes[seed["target"]] += seed["size_bytes"]
for target in planned["targets"]:
    assert target["corpus_seed_count"] == target_counts[target["target"]]
    assert target["corpus_bytes"] == target_bytes[target["target"]]
assert planned["corpus"]["provenance_sha256"] == provenance_ref["sha256"]
print("FX-FUZZ-001 static JSON/path/hash/schema checks passed")
PY
```
