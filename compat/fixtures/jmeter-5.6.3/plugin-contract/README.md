<!-- SPDX-License-Identifier: Apache-2.0 -->

# Plugin contract corpus

This is an original, bounded, static corpus for `FX-PLUGIN-001`.  It records
the wire and capability contracts needed before a Java plugin adapter can be
run; it is not a plugin distribution and it is not runtime evidence.  No
Java, JMeter, JVM worker, plugin JAR, class file, subprocess, network service,
or network client is present or started by these cases.

| case | compatibility IDs | static coverage |
|---|---|---|
| `discovery-ordering` | PLUG-001 | explicit component/dependency roots, deterministic classpath order, duplicate alias policy, missing-artifact diagnostics, and bounded discovery descriptors |
| `element-function-alias` | PLUG-002, JMX-004 | disabled plugin elements, plugin function text, primary/historical JMX aliases, insertion order, duplicate-looking nodes, unknown properties, and opaque nested payloads |
| `unavailable-subtree` | PLUG-003, JMX-004, SCRIPT-002 | disabled Java Sampler/JUnit and plugin nodes with missing classes, typed unavailable diagnostics, duplicate ordered descendants, exact unknown attributes/properties, and raw subtree no-drop hashes |

The existing `jmx-aliases/unknown-plugin` case remains the broader JMX
regression corpus.  These three cases add the plugin-family coverage that it
does not provide: discovery/classpath ordering and explicit Java Sampler/JUnit
class-loading descriptors.  All plugin and user classes are intentionally
absent placeholders (`com.example...`); no artifact or fabricated result is
checked in.

Every case has an original `plan.jmx` with all executable plugin/JVM nodes
disabled, a static-only property file, an input descriptor where needed, a
case manifest, provenance, and an explicit `format: "jmx-semantic"`
expectation.  The expectation is declarative and
uses `evidence_status: "external-unavailable"`; it must never be routed as a
JTL result or interpreted as an observed JMeter run.  `process_exit`, sample
counts, Java version, target triple, and classpath measurement are null because
no runtime was invoked.  The pinned Apache SHA-512 appears only as profile
provenance and is not a checked-in distribution.

The per-case bounds are deliberately small: one disabled thread group, at
most five disabled sampler nodes (at most four plugin/JVM nodes plus one known
disabled `DebugSampler` sibling), one iteration, zero samples, no network
requests, no processes, and at most 12 KiB of authored property text.  Unknown
nodes and duplicate-looking siblings remain ordered; they are not deduplicated
by name or class.

## Static acceptance

From the repository root, these checks parse only JSON/XML and compare the
declared SHA-256 values.  They do not run an oracle or any process:

```sh
python3 -m json.tool compat/fixtures/jmeter-5.6.3/plugin-contract/discovery-ordering/case.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/plugin-contract/element-function-alias/case.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/plugin-contract/unavailable-subtree/case.json >/dev/null
python3 - <<'PY'
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

root = Path("compat/fixtures/jmeter-5.6.3/plugin-contract")
required = {"discovery-ordering", "element-function-alias", "unavailable-subtree"}
assert {p.name for p in root.iterdir() if p.is_dir()} == required

def check_pairs(tree):
    children = list(tree)
    assert len(children) % 2 == 0, tree.tag
    for element, companion in zip(children[::2], children[1::2]):
        assert companion.tag == "hashTree", element.tag
        check_pairs(companion)

for case_dir in sorted(root.iterdir()):
    if not case_dir.is_dir():
        continue
    case = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))
    provenance = json.loads((case_dir / "provenance.json").read_text(encoding="utf-8"))
    expected_path = case_dir / case["execution"]["expected"]
    expected = json.loads(expected_path.read_text(encoding="utf-8"))
    plan_path = case_dir / case["plan"]["path"]
    props_path = case_dir / case["property_files"][0]["path"]
    assert hashlib.sha256(plan_path.read_bytes()).hexdigest() == case["plan"]["sha256"]
    assert hashlib.sha256(props_path.read_bytes()).hexdigest() == case["property_files"][0]["sha256"]
    assert hashlib.sha256(expected_path.read_bytes()).hexdigest() == case["descriptor"]["sha256"]
    assert provenance["inputs"]["plan_sha256"] == case["plan"]["sha256"]
    assert provenance["inputs"]["property_sha256"] == case["property_files"][0]["sha256"]
    assert expected["case_id"] == case["case_id"]
    assert expected["format"] == "jmx-semantic"
    assert expected["evidence_status"] == "external-unavailable"
    assert case["execution"]["process_exit"] is None
    assert case["execution"]["sample_count"] is None
    assert provenance["runtime"]["java"]["major"] is None
    assert provenance["runtime"]["target_triple"] is None
    assert provenance["runtime"]["jmeter_classpath"] is None
    assert provenance["runtime"]["plugin_artifacts"] == []
    document = ET.parse(plan_path).getroot()
    assert document.tag == "jmeterTestPlan"
    wrapper = document.find("hashTree")
    assert wrapper is not None
    check_pairs(wrapper)
    assert all(node.get("enabled") == "false"
               for node in document.iter()
               if node.get("testclass") in {
                   "com.example.plugin.OrderedSampler",
                   "com.example.plugin.AliasSampler",
                   "com.example.plugin.OpaqueSampler",
                   "JavaSampler",
                   "JUnitSampler",
               })

unavailable = json.loads((root / "unavailable-subtree/expected/semantic.json").read_text())
assert unavailable["capability_accounting"]["no_silent_success"] is True
assert unavailable["capability_accounting"]["stable_error_codes"] == [
    "plugin.class.unavailable", "script.class.unavailable"
]
source = (root / "unavailable-subtree/plan.jmx").read_bytes()
for tag, digest in unavailable["opaque_subtree_sha256"].items():
    match = re.search(rb"<" + tag.encode() + rb"\b.*?</" + tag.encode() + rb">", source, re.S)
    assert match is not None, tag
    assert hashlib.sha256(match.group()).hexdigest() == digest, tag
print("plugin-contract static JSON/XML/hash/topology checks passed")
PY

cargo run -p xtask -- fixture-check --profile compat/profiles/jmeter-5.6.3.json
```

The final command checks repository references and bounds; neither command
promotes a profile feature.  A future adapter run must pin each plugin/JVM
artifact, license, classpath checksum, loader version, and raw diagnostic
artifact before any external result is added.
