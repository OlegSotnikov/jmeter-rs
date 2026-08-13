<!-- SPDX-License-Identifier: Apache-2.0 -->

# JMX alias and extension corpus

This directory is an original, deterministic static corpus for the pinned
JMeter 5.6.3 JMX contract. It covers JMX-001 through JMX-004 without claiming
oracle conformance: no Java, Apache JMeter, JVM, plugin, or subprocess was
executed while creating these files. The profile rows remain `planned` or
`external` until the required pinned differential runs exist.

| case | IDs | static coverage |
|---|---|---|
| `aliases` | JMX-001, JMX-002, JMX-003 | root metadata; alternating `hashTree`; primary and historical SaveService aliases; all structural property node kinds; XML entities/Unicode; ordered collection/map entries; nested/object properties including `<value>` attributes; absent versus explicit empty values; `floatProp` remains a pinned-oracle question |
| `upgrades` | JMX-002, JMX-003 | version-1.0 URL decoding; class/GUI upgrades; JDBC, throughput, access-log, and BSF property renames; twelve omitted source/target upgrade rules enumerated explicitly; deleted properties retain raw diagnostic spans but are omitted from canonical upgraded output |
| `unknown-plugin` | JMX-001, JMX-002, JMX-004 | unknown/plugin class and GUI identities; extra attributes; unknown scalar/nested properties; comments/CDATA; ordered descendants; raw subtree hashes; planned `unsupported-capability` (`plugin.capability.unsupported`) accounting |

Each case has a `case.json`, `provenance.json`, original `plan.jmx`, pinned
`oracle.properties`, and an explicit `expected/semantic.json` descriptor.
The descriptor is semantic unless a region is marked lexical-preserving (the
unknown/plugin case records SHA-256 hashes for those raw XML regions).

The upstream references are the profile-pinned
[`saveservice.properties`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/bin/saveservice.properties)
and
[`upgrade.properties`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/bin/upgrade.properties).
They are cited as behavioral vocabulary only; no upstream plan or source is
copied into this corpus. The artifact SHA-512 and runtime metadata in each
provenance file are inherited from the active compatibility profile.
The aliases descriptor records the SHA-256 and parsed inventory counts for the
repository's pinned 5.6.3 SaveService (293 alias keys, 290 primary classes)
and upgrade (52 rules) tables, so registry drift is detectable without
duplicating those upstream-derived tables in fixture XML.
Raw XML hashes in the descriptors cover the UTF-8 bytes from the opening tag
through its matching closing tag, excluding indentation outside that span.
The `floatProp` structural entries are deliberately marked
`pinned-oracle-question`: the checked-in SaveService vocabulary comments out a
`floatProp` alias while retaining `FloatProperty`, so this corpus does not
claim that the pinned JMeter oracle accepts that wire tag.

## Static acceptance

From the repository root, these checks parse every owned XML/JSON file, verify
the declared input hashes, and confirm that all XML has the expected root and
alternating element/`hashTree` topology. They intentionally do not launch an
oracle or any subprocess:

```sh
python3 - <<'PY'
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

root = Path("compat/fixtures/jmeter-5.6.3/jmx-aliases")
for case in sorted(path for path in root.iterdir() if path.is_dir()):
    manifest = json.loads((case / "case.json").read_text())
    provenance = json.loads((case / "provenance.json").read_text())
    expected = json.loads((case / manifest["execution"]["expected"]).read_text())
    plan = case / manifest["plan"]["path"]
    properties = case / manifest["property_files"][0]["path"]
    assert hashlib.sha256(plan.read_bytes()).hexdigest() == manifest["plan"]["sha256"]
    assert hashlib.sha256(properties.read_bytes()).hexdigest() == manifest["property_files"][0]["sha256"]
    assert provenance["inputs"]["plan_sha256"] == manifest["plan"]["sha256"]
    assert provenance["inputs"]["property_sha256"] == manifest["property_files"][0]["sha256"]
    assert expected["case_id"] == manifest["case_id"]
    document = ET.parse(plan).getroot()
    assert document.tag == "jmeterTestPlan"
    wrapper = document.find("hashTree")
    assert wrapper is not None
    def check_pairs(tree):
        children = list(tree)
        assert len(children) % 2 == 0
        for element, companion in zip(children[::2], children[1::2]):
            assert companion.tag == "hashTree"
            check_pairs(companion)
    check_pairs(wrapper)
    if case.name == "aliases":
        question = expected["pinned_oracle_questions"][0]
        assert question["id"] == "JMX-FLOATPROP-001"
        assert question["status"] == "pinned-oracle-question"
        assert question["accepted_claim"] is False
        assert not any(row.get("input") == "HTTPSampler2_" for row in expected["alias_resolutions"])
        nested = document.find(".//elementProp[@name='fixture.nested']/objProp[@name='nested.object']/value")
        direct = document.find(".//objProp[@name='fixture.object']/value")
        for prop in (nested, direct):
            assert prop is not None and prop.attrib["encoding"] == "utf-8"
    elif case.name == "upgrades":
        omitted = {(row["source"], row["target"]) for row in expected["upgrade_rules_omitted"]}
        assert len(omitted) == 12
        deleted = expected["deleted_property_handling"]
        assert deleted["canonical_output"]["round_trip_preserved"] is False
        assert deleted["canonical_output"]["status"] == "omitted"
        for row in deleted["diagnostic_retention"]:
            assert hashlib.sha256(row["raw_xml"].encode()).hexdigest() == row["raw_xml_sha256"]
    elif case.name == "unknown-plugin":
        accounting = expected["capability_accounting"]
        assert accounting["status"] == "planned"
        assert accounting["unsupported_error_code"] == "unsupported-capability"
        assert accounting["stable_error_code"] == "plugin.capability.unsupported"
        assert accounting["no_silent_success"] is True
        source = plan.read_bytes()
        for tag, digest in (("PluginSampler", "84b73af682f4ee924963ecb9ee86bfcd9ae1ff2648329465bc8f253e76ccb4c5"), ("PluginChild", "6928136b4959f983cd3572df82419b130e22a76e135b87c12fc281f2b08e7510")):
            match = re.search(rb"<" + tag.encode() + rb"\b.*?</" + tag.encode() + rb">", source, re.S)
            assert match is not None
            assert hashlib.sha256(match.group()).hexdigest() == digest
print("jmx-aliases static XML/JSON/hash/topology checks passed")
PY
```

The repository fixture validator may additionally be run with the normal
`xtask fixtures` command when its Rust build is available. That validator is
not a substitute for the pinned Java oracle and is not run by this corpus.
