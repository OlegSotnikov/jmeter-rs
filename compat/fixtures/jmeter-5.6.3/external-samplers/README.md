<!-- SPDX-License-Identifier: Apache-2.0 -->

# External sampler corpus

This is an original, bounded, static corpus for
`FX-ELEMENTS-EXTERNAL-001`.  It covers the external portions of `ELEM-001`
(FTP, JDBC, Java, LDAP, and TCP; HTTP is deliberately absent), all sampler
families named by `ELEM-002`, and the deprecated BSF/report/MongoDB aliases in
`ELEM-009`.

| case | compatibility IDs | elements | external boundaries |
|---|---|---|---|
| `elem-001-external` | ELEM-001, TEST-002 | FTP, JDBC, Java, LDAP/LDAP Extended, TCP | EXT-SERVICE-001, EXT-JVM-001 |
| `elem-002-external` | ELEM-002, TEST-002 | JMS publisher/subscriber/point-to-point, mail reader/SMTP, MongoDB, Bolt, JUnit, OS process, access log | EXT-SERVICE-001, EXT-JVM-001, EXT-OS-001 |
| `elem-009-deprecated` | ELEM-009, TEST-002 | BSF sampler/assertion/processor/timer/listener, legacy report aliases, deprecated MongoDB | EXT-JVM-001, EXT-SERVICE-001 |

Every case has an original `plan.jmx`, a property file, a `case.json`
manifest, a `provenance.json` record, and an `expected/semantic.json`
descriptor.  The plans use bounded one-user/one-iteration topology and
placeholder endpoints or classes.  They contain no live service addresses,
credentials, scripts, driver JARs, Java classes, access-log inputs, or other
external artifacts.

The descriptor is an availability contract, not a result file.  Each element
records the required service, driver, JVM class, user class, or OS facility;
the version, license, checksum/provenance, and fixture-adapter fields are
explicitly required but currently absent.  Consequently every case is
`external-unavailable`, has no sample count, and must return a stable
unsupported-capability diagnostic if an execution adapter is not configured.
No sample output, process exit, or successful external result is asserted.

The Apache JMeter 5.6.3 release and SHA-512 in the manifests are profile
provenance only.  No JMeter distribution, Java source/class, driver, plugin,
server, network endpoint, or upstream fixture is redistributed.

The `semantic.json` descriptors are wire inventories, not abbreviated labels:
each node records its exact `testclass`, `guiclass`, disabled state, direct
property names, and nested `Arguments`/`JMSProperties` names.  The JMS entries
deliberately distinguish `PublisherSampler`/`JMSPublisherGui`,
`SubscriberSampler`/`JMSSubscriberGui`, and point-to-point
`JMSSampler`/`JMSSamplerGui`.  The Access Log legacy node records the pinned
upgrade input-to-output mapping, including its GUI conversion, separately.  BSF
nodes use the common TestBean keys; only the pinned `BSFSampler` upgrade table
maps the old `BSFSampler.*` names to those keys.  The report-plan names in ELEM-009
are disabled opaque preservation records because they are absent from the
5.6.3 SaveService alias vocabulary; they are not external capabilities and
have no executable requirement entry.

## Static acceptance

From the repository root, this check parses and validates only the committed
inputs.  It does not start Java, JMeter, a JVM worker, an external service, a
network client, or a subprocess:

```sh
python3 - <<'PY'
import hashlib
import json
import xml.etree.ElementTree as ET
from pathlib import Path

root = Path("compat/fixtures/jmeter-5.6.3/external-samplers")
required = {"elem-001-external", "elem-002-external", "elem-009-deprecated"}
assert {p.name for p in root.iterdir() if p.is_dir()} == required
for case_dir in sorted(root.iterdir()):
    if not case_dir.is_dir():
        continue
    manifest = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))
    provenance = json.loads((case_dir / "provenance.json").read_text(encoding="utf-8"))
    expected_path = case_dir / manifest["execution"]["expected"]
    expected = json.loads(expected_path.read_text(encoding="utf-8"))
    plan = case_dir / manifest["plan"]["path"]
    props = case_dir / manifest["property_files"][0]["path"]
    assert hashlib.sha256(plan.read_bytes()).hexdigest() == manifest["plan"]["sha256"]
    assert hashlib.sha256(props.read_bytes()).hexdigest() == manifest["property_files"][0]["sha256"]
    assert hashlib.sha256(expected_path.read_bytes()).hexdigest() == manifest["descriptor"]["sha256"]
    assert provenance["inputs"]["plan_sha256"] == manifest["plan"]["sha256"]
    assert provenance["inputs"]["property_sha256"] == manifest["property_files"][0]["sha256"]
    assert expected["case_id"] == manifest["case_id"]
    assert manifest["execution"]["status"] == "external-unavailable"
    assert manifest["execution"]["sample_count"] is None
    assert manifest["execution"]["process_exit"] is None
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
    assert expected["capability_accounting"]["status"] == "external-unavailable"
    assert expected["capability_accounting"]["no_silent_success"] is True
    inventory = expected["elements"] + expected.get("opaque_legacy", [])
    assert expected["topology"].get("planned_sampler_nodes", expected["topology"].get("planned_legacy_nodes")) == len(inventory)
    assert all(item["enabled"] is False for item in inventory)

    def nested_names(element):
        names = []
        for child in element:
            if child.tag not in {"elementProp", "collectionProp"}:
                continue
            for descendant in list(child.iter())[1:]:
                if descendant.get("name") is not None:
                    names.append(descendant.get("name"))
        return names

    seen = set()
    for item in inventory:
        key = (item["tag"], item["testclass"], item["name"])
        matches = [node for node in document.iter(item["tag"])
                   if (node.get("testclass"), node.get("testname")) ==
                   (item["testclass"], item["name"])]
        assert len(matches) == 1, (case_dir.name, key, len(matches))
        node = matches[0]
        assert node.get("guiclass") == item["guiclass"], (key, node.get("guiclass"))
        assert node.get("enabled") == "false", key
        assert [child.get("name") for child in node] == item["property_names"], key
        if "nested_property_names" in item:
            assert nested_names(node) == item["nested_property_names"], (key, nested_names(node))
        seen.add(key)
        if item in expected.get("opaque_legacy", []):
            assert item["executable"] is False
            assert item["status"].startswith("opaque-legacy-")
        if item["name"] == "Access log legacy upgrade input":
            assert item["upgrade_output"] == {
                "guiclass": "TestBeanGUI",
                "AccessLogSampler.log_file": "logFile",
                "HTTPSampler.port": "portString",
                "HTTPSampler.domain": "domain",
                "AccessLogSampler.parser_class_name": "parserClassName",
                "HTTPSampler.image_parser": "imageParsing",
            }
        if item["tag"] == "BSFSampler":
            assert item["upgrade_mapping"] == {
                "old_guiclass": "org.apache.jmeter.protocol.java.control.gui.BSFSamplerGui",
                "canonical_guiclass": "TestBeanGUI",
                "old_properties": {
                    "BSFSampler.filename": "filename",
                    "BSFSampler.language": "scriptLanguage",
                    "BSFSampler.parameters": "parameters",
                    "BSFSampler.query": "script",
                },
            }
    actual = []
    expected_keys = {(item["tag"], item["testclass"]) for item in inventory}
    for node in document.iter():
        if (node.tag, node.get("testclass")) in expected_keys:
            actual.append((node.tag, node.get("testclass"), node.get("testname")))
    assert len(actual) == len(inventory), (case_dir.name, actual)
    for requirement in expected["requirements"]:
        assert requirement["status"] == "external-unavailable"
        assert requirement["version_pin"] == "required-but-not-pinned"
        assert requirement["license"] == "required-but-not-recorded"
        assert requirement["provenance"] == "required-but-not-recorded"
        assert requirement["artifact_sha256"] == "required-but-not-recorded"
        assert requirement["fixture_source_revision"] == "required-but-not-recorded"
print("external-samplers static XML/JSON/hash/topology checks passed")
PY
```

The check intentionally does not promote any profile row.  A future adapter
run must pin the exact service/driver/JVM/OS version, license, image or
artifact digest, fixture source revision, credentials policy, and raw
diagnostic artifacts before adding conformance evidence.
