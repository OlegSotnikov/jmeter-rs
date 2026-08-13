<!-- SPDX-License-Identifier: Apache-2.0 -->

# JMX topology corpus

This family owns lossless JMX syntax and ordered topology. The original
`plan.jmx` case covers root metadata, typed properties, and the ordinary
alternating `hashTree` shape. `no-drop-boundaries/` is a bounded static-only
case for the JMX-facing part of the external surfaces:

- disabled unknown plugin elements and a plugin function expression;
- disabled legacy BSF, report-plan, and MongoDB aliases;
- GUI-shaped attributes and a recorder-shaped HTTPS sampler/header tree;
- duplicate-looking siblings, duplicate header values, unknown tags,
  comments, CDATA, object metadata, and raw subtree hashes.

It covers `JMX-004`, `ELEM-009`, `GUI-001`, `PROXY-002`, `PLUG-002`, and
`PLUG-003` only at the persistence/topology boundary. Plugin discovery,
script engines, GUI display, browser recording, CONNECT/TLS, external
services, and execution remain owned by their respective fixture families.
Every external or legacy node is disabled; execution fields are null and no
Java, JMeter, process, network, browser, or TLS tool is invoked.

The expectation uses the `jmx-semantic-static` comparator route. The generic
JTL comparator must reject this format. Raw hashes are diagnostic anchors for
future semantic comparison and do not constitute oracle evidence.

Static checks from the repository root:

```sh
python3 -m json.tool compat/fixtures/jmeter-5.6.3/jmx-topology/no-drop-boundaries/case.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/jmx-topology/no-drop-boundaries/provenance.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/jmx-topology/no-drop-boundaries/expected/semantic.json >/dev/null
python3 - <<'PY'
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

root = Path("compat/fixtures/jmeter-5.6.3/jmx-topology/no-drop-boundaries")
case = json.loads((root / "case.json").read_text(encoding="utf-8"))
expected = json.loads((root / "expected/semantic.json").read_text(encoding="utf-8"))
assert hashlib.sha256((root / "plan.jmx").read_bytes()).hexdigest() == case["plan"]["sha256"]
assert hashlib.sha256((root / "oracle.properties").read_bytes()).hexdigest() == case["property_files"][0]["sha256"]
assert hashlib.sha256((root / "expected/semantic.json").read_bytes()).hexdigest() == case["descriptor"]["sha256"]
assert case["execution"]["process_exit"] is None
assert case["execution"]["sample_count"] is None
assert expected["comparator_contract"]["comparator_route"] == "jmx-semantic-static"

document = ET.parse(root / "plan.jmx").getroot()
assert document.tag == "jmeterTestPlan"

def check_pairs(tree):
    children = list(tree)
    assert len(children) % 2 == 0
    for element, companion in zip(children[::2], children[1::2]):
        assert companion.tag == "hashTree"
        check_pairs(companion)

check_pairs(document.find("hashTree"))
source = (root / "plan.jmx").read_bytes()
for payload in expected["opaque_payloads"]:
    tag = payload["wire_tag"].encode()
    spans = re.findall(rb"<" + tag + rb"\b.*?</" + tag + rb">", source, re.S)
    assert any(hashlib.sha256(span).hexdigest() == payload["raw_xml_sha256"] for span in spans)
print("JMX no-drop static topology/hash checks passed")
PY
```
