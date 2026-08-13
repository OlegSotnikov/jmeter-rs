<!-- SPDX-License-Identifier: Apache-2.0 -->

# Random and time function oracle descriptors

This is an original, offline JMX fixture for `FUNC-001` and `FUNC-002` in the
Apache JMeter 5.6.3 profile.  It exercises the random/date/time functions that
can be checked without a service or a data file:

* `__Random`, `__RandomDate`, `__RandomFromMultipleVars`, `__RandomString`,
  and `__UUID`;
* `__counter`, including per-thread and global state;
* `__dateTimeConvert`, `__timeShift`, and the current-time forms of `__time`;
* thread/group scope and case-sensitive/undefined expansion.

The plan is bounded to two threads, two iterations per thread, and three local
Debug Samplers per iteration.  The first sampler produces named variables and
the following `side-effects` sampler consumes those variables in the same
virtual user, making variable leakage observable in a later label and
DebugSampler variable projection.  All fixed date and shift inputs are controlled
by the plan.  JMeter 5.6.3 obtains random values from `ThreadLocalRandom` and
does not expose a fixture seed setter; `__UUID` delegates to
`java.util.UUID.randomUUID()`, so the manifest records
`random_seed: null`; exact values are asserted only for degenerate domains,
while the expectation records inclusive ranges, allowed values, or UUID
shape for the remaining calls.  Current-time calls are explicitly covered by
`NORM-TIME-001` as shape/range descriptors and are never compared as literal
timestamps.  The process locale is the active profile's `en-US`; the explicit
date-function locale in the plan remains `en_US`.

The plan also contains static expansion-phase probes: a Test Plan variable,
a Thread Group `Arguments` configuration element, and sampler-runtime fields.
Preprocessor/postprocessor/listener expansion is deliberately marked as a
future gap rather than silently treated as covered.  The corresponding phase
and side-effect contracts remain `planned` and `comparator_enforced: false`.

The JTL descriptor uses `NORM-JTL-001` for XML structure and exact stable
attributes.  Byte and sent-byte counters are disabled in `oracle.properties`
instead of being discarded by normalization.  Timing fields and current-time
label components are the only normalized fields.  Random, scope, and event
ordering rules, later-consumed variable projections, and expansion phases live
under explicit planned contract schemas and are marked not comparator-enforced
until a validator supports those schemas.

The manifest requires a future runner to materialize the exact
`<jmeter-home>/bin/jmeter` and `<java-home>/bin/java` placeholders from a
profile-pinned runner manifest, launch with `-Duser.timezone=UTC -Dfile.encoding=UTF-8`,
and record the effective JVM timezone, locale, file encoding, and default
charset.  `TZ` and launcher locale requests are not treated as observations.

Exploratory probe plans were removed from this directory; only the materialized
files listed below constitute the corpus.

No JMeter process or oracle run is part of this handoff.  `case.json` and
`provenance.json` pin the exact 5.6.3 artifact for a later differential run;
the expectation is deliberately a conservative static contract rather than
fabricated sample output.  The profile digest declaration and a future case-run
artifact verification are separate provenance states; neither is asserted by
this static corpus.

## Static acceptance (no oracle)

From the repository root, the fixture-local checks are:

```sh
python3 -m json.tool compat/fixtures/jmeter-5.6.3/functions-random-time/case.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/functions-random-time/expected/semantic.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/functions-random-time/provenance.json >/dev/null
python3 - <<'PY'
import hashlib, json, xml.etree.ElementTree as ET
from pathlib import Path

root = Path("compat/fixtures/jmeter-5.6.3/functions-random-time")
case = json.loads((root / "case.json").read_text())
expected = json.loads((root / "expected/semantic.json").read_text())
provenance = json.loads((root / "provenance.json").read_text())
plan = ET.parse(root / "plan.jmx").getroot()
assert plan.attrib == {"version": "1.2", "properties": "5.0", "jmeter": "5.6.3"}
assert len(list(plan.iter("DebugSampler"))) == 3
assert case["command"]["argv_template"][0] == "<jmeter-home>/bin/jmeter"
assert "-Duser.timezone=UTC" in case["command"]["argv_template"]
assert "-Dfile.encoding=UTF-8" in case["command"]["argv_template"]
assert expected["sample_count"] == case["bounds"]["max_samples"] == 12
assert expected["side_effect_probe_contract"]["comparator_enforced"] is False
assert expected["expansion_phase_contract"]["comparator_enforced"] is False
assert provenance["oracle"]["case_run_verification"]["oracle_invoked"] is False
assert case["plan"]["sha256"] == hashlib.sha256((root / "plan.jmx").read_bytes()).hexdigest()
assert case["property_files"][0]["sha256"] == hashlib.sha256((root / "oracle.properties").read_bytes()).hexdigest()
assert case["execution"]["expected"]["sha256"] == hashlib.sha256((root / "expected/semantic.json").read_bytes()).hexdigest()
assert provenance["inputs"]["plan_sha256"] == case["plan"]["sha256"]
assert provenance["inputs"]["property_sha256"] == case["property_files"][0]["sha256"]
assert provenance["inputs"]["expected_sha256"] == case["execution"]["expected"]["sha256"]
print("functions-random-time static checks passed; no oracle executed")
PY
```

The repository `xtask fixture-check` remains a separate gate.  It validates
the complete workspace when its source is buildable; it is not JMeter evidence
and must not promote planned profile rows by itself.
