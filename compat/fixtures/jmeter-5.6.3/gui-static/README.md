<!-- SPDX-License-Identifier: Apache-2.0 -->

# GUI persistence static corpus

This is an original, static-only corpus for the profile-pinned Apache JMeter
5.6.3 GUI persistence surface. It covers `FX-GUI-001`, `GUI-001`, `GUI-002`,
and `GUI-003` without claiming that a GUI, Java, JMeter, JVM, or subprocess was
run. No file produced by the JMeter GUI is copied into this directory. The
profile rows remain `planned`, and the operating-system boundary remains
`external`.

| case | IDs | owned material |
|---|---|---|
| `guiclass-roundtrip` | `FX-GUI-001`, `GUI-001` | hand-authored JMX with ordered `hashTree` pairs, `guiclass`/`testclass`/`testname`/`enabled` attributes, nested `LoopController`, disabled sampler carrying an opaque no-drop `stringProp`, and an empty `WorkBench` source pair; direct JVM/OS boundaries |
| `persistence-contracts` | `FX-GUI-001`, `GUI-002` | pinned GUI save properties, `LAST`/template/backup contracts, and an allowlisted filesystem layout descriptor; direct JVM/OS boundaries |
| `platform-settings` | `FX-GUI-001`, `GUI-003` | locale, look-and-feel, toolbar/icon, tree, HiDPI, expand-tree, and undo settings plus twelve explicit Linux/Windows/macOS target-triple-by-Java lanes; direct JVM/OS boundaries |
| `workbench-migration` | `FX-GUI-001`, `GUI-001`, `GUI-002` | hand-authored non-empty `WorkBench` source and the pinned disabled `TestFragmentController` migration descriptor; direct JVM/OS boundaries |
| `plugin-editor-contract` | `FX-GUI-001`, `GUI-001` | original synthetic plugin-editor declaration with positive provisioning, unavailable-capability, and opaque no-drop paths; direct JVM/plugin/OS boundaries |

The aggregate `FX-GUI-001` boundary set is exactly
`EXT-JVM-001`, `EXT-PLUGIN-001`, and `EXT-OS-001`. Built-in direct cases use
the JVM/OS subset because they do not load a plugin editor. The
`plugin-editor-contract` case names all three boundaries and closes the
plugin-editor positive/unavailable union. The family union, rather than any
single direct case, must cover every aggregate boundary before materialization.

The JMX is deliberately conservative: it contains only built-in-looking
elements and disabled execution content. Its disabled sampler includes the
original opaque `jmeter-rs.gui.opaque.disabled` string property as a static
no-drop probe; it does not require a plugin artifact. Its expected descriptors
state what must be preserved, not what has been observed from JMeter. In JMeter 5.6.3,
loading a legacy `WorkBench` drops an empty branch and migrates a non-empty
branch into the `TestPlan`: non-test elements become disabled Test Plan
children and remaining elements become children of a disabled `WorkBench Test
Fragment`. Both source-only cases are represented here. The persistence and
platform descriptors similarly distinguish a static contract from a future
oracle observation.

## Future oracle actions (not run here)

Before any conformance claim, an isolated runner must provision the exact
`apache-jmeter-5.6.3.zip` artifact and Java runtime declared by the active
profile, then perform all actions below on each declared OS image. The runner
must expand `<temporary-root>` once, copy every hand-authored input into the
case-declared workspace, use the case-declared output root for generated files,
and never write generated output into this corpus. Relative paths must not be
resolved against `compat/fixtures/...`; every command manifest contains
absolute-after-expansion input/output paths and, where needed, a separate
working directory for each command template.

1. **GUI-001 / guiclass round trip.** Materialize the declared temporary roots,
   `java.util.prefs.userRoot`, and launcher locale before starting the pinned
   JMeter process. Launch the GUI with the `guiclass-roundtrip` recipe, load the
   plan, save it to a new path, close and reopen the saved plan, and compare the
   normalized XML tree. Assert every `guiclass`, `testclass`, `testname`,
   `enabled` value, property value/order (including the opaque disabled
   `jmeter-rs.gui.opaque.disabled` value), and sibling order. The empty
   `WorkBench` source pair must be absent from the saved tree. Repeat with the
   `workbench-migration` input: the non-empty branch must be migrated into the
   `TestPlan` as a disabled `WorkBench Test Fragment` (or disabled non-test
   child where the pinned source classifies it). Then load the saved plan with
   the non-GUI parser recipe and record diagnostics without enabling fixture
   samplers.
2. **GUI-002 / persistence.** With backup and autosave properties from
   `gui-persistence.properties`, first materialize `${JMETER_HOME}` in a copy
   of the property file. JMeter does not expand that token itself. Use the
   isolated preference root so `save_before_run` and `recent_file_0` cannot be
   inherited from a developer account. Save the plan repeatedly and record the
   numbered backup names (first version `000001`), sequence, directory,
   retention count, and whether a dirty plan is saved before a run. Load a plan
   through the GUI, then invoke the exact `LAST` argv shapes declared in the
   manifest; record resolved paths and diagnostics. In pinned 5.6.3, `-l LAST`
   derives the JTL path from `recent_file_0`, while `-j LAST` is passed literally
   and must be recorded as the literal `LAST` path under the declared
   LAST-command working directory; it does not derive `.log`. Run the explicit
   `fallback_absent`, `preference_true`, and `preference_false` fresh
   preference-root scenarios with a dirty plan and the GUI Start action. Also
   run `last_missing_recent` with `recent_file_0` absent and require an explicit
   unavailable/error diagnostic rather than a guessed path. Open the Templates action
   using the JMeter-home-relative `template.files` path, record the selected
   template path/description, and verify the empty/non-empty WorkBench outcomes
   above. Compare only manifest-declared path/sequence fields; preserve raw
   directory listings for diagnosis. The isolated preferences root contains
   separate pinned package nodes for `recent_file_0`/`laf.command`
   (`org/apache/jmeter/gui/action`) and `save_before_run`
   (`org/apache/jmeter/gui`).

   This literal `-j LAST` rule follows the pinned `JMeter.java` and launcher
   implementation: it intentionally overrides the stale research-table wording
   that describes `.log` derivation. A future runner must follow the pinned
   source and the three exact command templates in `case.json`, not infer a
   derived log path from that older wording.
3. **GUI-003 / platform settings.** Expand `matrix.json#/target_lanes` into
   twelve independent rows: Linux x86_64/aarch64, Windows x86_64/aarch64, and
   macOS x86_64/aarch64, each crossed independently with Java 8 and Java 17.
   Give every row a fresh, cleared preference root, separate workspace/output
   root, display-session identity, ProcessTree supervisor gate, and planned
   runtime identity record. On each matrix row, set the launcher
   `JMETER_LANGUAGE`/JVM properties before invoking JMeter; `language` in a
   late `-q` file is not an early locale source. Record the selected language,
   effective Swing LAF using the exact OS-name/family lookup order, toolbar/icon
   definitions and sizes, tree icon size, HiDPI state, expanded-tree state, and
   undo capacities. Restart after changing LAF as required by JMeter, reopen the
   same plan, and compare the platform-normalized settings descriptor. A
   display server/desktop is an explicit external prerequisite; the declared
   headless parser probe may check persistence only and is not GUI evidence.

   The platform property input uses the pinned toolbar vocabulary and order
   (`templates`, `undo`, `redo`, and `test_start_notimers` included), preserves
   the `jmeter.toolbar.icons` override/inheritance rule, and bounds invalid
   toolbar dimensions to JMeter's 22x22 fallback. Tree icons use the pinned
   19x19 default; HiDPI and undo values remain explicit fields rather than
   inferred from host rendering.

The exact argv templates, expanded workspace/output roots, per-template
working directories, preference scenarios, observations, external boundary,
and raw-artifact locations are repeated in each `case.json` so a future runner
does not infer a command or path from prose. The persistence manifest keeps
the `-j LAST` literal behavior distinct from `-l LAST` derivation.

## Static acceptance (no oracle or subprocess)

Run from the repository root. This checks only JSON syntax, input hashes,
profile provenance, expected statuses, XML parsing, and alternating
element/`hashTree` topology. It does not launch Java/JMeter or mutate any
filesystem path.

```sh
python3 - <<'PY'
import hashlib
import json
import xml.etree.ElementTree as ET
from pathlib import Path

root = Path("compat/fixtures/jmeter-5.6.3/gui-static")
profile_digest = (
    "387fadca903ee0aa30e3f2115fdfedb3898b102e6b9fe7cc3942703094bd2e65b235df2b0c6d0d3248e74c9a7950a36e42625fd74425368342c12e40b0163076"
)
required = {"FX-GUI-001", "GUI-001", "GUI-002", "GUI-003"}
seen = set()
family_boundaries = set()

def check_pairs(tree):
    children = list(tree)
    assert len(children) % 2 == 0, tree.tag
    for element, companion in zip(children[::2], children[1::2]):
        assert companion.tag == "hashTree", companion.tag
        check_pairs(companion)

for case_dir in sorted(path for path in root.iterdir() if path.is_dir()):
    manifest = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))
    provenance = json.loads((case_dir / "provenance.json").read_text(encoding="utf-8"))
    expected = json.loads((case_dir / manifest["execution"]["expected"]).read_text(encoding="utf-8"))
    assert manifest["profile_id"] == provenance["profile_id"] == "jmeter-5.6.3"
    assert manifest["execution"]["status"] == "static-only; oracle not executed"
    assert provenance["oracle_execution"]["performed"] is False
    assert provenance["oracle"]["artifact_sha512"] == profile_digest
    assert set(manifest["conformance_ids"]) <= required
    case_boundaries = set(manifest["external_runtime_boundary_ids"])
    assert case_boundaries <= {"EXT-JVM-001", "EXT-PLUGIN-001", "EXT-OS-001"}
    if manifest["case_id"] == "ORACLE-JMETER-563-GUI-STATIC-PLUGIN-EDITOR":
        assert case_boundaries == {"EXT-JVM-001", "EXT-PLUGIN-001", "EXT-OS-001"}
    else:
        assert case_boundaries == {"EXT-JVM-001", "EXT-OS-001"}
    family_boundaries.update(case_boundaries)
    bounds = manifest["bounds"]
    assert bounds["schema_id"] == "jmeter-rs.fixture-bounds"
    assert bounds["enforcement"] == "declared; static-only; future runner must enforce"
    for key in ("max_plan_bytes", "max_plan_nodes", "max_plan_depth", "max_property_text_bytes",
                "max_property_count_per_element", "max_backup_files", "max_template_files",
                "max_toolbar_entries", "max_output_bytes", "max_log_bytes",
                "max_gui_wait_seconds"):
        assert isinstance(bounds[key], int) and bounds[key] >= 0, (case_dir, key)
    seen.update(manifest["conformance_ids"])
    seen.add(manifest["fixture_family_id"])
    declared_hashes = {item["path"]: item["sha256"] for item in manifest["inputs"]}
    assert provenance["inputs"]["expected_sha256"] == declared_hashes[manifest["execution"]["expected"]]
    if manifest.get("property_files"):
        assert provenance["inputs"]["property_sha256"] == declared_hashes[manifest["property_files"][0]["path"]]
    if "plan" in manifest:
        assert provenance["inputs"]["plan_sha256"] == declared_hashes[manifest["plan"]["path"]]
    for item in manifest["inputs"]:
        path = (case_dir / item["path"]).resolve()
        assert path.is_file(), path
        assert hashlib.sha256(path.read_bytes()).hexdigest() == item["sha256"], path
    for item in manifest.get("property_files", []):
        path = (case_dir / item["path"]).resolve()
        assert path.is_file(), path
    if "plan" in manifest:
        plan = (case_dir / manifest["plan"]["path"]).resolve()
        assert plan.stat().st_size <= bounds["max_plan_bytes"]
        document = ET.parse(plan).getroot()
        assert document.tag == "jmeterTestPlan"
        assert document.attrib == {"version": "1.2", "properties": "5.0", "jmeter": "5.6.3"}
        wrapper = document.find("hashTree")
        assert wrapper is not None
        check_pairs(wrapper)
    assert expected["case_id"] == manifest["case_id"]
    assert expected["status"] == "planned; static expectation only"
    assert expected["evidence_status"] == "not-run"
    assert expected["source"]["oracle_status"] == "not-run"
    assert expected["source"]["runtime_observations"] is False
    validation = expected["validation_contract"]
    assert validation["comparator_enforced"] is False
    assert validation["comparator_id"] is None
    assert validation["comparator_route"] == "static-descriptor"
    if manifest["case_id"] == "ORACLE-JMETER-563-GUI-STATIC-PERSISTENCE":
        last = expected["contracts"]["last_resolution"]
        assert last["argv_templates"] == manifest["command"]["argv_templates"]
        assert last["working_directory_by_template"] == manifest["command"]["working_directory_by_template"]
assert seen == required, (seen, required)
assert family_boundaries == {"EXT-JVM-001", "EXT-PLUGIN-001", "EXT-OS-001"}
print("gui-static JSON/XML/hash/provenance checks passed; no oracle executed")
PY
```

The repository's normal fixture validator may be run separately when its Rust
toolchain is available. Passing either validator is not pinned JMeter evidence
and must not promote a profile row to `verified`.

## Provenance

The source vocabulary is the profile-pinned JMeter 5.6.3 release and the
research links in `docs/research/compatibility-surface.md`; the XML, property,
and descriptor files here are hand-authored original inputs. The provenance
files record the release commit and artifact digest for the future oracle,
static-only execution status, and the absence of network, credentials, and
raw oracle artifacts.
