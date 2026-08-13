<!-- SPDX-License-Identifier: Apache-2.0 -->

# Apache JMeter 5.6.3 CLI matrix (static corpus)

This is the original, descriptor-only corpus for `FX-CLI-001` and
`CLI-001`..`CLI-003`. It records the pinned Apache JMeter 5.6.3 command-line
surface without claiming that any command was run. The JMX, CSV, property
files, and Log4j2 XML are small original future inputs; they are not copied
upstream plans or oracle output.

## Scope and ownership

Only this directory is owned by this corpus:

| compatibility ID | observable surface | descriptor |
|---|---|---|
| `CLI-001` | all short/long spellings, repeat order, `LAST`, help/version vocabulary | [`inputs/option-catalog.json`](inputs/option-catalog.json) and [`inputs/scenarios.json`](inputs/scenarios.json) |
| `CLI-002` | legal/illegal combinations, `-e`/`-l`, report-only restrictions | [`inputs/scenarios.json`](inputs/scenarios.json) |
| `CLI-003` | normal/fatal/remote process categories and logging | [`inputs/process-contract.json`](inputs/process-contract.json) and [`inputs/runner-contract.json`](inputs/runner-contract.json) |
| `FX-CLI-001` | option, property, report, logging, exit-status, and future setup matrix | [`expected/semantic.json`](expected/semantic.json) and [`inputs/runner-contract.json`](inputs/runner-contract.json) |

The handoff metadata and hashes are in [`case.json`](case.json) and
[`provenance.json`](provenance.json). No profile row is promoted by this
corpus.

## Option coverage

`inputs/option-catalog.json` contains exactly 30 documented short/long pairs,
including the source/proxy option `-E/--proxyScheme`:

* help/version: `-?`/`--?`, `-h`/`--help`, `-v`/`--version`;
* files and mode: `-p`, `-q`, `-t`, `-l`, `-i`, `-j`, `-n`, `-s`;
* proxy: `-E`, `-H`, `-P`, `-N`, `-u`, `-a`;
* properties/logging: `-J`, `-G`, `-D`, `-S`, `-f`, `-L`;
* remote/home: `-r`, `-R`, `-d`, `-X`; and
* reporting: `-g`, `-e`, `-o`.

The repeatable set is `-q/-J/-G/-D/-S/-L`; each has a bounded repeated
scenario with source-aligned last-file or last-occurrence precedence probes.
`-t LAST` uses the source-defined `LoadRecentProject.getRecentFile(0)` lookup;
this static corpus supplies no recent-project state. `-l LAST` and
`-l LAST.jtl` use `processLAST(..., ".jtl")`, while `-j LAST` and `-j LAST.log`
retain the source inconsistency between the `JMeter.java` comment and
`NewDriver.replaceDateFormatInFileName` (the latter does not perform recent
project resolution). Lowercase `last` remains an explicit oracle probe rather
than an assumed alias. The `-?` options output is checked for the concrete
short/long option spellings; `-h/--help` uses the source `help.txt` vocabulary;
`-v/--version` checks the ASCII banner's copyright, Apache Software Foundation,
and `5.6.3` tokens. Localized prose and whitespace are not the sole oracle
under `NORM-CLI-001`.

The paired-single-quote `-j` date pattern remains source-ambiguous in this
static corpus: the research baseline names `java.text.SimpleDateFormat`, while
the exact pinned `NewDriver` call-site formatter has not been asserted here.
`inputs/scenarios.json` and `inputs/process-contract.json` therefore keep the
engine null and list both candidates; a future source/oracle pass must resolve
it under a fixed UTC clock before any formatter behavior is implemented or
compared.

## Combination, report, logging, and exit descriptors

The scenarios separate accepted mode vectors from rejection probes:

* normal non-GUI load, remote `-r`/`-R` with `-G`/`-X`, proxy, property, and
  logging vectors;
* `-e` requiring `-l`;
* `-g` report-only vectors with concrete CSV input. The source parser rejects
  only `-n`, `-r`, `-R`, and `-l`; concrete probes for each are present, while
  `-t` and `-e` are accepted/report-only-ignored probes. An omitted `-o`
  default/rejection policy is retained as an explicit oracle probe rather than
  assumed;
* output-directory safety (`-o` and `-f`), missing arguments, unknown options,
  missing plans, and deferred remote-mode restrictions; and
* normal completion versus sample failure, parser/usage returns versus fatal
  Throwable/System.exit startup/report failure, remote failure/shutdown, and the
  `jmeterengine.stopfail.system.exit`/
  `jmeterengine.remote.system.exit` property probes.

`inputs/process-contract.json` records stable categories and fields to retain
in a future differential run. Numeric status is null and unasserted in this
corpus; source-derived `System.exit(1)` is represented only as a fatal
termination category. No status, stream, log, report, or JTL bytes are
observed here. The deterministic sample-failure plan is a new bounded JMX
input, and its one expected failed sample remains planned until execution.

`usage-return` is the canonical exit-status class for help/version and parser or
`IllegalUserActionException` return paths. Numeric process exits remain null and
unasserted until a pinned child-process observation.

## Bounds and static-only policy

The manifests declare these future-run limits: 30 option definitions, 48
scenarios, 60 concrete vectors in the all-option-pairs scenario, 32 argv
tokens per scenario, four occurrences of a repeatable
option, 4 KiB option/property values, 64 KiB help/diagnostic/log output, 4 KiB
version output, 128 report entries, 40 plan nodes, depth seven, and a 30-second
process wait. `TZ=UTC` is fixed; PATH and locale variables are target-specific
materialization slots described by [`inputs/runner-contract.json`](inputs/runner-contract.json).
The future runner must not inherit host PATH/locale, must use target-native
path separators, and must record target triple, OS image, JVM locale, and
charset. The bounds are descriptors, not runtime enforcement in this corpus.

No Java, Apache JMeter, jmeter-rs, shell fixture, remote service, network
endpoint, or subprocess was started while creating this corpus. The command
vectors in `inputs/scenarios.json` are concrete future probes, but remain
non-executed descriptors; `case.json` references scenarios by ID.

## Future runner setup contract

[`inputs/runner-contract.json`](inputs/runner-contract.json) is a static
materialization contract, not runner code. A future oracle runner must:

* create a fresh ignored evidence root, explicitly prepare absent/empty output
  directories, and create deterministic nonempty sentinels for the output
  safety and `-f` replacement probes;
* materialize scenario IDs and `<...>` placeholders into direct argv tokens,
  reject unresolved placeholders, preserve quoted date patterns as one token,
  and never use shell interpolation;
* supervise server, client, registry, and worker processes through exact owned
  child handles with bounded readiness/shutdown/reaping; broad process
  discovery or cleanup is forbidden;
* use only a runner-owned loopback RMI registry/worker for remote scenarios,
  record materialized ports, and use a loopback port with no listener for the
  unavailable-registry probe; and
* use a deliberately induced, bounded stop-failure harness for both `-J`
  property values. The checked-in plan does not induce that condition.

No setup state, remote worker, output directory, or stop-failure observation is
present in the static corpus.

## Static acceptance

From the repository root, these checks parse only checked-in files and verify
their hashes. They do not invoke a runtime:

```sh
python3 -m json.tool compat/fixtures/jmeter-5.6.3/cli-matrix/case.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/cli-matrix/provenance.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/cli-matrix/inputs/option-catalog.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/cli-matrix/inputs/scenarios.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/cli-matrix/inputs/process-contract.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/cli-matrix/inputs/runner-contract.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/cli-matrix/expected/semantic.json >/dev/null
python3 - <<'PY'
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

root = Path("compat/fixtures/jmeter-5.6.3/cli-matrix")
case = json.loads((root / "case.json").read_text())
catalog = json.loads((root / "inputs/option-catalog.json").read_text())
runner = json.loads((root / "inputs/runner-contract.json").read_text())
assert catalog["option_count"] == 30
assert len(catalog["options"]) == 30
assert len({(item["short"], item["long"]) for item in catalog["options"]}) == 30
assert set(catalog["repeatable_option_ids"]) == {
    item["id"] for item in catalog["options"] if item["repeatable"]
}
scenarios = json.loads((root / "inputs/scenarios.json").read_text())
assert scenarios["scenario_count"] == 48
all_pairs = next(item for item in scenarios["scenarios"] if item["id"] == "all-option-pairs")
assert all_pairs["argv"] == all_pairs["argv_vectors"][0]
assert len(all_pairs["argv_vectors"]) == 60
assert all(len(vector) >= 2 and "<" not in " ".join(vector) for vector in all_pairs["argv_vectors"])
for index, option in enumerate(catalog["options"]):
    short_vector = all_pairs["argv_vectors"][2 * index]
    short_token = short_vector[1]
    assert short_token == option["short"] or (
        option["argument_kind"].startswith("key=value") and short_token.startswith(option["short"])
    )
    assert all_pairs["argv_vectors"][2 * index + 1][1] == option["long"]
assert catalog["report_only_parser_disallowed_option_ids"] == ["OPT-010", "OPT-024", "OPT-025", "OPT-007"]
assert runner["fixture_family_id"] == "FX-CLI-001"
assert runner["argv_materialization"]["exec_mode"] == "direct-argv-no-shell"
assert runner["platform_materialization"]["path"]["ambient_inheritance"] is False
assert runner["process_lifecycle"]["max_wait_seconds"] == 30
assert runner["local_rmi_setup"]["network_scope"] == "loopback-only"
assert runner["stop_failure_setup"]["static_observation"] is False
for item in case["inputs"]:
    data = (root / item["path"]).read_bytes()
    assert hashlib.sha256(data).hexdigest() == item["sha256"]
ET.parse(root / "inputs/cli-plan.jmx")
ET.parse(root / "inputs/cli-sample-failure-plan.jmx")
ET.parse(root / "inputs/log4j2.xml")
assert b"timeStamp,elapsed,label" in (root / "inputs/report-input.csv").read_bytes()
print("validated CLI static descriptors, JMX/XML syntax, and SHA-256 hashes")
PY
```

The acceptance result is static corpus integrity only. A future pinned-oracle
run must create raw logs/JTL/reports under ignored `oracle-runs/`, record its
Java/runtime metadata, and update evidence separately; it must not convert
these descriptors into fabricated observations.
