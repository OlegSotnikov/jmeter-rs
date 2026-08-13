<!-- SPDX-License-Identifier: Apache-2.0 -->

# Apache JMeter 5.6.3 cross-platform source corpus

This directory is the source-only design corpus for `FX-CROSS-PLATFORM-001`.
It covers `CFG-003` path/locale/encoding/time-zone/environment behavior,
`GUI-003` GUI persistence and headless settings, and `TEST-005`
cross-platform/performance gates.

No case in this directory has been run. Every case and expectation is marked
`planned` or `not-run`; there are no measured timings, process exits, JMeter
logs, JTLs, screenshots, or host observations. The pinned Apache JMeter
5.6.3 artifact is recorded only as the future oracle identity from the active
profile. Creating this corpus did not start a subprocess, Java/JMeter,
network service, or GUI, and did not mutate an operating-system setting.

The six target rows in each matrix are future CI lane descriptors only:
`linux/{x86_64,arm64}`, `macos/{x86_64,arm64}`, and
`windows/{x86_64,arm64}`. Current CI coverage is explicitly empty in every
case (`current_ci.status=not-configured`, `targets=[]`,
`runs_recorded=0`). A row marked `planned`/`not-run` is not evidence that its
OS, architecture, display server, filesystem policy, or adapter is available.

## Target matrix

The same bounded matrix is declared in the path, GUI, capability, and
performance projections. A target row is a future CI lane, not evidence that
the target is currently supported or available:

| OS | x86_64 | arm64 |
| --- | --- | --- |
| Linux | `x86_64-unknown-linux-gnu` | `aarch64-unknown-linux-gnu` |
| macOS | `x86_64-apple-darwin` | `aarch64-apple-darwin` |
| Windows | `x86_64-pc-windows-msvc` | `aarch64-pc-windows-msvc` |

The path cases contain concrete repository-owned files for repository-relative
opens, names containing spaces, Unicode path components, case spelling,
explicit roots, and a bounded raw non-Unicode-byte request. Platform separators
are represented as data in the expectation (the Windows value decodes to one
backslash); the JMX wire probes additionally retain Windows drive-qualified,
drive-relative, UNC, parent-escape, and drive-escape spellings. Repository
references remain portable forward-slash relative paths. LF and CRLF are
separate input files, and a third UTF-8 properties file probes literal
non-ASCII bytes without asserting its effective Java decoding. macOS rows keep
NFC and NFD source spellings as separate contracts and require returned lookup
forms to be recorded rather than silently rewritten. Locale, timezone, charset,
headless/display, and GUI settings are explicit matrix axes rather than ambient
process state.

## Case inventory

| case directory | coverage | static inputs/expectation |
| --- | --- | --- |
| `path-matrix` | six-target path-open, space, Unicode, case, separator, explicit-root, and raw-byte capability matrix | original UTF-8 JMX, properties, and bounded probe files |
| `line-endings` | LF versus CRLF source bytes, decoded escape semantics, and literal UTF-8 charset probes | original LF/CRLF/UTF-8 properties |
| `headless-gui` | GUI class/settings persistence plus observable locale/timezone/charset/headless/display axes | original UTF-8 JMX and properties |
| `capability-errors` | explicit unsupported-capability diagnostics for unavailable platform facilities | original JSON contract |
| `performance-baseline` | bounded performance/capacity metadata and empty measurement envelope | original JSON contract |

`expected/*.json` files are static semantic projections, not oracle output.
They mark future observations as `planned`/`not-run` and use null/empty values
for measurements where a future run would otherwise invite an invented result.
A future harness must record the exact Java
runtime, target triple, OS image, Rust toolchain, dependency lock hash,
locale, timezone, charset, environment allowlist, and raw diagnostic location
before any result can be considered evidence.

The three descriptor-only cases (`line-endings`, `capability-errors`, and
`performance-baseline`) declare `static_descriptor_routing` and a path-keyed
`descriptor` SHA-256. They intentionally have no executable plan: their argv
fields use typed materialization references such as
`<materialize:jmx-plan:cross-platform-line-endings-plan>`,
`<materialize:rust-cli:platform-capability-validator>`, and
`<materialize:rust-runner:performance-baseline>`. The path and headless cases
also expose the same static-projection identity while retaining their original
JMX plans. These references are routing metadata only; a future materializer
must resolve and hash its input before constructing an executable argv.
No static projection is comparator evidence, and no untyped plan placeholder is
accepted.

## Static checks

From the repository root, these checks read only local source files:

```sh
python3 -m json.tool compat/fixtures/jmeter-5.6.3/cross-platform/path-matrix/case.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/cross-platform/path-matrix/provenance.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/cross-platform/path-matrix/expected/semantic.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/cross-platform/line-endings/case.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/cross-platform/line-endings/provenance.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/cross-platform/line-endings/expected/semantic.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/cross-platform/headless-gui/case.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/cross-platform/headless-gui/provenance.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/cross-platform/headless-gui/expected/semantic.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/cross-platform/capability-errors/case.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/cross-platform/capability-errors/provenance.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/cross-platform/capability-errors/expected/semantic.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/cross-platform/performance-baseline/case.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/cross-platform/performance-baseline/provenance.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/cross-platform/performance-baseline/expected/semantic.json >/dev/null
python3 - <<'PY'
from pathlib import Path
import xml.etree.ElementTree as ET
for path in Path("compat/fixtures/jmeter-5.6.3/cross-platform").rglob("*.jmx"):
    ET.parse(path)
PY
```

The repository `fixture-check` additionally verifies the pinned profile
references and all SHA-256 values, including the path probe files and literal
UTF-8 properties input. It does not execute any case. Performance metadata
includes `queue_overflows` because its planned no-overflow threshold is not
evaluated until a future measurement exists. The same static check must verify
the descriptor hashes, provenance descriptor hashes, target-specific outcome
rows, and `observed=false`/`run_status=not-run` markers before any oracle work
is authorized.
