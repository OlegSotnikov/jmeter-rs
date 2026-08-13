<!-- SPDX-License-Identifier: Apache-2.0 -->

# Script and JVM capability corpus

This is an original, static corpus for the JMeter 5.6.3 external scripting and
user-class boundaries.  It is intentionally source-only: no Java/JMeter
process, compiler, subprocess, network service, engine JAR, plugin JAR, or
oracle result is checked in or started while validating these files.

| case | fixture family | conformance IDs | coverage |
|---|---|---|---|
| `function-matrix` | `FX-SCRIPT-001` | `FUNC-003` | `__BeanShell`, `__groovy`, `__jexl2`, `__jexl3`, and `__javaScript`/Rhino function forms, escaped comma arguments, sampler-time variables/property bindings, and planned thrown-function failures |
| `jsr223-matrix` | `FX-SCRIPT-001` | `SCRIPT-001` | JSR223 binding names and values, SampleResult values/identity, inline/file scripts, MD5 and absolute-path+mtime cache identity, same/different source, exact inline false switch, JMeter cache-eligibility special cases, and planned evaluation exceptions |
| `java-class-loading` | `FX-SCRIPT-001` | `SCRIPT-002` | JavaSamplerClient, explicit JUnit3/JUnit4 mode/class/annotation contracts, user-classpath descriptors, missing-class diagnostics, opaque unknown timeout handling, and class-loader isolation; the profile also requires a separate `FX-PLUGIN-001` plugin fixture before SCRIPT-002 can be complete |

The profile pins the external oracle to Apache JMeter `5.6.3`, release tag
`rel/v5.6.3`, source commit
`34a2785748e9e0b14702595e8682c387869deda3`, and
`apache-jmeter-5.6.3.zip` SHA-512
`387fadca903ee0aa30e3f2115fdfedb3898b102e6b9fe7cc3942703094bd2e65b235df2b0c6d0d3248e74c9a7950a36e42625fd74425368342c12e40b0163076`.
The cases declare the exact distribution class path and require a future oracle
run to record Java vendor/version (Java 8+; Java 17 is recommended), with locale
`C`, timezone `UTC`, UTF-8, and no inherited environment. Each static
provenance manifest declares the expected bundled BeanShell, Groovy, Commons
JEXL, and Rhino artifact path, version, and SHA-256 for that future class path;
no JVM/JMeter classpath observation is recorded by static validation. A missing
engine or user class is an external capability failure; it is never substituted
with another engine or silently ignored.

The scripts and class descriptors are hand-authored originals.  Script files
are deliberately tiny and side-effect bounded: they only write bounded marker
values to the JMeter variable map/`OUT` stream or throw a named exception.  The
class descriptors name classes that are intentionally absent from this
repository; there are no compiled classes or user plugin JARs to load. The
provenance manifests declare the expected bundled engine/component artifact
path, version, SHA-256, and JSR223 service-provider class where one exists; they
are not resolved runtime classpath observations. Rhino's core JAR is pinned for
`__javaScript`, but Rhino JSR223 is explicitly unavailable
because that JAR has no `javax.script.ScriptEngineFactory` provider and no
separately pinned provider is supplied.

For JSR223, a non-empty Script File always derives a `FileScriptCacheKey` from
the language, absolute path, and file modification time for an eligible engine;
the `cacheKey` wire value does not disable that file cache.  Inline caching is
disabled only by the exact string `false`; an empty/default value is not the
explicit off switch.  JMeter also special-cases
`bsh.engine.BshScriptEngine` out of compiled-script caching despite its
`javax.script.Compilable` implementation.  Unavailable Rhino JSR223 cases
therefore retain null, unevaluated cache identities rather than fabricated
keys.

Every case expectation is a planned static contract with `oracle_status:
not-run`.  The `execution.status` values beginning with `not-run-static` are
not conformance evidence.  They document the required future differential
observations, including the typed unavailable behavior:

```text
engine/class missing -> preserve JMX/script source -> script.engine.unavailable or script.class.unavailable
script throws        -> sample/script failure -> script.evaluation.failed (oracle-required mapping)
class loader rejects -> preserve class name    -> script.class.contract-invalid
```

## Static acceptance

From the repository root, the owned corpus can be checked without Java,
JMeter, compilation, a subprocess, or network access:

```sh
python3 -m json.tool compat/fixtures/jmeter-5.6.3/script-engines/function-matrix/case.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/script-engines/function-matrix/provenance.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/script-engines/jsr223-matrix/case.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/script-engines/jsr223-matrix/provenance.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/script-engines/java-class-loading/case.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/script-engines/java-class-loading/provenance.json >/dev/null
find compat/fixtures/jmeter-5.6.3/script-engines -name '*.jmx' -print0 | xargs -0 -n1 python3 -c 'import sys,xml.etree.ElementTree as ET; ET.parse(sys.argv[1])'

# Static source/provider inventory checks (no JVM or JMeter process):
python3 - <<'PY'
import json
from pathlib import Path

root = Path("compat/fixtures/jmeter-5.6.3/script-engines")
for path in root.glob("*/provenance.json"):
    data = json.loads(path.read_text())
    for field in ("script_engines", "classpath_artifacts"):
        for engine in data["runtime"].get(field, []):
            assert len(engine["artifact_sha256"]) == 64
            assert engine["artifact_path"].startswith("lib/")
            if field == "script_engines" and engine["availability"] == "unavailable":
                assert engine["service_provider"] is None
                assert engine["separately_pinned_engine_artifact"] is None
            elif field == "script_engines" and engine["service_provider"] is not None:
                assert engine["service_provider"]["path"] == "META-INF/services/javax.script.ScriptEngineFactory"
    assert data["runtime"]["java"]["major"] is None
    assert data["runtime"]["java"]["target_major"] == 17
    assert data["runtime"]["plugin_artifacts"] == []
    assert data["runtime"]["plugin_artifact_inventory"]["status"] == "absent"
    assert data["runtime"]["plugin_artifact_inventory"]["paths"] == []
print("validated static engine/provider inventories")
PY

for jar in \
  jmeter-oracle-cache/apache-jmeter-5.6.3/lib/bsh-2.0b6.jar \
  jmeter-oracle-cache/apache-jmeter-5.6.3/lib/groovy-jsr223-3.0.20.jar \
  jmeter-oracle-cache/apache-jmeter-5.6.3/lib/commons-jexl-2.1.1.jar \
  jmeter-oracle-cache/apache-jmeter-5.6.3/lib/commons-jexl3-3.2.1.jar; do
  unzip -p "$jar" META-INF/services/javax.script.ScriptEngineFactory >/dev/null
done
! unzip -l jmeter-oracle-cache/apache-jmeter-5.6.3/lib/rhino-1.7.14.jar | rg -q 'META-INF/services/javax.script.ScriptEngineFactory'
```

The repository fixture checker additionally validates the case/provenance
manifest references, JSON schema headers, safe relative paths, pinned profile
digest, and plan/property SHA-256 entries.  It must be run against the
complete profile fixture root after the corpus hashes are populated:

```sh
cargo run -p xtask -- fixture-check --profile compat/profiles/jmeter-5.6.3.json
```

These commands are static checks.  They do not promote `FUNC-003`,
`SCRIPT-001`, or `SCRIPT-002` from their profile `external`/`planned` state.
