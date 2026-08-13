<!-- SPDX-License-Identifier: Apache-2.0 -->

# Apache JMeter 5.6.3 original oracle corpus

This tree contains small, original JMX plans, property files, wire inputs, and
static expectation contracts for differential tests. They exercise JMeter
built-ins or explicitly bounded local boundaries and do not contact a public
or external service while being authored.

The checked-in material is source-only unless an exact run against the pinned
Apache JMeter 5.6.3 artifact is recorded as local evidence. A `case.json`,
`provenance.json`, or `expected/*.json` file is not, by itself, materialized
oracle evidence; most cases here deliberately remain planned or unavailable.
The active compatibility profile remains the authority for status, and these
files do not promote any profile row to verified conformance.

| case | fixture family | coverage | declared oracle shape |
|---|---|---|---|
| `lifecycle-debug` | `FX-ELEMENTS-CORE-001` | one-user lifecycle, User Defined Variables, `__P`, Debug Sampler variables/properties | XML JTL |
| `controllers` | `FX-ELEMENTS-CORE-001` | Simple, Loop, Once Only, and Interleave controller ordering | XML JTL |
| `assertion-failure` | `FX-ELEMENTS-CORE-001` | deterministic response assertion failure and separate sample/process status | XML JTL |
| `processors-extractors/{core,negative-bounds}` | `FX-ELEMENTS-CORE-001` | ELEM-008 pre/post processors, extractors, local response corpus, variable-snapshot contracts, negative/error/bounds and no-drop disabled inputs | static JMX semantic contracts |
| `jtl-fields` | `FX-JTL-001` | CSV headers/quoting/sample variables and XML attributes/assertions/response data | CSV and XML JTL |
| `jmx-topology` | `FX-JMX-001` | root metadata, ordered alternating `hashTree` pairs, and typed properties | JMX semantic expectation plus XML JTL smoke contract |

## Corpus inventory and status

The inventory includes the core cases above plus `assertions-full/*`,
`cli-matrix`, `config-precedence`, `controllers-full/*`, `cross-platform/*`,
`distributed`, `external-samplers/*`, `functions-files/*`,
`functions-random-time`, `functions-strings/*`, `fuzz-manifest`,
`gui-static/*`, `harness`, `http-sampler/core`, `http-state/*`,
`jmx-aliases/*`, `plugin-contract`, `jtl-fields`, `proxy-tls`,
`recorder-mirror`, `reports/*`, `script-engines/*`, and `timers/*`. The plans,
properties, inputs, and static
descriptors are original project files; no Apache JMeter plan, result, binary,
certificate, or key is redistributed.

Most cases use the repository-standard `case.json` and `provenance.json`
manifests. Source-only directories and partial scaffolds without that
topology are not cases and are not materialized oracle evidence. Custom JSON
schemas or layouts are allowed only when the fixture validator explicitly
recognizes their schema; otherwise they remain source material until validator
support and a corresponding acceptance path exist.

Expectation files may record a future oracle command and the pinned artifact
digest, but those records do not claim that the command ran. Raw output remains
local under `oracle-runs/`, and generated certificates/keystores remain under a
temporary `run-root/`; both are ignored by Git. Such output is evidence only
when it is actually produced and retained outside the repository.

## Quarantined external raw observations

The `assertion-failure`, `controllers`, `jmx-topology`, and `lifecycle-debug`
cases retain captured JMeter output as `external-raw-observation`. Their
manifests record `comparator_ready: false` and
`rust_conformance_claim: false`, so these captures are diagnostic material,
not deterministic oracle baselines and not compatibility evidence. All four
captures observed the repository root rather than the declared case working
directory, the `en_EN` locale rather than `C`, and the
`ANSI_X3.4-1968` Java default charset rather than `UTF-8` (while SaveService
reported UTF-8). Do not use their expected projections to promote a profile
row or infer a compatibility claim. A future rerun must use the declared
working directory and environment and replace the observation only after its
metadata is validated.

Each corresponding provenance record carries the profile-pinned Apache
signature and `KEYS` URLs, but explicitly records
`signature_verified_before_execution: false` and an unverified PGP object.
The SHA-512 check and the captured run therefore do not authenticate the
artifact. The xtask classifies `external-raw-observation` as quarantined, so
these records remain outside materialized or release evidence until a future
run supplies independently verified PGP provenance and matching environment
metadata.

## Re-running the oracle

The JMeter 5.6.3 ZIP is intentionally not part of this repository. Download
it to the ignored `jmeter-oracle-cache/` directory, obtain its official
`.sha512` sidecar, and verify before extracting or executing:

```sh
mkdir -p jmeter-oracle-cache
curl --fail --location --output jmeter-oracle-cache/apache-jmeter-5.6.3.zip \
  https://archive.apache.org/dist/jmeter/binaries/apache-jmeter-5.6.3.zip
curl --fail --location --output jmeter-oracle-cache/apache-jmeter-5.6.3.zip.sha512 \
  https://archive.apache.org/dist/jmeter/binaries/apache-jmeter-5.6.3.zip.sha512
(cd jmeter-oracle-cache && sha512sum -c apache-jmeter-5.6.3.zip.sha512)
unzip -q jmeter-oracle-cache/apache-jmeter-5.6.3.zip -d jmeter-oracle-cache
```

The expected digest is recorded in each provenance file and in the pinned
compatibility profile. Run from the repository root with a clean, fixed
environment; replace `<case>` and `<properties>` as appropriate:

```sh
mkdir -p oracle-runs/<case>
LC_ALL=C LANG=C TZ=UTC \
  jmeter-oracle-cache/apache-jmeter-5.6.3/bin/jmeter \
  -n -q compat/fixtures/jmeter-5.6.3/<case>/<properties> \
  -t compat/fixtures/jmeter-5.6.3/<case>/plan.jmx \
  -l oracle-runs/<case>/oracle.jtl \
  -j oracle-runs/<case>/oracle.log
```

`lifecycle-debug` additionally supplies
`-Joracle.case.property=property-value`. `jtl-fields` runs once with
`oracle-csv.properties` and once with `oracle-xml.properties`. Keep raw JTL
and logs in `oracle-runs/`; that directory is ignored and must never be
committed. A static expectation without a retained pinned-oracle run remains a
source contract, not conformance evidence.

For a manifest-accurate invocation, run with the case directory as the
working directory and use the arguments in `case.json`. The runs used to
generate this corpus additionally clear the inherited environment:

```sh
env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  LC_ALL=C LANG=C TZ=UTC \
  jmeter-oracle-cache/apache-jmeter-5.6.3/bin/jmeter ...
```

The ellipsis above is only a shell presentation shortcut; each expectation's
`generated_from.oracle_command` contains the complete reproducible command.

## Validation

From the repository root, validate every committed fixture document before a
corpus handoff:

```sh
python3 -m json.tool compat/fixtures/jmeter-5.6.3/<case>/case.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/<case>/provenance.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/<case>/expected/<file>.json >/dev/null
```

Parse each `plan.jmx` as XML and, where the case is materialized for oracle
execution, rerun the exact pinned oracle command. A successful process is not
sufficient evidence for a passing sample: the assertion case intentionally
has process exit 0 and one failed sample. Static syntax, schema, and hash
checks do not execute Java, JMeter, or any fixture service.

## Comparison rules

The manifests explicitly identify the conformance rows and normalization
policies. Only wall-clock timing, timestamp-derived Debug Sampler content, and
byte counts derived from that content are ignored. Hostnames are disabled in
the save configuration. Labels, ordered sample structure, status, response
code/message, thread name, assertion structure/message, configured variables,
JTL headers, delimiters, quoting, and XML variable attribute names remain
observable and must be compared.

The `jmx-topology` expectation follows the profile's semantic JMX policy, so
XML indentation and empty-element lexical spelling are not compared; root
metadata, ordered topology, attributes, typed properties, and decoded values
remain exact.

An oracle run that cannot be reproduced with the pinned JMeter distribution is
reported as unavailable or limited; an expectation must never be fabricated
from a Rust implementation.
