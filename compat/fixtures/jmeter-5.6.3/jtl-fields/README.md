<!-- SPDX-License-Identifier: Apache-2.0 -->

# JTL field-selection corpus

This is an original, offline corpus for JTL-001 through JTL-005 in the
Apache JMeter 5.6.3 compatibility profile (`FX-JTL-001`, with the
configuration cross-reference `FX-CONFIG-001`).  It is deliberately
static: this change does not run Java, JMeter, an oracle command, a network
service, or a subprocess.  The files under `inputs/` are hand-authored wire
inputs and the files under `expected/` are planned semantic projections for
the Rust codec/comparator.  The CSV/XML inputs model JMeter writer wire
details (quoted sample-variable headers, single-underscore XML variables,
`java.lang.String` children, assertion child elements, and `java.net.URL`).
They are not claimed to be measured JMeter output.  A future oracle run must
replace the `planned` evidence marker only after the pinned artifact and raw
local artifacts have been checked.

The corpus covers:

| Surface | Static cases |
| --- | --- |
| JTL-001 | `testResults` metadata, `sample`/`httpSample`, abbreviated attributes, XML entities, and legacy `rs` response-code input |
| JTL-002 | nested samples, assertion child elements, response/request headers, sampler data, response data on failed samples, response-file-only resources, and URL sections |
| JTL-003 | complete and minimal CSV column sets, configured sample variables, comma/tab delimiters, empty fields, quotes, commas, and embedded line breaks |
| JTL-004 | millisecond timestamps, CSV-only formatted-timestamp configuration, `ts` start/end selection vectors, UTF-8 values, a byte-preserved CRLF CSV artifact target, and legacy CSV date-shaped values |
| JTL-005 | save-service switch matrices, response-on-error fields, failure messages, unknown/omitted columns, parser limits, and malformed-input rejection |

`corpus.toml` is the index for every input, expected projection, configured
limit, invalid-input diagnostic, property hash, and resource hash.
`switches/` contains property matrices that describe output configurations;
they are input data, not evidence that a JMeter process accepted those
properties.  `variants/rust-no-drop/` is intentionally not JMeter-writer
wire, and `variants/jmeter-reader-loss/` documents upstream reader semantics
separately.  No `.jtl`, log, archive, class, or other raw oracle artifact is
checked in.

The `capabilities.response_file_only` entry in `corpus.toml` ties the
filename-enabled XML vector to its checked-in resource and planned
projection.

`expected/*.json` uses `neutral-csv-v1`/`neutral-xml-v1` projections for
writer-wire cases.  The `wire_contract` and per-sample `wire_children`
objects are machine-readable declarations of String classes, URL elements,
child order, sample-variable spelling, assertion-child multiplicity, and
response-file capability.  A URL is a typed `java.net.URL` child at the Rust
retention boundary, but it is not a typed subresult.  `rust-no-drop-parser`,
`jmeter-reader-semantics`, invalid-input, and resource-limit expectations are
explicit static non-comparator descriptors; they must be handled by their
dedicated reader/error/limit checks rather than passed to the JTL comparator.

The pinned JMeter converter couples the `SampleCount` and `ErrorCount` CSV/XML
fields behind the single `sample_count` save-service switch.  The corpus does
not invent an independent upstream error-count switch.  Likewise,
`assertion_results_failure_message` is a CSV-only save property: XML
`failureMessage` is an optional child of each assertion result and is retained
when present, independently of that CSV setting.  Every timestamp-selection
vector declares `sampleresult.timestamp.start` explicitly; no distribution
default is treated as an observation.

## Provenance and evidence status

The JMX plan and property files are original project-authored sources.  The
provenance file pins the Apache release and SHA-512 required by the active
profile, but records that no oracle invocation was performed for this corpus.
All expectations therefore use `planned`/`hypothesis` language.  The future
runtime declaration is explicitly `en-US`/UTF-8, but it has not been
measured.  Runtime-dependent fields are either fixed in the wire input to test parser behavior
or explicitly listed as not asserted; they are never normalized silently.

The corpus is intended to be consumed by bounded readers.  Invalid fixtures
must return a typed parse/limit error and must not produce a partial event
stream.  The expected error categories in `corpus.toml` are contract targets
for static parser tests, not observations from JMeter.

## Static checks

From the repository root, the fixture shape and hashes can be checked without
starting an oracle:

```sh
cargo xtask fixture-check --profile compat/profiles/jmeter-5.6.3.json \
  --fixtures compat/fixtures/jmeter-5.6.3/jtl-fields
fixture=compat/fixtures/jmeter-5.6.3/jtl-fields
python3 -m json.tool "$fixture/case.json" >/dev/null
python3 -m json.tool "$fixture/provenance.json" >/dev/null
for file in "$fixture"/expected/*.json; do python3 -m json.tool "$file" >/dev/null; done
python3 -c 'import pathlib,tomllib; tomllib.loads(pathlib.Path("compat/fixtures/jmeter-5.6.3/jtl-fields/corpus.toml").read_text())'
```

The repository-wide profile remains `planned`; this corpus does not promote
any compatibility row.
