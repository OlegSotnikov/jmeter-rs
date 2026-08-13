<!-- SPDX-License-Identifier: Apache-2.0 -->

# Original deterministic report corpus

This directory is a small, hand-authored corpus for the report surfaces in
the `jmeter-5.6.3` profile.  The inputs are JTL-shaped XML and CSV documents,
not copied JMeter result files.  Expected JSON documents describe the decoded
input events and the exact report projections that a deterministic report
consumer must produce.

| case | family | compatibility IDs | coverage |
|---|---|---|---|
| `aggregate-dashboard` | `FX-REPORT-001` | `REPORT-001`, `REPORT-002` | listener Aggregate/Summary/graph rows, sorted labels and error ties, empty input, APDEX, Math.round weighted percentiles, explicit LEGACY dashboard window, and planned graph inventory |
| `backend-protocol` | `FX-REPORT-EXTERNAL-001` | `REPORT-003` | planned JMeter Graphite/InfluxDB metric vocabulary, deterministic field ordering, timestamp precision, and explicit external-service accounting |

The aggregate corpus uses an explicit UTC epoch interval of 10 seconds and the
documented APDEX thresholds of 500 ms satisfied and 1,500 ms tolerated.  One
JTL row represents two samples (`SampleCount=2`, `ErrorCount=1`) so the
weighted `StatisticalSampleResult` path remains observable.  Two one-count
error keys exercise deterministic top-error tie ordering.  A successful row
without an elapsed field is retained as a wire-level absence and decoded as
the pinned zero value by the JMeter result reader.  XML and CSV carry the same
`sample_id` and `suite_id` variables: XML and CSV both retain those exact
configured names; CSV appends them as columns and XML carries them as sample
attributes.  The XML and CSV descriptors therefore project the same variable
values without a transport-specific double-underscore alias.

Listener percentiles use JMeter's pinned `Math.round(count * p)` weighted rank.
For the aggregate row with `t=600` and `SampleCount=2`, the effective elapsed
value is 300 ms twice; this differs from the row-level 600 ms value consumed by
the dashboard.  Dashboard counters/statistics are row-based, retain seven
rows, and use the explicit LEGACY Commons-Math `p * (n + 1)` estimator over
the newest five FIFO rows.  The expected descriptors retain both algorithms
and both count domains; they must not be normalized into one value.  Labels
and error keys are ordered lexicographically, while input events retain source
order.

The listener total APDEX is explicitly weighted (`satisfied=4`, `tolerated=1`,
`frustrated=3`, score `0.5625`); the dashboard total remains row-based
(`3/1/3`, score `0.5`).  The empty descriptor declares its combined zero-row
shape as an allowed variant; non-empty listener and dashboard projections are
separate documents with the `nonempty_report_surface` shape variant.

The backend case deliberately contains no server, credentials, subprocess, or
oracle output.  Its descriptors use the planned JMeter 5.6.3 Graphite
vocabulary (`ok.*`, `ko.*`, `a.*`, `h.count`, `sb.bytes`, `rb.bytes`, and
`maxAT`/`minAT`/`meanAT`/`startedT`/`endedT`) and InfluxDB line-protocol
vocabulary (`count`, `countError`, `avg`, `min`, `max`, `hit`, `sb`, `rb`,
`pct*`, with `application`, `transaction`, and `statut` tags).  They are
descriptor templates, not fabricated transport records.  The case status is
`external-unavailable` until a separately pinned local Graphite/InfluxDB
adapter is run.  Neither case was executed through Java, JMeter, a report
generator, or an external process while this corpus was authored, so both
manifests record a null process exit.

The report and backend plans are bounded one-iteration Debug Sampler smoke
sources, making their retained `-n -t` command recipes truthful and finite.
The report plan includes enabled JMeter `ResultCollector` listener elements
for Aggregate Report, Summary Report, and Graph Results.  The backend plan
includes exact JMeter `BackendListener` argument blocks for Graphite and
InfluxDB, but both external nodes are `enabled="false"` until a bounded local
service runner grants that capability.  `backend_metrics_percentile_estimator=LEGACY`
is pinned in the backend properties and descriptor.

There is intentionally no root-level plan: the former unbound JSR223 probe had
no case, input, expected descriptor, or provenance record and duplicated the
bounded `aggregate-dashboard/plan.jmx` boundary.  Each retained plan is
therefore owned by its case manifest and hash set.
The static expectations intentionally come from the hand-authored JTL inputs;
no command is claimed to have produced them.  The dashboard graph inventory
lists the profile's graph families with empty `planned_not_materialized`
points, so it expands coverage without fabricating output.

All plans, properties, inputs, expectations, and provenance records are
original project files.  The provenance records pin Apache JMeter 5.6.3 and
the profile artifact for a future differential run; they do not claim that a
static descriptor is oracle evidence.  Hashes cover every case input and
expected descriptor.  Raw oracle artifacts remain ignored and are not part of
this directory.

Each manifest declares finite input, sample, result, artifact, log, process
output, and process-wait bounds.  These bounds describe the future runner
contract; this static corpus does not start a process or materialize a report.

Static validation from the repository root:

```sh
python3 -m json.tool compat/fixtures/jmeter-5.6.3/reports/aggregate-dashboard/case.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/reports/backend-protocol/case.json >/dev/null
find compat/fixtures/jmeter-5.6.3/reports -name '*.jmx' -print0 \
  | xargs -0 -n1 python3 -c 'import sys,xml.etree.ElementTree as ET; ET.parse(sys.argv[1])' 
```

The repository fixture validator additionally checks schema references,
provenance, safe paths, and all declared SHA-256 values:

```sh
cargo xtask fixture-check --fixtures compat/fixtures/jmeter-5.6.3
```
