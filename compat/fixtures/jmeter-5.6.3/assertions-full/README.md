<!-- SPDX-License-Identifier: Apache-2.0 -->

# Full assertion oracle corpus

This directory is an original, offline corpus for the pinned JMeter 5.6.3
assertion contract (`ELEM-006`). The focused cases cover response, duration,
and size assertions, including pass, fail, equality/zero boundaries, malformed
patterns, invalid comparators, and the XML `assertionResult` representation.

| case | coverage |
| --- | --- |
| `text-core` | built-in Debug Sampler response-data marker, duration/size pass and fail, and assertion-result ordering |
| `boundaries` | response empty/not-empty behavior, duration zero/negative/positive boundaries, and all size comparators |
| `invalid` | malformed response regex, unknown response field, invalid size number/operator, and negative size |

Every case is a hand-authored JMX plan with a pinned XML save configuration,
`case.json`, `provenance.json`, and an expectation under `expected/`.  The
plans use only built-in JMeter elements and never contact a public or local
service. The Debug Sampler's response code (`200`), message (`OK`), and
configured variable marker are deterministic; dynamic diagnostic lines are
projected out of expectations. They are intentionally static corpus inputs; the
expectations identify the pinned Java oracle command but are not a claim that
the oracle was executed while this corpus was authored.

The save configuration keeps assertion results enabled with
`jmeter.save.saveservice.assertion_results=all` and
`jmeter.save.saveservice.assertion_results_failure_message=true`; filename
output is disabled and the machine-readable contract records `responseFile` as
absent. Each expected XML result names the built-in `<sample>` element (the
comparator also accepts its `httpSample` alias) and carries the
comparator-supported `wire_children.assertion_child_elements` descriptor.
That descriptor checks the ordered prefix `name`, `failure`, `error`,
`failureMessage`; passing results may omit the optional fourth child, while a
failure message occupies that fourth position when emitted. Every sample also
declares `absent_children: ["responseFile"]`.
Runtime elapsed time and timestamp counters remain normalized. Received bytes
are exact for empty Debug Sampler responses and normalized only for
variable-bearing responses whose diagnostic lines include runtime identity/time.

Duration outcomes and numeric exception/result messages are candidate-unobserved
until the pinned oracle run. The ignored `oracle-runs/assertions-full/` paths
named by the manifests are future output locations only; this checkout contains
no captured oracle evidence for these cases.

Each case is bounded to one thread and one iteration. No external script
engine, plugin, network, file, or process capability is required by these core
cases. Manifest `execution.sample_count` values are planned from static
topology (`sample_count_status: "planned-from-topology"`); they are not observed
counts (`sample_count_asserted: false`, `observed_sample_count: null`).

No profile row is promoted by adding these inputs.  Runtime/Java provenance is
left unobserved (`null`) because these cases are static and have not been
executed. A conformance run must
execute each exact command from its manifest with the verified
`apache-jmeter-5.6.3.zip` artifact and retain raw output only under ignored
`oracle-runs/` paths.
