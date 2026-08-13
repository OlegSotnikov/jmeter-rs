# Campaign evidence descriptor

`evidence.schema.json` is the machine-checkable schema for future TEST-003
campaign result records. `evidence.example.json` is deliberately a static
scaffold record: it links all 41 canonical top-level invariants to their source
targets (including the generated `jtl_model`, pure `bridge_rmi`, and
`save_config` targets) and retains the two additional source/profile IDs through
`coverage_ids` (`JTL-XML-WIRE-PROBE-001` and `PLUG-003`). It uses
`planned`/`not-run` statuses because no cargo-fuzz, subprocess, Java, or
network execution is part of this repository change.

The canonical count is an inventory boundary, not a coverage reduction:
`JTL-XML-WIRE-PROBE-001` is a focused sub-probe of `JTL-XML-WIRE-001`, while
`PLUG-003` is the compatibility/profile reference covered by
`PLUGIN-JSON-PREFLIGHT-001`. Both remain explicit in the descriptor.

The schema requires the active compatibility profile, exact pinned
`libfuzzer-sys` version, actual runner versions when a campaign is executed,
flags, invariant statuses, artifact hashes when present, and the corpus
provenance path. A campaign owner may copy the example into an external CI
artifact or a new result record, fill the actual nightly and cargo-fuzz values,
and update statuses only with campaign evidence. The example is not profile
promotion evidence.
