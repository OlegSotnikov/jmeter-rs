<!-- SPDX-License-Identifier: Apache-2.0 -->

# File-backed function corpus

This original, local-only corpus covers the JMeter 5.6.3 file/function
surface used by `FUNC-001` and `FUNC-002`: `__FileToString`,
`__StringFromFile`, `__StringToFile`, `__CSVRead`, and `__XPath`.

Each case is finite and self-contained:

| case | purpose | bound |
|---|---|---|
| `basic` | text/UTF-8/default/UTF-16 reads, CSV selectors, XPath, writes, missing-file sentinels, and shared-source UDV/sampler cursor probes | 1 user, 3 iterations, eight small inputs |
| `concurrency` | two users sharing file-function definition state and finite cursors; value/arrival mapping is planned only | 2 users, 1 iteration, two-line/two-row inputs |
| `negative` | missing, empty, blank-line, truly ragged multi-row CSV, bounded sequence, malformed XML, and malformed XPath-expression inputs; negative invariants are planned only | 1 user, 1 iteration, six materialized inputs plus three missing paths |
| `resource` | finite file/CSV resource design, without runtime rejection claims | 1 user, 1 iteration, 16 lines and one CSV row |
| `coverage` | enabled comparator-backed labels and sequence-variable projection for dynamic filenames, independent StringFromFile occurrences, naive CSV delimiter splitting, and XPath, plus a disabled unknown/case-sensitive preservation probe | 1 user, 3 enabled samples and 1 disabled sampler, four small inputs |

The plans, properties, inputs, manifests, expectations, and provenance files
are original project files. No Apache plan, JTL, binary, machine path, secret,
ambient file, or public service is included. `outputs/` in `basic` is ignored
because `__StringToFile` writes only to that case-local path when an explicitly
requested oracle run is performed.

`basic/expected/string-to-file-artifacts.json` is the corresponding
`file-artifact-contract`: it records the two future output paths, UTF-8 and
UTF-16LE encodings, exact byte counts, and SHA-256 digests. The contract does
not claim that either output exists in the repository.

The basic plan deliberately uses `inputs/lines.txt` for both the two UDV
occurrences and the two sampler occurrences, making occurrence identity
observable instead of allowing a path-only cursor to pass. The pinned JMeter
5.6.3 function documentation says an unbounded sequence restarts at the
beginning after EOF, so the third iteration is represented as a source-backed
recycle declaration. The XPath UDV uses a distinct file/expression key because
JMeter caches XPath containers by that pair. Runtime oracle evidence remains
unobserved.

Each manifest carries a finite `fixture-bounds` declaration. Bounds document
the intended design and are not runtime rejection evidence; the current
validator does not enforce the custom concurrency, negative-error, or resource
invariant schemas.

The `case.json` command templates are declarative: a future runner resolves the
explicit `<case-root>` token before changing directory, resolves all plan and
property paths below it, and must verify JVM `file.encoding=UTF-8`. Locale is
`en-US` and timezone is UTC. Output arguments use `<ignored>/` placeholders.
Only standard JTL projection fields are comparator-enforced. The current
debug projection parser can assert line-valued variables; multiline
UTF-8/default/UTF-16 reads remain exact input/provenance and future-artifact
contracts rather than fabricated runtime variable claims. Disabled-source,
negative-error, concurrency-order, and resource-bound contracts remain
explicitly declarative until their comparison schema exists. Static validation
checks XML, JSON, path safety, hashes, and finite design declarations without
launching Java, JMeter, or a subprocess. The profile remains `planned`; these
manifests do not promote conformance evidence.
