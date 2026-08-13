<!-- SPDX-License-Identifier: Apache-2.0 -->

# ELEM-008 processor and extractor corpus

This source-only corpus covers the Apache JMeter 5.6.3 pre-processor,
post-processor, and extractor wire surface for `FX-ELEMENTS-CORE-001` and
`ELEM-008`.  The plans are original, bounded inputs; they are not copies of
the pinned JMeter distribution and no Java/JMeter process was run while this
corpus was authored.

`core` carries a local response corpus (HTML, JSON, XML, text, headers, and a
malformed payload), the ordered processor topology, and candidate variable
snapshots.  Extracted values are deliberately `null`/`unobserved`: the pinned
source establishes property names, match/default/error contracts, and phase
ordering, but it does not establish runtime output without a response-bearing
oracle run.  `negative-bounds` isolates empty/malformed input, invalid match
numbers, argument-cardinality errors, and resource limits.

The disabled script, JDBC, legacy BSF, HTTP modifier, result-action, and
unknown plug-in nodes are retained as serialized inputs. Their runtime
behavior is external or unavailable; the expectations require a typed
capability outcome and lossless source preservation rather than a fabricated
result. They do not add a direct external boundary to this native core fixture.
The aggregate `ELEM-008` profile row separately declares the JVM, service, and
plugin boundaries required by the complete processor surface.

All paths and SHA-256 values are declared in the case manifests and
provenance.  `execution.status` is `not-run-static`; these files are planned
contracts, not conformance evidence.
