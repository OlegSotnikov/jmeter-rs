<!-- SPDX-License-Identifier: Apache-2.0 -->

# FUNC-001 string/function corpus

This directory contains original, hand-authored JMX inputs for the Apache
JMeter 5.6.3 function vocabulary. The `smoke` case enables only values whose
inputs and result are deterministic without a host, clock, random source,
file, response, or script engine. It retains the remaining built-in names in
disabled inventory rows so the case cannot silently narrow the 49-name
surface. The `invalid` case records case-sensitive unknown names, undefined
references, malformed arguments, and representable bounds.

`expected/semantic.json` files use the repository's supported `jtl-xml`
expectation schema. They are static comparator contracts, not captured JMeter
output. This task intentionally did not execute Java, JMeter, a local server,
or an oracle subprocess; therefore the invalid runtime category/value rows
remain explicitly not-run and no localized diagnostic is fabricated. The
smoke and accepted-boundary samples do expose deterministic variable side
effects through DebugSampler response projections.

The smoke split probe seeds `parts_5=stale`, splits four values (including
JMeter's `?` placeholder for the adjacent delimiters), and compares a
later DebugSampler label containing the unresolved `${parts_5}` reference; the
same sample projects the base `parts` value, `parts_n`, and every split slot.
The invalid case seeds `parts_3=stale`, uses comma-bearing `one\,two`
with an empty delimiter so the accepted default-comma behavior is
distinguishable, then retains the unresolved `${parts_3}` reference in the
same accepted sampler label after cleanup. It projects the base `parts` value,
numbered split slots, the empty-prefix slots, and the `__intSum` output
variable. The manifests still pin the 5.6.3 artifact, source revision, and
SHA-512 digest so a separately authorized oracle run can be reproduced later.

`smoke/thread-scope` is a bounded two-thread, one-iteration static contract.
It exposes `__threadNum`, `__counter`, and `__split` through one DebugSampler
per thread. Sample count and stable JTL attributes are comparator fields, but
cross-thread ordering and per-thread variable values remain explicitly planned
constraints because no oracle output was captured.

The complete 49-name built-in inventory is retained in the smoke expectation.
Its 25 capability-dependent rows are intentionally disabled and are not
golden coverage: `__BeanShell`, `__CSVRead`, `__FileToString`, `__Random`,
`__RandomDate`, `__RandomFromMultipleVars`, `__RandomString`,
`__StringFromFile`, `__StringToFile`, `__TestPlanName`, `__UUID`, `__XPath`,
`__groovy`, `__javaScript`, `__jexl2`, `__jexl3`, `__log`, `__logn`,
`__machineIP`, `__machineName`, `__regexFunction`, `__samplerName`,
`__threadGroupName`, `__threadNum`, and `__time`. The optional JMeter Plugins
functions `__substring` and `__strLen` are represented only as unresolved
negative descriptors; they are not claimed as 5.6.3 built-ins. No golden
coverage is invented for any disabled or external function.

Each case declares its fixture directory as the working directory. Its command
recipe therefore uses an explicit repository-relative path from that directory
to the pinned JMeter binary and `<ignored>/...` oracle-output placeholders, with
the profile's en-US locale, UTF-8 charset, and UTC allowlist. On the Linux
runner this is expressed as `LC_ALL=en_US.UTF-8` and `LANG=en_US.UTF-8`. The
recipe is metadata only and has not been executed here.

The smoke and invalid deterministic rows use the profile's en-US/UTC/UTF-8
environment and a single user/iteration; the scope contract is the explicit
two-thread exception. Property and variable side effects are called out in the
static expectation rather than inferred from a generated result. The
`sample_count_asserted` flag in each case manifest is true because the current
comparator enforces the statically declared topology count; it is not evidence
that an oracle sample count was observed.
