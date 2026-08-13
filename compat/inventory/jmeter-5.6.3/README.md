<!-- SPDX-License-Identifier: Apache-2.0 -->

# CFG-002 property inventory

`properties.json` is a generated, machine-readable inventory for compatibility
row `CFG-002` (documented property families/defaults). It is inventory data,
not conformance evidence and does not promote the profile row from `planned`.

Generate or check it from the repository root:

```sh
cargo xtask property-inventory --generate
cargo xtask property-inventory --check
```

The task reads only these six files from the ignored local, profile-pinned
Apache JMeter 5.6.3 extraction:

```text
jmeter-oracle-cache/apache-jmeter-5.6.3/bin/jmeter.properties
jmeter-oracle-cache/apache-jmeter-5.6.3/bin/reportgenerator.properties
jmeter-oracle-cache/apache-jmeter-5.6.3/bin/saveservice.properties
jmeter-oracle-cache/apache-jmeter-5.6.3/bin/system.properties
jmeter-oracle-cache/apache-jmeter-5.6.3/bin/upgrade.properties
jmeter-oracle-cache/apache-jmeter-5.6.3/bin/user.properties
```

## Provenance and redistribution

The six inputs are Apache JMeter 5.6.3 `rel/v5.6.3` source files at commit
`34a2785748e9e0b14702595e8682c387869deda3`. Each source file carries the
Apache-2.0 header and has a pinned source link:

- [`bin/jmeter.properties`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/bin/jmeter.properties)
- [`bin/reportgenerator.properties`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/bin/reportgenerator.properties)
- [`bin/saveservice.properties`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/bin/saveservice.properties)
- [`bin/system.properties`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/bin/system.properties)
- [`bin/upgrade.properties`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/bin/upgrade.properties)
- [`bin/user.properties`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/bin/user.properties)

The generated metadata records each raw source SHA-256, source path, source
URL, pinned artifact digest, the Apache source `LICENSE`/`NOTICE` paths,
Apache-2.0 license expression, and the repository `LICENSE`/`NOTICE` paths.
The root `NOTICE` carries the Apache JMeter attribution for this inventory and
the registry data. The source extraction and JMeter archive remain ignored
oracle/cache material; the archive, binaries, JARs, and complete upstream
notice bundle are not redistributed.

The reproducible transformation is exactly the generator command above. It
reads the six regular files, hashes raw bytes, parses selected declarations in
physical order, and emits stable pretty JSON with a trailing line feed. It
retains selected declaration spelling/raw lines for traceability but does not
copy the source files wholesale, decode Java properties, merge effective
values, retrieve the source, or invoke Java/JMeter. The generated metadata
records the modification notice and redistribution review; see
[`docs/third-party-provenance.md`](../../../docs/third-party-provenance.md)
for the repository license/provenance ledger.

Each source file records its repository-relative path, raw-byte SHA-256, byte
count, line ending kind, and source-order entries. Entries retain physical
line order, duplicate occurrences, source spelling, active/commented state,
empty values, and the exact separator. The `default` field is the exact source
spelling after that separator (including continuation lines); `default_value`
is the first-line parsed value and is not Java-escape decoded. A source comment
section heading is copied only when it is bounded by separator comments (with
the one upstream heading whose opening separator is omitted handled explicitly);
the entry also carries a normalized `family_id`. Consumer and sensitivity
fields are intentionally `unresolved`: this inventory does not infer runtime
readers or whether a value is secret. No Java `.properties` decoding or
effective property merge is performed.

The generator is offline and bounded: it makes no JVM, subprocess, or network
call, limits each source file to 8 MiB and the six-file tree to 32 MiB, and
limits the generated output to 64 MiB. `--check` builds the same bytes and
reports `INVENTORY-DRIFT` when the checked-in file differs. The output header
records the generator command, source policy, profile version, and pinned
JMeter source commit.
