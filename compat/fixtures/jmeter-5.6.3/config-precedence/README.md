<!-- SPDX-License-Identifier: Apache-2.0 -->

# Apache JMeter 5.6.3 configuration precedence corpus

This is a small, original, no-network configuration corpus for `FX-CONFIG-001`.
It covers the configuration-affecting portions of `CFG-001`, representative
documented property families for `CFG-002`, and the fixed environment inputs
that can be checked without an OS matrix for `CFG-003`.

The property files intentionally exercise:

- initial `-p` loading followed by fixture-local `user.properties` and
  `system.properties`;
- the documented startup phases (`-p`, `-j`/logging initialization, implicit
  user/system files, then remaining property options) while keeping the
  effective property merge order explicit;
- repeated `-q` files, with the second file overriding the first;
- repeated same-key `-J` and `-D` values, including `-Jcfg.empty=` and the
  actual `-Dcfg.system.remove=` removal vector;
- repeated `-S` system-property files, with the second file overriding the
  first;
- `-G` key/value and file forms, which populate a remote-only property map;
  these are explicitly a static projection and are unobservable without a
  remote worker run;
- Java `.properties` escapes, Unicode escapes, continuation lines, empty
  values, duplicate keys, and a literal UTF-8 property input; and
- an explicit case-root working directory, UTF-8 JMX metadata, requested
  profile locale `en-US`, UTC, requested UTF-8 default charset, and the
  profile's empty inherited-environment allowlist.

The case declares finite input, output, process, artifact, time, operation,
and property bounds. They are future-runner limits: the static fixture checker
only validates that the declarations are finite and well-shaped; it does not
start or constrain a process here.

`case.json`, `provenance.json`, and `expected/semantic.json` are intentionally
static and say `not_run`; their process exit and sample count are `null`.
They contain no Java/JMeter output, process result, log text, or host-specific
value. The expected maps are partial, explicitly selected configuration
projections: omitted keys are not implicit empty/default assertions, and
explicit removals are listed separately. Every `-G` scenario also lists the
projected keys as absent from both local JMeter and Java system maps. The
literal UTF-8 property is retained as a byte probe; its effective
`Properties.load(InputStream)` value is `null`/oracle-pending because the
decoder is ISO-8859-1.

`expected/semantic.json` declares the repository validator's extension schema
`jmeter-rs.configuration-projection` and `format=configuration-projection`.
Its `validation_contract` records the required sections and invariants,
including the remote-only `-G` rule and the selected/omitted-key rule. The
repository fixture validator checks custom-schema identity, references, paths,
and hashes; it does not execute this configuration projection comparator.
The maps remain pending a differential run with the pinned Apache JMeter 5.6.3
artifact. Raw evidence belongs only in the ignored `oracle-runs/` directory.

The command templates resolve every fixture input relative to `<case-root>`
(`compat/fixtures/jmeter-5.6.3/config-precedence`) and use explicit
`<jmeter-home>/bin/jmeter` and `<java-home>/bin/java` placeholders. The runner
must chdir to the case root before resolving argv paths, load the user/system
paths named by the initial `-p` file from the case root (then the declared
JMeter `bin` fallback), and reject ambient lookup. The empty
inherited-environment allowlist means a future harness must configure Java and
JMeter explicitly. The profile locale `en-US` must be materialized as an
installed target-OS locale with an explicit UTF-8 codeset—for example,
`en_US.UTF-8` on POSIX or `en-US` on Windows—and must fail closed if unavailable
rather than silently using `C`/POSIX or an uninstalled alias. Locale, timezone,
and default-charset fields are requested inputs with null/pending observations.
The future runner must record both `System.getProperty("file.encoding")` and
`Charset.defaultCharset().name()`; the requested UTF-8 value is not evidence.
No oracle process has run, so Java vendor/version, target triple, OS image,
launcher behavior, path-separator behavior, and Linux/Windows/macOS filesystem
behavior remain harness gaps.

The configuration projection invariants have stable IDs in
`expected/semantic.json`. They are declared but not enforced by the current
fixture validator. Comparator enforcement can become true only after the
dedicated future comparator `CMP-CONFIG-PROJECTION-001` is implemented and
identified; no current comparator execution is claimed.

The fixture is not a claim for the complete CLI grammar, usage text, report
restrictions, or process-exit behavior. Those belong to the separate
`FX-CLI-001` evidence row and to the CLI/process feature IDs.

## Static checks

From the repository root, without starting Java, JMeter, a fixture server, or
any oracle subprocess:

```sh
python3 -m json.tool compat/fixtures/jmeter-5.6.3/config-precedence/case.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/config-precedence/provenance.json >/dev/null
python3 -m json.tool compat/fixtures/jmeter-5.6.3/config-precedence/expected/semantic.json >/dev/null
```

The repository fixture checker additionally verifies all recorded SHA-256
values and the pinned profile references. A future oracle run must use the
argv templates in `case.json` without dropping the attached/separate `-G`
vectors, execute from the declared case root, verify the effective JVM
locale/charset—including both JVM encoding observations—and record exact
Java/runtime metadata before any expectation is promoted from static projection
to observed evidence. The current oracle option parser has known gaps for
`-p`, repeated `-q`, `-S`, `-D`, and `-G`; those vectors are intentional and
must not be removed or weakened to make the parser accept the fixture.
