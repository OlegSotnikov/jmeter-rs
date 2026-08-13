# JMeter compatibility surface

This is the compatibility inventory for the Rust implementation.  It is a
research baseline, not an implementation claim.  The compatibility target is
the behavior that a user can observe through a JMX plan, a JTL result file, the
command line, the documented configuration, and the built-in test elements.
The canonical publication repository for this project is
[`OlegSotnikov/jmeter-rs`](https://github.com/OlegSotnikov/jmeter-rs).

## Baseline

As of 2026-08-12, the latest stable tag visible in the Apache JMeter upstream
repository is `rel/v5.6.3`, commit
`34a2785748e9e0b14702595e8682c387869deda3`.  The release page identifies
5.6.3 as the latest release.  Release candidates and `master` are not the
compatibility baseline.

| item | pinned value | primary source |
|---|---|---|
| release | Apache JMeter 5.6.3 | [release page](https://github.com/apache/jmeter/releases/tag/rel/v5.6.3) |
| source snapshot | `34a2785748e9e0b14702595e8682c387869deda3` | [upstream tree](https://github.com/apache/jmeter/tree/34a2785748e9e0b14702595e8682c387869deda3) |
| user manual | 5.6.3 manual set | [manual index](https://jmeter.apache.org/usermanual/index.html) |
| runtime | Java 8 or later; Java 17 or later recommended | [requirements and changes](https://jmeter.apache.org/usermanual/get-started.html#requirements), [5.6.3 changes](https://jmeter.apache.org/changes.html) |
| component catalog | current built-in GUI/test-element catalog | [component reference](https://jmeter.apache.org/usermanual/component_reference.html) |
| save-service aliases | JMX/JTL aliases and conversion version 5.0 | [saveservice.properties](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/bin/saveservice.properties) |

The following tier labels are used throughout this document:

- **exact**: a finite, testable Rust contract.  Existing JMX/JTL/CLI behavior
  must be accepted and emitted with the same values, ordering where it is
  observable, defaults, and failure behavior.
- **staged**: feasible in compatibility phases, but too broad or expensive to
  complete before the core CLI/format/execution contract.  It must still have
  a named compatibility test before being called supported.
- **external**: the JMeter contract is finite, but the behavior depends on an
  external server, driver, interpreter, JVM class, OS facility, certificate,
  or arbitrary plugin.  The Rust side needs an adapter and a conformance test;
  reimplementing the dependency is not part of the core contract.

“100% compatible” must therefore mean “100% of the declared matrix for the
pinned release and declared external adapters”, not an unbounded promise to
run every third-party JMeter plugin or every possible remote service.

## Command line and process behavior

The complete 5.6.3 option set is defined in
[`JMeter.java`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/core/src/main/java/org/apache/jmeter/JMeter.java)
and documented in [Getting Started, full options](https://jmeter.apache.org/usermanual/get-started.html#options).
`-E/--proxyScheme` is present in the source and proxy subsection even though
older generated option text omitted it; it must be accepted.

| short | long | argument/meaning |
|---|---|---|
| `-?` | `--?` | print command options and exit |
| `-h` | `--help` | print usage/help and exit |
| `-v` | `--version` | print version and exit |
| `-p` | `--propfile` | primary JMeter property file |
| `-q` | `--addprop` | additional JMeter property file; repeatable |
| `-t` | `--testfile` | JMX test plan; `LAST` means last GUI-loaded plan |
| `-l` | `--logfile` | JTL result file; `LAST` derives a `.jtl` name |
| `-i` | `--jmeterlogconf` | Log4j2 configuration |
| `-j` | `--jmeterlogfile` | JMeter run log; `LAST` derives a `.log` name |
| `-n` | `--nongui` | non-GUI/CLI mode |
| `-s` | `--server` | start remote JMeter server |
| `-E` | `--proxyScheme` | HTTP proxy scheme |
| `-H` | `--proxyHost` | HTTP proxy host |
| `-P` | `--proxyPort` | HTTP proxy port |
| `-N` | `--nonProxyHosts` | pipe-separated non-proxy host patterns |
| `-u` | `--username` | proxy username |
| `-a` | `--password` | proxy password |
| `-J` | `--jmeterproperty` | local JMeter `key=value`; repeatable |
| `-G` | `--globalproperty` | remote JMeter `key=value` or properties file; repeatable |
| `-D` | `--systemproperty` | Java system `key=value`; repeatable |
| `-S` | `--systemPropertyFile` | additional Java system-property file; repeatable |
| `-f` | `--forceDeleteResultFile` | delete existing result/report output before running |
| `-L` | `--loglevel` | `[category=]level`; repeatable |
| `-r` | `--runremote` | start hosts in `remote_hosts` |
| `-R` | `--remotestart` | comma-separated remote hosts; overrides `remote_hosts` |
| `-d` | `--homedir` | JMeter home directory |
| `-X` | `--remoteexit` | stop remote servers after CLI test |
| `-g` | `--reportonly` | generate dashboard from an existing JTL |
| `-e` | `--reportatendofloadtests` | generate dashboard after load test; requires `-l` |
| `-o` | `--reportoutputfolder` | dashboard output directory; must be safe/empty unless `-f` |

Required process semantics include:

1. `-n` requires a test plan.  GUI-only defaults, `-r`, `-R`, and `-X` have
   the same mode restrictions as upstream.  `-g` is report-only and has
   incompatible options enforced by the parser.
2. Options and property files are processed in this order: `-p`; primary
   `jmeter.properties`; `-j`; logging initialization; `user.properties`;
   `system.properties`; remaining command-line options.  `-q`, `-J`, `-G`,
   `-D`, and `-S` are ordered and repeatable as upstream specifies.
3. A normal CLI test does not call `System.exit`; fatal startup/errors may
   exit with status 1.  `jmeterengine.stopfail.system.exit` and
   `jmeterengine.remote.system.exit` alter shutdown behavior.  `-X` stops
   remote engines.  Do not infer exit status only from whether samples failed;
   test the complete process-level behavior.
4. `jmeter.log` is Log4j2-configured and `-j` can contain a paired-quote
   `SimpleDateFormat`.  CLI diagnostics and usage text are observable output.
5. `-H/-P/-N/-u/-a/-E` set the corresponding HTTP/HTTPS Java system proxy
   properties; credentials on a command line can be visible to other users.

Primary sources: [CLI documentation](https://jmeter.apache.org/usermanual/get-started.html#non_gui),
[shutdown behavior](https://jmeter.apache.org/usermanual/get-started.html#shutdown),
[source option declarations](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/core/src/main/java/org/apache/jmeter/JMeter.java#L178-L319).

## JMX test-plan format

JMX is an XML serialization contract, not merely a convenient input format.
The current root shape is:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<jmeterTestPlan version="1.2" properties="5.0" jmeter="5.6.3">
  <hashTree>
    <TestPlan guiclass="TestPlanGui" testclass="TestPlan"
              testname="Test Plan" enabled="true">
      ...typed properties...
    </TestPlan>
    <hashTree>...</hashTree>
  </hashTree>
</jmeterTestPlan>
```

Compatibility requirements:

- Preserve the alternating test-element/`hashTree` topology, child order,
  enabled state, test name, GUI class, test class, and all unknown properties.
- Support the typed property nodes used by the upstream converters:
  `stringProp`, `boolProp`, `intProp`, `longProp`, `floatProp`, `doubleProp`,
  `collectionProp`, `mapProp`, `elementProp`, and `objProp`.  Collections and
  maps preserve order where the source does.
- Treat `guiclass`, `testclass`, `testname`, and `enabled` as special XML
  attributes.  Other element properties are typed child nodes.  XML escaping,
  Unicode, empty values, and absent-vs-empty properties are distinct cases.
- Load the alias map from the 5.0 save-service vocabulary, including historical
  aliases.  Apply the compatibility mappings in
  [`upgrade.properties`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/bin/upgrade.properties)
  when reading older plans.  A plan containing an unknown/deprecated class must
  produce the same safe placeholder/diagnostic behavior rather than silently
  dropping the subtree.
- Resolve relative files from the JMX base as JMeter does; `~/` (configurable
  by `jmeter.save.saveservice.base_prefix`) is relative to the JMX directory,
  while ordinary relative paths use the JMeter working/base rules.
- Preserve JMX `properties` and `jmeter` version metadata on read and write.
  Semantic round-trip is mandatory; byte-for-byte output is a separate golden
  target because XML serializers may differ in insignificant whitespace.

Primary sources: [JMX save service](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/core/src/main/java/org/apache/jmeter/save/SaveService.java),
[test-element converter](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/core/src/main/java/org/apache/jmeter/save/converters/TestElementConverter.java),
[conversion rules](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/core/src/main/java/org/apache/jmeter/save/converters/ConversionHelp.java),
[JMeter sample JMX](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/bin/templates/simple-http-request-test-plan.jmx).

## JTL/results format

JTL means JMeter's sample-result log.  It has two supported formats in 5.6.3:
CSV (the default) and XML.  `db` is a recognized historical value but is not
supported by the current save service.

### XML JTL

The root is `<testResults version="1.2">`.  A normal sample is serialized as
`<sample .../>`; HTTP samples use the `httpSample` alias.  The attribute names
are intentionally abbreviated and must remain compatible:

| attribute | meaning |
|---|---|
| `t` | elapsed time |
| `it` | idle time |
| `lt` | latency |
| `ct` | connect time |
| `ts` | timestamp (start or end according to `sampleresult.timestamp.start`) |
| `s` | successful |
| `lb` | sample label |
| `rc` (`rs` accepted on read) | response code |
| `rm` | response message |
| `tn` | thread name |
| `dt` | data type (`text` or `bin`) |
| `de` | data encoding |
| `by` | received bytes |
| `sby` | sent bytes |
| `sc` / `ec` | sample count / error count |
| `ng` / `na` | group/all active thread counts |
| `hn` | result-event hostname |
| configured sample variables | additional XML attributes |

Child nodes can include assertion results, nested sub-results, `responseData`,
`responseFile`, `responseHeader`, `requestHeader`, `samplerData`, and URL data.
Response data is written as text only by the XML converter; binary results may
be represented by a file reference or a diagnostic placeholder.  If
`responseFile` exists and response data is absent, JMeter reads that file when
loading the result.

### CSV JTL

The header and row columns are configuration-driven and must be emitted in this
order when enabled: `timeStamp`, `elapsed`, `label`, `responseCode`,
`responseMessage`, `threadName`, `dataType`, `success`, `failureMessage`,
`bytes`, `sentBytes`, `grpThreads`, `allThreads`, `URL`, `Filename`, `Latency`,
`Encoding`, `SampleCount`, `ErrorCount`, `Hostname`, `IdleTime`, `Connect`,
then columns for `sample_variables`.  The exact set is controlled by
`jmeter.save.saveservice.*`; `print_field_names` controls the header.

CSV compatibility includes delimiter (default comma, `\\t` for TAB), quoting
and escaping, empty fields, line-ending behavior, UTF-8/default encoding,
timestamp formats `none`, `ms`, or Java `SimpleDateFormat`, strict parsing and
the documented legacy timestamp fallbacks.  CSV cannot represent all fields
with embedded line breaks.  XML and CSV readers must accept files produced by
older JMeter releases when their declared columns differ.

Primary sources: [listeners/JTL documentation](https://jmeter.apache.org/usermanual/listeners.html),
[properties reference, results file section](https://jmeter.apache.org/usermanual/properties_reference.html#results_file_config),
[sample converter](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/core/src/main/java/org/apache/jmeter/save/converters/SampleResultConverter.java),
[CSV implementation](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/core/src/main/java/org/apache/jmeter/save/CSVSaveService.java),
[sample metadata](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/core/src/main/java/org/apache/jmeter/report/core/SampleMetadata.java).

## Built-in test elements

The following is the complete visible 5.6.3 component-reference catalog,
grouped as JMeter presents it.  Names marked **deprecated** remain relevant to
JMX loading even when hidden from the GUI.  “External” here means that the
element needs the named service/driver/runtime; it does not mean the element
can be omitted from the compatibility target.

### Samplers

`FTP Request` (FTP server), `HTTP Request` (including the GraphQL HTTP Request
GUI variant), `JDBC Request` (vendor JDBC driver/database), `Java Request`
(user Java sampler class), `LDAP Request`, `LDAP Extended Request`, `Access Log
Sampler`, `BeanShell Sampler` (BeanShell runtime), `JSR223 Sampler` (script
engine), `TCP Sampler` (TCP endpoint), `JMS Publisher`, `JMS Subscriber`,
`JMS Point-to-Point` (JMS provider/client), `JUnit Request` (JUnit/user test
class), `Mail Reader Sampler` (mail server/JavaMail), `Flow Control Action`,
`SMTP Sampler` (SMTP server/JavaMail), `OS Process Sampler` (host process),
`MongoDB Script (DEPRECATED)` (MongoDB Java driver), and `Bolt Request`
(Neo4j Bolt driver/server).

### Logic controllers

`Simple Controller`, `Loop Controller`, `Once Only Controller`, `Interleave
Controller`, `Random Controller`, `Random Order Controller`, `Throughput
Controller`, `Runtime Controller`, `If Controller`, `While Controller`,
`Switch Controller`, `ForEach Controller`, `Module Controller`, `Include
Controller`, `Transaction Controller`, `Recording Controller`, and `Critical
Section Controller`.

Controller semantics include child traversal order, iteration counts, random
selection, throughput percentages, runtime deadlines, switch labels/indexes,
variable expansion, module replacement, include-file resolution, transaction
parent/sub-result rules, and critical-section locking.  These are core
execution semantics and require deterministic seeded tests where randomness is
involved.

### Listeners and result consumers

`Sample Result Save Configuration`, `Graph Results`, `Assertion Results`, `View
Results Tree`, `Aggregate Report`, `View Results in Table`, `Simple Data
Writer`, `Aggregate Graph`, `Response Time Graph`, `Mailer Visualizer`,
`BeanShell Listener`, `Summary Report`, `Save Responses to a file`, `JSR223
Listener`, `Generate Summary Results`, `Comparison Assertion Visualizer`, and
`Backend Listener`.

The CLI `-l` collector and listeners must share the same `SampleResult` and
save configuration.  GUI visualizations can be staged, but their persisted
test-element properties and JTL behavior cannot be discarded.

### Configuration elements

`CSV Data Set Config`, `FTP Request Defaults`, `DNS Cache Manager`, `HTTP
Authorization Manager`, `HTTP Cache Manager`, `HTTP Cookie Manager`, `HTTP
Request Defaults`, `HTTP Header Manager`, `Java Request Defaults`, `JDBC
Connection Configuration`, `Keystore Configuration`, `Login Config Element`,
`LDAP Request Defaults`, `LDAP Extended Request Defaults`, `TCP Sampler Config`,
`User Defined Variables`, `Random Variable`, `Counter`, `Simple Config
Element`, `MongoDB Source Config (DEPRECATED)`, and `Bolt Connection
Configuration`.

Configuration scope and precedence (test plan, thread group, controller,
sampler), cookie/cache/DNS state, CSV sharing/EOF/recycle behavior, JDBC pool
lifecycle, and variable creation timing are part of the contract.

### Assertions

`Response Assertion`, `Duration Assertion`, `Size Assertion`, `XML Assertion`,
`BeanShell Assertion`, `MD5Hex Assertion`, `HTML Assertion`, `XPath Assertion`,
`XPath2 Assertion`, `XML Schema Assertion`, `JSR223 Assertion`, `Compare
Assertion`, `SMIME Assertion`, `JSON Assertion`, and `JSON JMESPath Assertion`.

### Timers

`Constant Timer`, `Gaussian Random Timer`, `Uniform Random Timer`, `Constant
Throughput Timer`, `Precise Throughput Timer`, `Synchronizing Timer`,
`BeanShell Timer`, `JSR223 Timer`, and `Poisson Random Timer`.

Timer placement, accumulation (timers delay before a sampler), random
distribution, throughput scheduling, synchronization timeout, and the
interaction with scheduler/ramp-up are observable.  Clock-dependent tests
need bounded assertions rather than exact wall-clock values.

### Pre-processors

`HTML Link Parser`, `HTTP URL Re-writing Modifier`, `User Parameters`,
`BeanShell PreProcessor`, `JSR223 PreProcessor`, `JDBC PreProcessor`, `RegEx
User Parameters`, and `Sample Timeout`.

### Post-processors

`Regular Expression Extractor`, `CSS Selector Extractor`, `XPath2 Extractor`,
`XPath Extractor`, `JSON JMESPath Extractor`, `Result Status Action Handler`,
`BeanShell PostProcessor`, `JSR223 PostProcessor`, `JDBC PostProcessor`, `JSON
Extractor`, and `Boundary Extractor`.

Extractor details include match number (`0`, positive, or random), default
values, generated variable names, capture groups, character encoding, XPath
namespace files, JSONPath/JMESPath behavior, and the exact point at which
variables become visible to later elements.

### Miscellaneous and thread groups

`Test Plan`, `Open Model Thread Group`, `Thread Group`, `WorkBench`, `SSL
Manager`, `HTTP(S) Test Script Recorder`, `HTTP Mirror Server`, `Property
Display`, `Debug Sampler`, `Debug PostProcessor`, `Test Fragment`, `setUp
Thread Group`, and `tearDown Thread Group`.

The old report-plan family (`Report Plan`, `Report Table`, `HTML Report
Writer`, `Report Page`, `Line Graph`, and `Bar Chart`) and the BSF family
(`BSF Sampler`, `BSF Assertion`, `BSF PreProcessor`, `BSF PostProcessor`, `BSF
Timer`, and `BSF Listener`) remain legacy aliases in the save-service map.
They are deprecated/hidden in the current UI but must be recognized or mapped
according to `upgrade.properties` when compatibility mode is enabled.

Primary source: [component reference](https://jmeter.apache.org/usermanual/component_reference.html)
and its release source
[`component_reference.xml`](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/xdocs/usermanual/component_reference.xml).

## Variables, properties, and functions

### Expansion rules

Variables are referenced as `${NAME}`.  Functions use `${__name(args)}` (the
parentheses may be omitted for a no-argument function).  Names are
case-sensitive; spaces around variable names are trimmed; undefined variables
and functions are returned unchanged, not treated as errors.  Variables are
thread-local.  JMeter properties are process-wide and are read with
`__property`/`__P` or set with `__setProperty`.

Function instances are shared across threads at the function-definition level,
but each occurrence in a test plan has its own function instance.  Expansion
timing matters: Test Plan fields are processed before thread variables exist,
and configuration elements such as User Defined Variables have their own
processing thread/timing.  Nested variable syntax is not generally supported;
`__V`, `__eval`, and `__evalVar` provide the documented indirection behavior.

### Built-in functions (49 in the 5.6.3 source)

The exact case-sensitive names are:

```text
__BeanShell __CSVRead __FileToString __P __Random __RandomDate
__RandomFromMultipleVars __RandomString __StringFromFile __StringToFile
__TestPlanName __UUID __V __XPath __changeCase __char __counter
__dateTimeConvert __digest __escapeHtml __escapeOroRegexpChars __escapeXml
__eval __evalVar __groovy __intSum __isPropDefined __isVarDefined
__javaScript __jexl2 __jexl3 __log __logn __longSum __machineIP
__machineName __property __regexFunction __samplerName __setProperty __split
__threadGroupName __threadNum __time __timeShift __unescape __unescapeHtml
__urldecode __urlencode
```

This inventory includes input (`StringFromFile`, `FileToString`, `CSVRead`,
`XPath`, `StringToFile`), calculations/randomness (`counter`, sums, random
values, UUID, digest, date/time), string/encoding functions, response
extraction (`regexFunction`), variables/properties, logging, and scripting.
Function behavior must include argument parsing, commas/escaping, defaults,
random bounds, charset/time-zone handling, file cursor sharing, and exact
undefined/error behavior.

### Predefined variables and properties

At runtime JMeter may create `COOKIE_<cookie-name>`,
`JMeterThread.last_sample_ok`, and `START` variables.  Built-in properties
include `START.MS`, `START.YMD`, `START.HMS`, and `TESTSTART.MS`; `START.*`
are also copied to variables.  `START.*` describes JMeter startup, not test
start.

The 5.6.3 [properties reference](https://jmeter.apache.org/usermanual/properties_reference.html)
contains 348 unique documented property names.  The important compatibility
families are:

| family | examples/contract |
|---|---|
| loading/class path | `user.properties`, `system.properties`, `search_paths`, `user.classpath`, `plugin_dependency_paths`, `not_in_menu` |
| HTTP/TLS | `jmeter.httpsampler`, `https.*`, `httpclient*`, `http.proxy*`, parser/cache/redirect limits, Kerberos/SPNEGO |
| save service | `jmeter.save.saveservice.*`, `sample_variables`, `sampleresult.*`, `subresults.disable_renaming` |
| distributed/RMI | `remote_hosts`, `server.*`, `client.*`, `mode`, `num_sample_threshold`, `time_threshold`, `asynch.batch.queue.size` |
| recorder/certificates | `proxy.*`, `proxy.cert.*`, `proxy.content_type_*`, `proxy.headers.remove` |
| scripting | `beanshell.*`, `jsr223.*`, `groovy.utilities`, `javascript.use_rhino`, `function.cache.per.iteration` |
| reporting | `jmeter.reportgenerator.*`, `aggregate_rpt_pct1..3`, `generate_report_ui.generation_timeout` |
| GUI/persistence | `language`, look-and-feel, toolbar/icon, `undo.history.size`, `onload.expandtree`, JMX backup/autosave properties |
| protocol-specific | JDBC, LDAP, TCP, cookies/cache, mail, and backend-listener properties |

Unknown properties must survive configuration loading and be available to
scripts/plugins.  Properties are normally resolved during class loading, so a
runtime `__setProperty` does not retroactively change every component.

Primary sources: [functions and variables manual](https://jmeter.apache.org/usermanual/functions),
[function source directory](https://github.com/apache/jmeter/tree/34a2785748e9e0b14702595e8682c387869deda3/src/functions/src/main/java/org/apache/jmeter/functions),
[properties reference](https://jmeter.apache.org/usermanual/properties_reference.html),
[function names in source](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/functions/src/main/java/org/apache/jmeter/functions/AbstractFunction.java).

## Scripting and user code

The JSR223 sampler/assertion/listener/timer/pre/post-processor contract exposes
JMeter context objects and depends on a JSR223-compatible engine.  Groovy is
the recommended compiled/cached engine in the 5.6.3 documentation; Java,
BeanShell, and JavaScript do not all implement `Compilable` in the same way.
Script variables and objects (`vars`, `props`, `ctx`, `prev`, `sampler`, `log`,
`OUT`, and the element-specific bindings) are observable APIs.

BeanShell remains supported and commonly appears in JMX plans.  BSF elements
are deprecated.  `__javaScript` uses the Rhino dependency in the release
build; JEXL2/JEXL3 functions require their corresponding Commons JEXL
versions.  A Rust implementation should provide an explicit external-runtime
adapter for each engine, preserve script text and language names in JMX, and
report “engine unavailable” with JMeter-compatible sample failure behavior.

Java Sampler and JUnit Request require loading arbitrary user classes.  Exact
compatibility requires a JVM adapter or a documented process bridge; translating
arbitrary Java bytecode into Rust is not a core implementation task.

Primary sources: [scripting component reference](https://jmeter.apache.org/usermanual/component_reference.html#JSR223_Sampler),
[functions build dependencies](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/functions/build.gradle.kts),
[components build dependencies](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/components/build.gradle.kts).

## Reporting and real-time output

JMeter has three distinct reporting surfaces:

1. Listener output (`-l`/JTL and GUI listeners), including Aggregate Report,
   Summary Report, graphs, result tree/table, Simple Data Writer, and Backend
   Listener.
2. CLI dashboard generation: `-g input.jtl` or `-e` after `-l`, with `-o`
   selecting the output directory.  The default HTML report computes APDEX,
   request summary, statistics, errors, top-five errors by sampler, and
   time-series/distribution graphs.
3. Backend listeners: Graphite text/pickle senders, InfluxDB metrics, and raw
   InfluxDB output.  These require external network services and credentials.

The dashboard graph contract includes response-time percentiles and
distribution, active threads, time-vs-threads, bytes throughput, response
times, latencies, connect time, hits/sec, response codes/sec, total and
transaction TPS, response/latency-vs-request, and synthetic response-time
distribution.  Defaults include 60-second overall granularity, APDEX
satisfied threshold 500 ms, tolerated threshold 1500 ms, and a 20,000-sample
statistical window; property overrides are part of compatibility.

JMeter intentionally notes that dashboard percentile estimates can differ from
the GUI Aggregate Report.  The Rust implementation must preserve the separate
algorithms rather than “fixing” them into one value.

Primary sources: [dashboard manual](https://jmeter.apache.org/usermanual/generating-dashboard.html),
[report generator defaults](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/bin/reportgenerator.properties),
[listeners](https://jmeter.apache.org/usermanual/listeners.html),
[real-time results](https://jmeter.apache.org/usermanual/realtime-results.html).

## Distributed execution

JMeter distributed mode is an RMI client/server protocol:

- `jmeter-server`/`-s` starts a worker; the client uses `-r` or `-R`.
- `remote_hosts` is comma-separated (`host[:port]`); default registry port is
  1099.  `server.rmi.localport` and `client.rmi.localport` constrain reverse
  connections for firewalls.
- `-Gkey=value`/`-Gfile` sends properties to workers; `-X` requests worker
  shutdown; `server.exitaftertest` can make a worker exit after one test.
- Since JMeter 4.0, RMI SSL is enabled by default.  The default keystore is
  `rmi_keystore.jks`, alias `rmi`, password `changeit`; the official helper
  creates a seven-day key pair.  All nodes need matching JMeter/Java versions
  and valid trust/keystore settings.
- The client sends the JMX plan to every server, but does not send data files,
  scripts, drivers, certificates, or arbitrary dependencies.  The same plan
  runs in full on every server; 1,000 threads on six workers means 6,000
  injected threads, not 1,000 divided among workers.
- Sample sender modes are `Standard`, `Hold`, `DiskStore`, `StrippedDiskStore`,
  `Batch`, `Statistical`, `Stripped`, `StrippedBatch`, `Asynch`,
  `StrippedAsynch`, or a custom `SampleSender`; stripping response data and
  batch thresholds change observable JTL results and throughput.

Exact RMI wire/API compatibility is an external-runtime/staged surface for
Rust.  A practical first adapter can run a JMeter worker and use a Rust client
or provide a Rust-native protocol only after differential tests establish the
same semantics.

Primary sources: [remote testing manual](https://jmeter.apache.org/usermanual/remote-test.html),
[distributed step-by-step](https://jmeter.apache.org/usermanual/jmeter_distributed_testing_step_by_step.html),
[remote properties](https://jmeter.apache.org/usermanual/properties_reference.html#remote),
[distributed runner source](https://github.com/apache/jmeter/tree/34a2785748e9e0b14702595e8682c387869deda3/src/core/src/main/java/org/apache/jmeter/engine).

## HTTP proxy, recorder, mirror server, and certificates

The HTTP(S) Test Script Recorder is a real intercepting proxy used to record a
browser session into a JMX tree.  Compatibility includes proxy bind address and
port, include/exclude URL and content-type filters, suggested exclusions,
header removal (Cookie and Authorization are always removed), grouping/target
controller, sampler naming, transaction pauses, redirect handling, binary
request files, and generated HTTP sampler properties.  The default pause is
5,000 ms; default suggested exclusions cover common images/CSS/JS/font types.
The recorder must support HTTP CONNECT and HTTPS interception and preserve
recorded request bodies/headers in the resulting JMX.

JMeter's HTTP Mirror Server is a deterministic local fixture useful for sampler
and integration tests.  It is a separate CLI/UI surface and must not be
confused with the outbound proxy used by HTTP samplers.

TLS/certificate compatibility includes:

- HTTP samplers accept untrusted/expired certificates by default (unless a
  plan/property explicitly changes trust behavior), support client
  certificates, and have SSL Manager/Keystore Configuration controls.
- Recorder certificates use `proxy.cert.directory`, `proxy.cert.file`
  (`proxyserver.jks`), type `JKS`, keystore/key password `password`, alias
  selection, seven-day default validity, dynamic keys, and TLS protocol
  settings.  Recording HTTPS needs the JDK `keytool` in the upstream workflow.
- RMI has its separate SSL keystore/truststore settings described above.
- SMTP can use a local trust store or trust-all mode.

These are external cryptographic/network contracts.  Use local fixture servers
and generated test certificates in integration tests; do not use public
internet endpoints in correctness tests.

Primary sources: [proxy step-by-step](https://jmeter.apache.org/usermanual/jmeter_proxy_step_by_step.html),
[recorder component reference](https://jmeter.apache.org/usermanual/component_reference.html#HTTP%28S%29_Test_Script_Recorder),
[proxy/certificate properties](https://jmeter.apache.org/usermanual/properties_reference.html#test_script_recorder),
[HTTP proxy source](https://github.com/apache/jmeter/tree/34a2785748e9e0b14702595e8682c387869deda3/src/protocol/http/src/main/java/org/apache/jmeter/protocol/http/proxy),
[SSL requirements](https://jmeter.apache.org/usermanual/get-started.html#opt_ssl).

## Plugins and extension loading

The finite built-in catalog is not the complete JMeter ecosystem.  JMeter
loads component/plugin JARs from `lib/ext` and `search_paths`, utility and
dependency JARs from `lib`, `user.classpath`, and
`plugin_dependency_paths`, and discovers component classes/functions through
the classpath.  A plugin can add samplers, controllers, assertions, timers,
pre/post-processors, listeners, functions, GUI classes, result senders, or
script engines.  The JMX stores class/GUI aliases and arbitrary plugin
properties.

Required compatibility policy:

- Built-ins and historical aliases are a finite exact target.
- Arbitrary Java plugins are an external runtime target.  Provide a JVM
  compatibility bridge or a documented Rust plugin ABI; do not silently map a
  missing Java class to a different sampler.
- Plugin discovery, classpath ordering, duplicate aliases, `not_in_menu`,
  plugin dependencies, and unknown-element preservation need contract tests.
- Third-party plugin collections are deliberately not counted in the baseline;
  each plugin/engine must be added to the matrix with its own version and
  fixture.

Primary sources: [classpath and plugin loading](https://jmeter.apache.org/usermanual/get-started.html#classpath),
[extension tutorial](https://jmeter.apache.org/extending/jmeter_tutorial.pdf),
[plugin paths in properties reference](https://jmeter.apache.org/usermanual/properties_reference.html#classpath),
[upstream class-loader setup](https://github.com/apache/jmeter/blob/34a2785748e9e0b14702595e8682c387869deda3/src/core/src/main/java/org/apache/jmeter/JMeter.java#L1020-L1045).

## GUI and persistence expectations

GUI mode is for creating/debugging plans; upstream explicitly recommends CLI
mode for load testing.  Nevertheless, GUI-visible persistence is part of JMX
compatibility:

- `guiclass` values determine how a test element is edited and displayed;
  opening a JMX must preserve them even in a headless CLI implementation.
- GUI saves create numbered backups by default (`jmeter.gui.action.save.backup_on_save=true`),
  default backup directory `${JMETER_HOME}/backups`, and default maximum of ten
  backups; `save_automatically_before_run=true` saves before a run.
- Recent-project `LAST` resolution, templates (`template.files`), WorkBench,
  expanded tree state, undo history, localization, look-and-feel, toolbar/icon
  settings, and `not_in_menu` are GUI persistence/configuration surfaces.
- A staged Rust GUI may initially be a separate editor or a headless-safe
  preservation layer, but it must round-trip plans produced by JMeter GUI
  without rewriting unknown fields.

Primary sources: [GUI/save properties](https://jmeter.apache.org/usermanual/properties_reference.html#backup),
[getting started](https://jmeter.apache.org/usermanual/get-started.html#running),
[templates](https://jmeter.apache.org/usermanual/get-started.html#template),
[JMeter GUI source](https://github.com/apache/jmeter/tree/34a2785748e9e0b14702595e8682c387869deda3/src/core/src/main/java/org/apache/jmeter/gui).

## Platform and environment behavior

JMeter is a Java application intended to run on any compliant Java/OS
combination; upstream publishes tested operating systems but does not define a
closed OS list.  The Rust analog should target Linux, Windows, and macOS and
test path, process, locale, TLS, and file-system behavior on all three.

Observable environment surfaces include Unix/Windows launcher names and
arguments, `JMETER_HOME`, `JAVA_HOME`/`JRE_HOME`, `JVM_ARGS`, `HEAP`, `GC_ALGO`,
`JMETER_LANGUAGE`, `JMETER_COMPLETE_ARGS`, path separators, current working
directory, default encoding/locale/time zone, host name/IP, available
processors/memory, OS process exit/timeout semantics, and file locking.  JDK
`keytool`, JDBC/JMS/mail/MongoDB/Neo4j drivers, script engines, and remote
services are external dependencies.  Installation paths containing spaces
have documented distributed-mode problems and need a regression test.

Primary sources: [requirements and launchers](https://jmeter.apache.org/usermanual/get-started.html#requirements),
[environment variables](https://jmeter.apache.org/usermanual/get-started.html#running),
[classpath layout](https://jmeter.apache.org/usermanual/get-started.html#classpath).

## Required test strategy

No single test type can prove compatibility.  The implementation should not
mark a matrix row supported until the corresponding evidence exists.

- **Unit tests:** CLI grammar/option combinations, property precedence,
  variable/function parsing, every function's argument/error semantics,
  controller state machines, timers' pure distributions, assertions and
  extractors, sample-result arithmetic, CSV quoting/metadata, XML converters,
  alias/upgrade maps, and report aggregation.
- **Golden tests:** load representative 5.6.3 JMX/JTL fixtures; compare the
  Rust semantic tree and all fields.  For generated files compare a normalized
  XML tree and CSV parsed rows/headers, plus a byte-level fixture where exact
  serialization is promised.
- **Differential integration tests:** run the same plan through upstream JMeter
  5.6.3 and Rust against local HTTP Mirror Server, HTTP/HTTPS fixtures, TCP,
  FTP, SMTP/mail, JDBC, LDAP, and OS-process fixtures.  Compare sample labels,
  timing fields within declared clock tolerances, status/code/message,
  response data, sub-results, variables, and JTL output.
- **External-adapter tests:** one pinned version/fixture per JDBC/JMS/mail/
  MongoDB/Neo4j driver and per scripting engine; JVM/plugin bridge tests must
  include unavailable-engine and thrown-exception paths.
- **Distributed tests:** two or more local workers, SSL and disabled-SSL RMI,
  every sample-sender mode, `-G/-X`, reverse-port/firewall simulation, data
  file availability, partial-worker failure, and exact thread multiplication.
- **Recorder/TLS tests:** HTTP CONNECT, HTTPS dynamic certificate generation,
  certificate install/trust behavior, include/exclude/header filters, binary
  files, redirects, naming/grouping, and generated JMX replay.
- **Property/fuzz tests:** XML entities/Unicode/malformed-but-tolerated JMX,
  CSV delimiters/quotes/newlines/legacy dates, unknown properties/elements,
  deeply nested hash trees, random controller seeds, and interrupted result
  writes.  Fuzzing must never silently discard a subtree.
- **Cross-platform and performance tests:** Linux/Windows/macOS launch and
  path matrix, headless mode, locale/time-zone matrix, high-thread execution,
  allocation/backpressure, and throughput overhead compared with upstream.

## Machine-checkable compatibility checklist

The final column is the source inventory's `inventory_status`, not the profile
claim status. It is intentionally `TODO` for this initial research inventory:
the profile uses lowercase `planned`, `external`, `verified`, or `blocked` for
feature claims. A CI/reporting tool can parse this table by ID and inventory
status without interpreting prose. A profile feature can become `verified`
only with the evidence named in the fourth column and a pinned JMeter
fixture/version.

| id | surface | tier | required evidence | inventory_status |
|---|---|---|---|---|
| CLI-001 | all short/long options, repeats, `LAST`, usage text | exact | CLI golden tests against 5.6.3 | TODO |
| CLI-002 | option combinations, `-e`/`-l`, report-only restrictions | exact | parser/error differential tests | TODO |
| CLI-003 | normal/fatal/remote exit behavior and log output | exact | subprocess exit/log tests | TODO |
| CFG-001 | property-file load order and `-J/-G/-D/-S/-q` precedence | exact | property precedence tests | TODO |
| CFG-002 | documented property families/defaults | exact | generated property inventory + tests | TODO |
| CFG-003 | path, locale, encoding, timezone, environment behavior | staged | Linux/Windows/macOS matrix | TODO |
| JMX-001 | root metadata and alternating `hashTree` topology | exact | XML semantic round-trip fixtures | TODO |
| JMX-002 | typed properties, XML escaping, absent-vs-empty values | exact | converter/golden tests | TODO |
| JMX-003 | aliases, historical aliases, upgrade mappings | exact | all `saveservice.properties`/`upgrade.properties` entries | TODO |
| JMX-004 | unknown/plugin elements and properties preserved | staged/external | plugin/unknown-element fixtures | TODO |
| JTL-001 | XML root, `sample`/`httpSample`, abbreviated attributes | exact | XML golden/differential tests | TODO |
| JTL-002 | nested sub-results, assertions, headers, sampler data/files | exact | rich XML result fixtures | TODO |
| JTL-003 | CSV columns, delimiter, quoting, header and sample variables | exact | parsed-row and byte fixtures | TODO |
| JTL-004 | timestamps, legacy date fallback, encoding/line endings | exact | date/locale/encoding matrix | TODO |
| JTL-005 | `sampleresult.*`, save-service switches, response-on-error | exact | property matrix | TODO |
| ELEM-001 | samplers: HTTP/FTP/JDBC/Java/LDAP/TCP | staged/external | local services + driver/JVM adapters | TODO |
| ELEM-002 | samplers: JMS/mail/MongoDB/Bolt/JUnit/OS/access log | external | pinned external fixtures | TODO |
| ELEM-003 | all logic controllers and thread-group lifecycle | exact | deterministic state-machine tests | TODO |
| ELEM-004 | listeners/result collectors and sample filtering | exact | listener/JTL differential tests | TODO |
| ELEM-005 | configuration elements and scope/precedence | exact | component plan fixtures | TODO |
| ELEM-006 | assertions and failure propagation | exact | assertion corpus | TODO |
| ELEM-007 | timers and scheduler/ramp-up interaction | staged | seeded/tolerance timing tests | TODO |
| ELEM-008 | pre-processors/post-processors/extractors | exact | response corpus + variable snapshots | TODO |
| ELEM-009 | deprecated BSF/report/MongoDB aliases | staged/external | legacy JMX fixtures | TODO |
| FUNC-001 | all 49 built-in functions and case-sensitive names | exact | one unit/golden test per function | TODO |
| FUNC-002 | undefined expansion, scope, timing, thread safety | exact | multi-thread expansion tests | TODO |
| FUNC-003 | BeanShell/Groovy/JEXL/Rhino scripting functions | external | pinned engine adapter tests | TODO |
| SCRIPT-001 | JSR223 bindings, caching, exceptions, script files | external | engine matrix | TODO |
| SCRIPT-002 | Java Sampler/JUnit/user class loading | external | JVM bridge/plugin fixtures | TODO |
| REPORT-001 | Aggregate/Summary/graph listeners | exact | deterministic result corpus | TODO |
| REPORT-002 | HTML/JSON dashboard metrics and percentile algorithms | exact | report golden fixtures | TODO |
| REPORT-003 | Graphite/InfluxDB backend listeners | external | local service protocol tests | TODO |
| DIST-001 | RMI server/client, `-r/-R/-G/-X`, thread multiplication | staged/external | two-worker integration tests | TODO |
| DIST-002 | RMI SSL, ports, keystore/truststore, failure behavior | external | generated cert/firewall tests | TODO |
| DIST-003 | all sample sender/backpressure modes | staged | mode-by-mode JTL tests | TODO |
| DIST-004 | plan transfer versus data/dependency non-transfer | exact | worker filesystem fixtures | TODO |
| PROXY-001 | outbound HTTP proxy flags/system properties | exact/external | proxy fixture tests | TODO |
| PROXY-002 | HTTP(S) recorder filters, generated JMX, CONNECT/TLS | staged/external | browser/proxy fixture tests | TODO |
| PROXY-003 | mirror server and binary/redirect/header behavior | exact | local mirror integration tests | TODO |
| TLS-001 | HTTP trust/client cert/SSL manager/keystore config | external | local TLS CA/server tests | TODO |
| TLS-002 | recorder JKS/dynamic cert defaults and keytool workflow | external | certificate generation tests | TODO |
| PLUG-001 | classpath/plugin discovery and ordering | external | pinned plugin fixture | TODO |
| PLUG-002 | plugin element/function/JMX alias contract | external | plugin contract suite | TODO |
| PLUG-003 | unavailable plugin diagnostics and subtree preservation | staged | missing-class JMX tests | TODO |
| GUI-001 | `guiclass`, GUI-created JMX round-trip | staged | JMeter GUI fixture corpus | TODO |
| GUI-002 | backups, autosave, `LAST`, templates, WorkBench | staged | filesystem persistence tests | TODO |
| GUI-003 | locale/look-and-feel/toolbar/tree/undo settings | staged | platform GUI smoke tests | TODO |
| TEST-001 | unit/golden/differential test harness itself | exact | reproducible pinned harness | TODO |
| TEST-002 | protocol fixtures and external dependency pins | external | containerized fixture manifest | TODO |
| TEST-003 | fuzzing malformed/unknown JMX/JTL without data loss | exact | fuzz corpus and no-drop invariant | TODO |
| TEST-004 | distributed/recorder/TLS integration suite | external | isolated CI environment | TODO |
| TEST-005 | cross-platform and performance regression gates | staged | OS/perf baseline reports | TODO |

This table is the hand-off contract for implementation agents. Keep its IDs and
surface inventory aligned with the profile. After the required tests exist,
update the profile feature status and its evidence record together; do not
turn this source marker into a compatibility claim. Expanding the
compatibility scope requires a new row and a pinned upstream source/fixture.
