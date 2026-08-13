# Decision 0009: standalone Rust product and optional compatibility pack

Status: accepted architecture; implementation and evidence pending  
Date: 2026-08-13  
Compatibility features: all profile rows, with direct focus on `CLI-001`,
`CLI-002`, `CLI-003`, `JMX-004`, `ELEM-001`, `ELEM-002`, `ELEM-008`,
`FUNC-003`, `SCRIPT-001`, `SCRIPT-002`, `DIST-001`, `PLUG-001`, `PLUG-002`,
`PLUG-003`, `GUI-001`, `GUI-002`, and `GUI-003`  
External boundaries: `EXT-JVM-001`, `EXT-RMI-001`, `EXT-PLUGIN-001`,
`EXT-SERVICE-001`, `EXT-TLS-001`, `EXT-OS-001`

## Context

The operationally valuable JMeter path is headless load execution. Apache
JMeter itself recommends CLI mode for load testing. Requiring a JVM and a
JMeter installation for native HTTP, controller, timer, assertion, extractor,
JTL, and report behavior would erase much of the deployment and isolation
benefit of a Rust implementation.

Some contracts cannot be truthfully translated into a finite Rust
implementation. A user-supplied Java sampler, JUnit class, JSR223/Groovy or
BeanShell script, arbitrary plugin JAR, plugin GUI editor, and the exact Java
RMI object contract execute Java bytecode selected by the plan or deployment.
Implementing similar behavior in Rust is useful but is not execution of that
bytecode and therefore is not a drop-in result.

GUI parity is not essential to the initial customer milestone. GUI-originated
JMX must remain safe and lossless in headless workflows, but reproducing Swing,
Java Preferences, and plugin editors is deferred.

## Decision

Ship one Rust application executable as the primary product. Its capability
set is called `standalone-native`. For that capability set:

- Java, a JVM, a JMeter distribution, and a helper executable are absent and
  must not be probed, downloaded, spawned, or required.
- Runtime tables, aliases, schemas, defaults, and static assets required by
  native execution are compiled into the executable or reproducibly generated
  into Rust data before release.
- The release archive contains the executable plus required license and notice
  documents. The executable itself does not require application sidecars.
  Platform system libraries are permitted; the Linux musl release additionally
  proves a static single-file variant.
- A remote database, broker, mail server, proxy, or other endpoint explicitly
  named by a test plan is a workload dependency, not an application sidecar.
  Its client implementation should be Rust-native where exact observable
  behavior can be proven.
- A JMX document may contain any bounded unknown or external subtree and still
  be loaded, inspected, and saved losslessly. Executability is a separate
  decision.

Retain a separately provisioned optional compatibility pack for contracts that
actually require Java semantics. The pack contains the exact signed JMeter
5.6.3 artifact, a minimal versioned helper, its dependency and license
manifest, and an explicitly selected Java runtime. It is not part of the
standalone archive and is not required for native plans. The application may
contain the Rust bridge client, but that code remains dormant unless the user
explicitly selects a pack and its full identity passes negotiation.

The optional pack is required for:

- arbitrary Java sampler, JUnit, user-class, JSR223, Groovy, BeanShell, and
  Java-plugin execution;
- exact Java plugin discovery, aliases, class-loader behavior, and plugin GUI
  editors;
- exact JMeter Java RMI interoperability and Java-provider behavior that a
  native implementation has not independently proven;
- the deferred exact Swing GUI contract.

These are capability partitions, not blanket component assignments. A native
Rust implementation may replace a finite built-in behavior after pinned
differential evidence proves its complete observable contract. It may not
claim to replace arbitrary bytecode, and the existence of a Java
implementation never forces an already proven native path through Java.

## Selection and atomic admission

Plan compilation emits a bounded, ordered implementation-path manifest. Every
enabled executable node and run-level callback is assigned exactly one closed
path identity:

```text
native.<versioned-capability>
compat.jvm.<versioned-capability>
compat.rmi.<versioned-capability>
unavailable.<stable-reason>
```

The identity binds the compatibility profile, executable-plan digest, node or
run-level source identity, provider identity, and negotiated capability-set
digest. It contains no secret bytes. Aliases and disabled or opaque nodes
retain their source representation but do not acquire an executable path.

Admission validates the whole manifest before setup, network I/O, file
truncation, service connection, process creation, script evaluation, or
listener publication. Standalone mode admits only manifests whose enabled
paths are all `native.*`. A compatibility-pack requirement or unavailable path
rejects the complete run with a typed, stable, source-located error. No native
prefix is executed, no output file is partially published, and no implicit
retry changes the path.

Compatibility-pack mode still uses the same atomic admission rule. It verifies
the signed artifact, helper, Java executable, ordered classpath, plugins,
platform, protocol, limits, and supervisor token before useful work. A path is
immutable for the admitted run. Failure or poisoning cannot hand the node back
to the native engine.

## GUI priority

`GUI-001..003` remain in the full JMeter 5.6.3 profile, because removing them
would redefine “full compatibility.” Their worker implementation and runtime
matrix are postponed until after the standalone headless release. Until then:

- `guiclass`, GUI-originated properties, unknown elements, and opaque plugin
  data remain part of lossless JMX handling;
- invoking a GUI operation returns the declared capability-unavailable error
  without opening a partial editor or starting a headless test;
- GUI descriptors and static checks may be maintained, but GUI runtime work
  does not consume the critical-path implementation budget;
- no standalone percentage or release claim counts GUI as implemented.

Decision 0002 remains the binding design if exact GUI work resumes.

## Compatibility claims

Publish two independent machine-readable reports:

1. `standalone-native`: the exact profile projection and cases executable by
   the one Rust binary with Java deliberately unavailable;
2. `full-jmeter-5.6.3`: all 52 profile rows with every declared optional and
   external adapter.

The standalone report is a projection, not a second definition of JMeter and
not permission to remove mixed or external rows. A row may be fully native,
partitioned by named cases, or unavailable. Only case-level evidence can make
that distinction; counting source files or successful parsing is not support.
Percentages are informational summaries over the machine-readable case
inventory and never replace the row-by-row evidence.

The project may call the standalone product production-ready when its declared
native projection is complete, even while the full profile and deferred GUI
remain incomplete. It may not call that release “100% JMeter compatible.” The
unqualified claim is reserved for the full report.

## Acceptance gates

The standalone release requires deterministic evidence that:

- every release target builds one application executable from the locked
  workspace; the Linux musl artifact has no dynamic application dependency;
- an isolated environment with no `java` executable, `JAVA_HOME`, JMeter home,
  classpath, plugin directory, or helper files runs every native fixture;
- static and runtime tracing show no JVM discovery or process creation on a
  native plan;
- embedded tables and assets have generated-source provenance and are included
  in the release identity;
- native and unavailable path classification is deterministic across repeated
  compilation and every enabled node is accounted for exactly once;
- a mixed native/Java plan is rejected before all observable side effects;
- unknown/Java/plugin JMX subtrees survive load and save even when execution is
  unavailable;
- every Java-only CLI route returns the stable capability error and exit class,
  without changing files or contacting a service;
- package inspection on Linux, Windows, and macOS finds no undeclared
  application sidecar or non-system dynamic library;
- unit, property, fuzz, integration, differential-oracle, cross-platform,
  security, performance, and soak evidence required by every claimed native
  case passes.

The optional compatibility pack independently requires Decisions 0001, 0004,
0005, and 0007, signed upstream provenance, protocol fuzzing, platform process
containment, crash/cancellation tests, and the exact differential fixtures. A
passing pack test cannot promote the standalone report, and a passing native
test cannot promote a Java-only case.

## Consequences

Most headless HTTP/API load tests can deploy as one Rust executable with a
smaller runtime and attack surface. Customers whose plans contain arbitrary
Java code receive an explicit deployment choice instead of a hidden Java
dependency or an approximate result.

The repository can still contain a small original Java helper and Java fixture
sources for the optional pack. Production engine and orchestration code remain
Rust. The helper is a compatibility boundary, not an alternate implementation
of native features.

Full-profile completion remains more expensive than the standalone milestone.
That cost is visible in separate evidence rather than being hidden by changing
the meaning of compatibility.
