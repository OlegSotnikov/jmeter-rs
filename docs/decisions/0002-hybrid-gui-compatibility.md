# Decision 0002: hybrid GUI compatibility boundary

Status: accepted architecture, revision 3; implementation and platform evidence pending  
Date: 2026-08-12  
Compatibility features: `GUI-001`, `GUI-002`, `GUI-003`, `CFG-003`, `PLUG-003`, `CLI-001`,
`CLI-002`, `CLI-003`, `JMX-001`, `JMX-002`, `JMX-003`, `JMX-004`,
`TEST-002`, `TEST-004`, `TEST-005`  
External boundaries: `EXT-JVM-001`, `EXT-PLUGIN-001`, `EXT-OS-001`

Priority note (2026-08-13): exact GUI implementation and runtime evidence are
postponed until after the standalone headless milestone by Decision 0009. This
changes scheduling only. The contract below remains binding if GUI work
resumes, and `GUI-001..003` remain unverified members of the full profile.

## Context

JMeter's GUI contract includes more than rendering a test-plan tree. It
includes Swing class instantiation, look-and-feel discovery, Java Preferences,
recent-file and `LAST` behavior, templates, backups, autosave timing,
WorkBench migration, plugin-provided editors, locale-before-launch behavior,
HiDPI resources, and platform-specific widget state. Recreating those details
with a Rust GUI toolkit would produce a useful new product interface, but it
would not by itself reproduce the observable JMeter 5.6.3 GUI contract.

The Rust engine must remain usable without Java for supported headless plans.
At the same time, full-profile compatibility cannot silently omit GUI behavior
or label a visually similar native interface as a drop-in replacement.

## Decision

Use a hybrid boundary:

- Rust owns CLI parsing, mode selection, explicit filesystem/environment
  policy, lossless JMX parsing and persistence, native headless execution, and
  validation of every returned artifact.
- A version-pinned JVM worker running the exact profile JMeter artifact owns
  only behavior whose contract depends on Swing, Java Preferences, JMeter GUI
  classes, or Java plugin editors.
- The GUI worker is an explicit external capability. It is never a hidden
  fallback for an unsupported native sampler or controller.
- A future native Rust GUI is a separate product surface. Its tests may prove
  its own behavior, but they cannot promote `GUI-001..003` unless it also
  passes the pinned JMeter differential contract.

Invoking `jmeter-rs` in JMeter's default GUI mode requests the `gui.worker` and
`gui.display` capabilities. If the exact worker, classpath, plugin set,
platform evidence, or display capability is unavailable, launch returns
machine code `runtime.capability.unsupported` with process exit class
`capability.unavailable`. Structured context contains the requested operation,
capability, profile ID/hash, target/platform profile, and bounded source
identity; it contains no raw property or path secret. It does not open a
partial native editor or silently switch to non-GUI execution.

The active profile feature rows correctly bind `GUI-001` to JVM/plugin/OS and
`GUI-002..003` to JVM/OS. The aggregate `FX-GUI-001` catalog now names
`EXT-JVM-001`, `EXT-PLUGIN-001`, and `EXT-OS-001`; built-in direct cases name
JVM/OS, while the dedicated plugin-editor positive/negative case names all
three. A case boundary may be a direct subset only when the executed family
union covers the catalog. This scope contains exactly `GUI-001..003`; no
`GUI-004` is invented. These static corrections change declared scope, not
verification, and all cases remain not-run.

The pinned worker is the GUI and persistence source of truth for one GUI
session. Rust supplies isolated roots and initial state, then observes and
validates the worker's Java Preferences, recent-file, backup, template,
dirty/save, and WorkBench transitions. Rust does not maintain a competing
recent-state or backup timeline during that session. After transactional close
it imports only validated final state. Headless CLI state remains Rust-owned
and crosses the boundary through an explicit versioned import/export operation.

GUI Start/Stop actions use the pinned JMeter engine inside the GUI worker,
because autosave, dirty-plan, listener, and lifecycle behavior belongs to the
GUI contract. They are not invisibly handed to the native Rust engine. A future
“run with native engine” action is a separately labelled product feature and is
not GUI conformance evidence. An unavailable worker capability returns a typed
error; it never approximates Start behavior.

Within a GUI session, the worker is authoritative for Java Preferences,
`recent_file_0`, dirty state, autosave and backup ordering, templates,
WorkBench migration, LAF, toolbar/tree and undo state, and GUI engine
lifecycle. Rust owns headless state, explicit filesystem policy, validation,
and transactional publication, but does not maintain a competing GUI recent-
file or backup timeline. GUI `-t LAST` and `-l LAST` resolve through the
worker's `recent_file_0`; literal `-j LAST` remains the separately pinned
launcher literal. A missing recent record is typed unavailable and never
guessed from cwd, a fixture, or ambient preferences.

## Responsibility split

Rust-native headless persistence covers:

- ordered element/`hashTree` topology and stable node identity;
- `testclass`, `guiclass`, `testname`, enabled state, attributes, typed
  properties, comments, processing instructions, and opaque plugin subtrees;
- bounded load, inspect, edit, save, and reopen for representable JMX;
- explicit backup roots and bounded retention;
- explicit headless recent-project state and deterministic `-t LAST`, `-l LAST`,
  and literal `-j LAST` routing;
- explicit template roots and headless preservation of GUI settings.

The pinned GUI worker covers:

- actual GUI class and plugin editor loading;
- Java Preferences precedence and persistence;
- dirty-plan autosave and GUI-triggered backup timing;
- template UI behavior;
- empty and non-empty WorkBench migration;
- Swing look-and-feel selection/fallback, toolbar and tree resources, HiDPI,
  undo behavior, display initialization, and restart-sensitive settings.

Rust re-parses every JMX file returned by the worker and compares it with the
operation's declared semantic and preservation contract. JMeter-defined
transformations are operation-specific: an empty WorkBench may be removed. For
a non-empty WorkBench, non-test children move to disabled Test Plan children;
remaining children are wrapped by a disabled `TestFragmentController` named
`WorkBench Test Fragment`, exactly when the pinned operation contract requires
it. The immutable input artifact
and opaque source data remain retained for diagnostics; “lossless” does not
mean reversing an intentional JMeter transformation. Missing classes or plugins
return typed capability errors while the original opaque subtree remains
available to Rust. Worker output is never accepted solely because the process
exited successfully.

## Worker protocol and launch

The GUI worker uses the shared bounded bridge protocol. Its handshake binds:

- protocol and preservation-contract versions;
- canonical UTF-8 compatibility-profile bytes, profile version, and SHA-256;
- JMeter archive SHA-512, source commit, release-signature verification record,
  and exact ordered classpath member SHA-256 values;
- jmeter-rs commit and platform-profile ID/hash;
- Java vendor, version, executable identity, and target platform;
- plugin identities, source/version/license/NOTICE provenance, and hashes;
- requested GUI operation and capability set;
- maximum message, JMX, artifact, diagnostic, and operation counts;
- locale, timezone, charset, look-and-feel, headless/display policy;
- explicit workspace, preferences, backup, template, log, result, and output
  roots.

Before JVM creation the launcher binds an absolute identity-checked JMeter home
and passes the equivalent of `-d`; it sets `java.util.prefs.userRoot` to the
fresh exclusive preference root. `user.home`, temporary directories, locale,
timezone, charset, `JMETER_LANGUAGE`, LAF properties, and display variables are
also fixed before startup. The worker records the observed values and fails the
handshake on any mismatch.

The compatibility worker enforces at least the fixture bounds: 65,536-byte JMX
input/output, 32 plan nodes, depth 8, 8,192 bytes per property text, 32
properties per element, 10 backup files with 96-byte names, four template files
with 64 entries and 65,536 bytes each, 64 toolbar entries, 65,536-byte icon
resources, undo capacities 25/50, 65,536 bytes per output/log stream, one active
GUI operation, 256 bytes per materialized path token, 128 recorded directory
entries, zero automatic retries, and a 30-second operation deadline. Preference
records share the negotiated property count/text and aggregate message bounds;
no unbounded Java Preferences enumeration is accepted.
Production hard caps may be larger but remain finite and negotiated; a fixture
value can only reduce them.

The GUI protocol is an append-only, role-bound schema distinct from generic
scripting and RMI frames. Its closed operations are:

```text
open_gui_session | load_plan | save_as | close_session | reopen |
read_preferences | write_preferences | observe_persistence |
load_template | migrate_workbench | observe_gui_state | start | stop |
export_headless_state | import_headless_state
```

Operations are versioned and bounded. Import first validates the whole
versioned state document and applies it transactionally; unsupported fields,
limit failure, or cancelled/deadline-expired work changes neither side. Each
request has a nonzero request ID, session generation, one finite remaining
operation budget, cancellation token, preservation-contract version, and stable
error code. Only one GUI operation is admitted per session. Raw JMX and
diagnostic diffs are artifacts referenced by hash; unbounded bytes do not ride
inside an error message. Generic JVM operations cannot be reinterpreted as GUI
operations, and frames/handles/sessions never cross GUI, capability, or RMI
roles.

The worker is launched without a shell from an absolute, identity-checked Java
executable and exact profile classpath. Locale, timezone, encoding,
`java.awt.headless`, and required display variables are set before JVM start.
The environment is cleared and rebuilt from a declared allowlist. Ambient
`HOME`, Java option variables, `CLASSPATH`, proxies, preferences, display, or
current directory are not inherited.

The handshake compares strict identity equality, not a capability
intersection: every ordered JMeter and plugin classpath member, Java executable,
helper/module role, dependency, source/version/hash, license/NOTICE state,
platform profile, display session, and root policy must match. No artifact is
downloaded at runtime. Missing or extra plugin/classpath entries fail closed,
Java plugin discovery never falls through to native `plugin-host`, and an
unavailable plugin editor leaves its original JMX subtree opaque and
round-trippable.

GUI workers use `ProcessTree` from Decision 0001. No GUI/JVM execution is
enabled until the process-global supervisor and the Java caller migration pass
independent safety audits. Exact child/tree cleanup, bounded stdout/stderr,
cancellation, and explicit shutdown apply to successful and failed launches.

The GUI adapter accepts only an activated `ProcessTree<GuiWorker>` capability,
whose containment token—not a PID or raw handle—is bound into the handshake.
It has no `Command`, `Child`, raw process/group ID, direct-child fallback, or
local cleanup route. Swing/display initialization and useful worker work begin
only after supervisor activation and after `gui.display` identity (kind,
session, platform, scaling) matches the requested platform profile. Missing or
lost containment is `runtime.capability.unsupported` before work or a terminal
containment failure afterward.

`ProcessTree` is ownership, not a sandbox. Untrusted plans or plugins require
an external OS sandbox/container with explicit CPU, memory, file-descriptor,
thread, filesystem, and loopback-only network limits. Without that capability,
the worker accepts only the trusted pinned fixture corpus. Network is denied by
default; filesystem access is limited to handle-bound declared roots. A plugin
may not expand those rights implicitly.

## Filesystem and secret policy

Each run receives private, exclusive roots for workspace, preferences,
backups/autosave, templates, logs/results, and oracle artifacts. Paths are
resolved through handle-bound containment; symlinks and parent swaps cannot
redirect reads, truncation, or writes. `${JMETER_HOME}` and similar tokens are
materialized by the controlled launcher only where pinned behavior requires
it; no ambient home lookup is used.

Containment rejects traversal components, symlinks, Windows junctions/reparse
points, device paths, alternate data streams, hard-link identity conflicts,
case/Unicode alias collisions, and parent replacement between validation and
use. Every create/replace/delete operates through the validated parent handle.

Preference values, proxy credentials, keystore passwords, request data,
scripts, plugin configuration, and source paths are redacted from diagnostics.
Raw evidence remains outside Git in a private bounded artifact root, encrypted
or access-controlled according to the run policy and subject to explicit
retention/deletion. A pre-storage secret scanner quarantines an artifact rather
than treating redaction as comparison normalization. Checked-in fixtures contain
only original sanitized plans and metadata with provenance.

Secrets and sensitive paths cross only as purpose-bound opaque references and
protected supervisor-installed descriptors/handles. They never appear in argv,
ordinary environment values, generic bridge frames, evidence manifests, or
identity digests containing secret bytes. The GUI worker consumes a one-shot
reference only after worker/display identity succeeds. A missing protected
channel fails the operation without side effects.

Save/import is transactional. Worker output is written to a new contained file,
bounded, hashed, parsed, and checked against the operation contract before an
atomic application-owned publication step. A parse, limit, preservation,
secret-scan, or publication failure leaves the original plan and imported state
unchanged; partial output is private diagnostic evidence only.

## Platform and evidence contract

GUI compatibility requires execution evidence on all profile lanes:

- `x86_64-unknown-linux-gnu`;
- `aarch64-unknown-linux-gnu`;
- `x86_64-pc-windows-msvc`;
- `aarch64-pc-windows-msvc`;
- `x86_64-apple-darwin`;
- `aarch64-apple-darwin`.

Each lane uses a fresh display/session and private roots, then records the
exact OS image, target, Java/JMeter/classpath/plugin hashes, locale, timezone,
charset, display server, scaling, and look-and-feel. Linux Xvfb evidence does
not substitute for Windows or macOS execution.

The six target triples cross with Java 8 and Java 17 as twelve independent
minimum evidence rows. Each row has fresh workspace/preferences/backup/
template/log/result roots and its own supervisor, display, classpath, plugin,
and platform identities. Evidence never inherits between Java majors or target
triples.

Each lane first passes Decision 0001's platform-specific containment, sibling-
safety, exact-reap, escape, shutdown, and handle-leak gates. The evidence tuple
also records the jmeter-rs commit, profile and platform-profile hashes, verified
Apache signature metadata, worker build hash, and complete dependency/license
inventory. Java 8 and the recommended Java 17 baseline are separate rows;
additional supported Java majors cannot inherit either result.

Required differential cases include:

- load, save-as, close, reopen, and ordered semantic/no-drop comparison;
- unknown properties and unavailable plugin editors;
- empty/non-empty WorkBench migration;
- repeated saves, backup numbering and retention, autosave precedence;
- positive and missing recent state for `-t LAST`/`-l LAST`, and literal
  `-j LAST`; missing `recent_file_0` returns the same typed unavailable/error
  class and performs no current-directory, fixture, or ambient-path guess;
- template discovery and loading;
- locale/LAF lookup and fallback, toolbar/tree resources, HiDPI, undo limits,
  restart behavior, and headless rejection.
- GUI Start/Stop ownership, autosave/backup order, sampler/listener output, and
  typed unavailable behavior;
- every input/output/count/deadline bound, transactional save rejection,
  sandbox denial, secret quarantine, cancellation, crash, and exact cleanup.
- traversal, symlink, junction/reparse, device, alternate-stream, hard-link,
  case/Unicode alias, and parent-swap races for every mutable root.

Static fixture validation and Rust JMX tests are prerequisites, not GUI
conformance evidence. Profile rows remain `planned` or `external` until their
named per-platform artifacts and comparator results pass.

GUI evidence uses dedicated closed routes:

```text
gui-jmx-semantic | gui-persistence | gui-platform | gui-capability-error
```

The generic non-GUI JMX/JTL comparator rejects these records. A private run
stores handshake, observation, comparator, artifact-manifest, bounded output,
and raw diagnostic records by case/target/Java/scenario. Evidence state is
exactly `not-run`, `observed`, `unavailable`, or `failed`; only `observed` with
a passing dedicated comparator and complete provenance can support promotion.
Static descriptors retain `comparator_enforced: false` and are never upgraded
to observations by a hash refresh.

## Consequences

No Rust GUI toolkit dependency is required for JMeter GUI compatibility. The
native headless engine remains Java-free for supported plans. Operators who
need drop-in GUI behavior must provision the exact JVM/JMeter capability, and
unsupported platforms fail explicitly.

This decision authorizes a narrow GUI worker protocol and harness after the
shared process-supervision gate. It does not authorize JNI, arbitrary JVM
fallback, downloading artifacts at runtime, committing a JMeter distribution,
or describing a native Rust UI as Swing-compatible without differential
evidence.
