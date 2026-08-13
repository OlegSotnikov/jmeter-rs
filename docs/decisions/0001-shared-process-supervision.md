# Decision 0001: shared cross-platform process supervision

Status: accepted architecture, revision 5; implementation and platform evidence pending  
Date: 2026-08-13  
Compatibility features: `CLI-003`, `CFG-003`, `ELEM-002`, `DIST-001`,
`DIST-002`, `DIST-003`, `DIST-004`, `PLUG-001`, `PLUG-002`, `PLUG-003`,
`TEST-001`, `TEST-002`, `TEST-004`, `TEST-005`  
External boundaries: `EXT-JVM-001`, `EXT-PLUGIN-001`, `EXT-RMI-001`,
`EXT-OS-001`

## Context

The JVM bridge, native plugin host, JMeter oracle, GUI helper, RMI adapter,
and OS Process Sampler can own subprocess trees. Direct-child cleanup is not
enough when a launcher or worker creates descendants. Unix process groups are
an ownership aid but not a hostile-code sandbox. Windows needs a Job Object
and a suspended-create boundary so a child cannot run before containment.

This repository previously executed `/usr/bin/kill -KILL -1` after a process
identifier degenerated to `1`. That operation targeted every signalable
process for the user. Numeric process identity, ownership transfer, waiting,
termination, and handle closure are therefore release-blocking safety
boundaries. They must not be independently reimplemented by callers, passed
through strings, or tested outside a proven isolation boundary.

Revision 4 replaces the public `Command` surface, destructive `Drop` work,
`Child::try_wait`-before-group-signalling design, and Windows ToolHelp thread
rediscovery from revision 3. It defines a constrained launch description, a
single linearized ownership root, a Unix retained-root protocol, and raw
Windows suspended creation with exact handle ownership.

## Decision

`crates/process-supervision` is the only production subprocess-termination
owner for repository adapters and tools:

```text
crates/java-bridge     -> crates/process-supervision
crates/plugin-host     -> crates/process-supervision
tools/jmeter-oracle    -> crates/process-supervision
GUI/RMI/OS adapters    -> crates/process-supervision
```

The crate is a private executor-neutral edge. No dependency points from it
into model, JMX, expression, results, runtime, bridge protocol, Java bridge,
plugin host, or oracle code. Callers receive typed lifecycle and I/O
capabilities; they never receive a `Child`, PID, PGID, raw handle, Job name,
or operation that accepts one.

Two policies exist:

- `ExactChild` is limited to a sealed allowlist of repository-owned helpers
  whose reviewed contract forbids descendants.
- `ProcessTree` is mandatory for Java, JMeter, GUI, RMI, plugin, OS Process
  Sampler, and any other executable that may create descendants.

`ProcessTree` never falls back to `ExactChild`. Exact-root cleanup after a
tree failure is only a safety/reaping action; it cannot convert
`ContainmentLost` into success. Unix observed-group ownership is not a
security sandbox: an escaped `setsid`/`setpgid` descendant requires an outer
namespace, container, service manager, or equivalent policy. Windows Job
ownership likewise does not replace CPU, memory, filesystem, or network
sandboxing. The capability report records the containment grade actually
present, and hostile-code execution fails closed when the requested grade is
unavailable.

## Constrained launch contract

The public crate API does not accept `std::process::Command`, a closure, an
`unsafe` callback, `pre_exec`, arbitrary creation flags, inherited raw
descriptors/handles, a shell command, or a PATH-resolved executable. Callers
submit a bounded `SpawnSpec<Purpose>` whose fields are typed capabilities:

```text
SpawnSpec<Purpose> {
    executable: ExecutableRef,
    arguments: BoundedArguments,
    working_root: WorkingRootRef,
    environment: BoundedEnvironment,
    stdio: StdioContract,
    secret_channels: BoundedSecretChannels,
    setup_deadline: MonotonicDeadline,
    containment: RequiredContainment,
}
```

`ExecutableRef` names an absolute allowlisted file and its expected identity.
The platform backend revalidates type, owner/ACL, file identity, and executable
policy immediately before launch. A mismatch is a pre-execution capability
error. Arguments and environment have finite count and byte limits, reject
NULs and platform-invalid encodings, and preserve exact argument boundaries.
The environment starts empty and contains only typed allowlisted entries.
There is no shell interpolation, ambient PATH lookup, loader injection, proxy,
credential, or Java-option inheritance.

`ExecutableRef` is handle-bound: it retains the opened regular-file identity,
parent/root identity, expected length/hash, and platform execution identity.
Immediately before spawn the backend reopens through the authorized parent,
rejects symlinks/reparse points and identity drift, and compares the opened
object—not pathname text—with the reference. Before activation it also
validates the created process image against that same identity (for example
the retained executable vnode/file identity exposed by the target OS) and the
worker handshake repeats the content/build digest. Secret delivery and useful
work remain disabled until all three checks agree. A target unable to prove
path-to-open-object-to-process-image continuity returns
`ExecutableIdentityUnsupported`; an immutable-looking path is not accepted as
a substitute.

`WorkingRootRef` is created by the application filesystem boundary and is
revalidated against its allowlisted root. `StdioContract` is a closed enum for
null, bounded framed pipe, bounded diagnostic pipe, or a reviewed inherited
application endpoint. Ambient terminal and arbitrary descriptor inheritance
are forbidden. Child and parent pipe ends are installed and accounted before
launch; every message/output queue and byte total is finite.

Secrets use non-serializable, purpose-bound references. Their one-shot native
descriptor or handle is installed through a fixed supervisor slot and is
never represented in argv, an ordinary environment value, a pathname, generic
metadata, logs, or evidence. A platform that cannot install and account for
the protected channel returns an explicit unsupported capability; it does not
fall back to argv or environment transfer.

On Unix the protected channel is a supervisor-created `pipe2`-equivalent pair
with close-on-exec and noninheritance by default. Only the exact child read end
is assigned its fixed descriptor slot for exec; the parent write end remains
service-owned, all aliases are closed/accounted, and no named filesystem object
is used. After process-image and helper-transcript activation, the service
writes exactly one length-delimited purpose/run/session-bound record within the
parent deadline, closes the write end, and requires one bounded acknowledgement
before the child endpoint is closed. EOF, duplicate read, over-limit data, or
identity/cancellation failure terminalizes the channel without another secret
delivery.

The supervisor internally constructs `Command` on supported Unix targets and
uses its audited Windows creation module. No caller can add a setup hook after
the supervisor's policy has been applied. Adding a launch field, purpose, or
exact-child allowlist entry requires an architecture and static caller review.

## Process-global ownership root

Production has one process-global fixed-capacity ownership root. The root is a
static `OnceLock`-initialized object containing a fixed slot array, a fixed
request queue, a bounded diagnostic ring, and one joinable service-thread
state. It is never owned by `Arc`, a caller, a destructible registry, a leaked
`Box`, or the final service handle. Its configured capacity is capped at
compile time, selected once at application startup, and cannot be changed by
untrusted input or a later caller.

The root-control state linearizes admission, free-slot reservation, launch
queueing, service initialization, activation, and shutdown. No operation
checks admission under one lock and publishes a task under another. Slot
generation and the occupied bit are assigned in the same transition that
removes a slot from the free bitmap. Every queued or in-progress launch is
included in shutdown accounting before the platform spawn begins.

The normative slot states are:

```text
Free
  -> Reserved
  -> LaunchQueued
  -> Creating
  -> ChildOwned
  -> ContainmentReady
  -> HandoffPending
  -> Active

Reserved..Active
  -> CleanupRequested
  -> Observing
  -> Terminating
  -> RootWaitable
  -> Reaping
  -> HandlesClosing
  -> Complete
  -> Free | Retired

any occupied state -> ContainmentLost | Quarantined
ContainmentLost    -> CleanupRequested | Complete
Quarantined        -> explicit bounded drain only
```

Lifecycle state and resource ownership are separate. A slot records fixed
ownership cells for the root process, Unix group token or Windows Job,
creation thread, stdio endpoints, secret endpoints, and other setup handles.
A resource-bearing cell is non-`Copy`, non-`Clone`, and has no ordinary
resource-closing `Drop`; only the service's explicit state transition may move,
close, or invalidate it. Assignment cannot implicitly overwrite an occupied
cell. The handoff guard may transfer into an empty cell during unwinding but
cannot close or lose the raw resource.
A transition cannot clear an ownership bit until the corresponding resource
has a proven terminal state. `Complete` means the exact root was reaped and
every handle has a known closed outcome; `ContainmentLost` alone never means
complete. A slot is reusable only after completion, caller acknowledgment or
abandonment, and checked generation advance. Generation overflow permanently
retires the slot.

All platform creation happens on the single service thread. A launch request
is moved into its pre-reserved slot before the service calls the OS. The
service holds only that slot's guard while creating and installing resources.
It never holds two slot locks and never holds a slot lock while acquiring root
control, diagnostics, waiting, or joining.

Every OS call that creates more than one resource has a fixed-capacity handoff
guard tied to the already locked slot. A successful return is copied/moved
into ownership cells before cancellation checks, allocation, logging,
callbacks, or another fallible call. If unwinding occurs, the guard's `Drop`
only installs returned resources into those cells and marks cleanup requested;
it performs no lock acquisition, allocation, wait, signal, close, or other OS
operation. Panic injection at every instruction boundary between OS return and
installation must leave all returned resources in the occupied slot. Cleanup
panics likewise leave resources in place and mark the slot degraded.

The service performs finite round-robin work. Automatic cleanup is limited to
three attempts, each with a maximum 250-millisecond budget, separated by an
interruptible service tick of at most 10 milliseconds. These are production
caps, not test sleeps; deterministic tests inject the clock and wake source.
Exhaustion transitions once to `Quarantined`. An explicit drain takes one
absolute deadline and attempts each eligible slot at most once per pass. It
never discards or replaces a retained slot to make capacity appear free.

## Caller capabilities and useful-work gate

`PreparedProcess` and `ActiveProcess` are single-owner, non-`Clone` tokens that
contain only slot index, generation, and sealed capability kind. They never
own a child or platform handle. A future shared lease requires a separate
bounded, fallible API with explicit final-lease accounting; infallible clone is
forbidden.

`Drop` is strictly constant-time and process-free. It performs only atomic
stores/compare-exchanges that mark abandonment and advance the global work
epoch. It does not lock, allocate, notify a condition variable, wait, close,
signal, format diagnostics, or call any OS process API. The service observes
the epoch on its bounded tick, so caller destruction cannot lose ownership
even if the service has failed.

The prepared token exposes only bounded setup-protocol I/O needed to prove the
worker identity. It cannot send a plan, plugin request, sample, credential, or
other useful user work. After the adapter's identity handshake succeeds, it
requests activation. Activation is a service operation linearized with global
admission closure: if shutdown closed admission first, activation fails and
cleanup begins; if activation wins, the slot is counted active before the
`ActiveProcess` capability is returned. Shutdown therefore cannot complete a
final accounting pass while a newly usable child is hidden in handoff.

All wait, status, cancellation, and cleanup methods validate slot and exact
generation. A stale token cannot inspect, activate, signal, close, clear, or
reuse anything. Terminal status is cached until the live token acknowledges it
or is abandoned. A caller that omits `wait` cannot leak a zombie or retain
capacity forever; the service observes root exit and finishes the policy's
cleanup protocol.

## Deadlines, cancellation, and shutdown

Every request uses an absolute deadline from an injected monotonic clock. A
phase may shorten remaining time but cannot create a fresh budget. Spawn
cannot be force-cancelled while the operating-system call is in progress, so
shutdown or request timeout marks the reserved slot for cleanup and reports
incomplete until creation returns and ownership is installed. The child can
never become active after that cancellation.

Cancellation severity is monotonic:

```text
none -> graceful-requested -> cleanup-requested -> timed-out
```

The supervisor owns forced cleanup, not application semantics. A caller may
attempt a bounded protocol-level graceful stop before requesting cleanup, but
process termination never stands in for JMeter graceful shutdown, remote exit,
or plugin close. Once forced cleanup or timeout occurs, the operation cannot
be reported as semantically successful.

Global shutdown is linearized under root control:

```text
Open -> Closing -> Draining -> StopRequested -> StopAcknowledged -> Joined
```

Closing admission and snapshotting every occupied state—including `Reserved`,
`LaunchQueued`, `Creating`, `ChildOwned`, `ContainmentReady`,
`HandoffPending`, `Active`, cleanup/reap states, containment-lost, and
quarantined—is one transition. `shutdown(deadline)` requests cleanup for every occupied slot and
waits only within the supplied budget. It returns a typed report with launch,
active, pending, quarantined, containment-lost, handle-unknown, complete,
service, acknowledgment, join, and bounded error counts. Any queued launch,
handoff, owned resource, unknown close outcome, missing service acknowledgment,
or unjoined service makes the result `ShutdownIncomplete`.

Only a zero-owned root can request service stop. The service acknowledges
between bounded slot attempts after it has left its loop. The caller invokes
`JoinHandle::join` only after that acknowledgment, so join cannot consume an
unbounded deadline. A missing acknowledgment retains the join handle and the
running static root. Concurrent shutdown callers observe one shutdown epoch;
exactly one caller owns the join transition and all receive the same terminal
report. Initialization, service-start failure, concurrent shutdown, and
repeated shutdown use the same root-control state, so a service cannot start
after shutdown has completed. Admission never reopens.

## Unix retained-root protocol

On supported Unix targets the service builds the command internally and uses
stable `CommandExt::process_group(0)`. The exact root `Child` is installed in
its slot before group validation. Root PID and observed PGID must both convert
to the private `ValidatedProcessGroup` type, must be equal, and must be greater
than `1`. Values `-1`, `0`, and `1`, overflow, lookup failure, and mismatch are
unrepresentable or typed setup failures. This is essential because a group
operation with identifier `1` has the broad `kill(-1, ...)` meaning on Unix.

The crate is the sole reaper for every child it creates. Initialization verifies
and records the process-global contract that `SIGCHLD` is neither ignored nor
configured with `SA_NOCLDWAIT`; callers and embedders may not change it or wait
for supervisor children. Unix production code does not call
`Child::try_wait`, `wait`, `waitpid(-1)`, or `waitid(P_ALL)`. It observes only
the exact root with safe `rustix::process::waitid(P_PID, WEXITED | WNOHANG |
WNOWAIT)`.

The recorded SIGCHLD disposition/mask contract is revalidated before every
root observation, signal-validation sequence, and final reap. A changed or
unreadable disposition, `SA_NOCLDWAIT`, ignored SIGCHLD, or incompatible mask
transitions the slot to `ReaperContractLost`; `ECHILD` is treated identically.
No numeric PID/PGID operation follows. The application installs no competing
reaper, and the supervisor exposes no child handle that another component can
wait on.

`WNOWAIT` is the ownership barrier. A reported exited root remains a waitable
zombie and is not reaped yet. POSIX defines a zombie as a process, keeps the
process ID for the process lifetime, keeps the group ID for the process-group
lifetime, and forbids reuse until those lifetimes end. Therefore a root that
has become waitable can still retain the PID/PGID identity while group cleanup
runs. This is safer than reaping first and then signalling a reusable number.
Support on each Unix target nevertheless requires an executable platform test
that `waitid(WNOWAIT)` plus `getpgid` has these specified semantics; an
unproven target returns an unsupported process-tree capability.

Immediately before every group signal, the service performs this exact
sequence:

1. Observe the exact root with `waitid(P_PID, WEXITED | WNOHANG | WNOWAIT)`.
   Either it is live or its exact exit status is cached while it remains
   waitable.
2. If observation returns `ECHILD`, an unexpected reaper or signal policy has
   destroyed the ownership barrier. Record `ContainmentLost` and send no PID
   or PGID signal.
3. Call safe `rustix::process::getpgid` for the retained root and require the
   exact validated PGID equal to the root PID and greater than one. On any
   error or mismatch, send no group signal.
4. Call safe `rustix::process::kill_process_group` with the validated newtype
   and `SIGKILL`. No external `kill` executable, negative integer formatting,
   raw libc call, or arbitrary numeric target exists.

If the root was live, the service continues exact `WNOWAIT` observation until
it becomes waitable or the absolute deadline expires. Before a final group
signal it repeats all four validation steps. It reaps the exact root only
after the final validated group operation has completed. A timeout or
ambiguous group-signal result retains the waitable root and group token in a
quarantined slot; it does not reap merely to free capacity. Once the root is
reaped, the numeric token is invalidated before the slot can change state and
is never used again.

The final Unix reap is the exact-child operation
`rustix::process::waitid(P_PID(root), WEXITED | WNOHANG)` without `WNOWAIT`,
performed only after the root was observed waitable and cleanup completed. It
must return that exact cached root status; an empty result, `ECHILD`, different
status, or other error retains/quarantines ownership and never permits numeric
reuse. `Child::wait`, `waitpid(-1)`, and `waitid(P_ALL)` remain forbidden.

If validation proves containment loss while the exact child is still safely
waitable, the service does not signal the old group. It may reap the exact root
and records the tree failure permanently. If the root is live and still an
owned child but its group changed, exact-child termination may be used only
after exact-root `WNOWAIT` observation proves the PID has not been reaped; the
tree outcome remains `ContainmentLost`. If exact observation returns `ECHILD`,
neither exact PID nor group signalling is safe and no numeric signal is sent.

For `ExactChild`, the same exact-root `WNOWAIT` observation precedes
`Child::kill`. A waitable root is reaped without a signal; a live owned root
may be killed and then reaped; `ECHILD` forbids numeric signalling. Group APIs
are never reachable from this policy.

A successful Unix group signal proves cleanup of the validated observed group,
not containment of a malicious descendant that escaped before observation.
The result therefore records `ObservedProcessGroup`; stronger `ProcessTree`
claims require the caller's declared outer containment or a reviewed trusted-
worker policy. Safety-critical integration runs use a PID namespace whose PID
1/reaper and process inventory are part of the evidence. macOS requires its
own executable retained-root and unrelated-sibling safety evidence; Linux
namespace results do not transfer to it.

## Windows suspended Job protocol

Windows uses a dedicated private raw `CreateProcessW` module. Stable
`std::process::Command` is not used because it does not expose the primary
thread handle needed to prove assignment-before-resume, and ToolHelp thread
rediscovery is not an ownership proof.

Before any OS resource is created, the service constructs and validates the
bounded UTF-16 application path, Windows command line using the reviewed
quoting algorithm, sorted case-insensitive environment block, working
directory, stdio plan, and explicit inherited-handle list. Embedded NULs,
ambiguous executable resolution, duplicate environment keys, length overflow,
unsupported encoding, and an unaccounted inherited handle fail before launch.

The service then performs this fixed sequence while holding the reserved slot:

1. Create and configure an unnamed Job with
   `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` and no breakaway flag; install its
   handle in the Job cell before another fallible call.
2. Create every stdio, protocol, and secret endpoint and install each parent
   and child handle in its dedicated cell. Set inheritance only on the exact
   child endpoints.
3. Build `STARTUPINFOEXW` with `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`; no ambient
   inheritable handle is eligible.
4. Call `CreateProcessW` with `CREATE_SUSPENDED |
   EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT`, fixed policy
   flags, no shell, and no breakaway request.
5. Move both returned `hProcess` and `hThread` from `PROCESS_INFORMATION` into
   their fixed cells through the no-OS handoff guard before any other action.
6. Assign the still-suspended exact process handle to the owned Job. An
   incompatible enclosing Job is a typed unsupported/setup failure; the code
   never retries with breakaway enabled.
7. Resume the exact retained `hThread` and require the returned previous
   suspend count to be exactly one. Only then can setup-protocol I/O begin.
8. Close the creation-thread and child-side temporary endpoints through their
   ownership cells; parent protocol endpoints remain bounded capabilities.

For a nonempty child-handle list, every listed handle is an exact child
endpoint, each unlisted/parent handle is noninheritable, the attribute list is
initialized and updated successfully, and `CreateProcessW` is called with
`bInheritHandles=TRUE`. The handle-list attribute—not the ambient inheritable
set—is authoritative. For an empty list, no handle-list attribute is supplied
and `bInheritHandles=FALSE`. Attribute-list size probing, allocation,
initialization, update, and deletion are fixed ownership-cell transitions;
failure at any step closes/accountably retains all endpoints and never calls
CreateProcess with a partially initialized list. Inheritance flags on temporary
child endpoints are cleared or the endpoints are closed immediately after the
creation result is secured, including every failure path.

Any failure before assignment terminates only through the exact retained
process handle. A failure after assignment terminates through the exact Job.
The process is still suspended, so useful child code cannot race containment
setup. PID is diagnostic data only and is never a termination target.

Cleanup uses `TerminateJobObject`, waits for the exact process handle, records
its exit code, and proves Job active-process count reaches zero within the
deadline before closing the Job. Root-exits-first cleanup still uses the same
Job handle and does not rediscover descendants. `ExactChild` uses only its
retained process handle. No named Job, process snapshot, PID reopen, or raw
integer retry is allowed.

Each Windows handle cell has the states `Empty`, `Owned`, `Closing`, `Closed`,
and `OutcomeUnknown`. A successful `CloseHandle` clears the raw value in the
same critical section. If the API result cannot prove whether a numeric handle
is still owned, the cell becomes `OutcomeUnknown`, the numeric value is never
used or closed again, and the slot remains permanently quarantined. A known
failure that contractually preserves ownership may be retried only while the
same cell remains `Owned`. Dropping a raw integer or relying on process exit to
make an unknown close result successful is forbidden.

Raw handles remain service-thread-owned and never appear in a public or
cross-thread type. Callers use safe framed endpoint capabilities. If the
implementation cannot maintain that thread confinement, exact inherited-
handle list, suspended assignment, and close-state contract without an unsafe
`Send`/`Sync`, Windows process support remains unavailable; it does not fall
back to `Command`, ToolHelp, or direct-child cleanup.

## Unsafe and dependency boundaries

Production remains stable Rust. Workspace unsafe policy changes from `forbid`
to `deny` only for the process-supervision crate, and only the private Windows
FFI module may use a narrowly scoped `#[allow(unsafe_code)]`. Every unsafe call
documents buffer initialization, UTF-16 lifetime, pointer validity, handle
rights, ownership before/after success and failure, aliasing, thread
confinement, and panic behavior. No unsafe public `Send`/`Sync`, JNI, native
plugin ABI, or unrelated FFI is authorized by this decision.

The Unix dependency changes to `rustix = "=1.1.4"`, default features disabled,
with only `std` and `process`. It supplies safe exact `waitid` with `WNOWAIT`,
`getpgid`, PID newtypes, and process-group signalling. It is licensed
`Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT`, declares Rust 1.63, and
uses Rust-only cfg/backend build selection rather than a native C library.
The existing `nix` dependency is removed from this crate once migration is
complete; two process API wrappers are not retained.

The Windows dependency remains exact-pinned `windows-sys = "=0.61.2"` with
default features disabled and only the reviewed Foundation, Security,
JobObjects, Threading, Pipes, and any narrowly required file/handle features.
Feature names, purpose, transitive versions, licenses, MSRV, build scripts,
and native risk are recorded in `docs/third-party-provenance.md` before code
lands. No dependency is added merely to hide a caller-owned process API.

## Error and diagnostic contract

Production APIs return typed stable errors. Required categories include
admission closed/capacity, invalid launch specification, executable identity,
platform unsupported, setup timeout, containment unavailable/lost, reaper
contract lost, queue full, child exit, termination failure, reap failure,
handle close failure/unknown, service degraded, shutdown incomplete, stale
generation, and invariant violation.

External error strings are never formatted into an unbounded temporary.
Diagnostics copy at most the remaining fixed byte capacity and append an
ellipsis only inside that capacity. Paths, arguments, environment values,
protocol bytes, and secrets are represented by stable codes, counts, and
approved identity digests, not raw values. Saturation is explicit and cannot
erase a slot's latest terminal code or ownership state.

## Verification requirements

Pure tests use a fake platform backend and an injected clock/wake source. The
fake API accepts only supervisor-minted opaque root/group/Job tokens, so a
failure-injection test cannot signal a real numeric target. Deterministic unit,
property, and bounded model tests cover:

- launch-spec bounds, Windows quoting/environment construction, purpose
  sealing, exact-child allowlisting, and secret/stdio inheritance policy;
- singleton initialization, capacity mismatch, reservation, generation
  exhaustion, stale token rejection, and diagnostic saturation;
- every state transition, invalid transition, retry/quarantine path, normal
  root exit, acknowledgment, and slot reuse condition;
- panic at every Unix-child and Windows-multi-handle handoff point, proving
  resources remain in their fixed slot without a lock-taking `Drop`;
- shutdown racing reservation, queued launch, OS creation return, containment
  setup, handoff, activation, token drop, cleanup, drain, service startup,
  acknowledgment, and join;
- constant-time token drop, service failure/panic/poison recovery, fairness,
  bounded attempts, and one absolute deadline with no phase reset;
- Unix live, waitable-zombie, `ECHILD`, PGID `-1/0/1`, mismatch, lookup/signal/
  wait/reap failure, retained-root timeout, and proof that no invalid path
  reaches a group operation;
- Windows every create/assign/resume/wait/terminate/query/close failure,
  exact suspend count, inherited-handle list, root-exits-first, Job drain,
  known close failure, unknown close outcome, and no PID-based cleanup.

Loom or an equivalent finite model explores admission, free bitmap,
generation, activation, abandonment, cleanup, and shutdown interleavings. A
process-state fuzz target operates only on the fake backend. Miri and
sanitizers cover the pure state machine and the isolated Windows FFI boundary.

No ordinary Cargo test may create a real process group, send a signal, start a
JVM/JMeter/plugin worker, or exercise forced process cleanup. Unix destructive
tests remain ignored and locked until an independently reviewed wrapper proves
all of the following before invoking the test binary:

- a fresh user and PID namespace were created;
- the inner supervisor/reaper is PID 1 and `/proc` is the namespace-local
  mount;
- host and inner PID identities differ and a namespace escape probe fails;
- only fixed fixture executables and bounded descendants can be created;
- timeout/cleanup is owned by the outer CI sandbox, not an in-repository broad
  `kill` command.

If any proof is unavailable, the lane exits with a named missing capability.
It never runs the test in the host namespace. macOS uses a dedicated disposable
runner and its own sibling-safety design. Windows uses a dedicated disposable
VM and validates suspended assignment, descendant containment, unrelated
sibling survival, nested-Job behavior, handle inheritance, and handle leaks.

Caller migration is a release gate. Static policy rejects production
`Command`, `Child`, `pre_exec`, `process_group`, `creation_flags`, raw wait,
raw signal, external `kill`/`pkill`/`killall`/`taskkill`, and independent
cleanup code in Java bridge, plugin host, oracle, GUI/RMI, and OS adapters.
Callers may begin useful work only from an activated supervisor capability.

Safe implementation acceptance commands are:

```text
cargo fmt --all -- --check
cargo check -p jmeter-rs-process-supervision --all-targets --locked
cargo test -p jmeter-rs-process-supervision --lib --locked
cargo clippy -p jmeter-rs-process-supervision --all-targets --all-features --locked -- -D warnings
python3 .github/scripts/check-process-supervision-migration.py
python3 .github/scripts/check-pid-namespace-wrappers.py
cargo run --locked -p xtask -- profile-check
cargo run --locked -p xtask -- policy-check
```

The real-process, namespace, Windows, macOS, Loom, Miri, sanitizer, fuzz, and
24-hour reuse/leak lanes are separate required evidence. A skipped or
unavailable lane is not a pass. No Java/JMeter/plugin execution is unlocked
until the shared implementation, all caller migrations, and the relevant
platform safety lane pass independent audit. No compatibility profile row is
promoted from this ADR, a compile check, or pure supervisor tests alone.

## Consequences

Process cleanup becomes a narrow capability rather than a convention spread
across adapters. The design consumes bounded static storage and one service
thread, and it may quarantine resources instead of risking a stale identifier.
Unix retains an exited root briefly to make PID/PGID reuse impossible during
group cleanup; Windows pays for an audited raw creation boundary to obtain
exact process/thread/Job ownership. These costs are intentional because
capacity loss and explicit unavailability are safer than signalling an
unowned process.

The implementation and migrations remain pending. Existing direct supervisors
and all real process/JVM tests stay quarantined until revision 4 is implemented
and independently approved on each target platform.

## Normative process-lifetime references

- [POSIX process, process-group, and lifetime definitions](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap03.html)
- [POSIX process and process-group ID reuse](https://pubs.opengroup.org/onlinepubs/009696699/basedefs/xbd_chap04.html)
- [POSIX wait semantics and `WNOWAIT`](https://pubs.opengroup.org/onlinepubs/9799919799/functions/V2_chap02.html)
- [Linux `waitid(2)` and zombie lifetime](https://man7.org/linux/man-pages/man2/waitpid.2.html)
