# Agent working agreement

These instructions apply to the entire repository. More-specific `AGENTS.md`
files may add local rules but may not relax this contract.

## Before changing files

1. Read `docs/architecture.md` completely.
2. Read `compat/README.md` and the active profile
   `compat/profiles/jmeter-5.6.3.json`.
3. Read the research document relevant to the task. Do not reload unrelated
   research merely to expand scope.
4. Inspect the worktree and preserve concurrent or user-owned changes.
5. State the compatibility IDs, owned paths, and acceptance commands for the
   task before implementation.

No Rust-specific Codex skill is installed in this repository. Follow the Rust
rules below and authoritative Rust/Cargo documentation. Do not invent or claim
use of a missing skill.

## Scope and ownership

- Work only on the assigned feature IDs and paths. Do not opportunistically
  refactor another worker's area.
- Architecture and repository-wide policy are owned by the primary
  orchestrator. If implementation reveals an architectural conflict, stop at
  the boundary, record evidence, and request a decision.
- Never commit, push, open a pull request, publish a crate, change GitHub
  settings, or update a remote unless the task explicitly authorizes it.
- Never mark conformance as verified without the exact evidence required by
  the profile. A compiling implementation is still `planned`.
- Preserve unknown JMX/plugin data and return explicit unsupported errors.
  Silent loss or fallback is a release-blocking defect.

## Rust rules

- Stable Rust only in production code; nightly is restricted to test tooling
  such as fuzzing, Miri, and sanitizers.
- All crates inherit edition, `rust-version`, license, repository, authors,
  and lint policy from the workspace.
- Keep dependency direction exactly as defined in `docs/architecture.md`.
  Tokio, HTTP clients, JVM bindings, and filesystem/environment access stay
  out of pure core crates.
- Prefer explicit domain types and enums over booleans and unstructured
  strings. Preserve upstream wire names at serialization boundaries.
- Production APIs return typed errors with stable codes. Do not panic on user,
  network, plugin, or file input. Avoid `unwrap`/`expect`; in tests they are
  acceptable only when the assertion context is obvious.
- No reachable `todo!`, `unimplemented!`, placeholder success, ignored error,
  or silent default. An intentionally unsupported path returns a tested
  capability error.
- Unsafe code is forbidden by default. A necessary unsafe boundary requires a
  dedicated module/crate, safety invariants, focused tests, and an architecture
  decision record.
- Do not block an async executor. Use explicit bounded blocking work and test
  cancellation. No correctness test may use an arbitrary wall-clock sleep.
- Queues, inputs, response bodies, XML depth, subprocess output, and retries
  are bounded. Document full/timeout/cancellation behavior.
- Format with rustfmt and satisfy the workspace Clippy policy. Suppress a lint
  only at the narrowest location with a reason.
- Add dependencies deliberately: record purpose, feature flags, MSRV, license,
  native build risk, and why an existing dependency or standard library is
  insufficient. Disable unnecessary default features.

## Process-safety rules

These rules are release-blocking. A prior test converted a degenerate process
group ID into `/usr/bin/kill -KILL -1`, which signalled every process available
to the test user.

- Never execute `kill`, `pkill`, `killall`, `taskkill`, `setsid`, or a shell to
  terminate or isolate a child or process group.
- Never format a PID or PGID as a negative command-line argument. Values `-1`,
  `0`, and `1` are forbidden signal targets in every representation.
- Use an owned `std::process::Child` handle. Before signalling, call
  `try_wait`; if the child exited, do not signal. Always wait/reap the exact
  child on every success, error, timeout, and cancellation path.
- Direct-child termination is the safe fallback. Group signalling is allowed
  only through a safe system-call wrapper, with a validated PGID greater than
  one derived from that still-live, unreaped child and with group ownership
  established by construction. Unsafe FFI remains forbidden.
- Production code must not discover a generic process by name or stale PID.
  Container cleanup uses the exact container ID created by the test and must
  never select by broad name, label, image, user, or ancestor filters.
- A test that actually signals a process group must be ignored by ordinary
  `cargo test` and run only inside a verified PID namespace such as
  `unshare --pid --fork --mount-proc`. Unit tests should exercise validation
  and exited-child behavior without delivering group signals.
- Fixture scripts must use exact child handles, graceful shutdown, bounded
  waits, and direct-child escalation. Broad cleanup commands are forbidden.

## Test and compatibility rules

- Every behavior gets a deterministic unit test at the lowest useful layer.
- Every fixed bug gets a regression test that fails before the fix.
- Parsers and state machines need negative and resource-limit tests, not only
  happy paths. Parser/protocol work also updates the appropriate property or
  fuzz corpus when practical.
- I/O behavior uses local deterministic fixtures. Correctness tests never use
  public internet services or ambient credentials.
- Compatibility claims use the exact JMeter artifact and SHA declared by the
  active profile. Keep raw oracle artifacts out of Git unless sanitized,
  deterministic, licensed, and covered by provenance metadata.
- Normalize only fields explicitly allowed by the profile. Always retain a raw
  diagnostic diff outside committed fixtures.
- Tests must not depend on local timezone, locale, hostname, random seed,
  current time, thread scheduling, home directory, or inherited proxy settings
  unless that dependency is the behavior under test.
- Run the narrow test first, then repository format/lint/test gates appropriate
  to the change. Report commands and exact outcomes; never say "tests pass"
  without naming what ran.

## Files and provenance

- Use `apply_patch` for hand edits. Generated files must identify their source
  command and must be reproducible.
- Do not copy upstream source or fixtures casually. Every non-original fixture
  has provenance, pinned source revision, license, modification note, and
  redistribution review. Prefer small original fixtures exercised by the
  pinned oracle.
- Never store secrets, private plans, customer traffic, downloaded JMeter
  distributions, dependency caches, generated private keys, raw logs, or
  machine-specific paths in Git.
- Keep documentation factual: distinguish implemented, tested, experimental,
  planned, external, and unsupported behavior.

## Handoff checklist

A completed implementation handoff states:

- compatibility IDs and observable behavior implemented;
- files added/changed and any concurrent files deliberately left untouched;
- tests added and commands run with results;
- profile/evidence updates, if legitimately earned;
- dependency, security, performance, and compatibility risks;
- remaining unsupported paths or oracle questions.

If a required check cannot run, report the exact missing capability. Do not
replace it with an unrelated check or weaken the assertion.
