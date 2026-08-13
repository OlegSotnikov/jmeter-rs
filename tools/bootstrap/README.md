# Local bootstrap

`bootstrap.sh` provisions the pinned development prerequisites without
installing system packages or changing a shell profile.

```sh
tools/bootstrap/bootstrap.sh
```

`bootstrap.sh` is the supported entrypoint; its Bash implementation and
race-free lock launcher are internal files and should not be invoked directly.
The launcher reserves an inherited, one-shot anonymous pipe descriptor and
writes a fresh random cookie/nonce record to it. The Bash payload consumes
that record before resolving any utility or cache path; a marker without the
inherited pipe, a closed/reused descriptor, a named FIFO, trailing bytes, or a
mismatched cookie fails closed. The nonce is passed only over the inherited
pipe, never in argv, a repository file, a cache, or a persistent environment
variable.

This handoff is an invocation protocol, not same-user authentication: a
caller able to execute the internal Bash file can reproduce its fixed marker
and record. Exact wrapper authentication would require a persistent secret,
which this project intentionally does not maintain. The safety authority is
the trusted Python launcher: it validates the fixed payload, supported host,
current-user cache root, and non-blocking regular lock, holds that lock across
the Bash exec on descriptor 8, and the Bash payload rechecks the lock path and
all cache safety preconditions. The Bash payload also reasserts the descriptor
8 exclusive lock with the fixed root-owned system `flock`; a forged FD handoff
therefore cannot turn an unlocked cache file into bootstrap authority. A
forged handoff without that locked-cache precondition fails before cache work.
Direct `bash bootstrap.bash`
execution is outside the supported interface; a hostile `BASH_ENV` can run
before any script body by Bash design, but the supported launcher supplies a
sanitized environment with no `BASH_ENV`/`ENV`.

The script reads the exact Rust channel, components, and target from the
repository's `rust-toolchain.toml` (currently Rust 1.97.1). The current
bootstrap scope is Linux x86_64 with the `x86_64-unknown-linux-gnu` host
target; it fails before any download on another OS or architecture. Rustup,
Cargo, the Rust toolchain, the pinned Temurin Java 17 JRE, and downloaded
installers are stored below the ignored `.cache/toolchains/` directory. The
JMeter archive is read from (or downloaded to) the ignored
`jmeter-oracle-cache/` directory and is checked against the SHA-512 digest and
Apache PGP signature in `compat/profiles/jmeter-5.6.3.json` before use.
The bootstrap independently pins and validates profile `jmeter-5.6.3`,
profile version `2`, the `apache-jmeter-5.6.3.zip` filename, its pinned SHA-512,
and the official Apache archive, digest, signature, and `KEYS` endpoints before
accepting that profile.

The project-local rustup installer is pinned to rustup 1.29.0 for the declared
`x86_64-unknown-linux-gnu` host target. Its SHA-256 is
`4acc9acc76d5079515b46346a485974457b5a79893cfb01112423c89aeb5aa10`, from
the versioned official rustup archive sidecar. A cached older rustup binary is
replaced and then checked against this exact version; an unknown or mismatched
installer fails closed. The installed project-local rustup entrypoint is also
checked against that same pinned SHA-256.
The Rust entrypoints used by verification are additionally checked against the
checked-in `rust-1.97.1-x86_64-unknown-linux-gnu.entrypoints.sha256` manifest
before any cached Rust binary is executed. Its rustup value is the official
1.29.0 installer sidecar; the Rust component values are read-only measurements
of the checked cache. Cached Rustup/toolchain paths,
Java paths, and the JMeter launcher path must be regular current-user-owned
nodes with no group/world write bits; the bootstrap fails closed and does not
repair permissions automatically.
If a local cache was created with modes such as `775`, remediate only the
project-local cache roots before retrying (for example,
`chmod -R go-w .cache/toolchains jmeter-oracle-cache` and restore ownership
with the platform's ownership tool when needed).

All rustup network operations use the pinned `RUSTUP_DIST_SERVER` and
`RUSTUP_UPDATE_ROOT` values (`https://static.rust-lang.org` and
`https://static.rust-lang.org/rustup`). A repository cache lock serializes
both mutating and read-only bootstrap runs. The POSIX entrypoint delegates to
an internal Python launcher that opens the lock with `O_NOFOLLOW` and holds
the file descriptor with `flock`; `--check` opens an existing lock read-only
and never creates it. The lock itself must be a current-user-owned regular
file without group/world write bits; a missing or unsafe lock fails closed.
Downloads use same-directory temporary files and an
atomic rename; interrupted extraction is cleaned up without replacing an
existing verified cache entry.

The project-local Java runtime is Eclipse Temurin JRE 17.0.20+8
(`OpenJDK17U-jre_x64_linux_hotspot_17.0.20_8.tar.gz`, SHA-256
`ef491a51a46ef90cc47fbc4abb219fde32483ff91be5ec66ddc896df43524b27`). The
extracted Java executable is also checked against its pinned SHA-256
`6dce8306ebf735a85decdc801d84431f6e84525b60adc885624df05edeffb481`.
Java verification passes `-XX:-UsePerfData`; the JMeter version probe also
sets this through both `JAVA_TOOL_OPTIONS` and `JVM_ARGS`, so the supported
verification path does not create Java `hsperfdata` files.

It verifies `rustc`, Cargo (including the channel's Cargo package version
0.98.0), rustfmt 1.9.0, clippy 0.1.97, the configured target, the
project-local Java 17 runtime, and JMeter 5.6.3. The script uses HTTPS-only
downloads, checks pinned installer/archive checksums and the Apache signing
key, and never pipes an unverified download into a shell interpreter. The
JMeter shell launcher is invoked only as the executable entrypoint from the
digest-checked and signature-verified Apache archive; it is not downloaded or
trusted separately.
Utility lookup is restricted to `/usr/bin:/bin` from process start;
cached Rust and Java binaries are invoked by absolute path, so a caller's
PATH cannot make repository-cache utilities shadow bootstrap commands.

To inspect pinned metadata and validate an already-populated local cache
without mutating it, use the read-only check mode:

```sh
tools/bootstrap/bootstrap.sh --check
```

`--check` performs no downloads, installer launches, extraction, persistent
cache writes, or rustup settings changes. It performs a real JMeter PGP
signature verification by importing the pinned `KEYS` into a temporary
GnuPG home outside the repository; that temporary home is removed on exit and
the persistent `.cache/toolchains/gnupg` home is never touched. It fails
closed when a required verified artifact, cache entrypoint, exact version,
target metadata, or digest is missing or mismatched. The extracted JMeter
cache check is intentionally narrow: the archive is tested and only the
launcher entrypoint's type, interpreter, and pinned SHA-256 are asserted; it
does not claim that every extracted file has a separate manifest hash. A
successful check is therefore a local-cache integrity result, not a claim
that another platform is supported.

For deterministic hardening checks that use only temporary files and the
already cached signed JMeter fixture, run:

```sh
tools/bootstrap/bootstrap.sh --self-test
```

The self-test covers valid and tampered hashes, every pinned Rust entrypoint
manifest digest's exact length and content, symlink and permission rejection,
profile pinning, isolated PGP verification, Java `-XX:-UsePerfData`, the
wrapper handoff's direct/marker/FD-spoof/named-FIFO/trailing-byte/closed/
reused failure cases, FIFO-lock rejection, hostile `BASH_ENV` behavior, and
persistent-cache no-write behavior. Every normal invocation starts through a
sanitized `/bin/bash --noprofile --norc` environment with `BASH_ENV`, `ENV`,
exported functions, proxies, and caller PATH removed; the internal marker is
accepted only when the inherited pipe contains its exact one-shot cookie
record and descriptor 8 carries the locked cache file.
Bootstrap external utilities are
canonicalized and validated as root-owned non-symlink executables under
`/usr/bin` or `/bin`.

The bootstrap is intentionally project-local. To use the installed tools in a
separate command, set the paths explicitly for that command, for example:

```sh
RUSTUP_HOME="$PWD/.cache/toolchains/rustup" \
CARGO_HOME="$PWD/.cache/toolchains/cargo" \
PATH="$PWD/.cache/toolchains/cargo/bin:$PATH" \
cargo +1.97.1 test --workspace --locked
```
