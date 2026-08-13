# Development environment capabilities

This is a historical, read-only capability audit of the development host for
`jmeter-rs`. It was performed on 2026-08-12 (UTC) from
`/storage/webdev/jmeter-rs`, before the current workspace/toolchain bootstrap.
The audit did not install packages, change configuration, initialize
repositories, contact authenticated services, or dump environment variables.

> Historical snapshot notice: the observations below describe the host and
> repository at audit time. The workspace now contains Cargo manifests,
> `Cargo.lock`, and `rust-toolchain.toml`; do not cite the old “no workspace”
> findings as current capability evidence. Refresh this report when the host
> or CI image changes.

At audit time, the compatibility context was the pinned [Apache JMeter 5.6.3
profile](../../compat/profiles/jmeter-5.6.3.json). That profile requires a
Java 8-or-newer runtime (Java 17 is the recommended oracle runtime), while
the Rust testing strategy requires an explicitly selected and pinned Rust
toolchain before implementation begins. At audit time, this host supplied
neither runtime, so it could not compile the Rust workspace or run the JMeter
oracle.

## Summary at audit time

| Capability | Observed result | Consequence |
| --- | --- | --- |
| Host OS | Ubuntu 24.04.4 LTS, Linux 6.8.0-137-generic, x86_64, glibc 2.39, `amd64` | A useful Linux/glibc development baseline; the compatibility matrix still needs Windows, macOS, and other declared targets in CI. |
| Repository | Git 2.43.0; unborn local `main`; `origin` points to `https://github.com/OlegSotnikov/jmeter-rs.git`; no `Cargo.toml` or `Cargo.lock` at audit time | Source bootstrap was still pending at audit time. |
| Rust | `rustc`, `cargo`, and `rustup` are not on `PATH` | No Rust compilation, formatting, linting, target, component, or Cargo subcommand checks can run locally. |
| Java/JMeter | `java`, `javac`, and `jmeter` are not on `PATH`; no JMeter installation was found under `/opt`, `/usr/local`, or `/usr/share` | JMeter 5.6.3 differential/conformance tests are blocked on this host. |
| GitHub CLI | `gh` is missing | Git transport and unauthenticated HTTPS work; `gh`-based repository/release automation is unavailable. |
| Containers | Docker client/server 29.7.2 with `overlayfs`; Docker Compose v5.4.0; Podman missing | A containerized oracle and local fixture services are possible, subject to pinned images and resource controls. |
| Native build chain | GCC/`cc` 13.3.0, GNU `ld` 2.42, GNU Make 4.3, `pkg-config` 1.8.1; OpenSSL 3.0.13 and headers; zlib 1.3 and headers | Native Linux builds have a compiler/linker and common TLS compression development inputs. Clang/LLVM, LLD, mold, and CMake are absent. |
| Rust test/security tools | `cargo-nextest`, `cargo-deny`, `cargo-audit`, `cargo-llvm-cov`, `cargo-miri`, and `cargo-fuzz` cannot be queried because Cargo is absent | Install pinned tools in CI after the Rust toolchain is selected; do not treat their absence as a passing check. |
| Auxiliary test tooling | Python 3.12.3 and pip 26.1.2; pytest and lxml absent. Node 24.19.0, npm/npx 11.17.0. `jq` 1.7, curl 8.5.0, unzip/zip, GnuPG 2.4.4 available; `xmllint` absent | Prefer Rust-native tests and XML tooling. Python/Node are optional support tools, not runtime prerequisites. |
| Network | `git ls-remote` to the empty GitHub repository exited 0; Apache JMeter checksum URL returned HTTP 200 | Pinned downloads are reachable now, but release/CI jobs must verify checksums and fail closed on unavailable or changed artifacts. |
| Capacity | 125 GiB memory, no swap; root filesystem 228 GiB total, 39 GiB free (83% used) | Container layers, Rust target data, and JMeter archives need cleanup or CI isolation; avoid assuming unlimited local disk. |

## Evidence and safe commands

All commands below are read-only probes. Outputs are limited to versions,
capabilities, and repository metadata; usernames, tokens, and environment
variables were not printed.

### Operating system and repository

```text
$ uname -srmo
Linux 6.8.0-137-generic x86_64 GNU/Linux
$ getconf LONG_BIT
64
$ getconf GNU_LIBC_VERSION
glibc 2.39
$ dpkg --print-architecture
amd64
$ sed -n '1,8p' /etc/os-release
PRETTY_NAME="Ubuntu 24.04.4 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.4 LTS (Noble Numbat)"
VERSION_CODENAME=noble
$ git --version
git version 2.43.0
$ git status --short --branch
## No commits yet on main
?? .editorconfig
?? .gitattributes
?? .gitignore
?? CODE_OF_CONDUCT.md
?? CONTRIBUTING.md
?? LICENSE
?? NOTICE
?? README.md
?? SECURITY.md
?? compat/
?? docs/
$ git remote -v
origin  https://github.com/OlegSotnikov/jmeter-rs.git (fetch)
origin  https://github.com/OlegSotnikov/jmeter-rs.git (push)
$ rg --files -g 'Cargo.toml' -g 'Cargo.lock'
# no output
```

The repository is an unborn `main` branch with uncommitted initial files.
The absence of a Cargo manifest is expected at this research stage, but it
means Cargo cannot yet perform metadata or lockfile checks.

### Rust toolchain, targets, and components

```text
$ for c in rustc cargo rustup; do command -v "$c" || echo "$c: missing"; done
rustc: missing
cargo: missing
rustup: missing
$ rustc -vV
bash: rustc: command not found
```

Because all three drivers are absent, `rustc -vV`, `cargo -V`,
`rustup show`, `rustup target list --installed`, and
`rustup component list --installed` have no result on this host. No installed
Rust target/component set should be assumed. The repository's Rust strategy
therefore remains the source of policy: select an exact stable toolchain,
declare the MSRV separately, and include `rustfmt` and `clippy`; add
`llvm-tools-preview` only to coverage/sanitizer jobs.

### Java and the JMeter oracle

```text
$ java -version
java: missing
$ javac -version
javac: missing
$ command -v jmeter || echo 'jmeter: missing'
jmeter: missing
$ find /opt /usr/local /usr/share -maxdepth 4 -type f \
    \( -name 'jmeter' -o -name 'jmeter.sh' -o -name 'apache-jmeter-*.zip' \) \
    -print
# no output
$ update-alternatives --list java
update-alternatives: error: no alternatives for java
```

There is no local Java runtime, JDK, JMeter launcher, or discovered JMeter
archive outside the repository. This blocks all oracle cases, Java-plugin
delegation, JSR223/script cases, and Java-based distributed-worker fixtures.
The profile's exact Apache archive, SHA-512 digest, signature URL, and KEYS
URL are recorded in the compatibility profile; an implementation or CI job
must fetch those values explicitly rather than resolving `latest`.

### GitHub and network access

```text
$ gh --version
gh: missing
$ timeout 20s git ls-remote --heads --tags \
    https://github.com/OlegSotnikov/jmeter-rs.git
$ echo $?
0
$ timeout 20s curl -fsSI --max-time 15 \
    https://archive.apache.org/dist/jmeter/binaries/apache-jmeter-5.6.3.zip.sha512
HTTP/1.1 200 OK
Server: Apache
Last-Modified: Sun, 07 Jan 2024 16:59:22 GMT
Content-Length: 154
```

The successful `git ls-remote` produced no refs, consistent with the newly
created empty GitHub repository. The HTTP probe used `HEAD`; it did not
download JMeter. Network reachability is not artifact verification: CI must
download the pinned archive, check the profile's SHA-512 value, and verify the
Apache signature/key when the release job requires it.

### Containers

```text
$ docker version --format 'client={{.Client.Version}} server={{.Server.Version}}'
client=29.7.2 server=29.7.2
$ docker info --format 'server={{.ServerVersion}} storage={{.Driver}}'
server=29.7.2 storage=overlayfs
$ docker compose version
Docker Compose version v5.4.0
$ podman --version
podman: missing
```

The Docker daemon is reachable to the current user. Do not put credentials,
private endpoints, or untrusted JMX plans into a default container; the
repository baseline requires isolated, least-privileged oracle jobs.

### Native build dependencies

```text
$ cc --version | sed -n '1p'
cc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0
$ gcc --version | sed -n '1p'
gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0
$ ld --version | sed -n '1,2p'
GNU ld (GNU Binutils for Ubuntu) 2.42
Copyright (C) 2023 Free Software Foundation, Inc.
$ make --version | sed -n '1p'
GNU Make 4.3
$ pkg-config --version
1.8.1
$ openssl version
OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)
$ pkg-config --modversion openssl
3.0.13
$ pkg-config --modversion zlib
1.3
$ test -f /usr/include/openssl/ssl.h && echo 'OpenSSL headers: present'
OpenSSL headers: present
$ test -f /usr/include/zlib.h && echo 'zlib headers: present'
zlib headers: present
```

`clang`, `lld`, `mold`, and `cmake` were not found. GCC plus GNU `ld` is
sufficient for the normal Linux Rust linker path once Rust is installed.
Prefer a Rustls-based default to avoid making OpenSSL a mandatory native
dependency; if a native-TLS feature is added, CI must install and record the
development package and exact `pkg-config` result on each target.

### Test and analysis helpers

```text
$ python3 --version
Python 3.12.3
$ pip3 --version | sed -n '1p'
pip 26.1.2 ... (python 3.12)
$ python3 -c 'import importlib.util; print("pytest present" if importlib.util.find_spec("pytest") else "pytest missing")'
pytest missing
$ python3 -c 'import importlib.util; print("lxml present" if importlib.util.find_spec("lxml") else "lxml missing")'
lxml missing
$ node --version
v24.19.0
$ npm --version
11.17.0
$ npx --version
11.17.0
$ jq --version
jq-1.7
$ curl --version | sed -n '1p'
curl 8.5.0 (x86_64-pc-linux-gnu) ... OpenSSL/3.0.13 ...
$ gpg --version | sed -n '1p'
gpg (GnuPG) 2.4.4
$ xmllint --version
xmllint: missing
```

The Cargo-specific helper probe was not runnable because Cargo itself is
absent. Consequently `cargo nextest`, `cargo deny`, `cargo audit`,
`cargo llvm-cov`, `cargo miri`, and `cargo fuzz` have no observed version.
These tools are CI dependencies to pin after the workspace and toolchain
exist; their absence is not evidence that the associated checks pass.

### Capacity

```text
$ free -h
Mem: 125Gi total, 13Gi used, 51Gi free, 70Gi buff/cache, 112Gi available
Swap: 0B
$ df -h .
Filesystem  Size  Used  Avail  Use%
...         228G  179G  39G    83%
```

The exact backing-device name is omitted because it is not relevant to the
build contract. Local Docker layers, Cargo registries, JMeter archives, and
oracle artifacts should be pruned or kept in CI artifacts with explicit
retention limits.

## Reproducible bootstrap recommendations

These commands are recommendations only; none was run during this audit.
The placeholder `<PINNED_RUST_TOOLCHAIN>` must be selected by the project
architecture/compatibility policy rather than guessed from this host.

1. Add a committed `rust-toolchain.toml` with the exact stable toolchain,
   `rustfmt`, `clippy`, and the declared native target. Keep the package
   `rust-version` (MSRV) separate from the pinned developer/release compiler.
   Bootstrap a clean machine or CI image with a minimal profile:

   ```text
   rustup toolchain install <PINNED_RUST_TOOLCHAIN> --profile minimal \
     --component rustfmt --component clippy \
     --target x86_64-unknown-linux-gnu
   cargo +<PINNED_RUST_TOOLCHAIN> fetch --locked
   cargo +<PINNED_RUST_TOOLCHAIN> test --workspace --all-targets --locked
   ```

   Do not rely on an ambient host compiler. Once a workspace exists, commit
   `Cargo.lock` for executable and oracle packages and make CI use `--locked`.

2. Keep the fast CI lane Rust-native: format, MSRV check, pinned-stable
   tests, clippy, XML/property tests, local protocol fixtures, and a small
   CLI end-to-end case. Install each optional tool at a reviewed exact version
   in its own CI step. Coverage requires `llvm-tools-preview`; Miri and
   cargo-fuzz require a declared nightly toolchain; dependency checks require
   pinned `cargo-deny` and `cargo-audit` versions. The host's missing tools
   must not cause CI to silently skip required jobs.

3. Provision the JMeter oracle in an isolated CI job or pinned Docker image
   with Java 17 for the recommended baseline. Add a Java 8 compatibility job
   only where the profile's lower-bound matrix is required. Fetch
   `apache-jmeter-5.6.3.zip` from the profile URL, verify its recorded
   SHA-512 digest, verify the OpenPGP signature against a trusted Apache key,
   and record the Java vendor/version, JMeter archive hash, plugin hashes,
   locale, timezone, and environment allowlist in each run. Keep oracle
   fixtures local and deterministic; never use a public service as a timing
   oracle.

4. Use the currently available GCC/GNU linker baseline for Linux. Make
   OpenSSL/native TLS an explicit optional feature, with a CI job that
   installs the matching development headers and checks `pkg-config`; prefer
   rustls for the default build. Add Clang/LLVM, CMake, and LLD only to jobs
   that need sanitizers, fuzzing, or a measured alternative linker.

5. Use Docker Compose only for versioned local HTTP/TLS/proxy/database or
   distributed-worker fixtures. Pin base images by digest, mount only
   allowlisted fixture/result directories, disable unnecessary network access,
   cap CPU/memory/processes, and retain logs/JTLs as test artifacts. A Docker
   daemon being available on this host does not make an unpinned container a
   reproducible test environment.

6. If the network is unavailable, allow developers to run Rust-only tests with
   a clear `JMeter oracle unavailable` report, but make release conformance
   jobs fail when the declared JMeter archive, Java runtime, or fixture service
   cannot be verified. Cache by exact toolchain, lockfile, archive digest, and
   container digest; never cache a directory named `latest` as evidence.

7. Because this host has no swap and only 39 GiB free, monitor disk and memory
   in long-running load/soak jobs. Prefer ephemeral CI workers for full JMeter
   archives, plugin matrices, fuzz corpora, and Docker layers.

## Blockers recorded by the historical snapshot

The following were observed prerequisites at audit time, not implementation
defects or current release claims:

- Rust/rustup/Cargo must be bootstrapped before any Rust source, unit test,
  integration test, formatter, lint, coverage, fuzz, or audit job can run.
- A compatible JDK and the pinned Apache JMeter 5.6.3 distribution must be
  provisioned before differential compatibility tests can run.
- A Cargo workspace and lockfile did not exist yet, so dependency and package
  reproducibility checks were not meaningful at audit time.
- Cross-platform compatibility is not testable on this Linux-only host; the
  declared Linux, Windows, and macOS matrix belongs in CI.

This report intentionally does not turn any missing prerequisite into a
support claim. Refresh it after workspace/toolchain bootstrap and whenever the
CI image changes; do not infer present-day availability from this snapshot.
