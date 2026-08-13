#!/bin/bash

set -Eeuo pipefail

# The Bash implementation is an internal payload.  The supported POSIX
# wrapper/launcher reserves descriptor 9 for a one-shot anonymous-pipe
# handoff and passes only a fixed argument marker.  This is not authentication:
# a same-uid caller can reproduce the marker and record.  Keep the handoff
# check before every external lookup and before deriving any cache path, while
# relying on the Python wrapper's locked-cache preconditions for authority.
bootstrap_capability_cookie="jmeter-rs-bootstrap-capability-v1"
bootstrap_capability_fd=9
bootstrap_capability_argument="--bootstrap-capability"
bootstrap_capability_self_test_option="--bootstrap-capability-self-test"
bootstrap_capability_marker="${1-}"
if [[ "$bootstrap_capability_marker" != "$bootstrap_capability_argument" ]]; then
    printf 'bootstrap error: internal bootstrap requires the supported wrapper handoff\n' >&2
    exit 1
fi
if [[ ! -p "/proc/self/fd/$bootstrap_capability_fd" ]]; then
    printf 'bootstrap error: wrapper handoff descriptor is missing or not a pipe\n' >&2
    exit 1
fi

# Linux exposes descriptor status without an external utility.  An inherited
# anonymous pipe has no file-status flags after Python marks it inheritable;
# named FIFOs retain filesystem/open flags and are rejected before reading.
bootstrap_capability_fd_flags=""
bootstrap_capability_fd_mnt_id=""
while IFS= read -r bootstrap_capability_fdinfo_line; do
    case "$bootstrap_capability_fdinfo_line" in
        flags:*)
            bootstrap_capability_fd_flags="${bootstrap_capability_fdinfo_line#flags:}"
            bootstrap_capability_fd_flags="${bootstrap_capability_fd_flags//[[:space:]]/}"
            ;;
        mnt_id:*)
            bootstrap_capability_fd_mnt_id="${bootstrap_capability_fdinfo_line#mnt_id:}"
            bootstrap_capability_fd_mnt_id="${bootstrap_capability_fd_mnt_id//[[:space:]]/}"
            ;;
    esac
done < "/proc/self/fdinfo/$bootstrap_capability_fd" || {
    printf 'bootstrap error: wrapper handoff descriptor status is unavailable\n' >&2
    exit 1
}
if [[ "$bootstrap_capability_fd_flags" != "00" ]]; then
    printf 'bootstrap error: wrapper handoff descriptor is not an anonymous pipe\n' >&2
    exit 1
fi
[[ "$bootstrap_capability_fd_mnt_id" =~ ^[0-9]+$ ]] || {
    printf 'bootstrap error: wrapper handoff descriptor mount identity is invalid\n' >&2
    exit 1
}
bootstrap_capability_mount_match=0
while IFS= read -r bootstrap_capability_mount_line; do
    bootstrap_capability_mount_id="${bootstrap_capability_mount_line%% *}"
    if [[ "$bootstrap_capability_mount_id" == "$bootstrap_capability_fd_mnt_id" ]]; then
        bootstrap_capability_mount_match=1
        break
    fi
done < /proc/self/mountinfo
if [[ "$bootstrap_capability_mount_match" == 1 ]]; then
    printf 'bootstrap error: wrapper handoff descriptor is a named filesystem FIFO\n' >&2
    exit 1
fi

bootstrap_capability_record=""
# The wrapper closes the pipe writer before exec.  Keep hostile/incomplete
# descriptors bounded as well; this is a handshake timeout, not a retry or
# correctness sleep.
if IFS= read -r -N 98 -t 1 bootstrap_capability_record <&9; then
    :
else
    bootstrap_capability_read_status=$?
    if [[ "$bootstrap_capability_read_status" == 142 ]]; then
        printf 'bootstrap error: wrapper handoff descriptor read timed out\n' >&2
    else
        printf 'bootstrap error: wrapper handoff descriptor is closed or truncated\n' >&2
    fi
    exit 1
fi
if [[ "$bootstrap_capability_record" != \
    "$bootstrap_capability_cookie:"* || \
    ! "$bootstrap_capability_record" =~ ^${bootstrap_capability_cookie}:[0-9a-fA-F]{64}$ ]]; then
    printf 'bootstrap error: wrapper handoff cookie or nonce is invalid\n' >&2
    exit 1
fi
bootstrap_capability_trailing=""
if IFS= read -r -N 1 -t 1 bootstrap_capability_trailing <&9; then
    printf 'bootstrap error: wrapper handoff has trailing bytes\n' >&2
    exit 1
else
    bootstrap_capability_trailing_status=$?
    if [[ "$bootstrap_capability_trailing_status" == 142 ]]; then
        printf 'bootstrap error: wrapper handoff did not reach EOF\n' >&2
        exit 1
    fi
fi
exec 9<&-
unset bootstrap_capability_marker bootstrap_capability_record \
    bootstrap_capability_fd_flags bootstrap_capability_fdinfo_line \
    bootstrap_capability_fd_mnt_id bootstrap_capability_mount_match \
    bootstrap_capability_mount_line bootstrap_capability_mount_id \
    bootstrap_capability_trailing
shift

# A tiny internal-only probe lets the launcher self-test exercise this gate
# without resolving a utility or touching repository/cache state.  It is
# reachable only after the inherited capability has been consumed.
if [[ "${1-}" == "$bootstrap_capability_self_test_option" ]]; then
    [[ "$#" -eq 1 ]] || {
        printf 'bootstrap error: invalid capability self-test arguments\n' >&2
        exit 1
    }
    exit 0
fi

# Normal execution also requires the inherited descriptor 8 lock handoff.
# The fixed descriptor is not an authentication secret; it makes a forged
# capability record useless without the same cache-root/lock preconditions
# that the trusted Python launcher validates.  The fixed system flock command
# reasserts exclusive ownership for a forged FD handoff too.  --self-test is
# read-only and intentionally has no lock authority.
if [[ "${1-}" != "--self-test" && ! -f /proc/self/fd/8 ]]; then
    printf 'bootstrap error: locked cache handoff is missing\n' >&2
    exit 1
fi

# The bootstrap currently supports one host only. Keep command lookup on a
# fixed set of trusted system directories from process start; never allow a
# repository cache directory to shadow even the path-resolution helpers.
trusted_system_path="/usr/bin:/bin"
export PATH="$trusted_system_path"

bootstrap_fatal() {
    printf 'bootstrap error: %s\n' "$*" >&2
    exit 1
}

trusted_stat="/usr/bin/stat"
trusted_readlink="/usr/bin/readlink"
trusted_flock="/usr/bin/flock"
[[ -x "$trusted_stat" && ! -L "$trusted_stat" ]] || \
    bootstrap_fatal "trusted system stat utility is unavailable: $trusted_stat"
[[ -x "$trusted_readlink" && ! -L "$trusted_readlink" ]] || \
    bootstrap_fatal "trusted system readlink utility is unavailable: $trusted_readlink"
[[ -x "$trusted_flock" && ! -L "$trusted_flock" ]] || \
    bootstrap_fatal "trusted system flock utility is unavailable: $trusted_flock"

validate_trusted_system_file() {
    local path="$1"
    local owner mode
    [[ "$path" == /usr/bin/* || "$path" == /bin/* ]] || \
        bootstrap_fatal "trusted utility is outside the fixed system roots: $path"
    [[ -f "$path" && -x "$path" && ! -L "$path" ]] || \
        bootstrap_fatal "trusted utility is not a non-symlink executable: $path"
    owner="$("$trusted_stat" -c '%u' -- "$path")"
    mode="$("$trusted_stat" -c '%a' -- "$path")"
    [[ "$owner" == "0" ]] || bootstrap_fatal "trusted utility is not root-owned: $path"
    (( (8#$mode & 022) == 0 )) || \
        bootstrap_fatal "trusted utility is group/world-writable: $path"
}

validate_trusted_system_file "$trusted_stat"
validate_trusted_system_file "$trusted_readlink"
validate_trusted_system_file "$trusted_flock"

resolve_trusted_utility() {
    local name="$1"
    local destination="$2"
    local candidate resolved
    candidate="$(command -v "$name" 2>/dev/null || true)"
    if [[ "$candidate" != /* ]]; then
        for candidate in "/usr/bin/$name" "/bin/$name"; do
            [[ -f "$candidate" ]] && break
        done
    fi
    [[ "$candidate" == /* ]] || \
        bootstrap_fatal "required system utility is not resolved to an absolute path: $name"
    resolved="$("$trusted_readlink" -f -- "$candidate")" || \
        bootstrap_fatal "could not canonicalize trusted utility: $name"
    validate_trusted_system_file "$resolved"
    printf -v "$destination" '%s' "$resolved"
}

utility_dirname=""
utility_pwd=""
resolve_trusted_utility dirname utility_dirname
resolve_trusted_utility pwd utility_pwd

repo_root="$(cd -- "$("$utility_dirname" -- "${BASH_SOURCE[0]}")/../.." && "$utility_pwd" -P)"
toolchain_file="$repo_root/rust-toolchain.toml"
profile_file="$repo_root/compat/profiles/jmeter-5.6.3.json"

if [[ "${1-}" != "--self-test" ]]; then
    bootstrap_lock_target="$("$trusted_readlink" -f -- /proc/self/fd/8)" || \
        bootstrap_fatal "could not resolve inherited bootstrap lock descriptor"
    [[ "$bootstrap_lock_target" == "$repo_root/.cache/.bootstrap.lock" ]] || \
        bootstrap_fatal "inherited bootstrap lock is outside the repository cache"
    "$trusted_flock" -n 8 || \
        bootstrap_fatal "inherited bootstrap lock is not held exclusively"
    unset bootstrap_lock_target
fi

cache_root="$repo_root/.cache/toolchains"
downloads_dir="$cache_root/downloads"
rustup_home="$cache_root/rustup"
cargo_home="$cache_root/cargo"
rustup_bin="$cargo_home/bin/rustup"
java_root="$cache_root/java"
gnupg_home="$cache_root/gnupg"
check_mode=0
self_test_mode=0
temporary_paths=()

utility_stat="$trusted_stat"
utility_readlink="$trusted_readlink"
utility_rm=""
utility_mkdir=""
utility_mv=""
utility_rmdir=""
utility_chmod=""
utility_python3=""
utility_grep=""
utility_sha256sum=""
utility_sha512sum=""
utility_mktemp=""
utility_curl=""
utility_unzip=""
utility_tar=""
utility_sed=""
utility_tail=""
utility_gpg=""
utility_env=""
utility_uname=""
utility_id=""
utility_cp=""
utility_ln=""
utility_find=""
for utility_name in \
    rm mkdir mv rmdir chmod python3 grep sha256sum sha512sum mktemp curl \
    unzip tar sed tail gpg env uname id cp ln find; do
    resolve_trusted_utility "$utility_name" "utility_$utility_name"
done
current_uid="$("$utility_id" -u)"
[[ "$current_uid" =~ ^[0-9]+$ ]] || bootstrap_fatal "could not determine current uid"

rust_version="1.97.1"
rust_cargo_package_version="0.98.0"
rustfmt_package_version="1.9.0"
clippy_package_version="0.1.97"
# Keep the installer version, host target, and digest paired.  The digest is
# the value published by the official rustup archive sidecar at:
# https://static.rust-lang.org/rustup/archive/1.29.0/x86_64-unknown-linux-gnu/rustup-init.sha256
# Do not replace this with a floating dist/latest URL or an unverified digest.
rustup_version="1.29.0"
rustup_target="x86_64-unknown-linux-gnu"
rustup_url="https://static.rust-lang.org/rustup/archive/${rustup_version}/${rustup_target}/rustup-init"
rustup_sha256="4acc9acc76d5079515b46346a485974457b5a79893cfb01112423c89aeb5aa10"
rustup_executable_sha256="$rustup_sha256"
rustup_dist_server="https://static.rust-lang.org"
rustup_update_root="https://static.rust-lang.org/rustup"
rust_entrypoint_manifest="$repo_root/tools/bootstrap/rust-1.97.1-x86_64-unknown-linux-gnu.entrypoints.sha256"

# Pin the project-local Java runtime instead of depending on an ambient JDK.
# The release and checksum are from the Eclipse Temurin 17 API entry for the
# exact Linux x64 HotSpot JRE archive below; no "latest" URL is used.
java_release="17.0.20+8"
java_archive="OpenJDK17U-jre_x64_linux_hotspot_17.0.20_8.tar.gz"
java_url="https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.20%2B8/${java_archive}"
java_checksum_url="${java_url}.sha256.txt"
java_sha256="ef491a51a46ef90cc47fbc4abb219fde32483ff91be5ec66ddc896df43524b27"
# Hashes of executable entrypoints inside the pinned Linux x86_64 artifacts.
# They are checked after extraction/installation in addition to archive hashes.
java_executable_sha256="6dce8306ebf735a85decdc801d84431f6e84525b60adc885624df05edeffb481"
java_home="$java_root/jdk-${java_release}-jre"

# Apache's release signature is made by this key. The fingerprint check is
# deliberate: the KEYS file is fetched over HTTPS, but an imported key is not
# treated as trusted merely because it appears in that file.
jmeter_signature_fingerprint="C4923F9ABFB2F1A06F08E88BAC214CAA0612B399"
jmeter_launcher_sha256="4055fdef809e6e6f48ddf85da7c67807f86593f9c7a068e7aef488f3299f8f9f"
jmeter_profile_id="jmeter-5.6.3"
jmeter_profile_version="2"
jmeter_upstream_version="5.6.3"
jmeter_artifact_format="zip"
jmeter_digest_algorithm="SHA-512"
jmeter_artifact_filename="apache-jmeter-5.6.3.zip"
jmeter_artifact_sha512="387fadca903ee0aa30e3f2115fdfedb3898b102e6b9fe7cc3942703094bd2e65b235df2b0c6d0d3248e74c9a7950a36e42625fd74425368342c12e40b0163076"
jmeter_artifact_url="https://archive.apache.org/dist/jmeter/binaries/apache-jmeter-5.6.3.zip"
jmeter_digest_url="https://archive.apache.org/dist/jmeter/binaries/apache-jmeter-5.6.3.zip.sha512"
jmeter_signature_url="https://archive.apache.org/dist/jmeter/binaries/apache-jmeter-5.6.3.zip.asc"
jmeter_keys_url="https://archive.apache.org/dist/jmeter/KEYS"
java_no_perf_data_arg="-XX:-UsePerfData"

die() {
    printf 'bootstrap error: %s\n' "$*" >&2
    exit 1
}

cleanup_on_exit() {
    local path
    for path in "${temporary_paths[@]}"; do
        [[ -n "$path" ]] || continue
        if [[ -d "$path" && ! -L "$path" ]]; then
            "$utility_rm" -rf -- "$path"
        else
            "$utility_rm" -f -- "$path"
        fi
    done
}

trap cleanup_on_exit EXIT

register_temporary_path() {
    temporary_paths+=("$1")
}

forget_temporary_path() {
    local path="$1"
    local index
    for index in "${!temporary_paths[@]}"; do
        if [[ "${temporary_paths[index]}" == "$path" ]]; then
            temporary_paths[index]=""
            return
        fi
    done
}

parse_exact_version() {
    local actual="$1"
    local expected="$2"
    local kind="$3"

    "$utility_python3" - "$actual" "$expected" "$kind" <<'PY'
import re
import sys

actual, expected, kind = sys.argv[1:]
patterns = {
    "rustup": r"^rustup\s+(\d+\.\d+\.\d+)\s+\([^)]*\)$",
    "rustc": r"^rustc\s+(\d+\.\d+\.\d+)\s+\([^\s)]+\s+[^)]*\)$",
    "cargo": r"^cargo\s+(\d+\.\d+\.\d+)\s+\([^\s)]+\s+[^)]*\)$",
    "rustfmt": r"^rustfmt\s+(\d+\.\d+\.\d+)-stable\s+\([^\s)]+\s+[^)]*\)$",
    "clippy": r"^clippy\s+(\d+\.\d+\.\d+)\s+\([^\s)]+\s+[^)]*\)$",
    "java": r'^openjdk version "(\d+\.\d+\.\d+)"\s+.*$',
}
pattern = patterns.get(kind)
if pattern is None:
    raise SystemExit(f"unknown version kind: {kind}")
match = re.fullmatch(pattern, actual)
if match is None or match.group(1) != expected:
    raise SystemExit(
        f"unexpected {kind} version: expected {expected}, got {actual!r}"
    )
PY
}

parse_exact_manifest_version() {
    local manifest="$1"
    local package="$2"
    local expected="$3"

    "$utility_python3" - "$manifest" "$package" "$expected" <<'PY'
import sys
import tomllib

path, package, expected = sys.argv[1:]
with open(path, "rb") as handle:
    manifest = tomllib.load(handle)
actual = manifest.get("pkg", {}).get(package, {}).get("version")
if actual != expected and not (
    package == "cargo" and isinstance(actual, str) and actual.split(" ", 1)[0] == expected
):
    raise SystemExit(f"unexpected {package} version: expected {expected}, got {actual!r}")
PY
}

parse_exact_jmeter_version() {
    local output="$1"
    local expected="$2"

    "$utility_python3" - "$output" "$expected" <<'PY'
import re
import sys

output, expected = sys.argv[1:]
matches = [
    line.strip()
    for line in output.splitlines()
    if re.search(r"(?<![0-9.])" + re.escape(expected) + r"$", line.strip())
]
if len(matches) != 1:
    raise SystemExit(
        f"expected exactly one JMeter banner ending in {expected!r}, found {len(matches)}"
    )
PY
}

verify_rustup_binary() {
    assert_secure_cache_path "$rustup_bin" "project-local rustup" "$repo_root/.cache"
    verify_file_sha256 "$rustup_bin" "$rustup_executable_sha256" \
        "project-local rustup"
}

verify_rust_entrypoint_manifest() {
    local channel="$1"
    local -a relative_paths=(
        "cargo/bin/rustup"
        "rustup/toolchains/${channel}-${rustup_target}/bin/rustc"
        "rustup/toolchains/${channel}-${rustup_target}/bin/cargo"
        "rustup/toolchains/${channel}-${rustup_target}/bin/rustfmt"
        "rustup/toolchains/${channel}-${rustup_target}/bin/clippy-driver"
        "rustup/toolchains/${channel}-${rustup_target}/bin/cargo-clippy"
    )
    local -a expected_hashes=(
        "$rustup_executable_sha256"
        "d3a664c970a9fd8361b64194861bebc1ae37b9054e5ee3400dc1c9e691797eea"
        "828980723df339d62434390e9fb8ef8831036583343ae2316b7ab5646b5c1953"
        "30de9e1efcd8f8fe7750e00d0c45ff8f4c480608ef1be5baf9ab6f1b4556e8f8"
        "e8fa6ad666c353e4c9248fc67074cf160ff2a5dbd97debd20416b81d7f917373"
        "a0a3808dddb32f525601e608740ee7c1c5df86db4a7183ea945449f60d29509d"
    )
    local index
    local metadata_only="${2:-0}"

    for index in "${!expected_hashes[@]}"; do
        [[ "${#expected_hashes[index]}" -eq 64 ]] || \
            die "pinned Rust entrypoint digest has the wrong length: ${relative_paths[index]}"
        [[ "${expected_hashes[index]}" =~ ^[[:xdigit:]]{64}$ ]] || \
            die "pinned Rust entrypoint digest is malformed: ${relative_paths[index]}"
    done

    assert_regular_file "$rust_entrypoint_manifest" \
        "checked Rust entrypoint manifest"
    if ! "$utility_python3" - "$rust_entrypoint_manifest" \
        "${relative_paths[0]}" "${expected_hashes[0]}" \
        "${relative_paths[1]}" "${expected_hashes[1]}" \
        "${relative_paths[2]}" "${expected_hashes[2]}" \
        "${relative_paths[3]}" "${expected_hashes[3]}" \
        "${relative_paths[4]}" "${expected_hashes[4]}" \
        "${relative_paths[5]}" "${expected_hashes[5]}" <<'PY'
import re
import sys

path = sys.argv[1]
expected = dict(zip(sys.argv[2::2], sys.argv[3::2]))
actual = {}
with open(path, encoding="ascii") as handle:
    for line_number, raw_line in enumerate(handle, 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) != 2 or not re.fullmatch(r"[0-9a-fA-F]{64}", fields[0]):
            raise SystemExit(f"malformed Rust entrypoint manifest line {line_number}")
        if fields[1] in actual:
            raise SystemExit(f"duplicate Rust entrypoint manifest path: {fields[1]}")
        actual[fields[1]] = fields[0].lower()
if actual != {key: value.lower() for key, value in expected.items()}:
    raise SystemExit("Rust entrypoint manifest does not match the pinned hash map")
PY
    then
        die "Rust entrypoint manifest does not match the pinned hash map"
    fi

    [[ "$metadata_only" == 0 || "$metadata_only" == 1 ]] || \
        die "invalid Rust entrypoint manifest validation mode"
    [[ "$metadata_only" == 0 ]] || return 0

    for index in "${!relative_paths[@]}"; do
        assert_secure_cache_path "$cache_root/${relative_paths[index]}" \
            "Rust entrypoint ${relative_paths[index]}" "$repo_root/.cache"
        verify_file_sha256 "$cache_root/${relative_paths[index]}" \
            "${expected_hashes[index]}" "Rust entrypoint ${relative_paths[index]}"
    done
}

validate_rust_cache_entrypoints() {
    local channel="$1"
    local toolchain_root="$rustup_home/toolchains/${channel}-${rustup_target}"
    local proxy

    verify_rust_entrypoint_manifest "$channel"
    assert_secure_cache_path "$rustup_home" "rustup home" "$repo_root/.cache"
    assert_secure_cache_path "$cargo_home/bin" "Cargo bin directory" "$repo_root/.cache"
    verify_rustup_binary
    for proxy in cargo cargo-clippy cargo-fmt rustc rustdoc rustfmt; do
        [[ -L "$cargo_home/bin/$proxy" ]] || \
            die "project-local Rust proxy is not a symlink: $cargo_home/bin/$proxy"
        [[ "$("$utility_readlink" -- "$cargo_home/bin/$proxy")" == "rustup" ]] || \
            die "project-local Rust proxy does not point to rustup: $cargo_home/bin/$proxy"
    done

    assert_secure_cache_path "$toolchain_root" "Rust toolchain cache" "$repo_root/.cache"
    assert_secure_cache_path "$toolchain_root/bin" "Rust toolchain bin directory" "$repo_root/.cache"
    for entrypoint in rustc cargo rustfmt clippy-driver; do
        assert_secure_cache_path "$toolchain_root/bin/$entrypoint" \
            "Rust toolchain $entrypoint" "$repo_root/.cache"
        assert_executable_file "$toolchain_root/bin/$entrypoint" \
            "Rust toolchain $entrypoint"
    done
    assert_regular_file \
        "$toolchain_root/lib/rustlib/multirust-channel-manifest.toml" \
        "Rust channel manifest"
}

validate_rust_target() {
    local channel="$1"
    local toolchain_root="$rustup_home/toolchains/$channel-$rustup_target"
    local toolchain_bin="$toolchain_root/bin"
    local target_root="$toolchain_root/lib/rustlib/$rustup_target"
    local target_libdir
    local target_sysroot
    local target_cfg
    local rustc_verbose
    local stdlib
    local candidate

    # Verify both rustc's resolved target paths and the target metadata, not
    # merely the existence of a rustlib directory with the right name.
    assert_directory "$target_root" "Rust target sysroot"
    assert_directory "$target_root/bin" "Rust target tool directory"
    assert_directory "$target_root/lib" "Rust target library directory"
    assert_regular_file "$toolchain_root/lib/rustlib/manifest-rust-std-$rustup_target" \
        "Rust target component manifest"
    rustc_verbose="$("$toolchain_bin/rustc" -vV)"
    "$utility_grep" -Fxq "host: $rustup_target" <<<"$rustc_verbose" || \
        die "rustc host does not match the pinned target: $rustup_target"
    target_sysroot="$("$toolchain_bin/rustc" --target "$rustup_target" --print sysroot)"
    [[ "$target_sysroot" == "$toolchain_root" ]] || \
        die "rustc resolved an unexpected target sysroot: $target_sysroot"
    target_libdir="$("$toolchain_bin/rustc" --target "$rustup_target" --print target-libdir)"
    [[ "$target_libdir" == "$target_root/lib" ]] || \
        die "rustc resolved an unexpected target library directory: $target_libdir"
    assert_directory "$target_libdir" "Rust target library directory"
    stdlib=""
    for candidate in "$target_libdir"/libstd-*.rlib; do
        if [[ -f "$candidate" ]]; then
            stdlib="$candidate"
            break
        fi
    done
    [[ -n "$stdlib" ]] || die "Rust target standard library archive is missing: $target_libdir"
    assert_regular_file "$stdlib" "Rust target standard library archive"
    target_cfg="$("$toolchain_bin/rustc" --target "$rustup_target" --print cfg)"
    for expected_cfg in 'target_arch="x86_64"' 'target_env="gnu"' 'target_os="linux"'; do
        "$utility_grep" -Fxq "$expected_cfg" <<<"$target_cfg" || \
            die "Rust target cfg is incomplete for $rustup_target: $expected_cfg"
    done
}

validate_java_cache_entrypoints() {
    local java_bin="$java_home/bin/java"
    assert_secure_cache_path "$java_home" "project-local Java home" "$repo_root/.cache"
    assert_secure_cache_path "$java_home/bin" "project-local Java bin directory" "$repo_root/.cache"
    assert_secure_cache_path "$java_bin" "project-local Java executable" "$repo_root/.cache"
    assert_executable_file "$java_bin" "project-local Java executable"
    assert_regular_file "$java_home/release" "project-local Java release metadata"
    verify_file_sha256 "$java_bin" "$java_executable_sha256" "project-local Java executable"
}

validate_jmeter_cache_entrypoints() {
    local oracle_cache="$repo_root/jmeter-oracle-cache"
    local jmeter_dir="$oracle_cache/apache-jmeter-5.6.3"
    local jmeter_bin="$jmeter_dir/bin/jmeter"
    assert_secure_cache_path "$oracle_cache" "JMeter oracle cache" "$oracle_cache"
    assert_secure_cache_path "$jmeter_dir" "JMeter extracted cache" "$oracle_cache"
    assert_secure_cache_path "$jmeter_dir/bin" "JMeter bin directory" "$oracle_cache"
    assert_secure_cache_path "$jmeter_bin" "JMeter shell launcher" "$oracle_cache"
    assert_executable_file "$jmeter_bin" "JMeter shell launcher"
    verify_file_sha256 "$jmeter_bin" "$jmeter_launcher_sha256" "JMeter shell launcher"
}

parse_options() {
    case "$#" in
        0) ;;
        1)
            case "$1" in
                --check) check_mode=1 ;;
                --self-test) self_test_mode=1 ;;
                *) die "usage: bootstrap.sh [--check|--self-test]" ;;
            esac
            ;;
        *) die "usage: bootstrap.sh [--check|--self-test]" ;;
    esac
}

check_supported_host() {
    local operating_system
    local machine
    operating_system="$("$utility_uname" -s)"
    machine="$("$utility_uname" -m)"
    [[ "$operating_system" == "Linux" ]] || \
        die "unsupported host OS: $operating_system (bootstrap currently supports Linux x86_64 only)"
    [[ "$machine" == "x86_64" ]] || \
        die "unsupported host architecture: $machine (bootstrap currently supports Linux x86_64 only)"
    [[ "$rustup_target" == "x86_64-unknown-linux-gnu" ]] || \
        die "configured rustup target is outside the supported Linux x86_64 scope: $rustup_target"
}

assert_not_symlink() {
    local path="$1"
    local description="$2"
    [[ ! -L "$path" ]] || die "$description must not be a symlink: $path"
}

assert_directory() {
    local path="$1"
    local description="$2"
    assert_not_symlink "$path" "$description"
    [[ -d "$path" ]] || die "$description is not a directory: $path"
}

assert_regular_file() {
    local path="$1"
    local description="$2"
    assert_not_symlink "$path" "$description"
    [[ -f "$path" ]] || die "$description is not a regular file: $path"
}

assert_executable_file() {
    local path="$1"
    local description="$2"
    assert_regular_file "$path" "$description"
    [[ -x "$path" ]] || die "$description is not executable: $path"
}

assert_secure_cache_node() {
    local path="$1"
    local description="$2"
    local owner mode

    assert_not_symlink "$path" "$description"
    [[ -e "$path" ]] || die "$description is missing: $path"
    owner="$("$utility_stat" -c '%u' -- "$path")"
    mode="$("$utility_stat" -c '%a' -- "$path")"
    [[ "$owner" == "$current_uid" ]] || \
        die "$description is not owned by the current uid ($current_uid): $path"
    [[ "$mode" =~ ^[0-7]+$ ]] || die "$description has an unreadable mode: $path"
    (( (8#$mode & 022) == 0 )) || \
        die "$description is group/world-writable (mode $mode); remediate it before bootstrap: $path"
    [[ -d "$path" || -f "$path" ]] || \
        die "$description is not a directory or regular file: $path"
}

assert_secure_cache_path() {
    local path="$1"
    local description="$2"
    local root="$3"
    local remainder component current

    [[ "$path" == "$root" || "$path" == "$root/"* ]] || \
        die "$description is outside its declared cache root: $path"
    assert_secure_cache_node "$root" "cache root for $description"
    remainder="${path#"$root"}"
    remainder="${remainder#/}"
    current="$root"
    while [[ -n "$remainder" ]]; do
        component="${remainder%%/*}"
        if [[ "$remainder" == */* ]]; then
            remainder="${remainder#*/}"
        else
            remainder=""
        fi
        [[ -n "$component" && "$component" != "." && "$component" != ".." ]] || \
            die "$description has an unsafe cache path component: $path"
        current="$current/$component"
        assert_secure_cache_node "$current" "$description path component"
    done
}

assert_secure_cache_tree() {
    local root="$1"
    local description="$2"
    local node owner mode resolved

    assert_secure_cache_node "$root" "$description"
    while IFS= read -r -d '' node; do
        if [[ -L "$node" ]]; then
            [[ ! -d "$node" ]] || \
                die "$description tree entry is a symlinked directory: $node"
            resolved="$("$utility_readlink" -f -- "$node")" || \
                die "$description tree entry symlink cannot be resolved: $node"
            [[ "$resolved" == "$root/"* ]] || \
                die "$description tree entry symlink escapes its cache root: $node"
            assert_secure_cache_node "$resolved" "$description symlink target"
            continue
        fi
        [[ -d "$node" || -f "$node" ]] || \
            die "$description tree entry is not a directory or regular file: $node"
        owner="$("$utility_stat" -c '%u' -- "$node")"
        mode="$("$utility_stat" -c '%a' -- "$node")"
        [[ "$owner" == "$current_uid" ]] || \
            die "$description tree entry is not owned by the current uid ($current_uid): $node"
        [[ "$mode" =~ ^[0-7]+$ ]] || die "$description tree entry has an unreadable mode: $node"
        (( (8#$mode & 022) == 0 )) || \
            die "$description tree entry is group/world-writable (mode $mode); remediate it before bootstrap: $node"
    done < <("$utility_find" -P -- "$root" -xdev -mindepth 1 -print0)
}

ensure_directory() {
    local path="$1"
    local description="$2"
    if [[ -L "$path" ]]; then
        die "$description must not be a symlink: $path"
    fi
    if [[ -e "$path" ]]; then
        [[ -d "$path" ]] || die "$description is not a directory: $path"
        return
    fi
    "$utility_mkdir" -m 0700 -- "$path"
}

ensure_file_destination() {
    local path="$1"
    local description="$2"
    assert_not_symlink "$path" "$description"
    if [[ -e "$path" ]]; then
        [[ -f "$path" ]] || die "$description is not a regular file: $path"
    fi
}

verify_file_sha256() {
    local file="$1"
    local expected="$2"
    local description="$3"

    [[ "$expected" =~ ^[[:xdigit:]]{64}$ ]] || \
        die "expected SHA-256 is malformed for $description"
    assert_regular_file "$file" "$description"
    if ! printf '%s  %s\n' "$expected" "$file" | \
        "$utility_sha256sum" --check --status -; then
        die "SHA-256 mismatch for $description: $file"
    fi
}

file_sha256_matches() {
    local file="$1"
    local expected="$2"
    assert_regular_file "$file" "hashed file"
    [[ "$expected" =~ ^[[:xdigit:]]{64}$ ]] || return 1
    printf '%s  %s\n' "$expected" "$file" | "$utility_sha256sum" --check --status -
}

verify_file_sha512() {
    local file="$1"
    local expected="$2"
    local description="$3"

    [[ "$expected" =~ ^[[:xdigit:]]{128}$ ]] || \
        die "expected SHA-512 is malformed for $description"
    assert_regular_file "$file" "$description"
    if ! printf '%s  %s\n' "$expected" "$file" | \
        "$utility_sha512sum" --check --status -; then
        die "SHA-512 mismatch for $description: $file"
    fi
}

download_https() {
    local url="$1"
    local destination="$2"
    local destination_dir="${destination%/*}"
    local destination_name="${destination##*/}"
    local temporary

    case "$url" in
        https://*) ;;
        *) die "refusing non-HTTPS download URL: $url" ;;
    esac

    assert_directory "$destination_dir" "download directory"
    ensure_file_destination "$destination" "download destination"
    temporary="$("$utility_mktemp" "$destination_dir/.${destination_name}.part.XXXXXX")"
    register_temporary_path "$temporary"
    if ! "$utility_curl" --fail --location --proto '=https' --tlsv1.2 \
        --retry 3 --retry-delay 2 --connect-timeout 20 --max-time 900 \
        --output "$temporary" "$url"; then
        die "download failed: $url"
    fi
    assert_regular_file "$temporary" "temporary download"
    # The temporary file is in the destination directory, so rename is
    # atomic. An interrupted transfer can leave only a .part file; it cannot
    # replace a previously verified final artifact.
    "$utility_mv" -f -- "$temporary" "$destination"
    forget_temporary_path "$temporary"
}

verify_published_sha256() {
    local archive="$1"
    local sidecar="$2"
    local expected="$3"
    local filename="$4"

    [[ "$expected" =~ ^[[:xdigit:]]{64}$ ]] || \
        die "expected SHA-256 is malformed for $filename"
    verify_file_sha256 "$archive" "$expected" "$filename archive"
    assert_regular_file "$sidecar" "$filename SHA-256 sidecar"

    "$utility_python3" - "$sidecar" "$filename" "$expected" <<'PY'
import re
import sys

path, expected_name, expected_digest = sys.argv[1:]
for raw_line in open(path, encoding="ascii"):
    fields = raw_line.split()
    if len(fields) < 2:
        continue
    digest = fields[0].lower()
    name = fields[1].lstrip("*")
    if re.fullmatch(r"[0-9a-f]{64}", digest):
        if digest != expected_digest.lower() or name != expected_name:
            raise SystemExit(
                f"published SHA-256 does not match profile: {digest} {name}"
            )
        break
else:
    raise SystemExit(f"no SHA-256 entry for {expected_name} in {path}")
PY
}

verify_published_sha512() {
    local archive="$1"
    local sidecar="$2"
    local expected="$3"
    local filename="$4"

    [[ "$expected" =~ ^[[:xdigit:]]{128}$ ]] || \
        die "expected SHA-512 is malformed for $filename"
    verify_file_sha512 "$archive" "$expected" "$filename archive"
    assert_regular_file "$sidecar" "$filename SHA-512 sidecar"

    "$utility_python3" - "$sidecar" "$filename" "$expected" <<'PY'
import re
import sys

path, expected_name, expected_digest = sys.argv[1:]
for raw_line in open(path, encoding="ascii"):
    fields = raw_line.split()
    if len(fields) < 2:
        continue
    digest = fields[0].lower()
    name = fields[1].lstrip("*")
    if re.fullmatch(r"[0-9a-f]{128}", digest):
        if digest != expected_digest.lower() or name != expected_name:
            raise SystemExit(
                f"published SHA-512 does not match profile: {digest} {name}"
            )
        break
else:
    raise SystemExit(f"no SHA-512 entry for {expected_name} in {path}")
PY
}

read_toolchain_spec() {
    assert_regular_file "$toolchain_file" "pinned toolchain file"

    "$utility_python3" - "$toolchain_file" <<'PY'
import re
import sys
import tomllib

path = sys.argv[1]
with open(path, "rb") as handle:
    document = tomllib.load(handle)
toolchain = document.get("toolchain", {})
channel = toolchain.get("channel")
profile = toolchain.get("profile", "minimal")
components = toolchain.get("components", [])
targets = toolchain.get("targets", [])

if not isinstance(channel, str) or not re.fullmatch(r"\d+\.\d+\.\d+", channel):
    raise SystemExit("toolchain channel must be an exact numeric stable version")
if channel != "1.97.1":
    raise SystemExit("toolchain channel must be the pinned Rust 1.97.1")
if not isinstance(profile, str) or profile not in {"minimal", "default", "complete"}:
    raise SystemExit("toolchain profile must be minimal, default, or complete")
if not isinstance(components, list) or not all(isinstance(item, str) for item in components):
    raise SystemExit("toolchain components must be a list of strings")
if not isinstance(targets, list) or not all(isinstance(item, str) for item in targets):
    raise SystemExit("toolchain targets must be a list of strings")
if targets != ["x86_64-unknown-linux-gnu"]:
    raise SystemExit(
        "toolchain targets must contain only the supported Linux x86_64 target"
    )

print(channel)
print(profile)
for item in components:
    print(f"component:{item}")
for item in targets:
    print(f"target:{item}")
PY
}

read_jmeter_profile() {
    assert_regular_file "$profile_file" "compatibility profile"

    "$utility_python3" - "$profile_file" \
        "$jmeter_profile_id" "$jmeter_profile_version" "$jmeter_upstream_version" \
        "$jmeter_artifact_format" "$jmeter_digest_algorithm" \
        "$jmeter_artifact_filename" "$jmeter_artifact_sha512" "$jmeter_artifact_url" \
        "$jmeter_digest_url" "$jmeter_signature_url" "$jmeter_keys_url" <<'PY'
import json
import sys

(
    path,
    expected_profile_id,
    expected_profile_version,
    expected_upstream_version,
    expected_artifact_format,
    expected_digest_algorithm,
    expected_filename,
    expected_digest,
    expected_url,
    expected_digest_url,
    expected_signature_url,
    expected_keys_url,
) = sys.argv[1:]
with open(path, encoding="utf-8") as handle:
    profile = json.load(handle)
if profile.get("profile_id") != expected_profile_id:
    raise SystemExit(
        f"unexpected compatibility profile id: {profile.get('profile_id')!r}"
    )
if profile.get("profile_version") != int(expected_profile_version):
    raise SystemExit(
        f"unexpected compatibility profile version: {profile.get('profile_version')!r}"
    )
upstream = profile.get("upstream", {})
if upstream.get("version") != expected_upstream_version:
    raise SystemExit(
        f"unexpected upstream version: {upstream.get('version')!r}"
    )
artifact = upstream["artifact"]
if artifact.get("format") != expected_artifact_format:
    raise SystemExit(f"unexpected artifact format: {artifact.get('format')!r}")
if artifact.get("digest_algorithm") != expected_digest_algorithm:
    raise SystemExit(
        f"unexpected artifact digest algorithm: {artifact.get('digest_algorithm')!r}"
    )
expected = {
    "filename": expected_filename,
    "digest": expected_digest,
    "url": expected_url,
    "digest_url": expected_digest_url,
    "signature_url": expected_signature_url,
    "keys_url": expected_keys_url,
}
for key in ("filename", "url", "digest_url", "digest", "signature_url", "keys_url"):
    value = artifact[key]
    if not isinstance(value, str) or not value:
        raise SystemExit(f"profile artifact field is not a non-empty string: {key}")
    if key in expected and value != expected[key]:
        raise SystemExit(
            f"profile {key} is not the independently pinned official value: {value!r}"
        )
    print(value)
PY
}

install_rustup() {
    if [[ "$check_mode" -eq 1 ]]; then
        assert_secure_cache_path "$cache_root" "toolchain cache root" "$repo_root/.cache"
        assert_secure_cache_path "$downloads_dir" "toolchain download directory" "$repo_root/.cache"
        assert_secure_cache_path "$rustup_home" "rustup home" "$repo_root/.cache"
        assert_secure_cache_path "$cargo_home" "Cargo home" "$repo_root/.cache"
    else
        ensure_directory "$cache_root" "toolchain cache root"
        ensure_directory "$downloads_dir" "toolchain download directory"
        ensure_directory "$rustup_home" "rustup home"
        ensure_directory "$cargo_home" "Cargo home"
        assert_secure_cache_path "$cache_root" "toolchain cache root" "$repo_root/.cache"
        assert_secure_cache_path "$downloads_dir" "toolchain download directory" "$repo_root/.cache"
        assert_secure_cache_path "$rustup_home" "rustup home" "$repo_root/.cache"
        assert_secure_cache_path "$cargo_home" "Cargo home" "$repo_root/.cache"
    fi
    assert_secure_cache_tree "$cache_root" "toolchain cache"

    local installer="$downloads_dir/rustup-init-${rustup_version}-${rustup_target}"
    if [[ ! -f "$installer" ]]; then
        [[ "$check_mode" -eq 0 ]] || die "rustup installer is missing in --check mode: $installer"
        download_https "$rustup_url" "$installer"
    fi
    if [[ "$check_mode" -eq 1 ]]; then
        assert_executable_file "$installer" "rustup ${rustup_version} installer"
    else
        assert_regular_file "$installer" "rustup ${rustup_version} installer"
    fi
    assert_secure_cache_path "$installer" "rustup ${rustup_version} installer" "$repo_root/.cache"
    verify_file_sha256 "$installer" "$rustup_sha256" "rustup ${rustup_version} installer"
    if [[ "$check_mode" -eq 0 ]]; then
        "$utility_chmod" 0755 -- "$installer"
        assert_secure_cache_path "$installer" "rustup ${rustup_version} installer" "$repo_root/.cache"
    fi

    local installed_rustup_version=""
    local installed_rustup_is_valid=0
    if [[ -e "$rustup_bin" ]]; then
        assert_secure_cache_path "$rustup_bin" "project-local rustup" "$repo_root/.cache"
        if file_sha256_matches "$rustup_bin" "$rustup_executable_sha256"; then
            assert_executable_file "$rustup_bin" "project-local rustup"
            installed_rustup_version="$(RUSTUP_HOME="$rustup_home" CARGO_HOME="$cargo_home" \
                RUSTUP_DIST_SERVER="$rustup_dist_server" \
                RUSTUP_UPDATE_ROOT="$rustup_update_root" \
                "$rustup_bin" --version || true)"
            if parse_exact_version "$installed_rustup_version" "$rustup_version" rustup \
                >/dev/null 2>&1; then
                installed_rustup_is_valid=1
            elif [[ "$check_mode" -eq 1 ]]; then
                die "project-local rustup version is not exact ${rustup_version}: ${installed_rustup_version:-missing}"
            fi
        elif [[ "$check_mode" -eq 1 ]]; then
            die "project-local rustup hash does not match the pinned ${rustup_version} binary"
        fi
    fi
    if [[ "$installed_rustup_is_valid" -eq 0 ]]; then
        [[ "$check_mode" -eq 0 ]] || die "project-local rustup version is not exact ${rustup_version}: ${installed_rustup_version:-missing}"
        RUSTUP_HOME="$rustup_home" CARGO_HOME="$cargo_home" \
            RUSTUP_DIST_SERVER="$rustup_dist_server" \
            RUSTUP_UPDATE_ROOT="$rustup_update_root" \
            "$installer" -y --no-modify-path --profile minimal \
            --default-toolchain none
    fi

    assert_secure_cache_tree "$cache_root" "toolchain cache after rustup setup"
    verify_rustup_binary
    assert_executable_file "$rustup_bin" "project-local rustup"
    installed_rustup_version="$(RUSTUP_HOME="$rustup_home" CARGO_HOME="$cargo_home" \
        RUSTUP_DIST_SERVER="$rustup_dist_server" \
        RUSTUP_UPDATE_ROOT="$rustup_update_root" \
        "$rustup_bin" --version)"
    parse_exact_version "$installed_rustup_version" "$rustup_version" rustup || \
        die "project-local rustup version is not exact $rustup_version: $installed_rustup_version"
    [[ "$check_mode" -eq 0 ]] || return 0
    RUSTUP_HOME="$rustup_home" CARGO_HOME="$cargo_home" \
        RUSTUP_DIST_SERVER="$rustup_dist_server" \
        RUSTUP_UPDATE_ROOT="$rustup_update_root" \
        "$rustup_bin" set auto-self-update disable
}

install_rust_toolchain() {
    local -a specification
    mapfile -t specification < <(read_toolchain_spec)
    ((${#specification[@]} >= 2)) || die "invalid toolchain specification"

    local channel="${specification[0]}"
    local profile="${specification[1]}"
    [[ "$channel" == "$rust_version" ]] || die "unexpected Rust channel: $channel"
    local -a install_args=(toolchain install "$channel" --profile "$profile")
    local entry
    for entry in "${specification[@]:2}"; do
        case "$entry" in
            component:*) install_args+=(--component "${entry#component:}") ;;
            target:*) install_args+=(--target "${entry#target:}") ;;
            *) die "unexpected toolchain setting: $entry" ;;
        esac
    done

    # rustfmt and clippy are required by the repository contract even if a
    # future scaffold accidentally omits them from rust-toolchain.toml.
    local has_rustfmt=0
    local has_clippy=0
    for entry in "${install_args[@]}"; do
        [[ "$entry" == rustfmt ]] && has_rustfmt=1
        [[ "$entry" == clippy ]] && has_clippy=1
    done
    ((has_rustfmt)) || install_args+=(--component rustfmt)
    ((has_clippy)) || install_args+=(--component clippy)

    if [[ "$check_mode" -eq 0 ]]; then
        RUSTUP_HOME="$rustup_home" CARGO_HOME="$cargo_home" \
            RUSTUP_TOOLCHAIN= \
            RUSTUP_DIST_SERVER="$rustup_dist_server" \
            RUSTUP_UPDATE_ROOT="$rustup_update_root" \
            "$rustup_bin" "${install_args[@]}"
    fi

    validate_rust_cache_entrypoints "$channel"
    local toolchain_bin="$rustup_home/toolchains/${channel}-${rustup_target}/bin"
    printf 'rust toolchain: %s\n' "$channel"
    local rustc_version cargo_version rustfmt_version clippy_version
    if [[ "$check_mode" -eq 1 ]]; then
        validate_rust_target "$channel"
        rustc_version="$("$toolchain_bin/rustc" --version)"
        cargo_version="$("$toolchain_bin/cargo" --version)"
        rustfmt_version="$("$toolchain_bin/rustfmt" --version)"
        clippy_version="$("$toolchain_bin/cargo" clippy --version)"
    else
        RUSTUP_HOME="$rustup_home" CARGO_HOME="$cargo_home" \
            RUSTUP_TOOLCHAIN= RUSTUP_DIST_SERVER="$rustup_dist_server" \
            RUSTUP_UPDATE_ROOT="$rustup_update_root" \
            "$rustup_bin" run "$channel" rustc -vV
        RUSTUP_HOME="$rustup_home" CARGO_HOME="$cargo_home" \
            RUSTUP_TOOLCHAIN= RUSTUP_DIST_SERVER="$rustup_dist_server" \
            RUSTUP_UPDATE_ROOT="$rustup_update_root" \
            "$rustup_bin" run "$channel" cargo -V
        RUSTUP_HOME="$rustup_home" CARGO_HOME="$cargo_home" \
            RUSTUP_TOOLCHAIN= RUSTUP_DIST_SERVER="$rustup_dist_server" \
            RUSTUP_UPDATE_ROOT="$rustup_update_root" \
            "$rustup_bin" component list --toolchain "$channel" --installed
        RUSTUP_HOME="$rustup_home" CARGO_HOME="$cargo_home" \
            RUSTUP_TOOLCHAIN= RUSTUP_DIST_SERVER="$rustup_dist_server" \
            RUSTUP_UPDATE_ROOT="$rustup_update_root" \
            "$rustup_bin" target list --toolchain "$channel" --installed

        local installed_components
        installed_components="$(RUSTUP_HOME="$rustup_home" CARGO_HOME="$cargo_home" \
            RUSTUP_TOOLCHAIN= RUSTUP_DIST_SERVER="$rustup_dist_server" \
            RUSTUP_UPDATE_ROOT="$rustup_update_root" \
            "$rustup_bin" component list --toolchain "$channel" --installed)"
        "$utility_grep" -Fxq "rustfmt-$rustup_target" <<<"$installed_components" || \
            die "rustfmt is not installed for Rust $channel"
        "$utility_grep" -Fxq "clippy-$rustup_target" <<<"$installed_components" || \
            die "clippy is not installed for Rust $channel"

        local installed_targets
        installed_targets="$(RUSTUP_HOME="$rustup_home" CARGO_HOME="$cargo_home" \
            RUSTUP_TOOLCHAIN= RUSTUP_DIST_SERVER="$rustup_dist_server" \
            RUSTUP_UPDATE_ROOT="$rustup_update_root" \
            "$rustup_bin" target list --toolchain "$channel" --installed)"
        "$utility_grep" -Fxq "$rustup_target" <<<"$installed_targets" || \
            die "Rust target is not installed: $rustup_target"

        rustc_version="$(RUSTUP_HOME="$rustup_home" CARGO_HOME="$cargo_home" \
            RUSTUP_TOOLCHAIN= RUSTUP_DIST_SERVER="$rustup_dist_server" \
            RUSTUP_UPDATE_ROOT="$rustup_update_root" \
            "$rustup_bin" run "$channel" rustc --version)"
        cargo_version="$(RUSTUP_HOME="$rustup_home" CARGO_HOME="$cargo_home" \
            RUSTUP_TOOLCHAIN= RUSTUP_DIST_SERVER="$rustup_dist_server" \
            RUSTUP_UPDATE_ROOT="$rustup_update_root" \
            "$rustup_bin" run "$channel" cargo --version)"
        rustfmt_version="$(RUSTUP_HOME="$rustup_home" CARGO_HOME="$cargo_home" \
            RUSTUP_TOOLCHAIN= RUSTUP_DIST_SERVER="$rustup_dist_server" \
            RUSTUP_UPDATE_ROOT="$rustup_update_root" \
            "$rustup_bin" run "$channel" rustfmt --version)"
        clippy_version="$(RUSTUP_HOME="$rustup_home" CARGO_HOME="$cargo_home" \
            RUSTUP_TOOLCHAIN= RUSTUP_DIST_SERVER="$rustup_dist_server" \
            RUSTUP_UPDATE_ROOT="$rustup_update_root" \
            "$rustup_bin" run "$channel" cargo clippy --version)"
    fi
    parse_exact_version "$rustc_version" "$channel" rustc || \
        die "unexpected rustc version: $rustc_version"
    parse_exact_version "$cargo_version" "$channel" cargo || \
        die "unexpected cargo version: $cargo_version"
    parse_exact_version "$rustfmt_version" "$rustfmt_package_version" rustfmt || \
        die "unexpected rustfmt version: $rustfmt_version"
    parse_exact_version "$clippy_version" "$clippy_package_version" clippy || \
        die "unexpected clippy version: $clippy_version"
    local channel_manifest="$rustup_home/toolchains/${channel}-${rustup_target}/lib/rustlib/multirust-channel-manifest.toml"
    [[ -f "$channel_manifest" ]] || \
        die "missing Rust channel manifest: $channel_manifest"
    parse_exact_manifest_version "$channel_manifest" cargo "$rust_cargo_package_version"
    parse_exact_manifest_version "$channel_manifest" rustfmt-preview "$rustfmt_package_version"
    parse_exact_manifest_version "$channel_manifest" clippy-preview "$clippy_package_version"
    printf 'rustc: %s\n' "$rustc_version"
    printf 'cargo: %s\n' "$cargo_version"
    printf 'cargo package: %s\n' "$rust_cargo_package_version"
    printf 'rustfmt: %s\n' "$rustfmt_version"
    printf 'clippy: %s\n' "$clippy_version"
}

install_java() {
    local archive="$downloads_dir/$java_archive"
    local sidecar="$archive.sha256"
    if [[ "$check_mode" -eq 1 ]]; then
        assert_secure_cache_path "$downloads_dir" "toolchain download directory" "$repo_root/.cache"
        assert_secure_cache_path "$java_root" "Java cache root" "$repo_root/.cache"
    else
        ensure_directory "$downloads_dir" "toolchain download directory"
        ensure_directory "$java_root" "Java cache root"
        assert_secure_cache_path "$downloads_dir" "toolchain download directory" "$repo_root/.cache"
        assert_secure_cache_path "$java_root" "Java cache root" "$repo_root/.cache"
    fi
    assert_secure_cache_tree "$java_root" "Java cache"
    if [[ ! -f "$archive" ]]; then
        [[ "$check_mode" -eq 0 ]] || die "Java archive is missing in --check mode: $archive"
        download_https "$java_url" "$archive"
    fi
    if [[ ! -f "$sidecar" ]]; then
        [[ "$check_mode" -eq 0 ]] || die "Java checksum sidecar is missing in --check mode: $sidecar"
        download_https "$java_checksum_url" "$sidecar"
    fi
    assert_secure_cache_path "$archive" "Java archive" "$repo_root/.cache"
    assert_secure_cache_path "$sidecar" "Java checksum sidecar" "$repo_root/.cache"
    verify_published_sha256 "$archive" "$sidecar" "$java_sha256" "$java_archive"

    local java_bin="$java_home/bin/java"
    if [[ ! -x "$java_bin" ]]; then
        [[ "$check_mode" -eq 0 ]] || die "project-local Java executable is missing in --check mode: $java_bin"
        assert_not_symlink "$java_home" "project-local Java home"
        [[ ! -e "$java_home" ]] || die "Java extraction exists but is incomplete: $java_home"
        local extraction_dir
        extraction_dir="$("$utility_mktemp" -d "$java_root/.java-extract.XXXXXX")"
        register_temporary_path "$extraction_dir"
        if ! "$utility_tar" --extract --gzip --file "$archive" --directory "$extraction_dir"; then
            die "could not extract verified Java archive"
        fi
        [[ -x "$extraction_dir/jdk-$java_release-jre/bin/java" ]] || {
            die "Java archive has an unexpected layout"
        }
        "$utility_mv" -- "$extraction_dir/jdk-$java_release-jre" "$java_home"
        forget_temporary_path "$extraction_dir"
        "$utility_rmdir" -- "$extraction_dir"
    fi
    assert_secure_cache_tree "$java_root" "Java cache after extraction"
    validate_java_cache_entrypoints

    local java_version
    java_version="$("$utility_env" -i PATH="$trusted_system_path" \
        "$java_bin" "$java_no_perf_data_arg" -version 2>&1 | "$utility_sed" -n '1p')"
    parse_exact_version "$java_version" "17.0.20" java || \
        die "unexpected project-local Java version: $java_version"
    printf 'Java executable: %s\n' "$java_bin"
    printf 'Java version: %s\n' "$java_version"
}

verify_jmeter_signature() {
    local signature="$1"
    local artifact="$2"
    local keys="$3"
    local verification_home
    local key_listing
    local signature_output

    if [[ "$check_mode" -eq 1 ]]; then
        # --check must not touch the persistent bootstrap GnuPG home or an
        # ambient user's keyring.  GnuPG necessarily creates state while
        # verifying, so isolate that state in a temporary directory outside
        # the repository and remove it through the exit cleanup trap.
        verification_home="$("$utility_mktemp" -d "/tmp/jmeter-bootstrap-gnupg.XXXXXX")"
        register_temporary_path "$verification_home"
    else
        ensure_directory "$gnupg_home" "bootstrap GnuPG home"
        "$utility_chmod" 0700 -- "$gnupg_home"
        verification_home="$gnupg_home"
    fi

    if ! key_listing="$("$utility_gpg" --batch --no-options --no-default-keyring --no-autostart \
        --homedir "$verification_home" --with-colons --show-keys "$keys" 2>/dev/null)"; then
        die "could not inspect Apache signing keys"
    fi
    if ! "$utility_grep" -Fq "fpr:::::::::$jmeter_signature_fingerprint:" <<<"$key_listing"; then
        die "Apache KEYS does not contain the pinned signing key"
    fi
    if ! "$utility_gpg" --batch --no-options --no-default-keyring --no-autostart \
        --homedir "$verification_home" --import "$keys" >/dev/null 2>&1; then
        die "could not import Apache signing keys"
    fi
    if ! signature_output="$("$utility_gpg" --batch --no-options --no-default-keyring --no-autostart \
        --no-auto-check-trustdb --homedir "$verification_home" --status-fd=1 \
        --verify "$signature" "$artifact" 2>&1)"; then
        printf '%s\n' "$signature_output" | "$utility_sed" -n '1,80p' >&2
        die "JMeter PGP signature verification failed"
    fi
    if ! "$utility_grep" -Fq "[GNUPG:] VALIDSIG $jmeter_signature_fingerprint " <<<"$signature_output"; then
        printf '%s\n' "$signature_output" | "$utility_sed" -n '1,80p' >&2
        die "JMeter PGP signature did not use the pinned Apache key"
    fi
}

verify_jmeter() {
    local -a profile_values
    mapfile -t profile_values < <(read_jmeter_profile)
    ((${#profile_values[@]} == 6)) || die "invalid JMeter artifact profile"

    local filename="${profile_values[0]}"
    local artifact_url="${profile_values[1]}"
    local digest_url="${profile_values[2]}"
    local expected_digest="${profile_values[3]}"
    local signature_url="${profile_values[4]}"
    local keys_url="${profile_values[5]}"
    [[ "$filename" != */* && "$filename" != *\\* && "$filename" != "." && "$filename" != ".." ]] || \
        die "JMeter artifact filename must be a plain filename"
    [[ "$artifact_url" == https://* ]] || die "JMeter artifact URL is not HTTPS"
    [[ "$digest_url" == https://* ]] || die "JMeter digest URL is not HTTPS"
    [[ "$signature_url" == https://* ]] || die "JMeter signature URL is not HTTPS"
    [[ "$keys_url" == https://* ]] || die "JMeter keys URL is not HTTPS"
    [[ "$expected_digest" =~ ^[[:xdigit:]]{128}$ ]] || die "JMeter profile digest is not SHA-512"

    local oracle_cache="$repo_root/jmeter-oracle-cache"
    local artifact="$oracle_cache/$filename"
    local sidecar="$artifact.sha512"
    local signature="$artifact.asc"
    local keys="$oracle_cache/KEYS"
    if [[ "$check_mode" -eq 1 ]]; then
        assert_secure_cache_path "$oracle_cache" "JMeter oracle cache" "$oracle_cache"
    else
        ensure_directory "$oracle_cache" "JMeter oracle cache"
        assert_secure_cache_path "$oracle_cache" "JMeter oracle cache" "$oracle_cache"
    fi
    assert_secure_cache_tree "$oracle_cache" "JMeter oracle cache"
    if [[ ! -f "$artifact" ]]; then
        [[ "$check_mode" -eq 0 ]] || die "JMeter archive is missing in --check mode: $artifact"
        download_https "$artifact_url" "$artifact"
    fi
    if [[ ! -f "$sidecar" ]]; then
        [[ "$check_mode" -eq 0 ]] || die "JMeter digest sidecar is missing in --check mode: $sidecar"
        download_https "$digest_url" "$sidecar"
    fi
    if [[ ! -f "$signature" ]]; then
        [[ "$check_mode" -eq 0 ]] || die "JMeter signature is missing in --check mode: $signature"
        download_https "$signature_url" "$signature"
    fi
    if [[ ! -f "$keys" ]]; then
        [[ "$check_mode" -eq 0 ]] || die "Apache KEYS file is missing in --check mode: $keys"
        download_https "$keys_url" "$keys"
    fi
    assert_secure_cache_path "$artifact" "JMeter archive" "$oracle_cache"
    assert_secure_cache_path "$sidecar" "JMeter digest sidecar" "$oracle_cache"
    assert_secure_cache_path "$signature" "JMeter PGP signature" "$oracle_cache"
    assert_secure_cache_path "$keys" "Apache KEYS file" "$oracle_cache"

    verify_published_sha512 "$artifact" "$sidecar" "$expected_digest" "$filename"
    assert_regular_file "$signature" "JMeter PGP signature"
    assert_regular_file "$keys" "Apache KEYS file"

    verify_jmeter_signature "$signature" "$artifact" "$keys"

    "$utility_unzip" -tq "$artifact" >/dev/null
    local jmeter_dir="$oracle_cache/apache-jmeter-5.6.3"
    local jmeter_bin="$jmeter_dir/bin/jmeter"
    if [[ ! -x "$jmeter_bin" ]]; then
        [[ "$check_mode" -eq 0 ]] || die "JMeter shell launcher is missing in --check mode: $jmeter_bin"
        assert_not_symlink "$jmeter_dir" "JMeter extracted cache"
        [[ ! -e "$jmeter_dir" ]] || die "JMeter extraction exists but is incomplete: $jmeter_dir"
        local extraction_dir
        extraction_dir="$("$utility_mktemp" -d "$oracle_cache/.apache-jmeter-5.6.3.extract.XXXXXX")"
        register_temporary_path "$extraction_dir"
        if ! "$utility_unzip" -q "$artifact" -d "$extraction_dir"; then
            die "could not extract verified JMeter archive"
        fi
        [[ -x "$extraction_dir/apache-jmeter-5.6.3/bin/jmeter" ]] || {
            die "JMeter archive has an unexpected layout"
        }
        "$utility_mv" -- "$extraction_dir/apache-jmeter-5.6.3" "$jmeter_dir"
        forget_temporary_path "$extraction_dir"
        "$utility_rmdir" -- "$extraction_dir"
    fi
    assert_secure_cache_tree "$oracle_cache" "JMeter oracle cache after extraction"
    validate_jmeter_cache_entrypoints
    [[ "$("$utility_sed" -n '1p' "$jmeter_bin")" == '#! /bin/sh' ]] || \
        die "JMeter shell launcher has an unexpected interpreter: $jmeter_bin"
    if [[ "$check_mode" -eq 1 ]]; then
        printf 'JMeter PGP: valid (verified in isolated temporary GnuPG home)\n'
        printf 'JMeter shell launcher: present and executable (covered by archive digest)\n'
        return 0
    fi
    local jmeter_version
    local jmeter_output
    if ! jmeter_output="$(
        "$utility_env" -i PATH="$trusted_system_path" JAVA_HOME="$java_home" JRE_HOME="$java_home" \
            JVM_ARGS="$java_no_perf_data_arg" JAVA_TOOL_OPTIONS="$java_no_perf_data_arg" \
            "$jmeter_bin" --version 2>&1
    )"; then
        printf '%s\n' "$jmeter_output" >&2
        die "JMeter could not run with project-local Java"
    fi
    parse_exact_jmeter_version "$jmeter_output" "5.6.3" || \
        die "unexpected JMeter version output"
    jmeter_version="$(printf '%s\n' "$jmeter_output" | \
        "$utility_sed" -n '/5\.6\.3$/p' | "$utility_tail" -n 1)"

    printf 'JMeter archive: %s\n' "$artifact"
    printf 'JMeter SHA-512: %s\n' "$expected_digest"
    printf 'JMeter PGP: valid (%s)\n' "$jmeter_signature_fingerprint"
    printf 'JMeter executable: %s\n' "$jmeter_bin"
    printf 'JMeter version: %s\n' "$jmeter_version"
}

self_test_expect_failure() {
    local description="$1"
    shift
    if ( "$@" >/dev/null 2>&1 ); then
        die "self-test expected failure did not fail: $description"
    fi
}

run_self_test() {
    local self_root
    local self_cache
    local self_file
    local symlink_path
    local permission_path
    local tampered_profile
    local tampered_manifest
    local malformed_manifest
    local wrong_manifest_digest
    local java_probe_dir
    local java_bin="$java_home/bin/java"
    local profile_mtime_before
    local profile_mtime_after
    local signature_mtime_before
    local signature_mtime_after
    local oracle_mtime_before
    local oracle_mtime_after
    local keys_mtime_before
    local keys_mtime_after
    local -a profile_values

    [[ -z "${BASH_ENV:-}" && -z "${ENV:-}" ]] || \
        die "self-test was not started with a sanitized environment"
    self_root="$("$utility_mktemp" -d "/tmp/bootstrap-self-test.XXXXXX")"
    register_temporary_path "$self_root"
    "$utility_chmod" 0700 -- "$self_root"
    self_cache="$self_root/cache"
    "$utility_mkdir" -m 0700 -- "$self_cache"
    assert_secure_cache_path "$self_cache" "self-test cache" "$self_root"

    self_file="$self_cache/payload"
    printf 'bootstrap-self-test\n' >"$self_file"
    "$utility_chmod" 0600 -- "$self_file"
    assert_secure_cache_path "$self_file" "self-test payload" "$self_root"
    assert_secure_cache_tree "$self_cache" "self-test cache tree"
    verify_file_sha256 "$self_file" \
        "095e7fbc2104056f942f46dd6bcd7698ffa7750ef395317be696d92635b850ca" \
        "self-test payload"
    printf 'tampered\n' >"$self_file"
    self_test_expect_failure "tampered content hash" verify_file_sha256 "$self_file" \
        "095e7fbc2104056f942f46dd6bcd7698ffa7750ef395317be696d92635b850ca" \
        "tampered self-test payload"

    symlink_path="$self_root/symlink"
    "$utility_ln" -s "$self_cache" "$symlink_path"
    self_test_expect_failure "symlinked cache directory" assert_secure_cache_path \
        "$symlink_path" "symlinked self-test cache" "$self_root"

    permission_path="$self_root/permission"
    "$utility_mkdir" -m 0775 -- "$permission_path"
    self_test_expect_failure "group-writable cache directory" assert_secure_cache_path \
        "$permission_path" "writable self-test cache" "$self_root"

    "$utility_python3" -E -S "$repo_root/tools/bootstrap/bootstrap-lock.py" \
        --self-test-lock || die "bootstrap lock self-test failed"
    "$utility_python3" -E -S "$repo_root/tools/bootstrap/bootstrap-lock.py" \
        --self-test-capability || die "bootstrap capability self-test failed"

    verify_rust_entrypoint_manifest "$rust_version" 1
    tampered_manifest="$self_root/rust-entrypoints-tampered.sha256"
    "$utility_cp" -- "$rust_entrypoint_manifest" "$tampered_manifest"
    wrong_manifest_digest="0${rustup_executable_sha256:1}"
    "$utility_sed" -i \
        "0,/^${rustup_executable_sha256}  /s//${wrong_manifest_digest}  /" \
        "$tampered_manifest"
    if ( rust_entrypoint_manifest="$tampered_manifest"; \
        verify_rust_entrypoint_manifest "$rust_version" 1 >/dev/null 2>&1 ); then
        die "self-test expected tampered Rust entrypoint digest content to fail"
    fi
    malformed_manifest="$self_root/rust-entrypoints-malformed.sha256"
    "$utility_cp" -- "$rust_entrypoint_manifest" "$malformed_manifest"
    "$utility_sed" -i \
        "0,/^${rustup_executable_sha256}  /s//${rustup_executable_sha256:0:63}  /" \
        "$malformed_manifest"
    if ( rust_entrypoint_manifest="$malformed_manifest"; \
        verify_rust_entrypoint_manifest "$rust_version" 1 >/dev/null 2>&1 ); then
        die "self-test expected malformed Rust entrypoint digest to fail"
    fi

    mapfile -t profile_values < <(read_jmeter_profile)
    ((${#profile_values[@]} == 6)) || die "self-test profile validation failed"
    tampered_profile="$self_root/profile.json"
    "$utility_cp" -- "$profile_file" "$tampered_profile"
    "$utility_sed" -i 's/"profile_version": 2/"profile_version": 1/' \
        "$tampered_profile"
    if ( profile_file="$tampered_profile"; read_jmeter_profile >/dev/null 2>&1 ); then
        die "self-test expected tampered profile validation to fail"
    fi

    profile_mtime_before="$("$utility_stat" -c '%Y:%s' -- "$profile_file")"
    signature_mtime_before="$("$utility_stat" -c '%Y:%s' -- "$gnupg_home" 2>/dev/null || true)"
    oracle_mtime_before="$("$utility_stat" -c '%Y:%s' -- "$repo_root/jmeter-oracle-cache/apache-jmeter-5.6.3.zip")"
    keys_mtime_before="$("$utility_stat" -c '%Y:%s' -- "$repo_root/jmeter-oracle-cache/KEYS")"
    check_mode=1
    verify_jmeter_signature \
        "$repo_root/jmeter-oracle-cache/apache-jmeter-5.6.3.zip.asc" \
        "$repo_root/jmeter-oracle-cache/apache-jmeter-5.6.3.zip" \
        "$repo_root/jmeter-oracle-cache/KEYS"
    signature_mtime_after="$("$utility_stat" -c '%Y:%s' -- "$gnupg_home" 2>/dev/null || true)"
    [[ "$signature_mtime_before" == "$signature_mtime_after" ]] || \
        die "self-test observed a persistent GnuPG state change"
    profile_mtime_after="$("$utility_stat" -c '%Y:%s' -- "$profile_file")"
    [[ "$profile_mtime_before" == "$profile_mtime_after" ]] || \
        die "self-test observed a profile mutation"
    oracle_mtime_after="$("$utility_stat" -c '%Y:%s' -- "$repo_root/jmeter-oracle-cache/apache-jmeter-5.6.3.zip")"
    keys_mtime_after="$("$utility_stat" -c '%Y:%s' -- "$repo_root/jmeter-oracle-cache/KEYS")"
    [[ "$oracle_mtime_before" == "$oracle_mtime_after" && \
        "$keys_mtime_before" == "$keys_mtime_after" ]] || \
        die "self-test observed a JMeter cache mutation"

    assert_regular_file "$java_bin" "self-test Java executable"
    verify_file_sha256 "$java_bin" "$java_executable_sha256" \
        "self-test Java executable"
    java_probe_dir="$self_root/java-home"
    "$utility_mkdir" -m 0700 -- "$java_probe_dir"
    "$utility_env" -i HOME="$java_probe_dir" TMPDIR="$java_probe_dir" \
        PATH="$trusted_system_path" "$java_bin" "$java_no_perf_data_arg" \
        -version >/dev/null 2>&1 || die "self-test Java perf-data probe failed"
    [[ ! -e "$java_probe_dir/hsperfdata_$current_uid" ]] || \
        die "self-test Java probe created hsperfdata despite -XX:-UsePerfData"

    printf 'bootstrap self-test passed (handoff, hash, tamper, Rust manifest, lock/FIFO, symlink, permission, profile, signature, Java perf-data, and no-write checks)\n'
}

main() {
    # Keep all utility lookups on trusted system directories.  Project-local
    # Rust and Java binaries are invoked by absolute path below, so cached
    # executables cannot shadow curl, gpg, Python, archive tools, or shell
    # helpers through PATH.
    export PATH="$trusted_system_path"
    parse_options "$@"
    check_supported_host
    if [[ "$self_test_mode" -eq 1 ]]; then
        run_self_test
        return 0
    fi
    if [[ "$check_mode" -eq 0 ]]; then
        ensure_directory "$repo_root/.cache" "repository cache directory"
    else
        assert_directory "$repo_root/.cache" "repository cache directory"
    fi
    assert_secure_cache_node "$repo_root/.cache" "repository cache directory"
    # Validate every pinned Rust digest and the checked manifest before any
    # installer or cached Rust entrypoint can execute.
    verify_rust_entrypoint_manifest "$rust_version" 1

    unset RUSTUP_TOOLCHAIN
    export RUSTUP_DIST_SERVER="$rustup_dist_server"
    export RUSTUP_UPDATE_ROOT="$rustup_update_root"
    install_rustup
    install_rust_toolchain
    install_java
    verify_jmeter

    if [[ "$check_mode" -eq 1 ]]; then
        printf 'bootstrap metadata/cache check complete (read-only)\n'
        printf 'no downloads, installs, extractions, persistent cache key imports, or rustup settings were performed\n'
    else
        printf 'bootstrap complete\n'
    fi
    printf 'project-local toolchain root: %s\n' "$cache_root"
    printf 'project-local Java home: %s\n' "$java_home"
    printf 'JMeter oracle home: %s\n' "$repo_root/jmeter-oracle-cache/apache-jmeter-5.6.3"
    printf 'use without shell changes: RUSTUP_HOME=%s CARGO_HOME=%s PATH=%s:$PATH\n' \
        "$rustup_home" "$cargo_home" "$cargo_home/bin"
}

main "$@"
