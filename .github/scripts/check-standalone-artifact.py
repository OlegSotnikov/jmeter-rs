#!/usr/bin/env python3
"""Validate and describe a Decision 0009 standalone release archive.

The archive is intentionally a very small product boundary: one executable,
the project license/notice, and the two documents shipped with the native
release.  This checker does not invoke the executable, a shell, Java, Cargo,
or any platform inspection utility; the release workflow supplies bounded,
tool-produced evidence files for those checks.  It is therefore suitable for
both the release workflow and deterministic local self-tests.

The generated manifest is evidence about the artifact that was checked.  It
is not a JMeter conformance report: the profile remains the source of truth
for compatibility claims, and ``execution_evidence`` distinguishes a native
runner smoke from a cross-target compile.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile
import tempfile
from typing import Iterable, NamedTuple
import zipfile


SCHEMA_ID = "jmeter-rs.standalone-artifact-manifest"
SCHEMA_VERSION = 1
CAPABILITY_SET = "standalone-native"
PROFILE_ID = "jmeter-5.6.3"
DECISION_ID = "0009"
COMPATIBILITY_IDS = ("TEST-001", "TEST-005")
COMPATIBILITY_ID = "TEST-005"  # Backward-compatible single-ID alias.
SUPPORTED_TARGETS = {
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-unknown-linux-musl",
    "x86_64-pc-windows-msvc",
    "aarch64-pc-windows-msvc",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
}
MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024
MAX_MEMBER_BYTES = 512 * 1024 * 1024
MAX_MEMBER_COUNT = 64
MAX_UNCOMPRESSED_BYTES = 1024 * 1024 * 1024
MAX_EVIDENCE_BYTES = 8 * 1024 * 1024
MAX_TREE_LINES = 250_000

# The P0 application has no compatibility-pack client.  The pure bridge
# protocol is therefore excluded as well as the worker/supervision crates for
# this artifact.  If the standalone application later grows an explicit,
# dormant bridge client, this list must change with a reviewed architecture
# decision rather than being silently widened in the release job.
FORBIDDEN_WORKSPACE_PACKAGES = frozenset(
    {
        "jmeter-rs-java-bridge",
        "jmeter-rs-plugin-host",
        "jmeter-rs-process-supervision",
        "jmeter-oracle",
        "jmeter-rs-bridge-protocol",
    }
)

LINUX_ALLOWED_SYSTEM_LIBRARIES = {
    "x86_64-unknown-linux-gnu": frozenset(
        {
            "libc.so.6",
            "libgcc_s.so.1",
            "libm.so.6",
            "libdl.so.2",
            "libpthread.so.0",
            "librt.so.1",
            "ld-linux-x86-64.so.2",
        }
    ),
    "aarch64-unknown-linux-gnu": frozenset(
        {
            "libc.so.6",
            "libgcc_s.so.1",
            "libm.so.6",
            "libdl.so.2",
            "libpthread.so.0",
            "librt.so.1",
            "ld-linux-aarch64.so.1",
        }
    ),
    "x86_64-unknown-linux-musl": frozenset(),
}
MACOS_ALLOWED_SYSTEM_LIBRARIES = frozenset(
    {
        "libSystem.B.dylib",
        "libc++.1.dylib",
    }
)
WINDOWS_ALLOWED_SYSTEM_IMPORTS = frozenset(
    {
        "advapi32.dll",
        "bcrypt.dll",
        "bcryptprimitives.dll",
        "combase.dll",
        "crypt32.dll",
        "gdi32.dll",
        "iphlpapi.dll",
        "kernel32.dll",
        "kernelbase.dll",
        "msvcp140.dll",
        "msvcp_win.dll",
        "msvcrt.dll",
        "ntdll.dll",
        "ole32.dll",
        "oleaut32.dll",
        "psapi.dll",
        "rpcrt4.dll",
        "sechost.dll",
        "secur32.dll",
        "shell32.dll",
        "ucrtbase.dll",
        "user32.dll",
        "userenv.dll",
        "version.dll",
        "vcruntime140.dll",
        "vcruntime140_1.dll",
        "ws2_32.dll",
    }
)
WINDOWS_ALLOWED_SYSTEM_PREFIXES = ("api-ms-win-", "ext-ms-win-")
FORBIDDEN_LINKAGE_MARKERS = (
    "java",
    "jvm",
    "jni",
    ".jar",
    "plugin",
    "sidecar",
    "helper",
)
FORBIDDEN_ENVIRONMENT_NAMES = frozenset(
    {
        "ALL_PROXY",
        "CLASSPATH",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "JAVA_HOME",
        "JDK_HOME",
        "JAVA_TOOL_OPTIONS",
        "JDK_JAVA_OPTIONS",
        "_JAVA_OPTIONS",
        "JMETer_HOME".upper(),
        "JRE_HOME",
        "JMETER_HOME",
        "JVM_HOME",
        "MAVEN_OPTS",
        "NO_PROXY",
        "all_proxy",
        "classpath",
        "http_proxy",
        "https_proxy",
        "java_home",
        "jdk_home",
        "jmeter_home",
        "jre_home",
        "jvm_home",
        "no_proxy",
    }
)
LINKAGE_SCHEMA_ID = "jmeter-rs.standalone-linkage-evidence"
RUNTIME_SCHEMA_ID = "jmeter-rs.standalone-runtime-evidence"

# Keep this list deliberately explicit.  A release archive must not acquire a
# new runtime table, sidecar, plugin, or generated file without changing this
# release boundary and its review.
RELEASE_DOCUMENTS = (
    "LICENSE",
    "NOTICE",
    "README.md",
    "docs/architecture.md",
    "docs/third-party-provenance.md",
)

FORBIDDEN_SUFFIXES = {
    ".class",
    ".ear",
    ".jar",
    ".java",
    ".jmod",
    ".war",
}


class ArtifactError(ValueError):
    """A release archive does not satisfy the standalone contract."""


class Member(NamedTuple):
    """A regular archive member and its bytes."""

    path: str
    data: bytes
    mode: int | None


class Archive(NamedTuple):
    """Archive bytes and regular members, in archive order."""

    format: str
    members: tuple[Member, ...]


def _normalise_member_name(name: str) -> str:
    """Return a safe POSIX member name, rejecting traversal and ambiguity."""

    if "\\" in name:
        raise ArtifactError(f"archive member uses a backslash: {name!r}")
    if not name or name.startswith("/"):
        raise ArtifactError(f"archive member has an absolute/empty path: {name!r}")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ArtifactError(f"archive member has an unsafe path: {name!r}")
    normalised = path.as_posix()
    if normalised != name.rstrip("/"):
        raise ArtifactError(f"archive member is not canonical: {name!r}")
    return normalised


def _read_regular_tar_member(tar: tarfile.TarFile, info: tarfile.TarInfo) -> Member | None:
    name = _normalise_member_name(info.name.rstrip("/"))
    if info.isdir():
        return None
    if not info.isreg():
        raise ArtifactError(f"archive member is not a regular file: {info.name!r}")
    if info.size > MAX_MEMBER_BYTES:
        raise ArtifactError(
            f"archive member exceeds {MAX_MEMBER_BYTES} bytes: {info.name!r}"
        )
    source = tar.extractfile(info)
    if source is None:
        raise ArtifactError(f"archive member has no readable payload: {info.name!r}")
    return Member(name, source.read(), stat.S_IMODE(info.mode))


def _zip_mode(info: zipfile.ZipInfo) -> int | None:
    mode = (info.external_attr >> 16) & 0xFFFF
    return mode or None


def _read_archive(path: Path) -> tuple[Archive, bytes]:
    """Read an archive without extracting it and return its raw bytes."""

    try:
        if path.stat().st_size > MAX_ARCHIVE_BYTES:
            raise ArtifactError(
                f"archive exceeds {MAX_ARCHIVE_BYTES} byte release limit"
            )
        raw = path.read_bytes()
    except OSError as error:
        raise ArtifactError(f"cannot read archive {path}: {error}") from error
    if not raw:
        raise ArtifactError("archive is empty")

    members: list[Member] = []
    seen: set[str] = set()
    uncompressed_bytes = 0
    if zipfile.is_zipfile(path):
        archive_format = "zip"
        try:
            with zipfile.ZipFile(path) as archive:
                infos = archive.infolist()
                if len(infos) > MAX_MEMBER_COUNT:
                    raise ArtifactError("archive has too many members")
                for info in infos:
                    name = info.filename.rstrip("/")
                    if not name:
                        continue
                    normalised = _normalise_member_name(name)
                    if normalised in seen:
                        raise ArtifactError(f"duplicate archive member: {normalised}")
                    seen.add(normalised)
                    if info.is_dir():
                        continue
                    mode = _zip_mode(info)
                    if mode is not None and stat.S_ISLNK(mode):
                        raise ArtifactError(f"archive member is a symlink: {name!r}")
                    if mode is not None and not stat.S_ISREG(mode):
                        raise ArtifactError(f"archive member is a special file: {name!r}")
                    try:
                        data = archive.read(info)
                    except (RuntimeError, OSError, zipfile.BadZipFile) as error:
                        raise ArtifactError(f"cannot read archive member {name!r}: {error}") from error
                    if len(data) > MAX_MEMBER_BYTES:
                        raise ArtifactError(
                            f"archive member exceeds {MAX_MEMBER_BYTES} bytes: {name!r}"
                        )
                    uncompressed_bytes += len(data)
                    if uncompressed_bytes > MAX_UNCOMPRESSED_BYTES:
                        raise ArtifactError("archive expands beyond the release limit")
                    members.append(Member(normalised, data, mode))
        except zipfile.BadZipFile as error:
            raise ArtifactError(f"invalid ZIP archive: {error}") from error
    else:
        archive_format = "tar.gz"
        if raw[:2] != b"\x1f\x8b":
            raise ArtifactError("archive must be ZIP or gzip-compressed tar")
        try:
            with tarfile.open(path, mode="r:*") as archive:
                infos = archive.getmembers()
                if len(infos) > MAX_MEMBER_COUNT:
                    raise ArtifactError("archive has too many members")
                for info in infos:
                    member = _read_regular_tar_member(archive, info)
                    if member is None:
                        continue
                    if member.path in seen:
                        raise ArtifactError(f"duplicate archive member: {member.path}")
                    seen.add(member.path)
                    uncompressed_bytes += len(member.data)
                    if uncompressed_bytes > MAX_UNCOMPRESSED_BYTES:
                        raise ArtifactError("archive expands beyond the release limit")
                    members.append(member)
        except (tarfile.TarError, EOFError, OSError) as error:
            raise ArtifactError(f"invalid tar archive: {error}") from error
    if not members:
        raise ArtifactError("archive has no regular files")
    return Archive(archive_format, tuple(members)), raw


def _strip_archive_root(paths: Iterable[str]) -> tuple[str, set[str]]:
    """Return an optional common top-level directory and relative file paths."""

    names = tuple(paths)
    first_parts = {PurePosixPath(name).parts[0] for name in names}
    if len(first_parts) == 1 and all(len(PurePosixPath(name).parts) > 1 for name in names):
        root = next(iter(first_parts))
        return root, {
            PurePosixPath(name).relative_to(root).as_posix() for name in names
        }
    return "", set(names)


def _binary_name(target: str) -> str:
    if not target or any(character.isspace() for character in target):
        raise ArtifactError("target must be a non-empty, whitespace-free triple")
    if target not in SUPPORTED_TARGETS:
        raise ArtifactError(f"target is not a supported standalone release target: {target!r}")
    return "jmeter-rs.exe" if "windows" in target else "jmeter-rs"


def _validate_forbidden_path(path: str, binary: str) -> None:
    lower = path.casefold()
    suffix = Path(path).suffix.casefold()
    if suffix in FORBIDDEN_SUFFIXES:
        raise ArtifactError(f"forbidden Java/plugin artifact in archive: {path}")
    if re.search(r"\.(?:dll|dylib|pdb|so(?:\.\d+)?)$", lower):
        raise ArtifactError(f"undeclared runtime/sidecar artifact in archive: {path}")
    if suffix == ".exe" and path != binary:
        raise ArtifactError(f"undeclared helper executable in archive: {path}")
    if path == binary:
        return
    segments = set(PurePosixPath(lower).parts)
    forbidden_segments = {
        "class path",
        "classpath",
        "compat-pack",
        "compatibility-pack",
        "helper",
        "java",
        "javac",
        "jdk",
        "jre",
        "jvm",
        "plugin",
        "plugins",
    }
    if segments & forbidden_segments:
        raise ArtifactError(f"forbidden helper/runtime path in archive: {path}")
    # Catch a helper or runtime encoded in a filename while allowing the
    # required project binary ``jmeter-rs`` itself.
    stem = Path(path).stem.casefold()
    if any(token in stem for token in ("helper", "jre", "jdk", "jvm", "plugin")):
        raise ArtifactError(f"forbidden helper/runtime filename in archive: {path}")


def validate_archive(path: Path, target: str) -> tuple[Archive, bytes, str, dict[str, dict[str, object]]]:
    """Validate exact inventory and return archive data and member records."""

    archive, raw = _read_archive(path)
    binary = _binary_name(target)
    root, relative_paths = _strip_archive_root(member.path for member in archive.members)
    expected = {binary, *RELEASE_DOCUMENTS}
    if relative_paths != expected:
        missing = sorted(expected - relative_paths)
        unexpected = sorted(relative_paths - expected)
        details: list[str] = []
        if missing:
            details.append(f"missing={missing}")
        if unexpected:
            details.append(f"unexpected={unexpected}")
        raise ArtifactError("archive inventory mismatch: " + ", ".join(details))

    records: dict[str, dict[str, object]] = {}
    for member in archive.members:
        relative = (
            PurePosixPath(member.path).relative_to(root).as_posix()
            if root
            else member.path
        )
        _validate_forbidden_path(relative, binary)
        if not member.data:
            raise ArtifactError(f"archive member is empty: {relative}")
        if relative == binary and not binary.casefold().endswith(".exe"):
            if member.mode is None or not (member.mode & stat.S_IXUSR):
                raise ArtifactError(f"release binary is not executable: {relative}")
        records[relative] = {
            "path": relative,
            "size_bytes": len(member.data),
            "sha256": hashlib.sha256(member.data).hexdigest(),
        }
    if binary not in records:
        raise ArtifactError(f"binary {binary!r} is missing")
    return archive, raw, root, records


def _required_text(value: str | None, field: str) -> str:
    if value is None or not value.strip():
        raise ArtifactError(f"manifest provenance field {field!r} is required")
    return value


def _read_bounded(path: Path, label: str, limit: int = MAX_EVIDENCE_BYTES) -> bytes:
    """Read one evidence input under a hard byte bound.

    Evidence is generated by the workflow, but it is still untrusted input to
    this checker.  Error messages name only the logical input kind so a
    machine-specific path or a secret-bearing command line cannot escape in
    CI diagnostics.
    """

    try:
        if path.stat().st_size > limit:
            raise ArtifactError(f"{label} exceeds the {limit}-byte evidence limit")
        data = path.read_bytes()
    except ArtifactError:
        raise
    except OSError as error:
        raise ArtifactError(f"cannot read {label} evidence: {error.strerror or 'I/O error'}") from error
    if len(data) > limit:
        raise ArtifactError(f"{label} exceeds the {limit}-byte evidence limit")
    return data


def _read_json_evidence(path: Path, label: str) -> tuple[dict[str, object], str]:
    data = _read_bounded(path, label)
    digest = hashlib.sha256(data).hexdigest()
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ArtifactError(f"{label} evidence is not bounded UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise ArtifactError(f"{label} evidence must be a JSON object")
    return value, digest


def _safe_label(value: object) -> str:
    """Redact path-like/secret-like diagnostics to a short stable token."""

    text = str(value)
    text = text.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    text = re.sub(r"[^A-Za-z0-9_.@+-]", "?", text)
    return text[:128] or "<empty>"


def _sha256_file(path: Path, label: str = "file") -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as error:
        raise ArtifactError(f"cannot hash {label} evidence: {error.strerror or 'I/O error'}") from error
    return digest.hexdigest()


def _metadata_package_index(metadata: dict[str, object]) -> tuple[dict[str, str], dict[str, object]]:
    packages = metadata.get("packages")
    resolve = metadata.get("resolve")
    if not isinstance(packages, list) or not isinstance(resolve, dict):
        raise ArtifactError("Cargo metadata evidence lacks packages/resolve objects")
    if len(packages) > MAX_TREE_LINES:
        raise ArtifactError("Cargo metadata evidence contains too many packages")
    package_names: dict[str, str] = {}
    for package in packages:
        if not isinstance(package, dict):
            raise ArtifactError("Cargo metadata package entry is not an object")
        package_id = package.get("id")
        package_name = package.get("name")
        if not isinstance(package_id, str) or not isinstance(package_name, str):
            raise ArtifactError("Cargo metadata package identity is malformed")
        if package_id in package_names and package_names[package_id] != package_name:
            raise ArtifactError("Cargo metadata contains conflicting package identities")
        package_names[package_id] = package_name
    nodes = resolve.get("nodes")
    if not isinstance(nodes, list) or len(nodes) > MAX_TREE_LINES:
        raise ArtifactError("Cargo metadata resolve graph is missing or too large")
    node_index: dict[str, object] = {}
    for node in nodes:
        if not isinstance(node, dict) or not isinstance(node.get("id"), str):
            raise ArtifactError("Cargo metadata resolve node is malformed")
        node_id = node["id"]
        if node_id in node_index:
            raise ArtifactError("Cargo metadata resolve graph repeats a node")
        node_index[node_id] = node
    return package_names, {"nodes": node_index, "resolve": resolve}


def _normal_dependency(dep: object) -> bool:
    if not isinstance(dep, dict):
        raise ArtifactError("Cargo metadata dependency entry is malformed")
    kinds = dep.get("dep_kinds")
    if not isinstance(kinds, list) or not kinds:
        raise ArtifactError("Cargo metadata dependency kinds are missing")
    for kind in kinds:
        if not isinstance(kind, dict):
            raise ArtifactError("Cargo metadata dependency kind is malformed")
        if kind.get("kind") in (None, "normal"):
            return True
    return False


def _validate_cargo_metadata(path: Path, target: str) -> tuple[dict[str, object], str]:
    metadata, digest = _read_json_evidence(path, "Cargo metadata")
    package_names, graph = _metadata_package_index(metadata)
    app_ids = [package_id for package_id, name in package_names.items() if name == "jmeter-rs"]
    if len(app_ids) != 1:
        raise ArtifactError("Cargo metadata must contain exactly one jmeter-rs package")
    nodes = graph["nodes"]
    app_id = app_ids[0]
    if app_id not in nodes:
        raise ArtifactError("Cargo metadata resolve graph omits the jmeter-rs package")
    reachable: set[str] = set()
    pending = [app_id]
    while pending:
        package_id = pending.pop()
        if package_id in reachable:
            continue
        if package_id not in package_names:
            raise ArtifactError("Cargo metadata resolve graph references an unknown package")
        reachable.add(package_id)
        node = nodes[package_id]
        if not isinstance(node, dict):
            raise ArtifactError("Cargo metadata resolve node is malformed")
        deps = node.get("deps")
        if not isinstance(deps, list):
            raise ArtifactError("Cargo metadata resolve node lacks dependency entries")
        for dep in deps:
            if not _normal_dependency(dep):
                continue
            dependency_id = dep.get("pkg") if isinstance(dep, dict) else None
            if not isinstance(dependency_id, str):
                raise ArtifactError("Cargo metadata dependency lacks a package ID")
            pending.append(dependency_id)
    closure_names = {package_names[package_id] for package_id in reachable}
    forbidden = sorted(closure_names & FORBIDDEN_WORKSPACE_PACKAGES)
    if forbidden:
        labels = ", ".join(_safe_label(name) for name in forbidden)
        raise ArtifactError(f"forbidden package in {target} normal dependency closure: {labels}")
    return {
        "target": target,
        "root_package": "jmeter-rs",
        "normal_package_count": len(reachable),
        "normal_workspace_packages": sorted(
            name
            for package_id, name in package_names.items()
            if package_id in reachable and name.startswith("jmeter-rs")
        ),
        "_all_normal_package_names": sorted(closure_names),
        "forbidden_packages": [],
        "metadata_sha256": digest,
    }, digest


_CARGO_TREE_PACKAGE = re.compile(
    r"^(?:\d+)([A-Za-z0-9][A-Za-z0-9_.-]*)\s+v[^\s]+(?:\s|$)"
)


def _validate_cargo_tree(path: Path, target: str) -> tuple[set[str], str]:
    data = _read_bounded(path, "Cargo tree")
    digest = hashlib.sha256(data).hexdigest()
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ArtifactError("Cargo tree evidence is not UTF-8") from error
    lines = text.splitlines()
    if len(lines) > MAX_TREE_LINES:
        raise ArtifactError("Cargo tree evidence contains too many lines")
    names: set[str] = set()
    for line in lines:
        match = _CARGO_TREE_PACKAGE.match(line)
        if match:
            names.add(match.group(1))
    if "jmeter-rs" not in names:
        raise ArtifactError(f"Cargo tree evidence for {target} lacks the jmeter-rs root")
    forbidden = sorted(names & FORBIDDEN_WORKSPACE_PACKAGES)
    if forbidden:
        labels = ", ".join(_safe_label(name) for name in forbidden)
        raise ArtifactError(f"forbidden package in {target} Cargo tree: {labels}")
    return names, digest


def _validate_dependency_evidence(
    metadata_path: Path | None,
    tree_path: Path | None,
    target: str,
) -> dict[str, object]:
    if metadata_path is None or tree_path is None:
        raise ArtifactError("Cargo metadata and Cargo tree evidence are required")
    metadata, _metadata_digest = _validate_cargo_metadata(metadata_path, target)
    tree_names, tree_digest = _validate_cargo_tree(tree_path, target)
    # Cargo tree is the human-readable corroboration of the machine-readable
    # resolve walk.  Requiring an exact package-name set catches an accidental
    # dev-only or wrong-target tree invocation without retaining workspace
    # paths in the release manifest.
    if tree_names != set(metadata["_all_normal_package_names"]):
        raise ArtifactError("Cargo metadata and Cargo tree normal closures disagree")
    metadata["tree_sha256"] = tree_digest
    metadata.pop("_all_normal_package_names", None)
    return metadata


def _linkage_kind(target: str) -> str:
    if target.endswith("-linux-gnu") or target.endswith("-linux-musl"):
        return "elf-dt-needed"
    if target.endswith("-apple-darwin"):
        return "macho-otool"
    if target.endswith("-windows-msvc"):
        return "pe-imports"
    raise ArtifactError(f"no linkage policy exists for target {_safe_label(target)}")


def _reject_linkage_markers(text: str) -> None:
    lowered = text.casefold()
    for marker in FORBIDDEN_LINKAGE_MARKERS:
        if marker in lowered:
            raise ArtifactError(f"forbidden JVM/plugin linkage marker: {_safe_label(marker)}")


def _parse_elf_needed(output: str) -> list[str]:
    libraries = re.findall(r"Shared library:\s*\[([^\]\r\n]{1,256})\]", output)
    if any("NEEDED" in line for line in output.splitlines()) and not libraries:
        raise ArtifactError("ELF DT_NEEDED output could not be parsed")
    return libraries


def _parse_macho_libraries(output: str) -> list[str]:
    libraries = []
    for line in output.splitlines():
        match = re.match(r"^\s+(\S+)\s+\(compatibility version\s+", line)
        if match:
            libraries.append(match.group(1))
    if not libraries:
        raise ArtifactError("macOS otool -L output contained no parseable libraries")
    return libraries


def _parse_pe_imports(output: str) -> list[str]:
    libraries: list[str] = []
    for line in output.splitlines():
        match = re.match(r"^\s*(?:DLL Name:\s*|Name:\s*)([A-Za-z0-9_.-]+\.dll)\s*$", line, re.IGNORECASE)
        if match:
            libraries.append(match.group(1))
            continue
        # objdump/dumpbin output may be reduced to one import name per line by
        # a platform wrapper.  Restrict this fallback to bare DLL names so it
        # cannot mistake imported function names for libraries.
        bare = re.match(r"^\s*([A-Za-z0-9_.-]+\.dll)\s*$", line, re.IGNORECASE)
        if bare:
            libraries.append(bare.group(1))
    if not libraries:
        raise ArtifactError("Windows PE import output contained no parseable DLLs")
    return libraries


def _validate_linkage_evidence(
    path: Path | None,
    target: str,
    binary_sha256: str,
    static_expected: bool,
) -> dict[str, object]:
    if path is None:
        raise ArtifactError("target linkage evidence is required")
    evidence, evidence_digest = _read_json_evidence(path, "linkage")
    if evidence.get("schema_id") != LINKAGE_SCHEMA_ID or evidence.get("schema_version") != 1:
        raise ArtifactError("linkage evidence schema is unsupported")
    if evidence.get("target") != target:
        raise ArtifactError("linkage evidence target does not match the archive")
    if evidence.get("binary_sha256") != binary_sha256:
        raise ArtifactError("linkage evidence is not bound to the archived executable")
    kind = evidence.get("kind")
    expected_kind = _linkage_kind(target)
    if kind != expected_kind:
        raise ArtifactError("linkage evidence format does not match the target")
    output = evidence.get("output")
    tool = evidence.get("tool")
    if not isinstance(output, str) or not output or len(output.encode("utf-8")) > MAX_EVIDENCE_BYTES:
        raise ArtifactError("linkage evidence output is missing or exceeds its bound")
    if not isinstance(tool, str) or not tool.strip():
        raise ArtifactError("linkage evidence tool identity is required")
    _reject_linkage_markers(output)
    if kind == "elf-dt-needed":
        libraries = _parse_elf_needed(output)
        allowed = LINUX_ALLOWED_SYSTEM_LIBRARIES[target]
        if target.endswith("-musl") and libraries:
            raise ArtifactError("musl executable has a dynamic DT_NEEDED entry")
        if not set(libraries) <= allowed:
            disallowed = sorted(set(libraries) - allowed)
            labels = ", ".join(_safe_label(name) for name in disallowed)
            raise ArtifactError(f"ELF imports outside the declared system policy: {labels}")
        if not target.endswith("-musl") and not libraries:
            raise ArtifactError("glibc executable has no parseable DT_NEEDED entries")
    elif kind == "macho-otool":
        libraries = _parse_macho_libraries(output)
        for library in libraries:
            basename = library.rsplit("/", 1)[-1]
            if library.startswith("@") or not library.startswith(("/usr/lib/", "/System/Library/")):
                raise ArtifactError(f"macOS import is not an allowed system path: {_safe_label(library)}")
            if basename not in MACOS_ALLOWED_SYSTEM_LIBRARIES:
                raise ArtifactError(f"macOS import outside the declared system policy: {_safe_label(library)}")
    else:
        libraries = _parse_pe_imports(output)
        normalised = [name.casefold() for name in libraries]
        disallowed = sorted(
            {
                name
                for name in normalised
                if name not in WINDOWS_ALLOWED_SYSTEM_IMPORTS
                and not name.startswith(WINDOWS_ALLOWED_SYSTEM_PREFIXES)
            }
        )
        if disallowed:
            labels = ", ".join(_safe_label(name) for name in disallowed)
            raise ArtifactError(f"Windows imports outside the declared system policy: {labels}")
    return {
        "schema_id": LINKAGE_SCHEMA_ID,
        "schema_version": 1,
        "kind": kind,
        "tool": _safe_label(tool),
        "libraries": sorted(set(libraries), key=str.casefold),
        "evidence_sha256": evidence_digest,
        "policy": "standalone-native-system-libraries-v1",
    }


def _validate_runtime_evidence(
    path: Path | None,
    target: str,
    binary_sha256: str,
    execution_evidence: str,
) -> tuple[dict[str, object], str]:
    if path is None:
        raise ArtifactError("sanitized runtime evidence is required")
    evidence, evidence_digest = _read_json_evidence(path, "runtime")
    if evidence.get("schema_id") != RUNTIME_SCHEMA_ID or evidence.get("schema_version") != 1:
        raise ArtifactError("runtime evidence schema is unsupported")
    if evidence.get("target") != target or evidence.get("binary_sha256") != binary_sha256:
        raise ArtifactError("runtime evidence is not bound to the archived executable")
    if evidence.get("execution_evidence") != execution_evidence:
        raise ArtifactError("runtime evidence kind does not match the provenance")
    version = evidence.get("version")
    fixture = evidence.get("fixture")
    environment = evidence.get("environment")
    child = evidence.get("child_executable_launch")
    if not all(isinstance(item, dict) for item in (version, fixture, environment, child)):
        raise ArtifactError("runtime evidence lacks version/fixture/environment/child objects")
    forbidden = environment.get("forbidden_environment_names")
    if environment.get("forbidden_absent") is not True or not isinstance(forbidden, list):
        raise ArtifactError("runtime evidence does not prove a cleared environment")
    if {str(name) for name in forbidden} != FORBIDDEN_ENVIRONMENT_NAMES:
        raise ArtifactError("runtime evidence environment denylist is incomplete")
    allowlist = environment.get("allowlist")
    if not isinstance(allowlist, list) or any(not isinstance(value, str) for value in allowlist):
        raise ArtifactError("runtime evidence environment allowlist is malformed")
    if fixture.get("id") != "debug-sampler/native-local" or fixture.get("network_fixture") is not False:
        raise ArtifactError("runtime fixture is not the offline DebugSampler contract")
    if execution_evidence == "native-runtime":
        if version.get("status") != "passed" or version.get("exit_code") != 0:
            raise ArtifactError("native runtime --version evidence did not pass")
        if fixture.get("status") != "passed" or fixture.get("exit_code") != 0:
            raise ArtifactError("native DebugSampler fixture evidence did not pass")
        child_status = child.get("status")
        if child_status == "verified-no-child-exec":
            if not isinstance(child.get("method"), str) or child.get("method") not in {
                "linux-strace-execve",
                "macos-dtruss-execve",
            }:
                raise ArtifactError("runtime child-launch trace method is not approved")
            if child.get("traced_invocations") != 2:
                raise ArtifactError("runtime child-launch trace did not cover both smoke invocations")
        elif child_status == "missing-gate":
            if child.get("method") != "none" or child.get("reason") not in {
                "platform-native-tracer-unavailable",
                "platform-native-tracer-failed",
            }:
                raise ArtifactError("runtime child-launch missing gate is not documented precisely")
        else:
            raise ArtifactError("runtime child-launch evidence has an unknown status")
    else:
        if version.get("status") != "not-run-cross-compile" or fixture.get("status") != "not-run-cross-compile":
            raise ArtifactError("cross-compile evidence must not claim runtime execution")
        if child.get("status") != "not-run-cross-compile" or child.get("reason") != "target-not-executable-on-host":
            raise ArtifactError("cross-compile evidence lacks the target execution boundary")
    return {
        "schema_id": RUNTIME_SCHEMA_ID,
        "schema_version": 1,
        "version_status": version.get("status"),
        "fixture_id": fixture.get("id"),
        "fixture_status": fixture.get("status"),
        "environment_policy": "explicit-empty-with-denylist-v1",
        "child_executable_launch": {
            "status": child.get("status"),
            "method": child.get("method"),
            "reason": child.get("reason"),
        },
        "evidence_sha256": evidence_digest,
    }, evidence_digest


def build_manifest(
    *,
    archive_path: Path,
    target: str,
    source_commit: str,
    dirty_tree: str,
    profile_sha256: str,
    rust_toolchain: str,
    rustc_version: str,
    cargo_lock_sha256: str,
    host_target: str,
    execution_evidence: str,
    runner_os: str,
    runner_arch: str,
    source_date_epoch: str,
    static_expected: bool,
    cargo_metadata_path: Path | None = None,
    cargo_tree_path: Path | None = None,
    linkage_evidence_path: Path | None = None,
    runtime_evidence_path: Path | None = None,
) -> dict[str, object]:
    """Validate an archive and construct its machine-readable evidence."""

    if execution_evidence not in {"native-runtime", "cross-compile-only"}:
        raise ArtifactError(
            "execution evidence must be native-runtime or cross-compile-only"
        )
    source_commit = _required_text(source_commit, "source_commit")
    if len(source_commit) != 40 or any(
        character not in "0123456789abcdef" for character in source_commit
    ):
        raise ArtifactError("source_commit must be a lowercase 40-character commit SHA")
    dirty_tree = _required_text(dirty_tree, "dirty_tree")
    if dirty_tree != "clean":
        raise ArtifactError("release provenance requires a clean dirty_tree value")
    rust_toolchain = _required_text(rust_toolchain, "rust_toolchain")
    profile_sha256 = _required_text(profile_sha256, "profile_sha256")
    if len(profile_sha256) != 64 or any(
        character not in "0123456789abcdef" for character in profile_sha256
    ):
        raise ArtifactError("profile_sha256 must be a lowercase SHA-256")
    rustc_version = _required_text(rustc_version, "rustc_version")
    cargo_lock_sha256 = _required_text(cargo_lock_sha256, "cargo_lock_sha256")
    if len(cargo_lock_sha256) != 64 or any(
        character not in "0123456789abcdef" for character in cargo_lock_sha256
    ):
        raise ArtifactError("cargo_lock_sha256 must be a lowercase SHA-256")
    host_target = _required_text(host_target, "host_target")
    runner_os = _required_text(runner_os, "runner_os")
    runner_arch = _required_text(runner_arch, "runner_arch")
    source_date_epoch = _required_text(source_date_epoch, "source_date_epoch")
    try:
        int(source_date_epoch)
    except ValueError as error:
        raise ArtifactError("source_date_epoch must be an integer") from error
    if execution_evidence == "native-runtime" and host_target != target:
        raise ArtifactError(
            "native-runtime evidence requires host_target to equal target"
        )
    if execution_evidence == "cross-compile-only" and host_target == target:
        raise ArtifactError(
            "cross-compile-only evidence requires a different host_target"
        )
    if target.endswith("-musl") != static_expected:
        raise ArtifactError("musl static expectation does not match the target policy")

    archive, raw, root, records = validate_archive(archive_path, target)
    members = [records[path] for path in sorted(records)]
    binary = _binary_name(target)
    dependency_evidence = _validate_dependency_evidence(
        cargo_metadata_path,
        cargo_tree_path,
        target,
    )
    linkage_evidence = _validate_linkage_evidence(
        linkage_evidence_path,
        target,
        str(records[binary]["sha256"]),
        static_expected,
    )
    runtime_evidence, runtime_evidence_sha256 = _validate_runtime_evidence(
        runtime_evidence_path,
        target,
        str(records[binary]["sha256"]),
        execution_evidence,
    )
    archive_sha256 = hashlib.sha256(raw).hexdigest()
    manifest: dict[str, object] = {
        "schema_id": SCHEMA_ID,
        "schema_version": SCHEMA_VERSION,
        "compatibility": {
            "capability_set": CAPABILITY_SET,
            "profile_id": PROFILE_ID,
            "profile_sha256": profile_sha256,
            "decision": DECISION_ID,
            "compatibility_ids": list(COMPATIBILITY_IDS),
            "release_channel": "experimental-pre-release",
            "conformance_claim": "none",
        },
        "artifact": {
            "filename": archive_path.name,
            "format": archive.format,
            "target": target,
            "archive_sha256": archive_sha256,
            "archive_size_bytes": len(raw),
            "archive_root": root,
            "binary": binary,
            "inventory": members,
        },
        "provenance": {
            "source_commit": source_commit,
            "dirty_tree": dirty_tree,
            "rust_toolchain": rust_toolchain,
            "rustc_version": rustc_version,
            "cargo_lock_sha256": cargo_lock_sha256,
            "target": target,
            "host_target": host_target,
            "execution_evidence": execution_evidence,
            "runner_os": runner_os,
            "runner_arch": runner_arch,
            "source_date_epoch": int(source_date_epoch),
            "build_profile": "release",
        },
        "dependency_closure": dependency_evidence,
        "linkage": linkage_evidence,
        "runtime_evidence": runtime_evidence,
        "negative_assertions": {
            "java_runtime": False,
            "jmeter_distribution": False,
            "helper_executable": False,
            "jar_or_plugin_artifact": False,
            "application_sidecar": False,
            "forbidden_workspace_dependency": False,
            "forbidden_dynamic_import": False,
            "child_executable_launch": (
                False
                if runtime_evidence["child_executable_launch"]["status"]
                == "verified-no-child-exec"
                else None
            ),
        },
        "static_binary": static_expected,
    }
    return manifest


def _write_manifest(path: Path, manifest: dict[str, object]) -> None:
    payload = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    try:
        path.write_text(payload, encoding="utf-8")
    except OSError as error:
        raise ArtifactError(f"cannot write manifest {path}: {error}") from error


def _create_test_archive(path: Path, target: str, *, archive_format: str) -> None:
    """Create a tiny deterministic fixture archive for ``--self-test``."""

    binary = _binary_name(target)
    payloads = {
        binary: b"standalone test binary\n",
        "LICENSE": b"license\n",
        "NOTICE": b"notice\n",
        "README.md": b"readme\n",
        "docs/architecture.md": b"architecture\n",
        "docs/third-party-provenance.md": b"provenance\n",
    }
    epoch = 1_700_000_000
    root = f"jmeter-rs-{target}"
    path.parent.mkdir(parents=True, exist_ok=True)
    if archive_format == "zip":
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for relative, data in sorted(payloads.items()):
                info = zipfile.ZipInfo(f"{root}/{relative}")
                info.date_time = (2023, 11, 14, 22, 13, 20)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = (0o100755 if relative == binary else 0o100644) << 16
                archive.writestr(info, data)
    else:
        import gzip

        with path.open("wb") as stream:
            with gzip.GzipFile(fileobj=stream, mode="wb", mtime=epoch) as compressed:
                with tarfile.open(fileobj=compressed, mode="w") as archive:
                    for relative, data in sorted(payloads.items()):
                        info = tarfile.TarInfo(f"{root}/{relative}")
                        info.size = len(data)
                        info.mode = 0o755 if relative == binary else 0o644
                        info.mtime = epoch
                        archive.addfile(info, io.BytesIO(data))


def _write_json_fixture(path: Path, value: dict[str, object]) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def _create_test_evidence(
    root: Path,
    archive_path: Path,
    target: str,
    *,
    execution_evidence: str,
    static_expected: bool,
) -> tuple[Path, Path, Path, Path]:
    """Create bounded, path-free evidence fixtures for checker self-tests."""

    _archive, _raw, _archive_root, records = validate_archive(archive_path, target)
    binary_sha256 = str(records[_binary_name(target)]["sha256"])
    root_id = "path+file:///workspace/apps/jmeter-rs#0.1.0"
    http_id = "path+file:///workspace/crates/http#jmeter-rs-http@0.1.0"
    results_id = "path+file:///workspace/crates/results#jmeter-rs-results@0.1.0"
    metadata = {
        "packages": [
            {"id": root_id, "name": "jmeter-rs"},
            {"id": http_id, "name": "jmeter-rs-http"},
            {"id": results_id, "name": "jmeter-rs-results"},
        ],
        "resolve": {
            "nodes": [
                {
                    "id": root_id,
                    "deps": [
                        {
                            "pkg": http_id,
                            "dep_kinds": [{"kind": None, "target": None}],
                        }
                    ],
                },
                {
                    "id": http_id,
                    "deps": [
                        {
                            "pkg": results_id,
                            "dep_kinds": [{"kind": "normal", "target": None}],
                        }
                    ],
                },
                {"id": results_id, "deps": []},
            ]
        },
    }
    metadata_path = root / f"{target}.metadata.json"
    tree_path = root / f"{target}.tree.txt"
    linkage_path = root / f"{target}.linkage.json"
    runtime_path = root / f"{target}.runtime.json"
    _write_json_fixture(metadata_path, metadata)
    tree_path.write_text(
        "0jmeter-rs v0.1.0\n"
        "1jmeter-rs-http v0.1.0\n"
        "2jmeter-rs-results v0.1.0\n",
        encoding="utf-8",
    )
    if target.endswith("-linux-gnu"):
        linkage_kind = "elf-dt-needed"
        linkage_tool = "readelf"
        loader = (
            "ld-linux-aarch64.so.1"
            if target.startswith("aarch64-")
            else "ld-linux-x86-64.so.2"
        )
        linkage_output = (
            "Dynamic section:\n"
            "  NEEDED Shared library: [libc.so.6]\n"
            "  NEEDED Shared library: [libgcc_s.so.1]\n"
            f"  NEEDED Shared library: [{loader}]\n"
        )
    elif target.endswith("-linux-musl"):
        linkage_kind = "elf-dt-needed"
        linkage_tool = "readelf"
        linkage_output = "Dynamic section has no dynamic dependencies.\n"
    elif target.endswith("-apple-darwin"):
        linkage_kind = "macho-otool"
        linkage_tool = "otool"
        linkage_output = (
            "binary:\n"
            "\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1.0.0)\n"
        )
    else:
        linkage_kind = "pe-imports"
        linkage_tool = "dumpbin"
        linkage_output = "  DLL Name: KERNEL32.dll\n  DLL Name: ucrtbase.dll\n"
    _write_json_fixture(
        linkage_path,
        {
            "schema_id": LINKAGE_SCHEMA_ID,
            "schema_version": 1,
            "target": target,
            "binary_sha256": binary_sha256,
            "kind": linkage_kind,
            "tool": linkage_tool,
            "output": linkage_output,
        },
    )
    environment_names = sorted(FORBIDDEN_ENVIRONMENT_NAMES)
    if execution_evidence == "native-runtime":
        version = {"status": "passed", "exit_code": 0}
        fixture = {
            "id": "debug-sampler/native-local",
            "network_fixture": False,
            "status": "passed",
            "exit_code": 0,
        }
        child = {
            "status": "verified-no-child-exec",
            "method": "linux-strace-execve",
            "traced_invocations": 2,
        }
    else:
        version = {"status": "not-run-cross-compile"}
        fixture = {
            "id": "debug-sampler/native-local",
            "network_fixture": False,
            "status": "not-run-cross-compile",
        }
        child = {
            "status": "not-run-cross-compile",
            "reason": "target-not-executable-on-host",
        }
    _write_json_fixture(
        runtime_path,
        {
            "schema_id": RUNTIME_SCHEMA_ID,
            "schema_version": 1,
            "target": target,
            "binary_sha256": binary_sha256,
            "execution_evidence": execution_evidence,
            "version": version,
            "fixture": fixture,
            "environment": {
                "allowlist": ["LANG=C", "LC_ALL=C", "PATH=<runtime-bin>", "TZ=UTC"],
                "forbidden_absent": True,
                "forbidden_environment_names": environment_names,
            },
            "child_executable_launch": child,
        },
    )
    return metadata_path, tree_path, linkage_path, runtime_path


def _manifest_kwargs(
    archive_path: Path,
    target: str,
    evidence: tuple[Path, Path, Path, Path],
    *,
    execution_evidence: str,
    host_target: str,
    static_expected: bool,
) -> dict[str, object]:
    metadata_path, tree_path, linkage_path, runtime_path = evidence
    return {
        "archive_path": archive_path,
        "target": target,
        "source_commit": "0" * 40,
        "dirty_tree": "clean",
        "profile_sha256": "b" * 64,
        "rust_toolchain": "1.97.1",
        "rustc_version": "rustc 1.97.1",
        "cargo_lock_sha256": "a" * 64,
        "host_target": host_target,
        "execution_evidence": execution_evidence,
        "runner_os": "Linux",
        "runner_arch": "X64",
        "source_date_epoch": "1700000000",
        "static_expected": static_expected,
        "cargo_metadata_path": metadata_path,
        "cargo_tree_path": tree_path,
        "linkage_evidence_path": linkage_path,
        "runtime_evidence_path": runtime_path,
    }


def self_test() -> None:
    """Run deterministic positive and negative archive checks."""

    with tempfile.TemporaryDirectory(prefix="standalone-artifact-test-") as directory:
        root = Path(directory)
        for archive_format, suffix in (("tar.gz", ".tar.gz"), ("zip", ".zip")):
            archive_path = root / f"native{suffix}"
            _create_test_archive(archive_path, "x86_64-unknown-linux-gnu", archive_format=archive_format)
            evidence = _create_test_evidence(
                root,
                archive_path,
                "x86_64-unknown-linux-gnu",
                execution_evidence="native-runtime",
                static_expected=False,
            )
            manifest = build_manifest(**_manifest_kwargs(
                archive_path,
                "x86_64-unknown-linux-gnu",
                evidence,
                execution_evidence="native-runtime",
                host_target="x86_64-unknown-linux-gnu",
                static_expected=False,
            ))
            assert manifest["artifact"]["format"] == archive_format
            assert len(manifest["artifact"]["inventory"]) == 6

        native_evidence = _create_test_evidence(
            root,
            root / "native.tar.gz",
            "x86_64-unknown-linux-gnu",
            execution_evidence="cross-compile-only",
            static_expected=False,
        )
        cross_manifest = build_manifest(
            **_manifest_kwargs(
                root / "native.tar.gz",
                "x86_64-unknown-linux-gnu",
                native_evidence,
                execution_evidence="cross-compile-only",
                host_target="aarch64-unknown-linux-gnu",
                static_expected=False,
            ),
        )
        assert cross_manifest["provenance"]["execution_evidence"] == "cross-compile-only"

        # The normal-only Cargo closure gate must reject a compatibility-pack
        # package even when the archive inventory itself is valid.
        metadata_path, tree_path, linkage_path, runtime_path = native_evidence
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        forbidden_id = "path+file:///workspace/crates/java-bridge#jmeter-rs-java-bridge@0.1.0"
        metadata["packages"].append({"id": forbidden_id, "name": "jmeter-rs-java-bridge"})
        metadata["resolve"]["nodes"][0]["deps"].append(
            {"pkg": forbidden_id, "dep_kinds": [{"kind": None, "target": None}]}
        )
        metadata["resolve"]["nodes"].append({"id": forbidden_id, "deps": []})
        forbidden_metadata = root / "forbidden.metadata.json"
        _write_json_fixture(forbidden_metadata, metadata)
        try:
            _validate_dependency_evidence(forbidden_metadata, tree_path, "x86_64-unknown-linux-gnu")
        except ArtifactError as error:
            assert "forbidden package" in str(error)
        else:  # pragma: no cover
            raise AssertionError("forbidden normal dependency unexpectedly validated")

        # Dynamic imports are checked independently of archive sidecar paths.
        linkage = json.loads(linkage_path.read_text(encoding="utf-8"))
        linkage["output"] += "  NEEDED Shared library: [libjvm.so]\n"
        forbidden_linkage = root / "forbidden.linkage.json"
        _write_json_fixture(forbidden_linkage, linkage)
        try:
            _validate_linkage_evidence(
                forbidden_linkage,
                "x86_64-unknown-linux-gnu",
                str(validate_archive(root / "native.tar.gz", "x86_64-unknown-linux-gnu")[3]["jmeter-rs"]["sha256"]),
                False,
            )
        except ArtifactError as error:
            assert "forbidden JVM/plugin linkage marker" in str(error)
        else:  # pragma: no cover
            raise AssertionError("forbidden JVM linkage unexpectedly validated")

        # Exercise every declared target's binary naming and linkage policy;
        # target rows must not silently inherit a host-specific policy.
        for target in SUPPORTED_TARGETS:
            assert _binary_name(target) == (
                "jmeter-rs.exe" if "windows" in target else "jmeter-rs"
            )
            assert _linkage_kind(target) in {"elf-dt-needed", "macho-otool", "pe-imports"}

        # Validate the positive platform-library fixtures for the remaining
        # declared OS families as well as Linux/glibc.
        for target in sorted(SUPPORTED_TARGETS - {"x86_64-unknown-linux-gnu"}):
            archive_format = "zip" if "windows" in target else "tar.gz"
            suffix = ".zip" if archive_format == "zip" else ".tar.gz"
            allowed_archive = root / f"allowed-{target}{suffix}"
            _create_test_archive(allowed_archive, target, archive_format=archive_format)
            evidence = _create_test_evidence(
                root,
                allowed_archive,
                target,
                execution_evidence="cross-compile-only" if "musl" in target else "native-runtime",
                static_expected="musl" in target,
            )
            _archive, _raw, _archive_root, records = validate_archive(allowed_archive, target)
            _validate_linkage_evidence(
                evidence[2],
                target,
                str(records[_binary_name(target)]["sha256"]),
                "musl" in target,
            )

        try:
            build_manifest(
                archive_path=root / "native.tar.gz",
                target="x86_64-unknown-linux-gnu",
                source_commit="0" * 40,
                dirty_tree="clean",
                profile_sha256="b" * 64,
                rust_toolchain="1.97.1",
                rustc_version="rustc 1.97.1",
                cargo_lock_sha256="a" * 64,
                host_target="aarch64-unknown-linux-gnu",
                execution_evidence="native-runtime",
                runner_os="Linux",
                runner_arch="ARM64",
                source_date_epoch="1700000000",
                static_expected=False,
            )
        except ArtifactError:
            pass
        else:  # pragma: no cover
            raise AssertionError("cross target was accepted as native runtime evidence")

        bad_path = root / "bad.zip"
        _create_test_archive(bad_path, "x86_64-unknown-linux-gnu", archive_format="zip")
        # Append an unexpected Java artifact to a fresh archive and assert the
        # exact-inventory check fails before any extraction is attempted.
        with zipfile.ZipFile(bad_path, "a", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("jmeter-rs-x86_64-unknown-linux-gnu/lib/worker.jar", b"jar")
        try:
            validate_archive(bad_path, "x86_64-unknown-linux-gnu")
        except ArtifactError:
            pass
        else:  # pragma: no cover - assertion message is the useful failure
            raise AssertionError("malformed archive unexpectedly validated")

        traversal_path = root / "traversal.zip"
        with zipfile.ZipFile(traversal_path, "w") as archive:
            for name in (
                "jmeter-rs-x86_64-unknown-linux-gnu/jmeter-rs",
                "jmeter-rs-x86_64-unknown-linux-gnu/LICENSE",
                "jmeter-rs-x86_64-unknown-linux-gnu/NOTICE",
                "jmeter-rs-x86_64-unknown-linux-gnu/README.md",
                "jmeter-rs-x86_64-unknown-linux-gnu/docs/architecture.md",
                "jmeter-rs-x86_64-unknown-linux-gnu/docs/../evil.txt",
            ):
                archive.writestr(name, b"x")
        try:
            validate_archive(traversal_path, "x86_64-unknown-linux-gnu")
        except ArtifactError:
            pass
        else:  # pragma: no cover
            raise AssertionError("traversal archive unexpectedly validated")

        try:
            _create_test_archive(root / "windows.zip", "x86_64-pc-windows-msvc", archive_format="zip")
            build_manifest(
                archive_path=root / "windows.zip",
                target="x86_64-pc-windows-msvc",
                source_commit="0" * 40,
                dirty_tree="dirty",
                profile_sha256="b" * 64,
                rust_toolchain="1.97.1",
                rustc_version="rustc 1.97.1",
                cargo_lock_sha256="a" * 64,
                host_target="x86_64-pc-windows-msvc",
                execution_evidence="native-runtime",
                runner_os="Windows",
                runner_arch="X64",
                source_date_epoch="1700000000",
                static_expected=False,
            )
        except ArtifactError:
            pass
        else:  # pragma: no cover
            raise AssertionError("dirty provenance unexpectedly validated")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", nargs="?", type=Path)
    parser.add_argument("--target")
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--source-commit")
    parser.add_argument("--dirty-tree")
    parser.add_argument("--profile-sha256")
    parser.add_argument("--rust-toolchain")
    parser.add_argument("--rustc-version")
    parser.add_argument("--cargo-lock-sha256")
    parser.add_argument("--host-target")
    parser.add_argument(
        "--execution-evidence",
        choices=("native-runtime", "cross-compile-only"),
    )
    parser.add_argument("--runner-os")
    parser.add_argument("--runner-arch")
    parser.add_argument("--source-date-epoch")
    parser.add_argument("--static-expected", action="store_true")
    parser.add_argument("--cargo-metadata", type=Path)
    parser.add_argument("--cargo-tree", type=Path)
    parser.add_argument("--linkage-evidence", type=Path)
    parser.add_argument("--runtime-evidence", type=Path)
    parser.add_argument("--self-test", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    if arguments.self_test:
        self_test()
        print("standalone artifact self-tests passed")
        return 0
    if arguments.archive is None or not arguments.target:
        raise ArtifactError("archive and --target are required")
    if arguments.manifest is None:
        validate_archive(arguments.archive, arguments.target)
        print(f"validated {arguments.archive}")
        return 0
    manifest = build_manifest(
        archive_path=arguments.archive,
        target=arguments.target,
        source_commit=arguments.source_commit,
        dirty_tree=arguments.dirty_tree,
        profile_sha256=arguments.profile_sha256,
        rust_toolchain=arguments.rust_toolchain,
        rustc_version=arguments.rustc_version,
        cargo_lock_sha256=arguments.cargo_lock_sha256,
        host_target=arguments.host_target,
        execution_evidence=arguments.execution_evidence,
        runner_os=arguments.runner_os,
        runner_arch=arguments.runner_arch,
        source_date_epoch=arguments.source_date_epoch,
        static_expected=arguments.static_expected,
        cargo_metadata_path=arguments.cargo_metadata,
        cargo_tree_path=arguments.cargo_tree,
        linkage_evidence_path=arguments.linkage_evidence,
        runtime_evidence_path=arguments.runtime_evidence,
    )
    _write_manifest(arguments.manifest, manifest)
    print(f"validated {arguments.archive}; wrote {arguments.manifest}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ArtifactError as error:
        print(f"standalone artifact rejected: {error}", file=sys.stderr)
        raise SystemExit(2) from error
