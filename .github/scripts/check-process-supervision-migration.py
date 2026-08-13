#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed static audit for the ADR-0001 subprocess callers.

This audit deliberately runs before any process-group test.  It checks every
Cargo dependency table (including target-specific tables) and every Rust file
under the three subprocess-owning callers.  Rust comments and literals are
masked before token checks so documentation and diagnostic strings do not
create false positives.  The caller-local process owner must disappear before
the ignored namespace tests can be enabled.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[2]
APPROVED_BACKEND = ROOT / "crates/process-supervision"
CALLERS = {
    ROOT / "crates/java-bridge": "../process-supervision",
    ROOT / "crates/plugin-host": "../process-supervision",
    ROOT / "tools/jmeter-oracle": "../../crates/process-supervision",
}
SHARED_NAME = "jmeter-rs-process-supervision"
# These are direct crates that expose process ownership, signal, wait, or raw
# handle APIs.  A transitive dependency is not enough to trigger this check;
# caller manifests must not name one of these packages directly.
PROCESS_DEPENDENCIES = frozenset(
    {
        "command-group",
        "ctrlc",
        "daemonize",
        "duct",
        "fork",
        "libc",
        "nix",
        "os_pipe",
        "portable-pty",
        "procfs",
        "process-wrap",
        "rustix",
        "signal-hook",
        "signal-hook-registry",
        "subprocess",
        "sysinfo",
        "wait-timeout",
        "windows",
        "windows-sys",
        "winapi",
    }
)

# The caller scan is intentionally conservative.  Comments and literals are
# masked before these expressions run, so prose and fixture strings do not
# create process-owner findings.
PROCESS_TOKENS = {
    "Command API": re.compile(r"\b(?:std::process::)?Command\b"),
    "Child API": re.compile(r"\b(?:std::process::)?Child(?:Stdin|Stdout|Stderr)?\b"),
    "process_group": re.compile(r"\bprocess_group\b"),
    "getpgid": re.compile(r"\bgetpgid\b"),
    "killpg": re.compile(r"\bkillpg\b"),
    "process ownership API": re.compile(
        r"\b(?:getpgrp|getsid|setpgid|setsid|kill_process|kill_process_group)\b"
    ),
    "raw PID type": re.compile(r"\b(?:Pid|Pgid|ProcessId|ProcessGroupId)\b"),
    "raw handle type": re.compile(
        r"\b(?:HANDLE|RawFd|RawHandle|BorrowedFd|BorrowedHandle|OwnedFd|OwnedHandle|"
        r"AsRawFd|AsRawHandle|AsRawSocket|FromRawFd|FromRawHandle|IntoRawFd|"
        r"IntoRawHandle|IntoRawSocket)\b"
    ),
    "raw handle API": re.compile(
        r"\b(?:as_raw_fd|as_raw_handle|as_raw_socket|from_raw_fd|from_raw_handle|"
        r"into_raw_fd|into_raw_handle|into_raw_socket)\b"
    ),
    "process creation hook": re.compile(
        r"\b(?:pre_exec|process_group|creation_flags|CreateProcessW|Toolhelp32)\b"
    ),
    "reap API": re.compile(r"\b(?:try_wait|waitpid|waitid|wait4)\b|\.\s*wait\s*\("),
    "signal API": re.compile(
        r"\b(?:killpg|sigaction|raise|Signal::[A-Za-z_][A-Za-z0-9_]*)\b"
        r"|\b(?:signal|kill)\s*\("
    ),
    # A direct child kill is still caller-owned termination.  The shared
    # supervisor is the only owner of both tree and exact-child escalation.
    "direct child kill": re.compile(r"\.\s*kill\s*\("),
}

RAW_PROCESS_IMPORT = re.compile(
    r"\b(?:libc|nix|rustix|windows_sys|winapi)::|"
    r"\b(?:use|extern\s+crate)\s+(?:libc|nix|rustix|windows_sys|winapi)\b|"
    r"\buse\s+std::os::(?:unix|windows)::process(?:::|::\{)|"
    r"\buse\s+std::process::id\b"
)
RAW_PROCESS_API = re.compile(
    r"\b(?:libc::(?:kill|wait|waitpid|waitid|setpgid|setsid)|"
    r"(?:nix|rustix)::(?:process|signal|unistd|sys::signal)|"
    r"(?:kill|killpg|getpgid|getpgrp|getsid|wait|wait3|wait4|waitpid|waitid|"
    r"setpgid|setsid|sigaction|raise|kill_process|kill_process_group)|"
    r"std::process::id)\b"
)

EXTERNAL_PROGRAM_NAMES = r"(?:kill|pkill|killall|taskkill|setsid)"
EXTERNAL_KILL = re.compile(
    r"\b(?:Command|process::Command|std::process::Command)\s*::\s*new\s*"
    rf"\(\s*([\"'])(?:[^\"']*/)?{EXTERNAL_PROGRAM_NAMES}\1",
    re.IGNORECASE,
)
EXTERNAL_KILL_VARIABLE = re.compile(
    r"\b(?:Command|process::Command|std::process::Command)\s*::\s*new\s*"
    rf"\(\s*&?(?:{EXTERNAL_PROGRAM_NAMES})(?:_path|_utility|_command)?\b",
    re.IGNORECASE,
)
EXTERNAL_KILL_ARG = re.compile(
    rf"\.(?:arg|args)\s*\(\s*([\"'])(?:[^\"']*/)?{EXTERNAL_PROGRAM_NAMES}\1",
    re.IGNORECASE,
)
HISTORICAL_KILL = re.compile(
    rf"\b{EXTERNAL_PROGRAM_NAMES}\s+[-–]?KILL\s+[-–]?1\b", re.IGNORECASE
)

# Numeric process/group identifiers must never be converted into command
# strings.  The format rules intentionally match both `format!("-{}", pid)`
# and captured identifiers (`format!("-{pid}")`).
NEGATIVE_IDENTIFIER_FORMAT = re.compile(
    r"\b(?:format|format_args)!\s*\(\s*([\"'])-\s*"
    r"(?:\{\s*[A-Za-z_][A-Za-z0-9_]*\s*\}|\{\})\1[^\n)]*\)",
)
NEGATIVE_LITERAL_FORMAT = re.compile(
    r"\b(?:format|format_args|concat)!\s*\(\s*([\"'])-\s*(?:[01]|\{[^}]*\})\1",
)
NEGATIVE_STRING_CONCAT = re.compile(
    r"(?:[\"']-\s*[\"']|[\"']-\s*\.\s*(?:to_owned|to_string)\s*\(\s*\))"
    r"[^\n;]*(?:pid|pgid|process_group|group|leader|target|id)\b",
    re.IGNORECASE,
)
NEGATIVE_FORMAT_CONCAT = re.compile(
    r"\b(?:format|format_args|concat)!\s*\([^\n;]*[\"']-\s*[\"']"
    r"[^\n;]*(?:pid|pgid|process_group|group|leader|target|id)\b",
    re.IGNORECASE,
)
RESERVED_ARGUMENT = re.compile(
    r"\.(?:arg|args)\s*\([^\n;]*(?:[\"']-?[01][\"']|(?<![A-Za-z0-9_])-?[01](?![A-Za-z0-9_]))",
)
RESERVED_PROCESS_TARGET = re.compile(
    r"\b(?:kill|killpg|getpgid|Pid::from_raw|Pgid::from_raw|waitpid|waitid)\s*\("
    r"[^\n;]*(?:[\"']-?[01][\"']|(?<![A-Za-z0-9_])-?[01](?![A-Za-z0-9_]))",
)

PUBLIC_PROCESS_API = re.compile(
    r"\b(?:Command|Child|Pid|Pgid|ProcessId|ProcessGroupId|"
    r"RawFd|RawHandle|BorrowedFd|BorrowedHandle|OwnedFd|OwnedHandle|HANDLE|"
    r"AsRawFd|AsRawHandle|AsRawSocket|FromRawFd|FromRawHandle|IntoRawFd|"
    r"IntoRawHandle|IntoRawSocket|JobObject|ProcessHandle|"
    r"as[_]?raw[_]?(?:fd|handle|socket)|from[_]?raw[_]?(?:fd|handle)|"
    r"into[_]?raw[_]?(?:fd|handle|socket))\b|"
    r"\b(?:pid|pgid|process[_]?id|process[_]?group[_]?id|child[_]?id|"
    r"process_group|raw[_]?fd|raw[_]?handle|handle)\b",
    re.IGNORECASE,
)
PUBLIC_DECLARATION = re.compile(
    r"\bpub(?:\s*\([^)]*\))?\s+(?:async\s+)?"
    r"(?:fn|struct|enum|type|trait|static|const|use|mod)\b"
)
PUBLIC_FIELD = re.compile(
    r"\bpub(?:\s*\([^)]*\))?\s+[A-Za-z_][A-Za-z0-9_]*\s*:\s*"
    r"(?:[^\n;{}]|\n){0,180}\b(?:Command|Child|Pid|Pgid|ProcessId|ProcessGroupId|"
    r"RawFd|RawHandle|BorrowedFd|BorrowedHandle|OwnedFd|OwnedHandle|HANDLE|"
    r"AsRawFd|AsRawHandle|AsRawSocket|FromRawFd|FromRawHandle|IntoRawFd|"
    r"IntoRawHandle|IntoRawSocket|"
    r"JobObject|ProcessHandle)\b",
    re.IGNORECASE,
)
PUBLIC_FIELD_NAME = re.compile(
    r"\bpub(?:\s*\([^)]*\))?\s+"
    r"(?:pid|pgid|process[_]?id|process[_]?group[_]?id|child[_]?id|"
    r"raw[_]?fd|raw[_]?handle|handle|as[_]?raw[_]?(?:fd|handle|socket))\s*:",
    re.IGNORECASE,
)

ALLOW_TEST_FIXTURE = re.compile(
    r"process-supervision-audit:\s*allow-test-fixture\s+reason=(?P<reason>[A-Za-z0-9_.-]+)"
)
ALLOWED_TEST_REASONS = frozenset({"inert-command-literal", "reserved-id-validation"})


def dependency_tables(value: object, path: tuple[str, ...] = ()):
    """Yield all top-level and target-specific Cargo dependency tables."""

    if not isinstance(value, dict):
        return
    if path and path[-1].endswith("dependencies"):
        yield value
    for key, child in value.items():
        if isinstance(child, dict):
            yield from dependency_tables(child, (*path, str(key)))


def _manifest_dependency_entries(manifest: dict) -> Iterable[tuple[str, object]]:
    """Yield dependency key/package pairs from every dependency table."""

    for table in dependency_tables(manifest):
        for name, dependency in table.items():
            yield str(name), dependency


def _dependency_package(name: str, dependency: object) -> str:
    if isinstance(dependency, dict):
        package = dependency.get("package")
        if isinstance(package, str) and package:
            return package
    return name


def mask_rust(source: str) -> str:
    """Mask comments and literals while retaining line/column positions."""

    output = list(source)
    length = len(source)
    index = 0
    block_depth = 0
    state = "normal"
    raw_hashes = 0

    def blank(position: int) -> None:
        if output[position] not in "\r\n":
            output[position] = " "

    while index < length:
        current = source[index]
        following = source[index + 1] if index + 1 < length else ""

        if state == "line-comment":
            if current == "\n":
                state = "normal"
            else:
                blank(index)
            index += 1
            continue

        if state == "block-comment":
            if current == "/" and following == "*":
                blank(index)
                blank(index + 1)
                block_depth += 1
                index += 2
            elif current == "*" and following == "/":
                blank(index)
                blank(index + 1)
                block_depth -= 1
                index += 2
                if block_depth == 0:
                    state = "normal"
            else:
                blank(index)
                index += 1
            continue

        if state == "string":
            blank(index)
            if current == "\\":
                if index + 1 < length:
                    blank(index + 1)
                    index += 2
                else:
                    index += 1
            elif current == '"':
                state = "normal"
                index += 1
            else:
                index += 1
            continue

        if state == "raw-string":
            blank(index)
            close = '"' + ("#" * raw_hashes)
            if source.startswith(close, index):
                for offset in range(len(close)):
                    blank(index + offset)
                index += len(close)
                state = "normal"
            else:
                index += 1
            continue

        if state == "char":
            blank(index)
            if current == "\\":
                if index + 1 < length:
                    blank(index + 1)
                    index += 2
                else:
                    index += 1
            elif current == "'":
                state = "normal"
                index += 1
            else:
                index += 1
            continue

        # Normal Rust source.
        if current == "/" and following == "/":
            blank(index)
            blank(index + 1)
            state = "line-comment"
            index += 2
        elif current == "/" and following == "*":
            blank(index)
            blank(index + 1)
            state = "block-comment"
            block_depth = 1
            index += 2
        elif current == "r":
            match = re.match(r"r(#+)?\"", source[index:])
            if match:
                raw_hashes = len(match.group(1) or "")
                for offset in range(len(match.group(0))):
                    blank(index + offset)
                state = "raw-string"
                index += len(match.group(0))
            else:
                index += 1
        elif current == '"':
            blank(index)
            state = "string"
            index += 1
        elif current == "'" and _looks_like_char_literal(source, index):
            blank(index)
            state = "char"
            index += 1
        else:
            index += 1

    return "".join(output)


def mask_rust_comments(source: str) -> str:
    """Mask Rust comments while retaining string literals and code.

    This second lexical view is used only for command-name and target-string
    rules.  A plain substring scan would treat a doc comment or a diagnostic
    sentence as an executable command; retaining literals lets the checker
    inspect an argument while the state machine still ignores comment text.
    """

    output = list(source)
    length = len(source)
    index = 0
    block_depth = 0
    state = "normal"
    raw_hashes = 0

    def blank(position: int) -> None:
        if output[position] not in "\r\n":
            output[position] = " "

    while index < length:
        current = source[index]
        following = source[index + 1] if index + 1 < length else ""

        if state == "line-comment":
            if current == "\n":
                state = "normal"
            else:
                blank(index)
            index += 1
            continue

        if state == "block-comment":
            if current == "/" and following == "*":
                blank(index)
                blank(index + 1)
                block_depth += 1
                index += 2
            elif current == "*" and following == "/":
                blank(index)
                blank(index + 1)
                block_depth -= 1
                index += 2
                if block_depth == 0:
                    state = "normal"
            else:
                blank(index)
                index += 1
            continue

        if state == "string":
            if current == "\\":
                index += 2 if index + 1 < length else 1
            elif current == '"':
                state = "normal"
                index += 1
            else:
                index += 1
            continue

        if state == "raw-string":
            close = '"' + ("#" * raw_hashes)
            if source.startswith(close, index):
                index += len(close)
                state = "normal"
            else:
                index += 1
            continue

        if state == "char":
            if current == "\\":
                index += 2 if index + 1 < length else 1
            elif current == "'":
                state = "normal"
                index += 1
            else:
                index += 1
            continue

        if current == "/" and following == "/":
            blank(index)
            blank(index + 1)
            state = "line-comment"
            index += 2
        elif current == "/" and following == "*":
            blank(index)
            blank(index + 1)
            state = "block-comment"
            block_depth = 1
            index += 2
        elif current == "r":
            match = re.match(r"r(#+)?\"", source[index:])
            if match:
                raw_hashes = len(match.group(1) or "")
                state = "raw-string"
                index += len(match.group(0))
            else:
                index += 1
        elif current == '"':
            state = "string"
            index += 1
        elif current == "'" and _looks_like_char_literal(source, index):
            state = "char"
            index += 1
        else:
            index += 1

    return "".join(output)


def rust_string_spans(source: str) -> list[tuple[int, int]]:
    """Return Rust string-literal spans, excluding comments and chars.

    Command names and numeric targets necessarily occur in literals, so the
    command-specific rules use a second lexical pass.  Knowing whether a
    match starts inside a literal keeps an incident report or a doc example
    inert without weakening checks for an actual ``Command::new``/``arg``
    expression.
    """

    spans: list[tuple[int, int]] = []
    length = len(source)
    index = 0

    while index < length:
        current = source[index]
        following = source[index + 1] if index + 1 < length else ""

        if current == "/" and following == "/":
            newline = source.find("\n", index + 2)
            index = length if newline < 0 else newline
            continue
        if current == "/" and following == "*":
            index += 2
            depth = 1
            while index < length and depth:
                if source.startswith("/*", index):
                    depth += 1
                    index += 2
                elif source.startswith("*/", index):
                    depth -= 1
                    index += 2
                else:
                    index += 1
            continue

        if current == "r":
            raw = re.match(r"r(#+)?\"", source[index:])
            if raw:
                hashes = len(raw.group(1) or "")
                start = index
                index += len(raw.group(0))
                close = '"' + ("#" * hashes)
                end = source.find(close, index)
                index = length if end < 0 else end + len(close)
                spans.append((start, index))
                continue

        if current == '"':
            start = index
            index += 1
            while index < length:
                if source[index] == "\\":
                    index += 2 if index + 1 < length else 1
                elif source[index] == '"':
                    index += 1
                    break
                else:
                    index += 1
            spans.append((start, index))
            continue

        if current == "'" and _looks_like_char_literal(source, index):
            index += 1
            while index < length:
                if source[index] == "\\":
                    index += 2 if index + 1 < length else 1
                elif source[index] == "'":
                    index += 1
                    break
                else:
                    index += 1
            continue

        index += 1

    return spans


def _literal_span_at(spans: Iterable[tuple[int, int]], offset: int) -> tuple[int, int] | None:
    for start, end in spans:
        if start <= offset < end:
            return start, end
    return None


def _looks_like_char_literal(source: str, index: int) -> bool:
    """Distinguish a character literal from a lifetime such as ``'a``."""

    end = index + 1
    escaped = False
    while end < len(source) and end - index <= 8:
        character = source[end]
        if not escaped and character == "'":
            return True
        if character == "\\" and not escaped:
            escaped = True
        else:
            escaped = False
        if character in "\r\n":
            return False
        end += 1
    return False


def source_line(source: str, offset: int) -> tuple[int, str]:
    line = source.count("\n", 0, offset) + 1
    start = source.rfind("\n", 0, offset) + 1
    end = source.find("\n", offset)
    if end < 0:
        end = len(source)
    return line, source[start:end].strip()


def display_path(path: Path) -> str:
    """Render repository paths compactly while supporting isolated probes."""

    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def audit_manifest_text(
    display: str, manifest_text: str, expected_path: str
) -> list[str]:
    """Audit one manifest from text without invoking Cargo or any process."""

    try:
        manifest = tomllib.loads(manifest_text)
    except tomllib.TOMLDecodeError as error:
        return [f"{display}: cannot parse Cargo.toml: {error}"]

    shared_entries: list[object] = []
    direct_process_dependencies: list[tuple[str, str]] = []
    for name, dependency in _manifest_dependency_entries(manifest):
        package = _dependency_package(name, dependency)
        if package == SHARED_NAME:
            shared_entries.append(dependency)
        if package in PROCESS_DEPENDENCIES:
            direct_process_dependencies.append((name, package))

    failures: list[str] = []
    if len(shared_entries) != 1:
        failures.append(f"{display}: requires exactly one shared path dependency")
    elif (
        not isinstance(shared_entries[0], dict)
        or shared_entries[0].get("path") != expected_path
        or shared_entries[0].get("git") is not None
        or shared_entries[0].get("registry") is not None
    ):
        failures.append(
            f"{display}: shared dependency must use exact path {expected_path!r}"
        )

    for name, package in direct_process_dependencies:
        failures.append(
            f"{display}: direct process dependency {name!r} resolves to forbidden package {package!r}"
        )
    return failures


def audit_manifest(manifest_path: Path, expected_path: str, failures: list[str]) -> None:
    try:
        manifest_text = manifest_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        failures.append(f"{display_path(manifest_path)}: cannot read Cargo.toml: {error}")
        return
    failures.extend(
        audit_manifest_text(display_path(manifest_path), manifest_text, expected_path)
    )


def _is_approved_backend(path: Path) -> bool:
    try:
        path.resolve().relative_to(APPROVED_BACKEND.resolve())
        return True
    except ValueError:
        return False


def _test_allow_lines(source: str, path: Path) -> tuple[set[int], list[str]]:
    """Return explicitly allowlisted fixture lines and marker errors.

    A marker is accepted only in a test file or a ``cfg(test)`` module, must
    name a narrow reason, and applies to the next non-empty source line only.
    This keeps test validation fixtures usable without creating a production
    escape hatch for process ownership rules.
    """

    is_test = "tests" in path.parts or "#[cfg(test)]" in source
    allowed: set[int] = set()
    failures: list[str] = []
    lines = source.splitlines()
    for index, line in enumerate(lines):
        marker = ALLOW_TEST_FIXTURE.search(line)
        if marker is None:
            continue
        reason = marker.group("reason")
        if not is_test:
            failures.append(
                f"{display_path(path)}:{index + 1}: test-fixture allowlist is outside tests"
            )
            continue
        if reason not in ALLOWED_TEST_REASONS:
            failures.append(
                f"{display_path(path)}:{index + 1}: unknown test-fixture allowlist reason {reason!r}"
            )
            continue
        allowed.add(index + 1)
        for next_index in range(index + 1, len(lines)):
            if lines[next_index].strip() and not lines[next_index].lstrip().startswith("//"):
                allowed.add(next_index + 1)
                break
    return allowed, failures


def _line_allowed(line: int, allowed_lines: set[int]) -> bool:
    return line in allowed_lines


def _public_declaration_spans(masked: str) -> Iterable[tuple[int, str]]:
    """Yield bounded public declaration snippets with their source offsets."""

    for declaration in PUBLIC_DECLARATION.finditer(masked):
        end = declaration.end()
        # A public signature may wrap over a few lines.  Stop at the first
        # body/semicolon and cap the scan to avoid crossing unrelated items.
        terminator = re.search(r"[;{]", masked[end : end + 512])
        if terminator is not None:
            end += terminator.start()
        else:
            end = min(len(masked), end + 512)
        yield declaration.start(), masked[declaration.start() : end]


def audit_source_text(path: Path, source: str, failures: list[str]) -> None:
    """Audit one Rust source text with comment/string-aware process rules."""

    if _is_approved_backend(path):
        return

    masked = mask_rust(source)
    code_with_literals = mask_rust_comments(source)
    string_spans = rust_string_spans(source)
    allowed_lines, allowlist_failures = _test_allow_lines(source, path)
    failures.extend(allowlist_failures)
    seen: set[tuple[str, int, str]] = set()

    def report(name: str, offset: int) -> None:
        line, text = source_line(source, offset)
        if _line_allowed(line, allowed_lines):
            return
        key = (display_path(path), line, name)
        if key in seen:
            return
        seen.add(key)
        failures.append(
            f"{display_path(path)}:{line}: {name} process owner remains: {text}"
        )

    for name, pattern in PROCESS_TOKENS.items():
        for match in pattern.finditer(masked):
            report(name, match.start())

    for name, pattern in (
        ("raw process dependency/import", RAW_PROCESS_IMPORT),
        ("raw signal/reap/process API", RAW_PROCESS_API),
    ):
        for match in pattern.finditer(masked):
            report(name, match.start())

    for name, pattern in (
        ("external kill utility", EXTERNAL_KILL),
        ("external kill utility variable", EXTERNAL_KILL_VARIABLE),
        ("external kill utility argument", EXTERNAL_KILL_ARG),
        ("historical kill -KILL -1 pattern", HISTORICAL_KILL),
        ("negative PID/PGID format", NEGATIVE_IDENTIFIER_FORMAT),
        ("reserved PID/PGID format", NEGATIVE_LITERAL_FORMAT),
        ("negative PID/PGID concatenation", NEGATIVE_STRING_CONCAT),
        ("negative PID/PGID format concatenation", NEGATIVE_FORMAT_CONCAT),
        ("reserved process argument", RESERVED_ARGUMENT),
        ("reserved process target", RESERVED_PROCESS_TARGET),
    ):
        for match in pattern.finditer(code_with_literals):
            literal_span = _literal_span_at(string_spans, match.start())
            if literal_span is not None and pattern is not HISTORICAL_KILL:
                # The only command-specific rule that legitimately starts
                # inside a literal is the historical shell command check. A
                # ``"-".to_owned()`` expression is still executable code;
                # permit that narrow concatenation shape below.
                if pattern is not NEGATIVE_STRING_CONCAT:
                    continue
                literal_end = literal_span[1]
                if not re.match(r"\s*\.\s*(?:to_owned|to_string)\s*\(", source[literal_end:]):
                    continue
            if pattern is HISTORICAL_KILL:
                context_start = max(0, match.start() - 240)
                context_end = min(len(masked), match.end() + 240)
                context = masked[context_start:context_end]
                if not re.search(
                    r"\b(?:Command|system|exec|sh|bash|dash)\b|\.\s*args?\s*\(",
                    context,
                ):
                    continue
            report(name, match.start())

    for offset, declaration in _public_declaration_spans(masked):
        if PUBLIC_PROCESS_API.search(declaration):
            report("public process/handle API", offset)
    for match in PUBLIC_FIELD.finditer(masked):
        report("public process/handle field", match.start())
    for match in PUBLIC_FIELD_NAME.finditer(masked):
        report("public process/handle field", match.start())


def audit_sources(caller: Path, failures: list[str]) -> None:
    if _is_approved_backend(caller):
        return
    source_paths = sorted(
        path
        for path in caller.rglob("*.rs")
        if path.is_file() and not {"target", ".git"}.intersection(path.parts)
    )
    if not source_paths:
        failures.append(f"{display_path(caller)}: no Rust sources found for audit")
        return
    for path in source_paths:
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            failures.append(f"{display_path(path)}: cannot read source: {error}")
            continue
        audit_source_text(path, source, failures)


def _fixture_failures(source: str, name: str = "tests/fixture.rs") -> list[str]:
    failures: list[str] = []
    audit_source_text(ROOT / name, source, failures)
    return failures


def self_test() -> int:
    """Run pure in-memory checker regression fixtures.

    This function intentionally performs no filesystem, Cargo, subprocess,
    signal, JVM, or network operation.  It protects the scanner itself from
    becoming a permissive substring check while documenting the historical
    dangerous command shape.
    """

    inert_docs_and_literals = r'''
// kill -KILL -1 in an incident report must remain documentation.
const MESSAGE: &str = "kill -KILL -1";
const SNIPPET: &str = r#"Command::new("/usr/bin/kill").arg("-1");"#;
#[cfg(test)]
mod tests {
    // process-supervision-audit: allow-test-fixture reason=reserved-id-validation
    fn validate_reserved_ids() {
        assert!(ValidatedProcessGroup::try_from(-1_i64).is_err());
        assert!(ValidatedProcessGroup::try_from(0_i64).is_err());
        assert!(ValidatedProcessGroup::try_from(1_i64).is_err());
    }
}
'''
    assert not _fixture_failures(inert_docs_and_literals), _fixture_failures(
        inert_docs_and_literals
    )

    historical_kill = r'''
use std::process::Command;
fn cleanup(pid: u32) {
    let _ = Command::new("/usr/bin/kill")
        .arg("-KILL")
        .arg(format!("-{pid}"))
        .status();
}
fn incident_shape() {
    let _ = std::process::Command::new("sh")
        .arg("-c")
        .arg("kill -KILL -1");
}
'''
    historical_failures = _fixture_failures(historical_kill)
    assert any("external kill utility" in failure for failure in historical_failures)
    assert any("negative PID/PGID format" in failure for failure in historical_failures)
    assert any(
        "historical kill -KILL -1 pattern" in failure for failure in historical_failures
    )

    for source in (
        'let _ = Command::new(worker).arg(format!("-{}", pid));',
        'let _ = Command::new(worker).arg(format!("-{pgid}"));',
        'let _ = Command::new(worker).arg("-1");',
        'let _ = killpg(Pid::from_raw(1), Signal::SIGKILL);',
        'let _ = format!("-{}", process_group);',
        'let _ = format!("{}{}", "-", pgid);',
    ):
        assert _fixture_failures(source), source

    for utility in ("kill", "pkill", "killall", "taskkill", "setsid"):
        source = f'let _ = Command::new("/usr/bin/{utility}");'
        utility_failures = _fixture_failures(source)
        assert any("external kill utility" in failure for failure in utility_failures), utility

    raw_api = r'''
use libc::kill;
use nix::sys::signal::killpg;
use rustix::process::waitid;
fn dangerous() { let _ = kill(1, 9); }
'''
    raw_failures = _fixture_failures(raw_api)
    assert any("raw process dependency/import" in failure for failure in raw_failures)
    assert any("raw signal/reap/process API" in failure for failure in raw_failures)
    backend_failures: list[str] = []
    audit_source_text(APPROVED_BACKEND / "src/lib.rs", raw_api, backend_failures)
    assert not backend_failures, backend_failures

    public_api = r'''
pub fn child() -> std::process::Child { unreachable!() }
pub struct Leaked {
    pub pid: u32,
    pub handle: RawHandle,
}
pub struct NumericLeak {
    pub process_id: u32,
}
pub fn as_raw_fd() -> i32 { 0 }
'''
    public_failures = _fixture_failures(public_api)
    assert any("public process/handle API" in failure for failure in public_failures)
    assert any("public process/handle field" in failure for failure in public_failures)

    valid_manifest = """
[dependencies]
jmeter-rs-process-supervision = { path = "../process-supervision" }
serde = { version = "1.0", default-features = false }
"""
    assert not audit_manifest_text(
        "self-test/Cargo.toml", valid_manifest, "../process-supervision"
    )
    for package in ("nix", "rustix", "libc", "windows-sys"):
        invalid_manifest = f"""
[dependencies]
supervisor = {{ package = \"{SHARED_NAME}\", path = \"../process-supervision\" }}
process_api = {{ package = \"{package}\", version = \"1.0\" }}
"""
        failures = audit_manifest_text(
            "self-test/Cargo.toml", invalid_manifest, "../process-supervision"
        )
        assert any("direct process dependency" in failure for failure in failures), package

    print("process-supervision migration checker self-tests passed")
    return 0


def main() -> int:
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    if sys.argv[1:]:
        print(
            "usage: check-process-supervision-migration.py [--self-test]",
            file=sys.stderr,
        )
        return 2
    failures: list[str] = []
    for caller, expected_path in CALLERS.items():
        manifest_path = caller / "Cargo.toml"
        if not manifest_path.is_file():
            failures.append(f"{manifest_path.relative_to(ROOT)}: manifest is missing")
            continue
        audit_manifest(manifest_path, expected_path, failures)
        # One recursive walk covers src/, tests/, examples/, and bins while
        # allowing a caller (such as the oracle) to have shell-only tests.
        audit_sources(caller, failures)

    if failures:
        print("ADR-0001 process-supervision migration is incomplete (fail-closed):", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 78
    print("ADR-0001 process-supervision caller audit passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
