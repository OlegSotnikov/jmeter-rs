#!/usr/bin/env python3
"""Plan and validate performance runs without starting a process or service.

This module intentionally has no subprocess, socket, or container-runtime
integration.  ``dry-run`` only reads JSON and declared fixture metadata and
prints a deterministic plan.  A future execution adapter must be added behind
an explicit capability; it must not be hidden behind this parser.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable, NoReturn


SCHEMA_ID = "jmeter-rs.perf-config"
SCHEMA_VERSION = 3
RESULT_SCHEMA_ID = "jmeter-rs.perf-result"
RESULT_SCHEMA_VERSION = 3
FUTURE_EVIDENCE_SCHEMA_ID = "jmeter-rs.perf-evidence"
FUTURE_EVIDENCE_SCHEMA_VERSION = 1
COLLECTED_EVIDENCE_SCHEMA_ID = "jmeter-rs.perf-collected-evidence"
COLLECTED_EVIDENCE_SCHEMA_VERSION = 2
FIXTURE_CATALOG_SCHEMA_ID = "jmeter-rs.perf-fixture-catalog"
FIXTURE_CATALOG_SCHEMA_VERSION = 1
PROFILE_ID = "jmeter-5.6.3"
REPO_ROOT = Path(__file__).resolve().parents[2]
PERF_ROOT = Path(__file__).resolve().parent
CONFIG_ROOT = PERF_ROOT / "configs"
PROFILE_PATH = REPO_ROOT / "compat" / "profiles" / "jmeter-5.6.3.json"
PROFILE_ROOT = REPO_ROOT / "compat" / "profiles"
FIXTURE_ROOT = REPO_ROOT / "compat" / "fixtures"
SCHEMA_ROOT = PERF_ROOT / "schema"
FIXTURE_CATALOG_PATH = PERF_ROOT / "fixture-catalog.json"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
ID = re.compile(r"^[a-z0-9][a-z0-9-]{2,63}$")
METRIC_ID = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
METRIC_PATH = re.compile(r"^[a-z][a-z0-9_.]{2,95}$")
ABSOLUTE_EXECUTABLE = re.compile(r"^/[A-Za-z0-9._/@:+,-]{1,255}$")
PINNED_IMAGE_REFERENCE = re.compile(r"^[A-Za-z0-9._:/-]{1,190}@sha256:[0-9a-f]{64}$")
TARGET_TRIPLE = re.compile(r"^[A-Za-z0-9._-]{3,80}$")

# These are parser/resource limits, not workload recommendations.  They keep
# malformed or extension-heavy JSON bounded before semantic validation runs.
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 200_000
MAX_JSON_STRING_CHARS = 8_192
MAX_JSON_LIST_ITEMS = 100_000
MAX_JSON_OBJECT_KEYS = 512
MAX_JSON_INTEGER_DIGITS = 128
MAX_CONFIG_EXTENSIONS_KEYS = 64
MAX_CONFIG_EXTENSIONS_BYTES = 256 * 1024
MAX_PARAMETER_KEYS = 64
MAX_PARAMETER_BYTES = 128 * 1024
MAX_ID_LIST_ITEMS = 64
MAX_CHILDREN = 16
MAX_CONTAINERS = 16
MAX_ARGS = 32
MAX_ARG_CHARS = 1_024
MAX_ARG_BYTES = 8 * 1_024
MAX_ENVIRONMENT_KEYS = 64
MAX_STRING_CHARS = 4_096
MAX_FIXTURE_PATH_CHARS = 256
MAX_ARTIFACT_ROOT_CHARS = 256
MAX_RESULT_FILENAME_CHARS = 128
MAX_VIRTUAL_USERS = 1_000_000
MAX_ITERATIONS = 10_000_000
MAX_DURATION_SECONDS = 86_400
MAX_INTERVAL_SECONDS = 86_400
MAX_SAMPLE_COUNT = 10_000_000
MAX_RESULT_BYTES = 100_000_000
MAX_TIMEOUT_MS = 86_400_000
MAX_OUTPUT_BYTES = 100_000_000
MAX_HASH_BYTES = 64 * 1024 * 1024
MAX_PLATFORM_TARGETS = 6
MAX_FIXTURE_CATALOG_ENTRIES = 64
MAX_CASE_MANIFEST_BYTES = 512 * 1024
MAX_THRESHOLD_VALUE = 1_000_000_000_000_000
METRIC_UNITS = {"count", "nanoseconds", "bytes", "operations-per-second"}
EVIDENCE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{2,127}$")


class ConfigError(ValueError):
    """A configuration is malformed, unsafe, or inconsistent."""


def fail(message: str) -> NoReturn:
    raise ConfigError(message)


def canonical_json(value: Any) -> str:
    """Return the stable JSON representation used for config identity."""

    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def require_reference_digest(reference: str, digest: str, context: str) -> None:
    """Validate a hash of a textual reference, never an artifact digest.

    Reference hashes make a future path/image/tool spelling reproducible.  They
    are intentionally separate from ``*_artifact_digest_sha256`` fields,
    which may only be populated by a future collector after hashing immutable
    bytes.
    """

    if not isinstance(reference, str) or not isinstance(digest, str):
        fail(f"{context} reference and digest must be strings")
    reject_surrogates(reference, f"{context} reference")
    reject_surrogates(digest, f"{context} digest")
    expected = sha256_bytes(reference.encode("utf-8"))
    require_equal(digest, expected, f"{context} reference digest")


def sha256_file(path: Path, context: str = "file", maximum: int = MAX_HASH_BYTES) -> str:
    """Hash a bounded regular file without reading an unbounded input."""

    if maximum < 1 or maximum > MAX_HASH_BYTES:
        fail(f"{context} requests a hash limit outside the approved byte cap")
    try:
        size = path.stat().st_size
    except OSError as error:
        fail(f"cannot stat {context} {path}: {error}")
    if size > maximum:
        fail(f"{context} exceeds the {maximum}-byte hash limit")
    digest = hashlib.sha256()
    consumed = 0
    try:
        with path.open("rb") as source:
            while True:
                block = source.read(min(1024 * 1024, maximum - consumed + 1))
                if not block:
                    break
                consumed += len(block)
                if consumed > maximum:
                    fail(f"{context} exceeds the {maximum}-byte hash limit")
                digest.update(block)
    except OSError as error:
        fail(f"cannot hash {context} {path}: {error}")
    if consumed != size:
        fail(f"{context} changed while it was being hashed")
    return digest.hexdigest()


def _parse_json_int(token: str) -> int:
    digits = token.lstrip("-")
    if len(digits) > MAX_JSON_INTEGER_DIGITS:
        fail(f"JSON integer exceeds the {MAX_JSON_INTEGER_DIGITS}-digit limit")
    try:
        return int(token)
    except ValueError as error:
        fail(f"invalid JSON integer: {error}")


def _parse_json_float(token: str) -> float:
    try:
        value = float(token)
    except ValueError as error:
        fail(f"invalid JSON number: {error}")
    if not math.isfinite(value):
        fail(f"non-finite JSON number is forbidden: {token}")
    return value


def _preflight_json_text(text: str, context: str) -> None:
    """Reject depth/structure bombs before ``json.loads`` allocates values."""

    depth = 0
    maximum_depth = 0
    structural_nodes = 0
    in_string = False
    escaped = False
    raw_string_length = 0
    for character in text:
        if in_string:
            if escaped:
                escaped = False
                raw_string_length += 1
            elif character == "\\":
                escaped = True
                raw_string_length += 1
            elif character == '"':
                in_string = False
                if raw_string_length > MAX_JSON_STRING_CHARS * 6 + 2:
                    fail(f"{context} string token exceeds the preflight bound")
            else:
                raw_string_length += 1
            continue
        if character == '"':
            in_string = True
            raw_string_length = 0
        elif character in "[{":
            depth += 1
            maximum_depth = max(maximum_depth, depth)
            structural_nodes += 1
            if maximum_depth > MAX_JSON_DEPTH:
                fail(f"{context} exceeds JSON depth limit {MAX_JSON_DEPTH}")
        elif character in "}]":
            depth = max(0, depth - 1)
        elif character in ",:":
            structural_nodes += 1
        if structural_nodes > MAX_JSON_NODES:
            fail(f"{context} exceeds the {MAX_JSON_NODES}-node JSON limit")


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ConfigError(f"duplicate JSON object key: {key!r}")
        value[key] = item
    return value


def _reject_nonfinite(token: str) -> NoReturn:
    raise ConfigError(f"non-finite JSON number is forbidden: {token}")


def reject_surrogates(value: str, context: str) -> None:
    """Reject escaped UTF-16 surrogate code points before any byte encoding."""

    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        fail(f"{context} contains an unpaired Unicode surrogate")


def _bound_json(value: Any, context: str, depth: int = 0, nodes: list[int] | None = None) -> None:
    """Apply global bounds to every value produced by the JSON parser."""

    if nodes is None:
        nodes = [0]
    nodes[0] += 1
    if nodes[0] > MAX_JSON_NODES:
        fail(f"{context} exceeds the {MAX_JSON_NODES}-node JSON limit")
    if depth > MAX_JSON_DEPTH:
        fail(f"{context} exceeds JSON depth limit {MAX_JSON_DEPTH}")
    if isinstance(value, str):
        reject_surrogates(value, context)
        if len(value) > MAX_JSON_STRING_CHARS:
            fail(f"{context} string exceeds {MAX_JSON_STRING_CHARS} characters")
        return
    if isinstance(value, dict):
        if len(value) > MAX_JSON_OBJECT_KEYS:
            fail(f"{context} has more than {MAX_JSON_OBJECT_KEYS} object keys")
        for key, item in value.items():
            reject_surrogates(key, f"{context} object key")
            if len(key) > MAX_JSON_STRING_CHARS:
                fail(f"{context} object key exceeds {MAX_JSON_STRING_CHARS} characters")
            _bound_json(item, f"{context}.{key}", depth + 1, nodes)
        return
    if isinstance(value, list):
        if len(value) > MAX_JSON_LIST_ITEMS:
            fail(f"{context} has more than {MAX_JSON_LIST_ITEMS} list items")
        for index, item in enumerate(value):
            _bound_json(item, f"{context}[{index}]", depth + 1, nodes)
        return
    if isinstance(value, float) and not math.isfinite(value):
        fail(f"{context} contains a non-finite number")


def parse_json_bytes(raw: bytes, context: str) -> Any:
    if len(raw) > MAX_JSON_BYTES:
        fail(f"{context} exceeds the {MAX_JSON_BYTES}-byte JSON limit")
    try:
        text = raw.decode("utf-8")
        _preflight_json_text(text, context)
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_nonfinite,
            parse_int=_parse_json_int,
            parse_float=_parse_json_float,
        )
    except ConfigError:
        raise
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        fail(f"cannot parse JSON {context}: {error}")
    _bound_json(value, context)
    return value


def read_json(path: Path, root: Path, context: str, max_bytes: int = MAX_JSON_BYTES) -> dict[str, Any]:
    canonical = safe_existing_file(path, root, context)
    if max_bytes > MAX_JSON_BYTES:
        fail(f"{context} requests an unapproved JSON bound")
    try:
        size = canonical.stat().st_size
        if size > max_bytes:
            fail(f"{context} exceeds the {max_bytes}-byte JSON limit")
        with canonical.open("rb") as source:
            raw = source.read(max_bytes + 1)
    except OSError as error:
        fail(f"cannot read JSON {canonical}: {error}")
    if len(raw) > max_bytes:
        fail(f"{context} exceeds the {max_bytes}-byte JSON limit")
    value = parse_json_bytes(raw, context)
    if not isinstance(value, dict):
        fail(f"JSON root must be an object: {context}")
    return value


def _path_relative_to(path: Path, root: Path, context: str) -> tuple[Path, Path]:
    """Return lexical and canonical paths after containment checks.

    The harness rejects symlink components rather than merely resolving them;
    that avoids a configuration changing its input/output target underneath a
    future execution adapter.
    """

    if root.is_symlink():
        fail(f"{context} root must not be a symlink: {root}")
    try:
        canonical_root = root.resolve(strict=True)
    except OSError as error:
        fail(f"{context} root is unavailable: {error}")
    candidate = path if path.is_absolute() else Path.cwd() / path
    candidate = candidate.absolute()
    try:
        relative = candidate.relative_to(canonical_root)
    except ValueError:
        fail(f"{context} escapes canonical root {canonical_root}: {candidate}")
    current = canonical_root
    for part in relative.parts:
        current /= part
        if os.path.lexists(current) and current.is_symlink():
            fail(f"{context} contains a symlink component: {current}")
    return candidate, canonical_root


def safe_existing_file(path: Path, root: Path, context: str) -> Path:
    candidate, canonical_root = _path_relative_to(path, root, context)
    try:
        canonical = candidate.resolve(strict=True)
    except OSError as error:
        fail(f"{context} does not resolve: {candidate}: {error}")
    try:
        canonical.relative_to(canonical_root)
    except ValueError:
        fail(f"{context} resolves outside canonical root: {candidate}")
    if not canonical.is_file():
        fail(f"{context} must be a regular file: {candidate}")
    return canonical


def safe_artifact_root(relative: str) -> Path:
    """Resolve a configured artifact root inside this performance tool."""

    if Path(relative).is_absolute() or ".." in Path(relative).parts:
        fail("artifacts.root must be relative and cannot contain '..'")
    if "\x00" in relative:
        fail("artifacts.root contains a NUL byte")
    candidate = PERF_ROOT / relative
    # Artifact output is deliberately confined to tools/perf, never the
    # repository root or a caller-selected absolute directory.
    return _safe_missing_path(candidate, PERF_ROOT, "artifacts.root")


def _safe_missing_path(path: Path, root: Path, context: str) -> Path:
    """Resolve a possibly-new path while rejecting symlink components."""

    if root.is_symlink():
        fail(f"{context} root must not be a symlink: {root}")
    try:
        canonical_root = root.resolve(strict=True)
    except OSError as error:
        fail(f"{context} root is unavailable: {error}")
    candidate = path if path.is_absolute() else Path.cwd() / path
    candidate = candidate.absolute()
    try:
        relative = candidate.relative_to(canonical_root)
    except ValueError:
        fail(f"{context} escapes canonical root {canonical_root}: {candidate}")
    current = canonical_root
    for part in relative.parts:
        current /= part
        if os.path.lexists(current) and current.is_symlink():
            fail(f"{context} contains a symlink component: {current}")
    # resolve(strict=False) still canonicalizes existing parents, so check the
    # resulting path once more for a symlink race or an escaping parent.
    resolved = candidate.resolve(strict=False)
    try:
        resolved.relative_to(canonical_root)
    except ValueError:
        fail(f"{context} resolves outside canonical root: {candidate}")
    return resolved


_SCHEMA_CONTRACTS: set[tuple[str, int]] | None = None
_FIXTURE_CATALOG: dict[str, dict[str, Any]] | None = None


def ensure_schema_contracts() -> None:
    """Bind the implementation to the checked-in schema identifiers."""

    global _SCHEMA_CONTRACTS
    if _SCHEMA_CONTRACTS is not None:
        return
    expected = {
        "config.schema.json": (SCHEMA_ID, SCHEMA_VERSION),
        "result.schema.json": (RESULT_SCHEMA_ID, RESULT_SCHEMA_VERSION),
        "future-evidence.schema.json": (
            FUTURE_EVIDENCE_SCHEMA_ID,
            FUTURE_EVIDENCE_SCHEMA_VERSION,
        ),
        "collected-evidence.schema.json": (
            COLLECTED_EVIDENCE_SCHEMA_ID,
            COLLECTED_EVIDENCE_SCHEMA_VERSION,
        ),
        "fixture-catalog.schema.json": (
            FIXTURE_CATALOG_SCHEMA_ID,
            FIXTURE_CATALOG_SCHEMA_VERSION,
        ),
    }
    contracts: set[tuple[str, int]] = set()
    for filename, (schema_id, version) in expected.items():
        document = read_json(SCHEMA_ROOT / filename, SCHEMA_ROOT, f"schema {filename}")
        require_equal(document.get("x-schema-id"), schema_id, f"schema {filename}.x-schema-id")
        require_equal(
            document.get("x-schema-version"),
            version,
            f"schema {filename}.x-schema-version",
        )
        contracts.add((schema_id, version))
    _SCHEMA_CONTRACTS = contracts


def load_fixture_catalog() -> dict[str, dict[str, Any]]:
    """Load and integrity-check the performance fixture/case binding catalog."""

    global _FIXTURE_CATALOG
    if _FIXTURE_CATALOG is not None:
        return _FIXTURE_CATALOG
    ensure_schema_contracts()
    document = read_json(FIXTURE_CATALOG_PATH, PERF_ROOT, "performance fixture catalog")
    require_keys(document, ("schema_id", "schema_version", "fixtures"), "fixture catalog")
    forbid_extra(document, ("schema_id", "schema_version", "fixtures"), "fixture catalog")
    require_equal(document["schema_id"], FIXTURE_CATALOG_SCHEMA_ID, "fixture catalog.schema_id")
    require_equal(
        document["schema_version"], FIXTURE_CATALOG_SCHEMA_VERSION, "fixture catalog.schema_version"
    )
    entries = require_list(
        document["fixtures"],
        "fixture catalog.fixtures",
        minimum=1,
        maximum=MAX_FIXTURE_CATALOG_ENTRIES,
    )
    catalog: dict[str, dict[str, Any]] = {}
    for index, entry in enumerate(entries):
        context = f"fixture catalog.fixtures[{index}]"
        if not isinstance(entry, dict):
            fail(f"{context} must be an object")
        keys = (
            "id",
            "profile_id",
            "fixture_family_id",
            "source_path",
            "source_sha256",
            "case_manifest_path",
            "case_id",
        )
        require_keys(entry, keys, context)
        forbid_extra(entry, keys, context)
        fixture_id = require_string(entry["id"], f"{context}.id", re.compile(r"^FX-[A-Z0-9-]+$"), 64)
        if fixture_id in catalog:
            fail(f"fixture catalog contains duplicate id {fixture_id!r}")
        require_equal(entry["profile_id"], PROFILE_ID, f"{context}.profile_id")
        family_id = require_string(
            entry["fixture_family_id"], f"{context}.fixture_family_id", re.compile(r"^FX-[A-Z0-9-]+$"), 64
        )
        source_path = require_string(entry["source_path"], f"{context}.source_path", maximum=MAX_FIXTURE_PATH_CHARS)
        case_path = require_string(
            entry["case_manifest_path"], f"{context}.case_manifest_path", maximum=MAX_FIXTURE_PATH_CHARS
        )
        if not source_path.startswith("compat/fixtures/") or Path(source_path).is_absolute() or ".." in Path(source_path).parts:
            fail(f"{context}.source_path must stay under compat/fixtures")
        if not case_path.startswith("compat/fixtures/") or Path(case_path).is_absolute() or ".." in Path(case_path).parts:
            fail(f"{context}.case_manifest_path must stay under compat/fixtures")
        require_hex_digest(entry["source_sha256"], f"{context}.source_sha256")
        case_id = require_string(entry["case_id"], f"{context}.case_id", re.compile(r"^ORACLE-[A-Z0-9-]+$"), 128)
        source = safe_existing_file(REPO_ROOT / source_path, FIXTURE_ROOT, f"{context}.source_path")
        actual_source_hash = sha256_file(source, f"{context}.source_path")
        require_equal(actual_source_hash, entry["source_sha256"], f"{context}.source_sha256")
        case_manifest = safe_existing_file(
            REPO_ROOT / case_path, FIXTURE_ROOT, f"{context}.case_manifest_path"
        )
        case = read_json(case_manifest, FIXTURE_ROOT, f"{context}.case_manifest_path", MAX_CASE_MANIFEST_BYTES)
        require_equal(case.get("schema_id"), "jmeter-rs.oracle-case", f"{context}.case.schema_id")
        require_equal(case.get("schema_version"), 1, f"{context}.case.schema_version")
        require_equal(case.get("case_id"), case_id, f"{context}.case.case_id")
        require_equal(case.get("profile_id"), PROFILE_ID, f"{context}.case.profile_id")
        require_equal(case.get("fixture_family_id"), family_id, f"{context}.case.fixture_family_id")
        if not isinstance(case.get("execution"), dict):
            fail(f"{context}.case.execution must be an object")
        plan = case.get("plan")
        if plan is not None and not isinstance(plan, dict):
            fail(f"{context}.case.plan must be an object or null")
        if isinstance(plan, dict) and ("path" in plan or "sha256" in plan):
            require_keys(plan, ("path", "sha256"), f"{context}.case.plan")
            plan_relative = require_string(
                plan["path"], f"{context}.case.plan.path", maximum=MAX_FIXTURE_PATH_CHARS
            )
            if Path(plan_relative).is_absolute() or ".." in Path(plan_relative).parts:
                fail(f"{context}.case.plan.path must stay within compat/fixtures")
            require_hex_digest(plan["sha256"], f"{context}.case.plan.sha256")
            plan_path = safe_existing_file(
                case_manifest.parent / plan_relative, FIXTURE_ROOT, f"{context}.case.plan"
            )
            if plan_path == source:
                require_equal(plan.get("sha256"), entry["source_sha256"], f"{context}.case.plan.sha256")
        catalog[fixture_id] = {
            **entry,
            "source": source,
            "case_manifest": case_manifest,
            "case": case,
        }
    _FIXTURE_CATALOG = catalog
    return catalog


def require_keys(value: dict[str, Any], keys: Iterable[str], context: str) -> None:
    if not isinstance(value, dict):
        fail(f"{context} must be an object")
    missing = sorted(set(keys) - set(value))
    if missing:
        fail(f"{context} is missing required keys: {', '.join(missing)}")


def forbid_extra(value: dict[str, Any], allowed: Iterable[str], context: str) -> None:
    if not isinstance(value, dict):
        fail(f"{context} must be an object")
    extra = sorted(set(value) - set(allowed))
    if extra:
        fail(f"{context} contains unsupported keys: {', '.join(extra)}")


def require_equal(value: Any, expected: Any, context: str) -> None:
    if value != expected:
        fail(f"{context} must be {expected!r}, got {value!r}")


def require_string(
    value: Any,
    context: str,
    pattern: re.Pattern[str] | None = None,
    maximum: int = MAX_STRING_CHARS,
) -> str:
    if not isinstance(value, str) or not value:
        fail(f"{context} must be a non-empty string")
    reject_surrogates(value, context)
    if "\x00" in value:
        fail(f"{context} contains a NUL byte")
    if len(value) > maximum:
        fail(f"{context} exceeds the {maximum}-character limit")
    if pattern is not None and pattern.fullmatch(value) is None:
        fail(f"{context} has an invalid value: {value!r}")
    return value


def require_hex_digest(value: Any, context: str) -> str:
    """Validate a lowercase SHA-256 without allowing regex type errors."""

    return require_string(value, context, HEX64, maximum=64)


def require_bool(value: Any, context: str) -> bool:
    if not isinstance(value, bool):
        fail(f"{context} must be a boolean")
    return value


def require_number(
    value: Any,
    context: str,
    minimum: float | None = None,
    maximum: float | None = None,
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        fail(f"{context} must be a number")
    if isinstance(value, float) and not math.isfinite(value):
        fail(f"{context} must be finite")
    if minimum is not None and value < minimum:
        fail(f"{context} must be at least {minimum}")
    if maximum is not None and value > maximum:
        fail(f"{context} must be at most {maximum}")
    return float(value)


def require_integer(
    value: Any,
    context: str,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        fail(f"{context} must be an integer")
    if minimum is not None and value < minimum:
        fail(f"{context} must be at least {minimum}")
    if maximum is not None and value > maximum:
        fail(f"{context} must be at most {maximum}")
    return value


def require_list(
    value: Any,
    context: str,
    minimum: int = 0,
    maximum: int = MAX_JSON_LIST_ITEMS,
) -> list[Any]:
    if not isinstance(value, list) or len(value) < minimum:
        fail(f"{context} must be a list with at least {minimum} item(s)")
    if not isinstance(value, list):
        fail(f"{context} must be a list")
    if len(value) > maximum:
        fail(f"{context} has more than {maximum} item(s)")
    return value


def require_unique_ids(items: list[dict[str, Any]], context: str) -> None:
    if not all(isinstance(item, dict) for item in items):
        fail(f"{context} contains a non-object entry")
    ids = [item.get("id") for item in items]
    if any(not isinstance(item_id, str) for item_id in ids):
        fail(f"{context} contains an entry without a string id")
    if len(ids) != len(set(ids)):
        fail(f"{context} contains duplicate ids")


def validate_ownership(value: Any, context: str) -> None:
    if not isinstance(value, dict):
        fail(f"{context} must be an object")
    require_keys(
        value,
        ("identity", "pre_signal_check", "reap", "termination", "pid_validation"),
        context,
    )
    forbid_extra(
        value,
        ("identity", "pre_signal_check", "reap", "termination", "pid_validation"),
        context,
    )
    expected = {
        "identity": "owned-child-handle",
        "pre_signal_check": "try_wait-before-signal",
        "reap": "wait-exact-child-on-all-paths",
        "termination": "direct-child-only",
        "pid_validation": "live-child-pgid-greater-than-one",
    }
    for key, wanted in expected.items():
        require_equal(value.get(key), wanted, f"{context}.{key}")


def validate_subprocess_policy(value: Any) -> None:
    context = "execution.subprocess_policy"
    if not isinstance(value, dict):
        fail(f"{context} must be an object")
    keys = (
        "benchmark_processes",
        "service_processes",
        "shell",
        "network",
        "process_start",
        "group_signalling",
    )
    require_keys(value, keys, context)
    forbid_extra(value, keys, context)
    expected = {
        "benchmark_processes": "forbidden",
        "service_processes": "forbidden",
        "shell": False,
        "network": "offline",
        "process_start": "disabled",
        "group_signalling": "forbidden",
    }
    for key, wanted in expected.items():
        require_equal(value.get(key), wanted, f"{context}.{key}")


def validate_child(value: Any, index: int) -> None:
    context = f"execution.children[{index}]"
    if not isinstance(value, dict):
        fail(f"{context} must be an object")
    keys = (
        "id",
        "role",
        "enabled",
        "future_only",
        "executable",
        "executable_reference_sha256",
        "executable_artifact_digest_sha256",
        "artifact_status",
        "args",
        "max_arg_bytes",
        "max_output_bytes",
        "startup_timeout_ms",
        "operation_timeout_ms",
        "graceful_shutdown_timeout_ms",
        "deadline_policy",
        "shell",
        "working_directory",
        "environment",
        "ownership",
    )
    require_keys(value, keys, context)
    forbid_extra(value, keys, context)
    require_string(value["id"], f"{context}.id", ID)
    if value["role"] not in {"benchmark", "fixture-service", "measurement-helper"}:
        fail(f"{context}.role is unsupported")
    require_equal(value["enabled"], False, f"{context}.enabled")
    require_equal(value["future_only"], True, f"{context}.future_only")
    require_string(value["executable"], f"{context}.executable", ABSOLUTE_EXECUTABLE, 256)
    if ".." in Path(value["executable"]).parts:
        fail(f"{context}.executable must not contain parent traversal")
    require_hex_digest(value["executable_reference_sha256"], f"{context}.executable_reference_sha256")
    require_reference_digest(value["executable"], value["executable_reference_sha256"], context)
    artifact_digest = value["executable_artifact_digest_sha256"]
    if artifact_digest is not None:
        require_hex_digest(artifact_digest, f"{context}.executable_artifact_digest_sha256")
    require_equal(value["artifact_status"], "future-pinned-not-present", f"{context}.artifact_status")
    require_equal(artifact_digest, None, f"{context}.executable_artifact_digest_sha256")
    arguments = require_list(value["args"], f"{context}.args", maximum=MAX_ARGS)
    total_argument_bytes = 0
    for argument_index, argument in enumerate(arguments):
        require_string(argument, f"{context}.args[{argument_index}]", maximum=MAX_ARG_CHARS)
        total_argument_bytes += len(argument.encode("utf-8"))
    max_arg_bytes = require_integer(
        value["max_arg_bytes"], f"{context}.max_arg_bytes", minimum=1, maximum=MAX_ARG_BYTES
    )
    if total_argument_bytes > max_arg_bytes:
        fail(f"{context}.args exceed max_arg_bytes")
    require_integer(
        value["max_output_bytes"],
        f"{context}.max_output_bytes",
        minimum=1,
        maximum=MAX_OUTPUT_BYTES,
    )
    startup_timeout = require_integer(
        value["startup_timeout_ms"],
        f"{context}.startup_timeout_ms",
        minimum=1,
        maximum=MAX_TIMEOUT_MS,
    )
    operation_timeout = require_integer(
        value["operation_timeout_ms"],
        f"{context}.operation_timeout_ms",
        minimum=1,
        maximum=MAX_TIMEOUT_MS,
    )
    graceful_timeout = require_integer(
        value["graceful_shutdown_timeout_ms"],
        f"{context}.graceful_shutdown_timeout_ms",
        minimum=1,
        maximum=MAX_TIMEOUT_MS,
    )
    if startup_timeout > operation_timeout or graceful_timeout > operation_timeout:
        fail(f"{context} startup/graceful deadlines must not exceed operation_timeout_ms")
    require_equal(value["deadline_policy"], "bounded-monotonic", f"{context}.deadline_policy")
    require_equal(value["shell"], False, f"{context}.shell")
    require_equal(value["working_directory"], "ephemeral-run-root", f"{context}.working_directory")
    environment = value["environment"]
    if not isinstance(environment, dict):
        fail(f"{context}.environment must be an object")
    if len(environment) > MAX_ENVIRONMENT_KEYS:
        fail(f"{context}.environment has too many keys")
    if environment:
        fail(f"{context}.environment must be empty until execution is implemented")
    validate_ownership(value["ownership"], f"{context}.ownership")


def validate_container(value: Any, index: int) -> None:
    context = f"execution.containers[{index}]"
    if not isinstance(value, dict):
        fail(f"{context} must be an object")
    keys = (
        "id",
        "role",
        "enabled",
        "future_only",
        "runtime",
        "runtime_reference_sha256",
        "runtime_artifact_digest_sha256",
        "image_reference",
        "image_reference_sha256",
        "image_artifact_digest_sha256",
        "image_status",
        "create_args",
        "max_arg_bytes",
        "max_output_bytes",
        "startup_timeout_ms",
        "operation_timeout_ms",
        "graceful_shutdown_timeout_ms",
        "deadline_policy",
        "id_source",
        "cleanup",
        "selectors",
    )
    require_keys(value, keys, context)
    forbid_extra(value, keys, context)
    require_string(value["id"], f"{context}.id", ID)
    require_equal(value["role"], "fixture-service", f"{context}.role")
    require_equal(value["enabled"], False, f"{context}.enabled")
    require_equal(value["future_only"], True, f"{context}.future_only")
    require_string(value["runtime"], f"{context}.runtime", ABSOLUTE_EXECUTABLE, 256)
    if ".." in Path(value["runtime"]).parts:
        fail(f"{context}.runtime must not contain parent traversal")
    require_hex_digest(value["runtime_reference_sha256"], f"{context}.runtime_reference_sha256")
    require_reference_digest(value["runtime"], value["runtime_reference_sha256"], context)
    runtime_artifact_digest = value["runtime_artifact_digest_sha256"]
    if runtime_artifact_digest is not None:
        require_hex_digest(runtime_artifact_digest, f"{context}.runtime_artifact_digest_sha256")
    require_equal(runtime_artifact_digest, None, f"{context}.runtime_artifact_digest_sha256")
    require_string(value["image_reference"], f"{context}.image_reference", PINNED_IMAGE_REFERENCE, 256)
    require_hex_digest(value["image_reference_sha256"], f"{context}.image_reference_sha256")
    require_reference_digest(value["image_reference"], value["image_reference_sha256"], f"{context}.image")
    image_artifact_digest = value["image_artifact_digest_sha256"]
    if image_artifact_digest is not None:
        require_hex_digest(image_artifact_digest, f"{context}.image_artifact_digest_sha256")
    require_equal(value["image_status"], "future-pinned-not-present", f"{context}.image_status")
    require_equal(image_artifact_digest, None, f"{context}.image_artifact_digest_sha256")
    arguments = require_list(value["create_args"], f"{context}.create_args", maximum=MAX_ARGS)
    total_argument_bytes = 0
    for argument_index, argument in enumerate(arguments):
        require_string(argument, f"{context}.create_args[{argument_index}]", maximum=MAX_ARG_CHARS)
        total_argument_bytes += len(argument.encode("utf-8"))
    max_arg_bytes = require_integer(
        value["max_arg_bytes"], f"{context}.max_arg_bytes", minimum=1, maximum=MAX_ARG_BYTES
    )
    if total_argument_bytes > max_arg_bytes:
        fail(f"{context}.create_args exceed max_arg_bytes")
    require_integer(
        value["max_output_bytes"],
        f"{context}.max_output_bytes",
        minimum=1,
        maximum=MAX_OUTPUT_BYTES,
    )
    startup_timeout = require_integer(
        value["startup_timeout_ms"],
        f"{context}.startup_timeout_ms",
        minimum=1,
        maximum=MAX_TIMEOUT_MS,
    )
    operation_timeout = require_integer(
        value["operation_timeout_ms"],
        f"{context}.operation_timeout_ms",
        minimum=1,
        maximum=MAX_TIMEOUT_MS,
    )
    graceful_timeout = require_integer(
        value["graceful_shutdown_timeout_ms"],
        f"{context}.graceful_shutdown_timeout_ms",
        minimum=1,
        maximum=MAX_TIMEOUT_MS,
    )
    if startup_timeout > operation_timeout or graceful_timeout > operation_timeout:
        fail(f"{context} startup/graceful deadlines must not exceed operation_timeout_ms")
    require_equal(value["deadline_policy"], "bounded-monotonic", f"{context}.deadline_policy")
    require_equal(value["id_source"], "created-by-this-run", f"{context}.id_source")
    require_equal(value["cleanup"], "exact-created-id-only", f"{context}.cleanup")
    if value["selectors"] != []:
        fail(f"{context}.selectors must be empty; broad selectors can target unrelated containers")


def validate_execution(value: Any) -> None:
    context = "execution"
    if not isinstance(value, dict):
        fail(f"{context} must be an object")
    keys = ("mode", "subprocess_policy", "children", "containers")
    require_keys(value, keys, context)
    forbid_extra(value, keys, context)
    require_equal(value["mode"], "dry-run-only", f"{context}.mode")
    validate_subprocess_policy(value["subprocess_policy"])
    children = require_list(value["children"], f"{context}.children", minimum=1, maximum=MAX_CHILDREN)
    if not all(isinstance(item, dict) for item in children):
        fail(f"{context}.children entries must be objects")
    require_unique_ids(children, f"{context}.children")
    for index, child in enumerate(children):
        validate_child(child, index)
    containers = require_list(value["containers"], f"{context}.containers", maximum=MAX_CONTAINERS)
    if not all(isinstance(item, dict) for item in containers):
        fail(f"{context}.containers entries must be objects")
    require_unique_ids(containers, f"{context}.containers")
    for index, container in enumerate(containers):
        validate_container(container, index)


def validate_compatibility(
    value: Any, profile: dict[str, Any], fixture_catalog: dict[str, dict[str, Any]]
) -> None:
    context = "compatibility"
    if not isinstance(value, dict):
        fail(f"{context} must be an object")
    keys = ("profile_id", "feature_ids", "fixture_id", "fixture_ids", "normalization_policy_refs")
    require_keys(value, keys, context)
    forbid_extra(value, keys, context)
    require_equal(value["profile_id"], PROFILE_ID, f"{context}.profile_id")
    feature_ids = require_list(
        value["feature_ids"], f"{context}.feature_ids", minimum=1, maximum=MAX_ID_LIST_ITEMS
    )
    if len(feature_ids) != len(set(feature_ids)):
        fail(f"{context}.feature_ids contains duplicate ids")
    for feature_id in feature_ids:
        require_string(
            feature_id,
            f"{context}.feature_ids entry",
            re.compile(r"^[A-Z]+-[0-9]{3}$"),
            maximum=64,
        )
    fixture_ids = require_list(
        value["fixture_ids"], f"{context}.fixture_ids", minimum=1, maximum=MAX_ID_LIST_ITEMS
    )
    if len(fixture_ids) != len(set(fixture_ids)):
        fail(f"{context}.fixture_ids contains duplicates")
    for fixture_id in fixture_ids:
        require_string(fixture_id, f"{context}.fixture_ids entry", re.compile(r"^FX-[A-Z0-9-]+$"))
    require_string(value["fixture_id"], f"{context}.fixture_id", re.compile(r"^FX-[A-Z0-9-]+$"))
    if value["fixture_id"] not in fixture_ids:
        fail(f"{context}.fixture_id must be present in fixture_ids")
    policy_refs = require_list(
        value["normalization_policy_refs"],
        f"{context}.normalization_policy_refs",
        minimum=1,
        maximum=MAX_ID_LIST_ITEMS,
    )
    if len(policy_refs) != len(set(policy_refs)):
        fail(f"{context}.normalization_policy_refs contains duplicates")
    for policy_ref in policy_refs:
        require_string(
            policy_ref,
            f"{context}.normalization_policy_refs entry",
            re.compile(r"^NORM-[A-Z0-9-]+$"),
            maximum=64,
        )
    profile_features = {item.get("id") for item in profile.get("features", []) if isinstance(item, dict)}
    profile_fixtures = {item.get("id") for item in profile.get("oracle_fixture_catalog", []) if isinstance(item, dict)}
    profile_policies = {item.get("id") for item in profile.get("normalization_policies", []) if isinstance(item, dict)}
    if not set(feature_ids) <= profile_features:
        fail(f"{context}.feature_ids references an id absent from the profile")
    if not set(fixture_ids) <= profile_fixtures:
        fail(f"{context}.fixture_ids references an id absent from the profile")
    if not set(fixture_ids) <= fixture_catalog.keys():
        missing = sorted(set(fixture_ids) - fixture_catalog.keys())
        fail(f"{context}.fixture_ids is not bound to fixture/case manifests: {', '.join(missing)}")
    for fixture_id in fixture_ids:
        entry = fixture_catalog[fixture_id]
        require_equal(entry["profile_id"], value["profile_id"], f"{context}.{fixture_id}.profile_id")
        profile_entry = next(
            (item for item in profile.get("oracle_fixture_catalog", []) if isinstance(item, dict) and item.get("id") == fixture_id),
            None,
        )
        if profile_entry is not None and profile_entry.get("status") == "planned":
            # The catalog binds the planned profile family to an actual checked-in
            # case manifest; it does not upgrade the profile's materialization
            # status or claim that oracle output exists.
            require_equal(
                entry["case"].get("execution", {}).get("status")
                in {
                    "planned",
                    "not_run",
                    "not-run",
                    "not-run-static",
                    "not-run-static-only",
                    "not-run-static-corpus",
                    "external-raw-observation",
                },
                True,
                f"{context}.{fixture_id}.case.status",
            )
    if not set(policy_refs) <= profile_policies:
        fail(f"{context}.normalization_policy_refs references an id absent from the profile")
    for feature in profile.get("features", []):
        if not isinstance(feature, dict) or feature.get("id") not in feature_ids:
            continue
        required_fixtures = set(feature.get("required_oracle_fixture_ids", []))
        required_policies = set(feature.get("normalization_policy_refs", []))
        if not required_fixtures <= set(fixture_ids):
            fail(f"{context}.fixture_ids does not cover feature {feature['id']}")
        if not required_policies <= set(policy_refs):
            fail(f"{context}.normalization_policy_refs does not cover feature {feature['id']}")


def validate_reproducibility(value: Any) -> None:
    context = "reproducibility"
    if not isinstance(value, dict):
        fail(f"{context} must be an object")
    keys = (
        "seed",
        "locale",
        "timezone",
        "charset",
        "target_os",
        "target_arch",
        "target_triple",
        "os_image_id",
        "os_image_reference",
        "os_image_reference_sha256",
        "os_image_artifact_digest_sha256",
        "rust_toolchain",
        "rust_toolchain_sha256",
        "cargo_lock_sha256",
        "source_date_epoch",
        "environment_allowlist",
        "working_directory_policy",
        "clock_mode",
    )
    require_keys(value, keys, context)
    forbid_extra(value, keys, context)
    seed = require_integer(value["seed"], f"{context}.seed", minimum=0)
    if seed > 18446744073709551615:
        fail(f"{context}.seed must fit in an unsigned 64-bit value")
    require_equal(value["locale"], "en-US", f"{context}.locale")
    require_equal(value["timezone"], "UTC", f"{context}.timezone")
    require_equal(value["charset"], "UTF-8", f"{context}.charset")
    if value["target_os"] not in {"linux", "windows", "macos"}:
        fail(f"{context}.target_os is unsupported")
    require_string(value["target_arch"], f"{context}.target_arch", re.compile(r"^(x86_64|aarch64)$"), 32)
    require_string(value["target_triple"], f"{context}.target_triple", TARGET_TRIPLE, maximum=128)
    require_string(
        value["os_image_id"],
        f"{context}.os_image_id",
        re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:/-]{2,127}$"),
        maximum=128,
    )
    require_string(value["os_image_reference"], f"{context}.os_image_reference", PINNED_IMAGE_REFERENCE, 256)
    require_hex_digest(value["os_image_reference_sha256"], f"{context}.os_image_reference_sha256")
    require_reference_digest(value["os_image_reference"], value["os_image_reference_sha256"], context)
    os_image_artifact_digest = value["os_image_artifact_digest_sha256"]
    if os_image_artifact_digest is not None:
        require_hex_digest(os_image_artifact_digest, f"{context}.os_image_artifact_digest_sha256")
    require_equal(os_image_artifact_digest, None, f"{context}.os_image_artifact_digest_sha256")
    require_string(value["rust_toolchain"], f"{context}.rust_toolchain", maximum=128)
    toolchain = safe_existing_file(REPO_ROOT / value["rust_toolchain"], REPO_ROOT, f"{context}.rust_toolchain")
    require_hex_digest(value["rust_toolchain_sha256"], f"{context}.rust_toolchain_sha256")
    actual_toolchain_hash = sha256_file(toolchain, f"{context}.rust_toolchain")
    require_equal(actual_toolchain_hash, value["rust_toolchain_sha256"], f"{context}.rust_toolchain_sha256")
    require_hex_digest(value["cargo_lock_sha256"], f"{context}.cargo_lock_sha256")
    lockfile = safe_existing_file(REPO_ROOT / "Cargo.lock", REPO_ROOT, f"{context}.Cargo.lock")
    actual_lock_hash = sha256_file(lockfile, f"{context}.Cargo.lock")
    if actual_lock_hash != value["cargo_lock_sha256"]:
        fail(
            f"{context}.cargo_lock_sha256 mismatch: "
            f"declared {value['cargo_lock_sha256']}, actual {actual_lock_hash}"
        )
    require_integer(value["source_date_epoch"], f"{context}.source_date_epoch", minimum=0, maximum=4_102_444_800)
    allowlist = require_list(
        value["environment_allowlist"], f"{context}.environment_allowlist", maximum=MAX_ENVIRONMENT_KEYS
    )
    if allowlist:
        fail(f"{context}.environment_allowlist must be empty for an offline run")
    require_equal(value["working_directory_policy"], "ephemeral-run-root", f"{context}.working_directory_policy")
    if value["clock_mode"] not in {"controlled-fixture", "monotonic-only"}:
        fail(f"{context}.clock_mode is unsupported")


def validate_platform_matrix(value: Any, reproducibility: dict[str, Any]) -> None:
    context = "platform_matrix"
    targets = require_list(value, context, minimum=MAX_PLATFORM_TARGETS, maximum=MAX_PLATFORM_TARGETS)
    expected = {
        ("linux", "x86_64", "x86_64-unknown-linux-gnu"),
        ("linux", "aarch64", "aarch64-unknown-linux-gnu"),
        ("windows", "x86_64", "x86_64-pc-windows-msvc"),
        ("windows", "aarch64", "aarch64-pc-windows-msvc"),
        ("macos", "x86_64", "x86_64-apple-darwin"),
        ("macos", "aarch64", "aarch64-apple-darwin"),
    }
    seen: set[tuple[str, str, str]] = set()
    for index, target in enumerate(targets):
        item_context = f"{context}[{index}]"
        if not isinstance(target, dict):
            fail(f"{item_context} must be an object")
        keys = (
            "id",
            "target_os",
            "target_arch",
            "target_triple",
            "status",
            "os_image_reference",
            "os_image_reference_sha256",
            "os_image_artifact_digest_sha256",
            "evidence_id",
        )
        require_keys(target, keys, item_context)
        forbid_extra(target, keys, item_context)
        target_id = require_string(
            target["id"], f"{item_context}.id", re.compile(r"^[a-z0-9][a-z0-9_-]{2,63}$"), 64
        )
        require_equal(target_id, f"{target['target_os']}-{target['target_arch']}", f"{item_context}.id")
        target_os = require_string(target["target_os"], f"{item_context}.target_os", maximum=32)
        target_arch = require_string(target["target_arch"], f"{item_context}.target_arch", maximum=32)
        triple = require_string(target["target_triple"], f"{item_context}.target_triple", TARGET_TRIPLE, 80)
        identity = (target_os, target_arch, triple)
        if identity not in expected or identity in seen:
            fail(f"{item_context} is not a unique member of the six-target future matrix")
        seen.add(identity)
        require_equal(target["status"], "future-planned", f"{item_context}.status")
        require_string(
            target["os_image_reference"],
            f"{item_context}.os_image_reference",
            PINNED_IMAGE_REFERENCE,
            256,
        )
        require_hex_digest(target["os_image_reference_sha256"], f"{item_context}.os_image_reference_sha256")
        require_reference_digest(target["os_image_reference"], target["os_image_reference_sha256"], item_context)
        artifact_digest = target["os_image_artifact_digest_sha256"]
        if artifact_digest is not None:
            require_hex_digest(artifact_digest, f"{item_context}.os_image_artifact_digest_sha256")
        require_equal(artifact_digest, None, f"{item_context}.os_image_artifact_digest_sha256")
        require_equal(target["evidence_id"], None, f"{item_context}.evidence_id")
    if seen != expected:
        fail(f"{context} must enumerate exactly the six declared OS/architecture targets")
    selected = (reproducibility["target_os"], reproducibility["target_arch"], reproducibility["target_triple"])
    if selected not in seen:
        fail("reproducibility target is absent from platform_matrix")
    selected_target = next(
        target
        for target in targets
        if (
            target["target_os"],
            target["target_arch"],
            target["target_triple"],
        )
        == selected
    )
    require_equal(
        reproducibility["os_image_reference"],
        selected_target["os_image_reference"],
        "reproducibility.os_image_reference",
    )
    require_equal(
        reproducibility["os_image_reference_sha256"],
        selected_target["os_image_reference_sha256"],
        "reproducibility.os_image_reference_sha256",
    )


def validate_operation(value: Any, index: int) -> None:
    context = f"workload.operations[{index}]"
    if not isinstance(value, dict):
        fail(f"{context} must be an object")
    keys = ("id", "kind", "enabled", "parameters")
    require_keys(value, keys, context)
    forbid_extra(value, keys, context)
    require_string(value["id"], f"{context}.id", ID)
    if value["kind"] not in {
        "parse-jmx",
        "compile-plan",
        "execute-offline-fixture",
        "serialize-results",
        "aggregate-results",
        "scheduler-step",
    }:
        fail(f"{context}.kind is not an offline operation")
    require_equal(value["enabled"], True, f"{context}.enabled")
    if not isinstance(value["parameters"], dict):
        fail(f"{context}.parameters must be an object")
    if len(value["parameters"]) > MAX_PARAMETER_KEYS:
        fail(f"{context}.parameters has more than {MAX_PARAMETER_KEYS} keys")
    _bound_json(value["parameters"], f"{context}.parameters")
    if len(canonical_json(value["parameters"]).encode("utf-8")) > MAX_PARAMETER_BYTES:
        fail(f"{context}.parameters exceeds {MAX_PARAMETER_BYTES} encoded bytes")


def validate_workload(
    value: Any,
    config_kind: str,
    primary_fixture_id: str,
    fixture_catalog: dict[str, dict[str, Any]],
) -> None:
    context = "workload"
    if not isinstance(value, dict):
        fail(f"{context} must be an object")
    keys = (
        "scenario_id",
        "case_id",
        "case_manifest_path",
        "fixture_family_id",
        "fixture_path",
        "fixture_sha256",
        "operations",
        "virtual_users",
        "iterations",
        "duration_seconds",
        "warmup_seconds",
        "ramp_up_seconds",
        "target_rate_per_second",
        "open_loop",
    )
    require_keys(value, keys, context)
    forbid_extra(value, keys, context)
    require_string(value["scenario_id"], f"{context}.scenario_id", ID)
    case_id = require_string(value["case_id"], f"{context}.case_id", re.compile(r"^ORACLE-[A-Z0-9-]+$"), 128)
    case_manifest_path = require_string(
        value["case_manifest_path"], f"{context}.case_manifest_path", maximum=MAX_FIXTURE_PATH_CHARS
    )
    if Path(case_manifest_path).is_absolute() or ".." in Path(case_manifest_path).parts:
        fail(f"{context}.case_manifest_path must stay within the fixture root")
    if not case_manifest_path.startswith("compat/fixtures/"):
        fail(f"{context}.case_manifest_path must stay under compat/fixtures")
    fixture_family_id = require_string(
        value["fixture_family_id"], f"{context}.fixture_family_id", re.compile(r"^FX-[A-Z0-9-]+$"), 64
    )
    fixture_path = require_string(value["fixture_path"], f"{context}.fixture_path", maximum=MAX_FIXTURE_PATH_CHARS)
    if Path(fixture_path).is_absolute() or ".." in Path(fixture_path).parts:
        fail(f"{context}.fixture_path must stay within the repository")
    if not fixture_path.startswith("compat/fixtures/"):
        fail(f"{context}.fixture_path must stay under compat/fixtures")
    require_hex_digest(value["fixture_sha256"], f"{context}.fixture_sha256")
    operations = require_list(value["operations"], f"{context}.operations", minimum=1, maximum=64)
    if not all(isinstance(item, dict) for item in operations):
        fail(f"{context}.operations entries must be objects")
    require_unique_ids(operations, f"{context}.operations")
    for index, operation in enumerate(operations):
        validate_operation(operation, index)
    iterations = value["iterations"]
    require_integer(
        value["virtual_users"], f"{context}.virtual_users", minimum=1, maximum=MAX_VIRTUAL_USERS
    )
    for key in ("iterations", "duration_seconds"):
        if value[key] is not None:
            maximum = MAX_ITERATIONS if key == "iterations" else MAX_DURATION_SECONDS
            require_integer(value[key], f"{context}.{key}", minimum=1, maximum=maximum)
    if (value["iterations"] is None) == (value["duration_seconds"] is None):
        fail(f"{context} must choose exactly one of iterations or duration_seconds")
    require_integer(
        value["warmup_seconds"], f"{context}.warmup_seconds", minimum=0, maximum=MAX_DURATION_SECONDS
    )
    require_integer(
        value["ramp_up_seconds"], f"{context}.ramp_up_seconds", minimum=0, maximum=MAX_DURATION_SECONDS
    )
    if value["target_rate_per_second"] is not None:
        require_number(
            value["target_rate_per_second"],
            f"{context}.target_rate_per_second",
            minimum=0,
            maximum=10_000_000,
        )
    require_bool(value["open_loop"], f"{context}.open_loop")
    if value["open_loop"] and value["target_rate_per_second"] is None:
        fail(f"{context}.open_loop requires target_rate_per_second")
    if not value["open_loop"] and value["target_rate_per_second"] == 0:
        fail(f"{context}.target_rate_per_second cannot be zero for a closed-loop workload")
    if config_kind == "micro" and value["duration_seconds"] is not None:
        fail("micro workload must be iteration-bounded")
    if config_kind == "macro" and value["duration_seconds"] is not None:
        fail("macro workload must be iteration-bounded")
    if config_kind == "soak":
        if value["duration_seconds"] not in {3600, 28800, 86400}:
            fail("soak duration_seconds must be exactly 3600, 28800, or 86400")
        if value["iterations"] is not None:
            fail("soak workload must be duration-bounded")
    if config_kind == "macro":
        execute_operations = [
            operation
            for operation in operations
            if operation.get("kind") == "execute-offline-fixture"
        ]
        if len(execute_operations) != 1:
            fail("macro workload must declare exactly one execute-offline-fixture operation")
        parameters = execute_operations[0]["parameters"]
        if "iterations_per_user" not in parameters:
            fail("macro execute-offline-fixture must declare iterations_per_user")
        iterations_per_user = require_integer(
            parameters["iterations_per_user"],
            "workload.operations.execute-offline-fixture.parameters.iterations_per_user",
            minimum=1,
            maximum=MAX_ITERATIONS,
        )
        if iterations is None or iterations_per_user != iterations:
            fail("macro iterations_per_user must equal workload.iterations")

    if primary_fixture_id not in fixture_catalog:
        fail(f"{context} primary fixture is absent from fixture catalog")
    entry = fixture_catalog[primary_fixture_id]
    require_equal(fixture_family_id, entry["fixture_family_id"], f"{context}.fixture_family_id")
    require_equal(fixture_path, entry["source_path"], f"{context}.fixture_path")
    require_equal(value["fixture_sha256"], entry["source_sha256"], f"{context}.fixture_sha256")
    require_equal(case_manifest_path, entry["case_manifest_path"], f"{context}.case_manifest_path")
    require_equal(case_id, entry["case_id"], f"{context}.case_id")
    fixture = safe_existing_file(REPO_ROOT / fixture_path, FIXTURE_ROOT, f"{context}.fixture_path")
    actual_hash = sha256_file(fixture, f"{context}.fixture_path")
    if actual_hash != value["fixture_sha256"]:
        fail(
            f"workload.fixture_sha256 mismatch for {fixture_path}: "
            f"declared {value['fixture_sha256']}, actual {actual_hash}"
        )


def validate_metric_list(value: Any, context: str) -> list[str]:
    values = require_list(value, context, minimum=1, maximum=64)
    if len(values) != len(set(values)):
        fail(f"{context} contains duplicate values")
    for index, metric in enumerate(values):
        require_string(metric, f"{context}[{index}]", METRIC_ID)
    return values


def validate_metrics(value: Any) -> None:
    context = "metrics"
    if not isinstance(value, dict):
        fail(f"{context} must be an object")
    keys = (
        "sample_interval_seconds",
        "warmup_samples",
        "histograms",
        "counters",
        "derived_metrics",
        "resource_metrics",
        "queue_policy",
        "max_samples",
    )
    require_keys(value, keys, context)
    forbid_extra(value, keys, context)
    require_integer(
        value["sample_interval_seconds"],
        f"{context}.sample_interval_seconds",
        minimum=1,
        maximum=MAX_INTERVAL_SECONDS,
    )
    require_integer(
        value["warmup_samples"],
        f"{context}.warmup_samples",
        minimum=0,
        maximum=MAX_SAMPLE_COUNT,
    )
    histograms = require_list(value["histograms"], f"{context}.histograms", minimum=1, maximum=64)
    histogram_ids: list[str] = []
    for index, histogram in enumerate(histograms):
        item_context = f"{context}.histograms[{index}]"
        if not isinstance(histogram, dict):
            fail(f"{item_context} must be an object")
        require_keys(histogram, ("id", "unit", "percentiles"), item_context)
        forbid_extra(histogram, ("id", "unit", "percentiles"), item_context)
        histogram_ids.append(require_string(histogram["id"], f"{item_context}.id", METRIC_ID))
        if histogram["unit"] not in {"nanoseconds", "bytes", "operations-per-second"}:
            fail(f"{item_context}.unit is unsupported")
        percentiles = require_list(
            histogram["percentiles"], f"{item_context}.percentiles", minimum=1, maximum=32
        )
        if len(percentiles) != len(set(percentiles)):
            fail(f"{item_context}.percentiles contains duplicates")
        for percentile in percentiles:
            require_number(
                percentile, f"{item_context}.percentiles entry", minimum=0, maximum=100
            )
    if len(histogram_ids) != len(set(histogram_ids)):
        fail(f"{context}.histograms contains duplicate ids")
    validate_metric_list(value["counters"], f"{context}.counters")
    derived = require_list(value["derived_metrics"], f"{context}.derived_metrics", maximum=64)
    derived_ids: list[str] = []
    for index, metric in enumerate(derived):
        item_context = f"{context}.derived_metrics[{index}]"
        if not isinstance(metric, dict):
            fail(f"{item_context} must be an object")
        require_keys(metric, ("id", "unit"), item_context)
        forbid_extra(metric, ("id", "unit"), item_context)
        derived_ids.append(require_string(metric["id"], f"{item_context}.id", METRIC_ID))
        if metric["unit"] not in METRIC_UNITS:
            fail(f"{item_context}.unit is unsupported")
    if len(derived_ids) != len(set(derived_ids)):
        fail(f"{context}.derived_metrics contains duplicate ids")
    histogram_by_id = {histogram["id"]: histogram for histogram in histograms}
    for derived in value["derived_metrics"]:
        derived_id = derived["id"]
        if derived_id.endswith("_p95") or derived_id.endswith("_p99"):
            suffix = "_p95" if derived_id.endswith("_p95") else "_p99"
            histogram_id = derived_id[: -len(suffix)]
            histogram = histogram_by_id.get(histogram_id)
            percentile = 95 if suffix == "_p95" else 99
            if histogram is None or percentile not in histogram["percentiles"]:
                fail(f"{context}.derived_metrics {derived_id!r} lacks histogram-backed p{percentile}")
    resources = require_list(value["resource_metrics"], f"{context}.resource_metrics", minimum=1, maximum=64)
    resource_ids: list[str] = []
    for index, resource in enumerate(resources):
        item_context = f"{context}.resource_metrics[{index}]"
        if not isinstance(resource, dict):
            fail(f"{item_context} must be an object")
        require_keys(resource, ("id", "source", "unit", "required"), item_context)
        forbid_extra(resource, ("id", "source", "unit", "required"), item_context)
        resource_ids.append(require_string(resource["id"], f"{item_context}.id", METRIC_ID))
        if resource["source"] not in {"owned-runner", "owned-child", "owned-container"}:
            fail(f"{item_context}.source is unsupported")
        if resource["unit"] not in {"bytes", "count", "nanoseconds"}:
            fail(f"{item_context}.unit is unsupported")
        require_bool(resource["required"], f"{item_context}.required")
    if len(resource_ids) != len(set(resource_ids)):
        fail(f"{context}.resource_metrics contains duplicate ids")
    require_equal(value["queue_policy"], "bounded-fail-on-overflow", f"{context}.queue_policy")
    require_integer(
        value["max_samples"],
        f"{context}.max_samples",
        minimum=1,
        maximum=MAX_SAMPLE_COUNT,
    )
    registry = metric_registry(value)
    required_resources = {
        resource["id"]
        for resource in resources
        if resource["required"]
    }
    if "cpu_time_ns" not in registry or registry["cpu_time_ns"] != "nanoseconds" or "cpu_time_ns" not in required_resources:
        fail(f"{context} must declare required cpu_time_ns metric")
    if "allocation_bytes" not in registry or registry["allocation_bytes"] != "bytes" or "allocation_bytes" not in required_resources:
        fail(f"{context} must declare required allocation_bytes metric")
    counters = set(value["counters"])
    if "results_dropped" not in counters:
        fail(f"{context}.counters must declare results_dropped")
    if "queue_overflows" not in counters:
        fail(f"{context}.counters must declare queue_overflows")
    if not any(counter.endswith("_failed") for counter in counters):
        fail(f"{context}.counters must declare a failure counter")


def metric_registry(metrics: dict[str, Any]) -> dict[str, str]:
    """Return metric->unit and reject ambiguous metric identities."""

    registry: dict[str, str] = {}
    for histogram in metrics["histograms"]:
        registry[histogram["id"]] = histogram["unit"]
    for counter in metrics["counters"]:
        if counter in registry:
            fail(f"metrics reuses metric id {counter!r}")
        registry[counter] = "count"
    for derived in metrics["derived_metrics"]:
        if derived["id"] in registry:
            fail(f"metrics reuses metric id {derived['id']!r}")
        registry[derived["id"]] = derived["unit"]
    for resource in metrics["resource_metrics"]:
        if resource["id"] in registry:
            fail(f"metrics reuses metric id {resource['id']!r}")
        registry[resource["id"]] = resource["unit"]
    return registry


def validate_thresholds(
    value: Any,
    metrics: dict[str, Any],
    workload: dict[str, Any],
    artifacts: dict[str, Any] | None = None,
) -> None:
    context = "thresholds"
    if not isinstance(value, dict):
        fail(f"{context} must be an object")
    keys = ("baseline_policy", "missing_metric_policy", "baselines", "baseline_artifact", "rules")
    require_keys(value, keys, context)
    forbid_extra(value, keys, context)
    if value["baseline_policy"] not in {"artifact-required", "explicit-values-only"}:
        fail(f"{context}.baseline_policy is unsupported")
    require_equal(value["missing_metric_policy"], "fail", f"{context}.missing_metric_policy")
    baselines = value["baselines"]
    if not isinstance(baselines, dict):
        fail(f"{context}.baselines must be an object")
    baseline_keys = (
        "minimum_completion_count",
        "minimum_sample_count",
        "minimum_steady_state_samples",
        "source",
    )
    require_keys(baselines, baseline_keys, f"{context}.baselines")
    forbid_extra(baselines, baseline_keys, f"{context}.baselines")
    minimum_completion = require_integer(
        baselines["minimum_completion_count"],
        f"{context}.baselines.minimum_completion_count",
        minimum=1,
        maximum=MAX_SAMPLE_COUNT,
    )
    minimum_samples = require_integer(
        baselines["minimum_sample_count"],
        f"{context}.baselines.minimum_sample_count",
        minimum=1,
        maximum=MAX_SAMPLE_COUNT,
    )
    require_integer(
        baselines["minimum_steady_state_samples"],
        f"{context}.baselines.minimum_steady_state_samples",
        minimum=1,
        maximum=MAX_SAMPLE_COUNT,
    )
    require_equal(baselines["source"], "explicit-config", f"{context}.baselines.source")
    baseline_artifact = value["baseline_artifact"]
    if value["baseline_policy"] == "explicit-values-only":
        require_equal(baseline_artifact, None, f"{context}.baseline_artifact")
    else:
        if not isinstance(baseline_artifact, dict):
            fail(f"{context}.baseline_artifact is required by artifact-required policy")
        artifact_keys = ("path", "artifact_digest_sha256", "max_bytes")
        require_keys(baseline_artifact, artifact_keys, f"{context}.baseline_artifact")
        forbid_extra(baseline_artifact, artifact_keys, f"{context}.baseline_artifact")
        baseline_path = require_string(
            baseline_artifact["path"], f"{context}.baseline_artifact.path", maximum=MAX_FIXTURE_PATH_CHARS
        )
        if (
            Path(baseline_path).is_absolute()
            or ".." in Path(baseline_path).parts
            or not baseline_path.startswith("artifacts/")
        ):
            fail(f"{context}.baseline_artifact.path must stay under the artifact root")
        require_hex_digest(
            baseline_artifact["artifact_digest_sha256"],
            f"{context}.baseline_artifact.artifact_digest_sha256",
        )
        max_bytes = require_integer(
            baseline_artifact["max_bytes"],
            f"{context}.baseline_artifact.max_bytes",
            minimum=1,
            maximum=MAX_HASH_BYTES,
        )
        baseline_file = safe_existing_file(
            PERF_ROOT / baseline_path,
            safe_artifact_root(artifacts["root"]) if artifacts is not None else PERF_ROOT,
            f"{context}.baseline_artifact.path",
        )
        if baseline_file.stat().st_size > max_bytes:
            fail(f"{context}.baseline_artifact exceeds max_bytes")
        actual_baseline_digest = sha256_file(baseline_file, f"{context}.baseline_artifact.path", max_bytes)
        require_equal(
            actual_baseline_digest,
            baseline_artifact["artifact_digest_sha256"],
            f"{context}.baseline_artifact.artifact_digest_sha256",
        )
    rules = require_list(value["rules"], f"{context}.rules", minimum=1, maximum=256)
    registry = metric_registry(metrics)
    rule_ids: list[str] = []
    rules_by_metric: dict[str, list[dict[str, Any]]] = {}
    for index, rule in enumerate(rules):
        item_context = f"{context}.rules[{index}]"
        if not isinstance(rule, dict):
            fail(f"{item_context} must be an object")
        keys = ("id", "metric", "operator", "value", "unit", "scope")
        require_keys(rule, keys, item_context)
        forbid_extra(rule, keys, item_context)
        rule_ids.append(require_string(rule["id"], f"{item_context}.id", ID))
        metric = require_string(rule["metric"], f"{item_context}.metric", METRIC_PATH)
        if metric not in registry:
            fail(f"{item_context}.metric is not declared in metrics")
        if rule["operator"] not in {"<", "<=", "=", ">=", ">"}:
            fail(f"{item_context}.operator is unsupported")
        require_number(rule["value"], f"{item_context}.value", minimum=0, maximum=MAX_THRESHOLD_VALUE)
        unit = require_string(rule["unit"], f"{item_context}.unit", maximum=64)
        if unit != registry[metric]:
            fail(f"{item_context}.unit {unit!r} does not match {metric!r} ({registry[metric]!r})")
        if metric.endswith("_p95") or metric.endswith("_p99"):
            suffix = "_p95" if metric.endswith("_p95") else "_p99"
            histogram_id = metric[: -len(suffix)]
            histograms = {histogram["id"]: histogram for histogram in metrics["histograms"]}
            histogram = histograms.get(histogram_id)
            percentile = 95 if suffix == "_p95" else 99
            if histogram is None or percentile not in histogram["percentiles"]:
                fail(f"{item_context}.metric must be backed by histogram {histogram_id!r} at p{percentile}")
            if rule["operator"] not in {"<", "<="}:
                fail(f"{item_context}.operator must be a ceiling for percentile metrics")
        if metric in {"throughput", "sample_count", "operations_completed", "samples_completed"}:
            if rule["operator"] not in {">", ">=", "="}:
                fail(f"{item_context}.operator must be a floor for completion/rate metrics")
        if any(token in metric for token in ("failed", "dropped", "overflow")) and rule["value"] == 0:
            if rule["operator"] not in {"=", "<", "<="}:
                fail(f"{item_context}.operator must enforce a no-failure/no-drop ceiling")
        if rule["scope"] not in {"run", "steady-state", "final-window"}:
            fail(f"{item_context}.scope is unsupported")
        rules_by_metric.setdefault(metric, []).append(rule)
    if len(rule_ids) != len(set(rule_ids)):
        fail(f"{context}.rules contains duplicate ids")
    required_metrics = {
        "throughput",
        "sample_count",
    }
    if not any(metric.endswith("_p95") for metric in rules_by_metric):
        fail(f"{context}.rules must include a p95 threshold")
    if not any(metric.endswith("_p99") for metric in rules_by_metric):
        fail(f"{context}.rules must include a p99 threshold")
    histogram_ids = {histogram["id"] for histogram in metrics["histograms"]}
    for elapsed_histogram in ("operation_elapsed", "sample_elapsed"):
        if elapsed_histogram not in histogram_ids:
            continue
        for percentile in (95, 99):
            metric = f"{elapsed_histogram}_p{percentile}"
            if metric not in rules_by_metric:
                fail(
                    f"{context}.rules must include elapsed p{percentile} threshold "
                    f"for {elapsed_histogram}"
                )
    if "schedule_delay_p95" not in rules_by_metric or "schedule_delay_p99" not in rules_by_metric:
        fail(f"{context}.rules must include schedule p95 and p99 thresholds")
    if not required_metrics <= rules_by_metric.keys():
        fail(f"{context}.rules must include throughput and sample_count baselines")
    required_zero_metrics = {
        metric
        for metric in registry
        if metric.endswith("_failed")
    } | {"results_dropped", "queue_overflows"}
    for metric in required_zero_metrics:
        if not any(
            rule["value"] == 0 and rule["operator"] in {"=", "<", "<="}
            for rule in rules_by_metric.get(metric, [])
        ):
            fail(f"{context}.rules must include a zero ceiling for {metric}")
    completion_metric = (
        "operations_completed" if "operations_completed" in registry else "samples_completed"
    )
    if completion_metric not in rules_by_metric:
        fail(f"{context}.rules must include a minimum completion threshold ({completion_metric})")
    if not any(rule["operator"] in {">", ">="} and rule["value"] >= minimum_completion for rule in rules_by_metric[completion_metric]):
        fail(f"{context}.rules completion threshold must cover minimum_completion_count")
    if not any(rule["operator"] in {">", ">="} and rule["value"] >= minimum_samples for rule in rules_by_metric["sample_count"]):
        fail(f"{context}.rules sample_count threshold must cover minimum_sample_count")
    iterations = workload["iterations"]
    if iterations is not None:
        expected = workload["virtual_users"] * iterations
        if minimum_completion > expected or minimum_samples > expected:
            fail(f"{context}.baselines exceed bounded workload sample capacity {expected}")


def validate_leak_sampling(value: Any, metrics: dict[str, Any]) -> None:
    context = "leak_sampling"
    if not isinstance(value, dict):
        fail(f"{context} must be an object")
    keys = (
        "enabled",
        "interval_seconds",
        "initial_delay_seconds",
        "baseline",
        "windows",
        "metrics",
        "growth_rules",
        "unavailable_policy",
        "require_final_sample",
    )
    require_keys(value, keys, context)
    forbid_extra(value, keys, context)
    require_equal(value["enabled"], True, f"{context}.enabled")
    require_integer(
        value["interval_seconds"],
        f"{context}.interval_seconds",
        minimum=1,
        maximum=MAX_INTERVAL_SECONDS,
    )
    require_integer(
        value["initial_delay_seconds"],
        f"{context}.initial_delay_seconds",
        minimum=0,
        maximum=MAX_DURATION_SECONDS,
    )
    if value["baseline"] not in {"first-stable-window", "first-sample"}:
        fail(f"{context}.baseline is unsupported")
    windows = value["windows"]
    if not isinstance(windows, dict):
        fail(f"{context}.windows must be an object")
    window_keys = ("warmup_samples", "steady_state_samples", "final_samples")
    require_keys(windows, window_keys, f"{context}.windows")
    forbid_extra(windows, window_keys, f"{context}.windows")
    require_integer(
        windows["warmup_samples"],
        f"{context}.windows.warmup_samples",
        minimum=0,
        maximum=MAX_SAMPLE_COUNT,
    )
    require_integer(
        windows["steady_state_samples"],
        f"{context}.windows.steady_state_samples",
        minimum=1,
        maximum=MAX_SAMPLE_COUNT,
    )
    require_integer(
        windows["final_samples"],
        f"{context}.windows.final_samples",
        minimum=1,
        maximum=MAX_SAMPLE_COUNT,
    )
    leak_metrics = validate_metric_list(value["metrics"], f"{context}.metrics")
    registry = metric_registry(metrics)
    histogram_ids = {histogram["id"] for histogram in metrics["histograms"]}
    for metric in leak_metrics:
        if metric not in registry:
            fail(f"{context}.metrics references undeclared metric {metric!r}")
        if metric in histogram_ids:
            fail(f"{context}.metrics cannot sample histogram identity {metric!r}; use a scalar resource metric")
    growth_rules = require_list(value["growth_rules"], f"{context}.growth_rules", minimum=1, maximum=64)
    growth_ids: list[str] = []
    for index, rule in enumerate(growth_rules):
        item_context = f"{context}.growth_rules[{index}]"
        if not isinstance(rule, dict):
            fail(f"{item_context} must be an object")
        keys = ("id", "metric", "unit", "comparison", "max_absolute", "max_relative")
        require_keys(rule, keys, item_context)
        forbid_extra(rule, keys, item_context)
        growth_ids.append(require_string(rule["id"], f"{item_context}.id", ID))
        metric = require_string(rule["metric"], f"{item_context}.metric", METRIC_ID)
        if metric not in registry:
            fail(f"{item_context}.metric is not declared in metrics")
        unit = require_string(rule["unit"], f"{item_context}.unit", maximum=64)
        if unit != registry[metric]:
            fail(f"{item_context}.unit {unit!r} does not match {metric!r} ({registry[metric]!r})")
        require_equal(rule["comparison"], "final-window-vs-baseline", f"{item_context}.comparison")
        require_number(
            rule["max_absolute"],
            f"{item_context}.max_absolute",
            minimum=0,
            maximum=MAX_THRESHOLD_VALUE,
        )
        relative = require_number(rule["max_relative"], f"{item_context}.max_relative", minimum=0)
        if relative > 10:
            fail(f"{item_context}.max_relative must be <= 10")
    if len(growth_ids) != len(set(growth_ids)):
        fail(f"{context}.growth_rules contains duplicate ids")
    growth_metrics = [rule["metric"] for rule in growth_rules]
    if set(growth_metrics) != set(leak_metrics):
        fail(f"{context}.growth_rules must cover exactly every leak-sampled metric")
    require_equal(value["unavailable_policy"], "fail", f"{context}.unavailable_policy")
    require_equal(value["require_final_sample"], True, f"{context}.require_final_sample")


def validate_artifacts(value: Any) -> None:
    context = "artifacts"
    if not isinstance(value, dict):
        fail(f"{context} must be an object")
    keys = ("root", "result_filename", "write_mode", "max_bytes", "raw_samples")
    require_keys(value, keys, context)
    forbid_extra(value, keys, context)
    root = require_string(value["root"], f"{context}.root", maximum=MAX_ARTIFACT_ROOT_CHARS)
    if Path(root).is_absolute() or ".." in Path(root).parts:
        fail(f"{context}.root must be relative and confined to tools/perf")
    safe_artifact_root(root)
    filename = require_string(
        value["result_filename"], f"{context}.result_filename", maximum=MAX_RESULT_FILENAME_CHARS
    )
    if (
        Path(filename).name != filename
        or ".." in Path(filename).parts
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{2,127}", filename) is None
    ):
        fail(f"{context}.result_filename must not contain directories")
    require_equal(value["write_mode"], "dry-run-only", f"{context}.write_mode")
    require_integer(
        value["max_bytes"],
        f"{context}.max_bytes",
        minimum=1024,
        maximum=MAX_RESULT_BYTES,
    )
    require_equal(value["raw_samples"], False, f"{context}.raw_samples")


def validate_extensions(value: Any) -> None:
    context = "config.extensions"
    if not isinstance(value, dict):
        fail(f"{context} must be an object")
    if len(value) > MAX_CONFIG_EXTENSIONS_KEYS:
        fail(f"{context} has more than {MAX_CONFIG_EXTENSIONS_KEYS} keys")
    _bound_json(value, context)
    if len(canonical_json(value).encode("utf-8")) > MAX_CONFIG_EXTENSIONS_BYTES:
        fail(f"{context} exceeds {MAX_CONFIG_EXTENSIONS_BYTES} encoded bytes")


def validate_workload_relationships(
    workload: dict[str, Any], metrics: dict[str, Any], thresholds: dict[str, Any], leak: dict[str, Any]
) -> None:
    expected = None
    if workload["iterations"] is not None:
        expected = workload["virtual_users"] * workload["iterations"]
        if expected > MAX_SAMPLE_COUNT:
            fail(f"workload bounded sample capacity exceeds {MAX_SAMPLE_COUNT}")
        if metrics["max_samples"] < expected:
            fail("metrics.max_samples is below bounded workload sample capacity")
    leak_windows = leak["windows"]
    leak_sample_budget = (
        leak_windows["warmup_samples"]
        + leak_windows["steady_state_samples"]
        + leak_windows["final_samples"]
    )
    if metrics["warmup_samples"] + leak_sample_budget > metrics["max_samples"]:
        fail("metrics.max_samples is below warmup plus leak-sampling budget")
    minimum_steady = thresholds["baselines"]["minimum_steady_state_samples"]
    if minimum_steady > leak_windows["steady_state_samples"]:
        fail("minimum_steady_state_samples exceeds the steady-state leak window")
    if expected is not None:
        for key in ("minimum_completion_count", "minimum_sample_count"):
            if thresholds["baselines"][key] > expected:
                fail(f"thresholds.baselines.{key} exceeds bounded workload capacity")
        if leak["initial_delay_seconds"] != 0:
            fail("iteration-bounded workloads must begin leak sampling at time zero")
        if metrics["warmup_samples"] + leak_sample_budget > expected:
            fail("iteration-bounded workload cannot provide the declared leak/warmup samples")
    if not workload["open_loop"] and workload["target_rate_per_second"] is not None:
        fail("closed-loop workloads must leave target_rate_per_second null")
    duration = workload["duration_seconds"]
    if duration is not None:
        if workload["warmup_seconds"] + workload["ramp_up_seconds"] > duration:
            fail("workload warmup plus ramp-up exceeds duration")
        leak_horizon = leak["initial_delay_seconds"] + leak_sample_budget * leak["interval_seconds"]
        if leak_horizon > duration:
            fail("leak sampling horizon exceeds workload duration")
        if metrics["sample_interval_seconds"] > duration:
            fail("metrics.sample_interval_seconds exceeds workload duration")
        if metrics["warmup_samples"] * metrics["sample_interval_seconds"] > duration:
            fail("metrics warmup sample horizon exceeds workload duration")
        if workload["open_loop"]:
            target_rate = workload["target_rate_per_second"]
            if target_rate is None or target_rate <= 0:
                fail("open-loop duration workload requires a positive target rate")
            expected_rate_samples = math.ceil(target_rate * duration)
            if expected_rate_samples > MAX_SAMPLE_COUNT:
                fail("target-rate horizon exceeds the bounded sample limit")
            if metrics["max_samples"] < expected_rate_samples:
                fail("metrics.max_samples is below target-rate workload horizon")
            for key in ("minimum_completion_count", "minimum_sample_count"):
                if thresholds["baselines"][key] > expected_rate_samples:
                    fail(f"thresholds.baselines.{key} exceeds target-rate workload horizon")
    elif workload["open_loop"]:
        fail("open-loop workloads must be duration-bounded")


def validate_config(config: dict[str, Any], profile: dict[str, Any] | None = None) -> None:
    """Validate all parser and safety invariants for one configuration."""

    require_keys(
        config,
        (
            "schema_id",
            "schema_version",
            "config_id",
            "kind",
            "compatibility",
            "reproducibility",
            "platform_matrix",
            "execution",
            "workload",
            "metrics",
            "thresholds",
            "leak_sampling",
            "artifacts",
        ),
        "config",
    )
    forbid_extra(
        config,
        (
            "schema_id",
            "schema_version",
            "config_id",
            "kind",
            "compatibility",
            "reproducibility",
            "platform_matrix",
            "execution",
            "workload",
            "metrics",
            "thresholds",
            "leak_sampling",
            "artifacts",
            "extensions",
        ),
        "config",
    )
    require_equal(config["schema_id"], SCHEMA_ID, "config.schema_id")
    require_equal(config["schema_version"], SCHEMA_VERSION, "config.schema_version")
    ensure_schema_contracts()
    config_id = require_string(config["config_id"], "config.config_id", ID)
    if "extensions" in config:
        validate_extensions(config["extensions"])
    kind = config["kind"]
    if kind not in {"micro", "macro", "soak"}:
        fail("config.kind must be micro, macro, or soak")
    if profile is None:
        profile = read_json(PROFILE_PATH, PROFILE_ROOT, "compatibility profile")
    fixture_catalog = load_fixture_catalog()
    validate_compatibility(config["compatibility"], profile, fixture_catalog)
    validate_reproducibility(config["reproducibility"])
    validate_platform_matrix(config["platform_matrix"], config["reproducibility"])
    validate_execution(config["execution"])
    validate_workload(
        config["workload"], kind, config["compatibility"]["fixture_id"], fixture_catalog
    )
    validate_artifacts(config["artifacts"])
    validate_metrics(config["metrics"])
    validate_thresholds(
        config["thresholds"],
        config["metrics"],
        config["workload"],
        config["artifacts"],
    )
    validate_leak_sampling(config["leak_sampling"], config["metrics"])
    validate_workload_relationships(
        config["workload"], config["metrics"], config["thresholds"], config["leak_sampling"]
    )
    # Validate all derived action identifiers while the source configuration is
    # still being accepted; dry-run must never be the first place this fails.
    planned_actions(config)
    if kind == "soak" and config["workload"]["duration_seconds"] not in {3600, 28800, 86400}:
        fail(f"{config_id}: unsupported soak duration")


def _evidence_metric_value(
    metric: str,
    observations: dict[str, dict[str, Any]],
    histograms: dict[str, dict[str, Any]],
) -> float:
    if metric.endswith("_p95") or metric.endswith("_p99"):
        suffix = "_p95" if metric.endswith("_p95") else "_p99"
        histogram = histograms.get(metric[: -len(suffix)])
        if histogram is None:
            fail(f"collected evidence threshold metric {metric!r} has no histogram")
        return float(histogram["percentiles"][suffix[1:]])
    observation = observations.get(metric)
    if observation is None:
        fail(f"collected evidence is missing metric {metric!r}")
    return float(observation["value"])


def _evidence_threshold_holds(operator: str, observed: float, threshold: float) -> bool:
    if operator == "<":
        return observed < threshold
    if operator == "<=":
        return observed <= threshold
    if operator == "=":
        return observed == threshold
    if operator == ">=":
        return observed >= threshold
    if operator == ">":
        return observed > threshold
    fail(f"collected evidence has unsupported threshold operator {operator!r}")


def _require_distinct_artifact_digest(
    artifact_digest: Any, reference_digest: Any, context: str
) -> None:
    require_hex_digest(artifact_digest, context)
    require_hex_digest(reference_digest, f"{context} reference")
    if artifact_digest == reference_digest:
        fail(f"{context} must be an immutable artifact digest, not a reference-string digest")


def _validate_evidence_reproducibility(
    value: Any, config: dict[str, Any]
) -> None:
    context = "collected.reproducibility"
    if not isinstance(value, dict):
        fail(f"{context} must be an object")
    keys = (
        "seed",
        "locale",
        "timezone",
        "charset",
        "target_os",
        "target_arch",
        "target_triple",
        "os_image",
        "rust_toolchain",
        "cargo_lock_sha256",
        "source_date_epoch",
        "environment_allowlist",
        "clock_mode",
    )
    require_keys(value, keys, context)
    forbid_extra(value, keys, context)
    declared = config["reproducibility"]
    for key in (
        "seed",
        "locale",
        "timezone",
        "charset",
        "target_os",
        "target_arch",
        "target_triple",
        "cargo_lock_sha256",
        "source_date_epoch",
        "environment_allowlist",
        "clock_mode",
    ):
        require_equal(value[key], declared[key], f"{context}.{key}")
    target = next(
        item
        for item in config["platform_matrix"]
        if (
            item["target_os"],
            item["target_arch"],
            item["target_triple"],
        )
        == (
            declared["target_os"],
            declared["target_arch"],
            declared["target_triple"],
        )
    )
    image = value["os_image"]
    if not isinstance(image, dict):
        fail(f"{context}.os_image must be an object")
    require_keys(image, ("reference", "reference_sha256", "artifact_digest_sha256"), f"{context}.os_image")
    forbid_extra(image, ("reference", "reference_sha256", "artifact_digest_sha256"), f"{context}.os_image")
    require_equal(image["reference"], declared["os_image_reference"], f"{context}.os_image.reference")
    require_equal(
        image["reference_sha256"], declared["os_image_reference_sha256"], f"{context}.os_image.reference_sha256"
    )
    require_reference_digest(image["reference"], image["reference_sha256"], f"{context}.os_image")
    _require_distinct_artifact_digest(
        image["artifact_digest_sha256"],
        image["reference_sha256"],
        f"{context}.os_image.artifact_digest_sha256",
    )
    require_equal(image["reference"], target["os_image_reference"], f"{context}.os_image.reference")
    require_equal(image["reference_sha256"], target["os_image_reference_sha256"], f"{context}.os_image.reference_sha256")
    toolchain = value["rust_toolchain"]
    if not isinstance(toolchain, dict):
        fail(f"{context}.rust_toolchain must be an object")
    require_keys(
        toolchain,
        ("reference", "reference_sha256", "artifact_digest_sha256", "compiler_version"),
        f"{context}.rust_toolchain",
    )
    forbid_extra(
        toolchain,
        ("reference", "reference_sha256", "artifact_digest_sha256", "compiler_version"),
        f"{context}.rust_toolchain",
    )
    require_equal(toolchain["reference"], declared["rust_toolchain"], f"{context}.rust_toolchain.reference")
    require_equal(
        toolchain["reference_sha256"],
        sha256_bytes(declared["rust_toolchain"].encode("utf-8")),
        f"{context}.rust_toolchain.reference_sha256",
    )
    require_reference_digest(toolchain["reference"], toolchain["reference_sha256"], f"{context}.rust_toolchain")
    _require_distinct_artifact_digest(
        toolchain["artifact_digest_sha256"],
        toolchain["reference_sha256"],
        f"{context}.rust_toolchain.artifact_digest_sha256",
    )
    require_equal(
        toolchain["artifact_digest_sha256"],
        declared["rust_toolchain_sha256"],
        f"{context}.rust_toolchain.artifact_digest_sha256",
    )
    require_string(toolchain["compiler_version"], f"{context}.rust_toolchain.compiler_version", maximum=256)


def _validate_evidence_runtime(value: Any, config: dict[str, Any]) -> None:
    context = "collected.runtime"
    if not isinstance(value, dict):
        fail(f"{context} must be an object")
    require_keys(value, ("executable", "container_runtime", "image"), context)
    forbid_extra(value, ("executable", "container_runtime", "image"), context)
    children = {
        item["executable"]: item
        for item in config["execution"]["children"]
        if item["role"] == "benchmark"
    }
    containers = {
        item["runtime"]: item
        for item in config["execution"]["containers"]
        if item["role"] == "fixture-service"
    }
    selected = config["reproducibility"]

    def check_reference(item: Any, allowed: dict[str, dict[str, Any]], item_context: str) -> None:
        if not isinstance(item, dict):
            fail(f"{item_context} must be an object")
        require_keys(item, ("reference", "reference_sha256", "artifact_digest_sha256"), item_context)
        forbid_extra(item, ("reference", "reference_sha256", "artifact_digest_sha256"), item_context)
        reference = require_string(item["reference"], f"{item_context}.reference", maximum=256)
        declared = allowed.get(reference)
        if declared is None:
            fail(f"{item_context}.reference is not one of the configured future references")
        require_equal(
            item["reference_sha256"],
            declared.get("executable_reference_sha256", declared.get("runtime_reference_sha256")),
            f"{item_context}.reference_sha256",
        )
        require_reference_digest(reference, item["reference_sha256"], item_context)
        _require_distinct_artifact_digest(
            item["artifact_digest_sha256"],
            item["reference_sha256"],
            f"{item_context}.artifact_digest_sha256",
        )

    check_reference(value["executable"], children, f"{context}.executable")
    check_reference(value["container_runtime"], containers, f"{context}.container_runtime")
    image = value["image"]
    if not isinstance(image, dict):
        fail(f"{context}.image must be an object")
    require_keys(image, ("reference", "reference_sha256", "artifact_digest_sha256"), f"{context}.image")
    forbid_extra(image, ("reference", "reference_sha256", "artifact_digest_sha256"), f"{context}.image")
    require_equal(image["reference"], selected["os_image_reference"], f"{context}.image.reference")
    require_equal(image["reference_sha256"], selected["os_image_reference_sha256"], f"{context}.image.reference_sha256")
    require_reference_digest(image["reference"], image["reference_sha256"], f"{context}.image")
    _require_distinct_artifact_digest(
        image["artifact_digest_sha256"],
        image["reference_sha256"],
        f"{context}.image.artifact_digest_sha256",
    )


def _validate_evidence_fixtures(
    value: Any, config: dict[str, Any], catalog: dict[str, dict[str, Any]]
) -> None:
    context = "collected.fixtures"
    fixtures = require_list(value, context, minimum=1, maximum=MAX_FIXTURE_CATALOG_ENTRIES)
    expected_ids = config["compatibility"]["fixture_ids"]
    actual_ids: list[str] = []
    for index, fixture in enumerate(fixtures):
        item_context = f"{context}[{index}]"
        if not isinstance(fixture, dict):
            fail(f"{item_context} must be an object")
        keys = (
            "id",
            "fixture_family_id",
            "profile_id",
            "source_path",
            "source_reference_sha256",
            "fixture_artifact_digest_sha256",
            "case_manifest_path",
            "case_manifest_reference_sha256",
            "case_manifest_artifact_digest_sha256",
            "case_id",
        )
        require_keys(fixture, keys, item_context)
        forbid_extra(fixture, keys, item_context)
        fixture_id = require_string(fixture["id"], f"{item_context}.id", re.compile(r"^FX-[A-Z0-9-]+$"), 64)
        actual_ids.append(fixture_id)
        if fixture_id not in expected_ids or fixture_id not in catalog:
            fail(f"{item_context}.id is not declared by the config/catalog")
        entry = catalog[fixture_id]
        for key in ("fixture_family_id", "profile_id", "source_path", "case_manifest_path", "case_id"):
            require_equal(fixture[key], entry[key], f"{item_context}.{key}")
        require_reference_digest(fixture["source_path"], fixture["source_reference_sha256"], item_context)
        require_reference_digest(
            fixture["case_manifest_path"], fixture["case_manifest_reference_sha256"], item_context
        )
        source_digest = sha256_file(entry["source"], f"{item_context}.source_path")
        case_digest = sha256_file(
            entry["case_manifest"], f"{item_context}.case_manifest_path", MAX_CASE_MANIFEST_BYTES
        )
        require_equal(fixture["fixture_artifact_digest_sha256"], source_digest, f"{item_context}.fixture_artifact_digest_sha256")
        require_equal(
            fixture["case_manifest_artifact_digest_sha256"], case_digest, f"{item_context}.case_manifest_artifact_digest_sha256"
        )
        _require_distinct_artifact_digest(
            fixture["fixture_artifact_digest_sha256"],
            fixture["source_reference_sha256"],
            f"{item_context}.fixture_artifact_digest_sha256",
        )
        _require_distinct_artifact_digest(
            fixture["case_manifest_artifact_digest_sha256"],
            fixture["case_manifest_reference_sha256"],
            f"{item_context}.case_manifest_artifact_digest_sha256",
        )
    if actual_ids != expected_ids or len(actual_ids) != len(set(actual_ids)):
        fail(f"{context} must exactly enumerate config compatibility.fixture_ids")


def _validate_evidence_metrics(
    value: Any, config: dict[str, Any]
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    context = "collected.metrics"
    if not isinstance(value, dict):
        fail(f"{context} must be an object")
    keys = (
        "observations",
        "completion_count",
        "sample_count",
        "throughput",
        "cpu_time_ns",
        "allocation_bytes",
        "samples_failed",
        "results_dropped",
        "queue_overflows",
        "workload_mode",
        "target_rate_per_second",
        "target_rate_expected_samples",
        "target_rate_relationship",
    )
    require_keys(value, keys, context)
    forbid_extra(value, keys, context)
    registry = metric_registry(config["metrics"])
    histogram_ids = {item["id"] for item in config["metrics"]["histograms"]}
    required_ids = set(registry) - histogram_ids
    observations = require_list(value["observations"], f"{context}.observations", minimum=1, maximum=256)
    by_id: dict[str, dict[str, Any]] = {}
    for index, observation in enumerate(observations):
        item_context = f"{context}.observations[{index}]"
        if not isinstance(observation, dict):
            fail(f"{item_context} must be an object")
        require_keys(observation, ("id", "value", "unit", "scope"), item_context)
        forbid_extra(observation, ("id", "value", "unit", "scope"), item_context)
        metric_id = require_string(observation["id"], f"{item_context}.id", METRIC_PATH)
        if metric_id in by_id:
            fail(f"{context}.observations contains duplicate metric id {metric_id!r}")
        if metric_id not in required_ids:
            fail(f"{item_context}.id is not an allowed non-histogram metric")
        unit = require_string(observation["unit"], f"{item_context}.unit", maximum=64)
        require_equal(unit, registry[metric_id], f"{item_context}.unit")
        require_number(observation["value"], f"{item_context}.value", minimum=0, maximum=MAX_THRESHOLD_VALUE)
        if observation["scope"] not in {"run", "steady-state", "final-window"}:
            fail(f"{item_context}.scope is unsupported")
        by_id[metric_id] = observation
    if set(by_id) != required_ids:
        missing = sorted(required_ids - set(by_id))
        fail(f"{context}.observations is missing declared metrics: {', '.join(missing)}")
    workload = config["workload"]
    expected_mode = "open-loop" if workload["open_loop"] else "closed-loop"
    require_equal(value["workload_mode"], expected_mode, f"{context}.workload_mode")
    if workload["open_loop"]:
        target_rate = workload["target_rate_per_second"]
        expected_samples = math.ceil(target_rate * workload["duration_seconds"])
        require_number(value["target_rate_per_second"], f"{context}.target_rate_per_second", minimum=0)
        require_equal(value["target_rate_per_second"], target_rate, f"{context}.target_rate_per_second")
        require_equal(value["target_rate_expected_samples"], expected_samples, f"{context}.target_rate_expected_samples")
        require_equal(value["target_rate_relationship"], "bounded-by-duration", f"{context}.target_rate_relationship")
    else:
        require_equal(value["target_rate_per_second"], None, f"{context}.target_rate_per_second")
        require_equal(value["target_rate_expected_samples"], None, f"{context}.target_rate_expected_samples")
        require_equal(value["target_rate_relationship"], "not-applicable-closed-loop", f"{context}.target_rate_relationship")
    completion_metric = "operations_completed" if "operations_completed" in by_id else "samples_completed"
    scalar_links = {
        "completion_count": completion_metric,
        "sample_count": "sample_count",
        "throughput": "throughput",
        "cpu_time_ns": "cpu_time_ns",
        "allocation_bytes": "allocation_bytes",
        "samples_failed": "samples_failed" if "samples_failed" in by_id else "operations_failed",
        "results_dropped": "results_dropped",
        "queue_overflows": "queue_overflows",
    }
    for field, metric_id in scalar_links.items():
        require_equal(value[field], by_id[metric_id]["value"], f"{context}.{field}")
        if field in {"completion_count", "sample_count", "samples_failed", "results_dropped", "queue_overflows"}:
            require_integer(value[field], f"{context}.{field}", minimum=0, maximum=MAX_SAMPLE_COUNT)
        else:
            require_number(value[field], f"{context}.{field}", minimum=0, maximum=MAX_THRESHOLD_VALUE)
    return by_id, {}


def _validate_evidence_histograms(value: Any, config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    context = "collected.histograms"
    histograms = require_list(value, context, minimum=1, maximum=64)
    expected = {item["id"]: item for item in config["metrics"]["histograms"]}
    actual: dict[str, dict[str, Any]] = {}
    for index, histogram in enumerate(histograms):
        item_context = f"{context}[{index}]"
        if not isinstance(histogram, dict):
            fail(f"{item_context} must be an object")
        require_keys(histogram, ("id", "unit", "count", "percentiles"), item_context)
        forbid_extra(histogram, ("id", "unit", "count", "percentiles"), item_context)
        histogram_id = require_string(histogram["id"], f"{item_context}.id", METRIC_ID)
        if histogram_id in actual:
            fail(f"{context} contains duplicate histogram id {histogram_id!r}")
        declared = expected.get(histogram_id)
        if declared is None:
            fail(f"{item_context}.id is not declared by config.metrics.histograms")
        require_equal(histogram["unit"], declared["unit"], f"{item_context}.unit")
        require_integer(histogram["count"], f"{item_context}.count", minimum=1, maximum=MAX_SAMPLE_COUNT)
        percentiles = histogram["percentiles"]
        if not isinstance(percentiles, dict):
            fail(f"{item_context}.percentiles must be an object")
        require_keys(percentiles, ("p50", "p95", "p99"), f"{item_context}.percentiles")
        forbid_extra(percentiles, ("p50", "p95", "p99"), f"{item_context}.percentiles")
        for percentile in (50, 95, 99):
            require_number(
                percentiles[f"p{percentile}"],
                f"{item_context}.percentiles.p{percentile}",
                minimum=0,
                maximum=MAX_THRESHOLD_VALUE,
            )
        if not (percentiles["p50"] <= percentiles["p95"] <= percentiles["p99"]):
            fail(f"{item_context}.percentiles must be monotonic")
        actual[histogram_id] = histogram
    if set(actual) != set(expected):
        fail(f"{context} must exactly enumerate config.metrics.histograms")
    return actual


def _validate_evidence_artifacts(
    value: Any,
    config: dict[str, Any],
    rule_ids: set[str],
) -> tuple[dict[str, dict[str, Any]], set[str]]:
    context = "collected.artifacts"
    artifacts = require_list(value, context, minimum=1, maximum=64)
    artifact_root = safe_artifact_root(config["artifacts"]["root"])
    actual: dict[str, dict[str, Any]] = {}
    for index, artifact in enumerate(artifacts):
        item_context = f"{context}[{index}]"
        if not isinstance(artifact, dict):
            fail(f"{item_context} must be an object")
        keys = ("id", "kind", "path", "size_bytes", "max_bytes", "artifact_digest_sha256", "required_for", "immutable")
        require_keys(artifact, keys, item_context)
        forbid_extra(artifact, keys, item_context)
        artifact_id = require_string(artifact["id"], f"{item_context}.id", ID)
        if artifact_id in actual:
            fail(f"{context} contains duplicate artifact id {artifact_id!r}")
        path = require_string(artifact["path"], f"{item_context}.path", maximum=MAX_FIXTURE_PATH_CHARS)
        if not path.startswith(config["artifacts"]["root"] + "/"):
            fail(f"{item_context}.path must stay beneath the configured artifact root")
        if (
            Path(path).name != path.split("/")[-1]
            or Path(path).is_absolute()
            or ".." in Path(path).parts
            or "\\" in path
        ):
            fail(f"{item_context}.path is not a confined relative artifact path")
        target = _safe_missing_path(REPO_ROOT / "tools" / "perf" / path, PERF_ROOT, f"{item_context}.path")
        if target.parent != artifact_root:
            fail(f"{item_context}.path must be a direct child of the configured artifact root")
        require_integer(artifact["size_bytes"], f"{item_context}.size_bytes", minimum=0, maximum=MAX_RESULT_BYTES)
        max_bytes = require_integer(artifact["max_bytes"], f"{item_context}.max_bytes", minimum=1, maximum=MAX_RESULT_BYTES)
        if artifact["size_bytes"] > max_bytes or max_bytes > config["artifacts"]["max_bytes"]:
            fail(f"{item_context} violates size/max_bytes/configured artifact bounds")
        require_hex_digest(artifact["artifact_digest_sha256"], f"{item_context}.artifact_digest_sha256")
        require_equal(artifact["immutable"], True, f"{item_context}.immutable")
        required_for = require_list(artifact["required_for"], f"{item_context}.required_for", minimum=1, maximum=64)
        for link_index, link in enumerate(required_for):
            link_value = require_string(link, f"{item_context}.required_for[{link_index}]", maximum=128)
            if link_value not in rule_ids and link_value != "evidence-envelope":
                fail(f"{item_context}.required_for references unknown threshold/action {link_value!r}")
        actual[artifact_id] = artifact
    required_ids: set[str] = set()
    return actual, required_ids


def _validate_evidence_thresholds(
    value: Any,
    config: dict[str, Any],
    observations: dict[str, dict[str, Any]],
    histograms: dict[str, dict[str, Any]],
    artifacts: dict[str, dict[str, Any]],
) -> None:
    context = "collected.thresholds"
    if not isinstance(value, dict):
        fail(f"{context} must be an object")
    keys = (
        "baseline_policy",
        "minimum_completion_count",
        "minimum_sample_count",
        "minimum_steady_state_samples",
        "required_artifact_ids",
        "rules",
        "status",
    )
    require_keys(value, keys, context)
    forbid_extra(value, keys, context)
    declared = config["thresholds"]
    require_equal(value["baseline_policy"], declared["baseline_policy"], f"{context}.baseline_policy")
    for field, source in (
        ("minimum_completion_count", "minimum_completion_count"),
        ("minimum_sample_count", "minimum_sample_count"),
        ("minimum_steady_state_samples", "minimum_steady_state_samples"),
    ):
        expected = declared["baselines"][source]
        require_equal(value[field], expected, f"{context}.{field}")
        require_integer(value[field], f"{context}.{field}", minimum=1, maximum=MAX_SAMPLE_COUNT)
    required_artifact_ids = require_list(value["required_artifact_ids"], f"{context}.required_artifact_ids", maximum=64)
    if len(required_artifact_ids) != len(set(required_artifact_ids)):
        fail(f"{context}.required_artifact_ids contains duplicates")
    required_artifact_id_set = set(required_artifact_ids)
    for index, artifact_id in enumerate(required_artifact_ids):
        identifier = require_string(artifact_id, f"{context}.required_artifact_ids[{index}]", ID)
        if identifier not in artifacts:
            fail(f"{context}.required_artifact_ids references absent artifact {identifier!r}")
        required_for = artifacts[identifier]["required_for"]
        if not any(link in {rule["id"] for rule in declared["rules"]} for link in required_for):
            fail(f"{context}.required_artifact_ids artifact {identifier!r} has no valid linkage")
    rules = require_list(value["rules"], f"{context}.rules", minimum=1, maximum=256)
    declared_rules = {rule["id"]: rule for rule in declared["rules"]}
    actual_rule_ids: list[str] = []
    for index, rule in enumerate(rules):
        item_context = f"{context}.rules[{index}]"
        if not isinstance(rule, dict):
            fail(f"{item_context} must be an object")
        keys = ("id", "metric", "operator", "threshold", "observed", "unit", "status", "artifact_required", "artifact_id", "histogram_id", "percentile")
        require_keys(rule, keys, item_context)
        forbid_extra(rule, keys, item_context)
        rule_id = require_string(rule["id"], f"{item_context}.id", ID)
        if rule_id in actual_rule_ids:
            fail(f"{context}.rules contains duplicate id {rule_id!r}")
        actual_rule_ids.append(rule_id)
        source = declared_rules.get(rule_id)
        if source is None:
            fail(f"{item_context}.id is not declared by config.thresholds.rules")
        require_equal(rule["metric"], source["metric"], f"{item_context}.metric")
        require_equal(rule["operator"], source["operator"], f"{item_context}.operator")
        require_equal(rule["threshold"], source["value"], f"{item_context}.threshold")
        require_equal(rule["unit"], source["unit"], f"{item_context}.unit")
        require_number(rule["threshold"], f"{item_context}.threshold", minimum=0, maximum=MAX_THRESHOLD_VALUE)
        observed = require_number(rule["observed"], f"{item_context}.observed", minimum=0, maximum=MAX_THRESHOLD_VALUE)
        require_equal(rule["observed"], _evidence_metric_value(source["metric"], observations, histograms), f"{item_context}.observed")
        is_percentile = source["metric"].endswith("_p95") or source["metric"].endswith("_p99")
        if is_percentile:
            suffix = "p95" if source["metric"].endswith("_p95") else "p99"
            expected_histogram = source["metric"][: -(len(suffix) + 1)]
            require_equal(rule["histogram_id"], expected_histogram, f"{item_context}.histogram_id")
            require_equal(rule["percentile"], int(suffix[1:]), f"{item_context}.percentile")
            if expected_histogram not in histograms:
                fail(f"{item_context} references an absent histogram")
        else:
            require_equal(rule["histogram_id"], None, f"{item_context}.histogram_id")
            require_equal(rule["percentile"], None, f"{item_context}.percentile")
        expected_artifact = declared["baseline_policy"] == "artifact-required"
        require_equal(rule["artifact_required"], expected_artifact, f"{item_context}.artifact_required")
        if expected_artifact:
            artifact_id = rule.get("artifact_id")
            require_string(artifact_id, f"{item_context}.artifact_id", ID)
            if artifact_id not in artifacts:
                fail(f"{item_context}.artifact_id references an absent artifact")
            if artifact_id not in required_artifact_id_set:
                fail(f"{item_context}.artifact_id must be listed in required_artifact_ids")
            if rule_id not in artifacts[artifact_id]["required_for"]:
                fail(f"{item_context}.artifact_id is not linked to this threshold rule")
        elif "artifact_id" in rule:
            require_equal(rule["artifact_id"], None, f"{item_context}.artifact_id")
        expected_status = "passed" if _evidence_threshold_holds(rule["operator"], observed, rule["threshold"]) else "failed"
        require_equal(rule["status"], expected_status, f"{item_context}.status")
    if actual_rule_ids != list(declared_rules):
        fail(f"{context}.rules must exactly enumerate config.thresholds.rules in order")
    statuses = {rule["status"] for rule in rules}
    expected_status = "passed" if statuses == {"passed"} else "failed"
    require_equal(value["status"], expected_status, f"{context}.status")


def _validate_evidence_leak_sampling(value: Any, config: dict[str, Any], observations: dict[str, dict[str, Any]]) -> None:
    context = "collected.leak_sampling"
    if not isinstance(value, dict):
        fail(f"{context} must be an object")
    keys = ("interval_seconds", "initial_delay_seconds", "windows", "horizon_seconds", "iteration_horizon", "sample_count", "metrics", "samples", "growth_status")
    require_keys(value, keys, context)
    forbid_extra(value, keys, context)
    declared = config["leak_sampling"]
    require_equal(value["interval_seconds"], declared["interval_seconds"], f"{context}.interval_seconds")
    require_equal(value["initial_delay_seconds"], declared["initial_delay_seconds"], f"{context}.initial_delay_seconds")
    require_integer(value["interval_seconds"], f"{context}.interval_seconds", minimum=1, maximum=MAX_INTERVAL_SECONDS)
    require_integer(value["initial_delay_seconds"], f"{context}.initial_delay_seconds", minimum=0, maximum=MAX_DURATION_SECONDS)
    windows = value["windows"]
    if not isinstance(windows, dict):
        fail(f"{context}.windows must be an object")
    require_keys(windows, ("warmup", "steady_state", "final"), f"{context}.windows")
    forbid_extra(windows, ("warmup", "steady_state", "final"), f"{context}.windows")
    expected_windows = {
        "warmup": declared["windows"]["warmup_samples"],
        "steady_state": declared["windows"]["steady_state_samples"],
        "final": declared["windows"]["final_samples"],
    }
    for window, expected in expected_windows.items():
        require_equal(windows[window], expected, f"{context}.windows.{window}")
        require_integer(windows[window], f"{context}.windows.{window}", minimum=0, maximum=MAX_SAMPLE_COUNT)
    expected_count = sum(expected_windows.values())
    require_equal(value["sample_count"], expected_count, f"{context}.sample_count")
    require_equal(value["metrics"], declared["metrics"], f"{context}.metrics")
    metric_ids = set(declared["metrics"])
    samples = require_list(value["samples"], f"{context}.samples", minimum=1, maximum=MAX_SAMPLE_COUNT)
    if len(samples) != expected_count:
        fail(f"{context}.samples length must equal the declared leak windows")
    for index, sample in enumerate(samples):
        item_context = f"{context}.samples[{index}]"
        if not isinstance(sample, dict):
            fail(f"{item_context} must be an object")
        require_keys(sample, ("sequence", "monotonic_ns", "values"), item_context)
        forbid_extra(sample, ("sequence", "monotonic_ns", "values"), item_context)
        require_equal(sample["sequence"], index, f"{item_context}.sequence")
        require_integer(sample["sequence"], f"{item_context}.sequence", minimum=0, maximum=MAX_SAMPLE_COUNT)
        require_integer(sample["monotonic_ns"], f"{item_context}.monotonic_ns", minimum=0, maximum=1_000_000_000_000_000_000)
        expected_timestamp = (
            declared["initial_delay_seconds"] + (index + 1) * declared["interval_seconds"]
        ) * 1_000_000_000
        require_equal(sample["monotonic_ns"], expected_timestamp, f"{item_context}.monotonic_ns")
        if index and sample["monotonic_ns"] <= samples[index - 1]["monotonic_ns"]:
            fail(f"{item_context}.monotonic_ns must increase")
        sample_values = sample["values"]
        if not isinstance(sample_values, dict):
            fail(f"{item_context}.values must be an object")
        if set(sample_values) != metric_ids:
            fail(f"{item_context}.values must contain every configured leak metric exactly once")
        for metric_id in metric_ids:
            require_number(sample_values[metric_id], f"{item_context}.values.{metric_id}", minimum=0, maximum=MAX_THRESHOLD_VALUE)
            require_equal(observations[metric_id]["unit"], metric_registry(config["metrics"])[metric_id], f"{item_context}.values.{metric_id}.unit")
    expected_horizon = declared["initial_delay_seconds"] + expected_count * declared["interval_seconds"]
    require_equal(value["horizon_seconds"], expected_horizon, f"{context}.horizon_seconds")
    require_integer(value["horizon_seconds"], f"{context}.horizon_seconds", minimum=0, maximum=MAX_DURATION_SECONDS)
    duration = config["workload"]["duration_seconds"]
    if duration is not None and expected_horizon > duration:
        fail(f"{context}.horizon_seconds exceeds workload duration")
    iteration_horizon = value["iteration_horizon"]
    if not isinstance(iteration_horizon, dict):
        fail(f"{context}.iteration_horizon must be an object")
    require_keys(iteration_horizon, ("mode", "expected_samples", "minimum_sample_count", "validated"), f"{context}.iteration_horizon")
    forbid_extra(iteration_horizon, ("mode", "expected_samples", "minimum_sample_count", "validated"), f"{context}.iteration_horizon")
    workload = config["workload"]
    if workload["iterations"] is not None:
        expected_mode = "iterations"
        expected_samples = workload["virtual_users"] * workload["iterations"]
    elif workload["open_loop"]:
        expected_mode = "duration"
        expected_samples = math.ceil(workload["target_rate_per_second"] * workload["duration_seconds"])
    else:
        expected_mode = "duration"
        expected_samples = workload["duration_seconds"]
    require_equal(iteration_horizon["mode"], expected_mode, f"{context}.iteration_horizon.mode")
    require_equal(iteration_horizon["expected_samples"], expected_samples, f"{context}.iteration_horizon.expected_samples")
    require_equal(iteration_horizon["minimum_sample_count"], expected_count, f"{context}.iteration_horizon.minimum_sample_count")
    require_equal(iteration_horizon["validated"], True, f"{context}.iteration_horizon.validated")
    if value["growth_status"] not in {"passed", "failed"}:
        fail(f"{context}.growth_status is unsupported")


def _validate_evidence_ownership(value: Any, config: dict[str, Any]) -> None:
    context = "collected.ownership"
    if not isinstance(value, dict):
        fail(f"{context} must be an object")
    require_keys(value, ("children", "containers"), context)
    forbid_extra(value, ("children", "containers"), context)
    expected_children = {item["id"] for item in config["execution"]["children"]}
    expected_containers = {item["id"] for item in config["execution"]["containers"]}
    for field, expected, identity, extra in (
        ("children", expected_children, "owned-child-handle", ("reaped", "termination")),
        ("containers", expected_containers, "created-by-this-run", ("cleanup",)),
    ):
        entries = require_list(value[field], f"{context}.{field}", maximum=MAX_CHILDREN if field == "children" else MAX_CONTAINERS)
        actual: set[str] = set()
        for index, entry in enumerate(entries):
            item_context = f"{context}.{field}[{index}]"
            if not isinstance(entry, dict):
                fail(f"{item_context} must be an object")
            required = ("id", "identity", *extra)
            require_keys(entry, required, item_context)
            forbid_extra(entry, required, item_context)
            identifier = require_string(entry["id"], f"{item_context}.id", ID)
            if identifier in actual or identifier not in expected:
                fail(f"{item_context}.id is not an exact declared ownership identity")
            actual.add(identifier)
            require_equal(entry["identity"], identity, f"{item_context}.identity")
            if field == "children":
                require_equal(entry["reaped"], True, f"{item_context}.reaped")
                require_equal(entry["termination"], "direct-child-only", f"{item_context}.termination")
            else:
                require_equal(entry["cleanup"], "exact-created-id-only", f"{item_context}.cleanup")
        if actual != expected:
            fail(f"{context}.{field} must exactly enumerate config ownership declarations")


def validate_collected_evidence(
    document: dict[str, Any],
    config: dict[str, Any],
    profile: dict[str, Any] | None = None,
    fixture_catalog: dict[str, dict[str, Any]] | None = None,
) -> None:
    """Validate future collected evidence and bind it to one validated config.

    This is intentionally a validation boundary only.  It never starts a
    process, contacts a service, or treats a dry-run result as measurements.
    """

    validate_config(config, profile)
    ensure_schema_contracts()
    context = "collected evidence"
    _bound_json(document, context)
    if not isinstance(document, dict):
        fail(f"{context} must be an object")
    keys = (
        "schema_id",
        "schema_version",
        "status",
        "evidence_id",
        "config_id",
        "config_sha256",
        "source_commit",
        "compatibility",
        "reproducibility",
        "runtime",
        "fixtures",
        "metrics",
        "histograms",
        "thresholds",
        "leak_sampling",
        "artifacts",
        "ownership",
    )
    require_keys(document, keys, context)
    forbid_extra(document, keys, context)
    require_equal(document["schema_id"], COLLECTED_EVIDENCE_SCHEMA_ID, f"{context}.schema_id")
    require_equal(document["schema_version"], COLLECTED_EVIDENCE_SCHEMA_VERSION, f"{context}.schema_version")
    status = document["status"]
    if status not in {"completed", "failed"}:
        fail(f"{context}.status is unsupported")
    require_string(document["evidence_id"], f"{context}.evidence_id", EVIDENCE_ID, 128)
    require_equal(document["config_id"], config["config_id"], f"{context}.config_id")
    require_equal(
        document["config_sha256"],
        sha256_bytes(canonical_json(config).encode("utf-8")),
        f"{context}.config_sha256",
    )
    source_commit = require_string(document["source_commit"], f"{context}.source_commit", HEX40, 40)
    if status == "completed":
        require_equal(len(source_commit), 40, f"{context}.source_commit")
    require_equal(document["compatibility"], config["compatibility"], f"{context}.compatibility")
    if profile is None:
        profile = read_json(PROFILE_PATH, PROFILE_ROOT, "compatibility profile")
    if fixture_catalog is None:
        fixture_catalog = load_fixture_catalog()
    _validate_evidence_reproducibility(document["reproducibility"], config)
    _validate_evidence_runtime(document["runtime"], config)
    _validate_evidence_fixtures(document["fixtures"], config, fixture_catalog)
    observations, _ = _validate_evidence_metrics(document["metrics"], config)
    histograms = _validate_evidence_histograms(document["histograms"], config)
    for metric_id, observation in observations.items():
        if metric_id.endswith("_p95") or metric_id.endswith("_p99"):
            suffix = "p95" if metric_id.endswith("_p95") else "p99"
            histogram_id = metric_id[: -(len(suffix) + 1)]
            histogram = histograms.get(histogram_id)
            if histogram is None:
                fail(f"collected evidence metric {metric_id!r} has no histogram binding")
            require_equal(
                observation["value"],
                histogram["percentiles"][suffix],
                f"collected.metrics.observations.{metric_id}",
            )
    artifact_rule_ids = {rule["id"] for rule in config["thresholds"]["rules"]}
    artifacts, _ = _validate_evidence_artifacts(document["artifacts"], config, artifact_rule_ids)
    _validate_evidence_thresholds(document["thresholds"], config, observations, histograms, artifacts)
    _validate_evidence_leak_sampling(document["leak_sampling"], config, observations)
    _validate_evidence_ownership(document["ownership"], config)
    if status == "completed":
        require_equal(document["thresholds"]["status"], "passed", f"{context}.thresholds.status")
        require_equal(document["leak_sampling"]["growth_status"], "passed", f"{context}.leak_sampling.growth_status")


def load_config(path: Path) -> dict[str, Any]:
    canonical = safe_existing_file(path, CONFIG_ROOT, f"performance config {path}")
    config = read_json(canonical, CONFIG_ROOT, f"performance config {path}")
    validate_config(config)
    return config


def load_configs(paths: Iterable[Path] | None = None) -> list[tuple[Path, dict[str, Any]]]:
    selected = sorted(paths if paths is not None else CONFIG_ROOT.glob("*.json"))
    if not selected:
        fail(f"no performance configs found in {CONFIG_ROOT}")
    if len(selected) > MAX_ID_LIST_ITEMS:
        fail(f"too many performance configs (maximum {MAX_ID_LIST_ITEMS})")
    loaded = [(path, load_config(path)) for path in selected]
    config_ids = [config["config_id"] for _, config in loaded]
    if len(config_ids) != len(set(config_ids)):
        fail("performance configs contain duplicate config_id values")
    return loaded


def metadata(config: dict[str, Any]) -> dict[str, Any]:
    """Build metadata exclusively from declared config values.

    Avoiding ambient hostname, clock, environment, and tool discovery keeps a
    dry-run reproducible.  A future execution adapter must append measured
    values under an explicitly versioned result schema.
    """

    reproducibility = config["reproducibility"]
    return {
        "seed": reproducibility["seed"],
        "locale": reproducibility["locale"],
        "timezone": reproducibility["timezone"],
        "charset": reproducibility["charset"],
        "target_os": reproducibility["target_os"],
        "target_arch": reproducibility["target_arch"],
        "target_triple": reproducibility["target_triple"],
        "os_image_id": reproducibility["os_image_id"],
        "os_image_reference": reproducibility["os_image_reference"],
        "os_image_reference_sha256": reproducibility["os_image_reference_sha256"],
        "os_image_artifact_digest_sha256": reproducibility["os_image_artifact_digest_sha256"],
        "rust_toolchain": reproducibility["rust_toolchain"],
        "rust_toolchain_sha256": reproducibility["rust_toolchain_sha256"],
        "cargo_lock_sha256": reproducibility["cargo_lock_sha256"],
        "source_date_epoch": reproducibility["source_date_epoch"],
        "environment_allowlist": reproducibility["environment_allowlist"],
        "clock_mode": reproducibility["clock_mode"],
        "collection_state": "not-collected",
        "fixture_family_id": config["workload"]["fixture_family_id"],
        "fixture_path": config["workload"]["fixture_path"],
        "fixture_sha256": config["workload"]["fixture_sha256"],
        "case_id": config["workload"]["case_id"],
        "case_manifest_path": config["workload"]["case_manifest_path"],
        "case_manifest_sha256": sha256_file(
            safe_existing_file(
                REPO_ROOT / config["workload"]["case_manifest_path"], FIXTURE_ROOT, "workload.case_manifest_path"
            ),
            "workload.case_manifest_path",
            MAX_CASE_MANIFEST_BYTES,
        ),
        "orchestrator_id": "tools/perf/orchestrator.py@1",
        "source_commit": None,
        "repository_state": "working-tree",
    }


def planned_actions(config: dict[str, Any]) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    for operation in config["workload"]["operations"]:
        actions.append(
            {
                "id": f"operation-{operation['id']}",
                "kind": "operation",
                "enabled": operation["enabled"],
                "performed": False,
                "requires_process": False,
                "owner": "in-process-plan",
            }
        )
    for child in config["execution"]["children"]:
        actions.append(
            {
                "id": f"child-{child['id']}",
                "kind": "child",
                "enabled": child["enabled"],
                "performed": False,
                "requires_process": True,
                "owner": "owned-child-handle",
            }
        )
    for container in config["execution"]["containers"]:
        actions.append(
            {
                "id": f"container-{container['id']}",
                "kind": "container",
                "enabled": container["enabled"],
                "performed": False,
                "requires_process": True,
                "owner": "owned-container-id",
            }
        )
    for metric in config["leak_sampling"]["metrics"]:
        actions.append(
            {
                "id": f"metric-sample-{metric.replace('_', '-')}",
                "kind": "metric-sample",
                "enabled": True,
                "performed": False,
                "requires_process": False,
                "owner": "runner",
            }
        )
    for rule in config["thresholds"]["rules"]:
        actions.append(
            {
                "id": f"threshold-{rule['id']}",
                "kind": "threshold-evaluation",
                "enabled": True,
                "performed": False,
                "requires_process": False,
                "owner": "runner",
            }
        )
    if len(actions) > MAX_JSON_LIST_ITEMS:
        fail("planned action count exceeds parser limit")
    for index, action in enumerate(actions):
        require_string(action["id"], f"planned_actions[{index}].id", ID)
    require_unique_ids(actions, "planned_actions")
    return actions


def dry_run_result(config: dict[str, Any]) -> dict[str, Any]:
    config_hash = sha256_bytes(canonical_json(config).encode("utf-8"))
    result = {
        "schema_id": RESULT_SCHEMA_ID,
        "schema_version": RESULT_SCHEMA_VERSION,
        "status": "dry-run",
        "config_id": config["config_id"],
        "config_sha256": config_hash,
        "kind": config["kind"],
        "compatibility": config["compatibility"],
        "future_evidence": {
            "schema_id": FUTURE_EVIDENCE_SCHEMA_ID,
            "schema_version": FUTURE_EVIDENCE_SCHEMA_VERSION,
            "status": "not-generated",
        },
        "metadata": metadata(config),
        "planned_actions": planned_actions(config),
        "measurements": [],
        "thresholds": {
            "status": "not-evaluated",
            "evaluated": False,
            "results": [
                {"id": rule["id"], "status": "not-evaluated"}
                for rule in config["thresholds"]["rules"]
            ],
        },
        "leak_sampling": {
            "status": "not-collected",
            "sample_count": 0,
            "samples": [],
            "growth_status": "not-evaluated",
        },
        "safety": {
            "execution_performed": False,
            "subprocesses_spawned": 0,
            "services_started": 0,
            "containers_started": 0,
            "children_reaped": 0,
            "safety_checks": [
                {"id": "no-process-start", "status": "pass"},
                {"id": "no-network", "status": "pass"},
                {"id": "no-shell", "status": "pass"},
                {"id": "exact-child-ownership-declared", "status": "pass"},
                {"id": "exact-container-cleanup-declared", "status": "pass"},
                {"id": "thresholds-not-claimed", "status": "pass"},
            ],
        },
    }
    validate_generated_result(result, config)
    return result


def validate_generated_result(result: dict[str, Any], config: dict[str, Any]) -> None:
    """Validate the exact dry-run envelope before it reaches stdout/disk."""

    ensure_schema_contracts()
    keys = (
        "schema_id",
        "schema_version",
        "status",
        "config_id",
        "config_sha256",
        "kind",
        "compatibility",
        "future_evidence",
        "metadata",
        "planned_actions",
        "measurements",
        "thresholds",
        "leak_sampling",
        "safety",
    )
    require_keys(result, keys, "dry-run result")
    forbid_extra(result, keys, "dry-run result")
    require_equal(result["schema_id"], RESULT_SCHEMA_ID, "dry-run result.schema_id")
    require_equal(result["schema_version"], RESULT_SCHEMA_VERSION, "dry-run result.schema_version")
    require_equal(result["status"], "dry-run", "dry-run result.status")
    require_equal(result["config_id"], config["config_id"], "dry-run result.config_id")
    expected_hash = sha256_bytes(canonical_json(config).encode("utf-8"))
    require_equal(result["config_sha256"], expected_hash, "dry-run result.config_sha256")
    require_equal(result["kind"], config["kind"], "dry-run result.kind")
    require_equal(result["compatibility"], config["compatibility"], "dry-run result.compatibility")
    future = result["future_evidence"]
    if not isinstance(future, dict):
        fail("dry-run result.future_evidence must be an object")
    require_keys(future, ("schema_id", "schema_version", "status"), "dry-run result.future_evidence")
    forbid_extra(future, ("schema_id", "schema_version", "status"), "dry-run result.future_evidence")
    require_equal(future["schema_id"], FUTURE_EVIDENCE_SCHEMA_ID, "dry-run future evidence schema_id")
    require_equal(
        future["schema_version"], FUTURE_EVIDENCE_SCHEMA_VERSION, "dry-run future evidence schema_version"
    )
    require_equal(future["status"], "not-generated", "dry-run future evidence status")
    require_equal(result["metadata"], metadata(config), "dry-run result.metadata")
    expected_actions = planned_actions(config)
    if result["planned_actions"] != expected_actions:
        fail("dry-run result.planned_actions does not match the configuration")
    actions = require_list(result["planned_actions"], "dry-run result.planned_actions", minimum=1, maximum=MAX_JSON_LIST_ITEMS)
    require_unique_ids(actions, "dry-run result.planned_actions")
    for index, action in enumerate(actions):
        item_context = f"dry-run result.planned_actions[{index}]"
        require_string(action["id"], f"{item_context}.id", ID)
        require_bool(action["enabled"], f"{item_context}.enabled")
        require_equal(action["performed"], False, f"{item_context}.performed")
        require_bool(action["requires_process"], f"{item_context}.requires_process")
    require_equal(result["measurements"], [], "dry-run result.measurements")
    thresholds = result["thresholds"]
    if not isinstance(thresholds, dict):
        fail("dry-run result.thresholds must be an object")
    require_keys(thresholds, ("status", "evaluated", "results"), "dry-run result.thresholds")
    forbid_extra(thresholds, ("status", "evaluated", "results"), "dry-run result.thresholds")
    require_equal(thresholds["status"], "not-evaluated", "dry-run result.thresholds.status")
    require_equal(thresholds["evaluated"], False, "dry-run result.thresholds.evaluated")
    threshold_results = require_list(
        thresholds["results"], "dry-run result.thresholds.results", minimum=1, maximum=256
    )
    expected_rule_ids = [rule["id"] for rule in config["thresholds"]["rules"]]
    actual_rule_ids: list[str] = []
    for index, item in enumerate(threshold_results):
        item_context = f"dry-run result.thresholds.results[{index}]"
        if not isinstance(item, dict):
            fail(f"{item_context} must be an object")
        require_keys(item, ("id", "status"), item_context)
        forbid_extra(item, ("id", "status"), item_context)
        actual_rule_ids.append(require_string(item["id"], f"{item_context}.id", ID))
        require_equal(item["status"], "not-evaluated", f"{item_context}.status")
    if actual_rule_ids != expected_rule_ids or len(actual_rule_ids) != len(set(actual_rule_ids)):
        fail("dry-run result threshold ids do not exactly match configuration rules")
    result_metadata = result["metadata"]
    require_equal(result_metadata["source_commit"], None, "dry-run result.metadata.source_commit")
    require_equal(
        result_metadata["repository_state"], "working-tree", "dry-run result.metadata.repository_state"
    )
    leak = result["leak_sampling"]
    if not isinstance(leak, dict):
        fail("dry-run result.leak_sampling must be an object")
    require_keys(leak, ("status", "sample_count", "samples", "growth_status"), "dry-run result.leak_sampling")
    forbid_extra(leak, ("status", "sample_count", "samples", "growth_status"), "dry-run result.leak_sampling")
    require_equal(leak["status"], "not-collected", "dry-run result.leak_sampling.status")
    require_equal(leak["sample_count"], 0, "dry-run result.leak_sampling.sample_count")
    require_equal(leak["samples"], [], "dry-run result.leak_sampling.samples")
    require_equal(leak["growth_status"], "not-evaluated", "dry-run result.leak_sampling.growth_status")
    safety = result["safety"]
    if not isinstance(safety, dict):
        fail("dry-run result.safety must be an object")
    require_keys(
        safety,
        (
            "execution_performed",
            "subprocesses_spawned",
            "services_started",
            "containers_started",
            "children_reaped",
            "safety_checks",
        ),
        "dry-run result.safety",
    )
    forbid_extra(
        safety,
        (
            "execution_performed",
            "subprocesses_spawned",
            "services_started",
            "containers_started",
            "children_reaped",
            "safety_checks",
        ),
        "dry-run result.safety",
    )
    require_equal(safety["execution_performed"], False, "dry-run result.safety.execution_performed")
    for key in ("subprocesses_spawned", "services_started", "containers_started", "children_reaped"):
        require_equal(safety[key], 0, f"dry-run result.safety.{key}")
    safety_checks = require_list(
        safety["safety_checks"], "dry-run result.safety.safety_checks", minimum=5, maximum=32
    )
    require_unique_ids(safety_checks, "dry-run result.safety.safety_checks")
    for index, check in enumerate(safety_checks):
        item_context = f"dry-run result.safety.safety_checks[{index}]"
        if not isinstance(check, dict):
            fail(f"{item_context} must be an object")
        require_keys(check, ("id", "status"), item_context)
        forbid_extra(check, ("id", "status"), item_context)
        require_string(check["id"], f"{item_context}.id", ID)
        require_equal(check["status"], "pass", f"{item_context}.status")


def print_json(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2))


def selected_configs(positional: list[Path], options: list[Path] | None) -> list[Path]:
    """Combine explicit config spellings while keeping default discovery."""

    return [*(options or []), *positional]


def safe_output_path(config: dict[str, Any], requested: Path) -> Path:
    if len(str(requested)) > MAX_FIXTURE_PATH_CHARS:
        fail(f"dry-run output path exceeds the {MAX_FIXTURE_PATH_CHARS}-character limit")
    artifact_root = safe_artifact_root(config["artifacts"]["root"])
    ensure_artifact_root(artifact_root)
    target = _safe_missing_path(
        requested if requested.is_absolute() else Path.cwd() / requested,
        artifact_root,
        "dry-run output",
    )
    if target.parent != artifact_root:
        fail("dry-run output must be a direct child of the configured artifact root")
    if target.name != config["artifacts"]["result_filename"]:
        fail("dry-run output filename must match artifacts.result_filename")
    if os.path.lexists(target):
        fail(f"refusing to overwrite existing dry-run output: {target}")
    return target


def _open_directory_chain(root: Path, create: bool = False) -> int:
    """Open an artifact directory without following a replaceable component."""

    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory or not hasattr(os, "supports_dir_fd"):
        fail("race-resistant artifact output requires O_NOFOLLOW and directory descriptors")
    perf_root = PERF_ROOT.resolve(strict=True)
    try:
        relative = root.absolute().relative_to(perf_root)
    except ValueError as error:
        fail(f"artifact root cannot be opened as a confined directory: {error}")
    if os.open not in os.supports_dir_fd:
        fail("race-resistant artifact output requires dir_fd support")
    flags = os.O_RDONLY | directory | nofollow
    descriptor: int | None = None
    try:
        descriptor = os.open(perf_root, flags)
        for part in relative.parts:
            while True:
                try:
                    child = os.open(part, flags, dir_fd=descriptor)
                    break
                except FileNotFoundError:
                    if not create:
                        raise
                    try:
                        os.mkdir(part, 0o700, dir_fd=descriptor)
                    except FileExistsError:
                        pass
            os.close(descriptor)
            descriptor = child
        return descriptor
    except OSError as error:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        fail(f"cannot open artifact directory safely: {error}")


def ensure_artifact_root(root: Path) -> None:
    """Create the confined artifact directory without following a parent symlink."""

    descriptor = _open_directory_chain(root, create=True)
    try:
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            fail(f"artifact root is not a directory: {root}")
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass


def write_exclusive_bytes(target: Path, artifact_root: Path, payload: bytes, maximum: int) -> None:
    """Create one bounded artifact through an exact parent directory handle."""

    if not isinstance(payload, bytes):
        fail("dry-run output payload must be bytes")
    if isinstance(maximum, bool) or not isinstance(maximum, int) or maximum < 1 or maximum > MAX_RESULT_BYTES:
        fail("dry-run output max_bytes is outside the approved result bound")
    canonical_root = _safe_missing_path(artifact_root, PERF_ROOT, "artifact output root")
    candidate = target.absolute()
    if candidate.parent != canonical_root or candidate.name in {"", ".", ".."}:
        fail("dry-run output target must be a direct child of the confined artifact root")
    if Path(candidate.name).name != candidate.name or "/" in candidate.name or "\\" in candidate.name:
        fail("dry-run output target must be a single filename")
    if (
        len(candidate.name) > MAX_RESULT_FILENAME_CHARS
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{2,127}", candidate.name) is None
    ):
        fail("dry-run output target filename is outside the bounded result contract")
    if len(payload) > maximum:
        fail(f"dry-run result exceeds artifacts.max_bytes ({maximum})")
    parent_descriptor = _open_directory_chain(canonical_root)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow
    descriptor: int | None = None
    try:
        descriptor = os.open(target.name, flags, 0o600, dir_fd=parent_descriptor)
        stat_result = os.fstat(descriptor)
        if not stat.S_ISREG(stat_result.st_mode):
            fail("dry-run output is not a regular file")
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                fail("dry-run output write made no progress")
            offset += written
        if offset > maximum:
            fail("dry-run output exceeded artifacts.max_bytes while writing")
    except FileExistsError:
        fail(f"refusing to overwrite existing dry-run output: {target}")
    except OSError as error:
        fail(f"cannot create dry-run output safely: {error}")
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            os.close(parent_descriptor)
        except OSError:
            pass


def command_validate(paths: list[Path]) -> int:
    loaded = load_configs(paths or None)
    print(f"validated {len(loaded)} performance configuration(s)")
    for path, config in loaded:
        duration = config["workload"]["duration_seconds"]
        bounded = f"{duration}s" if duration is not None else f"{config['workload']['iterations']} iterations"
        print(f"- {config['config_id']} ({config['kind']}, {bounded}): safe dry-run policy")
    return 0


def command_dry_run(paths: list[Path], output: Path | None) -> int:
    if not paths:
        fail("dry-run requires exactly one explicit configuration")
    loaded = load_configs(paths)
    if len(loaded) != 1:
        fail("dry-run accepts exactly one configuration so every output is a result-schema document")
    _, config = loaded[0]
    document: Any = dry_run_result(config)
    rendered = json.dumps(document, ensure_ascii=True, sort_keys=True, indent=2) + "\n"
    rendered_bytes = rendered.encode("utf-8")
    if len(rendered_bytes) > config["artifacts"]["max_bytes"]:
        fail(f"dry-run result exceeds artifacts.max_bytes ({config['artifacts']['max_bytes']})")
    if output is None:
        sys.stdout.write(rendered)
    else:
        target = safe_output_path(config, output)
        write_exclusive_bytes(
            target,
            target.parent,
            rendered_bytes,
            config["artifacts"]["max_bytes"],
        )
        print(f"wrote deterministic dry-run result to {target}")
    return 0


def _synthetic_collected_evidence(config: dict[str, Any]) -> dict[str, Any]:
    """Build bounded in-memory evidence for validator self-tests only."""

    catalog = load_fixture_catalog()
    registry = metric_registry(config["metrics"])
    histogram_ids = {item["id"] for item in config["metrics"]["histograms"]}
    workload = config["workload"]
    completion_value = (
        workload["virtual_users"] * workload["iterations"]
        if workload["iterations"] is not None
        else 1
    )
    sample_value = completion_value
    observations: list[dict[str, Any]] = []
    for metric_id, unit in registry.items():
        if metric_id in histogram_ids:
            continue
        if metric_id in {"operations_completed", "samples_completed", "sample_count"}:
            value: int | float = sample_value
        elif metric_id == "throughput":
            value = 1
        elif metric_id in {"cpu_time_ns", "allocation_bytes"}:
            value = 1
        elif metric_id in {"rss_bytes"}:
            value = 100
        elif metric_id in {"open_fd_count", "thread_count", "task_count"}:
            value = 1
        elif metric_id == "result_queue_depth":
            value = 0
        elif metric_id.endswith("_p95") or metric_id.endswith("_p99"):
            value = 1_000_000
        else:
            value = 0
        observations.append({"id": metric_id, "value": value, "unit": unit, "scope": "run"})
    observation_by_id = {item["id"]: item for item in observations}
    failure_metric = "samples_failed" if "samples_failed" in observation_by_id else "operations_failed"
    histograms: list[dict[str, Any]] = []
    histogram_by_id: dict[str, dict[str, Any]] = {}
    for histogram in config["metrics"]["histograms"]:
        item = {
            "id": histogram["id"],
            "unit": histogram["unit"],
            "count": 1,
            "percentiles": {"p50": 1_000_000, "p95": 1_000_000, "p99": 1_000_000},
        }
        histograms.append(item)
        histogram_by_id[item["id"]] = item
    threshold_rules: list[dict[str, Any]] = []
    for rule in config["thresholds"]["rules"]:
        metric = rule["metric"]
        observed = _evidence_metric_value(metric, observation_by_id, histogram_by_id)
        percentile = None
        histogram_id = None
        if metric.endswith("_p95") or metric.endswith("_p99"):
            percentile = 95 if metric.endswith("_p95") else 99
            histogram_id = metric[: -(len(f"_p{percentile}"))]
        threshold_rules.append(
            {
                "id": rule["id"],
                "metric": metric,
                "operator": rule["operator"],
                "threshold": rule["value"],
                "observed": observed,
                "unit": rule["unit"],
                "status": "passed",
                "artifact_required": False,
                "artifact_id": None,
                "histogram_id": histogram_id,
                "percentile": percentile,
            }
        )
    leak_count = sum(config["leak_sampling"]["windows"].values())
    leak_samples = []
    for sequence in range(leak_count):
        leak_samples.append(
            {
                "sequence": sequence,
                "monotonic_ns": (
                    config["leak_sampling"]["initial_delay_seconds"]
                    + (sequence + 1) * config["leak_sampling"]["interval_seconds"]
                )
                * 1_000_000_000,
                "values": {metric: observation_by_id[metric]["value"] for metric in config["leak_sampling"]["metrics"]},
            }
        )
    fixtures = []
    for fixture_id in config["compatibility"]["fixture_ids"]:
        entry = catalog[fixture_id]
        fixtures.append(
            {
                "id": fixture_id,
                "fixture_family_id": entry["fixture_family_id"],
                "profile_id": entry["profile_id"],
                "source_path": entry["source_path"],
                "source_reference_sha256": sha256_bytes(entry["source_path"].encode("utf-8")),
                "fixture_artifact_digest_sha256": sha256_file(entry["source"], "self-test fixture"),
                "case_manifest_path": entry["case_manifest_path"],
                "case_manifest_reference_sha256": sha256_bytes(entry["case_manifest_path"].encode("utf-8")),
                "case_manifest_artifact_digest_sha256": sha256_file(
                    entry["case_manifest"], "self-test case manifest", MAX_CASE_MANIFEST_BYTES
                ),
                "case_id": entry["case_id"],
            }
        )
    artifact_digest = "e" * 64
    artifact_id = "evidence-envelope"
    artifacts = [
        {
            "id": artifact_id,
            "kind": "result",
            "path": f"{config['artifacts']['root']}/{config['config_id']}-evidence.json",
            "size_bytes": 0,
            "max_bytes": config["artifacts"]["max_bytes"],
            "artifact_digest_sha256": artifact_digest,
            "required_for": [artifact_id],
            "immutable": True,
        }
    ]
    reproducibility = config["reproducibility"]
    first_child = config["execution"]["children"][0]
    first_container = config["execution"]["containers"][0]
    return {
        "schema_id": COLLECTED_EVIDENCE_SCHEMA_ID,
        "schema_version": COLLECTED_EVIDENCE_SCHEMA_VERSION,
        "status": "completed",
        "evidence_id": f"self-test-{config['config_id']}",
        "config_id": config["config_id"],
        "config_sha256": sha256_bytes(canonical_json(config).encode("utf-8")),
        "source_commit": "a" * 40,
        "compatibility": config["compatibility"],
        "reproducibility": {
            "seed": reproducibility["seed"],
            "locale": reproducibility["locale"],
            "timezone": reproducibility["timezone"],
            "charset": reproducibility["charset"],
            "target_os": reproducibility["target_os"],
            "target_arch": reproducibility["target_arch"],
            "target_triple": reproducibility["target_triple"],
            "os_image": {
                "reference": reproducibility["os_image_reference"],
                "reference_sha256": reproducibility["os_image_reference_sha256"],
                "artifact_digest_sha256": "b" * 64,
            },
            "rust_toolchain": {
                "reference": reproducibility["rust_toolchain"],
                "reference_sha256": sha256_bytes(reproducibility["rust_toolchain"].encode("utf-8")),
                "artifact_digest_sha256": reproducibility["rust_toolchain_sha256"],
                "compiler_version": "rustc-self-test",
            },
            "cargo_lock_sha256": reproducibility["cargo_lock_sha256"],
            "source_date_epoch": reproducibility["source_date_epoch"],
            "environment_allowlist": reproducibility["environment_allowlist"],
            "clock_mode": reproducibility["clock_mode"],
        },
        "runtime": {
            "executable": {
                "reference": first_child["executable"],
                "reference_sha256": first_child["executable_reference_sha256"],
                "artifact_digest_sha256": "d" * 64,
            },
            "container_runtime": {
                "reference": first_container["runtime"],
                "reference_sha256": first_container["runtime_reference_sha256"],
                "artifact_digest_sha256": "f" * 64,
            },
            "image": {
                "reference": reproducibility["os_image_reference"],
                "reference_sha256": reproducibility["os_image_reference_sha256"],
                "artifact_digest_sha256": "1" * 64,
            },
        },
        "fixtures": fixtures,
        "metrics": {
            "observations": observations,
            "completion_count": observation_by_id["operations_completed" if "operations_completed" in observation_by_id else "samples_completed"]["value"],
            "sample_count": observation_by_id["sample_count"]["value"],
            "throughput": observation_by_id["throughput"]["value"],
            "cpu_time_ns": observation_by_id["cpu_time_ns"]["value"],
            "allocation_bytes": observation_by_id["allocation_bytes"]["value"],
            "samples_failed": observation_by_id[failure_metric]["value"],
            "results_dropped": observation_by_id["results_dropped"]["value"],
            "queue_overflows": observation_by_id["queue_overflows"]["value"],
            "workload_mode": "open-loop" if config["workload"]["open_loop"] else "closed-loop",
            "target_rate_per_second": config["workload"]["target_rate_per_second"],
            "target_rate_expected_samples": None,
            "target_rate_relationship": "not-applicable-closed-loop",
        },
        "histograms": histograms,
        "thresholds": {
            "baseline_policy": config["thresholds"]["baseline_policy"],
            "minimum_completion_count": config["thresholds"]["baselines"]["minimum_completion_count"],
            "minimum_sample_count": config["thresholds"]["baselines"]["minimum_sample_count"],
            "minimum_steady_state_samples": config["thresholds"]["baselines"]["minimum_steady_state_samples"],
            "required_artifact_ids": [],
            "rules": threshold_rules,
            "status": "passed",
        },
        "leak_sampling": {
            "interval_seconds": config["leak_sampling"]["interval_seconds"],
            "initial_delay_seconds": config["leak_sampling"]["initial_delay_seconds"],
            "windows": {
                "warmup": config["leak_sampling"]["windows"]["warmup_samples"],
                "steady_state": config["leak_sampling"]["windows"]["steady_state_samples"],
                "final": config["leak_sampling"]["windows"]["final_samples"],
            },
            "horizon_seconds": config["leak_sampling"]["initial_delay_seconds"] + leak_count * config["leak_sampling"]["interval_seconds"],
            "iteration_horizon": {
                "mode": "iterations" if config["workload"]["iterations"] is not None else "duration",
                "expected_samples": (
                    config["workload"]["virtual_users"] * config["workload"]["iterations"]
                    if config["workload"]["iterations"] is not None
                    else config["workload"]["duration_seconds"]
                ),
                "minimum_sample_count": leak_count,
                "validated": True,
            },
            "sample_count": leak_count,
            "metrics": config["leak_sampling"]["metrics"],
            "samples": leak_samples,
            "growth_status": "passed",
        },
        "artifacts": artifacts,
        "ownership": {
            "children": [
                {"id": child["id"], "identity": "owned-child-handle", "reaped": True, "termination": "direct-child-only"}
                for child in config["execution"]["children"]
            ],
            "containers": [
                {"id": container["id"], "identity": "created-by-this-run", "cleanup": "exact-created-id-only"}
                for container in config["execution"]["containers"]
            ],
        },
    }


def command_self_test() -> int:
    def expect_reject(label: str, action: Any) -> None:
        try:
            action()
        except ConfigError:
            return
        fail(f"self-test accepted invalid {label}")

    loaded = load_configs()
    if not loaded:
        fail("self-test found no configs")
    for _, config in loaded:
        first = dry_run_result(config)
        second = dry_run_result(config)
        if first != second:
            fail(f"dry-run result is not deterministic for {config['config_id']}")
        if first["safety"]["subprocesses_spawned"] != 0:
            fail(f"unsafe process count for {config['config_id']}")
        if first["metadata"]["environment_allowlist"]:
            fail(f"ambient environment is allowed for {config['config_id']}")

    # Exercise the future evidence boundary against every mode.  These are
    # synthetic bounded values only; no benchmark, service, or child is run.
    for _, config in loaded:
        evidence = _synthetic_collected_evidence(config)
        validate_collected_evidence(evidence, config)
        mutated = json.loads(canonical_json(evidence))
        mutated["metrics"]["observations"].append(
            {**mutated["metrics"]["observations"][0], "value": 1}
        )
        expect_reject(
            f"{config['config_id']} duplicate evidence metric id",
            lambda mutated=mutated, config=config: validate_collected_evidence(mutated, config),
        )
        mutated = json.loads(canonical_json(evidence))
        mutated["artifacts"][0]["size_bytes"] = mutated["artifacts"][0]["max_bytes"] + 1
        expect_reject(
            f"{config['config_id']} artifact size bound",
            lambda mutated=mutated, config=config: validate_collected_evidence(mutated, config),
        )
        mutated = json.loads(canonical_json(evidence))
        mutated["fixtures"][0]["fixture_family_id"] = "FX-WRONG-FAMILY"
        expect_reject(
            f"{config['config_id']} fixture family binding",
            lambda mutated=mutated, config=config: validate_collected_evidence(mutated, config),
        )
        mutated = json.loads(canonical_json(evidence))
        mutated["fixtures"][0]["source_reference_sha256"] = "0" * 64
        expect_reject(
            f"{config['config_id']} fixture reference hash binding",
            lambda mutated=mutated, config=config: validate_collected_evidence(mutated, config),
        )
        mutated = json.loads(canonical_json(evidence))
        mutated["reproducibility"]["target_arch"] = (
            "aarch64" if config["reproducibility"]["target_arch"] == "x86_64" else "x86_64"
        )
        expect_reject(
            f"{config['config_id']} target binding",
            lambda mutated=mutated, config=config: validate_collected_evidence(mutated, config),
        )
        mutated = json.loads(canonical_json(evidence))
        mutated["thresholds"]["required_artifact_ids"] = ["evidence-envelope"]
        expect_reject(
            f"{config['config_id']} required artifact linkage",
            lambda mutated=mutated, config=config: validate_collected_evidence(mutated, config),
        )
        mutated = json.loads(canonical_json(evidence))
        mutated["leak_sampling"]["horizon_seconds"] += 1
        expect_reject(
            f"{config['config_id']} leak horizon",
            lambda mutated=mutated, config=config: validate_collected_evidence(mutated, config),
        )
        mutated = json.loads(canonical_json(evidence))
        mutated["leak_sampling"]["samples"][0]["monotonic_ns"] += 1
        expect_reject(
            f"{config['config_id']} leak interval schedule",
            lambda mutated=mutated, config=config: validate_collected_evidence(mutated, config),
        )
        mutated = json.loads(canonical_json(evidence))
        del mutated["leak_sampling"]["samples"][0]["values"][config["leak_sampling"]["metrics"][0]]
        expect_reject(
            f"{config['config_id']} required leak resource sample",
            lambda mutated=mutated, config=config: validate_collected_evidence(mutated, config),
        )
        mutated = json.loads(canonical_json(evidence))
        mutated["thresholds"]["rules"][0]["observed"] += 1
        expect_reject(
            f"{config['config_id']} threshold observation binding",
            lambda mutated=mutated, config=config: validate_collected_evidence(mutated, config),
        )
        mutated = json.loads(canonical_json(evidence))
        percentile_observation = next(
            observation
            for observation in mutated["metrics"]["observations"]
            if observation["id"].endswith("_p95")
        )
        percentile_observation["value"] += 1
        expect_reject(
            f"{config['config_id']} histogram percentile binding",
            lambda mutated=mutated, config=config: validate_collected_evidence(mutated, config),
        )
        unsafe = json.loads(canonical_json(config))
        unsafe["execution"]["children"][0]["args"] = ["\ud800"]
        expect_reject(
            f"{config['config_id']} escaped Unicode surrogate",
            lambda unsafe=unsafe: validate_config(unsafe),
        )
        elapsed_histogram = "operation_elapsed" if config["kind"] == "micro" else "sample_elapsed"
        for percentile in (95, 99):
            unsafe = json.loads(canonical_json(config))
            unsafe["thresholds"]["rules"] = [
                rule
                for rule in unsafe["thresholds"]["rules"]
                if rule["metric"] != f"{elapsed_histogram}_p{percentile}"
            ]
            expect_reject(
                f"{config['config_id']} missing elapsed p{percentile} threshold",
                lambda unsafe=unsafe: validate_config(unsafe),
            )
        for percentile in (95, 99):
            unsafe = json.loads(canonical_json(config))
            unsafe["thresholds"]["rules"] = [
                rule
                for rule in unsafe["thresholds"]["rules"]
                if rule["metric"] != f"schedule_delay_p{percentile}"
            ]
            expect_reject(
                f"{config['config_id']} missing schedule p{percentile} threshold",
                lambda unsafe=unsafe: validate_config(unsafe),
            )
        unsafe = json.loads(canonical_json(config))
        unsafe["metrics"]["resource_metrics"] = [
            resource
            for resource in unsafe["metrics"]["resource_metrics"]
            if resource["id"] != "allocation_bytes"
        ]
        expect_reject(
            f"{config['config_id']} missing allocation metric",
            lambda unsafe=unsafe: validate_config(unsafe),
        )
        if config["kind"] == "macro":
            unsafe = json.loads(canonical_json(config))
            execute = next(
                operation
                for operation in unsafe["workload"]["operations"]
                if operation["kind"] == "execute-offline-fixture"
            )
            execute["parameters"]["iterations_per_user"] += 1
            expect_reject(
                f"{config['config_id']} macro iteration relation",
                lambda unsafe=unsafe: validate_config(unsafe),
            )

    _, sample = loaded[0]
    unsafe = json.loads(canonical_json(sample))
    unsafe["execution"]["mode"] = "execute"
    expect_reject("execution mode", lambda: validate_config(unsafe))

    unsafe = json.loads(canonical_json(sample))
    unsafe["execution"]["children"][0]["enabled"] = True
    expect_reject("enabled child", lambda: validate_config(unsafe))

    expect_reject("duplicate JSON keys", lambda: parse_json_bytes(b'{"a":1,"a":2}', "duplicate-key"))
    expect_reject("non-finite JSON number", lambda: parse_json_bytes(b'{"a":NaN}', "nonfinite"))
    expect_reject(
        "escaped Unicode surrogate",
        lambda: parse_json_bytes(b'{"a":"\\ud800"}', "escaped-surrogate"),
    )
    expect_reject(
        "oversized JSON integer",
        lambda: parse_json_bytes(
            b'{"a":' + b"9" * (MAX_JSON_INTEGER_DIGITS + 1) + b"}", "oversized-integer"
        ),
    )
    expect_reject(
        "oversized JSON",
        lambda: parse_json_bytes(b"{" + b"a" * MAX_JSON_BYTES + b"}", "oversized"),
    )
    unsafe = json.loads(canonical_json(sample))
    unsafe["extensions"] = {f"extension-{index}": True for index in range(MAX_CONFIG_EXTENSIONS_KEYS + 1)}
    expect_reject("oversized extensions", lambda: validate_config(unsafe))
    unsafe = json.loads(canonical_json(sample))
    unsafe["workload"]["operations"][0]["parameters"] = {
        "oversized": "x" * (MAX_PARAMETER_BYTES + 1)
    }
    expect_reject("oversized operation parameters", lambda: validate_config(unsafe))
    expect_reject(
        "hashed file byte cap",
        lambda: sha256_file(PROFILE_PATH, "self-test profile", maximum=1),
    )
    expect_reject(
        "config outside fixture root",
        lambda: safe_existing_file(REPO_ROOT / "Cargo.lock", FIXTURE_ROOT, "fixture path"),
    )
    with tempfile.TemporaryDirectory(prefix="perf-path-self-test-") as temporary:
        temporary_root = Path(temporary)
        (temporary_root / "inside").mkdir()
        (temporary_root / "inside" / "link").symlink_to(temporary_root)
        expect_reject(
            "symlink path component",
            lambda: _safe_missing_path(
                temporary_root / "inside" / "link" / "escape", temporary_root, "symlink test"
            ),
        )
    unsafe = json.loads(canonical_json(sample))
    unsafe["workload"]["fixture_path"] = "compat/fixtures/../profiles/jmeter-5.6.3.json"
    expect_reject("fixture traversal", lambda: validate_config(unsafe))
    unsafe = json.loads(canonical_json(sample))
    unsafe["artifacts"]["root"] = "../outside"
    expect_reject("artifact traversal", lambda: validate_config(unsafe))
    unsafe = json.loads(canonical_json(sample))
    unsafe["execution"]["children"][0]["executable"] = "benchmark"
    expect_reject("unpinned relative executable", lambda: validate_config(unsafe))
    unsafe = json.loads(canonical_json(sample))
    unsafe["execution"]["children"][0]["executable"] = "/opt/../benchmark"
    unsafe["execution"]["children"][0]["executable_reference_sha256"] = sha256_bytes(
        unsafe["execution"]["children"][0]["executable"].encode("utf-8")
    )
    expect_reject("executable traversal", lambda: validate_config(unsafe))
    unsafe = json.loads(canonical_json(sample))
    unsafe["execution"]["children"][0]["executable_reference_sha256"] = "f" * 64
    expect_reject("future executable digest mismatch", lambda: validate_config(unsafe))
    unsafe = json.loads(canonical_json(sample))
    unsafe["execution"]["children"][0]["executable_reference_sha256"] = []
    expect_reject("non-string executable digest", lambda: validate_config(unsafe))
    unsafe = json.loads(canonical_json(sample))
    unsafe["execution"]["containers"][0]["image_reference"] = "registry.invalid/fixture:latest"
    expect_reject("unpinned container image", lambda: validate_config(unsafe))
    unsafe = json.loads(canonical_json(sample))
    unsafe["platform_matrix"][0]["os_image_reference"] = "registry.invalid/runner:future"
    expect_reject("unpinned future target image", lambda: validate_config(unsafe))
    unsafe = json.loads(canonical_json(sample))
    unsafe["reproducibility"]["os_image_reference"] = unsafe["platform_matrix"][1]["os_image_reference"]
    unsafe["reproducibility"]["os_image_reference_sha256"] = sha256_bytes(
        unsafe["reproducibility"]["os_image_reference"].encode("utf-8")
    )
    expect_reject("selected target image binding", lambda: validate_config(unsafe))
    unsafe = json.loads(canonical_json(sample))
    unsafe["execution"]["containers"][0]["image_artifact_digest_sha256"] = "f" * 64
    expect_reject("unmaterialized container artifact digest", lambda: validate_config(unsafe))
    unsafe = json.loads(canonical_json(sample))
    unsafe["execution"]["containers"][0]["runtime_reference_sha256"] = "f" * 64
    expect_reject("future runtime digest mismatch", lambda: validate_config(unsafe))
    unsafe = json.loads(canonical_json(sample))
    unsafe["metrics"]["sample_interval_seconds"] = MAX_INTERVAL_SECONDS + 1
    expect_reject("oversized metric interval", lambda: validate_config(unsafe))
    unsafe = json.loads(canonical_json(sample))
    unsafe["metrics"]["max_samples"] = MAX_SAMPLE_COUNT + 1
    expect_reject("oversized sample budget", lambda: validate_config(unsafe))
    unsafe = json.loads(canonical_json(sample))
    unsafe["metrics"]["counters"].remove("results_dropped")
    expect_reject("missing drop metric", lambda: validate_config(unsafe))
    unsafe = json.loads(canonical_json(sample))
    next(resource for resource in unsafe["metrics"]["resource_metrics"] if resource["id"] == "cpu_time_ns")["required"] = False
    expect_reject("optional cpu metric", lambda: validate_config(unsafe))
    unsafe = json.loads(canonical_json(sample))
    unsafe["thresholds"]["rules"] = [
        rule for rule in unsafe["thresholds"]["rules"] if rule["metric"] != "results_dropped"
    ]
    expect_reject("missing drop threshold", lambda: validate_config(unsafe))
    unsafe = json.loads(canonical_json(sample))
    unsafe["workload"]["virtual_users"] = MAX_VIRTUAL_USERS + 1
    expect_reject("oversized virtual-user count", lambda: validate_config(unsafe))
    unsafe = json.loads(canonical_json(sample))
    unsafe["thresholds"]["rules"][0]["unit"] = "bytes"
    expect_reject("threshold unit mismatch", lambda: validate_config(unsafe))
    unsafe = json.loads(canonical_json(sample))
    unsafe["thresholds"]["rules"][0]["metric"] = "not_declared"
    expect_reject("threshold undeclared metric", lambda: validate_config(unsafe))
    unsafe = json.loads(canonical_json(sample))
    unsafe["thresholds"]["rules"][0]["value"] = -1
    expect_reject("negative threshold domain", lambda: validate_config(unsafe))
    unsafe = json.loads(canonical_json(sample))
    unsafe["thresholds"]["baseline_policy"] = "artifact-required"
    unsafe["thresholds"]["baseline_artifact"] = None
    expect_reject("missing required baseline artifact", lambda: validate_config(unsafe))
    unsafe = json.loads(canonical_json(sample))
    unsafe["metrics"]["histograms"][0]["percentiles"] = [50]
    expect_reject("unbacked percentile threshold", lambda: validate_config(unsafe))
    unsafe = json.loads(canonical_json(sample))
    unsafe["leak_sampling"]["windows"]["steady_state_samples"] = MAX_SAMPLE_COUNT
    expect_reject("leak window relationship", lambda: validate_config(unsafe))
    unsafe = json.loads(canonical_json(sample))
    unsafe["leak_sampling"]["initial_delay_seconds"] = 1
    expect_reject("iteration leak horizon", lambda: validate_config(unsafe))
    unsafe = json.loads(canonical_json(sample))
    unsafe["workload"]["target_rate_per_second"] = 1
    expect_reject("closed-loop target rate", lambda: validate_config(unsafe))
    unsafe = json.loads(canonical_json(sample))
    unsafe["platform_matrix"][0]["status"] = "verified"
    expect_reject("untruthful future target status", lambda: validate_config(unsafe))
    expect_reject(
        "artifact max_bytes",
        lambda: write_exclusive_bytes(PERF_ROOT / "self-test-no-output", PERF_ROOT, b"xx", 1),
    )
    expect_reject(
        "artifact max_bytes upper bound",
        lambda: write_exclusive_bytes(
            PERF_ROOT / "self-test-no-output", PERF_ROOT, b"{}\n", MAX_RESULT_BYTES + 1
        ),
    )
    expect_reject(
        "artifact target escape",
        lambda: write_exclusive_bytes(PERF_ROOT / ".." / "outside.json", PERF_ROOT, b"{}\n", 16),
    )
    with tempfile.TemporaryDirectory(dir=PERF_ROOT, prefix="artifact-target-self-test-") as temporary:
        artifact_directory = Path(temporary)
        symlink_target = artifact_directory / "result.json"
        symlink_target.symlink_to(PROFILE_PATH)
        expect_reject(
            "artifact target symlink",
            lambda: write_exclusive_bytes(
                symlink_target, artifact_directory, b"{}\n", 16
            ),
        )
    with tempfile.TemporaryDirectory(dir=PERF_ROOT, prefix="artifact-overwrite-self-test-") as temporary:
        artifact_directory = Path(temporary)
        existing_target = artifact_directory / "result.json"
        write_exclusive_bytes(existing_target, artifact_directory, b"{}\n", 16)
        expect_reject(
            "artifact overwrite",
            lambda: write_exclusive_bytes(existing_target, artifact_directory, b"{}\n", 16),
        )
    unsafe = json.loads(canonical_json(sample))
    unsafe["execution"]["children"][0]["id"] = unsafe["execution"]["children"][1]["id"]
    expect_reject("duplicate action identity", lambda: validate_config(unsafe))
    unsafe = json.loads(canonical_json(sample))
    unsafe["thresholds"]["rules"][0]["id"] = "x" * 64
    expect_reject("oversized derived action identity", lambda: validate_config(unsafe))

    result = dry_run_result(sample)
    ensure_schema_contracts()
    evidence_schema = read_json(
        SCHEMA_ROOT / "collected-evidence.schema.json",
        SCHEMA_ROOT,
        "collected evidence schema",
    )
    require_keys(
        evidence_schema,
        ("x-schema-id", "x-schema-version", "required", "properties"),
        "collected evidence schema",
    )
    for required_field in (
        "source_commit",
        "runtime",
        "fixtures",
        "metrics",
        "histograms",
        "thresholds",
        "leak_sampling",
        "artifacts",
    ):
        if required_field not in evidence_schema["required"]:
            fail(f"collected evidence schema omits {required_field}")
    leak_schema = evidence_schema.get("$defs", {}).get("leak_sampling", {})
    if "samples" not in leak_schema.get("required", []):
        fail("collected evidence schema omits required leak samples")
    expect_reject(
        "generated result mutation",
        lambda: validate_generated_result({**result, "measurements": [{"metric": "x", "value": 1, "unit": "count", "scope": "run"}]}, sample),
    )

    print(f"self-test passed: {len(loaded)} config(s), per-config mutations, no subprocess or service execution")
    return 0


def parser() -> argparse.ArgumentParser:
    command_parser = argparse.ArgumentParser(
        description="Validate and dry-run safe performance plans; execution is intentionally unavailable."
    )
    subparsers = command_parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("self-test", help="run deterministic parser and safety self-tests")
    for command in ("validate", "dry-run"):
        child = subparsers.add_parser(command, help=f"{command} performance configuration(s)")
        child.add_argument(
            "configs",
            nargs="*",
            type=Path,
            help="config JSON path(s); default: every tools/perf/configs/*.json",
        )
        child.add_argument(
            "--config",
            dest="option_configs",
            action="append",
            type=Path,
            help="config JSON path (repeatable); equivalent to a positional path",
        )
        if command == "dry-run":
            child.add_argument("--output", type=Path, help="write deterministic result JSON to this path")
    return command_parser


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        if arguments.command == "self-test":
            return command_self_test()
        if arguments.command == "validate":
            return command_validate(selected_configs(arguments.configs, arguments.option_configs))
        if arguments.command == "dry-run":
            return command_dry_run(
                selected_configs(arguments.configs, arguments.option_configs), arguments.output
            )
        fail(f"unsupported command: {arguments.command}")
    except ConfigError as error:
        print(f"perf error: {error}", file=sys.stderr)
        return 2
    except OSError as error:
        print(f"perf error: filesystem operation failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
