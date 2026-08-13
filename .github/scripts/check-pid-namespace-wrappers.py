#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Statically prove the namespace-wrapper contract before ignored tests run.

The wrappers are launchers for ignored process-group tests, not cleanup tools.
They may use a shell only for bounded identity preflight; the actual test is
an exact ``exec cargo test`` after a fresh user/PID namespace and a
namespace-bound opaque token. A missing proof or a shell/process utility fails
closed with status 78.
"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PROOF_ENV = "JMT_PID_NAMESPACE_PROOF_TOKEN"
PROOF_PREFIX = "jmeter-rs-pidns-v1:"


@dataclass(frozen=True)
class WrapperSpec:
    package: str
    cargo_target: str
    test_name: str
    declaration_path: Path
    destructive_marker: str

    @property
    def cargo_invocation(self) -> str:
        return (
            f"cargo test --locked -p {self.package} {self.cargo_target} "
            f"{self.test_name} -- --exact --ignored --nocapture"
        )


WRAPPER_SPECS = {
    ROOT / "crates/process-supervision/tests/pid_namespace.sh": WrapperSpec(
        "jmeter-rs-process-supervision",
        "--lib",
        "process_tree_cleanup_is_namespace_scoped",
        ROOT / "crates/process-supervision/src/lib.rs",
        "let _namespace_proof_complete",
    ),
    ROOT / "tools/jmeter-oracle/tests/pid_namespace.sh": WrapperSpec(
        "jmeter-oracle",
        "--lib",
        "timeout_returns_error_after_process_group_cleanup",
        ROOT / "tools/jmeter-oracle/src/lib.rs",
        "ChildCleanup::ProcessGroup",
    ),
    ROOT / "crates/java-bridge/tests/pid_namespace.sh": WrapperSpec(
        "jmeter-rs-java-bridge",
        "--test supervisor",
        "process_group_cleanup_is_namespace_scoped",
        ROOT / "crates/java-bridge/tests/supervisor.rs",
        "ProcessGroupPolicy::Required",
    ),
    ROOT / "crates/plugin-host/tests/pid_namespace.sh": WrapperSpec(
        "jmeter-rs-plugin-host",
        "--test supervisor",
        "process_group_cleanup_is_namespace_scoped",
        ROOT / "crates/plugin-host/tests/supervisor.rs",
        "CleanupPolicy::ProcessGroup",
    ),
}
WRAPPERS = tuple(WRAPPER_SPECS)
PROOF_CHECKS = (
    ("host PID namespace identity", r"readlink[ \t]+/proc/self/ns/pid"),
    ("namespace PID identity", r"readlink[ \t]+/proc/1/ns/pid"),
    ("host user namespace identity", r"readlink[ \t]+/proc/self/ns/user"),
    ("namespace user mapping", r"/proc/self/uid_map"),
    ("self status", r"/proc/self/status"),
    ("PID 1 status", r"/proc/1/status"),
    ("namespace-local proc mount", r"/proc/self/mountinfo"),
    ("namespace escape probe", r"namespace_escape_probe"),
    ("opaque proof nonce source", r"/proc/sys/kernel/random/uuid"),
    ("opaque proof nonce length", r"\$\{#proof_nonce\}"),
    ("nested NSpid identity", r"NSpid"),
    ("namespace PID 1 proof", r"\$\$[^\n]*-(?:eq|ne)[ \t]*1"),
)
PROOF_MARKER = re.compile(r"\bnamespace_proof_validated[ \t]*=[ \t]*1\b")
PROOF_ASSIGNMENT = re.compile(
    rf"(?:export[ \t]+)?{re.escape(PROOF_ENV)}[ \t]*="
)
PROOF_EXPORT = re.compile(rf"\bexport[ \t]+{re.escape(PROOF_ENV)}\b")
UNSHARE = re.compile(
    r"(?:^|[;\s])(?:unshare|[\"']?\$[A-Za-z_][A-Za-z0-9_]*[\"']?)"
    r"[ \t]+--user[ \t]+--map-root-user[ \t]+--pid[ \t]+--fork"
    r"[ \t]+--mount-proc(?:[ \t]|$)"
)
SHELL_LAUNCH = re.compile(r"\b(?:sh|bash|dash|zsh)\b[^\n]*\s-c(?:\s|$)")
BROAD_PROCESS_UTILITY = re.compile(
    r"(?:^|[;&|\s])(?:kill|pkill|killall|taskkill|setsid)(?:\s|$)"
)


def executable_code(source: str) -> str:
    """Drop shell comments while retaining quoted script content for checks."""

    return "\n".join(
        line for line in source.splitlines() if not line.lstrip().startswith("#")
    )


def audit_wrapper_text(display: str, source: str, spec: WrapperSpec) -> list[str]:
    """Audit one wrapper without executing it."""

    code = executable_code(source)
    normalized = " ".join(code.split())
    missing: list[str] = []
    if not UNSHARE.search(code):
        missing.append(
            "exact unshare --user --map-root-user --pid --fork --mount-proc invocation"
        )
    if "--user" not in code or "--map-root-user" not in code:
        missing.append("fresh user namespace proof")
    for label, pattern in PROOF_CHECKS:
        if not re.search(pattern, code, re.IGNORECASE):
            missing.append(label)
    namespace_names = r"(?:host_pid_namespace|inner_pid_namespace|[A-Za-z_]+_HOST_PID_NAMESPACE)"
    if not re.search(rf"\b{namespace_names}\b", code):
        missing.append("host-to-inner PID namespace comparison")
    elif not re.search(
        rf"\b{namespace_names}\b[^\n]*(?:!=|=)[^\n]*\b{namespace_names}\b",
        code,
    ):
        missing.append("host-to-inner PID namespace comparison")
    if not PROOF_MARKER.search(code):
        missing.append("post-validation proof marker")
    marker = PROOF_MARKER.search(code)
    if marker is not None:
        proof_positions = [
            match.end()
            for _, pattern in PROOF_CHECKS
            for match in [re.search(pattern, code, re.IGNORECASE)]
            if match is not None
        ]
        if proof_positions and marker.start() <= max(proof_positions):
            missing.append("proof marker must follow every namespace validation")
    assignment = PROOF_ASSIGNMENT.search(code)
    if assignment is None:
        missing.append(f"{PROOF_ENV} assignment")
    else:
        marker = PROOF_MARKER.search(code)
        if marker is None or assignment.start() < marker.end():
            missing.append(f"{PROOF_ENV} assignment after all namespace checks")
        assignment_line_end = code.find("\n", assignment.start())
        assignment_line = code[assignment.start() : assignment_line_end]
        if "inner_pid_namespace" not in assignment_line:
            missing.append(f"{PROOF_ENV} bound to inner PID namespace")
        if "namespace_pid_last" not in assignment_line:
            missing.append(f"{PROOF_ENV} bound to namespace PID 1")
        if "proof_nonce" not in assignment_line:
            missing.append(f"{PROOF_ENV} bound to an opaque nonce")
    if PROOF_PREFIX not in code:
        missing.append("versioned namespace proof token")
    if not PROOF_EXPORT.search(code):
        missing.append(f"exported {PROOF_ENV}")

    expected = " ".join(spec.cargo_invocation.split())
    cargo_lines = [
        " ".join(line.split())[len("exec ") :]
        for line in code.splitlines()
        if re.match(r"^[ \t]*exec[ \t]+cargo[ \t]+test\b", line)
    ]
    if normalized.count("cargo test") != 1:
        missing.append("one Cargo test invocation")
    if cargo_lines != [expected]:
        missing.append(f"exact Cargo test allowlist: {expected}")
    if "--locked" not in code:
        missing.append("--locked Cargo invocation")
    if "--exact" not in code:
        missing.append("--exact test selection")
    if "--ignored" not in code:
        missing.append("--ignored Cargo restriction")
    if not re.search(r"\bexec[ \t]+cargo[ \t]+test\b", code):
        missing.append("direct exec Cargo test launcher")
    if SHELL_LAUNCH.search(code) and not re.search(r"\bexec[ \t]+cargo[ \t]+test\b", code):
        missing.append("shell preflight must end in exec cargo test")
    if BROAD_PROCESS_UTILITY.search(code):
        missing.append("broad process/signal utility in wrapper")
    return [f"{display}: missing {', '.join(missing)}"] if missing else []


def audit(path: Path) -> list[str]:
    display = path.relative_to(ROOT)
    if not path.is_file():
        return [f"{display}: wrapper is missing"]
    if not os.access(path, os.X_OK):
        return [f"{display}: wrapper is not executable"]
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        return [f"{display}: cannot read wrapper: {error}"]
    return audit_wrapper_text(str(display), source, WRAPPER_SPECS[path])


def audit_declaration(path: Path, spec: WrapperSpec) -> list[str]:
    """Require a destructive test to reject direct/host-namespace execution."""

    display = path.relative_to(ROOT)
    if not path.is_file():
        return [f"{display}: destructive test declaration is missing"]
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        return [f"{display}: cannot read declaration: {error}"]
    failures = audit_declaration_text(source, spec)
    return [f"{display}: {', '.join(failures)}"] if failures else []


def audit_declaration_text(source: str, spec: WrapperSpec) -> list[str]:
    """Pure declaration audit used by the validator and its self-tests."""

    function_offset = source.find(f"fn {spec.test_name}")
    if function_offset < 0:
        return [f"missing exact ignored test {spec.test_name}"]
    body = source[function_offset:]
    failures: list[str] = []
    previous_function = source.rfind("fn ", 0, function_offset)
    previous_ignore = source.rfind("#[ignore", 0, function_offset)
    if previous_ignore < previous_function:
        failures.append("test is not #[ignore]d")
    if PROOF_ENV not in body or PROOF_PREFIX not in body:
        failures.append(f"{PROOF_ENV} guard")
    required_checks = (
        'read_link("/proc/self/ns/pid")',
        'read_link("/proc/1/ns/pid")',
        'read_to_string("/proc/self/status")',
        'read_to_string("/proc/1/status")',
        'read_to_string("/proc/self/mountinfo")',
        'read_to_string("/proc/self/uid_map")',
        'read_to_string("/proc/self/gid_map")',
    )
    for required in required_checks:
        if required not in body:
            failures.append(required)
    if 'format!("jmeter-rs-pidns-v1:{}:1:",' not in body:
        failures.append("proof token must bind to current namespace and PID 1")
    if "nspid_fields" not in body and "nspid" not in body:
        failures.append("nested NSpid identity guard")
    if "pid_one_nspid" not in body and "namespace_pid" not in body:
        failures.append("namespace PID 1 identity guard")
    if "let nonce" not in body or "nonce.len()" not in body:
        failures.append("opaque proof nonce validation")
    marker_offset = body.find(spec.destructive_marker)
    proof_offset = body.find(PROOF_ENV)
    if proof_offset >= 0:
        if any(body.find(required) > proof_offset for required in required_checks):
            failures.append("namespace validation must precede proof-token guard")
    if marker_offset < 0:
        failures.append(f"destructive marker {spec.destructive_marker}")
    elif proof_offset < 0 or proof_offset > marker_offset:
        failures.append("proof guard must precede destructive process-group path")
    return failures


def self_test() -> int:
    """Run pure text-level regression checks; never starts a subprocess."""

    spec = next(iter(WRAPPER_SPECS.values()))
    valid_wrapper = f"""
set -eu
host_pid_namespace=$(readlink /proc/self/ns/pid)
inner_pid_namespace=$(readlink /proc/self/ns/pid)
inner_user_namespace=$(readlink /proc/self/ns/user)
uid_map=$(cat /proc/self/uid_map)
status=$(cat /proc/self/status)
pid_one_status=$(cat /proc/1/status)
mountinfo=$(cat /proc/self/mountinfo)
pid_one_namespace=$(readlink /proc/1/ns/pid)
if [ "$host_pid_namespace" = "$inner_pid_namespace" ]; then exit 1; fi
namespace_escape_probe=$(readlink /proc/self/ns/pid)
if [ "$namespace_escape_probe" = "$host_pid_namespace" ]; then exit 1; fi
if [ "$$" -ne 1 ]; then exit 1; fi
NSpid: 1
namespace_pid_last=1
proof_nonce=00000000-0000-0000-0000-000000000000
proof_nonce_source=/proc/sys/kernel/random/uuid
if [ "${{#proof_nonce}}" -ne 36 ]; then exit 1; fi
namespace_proof_validated=1
JMT_PID_NAMESPACE_PROOF_TOKEN="{PROOF_PREFIX}${{inner_pid_namespace}}:${{namespace_pid_last}}:${{proof_nonce}}"
export JMT_PID_NAMESPACE_PROOF_TOKEN
exec "$unshare_path" --user --map-root-user --pid --fork --mount-proc sh -eu -c '
    exec {spec.cargo_invocation}
'
"""
    assert not audit_wrapper_text("self-test-wrapper", valid_wrapper, spec)
    assert audit_wrapper_text(
        "self-test-wrapper", valid_wrapper.replace("--locked", ""), spec
    )
    assert audit_wrapper_text(
        "self-test-wrapper", valid_wrapper.replace(PROOF_ENV, "OTHER_TOKEN"), spec
    )
    valid_declaration = f'''#[ignore]
fn {spec.test_name}() {{
    let namespace = std::fs::read_link("/proc/self/ns/pid").expect("namespace");
    let pid_one_namespace = std::fs::read_link("/proc/1/ns/pid").expect("pid one namespace");
    let status = std::fs::read_to_string("/proc/self/status").expect("status");
    let pid_one_status = std::fs::read_to_string("/proc/1/status").expect("pid one status");
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").expect("mountinfo");
    let uid_map = std::fs::read_to_string("/proc/self/uid_map").expect("uid map");
    let gid_map = std::fs::read_to_string("/proc/self/gid_map").expect("gid map");
    let nspid_fields = status;
    let pid_one_nspid = pid_one_status;
    assert_eq!(pid_one_nspid, "");
    let token = std::env::var("{PROOF_ENV}").expect("proof");
    let prefix = format!("{PROOF_PREFIX}{{}}:1:", namespace.display());
    let nonce = token.strip_prefix(&prefix).expect("opaque nonce");
    assert_eq!(nonce.len(), 36);
    let _namespace_proof_complete = token;
    {spec.destructive_marker};
}}
'''
    assert not audit_declaration_text(valid_declaration, spec)
    assert audit_declaration_text(valid_declaration.replace(PROOF_ENV, "OTHER_TOKEN"), spec)
    assert audit_declaration_text(
        valid_declaration.replace("let pid_one_nspid = pid_one_status;", "let pid_identity = pid_one_status;").replace(
            "assert_eq!(pid_one_nspid, \"\");", "assert_eq!(pid_identity, \"\");"
        ),
        spec,
    )
    assert PROOF_ENV in valid_declaration
    print("PID namespace wrapper static self-tests passed")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args == ["--self-test"]:
        return self_test()
    if args:
        print("usage: check-pid-namespace-wrappers.py [--self-test]", file=sys.stderr)
        return 2

    failures = [failure for path in WRAPPERS for failure in audit(path)]
    for path, spec in WRAPPER_SPECS.items():
        failures.extend(audit_declaration(spec.declaration_path, spec))
    if failures:
        print("PID namespace wrapper audit is incomplete (fail-closed):", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 78
    print("PID namespace wrapper audit passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
