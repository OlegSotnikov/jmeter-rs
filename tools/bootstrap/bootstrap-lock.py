#!/usr/bin/python3
"""Sanitized, race-free launcher for the project-local bootstrap."""

from __future__ import annotations

import contextlib
import fcntl
import io
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import NoReturn


TRUSTED_BASH = "/bin/bash"
SUPPORTED_OPTIONS = {"--check", "--self-test"}
LOCK_FD = 8
CAPABILITY_FD = 9
CAPABILITY_COOKIE = "jmeter-rs-bootstrap-capability-v1"
CAPABILITY_ARGUMENT = "--bootstrap-capability"
CAPABILITY_SELF_TEST_OPTION = "--bootstrap-capability-self-test"
CAPABILITY_NONCE_HEX_LENGTH = 64
CAPABILITY_RECORD_LENGTH = len(CAPABILITY_COOKIE) + 1 + CAPABILITY_NONCE_HEX_LENGTH
SAFE_ENV = {
    "HOME": "/tmp",
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/bin:/bin",
    "TMPDIR": "/tmp",
    "TZ": "UTC",
}


def fail(message: str) -> NoReturn:
    print(f"bootstrap error: {message}", file=sys.stderr)
    raise SystemExit(1)


def validate_system_bash() -> None:
    try:
        resolved = os.path.realpath(TRUSTED_BASH)
        info = os.stat(resolved)
    except OSError as error:
        fail(f"trusted Bash is unavailable: {error}")
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_mode & 0o22
    ):
        fail(f"trusted Bash is not a secure root-owned executable: {TRUSTED_BASH}")


def validate_cache_directory(path: str, description: str) -> None:
    try:
        info = os.lstat(path)
    except OSError as error:
        fail(f"{description} is unavailable: {error}")
    if stat.S_ISLNK(info.st_mode):
        fail(f"{description} must not be a symlink: {path}")
    if not stat.S_ISDIR(info.st_mode):
        fail(f"{description} is not a directory: {path}")
    if info.st_uid != os.getuid():
        fail(f"{description} is not owned by the current uid: {path}")
    if info.st_mode & 0o22:
        fail(
            f"{description} is group/world-writable (mode "
            f"{stat.S_IMODE(info.st_mode):o}); remediate it before bootstrap: {path}"
        )


def validate_lock_fd(lock_fd: int, lock_path: str) -> None:
    try:
        info = os.fstat(lock_fd)
        target = os.readlink(f"/proc/self/fd/{lock_fd}")
    except OSError as error:
        _close_fd(lock_fd)
        fail(f"could not inspect secure bootstrap lock: {error}")
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_mode & 0o22
        or target != lock_path
    ):
        os.close(lock_fd)
        fail(f"bootstrap lock descriptor is not the expected secure file: {lock_path}")


def validate_supported_host() -> None:
    try:
        operating_system = os.uname().sysname
        machine = os.uname().machine
    except OSError as error:
        fail(f"could not determine bootstrap host: {error}")
    if operating_system != "Linux" or machine != "x86_64":
        fail(
            "unsupported host: bootstrap currently supports Linux x86_64 only "
            f"(found {operating_system} {machine})"
        )


def create_bootstrap_capability() -> int:
    """Create the one-shot anonymous-pipe handoff consumed by Bash.

    This is an invocation protocol, not authentication: a same-uid caller
    can reproduce its fixed argument and bytes.  Safety comes from the
    trusted Python path/cache/lock preconditions and the Bash rechecks; there
    is deliberately no persistent secret.  The random nonce is transported
    only through the inherited anonymous pipe, never in argv or the
    environment.
    """

    nonce = os.urandom(32).hex()
    record = f"{CAPABILITY_COOKIE}:{nonce}".encode("ascii")
    read_fd, write_fd = os.pipe()
    try:
        view = memoryview(record)
        while view:
            written = os.write(write_fd, view)
            if written <= 0:
                fail("could not write bootstrap capability")
            view = view[written:]
    finally:
        os.close(write_fd)

    try:
        if read_fd != CAPABILITY_FD:
            os.dup2(read_fd, CAPABILITY_FD, inheritable=True)
            os.close(read_fd)
        else:
            os.set_inheritable(CAPABILITY_FD, True)
    except OSError:
        if read_fd != CAPABILITY_FD:
            os.close(read_fd)
        raise
    return CAPABILITY_FD


def capability_record(nonce: str) -> bytes:
    return f"{CAPABILITY_COOKIE}:{nonce}".encode("ascii")


def _install_fd(source_fd: int, target_fd: int) -> None:
    if source_fd != target_fd:
        os.dup2(source_fd, target_fd, inheritable=True)
        os.close(source_fd)
    else:
        os.set_inheritable(target_fd, True)


def _write_pipe_record(record: bytes | str) -> None:
    read_fd, write_fd = os.pipe()
    try:
        encoded = record.encode("ascii") if isinstance(record, str) else record
        view = memoryview(encoded)
        while view:
            written = os.write(write_fd, view)
            if written <= 0:
                raise AssertionError("bootstrap capability self-test pipe write stalled")
            view = view[written:]
    finally:
        os.close(write_fd)
    _install_fd(read_fd, CAPABILITY_FD)


def _close_capability_fd() -> None:
    try:
        os.close(CAPABILITY_FD)
    except OSError:
        pass


@contextlib.contextmanager
def _preserve_test_fds():
    saved_fds: dict[int, int] = {}
    for target_fd in (LOCK_FD, CAPABILITY_FD):
        try:
            saved_fds[target_fd] = os.dup(target_fd)
        except OSError:
            pass
    try:
        yield
    finally:
        for target_fd in (LOCK_FD, CAPABILITY_FD):
            try:
                os.close(target_fd)
            except OSError:
                pass
            saved_fd = saved_fds.get(target_fd)
            if saved_fd is not None:
                os.dup2(saved_fd, target_fd, inheritable=False)
                os.close(saved_fd)


def _run_capability_probe(
    payload: str,
    include_marker: bool,
    pass_capability_fd: bool,
    option: str | None = CAPABILITY_SELF_TEST_OPTION,
    pass_lock_fd: bool = False,
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    arguments = [TRUSTED_BASH, "--noprofile", "--norc", payload]
    if include_marker:
        arguments.append(CAPABILITY_ARGUMENT)
    if option is not None:
        arguments.append(option)
    pass_fds = tuple(
        target_fd
        for target_fd, included in (
            (LOCK_FD, pass_lock_fd),
            (CAPABILITY_FD, pass_capability_fd),
        )
        if included
    )
    return subprocess.run(
        arguments,
        env=SAFE_ENV if environment is None else environment,
        pass_fds=pass_fds,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )


def run_capability_self_test() -> None:
    """Exercise the Bash gate without touching the repository cache."""

    payload = os.path.abspath(os.path.join(os.path.dirname(__file__), "bootstrap.bash"))
    nonce = "00" * 32

    def expect_failure(completed: subprocess.CompletedProcess[str], description: str) -> None:
        if completed.returncode == 0:
            raise AssertionError(f"capability self-test accepted {description}")

    with _preserve_test_fds():
        _close_capability_fd()
        _close_fd(LOCK_FD)
        expect_failure(
            _run_capability_probe(payload, False, False),
            "a direct invocation without a marker",
        )
        expect_failure(
            _run_capability_probe(payload, True, False),
            "a marker without an inherited descriptor",
        )

        _write_pipe_record(b"wrong-cookie:" + nonce.encode("ascii"))
        expect_failure(
            _run_capability_probe(payload, True, True),
            "a spoofed pipe with the wrong cookie",
        )
        _write_pipe_record(f"{CAPABILITY_COOKIE}:not-a-nonce")
        expect_failure(
            _run_capability_probe(payload, True, True),
            "a spoofed pipe with a malformed nonce",
        )

        _close_capability_fd()
        partial_read_fd, partial_write_fd = os.pipe()
        try:
            os.write(partial_write_fd, capability_record(nonce)[:8])
            _install_fd(partial_read_fd, CAPABILITY_FD)
            expect_failure(
                _run_capability_probe(payload, True, True),
                "an incomplete capability pipe",
            )
        finally:
            _close_fd(partial_write_fd)
            _close_capability_fd()

        fifo_root = tempfile.mkdtemp(prefix="bootstrap-capability-fifo-")
        fifo_path = os.path.join(fifo_root, "capability")
        try:
            os.mkfifo(fifo_path, 0o600)
            fifo_fd = os.open(fifo_path, os.O_RDWR | os.O_NONBLOCK)
            try:
                os.write(fifo_fd, capability_record(nonce))
                _install_fd(fifo_fd, CAPABILITY_FD)
                expect_failure(
                    _run_capability_probe(payload, True, True),
                    "a named FIFO capability descriptor",
                )
            finally:
                _close_capability_fd()
        finally:
            shutil.rmtree(fifo_root, ignore_errors=True)

        _write_pipe_record(capability_record(nonce) + b"x")
        expect_failure(
            _run_capability_probe(payload, True, True),
            "a capability record with trailing bytes",
        )

        _write_pipe_record(capability_record(nonce))
        expect_failure(
            _run_capability_probe(payload, True, True, option=None),
            "a forged matching pair without the locked-cache precondition",
        )

        fake_lock_fd, fake_lock_path = tempfile.mkstemp(
            prefix="bootstrap-capability-fake-lock-",
            dir="/tmp",
        )
        os.close(fake_lock_fd)
        try:
            fake_lock_fd = os.open(fake_lock_path, os.O_RDONLY)
            _install_fd(fake_lock_fd, LOCK_FD)
            _write_pipe_record(capability_record(nonce))
            expect_failure(
                _run_capability_probe(
                    payload,
                    True,
                    True,
                    option=None,
                    pass_lock_fd=True,
                ),
                "a forged matching pair with an unrelated lock descriptor",
            )
        finally:
            _close_fd(LOCK_FD)
            os.unlink(fake_lock_path)

        _write_pipe_record(capability_record(nonce))
        accepted = _run_capability_probe(payload, True, True)
        if accepted.returncode != 0:
            raise AssertionError(
                "capability self-test rejected a valid inherited descriptor: "
                f"{accepted.stderr.strip()}"
            )
        expect_failure(
            _run_capability_probe(payload, True, True),
            "a reused (already-consumed) descriptor",
        )

        hostile_root = tempfile.mkdtemp(prefix="bootstrap-capability-env-")
        hostile_marker = os.path.join(hostile_root, "direct-bash-env-ran")
        hostile_env_file = os.path.join(hostile_root, "BASH_ENV")
        with open(hostile_env_file, "w", encoding="ascii") as handle:
            handle.write(f"printf hostile > {hostile_marker!r}\n")
        hostile_environment = dict(SAFE_ENV)
        hostile_environment["BASH_ENV"] = hostile_env_file
        hostile = subprocess.run(
            [TRUSTED_BASH, "--noprofile", "--norc", payload],
            env=hostile_environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if hostile.returncode == 0 or not os.path.isfile(hostile_marker):
            raise AssertionError(
                "direct Bash BASH_ENV behavior was not observed before the gate"
            )
        _write_pipe_record(capability_record(nonce))
        hostile_forged = _run_capability_probe(
            payload,
            True,
            True,
            option=None,
            environment=hostile_environment,
        )
        if hostile_forged.returncode == 0 or not os.path.isfile(hostile_marker):
            raise AssertionError(
                "hostile BASH_ENV plus a forged matching handoff bypassed safety"
            )
        safe_environment_probe = subprocess.run(
            [
                TRUSTED_BASH,
                "--noprofile",
                "--norc",
                "-c",
                "[[ -z ${BASH_ENV-} && -z ${ENV-} ]]",
            ],
            env=SAFE_ENV,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if safe_environment_probe.returncode != 0:
            raise AssertionError(
                "sanitized wrapper environment probe failed: "
                f"{safe_environment_probe.stderr.strip()}"
            )
        shutil.rmtree(hostile_root, ignore_errors=True)

        strace_path = next(
            (
                candidate
                for candidate in ("/usr/bin/strace", "/bin/strace")
                if os.path.isfile(candidate) and not os.path.islink(candidate)
            ),
            None,
        )
        if strace_path is not None:
            trace_fd, trace_file = tempfile.mkstemp(
                prefix="jmeter-bootstrap-capability-trace-",
                dir="/tmp",
            )
            os.close(trace_fd)
            try:
                _write_pipe_record(capability_record(nonce))
                traced = subprocess.run(
                    [
                        strace_path,
                        "-f",
                        "-e",
                        "trace=execve",
                        "-o",
                        trace_file,
                        TRUSTED_BASH,
                        "--noprofile",
                        "--norc",
                        payload,
                        CAPABILITY_ARGUMENT,
                    ],
                    env=SAFE_ENV,
                    pass_fds=(CAPABILITY_FD,),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                )
                if traced.returncode == 0:
                    raise AssertionError("forged no-lock trace unexpectedly succeeded")
                with open(trace_file, encoding="utf-8") as handle:
                    exec_events = [line for line in handle if "execve(" in line]
                if len(exec_events) != 1:
                    raise AssertionError(
                        "forged capability rejection executed an external command"
                    )
                if nonce in "".join(exec_events):
                    raise AssertionError("capability nonce appeared in the Bash argv")
            finally:
                _close_capability_fd()
                os.unlink(trace_file)

    print("bootstrap capability self-test passed")


def _close_fd(fd: int) -> None:
    try:
        os.close(fd)
    except OSError:
        pass


def open_and_lock(cache_root: str, check_mode: bool) -> int:
    lock_path = os.path.join(cache_root, ".bootstrap.lock")
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    flags = os.O_RDONLY if check_mode else os.O_RDWR | os.O_CREAT
    # O_NONBLOCK is set on open, before fstat, so a hostile named FIFO cannot
    # make lock acquisition wait for a peer.  fstat then rejects the FIFO as
    # a non-regular lock; flock is attempted only after that type check.
    flags |= (
        getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        cache_fd = os.open(cache_root, directory_flags)
    except OSError as error:
        fail(f"could not open secure repository cache directory: {error}")
    try:
        cache_info = os.fstat(cache_fd)
        if (
            not stat.S_ISDIR(cache_info.st_mode)
            or cache_info.st_uid != os.getuid()
            or cache_info.st_mode & 0o22
        ):
            fail(f"repository cache directory changed during lock acquisition: {cache_root}")
        lock_fd = os.open(".bootstrap.lock", flags, 0o600, dir_fd=cache_fd)
    except OSError as error:
        if check_mode and error.errno == 2:
            fail(f"bootstrap cache lock is missing in --check mode: {lock_path}")
        fail(f"could not open secure bootstrap cache lock: {error}")
    finally:
        os.close(cache_fd)
    try:
        validate_lock_fd(lock_fd, lock_path)
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as error:
        os.close(lock_fd)
        if error.errno in (11, 13):
            fail(f"another bootstrap process owns the repository cache lock: {lock_path}")
        fail(f"could not lock the repository cache atomically: {error}")
    os.set_inheritable(lock_fd, True)
    return lock_fd


def run_lock_self_test() -> None:
    root = tempfile.mkdtemp(prefix="bootstrap-lock-self-test-")
    empty = tempfile.mkdtemp(prefix="bootstrap-lock-check-")
    lock_path = os.path.join(root, ".bootstrap.lock")

    def expect_lock_failure(path: str, check_mode: bool) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            try:
                open_and_lock(path, check_mode)
            except SystemExit:
                return
        raise AssertionError("expected lock acquisition to fail")

    try:
        expect_lock_failure(empty, True)
        assert not os.path.lexists(os.path.join(empty, ".bootstrap.lock"))

        lock_fd = open_and_lock(root, False)
        info_before = os.stat(lock_path)
        child_pid = os.fork()
        if child_pid == 0:
            try:
                expect_lock_failure(root, False)
            except Exception:
                os._exit(1)
            else:
                os._exit(0)
        _, child_status = os.waitpid(child_pid, 0)
        assert os.WIFEXITED(child_status) and os.WEXITSTATUS(child_status) == 0
        os.close(lock_fd)

        check_fd = open_and_lock(root, True)
        info_after = os.stat(lock_path)
        assert (
            info_before.st_ino,
            info_before.st_size,
            info_before.st_mtime_ns,
        ) == (
            info_after.st_ino,
            info_after.st_size,
            info_after.st_mtime_ns,
        )
        os.close(check_fd)

        os.unlink(lock_path)
        os.mkfifo(lock_path, 0o600)
        expect_lock_failure(root, False)
        expect_lock_failure(root, True)

        os.unlink(lock_path)
        os.symlink("/tmp", lock_path)
        expect_lock_failure(root, False)
    finally:
        shutil.rmtree(root, ignore_errors=True)
        shutil.rmtree(empty, ignore_errors=True)
    print("bootstrap lock self-test passed")


def main() -> None:
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test-lock":
        run_lock_self_test()
        return
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test-capability":
        run_capability_self_test()
        return
    if len(sys.argv) < 2:
        fail("bootstrap implementation path is missing")
    payload = os.path.abspath(sys.argv[1])
    options = sys.argv[2:]
    if len(options) > 1 or (options and options[0] not in SUPPORTED_OPTIONS):
        fail("usage: bootstrap.sh [--check|--self-test]")
    launcher_dir = os.path.dirname(os.path.abspath(__file__))
    expected_payload = os.path.join(launcher_dir, "bootstrap.bash")
    if payload != expected_payload:
        fail(f"bootstrap implementation is not the repository payload: {payload}")
    try:
        payload_info = os.lstat(payload)
    except OSError as error:
        fail(f"bootstrap implementation is unavailable: {error}")
    if stat.S_ISLNK(payload_info.st_mode) or not stat.S_ISREG(payload_info.st_mode):
        fail(f"bootstrap implementation is not a regular file: {payload}")

    validate_system_bash()
    validate_supported_host()
    repo_root = os.path.abspath(os.path.join(launcher_dir, os.pardir, os.pardir))
    cache_root = os.path.join(repo_root, ".cache")
    lock_fd = -1
    if options != ["--self-test"]:
        if not os.path.lexists(cache_root):
            if options == ["--check"]:
                fail(f"repository cache directory is missing in --check mode: {cache_root}")
            try:
                os.mkdir(cache_root, 0o700)
            except FileExistsError:
                pass
        validate_cache_directory(cache_root, "repository cache directory")
        lock_fd = open_and_lock(cache_root, options == ["--check"])
        try:
            _install_fd(lock_fd, LOCK_FD)
        except OSError as error:
            fail(f"could not reserve inherited bootstrap lock descriptor: {error}")
        lock_fd = LOCK_FD
    else:
        # Do not inherit an unrelated caller descriptor in the test-only
        # mode.  It has no mutation authority and intentionally does not take
        # the repository lock.
        _close_fd(LOCK_FD)

    try:
        capability_fd = create_bootstrap_capability()
    except OSError as error:
        fail(f"could not establish bootstrap capability: {error}")

    argv = [
        TRUSTED_BASH,
        "--noprofile",
        "--norc",
        payload,
        CAPABILITY_ARGUMENT,
        *options,
    ]
    try:
        os.execve(TRUSTED_BASH, argv, SAFE_ENV)
    except OSError as error:
        os.close(capability_fd)
        if lock_fd >= 0:
            _close_fd(lock_fd)
        fail(f"could not start sanitized bootstrap: {error}")


if __name__ == "__main__":
    main()
