#!/usr/bin/env python3
"""Bounded loopback HTTP, HTTPS, and proxy fixture for the JMeter oracle.

The fixture deliberately has no dependency outside the Python standard
library.  It binds only to 127.0.0.1, accepts only explicitly requested
listeners, and permits proxy forwarding only to loopback origins named by the
runner.  The ready document contains a typed readiness object and ports but
never a PID: the runner owns the child handle and is responsible for its
bounded shutdown.

TLS certificates and keys are runtime inputs.  They belong below the run root,
are never generated into this repository, and are not copied into trace
events.  Trace output is bounded and contains protocol metadata only.
"""

from __future__ import annotations

import argparse
import base64
import http.server
import ipaddress
import json
import os
import select
import signal
import socket
import socketserver
import stat
import ssl
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, BinaryIO, Iterable
from urllib.parse import urlsplit


LOOPBACK_HOST = "127.0.0.1"
MIN_UNPRIVILEGED_PORT = 1024
MAX_PORT = 65535
EPHEMERAL_PORT = 0

MAX_REQUEST_LINE_BYTES = 8 * 1024
MAX_HEADER_BYTES = 64 * 1024
MAX_HEADER_COUNT = 128
MAX_TARGET_BYTES = 8 * 1024
MAX_BODY_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_RELAY_BYTES = 8 * 1024 * 1024
MAX_TRACE_BYTES = 2 * 1024 * 1024
MAX_READY_BYTES = 16 * 1024
MAX_WORKERS = 32
IO_TIMEOUT_SECONDS = 10.0
MAX_SESSION_SECONDS = 30.0
MAX_SHUTDOWN_GRACE_SECONDS = 5.0
MAX_SHUTDOWN_JOIN_SECONDS = IO_TIMEOUT_SECONDS
MAX_SECRET_BYTES = 4096
RELAY_CHUNK_BYTES = 16 * 1024


class FixtureError(ValueError):
    """A configuration or protocol error that must fail closed."""


class TraceFailure(FixtureError):
    """Trace output failed and the fixture must finish nonzero."""


class SessionExpired(FixtureError):
    """The one absolute deadline for a client session has elapsed."""


class GlobalFailure:
    """First-failure latch shared by every listener and worker."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._message: str | None = None
        self._stop_event = threading.Event()

    def fail(self, code: str, detail: str = "") -> None:
        with self._lock:
            if self._message is None:
                self._message = f"{code}:{detail}" if detail else code
        self._stop_event.set()

    def request_stop(self) -> None:
        self._stop_event.set()

    def wait(self) -> None:
        self._stop_event.wait()

    @property
    def failed(self) -> bool:
        with self._lock:
            return self._message is not None

    @property
    def message(self) -> str:
        with self._lock:
            return self._message or ""


class SessionDeadline:
    """An absolute monotonic deadline shared by handshake, I/O, and cleanup."""

    def __init__(self, deadline: float) -> None:
        self._deadline = deadline

    @classmethod
    def from_accept(cls) -> "SessionDeadline":
        return cls(time.monotonic() + MAX_SESSION_SECONDS)

    def remaining(self) -> float:
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise SessionExpired("session deadline exceeded")
        return remaining

    def apply(self, connection: socket.socket) -> float:
        remaining = self.remaining()
        connection.settimeout(min(IO_TIMEOUT_SECONDS, remaining))
        return remaining


class Trace:
    """Thread-safe, bounded JSON-lines sink with no secret-bearing fields."""

    def __init__(self, path: Path, failure: GlobalFailure) -> None:
        self._lock = threading.Lock()
        self._bytes = 0
        self._closed = False
        self._failure = failure
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            nofollow = getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(path, flags | nofollow, 0o600)
            try:
                self._file = os.fdopen(descriptor, "w", encoding="utf-8")
            except BaseException:
                os.close(descriptor)
                raise
        except FileExistsError as exc:
            raise FixtureError(f"trace path already exists: {path}") from exc
        except OSError as exc:
            raise FixtureError(f"cannot create trace path {path}: {exc.strerror}") from exc

    def _close_best_effort(self) -> None:
        try:
            self._file.flush()
        except (OSError, ValueError):
            pass
        try:
            self._file.close()
        except (OSError, ValueError):
            pass

    def write(self, event: dict[str, Any]) -> None:
        try:
            payload = (
                json.dumps(event, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
                + "\n"
            ).encode("utf-8")
        except (TypeError, ValueError, UnicodeError) as exc:
            self._failure.fail("trace-serialize", type(exc).__name__)
            raise TraceFailure("trace event serialization failed") from exc
        if len(payload) > MAX_TRACE_BYTES:
            self._failure.fail("trace-limit", "event")
            raise TraceFailure("single trace event exceeds fixture limit")
        with self._lock:
            if self._closed:
                self._failure.fail("trace-closed")
                raise TraceFailure("trace sink is closed")
            if self._bytes + len(payload) > MAX_TRACE_BYTES:
                self._closed = True
                self._close_best_effort()
                self._failure.fail("trace-limit", "output")
                raise TraceFailure("trace output exceeds fixture limit")
            try:
                self._file.write(payload.decode("utf-8"))
                self._file.flush()
            except (OSError, UnicodeError, ValueError) as exc:
                self._closed = True
                self._close_best_effort()
                self._failure.fail("trace-write", type(exc).__name__)
                raise TraceFailure("trace write failed") from exc
            self._bytes += len(payload)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            failure: OSError | ValueError | None = None
            try:
                self._file.flush()
            except (OSError, ValueError) as exc:
                failure = exc
            try:
                self._file.close()
            except (OSError, ValueError) as exc:
                if failure is None:
                    failure = exc
            if failure is not None:
                self._failure.fail("trace-close", type(failure).__name__)
                raise TraceFailure("trace close failed") from failure


class BoundedThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """Threaded server with an explicit connection/thread budget."""

    allow_reuse_address = False
    daemon_threads = False
    # The fixture performs its own bounded handler joins before close; the
    # ThreadingMixIn default would join unboundedly inside server_close().
    block_on_close = False
    request_queue_size = MAX_WORKERS

    def __init__(self, *args: Any, failure: GlobalFailure, **kwargs: Any) -> None:
        self.failure = failure
        self._worker_slots = threading.BoundedSemaphore(MAX_WORKERS)
        self._session_lock = threading.Lock()
        self._session_deadlines: dict[int, SessionDeadline] = {}
        self._active_lock = threading.Lock()
        self._active: dict[threading.Thread, socket.socket] = {}
        super().__init__(*args, **kwargs)

    def get_request(self) -> tuple[socket.socket, Any]:
        request, address = super().get_request()
        try:
            request.settimeout(IO_TIMEOUT_SECONDS)
            with self._session_lock:
                self._session_deadlines[id(request)] = SessionDeadline.from_accept()
        except OSError:
            request.close()
            raise
        return request, address

    def take_session_deadline(self, request: socket.socket) -> SessionDeadline:
        with self._session_lock:
            return self._session_deadlines.pop(id(request), SessionDeadline.from_accept())

    def drop_session_deadline(self, request: socket.socket) -> None:
        with self._session_lock:
            self._session_deadlines.pop(id(request), None)

    def process_request(self, request: socket.socket, client_address: Any) -> None:
        if not self._worker_slots.acquire(blocking=False):
            self.drop_session_deadline(request)
            request.close()
            return
        thread = threading.Thread(
            target=self.process_request_thread,
            args=(request, client_address),
            name="fixture-handler",
            daemon=self.daemon_threads,
        )
        with self._active_lock:
            self._active[thread] = request
        try:
            thread.start()
        except BaseException as exc:
            with self._active_lock:
                self._active.pop(thread, None)
            self.drop_session_deadline(request)
            self._worker_slots.release()
            request.close()
            self.failure.fail("handler-start", type(exc).__name__)
            raise

    def process_request_thread(self, request: socket.socket, client_address: Any) -> None:
        try:
            self.finish_request(request, client_address)
        except TraceFailure as exc:
            self.failure.fail("trace-handler", type(exc).__name__)
        except FixtureError:
            # Invalid protocol input, rejected TLS, and expired sessions are
            # fixture vectors, not global server failures.
            pass
        except Exception as exc:  # pragma: no cover - defensive lifecycle guard
            self.failure.fail("handler", type(exc).__name__)
        finally:
            try:
                self.shutdown_request(request)
            finally:
                self.drop_session_deadline(request)
                with self._active_lock:
                    self._active.pop(threading.current_thread(), None)
                self._worker_slots.release()

    def close_active_connections(self) -> None:
        with self._active_lock:
            requests = list(self._active.values())
        for request in requests:
            try:
                request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            finally:
                try:
                    request.close()
                except OSError:
                    pass

    def wait_for_handlers_until(self, deadline: float) -> bool:
        while True:
            with self._active_lock:
                threads = list(self._active)
            if not threads:
                return True
            for thread in threads:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                thread.join(remaining)

    def active_handler_count(self) -> int:
        with self._active_lock:
            return len(self._active)


def _trace_tls(connection: socket.socket) -> dict[str, Any] | None:
    if not isinstance(connection, ssl.SSLSocket):
        return None
    cipher = connection.cipher()
    return {
        "alpn": connection.selected_alpn_protocol() or "<none>",
        "cipher": cipher[0] if cipher else "<none>",
        "tls_version": connection.version() or "<none>",
    }


def _validate_text(value: str, field: str, maximum: int) -> str:
    if not value or len(value) > maximum:
        raise FixtureError(f"{field} is empty or exceeds {maximum} characters")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise FixtureError(f"{field} contains a control character")
    return value


def _validate_port(value: int | None, field: str) -> int | None:
    if value is None:
        return None
    if value == EPHEMERAL_PORT:
        return value
    if MIN_UNPRIVILEGED_PORT <= value <= MAX_PORT:
        return value
    raise FixtureError(
        f"{field} must be 0 (ephemeral) or {MIN_UNPRIVILEGED_PORT}-{MAX_PORT}"
    )


def _absolute_existing_directory(value: str) -> Path:
    _validate_text(value, "run root", 4096)
    raw = Path(value)
    if not raw.is_absolute():
        raw = Path.cwd() / raw
    _reject_symlink_components(raw, "run root")
    root = raw.resolve(strict=False)
    if not root.exists() or not root.is_dir():
        raise FixtureError(f"run root is not an existing directory: {root}")
    _require_private_owner(root, "run root", 0o700)
    return root


def _effective_uid() -> int:
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:
        raise FixtureError("fixture requires effective-UID ownership checks")
    return int(geteuid())


def _require_private_owner(path: Path, field: str, expected_mode: int) -> os.stat_result:
    metadata = os.stat(path, follow_symlinks=False)
    if not stat.S_ISDIR(metadata.st_mode) and expected_mode == 0o700:
        raise FixtureError(f"{field} must be a directory")
    if metadata.st_uid != _effective_uid():
        raise FixtureError(f"{field} is not owned by the effective user")
    if stat.S_IMODE(metadata.st_mode) != expected_mode:
        raise FixtureError(f"{field} must have mode {expected_mode:04o}")
    return metadata


def _path_below(root: Path, value: str, field: str, *, must_exist: bool) -> Path:
    _validate_text(value, field, 4096)
    raw = Path(value)
    candidate = raw if raw.is_absolute() else root / raw
    _reject_symlink_components(candidate, field)
    resolved = candidate.resolve(strict=False)
    try:
        relative = resolved.relative_to(root)
    except ValueError as exc:
        raise FixtureError(f"{field} must stay below run root") from exc
    if not relative.parts or relative.name in (".", ".."):
        raise FixtureError(f"{field} must name a file below run root")
    if must_exist and (not resolved.exists() or not resolved.is_file()):
        raise FixtureError(f"{field} is not an existing regular file: {resolved}")
    return resolved


def _reject_symlink_components(path: Path, field: str) -> None:
    """Reject symlinks in an input path before resolving it."""
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        if current.is_symlink():
            raise FixtureError(f"{field} contains a symlink")


def _material_path(root: Path, value: str, field: str) -> Path:
    return _path_below(root, value, field, must_exist=True)


def _read_secret_file(root: Path, value: str) -> str:
    path = _material_path(root, value, "proxy secret file")
    metadata = os.stat(path, follow_symlinks=False)
    if not stat.S_ISREG(metadata.st_mode):
        raise FixtureError("proxy secret file must be a regular file")
    if metadata.st_uid != _effective_uid() or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise FixtureError("proxy secret file must be effective-user-owned with mode 0600")
    if metadata.st_nlink != 1 or metadata.st_size > MAX_SECRET_BYTES:
        raise FixtureError("proxy secret file exceeds the bounded secret policy")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise FixtureError("proxy secret file cannot be opened safely") from exc
    try:
        reopened = os.fstat(fd)
        if (
            not stat.S_ISREG(reopened.st_mode)
            or reopened.st_uid != _effective_uid()
            or stat.S_IMODE(reopened.st_mode) != 0o600
            or reopened.st_nlink != 1
            or reopened.st_size > MAX_SECRET_BYTES
        ):
            raise FixtureError("proxy secret file changed ownership or mode")
        data = os.read(fd, MAX_SECRET_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) > MAX_SECRET_BYTES:
        raise FixtureError("proxy secret file exceeds the bounded secret policy")
    if data.endswith(b"\n"):
        data = data[:-1]
    try:
        secret = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FixtureError("proxy secret file is not UTF-8") from exc
    return _validate_secret(secret)


def _validate_secret(value: str) -> str:
    if not value or len(value.encode("utf-8")) > MAX_SECRET_BYTES:
        raise FixtureError("proxy secret is empty or exceeds the bounded limit")
    if any(char in value for char in "\r\n\x00"):
        raise FixtureError("proxy secret contains a forbidden delimiter")
    return value


def _validate_secret_env_name(value: str) -> str:
    if not value or len(value) > 64 or not (
        ("A" <= value[0] <= "Z")
        or ("a" <= value[0] <= "z")
        or value[0] == "_"
    ):
        raise FixtureError("proxy secret environment name is invalid")
    if any(
        char != "_"
        and not (
            ("A" <= char <= "Z")
            or ("a" <= char <= "z")
            or ("0" <= char <= "9")
        )
        for char in value
    ):
        raise FixtureError("proxy secret environment name is invalid")
    return value


def _read_secret_env(value: str) -> str:
    name = _validate_secret_env_name(value)
    secret = os.environ.get(name)
    if secret is None:
        raise FixtureError("proxy secret environment capability is unavailable")
    return _validate_secret(secret)


def _loopback_host(value: str) -> str:
    _validate_text(value, "upstream host", 128)
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise FixtureError("upstream host must be a numeric loopback address") from exc
    if not address.is_loopback:
        raise FixtureError("upstream host must be loopback")
    return address.compressed


def _port_text(value: str) -> int:
    if not value or any(char not in "0123456789" for char in value):
        raise FixtureError("upstream port must be decimal")
    if len(value) > len(str(MAX_PORT)):
        raise FixtureError("upstream port exceeds fixture limit")
    port = int(value)
    _validate_port(port, "upstream port")
    if port == EPHEMERAL_PORT:
        raise FixtureError("upstream port cannot be ephemeral")
    return port


def _split_authority(authority: str) -> tuple[str, int]:
    _validate_text(authority, "authority", 256)
    if authority.startswith("["):
        end = authority.find("]")
        if end < 0 or len(authority) <= end + 2 or authority[end + 1] != ":":
            raise FixtureError("IPv6 authority must be [address]:port")
        host = authority[1:end]
        port_text = authority[end + 2 :]
    else:
        host, separator, port_text = authority.rpartition(":")
        if not separator or not host or ":" in host:
            raise FixtureError("authority must be host:port")
    return _loopback_host(host), _port_text(port_text)


def _parse_request_line(raw_line: bytes) -> tuple[str, str, str]:
    if not raw_line.endswith(b"\r\n"):
        raise FixtureError("request line must end with CRLF")
    try:
        decoded = raw_line[:-2].decode("iso-8859-1")
    except UnicodeDecodeError as exc:
        raise FixtureError("request line is not ISO-8859-1") from exc
    parts = decoded.split(" ")
    if len(parts) != 3 or not all(parts):
        raise FixtureError("request line has invalid spacing")
    method, target, version = parts
    if len(method) > 16 or any(char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ-" for char in method):
        raise FixtureError("request method is invalid")
    if version not in ("HTTP/1.0", "HTTP/1.1"):
        raise FixtureError("unsupported HTTP version")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in target):
        raise FixtureError("request target contains a control character")
    if len(target.encode("iso-8859-1")) > MAX_TARGET_BYTES:
        raise FixtureError("request target exceeds fixture limit")
    return method, target, version


def _send_bytes(
    connection: socket.socket,
    payload: bytes,
    deadline: SessionDeadline,
) -> None:
    remaining = memoryview(payload)
    while remaining:
        deadline.apply(connection)
        sent = connection.send(remaining)
        if sent <= 0:
            raise ConnectionError("connection closed during bounded write")
        remaining = remaining[sent:]


def _read_line(
    stream: BinaryIO,
    connection: socket.socket,
    deadline: SessionDeadline,
    limit: int,
    *,
    allow_eof: bool = False,
) -> bytes:
    line = bytearray()
    while len(line) <= limit:
        deadline.apply(connection)
        chunk = stream.read1(1)
        if not chunk:
            if allow_eof and not line:
                return b""
            raise FixtureError("request line or header is truncated")
        line.extend(chunk)
        if len(line) > limit:
            raise FixtureError("request line or header exceeds fixture limit")
        if line.endswith(b"\r\n"):
            return bytes(line)
    raise FixtureError("request line or header exceeds fixture limit")


def _read_request(
    stream: BinaryIO,
    connection: socket.socket,
    deadline: SessionDeadline,
) -> tuple[str, str, str, dict[str, str], bytes]:
    raw_line = _read_line(
        stream,
        connection,
        deadline,
        MAX_REQUEST_LINE_BYTES,
        allow_eof=True,
    )
    if not raw_line:
        raise EOFError
    method, target, version = _parse_request_line(raw_line)
    headers: dict[str, str] = {}
    total = len(raw_line)
    while True:
        line = _read_line(stream, connection, deadline, MAX_HEADER_BYTES)
        if not line:
            raise FixtureError("headers are truncated")
        total += len(line)
        if total > MAX_HEADER_BYTES:
            raise FixtureError("headers exceed fixture limit")
        if line == b"\r\n":
            break
        if not line.endswith(b"\r\n") or b":" not in line:
            raise FixtureError("malformed header")
        name_bytes, value_bytes = line[:-2].split(b":", 1)
        try:
            name = name_bytes.decode("ascii").strip().lower()
            value = value_bytes.decode("iso-8859-1").strip()
        except UnicodeDecodeError as exc:
            raise FixtureError("header encoding is invalid") from exc
        if not name or any(char not in "!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyz" for char in name):
            raise FixtureError("header name is invalid")
        if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
            raise FixtureError("header value contains a control character")
        if name in headers:
            raise FixtureError("duplicate headers are not accepted by fixture")
        headers[name] = value
        if len(headers) > MAX_HEADER_COUNT:
            raise FixtureError("header count exceeds fixture limit")

    transfer_encoding = headers.get("transfer-encoding", "").lower()
    if transfer_encoding not in ("", "identity"):
        raise FixtureError("chunked or other transfer encoding is unsupported")
    content_length = headers.get("content-length", "0")
    if not content_length or any(char not in "0123456789" for char in content_length):
        raise FixtureError("content-length must be decimal")
    if len(content_length) > len(str(MAX_BODY_BYTES)):
        raise FixtureError("content-length exceeds fixture limit")
    body_length = int(content_length)
    if body_length > MAX_BODY_BYTES:
        raise FixtureError("request body exceeds fixture limit")
    body = bytearray()
    while len(body) < body_length:
        deadline.apply(connection)
        chunk = stream.read1(min(RELAY_CHUNK_BYTES, body_length - len(body)))
        if not chunk:
            raise FixtureError("request body is truncated")
        body.extend(chunk)
    return method, target, version, headers, bytes(body)


def _origin_path(target: str) -> tuple[str, bool]:
    if target == "*":
        return "/", False
    if not target.startswith("/"):
        raise FixtureError("origin request must use origin-form target")
    try:
        parsed = urlsplit(target)
    except ValueError as exc:
        raise FixtureError("origin request target is malformed") from exc
    path = parsed.path or "/"
    if len(path.encode("utf-8")) > MAX_TARGET_BYTES:
        raise FixtureError("origin path exceeds fixture limit")
    return path, bool(parsed.query)


def _wrap_tls(
    connection: socket.socket,
    context: ssl.SSLContext,
    deadline: SessionDeadline,
) -> ssl.SSLSocket:
    """Handshake with nonblocking readiness waits under one absolute deadline."""
    deadline.apply(connection)
    wrapped = context.wrap_socket(
        connection,
        server_side=True,
        do_handshake_on_connect=False,
    )
    try:
        wrapped.setblocking(False)
        while True:
            deadline.remaining()
            try:
                wrapped.do_handshake()
                break
            except ssl.SSLWantReadError:
                ready, _, _ = select.select([wrapped], [], [], deadline.remaining())
                if not ready:
                    raise SessionExpired("TLS handshake deadline exceeded")
            except ssl.SSLWantWriteError:
                _, ready, _ = select.select([], [wrapped], [], deadline.remaining())
                if not ready:
                    raise SessionExpired("TLS handshake deadline exceeded")
    except BaseException:
        try:
            wrapped.close()
        except OSError:
            pass
        raise
    try:
        wrapped.setblocking(True)
    except OSError:
        try:
            wrapped.close()
        except OSError:
            pass
        raise
    deadline.apply(wrapped)
    return wrapped


class DeadlineStreamRequestHandler(socketserver.StreamRequestHandler):
    """Request handler that performs TLS only after worker admission."""

    def setup(self) -> None:
        server = self.server
        self._deadline = server.take_session_deadline(self.request)
        context = getattr(server, "ssl_context", None)
        if context is not None:
            try:
                self.request = _wrap_tls(self.request, context, self._deadline)
            except (FixtureError, OSError, ssl.SSLError, ValueError) as exc:
                try:
                    self.request.close()
                except OSError:
                    pass
                raise FixtureError("TLS handshake rejected") from exc
        self._deadline.apply(self.request)
        super().setup()

    def finish(self) -> None:
        connection = getattr(self, "connection", self.request)
        if not hasattr(self, "wfile"):
            try:
                connection.close()
            except OSError:
                pass
            return
        try:
            self._deadline.apply(connection)
            super().finish()
        except (FixtureError, OSError, ssl.SSLError, ValueError):
            try:
                connection.close()
            except OSError:
                pass


class OriginHandler(DeadlineStreamRequestHandler):
    """Small origin with deterministic text, redirect, header, and binary routes."""

    def handle(self) -> None:
        trace: Trace = getattr(self.server, "trace")
        route_name = getattr(self.server, "route_name", "http")
        try:
            method, target, _version, headers, body = _read_request(
                self.rfile, self.connection, self._deadline
            )
            path, query_present = _origin_path(target)
            status, extra_headers, response = self._response(route_name, method, path)
            self._send_response(status, extra_headers, response, method, self._deadline)
            event: dict[str, Any] = {
                "body_length": len(body),
                "host": "<loopback>" if headers.get("host") else "<missing>",
                "kind": "origin_request",
                "method": method,
                "origin": route_name,
                "path": path,
                "query_present": query_present,
                "status": status,
            }
            tls = _trace_tls(self.connection)
            if tls is not None:
                event["tls"] = tls
            trace.write(event)
        except TraceFailure:
            raise
        except (EOFError, FixtureError, OSError, socket.timeout):
            return

    @staticmethod
    def _response(route_name: str, method: str, path: str) -> tuple[int, list[tuple[str, str]], bytes]:
        if method not in ("GET", "HEAD", "OPTIONS", "POST"):
            return 405, [("Allow", "GET, HEAD, OPTIONS, POST")], b"method-not-allowed\n"
        if path == "/redirect":
            return 302, [("Location", "/final")], b"redirect\n"
        if path == "/binary":
            return 200, [("Content-Type", "application/octet-stream")], b"\x00fixture\xff\n"
        if path == "/headers":
            return 200, [("X-Fixture-Header", "stable")], b"headers\n"
        body = f"jmeter-fixture:{route_name}:{path}\n".encode("utf-8")
        return 200, [("Content-Type", "text/plain; charset=utf-8")], body

    def _send_response(
        self,
        status: int,
        extra_headers: Iterable[tuple[str, str]],
        body: bytes,
        method: str,
        deadline: SessionDeadline,
    ) -> None:
        if len(body) > MAX_RESPONSE_BYTES:
            raise FixtureError("origin response exceeds fixture limit")
        reason = http.server.BaseHTTPRequestHandler.responses.get(status, ("",))[0]
        lines = [f"HTTP/1.1 {status} {reason}\r\n"]
        lines.extend(f"{name}: {value}\r\n" for name, value in extra_headers)
        lines.extend(
            [
                f"Content-Length: {len(body)}\r\n",
                "Connection: close\r\n",
                "\r\n",
            ]
        )
        payload = "".join(lines).encode("iso-8859-1")
        if method != "HEAD":
            payload += body
        _send_bytes(self.connection, payload, deadline)


class TLSHTTPServer(BoundedThreadingTCPServer):
    """Bounded server whose admitted handlers perform TLS handshakes."""

    def __init__(
        self,
        address: tuple[str, int],
        handler: type[socketserver.BaseRequestHandler],
        context: ssl.SSLContext,
        trace: Trace,
        route_name: str,
        failure: GlobalFailure,
    ) -> None:
        self.ssl_context = context
        self.trace = trace
        self.route_name = route_name
        super().__init__(address, handler, failure=failure)


class ProxyHandler(DeadlineStreamRequestHandler):
    """HTTP proxy supporting absolute-form HTTP and bounded CONNECT tunnels."""

    def handle(self) -> None:
        server = self.server
        trace: Trace = getattr(server, "trace")
        proxy_user = getattr(server, "proxy_user", "")
        proxy_secret = getattr(server, "proxy_secret", "")
        try:
            method, target, _version, headers, body = _read_request(
                self.rfile, self.connection, self._deadline
            )
            auth_state = self._auth_state(headers, proxy_user, proxy_secret)
            if proxy_user and auth_state != "valid":
                self._send_proxy_auth_required(self._deadline)
                self._record(
                    trace,
                    {
                        "form": "connect" if method == "CONNECT" else "absolute",
                        "kind": "proxy_request",
                        "method": method,
                        "proxy_auth": auth_state,
                        "status": 407,
                        "target": self._redact_target(target),
                    },
                )
                return
            if method == "CONNECT":
                if body:
                    raise FixtureError("CONNECT requests cannot contain a body")
                self._connect(target, auth_state, trace, self._deadline)
            else:
                self._forward_http(
                    method, target, headers, body, auth_state, trace, self._deadline
                )
        except (EOFError, BrokenPipeError, ConnectionResetError, OSError, socket.timeout):
            return
        except TraceFailure:
            raise
        except FixtureError as exc:
            self._record(
                trace,
                {"error_code": type(exc).__name__, "kind": "proxy_error"},
            )

    @staticmethod
    def _record(trace: Trace, event: dict[str, Any]) -> None:
        trace.write(event)

    @staticmethod
    def _auth_state(headers: dict[str, str], username: str, secret: str) -> str:
        value = headers.get("proxy-authorization", "")
        if not value:
            return "absent"
        if not value.lower().startswith("basic "):
            return "invalid"
        try:
            decoded = base64.b64decode(value[6:].strip(), validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return "invalid"
        expected = f"{username}:{secret}"
        return "valid" if decoded == expected else "invalid"

    def _send_proxy_auth_required(self, deadline: SessionDeadline) -> None:
        _send_bytes(
            self.connection,
            b"HTTP/1.1 407 Proxy Authentication Required\r\n"
            b"Proxy-Authenticate: Basic realm=fixture\r\n"
            b"Content-Length: 0\r\n"
            b"Connection: close\r\n\r\n",
            deadline,
        )

    @staticmethod
    def _redact_target(target: str) -> str:
        if "@" in target:
            return "<redacted-target>"
        try:
            if "://" in target:
                parsed = urlsplit(target)
                if parsed.username or parsed.password:
                    return "<redacted-target>"
                path = parsed.path or "/"
                return f"{parsed.scheme}://<loopback>{path}"
            if ":" in target:
                _host, _port = target.rsplit(":", 1)
                return "<loopback>:<ephemeral-port>"
        except ValueError:
            pass
        return "<invalid-target>"

    def _allowed(self, host: str, port: int) -> None:
        allowed: set[tuple[str, int]] = getattr(self.server, "allowed_upstreams", set())
        if (host, port) not in allowed:
            raise FixtureError("upstream is not in the explicit loopback allowlist")

    def _connect(
        self,
        target: str,
        auth_state: str,
        trace: Trace,
        deadline: SessionDeadline,
    ) -> None:
        host, port = _split_authority(target)
        self._allowed(host, port)
        upstream = socket.create_connection((host, port), timeout=deadline.remaining())
        try:
            _send_bytes(
                self.connection,
                b"HTTP/1.1 200 Connection Established\r\n"
                b"Proxy-Agent: jmeter-rs-fixture\r\n"
                b"\r\n",
                deadline,
            )
            deadline.apply(upstream)
            to_upstream, to_client = self._relay(upstream, deadline)
            self._record(
                trace,
                {
                    "bytes_to_client": to_client,
                    "bytes_to_upstream": to_upstream,
                    "kind": "proxy_connect",
                    "proxy_auth": auth_state,
                    "status": 200,
                    "target_host": "<loopback>",
                    "target_port": "<ephemeral-port>",
                },
            )
        finally:
            upstream.close()

    def _forward_http(
        self,
        method: str,
        target: str,
        headers: dict[str, str],
        body: bytes,
        auth_state: str,
        trace: Trace,
        deadline: SessionDeadline,
    ) -> None:
        try:
            parsed = urlsplit(target)
            scheme = parsed.scheme.lower()
            host = parsed.hostname
            if scheme not in ("http", "https") or not host or parsed.username or parsed.password:
                raise FixtureError("proxy requires an absolute HTTP URL")
            host = _loopback_host(host)
            if parsed.port == 0:
                raise FixtureError("proxy target port cannot be zero")
            port = parsed.port or (443 if scheme == "https" else 80)
        except ValueError as exc:
            raise FixtureError("proxy target URL is malformed") from exc
        self._allowed(host, port)
        if scheme == "https":
            _send_bytes(
                self.connection,
                b"HTTP/1.1 400 CONNECT required\r\n"
                b"Content-Length: 0\r\n"
                b"Connection: close\r\n\r\n",
                deadline,
            )
            self._record(
                trace,
                {
                    "form": "absolute",
                    "kind": "proxy_http",
                    "method": method,
                    "path": parsed.path or "/",
                    "proxy_auth": auth_state,
                    "query_present": bool(parsed.query),
                    "response_status": 400,
                    "status": 400,
                },
            )
            return
        upstream = socket.create_connection((host, port), timeout=deadline.remaining())
        try:
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
            if len(path.encode("utf-8")) > MAX_TARGET_BYTES:
                raise FixtureError("proxy target path exceeds fixture limit")
            outgoing = [f"{method} {path} HTTP/1.1\r\n"]
            hop_by_hop = {
                "connection",
                "keep-alive",
                "proxy-authorization",
                "proxy-connection",
                "te",
                "trailer",
                "transfer-encoding",
                "upgrade",
            }
            for name, value in headers.items():
                if name in hop_by_hop:
                    continue
                outgoing.append(f"{name}: {value}\r\n")
            outgoing.extend(["Connection: close\r\n", "\r\n"])
            _send_bytes(
                upstream,
                "".join(outgoing).encode("iso-8859-1") + body,
                deadline,
            )
            response_status = self._copy_until_close(upstream, deadline)
            self._record(
                trace,
                {
                    "body_length": len(body),
                    "form": "absolute",
                    "kind": "proxy_http",
                    "method": method,
                    "path": parsed.path or "/",
                    "proxy_auth": auth_state,
                    "query_present": bool(parsed.query),
                    "response_status": response_status,
                    "status": response_status,
                },
            )
        finally:
            upstream.close()

    @staticmethod
    def _status_from_first_chunk(data: bytes) -> int | None:
        line = data.split(b"\r\n", 1)[0]
        parts = line.split(b" ", 2)
        if len(parts) < 2 or not parts[1].isdigit():
            return None
        status = int(parts[1])
        return status if 100 <= status <= 599 else None

    def _copy_until_close(
        self, upstream: socket.socket, deadline: SessionDeadline
    ) -> int | None:
        total = 0
        status: int | None = None
        status_buffer = bytearray()
        while True:
            deadline.apply(upstream)
            data = upstream.recv(RELAY_CHUNK_BYTES)
            if not data:
                return status
            total += len(data)
            if total > MAX_RESPONSE_BYTES:
                raise FixtureError("proxied response exceeds fixture limit")
            if status is None and len(status_buffer) <= MAX_REQUEST_LINE_BYTES:
                remaining = MAX_REQUEST_LINE_BYTES - len(status_buffer)
                status_buffer.extend(data[:remaining])
                if b"\r\n" in status_buffer:
                    status = self._status_from_first_chunk(bytes(status_buffer))
            _send_bytes(self.connection, data, deadline)

    def _relay(self, upstream: socket.socket, deadline: SessionDeadline) -> tuple[int, int]:
        sockets = [self.connection, upstream]
        to_upstream = 0
        to_client = 0
        while True:
            ready, _, _ = select.select(sockets, [], [], deadline.remaining())
            if not ready:
                raise SessionExpired("CONNECT relay session deadline exceeded")
            for source in ready:
                destination = upstream if source is self.connection else self.connection
                deadline.apply(source)
                data = source.recv(RELAY_CHUNK_BYTES)
                if not data:
                    return to_upstream, to_client
                if source is self.connection:
                    to_upstream += len(data)
                    if to_upstream > MAX_RELAY_BYTES:
                        raise FixtureError("client-to-upstream relay exceeds fixture limit")
                else:
                    to_client += len(data)
                    if to_client > MAX_RELAY_BYTES:
                        raise FixtureError("upstream-to-client relay exceeds fixture limit")
                _send_bytes(destination, data, deadline)


def _build_server_context(cert: Path, key: Path, client_ca: Path | None) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(["http/1.1"])
    context.load_cert_chain(certfile=cert, keyfile=key)
    if client_ca is not None:
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=client_ca)
    return context


def _serve(server: socketserver.TCPServer, failure: GlobalFailure) -> None:
    """Run a listener and convert an unexpected loop failure into shutdown."""
    try:
        server.serve_forever()
    except Exception as exc:  # pragma: no cover - defensive lifecycle guard
        failure.fail("listener", type(exc).__name__)


def _start_http_origin(
    port: int, trace: Trace, failure: GlobalFailure
) -> BoundedThreadingTCPServer:
    server = BoundedThreadingTCPServer((LOOPBACK_HOST, port), OriginHandler, failure=failure)
    server.trace = trace
    server.route_name = "http"
    threading.Thread(
        target=_serve, args=(server, failure), name="fixture-http", daemon=True
    ).start()
    return server


def _start_tls_origin(
    port: int,
    trace: Trace,
    cert: Path,
    key: Path,
    client_ca: Path | None,
    failure: GlobalFailure,
) -> TLSHTTPServer:
    context = _build_server_context(cert, key, client_ca)
    server = TLSHTTPServer(
        (LOOPBACK_HOST, port), OriginHandler, context, trace, "https", failure
    )
    threading.Thread(
        target=_serve, args=(server, failure), name="fixture-https", daemon=True
    ).start()
    return server


def _start_proxy(
    port: int,
    trace: Trace,
    allowed_upstreams: set[tuple[str, int]],
    proxy_user: str,
    proxy_secret: str,
    failure: GlobalFailure,
    cert: Path | None = None,
    key: Path | None = None,
) -> socketserver.TCPServer:
    if (cert is None) != (key is None):
        raise FixtureError("TLS proxy requires both certificate and key")
    if cert is not None and key is not None:
        context = _build_server_context(cert, key, None)
        server: socketserver.TCPServer = TLSProxyServer(
            (LOOPBACK_HOST, port),
            ProxyHandler,
            context,
            trace,
            allowed_upstreams,
            proxy_user,
            proxy_secret,
            failure,
        )
    else:
        server = BoundedThreadingTCPServer(
            (LOOPBACK_HOST, port), ProxyHandler, failure=failure
        )
        server.trace = trace
        server.allowed_upstreams = allowed_upstreams
        server.proxy_user = proxy_user
        server.proxy_secret = proxy_secret
    threading.Thread(
        target=_serve, args=(server, failure), name="fixture-proxy", daemon=True
    ).start()
    return server


class TLSProxyServer(TLSHTTPServer):
    def __init__(
        self,
        address: tuple[str, int],
        handler: type[socketserver.BaseRequestHandler],
        context: ssl.SSLContext,
        trace: Trace,
        allowed_upstreams: set[tuple[str, int]],
        proxy_user: str,
        proxy_secret: str,
        failure: GlobalFailure,
    ) -> None:
        self.allowed_upstreams = allowed_upstreams
        self.proxy_user = proxy_user
        self.proxy_secret = proxy_secret
        super().__init__(address, handler, context, trace, "proxy", failure)


def _publish_ready(path: Path, servers: dict[str, socketserver.TCPServer]) -> None:
    try:
        os.lstat(path)
    except FileNotFoundError:
        pass
    else:
        raise FixtureError("ready path already exists; use a fresh run root")
    record = {
        "limits": {
            "max_request_line_bytes": MAX_REQUEST_LINE_BYTES,
            "max_target_bytes": MAX_TARGET_BYTES,
            "max_body_bytes": MAX_BODY_BYTES,
            "max_header_bytes": MAX_HEADER_BYTES,
            "max_header_count": MAX_HEADER_COUNT,
            "max_relay_bytes": MAX_RELAY_BYTES,
            "max_relay_chunk_bytes": RELAY_CHUNK_BYTES,
            "max_response_bytes": MAX_RESPONSE_BYTES,
            "max_trace_bytes": MAX_TRACE_BYTES,
            "max_ready_bytes": MAX_READY_BYTES,
            "max_secret_bytes": MAX_SECRET_BYTES,
            "max_session_seconds": MAX_SESSION_SECONDS,
            "max_workers": MAX_WORKERS,
            "io_timeout_seconds": IO_TIMEOUT_SECONDS,
            "shutdown_grace_seconds": MAX_SHUTDOWN_GRACE_SECONDS,
            "shutdown_join_seconds": MAX_SHUTDOWN_JOIN_SECONDS,
        },
        "ports": {name: int(server.server_address[1]) for name, server in sorted(servers.items())},
        "readiness": {
            "protocol": "jmeter-rs.proxy-tls-ready",
            "listener_names": sorted(servers),
            "published_after": "all-requested-listeners-bound",
            "host": LOOPBACK_HOST,
            "ports_source": "ports",
            "atomic_rename": True,
            "pid_authority": False,
            "process_authority": "parent-owned-exact-child-handle",
            "stale_file_policy": "runner supplies a fresh private run root and absent ready path",
        },
        "schema_id": "jmeter-rs.proxy-tls-ready",
        "schema_version": 1,
        "host": LOOPBACK_HOST,
    }
    payload = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(payload) > MAX_READY_BYTES:
        raise FixtureError("ready document exceeds fixture limit")
    temporary_path: str | None = None
    descriptor: int | None = None
    try:
        descriptor, temporary_path = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as ready:
            descriptor = None
            ready.write(payload)
            ready.flush()
            os.fsync(ready.fileno())
        os.replace(temporary_path, path)
        temporary_path = None
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        directory_descriptor = os.open(path.parent, directory_flags)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except OSError as exc:
        raise FixtureError("cannot atomically publish ready document") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary_path is not None:
            try:
                os.unlink(temporary_path)
            except OSError:
                pass


def _requested_ports(args: argparse.Namespace) -> dict[str, int]:
    values = {
        "http": _validate_port(args.http_port, "--http-port"),
        "https": _validate_port(args.https_port, "--https-port"),
        "proxy": _validate_port(args.proxy_port, "--proxy-port"),
        "proxy_tls": _validate_port(args.proxy_tls_port, "--proxy-tls-port"),
    }
    requested = {name: port for name, port in values.items() if port is not None}
    if not requested:
        raise FixtureError("at least one listener port must be requested")
    explicit = [port for port in requested.values() if port != EPHEMERAL_PORT]
    if len(explicit) != len(set(explicit)):
        raise FixtureError("listener ports must be distinct")
    return requested


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", required=True, help="existing allowlisted temporary directory")
    parser.add_argument("--ready-file", default="ready.json")
    parser.add_argument("--trace-file", default="trace.jsonl")
    parser.add_argument("--http-port", type=int)
    parser.add_argument("--https-port", type=int)
    parser.add_argument("--proxy-port", type=int)
    parser.add_argument("--proxy-tls-port", type=int)
    parser.add_argument("--server-cert")
    parser.add_argument("--server-key")
    parser.add_argument("--expired-cert")
    parser.add_argument("--expired-key")
    parser.add_argument("--mismatch-cert")
    parser.add_argument("--mismatch-key")
    parser.add_argument("--client-ca")
    parser.add_argument("--proxy-cert")
    parser.add_argument("--proxy-key")
    parser.add_argument("--allow-upstream", action="append", default=[])
    parser.add_argument("--proxy-user", default="")
    secret_group = parser.add_mutually_exclusive_group()
    secret_group.add_argument("--proxy-secret-file")
    secret_group.add_argument("--proxy-secret-env")
    parser.add_argument("--tls-cert-kind", choices=("valid", "expired", "mismatch"), default="valid")
    parser.add_argument("--require-client-cert", action="store_true")
    return parser.parse_args(argv)


def _shutdown(servers: dict[str, socketserver.TCPServer], failure: GlobalFailure) -> None:
    for server in reversed(list(servers.values())):
        try:
            server.shutdown()
        except OSError as exc:
            failure.fail("listener-shutdown", type(exc).__name__)
    graceful_deadline = time.monotonic() + MAX_SHUTDOWN_GRACE_SECONDS
    bounded_servers = [server for server in servers.values() if isinstance(server, BoundedThreadingTCPServer)]
    for server in bounded_servers:
        if not server.wait_for_handlers_until(graceful_deadline):
            server.close_active_connections()
    join_deadline = time.monotonic() + MAX_SHUTDOWN_JOIN_SECONDS
    for server in bounded_servers:
        if not server.wait_for_handlers_until(join_deadline):
            failure.fail("handler-shutdown-timeout")
    for server in reversed(list(servers.values())):
        server.server_close()


def main(argv: list[str]) -> int:
    failure = GlobalFailure()
    try:
        args = parse_args(argv)
        root = _absolute_existing_directory(args.run_root)
        ready_path = _path_below(root, args.ready_file, "ready file", must_exist=False)
        trace_path = _path_below(root, args.trace_file, "trace file", must_exist=False)
        requested = _requested_ports(args)
        secret_requested = args.proxy_secret_file is not None or args.proxy_secret_env is not None
        if bool(args.proxy_user) != secret_requested:
            raise FixtureError("proxy username and one explicit secret capability are required together")
        proxy_user = _validate_text(args.proxy_user, "proxy username", 128) if args.proxy_user else ""
        if args.proxy_secret_file is not None:
            proxy_secret = _read_secret_file(root, args.proxy_secret_file)
        elif args.proxy_secret_env is not None:
            proxy_secret = _read_secret_env(args.proxy_secret_env)
        else:
            proxy_secret = ""
        if args.require_client_cert and not args.client_ca:
            raise FixtureError("--require-client-cert requires --client-ca")
        trace = Trace(trace_path, failure)
        servers: dict[str, socketserver.TCPServer] = {}
        try:
            # Start origins first so their actual ephemeral ports become the
            # default proxy allowlist.  Extra entries remain explicit and
            # loopback-only; DNS and public network destinations are rejected.
            if "http" in requested:
                servers["http"] = _start_http_origin(requested["http"], trace, failure)
            if "https" in requested:
                cert_value = {
                    "valid": args.server_cert,
                    "expired": args.expired_cert,
                    "mismatch": args.mismatch_cert,
                }[args.tls_cert_kind]
                key_value = {
                    "valid": args.server_key,
                    "expired": args.expired_key,
                    "mismatch": args.mismatch_key,
                }[args.tls_cert_kind]
                if not cert_value or not key_value:
                    raise FixtureError("HTTPS origin requires the selected certificate and key")
                cert = _material_path(root, cert_value, "server certificate")
                key = _material_path(root, key_value, "server key")
                client_ca = _material_path(root, args.client_ca, "client CA") if args.require_client_cert else None
                servers["https"] = _start_tls_origin(
                    requested["https"], trace, cert, key, client_ca, failure
                )

            allowed: set[tuple[str, int]] = {
                (LOOPBACK_HOST, int(server.server_address[1]))
                for name, server in servers.items()
                if name in ("http", "https")
            }
            allowed.update(_split_authority(value) for value in args.allow_upstream)
            if "proxy" in requested:
                servers["proxy"] = _start_proxy(
                    requested["proxy"], trace, allowed, proxy_user, proxy_secret, failure
                )
            if "proxy_tls" in requested:
                if not args.proxy_cert or not args.proxy_key:
                    raise FixtureError("TLS proxy requires --proxy-cert and --proxy-key")
                proxy_cert = _material_path(root, args.proxy_cert, "proxy certificate")
                proxy_key = _material_path(root, args.proxy_key, "proxy key")
                servers["proxy_tls"] = _start_proxy(
                    requested["proxy_tls"],
                    trace,
                    allowed,
                    proxy_user,
                    proxy_secret,
                    failure,
                    proxy_cert,
                    proxy_key,
                )
            _publish_ready(ready_path, servers)

            def stop_handler(_signum: int, _frame: Any) -> None:
                failure.request_stop()

            signal.signal(signal.SIGTERM, stop_handler)
            signal.signal(signal.SIGINT, stop_handler)
            failure.wait()
        finally:
            _shutdown(servers, failure)
            try:
                trace.close()
            except TraceFailure:
                pass
        return 1 if failure.failed else 0
    except (FixtureError, OSError, ssl.SSLError) as exc:
        if failure.failed:
            print("fixture failed: global failure latched", file=sys.stderr)
            return 1
        print(f"fixture configuration error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
