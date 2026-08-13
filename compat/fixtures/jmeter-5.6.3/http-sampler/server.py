#!/usr/bin/env python3
"""Bounded loopback HTTP fixture for the ELEM-001 oracle corpus.

Only Python's standard library is used.  The server binds to the explicit
loopback address, writes bounded JSON objects for accepted requests, and
exposes fixed response bodies/statuses for the sampler cases.  It never makes
an outbound request and does not consult proxy environment variables.  The
runner supplies a finite request budget; once that budget is completed the
server asks its own ``serve_forever`` loop to stop and closes normally.  No
PID, process name, signal, shell, or process-group operation is used here.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import socket
import struct
import sys
import tempfile
import threading
import time
import zlib
from http import HTTPStatus
from http import client as http_client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable, Iterable
from urllib.parse import parse_qs, parse_qsl, urlsplit


LOOPBACK_HOST = "127.0.0.1"
EPHEMERAL_PORT = 0
MIN_PORT = 1024
MAX_PORT = 65535
# BaseHTTPRequestHandler passes the stream to http.client.parse_headers,
# whose `_MAXLINE` is 65,536 and whose readline call probes one extra byte;
# `_MAXHEADERS` is 100.  These are imported as explicit constants below so
# ready metadata and post-parse checks cannot claim a larger preparse budget.
PREPARSE_MAX_LINE_BYTES = http_client._MAXLINE
PREPARSE_READLINE_LIMIT_BYTES = PREPARSE_MAX_LINE_BYTES + 1
PREPARSE_MAX_HEADER_COUNT = http_client._MAXHEADERS
MAX_REQUESTS = 10_000
MAX_BODY = 1 << 20
MAX_REQUEST_LINE = PREPARSE_MAX_LINE_BYTES - 2  # exclude the mandatory CRLF
MAX_TARGET = 8 << 10
MAX_HEADER_BYTES = PREPARSE_MAX_LINE_BYTES * PREPARSE_MAX_HEADER_COUNT
MAX_HEADER_COUNT = PREPARSE_MAX_HEADER_COUNT
MAX_CHUNK_LINE = 128
MAX_CHUNKS = 1024
MAX_TRAILER_BYTES = MAX_CHUNK_LINE * MAX_HEADER_COUNT
MAX_TRACE_EVENT = 2 << 20
MAX_TRACE_BYTES = 8 << 20
MAX_READY_BYTES = 16 << 10
MAX_OUTCOME_BYTES = 16 << 10
MAX_WORKERS = 32
MAX_RESPONSE_HEADER_FIELDS = 128
MAX_RESPONSE_HEADER_BYTES = 64 << 10
MAX_QUERY_FIELDS = 128
MAX_FORM_FIELDS = 16
MAX_MULTIPART_FIELDS = 2
ENTITY_FIELD_LIMIT_STATUS = 413
REQUEST_TIMEOUT_SECONDS = 10.0
TIMEOUT_DELAY_SECONDS = 0.45
SAMPLER_TIMEOUT_MS = 100
READINESS_TIMEOUT_MS = 10_000
IDLE_TIMEOUT_MIN_MS = 100
IDLE_TIMEOUT_MAX_MS = 300_000
DEFAULT_IDLE_TIMEOUT_MS = 5_000
SESSION_TIMEOUT_MIN_MS = 1_000
SESSION_TIMEOUT_MAX_MS = 600_000
DEFAULT_SESSION_TIMEOUT_MS = 30_000
REDIRECT_CODES = frozenset((301, 302, 303, 307, 308))
TRACE_SAFE_PATHS = frozenset(
    (
        "/ok",
        "/echo",
        "/headers",
        "/status/399",
        "/status/400",
        "/chunked",
        "/close",
        "/reuse",
        "/gzip",
        "/deflate",
        "/encoding/utf8",
        "/encoding/latin1",
        "/partial",
        "/redirect/301",
        "/redirect/302",
        "/redirect/303",
        "/redirect/307",
        "/redirect/308",
        "/reset",
        "/timeout",
        "/redirect-target",
        "/html",
        "/style.css",
        "/asset.png",
        "/asset.svg",
    )
)
TRACE_SAFE_HEADERS = frozenset(
    (
        "accept",
        "accept-encoding",
        "connection",
        "content-length",
        "content-type",
        "host",
        "transfer-encoding",
        "x-oracle-duplicate",
    )
)
TRACE_RESPONSE_HEADERS = frozenset(
    (
        "connection",
        "content-encoding",
        "content-length",
        "content-type",
        "location",
        "transfer-encoding",
        "x-oracle",
        "x-oracle-body-length",
    )
)
TOKEN_RE = re.compile(rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
MULTIPART_FIELD_HEADER_RE = re.compile(
    rb"(?:\A|\r\n)Content-Disposition[ \t]*:",
    re.IGNORECASE,
)
FORBIDDEN_TRAILER_NAMES = frozenset(
    (
        b"content-length",
        b"host",
        b"trailer",
        b"transfer-encoding",
    )
)
SENSITIVE_HEADER_RE = re.compile(
    r"(?:authorization|proxy-authorization|cookie|set-cookie|token|secret|password|credential|api[-_]?key|session)",
    re.IGNORECASE,
)
TEXT = b"http-sampler-oracle"
HTML = (
    b"<!doctype html><html><head><link rel=\"stylesheet\" href=\"/style.css\">"
    b"</head><body><img src=\"/asset.png\"><p>embedded-resource</p></body></html>"
)
CSS = b"body{background:url('/asset.svg');color:#123456}"
PNG = bytes.fromhex("89504e470d0a1a0a0000000d4948445200000001000000010802000000907753de")
SVG = b"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"1\" height=\"1\"></svg>"
UTF8 = "caf\u00e9 \u2603".encode("utf-8")
LATIN1 = "caf\u00e9".encode("iso-8859-1")
GZIP_BODY = b"compressed-http-sampler-body"
MULTIPART_FIELD_NAMES = frozenset(("part-one", "part-two"))
FORM_FIELD_VALUES = {"first": "alpha beta", "second": "two"}
MULTIPART_FIELD_VALUES = {"part-one": "one", "part-two": "two"}


class RequestLimitError(ValueError):
    """A malformed or over-budget request that must be rejected."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message.encode("ascii")


class TraceLimitError(RequestLimitError):
    """The bounded trace sink cannot accept another request event."""

    def __init__(self, message: str = "trace limit exceeded") -> None:
        super().__init__(507, message)


def bounded_port(value: str) -> int:
    """Parse port zero or one explicitly assigned unprivileged TCP port."""

    if re.fullmatch(r"[0-9]+", value) is None:
        raise argparse.ArgumentTypeError("port must be an ASCII decimal integer")
    try:
        port = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be a decimal integer") from exc
    if port != EPHEMERAL_PORT and not MIN_PORT <= port <= MAX_PORT:
        raise argparse.ArgumentTypeError(
            f"port must be 0 or between {MIN_PORT} and {MAX_PORT}"
        )
    return port


def bounded_request_count(value: str) -> int:
    """Parse the finite request budget used for same-process shutdown."""

    if re.fullmatch(r"[0-9]+", value) is None:
        raise argparse.ArgumentTypeError(
            "max-requests must be an ASCII decimal integer"
        )
    try:
        count = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("max-requests must be a decimal integer") from exc
    if not 1 <= count <= MAX_REQUESTS:
        raise argparse.ArgumentTypeError(
            f"max-requests must be between 1 and {MAX_REQUESTS}"
        )
    return count


def bounded_timeout(value: str, field: str, minimum: int, maximum: int) -> int:
    """Parse one finite integer millisecond timeout."""

    if re.fullmatch(r"[0-9]+", value) is None:
        raise argparse.ArgumentTypeError(f"{field} must be an ASCII decimal integer")
    try:
        timeout = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{field} must be a decimal integer") from exc
    if not minimum <= timeout <= maximum:
        raise argparse.ArgumentTypeError(
            f"{field} must be between {minimum} and {maximum} milliseconds"
        )
    return timeout


def bounded_idle_timeout(value: str) -> int:
    return bounded_timeout(value, "idle-timeout-ms", IDLE_TIMEOUT_MIN_MS, IDLE_TIMEOUT_MAX_MS)


def bounded_session_timeout(value: str) -> int:
    return bounded_timeout(
        value,
        "session-timeout-ms",
        SESSION_TIMEOUT_MIN_MS,
        SESSION_TIMEOUT_MAX_MS,
    )


def loopback_host(value: str) -> str:
    """Reject wildcard/public binds; the fixture is IPv4-loopback only."""

    if value != LOOPBACK_HOST:
        raise argparse.ArgumentTypeError(
            f"host must be the loopback address {LOOPBACK_HOST}"
        )
    return value


def _is_sensitive_header(name: str) -> bool:
    return SENSITIVE_HEADER_RE.search(name) is not None


def _trace_header_value(name: str, value: str) -> str:
    """Keep values only for a small non-secret header allowlist."""

    if name.casefold() not in TRACE_SAFE_HEADERS or _is_sensitive_header(name):
        return "<redacted>"
    if name.casefold() == "content-type":
        return _trace_content_type(value) or "<redacted>"
    return value


def _trace_response_header_value(name: str, value: str) -> str:
    """Keep only deterministic, non-secret response header values."""

    if name.casefold() not in TRACE_RESPONSE_HEADERS or _is_sensitive_header(name):
        return "<redacted>"
    return value


def _trace_content_type(value: str | None) -> str | None:
    """Keep only known media types and non-sensitive charset parameters."""

    if value is None:
        return None
    media_type, _, parameters = value.partition(";")
    media_type = media_type.strip().casefold()
    if _is_sensitive_header(parameters):
        return "<redacted>"
    if media_type == "multipart/form-data":
        return "multipart/form-data; boundary=<redacted>"
    if media_type == "application/x-www-form-urlencoded":
        return media_type
    if media_type == "text/plain" and parameters.strip().casefold() in {
        "",
        "charset=utf-8",
        "charset=iso-8859-1",
        "charset=us-ascii",
    }:
        return value
    return media_type if media_type else "<redacted>"


def _trace_body_projection(body: bytes, content_type: str | None) -> dict[str, object]:
    """Record bounded body facts and only known, non-secret effective fields."""

    media_type = (
        content_type.split(";", 1)[0].strip().casefold()
        if content_type is not None
        else ""
    )
    trace_content_type = _trace_content_type(content_type)
    projection: dict[str, object] = {
        "length": len(body),
        "sha256": hashlib.sha256(body).hexdigest(),
        "content_type": (
            _trace_header_value("Content-Type", trace_content_type)
            if trace_content_type is not None
            else None
        ),
        "redacted": True,
    }
    if content_type is None:
        return projection
    if media_type == "application/x-www-form-urlencoded":
        try:
            fields = parse_qsl(
                body.decode("ascii"),
                keep_blank_values=True,
                strict_parsing=True,
                max_num_fields=MAX_FORM_FIELDS,
            )
        except (UnicodeDecodeError, ValueError):
            fields = []
        if fields and fields == [
            (name, FORM_FIELD_VALUES[name]) for name in ("first", "second")
        ]:
            projection["effective_form"] = {
                "fields": [[name, value] for name, value in fields],
                "bytes": body.decode("ascii"),
                "redacted": False,
            }
        else:
            projection["effective_form"] = {"redacted": True}
    elif media_type == "multipart/form-data":
        # Multipart boundaries are runner-generated.  Retain only the known
        # fixture field names/ASCII values and the wire digest; never retain
        # boundary bytes or arbitrary part headers.
        fields: list[list[str]] = []
        for name in sorted(MULTIPART_FIELD_NAMES):
            marker = f'name="{name}"'.encode("ascii")
            marker_offset = body.find(marker)
            if marker_offset < 0:
                continue
            value_start = body.find(b"\r\n\r\n", marker_offset)
            if value_start < 0:
                continue
            value_start += 4
            value_end = body.find(b"\r\n", value_start)
            if value_end < value_start:
                continue
            value = body[value_start:value_end]
            try:
                value_text = value.decode("ascii")
            except UnicodeDecodeError:
                continue
            if MULTIPART_FIELD_VALUES.get(name) == value_text:
                fields.append([name, value_text])
        canonical_parts = [
            (
                b'--<boundary>\r\n'
                + f'Content-Disposition: form-data; name="{name}"'.encode("ascii")
                + b"\r\n\r\n"
                + value.encode("ascii")
                + b"\r\n"
            )
            for name, value in fields
        ]
        canonical_bytes = b"".join(canonical_parts) + b"--<boundary>--\r\n"
        projection["effective_multipart"] = {
            "fields": fields,
            "canonical_bytes": canonical_bytes.decode("ascii") if fields else "<redacted>",
            "wire_length": len(body),
            "wire_sha256": hashlib.sha256(body).hexdigest(),
            "boundary_bytes": "<redacted>",
            "redacted": True,
        }
    return projection


def _redacted_target(raw_target: str) -> tuple[str, int]:
    """Return a path and query count without retaining query values."""

    try:
        parsed = urlsplit(raw_target)
    except ValueError:
        return "<invalid-target>", 0
    path = parsed.path or "/"
    if path not in TRACE_SAFE_PATHS:
        path = "<unrecognized-path>"
    query_count = 0 if not parsed.query else parsed.query.count("&") + 1
    return path, query_count


def _validate_field_line(line: bytes, message: str) -> bytes:
    """Validate one strict HTTP field line, including name and value bytes."""

    content = line[:-2]
    if b":" not in content:
        raise RequestLimitError(400, message)
    name, value = content.split(b":", 1)
    if TOKEN_RE.fullmatch(name) is None:
        raise RequestLimitError(400, message)
    if any(byte < 0x20 and byte != 0x09 or byte == 0x7F for byte in value):
        raise RequestLimitError(400, message)
    return name.lower()


def _validate_chunk_extensions(extension_bytes: bytes) -> None:
    """Validate RFC 7230 chunk extensions without accepting silent junk."""

    offset = 0
    while offset < len(extension_bytes):
        if extension_bytes[offset] != ord(";"):
            raise RequestLimitError(400, "invalid chunk extension")
        offset += 1
        match = TOKEN_RE.match(extension_bytes, offset)
        if match is None:
            raise RequestLimitError(400, "invalid chunk extension name")
        offset = match.end()
        if offset == len(extension_bytes) or extension_bytes[offset] != ord("="):
            continue
        offset += 1
        if offset == len(extension_bytes):
            raise RequestLimitError(400, "invalid chunk extension value")
        if extension_bytes[offset] == ord('"'):
            offset += 1
            closed = False
            while offset < len(extension_bytes):
                byte = extension_bytes[offset]
                if byte == ord("\\"):
                    offset += 1
                    if offset == len(extension_bytes):
                        break
                    escaped = extension_bytes[offset]
                    if escaped < 0x20 or escaped == 0x7F:
                        raise RequestLimitError(400, "invalid quoted chunk extension")
                    offset += 1
                elif byte == ord('"'):
                    offset += 1
                    closed = True
                    break
                elif byte < 0x20 or byte == 0x7F:
                    raise RequestLimitError(400, "invalid quoted chunk extension")
                else:
                    offset += 1
            if not closed:
                raise RequestLimitError(400, "unterminated chunk extension")
        else:
            match = TOKEN_RE.match(extension_bytes, offset)
            if match is None:
                raise RequestLimitError(400, "invalid chunk extension value")
            offset = match.end()


def _parse_chunk_size(line: bytes) -> int:
    content = line[:-2]
    separator = content.find(b";")
    if separator < 0:
        size_bytes = content
    else:
        size_bytes = content[:separator]
        _validate_chunk_extensions(content[separator:])
    if re.fullmatch(rb"[0-9A-Fa-f]+", size_bytes) is None:
        raise RequestLimitError(400, "invalid chunk size")
    try:
        return int(size_bytes, 16)
    except ValueError as exc:
        raise RequestLimitError(400, "invalid chunk size") from exc


def _validate_entity_field_limits(body: bytes, content_type: str | None) -> None:
    """Reject over-limit form fields before a request is admitted to the trace."""

    if content_type is None:
        return
    media_type = content_type.split(";", 1)[0].strip().casefold()
    if media_type == "application/x-www-form-urlencoded":
        # Count separators before parsing so a parser exception cannot turn a
        # sixteen-plus-field body into an untyped projection-only condition.
        field_count = 0 if not body else body.count(b"&") + 1
        if field_count > MAX_FORM_FIELDS:
            raise RequestLimitError(
                ENTITY_FIELD_LIMIT_STATUS,
                "form field count exceeds fixture limit",
            )
        try:
            parse_qsl(
                body.decode("utf-8"),
                keep_blank_values=True,
                strict_parsing=True,
                max_num_fields=MAX_FORM_FIELDS,
            )
        except (UnicodeDecodeError, ValueError) as exc:
            raise RequestLimitError(400, "invalid form body") from exc
    elif media_type == "multipart/form-data":
        # A multipart part begins with a Content-Disposition header.  Counting
        # only header-line starts avoids matching arbitrary field bytes while
        # enforcing the bound before route dispatch and trace admission.  The
        # generated boundary and arbitrary part values remain unretained.
        field_count = 0
        for _ in MULTIPART_FIELD_HEADER_RE.finditer(body):
            field_count += 1
            if field_count > MAX_MULTIPART_FIELDS:
                raise RequestLimitError(
                    ENTITY_FIELD_LIMIT_STATUS,
                    "multipart field count exceeds fixture limit",
                )


def _atomic_publish(path: Path, payload: bytes) -> None:
    """Publish a bounded ready document with flush, fsync, and atomic rename."""

    if path.exists():
        raise FileExistsError(f"ready path already exists: {path}")
    temporary: Path | None = None
    descriptor: int | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
        temporary = Path(temporary_name)
        with os.fdopen(descriptor, "wb") as ready:
            descriptor = None
            ready.write(payload)
            ready.flush()
            os.fsync(ready.fileno())
        os.replace(temporary, path)
        temporary = None
        try:
            directory = os.open(path.parent, os.O_RDONLY)
        except OSError:
            # Directory fsync is unavailable on some platforms; the file's
            # flush/fsync and atomic rename remain mandatory.
            return
        try:
            try:
                os.fsync(directory)
            except OSError:
                # Directory fsync is optional; the file fsync and atomic
                # rename above are the required publication barriers.
                pass
        finally:
            os.close(directory)
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        raise


def fixed_gzip(payload: bytes) -> bytes:
    output = bytearray()
    with gzip.GzipFile(fileobj=_BytesWriter(output), mode="wb", mtime=0) as stream:
        stream.write(payload)
    return bytes(output)


def reset_connection(connection: socket.socket) -> str:
    """Request a TCP reset with the platform's supported linger layout."""

    for layout in ("ii", "hh"):
        try:
            connection.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_LINGER,
                struct.pack(layout, 1, 0),
            )
            return layout
        except OSError:
            continue
    return "unsupported"


class _BytesWriter:
    def __init__(self, output: bytearray) -> None:
        self.output = output

    def write(self, data: bytes) -> int:
        self.output.extend(data)
        return len(data)


class FixtureServer(ThreadingHTTPServer):
    # A bounded socket timeout plus non-daemon workers lets server_close wait
    # for exact request handlers without leaving a trace file half-written.
    daemon_threads = False
    block_on_close = True
    allow_reuse_address = False
    request_queue_size = MAX_WORKERS

    def __init__(
        self,
        address: tuple[str, int],
        trace_path: Path,
        outcome_path: Path,
        max_requests: int = MAX_REQUESTS,
        idle_timeout_ms: int = DEFAULT_IDLE_TIMEOUT_MS,
        session_timeout_ms: int = DEFAULT_SESSION_TIMEOUT_MS,
    ) -> None:
        host, port = address
        if host != LOOPBACK_HOST:
            raise ValueError(f"host must be the loopback address {LOOPBACK_HOST}")
        if not isinstance(port, int) or (
            port != EPHEMERAL_PORT and not MIN_PORT <= port <= MAX_PORT
        ):
            raise ValueError(f"port must be 0 or between {MIN_PORT} and {MAX_PORT}")
        if not isinstance(max_requests, int) or not 1 <= max_requests <= MAX_REQUESTS:
            raise ValueError(f"max_requests must be between 1 and {MAX_REQUESTS}")
        if not IDLE_TIMEOUT_MIN_MS <= idle_timeout_ms <= IDLE_TIMEOUT_MAX_MS:
            raise ValueError(
                f"idle_timeout_ms must be between {IDLE_TIMEOUT_MIN_MS} and {IDLE_TIMEOUT_MAX_MS}"
            )
        if not SESSION_TIMEOUT_MIN_MS <= session_timeout_ms <= SESSION_TIMEOUT_MAX_MS:
            raise ValueError(
                f"session_timeout_ms must be between {SESSION_TIMEOUT_MIN_MS} and {SESSION_TIMEOUT_MAX_MS}"
            )
        if session_timeout_ms < idle_timeout_ms:
            raise ValueError("session_timeout_ms must not be less than idle_timeout_ms")
        self.worker_slots = threading.BoundedSemaphore(MAX_WORKERS)
        self.active_connection_lock = threading.Lock()
        self.active_connections: set[socket.socket] = set()
        super().__init__(address, FixtureHandler)
        self.trace_path = trace_path
        self.outcome_path = outcome_path
        try:
            self.trace_file = trace_path.open("x", encoding="utf-8", newline="\n")
        except BaseException:
            super().server_close()
            raise
        self.max_requests = max_requests
        self.idle_timeout_ms = idle_timeout_ms
        self.session_timeout_ms = session_timeout_ms
        self.trace_lock = threading.Lock()
        self.connection_lock = threading.Lock()
        self.request_lock = threading.Lock()
        self.lifecycle_lock = threading.Lock()
        self.lifecycle_stop = threading.Event()
        self.started_at = time.monotonic()
        self.last_activity = self.started_at
        self.watchdog_thread: threading.Thread | None = None
        # Socket objects remain strongly referenced only for this bounded
        # request budget, avoiding fileno/id reuse changing connection IDs.
        self.connection_ids: dict[socket.socket, int] = {}
        self.next_connection_id = 1
        self.request_number = 0
        self.accepted_requests = 0
        self.completed_requests = 0
        self.trace_events = 0
        self.last_trace_sequence = 0
        self.trace_bytes = 0
        self.shutdown_requested = False
        self.shutdown_reason: str | None = None
        self.trace_closed = False

    def _touch_activity(self) -> None:
        with self.lifecycle_lock:
            self.last_activity = time.monotonic()

    def start_watchdog(self) -> None:
        if self.watchdog_thread is not None:
            raise RuntimeError("lifecycle watchdog already started")
        self.watchdog_thread = threading.Thread(
            target=self._watchdog,
            name="http-sampler-watchdog",
            daemon=True,
        )
        self.watchdog_thread.start()

    def _watchdog(self) -> None:
        interval = min(0.25, self.idle_timeout_ms / 1000.0)
        while not self.lifecycle_stop.wait(interval):
            now = time.monotonic()
            with self.lifecycle_lock:
                idle_ms = (now - self.last_activity) * 1000.0
                session_ms = (now - self.started_at) * 1000.0
            if session_ms >= self.session_timeout_ms:
                self._request_shutdown("session-timeout")
                return
            if idle_ms >= self.idle_timeout_ms:
                self._request_shutdown("idle-timeout")
                return

    def _request_shutdown(self, reason: str) -> None:
        with self.request_lock:
            if self.shutdown_requested:
                return
            self.shutdown_requested = True
            self.shutdown_reason = reason
        self._wake_shutdown()

    def _wake_shutdown(self) -> None:
        """Wake serve_forever after the shutdown reason is published."""

        self.lifecycle_stop.set()
        # BaseServer.shutdown waits for serve_forever's loop and must be
        # called from a different thread than serve_forever itself.
        threading.Thread(
            target=self.shutdown,
            name="http-sampler-shutdown",
            daemon=True,
        ).start()

    def process_request(
        self, request: socket.socket, client_address: tuple[str, int]
    ) -> None:
        self._touch_activity()
        if not self.worker_slots.acquire(blocking=False):
            request.close()
            return
        with self.active_connection_lock:
            if self.lifecycle_stop.is_set():
                request.close()
                self.worker_slots.release()
                return
            self.active_connections.add(request)
        try:
            super().process_request(request, client_address)
        except BaseException:
            with self.active_connection_lock:
                self.active_connections.discard(request)
            self.worker_slots.release()
            raise

    def process_request_thread(
        self, request: socket.socket, client_address: tuple[str, int]
    ) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self.active_connection_lock:
                self.active_connections.discard(request)
            self.worker_slots.release()

    def _close_active_connections(self) -> None:
        """Unblock exact admitted handlers before waiting for their threads."""

        with self.active_connection_lock:
            active = tuple(self.active_connections)
        for connection in active:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                connection.close()
            except OSError:
                pass

    def admit_request(self, handler: "FixtureHandler") -> None:
        """Reserve one trace sequence before invoking a route callback."""

        self._touch_activity()
        budget_exhausted = False
        with self.request_lock:
            if self.accepted_requests >= self.max_requests:
                budget_exhausted = True
            else:
                self.accepted_requests += 1
        if budget_exhausted:
            # The request lock must be released before requesting shutdown;
            # _request_shutdown takes the same lock to publish its reason.
            self._request_shutdown("bounded-error")
            raise RequestLimitError(503, "request budget exhausted")

        key = handler.connection
        with self.connection_lock:
            connection_id = self.connection_ids.get(key)
            reused = connection_id is not None
            if connection_id is None:
                connection_id = self.next_connection_id
                self.next_connection_id += 1
                self.connection_ids[key] = connection_id
            self.request_number += 1
            request_number = self.request_number
        handler.trace_sequence = request_number
        handler.trace_connection_id = connection_id
        handler.trace_connection_reused = reused

    def record(self, handler: "FixtureHandler", body: bytes) -> None:
        """Write one bounded request/response trace event after the route."""

        self._touch_activity()
        headers: list[list[str]] = []
        raw_items = getattr(handler.headers, "raw_items", None)
        if raw_items is not None:
            headers = [
                [
                    str(name),
                    _trace_header_value(str(name), str(value)),
                ]
                for name, value in raw_items()
            ]
        else:
            headers = [
                [
                    str(name),
                    _trace_header_value(str(name), str(value)),
                ]
                for name, value in handler.headers.items()
            ]
        target, query_parameter_count = _redacted_target(handler.path)
        request_content_type = handler.headers.get("Content-Type")
        response = handler.response_projection()
        event = {
            "sequence": handler.trace_sequence,
            "connection_id": handler.trace_connection_id,
            "connection_reused": handler.trace_connection_reused,
            "method": handler.command,
            "target": target,
            "query_parameter_count": query_parameter_count,
            "headers": headers,
            "body": _trace_body_projection(body, request_content_type),
            "response": response,
        }
        payload = (
            json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        try:
            if len(payload) > MAX_TRACE_EVENT:
                raise TraceLimitError("request trace event exceeds fixture limit")
            with self.trace_lock:
                if handler.trace_sequence != self.last_trace_sequence + 1:
                    raise TraceLimitError("trace sequence is not strictly ordered")
                if self.trace_bytes + len(payload) > MAX_TRACE_BYTES:
                    raise TraceLimitError("trace output exceeds fixture limit")
                self.trace_file.write(payload.decode("utf-8"))
                self.trace_file.flush()
                self.last_trace_sequence = handler.trace_sequence
                with self.request_lock:
                    self.trace_events += 1
                self.trace_bytes += len(payload)
        except (TraceLimitError, OSError):
            # The request was admitted but cannot be represented safely.  Stop
            # this process rather than continuing with a partial trace.
            self.abort_after_error()
            raise

    def request_finished(self) -> bool:
        """Finish one accepted request and enforce the hard trace budget."""

        with self.request_lock:
            self.completed_requests += 1
            should_shutdown = (
                self.completed_requests >= self.max_requests
                and not self.shutdown_requested
            )
            if should_shutdown:
                # Publish the successful reason while holding the same lock
                # used by watchdog/error paths, so a timeout cannot win the
                # race after the final trace event has completed.
                self.shutdown_requested = True
                self.shutdown_reason = (
                    "request-budget"
                    if self.trace_events == self.max_requests
                    else "bounded-error"
                )
        if should_shutdown:
            self._wake_shutdown()
        return should_shutdown

    def abort_after_error(self) -> None:
        """Stop accepting requests after a bounded trace/configuration error."""

        self._request_shutdown("bounded-error")

    def outcome_document(self) -> dict[str, object]:
        """Describe bounded completion for the exact child owner."""

        with self.request_lock:
            reason = self.shutdown_reason or "server-close"
            accepted = self.accepted_requests
            completed = self.completed_requests
            trace_events = self.trace_events
        complete = (
            reason == "request-budget"
            and completed == self.max_requests
            and trace_events == self.max_requests
        )
        return {
            "schema_id": "jmeter-rs.http-sampler-outcome",
            "schema_version": 1,
            "status": "completed" if complete else "incomplete",
            "shutdown_reason": reason,
            "expected_requests": self.max_requests,
            "accepted_requests": accepted,
            "completed_requests": completed,
            "trace_events": trace_events,
            "complete": complete,
            "exit_code": 0 if complete else 3,
        }

    def server_close(self) -> None:
        # ThreadingMixIn waits for all bounded request handlers first.  Only
        # then may the trace sink be closed.  Close only the exact descriptors
        # admitted by this server first, so a slow client cannot pin a finite
        # watchdog shutdown while a handler waits for more request bytes.
        self.lifecycle_stop.set()
        self._close_active_connections()
        try:
            super().server_close()
        finally:
            if self.watchdog_thread is not None:
                self.watchdog_thread.join(timeout=1.0)
            with self.trace_lock:
                if not self.trace_closed:
                    self.trace_file.flush()
                    self.trace_file.close()
                    self.trace_closed = True


class FixtureHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = ""
    sys_version = ""

    def log_message(self, _format: str, *_args: object) -> None:
        return

    @property
    def fixture_server(self) -> FixtureServer:
        return self.server  # type: ignore[return-value]

    def setup(self) -> None:
        super().setup()
        self.trace_sequence = 0
        self.trace_connection_id = 0
        self.trace_connection_reused = False
        self.response_status: int | None = None
        self.response_message = ""
        self.response_headers: list[list[str]] = []
        self.response_wire_body: bytes | None = None
        self.response_decoded_body: bytes | None = None
        self.transport: dict[str, object] | None = None
        # A client that never completes a bounded request cannot pin a worker
        # forever.  This timeout is independent of the sampler's route-level
        # /timeout response delay.
        self.connection.settimeout(REQUEST_TIMEOUT_SECONDS)

    def _reject(self, status: int, body: bytes) -> None:
        self.close_connection = True
        try:
            self._send(
                status,
                body,
                [("Content-Type", "text/plain; charset=US-ASCII")],
                close=True,
            )
        except (BrokenPipeError, ConnectionResetError, OSError, socket.timeout):
            self.close_connection = True

    def response_projection(self) -> dict[str, object]:
        """Return response metadata without retaining response bytes."""

        wire = self.response_wire_body
        decoded = self.response_decoded_body
        body = None
        if wire is not None:
            body = {
                "wire_length": len(wire),
                "wire_sha256": hashlib.sha256(wire).hexdigest(),
                "decoded_length": len(decoded) if decoded is not None else None,
                "decoded_sha256": (
                    hashlib.sha256(decoded).hexdigest() if decoded is not None else None
                ),
                "redacted": True,
            }
        return {
            "status": self.response_status,
            "message": self.response_message,
            "headers": self.response_headers,
            "body": body,
            "data": body,
            "transport": self.transport,
        }

    def parse_request(self) -> bool:
        if not super().parse_request():
            return False
        try:
            request_line_bytes = len(self.requestline.encode("iso-8859-1"))
            target_bytes = len(self.path.encode("iso-8859-1"))
        except UnicodeEncodeError:
            self._reject(400, b"request is not ISO-8859-1")
            return False
        if request_line_bytes > MAX_REQUEST_LINE:
            self._reject(414, b"request line exceeds fixture limit")
            return False
        if target_bytes > MAX_TARGET:
            self._reject(414, b"request target exceeds fixture limit")
            return False
        raw_items = list(self.headers.raw_items())
        try:
            encoded_items = [
                (name.encode("iso-8859-1"), value.encode("iso-8859-1"))
                for name, value in raw_items
            ]
        except UnicodeEncodeError:
            self._reject(400, b"request headers are not ISO-8859-1")
            return False
        for name, value in encoded_items:
            if TOKEN_RE.fullmatch(name) is None or any(
                byte < 0x20 and byte != 0x09 or byte == 0x7F for byte in value
            ):
                self._reject(400, b"invalid request header syntax")
                return False
        header_bytes = sum(len(name) + len(value) for name, value in encoded_items)
        if len(raw_items) > MAX_HEADER_COUNT or header_bytes > MAX_HEADER_BYTES:
            self._reject(431, b"request headers exceed fixture limit")
            return False
        return True

    def _read_line(self, limit: int, message: str) -> bytes:
        line = self.rfile.readline(limit + 1)
        if not line:
            raise RequestLimitError(400, message)
        if len(line) > limit:
            raise RequestLimitError(431, message)
        if not line.endswith(b"\r\n"):
            raise RequestLimitError(400, message)
        return line

    def _read_body(self) -> bytes:
        content_lengths = self.headers.get_all("Content-Length") or []
        transfer_encodings = self.headers.get_all("Transfer-Encoding") or []
        if len(content_lengths) > 1:
            raise RequestLimitError(400, "duplicate Content-Length")
        if len(transfer_encodings) > 1:
            raise RequestLimitError(400, "duplicate Transfer-Encoding")
        if content_lengths and transfer_encodings:
            raise RequestLimitError(400, "Content-Length with Transfer-Encoding")

        if content_lengths:
            raw_length = content_lengths[0].strip()
            try:
                length_bytes = raw_length.encode("ascii")
            except UnicodeEncodeError as exc:
                raise RequestLimitError(400, "invalid Content-Length") from exc
            if re.fullmatch(rb"(?:0|[1-9][0-9]*)", length_bytes) is None:
                raise RequestLimitError(400, "invalid Content-Length")
            try:
                length = int(raw_length, 10)
            except ValueError as exc:
                raise RequestLimitError(400, "invalid Content-Length") from exc
            if length > MAX_BODY:
                raise RequestLimitError(413, "request body exceeds fixture limit")
            body = self.rfile.read(length)
            if len(body) != length:
                raise RequestLimitError(400, "truncated request body")
            _validate_entity_field_limits(body, self.headers.get("Content-Type"))
            return body

        if not transfer_encodings:
            body = b""
            _validate_entity_field_limits(body, self.headers.get("Content-Type"))
            return body
        transfer_encoding = transfer_encodings[0].strip().lower()
        if transfer_encoding != "chunked":
            raise RequestLimitError(501, "unsupported Transfer-Encoding")
        chunks = bytearray()
        chunk_count = 0
        trailer_count = 0
        trailer_bytes = 0
        while True:
            line = self._read_line(MAX_CHUNK_LINE, "invalid chunk framing")
            size = _parse_chunk_size(line)
            if size == 0:
                while True:
                    trailer = self._read_line(MAX_CHUNK_LINE, "invalid chunk trailer")
                    if trailer == b"\r\n":
                        break
                    trailer_count += 1
                    trailer_bytes += len(trailer)
                    if (
                        trailer_count > MAX_HEADER_COUNT
                        or trailer_bytes > MAX_TRAILER_BYTES
                    ):
                        raise RequestLimitError(431, "chunk trailers exceed fixture limit")
                    trailer_name = _validate_field_line(trailer, "invalid chunk trailer")
                    if trailer_name in FORBIDDEN_TRAILER_NAMES:
                        raise RequestLimitError(400, "forbidden chunk trailer")
                break
            chunk_count += 1
            if chunk_count > MAX_CHUNKS:
                raise RequestLimitError(413, "too many request chunks")
            if size > MAX_BODY or len(chunks) + size > MAX_BODY:
                raise RequestLimitError(413, "request body exceeds fixture limit")
            chunk = self.rfile.read(size)
            if len(chunk) != size:
                raise RequestLimitError(400, "truncated request chunk")
            chunks.extend(chunk)
            if self.rfile.read(2) != b"\r\n":
                raise RequestLimitError(400, "invalid chunk terminator")
        body = bytes(chunks)
        _validate_entity_field_limits(body, self.headers.get("Content-Type"))
        return body

    def _serve_request(self, callback: "Callable[[bytes], None]") -> None:
        accepted = False
        body = b""
        try:
            body = self._read_body()
            self.fixture_server.admit_request(self)
            accepted = True
            try:
                callback(body)
            finally:
                self.fixture_server.record(self, body)
        except RequestLimitError as error:
            if accepted and isinstance(error, TraceLimitError):
                self.fixture_server.abort_after_error()
            self._reject(error.status, error.message)
        except ValueError:
            if accepted:
                self.fixture_server.abort_after_error()
            self._reject(500, b"response exceeds fixture limit")
        except (socket.timeout, TimeoutError):
            if accepted:
                self.fixture_server.abort_after_error()
            self._reject(408, b"request timed out")
        except (BrokenPipeError, ConnectionResetError, OSError):
            self.close_connection = True
        finally:
            if accepted and self.fixture_server.request_finished():
                # Do not permit a keep-alive client to submit a request after
                # the finite budget has completed.
                self.close_connection = True

    def _send(
        self,
        status: int,
        body: bytes = b"",
        headers: Iterable[tuple[str, str]] = (),
        *,
        chunked: bool = False,
        close: bool = False,
        decoded_body: bytes | None = None,
    ) -> None:
        if len(body) > MAX_BODY:
            raise ValueError("response body exceeds fixture limit")
        try:
            message = HTTPStatus(status).phrase
        except ValueError:
            message = f"Status {status}"
        provided_headers = [[str(name), str(value)] for name, value in headers]
        response_headers: list[list[str]] = []
        if chunked:
            response_headers.append(["Transfer-Encoding", "chunked"])
        else:
            response_headers.append(["Content-Length", str(len(body))])
        response_headers.extend(provided_headers)
        if close:
            response_headers.append(["Connection", "close"])
        try:
            response_header_bytes = sum(
                len(name.encode("iso-8859-1"))
                + len(value.encode("iso-8859-1"))
                + 4
                for name, value in response_headers
            )
        except UnicodeEncodeError as error:
            raise ValueError("response headers are not ISO-8859-1") from error
        if len(response_headers) > MAX_RESPONSE_HEADER_FIELDS:
            raise ValueError("response header field limit exceeded")
        if response_header_bytes > MAX_RESPONSE_HEADER_BYTES:
            raise ValueError("response header byte limit exceeded")
        self.response_status = status
        self.response_message = message
        self.response_headers = [
            [name, _trace_response_header_value(name, value)]
            for name, value in response_headers
        ]
        self.response_wire_body = body
        self.response_decoded_body = body if decoded_body is None else decoded_body
        self.send_response_only(status)
        if chunked:
            self.send_header("Transfer-Encoding", "chunked")
        else:
            self.send_header("Content-Length", str(len(body)))
        for name, value in provided_headers:
            self.send_header(name, value)
        if close:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        try:
            if chunked:
                for chunk in (body[:4], body[4:11], body[11:]):
                    if chunk:
                        self.wfile.write(f"{len(chunk):x}\r\n".encode("ascii"))
                        self.wfile.write(chunk)
                        self.wfile.write(b"\r\n")
                self.wfile.write(b"0\r\n\r\n")
            else:
                self.wfile.write(body)
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError, socket.timeout):
            self.close_connection = True

    def _dispatch(self, body: bytes) -> None:
        try:
            parsed = urlsplit(self.path)
        except ValueError:
            self._reject(400, b"invalid request target")
            return
        route = parsed.path
        try:
            query = parse_qs(
                parsed.query,
                keep_blank_values=True,
                max_num_fields=MAX_QUERY_FIELDS,
            )
        except ValueError:
            self._reject(414, b"query field limit exceeded")
            return

        if route == "/ok":
            self._send(200, TEXT, [("Content-Type", "text/plain")])
        elif route == "/status/399":
            self._send(399, b"status-399", [("Content-Type", "text/plain")])
        elif route == "/status/400":
            self._send(400, b"status-400", [("Content-Type", "text/plain")])
        elif route == "/echo":
            self._send(200, b"echo-ok", [("Content-Type", "text/plain")])
        elif route == "/headers":
            self._send(
                200,
                b"headers-ok",
                [
                    ("Content-Type", "text/plain"),
                    ("X-Oracle", "first"),
                    ("X-Oracle", "second"),
                    ("X-Oracle-Body-Length", str(len(body))),
                ],
            )
        elif route == "/chunked":
            self._send(200, b"chunked-response-body", [("Content-Type", "text/plain")], chunked=True)
        elif route == "/close":
            self._send(200, b"close-response", [("Content-Type", "text/plain")], close=True)
        elif route == "/reuse":
            self._send(200, b"reuse-response", [("Content-Type", "text/plain")])
        elif route == "/gzip":
            self._send(
                200,
                fixed_gzip(GZIP_BODY),
                [("Content-Type", "text/plain"), ("Content-Encoding", "gzip")],
                decoded_body=GZIP_BODY,
            )
        elif route == "/deflate":
            self._send(
                200,
                zlib.compress(GZIP_BODY, level=9),
                [("Content-Type", "text/plain"), ("Content-Encoding", "deflate")],
                decoded_body=GZIP_BODY,
            )
        elif route == "/encoding/utf8":
            self._send(200, UTF8, [("Content-Type", "text/plain; charset=UTF-8")])
        elif route == "/encoding/latin1":
            self._send(200, LATIN1, [("Content-Type", "text/plain; charset=ISO-8859-1")])
        elif route == "/partial":
            # Deliberately advertise more bytes than are sent, then close.
            partial_body = b"partial-body"
            self.response_status = 200
            self.response_message = HTTPStatus.OK.phrase
            self.response_headers = [
                ["Content-Length", "32"],
                ["Content-Type", "text/plain"],
                ["Connection", "close"],
            ]
            self.response_wire_body = partial_body
            self.response_decoded_body = partial_body
            self.transport = {
                "kind": "truncated-response",
                "declared_content_length": 32,
                "received_wire_bytes": len(partial_body),
                "connection_action": "half-close",
            }
            self.send_response_only(200)
            self.send_header("Content-Length", "32")
            self.send_header("Content-Type", "text/plain")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(partial_body)
            self.wfile.flush()
            try:
                self.connection.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            self.close_connection = True
        elif route == "/reset":
            linger_layout = reset_connection(self.connection)
            self.transport = {
                "kind": "connection-reset",
                "response_started": False,
                "connection_action": "SO_LINGER reset best effort",
                "linger_layout": linger_layout,
            }
            if linger_layout == "unsupported":
                # Keep the transport observation in the trace, but do not
                # claim a complete 21-vector run when the platform cannot
                # provide the reset action required by this case.
                self.fixture_server.abort_after_error()
            self.close_connection = True
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        elif route == "/timeout":
            self.transport = {
                "kind": "response-timeout",
                "server_delay_ms": int(TIMEOUT_DELAY_SECONDS * 1000),
                "sampler_timeout_ms": SAMPLER_TIMEOUT_MS,
            }
            threading.Event().wait(TIMEOUT_DELAY_SECONDS)
            self._send(200, b"late-response", [("Content-Type", "text/plain")])
        elif route.startswith("/redirect/"):
            match = re.fullmatch(r"/redirect/(?:301|302|303|307|308)", route)
            if match is None:
                self._send(404, b"unknown-redirect")
            else:
                code = int(route.rsplit("/", 1)[-1])
                target = f"/redirect-target?code={code}"
                self._send(code, b"redirect", [("Location", target), ("Content-Type", "text/plain")])
        elif route == "/redirect-target":
            code_text = query.get("code", ["unknown"])[0]
            try:
                code = int(code_text, 10)
            except ValueError:
                code = -1
            if code not in REDIRECT_CODES:
                self._send(400, b"invalid-redirect-code", [("Content-Type", "text/plain")])
            else:
                self._send(
                    200,
                    f"redirect-target-{code}".encode("ascii"),
                    [("Content-Type", "text/plain")],
                )
        elif route == "/html":
            self._send(200, HTML, [("Content-Type", "text/html; charset=UTF-8")])
        elif route == "/style.css":
            self._send(200, CSS, [("Content-Type", "text/css")])
        elif route == "/asset.png":
            self._send(200, PNG, [("Content-Type", "image/png")])
        elif route == "/asset.svg":
            self._send(200, SVG, [("Content-Type", "image/svg+xml")])
        else:
            self._send(404, b"not-found", [("Content-Type", "text/plain")])

    def do_GET(self) -> None:  # noqa: N802 - stdlib callback name
        self._serve_request(self._dispatch)

    def do_POST(self) -> None:  # noqa: N802 - stdlib callback name
        self._serve_request(self._dispatch)

    def do_PUT(self) -> None:  # noqa: N802 - stdlib callback name
        self._serve_request(self._dispatch)

    def do_DELETE(self) -> None:  # noqa: N802 - stdlib callback name
        self._serve_request(self._dispatch)

    def do_PATCH(self) -> None:  # noqa: N802 - stdlib callback name
        self._serve_request(self._dispatch)

    def do_HEAD(self) -> None:  # noqa: N802 - stdlib callback name
        self._serve_request(
            lambda _body: self._send(200, b"", [("Content-Type", "text/plain")])
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", type=loopback_host, default=LOOPBACK_HOST)
    parser.add_argument("--port", type=bounded_port, required=True)
    parser.add_argument("--trace", type=Path, required=True)
    parser.add_argument("--ready", type=Path, required=True)
    parser.add_argument("--outcome", type=Path, required=True)
    parser.add_argument("--max-requests", type=bounded_request_count, required=True)
    parser.add_argument(
        "--idle-timeout-ms",
        type=bounded_idle_timeout,
        default=DEFAULT_IDLE_TIMEOUT_MS,
    )
    parser.add_argument(
        "--session-timeout-ms",
        type=bounded_session_timeout,
        default=DEFAULT_SESSION_TIMEOUT_MS,
    )
    args = parser.parse_args()
    parent_paths = {
        args.trace.parent.resolve(),
        args.ready.parent.resolve(),
        args.outcome.parent.resolve(),
    }
    if len(parent_paths) != 1 or not next(iter(parent_paths)).is_dir():
        parser.error(
            "trace, ready, and outcome must share an existing canonical run root"
        )
    paths = {args.trace.resolve(), args.ready.resolve(), args.outcome.resolve()}
    if len(paths) != 3:
        parser.error("--trace, --ready, and --outcome must name different files")

    server: FixtureServer | None = None
    exit_code = 0
    try:
        server = FixtureServer(
            (args.host, args.port),
            args.trace,
            args.outcome,
            args.max_requests,
            args.idle_timeout_ms,
            args.session_timeout_ms,
        )
        ready = {
            "schema_id": "jmeter-rs.http-sampler-ready",
            "schema_version": 1,
            "host": args.host,
            "port": int(server.server_address[1]),
            "max_requests": args.max_requests,
            "lifecycle": {
                "hard_request_cap": args.max_requests,
                "idle_timeout_ms": args.idle_timeout_ms,
                "session_timeout_ms": args.session_timeout_ms,
                "pre_network_failures_stop_by": "idle-timeout-or-session-timeout",
                "normal_completion": {
                    "shutdown_reason": "request-budget",
                    "expected_requests": args.max_requests,
                    "expected_trace_events": args.max_requests,
                    "trace_sequence_base": 1,
                    "exit_code": 0,
                },
                "incomplete_completion": {
                    "shutdown_reasons": [
                        "idle-timeout",
                        "session-timeout",
                        "bounded-error",
                        "server-close",
                    ],
                    "exit_code": 3,
                },
            },
            "publication": {
                "method": "temporary-sibling",
                "flush": True,
                "fsync": True,
                "atomic_rename": True,
                "directory_fsync": "best-effort",
                "max_ready_bytes": MAX_READY_BYTES,
                "max_outcome_bytes": MAX_OUTCOME_BYTES,
            },
            "limits": {
                "port_min": MIN_PORT,
                "port_max": MAX_PORT,
                "max_request_budget": MAX_REQUESTS,
                "idle_timeout_min_ms": IDLE_TIMEOUT_MIN_MS,
                "idle_timeout_max_ms": IDLE_TIMEOUT_MAX_MS,
                "session_timeout_min_ms": SESSION_TIMEOUT_MIN_MS,
                "session_timeout_max_ms": SESSION_TIMEOUT_MAX_MS,
                "preparse_max_line_bytes": PREPARSE_MAX_LINE_BYTES,
                "preparse_readline_limit_bytes": PREPARSE_READLINE_LIMIT_BYTES,
                "preparse_max_header_count": PREPARSE_MAX_HEADER_COUNT,
                "max_body_bytes": MAX_BODY,
                "max_request_line_bytes": MAX_REQUEST_LINE,
                "max_target_bytes": MAX_TARGET,
                "max_header_bytes": MAX_HEADER_BYTES,
                "max_header_count": MAX_HEADER_COUNT,
                "max_chunk_line_bytes": MAX_CHUNK_LINE,
                "max_chunks": MAX_CHUNKS,
                "max_trailer_bytes": MAX_TRAILER_BYTES,
                "forbidden_trailer_names": sorted(
                    name.decode("ascii") for name in FORBIDDEN_TRAILER_NAMES
                ),
                "max_trace_event_bytes": MAX_TRACE_EVENT,
                "max_trace_bytes": MAX_TRACE_BYTES,
                "max_ready_bytes": MAX_READY_BYTES,
                "max_outcome_bytes": MAX_OUTCOME_BYTES,
                "max_response_header_fields": MAX_RESPONSE_HEADER_FIELDS,
                "max_response_header_bytes": MAX_RESPONSE_HEADER_BYTES,
                "max_query_fields": MAX_QUERY_FIELDS,
                "max_form_fields": MAX_FORM_FIELDS,
                "max_multipart_fields": MAX_MULTIPART_FIELDS,
                "entity_field_limit_status": ENTITY_FIELD_LIMIT_STATUS,
                "max_workers": MAX_WORKERS,
                "request_timeout_ms": int(REQUEST_TIMEOUT_SECONDS * 1000),
                "readiness_timeout_ms": READINESS_TIMEOUT_MS,
                "timeout_delay_ms": int(TIMEOUT_DELAY_SECONDS * 1000),
                "sampler_timeout_ms": SAMPLER_TIMEOUT_MS,
                "reset_linger_layouts": ["ii", "hh"],
                "redirect_codes": sorted(REDIRECT_CODES),
                "trace_safe_header_names": sorted(TRACE_SAFE_HEADERS),
                "trace_safe_paths": sorted(TRACE_SAFE_PATHS),
            },
        }
        ready_payload = json.dumps(ready, sort_keys=True, separators=(",", ":")) + "\n"
        if len(ready_payload.encode("utf-8")) > MAX_READY_BYTES:
            raise ValueError("ready document exceeds fixture limit")
        _atomic_publish(args.ready, ready_payload.encode("utf-8"))
        server.start_watchdog()
        server.serve_forever(poll_interval=0.05)
    except KeyboardInterrupt:
        exit_code = 130
    except (OSError, ValueError) as error:
        print(f"fixture configuration/runtime error: {error}", file=sys.stderr)
        exit_code = 2
    finally:
        if server is not None:
            try:
                server.server_close()
            except Exception as error:
                print(f"fixture shutdown error: {error}", file=sys.stderr)
                exit_code = max(exit_code, 2)
            outcome = server.outcome_document()
            outcome_payload = (
                json.dumps(outcome, sort_keys=True, separators=(",", ":")) + "\n"
            ).encode("utf-8")
            if len(outcome_payload) > MAX_OUTCOME_BYTES:
                print("fixture outcome exceeds fixture limit", file=sys.stderr)
                exit_code = max(exit_code, 2)
            else:
                try:
                    _atomic_publish(args.outcome, outcome_payload)
                except OSError as error:
                    print(f"fixture outcome publication error: {error}", file=sys.stderr)
                    exit_code = max(exit_code, 2)
            if not outcome["complete"]:
                exit_code = max(exit_code, int(outcome["exit_code"]))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
