#!/usr/bin/env python3
"""Deterministic loopback HTTP service for the HTTP state oracle corpus.

The fixture has no dependency outside the Python standard library.  It binds
only to ``127.0.0.1`` and serves fixed responses for cookie, cache,
redirect, authentication, and header-manager cases.  Request traces are
JSON-lines with credentials redacted.  The server is intentionally
single-threaded: a request is fully handled before the next request is
accepted, so sequence numbers and state observations do not depend on thread
scheduling.

Shutdown is coordinated by the serving process itself.  ``--max-requests``
sets a finite fail-safe request cap, while the optional ``--expected-requests``
sets an exact normal-completion count.  After the final response for either
bound, the main loop notices the stop flag and closes the listening socket and
trace file.  The ready metadata is endpoint-only; no process lookup, signal,
shell, or external cleanup command is used.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import tempfile
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Iterable
from urllib.parse import parse_qs, urlsplit


HOST = "127.0.0.1"
EPHEMERAL_PORT = 0
PORT_MIN = 1024
PORT_MAX = 65535
DEFAULT_PORT = 18080
MAX_REQUESTS = 10_000
DEFAULT_MAX_REQUESTS = 256
MAX_BODY_BYTES = 1 << 20
MAX_RESPONSE_BYTES = 1 << 20
MAX_HEADER_BYTES = 64 * 1024
MAX_HEADER_FIELDS = 128
MAX_RESPONSE_HEADER_FIELDS = 128
MAX_REQUEST_TARGET_BYTES = 8 * 1024
MAX_QUERY_FIELDS = 32
MAX_ROUTE_KEY_BYTES = 128
MAX_BODY_READ_CHUNK_BYTES = 64 * 1024
MAX_TRACE_RECORD_BYTES = 128 * 1024
MAX_TRACE_BYTES = 8 * 1024 * 1024
MAX_READY_BYTES = 16 * 1024
REQUEST_TIMEOUT_SECONDS = 5.0
IDLE_TIMEOUT_MIN_MS = 100
IDLE_TIMEOUT_MAX_MS = 300_000
DEFAULT_IDLE_TIMEOUT_MS = 5_000
SESSION_TIMEOUT_MIN_MS = 1_000
SESSION_TIMEOUT_MAX_MS = 600_000
DEFAULT_SESSION_TIMEOUT_MS = 30_000

FIXED_DATE = "Tue, 01 Jan 2030 00:00:00 GMT"
LAST_MODIFIED = "Mon, 31 Dec 2029 00:00:00 GMT"
FIXED_COOKIE_EXPIRES = "Tue, 01 Jan 2030 00:01:00 GMT"
REALM = "jmeter-oracle"
DIGEST_NONCE = "fixed-nonce-563"
# These are deliberately non-secret corpus values.  They exist only to make
# prefix selection and challenge retries observable; Authorization traces are
# always redacted and these values are never emitted in a response.
BASIC_CREDENTIALS = {
    "/auth/basic": ("alice", "dummy-basic-password"),
    # This path overlaps the broad prefix.  The broad entry is intentionally
    # first in the JMX AuthManager and therefore supplies the first-match
    # credentials here.
    "/auth/basic/specific": ("alice", "dummy-basic-password"),
    "/auth/specific-basic": ("specific-user", "dummy-specific-password"),
}
DIGEST_CREDENTIALS = {
    "/auth/digest": ("digest-user", "dummy-digest-password"),
    "/auth/digest/specific": ("digest-user", "dummy-digest-password"),
    "/auth/specific-digest": (
        "specific-digest-user",
        "dummy-specific-digest-password",
    ),
}
AUTH_REALMS = {
    "/auth/basic": REALM,
    "/auth/basic/specific": REALM,
    "/auth/specific-basic": f"{REALM}-basic-specific",
    "/auth/digest": REALM,
    "/auth/digest/specific": REALM,
    "/auth/specific-digest": f"{REALM}-digest-specific",
}


def _port(value: str) -> int:
    """Parse port zero or one explicitly assigned unprivileged TCP port."""

    if re.fullmatch(r"[0-9]+", value) is None:
        raise argparse.ArgumentTypeError("port must be an ASCII decimal integer")
    try:
        port = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if port != EPHEMERAL_PORT and not PORT_MIN <= port <= PORT_MAX:
        raise argparse.ArgumentTypeError(
            f"port must be 0 or between {PORT_MIN} and {PORT_MAX}"
        )
    return port


def _timeout(value: str, field: str, minimum: int, maximum: int) -> int:
    """Parse one finite millisecond timeout."""

    if re.fullmatch(r"[0-9]+", value) is None:
        raise argparse.ArgumentTypeError(f"{field} must be an ASCII decimal integer")
    try:
        timeout = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{field} must be an integer") from exc
    if not minimum <= timeout <= maximum:
        raise argparse.ArgumentTypeError(
            f"{field} must be between {minimum} and {maximum} milliseconds"
        )
    return timeout


def _idle_timeout(value: str) -> int:
    return _timeout(value, "idle-timeout-ms", IDLE_TIMEOUT_MIN_MS, IDLE_TIMEOUT_MAX_MS)


def _session_timeout(value: str) -> int:
    return _timeout(
        value,
        "session-timeout-ms",
        SESSION_TIMEOUT_MIN_MS,
        SESSION_TIMEOUT_MAX_MS,
    )


def _loopback_host(value: str) -> str:
    """Reject wildcard/public binds; the fixture is IPv4-loopback only."""

    if value != HOST:
        raise argparse.ArgumentTypeError(f"host must be the loopback address {HOST}")
    return value


def _request_count(value: str, field: str) -> int:
    """Parse a finite positive request count for a cap or exact stop."""

    if re.fullmatch(r"[0-9]+", value) is None:
        raise argparse.ArgumentTypeError(f"{field} must be an ASCII decimal integer")
    try:
        maximum = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{field} must be an integer") from exc
    if not 1 <= maximum <= MAX_REQUESTS:
        raise argparse.ArgumentTypeError(
            f"{field} must be between 1 and {MAX_REQUESTS}"
        )
    return maximum


def _max_requests(value: str) -> int:
    """Parse a finite positive request budget."""

    return _request_count(value, "max-requests")


def _expected_requests(value: str) -> int:
    """Parse an exact post-response request count when one is known."""

    return _request_count(value, "expected-requests")


def _header_value(handler: BaseHTTPRequestHandler, name: str) -> str | None:
    return handler.headers.get(name)


def _digest_response(
    username: str,
    password: str,
    realm: str,
    method: str,
    uri: str,
    nonce: str,
    nc: str,
    cnonce: str,
    qop: str,
) -> str:
    ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
    return hashlib.md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}".encode()).hexdigest()


def _parse_digest(value: str) -> dict[str, str]:
    if not value.startswith("Digest "):
        return {}
    pairs: dict[str, str] = {}
    for match in re.finditer(
        r"([A-Za-z][A-Za-z0-9_-]*)=(?:\"([^\"]*)\"|([^, ]+))", value[7:]
    ):
        pairs[match.group(1)] = (
            match.group(2) if match.group(2) is not None else match.group(3)
        )
    return pairs


class OracleHandler(BaseHTTPRequestHandler):
    """Bounded HTTP request handler for one sequential fixture server."""

    protocol_version = "HTTP/1.1"
    server_version = "jmeter-rs-http-state/1"
    sys_version = ""

    @property
    def oracle_server(self) -> "OracleServer":
        return self.server  # type: ignore[return-value]

    def setup(self) -> None:
        super().setup()
        self.oracle_server.begin_request()
        # A client that sends an incomplete header/body must not hold the
        # single-process fixture open indefinitely.
        timeout = self.oracle_server.request_timeout_seconds()
        self.connection.settimeout(timeout if timeout > 0 else 0.001)

    def log_message(self, _format: str, *_args: object) -> None:
        # Requests are recorded in the structured trace, never stderr.
        return

    def _reject(self, status: int, reason: str) -> None:
        """Send a fixed, bounded error and close the current connection."""

        body = f"fixture-error={reason}\n".encode("ascii")
        self.send_response_only(status)
        self.send_header("Date", FIXED_DATE)
        self.send_header("Server", self.server_version)
        self.send_header("Connection", "close")
        self.send_header("Content-Type", "text/plain; charset=US-ASCII")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        self.oracle_server.complete_request()
        self.close_connection = True

    def parse_request(self) -> bool:  # noqa: D401 - stdlib callback contract
        """Parse a request and enforce target/header limits before dispatch."""

        if not super().parse_request():
            return False
        target_bytes = self.path.encode("iso-8859-1", errors="replace")
        if len(target_bytes) > MAX_REQUEST_TARGET_BYTES:
            self._reject(414, "request-target-too-large")
            return False
        header_bytes = sum(
            len(name.encode("iso-8859-1", errors="replace"))
            + len(value.encode("iso-8859-1", errors="replace"))
            + 4
            for name, value in self.headers.items()
        )
        if len(self.headers) > MAX_HEADER_FIELDS or header_bytes > MAX_HEADER_BYTES:
            self._reject(431, "request-headers-too-large")
            return False
        return True

    def _read_body(self) -> bytes | None:
        transfer_encoding = self.headers.get("Transfer-Encoding")
        if transfer_encoding and transfer_encoding.lower() != "identity":
            self._reject(400, "transfer-encoding-unsupported")
            return None
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            return b""
        try:
            length = int(raw_length, 10)
        except ValueError:
            self._reject(400, "content-length-invalid")
            return None
        if length < 0 or length > MAX_BODY_BYTES:
            self._reject(413, "request-body-too-large")
            return None
        chunks: list[bytes] = []
        remaining = length
        while remaining:
            timeout = self.oracle_server.request_timeout_seconds()
            if timeout <= 0:
                self._reject(408, "request-body-deadline")
                return None
            self.connection.settimeout(timeout)
            try:
                chunk = self.rfile.read(min(remaining, MAX_BODY_READ_CHUNK_BYTES))
            except (TimeoutError, OSError):
                reason = (
                    "request-body-deadline"
                    if self.oracle_server.deadline_expired()
                    else "request-body-timeout"
                )
                self._reject(408, reason)
                return None
            if not chunk:
                self._reject(400, "request-body-truncated")
                return None
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _request_headers(self) -> dict[str, str | list[str]]:
        selected = (
            "Accept",
            "Authorization",
            "Cache-Control",
            "Cookie",
            "Host",
            "If-Modified-Since",
            "If-None-Match",
            "Referer",
            "User-Agent",
            "X-Base",
            "X-Duplicate-First",
            "X-Duplicate-Second",
            "X-Override",
            "X-Variant",
        )
        result: dict[str, str | list[str]] = {}
        for name in selected:
            values = self.headers.get_all(name)
            if not values:
                continue
            if name.lower() == "authorization":
                redacted = []
                for value in values:
                    scheme = value.split(" ", 1)[0]
                    redacted.append(f"{scheme} <redacted>")
                values = redacted
            if len(values) == 1:
                result[name.lower()] = values[0]
            else:
                result[name.lower()] = values
        return result

    def _record(self, path: str, body: bytes) -> None:
        parts = urlsplit(self.path)
        try:
            parsed_query = parse_qs(
                parts.query,
                keep_blank_values=True,
                strict_parsing=False,
                max_num_fields=MAX_QUERY_FIELDS,
            )
        except ValueError:
            parsed_query = {"_invalid": ["too-many-fields"]}
        query = {key: values for key, values in sorted(parsed_query.items())}
        request_headers = self._request_headers()
        record: dict[str, object] = {
            "sequence": self.oracle_server.next_sequence(),
            "method": self.command,
            "path": path,
            "query": query,
            "request_headers": request_headers,
            "body_length": len(body),
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "request_headers_sha256": hashlib.sha256(
                json.dumps(
                    request_headers,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest(),
        }
        self._trace_record = record

    def _send(
        self,
        status: int,
        body: bytes = b"",
        headers: Iterable[tuple[str, str]] = (),
        cookies: Iterable[str] = (),
    ) -> None:
        if len(body) > MAX_RESPONSE_BYTES:
            self._reject(500, "response-body-too-large")
            return
        fields = list(headers)
        fields.extend(("Set-Cookie", cookie) for cookie in cookies)
        if not any(name.lower() == "content-type" for name, _value in fields):
            fields.insert(0, ("Content-Type", "text/plain; charset=UTF-8"))
        # Date, Server, Connection, and Content-Length are emitted below in
        # addition to this caller-controlled list.  Reject a response before
        # writing any headers when the total field count is over budget.
        if len(fields) + 4 > MAX_RESPONSE_HEADER_FIELDS:
            self._reject(500, "response-header-count-too-large")
            return
        response_headers = [
            ("Date", FIXED_DATE),
            ("Server", self.server_version),
            ("Connection", "close"),
            *fields,
            ("Content-Length", str(len(body))),
        ]
        header_bytes = sum(
            len(name.encode("iso-8859-1", errors="replace"))
            + len(value.encode("iso-8859-1", errors="replace"))
            + 4
            for name, value in response_headers
        )
        if header_bytes > MAX_HEADER_BYTES:
            self._reject(500, "response-headers-too-large")
            return
        trace_record = getattr(self, "_trace_record", None)
        if trace_record is not None:
            trace_record["response"] = {
                "status": status,
                "headers": [[name, value] for name, value in response_headers],
                "headers_sha256": hashlib.sha256(
                    json.dumps(
                        response_headers,
                        separators=(",", ":"),
                    ).encode("utf-8")
                ).hexdigest(),
                "body_length": len(body),
                "body_sha256": hashlib.sha256(body).hexdigest(),
                "wire_body_length": 0 if self.command == "HEAD" else len(body),
            }
            self.oracle_server.record(trace_record)
        self.send_response_only(status)
        self.send_header("Date", FIXED_DATE)
        self.send_header("Server", self.server_version)
        self.send_header("Connection", "close")
        for name, value in fields:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        self.oracle_server.complete_request()
        self.close_connection = True

    def _echo_body(self, path: str, extra: str = "") -> bytes:
        cookie = self.headers.get("Cookie", "")
        return f"path={path}\ncookie={cookie}\n{extra}".encode("utf-8")

    def _dispatch(self, body: bytes) -> None:
        path = urlsplit(self.path).path
        self._record(path, body)

        if path == "/cookie/set":
            self._send(
                200,
                self._echo_body(path, "set=all"),
                cookies=(
                    "host=H; Path=/cookie; Max-Age=600",
                    "domain=D; Domain=127.0.0.1; Path=/cookie; Max-Age=600",
                    "root=R; Path=/; Max-Age=600",
                    "path=P; Path=/cookie/path; Max-Age=600",
                    "secure=S; Path=/; Secure; Max-Age=600",
                    "expired=gone; Path=/; Max-Age=0",
                    "dup=first; Path=/cookie; Max-Age=600",
                    "dup=second; Path=/cookie; Max-Age=600",
                ),
            )
            return
        if path == "/cookie/domain-set":
            self._send(
                200,
                self._echo_body(path, "set=host-and-fixture-domain"),
                cookies=(
                    "host-only=H; Path=/cookie; Max-Age=600",
                    "fixture-domain=D; Domain=fixture.test; Path=/cookie; Max-Age=600",
                ),
            )
            return
        if path == "/cookie/expiry":
            self._send(
                200,
                self._echo_body(path, "set=controlled-expiry"),
                cookies=(
                    f"expiry=active; Path=/cookie; Max-Age=60; Expires={FIXED_COOKIE_EXPIRES}",
                ),
            )
            return
        if path == "/cookie/delete":
            self._send(
                200,
                self._echo_body(path, "delete=all"),
                cookies=(
                    "host=; Path=/cookie; Max-Age=0",
                    "domain=; Domain=127.0.0.1; Path=/cookie; Max-Age=0",
                    "root=; Path=/; Max-Age=0",
                    "path=; Path=/cookie/path; Max-Age=0",
                    "secure=; Path=/; Max-Age=0",
                    "dup=; Path=/cookie; Max-Age=0",
                ),
            )
            return
        if path == "/cookie/expire":
            self._send(
                200,
                self._echo_body(path, "delete=controlled-expiry"),
                cookies=(
                    f"expiry=; Path=/cookie; Max-Age=0; Expires={FIXED_DATE}",
                    "fixture-domain=; Domain=fixture.test; Path=/cookie; Max-Age=0",
                ),
            )
            return
        if path in {
            "/cookie/echo",
            "/cookie/domain-echo",
            "/cookie/path/echo",
            "/cookie/secure",
            "/cookie/host",
        }:
            self._send(200, self._echo_body(path))
            return

        if path == "/cache/fresh":
            self._send(
                200,
                b"fresh-body-v1\n",
                (
                    ("Cache-Control", "max-age=600"),
                    ("ETag", '"fresh-v1"'),
                    ("Last-Modified", LAST_MODIFIED),
                ),
            )
            return
        if path == "/cache/etag":
            if _header_value(self, "If-None-Match") == '"etag-v1"':
                self._send(304, headers=(("ETag", '"etag-v1"'),))
            else:
                self._send(
                    200,
                    b"etag-body-v1\n",
                    (("Cache-Control", "max-age=0"), ("ETag", '"etag-v1"')),
                )
            return
        if path == "/cache/stale":
            conditional = _header_value(self, "If-None-Match") == '"stale-v1"'
            conditional = conditional or _header_value(self, "If-Modified-Since") == LAST_MODIFIED
            if conditional:
                self._send(
                    304,
                    headers=(("ETag", '"stale-v1"'), ("Last-Modified", LAST_MODIFIED)),
                )
            else:
                self._send(
                    200,
                    b"stale-body-v1\n",
                    (
                        ("Cache-Control", "max-age=0"),
                        ("ETag", '"stale-v1"'),
                        ("Last-Modified", LAST_MODIFIED),
                    ),
                )
            return
        if path == "/cache/last-modified":
            conditional = _header_value(self, "If-Modified-Since") == LAST_MODIFIED
            if conditional:
                self._send(304, headers=(("Last-Modified", LAST_MODIFIED),))
            else:
                self._send(
                    200,
                    b"last-modified-body-v1\n",
                    (
                        ("Cache-Control", "max-age=0"),
                        ("Last-Modified", LAST_MODIFIED),
                    ),
                )
            return
        if path == "/cache/no-cache":
            self._send(
                200,
                b"no-cache-body-v1\n",
                (
                    ("Cache-Control", "no-cache"),
                    ("ETag", '"nocache-v1"'),
                    ("Last-Modified", LAST_MODIFIED),
                ),
            )
            return
        if path == "/cache/no-store":
            self._send(200, b"no-store-body-v1\n", (("Cache-Control", "no-store"),))
            return
        if path == "/cache/vary":
            variant = self.headers.get("X-Variant", "none")
            if not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", variant):
                variant = "invalid"
            self._send(
                200,
                f"vary-body-{variant}\n".encode("ascii"),
                (
                    ("Cache-Control", "max-age=600"),
                    ("ETag", f'"vary-{variant}"'),
                    ("Last-Modified", LAST_MODIFIED),
                    ("Vary", "X-Variant"),
                ),
            )
            return
        if path.startswith("/cache/evict/"):
            key = path.rsplit("/", 1)[-1]
            if len(key.encode("ascii", errors="ignore")) > MAX_ROUTE_KEY_BYTES or not re.fullmatch(
                r"[a-z0-9-]{1,64}", key
            ):
                self._send(404, b"not-found\n")
            else:
                self._send(
                    200,
                    f"evict-body-{key}\n".encode("ascii"),
                    (("Cache-Control", "max-age=600"),),
                )
            return

        redirect_match = re.fullmatch(r"/redirect/(30[1-8])", path)
        if redirect_match is not None:
            code = int(redirect_match.group(1))
            self._send(
                code,
                b"redirect\n",
                (
                    ("Location", f"/redirect-target?code={code}"),
                    ("Content-Type", "text/plain; charset=US-ASCII"),
                ),
            )
            return
        if path == "/redirect/no-location":
            self._send(302, b"redirect-without-location\n")
            return
        if path == "/redirect/loop":
            try:
                loop_query = parse_qs(
                    urlsplit(self.path).query,
                    keep_blank_values=True,
                    max_num_fields=MAX_QUERY_FIELDS,
                )
            except ValueError:
                self._send(400, b"invalid-loop-query\n")
                return
            raw_step = loop_query.get("step", ["0"])[0]
            try:
                step = int(raw_step, 10)
            except ValueError:
                self._send(400, b"invalid-loop-step\n")
                return
            if not 0 <= step <= 5:
                self._send(400, b"invalid-loop-step\n")
            elif step == 5:
                self._send(200, b"redirect-loop-finished\n")
            else:
                self._send(
                    302,
                    b"redirect-loop\n",
                    (("Location", f"/redirect/loop?step={step + 1}"),),
                )
            return
        if path == "/redirect-target":
            try:
                target_query = parse_qs(
                    urlsplit(self.path).query,
                    keep_blank_values=True,
                    max_num_fields=MAX_QUERY_FIELDS,
                )
            except ValueError:
                self._send(400, b"invalid-target-query\n")
                return
            code = target_query.get("code", ["unknown"])[0]
            if not re.fullmatch(r"30[1-8]|unknown", code):
                code = "invalid"
            digest = hashlib.sha256(body).hexdigest()
            self._send(
                200,
                (
                    f"target-code={code}\nmethod={self.command}\n"
                    f"body-length={len(body)}\nbody-sha256={digest}\n"
                ).encode("ascii"),
            )
            return

        if path in BASIC_CREDENTIALS:
            username, password = BASIC_CREDENTIALS[path]
            expected = "Basic " + base64.b64encode(
                f"{username}:{password}".encode("ascii")
            ).decode("ascii")
            if self.headers.get("Authorization") == expected:
                result = (
                    b"basic-first-prefix-ok\n"
                    if path == "/auth/basic/specific"
                    else b"basic-ok\n"
                )
                self._send(200, result)
            else:
                self._send(
                    401,
                    b"basic-challenge\n",
                    (("WWW-Authenticate", f'Basic realm="{AUTH_REALMS[path]}"'),),
                )
            return
        if path in DIGEST_CREDENTIALS:
            username, password = DIGEST_CREDENTIALS[path]
            realm = AUTH_REALMS[path]
            auth = _parse_digest(self.headers.get("Authorization", ""))
            expected = _digest_response(
                auth.get("username", ""),
                password if auth.get("username") == username else "",
                realm,
                self.command,
                auth.get("uri", path),
                DIGEST_NONCE,
                auth.get("nc", ""),
                auth.get("cnonce", ""),
                auth.get("qop", ""),
            )
            if (
                auth.get("username") == username
                and auth.get("realm") == realm
                and auth.get("nonce") == DIGEST_NONCE
                and auth.get("qop") == "auth"
                and auth.get("nc")
                and auth.get("cnonce")
                and auth.get("uri") == path
                and auth.get("response") == expected
            ):
                self._send(200, b"digest-ok\n")
            else:
                self._send(
                    401,
                    b"digest-challenge\n",
                    (
                        (
                            "WWW-Authenticate",
                            f'Digest realm="{realm}", nonce="{DIGEST_NONCE}", '
                            'qop="auth", algorithm=MD5',
                        ),
                    ),
                )
            return
        if path == "/auth/challenge-basic":
            self._send(
                401,
                b"basic-challenge\n",
                (("WWW-Authenticate", f'Basic realm="{REALM}-challenge"'),),
            )
            return
        if path == "/auth/challenge-digest":
            self._send(
                401,
                b"digest-challenge\n",
                (
                    (
                        "WWW-Authenticate",
                        f'Digest realm="{REALM}-challenge", nonce="{DIGEST_NONCE}", '
                        'qop="auth", algorithm=MD5',
                    ),
                ),
            )
            return
        if path == "/auth/open":
            self._send(200, b"open-ok\n")
            return

        if path in {"/headers/echo", "/defaults/echo", "/dns/echo"}:
            selected = {
                name.lower(): self.headers.get(name, "")
                for name in (
                    "Accept",
                    "Host",
                    "Referer",
                    "User-Agent",
                    "X-Base",
                    "X-Duplicate-First",
                    "X-Duplicate-Second",
                    "X-Override",
                )
            }
            body_text = "path=" + path + "\n" + "\n".join(
                f"{key}={selected[key]}" for key in sorted(selected)
            ) + "\n"
            self._send(200, body_text.encode("utf-8"))
            return

        self._send(404, b"not-found\n")

    def _handle_method(self) -> None:
        body = self._read_body()
        if body is not None:
            self._dispatch(body)

    def do_GET(self) -> None:  # noqa: N802 - stdlib callback name
        self._handle_method()

    def do_HEAD(self) -> None:  # noqa: N802 - stdlib callback name
        self._handle_method()

    def do_POST(self) -> None:  # noqa: N802 - stdlib callback name
        self._handle_method()

    def do_PUT(self) -> None:  # noqa: N802 - stdlib callback name
        self._handle_method()

    def do_DELETE(self) -> None:  # noqa: N802 - stdlib callback name
        self._handle_method()

    def do_PATCH(self) -> None:  # noqa: N802 - stdlib callback name
        self._handle_method()


class OracleServer(HTTPServer):
    """Single-threaded server with bounded in-process lifecycle shutdown."""

    allow_reuse_address = False
    request_queue_size = 8

    def __init__(
        self,
        address: tuple[str, int],
        trace_path: Path,
        max_requests: int | None,
        expected_requests: int | None = None,
        idle_timeout_ms: int = DEFAULT_IDLE_TIMEOUT_MS,
        session_timeout_ms: int = DEFAULT_SESSION_TIMEOUT_MS,
    ) -> None:
        host, port = address
        if host != HOST:
            raise ValueError(f"host must be the loopback address {HOST}")
        if port != EPHEMERAL_PORT and not PORT_MIN <= port <= PORT_MAX:
            raise ValueError(
                f"port must be 0 or between {PORT_MIN} and {PORT_MAX}"
            )
        if max_requests is not None and not 1 <= max_requests <= MAX_REQUESTS:
            raise ValueError(f"max_requests must be between 1 and {MAX_REQUESTS}")
        if expected_requests is not None and not 1 <= expected_requests <= MAX_REQUESTS:
            raise ValueError(
                f"expected_requests must be between 1 and {MAX_REQUESTS}"
            )
        if (
            max_requests is not None
            and expected_requests is not None
            and expected_requests > max_requests
        ):
            raise ValueError("expected_requests must not exceed max_requests")
        if not IDLE_TIMEOUT_MIN_MS <= idle_timeout_ms <= IDLE_TIMEOUT_MAX_MS:
            raise ValueError(
                "idle_timeout_ms must be between "
                f"{IDLE_TIMEOUT_MIN_MS} and {IDLE_TIMEOUT_MAX_MS}"
            )
        if not SESSION_TIMEOUT_MIN_MS <= session_timeout_ms <= SESSION_TIMEOUT_MAX_MS:
            raise ValueError(
                "session_timeout_ms must be between "
                f"{SESSION_TIMEOUT_MIN_MS} and {SESSION_TIMEOUT_MAX_MS}"
            )
        if session_timeout_ms < idle_timeout_ms:
            raise ValueError("session_timeout_ms must not be less than idle_timeout_ms")
        super().__init__(address, OracleHandler)
        self.timeout = 0.05
        self.trace_path = trace_path
        self.max_requests = max_requests
        self.expected_requests = expected_requests
        self.idle_timeout_ms = idle_timeout_ms
        self.session_timeout_ms = session_timeout_ms
        self.started_at = time.monotonic()
        self.last_activity = self.started_at
        self._sequence = 0
        self._requests = 0
        self._completed_requests = 0
        self._stop_requested = False
        self._trace_bytes = 0
        self._trace_file = trace_path.open("w", encoding="utf-8", newline="\n")

    def next_sequence(self) -> int:
        self._sequence += 1
        return self._sequence

    def request_timeout_seconds(self) -> float:
        """Return the bounded remaining deadline for the current request."""

        now = time.monotonic()
        idle_remaining = self.idle_timeout_ms / 1000 - (now - self.last_activity)
        session_remaining = self.session_timeout_ms / 1000 - (now - self.started_at)
        remaining = min(idle_remaining, session_remaining)
        if remaining <= 0:
            self._stop_requested = True
            return 0.0
        return min(REQUEST_TIMEOUT_SECONDS, remaining)

    def deadline_expired(self) -> bool:
        """Return whether the session or idle deadline has elapsed."""

        return self.request_timeout_seconds() <= 0

    def record(self, record: dict[str, object]) -> None:
        encoded = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
        encoded_length = len(encoded) + 1
        if len(encoded) > MAX_TRACE_RECORD_BYTES:
            raise ValueError("trace record exceeds fixture limit")
        if self._trace_bytes + encoded_length > MAX_TRACE_BYTES:
            self._stop_requested = True
            raise ValueError("trace output exceeds fixture limit")
        self._trace_file.write(encoded.decode("utf-8") + "\n")
        self._trace_file.flush()
        self._trace_bytes += encoded_length
        self.last_activity = time.monotonic()

    def begin_request(self) -> None:
        """Consume one accepted connection from the finite request cap."""

        self._requests += 1
        self.last_activity = time.monotonic()
        if self.max_requests is not None and self._requests >= self.max_requests:
            self._stop_requested = True

    def complete_request(self) -> None:
        """Mark one bounded response complete and stop at the exact target."""

        self._completed_requests += 1
        self.last_activity = time.monotonic()
        if (
            self.expected_requests is not None
            and self._completed_requests >= self.expected_requests
        ):
            self._stop_requested = True

    def run_until_stopped(self) -> None:
        while not self._stop_requested:
            now = time.monotonic()
            if (now - self.started_at) * 1000 >= self.session_timeout_ms:
                self._stop_requested = True
                break
            if (now - self.last_activity) * 1000 >= self.idle_timeout_ms:
                self._stop_requested = True
                break
            self.handle_request()

    def server_close(self) -> None:
        try:
            self._trace_file.flush()
            self._trace_file.close()
        finally:
            super().server_close()


def _publish_ready(path: Path, server: OracleServer) -> None:
    """Publish endpoint policy with a bounded, atomic ready-file rename."""

    assigned_port = server.server_address[1]
    if not PORT_MIN <= assigned_port <= PORT_MAX:
        raise ValueError("the allocated endpoint port is outside the allowed range")
    record = {
        "protocol": "jmeter-rs-http-state-v1",
        "host": HOST,
        "port": assigned_port,
        "max_requests": server.max_requests,
        "expected_requests": server.expected_requests,
    }
    payload = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )
    if len(payload) > MAX_READY_BYTES:
        raise ValueError("ready metadata exceeds fixture limit")
    path.parent.mkdir(parents=True, exist_ok=True)
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
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        raise


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--host", type=_loopback_host, default=HOST)
    parser.add_argument("--port", type=_port, default=DEFAULT_PORT)
    parser.add_argument("--trace", "--trace-file", dest="trace", type=Path, required=True)
    parser.add_argument("--ready", "--ready-file", dest="ready", type=Path)
    parser.add_argument(
        "--max-requests",
        "--max-request",
        dest="max_requests",
        type=_max_requests,
        default=DEFAULT_MAX_REQUESTS,
    )
    parser.add_argument(
        "--expected-requests",
        dest="expected_requests",
        type=_expected_requests,
        help="stop gracefully after this many completed request responses",
    )
    parser.add_argument(
        "--idle-timeout-ms",
        type=_idle_timeout,
        default=DEFAULT_IDLE_TIMEOUT_MS,
    )
    parser.add_argument(
        "--session-timeout-ms",
        type=_session_timeout,
        default=DEFAULT_SESSION_TIMEOUT_MS,
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    args.trace.parent.mkdir(parents=True, exist_ok=True)
    server = OracleServer(
        (args.host, args.port),
        args.trace,
        args.max_requests,
        args.expected_requests,
        args.idle_timeout_ms,
        args.session_timeout_ms,
    )
    try:
        if args.ready is not None:
            _publish_ready(args.ready, server)
        server.run_until_stopped()
    except KeyboardInterrupt:
        # The serving process owns shutdown; no signal or external process
        # is needed to finish the current request and close the trace.
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
