"""Opus-owned immutable gates: HTTP keep-alive body desync in the panel.

An actor may not edit, skip, xfail, parametrize away, or delete anything here.
If a gate is wrong, escalate with evidence; do not change the file.

WHAT THIS FILE IS ABOUT

`PanelHandler.protocol_version = "HTTP/1.1"`, so every connection is keep-alive
by default. `_handle_api` rejects a request in several places **before** the
request body is ever read:

    principal is None                 -> 401
    authorize(...) refuses            -> 403
    no route matched                  -> 404
    Content-Length invalid            -> 400

If that request carried a body, its bytes are still sitting in the socket.
`BaseHTTPRequestHandler` then reads the *next* request line from the same
socket and gets body bytes instead — the connection is desynchronised. Every
subsequent request on it is parsed from the wrong offset.

Today the only mitigation is three copies of

    if route is not None and route.meta.raw_body:
        self.close_connection = True

in the three `except` arms. That covers upload routes and nothing else. A
plain `POST /api/sites` with a JSON body and a bad token desyncs, and no test
notices because every existing test opens a fresh connection per request.

Why this is worth a gate rather than a patch: Phase 7b exposes the panel
through Traefik, and Traefik pools connections to its backend. Leftover bytes
from one user's rejected request can then prefix a different user's request on
the same pooled connection. That is a cross-user boundary, not a cosmetic bug.

THE CONTRACT

  K1  A rejected request that declared an unread body must not leave the
      connection reusable in a desynchronised state.
  K2  Anti-vacuity for K1: a request whose body *is* consumed must keep the
      connection alive. "Close everything, always" is not a fix; it silently
      halves the panel's throughput and would make K1 pass for free.
  K3  A request whose framing itself is refused (`Content-Length: not-a-number`)
      behaves like K1. This reaches a different arm — `_content_length` raises
      before the route is even considered — so it is not a restatement of K1.
  K4  The 404 path (no route matched at all) behaves like K1.
  K5  A GET with no body keeps the connection alive — the ordinary case must
      not regress.

K1, K3 and K4 are the phase's work and must fail before it. K2 and K5 are
regression guards and pass today; that is disclosed rather than hidden.

Verified pre-implementation: 3 failed, 2 passed. K1's failure evidence is the
whole bug in one line — the follow-up request came back as

    HTTP/1.1 501 Unsupported method ('{}GET')

because the two leftover body bytes `{}` were consumed as the beginning of the
next request line.

HOW THE CHECK WORKS

Each gate speaks raw HTTP on one socket. It sends the offending request, reads
the response head, and then — if the server did not say `Connection: close` and
did not hang up — sends a second, well-formed request on the same socket and
demands a valid status line back. A desynchronised server answers the second
request by parsing leftover body bytes as a request line, which is the failure
these gates detect. Closing the connection is an acceptable answer; silently
staying open with unread bytes is not.
"""

from __future__ import annotations

import importlib
import json
import socket
import threading

import pytest

TOKEN = "gate-keepalive-token"


@pytest.fixture()
def panel_server(tmp_path, monkeypatch):
    monkeypatch.setenv("WPFY_INSTALL_ROOT", str(tmp_path / "opt"))
    monkeypatch.setenv("WPFY_CONFIG_DIR", str(tmp_path / "etc"))
    monkeypatch.setenv("WPFY_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("WPFY_LOG_DIR", str(tmp_path / "log"))
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")

    import wpfy.settings

    importlib.reload(wpfy.settings)
    for name in ("wpfy.registry", "wpfy.events", "wpfy.panel_auth", "wpfy.panel"):
        importlib.reload(importlib.import_module(name))
    import wpfy.panel

    for directory in ("opt", "etc", "state", "log"):
        (tmp_path / directory).mkdir(parents=True, exist_ok=True)

    config = wpfy.panel.PanelConfig(host="127.0.0.1", port=0, token=TOKEN)
    server = wpfy.panel.make_panel_server(config)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _request(method: str, path: str, *, token: str | None, body: dict | None) -> bytes:
    raw = b"" if body is None else json.dumps(body).encode("utf-8")
    head = [f"{method} {path} HTTP/1.1", "Host: 127.0.0.1", "Content-Length: %d" % len(raw)]
    if token is not None:
        head.append(f"Authorization: Bearer {token}")
    if body is not None:
        head.append("Content-Type: application/json")
    return ("\r\n".join(head) + "\r\n\r\n").encode("ascii") + raw


def _read_head(sock: socket.socket) -> bytes:
    sock.settimeout(5)
    buffered = b""
    while b"\r\n\r\n" not in buffered:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        buffered += chunk
    return buffered


def _drain_body(sock: socket.socket, head: bytes) -> None:
    """Consume exactly the declared response body so the socket is positioned at
    the next response, mirroring what a real keep-alive client does."""
    header_blob, _, tail = head.partition(b"\r\n\r\n")
    length = 0
    for line in header_blob.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            length = int(line.split(b":", 1)[1].strip())
    remaining = length - len(tail)
    while remaining > 0:
        chunk = sock.recv(min(4096, remaining))
        if not chunk:
            return
        remaining -= len(chunk)


def _connection_survives_a_rejection(address, method: str, path: str, token: str | None, body: dict):
    """Send one request that will be refused before its body is read, then probe
    the same connection. Returns (closed, second_status_line)."""
    sock = socket.create_connection(address, timeout=5)
    try:
        sock.sendall(_request(method, path, token=token, body=body))
        head = _read_head(sock)
        assert head.startswith(b"HTTP/1.1 "), f"no response to the rejected request: {head!r}"
        status = int(head.split(b" ")[1])
        assert status >= 400, f"expected a rejection, got {status}"

        if b"connection: close" in head.lower():
            return True, None
        _drain_body(sock, head)

        sock.sendall(_request("GET", "/api/sites", token=TOKEN, body=None))
        follow = _read_head(sock)
        if not follow:
            # Server hung up without announcing it. Ugly, but not desynchronised.
            return True, None
        return False, follow.split(b"\r\n", 1)[0]
    finally:
        sock.close()


def _assert_no_desync(address, method: str, path: str, token: str | None, body: dict) -> None:
    closed, status_line = _connection_survives_a_rejection(address, method, path, token, body)
    if closed:
        return
    assert status_line is not None and status_line.startswith(b"HTTP/1.1 "), (
        "the connection stayed open with the rejected request's body unread, so the "
        "next request was parsed from the wrong offset. The server answered a "
        f"well-formed follow-up request with: {status_line!r}"
    )
    code = int(status_line.split(b" ")[1])
    assert code < 400, (
        "a well-formed follow-up request on the reused connection was rejected "
        f"({code}), which means the leftover body bytes were parsed as its request line"
    )


def test_gate_rejected_request_with_unread_body_does_not_desync(panel_server):
    """K1: 401 before the body is read. The declared body is never consumed, so
    a keep-alive connection is left pointing at JSON where a request line
    should be."""
    _assert_no_desync(
        panel_server, "POST", "/api/sites", "wrong-token-entirely",
        {"domain": "gate.example", "flavor": "wp", "padding": "x" * 512},
    )


def test_gate_unknown_endpoint_with_unread_body_does_not_desync(panel_server):
    """K4: the 404 arm raises before any body read, with a valid token."""
    _assert_no_desync(
        panel_server, "POST", "/api/does-not-exist", TOKEN,
        {"padding": "y" * 512},
    )


def test_gate_malformed_content_length_does_not_desync(panel_server):
    """K3 variant reached without a user store: a request whose framing the
    server refuses must not leave the connection reusable. Distinct from K1 in
    that the failure happens in `_content_length`, a different arm."""
    sock = socket.create_connection(panel_server, timeout=5)
    try:
        sock.sendall(
            b"POST /api/sites HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            b"Authorization: Bearer " + TOKEN.encode() + b"\r\n"
            b"Content-Length: not-a-number\r\n\r\n{}"
        )
        head = _read_head(sock)
        assert head.startswith(b"HTTP/1.1 "), f"no response at all: {head!r}"
        if b"connection: close" in head.lower():
            return
        _drain_body(sock, head)
        sock.sendall(_request("GET", "/api/sites", token=TOKEN, body=None))
        follow = _read_head(sock)
        if not follow:
            return
        assert follow.startswith(b"HTTP/1.1 "), (
            f"connection desynchronised after a bad Content-Length: {follow!r}"
        )
        assert int(follow.split(b" ")[1]) < 400, (
            f"follow-up request rejected after a bad Content-Length: {follow!r}"
        )
    finally:
        sock.close()


def test_gate_consumed_body_keeps_the_connection_alive(panel_server):
    """K2: anti-vacuity. `close_connection = True` on every response would make
    K1, K3 and K4 pass while quietly discarding keep-alive for the whole panel.
    A request whose body the server actually read must stay reusable."""
    sock = socket.create_connection(panel_server, timeout=5)
    try:
        sock.sendall(_request("POST", "/api/sites", token=TOKEN, body={"domain": ""}))
        head = _read_head(sock)
        assert head.startswith(b"HTTP/1.1 "), f"no response: {head!r}"
        assert b"connection: close" not in head.lower(), (
            "the panel closed a connection whose request body it fully consumed; "
            "keep-alive must survive an ordinary request"
        )
        _drain_body(sock, head)

        sock.sendall(_request("GET", "/api/sites", token=TOKEN, body=None))
        follow = _read_head(sock)
        assert follow.startswith(b"HTTP/1.1 "), f"reused connection broke: {follow!r}"
        assert int(follow.split(b" ")[1]) < 400, f"reused connection returned {follow!r}"
    finally:
        sock.close()


def test_gate_bodyless_get_keeps_the_connection_alive(panel_server):
    """K5: the ordinary case. Two GETs on one connection, no bodies involved."""
    sock = socket.create_connection(panel_server, timeout=5)
    try:
        for _ in range(2):
            sock.sendall(_request("GET", "/api/sites", token=TOKEN, body=None))
            head = _read_head(sock)
            assert head.startswith(b"HTTP/1.1 "), f"no response: {head!r}"
            assert int(head.split(b" ")[1]) < 400, f"site list returned {head!r}"
            assert b"connection: close" not in head.lower(), (
                "the panel closed a plain keep-alive GET connection"
            )
            _drain_body(sock, head)
    finally:
        sock.close()
