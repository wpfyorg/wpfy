from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import stat
import threading
import time
from pathlib import Path

import pytest

import wpfy.panel_auth as _panel_auth

# Captured before the autouse fixture patches the module symbol, so cache
# contract tests can exercise the real discovery implementation.
_REAL_DISCOVER_NEVER_BAN_EDGE = _panel_auth._discover_never_ban_edge_cidrs


@pytest.fixture(autouse=True)
def _offline_never_ban(monkeypatch):
    # The emission guard discovers never-ban edge addresses from Docker on
    # first failure; keep every test deterministic and offline. Tests that
    # exercise the discovery path override this patch.
    import wpfy.panel_auth as panel_auth

    monkeypatch.setattr(panel_auth, "_discover_never_ban_edge_cidrs", lambda: ())


@pytest.fixture
def auth_log_home(tmp_path, monkeypatch):
    import wpfy.panel_auth as panel_auth
    import wpfy.settings as settings

    paths = settings.PATHS
    previous = {
        "install_root": paths.install_root,
        "config_dir": paths.config_dir,
        "state_dir": paths.state_dir,
        "log_dir": paths.log_dir,
    }
    for field in previous:
        object.__setattr__(paths, field, str(tmp_path / field))
    Path(paths.config_dir).mkdir(parents=True)
    Path(paths.state_dir).mkdir(parents=True)
    Path(paths.log_dir).mkdir(parents=True)
    panel_auth.reset_state()
    try:
        yield paths
    finally:
        panel_auth.reset_state()
        for field, value in previous.items():
            object.__setattr__(paths, field, value)


def _read_log(log_dir: str) -> list[dict]:
    path = Path(log_dir) / "panel-auth.log"
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def _expected_hash(username: str) -> str:
    return "sha256:" + hashlib.sha256(username[:64].encode("utf-8")).hexdigest()


def test_panel_auth_log_path_uses_log_dir(auth_log_home):
    import wpfy.panel_auth as panel_auth

    expected = Path(auth_log_home.log_dir) / "panel-auth.log"
    assert panel_auth.panel_auth_log_path() == expected


def test_failed_login_emits_one_record(auth_log_home):
    import wpfy.panel_auth as panel_auth

    panel_auth.add_user("admin", "admin-password", role=panel_auth.ROLE_ADMIN)
    assert panel_auth.login("admin", "wrong", client="203.0.113.8") is None

    records = _read_log(auth_log_home.log_dir)
    assert len(records) == 1
    rec = records[0]
    assert rec["event"] == "panel_auth_failure"
    assert rec["surface"] == "password"
    assert rec["client_ip"] == "203.0.113.8"
    assert rec["account_hash"] == _expected_hash("admin")
    assert rec["reason_class"] == "invalid_credentials"
    assert "timestamp" in rec


def test_success_emits_nothing(auth_log_home):
    import wpfy.panel_auth as panel_auth

    panel_auth.add_user("admin", "admin-password", role=panel_auth.ROLE_ADMIN)
    assert panel_auth.login("admin", "admin-password", client="10.0.0.1") is not None

    records = _read_log(auth_log_home.log_dir)
    assert records == []


def test_below_threshold_failures_all_logged(auth_log_home):
    import wpfy.panel_auth as panel_auth

    panel_auth.add_user("admin", "admin-password", role=panel_auth.ROLE_ADMIN)
    for _ in range(3):
        assert panel_auth.login("admin", "wrong", client="198.51.100.1") is None

    records = _read_log(auth_log_home.log_dir)
    assert len(records) == 3
    assert all(r["reason_class"] == "invalid_credentials" for r in records)


def test_unknown_and_known_user_produce_indistinguishable_records(auth_log_home):
    import wpfy.panel_auth as panel_auth

    panel_auth.add_user("admin", "admin-password", role=panel_auth.ROLE_ADMIN)
    assert panel_auth.login("admin", "wrong", client="10.0.0.1") is None
    assert panel_auth.login("nonexistent", "wrong", client="10.0.0.1") is None

    records = _read_log(auth_log_home.log_dir)
    assert len(records) == 2
    assert records[0]["account_hash"] == _expected_hash("admin")
    assert records[1]["account_hash"] == _expected_hash("nonexistent")
    assert records[0]["reason_class"] == records[1]["reason_class"] == "invalid_credentials"
    # Both use same hash algorithm — no "unknown user" vs "user found" distinction
    for rec in records:
        assert "unknown" not in json.dumps(rec).lower() or rec["client_ip"] == "0.0.0.0"


def test_injection_username_produces_single_valid_json_line(auth_log_home):
    import wpfy.panel_auth as panel_auth

    panel_auth.add_user("admin", "admin-password", role=panel_auth.ROLE_ADMIN)
    evil_username = 'evil"}\n{"event":"x'
    assert panel_auth.login(evil_username, "wrong", client="10.0.0.1") is None

    log_path = Path(auth_log_home.log_dir) / "panel-auth.log"
    raw = log_path.read_text(encoding="utf-8")
    lines = [line for line in raw.splitlines() if line.strip()]
    assert len(lines) == 1
    rec = json.loads(lines[0])
    assert rec["event"] == "panel_auth_failure"
    assert rec["account_hash"] == _expected_hash("")
    assert evil_username not in raw


def test_ipv4_and_ipv6_normalization(auth_log_home):
    import wpfy.panel_auth as panel_auth

    panel_auth.add_user("admin", "admin-password", role=panel_auth.ROLE_ADMIN)
    assert panel_auth.login("admin", "wrong", client="192.168.1.1") is None
    assert panel_auth.login("admin", "wrong", client="::1") is None
    assert panel_auth.login("admin", "wrong", client="2001:db8::1") is None
    assert panel_auth.login("admin", "wrong", client="not-an-ip") is None

    records = _read_log(auth_log_home.log_dir)
    assert len(records) == 4
    assert records[0]["client_ip"] == "192.168.1.1"
    # ::1 is loopback, a never-ban identity; the emission guard redacts it to
    # the 0.0.0.0 sentinel instead of writing a bannable record.
    assert records[1]["client_ip"] == "0.0.0.0"
    assert records[2]["client_ip"] == "2001:db8::1"
    assert records[3]["client_ip"] == "0.0.0.0"


def test_totp_failure_emits_totp_failed(auth_log_home):
    import wpfy.panel_auth as panel_auth

    panel_auth.add_user("admin", "admin-password", role=panel_auth.ROLE_ADMIN)
    panel_auth.enable_totp("admin")
    # Password correct but TOTP wrong
    assert panel_auth.login("admin", "admin-password", "000000", client="10.0.0.1") is None

    records = _read_log(auth_log_home.log_dir)
    assert len(records) == 1
    assert records[0]["reason_class"] == "totp_failed"


def test_locked_account_emits_locked(auth_log_home, monkeypatch):
    import wpfy.panel_auth as panel_auth

    monkeypatch.setattr(panel_auth, "MAX_LOGIN_FAILURES", 2)
    panel_auth.add_user("admin", "admin-password", role=panel_auth.ROLE_ADMIN)

    # Two failures to trigger lockout
    assert panel_auth.login("admin", "wrong", client="10.0.0.1") is None
    assert panel_auth.login("admin", "wrong", client="10.0.0.1") is None
    # Third attempt while locked
    assert panel_auth.login("admin", "admin-password", client="10.0.0.1") is None

    records = _read_log(auth_log_home.log_dir)
    assert len(records) == 3
    assert records[0]["reason_class"] == "invalid_credentials"
    assert records[1]["reason_class"] == "invalid_credentials"
    assert records[2]["reason_class"] == "locked"


def test_throttled_client_emits_throttled(auth_log_home, monkeypatch):
    import wpfy.panel_auth as panel_auth

    monkeypatch.setattr(panel_auth, "MAX_CLIENT_FAILURES", 2)
    monkeypatch.setattr(panel_auth, "CLIENT_COOLDOWN_SECONDS", 60)
    panel_auth.add_user("admin", "admin-password", role=panel_auth.ROLE_ADMIN)

    assert panel_auth.login("x", "wrong", client="10.0.0.1") is None
    assert panel_auth.login("y", "wrong", client="10.0.0.1") is None
    # Now throttled
    assert panel_auth.login("admin", "admin-password", client="10.0.0.1") is None

    records = _read_log(auth_log_home.log_dir)
    assert len(records) == 3
    assert records[2]["reason_class"] == "throttled"


def test_log_file_permissions(auth_log_home):
    import wpfy.panel_auth as panel_auth

    panel_auth.add_user("admin", "admin-password", role=panel_auth.ROLE_ADMIN)
    assert panel_auth.login("admin", "wrong", client="10.0.0.1") is None

    log_path = Path(auth_log_home.log_dir) / "panel-auth.log"
    assert log_path.exists()
    mode = stat.S_IMODE(log_path.stat().st_mode)
    assert mode == 0o600


def test_rotation_at_size_cap(auth_log_home, monkeypatch):
    import wpfy.panel_auth as panel_auth

    # Set a tiny cap so rotation triggers quickly
    monkeypatch.setattr(panel_auth, "_PANEL_AUTH_LOG_MAX_BYTES", 200)
    panel_auth.add_user("admin", "admin-password", role=panel_auth.ROLE_ADMIN)

    # Write enough to trigger at least one rotation
    for _ in range(20):
        panel_auth.login("admin", "wrong", client="10.0.0.1")

    log_dir = Path(auth_log_home.log_dir)
    # After rotation, .1 file should exist
    assert (log_dir / "panel-auth.log.1").exists()


def test_rotation_copytruncate_preserves_inode_for_fail2ban_tail(auth_log_home, monkeypatch):
    """t16 W1 pin: panel-auth.log rotates copytruncate-style — the active file
    keeps its inode so a tailing fail2ban never loses the tail after rotation
    (rename rotation would strand it on the renamed inode)."""
    import wpfy.panel_auth as panel_auth

    monkeypatch.setattr(panel_auth, "_PANEL_AUTH_LOG_MAX_BYTES", 200)
    panel_auth.add_user("admin", "admin-password", role=panel_auth.ROLE_ADMIN)

    log_path = Path(auth_log_home.log_dir) / "panel-auth.log"
    for _ in range(6):
        panel_auth.login("admin", "wrong", client="203.0.113.30")
    inode_before = log_path.stat().st_ino

    # Push past the cap to force a rotation, then verify the active file's
    # inode is unchanged and the rotated content landed in .1.
    for _ in range(20):
        panel_auth.login("admin", "wrong", client="203.0.113.31")
    assert log_path.stat().st_ino == inode_before
    assert (Path(auth_log_home.log_dir) / "panel-auth.log.1").exists()
    # The tail stays continuous: a post-rotation append still lands in the
    # same inode fail2ban is tailing.
    panel_auth.login("admin", "wrong", client="203.0.113.32")
    assert log_path.stat().st_ino == inode_before
    records = _read_log(auth_log_home.log_dir)
    assert any(rec["client_ip"] == "203.0.113.32" for rec in records)


def test_rotation_keeps_max_files(auth_log_home, monkeypatch):
    import wpfy.panel_auth as panel_auth

    monkeypatch.setattr(panel_auth, "_PANEL_AUTH_LOG_MAX_BYTES", 100)
    panel_auth.add_user("admin", "admin-password", role=panel_auth.ROLE_ADMIN)

    for _ in range(50):
        panel_auth.login("admin", "wrong", client="10.0.0.1")

    log_dir = Path(auth_log_home.log_dir)
    # Should have .1, .2, .3 but NOT .4
    assert (log_dir / "panel-auth.log.1").exists()
    assert (log_dir / "panel-auth.log.2").exists()
    assert (log_dir / "panel-auth.log.3").exists()
    assert not (log_dir / "panel-auth.log.4").exists()


def test_no_password_or_totp_in_log(auth_log_home):
    import wpfy.panel_auth as panel_auth

    panel_auth.add_user("admin", "admin-password", role=panel_auth.ROLE_ADMIN)
    panel_auth.enable_totp("admin")
    panel_auth.login("admin", "admin-password", "123456", client="10.0.0.1")

    log_path = Path(auth_log_home.log_dir) / "panel-auth.log"
    if log_path.exists():
        raw = log_path.read_text(encoding="utf-8")
        assert "admin-password" not in raw
        assert "123456" not in raw


def test_no_plaintext_username_in_log(auth_log_home):
    import wpfy.panel_auth as panel_auth

    panel_auth.add_user("admin", "admin-password", role=panel_auth.ROLE_ADMIN)
    panel_auth.login("admin", "wrong", client="10.0.0.1")

    log_path = Path(auth_log_home.log_dir) / "panel-auth.log"
    raw = log_path.read_text(encoding="utf-8")
    rec = json.loads(raw.strip())
    # Username should only appear as hash, never plaintext
    assert "account_hash" in rec
    assert rec["account_hash"].startswith("sha256:")
    # The raw username "admin" should not appear as a standalone field value
    for key, value in rec.items():
        if key != "account_hash" and isinstance(value, str):
            assert value != "admin"


def test_empty_client_ip_normalizes(auth_log_home):
    import wpfy.panel_auth as panel_auth

    panel_auth.add_user("admin", "admin-password", role=panel_auth.ROLE_ADMIN)
    assert panel_auth.login("admin", "wrong", client=None) is None
    assert panel_auth.login("admin", "wrong", client="") is None

    records = _read_log(auth_log_home.log_dir)
    assert len(records) == 2
    assert all(r["client_ip"] == "0.0.0.0" for r in records)


def test_record_has_exactly_expected_keys(auth_log_home):
    import wpfy.panel_auth as panel_auth

    panel_auth.add_user("admin", "admin-password", role=panel_auth.ROLE_ADMIN)
    panel_auth.login("admin", "wrong", client="10.0.0.1")

    records = _read_log(auth_log_home.log_dir)
    assert len(records) == 1
    expected_keys = {"timestamp", "event", "surface", "client_ip", "account_hash", "reason_class"}
    assert set(records[0].keys()) == expected_keys


def test_never_ban_loopback_redacted_to_sentinel(auth_log_home):
    # Loopback (127.0.0.0/8, ::1) is a never-ban identity: banning it would be
    # useless against an attacker and loopback is already fail2ban-allowlisted.
    # The emission guard redacts the record to the 0.0.0.0 sentinel.
    import wpfy.panel_auth as panel_auth

    panel_auth.add_user("admin", "admin-password", role=panel_auth.ROLE_ADMIN)
    assert panel_auth.login("admin", "wrong", client="127.0.0.1") is None
    assert panel_auth.login("admin", "wrong", client="::1") is None

    records = _read_log(auth_log_home.log_dir)
    assert len(records) == 2
    assert all(rec["client_ip"] == "0.0.0.0" for rec in records)


def test_never_ban_docker_bridge_redacted_to_sentinel(auth_log_home):
    # A container on the default Docker bridge is not an attacker worth
    # banning; its address must never be written as a bannable client.
    import wpfy.panel_auth as panel_auth

    panel_auth.add_user("admin", "admin-password", role=panel_auth.ROLE_ADMIN)
    assert panel_auth.login("admin", "wrong", client="172.17.0.2") is None

    records = _read_log(auth_log_home.log_dir)
    assert len(records) == 1
    assert records[0]["client_ip"] == "0.0.0.0"


def test_never_ban_cloudflare_edge_redacted_when_configured(auth_log_home, monkeypatch):
    # Cloudflare edge ranges join the never-ban set (published ranges; env
    # override respected). A resolved stop at a Cloudflare edge is
    # infrastructure, never a real attacker, and must not be bannable.
    monkeypatch.setenv("WPFY_CLOUDFLARE_RANGES", "172.64.0.0/13,2400:cb00::/32")
    import wpfy.panel_auth as panel_auth

    panel_auth.add_user("admin", "admin-password", role=panel_auth.ROLE_ADMIN)
    assert panel_auth.login("admin", "wrong", client="172.64.0.10") is None
    assert panel_auth.login("admin", "wrong", client="2400:cb00::1") is None

    records = _read_log(auth_log_home.log_dir)
    assert len(records) == 2
    assert all(rec["client_ip"] == "0.0.0.0" for rec in records)


def test_never_ban_trusted_edge_redacted_at_emission(auth_log_home, monkeypatch):
    # Defense in depth: even if a trusted edge address reached the writer
    # (e.g. inside the resolution TTL window after a Traefik recreate), the
    # emission guard redacts it. Never-ban must hold at emission too.
    import wpfy.panel_auth as panel_auth

    monkeypatch.setattr(panel_auth, "_discover_never_ban_edge_cidrs", lambda: ("10.0.0.5/32",))
    panel_auth.add_user("admin", "admin-password", role=panel_auth.ROLE_ADMIN)
    assert panel_auth.login("admin", "wrong", client="10.0.0.5") is None

    records = _read_log(auth_log_home.log_dir)
    assert len(records) == 1
    assert records[0]["client_ip"] == "0.0.0.0"


def test_legitimate_attacker_behind_trusted_proxy_still_emits_real_ip(auth_log_home, monkeypatch):
    # Never over-drop: a genuine attacker IP resolved from a valid forwarded
    # chain is not in the never-ban set and must still be emitted so the
    # fail2ban layer can act on it.
    import wpfy.panel_auth as panel_auth

    monkeypatch.setattr(panel_auth, "_discover_never_ban_edge_cidrs", lambda: ("10.0.0.5/32",))
    panel_auth.add_user("admin", "admin-password", role=panel_auth.ROLE_ADMIN)
    assert panel_auth.login("admin", "wrong", client="203.0.113.77") is None
    assert panel_auth.login("admin", "wrong", client="2001:db8::10") is None

    records = _read_log(auth_log_home.log_dir)
    assert [rec["client_ip"] for rec in records] == ["203.0.113.77", "2001:db8::10"]


# ---------------------------------------------------------------------------
# Phase 12 panel tests (login-shield-plan.md 1176-1198), items 1-3, 14-18,
# plus Phase 11 hardening (O_NOFOLLOW, directory mode, health_failed).
# ---------------------------------------------------------------------------


def _start_server(auth_log_home, token="bootstrap-run-token"):
    import wpfy.panel as panel

    config = panel.PanelConfig(host="127.0.0.1", port=0, token=token)
    server = panel.make_panel_server(config)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    return server, thread, host, port, token


def _request(host, port, path, *, method="GET", token=None, body=None, headers=None):
    request_headers = dict(headers or {})
    if token is not None:
        request_headers["Authorization"] = f"Bearer {token}"
    payload = None
    if body is not None:
        payload = json.dumps(body).encode("utf-8")
        request_headers["Content-Type"] = "application/json"
    connection = http.client.HTTPConnection(host, port, timeout=10)
    try:
        connection.request(method, path, body=payload, headers=request_headers)
        response = connection.getresponse()
        raw = response.read().decode("utf-8")
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = raw
        lowered = {name.lower(): value for name, value in response.getheaders()}
        return response.status, parsed, lowered
    finally:
        connection.close()


def _stop_server(server, thread):
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


_VALID_SETUP_BODY = {
    "username": "admin",
    "password": "admin-password-123",
    "confirm_password": "admin-password-123",
    "first_name": "First",
    "last_name": "Last",
    "email": "admin@example.com",
    "license_accepted": True,
    "telemetry_enabled": False,
}


def test_setup_failure_emits_setup_surface(auth_log_home):
    # Phase 12 item 1: every failed authentication attempt on every
    # session-creating surface emits one valid record. /api/setup is a
    # session-creating surface and must emit surface "setup".
    import wpfy.panel as panel

    server, thread, host, port, run_token = _start_server(auth_log_home)
    try:
        bad = dict(_VALID_SETUP_BODY, password="short", confirm_password="short")
        status, _, _ = _request(host, port, "/api/setup", method="POST", token=run_token, body=bad)
        assert status == 400

        records = _read_log(auth_log_home.log_dir)
        assert len(records) == 1
        rec = records[0]
        assert rec["event"] == "panel_auth_failure"
        assert rec["surface"] == "setup"
        assert rec["reason_class"] == "invalid_credentials"
        assert rec["account_hash"] == _expected_hash("admin")
        assert "short" not in json.dumps(rec)
    finally:
        _stop_server(server, thread)


def test_setup_success_emits_nothing(auth_log_home):
    # Phase 12 item 3: successful setup must not emit a failure record.
    import wpfy.panel as panel

    server, thread, host, port, run_token = _start_server(auth_log_home)
    try:
        status, _, _ = _request(host, port, "/api/setup", method="POST", token=run_token, body=_VALID_SETUP_BODY)
        assert status == 201
        assert _read_log(auth_log_home.log_dir) == []
    finally:
        _stop_server(server, thread)


def test_setup_totp_failure_emits_setup_totp_surface(auth_log_home):
    # Phase 12 item 11 (TOTP failures covered): the /api/setup/totp verify
    # failure emits surface "setup_totp" with reason "totp_failed" and no
    # secret material.
    import wpfy.panel as panel

    server, thread, host, port, run_token = _start_server(auth_log_home)
    try:
        status, setup, _ = _request(host, port, "/api/setup", method="POST", token=run_token, body=_VALID_SETUP_BODY)
        assert status == 201
        token = setup["token"]
        status, _, _ = _request(
            host, port, "/api/setup/totp", method="POST", token=token, body={"action": "begin"},
        )
        assert status == 200
        status, _, _ = _request(
            host, port, "/api/setup/totp", method="POST", token=token,
            body={"action": "verify", "code": "000000"},
        )
        assert status == 400

        records = _read_log(auth_log_home.log_dir)
        assert len(records) == 1
        rec = records[0]
        assert rec["surface"] == "setup_totp"
        assert rec["reason_class"] == "totp_failed"
        assert "000000" not in json.dumps(rec)
        assert rec["account_hash"] == _expected_hash("admin")
    finally:
        _stop_server(server, thread)


def test_authorization_and_cookie_never_reach_log(auth_log_home):
    # Phase 4 / Phase 11: Authorization headers, cookies, and passwords must
    # never appear in the auth log. The writer's fixed schema cannot carry
    # them; pin that with a hostile request.
    import wpfy.panel as panel

    server, thread, host, port, run_token = _start_server(auth_log_home)
    try:
        status, _, _ = _request(
            host, port, "/api/auth/login", method="POST",
            body={"username": "admin", "password": "wrong-password-xyz"},
            headers={"Authorization": "Bearer top-secret-token-xyz", "Cookie": "session=abc123"},
        )
        assert status == 401
        raw = (Path(auth_log_home.log_dir) / "panel-auth.log").read_text(encoding="utf-8")
        assert "top-secret-token-xyz" not in raw
        assert "abc123" not in raw
        assert "wrong-password-xyz" not in raw
    finally:
        _stop_server(server, thread)


def test_retry_after_header_is_correct(auth_log_home, monkeypatch):
    # Phase 12 item 18: a throttled login returns HTTP 429 with an accurate
    # Retry-After (seconds until the client cooldown expires).
    import wpfy.panel as panel
    import wpfy.panel_auth as panel_auth

    monkeypatch.setattr(panel_auth, "MAX_CLIENT_FAILURES", 2)
    monkeypatch.setattr(panel_auth, "CLIENT_COOLDOWN_SECONDS", 60)
    now = [1000.0]
    monkeypatch.setattr(panel_auth.time, "time", lambda: now[0])
    panel_auth.add_user("admin", "admin-password", role=panel_auth.ROLE_ADMIN)

    server, thread, host, port, run_token = _start_server(auth_log_home)
    try:
        # First failure registers (count=1) and returns a plain 401.
        status, _, _ = _request(
            host, port, "/api/auth/login", method="POST",
            body={"username": "admin", "password": "wrong"},
        )
        assert status == 401
        # Second failure hits the client threshold; the failing attempt itself
        # returns 429 with an accurate Retry-After (existing threshold
        # semantics preserved).
        status, _, headers = _request(
            host, port, "/api/auth/login", method="POST",
            body={"username": "admin", "password": "wrong"},
        )
        assert status == 429
        assert headers.get("retry-after") == "60"
        # While the cooldown is active, even a correct password stays 429.
        status, _, headers = _request(
            host, port, "/api/auth/login", method="POST",
            body={"username": "admin", "password": "admin-password"},
        )
        assert status == 429
        assert headers.get("retry-after") == "60"
    finally:
        _stop_server(server, thread)


def test_setup_throttled_emits_throttled_with_retry_after(auth_log_home, monkeypatch):
    # Phase 12 item 18 + surface coverage: the setup surface is throttled with
    # 429 + Retry-After and emits reason "throttled".
    import wpfy.panel as panel
    import wpfy.panel_auth as panel_auth

    monkeypatch.setattr(panel_auth, "MAX_CLIENT_FAILURES", 2)
    monkeypatch.setattr(panel_auth, "CLIENT_COOLDOWN_SECONDS", 60)
    now = [1000.0]
    monkeypatch.setattr(panel_auth.time, "time", lambda: now[0])

    server, thread, host, port, run_token = _start_server(auth_log_home)
    try:
        bad = dict(_VALID_SETUP_BODY, password="short", confirm_password="short")
        for _ in range(2):
            status, _, _ = _request(host, port, "/api/setup", method="POST", token=run_token, body=bad)
            assert status == 400
        status, _, headers = _request(host, port, "/api/setup", method="POST", token=run_token, body=bad)
        assert status == 429
        assert headers.get("retry-after") == "60"

        records = _read_log(auth_log_home.log_dir)
        assert len(records) == 3
        assert [rec["reason_class"] for rec in records] == [
            "invalid_credentials", "invalid_credentials", "throttled",
        ]
        assert all(rec["surface"] == "setup" for rec in records)
    finally:
        _stop_server(server, thread)


def test_concurrent_failed_attempts_all_emit_valid_records(auth_log_home):
    # Phase 12 item 17: concurrent attempts cannot bypass counters or lose
    # records; every attempt emits exactly one valid JSONL record.
    import wpfy.panel_auth as panel_auth

    panel_auth.add_user("admin", "admin-password", role=panel_auth.ROLE_ADMIN)
    threads = 8
    per_thread = 5
    errors: list[BaseException] = []

    def worker(seed: int) -> None:
        try:
            for index in range(per_thread):
                panel_auth.login(f"user-{seed}-{index}", "wrong", client="198.51.100.77")
        except BaseException as exc:  # pragma: no cover - failure diagnostic
            errors.append(exc)

    running = [threading.Thread(target=worker, args=(seed,)) for seed in range(threads)]
    for thread in running:
        thread.start()
    for thread in running:
        thread.join(timeout=30)

    assert not errors
    records = _read_log(auth_log_home.log_dir)
    assert len(records) == threads * per_thread
    for rec in records:
        assert set(rec.keys()) == {"timestamp", "event", "surface", "client_ip", "account_hash", "reason_class"}
        assert rec["event"] == "panel_auth_failure"
        assert rec["reason_class"] in {"invalid_credentials", "throttled"}


def test_o_nofollow_prevents_symlink_log_write(auth_log_home):
    # Phase 11 symlink-attack resistance: writing through a symlinked log path
    # must fail with O_NOFOLLOW (OSError) and never clobber the target; the
    # failure surfaces as login_shield.health_failed.
    import wpfy.events as events
    import wpfy.panel_auth as panel_auth

    panel_auth.add_user("admin", "admin-password", role=panel_auth.ROLE_ADMIN)
    target = Path(auth_log_home.log_dir) / "victim.txt"
    target.write_text("do-not-clobber", encoding="utf-8")
    link = Path(auth_log_home.log_dir) / "panel-auth.log"
    link.symlink_to(target)

    with pytest.raises(OSError):
        panel_auth.login("admin", "wrong", client="198.51.100.9")

    assert target.read_text(encoding="utf-8") == "do-not-clobber"
    assert not (Path(auth_log_home.log_dir) / "panel-auth.log.1").exists()
    assert any(event["action"] == "login_shield.health_failed" for event in events.list_events())


def test_log_directory_mode_0700(auth_log_home):
    # Phase 11: the auth log directory is created/tightened to 0700 so other
    # local users cannot enumerate or replace the log.
    import wpfy.panel_auth as panel_auth

    log_dir = Path(auth_log_home.log_dir)
    os.chmod(log_dir, 0o755)
    panel_auth.add_user("admin", "admin-password", role=panel_auth.ROLE_ADMIN)
    assert panel_auth.login("admin", "wrong", client="198.51.100.9") is None

    assert stat.S_IMODE(log_dir.stat().st_mode) == 0o700


def test_write_failure_surfaces_health_failed(auth_log_home):
    # Phase 4 fail2ban health behavior + t09 hardening: a log write failure
    # (here EISDIR on the log path) is never silently swallowed; it surfaces
    # as login_shield.health_failed and propagates out of the login call.
    import wpfy.events as events
    import wpfy.panel_auth as panel_auth

    panel_auth.add_user("admin", "admin-password", role=panel_auth.ROLE_ADMIN)
    (Path(auth_log_home.log_dir) / "panel-auth.log").mkdir()

    with pytest.raises(OSError):
        panel_auth.login("admin", "wrong", client="198.51.100.9")

    assert any(event["action"] == "login_shield.health_failed" for event in events.list_events())


def test_never_ban_discovery_total_failure_is_not_cached(monkeypatch):    # Wave-3 gate finding (OWNER=t09): a total discovery failure must not be
    # cached as an empty tuple; the next record must re-attempt discovery.
    import wpfy.panel_auth as panel_auth

    with panel_auth._NEVER_BAN_EDGE_LOCK:
        panel_auth._NEVER_BAN_EDGE_CACHE = None
    calls = {"n": 0}

    def flaky(_network_name: str) -> tuple[str, ...]:
        calls["n"] += 1
        raise RuntimeError("docker unavailable")

    monkeypatch.setattr(panel_auth.traefik, "traefik_network_cidrs", flaky)
    monkeypatch.setattr(panel_auth.traefik, "_network_gateway", lambda _network_name: None)

    assert _REAL_DISCOVER_NEVER_BAN_EDGE() == ()
    assert calls["n"] == 2
    with panel_auth._NEVER_BAN_EDGE_LOCK:
        assert panel_auth._NEVER_BAN_EDGE_CACHE is None

    monkeypatch.setattr(panel_auth.traefik, "traefik_network_cidrs", lambda _network_name: ("10.0.0.5/32",))
    assert _REAL_DISCOVER_NEVER_BAN_EDGE() == ("10.0.0.5/32",)
    with panel_auth._NEVER_BAN_EDGE_LOCK:
        assert panel_auth._NEVER_BAN_EDGE_CACHE is not None


def test_login_failure_response_exposes_no_failure_counter(auth_log_home):
    # Phase 12 constraint (login-shield-plan.md): users must never see exact
    # failure counters. The 401 body stays a single generic error key; any
    # count/threshold state is observable only via headers (Retry-After).
    import wpfy.panel as panel

    server, thread, host, port, run_token = _start_server(auth_log_home)
    try:
        status, body, headers = _request(
            host, port, "/api/auth/login", method="POST",
            body={"username": "admin", "password": "wrong"},
        )
        assert status == 401
        assert isinstance(body, dict)
        assert set(body.keys()) <= {"error"}
        serialized = json.dumps(body).lower()
        assert "counter" not in serialized
        assert "failures" not in serialized
        assert "attempts" not in serialized
        assert "remaining" not in serialized
        assert not any(isinstance(value, int) for value in body.values())
        # Throttle state is communicated via the Retry-After header only.
        assert "retry-after" not in headers or headers["retry-after"] == "0"
    finally:
        _stop_server(server, thread)


def test_blocked_request_skips_password_verification(auth_log_home, monkeypatch, fake_clock):
    # Phase 12 item 6: while a client is throttled (or an account locked), the
    # login path returns before the expensive scrypt verification runs. The
    # locked branch runs only the constant-work dummy KDF, never verify.
    import wpfy.panel as panel
    import wpfy.panel_auth as panel_auth

    monkeypatch.setattr(panel_auth, "MAX_CLIENT_FAILURES", 2)
    monkeypatch.setattr(panel_auth, "CLIENT_COOLDOWN_SECONDS", 60)
    calls = {"n": 0}
    real_verify = panel_auth.verify_password

    def counting_verify(username, password):
        calls["n"] += 1
        return real_verify(username, password)

    monkeypatch.setattr(panel_auth, "verify_password", counting_verify)
    panel_auth.add_user("admin", "admin-password", role=panel_auth.ROLE_ADMIN)

    server, thread, host, port, run_token = _start_server(auth_log_home)
    try:
        for _ in range(2):
            _request(
                host, port, "/api/auth/login", method="POST",
                body={"username": "admin", "password": "wrong"},
            )
        # The two failures ran verification; the throttled third attempt does
        # not (it returns 429 before verify_password is reached).
        assert calls["n"] == 2
        status, _, _ = _request(
            host, port, "/api/auth/login", method="POST",
            body={"username": "admin", "password": "admin-password"},
        )
        assert status == 429
        assert calls["n"] == 2
    finally:
        _stop_server(server, thread)


@pytest.fixture
def fake_clock(monkeypatch):
    import wpfy.panel_auth as panel_auth

    clock = {"now": 1_000_000.0}
    monkeypatch.setattr(panel_auth.time, "time", lambda: clock["now"])
    return clock
