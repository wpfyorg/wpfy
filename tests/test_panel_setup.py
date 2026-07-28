from __future__ import annotations

import base64
import http.client
import json
import stat
import threading
import time
from http.server import ThreadingHTTPServer

import pytest


def _request(host, port, path, *, method="GET", token=None, body=None):
    connection = http.client.HTTPConnection(host, port, timeout=10)
    headers = {}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    payload = None
    if body is not None:
        payload = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    try:
        connection.request(method, path, body=payload, headers=headers)
        response = connection.getresponse()
        return response.status, json.loads(response.read().decode("utf-8"))
    finally:
        connection.close()


@pytest.fixture
def setup_home(tmp_wpfy_home):
    import wpfy.panel_auth as panel_auth

    panel_auth.reset_state()
    try:
        yield tmp_wpfy_home
    finally:
        panel_auth.reset_state()


@pytest.fixture
def setup_server(setup_home):
    import wpfy.panel as panel

    config = panel.PanelConfig(host="127.0.0.1", port=0, token="fresh-run-token")
    server = panel.make_panel_server(config)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address, config
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _account(**updates):
    body = {
        "first_name": "Ada",
        "last_name": "Lovelace",
        "username": "ada",
        "email": "ada@example.com",
        "password": "correct-horse-battery",
        "confirm_password": "correct-horse-battery",
        "license_accepted": True,
        "telemetry_enabled": True,
    }
    body.update(updates)
    return body


def test_setup_creates_profile_private_state_and_permanently_closes_routes(setup_server):
    import wpfy.panel_auth as panel_auth
    import wpfy.panel_setup as panel_setup

    (host, port), config = setup_server
    assert _request(host, port, "/api/setup/status", token=config.token) == (
        200,
        {"configured": False, "setup_available": True, "edge_bound": False, "password_min_length": 12},
    )
    assert _request(host, port, "/api/setup/status", token="wrong")[0] == 401

    status, created = _request(host, port, "/api/setup", method="POST", token=config.token, body=_account())
    assert status == 201
    assert created["username"] == "ada"
    session = created["token"]

    users = panel_auth.list_users()
    assert users == [{
        "username": "ada", "first_name": "Ada", "last_name": "Lovelace", "email": "ada@example.com",
        "role": "admin", "sites": [], "totp_enabled": False,
    }]
    stored = panel_setup.state()
    assert stored["license_accepted_by"] == "ada"
    assert stored["license_version"] == "LICENSE"
    assert stored["telemetry_enabled"] is True
    assert stored["install_id"]
    assert stat.S_IMODE(panel_setup.state_path().stat().st_mode) == 0o600

    assert _request(host, port, "/api/setup/status", token=session)[0] == 410
    assert _request(host, port, "/api/setup", method="POST", token=session, body=_account())[0] == 410
    assert _request(host, port, "/api/setup", method="POST", token=config.token, body=_account())[0] == 401


def test_setup_password_license_edge_and_client_throttle(setup_home, monkeypatch):
    import wpfy.panel as panel
    import wpfy.panel_auth as panel_auth

    config = panel.PanelConfig(host="127.0.0.1", port=0, token="fresh-run-token", edge_bind=True)
    server = ThreadingHTTPServer((config.host, config.port), panel.make_panel_handler(config))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        status, payload = _request(host, port, "/api/setup", method="POST", token=config.token, body=_account())
        assert status == 403
        assert "SSH tunnel" in payload["error"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    monkeypatch.setattr(panel_auth, "MAX_CLIENT_FAILURES", 2)
    config = panel.PanelConfig(host="127.0.0.1", port=0, token="fresh-run-token")
    server = panel.make_panel_server(config)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        short = _account(password="short", confirm_password="short")
        assert _request(host, port, "/api/setup", method="POST", token=config.token, body=short)[0] == 400
        no_license = _account(license_accepted=False)
        assert _request(host, port, "/api/setup", method="POST", token=config.token, body=no_license)[0] == 400
        assert _request(host, port, "/api/setup", method="POST", token=config.token, body=_account())[0] == 429
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_setup_totp_verifies_before_storage_and_skip_is_explicit(setup_server):
    import wpfy.events as events
    import wpfy.panel_auth as panel_auth

    (host, port), config = setup_server
    _, created = _request(host, port, "/api/setup", method="POST", token=config.token, body=_account())
    session = created["token"]

    status, enrollment = _request(
        host, port, "/api/setup/totp", method="POST", token=session, body={"action": "begin"},
    )
    assert status == 200
    assert panel_auth.list_users()[0]["totp_enabled"] is False
    assert _request(
        host, port, "/api/setup/totp", method="POST", token=session, body={"action": "begin"},
    )[0] == 409
    assert _request(
        host, port, "/api/setup/totp", method="POST", token=session,
        body={"action": "verify", "code": "000000"},
    )[0] == 400
    assert panel_auth.list_users()[0]["totp_enabled"] is False

    secret = base64.b32decode(enrollment["secret"] + "=" * ((8 - len(enrollment["secret"]) % 8) % 8))
    code = panel_auth.totp_code(secret, time.time())
    assert _request(
        host, port, "/api/setup/totp", method="POST", token=session,
        body={"action": "verify", "code": code},
    )[0] == 200
    assert panel_auth.list_users()[0]["totp_enabled"] is True
    assert _request(
        host, port, "/api/setup/totp", method="POST", token=session, body={"action": "skip", "confirm": True},
    )[0] == 410
    assert any(event["action"] == "panel.totp.enrolled" for event in events.list_events())
    serialized = json.dumps(events.list_events())
    assert enrollment["secret"] not in serialized
    assert "ada@example.com" not in serialized


def test_setup_totp_skip_needs_second_confirmation(setup_server):
    import wpfy.events as events

    (host, port), config = setup_server
    _, created = _request(host, port, "/api/setup", method="POST", token=config.token, body=_account())
    session = created["token"]
    status, payload = _request(
        host, port, "/api/setup/totp", method="POST", token=session, body={"action": "skip"},
    )
    assert status == 400
    assert "cannot be published" in payload["error"]
    assert _request(
        host, port, "/api/setup/totp", method="POST", token=session,
        body={"action": "skip", "confirm": True},
    )[0] == 200
    assert _request(
        host, port, "/api/setup/totp", method="POST", token=session,
        body={"action": "skip", "confirm": True},
    )[0] == 410
    assert any(event["action"] == "panel.totp.skipped" for event in events.list_events())


def test_concurrent_first_run_requests_create_one_admin(setup_home):
    import threading

    import wpfy.panel_auth as panel_auth
    import wpfy.panel_setup as panel_setup

    bodies = [_account(username="first-admin"), _account(username="second-admin")]
    results = []

    def create(body):
        try:
            results.append(panel_setup.create_account(body, client="198.51.100.14", edge_bind=False))
        except ValueError as exc:
            results.append(exc)

    threads = [threading.Thread(target=create, args=(body,)) for body in bodies]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert sum(not isinstance(result, ValueError) for result in results) == 1
    assert len(panel_auth.list_users()) == 1


def test_old_user_records_read_with_empty_profile_fields(setup_home):
    import wpfy.panel_auth as panel_auth

    panel_auth.users_path().parent.mkdir(parents=True)
    panel_auth.users_path().write_text(json.dumps({"users": [{
        "username": "legacy", "role": "admin", "sites": [], "password_hash": "00", "password_salt": "00",
        "totp_secret": None,
    }]}), encoding="utf-8")
    assert panel_auth.list_users()[0] == {
        "username": "legacy", "first_name": "", "last_name": "", "email": "", "role": "admin",
        "sites": [], "totp_enabled": False,
    }
