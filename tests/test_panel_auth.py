from __future__ import annotations

import base64
import http.client
import json
import stat
import threading
from pathlib import Path

import pytest


@pytest.fixture
def auth_home(tmp_path, monkeypatch):
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
    panel_auth.reset_state()
    try:
        yield paths
    finally:
        panel_auth.reset_state()
        for field, value in previous.items():
            object.__setattr__(paths, field, value)


def test_scrypt_store_roundtrip_and_file_mode(auth_home):
    import wpfy.panel_auth as panel_auth

    panel_auth.add_user("admin", "same-password", role=panel_auth.ROLE_ADMIN)
    panel_auth.add_user("manager", "same-password", role=panel_auth.ROLE_SITE_MANAGER, sites=("one.example",))

    raw = json.loads(panel_auth.users_path().read_text(encoding="utf-8"))["users"]
    assert stat.S_IMODE(panel_auth.users_path().stat().st_mode) == 0o600
    assert raw[0]["password_salt"] != raw[1]["password_salt"]
    assert raw[0]["password_hash"] != raw[1]["password_hash"]
    assert "same-password" not in panel_auth.users_path().read_text(encoding="utf-8")
    assert panel_auth.verify_password("admin", "same-password")
    assert not panel_auth.verify_password("admin", "wrong")
    assert not panel_auth.verify_password("missing", "same-password")
    assert all("password_hash" not in user and "totp_secret" not in user for user in panel_auth.list_users())


@pytest.mark.parametrize(("timestamp", "expected"), (
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
    (20000000000, "65353130"),
))
def test_totp_rfc6238_sha1_vectors(auth_home, timestamp, expected):
    from wpfy.panel_auth import totp_code

    assert totp_code(b"12345678901234567890", timestamp, digits=8) == expected


def test_lockout_is_per_user_and_recorded(auth_home, monkeypatch):
    import wpfy.events as events
    import wpfy.panel_auth as panel_auth

    monkeypatch.setattr(panel_auth, "MAX_LOGIN_FAILURES", 2)
    panel_auth.add_user("first", "first-password", role=panel_auth.ROLE_ADMIN)
    panel_auth.add_user("second", "second-password", role=panel_auth.ROLE_ADMIN)

    assert panel_auth.login("first", "wrong") is None
    assert panel_auth.login("first", "wrong") is None
    assert panel_auth.login("first", "first-password") is None
    assert panel_auth.login("second", "second-password") is not None
    assert any(event["action"] == "auth.login.lockout" for event in events.list_events())


def test_totp_rejects_non_ascii_digits_without_escaping(auth_home):
    import wpfy.panel_auth as panel_auth

    panel_auth.add_user("admin", "admin-password", role=panel_auth.ROLE_ADMIN)
    panel_auth.enable_totp("admin")

    assert panel_auth.login("admin", "admin-password", "١٢٣٤٥٦") is None


def test_locked_login_runs_the_same_dummy_kdf_as_unknown_login(auth_home, monkeypatch):
    import wpfy.panel_auth as panel_auth

    monkeypatch.setattr(panel_auth, "MAX_LOGIN_FAILURES", 2)
    panel_auth.add_user("admin", "admin-password", role=panel_auth.ROLE_ADMIN)
    assert panel_auth.login("admin", "wrong-password") is None
    assert panel_auth.login("admin", "wrong-password") is None

    original = panel_auth._scrypt_candidate
    calls = []

    def counted(password, salt):
        calls.append((password, salt))
        return original(password, salt)

    monkeypatch.setattr(panel_auth, "_scrypt_candidate", counted)
    assert panel_auth.login("admin", "admin-password") is None
    locked_calls = len(calls)
    calls.clear()
    assert panel_auth.login("missing", "admin-password") is None
    unknown_calls = len(calls)

    assert locked_calls == unknown_calls == 1


def test_last_admin_cannot_be_demoted_or_removed(auth_home):
    import wpfy.panel_auth as panel_auth

    with pytest.raises(ValueError, match="at least one administrator"):
        panel_auth.add_user("manager", "manager-password", role=panel_auth.ROLE_SITE_MANAGER)
    assert panel_auth.list_users() == []

    panel_auth.add_user("first", "first-password", role=panel_auth.ROLE_ADMIN)
    panel_auth.add_user("second", "second-password", role=panel_auth.ROLE_ADMIN)
    panel_auth.add_user("manager", "manager-password", role=panel_auth.ROLE_SITE_MANAGER)
    panel_auth.set_role("first", panel_auth.ROLE_SITE_MANAGER)

    with pytest.raises(ValueError, match="at least one administrator"):
        panel_auth.update_user("second", role=panel_auth.ROLE_SITE_MANAGER)
    with pytest.raises(ValueError, match="at least one administrator"):
        panel_auth.remove_user("second")

    assert [(user["username"], user["role"]) for user in panel_auth.list_users()] == [
        ("first", panel_auth.ROLE_SITE_MANAGER),
        ("manager", panel_auth.ROLE_SITE_MANAGER),
        ("second", panel_auth.ROLE_ADMIN),
    ]


def test_removing_the_last_user_restores_run_token_bootstrap(auth_home):
    import wpfy.panel_auth as panel_auth

    panel_auth.add_user("solo", "solo-password", role=panel_auth.ROLE_ADMIN)
    panel_auth.remove_user("solo")

    assert panel_auth.list_users() == []
    assert panel_auth.login_required() is False


def test_corrupt_store_fails_closed_and_password_reset_revokes_sessions(auth_home):
    import wpfy.panel_auth as panel_auth

    panel_auth.add_user("admin", "first-password", role=panel_auth.ROLE_ADMIN)
    token, _ = panel_auth.login("admin", "first-password")
    panel_auth.set_password("admin", "second-password")
    assert panel_auth.authenticate_session(token) is None

    panel_auth.users_path().write_text("{broken", encoding="utf-8")
    assert panel_auth.login_required() is True
    assert panel_auth.verify_password("admin", "second-password") is False


def test_pending_totp_enrollment_does_not_lock_out_password_login(auth_home):
    import wpfy.panel_auth as panel_auth

    panel_auth.add_user("admin", "admin-password", role=panel_auth.ROLE_ADMIN)
    panel_auth.begin_totp_enrollment("admin")

    assert panel_auth.list_users()[0]["totp_enabled"] is False
    assert panel_auth.login("admin", "admin-password") is not None


def test_totp_enrollment_requires_code_and_rejects_replay(auth_home):
    import time

    import wpfy.panel_auth as panel_auth

    panel_auth.add_user("admin", "admin-password", role=panel_auth.ROLE_ADMIN)
    panel_auth.add_user("manager", "manager-password", role=panel_auth.ROLE_SITE_MANAGER)
    secret_b32, uri = panel_auth.enable_totp("manager")
    assert secret_b32 in uri
    with pytest.raises(ValueError, match="already enabled"):
        panel_auth.enable_totp("manager")

    assert panel_auth.login("manager", "manager-password") is None
    secret = base64.b32decode(secret_b32 + "=" * ((8 - len(secret_b32) % 8) % 8))
    code = panel_auth.totp_code(secret, time.time())
    assert panel_auth.login("manager", "manager-password", code) is not None
    assert panel_auth.login("manager", "manager-password", code) is None


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


def test_api_auth_errors_and_empty_store_bootstrap(auth_home):
    import time

    import wpfy.panel as panel
    import wpfy.panel_auth as panel_auth

    panel_auth.add_user("admin", "admin-password", role=panel_auth.ROLE_ADMIN)
    config = panel.PanelConfig(host="127.0.0.1", port=0, token="bootstrap-run-token")
    server = panel.make_panel_server(config)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        status, login = _request(
            host, port, "/api/auth/login", method="POST",
            body={"username": "admin", "password": "admin-password"},
        )
        assert status == 200
        token = login["token"]
        status, enrollment = _request(host, port, "/api/auth/totp", method="POST", token=token, body={})
        assert status == 200
        secret = base64.b32decode(
            enrollment["secret"] + "=" * ((8 - len(enrollment["secret"]) % 8) % 8),
        )
        code = panel_auth.totp_code(secret, time.time())
        assert _request(
            host, port, "/api/auth/totp", method="POST", token=token, body={"code": code},
        )[0] == 200
        assert _request(
            host, port, "/api/auth/login", method="POST",
            body={"username": "admin", "password": "admin-password", "totp": "١٢٣٤٥٦"},
        )[0] == 401
        assert _request(
            host, port, "/api/users/admin", method="PUT", token=token,
            body={"role": panel_auth.ROLE_SITE_MANAGER},
        )[0] == 400
        assert panel_auth.list_users()[0]["role"] == panel_auth.ROLE_ADMIN
        assert _request(host, port, "/api/users/admin", method="DELETE", token=token, body={})[0] == 200
        assert panel_auth.login_required() is False
        assert _request(host, port, "/api/users", token=config.token)[0] == 200
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_cli_reports_admin_invariant_and_allows_empty_store(auth_home):
    from types import SimpleNamespace

    import wpfy.cli as cli
    import wpfy.panel_auth as panel_auth

    panel_auth.add_user("admin", "admin-password", role=panel_auth.ROLE_ADMIN)
    panel_auth.add_user("manager", "manager-password", role=panel_auth.ROLE_SITE_MANAGER)

    role_result = cli.handle_panel_auth(SimpleNamespace(
        panel_command="user", panel_user_command="set-role",
        username="admin", role=panel_auth.ROLE_SITE_MANAGER,
    ))
    remove_result = cli.handle_panel_auth(SimpleNamespace(
        panel_command="user", panel_user_command="remove", username="admin",
    ))
    assert role_result.exit_code == remove_result.exit_code == 2
    assert "at least one administrator" in role_result.message
    assert "at least one administrator" in remove_result.message

    assert cli.handle_panel_auth(SimpleNamespace(
        panel_command="user", panel_user_command="remove", username="manager",
    )).exit_code == 0
    assert cli.handle_panel_auth(SimpleNamespace(
        panel_command="user", panel_user_command="remove", username="admin",
    )).exit_code == 0
    assert panel_auth.login_required() is False


def test_live_session_lifecycle_and_role_boundary(auth_home):
    import wpfy.panel as panel
    import wpfy.panel_auth as panel_auth

    panel_auth.add_user("admin", "admin-password", role=panel_auth.ROLE_ADMIN)
    panel_auth.add_user(
        "manager", "manager-password", role=panel_auth.ROLE_SITE_MANAGER, sites=("assigned.example",),
    )
    config = panel.PanelConfig(host="127.0.0.1", port=0, token="dead-run-token")
    server = panel.make_panel_server(config)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        status, admin = _request(
            host, port, "/api/auth/login", method="POST",
            body={"username": "admin", "password": "admin-password"},
        )
        assert status == 200
        status, manager = _request(
            host, port, "/api/auth/login", method="POST",
            body={"username": "manager", "password": "manager-password"},
        )
        assert status == 200

        assert _request(host, port, "/api/auth/me", token=manager["token"])[0] == 200
        assert _request(host, port, "/api/users", token=manager["token"])[0] == 403
        assert _request(host, port, "/api/users", token=admin["token"])[0] == 200
        assert _request(host, port, "/api/sites", method="POST", token=manager["token"], body={})[0] == 403

        assert _request(
            host, port, "/api/auth/logout", method="POST", token=manager["token"], body={},
        )[0] == 200
        assert _request(host, port, "/api/auth/me", token=manager["token"])[0] == 401
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_authorize_role_matrix(auth_home):
    import wpfy.panel as panel
    import wpfy.panel_auth as panel_auth

    admin = {"username": "admin", "role": panel_auth.ROLE_ADMIN, "sites": []}
    manager = {"username": "manager", "role": panel_auth.ROLE_SITE_MANAGER, "sites": ["one.example"]}

    for route in panel._ROUTES:
        if route.meta.scope != "public":
            panel.authorize(admin, route.meta, "one.example" if "domain" in route.pattern.groupindex else None)

    panel.authorize(manager, panel.RouteMeta("site.read", "site"), "one.example")
    panel.authorize(manager, panel.RouteMeta("site.list", "system"), None)
    with pytest.raises(panel.PanelError) as denied_site:
        panel.authorize(manager, panel.RouteMeta("site.read", "site"), "two.example")
    assert denied_site.value.status == 403
    with pytest.raises(panel.PanelError) as denied_system:
        panel.authorize(manager, panel.RouteMeta("system.overview", "system"), None)
    assert denied_system.value.status == 403


def test_client_login_throttle_expires_and_allows_a_valid_login(auth_home, monkeypatch):
    import wpfy.panel_auth as panel_auth

    now = [100.0]
    monkeypatch.setattr(panel_auth, "MAX_CLIENT_FAILURES", 2)
    monkeypatch.setattr(panel_auth, "CLIENT_COOLDOWN_SECONDS", 5)
    monkeypatch.setattr(panel_auth.time, "time", lambda: now[0])
    panel_auth.add_user("admin", "admin-password", role=panel_auth.ROLE_ADMIN)

    assert panel_auth.login("missing-one", "wrong", client="198.51.100.8") is None
    assert panel_auth.login("missing-two", "wrong", client="198.51.100.8") is None
    assert panel_auth.client_throttled("198.51.100.8")

    now[0] = 106.0
    assert not panel_auth.client_throttled("198.51.100.8")
    assert panel_auth.login("admin", "admin-password", client="198.51.100.8") is not None
