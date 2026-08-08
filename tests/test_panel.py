from __future__ import annotations

import importlib
from datetime import datetime, timedelta, timezone
from io import BytesIO
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import socket
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

TEST_TOKEN = "test-panel-token"
SECRET_MARKER = "s3cr3t-db-password"


def _seed_site(paths, domain: str = "example.com") -> Path:
    site = Path(paths.sites_dir) / domain
    site.mkdir(parents=True, exist_ok=True)
    (site / ".env").write_text(
        f"DOMAIN={domain}\n"
        "SITE_FLAVOR=wp\n"
        "PHP_VERSION=8.4\n"
        "LETSENCRYPT_MODE=disabled\n"
        "SITE_UID=1806\n"
        f"MARIADB_PASSWORD={SECRET_MARKER}\n",
        encoding="utf-8",
    )
    (site / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
    (site / "app").mkdir(exist_ok=True)
    return site


@pytest.fixture
def panel_server(tmp_wpfy_home, monkeypatch):
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    monkeypatch.setenv("WPFY_FM_ENABLED", "1")

    import wpfy.site_layout
    import wpfy.operational_inspection
    import wpfy.panel

    importlib.reload(wpfy.site_layout)
    importlib.reload(wpfy.operational_inspection)
    importlib.reload(wpfy.panel)

    config = wpfy.panel.PanelConfig(host="127.0.0.1", port=0, token=TEST_TOKEN)
    server = wpfy.panel.make_panel_server(config)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_address[1]}"
    yield base_url, tmp_wpfy_home
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


def _request(base_url: str, path: str, *, token: str | None = TEST_TOKEN, method: str = "GET", body: dict | None = None):
    request = urllib.request.Request(f"{base_url}{path}", method=method)
    if token is not None:
        request.add_header("Authorization", f"Bearer {token}")
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, data=data, timeout=10) as response:
            return response.status, response.read().decode("utf-8"), response.headers
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8"), exc.headers


def _raw_request(base_url: str, path: str, *, method: str = "GET", raw: bytes | None = None):
    request = urllib.request.Request(f"{base_url}{path}", method=method)
    request.add_header("Authorization", f"Bearer {TEST_TOKEN}")
    if raw is not None:
        request.add_header("Content-Type", "application/octet-stream")
    try:
        with urllib.request.urlopen(request, data=raw, timeout=10) as response:
            return response.status, response.read(), response.headers
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), exc.headers


def test_run_token_principal_supports_identity_and_totp_routes(panel_server):
    base_url, _ = panel_server

    status, body, _ = _request(base_url, "/api/auth/me")
    assert status == 200
    assert json.loads(body) == {
        "username": "run-token-admin",
        "role": "admin",
        "sites": [],
    }

    status, body, _ = _request(base_url, "/api/auth/totp", method="POST", body={})
    assert status == 409
    assert "panel user not found" in body

    status, body, _ = _request(base_url, "/api/auth/totp", method="DELETE")
    assert status == 400
    assert "panel user not found" in body


def test_api_requires_token(panel_server):
    base_url, _ = panel_server
    status, body, _ = _request(base_url, "/api/overview", token=None)
    assert status == 401
    assert "version" not in body

    status, body, _ = _request(base_url, "/api/overview", token="wrong-token")
    assert status == 401
    assert "version" not in body


def test_overview_reports_state(panel_server):
    base_url, paths = panel_server
    _seed_site(paths)
    status, body, headers = _request(base_url, "/api/overview")
    assert status == 200
    assert headers["Content-Type"].startswith("application/json")
    payload = json.loads(body)
    assert payload["site_count"] == 1
    assert payload["version"]


def test_unhandled_api_exception_returns_safe_500(panel_server, monkeypatch, caplog):
    import wpfy.panel as panel

    def explode(*args):
        raise TypeError("private failure detail")

    routes = tuple(
        panel.Route(route.method, route.pattern, explode, route.meta)
        if route.meta.action == "system.overview" else route
        for route in panel._ROUTES
    )
    monkeypatch.setattr(panel, "_ROUTES", routes)
    caplog.set_level("ERROR", logger="wpfy.panel")

    status, raw_body, headers = _raw_request(panel_server[0], "/api/overview", raw=b"unread")
    body = raw_body.decode("utf-8")

    assert status == 500
    assert json.loads(body) == {"error": "internal server error"}
    assert "private failure detail" not in body
    assert headers["Connection"] == "close"
    assert "unhandled panel API error" in caplog.text
    assert "private failure detail" in caplog.text


def test_sites_list_and_detail(panel_server):
    base_url, paths = panel_server
    _seed_site(paths)

    status, body, _ = _request(base_url, "/api/sites")
    assert status == 200
    sites = json.loads(body)["sites"]
    assert [site["domain"] for site in sites] == ["example.com"]

    status, body, _ = _request(base_url, "/api/sites/example.com")
    assert status == 200
    site = json.loads(body)["site"]
    assert site["flavor"] == "wp"

    status, _, _ = _request(base_url, "/api/sites/missing.example")
    assert status == 404


def test_responses_never_leak_env_secrets(panel_server):
    base_url, paths = panel_server
    _seed_site(paths)
    for path in ("/api/overview", "/api/sites", "/api/sites/example.com", "/api/sites/example.com/health"):
        _, body, _ = _request(base_url, path)
        assert SECRET_MARKER not in body, f"secret leaked via {path}"


def test_site_health_offline(panel_server):
    base_url, paths = panel_server
    _seed_site(paths)
    status, body, _ = _request(base_url, "/api/sites/example.com/health")
    assert status == 200
    health = json.loads(body)["health"]
    assert health["domain"] == "example.com"
    assert health["runtime_ready"] is False


def test_phase2_operational_status_codes(panel_server, monkeypatch):
    base_url, paths = panel_server
    _seed_site(paths)

    status, body, _ = _request(base_url, "/api/sites/example.com/databases")
    assert status == 503
    assert json.loads(body) == {
        "ok": False,
        "exit_code": 3,
        "databases": [],
        "message": "database operation refused: Docker runtime unavailable",
    }

    status, body, _ = _request(
        base_url, "/api/sites/example.com/databases", method="POST", body={"name": "bad-name"},
    )
    assert status == 400
    assert "invalid database name" in json.loads(body)["error"]

    status, body, _ = _request(base_url, "/api/sites/missing.example/databases")
    assert status == 404
    assert "site not found" in json.loads(body)["error"]

    import wpfy.panel
    from wpfy.site_runtime import RuntimeResult

    nginx_failure = (
        'nginx: [emerg] unknown directive "broken" in /etc/nginx/wpfy-extra/custom.conf:1\n'
        "nginx: configuration file /etc/nginx/nginx.conf test failed"
    )
    monkeypatch.setattr(
        wpfy.panel,
        "set_nginx_custom",
        lambda domain, content: RuntimeResult(1, nginx_failure, ran=True),
    )
    status, body, _ = _request(
        base_url, "/api/sites/example.com/nginx-custom", method="PUT", body={"content": "broken on;\n"},
    )
    assert status == 422
    assert json.loads(body) == {"ok": False, "exit_code": 1, "nginx_test_output": nginx_failure}

    runtime_failure = "nginx custom config refused: Docker runtime unavailable for validation"
    monkeypatch.setattr(
        wpfy.panel,
        "set_nginx_custom",
        lambda domain, content: RuntimeResult(3, runtime_failure, skipped=True),
    )
    status, body, _ = _request(
        base_url, "/api/sites/example.com/nginx-custom", method="PUT", body={"content": "location / {}\n"},
    )
    assert status == 503
    assert json.loads(body) == {"ok": False, "exit_code": 3, "nginx_test_output": runtime_failure}

    monkeypatch.setattr(
        wpfy.panel,
        "set_nginx_custom",
        lambda domain, content: RuntimeResult(3, "nginx custom command failed: permission denied", ran=True),
    )
    status, body, _ = _request(
        base_url, "/api/sites/example.com/nginx-custom", method="PUT", body={"content": "location / {}\n"},
    )
    assert status == 500
    assert "permission denied" in json.loads(body)["nginx_test_output"]


def test_runtime_action_reports_unavailable_when_it_skips(panel_server):
    """A runtime action that skipped started nothing, so it must not answer 2xx.

    The operation layer reports "Docker is unavailable, so I did nothing" as exit 0.
    Passing that through as 200 told the operator their site was started when no
    container moved. Only pure-runtime actions get this treatment: an sftp rotate that
    skips has already written the new password, so it stays 2xx (gate G2 pins that).
    """
    base_url, paths = panel_server
    _seed_site(paths)
    status, body, _ = _request(
        base_url, "/api/sites/example.com/runtime", method="POST", body={"action": "start"},
    )
    assert status == 503
    payload = json.loads(body)
    assert payload["skipped"] is True

    status, _, _ = _request(
        base_url, "/api/sites/example.com/runtime", method="POST", body={"action": "explode"},
    )
    assert status == 400


def test_backups_roundtrip_offline(panel_server):
    base_url, paths = panel_server
    _seed_site(paths)

    status, body, _ = _request(base_url, "/api/sites/example.com/backups")
    assert status == 200
    assert json.loads(body)["backups"] == []

    status, body, _ = _request(base_url, "/api/sites/example.com/backups", method="POST")
    assert status == 200
    assert json.loads(body)["ok"] is True

    status, body, _ = _request(base_url, "/api/sites/example.com/backups")
    backups = json.loads(body)["backups"]
    assert len(backups) == 1
    assert backups[0]["name"].startswith("example.com-")

    status, _, _ = _request(
        base_url, "/api/sites/example.com/restore", method="POST", body={"archive": "nope.tar.gz"},
    )
    assert status == 404


def test_wp_endpoint_validates_args(panel_server, monkeypatch):
    base_url, paths = panel_server
    _seed_site(paths)

    status, _, _ = _request(base_url, "/api/sites/example.com/wp", method="POST", body={"args": []})
    assert status == 400

    import wpfy.panel
    from wpfy.site_runtime import ProcessResult
    captured: dict = {}

    def fake_wp(domain, *args, interactive=False):
        captured["domain"] = domain
        captured["args"] = args
        return ProcessResult(0, stdout="5.9.1\n", ran=True)

    monkeypatch.setattr(wpfy.panel, "run_wp_cli", fake_wp)
    status, body, _ = _request(
        base_url, "/api/sites/example.com/wp", method="POST", body={"args": ["core", "version"]},
    )
    assert status == 200
    assert json.loads(body)["stdout"] == "5.9.1\n"
    assert captured["domain"] == "example.com"
    assert captured["args"] == ("core", "version")


def test_logs_api_delegates_to_runtime(monkeypatch):
    import wpfy.panel as panel
    from wpfy.site_runtime import ProcessResult

    calls = []
    monkeypatch.setattr(panel, "_known_domain", lambda domain: domain)
    monkeypatch.setattr(
        panel,
        "site_logs",
        lambda domain, **kwargs: calls.append((domain, kwargs)) or ProcessResult(0, stdout="line\n", ran=True),
    )

    assert panel.api_site_logs("example.com", "web", 5000) == {"logs": "line\n"}
    assert calls == [("example.com", {"services": ("web",), "lines": 2000, "no_color": True})]


def test_wp_api_rejects_unrun_runtime_result(monkeypatch):
    import wpfy.panel as panel
    from wpfy.site_runtime import ProcessResult

    monkeypatch.setattr(panel, "_known_domain", lambda domain: domain)
    monkeypatch.setattr(
        panel,
        "run_wp_cli",
        lambda *args: ProcessResult(1, stderr="runtime unavailable", skipped=True),
    )

    try:
        panel.api_site_wp("example.com", ["core", "version"])
    except panel.PanelError as exc:
        assert exc.status == 500
        assert str(exc) == "runtime unavailable"
    else:
        raise AssertionError("unrun WP result returned HTTP success")


def test_file_upload_bypasses_json_body_cap(panel_server, monkeypatch):
    base_url, paths = panel_server
    monkeypatch.setenv("WPFY_SKIP_CHOWN", "1")
    site = _seed_site(paths)
    payload = b"plugin" * 20000

    status, body, headers = _raw_request(
        base_url, "/api/sites/example.com/files/upload?path=plugin.zip", method="POST", raw=payload,
    )

    assert status == 201
    assert headers["Content-Type"].startswith("application/json")
    assert json.loads(body)["size"] == len(payload)
    assert (site / "app" / "plugin.zip").read_bytes() == payload


def test_rejected_raw_upload_closes_connection_before_reading_declared_body(panel_server):
    base_url, paths = panel_server
    _seed_site(paths)
    host, port = base_url.removeprefix("http://").split(":")
    request = (
        b"POST /api/sites/example.com/files/upload?path=../escape.txt HTTP/1.1\r\n"
        + f"Host: {host}\r\nAuthorization: Bearer {TEST_TOKEN}\r\n".encode("ascii")
        + b"Content-Length: 524288\r\nConnection: keep-alive\r\n\r\n"
    )

    with socket.create_connection((host, int(port)), timeout=10) as connection:
        connection.sendall(request)
        connection.shutdown(socket.SHUT_WR)
        response = b""
        while chunk := connection.recv(64 * 1024):
            response += chunk

    assert b"HTTP/1.1 400" in response
    assert b"Connection: close" in response


def test_file_download_forces_safe_attachment_headers(panel_server):
    base_url, paths = panel_server
    site = _seed_site(paths)
    payload = b"<script>alert(1)</script>\n"
    (site / "app" / "evil.html").write_bytes(payload)

    status, body, headers = _raw_request(
        base_url, "/api/sites/example.com/files/download?path=evil.html",
    )

    assert status == 200
    assert body == payload
    assert headers["Content-Type"] == "application/octet-stream"
    assert headers["Content-Disposition"].startswith('attachment; filename="evil.html"')
    assert "filename*=UTF-8''evil.html" in headers["Content-Disposition"]
    assert headers["X-Content-Type-Options"] == "nosniff"


def test_file_download_streams_only_the_advertised_size(panel_server, monkeypatch):
    base_url, paths = panel_server
    _seed_site(paths)
    import wpfy.files

    monkeypatch.setattr(
        wpfy.files,
        "open_download",
        lambda domain, path: wpfy.files.Download("growing.bin", 3, BytesIO(b"abcdef")),
    )
    status, body, headers = _raw_request(
        base_url, "/api/sites/example.com/files/download?path=growing.bin",
    )
    assert status == 200
    assert headers["Content-Length"] == "3"
    assert body == b"abc"


def test_file_editor_body_limit_covers_worst_case_json_escaping():
    import wpfy.files
    import wpfy.panel

    route = next(item for item in wpfy.panel._ROUTES if item.meta.action == "site.files.write")
    assert route.meta.max_body >= 6 * wpfy.files.MAX_EDIT_BYTES + 6 * 4096 + 4096


def test_static_ui_served_without_token(panel_server):
    base_url, _ = panel_server
    status, body, headers = _request(base_url, "/", token=None)
    assert status == 200
    assert headers["Content-Type"].startswith("text/html")
    assert "wpfy" in body
    assert 'data-tab="files"' in body
    assert 'id="file-upload-input"' in body
    assert "Content-Security-Policy" in headers

    status, script, headers = _request(base_url, "/panel.js", token=None)
    assert status == 200
    assert headers["Content-Type"].startswith("application/javascript")
    assert "async function apiUpload" in script
    assert 'result.path.split("/").pop() !== "wp-config.php"' in script
    assert "detailRequest !== detailRequestId || fileRequest !== fileRequestId" in script


def test_dry_run_previews_use_neutral_plan_badges(panel_server):
    base_url, _ = panel_server

    status, script, _ = _request(base_url, "/panel.js", token=None)
    assert status == 200
    assert 'state: operation.status === "planned" ? "plan"' in script
    assert 'checkItem({ name: "change", state: "plan", message: change })' in script

    status, stylesheet, _ = _request(base_url, "/panel.css", token=None)
    assert status == 200
    assert ".check-plan" in stylesheet


def test_static_traversal_and_unknown_paths_rejected(panel_server):
    base_url, _ = panel_server
    for path in ("/..%2fpanel.py", "/panel.py", "/nope.css", "/etc/passwd"):
        status, _, _ = _request(base_url, path, token=None)
        assert status == 404, f"expected 404 for {path}"


def test_client_route_paths_serve_shell_without_token(panel_server):
    base_url, _ = panel_server
    for path in (
        "/dashboard",
        "/sites",
        "/sites/new",
        "/sites/new/progress/job-123",
        "/sites/new/success/job-123",
        "/site/example.com",
        "/site/example.com/logs",
        "/events",
        "/notifications",
        "/account/settings",
        "/account/security",
        "/admin/users",
        "/admin/users/new",
        "/admin/events",
    ):
        status, body, headers = _request(base_url, path, token=None)
        assert status == 200, f"expected shell for {path}"
        assert headers["Content-Type"].startswith("text/html"), path
        assert 'id="file-upload-input"' in body, path
        assert "Content-Security-Policy" in headers, path

    for path in ("/nope", "/nope.html", "/site", "/admin"):
        status, _, _ = _request(base_url, path, token=None)
        assert status == 404, f"expected 404 for {path}"


def test_unknown_api_endpoint_and_bad_json(panel_server):
    base_url, _ = panel_server
    status, _, _ = _request(base_url, "/api/nope")
    assert status == 404

    request = urllib.request.Request(f"{base_url}/api/sites/example.com/runtime", method="POST")
    request.add_header("Authorization", f"Bearer {TEST_TOKEN}")
    try:
        with urllib.request.urlopen(request, data=b"not-json", timeout=10) as response:
            status = response.status
    except urllib.error.HTTPError as exc:
        status = exc.code
    assert status == 400


def test_server_rejects_non_loopback_host_and_empty_token(tmp_wpfy_home):
    import wpfy.panel

    with pytest.raises(ValueError, match="loopback"):
        wpfy.panel.make_panel_server(wpfy.panel.PanelConfig(host="0.0.0.0", port=0, token="x"))
    with pytest.raises(ValueError, match="token"):
        wpfy.panel.make_panel_server(wpfy.panel.PanelConfig(host="127.0.0.1", port=0, token=""))


def test_panel_url_puts_token_in_fragment():
    import wpfy.panel

    config = wpfy.panel.PanelConfig(host="127.0.0.1", port=1234, token="abc")
    assert wpfy.panel.panel_url(config) == "http://127.0.0.1:1234/#token=abc"


def test_create_rejects_unknown_flavor(panel_server):
    base_url, _ = panel_server
    status, body, _ = _request(
        base_url, "/api/sites", method="POST", body={"domain": "bad.example", "flavor": "node"},
    )
    assert status == 400
    assert "unknown site flavor" in body


def test_config_dry_run_does_not_apply(panel_server):
    base_url, paths = panel_server
    site = _seed_site(paths)
    before = (site / ".env").read_bytes()

    status, body, _ = _request(
        base_url, "/api/sites/example.com/config", method="POST",
        body={"php_version": "8.3", "dry_run": True},
    )

    assert status == 200
    assert json.loads(body)["changes"] == ["php 8.4→8.3"]
    assert (site / ".env").read_bytes() == before


def test_cli_panel_parser_defaults():
    from wpfy.cli import build_parser
    from wpfy.panel import DEFAULT_PANEL_PORT

    args = build_parser().parse_args(["panel"])
    assert args.host == "127.0.0.1"
    assert args.port == DEFAULT_PANEL_PORT
    assert args.token is None
    assert args.handler.__name__ == "handle_panel"


def test_cli_panel_refuses_public_bind():
    from wpfy.cli import build_parser

    args = build_parser().parse_args(["panel", "--host", "0.0.0.0"])
    result = args.handler(args)
    assert result.exit_code == 2
    assert "loopback" in result.message


def test_file_manager_status_disabled(panel_server):
    base_url, paths = panel_server
    _seed_site(paths)

    status, body, _ = _request(base_url, "/api/sites/example.com/file-manager")
    data = json.loads(body)
    assert status == 200
    assert data["state"] == "disabled"
    assert data["provider"] is None


def test_file_manager_enable_requires_auth(panel_server):
    base_url, _ = panel_server
    status, body, _ = _request(base_url, "/api/sites/example.com/file-manager/enable", method="POST", token=None)
    assert status == 401


def test_file_manager_lease_requires_auth(panel_server):
    base_url, _ = panel_server
    status, body, _ = _request(base_url, "/api/sites/example.com/file-manager/lease", method="POST", token=None)
    assert status == 401


def test_file_manager_lease_rejects_non_ready_state(panel_server):
    base_url, paths = panel_server
    _seed_site(paths)
    import wpfy.file_manager as file_manager

    for non_ready in ("disabled", "starting", "failed"):
        file_manager._write_state("example.com", {"state": non_ready, "domain": "example.com"})
        status, body, _ = _request(
            base_url, "/api/sites/example.com/file-manager/lease", method="POST",
        )
        assert status == 409, f"expected 409 for state={non_ready}, got {status}: {body}"


def test_file_manager_lease_populates_principal_as_holder(panel_server):
    base_url, paths = panel_server
    _seed_site(paths)
    import wpfy.file_manager as file_manager

    file_manager._write_state("example.com", {"state": "ready", "domain": "example.com"})

    status, _, _ = _request(base_url, "/api/sites/example.com/file-manager/lease", method="POST")
    assert status == 200

    state = file_manager.get_file_manager_state("example.com")
    assert state.state == "ready"
    assert state.lease_holders == ["run-token-admin"]
    assert state.active_leases == 1


def test_file_manager_disable_requires_auth(panel_server):
    base_url, _ = panel_server
    status, body, _ = _request(base_url, "/api/sites/example.com/file-manager", method="DELETE", token=None)
    assert status == 401


def test_file_manager_unknown_site_rejected(panel_server):
    base_url, _ = panel_server
    for path in ("/api/sites/nosuch/file-manager", "/api/sites/nosuch/file-manager/enable", "/api/sites/nosuch/file-manager/lease"):
        status, _, _ = _request(base_url, path, method="POST" if "enable" in path or "lease" in path else "GET")
        assert status >= 400, f"expected 4xx for {path}, got {status}"


def test_ssl_preflight_endpoint_exists(panel_server):
    base_url, paths = panel_server
    _seed_site(paths)
    status, body, _ = _request(base_url, "/api/sites/example.com/ssl/preflight", method="POST")
    assert status == 200
    data = json.loads(body)
    assert "passed" in data
    assert "message" in data


def test_ssl_preflight_requires_auth(panel_server):
    base_url, _ = panel_server
    status, _, _ = _request(base_url, "/api/sites/example.com/ssl/preflight", method="POST", token=None)
    assert status == 401


def test_admin_file_managers_requires_admin(panel_server):
    base_url, _ = panel_server
    status, body, _ = _request(base_url, "/api/admin/file-managers")
    assert status == 200
    data = json.loads(body)
    assert isinstance(data, list)


def test_file_manager_flag_off_returns_not_found(panel_server, monkeypatch):
    base_url, paths = panel_server
    _seed_site(paths)
    monkeypatch.setenv("WPFY_FM_ENABLED", "0")

    status, body, _ = _request(base_url, "/api/sites/example.com/file-manager")

    assert status == 404
    assert json.loads(body) == {"error": "file manager disabled"}


def test_legacy_files_flag_off_returns_not_found(panel_server, monkeypatch):
    base_url, paths = panel_server
    _seed_site(paths)
    monkeypatch.setenv("WPFY_FM_LEGACY_API", "0")

    status, body, _ = _request(base_url, "/api/sites/example.com/files")

    assert status == 404
    assert json.loads(body) == {"error": "file manager legacy api disabled"}


def test_file_manager_enable_sets_proxy_cookie(panel_server, monkeypatch):
    base_url, paths = panel_server
    _seed_site(paths)
    import wpfy.panel as panel

    monkeypatch.setattr(
        panel.panel_file_manager,
        "enable_file_manager",
        lambda domain, username, provider: {"state": "ready", "url": f"/api/sites/{domain}/file-manager/proxy/"},
    )

    status, _, headers = _request(
        base_url, "/api/sites/example.com/file-manager/enable", method="POST",
    )

    assert status == 200
    cookie = headers["Set-Cookie"]
    assert cookie.startswith("wpfy_fm=")
    assert "Path=/api/sites/example.com/file-manager/proxy/" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=Strict" in cookie
    assert "Max-Age=60" in cookie


def test_file_manager_error_is_sanitized(panel_server, monkeypatch):
    base_url, paths = panel_server
    _seed_site(paths)
    import wpfy.file_manager as file_manager
    import wpfy.panel as panel

    def fail(domain, username, provider):
        raise file_manager.FileManagerError("health_failed", "raw detail")

    monkeypatch.setattr(panel.panel_file_manager, "enable_file_manager", fail)

    status, body, _ = _request(
        base_url, "/api/sites/example.com/file-manager/enable", method="POST",
    )
    data = json.loads(body)

    assert status == 500
    assert data == {"state": "failed", "error": {"code": "health_failed", "message": "file manager failed to start"}}
    assert "raw detail" not in body


def test_metadata_reset_requires_confirmation_and_is_admin_only(panel_server, monkeypatch):
    base_url, paths = panel_server
    _seed_site(paths)
    import wpfy.panel as panel
    reset = []
    monkeypatch.setattr(panel.quantum_provider, "reset_metadata", lambda domain: reset.append(domain))

    status, _, _ = _request(
        base_url, "/api/sites/example.com/file-manager/metadata", method="DELETE",
        body={"confirm": "reset file manager metadata"},
    )
    assert status == 200
    assert reset == ["example.com"]

    status, _, _ = _request(
        base_url, "/api/sites/example.com/file-manager/metadata", method="DELETE",
        body={"confirm": "wrong"},
    )
    assert status == 400

    monkeypatch.setattr(
        panel.panel_auth,
        "authenticate_session",
        lambda token: {"username": "manager", "role": panel.panel_auth.ROLE_SITE_MANAGER, "sites": ["example.com"]},
    )
    status, _, _ = _request(
        base_url, "/api/sites/example.com/file-manager/metadata", method="DELETE", token="manager-token",
        body={"confirm": "reset file manager metadata"},
    )
    assert status == 403


def test_admin_file_manager_list_skips_corrupt_state(panel_server):
    base_url, paths = panel_server
    _seed_site(paths, "good.example.com")
    bad = _seed_site(paths, "bad.example.com")
    state = bad / ".wpfy" / "file-manager" / "state.json"
    state.parent.mkdir(parents=True, exist_ok=True)
    state.write_text("{invalid", encoding="utf-8")
    good_state = Path(paths.sites_dir) / "good.example.com" / ".wpfy" / "file-manager" / "state.json"
    good_state.parent.mkdir(parents=True, exist_ok=True)
    good_state.write_text(json.dumps({"state": "ready", "provider": "quantum"}), encoding="utf-8")

    status, body, _ = _request(base_url, "/api/admin/file-managers")

    assert status == 200
    assert [item["domain"] for item in json.loads(body)] == ["good.example.com"]


def test_file_manager_proxy_requires_cookie_and_forwards_user(panel_server, monkeypatch):
    base_url, paths = panel_server
    _seed_site(paths)
    import wpfy.panel as panel

    seen = {}

    class EchoHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen["user"] = self.headers.get("X-Forwarded-User")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, format, *args):
            pass

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), EchoHandler)
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr(panel.quantum_provider, "provider_port", lambda domain: upstream.server_address[1])
    monkeypatch.setattr(
        panel.panel_file_manager,
        "enable_file_manager",
        lambda domain, username, provider: {"state": "ready", "url": f"/api/sites/{domain}/file-manager/proxy/"},
    )
    try:
        status, _, _ = _request(base_url, "/api/sites/example.com/file-manager/proxy/", token=TEST_TOKEN)
        assert status == 403
        status, _, headers = _request(base_url, "/api/sites/example.com/file-manager/enable", method="POST")
        assert status == 200
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        request = urllib.request.Request(
            f"{base_url}/api/sites/example.com/file-manager/proxy/echo", headers={"Cookie": cookie},
        )
        request.add_header("Authorization", f"Bearer {TEST_TOKEN}")
        with urllib.request.urlopen(request, timeout=10) as response:
            assert response.status == 200
            assert response.read() == b"ok"
        assert seen["user"] == "run-token-admin"
    finally:
        upstream.shutdown()
        upstream.server_close()
        thread.join(timeout=5)


def test_idle_reap_stops_expired_file_manager(tmp_wpfy_home, monkeypatch):
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    import wpfy.events as events
    import wpfy.file_manager as panel_file_manager
    import wpfy.panel as panel

    _seed_site(tmp_wpfy_home)
    panel_file_manager._write_state("example.com", {
        "state": "ready",
        "domain": "example.com",
        "provider": "filebrowser-quantum",
        "idle_expires_at": (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),
        "lease_holders": [],
        "health": "healthy",
    })

    panel._idle_reap_once()

    assert panel_file_manager.get_file_manager_state("example.com").state == "disabled"
    assert any(event["action"] == "file_manager.auto_stopped" for event in events.list_events())


def test_idle_reap_ignores_future_and_already_disabled_states(tmp_wpfy_home, monkeypatch):
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    import wpfy.file_manager as panel_file_manager
    import wpfy.panel as panel

    _seed_site(tmp_wpfy_home)
    panel_file_manager._write_state("example.com", {
        "state": "ready",
        "domain": "example.com",
        "idle_expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        "lease_holders": [],
    })
    panel._idle_reap_once()
    assert panel_file_manager.get_file_manager_state("example.com").state == "ready"

    panel_file_manager._write_state("example.com", {"state": "disabled", "domain": "example.com"})
    panel._idle_reap_once()
    assert panel_file_manager.get_file_manager_state("example.com").state == "disabled"


def test_fm_reaper_stops_when_panel_server_closes(tmp_wpfy_home, monkeypatch):
    """t19 regression pin: make_panel_server's idle reaper thread must stop when
    the panel server closes. The historical daemon thread looped forever, so a
    server created in one test kept firing list_sites()/state reads into later
    tests (full-suite race: test_cli saw an extra registry.list_sites call from
    the reaper and failed test_site_list_reconciles_before_rendering)."""
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    monkeypatch.setenv("WPFY_FM_ENABLED", "1")
    import wpfy.panel as panel

    def count_reapers() -> int:
        return sum(1 for t in threading.enumerate() if t.name == "wpfy-fm-reaper")

    before = count_reapers()
    config = panel.PanelConfig(host="127.0.0.1", port=0, token=TEST_TOKEN)
    server = panel.make_panel_server(config)
    assert count_reapers() == before + 1, "make_panel_server must start exactly one reaper"

    # No serve_forever thread here: server_close() alone must stop the reaper.
    server.server_close()

    deadline = time.monotonic() + 5.0
    while count_reapers() > before and time.monotonic() < deadline:
        time.sleep(0.05)
    assert count_reapers() == before, "reaper thread must exit after server_close"


def test_rediscover_file_manager_marks_running_starting_site_ready(tmp_wpfy_home, monkeypatch):
    monkeypatch.delenv("WPFY_SKIP_RUNTIME", raising=False)
    import wpfy.file_manager as panel_file_manager
    import wpfy.panel as panel

    _seed_site(tmp_wpfy_home)
    panel_file_manager._write_state("example.com", {"state": "starting", "domain": "example.com"})
    monkeypatch.setattr(panel.subprocess, "run", lambda *args, **kwargs: type("Result", (), {
        "returncode": 0,
        "stdout": "example.com\n",
    })())

    panel._rediscover_file_managers()

    assert panel_file_manager.get_file_manager_state("example.com").state == "ready"


def test_rediscover_file_managers_skips_runtime_requested(tmp_wpfy_home, monkeypatch):
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    import wpfy.file_manager as panel_file_manager
    import wpfy.panel as panel

    _seed_site(tmp_wpfy_home)
    panel_file_manager._write_state("example.com", {"state": "starting", "domain": "example.com"})
    monkeypatch.setattr(panel.subprocess, "run", lambda *args, **kwargs: pytest.fail("docker must not run"))

    panel._rediscover_file_managers()

    assert panel_file_manager.get_file_manager_state("example.com").state == "starting"


def test_logout_revoke_file_manager_for_sole_lease_holder(tmp_wpfy_home, monkeypatch):
    import wpfy.file_manager as panel_file_manager
    import wpfy.panel as panel

    _seed_site(tmp_wpfy_home)
    panel_file_manager._write_state("example.com", {"state": "ready", "domain": "example.com", "lease_holders": ["alice"]})
    calls = []
    monkeypatch.setattr(panel_file_manager, "disable_file_manager", lambda domain, provider: calls.append((domain, provider)))

    panel._revoke_fm_for_logout("example.com", "alice")

    assert calls == [("example.com", panel.quantum_provider)]
