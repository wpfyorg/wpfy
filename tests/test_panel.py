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
import urllib.parse
import urllib.request
from pathlib import Path
import shutil
import subprocess

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


def _await_job(base_url: str, job_id: str, *, timeout: float = 10.0) -> dict:
    """Poll a job to a terminal state and return its final payload."""
    deadline = time.monotonic() + timeout
    last: dict = {}
    while time.monotonic() < deadline:
        status, body, _ = _request(base_url, f"/api/jobs/{job_id}")
        assert status == 200, f"job fetch failed: {status} {body}"
        last = json.loads(body)
        if last.get("state") in {"succeeded", "failed"}:
            return last
        time.sleep(0.05)
    raise AssertionError(f"job {job_id} did not finish within {timeout}s: {last}")


def _connect_stream(base_url: str, *, token: str | None = TEST_TOKEN, timeout: float = 5) -> socket.socket:
    """Open a raw socket and send a GET /api/stream request (SSE needs headers, not EventSource)."""
    parsed = urllib.parse.urlsplit(base_url)
    sock = socket.create_connection((parsed.hostname, parsed.port), timeout=timeout)
    lines = [f"GET /api/stream HTTP/1.1", f"Host: {parsed.hostname}:{parsed.port}"]
    if token is not None:
        lines.append(f"Authorization: Bearer {token}")
    lines.append("Connection: close")
    sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("utf-8"))
    return sock


def _read_stream_head(sock: socket.socket, *, timeout: float = 5) -> tuple[str, bytes]:
    sock.settimeout(timeout)
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    head, _, rest = data.partition(b"\r\n\r\n")
    return head.decode("utf-8", "replace"), rest


def _read_stream_frame(sock: socket.socket, leftover: bytes = b"", *, timeout: float = 5) -> str:
    """Read bytes until a full SSE frame (or comment line) is assembled."""
    sock.settimeout(timeout)
    data = leftover
    while b"\n\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data.decode("utf-8", "replace")


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


def test_sftp_rotate_returns_the_password_only_as_a_one_time_value(panel_server, monkeypatch):
    """`ensure_sftp_container()` appends `password (shown once): <secret>` to its
    message for the CLI, and `rotate_sftp_password()` returns that same result.

    `message` is a general-purpose display field — the panel renders it into the
    page, next to the one-time panel rather than inside it — so a password left
    there is a second copy that outlives the surface designed to show it once.
    The secret leaves this endpoint through `one_time` alone.
    """
    import wpfy.panel as panel

    base_url, paths = panel_server
    _seed_site(paths)
    secret = "PH-sftp-rotate-secret"

    def fake_rotate(domain, password=None):
        return panel.sftp.RuntimeResult(
            0, f"sftp container ready for {domain}\npassword (shown once): {password}"
        )

    monkeypatch.setattr(panel.sftp, "rotate_sftp_password", fake_rotate)
    monkeypatch.setattr(panel, "generated_secret", lambda: secret)

    status, body, _ = _request(
        base_url, "/api/sites/example.com/sftp", method="POST", body={"action": "rotate"},
    )

    assert status in {200, 202}, body
    payload = json.loads(body)
    assert payload["one_time"]["password"] == secret[:16]
    assert secret[:16] not in payload["message"], (
        f"the rotate message still carries the password: {payload['message']!r}"
    )


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
    assert status == 202
    job_id = json.loads(body)["job_id"]
    job = _await_job(base_url, job_id)
    assert job["state"] == "succeeded"
    assert job["result"]["ok"] is True

    status, body, _ = _request(base_url, "/api/sites/example.com/backups")
    backups = json.loads(body)["backups"]
    assert len(backups) == 1
    assert backups[0]["name"].startswith("example.com-")

    status, _, _ = _request(
        base_url, "/api/sites/example.com/restore", method="POST", body={"archive": "nope.tar.gz"},
    )
    assert status == 404


def _job_count(base_url: str) -> int:
    _, body, _ = _request(base_url, "/api/jobs")
    return len(json.loads(body)["jobs"])


def test_backup_dry_run_creates_no_job(panel_server):
    base_url, paths = panel_server
    _seed_site(paths)
    before = _job_count(base_url)

    status, body, _ = _request(
        base_url, "/api/sites/example.com/backups", method="POST", body={"dry_run": True},
    )
    assert status == 200
    assert json.loads(body)["changes"] == ["create backup"]
    assert _job_count(base_url) == before


def test_restore_unknown_domain_is_synchronous_404_with_no_job(panel_server):
    base_url, _ = panel_server
    before = _job_count(base_url)

    status, body, _ = _request(
        base_url, "/api/sites/missing.example/restore", method="POST", body={"archive": "x.tar.gz"},
    )
    assert status == 404
    assert _job_count(base_url) == before


def test_backup_job_failure_is_redacted(panel_server, monkeypatch):
    base_url, paths = panel_server
    _seed_site(paths)

    import wpfy.panel

    def fake_backup(domain, **kwargs):
        from wpfy.site_runtime import RuntimeResult
        return RuntimeResult(1, f"backup failed: MARIADB_PASSWORD={SECRET_MARKER}")

    monkeypatch.setattr(wpfy.panel, "backup_site", fake_backup)
    status, body, _ = _request(base_url, "/api/sites/example.com/backups", method="POST")
    assert status == 202
    job_id = json.loads(body)["job_id"]
    job = _await_job(base_url, job_id)
    assert job["state"] == "failed"
    assert SECRET_MARKER not in json.dumps(job)


def test_wp_endpoint_validates_args(panel_server, monkeypatch):
    base_url, paths = panel_server
    _seed_site(paths)
    before = _job_count(base_url)

    status, _, _ = _request(base_url, "/api/sites/example.com/wp", method="POST", body={"args": []})
    assert status == 400
    assert _job_count(base_url) == before

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
    assert status == 202
    job_id = json.loads(body)["job_id"]
    job = _await_job(base_url, job_id)
    assert job["state"] == "succeeded"
    assert job["result"]["stdout"] == "5.9.1\n"
    assert captured["domain"] == "example.com"
    assert captured["args"] == ("core", "version")


def test_wp_job_fails_when_runtime_unavailable(panel_server, monkeypatch):
    base_url, paths = panel_server
    _seed_site(paths)

    import wpfy.panel
    from wpfy.site_runtime import ProcessResult

    monkeypatch.setattr(
        wpfy.panel, "run_wp_cli",
        lambda *args, **kwargs: ProcessResult(1, stderr="runtime unavailable", skipped=True),
    )
    status, body, _ = _request(
        base_url, "/api/sites/example.com/wp", method="POST", body={"args": ["core", "version"]},
    )
    assert status == 202
    job = _await_job(base_url, json.loads(body)["job_id"])
    assert job["state"] == "failed"


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
    assert 'id="login-form"' in body        # the way in
    assert 'id="page"' in body              # the shell's mount point
    assert "Content-Security-Policy" in headers

    status, script, headers = _request(base_url, "/panel.js", token=None)
    assert status == 200
    assert headers["Content-Type"].startswith("application/javascript")
    assert "async function apiUpload" in script


def test_dashboard_and_sites_modules_are_csp_safe_served_assets(panel_server):
    base_url, _ = panel_server
    expected_endpoints = {
        "/page-dashboard.js": ("/api/overview", "/api/metrics", "/api/events", "/api/sites"),
        "/page-sites.js": ("/api/sites",),
        "/page-site-create.js": ("/api/sites",),
        "/page-events.js": ("/api/events",),
        "/page-job.js": ("/api/jobs",),
        "/page-users.js": ("/api/users",),
        "/page-services.js": ("/api/system/services", "/api/metrics/latest"),
        "/page-firewall.js": ("/api/firewall",),
        "/page-backup.js": ("/api/backup/remote", "/api/backup/schedule"),
        "/page-settings.js": ("/api/settings",),
        "/page-instance.js": ("/api/instance",),
        "/page-mail.js": ("/api/notifications/smtp",),
        "/page-basic-auth.js": ("/api/security/basic-auth",),
        "/page-job.js": ("/api/jobs/",),
        "/page-users.js": ("/api/users", "/api/sites"),
        "/page-services.js": ("/api/system/services", "/api/metrics/latest"),
    }
    for path, endpoints in expected_endpoints.items():
        status, script, headers = _request(base_url, path, token=None)
        assert status == 200
        assert headers["Content-Type"].startswith("application/javascript")
        assert "innerHTML" not in script
        assert "insertAdjacentHTML" not in script
        assert 'style="' not in script
        for endpoint in endpoints:
            assert endpoint in script


def test_site_detail_modules_are_csp_safe_served_assets(panel_server):
    base_url, _ = panel_server
    expected_endpoints = {
        "/page-site.js": ("/api/sites/",),
        "/site-tab-overview.js": ("/health", "/diagnostics", "/runtime", "/logs", "/api/events"),
        "/site-tab-settings.js": ("/config", "/php-settings", "/cache", "/cache/purge", "/nginx-custom", "/security", "/ssl/preflight"),
        "/site-tab-data.js": ("/databases", "/db-users", "/adminer", "/backups", "/restore"),
        "/site-tab-access.js": ("/sftp", "/wp", "/site-file-browser.js"),
        "/site-file-browser.js": ("/files", "wp-config.php", "signal.aborted"),
        "/site-tab-automation.js": ("/cron",),
    }
    for path, endpoints in expected_endpoints.items():
        status, script, headers = _request(base_url, path, token=None)
        assert status == 200
        assert headers["Content-Type"].startswith("application/javascript")
        assert "innerHTML" not in script
        assert "insertAdjacentHTML" not in script
        assert 'style="' not in script
        for endpoint in endpoints:
            assert endpoint in script


def test_data_tab_module_serves_confirmed_site_data_actions(panel_server):
    base_url, _ = panel_server
    status, script, headers = _request(base_url, "/site-tab-data.js", token=None)

    assert status == 200
    assert headers["Content-Type"].startswith("application/javascript")
    assert "confirmAction" in script
    assert "renderOneTime" in script
    assert "pollJob" in script
    assert 'body: { confirm: typed }' in script
    assert "keyword: domain" in script
    assert "innerHTML" not in script
    assert "insertAdjacentHTML" not in script
    assert 'style="' not in script


def test_every_shipped_script_actually_parses():
    """Every other client-side assertion in this file is a substring search, and
    a substring search passes happily against a file the browser cannot parse.
    That is not hypothetical: the dashboard module shipped one paren short, every
    grep-style test stayed green, and the page silently fell back to a placeholder
    because the dynamic import threw.

    Skipped, not failed, where node is absent: a missing checker is not evidence
    the scripts are broken. CI's ubuntu runner has node.
    """
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed; cannot parse-check the client modules")

    import wpfy.panel

    static = Path(wpfy.panel.STATIC_DIR)
    # `--input-type=module` so `import`/`export` are legal; the panel loads
    # panel.js and every page-*.js as ES modules.
    for script in sorted(static.glob("*.js")):
        result = subprocess.run(
            [node, "--input-type=module", "--check"],
            input=script.read_bytes(), capture_output=True,
        )
        assert result.returncode == 0, (
            f"{script.name} is not valid JavaScript:\n{result.stderr.decode('utf-8', 'replace')}"
        )


def test_file_manager_client_guards(panel_server):
    """Saving `wp-config.php` is explicitly guarded, and stale file requests
    are discarded before they can render under another site.
    """
    base_url, _ = panel_server
    _, script, _ = _request(base_url, "/site-file-browser.js", token=None)
    assert "wp-config.php" in script
    assert "signal.aborted" in script


def test_dry_run_previews_use_neutral_plan_badges(panel_server):
    """A dry-run preview describes what *would* change, so its rows must read
    as a plan — rendering them with the pass/fail vocabulary tells the operator
    the change already happened.

    Preview/apply moved out of `panel.js` in the rebuild: it now lives in the
    site Settings tab, which is where the five old config tabs were consolidated.
    """
    base_url, _ = panel_server

    status, script, _ = _request(base_url, "/site-tab-settings.js", token=None)
    assert status == 200
    assert "check-plan" in script, "preview rows carry no neutral plan badge"

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
        assert 'id="page"' in body, path
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


def test_create_honors_object_page_cache_and_sftp_fields(panel_server, monkeypatch):
    base_url, _ = panel_server
    monkeypatch.setenv("WPFY_SKIP_WORDPRESS_DOWNLOAD", "1")
    status, body, _ = _request(
        base_url, "/api/sites", method="POST",
        body={
            "domain": "cached.example", "flavor": "wp",
            "object_cache": "none", "page_cache": "none", "enable_sftp": True,
        },
    )
    assert status == 202
    job = _await_job(base_url, json.loads(body)["job_id"])
    assert job["state"] == "succeeded", job
    assert job["result"]["cache"] == {"page_cache": "none", "object_cache": "none", "ok": True}
    assert job["result"]["sftp"]["ok"] is True
    assert job["one_time"]["sftp_password"]


def test_create_keeps_the_sftp_password_out_of_the_job_result(panel_server, monkeypatch):
    """The one-time surface is consumed once; `job.result` is not.

    `ensure_sftp_container()` appends `password (shown once): <secret>` to its
    message, and the create job stores that message in `job.result`, which every
    later `GET /api/jobs` read returns in full. A password left there outlives
    the panel that showed it once and is readable from the Jobs page.
    """
    import wpfy.panel as panel

    base_url, _ = panel_server
    monkeypatch.setenv("WPFY_SKIP_WORDPRESS_DOWNLOAD", "1")

    def fake_ensure(domain, password=None):
        return panel.sftp.RuntimeResult(
            0, f"sftp container ready for {domain}\npassword (shown once): {password}"
        )

    monkeypatch.setattr(panel.sftp, "ensure_sftp_container", fake_ensure)

    status, body, _ = _request(
        base_url, "/api/sites", method="POST",
        body={"domain": "sftpleak.example", "flavor": "html", "enable_sftp": True},
    )
    assert status == 202
    job = _await_job(base_url, json.loads(body)["job_id"])
    assert job["state"] == "succeeded", job
    secret = job["one_time"]["sftp_password"]
    assert secret
    assert secret not in job["result"]["sftp"]["message"], (
        f"the create job result still carries the sftp password: {job['result']['sftp']['message']!r}"
    )


def test_create_rejects_unknown_cache_values(panel_server):
    base_url, _ = panel_server
    before = _job_count(base_url)

    status, body, _ = _request(
        base_url, "/api/sites", method="POST",
        body={"domain": "badcache.example", "flavor": "wp", "object_cache": "memcached"},
    )
    assert status == 400
    assert _job_count(base_url) == before

    status, body, _ = _request(
        base_url, "/api/sites", method="POST",
        body={"domain": "badcache2.example", "flavor": "wp", "page_cache": "varnish"},
    )
    assert status == 400
    assert _job_count(base_url) == before


def test_create_rejects_enable_sftp_wrong_type(panel_server):
    base_url, _ = panel_server
    status, body, _ = _request(
        base_url, "/api/sites", method="POST",
        body={"domain": "badsftp.example", "flavor": "html", "enable_sftp": "yes"},
    )
    assert status == 400


@pytest.mark.parametrize("field,value", [
    ("multisite_type", "subdirectory"),
    ("enable_backups", True),
    ("backup_retention", 7),
    ("notification_channel", "email"),
])
def test_create_rejects_cut_fields_as_unknown(panel_server, field, value):
    """Section 3.2: fields the wizard can no longer honor are rejected, not silently dropped."""
    base_url, _ = panel_server
    before = _job_count(base_url)

    status, body, _ = _request(
        base_url, "/api/sites", method="POST",
        body={"domain": "cut.example", field: value, "flavor": "html"},
    )
    assert status == 400
    assert "unsupported field" in body
    assert _job_count(base_url) == before


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


def test_config_apply_runs_as_a_job(panel_server):
    base_url, paths = panel_server
    _seed_site(paths)

    status, body, _ = _request(
        base_url, "/api/sites/example.com/config", method="POST", body={"php_version": "8.3"},
    )
    assert status == 202
    job = _await_job(base_url, json.loads(body)["job_id"])
    assert job["state"] == "succeeded"
    assert job["result"]["ok"] is True
    assert job["result"]["changes"] == ["php 8.4→8.3"]


def test_config_apply_unsupported_field_is_synchronous_400_with_no_job(panel_server):
    base_url, paths = panel_server
    _seed_site(paths)
    before = _job_count(base_url)

    status, body, _ = _request(
        base_url, "/api/sites/example.com/config", method="POST", body={"nope": "x"},
    )
    assert status == 400
    assert _job_count(base_url) == before


def test_config_apply_job_failure_is_redacted(panel_server, monkeypatch):
    base_url, paths = panel_server
    _seed_site(paths)

    import wpfy.panel
    import wpfy.site_lifecycle as site_lifecycle

    def fake_update_site(request):
        raise site_lifecycle.SiteLifecycleError(f"update failed: MARIADB_PASSWORD={SECRET_MARKER}")

    monkeypatch.setattr(wpfy.panel.site_lifecycle, "update_site", fake_update_site)
    status, body, _ = _request(
        base_url, "/api/sites/example.com/config", method="POST", body={"php_version": "8.3"},
    )
    assert status == 202
    job = _await_job(base_url, json.loads(body)["job_id"])
    assert job["state"] == "failed"
    assert SECRET_MARKER not in json.dumps(job)


def test_traefik_restart_runs_as_a_job(panel_server, monkeypatch):
    base_url, _ = panel_server

    import wpfy.panel
    from wpfy.site_runtime import RuntimeResult

    status, body, _ = _request(base_url, "/api/system/traefik/restart", method="POST", body={})
    assert status == 400

    monkeypatch.setattr(wpfy.panel.traefik, "restart_traefik_existing", lambda: RuntimeResult(0, "restarted", ran=True))
    status, body, _ = _request(
        base_url, "/api/system/traefik/restart", method="POST", body={"confirm": "wpfy-traefik"},
    )
    assert status == 202
    job = _await_job(base_url, json.loads(body)["job_id"])
    assert job["state"] == "succeeded"
    assert job["result"]["ok"] is True


def test_traefik_restart_job_fails_and_is_redacted(panel_server, monkeypatch):
    base_url, _ = panel_server

    import wpfy.panel
    from wpfy.site_runtime import RuntimeResult

    monkeypatch.setattr(
        wpfy.panel.traefik, "restart_traefik_existing",
        lambda: RuntimeResult(1, f"restart failed: MARIADB_PASSWORD={SECRET_MARKER}"),
    )
    status, body, _ = _request(
        base_url, "/api/system/traefik/restart", method="POST", body={"confirm": "wpfy-traefik"},
    )
    assert status == 202
    job = _await_job(base_url, json.loads(body)["job_id"])
    assert job["state"] == "failed"
    assert SECRET_MARKER not in json.dumps(job)


def test_restore_roundtrip_runs_as_a_job(panel_server):
    base_url, paths = panel_server
    _seed_site(paths)

    status, body, _ = _request(base_url, "/api/sites/example.com/backups", method="POST")
    _await_job(base_url, json.loads(body)["job_id"])
    status, body, _ = _request(base_url, "/api/sites/example.com/backups")
    archive_name = json.loads(body)["backups"][0]["name"]

    status, body, _ = _request(
        base_url, "/api/sites/example.com/restore", method="POST", body={"archive": archive_name},
    )
    assert status == 202
    job = _await_job(base_url, json.loads(body)["job_id"])
    assert job["state"] == "succeeded"
    assert job["result"]["ok"] is True


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


# --- GET /api/stream -----------------------------------------------------

def test_stream_requires_auth(panel_server):
    base_url, _ = panel_server
    sock = _connect_stream(base_url, token=None)
    try:
        head, _ = _read_stream_head(sock)
        assert head.startswith("HTTP/1.1 401")
    finally:
        sock.close()


def test_stream_headers_are_sse_and_no_store(panel_server):
    base_url, _ = panel_server
    sock = _connect_stream(base_url)
    try:
        head, _ = _read_stream_head(sock)
        assert head.startswith("HTTP/1.1 200")
        assert "content-type: text/event-stream" in head.lower()
        assert "cache-control: no-store" in head.lower()
        assert "x-content-type-options: nosniff" in head.lower()
    finally:
        sock.close()


def test_stream_concurrency_cap_returns_503(panel_server):
    base_url, _ = panel_server
    held = []
    try:
        for _ in range(8):
            sock = _connect_stream(base_url)
            head, _ = _read_stream_head(sock)
            assert head.startswith("HTTP/1.1 200"), head
            held.append(sock)

        overflow = _connect_stream(base_url)
        try:
            head, _ = _read_stream_head(overflow)
            assert head.startswith("HTTP/1.1 503"), head
        finally:
            overflow.close()
    finally:
        for sock in held:
            sock.close()


def test_stream_site_manager_only_sees_own_domain(panel_server):
    base_url, paths = panel_server
    _seed_site(paths, "assigned.example")
    _seed_site(paths, "unassigned.example")

    import wpfy.panel_auth as panel_auth
    panel_auth.add_user("sse-admin", "sse-admin-password-x", role=panel_auth.ROLE_ADMIN)
    panel_auth.add_user(
        "sse-manager", "sse-manager-password-x",
        role=panel_auth.ROLE_SITE_MANAGER, sites=("assigned.example",),
    )
    status, body, _ = _request(
        base_url, "/api/auth/login", token=None, method="POST",
        body={"username": "sse-admin", "password": "sse-admin-password-x"},
    )
    assert status == 200, body
    admin_token = json.loads(body)["token"]

    status, body, _ = _request(
        base_url, "/api/auth/login", token=None, method="POST",
        body={"username": "sse-manager", "password": "sse-manager-password-x"},
    )
    assert status == 200, body
    manager_token = json.loads(body)["token"]

    sock = _connect_stream(base_url, token=manager_token)
    try:
        head, leftover = _read_stream_head(sock)
        assert head.startswith("HTTP/1.1 200")

        cron_body = {"schedule": "* * * * *", "command": "true"}
        status, _, _ = _request(
            base_url, "/api/sites/unassigned.example/cron", method="POST", body=cron_body, token=admin_token,
        )
        assert status == 201
        status, _, _ = _request(
            base_url, "/api/sites/assigned.example/cron", method="POST", body=cron_body, token=admin_token,
        )
        assert status == 201

        frame = _read_stream_frame(sock, leftover, timeout=5)
        assert "unassigned.example" not in frame
        assert "assigned.example" in frame
        assert "site.cron.add" in frame
    finally:
        sock.close()


def test_stream_disconnect_does_not_leak_a_thread(panel_server, monkeypatch):
    import wpfy.panel as panel
    monkeypatch.setattr(panel, "_STREAM_KEEPALIVE_SECONDS", 0.2)

    base_url, _ = panel_server
    sock = _connect_stream(base_url)
    head, _ = _read_stream_head(sock)
    assert head.startswith("HTTP/1.1 200")
    sock.close()

    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and panel._STREAM_SUBSCRIBERS:
        time.sleep(0.1)
    assert not panel._STREAM_SUBSCRIBERS, "closed stream client left a subscriber (and its thread) registered"


def test_every_panel_event_reaches_the_stream():
    """A recorded event that skips `_emit_event` is written to the log but never
    reaches a live `/api/stream` subscriber — a silent half-mirror that makes the
    stream untrustworthy as a source of truth. `_emit_event` is the one funnel, so
    `events.record_event` must appear exactly once in panel.py: inside it.
    """
    source = (Path(__file__).resolve().parents[1] / "src" / "wpfy" / "panel.py").read_text()
    direct = source.count("events.record_event(")
    assert direct == 1, (
        f"panel.py calls events.record_event() {direct} times; every event must go "
        "through _emit_event() so live stream subscribers see it"
    )


_SECTION5_SYSTEM_ROUTES = (
    ("GET", "/api/settings"), ("PUT", "/api/settings/telemetry"),
    ("POST", "/api/settings/exposure"), ("DELETE", "/api/settings/exposure"),
    ("GET", "/api/backup/remote"), ("PUT", "/api/backup/remote"),
    ("DELETE", "/api/backup/remote"), ("PUT", "/api/backup/schedule"),
    ("DELETE", "/api/backup/schedule"), ("GET", "/api/firewall"),
    ("POST", "/api/firewall/install"), ("POST", "/api/firewall/ports"),
    ("DELETE", "/api/firewall/ports"), ("POST", "/api/firewall/enable"),
    ("POST", "/api/firewall/disable"), ("GET", "/api/notifications/smtp"),
    ("PUT", "/api/notifications/smtp"), ("POST", "/api/notifications/smtp/test"),
    ("DELETE", "/api/notifications/smtp"), ("GET", "/api/instance"),
    ("GET", "/api/security/basic-auth"),
)


@pytest.mark.parametrize(("method", "path"), _SECTION5_SYSTEM_ROUTES)
def test_section5_routes_refuse_site_managers(panel_server, monkeypatch, method, path):
    import wpfy.panel as panel

    monkeypatch.setattr(
        panel.panel_auth, "authenticate_session",
        lambda token: {"username": "manager", "role": panel.panel_auth.ROLE_SITE_MANAGER, "sites": ["example.com"]},
    )
    status, _, _ = _request(base_url := panel_server[0], path, method=method, token="manager-token", body={})
    assert status == 403, f"{method} {path} must remain admin-only"


def test_section5_admin_routes_and_write_only_secrets(panel_server, monkeypatch):
    base_url, paths = panel_server
    _seed_site(paths)
    import wpfy.panel as panel
    from wpfy.site_runtime import RuntimeResult

    monkeypatch.setattr(panel.panel_exposure, "expose", lambda *args, **kwargs: RuntimeResult(0, "exposed"))
    monkeypatch.setattr(panel.panel_exposure, "disable", lambda: RuntimeResult(0, "disabled"))
    monkeypatch.setattr(panel.backup_schedule, "install_schedule", lambda schedule: RuntimeResult(0, "scheduled"))
    monkeypatch.setattr(panel.backup_schedule, "disable_schedule", lambda: RuntimeResult(0, "disabled"))
    monkeypatch.setattr(panel.fail2ban_host, "ensure_fail2ban_host", lambda: panel.fail2ban_host.HostFail2banResult(0, "installed", installed=True, health_ok=True))
    monkeypatch.setattr(
        panel.fail2ban_docker, "enforcement_status",
        lambda: panel.fail2ban_docker.EnforcementStatus(True, False, False, True, True, "f2b-wpfy-panel-auth"),
    )
    monkeypatch.setattr(panel.fail2ban_docker, "action_is_stale", lambda: False)
    monkeypatch.setattr(panel.fail2ban_docker, "ipv6_capable", lambda: False)
    monkeypatch.setattr(panel.smtp, "send_test_message", lambda config, recipient: f"sent: {recipient}")

    s3_secret = "section5-s3-secret"
    smtp_secret = "section5-smtp-secret"
    s3_body = {"endpoint": "https://s3.example.test", "bucket": "backups", "region": "us-east-1", "prefix": "wpfy", "access_key": "access", "secret_key": s3_secret, "allow_insecure": False}
    smtp_body = {"host": "smtp.example.test", "port": 587, "sender": "wpfy@example.test", "username": "mailer", "password": smtp_secret, "tls": "starttls"}
    cases = (
        ("GET", "/api/settings", None),
        ("PUT", "/api/settings/telemetry", {"enabled": True}),
        ("POST", "/api/settings/exposure", {"domain": "panel.example.test", "confirm": "panel.example.test"}),
        ("DELETE", "/api/settings/exposure", {}),
        ("PUT", "/api/backup/remote", s3_body),
        ("GET", "/api/backup/remote", None),
        ("DELETE", "/api/backup/remote", {}),
        ("PUT", "/api/backup/schedule", {"cadence": "weekly", "time": "02:30", "weekday": "sun", "upload_s3": False}),
        ("DELETE", "/api/backup/schedule", {}),
        ("GET", "/api/firewall", None),
        ("POST", "/api/firewall/install", {}),
        ("PUT", "/api/notifications/smtp", smtp_body),
        ("GET", "/api/notifications/smtp", None),
        ("POST", "/api/notifications/smtp/test", {"recipient": "operator@example.test"}),
        ("DELETE", "/api/notifications/smtp", {}),
        ("GET", "/api/instance", None),
        ("GET", "/api/security/basic-auth", None),
    )
    secret_reads = {}
    inventory = ""
    for method, path, body in cases:
        status, raw, _ = _request(base_url, path, method=method, body=body)
        assert status in {200, 202}, f"{method} {path}: {status} {raw}"
        if method == "GET" and path in {"/api/backup/remote", "/api/notifications/smtp"}:
            secret_reads[path] = raw
        if path == "/api/security/basic-auth":
            inventory = raw
    assert s3_secret not in secret_reads["/api/backup/remote"]
    assert smtp_secret not in secret_reads["/api/notifications/smtp"]
    assert json.loads(inventory) == {
        "basic_auth": [{"domain": "example.com", "enabled": False, "username": None}],
    }
    # Exposure publishes the panel to the internet, so the operator must type
    # the destination -- a boolean or a near-miss domain must not get through.
    for bad_confirm in (False, True, "", "panel.example.tes", "other.example.test"):
        status, _, _ = _request(
            base_url,
            "/api/settings/exposure",
            method="POST",
            body={"domain": "panel.example.test", "confirm": bad_confirm},
        )
        assert status == 400, f"exposure accepted confirm={bad_confirm!r}"


def _firewall_ready(monkeypatch):
    """Pretend ufw is installed and answering, without one on the test host."""
    import wpfy.panel as panel

    calls: list[list[str]] = []

    def fake_run(args):
        calls.append(list(args))
        if args[:2] == ["status", "verbose"]:
            return 0, "Status: active\nDefault: deny (incoming), allow (outgoing)\n\n22/tcp ALLOW IN Anywhere\n"
        return 0, "ok"

    monkeypatch.setattr(panel.firewall_ports, "ufw_available", lambda: True)
    monkeypatch.setattr(panel.firewall_ports, "_run", fake_run)
    monkeypatch.delenv("WPFY_SKIP_RUNTIME", raising=False)
    return calls


def test_firewall_read_reports_ports_alongside_intrusion_prevention(panel_server, monkeypatch):
    base_url, _ = panel_server
    _firewall_ready(monkeypatch)
    status, raw, _ = _request(base_url, "/api/firewall")
    assert status == 200, raw
    ports = json.loads(raw)["ports"]
    assert ports["installed"] is True
    assert ports["active"] is True
    assert ports["ssh_port"] == 22
    assert any(rule["port"] == "22" for rule in ports["rules"])
    assert any(preset["port"] == "443" for preset in ports["presets"])


def test_firewall_read_survives_a_host_without_ufw(panel_server, monkeypatch):
    """Port management missing must not take the fail2ban half of the page down."""
    import wpfy.panel as panel

    base_url, _ = panel_server
    monkeypatch.setattr(panel.firewall_ports, "ufw_available", lambda: False)
    status, raw, _ = _request(base_url, "/api/firewall")
    assert status == 200, raw
    payload = json.loads(raw)
    assert payload["ports"]["installed"] is False
    assert "enforcement" in payload


def test_firewall_allow_rejects_junk_before_it_reaches_ufw(panel_server, monkeypatch):
    base_url, _ = panel_server
    calls = _firewall_ready(monkeypatch)
    for body in (
        {"port": "0", "protocol": "tcp"},
        {"port": "22", "protocol": "sctp"},
        {"port": "80", "protocol": "tcp", "source": "not-an-address"},
        {"port": "80", "protocol": "tcp", "comment": "`id`"},
        {"port": "80", "protocol": "tcp", "surprise": True},
    ):
        status, raw, _ = _request(base_url, "/api/firewall/ports", method="POST", body=body)
        assert status == 400, f"{body} was accepted: {raw}"
    assert all(call[:2] != ["allow", "from"] for call in calls)


def test_firewall_deny_of_the_ssh_port_needs_the_typed_confirmation(panel_server, monkeypatch):
    """Denying SSH from the panel severs the connection carrying the request.

    It stays reachable -- an operator with console access may genuinely want
    it -- but only by typing the port, never by clicking a button.
    """
    base_url, _ = panel_server
    calls = _firewall_ready(monkeypatch)

    status, raw, _ = _request(base_url, "/api/firewall/ports", method="POST",
                              body={"port": "22", "protocol": "tcp", "action": "deny"})
    assert status >= 400, raw
    assert all(call[0] != "deny" for call in calls), "ufw was invoked despite the guard"

    status, raw, _ = _request(base_url, "/api/firewall/ports", method="POST",
                              body={"port": "22", "protocol": "tcp", "action": "deny", "confirm": "22"})
    assert status == 200, raw
    assert any(call[0] == "deny" for call in calls)


def test_firewall_delete_of_the_ssh_rule_needs_the_typed_confirmation(panel_server, monkeypatch):
    base_url, _ = panel_server
    calls = _firewall_ready(monkeypatch)
    status, raw, _ = _request(base_url, "/api/firewall/ports", method="DELETE",
                              body={"port": "22", "protocol": "tcp", "action": "allow"})
    assert status >= 400, raw
    assert all(call[0] != "delete" for call in calls)


def test_firewall_enable_reserves_ssh_first(panel_server, monkeypatch):
    base_url, _ = panel_server
    calls = _firewall_ready(monkeypatch)
    status, raw, _ = _request(base_url, "/api/firewall/enable", method="POST", body={})
    assert status == 200, raw
    ordered = [call for call in calls if call[0] in {"allow", "--force"}]
    assert ordered[0][0] == "allow" and "22" in ordered[0]
    assert ordered[1] == ["--force", "enable"]


def test_firewall_disable_needs_confirmation(panel_server, monkeypatch):
    """Disabling opens every port on the host at once."""
    base_url, _ = panel_server
    calls = _firewall_ready(monkeypatch)
    status, raw, _ = _request(base_url, "/api/firewall/disable", method="POST", body={})
    assert status == 400, raw
    assert all(call[0] != "disable" for call in calls)

    status, raw, _ = _request(base_url, "/api/firewall/disable", method="POST", body={"confirm": "disable"})
    assert status == 200, raw
    assert any(call[0] == "disable" for call in calls)


def test_remote_backup_edit_keeps_the_stored_secret(panel_server):
    """The secret is write-only, so an edit cannot round-trip it.

    Demanding it on every write means a prefix change re-types an S3 secret, and
    a client sending "" to satisfy a required field replaces a working credential
    with an empty one -- which fails first at the next scheduled upload, silently.
    """
    base_url, _ = panel_server
    secret = "keep-this-s3-secret"
    original = {"endpoint": "https://s3.example.test", "bucket": "backups", "region": "us-east-1",
                "prefix": "wpfy", "access_key": "access", "secret_key": secret, "allow_insecure": False}

    status, raw, _ = _request(base_url, "/api/backup/remote", method="PUT", body=original)
    assert status == 200, raw

    edited = {**original, "prefix": "nightly", "secret_key": ""}
    status, raw, _ = _request(base_url, "/api/backup/remote", method="PUT", body=edited)
    assert status == 200, raw

    import wpfy.s3_backup as s3_backup
    stored = s3_backup.load_s3_config()
    assert stored.prefix == "nightly"
    assert stored.secret_key == secret, "a blank secret field wiped the stored credential"

    status, raw, _ = _request(base_url, "/api/backup/remote")
    assert secret not in raw, "the secret must never be readable back"


def test_remote_backup_replaces_the_secret_when_one_is_given(panel_server):
    base_url, _ = panel_server
    body = {"endpoint": "https://s3.example.test", "bucket": "backups", "region": "us-east-1",
            "prefix": "wpfy", "access_key": "access", "secret_key": "first-secret", "allow_insecure": False}
    assert _request(base_url, "/api/backup/remote", method="PUT", body=body)[0] == 200
    assert _request(base_url, "/api/backup/remote", method="PUT",
                    body={**body, "secret_key": "second-secret"})[0] == 200

    import wpfy.s3_backup as s3_backup
    assert s3_backup.load_s3_config().secret_key == "second-secret"


def test_remote_backup_first_write_still_needs_a_secret(panel_server):
    """"Keep the stored one" is meaningless when nothing is stored."""
    base_url, _ = panel_server
    body = {"endpoint": "https://s3.example.test", "bucket": "backups", "region": "us-east-1",
            "prefix": "wpfy", "access_key": "access", "allow_insecure": False}
    status, raw, _ = _request(base_url, "/api/backup/remote", method="PUT", body=body)
    assert status == 400
    assert "secret key" in raw


def test_password_minimum_applies_to_every_user_write(panel_server):
    """Setup enforced twelve characters; user creation enforced non-empty.

    An admin made to pick a strong password could then create a site-manager
    with a one-character one, on a panel `wpfy panel expose` can publish. The
    floor now lives in the one validator every write path already calls.
    """
    base_url, _ = panel_server
    status, raw, _ = _request(base_url, "/api/users", method="POST",
                              body={"username": "weakling", "password": "x", "role": "admin", "sites": []})
    assert status == 400, raw
    assert "12 characters" in raw

    import wpfy.panel_auth as panel_auth
    for call in (
        lambda: panel_auth.add_user("weakling", "short", role="admin"),
        lambda: panel_auth.update_user("weakling", password="short"),
        lambda: panel_auth.set_password("weakling", "short"),
    ):
        with pytest.raises(ValueError, match="12 characters"):
            call()


def test_smtp_edit_keeps_the_stored_password(panel_server):
    """Same shape as the backup destination, and for the same reason.

    The password is write-only, so a client editing the sender cannot round-trip
    a value it is never allowed to read. A blank field keeps the stored one.
    """
    base_url, _ = panel_server
    secret = "keep-this-smtp-secret"
    original = {"host": "smtp.example.test", "port": 587, "sender": "wpfy@example.test",
                "username": "mailer", "password": secret, "tls": "starttls"}
    assert _request(base_url, "/api/notifications/smtp", method="PUT", body=original)[0] == 200

    edited = {**original, "sender": "alerts@example.test", "password": ""}
    status, raw, _ = _request(base_url, "/api/notifications/smtp", method="PUT", body=edited)
    assert status == 200, raw

    import wpfy.smtp as smtp
    stored = smtp.load_smtp_config()
    assert stored.sender == "alerts@example.test"
    assert stored.password == secret, "a blank password field wiped the stored credential"

    status, raw, _ = _request(base_url, "/api/notifications/smtp")
    assert secret not in raw, "the password must never be readable back"


def test_smtp_first_write_still_needs_a_password(panel_server):
    base_url, _ = panel_server
    body = {"host": "smtp.example.test", "port": 587, "sender": "wpfy@example.test",
            "username": "mailer", "tls": "starttls"}
    status, raw, _ = _request(base_url, "/api/notifications/smtp", method="PUT", body=body)
    assert status == 400
    assert "password" in raw


def test_site_services_are_readable_per_site(panel_server):
    """The cross-site services list is admin-only, which left a site-manager
    unable to see the containers of the site they are responsible for."""
    base_url, paths = panel_server
    _seed_site(paths)
    status, raw, _ = _request(base_url, "/api/sites/example.com/services")
    assert status == 200, raw
    payload = json.loads(raw)
    assert payload["domain"] == "example.com"
    assert {"web", "app"} <= {row["name"] for row in payload["services"]}


def test_site_services_stay_scoped_to_one_site(panel_server, monkeypatch):
    """A site-manager reaching another site's services must be refused."""
    import wpfy.panel as panel

    base_url, paths = panel_server
    _seed_site(paths)
    monkeypatch.setattr(
        panel.panel_auth, "authenticate_session",
        lambda token: {"username": "manager", "role": panel.panel_auth.ROLE_SITE_MANAGER, "sites": ["other.example"]},
    )
    status, _, _ = _request(base_url, "/api/sites/example.com/services", token="manager-token")
    assert status == 403


def test_every_module_that_deletes_also_confirms():
    """A destructive action must not be reachable by a single click.

    The pre-rebuild panel fired six destructive actions with no confirmation at
    all -- file delete, empty-dir delete, SFTP password rotate, DB-user rotate,
    service restart, runtime restart -- and used six different idioms for the
    ones it did confirm, while the two purpose-built helpers had zero call
    sites. This is the structural floor: a module that issues a DELETE, or
    posts to a route the server marks destructive, has to have loaded the
    confirmation helper. It cannot prove the confirm guards the right call, but
    it does fail the day someone adds a delete button to a page that has no
    confirm in it at all.
    """
    import wpfy.panel

    static = Path(wpfy.panel.__file__).parent / "panel_static"
    modules = {
        path.name: path.read_text(encoding="utf-8")
        for path in sorted(static.glob("*.js"))
        if not path.name.endswith(".min.js") and path.name != "panel.js"
    }
    assert modules, "no client modules found"

    destructive_posts = ("/restore", "/firewall/enable", "/firewall/disable",
                         "/traefik/restart", "/settings/exposure")
    offenders = []
    for name, text in modules.items():
        deletes = 'method: "DELETE"' in text
        posts = any(route in text for route in destructive_posts)
        if (deletes or posts) and "confirmAction" not in text:
            offenders.append(name)

    assert not offenders, (
        "these modules perform a destructive request without loading the "
        f"confirmation helper: {offenders}"
    )


def test_the_riskiest_actions_demand_a_typed_confirmation():
    """Clicking through a dialog is not the same as typing the thing's name.

    Dropping a database, restoring over a live site, deleting a site, and
    denying the port that carries SSH are all unrecoverable from the panel, so
    each one makes the operator type the target rather than accept a default.
    """
    import wpfy.panel

    static = Path(wpfy.panel.__file__).parent / "panel_static"
    for name in ("site-tab-data.js", "site-tab-settings.js", "page-firewall.js", "site-file-browser.js"):
        text = (static / name).read_text(encoding="utf-8")
        assert "keyword:" in text, f"{name} confirms destructive work without a typed keyword"


def test_the_event_stream_filters_by_tenancy_not_just_permission():
    """A site-manager may subscribe to the live feed; it must not carry other
    tenants' events.

    `event.stream` sits in the site-manager allowlist next to `event.list`, so
    authorization alone lets a manager open the feed. Everything that keeps one
    tenant out of another's events is `_stream_visible`, and until this test it
    had no coverage at all — a permission with an untested filter behind it.
    """
    from wpfy import panel

    manager = {"role": panel.panel_auth.ROLE_SITE_MANAGER, "sites": ["mine.example"]}
    admin = {"role": panel.panel_auth.ROLE_ADMIN, "sites": []}

    assert panel._stream_visible({"domain": "mine.example"}, manager) is True
    assert panel._stream_visible({"domain": "theirs.example"}, manager) is False
    # Host-level events carry no domain; they are not the manager's business.
    assert panel._stream_visible({"domain": None}, manager) is False
    assert panel._stream_visible({}, manager) is False
    # An administrator sees the whole host, which is the point of the role.
    assert panel._stream_visible({"domain": "theirs.example"}, admin) is True
    assert panel._stream_visible({"domain": None}, admin) is True
