from __future__ import annotations

import importlib
import json
import threading
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
        f"MARIADB_PASSWORD={SECRET_MARKER}\n",
        encoding="utf-8",
    )
    (site / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
    return site


@pytest.fixture
def panel_server(tmp_wpfy_home, monkeypatch):
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")

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


def test_runtime_action_skips_offline(panel_server):
    base_url, paths = panel_server
    _seed_site(paths)
    status, body, _ = _request(
        base_url, "/api/sites/example.com/runtime", method="POST", body={"action": "start"},
    )
    assert status == 200
    payload = json.loads(body)
    assert payload["ok"] is True
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


def test_static_ui_served_without_token(panel_server):
    base_url, _ = panel_server
    status, body, headers = _request(base_url, "/", token=None)
    assert status == 200
    assert headers["Content-Type"].startswith("text/html")
    assert "wpfy" in body
    assert "Content-Security-Policy" in headers

    status, _, headers = _request(base_url, "/panel.js", token=None)
    assert status == 200
    assert headers["Content-Type"].startswith("application/javascript")


def test_static_traversal_and_unknown_paths_rejected(panel_server):
    base_url, _ = panel_server
    for path in ("/..%2fpanel.py", "/panel.py", "/nope.css", "/etc/passwd"):
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
