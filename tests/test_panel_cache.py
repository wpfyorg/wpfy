from __future__ import annotations

import importlib
import json
from pathlib import Path
import threading
import urllib.error
import urllib.request

import pytest

TEST_TOKEN = "test-panel-cache-token"
SECRET_MARKER = "panel-cache-db-secret"
ROOT_SECRET_MARKER = "panel-cache-root-secret"
DOMAIN = "cache.example.com"


def _seed_site(paths, *, page_cache="none", object_cache="none") -> Path:
    site = Path(paths.sites_dir) / DOMAIN
    (site / "nginx" / "extra").mkdir(parents=True, exist_ok=True)
    (site / "php").mkdir(parents=True, exist_ok=True)
    (site / "app").mkdir(parents=True, exist_ok=True)
    (site / ".env").write_text(
        f"DOMAIN={DOMAIN}\n"
        "SITE_FLAVOR=wp\n"
        "COMPOSE_PROJECT_NAME=cache-example-com\n"
        "APP_ROOT=/var/www/html\n"
        "PHP_VERSION=8.4\n"
        "SITE_UID=1700\n"
        "LETSENCRYPT_MODE=disabled\n"
        f"PAGE_CACHE={page_cache}\n"
        f"REDIS_ENABLED={'1' if object_cache == 'redis' else '0'}\n"
        "DB_NAME=cache\n"
        "DB_USER=cache\n"
        f"DB_PASSWORD={SECRET_MARKER}\n"
        f"MARIADB_PASSWORD={SECRET_MARKER}\n"
        f"DB_ROOT_PASSWORD={ROOT_SECRET_MARKER}\n"
        f"MARIADB_ROOT_PASSWORD={ROOT_SECRET_MARKER}\n",
        encoding="utf-8",
    )
    (site / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
    (site / "nginx" / "default.conf").write_text("server {\n    listen 8080;\n}\n", encoding="utf-8")
    (site / "nginx" / "extra" / "custom.conf").write_text("", encoding="utf-8")
    (site / "nginx" / "cache-path.conf").write_text("", encoding="utf-8")
    return site


@pytest.fixture
def panel_server(tmp_wpfy_home, monkeypatch):
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")

    import wpfy.operational_inspection
    import wpfy.panel
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    importlib.reload(wpfy.operational_inspection)
    importlib.reload(wpfy.panel)

    config = wpfy.panel.PanelConfig(host="127.0.0.1", port=0, token=TEST_TOKEN)
    server = wpfy.panel.make_panel_server(config)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        yield base_url, tmp_wpfy_home
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _request(base_url: str, path: str, *, method="GET", body=None):
    request = urllib.request.Request(f"{base_url}{path}", method=method)
    request.add_header("Authorization", f"Bearer {TEST_TOKEN}")
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, data=data, timeout=10) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def _snapshot(site: Path) -> dict[str, str]:
    return {
        str(path.relative_to(site)): path.read_text(encoding="utf-8", errors="ignore")
        for path in sorted(site.rglob("*"))
        if path.is_file()
    }


def test_cache_get_reports_options_byo_state_and_snippet_path(panel_server):
    base_url, paths = panel_server
    _seed_site(paths, page_cache="wp-rocket")
    plugin_dir = Path(paths.sites_dir) / DOMAIN / "app" / "wp-content" / "plugins" / "wp-rocket"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "wp-rocket.php").write_text("<?php\n", encoding="utf-8")

    status, payload = _request(base_url, f"/api/sites/{DOMAIN}/cache")

    assert status == 200
    assert payload["page_cache"] == "wp-rocket"
    assert payload["object_cache"] == "none"
    assert payload["byo_plugin"] == {
        "selected": True,
        "plugin": "wp-rocket",
        "files_present": True,
        "upload_path": str(plugin_dir.parent),
    }
    options = {item["value"]: item for item in payload["page_cache_options"]}
    assert options["w3-total-cache"]["badge"] == "Free"
    assert options["wp-rocket"]["badge"] == "Bring your own"
    assert options["wp-rocket"]["auto_install"] is False
    assert payload["snippet_path"].endswith("nginx/extra/wpfy-cache.conf")


def test_cache_dry_run_reports_changes_without_writing(panel_server):
    base_url, paths = panel_server
    site = _seed_site(paths)
    before = _snapshot(site)

    status, payload = _request(
        base_url,
        f"/api/sites/{DOMAIN}/cache",
        method="PUT",
        body={"page_cache": "wpfc", "object_cache": "redis", "dry_run": True},
    )

    assert status == 200
    assert payload["state"] == "preview"
    assert payload["changes"] == ["page cache: none -> wpfc", "object cache: none -> redis"]
    assert [operation["operation"] for operation in payload["operations"]] == [
        "install_page_cache", "render_cache_nginx", "set_wp_cache_constants", "wire_redis_backend",
    ]
    assert _snapshot(site) == before


def test_cache_apply_stages_free_plugin_and_snippet(panel_server):
    base_url, paths = panel_server
    site = _seed_site(paths)

    status, payload = _request(
        base_url,
        f"/api/sites/{DOMAIN}/cache",
        method="PUT",
        body={"page_cache": "wpfc"},
    )

    assert status == 200
    assert payload["ok"] is True
    assert payload["state"] == "deferred"
    assert "install_page_cache" in {action["status"] for action in payload["actions"]} or any(
        action["status"] == "deferred" for action in payload["actions"]
    )
    assert "wpfy_skip_cache" in (site / "nginx" / "extra" / "wpfy-cache.conf").read_text()
    assert "PAGE_CACHE=wpfc" in (site / ".env").read_text()


def test_cache_byo_is_successful_awaiting_upload_and_never_installs(panel_server, monkeypatch):
    base_url, paths = panel_server
    _seed_site(paths)
    calls = []

    def recorder(*args, **kwargs):
        calls.append(args)
        raise AssertionError("subprocess should not be called while runtime is skipped")

    monkeypatch.setattr("subprocess.run", recorder)

    status, payload = _request(
        base_url,
        f"/api/sites/{DOMAIN}/cache",
        method="PUT",
        body={"page_cache": "wp-rocket"},
    )

    assert status == 200
    assert payload["ok"] is True
    assert payload["state"] == "awaiting-upload"
    assert any(action["status"] == "awaiting-upload" for action in payload["actions"])
    assert "awaiting" in payload["message"].lower() or "upload" in payload["message"].lower()
    assert not calls


def test_cache_purge_reports_layer_failure(panel_server, monkeypatch):
    base_url, paths = panel_server
    _seed_site(paths)

    from wpfy import cache_operations

    monkeypatch.setattr(
        "wpfy.panel.site_cache.purge_site_cache",
        lambda domain: cache_operations.CacheResult((
            cache_operations.CacheOutcome(domain, "plugin", "skipped", "command unavailable"),
            cache_operations.CacheOutcome(domain, "nginx", "error", "permission denied"),
            cache_operations.CacheOutcome(domain, "redis", "ok", "cache flushed"),
        )),
    )

    status, payload = _request(base_url, f"/api/sites/{DOMAIN}/cache/purge", method="POST", body={})

    assert status == 500
    assert payload["ok"] is False
    assert payload["state"] == "error"
    assert {outcome["cache"] for outcome in payload["outcomes"]} == {"plugin", "nginx", "redis"}
    assert "permission denied" in payload["message"]


def test_cache_purge_reports_success_and_each_layer(panel_server, monkeypatch):
    base_url, paths = panel_server
    _seed_site(paths)

    from wpfy import cache_operations

    monkeypatch.setattr(
        "wpfy.panel.site_cache.purge_site_cache",
        lambda domain: cache_operations.CacheResult((
            cache_operations.CacheOutcome(domain, "plugin", "ok", "plugin cache flushed"),
            cache_operations.CacheOutcome(domain, "nginx", "ok", "cache cleared"),
            cache_operations.CacheOutcome(domain, "redis", "skipped", "not enabled"),
        )),
    )

    status, payload = _request(base_url, f"/api/sites/{DOMAIN}/cache/purge", method="POST", body={})

    assert status == 200
    assert payload["ok"] is True
    assert payload["state"] == "purged"
    assert [outcome["status"] for outcome in payload["outcomes"]] == ["ok", "ok", "skipped"]


def test_cache_endpoints_never_leak_secrets(panel_server):
    base_url, paths = panel_server
    _seed_site(paths, page_cache="wpfc", object_cache="redis")

    probes = [
        ("GET", f"/api/sites/{DOMAIN}/cache", None),
        ("PUT", f"/api/sites/{DOMAIN}/cache", {"page_cache": "wpfc", "dry_run": True}),
        ("PUT", f"/api/sites/{DOMAIN}/cache", {"object_cache": "redis"}),
        ("POST", f"/api/sites/{DOMAIN}/cache/purge", {}),
    ]
    for method, path, body in probes:
        _, payload = _request(base_url, path, method=method, body=body)
        text = json.dumps(payload)
        assert SECRET_MARKER not in text, f"secret leaked via {method} {path}"
        assert ROOT_SECRET_MARKER not in text, f"root secret leaked via {method} {path}"
