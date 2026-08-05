from __future__ import annotations

import importlib
import json
from pathlib import Path
import threading
import urllib.error
import urllib.request

import pytest

TEST_TOKEN = "test-panel-security-token"
DOMAIN = "security.example.com"
DB_SECRET = "panel-security-db-secret"
ROOT_SECRET = "panel-security-root-secret"
EDGE_CIDR = "172.31.0.0/16"
FAKE_CF_RANGE = "203.0.113.0/24"


def _seed_site(paths) -> Path:
    site = Path(paths.sites_dir) / DOMAIN
    (site / "nginx" / "extra").mkdir(parents=True, exist_ok=True)
    (site / "php").mkdir(parents=True, exist_ok=True)
    (site / "app").mkdir(parents=True, exist_ok=True)
    (site / ".env").write_text(
        f"DOMAIN={DOMAIN}\n"
        "SITE_FLAVOR=wp\n"
        "COMPOSE_PROJECT_NAME=security-example-com\n"
        "APP_ROOT=/var/www/html\n"
        "PHP_VERSION=8.4\n"
        "SITE_UID=1700\n"
        "LETSENCRYPT_MODE=disabled\n"
        "PAGE_CACHE=none\n"
        "DB_NAME=security\n"
        "DB_USER=security\n"
        f"DB_PASSWORD={DB_SECRET}\n"
        f"MARIADB_PASSWORD={DB_SECRET}\n"
        f"DB_ROOT_PASSWORD={ROOT_SECRET}\n"
        f"MARIADB_ROOT_PASSWORD={ROOT_SECRET}\n",
        encoding="utf-8",
    )
    (site / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
    (site / "nginx" / "default.conf").write_text("server { listen 8080; }\n", encoding="utf-8")
    (site / "nginx" / "extra" / "custom.conf").write_text("", encoding="utf-8")
    return site


@pytest.fixture
def panel_server(tmp_wpfy_home, monkeypatch):
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    monkeypatch.setenv("WPFY_TEST_TRAEFIK_NETWORK_CIDRS", EDGE_CIDR)
    monkeypatch.setenv("WPFY_CLOUDFLARE_RANGES", FAKE_CF_RANGE)
    monkeypatch.setenv("WPFY_TEST_DNS_IPS", "198.51.100.10")

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
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", tmp_wpfy_home
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


def _snapshot(site: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(site)): path.read_bytes()
        for path in sorted(site.rglob("*"))
        if path.is_file()
    }


def test_security_get_returns_render_state_without_credentials(panel_server):
    base_url, paths = panel_server
    _seed_site(paths)

    status, payload = _request(base_url, f"/api/sites/{DOMAIN}/security")

    assert status == 200
    assert payload["deny_ips"] == []
    assert payload["ua_blocks"] == []
    assert payload["basic_auth"] == {"enabled": False, "username": None}
    assert payload["cloudflare_only"] is False
    assert payload["login_rate_limit"] is False
    assert payload["snippet_path"].endswith("nginx/extra/wpfy-security.conf")
    assert payload["trusted_edge_sources"] == [EDGE_CIDR]
    assert "password" not in json.dumps(payload).lower()


def test_security_dry_run_previews_without_any_write(panel_server):
    base_url, paths = panel_server
    site = _seed_site(paths)
    before = _snapshot(site)

    status, payload = _request(
        base_url,
        f"/api/sites/{DOMAIN}/security",
        method="PUT",
        body={"deny_ips": ["198.51.100.0/24"], "ua_blocks": ["EvilBot"], "dry_run": True},
    )

    assert status == 200
    assert payload["state"] == "preview"
    assert payload["changes"] == ["deny network 198.51.100.0/24", "block user-agent EvilBot"]
    assert payload["warnings"] == []
    assert _snapshot(site) == before


def test_security_api_applies_the_wordpress_login_rate_limit(panel_server):
    base_url, paths = panel_server
    site = _seed_site(paths)

    status, payload = _request(
        base_url,
        f"/api/sites/{DOMAIN}/security",
        method="PUT",
        body={"login_rate_limit": True},
    )

    assert status == 200
    assert payload["login_rate_limit"] is True
    assert "enable WordPress login rate limit" in payload["changes"]
    assert "limit_req" in (site / "nginx" / "extra" / "wpfy-security.conf").read_text(encoding="utf-8")


def test_security_api_reconciles_requested_unchanged_lists(panel_server, monkeypatch):
    base_url, paths = panel_server
    _seed_site(paths)
    import wpfy.panel as panel

    calls = []
    monkeypatch.setattr(
        panel.site_security,
        "apply_security_runtime",
        lambda domain: calls.append(domain) or panel.site_security.SecurityResult(0, "security config unchanged"),
    )

    status, payload = _request(
        base_url,
        f"/api/sites/{DOMAIN}/security",
        method="PUT",
        body={"deny_ips": []},
    )

    assert status == 200
    assert payload["ok"] is True
    assert calls == [DOMAIN]


def test_cloudflare_warning_requires_deliberate_acknowledgement(panel_server):
    base_url, paths = panel_server
    site = _seed_site(paths)

    status, preview = _request(
        base_url,
        f"/api/sites/{DOMAIN}/security",
        method="PUT",
        body={"cloudflare_only": True},
    )

    assert status == 200
    assert preview["acknowledgement_required"] is True
    assert preview["warnings"]
    assert not (site / "security.json").exists()

    status, applied = _request(
        base_url,
        f"/api/sites/{DOMAIN}/security",
        method="PUT",
        body={"cloudflare_only": True, "acknowledge_warnings": True},
    )

    assert status == 200
    assert applied["state"] == "applied"
    assert json.loads((site / "security.json").read_text())["cloudflare_only"] is True

    status, unrelated = _request(
        base_url,
        f"/api/sites/{DOMAIN}/security",
        method="PUT",
        body={"basic_auth": {"enabled": True, "username": "operator"}},
    )
    assert status == 200
    assert unrelated["warnings"] == []
    assert unrelated["state"] == "applied"


def test_generated_basic_auth_password_is_one_time_and_never_cleartext(panel_server):
    base_url, paths = panel_server
    site = _seed_site(paths)

    status, enabled = _request(
        base_url,
        f"/api/sites/{DOMAIN}/security",
        method="PUT",
        body={"basic_auth": {"enabled": True, "username": "operator"}},
    )

    assert status == 200
    password = enabled["one_time"]["password"]
    assert len(password) >= 12
    _, later = _request(base_url, f"/api/sites/{DOMAIN}/security")
    assert password not in json.dumps(later)
    assert all(password.encode() not in content for content in _snapshot(site).values())
    assert "$6$" in (site / "nginx" / "htpasswd").read_text()


def test_security_rejects_unknown_and_hostile_fields_without_secret_leaks(panel_server):
    base_url, paths = panel_server
    _seed_site(paths)

    probes = [
        {"unexpected": True},
        {"deny_ips": ["0.0.0.0/0"]},
        {"ua_blocks": ["bad\nreturn 200;"]},
        {"basic_auth": {"enabled": True, "username": "operator", "hash": "leak"}},
    ]
    for body in probes:
        status, payload = _request(base_url, f"/api/sites/{DOMAIN}/security", method="PUT", body=body)
        assert status == 400
        rendered = json.dumps(payload)
        assert DB_SECRET not in rendered
        assert ROOT_SECRET not in rendered
