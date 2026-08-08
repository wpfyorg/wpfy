from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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
    monkeypatch.setenv("WPFY_FM_ENABLED", "1")
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


def _request(base_url: str, path: str, *, method="GET", body=None, headers=None):
    request = urllib.request.Request(f"{base_url}{path}", method=method)
    request.add_header("Authorization", f"Bearer {TEST_TOKEN}")
    for name, value in (headers or {}).items():
        request.add_header(name, value)
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


def test_security_rejects_cross_origin_mutation(panel_server):
    base_url, paths = panel_server
    _seed_site(paths)

    denied_status, denied_payload = _request(
        base_url,
        f"/api/sites/{DOMAIN}/ssl/preflight",
        method="POST",
        headers={"Origin": "https://evil.example"},
    )
    allowed_status, allowed_payload = _request(
        base_url,
        f"/api/sites/{DOMAIN}/ssl/preflight",
        method="POST",
        headers={"Origin": base_url},
    )

    assert denied_status == 403
    assert denied_payload == {"error": "cross-origin request denied"}
    assert allowed_status == 200
    assert "passed" in allowed_payload


def test_fm_enable_rate_limited(panel_server, monkeypatch):
    base_url, paths = panel_server
    _seed_site(paths)

    import wpfy.panel as panel
    import wpfy.panel_auth as panel_auth

    panel_auth._FM_ENABLE.clear()
    registered = []
    original_register = panel_auth.register_fm_enable

    def record_register(username):
        registered.append(username)
        original_register(username)

    monkeypatch.setattr(panel_auth, "register_fm_enable", record_register)
    monkeypatch.setattr(
        panel.panel_file_manager,
        "enable_file_manager",
        lambda domain, username, provider: {"domain": domain, "username": username},
    )
    try:
        responses = [
            _request(base_url, f"/api/sites/{DOMAIN}/file-manager/enable", method="POST")
            for _ in range(6)
        ]
    finally:
        panel_auth._FM_ENABLE.clear()

    assert all(status == 200 for status, _ in responses[:5])
    assert registered == ["run-token-admin"] * 5
    assert responses[5] == (429, {"error": "file manager enable rate limit reached; try again later"})


def test_no_origin_mutation_still_allowed(panel_server):
    base_url, paths = panel_server
    _seed_site(paths)

    status, payload = _request(
        base_url,
        f"/api/sites/{DOMAIN}/ssl/preflight",
        method="POST",
    )

    assert status == 200
    assert "passed" in payload


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
    rendered = json.dumps(payload)
    # The protected-surfaces label "password_reset" is a surface name, not a
    # credential; assert actual credential artifacts are absent from the read
    # payload instead of a broad substring that the label would trip.
    assert "password" not in json.dumps(payload["basic_auth"]).lower()
    assert "one_time" not in payload
    assert DB_SECRET not in rendered
    assert ROOT_SECRET not in rendered


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


# ---------------------------------------------------------------------------
# Login Shield panel surface (t17)
# ---------------------------------------------------------------------------

BAN_SCOPE_TEXT = (
    "Only enabled sites can trigger Login Shield bans. A resulting HTTP ban "
    "may block the attacker from all websites on this WPFY server."
)


def test_security_get_reports_login_shield_status_and_disclosure(panel_server):
    base_url, paths = panel_server
    _seed_site(paths)

    status, payload = _request(base_url, f"/api/sites/{DOMAIN}/security")

    assert status == 200
    assert payload["fail2ban"] is False
    shield = payload["login_shield"]
    assert shield["enabled"] is False
    assert shield["health"] == "disabled"
    assert shield["ban_scope"] == BAN_SCOPE_TEXT
    assert "host_fail2ban_installed" in shield
    assert "host_fail2ban_health" in shield
    assert "plugin" in shield
    assert "event_log_path" in shield
    assert "event_log_health" in shield
    assert "last_detected_failure" in shield
    assert "recent_bans" in shield
    assert "trusted_proxy_health" in shield
    assert "ipv4_protection" in shield
    assert "ipv6_protection" in shield
    assert "config_validation" in shield
    assert payload["protected_surfaces"] == [
        "wp_login", "xmlrpc", "rest", "password_reset", "user_enum", "app_password",
    ]


def test_login_shield_toggle_previews_without_writing(panel_server):
    base_url, paths = panel_server
    site = _seed_site(paths)
    before = _snapshot(site)

    status, payload = _request(
        base_url,
        f"/api/sites/{DOMAIN}/security",
        method="PUT",
        body={"fail2ban": True, "dry_run": True},
    )

    assert status == 200
    assert payload["state"] == "preview"
    assert payload["changes"] == ["enable WordPress fail2ban login shield"]
    assert _snapshot(site) == before


def test_login_shield_toggle_delegates_to_set_fail2ban(panel_server, monkeypatch):
    base_url, paths = panel_server
    _seed_site(paths)
    import wpfy.panel as panel

    calls = []

    def fake_set_fail2ban(domain, enabled):
        calls.append((domain, enabled))
        config = panel.site_security.load_security(domain)
        config["fail2ban"] = enabled
        panel.site_security.save_security(domain, config)
        return panel.site_security.SecurityResult(
            0, "login shield enabled" if enabled else "login shield disabled", True
        )

    monkeypatch.setattr(panel.site_security, "set_fail2ban", fake_set_fail2ban)

    status, enabled = _request(
        base_url, f"/api/sites/{DOMAIN}/security", method="PUT", body={"fail2ban": True}
    )
    assert status == 200
    assert enabled["state"] == "applied"
    assert enabled["changes"] == ["enable WordPress fail2ban login shield"]
    assert calls == [(DOMAIN, True)]

    status, disabled = _request(
        base_url, f"/api/sites/{DOMAIN}/security", method="PUT", body={"fail2ban": False}
    )
    assert status == 200
    assert disabled["state"] == "applied"
    assert disabled["changes"] == ["disable WordPress fail2ban login shield"]
    assert calls == [(DOMAIN, True), (DOMAIN, False)]


def test_login_shield_status_degraded_passes_through(panel_server, monkeypatch):
    base_url, paths = panel_server
    _seed_site(paths)
    import wpfy.panel as panel

    degraded = {
        "enabled": True,
        "health": "degraded",
        "action_stale": True,
        "degraded_reason": (
            "action stale: IPv6 capable but action rendered without IPv6 support; "
            "re-render required"
        ),
        "host_fail2ban_installed": True,
        "host_fail2ban_health": "ok",
        "plugin": {"slug": "wp-fail2ban", "active": True, "ownership": "wpfy-installed"},
        "event_log_health": "ok",
        "trusted_proxy_health": "edge-trust-configured",
        "last_detected_failure": None,
        "recent_bans": 1,
        "ban_scope": BAN_SCOPE_TEXT,
    }
    monkeypatch.setattr(panel.site_security, "login_shield_status", lambda domain: degraded)

    status, payload = _request(base_url, f"/api/sites/{DOMAIN}/security")

    assert status == 200
    assert payload["login_shield"]["health"] == "degraded"
    assert payload["login_shield"]["action_stale"] is True
    assert "IPv6" in payload["login_shield"]["degraded_reason"]


def test_login_shield_payload_never_exposes_auth_log_or_account_keys(panel_server):
    base_url, paths = panel_server
    site = _seed_site(paths)
    (site / "security").mkdir(parents=True, exist_ok=True)
    account_hash = "ab" * 32
    raw = {
        "timestamp": "2026-08-06T12:00:00Z",
        "event": "wordpress_auth_failure",
        "site": DOMAIN,
        "surface": "wp_login",
        "client_ip": "198.51.100.9",
        "account_hash": account_hash,
        "reason_class": "hard",
        "username": "mallory",
    }
    (site / "security" / "wp-auth.log").write_text(json.dumps(raw) + "\n", encoding="utf-8")

    status, payload = _request(base_url, f"/api/sites/{DOMAIN}/security")

    assert status == 200
    assert payload["login_shield"]["last_detected_failure"] == "2026-08-06T12:00:00Z"
    assert payload["login_shield"]["recent_matched_failures"] == 1
    rendered = json.dumps(payload)
    assert "mallory" not in rendered
    assert account_hash not in rendered
    assert "198.51.100.9" not in rendered
    assert "account_hash" not in rendered
    assert "reason_class" not in rendered


def test_panel_jail_not_toggleable_through_site_security(panel_server):
    base_url, paths = panel_server
    _seed_site(paths)

    status, payload = _request(
        base_url,
        f"/api/sites/{DOMAIN}/security",
        method="PUT",
        body={"panel_jail_enabled": False},
    )
    assert status == 400
    assert "unsupported field" in payload["error"]

    rendered = json.dumps(_request(base_url, f"/api/sites/{DOMAIN}/security")[1])
    assert "panel_jail_enabled" not in rendered
    assert "wpfy-panel-auth" not in rendered


# ---------------------------------------------------------------------------
# File-manager proxy mutations assert same-origin (wave-14 gate F1)
# ---------------------------------------------------------------------------


def _echo_upstream(seen):
    class EchoHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            seen.append(True)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok": true}')

        def log_message(self, format, *args):
            pass

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), EchoHandler)
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    return upstream, thread


def _fm_proxy_cookie(base_url, paths, monkeypatch):
    import wpfy.panel as panel

    seen = []
    upstream, thread = _echo_upstream(seen)
    monkeypatch.setattr(
        panel.quantum_provider, "provider_port", lambda domain: upstream.server_address[1]
    )
    monkeypatch.setattr(
        panel.panel_file_manager,
        "enable_file_manager",
        lambda domain, username, provider: {"state": "ready", "url": f"/api/sites/{domain}/file-manager/proxy/"},
    )
    request = urllib.request.Request(f"{base_url}/api/sites/{DOMAIN}/file-manager/enable", method="POST")
    request.add_header("Authorization", f"Bearer {TEST_TOKEN}")
    with urllib.request.urlopen(request, data=b"{}", timeout=10) as response:
        headers = dict(response.headers)
    cookie = headers["Set-Cookie"].split(";", 1)[0]
    return cookie, seen, upstream, thread


def test_file_manager_proxy_mutation_rejects_cross_origin(panel_server, monkeypatch):
    base_url, paths = panel_server
    _seed_site(paths)

    cookie, seen, upstream, thread = _fm_proxy_cookie(base_url, paths, monkeypatch)
    try:
        status, payload = _request(
            base_url,
            f"/api/sites/{DOMAIN}/file-manager/proxy/echo",
            method="POST",
            headers={"Cookie": cookie, "Origin": "https://evil.example"},
        )
        assert status == 403
        assert payload == {"error": "cross-origin request denied"}
        assert not seen, "cross-origin mutation reached the file manager upstream"
    finally:
        upstream.shutdown()
        upstream.server_close()
        thread.join(timeout=5)


def test_file_manager_proxy_mutation_without_origin_still_proxies(panel_server, monkeypatch):
    base_url, paths = panel_server
    _seed_site(paths)

    cookie, seen, upstream, thread = _fm_proxy_cookie(base_url, paths, monkeypatch)
    try:
        status, payload = _request(
            base_url,
            f"/api/sites/{DOMAIN}/file-manager/proxy/echo",
            method="POST",
            headers={"Cookie": cookie},
        )
        assert status == 200
        assert payload == {"ok": True}
        assert seen == [True], "validated same-origin mutation did not reach the upstream"
    finally:
        upstream.shutdown()
        upstream.server_close()
        thread.join(timeout=5)


def test_file_manager_proxy_read_stays_non_mutating(panel_server):
    """The GET proxy route keeps read semantics: no mutates, no origin gate."""
    import wpfy.panel as panel

    proxy = [
        (route.method, route.meta.mutates)
        for route in panel._ROUTES
        if "file-manager/proxy" in route.pattern.pattern
    ]
    assert ("GET", False) in proxy, "GET proxy route must remain read-only"
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        assert (method, True) in proxy, f"{method} proxy route must be declared mutating"
