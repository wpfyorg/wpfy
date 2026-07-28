from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import subprocess
import threading

import pytest


@pytest.fixture
def phase2_panel(tmp_wpfy_home, monkeypatch):
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    import wpfy.panel

    config = wpfy.panel.PanelConfig(host="127.0.0.1", port=0, token="test-panel-token")
    server = wpfy.panel.make_panel_server(config)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", tmp_wpfy_home
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_scaffold_creates_operator_files_and_generated_php_ini(tmp_wpfy_home):
    from wpfy import site_layout
    from wpfy.site_definition import SiteDefinition

    spec = SiteDefinition(domain="example.com", flavor="wp", use_mysql=True, use_redis=False)
    site_layout.ensure_site_scaffold(spec)
    root = Path(tmp_wpfy_home.sites_dir) / "example.com"

    assert (root / "nginx" / "extra" / "custom.conf").read_text() == ""
    assert (root / "php" / "custom.ini").read_text() == ""
    assert "memory_limit = 256M" in (root / "php" / "zz-wpfy.ini").read_text()
    assert "include /etc/nginx/wpfy-extra/*.conf;" in (root / "nginx" / "default.conf").read_text()

    (root / "nginx" / "extra" / "custom.conf").write_text("# operator\n")
    (root / "php" / "custom.ini").write_text("; operator\n")
    site_layout.ensure_site_scaffold(replace(spec, php_upload_max_size="128M"))
    assert (root / "nginx" / "extra" / "custom.conf").read_text() == "# operator\n"
    assert (root / "php" / "custom.ini").read_text() == "; operator\n"
    assert "client_max_body_size 128m;" in (root / "nginx" / "default.conf").read_text()


def test_scaffold_recreates_compose_after_mount_sources_exist(tmp_wpfy_home):
    from wpfy import site_layout
    from wpfy.site_definition import SiteDefinition

    spec = SiteDefinition(domain="example.com", flavor="wp", use_mysql=True, use_redis=False)
    site_layout.ensure_site_scaffold(spec)
    root = Path(tmp_wpfy_home.sites_dir) / "example.com"
    (root / "compose.yaml").unlink()

    site_layout.ensure_site_scaffold(spec)

    assert (root / "php" / "zz-wpfy.ini").is_file()
    assert (root / "php" / "custom.ini").is_file()
    assert (root / "nginx" / "default.conf").is_file()
    assert (root / "nginx" / "extra" / "custom.conf").is_file()
    assert (root / "compose.yaml").is_file()


def test_adminer_compose_is_loopback_only(tmp_wpfy_home):
    from wpfy import site_layout
    from wpfy.site_definition import SiteDefinition

    spec = SiteDefinition(
        domain="example.com", flavor="wp", use_mysql=True, use_redis=False, site_uid=100001,
        adminer_port="8081",
    )
    compose = site_layout.compose_content(spec)
    assert '127.0.0.1:8081:8080' in compose
    assert "0.0.0.0:8081" not in compose
    assert "adminer:5" in compose


def test_nginx_custom_validates_before_swap(tmp_wpfy_home, monkeypatch):
    from wpfy import site_layout
    from wpfy.site_definition import SiteDefinition

    site_layout.ensure_site_scaffold(
        SiteDefinition(domain="example.com", flavor="wp", use_mysql=True, use_redis=False),
    )
    calls = []

    def fake_compose(domain, *args, input_text=None):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, "nginx: configuration file test is successful\n", "")

    monkeypatch.setattr(site_layout, "compose_command", fake_compose)
    monkeypatch.setattr(site_layout, "docker_available", lambda: True)
    result = site_layout.set_nginx_custom("example.com", "location = /ok { return 204; }\n")
    custom = Path(tmp_wpfy_home.sites_dir) / "example.com" / "nginx" / "extra" / "custom.conf"

    assert result.exit_code == 0
    assert custom.read_text() == "location = /ok { return 204; }\n"
    assert any(args[-2:] == ("nginx", "-t") for args in calls)
    assert sorted(path.name for path in custom.parent.iterdir()) == ["custom.conf", "wpfy-security.conf"]


def test_nginx_custom_reports_stopped_runtime_without_installing(tmp_wpfy_home, monkeypatch):
    from wpfy import site_layout
    from wpfy.site_definition import SiteDefinition

    site_layout.ensure_site_scaffold(
        SiteDefinition(domain="example.com", flavor="wp", use_mysql=True, use_redis=False),
    )
    custom = Path(tmp_wpfy_home.sites_dir) / "example.com" / "nginx" / "extra" / "custom.conf"
    custom.write_text("# live\n", encoding="utf-8")
    calls = []

    def fake_compose(domain, *args, input_text=None):
        calls.append(args)
        return subprocess.CompletedProcess(
            args,
            1,
            "",
            'nginx: [emerg] host not found in upstream "app" in /etc/nginx/conf.d/default.conf:43\n',
        )

    monkeypatch.setattr(site_layout, "compose_command", fake_compose)
    monkeypatch.setattr(site_layout, "docker_available", lambda: True)

    result = site_layout.set_nginx_custom("example.com", "location = /ok { return 204; }\n")

    assert result.exit_code != 0
    assert "site runtime to be running" in result.message
    assert custom.read_text(encoding="utf-8") == "# live\n"
    assert not any("reload" in args for args in calls)
    assert sorted(path.name for path in custom.parent.iterdir()) == ["custom.conf", "wpfy-security.conf"]


def test_cli_phase2_parsers_exist():
    from wpfy.cli import build_parser

    parser = build_parser()
    assert parser.parse_args(["db", "example.com", "list"]).db_command == "list"
    assert parser.parse_args(["db", "example.com", "user-add", "wp_user", "--password", "-"]).password == "-"
    assert parser.parse_args(["config", "example.com", "--memory-limit", "512M"]).php_memory_limit == "512M"
    assert parser.parse_args(["site", "nginx", "example.com", "set", "--stdin"]).nginx_command == "set"


def test_panel_php_settings_endpoint(phase2_panel):
    import json
    from urllib.request import Request, urlopen

    base_url, paths = phase2_panel
    site = Path(paths.sites_dir) / "example.com"
    site.mkdir(parents=True)
    (site / ".env").write_text("DOMAIN=example.com\nSITE_FLAVOR=wp\nPHP_VERSION=8.4\n", encoding="utf-8")
    (site / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
    request = Request(
        f"{base_url}/api/sites/example.com/php-settings",
        method="POST",
        data=json.dumps({"php_memory_limit": "512M"}).encode(),
        headers={"Authorization": "Bearer test-panel-token", "Content-Type": "application/json"},
    )
    with urlopen(request) as response:
        body = json.loads(response.read())
    assert body["ok"] is True
    assert "memory_limit = 512M" in (site / "php" / "zz-wpfy.ini").read_text()
