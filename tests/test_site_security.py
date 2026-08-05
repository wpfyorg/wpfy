from __future__ import annotations

import importlib
import json
from pathlib import Path
import re

import pytest


@pytest.fixture
def security_modules(tmp_wpfy_home, monkeypatch):
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    monkeypatch.setenv("WPFY_TEST_TRAEFIK_NETWORK_CIDRS", "172.18.0.0/16")
    import wpfy.site_paths
    import wpfy.site_security
    import wpfy.site_layout

    importlib.reload(wpfy.site_paths)
    importlib.reload(wpfy.site_security)
    importlib.reload(wpfy.site_layout)
    return wpfy.site_layout, wpfy.site_security


def _site(layout, domain="security.example.com"):
    layout.ensure_site_scaffold(
        layout.SiteSpec(domain=domain, flavor="wp", use_mysql=True, use_redis=False),
    )
    return layout.site_dir(domain)


def test_scaffold_creates_security_state_and_generated_include(security_modules):
    layout, security = security_modules
    site = _site(layout)

    assert not (site / "security.json").exists()
    snippet = site / "nginx" / "extra" / security.SECURITY_SNIPPET
    assert snippet.is_file()
    assert "real_ip_header X-Forwarded-For;" in snippet.read_text(encoding="utf-8")
    forwarded_scheme = site / "nginx" / security.FORWARDED_SCHEME_SNIPPET
    forwarded_text = forwarded_scheme.read_text(encoding="utf-8")
    assert "geo $realip_remote_addr $wpfy_trusted_edge {" in forwarded_text
    assert "172.18.0.0/16 1;" in forwarded_text
    assert 'map "$wpfy_trusted_edge:$http_x_forwarded_proto" $wpfy_https {' in forwarded_text
    assert '"1:https" on;' in forwarded_text
    htpasswd = site / "nginx" / security.HTPASSWD_FILE
    assert htpasswd.is_file()
    assert htpasswd.stat().st_mode & 0o777 == 0o640
    access_log = security.access_log_path("security.example.com")
    assert access_log.is_file()
    assert access_log.stat().st_mode & 0o777 == 0o640
    assert "copytruncate" in security._logrotate_path("security.example.com").read_text(encoding="utf-8")
    compose = (site / "compose.yaml").read_text(encoding="utf-8")
    assert f"./nginx/{security.HTPASSWD_FILE}:{security.HTPASSWD_CONTAINER_PATH}:ro" in compose
    assert (
        f"./nginx/{security.FORWARDED_SCHEME_SNIPPET}:"
        "/etc/nginx/conf.d/00-wpfy-forwarded-scheme.conf:ro"
    ) in compose
    assert "./nginx/wpfy-access.log:/var/log/nginx/wpfy-access.log" in compose
    nginx_config = (site / "nginx" / "default.conf").read_text(encoding="utf-8")
    assert "fastcgi_param HTTPS $wpfy_https;" in nginx_config
    assert "fastcgi_param HTTPS on;" not in nginx_config
    assert "default off;" in forwarded_text


def test_security_state_round_trip_and_rendering(security_modules):
    layout, security = security_modules
    site = _site(layout)
    domain = "security.example.com"

    security.add_deny_ip(domain, "198.51.100.7/24")
    security.add_ua_block(domain, "^EvilBot(?:/|$)")

    assert security.load_security(domain) == {
        "basic_auth": {"enabled": False, "username": None},
        "cloudflare_only": False,
        "login_rate_limit": False,
        "fail2ban": False,
        "deny_ips": ["198.51.100.0/24"],
        "ua_blocks": ["^EvilBot(?:/|$)"],
    }
    snippet = (site / "nginx" / "extra" / security.SECURITY_SNIPPET).read_text(encoding="utf-8")
    assert "deny 198.51.100.0/24;" in snippet
    assert '^EvilBot(?:/|$)' in snippet
    assert 'return 403;' in snippet

    security.remove_deny_ip(domain, "198.51.100.7/24")
    security.remove_ua_block(domain, "^EvilBot(?:/|$)")
    assert security.load_security(domain) == {
        "basic_auth": {"enabled": False, "username": None},
        "cloudflare_only": False,
        "login_rate_limit": False,
        "fail2ban": False,
        "deny_ips": [],
        "ua_blocks": [],
    }


def test_security_render_is_byte_stable(security_modules):
    layout, security = security_modules
    site = _site(layout)
    domain = "security.example.com"
    security.add_deny_ip(domain, "203.0.113.7/32")
    security.add_ua_block(domain, "EvilBot")
    path = site / "nginx" / "extra" / security.SECURITY_SNIPPET
    first = path.read_bytes()

    assert security.render_security(domain).changed is False
    assert security.render_security(domain).changed is False
    assert path.read_bytes() == first


def test_forwarded_scheme_render_is_byte_stable(security_modules):
    layout, security = security_modules
    site = _site(layout)
    domain = "security.example.com"
    path = site / "nginx" / security.FORWARDED_SCHEME_SNIPPET
    first = path.read_bytes()

    assert security.render_forwarded_scheme(domain).changed is False
    assert security.render_forwarded_scheme(domain).changed is False
    assert path.read_bytes() == first


@pytest.mark.parametrize(
    "value",
    (
        "10.0.0.0/8; return 200 'bad'",
        "10.0.0.0/8\nallow all;",
        '10.0.0.0/8" break',
        "10.0.0.0/8\\x00bad",
        "0.0.0.0/0",
        "",
        "   ",
    ),
)
def test_invalid_cidr_is_rejected_before_state_or_snippet_write(security_modules, value):
    layout, security = security_modules
    site = _site(layout)
    domain = "security.example.com"
    snippet_path = site / "nginx" / "extra" / security.SECURITY_SNIPPET
    state_path = site / security.SECURITY_STATE
    before = (
        state_path.read_bytes() if state_path.exists() else None,
        snippet_path.read_bytes() if snippet_path.exists() else None,
    )

    with pytest.raises(ValueError):
        security.add_deny_ip(domain, value)

    after = (
        state_path.read_bytes() if state_path.exists() else None,
        snippet_path.read_bytes() if snippet_path.exists() else None,
    )
    assert after == before
    snippet_text = snippet_path.read_text(encoding="utf-8") if snippet_path.exists() else ""
    assert "bad" not in snippet_text


@pytest.mark.parametrize(
    "value",
    (
        'evil"; return 200 "bad',
        "evilbot\nreturn 200 'bad';",
        "evilbot\\\nbad",
        "evilbot}\nserver {",
        "",
        "   ",
    ),
)
def test_invalid_user_agent_is_rejected_before_state_or_snippet_write(security_modules, value):
    layout, security = security_modules
    site = _site(layout)
    domain = "security.example.com"
    snippet_path = site / "nginx" / "extra" / security.SECURITY_SNIPPET
    state_path = site / security.SECURITY_STATE
    before = (
        state_path.read_bytes() if state_path.exists() else None,
        snippet_path.read_bytes() if snippet_path.exists() else None,
    )

    with pytest.raises(ValueError):
        security.add_ua_block(domain, value)

    after = (
        state_path.read_bytes() if state_path.exists() else None,
        snippet_path.read_bytes() if snippet_path.exists() else None,
    )
    assert after == before


def test_htpasswd_helpers_moved_and_new_hashes_are_salted(monkeypatch):
    import wpfy.cli as cli
    from wpfy import site_security

    assert not hasattr(cli, "_htpasswd_sha")
    assert not hasattr(cli, "_safe_htpasswd_username")
    monkeypatch.setattr(site_security.secrets, "choice", lambda _alphabet: ".")
    assert site_security._htpasswd_apr1("secret") == "$apr1$........$9SzY/TdPRPHQr/nVfsH1r/"

    monkeypatch.undo()
    first = site_security._htpasswd_apr1("secret")
    second = site_security._htpasswd_apr1("secret")
    assert first.startswith("$apr1$")
    assert first != second
    assert site_security._safe_htpasswd_username("operator@example.com")
    assert not site_security._safe_htpasswd_username("bad:name")


def test_htpasswd_hash_uses_openssl_stdin_and_records_apr1_fallback(monkeypatch):
    from wpfy import site_security

    seen = {}

    class OpenSSL:
        returncode = 0

        def communicate(self, password):
            seen["input"] = password
            return "$6$salt$hash\n", ""

    def openssl(argv, **kwargs):
        seen["argv"] = argv
        seen.update(kwargs)
        return OpenSSL()

    monkeypatch.setattr(site_security.subprocess, "Popen", openssl)
    assert site_security._htpasswd_hash("secret") == ("$6$salt$hash", "sha512crypt")
    assert seen["argv"] == ["openssl", "passwd", "-6", "-stdin"]
    assert seen["input"] == "secret"

    monkeypatch.setattr(site_security.subprocess, "Popen", lambda *args, **kwargs: (_ for _ in ()).throw(FileNotFoundError()))
    hashed, scheme = site_security._htpasswd_hash("secret")
    assert hashed.startswith("$apr1$")
    assert scheme == "apr1"


def test_real_ip_uses_edge_subnet_and_cloudflare_for_proxied_site(security_modules, monkeypatch):
    layout, security = security_modules
    domain = "security.example.com"
    site = _site(layout, domain)
    env_file = site / ".env"
    env_file.write_text(env_file.read_text(encoding="utf-8") + "PROXIED=1\n", encoding="utf-8")
    monkeypatch.setenv("WPFY_TEST_TRAEFIK_NETWORK_CIDRS", "172.18.0.0/16")
    monkeypatch.setenv("WPFY_CLOUDFLARE_RANGES", "203.0.113.0/24,2001:db8::/32")

    result = security.add_deny_ip(domain, "198.51.100.7/32")

    assert result.exit_code == 0
    snippet = (site / "nginx" / "extra" / security.SECURITY_SNIPPET).read_text(encoding="utf-8")
    assert "set_real_ip_from 172.18.0.0/16;" in snippet
    assert "set_real_ip_from 203.0.113.0/24;" in snippet
    assert "set_real_ip_from 2001:db8::/32;" in snippet
    assert "wpfy-traefik" not in snippet


def test_real_ip_discovery_failure_installs_fail_closed_rules(security_modules, monkeypatch):
    layout, security = security_modules
    site = _site(layout)

    def fail_trust_discovery():
        raise RuntimeError("Docker reported no subnet")

    monkeypatch.setattr(security, "traefik_network_cidrs", fail_trust_discovery)
    result = security.add_deny_ip("security.example.com", "198.51.100.7/32")

    assert result.exit_code != 0
    assert "fail-closed" in result.message
    snippet = (site / "nginx" / "extra" / security.SECURITY_SNIPPET).read_text(encoding="utf-8")
    assert "set_real_ip_from 127.0.0.1/32;" in snippet
    assert "deny all;" in snippet


@pytest.mark.parametrize(
    "mutation",
    (
        "add-deny-ip",
        "remove-deny-ip",
        "add-ua-block",
        "remove-ua-block",
        "basic-auth-on",
        "basic-auth-off",
        "cloudflare-only-on",
        "cloudflare-only-off",
    ),
)
def test_security_mutations_propagate_render_failure(security_modules, monkeypatch, mutation):
    layout, security = security_modules
    domain = "security.example.com"
    _site(layout, domain)
    failure = security.SecurityResult(3, "security render failed")
    monkeypatch.setattr(security, "render_security", lambda _domain: failure)

    operations = {
        "add-deny-ip": lambda: security.add_deny_ip(domain, "198.51.100.7/32"),
        "remove-deny-ip": lambda: security.remove_deny_ip(domain, "198.51.100.7/32"),
        "add-ua-block": lambda: security.add_ua_block(domain, "EvilBot"),
        "remove-ua-block": lambda: security.remove_ua_block(domain, "EvilBot"),
        "basic-auth-on": lambda: security.set_basic_auth(
            domain,
            enabled=True,
            username="operator",
            password="test-secret",
        ),
        "basic-auth-off": lambda: security.set_basic_auth(domain, enabled=False),
        "cloudflare-only-on": lambda: security.set_cloudflare_only(domain, True),
        "cloudflare-only-off": lambda: security.set_cloudflare_only(domain, False),
    }

    result = operations[mutation]()

    assert result.exit_code == failure.exit_code
    assert result.message == failure.message


def test_basic_auth_hashes_password_and_rotates_in_place(security_modules):
    layout, security = security_modules
    domain = "security.example.com"
    site = _site(layout, domain)
    htpasswd = site / "nginx" / security.HTPASSWD_FILE
    before_inode = htpasswd.stat().st_ino

    enabled = security.set_basic_auth(domain, enabled=True, username="operator", password="first-secret")
    first = htpasswd.read_text(encoding="utf-8")
    rotated = security.set_basic_auth(domain, enabled=True, username="operator", password="second-secret")
    second = htpasswd.read_text(encoding="utf-8")

    assert enabled.exit_code == rotated.exit_code == 0
    assert htpasswd.stat().st_ino == before_inode
    assert first != second
    assert "first-secret" not in first
    assert "second-secret" not in second
    assert first.startswith("operator:$6$")
    assert second.startswith("operator:$6$")
    assert htpasswd.stat().st_mode & 0o777 == 0o640
    assert "password" not in security.load_security(domain)["basic_auth"]
    assert not list((site / "app").rglob("*htpasswd*"))
    snippet = (site / "nginx" / "extra" / security.SECURITY_SNIPPET).read_text(encoding="utf-8")
    assert f"auth_basic_user_file {security.HTPASSWD_CONTAINER_PATH};" in snippet
    nginx_config = (site / "nginx" / "default.conf").read_text(encoding="utf-8")
    assert "location = /healthz.html {\n        access_log off;\n        auth_basic off;" in nginx_config

    disabled = security.set_basic_auth(domain, enabled=False)
    assert disabled.exit_code == 0
    assert htpasswd.stat().st_ino == before_inode
    assert htpasswd.read_text(encoding="utf-8") == ""
    snippet = (site / "nginx" / "extra" / security.SECURITY_SNIPPET).read_text(encoding="utf-8")
    assert "auth_basic" not in snippet


def test_login_rate_limit_renders_php_handler_and_updates_the_mounted_zone(security_modules, monkeypatch):
    layout, security = security_modules
    domain = "security.example.com"
    site = _site(layout, domain)
    monkeypatch.setenv("WPFY_TEST_TRAEFIK_NETWORK_CIDRS", "172.18.0.0/16")
    zone_file = site / "nginx" / security.RATELIMIT_SNIPPET
    before_inode = zone_file.stat().st_ino

    enabled = security.set_login_rate_limit(domain, True)
    request_zone = security.login_zone_name(domain)
    snippet = (site / "nginx" / "extra" / security.SECURITY_SNIPPET).read_text(encoding="utf-8")
    zones = zone_file.read_text(encoding="utf-8")
    compose = (site / "compose.yaml").read_text(encoding="utf-8")

    assert enabled.exit_code == 0
    assert security.load_security(domain)["login_rate_limit"] is True
    assert f"limit_req zone={request_zone} burst=5 nodelay;" in snippet
    assert "location = /wp-login.php {" in snippet
    assert "fastcgi_pass app:9000;" in snippet
    assert "fastcgi_param SCRIPT_FILENAME" in snippet
    assert "fastcgi_param HTTPS $wpfy_https;" in snippet
    assert f"limit_req_zone $binary_remote_addr zone={request_zone}:1m rate=1r/s;" in zones
    assert f"limit_conn_zone $binary_remote_addr zone={request_zone}_conn:1m;" in zones
    assert "set_real_ip_from 172.18.0.0/16;" in snippet
    assert f"./nginx/{security.RATELIMIT_SNIPPET}:/etc/nginx/conf.d/00-wpfy-ratelimit.conf:ro" in compose
    assert zone_file.stat().st_ino == before_inode

    disabled = security.set_login_rate_limit(domain, False)
    assert disabled.exit_code == 0
    assert zone_file.read_text(encoding="utf-8") == ""
    assert "wp-login" not in (site / "nginx" / "extra" / security.SECURITY_SNIPPET).read_text(encoding="utf-8")
    assert zone_file.stat().st_ino == before_inode


def test_login_rate_limit_reports_staged_config_until_nginx_reload_succeeds(security_modules, monkeypatch):
    layout, security = security_modules
    domain = "security.example.com"
    _site(layout, domain)
    reloads = ["nginx rejected config", None]
    monkeypatch.setattr(security, "_reload_web_service", lambda _domain: reloads.pop(0))

    failed = security.set_login_rate_limit(domain, True)
    retried = security.set_login_rate_limit(domain, True)

    assert failed.exit_code != 0
    assert "written but not applied" in failed.message
    assert security.load_security(domain)["login_rate_limit"] is True
    assert retried.exit_code == 0


def test_cloudflare_only_reports_staged_labels_until_web_recreate_succeeds(security_modules, monkeypatch):
    layout, security = security_modules
    domain = "security.example.com"
    _site(layout, domain)
    recreates = ["docker unavailable", None]
    monkeypatch.setattr(security, "_recreate_web_service", lambda _domain: recreates.pop(0))

    failed = security.set_cloudflare_only(domain, True)
    retried = security.set_cloudflare_only(domain, True)

    assert failed.exit_code != 0
    assert "written but not applied" in failed.message
    assert security.load_security(domain)["cloudflare_only"] is True
    assert retried.exit_code == 0


def test_fail2ban_is_per_site_and_uses_docker_user_chain(security_modules, monkeypatch):
    layout, security = security_modules
    domain = "security.example.com"
    site = _site(layout, domain)
    monkeypatch.setenv("WPFY_TEST_TRAEFIK_NETWORK_CIDRS", "172.18.0.0/16")
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    monkeypatch.setattr(security, "fail2ban_available", lambda: True)

    access_log = security.access_log_path(domain)
    before_inode = access_log.stat().st_ino
    enabled = security.set_fail2ban(domain, True)
    filter_text = security.fail2ban_filter_path().read_text(encoding="utf-8")
    jail_text = security.fail2ban_jail_path().read_text(encoding="utf-8")

    assert enabled.exit_code == 0
    assert security.load_security(domain)["fail2ban"] is True
    assert "datepattern = {NONE}" in filter_text
    assert "POST /wp-login" in filter_text
    assert "POST /xmlrpc" not in filter_text
    login_pattern = re.search(r"failregex = (.*<HOST>.*)", filter_text)
    assert login_pattern is not None
    compiled = re.compile(login_pattern.group(1).replace("<HOST>", r"(?P<host>[0-9a-fA-F:.]+)"))
    login_with_query = (
        '203.0.113.9 - - [28/Jul/2026:01:00:00 +0000] '
        '"POST /wp-login.php?redirect_to=/ HTTP/1.1" 200 12 "-" "curl"'
    )
    assert compiled.search(login_with_query)
    assert str(access_log) in jail_text
    assert 'port="http,https"' in jail_text
    assert "chain=DOCKER-USER" in jail_text
    assert "chain=INPUT" not in jail_text
    assert access_log.stat().st_ino == before_inode
    logrotate_text = security._logrotate_path(domain).read_text(encoding="utf-8")
    assert "maxsize 100M" in logrotate_text
    assert "copytruncate" in logrotate_text

    disabled = security.set_fail2ban(domain, False)
    assert disabled.exit_code == 0
    assert security.load_security(domain)["fail2ban"] is False
    assert not security.fail2ban_filter_path().exists()
    assert not security.fail2ban_jail_path().exists()


def test_removing_site_removes_its_fail2ban_jail(security_modules, monkeypatch):
    layout, security = security_modules
    deleted_domain = "delete-jail.example.com"
    retained_domain = "retain-jail.example.com"
    _site(layout, deleted_domain)
    _site(layout, retained_domain)
    monkeypatch.setenv("WPFY_TEST_TRAEFIK_NETWORK_CIDRS", "172.18.0.0/16")
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    monkeypatch.setattr(security, "fail2ban_available", lambda: True)
    reloads = []
    monkeypatch.setattr(security, "_reload_fail2ban", lambda: reloads.append(True))

    assert security.set_fail2ban(deleted_domain, True).exit_code == 0
    assert security.set_fail2ban(retained_domain, True).exit_code == 0
    assert layout.remove_site_scaffold(deleted_domain)

    jail_text = security.fail2ban_jail_path().read_text(encoding="utf-8")
    assert f"[{security._fail2ban_jail_name(deleted_domain)}]" not in jail_text
    assert f"[{security._fail2ban_jail_name(retained_domain)}]" in jail_text
    assert not security._logrotate_path(deleted_domain).exists()
    assert len(reloads) == 3


def test_fail2ban_disable_skips_unrelated_corrupt_security_state(security_modules, monkeypatch):
    layout, security = security_modules
    target_domain = "disable-jail.example.com"
    retained_domain = "healthy-jail.example.com"
    corrupt_domain = "corrupt-jail.example.com"
    _site(layout, target_domain)
    _site(layout, retained_domain)
    corrupt_site = _site(layout, corrupt_domain)
    monkeypatch.setenv("WPFY_TEST_TRAEFIK_NETWORK_CIDRS", "172.18.0.0/16")
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    monkeypatch.setattr(security, "fail2ban_available", lambda: True)

    assert security.set_fail2ban(target_domain, True).exit_code == 0
    assert security.set_fail2ban(retained_domain, True).exit_code == 0
    (corrupt_site / security.SECURITY_STATE).write_text("{not-json", encoding="utf-8")

    disabled = security.set_fail2ban(target_domain, False)

    assert disabled.exit_code == 0
    assert corrupt_domain in disabled.message
    assert security.load_security(target_domain)["fail2ban"] is False
    jail_text = security.fail2ban_jail_path().read_text(encoding="utf-8")
    assert f"[{security._fail2ban_jail_name(target_domain)}]" not in jail_text
    assert f"[{security._fail2ban_jail_name(retained_domain)}]" in jail_text


def test_fail2ban_refuses_without_client_binary(security_modules, monkeypatch):
    layout, security = security_modules
    _site(layout)
    monkeypatch.setattr(security, "fail2ban_available", lambda: False)

    result = security.set_fail2ban("security.example.com", True)

    assert result.exit_code != 0
    assert "fail2ban" in result.message
    assert security.load_security("security.example.com")["fail2ban"] is False
    assert not security.fail2ban_filter_path().exists()
    assert not security.fail2ban_jail_path().exists()


def test_basic_auth_generated_password_is_returned_once(security_modules):
    layout, security = security_modules
    _site(layout)

    result = security.set_basic_auth("security.example.com", enabled=True, username="operator")
    rerender = security.render_security("security.example.com")

    assert result.one_time_password
    assert rerender.one_time_password is None
    site_text = "\n".join(
        path.read_text(encoding="utf-8", errors="ignore")
        for path in layout.site_dir("security.example.com").rglob("*")
        if path.is_file()
    )
    assert result.one_time_password not in site_text


def test_cloudflare_only_labels_round_trip_from_security_state(security_modules, monkeypatch):
    layout, security = security_modules
    domain = "security.example.com"
    _site(layout, domain)
    monkeypatch.setenv("WPFY_CLOUDFLARE_RANGES", "203.0.113.0/24,2001:db8::/32")

    enabled = security.set_cloudflare_only(domain, True)
    compose = layout.compose_content(
        layout.SiteSpec.from_env(domain, layout.read_env(layout.env_path(domain))),
    )
    assert enabled.exit_code == 0
    assert "ipallowlist.sourcerange=203.0.113.0/24,2001:db8::/32" in compose
    assert f"routers.security-example-com.middlewares=security-example-com-cloudflare-only" in compose

    disabled = security.set_cloudflare_only(domain, False)
    compose = layout.compose_content(
        layout.SiteSpec.from_env(domain, layout.read_env(layout.env_path(domain))),
    )
    assert disabled.exit_code == 0
    assert "cloudflare-only" not in compose
    assert "ipallowlist" not in compose.lower()


def test_cloudflare_only_preflight_warns_for_direct_dns(security_modules, monkeypatch):
    layout, security = security_modules
    _site(layout)
    monkeypatch.setenv("WPFY_TEST_DNS_IPS", "203.0.113.9")

    result = security.security_preflight("security.example.com", {"cloudflare_only": True})

    assert result.warnings
    assert "Cloudflare" in result.warnings[0]


def test_security_state_is_backed_up(security_modules, monkeypatch):
    layout, security = security_modules
    domain = "security.example.com"
    _site(layout, domain)
    security.add_deny_ip(domain, "203.0.113.7/32")
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")

    result = layout.backup_site(domain)
    assert result.exit_code == 0
    import wpfy.settings
    archives = sorted((Path(wpfy.settings.PATHS.state_dir) / "backups" / domain).glob("*.tar.gz"))
    assert archives

    import tarfile
    with tarfile.open(archives[-1], "r:gz") as archive:
        assert f"{domain}/security.json" in archive.getnames()
