from __future__ import annotations

import importlib
import json
from pathlib import Path
import re
import subprocess

import pytest


class FakeProc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


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
        "fail2ban_plugin": {
            "slug": None,
            "version": None,
            "ownership": None,
            "auto_updates_disabled": False,
            "active": False,
        },
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
        "fail2ban_plugin": {
            "slug": None,
            "version": None,
            "ownership": None,
            "auto_updates_disabled": False,
            "active": False,
        },
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

        def communicate(self, password, timeout=None):
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
    from wpfy.site_event_pipeline import auth_log_path

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
    # The combined shared filter carries the strict event-path regex too.
    assert 'event":"wordpress_auth_failure"' in filter_text
    login_pattern = re.search(r"failregex = (.*<HOST>.*)", filter_text)
    assert login_pattern is not None
    compiled = re.compile(login_pattern.group(1).replace("<HOST>", r"(?P<host>[0-9a-fA-F:.]+)"))
    login_with_query = (
        '203.0.113.9 - - [28/Jul/2026:01:00:00 +0000] '
        '"POST /wp-login.php?redirect_to=/ HTTP/1.1" 200 12 "-" "curl"'
    )
    assert compiled.search(login_with_query)
    # Blocker 2 fix: the per-site jail reads ONLY the strict per-site event log
    # (t10 event path). The coarse nginx access log is NOT a jail logpath; the
    # backstop regex stays in the shared filter but is inert for this jail
    # (fail2ban 1.0.2 rejects a space-separated dual logpath at reload).
    assert str(access_log) not in jail_text
    assert str(auth_log_path(domain)) in jail_text
    assert jail_text.count("logpath =") == 1
    jail_name = security._fail2ban_jail_name(domain)
    assert f"action = wpfy-docker-http[name={jail_name}]" in jail_text
    assert "iptables-multiport" not in jail_text
    assert "chain=INPUT" not in jail_text
    assert "chain=DOCKER-USER" not in jail_text
    assert access_log.stat().st_ino == before_inode
    logrotate_text = security._logrotate_path(domain).read_text(encoding="utf-8")
    assert "maxsize 100M" in logrotate_text
    assert "copytruncate" in logrotate_text

    disabled = security.set_fail2ban(domain, False)
    assert disabled.exit_code == 0
    assert security.load_security(domain)["fail2ban"] is False
    assert not security.fail2ban_filter_path().exists()
    assert not security.fail2ban_jail_path().exists()


def test_per_site_jail_renders_exactly_one_logpath(security_modules, monkeypatch):
    """Blocker 2 pin: a per-site jail render carries exactly ONE logpath key
    pointing at the strict wp-auth.log only — never the nginx access log.

    fail2ban 1.0.2 rejects duplicate 'logpath =' keys and its addlogpath
    client/server protocol fails at reload on a space-separated dual value
    ('File option must be head or tail'); the only valid multi-path form is a
    single space-separated value, which WPFY does not use for per-site jails.
    """
    layout, security = security_modules
    domain = "security.example.com"
    _site(layout, domain)
    from wpfy.site_event_pipeline import auth_log_path

    content = security._fail2ban_jail_content((domain,))
    logpath_lines = [
        line for line in content.splitlines() if line.lstrip().startswith("logpath")
    ]
    assert len(logpath_lines) == 1
    assert str(auth_log_path(domain)) in logpath_lines[0]
    assert "wpfy-access.log" not in logpath_lines[0]
    assert "logpath =" in content


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


def test_security_state_includes_plugin_ownership_default(security_modules):
    layout, security = security_modules
    _site(layout)
    state = security.load_security("security.example.com")
    assert state["fail2ban_plugin"] == {
        "slug": None,
        "version": None,
        "ownership": None,
        "auto_updates_disabled": False,
        "active": False,
    }


def test_security_state_round_trip_preserves_plugin_ownership(security_modules):
    layout, security = security_modules
    _site(layout)
    domain = "security.example.com"
    config = security.load_security(domain)
    config["fail2ban_plugin"] = {
        "slug": "wp-fail2ban",
        "version": "5.4.1",
        "ownership": "wpfy-installed",
        "auto_updates_disabled": True,
        "active": True,
    }
    security.save_security(domain, config)
    state = security.load_security(domain)["fail2ban_plugin"]
    assert state["ownership"] == "wpfy-installed"
    assert state["version"] == "5.4.1"
    assert state["active"] is True
    assert state["auto_updates_disabled"] is True


@pytest.mark.parametrize(
    "ownership",
    ("wpfy", "admin", "installed-by-admin", "unknown", "", "wpfy-installed; rm -rf"),
)
def test_security_state_rejects_invalid_plugin_ownership(security_modules, ownership):
    layout, security = security_modules
    _site(layout)
    domain = "security.example.com"
    config = security.load_security(domain)
    config["fail2ban_plugin"] = {
        "slug": "wp-fail2ban",
        "version": "5.4.1",
        "ownership": ownership,
        "auto_updates_disabled": False,
        "active": False,
    }
    with pytest.raises(ValueError):
        security.save_security(domain, config)


def test_fail2ban_enable_ensures_host_when_absent(security_modules, monkeypatch):
    """t08 Branch C: enabling a site ensures host fail2ban instead of refusing."""
    layout, security = security_modules
    _site(layout, "ensure-host.example.com")
    from wpfy.fail2ban_host import HostFail2banResult

    ensured = []
    monkeypatch.setattr(security, "fail2ban_available", lambda: False)
    monkeypatch.setattr(
        security,
        "ensure_fail2ban_host",
        lambda: ensured.append(True)
        or HostFail2banResult(0, "fail2ban healthy", installed=True, health_ok=True),
    )

    result = security.set_fail2ban("ensure-host.example.com", True)

    assert result.exit_code == 0
    assert ensured == [True]
    assert security.load_security("ensure-host.example.com")["fail2ban"] is True
    assert security.fail2ban_filter_path().exists()
    assert security.fail2ban_jail_path().exists()


def test_fail2ban_enable_refuses_when_host_ensure_unhealthy(security_modules, monkeypatch):
    """t08 Branch C: unhealthy/skipped host ensure still refuses cleanly."""
    layout, security = security_modules
    _site(layout, "unhealthy-host.example.com")
    from wpfy.fail2ban_host import HostFail2banResult

    monkeypatch.setattr(security, "fail2ban_available", lambda: False)
    monkeypatch.setattr(
        security,
        "ensure_fail2ban_host",
        lambda: HostFail2banResult(0, "skipped by WPFY_SKIP_RUNTIME", installed=False, health_ok=False),
    )

    result = security.set_fail2ban("unhealthy-host.example.com", True)

    assert result.exit_code != 0
    assert "fail2ban" in result.message
    assert security.load_security("unhealthy-host.example.com")["fail2ban"] is False
    assert not security.fail2ban_filter_path().exists()
    assert not security.fail2ban_jail_path().exists()


def test_fail2ban_filter_file_matches_host_owner(security_modules, monkeypatch):
    """t08: filter.d/wpfy-wordpress.conf content equals the single owner."""
    layout, security = security_modules
    _site(layout)
    from wpfy import fail2ban_host

    monkeypatch.setattr(security, "fail2ban_available", lambda: True)
    assert security.set_fail2ban("security.example.com", True).exit_code == 0

    written = security.fail2ban_filter_path().read_text(encoding="utf-8")
    assert written == fail2ban_host.wordpress_filter_content()


def test_fail2ban_jail_uses_central_policy(security_modules, monkeypatch):
    """t08: per-site jail consumes WORDPRESS_JAIL constants."""
    layout, security = security_modules
    _site(layout)
    from wpfy.fail2ban_host import WORDPRESS_JAIL

    monkeypatch.setattr(security, "fail2ban_available", lambda: True)
    assert security.set_fail2ban("security.example.com", True).exit_code == 0

    jail_text = security.fail2ban_jail_path().read_text(encoding="utf-8")
    assert f"maxretry = {WORDPRESS_JAIL['maxretry']}" in jail_text
    assert f"findtime = {WORDPRESS_JAIL['findtime']}" in jail_text
    assert f"bantime = {WORDPRESS_JAIL['bantime']}" in jail_text


def test_fail2ban_jail_uses_wpfy_docker_action_not_stock(security_modules, monkeypatch):
    """t11: generated jails reference the WPFY action; no stock
    iptables-multiport DOCKER-USER action remains."""
    layout, security = security_modules
    domain = "security.example.com"
    _site(layout, domain)
    monkeypatch.setenv("WPFY_TEST_TRAEFIK_NETWORK_CIDRS", "172.18.0.0/16")
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    monkeypatch.setattr(security, "fail2ban_available", lambda: True)

    assert security.set_fail2ban(domain, True).exit_code == 0
    jail_text = security.fail2ban_jail_path().read_text(encoding="utf-8")

    assert "wpfy-docker-http" in jail_text
    assert "iptables-multiport" not in jail_text
    assert "chain=DOCKER-USER" not in jail_text
    assert "chain=INPUT" not in jail_text
    for line in jail_text.splitlines():
        if line.strip().startswith("action"):
            assert "DOCKER-USER" not in line
            assert "INPUT" not in line


def test_fail2ban_jail_per_site_chain_names_unique_and_bounded(security_modules, monkeypatch):
    """t11 + B1 pin: per-site jails get unique f2b-wpfy-<digest> chains, each
    within the iptables 28-char limit (no silent EINVAL no-op bans)."""
    layout, security = security_modules
    domains = ("unique-a.example.com", "unique-b.example.com")
    for domain in domains:
        _site(layout, domain)
    monkeypatch.setenv("WPFY_TEST_TRAEFIK_NETWORK_CIDRS", "172.18.0.0/16")
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    monkeypatch.setattr(security, "fail2ban_available", lambda: True)

    for domain in domains:
        assert security.set_fail2ban(domain, True).exit_code == 0
    jail_text = security.fail2ban_jail_path().read_text(encoding="utf-8")
    from wpfy.fail2ban_docker import CHAIN_PREFIX, IPTABLES_CHAIN_MAX_LENGTH, validate_chain_name

    chain_names = re.findall(r"wpfy-docker-http\[name=([^\]]+)\]", jail_text)
    assert len(chain_names) == len(set(chain_names)) == 2
    for name in chain_names:
        assert re.fullmatch(r"[0-9a-f]{16}", name), name
        chain = f"{CHAIN_PREFIX}{name}"
        validate_chain_name(chain)
        assert len(chain) <= IPTABLES_CHAIN_MAX_LENGTH, chain


def test_fail2ban_enable_emits_login_shield_enabled_and_ban_events(security_modules, monkeypatch):
    """t13: enable records login_shield.enabled + login_shield.wordpress_fail2ban_ban."""
    layout, security = security_modules
    domain = "security.example.com"
    _site(layout, domain)
    monkeypatch.setenv("WPFY_TEST_TRAEFIK_NETWORK_CIDRS", "172.18.0.0/16")
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    monkeypatch.setattr(security, "fail2ban_available", lambda: True)
    import wpfy.events as events

    assert security.set_fail2ban(domain, True).exit_code == 0

    enabled_events = events.list_events(domain=domain, action="login_shield.enabled")
    assert len(enabled_events) == 1
    assert "wpfy-docker-http" in enabled_events[0]["detail"]
    ban_events = events.list_events(domain=domain, action="login_shield.wordpress_fail2ban_ban")
    assert len(ban_events) == 1
    assert "policy=" in ban_events[0]["detail"]


def test_fail2ban_disable_emits_login_shield_disabled(security_modules, monkeypatch):
    layout, security = security_modules
    domain = "security.example.com"
    _site(layout, domain)
    monkeypatch.setenv("WPFY_TEST_TRAEFIK_NETWORK_CIDRS", "172.18.0.0/16")
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    monkeypatch.setattr(security, "fail2ban_available", lambda: True)
    import wpfy.events as events

    assert security.set_fail2ban(domain, True).exit_code == 0
    assert security.set_fail2ban(domain, False).exit_code == 0

    disabled_events = events.list_events(domain=domain, action="login_shield.disabled")
    assert len(disabled_events) == 1
    assert "jail" in disabled_events[0]["detail"]


def test_fail2ban_enable_requires_plugin_install_success(security_modules, monkeypatch):
    """t13: a refused plugin install never marks the site enabled."""
    layout, security = security_modules
    domain = "security.example.com"
    _site(layout, domain)
    monkeypatch.setenv("WPFY_TEST_TRAEFIK_NETWORK_CIDRS", "172.18.0.0/16")
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    monkeypatch.setattr(security, "fail2ban_available", lambda: True)
    import wpfy.plugin_install as plugin_install

    def refusing(domain):
        return plugin_install.PluginInstallResult(3, "install refused without integrity evidence")

    monkeypatch.setattr(plugin_install, "install_wp_fail2ban", refusing)

    result = security.set_fail2ban(domain, True)

    assert result.exit_code != 0
    assert security.load_security(domain)["fail2ban"] is False
    assert not security.fail2ban_jail_path().exists()
    assert "not enabled" in result.message


def test_fail2ban_enable_refuses_when_fixture_pipeline_proof_fails(security_modules, monkeypatch):
    """t13: no enabled mark when event -> filter -> jail proof fails."""
    layout, security = security_modules
    domain = "security.example.com"
    _site(layout, domain)
    monkeypatch.setenv("WPFY_TEST_TRAEFIK_NETWORK_CIDRS", "172.18.0.0/16")
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    monkeypatch.setattr(security, "fail2ban_available", lambda: True)
    import wpfy.events as events

    monkeypatch.setattr(
        security,
        "_fixture_pipeline_proof",
        lambda _domain, append_event=False: (False, ["filter did not match the fixture event"]),
    )

    result = security.set_fail2ban(domain, True)

    assert result.exit_code != 0
    assert "proof" in result.message
    assert security.load_security(domain)["fail2ban"] is False
    assert not security.fail2ban_jail_path().exists()
    assert any(e["action"] == "login_shield.health_failed" for e in events.list_events(domain=domain))


def test_fixture_pipeline_proof_fails_closed_on_oversized_chain(security_modules, monkeypatch):
    """B1 companion pin: an enabled mark is impossible while the site's chain
    name would exceed the iptables 28-char limit — the proof fails closed, so
    'enabled recorded while enforcement impossible' can never happen."""
    layout, security = security_modules
    domain = "security.example.com"
    _site(layout, domain)
    monkeypatch.setattr(security, "_fail2ban_jail_name", lambda _domain: "x" * 25)

    ok, errors = security._fixture_pipeline_proof(domain, append_event=False)

    assert ok is False
    assert any("chain" in error for error in errors)


def test_fail2ban_enable_idempotent_repeat(security_modules, monkeypatch):
    layout, security = security_modules
    domain = "security.example.com"
    _site(layout, domain)
    monkeypatch.setenv("WPFY_TEST_TRAEFIK_NETWORK_CIDRS", "172.18.0.0/16")
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    monkeypatch.setattr(security, "fail2ban_available", lambda: True)
    from wpfy.site_event_pipeline import auth_log_path

    first = security.set_fail2ban(domain, True)
    second = security.set_fail2ban(domain, True)
    log_text = auth_log_path(domain).read_text(encoding="utf-8")

    assert first.exit_code == second.exit_code == 0
    assert "already enabled" in second.message
    # W7: the controlled fixture event is pruned after the proof, so the live
    # auth log stays bounded and status never counts fixture noise. A repeat
    # enable appends nothing at all.
    assert log_text.count("wordpress_auth_failure") == 0


def test_fail2ban_disable_keeps_log_and_removes_only_this_jail(security_modules, monkeypatch):
    layout, security = security_modules
    kept = "keep-jail.example.com"
    dropped = "drop-jail.example.com"
    _site(layout, kept)
    _site(layout, dropped)
    monkeypatch.setenv("WPFY_TEST_TRAEFIK_NETWORK_CIDRS", "172.18.0.0/16")
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    monkeypatch.setattr(security, "fail2ban_available", lambda: True)
    from wpfy.site_event_pipeline import auth_log_path

    assert security.set_fail2ban(kept, True).exit_code == 0
    assert security.set_fail2ban(dropped, True).exit_code == 0
    log_before = auth_log_path(dropped).read_text(encoding="utf-8")
    assert security.set_fail2ban(dropped, False).exit_code == 0

    jail_text = security.fail2ban_jail_path().read_text(encoding="utf-8")
    assert f"[{security._fail2ban_jail_name(dropped)}]" not in jail_text
    assert f"[{security._fail2ban_jail_name(kept)}]" in jail_text
    # Logs preserved per retention policy.
    assert auth_log_path(dropped).exists()
    assert auth_log_path(dropped).read_text(encoding="utf-8") == log_before


def test_fail2ban_bridge_guard_tracks_state(security_modules, monkeypatch):
    layout, security = security_modules
    domain = "security.example.com"
    _site(layout, domain)
    monkeypatch.setenv("WPFY_TEST_TRAEFIK_NETWORK_CIDRS", "172.18.0.0/16")
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    monkeypatch.setattr(security, "fail2ban_available", lambda: True)
    from wpfy.site_event_pipeline import bridge_path

    assert security.set_fail2ban(domain, True).exit_code == 0
    assert "WPFY_SHIELD_ENABLED', true" in bridge_path(domain).read_text(encoding="utf-8")
    assert security.set_fail2ban(domain, False).exit_code == 0
    assert "WPFY_SHIELD_ENABLED', false" in bridge_path(domain).read_text(encoding="utf-8")


def test_login_shield_status_includes_ban_scope_and_integration(security_modules, monkeypatch):
    layout, security = security_modules
    domain = "security.example.com"
    _site(layout, domain)
    monkeypatch.setenv("WPFY_TEST_TRAEFIK_NETWORK_CIDRS", "172.18.0.0/16")
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    monkeypatch.setattr(security, "fail2ban_available", lambda: True)

    before = security.login_shield_status(domain)
    assert before["enabled"] is False
    assert "all websites on this WPFY server" in before["ban_scope"]

    assert security.set_fail2ban(domain, True).exit_code == 0
    status = security.login_shield_status(domain)
    assert status["enabled"] is True
    assert status["jail_name"] == security._fail2ban_jail_name(domain)
    assert status["event_log_path"].endswith("wp-auth.log")
    assert "Only enabled sites can trigger Login Shield bans" in status["ban_scope"]


def test_fail2ban_enable_uses_site_mutation_lock(security_modules, monkeypatch):
    layout, security = security_modules
    domain = "security.example.com"
    _site(layout, domain)
    monkeypatch.setenv("WPFY_TEST_TRAEFIK_NETWORK_CIDRS", "172.18.0.0/16")
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    monkeypatch.setattr(security, "fail2ban_available", lambda: True)
    import hashlib
    from pathlib import Path
    import wpfy.settings

    assert security.set_fail2ban(domain, True).exit_code == 0
    digest = hashlib.sha256(domain.encode("utf-8")).hexdigest()[:16]
    lock = Path(wpfy.settings.PATHS.state_dir) / "site-mutation-locks" / f"{digest}.lock"
    assert lock.exists()


def test_repair_login_shield_restores_missing_jail(security_modules, monkeypatch):
    layout, security = security_modules
    domain = "security.example.com"
    _site(layout, domain)
    monkeypatch.setenv("WPFY_TEST_TRAEFIK_NETWORK_CIDRS", "172.18.0.0/16")
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    monkeypatch.setattr(security, "fail2ban_available", lambda: True)
    import wpfy.events as events

    assert security.set_fail2ban(domain, True).exit_code == 0
    security.fail2ban_jail_path().unlink()

    repaired = security.repair_login_shield(domain)

    assert repaired.exit_code == 0
    assert repaired.changed is True
    assert security.fail2ban_jail_path().exists()
    assert any(e["action"] == "login_shield.repaired" for e in events.list_events(domain=domain))

    noop = security.repair_login_shield(domain)
    assert noop.exit_code == 0 and noop.changed is False


# ---------------------------------------------------------------------------
# t15: reset / unban / host repair / host test / status additions
# ---------------------------------------------------------------------------


def test_reset_login_shield_disabled_site_is_noop(security_modules, monkeypatch):
    layout, security = security_modules
    domain = "security.example.com"
    _site(layout, domain)
    monkeypatch.setenv("WPFY_TEST_TRAEFIK_NETWORK_CIDRS", "172.18.0.0/16")
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    monkeypatch.setattr(security, "fail2ban_available", lambda: True)

    result = security.reset_login_shield(domain)

    assert result.exit_code == 0
    assert "nothing to reset" in result.message
    assert security.load_security(domain)["fail2ban"] is False


def test_reset_login_shield_rebuilds_config_keeps_enabled(security_modules, monkeypatch):
    layout, security = security_modules
    domain = "security.example.com"
    _site(layout, domain)
    monkeypatch.setenv("WPFY_TEST_TRAEFIK_NETWORK_CIDRS", "172.18.0.0/16")
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    monkeypatch.setattr(security, "fail2ban_available", lambda: True)

    assert security.set_fail2ban(domain, True).exit_code == 0
    jail_name = security._fail2ban_jail_name(domain)
    assert f"[{jail_name}]" in security.fail2ban_jail_path().read_text(encoding="utf-8")

    result = security.reset_login_shield(domain)

    assert result.exit_code == 0
    assert result.changed is True
    # Never permanently disables protection: state stays enabled and the
    # site's jail is re-rendered (not removed).
    assert security.load_security(domain)["fail2ban"] is True
    jail_text = security.fail2ban_jail_path().read_text(encoding="utf-8")
    assert f"[{jail_name}]" in jail_text
    assert "rebuilt" in result.message


def test_reset_login_shield_reports_cleared_bans(security_modules, monkeypatch):
    layout, security = security_modules
    domain = "security.example.com"
    _site(layout, domain)
    monkeypatch.setenv("WPFY_TEST_TRAEFIK_NETWORK_CIDRS", "172.18.0.0/16")
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    monkeypatch.setattr(security, "fail2ban_available", lambda: True)
    assert security.set_fail2ban(domain, True).exit_code == 0
    monkeypatch.setattr(security, "_clear_jail_bans", lambda jail: 3)

    result = security.reset_login_shield(domain)

    assert result.exit_code == 0
    assert "cleared 3 ban(s)" in result.message


def test_clear_jail_bans_parses_status_and_unbans_each(monkeypatch):
    import wpfy.site_security as security

    calls = []

    def fake_run(cmd, **kwargs):
        if cmd[:2] == ["fail2ban-client", "status"]:
            return FakeProc(
                0,
                "Status for the jail: wpfy-abc\n"
                "|- Filter\n"
                "|  |- Currently failed: 3\n"
                "`- Actions\n"
                "   |- Currently banned: 2\n"
                "   |- Total banned: 5\n"
                "   `- Banned IP list:   203.0.113.9 198.51.100.7\n",
            )
        calls.append(cmd)
        return FakeProc(0)

    monkeypatch.delenv("WPFY_SKIP_RUNTIME", raising=False)
    monkeypatch.setattr(security, "fail2ban_available", lambda: True)
    monkeypatch.setattr(security.subprocess, "run", fake_run)

    assert security._clear_jail_bans("wpfy-abc") == 2
    assert calls == [
        ["fail2ban-client", "set", "wpfy-abc", "unbanip", "203.0.113.9"],
        ["fail2ban-client", "set", "wpfy-abc", "unbanip", "198.51.100.7"],
    ]


def test_clear_jail_bans_parses_ipv6_banned_ips(monkeypatch):
    """t16 W4 pin: IPv6 banned IPs contain ':' and must not truncate the
    parse — neither inline nor on a wrapped continuation line."""
    import wpfy.site_security as security

    calls = []

    def fake_run(cmd, **kwargs):
        if cmd[:2] == ["fail2ban-client", "status"]:
            return FakeProc(
                0,
                "Status for the jail: wpfy-abc\n"
                "`- Actions\n"
                "   |- Currently banned: 3\n"
                "   |- Total banned: 3\n"
                "   `- Banned IP list:   2001:db8::1\n"
                "   2001:db8::5 203.0.113.9\n",
            )
        calls.append(cmd)
        return FakeProc(0)

    monkeypatch.delenv("WPFY_SKIP_RUNTIME", raising=False)
    monkeypatch.setattr(security, "fail2ban_available", lambda: True)
    monkeypatch.setattr(security.subprocess, "run", fake_run)

    assert security._clear_jail_bans("wpfy-abc") == 3
    assert calls == [
        ["fail2ban-client", "set", "wpfy-abc", "unbanip", "2001:db8::1"],
        ["fail2ban-client", "set", "wpfy-abc", "unbanip", "2001:db8::5"],
        ["fail2ban-client", "set", "wpfy-abc", "unbanip", "203.0.113.9"],
    ]


def test_runtime_subprocess_calls_carry_bounded_timeout(monkeypatch):
    """t16 W3 residual pin: every host subprocess call in site_security is
    bounded by _SUBPROCESS_TIMEOUT_SECONDS so a stuck xtables/dpkg/service
    lock cannot hang enable/status/reset forever. Timeout surfaces as a
    TimeoutExpired failure path, never an unhandled hang."""
    import wpfy.site_security as security

    seen = []

    def fake_run(cmd, **kwargs):
        seen.append((tuple(cmd), kwargs.get("timeout")))
        return FakeProc(0)

    monkeypatch.delenv("WPFY_SKIP_RUNTIME", raising=False)
    monkeypatch.setattr(security, "fail2ban_available", lambda: True)
    monkeypatch.setattr(security.subprocess, "run", fake_run)

    security._reload_fail2ban()
    security._validate_fail2ban()
    security._fail2ban_ping()
    security._config_validation_status()
    security._recent_bans("wpfy-abc")
    security._clear_jail_bans("wpfy-abc")
    security.unban_fail2ban("203.0.113.9")

    assert seen, "expected runtime subprocess calls"
    timeout_values = {timeout for _, timeout in seen}
    assert timeout_values == {security._SUBPROCESS_TIMEOUT_SECONDS}, (
        f"every runtime subprocess call must carry the bounded timeout: {seen}"
    )


def test_htpasswd_hash_communicate_is_timeout_bounded(monkeypatch):
    """t16 W3 residual pin: the openssl Popen communicate carries the same
    bounded timeout; a hang raises a clear RuntimeError instead of blocking."""
    import wpfy.site_security as security

    class OpenSSL:
        returncode = 0
        _raised = False

        def kill(self):
            return None

        def communicate(self, password="", timeout=None):
            if not self._raised:
                self._raised = True
                raise subprocess.TimeoutExpired(["openssl"], 1)
            return "", ""

    def fake_popen(*args, **kwargs):
        return OpenSSL()

    monkeypatch.setattr(security.subprocess, "Popen", fake_popen)
    with pytest.raises(RuntimeError, match="timed out"):
        security._htpasswd_hash("secret")


def test_login_shield_status_plugin_live_state(security_modules, monkeypatch):
    """t16 W8 pin: status reports the plugin's live wp-cli state, not a stale
    recorded flag; an out-of-band deactivation degrades health."""
    layout, security = security_modules
    domain = "security.example.com"
    _site(layout, domain)
    monkeypatch.setenv("WPFY_TEST_TRAEFIK_NETWORK_CIDRS", "172.18.0.0/16")
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    monkeypatch.setattr(security, "fail2ban_available", lambda: True)
    assert security.set_fail2ban(domain, True).exit_code == 0

    import wpfy.plugin_install as plugin_install

    monkeypatch.setattr(
        plugin_install, "plugin_live_state", lambda _domain: {"active": False, "version": "5.4.1"}
    )
    status = security.login_shield_status(domain)
    assert status["plugin"]["active"] is False
    assert status["plugin_active_source"] == "live"
    assert status["health"] == "degraded"
    assert "plugin not active" in (status["degraded_reason"] or "")

    monkeypatch.setattr(
        plugin_install, "plugin_live_state", lambda _domain: {"active": True, "version": "5.4.1"}
    )
    status = security.login_shield_status(domain)
    assert status["plugin"]["active"] is True
    assert status["plugin_active_source"] == "live"
    assert status["health"] == "ok"


def test_login_shield_status_plugin_falls_back_to_recorded_when_runtime_skipped(
    security_modules, monkeypatch,
):
    """t16 W8: under WPFY_SKIP_RUNTIME the live probe is unavailable; status
    reports the recorded flag with source=recorded (bounded staleness)."""
    layout, security = security_modules
    domain = "security.example.com"
    _site(layout, domain)
    monkeypatch.setenv("WPFY_TEST_TRAEFIK_NETWORK_CIDRS", "172.18.0.0/16")
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    monkeypatch.setattr(security, "fail2ban_available", lambda: True)
    assert security.set_fail2ban(domain, True).exit_code == 0

    status = security.login_shield_status(domain)
    assert status["plugin_active_source"] == "recorded"
    assert isinstance(status["plugin"]["active"], bool)


def test_unban_fail2ban_rejects_invalid_ip(security_modules, monkeypatch):
    layout, security = security_modules
    result = security.unban_fail2ban("not-an-ip")
    assert result.exit_code == 2
    assert "invalid IP" in result.message


def test_unban_fail2ban_clears_wpfy_jails_and_emits_event(security_modules, monkeypatch):
    layout, security = security_modules
    domain = "security.example.com"
    _site(layout, domain)
    monkeypatch.setenv("WPFY_TEST_TRAEFIK_NETWORK_CIDRS", "172.18.0.0/16")
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    monkeypatch.setattr(security, "fail2ban_available", lambda: True)
    assert security.set_fail2ban(domain, True).exit_code == 0
    monkeypatch.delenv("WPFY_SKIP_RUNTIME")
    import wpfy.events as events

    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return FakeProc(0)

    monkeypatch.setattr(security.subprocess, "run", fake_run)

    result = security.unban_fail2ban("203.0.113.9")

    assert result.exit_code == 0
    assert result.changed is True
    jail_name = security._fail2ban_jail_name(domain)
    assert ["fail2ban-client", "set", "wpfy-panel-auth", "unbanip", "203.0.113.9"] in calls
    assert ["fail2ban-client", "set", jail_name, "unbanip", "203.0.113.9"] in calls
    assert any(e["action"] == "login_shield.unban" for e in events.list_events())


def test_unban_fail2ban_runtime_skipped_noop(security_modules, monkeypatch):
    layout, security = security_modules
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    result = security.unban_fail2ban("203.0.113.9")
    assert result.exit_code == 0
    assert "skipped" in result.message


def test_repair_host_login_shield_idempotent_and_emits_event(security_modules, monkeypatch):
    layout, security = security_modules
    from wpfy.fail2ban_host import HostFail2banResult
    import wpfy.events as events

    monkeypatch.setattr(
        "wpfy.fail2ban_host.ensure_fail2ban_host",
        lambda: HostFail2banResult(0, "fail2ban healthy", installed=True, health_ok=True),
    )
    monkeypatch.setattr(security, "_validate_fail2ban", lambda: None)
    monkeypatch.setattr(security, "_reload_fail2ban", lambda: None)

    first = security.repair_host_login_shield()
    second = security.repair_host_login_shield()

    assert first.exit_code == 0
    assert second.exit_code == 0
    assert any(e["action"] == "login_shield.repaired" for e in events.list_events())


def test_repair_host_login_shield_rolls_back_on_validate_failure(security_modules, monkeypatch):
    layout, security = security_modules
    from wpfy.fail2ban_host import HostFail2banResult
    import wpfy.events as events

    monkeypatch.setattr(
        "wpfy.fail2ban_host.ensure_fail2ban_host",
        lambda: HostFail2banResult(0, "fail2ban healthy", installed=True, health_ok=True),
    )
    monkeypatch.setattr(security, "_validate_fail2ban", lambda: "broken jail config")
    monkeypatch.setattr(security, "_reload_fail2ban", lambda: None)

    result = security.repair_host_login_shield()

    assert result.exit_code == 3
    assert "validation" in result.message
    assert any(e["action"] == "login_shield.health_failed" for e in events.list_events())
    assert not any(e["action"] == "login_shield.repaired" for e in events.list_events())


def test_repair_host_login_shield_surfaces_ensure_failure(security_modules, monkeypatch):
    layout, security = security_modules
    from wpfy.fail2ban_host import HostFail2banResult

    monkeypatch.setattr(
        "wpfy.fail2ban_host.ensure_fail2ban_host",
        lambda: HostFail2banResult(3, "apt install failed", installed=False, health_ok=False),
    )
    result = security.repair_host_login_shield()
    assert result.exit_code == 3
    assert "apt install failed" in result.message


def test_test_host_login_shield_fixture_matches(security_modules, monkeypatch):
    layout, security = security_modules
    monkeypatch.setenv("WPFY_TEST_TRAEFIK_NETWORK_CIDRS", "172.18.0.0/16")
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    monkeypatch.setattr(security, "fail2ban_available", lambda: True)

    result = security.test_host_login_shield()

    assert result.exit_code == 0
    assert "panel filter matched" in result.message
    assert "wordpress auth filter matched" in result.message
    assert "panel jail active" in result.message


def test_host_fail2ban_status_reports_panel_jail(security_modules, monkeypatch):
    layout, security = security_modules
    monkeypatch.setenv("WPFY_TEST_TRAEFIK_NETWORK_CIDRS", "172.18.0.0/16")
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    monkeypatch.setattr(security, "fail2ban_available", lambda: True)

    status = security.host_fail2ban_status()

    assert status["jail_name"] == "wpfy-panel-auth"
    assert "panel-auth.log" in status["event_log_path"]
    assert status["ban_scope"] == security.BAN_SCOPE_MESSAGE
    assert status["wpfy_chain_attached"] is True
    assert "recent_bans" in status
    assert "health" in status


def test_host_fail2ban_status_degraded_when_action_stale(security_modules, monkeypatch):
    layout, security = security_modules
    monkeypatch.setenv("WPFY_TEST_TRAEFIK_NETWORK_CIDRS", "172.18.0.0/16")
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    monkeypatch.setattr(security, "fail2ban_available", lambda: True)
    import importlib
    from wpfy import fail2ban_docker

    importlib.reload(fail2ban_docker)
    fail2ban_docker.install_action(chain="f2b-wpfy-panel-auth", ipv6=False)
    monkeypatch.setenv("WPFY_TEST_IPV6_CAPABLE", "1")
    importlib.reload(fail2ban_docker)

    status = security.host_fail2ban_status()

    assert status["health"] == "degraded"
    assert "re-render" in status["degraded_reason"]


def test_login_shield_status_degraded_when_action_stale(security_modules, monkeypatch):
    layout, security = security_modules
    domain = "security.example.com"
    _site(layout, domain)
    monkeypatch.setenv("WPFY_TEST_TRAEFIK_NETWORK_CIDRS", "172.18.0.0/16")
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    monkeypatch.setattr(security, "fail2ban_available", lambda: True)
    import importlib
    from wpfy import fail2ban_docker

    chain = security._fail2ban_chain_name(security._fail2ban_jail_name(domain))
    importlib.reload(fail2ban_docker)
    fail2ban_docker.install_action(chain=chain, ipv6=False)
    monkeypatch.setenv("WPFY_TEST_IPV6_CAPABLE", "1")
    importlib.reload(fail2ban_docker)

    status = security.login_shield_status(domain)

    assert status["health"] == "degraded"
    assert "re-render" in status["degraded_reason"]
    assert status["action_stale"] is True


def test_login_shield_status_reports_explicit_chain_and_recent_bans(security_modules, monkeypatch):
    layout, security = security_modules
    domain = "security.example.com"
    _site(layout, domain)
    monkeypatch.setenv("WPFY_TEST_TRAEFIK_NETWORK_CIDRS", "172.18.0.0/16")
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    monkeypatch.setattr(security, "fail2ban_available", lambda: True)

    status = security.login_shield_status(domain)

    # Wave-5 LOW finding: the explicit per-site chain is probed and reported
    # (never the default f2b-wpfy-http); under runtime skip the probe assumes
    # attachment so active jails never read False.
    assert status["wpfy_chain_attached"] is True
    assert "recent_bans" in status
    assert "total_bans" in status
    assert "health" in status


def test_recent_bans_parses_fail2ban_status(monkeypatch):
    import wpfy.site_security as security

    monkeypatch.delenv("WPFY_SKIP_RUNTIME", raising=False)
    monkeypatch.setattr(security, "fail2ban_available", lambda: True)

    def fake_run(cmd, **kwargs):
        return FakeProc(
            0,
            "Status for the jail: wpfy-abc\n"
            "|- Filter\n"
            "|  |- Currently failed: 3\n"
            "`- Actions\n"
            "   |- Currently banned: 2\n"
            "   |- Total banned: 5\n"
            "   `- Banned IP list:   203.0.113.9\n",
        )

    monkeypatch.setattr(security.subprocess, "run", fake_run)
    assert security._recent_bans("wpfy-abc") == (2, 5)
