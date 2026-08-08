"""Two-site Login Shield enable/disable lifecycle tests (t13, Phase 12 WordPress
items, fixture-level).

FIXTURE-LEVEL contract: these tests prove the enable/disable orchestration,
state isolation, event mapping, and the event -> log -> filter -> jail pipeline
using generated fixture records and regex semantics. They do NOT prove real
enforcement (an attacker reaching a DOCKER-USER REJECT rule); that live,
gated verification runs at t21 against a real host.

Disable is deliberate: the shared WPFY WordPress jail file must contain only
the enabled site's per-site jail; the disabled site must not generate auth
events (bridge guard off) and its failures must never enter a WPFY jail.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

import wpfy.site_security as security
import wpfy.site_layout as layout
from wpfy import fail2ban_host, plugin_install
from wpfy.site_event_pipeline import auth_log_path, bridge_path
from wpfy.site_runtime import ProcessResult
from tests.fail2ban_harness import compile_failregex, extract_fid


@pytest.fixture
def shield_env(tmp_wpfy_home, monkeypatch):
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    monkeypatch.setenv("WPFY_TEST_TRAEFIK_NETWORK_CIDRS", "172.18.0.0/16")
    # Tests run offline: fake the fail2ban-client binary availability (the
    # reload/validate helpers still no-op via WPFY_SKIP_RUNTIME).
    monkeypatch.setattr(security, "fail2ban_available", lambda: True)
    return security, layout


def _site(layout, domain="shield-a.example.com"):
    layout.ensure_site_scaffold(
        layout.SiteSpec(domain=domain, flavor="wp", use_mysql=True, use_redis=False),
    )
    return layout.site_dir(domain)


def _seed_ownership(domain, *, ownership, active=False):
    config = security.load_security(domain)
    config["fail2ban_plugin"] = {
        "slug": "wp-fail2ban",
        "version": "5.4.1",
        "ownership": ownership,
        "auto_updates_disabled": False,
        "active": active,
    }
    security.save_security(domain, config)


class FakeWpCli:
    """Recording wp-cli stand-in for plugin ownership assertions."""

    def __init__(self, *, installed=False, active=False):
        self.calls: list[tuple[str, tuple[str, ...]]] = []
        self.installed = installed
        self.active = active

    def __call__(self, domain, *args, **kwargs):
        self.calls.append((domain, args))
        command = list(args)
        if command[:2] == ["plugin", "get"]:
            if not self.installed:
                return ProcessResult(1, stderr="Error: Plugin 'wp-fail2ban' not found.")
            field = command[-1]
            if field == "--field=status":
                return ProcessResult(0, stdout="active\n" if self.active else "inactive\n")
            if field == "--field=version":
                return ProcessResult(0, stdout="5.4.1\n")
            return ProcessResult(0, stdout="")
        if command[:2] == ["plugin", "deactivate"]:
            self.active = False
            return ProcessResult(0, stdout="Plugin 'wp-fail2ban' deactivated.")
        return ProcessResult(0, stdout="ok")


class RecordingInstall:
    """Records which domains received an install/deactivate call."""

    def __init__(self, *, ownership="wpfy-installed"):
        self.installs: list[str] = []
        self.deactivates: list[str] = []
        self.ownership = ownership

    def install(self, domain):
        self.installs.append(domain)
        _seed_ownership(domain, ownership=self.ownership, active=True)
        return plugin_install.PluginInstallResult(0, "installed", changed=True, ownership=self.ownership)

    def deactivate(self, domain):
        self.deactivates.append(domain)
        return plugin_install.PluginInstallResult(0, "deactivated", changed=True, ownership=self.ownership)


def _enable_with_recording_plugin(monkeypatch, domain, *, ownership="wpfy-installed"):
    recorder = RecordingInstall(ownership=ownership)
    monkeypatch.setattr(plugin_install, "install_wp_fail2ban", recorder.install)
    monkeypatch.setattr(plugin_install, "deactivate_wp_fail2ban", recorder.deactivate)
    result = security.set_fail2ban(domain, True)
    assert result.exit_code == 0, result.message
    return recorder


def _shared_jail_text() -> str:
    return security.fail2ban_jail_path().read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Phase 12 WordPress tests (fixture-level)
# ---------------------------------------------------------------------------


def test_both_sites_begin_disabled_by_default(shield_env):
    _security, layout = shield_env
    _site(layout, "shield-a.example.com")
    _site(layout, "shield-b.example.com")

    state_a = security.load_security("shield-a.example.com")
    state_b = security.load_security("shield-b.example.com")
    assert state_a["fail2ban"] is False
    assert state_b["fail2ban"] is False
    assert not security.fail2ban_jail_path().exists()
    assert "WPFY_SHIELD_ENABLED', false" in bridge_path("shield-a.example.com").read_text(encoding="utf-8")
    assert "WPFY_SHIELD_ENABLED', false" in bridge_path("shield-b.example.com").read_text(encoding="utf-8")


def test_enabling_site_a_changes_only_site_a(shield_env, monkeypatch):
    _security, layout = shield_env
    site_b = _site(layout, "shield-b.example.com")
    _site(layout, "shield-a.example.com")
    _enable_with_recording_plugin(monkeypatch, "shield-a.example.com")

    state_b = security.load_security("shield-b.example.com")
    assert state_b["fail2ban"] is False
    assert state_b["fail2ban_plugin"]["ownership"] is None
    assert not (site_b / security.SECURITY_STATE).exists()
    jail_text = _shared_jail_text()
    assert f"[{security._fail2ban_jail_name('shield-a.example.com')}]" in jail_text
    assert f"[{security._fail2ban_jail_name('shield-b.example.com')}]" not in jail_text
    assert "WPFY_SHIELD_ENABLED', false" in bridge_path("shield-b.example.com").read_text(encoding="utf-8")


def test_wp_fail2ban_installs_only_in_site_a(shield_env, monkeypatch):
    _security, layout = shield_env
    _site(layout, "shield-a.example.com")
    _site(layout, "shield-b.example.com")

    recorder = _enable_with_recording_plugin(monkeypatch, "shield-a.example.com")

    assert recorder.installs == ["shield-a.example.com"]
    assert recorder.deactivates == []
    state_a = security.load_security("shield-a.example.com")
    assert state_a["fail2ban_plugin"]["ownership"] == "wpfy-installed"
    assert security.load_security("shield-b.example.com")["fail2ban_plugin"]["ownership"] is None


def test_admin_plugin_ownership_preserved_on_disable(shield_env, monkeypatch):
    _security, layout = shield_env
    domain = "shield-a.example.com"
    _site(layout, domain)
    _seed_ownership(domain, ownership="admin-installed", active=True)
    fake = FakeWpCli(installed=True, active=True)
    monkeypatch.setattr(plugin_install, "run_wp_cli", fake)

    result = security.set_fail2ban(domain, False)

    assert result.exit_code == 0
    assert all("deactivate" not in args for _, args in fake.calls)
    state = security.load_security(domain)
    assert state["fail2ban_plugin"]["ownership"] == "admin-installed"
    assert state["fail2ban_plugin"]["active"] is True


def test_site_b_login_failure_does_not_enter_wpfy_jail(shield_env, monkeypatch):
    _security, layout = shield_env
    _site(layout, "shield-a.example.com")
    _site(layout, "shield-b.example.com")
    _enable_with_recording_plugin(monkeypatch, "shield-a.example.com")

    # A fixture-level failure on Site B (disabled) has no per-site jail to enter.
    b_log = auth_log_path("shield-b.example.com")
    b_record = json.dumps({
        "timestamp": "2026-08-06T12:00:00Z",
        "event": "wordpress_auth_failure",
        "site": "shield-b.example.com",
        "surface": "wp_login",
        "client_ip": "203.0.113.55",
        "account_hash": "1" * 64,
        "reason_class": "hard",
    }, ensure_ascii=True, separators=(",", ":"))
    b_log.write_text(b_record + "\n", encoding="utf-8")

    jail_text = _shared_jail_text()
    assert f"[{security._fail2ban_jail_name('shield-b.example.com')}]" not in jail_text
    assert str(b_log) not in jail_text
    # The bridge on B is guard-off: B generates no WPFY auth events.
    assert "WPFY_SHIELD_ENABLED', false" in bridge_path("shield-b.example.com").read_text(encoding="utf-8")


def test_site_a_fixture_proof_is_bounded_and_log_clean(shield_env, monkeypatch):
    _security, layout = shield_env
    _site(layout, "shield-a.example.com")
    _enable_with_recording_plugin(monkeypatch, "shield-a.example.com")

    a_log = auth_log_path("shield-a.example.com")
    lines = [line for line in a_log.read_text(encoding="utf-8").splitlines() if line.strip()]
    # W7: the controlled fixture is pruned after the proof, so the live log
    # stays bounded and status never counts fixture noise.
    assert lines == []

    # The proof contract still holds: the strict filter matches the fixture
    # record and the jail references this site's event log.
    compiled = compile_failregex(fail2ban_host.wordpress_auth_failregex())
    record = json.dumps({
        "timestamp": "2026-08-06T12:00:00Z",
        "event": "wordpress_auth_failure",
        "site": "shield-a.example.com",
        "surface": "wp_login",
        "client_ip": "203.0.113.9",
        "account_hash": "0" * 64,
        "reason_class": "soft",
    }, ensure_ascii=True, separators=(",", ":"))
    match = compiled.match(record)
    assert match is not None
    assert extract_fid(match) == "203.0.113.9"
    jail_text = _shared_jail_text()
    assert f"[{security._fail2ban_jail_name('shield-a.example.com')}]" in jail_text
    assert str(a_log) in jail_text


def test_repeated_enable_disable_are_idempotent(shield_env, monkeypatch):
    _security, layout = shield_env
    domain = "shield-a.example.com"
    _site(layout, domain)
    recorder = RecordingInstall()
    monkeypatch.setattr(plugin_install, "install_wp_fail2ban", recorder.install)
    monkeypatch.setattr(plugin_install, "deactivate_wp_fail2ban", recorder.deactivate)

    assert security.set_fail2ban(domain, True).exit_code == 0
    assert security.set_fail2ban(domain, True).exit_code == 0
    assert security.set_fail2ban(domain, False).exit_code == 0
    assert security.set_fail2ban(domain, False).exit_code == 0

    assert recorder.installs == [domain]
    assert recorder.deactivates == [domain]
    assert security.load_security(domain)["fail2ban"] is False
    assert not security.fail2ban_jail_path().exists()


def test_malformed_state_on_site_b_does_not_break_lifecycle(shield_env, monkeypatch):
    _security, layout = shield_env
    domain_a = "shield-a.example.com"
    domain_b = "shield-b.example.com"
    site_b = _site(layout, domain_b)
    _site(layout, domain_a)
    (site_b / security.SECURITY_STATE).write_text("{not-json", encoding="utf-8")

    _enable_with_recording_plugin(monkeypatch, domain_a)
    result = security.set_fail2ban(domain_a, False)

    assert result.exit_code == 0
    assert "corrupt" in result.message
    assert security.load_security(domain_a)["fail2ban"] is False
    # Site B remains untouched and its corrupt state does not break site A.
    assert (site_b / security.SECURITY_STATE).read_text(encoding="utf-8") == "{not-json"


def test_container_recreation_preserves_state_driven_integration(shield_env, monkeypatch):
    _security, layout = shield_env
    domain = "shield-a.example.com"
    _site(layout, domain)
    _enable_with_recording_plugin(monkeypatch, domain)

    compose = layout.compose_content(
        layout.SiteSpec.from_env(domain, layout.read_env(layout.env_path(domain))),
    )
    assert "./security/wp-auth.log:/var/log/wpfy/wp-auth.log" in compose
    assert f"./security/{plugin_install.STAGING_SUBDIR}" in compose or "./security:" in compose
    assert bridge_path(domain).is_file()

    # Simulate `wpfy refresh`: scaffold re-runs and re-renders the bridge from
    # persisted state (still enabled).
    layout.ensure_site_scaffold(
        layout.SiteSpec.from_env(domain, layout.read_env(layout.env_path(domain))),
    )
    assert "WPFY_SHIELD_ENABLED', true" in bridge_path(domain).read_text(encoding="utf-8")

    assert security.set_fail2ban(domain, False).exit_code == 0
    layout.ensure_site_scaffold(
        layout.SiteSpec.from_env(domain, layout.read_env(layout.env_path(domain))),
    )
    assert "WPFY_SHIELD_ENABLED', false" in bridge_path(domain).read_text(encoding="utf-8")


def test_auth_failure_surfaces_all_match_filter(shield_env):
    _security, layout = shield_env
    compiled = compile_failregex(fail2ban_host.wordpress_auth_failregex())
    surfaces = ("wp_login", "xmlrpc", "rest", "password_reset", "user_enum", "app_password")
    for surface in surfaces:
        record = json.dumps({
            "timestamp": "2026-08-06T12:00:00Z",
            "event": "wordpress_auth_failure",
            "site": "shield-a.example.com",
            "surface": surface,
            "client_ip": "198.51.100.7",
            "account_hash": "2" * 64,
            "reason_class": "hard" if surface != "wp_login" else "soft",
        }, ensure_ascii=True, separators=(",", ":"))
        match = compiled.match(record)
        assert match is not None, surface
        assert extract_fid(match) == "198.51.100.7"


def test_per_site_jail_single_logpath_only_wp_auth(shield_env, monkeypatch):
    """Blocker 2 pin: after enable the per-site jail renders exactly one
    logpath key = the strict wp-auth.log; the coarse nginx access log is not
    tailed by the jail (fail2ban 1.0.2 rejects dual logpath at reload)."""
    _security, layout = shield_env
    _site(layout, "shield-a.example.com")
    _enable_with_recording_plugin(monkeypatch, "shield-a.example.com")

    jail_text = _shared_jail_text()
    logpath_lines = [
        line for line in jail_text.splitlines() if line.lstrip().startswith("logpath")
    ]
    assert len(logpath_lines) == 1
    assert str(auth_log_path("shield-a.example.com")) in logpath_lines[0]
    assert "wpfy-access.log" not in logpath_lines[0]


def test_disabling_site_a_removes_only_site_a_integration(shield_env, monkeypatch):
    _security, layout = shield_env
    _site(layout, "shield-a.example.com")
    _site(layout, "shield-b.example.com")
    recorder = RecordingInstall()
    monkeypatch.setattr(plugin_install, "install_wp_fail2ban", recorder.install)
    monkeypatch.setattr(plugin_install, "deactivate_wp_fail2ban", recorder.deactivate)

    assert security.set_fail2ban("shield-a.example.com", True).exit_code == 0
    assert security.set_fail2ban("shield-b.example.com", True).exit_code == 0
    assert security.set_fail2ban("shield-a.example.com", False).exit_code == 0

    jail_text = _shared_jail_text()
    assert f"[{security._fail2ban_jail_name('shield-a.example.com')}]" not in jail_text
    assert f"[{security._fail2ban_jail_name('shield-b.example.com')}]" in jail_text
    assert recorder.deactivates == ["shield-a.example.com"]
    # Shared filter file stays while Site B still uses it (combined filter
    # carries the strict event regex).
    assert security.fail2ban_filter_path().exists()
    filter_text = security.fail2ban_filter_path().read_text(encoding="utf-8")
    assert 'event":"wordpress_auth_failure"' in filter_text
    # A's event log is preserved (retention) but its bridge is guard-off.
    assert auth_log_path("shield-a.example.com").exists()
    assert "WPFY_SHIELD_ENABLED', false" in bridge_path("shield-a.example.com").read_text(encoding="utf-8")


def test_bridge_writes_only_auth_events_no_options_transients(shield_env):
    _security, _layout = shield_env
    content = plugin_install  # ensure import; bridge content lives in pipeline
    from wpfy.site_event_pipeline import bridge_content

    text = bridge_content("shield-a.example.com", enabled=True)
    for api in ("add_option", "update_option", "add_site_option", "update_site_option",
                "set_transient", "set_site_transient", "get_transient"):
        assert api not in text, f"bridge must not call {api}"
    assert text.count("file_put_contents") == 1
    assert "add_action" in text or "add_filter" in text
    assert "add_action( 'application_password_failed_authentication'" in text


def test_wp_cli_remains_functional_no_unbounded_writes(shield_env, monkeypatch):
    _security, layout = shield_env
    domain = "shield-a.example.com"
    _site(layout, domain)
    fake = FakeWpCli(installed=True, active=True)
    monkeypatch.setattr(plugin_install, "run_wp_cli", fake)

    assert security.set_fail2ban(domain, True).exit_code == 0
    assert security.set_fail2ban(domain, False).exit_code == 0

    # Only plugin lifecycle commands ran; no per-request WP-CLI churn.
    assert fake.calls
    for seen_domain, args in fake.calls:
        assert seen_domain == domain
        assert args[0] == "plugin"
    log = auth_log_path(domain)
    assert log.exists()
    # W7: fixture lines are pruned after the proof; the auth log stays bounded.
    assert log.read_text(encoding="utf-8").count("wordpress_auth_failure") == 0
