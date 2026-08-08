"""CLI surface tests for the Login Shield Phase 7 commands (t15).

Covers the t14a decision surface exactly:

- Host-level: ``wpfy security fail2ban status|repair|test|unban <ip>``
- Per-site: ``wpfy site security <domain> fail2ban status|reset`` (on|off preserved)
- Parser conflict check (``security`` vs ``secure`` vs ``site security``)
- Privilege gate for unban and reset (root/wrapper required)
- Status rendering (all lifecycle-status-schema fields + degraded health)
"""

from __future__ import annotations

import pytest

from wpfy.cli import build_parser, run


# ---------------------------------------------------------------------------
# Parser surface (t14a decision)
# ---------------------------------------------------------------------------


def test_security_fail2ban_parser_status():
    args = build_parser().parse_args(["security", "fail2ban", "status"])
    assert args.command == "security"
    assert args.security_group == "fail2ban"
    assert args.fail2ban_command == "status"


def test_security_fail2ban_parser_repair_and_test():
    parser = build_parser()
    repair = parser.parse_args(["security", "fail2ban", "repair"])
    assert repair.fail2ban_command == "repair"
    test = parser.parse_args(["security", "fail2ban", "test"])
    assert test.fail2ban_command == "test"


def test_security_fail2ban_parser_unban():
    args = build_parser().parse_args(["security", "fail2ban", "unban", "203.0.113.9"])
    assert args.fail2ban_command == "unban"
    assert args.ip == "203.0.113.9"


def test_site_security_fail2ban_status_reset_and_on_off_parsers():
    parser = build_parser()
    status = parser.parse_args(["site", "security", "example.com", "fail2ban", "status"])
    assert status.security_command == "fail2ban"
    assert status.security_action == "status"
    reset = parser.parse_args(["site", "security", "example.com", "fail2ban", "reset"])
    assert reset.security_action == "reset"
    on = parser.parse_args(["site", "security", "example.com", "fail2ban", "on"])
    assert on.security_action == "on"
    off = parser.parse_args(["site", "security", "example.com", "fail2ban", "off"])
    assert off.security_action == "off"


def test_security_parser_has_no_conflict_with_secure():
    """security (new host group), secure (audit), site security are distinct."""
    parser = build_parser()
    top_choices = next(
        action.choices
        for action in parser._actions
        if hasattr(action, "choices") and action.choices
    )
    assert "security" in top_choices
    assert "secure" in top_choices
    # host and per-site namespaces are disjoint: same token string 'fail2ban
    # status' under different parents resolves to different handlers/dests.
    host = parser.parse_args(["security", "fail2ban", "status"])
    site = parser.parse_args(["site", "security", "example.com", "fail2ban", "status"])
    assert host.fail2ban_command == "status"
    assert not hasattr(host, "security_command")
    assert site.security_command == "fail2ban"
    assert site.security_action == "status"


# ---------------------------------------------------------------------------
# Status rendering
# ---------------------------------------------------------------------------

_SITE_STATUS = {
    "site": "example.com",
    "enabled": True,
    "plugin": {
        "slug": "wp-fail2ban",
        "version": "5.4.1",
        "ownership": "wpfy-installed",
        "auto_updates_disabled": True,
        "active": True,
    },
    "host_fail2ban_installed": True,
    "host_fail2ban_health": "ok",
    "jail_name": "wpfy-abc123",
    "jail_active": True,
    "event_log_path": "/tmp/wp-auth.log",
    "event_log_health": "ok",
    "filter_name": "wpfy-wordpress",
    "last_detected_failure": "2026-08-06T12:00:00Z",
    "recent_matched_failures": 3,
    "recent_bans": 1,
    "total_bans": 4,
    "ban_scope": (
        "Only enabled sites can trigger Login Shield bans. A resulting HTTP "
        "ban may block the attacker from all websites on this WPFY server."
    ),
    "trusted_proxy_health": "edge-trust-configured",
    "ipv4_protection": True,
    "ipv6_protection": False,
    "config_validation": "valid",
    "wpfy_chain_attached": True,
    "action_stale": False,
    "degraded_reason": None,
    "health": "ok",
}


def test_site_fail2ban_status_renders_all_fields(monkeypatch, capsys):
    import wpfy.cli as cli

    monkeypatch.setattr(cli.site_security, "login_shield_status", lambda domain: _SITE_STATUS)

    assert run(["site", "security", "example.com", "fail2ban", "status"]) == 0
    out = capsys.readouterr().out
    assert "Site: example.com" in out
    assert "Login Shield: enabled" in out
    assert "WP fail2ban installed: wp-fail2ban" in out
    assert "WP fail2ban active: True" in out
    assert "WP fail2ban ownership: wpfy-installed" in out
    assert "Host Fail2ban installed: True" in out
    assert "Host Fail2ban service health: ok" in out
    assert "Relevant jail: wpfy-abc123" in out
    assert "Jail active: True" in out
    assert "Event log path: /tmp/wp-auth.log" in out
    assert "Event log health: ok" in out
    assert "Last detected authentication failure: 2026-08-06T12:00:00Z" in out
    assert "Recent matched failures: 3" in out
    assert "Recent bans: 1" in out
    assert "Ban scope:" in out
    assert "all websites on this WPFY server" in out
    assert "Trusted proxy health: edge-trust-configured" in out
    assert "IPv4 protection: active" in out
    assert "IPv6 protection: inactive" in out
    assert "Configuration validation: valid" in out
    assert "Health: ok" in out


def test_status_renders_degraded_health_with_reason(monkeypatch, capsys):
    import wpfy.cli as cli

    status = dict(_SITE_STATUS)
    status.update({
        "enabled": True,
        "last_detected_failure": None,
        "recent_matched_failures": 0,
        "recent_bans": None,
        "action_stale": True,
        "degraded_reason": (
            "action stale: IPv6 capable but action rendered without IPv6 "
            "support; re-render required"
        ),
        "health": "degraded",
    })
    monkeypatch.setattr(cli.site_security, "login_shield_status", lambda domain: status)

    assert run(["site", "security", "example.com", "fail2ban", "status"]) == 0
    out = capsys.readouterr().out
    assert "Health: degraded" in out
    assert "re-render required" in out
    assert "Recent bans: unknown" in out


def test_security_status_handler_renders_host_fields(monkeypatch, capsys):
    import wpfy.cli as cli

    host_status = dict(_SITE_STATUS)
    host_status.update({
        "site": None,
        "plugin": {},
        "jail_name": "wpfy-panel-auth",
        "event_log_path": "/var/log/wpfy/panel-auth.log",
        "filter_name": "wpfy-panel-auth",
    })
    monkeypatch.setattr(cli.site_security, "host_fail2ban_status", lambda: host_status)

    assert run(["security", "fail2ban", "status"]) == 0
    out = capsys.readouterr().out
    assert "Host fail2ban status" in out
    assert "Relevant jail: wpfy-panel-auth" in out
    assert "panel-auth.log" in out
    assert "WP fail2ban installed: no" in out


# ---------------------------------------------------------------------------
# Privilege gate: unban + reset require root/wrapper
# ---------------------------------------------------------------------------


def test_site_fail2ban_reset_requires_privilege(monkeypatch, capsys):
    import wpfy.cli as cli

    monkeypatch.setattr(cli, "_privileged_cli", lambda: False)
    assert run(["site", "security", "example.com", "fail2ban", "reset"]) == 2
    assert "privileged" in capsys.readouterr().out


def test_site_fail2ban_reset_privileged_invokes_operation(monkeypatch, capsys):
    import wpfy.cli as cli

    called = []
    monkeypatch.setattr(cli, "_privileged_cli", lambda: True)
    monkeypatch.setattr(
        cli.site_security,
        "reset_login_shield",
        lambda domain: called.append(domain) or cli.site_security.SecurityResult(0, "reset ok", True),
    )
    assert run(["site", "security", "example.com", "fail2ban", "reset"]) == 0
    assert called == ["example.com"]
    assert "reset ok" in capsys.readouterr().out


def test_security_unban_requires_privilege(monkeypatch, capsys):
    import wpfy.cli as cli

    monkeypatch.setattr(cli, "_privileged_cli", lambda: False)
    assert run(["security", "fail2ban", "unban", "203.0.113.9"]) == 2
    assert "privileged" in capsys.readouterr().out


def test_security_unban_privileged_invokes_operation(monkeypatch, capsys):
    import wpfy.cli as cli

    called = []
    monkeypatch.setattr(cli, "_privileged_cli", lambda: True)
    monkeypatch.setattr(
        cli.site_security,
        "unban_fail2ban",
        lambda ip: called.append(ip) or cli.site_security.SecurityResult(0, "unbanned 203.0.113.9", True),
    )
    assert run(["security", "fail2ban", "unban", "203.0.113.9"]) == 0
    assert called == ["203.0.113.9"]


# ---------------------------------------------------------------------------
# repair + test handlers
# ---------------------------------------------------------------------------


def test_security_repair_handler(monkeypatch, capsys):
    import wpfy.cli as cli

    monkeypatch.setattr(
        cli.site_security,
        "repair_host_login_shield",
        lambda: cli.site_security.SecurityResult(0, "host fail2ban repaired", True),
    )
    assert run(["security", "fail2ban", "repair"]) == 0
    assert "repaired" in capsys.readouterr().out


def test_security_repair_handler_propagates_failure(monkeypatch, capsys):
    import wpfy.cli as cli

    monkeypatch.setattr(
        cli.site_security,
        "repair_host_login_shield",
        lambda: cli.site_security.SecurityResult(3, "host fail2ban repair failed; reload: nope"),
    )
    assert run(["security", "fail2ban", "repair"]) == 3
    assert "reload: nope" in capsys.readouterr().out


def test_security_test_handler(monkeypatch, capsys):
    import wpfy.cli as cli

    monkeypatch.setattr(
        cli.site_security,
        "test_host_login_shield",
        lambda: cli.site_security.SecurityResult(0, "login shield test passed: panel filter matched"),
    )
    assert run(["security", "fail2ban", "test"]) == 0
    assert "panel filter matched" in capsys.readouterr().out
