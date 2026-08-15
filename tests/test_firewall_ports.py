"""Port management: parsing, validation, and the two lockout guards.

Every test here runs without ufw installed. That is the point: the guards have
to hold on a laptop, in CI, and on a host where `ufw` was never installed, not
only where a real firewall can answer back.
"""

from __future__ import annotations

import pytest

from wpfy import firewall_ports


STATUS_VERBOSE = """Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
80/tcp                     ALLOW IN    Anywhere
443/tcp                    ALLOW IN    Anywhere
3306/tcp                   ALLOW IN    203.0.113.4                # office only
2222:2299/tcp              ALLOW IN    Anywhere
6379/tcp                   DENY IN     Anywhere
OpenSSH                    ALLOW IN    Anywhere
22/tcp (v6)                ALLOW IN    Anywhere (v6)
"""


def test_parse_status_reads_defaults_and_rules():
    state = firewall_ports.parse_status(STATUS_VERBOSE)
    assert state.active is True
    assert state.default_incoming == "deny"
    assert state.default_outgoing == "allow"
    ports = [(rule.port, rule.protocol, rule.action, rule.v6) for rule in state.rules]
    assert ("22", "tcp", "allow", False) in ports
    assert ("6379", "tcp", "deny", False) in ports
    assert ("2222:2299", "tcp", "allow", False) in ports


def test_parse_status_folds_the_ipv6_twin_into_one_row():
    """ufw prints an IPv6 twin for every anywhere-rule; the operator wrote one rule.

    Listing both gives two rows with two delete buttons where deleting either
    removes both -- a description of the rule set that does not match it.
    """
    state = firewall_ports.parse_status(STATUS_VERBOSE)
    ssh = [rule for rule in state.rules if rule.port == "22"]
    assert len(ssh) == 1
    assert ssh[0].v6 is False


def test_parse_status_keeps_a_rule_that_is_only_ipv6():
    """`v6` surviving means IPv6-only, which is worth saying; a twin is not."""
    state = firewall_ports.parse_status(
        "Status: active\n\nTo    Action  From\n--    ------  ----\n"
        "9090/tcp (v6)              ALLOW IN    Anywhere (v6)\n"
    )
    assert [(rule.port, rule.v6) for rule in state.rules] == [("9090", True)]


def test_parse_status_keeps_the_source_restriction():
    """A rule scoped to one address is not the same rule as one open to the world.

    Rendering `3306/tcp ALLOW` without its `From` column tells the operator
    their database is exposed when it is not -- or, read the other way, hides
    that a restriction they think exists was never applied.
    """
    state = firewall_ports.parse_status(STATUS_VERBOSE)
    mysql = next(rule for rule in state.rules if rule.port == "3306")
    assert mysql.source == "203.0.113.4"


def test_parse_status_splits_the_comment_out_of_the_source():
    """ufw prints the comment inside the `From` column, padded with spaces.

    Left glued to the source it is rendered as part of the address and, worse,
    sent back as `source` when the rule is deleted -- where it is rejected as a
    malformed address, so the rule cannot be removed from the panel at all.
    """
    state = firewall_ports.parse_status(STATUS_VERBOSE)
    mysql = next(rule for rule in state.rules if rule.port == "3306")
    assert mysql.source == "203.0.113.4"
    assert mysql.comment == "office only"
    firewall_ports.validate_source(mysql.source)  # the delete path must accept it


def test_parse_status_folds_twins_that_carry_a_comment():
    """The comment is padded to a different width on the v6 row.

    Comparing the raw `From` column makes the twins look like different rules,
    which is exactly how the duplicate rows survived the first fix.
    """
    state = firewall_ports.parse_status(
        "Status: active\n\nTo    Action  From\n--    ------  ----\n"
        "51820/udp                  ALLOW IN    Anywhere                   # wpfy validation\n"
        "51820/udp (v6)             ALLOW IN    Anywhere (v6)              # wpfy validation\n"
    )
    assert len(state.rules) == 1
    assert state.rules[0].comment == "wpfy validation"


def test_parse_added_keeps_the_comment():
    rules = firewall_ports.parse_added(SHOW_ADDED)
    assert rules[0].comment == "wpfy ssh lockout guard"
    assert rules[2].comment == ""


def test_parse_status_skips_named_application_profiles():
    """`OpenSSH` is a profile name, not a port; a numeric parse of it is a lie."""
    state = firewall_ports.parse_status(STATUS_VERBOSE)
    assert all(rule.port != "OpenSSH" for rule in state.rules)


def test_parse_status_reports_inactive():
    state = firewall_ports.parse_status("Status: inactive\n")
    assert state.active is False
    assert state.rules == ()


# Captured verbatim from `ufw show added` on Ubuntu 24.04 (ufw 0.36.2) after
# adding the rules through this module -- ufw normalises anywhere-rules to the
# shorthand and keeps the long form only when a source is set.
SHOW_ADDED = """Added user rules (see 'ufw status' for running firewall):
ufw allow 22/tcp comment 'wpfy ssh lockout guard'
ufw allow from 203.0.113.0/24 to any port 8080 proto tcp comment 'src test'
ufw allow 9000:9010/tcp
ufw deny 3306/tcp comment 'db'
ufw allow OpenSSH
"""


def test_port_allowed_answers_from_the_rule_set(monkeypatch):
    monkeypatch.setattr(firewall_ports, "ufw_available", lambda: True)
    monkeypatch.setattr(firewall_ports, "_run", lambda args: (0, STATUS_VERBOSE))
    assert firewall_ports.port_allowed(443) is True
    assert firewall_ports.port_allowed(2250) is True, "a range must cover the ports inside it"
    assert firewall_ports.port_allowed(3939) is False
    assert firewall_ports.port_allowed(6379) is False, "a deny rule is not an allow"


def test_port_allowed_is_none_when_nothing_was_read(monkeypatch):
    """Found on the validation VPS: the panel is a host process, so an active ufw
    blackholes it while the Docker-published ports sail past ufw untouched.

    The caller warns the operator their port is closed, so "we never looked" has
    to be distinguishable from "it is closed" -- otherwise a host without ufw
    gets told its firewall is blocking the panel.
    """
    monkeypatch.setattr(firewall_ports, "ufw_available", lambda: False)
    assert firewall_ports.port_allowed(3939) is None


def test_port_allowed_is_true_while_the_firewall_is_off(monkeypatch):
    monkeypatch.setattr(firewall_ports, "ufw_available", lambda: True)
    monkeypatch.setattr(firewall_ports, "_run", lambda args: (0, "Status: inactive\n"))
    assert firewall_ports.port_allowed(3939) is True


def test_parse_added_reads_both_grammars():
    rules = firewall_ports.parse_added(SHOW_ADDED)
    assert [(r.port, r.protocol, r.action, r.source) for r in rules] == [
        ("22", "tcp", "allow", "Anywhere"),
        ("8080", "tcp", "allow", "203.0.113.0/24"),
        ("9000:9010", "tcp", "allow", "Anywhere"),
        ("3306", "tcp", "deny", "Anywhere"),
    ]


def test_parse_added_skips_named_application_profiles():
    assert all(rule.port != "OpenSSH" for rule in firewall_ports.parse_added(SHOW_ADDED))


def test_status_lists_rules_while_the_firewall_is_off(monkeypatch):
    """An inactive ufw prints no rule list at all, and the rules still exist.

    Reporting an empty set there is wrong twice: the rules apply the moment the
    firewall comes up, and an operator shown "no rules" adds the port a second
    time, so enabling it installs duplicates nobody asked for.
    """
    calls: list[list[str]] = []

    def fake_run(args):
        calls.append(args)
        return (0, "Status: inactive\n" if args[0] == "status" else SHOW_ADDED)

    monkeypatch.setattr(firewall_ports, "ufw_available", lambda: True)
    monkeypatch.setattr(firewall_ports, "_run", fake_run)
    state = firewall_ports.status()
    assert state.active is False
    assert [rule.port for rule in state.rules] == ["22", "8080", "9000:9010", "3306"]
    assert ["show", "added"] in calls


def test_status_does_not_ask_for_added_rules_while_active(monkeypatch):
    """`status verbose` is the truth when the firewall is up -- it says what applies."""
    calls: list[list[str]] = []

    def fake_run(args):
        calls.append(args)
        return (0, STATUS_VERBOSE)

    monkeypatch.setattr(firewall_ports, "ufw_available", lambda: True)
    monkeypatch.setattr(firewall_ports, "_run", fake_run)
    assert firewall_ports.status().active is True
    assert calls == [["status", "verbose"]]


@pytest.mark.parametrize("value,expected", [
    ("22", "22"), ("2200:2210", "2200:2210"), (" 443 ", "443"), ("65535", "65535"),
])
def test_validate_port_accepts_ports_and_ranges(value, expected):
    assert firewall_ports.validate_port(value) == expected


@pytest.mark.parametrize("value", ["0", "65536", "-1", "22:21", "22/tcp", "", "; rm -rf /", "abc", "1:2:3"])
def test_validate_port_rejects_everything_else(value):
    with pytest.raises(ValueError):
        firewall_ports.validate_port(value)


@pytest.mark.parametrize("value", ["sctp", "TCPP", "", None, "tcp; ufw disable"])
def test_validate_protocol_rejects_everything_but_tcp_and_udp(value):
    with pytest.raises(ValueError):
        firewall_ports.validate_protocol(value)


def test_validate_source_normalises_and_rejects():
    assert firewall_ports.validate_source("203.0.113.0/24") == "203.0.113.0/24"
    assert firewall_ports.validate_source("203.0.113.4") == "203.0.113.4/32"
    assert firewall_ports.validate_source("  ") is None
    with pytest.raises(ValueError):
        firewall_ports.validate_source("not-an-address")


def test_validate_comment_rejects_shell_and_flag_characters():
    assert firewall_ports.validate_comment("wpfy api") == "wpfy api"
    for value in ["`id`", "a$b", "--force", "x\ny", "'q'"]:
        with pytest.raises(ValueError):
            firewall_ports.validate_comment(value)


def test_ssh_port_reads_sshd_config(tmp_path, monkeypatch):
    config = tmp_path / "sshd_config"
    config.write_text("#Port 22\nPort 2202\nPermitRootLogin no\n", encoding="utf-8")
    monkeypatch.setenv("WPFY_SSHD_CONFIG", str(config))
    assert firewall_ports.ssh_port() == 2202


def test_ssh_port_falls_back_to_22_when_unreadable(tmp_path, monkeypatch):
    monkeypatch.setenv("WPFY_SSHD_CONFIG", str(tmp_path / "missing"))
    assert firewall_ports.ssh_port() == firewall_ports.DEFAULT_SSH_PORT


def test_ssh_port_ignores_a_commented_directive(tmp_path, monkeypatch):
    config = tmp_path / "sshd_config"
    config.write_text("#Port 2202\n", encoding="utf-8")
    monkeypatch.setenv("WPFY_SSHD_CONFIG", str(config))
    assert firewall_ports.ssh_port() == 22


def _record_commands(monkeypatch) -> list[list[str]]:
    """Pretend ufw is installed and record what would have been run."""
    calls: list[list[str]] = []

    def fake_run(args):
        calls.append(list(args))
        return 0, "ok"

    monkeypatch.setattr(firewall_ports, "ufw_available", lambda: True)
    monkeypatch.setattr(firewall_ports, "_run", fake_run)
    monkeypatch.delenv("WPFY_SKIP_RUNTIME", raising=False)
    return calls


def test_deny_refuses_the_ssh_port_without_confirmation(monkeypatch):
    """The panel is reached over SSH's connection; denying it is unrecoverable."""
    calls = _record_commands(monkeypatch)
    result = firewall_ports.deny_port("22", "tcp")
    assert result.exit_code != 0
    assert "SSH" in result.message
    assert calls == [], "the guard must refuse before ufw is invoked, not after"


def test_deny_refuses_a_range_that_swallows_the_ssh_port(monkeypatch):
    """A range is the quiet way to lose SSH: nobody reads `20:30` as `22`."""
    calls = _record_commands(monkeypatch)
    result = firewall_ports.deny_port("20:30", "tcp")
    assert result.exit_code != 0
    assert calls == []


def test_deny_follows_a_moved_ssh_port(tmp_path, monkeypatch):
    """Guarding 22 on a host that moved sshd to 2202 guards nothing."""
    config = tmp_path / "sshd_config"
    config.write_text("Port 2202\n", encoding="utf-8")
    monkeypatch.setenv("WPFY_SSHD_CONFIG", str(config))
    calls = _record_commands(monkeypatch)

    assert firewall_ports.deny_port("2202", "tcp").exit_code != 0
    assert calls == []
    assert firewall_ports.deny_port("22", "tcp").exit_code == 0


def test_deny_proceeds_when_forced(monkeypatch):
    calls = _record_commands(monkeypatch)
    result = firewall_ports.deny_port("22", "tcp", force=True)
    assert result.exit_code == 0
    assert calls and calls[0][0] == "deny"


def test_delete_refuses_to_remove_the_ssh_allow_rule(monkeypatch):
    calls = _record_commands(monkeypatch)
    result = firewall_ports.delete_rule("22", "tcp", "allow")
    assert result.exit_code != 0
    assert calls == []


def test_delete_of_a_deny_rule_is_not_guarded(monkeypatch):
    """Removing a *deny* on the SSH port restores access; blocking it would be
    the guard working against the operator it exists to protect."""
    calls = _record_commands(monkeypatch)
    assert firewall_ports.delete_rule("22", "tcp", "deny").exit_code == 0
    assert calls and calls[0][:2] == ["delete", "deny"]


def test_enable_allows_ssh_before_it_turns_the_firewall_on(monkeypatch):
    """Ordering is the whole guard.

    `ufw enable` applies default-deny the instant it runs. An SSH rule added
    afterwards arrives over a connection the enable already dropped.
    """
    calls = _record_commands(monkeypatch)
    result = firewall_ports.enable()
    assert result.exit_code == 0
    assert len(calls) == 2
    assert calls[0][0] == "allow" and "22" in calls[0]
    assert calls[1] == ["--force", "enable"]


def test_enable_aborts_when_the_ssh_rule_cannot_be_added(monkeypatch):
    """If the reservation fails, enabling would lock the operator out."""
    monkeypatch.setattr(firewall_ports, "ufw_available", lambda: True)
    monkeypatch.delenv("WPFY_SKIP_RUNTIME", raising=False)
    calls: list[list[str]] = []

    def fake_run(args):
        calls.append(list(args))
        return (1, "permission denied") if args[0] == "allow" else (0, "ok")

    monkeypatch.setattr(firewall_ports, "_run", fake_run)
    result = firewall_ports.enable()
    assert result.exit_code != 0
    assert "refusing to enable" in result.message
    assert ["--force", "enable"] not in calls


def test_mutations_report_a_missing_ufw_instead_of_installing_it(monkeypatch):
    monkeypatch.setattr(firewall_ports, "ufw_available", lambda: False)
    for result in (
        firewall_ports.allow_port("80", "tcp"),
        firewall_ports.enable(),
        firewall_ports.disable(),
    ):
        assert result.exit_code != 0
        assert "not installed" in result.message


def test_status_without_ufw_is_a_reported_state_not_an_error(monkeypatch):
    monkeypatch.setattr(firewall_ports, "ufw_available", lambda: False)
    state = firewall_ports.status()
    assert state.installed is False
    assert state.active is False
    assert "apt-get install" in state.message


def test_delete_uses_the_same_spec_grammar_as_add(monkeypatch):
    """`ufw delete` matches on rule text.

    A delete written in a different shorthand than the add matches nothing and
    still exits 0, so the panel would report a rule removed that is still live.
    """
    calls = _record_commands(monkeypatch)
    firewall_ports.allow_port("8080", "tcp", source="203.0.113.0/24")
    firewall_ports.delete_rule("8080", "tcp", "allow", source="203.0.113.0/24")
    assert calls[0][1:] == calls[1][2:]


def test_status_marks_an_unread_probe_as_unchecked(monkeypatch):
    """`active=False` from a probe that never ran is not the same as "off".

    A caller that renders the two identically tells the operator their firewall
    is disabled when the panel simply did not look.
    """
    monkeypatch.setattr(firewall_ports, "ufw_available", lambda: False)
    assert firewall_ports.status().checked is False

    monkeypatch.setattr(firewall_ports, "ufw_available", lambda: True)
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    assert firewall_ports.status().checked is False

    monkeypatch.delenv("WPFY_SKIP_RUNTIME", raising=False)
    monkeypatch.setattr(firewall_ports, "_run", lambda args: (1, "permission denied"))
    assert firewall_ports.status().checked is False


def test_status_marks_a_real_read_as_checked(monkeypatch):
    monkeypatch.setattr(firewall_ports, "ufw_available", lambda: True)
    monkeypatch.delenv("WPFY_SKIP_RUNTIME", raising=False)
    monkeypatch.setattr(firewall_ports, "_run", lambda args: (0, STATUS_VERBOSE))
    state = firewall_ports.status()
    assert state.checked is True
    assert state.active is True
