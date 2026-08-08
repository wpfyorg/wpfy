"""Tests for wpfy.fail2ban_docker — Docker-aware Fail2ban action module.

Covers the Phase 12 "Docker action tests" items 1-10 from the Login Shield
plan (login-shield-plan.md):

 1. Action creates only WPFY-owned chain
 2. Rule attached to DOCKER-USER
 3. Ports 80/443 blocked (assert generated iptables args)
 4. SSH untouched
 5. Unban restores
 6. Multiple jails ban/unban safely
 7. Fail2ban restart restores chain
 8. Existing rules preserved
 9. iptables-nft compatibility (plain iptables/ip6tables binaries)
10. No INPUT dependency
"""

from __future__ import annotations

import importlib
import os
import re

import pytest


@pytest.fixture
def docker_module(tmp_wpfy_home, monkeypatch):
    """Reload fail2ban_docker with test env vars active."""
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    import wpfy.fail2ban_docker

    importlib.reload(wpfy.fail2ban_docker)
    return wpfy.fail2ban_docker


# ---------------------------------------------------------------------------
# 1. Action creates only WPFY-owned chain
# ---------------------------------------------------------------------------


def test_actionstart_creates_wpfy_chain(docker_module):
    """actionstart creates the WPFY chain via iptables -N."""
    content = docker_module.action_content(chain="f2b-wpfy-test", ipv6=False)
    assert "iptables -w -N f2b-wpfy-test" in content


def test_actionstart_does_not_create_unrelated_chains(docker_module):
    """actionstart only creates the named WPFY chain, nothing else."""
    content = docker_module.action_content(chain="f2b-wpfy-test", ipv6=False)
    # Scope to actionstart section only (actioncheck also has -N for repair)
    start_section = content.split("actionstart")[1].split("actionstop")[0]
    creates = re.findall(r"iptables -w -N (\S+)", start_section)
    assert creates == ["f2b-wpfy-test"]


# ---------------------------------------------------------------------------
# 2. Rule attached to DOCKER-USER
# ---------------------------------------------------------------------------


def test_actionstart_attaches_to_docker_user(docker_module):
    """actionstart inserts the WPFY chain jump into DOCKER-USER."""
    content = docker_module.action_content(chain="f2b-wpfy-test", ipv6=False)
    assert "iptables -w -I DOCKER-USER 1 -j f2b-wpfy-test" in content


def test_actionstart_checks_before_insert(docker_module):
    """Attach is guarded by iptables -C DOCKER-USER check."""
    content = docker_module.action_content(chain="f2b-wpfy-test", ipv6=False)
    assert "iptables -w -C DOCKER-USER -j f2b-wpfy-test" in content


def test_actioncheck_repairs_attachment(docker_module):
    """actioncheck re-verifies and re-attaches the chain if needed."""
    content = docker_module.action_content(chain="f2b-wpfy-test", ipv6=False)
    check_section = content.split("actioncheck")[1].split("actionban")[0]
    assert "iptables -w -C DOCKER-USER -j f2b-wpfy-test" in check_section
    assert "iptables -w -I DOCKER-USER 1 -j f2b-wpfy-test" in check_section


# ---------------------------------------------------------------------------
# 3. Ports 80/443 blocked
# ---------------------------------------------------------------------------


def test_ban_blocks_ports_80_and_443(docker_module):
    """actionban uses multiport --dports 80,443."""
    content = docker_module.action_content(chain="f2b-wpfy-test", ipv6=False)
    assert "--dports 80,443" in content


def test_ban_uses_tcp_protocol(docker_module):
    """actionban specifies -p tcp."""
    content = docker_module.action_content(chain="f2b-wpfy-test", ipv6=False)
    ban_line = [
        line for line in content.splitlines() if line.strip().startswith("actionban")
    ]
    assert len(ban_line) == 1
    assert "-p tcp" in ban_line[0]


def test_ban_uses_reject_target(docker_module):
    """actionban rejects with icmp-port-unreachable."""
    content = docker_module.action_content(chain="f2b-wpfy-test", ipv6=False)
    assert "REJECT --reject-with icmp-port-unreachable" in content


# ---------------------------------------------------------------------------
# 4. SSH untouched
# ---------------------------------------------------------------------------


def test_ssh_port_never_referenced(docker_module):
    """Port 22 never appears in any iptables command."""
    content = docker_module.action_content(chain="f2b-wpfy-test", ipv6=False)
    assert "--dports 22" not in content
    assert "--dport 22" not in content
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        assert "ssh" not in stripped.lower(), f"SSH referenced: {stripped}"


# ---------------------------------------------------------------------------
# 5. Unban restores
# ---------------------------------------------------------------------------


def test_unban_removes_matching_rule(docker_module):
    """actionunban deletes the exact ban rule from the WPFY chain."""
    content = docker_module.action_content(chain="f2b-wpfy-test", ipv6=False)
    unban_line = [
        line for line in content.splitlines() if line.strip().startswith("actionunban")
    ]
    assert len(unban_line) == 1
    assert "iptables -w -D f2b-wpfy-test" in unban_line[0]
    assert "--dports 80,443" in unban_line[0]
    assert "-s <ip>" in unban_line[0]


def test_unban_is_safe_on_missing_rule(docker_module):
    """actionunban swallows errors (2>/dev/null || true)."""
    content = docker_module.action_content(chain="f2b-wpfy-test", ipv6=False)
    unban_line = [
        line for line in content.splitlines() if line.strip().startswith("actionunban")
    ]
    assert "2>/dev/null || true" in unban_line[0]


# ---------------------------------------------------------------------------
# 6. Multiple jails ban/unban safely
# ---------------------------------------------------------------------------


def test_ban_uses_jail_name_comment(docker_module):
    """Ban rule carries a per-jail comment tag for safe multi-jail use."""
    content = docker_module.action_content(chain="f2b-wpfy-<name>", ipv6=False)
    assert 'comment --comment "f2b-wpfy-<name>"' in content


def test_unban_matches_jail_name_comment(docker_module):
    """Unban rule matches the same per-jail comment tag."""
    content = docker_module.action_content(chain="f2b-wpfy-<name>", ipv6=False)
    unban_line = [
        line for line in content.splitlines() if line.strip().startswith("actionunban")
    ]
    assert 'comment --comment "f2b-wpfy-<name>"' in unban_line[0]


def test_multiple_jails_share_chain_without_conflict(docker_module):
    """Two jails with different names produce distinct ban comments."""
    content_a = docker_module.action_content(chain="f2b-wpfy-jailA", ipv6=False)
    content_b = docker_module.action_content(chain="f2b-wpfy-jailB", ipv6=False)
    assert "f2b-wpfy-jailA" in content_a
    assert "f2b-wpfy-jailB" in content_b
    assert "f2b-wpfy-jailB" not in content_a
    assert "f2b-wpfy-jailA" not in content_b


# ---------------------------------------------------------------------------
# 7. Fail2ban restart restores chain
# ---------------------------------------------------------------------------


def test_actionstart_idempotent_on_reload(docker_module):
    """actionstart uses -N with 2>/dev/null || true — safe on reload."""
    content = docker_module.action_content(chain="f2b-wpfy-test", ipv6=False)
    start_section = content.split("actionstart")[1].split("actionstop")[0]
    assert "iptables -w -N f2b-wpfy-test 2>/dev/null || true" in start_section


def test_actionstart_flushes_stale_rules(docker_module):
    """actionstart flushes the chain to clear stale rules from prior runs."""
    content = docker_module.action_content(chain="f2b-wpfy-test", ipv6=False)
    start_section = content.split("actionstart")[1].split("actionstop")[0]
    assert "iptables -w -F f2b-wpfy-test" in start_section


def test_actionstart_attach_is_guarded(docker_module):
    """Attach uses -C check || -I insert — no duplicate jumps."""
    content = docker_module.action_content(chain="f2b-wpfy-test", ipv6=False)
    start_section = content.split("actionstart")[1].split("actionstop")[0]
    assert (
        "iptables -w -C DOCKER-USER -j f2b-wpfy-test 2>/dev/null"
        " || iptables -w -I DOCKER-USER 1 -j f2b-wpfy-test"
    ) in start_section


# ---------------------------------------------------------------------------
# 8. Existing rules preserved
# ---------------------------------------------------------------------------


def test_no_flush_of_docker_user_chain(docker_module):
    """DOCKER-USER chain is never flushed — only the WPFY chain is."""
    content = docker_module.action_content(chain="f2b-wpfy-test", ipv6=False)
    assert "iptables -w -F DOCKER-USER" not in content
    # WPFY chain IS flushed (safe — it's our chain)
    assert "iptables -w -F f2b-wpfy-test" in content


def test_actionstop_preserves_chain_when_rules_remain(docker_module):
    """actionstop only removes the chain when rule_count <= 1 (empty)."""
    content = docker_module.action_content(chain="f2b-wpfy-test", ipv6=False)
    stop_section = content.split("actionstop")[1].split("actioncheck")[0]
    assert "rule_count" in stop_section
    assert '-le 1' in stop_section
    # Delete and remove are inside the conditional
    assert "iptables -w -D DOCKER-USER -j f2b-wpfy-test" in stop_section
    assert "iptables -w -X f2b-wpfy-test" in stop_section


def test_no_delete_of_unrelated_rules(docker_module):
    """No -D commands target DOCKER-USER rules outside the WPFY jump."""
    content = docker_module.action_content(chain="f2b-wpfy-test", ipv6=False)
    # The only -D targeting DOCKER-USER is the jump removal
    docker_user_deletes = re.findall(
        r"iptables -w -D DOCKER-USER[^\n]*", content
    )
    for rule in docker_user_deletes:
        assert "f2b-wpfy-test" in rule


# ---------------------------------------------------------------------------
# 9. iptables-nft compatibility
# ---------------------------------------------------------------------------


def test_uses_plain_iptables_binary(docker_module):
    """All IPv4 commands use 'iptables' (maps to nft backend on modern Ubuntu)."""
    content = docker_module.action_content(chain="f2b-wpfy-test", ipv6=False)
    assert "iptables-nft" not in content
    assert "iptables-legacy" not in content
    assert "nft " not in content


def test_uses_plain_ip6tables_binary(docker_module):
    """All IPv6 commands use 'ip6tables' (maps to nft backend)."""
    content = docker_module.action_content(chain="f2b-wpfy-test", ipv6=True)
    assert "ip6tables-nft" not in content
    assert "ip6tables-legacy" not in content


def test_concurrent_safety_with_wait_flag(docker_module):
    """All iptables invocations use -w for xtables lock."""
    content = docker_module.action_content(chain="f2b-wpfy-test", ipv6=False)
    iptables_cmds = re.findall(r"iptables\s+(-\w+)", content)
    for flag in iptables_cmds:
        assert flag == "-w", f"iptables command missing -w flag: {flag}"


# ---------------------------------------------------------------------------
# 10. No INPUT dependency
# ---------------------------------------------------------------------------


def test_no_input_chain_reference(docker_module):
    """INPUT chain is never referenced in any command."""
    content = docker_module.action_content(chain="f2b-wpfy-test", ipv6=False)
    # Search for INPUT as a chain target (not inside a comment or word)
    assert "chain=INPUT" not in content
    # No iptables command targets INPUT
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if "iptables" in stripped:
            # INPUT should not appear as a chain argument
            assert not re.search(r"\bINPUT\b", stripped), (
                f"INPUT chain referenced: {stripped}"
            )


def test_no_input_chain_reference_ipv6(docker_module):
    """INPUT chain is never referenced even with IPv6 enabled."""
    content = docker_module.action_content(chain="f2b-wpfy-test", ipv6=True)
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if "iptables" in stripped or "ip6tables" in stripped:
            assert not re.search(r"\bINPUT\b", stripped), (
                f"INPUT chain referenced: {stripped}"
            )


# ---------------------------------------------------------------------------
# IPv6 capability detection
# ---------------------------------------------------------------------------


def test_ipv6_capable_false_when_runtime_skipped(docker_module):
    """WPFY_SKIP_RUNTIME=1 → ipv6_capable() returns False."""
    assert docker_module.ipv6_capable() is False


def test_ipv6_capable_override_true(monkeypatch, tmp_wpfy_home):
    """WPFY_TEST_IPV6_CAPABLE=1 forces True."""
    monkeypatch.setenv("WPFY_TEST_IPV6_CAPABLE", "1")
    import wpfy.fail2ban_docker

    importlib.reload(wpfy.fail2ban_docker)
    assert wpfy.fail2ban_docker.ipv6_capable() is True


def test_ipv6_capable_override_false(monkeypatch, tmp_wpfy_home):
    """WPFY_TEST_IPV6_CAPABLE=0 forces False."""
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    monkeypatch.setenv("WPFY_TEST_IPV6_CAPABLE", "0")
    import wpfy.fail2ban_docker

    importlib.reload(wpfy.fail2ban_docker)
    assert wpfy.fail2ban_docker.ipv6_capable() is False


def test_ipv6_commands_present_when_enabled(docker_module):
    """ip6tables commands appear when ipv6=True."""
    content = docker_module.action_content(chain="f2b-wpfy-test", ipv6=True)
    assert "ip6tables -w -N f2b-wpfy-test" in content
    assert "ip6tables -w -C DOCKER-USER -j f2b-wpfy-test" in content
    assert "ip6tables -w -I DOCKER-USER 1 -j f2b-wpfy-test" in content


def test_ipv6_commands_absent_when_disabled(docker_module):
    """No ip6tables commands when ipv6=False."""
    content = docker_module.action_content(chain="f2b-wpfy-test", ipv6=False)
    assert "ip6tables" not in content


# ---------------------------------------------------------------------------
# Action file path
# ---------------------------------------------------------------------------


def test_action_file_path_under_action_d(docker_module):
    """action_file_path returns <fail2ban-root>/action.d/wpfy-docker-http.conf."""
    path = docker_module.action_file_path()
    assert path.name == "wpfy-docker-http.conf"
    assert path.parent.name == "action.d"
    assert "fail2ban" in str(path)


# ---------------------------------------------------------------------------
# Managed header
# ---------------------------------------------------------------------------


def test_content_starts_with_managed_header(docker_module):
    """Rendered content begins with the managed-by-WPFY header."""
    content = docker_module.action_content(chain="f2b-wpfy-test", ipv6=False)
    assert content.startswith(docker_module.MANAGED_HEADER)


# ---------------------------------------------------------------------------
# Install action
# ---------------------------------------------------------------------------


def test_install_action_creates_file(docker_module):
    """install_action writes the action file to the correct path."""
    changed = docker_module.install_action(chain="f2b-wpfy-test", ipv6=False)
    assert changed is True
    path = docker_module.action_file_path()
    assert path.exists()
    text = path.read_text(encoding="utf-8")
    assert docker_module.MANAGED_HEADER in text
    assert "f2b-wpfy-test" in text


def test_install_action_idempotent(docker_module):
    """Second install with same content returns False (no change)."""
    docker_module.install_action(chain="f2b-wpfy-test", ipv6=False)
    changed = docker_module.install_action(chain="f2b-wpfy-test", ipv6=False)
    assert changed is False


def test_install_action_detects_change(docker_module):
    """Install with different chain name returns True (content changed)."""
    docker_module.install_action(chain="f2b-wpfy-first", ipv6=False)
    changed = docker_module.install_action(chain="f2b-wpfy-second", ipv6=False)
    assert changed is True


# ---------------------------------------------------------------------------
# Enforcement status
# ---------------------------------------------------------------------------


def test_enforcement_status_runtime_skipped(docker_module):
    """With WPFY_SKIP_RUNTIME=1, status assumes OK."""
    status = docker_module.enforcement_status(chain="f2b-wpfy-test")
    assert status.chain_name == "f2b-wpfy-test"
    assert status.ipv4_active is True
    assert status.docker_user_present is True
    assert status.wpfy_chain_attached is True
    assert status.ipv6_applicable is False
    assert status.ipv6_active is False


def test_enforcement_status_ipv6_applicable(monkeypatch, tmp_wpfy_home):
    """When WPFY_TEST_IPV6_CAPABLE=1, ipv6_applicable is True."""
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    monkeypatch.setenv("WPFY_TEST_IPV6_CAPABLE", "1")
    import wpfy.fail2ban_docker

    importlib.reload(wpfy.fail2ban_docker)
    status = wpfy.fail2ban_docker.enforcement_status(chain="f2b-wpfy-test")
    assert status.ipv6_applicable is True


# ---------------------------------------------------------------------------
# Policy constants
# ---------------------------------------------------------------------------


def test_allowlist_contains_loopback(docker_module):
    """Allowlist includes 127.0.0.0/8 and ::1."""
    assert "127.0.0.0/8" in docker_module.ALLOWLIST_IPV4
    assert "::1" in docker_module.ALLOWLIST_IPV6


# ---------------------------------------------------------------------------
# Content determinism
# ---------------------------------------------------------------------------


def test_content_is_deterministic(docker_module):
    """Same inputs produce identical output (required for install idempotency)."""
    a = docker_module.action_content(chain="f2b-wpfy-test", ipv6=False)
    b = docker_module.action_content(chain="f2b-wpfy-test", ipv6=False)
    assert a == b


def test_content_differs_with_ipv6(docker_module):
    """IPv6 enabled produces different content than disabled."""
    v4 = docker_module.action_content(chain="f2b-wpfy-test", ipv6=False)
    v6 = docker_module.action_content(chain="f2b-wpfy-test", ipv6=True)
    assert v4 != v6
    assert "ip6tables" in v6
    assert "ip6tables" not in v4


# ---------------------------------------------------------------------------
# RunResult dataclass
# ---------------------------------------------------------------------------


def test_run_result_skipped(docker_module):
    """RunResult with skipped=True has returncode 0."""
    result = docker_module.RunResult(
        returncode=0, stdout="", stderr="", skipped=True
    )
    assert result.skipped is True
    assert result.returncode == 0


# ---------------------------------------------------------------------------
# _run helper
# ---------------------------------------------------------------------------


def test_run_returns_skipped_when_runtime_disabled(docker_module):
    """_run returns skipped result when WPFY_SKIP_RUNTIME=1."""
    result = docker_module._run(["iptables", "-L"])
    assert result.skipped is True
    assert result.returncode == 0


def test_run_timeout_surfaces_returncode_124(monkeypatch, tmp_wpfy_home):
    """t16 W3 pin: iptables -w can block on the xtables lock forever; _run
    must bound the wait and surface a timeout as a non-zero failure (124),
    never as success."""
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "0")
    import importlib

    import wpfy.fail2ban_docker

    importlib.reload(wpfy.fail2ban_docker)
    result = wpfy.fail2ban_docker._run(["sleep", "2"], timeout=0.1)
    assert result.returncode == 124
    assert "timed out" in result.stderr


# ---------------------------------------------------------------------------
# Default chain name
# ---------------------------------------------------------------------------


def test_default_chain_uses_name_tag(docker_module):
    """Default chain name is f2b-wpfy-<name> for fail2ban jail-name tag."""
    content = docker_module.action_content(ipv6=False)
    assert "f2b-wpfy-<name>" in content


# ---------------------------------------------------------------------------
# Action file structure
# ---------------------------------------------------------------------------


def test_action_has_definition_section(docker_module):
    """Rendered content contains [Definition] section."""
    content = docker_module.action_content(chain="f2b-wpfy-test", ipv6=False)
    assert "[Definition]" in content


def test_action_has_all_five_actions(docker_module):
    """All five fail2ban action hooks are present."""
    content = docker_module.action_content(chain="f2b-wpfy-test", ipv6=False)
    assert "actionstart" in content
    assert "actionstop" in content
    assert "actioncheck" in content
    assert "actionban" in content
    assert "actionunban" in content


# ---------------------------------------------------------------------------
# t11: allowlist single-source consistency
# ---------------------------------------------------------------------------


def test_allowlist_single_source_consistency(docker_module):
    """ALLOWLIST_IPV4/IPV6 derive from SAFE_ALLOWLIST and never drift."""
    from wpfy.fail2ban_host import SAFE_ALLOWLIST

    assert set(SAFE_ALLOWLIST) == set(docker_module.ALLOWLIST_IPV4) | set(docker_module.ALLOWLIST_IPV6)
    assert ":" not in "".join(docker_module.ALLOWLIST_IPV4)
    assert all(":" in item for item in docker_module.ALLOWLIST_IPV6)


# ---------------------------------------------------------------------------
# t11: unique chain name validation (pin test)
# ---------------------------------------------------------------------------


def test_validate_chain_name_requires_wpfy_prefix(docker_module):
    """Chain names must be WPFY-owned (f2b-wpfy- prefix)."""
    with pytest.raises(ValueError):
        docker_module.validate_chain_name("iptables-chain")
    with pytest.raises(ValueError):
        docker_module.validate_chain_name("")
    with pytest.raises(ValueError):
        docker_module.validate_chain_name("f2b-wpfy-")


def test_two_jails_sharing_chain_name_fail_validation(docker_module):
    """Pin: shared chain name fails — actionstart would flush the WPFY chain."""
    with pytest.raises(ValueError):
        docker_module.validate_unique_chain_names(
            ["f2b-wpfy-http", "f2b-wpfy-http"]
        )
    # Distinct chains and the fail2ban <name> tag pass.
    docker_module.validate_unique_chain_names(
        ["f2b-wpfy-jailA", "f2b-wpfy-jailB"]
    )
    docker_module.validate_unique_chain_names(["f2b-wpfy-<name>"])


def test_validate_chain_name_rejects_over_28_chars(docker_module):
    """B1 pin: iptables chain names are capped at 28 chars; a longer WPFY
    chain is rejected so a silent EINVAL no-op ban can never be configured."""
    with pytest.raises(ValueError, match="28"):
        docker_module.validate_chain_name("f2b-wpfy-" + "a" * 20)  # 29 chars
    with pytest.raises(ValueError, match="28"):
        docker_module.validate_chain_name(
            "f2b-wpfy-wpfy-a379a6f6eeafb9a5"  # the historical 30-char chain
        )


def test_validate_chain_name_accepts_exactly_28_chars(docker_module):
    """B1 pin: a chain at the iptables limit is still accepted."""
    docker_module.validate_chain_name("f2b-wpfy-" + "b" * 19)  # 28 chars
    docker_module.validate_chain_name("f2b-wpfy-" + "c" * 3)  # short chains fine


def test_per_site_and_panel_chain_names_within_iptables_limit(docker_module):
    """B1 pin: every generated WPFY chain (per-site + panel) is <= 28 chars,
    valid, and unique — the exact set the jail renderer emits."""
    import hashlib

    from wpfy.fail2ban_host import PANEL_JAIL_CHAIN

    domains = ("alpha.example.com", "beta.example.com", "gamma-1.example.org")
    chains = [PANEL_JAIL_CHAIN]
    for domain in domains:
        digest = hashlib.sha256(domain.encode("utf-8")).hexdigest()[:16]
        chains.append(f"{docker_module.CHAIN_PREFIX}{digest}")
    for chain in chains:
        docker_module.validate_chain_name(chain)
        assert len(chain) <= docker_module.IPTABLES_CHAIN_MAX_LENGTH, chain
    docker_module.validate_unique_chain_names(chains)
    assert len(set(chains)) == len(chains)
    assert PANEL_JAIL_CHAIN == "f2b-wpfy-panel-auth"


def test_action_content_validates_chain_name(docker_module):
    """action_content rejects non-WPFY chain names."""
    with pytest.raises(ValueError):
        docker_module.action_content(chain="custom-chain", ipv6=False)


# ---------------------------------------------------------------------------
# t11: IPv6 re-render + stale-action detection
# ---------------------------------------------------------------------------


def test_action_content_embeds_ipv6_render_marker(docker_module):
    """Rendered file records which capability it was built for."""
    v4 = docker_module.action_content(chain="f2b-wpfy-test", ipv6=False)
    v6 = docker_module.action_content(chain="f2b-wpfy-test", ipv6=True)
    assert "# Rendered with IPv6 support: no" in v4
    assert "# Rendered with IPv6 support: yes" in v6


def test_action_rendered_ipv6_reads_marker(docker_module):
    """action_rendered_ipv6 parses the marker from the installed file."""
    docker_module.install_action(chain="f2b-wpfy-test", ipv6=False)
    assert docker_module.action_rendered_ipv6() is False
    docker_module.install_action(chain="f2b-wpfy-test", ipv6=True)
    assert docker_module.action_rendered_ipv6() is True


def test_action_rendered_ipv6_none_when_absent(docker_module):
    """No file yet -> no render state."""
    assert docker_module.action_rendered_ipv6() is None
    assert docker_module.action_is_stale() is False


def test_action_is_stale_when_ipv6_gained(monkeypatch, tmp_wpfy_home):
    """Action rendered without ip6 block is stale once host gains IPv6."""
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    import wpfy.fail2ban_docker

    importlib.reload(wpfy.fail2ban_docker)
    wpfy.fail2ban_docker.install_action(chain="f2b-wpfy-test", ipv6=False)
    assert wpfy.fail2ban_docker.action_is_stale() is False

    monkeypatch.setenv("WPFY_TEST_IPV6_CAPABLE", "1")
    importlib.reload(wpfy.fail2ban_docker)
    assert wpfy.fail2ban_docker.action_is_stale() is True


def test_action_not_stale_when_rendered_with_ipv6(monkeypatch, tmp_wpfy_home):
    """Action rendered with ip6 block is never stale on capable host."""
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    monkeypatch.setenv("WPFY_TEST_IPV6_CAPABLE", "1")
    import wpfy.fail2ban_docker

    importlib.reload(wpfy.fail2ban_docker)
    wpfy.fail2ban_docker.install_action(chain="f2b-wpfy-test", ipv6=True)
    assert wpfy.fail2ban_docker.action_is_stale() is False


def test_install_rerenders_on_ipv6_capability_change(monkeypatch, tmp_wpfy_home):
    """install_action re-renders (ip6 block added) when capability changes."""
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    import wpfy.fail2ban_docker

    importlib.reload(wpfy.fail2ban_docker)
    wpfy.fail2ban_docker.install_action(chain="f2b-wpfy-test", ipv6=False)
    assert wpfy.fail2ban_docker.action_is_stale() is False

    monkeypatch.setenv("WPFY_TEST_IPV6_CAPABLE", "1")
    importlib.reload(wpfy.fail2ban_docker)
    changed = wpfy.fail2ban_docker.install_action(chain="f2b-wpfy-test")
    assert changed is True
    text = wpfy.fail2ban_docker.action_file_path().read_text(encoding="utf-8")
    assert "ip6tables -w -N f2b-wpfy-test" in text
    assert wpfy.fail2ban_docker.action_is_stale() is False


def test_enforcement_status_degraded_when_action_stale(monkeypatch, tmp_wpfy_home):
    """Health reports degraded until an IPv6-capable action is configured."""
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    import wpfy.fail2ban_docker

    importlib.reload(wpfy.fail2ban_docker)
    wpfy.fail2ban_docker.install_action(chain="f2b-wpfy-test", ipv6=False)

    monkeypatch.setenv("WPFY_TEST_IPV6_CAPABLE", "1")
    importlib.reload(wpfy.fail2ban_docker)
    status = wpfy.fail2ban_docker.enforcement_status(chain="f2b-wpfy-test")
    assert status.action_stale is True
    assert "stale" in status.degraded_reason
    assert "IPv6" in status.degraded_reason

    wpfy.fail2ban_docker.install_action(chain="f2b-wpfy-test")
    status = wpfy.fail2ban_docker.enforcement_status(chain="f2b-wpfy-test")
    assert status.action_stale is False
    assert status.degraded_reason == ""


# ---------------------------------------------------------------------------
# t11: enforcement-path fixture (executable model of rendered commands)
#
# Renders the real action and executes actionstart/actionban/actionunban/
# actionstop lines against a fake firewall object. No real iptables needed.
# ---------------------------------------------------------------------------


class FakeFirewall:
    """Ordered-chain model of the iptables commands the action renders."""

    def __init__(self, docker_user_rules=()):
        self.chains = {"DOCKER-USER": list(docker_user_rules)}
        self.creation_order = []

    def run(self, argv):
        argv = [a for a in argv if a != "-w"]
        if not argv:
            return 0, ""
        if argv[0] in ("iptables", "ip6tables"):
            argv = argv[1:]
        if not argv:
            return 0, ""
        op = argv[0]
        if op == "-N":
            name = argv[1]
            if name not in self.chains:
                self.chains[name] = []
                self.creation_order.append(name)
            return 0, ""
        if op == "-F":
            name = argv[1]
            if name not in self.chains:
                return 1, ""
            self.chains[name] = []
            return 0, ""
        if op == "-C":
            target = argv[1]
            rule = " ".join(argv[2:])
            return (0, "") if rule in self.chains.get(target, []) else (1, "")
        if op == "-I":
            target = argv[1]
            if target not in self.chains:
                return 1, ""
            rest = argv[2:]
            position = 1
            if rest and rest[0].isdigit():
                position = int(rest[0])
                rest = rest[1:]
            rule = " ".join(rest)
            position = min(max(position - 1, 0), len(self.chains[target]))
            self.chains[target].insert(position, rule)
            return 0, ""
        if op == "-D":
            target = argv[1]
            if target not in self.chains:
                return 1, ""
            rule = " ".join(argv[2:])
            try:
                self.chains[target].remove(rule)
            except ValueError:
                return 1, ""
            return 0, ""
        if op == "-X":
            name = argv[1]
            if name not in self.chains:
                return 0, ""
            if self.chains[name]:
                return 1, ""
            del self.chains[name]
            return 0, ""
        if op == "-S":
            name = argv[1]
            if name not in self.chains:
                return 1, ""
            lines = [f"-N {name}"] + list(self.chains[name])
            return 0, "\n".join(lines) + "\n"
        if op == "-L":
            name = argv[1]
            if name not in self.chains:
                return 1, ""
            return 0, "\n".join(self.chains[name]) + "\n"
        return 1, ""


_SECTION_RE = re.compile(r"^(action\w+)\s*=\s*(.*)$")


def _section_commands(content, section):
    """Extract executable command lines from one rendered action section."""
    out = []
    current = None
    for raw in content.splitlines():
        stripped = raw.strip()
        match = _SECTION_RE.match(stripped)
        if match:
            current = match.group(1)
            body = match.group(2).strip()
            if current == section and body and not body.startswith("#"):
                out.append(body)
            continue
        if current == section and stripped and not stripped.startswith("#"):
            out.append(stripped)
    return out


def _tokens(line):
    import shlex

    # Drop stderr/stdout redirects. Order matters: 2>/dev/null must go before
    # the bare >/dev/null replacement (which would otherwise leave a stray 2).
    line = (
        line.replace("2>/dev/null", "")
        .replace("2>&1", "")
        .replace(">/dev/null", "")
    )
    try:
        return shlex.split(line)
    except ValueError:
        return []


def _run_command(line, fw, env):
    line = line.strip()
    if not line:
        return 0
    if "||" in line:
        for part in (p.strip() for p in line.split("||")):
            if part == "true":
                return 0
            if _run_command(part, fw, env) == 0:
                return 0
        return 1
    if line.startswith("rule_count=$("):
        inner = line[len("rule_count=$("):-1]
        cmd_part = inner.split("|")[0].strip()
        _rc, output = fw.run(_tokens(cmd_part))
        env["rule_count"] = len(output.strip().splitlines()) if output.strip() else 0
        return 0
    argv = _tokens(line)
    if not argv:
        return 0
    rc, _output = fw.run(argv)
    return rc


def _parse_statements(lines):
    statements = []
    index = 0
    while index < len(lines):
        stripped = lines[index].strip()
        if not stripped or stripped.startswith("#"):
            index += 1
            continue
        if stripped.startswith("if ") and stripped.endswith("; then"):
            depth = 1
            cursor = index + 1
            while cursor < len(lines) and depth:
                token = lines[cursor].strip()
                if token.startswith("if ") and token.endswith("; then"):
                    depth += 1
                elif token == "fi":
                    depth -= 1
                cursor += 1
            body_lines = lines[index + 1 : cursor - 1]
            then_body: list[str] = []
            else_body: list[str] = []
            target = then_body
            body_depth = 0
            for bline in body_lines:
                bstripped = bline.strip()
                if bstripped == "else" and body_depth == 0:
                    target = else_body
                    continue
                if bstripped.startswith("if ") and bstripped.endswith("; then"):
                    body_depth += 1
                elif bstripped == "fi":
                    body_depth -= 1
                target.append(bline)
            statements.append(("ifelse", stripped, then_body, else_body))
            index = cursor
        else:
            statements.append(("cmd", stripped))
            index += 1
    return statements


def _run_statements(statements, fw, env):
    for item in statements:
        kind = item[0]
        if kind == "cmd":
            _run_command(item[1], fw, env)
            continue
        if kind == "if":
            header = item[1]
            condition = header[len("if ") : -len("; then")].strip()
            body = _parse_statements(item[2])
            if _evaluate_condition(condition, fw, env):
                _run_statements(body, fw, env)
            continue
        header = item[1]
        condition = header[len("if ") : -len("; then")].strip()
        then_body = _parse_statements(item[2])
        else_body = _parse_statements(item[3])
        if _evaluate_condition(condition, fw, env):
            _run_statements(then_body, fw, env)
        else:
            _run_statements(else_body, fw, env)


def _evaluate_condition(condition, fw, env):
    match = re.match(r'\[ "\$rule_count" -le (\d+) \]', condition)
    if match:
        return env.get("rule_count", 0) <= int(match.group(1))
    family_match = re.match(r'\[ "([^"]+)" = "([^"]+)" \]', condition)
    if family_match:
        key = family_match.group(1)
        # fail2ban substitutes <family>/<ipfamily> tags before the action
        # runs; map the angle-bracketed tag back to the env key.
        if key.startswith("<") and key.endswith(">"):
            key = key[1:-1]
        return env.get(key) == family_match.group(2)
    return _run_command(condition, fw, env) == 0


def _run_section(fw, content, section, env=None):
    env = env if env is not None else {}
    statements = _parse_statements(_section_commands(content, section))
    _run_statements(statements, fw, env)
    return fw


def _render_model(chain, ip="203.0.113.9"):
    """Render action content for one jail, substitute fail2ban tags."""
    import wpfy.fail2ban_docker

    content = wpfy.fail2ban_docker.action_content(chain=chain, ipv6=False)
    return content.replace("<ip>", ip).replace("<name>", chain[len("f2b-wpfy-"):])


def _banned_firewall(chain="f2b-wpfy-jailA", ip="203.0.113.9", seed=()):
    """Start the action then ban one IP; returns (firewall, content)."""
    content = _render_model(chain, ip)
    fw = FakeFirewall(docker_user_rules=seed)
    _run_section(fw, content, "actionstart")
    _run_section(fw, content, "actionban")
    return fw, content


def test_enforcement_model_creates_only_wpfy_chain(docker_module):
    """Executed actionstart creates exactly the WPFY chain, nothing else."""
    fw, _ = _banned_firewall()
    assert fw.creation_order == ["f2b-wpfy-jailA"]
    assert "DOCKER-USER" in fw.chains


def test_enforcement_model_attaches_to_docker_user_at_top(docker_module):
    """WPFY jump is inserted first in DOCKER-USER, before existing rules."""
    seed = ["-p tcp --dport 22 -j ACCEPT", "-j RETURN"]
    fw, _ = _banned_firewall(seed=seed)
    assert fw.chains["DOCKER-USER"][0] == "-j f2b-wpfy-jailA"
    assert fw.chains["DOCKER-USER"][1:] == seed


def test_enforcement_model_ban_blocks_80_443_with_reject(docker_module):
    """actionban inserts a REJECT rule for TCP 80,443 into the WPFY chain."""
    fw, _ = _banned_firewall()
    rules = fw.chains["f2b-wpfy-jailA"]
    assert rules, "ban rule must exist in the WPFY chain"
    assert any("--dports 80,443" in rule and "-j REJECT" in rule for rule in rules)
    assert any("-s 203.0.113.9" in rule for rule in rules)


def test_enforcement_model_ssh_untouched(docker_module):
    """SSH rule survives ban; no port-22 rule is ever created."""
    fw, _ = _banned_firewall(seed=["-p tcp --dport 22 -j ACCEPT"])
    assert "-p tcp --dport 22 -j ACCEPT" in fw.chains["DOCKER-USER"]
    # DOCKER-USER keeps exactly the seeded SSH rule plus the WPFY jump.
    assert fw.chains["DOCKER-USER"] == [
        "-j f2b-wpfy-jailA",
        "-p tcp --dport 22 -j ACCEPT",
    ]
    # The WPFY chain (the only chain the action writes bans to) never carries
    # a port-22 rule.
    for rule in fw.chains["f2b-wpfy-jailA"]:
        assert "--dport 22" not in rule
        assert "dports 22" not in rule
        assert "port 22" not in rule


def test_enforcement_model_unban_restores(docker_module):
    """actionunban removes the exact ban rule; chain returns to empty."""
    fw, content = _banned_firewall()
    assert fw.chains["f2b-wpfy-jailA"]
    _run_section(fw, content, "actionunban")
    assert fw.chains["f2b-wpfy-jailA"] == []
    # DOCKER-USER jump survives (chain still owned by WPFY).
    assert "-j f2b-wpfy-jailA" in fw.chains["DOCKER-USER"]


def test_enforcement_model_multiple_jails_coexist(docker_module):
    """Two jails ban/unban independently without touching each other."""
    content_a = _render_model("f2b-wpfy-jailA")
    content_b = _render_model("f2b-wpfy-jailB")
    fw = FakeFirewall()
    _run_section(fw, content_a, "actionstart")
    _run_section(fw, content_b, "actionstart")
    _run_section(fw, content_a, "actionban")
    _run_section(fw, content_b, "actionban")
    assert len(fw.chains["f2b-wpfy-jailA"]) == 1
    assert len(fw.chains["f2b-wpfy-jailB"]) == 1
    assert "-j f2b-wpfy-jailA" in fw.chains["DOCKER-USER"]
    assert "-j f2b-wpfy-jailB" in fw.chains["DOCKER-USER"]

    _run_section(fw, content_a, "actionunban")
    assert fw.chains["f2b-wpfy-jailA"] == []
    assert len(fw.chains["f2b-wpfy-jailB"]) == 1
    assert "-j f2b-wpfy-jailB" in fw.chains["DOCKER-USER"]


def test_enforcement_model_restart_restores_without_duplicate_jump(docker_module):
    """Fail2ban reload (actionstart again) keeps one jump and chain present."""
    fw, content = _banned_firewall()
    _run_section(fw, content, "actionstart")
    _run_section(fw, content, "actionstart")
    assert fw.chains["DOCKER-USER"].count("-j f2b-wpfy-jailA") == 1
    assert "f2b-wpfy-jailA" in fw.chains
    # Re-issued ban after restart restores blocking.
    _run_section(fw, content, "actionban")
    assert len(fw.chains["f2b-wpfy-jailA"]) == 1


def test_enforcement_model_existing_rules_preserved(docker_module):
    """Docker/firewall rules in DOCKER-USER are never flushed or deleted."""
    seed = ["-p tcp --dport 22 -j ACCEPT", "-m conntrack --ctstate ESTABLISHED -j ACCEPT"]
    fw, _ = _banned_firewall(seed=seed)
    assert fw.chains["DOCKER-USER"][1:] == seed
    for rule in seed:
        assert rule in fw.chains["DOCKER-USER"]


def test_enforcement_model_no_input_dependency(docker_module):
    """Executed action never creates or touches the INPUT chain."""
    fw, _ = _banned_firewall()
    assert "INPUT" not in fw.chains
    for chain, rules in fw.chains.items():
        for rule in rules:
            assert "INPUT" not in rule


def test_enforcement_model_actionstop_removes_only_empty_wpfy_chain(docker_module):
    """actionstop deletes only its own empty chain; keeps it when banned."""
    fw, content = _banned_firewall()
    _run_section(fw, content, "actionstop")
    # Ban present -> chain and jump survive.
    assert "f2b-wpfy-jailA" in fw.chains
    assert "-j f2b-wpfy-jailA" in fw.chains["DOCKER-USER"]

    _run_section(fw, content, "actionunban")
    _run_section(fw, content, "actionstop")
    assert "f2b-wpfy-jailA" not in fw.chains
    assert "-j f2b-wpfy-jailA" not in fw.chains["DOCKER-USER"]
    assert "DOCKER-USER" in fw.chains


# ---------------------------------------------------------------------------
# t12 (wave-5 gate finding): REAL ip6tables ban/unban capability
#
# Before t12 the ipv6=True render only scaffolded the chain; actionban/
# actionunban emitted iptables only, so public IPv6 was never actually
# blocked. The ipv6=True render now branches on the fail2ban <family> tag
# with real ip6tables ban/unban (icmp6-port-unreachable).
# ---------------------------------------------------------------------------


def _render_model_ipv6(chain, ip="2001:db8::1"):
    """Render ipv6=True action content with fail2ban tags substituted."""
    import wpfy.fail2ban_docker

    content = wpfy.fail2ban_docker.action_content(chain=chain, ipv6=True)
    return content.replace("<ip>", ip).replace("<name>", chain[len("f2b-wpfy-"):])


def test_ipv6_render_has_real_ban_unban_commands(docker_module):
    """ipv6=True actionban/actionunban include real ip6tables commands."""
    v6 = docker_module.action_content(chain="f2b-wpfy-test", ipv6=True)
    assert "ip6tables -w -I f2b-wpfy-test 1 -s <ip>" in v6
    assert "ip6tables -w -D f2b-wpfy-test" in v6
    assert "icmp6-port-unreachable" in v6
    assert "icmp-port-unreachable" in v6
    # The family branch drives the choice.
    assert 'if [ "<family>" = "ipv6" ]; then' in v6

    v4 = docker_module.action_content(chain="f2b-wpfy-test", ipv6=False)
    assert "ip6tables" not in v4
    assert "icmp6-port-unreachable" not in v4
    # IPv4-only render keeps the single-line actionban contract.
    ban_lines = [l for l in v4.splitlines() if l.strip().startswith("actionban")]
    assert len(ban_lines) == 1


def test_enforcement_model_ipv6_ban_and_unban_transitions(docker_module):
    """Executed ipv6=True content bans with ip6tables and unbans exactly."""
    content = _render_model_ipv6("f2b-wpfy-jailV6", ip="2001:db8::1")
    fw = FakeFirewall()
    _run_section(fw, content, "actionstart", env={"family": "ipv6"})
    _run_section(fw, content, "actionban", env={"family": "ipv6"})

    rules = fw.chains["f2b-wpfy-jailV6"]
    assert rules, "IPv6 ban rule must land in the WPFY chain"
    assert any("-s 2001:db8::1" in rule and "icmp6-port-unreachable" in rule for rule in rules)
    assert any("--dports 80,443" in rule for rule in rules)
    # IPv6 ban must not have emitted the IPv4 REJECT form.
    assert not any("icmp-port-unreachable" in rule for rule in rules)

    _run_section(fw, content, "actionunban", env={"family": "ipv6"})
    assert fw.chains["f2b-wpfy-jailV6"] == []
    # The DOCKER-USER jump survives (chain still WPFY-owned).
    assert "-j f2b-wpfy-jailV6" in fw.chains["DOCKER-USER"]


def test_enforcement_model_ipv6_render_keeps_ipv4_branch(docker_module):
    """The same ipv6=True action still bans IPv4 via the else branch."""
    content = _render_model_ipv6("f2b-wpfy-jailV6", ip="203.0.113.9")
    fw = FakeFirewall()
    _run_section(fw, content, "actionstart", env={"family": "ipv4"})
    _run_section(fw, content, "actionban", env={"family": "ipv4"})
    rules = fw.chains["f2b-wpfy-jailV6"]
    assert any("-s 203.0.113.9" in rule and "icmp-port-unreachable" in rule for rule in rules)
    assert not any("icmp6-port-unreachable" in rule for rule in rules)


def test_enforcement_model_ipv6_unban_restores_then_stop_removes_chain(docker_module):
    """Full IPv6 lifecycle: ban, unban, actionstop removes empty chain."""
    content = _render_model_ipv6("f2b-wpfy-jailV6", ip="2001:db8::1")
    fw = FakeFirewall()
    _run_section(fw, content, "actionstart", env={"family": "ipv6"})
    _run_section(fw, content, "actionban", env={"family": "ipv6"})
    _run_section(fw, content, "actionstop", env={"family": "ipv6"})
    # Ban present -> chain kept.
    assert "f2b-wpfy-jailV6" in fw.chains
    _run_section(fw, content, "actionunban", env={"family": "ipv6"})
    _run_section(fw, content, "actionstop", env={"family": "ipv6"})
    assert "f2b-wpfy-jailV6" not in fw.chains
    assert "-j f2b-wpfy-jailV6" not in fw.chains["DOCKER-USER"]


def test_enforcement_status_ipv6_active_requires_ban_capability(monkeypatch, tmp_wpfy_home):
    """ipv6_active must require the action to carry real IPv6 ban commands.

    Wave-5 gate finding: chain existence in ip6tables is not enough; an
    action rendered without the ip6 ban/unban cannot enforce IPv6 and must
    report degraded.
    """
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    import wpfy.fail2ban_docker

    importlib.reload(wpfy.fail2ban_docker)
    # Action rendered WITHOUT ipv6 ban capability, but the host is IPv6
    # capable and the (fake, skipped) ip6tables chain probes would succeed.
    wpfy.fail2ban_docker.install_action(chain="f2b-wpfy-test", ipv6=False)

    monkeypatch.setenv("WPFY_TEST_IPV6_CAPABLE", "1")
    importlib.reload(wpfy.fail2ban_docker)
    status = wpfy.fail2ban_docker.enforcement_status(chain="f2b-wpfy-test")
    assert status.ipv6_applicable is True
    assert status.ipv6_active is False
    assert "ban capability" in status.degraded_reason
    assert "re-render" in status.degraded_reason

    # Re-render with IPv6 support -> ban capability present -> active.
    wpfy.fail2ban_docker.install_action(chain="f2b-wpfy-test")
    status = wpfy.fail2ban_docker.enforcement_status(chain="f2b-wpfy-test")
    assert status.ipv6_active is True
    assert status.degraded_reason == ""


def test_enforcement_status_ipv6_active_false_when_chain_missing(monkeypatch, tmp_wpfy_home):
    """Even with a rendered IPv6 action, a missing IPv6 chain is degraded."""
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "0")
    monkeypatch.setenv("WPFY_TEST_IPV6_CAPABLE", "1")
    monkeypatch.setenv("WPFY_TEST_IP6TABLES_BIN", "/nonexistent/ip6tables")
    import wpfy.fail2ban_docker

    importlib.reload(wpfy.fail2ban_docker)
    wpfy.fail2ban_docker.install_action(chain="f2b-wpfy-test", ipv6=True)
    status = wpfy.fail2ban_docker.enforcement_status(chain="f2b-wpfy-test")
    # ip6tables binary missing -> FileNotFoundError -> returncode 127 -> not
    # present, so IPv6 cannot be enforced even though the action is capable.
    assert status.ipv6_active is False
    assert "IPv6 DOCKER-USER not configured" in status.degraded_reason


# ---------------------------------------------------------------------------
# t14 (chain): Phase 12 items 9 and 19 at the action-model level.
#
# Item 9: host-level bans persist independent of the panel. The ban lives in
# the iptables model (host state), not in the panel process; a panel restart
# (in-memory panel state reset) cannot remove it, and a fail2ban reload
# (actionstart) flushes then re-issues the ban from the ban table.
# Item 19: root can inspect the ban (iptables -S) and unban surgically.
# ---------------------------------------------------------------------------


def test_panel_restart_does_not_remove_active_host_ban(docker_module):
    """Host-level ban survives a panel restart and a fail2ban reload."""
    import wpfy.panel_auth

    content = _render_model("f2b-wpfy-panel-auth", ip="203.0.113.55")
    fw = FakeFirewall()
    _run_section(fw, content, "actionstart")
    _run_section(fw, content, "actionban")
    assert any("203.0.113.55" in rule and "--dports 80,443" in rule for rule in fw.chains["f2b-wpfy-panel-auth"])

    # Panel restart: the panel's in-memory state is wiped, but the ban lives
    # in the firewall model and is untouched by any panel-side operation.
    wpfy.panel_auth.reset_state()
    assert any("203.0.113.55" in rule for rule in fw.chains["f2b-wpfy-panel-auth"])
    assert "-j f2b-wpfy-panel-auth" in fw.chains["DOCKER-USER"]

    # Fail2ban reload re-runs actionstart (chain flushed) then re-issues the
    # ban from the ban table; blocking is restored, jump never duplicated.
    _run_section(fw, content, "actionstart")
    assert fw.chains["DOCKER-USER"].count("-j f2b-wpfy-panel-auth") == 1
    _run_section(fw, content, "actionban")
    assert any("203.0.113.55" in rule for rule in fw.chains["f2b-wpfy-panel-auth"])


def test_root_inspection_and_unban_are_safe(docker_module):
    """Root can list the ban (iptables -S) and unban removes exactly one rule."""
    content = _render_model("f2b-wpfy-panel-auth", ip="203.0.113.55")
    seed = ["-p tcp --dport 22 -j ACCEPT", "-j RETURN"]
    fw = FakeFirewall(docker_user_rules=seed)
    _run_section(fw, content, "actionstart")
    _run_section(fw, content, "actionban")

    # Inspection shows the exact ban rule.
    rc, listing = fw.run(["iptables", "-w", "-S", "f2b-wpfy-panel-auth"])
    assert rc == 0
    assert "-s 203.0.113.55" in listing
    assert "--dports 80,443" in listing

    # Unban removes only the matching rule; unrelated rules survive.
    _run_section(fw, content, "actionunban")
    assert fw.chains["f2b-wpfy-panel-auth"] == []
    assert fw.chains["DOCKER-USER"] == [
        "-j f2b-wpfy-panel-auth",
        "-p tcp --dport 22 -j ACCEPT",
        "-j RETURN",
    ]
