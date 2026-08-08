from __future__ import annotations

import importlib
from pathlib import Path

import pytest


@pytest.fixture
def f2b_module(tmp_wpfy_home, monkeypatch):
    """Reload fail2ban_host with redirected paths."""
    import wpfy.fail2ban_host

    importlib.reload(wpfy.fail2ban_host)
    return wpfy.fail2ban_host


class Proc:
    """Stub for subprocess.CompletedProcess."""

    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_fail2ban_absent_triggers_install(f2b_module, monkeypatch):
    """Test 1: Fail2ban absent → installation proceeds."""
    calls = []
    state = {"installed": False}

    def which(binary):
        if binary == "fail2ban-client":
            return "/usr/bin/fail2ban-client" if state["installed"] else None
        return "/usr/bin/" + binary

    def run(command, **kwargs):
        calls.append(command)
        if command[0] == "apt-get":
            state["installed"] = True
            return Proc(stdout="installed")
        if command[0] == "systemctl":
            return Proc(stdout="enabled")
        if command == ["fail2ban-client", "ping"]:
            return Proc(stdout="Server replied: pong")
        if command == ["fail2ban-client", "-t"]:
            return Proc(stdout="config ok")
        if command == ["fail2ban-client", "reload"]:
            return Proc(stdout="reloaded")
        if command == ["fail2ban-client", "version"]:
            return Proc(stdout="1.0.0")
        return Proc()

    monkeypatch.setattr(f2b_module.shutil, "which", which)
    monkeypatch.setattr(f2b_module.subprocess, "run", run)

    result = f2b_module.ensure_fail2ban_host()

    assert result.exit_code == 0
    assert result.installed is True
    assert result.health_ok is True
    assert result.changed is True
    assert "freshly installed" in result.message
    assert any(cmd[0] == "apt-get" for cmd in calls)


def test_install_success_writes_managed_configs(f2b_module, monkeypatch):
    """Test 2: Package installation succeeds and WPFY configs are written."""
    state = {"installed": False}

    def which(binary):
        if binary == "fail2ban-client":
            return "/usr/bin/fail2ban-client" if state["installed"] else None
        return "/usr/bin/" + binary

    def run(command, **kwargs):
        if command[0] == "apt-get":
            state["installed"] = True
            return Proc(stdout="installed")
        if command[0] == "systemctl":
            return Proc(stdout="enabled")
        if command == ["fail2ban-client", "ping"]:
            return Proc(stdout="Server replied: pong")
        if command == ["fail2ban-client", "-t"]:
            return Proc(stdout="config ok")
        if command == ["fail2ban-client", "reload"]:
            return Proc(stdout="reloaded")
        if command == ["fail2ban-client", "version"]:
            return Proc(stdout="1.0.0")
        return Proc()

    monkeypatch.setattr(f2b_module.shutil, "which", which)
    monkeypatch.setattr(f2b_module.subprocess, "run", run)

    result = f2b_module.ensure_fail2ban_host()

    assert result.exit_code == 0
    root = f2b_module._fail2ban_root()
    assert (root / "filter.d" / "wpfy-panel-auth.conf").is_file()
    assert (root / "filter.d" / "wpfy-wordpress.conf").is_file()
    assert (root / "jail.d" / "wpfy-panel-auth.local").is_file()
    assert (root / "jail.d" / "wpfy-wordpress.local").is_file()
    assert (root / "action.d" / "wpfy-docker-http.conf").is_file()
    for path in (root / "filter.d").iterdir():
        if path.name.startswith("wpfy-"):
            assert f2b_module._MANAGED_HEADER in path.read_text(encoding="utf-8")


def test_install_failure_fails_safely(f2b_module, monkeypatch):
    """Test 3: Package installation fails safely — no half-configured state."""

    def which(binary):
        return None

    def run(command, **kwargs):
        if command[0] == "apt-get":
            return Proc(1, stderr="repository unavailable")
        return Proc()

    monkeypatch.setattr(f2b_module.shutil, "which", which)
    monkeypatch.setattr(f2b_module.subprocess, "run", run)

    result = f2b_module.ensure_fail2ban_host()

    assert result.exit_code == 1
    assert result.installed is False
    assert result.health_ok is False
    assert "apt-get" in result.message or "installation failed" in result.message
    root = f2b_module._fail2ban_root()
    assert not root.exists() or not any(root.rglob("wpfy-*"))


def test_installed_but_stopped_enables_service(f2b_module, monkeypatch):
    """Test 4: Fail2ban installed but service stopped → enable and start."""
    calls = []

    def which(binary):
        return "/usr/bin/fail2ban-client" if binary == "fail2ban-client" else None

    def run(command, **kwargs):
        calls.append(command)
        if command[0] == "systemctl":
            return Proc(stdout="enabled")
        if command == ["fail2ban-client", "ping"]:
            return Proc(stdout="Server replied: pong")
        if command == ["fail2ban-client", "-t"]:
            return Proc(stdout="config ok")
        if command == ["fail2ban-client", "reload"]:
            return Proc(stdout="reloaded")
        if command == ["fail2ban-client", "version"]:
            return Proc(stdout="1.0.0")
        return Proc()

    monkeypatch.setattr(f2b_module.shutil, "which", which)
    monkeypatch.setattr(f2b_module.subprocess, "run", run)

    result = f2b_module.ensure_fail2ban_host()

    assert result.exit_code == 0
    assert result.installed is True
    assert result.health_ok is True
    assert any(cmd[0] == "systemctl" for cmd in calls)


def test_invalid_config_rolls_back(f2b_module, monkeypatch):
    """Test 5: Fail2ban installed but configuration invalid → rollback."""
    root = f2b_module._fail2ban_root()
    root.mkdir(parents=True, exist_ok=True)
    (root / "jail.d").mkdir(exist_ok=True)
    original = "# Managed by WPFY. Manual changes may be overwritten.\n[original]\nenabled = true\n"
    (root / "jail.d" / "wpfy-wordpress.local").write_text(original, encoding="utf-8")

    def which(binary):
        return "/usr/bin/fail2ban-client" if binary == "fail2ban-client" else None

    def run(command, **kwargs):
        if command[0] == "systemctl":
            return Proc(stdout="enabled")
        if command == ["fail2ban-client", "ping"]:
            return Proc(stdout="Server replied: pong")
        if command == ["fail2ban-client", "-t"]:
            return Proc(1, stderr="invalid config syntax")
        if command == ["fail2ban-client", "version"]:
            return Proc(stdout="1.0.0")
        return Proc()

    monkeypatch.setattr(f2b_module.shutil, "which", which)
    monkeypatch.setattr(f2b_module.subprocess, "run", run)

    result = f2b_module.ensure_fail2ban_host()

    assert result.exit_code == 1
    assert result.health_ok is False
    assert "validation failed" in result.message or "rolled back" in result.message
    restored = (root / "jail.d" / "wpfy-wordpress.local").read_text(encoding="utf-8")
    assert "[original]" in restored


def test_healthy_not_reinstalled(f2b_module, monkeypatch):
    """Test 6: Healthy installation is not reinstalled."""
    apt_calls = []

    def which(binary):
        return "/usr/bin/fail2ban-client" if binary == "fail2ban-client" else None

    def run(command, **kwargs):
        if command[0] == "apt-get":
            apt_calls.append(command)
            return Proc(stdout="installed")
        if command[0] == "systemctl":
            return Proc(stdout="enabled")
        if command == ["fail2ban-client", "ping"]:
            return Proc(stdout="Server replied: pong")
        if command == ["fail2ban-client", "-t"]:
            return Proc(stdout="config ok")
        if command == ["fail2ban-client", "reload"]:
            return Proc(stdout="reloaded")
        if command == ["fail2ban-client", "version"]:
            return Proc(stdout="1.0.0")
        return Proc()

    monkeypatch.setattr(f2b_module.shutil, "which", which)
    monkeypatch.setattr(f2b_module.subprocess, "run", run)

    first = f2b_module.ensure_fail2ban_host()
    assert first.exit_code == 0

    result = f2b_module.ensure_fail2ban_host()

    assert result.exit_code == 0
    assert result.installed is True
    assert result.health_ok is True
    assert result.changed is False
    assert not apt_calls


def test_admin_jails_untouched(f2b_module, monkeypatch):
    """Test 7: Administrator-owned jails remain untouched."""
    root = f2b_module._fail2ban_root()
    root.mkdir(parents=True, exist_ok=True)
    (root / "jail.d").mkdir(exist_ok=True)
    admin_jail = root / "jail.d" / "custom-admin.conf"
    admin_content = "[custom-jail]\nenabled = true\nport = 22\n"
    admin_jail.write_text(admin_content, encoding="utf-8")

    def which(binary):
        return "/usr/bin/fail2ban-client" if binary == "fail2ban-client" else None

    def run(command, **kwargs):
        if command[0] == "systemctl":
            return Proc(stdout="enabled")
        if command == ["fail2ban-client", "ping"]:
            return Proc(stdout="Server replied: pong")
        if command == ["fail2ban-client", "-t"]:
            return Proc(stdout="config ok")
        if command == ["fail2ban-client", "reload"]:
            return Proc(stdout="reloaded")
        if command == ["fail2ban-client", "version"]:
            return Proc(stdout="1.0.0")
        return Proc()

    monkeypatch.setattr(f2b_module.shutil, "which", which)
    monkeypatch.setattr(f2b_module.subprocess, "run", run)

    result = f2b_module.ensure_fail2ban_host()

    assert result.exit_code == 0
    assert admin_jail.read_text(encoding="utf-8") == admin_content


def test_atomic_update(f2b_module, monkeypatch):
    """Test 8: WPFY-owned files are updated atomically."""
    root = f2b_module._fail2ban_root()
    root.mkdir(parents=True, exist_ok=True)
    (root / "filter.d").mkdir(exist_ok=True)
    old_content = f"{f2b_module._MANAGED_HEADER}\n[Definition]\nold = true\n"
    (root / "filter.d" / "wpfy-wordpress.conf").write_text(old_content, encoding="utf-8")

    def which(binary):
        return "/usr/bin/fail2ban-client" if binary == "fail2ban-client" else None

    def run(command, **kwargs):
        if command[0] == "systemctl":
            return Proc(stdout="enabled")
        if command == ["fail2ban-client", "ping"]:
            return Proc(stdout="Server replied: pong")
        if command == ["fail2ban-client", "-t"]:
            return Proc(stdout="config ok")
        if command == ["fail2ban-client", "reload"]:
            return Proc(stdout="reloaded")
        if command == ["fail2ban-client", "version"]:
            return Proc(stdout="1.0.0")
        return Proc()

    monkeypatch.setattr(f2b_module.shutil, "which", which)
    monkeypatch.setattr(f2b_module.subprocess, "run", run)

    result = f2b_module.ensure_fail2ban_host()

    assert result.exit_code == 0
    new_content = (root / "filter.d" / "wpfy-wordpress.conf").read_text(encoding="utf-8")
    assert "old = true" not in new_content
    assert f2b_module._MANAGED_HEADER in new_content


def test_rollback_on_broken_config(f2b_module, monkeypatch):
    """Test 9: Broken WPFY configuration rolls back to previous working state."""
    root = f2b_module._fail2ban_root()
    root.mkdir(parents=True, exist_ok=True)
    (root / "jail.d").mkdir(exist_ok=True)
    working = f"{f2b_module._MANAGED_HEADER}\n[wpfy-wordpress]\nenabled = false\n"
    (root / "jail.d" / "wpfy-wordpress.local").write_text(working, encoding="utf-8")

    def which(binary):
        return "/usr/bin/fail2ban-client" if binary == "fail2ban-client" else None

    def run(command, **kwargs):
        if command[0] == "systemctl":
            return Proc(stdout="enabled")
        if command == ["fail2ban-client", "ping"]:
            return Proc(stdout="Server replied: pong")
        if command == ["fail2ban-client", "-t"]:
            return Proc(1, stderr="syntax error in jail config")
        if command == ["fail2ban-client", "version"]:
            return Proc(stdout="1.0.0")
        return Proc()

    monkeypatch.setattr(f2b_module.shutil, "which", which)
    monkeypatch.setattr(f2b_module.subprocess, "run", run)

    result = f2b_module.ensure_fail2ban_host()

    assert result.exit_code == 1
    assert result.health_ok is False
    restored = (root / "jail.d" / "wpfy-wordpress.local").read_text(encoding="utf-8")
    assert "[wpfy-wordpress]" in restored
    assert "enabled = false" in restored


def test_idempotent_repeat(f2b_module, monkeypatch):
    """Test 10: Repeated installation is idempotent."""

    def which(binary):
        return "/usr/bin/fail2ban-client" if binary == "fail2ban-client" else None

    def run(command, **kwargs):
        if command[0] == "systemctl":
            return Proc(stdout="enabled")
        if command == ["fail2ban-client", "ping"]:
            return Proc(stdout="Server replied: pong")
        if command == ["fail2ban-client", "-t"]:
            return Proc(stdout="config ok")
        if command == ["fail2ban-client", "reload"]:
            return Proc(stdout="reloaded")
        if command == ["fail2ban-client", "version"]:
            return Proc(stdout="1.0.0")
        return Proc()

    monkeypatch.setattr(f2b_module.shutil, "which", which)
    monkeypatch.setattr(f2b_module.subprocess, "run", run)

    first = f2b_module.ensure_fail2ban_host()
    second = f2b_module.ensure_fail2ban_host()

    assert first.exit_code == second.exit_code == 0
    assert first.changed is True
    assert second.changed is False
    assert first.health_ok is True
    assert second.health_ok is True


def test_disable_does_not_remove_unrelated_jails(f2b_module, monkeypatch):
    """Test 11: Uninstall or site disable does not remove unrelated jails."""
    root = f2b_module._fail2ban_root()
    root.mkdir(parents=True, exist_ok=True)
    (root / "jail.d").mkdir(exist_ok=True)
    unrelated = root / "jail.d" / "sshd.conf"
    unrelated_content = "[sshd]\nenabled = true\nport = 22\n"
    unrelated.write_text(unrelated_content, encoding="utf-8")

    def which(binary):
        return "/usr/bin/fail2ban-client" if binary == "fail2ban-client" else None

    def run(command, **kwargs):
        if command[0] == "systemctl":
            return Proc(stdout="enabled")
        if command == ["fail2ban-client", "ping"]:
            return Proc(stdout="Server replied: pong")
        if command == ["fail2ban-client", "-t"]:
            return Proc(stdout="config ok")
        if command == ["fail2ban-client", "reload"]:
            return Proc(stdout="reloaded")
        if command == ["fail2ban-client", "version"]:
            return Proc(stdout="1.0.0")
        return Proc()

    monkeypatch.setattr(f2b_module.shutil, "which", which)
    monkeypatch.setattr(f2b_module.subprocess, "run", run)

    result = f2b_module.ensure_fail2ban_host()

    assert result.exit_code == 0
    assert unrelated.exists()
    assert unrelated.read_text(encoding="utf-8") == unrelated_content


def test_skip_runtime_honored(f2b_module, monkeypatch):
    """WPFY_SKIP_RUNTIME=1 skips all mutations."""
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    importlib.reload(f2b_module)

    def which(binary):
        return "/usr/bin/fail2ban-client" if binary == "fail2ban-client" else None

    monkeypatch.setattr(f2b_module.shutil, "which", which)

    result = f2b_module.ensure_fail2ban_host()

    assert result.exit_code == 0
    assert "skipped" in result.message.lower()
    assert result.changed is False


def test_policy_constants_accessible(f2b_module):
    """Policy constants are importable by later modules."""
    assert f2b_module.PANEL_JAIL["findtime"] == "10m"
    assert f2b_module.PANEL_JAIL["maxretry"] == "8"
    assert f2b_module.PANEL_JAIL["bantime"] == "15m"
    assert f2b_module.WORDPRESS_JAIL["findtime"] == "10m"
    assert f2b_module.WORDPRESS_JAIL["maxretry"] == "5"
    assert f2b_module.WORDPRESS_JAIL["bantime"] == "1h"
    assert "127.0.0.0/8" in f2b_module.SAFE_ALLOWLIST
    assert "::1" in f2b_module.SAFE_ALLOWLIST
    assert f2b_module.INCREMENTAL_BAN_CAP == "24h"


# ---------------------------------------------------------------------------
# t08 additions: apt update/lock, package+service rollback, config-before-start
# ordering, single-owner filter, real docker action pin, jail.conf protection.
# ---------------------------------------------------------------------------


def _healthy_run(command, state, calls=None):
    """Default command stub shared by the t08 ensure stubs."""
    if calls is not None:
        calls.append(command)
    if command[0] == "apt-get":
        if "remove" in command:
            state["installed"] = False
            return Proc(stdout="removed")
        state["installed"] = True
        return Proc(stdout="installed")
    if command[0] == "systemctl":
        return Proc(stdout="enabled")
    if command == ["fail2ban-client", "ping"]:
        return Proc(stdout="Server replied: pong")
    if command == ["fail2ban-client", "-t"]:
        return Proc(stdout="config ok")
    if command == ["fail2ban-client", "reload"]:
        return Proc(stdout="reloaded")
    if command == ["fail2ban-client", "version"]:
        return Proc(stdout="1.0.0")
    return Proc()


def _binary_present(f2b_module, monkeypatch, state):
    def which(binary):
        if binary == "fail2ban-client":
            return "/usr/bin/fail2ban-client" if state["installed"] else None
        return "/usr/bin/" + binary

    monkeypatch.setattr(f2b_module.shutil, "which", which)


def test_apt_update_runs_before_install_with_lock_handling(f2b_module, monkeypatch):
    """t08: apt-get update precedes install and carries a lock timeout."""
    state = {"installed": False}
    calls = []
    _binary_present(f2b_module, monkeypatch, state)
    monkeypatch.setattr(
        f2b_module.subprocess,
        "run",
        lambda command, **kwargs: _healthy_run(command, state, calls),
    )

    result = f2b_module.ensure_fail2ban_host()

    assert result.exit_code == 0
    updates = [c for c in calls if c[0] == "apt-get" and "update" in c]
    installs = [c for c in calls if c[0] == "apt-get" and "install" in c]
    assert updates and installs, "fresh install must update then install"
    assert calls.index(updates[0]) < calls.index(installs[0])
    for cmd in updates + installs:
        assert any("DPkg::Lock::Timeout" in arg for arg in cmd), (
            f"apt command lacks lock timeout: {cmd}"
        )


def test_fresh_install_rolls_back_package_when_enable_fails(f2b_module, monkeypatch):
    """t08: post-apt failure (systemctl enable) restores pre-install state."""
    state = {"installed": False}
    removes = []
    _binary_present(f2b_module, monkeypatch, state)

    def run(command, **kwargs):
        if command[0] == "apt-get":
            if "remove" in command:
                removes.append(command)
                state["installed"] = False
                return Proc(stdout="removed")
            state["installed"] = True
            return Proc(stdout="installed")
        if command[0] == "systemctl":
            return Proc(1, stderr="cannot enable")
        if command == ["fail2ban-client", "-t"]:
            return Proc(stdout="config ok")
        return Proc()

    monkeypatch.setattr(f2b_module.subprocess, "run", run)

    result = f2b_module.ensure_fail2ban_host()

    assert result.exit_code == 1
    assert result.installed is False
    assert removes, "fresh install must be removed on post-apt failure"
    assert any("remove" in arg for cmd in removes for arg in cmd)


def test_fresh_install_rolls_back_package_when_ping_fails(f2b_module, monkeypatch):
    """t08: post-apt failure (ping) restores pre-install package+service state."""
    state = {"installed": False}
    removes = []
    _binary_present(f2b_module, monkeypatch, state)

    def run(command, **kwargs):
        if command[0] == "apt-get":
            if "remove" in command:
                removes.append(command)
                state["installed"] = False
                return Proc(stdout="removed")
            state["installed"] = True
            return Proc(stdout="installed")
        if command[0] == "systemctl":
            return Proc(stdout="enabled")
        if command == ["fail2ban-client", "-t"]:
            return Proc(stdout="config ok")
        if command == ["fail2ban-client", "ping"]:
            return Proc(1, stderr="no pong")
        return Proc()

    monkeypatch.setattr(f2b_module.subprocess, "run", run)

    result = f2b_module.ensure_fail2ban_host()

    assert result.exit_code == 1
    assert result.health_ok is False
    assert removes


def test_fresh_install_rolls_back_package_on_invalid_config(f2b_module, monkeypatch):
    """t08: post-apt failure (config invalid) restores pre-install state."""
    state = {"installed": False}
    removes = []
    _binary_present(f2b_module, monkeypatch, state)

    def run(command, **kwargs):
        if command[0] == "apt-get":
            if "remove" in command:
                removes.append(command)
                state["installed"] = False
                return Proc(stdout="removed")
            state["installed"] = True
            return Proc(stdout="installed")
        if command[0] == "systemctl":
            return Proc(stdout="enabled")
        if command == ["fail2ban-client", "-t"]:
            return Proc(1, stderr="invalid config syntax")
        return Proc()

    monkeypatch.setattr(f2b_module.subprocess, "run", run)

    result = f2b_module.ensure_fail2ban_host()

    assert result.exit_code == 1
    assert removes
    assert "validation failed" in result.message or "rolled back" in result.message


def test_configs_land_before_service_start(f2b_module, monkeypatch):
    """t08 wave-3 ordering: WPFY configs are written and validated before
    systemctl enable --now runs."""
    root = f2b_module._fail2ban_root()
    state = {"installed": False, "configs_seen_at_enable": False}
    _binary_present(f2b_module, monkeypatch, state)

    def run(command, **kwargs):
        if command[0] == "apt-get":
            state["installed"] = True
            return Proc(stdout="installed")
        if command[0] == "systemctl":
            assert (root / "filter.d" / "wpfy-wordpress.conf").is_file(), (
                "systemctl enable ran before WPFY configs landed"
            )
            state["configs_seen_at_enable"] = True
            return Proc(stdout="enabled")
        if command == ["fail2ban-client", "-t"]:
            assert (root / "jail.d" / "wpfy-wordpress.local").is_file(), (
                "validation ran before WPFY configs landed"
            )
            return Proc(stdout="config ok")
        if command == ["fail2ban-client", "ping"]:
            return Proc(stdout="Server replied: pong")
        if command == ["fail2ban-client", "reload"]:
            return Proc(stdout="reloaded")
        if command == ["fail2ban-client", "version"]:
            return Proc(stdout="1.0.0")
        return Proc()

    monkeypatch.setattr(f2b_module.subprocess, "run", run)

    result = f2b_module.ensure_fail2ban_host()

    assert result.exit_code == 0
    assert state["configs_seen_at_enable"] is True


def test_real_docker_action_never_rewritten_by_ensure(f2b_module, monkeypatch):
    """t08 pin: ensure_fail2ban_host never rewrites a real action body."""
    monkeypatch.setenv("WPFY_TEST_IPV6_CAPABLE", "0")
    from wpfy import fail2ban_docker

    root = f2b_module._fail2ban_root()
    action = root / "action.d" / "wpfy-docker-http.conf"
    action.parent.mkdir(parents=True, exist_ok=True)
    real = fail2ban_docker.action_content(chain="f2b-wpfy-<name>", ipv6=False)
    action.write_text(real, encoding="utf-8")

    state = {"installed": True}
    _binary_present(f2b_module, monkeypatch, state)
    monkeypatch.setattr(
        f2b_module.subprocess,
        "run",
        lambda command, **kwargs: _healthy_run(command, state),
    )

    result = f2b_module.ensure_fail2ban_host()

    assert result.exit_code == 0
    assert action.read_text(encoding="utf-8") == real


def test_action_file_contains_real_body_not_placeholder(f2b_module, monkeypatch):
    """t08 pin: fresh ensure writes the real Docker action, never a stub."""
    monkeypatch.setenv("WPFY_TEST_IPV6_CAPABLE", "0")
    state = {"installed": False}
    _binary_present(f2b_module, monkeypatch, state)
    monkeypatch.setattr(
        f2b_module.subprocess,
        "run",
        lambda command, **kwargs: _healthy_run(command, state),
    )

    result = f2b_module.ensure_fail2ban_host()

    assert result.exit_code == 0
    action = f2b_module._fail2ban_root() / "action.d" / "wpfy-docker-http.conf"
    text = action.read_text(encoding="utf-8")
    assert "Phase 3 will implement" not in text
    assert "iptables -w -N" in text
    assert "DOCKER-USER" in text


def test_admin_jail_conf_never_modified(f2b_module, monkeypatch):
    """t08: /etc/fail2ban/jail.conf is never touched."""
    root = f2b_module._fail2ban_root()
    root.mkdir(parents=True, exist_ok=True)
    jail_conf = root / "jail.conf"
    original = "[DEFAULT]\nbantime = 10m\n[sshd]\nenabled = true\n"
    jail_conf.write_text(original, encoding="utf-8")

    state = {"installed": True}
    _binary_present(f2b_module, monkeypatch, state)
    monkeypatch.setattr(
        f2b_module.subprocess,
        "run",
        lambda command, **kwargs: _healthy_run(command, state),
    )

    result = f2b_module.ensure_fail2ban_host()

    assert result.exit_code == 0
    assert jail_conf.read_text(encoding="utf-8") == original


def test_default_enabled_distro_jails_reported_not_disabled(f2b_module, monkeypatch):
    """t08: default-enabled distro jails are surfaced, never modified."""
    root = f2b_module._fail2ban_root()
    root.mkdir(parents=True, exist_ok=True)
    (root / "jail.d").mkdir(exist_ok=True)
    distro = root / "jail.d" / "sshd.conf"
    distro_content = "[sshd]\nenabled = true\nport = 22\n"
    distro.write_text(distro_content, encoding="utf-8")

    state = {"installed": True}
    _binary_present(f2b_module, monkeypatch, state)
    monkeypatch.setattr(
        f2b_module.subprocess,
        "run",
        lambda command, **kwargs: _healthy_run(command, state),
    )

    result = f2b_module.ensure_fail2ban_host()

    assert result.exit_code == 0
    assert distro.read_text(encoding="utf-8") == distro_content
    assert "sshd" in result.message


def test_wordpress_filter_single_source_of_truth(f2b_module, monkeypatch):
    """t08: the WP filter body is owned by fail2ban_host; site_security delegates."""
    from wpfy import site_security

    assert site_security._fail2ban_filter_content() == f2b_module.wordpress_filter_content()


# ---------------------------------------------------------------------------
# t20 fix: fail2ban 1.0 failure-id contract (shared guard + filter-level
# validation) and ensure_fail2ban_host recovery hardening.
# ---------------------------------------------------------------------------


def test_all_rendered_filters_have_failure_id_groups(f2b_module):
    """Shared guard: every strict failregex carries a failure-id named group.

    This is the check that would have caught the t20 blocker (legacy
    ``(?P<host>...)`` raises RegexException under fail2ban >=1.0). Lines using
    the ``<HOST>`` tag are exempt because fail2ban expands the tag to the
    ip4/ip6/dns named groups at filter load.
    """
    from tests.fail2ban_harness import compile_failregex, failregex_lines

    contents = {
        "panel": f2b_module.panel_filter_content(),
        "wordpress": f2b_module.wordpress_filter_content(),
        "wordpress-auth": f2b_module.wordpress_auth_filter_content(),
    }
    checked = 0
    host_tagged = 0
    for name, content in contents.items():
        patterns = failregex_lines(content)
        assert patterns, f"filter {name} declares no failregex"
        for pattern in patterns:
            if "<HOST>" in pattern:
                host_tagged += 1
                continue
            compile_failregex(pattern)
            checked += 1
    assert checked >= 2, "expected the strict panel + wordpress-auth failregexes to be guarded"
    assert host_tagged >= 1, "expected the nginx backstop <HOST> tag to remain"


def test_legacy_host_group_failregex_rejected_by_shared_guard():
    """The shared guard rejects the exact t20 blocker pattern class."""
    import pytest
    from tests.fail2ban_harness import compile_failregex

    with pytest.raises(AssertionError, match="no failure-id group"):
        compile_failregex(r"^\{.*(?P<host>\d+\.\d+\.\d+\.\d+)\}$")
    with pytest.raises(AssertionError, match="legacy"):
        compile_failregex(r"^(?P<ip4>\d+\.\d+\.\d+\.\d+)|(?P<host>x)$")


def test_render_and_validate_filters_catches_legacy_host_group(f2b_module, monkeypatch):
    """ensure_fail2ban_host filter-level validation rejects a legacy host group.

    This runs in-process before ``fail2ban-client -t`` and before
    ``systemctl enable --now``, closing the -t blind spot.
    """
    legacy = (
        "# Managed by WPFY. Manual changes may be overwritten.\n"
        "[Definition]\n"
        "datepattern = {NONE}\n"
        'failregex = ^\\{.*(?P<host>\\d+\\.\\d+\\.\\d+\\.\\d+).*\\} $\n'
        "ignoreregex =\n\n"
    )
    monkeypatch.setattr(f2b_module, "panel_filter_content", lambda: legacy)
    ok, msg = f2b_module._render_and_validate_filters()
    assert ok is False
    assert "no failure-id group" in msg


def test_render_and_validate_filters_accepts_current_filters(f2b_module):
    ok, msg = f2b_module._render_and_validate_filters()
    assert ok is True, msg


# ---------------------------------------------------------------------------
# Blocker 2: single-logpath jail contract (validate_jail_logpath guard)
# ---------------------------------------------------------------------------


def test_validate_jail_logpath_single_key_passes(f2b_module):
    content = (
        "# Managed by WPFY. Manual changes may be overwritten.\n"
        "[deadbeef]\n"
        "enabled = true\n"
        "filter = wpfy-wordpress\n"
        "logpath = /var/lib/wpfy/sites/a.example.com/security/wp-auth.log\n"
        "backend = auto\n"
    )
    ok, msg = f2b_module.validate_jail_logpath(content)
    assert ok is True, msg


def test_validate_jail_logpath_rejects_duplicate_keys(f2b_module):
    """fail2ban 1.0.2 parser rejects a second 'logpath =' key outright."""
    content = (
        "[deadbeef]\n"
        "enabled = true\n"
        "logpath = /a/wp-auth.log\n"
        "logpath = /b/wpfy-access.log\n"
    )
    ok, msg = f2b_module.validate_jail_logpath(content)
    assert ok is False
    assert "logpath" in msg
    assert "at most one" in msg


def test_validate_jail_logpath_accepts_space_separated_single_value(f2b_module):
    """The only supported multi-path form is one space-separated logpath value."""
    content = (
        "[deadbeef]\n"
        "enabled = true\n"
        "logpath = /a/first.log /b/second.log\n"
    )
    ok, msg = f2b_module.validate_jail_logpath(content)
    assert ok is True, msg


def test_validate_jail_logpath_accepts_one_key_per_jail_section(f2b_module):
    """Per-site jail file holds one section per domain; each may have one
    logpath. The guard must check per section, not per file."""
    content = (
        "[aaaaaaaaaaaaaaaa]\n"
        "enabled = true\n"
        "logpath = /a/wp-auth.log\n"
        "\n"
        "[bbbbbbbbbbbbbbbb]\n"
        "enabled = true\n"
        "logpath = /b/wp-auth.log\n"
    )
    ok, msg = f2b_module.validate_jail_logpath(content)
    assert ok is True, msg


def test_validate_jail_logpath_ignores_comment_lines(f2b_module):
    content = (
        "# logpath = /commented/out.log\n"
        "[deadbeef]\n"
        "logpath = /a/wp-auth.log\n"
    )
    ok, msg = f2b_module.validate_jail_logpath(content)
    assert ok is True, msg


def test_validate_config_rejects_duplicate_logpath_in_managed_jail(f2b_module, monkeypatch):
    """Blocker 2 guard in _validate_config: a WPFY jail file on disk with two
    logpath keys fails validation in-process, BEFORE fail2ban-client -t (which
    alone passes the broken render and only fails at reload)."""
    state = {"installed": True}
    _binary_present(f2b_module, monkeypatch, state)
    root = f2b_module._fail2ban_root()
    (root / "jail.d").mkdir(parents=True, exist_ok=True)
    (root / "jail.d" / "wpfy-wordpress.conf").write_text(
        "# Managed by WPFY. Manual changes may be overwritten.\n"
        "[deadbeef]\n"
        "enabled = true\n"
        "logpath = /a/wp-auth.log\n"
        "logpath = /b/wpfy-access.log\n",
        encoding="utf-8",
    )
    t_calls = []

    def run(command, **kwargs):
        if command == ["fail2ban-client", "-t"]:
            t_calls.append(command)
            return Proc(stdout="config ok")
        return Proc()

    monkeypatch.setattr(f2b_module.subprocess, "run", run)
    ok, msg = f2b_module._validate_config()
    assert ok is False
    assert "logpath" in msg
    assert t_calls == [], "must fail in-process before fail2ban-client -t"


def test_validate_config_accepts_single_logpath_managed_jails(f2b_module, monkeypatch):
    state = {"installed": True}
    _binary_present(f2b_module, monkeypatch, state)

    def run(command, **kwargs):
        if command == ["fail2ban-client", "-t"]:
            return Proc(stdout="config ok")
        return Proc()

    monkeypatch.setattr(f2b_module.subprocess, "run", run)
    ok, msg = f2b_module._validate_config()
    assert ok is True, msg


def test_ping_failure_message_includes_fail2ban_diagnostics(f2b_module, monkeypatch):
    """t20: when the service starts but ping fails, surface journalctl/log tail
    so an operator sees the startup RegexException instead of a bare error."""
    state = {"installed": True}
    _binary_present(f2b_module, monkeypatch, state)

    def run(command, **kwargs):
        if command[0] == "systemctl":
            return Proc(stdout="enabled")
        if command == ["fail2ban-client", "-t"]:
            return Proc(stdout="config ok")
        if command == ["fail2ban-client", "ping"]:
            return Proc(1, stderr="no pong")
        if command[0] == "journalctl":
            return Proc(stdout="ERROR No failure-id group in '^\\{...'")
        if command[0] == "tail":
            return Proc(1, stderr="no such file")
        return Proc()

    monkeypatch.setattr(f2b_module.subprocess, "run", run)
    result = f2b_module.ensure_fail2ban_host()
    assert result.exit_code == 1
    assert "diagnostics" in result.message
    assert "No failure-id group" in result.message


def test_reload_failure_existing_install_recovers_with_restart(f2b_module, monkeypatch):
    """t20: reload failure on an existing install restores the previous config
    and restarts the service so protection is not silently off. F3: a
    successful recovery restart emits login_shield.repaired (outcome ok), never
    login_shield.health_failed with outcome ok."""
    state = {"installed": True}
    calls = []
    _binary_present(f2b_module, monkeypatch, state)
    import wpfy.events as events

    def run(command, **kwargs):
        calls.append(command)
        if command[0] == "systemctl":
            if "restart" in command:
                return Proc(stdout="restarted")
            return Proc(stdout="enabled")
        if command == ["fail2ban-client", "-t"]:
            return Proc(stdout="config ok")
        if command == ["fail2ban-client", "ping"]:
            return Proc(stdout="Server replied: pong")
        if command == ["fail2ban-client", "reload"]:
            return Proc(1, stderr="reload rejected")
        if command == ["fail2ban-client", "version"]:
            return Proc(stdout="1.0.0")
        return Proc()

    monkeypatch.setattr(f2b_module.subprocess, "run", run)
    result = f2b_module.ensure_fail2ban_host()
    assert result.exit_code == 0
    assert result.health_ok is True
    assert "restarted" in result.message
    restarts = [c for c in calls if c[0] == "systemctl" and "restart" in c]
    assert restarts

    repaired = events.list_events(action="login_shield.repaired")
    assert any(e["outcome"] == "ok" and "restarted healthy" in e["detail"] for e in repaired)
    assert not any(
        e["action"] == "login_shield.health_failed" and e["outcome"] == "ok"
        for e in events.list_events()
    )


def test_reload_failure_existing_install_reports_unhealthy_restart(f2b_module, monkeypatch):
    """t20: if the recovery restart does not ping, report failure with detail."""
    state = {"installed": True}
    _binary_present(f2b_module, monkeypatch, state)

    def run(command, **kwargs):
        if command[0] == "systemctl":
            if "restart" in command:
                return Proc(stdout="restarted")
            return Proc(stdout="enabled")
        if command == ["fail2ban-client", "-t"]:
            return Proc(stdout="config ok")
        if command == ["fail2ban-client", "ping"]:
            return Proc(1, stderr="no pong")
        if command == ["fail2ban-client", "reload"]:
            return Proc(1, stderr="reload rejected")
        return Proc()

    monkeypatch.setattr(f2b_module.subprocess, "run", run)
    result = f2b_module.ensure_fail2ban_host()
    assert result.exit_code == 1
    assert result.health_ok is False
    assert "ping failed" in result.message


def test_reload_failure_fresh_install_rolls_back_package(f2b_module, monkeypatch):
    """t20: a fresh install with no prior config rolls back on reload failure."""
    state = {"installed": False}
    removes = []
    _binary_present(f2b_module, monkeypatch, state)

    def run(command, **kwargs):
        if command[0] == "apt-get":
            if "remove" in command:
                removes.append(command)
                state["installed"] = False
                return Proc(stdout="removed")
            state["installed"] = True
            return Proc(stdout="installed")
        if command[0] == "systemctl":
            return Proc(stdout="enabled")
        if command == ["fail2ban-client", "-t"]:
            return Proc(stdout="config ok")
        if command == ["fail2ban-client", "ping"]:
            return Proc(stdout="Server replied: pong")
        if command == ["fail2ban-client", "reload"]:
            return Proc(1, stderr="reload rejected")
        return Proc()

    monkeypatch.setattr(f2b_module.subprocess, "run", run)
    result = f2b_module.ensure_fail2ban_host()
    assert result.exit_code == 1
    assert removes, "fresh install must be removed when reload fails"
