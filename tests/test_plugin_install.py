from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import urllib.error
import zipfile

import pytest

import wpfy.plugin_install as plugin_install
import wpfy.site_security as site_security
from wpfy.site_runtime import ProcessResult


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def plugin_env(tmp_wpfy_home, monkeypatch):
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    monkeypatch.setenv("WPFY_TEST_TRAEFIK_NETWORK_CIDRS", "172.18.0.0/16")
    import wpfy.site_layout

    return wpfy.site_layout, site_security, plugin_install


def _site(layout, domain="shield-a.example.com"):
    layout.ensure_site_scaffold(
        layout.SiteSpec(domain=domain, flavor="wp", use_mysql=True, use_redis=False),
    )
    return layout.site_dir(domain)


PLUGIN_FILES = {
    "wp-fail2ban.php": b"<?php /* Plugin Name: WP fail2ban */ Version: 5.4.1",
    "lib/syslog.php": b"<?php /* syslog bridge */",
    "readme.txt": b"=== WP fail2ban ===\nStable tag: 5.4.1\n",
}


def plugin_zip_bytes(tamper: bool = False) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in PLUGIN_FILES.items():
            archive.writestr(name, b"EVIL" + data if tamper and name == "wp-fail2ban.php" else data)
    return buffer.getvalue()


def checksum_payload(zip_bytes: bytes) -> dict:
    files = {
        name: {
            "md5": hashlib.md5(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        for name, data in PLUGIN_FILES.items()
    }
    return {
        "plugin": "wp-fail2ban",
        "version": "5.4.1",
        "source": {"plugin": "https://plugins.svn.wordpress.org/wp-fail2ban/trunk/", "status": "latest"},
        "zip": {
            plugin_install.WP_FAIL2BAN_ZIP_URL: {
                "md5": hashlib.md5(zip_bytes).hexdigest(),
                "sha256": hashlib.sha256(zip_bytes).hexdigest(),
            }
        },
        "files": files,
    }


def array_checksum_payload(zip_bytes: bytes, *, match_second: bool = True) -> dict:
    """checksum_payload with per-file md5/sha256 emitted as hash ARRAYS.

    WordPress.org repack detection (wp-fail2ban 5.4.1) lists multiple
    acceptable hashes per file. match_second=True places the real digest in
    the second slot to mirror the live t21 evidence.
    """
    payload = checksum_payload(zip_bytes)
    for entry in payload["files"].values():
        for field in ("md5", "sha256"):
            real = entry[field]
            decoy = "0" * len(real)
            entry[field] = [decoy, real] if match_second else [real, decoy]
    return payload


class _FakeResponse:
    def __init__(self, data: bytes):
        self._data = data

    def read(self) -> bytes:
        return self._data

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def fake_urlopen_factory(payload: dict, zip_bytes: bytes, *, manifest_error=None, zip_error=None):
    def opener(url, timeout=None):
        if url == plugin_install.WP_FAIL2BAN_CHECKSUM_URL:
            if manifest_error is not None:
                raise urllib.error.URLError(manifest_error)
            return _FakeResponse(json.dumps(payload).encode("utf-8"))
        if url == plugin_install.WP_FAIL2BAN_ZIP_URL:
            if zip_error is not None:
                raise urllib.error.URLError(zip_error)
            return _FakeResponse(zip_bytes)
        raise AssertionError(f"unexpected url requested: {url}")

    return opener


class FakeWpCli:
    """Stateful stand-in for wpfy.site_runtime.run_wp_cli."""

    def __init__(self, *, skip: bool = False):
        self.calls: list[tuple[str, tuple[str, ...]]] = []
        self.skip = skip
        self.installed = False
        self.active = False
        self.version = "5.4.1"
        self.auto_updates_off = False
        self.install_fails = False
        self.activate_fails = False
        self.deactivate_fails = False

    def __call__(self, domain, *args, **kwargs):
        self.calls.append((domain, args))
        if self.skip:
            return ProcessResult(1, skipped=True)
        command = list(args)
        if command[:2] == ["plugin", "get"]:
            if not self.installed:
                return ProcessResult(1, stderr="Error: Plugin 'wp-fail2ban' not found.")
            field = command[-1]
            if field == "--field=status":
                return ProcessResult(0, stdout="active\n" if self.active else "inactive\n")
            if field == "--field=version":
                return ProcessResult(0, stdout=f"{self.version}\n")
            return ProcessResult(0, stdout="")
        if command[:2] == ["plugin", "install"]:
            if self.install_fails:
                return ProcessResult(1, stderr="download failed")
            self.installed = True
            self.active = False
            return ProcessResult(0, stdout="Installing... Success")
        if command[:2] == ["plugin", "activate"]:
            if self.activate_fails:
                return ProcessResult(1, stderr="activate failed")
            self.active = True
            return ProcessResult(0, stdout="Plugin 'wp-fail2ban' activated.")
        if command[:2] == ["plugin", "deactivate"]:
            if self.deactivate_fails:
                return ProcessResult(1, stderr="deactivate failed")
            self.active = False
            return ProcessResult(0, stdout="Plugin 'wp-fail2ban' deactivated.")
        if command[:2] == ["plugin", "auto-updates"] and len(command) >= 3 and command[2] == "disable":
            self.auto_updates_off = True
            return ProcessResult(0, stdout="Success")
        return ProcessResult(0, stdout="ok")


def _seed_ownership(security, domain, *, ownership, active=False, version="5.4.1"):
    config = security.load_security(domain)
    config["fail2ban_plugin"] = {
        "slug": "wp-fail2ban",
        "version": version,
        "ownership": ownership,
        "auto_updates_disabled": False,
        "active": active,
    }
    security.save_security(domain, config)


def _install_args(fake: FakeWpCli, domain: str) -> list[tuple[str, ...]]:
    return [args for seen_domain, args in fake.calls if seen_domain == domain and args[0] == "plugin"]


# ---------------------------------------------------------------------------
# Two-site isolation
# ---------------------------------------------------------------------------


def test_install_into_site_a_leaves_site_b_unchanged(plugin_env, monkeypatch):
    layout, security, plugin = plugin_env
    domain_a = "shield-a.example.com"
    domain_b = "shield-b.example.com"
    site_a = _site(layout, domain_a)
    site_b = _site(layout, domain_b)

    zip_bytes = plugin_zip_bytes()
    monkeypatch.setattr(
        plugin.urllib.request,
        "urlopen",
        fake_urlopen_factory(checksum_payload(zip_bytes), zip_bytes),
    )
    fake = FakeWpCli()
    monkeypatch.setattr(plugin, "run_wp_cli", fake)

    result = plugin.install_wp_fail2ban(domain_a)

    assert result.exit_code == 0
    assert result.ownership == "wpfy-installed"
    state_a = security.load_security(domain_a)
    assert state_a["fail2ban_plugin"] == {
        "slug": "wp-fail2ban",
        "version": "5.4.1",
        "ownership": "wpfy-installed",
        "auto_updates_disabled": True,
        "active": True,
    }
    assert not (site_b / security.SECURITY_STATE).exists()
    assert all(seen_domain != domain_b for seen_domain, _ in fake.calls)
    assert fake.installed is True
    assert fake.active is True
    assert fake.auto_updates_off is True
    install_command = [args for args in _install_args(fake, domain_a) if args[:2] == ("plugin", "install")]
    assert install_command
    assert "/security/wp-fail2ban-5.4.1.zip" in install_command[0]
    staged = site_a / "security" / "wp-fail2ban-5.4.1.zip"
    assert staged.is_file()
    assert hashlib.sha256(staged.read_bytes()).hexdigest() == hashlib.sha256(zip_bytes).hexdigest()


def test_install_is_idempotent_and_keeps_recorded_ownership(plugin_env, monkeypatch):
    layout, security, plugin = plugin_env
    domain = "shield-a.example.com"
    _site(layout, domain)
    zip_bytes = plugin_zip_bytes()
    monkeypatch.setattr(
        plugin.urllib.request,
        "urlopen",
        fake_urlopen_factory(checksum_payload(zip_bytes), zip_bytes),
    )
    fake = FakeWpCli()
    monkeypatch.setattr(plugin, "run_wp_cli", fake)

    first = plugin.install_wp_fail2ban(domain)
    second = plugin.install_wp_fail2ban(domain)

    assert first.exit_code == second.exit_code == 0
    state = security.load_security(domain)
    assert state["fail2ban_plugin"]["ownership"] == "wpfy-installed"
    install_runs = [args for args in _install_args(fake, domain) if args[:2] == ("plugin", "install")]
    assert len(install_runs) == 1


# ---------------------------------------------------------------------------
# Ownership state transitions
# ---------------------------------------------------------------------------


def test_admin_installed_plugin_is_preserved_on_deactivate(plugin_env, monkeypatch):
    layout, security, plugin = plugin_env
    domain = "shield-a.example.com"
    _site(layout, domain)
    _seed_ownership(security, domain, ownership="admin-installed", active=False)
    fake = FakeWpCli()
    fake.installed = True
    fake.active = False
    monkeypatch.setattr(plugin, "run_wp_cli", fake)

    result = plugin.deactivate_wp_fail2ban(domain)

    assert result.exit_code == 0
    assert result.changed is False
    assert "preserved" in result.message
    assert all("deactivate" not in args for _, args in fake.calls)
    assert security.load_security(domain)["fail2ban_plugin"]["active"] is False


def test_already_active_plugin_is_preserved_on_deactivate(plugin_env, monkeypatch):
    layout, security, plugin = plugin_env
    domain = "shield-a.example.com"
    _site(layout, domain)
    _seed_ownership(security, domain, ownership="already-active", active=True)
    fake = FakeWpCli()
    fake.installed = True
    fake.active = True
    monkeypatch.setattr(plugin, "run_wp_cli", fake)

    result = plugin.deactivate_wp_fail2ban(domain)

    assert result.exit_code == 0
    assert result.changed is False
    assert all("deactivate" not in args for _, args in fake.calls)
    assert security.load_security(domain)["fail2ban_plugin"]["active"] is True


def test_wpfy_installed_plugin_is_deactivated_on_disable(plugin_env, monkeypatch):
    layout, security, plugin = plugin_env
    domain = "shield-a.example.com"
    _site(layout, domain)
    _seed_ownership(security, domain, ownership="wpfy-installed", active=True)
    fake = FakeWpCli()
    fake.installed = True
    fake.active = True
    monkeypatch.setattr(plugin, "run_wp_cli", fake)

    result = plugin.deactivate_wp_fail2ban(domain)

    assert result.exit_code == 0
    assert result.changed is True
    assert any("deactivate" in args for _, args in fake.calls)
    state = security.load_security(domain)
    assert state["fail2ban_plugin"]["ownership"] == "wpfy-installed"
    assert state["fail2ban_plugin"]["active"] is False


def test_activated_by_wpfy_plugin_is_deactivated_on_disable(plugin_env, monkeypatch):
    layout, security, plugin = plugin_env
    domain = "shield-a.example.com"
    _site(layout, domain)
    _seed_ownership(security, domain, ownership="activated-by-wpfy", active=True)
    fake = FakeWpCli()
    fake.installed = True
    fake.active = True
    monkeypatch.setattr(plugin, "run_wp_cli", fake)

    result = plugin.deactivate_wp_fail2ban(domain)

    assert result.exit_code == 0
    assert result.changed is True
    assert any("deactivate" in args for _, args in fake.calls)
    assert security.load_security(domain)["fail2ban_plugin"]["active"] is False


def test_admin_installed_plugin_activated_by_wpfy_records_activated_by_wpfy(plugin_env, monkeypatch):
    layout, security, plugin = plugin_env
    domain = "shield-a.example.com"
    _site(layout, domain)
    fake = FakeWpCli()
    fake.installed = True
    fake.active = False
    monkeypatch.setattr(plugin, "run_wp_cli", fake)

    result = plugin.install_wp_fail2ban(domain)

    assert result.exit_code == 0
    assert result.ownership == "activated-by-wpfy"
    state = security.load_security(domain)["fail2ban_plugin"]
    assert state["ownership"] == "activated-by-wpfy"
    assert state["active"] is True
    assert state["auto_updates_disabled"] is True
    assert fake.active is True
    assert any("activate" in args for _, args in fake.calls)


def test_already_active_plugin_keeps_admin_auto_update_policy(plugin_env, monkeypatch):
    layout, security, plugin = plugin_env
    domain = "shield-a.example.com"
    _site(layout, domain)
    fake = FakeWpCli()
    fake.installed = True
    fake.active = True
    monkeypatch.setattr(plugin, "run_wp_cli", fake)

    result = plugin.install_wp_fail2ban(domain)

    assert result.exit_code == 0
    assert result.ownership == "already-active"
    state = security.load_security(domain)["fail2ban_plugin"]
    assert state["ownership"] == "already-active"
    assert state["auto_updates_disabled"] is False
    assert fake.auto_updates_off is False


def test_version_mismatch_is_recorded_not_silently_overwritten(plugin_env, monkeypatch):
    layout, security, plugin = plugin_env
    domain = "shield-a.example.com"
    _site(layout, domain)
    fake = FakeWpCli()
    fake.installed = True
    fake.active = True
    fake.version = "5.4.0"
    monkeypatch.setattr(plugin, "run_wp_cli", fake)

    result = plugin.install_wp_fail2ban(domain)

    assert result.exit_code == 0
    assert security.load_security(domain)["fail2ban_plugin"]["version"] == "5.4.0"
    assert "5.4.0" in result.message


# ---------------------------------------------------------------------------
# Integrity verification
# ---------------------------------------------------------------------------


def test_integrity_verify_accepts_matching_archive_and_rejects_tampered(plugin_env):
    _layout, _security, plugin = plugin_env
    good = plugin_zip_bytes()
    payload = checksum_payload(good)
    temp = Path(plugin._current_paths().tmp_dir)
    temp.mkdir(parents=True, exist_ok=True)
    good_zip = temp / "good.zip"
    good_zip.write_bytes(good)
    bad_zip = temp / "bad.zip"
    bad_zip.write_bytes(plugin_zip_bytes(tamper=True))

    verified = plugin.verify_plugin_zip(good_zip, payload)
    assert verified.verified is True
    assert verified.file_count == len(PLUGIN_FILES)
    assert verified.zip_sha256 == hashlib.sha256(good).hexdigest()

    tampered = plugin.verify_plugin_zip(bad_zip, payload)
    assert tampered.verified is False
    assert tampered.errors


def _tmp_zip(plugin, data: bytes) -> Path:
    temp = Path(plugin._current_paths().tmp_dir)
    temp.mkdir(parents=True, exist_ok=True)
    path = temp / "schema.zip"
    path.write_bytes(data)
    return path


def test_integrity_verify_accepts_single_string_hashes(plugin_env):
    _layout, _security, plugin = plugin_env
    good = plugin_zip_bytes()
    verified = plugin.verify_plugin_zip(_tmp_zip(plugin, good), checksum_payload(good))
    assert verified.verified is True
    assert verified.file_count == len(PLUGIN_FILES)


def test_integrity_verify_accepts_array_hashes_matching_any(plugin_env):
    _layout, _security, plugin = plugin_env
    good = plugin_zip_bytes()
    # Real digest is the 2nd accepted hash (t21 live evidence shape).
    verified = plugin.verify_plugin_zip(_tmp_zip(plugin, good), array_checksum_payload(good, match_second=True))
    assert verified.verified is True
    # Real digest as the 1st accepted hash also matches.
    verified_first = plugin.verify_plugin_zip(_tmp_zip(plugin, good), array_checksum_payload(good, match_second=False))
    assert verified_first.verified is True


def test_integrity_verify_array_hashes_no_match_fails_closed(plugin_env):
    _layout, _security, plugin = plugin_env
    good = plugin_zip_bytes()
    bad = plugin_zip_bytes(tamper=True)
    # Tampered archive: computed digest matches NO entry in any array.
    refused = plugin.verify_plugin_zip(_tmp_zip(plugin, bad), array_checksum_payload(good))
    assert refused.verified is False
    assert any("mismatch" in error for error in refused.errors)


def test_integrity_verify_mixed_string_and_array_hashes(plugin_env):
    _layout, _security, plugin = plugin_env
    good = plugin_zip_bytes()
    payload = checksum_payload(good)
    entry = payload["files"]["wp-fail2ban.php"]
    entry["md5"] = ["0" * 32, entry["md5"]]
    entry["sha256"] = ["0" * 64, entry["sha256"]]
    # lib/syslog.php + readme.txt remain plain strings.
    verified = plugin.verify_plugin_zip(_tmp_zip(plugin, good), payload)
    assert verified.verified is True


def test_integrity_verify_malformed_hash_value_fails_closed(plugin_env):
    _layout, _security, plugin = plugin_env
    good = plugin_zip_bytes()
    payload = checksum_payload(good)
    payload["files"]["readme.txt"]["md5"] = {"unexpected": "schema drift"}
    payload["files"]["lib/syslog.php"]["sha256"] = 12345
    refused = plugin.verify_plugin_zip(_tmp_zip(plugin, good), payload)
    assert refused.verified is False
    assert any("malformed" in error for error in refused.errors)


def test_integrity_verify_member_not_in_manifest_fails_closed(plugin_env):
    _layout, _security, plugin = plugin_env
    good = plugin_zip_bytes()
    payload = checksum_payload(good)
    del payload["files"]["readme.txt"]
    refused = plugin.verify_plugin_zip(_tmp_zip(plugin, good), payload)
    assert refused.verified is False
    assert any("unexpected file" in error for error in refused.errors)


def test_integrity_member_not_in_manifest_records_no_evidence_risk(plugin_env, monkeypatch):
    layout, security, plugin = plugin_env
    domain = "shield-a.example.com"
    _site(layout, domain)
    zip_bytes = plugin_zip_bytes()
    payload = checksum_payload(zip_bytes)
    del payload["files"]["readme.txt"]
    monkeypatch.setattr(
        plugin.urllib.request,
        "urlopen",
        fake_urlopen_factory(payload, zip_bytes),
    )
    fake = FakeWpCli()
    monkeypatch.setattr(plugin, "run_wp_cli", fake)

    result = plugin.install_wp_fail2ban(domain)

    assert result.exit_code != 0
    assert "unexpected file" in result.integrity_risk
    assert all(args[:2] != ("plugin", "install") for _, args in fake.calls)
    manifest = plugin.load_plugin_manifest()
    assert manifest["verified"] is False
    assert "risk" in manifest


def test_integrity_checksum_fetch_failure_records_no_evidence_risk(plugin_env, monkeypatch):
    layout, security, plugin = plugin_env
    domain = "shield-a.example.com"
    _site(layout, domain)
    monkeypatch.setattr(
        plugin.urllib.request,
        "urlopen",
        fake_urlopen_factory({}, b"", manifest_error=urllib.error.URLError("network down")),
    )
    fake = FakeWpCli()
    monkeypatch.setattr(plugin, "run_wp_cli", fake)

    result = plugin.install_wp_fail2ban(domain)

    assert result.exit_code != 0
    assert result.integrity_risk and "fetch failed" in result.integrity_risk
    assert all("install" not in args or args[0] != "plugin" or args[1] != "install"
               for _, args in fake.calls)
    manifest = plugin.load_plugin_manifest()
    assert manifest is not None
    assert manifest["verified"] is False
    assert "risk" in manifest
    assert not (layout.site_dir(domain) / "security" / "wp-fail2ban-5.4.1.zip").exists()


def test_integrity_tampered_archive_refuses_install(plugin_env, monkeypatch):
    layout, security, plugin = plugin_env
    domain = "shield-a.example.com"
    _site(layout, domain)
    tampered = plugin_zip_bytes(tamper=True)
    monkeypatch.setattr(
        plugin.urllib.request,
        "urlopen",
        fake_urlopen_factory(checksum_payload(plugin_zip_bytes()), tampered),
    )
    fake = FakeWpCli()
    monkeypatch.setattr(plugin, "run_wp_cli", fake)

    result = plugin.install_wp_fail2ban(domain)

    assert result.exit_code != 0
    assert result.integrity_risk
    assert all(args[:2] != ("plugin", "install") for _, args in fake.calls)
    manifest = plugin.load_plugin_manifest()
    assert manifest["verified"] is False
    assert not security.load_security(domain)["fail2ban_plugin"]["ownership"]


# ---------------------------------------------------------------------------
# Missing binary / offline-safe behavior
# ---------------------------------------------------------------------------


def test_install_skipped_when_runtime_unavailable(plugin_env):
    layout, security, plugin = plugin_env
    domain = "shield-a.example.com"
    _site(layout, domain)

    result = plugin.install_wp_fail2ban(domain)

    assert result.exit_code == 0
    assert result.skipped is True
    assert not (layout.site_dir(domain) / security.SECURITY_STATE).exists()
    assert plugin.load_plugin_manifest() is None


def test_deactivate_skipped_when_runtime_unavailable(plugin_env):
    layout, security, plugin = plugin_env
    domain = "shield-a.example.com"
    _site(layout, domain)
    _seed_ownership(security, domain, ownership="wpfy-installed", active=True)

    result = plugin.deactivate_wp_fail2ban(domain)

    assert result.exit_code == 0
    assert result.skipped is True
    assert security.load_security(domain)["fail2ban_plugin"]["active"] is True


def test_install_refuses_missing_site(plugin_env):
    _layout, _security, plugin = plugin_env

    result = plugin.install_wp_fail2ban("no-such-site.example.com")

    assert result.exit_code != 0
    assert "site not found" in result.message


def test_deactivate_never_uninstalls(plugin_env, monkeypatch):
    layout, security, plugin = plugin_env
    domain = "shield-a.example.com"
    _site(layout, domain)
    _seed_ownership(security, domain, ownership="wpfy-installed", active=True)
    fake = FakeWpCli()
    fake.installed = True
    fake.active = True
    monkeypatch.setattr(plugin, "run_wp_cli", fake)

    result = plugin.deactivate_wp_fail2ban(domain)

    assert result.exit_code == 0
    assert all("uninstall" not in args for _, args in fake.calls)
    assert fake.installed is True
