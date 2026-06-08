from __future__ import annotations

import importlib
import stat

import pytest
from wpfy.site_layout import compose_content, SiteSpec


def test_sftp_service_image():
    from wpfy.sftp import _sftp_service_yaml
    yaml = _sftp_service_yaml("example.com")
    assert "image: atmoz/sftp:alpine" in yaml


def test_sftp_service_container_name():
    from wpfy.sftp import _sftp_service_yaml
    yaml = _sftp_service_yaml("example.com")
    assert "container_name: example-com-sftp" in yaml


def test_sftp_service_restart_policy():
    from wpfy.sftp import _sftp_service_yaml
    yaml = _sftp_service_yaml("example.com")
    assert "restart: unless-stopped" in yaml


def test_sftp_service_has_baseline_hardening():
    from wpfy.sftp import _sftp_service_yaml
    yaml = _sftp_service_yaml("example.com")
    assert "security_opt:" in yaml
    assert "no-new-privileges:true" in yaml
    assert "cap_drop:" in yaml
    assert "NET_RAW" in yaml
    assert "pids_limit:" in yaml
    assert "mem_limit:" in yaml
    assert "logging:" in yaml


def test_sftp_service_has_port_mapping():
    from wpfy.sftp import _sftp_service_yaml
    yaml = _sftp_service_yaml("example.com")
    assert '"127.0.0.1:2222:22"' in yaml
    assert '"2222:22"' not in yaml


def test_sftp_service_command_uses_password_env_var():
    from wpfy.sftp import _sftp_service_yaml
    yaml = _sftp_service_yaml("example.com")
    assert "sftpuser:${SFTP_PASSWORD}:1000:1000:app" in yaml


def test_sftp_service_has_networks():
    from wpfy.sftp import _sftp_service_yaml
    yaml = _sftp_service_yaml("example.com")
    assert "networks:" in yaml
    assert "site" in yaml


def test_sftp_service_has_volume():
    from wpfy.sftp import _sftp_service_yaml
    yaml = _sftp_service_yaml("example.com")
    assert "volumes:" in yaml
    assert "./app:/home/sftpuser/app" in yaml


def test_ensure_sftp_container_invalid_domain():
    from wpfy.sftp import ensure_sftp_container
    result = ensure_sftp_container("invalid domain")
    assert result.exit_code == 2


def test_sftp_domain_with_hyphen_converts_to_project():
    from wpfy.sftp import _sftp_service_yaml
    yaml = _sftp_service_yaml("my-site.org")
    assert "container_name: my-site-org-sftp" in yaml


def test_sftp_ensure_compose_has_sftp_false_when_absent(tmp_wpfy_home, monkeypatch):
    from wpfy.sftp import _compose_has_sftp
    from pathlib import Path

    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    domain = "nosftp.com"
    site_dir = Path(tmp_wpfy_home.sites_dir) / domain
    site_dir.mkdir(parents=True, exist_ok=True)

    spec = SiteSpec(domain=domain, flavor="wp", use_mysql=True, use_redis=False, site_uid=100000)
    (site_dir / "compose.yaml").write_text(compose_content(spec), encoding="utf-8")

    assert _compose_has_sftp(domain) is False


def test_sftp_redact_secrets_hides_password():
    from wpfy.sftp import _redact_secrets
    text = "SFTP_PASSWORD=mysecret123pass"
    result = _redact_secrets(text)
    assert "mysecret123pass" not in result
    assert "***REDACTED***" in result


def test_sftp_redact_secrets_handles_colon_delimiter():
    from wpfy.sftp import _redact_secrets
    text = "SFTP_PASSWORD: mysecret456pass"
    result = _redact_secrets(text)
    assert "mysecret456pass" not in result
    assert "***REDACTED***" in result


def test_sftp_redact_secrets_preserves_other_text():
    from wpfy.sftp import _redact_secrets
    text = "container=sftp  SFTP_PASSWORD=abc123  status=running"
    result = _redact_secrets(text)
    assert "container=sftp" in result
    assert "status=running" in result
    assert "abc123" not in result


def test_sftp_redact_secrets_no_password():
    from wpfy.sftp import _redact_secrets
    text = "no secrets here"
    result = _redact_secrets(text)
    assert result == text


def test_sftp_status_invalid_domain(monkeypatch):
    from wpfy.sftp import sftp_status
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    result = sftp_status("invalid domain")
    assert result.exit_code == 2


def test_sftp_status_does_not_print_password_field(tmp_path, monkeypatch):
    from wpfy.sftp import sftp_status

    domain = "sftp-status.example.com"
    site_root = tmp_path / domain
    site_root.mkdir(parents=True, exist_ok=True)
    spec = SiteSpec(domain=domain, flavor="html", use_mysql=False, use_redis=False, site_uid=100000)
    (site_root / "compose.yaml").write_text(compose_content(spec) + "\n  sftp:\n", encoding="utf-8")
    (site_root / ".env").write_text("SFTP_PASSWORD=secret\nSFTP_PORT=2225\n", encoding="utf-8")
    monkeypatch.setattr("wpfy.sftp.site_exists", lambda value: value == domain)
    monkeypatch.setattr("wpfy.sftp.compose_path", lambda value: site_root / "compose.yaml")
    monkeypatch.setattr("wpfy.sftp.env_path", lambda value: site_root / ".env")

    class Proc:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr("wpfy.sftp.compose_command", lambda *args: Proc())

    result = sftp_status(domain)

    assert result.exit_code == 0
    assert "password configured: True" in result.message
    assert "port: 2225" in result.message
    assert "secret" not in result.message
    assert "password:" not in result.message


def test_ensure_sftp_container_waits_for_port_when_restarting(tmp_path, monkeypatch):
    from wpfy.sftp import ensure_sftp_container

    domain = "sftp-wait.example.com"
    site_root = tmp_path / domain
    site_root.mkdir(parents=True, exist_ok=True)
    spec = SiteSpec(domain=domain, flavor="html", use_mysql=False, use_redis=False, site_uid=100000)
    (site_root / "compose.yaml").write_text(compose_content(spec) + "\n  sftp:\n", encoding="utf-8")
    (site_root / ".env").write_text("SFTP_PASSWORD=secret\nSFTP_PORT=2226\n", encoding="utf-8")
    monkeypatch.setattr("wpfy.sftp.site_exists", lambda value: value == domain)
    monkeypatch.setattr("wpfy.sftp.compose_path", lambda value: site_root / "compose.yaml")
    monkeypatch.setattr("wpfy.sftp.env_path", lambda value: site_root / ".env")

    class Proc:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr("wpfy.sftp.compose_command", lambda *args: Proc())
    monkeypatch.setattr("wpfy.sftp._wait_for_sftp_port", lambda host_port="2222": False)

    result = ensure_sftp_container(domain)

    assert result.exit_code == 1
    assert "port 2226 is not ready" in result.message


def test_ensure_sftp_container_writes_private_env_and_loopback_port(tmp_wpfy_home, monkeypatch):
    import wpfy.sftp
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    importlib.reload(wpfy.sftp)
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    monkeypatch.setattr(wpfy.sftp, "_wait_for_sftp_port", lambda host_port="2222": True)

    class Proc:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr(wpfy.sftp, "compose_command", lambda *args: Proc())

    spec = wpfy.site_layout.SiteSpec(domain="sftp-new.example.com", flavor="html", use_mysql=False, use_redis=False)
    wpfy.site_layout.ensure_site_scaffold(spec)

    result = wpfy.sftp.ensure_sftp_container("sftp-new.example.com", password="custom-secret")

    env_file = wpfy.site_layout.env_path("sftp-new.example.com")
    env_text = env_file.read_text(encoding="utf-8")
    compose_text = wpfy.site_layout.compose_path("sftp-new.example.com").read_text(encoding="utf-8")
    assert result.exit_code == 0
    assert "SFTP_PASSWORD=custom-secret" in env_text
    assert "SFTP_PORT=2222" in env_text
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o600
    assert '"127.0.0.1:2222:22"' in compose_text
    assert '"2222:22"' not in compose_text


def test_ensure_sftp_container_reuses_existing_port_without_duplicate_block(tmp_wpfy_home, monkeypatch):
    import wpfy.sftp
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    importlib.reload(wpfy.sftp)
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    monkeypatch.setattr(wpfy.sftp, "_wait_for_sftp_port", lambda host_port="2222": True)

    class Proc:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr(wpfy.sftp, "compose_command", lambda *args: Proc())

    spec = wpfy.site_layout.SiteSpec(domain="sftp-reuse.example.com", flavor="html", use_mysql=False, use_redis=False)
    wpfy.site_layout.ensure_site_scaffold(spec)
    env_file = wpfy.site_layout.env_path("sftp-reuse.example.com")
    env_file.write_text(env_file.read_text(encoding="utf-8") + "SFTP_PASSWORD=secret\nSFTP_PORT=2230\n", encoding="utf-8")
    wpfy.site_layout.compose_path("sftp-reuse.example.com").write_text(
        wpfy.site_layout.compose_path("sftp-reuse.example.com").read_text(encoding="utf-8")
        + wpfy.sftp._sftp_service_yaml("sftp-reuse.example.com", "2230")
        + "\n",
        encoding="utf-8",
    )

    result = wpfy.sftp.ensure_sftp_container("sftp-reuse.example.com")

    compose_text = wpfy.site_layout.compose_path("sftp-reuse.example.com").read_text(encoding="utf-8")
    assert result.exit_code == 0
    assert "SFTP_PORT=2230" in env_file.read_text(encoding="utf-8")
    assert compose_text.count("  sftp:") == 1


def test_ensure_sftp_container_repairs_partial_sftp_public_binding(tmp_wpfy_home, monkeypatch):
    import wpfy.sftp
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    importlib.reload(wpfy.sftp)
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    monkeypatch.setattr(wpfy.sftp, "_wait_for_sftp_port", lambda host_port="2222": True)

    class Proc:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr(wpfy.sftp, "compose_command", lambda *args: Proc())

    domain = "sftp-partial.example.com"
    spec = wpfy.site_layout.SiteSpec(domain=domain, flavor="html", use_mysql=False, use_redis=False)
    wpfy.site_layout.ensure_site_scaffold(spec)
    compose_file = wpfy.site_layout.compose_path(domain)
    compose_file.write_text(
        compose_file.read_text(encoding="utf-8")
        + wpfy.sftp._sftp_service_yaml(domain).replace("127.0.0.1:2222:22", "2222:22")
        + "\n",
        encoding="utf-8",
    )

    result = wpfy.sftp.ensure_sftp_container(domain, password="custom-secret")

    compose_text = compose_file.read_text(encoding="utf-8")
    env_text = wpfy.site_layout.env_path(domain).read_text(encoding="utf-8")
    assert result.exit_code == 0
    assert "SFTP_PASSWORD=custom-secret" in env_text
    assert "SFTP_PORT=2222" in env_text
    assert '"127.0.0.1:2222:22"' in compose_text
    assert '"2222:22"' not in compose_text
    assert compose_text.count("  sftp:") == 1


def test_sftp_port_allocation_skips_other_site_ports(tmp_wpfy_home, monkeypatch):
    import wpfy.sftp
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    importlib.reload(wpfy.sftp)
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    monkeypatch.setattr(wpfy.sftp, "_port_available", lambda port: True)
    monkeypatch.setattr(wpfy.sftp, "_wait_for_sftp_port", lambda host_port="2222": True)

    class Proc:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr(wpfy.sftp, "compose_command", lambda *args: Proc())

    for domain in ("one.example.com", "two.example.com"):
        spec = wpfy.site_layout.SiteSpec(domain=domain, flavor="html", use_mysql=False, use_redis=False)
        wpfy.site_layout.ensure_site_scaffold(spec)

    first = wpfy.sftp.ensure_sftp_container("one.example.com")
    second = wpfy.sftp.ensure_sftp_container("two.example.com")

    first_env = wpfy.site_layout.read_env(wpfy.site_layout.env_path("one.example.com"))
    second_env = wpfy.site_layout.read_env(wpfy.site_layout.env_path("two.example.com"))
    assert first.exit_code == 0
    assert second.exit_code == 0
    assert first_env["SFTP_PORT"] == "2222"
    assert second_env["SFTP_PORT"] == "2223"


def test_remove_sftp_regenerates_all_persisted_state(tmp_wpfy_home, monkeypatch):
    import wpfy.registry
    import wpfy.sftp
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    importlib.reload(wpfy.sftp)

    class Proc:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr(wpfy.sftp, "compose_command", lambda *args: Proc())
    domain = "sftp-remove.example.com"
    definition = wpfy.site_layout.SiteSpec(
        domain=domain,
        flavor="html",
        use_mysql=False,
        use_redis=False,
        sftp_password="secret",
        sftp_port="2240",
    )
    wpfy.site_layout.ensure_site_scaffold(definition)

    result = wpfy.sftp.remove_sftp_container(domain)

    compose = wpfy.site_layout.compose_path(domain).read_text(encoding="utf-8")
    env = wpfy.site_layout.env_path(domain).read_text(encoding="utf-8")
    metadata = wpfy.registry.get_site(domain)
    assert result.exit_code == 0
    assert "  sftp:" not in compose
    assert "SFTP_PASSWORD" not in env
    assert "SFTP_PORT" not in env
    assert "sftp_enabled" not in metadata
