from __future__ import annotations

import pytest
from wpfy.traefik import (
    traefik_compose_content,
    traefik_static_config,
    TRAEFIK_IMAGE,
    TRAEFIK_NETWORK,
    TRAEFIK_CONTAINER,
    TRAEFIK_PROJECT,
    ensure_traefik_scaffold,
    ensure_traefik_network,
    traefik_network_cidrs,
    traefik_status,
)
from wpfy.site_layout import RuntimeResult


def test_traefik_compose_content_has_name():
    content = traefik_compose_content()
    assert f"name: {TRAEFIK_PROJECT}" in content


def test_traefik_compose_content_has_services():
    content = traefik_compose_content()
    assert "services:" in content
    assert "  traefik:" in content


def test_traefik_compose_content_has_correct_image():
    content = traefik_compose_content()
    assert f"image: {TRAEFIK_IMAGE}" in content


def test_traefik_compose_content_has_container_name():
    content = traefik_compose_content()
    assert f"container_name: {TRAEFIK_CONTAINER}" in content


def test_traefik_compose_content_has_restart_policy():
    content = traefik_compose_content()
    assert "restart: unless-stopped" in content


def test_traefik_compose_content_has_baseline_hardening():
    content = traefik_compose_content()
    assert "security_opt:" in content
    assert "no-new-privileges:true" in content
    assert "cap_drop:" in content
    assert "NET_RAW" in content
    assert "pids_limit:" in content
    assert "mem_limit:" in content
    assert "logging:" in content
    assert "healthcheck:" in content


def test_traefik_compose_content_has_ports():
    content = traefik_compose_content()
    assert '"80:80"' in content
    assert '"443:443"' in content


def test_traefik_compose_content_has_volumes():
    content = traefik_compose_content()
    assert "volumes:" in content
    assert "/var/run/docker.sock:/var/run/docker.sock:ro" in content
    assert "letsencrypt_data:" in content


def test_traefik_compose_content_has_network():
    content = traefik_compose_content()
    assert f"{TRAEFIK_NETWORK}:" in content
    assert "external: true" in content


def test_traefik_compose_content_has_no_acme_command():
    content = traefik_compose_content()
    assert "certificatesresolvers.le.acme" not in content


def test_traefik_static_config_has_api(tmp_wpfy_home):
    config = traefik_static_config()
    assert "api:" in config
    assert "dashboard: false" in config


def test_traefik_static_config_has_ping(tmp_wpfy_home):
    config = traefik_static_config()
    assert "ping: {}" in config


def test_traefik_static_config_has_entrypoints(tmp_wpfy_home):
    config = traefik_static_config()
    assert "entryPoints:" in config
    assert 'address: ":80"' in config
    assert 'address: ":443"' in config


def test_traefik_static_config_has_providers(tmp_wpfy_home):
    config = traefik_static_config()
    assert "providers:" in config
    assert "docker:" in config
    assert "exposedByDefault: false" in config
    assert f"network: {TRAEFIK_NETWORK}" in config


def test_traefik_static_config_has_acme_resolver(tmp_wpfy_home, monkeypatch):
    monkeypatch.setenv("WPFY_ACME_EMAIL", "ops@example.com")
    config = traefik_static_config()
    assert "certificatesResolvers:" in config
    assert "  le:" in config
    assert "    acme:" in config
    assert '      email: "ops@example.com"' in config
    assert "      storage: /letsencrypt/acme.json" in config
    assert "      tlsChallenge: {}" in config


def test_traefik_static_config_has_http_challenge_resolver(tmp_wpfy_home):
    config = traefik_static_config()
    assert "  le-http:" in config
    assert "      httpChallenge:" in config
    assert "        entryPoint: web" in config


def test_traefik_static_config_has_cloudflare_dns_resolver(tmp_wpfy_home):
    config = traefik_static_config()
    assert "  le-dns-cloudflare:" in config
    assert "      dnsChallenge:" in config
    assert "        provider: cloudflare" in config


def test_traefik_static_config_is_text(tmp_wpfy_home):
    config = traefik_static_config()
    assert isinstance(config, str)
    assert config.endswith("\n")


def test_ensure_traefik_network_skipped_with_env(monkeypatch):
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    result = ensure_traefik_network()
    assert isinstance(result, RuntimeResult)
    assert result.skipped is True


def test_traefik_network_cidrs_uses_docker_ipam(monkeypatch):
    import subprocess

    monkeypatch.delenv("WPFY_TEST_TRAEFIK_NETWORK_CIDRS", raising=False)
    monkeypatch.setattr("wpfy.traefik.docker_available", lambda: True)
    monkeypatch.setattr(
        "wpfy.traefik.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 0, '[{"Subnet":"172.18.0.0/16","Gateway":"172.18.0.1"}]\n', "",
        ),
    )

    assert traefik_network_cidrs() == ("172.18.0.0/16",)


def test_traefik_network_cidrs_refuses_missing_ipam(monkeypatch):
    import subprocess

    monkeypatch.delenv("WPFY_TEST_TRAEFIK_NETWORK_CIDRS", raising=False)
    monkeypatch.setattr("wpfy.traefik.docker_available", lambda: True)
    monkeypatch.setattr(
        "wpfy.traefik.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, "[]\n", ""),
    )

    with pytest.raises(RuntimeError, match="no subnet"):
        traefik_network_cidrs()


def test_ensure_traefik_scaffold_touches_files(tmp_wpfy_home, monkeypatch):
    from pathlib import Path

    traefik_root = Path(tmp_wpfy_home.traefik_dir)
    monkeypatch.setenv("WPFY_TRAEFIK_DIR", str(traefik_root))

    touched = ensure_traefik_scaffold()
    assert len(touched) > 0
    assert traefik_root.exists()

    compose_path = traefik_root / "compose.yaml"
    config_path = traefik_root / "traefik.yml"
    assert compose_path.exists()
    assert config_path.exists()
    assert TRAEFIK_PROJECT in compose_path.read_text()
    assert "entryPoints:" in config_path.read_text()


def test_traefik_status_before_scaffold_does_not_raise(tmp_wpfy_home, monkeypatch):
    monkeypatch.setattr("wpfy.traefik.docker_available", lambda: True)

    result = traefik_status()

    assert result.exit_code == 0
    assert "not installed" in result.message


def test_start_recreates_running_traefik_when_static_config_changes(monkeypatch, tmp_wpfy_home, tmp_path):
    import subprocess
    import wpfy.traefik as traefik

    config = tmp_path / "traefik.yml"
    calls = []
    monkeypatch.setattr(traefik, "runtime_skip_requested", lambda: False)
    monkeypatch.setattr(traefik, "docker_available", lambda: True)
    monkeypatch.setattr(traefik, "_pull_traefik_image", lambda: RuntimeResult(0, "ready"))
    monkeypatch.setattr(traefik, "traefik_running", lambda: True)
    monkeypatch.setattr(traefik, "_ensure_traefik_scaffold", lambda: [str(config)])
    monkeypatch.setattr(traefik, "_traefik_static_config", lambda: "changed")
    monkeypatch.setattr(traefik, "_applied_config_hash", lambda: None)
    monkeypatch.setattr(traefik, "ensure_traefik_network", lambda: RuntimeResult(0, "ok"))
    monkeypatch.setattr(traefik, "ensure_panel_edge_network", lambda: RuntimeResult(0, "ok"))

    def compose(*args):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, "Recreated", "")

    monkeypatch.setattr(traefik, "_traefik_compose", compose)
    monkeypatch.setattr(traefik, "_wait_for_traefik_healthy", lambda: RuntimeResult(0, "healthy"))
    monkeypatch.setattr(traefik, "_record_applied_state", lambda config: None)

    result = traefik.start_traefik()

    assert result.exit_code == 0
    assert calls == [("up", "-d", "--force-recreate", "traefik")]


def test_start_does_not_recreate_when_static_config_is_unchanged(monkeypatch, tmp_wpfy_home, tmp_path):
    import subprocess
    import wpfy.traefik as traefik

    config = tmp_path / "traefik.yml"
    # "unchanged" must be true of the rendered file as well as the recorded
    # hash: since L8 the file is authoritative, because it is what Traefik reads.
    config.write_text("unchanged", encoding="utf-8")
    calls = []
    monkeypatch.setattr(traefik, "runtime_skip_requested", lambda: False)
    monkeypatch.setattr(traefik, "docker_available", lambda: True)
    monkeypatch.setattr(traefik, "_pull_traefik_image", lambda: RuntimeResult(0, "ready"))
    monkeypatch.setattr(traefik, "traefik_running", lambda: True)
    monkeypatch.setattr(traefik, "_ensure_traefik_scaffold", lambda: [])
    monkeypatch.setattr(traefik, "traefik_config_path", lambda: config)
    monkeypatch.setattr(traefik, "_traefik_static_config", lambda: "unchanged")
    monkeypatch.setattr(traefik, "_applied_config_hash", lambda: traefik._config_hash("unchanged"))
    monkeypatch.setattr(traefik, "ensure_traefik_network", lambda: RuntimeResult(0, "ok"))
    monkeypatch.setattr(traefik, "ensure_panel_edge_network", lambda: RuntimeResult(0, "ok"))

    def compose(*args):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, "Running", "")

    monkeypatch.setattr(traefik, "_traefik_compose", compose)
    monkeypatch.setattr(traefik, "_wait_for_traefik_healthy", lambda: RuntimeResult(0, "healthy"))
    monkeypatch.setattr(traefik, "_record_applied_state", lambda config: None)

    result = traefik.start_traefik()

    assert result.exit_code == 0
    assert calls == [("up", "-d")]


def test_start_records_only_after_healthy_apply(monkeypatch, tmp_wpfy_home):
    import subprocess
    import wpfy.traefik as traefik

    monkeypatch.setattr(traefik, "runtime_skip_requested", lambda: False)
    monkeypatch.setattr(traefik, "docker_available", lambda: True)
    monkeypatch.setattr(traefik, "_pull_traefik_image", lambda: RuntimeResult(0, "ready"))
    monkeypatch.setattr(traefik, "traefik_running", lambda: True)
    monkeypatch.setattr(traefik, "ensure_traefik_network", lambda: RuntimeResult(0, "ok"))
    monkeypatch.setattr(traefik, "ensure_panel_edge_network", lambda: RuntimeResult(0, "ok"))
    monkeypatch.setattr(
        traefik,
        "_traefik_compose",
        lambda *args: subprocess.CompletedProcess(args, 0, "started", ""),
    )
    monkeypatch.setattr(traefik, "_wait_for_traefik_healthy", lambda: RuntimeResult(1, "unhealthy"))

    assert traefik.start_traefik().exit_code == 1
    assert traefik.applied_config_hash() is None

    monkeypatch.setattr(traefik, "_wait_for_traefik_healthy", lambda: RuntimeResult(0, "healthy"))
    assert traefik.start_traefik().exit_code == 0
    assert traefik.applied_config_hash() is not None


def test_traefik_transaction_rejects_same_thread_reentry(tmp_wpfy_home):
    import wpfy.traefik as traefik

    with traefik.traefik_transaction():
        with pytest.raises(RuntimeError, match="cannot be re-entered"):
            with traefik.traefik_transaction():
                pass


def test_acme_email_problem_flags_unconfigured_default(monkeypatch, tmp_wpfy_home, tmp_path):
    import wpfy.traefik as traefik

    monkeypatch.setattr(traefik, "traefik_config_path", lambda: tmp_path / "traefik.yml")
    monkeypatch.delenv("WPFY_ACME_EMAIL", raising=False)

    problem = traefik.acme_email_problem()

    assert problem is not None
    assert "stack acme-email" in problem


def test_acme_email_problem_accepts_valid_env_email(monkeypatch, tmp_wpfy_home, tmp_path):
    import wpfy.traefik as traefik

    monkeypatch.setattr(traefik, "traefik_config_path", lambda: tmp_path / "traefik.yml")
    monkeypatch.setenv("WPFY_ACME_EMAIL", "ops@example.com")

    assert traefik.acme_email_problem() is None


def test_acme_email_problem_rejects_malformed_env_email(monkeypatch, tmp_wpfy_home, tmp_path):
    import wpfy.traefik as traefik

    monkeypatch.setattr(traefik, "traefik_config_path", lambda: tmp_path / "traefik.yml")
    monkeypatch.setenv("WPFY_ACME_EMAIL", "not-an-email")

    assert traefik.acme_email_problem() is not None


def test_acme_email_problem_prefers_valid_env_over_config(monkeypatch, tmp_wpfy_home, tmp_path):
    import wpfy.traefik as traefik

    config = tmp_path / "traefik.yml"
    config.write_text(
        "certificatesResolvers:\n  le:\n    acme:\n      email: admin@localhost\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(traefik, "traefik_config_path", lambda: config)
    # The already-written proxy config is what Traefik actually uses, so a
    # valid env var alone is not enough until the scaffold is regenerated.
    monkeypatch.setenv("WPFY_ACME_EMAIL", "ops@example.com")

    assert traefik.acme_email_problem() is None


def test_acme_email_problem_accepts_valid_scaffolded_config(monkeypatch, tmp_wpfy_home, tmp_path):
    import wpfy.traefik as traefik

    config = tmp_path / "traefik.yml"
    config.write_text(
        "certificatesResolvers:\n  le:\n    acme:\n      email: ops@example.com\n"
        "  le-http:\n    acme:\n      email: ops@example.com\n"
        "  le-dns-cloudflare:\n    acme:\n      email: ops@example.com\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(traefik, "traefik_config_path", lambda: config)
    monkeypatch.delenv("WPFY_ACME_EMAIL", raising=False)

    assert traefik.acme_email_problem() is None
