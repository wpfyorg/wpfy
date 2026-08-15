from __future__ import annotations

import os
from pathlib import Path
import stat

import pytest


DOMAIN = "panel.example.com"
PUBLIC_IP = "203.0.113.12"
EDGE_CIDR = "172.31.240.0/24"
EDGE_HOST = "172.31.240.1"


@pytest.fixture
def exposure_home(tmp_path, monkeypatch):
    import wpfy.panel_auth as panel_auth
    import wpfy.settings as settings

    paths = settings.PATHS
    previous = {
        field: getattr(paths, field)
        for field in ("install_root", "config_dir", "state_dir", "log_dir")
    }
    values = {
        "install_root": str(tmp_path / "install"),
        "config_dir": str(tmp_path / "config"),
        "state_dir": str(tmp_path / "state"),
        "log_dir": str(tmp_path / "log"),
    }
    for field, value in values.items():
        object.__setattr__(paths, field, value)
    monkeypatch.setenv("WPFY_SYSTEMD_DIR", str(tmp_path / "systemd"))
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    # `expose` refuses without a usable ACME contact, the same way enabling SSL
    # for a site does. These tests are about the router and the service, so the
    # host is given a contact rather than each test asserting the refusal.
    monkeypatch.setenv("WPFY_ACME_EMAIL", "ops@example.test")
    monkeypatch.setenv("WPFY_TEST_DNS_IPS", PUBLIC_IP)
    monkeypatch.setenv("WPFY_TEST_PUBLIC_IPS", PUBLIC_IP)
    monkeypatch.setenv("WPFY_TEST_TRAEFIK_NETWORK_CIDRS", EDGE_CIDR)
    # The CIDR override alone left the fixture self-contradictory: the subnet was
    # injected while the gateway still came from the real Docker daemon, so on a
    # machine with Docker the two disagreed and on a machine without one there
    # was no gateway at all. Pinning both makes these tests say the same thing
    # everywhere, and stops them needing a `wpfy-panel-edge` network to run.
    import wpfy.traefik as traefik

    monkeypatch.setattr(
        traefik, "_network_gateway",
        lambda network: EDGE_HOST if network == "wpfy-panel-edge" else None)
    for directory in (paths.config_dir, paths.state_dir, paths.log_dir, paths.traefik_dir):
        Path(directory).mkdir(parents=True, exist_ok=True)
    panel_auth.reset_state()
    try:
        yield paths
    finally:
        panel_auth.reset_state()
        for field, value in previous.items():
            object.__setattr__(paths, field, value)


def _seed_user():
    import wpfy.panel_auth as panel_auth

    panel_auth.add_user("exposure-admin", "long-enough-password", role=panel_auth.ROLE_ADMIN)
    panel_auth.enable_totp("exposure-admin")


def test_render_router_config_is_tls_only_and_rate_limited(exposure_home):
    import wpfy.panel_exposure as exposure

    text = exposure.render_router_config(DOMAIN, f"http://{EDGE_HOST}:8642")

    assert f"Host(`{DOMAIN}`)" in text
    assert "websecure" in text
    assert "certResolver: le-http" in text
    assert "rateLimit:" in text
    assert f"average: {exposure.RATE_LIMIT_AVERAGE}" in text
    assert "\n        - web\n" not in text


@pytest.mark.parametrize("target", [
    "https://172.31.240.1:8642",
    "http://panel.example.com:8642",
    "http://user@172.31.240.1:8642",
    "http://172.31.240.1:8642/path",
    "http://172.31.240.1",
])
def test_render_router_config_rejects_unexpected_targets(exposure_home, target):
    import wpfy.panel_exposure as exposure

    with pytest.raises(ValueError):
        exposure.render_router_config(DOMAIN, target)


def test_validate_edge_bind_accepts_only_usable_network_addresses(exposure_home):
    """An edge-bound panel outside its bridge cannot be reached by Traefik."""
    import wpfy.panel_exposure as exposure

    assert exposure.validate_panel_edge_bind(EDGE_HOST) == EDGE_HOST
    for host in ("172.31.240.0", "172.31.240.255", "172.31.241.1", "0.0.0.0"):
        with pytest.raises(ValueError):
            exposure.validate_panel_edge_bind(host)


def test_validate_panel_edge_bind_accepts_usable_ipv6_addresses(exposure_home, monkeypatch):
    """IPv6 panel-edge addresses have no broadcast address to reject."""
    import wpfy.panel_exposure as exposure

    monkeypatch.setenv("WPFY_TEST_TRAEFIK_NETWORK_CIDRS", "172.31.240.0/24,fd00:240::/64")

    assert exposure.validate_panel_edge_bind("fd00:240::1") == "fd00:240::1"
    with pytest.raises(ValueError, match="network address"):
        exposure.validate_panel_edge_bind("fd00:240::")


def test_validate_panel_edge_bind_refuses_an_unknown_network(exposure_home, monkeypatch):
    """An uninspected bridge must not turn an arbitrary host address into an edge bind."""
    import wpfy.panel_exposure as exposure

    monkeypatch.delenv("WPFY_TEST_TRAEFIK_NETWORK_CIDRS")
    monkeypatch.setattr(exposure.traefik, "traefik_network_cidrs", lambda _network: ())

    with pytest.raises(ValueError, match="could not be inspected"):
        exposure.validate_panel_edge_bind(EDGE_HOST)


def test_validate_edge_bind_keeps_domainless_public_addresses(exposure_home):
    """Domainless TLS binds the host public address, not the Docker bridge."""
    import wpfy.panel_exposure as exposure

    assert exposure.validate_edge_bind(PUBLIC_IP) == PUBLIC_IP


def test_expose_writes_private_directory_and_truthful_status(exposure_home):
    import wpfy.panel_exposure as exposure

    _seed_user()
    result = exposure.expose(DOMAIN, confirm=DOMAIN)

    assert result.exit_code == 0
    assert "required next: wpfy panel service install" in result.message
    assert "panel exposed" not in result.message
    assert exposure.exposure_status()["domain"] == DOMAIN
    assert exposure.exposure_status()["recognised"] is True
    assert stat.S_IMODE(exposure.dynamic_dir().stat().st_mode) == 0o755
    assert stat.S_IMODE(exposure.panel_router_path().stat().st_mode) == 0o644
    assert exposure.panel_router_path().parent == Path(exposure_home.traefik_dir) / "dynamic"


def test_exposure_status_treats_an_unreadable_router_shape_as_exposed(exposure_home):
    import wpfy.panel_exposure as exposure

    exposure.dynamic_dir().mkdir(mode=0o755)
    exposure.panel_router_path().write_text("not a wpfy router\n", encoding="utf-8")

    status = exposure.exposure_status()
    assert status["exposed"] is True
    assert status["recognised"] is False
    assert status["domain"] is None


def test_install_service_refuses_before_router_exists(exposure_home):
    import wpfy.panel_exposure as exposure

    result = exposure.install_service(EDGE_HOST, 8642)

    assert result.exit_code != 0
    assert not exposure.panel_service_path().exists()


def test_install_service_rolls_back_a_failed_systemd_install(exposure_home, monkeypatch):
    import wpfy.panel_exposure as exposure
    from wpfy.site_runtime import RuntimeResult

    _seed_user()
    assert exposure.expose(DOMAIN, confirm=DOMAIN).exit_code == 0

    def fail_after_write(units, names, message):
        for path, content in units.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        return RuntimeResult(1, "systemctl failed")

    monkeypatch.setattr(exposure.systemd, "install_units", fail_after_write)
    result = exposure.install_service(EDGE_HOST, 8642)

    assert result.exit_code == 1
    assert not exposure.panel_service_path().exists()


def test_disable_removes_router_even_if_service_removal_fails(exposure_home, monkeypatch):
    import wpfy.panel_exposure as exposure
    from wpfy.site_runtime import RuntimeResult

    _seed_user()
    assert exposure.expose(DOMAIN, confirm=DOMAIN).exit_code == 0
    monkeypatch.setattr(exposure, "remove_service", lambda: RuntimeResult(1, "stop failed"))

    result = exposure.disable()

    assert result.exit_code == 1
    assert not exposure.panel_router_path().exists()


def test_panel_parser_exposes_explicit_management_commands(exposure_home):
    import wpfy.cli as cli

    parser = cli.build_parser()
    expose = parser.parse_args(["panel", "expose", "--domain", DOMAIN, "--confirm", DOMAIN])
    status = parser.parse_args(["panel", "expose", "--status"])
    install = parser.parse_args(["panel", "service", "install"])
    remove = parser.parse_args(["panel", "service", "remove"])

    assert expose.handler is cli.handle_panel_exposure
    assert expose.domain == DOMAIN
    assert status.status is True
    assert install.panel_service_command == "install"
    assert remove.panel_service_command == "remove"


def test_exposure_status_command_reports_required_service(exposure_home, capsys):
    import wpfy.cli as cli
    import wpfy.panel_exposure as exposure

    _seed_user()
    assert exposure.expose(DOMAIN, confirm=DOMAIN).exit_code == 0

    assert cli.run(["panel", "expose", "--status"]) == 0
    output = capsys.readouterr().out
    assert "router: configured" in output
    assert f"domain: {DOMAIN}" in output
    assert "service: not installed" in output
    assert "service install is required" in output


def test_edge_service_mode_cannot_bypass_exposure_gates(exposure_home):
    import wpfy.panel as panel

    config = panel.PanelConfig(host=EDGE_HOST, port=0, token="memory-only", edge_bind=True)
    with pytest.raises(ValueError, match="named-user login"):
        panel.make_panel_server(config)
