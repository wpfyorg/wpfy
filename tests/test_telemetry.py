from __future__ import annotations

import json
from types import SimpleNamespace


class _Response:
    status = 204

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, size=-1):
        return b""


def _state(panel_setup, **updates):
    current = {
        "install_id": "11111111-2222-4333-8444-555555555555",
        "telemetry_enabled": True,
        "telemetry_last_sent_at": None,
        "license_accepted_at": "2026-07-28T12:00:00Z",
        "license_accepted_by": "admin",
        "license_version": "LICENSE",
    }
    current.update(updates)
    panel_setup._write_state(current)


def test_payload_is_exhaustive_and_contains_no_site_identifiers(tmp_wpfy_home, monkeypatch):
    import wpfy.panel_setup as panel_setup
    import wpfy.telemetry as telemetry

    _state(panel_setup)
    monkeypatch.setattr(telemetry, "list_sites", lambda: [
        {"domain": "private.example", "path": "/secret/private.example"},
        {"domain": "client.example", "path": "/secret/client.example"},
    ])
    monkeypatch.setattr(telemetry, "list_site_services", lambda domain, services: [
        {"name": "web", "status": "healthy"}, {"name": "app", "status": "running"},
    ] if domain == "private.example" else [
        {"name": "web", "status": "exited"}, {"name": "app", "status": "exited"},
    ])
    monkeypatch.setattr(telemetry, "_os_release", lambda: ("ubuntu", "24.04"))
    monkeypatch.setattr(telemetry.platform, "python_version", lambda: "3.12.4")

    payload = telemetry.payload()
    assert set(payload) == {
        "install_id", "wpfy_version", "os", "release", "python_version", "site_count", "active_sites",
    }
    assert payload["site_count"] == 2
    assert payload["active_sites"] == 1
    assert payload["os"] == "ubuntu"
    assert payload["release"] == "24.04"
    serialized = json.dumps(payload)
    assert "private.example" not in serialized
    assert "client.example" not in serialized
    assert "/secret" not in serialized


def test_sender_is_inert_without_endpoint_daily_and_silent_on_failure(tmp_wpfy_home, monkeypatch):
    import wpfy.panel_setup as panel_setup
    import wpfy.telemetry as telemetry

    _state(panel_setup)
    monkeypatch.setattr(telemetry, "list_sites", lambda: [])
    calls = []

    def fake_urlopen(request, timeout):
        calls.append((json.loads(request.data), timeout))
        return _Response()

    monkeypatch.setattr(telemetry, "urlopen", fake_urlopen)
    monkeypatch.delenv("WPFY_TELEMETRY_ENDPOINT", raising=False)
    telemetry._send_if_due()
    assert calls == []

    monkeypatch.setenv("WPFY_TELEMETRY_ENDPOINT", "https://telemetry.invalid/collect")
    telemetry._send_if_due()
    assert len(calls) == 1
    assert panel_setup.state()["telemetry_last_sent_at"]
    telemetry._send_if_due()
    assert len(calls) == 1

    _state(panel_setup, telemetry_last_sent_at=None)
    monkeypatch.setattr(telemetry, "urlopen", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("offline")))
    telemetry._send_if_due()
    assert panel_setup.state()["telemetry_last_sent_at"] is None


def test_environment_override_wins_and_cli_prints_real_payload(tmp_wpfy_home, monkeypatch):
    import wpfy.cli as cli
    import wpfy.panel_setup as panel_setup
    import wpfy.telemetry as telemetry

    _state(panel_setup)
    monkeypatch.setenv("WPFY_TELEMETRY", "0")
    monkeypatch.setattr(telemetry, "list_sites", lambda: [])
    monkeypatch.setattr(telemetry, "_os_release", lambda: ("ubuntu", "24.04"))
    monkeypatch.setattr(telemetry.platform, "python_version", lambda: "3.12.4")

    current = telemetry.status()
    assert current["stored_enabled"] is True
    assert current["environment_override"] is True
    assert current["effective_enabled"] is False

    result = cli.handle_telemetry(SimpleNamespace(telemetry_command="status"))
    assert result.exit_code == 0
    rendered = json.dumps(current["payload"], indent=2, sort_keys=True)
    assert rendered in result.message
    assert "effective: disabled" in result.message
    assert "not configured (nothing is sent)" in result.message

    assert cli.handle_telemetry(SimpleNamespace(telemetry_command="disable")).exit_code == 0
    assert panel_setup.state()["telemetry_enabled"] is False
    assert cli.handle_telemetry(SimpleNamespace(telemetry_command="enable")).exit_code == 0
    assert panel_setup.state()["telemetry_enabled"] is True


def test_telemetry_parser_surface(tmp_wpfy_home):
    import wpfy.cli as cli

    parser = cli.build_parser()
    for command in ("status", "enable", "disable"):
        args = parser.parse_args(["telemetry", command])
        assert args.handler is cli.handle_telemetry
