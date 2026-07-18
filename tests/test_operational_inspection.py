from __future__ import annotations

import importlib
import json

import pytest

from wpfy.operational_inspection import InspectionCheck, _container_security_checks


def test_container_security_checks_return_structured_facts():
    checks = _container_security_checks(
        "example-web",
        {"Config": {"User": "101"}},
        {
            "Privileged": False,
            "SecurityOpt": ["no-new-privileges:true"],
            "CapDrop": ["NET_RAW"],
            "PidsLimit": 256,
            "Memory": 268435456,
            "LogConfig": {
                "Type": "json-file",
                "Config": {"max-size": "10m", "max-file": "3"},
            },
            "PortBindings": {},
        },
    )

    assert all(isinstance(check, InspectionCheck) for check in checks)
    assert all(check.ok is True for check in checks)


def test_container_security_checks_keep_warnings_structured():
    checks = _container_security_checks(
        "example-app",
        {"Config": {"User": ""}},
        {
            "Privileged": False,
            "SecurityOpt": [],
            "CapDrop": [],
            "PidsLimit": 0,
            "Memory": 0,
            "LogConfig": {},
            "PortBindings": {},
        },
    )

    assert any(check.ok is None and "root" in check.message for check in checks)


def test_container_security_checks_accept_per_site_uid():
    # A high per-site uid (e.g. 100000) must read as a non-root user, not flagged.
    checks = _container_security_checks(
        "example-web",
        {"Config": {"User": "100000:100000"}},
        {
            "Privileged": False,
            "SecurityOpt": ["no-new-privileges:true"],
            "CapDrop": ["NET_RAW"],
            "PidsLimit": 256,
            "Memory": 268435456,
            "LogConfig": {"Type": "json-file", "Config": {"max-size": "10m", "max-file": "3"}},
            "PortBindings": {},
        },
    )
    user_checks = [c for c in checks if "user" in c.message or "root" in c.message]
    assert user_checks and all(c.ok is True for c in user_checks)


def test_security_checks_inspects_all_containers_once(tmp_wpfy_home, monkeypatch):
    import wpfy.operational_inspection as inspection
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    importlib.reload(inspection)
    calls = []
    info = {
        "Name": "/example-com-web",
        "Config": {"User": "100000:100000"},
        "HostConfig": {
            "Privileged": False,
            "SecurityOpt": ["no-new-privileges:true"],
            "CapDrop": ["NET_RAW"],
            "PidsLimit": 256,
            "Memory": 268435456,
            "LogConfig": {"Type": "json-file", "Config": {"max-size": "10m", "max-file": "3"}},
            "PortBindings": {},
        },
    }

    def fake_run(args, **kwargs):
        calls.append(args)
        return type("Proc", (), {"returncode": 1, "stdout": json.dumps([info]), "stderr": "missing"})()

    monkeypatch.setattr(inspection.subprocess, "run", fake_run)

    checks = inspection.security_checks("example.com")

    assert len(calls) == 1
    assert calls[0][:2] == ["docker", "inspect"]
    assert len(calls[0][2:]) == 5
    assert any(check.name == "example-com-web" and check.ok is True for check in checks)
    assert sum(check.message == "not running (skip)" for check in checks) == 4


def test_security_checks_reports_malformed_batch_for_each_container(tmp_wpfy_home, monkeypatch):
    import wpfy.operational_inspection as inspection
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    importlib.reload(inspection)
    proc = type("Proc", (), {"returncode": 1, "stdout": "not-json", "stderr": "bad"})()
    monkeypatch.setattr(inspection.subprocess, "run", lambda *args, **kwargs: proc)

    checks = inspection.security_checks("example.com")

    assert sum("inspect parse error" in check.message for check in checks) == 5


def test_nginx_service_info_uses_complete_authoritative_web_block(tmp_wpfy_home):
    import wpfy.operational_inspection as inspection
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    importlib.reload(inspection)
    root = wpfy.site_layout.site_dir("example.com")
    (root / "nginx").mkdir(parents=True)
    (root / ".env").write_text("DOMAIN=example.com\nSITE_FLAVOR=wp\nSITE_UID=100000\n", encoding="utf-8")
    (root / "nginx" / "default.conf").write_text("server { listen 8080; }\n", encoding="utf-8")

    info = inspection.nginx_service_info("example.com")

    generated = info.checks[0].message
    assert "  web:" in generated
    assert "traefik.http.services.example-com.loadbalancer.server.port=8080" in generated
    assert "./nginx/default.conf:/etc/nginx/conf.d/default.conf:ro" in generated
    assert "  app:" not in generated
    assert info.checks[1].ok is True


def test_php_service_info_distinguishes_stopped_failed_and_success(monkeypatch):
    import wpfy.operational_inspection as inspection

    class Proc:
        def __init__(self, returncode=0, stdout="", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    monkeypatch.setattr(inspection, "runtime_skip_requested", lambda: False)
    monkeypatch.setattr(inspection, "docker_available", lambda: True)
    monkeypatch.setattr(inspection, "compose_command", lambda *args: Proc())
    assert inspection.php_service_info("example.com").checks[0].message == "stopped"

    def failed_query(domain, *args):
        if args[:3] == ("ps", "-q", "app"):
            return Proc(stdout="container-id\n")
        return Proc(9, stderr="query broke")

    monkeypatch.setattr(inspection, "compose_command", failed_query)
    failed = inspection.php_service_info("example.com")
    assert failed.checks[-1].ok is False
    assert "query broke" in failed.checks[-1].message

    def successful_query(domain, *args):
        if args[:3] == ("ps", "-q", "app"):
            return Proc(stdout="container-id\n")
        return Proc(stdout="Core\njson\n")

    monkeypatch.setattr(inspection, "compose_command", successful_query)
    success = inspection.php_service_info("example.com")
    assert success.checks[-1] == inspection.InspectionCheck("loaded modules", True, "Core\njson")


def test_mysql_service_info_is_not_applicable_without_database(tmp_wpfy_home, monkeypatch):
    import wpfy.operational_inspection as inspection
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    importlib.reload(inspection)
    root = wpfy.site_layout.site_dir("static.example.com")
    root.mkdir(parents=True)
    (root / ".env").write_text("DOMAIN=static.example.com\nSITE_FLAVOR=html\n", encoding="utf-8")
    monkeypatch.setattr(inspection, "compose_command", lambda *args: pytest.fail("compose must not run"))

    info = inspection.mysql_service_info("static.example.com")

    assert info.checks == (inspection.InspectionCheck("status", None, "not applicable (site has no mysql service)"),)
