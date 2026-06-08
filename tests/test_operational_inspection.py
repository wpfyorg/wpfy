from __future__ import annotations

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
