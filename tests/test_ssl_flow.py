from __future__ import annotations

import pytest
import datetime

from wpfy.certificate_lifecycle import preflight_ssl, get_cert_info, cert_expiry_days


def test_preflight_ssl_passes_with_test_overrides(monkeypatch):
    monkeypatch.setenv("WPFY_TEST_DNS_IPS", "1.2.3.4")
    monkeypatch.setenv("WPFY_TEST_PUBLIC_IPS", "1.2.3.4")

    result = preflight_ssl("example.com")
    assert result.passed is True
    assert "1.2.3.4" in result.a_records
    assert "1.2.3.4" in result.public_ipv4


def test_preflight_ssl_fails_mismatch(monkeypatch):
    monkeypatch.setenv("WPFY_TEST_DNS_IPS", "1.2.3.4")
    monkeypatch.setenv("WPFY_TEST_PUBLIC_IPS", "5.6.7.8")

    result = preflight_ssl("example.com")
    assert result.passed is False
    assert "example.com" in result.domain


def test_preflight_ssl_direct_mode_when_dns_matches(monkeypatch):
    monkeypatch.setenv("WPFY_TEST_DNS_IPS", "1.2.3.4")
    monkeypatch.setenv("WPFY_TEST_PUBLIC_IPS", "1.2.3.4")

    result = preflight_ssl("example.com")
    assert result.passed is True
    assert result.mode == "direct"


def test_preflight_ssl_proxied_mode_for_cloudflare_ip(monkeypatch):
    # A record points at Cloudflare, not the VPS public IP.
    monkeypatch.setenv("WPFY_TEST_DNS_IPS", "104.16.0.1")
    monkeypatch.setenv("WPFY_TEST_PUBLIC_IPS", "5.6.7.8")

    result = preflight_ssl("example.com")
    assert result.passed is True
    assert result.mode == "proxied"
    assert "Cloudflare" in result.message


def test_preflight_ssl_non_cf_mismatch_still_fails(monkeypatch):
    monkeypatch.setenv("WPFY_TEST_DNS_IPS", "9.9.9.9")
    monkeypatch.setenv("WPFY_TEST_PUBLIC_IPS", "5.6.7.8")

    result = preflight_ssl("example.com")
    assert result.passed is False
    assert result.mode == "direct"


def test_read_acme_file_merges_multiple_resolvers(monkeypatch):
    import wpfy.certificate_lifecycle as certificate_lifecycle

    monkeypatch.setattr(certificate_lifecycle.os.path, "exists", lambda path: False)

    class Proc:
        returncode = 0
        stdout = (
            '{"le":{"Certificates":[{"domain":{"main":"direct.com"}}]},'
            '"le-http":{"Certificates":[{"domain":{"main":"proxied.com"}}]}}'
        )

    monkeypatch.setattr(certificate_lifecycle.subprocess, "run", lambda *args, **kwargs: Proc())

    certs = certificate_lifecycle._read_acme_file()
    mains = {c["domain"]["main"] for c in certs}
    assert mains == {"direct.com", "proxied.com"}


def test_get_cert_info_finds_cert_under_second_resolver(monkeypatch):
    import wpfy.certificate_lifecycle as certificate_lifecycle

    monkeypatch.setattr(
        certificate_lifecycle,
        "_read_acme_file",
        lambda: [
            {"domain": {"main": "direct.com"}, "certificate": "bad"},
            {"domain": {"main": "proxied.com"}, "certificate": "bad"},
        ],
    )

    info = get_cert_info("proxied.com")
    assert info["status"] == "issued"


def test_get_cert_info_reads_acme_from_traefik_container(monkeypatch):
    import wpfy.certificate_lifecycle as certificate_lifecycle

    monkeypatch.setattr(certificate_lifecycle.os.path, "exists", lambda path: False)

    class Proc:
        returncode = 0
        stdout = '{"le":{"Certificates":[{"domain":{"main":"example.com"},"certificate":"bad"}]}}'

    monkeypatch.setattr(certificate_lifecycle.subprocess, "run", lambda *args, **kwargs: Proc())

    info = get_cert_info("example.com")

    assert info["status"] == "issued"


def test_get_cert_info_matches_domain_case_insensitively(monkeypatch):
    import wpfy.certificate_lifecycle as certificate_lifecycle

    monkeypatch.setattr(
        certificate_lifecycle,
        "_read_acme_file",
        lambda: [{"domain": {"main": "ssl.example.test"}, "certificate": "bad"}],
    )

    info = get_cert_info("SSL.EXAMPLE.TEST")

    assert info["status"] == "issued"


def test_get_cert_info_returns_unavailable_when_docker_is_missing(monkeypatch):
    import wpfy.certificate_lifecycle as certificate_lifecycle

    monkeypatch.setattr(certificate_lifecycle.os.path, "exists", lambda path: False)

    def missing_docker(*args, **kwargs):
        raise FileNotFoundError("docker")

    monkeypatch.setattr(certificate_lifecycle.subprocess, "run", missing_docker)

    info = get_cert_info("example.com")

    assert info["status"] == "unavailable"


def test_cert_expiry_days_uses_issued_certificate_metadata(monkeypatch):
    import wpfy.certificate_lifecycle as certificate_lifecycle

    future = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=45)
    monkeypatch.setattr(
        certificate_lifecycle,
        "get_cert_info",
        lambda domain: {
            "status": "issued",
            "issuer": "",
            "not_before": "",
            "not_after": future.isoformat(),
            "sans": [],
        },
    )

    assert cert_expiry_days("example.com") >= 44


def test_force_renew_removes_matching_certificate_from_all_resolvers(monkeypatch):
    import json
    import wpfy.certificate_lifecycle as lifecycle

    monkeypatch.setattr(lifecycle, "docker_available", lambda: True)
    monkeypatch.setattr(
        lifecycle,
        "get_cert_info",
        lambda domain: {"status": "issued"},
    )
    writes = []

    class Proc:
        def __init__(self, returncode=0, stdout="", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def fake_run(command, **kwargs):
        if command[-2:] == ["cat", "/letsencrypt/acme.json"]:
            return Proc(stdout=json.dumps({
                "le": {"Certificates": [{"domain": {"main": "example.com"}}]},
                "le-http": {"Certificates": [{"domain": {"main": "other.com"}}]},
            }))
        if kwargs.get("input"):
            writes.append(json.loads(kwargs["input"]))
        return Proc()

    monkeypatch.setattr(lifecycle.subprocess, "run", fake_run)

    result = lifecycle.force_renew_cert("EXAMPLE.COM")

    assert result.exit_code == 0
    assert writes[0]["le"]["Certificates"] == []
    assert writes[0]["le-http"]["Certificates"][0]["domain"]["main"] == "other.com"


@pytest.mark.parametrize(
    ("failed_step", "expected_calls", "message"),
    [
        ("mkdir", ["mkdir"], "prepare ACME backup"),
        ("cp", ["mkdir", "cp"], "back up acme.json"),
        ("cat", ["mkdir", "cp", "cat"], "backup preserved"),
        ("write", ["mkdir", "cp", "cat", "write"], "ACME was not replaced"),
        ("hup", ["mkdir", "cp", "cat", "write", "hup"], "reload failed"),
    ],
)
def test_force_renew_stops_after_failed_prerequisite(monkeypatch, failed_step, expected_calls, message):
    import json
    import wpfy.certificate_lifecycle as lifecycle

    monkeypatch.setattr(lifecycle, "docker_available", lambda: True)
    monkeypatch.setattr(lifecycle, "get_cert_info", lambda domain: {"status": "issued"})
    calls = []

    class Proc:
        def __init__(self, returncode=0, stdout="", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def fake_run(command, **kwargs):
        if "mkdir" in command:
            step = "mkdir"
        elif "cp" in command:
            step = "cp"
        elif command[-2:] == ["cat", "/letsencrypt/acme.json"]:
            step = "cat"
        elif kwargs.get("input"):
            step = "write"
        else:
            step = "hup"
        calls.append(step)
        assert lifecycle.TRAEFIK_CONTAINER in command
        if step == failed_step:
            return Proc(9, stderr=f"{step} failed")
        if step == "cat":
            return Proc(stdout=json.dumps({"le": {"Certificates": [{"domain": {"main": "example.com"}}]}}))
        return Proc()

    monkeypatch.setattr(lifecycle.subprocess, "run", fake_run)

    result = lifecycle.force_renew_cert("example.com")

    assert result.exit_code != 0
    assert calls == expected_calls
    assert message in result.message
