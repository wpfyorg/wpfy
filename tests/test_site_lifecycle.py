from __future__ import annotations

from wpfy.site_layout import RuntimeResult
from wpfy.certificate_lifecycle import SSLPreflightResult


def test_create_site_runs_lifecycle_in_order(monkeypatch):
    import wpfy.site_lifecycle as lifecycle

    calls: list[str] = []
    captured = {}
    monkeypatch.setattr(
        lifecycle,
        "preflight_ssl",
        lambda domain: calls.append("preflight") or SSLPreflightResult(
            domain, ("104.16.0.1",), (), ("203.0.113.10",), (), True, "proxied", mode="proxied"
        ),
    )

    def fake_scaffold(spec):
        calls.append("scaffold")
        captured["spec"] = spec
        return ["compose.yaml"]

    monkeypatch.setattr(lifecycle, "ensure_site_scaffold", fake_scaffold)
    monkeypatch.setattr(
        lifecycle,
        "bootstrap_site_files",
        lambda domain: calls.append("bootstrap") or RuntimeResult(0, "bootstrapped", ran=True),
    )
    monkeypatch.setattr(
        lifecycle,
        "start_site_runtime",
        lambda domain: calls.append("runtime") or RuntimeResult(0, "started", ran=True),
    )
    monkeypatch.setattr(
        lifecycle,
        "wordpress_install_state",
        lambda domain: calls.append("wordpress-state") or RuntimeResult(1, "not installed", ran=True),
    )
    monkeypatch.setattr(
        lifecycle,
        "provision_wordpress_site",
        lambda *args: calls.append("wordpress-provision") or RuntimeResult(0, "installed", ran=True),
    )

    result = lifecycle.create_site(
        lifecycle.CreateSiteRequest("example.com", "wp", letsencrypt="certbot"),
        credentials=lambda: lifecycle.WordPressCredentials(
            "admin", "admin@example.com", "generated-password", password_generated=True
        ),
    )

    assert calls == ["preflight", "scaffold", "bootstrap", "runtime", "wordpress-state", "wordpress-provision"]
    assert captured["spec"].proxied is True
    assert result.generated_password == "generated-password"
    assert result.exit_code == 0


def test_create_site_stops_before_mutation_when_preflight_fails(monkeypatch):
    import pytest
    import wpfy.site_lifecycle as lifecycle

    monkeypatch.setattr(
        lifecycle,
        "preflight_ssl",
        lambda domain: SSLPreflightResult(domain, (), (), ("203.0.113.10",), (), False, "preflight failed"),
    )
    monkeypatch.setattr(
        lifecycle,
        "ensure_site_scaffold",
        lambda spec: pytest.fail("scaffold must not run after failed preflight"),
    )

    with pytest.raises(lifecycle.SiteLifecycleError, match="preflight failed") as exc:
        lifecycle.create_site(
            lifecycle.CreateSiteRequest("example.com", "wp", letsencrypt="certbot"),
            credentials=lambda: pytest.fail("credentials must not be requested"),
        )

    assert exc.value.preflight is True


def test_update_site_passes_authoritative_definition_to_scaffold(monkeypatch):
    import wpfy.site_lifecycle as lifecycle

    captured = {}
    monkeypatch.setattr(lifecycle, "site_info", lambda domain: {"domain": domain, "flavor": "wp"})
    monkeypatch.setattr(
        lifecycle,
        "read_env",
        lambda path: {
            "SITE_FLAVOR": "wp",
            "PHP_VERSION": "8.3",
            "LETSENCRYPT_MODE": "",
            "DNS_PROVIDER": "",
        },
    )
    monkeypatch.setattr(lifecycle, "ensure_site_scaffold", lambda spec: captured.setdefault("spec", spec) and [])
    monkeypatch.setattr(lifecycle, "start_site_runtime", lambda domain: RuntimeResult(0, "started", ran=True))
    result = lifecycle.update_site(lifecycle.UpdateSiteRequest("example.com", php_version="8.4", wpredis=True))

    assert result.changes == ("php 8.3→8.4", "flavor wp→wpredis")
    assert captured["spec"].use_redis is True
    assert captured["spec"].registry_metadata()["php_version"] == "8.4"
    assert captured["spec"].registry_metadata()["cache_type"] == "redis"


def test_enable_ssl_preserves_existing_site_definition(monkeypatch):
    import wpfy.site_lifecycle as lifecycle

    captured = {}
    monkeypatch.setattr(
        lifecycle,
        "preflight_ssl",
        lambda domain: SSLPreflightResult(
            domain, ("104.16.0.1",), (), ("203.0.113.10",), (), True, "proxied", mode="proxied"
        ),
    )
    monkeypatch.setattr(lifecycle, "site_info", lambda domain: {"domain": domain, "flavor": "wpredis"})
    monkeypatch.setattr(
        lifecycle,
        "read_env",
        lambda path: {"PHP_VERSION": "8.3"},
    )
    monkeypatch.setattr(lifecycle, "ensure_site_scaffold", lambda spec: captured.setdefault("spec", spec) and [])
    monkeypatch.setattr(lifecycle, "start_site_runtime", lambda domain: RuntimeResult(0, "started", ran=True))
    calls = []

    class Proc:
        returncode = 0
        stdout = "Success"
        stderr = ""

    monkeypatch.setattr(lifecycle, "compose_command", lambda domain, *args: calls.append(args) or Proc())

    result = lifecycle.enable_ssl("example.com", letsencrypt="certbot")

    assert result.spec.flavor == "wpredis"
    assert result.spec.php_version == "8.3"
    assert result.spec.use_redis is True
    assert result.spec.proxied is True
    assert calls == [
        ("--profile", "cli", "run", "--rm", "wpcli", "option", "update", "home", "https://example.com", "--allow-root"),
        ("--profile", "cli", "run", "--rm", "wpcli", "option", "update", "siteurl", "https://example.com", "--allow-root"),
    ]
    assert result.wordpress_message == "OK home and siteurl updated to https://example.com"


def test_enable_ssl_returns_failure_when_wordpress_url_update_fails(monkeypatch):
    import wpfy.site_lifecycle as lifecycle

    monkeypatch.setattr(
        lifecycle,
        "preflight_ssl",
        lambda domain: SSLPreflightResult(domain, ("203.0.113.10",), (), ("203.0.113.10",), (), True, "direct"),
    )
    monkeypatch.setattr(lifecycle, "site_info", lambda domain: {"domain": domain, "flavor": "wp"})
    monkeypatch.setattr(lifecycle, "read_env", lambda path: {"PHP_VERSION": "8.4"})
    monkeypatch.setattr(lifecycle, "ensure_site_scaffold", lambda spec: [])
    monkeypatch.setattr(lifecycle, "start_site_runtime", lambda domain: RuntimeResult(0, "started", ran=True))

    class Proc:
        returncode = 1
        stdout = ""
        stderr = "database unavailable"

    monkeypatch.setattr(lifecycle, "compose_command", lambda domain, *args: Proc())

    result = lifecycle.enable_ssl("example.com", letsencrypt="certbot")

    assert result.exit_code == 1
    assert result.wordpress_message == "FAIL database unavailable"
