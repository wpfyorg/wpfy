from __future__ import annotations

from wpfy.site_layout import RuntimeResult
from wpfy.certificate_lifecycle import SSLPreflightResult


def test_delete_site_stops_when_backup_fails(monkeypatch):
    import wpfy.site_lifecycle as lifecycle

    calls = []
    monkeypatch.setattr(lifecycle, "site_info", lambda domain: {"domain": domain})
    monkeypatch.setattr(
        lifecycle,
        "backup_site",
        lambda domain, require_database=False: calls.append(("backup", require_database))
        or RuntimeResult(1, "backup failed"),
    )
    monkeypatch.setattr(lifecycle, "stop_site_runtime", lambda *args, **kwargs: calls.append("stop"))
    monkeypatch.setattr(lifecycle, "remove_site_scaffold", lambda domain: calls.append("remove"))

    result = lifecycle.delete_site(lifecycle.DeleteSiteRequest("example.com", force=True))

    assert result.exit_code == 1
    assert result.removed is False
    assert calls == [("backup", True)]


def test_update_site_dry_run_does_not_apply(monkeypatch):
    import wpfy.site_lifecycle as lifecycle

    monkeypatch.setattr(lifecycle, "site_info", lambda domain: {"domain": domain})
    monkeypatch.setattr(lifecycle, "read_env", lambda path: {
        "SITE_FLAVOR": "wp", "PHP_VERSION": "8.4", "LETSENCRYPT_MODE": "",
    })
    monkeypatch.setattr(lifecycle, "ensure_site_scaffold", lambda spec: (_ for _ in ()).throw(AssertionError("mutated")))
    monkeypatch.setattr(lifecycle, "start_site_runtime", lambda domain: (_ for _ in ()).throw(AssertionError("started")))

    result = lifecycle.update_site(lifecycle.UpdateSiteRequest("example.com", php_version="8.3", dry_run=True))

    assert result.changes == ("php 8.4→8.3",)
    assert result.touched == ()
    assert result.runtime.skipped is True


def test_create_site_runs_lifecycle_in_order(monkeypatch):
    import wpfy.site_lifecycle as lifecycle

    calls: list[str] = []
    captured = {}
    monkeypatch.setattr(lifecycle, "acme_email_problem", lambda: None)
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

    monkeypatch.setattr(lifecycle, "acme_email_problem", lambda: None)
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


def test_create_site_stops_after_bootstrap_failure(monkeypatch):
    import wpfy.site_lifecycle as lifecycle

    calls = []
    monkeypatch.setattr(lifecycle, "ensure_site_scaffold", lambda spec: ["compose.yaml"])
    monkeypatch.setattr(
        lifecycle,
        "bootstrap_site_files",
        lambda domain: RuntimeResult(3, "download failed"),
    )
    monkeypatch.setattr(lifecycle, "apply_site_ownership", lambda domain: calls.append("ownership"))
    monkeypatch.setattr(lifecycle, "start_site_runtime", lambda domain: calls.append("runtime"))

    result = lifecycle.create_site(
        lifecycle.CreateSiteRequest("example.com", "wp"),
        credentials=lambda: calls.append("credentials"),
    )

    assert result.exit_code == 3
    assert result.runtime.skipped is True
    assert "bootstrap failed" in result.runtime.message
    assert calls == []


def test_create_site_stops_after_real_bootstrap_symlink_rejection(
    tmp_wpfy_home, monkeypatch, tmp_path
):
    import importlib
    import pytest
    import wpfy.site_layout as layout
    import wpfy.site_lifecycle as lifecycle

    importlib.reload(layout)
    importlib.reload(lifecycle)
    domain = "unsafe-create.example.com"
    external = tmp_path / "external-content"
    external.mkdir()
    (external / "sentinel").write_bytes(b"sentinel")
    real_scaffold = lifecycle.ensure_site_scaffold

    def scaffold_with_symlink(spec):
        touched = real_scaffold(spec)
        (layout.app_dir(domain) / "wp-content").symlink_to(
            external, target_is_directory=True
        )
        return touched

    monkeypatch.setattr(lifecycle, "ensure_site_scaffold", scaffold_with_symlink)
    monkeypatch.setattr(
        lifecycle,
        "apply_site_ownership",
        lambda domain_arg: pytest.fail("ownership ran after bootstrap rejection"),
    )
    monkeypatch.setattr(
        lifecycle,
        "start_site_runtime",
        lambda domain_arg: pytest.fail("runtime ran after bootstrap rejection"),
    )
    monkeypatch.setattr(
        lifecycle,
        "provision_wordpress_site",
        lambda *args: pytest.fail("WordPress provisioning ran after bootstrap rejection"),
    )

    result = lifecycle.create_site(
        lifecycle.CreateSiteRequest(domain, "wp"),
        credentials=lambda: pytest.fail("credentials requested after bootstrap rejection"),
    )

    assert result.exit_code != 0
    assert result.runtime.skipped is True
    assert "unsafe WordPress destination symlink" in result.bootstrap.message
    assert (external / "sentinel").read_bytes() == b"sentinel"


def test_create_site_rejects_preexisting_healthcheck_symlink_before_runtime(
    tmp_wpfy_home, monkeypatch, tmp_path
):
    import importlib
    import pytest
    import wpfy.site_layout as layout
    import wpfy.site_lifecycle as lifecycle

    importlib.reload(layout)
    importlib.reload(lifecycle)
    domain = "health-create.example.com"
    app_root = layout.app_dir(domain)
    app_root.mkdir(parents=True)
    external = tmp_path / "external-health"
    external.write_bytes(b"sentinel")
    layout.healthcheck_path(domain).symlink_to(external)
    monkeypatch.setattr(
        lifecycle,
        "start_site_runtime",
        lambda domain_arg: pytest.fail("runtime ran after scaffold rejection"),
    )

    with pytest.raises(lifecycle.SiteLifecycleError, match="unsafe scaffold destination symlink"):
        lifecycle.create_site(
            lifecycle.CreateSiteRequest(domain, "wp"),
            credentials=lambda: pytest.fail("credentials requested after scaffold rejection"),
        )

    assert external.read_bytes() == b"sentinel"


def test_create_site_stops_runtime_after_ownership_failure(monkeypatch):
    import pytest
    import wpfy.site_lifecycle as lifecycle

    monkeypatch.setattr(lifecycle, "ensure_site_scaffold", lambda spec: ["compose.yaml"])
    monkeypatch.setattr(
        lifecycle,
        "bootstrap_site_files",
        lambda domain: RuntimeResult(0, "bootstrapped", ran=True),
    )
    monkeypatch.setattr(
        lifecycle,
        "apply_site_ownership",
        lambda domain: RuntimeResult(3, "unsafe site ownership symlink"),
    )
    monkeypatch.setattr(
        lifecycle,
        "start_site_runtime",
        lambda domain: pytest.fail("runtime ran after ownership failure"),
    )

    result = lifecycle.create_site(
        lifecycle.CreateSiteRequest("ownership-failure.example.com", "wp"),
        credentials=lambda: pytest.fail("credentials requested after ownership failure"),
    )

    assert result.exit_code == 3
    assert result.runtime.skipped is True
    assert "ownership failed" in result.runtime.message


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
    monkeypatch.setattr(
        lifecycle.site_cache,
        "configure_site_cache",
        lambda domain: lifecycle.site_cache.CacheConfigurationResult(captured["spec"], ()),
    )
    result = lifecycle.update_site(lifecycle.UpdateSiteRequest("example.com", php_version="8.4", wpredis=True))

    assert result.changes == ("php 8.3→8.4", "object cache none→redis")
    assert captured["spec"].flavor == "wp"
    assert captured["spec"].object_cache == "redis"
    assert captured["spec"].use_redis is True
    assert captured["spec"].registry_metadata()["php_version"] == "8.4"
    assert captured["spec"].registry_metadata()["cache_type"] == "redis"


def test_enable_ssl_preserves_existing_site_definition(monkeypatch):
    import wpfy.site_lifecycle as lifecycle

    captured = {}
    monkeypatch.setattr(lifecycle, "acme_email_problem", lambda: None)
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
        lambda path: {"SITE_FLAVOR": "wpredis", "PHP_VERSION": "8.3"},
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

    assert result.spec.flavor == "wp"
    assert result.spec.php_version == "8.3"
    assert result.spec.object_cache == "redis"
    assert result.spec.use_redis is True
    assert result.spec.proxied is True
    assert calls == [
        ("--profile", "cli", "run", "--rm", "wpcli", "option", "update", "home", "https://example.com", "--allow-root"),
        ("--profile", "cli", "run", "--rm", "wpcli", "option", "update", "siteurl", "https://example.com", "--allow-root"),
    ]
    assert result.wordpress_message == "OK home and siteurl updated to https://example.com"


def test_enable_ssl_returns_failure_when_wordpress_url_update_fails(monkeypatch):
    import wpfy.site_lifecycle as lifecycle

    monkeypatch.setattr(lifecycle, "acme_email_problem", lambda: None)
    monkeypatch.setattr(
        lifecycle,
        "preflight_ssl",
        lambda domain: SSLPreflightResult(domain, ("203.0.113.10",), (), ("203.0.113.10",), (), True, "direct"),
    )
    monkeypatch.setattr(lifecycle, "site_info", lambda domain: {"domain": domain, "flavor": "wp"})
    monkeypatch.setattr(lifecycle, "read_env", lambda path: {"SITE_FLAVOR": "wp", "PHP_VERSION": "8.4"})
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


def test_update_site_password_travels_via_stdin(monkeypatch):
    import wpfy.site_lifecycle as lifecycle

    calls = []
    monkeypatch.setattr(lifecycle, "site_info", lambda domain: {"domain": domain, "flavor": "wp"})
    monkeypatch.setattr(lifecycle, "read_env", lambda path: {"SITE_FLAVOR": "wp", "PHP_VERSION": "8.4"})
    monkeypatch.setattr(lifecycle, "ensure_site_scaffold", lambda spec: [])
    monkeypatch.setattr(lifecycle, "start_site_runtime", lambda domain: RuntimeResult(0, "started", ran=True))

    class Proc:
        returncode = 0
        stdout = "site-admin\n"
        stderr = ""

    def fake_wp_cli(domain, *args, input_text=None):
        calls.append((args, input_text))
        return Proc()

    monkeypatch.setattr(lifecycle, "wp_cli_command", fake_wp_cli)

    result = lifecycle.update_site(lifecycle.UpdateSiteRequest("example.com", password="s3cret-pass"))

    update_args, update_stdin = calls[-1]
    assert "--prompt=user_pass" in update_args
    assert update_stdin == "s3cret-pass\n"
    # The password must never appear in process argv.
    assert all("s3cret-pass" not in arg for arg in update_args)
    # The actual administrator login resolved from wp-cli is targeted, not a literal "admin".
    assert "site-admin" in update_args
    assert result.password_summary == "OK password updated for site-admin"


def test_update_site_password_falls_back_to_admin_when_lookup_fails(monkeypatch):
    import wpfy.site_lifecycle as lifecycle

    calls = []
    monkeypatch.setattr(lifecycle, "site_info", lambda domain: {"domain": domain, "flavor": "wp"})
    monkeypatch.setattr(lifecycle, "read_env", lambda path: {"SITE_FLAVOR": "wp", "PHP_VERSION": "8.4"})
    monkeypatch.setattr(lifecycle, "ensure_site_scaffold", lambda spec: [])
    monkeypatch.setattr(lifecycle, "start_site_runtime", lambda domain: RuntimeResult(0, "started", ran=True))

    class Proc:
        def __init__(self, returncode, stdout=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = ""

    def fake_wp_cli(domain, *args, input_text=None):
        calls.append(args)
        if args[:2] == ("user", "list"):
            return Proc(1)
        return Proc(0)

    monkeypatch.setattr(lifecycle, "wp_cli_command", fake_wp_cli)

    result = lifecycle.update_site(lifecycle.UpdateSiteRequest("example.com", password="s3cret-pass"))

    assert "admin" in calls[-1]
    assert result.password_summary == "OK password updated for admin"


def test_update_site_does_not_start_runtime_after_scaffold_ownership_failure(monkeypatch):
    import pytest
    import wpfy.site_lifecycle as lifecycle

    monkeypatch.setattr(lifecycle, "site_info", lambda domain: {"domain": domain, "flavor": "wp"})
    monkeypatch.setattr(lifecycle, "read_env", lambda path: {"SITE_FLAVOR": "wp", "PHP_VERSION": "8.4"})
    monkeypatch.setattr(
        lifecycle,
        "ensure_site_scaffold",
        lambda spec: (_ for _ in ()).throw(ValueError("ownership failed safely")),
    )
    monkeypatch.setattr(
        lifecycle,
        "start_site_runtime",
        lambda domain: pytest.fail("runtime started after ownership failure"),
    )

    with pytest.raises(lifecycle.SiteLifecycleError, match="ownership failed safely"):
        lifecycle.update_site(lifecycle.UpdateSiteRequest("example.com"))


def test_update_site_rejects_environment_symlink_before_runtime(
    tmp_wpfy_home, monkeypatch, tmp_path
):
    import importlib
    import pytest
    import wpfy.site_layout as layout
    import wpfy.site_lifecycle as lifecycle

    importlib.reload(layout)
    importlib.reload(lifecycle)
    domain = "update-env-symlink.example.com"
    site_root = layout.site_dir(domain)
    site_root.mkdir(parents=True)
    layout.compose_path(domain).write_text("services: {}\n", encoding="utf-8")
    external = tmp_path / "external-update-env"
    external.write_text("SITE_FLAVOR=wp\nPHP_VERSION=8.4\n", encoding="utf-8")
    layout.env_path(domain).symlink_to(external)
    monkeypatch.setattr(
        lifecycle,
        "start_site_runtime",
        lambda domain_arg: pytest.fail("runtime started after unsafe env rejection"),
    )

    with pytest.raises(lifecycle.SiteLifecycleError, match="unsafe site environment"):
        lifecycle.update_site(lifecycle.UpdateSiteRequest(domain))

    assert external.read_text(encoding="utf-8") == "SITE_FLAVOR=wp\nPHP_VERSION=8.4\n"


def test_update_site_password_failure_is_redacted(monkeypatch):
    import wpfy.site_lifecycle as lifecycle

    monkeypatch.setattr(lifecycle, "site_info", lambda domain: {"domain": domain, "flavor": "wp"})
    monkeypatch.setattr(lifecycle, "read_env", lambda path: {"SITE_FLAVOR": "wp", "PHP_VERSION": "8.4"})
    monkeypatch.setattr(lifecycle, "ensure_site_scaffold", lambda spec: [])
    monkeypatch.setattr(lifecycle, "start_site_runtime", lambda domain: RuntimeResult(0, "started", ran=True))

    class Proc:
        def __init__(self, returncode, stdout="", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def fake_wp_cli(domain, *args, input_text=None):
        if args[:2] == ("user", "list"):
            return Proc(0, stdout="admin\n")
        return Proc(1, stderr="error processing s3cret-pass input")

    monkeypatch.setattr(lifecycle, "wp_cli_command", fake_wp_cli)

    result = lifecycle.update_site(lifecycle.UpdateSiteRequest("example.com", password="s3cret-pass"))

    assert result.password_summary.startswith("FAIL")
    assert "s3cret-pass" not in result.password_summary


def test_create_site_requires_acme_email_before_preflight(monkeypatch):
    import pytest
    import wpfy.site_lifecycle as lifecycle

    monkeypatch.setattr(lifecycle, "acme_email_problem", lambda: "ACME contact email is not configured")
    monkeypatch.setattr(
        lifecycle,
        "preflight_ssl",
        lambda domain: pytest.fail("preflight must not run without an ACME email"),
    )
    monkeypatch.setattr(
        lifecycle,
        "ensure_site_scaffold",
        lambda spec: pytest.fail("scaffold must not run without an ACME email"),
    )

    with pytest.raises(lifecycle.SiteLifecycleError, match="ACME contact email") as exc:
        lifecycle.create_site(
            lifecycle.CreateSiteRequest("example.com", "wp", letsencrypt="certbot"),
            credentials=lambda: pytest.fail("credentials must not be requested"),
        )

    assert exc.value.preflight is True


def test_enable_ssl_requires_acme_email(monkeypatch):
    import pytest
    import wpfy.site_lifecycle as lifecycle

    monkeypatch.setattr(lifecycle, "acme_email_problem", lambda: "ACME contact email is not configured")
    monkeypatch.setattr(
        lifecycle,
        "preflight_ssl",
        lambda domain: pytest.fail("preflight must not run without an ACME email"),
    )

    with pytest.raises(lifecycle.SiteLifecycleError, match="ACME contact email") as exc:
        lifecycle.enable_ssl("example.com", letsencrypt="certbot")

    assert exc.value.preflight is True
