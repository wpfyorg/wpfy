from __future__ import annotations

import io
import importlib
import stat
import tarfile
from pathlib import Path

import pytest
from wpfy.site_layout import validate_domain, domain_to_project, compose_content, env_content, SiteSpec


def _spec(**kwargs) -> SiteSpec:
    # compose_content requires an allocated site_uid (done by ensure_site_scaffold
    # in production); tests that build a spec by hand get a default unless overridden.
    kwargs.setdefault("site_uid", 100000)
    return SiteSpec(**kwargs)


def test_validate_domain_valid():
    validate_domain("example.com")
    validate_domain("sub.example.com")
    validate_domain("my-site.org")


def test_validate_domain_too_long():
    long_domain = "a" * 250 + ".com"
    with pytest.raises(ValueError, match="too long"):
        validate_domain(long_domain)


def test_validate_domain_invalid():
    with pytest.raises(ValueError, match="invalid domain"):
        validate_domain("-invalid.com")
    with pytest.raises(ValueError, match="invalid domain"):
        validate_domain("example-.com")


def test_domain_to_project():
    assert domain_to_project("example.com") == "example-com"
    assert domain_to_project("sub.example.com") == "sub-example-com"
    assert domain_to_project("my_site.org") == "my-site-org"


def test_compose_content_basic():
    spec = _spec(
        domain="example.com",
        flavor="site",
        use_mysql=False,
        use_redis=False,
    )
    content = compose_content(spec)
    assert "name: example-com" in content
    assert "services:" in content
    assert "web:" in content
    assert "image: ghcr.io/wpfyorg/php-fpm:8.4" in content


def test_compose_content_respects_explicit_php_version():
    spec = _spec(
        domain="example.com",
        flavor="site",
        use_mysql=False,
        use_redis=False,
        php_version="8.3",
    )
    content = compose_content(spec)
    assert "image: ghcr.io/wpfyorg/php-fpm:8.3" in content


def test_compose_content_with_mysql():
    spec = _spec(
        domain="example.com",
        flavor="wp",
        use_mysql=True,
        use_redis=False,
    )
    content = compose_content(spec)
    assert "db:" in content
    assert "mariadb" in content


def test_compose_content_with_redis():
    spec = _spec(
        domain="example.com",
        flavor="wpredis",
        use_mysql=True,
        use_redis=True,
    )
    content = compose_content(spec)
    assert "redis:" in content
    assert "- ./redis-data:/data" in content


def test_compose_content_has_restart_policies():
    spec = _spec(
        domain="example.com",
        flavor="wp",
        use_mysql=True,
        use_redis=True,
    )
    content = compose_content(spec)
    assert content.count("restart: unless-stopped") >= 4


def test_compose_content_web_has_restart_policy():
    spec = _spec(domain="example.com", flavor="site", use_mysql=False, use_redis=False)
    content = compose_content(spec)
    assert "  web:" in content
    assert "    restart: unless-stopped" in content


def test_compose_content_app_has_restart_policy():
    spec = _spec(domain="example.com", flavor="site", use_mysql=False, use_redis=False)
    content = compose_content(spec)
    assert "  app:" in content
    app_index = content.index("  app:")
    after_app = content[app_index:]
    assert "    restart: unless-stopped" in after_app[:400]


def test_compose_content_with_ssl_labels():
    spec = _spec(
        domain="example.com",
        flavor="wp",
        use_mysql=True,
        use_redis=False,
        ssl_enabled=True,
    )
    content = compose_content(spec)
    assert "traefik.http.routers.example-com.entrypoints=websecure" in content
    assert "traefik.http.routers.example-com.service=example-com" in content
    assert "traefik.http.routers.example-com.tls=true" in content
    assert "traefik.http.routers.example-com.tls.certresolver=le" in content
    assert "traefik.http.routers.example-com-http.rule=Host(`example.com`)" in content
    assert "traefik.http.routers.example-com-http.entrypoints=web" in content
    assert "traefik.http.middlewares.example-com-redirect.redirectscheme.scheme=https" in content
    assert "traefik.http.routers.example-com-http.service=example-com" in content


def test_compose_content_proxied_uses_le_http_resolver():
    spec = _spec(
        domain="example.com",
        flavor="wp",
        use_mysql=True,
        use_redis=False,
        ssl_enabled=True,
        proxied=True,
    )
    content = compose_content(spec)
    assert "traefik.http.routers.example-com.tls.certresolver=le-http" in content
    assert "tls.certresolver=le\"" not in content


def test_compose_content_direct_keeps_le_resolver():
    spec = _spec(
        domain="example.com",
        flavor="wp",
        use_mysql=True,
        use_redis=False,
        ssl_enabled=True,
        proxied=False,
    )
    content = compose_content(spec)
    assert "traefik.http.routers.example-com.tls.certresolver=le\"" in content
    assert "le-http" not in content


def test_env_content_writes_proxied_flag():
    spec = _spec(
        domain="example.com",
        flavor="wp",
        use_mysql=True,
        use_redis=False,
        ssl_enabled=True,
        proxied=True,
    )
    assert "PROXIED=1" in env_content(spec)


def test_env_content_omits_proxied_when_direct():
    spec = _spec(
        domain="example.com",
        flavor="wp",
        use_mysql=True,
        use_redis=False,
        ssl_enabled=True,
        proxied=False,
    )
    assert "PROXIED" not in env_content(spec)


def test_compose_content_without_ssl_labels():
    spec = _spec(
        domain="example.com",
        flavor="wp",
        use_mysql=True,
        use_redis=False,
        ssl_enabled=False,
    )
    content = compose_content(spec)
    assert "tls.certresolver" not in content
    assert "redirectscheme" not in content
    assert "traefik.http.routers.example-com.entrypoints=web" in content


def test_compose_content_has_wpcli_service():
    spec = _spec(
        domain="example.com",
        flavor="wp",
        use_mysql=True,
        use_redis=False,
    )
    content = compose_content(spec)
    assert "wpcli:" in content
    assert "profiles:" in content
    assert "cli" in content
    assert "container_name: example-com-wpcli" in content
    assert "/usr/local/bin/wp" in content


def test_compose_content_wpcli_runs_as_the_site_user_never_root():
    # wp-cli writes files (core download, plugin/theme installs); if the one-shot ran as
    # root it would leave root-owned files and break per-site uid isolation. Scope the
    # assertion to the wpcli service block so it can't pass on another service's directive.
    spec = _spec(domain="example.com", flavor="wp", use_mysql=True, use_redis=False, site_uid=100013)
    content = compose_content(spec)
    # wpcli is the last service; the next top-level (0-indent) block is `networks:`.
    wpcli_block = content[content.index("  wpcli:"):]
    end = wpcli_block.find("\nnetworks:")
    wpcli_block = wpcli_block[: end if end != -1 else None]
    assert '    user: "100013:100013"' in wpcli_block
    assert "0:0" not in wpcli_block
    assert "root" not in wpcli_block


def test_compose_content_wpcli_has_env_file():
    spec = _spec(domain="example.com", flavor="wp", use_mysql=True, use_redis=False)
    content = compose_content(spec)
    assert "    env_file:" in content
    assert "      - .env" in content


def test_compose_content_wpcli_has_volume():
    spec = _spec(domain="example.com", flavor="wp", use_mysql=True, use_redis=False)
    content = compose_content(spec)
    assert "./app:/var/www/html" in content


def test_compose_content_has_network_wpfy():
    spec = _spec(domain="example.com", flavor="site", use_mysql=False, use_redis=False)
    content = compose_content(spec)
    assert "wpfy:" in content
    assert "external: true" in content


def test_compose_content_has_baseline_hardening():
    spec = _spec(domain="example.com", flavor="wpredis", use_mysql=True, use_redis=True)
    content = compose_content(spec)
    assert content.count("no-new-privileges:true") >= 5
    assert content.count("cap_drop:") >= 5
    assert content.count("NET_RAW") >= 5
    assert content.count("pids_limit:") >= 5
    assert content.count("mem_limit:") >= 5
    assert content.count("logging:") >= 5
    assert "max-size: 10m" in content
    assert 'max-file: "3"' in content


def test_compose_content_runs_every_container_as_the_site_uid():
    spec = _spec(domain="example.com", flavor="wpredis", use_mysql=True, use_redis=True, site_uid=100007)
    content = compose_content(spec)
    assert 'image: nginxinc/nginx-unprivileged:1.27-alpine' in content
    # web, app, db, redis, and the wpcli one-shot all drop to the one per-site uid.
    assert content.count('    user: "100007:100007"') == 5
    # no container is left at root or the old shared image uids.
    assert '101:101' not in content
    assert '82:82' not in content
    assert '999:999' not in content


def test_compose_content_isolates_sites_with_distinct_uids():
    a = compose_content(_spec(domain="a.com", flavor="wp", use_mysql=True, use_redis=False, site_uid=100001))
    b = compose_content(_spec(domain="b.com", flavor="wp", use_mysql=True, use_redis=False, site_uid=100002))
    assert 'user: "100001:100001"' in a and 'user: "100001:100001"' not in b
    assert 'user: "100002:100002"' in b and 'user: "100002:100002"' not in a


def test_compose_content_uses_per_site_bind_mounted_data_dirs():
    content = compose_content(_spec(domain="example.com", flavor="wpredis", use_mysql=True, use_redis=True))
    assert "- ./db-data:/var/lib/mysql" in content
    assert "- ./redis-data:/data" in content
    # no named volumes remain.
    assert "db_data:" not in content
    assert "redis_data:" not in content
    assert "\nvolumes:" not in content


def test_compose_content_requires_allocated_uid():
    spec = SiteSpec(domain="example.com", flavor="site", use_mysql=False, use_redis=False)
    with pytest.raises(ValueError, match="site_uid"):
        compose_content(spec)


def test_compose_content_db_has_restart_policy():
    spec = _spec(domain="example.com", flavor="wp", use_mysql=True, use_redis=False)
    content = compose_content(spec)
    assert "  db:" in content
    db_index = content.index("  db:")
    after_db = content[db_index:]
    assert "    restart: unless-stopped" in after_db[:500]


def test_compose_content_redis_has_restart_policy():
    spec = _spec(domain="example.com", flavor="wpredis", use_mysql=True, use_redis=True)
    content = compose_content(spec)
    assert "  redis:" in content
    redis_index = content.index("  redis:")
    after_redis = content[redis_index:]
    assert "    restart: unless-stopped" in after_redis[:500]


def test_compose_content_traefik_labels_includes_enable():
    spec = _spec(domain="test.com", flavor="site", use_mysql=False, use_redis=False)
    content = compose_content(spec)
    assert 'traefik.enable=true' in content
    assert 'traefik.http.routers.test-com.rule=Host(`test.com`)' in content
    assert 'traefik.http.routers.test-com.service=test-com' in content


def test_compose_content_traefik_labels_has_loadbalancer():
    spec = _spec(domain="test.com", flavor="site", use_mysql=False, use_redis=False)
    content = compose_content(spec)
    assert 'traefik.http.services.test-com.loadbalancer.server.port=8080' in content


def test_ensure_site_scaffold_writes_private_env(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    spec = wpfy.site_layout.SiteSpec(domain="secure.example.com", flavor="wp", use_mysql=True, use_redis=False)

    wpfy.site_layout.ensure_site_scaffold(spec)

    mode = stat.S_IMODE(wpfy.site_layout.env_path("secure.example.com").stat().st_mode)
    assert mode == 0o600


def test_ensure_site_scaffold_persists_site_uid(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    spec = wpfy.site_layout.SiteSpec(domain="uid.example.com", flavor="wp", use_mysql=True, use_redis=False)
    wpfy.site_layout.ensure_site_scaffold(spec)

    env = wpfy.site_layout.read_env(wpfy.site_layout.env_path("uid.example.com"))
    assert env["SITE_UID"] == str(wpfy.site_layout.SITE_UID_BASE)
    compose = wpfy.site_layout.compose_path("uid.example.com").read_text(encoding="utf-8")
    assert f'user: "{wpfy.site_layout.SITE_UID_BASE}:{wpfy.site_layout.SITE_UID_BASE}"' in compose


def test_ensure_site_scaffold_reuses_existing_site_uid(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    spec = wpfy.site_layout.SiteSpec(domain="reuse.example.com", flavor="wp", use_mysql=True, use_redis=False)
    wpfy.site_layout.ensure_site_scaffold(spec)
    first = wpfy.site_layout.read_env(wpfy.site_layout.env_path("reuse.example.com"))["SITE_UID"]

    # Re-running scaffolding must not reallocate the uid.
    wpfy.site_layout.ensure_site_scaffold(spec)
    second = wpfy.site_layout.read_env(wpfy.site_layout.env_path("reuse.example.com"))["SITE_UID"]
    assert first == second


def test_site_uids_are_unique_across_sites(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    uids = set()
    for name in ("one.example.com", "two.example.com", "three.example.com"):
        spec = wpfy.site_layout.SiteSpec(domain=name, flavor="wp", use_mysql=True, use_redis=False)
        wpfy.site_layout.ensure_site_scaffold(spec)
        uids.add(wpfy.site_layout.read_env(wpfy.site_layout.env_path(name))["SITE_UID"])
    assert len(uids) == 3


def test_apply_site_ownership_skips_cleanly_when_not_root(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    spec = wpfy.site_layout.SiteSpec(domain="own.example.com", flavor="wp", use_mysql=True, use_redis=True)

    # Non-root: chown must be skipped, not attempted, and never raise.
    monkeypatch.setattr(wpfy.site_layout.os, "geteuid", lambda: 1000, raising=False)
    called = []
    monkeypatch.setattr(wpfy.site_layout.os, "chown", lambda *a, **k: called.append(a))
    result = wpfy.site_layout._apply_site_ownership("own.example.com", 100000)
    assert result.skipped is True
    assert called == []


def test_apply_site_ownership_chowns_when_root(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    spec = wpfy.site_layout.SiteSpec(domain="root.example.com", flavor="wpredis", use_mysql=True, use_redis=True)
    wpfy.site_layout.ensure_site_scaffold(spec)
    (wpfy.site_layout.app_dir("root.example.com") / "index.php").write_text("<?php\n", encoding="utf-8")

    chowned: list[tuple] = []
    monkeypatch.setattr(wpfy.site_layout.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(wpfy.site_layout.os, "chown", lambda path, uid, gid: chowned.append((str(path), uid, gid)))
    result = wpfy.site_layout._apply_site_ownership("root.example.com", 100042)

    assert result.ran is True
    owned = {path for path, uid, gid in chowned}
    assert all(uid == 100042 and gid == 100042 for _, uid, gid in chowned)
    assert str(wpfy.site_layout.app_dir("root.example.com")) in owned
    assert str(wpfy.site_layout.app_dir("root.example.com") / "index.php") in owned
    assert str(wpfy.site_layout.db_data_dir("root.example.com")) in owned
    assert str(wpfy.site_layout.redis_data_dir("root.example.com")) in owned


def test_ensure_site_scaffold_writes_hardened_nginx(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    spec = wpfy.site_layout.SiteSpec(domain="nginx.example.com", flavor="wp", use_mysql=True, use_redis=False)

    wpfy.site_layout.ensure_site_scaffold(spec)

    content = wpfy.site_layout.nginx_conf_path("nginx.example.com").read_text(encoding="utf-8")
    assert "server_tokens off;" in content
    assert "autoindex off;" in content
    assert "X-Content-Type-Options nosniff" in content
    assert "^/wp-content/uploads/.*\\.php$" in content
    assert "wp-config\\.php" in content
    assert "xmlrpc\\.php" in content
    assert "\\.(?:bak|backup|old|orig|save|sql|sqlite|zip|tar|tgz|gz|log)$" in content
    assert "/\\.(?!well-known" in content


def test_backup_archive_is_not_world_readable(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    spec = wpfy.site_layout.SiteSpec(domain="backup.example.com", flavor="site", use_mysql=False, use_redis=False)
    wpfy.site_layout.ensure_site_scaffold(spec)

    result = wpfy.site_layout.backup_site("backup.example.com")

    assert result.exit_code == 0
    archive_path = result.message.removeprefix("backup created: ")
    mode = stat.S_IMODE(Path(archive_path).stat().st_mode)
    assert mode == 0o600


def test_provision_wordpress_runs_expected_wp_cli_sequence(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout
    from wpfy.site_layout import RuntimeResult

    importlib.reload(wpfy.site_layout)
    domain = "install.example.com"
    spec = wpfy.site_layout.SiteSpec(domain=domain, flavor="wp", use_mysql=True, use_redis=False)
    wpfy.site_layout.ensure_site_scaffold(spec)
    app_root = wpfy.site_layout.app_dir(domain)
    (app_root / "wp-includes").mkdir(parents=True)
    (app_root / "wp-includes" / "version.php").write_text("<?php\n", encoding="utf-8")

    calls = []

    class Proc:
        def __init__(self, returncode=0, stdout="", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def fake_wp_cli(domain_arg, *args, input_text=None):
        calls.append((args, input_text))
        if args[:3] == ("core", "is-installed", "--allow-root"):
            return Proc(returncode=1, stderr="not installed")
        return Proc()

    monkeypatch.setattr(wpfy.site_layout, "docker_available", lambda: True)
    monkeypatch.setattr(wpfy.site_layout, "_wait_for_service", lambda domain_arg, service: RuntimeResult(0, "db ready", ran=True))
    monkeypatch.setattr(wpfy.site_layout, "wp_cli_command", fake_wp_cli)

    result = wpfy.site_layout.provision_wordpress_site(
        domain,
        "admin",
        "admin@example.com",
        "secret-password",
    )

    assert result.exit_code == 0
    assert [call[0][:2] for call in calls] == [
        ("core", "is-installed"),
        ("db", "create"),
        ("core", "install"),
    ]
    assert calls[-1][1] == "secret-password\n"
    assert "--prompt=admin_password" in calls[-1][0]
    assert "--url=http://install.example.com" in calls[-1][0]
    assert "--admin_user=admin" in calls[-1][0]
    assert "--admin_email=admin@example.com" in calls[-1][0]


def test_provision_wordpress_uses_https_url_when_ssl_enabled(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout
    from wpfy.site_layout import RuntimeResult

    importlib.reload(wpfy.site_layout)
    domain = "secure-install.example.com"
    spec = wpfy.site_layout.SiteSpec(
        domain=domain,
        flavor="wp",
        use_mysql=True,
        use_redis=False,
        letsencrypt="default",
        ssl_enabled=True,
    )
    wpfy.site_layout.ensure_site_scaffold(spec)
    app_root = wpfy.site_layout.app_dir(domain)
    (app_root / "wp-includes").mkdir(parents=True)
    (app_root / "wp-includes" / "version.php").write_text("<?php\n", encoding="utf-8")

    calls = []

    class Proc:
        def __init__(self, returncode=0, stdout="", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def fake_wp_cli(domain_arg, *args, input_text=None):
        calls.append(args)
        if args[:3] == ("core", "is-installed", "--allow-root"):
            return Proc(returncode=1, stderr="not installed")
        return Proc()

    monkeypatch.setattr(wpfy.site_layout, "docker_available", lambda: True)
    monkeypatch.setattr(wpfy.site_layout, "_wait_for_service", lambda domain_arg, service: RuntimeResult(0, "db ready", ran=True))
    monkeypatch.setattr(wpfy.site_layout, "wp_cli_command", fake_wp_cli)

    result = wpfy.site_layout.provision_wordpress_site(domain, "admin", "admin@example.com", "secret-password")

    assert result.exit_code == 0
    assert "--url=https://secure-install.example.com" in calls[-1]


def test_provision_wordpress_downloads_core_when_absent(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout
    from wpfy.site_layout import RuntimeResult

    importlib.reload(wpfy.site_layout)
    domain = "download.example.com"
    spec = wpfy.site_layout.SiteSpec(domain=domain, flavor="wp", use_mysql=True, use_redis=False)
    wpfy.site_layout.ensure_site_scaffold(spec)

    calls = []

    class Proc:
        def __init__(self, returncode=0, stdout="", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def fake_wp_cli(domain_arg, *args, input_text=None):
        calls.append(args)
        if args[:3] == ("core", "is-installed", "--allow-root"):
            return Proc(returncode=1, stderr="not installed")
        return Proc()

    monkeypatch.setattr(wpfy.site_layout, "docker_available", lambda: True)
    monkeypatch.setattr(wpfy.site_layout, "_wait_for_service", lambda domain_arg, service: RuntimeResult(0, "db ready", ran=True))
    monkeypatch.setattr(wpfy.site_layout, "wp_cli_command", fake_wp_cli)

    result = wpfy.site_layout.provision_wordpress_site(domain, "admin", "admin@example.com", "secret-password")

    assert result.exit_code == 0
    assert ("core", "download", "--force", "--allow-root") in calls


def test_provision_wordpress_is_idempotent_when_already_installed(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    domain = "installed.example.com"
    spec = wpfy.site_layout.SiteSpec(domain=domain, flavor="wp", use_mysql=True, use_redis=False)
    wpfy.site_layout.ensure_site_scaffold(spec)
    calls = []

    class Proc:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_wp_cli(domain_arg, *args, input_text=None):
        calls.append(args)
        return Proc()

    monkeypatch.setattr(wpfy.site_layout, "docker_available", lambda: True)
    monkeypatch.setattr(wpfy.site_layout, "wp_cli_command", fake_wp_cli)

    result = wpfy.site_layout.provision_wordpress_site(domain, "admin", "admin@example.com", "secret-password")

    assert result.exit_code == 0
    assert result.message == "wordpress already installed"
    assert calls == [("core", "is-installed", "--allow-root")]


def test_provision_wordpress_redacts_password_from_errors(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout
    from wpfy.site_layout import RuntimeResult

    importlib.reload(wpfy.site_layout)
    domain = "redact.example.com"
    spec = wpfy.site_layout.SiteSpec(domain=domain, flavor="wp", use_mysql=True, use_redis=False)
    wpfy.site_layout.ensure_site_scaffold(spec)
    app_root = wpfy.site_layout.app_dir(domain)
    (app_root / "wp-includes").mkdir(parents=True)
    (app_root / "wp-includes" / "version.php").write_text("<?php\n", encoding="utf-8")

    class Proc:
        def __init__(self, returncode=0, stdout="", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def fake_wp_cli(domain_arg, *args, input_text=None):
        if args[:3] == ("core", "is-installed", "--allow-root"):
            return Proc(returncode=1, stderr="not installed")
        if args[:2] == ("core", "install"):
            return Proc(returncode=1, stderr="failed with secret-password")
        return Proc()

    monkeypatch.setattr(wpfy.site_layout, "docker_available", lambda: True)
    monkeypatch.setattr(wpfy.site_layout, "_wait_for_service", lambda domain_arg, service: RuntimeResult(0, "db ready", ran=True))
    monkeypatch.setattr(wpfy.site_layout, "wp_cli_command", fake_wp_cli)

    result = wpfy.site_layout.provision_wordpress_site(domain, "admin", "admin@example.com", "secret-password")

    assert result.exit_code == 1
    assert "secret-password" not in result.message
    assert "***REDACTED***" in result.message


def test_wordpress_config_escapes_database_values():
    import wpfy.site_layout

    content = wpfy.site_layout._wordpress_config_content({
        "DB_NAME": "wp'name",
        "DB_USER": "wp\\user",
        "DB_PASSWORD": "pa'ss\\word",
    })

    assert "wp\\'name" in content
    assert "wp\\\\user" in content
    assert "pa\\'ss\\\\word" in content


def _write_tar_with_text(path: Path, members: dict[str, str]) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for name, text in members.items():
            data = text.encode("utf-8")
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))


def test_restore_rejects_parent_path_member(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    archive = Path(tmp_wpfy_home.state_dir) / "evil.tar.gz"
    archive.parent.mkdir(parents=True, exist_ok=True)
    _write_tar_with_text(archive, {"restore.example.com/compose.yaml": "services: {}\n", "../escape": "bad"})

    result = wpfy.site_layout.restore_site("restore.example.com", str(archive))

    assert result.exit_code == 2
    assert "unsafe path" in result.message
    assert not (Path(tmp_wpfy_home.install_root) / "escape").exists()


def test_restore_validates_archive_before_stopping_runtime(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    archive = Path(tmp_wpfy_home.state_dir) / "unsafe-runtime.tar.gz"
    archive.parent.mkdir(parents=True, exist_ok=True)
    _write_tar_with_text(archive, {"restore-runtime.example.com/compose.yaml": "services: {}\n", "../escape": "bad"})
    calls = []

    class Proc:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr(wpfy.site_layout, "docker_available", lambda: True)
    monkeypatch.setattr(wpfy.site_layout, "compose_command", lambda *args: calls.append(args) or Proc())

    result = wpfy.site_layout.restore_site("restore-runtime.example.com", str(archive))

    assert result.exit_code == 2
    assert "unsafe path" in result.message
    assert calls == []


def test_restore_rejects_absolute_path_member(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    archive = Path(tmp_wpfy_home.state_dir) / "absolute.tar.gz"
    archive.parent.mkdir(parents=True, exist_ok=True)
    _write_tar_with_text(archive, {"/tmp/wpfy-escape": "bad"})

    result = wpfy.site_layout.restore_site("absolute.example.com", str(archive))

    assert result.exit_code == 2
    assert "absolute path" in result.message


def test_restore_rejects_link_member(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    archive = Path(tmp_wpfy_home.state_dir) / "link.tar.gz"
    archive.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "w:gz") as tar:
        info = tarfile.TarInfo("link.example.com/app")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc"
        tar.addfile(info)

    result = wpfy.site_layout.restore_site("link.example.com", str(archive))

    assert result.exit_code == 2
    assert "unsupported link" in result.message


def test_restore_rejects_archive_for_other_domain(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    archive = Path(tmp_wpfy_home.state_dir) / "wrong-domain.tar.gz"
    archive.parent.mkdir(parents=True, exist_ok=True)
    _write_tar_with_text(archive, {"other.example.com/compose.yaml": "services: {}\n"})

    result = wpfy.site_layout.restore_site("target.example.com", str(archive))

    assert result.exit_code == 2
    assert "another site" in result.message


def test_restore_valid_archive_preserves_private_env(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    archive = Path(tmp_wpfy_home.state_dir) / "valid.tar.gz"
    archive.parent.mkdir(parents=True, exist_ok=True)
    _write_tar_with_text(archive, {
        "valid.example.com/compose.yaml": "services: {}\n",
        "valid.example.com/.env": "DOMAIN=valid.example.com\n",
    })

    result = wpfy.site_layout.restore_site("valid.example.com", str(archive))

    assert result.exit_code == 0
    mode = stat.S_IMODE(wpfy.site_layout.env_path("valid.example.com").stat().st_mode)
    assert mode == 0o600


def test_nginx_conf_allows_large_uploads_and_long_requests(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    spec = wpfy.site_layout.SiteSpec(domain="uploads.example.com", flavor="wp", use_mysql=True, use_redis=False)

    wpfy.site_layout.ensure_site_scaffold(spec)

    content = wpfy.site_layout.nginx_conf_path("uploads.example.com").read_text(encoding="utf-8")
    # Matches the bundled PHP images (upload_max_filesize 64M, max_execution_time 300).
    assert "client_max_body_size 64m;" in content
    assert "fastcgi_read_timeout 300s;" in content


def test_nginx_conf_php_handler_is_case_insensitive_with_missing_file_guard(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    spec = wpfy.site_layout.SiteSpec(domain="phpcase.example.com", flavor="wp", use_mysql=True, use_redis=False)

    wpfy.site_layout.ensure_site_scaffold(spec)

    content = wpfy.site_layout.nginx_conf_path("phpcase.example.com").read_text(encoding="utf-8")
    assert "location ~* \\.php$ {" in content
    assert "try_files $uri =404;" in content


def test_nginx_conf_hsts_only_when_ssl_enabled(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    hsts = "Strict-Transport-Security"

    plain = wpfy.site_layout.SiteSpec(domain="plain.example.com", flavor="wp", use_mysql=True, use_redis=False)
    wpfy.site_layout.ensure_site_scaffold(plain)
    assert hsts not in wpfy.site_layout.nginx_conf_path("plain.example.com").read_text(encoding="utf-8")

    ssl = wpfy.site_layout.SiteSpec(
        domain="tls.example.com", flavor="wp", use_mysql=True, use_redis=False,
        letsencrypt="default", ssl_enabled=True,
    )
    wpfy.site_layout.ensure_site_scaffold(ssl)
    assert hsts in wpfy.site_layout.nginx_conf_path("tls.example.com").read_text(encoding="utf-8")


def test_env_content_preserves_operator_added_keys():
    spec = _spec(domain="example.com", flavor="wp", use_mysql=True, use_redis=False)
    existing = {
        "DB_PASSWORD": "keep-db",
        "WP_DEBUG": "1",
        "MY_API_KEY": "operator-added",
    }

    content = env_content(spec, existing)

    assert "WP_DEBUG=1" in content
    assert "MY_API_KEY=operator-added" in content
    assert "DB_PASSWORD=keep-db" in content


def test_env_content_still_drops_managed_keys_owned_by_spec():
    # SFTP disabled in the spec: SFTP_* must not be resurrected from the old .env.
    spec = _spec(domain="example.com", flavor="wp", use_mysql=True, use_redis=False)
    existing = {"SFTP_PASSWORD": "old-secret", "SFTP_PORT": "2222", "CUSTOM": "kept"}

    content = env_content(spec, existing)

    assert "SFTP_PASSWORD" not in content
    assert "SFTP_PORT" not in content
    assert "CUSTOM=kept" in content


def test_ensure_site_scaffold_rejects_compose_project_collision(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    first = wpfy.site_layout.SiteSpec(domain="a-b.example.com", flavor="html", use_mysql=False, use_redis=False)
    wpfy.site_layout.ensure_site_scaffold(first)

    second = wpfy.site_layout.SiteSpec(domain="a.b.example.com", flavor="html", use_mysql=False, use_redis=False)
    with pytest.raises(ValueError, match="compose project"):
        wpfy.site_layout.ensure_site_scaffold(second)

    # Re-running the original domain stays idempotent.
    wpfy.site_layout.ensure_site_scaffold(first)


def test_site_exists_rejects_traversal_input(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    assert wpfy.site_layout.site_exists("../../etc") is False
    assert wpfy.site_layout.site_exists("/etc") is False
    assert wpfy.site_layout.site_exists("not a domain") is False


def test_stop_site_runtime_omits_volume_removal_by_default(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    monkeypatch.delenv("WPFY_SKIP_RUNTIME", raising=False)
    monkeypatch.setattr(wpfy.site_layout, "docker_available", lambda: True)
    calls = []

    class Proc:
        returncode = 0
        stdout = "stopped"
        stderr = ""

    monkeypatch.setattr(wpfy.site_layout, "compose_command", lambda domain, *args: calls.append(args) or Proc())

    wpfy.site_layout.stop_site_runtime("stop.example.com")
    wpfy.site_layout.stop_site_runtime("stop.example.com", remove_volumes=True)

    assert calls == [("down",), ("down", "-v")]


def test_extract_tar_safely_rejects_traversal_member(tmp_path):
    import wpfy.site_layout

    archive_path = tmp_path / "evil.tar.gz"
    _write_tar_with_text(archive_path, {"wordpress/index.php": "<?php\n", "../escape.txt": "bad"})
    destination = tmp_path / "dest"
    destination.mkdir()

    with tarfile.open(archive_path, "r:gz") as archive:
        with pytest.raises(Exception):
            wpfy.site_layout._extract_tar_safely(archive, str(destination))

    assert not (tmp_path / "escape.txt").exists()


def test_restore_preserves_live_db_credentials_when_db_initialized(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    domain = "restore-live.example.com"
    spec = wpfy.site_layout.SiteSpec(domain=domain, flavor="wp", use_mysql=True, use_redis=False)
    wpfy.site_layout.ensure_site_scaffold(spec)

    backup = wpfy.site_layout.backup_site(domain)
    assert backup.exit_code == 0
    archive_path = backup.message.removeprefix("backup created: ")

    # Rotate credentials after the backup and mark the DB volume as initialized:
    # the archive now carries stale credentials the volume no longer accepts.
    env_file = wpfy.site_layout.env_path(domain)
    rotated = wpfy.site_layout.read_env(env_file)
    old_password = rotated["DB_PASSWORD"]
    rotated["DB_PASSWORD"] = "rotated-live-password"
    rotated["DB_ROOT_PASSWORD"] = "rotated-root-password"
    env_file.write_text("\n".join(f"{k}={v}" for k, v in rotated.items()) + "\n", encoding="utf-8")
    (wpfy.site_layout.db_data_dir(domain) / "ibdata1").write_text("initialized", encoding="utf-8")

    result = wpfy.site_layout.restore_site(domain, archive_path)

    restored = wpfy.site_layout.read_env(env_file)
    assert result.exit_code == 0
    assert restored["DB_PASSWORD"] == "rotated-live-password"
    assert restored["DB_ROOT_PASSWORD"] == "rotated-root-password"
    assert restored["DB_PASSWORD"] != old_password


def test_restore_keeps_archive_credentials_for_uninitialized_db(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    domain = "restore-fresh.example.com"
    spec = wpfy.site_layout.SiteSpec(domain=domain, flavor="wp", use_mysql=True, use_redis=False)
    wpfy.site_layout.ensure_site_scaffold(spec)

    backup = wpfy.site_layout.backup_site(domain)
    assert backup.exit_code == 0
    archive_path = backup.message.removeprefix("backup created: ")

    env_file = wpfy.site_layout.env_path(domain)
    archived = wpfy.site_layout.read_env(env_file)
    rotated = dict(archived)
    rotated["DB_PASSWORD"] = "rotated-live-password"
    env_file.write_text("\n".join(f"{k}={v}" for k, v in rotated.items()) + "\n", encoding="utf-8")
    # db-data stays empty: MariaDB will initialize from the restored .env.

    result = wpfy.site_layout.restore_site(domain, archive_path)

    restored = wpfy.site_layout.read_env(env_file)
    assert result.exit_code == 0
    assert restored["DB_PASSWORD"] == archived["DB_PASSWORD"]
