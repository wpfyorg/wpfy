from __future__ import annotations

import io
import hashlib
import importlib
import os
import stat
import tarfile
from datetime import datetime, timezone
from pathlib import Path

import pytest
from wpfy.site_layout import validate_domain, domain_to_project, compose_content, env_content, SiteSpec


def _spec(**kwargs) -> SiteSpec:
    # compose_content requires an allocated site_uid (done by ensure_site_scaffold
    # in production); tests that build a spec by hand get a default unless overridden.
    kwargs.setdefault("site_uid", 100000)
    return SiteSpec(**kwargs)


def _mock_wordpress_download(monkeypatch, layout, members):
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w:gz") as archive:
        for name, content in members.items():
            member = tarfile.TarInfo(f"wordpress/{name}")
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    archive_bytes = payload.getvalue()

    class Response(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.close()

    responses = iter([
        Response(b'{"offers":[{"response":"upgrade","locale":"en_US","current":"7.0.1"}]}'),
        Response(hashlib.sha1(archive_bytes).hexdigest().encode("ascii")),
        Response(archive_bytes),
    ])
    monkeypatch.setattr(layout, "urlopen", lambda *args, **kwargs: next(responses))


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


def test_compose_content_with_wildcard_ssl_labels():
    content = compose_content(_spec(
        domain="example.com",
        flavor="wp",
        use_mysql=True,
        use_redis=False,
        letsencrypt="wildcard",
        dns_provider="cloudflare",
        ssl_enabled=True,
    ))

    assert "traefik.http.routers.example-com.tls.certresolver=le-dns-cloudflare" in content
    assert "traefik.http.routers.example-com.tls.domains[0].main=example.com" in content
    assert "traefik.http.routers.example-com.tls.domains[0].sans=*.example.com" in content
    assert "HostRegexp(`^.+\\.example\\.com$`)" in content
    assert (
        "      - 'traefik.http.routers.example-com.rule=Host(`example.com`) || "
        "HostRegexp(`^.+\\.example\\.com$`)'"
    ) in content
    assert (
        "      - 'traefik.http.routers.example-com-http.rule=Host(`example.com`) || "
        "HostRegexp(`^.+\\.example\\.com$`)'"
    ) in content


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


def test_compose_content_wpcli_mounts_per_site_security_staging_ro():
    spec = _spec(domain="example.com", flavor="wp", use_mysql=True, use_redis=False)
    content = compose_content(spec)
    assert "./security:/security:ro" in content


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


def test_compose_content_mounts_managed_cache_path_before_default_vhost():
    content = compose_content(_spec(domain="cache.example.com", flavor="wp", use_mysql=True, use_redis=False))

    cache_mount = "./nginx/cache-path.conf:/etc/nginx/conf.d/00-wpfy-cache-path.conf:ro"
    default_mount = "./nginx/default.conf:/etc/nginx/conf.d/default.conf:ro"
    assert cache_mount in content
    assert content.index(cache_mount) < content.index(default_mount)


def test_wpfc_scaffold_creates_mounts_and_owns_cache_data(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    domain = "writable-cache.example.com"
    spec = wpfy.site_layout.SiteSpec(
        domain=domain,
        flavor="wp",
        use_mysql=True,
        use_redis=False,
        page_cache="wpfc",
    )

    wpfy.site_layout.ensure_site_scaffold(spec)

    cache_root = wpfy.site_layout.site_dir(domain) / "cache-data"
    compose = wpfy.site_layout.compose_path(domain).read_text(encoding="utf-8")
    assert cache_root.is_dir()
    assert "./cache-data:/var/cache/nginx/fastcgi" in compose

    owned_inodes = set()
    modes = {}
    monkeypatch.setattr(wpfy.site_layout.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(
        wpfy.site_layout.os,
        "fchown",
        lambda fd, uid, gid: owned_inodes.add(os.fstat(fd).st_ino),
    )
    monkeypatch.setattr(
        wpfy.site_layout.os,
        "fchmod",
        lambda fd, mode: modes.__setitem__(os.fstat(fd).st_ino, mode),
    )
    monkeypatch.setattr(wpfy.site_layout.os, "chown", lambda *args, **kwargs: None)

    result = wpfy.site_layout._apply_site_ownership(domain, 100042)

    assert result.ran is True
    assert cache_root.stat().st_ino in owned_inodes
    assert modes[cache_root.stat().st_ino] == 0o700


def test_ensure_site_scaffold_writes_cache_managed_paths(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    domain = "cache-paths.example.com"
    spec = wpfy.site_layout.SiteSpec(
        domain=domain,
        flavor="wp",
        use_mysql=True,
        use_redis=False,
        page_cache="wpfc",
    )

    wpfy.site_layout.ensure_site_scaffold(spec)

    env = wpfy.site_layout.read_env(wpfy.site_layout.env_path(domain))
    assert env["PAGE_CACHE"] == "wpfc"
    assert (wpfy.site_layout.nginx_dir(domain) / "cache-path.conf").read_text(encoding="utf-8") == ""


def test_ensure_site_scaffold_skips_unrecognised_wp_config(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    domain = "unrecognised-config.example.com"
    spec = wpfy.site_layout.SiteSpec(domain=domain, flavor="wp", use_mysql=True, use_redis=False)
    wpfy.site_layout.ensure_site_scaffold(spec)
    config = wpfy.site_layout.app_dir(domain) / "wp-config.php"
    content = (
        b"<?php\n$table_prefix = 'wp_';\nif ( ! defined( 'ABSPATH' ) ) {\n"
        b"    define( 'ABSPATH', __DIR__ . '/' );\n}\nrequire_once ABSPATH . 'wp-settings.php';\n"
    )
    config.write_bytes(content)
    events = []
    monkeypatch.setattr(wpfy.site_layout, "record_event", lambda *args, **kwargs: events.append((args, kwargs)))

    wpfy.site_layout.ensure_site_scaffold(spec)

    assert config.read_bytes() == content
    assert events == [(("site.wp-config-anchor",), {
        "domain": domain,
        "outcome": "skipped",
        "detail": "wp-config.php anchor repair skipped: unrecognised config shape",
    })]


def test_ensure_site_scaffold_writes_private_env(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    spec = wpfy.site_layout.SiteSpec(domain="secure.example.com", flavor="wp", use_mysql=True, use_redis=False)

    wpfy.site_layout.ensure_site_scaffold(spec)

    mode = stat.S_IMODE(wpfy.site_layout.env_path("secure.example.com").stat().st_mode)
    assert mode == 0o600


def test_ensure_site_scaffold_rejects_env_symlink_before_writing_files(
    tmp_wpfy_home, monkeypatch, tmp_path
):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    domain = "env-scaffold-symlink.example.com"
    site_root = wpfy.site_layout.site_dir(domain)
    site_root.mkdir(parents=True)
    external = tmp_path / "external-env"
    external.write_bytes(b"sentinel")
    wpfy.site_layout.env_path(domain).symlink_to(external)
    spec = wpfy.site_layout.SiteSpec(domain=domain, flavor="wp", use_mysql=True, use_redis=False)

    with pytest.raises(ValueError, match="unsafe scaffold destination symlink"):
        wpfy.site_layout.ensure_site_scaffold(spec)

    assert external.read_bytes() == b"sentinel"
    assert not wpfy.site_layout.compose_path(domain).exists()


def test_ensure_site_scaffold_propagates_ownership_failure(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    domain = "ownership-scaffold-failure.example.com"
    monkeypatch.setattr(
        wpfy.site_layout,
        "_apply_site_ownership",
        lambda *args: wpfy.site_layout.RuntimeResult(3, "ownership failed safely"),
    )
    spec = wpfy.site_layout.SiteSpec(domain=domain, flavor="wp", use_mysql=True, use_redis=False)

    with pytest.raises(ValueError, match="ownership failed safely"):
        wpfy.site_layout.ensure_site_scaffold(spec)


def test_ensure_site_scaffold_preserves_non_utf8_access_log(tmp_wpfy_home):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    domain = "non-utf8-access-log.example.com"
    spec = wpfy.site_layout.SiteSpec(domain=domain, flavor="wp", use_mysql=True, use_redis=False)
    wpfy.site_layout.ensure_site_scaffold(spec)
    access_log = wpfy.site_layout.nginx_dir(domain) / wpfy.site_layout.site_security.ACCESS_LOG_FILE
    original = b'203.0.113.9 - - [28/Jul/2026:01:00:00 +0000] "GET / HTTP/1.1" 200 12 "-" "\xff"\n'
    access_log.write_bytes(original)

    touched = wpfy.site_layout.ensure_site_scaffold(spec)

    assert access_log.read_bytes() == original
    assert str(access_log) not in touched


def test_ensure_site_scaffold_rejects_env_symlink_inserted_after_validation(
    tmp_wpfy_home, monkeypatch, tmp_path
):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    domain = "env-scaffold-race.example.com"
    external = tmp_path / "external-env-race"
    external.write_bytes(b"sentinel")

    original_read = wpfy.site_layout._read_text_safely

    def read_and_swap(root, name):
        content = original_read(root, name)
        if name == ".env" and not wpfy.site_layout.env_path(domain).exists():
            wpfy.site_layout.env_path(domain).symlink_to(external)
        return content

    monkeypatch.setattr(wpfy.site_layout, "_read_text_safely", read_and_swap)
    spec = wpfy.site_layout.SiteSpec(domain=domain, flavor="wp", use_mysql=True, use_redis=False)

    with pytest.raises(ValueError, match="unsafe scaffold destination"):
        wpfy.site_layout.ensure_site_scaffold(spec)

    assert external.read_bytes() == b"sentinel"


def test_apply_site_ownership_rejects_environment_symlink(
    tmp_wpfy_home, monkeypatch, tmp_path
):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    domain = "ownership-env-symlink.example.com"
    site_root = wpfy.site_layout.site_dir(domain)
    site_root.mkdir(parents=True)
    external = tmp_path / "external-ownership-env"
    external.write_text("SITE_UID=100042\n", encoding="utf-8")
    wpfy.site_layout.env_path(domain).symlink_to(external)

    result = wpfy.site_layout.apply_site_ownership(domain)

    assert result.exit_code != 0
    assert "unsafe site environment" in result.message
    assert external.read_text(encoding="utf-8") == "SITE_UID=100042\n"


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


def test_ensure_site_scaffold_noop_preserves_registry_bytes_and_mtime(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    spec = wpfy.site_layout.SiteSpec(domain="registry-noop.example.com", flavor="wp", use_mysql=True, use_redis=False)
    wpfy.site_layout.ensure_site_scaffold(spec)
    registry_path = Path(tmp_wpfy_home.state_dir) / "sites.json"
    before = registry_path.read_bytes(), registry_path.stat().st_mtime_ns
    calls = []
    real_add = wpfy.site_layout.registry.add_site
    monkeypatch.setattr(
        wpfy.site_layout.registry,
        "add_site",
        lambda *args, **kwargs: calls.append(args) or real_add(*args, **kwargs),
    )

    assert wpfy.site_layout.ensure_site_scaffold(spec) == []
    assert calls == []
    assert (registry_path.read_bytes(), registry_path.stat().st_mtime_ns) == before


def test_ensure_site_scaffold_changed_metadata_preserves_registry_state(tmp_wpfy_home):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    domain = "registry-change.example.com"
    initial = wpfy.site_layout.SiteSpec(domain=domain, flavor="wp", use_mysql=True, use_redis=False)
    wpfy.site_layout.ensure_site_scaffold(initial)
    wpfy.site_layout.registry.update_site(domain, {"created_at": "kept", "maintenance": "enabled"})

    changed = wpfy.site_layout.SiteSpec(domain=domain, flavor="wpredis", use_mysql=True, use_redis=True)
    wpfy.site_layout.ensure_site_scaffold(changed)

    metadata = wpfy.site_layout.registry.get_site(domain)
    assert metadata is not None
    assert metadata["created_at"] == "kept"
    assert metadata["maintenance"] == "enabled"
    assert metadata["flavor"] == "wpredis"
    assert metadata["cache_type"] == "redis"


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
    descriptor_chowns: list[tuple[int, int]] = []
    monkeypatch.setattr(wpfy.site_layout.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(
        wpfy.site_layout.os,
        "chown",
        lambda path, uid, gid, **kwargs: chowned.append((str(path), uid, gid)),
    )
    monkeypatch.setattr(
        wpfy.site_layout.os,
        "fchown",
        lambda fd, uid, gid: descriptor_chowns.append((uid, gid)),
    )
    monkeypatch.setattr(wpfy.site_layout.os, "fchmod", lambda fd, mode: None)
    result = wpfy.site_layout._apply_site_ownership("root.example.com", 100042)

    assert result.ran is True
    assert all(uid == 100042 and gid == 100042 for _, uid, gid in chowned)
    assert all(uid == 100042 and gid == 100042 for uid, gid in descriptor_chowns)
    assert "index.php" in {path for path, _, _ in chowned}
    assert len(descriptor_chowns) >= 3


def test_apply_site_ownership_rejects_symlink_without_following_target(tmp_wpfy_home, monkeypatch, tmp_path):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    domain = "ownership-symlink.example.com"
    spec = wpfy.site_layout.SiteSpec(domain=domain, flavor="wp", use_mysql=True, use_redis=False)
    wpfy.site_layout.ensure_site_scaffold(spec)
    external = tmp_path / "external-owned-file"
    external.write_bytes(b"sentinel")
    (wpfy.site_layout.app_dir(domain) / "unsafe-link").symlink_to(external)
    monkeypatch.setattr(wpfy.site_layout.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(wpfy.site_layout.os, "fchown", lambda fd, uid, gid: None)
    monkeypatch.setattr(wpfy.site_layout.os, "fchmod", lambda fd, mode: None)
    chowned = []
    monkeypatch.setattr(
        wpfy.site_layout.os,
        "chown",
        lambda name, uid, gid, **kwargs: chowned.append(name),
    )

    result = wpfy.site_layout._apply_site_ownership(domain, 100042)

    assert result.exit_code != 0
    assert "unsafe site ownership symlink" in result.message
    assert "unsafe-link" not in chowned
    assert external.read_bytes() == b"sentinel"


def test_apply_site_ownership_rejects_broken_root_symlink(tmp_wpfy_home, monkeypatch, tmp_path):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    domain = "ownership-root-symlink.example.com"
    spec = wpfy.site_layout.SiteSpec(domain=domain, flavor="wp", use_mysql=True, use_redis=False)
    wpfy.site_layout.ensure_site_scaffold(spec)
    root = wpfy.site_layout.app_dir(domain)
    wpfy.site_layout.healthcheck_path(domain).unlink()
    root.rmdir()
    root.symlink_to(tmp_path / "missing-app", target_is_directory=True)
    monkeypatch.setattr(wpfy.site_layout.os, "geteuid", lambda: 0, raising=False)

    result = wpfy.site_layout._apply_site_ownership(domain, 100042)

    assert result.exit_code != 0
    assert "unsafe site ownership symlink" in result.message


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


def test_ensure_site_scaffold_rejects_healthcheck_symlink_without_writing_external(
    tmp_wpfy_home, monkeypatch, tmp_path
):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    domain = "health-symlink.example.com"
    app_root = wpfy.site_layout.app_dir(domain)
    app_root.mkdir(parents=True)
    external = tmp_path / "external-health"
    external.write_bytes(b"sentinel")
    wpfy.site_layout.healthcheck_path(domain).symlink_to(external)
    spec = wpfy.site_layout.SiteSpec(domain=domain, flavor="wp", use_mysql=True, use_redis=False)

    with pytest.raises(ValueError, match="unsafe scaffold destination symlink"):
        wpfy.site_layout.ensure_site_scaffold(spec)

    assert external.read_bytes() == b"sentinel"


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


def test_list_backup_archives_returns_newest_tarballs(tmp_wpfy_home):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    backups = wpfy.site_layout.backups_dir("list.example.com")
    backups.mkdir(parents=True)
    older = backups / "list.example.com-1.tar.gz"
    newer = backups / "list.example.com-2.tar.gz"
    ignored = backups / "list.example.com.sql"
    older.write_text("older", encoding="utf-8")
    newer.write_text("newer", encoding="utf-8")
    ignored.write_text("ignored", encoding="utf-8")
    older.touch()
    newer.touch()
    os.utime(older, (100, 100))
    os.utime(newer, (200, 200))

    assert wpfy.site_layout.list_backup_archives("list.example.com") == [newer, older]


def test_list_backup_archives_missing_directory_is_empty(tmp_wpfy_home):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)

    assert wpfy.site_layout.list_backup_archives("missing.example.com") == []


def test_list_backup_archives_rejects_invalid_domain(tmp_wpfy_home):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)

    with pytest.raises(ValueError, match="invalid domain"):
        wpfy.site_layout.list_backup_archives("../escape")


def test_prune_backup_archives_keeps_newest(tmp_wpfy_home):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    backups = wpfy.site_layout.backups_dir("prune.example.com")
    backups.mkdir(parents=True)
    oldest = backups / "prune.example.com-1.tar.gz"
    middle = backups / "prune.example.com-2.tar.gz"
    newest = backups / "prune.example.com-3.tar.gz"
    for index, path in enumerate((oldest, middle, newest), start=1):
        path.write_text(str(index), encoding="utf-8")
        os.utime(path, (index, index))

    result = wpfy.site_layout.prune_backup_archives("prune.example.com", 2)

    assert result.exit_code == 0
    assert not oldest.exists()
    assert middle.exists()
    assert newest.exists()


def test_backup_site_copies_verified_archive_to_destination(tmp_wpfy_home, monkeypatch, tmp_path):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    domain = "copy.example.com"
    spec = wpfy.site_layout.SiteSpec(domain=domain, flavor="site", use_mysql=False, use_redis=False)
    wpfy.site_layout.ensure_site_scaffold(spec)

    result = wpfy.site_layout.backup_site(domain, destination_dir=tmp_path / "exports")

    assert result.exit_code == 0
    canonical = next(wpfy.site_layout.backups_dir(domain).glob("*.tar.gz"))
    copied = tmp_path / "exports" / canonical.name
    assert canonical.exists()
    assert copied.exists()
    assert stat.S_IMODE(copied.stat().st_mode) == 0o600
    assert f"copied to: {copied}" in result.message


def test_wordpress_download_failure_is_nonzero_and_retryable(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    domain = "bootstrap-failure.example.com"
    spec = wpfy.site_layout.SiteSpec(domain=domain, flavor="wp", use_mysql=True, use_redis=False)
    wpfy.site_layout.ensure_site_scaffold(spec)
    monkeypatch.setattr(wpfy.site_layout, "urlopen", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("offline")))

    result = wpfy.site_layout.bootstrap_site_files(domain)

    assert result.exit_code != 0
    assert "offline" in result.message
    assert not (
        wpfy.site_layout.app_dir(domain).joinpath("index.php").exists()
        and wpfy.site_layout.app_dir(domain).joinpath("wp-config.php").exists()
    )


def test_wordpress_bootstrap_verifies_versioned_archive_before_open(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout as layout

    importlib.reload(layout)
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    domain = "verified-bootstrap.example.com"
    layout.ensure_site_scaffold(
        layout.SiteSpec(domain=domain, flavor="wp", use_mysql=True, use_redis=False)
    )
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w:gz") as archive:
        member = tarfile.TarInfo("wordpress/index.php")
        content = b"<?php\n"
        member.size = len(content)
        archive.addfile(member, io.BytesIO(content))
    archive_bytes = payload.getvalue()
    events = []

    class Response(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.close()

    responses = {
        layout.WORDPRESS_VERSION_URL: Response(
            b'{"offers":[{"response":"upgrade","locale":"en_US","current":"7.0.1"}]}'
        ),
        "https://wordpress.org/wordpress-7.0.1.tar.gz.sha1": Response(
            hashlib.sha1(archive_bytes).hexdigest().encode("ascii")
        ),
        "https://wordpress.org/wordpress-7.0.1.tar.gz": Response(archive_bytes),
    }
    original_tar_open = layout.tarfile.open

    def urlopen(url, **kwargs):
        events.append(url)
        return responses[url]

    def tar_open(*args, **kwargs):
        events.append("tar-open")
        return original_tar_open(*args, **kwargs)

    monkeypatch.setattr(layout, "urlopen", urlopen)
    monkeypatch.setattr(layout.tarfile, "open", tar_open)

    result = layout.bootstrap_site_files(domain)

    assert result.exit_code == 0
    assert "7.0.1 verified" in result.message
    assert events == [
        layout.WORDPRESS_VERSION_URL,
        "https://wordpress.org/wordpress-7.0.1.tar.gz.sha1",
        "https://wordpress.org/wordpress-7.0.1.tar.gz",
        "tar-open",
    ]


def test_wordpress_digest_mismatch_never_opens_archive(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout as layout

    importlib.reload(layout)
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    domain = "digest-mismatch.example.com"
    layout.ensure_site_scaffold(
        layout.SiteSpec(domain=domain, flavor="wp", use_mysql=True, use_redis=False)
    )

    class Response(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.close()

    responses = iter([
        Response(b'{"offers":[{"response":"upgrade","locale":"en_US","current":"7.0.1"}]}'),
        Response(b"0" * 40),
        Response(b"not the expected archive"),
    ])
    monkeypatch.setattr(layout, "urlopen", lambda *args, **kwargs: next(responses))
    monkeypatch.setattr(
        layout.tarfile,
        "open",
        lambda *args, **kwargs: pytest.fail("archive opened before digest verification"),
    )

    result = layout.bootstrap_site_files(domain)

    assert result.exit_code != 0
    assert "digest mismatch" in result.message
    assert not layout.app_dir(domain).joinpath("index.php").exists()


@pytest.mark.parametrize("archive_kind", ["malformed", "unsafe-member"])
def test_wordpress_bootstrap_rejects_checksum_valid_invalid_archives(
    tmp_wpfy_home, monkeypatch, tmp_path, archive_kind
):
    import wpfy.site_layout as layout

    importlib.reload(layout)
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    domain = f"{archive_kind}.example.com"
    layout.ensure_site_scaffold(
        layout.SiteSpec(domain=domain, flavor="wp", use_mysql=True, use_redis=False)
    )
    if archive_kind == "malformed":
        payload = b"not a tar archive"
    else:
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as archive:
            member = tarfile.TarInfo("../escape.php")
            member.size = 6
            archive.addfile(member, io.BytesIO(b"escape"))
        payload = stream.getvalue()

    class Response(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.close()

    responses = iter([
        Response(b'{"offers":[{"response":"upgrade","locale":"en_US","current":"7.0.1"}]}'),
        Response(hashlib.sha1(payload).hexdigest().encode()),
        Response(payload),
    ])
    monkeypatch.setattr(layout, "urlopen", lambda *args, **kwargs: next(responses))

    result = layout.bootstrap_site_files(domain)

    assert result.exit_code != 0
    assert "wordpress bootstrap failed:" in result.message
    assert "digest mismatch" not in result.message
    if archive_kind == "unsafe-member":
        assert "unsafe archive member: unsafe path" in result.message
        assert not (tmp_path / "escape.php").exists()


@pytest.mark.parametrize(
    ("link_path", "archive_member"),
    [
        ("wp-settings.php", "wp-settings.php"),
        ("wp-includes", "wp-includes/version.php"),
        ("wp-includes/assets", "wp-includes/assets/script.js"),
    ],
    ids=["file", "directory", "nested-directory"],
)
def test_wordpress_bootstrap_rejects_destination_symlinks(
    tmp_wpfy_home, monkeypatch, tmp_path, link_path, archive_member
):
    import wpfy.site_layout as layout

    importlib.reload(layout)
    domain = "symlink-bootstrap.example.com"
    layout.ensure_site_scaffold(
        layout.SiteSpec(domain=domain, flavor="wp", use_mysql=True, use_redis=False)
    )
    root = layout.app_dir(domain)
    destination = root / link_path
    destination.parent.mkdir(parents=True, exist_ok=True)
    if link_path.endswith(".php"):
        external = tmp_path / "external.php"
        external.write_bytes(b"sentinel")
        destination.symlink_to(external)
    else:
        external = tmp_path / "external"
        external.mkdir()
        (external / "sentinel").write_bytes(b"sentinel")
        destination.symlink_to(external, target_is_directory=True)
    _mock_wordpress_download(monkeypatch, layout, {archive_member: b"core data"})

    result = layout.bootstrap_site_files(domain)

    assert result.exit_code != 0
    assert "unsafe WordPress destination symlink" in result.message
    if external.is_dir():
        assert [path.name for path in external.iterdir()] == ["sentinel"]
    else:
        assert external.read_bytes() == b"sentinel"


@pytest.mark.parametrize("link_name", ["index.php", "wp-config.php"])
def test_wordpress_bootstrap_rejects_bootstrapped_marker_symlinks(
    tmp_wpfy_home, monkeypatch, tmp_path, link_name
):
    import wpfy.site_layout as layout

    importlib.reload(layout)
    domain = "symlink-marker.example.com"
    layout.ensure_site_scaffold(
        layout.SiteSpec(domain=domain, flavor="wp", use_mysql=True, use_redis=False)
    )
    root = layout.app_dir(domain)
    external = tmp_path / link_name
    external.write_bytes(b"sentinel")
    (root / link_name).symlink_to(external)
    other_name = "wp-config.php" if link_name == "index.php" else "index.php"
    (root / other_name).write_bytes(b"regular")

    result = layout.bootstrap_site_files(domain)

    assert result.exit_code != 0
    assert "unsafe WordPress destination symlink" in result.message
    assert external.read_bytes() == b"sentinel"


@pytest.mark.parametrize("destination_name", ["app", "healthcheck", "wp-content", "uploads"])
def test_wordpress_bootstrap_rejects_managed_tree_symlinks(
    tmp_wpfy_home, monkeypatch, tmp_path, destination_name
):
    import wpfy.site_layout as layout

    importlib.reload(layout)
    domain = "managed-tree-symlink.example.com"
    layout.ensure_site_scaffold(
        layout.SiteSpec(domain=domain, flavor="wp", use_mysql=True, use_redis=False)
    )
    root = layout.app_dir(domain)
    if destination_name == "app":
        layout.healthcheck_path(domain).unlink()
        root.rmdir()
        destination = root
    elif destination_name == "healthcheck":
        destination = layout.healthcheck_path(domain)
        destination.unlink()
    else:
        destination = root / "wp-content"
        if destination_name == "uploads":
            destination.mkdir()
            destination /= "uploads"
        (root / "index.php").write_bytes(b"regular")
        (root / "wp-config.php").write_bytes(b"regular")

    if destination_name == "healthcheck":
        external = tmp_path / "external-healthcheck"
        external.write_bytes(b"sentinel")
        destination.symlink_to(external)
    else:
        external = tmp_path / f"external-{destination_name}"
        external.mkdir()
        (external / "sentinel").write_bytes(b"sentinel")
        destination.symlink_to(external, target_is_directory=True)
    monkeypatch.setattr(
        layout,
        "urlopen",
        lambda *args, **kwargs: pytest.fail("download started after unsafe destination"),
    )

    result = layout.bootstrap_site_files(domain)

    assert result.exit_code != 0
    assert "unsafe WordPress destination symlink" in result.message
    if external.is_dir():
        assert [path.name for path in external.iterdir()] == ["sentinel"]
    else:
        assert external.read_bytes() == b"sentinel"


def test_wordpress_bootstrap_rejects_nested_symlink_in_completed_tree(
    tmp_wpfy_home, monkeypatch, tmp_path
):
    import wpfy.site_layout as layout

    importlib.reload(layout)
    domain = "completed-tree-symlink.example.com"
    layout.ensure_site_scaffold(
        layout.SiteSpec(domain=domain, flavor="wp", use_mysql=True, use_redis=False)
    )
    root = layout.app_dir(domain)
    (root / "index.php").write_bytes(b"regular")
    (root / "wp-config.php").write_bytes(b"regular")
    destination = root / "wp-includes" / "assets"
    destination.parent.mkdir()
    external = tmp_path / "external-assets"
    external.mkdir()
    (external / "sentinel").write_bytes(b"sentinel")
    destination.symlink_to(external, target_is_directory=True)

    result = layout.bootstrap_site_files(domain)

    assert result.exit_code != 0
    assert "unsafe WordPress destination symlink" in result.message
    assert [path.name for path in external.iterdir()] == ["sentinel"]


def test_wordpress_bootstrap_rejects_destination_swapped_after_validation(
    tmp_wpfy_home, monkeypatch, tmp_path
):
    import wpfy.site_layout as layout

    importlib.reload(layout)
    domain = "destination-race.example.com"
    layout.ensure_site_scaffold(
        layout.SiteSpec(domain=domain, flavor="wp", use_mysql=True, use_redis=False)
    )
    root = layout.app_dir(domain)
    destination = root / "wp-includes"
    destination.mkdir()
    external = tmp_path / "external-race"
    external.mkdir()
    (external / "sentinel").write_bytes(b"sentinel")
    _mock_wordpress_download(
        monkeypatch,
        layout,
        {"wp-includes/version.php": b"<?php $wp_version = '7.0.1';\n"},
    )
    original_destination_symlink = layout._destination_symlink

    def swap_after_validation(root_arg, destinations):
        unsafe = original_destination_symlink(root_arg, destinations)
        if unsafe is None and not isinstance(destinations, tuple):
            destination.rmdir()
            destination.symlink_to(external, target_is_directory=True)
        return unsafe

    monkeypatch.setattr(layout, "_destination_symlink", swap_after_validation)

    result = layout.bootstrap_site_files(domain)

    assert result.exit_code != 0
    assert (external / "sentinel").read_bytes() == b"sentinel"
    assert not (external / "version.php").exists()


def test_wordpress_bootstrap_rejects_healthcheck_swapped_before_write(
    tmp_wpfy_home, monkeypatch, tmp_path
):
    import wpfy.site_layout as layout

    importlib.reload(layout)
    domain = "healthcheck-race.example.com"
    layout.ensure_site_scaffold(
        layout.SiteSpec(domain=domain, flavor="wp", use_mysql=True, use_redis=False)
    )
    health_file = layout.healthcheck_path(domain)
    health_file.unlink()
    external = tmp_path / "external-healthcheck-race"
    external.write_bytes(b"sentinel")
    original_destination_symlink = layout._destination_symlink

    def swap_after_validation(root_arg, destinations):
        unsafe = original_destination_symlink(root_arg, destinations)
        if unsafe is None and destinations == (health_file,):
            health_file.symlink_to(external)
        return unsafe

    monkeypatch.setattr(layout, "_destination_symlink", swap_after_validation)

    result = layout.bootstrap_site_files(domain)

    assert result.exit_code != 0
    assert external.read_bytes() == b"sentinel"


def test_wordpress_bootstrap_rejects_content_directory_swapped_before_creation(
    tmp_wpfy_home, monkeypatch, tmp_path
):
    import wpfy.site_layout as layout

    importlib.reload(layout)
    domain = "content-race.example.com"
    layout.ensure_site_scaffold(
        layout.SiteSpec(domain=domain, flavor="wp", use_mysql=True, use_redis=False)
    )
    root = layout.app_dir(domain)
    external = tmp_path / "external-content-race"
    external.mkdir()
    (external / "sentinel").write_bytes(b"sentinel")
    original_destination_symlink = layout._destination_symlink

    def swap_after_validation(root_arg, destinations):
        unsafe = original_destination_symlink(root_arg, destinations)
        if unsafe is None and len(destinations) == 2 and destinations[-1].name == "uploads":
            (root / "wp-content").symlink_to(external, target_is_directory=True)
        return unsafe

    monkeypatch.setattr(layout, "_destination_symlink", swap_after_validation)

    result = layout.bootstrap_site_files(domain)

    assert result.exit_code != 0
    assert [path.name for path in external.iterdir()] == ["sentinel"]


def test_wordpress_offline_bootstrap_rejects_concurrent_unrelated_symlink(
    tmp_wpfy_home, monkeypatch, tmp_path
):
    import wpfy.site_layout as layout

    importlib.reload(layout)
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    domain = "offline-race.example.com"
    layout.ensure_site_scaffold(
        layout.SiteSpec(domain=domain, flavor="wp", use_mysql=True, use_redis=False)
    )
    monkeypatch.setenv("WPFY_SKIP_WORDPRESS_DOWNLOAD", "1")
    root = layout.app_dir(domain)
    external = tmp_path / "external-offline-race"
    external.mkdir()
    (external / "sentinel").write_bytes(b"sentinel")
    original_write = layout._write_text_safely

    def write_and_swap(root_arg, name, content):
        original_write(root_arg, name, content)
        if name == "wp-config.php":
            (root / "wp-includes").symlink_to(external, target_is_directory=True)

    monkeypatch.setattr(layout, "_write_text_safely", write_and_swap)

    result = layout.bootstrap_site_files(domain)

    assert result.exit_code != 0
    assert "unsafe WordPress destination symlink" in result.message
    assert [path.name for path in external.iterdir()] == ["sentinel"]


@pytest.mark.parametrize(("flavor", "index_name"), [("html", "index.html"), ("site", "index.php")])
def test_non_wordpress_bootstrap_returns_failure_for_index_symlink(
    tmp_wpfy_home, monkeypatch, tmp_path, flavor, index_name
):
    import wpfy.site_layout as layout

    importlib.reload(layout)
    domain = f"{flavor}-symlink.example.com"
    layout.ensure_site_scaffold(
        layout.SiteSpec(domain=domain, flavor=flavor, use_mysql=False, use_redis=False)
    )
    external = tmp_path / f"external-{index_name}"
    external.write_bytes(b"sentinel")
    (layout.app_dir(domain) / index_name).symlink_to(external)

    result = layout.bootstrap_site_files(domain)

    assert result.exit_code != 0
    assert external.read_bytes() == b"sentinel"


def test_ensure_wordpress_config_rejects_symlink(tmp_wpfy_home, tmp_path):
    import wpfy.site_layout as layout

    importlib.reload(layout)
    domain = "config-symlink.example.com"
    layout.ensure_site_scaffold(
        layout.SiteSpec(domain=domain, flavor="wp", use_mysql=True, use_redis=False)
    )
    external = tmp_path / "external-config.php"
    external.write_bytes(b"sentinel")
    (layout.app_dir(domain) / "wp-config.php").symlink_to(external)

    result = layout._ensure_wordpress_config(domain)

    assert result.exit_code != 0
    assert "unsafe WordPress destination symlink" in result.message
    assert external.read_bytes() == b"sentinel"


def test_wordpress_bootstrap_preserves_safe_existing_content(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout as layout

    importlib.reload(layout)
    domain = "safe-retry.example.com"
    layout.ensure_site_scaffold(
        layout.SiteSpec(domain=domain, flavor="wp", use_mysql=True, use_redis=False)
    )
    root = layout.app_dir(domain)
    (root / "operator.txt").write_text("keep me", encoding="utf-8")
    upload = root / "wp-content" / "uploads" / "operator.txt"
    upload.parent.mkdir(parents=True)
    upload.write_text("keep upload", encoding="utf-8")
    _mock_wordpress_download(
        monkeypatch,
        layout,
        {
            "index.php": b"<?php\n",
            "wp-config-sample.php": b"sample\n",
            "wp-includes/version.php": b"<?php $wp_version = '7.0.1';\n",
        },
    )

    result = layout.bootstrap_site_files(domain)

    assert result.exit_code == 0
    assert (root / "operator.txt").read_text(encoding="utf-8") == "keep me"
    assert upload.read_text(encoding="utf-8") == "keep upload"


def test_wordpress_bootstrap_rejects_partial_retry_while_runtime_is_active(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout as layout

    importlib.reload(layout)
    domain = "active-retry.example.com"
    layout.ensure_site_scaffold(
        layout.SiteSpec(domain=domain, flavor="wp", use_mysql=True, use_redis=False)
    )
    layout.healthcheck_path(domain).unlink()

    class Proc:
        returncode = 0
        stdout = "running-container-id\n"
        stderr = ""

    monkeypatch.setattr(layout, "docker_available", lambda: True)
    monkeypatch.setattr(layout, "runtime_skip_requested", lambda: False)
    monkeypatch.setattr(layout, "compose_command", lambda *args: Proc())
    monkeypatch.setattr(
        layout,
        "urlopen",
        lambda *args, **kwargs: pytest.fail("download started while runtime could mutate destination"),
    )

    result = layout.bootstrap_site_files(domain)

    assert result.exit_code != 0
    assert "stop the site runtime before retrying" in result.message
    assert not layout.healthcheck_path(domain).exists()


@pytest.mark.parametrize("payload", [b"{}", b"not-json", b'{"offers":[]}'])
def test_wordpress_release_metadata_fails_closed(monkeypatch, payload):
    import wpfy.site_layout as layout

    class Response(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.close()

    monkeypatch.setattr(layout, "urlopen", lambda *args, **kwargs: Response(payload))

    with pytest.raises(ValueError):
        layout._wordpress_release_version()


def test_backup_site_does_not_overwrite_same_second_archive(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    domain = "same-second.example.com"
    spec = wpfy.site_layout.SiteSpec(domain=domain, flavor="site", use_mysql=False, use_redis=False)
    wpfy.site_layout.ensure_site_scaffold(spec)

    class FixedDatetime:
        @classmethod
        def now(cls, tz):
            return datetime(2026, 7, 3, 8, 0, 0, tzinfo=timezone.utc)

    monkeypatch.setattr(wpfy.site_layout, "datetime", FixedDatetime)

    first = wpfy.site_layout.backup_site(domain)
    second = wpfy.site_layout.backup_site(domain)

    assert first.exit_code == 0
    assert second.exit_code == 0
    archives = sorted(wpfy.site_layout.backups_dir(domain).glob("*.tar.gz"))
    assert [path.name for path in archives] == [
        "same-second.example.com-20260703080000-1.tar.gz",
        "same-second.example.com-20260703080000.tar.gz",
    ]


def test_backup_site_does_not_copy_when_archive_verification_fails(tmp_wpfy_home, monkeypatch, tmp_path):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    domain = "verify-copy.example.com"
    spec = wpfy.site_layout.SiteSpec(domain=domain, flavor="site", use_mysql=False, use_redis=False)
    wpfy.site_layout.ensure_site_scaffold(spec)

    original_open = wpfy.site_layout.tarfile.open

    def fail_verification(name, mode="r", *args, **kwargs):
        if mode == "r:gz":
            raise tarfile.ReadError("bad archive")
        return original_open(name, mode, *args, **kwargs)

    monkeypatch.setattr(wpfy.site_layout.tarfile, "open", fail_verification)

    result = wpfy.site_layout.backup_site(domain, destination_dir=tmp_path / "exports")

    assert result.exit_code == 3
    assert not (tmp_path / "exports").exists()
    assert not list(wpfy.site_layout.backups_dir(domain).glob("*"))


def test_restore_rejects_non_tar_before_runtime_stop(tmp_wpfy_home, monkeypatch, tmp_path):
    import wpfy.site_layout as layout

    importlib.reload(layout)
    domain = "invalid-restore.example.com"
    archive_path = tmp_path / "invalid.tar.gz"
    archive_path.write_bytes(b"not a gzip archive")
    monkeypatch.setattr(
        layout,
        "stop_site_runtime",
        lambda *args, **kwargs: pytest.fail("runtime stopped before archive validation"),
    )

    result = layout.restore_site(domain, str(archive_path))

    assert result.exit_code == 2
    assert "invalid backup archive" in result.message


def test_backup_site_uploads_verified_archive_to_s3(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout
    from wpfy.s3_backup import S3Uploader

    importlib.reload(wpfy.site_layout)
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    monkeypatch.setenv("WPFY_BACKUP_S3_ENDPOINT", "https://storage.example.test")
    monkeypatch.setenv("WPFY_BACKUP_S3_BUCKET", "site-backups")
    monkeypatch.setenv("WPFY_BACKUP_S3_REGION", "auto")
    monkeypatch.setenv("WPFY_BACKUP_S3_ACCESS_KEY", "access-key")
    monkeypatch.setenv("WPFY_BACKUP_S3_SECRET_KEY", "secret-key")
    monkeypatch.setenv("WPFY_BACKUP_S3_PREFIX", "daily")
    domain = "s3.example.com"
    spec = wpfy.site_layout.SiteSpec(domain=domain, flavor="site", use_mysql=False, use_redis=False)
    wpfy.site_layout.ensure_site_scaffold(spec)
    captured = {}

    class Response(io.BytesIO):
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.close()

    def opener(request, *, timeout):
        captured["authorization"] = request.headers["Authorization"]
        captured["file_body"] = not isinstance(request.data, bytes)
        captured["url"] = request.full_url
        return Response()

    result = wpfy.site_layout.backup_site(domain, upload_s3=True, uploader=S3Uploader(opener))

    assert result.exit_code == 0
    assert captured["file_body"] is True
    assert "SignedHeaders=content-length;host;x-amz-content-sha256;x-amz-date" in captured["authorization"]
    assert captured["url"].startswith("https://storage.example.test/site-backups/daily/s3.example.com/s3.example.com-")
    assert "uploaded to: s3://site-backups/daily/s3.example.com/" in result.message
    assert "secret-key" not in result.message


def test_backup_site_skips_s3_upload_until_archive_verifies(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    domain = "verify-s3.example.com"
    spec = wpfy.site_layout.SiteSpec(domain=domain, flavor="site", use_mysql=False, use_redis=False)
    wpfy.site_layout.ensure_site_scaffold(spec)
    calls = []

    class FakeUploader:
        def upload_archive(self, config, archive_path, domain_arg):
            calls.append((config, archive_path, domain_arg))
            return "s3://never"

    original_open = wpfy.site_layout.tarfile.open

    def fail_verification(name, mode="r", *args, **kwargs):
        if mode == "r:gz":
            raise tarfile.ReadError("bad archive")
        return original_open(name, mode, *args, **kwargs)

    monkeypatch.setattr(wpfy.site_layout.tarfile, "open", fail_verification)

    result = wpfy.site_layout.backup_site(domain, upload_s3=True, uploader=FakeUploader())

    assert result.exit_code == 3
    assert calls == []


def test_backup_site_s3_failure_preserves_local_archive_and_redacts_secret(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    monkeypatch.setenv("WPFY_BACKUP_S3_ENDPOINT", "https://storage.example.test")
    monkeypatch.setenv("WPFY_BACKUP_S3_BUCKET", "site-backups")
    monkeypatch.setenv("WPFY_BACKUP_S3_REGION", "auto")
    monkeypatch.setenv("WPFY_BACKUP_S3_ACCESS_KEY", "access-key")
    monkeypatch.setenv("WPFY_BACKUP_S3_SECRET_KEY", "secret-key")
    domain = "failed-s3.example.com"
    spec = wpfy.site_layout.SiteSpec(domain=domain, flavor="site", use_mysql=False, use_redis=False)
    wpfy.site_layout.ensure_site_scaffold(spec)

    class FakeUploader:
        def upload_archive(self, config, archive_path, domain_arg):
            raise OSError(f"upload denied for {config.secret_key}")

    result = wpfy.site_layout.backup_site(domain, upload_s3=True, uploader=FakeUploader())

    local_path = Path(result.message.split("; ", maxsplit=1)[0].removeprefix("backup created: "))
    assert result.exit_code == 4
    assert local_path.exists()
    assert "secret-key" not in result.message
    assert "***REDACTED***" in result.message


def test_s3_uploader_uses_path_style_endpoint():
    from wpfy.s3_backup import S3Config, signed_put_request

    config = S3Config(
        endpoint="https://storage.example.test",
        bucket="site-backups",
        region="auto",
        prefix="daily",
        access_key="access-key",
        secret_key="secret-key",
    )

    request = signed_put_request(config, "daily/example.com/archive.tar.gz", b"payload")

    assert request.full_url == "https://storage.example.test/site-backups/daily/example.com/archive.tar.gz"
    assert "Authorization" in request.headers


def test_load_s3_config_reads_stored_file_when_env_missing(tmp_wpfy_home, monkeypatch):
    import wpfy.s3_backup

    importlib.reload(wpfy.s3_backup)
    config = wpfy.s3_backup.S3Config(
        endpoint="https://stored.example.test",
        bucket="stored-bucket",
        region="auto",
        prefix="weekly",
        access_key="stored-access",
        secret_key="stored-secret",
    )

    wpfy.s3_backup.write_s3_config(config)
    loaded = wpfy.s3_backup.load_s3_config()

    assert loaded == config
    assert stat.S_IMODE(wpfy.s3_backup.s3_config_path().stat().st_mode) == 0o600


def test_load_s3_config_env_overrides_stored_file(tmp_wpfy_home, monkeypatch):
    import wpfy.s3_backup

    importlib.reload(wpfy.s3_backup)
    wpfy.s3_backup.write_s3_config(
        wpfy.s3_backup.S3Config(
            endpoint="https://stored.example.test",
            bucket="stored-bucket",
            region="auto",
            prefix="stored",
            access_key="stored-access",
            secret_key="stored-secret",
        )
    )
    monkeypatch.setenv("WPFY_BACKUP_S3_ENDPOINT", "https://env.example.test")
    monkeypatch.setenv("WPFY_BACKUP_S3_BUCKET", "env-bucket")
    monkeypatch.setenv("WPFY_BACKUP_S3_REGION", "us-east-1")
    monkeypatch.setenv("WPFY_BACKUP_S3_ACCESS_KEY", "env-access")
    monkeypatch.setenv("WPFY_BACKUP_S3_SECRET_KEY", "env-secret")
    monkeypatch.setenv("WPFY_BACKUP_S3_PREFIX", "env-prefix")

    loaded = wpfy.s3_backup.load_s3_config()

    assert loaded.endpoint == "https://env.example.test"
    assert loaded.bucket == "env-bucket"
    assert loaded.secret_key == "env-secret"


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
    monkeypatch.setattr(
        wpfy.site_layout,
        "wait_for_service",
        lambda domain_arg, service: RuntimeResult(0, "db ready", ran=True),
    )
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
    monkeypatch.setattr(
        wpfy.site_layout,
        "wait_for_service",
        lambda domain_arg, service: RuntimeResult(0, "db ready", ran=True),
    )
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
    monkeypatch.setattr(
        wpfy.site_layout,
        "wait_for_service",
        lambda domain_arg, service: RuntimeResult(0, "db ready", ran=True),
    )
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
    monkeypatch.setattr(
        wpfy.site_layout,
        "wait_for_service",
        lambda domain_arg, service: RuntimeResult(0, "db ready", ran=True),
    )
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


def test_restore_rejects_fifo_member_before_stopping_runtime(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    domain = "fifo.example.com"
    archive = Path(tmp_wpfy_home.state_dir) / "fifo.tar.gz"
    archive.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "w:gz") as tar:
        root = tarfile.TarInfo(domain)
        root.type = tarfile.DIRTYPE
        tar.addfile(root)
        fifo = tarfile.TarInfo(f"{domain}/blocked-pipe")
        fifo.type = tarfile.FIFOTYPE
        tar.addfile(fifo)
    calls = []
    monkeypatch.setattr(wpfy.site_layout, "docker_available", lambda: True)
    monkeypatch.setattr(wpfy.site_layout, "runtime_skip_requested", lambda: False)
    monkeypatch.setattr(
        wpfy.site_layout,
        "compose_command",
        lambda *args: calls.append(args) or pytest.fail("runtime stopped for unsafe archive"),
    )

    result = wpfy.site_layout.restore_site(domain, str(archive))

    assert result.exit_code == 2
    assert "unsupported device file" in result.message
    assert calls == []


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


def test_restore_rejects_regular_file_site_root_before_stopping_runtime(
    tmp_wpfy_home, monkeypatch
):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    domain = "file-root.example.com"
    archive = Path(tmp_wpfy_home.state_dir) / "file-root.tar.gz"
    archive.parent.mkdir(parents=True, exist_ok=True)
    _write_tar_with_text(archive, {domain: "not a directory"})
    calls = []

    class Proc:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr(wpfy.site_layout, "docker_available", lambda: True)
    monkeypatch.setattr(wpfy.site_layout, "runtime_skip_requested", lambda: False)
    monkeypatch.setattr(
        wpfy.site_layout,
        "compose_command",
        lambda *args: calls.append(args) or Proc(),
    )

    result = wpfy.site_layout.restore_site(domain, str(archive))

    assert result.exit_code == 2
    assert "site root is not a directory" in result.message
    assert calls == []


def test_restore_rejects_database_volume_members_without_changing_live_data(
    tmp_wpfy_home, monkeypatch
):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    domain = "db-volume.example.com"
    archive = Path(tmp_wpfy_home.state_dir) / "db-volume.tar.gz"
    archive.parent.mkdir(parents=True, exist_ok=True)
    _write_tar_with_text(archive, {f"{domain}/db-data/ibdata1": "replacement"})
    live_data = wpfy.site_layout.db_data_dir(domain) / "ibdata1"
    live_data.parent.mkdir(parents=True)
    live_data.write_text("live", encoding="utf-8")

    result = wpfy.site_layout.restore_site(domain, str(archive))

    assert result.exit_code == 2
    assert "excluded database volume data" in result.message
    assert live_data.read_text(encoding="utf-8") == "live"


def test_restore_defensively_excludes_database_volume_from_merge(
    tmp_wpfy_home, monkeypatch
):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    monkeypatch.setattr(wpfy.site_layout, "_validate_restore_member", lambda *args: None)
    domain = "db-volume-defense.example.com"
    archive = Path(tmp_wpfy_home.state_dir) / "db-volume-defense.tar.gz"
    archive.parent.mkdir(parents=True, exist_ok=True)
    _write_tar_with_text(archive, {
        f"{domain}/compose.yaml": "services: {}\n",
        f"{domain}/db-data/ibdata1": "replacement",
    })
    live_data = wpfy.site_layout.db_data_dir(domain) / "ibdata1"
    live_data.parent.mkdir(parents=True)
    live_data.write_text("live", encoding="utf-8")

    result = wpfy.site_layout.restore_site(domain, str(archive))

    assert result.exit_code == 0
    assert live_data.read_text(encoding="utf-8") == "live"


def test_restore_reports_file_replacement_failure_without_restarting(
    tmp_wpfy_home, monkeypatch
):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    domain = "replace-failure.example.com"
    archive = Path(tmp_wpfy_home.state_dir) / "replace-failure.tar.gz"
    archive.parent.mkdir(parents=True, exist_ok=True)
    _write_tar_with_text(archive, {f"{domain}/compose.yaml": "services: {}\n"})

    class Proc:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr(wpfy.site_layout, "docker_available", lambda: True)
    monkeypatch.setattr(wpfy.site_layout, "runtime_skip_requested", lambda: False)
    monkeypatch.setattr(wpfy.site_layout, "compose_command", lambda *args: Proc())
    monkeypatch.setattr(
        wpfy.site_layout,
        "_remove_entries_safely",
        lambda *args: (_ for _ in ()).throw(OSError("replacement failed")),
    )
    monkeypatch.setattr(
        wpfy.site_layout,
        "start_site_runtime",
        lambda domain_arg: pytest.fail("runtime restarted after a partial restore"),
    )

    result = wpfy.site_layout.restore_site(domain, str(archive))

    assert result.exit_code == 3
    assert "failed to replace site files during restore" in result.message


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


def test_restore_rejects_symlinked_site_root(tmp_wpfy_home, monkeypatch, tmp_path):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    domain = "root-symlink.example.com"
    archive = Path(tmp_wpfy_home.state_dir) / "root-symlink.tar.gz"
    archive.parent.mkdir(parents=True, exist_ok=True)
    _write_tar_with_text(archive, {f"{domain}/compose.yaml": "services: {}\n"})
    external = tmp_path / "external-site-root"
    external.mkdir()
    (external / "sentinel").write_bytes(b"sentinel")
    target = wpfy.site_layout.site_dir(domain)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.symlink_to(external, target_is_directory=True)

    result = wpfy.site_layout.restore_site(domain, str(archive))

    assert result.exit_code != 0
    assert "restore target is an unsafe symlink" in result.message
    assert [path.name for path in external.iterdir()] == ["sentinel"]


def test_restore_rejects_broken_destination_symlink_without_following_it(
    tmp_wpfy_home, monkeypatch, tmp_path
):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    domain = "broken-symlink.example.com"
    archive = Path(tmp_wpfy_home.state_dir) / "broken-symlink.tar.gz"
    archive.parent.mkdir(parents=True, exist_ok=True)
    _write_tar_with_text(archive, {f"{domain}/app/index.php": "<?php\n"})
    target = wpfy.site_layout.site_dir(domain)
    target.mkdir(parents=True)
    external = tmp_path / "missing-external-app"
    (target / "app").symlink_to(external, target_is_directory=True)

    result = wpfy.site_layout.restore_site(domain, str(archive))

    assert result.exit_code != 0
    assert "restore target contains an unsafe symlink" in result.message
    assert not external.exists()


def test_restore_rejects_env_symlink_without_changing_external_mode(
    tmp_wpfy_home, monkeypatch, tmp_path
):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    domain = "env-symlink.example.com"
    archive = Path(tmp_wpfy_home.state_dir) / "env-symlink.tar.gz"
    archive.parent.mkdir(parents=True, exist_ok=True)
    _write_tar_with_text(archive, {f"{domain}/compose.yaml": "services: {}\n"})
    target = wpfy.site_layout.site_dir(domain)
    target.mkdir(parents=True)
    external = tmp_path / "external-env"
    external.write_bytes(b"sentinel")
    external.chmod(0o644)
    (target / ".env").symlink_to(external)

    result = wpfy.site_layout.restore_site(domain, str(archive))

    assert result.exit_code != 0
    assert "restore target contains an unsafe symlink" in result.message
    assert external.read_bytes() == b"sentinel"
    assert stat.S_IMODE(external.stat().st_mode) == 0o644


def test_restore_rejects_env_symlink_inserted_after_tree_scan(
    tmp_wpfy_home, monkeypatch, tmp_path
):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    domain = "env-race.example.com"
    archive = Path(tmp_wpfy_home.state_dir) / "env-race.tar.gz"
    archive.parent.mkdir(parents=True, exist_ok=True)
    _write_tar_with_text(archive, {f"{domain}/compose.yaml": "services: {}\n"})
    target = wpfy.site_layout.site_dir(domain)
    target.mkdir(parents=True)
    external = tmp_path / "external-env-race"
    external.write_bytes(b"sentinel")
    external.chmod(0o644)
    original_tree_symlink = wpfy.site_layout._tree_symlink

    def swap_after_scan(root):
        unsafe = original_tree_symlink(root)
        if root == target and unsafe is None:
            (target / ".env").symlink_to(external)
        return unsafe

    monkeypatch.setattr(wpfy.site_layout, "_tree_symlink", swap_after_scan)

    result = wpfy.site_layout.restore_site(domain, str(archive))

    assert result.exit_code != 0
    assert external.read_bytes() == b"sentinel"
    assert stat.S_IMODE(external.stat().st_mode) == 0o644


def test_restore_reapplies_site_ownership_after_copy(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    archive = Path(tmp_wpfy_home.state_dir) / "ownership.tar.gz"
    archive.parent.mkdir(parents=True, exist_ok=True)
    _write_tar_with_text(archive, {
        "ownership.example.com/compose.yaml": "services: {}\n",
        "ownership.example.com/.env": "DOMAIN=ownership.example.com\nSITE_UID=100042\n",
    })

    calls: list[str] = []
    monkeypatch.setattr(
        wpfy.site_layout,
        "apply_site_ownership",
        lambda domain: calls.append(domain) or wpfy.site_layout.RuntimeResult(0, "owned", ran=True),
    )

    result = wpfy.site_layout.restore_site("ownership.example.com", str(archive))

    assert result.exit_code == 0
    assert calls == ["ownership.example.com"]


def test_restore_stops_after_ownership_failure(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    domain = "restore-ownership-failure.example.com"
    archive = Path(tmp_wpfy_home.state_dir) / "restore-ownership-failure.tar.gz"
    archive.parent.mkdir(parents=True, exist_ok=True)
    _write_tar_with_text(archive, {f"{domain}/compose.yaml": "services: {}\n"})

    class Proc:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr(wpfy.site_layout, "docker_available", lambda: True)
    monkeypatch.setattr(wpfy.site_layout, "runtime_skip_requested", lambda: False)
    monkeypatch.setattr(wpfy.site_layout, "compose_command", lambda *args: Proc())
    monkeypatch.setattr(
        wpfy.site_layout,
        "apply_site_ownership",
        lambda domain_arg: wpfy.site_layout.RuntimeResult(3, "unsafe site ownership symlink"),
    )
    monkeypatch.setattr(
        wpfy.site_layout,
        "start_site_runtime",
        lambda domain_arg: pytest.fail("runtime restarted after ownership failure"),
    )

    result = wpfy.site_layout.restore_site(domain, str(archive))

    assert result.exit_code == 3
    assert "unsafe site ownership symlink" in result.message


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
    import wpfy.site_runtime

    importlib.reload(wpfy.site_layout)
    importlib.reload(wpfy.site_runtime)
    monkeypatch.delenv("WPFY_SKIP_RUNTIME", raising=False)
    monkeypatch.setattr(wpfy.site_runtime, "docker_available", lambda: True)
    calls = []

    class Proc:
        returncode = 0
        stdout = "stopped"
        stderr = ""

    monkeypatch.setattr(wpfy.site_runtime, "compose_command", lambda domain, *args: calls.append(args) or Proc())

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
    archive_path = backup.message.removeprefix("backup created: ").split(";", 1)[0]

    # Rotate credentials after the backup and mark the DB volume as initialized:
    # the archive now carries stale credentials the volume no longer accepts.
    env_file = wpfy.site_layout.env_path(domain)
    rotated = wpfy.site_layout.read_env(env_file)
    archived = dict(rotated)
    rotated["DB_NAME"] = "rotated_live_name"
    rotated["DB_USER"] = "rotated_live_user"
    rotated["DB_PASSWORD"] = "rotated-live-password"
    rotated["DB_ROOT_PASSWORD"] = "rotated-root-password"
    env_file.write_text("\n".join(f"{k}={v}" for k, v in rotated.items()) + "\n", encoding="utf-8")
    (wpfy.site_layout.db_data_dir(domain) / "ibdata1").write_text("initialized", encoding="utf-8")

    result = wpfy.site_layout.restore_site(domain, archive_path)

    restored = wpfy.site_layout.read_env(env_file)
    assert result.exit_code == 0
    for key in ("DB_NAME", "DB_USER", "DB_PASSWORD", "DB_ROOT_PASSWORD"):
        assert restored[key] == rotated[key]
        assert restored[key] != archived[key]


def test_restore_keeps_archive_credentials_for_uninitialized_db(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    domain = "restore-fresh.example.com"
    spec = wpfy.site_layout.SiteSpec(domain=domain, flavor="wp", use_mysql=True, use_redis=False)
    wpfy.site_layout.ensure_site_scaffold(spec)

    backup = wpfy.site_layout.backup_site(domain)
    assert backup.exit_code == 0
    archive_path = backup.message.removeprefix("backup created: ").split(";", 1)[0]

    env_file = wpfy.site_layout.env_path(domain)
    archived = wpfy.site_layout.read_env(env_file)
    rotated = dict(archived)
    rotated["DB_NAME"] = "rotated_live_name"
    rotated["DB_USER"] = "rotated_live_user"
    rotated["DB_PASSWORD"] = "rotated-live-password"
    rotated["DB_ROOT_PASSWORD"] = "rotated-root-password"
    env_file.write_text("\n".join(f"{k}={v}" for k, v in rotated.items()) + "\n", encoding="utf-8")
    # db-data stays empty: MariaDB will initialize from the restored .env.

    result = wpfy.site_layout.restore_site(domain, archive_path)

    restored = wpfy.site_layout.read_env(env_file)
    assert result.exit_code == 0
    for key in ("DB_NAME", "DB_USER", "DB_PASSWORD", "DB_ROOT_PASSWORD"):
        assert restored[key] == archived[key]


def test_compose_content_app_mounts_security_auth_log_and_bridge(tmp_wpfy_home):
    import wpfy.site_event_pipeline as pipeline

    content = compose_content(_spec(domain="example.com", flavor="wp", use_mysql=True, use_redis=False))
    log_mount = f"./security/{pipeline.AUTH_LOG_FILE}:{pipeline.AUTH_LOG_CONTAINER_PATH}"
    bridge_mount = f"./security/{pipeline.BRIDGE_MU_FILE}:{pipeline.BRIDGE_CONTAINER_PATH}:ro"
    assert log_mount in content
    assert bridge_mount in content
    # The auth log mount stays outside the document root; the bridge is read-only.
    assert "/var/www/html" not in log_mount
    assert bridge_mount.endswith(":ro")


def test_apply_site_ownership_owns_security_pipeline_files(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout
    import wpfy.site_event_pipeline as pipeline

    importlib.reload(wpfy.site_layout)
    domain = "ownership-pipeline.example.com"
    spec = wpfy.site_layout.SiteSpec(domain=domain, flavor="wp", use_mysql=True, use_redis=False)
    wpfy.site_layout.ensure_site_scaffold(spec)

    chowned: list[tuple] = []
    monkeypatch.setattr(wpfy.site_layout.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(
        wpfy.site_layout.os,
        "chown",
        lambda path, uid, gid, **kwargs: chowned.append((str(path), uid, gid)),
    )
    monkeypatch.setattr(wpfy.site_layout.os, "fchown", lambda fd, uid, gid: None)
    monkeypatch.setattr(wpfy.site_layout.os, "fchmod", lambda fd, mode: None)

    result = wpfy.site_layout._apply_site_ownership(domain, 100042)

    assert result.ran is True
    owned_paths = {path for path, _, _ in chowned}
    assert str(pipeline.auth_log_path(domain)) in owned_paths
    assert str(pipeline.bridge_path(domain)) in owned_paths


def test_ensure_site_scaffold_rejects_security_dir_symlink(tmp_wpfy_home, tmp_path):
    import wpfy.site_layout
    import wpfy.site_event_pipeline as pipeline

    importlib.reload(wpfy.site_layout)
    domain = "security-symlink.example.com"
    spec = wpfy.site_layout.SiteSpec(domain=domain, flavor="wp", use_mysql=True, use_redis=False)
    wpfy.site_layout.ensure_site_scaffold(spec)

    external = tmp_path / "external-security"
    external.mkdir()
    (external / "sentinel").write_bytes(b"sentinel")
    import shutil
    shutil.rmtree(pipeline.security_dir(domain))
    pipeline.security_dir(domain).symlink_to(external, target_is_directory=True)

    with pytest.raises(ValueError, match="unsafe scaffold destination symlink"):
        wpfy.site_layout.ensure_site_scaffold(spec)

    assert (external / "sentinel").read_bytes() == b"sentinel"
