from __future__ import annotations

from wpfy.site_definition import SiteDefinition
from wpfy.site_layout import compose_content, env_content


def test_site_definition_renders_sftp_across_persisted_representations():
    definition = SiteDefinition(
        domain="example.com",
        flavor="wpredis",
        use_mysql=True,
        use_redis=True,
        php_version="8.3",
        letsencrypt="default",
        ssl_enabled=True,
        sftp_password="secret",
        sftp_port="2230",
        site_uid=100005,
    )

    compose = compose_content(definition)
    env = env_content(definition)
    metadata = definition.registry_metadata()

    assert "  sftp:" in compose
    assert '"127.0.0.1:2230:22"' in compose
    # the sftp sidecar shares the site's per-site uid so its uploads align with php-fpm.
    assert "sftpuser:${SFTP_PASSWORD}:100005:100005:app" in compose
    assert "SFTP_PASSWORD=secret" in env
    assert "SFTP_PORT=2230" in env
    assert "SITE_UID=100005" in env
    assert metadata["sftp_enabled"] is True
    assert metadata["site_uid"] == 100005


def test_site_definition_loads_current_state_from_env():
    definition = SiteDefinition.from_env(
        "example.com",
        {
            "SITE_FLAVOR": "wpredis",
            "PHP_VERSION": "8.2",
            "LETSENCRYPT_MODE": "certbot",
            "PROXIED": "1",
            "SFTP_PASSWORD": "secret",
            "SFTP_PORT": "2225",
        },
    )

    assert definition.flavor == "wp"
    assert definition.page_cache == "none"
    assert definition.object_cache == "redis"
    assert definition.use_mysql is True
    assert definition.use_redis is True
    assert definition.ssl_enabled is True
    assert definition.proxied is True
    assert definition.sftp_port == "2225"


def test_site_definition_migrates_legacy_page_cache_flavor_on_load():
    definition = SiteDefinition.from_env(
        "legacy.example.com",
        {"SITE_FLAVOR": "wpfc", "PHP_VERSION": "8.4"},
    )

    assert definition.flavor == "wp"
    assert definition.page_cache == "wpfc"
    assert definition.object_cache == "none"
    rendered = env_content(definition)
    assert "SITE_FLAVOR=wp\n" in rendered
    assert "PAGE_CACHE=wpfc\n" in rendered


def test_site_definition_persists_orthogonal_page_and_object_cache():
    definition = SiteDefinition(
        domain="cache.example.com",
        flavor="wp",
        use_mysql=True,
        use_redis=True,
        page_cache="w3-total-cache",
        object_cache="redis",
    )

    rendered = env_content(definition)
    metadata = definition.registry_metadata()

    assert "PAGE_CACHE=w3-total-cache\n" in rendered
    assert "REDIS_ENABLED=1\n" in rendered
    assert metadata["page_cache"] == "w3-total-cache"
    assert metadata["object_cache"] == "redis"
