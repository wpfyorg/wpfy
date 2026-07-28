from __future__ import annotations

from dataclasses import replace
import importlib
import subprocess

import pytest


PAGE_CACHES = (
    "wpfc",
    "wp-super-cache",
    "w3-total-cache",
    "cache-enabler",
    "wp-fastest-cache",
    "wp-rocket",
    "flying-press",
)


def _modules(tmp_wpfy_home):
    import wpfy.site_paths
    import wpfy.site_layout
    import wpfy.site_cache

    importlib.reload(wpfy.site_paths)
    importlib.reload(wpfy.site_layout)
    importlib.reload(wpfy.site_cache)
    return wpfy.site_layout, wpfy.site_cache


def _definition(cache, *, page_cache="none", object_cache="none"):
    return cache.SiteDefinition(
        domain="cache.example.com",
        flavor="wp",
        use_mysql=True,
        use_redis=object_cache == "redis",
        page_cache=page_cache,
        object_cache=object_cache,
        site_uid=100000,
    )


@pytest.mark.parametrize("plugin", PAGE_CACHES)
def test_cache_snippets_explicitly_bypass_personalised_and_mutating_requests(plugin):
    from wpfy import site_cache as cache

    snippet = cache._cache_snippet(plugin)

    assert "set $wpfy_skip_cache 0;" in snippet
    assert snippet.count("set $wpfy_skip_cache 1;") >= 6
    for marker in (
        "wordpress_logged_in",
        "comment_author",
        "wp-postpass",
        "$request_method",
        "$query_string",
        "wp-admin",
    ):
        assert marker in snippet
    assert "fastcgi_cache_bypass $wpfy_skip_cache;" in snippet
    assert "fastcgi_no_cache $wpfy_skip_cache;" in snippet


def test_wpfc_renders_real_cache_zone_and_store_bypass():
    from wpfy import site_cache as cache

    assert "fastcgi_cache_path /var/cache/nginx/fastcgi" in cache._cache_path_snippet("wpfc")
    snippet = cache._cache_snippet("wpfc")
    assert "fastcgi_cache WPFY;" in snippet
    assert "fastcgi_cache_bypass $wpfy_skip_cache;" in snippet
    assert "fastcgi_no_cache $wpfy_skip_cache;" in snippet


def test_non_wpfc_keeps_cache_path_empty_and_does_not_mount_store(tmp_wpfy_home, monkeypatch):
    layout, cache = _modules(tmp_wpfy_home)
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    domain = "plugin-cache.example.com"
    definition = layout.SiteSpec(
        domain=domain,
        flavor="wp",
        use_mysql=True,
        use_redis=False,
        page_cache="wp-super-cache",
    )
    layout.ensure_site_scaffold(definition)

    result = cache.render_cache_nginx(domain)

    site_root = layout.site_dir(domain)
    assert result.exit_code == 0
    assert (site_root / "nginx" / "cache-path.conf").read_text(encoding="utf-8") == ""
    compose = (site_root / "compose.yaml").read_text(encoding="utf-8")
    assert "./cache-data:/var/cache/nginx/fastcgi" not in compose
    assert not (site_root / "cache-data").exists()


def test_generated_cache_path_install_preserves_single_file_mount_inode(tmp_wpfy_home, monkeypatch):
    layout, cache = _modules(tmp_wpfy_home)
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    domain = "inode-cache.example.com"
    definition = layout.SiteSpec(
        domain=domain,
        flavor="wp",
        use_mysql=True,
        use_redis=False,
        page_cache="wpfc",
    )
    layout.ensure_site_scaffold(definition)
    cache_path = layout.site_dir(domain) / "nginx" / "cache-path.conf"
    inode_before = cache_path.stat().st_ino

    result = cache.render_cache_nginx(domain)

    assert result.exit_code == 0
    assert cache_path.stat().st_ino == inode_before
    assert cache_path.read_text(encoding="utf-8") == cache._cache_path_snippet("wpfc")


def test_generated_cache_render_never_mounts_a_candidate_into_read_only_include_dir(
    tmp_wpfy_home, monkeypatch,
):
    """Generated snippets are trusted writes, not container-validated candidates."""
    layout, cache = _modules(tmp_wpfy_home)
    domain = "generated-cache.example.com"
    definition = layout.SiteSpec(
        domain=domain,
        flavor="wp",
        use_mysql=True,
        use_redis=False,
        page_cache="w3-total-cache",
    )
    layout.ensure_site_scaffold(definition)

    calls = []
    monkeypatch.setattr(cache, "runtime_skip_requested", lambda: False)
    monkeypatch.setattr(cache, "docker_available", lambda: True)
    monkeypatch.setattr(
        cache,
        "compose_command",
        lambda domain, *args: calls.append((domain, args)) or subprocess.CompletedProcess(args, 0, "", ""),
    )

    result = cache.render_cache_nginx(domain)

    assert result.exit_code == 0
    assert calls == [(domain, ("exec", "-T", "web", "nginx", "-s", "reload"))]
    assert not any(
        "/etc/nginx/wpfy-extra" in argument
        for _domain, args in calls
        for argument in args
    )
    assert (layout.site_dir(domain) / "nginx" / "extra" / "wpfy-cache.conf").read_text(
        encoding="utf-8",
    ).strip()


def test_generated_cache_reload_failure_is_nonzero_and_actionable(tmp_wpfy_home, monkeypatch):
    layout, cache = _modules(tmp_wpfy_home)
    domain = "reload-failure.example.com"
    definition = layout.SiteSpec(
        domain=domain,
        flavor="wp",
        use_mysql=True,
        use_redis=False,
        page_cache="wpfc",
    )
    layout.ensure_site_scaffold(definition)
    monkeypatch.setattr(cache, "runtime_skip_requested", lambda: False)
    monkeypatch.setattr(cache, "docker_available", lambda: True)
    monkeypatch.setattr(cache.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(
        cache,
        "compose_command",
        lambda domain, *args: subprocess.CompletedProcess(args, 17, "", "nginx: configuration test failed"),
    )

    result = cache.render_cache_nginx(domain)

    assert result.exit_code == 17
    assert result.status == "error"
    assert result.changed is True
    assert "nginx reload failed" in result.message
    assert "nginx: configuration test failed" in result.message
    assert f"run wpfy debug {domain}" in result.message


def test_generated_cache_reload_retries_shared_mount_propagation(tmp_wpfy_home, monkeypatch):
    layout, cache = _modules(tmp_wpfy_home)
    domain = "reload-retry.example.com"
    definition = layout.SiteSpec(
        domain=domain,
        flavor="wp",
        use_mysql=True,
        use_redis=False,
        page_cache="wpfc",
    )
    layout.ensure_site_scaffold(definition)
    monkeypatch.setattr(cache, "runtime_skip_requested", lambda: False)
    monkeypatch.setattr(cache, "docker_available", lambda: True)
    sleeps = []
    monkeypatch.setattr(cache.time, "sleep", sleeps.append)
    calls = []

    def compose_command(domain_arg, *args):
        calls.append(args)
        if len(calls) < 3:
            return subprocess.CompletedProcess(args, 1, "", "zone not propagated yet")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(cache, "compose_command", compose_command)

    result = cache.render_cache_nginx(domain)

    assert result.exit_code == 0
    assert calls == [("exec", "-T", "web", "nginx", "-s", "reload")] * 3
    assert sleeps == [0.5, 0.5]


def test_generated_cache_reload_exception_is_nonzero_and_actionable(tmp_wpfy_home, monkeypatch):
    layout, cache = _modules(tmp_wpfy_home)
    domain = "reload-exception.example.com"
    definition = layout.SiteSpec(
        domain=domain,
        flavor="wp",
        use_mysql=True,
        use_redis=False,
        page_cache="wpfc",
    )
    layout.ensure_site_scaffold(definition)
    monkeypatch.setattr(cache, "runtime_skip_requested", lambda: False)
    monkeypatch.setattr(cache, "docker_available", lambda: True)
    monkeypatch.setattr(cache, "compose_command", lambda *args: (_ for _ in ()).throw(OSError("docker missing")))

    result = cache.render_cache_nginx(domain)

    assert result.exit_code == 3
    assert result.status == "error"
    assert result.changed is True
    assert "nginx reload failed: docker missing" in result.message
    assert f"run wpfy debug {domain}" in result.message


@pytest.mark.parametrize(
    ("plugin", "slug"),
    (
        ("wpfc", "nginx-helper"),
        ("wp-super-cache", "wp-super-cache"),
        ("w3-total-cache", "w3-total-cache"),
        ("cache-enabler", "cache-enabler"),
        ("wp-fastest-cache", "wp-fastest-cache"),
    ),
)
def test_free_page_cache_install_uses_exact_wp_cli_argv(monkeypatch, plugin, slug):
    from wpfy import site_cache as cache

    calls = []
    monkeypatch.setattr(cache, "_definition", lambda domain: _definition(cache, page_cache=plugin))
    monkeypatch.setattr(
        cache,
        "run_wp_cli",
        lambda domain, *args, **kwargs: calls.append((domain, args, kwargs)) or cache.ProcessResult(0, ran=True),
    )

    result = cache.install_page_cache("cache.example.com", plugin)

    assert result.exit_code == 0
    assert calls[-1] == (
        "cache.example.com",
        ("plugin", "install", slug, "--activate"),
        {"interactive": False},
    )
    assert all("password" not in " ".join(args).lower() for _, args, _ in calls)


@pytest.mark.parametrize("plugin", ("wp-rocket", "flying-press"))
def test_byo_page_cache_never_issues_install(monkeypatch, plugin):
    from wpfy import site_cache as cache

    calls = []
    monkeypatch.setattr(cache, "_definition", lambda domain: _definition(cache, page_cache=plugin))
    monkeypatch.setattr(
        cache,
        "run_wp_cli",
        lambda domain, *args, **kwargs: calls.append(args) or cache.ProcessResult(0, ran=True),
    )

    result = cache.install_page_cache("cache.example.com", plugin)

    assert result.status == "awaiting-upload"
    assert "awaiting operator upload" in result.message
    assert not any(args[:2] == ("plugin", "install") for args in calls)


def test_wp_cache_constant_and_redis_wiring_use_exact_safe_argv(monkeypatch):
    from wpfy import site_cache as cache

    calls = []
    definition = _definition(cache, page_cache="w3-total-cache", object_cache="redis")
    monkeypatch.setattr(cache, "_definition", lambda domain: definition)
    monkeypatch.setattr(
        cache,
        "run_wp_cli",
        lambda domain, *args, **kwargs: calls.append(args) or cache.ProcessResult(0, ran=True),
    )

    assert cache.set_wp_cache_constants(definition.domain).exit_code == 0
    assert cache.wire_redis_backend(definition.domain).exit_code == 0

    assert calls == [
        ("config", "set", "WP_CACHE", "true", "--raw", "--type=constant"),
        ("plugin", "install", "redis-cache", "--activate"),
        ("config", "set", "WP_REDIS_HOST", "redis", "--type=constant"),
        ("config", "set", "WP_REDIS_PORT", "6379", "--raw", "--type=constant"),
        ("redis", "enable"),
    ]
    assert all("password" not in " ".join(args).lower() for args in calls)


def test_purge_attempts_plugin_then_always_clears_owned_layers(monkeypatch):
    from wpfy import site_cache as cache

    calls = []
    definition = _definition(cache, page_cache="w3-total-cache", object_cache="redis")
    monkeypatch.setattr(cache, "_definition", lambda domain: definition)
    monkeypatch.setattr(
        cache,
        "run_wp_cli",
        lambda domain, *args, **kwargs: calls.append(("plugin", args)) or cache.ProcessResult(1, stderr="command not found"),
    )
    monkeypatch.setattr(
        cache.cache_operations,
        "_nginx",
        lambda domain: calls.append(("nginx", domain)) or cache.cache_operations.CacheOutcome(
            domain, "nginx", "ok", "cache cleared",
        ),
    )
    monkeypatch.setattr(
        cache.cache_operations,
        "_redis",
        lambda domain: calls.append(("redis", domain)) or cache.cache_operations.CacheOutcome(
            domain, "redis", "ok", "cache flushed",
        ),
    )

    result = cache.purge_site_cache(definition.domain)

    assert result.exit_code == 0
    assert calls == [
        ("plugin", ("w3-total-cache", "flush", "all")),
        ("nginx", definition.domain),
        ("redis", definition.domain),
    ]
    assert result.outcomes[0].status == "skipped"


def test_switching_page_cache_is_idempotent_and_refresh_stable(tmp_wpfy_home, monkeypatch):
    layout, cache = _modules(tmp_wpfy_home)
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    domain = "switch-cache.example.com"
    definition = layout.SiteSpec(domain=domain, flavor="wp", use_mysql=True, use_redis=False)
    layout.ensure_site_scaffold(definition)
    monkeypatch.setattr(cache, "run_wp_cli", lambda *args, **kwargs: cache.ProcessResult(0, ran=True))

    first = cache.set_page_cache(domain, "w3-total-cache")
    site_root = layout.site_dir(domain)
    tracked = (
        site_root / ".env",
        site_root / "compose.yaml",
        site_root / "nginx" / "cache-path.conf",
        site_root / "nginx" / "extra" / "wpfy-cache.conf",
    )
    before = tuple(path.read_bytes() for path in tracked)
    second = cache.set_page_cache(domain, "w3-total-cache")
    after = tuple(path.read_bytes() for path in tracked)

    assert first.exit_code == 0
    assert second.exit_code == 0
    assert second.touched == ()
    assert before == after

    disabled = cache.set_page_cache(domain, "none")
    assert disabled.exit_code == 0
    assert not tracked[-1].exists()


def test_legacy_wpfc_env_migrates_without_manual_step(tmp_wpfy_home):
    layout, _cache = _modules(tmp_wpfy_home)
    domain = "legacy-cache.example.com"
    site_root = layout.site_dir(domain)
    site_root.mkdir(parents=True)
    layout.env_path(domain).write_text(
        f"DOMAIN={domain}\nSITE_FLAVOR=wpfc\nPHP_VERSION=8.4\n",
        encoding="utf-8",
    )

    legacy = layout.SiteSpec.from_env(domain, layout.read_env(layout.env_path(domain)))
    assert legacy.flavor == "wp"
    assert legacy.page_cache == "wpfc"

    layout.ensure_site_scaffold(replace(legacy, site_uid=None))
    migrated = layout.read_env(layout.env_path(domain))
    assert migrated["SITE_FLAVOR"] == "wp"
    assert migrated["PAGE_CACHE"] == "wpfc"
