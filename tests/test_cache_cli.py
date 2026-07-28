from __future__ import annotations

def test_cache_parser_exposes_all_operations():
    from wpfy.cli import build_parser

    parser = build_parser()
    assert parser.parse_args(["cache", "example.com", "show"]).cache_command == "show"
    assert parser.parse_args(["cache", "example.com", "set", "w3-total-cache"]).plugin == "w3-total-cache"
    assert parser.parse_args(["cache", "example.com", "object", "redis"]).backend == "redis"
    assert parser.parse_args(["cache", "example.com", "purge"]).cache_command == "purge"


def test_site_create_cache_flags_are_orthogonal(monkeypatch):
    import wpfy.cli as cli

    captured = {}

    def fake_create(request, **kwargs):
        captured["request"] = request
        return cli.site_lifecycle.CreateSiteResult(
            spec=cli.site_lifecycle.SiteSpec(
                request.domain,
                request.flavor,
                True,
                request.object_cache == "redis",
                page_cache=request.page_cache,
                object_cache=request.object_cache,
            ),
            touched=(),
            bootstrap=cli.site_lifecycle.RuntimeResult(0, "ok", ran=True),
            runtime=cli.site_lifecycle.RuntimeResult(0, "started", ran=True),
        )

    monkeypatch.setattr(cli.site_lifecycle, "create_site", fake_create)

    assert cli.run(["site", "create", "cache.example.com", "--w3tc", "--wpredis"]) == 0
    assert captured["request"].flavor == "wp"
    assert captured["request"].page_cache == "w3-total-cache"
    assert captured["request"].object_cache == "redis"


def test_site_create_paid_cache_next_step_identifies_upload_path(monkeypatch, capsys, tmp_path):
    import wpfy.cli as cli

    monkeypatch.setattr(cli, "app_dir", lambda domain: tmp_path / domain / "app")
    monkeypatch.setattr(
        cli.site_lifecycle,
        "create_site",
        lambda request, **kwargs: cli.site_lifecycle.CreateSiteResult(
            spec=cli.site_lifecycle.SiteSpec(
                request.domain,
                request.flavor,
                True,
                False,
                page_cache=request.page_cache,
                object_cache=request.object_cache,
            ),
            touched=(),
            bootstrap=cli.site_lifecycle.RuntimeResult(0, "ok", ran=True),
            runtime=cli.site_lifecycle.RuntimeResult(0, "started", ran=True),
        ),
    )

    assert cli.run(["site", "create", "paid.example.com", "--wprocket"]) == 0
    output = capsys.readouterr().out
    assert f"upload and extract the licensed wp-rocket zip under {tmp_path / 'paid.example.com' / 'app' / 'wp-content' / 'plugins'}" in output
    assert "server-side cache rules are already staged" in output


def test_cache_set_delegates_to_operation_layer(monkeypatch, capsys):
    import wpfy.cli as cli

    definition = cli.site_cache.SiteDefinition(
        domain="cache.example.com",
        flavor="wp",
        use_mysql=True,
        use_redis=False,
        page_cache="w3-total-cache",
        object_cache="none",
    )
    captured = {}

    def fake_set(domain, plugin):
        captured["args"] = (domain, plugin)
        return cli.site_cache.CacheConfigurationResult(
            definition,
            (cli.site_cache.CacheActionResult("ok", "w3-total-cache installed"),),
            (".env",),
        )

    monkeypatch.setattr(cli.site_cache, "set_page_cache", fake_set)

    assert cli.run(["cache", "cache.example.com", "set", "w3-total-cache"]) == 0
    output = capsys.readouterr().out
    assert captured["args"] == ("cache.example.com", "w3-total-cache")
    assert "=== page cache ===" in output
    assert "w3-total-cache installed" in output


def test_cache_purge_delegates_and_propagates_exit_code(monkeypatch, capsys):
    import wpfy.cli as cli

    outcomes = (
        cli.cache_operations.CacheOutcome("cache.example.com", "plugin", "skipped", "command unavailable"),
        cli.cache_operations.CacheOutcome("cache.example.com", "nginx", "ok", "cache cleared"),
    )
    monkeypatch.setattr(
        cli.site_cache,
        "purge_site_cache",
        lambda domain: cli.cache_operations.CacheResult(outcomes),
    )

    assert cli.run(["cache", "cache.example.com", "purge"]) == 0
    output = capsys.readouterr().out
    assert "plugin: skipped command unavailable" in output
    assert "nginx: ok cache cleared" in output
