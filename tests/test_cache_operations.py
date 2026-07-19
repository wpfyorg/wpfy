from __future__ import annotations

from wpfy import cache_operations as cache


def _runtime_ready(monkeypatch):
    monkeypatch.setattr(cache, "runtime_skip_requested", lambda: False)
    monkeypatch.setattr(cache, "docker_available", lambda: True)


class Proc:
    def __init__(self, returncode=0):
        self.returncode = returncode


def test_default_clear_targets_nginx_only(monkeypatch):
    _runtime_ready(monkeypatch)
    calls = []
    monkeypatch.setattr(cache, "site_exists", lambda domain: True)
    monkeypatch.setattr(cache, "compose_command", lambda domain, *args: calls.append((domain, args)) or Proc())

    result = cache.clear(cache.CacheRequest(domain="example.com"))

    assert result.exit_code == 0
    assert len(calls) == 3
    assert result.outcomes == (cache.CacheOutcome("example.com", "nginx", "ok", "cache cleared"),)


def test_redis_disabled_is_skipped_without_exec(monkeypatch):
    _runtime_ready(monkeypatch)
    monkeypatch.setattr(cache, "site_exists", lambda domain: True)
    monkeypatch.setattr(cache, "read_env", lambda path: {"SITE_FLAVOR": "wp", "REDIS_ENABLED": "0"})
    monkeypatch.setattr(cache, "compose_command", lambda *args: (_ for _ in ()).throw(AssertionError("must not run")))

    result = cache.clear(cache.CacheRequest(domain="example.com", redis=True))

    assert result.exit_code == 0
    assert result.outcomes[0].status == "skipped"


def test_all_sites_keep_order_and_report_partial_failure(monkeypatch):
    _runtime_ready(monkeypatch)
    monkeypatch.setattr(cache, "list_sites", lambda: [{"domain": "a.test"}, {"domain": "z.test"}])
    monkeypatch.setattr(cache, "site_exists", lambda domain: True)
    monkeypatch.setattr(cache, "read_env", lambda path: {"SITE_FLAVOR": "wpredis", "REDIS_ENABLED": "1"})

    def compose(domain, *args):
        return Proc(1 if domain == "z.test" and "redis-cli" in args else 0)

    monkeypatch.setattr(cache, "compose_command", compose)

    result = cache.clear(cache.CacheRequest(redis=True))

    assert [outcome.domain for outcome in result.outcomes] == ["a.test", "z.test"]
    assert [outcome.status for outcome in result.outcomes] == ["ok", "error"]
    assert result.exit_code == 1


def test_all_selects_nginx_redis_opcache(monkeypatch):
    _runtime_ready(monkeypatch)
    monkeypatch.setattr(cache, "site_exists", lambda domain: True)
    monkeypatch.setattr(cache, "read_env", lambda path: {"SITE_FLAVOR": "wpredis"})
    monkeypatch.setattr(cache, "compose_command", lambda *args: Proc())

    result = cache.clear(cache.CacheRequest(domain="example.com", clear_all=True))

    assert [outcome.cache for outcome in result.outcomes] == ["nginx", "redis", "opcache"]


def test_runtime_exception_becomes_nonzero_outcome(monkeypatch):
    _runtime_ready(monkeypatch)
    monkeypatch.setattr(cache, "site_exists", lambda domain: True)
    monkeypatch.setattr(cache, "compose_command", lambda *args: (_ for _ in ()).throw(OSError("docker missing")))

    result = cache.clear(cache.CacheRequest(domain="example.com", opcache=True))

    assert result.exit_code == 1
    assert "docker missing" in result.outcomes[0].message


def test_no_managed_sites_is_explicit(monkeypatch):
    monkeypatch.setattr(cache, "list_sites", lambda: [])

    result = cache.clear(cache.CacheRequest())

    assert result.no_sites_found is True
    assert result.exit_code == 0


def test_runtime_skip_is_nonzero_without_compose(monkeypatch):
    monkeypatch.setattr(cache, "site_exists", lambda domain: True)
    monkeypatch.setattr(cache, "runtime_skip_requested", lambda: True)
    monkeypatch.setattr(cache, "compose_command", lambda *args: (_ for _ in ()).throw(AssertionError("must not run")))

    result = cache.clear(cache.CacheRequest(domain="example.com"))

    assert result.exit_code == 1
    assert result.outcomes[0].message == "runtime unavailable (Docker/Compose not available)"


def test_explicit_missing_site_is_skipped_without_runtime(monkeypatch):
    _runtime_ready(monkeypatch)
    monkeypatch.setattr(cache, "site_exists", lambda domain: False)
    monkeypatch.setattr(cache, "compose_command", lambda *args: (_ for _ in ()).throw(AssertionError("must not run")))

    result = cache.clear(cache.CacheRequest(domain="missing.test"))

    assert result.exit_code == 0
    assert result.outcomes[0].status == "skipped"


def test_all_cache_failures_are_nonzero_and_named(monkeypatch):
    _runtime_ready(monkeypatch)
    monkeypatch.setattr(cache, "site_exists", lambda domain: True)
    monkeypatch.setattr(cache, "read_env", lambda path: {"SITE_FLAVOR": "wpredis", "REDIS_ENABLED": "1"})
    monkeypatch.setattr(cache, "compose_command", lambda *args: Proc(9))

    result = cache.clear(cache.CacheRequest(domain="example.com", clear_all=True))

    assert result.exit_code == 1
    assert [(item.cache, item.status) for item in result.outcomes] == [
        ("nginx", "error"),
        ("redis", "error"),
        ("opcache", "error"),
    ]
