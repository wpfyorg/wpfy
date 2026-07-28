"""OPUS-OWNED IMMUTABLE GATE TESTS — Phase 3 (native caching-plugin integration).

DO NOT EDIT, SKIP, XFAIL, PARAMETRIZE AWAY, OR DELETE ANYTHING IN THIS FILE.

These tests are the security and correctness contract for Phase 3. They are
written by the orchestrator before implementation and are verified byte-identical
(SHA-256 baseline) as a precondition for accepting the phase. If you believe a
gate asserts the wrong thing, escalate with evidence — do not edit the gate.

This file is deliberately self-contained: it depends only on the stdlib and the
`wpfy` package, never on other test modules or shared fixtures.

The invariant this phase exists to protect:

    A cached page must never be served to a request that could be personalised
    or that mutates state.

Serving one logged-in user's cached dashboard to another visitor, or caching a
POST response, is a data-disclosure bug, not a performance bug. Plugin authors
change their cache-file conventions between major versions; these bypass rules
must not drift with them.

Invariants locked here:
  G1  For every page-cache option, the generated nginx snippet bypasses cache for
      a logged-in cookie, a comment-author cookie, a password-protected-post
      cookie, a POST request, a request carrying a query string, and any
      /wp-admin path.
  G2  The bypass variable is actually wired into the directives that serve and
      store cache — declaring the conditions but not consulting them is the
      failure mode this catches.
  G3  Paid/BYO plugins (WP Rocket, FlyingPress) never trigger a plugin install.
  G4  Anti-vacuity for G3: free plugins do trigger an install.
  G5  Purge clears the nginx and Redis layers even when the plugin's own wp-cli
      command fails, since those commands change across plugin releases.
  G6  wp-config.php is never regenerated from a template; cache constants are
      asserted through `wp config set`.
  G7  Enabling the Redis object cache never publishes a Redis host port.

Contract pinned by these gates (the actor must match these names):
  * module `wpfy.site_cache` exposing `install_page_cache(domain, plugin)`,
    `render_cache_nginx(domain)`, `set_wp_cache_constants(domain)`,
    `wire_redis_backend(domain)`, `purge_site_cache(domain)`.
  * `SiteDefinition` fields `page_cache` and `object_cache`.
  * generated snippet at `<site>/nginx/extra/wpfy-cache.conf`.
  * the snippet's single bypass variable is named `$wpfy_skip_cache`, defaults to
    0, and is set to 1 by each required condition.
"""

from __future__ import annotations

import os
import re
import subprocess
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

import pytest

SEEDED_DOMAIN = "cache.example"

# Every page-cache option that renders server-side rules. `none` is excluded
# because it renders no cache behaviour to bypass.
PAGE_CACHE_OPTIONS = (
    "wpfc",
    "wp-super-cache",
    "w3-total-cache",
    "cache-enabler",
    "wp-fastest-cache",
    "wp-rocket",
    "flying-press",
)

# Plugins wpfy installs from the WordPress.org repository.
FREE_PLUGINS = ("wp-super-cache", "w3-total-cache", "cache-enabler", "wp-fastest-cache")

# Paid plugins the operator uploads themselves. wpfy stages server-side config
# only; issuing an install for these would fail or fetch an unrelated plugin of
# the same slug.
BYO_PLUGINS = ("wp-rocket", "flying-press")

BYPASS_VARIABLE = "$wpfy_skip_cache"

# (label, regex) for each condition that must set the bypass variable.
REQUIRED_BYPASS_CONDITIONS = (
    ("logged-in cookie", re.compile(r"wordpress_logged_in", re.IGNORECASE)),
    ("comment-author cookie", re.compile(r"comment_author", re.IGNORECASE)),
    ("password-protected-post cookie", re.compile(r"wp-postpass", re.IGNORECASE)),
    ("POST requests", re.compile(r"\$request_method", re.IGNORECASE)),
    ("query strings", re.compile(r"\$query_string|\$is_args", re.IGNORECASE)),
    ("/wp-admin", re.compile(r"wp-admin", re.IGNORECASE)),
)


# --------------------------------------------------------------------------
# Self-contained harness
# --------------------------------------------------------------------------

_GATE_ENV = (
    "WPFY_INSTALL_ROOT",
    "WPFY_CONFIG_DIR",
    "WPFY_STATE_DIR",
    "WPFY_LOG_DIR",
    "WPFY_SKIP_RUNTIME",
    "WPFY_SKIP_WORDPRESS_DOWNLOAD",
    "WPFY_ACME_EMAIL",
)

_PATH_FIELDS = ("install_root", "config_dir", "state_dir", "log_dir")


class _Recorder:
    """Records every host command and lets a test choose which ones fail."""

    def __init__(self) -> None:
        self.calls: list[dict] = []
        self.fail_predicate = None

    def reset(self) -> None:
        self.calls.clear()

    def __call__(self, args, **kwargs):
        argv = [str(item) for item in args] if isinstance(args, (list, tuple)) else [str(args)]
        stdin = kwargs.get("input")
        self.calls.append({"argv": argv, "stdin": stdin if isinstance(stdin, str) else ""})
        if self.fail_predicate is not None and self.fail_predicate(argv):
            return subprocess.CompletedProcess(argv, 1, "", "Error: command not found\n")
        return subprocess.CompletedProcess(argv, 0, "", "")

    def joined(self) -> list[str]:
        return [" ".join(call["argv"]) for call in self.calls]

    def any_matching(self, *tokens: str) -> bool:
        return any(all(token in line for token in tokens) for line in self.joined())


@contextmanager
def _gate_home(tmp_path, monkeypatch):
    import wpfy.registry
    import wpfy.settings
    import wpfy.site_runtime

    paths = wpfy.settings.PATHS
    previous_env = {name: os.environ.get(name) for name in _GATE_ENV}
    previous_paths = {field: getattr(paths, field) for field in _PATH_FIELDS}
    previous_registry = wpfy.registry._REGISTRY

    os.environ.update({
        "WPFY_INSTALL_ROOT": str(tmp_path / "install"),
        "WPFY_CONFIG_DIR": str(tmp_path / "config"),
        "WPFY_STATE_DIR": str(tmp_path / "state"),
        "WPFY_LOG_DIR": str(tmp_path / "log"),
        "WPFY_SKIP_WORDPRESS_DOWNLOAD": "1",
        "WPFY_ACME_EMAIL": "gate@example.com",
    })
    os.environ.pop("WPFY_SKIP_RUNTIME", None)
    for field in _PATH_FIELDS:
        object.__setattr__(paths, field, os.environ[f"WPFY_{field.upper()}"])
    wpfy.registry._REGISTRY = None

    recorder = _Recorder()
    import shutil as _shutil

    monkeypatch.setattr(subprocess, "run", recorder)
    monkeypatch.setattr(
        _shutil,
        "which",
        lambda name, *args, **kwargs: f"/usr/bin/{name}" if name == "docker" else None,
    )
    wpfy.site_runtime.docker_available.cache_clear()
    wpfy.site_runtime.docker_available()
    recorder.reset()

    try:
        yield paths, recorder
    finally:
        for field, value in previous_paths.items():
            object.__setattr__(paths, field, value)
        wpfy.registry._REGISTRY = previous_registry
        wpfy.site_runtime.docker_available.cache_clear()
        for name, value in previous_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


@pytest.fixture
def gate_home(tmp_path, monkeypatch):
    with _gate_home(tmp_path, monkeypatch) as ctx:
        yield ctx


def _seed_site(paths, *, page_cache="none", object_cache="none", domain=SEEDED_DOMAIN) -> Path:
    site = Path(paths.sites_dir) / domain
    (site / "nginx" / "extra").mkdir(parents=True, exist_ok=True)
    (site / "php").mkdir(parents=True, exist_ok=True)
    (site / "app").mkdir(parents=True, exist_ok=True)
    (site / ".env").write_text(
        f"DOMAIN={domain}\n"
        "SITE_FLAVOR=wp\n"
        "COMPOSE_PROJECT_NAME=cache-example\n"
        "APP_ROOT=/var/www/html\n"
        "PHP_VERSION=8.4\n"
        "SITE_UID=1700\n"
        "LETSENCRYPT_MODE=disabled\n"
        "DB_NAME=cache_example\n"
        "DB_USER=cache_example\n"
        "DB_PASSWORD=cache-gate-pw\n"
        "DB_ROOT_PASSWORD=cache-gate-root-pw\n"
        f"PAGE_CACHE={page_cache}\n"
        + ("REDIS_ENABLED=1\n" if object_cache == "redis" else ""),
        encoding="utf-8",
    )
    (site / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
    (site / "nginx" / "default.conf").write_text("server {\n    listen 8080;\n}\n", encoding="utf-8")
    (site / "nginx" / "extra" / "custom.conf").write_text("", encoding="utf-8")
    return site


def _cache_snippet(paths, domain: str = SEEDED_DOMAIN) -> str:
    path = Path(paths.sites_dir) / domain / "nginx" / "extra" / "wpfy-cache.conf"
    return path.read_text(encoding="utf-8") if path.exists() else ""


def _render(paths, recorder, plugin: str) -> str:
    """Render the cache snippet for one page-cache option and return its text."""
    from wpfy import site_cache

    _seed_site(paths, page_cache=plugin)
    recorder.reset()
    site_cache.render_cache_nginx(SEEDED_DOMAIN)
    return _cache_snippet(paths)


# --------------------------------------------------------------------------
# G1 / G2 — the cache-bypass invariant
# --------------------------------------------------------------------------

@pytest.mark.parametrize("plugin", PAGE_CACHE_OPTIONS)
def test_gate_cache_snippet_bypasses_personalised_and_mutating_requests(gate_home, plugin):
    """G1: every page-cache option bypasses cache on all six conditions.

    A miss here means a logged-in user's page can be stored and later served to
    an anonymous visitor, or a POST can be answered from cache.
    """
    paths, recorder = gate_home
    snippet = _render(paths, recorder, plugin)

    assert snippet.strip(), f"{plugin}: no cache snippet was rendered"

    missing = [label for label, pattern in REQUIRED_BYPASS_CONDITIONS if not pattern.search(snippet)]
    assert not missing, (
        f"{plugin}: cache snippet does not bypass cache for {', '.join(missing)}.\n{snippet}"
    )


@pytest.mark.parametrize("plugin", PAGE_CACHE_OPTIONS)
def test_gate_bypass_variable_defaults_off_and_is_set_by_every_condition(gate_home, plugin):
    """G2a: the bypass variable defaults to 0 and each condition turns it on.

    Declaring conditions that set some *other* variable would satisfy a naive
    text search while leaving the cache fully exposed.
    """
    paths, recorder = gate_home
    snippet = _render(paths, recorder, plugin)
    escaped = re.escape(BYPASS_VARIABLE)

    assert re.search(rf"set\s+{escaped}\s+0\s*;", snippet), (
        f"{plugin}: {BYPASS_VARIABLE} is never given a safe default of 0.\n{snippet}"
    )

    setter_count = len(re.findall(rf"set\s+{escaped}\s+1\s*;", snippet))
    assert setter_count >= len(REQUIRED_BYPASS_CONDITIONS), (
        f"{plugin}: expected at least {len(REQUIRED_BYPASS_CONDITIONS)} conditions to set "
        f"{BYPASS_VARIABLE} to 1, found {setter_count}.\n{snippet}"
    )


@pytest.mark.parametrize("plugin", PAGE_CACHE_OPTIONS)
def test_gate_bypass_variable_is_consulted_by_cache_directives(gate_home, plugin):
    """G2b: the bypass variable is actually wired into cache serving and storing.

    Computing the right answer and then not using it is the most likely way for
    this to be silently wrong.
    """
    paths, recorder = gate_home
    snippet = _render(paths, recorder, plugin)
    escaped = re.escape(BYPASS_VARIABLE)

    consulted = re.findall(rf"^\s*(?!set\b)(\w+)[^\n;]*{escaped}", snippet, re.MULTILINE)
    assert consulted, (
        f"{plugin}: {BYPASS_VARIABLE} is set but never read by any directive; "
        f"the bypass has no effect.\n{snippet}"
    )

    if plugin == "wpfc":
        # wpfy's own fastcgi cache must refuse both to serve from cache and to
        # store into it. Bypassing only the read still poisons the cache.
        for directive in ("fastcgi_cache_bypass", "fastcgi_no_cache"):
            assert re.search(rf"{directive}[^\n;]*{escaped}", snippet), (
                f"wpfc: {directive} does not consult {BYPASS_VARIABLE}.\n{snippet}"
            )


def test_gate_cache_snippet_is_regenerated_deterministically(gate_home):
    """G1 support: repeated renders are byte-identical, so refresh stays a no-op."""
    paths, recorder = gate_home
    from wpfy import site_cache

    _seed_site(paths, page_cache="wpfc")
    site_cache.render_cache_nginx(SEEDED_DOMAIN)
    first = _cache_snippet(paths)
    site_cache.render_cache_nginx(SEEDED_DOMAIN)
    second = _cache_snippet(paths)

    assert first == second, "render_cache_nginx is not deterministic; refresh would churn the snippet"
    assert first.strip(), "no snippet rendered for wpfc"


def test_gate_disabling_page_cache_removes_the_snippet(gate_home):
    """G1 support: turning caching off must not leave stale bypass rules behind."""
    paths, recorder = gate_home
    from wpfy import site_cache

    _seed_site(paths, page_cache="wpfc")
    site_cache.render_cache_nginx(SEEDED_DOMAIN)
    assert _cache_snippet(paths).strip(), "no snippet rendered for wpfc"

    _seed_site(paths, page_cache="none")
    site_cache.render_cache_nginx(SEEDED_DOMAIN)

    assert not _cache_snippet(paths).strip(), (
        "disabling page cache left a stale wpfy-cache.conf in the include directory"
    )


# --------------------------------------------------------------------------
# G3 / G4 — BYO plugins are never installed
# --------------------------------------------------------------------------

@pytest.mark.parametrize("plugin", BYO_PLUGINS)
def test_gate_byo_plugin_is_never_installed(gate_home, plugin):
    """G3: paid plugins are staged, never fetched from the plugin repository."""
    paths, recorder = gate_home
    from wpfy import site_cache

    _seed_site(paths, page_cache=plugin)
    recorder.reset()
    site_cache.install_page_cache(SEEDED_DOMAIN, plugin)

    assert not recorder.any_matching("plugin", "install"), (
        f"{plugin} is operator-supplied but an install was issued: {recorder.joined()}"
    )


@pytest.mark.parametrize("plugin", FREE_PLUGINS)
def test_gate_free_plugin_is_installed_and_activated(gate_home, plugin):
    """G4: anti-vacuity — repository plugins really are installed and activated."""
    paths, recorder = gate_home
    from wpfy import site_cache

    _seed_site(paths, page_cache=plugin)
    recorder.reset()
    site_cache.install_page_cache(SEEDED_DOMAIN, plugin)

    assert recorder.any_matching("plugin", "install", plugin), (
        f"{plugin} was never installed; the BYO gate would pass vacuously. {recorder.joined()}"
    )
    assert recorder.any_matching("--activate") or recorder.any_matching("plugin", "activate"), (
        f"{plugin} was installed but never activated: {recorder.joined()}"
    )


# --------------------------------------------------------------------------
# G5 — layered purge survives plugin command drift
# --------------------------------------------------------------------------

def test_gate_purge_clears_nginx_and_redis_when_the_plugin_command_fails(gate_home):
    """G5: a stale or renamed plugin command must not leave caches populated.

    Plugin wp-cli commands come and go between major releases. The nginx and
    Redis layers are wpfy's own and must always be cleared regardless.
    """
    paths, recorder = gate_home
    from wpfy import site_cache

    _seed_site(paths, page_cache="w3-total-cache", object_cache="redis")
    recorder.reset()
    # Every wp-cli invocation fails, as it would against a plugin version whose
    # flush subcommand was renamed.
    recorder.fail_predicate = lambda argv: "wpcli" in argv or "wp" in argv

    site_cache.purge_site_cache(SEEDED_DOMAIN)

    joined = recorder.joined()
    assert any("rm -rf" in line and "cache" in line for line in joined), (
        f"nginx cache was not cleared after the plugin command failed: {joined}"
    )
    assert any("FLUSHALL" in line or "flushall" in line for line in joined), (
        f"Redis object cache was not flushed after the plugin command failed: {joined}"
    )


def test_gate_purge_reports_failure_when_a_layer_cannot_be_cleared(gate_home):
    """G5b: a purge that silently reports success is worse than one that fails."""
    paths, recorder = gate_home
    from wpfy import site_cache

    _seed_site(paths, page_cache="wpfc", object_cache="redis")
    recorder.reset()
    recorder.fail_predicate = lambda argv: True     # nothing can be cleared

    result = site_cache.purge_site_cache(SEEDED_DOMAIN)

    exit_code = getattr(result, "exit_code", None)
    assert exit_code is not None and exit_code != 0, (
        f"purge reported success while every layer failed to clear: {result!r}"
    )


# --------------------------------------------------------------------------
# G6 — wp-config.php is mutated, never regenerated
# --------------------------------------------------------------------------

def test_gate_wp_config_is_never_rewritten_from_a_template(gate_home):
    """G6: cache constants are asserted with `wp config set`.

    wp-config.php holds live WordPress state — salts, table prefix, and whatever
    the operator or a plugin has added. Regenerating it from a template silently
    destroys all of that.
    """
    paths, recorder = gate_home
    from wpfy import site_cache

    site = _seed_site(paths, page_cache="cache-enabler")
    wp_config = site / "app" / "wp-config.php"
    sentinel = "<?php\n// GATE-SENTINEL-DO-NOT-LOSE\ndefine('AUTH_SALT', 'gate-salt');\n"
    wp_config.write_text(sentinel, encoding="utf-8")

    recorder.reset()
    site_cache.set_wp_cache_constants(SEEDED_DOMAIN)

    assert wp_config.read_text(encoding="utf-8") == sentinel, (
        "wp-config.php was rewritten instead of being mutated through wp-cli"
    )
    assert recorder.any_matching("config", "set", "WP_CACHE"), (
        f"WP_CACHE was never asserted through `wp config set`: {recorder.joined()}"
    )


# --------------------------------------------------------------------------
# G7 — the Redis object cache stays inside the site network
# --------------------------------------------------------------------------

def test_gate_redis_object_cache_never_publishes_a_host_port(gate_home):
    """G7: Redis has no authentication here; a published port is an open door."""
    _paths, _recorder = gate_home
    from wpfy import site_layout
    from wpfy.site_definition import SiteDefinition

    spec = SiteDefinition(
        domain="redis-cache.example",
        flavor="wp",
        use_mysql=True,
        use_redis=True,
        site_uid=1700,
    )
    spec = replace(spec, object_cache="redis")
    compose = site_layout.compose_content(spec)

    redis_block = re.search(r"^  redis:\n(?:^ {4}.*\n|^\n)*", compose, re.MULTILINE)
    assert redis_block, f"no redis service was emitted:\n{compose}"

    block = redis_block.group(0)
    assert "ports:" not in block, f"the redis service publishes a host port:\n{block}"
    assert "0.0.0.0" not in block, f"the redis service binds all interfaces:\n{block}"
