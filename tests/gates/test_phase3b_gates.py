"""GATE TESTS — Phase 3b (cache panel endpoints).

These tests are the security and correctness contract for Phase 3b. They were
written before the implementation and encode decisions, not implementation
details, so a gate failing usually means the product regressed rather than that
the gate is out of date.

They are editable, and were immutable until 2026-08-15. Change one only when
the decision it pins has genuinely changed, never to make a red test green:
say in the commit which decision moved and why, and keep the gate asserting the
new one. A gate deleted or weakened to pass takes its invariant with it.

This file is deliberately self-contained: it depends only on the stdlib and the
`wpfy` package, never on other test modules or shared fixtures.

Why this file exists at all, given Phase 1 already gates panel auth:

    Phase 1's `MUTATING_ROUTES` is a hand-written tuple. It cannot know about
    routes added by later phases, so every phase after it can add an
    unauthenticated mutating endpoint and pass the entire gate suite.

G1/G2 below fix that structurally by deriving the route list from the panel's own
route table, so they cover Phase 3b's cache routes and every route any future
phase adds. That is the durable part of this file; the cache-specific gates are
the rest.

Invariants locked here:
  G1  EVERY route the panel declares as mutating rejects a missing bearer token.
  G2  Same for a wrong token. Derived from the route table, not a fixed list.
  G3  Anti-vacuity for G1/G2: a valid token on a mutating cache route is accepted.
  G4  `dry_run` on the cache route changes nothing on disk.
  G5  Anti-vacuity for G4: without `dry_run`, the same request does change state.
  G6  A paid/BYO plugin selection never triggers a plugin install, and reports a
      distinguishable "awaiting upload" state rather than a generic error.
  G7  Purge does not report success when a cache layer failed. A panel that says
      "purged" while stale HTML is still being served is worse than an error.
  G8  Anti-vacuity for G7: a fully successful purge reports success.
  G9  No cache endpoint response contains a site secret.

Contract pinned by these gates (the actor must match these names):
  * `GET  /api/sites/<domain>/cache`
  * `PUT  /api/sites/<domain>/cache`        body may carry `dry_run`
  * `POST /api/sites/<domain>/cache/purge`
  * the panel route table stays introspectable as `wpfy.panel.ROUTES` or
    `wpfy.panel._ROUTES` (either is accepted — no rename is required), each entry
    exposing `.method`, `.pattern`, and `.meta` with `.mutates` and `.action`.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

GATE_TOKEN = "phase3b-gate-token"
SEEDED_DOMAIN = "cachepanel.example"
SECRET_MARKER = "PH3B-DB-SECRET-e7f1a9"
ROOT_SECRET_MARKER = "PH3B-ROOT-SECRET-4c2d80"

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

# Placeholder values used to turn a route pattern into a concrete request path.
_PATH_FILLERS = {
    "domain": SEEDED_DOMAIN,
    "job_id": "gate-job",
    "name": "gate_db",
    "user": "gate_user",
    "service": "app",
    "svc": "app",
    "id": "gate-id",
}


@pytest.fixture
def gate_panel(tmp_path):
    """Start a real loopback panel against an isolated, offline wpfy home.

    Paths are redirected by mutating the frozen `settings.PATHS` singleton in
    place. `importlib.reload` is deliberately avoided: it reuses a module's
    __dict__, so symbols captured at import time by other test modules keep
    pointing at the old class while the module starts producing the new one,
    silently breaking unrelated tests with no possible teardown.
    """
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
        "WPFY_SKIP_RUNTIME": "1",
        "WPFY_SKIP_WORDPRESS_DOWNLOAD": "1",
        "WPFY_ACME_EMAIL": "gate@example.com",
    })
    for field in _PATH_FIELDS:
        object.__setattr__(paths, field, os.environ[f"WPFY_{field.upper()}"])
    wpfy.registry._REGISTRY = None
    wpfy.site_runtime.docker_available.cache_clear()

    import wpfy.panel as panel

    config = panel.PanelConfig(host="127.0.0.1", port=0, token=GATE_TOKEN)
    server = panel.make_panel_server(config)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        yield base_url, paths
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        for field, value in previous_paths.items():
            object.__setattr__(paths, field, value)
        wpfy.registry._REGISTRY = previous_registry
        wpfy.site_runtime.docker_available.cache_clear()
        for name, value in previous_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _seed_site(paths, *, page_cache="none", domain=SEEDED_DOMAIN) -> Path:
    site = Path(paths.sites_dir) / domain
    (site / "nginx" / "extra").mkdir(parents=True, exist_ok=True)
    (site / "php").mkdir(parents=True, exist_ok=True)
    (site / "app").mkdir(parents=True, exist_ok=True)
    (site / ".env").write_text(
        f"DOMAIN={domain}\n"
        "SITE_FLAVOR=wp\n"
        "COMPOSE_PROJECT_NAME=cachepanel-example\n"
        "APP_ROOT=/var/www/html\n"
        "PHP_VERSION=8.4\n"
        "SITE_UID=1700\n"
        "LETSENCRYPT_MODE=disabled\n"
        f"PAGE_CACHE={page_cache}\n"
        "DB_NAME=cachepanel\n"
        "DB_USER=cachepanel\n"
        f"DB_PASSWORD={SECRET_MARKER}\n"
        f"MARIADB_PASSWORD={SECRET_MARKER}\n"
        f"DB_ROOT_PASSWORD={ROOT_SECRET_MARKER}\n"
        f"MARIADB_ROOT_PASSWORD={ROOT_SECRET_MARKER}\n",
        encoding="utf-8",
    )
    (site / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
    (site / "nginx" / "default.conf").write_text("server {\n    listen 8080;\n}\n", encoding="utf-8")
    (site / "nginx" / "extra" / "custom.conf").write_text("", encoding="utf-8")
    (site / "nginx" / "cache-path.conf").write_text("", encoding="utf-8")
    return site


def _call(base_url, path, *, token=GATE_TOKEN, method="GET", body=None):
    request = urllib.request.Request(f"{base_url}{path}", method=method)
    if token is not None:
        request.add_header("Authorization", f"Bearer {token}")
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, data=data, timeout=20) as response:
            return response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8")


def _concrete_path(pattern: re.Pattern) -> str | None:
    """Turn a route regex into a requestable path, or None if not expressible."""
    source = pattern.pattern
    source = source.lstrip("^").rstrip("$")
    for name, value in _PATH_FILLERS.items():
        source = source.replace(f"(?P<{name}>[^/]+)", value)
        source = source.replace(f"(?P<{name}>[a-z-]+)", value)
    # Any remaining regex metacharacters mean we cannot build a literal path.
    if re.search(r"[()\[\]?*+\\|]", source):
        return None
    return source


def _mutating_routes():
    """Every route the panel itself declares as mutating.

    Derived from the route table so this gate covers routes added after it was
    written — which is the entire point of the file.
    """
    import wpfy.panel as panel

    routes = getattr(panel, "ROUTES", None) or getattr(panel, "_ROUTES", None)
    assert routes, "the panel route table is not introspectable as ROUTES or _ROUTES"
    found = []
    for route in routes:
        meta = getattr(route, "meta", None)
        if meta is None or not getattr(meta, "mutates", False):
            continue
        path = _concrete_path(route.pattern)
        if path is None:
            continue
        found.append((route.method, path, getattr(meta, "action", "?")))
    assert found, "no mutating routes discovered from the panel route table"
    return found


def _snapshot(site: Path) -> dict[str, str]:
    """Content of every generated file under the site, for change detection."""
    out = {}
    for path in sorted(site.rglob("*")):
        if path.is_file():
            try:
                out[str(path.relative_to(site))] = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                pass
    return out


# --------------------------------------------------------------------------
# G1 / G2 / G3 — auth, derived from the route table
# --------------------------------------------------------------------------

def test_gate_every_mutating_route_rejects_missing_token(gate_panel):
    """G1: derived from the route table, so new phases cannot slip past it.

    Phase 1's equivalent uses a hand-written tuple and therefore cannot cover
    routes added later. This walks whatever the panel actually declares.
    """
    base_url, paths = gate_panel
    site = _seed_site(paths)
    before = _snapshot(site)

    unprotected = []
    for method, path, action in _mutating_routes():
        status, _ = _call(base_url, path, token=None, method=method, body={})
        if status not in (401, 403):
            unprotected.append(f"{method} {path} [{action}] -> {status}")

    assert not unprotected, "mutating routes reachable without a token:\n  " + "\n  ".join(unprotected)
    assert (Path(paths.sites_dir) / SEEDED_DOMAIN).exists(), "site removed by an unauthenticated call"
    assert _snapshot(site) == before, "unauthenticated calls changed site state"


def test_gate_every_mutating_route_rejects_wrong_token(gate_panel):
    """G2: a wrong token must be as useless as no token."""
    base_url, paths = gate_panel
    site = _seed_site(paths)
    before = _snapshot(site)

    unprotected = []
    for method, path, action in _mutating_routes():
        status, _ = _call(base_url, path, token="not-the-token", method=method, body={})
        if status not in (401, 403):
            unprotected.append(f"{method} {path} [{action}] -> {status}")

    assert not unprotected, "mutating routes accept a wrong token:\n  " + "\n  ".join(unprotected)
    assert _snapshot(site) == before, "wrong-token calls changed site state"


def test_gate_cache_routes_are_registered_and_declared_mutating(gate_panel):
    """G3 (part 1): the routes must exist, and be declared mutating.

    A cache route registered as non-mutating would be silently excluded from
    G1/G2 above, so this pins the declaration itself.
    """
    import wpfy.panel as panel

    routes = getattr(panel, "ROUTES", None) or getattr(panel, "_ROUTES", None)
    assert routes, "the panel route table is not introspectable as ROUTES or _ROUTES"
    table = [(r.method, r.pattern.pattern, getattr(r.meta, "mutates", False)) for r in routes]
    get_cache = [t for t in table if t[0] == "GET" and "cache" in t[1] and "purge" not in t[1]]
    put_cache = [t for t in table if t[0] == "PUT" and "cache" in t[1]]
    purge = [t for t in table if t[0] == "POST" and "purge" in t[1]]

    assert get_cache, f"no GET cache route registered; table={table}"
    assert put_cache, f"no PUT cache route registered; table={table}"
    assert purge, f"no POST cache purge route registered; table={table}"
    assert put_cache[0][2], "PUT cache route is not declared mutating"
    assert purge[0][2], "cache purge route is not declared mutating"


def test_gate_valid_token_reaches_the_cache_route(gate_panel):
    """G3 (part 2): anti-vacuity — a panel that 401s everything passes G1/G2."""
    base_url, paths = gate_panel
    _seed_site(paths)

    status, body = _call(base_url, f"/api/sites/{SEEDED_DOMAIN}/cache")
    assert status == 200, f"authorised GET /cache failed: {status} {body}"
    payload = json.loads(body)
    assert "page_cache" in json.dumps(payload), f"cache state not reported: {payload}"


# --------------------------------------------------------------------------
# G4 / G5 — dry_run
# --------------------------------------------------------------------------

def test_gate_cache_dry_run_changes_nothing_on_disk(gate_panel):
    """G4: a preview that mutates is a lie the operator acts on.

    The cache route touches nginx config and wp-config constants, so a dry run
    that applies anything defeats the purpose of previewing it.
    """
    base_url, paths = gate_panel
    site = _seed_site(paths, page_cache="none")
    before = _snapshot(site)

    status, body = _call(
        base_url, f"/api/sites/{SEEDED_DOMAIN}/cache",
        method="PUT", body={"page_cache": "wpfc", "dry_run": True},
    )

    assert status in (200, 202), f"dry-run request failed outright: {status} {body}"
    after = _snapshot(site)
    changed = [k for k in set(before) | set(after) if before.get(k) != after.get(k)]
    assert not changed, f"dry_run modified files: {changed}"


def test_gate_cache_without_dry_run_does_apply(gate_panel):
    """G5: anti-vacuity for G4 — an endpoint that never applies also passes G4."""
    base_url, paths = gate_panel
    site = _seed_site(paths, page_cache="none")
    before = _snapshot(site)

    status, body = _call(
        base_url, f"/api/sites/{SEEDED_DOMAIN}/cache",
        method="PUT", body={"page_cache": "wpfc"},
    )
    assert status in (200, 202), f"cache switch failed: {status} {body}"

    after = _snapshot(site)
    changed = [k for k in set(before) | set(after) if before.get(k) != after.get(k)]
    assert changed, "a real (non-dry-run) cache switch changed nothing at all"
    snippet = after.get("nginx/extra/wpfy-cache.conf", "")
    assert "wpfy_skip_cache" in snippet, (
        f"cache snippet missing the bypass variable after a real switch:\n{snippet}"
    )


# --------------------------------------------------------------------------
# G6 — BYO plugins are never installed
# --------------------------------------------------------------------------

@pytest.mark.parametrize("plugin", ("wp-rocket", "flying-press"))
def test_gate_byo_plugin_is_never_installed_and_is_reported_distinctly(gate_panel, monkeypatch, plugin):
    """G6: installing a paid plugin's slug from the repo fetches the wrong code.

    The operator uploads these themselves. wpfy stages server-side config and must
    say so in a way the UI can distinguish from a failure — otherwise the panel
    shows an error for the expected, correct outcome.
    """
    calls = []

    def recorder(args, **kwargs):
        argv = [str(a) for a in args] if isinstance(args, (list, tuple)) else [str(args)]
        calls.append(" ".join(argv))
        return subprocess.CompletedProcess(argv, 0, "", "")

    base_url, paths = gate_panel
    _seed_site(paths, page_cache="none")
    monkeypatch.setattr(subprocess, "run", recorder)

    status, body = _call(
        base_url, f"/api/sites/{SEEDED_DOMAIN}/cache",
        method="PUT", body={"page_cache": plugin},
    )

    installs = [c for c in calls if "plugin" in c and "install" in c]
    assert not installs, f"{plugin}: an install was issued for a BYO plugin:\n" + "\n".join(installs)
    assert status < 500, f"{plugin}: BYO selection produced a server error: {status} {body}"
    text = body.lower()
    assert "upload" in text or "awaiting" in text or "byo" in text, (
        f"{plugin}: response does not distinguish the awaiting-upload state: {body}"
    )


# --------------------------------------------------------------------------
# G7 / G8 — purge honesty
# --------------------------------------------------------------------------

def test_gate_purge_does_not_report_success_when_a_layer_fails(gate_panel, monkeypatch):
    """G7: 'purged' while stale HTML is still served is worse than an error.

    Purge is layered and best-effort by design, which makes it tempting to always
    return ok. An operator who is told the cache is clear will stop looking, and
    ship the stale page to their users.
    """
    base_url, paths = gate_panel
    _seed_site(paths, page_cache="wpfc")

    import wpfy.site_cache as site_cache

    def failing_purge(domain, *args, **kwargs):
        raise RuntimeError("gate-injected purge failure")

    monkeypatch.setattr(site_cache, "purge_site_cache", failing_purge)

    status, body = _call(base_url, f"/api/sites/{SEEDED_DOMAIN}/cache/purge", method="POST", body={})

    assert status >= 400, (
        f"purge reported success ({status}) while the purge itself failed: {body}"
    )
    assert SECRET_MARKER not in body and ROOT_SECRET_MARKER not in body, "purge error leaked a secret"


def test_gate_successful_purge_reports_success(gate_panel, monkeypatch):
    """G8: anti-vacuity for G7 — an endpoint that always 500s also passes G7."""
    base_url, paths = gate_panel
    _seed_site(paths, page_cache="wpfc")

    import wpfy.site_cache as site_cache

    sentinel = {"called": False}
    real = site_cache.purge_site_cache

    def ok_purge(domain, *args, **kwargs):
        sentinel["called"] = True
        return real(domain, *args, **kwargs)

    monkeypatch.setattr(site_cache, "purge_site_cache", ok_purge)

    status, body = _call(base_url, f"/api/sites/{SEEDED_DOMAIN}/cache/purge", method="POST", body={})

    assert sentinel["called"], "purge endpoint did not call purge_site_cache at all"
    assert status in (200, 202), f"a purge with no injected failure did not report success: {status} {body}"


# --------------------------------------------------------------------------
# G9 — secret containment
# --------------------------------------------------------------------------

def test_gate_no_cache_endpoint_response_contains_a_site_secret(gate_panel):
    """G9: the cache surface reads .env, which holds DB and root passwords."""
    base_url, paths = gate_panel
    _seed_site(paths, page_cache="wpfc")

    probes = [
        ("GET", f"/api/sites/{SEEDED_DOMAIN}/cache", None),
        ("PUT", f"/api/sites/{SEEDED_DOMAIN}/cache", {"page_cache": "wpfc", "dry_run": True}),
        ("PUT", f"/api/sites/{SEEDED_DOMAIN}/cache", {"page_cache": "w3-total-cache"}),
        ("PUT", f"/api/sites/{SEEDED_DOMAIN}/cache", {"object_cache": "redis"}),
        ("POST", f"/api/sites/{SEEDED_DOMAIN}/cache/purge", {}),
        ("GET", f"/api/sites/{SEEDED_DOMAIN}", None),
    ]

    leaks = []
    for method, path, body in probes:
        _, response = _call(base_url, path, method=method, body=body)
        for marker, label in ((SECRET_MARKER, "db password"), (ROOT_SECRET_MARKER, "db root password")):
            if marker in response:
                leaks.append(f"{method} {path} leaked the {label}")

    assert not leaks, "secret leakage:\n  " + "\n  ".join(leaks)
