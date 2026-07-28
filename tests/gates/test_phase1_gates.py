"""OPUS-OWNED IMMUTABLE GATE TESTS — Phase 1 (panel site lifecycle, jobs, events).

DO NOT EDIT, SKIP, XFAIL, PARAMETRIZE AWAY, OR DELETE ANYTHING IN THIS FILE.

These tests are the security contract for Phase 1. They are written by the
orchestrator before implementation and are verified byte-identical
(`git diff --exit-code tests/gates/`) as a precondition for accepting the phase.
If you believe a gate asserts the wrong thing, escalate with evidence — do not
edit the gate to make your implementation pass.

This file is deliberately self-contained: it depends only on the stdlib and the
`wpfy` package, never on other test modules or shared fixtures, so that no edit
outside `src/wpfy/` can weaken it.

Invariants locked here:
  G1  Every mutating panel route requires a valid bearer token, and rejects a
      missing or wrong token with 401 while making no state change.
  G2  Every Phase 1 route actually exists (a valid token must not yield 404).
  G3  Site deletion refuses to proceed without an exact typed confirmation.
  G4  A one-time secret is readable at most once and never reappears.
  G5  No panel response and no persisted event ever contains a site secret.
"""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

GATE_TOKEN = "gate-phase1-token"
WRONG_TOKEN = "not-the-token"
SECRET_MARKER = "s3cr3t-gate-db-password"
SFTP_SECRET_MARKER = "s3cr3t-gate-sftp-password"
SEEDED_DOMAIN = "seeded.example"
CREATED_DOMAIN = "created.example"


# --------------------------------------------------------------------------
# Self-contained harness (no shared fixtures by design)
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


@pytest.fixture
def gate_panel(tmp_path):
    """Start a real loopback panel against an isolated, offline wpfy home.

    Paths are redirected by mutating the shared frozen `settings.PATHS` singleton
    in place rather than by reloading modules. Every module in `src/wpfy` resolves
    paths through that object at call time (none capture values at import time),
    so in-place mutation reaches all of them.

    Reloading is deliberately avoided: `importlib.reload` reuses a module's
    __dict__, so a previously imported symbol (e.g. `InspectionCheck`, captured at
    import time by tests/test_operational_inspection.py) keeps pointing at the old
    class while functions in that same module begin producing instances of the new
    one — silently breaking unrelated tests later in the same process. No teardown
    can restore the original class identity, so the reload must never happen.
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
    wpfy.registry._REGISTRY = None          # singleton caches <state_dir>/sites.json
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


def _seed_site(paths, domain: str = SEEDED_DOMAIN) -> Path:
    site = Path(paths.sites_dir) / domain
    site.mkdir(parents=True, exist_ok=True)
    (site / ".env").write_text(
        f"DOMAIN={domain}\n"
        "SITE_FLAVOR=wp\n"
        "PHP_VERSION=8.4\n"
        "LETSENCRYPT_MODE=disabled\n"
        f"MARIADB_PASSWORD={SECRET_MARKER}\n"
        f"DB_PASSWORD={SECRET_MARKER}\n"
        f"SFTP_PASSWORD={SFTP_SECRET_MARKER}\n",
        encoding="utf-8",
    )
    (site / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
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
        with urllib.request.urlopen(request, data=data, timeout=15) as response:
            return response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8")


def _await_job(base_url, job_id, timeout=60.0):
    """Poll a job to a terminal state; return its final payload."""
    deadline = time.monotonic() + timeout
    last = {}
    while time.monotonic() < deadline:
        status, body = _call(base_url, f"/api/jobs/{job_id}")
        assert status == 200, f"job fetch failed: {status} {body}"
        last = json.loads(body)
        state = str(last.get("state") or last.get("job", {}).get("state") or "")
        if state in {"succeeded", "failed", "done", "error", "complete", "completed"}:
            return last
        time.sleep(0.1)
    raise AssertionError(f"job {job_id} did not finish within {timeout}s: {last}")


# G1 + G2: every mutating route is auth-gated, exists, and does not act unauthenticated
# --------------------------------------------------------------------------

# (method, path template, body) for every route Phase 1 must expose that mutates state.
MUTATING_ROUTES = (
    ("POST", "/api/sites", {"domain": CREATED_DOMAIN, "flavor": "html"}),
    ("DELETE", f"/api/sites/{SEEDED_DOMAIN}", {"confirm": SEEDED_DOMAIN}),
    ("POST", f"/api/sites/{SEEDED_DOMAIN}/config", {"php_version": "8.3"}),
    ("POST", f"/api/sites/{SEEDED_DOMAIN}/sftp", {"action": "rotate"}),
    ("POST", f"/api/sites/{SEEDED_DOMAIN}/backups", None),
    ("POST", f"/api/sites/{SEEDED_DOMAIN}/runtime", {"action": "start"}),
)


@pytest.mark.parametrize("method,path,body", MUTATING_ROUTES)
def test_gate_mutating_route_rejects_missing_token(gate_panel, method, path, body):
    """G1: no token -> 401, and nothing happened."""
    base_url, paths = gate_panel
    _seed_site(paths)
    sites_root = Path(paths.sites_dir)

    status, response = _call(base_url, path, token=None, method=method, body=body)

    assert status == 401, f"{method} {path} allowed an unauthenticated request ({status})"
    assert (sites_root / SEEDED_DOMAIN).exists(), f"{method} {path} mutated state without a token"
    assert not (sites_root / CREATED_DOMAIN).exists(), f"{method} {path} created a site without a token"
    assert SECRET_MARKER not in response


@pytest.mark.parametrize("method,path,body", MUTATING_ROUTES)
def test_gate_mutating_route_rejects_wrong_token(gate_panel, method, path, body):
    """G1: wrong token -> 401, and nothing happened."""
    base_url, paths = gate_panel
    _seed_site(paths)
    sites_root = Path(paths.sites_dir)

    status, response = _call(base_url, path, token=WRONG_TOKEN, method=method, body=body)

    assert status == 401, f"{method} {path} accepted a wrong token ({status})"
    assert (sites_root / SEEDED_DOMAIN).exists(), f"{method} {path} mutated state with a wrong token"
    assert not (sites_root / CREATED_DOMAIN).exists(), f"{method} {path} created a site with a wrong token"
    assert SECRET_MARKER not in response


@pytest.mark.parametrize("method,path,body", MUTATING_ROUTES)
def test_gate_mutating_route_exists(gate_panel, method, path, body):
    """G2: with a valid token the route must be implemented.

    501 is included because BaseHTTPRequestHandler answers an unregistered HTTP
    method with 'Unsupported method' — without it this gate would pass vacuously
    for DELETE.
    """
    base_url, paths = gate_panel
    _seed_site(paths)

    status, response = _call(base_url, path, method=method, body=body)

    assert status not in (404, 405, 501), f"{method} {path} is not implemented ({status}): {response}"


def test_gate_sftp_rotate_action_is_implemented(gate_panel):
    """G2: 'rotate' must be a recognised sftp action, not an unknown-action rejection.

    Without this, the generic route-exists gate above passes vacuously, because the
    pre-Phase-1 handler already answers an unknown action with 400.
    """
    base_url, paths = gate_panel
    _seed_site(paths)

    status, response = _call(
        base_url, f"/api/sites/{SEEDED_DOMAIN}/sftp", method="POST", body={"action": "rotate"},
    )

    assert "unknown" not in response.lower(), f"sftp rotate is not implemented: {response}"
    assert status in (200, 202), f"sftp rotate was rejected ({status}): {response}"


@pytest.mark.parametrize(
    "path",
    ("/api/jobs", f"/api/events?domain={SEEDED_DOMAIN}", "/api/events"),
)
def test_gate_read_routes_exist_and_are_auth_gated(gate_panel, path):
    """G1 + G2 for the new read surfaces."""
    base_url, paths = gate_panel
    _seed_site(paths)

    status, _ = _call(base_url, path, token=None)
    assert status == 401, f"GET {path} served data without a token ({status})"

    status, _ = _call(base_url, path, token=WRONG_TOKEN)
    assert status == 401, f"GET {path} accepted a wrong token ({status})"

    status, body = _call(base_url, path)
    assert status == 200, f"GET {path} is not implemented ({status}): {body}"


# G3: destructive deletion demands an exact typed confirmation
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "body",
    (
        None,
        {},
        {"confirm": ""},
        {"confirm": "yes"},
        {"confirm": "YES"},
        {"confirm": True},
        {"confirm": "other.example"},
        {"confirm": SEEDED_DOMAIN.upper()},
        {"confirm": f" {SEEDED_DOMAIN}"},
        {"force": True},
    ),
)
def test_gate_delete_requires_exact_typed_confirmation(gate_panel, body):
    """G3: anything other than the exact domain string must refuse to delete."""
    base_url, paths = gate_panel
    site = _seed_site(paths)

    status, response = _call(base_url, f"/api/sites/{SEEDED_DOMAIN}", method="DELETE", body=body)

    assert status == 400, (
        f"delete with confirmation {body!r} returned {status}, expected 400: {response}"
    )
    assert site.exists(), f"delete with confirmation {body!r} removed the site anyway"
    assert (site / ".env").exists(), f"delete with confirmation {body!r} damaged the site"


def test_gate_delete_with_exact_confirmation_is_accepted(gate_panel):
    """G3 counterpart: the exact confirmation is accepted, so the gate is not vacuous."""
    base_url, paths = gate_panel
    _seed_site(paths)

    status, response = _call(
        base_url, f"/api/sites/{SEEDED_DOMAIN}", method="DELETE", body={"confirm": SEEDED_DOMAIN},
    )

    assert status in (200, 202), f"exact confirmation was rejected ({status}): {response}"


# G4: one-time secrets are readable at most once
# --------------------------------------------------------------------------

def test_gate_one_time_secret_is_readable_at_most_once(gate_panel):
    """G4: a job's one_time payload is returned once, then never again.

    Uses the pinned panel_jobs contract directly, because with
    WPFY_SKIP_RUNTIME=1 no real flow generates a credential.
    """
    base_url, _ = gate_panel
    import wpfy.panel_jobs as panel_jobs

    secret = "one-time-gate-secret-value"
    job = panel_jobs.create_job("gate.probe", domain=SEEDED_DOMAIN)
    job_id = getattr(job, "id", None) or job["id"]
    panel_jobs.complete_job(job_id, result={"ok": True}, one_time={"password": secret})

    status, first = _call(base_url, f"/api/jobs/{job_id}")
    assert status == 200, f"job fetch failed: {first}"
    assert secret in first, "one-time secret was never readable; it must be shown exactly once"

    for attempt in range(2, 5):
        status, again = _call(base_url, f"/api/jobs/{job_id}")
        assert status == 200
        assert secret not in again, f"one-time secret was still readable on fetch #{attempt}"

    _, listing = _call(base_url, "/api/jobs")
    assert secret not in listing, "one-time secret leaked through the job listing"


# G5: secrets never escape, over HTTP or into persisted events
# --------------------------------------------------------------------------

def test_gate_no_endpoint_leaks_site_secrets(gate_panel):
    """G5: sweep every read surface, including the new ones, for seeded secrets."""
    base_url, paths = gate_panel
    _seed_site(paths)

    for path in (
        "/api/overview",
        "/api/sites",
        f"/api/sites/{SEEDED_DOMAIN}",
        f"/api/sites/{SEEDED_DOMAIN}/health",
        f"/api/sites/{SEEDED_DOMAIN}/diagnostics",
        f"/api/sites/{SEEDED_DOMAIN}/backups",
        f"/api/sites/{SEEDED_DOMAIN}/sftp",
        "/api/system/diagnostics",
        "/api/jobs",
        "/api/events",
        f"/api/events?domain={SEEDED_DOMAIN}",
    ):
        status, body = _call(base_url, path)
        assert status in (200, 404), f"GET {path} returned {status}: {body}"
        assert SECRET_MARKER not in body, f"database secret leaked via {path}"
        assert SFTP_SECRET_MARKER not in body, f"sftp secret leaked via {path}"


def test_gate_persisted_events_never_contain_secrets(gate_panel):
    """G5: the on-disk event log is redacted, not just the HTTP view."""
    base_url, paths = gate_panel
    _seed_site(paths)

    # Drive mutating flows that touch secret-bearing state.
    _call(base_url, f"/api/sites/{SEEDED_DOMAIN}/backups", method="POST")
    _call(base_url, f"/api/sites/{SEEDED_DOMAIN}/config", method="POST", body={"php_version": "8.3"})
    _call(base_url, f"/api/sites/{SEEDED_DOMAIN}/sftp", method="POST", body={"action": "rotate"})
    status, body = _call(base_url, "/api/sites", method="POST",
                         body={"domain": CREATED_DOMAIN, "flavor": "html"})
    if status in (200, 202):
        payload = json.loads(body)
        job_id = payload.get("job_id") or payload.get("id")
        if job_id:
            _await_job(base_url, job_id)

    state_root = Path(paths.state_dir)
    event_files = list(state_root.rglob("events*.jsonl"))
    assert event_files, f"no event log was written under {state_root}"

    for event_file in event_files:
        content = event_file.read_text(encoding="utf-8", errors="replace")
        assert SECRET_MARKER not in content, f"database secret persisted into {event_file}"
        assert SFTP_SECRET_MARKER not in content, f"sftp secret persisted into {event_file}"
