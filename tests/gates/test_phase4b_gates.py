"""OPUS-OWNED IMMUTABLE GATE TESTS — Phase 4b (security + cron panel endpoints).

DO NOT EDIT, SKIP, XFAIL, PARAMETRIZE AWAY, OR DELETE ANYTHING IN THIS FILE.

These tests are the security and correctness contract for Phase 4b. They are
written by the orchestrator before implementation and are verified byte-identical
(SHA-256 baseline) as a precondition for accepting the phase. If you believe a
gate asserts the wrong thing, escalate with evidence — do not edit the gate.

This file is deliberately self-contained: it depends only on the stdlib and the
`wpfy` package, never on other test modules or shared fixtures.

Deliberately NOT re-tested here: bearer-token auth on the new routes. Phase 3b's
G1/G2 derive the mutating-route list from the panel's own route table, so they
already cover every route this phase adds. Adding a hand-written auth list here
would be weaker than what already exists.

What this phase can get wrong that nothing else catches:

    Phase 4a's op layer refuses hostile input and warns before a lockout. The
    panel is a second, independent path to that same state. It can bypass the op
    layer by writing `security.json` / `cron.json` directly, drop the preflight
    warning that stands between an operator and an unreachable site, or apply a
    "preview" for real. None of the 4a gates observe the HTTP surface.

Invariants locked here:
  S1  `dry_run` on the security route changes nothing on disk.
  S2  Anti-vacuity for S1: without `dry_run`, the same request does change state.
  S3  Enabling Cloudflare-only on a site whose DNS is not Cloudflare-proxied
      surfaces the preflight warning AND does not apply. This warning is the only
      thing between an operator and a site that answers nobody.
  S4  Anti-vacuity for S3, both halves: an explicit acknowledgement applies the
      change, and a genuinely proxied site applies without needing one.
  S5  A generated basic-auth password is returned once and never again, and never
      lands in cleartext anywhere under the site directory.
  S6  Hostile CIDR and user-agent values are refused over HTTP and never reach
      the generated nginx config. The panel must not bypass the op layer.
  S7  No security endpoint response contains a site secret.
  C1  Cron create/list/delete round-trips through the API.
  C2  A hostile `service` is refused over HTTP, including another site's service
      and the shared edge proxy. Cron runs commands, so this is the boundary that
      keeps one site's schedule out of another site's container.
  C3  A cron run that fails does not report success — in the JSON outcome AND in
      the HTTP status, which must agree with each other.
  C4  No cron endpoint response contains a site secret.

Contract pinned by these gates (the actor must match these names):
  * `GET  /api/sites/<domain>/security`
  * `PUT  /api/sites/<domain>/security`
        body keys: `deny_ips`, `ua_blocks`, `basic_auth` {enabled, username,
        password?}, `cloudflare_only`, `dry_run`, `acknowledge_warnings`
        response carries `warnings` (list) and, when a password was generated,
        `one_time` {"password": ...}
  * `GET    /api/sites/<domain>/cron`            response carries `jobs` (list of
        objects with an `id`)
  * `POST   /api/sites/<domain>/cron`            body: schedule, command,
        service?, timeout?
  * `DELETE /api/sites/<domain>/cron/<job_id>`
  * `POST   /api/sites/<domain>/cron/<job_id>/run`
"""

from __future__ import annotations

import json
import os
import re
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

GATE_TOKEN = "phase4b-gate-token"
SEEDED_DOMAIN = "securitypanel.example"
OTHER_DOMAIN = "othersite.example"
SECRET_MARKER = "PH4B-DB-SECRET-b3d1f7"
ROOT_SECRET_MARKER = "PH4B-ROOT-SECRET-91ac4e"

# Pinned so security rendering never depends on the host's live Docker state.
EDGE_CIDR = "172.31.0.0/16"
# A private range stands in for Cloudflare so "proxied" is expressible offline.
FAKE_CF_RANGE = "203.0.113.0/24"
PROXIED_IP = "203.0.113.10"
UNPROXIED_IP = "198.51.100.10"

_GATE_ENV = (
    "WPFY_INSTALL_ROOT",
    "WPFY_CONFIG_DIR",
    "WPFY_STATE_DIR",
    "WPFY_LOG_DIR",
    "WPFY_SKIP_RUNTIME",
    "WPFY_SKIP_WORDPRESS_DOWNLOAD",
    "WPFY_SKIP_CHOWN",
    "WPFY_ACME_EMAIL",
    "WPFY_TEST_TRAEFIK_NETWORK_CIDRS",
    "WPFY_CLOUDFLARE_RANGES",
    "WPFY_TEST_DNS_IPS",
)

_PATH_FIELDS = ("install_root", "config_dir", "state_dir", "log_dir")

HOSTILE_CIDRS = (
    "10.0.0.0/8; return 200 'wpfy_injected'",
    "10.0.0.0/8\nallow all; # wpfy_injected",
    "10.0.0.0/8\x00wpfy_injected",
    '10.0.0.0/8" wpfy_injected "',
    "10.0.0.0/8}\nserver { # wpfy_injected",
    "0.0.0.0/0",
    "999.999.999.999/8",
    "not-an-ip",
    "",
)

HOSTILE_USER_AGENTS = (
    'evilbot" ) { return 200 "wpfy_injected"; } if ( $http_user_agent ~ "x',
    "evilbot\nreturn 200 'wpfy_injected';",
    "evilbot\x00wpfy_injected",
    "evilbot}\nserver { # wpfy_injected",
    "evilbot\"; # wpfy_injected",
    "",
)

# `wpfy-traefik` is the shared edge proxy; the others target another site or
# escape the service vocabulary entirely.
HOSTILE_SERVICES = (
    "othersite-example-app",
    "../othersite.example/app",
    "app; rm -rf /",
    "app\nwpfy_injected",
    "app\x00",
    "wpfy-traefik",
    "",
)


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
        "WPFY_SKIP_CHOWN": "1",
        "WPFY_ACME_EMAIL": "gate@example.com",
        # Without this the generated snippet depends on the host's live Docker
        # network, which would make these gates pass or fail by environment.
        "WPFY_TEST_TRAEFIK_NETWORK_CIDRS": EDGE_CIDR,
        "WPFY_CLOUDFLARE_RANGES": FAKE_CF_RANGE,
        "WPFY_TEST_DNS_IPS": UNPROXIED_IP,
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


def _seed_site(paths, *, domain=SEEDED_DOMAIN) -> Path:
    site = Path(paths.sites_dir) / domain
    (site / "nginx" / "extra").mkdir(parents=True, exist_ok=True)
    (site / "php").mkdir(parents=True, exist_ok=True)
    (site / "app").mkdir(parents=True, exist_ok=True)
    (site / ".env").write_text(
        f"DOMAIN={domain}\n"
        "SITE_FLAVOR=wp\n"
        f"COMPOSE_PROJECT_NAME={domain.replace('.', '-')}\n"
        "APP_ROOT=/var/www/html\n"
        "PHP_VERSION=8.4\n"
        "SITE_UID=1700\n"
        "LETSENCRYPT_MODE=disabled\n"
        "PAGE_CACHE=none\n"
        "DB_NAME=secpanel\n"
        "DB_USER=secpanel\n"
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
    (site / "nginx" / "htpasswd").write_text("", encoding="utf-8")
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


def _snapshot(site: Path) -> dict[str, str]:
    """Content of every file under the site, for change detection."""
    out = {}
    for path in sorted(site.rglob("*")):
        if path.is_file():
            try:
                out[str(path.relative_to(site))] = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                pass
    return out


def _security_snippet(site: Path) -> str:
    path = site / "nginx" / "extra" / "wpfy-security.conf"
    return path.read_text(encoding="utf-8") if path.exists() else ""


def _route_exists(status: int) -> bool:
    """404/405 means the endpoint is absent, which is not a security property.

    Without this distinction every hostile-input gate below would pass against a
    panel that simply has no security or cron routes at all — they would be
    vacuous the moment they were written.
    """
    return status not in (404, 405)


def _refused(status: int, payload: str) -> bool:
    """A refusal is a non-2xx from a route that actually exists.

    A silent 2xx on hostile input is the bug this detects. A 404 is not a
    refusal — see `_route_exists`.
    """
    assert _route_exists(status), (
        f"the endpoint does not exist (status {status}); a missing route cannot "
        f"refuse anything, so this gate would be vacuous: {payload}"
    )
    return not (200 <= status < 300)


def _set_dns(ips: str) -> None:
    os.environ["WPFY_TEST_DNS_IPS"] = ips


# --------------------------------------------------------------------------
# S1 / S2 — dry_run must be a preview, not a half-applied mutation
# --------------------------------------------------------------------------

def test_gate_security_dry_run_changes_nothing_on_disk(gate_panel):
    """S1: this route rewrites nginx config and an htpasswd file.

    A preview that half-applies is worse than no preview: the operator believes
    nothing happened.
    """
    base_url, paths = gate_panel
    site = _seed_site(paths)
    before = _snapshot(site)

    status, payload = _call(
        base_url,
        f"/api/sites/{SEEDED_DOMAIN}/security",
        method="PUT",
        body={"deny_ips": ["198.51.100.0/24"], "dry_run": True},
    )
    assert 200 <= status < 300, f"dry-run security preview failed: {status} {payload}"

    after = _snapshot(site)
    assert before == after, (
        "dry_run mutated the site on disk; changed paths: "
        f"{sorted(set(before) ^ set(after)) or [k for k in before if before[k] != after.get(k)]}"
    )


def test_gate_security_without_dry_run_actually_applies(gate_panel):
    """S2: anti-vacuity for S1.

    Without this, an endpoint that silently does nothing at all would satisfy S1
    and the whole preview contract would be untested.
    """
    base_url, paths = gate_panel
    site = _seed_site(paths)

    status, payload = _call(
        base_url,
        f"/api/sites/{SEEDED_DOMAIN}/security",
        method="PUT",
        body={"deny_ips": ["198.51.100.0/24"]},
    )
    assert 200 <= status < 300, f"applying a deny rule failed: {status} {payload}"

    snippet = _security_snippet(site)
    assert "deny 198.51.100.0/24;" in snippet, (
        f"the applied deny rule never reached the nginx snippet; snippet was:\n{snippet}"
    )


# --------------------------------------------------------------------------
# S3 / S4 — the lockout warning is load-bearing
# --------------------------------------------------------------------------

def test_gate_cloudflare_only_on_unproxied_site_warns_and_does_not_apply(gate_panel):
    """S3: enabling this on an unproxied site makes the site answer nobody.

    The CLI requires --force past the warning. The panel must not be the easy
    path that skips it.
    """
    base_url, paths = gate_panel
    site = _seed_site(paths)
    _set_dns(UNPROXIED_IP)

    status, payload = _call(
        base_url,
        f"/api/sites/{SEEDED_DOMAIN}/security",
        method="PUT",
        body={"cloudflare_only": True},
    )

    body = json.loads(payload) if payload.strip().startswith("{") else {}
    warnings = body.get("warnings") or []
    assert warnings, (
        "enabling Cloudflare-only on an unproxied site surfaced no warning at all; "
        f"status {status}, body {payload}"
    )
    assert any("cloudflare" in str(w).lower() for w in warnings), (
        f"the warning does not name the lockout risk: {warnings}"
    )

    config_path = site / "security.json"
    applied = False
    if config_path.exists():
        applied = json.loads(config_path.read_text(encoding="utf-8")).get("cloudflare_only") is True
    assert not applied, (
        "Cloudflare-only was applied despite an unacknowledged lockout warning; "
        "the site is now unreachable and the operator was only warned after the fact"
    )


def test_gate_cloudflare_only_applies_when_acknowledged_or_proxied(gate_panel):
    """S4: anti-vacuity for S3, in both directions.

    A route that always refused Cloudflare-only would satisfy S3 while making the
    feature useless, so both the acknowledged path and the genuinely-proxied path
    must reach application.
    """
    base_url, paths = gate_panel
    site = _seed_site(paths)

    # Acknowledged, still unproxied: the operator accepted the risk explicitly.
    _set_dns(UNPROXIED_IP)
    status, payload = _call(
        base_url,
        f"/api/sites/{SEEDED_DOMAIN}/security",
        method="PUT",
        body={"cloudflare_only": True, "acknowledge_warnings": True},
    )
    assert 200 <= status < 300, f"acknowledged Cloudflare-only was refused: {status} {payload}"
    config = json.loads((site / "security.json").read_text(encoding="utf-8"))
    assert config.get("cloudflare_only") is True, (
        f"acknowledged Cloudflare-only did not apply; security.json was {config}"
    )

    # A genuinely proxied site needs no acknowledgement: there is no lockout risk.
    other = _seed_site(paths, domain=OTHER_DOMAIN)
    _set_dns(PROXIED_IP)
    status, payload = _call(
        base_url,
        f"/api/sites/{OTHER_DOMAIN}/security",
        method="PUT",
        body={"cloudflare_only": True},
    )
    assert 200 <= status < 300, f"Cloudflare-only on a proxied site was refused: {status} {payload}"
    config = json.loads((other / "security.json").read_text(encoding="utf-8"))
    assert config.get("cloudflare_only") is True, (
        f"Cloudflare-only did not apply to a proxied site; security.json was {config}"
    )


# --------------------------------------------------------------------------
# S5 — one-time credential handling
# --------------------------------------------------------------------------

def test_gate_generated_basic_auth_password_is_shown_once_and_never_stored(gate_panel):
    """S5: a credential the operator cannot re-read must not be recoverable.

    Two failures are covered: leaking it on a later read, and leaving it in
    cleartext on disk where any backup of the site directory would carry it.
    """
    base_url, paths = gate_panel
    site = _seed_site(paths)

    status, payload = _call(
        base_url,
        f"/api/sites/{SEEDED_DOMAIN}/security",
        method="PUT",
        body={"basic_auth": {"enabled": True, "username": "operator"}},
    )
    assert 200 <= status < 300, f"enabling basic auth failed: {status} {payload}"

    body = json.loads(payload)
    one_time = body.get("one_time") or {}
    password = one_time.get("password")
    assert password, (
        "enabling basic auth without a password returned no generated credential, "
        f"so the operator can never authenticate; body was {payload}"
    )
    assert len(password) >= 12, f"generated password is too short to be meaningful: {len(password)} chars"

    # It must not come back on a subsequent read.
    status, second = _call(base_url, f"/api/sites/{SEEDED_DOMAIN}/security")
    assert 200 <= status < 300, f"reading security state failed: {status} {second}"
    assert password not in second, "the generated password is readable again from GET /security"

    # It must not be sitting in cleartext anywhere under the site.
    for path in sorted(site.rglob("*")):
        if not path.is_file():
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        assert password not in content, (
            f"the basic-auth password is stored in cleartext at {path.relative_to(site)}"
        )


# --------------------------------------------------------------------------
# S6 — the panel must not bypass the op layer's validation
# --------------------------------------------------------------------------

@pytest.mark.parametrize("cidr", HOSTILE_CIDRS)
def test_gate_hostile_cidr_is_refused_over_http(gate_panel, cidr):
    """S6: the panel is a second path to the same state as the CLI.

    Writing `security.json` directly, or trusting the client, would let these
    reach the generated nginx config even though 4a refuses them.
    """
    base_url, paths = gate_panel
    site = _seed_site(paths)

    status, payload = _call(
        base_url,
        f"/api/sites/{SEEDED_DOMAIN}/security",
        method="PUT",
        body={"deny_ips": [cidr]},
    )
    assert _refused(status, payload), (
        f"hostile CIDR {cidr!r} was accepted with status {status}: {payload}"
    )
    snippet = _security_snippet(site)
    assert "wpfy_injected" not in snippet, (
        f"hostile CIDR {cidr!r} reached the nginx snippet:\n{snippet}"
    )
    if cidr == "0.0.0.0/0":
        assert "deny 0.0.0.0/0;" not in snippet, "a deny-everything rule was rendered"


@pytest.mark.parametrize("pattern", HOSTILE_USER_AGENTS)
def test_gate_hostile_user_agent_is_refused_over_http(gate_panel, pattern):
    """S6: the UA block is interpolated into an nginx `if` condition."""
    base_url, paths = gate_panel
    site = _seed_site(paths)

    status, payload = _call(
        base_url,
        f"/api/sites/{SEEDED_DOMAIN}/security",
        method="PUT",
        body={"ua_blocks": [pattern]},
    )
    assert _refused(status, payload), (
        f"hostile user agent {pattern!r} was accepted with status {status}: {payload}"
    )
    snippet = _security_snippet(site)
    assert "wpfy_injected" not in snippet, (
        f"hostile user agent {pattern!r} reached the nginx snippet:\n{snippet}"
    )


def test_gate_valid_security_input_is_actually_applied(gate_panel):
    """S6 anti-vacuity: a route that refused everything would pass every case above."""
    base_url, paths = gate_panel
    site = _seed_site(paths)

    status, payload = _call(
        base_url,
        f"/api/sites/{SEEDED_DOMAIN}/security",
        method="PUT",
        body={"deny_ips": ["203.0.113.7/32"], "ua_blocks": ["EvilBot"]},
    )
    assert 200 <= status < 300, f"valid security input was refused: {status} {payload}"

    snippet = _security_snippet(site)
    assert "deny 203.0.113.7/32;" in snippet, f"valid CIDR never rendered:\n{snippet}"
    assert "EvilBot" in snippet, f"valid user-agent pattern never rendered:\n{snippet}"


# --------------------------------------------------------------------------
# S7 / C4 — secrets must not ride out on any response
# --------------------------------------------------------------------------

def test_gate_no_security_or_cron_response_leaks_a_site_secret(gate_panel):
    """S7 + C4: these endpoints read a site directory that holds DB credentials."""
    base_url, paths = gate_panel
    _seed_site(paths)

    _call(
        base_url,
        f"/api/sites/{SEEDED_DOMAIN}/security",
        method="PUT",
        body={"deny_ips": ["203.0.113.7/32"]},
    )
    _call(
        base_url,
        f"/api/sites/{SEEDED_DOMAIN}/cron",
        method="POST",
        body={"schedule": "*/5 * * * *", "command": "wp cron event run --due-now", "service": "app"},
    )

    for path in (
        f"/api/sites/{SEEDED_DOMAIN}/security",
        f"/api/sites/{SEEDED_DOMAIN}/cron",
    ):
        status, payload = _call(base_url, path)
        # A 404 body trivially contains no secret, which would make this gate
        # vacuous against a panel that never implemented the route.
        assert 200 <= status < 300, (
            f"{path} did not return a readable response (status {status}), so this "
            f"gate cannot observe whether it leaks: {payload}"
        )
        assert SECRET_MARKER not in payload, f"{path} leaked the DB password"
        assert ROOT_SECRET_MARKER not in payload, f"{path} leaked the DB root password"


# --------------------------------------------------------------------------
# C1 / C2 / C3 — cron over HTTP
# --------------------------------------------------------------------------

def test_gate_cron_create_list_delete_round_trips(gate_panel):
    """C1: the tab is useless if a created job cannot be listed or removed."""
    base_url, paths = gate_panel
    _seed_site(paths)

    status, payload = _call(
        base_url,
        f"/api/sites/{SEEDED_DOMAIN}/cron",
        method="POST",
        body={"schedule": "*/5 * * * *", "command": "wp cron event run --due-now", "service": "app"},
    )
    assert 200 <= status < 300, f"creating a cron job failed: {status} {payload}"
    created = json.loads(payload)
    job_id = created.get("id") or (created.get("job") or {}).get("id")
    assert job_id, f"the create response carries no job id: {payload}"

    status, payload = _call(base_url, f"/api/sites/{SEEDED_DOMAIN}/cron")
    assert 200 <= status < 300, f"listing cron jobs failed: {status} {payload}"
    jobs = json.loads(payload).get("jobs")
    assert isinstance(jobs, list) and any(job.get("id") == job_id for job in jobs), (
        f"the created job {job_id} is not in the listing: {payload}"
    )

    status, payload = _call(
        base_url, f"/api/sites/{SEEDED_DOMAIN}/cron/{job_id}", method="DELETE"
    )
    assert 200 <= status < 300, f"deleting a cron job failed: {status} {payload}"

    status, payload = _call(base_url, f"/api/sites/{SEEDED_DOMAIN}/cron")
    jobs = json.loads(payload).get("jobs") or []
    assert not any(job.get("id") == job_id for job in jobs), (
        f"the job survived deletion: {payload}"
    )


@pytest.mark.parametrize("service", HOSTILE_SERVICES)
def test_gate_hostile_cron_service_is_refused_over_http(gate_panel, service):
    """C2: cron executes commands, so `service` decides which container runs them.

    `othersite-example-app` and `../othersite.example/app` are one site reaching
    into another; `wpfy-traefik` is a site reaching the shared edge proxy.
    """
    base_url, paths = gate_panel
    _seed_site(paths)
    _seed_site(paths, domain=OTHER_DOMAIN)

    status, payload = _call(
        base_url,
        f"/api/sites/{SEEDED_DOMAIN}/cron",
        method="POST",
        body={"schedule": "*/5 * * * *", "command": "echo hi", "service": service},
    )
    assert _refused(status, payload), (
        f"hostile cron service {service!r} was accepted with status {status}: {payload}"
    )


def test_gate_valid_cron_service_is_accepted(gate_panel):
    """C2 anti-vacuity: a route that refused every service would pass every case above."""
    base_url, paths = gate_panel
    _seed_site(paths)

    status, payload = _call(
        base_url,
        f"/api/sites/{SEEDED_DOMAIN}/cron",
        method="POST",
        body={"schedule": "*/5 * * * *", "command": "wp cron event run --due-now", "service": "app"},
    )
    assert 200 <= status < 300, f"a legitimate cron job was refused: {status} {payload}"


def test_gate_failed_cron_run_does_not_report_success(gate_panel):
    """C3: an operator told a job ran stops investigating why it did not.

    The runtime is unavailable in this environment, so a run cannot have
    succeeded. The response must not claim it did.
    """
    base_url, paths = gate_panel
    _seed_site(paths)

    status, payload = _call(
        base_url,
        f"/api/sites/{SEEDED_DOMAIN}/cron",
        method="POST",
        body={"schedule": "*/5 * * * *", "command": "wp cron event run --due-now", "service": "app"},
    )
    assert 200 <= status < 300, f"creating a cron job failed: {status} {payload}"
    created = json.loads(payload)
    job_id = created.get("id") or (created.get("job") or {}).get("id")
    assert job_id, f"the create response carries no job id: {payload}"

    status, payload = _call(
        base_url, f"/api/sites/{SEEDED_DOMAIN}/cron/{job_id}/run", method="POST"
    )
    body = json.loads(payload) if payload.strip().startswith("{") else {}
    outcome = str(body.get("outcome") or body.get("status") or "").lower()
    assert outcome != "ok", (
        "a cron run reported success with no container to run in; "
        f"status {status}, body {payload}"
    )
    assert outcome, (
        f"the run response reports no outcome the UI could distinguish: {payload}"
    )
    # The HTTP status must agree with the outcome. An earlier revision of this
    # gate checked only the JSON field, so a change to an unconditional HTTP 200
    # passed it: the UI read `ok` and looked right while every status-checking
    # client — curl, a monitor, a deploy script — saw success for a job that
    # never ran. Phase 3b's purge gate (G7) already requires non-2xx when an
    # operation fails; cron must not contradict it.
    assert not (200 <= status < 300), (
        f"a cron run with outcome {outcome!r} answered HTTP {status}; a non-ok "
        f"outcome must not be reported as HTTP success: {payload}"
    )
