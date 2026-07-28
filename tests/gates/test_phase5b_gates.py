"""OPUS-OWNED IMMUTABLE GATE TESTS — Phase 5b (metrics, events and services panel).

DO NOT EDIT, SKIP, XFAIL, PARAMETRIZE AWAY, OR DELETE ANYTHING IN THIS FILE.

These tests are the security and correctness contract for Phase 5b. They are
written by the orchestrator before implementation and are verified byte-identical
(SHA-256 baseline) as a precondition for accepting the phase. If you believe a
gate asserts the wrong thing, escalate with evidence — do not edit the gate.

This file is deliberately self-contained: it depends only on the stdlib and the
`wpfy` package, never on other test modules or shared fixtures.

Deliberately NOT re-tested here: bearer auth on the new routes. Phase 3b's G1/G2
derive the mutating-route list from the panel's own route table, so they cover
every route this phase adds — *provided the route declares itself accurately*,
which is why R1 below exists.

What this phase can get wrong that nothing else catches:

    Phase 5b is the first phase to expose a *restart* verb. Every earlier
    mutation rewrote a file and reconciled; this one names a container and acts
    on it. That makes the service name the most dangerous string the panel has
    ever accepted, for three reasons no existing test observes:

    1. The name is interpolated into a `docker compose` argument vector. A name
       beginning with `-` becomes a flag; a name containing another site's
       project reaches another site's containers; `wpfy-traefik` reaches the
       shared edge and takes every site offline at once.
    2. `?scope=` reaches the metrics query over HTTP for the first time. Phase
       5a's gates proved the SQL is parameterised; nothing yet proves the panel
       does not widen the scope on its way there.
    3. The locked decision is container-level restarts *only* — no host service
       management, no reboot. That is a boundary a route table can quietly cross.

Invariants locked here:
  R1   Every non-GET route in the panel's own table declares `mutates=True`, and
       the edge-proxy restart declares `destructive=True`. A route that lies
       about mutating removes itself from Phase 3b's auth gates.
  R2   No route exposes host service management or a reboot path.
  R3   Exercising the panel invokes no host-mutating command.
  S1   A hostile `service` name is refused, including another site's service, the
       shared edge proxy, flag-shaped names, and shell metacharacters.
  S2   Anti-vacuity for S1: a legitimate service restart reaches execution.
  S3   A restart targets only the requesting site's compose project.
  S4   The service name never reaches the argument vector as a flag.
  S5   A service the site does not have is refused, not silently reported ok.
  T1   The edge-proxy restart requires a typed confirmation and does nothing
       without one.
  T2   Anti-vacuity for T1: the correct confirmation reaches execution.
  M1   A hostile `scope` over HTTP never returns another scope's rows.
  M2   Anti-vacuity for M1: a valid scope and range return rows.
  M3   An unknown range is refused with a client error, not a 500 and not a
       silent full-history read.
  M4   One site's metrics never contain another site's rows.
  E1   A hostile `limit` on the events feed is refused or clamped, never fatal.
  L1   No response from any endpoint this phase adds contains a site secret.

Three of these are regression guards rather than feature gates, and therefore
pass before the phase is implemented — deliberately, and verified to be
non-vacuous for what they actually assert:

  * R1 and R2 read the panel's own route table. They hold today and must keep
    holding as this phase adds routes; that is the whole point.
  * E1 exercises `/api/events`, which Phase 1 already ships. This phase adds the
    Events *page* on top of it, so the guard protects an existing endpoint from
    the new query parameters the page will drive.

Every other gate in this file was confirmed to fail before implementation, and
the ones that could have passed vacuously — host-mutation, flag-shaped service
names, per-site metrics isolation — carry explicit existence or success
preconditions so that a panel with none of these routes cannot satisfy them.

Contract pinned by these gates (the actor must match these names):
  * `GET  /api/metrics?scope=<host|domain>&range=<30m|1h|3h|6h|12h|24h>`
        response carries `samples`, a list whose entries expose `scope` and
        `cpu_percent`
  * `GET  /api/system/services`
        response carries `services`, a list whose entries expose `name` and
        `status`
  * `POST /api/sites/<domain>/services/<service>/restart`
        `RouteMeta(..., mutates=True)`
  * `POST /api/system/traefik/restart`
        body `{"confirm": "wpfy-traefik"}`, `RouteMeta(..., mutates=True,
        destructive=True)`

These gates put a fake `docker` first on PATH which logs every invocation and
exits 0, plus fake `systemctl`, `service`, `apt`, `apt-get`, `reboot` and
`shutdown` which log and exit 0. `WPFY_SKIP_RUNTIME` is deliberately NOT set:
skipping the runtime would make every restart gate vacuous, because no argument
vector would ever be built.
"""

from __future__ import annotations

import json
import os
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

GATE_TOKEN = "phase5b-gate-token"
SEEDED_DOMAIN = "dashboard.example"
OTHER_DOMAIN = "neighbour.example"
SECRET_MARKER = "PH5B-DB-SECRET-a91c3f"
ROOT_SECRET_MARKER = "PH5B-ROOT-SECRET-5e70bd"

EDGE_CONTAINER = "wpfy-traefik"
EXPECTED_RANGES = ("30m", "1h", "3h", "6h", "12h", "24h")

_GATE_ENV = (
    "WPFY_INSTALL_ROOT",
    "WPFY_CONFIG_DIR",
    "WPFY_STATE_DIR",
    "WPFY_LOG_DIR",
    "WPFY_SKIP_RUNTIME",
    "WPFY_SKIP_WORDPRESS_DOWNLOAD",
    "WPFY_SKIP_CHOWN",
    "WPFY_TEST_PROC_DIR",
    "WPFY_TEST_TRAEFIK_NETWORK_CIDRS",
    "WPFY_GATE_DOCKER_LOG",
    "WPFY_GATE_FORBIDDEN_LOG",
    "PATH",
)

_PATH_FIELDS = ("install_root", "config_dir", "state_dir", "log_dir")

# The edge proxy is the worst case: restarting it takes every site offline at
# once, so it must not be reachable through a per-site route. The flag-shaped
# entries matter because the name is interpolated into an argument vector.
HOSTILE_SERVICES = (
    EDGE_CONTAINER,
    "neighbour-example-app",
    f"{OTHER_DOMAIN}/app",
    "../neighbour.example/app",
    "app; rm -rf /",
    "app\nwpfy_injected",
    "app\x00",
    "-v",
    "--project-name",
    "--remove-orphans",
    "all",
    "",
)

HOSTILE_SCOPES = (
    "host' OR 1=1 --",
    "%",
    "_ost",
    OTHER_DOMAIN,
    "../../etc/passwd",
    "host\x00",
)

HOSTILE_LIMITS = ("-1", "0", "abc", "1e9", "99999999999999999999", "")

FORBIDDEN_COMMANDS = ("systemctl", "service", "apt", "apt-get", "reboot", "shutdown")

_FAKE_DOCKER = """#!/bin/sh
printf '%s\\n' "$*" >> "$WPFY_GATE_DOCKER_LOG"
case "$1" in
  version|info) printf 'wpfy-gate-fake-docker\\n' ;;
esac
exit 0
"""

_FAKE_FORBIDDEN = """#!/bin/sh
printf '%s %s\\n' "$(basename "$0")" "$*" >> "$WPFY_GATE_FORBIDDEN_LOG"
exit 0
"""


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


class GateHome:
    def __init__(self, base_url: str, paths, root: Path):
        self.base_url = base_url
        self.paths = paths
        self.root = root
        self.docker_log = root / "docker-invocations.log"
        self.forbidden_log = root / "forbidden-invocations.log"

    def _lines(self, path: Path) -> list[str]:
        if not path.exists():
            return []
        return [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]

    def docker_invocations(self) -> list[str]:
        return self._lines(self.docker_log)

    def forbidden_invocations(self) -> list[str]:
        return self._lines(self.forbidden_log)

    def reset_docker_log(self) -> None:
        self.docker_log.unlink(missing_ok=True)

    def restart_invocations(self) -> list[str]:
        return [line for line in self.docker_invocations() if "restart" in line.split()]


def _seed_site(paths, domain: str) -> Path:
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
        # Redis is deliberately absent so a `redis` restart is a service this
        # site does not have.
        "REDIS_ENABLED=0\n"
        "DB_NAME=dashdb\n"
        "DB_USER=dashdb\n"
        f"DB_PASSWORD={SECRET_MARKER}\n"
        f"MARIADB_PASSWORD={SECRET_MARKER}\n"
        f"DB_ROOT_PASSWORD={ROOT_SECRET_MARKER}\n"
        f"MARIADB_ROOT_PASSWORD={ROOT_SECRET_MARKER}\n",
        encoding="utf-8",
    )
    (site / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
    (site / "nginx" / "default.conf").write_text("server {\n    listen 8080;\n}\n", encoding="utf-8")
    (site / "nginx" / "extra" / "custom.conf").write_text("", encoding="utf-8")
    return site


@pytest.fixture
def gate_panel(tmp_path):
    """A real loopback panel over an isolated home, with docker and host tools faked.

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

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    proc_dir = tmp_path / "proc"
    proc_dir.mkdir(parents=True, exist_ok=True)
    (proc_dir / "stat").write_text("cpu  100 10 50 840 0 0 0 0 0 0\n", encoding="utf-8")
    (proc_dir / "meminfo").write_text(
        "MemTotal:        2048000 kB\nMemFree:          256000 kB\nMemAvailable:     512000 kB\n",
        encoding="utf-8",
    )

    os.environ.update({
        "WPFY_INSTALL_ROOT": str(tmp_path / "install"),
        "WPFY_CONFIG_DIR": str(tmp_path / "config"),
        "WPFY_STATE_DIR": str(tmp_path / "state"),
        "WPFY_LOG_DIR": str(tmp_path / "log"),
        "WPFY_SKIP_WORDPRESS_DOWNLOAD": "1",
        "WPFY_SKIP_CHOWN": "1",
        "WPFY_TEST_PROC_DIR": str(proc_dir),
        "WPFY_TEST_TRAEFIK_NETWORK_CIDRS": "172.31.0.0/16",
        "WPFY_GATE_DOCKER_LOG": str(tmp_path / "docker-invocations.log"),
        "WPFY_GATE_FORBIDDEN_LOG": str(tmp_path / "forbidden-invocations.log"),
        "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
    })
    # Skipping the runtime would make every restart gate vacuous: no argument
    # vector would ever be built, so nothing could be asserted about it.
    os.environ.pop("WPFY_SKIP_RUNTIME", None)
    for field in _PATH_FIELDS:
        object.__setattr__(paths, field, os.environ[f"WPFY_{field.upper()}"])
    Path(paths.state_dir).mkdir(parents=True, exist_ok=True)
    Path(paths.log_dir).mkdir(parents=True, exist_ok=True)

    _write_executable(bin_dir / "docker", _FAKE_DOCKER)
    for command in FORBIDDEN_COMMANDS:
        _write_executable(bin_dir / command, _FAKE_FORBIDDEN)

    wpfy.registry._REGISTRY = None
    wpfy.site_runtime.docker_available.cache_clear()

    _seed_site(paths, SEEDED_DOMAIN)
    _seed_site(paths, OTHER_DOMAIN)

    import wpfy.panel as panel

    config = panel.PanelConfig(host="127.0.0.1", port=0, token=GATE_TOKEN)
    server = panel.make_panel_server(config)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    home = GateHome(f"http://127.0.0.1:{server.server_address[1]}", paths, tmp_path)
    try:
        yield home
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


def _call(home, path, *, method="GET", body=None):
    request = urllib.request.Request(f"{home.base_url}{path}", method=method)
    request.add_header("Authorization", f"Bearer {GATE_TOKEN}")
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, data=data, timeout=30) as response:
            return response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8")


def _route_exists(status: int) -> bool:
    """404/405 means the endpoint is absent, which is not a security property.

    Without this distinction every hostile-input gate here would pass against a
    panel that simply has no metrics or services routes at all.
    """
    return status not in (404, 405)


def _refused(status: int, payload: str) -> bool:
    assert _route_exists(status), (
        f"the endpoint does not exist (status {status}); a missing route cannot "
        f"refuse anything, so this gate would be vacuous: {payload}"
    )
    assert status < 500, f"hostile input caused a server error rather than a refusal: {payload}"
    return not (200 <= status < 300)


def _samples(payload: str) -> list[dict]:
    document = json.loads(payload)
    assert isinstance(document, dict) and "samples" in document, (
        f"the metrics response carries no `samples` key: {payload[:400]}"
    )
    return list(document["samples"])


def test_gate_every_mutating_route_declares_itself(gate_panel):
    """A route that lies about mutating removes itself from Phase 3b's auth gates.

    Those gates derive the list of routes needing a token from this table, so an
    unmarked POST becomes an unauthenticated mutation without any gate noticing.
    """
    import wpfy.panel as panel

    undeclared = [
        (route.method, route.pattern.pattern)
        for route in panel._ROUTES
        if route.method != "GET" and not route.meta.mutates
    ]
    assert not undeclared, f"non-GET routes not declared as mutating: {undeclared}"


def test_gate_edge_proxy_restart_is_declared_destructive(gate_panel):
    """Restarting the shared edge takes every site offline at once."""
    import wpfy.panel as panel

    matches = [
        route for route in panel._ROUTES
        if route.method == "POST" and "traefik" in route.pattern.pattern and "restart" in route.pattern.pattern
    ]
    assert matches, "no POST route restarts the edge proxy"
    for route in matches:
        assert route.meta.destructive, (
            f"{route.pattern.pattern} is not declared destructive, so it does not "
            f"require the typed confirmation the spine gives destructive routes"
        )


def test_gate_no_route_exposes_host_service_control(gate_panel):
    """The locked decision is container-level only: no host services, no reboot."""
    import wpfy.panel as panel

    forbidden = ("reboot", "shutdown", "systemctl", "poweroff", "host/service", "hostservice")
    offenders = [
        (route.method, route.pattern.pattern)
        for route in panel._ROUTES
        for token in forbidden
        if token in route.pattern.pattern.lower()
    ]
    assert not offenders, f"routes expose host-level control: {offenders}"


def test_gate_panel_invokes_no_host_mutating_command(gate_panel):
    """Read-only-toward-the-host by construction; this is the check.

    The existence preconditions matter: without them this gate passes against a
    panel that has none of this phase's routes, since a 404 shells out to
    nothing.
    """
    exercised = (
        ("GET", "/api/overview", None),
        ("GET", "/api/system/services", None),
        ("GET", "/api/metrics?scope=host&range=1h", None),
        ("POST", f"/api/sites/{SEEDED_DOMAIN}/services/web/restart", {}),
        ("POST", "/api/system/traefik/restart", {"confirm": EDGE_CONTAINER}),
    )
    for method, path, body in exercised:
        status, payload = _call(gate_panel, path, method=method, body=body)
        assert _route_exists(status), (
            f"{method} {path} does not exist (status {status}); this gate would be "
            f"vacuous, because a missing route cannot invoke anything: {payload}"
        )

    invocations = gate_panel.forbidden_invocations()
    assert not invocations, f"the panel invoked host-mutating commands: {invocations}"


@pytest.mark.parametrize("service", HOSTILE_SERVICES)
def test_gate_hostile_service_name_is_refused(gate_panel, service):
    """The service name is interpolated into a `docker compose` argument vector.

    `wpfy-traefik` reaches the shared edge, another site's project reaches
    another site's containers, and a name beginning with `-` becomes a flag.
    """
    gate_panel.reset_docker_log()
    encoded = urllib.request.quote(service, safe="")
    status, payload = _call(
        gate_panel, f"/api/sites/{SEEDED_DOMAIN}/services/{encoded}/restart", method="POST", body={},
    )

    assert _refused(status, payload), f"the panel accepted service {service!r}: {payload}"
    assert not gate_panel.restart_invocations(), (
        f"service {service!r} was refused at the HTTP layer but a restart still "
        f"ran: {gate_panel.restart_invocations()}"
    )


def test_gate_a_legitimate_service_restart_reaches_execution(gate_panel):
    """Anti-vacuity: a route that refuses everything passes every gate above."""
    gate_panel.reset_docker_log()
    status, payload = _call(
        gate_panel, f"/api/sites/{SEEDED_DOMAIN}/services/web/restart", method="POST", body={},
    )

    assert 200 <= status < 300, f"restarting `web` was refused: {status} {payload}"
    restarts = gate_panel.restart_invocations()
    assert restarts, "no docker invocation carried a restart"
    assert any("web" in line.split() for line in restarts), (
        f"no restart names the `web` service: {restarts}"
    )


def test_gate_restart_targets_only_the_requesting_sites_project(gate_panel):
    """Site isolation, at the one place the panel names a container to act on."""
    gate_panel.reset_docker_log()
    _call(gate_panel, f"/api/sites/{SEEDED_DOMAIN}/services/web/restart", method="POST", body={})

    seeded_project = SEEDED_DOMAIN.replace(".", "-")
    other_project = OTHER_DOMAIN.replace(".", "-")
    restarts = gate_panel.restart_invocations()
    assert restarts, "no restart was invoked, so isolation is untested"
    for line in restarts:
        assert seeded_project in line, (
            f"a restart for {SEEDED_DOMAIN} does not name its compose project: {line!r}"
        )
        assert other_project not in line, (
            f"a restart for {SEEDED_DOMAIN} reached {OTHER_DOMAIN}'s project: {line!r}"
        )


def test_gate_service_name_never_becomes_a_flag(gate_panel):
    """A name beginning with `-` must never be handed to docker as an option.

    The precondition is what stops this being vacuous: a panel that invokes no
    docker command at all trivially never passes a flag.
    """
    gate_panel.reset_docker_log()
    status, payload = _call(
        gate_panel, f"/api/sites/{SEEDED_DOMAIN}/services/web/restart", method="POST", body={},
    )
    assert 200 <= status < 300, f"the control restart failed, so no vector exists: {payload}"
    assert gate_panel.docker_invocations(), (
        "a legitimate restart built no docker argument vector, so there is nothing "
        "for a flag-shaped name to leak into and this gate would be vacuous"
    )

    for service in ("-v", "--project-name", "--remove-orphans"):
        gate_panel.reset_docker_log()
        encoded = urllib.request.quote(service, safe="")
        _call(
            gate_panel, f"/api/sites/{SEEDED_DOMAIN}/services/{encoded}/restart",
            method="POST", body={},
        )
        for line in gate_panel.docker_invocations():
            assert service not in line.split(), (
                f"the flag-shaped service {service!r} reached the argument vector: {line!r}"
            )


def test_gate_a_service_the_site_does_not_have_is_refused(gate_panel):
    """Redis is disabled on the seeded site, so restarting it cannot succeed.

    Reporting success for a container that does not exist is worse than an
    error: the operator believes they have restarted something.
    """
    gate_panel.reset_docker_log()
    status, payload = _call(
        gate_panel, f"/api/sites/{SEEDED_DOMAIN}/services/redis/restart", method="POST", body={},
    )
    assert _refused(status, payload), (
        f"restarting `redis` on a site without Redis reported success: {payload}"
    )


def test_gate_edge_restart_requires_a_typed_confirmation(gate_panel):
    for body in ({}, {"confirm": ""}, {"confirm": SEEDED_DOMAIN}, {"confirm": "yes"}):
        gate_panel.reset_docker_log()
        status, payload = _call(gate_panel, "/api/system/traefik/restart", method="POST", body=body)
        assert _refused(status, payload), (
            f"the edge restart accepted body {body!r}: {payload}"
        )
        assert not gate_panel.restart_invocations(), (
            f"the edge restart ran without a valid confirmation: "
            f"{gate_panel.restart_invocations()}"
        )


def test_gate_edge_restart_with_the_right_confirmation_reaches_execution(gate_panel):
    """Anti-vacuity for the confirmation gate."""
    gate_panel.reset_docker_log()
    status, payload = _call(
        gate_panel, "/api/system/traefik/restart", method="POST", body={"confirm": EDGE_CONTAINER},
    )
    assert 200 <= status < 300, f"a correctly confirmed edge restart was refused: {status} {payload}"
    assert gate_panel.docker_invocations(), "a confirmed edge restart invoked no docker command"


@pytest.mark.parametrize("scope", HOSTILE_SCOPES)
def test_gate_hostile_metrics_scope_never_returns_another_scopes_rows(gate_panel, scope):
    """`?scope=` reaches the metrics query from the wire for the first time here."""
    encoded = urllib.request.quote(scope, safe="")
    status, payload = _call(gate_panel, f"/api/metrics?scope={encoded}&range=24h")
    assert _route_exists(status), f"the metrics endpoint does not exist: {payload}"
    assert status < 500, f"scope {scope!r} caused a server error: {payload}"
    if not (200 <= status < 300):
        return
    leaked = [sample for sample in _samples(payload) if sample.get("scope") != scope]
    assert not leaked, (
        f"scope {scope!r} returned rows belonging to "
        f"{sorted({str(sample.get('scope')) for sample in leaked})}"
    )


def test_gate_a_valid_scope_and_range_return_rows(gate_panel):
    """Anti-vacuity: an endpoint that always returns nothing passes M1 trivially."""
    import wpfy.metrics as metrics

    metrics.sample_once()
    status, payload = _call(gate_panel, "/api/metrics?scope=host&range=1h")
    assert 200 <= status < 300, f"a valid metrics read failed: {status} {payload}"
    samples = _samples(payload)
    assert samples, "no samples returned for a sample taken moments ago"
    assert {sample.get("scope") for sample in samples} == {"host"}


@pytest.mark.parametrize("range_key", ("99y", "30", "", "1h; DROP TABLE samples", "-1h"))
def test_gate_an_unknown_metrics_range_is_refused(gate_panel, range_key):
    """A 500 leaks internals; a silent full read is how a browser gets 20k points."""
    encoded = urllib.request.quote(range_key, safe="")
    status, payload = _call(gate_panel, f"/api/metrics?scope=host&range={encoded}")
    assert _route_exists(status), f"the metrics endpoint does not exist: {payload}"
    assert 400 <= status < 500, (
        f"range {range_key!r} answered {status}; an unknown range is a client error: {payload}"
    )


def test_gate_one_sites_metrics_never_contain_another_sites_rows(gate_panel):
    import wpfy.metrics as metrics

    metrics.sample_once()
    status, payload = _call(
        gate_panel, f"/api/metrics?scope={SEEDED_DOMAIN}&range=24h",
    )
    assert 200 <= status < 300, (
        f"a valid per-site metrics read failed ({status}); a read that never "
        f"succeeds cannot demonstrate isolation: {payload}"
    )
    foreign = [
        sample for sample in _samples(payload)
        if sample.get("scope") not in (SEEDED_DOMAIN,)
    ]
    assert not foreign, f"{SEEDED_DOMAIN}'s metrics contained other scopes: {foreign}"


@pytest.mark.parametrize("limit", HOSTILE_LIMITS)
def test_gate_a_hostile_events_limit_is_never_fatal(gate_panel, limit):
    """The Events page drives this parameter, so it is user input."""
    encoded = urllib.request.quote(limit, safe="")
    status, payload = _call(gate_panel, f"/api/events?limit={encoded}")
    assert _route_exists(status), f"the events endpoint does not exist: {payload}"
    assert status < 500, f"limit {limit!r} caused a server error: {payload}"


def test_gate_no_new_endpoint_leaks_a_site_secret(gate_panel):
    """The seeded site's password markers must not appear in any response."""
    import wpfy.metrics as metrics

    metrics.sample_once()
    paths = (
        "/api/metrics?scope=host&range=1h",
        f"/api/metrics?scope={SEEDED_DOMAIN}&range=24h",
        "/api/system/services",
        "/api/events?limit=200",
    )
    for path in paths:
        status, payload = _call(gate_panel, path)
        if not _route_exists(status):
            raise AssertionError(f"{path} does not exist, so this gate would be vacuous")
        for marker in (SECRET_MARKER, ROOT_SECRET_MARKER):
            assert marker not in payload, f"{marker} appears in the response from {path}"


def test_gate_services_endpoint_reports_named_services(gate_panel):
    """Anti-vacuity for the secret scan: an empty response leaks nothing either."""
    status, payload = _call(gate_panel, "/api/system/services")
    assert 200 <= status < 300, f"the services endpoint failed: {status} {payload}"
    document = json.loads(payload)
    assert isinstance(document, dict) and "services" in document, (
        f"the services response carries no `services` key: {payload[:400]}"
    )
    services = list(document["services"])
    assert services, "the services endpoint reported nothing at all"
    for entry in services:
        assert "name" in entry and "status" in entry, (
            f"a service entry lacks `name` or `status`: {entry}"
        )
