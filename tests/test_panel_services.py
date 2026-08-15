from __future__ import annotations

import importlib
import json
import os
from pathlib import Path
import threading
import urllib.error
import urllib.request

import pytest


TOKEN = "test-panel-services-token"
DOMAIN = "services.example.com"
SECRET = "panel-services-db-secret"


def _seed_site(paths) -> None:
    site = Path(paths.sites_dir) / DOMAIN
    (site / "nginx" / "extra").mkdir(parents=True, exist_ok=True)
    (site / "php").mkdir(parents=True, exist_ok=True)
    (site / "app").mkdir(parents=True, exist_ok=True)
    (site / ".env").write_text(
        f"DOMAIN={DOMAIN}\nSITE_FLAVOR=wp\nCOMPOSE_PROJECT_NAME=services-example-com\n"
        "APP_ROOT=/var/www/html\nPHP_VERSION=8.4\nSITE_UID=1700\n"
        "LETSENCRYPT_MODE=disabled\nPAGE_CACHE=none\nREDIS_ENABLED=0\n"
        "DB_NAME=site\nDB_USER=site\n"
        f"DB_PASSWORD={SECRET}\nMARIADB_PASSWORD={SECRET}\n",
        encoding="utf-8",
    )
    (site / "compose.yaml").write_text("services: {}\n", encoding="utf-8")


@pytest.fixture
def panel_server(tmp_wpfy_home, tmp_path, monkeypatch):
    monkeypatch.delenv("WPFY_SKIP_RUNTIME", raising=False)
    docker_log = tmp_path / "docker.log"
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    docker = bin_dir / "docker"
    docker.write_text(
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$WPFY_TEST_DOCKER_LOG\"\n"
        "case \"$*\" in *'compose version'*) echo 'Docker Compose version v2.0.0' ;; esac\nexit 0\n",
        encoding="utf-8",
    )
    docker.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    monkeypatch.setenv("WPFY_TEST_DOCKER_LOG", str(docker_log))
    monkeypatch.setenv("WPFY_TEST_TRAEFIK_NETWORK_CIDRS", "172.31.0.0/16")
    _seed_site(tmp_wpfy_home)

    import wpfy.panel
    import wpfy.site_runtime
    import wpfy.traefik

    importlib.reload(wpfy.panel)
    wpfy.site_runtime.docker_available.cache_clear()
    config = wpfy.panel.PanelConfig(host="127.0.0.1", port=0, token=TOKEN)
    server = wpfy.panel.make_panel_server(config)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", docker_log
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        wpfy.site_runtime.docker_available.cache_clear()


def _request(base_url: str, path: str, *, method="GET", body=None):
    request = urllib.request.Request(f"{base_url}{path}", method=method)
    request.add_header("Authorization", f"Bearer {TOKEN}")
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, data=data, timeout=10) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def _invocations(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines() if path.exists() else []


def test_services_endpoint_lists_edge_and_site_services_without_secrets(panel_server):
    base_url, _ = panel_server
    status, payload = _request(base_url, "/api/system/services")
    assert status == 200
    assert "wpfy-traefik" in {service["name"] for service in payload["services"]}
    assert f"{DOMAIN}:web" in {service["name"] for service in payload["services"]}
    assert SECRET not in json.dumps(payload)


def test_site_service_restart_uses_existing_allowlist_and_exact_argument_vector(panel_server):
    base_url, docker_log = panel_server
    docker_log.unlink(missing_ok=True)

    status, payload = _request(base_url, f"/api/sites/{DOMAIN}/services/web/restart", method="POST", body={})

    assert status == 200
    assert payload["ran"] is True
    restarts = [line for line in _invocations(docker_log) if "restart" in line.split()]
    assert restarts == ["compose --project-name services-example-com restart web"]


@pytest.mark.parametrize("service", ("redis", "wpfy-traefik", "-v", "--remove-orphans", "other-site-app"))
def test_site_service_restart_refuses_unavailable_and_hostile_names_before_execution(panel_server, service):
    base_url, docker_log = panel_server
    docker_log.unlink(missing_ok=True)
    status, _ = _request(
        base_url,
        f"/api/sites/{DOMAIN}/services/{urllib.request.quote(service, safe='')}/restart",
        method="POST",
        body={},
    )
    assert status == 400
    assert not [line for line in _invocations(docker_log) if "restart" in line.split()]


@pytest.mark.parametrize("body", ({}, {"confirm": ""}, {"confirm": DOMAIN}, {"confirm": "yes"}))
def test_edge_restart_requires_exact_typed_confirmation(panel_server, body):
    base_url, docker_log = panel_server
    docker_log.unlink(missing_ok=True)
    status, _ = _request(base_url, "/api/system/traefik/restart", method="POST", body=body)
    assert status == 400
    assert not [line for line in _invocations(docker_log) if "restart" in line.split()]


def test_edge_restart_runs_with_exact_confirmation(panel_server):
    """The restart is a job now, so the response is the ticket, not the result.

    It used to block for the whole restart and answer 200. Every long operation
    in the panel returns 202 with a job id; this asserts the work still reaches
    Docker, by waiting for the job rather than for the request.
    """
    import time as _time

    base_url, docker_log = panel_server
    docker_log.unlink(missing_ok=True)
    status, payload = _request(
        base_url,
        "/api/system/traefik/restart",
        method="POST",
        body={"confirm": "wpfy-traefik"},
    )
    assert status == 202, payload
    job_id = payload["job_id"]

    deadline = _time.time() + 10
    while _time.time() < deadline:
        _, job = _request(base_url, f"/api/jobs/{job_id}")
        if job["state"] in {"succeeded", "failed"}:
            break
        _time.sleep(0.1)
    assert job["state"] == "succeeded", job
    assert job["result"]["ran"] is True
    assert _invocations(docker_log)


def test_edge_service_status_is_one_state_not_a_docker_table(monkeypatch):
    """Found on a clean VPS: the dashboard said "1 service degraded: wpfy-traefik"
    while Docker reported the container healthy.

    `traefik_status()` returns the whole `docker compose ps` table -- header row,
    image, ports -- which is right for the CLI and wrong as a status field. The
    client reads it as one container's state, finds no match, and reports the
    edge proxy as degraded on the dashboard of a healthy install.
    """
    from wpfy import panel, traefik
    from wpfy.site_runtime import RuntimeResult

    real_table = (
        "NAME           IMAGE             COMMAND                  SERVICE   CREATED   STATUS\n"
        "wpfy-traefik   traefik:v3.6.17   \"/entrypoint.sh trae…\"   traefik   22 minutes ago   "
        "Up 22 minutes (healthy)   0.0.0.0:80->80/tcp"
    )
    monkeypatch.setattr(traefik, "traefik_status", lambda: RuntimeResult(0, real_table, ran=True))
    monkeypatch.setattr(traefik, "traefik_health", lambda: "healthy")
    monkeypatch.setattr(panel, "list_sites", lambda: [])

    edge = next(s for s in panel.api_system_services()["services"] if s["name"] == "wpfy-traefik")

    assert edge["status"] == "healthy"
    assert "\n" not in edge["status"] and "NAME" not in edge["status"]


def test_the_client_treats_healthy_as_healthy():
    """Docker reports `healthy` for a container with a healthcheck and `running`
    for one without. A client accepting only `running` marks the edge proxy --
    and every site image that declares a healthcheck -- permanently degraded.
    """
    from wpfy import panel

    source = (Path(panel.__file__).parent / "panel_static" / "panel.js").read_text(encoding="utf-8")
    assert 'SERVICE_HEALTHY = new Set(["running", "healthy"])' in source
    assert "export function isServiceHealthy" in source

    static = Path(panel.__file__).parent / "panel_static"
    for name in ("page-services.js", "site-tab-overview.js", "panel.js"):
        body = (static / name).read_text(encoding="utf-8")
        assert 'status !== "running"' not in body, f"{name} still hardcodes the running-only check"
        assert 'status === "running"' not in body, f"{name} still hardcodes the running-only check"


def test_overview_traefik_field_is_a_state_not_a_table(monkeypatch):
    """The dashboard's Traefik card printed the `docker compose ps` header as its
    own subtext, and decided "degraded" by searching that table for "error" --
    a substring that a container name can supply by accident.
    """
    from wpfy import operational_inspection, panel, traefik

    monkeypatch.setattr(traefik, "traefik_health", lambda: "healthy")
    monkeypatch.setattr(
        operational_inspection, "aggregate_info",
        lambda: operational_inspection.AggregateInfo((), "NAME IMAGE COMMAND\nwpfy-traefik ...", "29.7.2"))

    payload = panel.api_overview()

    assert payload["traefik"] == "healthy"
    assert payload["warnings"] == 0


def test_site_health_badge_uses_the_vocabulary_the_server_emits():
    """Found creating a site on the VPS: a fully working site showed "ready" in red.

    `site_health` emits ready | running | degraded | down | needs-bootstrap |
    <status>-bootstrap. The badge tested for "healthy", which the server never
    emits, so green was unreachable for every site in every state.
    """
    from wpfy import panel

    source = (Path(panel.__file__).parent / "panel_static" / "site-tab-overview.js").read_text(encoding="utf-8")
    assert 'status === "healthy"' not in source, "still testing for a status the server never emits"
    assert 'ready: "bg-green-lt text-green"' in source
    assert 'if (key === "ready") return "green";' in source
