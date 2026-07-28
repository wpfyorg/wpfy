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
    base_url, docker_log = panel_server
    docker_log.unlink(missing_ok=True)
    status, payload = _request(
        base_url,
        "/api/system/traefik/restart",
        method="POST",
        body={"confirm": "wpfy-traefik"},
    )
    assert status == 200
    assert payload["ran"] is True
    assert _invocations(docker_log)
