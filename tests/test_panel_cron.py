from __future__ import annotations

import importlib
import json
from pathlib import Path
import threading
import urllib.error
import urllib.request

import pytest

TEST_TOKEN = "test-panel-cron-token"
DOMAIN = "cron.example.com"
DB_SECRET = "panel-cron-db-secret"
ROOT_SECRET = "panel-cron-root-secret"


def _seed_site(paths) -> Path:
    site = Path(paths.sites_dir) / DOMAIN
    (site / "nginx" / "extra").mkdir(parents=True, exist_ok=True)
    (site / "php").mkdir(parents=True, exist_ok=True)
    (site / "app").mkdir(parents=True, exist_ok=True)
    (site / ".env").write_text(
        f"DOMAIN={DOMAIN}\n"
        "SITE_FLAVOR=wpredis\n"
        "COMPOSE_PROJECT_NAME=cron-example-com\n"
        "APP_ROOT=/var/www/html\n"
        "PHP_VERSION=8.4\n"
        "SITE_UID=1700\n"
        "LETSENCRYPT_MODE=disabled\n"
        "PAGE_CACHE=none\n"
        "REDIS_ENABLED=1\n"
        "DB_NAME=cron\n"
        "DB_USER=cron\n"
        f"DB_PASSWORD={DB_SECRET}\n"
        f"MARIADB_PASSWORD={DB_SECRET}\n"
        f"DB_ROOT_PASSWORD={ROOT_SECRET}\n"
        f"MARIADB_ROOT_PASSWORD={ROOT_SECRET}\n",
        encoding="utf-8",
    )
    (site / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
    (site / "nginx" / "default.conf").write_text("server { listen 8080; }\n", encoding="utf-8")
    return site


@pytest.fixture
def panel_server(tmp_wpfy_home, monkeypatch):
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")

    import wpfy.operational_inspection
    import wpfy.panel
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    importlib.reload(wpfy.operational_inspection)
    importlib.reload(wpfy.panel)

    config = wpfy.panel.PanelConfig(host="127.0.0.1", port=0, token=TEST_TOKEN)
    server = wpfy.panel.make_panel_server(config)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", tmp_wpfy_home
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _request(base_url: str, path: str, *, method="GET", body=None):
    request = urllib.request.Request(f"{base_url}{path}", method=method)
    request.add_header("Authorization", f"Bearer {TEST_TOKEN}")
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, data=data, timeout=10) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def test_cron_get_returns_jobs_and_site_service_allowlist(panel_server):
    base_url, paths = panel_server
    _seed_site(paths)

    status, payload = _request(base_url, f"/api/sites/{DOMAIN}/cron")

    assert status == 200
    assert payload["jobs"] == []
    assert set(payload["services"]) == {"app", "db", "redis", "web"}
    assert DB_SECRET not in json.dumps(payload)
    assert ROOT_SECRET not in json.dumps(payload)


def test_cron_create_enable_run_and_delete_round_trip(panel_server):
    base_url, paths = panel_server
    _seed_site(paths)

    status, created = _request(
        base_url,
        f"/api/sites/{DOMAIN}/cron",
        method="POST",
        body={"schedule": "*/5 * * * *", "command": "wp cron event run --due-now", "service": "app", "timeout": 45},
    )
    assert status == 201
    job_id = created["id"]
    assert created["job"] == {
        "id": job_id,
        "schedule": "*/5 * * * *",
        "command": "wp cron event run --due-now",
        "service": "app",
        "enabled": True,
        "timeout": 45,
    }

    _, listed = _request(base_url, f"/api/sites/{DOMAIN}/cron")
    assert listed["jobs"][0]["id"] == job_id
    assert listed["jobs"][0]["last_run"] is None

    status, disabled = _request(
        base_url,
        f"/api/sites/{DOMAIN}/cron/{job_id}",
        method="PUT",
        body={"enabled": False},
    )
    assert status == 200
    assert disabled["enabled"] is False

    status, run = _request(
        base_url,
        f"/api/sites/{DOMAIN}/cron/{job_id}/run",
        method="POST",
        body={},
    )
    assert status == 503
    assert run["ok"] is False
    assert run["outcome"] == "skipped"
    assert run["skipped"] is True
    assert "WPFY_SKIP_RUNTIME" in run["message"]

    _, after_run = _request(base_url, f"/api/sites/{DOMAIN}/cron")
    assert after_run["jobs"][0]["last_run"]["outcome"] == "skipped"

    status, removed = _request(
        base_url,
        f"/api/sites/{DOMAIN}/cron/{job_id}",
        method="DELETE",
        body={},
    )
    assert status == 200
    assert removed["removed"] is True
    _, final = _request(base_url, f"/api/sites/{DOMAIN}/cron")
    assert final["jobs"] == []


@pytest.mark.parametrize(
    ("outcome", "expected_status"),
    (("ok", 200), ("skipped", 503), ("failed", 500), ("timeout", 500)),
)
def test_cron_run_status_matches_outcome(panel_server, monkeypatch, outcome, expected_status):
    import wpfy.site_cron

    base_url, paths = panel_server
    _seed_site(paths)
    _, created = _request(
        base_url,
        f"/api/sites/{DOMAIN}/cron",
        method="POST",
        body={"schedule": "* * * * *", "command": "echo status", "service": "app"},
    )
    job_id = created["id"]
    result = wpfy.site_cron.CronJobRun(
        DOMAIN,
        job_id,
        outcome,
        f"cron run {outcome}",
        0.125,
        exit_code=0 if outcome in {"ok", "skipped"} else 1,
        ran=outcome != "skipped",
        skipped=outcome == "skipped",
    )
    monkeypatch.setattr("wpfy.panel.site_cron.run_job", lambda domain, requested_id: result)

    status, payload = _request(
        base_url,
        f"/api/sites/{DOMAIN}/cron/{job_id}/run",
        method="POST",
        body={},
    )

    assert status == expected_status
    assert payload == {
        "ok": outcome == "ok",
        "domain": DOMAIN,
        "job_id": job_id,
        "outcome": outcome,
        "message": f"cron run {outcome}",
        "duration": 0.125,
        "exit_code": 0 if outcome in {"ok", "skipped"} else 1,
        "ran": outcome != "skipped",
        "skipped": outcome == "skipped",
    }


def test_cron_defaults_service_and_timeout(panel_server):
    base_url, paths = panel_server
    _seed_site(paths)

    status, created = _request(
        base_url,
        f"/api/sites/{DOMAIN}/cron",
        method="POST",
        body={"schedule": "0 3 * * *", "command": "php -v"},
    )

    assert status == 201
    assert created["job"]["service"] == "app"
    assert created["job"]["timeout"] == 300


def test_cron_rejects_cross_site_and_unknown_services(panel_server):
    base_url, paths = panel_server
    _seed_site(paths)

    for service in ("wpfy-traefik", "other-site-app", "../other/app", "app; rm -rf /"):
        status, payload = _request(
            base_url,
            f"/api/sites/{DOMAIN}/cron",
            method="POST",
            body={"schedule": "* * * * *", "command": "echo hi", "service": service},
        )
        assert status == 400
        rendered = json.dumps(payload)
        assert DB_SECRET not in rendered
        assert ROOT_SECRET not in rendered


def test_cron_strict_fields_and_invalid_job_updates_are_refused(panel_server):
    base_url, paths = panel_server
    _seed_site(paths)

    status, payload = _request(
        base_url,
        f"/api/sites/{DOMAIN}/cron",
        method="POST",
        body={"schedule": "* * * * *", "command": "echo hi", "service": "app", "enabled": False},
    )
    assert status == 400
    assert "unsupported" in payload["error"]

    status, payload = _request(
        base_url,
        f"/api/sites/{DOMAIN}/cron/not-a-real-job",
        method="PUT",
        body={"enabled": "false"},
    )
    assert status == 400
    assert "boolean enabled" in payload["error"]
