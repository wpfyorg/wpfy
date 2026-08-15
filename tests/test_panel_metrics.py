from __future__ import annotations

import importlib
import json
import threading
import time
import urllib.error
import urllib.request

import pytest


TOKEN = "test-panel-metrics-token"
SECRET = "panel-metrics-secret"


@pytest.fixture
def panel_server(tmp_wpfy_home, monkeypatch):
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")

    import wpfy.metrics
    import wpfy.panel

    importlib.reload(wpfy.metrics)
    importlib.reload(wpfy.panel)
    config = wpfy.panel.PanelConfig(host="127.0.0.1", port=0, token=TOKEN)
    server = wpfy.panel.make_panel_server(config)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", wpfy.metrics
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _request(base_url: str, path: str):
    request = urllib.request.Request(f"{base_url}{path}")
    request.add_header("Authorization", f"Bearer {TOKEN}")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def _seed(metrics) -> None:
    now = int(time.time())
    metrics._insert_samples([
        metrics.Sample(now, "host", 12.5, 100, 200, 300, 400, 0.5),
        metrics.Sample(now, "one.example", 3.0, 10, 20, 30, 40, 0.5),
        metrics.Sample(now, "two.example", 4.0, 11, 22, 33, 44, 0.5),
    ])


def test_metrics_endpoint_returns_full_sample_and_range_vocabulary(panel_server):
    base_url, metrics = panel_server
    _seed(metrics)

    status, payload = _request(base_url, "/api/metrics?scope=host&range=1h")

    assert status == 200
    assert payload["ranges"] == list(metrics.RANGES)
    assert payload["samples"] == [{
        "timestamp": payload["samples"][0]["timestamp"],
        "scope": "host",
        "cpu_percent": 12.5,
        "memory_used": 100,
        "memory_total": 200,
        "disk_used": 300,
        "disk_total": 400,
        "load1": 0.5,
    }]


@pytest.mark.parametrize("range_key", ("", "99y", "1h; DROP TABLE samples", "-1h"))
def test_metrics_endpoint_rejects_unknown_range(panel_server, range_key):
    base_url, _ = panel_server
    status, payload = _request(base_url, f"/api/metrics?scope=host&range={urllib.request.quote(range_key)}")
    assert status == 400
    assert "range" in payload["error"]


def test_metrics_endpoint_preserves_exact_unknown_scope(panel_server):
    base_url, metrics = panel_server
    _seed(metrics)

    status, payload = _request(base_url, "/api/metrics?scope=one.example%25&range=24h")

    assert status == 200
    assert payload["scope"] == "one.example%"
    assert payload["samples"] == []


def test_metrics_endpoint_isolates_site_rows_and_leaks_no_secret(panel_server):
    base_url, metrics = panel_server
    _seed(metrics)

    status, payload = _request(base_url, "/api/metrics?scope=one.example&range=24h")

    assert status == 200
    assert {sample["scope"] for sample in payload["samples"]} == {"one.example"}
    assert SECRET not in json.dumps(payload)


def test_latest_samples_returns_one_row_per_scope(panel_server):
    """The services view needs a current reading for every scope in one query."""
    import time as _time

    _, metrics = panel_server
    now = int(_time.time())
    metrics._insert_samples([
        metrics.Sample(now - 120, metrics.HOST_SCOPE, 10.0, 1, 2, 3, 4, 0.5),
        metrics.Sample(now - 60, metrics.HOST_SCOPE, 20.0, 1, 2, 3, 4, 0.5),
        metrics.Sample(now - 60, "example.com", 30.0, 5, 6, 7, 8, 0.5),
    ])
    latest = {sample.scope: sample for sample in metrics.latest_samples()}
    assert {metrics.HOST_SCOPE, "example.com"} <= set(latest)
    assert len([s for s in metrics.latest_samples() if s.scope == metrics.HOST_SCOPE]) == 1
    assert latest[metrics.HOST_SCOPE].cpu_percent == 20.0, "an older host sample won over the newer one"


def test_latest_samples_drops_stale_scopes(panel_server):
    """A site whose containers stopped keeps its last sample forever.

    Rendering yesterday's reading as the current one is worse than rendering
    nothing: the operator reads a stopped site as a healthy one.
    """
    import time as _time

    _, metrics = panel_server
    now = int(_time.time())
    metrics._insert_samples([
        metrics.Sample(now - 10, metrics.HOST_SCOPE, 1.0, 1, 2, 3, 4, 0.1),
        metrics.Sample(now - 86400, "stopped.example", 99.0, 1, 2, 3, 4, 0.1),
    ])
    scopes = {sample.scope for sample in metrics.latest_samples()}
    assert "stopped.example" not in scopes
    assert metrics.HOST_SCOPE in scopes
