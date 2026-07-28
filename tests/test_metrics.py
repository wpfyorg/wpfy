from __future__ import annotations

import importlib
import json
from pathlib import Path
import sqlite3
import subprocess

import pytest


HOST_PROC_STAT = """cpu  100 10 50 840 0 0 0 0 0 0
cpu0 50 5 25 420 0 0 0 0 0 0
"""
HOST_PROC_MEMINFO = """MemTotal:        2048000 kB
MemFree:          256000 kB
MemAvailable:     512000 kB
Buffers:           64000 kB
Cached:           256000 kB
"""


def _docker_row(name: str, cpu: str, memory: str) -> str:
    return json.dumps({"Name": name, "CPUPerc": cpu, "MemUsage": memory})


@pytest.fixture
def metrics_home(tmp_wpfy_home, tmp_path, monkeypatch):
    import wpfy.metrics
    import wpfy.site_layout
    import wpfy.site_paths

    proc_dir = tmp_path / "proc"
    proc_dir.mkdir()
    (proc_dir / "stat").write_text(HOST_PROC_STAT, encoding="utf-8")
    (proc_dir / "meminfo").write_text(HOST_PROC_MEMINFO, encoding="utf-8")
    monkeypatch.setenv("WPFY_TEST_PROC_DIR", str(proc_dir))

    importlib.reload(wpfy.site_paths)
    importlib.reload(wpfy.site_layout)
    metrics = importlib.reload(wpfy.metrics)

    domains = ("metrics.example", "metrics.example.org")
    for domain in domains:
        root = Path(tmp_wpfy_home.sites_dir) / domain
        root.mkdir(parents=True)
        (root / ".env").write_text(
            f"DOMAIN={domain}\nSITE_FLAVOR=wp\nCOMPOSE_PROJECT_NAME={domain.replace('.', '-')}\n",
            encoding="utf-8",
        )
        (root / "compose.yaml").write_text("services: {}\n", encoding="utf-8")

    stats = "\n".join((
        _docker_row("metrics-example-app-1", "5.00%", "1GiB / 2GiB"),
        _docker_row("metrics-example-org-app-1", "77.50%", "500MiB / 2GiB"),
        _docker_row("wpfy-traefik", "3.00%", "64MiB / 2GiB"),
    ))
    monkeypatch.setattr(metrics.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(metrics.shutil, "which", lambda command: "/usr/bin/docker")
    monkeypatch.setattr(
        metrics.subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(command, 0, stats, ""),
    )
    return metrics, tmp_wpfy_home, domains


def test_sample_parses_static_proc_and_exact_container_projects(metrics_home):
    metrics, _, domains = metrics_home

    result = metrics.sample_once()

    samples = {sample.scope: sample for sample in result.samples}
    assert set(samples) == {metrics.HOST_SCOPE, *domains}
    assert samples[metrics.HOST_SCOPE].cpu_percent == 0.0
    assert samples[metrics.HOST_SCOPE].memory_total == 2048000 * 1024
    assert samples[metrics.HOST_SCOPE].memory_used == (2048000 - 512000) * 1024
    assert samples["metrics.example"].cpu_percent == 5.0
    assert samples["metrics.example"].memory_used == 1024**3
    assert samples["metrics.example.org"].cpu_percent == 77.5
    assert "wpfy-traefik" not in samples


def test_container_mapping_accepts_real_compose_names_without_prefix_collisions(metrics_home):
    metrics, _, _ = metrics_home
    projects = {
        "metrics-example": "metrics.example",
        "metrics-example-org": "metrics.example.org",
    }

    assert metrics._container_domain("metrics-example-app", projects) == "metrics.example"
    assert metrics._container_domain("metrics-example-app-1", projects) == "metrics.example"
    assert metrics._container_domain("metrics-example-org-app", projects) == "metrics.example.org"
    assert metrics._container_domain("metrics-example-org-app-1", projects) == "metrics.example.org"
    assert metrics._container_domain("wpfy-traefik", projects) is None


def test_range_bounds_rows_and_rejects_unknown_ranges(metrics_home, monkeypatch):
    metrics, _, _ = metrics_home
    monkeypatch.setattr(metrics.time, "time", lambda: 10_000)
    metrics.sample_once()
    with sqlite3.connect(metrics.metrics_db_path()) as connection:
        connection.executemany(
            "INSERT INTO samples VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                (10_000 - 120 * 60, metrics.HOST_SCOPE, 42.0, 1, 2, 3, 4, 0.5),
                (10_000 - 10 * 60, metrics.HOST_SCOPE, 43.0, 1, 2, 3, 4, 0.5),
            ),
        )

    narrow = metrics.read_samples(metrics.HOST_SCOPE, "30m")
    wide = metrics.read_samples(metrics.HOST_SCOPE, "3h")

    assert 43.0 in [sample.cpu_percent for sample in narrow]
    assert 42.0 not in [sample.cpu_percent for sample in narrow]
    assert 42.0 in [sample.cpu_percent for sample in wide]
    with pytest.raises(ValueError, match="unknown metrics range"):
        metrics.read_samples(metrics.HOST_SCOPE, "99y")


def test_prune_uses_retention_cutoff_and_timestamp_index(metrics_home, monkeypatch):
    metrics, _, _ = metrics_home
    now = 2_000_000
    monkeypatch.setattr(metrics.time, "time", lambda: now)
    metrics.sample_once()
    cutoff = now - metrics.RETENTION_DAYS * 86400
    with sqlite3.connect(metrics.metrics_db_path()) as connection:
        connection.executemany(
            "INSERT INTO samples VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                (cutoff - 1, metrics.HOST_SCOPE, 42.0, 1, 2, 3, 4, 0.5),
                (cutoff, metrics.HOST_SCOPE, 43.0, 1, 2, 3, 4, 0.5),
            ),
        )

    assert metrics.prune(now=now) == 1
    assert 42.0 not in [sample.cpu_percent for sample in metrics.read_samples(metrics.HOST_SCOPE, "24h")]
    with sqlite3.connect(metrics.metrics_db_path()) as connection:
        indexes = {row[1] for row in connection.execute("PRAGMA index_list(samples)")}
    assert "idx_samples_timestamp" in indexes
    assert "idx_samples_scope_timestamp" in indexes


def test_metrics_cli_samples_shows_and_prunes(metrics_home, capsys):
    from wpfy import cli

    metrics, _, _ = metrics_home

    assert cli.run(["metrics", "sample"]) == 0
    assert cli.run(["metrics", "show", "--scope", "metrics.example", "--range", "1h"]) == 0
    assert cli.run(["metrics", "prune"]) == 0

    output = capsys.readouterr().out
    assert "=== metrics sample ===" in output
    assert "scope=metrics.example cpu=5.00%" in output
    assert "scope=metrics.example range=1h" in output
    assert "metrics prune: deleted 0 row(s)" in output
    assert metrics.metrics_db_path().exists()


def test_missing_proc_and_docker_degrade_without_raising(tmp_wpfy_home, tmp_path, monkeypatch):
    import wpfy.metrics

    metrics = importlib.reload(wpfy.metrics)
    monkeypatch.setenv("WPFY_TEST_PROC_DIR", str(tmp_path / "missing-proc"))
    monkeypatch.setattr(metrics.shutil, "which", lambda command: None)
    monkeypatch.setattr(metrics.time, "sleep", lambda seconds: None)

    result = metrics.sample_once()

    assert [sample.scope for sample in result.samples] == [metrics.HOST_SCOPE]
    assert result.warnings
