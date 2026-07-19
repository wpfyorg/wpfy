from __future__ import annotations

from pathlib import Path

from wpfy import site_runtime as runtime


class Proc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _runtime_ready(monkeypatch):
    monkeypatch.setattr(runtime, "runtime_skip_requested", lambda: False)
    monkeypatch.setattr(runtime, "docker_available", lambda: True)
    monkeypatch.setattr(runtime, "site_dir", lambda domain: Path("/tmp/site"))


def test_site_logs_capture_and_follow_modes(monkeypatch):
    _runtime_ready(monkeypatch)
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return Proc(stdout="logs\n")

    monkeypatch.setattr(runtime.subprocess, "run", run)

    captured = runtime.site_logs("example.com", services=("web",), lines=25, no_color=True)
    followed = runtime.site_logs("example.com", services=("app",), follow=True)

    assert captured.stdout == "logs\n"
    assert calls[0][0] == ["docker", "compose", "logs", "--tail", "25", "--no-color", "web"]
    assert calls[0][1]["capture_output"] is True
    assert calls[1][0][-2:] == ["--follow", "app"]
    assert calls[1][1]["capture_output"] is False
    assert followed.ran is True


def test_site_logs_rejects_unknown_service():
    try:
        runtime.site_logs("example.com", services=("shell",))
    except ValueError as exc:
        assert str(exc) == "unknown log service: shell"
    else:
        raise AssertionError("unknown service accepted")


def test_site_logs_unavailable_and_nonzero_modes(monkeypatch):
    monkeypatch.setattr(runtime, "runtime_skip_requested", lambda: True)
    unavailable = runtime.site_logs("example.com")
    _runtime_ready(monkeypatch)
    monkeypatch.setattr(runtime.subprocess, "run", lambda *args, **kwargs: Proc(6, stderr="logs failed"))

    captured = runtime.site_logs("example.com")
    followed = runtime.site_logs("example.com", follow=True)

    assert unavailable.skipped is True
    assert captured.exit_code == 6
    assert captured.stderr == "logs failed"
    assert followed.exit_code == 6


def test_log_reset_failure_gates_restart(monkeypatch):
    calls = []
    monkeypatch.setattr(
        runtime,
        "stop_site_runtime",
        lambda domain: calls.append("stop") or runtime.RuntimeResult(8, "failed", ran=True),
    )
    monkeypatch.setattr(
        runtime,
        "start_site_runtime",
        lambda domain: calls.append("start") or runtime.RuntimeResult(0, "started", ran=True),
    )

    result = runtime.reset_site_logs("example.com")

    assert calls == ["stop"]
    assert result.exit_code == 8


def test_log_reset_skipped_stop_is_not_success(monkeypatch):
    monkeypatch.setattr(
        runtime,
        "stop_site_runtime",
        lambda domain: runtime.RuntimeResult(0, "skipped", skipped=True),
    )

    assert runtime.reset_site_logs("example.com").exit_code == 1


def test_log_reset_propagates_restart_failure(monkeypatch):
    monkeypatch.setattr(runtime, "stop_site_runtime", lambda domain: runtime.RuntimeResult(0, "stopped", ran=True))
    monkeypatch.setattr(
        runtime,
        "start_site_runtime",
        lambda domain: runtime.RuntimeResult(7, "restart failed", ran=True),
    )

    result = runtime.reset_site_logs("example.com")

    assert result.exit_code == 7


def test_wait_for_service_skips_without_compose(monkeypatch):
    monkeypatch.setattr(runtime, "runtime_skip_requested", lambda: True)
    monkeypatch.setattr(
        runtime,
        "_compose_service_health",
        lambda *args: (_ for _ in ()).throw(AssertionError("must not run")),
    )

    result = runtime.wait_for_service("example.com", "db")

    assert result.skipped is True
    assert result.exit_code == 0


def test_container_healths_batches_ids_and_maps_failures(monkeypatch):
    calls = []
    monkeypatch.setattr(runtime.shutil, "which", lambda command: "/usr/bin/docker")
    monkeypatch.setattr(
        runtime.subprocess,
        "run",
        lambda command, **kwargs: calls.append(command) or Proc(stdout="healthy\nrunning\n"),
    )

    assert runtime._container_healths(["web-id", "app-id"]) == ["healthy", "running"]
    assert calls == [[
        "/usr/bin/docker",
        "inspect",
        "--format",
        "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}",
        "web-id",
        "app-id",
    ]]

    monkeypatch.setattr(runtime.subprocess, "run", lambda *args, **kwargs: Proc(1, stderr="failed"))
    assert runtime._container_healths(["web-id", "app-id"]) == ["unknown", "unknown"]

    monkeypatch.setattr(runtime.subprocess, "run", lambda *args, **kwargs: Proc(stdout="healthy\n"))
    assert runtime._container_healths(["web-id", "app-id"]) == ["unknown", "unknown"]


def test_container_healths_empty_ids_skips_inspect(monkeypatch):
    monkeypatch.setattr(
        runtime.subprocess,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("inspect must not run")),
    )

    assert runtime._container_healths([]) == []


def test_wait_for_service_batches_each_poll(monkeypatch):
    _runtime_ready(monkeypatch)
    calls = []
    monkeypatch.setattr(runtime, "_compose_service_ids", lambda domain, service: ["db-1", "db-2"])
    monkeypatch.setattr(
        runtime,
        "_container_healths",
        lambda container_ids: calls.append(container_ids) or ["healthy", "healthy"],
    )

    result = runtime.wait_for_service("example.com", "db", timeout_seconds=1)

    assert result.exit_code == 0
    assert calls == [["db-1", "db-2"]]


def test_wp_modes_share_command_and_deduplicate_allow_root(monkeypatch):
    _runtime_ready(monkeypatch)
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return Proc(stdout="ok\n")

    monkeypatch.setattr(runtime.subprocess, "run", run)

    captured = runtime.run_wp_cli("example.com", "core", "version", "--allow-root", "--allow-root")
    interactive = runtime.run_wp_cli("example.com", "option", "list", interactive=True)

    assert captured.stdout == "ok\n"
    assert calls[0][0].count("--allow-root") == 1
    assert "-T" in calls[0][0]
    assert calls[0][1]["capture_output"] is True
    assert calls[1][0].count("--allow-root") == 1
    assert "-T" not in calls[1][0]
    assert calls[1][1]["capture_output"] is False
    assert interactive.ran is True


def test_wp_exception_is_structured(monkeypatch):
    _runtime_ready(monkeypatch)
    monkeypatch.setattr(
        runtime.subprocess,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("docker missing")),
    )

    result = runtime.run_wp_cli("example.com", "core", "version")

    assert result.exit_code == 1
    assert result.stderr == "docker missing"


def test_wp_nonzero_is_preserved(monkeypatch):
    _runtime_ready(monkeypatch)
    monkeypatch.setattr(runtime.subprocess, "run", lambda *args, **kwargs: Proc(13, stderr="wp failed"))

    result = runtime.run_wp_cli("example.com", "core", "version")

    assert result.ran is True
    assert result.exit_code == 13
    assert result.stderr == "wp failed"
