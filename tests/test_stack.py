from __future__ import annotations

from pathlib import Path

from wpfy import stack
from wpfy.site_runtime import RuntimeResult


class Proc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_install_all_uses_one_pull_contract_and_keeps_going(monkeypatch):
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        if command[-1] == "mariadb:11.4":
            return Proc(7, stderr="registry unavailable")
        return Proc(stdout="pulled")

    monkeypatch.setattr(stack.traefik, "start_traefik", lambda: RuntimeResult(0, "started", ran=True))
    monkeypatch.setattr(stack.subprocess, "run", run)

    result = stack.install(stack.StackInstallRequest(install_all=True))

    assert [fact.name for fact in result.facts] == ["Traefik", "PHP 8.4", "MariaDB", "Redis"]
    assert result.exit_code == 7
    assert [command[-1] for command in calls] == [
        "ghcr.io/wpfyorg/php-fpm:8.4",
        "mariadb:11.4",
        "redis:7.2-alpine",
    ]


def test_install_wpcli_reuses_selected_default_php(monkeypatch):
    calls = []
    monkeypatch.setattr(stack.subprocess, "run", lambda command, **kwargs: calls.append(command) or Proc())

    result = stack.install(stack.StackInstallRequest(php_version="8.4", wpcli=True))

    assert len(calls) == 1
    assert result.facts[-1].message == "using ghcr.io/wpfyorg/php-fpm:8.4 (bundled)"


def test_install_reports_traefik_and_helper_failures(monkeypatch):
    monkeypatch.setattr(stack.traefik, "start_traefik", lambda: RuntimeResult(5, "start failed", ran=True))
    monkeypatch.setattr(stack.subprocess, "run", lambda *args, **kwargs: Proc(7, stderr="pull failed"))

    result = stack.install(stack.StackInstallRequest(nginx=True, helpers=("adminer",)))

    assert [fact.exit_code for fact in result.facts] == [5, 7]
    assert result.exit_code == 7


def test_install_reports_nothing_when_no_component_selected():
    assert stack.install(stack.StackInstallRequest()).facts == ()


def test_purge_requires_force_without_runtime_call(monkeypatch):
    monkeypatch.setattr(stack.traefik, "stop_traefik", lambda: (_ for _ in ()).throw(AssertionError("must not run")))

    result = stack.purge(force=False)

    assert result.exit_code == 2
    assert result.facts[0].message == "--force is required"


def test_purge_stop_failure_blocks_teardown(monkeypatch):
    monkeypatch.setattr(stack.traefik, "stop_traefik", lambda: RuntimeResult(9, "stop failed", ran=True))
    monkeypatch.setattr(
        stack.subprocess,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("must not run")),
    )

    result = stack.purge(force=True)

    assert result.exit_code == 9
    assert [fact.name for fact in result.facts] == ["Traefik"]


def test_purge_propagates_teardown_failure(monkeypatch, tmp_path):
    compose_file = tmp_path / "compose.yaml"
    compose_file.touch()
    monkeypatch.setattr(stack.traefik, "stop_traefik", lambda: RuntimeResult(0, "stopped", ran=True))
    monkeypatch.setattr(stack.traefik, "traefik_compose_path", lambda: compose_file)
    monkeypatch.setattr(stack.traefik, "traefik_dir", lambda: tmp_path)
    monkeypatch.setattr(stack.subprocess, "run", lambda *args, **kwargs: Proc(11, stderr="volume busy"))

    result = stack.purge(force=True)

    assert result.exit_code == 11
    assert result.facts[-1] == stack.StackFact("compose project", "FAIL", "volume busy", 11)


def test_purge_structures_teardown_exception(monkeypatch, tmp_path):
    compose_file = tmp_path / "compose.yaml"
    compose_file.touch()
    monkeypatch.setattr(stack.traefik, "stop_traefik", lambda: RuntimeResult(0, "stopped", ran=True))
    monkeypatch.setattr(stack.traefik, "traefik_compose_path", lambda: compose_file)
    monkeypatch.setattr(stack.traefik, "traefik_dir", lambda: tmp_path)
    monkeypatch.setattr(stack.subprocess, "run", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("missing")))

    result = stack.purge(force=True)

    assert result.exit_code == 1
    assert result.facts[-1].status == "FAIL"


def test_upgrade_stops_after_pull_failure(monkeypatch):
    calls = []
    monkeypatch.setattr(stack.traefik, "traefik_compose_path", lambda: Path("/tmp/compose.yaml"))
    monkeypatch.setattr(stack.traefik, "traefik_dir", lambda: Path("/tmp"))
    monkeypatch.setattr(Path, "exists", lambda self: True)
    monkeypatch.setattr(
        stack.subprocess,
        "run",
        lambda command, **kwargs: calls.append(command) or Proc(6, stderr="pull failed"),
    )

    result = stack.upgrade()

    assert result.exit_code == 6
    assert len(calls) == 1


def test_upgrade_reports_missing_install(monkeypatch, tmp_path):
    monkeypatch.setattr(stack.traefik, "traefik_compose_path", lambda: tmp_path / "missing.yaml")

    result = stack.upgrade()

    assert result.exit_code == 2


def test_upgrade_reports_restart_failure_and_exception(monkeypatch):
    monkeypatch.setattr(stack.traefik, "traefik_compose_path", lambda: Path("/tmp/compose.yaml"))
    monkeypatch.setattr(stack.traefik, "traefik_dir", lambda: Path("/tmp"))
    monkeypatch.setattr(Path, "exists", lambda self: True)
    responses = iter((Proc(), Proc(9, stderr="restart failed")))
    monkeypatch.setattr(stack.subprocess, "run", lambda *args, **kwargs: next(responses))

    failed = stack.upgrade()
    monkeypatch.setattr(stack.subprocess, "run", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("missing")))
    errored = stack.upgrade()

    assert failed.exit_code == 9
    assert errored.exit_code == 1


def test_status_returns_structured_facts(monkeypatch):
    responses = iter((Proc(stdout="27.0\n"), Proc(stdout="ghcr.io/wpfyorg/php-fpm:8.4\n")))
    monkeypatch.setattr(stack.traefik, "traefik_status", lambda: RuntimeResult(0, "running", ran=True))
    monkeypatch.setattr(stack.subprocess, "run", lambda *args, **kwargs: next(responses))

    result = stack.status()

    assert result.docker_version == "27.0"
    assert result.images == ("ghcr.io/wpfyorg/php-fpm:8.4",)
    assert result.exit_code == 0


def test_status_preserves_component_failures(monkeypatch):
    responses = iter((Proc(3, stderr="daemon down"), Proc(4, stderr="images failed")))
    monkeypatch.setattr(stack.traefik, "traefik_status", lambda: RuntimeResult(5, "stopped", ran=True))
    monkeypatch.setattr(stack.subprocess, "run", lambda *args, **kwargs: next(responses))

    result = stack.status()

    assert result.exit_code == 5
    assert result.docker_error == "daemon down"
    assert result.images_error == "images failed"
