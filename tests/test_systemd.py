from __future__ import annotations

from wpfy import systemd


class Proc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_command_line_quotes_shell_arguments():
    assert systemd.command_line(["wpfy", "backup", "--path", "/backups with space"]) == (
        "wpfy backup --path '/backups with space'"
    )


def test_install_units_writes_then_reloads_then_enables(tmp_path, monkeypatch):
    root = tmp_path / "systemd"
    monkeypatch.setenv("WPFY_SYSTEMD_DIR", str(root))
    commands = []
    monkeypatch.setattr(
        systemd.subprocess,
        "run",
        lambda command, **kwargs: commands.append(command) or Proc(),
    )

    result = systemd.install_units({root / "owned.timer": "timer\n"}, ["owned.timer"], "installed")

    assert result.exit_code == 0
    assert (root / "owned.timer").read_text(encoding="utf-8") == "timer\n"
    assert commands == [
        ["systemctl", "daemon-reload"],
        ["systemctl", "enable", "--now", "owned.timer"],
    ]


def test_install_units_stops_after_reload_failure(tmp_path, monkeypatch):
    root = tmp_path / "systemd"
    monkeypatch.setenv("WPFY_SYSTEMD_DIR", str(root))
    commands = []
    monkeypatch.setattr(
        systemd.subprocess,
        "run",
        lambda command, **kwargs: commands.append(command) or Proc(5, stderr="reload failed"),
    )

    result = systemd.install_units({root / "owned.timer": "timer\n"}, ["owned.timer"], "installed")

    assert result.exit_code == 5
    assert result.message == "reload failed"
    assert commands == [["systemctl", "daemon-reload"]]


def test_install_units_shapes_write_failure(tmp_path, monkeypatch):
    root = tmp_path / "systemd"
    root.write_text("not a directory", encoding="utf-8")
    monkeypatch.setenv("WPFY_SYSTEMD_DIR", str(root))
    monkeypatch.setattr(systemd.subprocess, "run", lambda command, **kwargs: (_ for _ in ()).throw(AssertionError))

    result = systemd.install_units({root / "owned.timer": "timer\n"}, ["owned.timer"], "installed")

    assert result.exit_code == 1


def test_install_units_propagates_enable_failure(tmp_path, monkeypatch):
    root = tmp_path / "systemd"
    monkeypatch.setenv("WPFY_SYSTEMD_DIR", str(root))
    commands = []

    def run(command, **kwargs):
        commands.append(command)
        return Proc() if len(commands) == 1 else Proc(6, stderr="enable failed")

    monkeypatch.setattr(systemd.subprocess, "run", run)

    result = systemd.install_units({root / "owned.timer": "timer\n"}, ["owned.timer"], "installed")

    assert result.exit_code == 6
    assert result.message == "enable failed"


def test_disable_failure_keeps_owned_files(tmp_path, monkeypatch):
    owned = tmp_path / "owned.timer"
    owned.write_text("timer\n", encoding="utf-8")
    monkeypatch.setattr(systemd.subprocess, "run", lambda command, **kwargs: Proc(4, stderr="disable failed"))

    result = systemd.disable_units(["owned.timer"], [owned], "disabled")

    assert result.exit_code == 4
    assert owned.exists()


def test_disable_removes_only_owned_paths_then_reloads(tmp_path, monkeypatch):
    owned = tmp_path / "owned.timer"
    other = tmp_path / "other.timer"
    owned.write_text("timer\n", encoding="utf-8")
    other.write_text("other\n", encoding="utf-8")
    commands = []
    monkeypatch.setattr(
        systemd.subprocess,
        "run",
        lambda command, **kwargs: commands.append(command) or Proc(),
    )

    result = systemd.disable_units(["owned.timer"], [owned], "disabled")

    assert result.exit_code == 0
    assert not owned.exists()
    assert other.exists()
    assert commands == [
        ["systemctl", "disable", "--now", "owned.timer"],
        ["systemctl", "daemon-reload"],
    ]


def test_disable_shapes_unlink_failure_without_reload(tmp_path, monkeypatch):
    owned = tmp_path / "owned.timer"
    owned.mkdir()
    commands = []
    monkeypatch.setattr(
        systemd.subprocess,
        "run",
        lambda command, **kwargs: commands.append(command) or Proc(),
    )

    result = systemd.disable_units(["owned.timer"], [owned], "disabled")

    assert result.exit_code == 1
    assert commands == [["systemctl", "disable", "--now", "owned.timer"]]


def test_disable_propagates_final_reload_failure_after_cleanup(tmp_path, monkeypatch):
    owned = tmp_path / "owned.timer"
    owned.write_text("timer\n", encoding="utf-8")
    commands = []

    def run(command, **kwargs):
        commands.append(command)
        return Proc() if len(commands) == 1 else Proc(7, stderr="final reload failed")

    monkeypatch.setattr(systemd.subprocess, "run", run)

    result = systemd.disable_units(["owned.timer"], [owned], "disabled")

    assert result.exit_code == 7
    assert not owned.exists()


def test_missing_systemctl_returns_failure(monkeypatch):
    def missing(command, **kwargs):
        raise FileNotFoundError

    monkeypatch.setattr(systemd.subprocess, "run", missing)

    assert systemd.run_systemctl(["systemctl", "daemon-reload"]).message == "systemctl not found"
