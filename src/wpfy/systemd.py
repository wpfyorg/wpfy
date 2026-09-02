"""Systemd unit installation and management."""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
import os
from pathlib import Path
import shlex
import subprocess

from .site_runtime import RuntimeResult


def systemd_dir() -> Path:
    """Return systemd directory."""
    return Path(os.environ.get("WPFY_SYSTEMD_DIR", "/etc/systemd/system"))


def command_line(command: Sequence[str]) -> str:
    """Command line."""
    return " ".join(shlex.quote(part) for part in command)


def run_systemctl(command: list[str]) -> RuntimeResult:
    """Run systemctl."""
    try:
        proc = subprocess.run(command, check=False, capture_output=True, text=True)
    except FileNotFoundError:
        return RuntimeResult(1, "systemctl not found")
    if proc.returncode != 0:
        message = proc.stderr.strip() or proc.stdout.strip() or f"{command[0]} failed"
        return RuntimeResult(proc.returncode, message)
    return RuntimeResult(0, "ok", ran=True)


def install_units(units: Mapping[Path, str], timer_names: Sequence[str], success_message: str) -> RuntimeResult:
    """Install units."""
    if os.environ.get("WPFY_SKIP_RUNTIME") == "1":
        return RuntimeResult(0, "skipped by WPFY_SKIP_RUNTIME", skipped=True)
    try:
        systemd_dir().mkdir(parents=True, exist_ok=True)
        for path, content in units.items():
            path.write_text(content, encoding="utf-8")
    except OSError as exc:
        return RuntimeResult(1, str(exc))
    for command in (["systemctl", "daemon-reload"], ["systemctl", "enable", "--now", *timer_names]):
        result = run_systemctl(command)
        if result.exit_code != 0:
            return result
    return RuntimeResult(0, success_message, ran=True)


def disable_units(timer_names: Sequence[str], owned_paths: Iterable[Path], success_message: str) -> RuntimeResult:
    """Disable units."""
    result = run_systemctl(["systemctl", "disable", "--now", *timer_names])
    if result.exit_code != 0:
        return result
    try:
        for path in owned_paths:
            path.unlink(missing_ok=True)
    except OSError as exc:
        return RuntimeResult(1, str(exc))
    reload_result = run_systemctl(["systemctl", "daemon-reload"])
    if reload_result.exit_code != 0:
        return reload_result
    return RuntimeResult(0, success_message, ran=True)
