from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import shlex
import subprocess

from .site_runtime import RuntimeResult


SERVICE_NAME = "wpfy-backup.service"
TIMER_NAME = "wpfy-backup.timer"
VALID_WEEKDAYS = {"mon", "tue", "wed", "thu", "fri", "sat", "sun"}


@dataclass(frozen=True, slots=True)
class BackupSchedule:
    cadence: str
    time: str
    destination_dir: str | None = None
    upload_s3: bool = False
    weekday: str | None = None


def systemd_dir() -> Path:
    return Path(os.environ.get("WPFY_SYSTEMD_DIR", "/etc/systemd/system"))


def service_path() -> Path:
    return systemd_dir() / SERVICE_NAME


def timer_path() -> Path:
    return systemd_dir() / TIMER_NAME


def validate_time(value: str) -> bool:
    parts = value.split(":")
    if len(parts) != 2:
        return False
    hour_text, minute_text = parts
    if not (hour_text.isdigit() and minute_text.isdigit()):
        return False
    hour = int(hour_text)
    minute = int(minute_text)
    return 0 <= hour <= 23 and 0 <= minute <= 59 and len(hour_text) == 2 and len(minute_text) == 2


def validate_weekday(value: str) -> bool:
    return value in VALID_WEEKDAYS


def install_schedule(schedule: BackupSchedule) -> RuntimeResult:
    root = systemd_dir()
    root.mkdir(parents=True, exist_ok=True)
    service_path().write_text(_service_content(schedule), encoding="utf-8")
    timer_path().write_text(_timer_content(schedule), encoding="utf-8")
    for command in (["systemctl", "daemon-reload"], ["systemctl", "enable", "--now", TIMER_NAME]):
        result = _run_systemctl(command)
        if result.exit_code != 0:
            return result
    return RuntimeResult(0, _schedule_message(schedule), ran=True)


def disable_schedule() -> RuntimeResult:
    result = _run_systemctl(["systemctl", "disable", "--now", TIMER_NAME])
    if result.exit_code != 0:
        return result
    for path in (timer_path(), service_path()):
        if path.exists():
            path.unlink()
    reload_result = _run_systemctl(["systemctl", "daemon-reload"])
    if reload_result.exit_code != 0:
        return reload_result
    return RuntimeResult(0, "schedule: disabled", ran=True)


def schedule_status() -> RuntimeResult:
    if not timer_path().exists():
        return RuntimeResult(2, "schedule: not configured")
    return RuntimeResult(0, f"schedule: configured at {timer_path()}", ran=True)


def _service_content(schedule: BackupSchedule) -> str:
    command = ["/usr/local/bin/wpfy", "backup", "all"]
    if schedule.destination_dir:
        command.extend(["--path", schedule.destination_dir])
    if schedule.upload_s3:
        command.append("--s3")
    return "\n".join([
        "[Unit]",
        "Description=wpfy backup all managed sites",
        "",
        "[Service]",
        "Type=oneshot",
        f"ExecStart={_command_line(command)}",
        "",
    ])


def _timer_content(schedule: BackupSchedule) -> str:
    return "\n".join([
        "[Unit]",
        "Description=Run wpfy backups",
        "",
        "[Timer]",
        f"OnCalendar={_on_calendar(schedule)}",
        "Persistent=true",
        "",
        "[Install]",
        "WantedBy=timers.target",
        "",
    ])


def _on_calendar(schedule: BackupSchedule) -> str:
    if schedule.cadence == "weekly":
        return f"{schedule.weekday} *-*-* {schedule.time}:00"
    return f"*-*-* {schedule.time}:00"


def _schedule_message(schedule: BackupSchedule) -> str:
    if schedule.cadence == "weekly":
        return f"schedule: enabled weekly on {schedule.weekday} at {schedule.time}"
    return f"schedule: enabled daily at {schedule.time}"


def _command_line(command: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in command)


def _run_systemctl(command: list[str]) -> RuntimeResult:
    try:
        proc = subprocess.run(command, check=False, capture_output=True, text=True)
    except FileNotFoundError:
        return RuntimeResult(1, "systemctl not found")
    if proc.returncode != 0:
        message = proc.stderr.strip() or proc.stdout.strip() or f"{command[0]} failed"
        return RuntimeResult(proc.returncode, message)
    return RuntimeResult(0, "ok", ran=True)
