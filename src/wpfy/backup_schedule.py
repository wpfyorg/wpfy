from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from . import systemd
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


def service_path() -> Path:
    return systemd.systemd_dir() / SERVICE_NAME


def timer_path() -> Path:
    return systemd.systemd_dir() / TIMER_NAME


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
    return systemd.install_units(
        {
            service_path(): _service_content(schedule),
            timer_path(): _timer_content(schedule),
        },
        [TIMER_NAME],
        _schedule_message(schedule),
    )


def disable_schedule() -> RuntimeResult:
    return systemd.disable_units(
        [TIMER_NAME],
        [timer_path(), service_path()],
        "schedule: disabled",
    )


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
        f"ExecStart={systemd.command_line(command)}",
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
