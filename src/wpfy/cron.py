from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
import shlex
import shutil
import stat
import subprocess
from typing import Final

from .settings import PATHS
from .site_definition import WORDPRESS_FLAVORS
from .site_layout import RuntimeResult, list_sites, runtime_skip_requested, site_health, wp_cli_command


INTERVALS: Final = ("minute", "five-minute", "hourly", "six-hour", "daily", "weekly")
TIMER_CALENDARS: Final = {
    "minute": "*-*-* *:*:00",
    "five-minute": "*-*-* *:0/5:00",
    "hourly": "*-*-* *:00:00",
    "six-hour": "*-*-* 0/6:00:00",
    "daily": "*-*-* 03:10:00",
    "weekly": "Sun *-*-* 03:40:00",
}
LOG_NAME: Final = "cron.log"


@dataclass(frozen=True, slots=True)
class CronRun:
    interval: str
    lines: tuple[str, ...]
    exit_code: int = 0


def systemd_dir() -> Path:
    return Path(os.environ.get("WPFY_SYSTEMD_DIR", "/etc/systemd/system"))


def cron_log_path() -> Path:
    return Path(PATHS.log_dir) / LOG_NAME


def custom_hook_path(interval: str) -> Path:
    return Path(PATHS.config_dir) / "custom" / "cron" / f"{interval}.sh"


def install_timers() -> RuntimeResult:
    root = systemd_dir()
    root.mkdir(parents=True, exist_ok=True)
    for interval in INTERVALS:
        service_path(interval).write_text(_service_content(interval), encoding="utf-8")
        timer_path(interval).write_text(_timer_content(interval), encoding="utf-8")
    for command in (["systemctl", "daemon-reload"], ["systemctl", "enable", "--now", *timer_names()]):
        result = _run_systemctl(command)
        if result.exit_code != 0:
            return result
    return RuntimeResult(0, f"cron timers installed: {', '.join(INTERVALS)}", ran=True)


def disable_timers() -> RuntimeResult:
    result = _run_systemctl(["systemctl", "disable", "--now", *timer_names()])
    if result.exit_code != 0:
        return result
    for interval in INTERVALS:
        for path in (timer_path(interval), service_path(interval)):
            if path.exists():
                path.unlink()
    reload_result = _run_systemctl(["systemctl", "daemon-reload"])
    if reload_result.exit_code != 0:
        return reload_result
    return RuntimeResult(0, "cron timers disabled", ran=True)


def timers_status() -> RuntimeResult:
    configured = [interval for interval in INTERVALS if timer_path(interval).exists()]
    if not configured:
        return RuntimeResult(2, "cron timers not configured")
    return RuntimeResult(0, f"cron timers configured: {', '.join(configured)}", ran=True)


def run_interval(interval: str) -> CronRun:
    if interval not in INTERVALS:
        return CronRun(interval, (f"invalid cron interval: {interval}",), exit_code=2)

    lines = [f"cron {interval}: start"]
    exit_code = _run_wordpress_cron(lines)
    exit_code = max(exit_code, _run_interval_tasks(interval, lines))
    exit_code = max(exit_code, _run_custom_hook(interval, lines))
    lines.append(f"cron {interval}: done")
    _append_cron_log(lines)
    return CronRun(interval, tuple(lines), exit_code=exit_code)


def read_cron_log(lines: int) -> RuntimeResult:
    path = cron_log_path()
    if not path.exists():
        return RuntimeResult(2, f"cron log not found: {path}")
    content = path.read_text(encoding="utf-8").splitlines()
    selected = content[-lines:] if lines > 0 else content
    return RuntimeResult(0, "\n".join(selected), ran=True)


def service_path(interval: str) -> Path:
    return systemd_dir() / f"wpfy-cron-{interval}.service"


def timer_path(interval: str) -> Path:
    return systemd_dir() / f"wpfy-cron-{interval}.timer"


def timer_names() -> list[str]:
    return [f"wpfy-cron-{interval}.timer" for interval in INTERVALS]


def _run_wordpress_cron(lines: list[str]) -> int:
    sites = sorted(
        (site for site in list_sites() if str(site.get("flavor", "")) in WORDPRESS_FLAVORS),
        key=lambda site: str(site.get("domain", "")),
    )
    if not sites:
        lines.append("wordpress cron: no managed WordPress sites")
        return 0
    if runtime_skip_requested():
        lines.append("wordpress cron: skipped by WPFY_SKIP_RUNTIME=1")
        return 0
    if shutil.which("docker") is None:
        lines.append("wordpress cron: skipped because Docker is unavailable")
        return 0

    exit_code = 0
    for site in sites:
        domain = str(site.get("domain", ""))
        proc = wp_cli_command(domain, "cron", "event", "run", "--due-now", "--allow-root")
        if proc.returncode == 0:
            lines.append(f"{domain}: wp cron OK")
            continue
        exit_code = 1
        message = proc.stderr.strip() or proc.stdout.strip() or "wp cron failed"
        lines.append(f"{domain}: wp cron FAIL {message}")
    return exit_code


def _run_interval_tasks(interval: str, lines: list[str]) -> int:
    match interval:
        case "minute":
            return 0
        case "five-minute":
            lines.append(_load_health_line())
            return 0
        case "hourly":
            lines.append(_disk_health_line())
            return 0
        case "six-hour":
            lines.append("six-hour: no built-in host mutation tasks")
            return 0
        case "daily":
            exit_code = _append_all_site_health(lines)
            _rotate_cron_log()
            lines.append("cron log rotation: OK")
            return exit_code
        case "weekly":
            lines.append("update check: run `wpfy update --check` manually for release details")
            return 0
        case unreachable:
            raise AssertionError(f"unreachable interval: {unreachable}")


def _run_custom_hook(interval: str, lines: list[str]) -> int:
    path = custom_hook_path(interval)
    if not path.exists():
        return 0
    if not _is_safe_hook(path):
        lines.append(f"custom hook: refused unsafe hook {path}")
        return 1
    proc = subprocess.run([str(path)], check=False, capture_output=True, text=True)
    output = "\n".join(part for part in (proc.stdout.strip(), proc.stderr.strip()) if part)
    if proc.returncode == 0:
        lines.append(f"custom hook: OK {path}")
        if output:
            lines.append(output)
        return 0
    lines.append(f"custom hook: FAIL {path} exit {proc.returncode}")
    if output:
        lines.append(output)
    return 1


def _is_safe_hook(path: Path) -> bool:
    try:
        mode = path.stat().st_mode
    except OSError:
        return False
    return stat.S_ISREG(mode) and os.access(path, os.X_OK) and not bool(mode & stat.S_IWOTH)


def _append_all_site_health(lines: list[str]) -> int:
    exit_code = 0
    sites = sorted(list_sites(), key=lambda site: str(site.get("domain", "")))
    if not sites:
        lines.append("site health: no managed sites")
        return 0
    for site in sites:
        domain = str(site.get("domain", ""))
        result = site_health(domain)
        status = "OK" if result.exit_code == 0 else "FAIL"
        if result.exit_code != 0:
            exit_code = 1
        lines.append(f"{domain}: health {status} {result.message}")
    return exit_code


def _load_health_line() -> str:
    try:
        load_1, _, _ = os.getloadavg()
    except OSError:
        return "load health: unavailable"
    return f"load health: 1m={load_1:.2f}"


def _disk_health_line() -> str:
    probe = Path(PATHS.install_root)
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    usage = shutil.disk_usage(probe)
    used_percent = (usage.used / usage.total) * 100 if usage.total else 0
    return f"disk health: {used_percent:.1f}% used at {PATHS.install_root}"


def _append_cron_log(lines: list[str]) -> None:
    path = cron_log_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        for line in lines:
            handle.write(f"{line}\n")


def _rotate_cron_log() -> None:
    path = cron_log_path()
    if not path.exists() or path.stat().st_size <= 1024 * 1024:
        return
    rotated = path.with_suffix(".log.1")
    if rotated.exists():
        rotated.unlink()
    path.rename(rotated)


def _service_content(interval: str) -> str:
    return "\n".join([
        "[Unit]",
        f"Description=wpfy cron {interval}",
        "",
        "[Service]",
        "Type=oneshot",
        f"ExecStart={_command_line(['/usr/local/bin/wpfy', 'cron', interval])}",
        "",
    ])


def _timer_content(interval: str) -> str:
    return "\n".join([
        "[Unit]",
        f"Description=Run wpfy cron {interval}",
        "",
        "[Timer]",
        f"OnCalendar={TIMER_CALENDARS[interval]}",
        "Persistent=true",
        "",
        "[Install]",
        "WantedBy=timers.target",
        "",
    ])


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
