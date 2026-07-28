from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import os
import shutil
import stat
import subprocess
from typing import Final

from . import metrics, site_cron, systemd
from .site_definition import WORDPRESS_FLAVORS
from .site_layout import list_sites
from .site_runtime import RuntimeResult, app_health_ok, runtime_skip_requested, site_health, wp_cli_command


def _current_paths():
    from .settings import PATHS as current_paths

    return current_paths


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


def cron_log_path() -> Path:
    return Path(_current_paths().log_dir) / LOG_NAME


def custom_hook_path(interval: str) -> Path:
    return Path(_current_paths().config_dir) / "custom" / "cron" / f"{interval}.sh"


def install_timers() -> RuntimeResult:
    units: dict[Path, str] = {}
    for interval in INTERVALS:
        units[service_path(interval)] = _service_content(interval)
        units[timer_path(interval)] = _timer_content(interval)
    return systemd.install_units(
        units,
        timer_names(),
        f"cron timers installed: {', '.join(INTERVALS)}",
    )


def disable_timers() -> RuntimeResult:
    paths = [path for interval in INTERVALS for path in (timer_path(interval), service_path(interval))]
    return systemd.disable_units(timer_names(), paths, "cron timers disabled")


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
    return systemd.systemd_dir() / f"wpfy-cron-{interval}.service"


def timer_path(interval: str) -> Path:
    return systemd.systemd_dir() / f"wpfy-cron-{interval}.timer"


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


def _run_site_cron(lines: list[str]) -> int:
    result = site_cron.run_due(datetime.now().replace(second=0, microsecond=0))
    if not result.jobs:
        lines.append("site cron: no jobs due")
        return 0
    for job in result.jobs:
        identifier = job.job_id or "unknown"
        lines.append(
            f"{job.domain}: cron {identifier} {job.outcome.upper()} duration={job.duration:.3f}s"
        )
    return result.exit_code


def _sample_metrics(lines: list[str]) -> int:
    try:
        result = metrics.sample_once()
    except Exception as exc:
        lines.append(f"metrics sample: FAIL {exc}")
        return 1
    lines.append(f"metrics sample: OK {len(result.samples)} scope(s)")
    for warning in result.warnings:
        lines.append(f"metrics sample: WARN {warning}")
    return 0


def _prune_metrics(lines: list[str]) -> int:
    try:
        deleted = metrics.prune()
    except Exception as exc:
        lines.append(f"metrics prune: FAIL {exc}")
        return 1
    lines.append(f"metrics prune: OK deleted={deleted}")
    return 0


def _run_interval_tasks(interval: str, lines: list[str]) -> int:
    match interval:
        case "minute":
            exit_code = _run_site_cron(lines)
            return max(exit_code, _sample_metrics(lines))
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
            exit_code = max(exit_code, _prune_metrics(lines))
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
        ok = app_health_ok(result.status, result.bootstrap_ready, result.runtime_ready)
        status = "OK" if ok is True else "WARN" if ok is None else "FAIL"
        if ok is False:
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
    probe = Path(_current_paths().install_root)
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    usage = shutil.disk_usage(probe)
    used_percent = (usage.used / usage.total) * 100 if usage.total else 0
    return f"disk health: {used_percent:.1f}% used at {_current_paths().install_root}"


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
        f"ExecStart={systemd.command_line(['/usr/local/bin/wpfy', 'cron', interval])}",
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
