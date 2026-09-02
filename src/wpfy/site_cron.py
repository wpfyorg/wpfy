"""WordPress cron job execution and scheduling."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import time
from typing import Final

from . import events, settings
from .site_definition import SiteDefinition
from .site_layout import list_sites
from .site_paths import domain_to_project, env_path, read_env, site_dir, site_exists, validate_domain
from .site_runtime import compose_command, docker_available, runtime_skip_requested


DEFAULT_TIMEOUT: Final = 300
MAX_TIMEOUT: Final = 86_400
_TIMEOUT_KILL_GRACE: Final = 5
_PROCESS_GROUP_KILL_GRACE: Final = 2
_HOST_EXEC_START_GRACE: Final = 15
_HOST_TIMEOUT_GRACE: Final = 5
_RUNTIME_PROBE_TIMEOUT: Final = 10
_TIMEOUT_SUPERVISOR: Final = (
    'command=$1; kill_grace=$2; marker=$3; child=""; '
    'on_timeout() { trap - TERM; if [ -n "$child" ]; then '
    'kill -TERM -- "-$child" 2>/dev/null || true; sleep "$kill_grace"; '
    'kill -KILL -- "-$child" 2>/dev/null || true; wait "$child" 2>/dev/null || true; fi; '
    'printf "%s\\n" "$marker" >&2; exit 200; }; '
    'trap on_timeout TERM; setsid sh -lc "$command" & child=$!; '
    'wait "$child"; status=$?; trap - TERM; exit "$status"'
)
_CRON_FILENAME: Final = "cron.json"
_JOB_FIELDS: Final = frozenset({"id", "schedule", "command", "service", "enabled", "timeout"})
_JOB_ID_RE: Final = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
_FIELD_RE: Final = re.compile(r"[0-9*/,-]+")
_NUMBER_RE: Final = re.compile(r"[0-9]+")
_FIELD_LIMITS: Final = (
    (0, 59),
    (0, 23),
    (1, 31),
    (1, 12),
    (0, 7),
)


@dataclass(frozen=True, slots=True)
class CronJobRun:
    """Cron job execution run."""
    domain: str
    job_id: str | None
    outcome: str
    message: str
    duration: float
    exit_code: int = 0
    ran: bool = False
    skipped: bool = False


@dataclass(frozen=True, slots=True)
class CronDueRun:
    """Cron due jobs run."""
    moment: datetime
    jobs: tuple[CronJobRun, ...]

    @property
    def exit_code(self) -> int:
        """Return exit code."""
        return 1 if any(job.exit_code != 0 for job in self.jobs) else 0


def _site_root(domain: str) -> Path:
    validate_domain(domain)
    if not site_exists(domain):
        raise ValueError(f"site not found: {domain}")
    return site_dir(domain)


def _field_values(field: str, minimum: int, maximum: int, *, weekday: bool = False) -> frozenset[int]:
    if not _FIELD_RE.fullmatch(field):
        raise ValueError(f"invalid cron field: {field!r}")

    values: set[int] = set()
    for item in field.split(","):
        if not item:
            raise ValueError(f"invalid cron field: {field!r}")

        step = 1
        base = item
        if "/" in item:
            if item.count("/") != 1:
                raise ValueError(f"invalid cron step: {item!r}")
            base, step_text = item.split("/", 1)
            if not _NUMBER_RE.fullmatch(step_text):
                raise ValueError(f"invalid cron step: {item!r}")
            step = int(step_text)
            if step <= 0:
                raise ValueError(f"invalid cron step: {item!r}")
            if base != "*" and "-" not in base:
                raise ValueError(f"cron steps require * or a range: {item!r}")

        if base == "*":
            start, end = minimum, maximum
        elif "-" in base:
            if base.count("-") != 1:
                raise ValueError(f"invalid cron range: {item!r}")
            start_text, end_text = base.split("-", 1)
            if not _NUMBER_RE.fullmatch(start_text) or not _NUMBER_RE.fullmatch(end_text):
                raise ValueError(f"invalid cron range: {item!r}")
            start, end = int(start_text), int(end_text)
            if start > end:
                raise ValueError(f"inverted cron range: {item!r}")
        else:
            if not _NUMBER_RE.fullmatch(base):
                raise ValueError(f"invalid cron value: {item!r}")
            start = end = int(base)

        if start < minimum or end > maximum:
            raise ValueError(f"cron value out of range: {item!r}")
        selected = range(start, end + 1, step)
        if weekday:
            values.update(0 if value == 7 else value for value in selected)
        else:
            values.update(selected)

    return frozenset(values)


def _parse_schedule(schedule: str) -> tuple[str, tuple[frozenset[int], ...], tuple[bool, ...]]:
    if not isinstance(schedule, str):
        raise TypeError("schedule must be a string")
    if any(character in schedule for character in "\r\n\x00"):
        raise ValueError("schedule contains an invalid control character")

    stripped = schedule.strip(" \t")
    fields = re.split(r"[ \t]+", stripped) if stripped else []
    if len(fields) != 5:
        raise ValueError("cron schedule must contain exactly five fields")

    parsed = tuple(
        _field_values(field, minimum, maximum, weekday=index == 4)
        for index, (field, (minimum, maximum)) in enumerate(zip(fields, _FIELD_LIMITS))
    )
    restricted = tuple(field != "*" for field in fields)
    return " ".join(fields), parsed, restricted


def validate_schedule(schedule: str) -> str:
    """Validate a standard five-field cron expression and normalize its spacing."""
    normalized, _, _ = _parse_schedule(schedule)
    return normalized


def schedule_matches(schedule: str, moment: datetime) -> bool:
    """Return whether ``moment`` matches ``schedule`` using traditional cron day semantics."""
    if not isinstance(moment, datetime):
        raise TypeError("moment must be a datetime")

    _, fields, restricted = _parse_schedule(schedule)
    minute, hour, day_of_month, month, day_of_week = fields
    if moment.minute not in minute or moment.hour not in hour or moment.month not in month:
        return False

    cron_weekday = (moment.weekday() + 1) % 7
    day_of_month_matches = moment.day in day_of_month
    day_of_week_matches = cron_weekday in day_of_week
    day_of_month_restricted = restricted[2]
    day_of_week_restricted = restricted[4]

    if day_of_month_restricted and day_of_week_restricted:
        return day_of_month_matches or day_of_week_matches
    if day_of_month_restricted:
        return day_of_month_matches
    if day_of_week_restricted:
        return day_of_week_matches
    return True


def allowed_services(domain: str) -> frozenset[str]:
    """Services this site actually runs — the only names a job or restart may name."""
    definition = SiteDefinition.from_env(domain, read_env(env_path(domain)))
    services = {"web", "app"}
    if definition.use_mysql:
        services.add("db")
    if definition.use_redis:
        services.add("redis")
    if definition.sftp_password:
        services.add("sftp")
    if definition.use_mysql and definition.adminer_port:
        services.add("adminer")
    return frozenset(services)


def validate_service(domain: str, service: object) -> str:
    """Validate service."""
    if not isinstance(service, str):
        raise TypeError("service must be a string")
    if service not in allowed_services(domain):
        raise ValueError(f"service is not available for this site: {service!r}")
    return service


def _validate_command(command: object) -> str:
    if not isinstance(command, str):
        raise TypeError("command must be a string")
    if not command.strip():
        raise ValueError("command must not be empty")
    if "\x00" in command:
        raise ValueError("command contains a NUL byte")
    try:
        command.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("command is not valid UTF-8") from exc
    return command


def _validate_job_id(job_id: object) -> str:
    if not isinstance(job_id, str) or not _JOB_ID_RE.fullmatch(job_id):
        raise ValueError(f"invalid cron job id: {job_id!r}")
    return job_id


def _validate_timeout(timeout: object) -> int:
    if isinstance(timeout, bool) or not isinstance(timeout, int):
        raise TypeError("timeout must be an integer")
    if not 1 <= timeout <= MAX_TIMEOUT:
        raise ValueError(f"timeout must be between 1 and {MAX_TIMEOUT} seconds")
    return timeout


def _migrate_loaded_job(job: object) -> object:
    if isinstance(job, dict) and job.get("service") == "wpcli":
        return {**job, "service": "app"}
    return job


def _normalize_job(domain: str, job: object) -> dict[str, object]:
    if not isinstance(job, dict) or set(job) != _JOB_FIELDS:
        raise ValueError("cron job must contain exactly id, schedule, command, service, enabled, and timeout")
    enabled = job["enabled"]
    if not isinstance(enabled, bool):
        raise TypeError("enabled must be a boolean")
    return {
        "id": _validate_job_id(job["id"]),
        "schedule": validate_schedule(job["schedule"]),
        "command": _validate_command(job["command"]),
        "service": validate_service(domain, job["service"]),
        "enabled": enabled,
        "timeout": _validate_timeout(job["timeout"]),
    }


def _read_cron_text(root: Path) -> str | None:
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            file_fd = os.open(_CRON_FILENAME, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=root_fd)
        except FileNotFoundError:
            return None
        with os.fdopen(file_fd, "r", encoding="utf-8") as handle:
            return handle.read()
    finally:
        os.close(root_fd)


def load_cron(domain: str) -> list[dict[str, object]]:
    """Load and validate the per-site cron job list."""
    root = _site_root(domain)
    text = _read_cron_text(root)
    if text is None:
        return []
    try:
        spec = json.loads(text)
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise ValueError(f"invalid cron state for {domain}") from exc
    if not isinstance(spec, list):
        raise ValueError("cron state must be a list")

    jobs = [_normalize_job(domain, _migrate_loaded_job(job)) for job in spec]
    job_ids = [str(job["id"]) for job in jobs]
    if len(job_ids) != len(set(job_ids)):
        raise ValueError("cron job ids must be unique")
    return jobs


def save_cron(domain: str, spec: list[dict[str, object]]) -> None:
    """Validate and atomically save the per-site cron job list."""
    root = _site_root(domain)
    if not isinstance(spec, list):
        raise TypeError("cron state must be a list")
    jobs = [_normalize_job(domain, job) for job in spec]
    job_ids = [str(job["id"]) for job in jobs]
    if len(job_ids) != len(set(job_ids)):
        raise ValueError("cron job ids must be unique")

    content = json.dumps(jobs, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    candidate = f".{_CRON_FILENAME}.{secrets.token_hex(8)}.candidate"
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        file_fd = os.open(
            candidate,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=root_fd,
        )
        try:
            with os.fdopen(file_fd, "w", encoding="utf-8") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            try:
                os.close(file_fd)
            except OSError:
                pass
            raise

        try:
            metadata = os.stat(_CRON_FILENAME, dir_fd=root_fd, follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                raise OSError("cron state is an unsafe symlink")
        except FileNotFoundError:
            pass
        os.replace(candidate, _CRON_FILENAME, src_dir_fd=root_fd, dst_dir_fd=root_fd)
        os.fsync(root_fd)
    finally:
        try:
            os.unlink(candidate, dir_fd=root_fd)
        except FileNotFoundError:
            pass
        os.close(root_fd)


def add_job(
    domain: str,
    *,
    schedule: str,
    command: str,
    service: str,
    enabled: bool = True,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, object]:
    """Add a validated job and return its persisted representation."""
    normalized_schedule = validate_schedule(schedule)
    normalized_command = _validate_command(command)
    normalized_service = validate_service(domain, service)
    if not isinstance(enabled, bool):
        raise TypeError("enabled must be a boolean")
    normalized_timeout = _validate_timeout(timeout)

    jobs = load_cron(domain)
    existing_ids = {str(job["id"]) for job in jobs}
    job_id = secrets.token_hex(6)
    while job_id in existing_ids:
        job_id = secrets.token_hex(6)
    job: dict[str, object] = {
        "id": job_id,
        "schedule": normalized_schedule,
        "command": normalized_command,
        "service": normalized_service,
        "enabled": enabled,
        "timeout": normalized_timeout,
    }
    save_cron(domain, [*jobs, job])
    return dict(job)


def remove_job(domain: str, job_id: str) -> None:
    """Remove one job by id."""
    normalized_id = _validate_job_id(job_id)
    jobs = load_cron(domain)
    remaining = [job for job in jobs if job["id"] != normalized_id]
    if len(remaining) == len(jobs):
        raise ValueError(f"cron job not found: {normalized_id}")
    save_cron(domain, remaining)


def set_enabled(domain: str, job_id: str, enabled: bool) -> None:
    """Enable or disable one job by id."""
    normalized_id = _validate_job_id(job_id)
    if not isinstance(enabled, bool):
        raise TypeError("enabled must be a boolean")
    jobs = load_cron(domain)
    updated = []
    found = False
    for job in jobs:
        if job["id"] == normalized_id:
            job = {**job, "enabled": enabled}
            found = True
        updated.append(job)
    if not found:
        raise ValueError(f"cron job not found: {normalized_id}")
    save_cron(domain, updated)


def _lock_path(domain: str, job_id: str) -> Path:
    return Path(settings.PATHS.state_dir) / "cron-locks" / domain / f"{job_id}.lock"


def _acquire_job_lock(domain: str, job_id: str) -> int | None:
    path = _lock_path(domain, job_id)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        return None
    os.ftruncate(fd, 0)
    os.write(fd, f"pid={os.getpid()} started={datetime.now(timezone.utc).isoformat()}\n".encode("utf-8"))
    os.fsync(fd)
    return fd


def _release_job_lock(fd: int) -> None:
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _record_run(job: dict[str, object], result: CronJobRun, started_at: datetime, *, actor: str) -> None:
    events.record_event(
        "site.cron.run",
        domain=result.domain,
        outcome=result.outcome,
        actor=actor,
        job_id=result.job_id,
        detail={
            "started_at": started_at.isoformat(),
            "duration_seconds": round(result.duration, 6),
            "service": job["service"],
            "command": events._redact(job["command"]),
            "message": result.message,
        },
    )


def _service_runtime_probe(domain: str, service: str) -> subprocess.CompletedProcess[str]:
    return compose_command(
        domain,
        "ps",
        "--status",
        "running",
        "-q",
        service,
        timeout=_RUNTIME_PROBE_TIMEOUT,
    )


def _execute_job(domain: str, job: dict[str, object], *, actor: str) -> CronJobRun:
    job_id = str(job["id"])
    lock_fd = _acquire_job_lock(domain, job_id)
    if lock_fd is None:
        return CronJobRun(
            domain,
            job_id,
            "skipped",
            "cron job is already running",
            0.0,
            skipped=True,
        )

    started_at = datetime.now(timezone.utc)
    started = time.monotonic()
    try:
        if runtime_skip_requested():
            result = CronJobRun(
                domain,
                job_id,
                "skipped",
                "runtime skipped by WPFY_SKIP_RUNTIME=1",
                time.monotonic() - started,
                skipped=True,
            )
        elif not docker_available():
            result = CronJobRun(
                domain,
                job_id,
                "skipped",
                "runtime skipped because Docker or Compose is unavailable",
                time.monotonic() - started,
                skipped=True,
            )
        else:
            service = str(job["service"])
            timeout = int(job["timeout"])
            timeout_marker = f"__WPFY_CRON_TIMEOUT_{secrets.token_hex(16)}__"
            try:
                proc = compose_command(
                    domain,
                    "--project-name",
                    domain_to_project(domain),
                    "exec",
                    "-T",
                    service,
                    "timeout",
                    "-k",
                    str(_TIMEOUT_KILL_GRACE),
                    str(timeout),
                    "sh",
                    "-c",
                    _TIMEOUT_SUPERVISOR,
                    "wpfy-cron",
                    str(job["command"]),
                    str(_PROCESS_GROUP_KILL_GRACE),
                    timeout_marker,
                    timeout=(
                        timeout + _HOST_EXEC_START_GRACE + _TIMEOUT_KILL_GRACE + _HOST_TIMEOUT_GRACE
                    ),
                )
            except subprocess.TimeoutExpired:
                result = CronJobRun(
                    domain,
                    job_id,
                    "timeout",
                    f"cron job exceeded {timeout} seconds",
                    time.monotonic() - started,
                    exit_code=124,
                    ran=True,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                result = CronJobRun(
                    domain,
                    job_id,
                    "failed",
                    str(exc) or "cron execution failed",
                    time.monotonic() - started,
                    exit_code=1,
                    ran=True,
                )
            else:
                stderr_lines = proc.stderr.splitlines()
                timed_out = timeout_marker in stderr_lines
                stderr = "\n".join(line for line in stderr_lines if line != timeout_marker).strip()
                message = stderr or proc.stdout.strip()
                if proc.returncode == 0:
                    result = CronJobRun(
                        domain,
                        job_id,
                        "ok",
                        message or "cron job completed",
                        time.monotonic() - started,
                        ran=True,
                    )
                elif timed_out:
                    result = CronJobRun(
                        domain,
                        job_id,
                        "timeout",
                        f"cron job exceeded {timeout} seconds",
                        time.monotonic() - started,
                        exit_code=124,
                        ran=True,
                    )
                else:
                    try:
                        runtime = _service_runtime_probe(domain, service)
                    except subprocess.TimeoutExpired:
                        runtime = None
                        runtime_error = f"runtime probe exceeded {_RUNTIME_PROBE_TIMEOUT} seconds"
                    except (OSError, subprocess.SubprocessError) as exc:
                        runtime = None
                        runtime_error = str(exc) or "runtime probe failed"

                    if runtime is None:
                        result = CronJobRun(
                            domain,
                            job_id,
                            "failed",
                            runtime_error,
                            time.monotonic() - started,
                            exit_code=proc.returncode or 1,
                            ran=True,
                        )
                    elif runtime.returncode != 0:
                        runtime_message = runtime.stderr.strip() or runtime.stdout.strip()
                        result = CronJobRun(
                            domain,
                            job_id,
                            "failed",
                            runtime_message or "runtime probe failed",
                            time.monotonic() - started,
                            exit_code=proc.returncode or 1,
                            ran=True,
                        )
                    elif not runtime.stdout.strip():
                        result = CronJobRun(
                            domain,
                            job_id,
                            "skipped",
                            f"service {service} is not running",
                            time.monotonic() - started,
                            skipped=True,
                        )
                    else:
                        result = CronJobRun(
                            domain,
                            job_id,
                            "failed",
                            message or f"cron job exited with status {proc.returncode}",
                            time.monotonic() - started,
                            exit_code=proc.returncode or 1,
                            ran=True,
                        )
        _record_run(job, result, started_at, actor=actor)
        return result
    finally:
        _release_job_lock(lock_fd)


def run_job(domain: str, job_id: str) -> CronJobRun:
    """Run one stored job immediately, ignoring its schedule and enabled state."""
    normalized_id = _validate_job_id(job_id)
    for job in load_cron(domain):
        if job["id"] == normalized_id:
            return _execute_job(domain, job, actor="cli")
    raise ValueError(f"cron job not found: {normalized_id}")


def run_due(moment: datetime) -> CronDueRun:
    """Run each enabled job matching this minute without backfilling earlier minutes."""
    if not isinstance(moment, datetime):
        raise TypeError("moment must be a datetime")

    results: list[CronJobRun] = []
    sites = sorted(list_sites(), key=lambda site: str(site.get("domain", "")))
    for site in sites:
        domain = str(site.get("domain", ""))
        try:
            jobs = load_cron(domain)
        except Exception as exc:
            results.append(CronJobRun(domain, None, "failed", str(exc), 0.0, exit_code=1))
            continue
        for job in jobs:
            if not job["enabled"] or not schedule_matches(str(job["schedule"]), moment):
                continue
            try:
                results.append(_execute_job(domain, job, actor="scheduler"))
            except Exception as exc:
                result = CronJobRun(domain, str(job["id"]), "failed", str(exc), 0.0, exit_code=1)
                _record_run(job, result, datetime.now(timezone.utc), actor="scheduler")
                results.append(result)
    return CronDueRun(moment, tuple(results))
