"""System metrics collection and storage."""
from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import time
from typing import Final

from . import settings
from .site_layout import list_sites
from .site_paths import domain_to_project


RANGES: Final = ("30m", "1h", "3h", "6h", "12h", "24h")
RETENTION_DAYS: Final = 14
HOST_SCOPE: Final = "host"
DOCKER_STATS_TIMEOUT: Final = 15
_KNOWN_SERVICES: Final = ("web", "app", "db", "redis", "sftp", "adminer", "wpcli")

_RANGE_SECONDS: Final = {
    "30m": 30 * 60,
    "1h": 60 * 60,
    "3h": 3 * 60 * 60,
    "6h": 6 * 60 * 60,
    "12h": 12 * 60 * 60,
    "24h": 24 * 60 * 60,
}
_SIZE_PATTERN = re.compile(r"^([0-9]+(?:\.[0-9]+)?)\s*([kmgt]?i?b)$", re.IGNORECASE)
_SIZE_MULTIPLIERS: Final = {
    "b": 1,
    "kb": 1000,
    "kib": 1024,
    "mb": 1000**2,
    "mib": 1024**2,
    "gb": 1000**3,
    "gib": 1024**3,
    "tb": 1000**4,
    "tib": 1024**4,
}


@dataclass(frozen=True, slots=True)
class Sample:
    """Single metrics sample."""
    timestamp: int
    scope: str
    cpu_percent: float
    memory_used: int
    memory_total: int
    disk_used: int
    disk_total: int
    load1: float


@dataclass(frozen=True, slots=True)
class SampleRun:
    """Metrics sampling run."""
    samples: tuple[Sample, ...]
    warnings: tuple[str, ...] = ()


@dataclass
class _SiteTotals:
    cpu_percent: float = 0.0
    memory_used: int = 0
    memory_total: int = 0


def metrics_db_path() -> Path:
    """Return metrics db path."""
    return Path(settings.PATHS.state_dir) / "metrics.sqlite3"


def sample_once() -> SampleRun:
    """Sample once."""
    warnings: list[str] = []
    timestamp = int(time.time())
    load1 = _load1()
    disk_used, disk_total = _disk_usage(Path(settings.PATHS.install_root))

    try:
        cpu_percent = _host_cpu_percent()
    except (OSError, ValueError) as exc:
        cpu_percent = 0.0
        warnings.append(f"host CPU unavailable: {exc}")

    try:
        memory_used, memory_total = _host_memory()
    except (OSError, ValueError) as exc:
        memory_used, memory_total = _portable_memory()
        warnings.append(f"host memory unavailable: {exc}")

    samples = [Sample(
        timestamp,
        HOST_SCOPE,
        cpu_percent,
        memory_used,
        memory_total,
        disk_used,
        disk_total,
        load1,
    )]

    site_totals, docker_warning = _site_totals()
    if docker_warning:
        warnings.append(docker_warning)
    for domain in sorted(site_totals):
        totals = site_totals[domain]
        site_disk_used, site_disk_total = _disk_usage(Path(settings.PATHS.sites_dir) / domain)
        samples.append(Sample(
            timestamp,
            domain,
            totals.cpu_percent,
            totals.memory_used,
            totals.memory_total,
            site_disk_used,
            site_disk_total,
            load1,
        ))

    _insert_samples(samples)
    return SampleRun(tuple(samples), tuple(warnings))


def read_samples(scope: str, range_key: str) -> tuple[Sample, ...]:
    """Read samples."""
    try:
        seconds = _RANGE_SECONDS[range_key]
    except KeyError as exc:
        raise ValueError(f"unknown metrics range: {range_key}") from exc

    path = metrics_db_path()
    if not path.exists():
        return ()
    cutoff = int(time.time()) - seconds
    with closing(_connect()) as connection, connection:
        rows = connection.execute(
            "SELECT timestamp, scope, cpu_percent, memory_used, memory_total, "
            "disk_used, disk_total, load1 FROM samples "
            "WHERE scope = ? AND timestamp >= ? ORDER BY timestamp ASC",
            (scope, cutoff),
        ).fetchall()
    return tuple(Sample(*row) for row in rows)


def latest_samples(max_age_seconds: int = 900) -> tuple[Sample, ...]:
    """The newest sample for every scope, in one query.

    The services view needs a current reading for the host and for each site at
    once. Asking `read_samples` per scope is one round trip per site, so a host
    with twenty sites pays twenty queries to render one page.

    Samples older than `max_age_seconds` are dropped rather than returned stale:
    a site whose containers stopped keeps its last sample forever, and a reading
    from yesterday presented as current is worse than no reading at all.
    """
    path = metrics_db_path()
    if not path.exists():
        return ()
    cutoff = int(time.time()) - max(0, int(max_age_seconds))
    with closing(_connect()) as connection, connection:
        rows = connection.execute(
            "SELECT s.timestamp, s.scope, s.cpu_percent, s.memory_used, s.memory_total, "
            "s.disk_used, s.disk_total, s.load1 FROM samples AS s "
            "JOIN (SELECT scope, MAX(timestamp) AS ts FROM samples GROUP BY scope) AS newest "
            "ON s.scope = newest.scope AND s.timestamp = newest.ts "
            "WHERE s.timestamp >= ? ORDER BY s.scope ASC",
            (cutoff,),
        ).fetchall()
    return tuple(Sample(*row) for row in rows)


def prune(retention_days: int = RETENTION_DAYS, *, now: int | None = None) -> int:
    """Prune."""
    if retention_days < 0:
        raise ValueError("retention_days must not be negative")
    path = metrics_db_path()
    if not path.exists():
        return 0
    cutoff = (int(time.time()) if now is None else int(now)) - retention_days * 86400
    with closing(_connect()) as connection, connection:
        cursor = connection.execute("DELETE FROM samples WHERE timestamp < ?", (cutoff,))
    return max(cursor.rowcount, 0)


def _connect() -> sqlite3.Connection:
    path = metrics_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=10)
    try:
        connection.execute("PRAGMA busy_timeout = 10000")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = NORMAL")
        connection.execute(
            "CREATE TABLE IF NOT EXISTS samples ("
            "timestamp INTEGER NOT NULL, "
            "scope TEXT NOT NULL, "
            "cpu_percent REAL NOT NULL, "
            "memory_used INTEGER NOT NULL, "
            "memory_total INTEGER NOT NULL, "
            "disk_used INTEGER NOT NULL, "
            "disk_total INTEGER NOT NULL, "
            "load1 REAL NOT NULL"
            ")"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_samples_scope_timestamp ON samples (scope, timestamp)"
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_samples_timestamp ON samples (timestamp)")
        connection.commit()
        path.chmod(0o600)
        return connection
    except Exception:
        connection.close()
        raise


def _insert_samples(samples: list[Sample]) -> None:
    with closing(_connect()) as connection, connection:
        connection.executemany(
            "INSERT INTO samples (timestamp, scope, cpu_percent, memory_used, memory_total, "
            "disk_used, disk_total, load1) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    sample.timestamp,
                    sample.scope,
                    sample.cpu_percent,
                    sample.memory_used,
                    sample.memory_total,
                    sample.disk_used,
                    sample.disk_total,
                    sample.load1,
                )
                for sample in samples
            ],
        )


def _proc_dir() -> Path:
    return Path(os.environ.get("WPFY_TEST_PROC_DIR", "/proc"))


def _cpu_totals() -> tuple[int, int]:
    line = _proc_dir().joinpath("stat").read_text(encoding="utf-8").splitlines()[0]
    fields = line.split()
    if not fields or fields[0] != "cpu" or len(fields) < 5:
        raise ValueError("invalid /proc/stat CPU row")
    values = [int(value) for value in fields[1:]]
    total = sum(values)
    idle = values[3] + (values[4] if len(values) > 4 else 0)
    return total, idle


def _host_cpu_percent() -> float:
    first_total, first_idle = _cpu_totals()
    time.sleep(0.25)
    second_total, second_idle = _cpu_totals()
    total_delta = second_total - first_total
    if total_delta <= 0:
        return 0.0
    idle_delta = max(second_idle - first_idle, 0)
    percent = ((total_delta - idle_delta) / total_delta) * 100
    return min(max(percent, 0.0), 100.0)


def _host_memory() -> tuple[int, int]:
    values: dict[str, int] = {}
    for line in _proc_dir().joinpath("meminfo").read_text(encoding="utf-8").splitlines():
        key, separator, remainder = line.partition(":")
        if not separator:
            continue
        fields = remainder.split()
        if not fields:
            continue
        multiplier = 1024 if len(fields) > 1 and fields[1].lower() == "kb" else 1
        values[key] = int(fields[0]) * multiplier
    total = values.get("MemTotal", 0)
    available = values.get("MemAvailable")
    if available is None:
        available = sum(values.get(key, 0) for key in ("MemFree", "Buffers", "Cached"))
    if total <= 0:
        raise ValueError("MemTotal missing from /proc/meminfo")
    return max(total - available, 0), total


def _portable_memory() -> tuple[int, int]:
    try:
        page_size = int(os.sysconf("SC_PAGE_SIZE"))
        pages = int(os.sysconf("SC_PHYS_PAGES"))
    except (AttributeError, OSError, ValueError):
        return 0, 0
    return 0, max(page_size * pages, 0)


def _load1() -> float:
    try:
        value = float(os.getloadavg()[0])
    except OSError:
        return 0.0
    return value if math.isfinite(value) and value >= 0 else 0.0


def _disk_usage(path: Path) -> tuple[int, int]:
    probe = path
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    usage = shutil.disk_usage(probe)
    return int(usage.used), int(usage.total)


def _site_totals() -> tuple[dict[str, _SiteTotals], str | None]:
    projects = {
        domain_to_project(domain): domain
        for domain in (str(site.get("domain", "")) for site in list_sites())
        if domain
    }
    if not projects:
        return {}, None
    docker = shutil.which("docker")
    if not docker:
        return {}, "Docker unavailable; per-site metrics skipped"
    try:
        proc = subprocess.run(
            [docker, "stats", "--no-stream", "--format", "json"],
            check=False,
            capture_output=True,
            text=True,
            timeout=DOCKER_STATS_TIMEOUT,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {}, f"Docker stats unavailable: {exc}"
    if proc.returncode != 0:
        message = proc.stderr.strip() or proc.stdout.strip() or f"exit {proc.returncode}"
        return {}, f"Docker stats failed: {message}"

    totals: dict[str, _SiteTotals] = {}
    for line in proc.stdout.splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        domain = _container_domain(str(row.get("Name", "")), projects)
        if domain is None:
            continue
        try:
            cpu_percent = _parse_percent(str(row.get("CPUPerc", "0")))
            memory_used, memory_total = _parse_memory_usage(str(row.get("MemUsage", "0B / 0B")))
        except ValueError:
            continue
        aggregate = totals.setdefault(domain, _SiteTotals())
        aggregate.cpu_percent += cpu_percent
        aggregate.memory_used += memory_used
        aggregate.memory_total += memory_total
    return totals, None


def _container_domain(name: str, projects: dict[str, str]) -> str | None:
    for project, domain in projects.items():
        for service in _KNOWN_SERVICES:
            exact_name = f"{project}-{service}"
            if name == exact_name or re.fullmatch(rf"{re.escape(exact_name)}-\d+", name):
                return domain
    return None


def _parse_percent(value: str) -> float:
    percent = float(value.strip().removesuffix("%") or "0")
    if not math.isfinite(percent):
        raise ValueError("non-finite percentage")
    return max(percent, 0.0)


def _parse_memory_usage(value: str) -> tuple[int, int]:
    used, separator, total = value.partition("/")
    if not separator:
        raise ValueError("invalid Docker memory usage")
    return _parse_size(used), _parse_size(total)


def _parse_size(value: str) -> int:
    match = _SIZE_PATTERN.fullmatch(value.strip())
    if match is None:
        raise ValueError(f"invalid size: {value}")
    number, unit = match.groups()
    return int(float(number) * _SIZE_MULTIPLIERS[unit.lower()])
