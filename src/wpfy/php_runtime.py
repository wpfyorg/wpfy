"""PHP-FPM runtime configuration and pool sizing."""
from __future__ import annotations

import os
from pathlib import Path

from .image_references import PHP_IMAGE_REPOSITORY, PHP_IMAGE_REFERENCES, php_image

SUPPORTED_PHP_VERSIONS = tuple(PHP_IMAGE_REFERENCES)
DEFAULT_PHP_VERSION = "8.4"

# --- FPM capacity sizing ---------------------------------------------------
#
# The upstream php:*-fpm image ships a development pool (www.conf) whose
# pm.max_children=5 was never meant for production and was never overridden by
# wpfy. Size the pool and the app container from the host instead of constants.
# See runcloud-audit/perf/FPM-SIZING-PLAN.md.

#: Observed RSS in MiB of a loaded WordPress worker (WP + Elementor + ~15 plugins).
WORKER_RSS_MB = 96

#: How many workers' worth of memory may be mapped per CPU core when RAM allows.
CPU_OVERSUBSCRIBE = 4


def host_memory_total_bytes(proc_dir: str | os.PathLike[str] | None = None) -> int | None:
    """Total host RAM in bytes from /proc/meminfo, or None when unreadable.

    Non-Linux dev hosts have no /proc/meminfo; sizing then falls back to a
    512m host-wide app allowance instead of failing site creation.
    WPFY_TEST_PROC_DIR redirects the read for offline tests, mirroring
    metrics.py.
    """
    root = Path(proc_dir or os.environ.get("WPFY_TEST_PROC_DIR") or "/proc")
    try:
        text = root.joinpath("meminfo").read_text(encoding="utf-8")
    except OSError:
        return None
    for line in text.splitlines():
        key, separator, remainder = line.partition(":")
        if not separator or key != "MemTotal":
            continue
        fields = remainder.split()
        if not fields:
            return None
        try:
            value = int(fields[0])
        except ValueError:
            return None
        if len(fields) > 1 and fields[1].lower() == "kb":
            value *= 1024
        return value if value > 0 else None
    return None


def app_resources(
    cpu_count: int | None = None,
    mem_total_bytes: int | None = None,
) -> tuple[int, str, str]:
    """Derive the app service's worker count, memory limit, and CPU quota.

    Sizing is per host, not per site. Like every other per-site limit wpfy
    emits (db 768m, redis 256m, web 256m), ``mem_limit`` is a cap rather than
    a reservation, so it is deliberately overcommitted across sites; with
    ``pm = ondemand`` an idle site holds no workers at all. ``cpus`` is a CFS
    quota, not a reservation, so granting the full host costs nothing and the
    scheduler still shares fairly under contention.

    Host inputs are injectable by position or keyword so tests can pin the
    shape; when omitted, CPU count comes from os.cpu_count() and RAM from
    /proc/meminfo via host_memory_total_bytes().

    Returns (max_children, mem_limit, cpus), e.g. (8, "768m", "2.00") on a
    2-core host with 2468 MiB of RAM.
    """
    host_cpus = max(1, cpu_count or os.cpu_count() or 1)
    if mem_total_bytes is None:
        mem_total_bytes = host_memory_total_bytes()
    if mem_total_bytes and mem_total_bytes > 0:
        ram_mb = mem_total_bytes // (1024 * 1024)
        app_mem = max(512, min(WORKER_RSS_MB * CPU_OVERSUBSCRIBE * host_cpus, int(ram_mb * 0.40)))
    else:
        app_mem = 512
    children = app_mem // WORKER_RSS_MB
    return children, f"{app_mem}m", f"{host_cpus}.00"


def fpm_pool_content(max_children: int) -> str:
    """Render the generated FPM pool override for the site's app service.

    Re-opens the upstream [www] section: php-fpm merges same-named sections and
    later files win, so the generated override (sorted after www.conf) replaces
    the image's development defaults without touching the image.
    """
    return "\n".join([
        "[www]",
        "pm = ondemand",
        f"pm.max_children = {max_children}",
        "pm.process_idle_timeout = 10s",
        "pm.max_requests = 500",
        "",
    ])
