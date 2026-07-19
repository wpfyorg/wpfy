from __future__ import annotations

from dataclasses import dataclass

from .site_definition import SiteDefinition
from .site_layout import list_sites
from .site_paths import env_path, read_env, site_exists
from .site_runtime import compose_command, docker_available, runtime_skip_requested


@dataclass(frozen=True, slots=True)
class CacheRequest:
    domain: str | None = None
    redis: bool = False
    opcache: bool = False
    clear_all: bool = False


@dataclass(frozen=True, slots=True)
class CacheOutcome:
    domain: str
    cache: str
    status: str
    message: str


@dataclass(frozen=True, slots=True)
class CacheResult:
    outcomes: tuple[CacheOutcome, ...]
    no_sites_found: bool = False

    @property
    def exit_code(self) -> int:
        return 1 if any(outcome.status == "error" for outcome in self.outcomes) else 0


def _nginx(domain: str) -> CacheOutcome:
    if runtime_skip_requested() or not docker_available():
        return CacheOutcome(domain, "nginx", "error", "runtime unavailable (Docker/Compose not available)")
    cache_dirs = ("/var/cache/nginx/fastcgi", "/var/cache/nginx/proxy", "/var/cache/nginx/uwsgi")
    try:
        results = [
            compose_command(domain, "exec", "-T", "web", "sh", "-lc", f"rm -rf {path}/* 2>/dev/null || true")
            for path in cache_dirs
        ]
    except Exception as exc:
        return CacheOutcome(domain, "nginx", "error", f"docker exec failed: {exc}")
    if any(proc.returncode == 0 for proc in results):
        return CacheOutcome(domain, "nginx", "ok", "cache cleared")
    return CacheOutcome(domain, "nginx", "error", "docker exec failed")


def _redis(domain: str) -> CacheOutcome:
    try:
        definition = SiteDefinition.from_env(domain, read_env(env_path(domain)))
    except (OSError, ValueError) as exc:
        return CacheOutcome(domain, "redis", "error", str(exc))
    if not definition.use_redis:
        return CacheOutcome(domain, "redis", "skipped", "not enabled")
    if runtime_skip_requested() or not docker_available():
        return CacheOutcome(domain, "redis", "error", "runtime unavailable (Docker/Compose not available)")
    try:
        proc = compose_command(domain, "exec", "-T", "redis", "redis-cli", "FLUSHALL")
    except Exception as exc:
        return CacheOutcome(domain, "redis", "error", f"exec failed: {exc}")
    if proc.returncode == 0:
        return CacheOutcome(domain, "redis", "ok", "cache flushed")
    return CacheOutcome(domain, "redis", "error", "exec failed (site may be stopped)")


def _opcache(domain: str) -> CacheOutcome:
    if runtime_skip_requested() or not docker_available():
        return CacheOutcome(domain, "opcache", "error", "runtime unavailable (Docker/Compose not available)")
    try:
        proc = compose_command(domain, "exec", "-T", "app", "sh", "-lc", "kill -USR2 1")
    except Exception as exc:
        return CacheOutcome(domain, "opcache", "error", f"exec failed: {exc}")
    if proc.returncode == 0:
        return CacheOutcome(domain, "opcache", "ok", "reset")
    return CacheOutcome(domain, "opcache", "error", "exec failed (site may be stopped)")


def clear(request: CacheRequest) -> CacheResult:
    selected = ("nginx", "redis", "opcache") if request.clear_all else tuple(
        cache for cache, enabled in (
            ("redis", request.redis),
            ("opcache", request.opcache),
        ) if enabled
    ) or ("nginx",)
    sites = [request.domain] if request.domain else [str(site["domain"]) for site in list_sites()]
    if not sites:
        return CacheResult((), no_sites_found=True)

    outcomes: list[CacheOutcome] = []
    operations = {"nginx": _nginx, "redis": _redis, "opcache": _opcache}
    for domain in sites:
        if not site_exists(domain):
            outcomes.append(CacheOutcome(domain, "site", "skipped", "site not found"))
            continue
        outcomes.extend(operations[cache](domain) for cache in selected)
    return CacheResult(tuple(outcomes))
