from __future__ import annotations

import hmac
import ipaddress
import json
import logging
import re
import secrets
import subprocess
import threading
from dataclasses import asdict, dataclass, replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlparse

from . import __version__, events, files, metrics, operational_inspection, panel_auth, panel_jobs, panel_setup, sftp
from . import site_cache, site_cron, site_database
from . import site_configuration, site_lifecycle, site_security
from .php_runtime import DEFAULT_PHP_VERSION
from .site_definition import (
    WORDPRESS_FLAVORS,
    SiteDefinition,
    validate_object_cache,
    validate_page_cache,
)
from .site_layout import (
    backup_site,
    ensure_site_scaffold,
    generated_secret,
    get_nginx_custom,
    list_backup_archives,
    list_sites,
    restore_site,
    set_nginx_custom,
    site_info,
)
from .site_paths import app_dir, env_path, nginx_dir, read_env, site_exists, validate_domain
from .site_runtime import (
    RuntimeResult,
    list_site_services,
    restart_site_service,
    run_wp_cli,
    runtime_skip_requested,
    site_health,
    site_logs,
    start_site_runtime,
    stop_site_runtime,
)
from . import panel_exposure, traefik

DEFAULT_PANEL_PORT = 8642
STATIC_DIR = Path(__file__).parent / "panel_static"
_STATIC_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
}
_LOG_SERVICES = {"web", "app", "db", "redis", "sftp"}
_LOGGER = logging.getLogger(__name__)
_MAX_BODY_BYTES = 64 * 1024
_MAX_LOG_LINES = 2000
RUN_TOKEN_ADMIN = "run-token-admin"
_ALLOWED_PANEL_FLAVORS = frozenset({"php", "html", *WORDPRESS_FLAVORS})
_SITE_MANAGER_ALLOWED_ACTIONS = frozenset({
    "auth.me", "auth.logout", "auth.totp.enable", "auth.totp.disable",
    "site.list", "job.list", "job.read", "event.list",
})

_TRUSTED_EDGE_LOCK = threading.Lock()
_TRUSTED_EDGE_NETWORKS: tuple[str, ...] | None = None


def _address_in_networks(address: object, networks: tuple[str, ...]) -> bool:
    if not isinstance(address, str) or not networks:
        return False
    try:
        parsed = ipaddress.ip_address(address.strip())
    except ValueError:
        return False
    for raw in networks:
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            continue
        if parsed.version == network.version and parsed in network:
            return True
    return False


def resolve_client_address(peer: str, forwarded: object, trusted: tuple[str, ...]) -> str:
    """Resolve the caller that failed-login throttling should be keyed on.

    A forwarded header is believed only when the connection itself arrived from
    the known edge. Believing it unconditionally would be worse than keying on
    the proxy: any caller could then evade its own cooldown and pin one onto
    somebody else's address.

    Mirrors the site-level handling in `site_security` — trust only the edge,
    walk the chain right-to-left past our own hops (`real_ip_recursive`), and
    fail closed to the peer when no edge is known.
    """
    if not _address_in_networks(peer, trusted):
        return peer
    if not isinstance(forwarded, str):
        return peer
    for candidate in reversed(forwarded.split(",")):
        candidate = candidate.strip()
        if not candidate:
            continue
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if not _address_in_networks(candidate, trusted):
            return candidate
    return peer


def trusted_edge_networks() -> tuple[str, ...]:
    """CIDRs whose peers may assert a forwarded client address.

    Consulted on every sign-in, and discovery shells out to Docker, so a
    successful result is cached for the process. A failure is deliberately not
    cached: a transient Docker outage then degrades to the shared bucket for one
    request instead of pinning that degradation for the panel's lifetime.
    """
    global _TRUSTED_EDGE_NETWORKS
    with _TRUSTED_EDGE_LOCK:
        if _TRUSTED_EDGE_NETWORKS is not None:
            return _TRUSTED_EDGE_NETWORKS
    try:
        discovered = tuple(traefik.traefik_network_cidrs(panel_exposure.PANEL_EDGE_NETWORK))
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError):
        return ()
    with _TRUSTED_EDGE_LOCK:
        _TRUSTED_EDGE_NETWORKS = discovered
    return discovered


@dataclass(frozen=True, slots=True)
class PanelConfig:
    host: str = "127.0.0.1"
    port: int = DEFAULT_PANEL_PORT
    token: str = ""
    edge_bind: bool = False


@dataclass(frozen=True, slots=True)
class RouteMeta:
    action: str
    scope: str
    mutates: bool = False
    destructive: bool = False
    raw_body: bool = False
    max_body: int | None = None


@dataclass(frozen=True, slots=True)
class RawBody:
    stream: object
    content_length: int


@dataclass(frozen=True, slots=True)
class Route:
    method: str
    pattern: re.Pattern[str]
    handler: object
    meta: RouteMeta


class PanelError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


def generate_panel_token() -> str:
    return secrets.token_urlsafe(32)


def validate_loopback_host(host: str) -> None:
    try:
        if ipaddress.ip_address(host).is_loopback:
            return
    except ValueError:
        if host == "localhost":
            return
    raise ValueError(
        f"panel host must be a loopback address, got {host!r}; "
        "for remote access use an SSH tunnel: ssh -L <port>:127.0.0.1:<port> <server>"
    )


def _run_token_principal() -> dict[str, object]:
    return {
        "username": RUN_TOKEN_ADMIN,
        "role": panel_auth.ROLE_ADMIN,
        "sites": [],
    }


def _principal_username(principal) -> str:
    if principal == RUN_TOKEN_ADMIN:
        return RUN_TOKEN_ADMIN
    if isinstance(principal, dict) and isinstance(principal.get("username"), str):
        return principal["username"]
    return "unknown"


def _principal_is_manager(principal) -> bool:
    return isinstance(principal, dict) and principal.get("role") == panel_auth.ROLE_SITE_MANAGER


def authorize(principal, meta: RouteMeta, domain: str | None) -> None:
    if principal is None:
        raise PanelError(401, "missing or invalid token")
    if principal == RUN_TOKEN_ADMIN:
        return
    if not isinstance(principal, dict):
        raise PanelError(401, "missing or invalid token")
    if principal.get("role") == panel_auth.ROLE_ADMIN:
        return
    if not _principal_is_manager(principal):
        raise PanelError(403, "forbidden")
    if meta.action in _SITE_MANAGER_ALLOWED_ACTIONS:
        return
    if meta.scope == "site" and domain is not None and domain in set(principal.get("sites") or ()):
        return
    raise PanelError(403, "forbidden")


def _known_domain(domain: str) -> str:
    try:
        validate_domain(domain)
    except ValueError as exc:
        raise PanelError(400, str(exc))
    if not site_exists(domain):
        raise PanelError(404, f"site not found: {domain}")
    return domain


def _runtime_payload(result: RuntimeResult) -> dict:
    return {"ok": result.exit_code == 0, "exit_code": result.exit_code, "message": result.message,
            "ran": result.ran, "skipped": result.skipped}


def _operation_status(
    result, *, not_found: bool = False, nginx_validation: bool = False, skip_is_failure: bool = False,
) -> int:
    """Map an operation result to a status code.

    `skipped` does not mean the same thing everywhere. A skipped `restart` did nothing at
    all, so reporting 2xx tells the operator their containers restarted when they did not.
    A skipped `sftp rotate`, by contrast, has already written the new password to `.env`
    and only deferred the container reconcile — answering 5xx there would make the caller
    discard a one-time password that is now the site's real one. So the caller declares
    which case it is; only pure-runtime actions pass `skip_is_failure`.
    """
    if skip_is_failure and getattr(result, "skipped", False):
        return 503
    if result.exit_code == 0:
        return 200
    if result.exit_code == 2:
        return 404 if not_found else 400
    message = str(result.message).lower()
    if any(marker in message for marker in ("runtime unavailable", "runtime to be running", "docker unavailable")):
        return 503
    if nginx_validation and result.exit_code != 3:
        return 422
    return 500


def _dry_run(body: dict, changes: list[str], restarts: list[str], scope: str) -> tuple[int, dict] | None:
    if body.get("dry_run") is True:
        return 200, {"changes": changes, "restarts": restarts, "scope": scope}
    return None


def _job_payload(job: panel_jobs.Job, *, one_time: dict | None = None) -> dict:
    payload = {
        "id": job.id, "action": job.action, "domain": job.domain, "state": job.state,
        "steps": list(job.steps), "created_at": job.created_at, "result": job.result,
    }
    if one_time is not None:
        payload["one_time"] = one_time
    return payload


def _start_job(job: panel_jobs.Job, fn, *, actor: str = RUN_TOKEN_ADMIN) -> None:
    def runner() -> None:
        try:
            result, one_time = fn()
            panel_jobs.complete_job(job.id, result=result, one_time=one_time)
            events.record_event(job.action, domain=job.domain, actor=actor, job_id=job.id)
        except Exception as exc:
            message = events._redact(str(exc))
            panel_jobs.fail_job(job.id, message)
            events.record_event(job.action, domain=job.domain, outcome="failed", detail=message,
                                actor=actor, job_id=job.id)
    threading.Thread(target=runner, name=f"wpfy-panel-{job.id[:8]}", daemon=True).start()


def api_overview() -> dict:
    facts = operational_inspection.aggregate_info()
    warnings = int(facts.docker_version == "unavailable")
    if any(marker in facts.traefik_message.lower() for marker in ("unavailable", "not running", "not installed", "error")):
        warnings += 1
    return {"version": __version__, "docker_version": facts.docker_version, "traefik": facts.traefik_message,
            "site_count": len(facts.sites), "warnings": warnings}


def api_sites() -> dict:
    return {"sites": sorted(list_sites(), key=lambda site: str(site.get("domain", "")))}


def api_site_detail(domain: str) -> dict:
    _known_domain(domain)
    try:
        return {"site": site_info(domain)}
    except FileNotFoundError as exc:
        raise PanelError(404, str(exc))


def api_site_health(domain: str) -> dict:
    _known_domain(domain)
    return {"health": asdict(site_health(domain))}


def api_site_diagnostics(domain: str) -> dict:
    _known_domain(domain)
    return {"checks": [asdict(check) for check in operational_inspection.site_diagnostics(domain)]}


def api_system_diagnostics() -> dict:
    return {"checks": [asdict(check) for check in operational_inspection.system_diagnostics()]}


def api_metrics(scope: str, range_key: str) -> dict:
    if not isinstance(scope, str) or not scope:
        raise PanelError(400, "metrics scope must be a non-empty string")
    if not isinstance(range_key, str) or not range_key:
        raise PanelError(400, "metrics range is required")
    try:
        samples = metrics.read_samples(scope, range_key)
    except ValueError as exc:
        raise PanelError(400, str(exc)) from exc
    return {"scope": scope, "range": range_key, "ranges": list(metrics.RANGES),
            "samples": [asdict(sample) for sample in samples]}


def api_system_services() -> dict:
    services = [{"name": traefik.TRAEFIK_CONTAINER, "status": traefik.traefik_status().message}]
    for site in sorted(list_sites(), key=lambda item: str(item.get("domain", ""))):
        domain = str(site.get("domain", ""))
        if not domain:
            continue
        try:
            allowed = tuple(sorted(site_cron.allowed_services(domain)))
            services.extend({"name": f"{domain}:{row['name']}", "status": row["status"]}
                            for row in list_site_services(domain, allowed))
        except (OSError, TypeError, ValueError):
            continue
    return {"services": services}


def api_site_logs(domain: str, service: str, lines: int) -> dict:
    _known_domain(domain)
    if service and service not in _LOG_SERVICES:
        raise PanelError(400, f"unknown log service: {service}")
    lines = max(1, min(lines, _MAX_LOG_LINES))
    result = site_logs(domain, services=(service,) if service else (), lines=lines, no_color=True)
    output = result.stdout or result.stderr
    if result.exit_code != 0:
        raise PanelError(500, output.strip() or "docker compose logs failed")
    return {"logs": output}


def api_site_backups(domain: str) -> dict:
    _known_domain(domain)
    backups = []
    for archive in list_backup_archives(domain):
        stat = archive.stat()
        backups.append({"name": archive.name, "size_bytes": stat.st_size, "modified_at": int(stat.st_mtime)})
    return {"backups": backups}


def api_site_backup_create(domain: str) -> tuple[int, dict]:
    _known_domain(domain)
    result = backup_site(domain)
    return _operation_status(result), _runtime_payload(result)


def api_site_restore(domain: str, archive_name: str) -> tuple[int, dict]:
    _known_domain(domain)
    archive = {item.name: item for item in list_backup_archives(domain)}.get(archive_name)
    if archive is None:
        raise PanelError(404, f"backup archive not found for {domain}: {archive_name}")
    result = restore_site(domain, str(archive))
    return _operation_status(result), _runtime_payload(result)


def api_site_runtime(domain: str, action: str) -> tuple[int, dict]:
    _known_domain(domain)
    if action == "start":
        result = start_site_runtime(domain)
    elif action == "stop":
        result = stop_site_runtime(domain)
    elif action == "restart":
        stop = stop_site_runtime(domain)
        if stop.exit_code != 0:
            return _operation_status(stop, skip_is_failure=True), _runtime_payload(stop)
        result = start_site_runtime(domain)
    else:
        raise PanelError(400, f"unknown runtime action: {action}")
    return _operation_status(result, skip_is_failure=True), _runtime_payload(result)


def api_site_sftp(domain: str) -> tuple[int, dict]:
    _known_domain(domain)
    result = sftp.sftp_status(domain)
    return _operation_status(result, not_found=True), _runtime_payload(result)


def api_site_sftp_action(domain: str, action: str) -> tuple[int, dict]:
    _known_domain(domain)
    if action == "enable":
        result = sftp.ensure_sftp_container(domain)
        payload = _runtime_payload(result)
        if "\npassword (shown once):" in payload["message"]:
            payload["message"] = payload["message"].split("\npassword (shown once):", 1)[0]
        return _operation_status(result, not_found=True), payload
    elif action == "disable":
        result = sftp.remove_sftp_container(domain)
    elif action == "rotate":
        password = generated_secret()[:16]
        result = sftp.rotate_sftp_password(domain, password=password)
        payload = _runtime_payload(result)
        if result.exit_code == 0:
            payload["one_time"] = {"password": password}
        return _operation_status(result, not_found=True), payload
    else:
        raise PanelError(400, f"unknown sftp action: {action}")
    return _operation_status(result, not_found=True), _runtime_payload(result)


def api_site_wp(domain: str, wp_args: list) -> tuple[int, dict]:
    _known_domain(domain)
    if not wp_args or not all(isinstance(arg, str) and "\x00" not in arg for arg in wp_args):
        raise PanelError(400, "wp requires a non-empty list of string arguments")
    proc = run_wp_cli(domain, *wp_args)
    if not proc.ran:
        raise PanelError(500, proc.stderr.strip() or "wp-cli failed to run")
    return 200, {"ok": proc.exit_code == 0, "exit_code": proc.exit_code, "stdout": proc.stdout, "stderr": proc.stderr}


def api_site_config(domain: str, body: dict) -> tuple[int, dict]:
    _known_domain(domain)
    php_keys = {
        "php_memory_limit", "php_max_execution_time", "php_max_input_time",
        "php_max_input_vars", "php_upload_max_size", "reset_php",
    }
    allowed = {"php_version", "flavor", "letsencrypt", "password", "dry_run", *php_keys}
    if any(key not in allowed for key in body):
        raise PanelError(400, "config contains an unsupported field")
    if any(key in body for key in php_keys):
        lifecycle_keys = {"php_version", "flavor", "letsencrypt", "password"}
        if any(key in body for key in lifecycle_keys):
            raise PanelError(400, "PHP ini settings cannot be combined with other config changes")
        return api_php_settings(domain, body)
    flavor = body.get("flavor")
    if flavor is not None and (not isinstance(flavor, str) or flavor not in _ALLOWED_PANEL_FLAVORS):
        raise PanelError(400, f"unknown site flavor: {flavor}")
    for key in ("php_version", "letsencrypt", "password"):
        if body.get(key) is not None and not isinstance(body[key], str):
            raise PanelError(400, f"{key} must be a string")
    try:
        result = site_lifecycle.update_site(site_lifecycle.UpdateSiteRequest(
            domain=domain,
            php_version=body.get("php_version"),
            flavor=flavor,
            letsencrypt=body.get("letsencrypt"),
            password=body.get("password"),
            dry_run=body.get("dry_run") is True,
        ))
    except site_lifecycle.SiteLifecycleError as exc:
        raise PanelError(400, str(exc))
    if body.get("dry_run") is True:
        return 200, {"changes": list(result.changes), "restarts": [domain] if result.changes else [], "scope": "site"}
    return (200 if result.exit_code == 0 else 500), {
        "ok": result.exit_code == 0, "changes": list(result.changes), "touched": list(result.touched),
        "runtime": _runtime_payload(result.runtime),
    }


def _config_result_payload(result: site_configuration.ConfigurationResult) -> tuple[int, dict]:
    return _operation_status(result), {
        "ok": result.exit_code == 0,
        "exit_code": result.exit_code,
        "message": result.message,
        "changes": list(result.changes),
        "touched": list(result.touched),
        "runtime": _runtime_payload(result.runtime),
    }


def api_php_settings(domain: str, body: dict | None = None) -> tuple[int, dict]:
    _known_domain(domain)
    body = body or {}
    allowed = {
        "php_memory_limit", "php_max_execution_time", "php_max_input_time",
        "php_max_input_vars", "php_upload_max_size", "reset_php", "dry_run",
    }
    if any(key not in allowed for key in body):
        raise PanelError(400, "php-settings contains an unsupported field")
    for key in allowed - {"reset_php", "dry_run"}:
        if key in body and not isinstance(body[key], str):
            raise PanelError(400, f"{key} must be a string")
    if "reset_php" in body and not isinstance(body["reset_php"], bool):
        raise PanelError(400, "reset_php must be a boolean")
    if body.get("dry_run") is True:
        result = site_configuration.update_php_settings(
            domain,
            php_memory_limit=body.get("php_memory_limit"),
            php_max_execution_time=body.get("php_max_execution_time"),
            php_max_input_time=body.get("php_max_input_time"),
            php_max_input_vars=body.get("php_max_input_vars"),
            php_upload_max_size=body.get("php_upload_max_size"),
            reset=body.get("reset_php") is True,
            dry_run=True,
        )
        return _config_result_payload(result)
    try:
        result = site_configuration.update_php_settings(
            domain,
            php_memory_limit=body.get("php_memory_limit"),
            php_max_execution_time=body.get("php_max_execution_time"),
            php_max_input_time=body.get("php_max_input_time"),
            php_max_input_vars=body.get("php_max_input_vars"),
            php_upload_max_size=body.get("php_upload_max_size"),
            reset=body.get("reset_php") is True,
        )
    except ValueError as exc:
        raise PanelError(400, str(exc)) from exc
    return _config_result_payload(result)


def api_databases(domain: str) -> tuple[int, dict]:
    _known_domain(domain)
    result = site_database.list_databases(domain)
    return _operation_status(result), {
        "ok": result.exit_code == 0, "exit_code": result.exit_code,
        "databases": list(result.items), "message": result.message,
    }


def api_db_users(domain: str) -> tuple[int, dict]:
    _known_domain(domain)
    result = site_database.list_users(domain)
    return _operation_status(result), {
        "ok": result.exit_code == 0, "exit_code": result.exit_code,
        "users": list(result.items), "message": result.message,
    }


def _database_result_payload(result: site_database.DatabaseResult) -> dict:
    return {
        "ok": result.exit_code == 0,
        "exit_code": result.exit_code,
        "message": result.message,
        "items": list(result.items),
    }


def api_nginx_custom(domain: str) -> tuple[int, dict]:
    _known_domain(domain)
    result = get_nginx_custom(domain)
    if result.exit_code != 0:
        raise PanelError(_operation_status(result, not_found=True), result.message)
    return 200, {"ok": True, "content": result.message}


_PAGE_CACHE_CHOICES = (
    ("none", "None", "Free"),
    ("wpfc", "Nginx FastCGI cache", "Free"),
    ("wp-super-cache", "WP Super Cache", "Free"),
    ("w3-total-cache", "W3 Total Cache", "Free"),
    ("cache-enabler", "Cache Enabler", "Free"),
    ("wp-fastest-cache", "WP Fastest Cache", "Free"),
    ("wp-rocket", "WP Rocket", "Bring your own"),
    ("flying-press", "FlyingPress", "Bring your own"),
)


def _cache_definition(domain: str) -> SiteDefinition:
    domain = _known_domain(domain)
    definition = SiteDefinition.from_env(domain, read_env(env_path(domain)))
    if definition.flavor not in WORDPRESS_FLAVORS:
        raise PanelError(400, f"cache integration requires a WordPress site: {domain}")
    return definition


def _cache_state_payload(domain: str, definition: SiteDefinition | None = None) -> dict:
    definition = definition or _cache_definition(domain)
    upload_path = app_dir(domain) / "wp-content" / "plugins"
    selected_byo = definition.page_cache in site_cache.BYO_PAGE_CACHE_PLUGINS
    plugin_path = upload_path / definition.page_cache if selected_byo else None
    return {
        "page_cache": definition.page_cache,
        "object_cache": definition.object_cache,
        "page_cache_options": [
            {
                "value": value,
                "label": label,
                "badge": badge,
                "source": "byo" if badge == "Bring your own" else "free",
                "auto_install": badge == "Free" and value != "none",
            }
            for value, label, badge in _PAGE_CACHE_CHOICES
        ],
        "object_cache_options": [
            {"value": "none", "label": "Disabled"},
            {"value": "redis", "label": "Redis Object Cache"},
        ],
        "byo_plugin": {
            "selected": selected_byo,
            "plugin": definition.page_cache if selected_byo else None,
            "files_present": plugin_path.is_dir() if plugin_path is not None else None,
            "upload_path": str(upload_path),
        },
        "snippet_path": str(nginx_dir(domain) / "extra" / "wpfy-cache.conf"),
    }


def api_site_cache(domain: str) -> tuple[int, dict]:
    return 200, {"ok": True, **_cache_state_payload(domain)}


def _cache_changes(current: SiteDefinition, desired: SiteDefinition) -> list[str]:
    changes = []
    if current.page_cache != desired.page_cache:
        changes.append(f"page cache: {current.page_cache} -> {desired.page_cache}")
    if current.object_cache != desired.object_cache:
        changes.append(f"object cache: {current.object_cache} -> {desired.object_cache}")
    return changes


def _cache_operation_plan(desired: SiteDefinition, *, object_cache_requested: bool) -> list[dict]:
    operations = [
        {
            "operation": "install_page_cache",
            "status": "planned",
            "message": (
                f"stage {desired.page_cache}; operator upload required"
                if desired.page_cache in site_cache.BYO_PAGE_CACHE_PLUGINS
                else f"install or activate {desired.page_cache}"
            ),
        },
        {"operation": "render_cache_nginx", "status": "planned", "message": "regenerate the nginx cache snippet"},
        {"operation": "set_wp_cache_constants", "status": "planned", "message": "assert the WP_CACHE constant"},
    ]
    if desired.object_cache == "redis" or object_cache_requested:
        operations.append({
            "operation": "wire_redis_backend",
            "status": "planned",
            "message": "enable Redis object cache" if desired.object_cache == "redis" else "disable Redis object cache",
        })
    return operations


def _panel_cache_action(action: site_cache.CacheActionResult) -> site_cache.CacheActionResult:
    if (
        action.exit_code != 0
        and runtime_skip_requested()
        and "runtime unavailable" in action.message.lower()
    ):
        return site_cache.CacheActionResult(
            "deferred",
            f"{action.message}; deferred while WPFY_SKIP_RUNTIME is enabled",
        )
    return action


def _cache_action_payload(action: site_cache.CacheActionResult) -> dict:
    return {
        "status": action.status,
        "message": action.message,
        "exit_code": action.exit_code,
        "changed": action.changed,
    }


def _put_cache(principal, match, query, body):
    domain = match.group("domain")
    current = _cache_definition(domain)
    allowed = {"page_cache", "object_cache", "dry_run"}
    if any(key not in allowed for key in body):
        raise PanelError(400, "cache update contains an unsupported field")
    if "dry_run" in body and not isinstance(body["dry_run"], bool):
        raise PanelError(400, "dry_run must be a boolean")
    if "page_cache" not in body and "object_cache" not in body:
        raise PanelError(400, "cache update requires page_cache and/or object_cache")

    page_cache = body.get("page_cache", current.page_cache)
    object_cache = body.get("object_cache", current.object_cache)
    if not isinstance(page_cache, str):
        raise PanelError(400, "page_cache must be a string")
    if not isinstance(object_cache, str):
        raise PanelError(400, "object_cache must be a string")
    try:
        page_cache = validate_page_cache(page_cache)
        object_cache = validate_object_cache(object_cache)
    except ValueError as exc:
        raise PanelError(400, str(exc)) from exc
    desired = replace(
        current,
        page_cache=page_cache,
        object_cache=object_cache,
        use_redis=object_cache == "redis",
    )
    changes = _cache_changes(current, desired)
    operations = _cache_operation_plan(desired, object_cache_requested="object_cache" in body)
    if body.get("dry_run") is True:
        return 200, {
            "ok": True,
            "dry_run": True,
            "state": "preview",
            "changes": changes,
            "operations": operations,
            "restarts": [domain] if changes else [],
            "scope": "site",
            **_cache_state_payload(domain, desired),
        }

    touched = tuple(ensure_site_scaffold(desired))
    runtime = start_site_runtime(domain)
    if runtime.exit_code != 0 and not runtime.skipped:
        actions = (site_cache.CacheActionResult("error", runtime.message, runtime.exit_code),)
    else:
        ordered_actions = [
            site_cache.install_page_cache(domain, desired.page_cache),
            site_cache.render_cache_nginx(domain),
            site_cache.set_wp_cache_constants(domain),
        ]
        if desired.object_cache == "redis" or "object_cache" in body:
            ordered_actions.append(site_cache.wire_redis_backend(domain))
        actions = tuple(_panel_cache_action(action) for action in ordered_actions)

    result = site_cache.CacheConfigurationResult(desired, actions, touched)
    action_payloads = [_cache_action_payload(action) for action in result.actions]
    state = (
        "error" if result.exit_code != 0
        else "awaiting-upload" if any(action.status == "awaiting-upload" for action in result.actions)
        else "deferred" if any(action.status == "deferred" for action in result.actions)
        else "ok"
    )
    return _operation_status(result), {
        "ok": result.exit_code == 0,
        "state": state,
        "exit_code": result.exit_code,
        "message": result.message,
        "changes": changes,
        "actions": action_payloads,
        "touched": list(result.touched),
        "runtime": _runtime_payload(runtime),
        **_cache_state_payload(domain, desired),
    }


def _purge_outcome_payload(outcome) -> dict:
    status = outcome.status
    if (
        status == "error"
        and runtime_skip_requested()
        and "runtime unavailable" in outcome.message.lower()
    ):
        status = "skipped"
    return {
        "cache": outcome.cache,
        "status": status,
        "message": outcome.message,
    }


def _post_cache_purge(principal, match, query, body):
    domain = _known_domain(match.group("domain"))
    if body:
        raise PanelError(400, "cache purge does not accept request fields")
    try:
        result = site_cache.purge_site_cache(domain)
    except Exception as exc:
        raise PanelError(500, f"cache purge failed: {events._redact(str(exc))}") from exc
    outcomes = [_purge_outcome_payload(outcome) for outcome in result.outcomes]
    failed = [outcome for outcome in outcomes if outcome["status"] == "error"]
    status = 503 if failed and all("runtime unavailable" in outcome["message"].lower() for outcome in failed) else 500
    if not failed:
        status = 200
    message = "; ".join(
        f"{outcome['cache']}: {outcome['message']}" for outcome in outcomes
    ) or "no cache layers were selected"
    return status, {
        "ok": not failed,
        "state": "error" if failed else "purged",
        "exit_code": 1 if failed else 0,
        "message": message,
        "outcomes": outcomes,
    }


def _get_cache(principal, match, query, body): return api_site_cache(match.group("domain"))


def _security_state_payload(domain: str, config: dict | None = None) -> dict:
    domain = _known_domain(domain)
    config = config or site_security.load_security(domain)
    trusted_sources = list(site_security.traefik_network_cidrs())
    if site_security._cloudflare_trust_required(domain, config):
        trusted_sources.extend(site_security.cloudflare_cidrs())
    return {
        "deny_ips": list(config["deny_ips"]),
        "ua_blocks": list(config["ua_blocks"]),
        "basic_auth": dict(config["basic_auth"]),
        "cloudflare_only": config["cloudflare_only"],
        "login_rate_limit": config["login_rate_limit"],
        "snippet_path": str(nginx_dir(domain) / "extra" / site_security.SECURITY_SNIPPET),
        "rate_limit_path": str(nginx_dir(domain) / site_security.RATELIMIT_SNIPPET),
        "trusted_edge_sources": list(dict.fromkeys(trusted_sources)),
    }


def _security_changes(current: dict, desired: dict, *, basic_auth_requested: bool) -> list[str]:
    changes = []
    for cidr in sorted(set(current["deny_ips"]) - set(desired["deny_ips"])):
        changes.append(f"remove denied network {cidr}")
    for cidr in sorted(set(desired["deny_ips"]) - set(current["deny_ips"])):
        changes.append(f"deny network {cidr}")
    for pattern in sorted(set(current["ua_blocks"]) - set(desired["ua_blocks"])):
        changes.append(f"remove user-agent block {pattern}")
    for pattern in sorted(set(desired["ua_blocks"]) - set(current["ua_blocks"])):
        changes.append(f"block user-agent {pattern}")
    if basic_auth_requested:
        current_auth, desired_auth = current["basic_auth"], desired["basic_auth"]
        if current_auth != desired_auth:
            state = "enable" if desired_auth["enabled"] else "disable"
            changes.append(f"{state} basic auth")
        elif desired_auth["enabled"]:
            changes.append("rotate basic-auth password")
    if current["cloudflare_only"] != desired["cloudflare_only"]:
        state = "enable" if desired["cloudflare_only"] else "disable"
        changes.append(f"{state} Cloudflare-only access")
    if current["login_rate_limit"] != desired["login_rate_limit"]:
        state = "enable" if desired["login_rate_limit"] else "disable"
        changes.append(f"{state} WordPress login rate limit")
    return changes


def _get_security(principal, match, query, body):
    return 200, {"ok": True, "warnings": [], **_security_state_payload(match.group("domain"))}


def _put_security(principal, match, query, body):
    domain = _known_domain(match.group("domain"))
    allowed = {
        "deny_ips", "ua_blocks", "basic_auth", "cloudflare_only", "login_rate_limit",
        "dry_run", "acknowledge_warnings",
    }
    if any(key not in allowed for key in body):
        raise PanelError(400, "security update contains an unsupported field")
    for key in ("dry_run", "acknowledge_warnings"):
        if key in body and not isinstance(body[key], bool):
            raise PanelError(400, f"{key} must be a boolean")
    requested = {"deny_ips", "ua_blocks", "basic_auth", "cloudflare_only", "login_rate_limit"} & set(body)
    if not requested:
        raise PanelError(400, "security update requires at least one security field")

    current = site_security.load_security(domain)
    desired = {
        "deny_ips": body.get("deny_ips", current["deny_ips"]),
        "ua_blocks": body.get("ua_blocks", current["ua_blocks"]),
        "basic_auth": body.get("basic_auth", current["basic_auth"]),
        "cloudflare_only": body.get("cloudflare_only", current["cloudflare_only"]),
        "login_rate_limit": body.get("login_rate_limit", current["login_rate_limit"]),
    }
    basic_auth = desired["basic_auth"]
    if not isinstance(basic_auth, dict):
        raise PanelError(400, "basic_auth must be an object")
    if any(key not in {"enabled", "username", "password"} for key in basic_auth):
        raise PanelError(400, "basic_auth contains an unsupported field")
    password = basic_auth.get("password")
    if password is not None and (not isinstance(password, str) or not password):
        raise PanelError(400, "basic-auth password must be a non-empty string")
    auth_for_validation = {key: value for key, value in basic_auth.items() if key != "password"}
    if auth_for_validation.get("enabled") is False:
        auth_for_validation["username"] = None
    desired["basic_auth"] = auth_for_validation
    try:
        desired = site_security._validated_config(desired)
        enables_cloudflare_only = (
            "cloudflare_only" in body
            and desired["cloudflare_only"] is True
            and current["cloudflare_only"] is False
        )
        preflight = site_security.security_preflight(
            domain,
            {"cloudflare_only": True} if enables_cloudflare_only else {},
        )
    except (TypeError, ValueError) as exc:
        raise PanelError(400, str(exc)) from exc

    warnings = list(preflight.warnings)
    changes = _security_changes(current, desired, basic_auth_requested="basic_auth" in body)
    preview = {
        "ok": True,
        "dry_run": body.get("dry_run") is True,
        "state": "warning" if warnings else "preview",
        "changes": changes,
        "operations": [
            {"operation": "apply_security", "status": "planned", "message": change}
            for change in changes
        ],
        "warnings": warnings,
        "restarts": [domain] if changes else [],
        "scope": "site",
        **_security_state_payload(domain, desired),
    }
    if body.get("dry_run") is True or (warnings and body.get("acknowledge_warnings") is not True):
        preview["acknowledgement_required"] = bool(warnings)
        return 200, preview

    results = []
    for cidr in sorted(set(current["deny_ips"]) - set(desired["deny_ips"])):
        results.append(site_security.remove_deny_ip(domain, cidr))
    for cidr in sorted(set(desired["deny_ips"]) - set(current["deny_ips"])):
        results.append(site_security.add_deny_ip(domain, cidr))
    for pattern in sorted(set(current["ua_blocks"]) - set(desired["ua_blocks"])):
        results.append(site_security.remove_ua_block(domain, pattern))
    for pattern in sorted(set(desired["ua_blocks"]) - set(current["ua_blocks"])):
        results.append(site_security.add_ua_block(domain, pattern))
    if "basic_auth" in body:
        results.append(site_security.set_basic_auth(
            domain,
            enabled=desired["basic_auth"]["enabled"],
            username=desired["basic_auth"]["username"],
            password=password,
        ))
    if "cloudflare_only" in body and current["cloudflare_only"] != desired["cloudflare_only"]:
        results.append(site_security.set_cloudflare_only(domain, desired["cloudflare_only"]))
    if "login_rate_limit" in body and current["login_rate_limit"] != desired["login_rate_limit"]:
        results.append(site_security.set_login_rate_limit(domain, desired["login_rate_limit"]))

    failed = next((result for result in results if result.exit_code != 0), None)
    payload = {
        "ok": failed is None,
        "state": "error" if failed else "applied",
        "warnings": warnings,
        "changes": changes,
        "message": failed.message if failed else ("security configuration applied" if changes else "security configuration unchanged"),
        **_security_state_payload(domain),
    }
    generated = next((result.one_time_password for result in results if result.one_time_password), None)
    if generated and failed is None:
        payload["one_time"] = {"password": generated}
    return (500 if failed else 200), payload


def _cron_last_runs(domain: str) -> dict[str, dict]:
    latest = {}
    for event in events.list_events(limit=1000, domain=domain, action="site.cron.run"):
        job_id = event.get("job_id")
        if job_id and job_id not in latest:
            latest[str(job_id)] = {
                "timestamp": event.get("timestamp"),
                "outcome": event.get("outcome"),
                "detail": event.get("detail"),
            }
    return latest


def _get_cron(principal, match, query, body):
    domain = _known_domain(match.group("domain"))
    last_runs = _cron_last_runs(domain)
    jobs = [{**job, "last_run": last_runs.get(str(job["id"]))} for job in site_cron.load_cron(domain)]
    return 200, {"ok": True, "jobs": jobs, "services": sorted(site_cron.allowed_services(domain))}


def _post_cron(principal, match, query, body):
    domain = _known_domain(match.group("domain"))
    allowed = {"schedule", "command", "service", "timeout"}
    if any(key not in allowed for key in body):
        raise PanelError(400, "cron job contains an unsupported field")
    if "schedule" not in body or "command" not in body:
        raise PanelError(400, "cron job requires schedule and command")
    try:
        job = site_cron.add_job(
            domain,
            schedule=body["schedule"],
            command=body["command"],
            service=body.get("service", "app"),
            timeout=body.get("timeout", site_cron.DEFAULT_TIMEOUT),
        )
    except (TypeError, ValueError) as exc:
        raise PanelError(400, str(exc)) from exc
    return 201, {"ok": True, "id": job["id"], "job": job}


def _put_cron(principal, match, query, body):
    domain, job_id = _known_domain(match.group("domain")), match.group("job_id")
    if set(body) != {"enabled"} or not isinstance(body.get("enabled"), bool):
        raise PanelError(400, "cron update requires one boolean enabled field")
    try:
        site_cron.set_enabled(domain, job_id, body["enabled"])
    except (TypeError, ValueError) as exc:
        raise PanelError(400, str(exc)) from exc
    return 200, {"ok": True, "id": job_id, "enabled": body["enabled"]}


def _delete_cron(principal, match, query, body):
    domain, job_id = _known_domain(match.group("domain")), match.group("job_id")
    if body:
        raise PanelError(400, "cron deletion does not accept request fields")
    try:
        site_cron.remove_job(domain, job_id)
    except ValueError as exc:
        raise PanelError(400, str(exc)) from exc
    return 200, {"ok": True, "id": job_id, "removed": True}


def _post_cron_run(principal, match, query, body):
    domain, job_id = _known_domain(match.group("domain")), match.group("job_id")
    if body:
        raise PanelError(400, "cron run does not accept request fields")
    try:
        result = site_cron.run_job(domain, job_id)
    except ValueError as exc:
        raise PanelError(400, str(exc)) from exc
    status = 200 if result.outcome == "ok" else 503 if result.outcome == "skipped" else 500
    return status, {"ok": result.outcome == "ok", **asdict(result)}


def _get_databases(principal, match, query, body): return api_databases(match.group("domain"))


def _get_db_users(principal, match, query, body): return api_db_users(match.group("domain"))


def _get_php_settings(principal, match, query, body):
    domain = _known_domain(match.group("domain"))
    return 200, {"settings": site_configuration.php_settings(domain)}


def _get_nginx_custom(principal, match, query, body): return api_nginx_custom(match.group("domain"))


def _post_database(principal, match, query, body):
    domain = _known_domain(match.group("domain"))
    name = body.get("name")
    if not isinstance(name, str):
        raise PanelError(400, "database creation requires name")
    planned = _dry_run(body, [f"create database {name}"], [], "database")
    if planned:
        return planned
    try:
        result = site_database.create_database(domain, name)
    except ValueError as exc:
        raise PanelError(400, str(exc)) from exc
    return _operation_status(result), _database_result_payload(result)


def _delete_database(principal, match, query, body):
    domain, name = _known_domain(match.group("domain")), match.group("name")
    if body.get("confirm") != name:
        raise PanelError(400, "database deletion requires confirm to exactly match the database name")
    planned = _dry_run(body, [f"drop database {name}"], [], "database")
    if planned:
        return planned
    try:
        result = site_database.drop_database(domain, name)
    except ValueError as exc:
        raise PanelError(400, str(exc)) from exc
    return _operation_status(result), _database_result_payload(result)


def _post_db_user(principal, match, query, body):
    domain = _known_domain(match.group("domain"))
    user, password, database = body.get("user"), body.get("password"), body.get("database")
    if not isinstance(user, str):
        raise PanelError(400, "database user creation requires user")
    if password is not None and not isinstance(password, str):
        raise PanelError(400, "password must be a string")
    if database is not None and not isinstance(database, str):
        raise PanelError(400, "database must be a string")
    planned = _dry_run(body, [f"create database user {user}"], [], "database")
    if planned:
        return planned
    job = panel_jobs.create_job("site.database.user-create", domain)

    def operation():
        try:
            result = site_database.create_user(domain, user, password=password, grants=database)
        except ValueError as exc:
            raise RuntimeError(str(exc)) from exc
        if result.exit_code != 0:
            raise RuntimeError(result.message)
        return _database_result_payload(result), (
            {"password": result.one_time_password} if result.one_time_password else None
        )

    _start_job(job, operation, actor=_principal_username(principal))
    return 202, {"job_id": job.id}


def _delete_db_user(principal, match, query, body):
    domain, user = _known_domain(match.group("domain")), match.group("user")
    if body.get("confirm") != user:
        raise PanelError(400, "database user deletion requires confirm to exactly match the username")
    planned = _dry_run(body, [f"drop database user {user}"], [], "database")
    if planned:
        return planned
    try:
        result = site_database.drop_user(domain, user)
    except ValueError as exc:
        raise PanelError(400, str(exc)) from exc
    return _operation_status(result), _database_result_payload(result)


def _post_db_password(principal, match, query, body):
    domain, user = _known_domain(match.group("domain")), match.group("user")
    password = body.get("password")
    if password is not None and not isinstance(password, str):
        raise PanelError(400, "password must be a string")
    planned = _dry_run(body, [f"set database user password {user}"], [], "database")
    if planned:
        return planned
    job = panel_jobs.create_job("site.database.user-password", domain)

    def operation():
        try:
            result = site_database.set_user_password(domain, user, password=password)
        except ValueError as exc:
            raise RuntimeError(str(exc)) from exc
        if result.exit_code != 0:
            raise RuntimeError(result.message)
        return _database_result_payload(result), (
            {"password": result.one_time_password} if result.one_time_password else None
        )

    _start_job(job, operation, actor=_principal_username(principal))
    return 202, {"job_id": job.id}


def _post_adminer(principal, match, query, body):
    domain = _known_domain(match.group("domain"))
    action = body.get("action")
    if action not in {"on", "off"}:
        raise PanelError(400, "adminer action must be on or off")
    port = body.get("port")
    if port is not None and not isinstance(port, (str, int)):
        raise PanelError(400, "adminer port must be an integer")
    planned = _dry_run(body, [f"adminer {action}"], [domain], "site")
    if planned:
        return planned
    try:
        result = site_configuration.configure_adminer(domain, enabled=action == "on", port=port)
    except (ValueError, FileNotFoundError) as exc:
        raise PanelError(400, str(exc)) from exc
    return _config_result_payload(result)


def _post_php_settings(principal, match, query, body):
    return api_php_settings(match.group("domain"), body)


def _put_nginx_custom(principal, match, query, body):
    domain = _known_domain(match.group("domain"))
    content = body.get("content")
    if not isinstance(content, str):
        raise PanelError(400, "nginx custom config requires content")
    if body.get("dry_run") is True:
        return _dry_run(body, ["update nginx custom config"], [domain], "site")
    result = set_nginx_custom(domain, content)
    return _operation_status(result, nginx_validation=True), {
        "ok": result.exit_code == 0,
        "exit_code": result.exit_code,
        "nginx_test_output": result.message,
    }


def _get_setup_status(principal, match, query, body):
    return 200, panel_setup.status(edge_bind=body.get("_edge_bind") is True)


def _post_setup(principal, match, query, body):
    client = body.pop("_socket_client", None)
    edge_bind = body.pop("_edge_bind", False) is True
    try:
        token, user = panel_setup.create_account(body, client=client, edge_bind=edge_bind)
    except panel_auth.ClientThrottleError as exc:
        raise PanelError(429, str(exc)) from exc
    except ValueError as exc:
        status = 403 if edge_bind else 400
        raise PanelError(status, str(exc)) from exc
    return 201, {
        "token": token,
        "username": user["username"],
        "role": user["role"],
        "sites": user["sites"],
    }


def _post_setup_totp(principal, match, query, body):
    if not isinstance(principal, dict) or principal.get("_setup_session") is not True:
        raise PanelError(410, "setup enrollment is no longer available")
    username = principal["username"]
    action = body.get("action")
    if action == "begin":
        try:
            secret, uri = panel_auth.begin_totp_enrollment(username)
        except ValueError as exc:
            raise PanelError(409, str(exc)) from exc
        return 200, {"secret": secret, "uri": uri}
    if action == "verify":
        try:
            panel_auth.complete_totp_enrollment(username, body.get("code"))
        except ValueError as exc:
            raise PanelError(400, str(exc)) from exc
        panel_auth.finish_setup_session(principal.get("_session_token"))
        events.record_event("panel.totp.enrolled", actor=username)
        return 200, {"ok": True, "enrolled": True}
    if action == "skip":
        if body.get("confirm") is not True:
            raise PanelError(
                400,
                "confirm skipping TOTP: without a second factor this panel cannot be published to the internet",
            )
        panel_auth.cancel_totp_enrollment(username)
        panel_auth.finish_setup_session(principal.get("_session_token"))
        events.record_event("panel.totp.skipped", actor=username)
        return 200, {"ok": True, "skipped": True}
    raise PanelError(400, "setup TOTP action must be begin, verify, or skip")


def _post_auth_login(principal, match, query, body):
    client = body.get("_socket_client")
    result = panel_auth.login(body.get("username"), body.get("password"), body.get("totp"), client=client)
    if result is None:
        if panel_auth.client_throttled(client):
            raise PanelError(429, "too many failed login attempts; try again later")
        raise PanelError(401, "invalid credentials")
    token, user = result
    return 200, {
        "token": token,
        "username": user["username"],
        "role": user["role"],
        "sites": user["sites"],
    }


def _post_auth_logout(principal, match, query, body):
    panel_auth.logout(principal.get("_session_token") if isinstance(principal, dict) else None)
    return 200, {"ok": True}


def _get_auth_me(principal, match, query, body):
    return 200, {
        "username": principal["username"],
        "role": principal["role"],
        "sites": list(principal.get("sites") or []),
    }


def _post_auth_totp(principal, match, query, body):
    try:
        if "code" in body:
            panel_auth.complete_totp_enrollment(principal["username"], body.get("code"))
            return 200, {"ok": True, "enrolled": True}
        secret, uri = panel_auth.begin_totp_enrollment(principal["username"])
    except ValueError as exc:
        raise PanelError(400 if "code" in body else 409, str(exc)) from exc
    return 200, {"secret": secret, "uri": uri}


def _delete_auth_totp(principal, match, query, body):
    panel_auth.disable_totp(principal["username"])
    return 200, {"ok": True}


def _get_users(principal, match, query, body):
    return 200, {"users": panel_auth.list_users()}


def _post_user(principal, match, query, body):
    allowed = {"username", "password", "role", "sites"}
    if any(key not in allowed for key in body):
        raise PanelError(400, "user contains an unsupported field")
    try:
        panel_auth.add_user(
            body.get("username"), body.get("password"), role=body.get("role"), sites=body.get("sites", ()),
        )
    except ValueError as exc:
        raise PanelError(400, str(exc)) from exc
    return 201, {"ok": True}


def _put_user(principal, match, query, body):
    allowed = {"role", "password", "sites"}
    if not body or any(key not in allowed for key in body):
        raise PanelError(400, "user update requires role, password, and/or sites")
    try:
        panel_auth.update_user(
            unquote(match.group("username")),
            role=body.get("role"), password=body.get("password"),
            sites=body.get("sites") if "sites" in body else None,
        )
    except ValueError as exc:
        raise PanelError(400, str(exc)) from exc
    return 200, {"ok": True}


def _delete_user(principal, match, query, body):
    try:
        panel_auth.remove_user(unquote(match.group("username")))
    except ValueError as exc:
        raise PanelError(400, str(exc)) from exc
    return 200, {"ok": True}


def _delete_user_totp(principal, match, query, body):
    try:
        panel_auth.disable_totp(unquote(match.group("username")))
    except ValueError as exc:
        raise PanelError(400, str(exc)) from exc
    return 200, {"ok": True}


def _get_overview(principal, match, query, body): return 200, api_overview()
def _get_sites(principal, match, query, body):
    payload = api_sites()
    if _principal_is_manager(principal):
        assigned = set(principal.get("sites") or ())
        payload["sites"] = [site for site in payload["sites"] if site.get("domain") in assigned]
    return 200, payload
def _get_metrics(principal, match, query, body):
    scope = (query.get("scope") or [metrics.HOST_SCOPE])[0]
    range_key = (query.get("range") or [""])[0]
    return 200, api_metrics(scope, range_key)
def _get_system_services(principal, match, query, body): return 200, api_system_services()
def _get_system_diagnostics(principal, match, query, body): return 200, api_system_diagnostics()
def _post_site_service_restart(principal, match, query, body):
    domain = _known_domain(match.group("domain"))
    service = unquote(match.group("service"))
    try:
        site_cron.validate_service(domain, service)
    except (TypeError, ValueError) as exc:
        raise PanelError(400, str(exc)) from exc
    result = restart_site_service(domain, service)
    return _operation_status(result, skip_is_failure=True), _runtime_payload(result)
def _post_traefik_restart(principal, match, query, body):
    if body.get("confirm") != traefik.TRAEFIK_CONTAINER:
        raise PanelError(400, "traefik restart requires confirm to exactly match wpfy-traefik")
    result = traefik.restart_traefik_existing()
    return _operation_status(result, skip_is_failure=True), _runtime_payload(result)
def _get_site(principal, match, query, body): return 200, api_site_detail(match.group("domain"))
def _get_health(principal, match, query, body): return 200, api_site_health(match.group("domain"))
def _get_diagnostics(principal, match, query, body): return 200, api_site_diagnostics(match.group("domain"))
def _get_backups(principal, match, query, body): return 200, api_site_backups(match.group("domain"))
def _get_sftp(principal, match, query, body): return api_site_sftp(match.group("domain"))


def _get_logs(principal, match, query, body):
    try:
        lines = int((query.get("lines") or ["200"])[0])
    except ValueError:
        raise PanelError(400, "lines must be an integer")
    return 200, api_site_logs(match.group("domain"), (query.get("service") or [""])[0], lines)


def _get_jobs(principal, match, query, body):
    jobs = panel_jobs.list_jobs()
    if _principal_is_manager(principal):
        assigned = set(principal.get("sites") or ())
        jobs = [job for job in jobs if job.domain in assigned]
    return 200, {"jobs": [_job_payload(job) for job in jobs]}


def _get_job(principal, match, query, body):
    job = panel_jobs.get_job(match.group("job_id"))
    if job is None:
        raise PanelError(404, "job not found")
    if _principal_is_manager(principal) and job.domain not in set(principal.get("sites") or ()):
        raise PanelError(403, "forbidden")
    job, one_time = panel_jobs.consume_job(job.id)
    return 200, _job_payload(job, one_time=one_time)


def _get_events(principal, match, query, body):
    try:
        limit = int((query.get("limit") or ["200"])[0])
    except ValueError:
        raise PanelError(400, "limit must be an integer")
    domain = (query.get("domain") or [None])[0]
    action = (query.get("action") or [None])[0]
    listed = events.list_events(limit=limit, domain=domain, action=action)
    if _principal_is_manager(principal):
        assigned = set(principal.get("sites") or ())
        listed = [event for event in listed if event.get("domain") in assigned]
    return 200, {"events": listed}


def _post_create_site(principal, match, query, body):
    domain, flavor = body.get("domain"), body.get("flavor")
    if not isinstance(domain, str) or not domain:
        raise PanelError(400, "site creation requires a domain")
    try:
        validate_domain(domain)
    except ValueError as exc:
        raise PanelError(400, str(exc))
    if not isinstance(flavor, str) or flavor not in _ALLOWED_PANEL_FLAVORS:
        raise PanelError(400, f"unknown site flavor: {flavor}")
    planned = _dry_run(body, [f"create {domain} ({flavor})"], [domain], "site")
    if planned:
        return planned
    job = panel_jobs.create_job("site.create", domain)

    def operation():
        admin_user = body.get("admin_user") or "admin"
        admin_email = body.get("admin_email") or f"admin@{domain}"
        def credentials():
            return site_lifecycle.WordPressCredentials(admin_user, admin_email, generated_secret(), True)
        result = site_lifecycle.create_site(
            site_lifecycle.CreateSiteRequest(
                domain=domain, flavor=flavor, php_version=body.get("php_version") or DEFAULT_PHP_VERSION,
                letsencrypt=body.get("letsencrypt"), dns_provider=body.get("dns_provider"),
            ),
            credentials=credentials,
            progress=lambda step: panel_jobs.append_step(job.id, step),
        )
        payload = {"ok": result.exit_code == 0, "exit_code": result.exit_code,
                   "touched": list(result.touched), "runtime": _runtime_payload(result.runtime)}
        one_time = {"wordpress_admin_password": result.generated_password} if result.generated_password else None
        if result.exit_code != 0:
            raise RuntimeError("site creation failed")
        return payload, one_time
    _start_job(job, operation, actor=_principal_username(principal))
    return 202, {"job_id": job.id}


def _delete_site(principal, match, query, body):
    domain = match.group("domain")
    if not isinstance(body.get("confirm"), str) or body.get("confirm") != domain:
        raise PanelError(400, "delete requires confirm to exactly match the domain")
    _known_domain(domain)
    planned = _dry_run(body, [f"backup and delete {domain}"], [domain], "site")
    if planned:
        return planned
    job = panel_jobs.create_job("site.delete", domain)
    def operation():
        result = site_lifecycle.delete_site(site_lifecycle.DeleteSiteRequest(domain=domain, force=True))
        payload = {"ok": result.exit_code == 0, "exit_code": result.exit_code, "removed": result.removed,
                   "backup": _runtime_payload(result.backup), "runtime": _runtime_payload(result.runtime)}
        if result.exit_code != 0:
            raise RuntimeError("site deletion failed")
        return payload, None
    _start_job(job, operation, actor=_principal_username(principal))
    return 202, {"job_id": job.id}


def _post_backup(principal, match, query, body):
    planned = _dry_run(body, ["create backup"], [], "site")
    return planned or api_site_backup_create(match.group("domain"))


def _post_restore(principal, match, query, body):
    archive = body.get("archive")
    if not isinstance(archive, str) or not archive:
        raise PanelError(400, "restore requires an archive name")
    planned = _dry_run(body, [f"restore {archive}"], [match.group("domain")], "site")
    return planned or api_site_restore(match.group("domain"), archive)


def _post_runtime(principal, match, query, body):
    action = str(body.get("action", ""))
    planned = _dry_run(body, [f"runtime {action}"], [match.group("domain")], "site")
    return planned or api_site_runtime(match.group("domain"), action)


def _post_sftp(principal, match, query, body):
    action = str(body.get("action", ""))
    planned = _dry_run(body, [f"sftp {action}"], [match.group("domain")], "site")
    return planned or api_site_sftp_action(match.group("domain"), action)


def _file_query_path(query: dict) -> str:
    path = (query.get("path") or [""])[0]
    if not isinstance(path, str):
        raise PanelError(400, "path must be a string")
    return path


def _get_files(principal, match, query, body):
    return 200, files.list_files(_known_domain(match.group("domain")), _file_query_path(query))


def _get_file_content(principal, match, query, body):
    return 200, files.read_file(_known_domain(match.group("domain")), _file_query_path(query))


def _put_file_content(principal, match, query, body):
    domain = _known_domain(match.group("domain"))
    path, content = body.get("path"), body.get("content")
    if not isinstance(path, str) or not isinstance(content, str):
        raise PanelError(400, "file content update requires string path and content fields")
    return 200, {"ok": True, **files.write_file(domain, path, content)}


def _get_file_download(principal, match, query, body):
    return 200, files.open_download(_known_domain(match.group("domain")), _file_query_path(query))


def _post_file_upload(principal, match, query, body):
    if not isinstance(body, RawBody):
        raise PanelError(400, "upload requires a raw request body")
    result = files.upload_file(
        _known_domain(match.group("domain")), _file_query_path(query), body.stream, body.content_length,
    )
    return 201, {"ok": True, **result}


def _post_file_mkdir(principal, match, query, body):
    path = body.get("path")
    if not isinstance(path, str):
        raise PanelError(400, "directory creation requires a string path")
    return 201, {"ok": True, **files.make_directory(_known_domain(match.group("domain")), path)}


def _post_file_rename(principal, match, query, body):
    path, target = body.get("path"), body.get("to")
    if not isinstance(path, str) or not isinstance(target, str):
        raise PanelError(400, "rename requires string path and to fields")
    return 200, {"ok": True, **files.rename_path(_known_domain(match.group("domain")), path, target)}


def _post_file_chmod(principal, match, query, body):
    path, mode = body.get("path"), body.get("mode")
    if not isinstance(path, str):
        raise PanelError(400, "chmod requires a string path")
    return 200, {"ok": True, **files.chmod_path(_known_domain(match.group("domain")), path, mode)}


def _delete_file(principal, match, query, body):
    path = body.get("path")
    if not isinstance(path, str):
        raise PanelError(400, "file deletion requires a string path")
    return 200, {"ok": True, **files.delete_path(
        _known_domain(match.group("domain")), path, confirm=body.get("confirm"),
    )}


def _post_wp(principal, match, query, body): return api_site_wp(match.group("domain"), body.get("args") or [])
def _post_config(principal, match, query, body): return api_site_config(match.group("domain"), body)


_SETUP_ROUTES = (
    Route("GET", re.compile(r"^/api/setup/status$"), _get_setup_status, RouteMeta("setup.status", "setup")),
    Route("POST", re.compile(r"^/api/setup$"), _post_setup, RouteMeta("setup.create", "setup", True)),
    Route(
        "POST", re.compile(r"^/api/setup/totp$"),
        _post_setup_totp, RouteMeta("setup.totp", "setup-session", True),
    ),
)


_ROUTES = (
    Route("POST", re.compile(r"^/api/auth/login$"), _post_auth_login, RouteMeta("auth.login", "public", True)),
    Route("GET", re.compile(r"^/api/auth/me$"), _get_auth_me, RouteMeta("auth.me", "session")),
    Route("POST", re.compile(r"^/api/auth/totp$"), _post_auth_totp, RouteMeta("auth.totp.enable", "session", True)),
    Route(
        "DELETE", re.compile(r"^/api/auth/totp$"),
        _delete_auth_totp, RouteMeta("auth.totp.disable", "session", True),
    ),
    Route("GET", re.compile(r"^/api/users$"), _get_users, RouteMeta("user.list", "system")),
    Route("POST", re.compile(r"^/api/users$"), _post_user, RouteMeta("user.add", "system", True)),
    Route(
        "DELETE", re.compile(r"^/api/users/(?P<username>[^/]+)/totp$"),
        _delete_user_totp, RouteMeta("user.totp.disable", "system", True),
    ),
    Route(
        "PUT", re.compile(r"^/api/users/(?P<username>[^/]+)$"),
        _put_user, RouteMeta("user.update", "system", True),
    ),
    Route(
        "DELETE", re.compile(r"^/api/users/(?P<username>[^/]+)$"),
        _delete_user, RouteMeta("user.remove", "system", True),
    ),
    Route("GET", re.compile(r"^/api/overview$"), _get_overview, RouteMeta("system.overview", "system")),
    Route("GET", re.compile(r"^/api/sites$"), _get_sites, RouteMeta("site.list", "system")),
    Route("POST", re.compile(r"^/api/sites$"), _post_create_site, RouteMeta("site.create", "site", True)),
    Route("GET", re.compile(r"^/api/metrics$"), _get_metrics, RouteMeta("system.metrics", "system")),
    Route("GET", re.compile(r"^/api/system/services$"), _get_system_services, RouteMeta("system.services", "system")),
    Route("POST", re.compile(r"^/api/system/traefik/restart$"), _post_traefik_restart, RouteMeta("system.traefik.restart", "system", True, True)),
    Route("GET", re.compile(r"^/api/system/diagnostics$"), _get_system_diagnostics, RouteMeta("system.diagnostics", "system")),
    Route("GET", re.compile(r"^/api/jobs$"), _get_jobs, RouteMeta("job.list", "system")),
    Route("GET", re.compile(r"^/api/jobs/(?P<job_id>[^/]+)$"), _get_job, RouteMeta("job.read", "system")),
    Route("GET", re.compile(r"^/api/events$"), _get_events, RouteMeta("event.list", "system")),
    Route("DELETE", re.compile(r"^/api/sites/(?P<domain>[^/]+)$"), _delete_site, RouteMeta("site.delete", "site", True, True)),
    Route("GET", re.compile(r"^/api/sites/(?P<domain>[^/]+)$"), _get_site, RouteMeta("site.read", "site")),
    Route("GET", re.compile(r"^/api/sites/(?P<domain>[^/]+)/health$"), _get_health, RouteMeta("site.health", "site")),
    Route("GET", re.compile(r"^/api/sites/(?P<domain>[^/]+)/diagnostics$"), _get_diagnostics, RouteMeta("site.diagnostics", "site")),
    Route("GET", re.compile(r"^/api/sites/(?P<domain>[^/]+)/logs$"), _get_logs, RouteMeta("site.logs", "site")),
    Route("GET", re.compile(r"^/api/sites/(?P<domain>[^/]+)/backups$"), _get_backups, RouteMeta("site.backup.list", "site")),
    Route("GET", re.compile(r"^/api/sites/(?P<domain>[^/]+)/sftp$"), _get_sftp, RouteMeta("site.sftp.read", "site")),
    Route("GET", re.compile(r"^/api/sites/(?P<domain>[^/]+)/files$"), _get_files, RouteMeta("site.files.list", "site")),
    Route("GET", re.compile(r"^/api/sites/(?P<domain>[^/]+)/files/content$"), _get_file_content, RouteMeta("site.files.read", "site")),
    Route("GET", re.compile(r"^/api/sites/(?P<domain>[^/]+)/files/download$"), _get_file_download, RouteMeta("site.files.download", "site")),
    Route("POST", re.compile(r"^/api/sites/(?P<domain>[^/]+)/services/(?P<service>[^/]*)/restart$"), _post_site_service_restart, RouteMeta("site.service.restart", "site", True)),
    Route(
        "GET", re.compile(r"^/api/sites/(?P<domain>[^/]+)/databases$"),
        _get_databases, RouteMeta("site.database.list", "site"),
    ),
    Route(
        "GET", re.compile(r"^/api/sites/(?P<domain>[^/]+)/db-users$"),
        _get_db_users, RouteMeta("site.database.users", "site"),
    ),
    Route(
        "GET", re.compile(r"^/api/sites/(?P<domain>[^/]+)/php-settings$"),
        _get_php_settings, RouteMeta("site.php-settings.read", "site"),
    ),
    Route(
        "GET", re.compile(r"^/api/sites/(?P<domain>[^/]+)/nginx-custom$"),
        _get_nginx_custom, RouteMeta("site.nginx-custom.read", "site"),
    ),
    Route(
        "GET", re.compile(r"^/api/sites/(?P<domain>[^/]+)/cache$"),
        _get_cache, RouteMeta("site.cache.read", "site"),
    ),
    Route(
        "GET", re.compile(r"^/api/sites/(?P<domain>[^/]+)/security$"),
        _get_security, RouteMeta("site.security.read", "site"),
    ),
    Route(
        "GET", re.compile(r"^/api/sites/(?P<domain>[^/]+)/cron$"),
        _get_cron, RouteMeta("site.cron.read", "site"),
    ),
    Route("POST", re.compile(r"^/api/sites/(?P<domain>[^/]+)/backups$"), _post_backup, RouteMeta("site.backup", "site", True)),
    Route("POST", re.compile(r"^/api/sites/(?P<domain>[^/]+)/restore$"), _post_restore, RouteMeta("site.restore", "site", True, True)),
    Route("POST", re.compile(r"^/api/sites/(?P<domain>[^/]+)/runtime$"), _post_runtime, RouteMeta("site.runtime", "site", True)),
    Route("POST", re.compile(r"^/api/sites/(?P<domain>[^/]+)/sftp$"), _post_sftp, RouteMeta("site.sftp", "site", True)),
    Route(
        "PUT", re.compile(r"^/api/sites/(?P<domain>[^/]+)/files/content$"), _put_file_content,
        RouteMeta("site.files.write", "site", mutates=True, max_body=6 * files.MAX_EDIT_BYTES + 32 * 1024),
    ),
    Route(
        "POST", re.compile(r"^/api/sites/(?P<domain>[^/]+)/files/upload$"), _post_file_upload,
        RouteMeta("site.files.upload", "site", mutates=True, raw_body=True, max_body=files.MAX_UPLOAD_BYTES),
    ),
    Route("POST", re.compile(r"^/api/sites/(?P<domain>[^/]+)/files/mkdir$"), _post_file_mkdir, RouteMeta("site.files.mkdir", "site", True)),
    Route("POST", re.compile(r"^/api/sites/(?P<domain>[^/]+)/files/rename$"), _post_file_rename, RouteMeta("site.files.rename", "site", True)),
    Route("POST", re.compile(r"^/api/sites/(?P<domain>[^/]+)/files/chmod$"), _post_file_chmod, RouteMeta("site.files.chmod", "site", True)),
    Route("DELETE", re.compile(r"^/api/sites/(?P<domain>[^/]+)/files$"), _delete_file, RouteMeta("site.files.delete", "site", True, True)),
    Route(
        "POST", re.compile(r"^/api/sites/(?P<domain>[^/]+)/databases$"),
        _post_database, RouteMeta("site.database.create", "site", True),
    ),
    Route(
        "DELETE", re.compile(r"^/api/sites/(?P<domain>[^/]+)/databases/(?P<name>[^/]+)$"),
        _delete_database, RouteMeta("site.database.drop", "site", True, True),
    ),
    Route(
        "POST", re.compile(r"^/api/sites/(?P<domain>[^/]+)/db-users$"),
        _post_db_user, RouteMeta("site.database.user-create", "site", True),
    ),
    Route(
        "DELETE", re.compile(r"^/api/sites/(?P<domain>[^/]+)/db-users/(?P<user>[^/]+)$"),
        _delete_db_user, RouteMeta("site.database.user-drop", "site", True, True),
    ),
    Route(
        "POST", re.compile(r"^/api/sites/(?P<domain>[^/]+)/db-users/(?P<user>[^/]+)/password$"),
        _post_db_password, RouteMeta("site.database.user-password", "site", True),
    ),
    Route(
        "POST", re.compile(r"^/api/sites/(?P<domain>[^/]+)/adminer$"),
        _post_adminer, RouteMeta("site.adminer", "site", True),
    ),
    Route(
        "POST", re.compile(r"^/api/sites/(?P<domain>[^/]+)/php-settings$"),
        _post_php_settings, RouteMeta("site.php-settings", "site", True),
    ),
    Route(
        "PUT", re.compile(r"^/api/sites/(?P<domain>[^/]+)/nginx-custom$"),
        _put_nginx_custom, RouteMeta("site.nginx-custom", "site", True),
    ),
    Route(
        "PUT", re.compile(r"^/api/sites/(?P<domain>[^/]+)/cache$"),
        _put_cache, RouteMeta("site.cache", "site", True),
    ),
    Route(
        "POST", re.compile(r"^/api/sites/(?P<domain>[^/]+)/cache/purge$"),
        _post_cache_purge, RouteMeta("site.cache.purge", "site", True),
    ),
    Route(
        "PUT", re.compile(r"^/api/sites/(?P<domain>[^/]+)/security$"),
        _put_security, RouteMeta("site.security", "site", True),
    ),
    Route(
        "POST", re.compile(r"^/api/sites/(?P<domain>[^/]+)/cron$"),
        _post_cron, RouteMeta("site.cron.add", "site", True),
    ),
    Route(
        "PUT", re.compile(r"^/api/sites/(?P<domain>[^/]+)/cron/(?P<job_id>[^/]+)$"),
        _put_cron, RouteMeta("site.cron.enable", "site", True),
    ),
    Route(
        "DELETE", re.compile(r"^/api/sites/(?P<domain>[^/]+)/cron/(?P<job_id>[^/]+)$"),
        _delete_cron, RouteMeta("site.cron.remove", "site", True),
    ),
    Route(
        "POST", re.compile(r"^/api/sites/(?P<domain>[^/]+)/cron/(?P<job_id>[^/]+)/run$"),
        _post_cron_run, RouteMeta("site.cron.run", "site", True),
    ),
    Route("POST", re.compile(r"^/api/sites/(?P<domain>[^/]+)/wp$"), _post_wp, RouteMeta("site.wp", "site", True)),
    Route("POST", re.compile(r"^/api/sites/(?P<domain>[^/]+)/config$"), _post_config, RouteMeta("site.config", "site", True)),
    # Logout invalidates its caller's credential, so keep it terminal among declarative routes.
    Route("POST", re.compile(r"^/api/auth/logout$"), _post_auth_logout, RouteMeta("auth.logout", "session", True)),
)


def make_panel_handler(config: PanelConfig) -> type[BaseHTTPRequestHandler]:
    class PanelHandler(BaseHTTPRequestHandler):
        server_version = f"wpfy-panel/{__version__}"
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args) -> None:
            pass

        def handle_one_request(self) -> None:
            self._request_body_read = False
            super().handle_one_request()

        def _close_if_body_unread(self) -> None:
            if self._request_body_read:
                return
            value = self.headers.get("Content-Length")
            if value is None:
                return
            try:
                unread = int(value) > 0
            except ValueError:
                unread = True
            if unread:
                self.close_connection = True

        def _send_json(self, status: int, payload: dict) -> None:
            self._close_if_body_unread()
            data = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            if self.close_connection:
                self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)

        def _send_download(self, status: int, download: files.Download) -> None:
            self._close_if_body_unread()
            safe_name = re.sub(r"[^\w.\- ]", "_", download.name, flags=re.ASCII) or "download"
            encoded_name = quote(download.name, safe="")
            self.send_response(status)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header(
                "Content-Disposition",
                f"attachment; filename=\"{safe_name}\"; filename*=UTF-8''{encoded_name}",
            )
            self.send_header("Content-Length", str(download.size))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            if self.close_connection:
                self.send_header("Connection", "close")
            self.end_headers()
            remaining = download.size
            while remaining:
                chunk = download.stream.read(min(1024 * 1024, remaining))
                if not chunk:
                    self.close_connection = True
                    break
                self.wfile.write(chunk)
                remaining -= len(chunk)

        def _bearer_token(self) -> str | None:
            header = self.headers.get("Authorization", "")
            if not header.startswith("Bearer "):
                return None
            token = header[len("Bearer "):]
            return token or None

        def _authenticate(self):
            token = self._bearer_token()
            if token is None:
                return None
            if not panel_auth.login_required() and hmac.compare_digest(token, config.token):
                return _run_token_principal()
            principal = panel_auth.authenticate_session(token)
            if principal is not None:
                principal["_session_token"] = token
            return principal

        def _content_length(self, *, required: bool = False) -> int:
            value = self.headers.get("Content-Length")
            if value is None:
                if required:
                    raise PanelError(411, "Content-Length header required")
                return 0
            try:
                length = int(value)
            except ValueError:
                raise PanelError(400, "invalid Content-Length header") from None
            if length < 0:
                raise PanelError(400, "invalid Content-Length header")
            return length

        def _read_body(self, max_body: int | None = None) -> dict:
            length = self._content_length()
            if length <= 0:
                return {}
            if length > (max_body if max_body is not None else _MAX_BODY_BYTES):
                raise PanelError(413, "request body too large")
            raw = self.rfile.read(length)
            self._request_body_read = True
            try:
                body = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise PanelError(400, "request body must be JSON")
            if not isinstance(body, dict):
                raise PanelError(400, "request body must be a JSON object")
            return body

        def _read_raw_body(self, max_body: int | None) -> RawBody:
            length = self._content_length(required=True)
            if max_body is not None and length > max_body:
                self.close_connection = True
                raise PanelError(413, "request body too large")
            return RawBody(self.rfile, length)

        def _serve_static(self, path: str) -> None:
            name = "index.html" if path in ("", "/") else path.lstrip("/")
            target = (STATIC_DIR / name).resolve()
            root = STATIC_DIR.resolve()
            try:
                target.relative_to(root)
            except ValueError:
                self._send_json(404, {"error": "not found"}); return
            if not target.is_file():
                self._send_json(404, {"error": "not found"}); return
            content_type = _STATIC_TYPES.get(target.suffix)
            if content_type is None:
                self._send_json(404, {"error": "not found"}); return
            data = target.read_bytes()
            self._close_if_body_unread()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Content-Type-Options", "nosniff")
            if content_type.startswith("text/html"):
                self.send_header("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
            if self.close_connection:
                self.send_header("Connection", "close")
            self.end_headers(); self.wfile.write(data)

        def _handle_api(self, method: str) -> None:
            route = None
            parsed = urlparse(self.path)
            try:
                route = next(
                    (
                        route for route in (*_SETUP_ROUTES, *_ROUTES)
                        if route.method == method and route.pattern.fullmatch(parsed.path)
                    ),
                    None,
                )
                principal = None if route is not None and route.meta.scope == "public" else self._authenticate()
                if principal is None and (route is None or route.meta.scope != "public"):
                    raise PanelError(401, "missing or invalid token")
                if route is None:
                    raise PanelError(404, f"unknown endpoint: {parsed.path}")
                match = route.pattern.fullmatch(parsed.path)
                domain = match.groupdict().get("domain") if match else None
                if route.meta.scope != "public":
                    authorize(principal, route.meta, domain)
                if route.meta.scope == "setup" and panel_auth.login_required():
                    raise PanelError(410, "first-run setup is permanently closed")
                if route.meta.scope == "setup-session" and (
                    not isinstance(principal, dict) or principal.get("_setup_session") is not True
                ):
                    raise PanelError(410, "setup enrollment is no longer available")
                if route.meta.raw_body:
                    body = self._read_raw_body(route.meta.max_body)
                elif method in {"POST", "PUT", "DELETE"}:
                    body = self._read_body(route.meta.max_body)
                else:
                    body = {}
                if route.meta.action in {"auth.login", "setup.create"}:
                    body["_socket_client"] = resolve_client_address(
                        self.client_address[0],
                        self.headers.get("X-Forwarded-For"),
                        trusted_edge_networks(),
                    )
                if route.meta.action in {"setup.status", "setup.create"}:
                    body["_edge_bind"] = config.edge_bind
                status, payload = route.handler(principal, match, parse_qs(parsed.query), body)
                preview_response = isinstance(payload, dict) and (
                    payload.get("dry_run") is True or payload.get("acknowledgement_required") is True
                )
                detailed_operation_event = route.meta.action == "site.cron.run"
                if (
                    route.meta.mutates and status < 400 and status != 202
                    and not preview_response and not detailed_operation_event
                ):
                    actor = (
                        payload.get("username", "unknown")
                        if route.meta.action == "auth.login"
                        else _principal_username(principal)
                    )
                    events.record_event(route.meta.action, domain=domain, actor=actor)
            except PanelError as exc:
                self._send_json(exc.status, {"error": str(exc)}); return
            except (FileNotFoundError, ValueError) as exc:
                self._send_json(400, {"error": str(exc)}); return
            except (OSError, subprocess.SubprocessError) as exc:
                self._send_json(500, {"error": str(exc)}); return
            except Exception:
                _LOGGER.exception("unhandled panel API error")
                self._send_json(500, {"error": "internal server error"}); return
            if isinstance(payload, files.Download):
                try:
                    self._send_download(status, payload)
                finally:
                    payload.stream.close()
            else:
                self._send_json(status, payload)

        def do_GET(self) -> None:
            if urlparse(self.path).path.startswith("/api/"): self._handle_api("GET")
            else: self._serve_static(urlparse(self.path).path)

        def do_POST(self) -> None:
            if urlparse(self.path).path.startswith("/api/"): self._handle_api("POST")
            else: self._send_json(404, {"error": "not found"})

        def do_PUT(self) -> None:
            if urlparse(self.path).path.startswith("/api/"): self._handle_api("PUT")
            else: self._send_json(404, {"error": "not found"})

        def do_DELETE(self) -> None:
            if urlparse(self.path).path.startswith("/api/"): self._handle_api("DELETE")
            else: self._send_json(404, {"error": "not found"})

    return PanelHandler


def make_panel_server(config: PanelConfig) -> ThreadingHTTPServer:
    if not config.token:
        raise ValueError("panel requires a non-empty token")
    if config.edge_bind:
        from . import panel_exposure

        if not panel_auth.login_required():
            raise ValueError("edge-bound panel requires named-user login")
        if not any(user.get("totp_enabled") for user in panel_auth.list_users()):
            raise ValueError("edge-bound panel requires an enrolled TOTP factor")
        if not panel_exposure.exposure_status().get("exposed"):
            raise ValueError("edge-bound panel requires an active exposure router")
        panel_exposure.validate_edge_bind(config.host)
    else:
        validate_loopback_host(config.host)
    server = ThreadingHTTPServer((config.host, config.port), make_panel_handler(config))
    server.daemon_threads = True
    return server


def panel_url(config: PanelConfig, port: int | None = None) -> str:
    base = f"http://{config.host}:{port or config.port}/"
    return base if panel_auth.login_required() else f"{base}#token={config.token}"


def serve_panel(config: PanelConfig) -> None:
    with make_panel_server(config) as server:
        server.serve_forever()
