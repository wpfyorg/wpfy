from __future__ import annotations

import hmac
import http.client
import ipaddress
import json
import logging
import os
import queue
import re
import secrets
import subprocess
import threading
import time
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlparse

from . import __version__, backup_schedule, certificate_lifecycle, events, fail2ban_docker, fail2ban_host, files, firewall_ports, metrics, operational_inspection, panel_auth, panel_jobs, panel_setup, s3_backup, settings, smtp, sftp, telemetry
from . import site_cache, site_cron, site_database
from . import site_configuration, site_lifecycle, site_security
from .php_runtime import DEFAULT_PHP_VERSION, SUPPORTED_PHP_VERSIONS

# Login Shield presentation labels (t17). Enforcement lives in
# fail2ban_host.wordpress_auth_failregex(); this list only describes the
# protected WordPress authentication surfaces for the panel Security tab.
LOGIN_SHIELD_PROTECTED_SURFACES = (
    "wp_login",
    "xmlrpc",
    "rest",
    "password_reset",
    "user_enum",
    "app_password",
)
from .site_definition import (
    DNS_PROVIDERS,
    LETSENCRYPT_MODES,
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
from . import file_manager as panel_file_manager
from .file_manager_providers import quantum as quantum_provider

DEFAULT_PANEL_PORT = 8642
PANEL_SOCKET_TIMEOUT = 30
STATIC_DIR = Path(__file__).parent / "panel_static"
_STATIC_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
}
_CLIENT_ROUTE_PREFIXES = (
    "/dashboard",
    "/sites",
    "/site/",
    "/events",
    "/notifications",
    "/account/",
    "/admin/",
)
_LOG_SERVICES = {"web", "app", "db", "redis", "sftp"}
_LOGGER = logging.getLogger(__name__)
_MAX_BODY_BYTES = 64 * 1024
_FM_PROXY_MAX_BODY = files.MAX_UPLOAD_BYTES  # ponytail: reuse existing upload ceiling
_MAX_LOG_LINES = 2000
RUN_TOKEN_ADMIN = "run-token-admin"
_ALLOWED_PANEL_FLAVORS = frozenset({"php", "html", *WORDPRESS_FLAVORS})
_SITE_MANAGER_ALLOWED_ACTIONS = frozenset({
    "auth.me", "auth.logout", "auth.totp.enable", "auth.totp.disable",
    "site.list", "job.list", "job.read", "event.list", "event.stream",
})

_TRUSTED_EDGE_LOCK = threading.Lock()
# Short TTL so a recreated Traefik with a new container IP is picked up by
# the panel before the next failed-login attempt can be misclassified. A
# failure is deliberately not cached: a transient Docker outage then degrades
# to the shared bucket for one request instead of pinning that degradation for
# the panel's lifetime.
_TRUSTED_EDGE_TTL_SECONDS = 30
_TRUSTED_EDGE_CACHE: tuple[tuple[str, ...], float] | None = None
# Sentinel for a client address that cannot be determined (trusted edge with
# no usable forwarded chain). The trusted proxy endpoints themselves are in
# the never-ban set: recording the proxy's own IP as a client would let a
# later fail2ban stage take the entire panel edge offline.
_UNKNOWN_CLIENT = "0.0.0.0"
_FM_PROXY_TICKETS: dict[str, tuple[str, str, float]] = {}
_FM_PROXY_TICKETS_LOCK = threading.Lock()


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
    fail closed to the peer when no edge is known. When the peer IS a trusted
    edge but no untrusted client can be determined (no forwarded header, an
    empty or malformed chain, or a chain of only trusted hops), resolve to the
    unknown sentinel: the proxy's own address is never emitted as a client.
    """
    if not _address_in_networks(peer, trusted):
        return peer
    if not isinstance(forwarded, str):
        return _UNKNOWN_CLIENT
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
    return _UNKNOWN_CLIENT


def trusted_edge_networks() -> tuple[str, ...]:
    """CIDRs whose peers may assert a forwarded client address.

    Consulted on every sign-in, and discovery shells out to Docker, so a
    successful result is cached for at most ``_TRUSTED_EDGE_TTL_SECONDS``
    seconds (using ``time.monotonic`` so clock changes cannot extend the
    cache). A failure is deliberately not cached: a transient Docker outage
    then degrades to the shared bucket for one request instead of pinning that
    degradation for the panel's lifetime, and the next request re-discovers.
    """
    global _TRUSTED_EDGE_CACHE
    now = time.monotonic()
    with _TRUSTED_EDGE_LOCK:
        cached = _TRUSTED_EDGE_CACHE
        if cached is not None and cached[1] > now:
            return cached[0]
    try:
        discovered = tuple(traefik.traefik_network_cidrs(panel_exposure.PANEL_EDGE_NETWORK))
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError):
        return ()
    with _TRUSTED_EDGE_LOCK:
        _TRUSTED_EDGE_CACHE = (discovered, time.monotonic() + _TRUSTED_EDGE_TTL_SECONDS)
    return discovered


@dataclass(frozen=True, slots=True)
class PanelConfig:
    host: str = "127.0.0.1"
    port: int = DEFAULT_PANEL_PORT
    token: str = ""
    edge_bind: bool = False
    #: Serve the panel's own socket over TLS with the self-signed certificate
    #: from `panel_tls`. Used by the domainless exposure, where no CA will issue
    #: for a bare address and plaintext would put the first-run password, the
    #: TOTP secret and every session token on the wire in the clear.
    self_signed_tls: bool = False


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
class _FileManagerProxyResponse:
    response: http.client.HTTPResponse
    connection: http.client.HTTPConnection
    headers: dict[str, str]


@dataclass(frozen=True, slots=True)
class Route:
    method: str
    pattern: re.Pattern[str]
    handler: object
    meta: RouteMeta


class PanelError(Exception):
    def __init__(self, status: int, message: str, headers: dict[str, str] | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.headers = headers or {}


class _PanelHTTPServer(ThreadingHTTPServer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # t19: reaper stop signal so a closed panel server never leaks a
        # forever-looping daemon thread into the process (full-suite race).
        self._reaper_stop = threading.Event()

    def get_request(self):
        request, client_address = super().get_request()
        request.settimeout(PANEL_SOCKET_TIMEOUT)
        return request, client_address

    def server_close(self):
        self._reaper_stop.set()
        super().server_close()


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


def _idle_reap_once() -> None:
    stopped = 0
    for entry in list_sites():
        if stopped >= 5:
            break
        try:
            domain = entry["domain"]
            state = panel_file_manager.get_file_manager_state(domain)
            if state.state not in {"ready", "idle-warning"} or not state.idle_expires_at:
                continue
            if datetime.fromisoformat(state.idle_expires_at).timestamp() >= datetime.now(timezone.utc).timestamp():
                continue
            with panel_file_manager._get_lock(domain):
                state = panel_file_manager.get_file_manager_state(domain)
                if state.state not in {"ready", "idle-warning"} or not state.idle_expires_at:
                    continue
                if datetime.fromisoformat(state.idle_expires_at).timestamp() >= datetime.now(timezone.utc).timestamp():
                    continue
            panel_file_manager.disable_file_manager(domain, quantum_provider)
            _emit_event("file_manager.auto_stopped", domain=domain, actor="system")
            stopped += 1
        except Exception:  # noqa: BLE001, BROAD_EXCEPT_OK
            _LOGGER.exception("file-manager idle reap failed")


def _idle_reap_loop(stop_event: threading.Event) -> None:
    while not stop_event.is_set():
        try:
            _idle_reap_once()
        except Exception:  # noqa: BLE001, BROAD_EXCEPT_OK
            _LOGGER.exception("file-manager idle reaper tick failed")
        stop_event.wait(30)


def _rediscover_file_managers() -> None:
    if runtime_skip_requested():
        return
    try:
        result = subprocess.run(
            ["docker", "ps", "--format", '{{.Label "wpfy.site"}}', "--filter", "label=wpfy.kind=file-manager"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        _LOGGER.warning("file-manager rediscovery failed: %s", exc)
        return
    if result.returncode != 0:
        _LOGGER.warning("file-manager rediscovery returned status %s", result.returncode)
        return
    known_domains = {entry["domain"] for entry in list_sites() if "domain" in entry}
    for domain in set(result.stdout.splitlines()) & known_domains:
        try:
            if panel_file_manager.get_file_manager_state(domain).state in {"starting", "failed"}:
                panel_file_manager.mark_ready(domain)
        except Exception:  # noqa: BLE001, BROAD_EXCEPT_OK
            _LOGGER.exception("file-manager rediscovery state update failed")


def _revoke_fm_for_logout(domain: str, username: str) -> None:
    try:
        holders = panel_file_manager.lease_holder_usernames(domain)
        if username in holders and len(holders) <= 1:
            panel_file_manager.disable_file_manager(domain, quantum_provider)
            _emit_event("file_manager.stopped", domain=domain, actor=username)
    except Exception:  # noqa: BLE001, BROAD_EXCEPT_OK
        _LOGGER.exception("file-manager logout revocation failed")


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


def _assert_same_origin(headers, host_header: str) -> None:
    try:
        request_host = urlparse(f"//{host_header}").hostname
    except ValueError:
        request_host = None
    origin = headers.get("Origin")
    referer = headers.get("Referer")
    if origin is not None:
        try:
            parsed = urlparse(origin)
        except ValueError:
            raise PanelError(403, "cross-origin request denied") from None
        if parsed.scheme not in {"http", "https"} or parsed.hostname is None or request_host is None:
            raise PanelError(403, "cross-origin request denied")
        if parsed.hostname.lower() != request_host.lower():
            raise PanelError(403, "cross-origin request denied")
    elif referer is not None:
        try:
            parsed = urlparse(referer)
        except ValueError:
            raise PanelError(403, "cross-origin request denied") from None
        if parsed.hostname is None or request_host is None:
            raise PanelError(403, "cross-origin request denied")
        if parsed.hostname.lower() != request_host.lower():
            raise PanelError(403, "cross-origin request denied")


def authorize(principal, meta: RouteMeta, domain: str | None) -> None:
    if principal is None:
        raise PanelError(401, "missing or invalid token")
    if principal == RUN_TOKEN_ADMIN:
        return
    if not isinstance(principal, dict):
        raise PanelError(401, "missing or invalid token")
    if principal.get("_setup_secret"):
        # The setup link creates the first administrator and does nothing else.
        # It carries no role, so every other route is refused here rather than
        # falling through to the site-manager checks below.
        if meta.scope == "setup":
            return
        raise PanelError(403, "forbidden")
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


def _file_manager_enabled() -> bool:
    return os.environ.get("WPFY_FM_ENABLED", "0") == "1"


def _file_manager_gate() -> None:
    if not _file_manager_enabled():
        raise PanelError(404, "file manager disabled")


def _file_manager_error(exc: panel_file_manager.FileManagerError) -> tuple[int, dict]:
    messages = {
        "site_not_found": "site not found",
        "app_dir_missing": "application directory unavailable",
        "limit_reached": panel_file_manager._LIMIT_MESSAGE,
        "config_failed": "file manager failed to start",
        "start_failed": "file manager failed to start",
        "health_failed": "file manager failed to start",
    }
    status = 429 if exc.code == "limit_reached" else 404 if exc.code == "site_not_found" else 500
    return status, {"state": "failed", "error": {"code": exc.code, "message": messages.get(exc.code, "file manager failed")}}


def _file_manager_cookie(domain: str, username: str) -> str:
    token = secrets.token_urlsafe(32)
    with _FM_PROXY_TICKETS_LOCK:
        now = time.time()
        _FM_PROXY_TICKETS.update({key: value for key, value in _FM_PROXY_TICKETS.items() if value[2] > now})
        _FM_PROXY_TICKETS[token] = (domain, username, now + 60)
    return f"wpfy_fm={token}; Path=/api/sites/{domain}/file-manager/proxy/; HttpOnly; SameSite=Strict; Max-Age=60"


def _validate_file_manager_cookie(headers, domain: str, username: str) -> None:
    cookie = SimpleCookie()
    cookie.load(headers.get("Cookie", ""))
    morsel = cookie.get("wpfy_fm")
    token = morsel.value if morsel is not None else ""
    with _FM_PROXY_TICKETS_LOCK:
        now = time.time()
        expired = [key for key, value in _FM_PROXY_TICKETS.items() if value[2] <= now]
        for key in expired:
            _FM_PROXY_TICKETS.pop(key, None)
        ticket = _FM_PROXY_TICKETS.get(token)
    if ticket is None or ticket[0] != domain or ticket[1] != username:
        raise PanelError(403, "file manager proxy session required")


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
            _emit_event(job.action, domain=job.domain, actor=actor, job_id=job.id)
        except Exception as exc:
            message = events._redact(str(exc))
            panel_jobs.fail_job(job.id, message)
            _emit_event(job.action, domain=job.domain, outcome="failed", detail=message,
                        actor=actor, job_id=job.id)
    threading.Thread(target=runner, name=f"wpfy-panel-{job.id[:8]}", daemon=True).start()


# --- Event stream (GET /api/stream) -----------------------------------------
#
# Registered like `file_manager.proxy`: the dispatcher hands the handler the
# raw request object so it can write `text/event-stream` frames directly to
# the socket instead of going through the JSON encoder. See _handle_api.

_STREAM_MAX_CONCURRENT = 8
_STREAM_KEEPALIVE_SECONDS = 15
_STREAM_LOCK = threading.Lock()
_STREAM_SUBSCRIBERS: list[queue.Queue] = []


@dataclass(frozen=True, slots=True)
class _StreamAlreadySent:
    """Sentinel: the handler wrote its own response; _handle_api sends nothing."""


def _stream_subscribe() -> queue.Queue | None:
    with _STREAM_LOCK:
        if len(_STREAM_SUBSCRIBERS) >= _STREAM_MAX_CONCURRENT:
            return None
        subscriber: queue.Queue = queue.Queue(maxsize=200)
        _STREAM_SUBSCRIBERS.append(subscriber)
        return subscriber


def _stream_unsubscribe(subscriber: queue.Queue) -> None:
    with _STREAM_LOCK:
        if subscriber in _STREAM_SUBSCRIBERS:
            _STREAM_SUBSCRIBERS.remove(subscriber)


def _stream_publish(event: dict) -> None:
    with _STREAM_LOCK:
        subscribers = list(_STREAM_SUBSCRIBERS)
    for subscriber in subscribers:
        try:
            subscriber.put_nowait(event)
        except queue.Full:
            pass  # ponytail: drop on a full queue rather than block the publisher


def _emit_event(action, *, domain=None, outcome="ok", detail="", actor="cli", job_id=None) -> None:
    """Record an event and fan it out to any live /api/stream subscribers."""
    event = events.record_event(action, domain=domain, outcome=outcome, detail=detail, actor=actor, job_id=job_id)
    if event is not None:
        _stream_publish(event)


def _stream_visible(event: dict, principal) -> bool:
    """Per-principal filter, matching _get_events (panel.py `_get_events`)."""
    if not _principal_is_manager(principal):
        return True
    assigned = set(principal.get("sites") or ())
    return event.get("domain") in assigned


def _get_stream(request, principal, match, query, body):
    subscriber = _stream_subscribe()
    if subscriber is None:
        return 503, {"error": "too many concurrent event streams"}
    try:
        request.send_response(200)
        request.send_header("Content-Type", "text/event-stream; charset=utf-8")
        request.send_header("Cache-Control", "no-store")
        request.send_header("X-Content-Type-Options", "nosniff")
        request.send_header("Connection", "close")
        request.close_connection = True
        request.end_headers()
        deadline = time.monotonic() + _STREAM_KEEPALIVE_SECONDS
        while True:
            remaining = max(0.0, deadline - time.monotonic())
            try:
                event = subscriber.get(timeout=remaining)
            except queue.Empty:
                request.wfile.write(b": keepalive\n\n")
                request.wfile.flush()
                deadline = time.monotonic() + _STREAM_KEEPALIVE_SECONDS
                continue
            deadline = time.monotonic() + _STREAM_KEEPALIVE_SECONDS
            if not _stream_visible(event, principal):
                continue
            frame = f"event: {event.get('action', '')}\ndata: {json.dumps(event)}\n\n"
            request.wfile.write(frame.encode("utf-8"))
            request.wfile.flush()
    except (BrokenPipeError, ConnectionError, OSError):
        pass
    finally:
        _stream_unsubscribe(subscriber)
    return 200, _StreamAlreadySent()


def api_overview() -> dict:
    facts = operational_inspection.aggregate_info()
    # `aggregate_info` carries the `docker compose ps` table, which is what
    # `wpfy info` should print and not what a dashboard card can show -- the card
    # rendered "NAME IMAGE COMMAND SE..." under the heading. It also made the
    # warning check a substring search over a table wide enough to match by
    # accident. One parsed state instead.
    health = traefik.traefik_health()
    warnings = int(facts.docker_version == "unavailable")
    if health not in ("running", "healthy"):
        warnings += 1
    return {"version": __version__, "docker_version": facts.docker_version, "traefik": health,
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


def api_site_services(domain: str) -> dict:
    """Service rows for one site.

    `api_system_services` covers every site at once and is admin-only, which
    leaves a site-manager unable to see the containers of the site they are
    responsible for. This is the same data narrowed to one domain, so it can
    carry the `site` scope and be filtered per principal like every other
    per-site read.
    """
    _known_domain(domain)
    allowed = tuple(sorted(site_cron.allowed_services(domain)))
    return {"domain": domain, "services": list_site_services(domain, allowed)}


def api_metrics_latest() -> dict:
    samples = metrics.latest_samples()
    return {"host_scope": metrics.HOST_SCOPE, "samples": [asdict(sample) for sample in samples]}


def api_system_services() -> dict:
    # `traefik_status()` returns the whole `docker compose ps` table, header row
    # included -- right for the CLI, wrong here: the client reads this field as
    # one container's state, finds no "healthy" in the blob, and reports the
    # edge proxy as degraded on the dashboard of a perfectly healthy install.
    # Same parsed vocabulary as the per-site rows below.
    services = [{"name": traefik.TRAEFIK_CONTAINER, "status": traefik.traefik_health()}]
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


_SFTP_PASSWORD_MARKER = "\npassword (shown once):"


def _sftp_payload(result) -> dict:
    """Runtime payload with the CLI's password line stripped from `message`.

    `sftp.ensure_sftp_container()` appends `password (shown once): <secret>` to
    its message for the benefit of the CLI, and `rotate_sftp_password()` returns
    that same result. `message` is a general-purpose display field -- the panel
    renders it into the page and it is not the one-time surface -- so the secret
    must leave here through `one_time` alone. Stripping per-branch let the
    rotate path ship the password twice, once in `one_time` and once in text the
    client had every reason to display and keep on screen.
    """
    payload = _runtime_payload(result)
    if _SFTP_PASSWORD_MARKER in payload.get("message", ""):
        payload["message"] = payload["message"].split(_SFTP_PASSWORD_MARKER, 1)[0]
    return payload


def api_site_sftp_action(domain: str, action: str) -> tuple[int, dict]:
    _known_domain(domain)
    if action == "enable":
        result = sftp.ensure_sftp_container(domain)
    elif action == "disable":
        result = sftp.remove_sftp_container(domain)
    elif action == "rotate":
        password = generated_secret()[:16]
        result = sftp.rotate_sftp_password(domain, password=password)
        payload = _sftp_payload(result)
        if result.exit_code == 0:
            payload["one_time"] = {"password": password}
        return _operation_status(result, not_found=True), payload
    else:
        raise PanelError(400, f"unknown sftp action: {action}")
    return _operation_status(result, not_found=True), _sftp_payload(result)


def api_site_wp(domain: str, wp_args: list) -> tuple[int, dict]:
    _known_domain(domain)
    if not wp_args or not all(isinstance(arg, str) and "\x00" not in arg for arg in wp_args):
        raise PanelError(400, "wp requires a non-empty list of string arguments")
    proc = run_wp_cli(domain, *wp_args)
    if not proc.ran:
        raise PanelError(500, proc.stderr.strip() or "wp-cli failed to run")
    return 200, {"ok": proc.exit_code == 0, "exit_code": proc.exit_code, "stdout": proc.stdout, "stderr": proc.stderr}


_CONFIG_PHP_KEYS = frozenset({
    "php_memory_limit", "php_max_execution_time", "php_max_input_time",
    "php_max_input_vars", "php_upload_max_size", "reset_php",
})
_CONFIG_LIFECYCLE_KEYS = frozenset({"php_version", "flavor", "letsencrypt", "password"})


def _validate_config_lifecycle_body(domain: str, body: dict) -> str | None:
    """Validate the lifecycle-update fields of a config body; return the flavor.

    Raises PanelError(400, ...) on anything invalid. Runs entirely before any
    job is created, so a bad request fails synchronously (house rule 0).
    """
    flavor = body.get("flavor")
    if flavor is not None and (not isinstance(flavor, str) or flavor not in _ALLOWED_PANEL_FLAVORS):
        raise PanelError(400, f"unknown site flavor: {flavor}")
    for key in ("php_version", "letsencrypt", "password"):
        if body.get(key) is not None and not isinstance(body[key], str):
            raise PanelError(400, f"{key} must be a string")
    for key, value, allowed in (
        ("php_version", body.get("php_version"), SUPPORTED_PHP_VERSIONS),
        ("letsencrypt", body.get("letsencrypt"), LETSENCRYPT_MODES),
    ):
        if value is not None and value not in allowed:
            raise PanelError(400, f"invalid {key}: {value!r}; accepted values: {', '.join(allowed)}")
    return flavor


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
    # The trusted-edge list is discovered from the running Traefik network, so it
    # is unavailable whenever Docker is down -- and it is informational, unlike
    # the deny-lists and basic-auth state around it. Letting the RuntimeError
    # escape turned the whole security read into a 500 exactly when an operator
    # is most likely to be reading it: while the runtime is broken.
    # `login_shield_status()` already degrades this way; match it.
    trusted_error = None
    try:
        trusted_sources = list(site_security.traefik_network_cidrs())
        if site_security._cloudflare_trust_required(domain, config):
            trusted_sources.extend(site_security.cloudflare_cidrs())
    except (RuntimeError, OSError) as exc:
        trusted_sources = []
        trusted_error = events._redact(str(exc))
    return {
        "trusted_edge_error": trusted_error,
        "deny_ips": list(config["deny_ips"]),
        "ua_blocks": list(config["ua_blocks"]),
        "basic_auth": dict(config["basic_auth"]),
        "cloudflare_only": config["cloudflare_only"],
        "login_rate_limit": config["login_rate_limit"],
        "fail2ban": config["fail2ban"] is True,
        "login_shield": site_security.login_shield_status(domain),
        "protected_surfaces": list(LOGIN_SHIELD_PROTECTED_SURFACES),
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
    if current["fail2ban"] != desired["fail2ban"]:
        state = "enable" if desired["fail2ban"] else "disable"
        changes.append(f"{state} WordPress fail2ban login shield")
    return changes


def _get_security(principal, match, query, body):
    return 200, {"ok": True, "warnings": [], **_security_state_payload(match.group("domain"))}


def _put_security(principal, match, query, body):
    domain = _known_domain(match.group("domain"))
    allowed = {
        "deny_ips", "ua_blocks", "basic_auth", "cloudflare_only", "login_rate_limit",
        "fail2ban", "dry_run", "acknowledge_warnings",
    }
    if any(key not in allowed for key in body):
        raise PanelError(400, "security update contains an unsupported field")
    for key in ("dry_run", "acknowledge_warnings"):
        if key in body and not isinstance(body[key], bool):
            raise PanelError(400, f"{key} must be a boolean")
    requested = {"deny_ips", "ua_blocks", "basic_auth", "cloudflare_only", "login_rate_limit", "fail2ban"} & set(body)
    if not requested:
        raise PanelError(400, "security update requires at least one security field")

    current = site_security.load_security(domain)
    desired = {
        "deny_ips": body.get("deny_ips", current["deny_ips"]),
        "ua_blocks": body.get("ua_blocks", current["ua_blocks"]),
        "basic_auth": body.get("basic_auth", current["basic_auth"]),
        "cloudflare_only": body.get("cloudflare_only", current["cloudflare_only"]),
        "login_rate_limit": body.get("login_rate_limit", current["login_rate_limit"]),
        "fail2ban": body.get("fail2ban", current["fail2ban"]),
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
    list_changed = False
    for cidr in sorted(set(current["deny_ips"]) - set(desired["deny_ips"])):
        results.append(site_security.remove_deny_ip(domain, cidr))
        list_changed = True
    for cidr in sorted(set(desired["deny_ips"]) - set(current["deny_ips"])):
        results.append(site_security.add_deny_ip(domain, cidr))
        list_changed = True
    for pattern in sorted(set(current["ua_blocks"]) - set(desired["ua_blocks"])):
        results.append(site_security.remove_ua_block(domain, pattern))
        list_changed = True
    for pattern in sorted(set(desired["ua_blocks"]) - set(current["ua_blocks"])):
        results.append(site_security.add_ua_block(domain, pattern))
        list_changed = True
    if (
        not list_changed
        and {"deny_ips", "ua_blocks"}.intersection(requested)
        and not {"basic_auth", "cloudflare_only", "login_rate_limit", "fail2ban"}.intersection(requested)
    ):
        results.append(site_security.apply_security_runtime(domain))
    if "basic_auth" in body:
        results.append(site_security.set_basic_auth(
            domain,
            enabled=desired["basic_auth"]["enabled"],
            username=desired["basic_auth"]["username"],
            password=password,
        ))
    if "cloudflare_only" in body:
        results.append(site_security.set_cloudflare_only(domain, desired["cloudflare_only"]))
    if "login_rate_limit" in body:
        results.append(site_security.set_login_rate_limit(domain, desired["login_rate_limit"]))
    if "fail2ban" in body:
        results.append(site_security.set_fail2ban(domain, desired["fail2ban"]))

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
    return 200, panel_setup.status(remote=body.get("_edge_bind") is True)


def _post_setup(principal, match, query, body):
    client = body.pop("_socket_client", None)
    if isinstance(principal, dict) and principal.get("_setup_secret"):
        # The request authenticated with the secret; making the body repeat it
        # would be two credentials for one grant.
        body.setdefault("setup_secret", principal["_setup_secret"])
    remote = body.pop("_edge_bind", False) is True
    setup_username = body.get("username", "") if isinstance(body.get("username"), str) else ""
    try:
        token, user = panel_setup.create_account(body, client=client, remote=remote)
    except panel_auth.ClientThrottleError as exc:
        panel_auth._append_panel_auth_failure("setup", client, setup_username, "throttled")
        retry_after = panel_auth.client_retry_after(client)
        headers = {"Retry-After": str(retry_after)} if retry_after > 0 else {}
        raise PanelError(429, str(exc), headers) from exc
    except ValueError as exc:
        panel_auth._append_panel_auth_failure("setup", client, setup_username, "invalid_credentials")
        status = 403 if remote else 400
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
            client = body.get("_socket_client")
            panel_auth._append_panel_auth_failure("setup_totp", client, username, "totp_failed")
            raise PanelError(400, str(exc)) from exc
        panel_auth.finish_setup_session(principal.get("_session_token"))
        _emit_event("panel.totp.enrolled", actor=username)
        return 200, {"ok": True, "enrolled": True}
    if action == "skip":
        if body.get("confirm") is not True:
            raise PanelError(
                400,
                "confirm skipping TOTP: without a second factor this panel cannot be published to the internet",
            )
        panel_auth.cancel_totp_enrollment(username)
        panel_auth.finish_setup_session(principal.get("_session_token"))
        _emit_event("panel.totp.skipped", actor=username)
        return 200, {"ok": True, "skipped": True}
    raise PanelError(400, "setup TOTP action must be begin, verify, or skip")


def _post_auth_login(principal, match, query, body):
    client = body.get("_socket_client")
    result = panel_auth.login(body.get("username"), body.get("password"), body.get("totp"), client=client)
    if result is None:
        if panel_auth.client_throttled(client):
            retry_after = panel_auth.client_retry_after(client)
            headers = {"Retry-After": str(retry_after)} if retry_after > 0 else {}
            raise PanelError(429, "too many failed login attempts; try again later", headers)
        raise PanelError(401, "invalid credentials")
    token, user = result
    return 200, {
        "token": token,
        "username": user["username"],
        "role": user["role"],
        "sites": user["sites"],
    }


def _post_auth_logout(principal, match, query, body):
    username = principal.get("username") if isinstance(principal, dict) else None
    panel_auth.logout(principal.get("_session_token") if isinstance(principal, dict) else None)
    if isinstance(username, str):
        for entry in list_sites():
            domain = entry.get("domain")
            if isinstance(domain, str):
                threading.Thread(
                    target=_revoke_fm_for_logout,
                    args=(domain, username),
                    daemon=True,
                ).start()
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
def _get_metrics_latest(principal, match, query, body): return 200, api_metrics_latest()
def _get_system_services(principal, match, query, body): return 200, api_system_services()
def _get_system_diagnostics(principal, match, query, body): return 200, api_system_diagnostics()


def _get_settings(principal, match, query, body):
    return 200, {"exposure": panel_exposure.exposure_status(), "telemetry": telemetry.status()}


def _put_settings_telemetry(principal, match, query, body):
    if set(body) != {"enabled"} or not isinstance(body.get("enabled"), bool):
        raise PanelError(400, "telemetry requires an enabled boolean")
    telemetry.set_enabled(body["enabled"])
    return 200, telemetry.status()


def _post_settings_exposure(principal, match, query, body):
    allowed = {"domain", "confirm", "port"}
    if any(key not in allowed for key in body):
        raise PanelError(400, "panel exposure contains an unsupported field")
    domain = body.get("domain")
    if not isinstance(domain, str) or not domain:
        raise PanelError(400, "panel exposure requires a domain")
    # expose() gates on `confirm == domain` so the operator has to type the
    # destination they are about to publish to the internet. Forwarding the
    # domain we already hold would satisfy that check for them and reduce it to
    # a checkbox, so the client sends it and we pass it through unchanged --
    # same contract as _delete_site and _post_traefik_restart.
    if body.get("confirm") != domain:
        raise PanelError(400, "panel exposure requires confirm to exactly match the domain")
    port = body.get("port", panel_exposure.DEFAULT_PANEL_PORT)
    if not isinstance(port, int) or isinstance(port, bool):
        raise PanelError(400, "panel exposure port must be an integer")
    result = panel_exposure.expose(domain, confirm=body["confirm"], port=port)
    return _operation_status(result), _runtime_payload(result)


def _delete_settings_exposure(principal, match, query, body):
    result = panel_exposure.disable()
    return _operation_status(result), _runtime_payload(result)


def _s3_config_payload(config):
    return {
        "endpoint": config.endpoint,
        "bucket": config.bucket,
        "region": config.region,
        "prefix": config.prefix,
        "access_key": config.access_key,
        "allow_insecure": config.allow_insecure,
    }


def _get_remote_backup(principal, match, query, body):
    try:
        config = s3_backup.load_s3_config()
    except s3_backup.S3ConfigError:
        config_payload = None
    else:
        config_payload = _s3_config_payload(config)
    schedule = backup_schedule.schedule_status()
    return 200, {"config": config_payload, "schedule": _runtime_payload(schedule)}


def _put_remote_backup(principal, match, query, body):
    """Write the destination. A blank `secret_key` keeps the stored one.

    The secret is write-only -- no read path returns it -- so a client editing
    a destination cannot round-trip the value it is not allowed to see. Demanding
    it on every write means changing a prefix forces the operator to re-type an
    S3 secret, and a client that sends "" to satisfy a required field silently
    replaces a working credential with an empty one. Nothing fails until the next
    scheduled upload, in the middle of the night, quietly. So an absent or empty
    secret means "keep what is stored", and only a non-empty value replaces it.
    """
    required = {"endpoint", "bucket", "region", "prefix", "access_key", "allow_insecure"}
    allowed = required | {"secret_key"}
    if any(key not in allowed for key in body) or not required <= set(body):
        raise PanelError(400, "remote backup requires endpoint, bucket, region, prefix, access_key, and allow_insecure")
    if any(not isinstance(body[key], str) for key in required - {"allow_insecure"}) or not isinstance(body["allow_insecure"], bool):
        raise PanelError(400, "remote backup configuration has invalid field types")
    secret_key = body.get("secret_key", "")
    if not isinstance(secret_key, str):
        raise PanelError(400, "remote backup configuration has invalid field types")
    if not secret_key:
        try:
            secret_key = s3_backup.load_s3_config().secret_key
        except s3_backup.S3ConfigError as exc:
            raise PanelError(400, "no stored secret key to keep; enter the secret key for this destination") from exc
    config = s3_backup.S3Config(**{**body, "secret_key": secret_key})
    try:
        s3_backup.write_s3_config(config)
    except s3_backup.S3ConfigError as exc:
        raise PanelError(400, s3_backup.redact_s3_secrets(str(exc), config)) from exc
    return 200, {"config": _s3_config_payload(config)}


def _delete_remote_backup(principal, match, query, body):
    s3_backup.clear_s3_config()
    return 200, {"ok": True}


def _put_backup_schedule(principal, match, query, body):
    allowed = {"cadence", "time", "weekday", "destination_dir", "upload_s3"}
    if any(key not in allowed for key in body):
        raise PanelError(400, "backup schedule contains an unsupported field")
    cadence, at = body.get("cadence"), body.get("time")
    if cadence not in {"daily", "weekly"} or not isinstance(at, str) or not backup_schedule.validate_time(at):
        raise PanelError(400, "backup schedule requires daily or weekly cadence and time in HH:MM format")
    weekday = body.get("weekday")
    if cadence == "weekly" and (not isinstance(weekday, str) or not backup_schedule.validate_weekday(weekday)):
        raise PanelError(400, "weekly backup schedule requires a valid weekday")
    if cadence == "daily" and weekday is not None:
        raise PanelError(400, "daily backup schedule does not accept a weekday")
    destination_dir = body.get("destination_dir")
    if destination_dir is not None and not isinstance(destination_dir, str):
        raise PanelError(400, "backup destination_dir must be a string or null")
    upload_s3 = body.get("upload_s3", False)
    if not isinstance(upload_s3, bool):
        raise PanelError(400, "backup upload_s3 must be a boolean")
    result = backup_schedule.install_schedule(backup_schedule.BackupSchedule(cadence, at, destination_dir, upload_s3, weekday))
    return _operation_status(result), _runtime_payload(result)


def _delete_backup_schedule(principal, match, query, body):
    result = backup_schedule.disable_schedule()
    return _operation_status(result), _runtime_payload(result)


def _firewall_ports_payload() -> dict:
    state = firewall_ports.status()
    return {
        "installed": state.installed, "active": state.active,
        "default_incoming": state.default_incoming, "default_outgoing": state.default_outgoing,
        "ssh_port": state.ssh_port, "message": state.message,
        "rules": [asdict(rule) for rule in state.rules],
        "presets": [dict(preset) for preset in firewall_ports.PRESETS],
    }


def _get_firewall(principal, match, query, body):
    enforcement = fail2ban_docker.enforcement_status()
    return 200, {
        "enforcement": asdict(enforcement),
        "action_stale": fail2ban_docker.action_is_stale(),
        "ipv6_capable": fail2ban_docker.ipv6_capable(),
        "ports": _firewall_ports_payload(),
    }


_PORT_RULE_FIELDS = frozenset({"port", "protocol", "source", "comment", "action", "confirm"})


def _port_rule_request(body: dict, *, allowed_actions: tuple[str, ...]) -> tuple[str, str, str, str | None, str | None, bool]:
    """Validate a port-rule request and resolve the SSH confirmation.

    The confirmation is resolved here rather than in `firewall_ports` so the
    domain module keeps one meaning for `force` -- "the caller has accepted the
    lockout risk" -- and the panel stays the only place that decides what
    accepting it looks like over HTTP.
    """
    if any(key not in _PORT_RULE_FIELDS for key in body):
        raise PanelError(400, "port rule contains an unsupported field")
    action = str(body.get("action") or allowed_actions[0]).strip().lower()
    if action not in allowed_actions:
        raise PanelError(400, f"invalid action: {action!r}; accepted values: {', '.join(allowed_actions)}")
    try:
        port = firewall_ports.validate_port(body.get("port"))
        protocol = firewall_ports.validate_protocol(body.get("protocol") or "tcp")
        source = firewall_ports.validate_source(body.get("source"))
        comment = firewall_ports.validate_comment(body.get("comment"))
    except ValueError as exc:
        raise PanelError(400, str(exc)) from exc
    ssh = firewall_ports.ssh_port()
    force = body.get("confirm") == str(ssh)
    return action, port, protocol, source, comment, force


def _post_firewall_port(principal, match, query, body):
    action, port, protocol, source, comment, force = _port_rule_request(body, allowed_actions=("allow", "deny"))
    if action == "allow":
        result = firewall_ports.allow_port(port, protocol, source=source, comment=comment)
    else:
        result = firewall_ports.deny_port(port, protocol, source=source, comment=comment, force=force)
    payload = _runtime_payload(result)
    payload["ports"] = _firewall_ports_payload()
    return _operation_status(result), payload


def _delete_firewall_port(principal, match, query, body):
    action, port, protocol, source, _comment, force = _port_rule_request(
        body, allowed_actions=("allow", "deny", "reject"),
    )
    result = firewall_ports.delete_rule(port, protocol, action, source=source, force=force)
    payload = _runtime_payload(result)
    payload["ports"] = _firewall_ports_payload()
    return _operation_status(result), payload


def _post_firewall_enable(principal, match, query, body):
    result = firewall_ports.enable()
    payload = _runtime_payload(result)
    payload["ports"] = _firewall_ports_payload()
    return _operation_status(result), payload


def _post_firewall_disable(principal, match, query, body):
    # Disabling opens every port at once, so it carries the same typed
    # confirmation the destructive site operations use.
    if body.get("confirm") != "disable":
        raise PanelError(400, "disabling the firewall requires confirm to be exactly \"disable\"")
    result = firewall_ports.disable()
    payload = _runtime_payload(result)
    payload["ports"] = _firewall_ports_payload()
    return _operation_status(result), payload


def _post_firewall_install(principal, match, query, body):
    job = panel_jobs.create_job("firewall.install", None)

    def operation():
        result = fail2ban_host.ensure_fail2ban_host()
        payload = {
            "ok": result.exit_code == 0,
            "exit_code": result.exit_code,
            "message": result.message,
            "changed": result.changed,
            "installed": result.installed,
            "health_ok": result.health_ok,
        }
        if result.exit_code != 0:
            raise RuntimeError(result.message or "firewall install failed")
        return payload, None
    _start_job(job, operation, actor=_principal_username(principal))
    return 202, {"job_id": job.id}


def _smtp_config_payload(config):
    return {"host": config.host, "port": config.port, "sender": config.sender, "username": config.username, "tls": config.tls}


def _get_smtp(principal, match, query, body):
    try:
        config = smtp.load_smtp_config()
    except smtp.SMTPConfigError:
        return 200, {"configured": False, "status": []}
    return 200, {"configured": True, "config": _smtp_config_payload(config), "status": smtp.smtp_status_lines(config)}


def _put_smtp(principal, match, query, body):
    """Write the SMTP transport. A blank `password` keeps the stored one.

    Same shape as `_put_remote_backup`, and for the same reason: the password is
    write-only, so a client editing the sender address cannot round-trip a value
    it is never allowed to read. Demanding it on every write means changing a
    port re-types a mail password, and a client sending "" to satisfy a required
    field silently replaces a working credential with an empty one.
    """
    required = {"host", "port", "sender", "username", "tls"}
    allowed = required | {"password"}
    if any(key not in allowed for key in body) or not required <= set(body):
        raise PanelError(400, "SMTP requires host, port, sender, username, and tls")
    if any(not isinstance(body[key], str) for key in required - {"port"}) or not isinstance(body["port"], int) or isinstance(body["port"], bool):
        raise PanelError(400, "SMTP configuration has invalid field types")
    if not 1 <= body["port"] <= 65535 or body["tls"] not in smtp.TLS_MODES:
        raise PanelError(400, "SMTP port or tls mode is invalid")
    password = body.get("password", "")
    if not isinstance(password, str):
        raise PanelError(400, "SMTP configuration has invalid field types")
    if not password:
        try:
            password = smtp.load_smtp_config().password
        except smtp.SMTPConfigError as exc:
            raise PanelError(400, "no stored password to keep; enter the SMTP password") from exc
    config = smtp.SMTPConfig(**{**body, "password": password})
    smtp.write_smtp_config(config)
    return 200, {"config": _smtp_config_payload(config)}


def _post_smtp_test(principal, match, query, body):
    if set(body) != {"recipient"} or not isinstance(body.get("recipient"), str):
        raise PanelError(400, "SMTP test requires a recipient string")
    try:
        config = smtp.load_smtp_config()
        message = smtp.send_test_message(config, body["recipient"])
    except smtp.SMTPConfigError as exc:
        if "config" in locals():
            raise PanelError(400, smtp.redact_smtp_secret(str(exc), config)) from exc
        raise PanelError(400, str(exc)) from exc
    except (OSError, ValueError) as exc:
        raise PanelError(500, smtp.redact_smtp_secret(str(exc), config)) from exc
    return 200, {"message": smtp.redact_smtp_secret(message, config)}


def _delete_smtp(principal, match, query, body):
    smtp.clear_smtp_config()
    return 200, {"ok": True}


def _get_instance(principal, match, query, body):
    facts = operational_inspection.aggregate_info()
    paths = settings.PATHS
    return 200, {
        "version": __version__,
        "paths": {"install_root": paths.install_root, "config_dir": paths.config_dir, "state_dir": paths.state_dir, "log_dir": paths.log_dir},
        "docker_version": facts.docker_version,
        "traefik": facts.traefik_message,
        "site_count": len(facts.sites),
    }


def _get_basic_auth_inventory(principal, match, query, body):
    rows = []
    for site in sorted(list_sites(), key=lambda item: str(item.get("domain", ""))):
        domain = site.get("domain")
        if not isinstance(domain, str):
            continue
        basic_auth = site_security.load_security(domain)["basic_auth"]
        rows.append({"domain": domain, "enabled": basic_auth["enabled"], "username": basic_auth["username"]})
    return 200, {"basic_auth": rows}


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
    job = panel_jobs.create_job("system.traefik.restart", None)

    def operation():
        result = traefik.restart_traefik_existing()
        payload = _runtime_payload(result)
        if result.exit_code != 0:
            raise RuntimeError(result.message or "traefik restart failed")
        return payload, None
    _start_job(job, operation, actor=_principal_username(principal))
    return 202, {"job_id": job.id}
def _get_site(principal, match, query, body): return 200, api_site_detail(match.group("domain"))
def _get_health(principal, match, query, body): return 200, api_site_health(match.group("domain"))
def _get_site_services(principal, match, query, body): return 200, api_site_services(match.group("domain"))
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


_CREATE_SITE_FIELDS = frozenset({
    "domain", "flavor", "php_version", "letsencrypt", "dns_provider",
    "admin_user", "admin_email", "object_cache", "page_cache", "enable_sftp", "dry_run",
})


def _post_create_site(principal, match, query, body):
    if any(key not in _CREATE_SITE_FIELDS for key in body):
        raise PanelError(400, "site creation contains an unsupported field")
    domain, flavor = body.get("domain"), body.get("flavor")
    if not isinstance(domain, str) or not domain:
        raise PanelError(400, "site creation requires a domain")
    try:
        validate_domain(domain)
    except ValueError as exc:
        raise PanelError(400, str(exc))
    if not isinstance(flavor, str) or flavor not in _ALLOWED_PANEL_FLAVORS:
        raise PanelError(400, f"unknown site flavor: {flavor}")
    php_version = body.get("php_version") if body.get("php_version") is not None else DEFAULT_PHP_VERSION
    for key, value, allowed in (
        ("php_version", php_version, SUPPORTED_PHP_VERSIONS),
        ("letsencrypt", body.get("letsencrypt"), LETSENCRYPT_MODES),
        ("dns_provider", body.get("dns_provider"), DNS_PROVIDERS),
    ):
        if value is not None and (not isinstance(value, str) or value not in allowed):
            raise PanelError(400, f"invalid {key}: {value!r}; accepted values: {', '.join(allowed)}")
    object_cache = body.get("object_cache")
    if object_cache is not None:
        if not isinstance(object_cache, str):
            raise PanelError(400, "object_cache must be a string")
        try:
            object_cache = validate_object_cache(object_cache)
        except ValueError as exc:
            raise PanelError(400, str(exc)) from exc
    page_cache = body.get("page_cache")
    if page_cache is not None:
        if not isinstance(page_cache, str):
            raise PanelError(400, "page_cache must be a string")
        try:
            page_cache = validate_page_cache(page_cache)
        except ValueError as exc:
            raise PanelError(400, str(exc)) from exc
    if (object_cache is not None or page_cache is not None) and flavor not in WORDPRESS_FLAVORS:
        raise PanelError(400, f"cache integration requires a WordPress site: {domain}")
    enable_sftp = body.get("enable_sftp")
    if enable_sftp is not None and not isinstance(enable_sftp, bool):
        raise PanelError(400, "enable_sftp must be a boolean")
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
                domain=domain, flavor=flavor, php_version=php_version,
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

        if object_cache is not None or page_cache is not None:
            panel_jobs.append_step(job.id, "applying cache configuration")
            current = _cache_definition(domain)
            desired = replace(
                current,
                page_cache=page_cache if page_cache is not None else current.page_cache,
                object_cache=object_cache if object_cache is not None else current.object_cache,
                use_redis=(object_cache if object_cache is not None else current.object_cache) == "redis",
            )
            ensure_site_scaffold(desired)
            start_site_runtime(domain)
            ordered_actions = [
                site_cache.install_page_cache(domain, desired.page_cache),
                site_cache.render_cache_nginx(domain),
                site_cache.set_wp_cache_constants(domain),
            ]
            if desired.object_cache == "redis" or object_cache is not None:
                ordered_actions.append(site_cache.wire_redis_backend(domain))
            ordered_actions = [_panel_cache_action(action) for action in ordered_actions]
            cache_result = site_cache.CacheConfigurationResult(desired, tuple(ordered_actions), ())
            payload["cache"] = {
                "page_cache": desired.page_cache, "object_cache": desired.object_cache,
                "ok": cache_result.exit_code == 0,
            }
            if cache_result.exit_code != 0:
                raise RuntimeError(cache_result.message or "site cache configuration failed")

        if enable_sftp is True:
            panel_jobs.append_step(job.id, "provisioning sftp")
            sftp_password = generated_secret()[:16]
            sftp_result = sftp.ensure_sftp_container(domain, password=sftp_password)
            payload["sftp"] = _sftp_payload(sftp_result)
            if sftp_result.exit_code != 0:
                raise RuntimeError(sftp_result.message or "sftp provisioning failed")
            one_time = {**(one_time or {}), "sftp_password": sftp_password}

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
    domain = match.group("domain")
    _known_domain(domain)
    planned = _dry_run(body, ["create backup"], [], "site")
    if planned:
        return planned
    job = panel_jobs.create_job("site.backup.create", domain)

    def operation():
        _, payload = api_site_backup_create(domain)
        if not payload.get("ok"):
            raise RuntimeError(payload.get("message") or "backup failed")
        return payload, None
    _start_job(job, operation, actor=_principal_username(principal))
    return 202, {"job_id": job.id}


def _post_restore(principal, match, query, body):
    domain = match.group("domain")
    _known_domain(domain)
    archive = body.get("archive")
    if not isinstance(archive, str) or not archive:
        raise PanelError(400, "restore requires an archive name")
    if archive not in {item.name for item in list_backup_archives(domain)}:
        raise PanelError(404, f"backup archive not found for {domain}: {archive}")
    planned = _dry_run(body, [f"restore {archive}"], [domain], "site")
    if planned:
        return planned
    job = panel_jobs.create_job("site.restore", domain)

    def operation():
        _, payload = api_site_restore(domain, archive)
        if not payload.get("ok"):
            raise RuntimeError(payload.get("message") or "restore failed")
        return payload, None
    _start_job(job, operation, actor=_principal_username(principal))
    return 202, {"job_id": job.id}


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


def _post_wp(principal, match, query, body):
    domain = match.group("domain")
    _known_domain(domain)
    wp_args = body.get("args") or []
    if not wp_args or not all(isinstance(arg, str) and "\x00" not in arg for arg in wp_args):
        raise PanelError(400, "wp requires a non-empty list of string arguments")
    planned = _dry_run(body, [f"wp {' '.join(wp_args)}"], [domain], "site")
    if planned:
        return planned
    job = panel_jobs.create_job("site.wp", domain)

    def operation():
        # ponytail: run_wp_cli blocks on subprocess.run (no incremental hook to
        # stream into append_step); the job still frees the request immediately
        # and the full stdout/stderr land in the job result on completion.
        # Add a progress-capable run_wp_cli variant if live tailing is needed.
        # api_site_wp raises PanelError on a real execution failure (not ran);
        # that propagates through and fails the job, matching house rule 1.1.
        _, payload = api_site_wp(domain, wp_args)
        return payload, None
    _start_job(job, operation, actor=_principal_username(principal))
    return 202, {"job_id": job.id}


def _post_config(principal, match, query, body):
    domain = match.group("domain")
    _known_domain(domain)
    allowed = {"php_version", "flavor", "letsencrypt", "password", "dry_run", *_CONFIG_PHP_KEYS}
    if any(key not in allowed for key in body):
        raise PanelError(400, "config contains an unsupported field")
    if any(key in body for key in _CONFIG_PHP_KEYS):
        if any(key in body for key in _CONFIG_LIFECYCLE_KEYS):
            raise PanelError(400, "PHP ini settings cannot be combined with other config changes")
        # PHP ini settings are already fast/synchronous via the dedicated
        # php-settings route; this alias keeps that behavior unconverted.
        return api_php_settings(domain, body)
    flavor = _validate_config_lifecycle_body(domain, body)
    if body.get("dry_run") is True:
        try:
            result = site_lifecycle.update_site(site_lifecycle.UpdateSiteRequest(
                domain=domain, php_version=body.get("php_version"), flavor=flavor,
                letsencrypt=body.get("letsencrypt"), password=body.get("password"), dry_run=True,
            ))
        except site_lifecycle.SiteLifecycleError as exc:
            raise PanelError(400, str(exc))
        return 200, {"changes": list(result.changes), "restarts": [domain] if result.changes else [], "scope": "site"}
    job = panel_jobs.create_job("site.config", domain)

    def operation():
        try:
            result = site_lifecycle.update_site(site_lifecycle.UpdateSiteRequest(
                domain=domain, php_version=body.get("php_version"), flavor=flavor,
                letsencrypt=body.get("letsencrypt"), password=body.get("password"), dry_run=False,
            ))
        except site_lifecycle.SiteLifecycleError as exc:
            raise RuntimeError(str(exc)) from exc
        payload = {
            "ok": result.exit_code == 0, "changes": list(result.changes), "touched": list(result.touched),
            "runtime": _runtime_payload(result.runtime),
        }
        if result.exit_code != 0:
            raise RuntimeError(result.runtime.message or "site config update failed")
        return payload, None
    _start_job(job, operation, actor=_principal_username(principal))
    return 202, {"job_id": job.id}


def _post_ssl_preflight(principal, match, query, body):
    domain = match.group("domain")
    _known_domain(domain)
    result = certificate_lifecycle.preflight_ssl(domain)
    return 200, {
        "domain": result.domain,
        "passed": result.passed,
        "mode": result.mode,
        "message": result.message,
        "a_records": list(result.a_records),
        "aaaa_records": list(result.aaaa_records),
        "public_ipv4": list(result.public_ipv4),
        "public_ipv6": list(result.public_ipv6),
    }


def _get_admin_file_managers(principal, match, query, body):
    _file_manager_gate()
    from .site_layout import list_sites as _list_site_dirs
    domains = _list_site_dirs()
    result = []
    for entry in domains:
        try:
            domain = entry["domain"]
            state = panel_file_manager.get_file_manager_state(domain)
            if state.state in ("ready", "starting", "idle-warning"):
                result.append({
                    "domain": domain,
                    "state": state.state,
                    "provider": state.provider,
                    "enabled_at": state.enabled_at,
                    "last_lease_at": state.last_lease_at,
                    "idle_expires_at": state.idle_expires_at,
                    "active_leases": state.active_leases,
                    "health": state.health,
                })
        except (KeyError, OSError, TypeError, ValueError):
            continue
    return 200, result


# ---- file-manager routes ----

def _get_file_manager_status(principal, match, query, body):
    _file_manager_gate()
    domain = match.group("domain")
    _known_domain(domain)
    state = panel_file_manager.get_file_manager_state(domain)
    return 200, {
        "state": state.state,
        "provider": state.provider,
        "health": state.health,
        "enabled_at": state.enabled_at,
        "last_lease_at": state.last_lease_at,
        "idle_expires_at": state.idle_expires_at,
        "active_leases": state.active_leases,
        "error": state.error,
    }


def _post_file_manager_enable(principal, match, query, body):
    _file_manager_gate()
    domain = match.group("domain")
    _known_domain(domain)
    username = _principal_username(principal)
    if not panel_auth.fm_enable_allowed(username):
        return 429, {"error": "file manager enable rate limit reached; try again later"}
    try:
        result = panel_file_manager.enable_file_manager(domain, username, quantum_provider)
    except panel_file_manager.FileManagerError as exc:
        return _file_manager_error(exc)
    panel_auth.register_fm_enable(username)
    return 200, result, {"Set-Cookie": _file_manager_cookie(domain, username)}


def _post_file_manager_lease(principal, match, query, body):
    _file_manager_gate()
    domain = match.group("domain")
    _known_domain(domain)
    state = panel_file_manager.get_file_manager_state(domain)
    if state.state != "ready":
        raise PanelError(409, "file manager is not ready")
    username = _principal_username(principal)
    try:
        result = panel_file_manager.create_lease(domain, username)
    except panel_file_manager.FileManagerError as exc:
        return _file_manager_error(exc)
    return 200, result, {"Set-Cookie": _file_manager_cookie(domain, username)}


def _delete_file_manager(principal, match, query, body):
    _file_manager_gate()
    domain = match.group("domain")
    _known_domain(domain)
    try:
        result = panel_file_manager.disable_file_manager(domain, quantum_provider)
    except panel_file_manager.FileManagerError as exc:
        return _file_manager_error(exc)
    return 200, result


def _delete_file_manager_metadata(principal, match, query, body):
    _file_manager_gate()
    domain = _known_domain(match.group("domain"))
    if body.get("confirm") != "reset file manager metadata":
        raise PanelError(400, "metadata reset requires confirmation")
    quantum_provider.reset_metadata(domain)
    _emit_event("file_manager.reset", domain=domain, actor=_principal_username(principal))
    return 200, {"ok": True}


def _proxy_file_manager(request, principal, match, query, body):
    _file_manager_gate()
    domain = _known_domain(match.group("domain"))
    _validate_file_manager_cookie(request.headers, domain, _principal_username(principal))
    port = quantum_provider.provider_port(domain)
    upstream_path = "/" + unquote(match.group("path")).lstrip("/")
    parsed_query = urlparse(request.path).query
    if parsed_query:
        upstream_path += "?" + parsed_query
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=PANEL_SOCKET_TIMEOUT)
    try:
        connection.putrequest(request.command, upstream_path, skip_host=True, skip_accept_encoding=True)
        forwarded = {"content-type", "content-length", "content-disposition", "range"}
        forwarded.update(name for name in request.headers if name.lower().startswith("if-"))
        for name, value in request.headers.items():
            lower = name.lower()
            if lower in forwarded:
                connection.putheader(name, value)
        connection.putheader("X-Forwarded-User", _principal_username(principal))
        connection.putheader("X-Forwarded-Proto", "http")
        connection.endheaders()
        if isinstance(body, RawBody):
            remaining = body.content_length
            while remaining:
                chunk = body.stream.read(min(1024 * 1024, remaining))
                if not chunk:
                    break
                connection.send(chunk)
                remaining -= len(chunk)
        response = connection.getresponse()
    except (http.client.HTTPException, OSError, TimeoutError):
        connection.close()
        raise PanelError(502, "file manager proxy unavailable") from None
    response_headers = {}
    for name in ("Content-Type", "Content-Length", "Content-Disposition"):
        value = response.getheader(name)
        if value is not None:
            response_headers[name] = value
    location = response.getheader("Location")
    if location is not None:
        response_headers["Location"] = location.replace(
            f"http://127.0.0.1:{port}", f"/api/sites/{domain}/file-manager/proxy",
        )
    return response.status, _FileManagerProxyResponse(response, connection, response_headers)


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
    Route("POST", re.compile(r"^/api/sites$"), _post_create_site, RouteMeta("site.create", "system", True)),
    Route("GET", re.compile(r"^/api/metrics$"), _get_metrics, RouteMeta("system.metrics", "system")),
    Route("GET", re.compile(r"^/api/metrics/latest$"), _get_metrics_latest, RouteMeta("system.metrics", "system")),
    Route("GET", re.compile(r"^/api/system/services$"), _get_system_services, RouteMeta("system.services", "system")),
    Route("POST", re.compile(r"^/api/system/traefik/restart$"), _post_traefik_restart, RouteMeta("system.traefik.restart", "system", True, True)),
    Route("GET", re.compile(r"^/api/system/diagnostics$"), _get_system_diagnostics, RouteMeta("system.diagnostics", "system")),
    Route("GET", re.compile(r"^/api/settings$"), _get_settings, RouteMeta("settings.read", "system")),
    Route("PUT", re.compile(r"^/api/settings/telemetry$"), _put_settings_telemetry, RouteMeta("settings.telemetry", "system", True)),
    Route("POST", re.compile(r"^/api/settings/exposure$"), _post_settings_exposure, RouteMeta("settings.exposure", "system", True, True)),
    Route("DELETE", re.compile(r"^/api/settings/exposure$"), _delete_settings_exposure, RouteMeta("settings.exposure.disable", "system", True, True)),
    Route("GET", re.compile(r"^/api/backup/remote$"), _get_remote_backup, RouteMeta("backup.remote.read", "system")),
    Route("PUT", re.compile(r"^/api/backup/remote$"), _put_remote_backup, RouteMeta("backup.remote.write", "system", True)),
    Route("DELETE", re.compile(r"^/api/backup/remote$"), _delete_remote_backup, RouteMeta("backup.remote.clear", "system", True, True)),
    Route("PUT", re.compile(r"^/api/backup/schedule$"), _put_backup_schedule, RouteMeta("backup.schedule.write", "system", True)),
    Route("DELETE", re.compile(r"^/api/backup/schedule$"), _delete_backup_schedule, RouteMeta("backup.schedule.disable", "system", True, True)),
    Route("GET", re.compile(r"^/api/firewall$"), _get_firewall, RouteMeta("firewall.read", "system")),
    Route("POST", re.compile(r"^/api/firewall/install$"), _post_firewall_install, RouteMeta("firewall.install", "system", True)),
    Route("POST", re.compile(r"^/api/firewall/ports$"), _post_firewall_port, RouteMeta("firewall.port.add", "system", True, True)),
    Route("DELETE", re.compile(r"^/api/firewall/ports$"), _delete_firewall_port, RouteMeta("firewall.port.remove", "system", True, True)),
    Route("POST", re.compile(r"^/api/firewall/enable$"), _post_firewall_enable, RouteMeta("firewall.enable", "system", True, True)),
    Route("POST", re.compile(r"^/api/firewall/disable$"), _post_firewall_disable, RouteMeta("firewall.disable", "system", True, True)),
    Route("GET", re.compile(r"^/api/notifications/smtp$"), _get_smtp, RouteMeta("notify.smtp.read", "system")),
    Route("PUT", re.compile(r"^/api/notifications/smtp$"), _put_smtp, RouteMeta("notify.smtp.write", "system", True)),
    Route("POST", re.compile(r"^/api/notifications/smtp/test$"), _post_smtp_test, RouteMeta("notify.smtp.test", "system", True)),
    Route("DELETE", re.compile(r"^/api/notifications/smtp$"), _delete_smtp, RouteMeta("notify.smtp.clear", "system", True, True)),
    Route("GET", re.compile(r"^/api/instance$"), _get_instance, RouteMeta("instance.read", "system")),
    Route("GET", re.compile(r"^/api/security/basic-auth$"), _get_basic_auth_inventory, RouteMeta("security.basicauth.list", "system")),
    Route("GET", re.compile(r"^/api/jobs$"), _get_jobs, RouteMeta("job.list", "system")),
    Route("GET", re.compile(r"^/api/jobs/(?P<job_id>[^/]+)$"), _get_job, RouteMeta("job.read", "system")),
    Route("GET", re.compile(r"^/api/events$"), _get_events, RouteMeta("event.list", "system")),
    Route("GET", re.compile(r"^/api/stream$"), _get_stream, RouteMeta("event.stream", "system")),
    Route("DELETE", re.compile(r"^/api/sites/(?P<domain>[^/]+)$"), _delete_site, RouteMeta("site.delete", "site", True, True)),
    Route("GET", re.compile(r"^/api/sites/(?P<domain>[^/]+)$"), _get_site, RouteMeta("site.read", "site")),
    Route("GET", re.compile(r"^/api/sites/(?P<domain>[^/]+)/health$"), _get_health, RouteMeta("site.health", "site")),
    Route("GET", re.compile(r"^/api/sites/(?P<domain>[^/]+)/services$"), _get_site_services, RouteMeta("site.services", "site")),
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
    Route("GET", re.compile(r"^/api/sites/(?P<domain>[^/]+)/file-manager$"), _get_file_manager_status, RouteMeta("file_manager.status", "site")),
    Route("POST", re.compile(r"^/api/sites/(?P<domain>[^/]+)/file-manager/enable$"), _post_file_manager_enable, RouteMeta("file_manager.enable", "site", True)),
    Route("POST", re.compile(r"^/api/sites/(?P<domain>[^/]+)/file-manager/lease$"), _post_file_manager_lease, RouteMeta("file_manager.lease", "site", True)),
    Route("DELETE", re.compile(r"^/api/sites/(?P<domain>[^/]+)/file-manager/metadata$"), _delete_file_manager_metadata, RouteMeta("file_manager.metadata_reset", "system", True, True)),
    Route("GET", re.compile(r"^/api/sites/(?P<domain>[^/]+)/file-manager/proxy/(?P<path>.*)$"), _proxy_file_manager, RouteMeta("file_manager.proxy", "site", raw_body=True, max_body=_FM_PROXY_MAX_BODY)),
    Route("POST", re.compile(r"^/api/sites/(?P<domain>[^/]+)/file-manager/proxy/(?P<path>.*)$"), _proxy_file_manager, RouteMeta("file_manager.proxy", "site", mutates=True, raw_body=True, max_body=_FM_PROXY_MAX_BODY)),
    Route("PUT", re.compile(r"^/api/sites/(?P<domain>[^/]+)/file-manager/proxy/(?P<path>.*)$"), _proxy_file_manager, RouteMeta("file_manager.proxy", "site", mutates=True, raw_body=True, max_body=_FM_PROXY_MAX_BODY)),
    Route("PATCH", re.compile(r"^/api/sites/(?P<domain>[^/]+)/file-manager/proxy/(?P<path>.*)$"), _proxy_file_manager, RouteMeta("file_manager.proxy", "site", mutates=True, raw_body=True, max_body=_FM_PROXY_MAX_BODY)),
    Route("DELETE", re.compile(r"^/api/sites/(?P<domain>[^/]+)/file-manager/proxy/(?P<path>.*)$"), _proxy_file_manager, RouteMeta("file_manager.proxy", "site", mutates=True, raw_body=True, max_body=_FM_PROXY_MAX_BODY)),
    Route("DELETE", re.compile(r"^/api/sites/(?P<domain>[^/]+)/file-manager$"), _delete_file_manager, RouteMeta("file_manager.disable", "site", True)),
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
    Route("POST", re.compile(r"^/api/sites/(?P<domain>[^/]+)/ssl/preflight$"), _post_ssl_preflight, RouteMeta("site.ssl.preflight", "site", True)),
    Route("GET", re.compile(r"^/api/admin/file-managers$"), _get_admin_file_managers, RouteMeta("file_manager.admin_list", "system")),
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

        def _send_json(self, status: int, payload: dict, headers: dict[str, str] | None = None) -> None:
            self._close_if_body_unread()
            data = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            if self.close_connection:
                self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)

        def _send_file_manager_proxy(self, status: int, proxy: _FileManagerProxyResponse) -> None:
            self._close_if_body_unread()
            self.send_response(status)
            for name, value in proxy.headers.items():
                self.send_header(name, value)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            if self.close_connection:
                self.send_header("Connection", "close")
            self.end_headers()
            try:
                while True:
                    chunk = proxy.response.read(1024 * 1024)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
            finally:
                proxy.response.close()
                proxy.connection.close()

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
            if not panel_auth.login_required() and panel_setup.setup_secret_matches(token):
                # A domainless panel prints no run token, so the setup link is
                # the browser's only credential. It authenticates the setup
                # routes and nothing else -- see `authorize`.
                return {"_setup_secret": token, "username": None, "role": None, "sites": ()}
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
                if path.startswith(_CLIENT_ROUTE_PREFIXES):
                    target = STATIC_DIR / "index.html"
                else:
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
                self.send_header("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; frame-ancestors 'self'; frame-src 'self'")
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
                if route is not None and route.meta.action.startswith("site.files.") and os.environ.get("WPFY_FM_LEGACY_API", "1") != "1":
                    raise PanelError(404, "file manager legacy api disabled")
                principal = None if route is not None and route.meta.scope == "public" else self._authenticate()
                if principal is None and (route is None or route.meta.scope != "public"):
                    raise PanelError(401, "missing or invalid token")
                if route is None:
                    raise PanelError(404, f"unknown endpoint: {parsed.path}")
                match = route.pattern.fullmatch(parsed.path)
                domain = match.groupdict().get("domain") if match else None
                if route.meta.scope != "public":
                    authorize(principal, route.meta, domain)
                if route.meta.action.startswith("file_manager."):
                    _file_manager_gate()
                if route.meta.mutates:
                    _assert_same_origin(self.headers, self.headers.get("Host", ""))
                if route.meta.scope == "setup" and panel_auth.login_required():
                    raise PanelError(410, "first-run setup is permanently closed")
                if route.meta.scope == "setup-session" and (
                    not isinstance(principal, dict) or principal.get("_setup_session") is not True
                ):
                    raise PanelError(410, "setup enrollment is no longer available")
                if route.meta.raw_body:
                    body = RawBody(self.rfile, 0) if route.meta.action == "file_manager.proxy" and method == "GET" else self._read_raw_body(route.meta.max_body)
                elif method in {"POST", "PUT", "DELETE"}:
                    body = self._read_body(route.meta.max_body)
                else:
                    body = {}
                if route.meta.action in {"auth.login", "setup.create", "setup.totp"}:
                    body["_socket_client"] = resolve_client_address(
                        self.client_address[0],
                        self.headers.get("X-Forwarded-For"),
                        trusted_edge_networks(),
                    )
                if route.meta.action in {"setup.status", "setup.create"}:
                    # "Can this request have come from off the host?" -- not
                    # "is this edge-bound?". A domainless panel is not edge-bound
                    # and is still on the open internet, and keying the setup
                    # gate to edge_bind alone left `--public` creating the first
                    # administrator with no secret at all.
                    body["_edge_bind"] = config.edge_bind or config.self_signed_tls
                if route.meta.action in {"file_manager.proxy", "event.stream"}:
                    result = route.handler(self, principal, match, parse_qs(parsed.query), body)
                else:
                    result = route.handler(principal, match, parse_qs(parsed.query), body)
                response_headers = None
                if len(result) == 3:
                    status, payload, response_headers = result
                else:
                    status, payload = result
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
                    _emit_event(route.meta.action, domain=domain, actor=actor)
            except PanelError as exc:
                self._send_json(exc.status, {"error": str(exc)}, exc.headers); return
            except (FileNotFoundError, ValueError) as exc:
                self._send_json(400, {"error": str(exc)}); return
            except (OSError, subprocess.SubprocessError) as exc:
                self._send_json(500, {"error": str(exc)}); return
            except Exception:
                _LOGGER.exception("unhandled panel API error")
                self._send_json(500, {"error": "internal server error"}); return
            if isinstance(payload, _StreamAlreadySent):
                return
            if isinstance(payload, _FileManagerProxyResponse):
                self._send_file_manager_proxy(status, payload)
            elif isinstance(payload, files.Download):
                try:
                    self._send_download(status, payload)
                finally:
                    payload.stream.close()
            else:
                self._send_json(status, payload, response_headers)

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

        def do_PATCH(self) -> None:
            if urlparse(self.path).path.startswith("/api/"): self._handle_api("PATCH")
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
        panel_exposure.validate_panel_edge_bind(config.host)
    elif config.self_signed_tls:
        from . import panel_exposure

        # The one non-loopback bind that is not edge-bound. It is allowed only
        # because the socket is wrapped in TLS below before the first accept,
        # and only for the address `expose --no-domain` issued the certificate
        # for -- a different address would answer with a certificate whose
        # fingerprint the operator was never given.
        try:
            validate_loopback_host(config.host)
        except ValueError:
            panel_exposure.validate_edge_bind(config.host)
            if config.host != panel_exposure.public_bind_address():
                raise ValueError(
                    f"the self-signed certificate belongs to this host's public address, "
                    f"not {config.host}; run: wpfy panel --public"
                ) from None
    else:
        validate_loopback_host(config.host)
    _rediscover_file_managers()
    server = _PanelHTTPServer((config.host, config.port), make_panel_handler(config))
    if config.self_signed_tls:
        from . import panel_tls

        # Wrapped before the first accept, so there is no window in which the
        # panel answers a plaintext request on a public address.
        certificate = panel_tls.ensure_self_signed(config.host)
        server.socket = panel_tls.ssl_context(certificate).wrap_socket(server.socket, server_side=True)
    server.daemon_threads = True
    threading.Thread(
        target=_idle_reap_loop,
        args=(server._reaper_stop,),
        name="wpfy-fm-reaper",
        daemon=True,
    ).start()
    return server


def panel_url(config: PanelConfig, port: int | None = None) -> str:
    scheme = "https" if config.self_signed_tls else "http"
    base = f"{scheme}://{config.host}:{port or config.port}/"
    if panel_auth.login_required() or config.self_signed_tls:
        # The run token stands in for an account on a loopback panel, where
        # reaching it already proves shell access. On a public address it is a
        # full admin grant printed to the terminal and copied into the journal,
        # so the setup secret -- single-use and expiring -- is the only way in.
        return base
    return f"{base}#token={config.token}"


def serve_panel(config: PanelConfig) -> None:
    with make_panel_server(config) as server:
        server.serve_forever()
