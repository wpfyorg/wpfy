from __future__ import annotations

import hmac
import ipaddress
import json
import re
import secrets
import subprocess
from dataclasses import asdict, dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import __version__
from . import operational_inspection
from . import sftp
from . import site_lifecycle
from .site_layout import (
    backup_site,
    list_backup_archives,
    list_sites,
    restore_site,
    site_info,
)
from .site_paths import site_exists, validate_domain
from .site_runtime import (
    RuntimeResult,
    compose_command,
    site_health,
    start_site_runtime,
    stop_site_runtime,
    wp_cli_command,
)

DEFAULT_PANEL_PORT = 8642
STATIC_DIR = Path(__file__).parent / "panel_static"
_STATIC_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
}
_LOG_SERVICES = {"web", "app", "db", "redis", "sftp"}
_MAX_BODY_BYTES = 64 * 1024
_MAX_LOG_LINES = 2000


@dataclass(frozen=True, slots=True)
class PanelConfig:
    host: str = "127.0.0.1"
    port: int = DEFAULT_PANEL_PORT
    token: str = ""


class PanelError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


def generate_panel_token() -> str:
    return secrets.token_urlsafe(32)


def validate_loopback_host(host: str) -> None:
    """The panel is loopback-only by design; remote access goes over an SSH tunnel."""
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


def _known_domain(domain: str) -> str:
    try:
        validate_domain(domain)
    except ValueError as exc:
        raise PanelError(400, str(exc))
    if not site_exists(domain):
        raise PanelError(404, f"site not found: {domain}")
    return domain


def _runtime_payload(result: RuntimeResult) -> dict:
    return {
        "ok": result.exit_code == 0,
        "exit_code": result.exit_code,
        "message": result.message,
        "ran": result.ran,
        "skipped": result.skipped,
    }


def _runtime_status(result: RuntimeResult, *, not_found_ok: bool = False) -> int:
    if result.exit_code == 0:
        return 200
    if result.exit_code == 2:
        return 404 if not_found_ok else 400
    return 500


def api_overview() -> dict:
    facts = operational_inspection.aggregate_info()
    warnings = 0
    if facts.docker_version == "unavailable":
        warnings += 1
    lowered = facts.traefik_message.lower()
    if any(marker in lowered for marker in ("unavailable", "not running", "not installed", "error")):
        warnings += 1
    return {
        "version": __version__,
        "docker_version": facts.docker_version,
        "traefik": facts.traefik_message,
        "site_count": len(facts.sites),
        "warnings": warnings,
    }


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
    checks = operational_inspection.site_diagnostics(domain)
    return {"checks": [asdict(check) for check in checks]}


def api_system_diagnostics() -> dict:
    checks = operational_inspection.system_diagnostics()
    return {"checks": [asdict(check) for check in checks]}


def api_site_logs(domain: str, service: str, lines: int) -> dict:
    _known_domain(domain)
    if service and service not in _LOG_SERVICES:
        raise PanelError(400, f"unknown log service: {service}")
    lines = max(1, min(lines, _MAX_LOG_LINES))
    args = ["logs", "--no-color", "--tail", str(lines)]
    if service:
        args.append(service)
    try:
        proc = compose_command(domain, *args)
    except (OSError, subprocess.SubprocessError) as exc:
        raise PanelError(500, f"log collection failed: {exc}")
    output = proc.stdout or proc.stderr
    if proc.returncode != 0:
        raise PanelError(500, output.strip() or "docker compose logs failed")
    return {"logs": output}


def api_site_backups(domain: str) -> dict:
    _known_domain(domain)
    backups = []
    for archive in list_backup_archives(domain):
        stat = archive.stat()
        backups.append({
            "name": archive.name,
            "size_bytes": stat.st_size,
            "modified_at": int(stat.st_mtime),
        })
    return {"backups": backups}


def api_site_backup_create(domain: str) -> tuple[int, dict]:
    _known_domain(domain)
    result = backup_site(domain)
    return _runtime_status(result), _runtime_payload(result)


def api_site_restore(domain: str, archive_name: str) -> tuple[int, dict]:
    _known_domain(domain)
    known = {archive.name: archive for archive in list_backup_archives(domain)}
    archive = known.get(archive_name)
    if archive is None:
        raise PanelError(404, f"backup archive not found for {domain}: {archive_name}")
    result = restore_site(domain, str(archive))
    return _runtime_status(result), _runtime_payload(result)


def api_site_runtime(domain: str, action: str) -> tuple[int, dict]:
    _known_domain(domain)
    if action == "start":
        result = start_site_runtime(domain)
    elif action == "stop":
        result = stop_site_runtime(domain)
    elif action == "restart":
        stop = stop_site_runtime(domain)
        if stop.exit_code != 0:
            return _runtime_status(stop), _runtime_payload(stop)
        result = start_site_runtime(domain)
    else:
        raise PanelError(400, f"unknown runtime action: {action}")
    return _runtime_status(result), _runtime_payload(result)


def api_site_sftp(domain: str) -> tuple[int, dict]:
    result = sftp.sftp_status(domain)
    return _runtime_status(result, not_found_ok=True), _runtime_payload(result)


def api_site_sftp_action(domain: str, action: str) -> tuple[int, dict]:
    if action == "enable":
        result = sftp.ensure_sftp_container(domain)
    elif action == "disable":
        result = sftp.remove_sftp_container(domain)
    else:
        raise PanelError(400, f"unknown sftp action: {action}")
    return _runtime_status(result, not_found_ok=True), _runtime_payload(result)


def api_site_wp(domain: str, wp_args: list) -> tuple[int, dict]:
    _known_domain(domain)
    if not wp_args or not all(isinstance(arg, str) and "\x00" not in arg for arg in wp_args):
        raise PanelError(400, "wp requires a non-empty list of string arguments")
    if "--allow-root" not in wp_args:
        wp_args = [*wp_args, "--allow-root"]
    try:
        proc = wp_cli_command(domain, *wp_args)
    except (OSError, subprocess.SubprocessError) as exc:
        raise PanelError(500, f"wp-cli failed: {exc}")
    return 200, {
        "ok": proc.returncode == 0,
        "exit_code": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def api_site_config(domain: str, body: dict) -> tuple[int, dict]:
    _known_domain(domain)
    php_version = body.get("php_version")
    if not isinstance(php_version, str) or not php_version:
        raise PanelError(400, "config accepts only: php_version")
    try:
        result = site_lifecycle.update_site(
            site_lifecycle.UpdateSiteRequest(domain=domain, php_version=php_version)
        )
    except site_lifecycle.SiteLifecycleError as exc:
        raise PanelError(400, str(exc))
    return 200 if result.exit_code == 0 else 500, {
        "ok": result.exit_code == 0,
        "changes": list(result.changes),
        "touched": list(result.touched),
        "runtime": _runtime_payload(result.runtime),
    }


_SITE_ROUTE = re.compile(r"^/api/sites/([^/]+)(?:/([a-z-]+))?$")


def _dispatch_get(path: str, query: dict[str, list[str]]) -> tuple[int, dict]:
    if path == "/api/overview":
        return 200, api_overview()
    if path == "/api/sites":
        return 200, api_sites()
    if path == "/api/system/diagnostics":
        return 200, api_system_diagnostics()
    match = _SITE_ROUTE.match(path)
    if match:
        domain, section = match.group(1), match.group(2)
        if section is None:
            return 200, api_site_detail(domain)
        if section == "health":
            return 200, api_site_health(domain)
        if section == "diagnostics":
            return 200, api_site_diagnostics(domain)
        if section == "logs":
            service = (query.get("service") or [""])[0]
            try:
                lines = int((query.get("lines") or ["200"])[0])
            except ValueError:
                raise PanelError(400, "lines must be an integer")
            return 200, api_site_logs(domain, service, lines)
        if section == "backups":
            return 200, api_site_backups(domain)
        if section == "sftp":
            return api_site_sftp(domain)
    raise PanelError(404, f"unknown endpoint: {path}")


def _dispatch_post(path: str, body: dict) -> tuple[int, dict]:
    match = _SITE_ROUTE.match(path)
    if match and match.group(2):
        domain, section = match.group(1), match.group(2)
        if section == "backups":
            return api_site_backup_create(domain)
        if section == "restore":
            archive = body.get("archive")
            if not isinstance(archive, str) or not archive:
                raise PanelError(400, "restore requires an archive name")
            return api_site_restore(domain, archive)
        if section == "runtime":
            return api_site_runtime(domain, str(body.get("action", "")))
        if section == "sftp":
            return api_site_sftp_action(domain, str(body.get("action", "")))
        if section == "wp":
            return api_site_wp(domain, body.get("args") or [])
        if section == "config":
            return api_site_config(domain, body)
    raise PanelError(404, f"unknown endpoint: {path}")


def make_panel_handler(config: PanelConfig) -> type[BaseHTTPRequestHandler]:

    class PanelHandler(BaseHTTPRequestHandler):
        server_version = f"wpfy-panel/{__version__}"
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args) -> None:  # noqa: A002 - stdlib signature
            pass

        def _send_json(self, status: int, payload: dict) -> None:
            data = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(data)

        def _authorized(self) -> bool:
            header = self.headers.get("Authorization", "")
            if not header.startswith("Bearer "):
                return False
            return hmac.compare_digest(header[len("Bearer "):], config.token)

        def _read_body(self) -> dict:
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                raise PanelError(400, "invalid Content-Length header")
            if length <= 0:
                return {}
            if length > _MAX_BODY_BYTES:
                raise PanelError(413, "request body too large")
            raw = self.rfile.read(length)
            try:
                body = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise PanelError(400, "request body must be JSON")
            if not isinstance(body, dict):
                raise PanelError(400, "request body must be a JSON object")
            return body

        def _serve_static(self, path: str) -> None:
            name = "index.html" if path in ("", "/") else path.lstrip("/")
            target = (STATIC_DIR / name).resolve()
            if not str(target).startswith(str(STATIC_DIR.resolve())) or not target.is_file():
                self._send_json(404, {"error": "not found"})
                return
            content_type = _STATIC_TYPES.get(target.suffix)
            if content_type is None:
                self._send_json(404, {"error": "not found"})
                return
            data = target.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Content-Type-Options", "nosniff")
            if content_type.startswith("text/html"):
                self.send_header(
                    "Content-Security-Policy",
                    "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'",
                )
            self.end_headers()
            self.wfile.write(data)

        def _handle_api(self, method: str) -> None:
            if not self._authorized():
                self._send_json(401, {"error": "missing or invalid token"})
                return
            parsed = urlparse(self.path)
            try:
                if method == "GET":
                    status, payload = _dispatch_get(parsed.path, parse_qs(parsed.query))
                else:
                    status, payload = _dispatch_post(parsed.path, self._read_body())
            except PanelError as exc:
                self._send_json(exc.status, {"error": str(exc)})
                return
            except (FileNotFoundError, ValueError) as exc:
                self._send_json(400, {"error": str(exc)})
                return
            except (OSError, subprocess.SubprocessError) as exc:
                self._send_json(500, {"error": str(exc)})
                return
            self._send_json(status, payload)

        def do_GET(self) -> None:  # noqa: N802 - stdlib signature
            if urlparse(self.path).path.startswith("/api/"):
                self._handle_api("GET")
            else:
                self._serve_static(urlparse(self.path).path)

        def do_POST(self) -> None:  # noqa: N802 - stdlib signature
            if urlparse(self.path).path.startswith("/api/"):
                self._handle_api("POST")
            else:
                self._send_json(404, {"error": "not found"})

    return PanelHandler


def make_panel_server(config: PanelConfig) -> ThreadingHTTPServer:
    if not config.token:
        raise ValueError("panel requires a non-empty token")
    validate_loopback_host(config.host)
    server = ThreadingHTTPServer((config.host, config.port), make_panel_handler(config))
    server.daemon_threads = True
    return server


def panel_url(config: PanelConfig, port: int | None = None) -> str:
    # The token travels in the URL fragment: it never reaches server logs.
    return f"http://{config.host}:{port or config.port}/#token={config.token}"


def serve_panel(config: PanelConfig) -> None:
    with make_panel_server(config) as server:
        server.serve_forever()
