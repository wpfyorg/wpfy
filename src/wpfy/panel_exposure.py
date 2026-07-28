from __future__ import annotations

import ipaddress
import os
from pathlib import Path
import re
import tempfile
from urllib.parse import urlsplit

from . import certificate_lifecycle, panel_auth, systemd, traefik
from .site_paths import validate_domain
from .site_runtime import RuntimeResult


PANEL_EDGE_NETWORK = "wpfy-panel-edge"
RATE_LIMIT_AVERAGE = 10
RATE_LIMIT_BURST = 20
DEFAULT_PANEL_PORT = 8642
_ROUTER_NAME = "wpfy-panel"
_SERVICE_NAME = "wpfy-panel.service"
_CONTAINER_DYNAMIC_DIR = "/etc/traefik/dynamic"
_DOMAIN_RULE_RE = re.compile(r"Host\(`([^`]+)`\)")


def dynamic_dir() -> Path:
    return traefik.traefik_dir() / "dynamic"


def panel_router_path() -> Path:
    return dynamic_dir() / "wpfy-panel.yml"


def panel_service_path() -> Path:
    return systemd.systemd_dir() / _SERVICE_NAME


def _validated_target_url(target_url: str) -> str:
    if not isinstance(target_url, str):
        raise TypeError("panel target URL must be a string")
    parsed = urlsplit(target_url)
    if parsed.scheme != "http" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("panel target URL must be an unauthenticated HTTP URL")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("panel target URL must not contain a path, query, or fragment")
    try:
        ipaddress.ip_address(parsed.hostname)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("panel target URL must use an IP address") from exc
    if port is None or not 1 <= port <= 65535:
        raise ValueError("panel target URL must include a valid port")
    return target_url


def render_router_config(domain, target_url) -> str:
    if not isinstance(domain, str):
        raise TypeError("panel domain must be a string")
    validate_domain(domain)
    target_url = _validated_target_url(target_url)
    return "\n".join([
        "http:",
        "  routers:",
        f"    {_ROUTER_NAME}:",
        f'      rule: "Host(`{domain}`)"',
        "      entryPoints:",
        "        - websecure",
        "      middlewares:",
        f"        - {_ROUTER_NAME}-rate-limit",
        f"      service: {_ROUTER_NAME}",
        "      tls:",
        "        certResolver: le-http",
        "  middlewares:",
        f"    {_ROUTER_NAME}-rate-limit:",
        "      rateLimit:",
        f"        average: {RATE_LIMIT_AVERAGE}",
        f"        burst: {RATE_LIMIT_BURST}",
        "  services:",
        f"    {_ROUTER_NAME}:",
        "      loadBalancer:",
        "        servers:",
        f'          - url: "{target_url}"',
        "",
    ])


def validate_edge_bind(host) -> str:
    if not isinstance(host, str) or not host:
        raise ValueError("panel edge bind must be an IP address")
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError("panel edge bind must be an IP address") from exc
    if address.is_unspecified:
        raise ValueError("panel edge bind cannot be a wildcard address")

    for raw_cidr in traefik.traefik_network_cidrs(PANEL_EDGE_NETWORK):
        network = ipaddress.ip_network(raw_cidr, strict=False)
        if address.version != network.version or address not in network:
            continue
        if address == network.network_address or (
            network.version == 4 and address == network.broadcast_address
        ):
            break
        return str(address)
    raise ValueError(f"panel edge bind {host!r} is outside {PANEL_EDGE_NETWORK}")


def edge_bind_address() -> str:
    for raw_cidr in traefik.traefik_network_cidrs(PANEL_EDGE_NETWORK):
        network = ipaddress.ip_network(raw_cidr, strict=False)
        try:
            return validate_edge_bind(str(next(network.hosts())))
        except (StopIteration, ValueError):
            continue
    raise RuntimeError(f"cannot determine a gateway address for {PANEL_EDGE_NETWORK}")


def _target_url(host: str, port: int) -> str:
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ValueError("panel port must be between 1 and 65535")
    address = ipaddress.ip_address(validate_edge_bind(host))
    rendered_host = f"[{address}]" if address.version == 6 else str(address)
    return f"http://{rendered_host}:{port}"


def _ensure_dynamic_dir() -> None:
    directory = dynamic_dir()
    if directory.is_symlink():
        raise OSError(f"refusing symlinked Traefik dynamic directory: {directory}")
    directory.mkdir(parents=True, exist_ok=True, mode=0o755)
    os.chmod(directory, 0o755)


def _write_router(content: str) -> None:
    _ensure_dynamic_dir()
    destination = panel_router_path()
    if destination.is_symlink():
        raise OSError(f"refusing symlinked panel router config: {destination}")
    fd, temporary_name = tempfile.mkstemp(prefix=".wpfy-panel-", dir=dynamic_dir(), text=True)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def _has_totp_user() -> bool:
    return any(user.get("totp_enabled") is True for user in panel_auth.list_users())


def expose(domain, *, confirm, port=DEFAULT_PANEL_PORT) -> RuntimeResult:
    try:
        if not isinstance(domain, str):
            raise TypeError("panel domain must be a string")
        validate_domain(domain)
        if confirm != domain:
            return RuntimeResult(2, f"confirmation must exactly match {domain}")
        if not panel_auth.login_required():
            return RuntimeResult(2, "panel exposure requires named-user login; the run token is still active")
        if not _has_totp_user():
            return RuntimeResult(2, "panel exposure requires at least one TOTP-enabled user")
        preflight = certificate_lifecycle.preflight_ssl(domain)
        if not preflight.passed:
            return RuntimeResult(2, preflight.message)

        traefik.ensure_traefik_scaffold()
        start_result = traefik.start_traefik()
        if start_result.exit_code != 0:
            return start_result
        host = edge_bind_address()
        content = render_router_config(domain, _target_url(host, port))
        service_path = panel_service_path()
        if service_path.exists() and service_path.read_text(encoding="utf-8") != panel_service_content(host, port):
            return RuntimeResult(2, "remove the installed panel service before changing its bind or port")
        current = panel_router_path()
        unchanged = current.exists() and current.read_text(encoding="utf-8") == content
        if not unchanged:
            _write_router(content)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        return RuntimeResult(2, str(exc))
    if service_path.exists():
        return RuntimeResult(
            0,
            f"panel router and service configured for https://{domain}; verify the public URL",
            ran=True,
        )
    state = "already configured" if unchanged else "configured"
    return RuntimeResult(
        0,
        f"panel router {state} for https://{domain}; required next: wpfy panel service install",
        ran=True,
    )


def _router_details() -> dict | None:
    path = panel_router_path()
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None
    domain_match = _DOMAIN_RULE_RE.search(text)
    target_match = re.search(r'^\s*- url: "([^"]+)"\s*$', text, re.MULTILINE)
    if not domain_match or not target_match:
        return None
    domain = domain_match.group(1)
    target_url = target_match.group(1)
    try:
        validate_domain(domain)
        _validated_target_url(target_url)
        parsed = urlsplit(target_url)
        host = validate_edge_bind(parsed.hostname)
        port = parsed.port
        if render_router_config(domain, target_url) != text:
            return None
    except (RuntimeError, TypeError, ValueError):
        return None
    return {"domain": domain, "target_host": host, "target_port": port}


def exposure_status() -> dict:
    path = panel_router_path()
    router_present = path.exists()
    details = _router_details()
    return {
        "exposed": router_present,
        "recognised": details is not None,
        "domain": details["domain"] if details else None,
        "target_host": details["target_host"] if details else None,
        "target_port": details["target_port"] if details else None,
        "router_present": router_present,
        "router_path": str(path),
        "service_installed": panel_service_path().exists(),
    }


def panel_service_content(host, port) -> str:
    host = validate_edge_bind(host)
    _target_url(host, port)
    command = systemd.command_line([
        "/usr/local/bin/wpfy", "panel", "--host", host, "--port", str(port), "--edge-service",
    ])
    return "\n".join([
        "[Unit]",
        "Description=wpfy browser panel",
        "After=docker.service network-online.target",
        "Wants=network-online.target",
        "",
        "[Service]",
        "Type=simple",
        f"ExecStart={command}",
        "Restart=on-failure",
        "RestartSec=5s",
        "NoNewPrivileges=true",
        "",
        "[Install]",
        "WantedBy=multi-user.target",
        "",
    ])


def install_service(host, port) -> RuntimeResult:
    try:
        content = panel_service_content(host, port)
        if not exposure_status()["exposed"]:
            return RuntimeResult(2, "expose the panel router before installing the panel service")
        if not panel_auth.login_required() or not _has_totp_user():
            return RuntimeResult(2, "panel service requires named-user login and an enrolled TOTP factor")
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        return RuntimeResult(2, str(exc))

    path = panel_service_path()
    result = systemd.install_units({path: content}, [_SERVICE_NAME], "panel service installed")
    if result.exit_code != 0:
        path.unlink(missing_ok=True)
    return result


def remove_service() -> RuntimeResult:
    path = panel_service_path()
    if not path.exists():
        return RuntimeResult(0, "panel service is not installed")
    return systemd.disable_units([_SERVICE_NAME], [path], "panel service removed")


def disable() -> RuntimeResult:
    errors: list[str] = []
    try:
        panel_router_path().unlink(missing_ok=True)
    except OSError as exc:
        errors.append(str(exc))
    service_result = remove_service()
    if service_result.exit_code != 0:
        errors.append(service_result.message)
    if errors:
        return RuntimeResult(1, "; ".join(errors))
    return RuntimeResult(0, "panel exposure disabled", ran=True)
