from __future__ import annotations

from dataclasses import replace
import re
import socket
import time

from .site_definition import SiteDefinition
from .site_layout import (
    ensure_site_scaffold,
    generated_secret,
)
from .site_paths import compose_path, env_path, read_env, read_text, site_exists, validate_domain
from .site_runtime import RuntimeResult, compose_command


_SFTP_IMAGE = "atmoz/sftp:alpine"
_SFTP_PORT = "2222"
_SFTP_READY_TIMEOUT_SECONDS = 15.0


def _compose_has_sftp(domain: str) -> bool:
    text = read_text(compose_path(domain))
    if text is None:
        return False
    return bool(re.search(r"^\s{2}sftp:", text, re.MULTILINE))


def _backup_compose(domain: str) -> None:
    cp = compose_path(domain)
    if cp.exists():
        backup = cp.with_suffix(cp.suffix + ".bak")
        backup.write_text(cp.read_text(encoding="utf-8"), encoding="utf-8")


def _wait_for_sftp_port(host_port: str = _SFTP_PORT, timeout: float = _SFTP_READY_TIMEOUT_SECONDS) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", int(host_port)), timeout=1):
                return True
        except OSError:
            time.sleep(0.5)
    return False


def _port_available(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.2)
        return sock.connect_ex(("127.0.0.1", port)) != 0


def _used_sftp_ports(current_domain: str) -> set[str]:
    used: set[str] = set()
    current_env = env_path(current_domain)
    sites_root = current_env.parent.parent
    if not sites_root.exists():
        return used
    for env_file in sites_root.glob("*/.env"):
        if env_file == current_env:
            continue
        port = read_env(env_file).get("SFTP_PORT")
        if port:
            used.add(port)
    return used


def _allocate_sftp_port(domain: str, env: dict[str, str]) -> str:
    existing = env.get("SFTP_PORT")
    if existing:
        return existing
    used = _used_sftp_ports(domain)
    port = int(_SFTP_PORT)
    while str(port) in used or not _port_available(port):
        port += 1
    return str(port)


def _current_definition(domain: str) -> SiteDefinition:
    return SiteDefinition.from_env(domain, read_env(env_path(domain)))


def ensure_sftp_container(domain: str, password: str | None = None) -> RuntimeResult:
    try:
        validate_domain(domain)
    except ValueError as exc:
        return RuntimeResult(2, str(exc))

    if not site_exists(domain):
        return RuntimeResult(2, f"site not found: {domain}")

    env_file = env_path(domain)
    env = read_env(env_file)
    env_has_sftp = "SFTP_PASSWORD" in env
    compose_has_sftp = _compose_has_sftp(domain)
    host_port = _allocate_sftp_port(domain, env)

    # Precedence: an explicit --password always wins (rotation), then the
    # already-configured value, then a fresh generated one shown exactly once.
    generated = False
    if password is None:
        password = env.get("SFTP_PASSWORD")
        if not password:
            password = generated_secret()[:16]
            generated = True

    _backup_compose(domain)
    definition = replace(
        _current_definition(domain),
        sftp_password=password,
        sftp_port=host_port,
    )
    ensure_site_scaffold(definition)

    proc = compose_command(domain, "up", "-d", "sftp")
    if proc.returncode != 0:
        err = proc.stderr.strip() or proc.stdout.strip() or "docker compose up sftp failed"
        return RuntimeResult(proc.returncode, f"sftp configured but start failed: {err}")
    if not _wait_for_sftp_port(host_port):
        return RuntimeResult(1, f"sftp configured but port {host_port} is not ready")

    state = "already enabled" if env_has_sftp and compose_has_sftp else "enabled"
    message = f"sftp {state} for {domain} on port {host_port}; username: sftpuser"
    if generated:
        message += f"\npassword (shown once): {password}"
    return RuntimeResult(0, message, ran=True)


def remove_sftp_container(domain: str) -> RuntimeResult:
    try:
        validate_domain(domain)
    except ValueError as exc:
        return RuntimeResult(2, str(exc))

    if not site_exists(domain):
        return RuntimeResult(2, f"site not found: {domain}")

    env = read_env(env_path(domain))
    compose_has_sftp = _compose_has_sftp(domain)

    if "SFTP_PASSWORD" not in env and not compose_has_sftp:
        return RuntimeResult(0, f"sftp is not enabled for {domain}", ran=True)

    compose_command(domain, "rm", "-sf", "sftp")
    compose_command(domain, "down", "sftp")

    _backup_compose(domain)

    definition = replace(_current_definition(domain), sftp_password=None, sftp_port=None)
    ensure_site_scaffold(definition)

    return RuntimeResult(0, f"sftp disabled for {domain}", ran=True)


def sftp_status(domain: str) -> RuntimeResult:
    try:
        validate_domain(domain)
    except ValueError as exc:
        return RuntimeResult(2, str(exc))

    if not site_exists(domain):
        return RuntimeResult(2, f"site not found: {domain}")

    env = read_env(env_path(domain))
    compose_has_sftp = _compose_has_sftp(domain)
    env_has_password = "SFTP_PASSWORD" in env
    host_port = env.get("SFTP_PORT", _SFTP_PORT)

    if not env_has_password and not compose_has_sftp:
        return RuntimeResult(0, f"sftp: disabled for {domain}", ran=True)

    proc = compose_command(domain, "ps", "sftp")
    container_running = False
    container_info = "no sftp container"
    if proc.returncode == 0 and proc.stdout.strip():
        container_info = _redact_secrets(proc.stdout.strip())
        ps_lines = [l for l in proc.stdout.splitlines() if l.strip()]
        container_running = len(ps_lines) > 1

    lines = [
        f"sftp status for {domain}:",
        f"  enabled: {compose_has_sftp}",
        f"  password configured: {env_has_password}",
        f"  username: sftpuser",
        f"  image: {_SFTP_IMAGE}",
        f"  port: {host_port}",
        f"  container: {'running' if container_running else 'stopped'}",
        f"  details: {container_info}",
    ]
    return RuntimeResult(0, "\n".join(lines), ran=True)


def _redact_secrets(text: str) -> str:
    return re.sub(
        r"(SFTP_PASSWORD[=:]\s*)(\S+)",
        r"\1***REDACTED***",
        text,
        flags=re.IGNORECASE,
    )
