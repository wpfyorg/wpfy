from __future__ import annotations

from dataclasses import replace
import re
import socket
import time

from .image_references import SFTP_IMAGE
from .site_definition import SiteDefinition
from .site_layout import (
    ensure_site_scaffold,
    generated_secret,
)
from .site_paths import compose_path, env_path, read_env, read_text, site_exists, validate_domain
from .site_runtime import RuntimeResult, compose_command, runtime_skip_requested
from .events import record_event
from . import firewall_ports


# Compatibility alias for callers that used the private status constant; the
# authority is image_references.SFTP_IMAGE.
_SFTP_IMAGE = SFTP_IMAGE
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


def _sftp_ufw_note(domain: str, host_port: str) -> str:
    """Best-effort ufw rule for the published SFTP port, as a message note.

    Docker-published ports bypass ufw's INPUT chain, so the rule documents the
    exposure rather than enforcing it -- `ufw status` should still tell the
    truth about a port a desktop client can reach. Failure is non-fatal: the
    container is already running.
    """
    try:
        rule = firewall_ports.allow_port(host_port, "tcp", comment=f"wpfy sftp {domain}")
        if rule.exit_code != 0:
            return f"\nWARN ufw: {rule.message}"
    except (OSError, ValueError, RuntimeError) as exc:
        return f"\nWARN ufw: {exc}"
    return ""


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

    if runtime_skip_requested():
        record_event("site.sftp.enable", domain=domain, detail=f"sftp configured on port {host_port}")
        message = f"sftp configured for {domain} on port {host_port}; username: sftpuser"
        if generated:
            message += f"\npassword (shown once): {password}"
        message += _sftp_ufw_note(domain, host_port)
        return RuntimeResult(0, message, skipped=True)

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
    message += _sftp_ufw_note(domain, host_port)

    result = RuntimeResult(0, message, ran=True)
    record_event("site.sftp.enable", domain=domain, detail=f"sftp enabled on port {host_port}")
    return result


def rotate_sftp_password(domain: str, password: str | None = None) -> RuntimeResult:
    password = password or generated_secret()[:16]
    result = ensure_sftp_container(domain, password=password)
    record_event(
        "site.sftp.rotate",
        domain=domain,
        outcome="ok" if result.exit_code == 0 else "failed",
        detail="sftp password rotated" if result.exit_code == 0 else "sftp password rotation failed",
    )
    return result


def _ufw_pending_path(domain: str):
    """Marker recording a documentation rule that still needs deletion.

    The generated .env emits SFTP_PORT only while a password is configured, so
    a port retained purely for rule cleanup would be erased by the next
    scaffold rewrite. A sibling marker file survives that rewrite.
    """
    return env_path(domain).parent / "sftp-ufw-pending"


def _delete_ufw_note(domain: str, host_port: str) -> str:
    """Best-effort removal of the documentation rule, as a message note."""
    try:
        rule = firewall_ports.delete_rule(host_port, "tcp")
        if rule.exit_code != 0:
            return f"\nWARN ufw: {rule.message}"
    except (OSError, ValueError, RuntimeError) as exc:
        return f"\nWARN ufw: {exc}"
    try:
        _ufw_pending_path(domain).unlink(missing_ok=True)
    except OSError:
        pass
    return ""


def remove_sftp_container(domain: str) -> RuntimeResult:
    try:
        validate_domain(domain)
    except ValueError as exc:
        return RuntimeResult(2, str(exc))

    if not site_exists(domain):
        return RuntimeResult(2, f"site not found: {domain}")

    env = read_env(env_path(domain))
    compose_has_sftp = _compose_has_sftp(domain)
    has_password = "SFTP_PASSWORD" in env
    host_port = env.get("SFTP_PORT") or _SFTP_PORT

    if not has_password and not compose_has_sftp:
        pending = _ufw_pending_path(domain)
        if pending.exists():
            # A previous disable could not remove the documentation rule and
            # left a marker for exactly this retry.
            try:
                host_port = pending.read_text(encoding="utf-8").strip() or host_port
            except OSError:
                pass
            note = _delete_ufw_note(domain, host_port)
            definition = replace(_current_definition(domain), sftp_password=None, sftp_port=None)
            ensure_site_scaffold(definition)
            outcome = "failed" if note.startswith("\nWARN") else "ok"
            record_event("site.sftp.disable", domain=domain, outcome=outcome,
                         detail="stale sftp firewall rule retried")
            return RuntimeResult(0, f"sftp disabled for {domain}; stale firewall rule retried.{note}", ran=True)
        return RuntimeResult(0, f"sftp is not enabled for {domain}", ran=True)

    # Record cleanup metadata BEFORE stopping anything: if the marker cannot
    # be persisted and verified, abort while SFTP is still coherent rather
    # than disabling into an undiscoverable stale firewall rule.
    pending = _ufw_pending_path(domain)
    try:
        pending.write_text(host_port, encoding="utf-8")
        if pending.read_text(encoding="utf-8").strip() != host_port:
            raise OSError("marker readback mismatch")
    except OSError as exc:
        return RuntimeResult(
            1, f"sftp disable aborted: cannot record cleanup metadata ({exc}); SFTP is unchanged",
        )

    # Service-scoped teardown: `compose down` takes no service name, so the
    # sequence is stop then rm. Both return codes are checked -- with a public
    # bind, a silent failed removal would leave SFTP reachable while everything
    # else claims it is disabled.
    proc_stop = compose_command(domain, "stop", "sftp")
    proc_rm = compose_command(domain, "rm", "-sf", "sftp")
    if proc_stop.returncode != 0 or proc_rm.returncode != 0:
        err = (proc_stop.stderr.strip() or proc_stop.stdout.strip()
               or proc_rm.stderr.strip() or proc_rm.stdout.strip()
               or "docker compose removal failed")
        return RuntimeResult(1, f"sftp disable failed; the container may still be running: {err}")

    ps = compose_command(domain, "ps", "sftp")
    ps_lines = [line for line in (ps.stdout or "").splitlines() if line.strip()]
    if ps.returncode == 0 and len(ps_lines) > 1:
        return RuntimeResult(1, "sftp disable failed: an sftp container is still present after removal")

    _backup_compose(domain)

    # Remove the documentation rule while the port is still known. When the
    # deletion fails, the marker written above survives so the next disable
    # retries; compose renders the sftp service from the password alone, so
    # cleanup metadata never resurrects the container.
    rule_note = _delete_ufw_note(domain, host_port)
    if rule_note.startswith("\nWARN"):
        message = (f"sftp disabled for {domain}"
                   f"\nWARN ufw: stale rule for {host_port}/tcp could not be removed; the next disable retries it")
    else:
        try:
            pending.unlink(missing_ok=True)
        except OSError as exc:
            message = f"sftp disabled for {domain}\nWARN ufw: could not remove the retry marker: {exc}"
        else:
            message = f"sftp disabled for {domain}"

    definition = replace(_current_definition(domain), sftp_password=None, sftp_port=None)
    ensure_site_scaffold(definition)
    return RuntimeResult(0, message, ran=True)


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
