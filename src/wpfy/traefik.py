from __future__ import annotations

import ipaddress
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
import re
import shutil
import subprocess
import threading
import time
import uuid
from pathlib import Path

from . import settings
from .site_runtime import RuntimeResult, docker_available, runtime_skip_requested
from .dns import cloudflare_config_path
from .site_definition import compose_hardening_lines
from .site_paths import read_env


TRAEFIK_IMAGE = "traefik:v3.6.17"
_DEFAULT_ACME_EMAIL = "admin@localhost"
_ACME_EMAIL_RE = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9.!#$%&'+/=?^_`{|}~-]*@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+"
)
TRAEFIK_NETWORK = "wpfy"
PANEL_EDGE_NETWORK = "wpfy-panel-edge"
TRAEFIK_CONTAINER = "wpfy-traefik"
TRAEFIK_PROJECT = "wpfy-traefik"
_COMPOSE_TIMEOUT_SECONDS = 120
_HEALTH_TIMEOUT_SECONDS = 180
_transaction_state = threading.local()


@dataclass(frozen=True, slots=True)
class AcmeEmailResolution:
    email: str
    source: str


def traefik_dir() -> Path:
    return Path(settings.PATHS.traefik_dir)


def traefik_compose_path() -> Path:
    return traefik_dir() / "compose.yaml"


def traefik_config_path() -> Path:
    return traefik_dir() / "traefik.yml"


def acme_email_path() -> Path:
    return Path(settings.PATHS.config_dir) / "acme.env"


def applied_state_path() -> Path:
    return Path(settings.PATHS.state_dir) / "traefik-applied.json"


@contextmanager
def traefik_transaction():
    if getattr(_transaction_state, "held", False):
        raise RuntimeError("Traefik transaction cannot be re-entered in the same thread")
    path = Path(settings.PATHS.state_dir) / "traefik.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        _transaction_state.held = True
        yield
    finally:
        _transaction_state.held = False
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _valid_acme_email(address: object) -> bool:
    return isinstance(address, str) and bool(_ACME_EMAIL_RE.fullmatch(address))


def _config_acme_email() -> str | None:
    try:
        text = traefik_config_path().read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    emails: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("email:"):
            continue
        value = stripped.split(":", 1)[1].strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        emails.append(value)
    if len(emails) == 3 and len(set(emails)) == 1 and _valid_acme_email(emails[0]):
        return emails[0]
    return None


def _file_acme_email() -> str | None:
    try:
        value = read_env(acme_email_path()).get("WPFY_ACME_EMAIL", "").strip()
    except OSError:
        return None
    return value if _valid_acme_email(value) else None


def resolve_acme_email() -> AcmeEmailResolution:
    """Resolve desired ACME address. Caller holds transaction when state can change."""
    environment = os.environ.get("WPFY_ACME_EMAIL", "").strip()
    if _valid_acme_email(environment):
        return AcmeEmailResolution(environment, "env")
    persisted = _file_acme_email()
    if persisted:
        return AcmeEmailResolution(persisted, "file")
    configured = _config_acme_email()
    if configured:
        return AcmeEmailResolution(configured, "config")
    return AcmeEmailResolution(_DEFAULT_ACME_EMAIL, "default")


def _atomic_write(path: Path, content: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, mode)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _set_acme_email(address: str) -> Path:
    if not _valid_acme_email(address):
        raise ValueError("ACME contact email must be a valid email address")
    path = acme_email_path()
    _atomic_write(path, f"WPFY_ACME_EMAIL={address}\n".encode("utf-8"))
    return path


def set_acme_email(address: str) -> Path:
    with traefik_transaction():
        return _set_acme_email(address)


def _config_hash(config_text: str) -> str:
    return hashlib.sha256(config_text.encode("utf-8")).hexdigest()


def _applied_config_hash() -> str | None:
    try:
        payload = json.loads(applied_state_path().read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    value = payload.get("hash") if isinstance(payload, dict) else None
    return value if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) else None


def applied_config_hash() -> str | None:
    with traefik_transaction():
        return _applied_config_hash()


def _record_applied_state(config_text: str) -> None:
    _atomic_write(applied_state_path(), (json.dumps({"hash": _config_hash(config_text)}) + "\n").encode("utf-8"))


def record_applied_state(config_text: str) -> None:
    with traefik_transaction():
        _record_applied_state(config_text)


def _clear_applied_state() -> None:
    try:
        applied_state_path().unlink()
    except FileNotFoundError:
        pass


def clear_applied_state() -> None:
    with traefik_transaction():
        _clear_applied_state()


def _traefik_compose(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "compose", *args],
        cwd=traefik_dir(),
        check=False,
        capture_output=True,
        text=True,
        timeout=_COMPOSE_TIMEOUT_SECONDS,
    )


def _ensure_bridge_network(network_name: str) -> RuntimeResult:
    if runtime_skip_requested():
        return RuntimeResult(0, "traefik network creation skipped by WPFY_SKIP_RUNTIME=1", skipped=True)
    if not docker_available():
        return RuntimeResult(0, "traefik network creation skipped (Docker/Compose not available)", skipped=True)

    proc = subprocess.run(
        ["docker", "network", "inspect", network_name],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode == 0:
        return RuntimeResult(0, f"traefik network '{network_name}' already exists", ran=True)

    proc = subprocess.run(
        ["docker", "network", "create", "--driver", "bridge", network_name],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        message = proc.stderr.strip() or proc.stdout.strip() or "docker network create failed"
        return RuntimeResult(proc.returncode, message)
    return RuntimeResult(0, f"traefik network '{network_name}' created", ran=True)


def ensure_traefik_network() -> RuntimeResult:
    return _ensure_bridge_network(TRAEFIK_NETWORK)


def ensure_panel_edge_network() -> RuntimeResult:
    return _ensure_bridge_network(PANEL_EDGE_NETWORK)


def traefik_network_cidrs(network_name: str = TRAEFIK_NETWORK) -> tuple[str, ...]:
    """Return trusted edge sources; name Traefik itself, never its subnet.

    ``WPFY_TEST_TRAEFIK_NETWORK_CIDRS`` remains a test-only compatibility hook
    for offline callers that cannot provide a Docker container.
    """
    override = os.environ.get("WPFY_TEST_TRAEFIK_NETWORK_CIDRS")
    if override:
        raw_cidrs = [item.strip() for item in override.split(",") if item.strip()]
        cidrs: list[str] = []
        for raw in raw_cidrs:
            try:
                network = ipaddress.ip_network(raw, strict=False)
            except ValueError as exc:
                raise RuntimeError(f"cannot determine wpfy edge address: invalid test source {raw!r}") from exc
            if network.prefixlen == 0:
                raise RuntimeError("cannot determine wpfy edge address: wildcard test source refused")
            cidrs.append(network.with_prefixlen)
        if not cidrs:
            raise RuntimeError("cannot determine wpfy edge address: no test source")
        return tuple(sorted(set(cidrs)))
    return traefik_edge_addresses(network_name)


def traefik_edge_addresses(network_name: str = TRAEFIK_NETWORK) -> tuple[str, ...]:
    """Return only Traefik's host addresses on the shared edge network."""
    if not docker_available():
        raise RuntimeError("cannot determine wpfy edge address: Docker is unavailable")
    proc = subprocess.run(
        ["docker", "inspect", "--format", "{{json .NetworkSettings.Networks}}", TRAEFIK_CONTAINER],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or "container inspect failed"
        raise RuntimeError(f"cannot determine wpfy edge address: {detail}")
    try:
        networks = json.loads(proc.stdout.strip())
    except json.JSONDecodeError as exc:
        raise RuntimeError("cannot determine wpfy edge address: invalid Docker inspect output") from exc
    network = networks.get(network_name) if isinstance(networks, dict) else None
    if not isinstance(network, dict):
        raise RuntimeError(f"cannot determine wpfy edge address: container is not on {network_name}")
    addresses: list[str] = []
    for raw in (network.get("IPAddress"), network.get("GlobalIPv6Address")):
        if not isinstance(raw, str) or not raw:
            continue
        try:
            address = ipaddress.ip_address(raw)
        except ValueError as exc:
            raise RuntimeError(f"cannot determine wpfy edge address: invalid address {raw!r}") from exc
        addresses.append(f"{address}/{'32' if address.version == 4 else '128'}")
    if not addresses:
        raise RuntimeError("cannot determine wpfy edge address: container has no address on edge network")
    return tuple(sorted(set(addresses)))


def effective_acme_email() -> str:
    with traefik_transaction():
        return resolve_acme_email().email


def acme_email_problem() -> str | None:
    """Return an actionable message if certificate issuance would fail at ACME
    registration because no real contact email is configured, else None."""
    with traefik_transaction():
        if resolve_acme_email().source != "default":
            return None
        return (
            "ACME contact email is not configured; "
            "Let's Encrypt rejects invalid contact addresses. "
            "Run 'wpfy stack acme-email you@example.com', then restart Traefik if requested. "
            "Then retry enabling SSL"
        )


def traefik_static_config() -> str:
    with traefik_transaction():
        return _traefik_static_config()


def _traefik_static_config() -> str:
    """Render static config. Caller holds the Traefik transaction."""
    acme_email = resolve_acme_email().email
    lines = [
        "api:",
        "  dashboard: false",
        "",
        "ping: {}",
        "",
        "entryPoints:",
        "  web:",
        '    address: ":80"',
        "  websecure:",
        '    address: ":443"',
        "",
        "providers:",
        "  docker:",
        "    endpoint: \"unix:///var/run/docker.sock\"",
        "    exposedByDefault: false",
        f"    network: {TRAEFIK_NETWORK}",
        "  file:",
        "    directory: /etc/traefik/dynamic",
        "    watch: true",
        "",
        "certificatesResolvers:",
        "  le:",
        "    acme:",
        f'      email: "{acme_email}"',
        "      storage: /letsencrypt/acme.json",
        "      tlsChallenge: {}",
        # le-http validates over plain HTTP on :80, so it works for domains
        # behind a TLS-terminating proxy (e.g. Cloudflare) that forwards the
        # /.well-known/acme-challenge/ path to the origin.
        "  le-http:",
        "    acme:",
        f'      email: "{acme_email}"',
        "      storage: /letsencrypt/acme.json",
        "      httpChallenge:",
        "        entryPoint: web",
        "  le-dns-cloudflare:",
        "    acme:",
        f'      email: "{acme_email}"',
        "      storage: /letsencrypt/acme.json",
        "      dnsChallenge:",
        "        provider: cloudflare",
    ]
    return "\n".join(lines) + "\n"


def _static_config_needs_apply() -> bool:
    """True when the rendered file, or the running proxy, is not the desired config.

    The rendered file is authoritative and is checked first: it is what Traefik
    reads, so a mismatch there always needs an apply no matter what any recorded
    state claims. Recorded state only answers the narrower question of whether
    the running container has loaded a file that is already correct — Traefik
    reads static config at startup only. Trusting the record alone let a wrong
    record hide a wrong file indefinitely.
    """
    desired = _traefik_static_config()
    try:
        on_disk = traefik_config_path().read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return True
    if on_disk != desired:
        return True
    return _config_hash(desired) != _applied_config_hash()


def static_config_needs_apply() -> bool:
    with traefik_transaction():
        return _static_config_needs_apply()


def traefik_compose_content() -> str:
    config_mount = str(traefik_config_path())
    dynamic_mount = str(traefik_dir() / "dynamic")
    lines = [
        f"name: {TRAEFIK_PROJECT}",
        "services:",
        "  traefik:",
        f"    image: {TRAEFIK_IMAGE}",
        f"    container_name: {TRAEFIK_CONTAINER}",
        "    restart: unless-stopped",
        *compose_hardening_lines(256, "256m", "0.50"),
        "    ports:",
        '      - "80:80"',
        '      - "443:443"',
    ]
    cf_config = cloudflare_config_path()
    if cf_config.exists():
        lines.extend([
            "    env_file:",
            f"      - {cf_config}",
        ])
    lines.extend([
        "    volumes:",
        "      - /var/run/docker.sock:/var/run/docker.sock:ro",
        f"      - {config_mount}:/etc/traefik/traefik.yml:ro",
        f"      - {dynamic_mount}:/etc/traefik/dynamic:ro",
        "      - letsencrypt_data:/letsencrypt",
        "    networks:",
        f"      - {TRAEFIK_NETWORK}",
        f"      - {PANEL_EDGE_NETWORK}",
        "    healthcheck:",
        "      test: [\"CMD\", \"traefik\", \"healthcheck\", \"--ping\"]",
        "      interval: 30s",
        "      timeout: 10s",
        "      retries: 3",
        "",
        "networks:",
        f"  {TRAEFIK_NETWORK}:",
        "    external: true",
        f"  {PANEL_EDGE_NETWORK}:",
        "    external: true",
        "",
        "volumes:",
        "  letsencrypt_data:",
    ])
    return "\n".join(lines) + "\n"


def _migrate_or_bootstrap_acme_email() -> None:
    """Persist only legacy floor migration or first valid environment bootstrap."""
    if acme_email_path().exists():
        return
    floor = _config_acme_email()
    if floor:
        _set_acme_email(floor)
        return
    environment = os.environ.get("WPFY_ACME_EMAIL", "").strip()
    if _valid_acme_email(environment):
        _set_acme_email(environment)


def _ensure_traefik_scaffold() -> list[str]:
    """Write generated files in place. Caller holds the Traefik transaction."""
    touched: list[str] = []
    td = traefik_dir()
    if not td.exists():
        td.mkdir(parents=True, exist_ok=True)
        touched.append(str(td))

    dynamic = td / "dynamic"
    if dynamic.is_symlink():
        raise OSError(f"refusing symlinked Traefik dynamic directory: {dynamic}")
    if not dynamic.exists():
        dynamic.mkdir(mode=0o755)
        touched.append(str(dynamic))
    if not dynamic.is_dir():
        raise OSError(f"Traefik dynamic path is not a directory: {dynamic}")
    os.chmod(dynamic, 0o755)

    compose_file = traefik_compose_path()
    content = traefik_compose_content()
    if not compose_file.exists() or compose_file.read_text(encoding="utf-8") != content:
        compose_file.write_text(content, encoding="utf-8")
        touched.append(str(compose_file))

    config_file = traefik_config_path()
    _migrate_or_bootstrap_acme_email()
    config_content = _traefik_static_config()
    if not config_file.exists() or config_file.read_text(encoding="utf-8") != config_content:
        with config_file.open("w", encoding="utf-8") as stream:
            stream.write(config_content)
            stream.flush()
            os.fsync(stream.fileno())
        touched.append(str(config_file))

    return touched


def ensure_traefik_scaffold() -> list[str]:
    with traefik_transaction():
        return _ensure_traefik_scaffold()


def _wait_for_traefik_healthy() -> RuntimeResult:
    """Wait for Traefik health. Caller holds the Traefik transaction."""
    deadline = time.monotonic() + _HEALTH_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        try:
            proc = subprocess.run(
                ["docker", "inspect", "--format", "{{.State.Health.Status}}", TRAEFIK_CONTAINER],
                check=False,
                capture_output=True,
                text=True,
                timeout=15,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return RuntimeResult(1, f"Traefik health inspection failed: {exc}")
        if proc.returncode == 0 and proc.stdout.strip() == "healthy":
            return RuntimeResult(0, "traefik is healthy", ran=True)
        time.sleep(1)
    return RuntimeResult(
        1,
        f"Traefik did not become healthy within {_HEALTH_TIMEOUT_SECONDS} seconds; "
        "it may still be starting, check 'wpfy stack status'",
    )


def _refresh_managed_site_edge_trust() -> RuntimeResult:
    """Re-render and reload site trust after Traefik receives new addresses."""
    from . import site_security

    sites_root = Path(settings.PATHS.sites_dir)
    if not sites_root.is_dir():
        return RuntimeResult(0, "no managed sites need edge trust refresh")
    changed_domains: list[str] = []
    for root in sorted(sites_root.iterdir(), key=lambda item: item.name):
        if not root.is_dir():
            continue
        domain = root.name
        try:
            forwarded = site_security.render_forwarded_scheme(domain)
            security = site_security.render_security(domain)
        except (OSError, ValueError) as exc:
            return RuntimeResult(3, f"edge trust refresh failed for {domain}: {exc}")
        if forwarded.exit_code != 0 or security.exit_code != 0:
            message = forwarded.message if forwarded.exit_code != 0 else security.message
            return RuntimeResult(3, f"edge trust refresh failed for {domain}: {message}")
        if not (forwarded.changed or security.changed):
            continue
        running = site_security._running_web_container(domain)
        if running != "":
            reload_error = site_security._reload_web_service(domain)
            if reload_error:
                return RuntimeResult(3, f"edge trust refresh did not apply to {domain}: {reload_error}")
        changed_domains.append(domain)
    if not changed_domains:
        return RuntimeResult(0, "managed site edge trust unchanged")
    return RuntimeResult(0, f"refreshed edge trust for {len(changed_domains)} managed site(s)", ran=True)


def _start_traefik() -> RuntimeResult:
    """Apply desired static config. Caller holds the Traefik transaction."""
    was_running = traefik_running()
    # Decide this BEFORE the scaffold writes, or the comparison is made against
    # the file we are about to overwrite and every change looks like a no-op.
    needs_apply = _static_config_needs_apply()
    _ensure_traefik_scaffold()
    desired = _traefik_static_config()
    for ensure_network in (ensure_traefik_network, ensure_panel_edge_network):
        net_result = ensure_network()
        if net_result.exit_code != 0:
            return net_result
    command = (
        ("up", "-d", "--force-recreate", "traefik")
        if was_running and needs_apply
        else ("up", "-d")
    )
    try:
        proc = _traefik_compose(*command)
    except (OSError, subprocess.SubprocessError) as exc:
        return RuntimeResult(1, f"docker compose up failed: {exc}")
    if proc.returncode != 0:
        message = proc.stderr.strip() or proc.stdout.strip() or "docker compose up failed"
        return RuntimeResult(proc.returncode, message)
    health = _wait_for_traefik_healthy()
    if health.exit_code != 0:
        return health
    refreshed = _refresh_managed_site_edge_trust()
    if refreshed.exit_code != 0:
        return refreshed
    _record_applied_state(desired)
    message = proc.stdout.strip() or proc.stderr.strip() or "traefik started"
    if refreshed.ran:
        message += f"; {refreshed.message}"
    return RuntimeResult(0, message, ran=True)


def _start_traefik_locked() -> RuntimeResult:
    """Start Traefik. Caller holds the Traefik transaction."""
    if runtime_skip_requested():
        return RuntimeResult(0, "traefik start skipped by WPFY_SKIP_RUNTIME=1", skipped=True)
    if not docker_available():
        return RuntimeResult(0, "traefik start skipped (Docker/Compose not available)", skipped=True)
    return _start_traefik()


def _traefik_image_available() -> bool:
    try:
        proc = subprocess.run(
            ["docker", "image", "inspect", TRAEFIK_IMAGE],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0


def _pull_traefik_image() -> RuntimeResult:
    """Pull before acquiring the Traefik transaction."""
    if _traefik_image_available():
        return RuntimeResult(0, "Traefik image already available", ran=True)
    try:
        proc = subprocess.run(
            ["docker", "pull", TRAEFIK_IMAGE],
            check=False,
            capture_output=True,
            text=True,
            timeout=_COMPOSE_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        if _traefik_image_available():
            return RuntimeResult(0, f"Traefik image pull failed; using local image: {exc}", ran=True)
        return RuntimeResult(1, f"Traefik image pull failed: {exc}")
    if proc.returncode != 0:
        message = proc.stderr.strip() or proc.stdout.strip() or "Traefik image pull failed"
        if _traefik_image_available():
            return RuntimeResult(0, f"Traefik image pull failed; using local image: {message}", ran=True)
        return RuntimeResult(proc.returncode, message)
    return RuntimeResult(0, "Traefik image ready", ran=True)


def start_traefik() -> RuntimeResult:
    if runtime_skip_requested():
        return RuntimeResult(0, "traefik start skipped by WPFY_SKIP_RUNTIME=1", skipped=True)
    if not docker_available():
        return RuntimeResult(0, "traefik start skipped (Docker/Compose not available)", skipped=True)
    pulled = _pull_traefik_image()
    if pulled.exit_code != 0:
        return pulled
    with traefik_transaction():
        return _start_traefik_locked()


def _restart_traefik_existing() -> RuntimeResult:
    """Restart restored config. Caller holds the Traefik transaction."""
    try:
        proc = _traefik_compose("restart", "traefik")
    except (OSError, subprocess.SubprocessError) as exc:
        return RuntimeResult(1, f"traefik restart failed: {exc}")
    if proc.returncode != 0:
        message = proc.stderr.strip() or proc.stdout.strip() or "docker compose restart failed"
        return RuntimeResult(proc.returncode, message)
    health = _wait_for_traefik_healthy()
    if health.exit_code != 0:
        return health
    try:
        config_text = traefik_config_path().read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return RuntimeResult(1, f"cannot read restored Traefik config: {exc}")
    _record_applied_state(config_text)
    message = proc.stdout.strip() or proc.stderr.strip() or "traefik restarted"
    return RuntimeResult(0, message, ran=True)


def _restart_traefik_without_state() -> RuntimeResult:
    """Restart existing Traefik. Caller holds the Traefik transaction."""
    try:
        proc = _traefik_compose("restart", "traefik")
    except (OSError, subprocess.SubprocessError) as exc:
        return RuntimeResult(1, f"traefik restart failed: {exc}")
    if proc.returncode != 0:
        message = proc.stderr.strip() or proc.stdout.strip() or "docker compose restart failed"
        return RuntimeResult(proc.returncode, message)
    message = proc.stdout.strip() or proc.stderr.strip() or "traefik restarted"
    return RuntimeResult(0, message, ran=True)


def _restart_traefik_existing_locked(*, scaffold: bool = False) -> RuntimeResult:
    """Restart Traefik. Caller holds the Traefik transaction."""
    if runtime_skip_requested():
        return RuntimeResult(0, "traefik restart skipped by WPFY_SKIP_RUNTIME=1", skipped=True)
    if not docker_available():
        return RuntimeResult(0, "traefik restart skipped (Docker/Compose not available)", skipped=True)
    if scaffold:
        _ensure_traefik_scaffold()
        for ensure_network in (ensure_traefik_network, ensure_panel_edge_network):
            net_result = ensure_network()
            if net_result.exit_code != 0:
                return net_result
        return _restart_traefik_without_state()
    return _restart_traefik_existing()


def restart_traefik_existing() -> RuntimeResult:
    with traefik_transaction():
        return _restart_traefik_existing_locked(scaffold=True)


def stop_traefik() -> RuntimeResult:
    if runtime_skip_requested() or not docker_available():
        return RuntimeResult(0, "traefik stop skipped", skipped=True)
    try:
        with traefik_transaction():
            proc = _traefik_compose("down")
            if proc.returncode == 0:
                _clear_applied_state()
    except (OSError, subprocess.SubprocessError) as exc:
        return RuntimeResult(1, f"docker compose down failed: {exc}")
    if proc.returncode != 0:
        message = proc.stderr.strip() or proc.stdout.strip() or "docker compose down failed"
        return RuntimeResult(proc.returncode, message)
    message = proc.stdout.strip() or proc.stderr.strip() or "traefik stopped"
    return RuntimeResult(0, message, ran=True)


def traefik_status() -> RuntimeResult:
    if runtime_skip_requested() or not docker_available():
        return RuntimeResult(0, "traefik status unavailable (Docker/Compose not available)", skipped=True)
    if not traefik_compose_path().exists():
        return RuntimeResult(0, "Traefik not installed")
    proc = _traefik_compose("ps")
    if proc.returncode != 0:
        message = proc.stderr.strip() or proc.stdout.strip() or "docker compose ps failed"
        return RuntimeResult(proc.returncode, message)
    message = proc.stdout.strip() or proc.stderr.strip() or "no running traefik containers"
    return RuntimeResult(0, message, ran=True)


def traefik_running() -> bool:
    docker = shutil.which("docker")
    if not docker:
        return False
    proc = subprocess.run(
        [docker, "inspect", "--format", "{{.State.Status}}", TRAEFIK_CONTAINER],
        check=False,
        capture_output=True,
        text=True,
    )
    return proc.returncode == 0 and proc.stdout.strip() == "running"


def reload_traefik() -> RuntimeResult:
    if runtime_skip_requested():
        return RuntimeResult(0, "traefik reload skipped by WPFY_SKIP_RUNTIME=1", skipped=True)
    if not docker_available():
        return RuntimeResult(0, "traefik reload skipped (Docker/Compose not available)", skipped=True)
    if not traefik_running():
        return RuntimeResult(1, "traefik is not running; cannot reload")

    proc = subprocess.run(
        ["docker", "kill", "-s", "HUP", TRAEFIK_CONTAINER],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        message = proc.stderr.strip() or proc.stdout.strip() or "traefik reload failed"
        return RuntimeResult(proc.returncode, message)
    return RuntimeResult(0, "traefik reloaded successfully", ran=True)
