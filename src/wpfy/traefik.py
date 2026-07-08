from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

from .settings import PATHS
from .site_layout import RuntimeResult, runtime_skip_requested, docker_available
from .dns import cloudflare_config_path


TRAEFIK_IMAGE = "traefik:v3.6.17"
_DEFAULT_ACME_EMAIL = "admin@localhost"
_ACME_EMAIL_RE = re.compile(r"[^@\s]+@[^@\s.]+(?:\.[^@\s.]+)+")
TRAEFIK_NETWORK = "wpfy"
TRAEFIK_CONTAINER = "wpfy-traefik"
TRAEFIK_PROJECT = "wpfy-traefik"


def traefik_dir() -> Path:
    return Path(PATHS.traefik_dir)


def traefik_compose_path() -> Path:
    return traefik_dir() / "compose.yaml"


def traefik_config_path() -> Path:
    return traefik_dir() / "traefik.yml"


def _traefik_compose(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "compose", *args],
        cwd=traefik_dir(),
        check=False,
        capture_output=True,
        text=True,
    )


def ensure_traefik_network() -> RuntimeResult:
    if runtime_skip_requested():
        return RuntimeResult(0, "traefik network creation skipped by WPFY_SKIP_RUNTIME=1", skipped=True)
    if not docker_available():
        return RuntimeResult(0, "traefik network creation skipped (Docker/Compose not available)", skipped=True)

    proc = subprocess.run(
        ["docker", "network", "inspect", TRAEFIK_NETWORK],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode == 0:
        return RuntimeResult(0, f"traefik network '{TRAEFIK_NETWORK}' already exists", ran=True)

    proc = subprocess.run(
        ["docker", "network", "create", "--driver", "bridge", TRAEFIK_NETWORK],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        message = proc.stderr.strip() or proc.stdout.strip() or "docker network create failed"
        return RuntimeResult(proc.returncode, message)
    return RuntimeResult(0, f"traefik network '{TRAEFIK_NETWORK}' created", ran=True)


def effective_acme_email() -> str:
    """The ACME contact email Traefik will actually use: the one already
    written to traefik.yml if the proxy is scaffolded, else the env value
    a future scaffold would render."""
    config_file = traefik_config_path()
    if config_file.exists():
        for line in config_file.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith("email:"):
                return stripped.split(":", 1)[1].strip()
    return os.environ.get("WPFY_ACME_EMAIL", _DEFAULT_ACME_EMAIL)


def acme_email_problem() -> str | None:
    """Return an actionable message if certificate issuance would fail at ACME
    registration because no real contact email is configured, else None."""
    email = effective_acme_email()
    if email and email != _DEFAULT_ACME_EMAIL and _ACME_EMAIL_RE.fullmatch(email):
        return None
    return (
        f"ACME contact email is not configured (current: {email or 'unset'}); "
        "Let's Encrypt rejects invalid contact addresses. "
        "Set WPFY_ACME_EMAIL=you@example.com and re-run 'wpfy stack install --nginx', "
        "then retry enabling SSL"
    )


def traefik_static_config() -> str:
    acme_email = os.environ.get("WPFY_ACME_EMAIL", _DEFAULT_ACME_EMAIL)
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
        "",
        "certificatesResolvers:",
        "  le:",
        "    acme:",
        f"      email: {acme_email}",
        "      storage: /letsencrypt/acme.json",
        "      tlsChallenge: {}",
        # le-http validates over plain HTTP on :80, so it works for domains
        # behind a TLS-terminating proxy (e.g. Cloudflare) that forwards the
        # /.well-known/acme-challenge/ path to the origin.
        "  le-http:",
        "    acme:",
        f"      email: {acme_email}",
        "      storage: /letsencrypt/acme.json",
        "      httpChallenge:",
        "        entryPoint: web",
        "  le-dns-cloudflare:",
        "    acme:",
        f"      email: {acme_email}",
        "      storage: /letsencrypt/acme.json",
        "      dnsChallenge:",
        "        provider: cloudflare",
    ]
    return "\n".join(lines) + "\n"


def traefik_compose_content() -> str:
    config_mount = str(traefik_config_path())
    lines = [
        f"name: {TRAEFIK_PROJECT}",
        "services:",
        "  traefik:",
        f"    image: {TRAEFIK_IMAGE}",
        f"    container_name: {TRAEFIK_CONTAINER}",
        "    restart: unless-stopped",
        "    security_opt:",
        "      - no-new-privileges:true",
        "    cap_drop:",
        "      - NET_RAW",
        "    pids_limit: 256",
        "    mem_limit: 256m",
        "    cpus: 0.50",
        "    logging:",
        "      driver: json-file",
        "      options:",
        "        max-size: 10m",
        "        max-file: \"3\"",
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
        "      - letsencrypt_data:/letsencrypt",
        "    networks:",
        f"      - {TRAEFIK_NETWORK}",
        "    healthcheck:",
        "      test: [\"CMD\", \"traefik\", \"healthcheck\", \"--ping\"]",
        "      interval: 30s",
        "      timeout: 10s",
        "      retries: 3",
        "",
        "networks:",
        f"  {TRAEFIK_NETWORK}:",
        "    external: true",
        "",
        "volumes:",
        "  letsencrypt_data:",
    ])
    return "\n".join(lines) + "\n"


def ensure_traefik_scaffold() -> list[str]:
    touched: list[str] = []
    td = traefik_dir()
    if not td.exists():
        td.mkdir(parents=True, exist_ok=True)
        touched.append(str(td))

    compose_file = traefik_compose_path()
    content = traefik_compose_content()
    if not compose_file.exists() or compose_file.read_text(encoding="utf-8") != content:
        compose_file.write_text(content, encoding="utf-8")
        touched.append(str(compose_file))

    config_file = traefik_config_path()
    config_content = traefik_static_config()
    if not config_file.exists() or config_file.read_text(encoding="utf-8") != config_content:
        config_file.write_text(config_content, encoding="utf-8")
        touched.append(str(config_file))

    return touched


def start_traefik() -> RuntimeResult:
    if runtime_skip_requested():
        return RuntimeResult(0, "traefik start skipped by WPFY_SKIP_RUNTIME=1", skipped=True)
    if not docker_available():
        return RuntimeResult(0, "traefik start skipped (Docker/Compose not available)", skipped=True)

    ensure_traefik_scaffold()
    net_result = ensure_traefik_network()
    if net_result.exit_code != 0:
        return net_result

    proc = _traefik_compose("up", "-d")
    if proc.returncode != 0:
        message = proc.stderr.strip() or proc.stdout.strip() or "docker compose up failed"
        return RuntimeResult(proc.returncode, message)
    message = proc.stdout.strip() or proc.stderr.strip() or "traefik started"
    return RuntimeResult(0, message, ran=True)


def restart_traefik_existing() -> RuntimeResult:
    if runtime_skip_requested():
        return RuntimeResult(0, "traefik restart skipped by WPFY_SKIP_RUNTIME=1", skipped=True)
    if not docker_available():
        return RuntimeResult(0, "traefik restart skipped (Docker/Compose not available)", skipped=True)
    net_result = ensure_traefik_network()
    if net_result.exit_code != 0:
        return net_result
    proc = _traefik_compose("up", "-d")
    if proc.returncode != 0:
        message = proc.stderr.strip() or proc.stdout.strip() or "docker compose up failed"
        return RuntimeResult(proc.returncode, message)
    message = proc.stdout.strip() or proc.stderr.strip() or "traefik restarted"
    return RuntimeResult(0, message, ran=True)


def stop_traefik() -> RuntimeResult:
    if runtime_skip_requested() or not docker_available():
        return RuntimeResult(0, "traefik stop skipped", skipped=True)
    proc = _traefik_compose("down")
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
