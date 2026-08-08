from __future__ import annotations

import json
import os
import secrets
import shutil
import socket
import subprocess
import urllib.error
import urllib.request

from ..site_paths import app_dir, domain_to_project, site_dir
from ..site_runtime import compose_command, docker_available, runtime_skip_requested


_QUANTUM_IMAGE = (
    "gtstef/filebrowser:1.5.0-stable-slim@"
    "sha256:aadfaa026ebae24e373e523662cd9e8f562b5e3c404ac1df65ef13ddcd14b2fc"
)
_QUANTUM_VERSION = "1.5.0-stable-slim"
_IMAGE_DIGEST = "aadfaa026ebae24e373e523662cd9e8f562b5e3c404ac1df65ef13ddcd14b2fc"
_HEALTH_TIMEOUT = 3.0
_START_TIMEOUT = 60
_FIRST_PORT = 8081


def _fm_dir(domain: str) -> str:
    return str(site_dir(domain) / ".wpfy" / "file-manager")


def _compose_path(domain: str) -> str:
    return str(site_dir(domain) / ".wpfy" / "file-manager-compose.yaml")


def _project(domain: str) -> str:
    return domain_to_project(domain)


def _container_name(domain: str) -> str:
    return f"wpfy-fm-{_project(domain)}"


def _resolve_uid_gid(domain: str) -> tuple[int, int]:
    stat = os.stat(app_dir(domain))
    return stat.st_uid, stat.st_gid


def _port_path(domain: str) -> str:
    return os.path.join(_fm_dir(domain), "port")


def _read_port(domain: str) -> int:
    with open(_port_path(domain), encoding="utf-8") as port_file:
        return int(port_file.read().strip())


def provider_port(domain: str) -> int:
    return _read_port(domain)


def _allocate_port(domain: str) -> int:
    path = _port_path(domain)
    if os.path.exists(path):
        return _read_port(domain)
    port = _FIRST_PORT
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            try:
                probe.bind(("127.0.0.1", port))
            except OSError:
                port += 1
                continue
        with open(path, "w", encoding="utf-8") as port_file:
            port_file.write(str(port))
        os.chmod(path, 0o600)
        return port
    # ponytail: ceiling — probe-then-release race means two concurrent enables
    # across sites can both observe the same port free, then both claim it;
    # the loser is stuck until something rewrites the port file. Upgrade path:
    # hold the bound socket until compose up succeeds (refactor to a context
    # manager returned by _allocate_port and consumed by start()).



def _existing_auth_key(config_path: str) -> str | None:
    if not os.path.exists(config_path):
        return None
    with open(config_path, encoding="utf-8") as config_file:
        for line in config_file:
            if line.startswith("  key:"):
                value = line.split(":", 1)[1].strip().strip('"')
                return value or None
    return None


def _config(auth_key: str) -> str:
    return f'''server:
  listen: "0.0.0.0"
  port: 80
  database: "/home/filebrowser/data/database.db"
  cacheDir: "/home/filebrowser/data/cache"
  sources:
    - path: "/srv"
      config:
        private: true
auth:
  key: "{auth_key}"
  tokenExpirationHours: 2
  methods:
    proxy:
      enabled: true
      header: "X-Forwarded-User"
    password:
      enabled: false
      signup: false
    noauth: false
userDefaults:
  account:
    permissions:
      share: false
'''


def ensure_config(domain: str) -> None:
    """Create the per-site Quantum config, compose file, and stable port."""
    fm_dir = _fm_dir(domain)
    os.makedirs(fm_dir, mode=0o700, exist_ok=True)
    os.chmod(fm_dir, 0o700)
    config_path = os.path.join(fm_dir, "config.yaml")
    auth_key = _existing_auth_key(config_path) or secrets.token_hex(32)
    with open(config_path, "w", encoding="utf-8") as config_file:
        config_file.write(_config(auth_key))
    os.chmod(config_path, 0o600)

    port = _allocate_port(domain)
    uid, gid = _resolve_uid_gid(domain)
    project = _project(domain)
    app = str(app_dir(domain))
    data = fm_dir
    compose = f'''services:
  file-manager:
    image: {_QUANTUM_IMAGE}
    container_name: {_container_name(domain)}
    user: "{uid}:{gid}"
    environment:
      FILEBROWSER_CONFIG: /home/filebrowser/data/config.yaml
    ports:
      - "127.0.0.1:{port}:80"
    volumes:
      - {app}:/srv:rw
      - {data}:/home/filebrowser/data:rw
    read_only: true
    tmpfs:
      - /tmp:size=128M,mode=1777
    cap_drop:
      - ALL
    no_new_privileges: true
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: "0.50"
          pids: 128
    labels:
      wpfy.managed: "true"
      wpfy.kind: "file-manager"
      wpfy.site: "{domain}"
      wpfy.provider: "filebrowser-quantum"
      wpfy.version: "{_QUANTUM_VERSION}"
      wpfy.image-digest: "{_IMAGE_DIGEST}"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:80/health"]
      interval: 10s
      timeout: 5s
      retries: 3
      start_period: 20s
'''
    compose_path = _compose_path(domain)
    with open(f"{compose_path}.tmp", "w", encoding="utf-8") as compose_file:
        compose_file.write(compose)
    os.replace(f"{compose_path}.tmp", compose_path)


def start(domain: str) -> None:
    """Start Quantum through its isolated per-site Compose project."""
    if runtime_skip_requested():
        return
    if not docker_available():
        raise RuntimeError("Docker is not available")
    proc = compose_command(
        domain,
        "-f",
        _compose_path(domain),
        "-p",
        _container_name(domain),
        "up",
        "-d",
        "--wait",
        "--wait-timeout",
        str(_START_TIMEOUT),
    )
    if proc.returncode != 0:
        try:
            port = _read_port(domain)
            reallocated = _reallocate_if_collision(domain, port) != port
        except (OSError, ValueError):
            reallocated = False
        if reallocated:
            proc = compose_command(
                domain,
                "-f",
                _compose_path(domain),
                "-p",
                _container_name(domain),
                "up",
                "-d",
                "--wait",
                "--wait-timeout",
                str(_START_TIMEOUT),
            )
        if proc.returncode != 0:
            try:
                stop(domain)
            except (OSError, subprocess.SubprocessError):
                pass
            error = proc.stderr.strip() or proc.stdout.strip() or "docker compose up failed"
            raise RuntimeError(f"file manager start failed: {error}")


def _rewrite_compose_port(domain: str, old_port: int, new_port: int) -> None:
    compose_path = _compose_path(domain)
    if not os.path.exists(compose_path):
        return
    needle = f'"127.0.0.1:{old_port}:80"'
    replacement = f'"127.0.0.1:{new_port}:80"'
    text = open(compose_path, encoding="utf-8").read()
    if needle not in text:
        return
    text = text.replace(needle, replacement)
    tmp = f"{compose_path}.tmp"
    with open(tmp, "w", encoding="utf-8") as compose_file:
        compose_file.write(text)
    os.replace(tmp, compose_path)


def _reallocate_if_collision(domain: str, port: int) -> int:
    """If `port` is still loopback-bindable, return it unchanged.
    On collision, allocate a fresh port (rewriting the port file) and rewrite
    the compose file's port mapping. Returns the port that should be used.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            pass
        else:
            return port
    os.remove(_port_path(domain))
    new_port = _allocate_port(domain)
    _rewrite_compose_port(domain, port, new_port)
    return new_port


def stop(domain: str) -> None:
    """Stop Quantum without removing per-site metadata."""
    if runtime_skip_requested():
        return
    compose_command(
        domain,
        "-f",
        _compose_path(domain),
        "-p",
        _container_name(domain),
        "down",
        "--timeout",
        "10",
    )


def status(domain: str) -> dict:
    """Return Compose container status for this site's Quantum service."""
    compose_path = _compose_path(domain)
    if not os.path.exists(compose_path):
        return {"running": False, "detail": "no compose file"}
    proc = compose_command(domain, "-f", compose_path, "-p", _container_name(domain), "ps", "--format", "json")
    containers = []
    for line in proc.stdout.strip().splitlines():
        try:
            containers.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return {"running": any(container.get("State") == "running" for container in containers), "containers": containers}


def health(domain: str) -> bool:
    """Check loopback HTTP readiness and verify the expected container owns it."""
    if not os.path.exists(_compose_path(domain)):
        return False
    try:
        port = _read_port(domain)
        request = urllib.request.Request(f"http://127.0.0.1:{port}/health")
        with urllib.request.urlopen(request, timeout=_HEALTH_TIMEOUT) as response:
            if not 200 <= response.status < 300:
                return False
        proc = subprocess.run(
            ["docker", "inspect", "-f", "{{.Name}}", _container_name(domain)],
            check=False,
            capture_output=True,
            text=True,
            timeout=_HEALTH_TIMEOUT,
        )
        return proc.returncode == 0 and proc.stdout.strip().lstrip("/") == _container_name(domain)
    except (OSError, ValueError, urllib.error.URLError, subprocess.SubprocessError):
        return False


def create_launch_session(domain: str, username: str) -> str:
    """Delegate session auth to panel proxy via X-Forwarded-User."""
    del username
    return f"/api/sites/{domain}/file-manager/proxy/"


def reset_metadata(domain: str) -> None:
    """Stop Quantum and remove its config, SQLite databases, and caches."""
    try:
        stop(domain)
    except (OSError, subprocess.SubprocessError):
        pass
    fm_dir = _fm_dir(domain)
    for root, dirs, files in os.walk(fm_dir, topdown=False):
        for filename in files:
            if filename == "config.yaml" or filename.endswith((".db", ".sqlite", ".sqlite3")):
                os.remove(os.path.join(root, filename))
        for directory in dirs:
            if directory in {"cache", "tmp"}:
                path = os.path.join(root, directory)
                if os.path.isdir(path):
                    shutil.rmtree(path)
