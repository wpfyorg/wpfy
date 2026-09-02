"""Docker daemon IPv6 configuration.

wpfy depends on the Docker daemon for every workload it installs, so bringing
the daemon's own IPv6 settings in line is host-level management of a dependency
(the same shape as ``stack install``'s idempotent fail2ban management), not the
forbidden "run Nginx/PHP/MariaDB/Redis on the host".

Hard rules, all deliberate:
- merge, never clobber: keys wpfy does not own survive untouched;
- refuse on unparseable JSON rather than overwrite what we could not read;
- back up before any first write;
- never restart Docker -- that stops every container on the host. The operator
  runs ``systemctl restart docker`` themselves after seeing the consequence.
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from . import traefik
from .site_runtime import RuntimeResult, runtime_skip_requested

DAEMON_JSON_PATH = Path("/etc/docker/daemon.json")

#: Keys wpfy owns inside daemon.json. Anything else in the file is the
#: operator's and must survive every write.
WPFY_DAEMON_KEYS = ("ipv6", "ip6tables", "fixed-cidr-v6")

#: Documented default ULA subnet for the daemon's default-bridge pool (docker0).
#: One reserved /64 out of wpfy's prefix, not the whole prefix: fixed-cidr-v6
#: set to the parent /48 would overlap every subnet wpfy hands out beneath it.
DEFAULT_ULA_SUBNET = traefik.wpfy_ula_subnet(traefik.WPFY_ULA_INDEX_DOCKER_BRIDGE)

_DOCKER_INSPECT_TIMEOUT_SECONDS = 15

_TEST_HOST_IPV6 = "WPFY_TEST_HOST_IPV6"
_TEST_DAEMON_PATH = "WPFY_TEST_DAEMON_JSON"


@dataclass(frozen=True, slots=True)
class DaemonIPv6Plan:
    """What ``ensure_daemon_ipv6`` decided, without side effects."""

    needed: bool
    desired: dict[str, object]
    current: dict[str, object] | None
    backup_path: str | None


def host_has_global_ipv6() -> bool:
    """True when the host has at least one global-scope IPv6 address."""
    override = os.environ.get(_TEST_HOST_IPV6)
    if override is not None:
        return override == "1"
    if os.environ.get("WPFY_SKIP_RUNTIME", "0") == "1":
        return False
    if not shutil.which("ip"):
        return False
    with contextlib.suppress(FileNotFoundError, OSError):
        proc = subprocess.run(
            ["ip", "-6", "addr", "show", "scope", "global"],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return True
    return False


def _daemon_path() -> Path:
    override = os.environ.get(_TEST_DAEMON_PATH)
    return Path(override) if override else DAEMON_JSON_PATH


def read_daemon_config() -> tuple[dict[str, object], bool]:
    """Return (config, exists). Raises on JSON that does not parse.

    A missing file reads as empty; an existing file that is not valid JSON is
    an error, never an empty config to be overwritten.
    """
    path = _daemon_path()
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}, False
    except OSError as exc:
        raise RuntimeError(f"cannot read {path}: {exc}") from exc
    try:
        parsed = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"{path} is not valid JSON ({exc.msg} at line {exc.lineno}); "
            f"refusing to modify it. Fix or remove the file, then retry."
        ) from exc
    if not isinstance(parsed, dict):
        raise RuntimeError(f"{path} must contain a JSON object, got {type(parsed).__name__}")
    return parsed, True


def desired_daemon_ipv6(subnet: str | None = None) -> dict[str, object]:
    """Desired daemon ipv6."""
    return {
        "ipv6": True,
        "ip6tables": True,
        "fixed-cidr-v6": subnet or DEFAULT_ULA_SUBNET,
    }


def plan_daemon_ipv6(subnet: str | None = None) -> DaemonIPv6Plan:
    """Compute the diff between the file and the desired state."""
    current, exists = read_daemon_config()
    desired = desired_daemon_ipv6(subnet)
    needed = any(current.get(key) != value for key, value in desired.items())
    backup = None
    if needed and exists:
        backup = str(_backup_path())
    return DaemonIPv6Plan(needed=needed, desired=desired, current=current, backup_path=backup)


def _backup_path() -> Path:
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    return _daemon_path().with_name(f"daemon.json.wpfy-{stamp}.bak")


def ensure_daemon_ipv6(*, enable: bool | None = None, subnet: str | None = None) -> RuntimeResult:
    """Merge wpfy's IPv6 keys into /etc/docker/daemon.json. Never restarts Docker.

    ``enable=False`` removes wpfy's keys (explicit opt-out); ``enable=None``
    decides from the host: enabled when the host has global IPv6.
    """
    if runtime_skip_requested():
        # Every other host-mutating path honours this hook; this one writes to
        # /etc/docker/daemon.json, so it honours it hardest.
        return RuntimeResult(0, "Docker daemon IPv6 skipped by WPFY_SKIP_RUNTIME=1", skipped=True)

    if enable is None:
        enable = host_has_global_ipv6()

    path = _daemon_path()
    current, exists = read_daemon_config()

    if not enable:
        if not any(key in current for key in WPFY_DAEMON_KEYS):
            return RuntimeResult(0, "Docker daemon IPv6 already disabled (no wpfy keys present)", ran=True)
        desired = {key: value for key, value in current.items() if key not in WPFY_DAEMON_KEYS}
        action = "removed"
    else:
        desired = {**current, **desired_daemon_ipv6(subnet)}
        if desired == current:
            return RuntimeResult(0, "Docker daemon IPv6 already configured", ran=True)
        action = "applied"

    if exists:
        backup = _backup_path()
        shutil.copy2(path, backup)

    rendered = json.dumps(desired, indent=2, sort_keys=True) + "\n"
    _atomic_write_daemon_config(path, rendered, exists=exists)

    message = (
        f"{action} IPv6 keys {', '.join(sorted(WPFY_DAEMON_KEYS))} in {path}. "
        "The running daemon still has IPv6 off until it is restarted: run "
        "'sudo systemctl restart docker' yourself -- that stops EVERY container "
        "on this host (all sites go down briefly). Schedule it."
        if action == "applied"
        else f"removed wpfy IPv6 keys from {path}; restart Docker to apply "
             "(stops every container on the host)"
    )
    return RuntimeResult(0, message, ran=True)


def _atomic_write_daemon_config(path: Path, rendered: str, *, exists: bool) -> None:
    """Durably replace daemon JSON without exposing a truncated live file.

    ``daemon.json`` is not a bind-mounted per-container file, so atomic
    replacement is safer than truncating its live inode: an interruption after
    ``O_TRUNC`` otherwise leaves Docker with invalid JSON and unable to restart.
    Existing mode and ownership survive the replacement.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    stat = path.stat() if exists else None
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        if stat is not None:
            os.fchmod(fd, stat.st_mode & 0o777)
            os.fchown(fd, stat.st_uid, stat.st_gid)
        else:
            os.fchmod(fd, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(rendered)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()
        raise


def daemon_ipv6_active() -> bool:
    """True only when the *running* daemon has IPv6 on.

    Deliberately not a read of daemon.json. ``ensure_daemon_ipv6`` never
    restarts Docker, so between the write and the operator's restart the file
    says enabled while the daemon it describes still has IPv6 off. Anything
    that gates a protection on "IPv6 is active" must see the daemon, not our
    own intent -- believing the file is how you claim to enforce IPv6 while
    every v6 packet is still being NAT'd through the userland proxy.

    The default ``bridge`` mirrors the daemon's ``ipv6`` setting, but it alone
    does not prove WPFY traffic uses kernel IPv6 forwarding. Both WPFY shared
    edge networks must also be IPv6-enabled. Anything that goes wrong (no
    docker, no permission, timeout, missing network, junk output) answers
    False: unknown is not active.
    """
    if os.environ.get("WPFY_SKIP_RUNTIME", "0") == "1":
        return False
    if not shutil.which("docker"):
        return False
    try:
        proc = subprocess.run(
            [
                "docker", "network", "inspect", "--format", "{{.EnableIPv6}}",
                "bridge", traefik.TRAEFIK_NETWORK, traefik.PANEL_EDGE_NETWORK,
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=_DOCKER_INSPECT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    states = [line.strip().lower() for line in proc.stdout.splitlines() if line.strip()]
    return proc.returncode == 0 and states == ["true", "true", "true"]
