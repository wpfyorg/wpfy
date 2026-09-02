"""File manager provider lifecycle and session management."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import os
import subprocess
import threading
from typing import Protocol

from .site_runtime import runtime_skip_requested


_PROVIDER_STATE_DIR = ".wpfy/file-manager"
_IDLE_SHUTDOWN_SECONDS = 15 * 60
_IDLE_WARNING_SECONDS = 2 * 60
_LEASE_VALIDITY_SECONDS = 120
_STARTUP_TIMEOUT_SECONDS = 60
_LIMIT_MESSAGE = "The server has reached its active file-manager limit. Disable an inactive file manager or try again later."


class FileManagerError(RuntimeError):
    """File manager operation error."""
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True)
class FileManagerState:
    """File manager instance state."""
    state: str
    domain: str
    provider: str | None = None
    enabled_at: str | None = None
    last_lease_at: str | None = None
    last_operation_at: str | None = None
    idle_expires_at: str | None = None
    lease_holders: list[str] = field(default_factory=list)
    active_leases: int = 0
    health: str = "unknown"
    error: str | None = None


class FileManagerProvider(Protocol):
    """File manager provider interface."""
    def ensure_config(self, domain: str) -> None:
        """Ensure provider configuration for domain."""
        ...
    def start(self, domain: str) -> None:
        """Start file manager for domain."""
        ...
    def stop(self, domain: str) -> None:
        """Stop file manager for domain."""
        ...
    def status(self, domain: str) -> dict:
        """Get file manager status for domain."""
        ...
    def health(self, domain: str) -> bool:
        """Check file manager health for domain."""
        ...
    def create_launch_session(self, domain: str, username: str) -> str:
        """Create launch session for user on domain."""
        ...
    def reset_metadata(self, domain: str) -> None:
        """Reset file manager metadata for domain."""
        ...


_locks: dict[str, threading.Lock] = {}
_locks_lock = threading.Lock()


def _get_lock(domain: str) -> threading.Lock:
    """Reset metadata."""
    with _locks_lock:
        if domain not in _locks:
            _locks[domain] = threading.Lock()
        return _locks[domain]


def _state_path(domain: str) -> str:
    from .site_paths import site_dir
    return str(site_dir(domain) / _PROVIDER_STATE_DIR / "state.json")


def _read_state(domain: str) -> dict | None:
    path = _state_path(domain)
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def _host_ram_gb() -> float:
    return os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE") / (1024**3)


def _max_file_managers() -> int:
    override = os.environ.get("WPFY_FM_MAX")
    if override is not None:
        try:
            return int(override)
        except ValueError:
            pass
    ram_gb = _host_ram_gb()
    if ram_gb < 4:
        return 1
    if ram_gb < 8:
        return 2
    if ram_gb < 16:
        return 4
    return 8


def count_running_file_managers() -> int:
    """Count running file managers."""
    if runtime_skip_requested():
        return 0
    try:
        result = subprocess.run(
            ["docker", "ps", "-q", "--filter", "label=wpfy.kind=file-manager"],
            check=False,
            capture_output=True,
            text=True,
        )
        return len(result.stdout.splitlines()) if result.returncode == 0 else 0
    except (OSError, subprocess.SubprocessError):
        return 0


def _write_state(domain: str, state: dict) -> None:
    path = _state_path(domain)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, default=str)
    os.replace(tmp, path)


def get_file_manager_state(domain: str, provider: FileManagerProvider | None = None) -> FileManagerState:
    """Get file manager state."""
    stored = _read_state(domain) or {}
    holders = stored.get("lease_holders", [])
    if not isinstance(holders, list):
        holders = []
    return FileManagerState(
        state=stored.get("state", "disabled"),
        domain=domain,
        provider=stored.get("provider"),
        enabled_at=stored.get("enabled_at"),
        last_lease_at=stored.get("last_lease_at"),
        last_operation_at=stored.get("last_operation_at"),
        idle_expires_at=stored.get("idle_expires_at"),
        lease_holders=holders,
        active_leases=len(holders),
        health=stored.get("health", "unknown"),
        error=stored.get("error"),
    )


def enable_file_manager(domain: str, username: str, provider: FileManagerProvider) -> dict:
    """Enable file manager."""
    from .site_paths import site_exists, app_dir

    if not site_exists(domain):
        raise FileManagerError("site_not_found", f"site not found: {domain}")
    if not os.path.isdir(app_dir(domain)):
        raise FileManagerError("app_dir_missing", f"application directory not found for {domain}")

    lock = _get_lock(domain)
    with lock:
        current = _read_state(domain) or {}
        state = current.get("state", "disabled")
        if state == "ready":
            url = provider.create_launch_session(domain, username)
            return {"state": "ready", "url": url}
        if state == "starting":
            return {"state": "starting"}
        if state == "failed":
            pass
        if state not in {"starting", "ready", "idle-warning"} and count_running_file_managers() >= _max_file_managers():
            raise FileManagerError("limit_reached", _LIMIT_MESSAGE)

        _write_state(domain, {
            "state": "starting",
            "domain": domain,
            "provider": "filebrowser-quantum",
            "enabled_at": datetime.now(timezone.utc).isoformat(),
            "health": "unknown",
            "lease_holders": [],
        })

        phase = "config"
        try:
            provider.ensure_config(domain)
            phase = "start"
            provider.start(domain)
            phase = "health"
            healthy = provider.health(domain)
            if not healthy:
                raise FileManagerError("health_failed", "file manager health check failed")
            now = datetime.now(timezone.utc).isoformat()
            idle_expires = datetime.now(timezone.utc).timestamp() + _IDLE_SHUTDOWN_SECONDS
            _write_state(domain, {
                "state": "ready",
                "domain": domain,
                "provider": "filebrowser-quantum",
                "enabled_at": current.get("enabled_at") or now,
                "last_lease_at": now,
                "idle_expires_at": datetime.fromtimestamp(idle_expires, tz=timezone.utc).isoformat(),
                "lease_holders": [],
                "active_leases": 0,
                "health": "healthy",
                "error": None,
            })
            url = provider.create_launch_session(domain, username)
            return {"state": "ready", "url": url}
        except Exception as exc:  # noqa: BLE001
            code = exc.code if isinstance(exc, FileManagerError) else {
                "config": "config_failed",
                "start": "start_failed",
                "health": "health_failed",
            }[phase]
            if not runtime_skip_requested():
                try:
                    provider.stop(domain)
                except Exception:  # noqa: BLE001
                    pass
            error = exc if isinstance(exc, FileManagerError) else FileManagerError(code, str(exc))
            _write_state(domain, {
                "state": "failed",
                "domain": domain,
                "provider": "filebrowser-quantum",
                "health": "unhealthy",
                "error": str(exc),
                "code": code,
                "lease_holders": current.get("lease_holders", []),
            })
            raise error from exc


def mark_ready(domain: str) -> dict:
    """Mark ready."""
    with _get_lock(domain):
        current = _read_state(domain) or {}
        now = datetime.now(timezone.utc)
        idle_expires = now.timestamp() + _IDLE_SHUTDOWN_SECONDS
        _write_state(domain, {
            "state": "ready",
            "domain": domain,
            "provider": "filebrowser-quantum",
            "enabled_at": current.get("enabled_at") or now.isoformat(),
            "idle_expires_at": datetime.fromtimestamp(idle_expires, tz=timezone.utc).isoformat(),
            "lease_holders": [],
            "active_leases": 0,
            "health": "healthy",
            "error": None,
        })
    return {"state": "ready"}


def disable_file_manager(domain: str, provider: FileManagerProvider) -> dict:
    """Disable file manager."""
    lock = _get_lock(domain)
    with lock:
        try:
            provider.stop(domain)
        except Exception:
            pass
        _write_state(domain, {
            "state": "disabled",
            "domain": domain,
            "provider": None,
            "health": "unknown",
            "lease_holders": [],
            "active_leases": 0,
            "error": None,
        })
    return {"state": "disabled"}


def create_lease(domain: str, username: str | None = None) -> dict:
    """Create lease."""
    with _get_lock(domain):
        now = datetime.now(timezone.utc)
        stored = _read_state(domain) or {}
        new_expires = now.timestamp() + _LEASE_VALIDITY_SECONDS
        holders = list(dict.fromkeys(stored.get("lease_holders", [])))
        if username is not None and username not in holders:
            holders.append(username)
        leases = len(holders)
        # ponytail: no per-holder TTL yet; todo 9 reaper can add expiry metadata.
        _write_state(domain, {
            **stored,
            "last_lease_at": now.isoformat(),
            "idle_expires_at": datetime.fromtimestamp(new_expires, tz=timezone.utc).isoformat(),
            "lease_holders": holders,
            "active_leases": leases,
        })
    return {
        "idle_expires_at": datetime.fromtimestamp(new_expires, tz=timezone.utc).isoformat(),
        "active_leases": leases,
    }


def lease_holder_usernames(domain: str) -> list[str]:
    """Lease holder usernames."""
    return list(dict.fromkeys((_read_state(domain) or {}).get("lease_holders", [])))


def launch_session(domain: str, username: str, provider: FileManagerProvider) -> dict:
    """Launch session."""
    state = _read_state(domain) or {}
    if state.get("state") != "ready":
        raise RuntimeError("file manager is not ready")
    url = provider.create_launch_session(domain, username)
    return {"url": url}


def is_in_warning_window(domain: str) -> bool:
    """Check if in warning window."""
    stored = _read_state(domain) or {}
    expires = stored.get("idle_expires_at")
    if not expires or stored.get("state") != "ready":
        return False
    try:
        deadline = datetime.fromisoformat(expires).timestamp()
        return datetime.now(timezone.utc).timestamp() >= deadline - _IDLE_WARNING_SECONDS
    except (ValueError, OSError):
        return False
