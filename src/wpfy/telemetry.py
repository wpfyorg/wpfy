from __future__ import annotations

from datetime import datetime, timedelta, timezone
import fcntl
import json
import os
from pathlib import Path
import platform
import threading
from urllib.request import Request, urlopen

from . import __version__, panel_setup
from .site_layout import list_sites
from .site_runtime import list_site_services

TELEMETRY_ENDPOINT = ""
TELEMETRY_INTERVAL = timedelta(days=1)
TELEMETRY_TIMEOUT_SECONDS = 1.5
_DISABLED_VALUES = frozenset({"0", "false", "no", "off"})
_ACTIVE_STATES = frozenset({"healthy", "running"})


def endpoint() -> str:
    return os.environ.get("WPFY_TELEMETRY_ENDPOINT", TELEMETRY_ENDPOINT).strip()


def environment_disabled() -> bool:
    return os.environ.get("WPFY_TELEMETRY", "").strip().lower() in _DISABLED_VALUES


def enabled() -> bool:
    current = panel_setup.state()
    return (
        isinstance(current.get("install_id"), str)
        and bool(current.get("telemetry_enabled"))
        and not environment_disabled()
    )


def _os_release() -> tuple[str, str]:
    values = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key] = value.strip().strip('"')
    except (OSError, UnicodeDecodeError):
        pass
    name = values.get("ID") or platform.system().lower() or "unknown"
    release = values.get("VERSION_ID") or platform.release() or "unknown"
    return name, release


def _active_site_count(sites: list[dict]) -> int:
    active = 0
    for site in sites:
        domain = site.get("domain")
        if not isinstance(domain, str):
            continue
        try:
            states = {row.get("status") for row in list_site_services(domain, ("web", "app"))}
        except (OSError, ValueError):
            continue
        if states and states <= _ACTIVE_STATES:
            active += 1
    return active


def payload() -> dict:
    current = panel_setup.state()
    sites = list_sites()
    os_name, release = _os_release()
    return {
        "install_id": current["install_id"],
        "wpfy_version": __version__,
        "os": os_name,
        "release": release,
        "python_version": platform.python_version(),
        "site_count": len(sites),
        "active_sites": _active_site_count(sites),
    }


def set_enabled(value: bool) -> None:
    panel_setup.set_telemetry_enabled(value)


def status() -> dict:
    current = panel_setup.state()
    return {
        "stored_enabled": bool(current.get("telemetry_enabled")),
        "environment_override": environment_disabled(),
        "effective_enabled": enabled(),
        "endpoint_configured": bool(endpoint()),
        "last_sent_at": current.get("telemetry_last_sent_at"),
        "payload": payload(),
    }


def _parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


def _send_if_due() -> None:
    target = endpoint()
    if not target or not enabled():
        return
    lock_path = panel_setup.state_path().with_suffix(".telemetry.lock")
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        with os.fdopen(fd, "rb") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            current = panel_setup.state()
            if not bool(current.get("telemetry_enabled")) or environment_disabled():
                return
            now = datetime.now(timezone.utc)
            previous = _parse_timestamp(current.get("telemetry_last_sent_at"))
            if previous is not None and now - previous < TELEMETRY_INTERVAL:
                return
            data = json.dumps(payload(), separators=(",", ":"), sort_keys=True).encode("utf-8")
            request = Request(target, data=data, headers={"Content-Type": "application/json"}, method="POST")
            with urlopen(request, timeout=TELEMETRY_TIMEOUT_SECONDS) as response:
                if not 200 <= response.status < 300:
                    return
                response.read(1)
            timestamp = now.replace(microsecond=0).isoformat().replace("+00:00", "Z")
            panel_setup.mark_telemetry_sent(timestamp)
    except Exception:
        return


def maybe_send_async() -> None:
    threading.Thread(target=_send_if_due, name="wpfy-telemetry", daemon=True).start()
