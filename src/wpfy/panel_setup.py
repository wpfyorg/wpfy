from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import re
import uuid

from . import events, panel_auth, settings

LICENSE_VERSION = "LICENSE"
PASSWORD_MIN_LENGTH = 12
_EMAIL_SHAPE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def state_path() -> Path:
    return Path(settings.PATHS.config_dir) / "panel-state.json"


@contextmanager
def state_lock():
    path = state_path().with_suffix(".lock")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _default_state() -> dict:
    return {
        "install_id": None,
        "telemetry_enabled": False,
        "telemetry_last_sent_at": None,
        "license_accepted_at": None,
        "license_accepted_by": None,
        "license_version": LICENSE_VERSION,
    }


def _read_state() -> dict:
    path = state_path()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"panel state is unreadable: {path}") from exc
    if not isinstance(raw, dict):
        raise ValueError(f"panel state is invalid: {path}")
    return raw


def _write_state(state: dict) -> None:
    path = state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(state, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("utf-8")
    temp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        os.chmod(path, 0o600)
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


def state() -> dict:
    with state_lock():
        current = _default_state()
        current.update(_read_state())
        return current


def status(*, edge_bind: bool) -> dict:
    configured = panel_auth.login_required()
    if configured:
        return {"configured": True, "setup_available": False}
    return {
        "configured": False,
        "setup_available": True,
        "edge_bound": edge_bind,
        "password_min_length": PASSWORD_MIN_LENGTH,
    }


def _text(value: object, field: str, maximum: int = 80) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > maximum:
        raise ValueError(f"{field} is required and must be at most {maximum} characters")
    return value.strip()


def create_account(body: dict, *, client: str | None, edge_bind: bool) -> tuple[str, dict]:
    if edge_bind:
        raise ValueError("first-run setup is disabled while the panel is edge-bound; use the SSH tunnel")
    if panel_auth.client_throttled(client):
        raise panel_auth.ClientThrottleError("too many setup attempts; try again later")
    try:
        first_name = _text(body.get("first_name"), "first name")
        last_name = _text(body.get("last_name"), "last name")
        username = panel_auth.validate_username(body.get("username"))
        email = _text(body.get("email"), "email", 254)
        if not _EMAIL_SHAPE.fullmatch(email):
            raise ValueError("email must be a valid email-shaped value")
        password = panel_auth.validate_password(body.get("password"))
        if len(password) < PASSWORD_MIN_LENGTH:
            raise ValueError(f"password must be at least {PASSWORD_MIN_LENGTH} characters")
        if password != body.get("confirm_password"):
            raise ValueError("password and confirm password must match")
        if body.get("license_accepted") is not True:
            raise ValueError("you must accept the LICENSE and no-warranty acknowledgement")
        telemetry_enabled = body.get("telemetry_enabled", True)
        if not isinstance(telemetry_enabled, bool):
            raise ValueError("telemetry_enabled must be a boolean")
    except ValueError:
        panel_auth.register_client_failure(client)
        raise

    with state_lock():
        if panel_auth.login_required():
            raise ValueError("first-run setup is permanently closed")
        current = _default_state()
        current.update(_read_state())
        if not current.get("install_id"):
            current["install_id"] = str(uuid.uuid4())
        current.update({
            "telemetry_enabled": telemetry_enabled,
            "license_accepted_at": _now(),
            "license_accepted_by": username,
            "license_version": LICENSE_VERSION,
        })
        _write_state(current)
        panel_auth.add_user(
            username,
            password,
            role=panel_auth.ROLE_ADMIN,
            first_name=first_name,
            last_name=last_name,
            email=email,
        )
    events.record_event("panel.setup.completed", actor=username)
    result = panel_auth.login(username, password, client=client, setup=True)
    if result is None:
        raise ValueError("account was created but the setup session could not be opened")
    return result


def mark_telemetry_sent(timestamp: str) -> None:
    with state_lock():
        current = _default_state()
        current.update(_read_state())
        current["telemetry_last_sent_at"] = timestamp
        _write_state(current)


def set_telemetry_enabled(enabled: bool) -> None:
    with state_lock():
        current = _default_state()
        current.update(_read_state())
        current["telemetry_enabled"] = bool(enabled)
        _write_state(current)
