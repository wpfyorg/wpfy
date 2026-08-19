from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
import secrets
from pathlib import Path
import re
import uuid

from . import events, panel_auth, settings

LICENSE_VERSION = "LICENSE"
# Re-exported: the floor is enforced inside panel_auth._validate_password so
# every write path gets it, not just this form.
PASSWORD_MIN_LENGTH = panel_auth.PASSWORD_MIN_LENGTH
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
        "setup_secret_hash": None,
        "setup_secret_issued_at": None,
    }


# ---------------------------------------------------------------------------
# Setup secret
#
# First-run account creation is refused over an edge-bound panel: the operator
# is expected to reach loopback through an SSH tunnel. A domainless exposure has
# no tunnel in the picture, so the secret takes the tunnel's place -- it proves
# the person creating the first administrator is the person who ran
# `wpfy panel expose` on the host, because that command is the only thing that
# prints it.
#
# Only a hash is stored, so a readable state file does not hand over the right
# to create the administrator. It is single-use and expires, because a secret
# that grants account creation should not sit valid on an internet-facing panel
# for as long as nobody happens to use it.
# ---------------------------------------------------------------------------

SETUP_SECRET_TTL_SECONDS = 3600


def _hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def issue_setup_secret() -> str:
    """Mint a one-time secret and return it. Only its hash is persisted."""
    secret = secrets.token_urlsafe(32)
    with state_lock():
        current = _default_state()
        current.update(_read_state())
        current["setup_secret_hash"] = _hash_secret(secret)
        current["setup_secret_issued_at"] = _now()
        _write_state(current)
    return secret


def clear_setup_secret() -> None:
    with state_lock():
        current = _default_state()
        current.update(_read_state())
        current["setup_secret_hash"] = None
        current["setup_secret_issued_at"] = None
        _write_state(current)


def _secret_expired(issued_at: object) -> bool:
    if not isinstance(issued_at, str) or not issued_at:
        return True
    try:
        issued = datetime.fromisoformat(issued_at.replace("Z", "+00:00"))
    except ValueError:
        return True
    return (datetime.now(timezone.utc) - issued).total_seconds() > SETUP_SECRET_TTL_SECONDS


def setup_secret_matches(secret: object) -> bool:
    """Check the secret without burning it.

    The secret has to authenticate the request before it can be spent by it: a
    domainless panel prints no run token, so the setup link is the only
    credential the browser has, and `GET /api/setup/status` must answer it. Only
    `create_account` consumes the secret, so a peek here cannot spend a grant
    that never produced an account.
    """
    if not isinstance(secret, str) or not secret:
        return False
    with state_lock():
        current = _default_state()
        current.update(_read_state())
        stored = current.get("setup_secret_hash")
        if not isinstance(stored, str) or not stored:
            return False
        if _secret_expired(current.get("setup_secret_issued_at")):
            return False
        return secrets.compare_digest(stored, _hash_secret(secret))


def consume_setup_secret(secret: object) -> bool:
    """Check and burn the secret in one locked step.

    Compared with `secrets.compare_digest` so a wrong guess cannot be narrowed
    by timing, and cleared inside the same lock the check ran under so two
    requests racing on the internet cannot both win.
    """
    if not isinstance(secret, str) or not secret:
        return False
    with state_lock():
        current = _default_state()
        current.update(_read_state())
        stored = current.get("setup_secret_hash")
        if not isinstance(stored, str) or not stored:
            return False
        if _secret_expired(current.get("setup_secret_issued_at")):
            current["setup_secret_hash"] = None
            current["setup_secret_issued_at"] = None
            _write_state(current)
            return False
        if not secrets.compare_digest(stored, _hash_secret(secret)):
            return False
        current["setup_secret_hash"] = None
        current["setup_secret_issued_at"] = None
        _write_state(current)
        return True


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


def status(*, remote: bool) -> dict:
    configured = panel_auth.login_required()
    if configured:
        return {"configured": True, "setup_available": False}
    return {
        "configured": False,
        "setup_available": True,
        "edge_bound": remote,
        "password_min_length": PASSWORD_MIN_LENGTH,
    }


def _text(value: object, field: str, maximum: int = 80) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > maximum:
        raise ValueError(f"{field} is required and must be at most {maximum} characters")
    return value.strip()


def create_account(body: dict, *, client: str | None, remote: bool) -> tuple[str, dict]:
    # Account creation over the edge used to be refused outright, on the
    # reasoning that the operator can always reach loopback through an SSH
    # tunnel. A domainless exposure has no tunnel in the picture, so the refusal
    # stands unless the request carries the one-time secret that
    # `wpfy panel expose` printed on the host. The secret is burned on use, so a
    # request that gets this far cannot be replayed -- and without one the
    # original refusal is unchanged, including its wording.
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

    # Recheck immediately before the atomic burn. The check releases the auth
    # lock before state_lock is acquired, preserving lock-order independence.
    if remote:
        if panel_auth.client_throttled(client):
            raise panel_auth.ClientThrottleError("too many setup attempts; try again later")
        try:
            consumed = consume_setup_secret(body.get("setup_secret"))
        except ValueError:
            panel_auth.register_client_failure(client)
            raise
        if not consumed:
            panel_auth.register_client_failure(client)
            raise ValueError(
                "first-run setup is disabled on a panel reachable from off this host; "
                "open the one-time setup link printed by `wpfy panel expose`, or use the SSH tunnel"
            )

    try:
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
    except ValueError:
        panel_auth.register_client_failure(client)
        raise
    events.record_event("panel.setup.completed", actor=username)
    result = panel_auth.login(username, password, client=client, setup=True)
    if result is None:
        panel_auth.register_client_failure(client)
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
