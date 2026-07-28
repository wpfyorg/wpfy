from __future__ import annotations

import base64
from contextlib import contextmanager
import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import struct
import threading
import time
from dataclasses import dataclass, replace
from pathlib import Path
from urllib.parse import quote

from . import events, settings
from .site_paths import validate_domain

ROLE_ADMIN = "admin"
ROLE_SITE_MANAGER = "site-manager"
ROLES = frozenset({ROLE_ADMIN, ROLE_SITE_MANAGER})

SESSION_IDLE_SECONDS = 30 * 60
SESSION_ABSOLUTE_SECONDS = 12 * 60 * 60
MAX_LOGIN_FAILURES = 5
LOCKOUT_SECONDS = 5 * 60
MAX_CLIENT_FAILURES = 10
CLIENT_COOLDOWN_SECONDS = 60
TOTP_STEP_SECONDS = 30
TOTP_SKEW_STEPS = 1

_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_LENGTH = 32
_SALT_BYTES = 16
_TOTP_SECRET_BYTES = 20
_USERNAME = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$")
_DUMMY_SALT = b"wpfy-panel-auth-dummy-salt"
_STATE_LOCK = threading.RLock()


@dataclass(frozen=True, slots=True)
class Session:
    username: str
    created_at: float
    last_seen_at: float
    setup: bool = False


class ClientThrottleError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class LoginFailure:
    count: int
    locked_until: float = 0.0


@dataclass(frozen=True, slots=True)
class ClientFailure:
    count: int
    cooldown_until: float
    expires_at: float


_SESSIONS: dict[str, Session] = {}
_LOGIN_FAILURES: dict[str, LoginFailure] = {}
_CLIENT_FAILURES: dict[str, ClientFailure] = {}
_LAST_TOTP_STEPS: dict[str, int] = {}
_PENDING_TOTP: dict[str, str] = {}
_PENDING_TOTP_DISCLOSED: set[str] = set()


class UserStoreError(ValueError):
    pass


def users_path() -> Path:
    return Path(settings.PATHS.config_dir) / "panel-users.json"


@contextmanager
def _store_lock():
    path = users_path().with_suffix(".lock")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _validate_username(username: str) -> str:
    if not isinstance(username, str) or not _USERNAME.fullmatch(username):
        raise ValueError("username must use 1-64 letters, digits, '_', '.', '@', or '-'")
    return username


def _validate_password(password: str) -> str:
    if not isinstance(password, str) or not password:
        raise ValueError("password must be a non-empty string")
    return password


def _validate_role(role: str) -> str:
    if role not in ROLES:
        raise ValueError(f"role must be one of: {', '.join(sorted(ROLES))}")
    return role


def validate_username(username: object) -> str:
    return _validate_username(username)


def validate_password(password: object) -> str:
    return _validate_password(password)


def _validated_sites(sites) -> list[str]:
    if isinstance(sites, (str, bytes)):
        raise ValueError("sites must be a list of domains")
    try:
        values = list(sites)
    except TypeError as exc:
        raise ValueError("sites must be a list of domains") from exc
    normalized = []
    for domain in values:
        if not isinstance(domain, str):
            raise ValueError("site assignments must be domain strings")
        validate_domain(domain)
        normalized.append(domain)
    return sorted(set(normalized))


def _read_users() -> list[dict]:
    path = users_path()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UserStoreError(f"panel user store is unreadable: {path}") from exc
    users = raw.get("users") if isinstance(raw, dict) else raw
    if not isinstance(users, list) or any(not isinstance(entry, dict) for entry in users):
        raise UserStoreError(f"panel user store is invalid: {path}")
    return users


def _write_users(users: list[dict]) -> None:
    path = users_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps({"users": users}, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("utf-8")
    temp = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
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


def _find_user(users: list[dict], username: str) -> dict | None:
    return next((entry for entry in users if entry.get("username") == username), None)


def _password_record(password: str) -> tuple[str, str]:
    salt = secrets.token_bytes(_SALT_BYTES)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_SCRYPT_LENGTH,
    )
    return digest.hex(), salt.hex()


def _public_user(user: dict) -> dict:
    return {
        "username": user.get("username"),
        "first_name": user.get("first_name", ""),
        "last_name": user.get("last_name", ""),
        "email": user.get("email", ""),
        "role": user.get("role"),
        "sites": list(user.get("sites") or []),
        "totp_enabled": bool(user.get("totp_secret")),
    }


def _revoke_user_sessions(username: str) -> None:
    for token, session in tuple(_SESSIONS.items()):
        if session.username == username:
            _SESSIONS.pop(token, None)


def _require_admin(users: list[dict]) -> None:
    if users and not any(entry.get("role") == ROLE_ADMIN for entry in users):
        raise ValueError("at least one administrator must remain while panel users exist")


def add_user(
    username, password, *, role, sites=(), first_name="", last_name="", email="",
) -> None:
    username = _validate_username(username)
    password = _validate_password(password)
    role = _validate_role(role)
    sites = _validated_sites(sites)
    for field, value, maximum in (
        ("first name", first_name, 80), ("last name", last_name, 80), ("email", email, 254),
    ):
        if not isinstance(value, str) or len(value) > maximum:
            raise ValueError(f"{field} must be a string of at most {maximum} characters")
    password_hash, password_salt = _password_record(password)
    with _STATE_LOCK, _store_lock():
        users = _read_users()
        if _find_user(users, username) is not None:
            raise ValueError(f"panel user already exists: {username}")
        users.append({
            "username": username,
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
            "role": role,
            "sites": sites,
            "password_hash": password_hash,
            "password_salt": password_salt,
            "totp_secret": None,
        })
        _require_admin(users)
        users.sort(key=lambda entry: str(entry.get("username", "")))
        _write_users(users)


def remove_user(username) -> None:
    username = _validate_username(username)
    with _STATE_LOCK, _store_lock():
        users = _read_users()
        if _find_user(users, username) is None:
            raise ValueError(f"panel user not found: {username}")
        remaining = [entry for entry in users if entry.get("username") != username]
        _require_admin(remaining)
        _write_users(remaining)
        _LOGIN_FAILURES.pop(username, None)
        _LAST_TOTP_STEPS.pop(username, None)
        _revoke_user_sessions(username)


def list_users() -> list[dict]:
    return [_public_user(user) for user in _read_users()]


def set_password(username, password) -> None:
    username = _validate_username(username)
    password = _validate_password(password)
    password_hash, password_salt = _password_record(password)
    with _STATE_LOCK, _store_lock():
        users = _read_users()
        user = _find_user(users, username)
        if user is None:
            raise ValueError(f"panel user not found: {username}")
        user["password_hash"] = password_hash
        user["password_salt"] = password_salt
        _write_users(users)
        _LOGIN_FAILURES.pop(username, None)
        _revoke_user_sessions(username)


def set_role(username, role) -> None:
    username = _validate_username(username)
    role = _validate_role(role)
    with _STATE_LOCK, _store_lock():
        users = _read_users()
        user = _find_user(users, username)
        if user is None:
            raise ValueError(f"panel user not found: {username}")
        user["role"] = role
        _require_admin(users)
        _write_users(users)


def set_sites(username, sites) -> None:
    username = _validate_username(username)
    sites = _validated_sites(sites)
    with _STATE_LOCK, _store_lock():
        users = _read_users()
        user = _find_user(users, username)
        if user is None:
            raise ValueError(f"panel user not found: {username}")
        user["sites"] = sites
        _write_users(users)


def update_user(username, *, role=None, password=None, sites=None) -> None:
    username = _validate_username(username)
    if role is not None:
        role = _validate_role(role)
    if password is not None:
        password = _validate_password(password)
    if sites is not None:
        sites = _validated_sites(sites)
    password_record = _password_record(password) if password is not None else None
    with _STATE_LOCK, _store_lock():
        users = _read_users()
        user = _find_user(users, username)
        if user is None:
            raise ValueError(f"panel user not found: {username}")
        if role is not None:
            user["role"] = role
        if sites is not None:
            user["sites"] = sites
        if password_record is not None:
            user["password_hash"], user["password_salt"] = password_record
        _require_admin(users)
        _write_users(users)
        if password is not None:
            _LOGIN_FAILURES.pop(username, None)
            _revoke_user_sessions(username)


def assign_site(username, domain) -> None:
    username = _validate_username(username)
    validate_domain(domain)
    with _STATE_LOCK, _store_lock():
        users = _read_users()
        user = _find_user(users, username)
        if user is None:
            raise ValueError(f"panel user not found: {username}")
        user["sites"] = sorted(set(user.get("sites") or ()) | {domain})
        _write_users(users)


def revoke_site(username, domain) -> None:
    username = _validate_username(username)
    validate_domain(domain)
    with _STATE_LOCK, _store_lock():
        users = _read_users()
        user = _find_user(users, username)
        if user is None:
            raise ValueError(f"panel user not found: {username}")
        user["sites"] = sorted(set(user.get("sites") or ()) - {domain})
        _write_users(users)


def _scrypt_candidate(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_SCRYPT_LENGTH,
    )


def _dummy_password_work(password) -> None:
    try:
        _scrypt_candidate(password if isinstance(password, str) else "", _DUMMY_SALT)
    except (TypeError, ValueError, OverflowError):
        pass


def verify_password(username, password) -> bool:
    try:
        user = _find_user(_read_users(), username) if isinstance(username, str) else None
        supplied = password if isinstance(password, str) else ""
        salt = bytes.fromhex(user["password_salt"]) if user is not None else _DUMMY_SALT
        expected = bytes.fromhex(user["password_hash"]) if user is not None else bytes(_SCRYPT_LENGTH)
        candidate = _scrypt_candidate(supplied, salt)
        return user is not None and hmac.compare_digest(candidate, expected)
    except (KeyError, TypeError, ValueError, OverflowError):
        _dummy_password_work(password)
        return False


def enable_totp(username) -> tuple[str, str]:
    username = _validate_username(username)
    with _STATE_LOCK, _store_lock():
        users = _read_users()
        user = _find_user(users, username)
        if user is None:
            raise ValueError(f"panel user not found: {username}")
        if user.get("totp_secret"):
            raise ValueError("TOTP is already enabled")
        secret = base64.b32encode(secrets.token_bytes(_TOTP_SECRET_BYTES)).decode("ascii").rstrip("=")
        user["totp_secret"] = secret
        _write_users(users)
        _LAST_TOTP_STEPS.pop(username, None)
    uri = f"otpauth://totp/wpfy:{quote(username, safe='')}?secret={secret}&issuer=wpfy"
    return secret, uri


def begin_totp_enrollment(username) -> tuple[str, str]:
    username = _validate_username(username)
    with _STATE_LOCK:
        user = _find_user(_read_users(), username)
        if user is None:
            raise ValueError(f"panel user not found: {username}")
        if user.get("totp_secret"):
            raise ValueError("TOTP is already enabled")
        if username in _PENDING_TOTP_DISCLOSED:
            raise ValueError("the setup TOTP secret has already been disclosed")
        secret = base64.b32encode(secrets.token_bytes(_TOTP_SECRET_BYTES)).decode("ascii").rstrip("=")
        _PENDING_TOTP[username] = secret
        _PENDING_TOTP_DISCLOSED.add(username)
    uri = f"otpauth://totp/wpfy:{quote(username, safe='')}?secret={secret}&issuer=wpfy"
    return secret, uri


def complete_totp_enrollment(username, code: object) -> None:
    username = _validate_username(username)
    now = time.time()
    with _STATE_LOCK, _store_lock():
        users = _read_users()
        user = _find_user(users, username)
        secret = _PENDING_TOTP.get(username)
        if user is None:
            raise ValueError(f"panel user not found: {username}")
        if not secret:
            raise ValueError("start TOTP enrollment before verifying a code")
        candidate = dict(user)
        candidate["totp_secret"] = secret
        matched_step = _matching_totp_step(candidate, code, now)
        if matched_step is None:
            raise ValueError("invalid TOTP code")
        user["totp_secret"] = secret
        _write_users(users)
        _LAST_TOTP_STEPS[username] = matched_step
        _PENDING_TOTP.pop(username, None)
        _PENDING_TOTP_DISCLOSED.discard(username)


def cancel_totp_enrollment(username) -> None:
    username = _validate_username(username)
    with _STATE_LOCK:
        _PENDING_TOTP.pop(username, None)
        _PENDING_TOTP_DISCLOSED.discard(username)


def disable_totp(username) -> None:
    username = _validate_username(username)
    with _STATE_LOCK, _store_lock():
        users = _read_users()
        user = _find_user(users, username)
        if user is None:
            raise ValueError(f"panel user not found: {username}")
        user["totp_secret"] = None
        _write_users(users)
        _LAST_TOTP_STEPS.pop(username, None)
        _PENDING_TOTP.pop(username, None)
        _PENDING_TOTP_DISCLOSED.discard(username)


def login_required() -> bool:
    try:
        return bool(_read_users())
    except UserStoreError:
        return users_path().exists()


def totp_code(secret: bytes, timestamp: float, *, digits: int = 6) -> str:
    if not isinstance(secret, bytes) or not secret:
        raise ValueError("TOTP secret must be non-empty bytes")
    if not isinstance(digits, int) or not 1 <= digits <= 10:
        raise ValueError("TOTP digits must be between 1 and 10")
    counter = int(timestamp // TOTP_STEP_SECONDS)
    digest = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10**digits)).zfill(digits)


def _decode_totp_secret(value: str) -> bytes:
    padding = "=" * ((8 - len(value) % 8) % 8)
    return base64.b32decode(value + padding, casefold=True)


def _matching_totp_step(user: dict, supplied: object, now: float) -> int | None:
    secret_value = user.get("totp_secret")
    if not secret_value:
        return 0
    if not isinstance(supplied, str) or not re.fullmatch(r"[0-9]{6}", supplied):
        return None
    try:
        secret = _decode_totp_secret(secret_value)
    except (TypeError, ValueError, base64.binascii.Error):
        return None
    current_step = int(now // TOTP_STEP_SECONDS)
    for offset in range(-TOTP_SKEW_STEPS, TOTP_SKEW_STEPS + 1):
        step = current_step + offset
        if step >= 0 and hmac.compare_digest(totp_code(secret, step * TOTP_STEP_SECONDS), supplied):
            return step
    return None


def _register_failure(username: str, now: float) -> None:
    previous = _LOGIN_FAILURES.get(username, LoginFailure(0))
    if previous.locked_until > now:
        return
    count = previous.count + 1
    locked_until = now + LOCKOUT_SECONDS if count >= MAX_LOGIN_FAILURES else 0.0
    _LOGIN_FAILURES[username] = LoginFailure(count, locked_until)
    if locked_until:
        events.record_event(
            "auth.login.lockout", outcome="locked", detail="too many failed login attempts", actor=username,
        )


def _client_key(client: object) -> str:
    return client if isinstance(client, str) and client else "unknown"


def _prune_client_failures(now: float) -> None:
    for client, failure in tuple(_CLIENT_FAILURES.items()):
        if failure.expires_at <= now:
            _CLIENT_FAILURES.pop(client, None)


def client_throttled(client) -> bool:
    now = time.time()
    with _STATE_LOCK:
        _prune_client_failures(now)
        failure = _CLIENT_FAILURES.get(_client_key(client))
        return failure is not None and failure.cooldown_until > now


def _register_client_failure(client: str, now: float) -> None:
    _prune_client_failures(now)
    previous = _CLIENT_FAILURES.get(client)
    count = (previous.count if previous is not None else 0) + 1
    cooldown_until = now + CLIENT_COOLDOWN_SECONDS if count >= MAX_CLIENT_FAILURES else 0.0
    expires_at = cooldown_until or now + CLIENT_COOLDOWN_SECONDS
    _CLIENT_FAILURES[client] = ClientFailure(count, cooldown_until, expires_at)
    if cooldown_until:
        events.record_event(
            "auth.login.client-throttle", outcome="throttled", detail="too many failed login attempts", actor=client,
        )


def register_client_failure(client) -> None:
    now = time.time()
    with _STATE_LOCK:
        _register_client_failure(_client_key(client), now)


def login(
    username: object, password: object, totp: object = None, *, client=None, setup: bool = False,
) -> tuple[str, dict] | None:
    username_key = username if isinstance(username, str) and _USERNAME.fullmatch(username) else ""
    client_key = _client_key(client)
    now = time.time()
    if client_throttled(client_key):
        return None
    with _STATE_LOCK:
        failure = _LOGIN_FAILURES.get(username_key)
        locked = failure is not None and failure.locked_until > now
        if failure is not None and failure.locked_until and failure.locked_until <= now:
            _LOGIN_FAILURES.pop(username_key, None)
    if locked:
        _dummy_password_work(password)
        return None

    password_ok = verify_password(username_key, password)
    try:
        user = _find_user(_read_users(), username_key)
    except UserStoreError:
        user = None
    matched_step = _matching_totp_step(user, totp, now) if user is not None else None
    credentials_ok = password_ok and user is not None and matched_step is not None

    with _STATE_LOCK:
        if credentials_ok and matched_step:
            if matched_step <= _LAST_TOTP_STEPS.get(username_key, -1):
                credentials_ok = False
            else:
                _LAST_TOTP_STEPS[username_key] = matched_step
        if not credentials_ok:
            _register_client_failure(client_key, now)
            if user is not None:
                _register_failure(username_key, now)
            return None
        _LOGIN_FAILURES.pop(username_key, None)
        _CLIENT_FAILURES.pop(client_key, None)
        token = secrets.token_urlsafe(32)
        while token in _SESSIONS:
            token = secrets.token_urlsafe(32)
        _SESSIONS[token] = Session(username_key, now, now, setup=setup)
    return token, _public_user(user)


def authenticate_session(token: object) -> dict | None:
    if not isinstance(token, str) or not token:
        return None
    now = time.time()
    with _STATE_LOCK:
        session = _SESSIONS.get(token)
        if session is None:
            return None
        if now - session.last_seen_at > SESSION_IDLE_SECONDS or now - session.created_at > SESSION_ABSOLUTE_SECONDS:
            _SESSIONS.pop(token, None)
            return None
        try:
            user = _find_user(_read_users(), session.username)
        except UserStoreError:
            user = None
        if user is None:
            _SESSIONS.pop(token, None)
            return None
        _SESSIONS[token] = replace(session, last_seen_at=now)
        public = _public_user(user)
        public["_setup_session"] = session.setup
        return public


def finish_setup_session(token: object) -> None:
    if not isinstance(token, str) or not token:
        return
    with _STATE_LOCK:
        session = _SESSIONS.get(token)
        if session is not None:
            _SESSIONS[token] = replace(session, setup=False)


def logout(token: object) -> None:
    if isinstance(token, str):
        with _STATE_LOCK:
            _SESSIONS.pop(token, None)


def reset_state() -> None:
    with _STATE_LOCK:
        _SESSIONS.clear()
        _LOGIN_FAILURES.clear()
        _CLIENT_FAILURES.clear()
        _LAST_TOTP_STEPS.clear()
        _PENDING_TOTP.clear()
        _PENDING_TOTP_DISCLOSED.clear()
