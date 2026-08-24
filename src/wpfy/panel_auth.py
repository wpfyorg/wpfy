from __future__ import annotations

import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import hmac
import ipaddress
from itertools import islice
import json
import math
import os
import re
import secrets
import shutil
import stat
import struct
import subprocess
import threading
import time
from dataclasses import dataclass, replace
from pathlib import Path
from urllib.parse import quote

from . import cloudflare_ranges, events, settings, traefik
from .site_paths import validate_domain

ROLE_ADMIN = "admin"
ROLE_SITE_MANAGER = "site-manager"
ROLES = frozenset({ROLE_ADMIN, ROLE_SITE_MANAGER})
PASSWORD_MIN_LENGTH = 12
MAX_LOGIN_USERNAME_LENGTH = 64
MAX_LOGIN_PASSWORD_LENGTH = 4096
MAX_LOGIN_TOTP_LENGTH = 64

SESSION_IDLE_SECONDS = 30 * 60
SESSION_ABSOLUTE_SECONDS = 12 * 60 * 60
MAX_SESSIONS = 4096
MAX_SESSIONS_PER_USER = 8
SESSION_REAPER_BATCH = 256
MAX_LOGIN_FAILURES = 5
LOCKOUT_SECONDS = 5 * 60
MAX_FM_ENABLE = 5
FM_ENABLE_WINDOW_SECONDS = 5 * 60
MAX_CLIENT_FAILURES = 10
CLIENT_COOLDOWN_SECONDS = 60
TOTP_STEP_SECONDS = 30
TOTP_SKEW_STEPS = 1
TOTP_ENROLLMENT_TTL_SECONDS = 10 * 60
# Two-step login: how long a password-verified challenge may wait for its TOTP
# code. Short by design -- it is a single second factor prompt, not a session.
PENDING_LOGIN_TTL_SECONDS = 120
# Pending challenges are unauthenticated state keyed by an opaque id, so their
# count is bounded: globally, and per username so one account cannot be used
# to fill the table. Creation refuses (generic failure) once a cap is hit;
# entries expire in PENDING_LOGIN_TTL_SECONDS regardless.
MAX_PENDING_LOGINS = 256
MAX_PENDING_LOGINS_PER_USER = 8

_LEGACY_SCRYPT_N = 2**14
_LEGACY_SCRYPT_R = 8
_LEGACY_SCRYPT_P = 1
_PRIOR_SCRYPT_N = 2**15
_PRIOR_SCRYPT_R = 4
_PRIOR_SCRYPT_P = 2
_SCRYPT_LENGTH = 32
_SALT_BYTES = 16
_TOTP_SECRET_BYTES = 20

# Python/OpenSSL's default scrypt maxmem rejects OWASP's N=2**17,r=8,p=1
# (128 MiB working set) on this host: N=2**17 raises "memory limit exceeded"
# with hashlib.scrypt's default maxmem. N=2**14,r=8,p=5 stays within the same
# 16 MiB working set and measured ~0.23 seconds per derivation here. Keep
# parameters encoded so future hosts can migrate safely. Previous versioned
# records (N=2**15,r=4,p=2) remain accepted during migration.
_SCRYPT_VERSION = 1
_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 5
_SUPPORTED_SCRYPT_PARAMS = frozenset({
    (_LEGACY_SCRYPT_N, _LEGACY_SCRYPT_R, _LEGACY_SCRYPT_P, _SCRYPT_LENGTH),
    (_PRIOR_SCRYPT_N, _PRIOR_SCRYPT_R, _PRIOR_SCRYPT_P, _SCRYPT_LENGTH),
    (_SCRYPT_N, _SCRYPT_R, _SCRYPT_P, _SCRYPT_LENGTH),
})
_USERNAME = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$")
_DUMMY_SALT = b"wpfy-panel-auth-dummy-salt"
_STATE_LOCK = threading.RLock()
_AUTH_LOG_LOCK = threading.Lock()


def _bounded_int_env(name: str, default: int, *, minimum: int, maximum: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)), 10)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, value))


# Admission is deliberately small and non-blocking.  Login requests never
# queue behind a KDF, and the cap is bounded even when an operator supplies an
# unsafe environment value.
LOGIN_KDF_CONCURRENCY = _bounded_int_env(
    "WPFY_PANEL_LOGIN_KDF_CONCURRENCY", 2, minimum=1, maximum=8,
)
LOGIN_KDF_PER_CLIENT_CONCURRENCY = _bounded_int_env(
    "WPFY_PANEL_LOGIN_KDF_PER_CLIENT_CONCURRENCY", 1, minimum=1, maximum=2,
)
_LOGIN_KDF_SEMAPHORE = threading.BoundedSemaphore(LOGIN_KDF_CONCURRENCY)
_LOGIN_KDF_CLIENTS: dict[str, int] = {}

# Sentinel for a client address that cannot be determined (trusted edge with
# no usable forwarded chain) or that must never be written as a bannable
# identity. Banning 0.0.0.0 is a no-op in iptables, so keeping the record
# preserves observability without any self-DoS hazard.
UNKNOWN_CLIENT = "0.0.0.0"

# Never-ban static members: the sentinel itself, loopback (already in the
# fail2ban safe allowlist), and the default Docker bridge subnet (a container
# on a shared bridge is never a client worth banning). Not broadened to all
# private networks, per plan.
_NEVER_BAN_STATIC_CIDRS = ("0.0.0.0/32", "127.0.0.0/8", "::1/128", "172.17.0.0/16")

# Discovered never-ban members (Traefik edge endpoints + panel backend) are
# cached with a short monotonic TTL, mirroring `panel.trusted_edge_networks`.
# A discovery failure is deliberately not cached.
_NEVER_BAN_EDGE_LOCK = threading.Lock()
_NEVER_BAN_EDGE_TTL_SECONDS = 30
_NEVER_BAN_EDGE_GRACE_SECONDS = 60
_NEVER_BAN_EDGE_CACHE: tuple[tuple[str, ...], float] | None = None
_NEVER_BAN_EDGE_STALE: tuple[str, ...] = ()
_NEVER_BAN_EDGE_GRACE_UNTIL = 0.0
_NEVER_BAN_EDGE_REQUEST_SAFE = False

_PANEL_AUTH_LOG_MAX_BYTES = int(
    os.environ.get("WPFY_PANEL_AUTH_LOG_MAX_BYTES", str(10 * 1024 * 1024))
)
_PANEL_AUTH_LOG_KEEP = 3


@dataclass(frozen=True, slots=True)
class Session:
    username: str
    created_at: float
    last_seen_at: float
    setup: bool = False
    credential_fingerprint: tuple[object, object, object] | None = None


@dataclass(frozen=True, slots=True)
class PendingLogin:
    """A password-verified login waiting for its TOTP code.

    Keyed by an opaque random challenge id -- never by, and never containing,
    a session token. The credential fingerprint captured at the password step
    is re-checked against disk before the session is issued, so a password or
    TOTP change between the steps kills the pending login.
    """

    username: str
    credential_fingerprint: tuple[object, object, object] | None
    client: str
    expires_at: float


@dataclass(frozen=True, slots=True)
class PasswordLoginOutcome:
    """Result of login step 1: either a challenge to verify, or a session."""

    challenge: str | None = None
    token: str | None = None
    user: dict | None = None

    @property
    def mfa_required(self) -> bool:
        return self.challenge is not None


class ClientThrottleError(ValueError):
    pass


class LoginAdmissionError(ClientThrottleError):
    """The bounded login-KDF admission gate is saturated."""

    def __init__(self, retry_after: int = 1) -> None:
        super().__init__("login verification capacity is temporarily busy")
        self.retry_after = max(1, int(retry_after))


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
_FM_ENABLE: dict[str, list[float]] = {}
_LAST_TOTP_STEPS: dict[str, int] = {}
_PENDING_TOTP: dict[str, str] = {}
_PENDING_TOTP_DISCLOSED: set[str] = set()
_PENDING_TOTP_EXPIRES: dict[str, float] = {}
# Two-step login challenges, keyed by the opaque challenge id handed to the
# client after a successful password verification.
_PENDING_LOGINS: dict[str, PendingLogin] = {}


class UserStoreError(ValueError):
    pass


class ReauthenticationError(ValueError):
    """Supplied current credentials failed a self-service reauthentication."""


def users_path() -> Path:
    return Path(settings.PATHS.config_dir) / "panel-users.json"


def panel_auth_log_path() -> Path:
    """Return the path to the dedicated panel authentication failure log."""
    return Path(settings.PATHS.log_dir) / "panel-auth.log"


def ensure_panel_auth_log() -> Path:
    """Create the auth log if it does not exist yet, with the writer's modes.

    fail2ban refuses to load a jail whose `logpath` is missing -- `fail2ban-client
    -t` fails with "Have not found any log file", which on a fresh host rolls the
    whole wpfy fail2ban install back before the panel has ever recorded a failure.
    The jail has to be installed against a file that already exists.
    """
    path = panel_auth_log_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    # O_NOFOLLOW for the same reason the writer uses it: a symlinked log path
    # fails closed rather than creating a file through the link.
    os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600))
    return path


def _normalize_client_ip(value: object) -> str:
    """Normalize a client IP address string; return the sentinel for anything unparseable."""
    if not isinstance(value, str) or not value:
        return UNKNOWN_CLIENT
    truncated = value[:64]
    try:
        return str(ipaddress.ip_address(truncated))
    except (ValueError, TypeError):
        return UNKNOWN_CLIENT


def _address_in_networks(address: str, networks: tuple[str, ...]) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    for raw in networks:
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            continue
        if parsed.version == network.version and parsed in network:
            return True
    return False


def _discover_never_ban_edge_cidrs() -> tuple[str, ...]:
    """Traefik edge endpoints (both networks) plus the panel backend address.

    Successful discovery is cached for at most ``_NEVER_BAN_EDGE_TTL_SECONDS``
    seconds using ``time.monotonic``; a failure (Docker unavailable, container
    not on the network) is not cached so a transient outage re-attempts on the
    next record. Same contract as ``panel.trusted_edge_networks``.
    """
    global _NEVER_BAN_EDGE_CACHE, _NEVER_BAN_EDGE_STALE, _NEVER_BAN_EDGE_GRACE_UNTIL
    now = time.monotonic()
    with _NEVER_BAN_EDGE_LOCK:
        cached = _NEVER_BAN_EDGE_CACHE
        if cached is not None and cached[1] > now:
            return cached[0]
    discovered: list[str] = []
    discovered_any = False
    for network_name in (traefik.TRAEFIK_NETWORK, traefik.PANEL_EDGE_NETWORK):
        try:
            discovered.extend(traefik.traefik_network_cidrs(network_name))
            discovered_any = True
        except (RuntimeError, OSError, ValueError, subprocess.SubprocessError):
            continue
    # The panel backend binds the panel-edge gateway; its own address is
    # infrastructure, not a client.
    try:
        gateway = traefik._network_gateway(traefik.PANEL_EDGE_NETWORK)
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError):
        gateway = None
    if gateway:
        try:
            address = ipaddress.ip_address(gateway)
        except ValueError:
            address = None
        if address is not None:
            discovered.append(f"{address}/{'32' if address.version == 4 else '128'}")
            discovered_any = True
    if not discovered_any:
        # Total discovery failure: deliberately not cached. A transient
        # Docker outage must not pin the empty set for the cache TTL; the
        # next record re-attempts discovery (same contract as
        # `panel.trusted_edge_networks`).
        now = time.monotonic()
        with _NEVER_BAN_EDGE_LOCK:
            if _NEVER_BAN_EDGE_CACHE is not None and _NEVER_BAN_EDGE_GRACE_UNTIL > now:
                return _NEVER_BAN_EDGE_STALE
        return ()
    result = tuple(sorted(set(discovered)))
    expires_at = time.monotonic() + _NEVER_BAN_EDGE_TTL_SECONDS
    with _NEVER_BAN_EDGE_LOCK:
        # Immutable snapshot replacement: readers see old or new topology,
        # never a partially refreshed set.
        _NEVER_BAN_EDGE_CACHE = (result, expires_at)
        _NEVER_BAN_EDGE_STALE = result
        _NEVER_BAN_EDGE_GRACE_UNTIL = expires_at + _NEVER_BAN_EDGE_GRACE_SECONDS
    return result


def _client_ip_is_never_ban(value: str) -> bool:
    """True when the normalized client IP must never be a bannable identity.

    The never-ban set: the 0.0.0.0 sentinel, loopback, the default Docker
    bridge, Cloudflare edge ranges (published ranges; env override respected),
    the Traefik edge endpoints, and the panel backend address. Banning any of
    them would take panel infrastructure offline or ban a non-attacker.
    """
    if _address_in_networks(value, _NEVER_BAN_STATIC_CIDRS):
        return True
    if cloudflare_ranges.is_cloudflare_ip(value):
        return True
    if _address_in_networks(value, cached_never_ban_edge_cidrs()):
        return True
    # Once grace ends, stop trusting stale topology for forwarded-client
    # resolution, but keep the last observed proxy identities fail2ban-safe.
    # Otherwise an expired cache could emit the Traefik peer as bannable.
    with _NEVER_BAN_EDGE_LOCK:
        stale = _NEVER_BAN_EDGE_STALE
    return _address_in_networks(value, stale)


def cached_never_ban_edge_cidrs() -> tuple[str, ...]:
    """Return the startup/refreshed edge snapshot without Docker I/O."""
    if not _NEVER_BAN_EDGE_REQUEST_SAFE:
        # Direct library callers (including offline maintenance/tests) retain
        # the historical discovery behavior.  The HTTP server flips this
        # switch after startup refresh, so request handling is cache-only.
        return _discover_never_ban_edge_cidrs()
    now = time.monotonic()
    with _NEVER_BAN_EDGE_LOCK:
        cached = _NEVER_BAN_EDGE_CACHE
        if cached is not None and cached[1] > now:
            return cached[0]
        # Failed refreshes retain last-known-good infrastructure identities for
        # bounded grace. This protects fail2ban from banning a trusted proxy
        # while Docker is unavailable, without trusting stale topology forever.
        if cached is not None and _NEVER_BAN_EDGE_GRACE_UNTIL > now:
            return _NEVER_BAN_EDGE_STALE
    return ()


def refresh_never_ban_edge_cidrs() -> tuple[str, ...]:
    """Refresh edge exclusions outside request handling."""
    global _NEVER_BAN_EDGE_REQUEST_SAFE
    discovered = _discover_never_ban_edge_cidrs()
    _NEVER_BAN_EDGE_REQUEST_SAFE = True
    return discovered


def _hash_account(identifier: str) -> str:
    """Return 'sha256:<hex>' of the truncated account identifier."""
    truncated = (identifier if isinstance(identifier, str) else "")[:64]
    return "sha256:" + hashlib.sha256(truncated.encode("utf-8")).hexdigest()


def _rotate_panel_auth_log(path: Path) -> None:
    """Rotate panel-auth.log copytruncate-style (t16 W1).

    Keeps up to _PANEL_AUTH_LOG_KEEP rotated files (.1, .2, .3).
    Best-effort: silently returns on any OS error.

    Copytruncate, not rename: the jail tails panel-auth.log with
    ``backend = auto``; a rename changes the inode and strands the tail on the
    renamed file, so fail2ban would miss every fresh record until reload —
    silently dropping ban coverage. Copying the current content to .1 and
    truncating the active file in place keeps the inode, so a tailing fail2ban
    never loses the tail. The rotation runs under _AUTH_LOG_LOCK, so the
    copy-then-truncate is atomic with respect to concurrent writers.
    """
    try:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            return  # never rotate or truncate through a symlink
        if metadata.st_size <= _PANEL_AUTH_LOG_MAX_BYTES:
            return
    except OSError:
        return
    for i in range(_PANEL_AUTH_LOG_KEEP - 1, 0, -1):
        src = path.with_name(f"{path.name}.{i}")
        dst = path.with_name(f"{path.name}.{i + 1}")
        try:
            if src.exists():
                try:
                    dst.unlink()
                except FileNotFoundError:
                    pass
                src.rename(dst)
        except OSError:
            pass
    rotated = path.with_name(f"{path.name}.1")
    try:
        try:
            rotated.unlink()
        except FileNotFoundError:
            pass
        # Copy current content to .1, then truncate the active file in place
        # (same inode fail2ban is tailing).
        shutil.copyfile(path, rotated)
        fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
        try:
            os.ftruncate(fd, 0)
        finally:
            os.close(fd)
    except OSError:
        pass


def _append_panel_auth_failure(
    surface: str,
    client_ip: object,
    account_identifier: str,
    reason_class: str,
) -> None:
    """Write one JSON Lines record to the panel auth failure log.

    Emission guard: a resolved client IP that is a never-ban identity (edge
    endpoint, Docker bridge, Cloudflare edge, panel backend, loopback) is
    redacted to the 0.0.0.0 sentinel before writing, so no record can ever
    carry a bannable identity from the never-ban set. The record is kept for
    observability; banning 0.0.0.0 is a no-op in iptables.

    Hardening: the log file is opened with O_NOFOLLOW (a symlinked log path
    fails closed instead of writing through the link) and the log directory is
    tightened to mode 0700. A write failure is never silently swallowed: it is
    recorded as ``login_shield.health_failed`` and re-raised so the caller can
    surface the degraded health instead of pretending the attempt was logged.
    """
    normalized = _normalize_client_ip(client_ip)
    if _client_ip_is_never_ban(normalized):
        normalized = UNKNOWN_CLIENT
    record = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "event": "panel_auth_failure",
        "surface": surface,
        "client_ip": normalized,
        "account_hash": _hash_account(account_identifier),
        "reason_class": reason_class,
    }
    path = panel_auth_log_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(path.parent, 0o700)
        with _AUTH_LOG_LOCK:
            _rotate_panel_auth_log(path)
            line = json.dumps(record, ensure_ascii=True, separators=(",", ":")) + "\n"
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
            try:
                os.write(fd, line.encode("utf-8"))
            finally:
                os.close(fd)
    except (OSError, TypeError, ValueError) as exc:
        try:
            events.record_event(
                "login_shield.health_failed",
                outcome="failed",
                detail=f"panel auth failure log write failed: {type(exc).__name__}",
                actor="panel",
            )
        except Exception:
            pass
        raise


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
    """The length floor lives here, not at the caller.

    It used to be enforced only by the first-run setup form, so the admin who
    was made to pick twelve characters could then create a site-manager with a
    one-character password -- on a panel that `wpfy panel expose` can publish to
    the internet. Every write path (`add_user`, `update_user`, `set_password`,
    setup) already funnels through this function, so the guard belongs here and
    nowhere else. Stored passwords are unaffected: validation runs on write, so
    existing accounts keep working until someone changes them.
    """
    if not isinstance(password, str) or not password:
        raise ValueError("password must be a non-empty string")
    if len(password) < PASSWORD_MIN_LENGTH:
        raise ValueError(f"password must be at least {PASSWORD_MIN_LENGTH} characters")
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


def _scrypt_derive(password: str, salt: bytes, *, n: int, r: int, p: int, dklen: int) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=dklen)


def _encode_password_record(salt: bytes, digest: bytes) -> tuple[str, str]:
    encoded = (
        f"scrypt$v={_SCRYPT_VERSION}$n={_SCRYPT_N}$r={_SCRYPT_R}$p={_SCRYPT_P}"
        f"$dklen={_SCRYPT_LENGTH}$salt={salt.hex()}$hash={digest.hex()}"
    )
    return encoded, salt.hex()


def _password_record(password: str) -> tuple[str, str]:
    salt = secrets.token_bytes(_SALT_BYTES)
    digest = _scrypt_derive(password, salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_SCRYPT_LENGTH)
    return _encode_password_record(salt, digest)


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


def _prune_user_sessions(username: str) -> None:
    sessions = [
        (token, session) for token, session in _SESSIONS.items()
        if session.username == username
    ]
    overflow = len(sessions) - MAX_SESSIONS_PER_USER
    if overflow <= 0:
        return
    sessions.sort(key=lambda item: (item[1].last_seen_at, item[1].created_at))
    for token, _session in sessions[:overflow]:
        _SESSIONS.pop(token, None)


def _prune_sessions(now: float) -> None:
    """Remove expired sessions and enforce a bounded in-memory session table."""
    for token in tuple(islice(_SESSIONS, SESSION_REAPER_BATCH)):
        session = _SESSIONS.get(token)
        if session is not None and (
            now - session.last_seen_at > SESSION_IDLE_SECONDS
            or now - session.created_at > SESSION_ABSOLUTE_SECONDS
        ):
            _SESSIONS.pop(token, None)

    overflow = len(_SESSIONS) - MAX_SESSIONS
    if overflow > 0:
        candidates = sorted(
            _SESSIONS.items(),
            key=lambda item: (
                not (
                    now - item[1].last_seen_at > SESSION_IDLE_SECONDS
                    or now - item[1].created_at > SESSION_ABSOLUTE_SECONDS
                ),
                item[1].last_seen_at,
                item[1].created_at,
            ),
        )
        for token, _session in candidates[:overflow]:
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


def update_profile(username, *, first_name=None, last_name=None, email=None) -> dict:
    """Self-service record edit: display fields only, never role/sites/password.

    The caller is the authenticated account itself (the panel route passes the
    session's own username), so there is deliberately no way to address another
    user here. Profile fields are outside the authentication fingerprint, so
    existing sessions survive a rename.
    """
    username = _validate_username(username)
    updates = {}
    for field, value, maximum in (
        ("first_name", first_name, 80), ("last_name", last_name, 80), ("email", email, 254),
    ):
        if value is None:
            continue
        if not isinstance(value, str) or len(value) > maximum:
            raise ValueError(f"{field} must be a string of at most {maximum} characters")
        updates[field] = value
    with _STATE_LOCK, _store_lock():
        users = _read_users()
        user = _find_user(users, username)
        if user is None:
            raise ValueError(f"panel user not found: {username}")
        user.update(updates)
        _write_users(users)
        return _public_user(user)


def get_public_user(username):
    """Read-only public view of one user, or None when unknown."""
    with _STATE_LOCK, _store_lock():
        user = _find_user(_read_users(), username)
        return _public_user(user) if user else None


def change_password(username, current_password, new_password, *, keep_token=None) -> None:
    """Self-service rotation: verify the current secret, then revoke other sessions.

    Verification reuses the login path (`_verify_password_with_fingerprint`),
    including its dummy-KDF work for unknown users and malformed records, so
    this route costs the same as a login attempt for every outcome. The kept
    session -- normally the one that initiated the change -- has its
    credential fingerprint rebound to the new record; every other session of
    the user is dropped.
    """
    username = _validate_username(username)
    new_password = _validate_password(new_password)
    valid, fingerprint = _verify_password_with_fingerprint(username, current_password)
    if not valid or fingerprint is None:
        raise ReauthenticationError("current password is incorrect")
    new_record = _password_record(new_password)
    with _STATE_LOCK, _store_lock():
        users = _read_users()
        user = _find_user(users, username)
        if user is None:
            raise ValueError(f"panel user not found: {username}")
        # CAS on the credential fingerprint: a concurrent password/TOTP change
        # between verification and this write must not be silently overwritten.
        if _auth_fingerprint(user) != fingerprint:
            raise ReauthenticationError("account state changed; retry")
        user["password_hash"], user["password_salt"] = new_record
        _write_users(users)
        _LOGIN_FAILURES.pop(username, None)
        for token in tuple(_SESSIONS):
            session = _SESSIONS.get(token)
            if session is None or session.username != username:
                continue
            if keep_token is not None and hmac.compare_digest(token.encode("utf-8"), str(keep_token).encode("utf-8")):
                _SESSIONS[token] = replace(session, credential_fingerprint=_auth_fingerprint(user))
            else:
                _SESSIONS.pop(token, None)


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
    """Derive dummy-password work with current parameters."""
    return _scrypt_derive(password, salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_SCRYPT_LENGTH)


def _legacy_scrypt_candidate(password: str, salt: bytes) -> bytes:
    return _scrypt_derive(
        password, salt, n=_LEGACY_SCRYPT_N, r=_LEGACY_SCRYPT_R,
        p=_LEGACY_SCRYPT_P, dklen=_SCRYPT_LENGTH,
    )


def _prior_scrypt_candidate(password: str, salt: bytes) -> bytes:
    return _scrypt_derive(
        password, salt, n=_PRIOR_SCRYPT_N, r=_PRIOR_SCRYPT_R,
        p=_PRIOR_SCRYPT_P, dklen=_SCRYPT_LENGTH,
    )


def _composite_password_work(password: str, salt: bytes) -> tuple[bytes, bytes, bytes]:
    """Always perform every supported KDF generation for uniform timing."""
    legacy = _legacy_scrypt_candidate(password, salt)
    prior = _prior_scrypt_candidate(password, salt)
    current = _scrypt_candidate(password, salt)
    return legacy, prior, current


def _dummy_password_work(password) -> None:
    try:
        legacy, prior, current = _composite_password_work(
            password if isinstance(password, str) else "", _DUMMY_SALT,
        )
        zero = bytes(_SCRYPT_LENGTH)
        hmac.compare_digest(legacy, zero)
        hmac.compare_digest(prior, zero)
        hmac.compare_digest(current, zero)
    except (TypeError, ValueError, OverflowError):
        pass


def _parse_password_record(user: dict) -> tuple[int, int, int, int, bytes, bytes, bool] | None:
    """Return KDF material and whether record uses pre-versioned legacy fields."""
    stored_hash = user.get("password_hash")
    stored_salt = user.get("password_salt")
    if not isinstance(stored_hash, str) or not isinstance(stored_salt, str):
        return None
    if stored_hash.startswith("scrypt$"):
        fields: dict[str, str] = {}
        for component in stored_hash.split("$")[1:]:
            key, separator, value = component.partition("=")
            if not separator or not key or key in fields:
                return None
            fields[key] = value
        if set(fields) != {"v", "n", "r", "p", "dklen", "salt", "hash"}:
            return None
        try:
            version = int(fields["v"], 10)
            params = tuple(int(fields[key], 10) for key in ("n", "r", "p", "dklen"))
            salt = bytes.fromhex(fields["salt"])
            digest = bytes.fromhex(fields["hash"])
            duplicate_salt = bytes.fromhex(stored_salt)
        except (TypeError, ValueError):
            return None
        if (
            version != _SCRYPT_VERSION
            or params not in _SUPPORTED_SCRYPT_PARAMS
            or len(salt) != _SALT_BYTES
            or len(digest) != _SCRYPT_LENGTH
            or not hmac.compare_digest(salt, duplicate_salt)
        ):
            return None
        prior_params = params == (_PRIOR_SCRYPT_N, _PRIOR_SCRYPT_R, _PRIOR_SCRYPT_P, _SCRYPT_LENGTH)
        return (params[0], params[1], params[2], params[3], salt, digest, prior_params)

    try:
        digest = bytes.fromhex(stored_hash)
        salt = bytes.fromhex(stored_salt)
    except (TypeError, ValueError):
        return None
    if len(digest) != _SCRYPT_LENGTH or len(salt) != _SALT_BYTES:
        return None
    return (_LEGACY_SCRYPT_N, _LEGACY_SCRYPT_R, _LEGACY_SCRYPT_P, _SCRYPT_LENGTH, salt, digest, True)


def _upgrade_legacy_password(
    username: str, legacy_hash: str, legacy_salt: str, current_digest: bytes,
) -> tuple[str, str] | None:
    """Replace unchanged legacy credentials with a versioned current record."""
    salt = bytes.fromhex(legacy_salt)
    password_hash, password_salt = _encode_password_record(salt, current_digest)
    with _STATE_LOCK, _store_lock():
        users = _read_users()
        user = _find_user(users, username)
        if user is None or user.get("password_hash") != legacy_hash or user.get("password_salt") != legacy_salt:
            return None
        user["password_hash"] = password_hash
        user["password_salt"] = password_salt
        _write_users(users)
        return password_hash, password_salt


def _password_matches_user(user: dict | None, password: object) -> tuple[bool, bool, bytes | None]:
    """Return password validity and whether successful auth needs migration."""
    supplied = password if isinstance(password, str) else ""
    if user is None:
        _dummy_password_work(password)
        return False, False, None
    material = _parse_password_record(user)
    if material is None:
        _dummy_password_work(password)
        return False, False, None
    n, r, p, dklen, salt, expected, upgrade = material
    try:
        legacy_candidate, prior_candidate, current_candidate = _composite_password_work(supplied, salt)
    except (TypeError, ValueError, OverflowError):
        _dummy_password_work(password)
        return False, False, None
    legacy_match = hmac.compare_digest(legacy_candidate, expected)
    prior_match = hmac.compare_digest(prior_candidate, expected)
    current_match = hmac.compare_digest(current_candidate, expected)
    # ``n/r/p/dklen`` are validated above; retain explicit use of parsed
    # parameters so malformed/future records cannot silently select a KDF.
    params = (n, r, p, dklen)
    legacy_params = params == (
        _LEGACY_SCRYPT_N, _LEGACY_SCRYPT_R, _LEGACY_SCRYPT_P, _SCRYPT_LENGTH,
    )
    prior_params = params == (
        _PRIOR_SCRYPT_N, _PRIOR_SCRYPT_R, _PRIOR_SCRYPT_P, _SCRYPT_LENGTH,
    )
    valid = legacy_match if legacy_params else prior_match if prior_params else current_match
    return valid, valid and upgrade, current_candidate


def _verify_password_with_fingerprint(username, password) -> tuple[bool, tuple[object, object, object] | None]:
    try:
        user = _find_user(_read_users(), username) if isinstance(username, str) else None
    except UserStoreError:
        _dummy_password_work(password)
        return False, None
    valid, upgrade, current_digest = _password_matches_user(user, password)
    if not valid or user is None:
        return False, None
    fingerprint = _auth_fingerprint(user)
    if upgrade and current_digest is not None:
        try:
            migrated = _upgrade_legacy_password(
                username, user["password_hash"], user["password_salt"], current_digest,
            )
            if migrated is not None:
                # Preserve TOTP from user snapshot used for authentication;
                # migration CAS must not bind a newer TOTP state to old code.
                fingerprint = (migrated[0], migrated[1], user.get("totp_secret"))
        except (OSError, UserStoreError, TypeError, ValueError, OverflowError):
            # Successful authentication must not become an outage when only
            # best-effort credential migration cannot write the store.
            pass
    return True, fingerprint


def verify_password(username, password) -> bool:
    valid, _fingerprint = _verify_password_with_fingerprint(username, password)
    return valid


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


def _prune_pending_totp(now: float) -> None:
    for username, expires_at in tuple(_PENDING_TOTP_EXPIRES.items()):
        if expires_at <= now:
            _PENDING_TOTP.pop(username, None)
            _PENDING_TOTP_EXPIRES.pop(username, None)
            _PENDING_TOTP_DISCLOSED.discard(username)


def begin_totp_enrollment(username) -> tuple[str, str]:
    username = _validate_username(username)
    now = time.time()
    with _STATE_LOCK:
        _prune_pending_totp(now)
        user = _find_user(_read_users(), username)
        if user is None:
            raise ValueError(f"panel user not found: {username}")
        if user.get("totp_secret"):
            raise ValueError("TOTP is already enabled")
        expires_at = _PENDING_TOTP_EXPIRES.get(username, 0.0)
        if username in _PENDING_TOTP_DISCLOSED and expires_at > now:
            raise ValueError("the setup TOTP secret has already been disclosed")
        if expires_at <= now:
            _PENDING_TOTP.pop(username, None)
            _PENDING_TOTP_EXPIRES.pop(username, None)
            _PENDING_TOTP_DISCLOSED.discard(username)
        secret = base64.b32encode(secrets.token_bytes(_TOTP_SECRET_BYTES)).decode("ascii").rstrip("=")
        _PENDING_TOTP[username] = secret
        _PENDING_TOTP_EXPIRES[username] = now + TOTP_ENROLLMENT_TTL_SECONDS
        _PENDING_TOTP_DISCLOSED.add(username)
    uri = f"otpauth://totp/wpfy:{quote(username, safe='')}?secret={secret}&issuer=wpfy"
    return secret, uri


def complete_totp_enrollment(username, code: object) -> tuple[object, object, object]:
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
        if _PENDING_TOTP_EXPIRES.get(username, 0.0) <= now:
            _PENDING_TOTP.pop(username, None)
            _PENDING_TOTP_EXPIRES.pop(username, None)
            _PENDING_TOTP_DISCLOSED.discard(username)
            raise ValueError("TOTP enrollment expired; start again")
        candidate = dict(user)
        candidate["totp_secret"] = secret
        matched_step = _matching_totp_step(candidate, code, now)
        if matched_step is None:
            raise ValueError("invalid TOTP code")
        user["totp_secret"] = secret
        _write_users(users)
        _LAST_TOTP_STEPS[username] = matched_step
        _PENDING_TOTP.pop(username, None)
        _PENDING_TOTP_EXPIRES.pop(username, None)
        _PENDING_TOTP_DISCLOSED.discard(username)
        return _auth_fingerprint(user)


def cancel_totp_enrollment(username) -> None:
    username = _validate_username(username)
    with _STATE_LOCK:
        _PENDING_TOTP.pop(username, None)
        _PENDING_TOTP_EXPIRES.pop(username, None)
        _PENDING_TOTP_DISCLOSED.discard(username)


def _auth_fingerprint(user: dict) -> tuple[object, object, object]:
    return user.get("password_hash"), user.get("password_salt"), user.get("totp_secret")


def _clear_totp_locked(users: list[dict], user: dict, username: str) -> None:
    user["totp_secret"] = None
    _write_users(users)
    _LAST_TOTP_STEPS.pop(username, None)
    _PENDING_TOTP.pop(username, None)
    _PENDING_TOTP_EXPIRES.pop(username, None)
    _PENDING_TOTP_DISCLOSED.discard(username)
    _revoke_user_sessions(username)


def disable_totp(username, password: object = None, totp: object = None) -> None:
    """Self-disable contract: password plus current TOTP when currently enabled.

    Password KDF work and initial reads happen outside auth/store locks. The
    final locked read compares the authentication fingerprint, preventing a
    concurrent password/TOTP change from being overwritten with stale data.
    """
    username = _validate_username(username)
    now = time.time()
    users = _read_users()
    user = _find_user(users, username)
    if user is None:
        raise ValueError(f"panel user not found: {username}")
    password_ok, _legacy, _current_digest = _password_matches_user(user, password)
    if not password_ok:
        raise ValueError("reauthentication failed")
    fingerprint = _auth_fingerprint(user)

    with _STATE_LOCK, _store_lock():
        current_users = _read_users()
        current = _find_user(current_users, username)
        if current is None:
            raise ValueError(f"panel user not found: {username}")
        if _auth_fingerprint(current) != fingerprint:
            raise ValueError("reauthentication state changed; retry")
        current_step = _matching_totp_step(current, totp, now) if current.get("totp_secret") else 0
        if current_step is None:
            raise ValueError("current TOTP code required")
        if current.get("totp_secret") and current_step <= _LAST_TOTP_STEPS.get(username, -1):
            raise ValueError("TOTP code has already been used")
        _clear_totp_locked(current_users, current, username)


def recover_disable_totp(username) -> None:
    """Trusted host-admin recovery operation; never use for self-service APIs."""
    username = _validate_username(username)
    with _STATE_LOCK, _store_lock():
        users = _read_users()
        user = _find_user(users, username)
        if user is None:
            raise ValueError(f"panel user not found: {username}")
        _clear_totp_locked(users, user, username)


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


def _login_payload_is_possible(username: object, password: object, totp: object) -> bool:
    """Reject malformed login material before it can reach a KDF."""
    if not isinstance(username, str) or len(username) > MAX_LOGIN_USERNAME_LENGTH:
        return False
    if not isinstance(password, str) or len(password) > MAX_LOGIN_PASSWORD_LENGTH:
        return False
    if totp is not None and (
        not isinstance(totp, str) or len(totp) > MAX_LOGIN_TOTP_LENGTH
    ):
        return False
    return True


@contextmanager
def _login_kdf_admission(client: str):
    """Reserve global and per-client capacity without ever queueing a request."""
    if not _LOGIN_KDF_SEMAPHORE.acquire(blocking=False):
        raise LoginAdmissionError()
    reserved = False
    try:
        with _STATE_LOCK:
            in_flight = _LOGIN_KDF_CLIENTS.get(client, 0)
            if in_flight >= LOGIN_KDF_PER_CLIENT_CONCURRENCY:
                raise LoginAdmissionError()
            _LOGIN_KDF_CLIENTS[client] = in_flight + 1
            reserved = True
        yield
    finally:
        if reserved:
            with _STATE_LOCK:
                remaining = _LOGIN_KDF_CLIENTS.get(client, 0) - 1
                if remaining > 0:
                    _LOGIN_KDF_CLIENTS[client] = remaining
                else:
                    _LOGIN_KDF_CLIENTS.pop(client, None)
        _LOGIN_KDF_SEMAPHORE.release()


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


def client_retry_after(client) -> int:
    """Seconds until the client cooldown expires, for a Retry-After header.

    Returns 0 when the client is not currently throttled. Only ever consulted
    for clients that just returned ``client_throttled() is True``.
    """
    now = time.time()
    with _STATE_LOCK:
        _prune_client_failures(now)
        failure = _CLIENT_FAILURES.get(_client_key(client))
    if failure is None or failure.cooldown_until <= now:
        return 0
    return max(1, math.ceil(failure.cooldown_until - now))


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


def _prune_fm_enable(now: float) -> None:
    cutoff = now - FM_ENABLE_WINDOW_SECONDS
    for username, timestamps in tuple(_FM_ENABLE.items()):
        recent = [timestamp for timestamp in timestamps if timestamp > cutoff]
        if recent:
            _FM_ENABLE[username] = recent
        else:
            _FM_ENABLE.pop(username, None)


def fm_enable_allowed(username: str) -> bool:
    now = time.time()
    with _STATE_LOCK:
        _prune_fm_enable(now)
        return len(_FM_ENABLE.get(username, ())) < MAX_FM_ENABLE


def register_fm_enable(username: str) -> None:
    now = time.time()
    with _STATE_LOCK:
        _prune_fm_enable(now)
        _FM_ENABLE.setdefault(username, []).append(now)


def login(
    username: object, password: object, totp: object = None, *, client=None, setup: bool = False,
) -> tuple[str, dict] | None:
    # These checks are intentionally before admission and before any KDF.  The
    # HTTP layer has already bounded the JSON body, but a valid-sized body can
    # still contain values that would make password verification needlessly
    # expensive or ambiguous.
    if not _login_payload_is_possible(username, password, totp):
        return None
    username_key = username if isinstance(username, str) and _USERNAME.fullmatch(username) else ""
    client_key = _client_key(client)
    now = time.time()
    challenge_now = time.monotonic()
    if client_throttled(client_key):
        _append_panel_auth_failure("password", client, username_key, "throttled")
        return None
    with _login_kdf_admission(client_key):
        with _STATE_LOCK:
            # Any auth-state touch prunes expired pending challenges, so
            # the table drains even when no new challenge is created.
            _prune_pending_logins(challenge_now)
            failure = _LOGIN_FAILURES.get(username_key)
            locked = failure is not None and failure.locked_until > now
            if failure is not None and failure.locked_until and failure.locked_until <= now:
                _LOGIN_FAILURES.pop(username_key, None)
        if locked:
            _dummy_password_work(password)
            with _STATE_LOCK:
                _register_client_failure(client_key, now)
            _append_panel_auth_failure("password", client, username_key, "locked")
            return None

        password_ok, credential_fingerprint = _verify_password_with_fingerprint(username_key, password)
        try:
            user = _find_user(_read_users(), username_key)
        except UserStoreError:
            user = None
        matched_step = _matching_totp_step(user, totp, now) if user is not None else None
        credentials_ok = password_ok and user is not None and matched_step is not None

        with _STATE_LOCK, _store_lock():
            _prune_sessions(now)
            if credentials_ok:
                try:
                    current_user = _find_user(_read_users(), username_key)
                except UserStoreError:
                    current_user = None
                if (
                    current_user is None
                    or credential_fingerprint is None
                    or _auth_fingerprint(current_user) != credential_fingerprint
                ):
                    credentials_ok = False
                else:
                    user = current_user
            if credentials_ok and matched_step:
                if matched_step <= _LAST_TOTP_STEPS.get(username_key, -1):
                    credentials_ok = False
                else:
                    _LAST_TOTP_STEPS[username_key] = matched_step
            if not credentials_ok:
                _register_client_failure(client_key, now)
                if user is not None:
                    _register_failure(username_key, now)
                reason = "totp_failed" if password_ok and user is not None else "invalid_credentials"
                _append_panel_auth_failure("password", client, username_key, reason)
                return None
            _LOGIN_FAILURES.pop(username_key, None)
            _CLIENT_FAILURES.pop(client_key, None)
            token = secrets.token_urlsafe(32)
            while token in _SESSIONS:
                token = secrets.token_urlsafe(32)
            _SESSIONS[token] = Session(
                username_key, now, now, setup=setup, credential_fingerprint=credential_fingerprint,
            )
            _prune_user_sessions(username_key)
            _prune_sessions(now)
        return token, _public_user(user)


def _prune_pending_logins(now: float) -> None:
    for challenge, pending in tuple(_PENDING_LOGINS.items()):
        if pending.expires_at <= now:
            _PENDING_LOGINS.pop(challenge, None)


def login_password(username: object, password: object, *, client=None) -> PasswordLoginOutcome | None:
    """Step 1 of the two-step login: verify the password only.

    Mirrors ``login`` gate for gate -- payload sanity before admission, client
    throttle and per-user lockout before any KDF, the composite dummy KDF for
    unknown or malformed records, and a CAS fingerprint re-check against disk
    inside the store lock -- so the two entry points stay indistinguishable to
    an attacker. The branch point is TOTP enrollment: an enrolled account gets
    an opaque single-use challenge and no session; everyone else gets the same
    session ``login`` would have issued. Failure accounting (client failures,
    per-user lockout, auth-log records) runs exactly as in the combined path.
    """
    if not _login_payload_is_possible(username, password, None):
        return None
    username_key = username if isinstance(username, str) and _USERNAME.fullmatch(username) else ""
    client_key = _client_key(client)
    now = time.time()
    challenge_now = time.monotonic()
    if client_throttled(client_key):
        _append_panel_auth_failure("password", client, username_key, "throttled")
        return None
    with _login_kdf_admission(client_key):
        with _STATE_LOCK:
            failure = _LOGIN_FAILURES.get(username_key)
            locked = failure is not None and failure.locked_until > now
            if failure is not None and failure.locked_until and failure.locked_until <= now:
                _LOGIN_FAILURES.pop(username_key, None)
        if locked:
            _dummy_password_work(password)
            with _STATE_LOCK:
                _register_client_failure(client_key, now)
            _append_panel_auth_failure("password", client, username_key, "locked")
            return None

        password_ok, credential_fingerprint = _verify_password_with_fingerprint(username_key, password)
        try:
            user = _find_user(_read_users(), username_key)
        except UserStoreError:
            user = None
        credentials_ok = password_ok and user is not None

        with _STATE_LOCK, _store_lock():
            _prune_sessions(now)
            if credentials_ok:
                try:
                    current_user = _find_user(_read_users(), username_key)
                except UserStoreError:
                    current_user = None
                if (
                    current_user is None
                    or credential_fingerprint is None
                    or _auth_fingerprint(current_user) != credential_fingerprint
                ):
                    credentials_ok = False
                else:
                    user = current_user
            if not credentials_ok:
                _register_client_failure(client_key, now)
                if user is not None:
                    _register_failure(username_key, now)
                _append_panel_auth_failure("password", client, username_key, "invalid_credentials")
                return None
            if user.get("totp_secret"):
                # Password verified, second factor outstanding. The challenge is
                # the only handle: random, single-use, client-bound, short-lived.
                # Failure counters are deliberately left alone -- the login has
                # not succeeded yet, and step 2 keeps counting against both.
                _prune_pending_logins(challenge_now)
                if len(_PENDING_LOGINS) >= MAX_PENDING_LOGINS or sum(
                    1 for p in _PENDING_LOGINS.values() if p.username == username_key
                ) >= MAX_PENDING_LOGINS_PER_USER:
                    # Capacity refusal: challenge creation is unauthenticated
                    # work, so flooding it counts against the requesting
                    # client like any other login failure.
                    _register_client_failure(client_key, now)
                    _append_panel_auth_failure("password", client, username_key, "throttled")
                    return None
                challenge = secrets.token_urlsafe(32)
                while challenge in _PENDING_LOGINS:
                    challenge = secrets.token_urlsafe(32)
                _PENDING_LOGINS[challenge] = PendingLogin(
                    username=username_key,
                    credential_fingerprint=credential_fingerprint,
                    client=client_key,
                    expires_at=challenge_now + PENDING_LOGIN_TTL_SECONDS,
                )
                return PasswordLoginOutcome(challenge=challenge)
            _LOGIN_FAILURES.pop(username_key, None)
            _CLIENT_FAILURES.pop(client_key, None)
            token = secrets.token_urlsafe(32)
            while token in _SESSIONS:
                token = secrets.token_urlsafe(32)
            _SESSIONS[token] = Session(
                username_key, now, now, credential_fingerprint=credential_fingerprint,
            )
            _prune_user_sessions(username_key)
            _prune_sessions(now)
        return PasswordLoginOutcome(token=token, user=_public_user(user))


def complete_login(challenge: object, code: object, *, client=None) -> tuple[str, dict] | None:
    """Step 2 of the two-step login: trade a pending challenge plus TOTP code
    for a session.

    The challenge is consumed under the state lock before anything else is
    checked, so a wrong code, an expired window, and a successful verify all
    burn it exactly once. Every refusal below returns the same generic failure
    the combined path returns; nothing here distinguishes an unknown challenge
    from a wrong code to the caller. Failures flow through the same accounting
    surfaces as ``login`` -- client failures, per-user lockout, and auth-log
    records whose reason classes ("invalid_credentials" / "totp_failed") the
    fail2ban jail already parses.
    """
    client_key = _client_key(client)
    now = time.time()
    challenge_now = time.monotonic()
    if client_throttled(client_key):
        # Consulted before consuming the challenge: a throttled client may
        # still hold a valid challenge when its cooldown expires.
        _append_panel_auth_failure("password", client, "", "throttled")
        return None
    pending = None
    if isinstance(challenge, str) and challenge:
        with _STATE_LOCK:
            _prune_pending_logins(challenge_now)
            pending = _PENDING_LOGINS.pop(challenge, None)
    if (
        pending is None
        or not isinstance(code, str)
        or not code
        or len(code) > MAX_LOGIN_TOTP_LENGTH
    ):
        with _STATE_LOCK:
            _register_client_failure(client_key, now)
        _append_panel_auth_failure(
            "password", client, pending.username if pending is not None else "", "invalid_credentials",
        )
        return None
    if pending.client != client_key:
        # A challenge speaks only for the client identity that earned it;
        # replaying it from elsewhere is an attack, not a retry.
        with _STATE_LOCK:
            _register_client_failure(client_key, now)
        _append_panel_auth_failure("password", client, pending.username, "invalid_credentials")
        return None
    if pending.expires_at <= challenge_now:
        with _STATE_LOCK:
            _register_client_failure(client_key, now)
        _append_panel_auth_failure("password", client, pending.username, "invalid_credentials")
        return None
    username_key = pending.username
    with _STATE_LOCK:
        failure = _LOGIN_FAILURES.get(username_key)
        locked = failure is not None and failure.locked_until > now
    if locked:
        with _STATE_LOCK:
            _register_client_failure(client_key, now)
        _append_panel_auth_failure("password", client, username_key, "locked")
        return None

    with _STATE_LOCK, _store_lock():
        # Lock acquisition can consume the whole challenge lifetime. Re-read
        # monotonic time inside final issuance transaction; expiry is rejected
        # at the boundary (`expires_at <= now`) even if pre-check passed.
        now = time.time()
        challenge_now = time.monotonic()
        if pending.expires_at <= challenge_now:
            _register_client_failure(client_key, now)
            _append_panel_auth_failure("password", client, username_key, "invalid_credentials")
            return None
        _prune_sessions(now)
        # Recheck lockout and client throttle atomically with issuance. The
        # checks above ran before the challenge was consumed; a lockout or
        # cooldown established between then and now must still stop this
        # redemption, including when several pre-issued challenges race.
        failure = _LOGIN_FAILURES.get(username_key)
        if failure is not None and failure.locked_until > now:
            _register_client_failure(client_key, now)
            _append_panel_auth_failure("password", client, username_key, "locked")
            return None
        client_failure = _CLIENT_FAILURES.get(client_key)
        if client_failure is not None and client_failure.cooldown_until > now:
            _append_panel_auth_failure("password", client, username_key, "throttled")
            return None
        try:
            user = _find_user(_read_users(), username_key)
        except UserStoreError:
            user = None
        credentials_ok = (
            user is not None
            and pending.credential_fingerprint is not None
            and _auth_fingerprint(user) == pending.credential_fingerprint
        )
        matched_step = _matching_totp_step(user, code, now) if credentials_ok else None
        credentials_ok = credentials_ok and matched_step is not None
        if credentials_ok and matched_step:
            if matched_step <= _LAST_TOTP_STEPS.get(username_key, -1):
                credentials_ok = False
            else:
                _LAST_TOTP_STEPS[username_key] = matched_step
        if not credentials_ok:
            _register_client_failure(client_key, now)
            if user is not None:
                _register_failure(username_key, now)
            reason = "totp_failed" if user is not None else "invalid_credentials"
            _append_panel_auth_failure("password", client, username_key, reason)
            return None
        _LOGIN_FAILURES.pop(username_key, None)
        _CLIENT_FAILURES.pop(client_key, None)
        token = secrets.token_urlsafe(32)
        while token in _SESSIONS:
            token = secrets.token_urlsafe(32)
        _SESSIONS[token] = Session(
            username_key, now, now, credential_fingerprint=pending.credential_fingerprint,
        )
        _prune_user_sessions(username_key)
        _prune_sessions(now)
    return token, _public_user(user)


def cancel_login(challenge: object, *, client=None) -> None:
    """Discard an abandoned two-step challenge without counting a failure.

    Browsing back from the code step must not leave unauthenticated pending
    entries filling the bounded challenge table. Cancellation grants no auth
    capability, so a missing, malformed, or foreign challenge is a harmless
    no-op.
    """
    if not isinstance(challenge, str) or not challenge:
        return
    client_key = _client_key(client)
    with _STATE_LOCK:
        pending = _PENDING_LOGINS.get(challenge)
        if pending is not None and pending.client == client_key:
            _PENDING_LOGINS.pop(challenge, None)


def authenticate_session(token: object) -> dict | None:
    if not isinstance(token, str) or not token:
        return None
    now = time.time()
    with _STATE_LOCK, _store_lock():
        _prune_sessions(now)
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
        if session.credential_fingerprint is None or _auth_fingerprint(user) != session.credential_fingerprint:
            _SESSIONS.pop(token, None)
            return None
        _SESSIONS[token] = replace(session, last_seen_at=now)
        public = _public_user(user)
        public["_setup_session"] = session.setup
        return public


def finish_setup_session(
    token: object, expected_fingerprint: tuple[object, object, object] | None = None,
) -> bool:
    if not isinstance(token, str) or not token:
        return False
    with _STATE_LOCK, _store_lock():
        session = _SESSIONS.get(token)
        if session is None or not session.setup:
            return False
        try:
            user = _find_user(_read_users(), session.username)
        except UserStoreError:
            user = None
        if user is None:
            _SESSIONS.pop(token, None)
            return False
        expected = expected_fingerprint if expected_fingerprint is not None else session.credential_fingerprint
        if expected is None or _auth_fingerprint(user) != expected:
            # A credential mutation between enrollment and this CAS invalidates
            # setup token rather than rebinding it to arbitrary disk state.
            _SESSIONS.pop(token, None)
            return False
        _SESSIONS[token] = replace(session, setup=False, credential_fingerprint=expected)
        return True


def logout(token: object) -> None:
    if isinstance(token, str):
        with _STATE_LOCK:
            _SESSIONS.pop(token, None)


def session_token_id(token: object) -> str:
    """Stable public identifier for a session token.

    Sessions are keyed by the raw bearer token in memory, but that token must
    never travel back to a client -- not even its own. The first 12 hex chars
    of the SHA-256 are enough for a user to tell sessions apart and revoke a
    specific one without disclosing anything replayable.
    """
    if not isinstance(token, str) or not token:
        return ""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]


def list_sessions(username: str) -> list[dict]:
    """The caller's own live sessions, oldest first, hash ids only."""
    username = _validate_username(username)
    now = time.time()
    with _STATE_LOCK, _store_lock():
        _prune_sessions(now)
        rows = [
            {
                "id": session_token_id(token),
                "created": datetime.fromtimestamp(session.created_at, tz=timezone.utc).isoformat(),
                "last_seen": datetime.fromtimestamp(session.last_seen_at, tz=timezone.utc).isoformat(),
            }
            for token, session in _SESSIONS.items()
            if session.username == username
        ]
    rows.sort(key=lambda row: (row["created"], row["id"]))
    return rows


def revoke_session_by_id(username: str, token_id: object) -> bool:
    """Revoke one of the caller's own sessions by its public hash id."""
    username = _validate_username(username)
    if not isinstance(token_id, str) or not token_id:
        return False
    wanted = token_id.encode("utf-8")
    with _STATE_LOCK:
        for token in tuple(_SESSIONS):
            session = _SESSIONS.get(token)
            if session is None or session.username != username:
                continue
            if hmac.compare_digest(session_token_id(token).encode("utf-8"), wanted):
                _SESSIONS.pop(token, None)
                return True
    return False


def reset_state() -> None:
    global _NEVER_BAN_EDGE_CACHE, _NEVER_BAN_EDGE_STALE, _NEVER_BAN_EDGE_GRACE_UNTIL
    global _NEVER_BAN_EDGE_REQUEST_SAFE
    with _STATE_LOCK:
        _SESSIONS.clear()
        _LOGIN_FAILURES.clear()
        _CLIENT_FAILURES.clear()
        _LAST_TOTP_STEPS.clear()
        _PENDING_TOTP.clear()
        _PENDING_TOTP_EXPIRES.clear()
        _PENDING_TOTP_DISCLOSED.clear()
        _PENDING_LOGINS.clear()
        _LOGIN_KDF_CLIENTS.clear()
    with _NEVER_BAN_EDGE_LOCK:
        _NEVER_BAN_EDGE_CACHE = None
        _NEVER_BAN_EDGE_STALE = ()
        _NEVER_BAN_EDGE_GRACE_UNTIL = 0.0
    _NEVER_BAN_EDGE_REQUEST_SAFE = False
