"""Site-level security (basic auth, IP restrictions, rate limiting, fail2ban)."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import contextlib
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import time

from . import cloudflare_ranges
from .certificate_lifecycle import resolve_domain_ips
from .events import record_event
from .fail2ban_host import (
    WORDPRESS_JAIL,
    ensure_fail2ban_host,
    extract_failure_id,
    validate_jail_logpath,
    wordpress_filter_content,
)
from .site_paths import env_path, read_env, site_dir, site_exists, validate_domain
from .settings import current_paths
from .traefik import traefik_network_cidrs


SECURITY_STATE = "security.json"
SECURITY_SNIPPET = "wpfy-security.conf"
FORWARDED_SCHEME_SNIPPET = "wpfy-forwarded-scheme.conf"
RATELIMIT_SNIPPET = "wpfy-ratelimit.conf"
ACCESS_LOG_FILE = "wpfy-access.log"
ACCESS_LOG_CONTAINER_PATH = "/var/log/nginx/wpfy-access.log"
FAIL2BAN_FILTER_NAME = "wpfy-wordpress"
FAIL2BAN_FILTER_FILE = f"{FAIL2BAN_FILTER_NAME}.conf"
FAIL2BAN_JAIL_FILE = "wpfy-wordpress.conf"
LOGIN_RATE_LIMIT_RATE = "1r/s"
LOGIN_RATE_LIMIT_BURST = 5
LOGIN_RATE_LIMIT_ZONE_SIZE = "1m"
HTPASSWD_FILE = "htpasswd"
HTPASSWD_CONTAINER_PATH = "/etc/nginx/wpfy-htpasswd"
# t16 W3 residual: bound every host subprocess (fail2ban-client, docker,
# openssl) so a stuck xtables/dpkg/service lock cannot hang stack install,
# enable, or status forever. Timeout surfaces as returncode 124 on _run, and
# as a caught TimeoutExpired everywhere else.
_SUBPROCESS_TIMEOUT_SECONDS = 10.0
_SAFE_HTPASSWD_USERNAME_RE = re.compile(r"[A-Za-z0-9_.@-]+")
_SAFE_UA_PATTERN_RE = re.compile(r"[A-Za-z0-9 ._/@:+*?^$|()\[\]-]{1,256}")
_APR1_ALPHABET = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

# Ban scope disclosure (plan Phase 6/7 + architecture section 9): the WPFY
# Docker action bans in DOCKER-USER, so a ban blocks HTTP/HTTPS on every site
# on this server, not just the site that triggered it.
BAN_SCOPE_MESSAGE = (
    "Only enabled sites can trigger Login Shield bans. A resulting HTTP ban "
    "may block the attacker from all websites on this WPFY server."
)

# Controlled fixture event for the enable pipeline proof (t13). TEST-NET-3 is
# reserved for documentation; a live attacker never legitimately originates
# from it, so the fixture line cannot manufacture a real ban.
_WP_FIXTURE_IP = "203.0.113.9"
_WP_FIXTURE_ACCOUNT_HASH = "0" * 64
_WP_FIXTURE_TIMESTAMP = "2026-08-06T12:00:00Z"

_DEFAULT_SECURITY = {
    "basic_auth": {"enabled": False, "username": None},
    "cloudflare_only": False,
    "login_rate_limit": False,
    "fail2ban": False,
    "deny_ips": [],
    "ua_blocks": [],
    "fail2ban_plugin": {
        "slug": None,
        "version": None,
        "ownership": None,
        "auto_updates_disabled": False,
        "active": False,
    },
}
_RECREATE_RETRY_REQUIRED: set[str] = set()

# Ownership states for the managed wp-fail2ban plugin (login-shield plan Phase 6).
# WPFY may deactivate packages it installed or activated; it must never uninstall
# or deactivate packages the administrator installed or already had active.
PLUGIN_OWNERSHIP_STATES = (
    "wpfy-installed",
    "admin-installed",
    "already-active",
    "activated-by-wpfy",
)
PRESERVED_PLUGIN_OWNERSHIP = frozenset({"admin-installed", "already-active"})
WPFY_PLUGIN_OWNERSHIP = frozenset({"wpfy-installed", "activated-by-wpfy"})
_DEFAULT_PLUGIN_STATE = dict(_DEFAULT_SECURITY["fail2ban_plugin"])


@dataclass(frozen=True, slots=True)
class SecurityResult:
    """Security configuration result."""
    exit_code: int
    message: str
    changed: bool = False
    one_time_password: str | None = None


@dataclass(frozen=True, slots=True)
class SecurityPreflightResult:
    """Security preflight check result."""
    warnings: tuple[str, ...] = ()


def _require_site(domain: str) -> Path:
    validate_domain(domain)
    if not site_exists(domain):
        raise FileNotFoundError(f"site not found: {domain}")
    return site_dir(domain)


def access_log_path(domain: str) -> Path:
    """Return access log path."""
    validate_domain(domain)
    root = Path(current_paths().sites_dir) / domain
    if not root.is_dir():
        raise FileNotFoundError(f"site not found: {domain}")
    return root / "nginx" / ACCESS_LOG_FILE


# Legacy alias kept only because site_event_pipeline imports this name;
# new code calls settings.current_paths() directly.
_current_paths = current_paths


def _fail2ban_root() -> Path:
    # Wpfy keeps its own configuration in /etc/wpfy; fail2ban and logrotate use
    # sibling system directories. Tests redirect WPFY_CONFIG_DIR and stay isolated.
    return Path(current_paths().config_dir).parent / "fail2ban"


def fail2ban_filter_path() -> Path:
    """Return fail2ban filter path."""
    return _fail2ban_root() / "filter.d" / FAIL2BAN_FILTER_FILE


def fail2ban_jail_path() -> Path:
    """Return fail2ban jail path."""
    return _fail2ban_root() / "jail.d" / FAIL2BAN_JAIL_FILE


def wp_auth_log_path(domain: str) -> Path:
    """Host path of the per-site WordPress authentication event log (t10)."""
    from .site_event_pipeline import auth_log_path

    return auth_log_path(domain)


@contextmanager
def _site_mutation_lock(domain: str):
    """Exclusive per-site flock around security mutations (enable/disable).

    Mirrors the traefik/panel flock pattern: blocking lock in the state dir,
    released on exit, safe across processes and threads.
    """
    import fcntl

    root = Path(current_paths().state_dir) / "site-mutation-locks"
    root.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(domain.encode("utf-8")).hexdigest()[:16]
    path = root / f"{digest}.lock"
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _logrotate_path(domain: str) -> Path:
    validate_domain(domain)
    digest = hashlib.sha256(domain.encode("utf-8")).hexdigest()[:16]
    return Path(current_paths().config_dir).parent / "logrotate.d" / f"wpfy-{digest}"


def fail2ban_available() -> bool:
    """Check if fail2ban is available."""
    return shutil.which("fail2ban-client") is not None


def _safe_read(root: Path, name: str) -> str | None:
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=root_fd)
        except FileNotFoundError:
            return None
        with os.fdopen(file_fd, "r", encoding="utf-8") as handle:
            return handle.read()
    finally:
        os.close(root_fd)


def _safe_write(root: Path, name: str, content: str, mode: int) -> None:
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        file_fd = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            mode,
            dir_fd=root_fd,
        )
        with os.fdopen(file_fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(root_fd)


def _safe_write_in_place(root: Path, name: str, content: str, mode: int) -> None:
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        file_fd = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
            mode,
            dir_fd=root_fd,
        )
        with os.fdopen(file_fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(name, mode, dir_fd=root_fd, follow_symlinks=False)
    finally:
        os.close(root_fd)


def _replace_file(root: Path, target: str, replacement: str) -> None:
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with contextlib.suppress(FileNotFoundError):
            metadata = os.stat(target, dir_fd=root_fd, follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                raise OSError(f"managed security config is a symlink: {target}")
        os.replace(replacement, target, src_dir_fd=root_fd, dst_dir_fd=root_fd)
    finally:
        os.close(root_fd)


def _cleanup(root: Path, name: str) -> None:
    with contextlib.suppress(OSError):
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.unlink(name, dir_fd=root_fd)
        except FileNotFoundError:
            pass
        finally:
            os.close(root_fd)


def _install_text(root: Path, target: str, content: str, mode: int) -> bool:
    current = _safe_read(root, target)
    if current == content:
        return False
    candidate = f".{target}-{secrets.token_hex(8)}.candidate"
    try:
        _safe_write(root, candidate, content, mode)
        _replace_file(root, target, candidate)
        candidate = ""
    finally:
        if candidate:
            _cleanup(root, candidate)
    return True


def _install_text_in_place(root: Path, target: str, content: str, mode: int) -> bool:
    """Update individually bind-mounted nginx files without replacing their inode."""
    if _safe_read(root, target) == content:
        return False
    _safe_write_in_place(root, target, content, mode)
    return True


def _normalize_cidr(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("CIDR must not be empty")
    try:
        network = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError as exc:
        raise ValueError(f"invalid CIDR: {value!r}") from exc
    if network.prefixlen == 0:
        raise ValueError("deny-everything CIDRs are not allowed")
    return network.with_prefixlen


def _normalize_ua_pattern(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("user-agent pattern must not be empty")
    pattern = value.strip()
    if not _SAFE_UA_PATTERN_RE.fullmatch(pattern):
        raise ValueError(
            "invalid user-agent pattern: use ASCII letters, digits, spaces, and conservative regex punctuation",
        )
    return pattern


def _validated_config(config: dict) -> dict:
    if not isinstance(config, dict):
        raise TypeError("security config must be an object")
    normalized = dict(config)

    basic_auth = config.get("basic_auth", _DEFAULT_SECURITY["basic_auth"])
    if not isinstance(basic_auth, dict) or not isinstance(basic_auth.get("enabled", False), bool):
        raise ValueError("security basic_auth must contain a boolean enabled value")
    username = basic_auth.get("username")
    if username is not None and not _safe_htpasswd_username(username):
        raise ValueError("invalid basic-auth username")
    normalized["basic_auth"] = {
        "enabled": basic_auth.get("enabled", False),
        "username": username,
    }

    cloudflare_only = config.get("cloudflare_only", False)
    if not isinstance(cloudflare_only, bool):
        raise ValueError("security cloudflare_only must be a boolean")
    normalized["cloudflare_only"] = cloudflare_only

    login_rate_limit = config.get("login_rate_limit", False)
    if not isinstance(login_rate_limit, bool):
        raise ValueError("security login_rate_limit must be a boolean")
    normalized["login_rate_limit"] = login_rate_limit

    fail2ban = config.get("fail2ban", False)
    if not isinstance(fail2ban, bool):
        raise ValueError("security fail2ban must be a boolean")
    normalized["fail2ban"] = fail2ban

    deny_ips = config.get("deny_ips", [])
    if not isinstance(deny_ips, list):
        raise ValueError("security deny_ips must be a list")
    normalized["deny_ips"] = sorted({_normalize_cidr(value) for value in deny_ips})

    ua_blocks = config.get("ua_blocks", [])
    if not isinstance(ua_blocks, list):
        raise ValueError("security ua_blocks must be a list")
    normalized["ua_blocks"] = sorted({_normalize_ua_pattern(value) for value in ua_blocks})

    plugin = config.get("fail2ban_plugin")
    if plugin is None or not isinstance(plugin, dict):
        plugin = {}
    plugin_slug = plugin.get("slug")
    if plugin_slug is not None and not isinstance(plugin_slug, str):
        raise ValueError("security fail2ban_plugin.slug must be a string or null")
    plugin_version = plugin.get("version")
    if plugin_version is not None and not isinstance(plugin_version, str):
        raise ValueError("security fail2ban_plugin.version must be a string or null")
    plugin_ownership = plugin.get("ownership")
    if plugin_ownership is not None and plugin_ownership not in PLUGIN_OWNERSHIP_STATES:
        raise ValueError(f"invalid fail2ban_plugin ownership: {plugin_ownership}")
    auto_updates_disabled = plugin.get("auto_updates_disabled", False)
    if not isinstance(auto_updates_disabled, bool):
        raise ValueError("security fail2ban_plugin.auto_updates_disabled must be a boolean")
    plugin_active = plugin.get("active", False)
    if not isinstance(plugin_active, bool):
        raise ValueError("security fail2ban_plugin.active must be a boolean")
    normalized["fail2ban_plugin"] = {
        "slug": plugin_slug,
        "version": plugin_version,
        "ownership": plugin_ownership,
        "auto_updates_disabled": auto_updates_disabled,
        "active": plugin_active,
    }

    try:
        json.dumps(normalized)
    except (TypeError, ValueError) as exc:
        raise ValueError("security config must contain JSON values") from exc
    return normalized


def _decode_config(content: str) -> dict:
    try:
        raw = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid security.json: {exc}") from exc
    return _validated_config(raw)


def load_security(domain: str) -> dict:
    """Load security."""
    root = _require_site(domain)
    content = _safe_read(root, SECURITY_STATE)
    if content is None:
        return _validated_config(dict(_DEFAULT_SECURITY))
    return _decode_config(content)


def save_security(domain: str, config: dict) -> None:
    """Save security."""
    root = _require_site(domain)
    candidate = dict(config)
    if not isinstance(candidate.get("login_rate_limit", False), bool):
        candidate["login_rate_limit"] = False
    if not isinstance(candidate.get("fail2ban", False), bool):
        candidate["fail2ban"] = False
    normalized = _validated_config(candidate)
    content = json.dumps(normalized, indent=2, sort_keys=True) + "\n"
    _install_text(root, SECURITY_STATE, content, 0o600)


def cloudflare_cidrs() -> tuple[str, ...]:
    """Cloudflare cidrs."""
    cidrs: list[str] = []
    for raw in cloudflare_ranges._effective_cidrs():
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError as exc:
            raise RuntimeError(f"invalid Cloudflare edge range: {raw!r}") from exc
        if network.prefixlen == 0:
            raise RuntimeError("wildcard Cloudflare edge range refused")
        cidrs.append(network.with_prefixlen)
    if not cidrs:
        raise RuntimeError("no Cloudflare edge ranges are configured")
    return tuple(dict.fromkeys(cidrs))


def _cloudflare_trust_required(domain: str, config: dict) -> bool:
    if config["cloudflare_only"]:
        return True
    return read_env(env_path(domain)).get("PROXIED") == "1"


def login_zone_name(domain: str) -> str:
    """Login zone name."""
    validate_domain(domain)
    digest = hashlib.sha256(domain.encode("utf-8")).hexdigest()[:16]
    return f"wpfy_login_{digest}"


def _rate_limit_zone_content(domain: str, config: dict) -> str:
    if not config["login_rate_limit"]:
        return ""
    request_zone = login_zone_name(domain)
    connection_zone = f"{request_zone}_conn"
    return "\n".join((
        "# Generated by wpfy. Per-site login rate-limit zones; do not edit.",
        f"limit_req_zone $binary_remote_addr zone={request_zone}:{LOGIN_RATE_LIMIT_ZONE_SIZE} rate={LOGIN_RATE_LIMIT_RATE};",
        f"limit_conn_zone $binary_remote_addr zone={connection_zone}:{LOGIN_RATE_LIMIT_ZONE_SIZE};",
        "",
    ))


def _fail2ban_filter_content() -> str:
    """Delegate to the single owner so filter.d/wpfy-wordpress.conf never diverges."""
    return wordpress_filter_content()


def _enabled_fail2ban_domains(
    *, skip_invalid: bool = False, skipped_domains: list[str] | None = None
) -> tuple[str, ...]:
    sites_root = Path(current_paths().sites_dir)
    if not sites_root.is_dir():
        return ()
    domains: list[str] = []
    for candidate in sorted(sites_root.iterdir(), key=lambda item: item.name):
        if not candidate.is_dir():
            continue
        try:
            validate_domain(candidate.name)
            state = _safe_read(candidate, SECURITY_STATE)
            config = _validated_config(dict(_DEFAULT_SECURITY)) if state is None else _decode_config(state)
        except (OSError, TypeError, ValueError) as exc:
            if not skip_invalid:
                raise ValueError(f"cannot load security state for {candidate.name}: {exc}") from exc
            if skipped_domains is not None:
                skipped_domains.append(candidate.name)
            continue
        if config["fail2ban"]:
            domains.append(candidate.name)
    return tuple(domains)


def _fail2ban_jail_name(domain: str) -> str:
    """Per-site jail name: bare 16-hex digest of the domain.

    Blocker B1: the WPFY action renders the chain as ``CHAIN_PREFIX + <name>``
    (``f2b-wpfy-`` + the per-jail name parameter). Keeping the jail name a
    bare digest (16 chars) yields ``f2b-wpfy-<16hex>`` = 25 chars — under the
    iptables 28-char cap. The historical ``wpfy-<16hex>`` jail name produced
    the 30-char ``f2b-wpfy-wpfy-<16hex>`` chain that iptables rejected with
    EINVAL and the action silently swallowed (bans were no-ops).
    """
    return hashlib.sha256(domain.encode("utf-8")).hexdigest()[:16]


def _fail2ban_jail_content(domains: tuple[str, ...]) -> str:
    from .fail2ban_docker import (
        CHAIN_PREFIX,
        validate_chain_name,
        validate_unique_chain_names,
    )

    # Per-jail WPFY action name: the action renders chain CHAIN_PREFIX +
    # <name>; fail2ban substitutes the per-jail name parameter, so each site
    # gets a unique f2b-wpfy-<digest> chain (25 chars, inside the iptables
    # 28-char cap). Reject shared literal chains and any chain that would
    # silently fail to ban.
    chain_names = [f"{CHAIN_PREFIX}{_fail2ban_jail_name(domain)}" for domain in domains]
    for chain_name in chain_names:
        validate_chain_name(chain_name)
    validate_unique_chain_names(chain_names)

    lines = ["# Generated by wpfy. Per-site jails; do not edit."]
    for domain in domains:
        jail_name = _fail2ban_jail_name(domain)
        lines.extend((
            "",
            f"[{jail_name}]",
            "enabled = true",
            f"filter = {FAIL2BAN_FILTER_NAME}",
            # Blocker 2 fix: the jail reads ONLY the per-site strict WP auth
            # event log (t10, proven WP fail2ban event path). The coarse nginx
            # access-log backstop regex stays in the shared filter but is NOT a
            # jail logpath: fail2ban 1.0.2 rejects a space-separated dual
            # logpath at reload (addlogpath protocol) and duplicate logpath
            # keys outright.
            f"logpath = {wp_auth_log_path(domain)}",
            "backend = auto",
            f"maxretry = {WORDPRESS_JAIL['maxretry']}",
            f"findtime = {WORDPRESS_JAIL['findtime']}",
            f"bantime = {WORDPRESS_JAIL['bantime']}",
            f"action = wpfy-docker-http[name={jail_name}]",
        ))
    return "\n".join(lines) + "\n"


def _install_global_text(path: Path, content: str) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    return _install_text(path.parent, path.name, content, 0o644)


def _remove_global_file(path: Path) -> bool:
    try:
        path.unlink()
    except FileNotFoundError:
        return False
    return True


def _render_fail2ban_configs(
    *, skip_invalid: bool = False, skipped_domains: list[str] | None = None
) -> bool:
    domains = _enabled_fail2ban_domains(skip_invalid=skip_invalid, skipped_domains=skipped_domains)
    filter_path = fail2ban_filter_path()
    jail_path = fail2ban_jail_path()
    if not domains:
        # Remove shared files only when no WPFY feature uses them. The Docker
        # action (action.d/wpfy-docker-http.conf) is owned by host ensure and
        # stays for the panel jail; it is never removed here.
        removed = _remove_global_file(filter_path)
        removed = _remove_global_file(jail_path) or removed
        return removed
    # Blocker 2 gate: validate the rendered per-site jail in-process BEFORE it
    # is written. fail2ban-client -t alone accepts a dual-logpath render and
    # the failure only surfaces at reload (degrading fail2ban); the guard
    # fails closed here instead.
    jail_content = _fail2ban_jail_content(domains)
    jail_ok, jail_msg = validate_jail_logpath(jail_content)
    if not jail_ok:
        raise ValueError(f"per-site jail contract violation: {jail_msg}")
    changed = _install_global_text(filter_path, _fail2ban_filter_content())
    changed = _install_global_text(jail_path, jail_content) or changed
    return changed


def _configure_access_log_rotation(domain: str) -> bool:
    log = access_log_path(domain)
    content = "\n".join((
        "# Generated by wpfy. Keep host-visible access logs bounded.",
        f"{log} {{",
        "    weekly",
        "    maxsize 100M",
        "    rotate 12",
        "    missingok",
        "    notifempty",
        "    compress",
        "    delaycompress",
        "    copytruncate",
        "}",
        "",
    ))
    return _install_global_text(_logrotate_path(domain), content)


def _remove_access_log_rotation(domain: str) -> bool:
    return _remove_global_file(_logrotate_path(domain))


def _reload_fail2ban() -> str | None:
    if os.environ.get("WPFY_SKIP_RUNTIME") == "1":
        return None
    proc = subprocess.run(["fail2ban-client", "reload"], check=False, capture_output=True, text=True, timeout=_SUBPROCESS_TIMEOUT_SECONDS)
    if proc.returncode == 0:
        return None
    return proc.stderr.strip() or proc.stdout.strip() or "fail2ban-client reload failed"


def _validate_fail2ban() -> str | None:
    """Run fail2ban-client -t; returns an error string or None."""
    if os.environ.get("WPFY_SKIP_RUNTIME") == "1" or not fail2ban_available():
        return None
    proc = subprocess.run(["fail2ban-client", "-t"], check=False, capture_output=True, text=True, timeout=_SUBPROCESS_TIMEOUT_SECONDS)
    if proc.returncode == 0:
        return None
    return proc.stderr.strip() or proc.stdout.strip() or "fail2ban-client -t failed"


def _fail2ban_ping() -> str | None:
    if os.environ.get("WPFY_SKIP_RUNTIME") == "1" or not fail2ban_available():
        return None
    proc = subprocess.run(["fail2ban-client", "ping"], check=False, capture_output=True, text=True, timeout=_SUBPROCESS_TIMEOUT_SECONDS)
    if proc.returncode == 0 and "pong" in proc.stdout.lower():
        return "ok"
    return "unhealthy"


def _wp_fixture_record(domain: str) -> str:
    return json.dumps({
        "timestamp": _WP_FIXTURE_TIMESTAMP,
        "event": "wordpress_auth_failure",
        "site": domain,
        "surface": "wp_login",
        "client_ip": _WP_FIXTURE_IP,
        "account_hash": _WP_FIXTURE_ACCOUNT_HASH,
        "reason_class": "soft",
    }, ensure_ascii=True, separators=(",", ":"))


def _append_auth_fixture(domain: str, line: str) -> None:
    """Append one fixture line to the per-site event log without following symlinks."""
    from .site_event_pipeline import AUTH_LOG_FILE, security_dir

    root = security_dir(domain)
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        file_fd = os.open(AUTH_LOG_FILE, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW, dir_fd=root_fd)
        with os.fdopen(file_fd, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    finally:
        os.close(root_fd)


def _prune_auth_fixture(domain: str, fixture_line: str) -> None:
    """Remove one exact controlled fixture line from wp-auth.log (t16 W7).

    The fixture is appended only to prove the bind-mounted log is writable
    end-to-end, then pruned so fixture records never accumulate in the live
    log and never inflate ``login_shield_status`` failure counts. Only the
    exact deterministic fixture line is removed — real auth-failure records
    are preserved. In-place truncation keeps the bind-mounted inode so the
    app container and fail2ban keep tailing the same file.
    """
    from .site_event_pipeline import AUTH_LOG_FILE, security_dir

    root = security_dir(domain)
    try:
        content = _safe_read(root, AUTH_LOG_FILE)
    except OSError:
        return
    if content is None:
        return
    kept = [line for line in content.splitlines() if line != fixture_line]
    rewritten = "\n".join(kept)
    if kept and not rewritten.endswith("\n"):
        rewritten += "\n"
    with contextlib.suppress(OSError):
        _safe_write_in_place(root, AUTH_LOG_FILE, rewritten, 0o640)


def _fixture_pipeline_proof(domain: str, *, append_event: bool = False) -> tuple[bool, list[str]]:
    """Fixture-level proof: controlled event -> event log -> filter -> jail.

    NOT real enforcement: it appends one controlled fixture record (only on a
    real state change), confirms the strict WPFY auth filter matches it and
    extracts the fixture client, confirms the shared jail references this
    site's event log, and fails closed unless this site's iptables chain name
    is valid and inside the 28-char cap (blocker B1 companion). The fixture
    line is pruned immediately (W7) so it never accumulates or inflates
    status. A live, gated verification of an actual DOCKER-USER ban runs at
    t21.
    """
    from .fail2ban_host import extract_failure_id, wordpress_auth_failregex
    from .fail2ban_docker import validate_chain_name

    errors: list[str] = []
    record = _wp_fixture_record(domain)
    log = wp_auth_log_path(domain)

    if append_event:
        try:
            _append_auth_fixture(domain, record)
        except (OSError, ValueError) as exc:
            errors.append(f"cannot append fixture event to event log: {exc}")
        # W7: bound the proof writes — remove the exact fixture line so the
        # live log stays clean after the proof completes.
        _prune_auth_fixture(domain, record)

    try:
        compiled = re.compile(wordpress_auth_failregex(), re.MULTILINE | re.DOTALL)
    except re.error as exc:
        errors.append(f"auth filter regex invalid: {exc}")
    else:
        match = compiled.match(record)
        if match is None:
            errors.append("fixture event did not match the WPFY auth filter")
        elif extract_failure_id(match) != _WP_FIXTURE_IP:
            errors.append("auth filter extracted the wrong client IP")

    jail_path = fail2ban_jail_path()
    try:
        jail_text = jail_path.read_text(encoding="utf-8")
    except OSError:
        jail_text = ""
    if not jail_text:
        errors.append("per-site jail file is missing")
    else:
        if f"[{_fail2ban_jail_name(domain)}]" not in jail_text:
            errors.append("per-site jail section is missing")
        elif str(log) not in jail_text:
            errors.append("per-site jail does not reference the site event log")

    # B1 companion: fail closed on an invalid or oversized chain name. A
    # chain iptables rejects (EINVAL) silently no-ops every ban; the site must
    # never be marked enabled while its enforcement chain cannot exist.
    try:
        validate_chain_name(_fail2ban_chain_name(_fail2ban_jail_name(domain)))
    except ValueError as exc:
        errors.append(f"per-site jail chain name invalid: {exc}")

    return not errors, errors


def _revert_fail2ban_state(domain: str) -> None:
    """Roll back an interrupted enable: state off, bridge guard off, configs re-rendered."""
    with contextlib.suppress(OSError, TypeError, ValueError):
        config = load_security(domain)
        if config["fail2ban"]:
            updated = dict(config)
            updated["fail2ban"] = False
            save_security(domain, updated)
    with contextlib.suppress(OSError, TypeError, ValueError):
        from .site_event_pipeline import ensure_event_pipeline_files

        ensure_event_pipeline_files(domain, enabled=False)
    with contextlib.suppress(OSError, RuntimeError, ValueError):
        _render_fail2ban_configs(skip_invalid=True)
    reload_error = _reload_fail2ban() if fail2ban_available() else None
    if reload_error:
        record_event(
            "login_shield.health_failed",
            domain=domain,
            outcome="error",
            detail=f"rollback reload failed: {reload_error}",
        )


def _recreate_web_service(domain: str) -> str | None:
    from .site_runtime import compose_command, docker_available, runtime_skip_requested

    if runtime_skip_requested() or not docker_available():
        return None
    try:
        proc = compose_command(domain, "up", "-d", "--force-recreate", "web")
    except (OSError, subprocess.SubprocessError) as exc:
        return str(exc)
    if proc.returncode == 0:
        return None
    return proc.stderr.strip() or proc.stdout.strip() or "web service recreate failed"


def _running_web_container(domain: str) -> str | None:
    from .site_runtime import compose_command, docker_available, runtime_skip_requested

    if runtime_skip_requested() or not docker_available():
        return None
    try:
        proc = compose_command(domain, "ps", "--status", "running", "-q", "web")
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip().splitlines()[0] if proc.stdout.strip() else ""


def _running_web_labels(domain: str, container: str) -> dict[str, str] | None:
    from .site_runtime import compose_command

    try:
        rendered = compose_command(domain, "config", "--format", "json")
        if rendered.returncode != 0:
            return None
        expected = json.loads(rendered.stdout)["services"]["web"]["labels"]
        if isinstance(expected, list):
            expected = dict(item.split("=", 1) for item in expected)
        if not isinstance(expected, dict):
            return None
        if any(not isinstance(key, str) or not key.startswith("traefik.") for key in expected):
            return {}
        inspected = subprocess.run(
            ["docker", "inspect", "--format", "{{json .Config.Labels}}", container],
            check=False,
            capture_output=True,
            text=True,
            timeout=_SUBPROCESS_TIMEOUT_SECONDS,
        )
        if inspected.returncode != 0:
            return None
        labels = json.loads(inspected.stdout)
        if not isinstance(labels, dict):
            return {}
        running_traefik = {
            key: value for key, value in labels.items() if isinstance(key, str) and key.startswith("traefik.")
        }
        return labels if running_traefik == expected else {}
    except (AttributeError, KeyError, TypeError, ValueError, OSError, subprocess.SubprocessError):
        return None


def _reload_web_service(domain: str) -> str | None:
    from .site_runtime import compose_command, docker_available, runtime_skip_requested

    if runtime_skip_requested() or not docker_available():
        return None
    for attempt in range(3):
        try:
            proc = compose_command(domain, "exec", "-T", "web", "nginx", "-s", "reload")
        except (OSError, subprocess.SubprocessError) as exc:
            return str(exc)
        if proc.returncode == 0:
            return None
        if attempt < 2:
            time.sleep(0.5)
    return proc.stderr.strip() or proc.stdout.strip() or "nginx reload failed"


def apply_security_runtime(domain: str) -> SecurityResult:
    """Apply security runtime."""
    forwarded = render_forwarded_scheme(domain)
    if forwarded.exit_code != 0:
        return forwarded
    rendered = render_security(domain)
    if rendered.exit_code != 0:
        return rendered
    running = _running_web_container(domain)
    if running == "":
        return SecurityResult(0, "security configuration staged; will apply when site starts", rendered.changed or forwarded.changed)
    reload_error = _reload_web_service(domain)
    if reload_error:
        return SecurityResult(
            3,
            f"security configuration written but not applied; nginx reload failed: {reload_error}",
            rendered.changed or forwarded.changed,
        )
    return SecurityResult(rendered.exit_code, rendered.message, rendered.changed or forwarded.changed)


def _edge_network_cidrs() -> tuple[str, ...]:
    if os.environ.get("WPFY_SKIP_RUNTIME") == "1" and not os.environ.get("WPFY_TEST_TRAEFIK_NETWORK_CIDRS"):
        raise RuntimeError("wpfy edge network discovery skipped by WPFY_SKIP_RUNTIME")
    return traefik_network_cidrs()


def _forwarded_scheme_content(trusted_sources: tuple[str, ...]) -> str:
    lines = [
        "# Generated by wpfy. Trust forwarded scheme only from the Traefik edge hop.",
        "geo $realip_remote_addr $wpfy_trusted_edge {",
        "    default 0;",
    ]
    lines.extend(f"    {source} 1;" for source in trusted_sources)
    lines.extend([
        "}",
        "",
        'map "$wpfy_trusted_edge:$http_x_forwarded_proto" $wpfy_https {',
        "    default off;",
        '    "1:https" on;',
        "}",
        "",
    ])
    return "\n".join(lines)


def render_forwarded_scheme(domain: str) -> SecurityResult:
    """Render forwarded scheme."""
    root = _require_site(domain) / "nginx"
    try:
        config = load_security(domain)
        trusted_sources = list(_edge_network_cidrs())
        if _cloudflare_trust_required(domain, config):
            trusted_sources.extend(cloudflare_cidrs())
    except RuntimeError:
        # Fail closed when runtime discovery is unavailable: no forwarded header
        # can assert HTTPS until a later refresh discovers the real edge address.
        trusted_sources = ["127.0.0.1/32"]
    try:
        changed = _install_text_in_place(
            root,
            FORWARDED_SCHEME_SNIPPET,
            _forwarded_scheme_content(tuple(dict.fromkeys(trusted_sources))),
            0o644,
        )
    except OSError as exc:
        return SecurityResult(3, f"failed to render forwarded scheme config: {exc}")
    return SecurityResult(
        0,
        "nginx forwarded scheme config updated" if changed else "nginx forwarded scheme config unchanged",
        changed,
    )


def _security_snippet(domain: str, config: dict) -> tuple[str, str | None]:
    normalized = _validated_config(config)
    lines = ["# Generated by wpfy. Per-site security rules are managed; do not edit."]
    trust_error: str | None = None
    # Every site writes a host-visible access log. Resolve its first field to
    # the actual client before fail2ban ever reads it; logging Traefik here
    # would make a ban take the entire edge offline.
    try:
        trusted_sources = list(_edge_network_cidrs())
        if _cloudflare_trust_required(domain, normalized):
            trusted_sources.extend(cloudflare_cidrs())
    except RuntimeError as exc:
        trust_error = str(exc)
        trusted_sources = ["127.0.0.1/32"]
    lines.extend(["", "# Resolve the client through trusted edge hops only."])
    lines.extend(f"set_real_ip_from {source};" for source in dict.fromkeys(trusted_sources))
    lines.extend([
        "real_ip_header X-Forwarded-For;",
        "real_ip_recursive on;",
    ])
    if trust_error and (normalized["deny_ips"] or normalized["login_rate_limit"] or normalized["fail2ban"]):
        lines.extend([
            "",
            "# Edge trust discovery failed. Block every request rather than trust a guessed proxy source.",
            "deny all;",
        ])
    if normalized["login_rate_limit"]:
        request_zone = login_zone_name(domain)
        connection_zone = f"{request_zone}_conn"
        lines.extend([
            "",
            "# ponytail: add an operator CIDR exception here only with an explicit trust model.",
            "limit_req_status 429;",
            "limit_conn_status 429;",
            "location = /wp-login.php {",
            f"    limit_req zone={request_zone} burst={LOGIN_RATE_LIMIT_BURST} nodelay;",
            f"    limit_conn {connection_zone} 5;",
            "    try_files $uri =404;",
            "    include fastcgi_params;",
            "    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;",
            "    fastcgi_param HTTPS $wpfy_https;",
            "    fastcgi_read_timeout 300s;",
            "    fastcgi_pass app:9000;",
            "}",
        ])
    if normalized["basic_auth"]["enabled"]:
        lines.extend([
            "",
            "# Require the managed per-site HTTP basic-auth credential.",
            'auth_basic "Restricted";',
            f"auth_basic_user_file {HTPASSWD_CONTAINER_PATH};",
        ])
    if normalized["ua_blocks"]:
        lines.extend(["", "# Block configured user-agent patterns."])
        for pattern in normalized["ua_blocks"]:
            lines.append(f'if ($http_user_agent ~* "{pattern}") {{ return 403; }}')
    if normalized["deny_ips"]:
        lines.extend(["", "# Deny configured client networks after real-IP resolution."])
        lines.extend(f"deny {cidr};" for cidr in normalized["deny_ips"])
    return "\n".join(lines) + "\n", trust_error


def render_security(domain: str) -> SecurityResult:
    """Render security."""
    root = _require_site(domain)
    try:
        state_content = _safe_read(root, SECURITY_STATE)
        config = _validated_config(dict(_DEFAULT_SECURITY)) if state_content is None else _decode_config(state_content)
        rotation_changed = _configure_access_log_rotation(domain)
        from .site_event_pipeline import _configure_auth_log_rotation
        auth_rotation_changed = _configure_auth_log_rotation(domain)
        content, trust_error = _security_snippet(domain, config)
        changed = _install_text(root / "nginx" / "extra", SECURITY_SNIPPET, content, 0o644)
        changed = changed or rotation_changed or auth_rotation_changed
        zone_content = _rate_limit_zone_content(domain, config)
        zone_root = root / "nginx"
        zone_changed = _safe_read(zone_root, RATELIMIT_SNIPPET) != zone_content
        if zone_changed:
            _safe_write_in_place(zone_root, RATELIMIT_SNIPPET, zone_content, 0o644)
        changed = changed or zone_changed
    except (OSError, RuntimeError, ValueError) as exc:
        return SecurityResult(3, f"failed to render security config: {exc}")
    if trust_error and (config["deny_ips"] or config["login_rate_limit"] or config["fail2ban"]):
        return SecurityResult(
            3,
            f"failed to determine the wpfy edge trust source; installed a fail-closed deny-all config: {trust_error}",
            changed,
        )
    return SecurityResult(
        0,
        "nginx security config updated" if changed else "nginx security config unchanged",
        changed,
    )


def _update_list(domain: str, key: str, value: str, *, remove: bool) -> SecurityResult:
    if key == "deny_ips":
        normalized_value = _normalize_cidr(value)
        action = "deny-ip"
    elif key == "ua_blocks":
        normalized_value = _normalize_ua_pattern(value)
        action = "ua-block"
    else:
        raise ValueError(f"unsupported security list: {key}")

    config = load_security(domain)
    values = list(config[key])
    changed = False
    if remove:
        if normalized_value in values:
            values.remove(normalized_value)
            changed = True
    elif normalized_value not in values:
        values.append(normalized_value)
        changed = True

    if changed:
        updated = dict(config)
        updated[key] = values
        save_security(domain, updated)
    rendered = apply_security_runtime(domain)
    if rendered.exit_code != 0:
        return rendered

    operation = "remove" if remove else "add"
    if changed:
        record_event(
            f"site.security.{action}.{operation}",
            domain=domain,
            detail=f"per-site {action} rule {'removed' if remove else 'added'}",
        )
    state = "removed" if remove and changed else "added" if changed else "unchanged"
    message = f"{action} rule {state}"
    if "staged" in rendered.message.lower():
        message += f"; {rendered.message}"
    return SecurityResult(0, message, changed or rendered.changed)


def add_deny_ip(domain: str, cidr: str) -> SecurityResult:
    """Add deny ip."""
    return _update_list(domain, "deny_ips", cidr, remove=False)


def remove_deny_ip(domain: str, cidr: str) -> SecurityResult:
    """Remove deny ip."""
    return _update_list(domain, "deny_ips", cidr, remove=True)


def add_ua_block(domain: str, pattern: str) -> SecurityResult:
    """Add ua block."""
    return _update_list(domain, "ua_blocks", pattern, remove=False)


def remove_ua_block(domain: str, pattern: str) -> SecurityResult:
    """Remove ua block."""
    return _update_list(domain, "ua_blocks", pattern, remove=True)


def _safe_htpasswd_username(value: str) -> bool:
    return isinstance(value, str) and bool(_SAFE_HTPASSWD_USERNAME_RE.fullmatch(value))


def _htpasswd_apr1(password: str) -> str:
    """Return an Apache APR1 htpasswd hash using a fresh 48-bit salt."""
    password_bytes = password.encode("utf-8")
    salt = "".join(secrets.choice(_APR1_ALPHABET) for _ in range(8)).encode("ascii")
    digest = hashlib.md5(password_bytes + salt + password_bytes).digest()
    context = password_bytes + b"$apr1$" + salt
    for offset in range(0, len(password_bytes), len(digest)):
        context += digest[: min(len(digest), len(password_bytes) - offset)]
    length = len(password_bytes)
    while length:
        context += b"\0" if length & 1 else password_bytes[:1]
        length >>= 1
    digest = hashlib.md5(context).digest()
    for iteration in range(1000):
        context = password_bytes if iteration & 1 else digest
        if iteration % 3:
            context += salt
        if iteration % 7:
            context += password_bytes
        context += digest if iteration & 1 else password_bytes
        digest = hashlib.md5(context).digest()

    def encode(value: int, count: int) -> str:
        """Encode value."""
        chars = []
        for _ in range(count):
            chars.append(_APR1_ALPHABET[value & 0x3F])
            value >>= 6
        return "".join(chars)

    encoded = "".join((
        encode((digest[0] << 16) | (digest[6] << 8) | digest[12], 4),
        encode((digest[1] << 16) | (digest[7] << 8) | digest[13], 4),
        encode((digest[2] << 16) | (digest[8] << 8) | digest[14], 4),
        encode((digest[3] << 16) | (digest[9] << 8) | digest[15], 4),
        encode((digest[4] << 16) | (digest[10] << 8) | digest[5], 4),
        encode(digest[11], 2),
    ))
    return f"$apr1${salt.decode('ascii')}${encoded}"


def _htpasswd_hash(password: str) -> tuple[str, str]:
    """Return a host-generated sha512crypt hash, or APR1 when OpenSSL is absent."""
    try:
        process = subprocess.Popen(
            ["openssl", "passwd", "-6", "-stdin"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError:
        return _htpasswd_apr1(password), "apr1"
    try:
        stdout, stderr = process.communicate(password, timeout=_SUBPROCESS_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        raise RuntimeError("openssl passwd -6 timed out") from None
    if process.returncode != 0:
        message = stderr.strip() or stdout.strip() or "openssl passwd -6 failed"
        raise RuntimeError(message)
    hashed = stdout.strip()
    if not hashed.startswith("$6$"):
        raise RuntimeError("openssl passwd -6 did not return a sha512crypt hash")
    return hashed, "sha512crypt"


def _refresh_site_compose(domain: str) -> None:
    from .site_definition import SiteDefinition
    from .site_layout import ensure_site_scaffold

    definition = SiteDefinition.from_env(domain, read_env(env_path(domain)))
    ensure_site_scaffold(definition)


def set_basic_auth(
    domain: str,
    *,
    enabled: bool,
    username: str | None = None,
    password: str | None = None,
) -> SecurityResult:
    """Set basic auth."""
    root = _require_site(domain)
    if not isinstance(enabled, bool):
        raise TypeError("basic-auth enabled must be a boolean")

    config = load_security(domain)
    current = config["basic_auth"]
    generated_password: str | None = None
    credential_scheme: str | None = None
    htpasswd_root = root / "nginx"

    if enabled:
        if username is None:
            username = current.get("username")
        if not username or not _safe_htpasswd_username(username):
            raise ValueError("invalid username: use letters, digits, '_', '.', '@', or '-'")
        if password is None:
            from .site_layout import generated_secret
            password = generated_secret()
            generated_password = password
        if not isinstance(password, str) or not password:
            raise ValueError("basic-auth password must not be empty")
        try:
            hashed_password, credential_scheme = _htpasswd_hash(password)
        except RuntimeError as exc:
            return SecurityResult(
                3,
                f"failed to generate basic-auth credential: {exc}",
                one_time_password=generated_password,
            )
        htpasswd_content = f"{username}:{hashed_password}\n"
        htpasswd_changed = _safe_read(htpasswd_root, HTPASSWD_FILE) != htpasswd_content
        if htpasswd_changed:
            _safe_write_in_place(htpasswd_root, HTPASSWD_FILE, htpasswd_content, 0o640)
            site_uid = read_env(env_path(domain)).get("SITE_UID")
            if site_uid and os.geteuid() == 0:
                os.chown(htpasswd_root / HTPASSWD_FILE, int(site_uid), int(site_uid), follow_symlinks=False)
        desired = {"enabled": True, "username": username}
    else:
        htpasswd_changed = _safe_read(htpasswd_root, HTPASSWD_FILE) not in (None, "")
        if htpasswd_changed:
            _safe_write_in_place(htpasswd_root, HTPASSWD_FILE, "", 0o640)
        desired = {"enabled": False, "username": None}

    state_changed = current != desired
    if state_changed:
        updated = dict(config)
        updated["basic_auth"] = desired
        save_security(domain, updated)
    rendered = apply_security_runtime(domain)
    if rendered.exit_code != 0:
        return SecurityResult(
            rendered.exit_code,
            rendered.message,
            state_changed or htpasswd_changed,
            generated_password,
        )
    changed = state_changed or htpasswd_changed or rendered.changed
    if changed:
        record_event(
            "site.security.basic-auth.on" if enabled else "site.security.basic-auth.off",
            domain=domain,
            detail=(
                f"per-site basic auth enabled; credential redacted; hash scheme={credential_scheme}"
                if enabled else "per-site basic auth disabled; credential redacted"
            ),
        )
    state = "enabled" if enabled else "disabled"
    return SecurityResult(0, f"basic auth {state}" if changed else f"basic auth already {state}", changed, generated_password)


def set_cloudflare_only(domain: str, enabled: bool) -> SecurityResult:
    """Set cloudflare only."""
    if not isinstance(enabled, bool):
        raise TypeError("cloudflare-only enabled must be a boolean")
    config = load_security(domain)
    changed = config["cloudflare_only"] != enabled
    if changed:
        updated = dict(config)
        updated["cloudflare_only"] = enabled
        save_security(domain, updated)

    rendered = render_security(domain)
    if rendered.exit_code != 0:
        return rendered
    try:
        _refresh_site_compose(domain)
    except (OSError, RuntimeError, ValueError) as exc:
        return SecurityResult(3, f"failed to render Cloudflare-only edge labels: {exc}", changed)
    running = _running_web_container(domain)
    if running == "":
        return SecurityResult(
            0,
            "Cloudflare-only configuration staged; will apply when site starts",
            changed or rendered.changed,
        )
    if changed or not running or domain in _RECREATE_RETRY_REQUIRED:
        recreate_error = _recreate_web_service(domain)
    else:
        labels_match = bool(_running_web_labels(domain, running))
        recreate_error = None if labels_match else _recreate_web_service(domain)
    if recreate_error:
        _RECREATE_RETRY_REQUIRED.add(domain)
        return SecurityResult(
            3,
            f"Cloudflare-only edge labels written but not applied; web recreate failed: {recreate_error}",
            changed or rendered.changed,
        )
    _RECREATE_RETRY_REQUIRED.discard(domain)

    if changed:
        record_event(
            "site.security.cloudflare-only.on" if enabled else "site.security.cloudflare-only.off",
            domain=domain,
            detail=f"Cloudflare-only edge enforcement {'enabled' if enabled else 'disabled'}",
        )
    state = "enabled" if enabled else "disabled"
    return SecurityResult(0, f"Cloudflare-only {state}" if changed else f"Cloudflare-only already {state}", changed)


def set_login_rate_limit(domain: str, enabled: bool) -> SecurityResult:
    """Set login rate limit."""
    if not isinstance(enabled, bool):
        raise TypeError("login rate-limit enabled must be a boolean")
    config = load_security(domain)
    changed = config["login_rate_limit"] != enabled
    if changed:
        updated = dict(config)
        updated["login_rate_limit"] = enabled
        save_security(domain, updated)

    rendered = apply_security_runtime(domain)
    if rendered.exit_code != 0:
        return rendered
    try:
        _refresh_site_compose(domain)
    except (OSError, RuntimeError, ValueError) as exc:
        return SecurityResult(3, f"failed to render login rate-limit nginx mount: {exc}", changed)

    if changed:
        record_event(
            "site.security.login-rate-limit.on" if enabled else "site.security.login-rate-limit.off",
            domain=domain,
            detail=f"WordPress login rate limit {'enabled' if enabled else 'disabled'}",
        )
    state = "enabled" if enabled else "disabled"
    return SecurityResult(0, f"login rate limit {state}" if changed else f"login rate limit already {state}", changed)


def set_fail2ban(domain: str, enabled: bool) -> SecurityResult:
    """Enable or disable the per-site Login Shield (t13 lifecycle).

    Enable: validate site, take the mutation lock, ensure host fail2ban,
    install/activate the official wp-fail2ban plugin (t06 ownership), place the
    state-driven bridge (t10), render security + shared filter + per-site jail
    (hashed jail name, unique f2b-wpfy-<name> chain, WORDPRESS_JAIL policy),
    validate + reload, then run the fixture pipeline proof. The site is marked
    enabled only after the proof passes; on any failure the state is rolled
    back and ``login_shield.health_failed`` is recorded.

    Disable: disable WPFY event generation (bridge guard), deactivate the
    plugin only when WPFY owns it, remove only this site's jail references,
    keep host fail2ban and preserved admin config/logs, validate + reload.
    """
    _require_site(domain)
    if not isinstance(enabled, bool):
        raise TypeError("fail2ban enabled must be a boolean")
    with _site_mutation_lock(domain):
        if enabled:
            return _enable_login_shield(domain)
        return _disable_login_shield(domain)


def _enable_login_shield(domain: str) -> SecurityResult:
    config = load_security(domain)
    changed = config["fail2ban"] is not True

    # Host fail2ban (t08 Branch C): ensure idempotently, refuse cleanly on a
    # skipped/unhealthy ensure so no half-configured jail is ever written.
    if not fail2ban_available():
        host = ensure_fail2ban_host()
        if host.exit_code != 0:
            return SecurityResult(3, f"fail2ban host install failed: {host.message}")
        if not (host.installed and host.health_ok):
            return SecurityResult(
                3,
                "fail2ban host service is not healthy after ensure; cannot enable per-site jail",
            )

    # Plugin install/activation (t06): only in this site, ownership recorded.
    # Gated on a real transition so idempotent re-enables are no-ops; drift
    # (state enabled but plugin missing) is surfaced by login_shield_status.
    if changed:
        from .plugin_install import install_wp_fail2ban

        install = install_wp_fail2ban(domain)
        if install.exit_code != 0:
            _revert_fail2ban_state(domain)
            return SecurityResult(
                install.exit_code,
                f"login shield not enabled; wp-fail2ban plugin install refused: {install.message}",
                changed or install.changed,
            )
        # Reload after install so the recorded plugin ownership is never
        # clobbered by the pre-install snapshot.
        config = load_security(domain)

    # Per-site event-log path + state-driven bridge (t10).
    from .site_event_pipeline import ensure_event_pipeline_files

    ensure_event_pipeline_files(domain, enabled=True)

    if changed:
        updated = dict(config)
        updated["fail2ban"] = True
        save_security(domain, updated)

    rendered = render_security(domain)
    if rendered.exit_code != 0:
        _revert_fail2ban_state(domain)
        return SecurityResult(rendered.exit_code, rendered.message, changed or rendered.changed)
    skipped_domains: list[str] = []
    try:
        _refresh_site_compose(domain)
        configs_changed = _render_fail2ban_configs(
            skip_invalid=True,
            skipped_domains=skipped_domains,
        )
        recreate_error = _recreate_web_service(domain)
        if recreate_error:
            _revert_fail2ban_state(domain)
            record_event(
                "login_shield.health_failed",
                domain=domain,
                outcome="error",
                detail=f"web recreate failed: {recreate_error}",
            )
            return SecurityResult(
                3,
                f"login shield not enabled; web recreate failed: {recreate_error}",
                True,
            )
        validation_error = _validate_fail2ban()
        if validation_error:
            _revert_fail2ban_state(domain)
            record_event(
                "login_shield.health_failed",
                domain=domain,
                outcome="error",
                detail=f"config validation failed: {validation_error}",
            )
            return SecurityResult(
                3,
                f"login shield not enabled; fail2ban config validation failed: {validation_error}",
                True,
            )
        reload_error = _reload_fail2ban() if fail2ban_available() else None
        if reload_error:
            _revert_fail2ban_state(domain)
            record_event(
                "login_shield.health_failed",
                domain=domain,
                outcome="error",
                detail=f"reload failed: {reload_error}",
            )
            return SecurityResult(
                3,
                f"login shield not enabled; fail2ban reload failed: {reload_error}",
                True,
            )
    except (OSError, RuntimeError, ValueError) as exc:
        _revert_fail2ban_state(domain)
        return SecurityResult(3, f"failed to configure login shield: {exc}", changed or rendered.changed)

    # Fixture pipeline proof: event -> log -> filter -> jail. Mark enabled only
    # after it passes; the controlled fixture is appended only on a real change.
    proof_passed, proof_errors = _fixture_pipeline_proof(domain, append_event=changed)
    if not proof_passed:
        _revert_fail2ban_state(domain)
        record_event(
            "login_shield.health_failed",
            domain=domain,
            outcome="error",
            detail="fixture pipeline proof failed: " + "; ".join(proof_errors),
        )
        return SecurityResult(
            3,
            "login shield not enabled; plugin-to-log filter/jail pipeline proof failed: "
            + "; ".join(proof_errors),
            True,
        )

    jail_name = _fail2ban_jail_name(domain)
    if configs_changed:
        record_event(
            "login_shield.wordpress_fail2ban_ban",
            domain=domain,
            detail=(
                f"wpfy-wordpress jail activated for {domain}; "
                f"action=wpfy-docker-http[name={jail_name}] "
                f"chain={_fail2ban_chain_name(jail_name)} "
                f"policy=maxretry {WORDPRESS_JAIL['maxretry']}/"
                f"findtime {WORDPRESS_JAIL['findtime']}/"
                f"bantime {WORDPRESS_JAIL['bantime']}"
            ),
        )
    if changed:
        plugin = config.get("fail2ban_plugin") or {}
        record_event(
            "login_shield.enabled",
            domain=domain,
            detail=(
                f"Login Shield enabled; jail={jail_name} "
                f"chain={_fail2ban_chain_name(jail_name)} "
                f"action=wpfy-docker-http[name={jail_name}] "
                f"policy=maxretry {WORDPRESS_JAIL['maxretry']}/"
                f"findtime {WORDPRESS_JAIL['findtime']}/"
                f"bantime {WORDPRESS_JAIL['bantime']} "
                f"plugin_ownership={plugin.get('ownership') or 'none'} "
                f"fixture_proof=ok"
            ),
        )
    message = "login shield enabled" if changed else "login shield already enabled"
    if skipped_domains:
        message += f"; skipped corrupt security state for {', '.join(skipped_domains)}"
    return SecurityResult(0, message, changed or rendered.changed or configs_changed)


def _disable_login_shield(domain: str) -> SecurityResult:
    config = load_security(domain)
    changed = config["fail2ban"] is True

    # 1. Disable WPFY event generation for this site (bridge guard off).
    from .site_event_pipeline import ensure_event_pipeline_files

    ensure_event_pipeline_files(domain, enabled=False)

    # 3. Deactivate wp-fail2ban only when WPFY owns the activation (t06).
    # Gated on a real transition so idempotent re-disables are no-ops.
    deactivate_warning = ""
    if changed:
        from .plugin_install import deactivate_wp_fail2ban

        deactivated = deactivate_wp_fail2ban(domain)
        if deactivated.exit_code != 0:
            # Complete the removal regardless: the jail is gone so the site cannot
            # trigger bans, but surface the plugin problem to the operator.
            deactivate_warning = f"; plugin deactivate failed: {deactivated.message}"

    if changed:
        updated = dict(config)
        updated["fail2ban"] = False
        save_security(domain, updated)

    rendered = render_security(domain)
    if rendered.exit_code != 0:
        return SecurityResult(rendered.exit_code, rendered.message, changed or rendered.changed)
    skipped_domains: list[str] = []
    try:
        _refresh_site_compose(domain)
        configs_changed = _render_fail2ban_configs(
            skip_invalid=True,
            skipped_domains=skipped_domains,
        )
        reload_error = _reload_fail2ban() if fail2ban_available() else None
        if reload_error:
            record_event(
                "login_shield.health_failed",
                domain=domain,
                outcome="error",
                detail=f"reload failed during disable: {reload_error}",
            )
            return SecurityResult(3, f"login shield disabled but fail2ban reload failed: {reload_error}", True)
    except (OSError, RuntimeError, ValueError) as exc:
        return SecurityResult(3, f"failed to disable login shield: {exc}", changed or rendered.changed)

    if changed:
        plugin = config.get("fail2ban_plugin") or {}
        detail = (
            f"Login Shield disabled; jail={_fail2ban_jail_name(domain)} removed; "
            f"plugin_ownership={plugin.get('ownership') or 'none'}; "
            "host fail2ban kept; admin config and logs preserved"
        )
        if deactivate_warning:
            detail += deactivate_warning
        record_event("login_shield.disabled", domain=domain, detail=detail)
    message = "login shield disabled" if changed else "login shield already disabled"
    if skipped_domains:
        message += f"; skipped corrupt security state for {', '.join(skipped_domains)}"
    if deactivate_warning:
        message += deactivate_warning
    return SecurityResult(0, message, changed or rendered.changed or configs_changed)


def _fail2ban_chain_name(jail_name: str) -> str:
    from .fail2ban_docker import CHAIN_PREFIX

    return f"{CHAIN_PREFIX}{jail_name}"


def _trusted_proxy_health() -> str:
    """Report whether the edge trust source for real-IP resolution is usable."""
    try:
        sources = _edge_network_cidrs()
    except RuntimeError as exc:
        return f"edge-trust-unavailable: {exc}"
    return "edge-trust-configured" if sources else "edge-trust-missing"


def _config_validation_status() -> str:
    if os.environ.get("WPFY_SKIP_RUNTIME") == "1" or not fail2ban_available():
        return "not-validated-runtime-skipped"
    try:
        proc = subprocess.run(["fail2ban-client", "-t"], check=False, capture_output=True, text=True, timeout=_SUBPROCESS_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        return "invalid"
    return "valid" if proc.returncode == 0 else "invalid"


def _jail_active(domain: str) -> bool:
    try:
        jail_text = fail2ban_jail_path().read_text(encoding="utf-8")
    except OSError:
        return False
    jail_name = _fail2ban_jail_name(domain)
    section = re.search(rf"\[{re.escape(jail_name)}\](.*?)(?=\n\[|\Z)", jail_text, re.DOTALL)
    if section is None:
        return False
    return "enabled = true" in section.group(1) and f"action = wpfy-docker-http[name={jail_name}]" in section.group(1)


def login_shield_status(domain: str) -> dict:
    """Structured per-site Login Shield status (consumed by the CLI/panel at t15).

    Runtime probes (ping, config validation, iptables enforcement) are guarded
    by WPFY_SKIP_RUNTIME and binary availability; fixture-level facts (state,
    jail file, event log) are always reported. The ban-scope disclosure is part
    of this surface so operators never see a jail without the server-wide
    consequence.
    """
    validate_domain(domain)
    config = load_security(domain)
    plugin = dict(config.get("fail2ban_plugin") or {})
    enabled = config["fail2ban"] is True
    jail_name = _fail2ban_jail_name(domain)
    log = wp_auth_log_path(domain)

    # t16 W8: report the plugin's LIVE wp-cli state when the site is enabled
    # and runtime is available, so an out-of-band deactivation is never
    # reported as active. Under WPFY_SKIP_RUNTIME (or a failed probe) the
    # recorded flag is reported with source=recorded (bounded staleness).
    plugin_active_source = "recorded"
    if enabled:
        try:
            from .plugin_install import plugin_live_state

            live = plugin_live_state(domain)
        except (OSError, TypeError, ValueError):
            live = None
        if live is not None:
            plugin["active"] = bool(live.get("active"))
            if live.get("version"):
                plugin["version"] = live["version"]
            plugin_active_source = "live"

    last_failure: str | None = None
    matched_failures = 0
    try:
        lines = log.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        lines = []
    for line in reversed(lines):
        if "wordpress_auth_failure" not in line:
            continue
        matched_failures += 1
        if matched_failures > 1000:
            break
    for line in reversed(lines):
        if "wordpress_auth_failure" not in line:
            continue
        try:
            payload = json.loads(line)
            last_failure = payload.get("timestamp") or payload.get("surface") or "detected"
        except (TypeError, ValueError):
            last_failure = "detected"
        break

    from .fail2ban_docker import enforcement_status

    enforcement = enforcement_status(chain=_fail2ban_chain_name(jail_name))
    currently_banned, total_banned = _recent_bans(jail_name)

    health_reasons: list[str] = []
    if enforcement.action_stale:
        health_reasons.append(enforcement.degraded_reason or "action stale; re-render required")
    if enabled and not enforcement.ipv4_active:
        health_reasons.append("IPv4 enforcement not active")
    if enabled and not _jail_active(domain):
        health_reasons.append("jail not active")
    if enabled and plugin_active_source == "live" and not plugin.get("active"):
        health_reasons.append("wp-fail2ban plugin not active (live wp-cli probe)")
    health = "degraded" if health_reasons else ("ok" if enabled else "disabled")
    # Surface the plugin liveness reason in degraded_reason too, so an
    # operator reading the existing field sees why health is degraded.
    plugin_reason = next(
        (reason for reason in health_reasons if reason.startswith("wp-fail2ban plugin")),
        None,
    )
    degraded_reason = enforcement.degraded_reason or None
    if plugin_reason:
        degraded_reason = (
            f"{degraded_reason}; {plugin_reason}" if degraded_reason else plugin_reason
        )

    return {
        "site": domain,
        "enabled": enabled,
        "plugin": plugin,
        "plugin_active_source": plugin_active_source,
        "host_fail2ban_installed": fail2ban_available(),
        "host_fail2ban_health": _fail2ban_ping() or "unknown",
        "jail_name": jail_name,
        "jail_active": enabled and _jail_active(domain),
        "event_log_path": str(log),
        "event_log_health": "ok" if log.is_file() else "missing",
        "filter_name": FAIL2BAN_FILTER_NAME,
        "last_detected_failure": last_failure,
        "recent_matched_failures": matched_failures,
        "recent_bans": currently_banned,
        "total_bans": total_banned,
        "ban_scope": BAN_SCOPE_MESSAGE,
        "trusted_proxy_health": _trusted_proxy_health(),
        "ipv4_protection": bool(enforcement.ipv4_active),
        "ipv6_protection": bool(enforcement.ipv6_active),
        "config_validation": _config_validation_status(),
        "wpfy_chain_attached": bool(enforcement.wpfy_chain_attached),
        "action_stale": bool(enforcement.action_stale),
        "degraded_reason": degraded_reason,
        "health": health,
    }


def repair_login_shield(domain: str) -> SecurityResult:
    """Idempotent repair: restore missing WPFY-managed fail2ban config files
    for an enabled site without re-installing the plugin or recreating state.

    Emits ``login_shield.repaired`` when something was restored.
    """
    _require_site(domain)
    with _site_mutation_lock(domain):
        config = load_security(domain)
        if config["fail2ban"] is not True:
            return SecurityResult(0, "login shield disabled; nothing to repair")
        missing: list[str] = []
        for label, path in (
            ("jail file", fail2ban_jail_path()),
            ("wordpress filter", fail2ban_filter_path()),
        ):
            if not path.exists():
                missing.append(label)
        if not missing:
            return SecurityResult(0, "login shield integration intact")
        try:
            _render_fail2ban_configs(skip_invalid=True)
        except (OSError, RuntimeError, ValueError) as exc:
            return SecurityResult(3, f"login shield repair failed: {exc}")
        reload_error = _reload_fail2ban() if fail2ban_available() else None
        if reload_error:
            record_event(
                "login_shield.health_failed",
                domain=domain,
                outcome="error",
                detail=f"repair reload failed: {reload_error}",
            )
            return SecurityResult(3, f"login shield repair failed; reload: {reload_error}")
        record_event(
            "login_shield.repaired",
            domain=domain,
            detail=f"restored missing {', '.join(missing)}",
        )
        return SecurityResult(0, f"login shield repaired: restored {', '.join(missing)}", True)


def _recent_bans(jail_name: str) -> tuple[int | None, int | None]:
    """Return (currently_banned, total_banned) from fail2ban-client status.

    Runtime-guarded; returns (None, None) when the service cannot be probed
    so the CLI can render "unknown" instead of a misleading zero.
    """
    if os.environ.get("WPFY_SKIP_RUNTIME") == "1" or not fail2ban_available():
        return None, None
    try:
        proc = subprocess.run(
            ["fail2ban-client", "status", jail_name],
            check=False,
            capture_output=True,
            text=True,
            timeout=_SUBPROCESS_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return None, None
    if proc.returncode != 0:
        return None, None
    currently: int | None = None
    total: int | None = None
    for line in proc.stdout.splitlines():
        stripped = line.strip()
        if "Currently banned:" in stripped:
            value = stripped.split(":", 1)[1].strip()
            with contextlib.suppress(ValueError):
                currently = int(value)
        elif "Total banned:" in stripped:
            value = stripped.split(":", 1)[1].strip()
            with contextlib.suppress(ValueError):
                total = int(value)
    return currently, total


def _valid_banned_ip(token: str) -> bool:
    """True when *token* parses as an IP address (IPv4 or IPv6)."""
    try:
        ipaddress.ip_address(token)
    except ValueError:
        return False
    return True


def _clear_jail_bans(jail_name: str) -> int:
    """Clear currently banned IPs for one WPFY jail via fail2ban-client.

    Returns the number of IPs unbanned. Runtime-guarded; a jail that is not
    loaded (or a skipped runtime) reports zero bans to clear. The exact unban
    command is the documented one (architecture section 12): ``fail2ban-client
    set <jail> unbanip <ip>`` per currently-banned address.

    t16 W4: the parse is colon-safe. IPv6 addresses contain ``:``, so the
    banned list is terminated only by an empty line or a line that does not
    begin with a valid IP — never by the presence of a colon.
    """
    if os.environ.get("WPFY_SKIP_RUNTIME") == "1" or not fail2ban_available():
        return 0
    try:
        proc = subprocess.run(
            ["fail2ban-client", "status", jail_name],
            check=False,
            capture_output=True,
            text=True,
            timeout=_SUBPROCESS_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return 0
    if proc.returncode != 0:
        return 0
    banned: list[str] = []
    in_list = False
    for line in proc.stdout.splitlines():
        stripped = line.strip()
        if "Banned IP list:" in stripped:
            in_list = True
            rest = stripped.split(":", 1)[1].strip()
            banned.extend(token for token in rest.split() if _valid_banned_ip(token))
            continue
        if in_list:
            tokens = stripped.split()
            if not tokens or not _valid_banned_ip(tokens[0]):
                # End of the banned list: empty line or the next status field
                # (counts never look like an IP). Colon is NOT a terminator.
                break
            banned.extend(token for token in tokens if _valid_banned_ip(token))
    cleared = 0
    for ip in banned:
        try:
            unban = subprocess.run(
                ["fail2ban-client", "set", jail_name, "unbanip", ip],
                check=False,
                capture_output=True,
                text=True,
                timeout=_SUBPROCESS_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            continue
        if unban.returncode == 0:
            cleared += 1
    return cleared


def reset_login_shield(domain: str) -> SecurityResult:
    """Per-site Login Shield reset: clear active WPFY jail bans for this site
    and rebuild WPFY-managed fail2ban config (render, validate, reload).

    Never permanently disables protection: the site stays enabled and its jail
    is re-rendered, not removed. Bounded to this site's jail (other jails are
    untouched) and repair-safe (validate + reload, failure surfaced, no state
    change). Requires local privileged CLI access, enforced by the CLI layer.
    """
    _require_site(domain)
    with _site_mutation_lock(domain):
        config = load_security(domain)
        if config["fail2ban"] is not True:
            return SecurityResult(0, "login shield disabled; nothing to reset")
        jail_name = _fail2ban_jail_name(domain)
        cleared = _clear_jail_bans(jail_name)
        try:
            rendered = render_security(domain)
            if rendered.exit_code != 0:
                return SecurityResult(rendered.exit_code, rendered.message, True)
            _refresh_site_compose(domain)
            _render_fail2ban_configs(skip_invalid=True)
        except (OSError, RuntimeError, ValueError) as exc:
            return SecurityResult(3, f"failed to rebuild fail2ban config: {exc}", True)
        validation_error = _validate_fail2ban()
        if validation_error:
            record_event(
                "login_shield.health_failed",
                domain=domain,
                outcome="error",
                detail=f"reset validate failed: {validation_error}",
            )
            return SecurityResult(
                3,
                f"login shield reset failed; config validation: {validation_error}",
                True,
            )
        reload_error = _reload_fail2ban() if fail2ban_available() else None
        if reload_error:
            record_event(
                "login_shield.health_failed",
                domain=domain,
                outcome="error",
                detail=f"reset reload failed: {reload_error}",
            )
            return SecurityResult(
                3,
                f"login shield reset failed; reload: {reload_error}",
                True,
            )
        if cleared:
            return SecurityResult(
                0,
                f"login shield reset: cleared {cleared} ban(s), rebuilt config",
                True,
            )
        return SecurityResult(0, "login shield reset: no active bans; rebuilt config", True)


def unban_fail2ban(ip: str) -> SecurityResult:
    """Host-level unban: remove *ip* from every WPFY jail (panel + per-site).

    Validates the address, targets only WPFY-owned jails, and records
    ``login_shield.unban`` when at least one jail released the address.
    Requires local privileged CLI access, enforced by the CLI layer.
    """
    try:
        ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return SecurityResult(2, f"invalid IP address: {ip}")
    if os.environ.get("WPFY_SKIP_RUNTIME") == "1" or not fail2ban_available():
        return SecurityResult(0, f"fail2ban unban skipped by WPFY_SKIP_RUNTIME for {ip}")
    domains = _enabled_fail2ban_domains(skip_invalid=True)
    jails = ["wpfy-panel-auth", *(_fail2ban_jail_name(domain) for domain in domains)]
    unbanned: list[str] = []
    for jail in jails:
        try:
            proc = subprocess.run(
                ["fail2ban-client", "set", jail, "unbanip", ip],
                check=False,
                capture_output=True,
                text=True,
                timeout=_SUBPROCESS_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            continue
        if proc.returncode == 0:
            unbanned.append(jail)
    if not unbanned:
        return SecurityResult(0, f"{ip} was not banned in any WPFY jail")
    record_event(
        "login_shield.unban",
        detail=f"unbanned {ip} from {', '.join(unbanned)}",
    )
    return SecurityResult(0, f"unbanned {ip} from {', '.join(unbanned)}", changed=True)


def repair_host_login_shield() -> SecurityResult:
    """Host-level repair: idempotent host ensure (config re-render, validate,
    reload with rollback) plus explicit validate/reload verification.

    Emits ``login_shield.repaired`` on success and ``login_shield.health_failed``
    when validation or reload fails after ensure.
    """
    from .fail2ban_host import ensure_fail2ban_host

    host = ensure_fail2ban_host()
    if host.exit_code != 0:
        return SecurityResult(host.exit_code, f"fail2ban host repair failed: {host.message}")
    validation_error = _validate_fail2ban()
    if validation_error:
        record_event(
            "login_shield.health_failed",
            outcome="error",
            detail=f"host repair validate failed: {validation_error}",
        )
        return SecurityResult(
            3,
            f"fail2ban host repair failed; config validation: {validation_error}",
        )
    reload_error = _reload_fail2ban()
    if reload_error:
        record_event(
            "login_shield.health_failed",
            outcome="error",
            detail=f"host repair reload failed: {reload_error}",
        )
        return SecurityResult(3, f"fail2ban host repair failed; reload: {reload_error}")
    detail = f"host fail2ban repaired; {host.message}"
    record_event("login_shield.repaired", detail=detail)
    return SecurityResult(0, detail, changed=host.changed)


def _panel_fixture_record() -> str:
    """Controlled panel-auth fixture record (TEST-NET-3 client, fixed shape)."""
    return json.dumps({
        "timestamp": _WP_FIXTURE_TIMESTAMP,
        "event": "panel_auth_failure",
        "surface": "password",
        "client_ip": _WP_FIXTURE_IP,
        "account_hash": "sha256:" + _WP_FIXTURE_ACCOUNT_HASH,
        "reason_class": "invalid_credentials",
    }, ensure_ascii=True, separators=(",", ":"))


def test_host_login_shield() -> SecurityResult:
    """Host-level fixture test: controlled events -> filter/jail match.

    Verifies (fixture-level, no real ban): the strict panel and WordPress auth
    regexes match their controlled records and extract the fixture client; the
    panel jail content is active with the WPFY Docker action over
    panel-auth.log; and fail2ban validates (runtime-guarded). A live
    wrong-password-to-DOCKER-USER run happens at t21.
    """
    from .fail2ban_host import (
        PANEL_JAIL_ACTION,
        panel_failregex,
        panel_jail_content,
        wordpress_auth_failregex,
    )

    errors: list[str] = []
    checked: list[str] = []

    panel_record = _panel_fixture_record()
    try:
        panel_compiled = re.compile(panel_failregex(), re.MULTILINE | re.DOTALL)
    except re.error as exc:
        errors.append(f"panel filter regex invalid: {exc}")
    else:
        match = panel_compiled.match(panel_record)
        if match is None or extract_failure_id(match) != _WP_FIXTURE_IP:
            errors.append("panel filter did not match the controlled panel fixture")
        else:
            checked.append("panel filter matched controlled panel_auth_failure record")

    wp_record = _wp_fixture_record("host-test.example")
    try:
        wp_compiled = re.compile(wordpress_auth_failregex(), re.MULTILINE | re.DOTALL)
    except re.error as exc:
        errors.append(f"wordpress auth filter regex invalid: {exc}")
    else:
        match = wp_compiled.match(wp_record)
        if match is None or extract_failure_id(match) != _WP_FIXTURE_IP:
            errors.append("wordpress auth filter did not match the controlled WP fixture")
        else:
            checked.append("wordpress auth filter matched controlled wordpress_auth_failure record")

    jail = panel_jail_content()
    if (
        "enabled = true" not in jail
        or PANEL_JAIL_ACTION not in jail
        or "panel-auth.log" not in jail
    ):
        errors.append(
            "panel jail content is not active with the WPFY Docker action over panel-auth.log"
        )
    else:
        checked.append("panel jail active with wpfy-docker-http action and panel-auth.log")

    validation_error = _validate_fail2ban()
    if validation_error:
        errors.append(f"fail2ban config validation failed: {validation_error}")
    else:
        checked.append("fail2ban config validation passed (or runtime skipped)")

    if errors:
        return SecurityResult(3, "login shield test failed: " + "; ".join(errors))
    return SecurityResult(0, "login shield test passed: " + "; ".join(checked))


def host_fail2ban_status() -> dict:
    """Structured host-level Login Shield status (shared fail2ban service).

    Mirrors ``login_shield_status``'s field set; the relevant jail is the
    panel jail (``wpfy-panel-auth``) and the event log is the panel auth log.
    WP plugin fields do not apply at host level and are reported empty. The
    ban-scope disclosure is included so operators never see a jail without the
    server-wide consequence.
    """
    from .fail2ban_docker import enforcement_status
    from .fail2ban_host import PANEL_JAIL_ACTION, PANEL_JAIL_CHAIN
    from .panel_auth import panel_auth_log_path

    jail_name = "wpfy-panel-auth"
    chain = PANEL_JAIL_CHAIN
    log = panel_auth_log_path()

    last_failure: str | None = None
    matched_failures = 0
    try:
        lines = log.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        lines = []
    for line in reversed(lines):
        if "panel_auth_failure" not in line:
            continue
        matched_failures += 1
        if matched_failures > 1000:
            break
    for line in reversed(lines):
        if "panel_auth_failure" not in line:
            continue
        try:
            payload = json.loads(line)
            last_failure = payload.get("timestamp") or payload.get("surface") or "detected"
        except (TypeError, ValueError):
            last_failure = "detected"
        break

    enforcement = enforcement_status(chain=chain)
    currently_banned, total_banned = _recent_bans(jail_name)

    jail_file = _fail2ban_root() / "jail.d" / "wpfy-panel-auth.local"
    try:
        jail_text = jail_file.read_text(encoding="utf-8")
    except OSError:
        jail_text = ""
    jail_active = "enabled = true" in jail_text and PANEL_JAIL_ACTION in jail_text

    health_reasons: list[str] = []
    if enforcement.action_stale:
        health_reasons.append(enforcement.degraded_reason or "action stale; re-render required")
    if not enforcement.ipv4_active:
        health_reasons.append("IPv4 enforcement not active")
    if not jail_active:
        health_reasons.append("panel jail not active")
    health = "degraded" if health_reasons else "ok"

    return {
        "site": None,
        "enabled": jail_active,
        "plugin": {},
        "host_fail2ban_installed": fail2ban_available(),
        "host_fail2ban_health": _fail2ban_ping() or "unknown",
        "jail_name": jail_name,
        "jail_active": jail_active,
        "event_log_path": str(log),
        "event_log_health": "ok" if log.is_file() else "missing",
        "filter_name": "wpfy-panel-auth",
        "last_detected_failure": last_failure,
        "recent_matched_failures": matched_failures,
        "recent_bans": currently_banned,
        "total_bans": total_banned,
        "ban_scope": BAN_SCOPE_MESSAGE,
        "trusted_proxy_health": _trusted_proxy_health(),
        "ipv4_protection": bool(enforcement.ipv4_active),
        "ipv6_protection": bool(enforcement.ipv6_active),
        "config_validation": _config_validation_status(),
        "wpfy_chain_attached": bool(enforcement.wpfy_chain_attached),
        "action_stale": bool(enforcement.action_stale),
        "degraded_reason": enforcement.degraded_reason or None,
        "health": health,
    }


def security_preflight(domain: str, change: dict) -> SecurityPreflightResult:
    """Security preflight."""
    _require_site(domain)
    if not isinstance(change, dict):
        raise TypeError("security change must be an object")
    warnings: list[str] = []
    if change.get("cloudflare_only") is True:
        a_records, aaaa_records = resolve_domain_ips(domain)
        resolved = a_records + aaaa_records
        if not cloudflare_ranges.ips_are_cloudflare(resolved):
            records = ", ".join(resolved) if resolved else "no A or AAAA records"
            warnings.append(
                "Cloudflare-only would block this site because its DNS is not fully proxied through Cloudflare "
                f"({records}); enable the Cloudflare proxy first or use --force to accept the lockout risk."
            )
    return SecurityPreflightResult(tuple(warnings))
