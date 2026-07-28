from __future__ import annotations

import base64
from dataclasses import dataclass
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

from . import cloudflare_ranges
from .certificate_lifecycle import resolve_domain_ips
from .events import record_event
from .site_paths import env_path, read_env, site_dir, site_exists, validate_domain
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
_SAFE_HTPASSWD_USERNAME_RE = re.compile(r"[A-Za-z0-9_.@-]+")
_SAFE_UA_PATTERN_RE = re.compile(r"[A-Za-z0-9 ._/@:+*?^$|()\[\]-]{1,256}")
_DEFAULT_SECURITY = {
    "basic_auth": {"enabled": False, "username": None},
    "cloudflare_only": False,
    "login_rate_limit": False,
    "fail2ban": False,
    "deny_ips": [],
    "ua_blocks": [],
}


@dataclass(frozen=True, slots=True)
class SecurityResult:
    exit_code: int
    message: str
    changed: bool = False
    one_time_password: str | None = None


@dataclass(frozen=True, slots=True)
class SecurityPreflightResult:
    warnings: tuple[str, ...] = ()


def _require_site(domain: str) -> Path:
    validate_domain(domain)
    if not site_exists(domain):
        raise FileNotFoundError(f"site not found: {domain}")
    return site_dir(domain)


def access_log_path(domain: str) -> Path:
    validate_domain(domain)
    root = Path(_current_paths().sites_dir) / domain
    if not root.is_dir():
        raise FileNotFoundError(f"site not found: {domain}")
    return root / "nginx" / ACCESS_LOG_FILE


def _current_paths():
    from .settings import PATHS as current_paths

    return current_paths


def _fail2ban_root() -> Path:
    # Wpfy keeps its own configuration in /etc/wpfy; fail2ban and logrotate use
    # sibling system directories. Tests redirect WPFY_CONFIG_DIR and stay isolated.
    return Path(_current_paths().config_dir).parent / "fail2ban"


def fail2ban_filter_path() -> Path:
    return _fail2ban_root() / "filter.d" / FAIL2BAN_FILTER_FILE


def fail2ban_jail_path() -> Path:
    return _fail2ban_root() / "jail.d" / FAIL2BAN_JAIL_FILE


def _logrotate_path(domain: str) -> Path:
    validate_domain(domain)
    digest = hashlib.sha256(domain.encode("utf-8")).hexdigest()[:16]
    return Path(_current_paths().config_dir).parent / "logrotate.d" / f"wpfy-{digest}"


def fail2ban_available() -> bool:
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
        try:
            metadata = os.stat(target, dir_fd=root_fd, follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                raise OSError(f"managed security config is a symlink: {target}")
        except FileNotFoundError:
            pass
        os.replace(replacement, target, src_dir_fd=root_fd, dst_dir_fd=root_fd)
    finally:
        os.close(root_fd)


def _cleanup(root: Path, name: str) -> None:
    try:
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.unlink(name, dir_fd=root_fd)
        except FileNotFoundError:
            pass
        finally:
            os.close(root_fd)
    except OSError:
        pass


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
    root = _require_site(domain)
    content = _safe_read(root, SECURITY_STATE)
    if content is None:
        return _validated_config(dict(_DEFAULT_SECURITY))
    return _decode_config(content)


def save_security(domain: str, config: dict) -> None:
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
    return "\n".join((
        "# Generated by wpfy. Matches the combined-format access log it renders.",
        "[Definition]",
        "datepattern = {NONE}",
        'failregex = ^<HOST> \\S+ \\S+ \\[[^]]+\\] "POST /wp-login\\.php(?:\\?[^ ]*)? HTTP/\\d\\.\\d" (?:200|401|403) \\d+',
        "ignoreregex =",
        "",
    ))


def _enabled_fail2ban_domains(
    *, skip_invalid: bool = False, skipped_domains: list[str] | None = None
) -> tuple[str, ...]:
    sites_root = Path(_current_paths().sites_dir)
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
    return f"wpfy-{hashlib.sha256(domain.encode('utf-8')).hexdigest()[:16]}"


def _fail2ban_jail_content(domains: tuple[str, ...]) -> str:
    lines = ["# Generated by wpfy. Per-site jails; do not edit."]
    for domain in domains:
        jail_name = _fail2ban_jail_name(domain)
        lines.extend((
            "",
            f"[{jail_name}]",
            "enabled = true",
            f"filter = {FAIL2BAN_FILTER_NAME}",
            f"logpath = {access_log_path(domain)}",
            "backend = auto",
            "maxretry = 5",
            "findtime = 10m",
            "bantime = 1h",
            (
                f'action = iptables-multiport[name={jail_name}, port="http,https", '
                "protocol=tcp, chain=DOCKER-USER]"
            ),
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
        filter_removed = _remove_global_file(filter_path)
        jail_removed = _remove_global_file(jail_path)
        return filter_removed or jail_removed
    filter_changed = _install_global_text(filter_path, _fail2ban_filter_content())
    jail_changed = _install_global_text(jail_path, _fail2ban_jail_content(domains))
    return filter_changed or jail_changed


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
    proc = subprocess.run(["fail2ban-client", "reload"], check=False, capture_output=True, text=True)
    if proc.returncode == 0:
        return None
    return proc.stderr.strip() or proc.stdout.strip() or "fail2ban-client reload failed"


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


def _edge_network_cidrs() -> tuple[str, ...]:
    if os.environ.get("WPFY_SKIP_RUNTIME") == "1" and not os.environ.get("WPFY_TEST_TRAEFIK_NETWORK_CIDRS"):
        raise RuntimeError("wpfy edge network discovery skipped by WPFY_SKIP_RUNTIME")
    return traefik_network_cidrs()


def _forwarded_scheme_content(trusted_sources: tuple[str, ...]) -> str:
    lines = [
        "# Generated by wpfy. Trust forwarded scheme only from the shared edge network.",
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
    root = _require_site(domain) / "nginx"
    try:
        trusted_sources = _edge_network_cidrs()
    except RuntimeError:
        # Fail closed when runtime discovery is unavailable: no forwarded header
        # can assert HTTPS until a later refresh discovers the real edge CIDR.
        trusted_sources = ("127.0.0.1/32",)
    try:
        changed = _install_text(
            root,
            FORWARDED_SCHEME_SNIPPET,
            _forwarded_scheme_content(trusted_sources),
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
    root = _require_site(domain)
    try:
        state_content = _safe_read(root, SECURITY_STATE)
        config = _validated_config(dict(_DEFAULT_SECURITY)) if state_content is None else _decode_config(state_content)
        rotation_changed = _configure_access_log_rotation(domain)
        content, trust_error = _security_snippet(domain, config)
        changed = _install_text(root / "nginx" / "extra", SECURITY_SNIPPET, content, 0o644)
        changed = changed or rotation_changed
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
    rendered = render_security(domain)
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
    return SecurityResult(0, f"{action} rule {state}", changed or rendered.changed)


def add_deny_ip(domain: str, cidr: str) -> SecurityResult:
    return _update_list(domain, "deny_ips", cidr, remove=False)


def remove_deny_ip(domain: str, cidr: str) -> SecurityResult:
    return _update_list(domain, "deny_ips", cidr, remove=True)


def add_ua_block(domain: str, pattern: str) -> SecurityResult:
    return _update_list(domain, "ua_blocks", pattern, remove=False)


def remove_ua_block(domain: str, pattern: str) -> SecurityResult:
    return _update_list(domain, "ua_blocks", pattern, remove=True)


def _safe_htpasswd_username(value: str) -> bool:
    return isinstance(value, str) and bool(_SAFE_HTPASSWD_USERNAME_RE.fullmatch(value))


def _htpasswd_sha(password: str) -> str:
    digest = hashlib.sha1(password.encode("utf-8")).digest()
    return "{SHA}" + base64.b64encode(digest).decode("ascii")


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
    root = _require_site(domain)
    if not isinstance(enabled, bool):
        raise TypeError("basic-auth enabled must be a boolean")

    config = load_security(domain)
    current = config["basic_auth"]
    generated_password: str | None = None
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
        htpasswd_content = f"{username}:{_htpasswd_sha(password)}\n"
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
    rendered = render_security(domain)
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
            detail=f"per-site basic auth {'enabled' if enabled else 'disabled'}; credential redacted",
        )
    state = "enabled" if enabled else "disabled"
    return SecurityResult(0, f"basic auth {state}" if changed else f"basic auth already {state}", changed, generated_password)


def set_cloudflare_only(domain: str, enabled: bool) -> SecurityResult:
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

    if changed:
        record_event(
            "site.security.cloudflare-only.on" if enabled else "site.security.cloudflare-only.off",
            domain=domain,
            detail=f"Cloudflare-only edge enforcement {'enabled' if enabled else 'disabled'}",
        )
    state = "enabled" if enabled else "disabled"
    return SecurityResult(0, f"Cloudflare-only {state}" if changed else f"Cloudflare-only already {state}", changed)


def set_login_rate_limit(domain: str, enabled: bool) -> SecurityResult:
    if not isinstance(enabled, bool):
        raise TypeError("login rate-limit enabled must be a boolean")
    config = load_security(domain)
    changed = config["login_rate_limit"] != enabled
    if changed:
        updated = dict(config)
        updated["login_rate_limit"] = enabled
        save_security(domain, updated)

    rendered = render_security(domain)
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
    _require_site(domain)
    if not isinstance(enabled, bool):
        raise TypeError("fail2ban enabled must be a boolean")
    if enabled and not fail2ban_available():
        return SecurityResult(3, "fail2ban is not installed; install fail2ban before enabling this jail")

    config = load_security(domain)
    changed = config["fail2ban"] != enabled
    if changed:
        updated = dict(config)
        updated["fail2ban"] = enabled
        save_security(domain, updated)

    rendered = render_security(domain)
    if rendered.exit_code != 0:
        return SecurityResult(rendered.exit_code, rendered.message, changed or rendered.changed)
    skipped_domains: list[str] = []
    try:
        _refresh_site_compose(domain)
        configs_changed = _render_fail2ban_configs(
            skip_invalid=not enabled,
            skipped_domains=skipped_domains,
        )
        recreate_error = _recreate_web_service(domain) if enabled else None
        if recreate_error:
            return SecurityResult(3, f"fail2ban configuration changed but web recreate failed: {recreate_error}", True)
        reload_error = _reload_fail2ban() if fail2ban_available() else None
    except (OSError, RuntimeError, ValueError) as exc:
        return SecurityResult(3, f"failed to configure fail2ban: {exc}", changed or rendered.changed)
    if reload_error:
        return SecurityResult(3, f"fail2ban configuration changed but reload failed: {reload_error}", True)

    if changed:
        record_event(
            "site.security.fail2ban.on" if enabled else "site.security.fail2ban.off",
            domain=domain,
            detail=f"per-site fail2ban jail {'enabled' if enabled else 'disabled'}",
        )
    state = "enabled" if enabled else "disabled"
    message = f"fail2ban {state}" if changed else f"fail2ban already {state}"
    if skipped_domains:
        message += f"; skipped corrupt security state for {', '.join(skipped_domains)}"
    return SecurityResult(0, message, changed or rendered.changed or configs_changed)


def security_preflight(domain: str, change: dict) -> SecurityPreflightResult:
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
