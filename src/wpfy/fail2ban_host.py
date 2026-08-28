from __future__ import annotations

from dataclasses import dataclass
import contextlib
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import time

from .events import record_event
from .settings import current_paths


# ---------------------------------------------------------------------------
# Policy constants — imported by later Login Shield modules.
# ---------------------------------------------------------------------------

# Panel authentication jail: protects wpfy panel login surface.
PANEL_JAIL: dict[str, str] = {
    "findtime": "10m",
    "maxretry": "8",
    "bantime": "15m",
}

# WordPress login jail: protects wp-login.php across enabled sites.
WORDPRESS_JAIL: dict[str, str] = {
    "findtime": "10m",
    "maxretry": "5",
    "bantime": "1h",
}

# Safe loopback allowlist — never ban these addresses.
SAFE_ALLOWLIST: tuple[str, ...] = ("127.0.0.0/8", "::1")

# Incremental-ban cap: bantime may escalate on repeat offences in later
# phases, but must never exceed this ceiling without explicit operator action.
INCREMENTAL_BAN_CAP: str = "24h"

# Panel auth jail wiring: the WPFY Docker action renders f2b-wpfy-<name> and
# this jail instantiates it with name=panel-auth, yielding the unique chain
# f2b-wpfy-panel-auth. Single source for the action line + chain name.
PANEL_JAIL_ACTION = "wpfy-docker-http[name=panel-auth]"
PANEL_JAIL_CHAIN = "f2b-wpfy-panel-auth"
PANEL_AUTH_LOG_FILENAME = "panel-auth.log"

# Header written into every WPFY-owned fail2ban config file.
_MANAGED_HEADER = "# Managed by WPFY. Manual changes may be overwritten."

# Subprocess timeout for apt-get / systemctl / fail2ban-client calls.
_SUBPROCESS_TIMEOUT = 120

# fail2ban >=1.0 requires every failregex to carry a failure-id named group
# (server/failregex.py FAILURE_ID_GROUPS). A legacy ``(?P<host>...)`` group
# raises RegexException at jail start (t20 blocker). The WPFY strict JSONL
# filters expose ip4/ip6; ``<HOST>`` in the nginx backstop expands to those
# groups at filter load.
FAILURE_ID_GROUPS = frozenset({"fid", "ip4", "ip6", "dns"})


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class HostFail2banResult:
    exit_code: int
    message: str
    changed: bool = False
    installed: bool = False
    health_ok: bool = False


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def extract_failure_id(match: re.Match) -> str:
    """Extract the ban target from a fail2ban 1.0 match.

    fail2ban >=1.0 reads ip4/ip6/dns/fid named groups, never ``host``. The
    WPFY strict JSONL filters populate exactly one of ip4/ip6 per match.
    """
    for name in ("ip4", "ip6", "dns", "fid"):
        value = match.group(name)
        if value is not None:
            return value
    raise ValueError(f"match carries no failure-id group value: {match.re.pattern!r}")


def _fail2ban_root() -> Path:
    """Derive fail2ban config root from WPFY_CONFIG_DIR (same as site_security)."""
    return Path(current_paths().config_dir).parent / "fail2ban"


def _runtime_skip_requested() -> bool:
    return os.environ.get("WPFY_SKIP_RUNTIME") == "1"


def _fail2ban_installed() -> bool:
    """Return True when the fail2ban-client binary is on PATH."""
    return shutil.which("fail2ban-client") is not None


def _install_package() -> tuple[bool, str]:
    """Install fail2ban via apt-get. Returns (success, message)."""
    if _runtime_skip_requested():
        return False, "skipped by WPFY_SKIP_RUNTIME"
    env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
    try:
        proc = subprocess.run(
            [
                "apt-get",
                "-o",
                "DPkg::Lock::Timeout=300",
                "install",
                "-y",
                "fail2ban",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=_SUBPROCESS_TIMEOUT,
            env=env,
        )
    except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired) as exc:
        return False, f"apt-get failed: {exc}"
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or "apt-get returned non-zero"
        return False, f"apt-get install fail2ban failed: {detail}"
    return True, "fail2ban package installed"


def _apt_update() -> tuple[bool, str]:
    """Refresh apt lists before install so fresh hosts are not stale.

    Waits on a concurrent dpkg/apt lock instead of failing immediately.
    Returns (success, message).
    """
    if _runtime_skip_requested():
        return False, "skipped by WPFY_SKIP_RUNTIME"
    env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
    try:
        proc = subprocess.run(
            ["apt-get", "-o", "DPkg::Lock::Timeout=300", "update"],
            check=False,
            capture_output=True,
            text=True,
            timeout=_SUBPROCESS_TIMEOUT,
            env=env,
        )
    except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired) as exc:
        return False, f"apt-get update failed: {exc}"
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or "apt-get update returned non-zero"
        return False, f"apt-get update failed: {detail}"
    return True, "apt lists refreshed"


def _remove_package() -> tuple[bool, str]:
    """Remove the fail2ban package to restore a pre-install host state."""
    if _runtime_skip_requested():
        return False, "skipped by WPFY_SKIP_RUNTIME"
    env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
    try:
        proc = subprocess.run(
            [
                "apt-get",
                "-o",
                "DPkg::Lock::Timeout=300",
                "remove",
                "-y",
                "fail2ban",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=_SUBPROCESS_TIMEOUT,
            env=env,
        )
    except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired) as exc:
        return False, f"apt-get remove failed: {exc}"
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or "apt-get remove returned non-zero"
        return False, f"apt-get remove fail2ban failed: {detail}"
    return True, "fail2ban package removed"


def _stop_and_disable_service() -> None:
    """Best-effort stop/disable of the fail2ban unit before package rollback."""
    if _runtime_skip_requested():
        return
    with contextlib.suppress(OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
        subprocess.run(
            ["systemctl", "disable", "--now", "fail2ban"],
            check=False,
            capture_output=True,
            text=True,
            timeout=_SUBPROCESS_TIMEOUT,
        )


def _rollback_fresh_install() -> None:
    """Restore pre-install package and service state for a fresh install."""
    _stop_and_disable_service()
    _remove_package()


def _enable_service() -> tuple[bool, str]:
    """Enable and start the fail2ban systemd unit."""
    if _runtime_skip_requested():
        return False, "skipped by WPFY_SKIP_RUNTIME"
    try:
        proc = subprocess.run(
            ["systemctl", "enable", "--now", "fail2ban"],
            check=False,
            capture_output=True,
            text=True,
            timeout=_SUBPROCESS_TIMEOUT,
        )
    except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired) as exc:
        return False, f"systemctl enable --now fail2ban failed: {exc}"
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or "systemctl returned non-zero"
        return False, f"systemctl enable --now fail2ban failed: {detail}"
    return True, "fail2ban service enabled and started"


#: How long to wait for fail2ban-server to answer after the unit reports started.
PING_TIMEOUT_SECONDS = 20


def _ping_fail2ban() -> tuple[bool, str]:
    """Verify fail2ban-client ping returns pong, waiting for the socket to appear.

    `systemctl start` returns once the unit is active, but fail2ban-server binds
    /var/run/fail2ban/fail2ban.sock afterwards, so a single immediate ping loses
    a race it was never told about. On a clean host it lost it every time --
    "Failed to access socket path" -- and the rollback then tore out a fail2ban
    that was seconds from ready, package included.
    """
    if _runtime_skip_requested():
        return True, "skipped by WPFY_SKIP_RUNTIME"
    deadline = time.monotonic() + PING_TIMEOUT_SECONDS
    detail = "no pong"
    while True:
        try:
            proc = subprocess.run(
                ["fail2ban-client", "ping"],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired) as exc:
            return False, f"fail2ban-client ping failed: {exc}"
        if proc.returncode == 0 and "pong" in proc.stdout.lower():
            return True, "fail2ban-client ping: pong"
        detail = proc.stderr.strip() or proc.stdout.strip() or "no pong"
        if time.monotonic() >= deadline:
            return False, f"fail2ban-client ping failed after {PING_TIMEOUT_SECONDS}s: {detail}"
        time.sleep(0.5)


def _iter_failregex_lines(content: str) -> list[tuple[int, str]]:
    """Yield (line_no, pattern) for every failregex in a rendered filter body.

    Joins continuation lines so a multi-line failregex is validated whole.
    """
    result: list[tuple[int, str]] = []
    current: str | None = None
    start_line = 0
    for lineno, line in enumerate(content.splitlines(), start=1):
        if line.lstrip().startswith("failregex"):
            current = line.split("=", 1)[1].strip()
            start_line = lineno
        elif line.startswith(" ") and current is not None and line.strip():
            current = f"{current} {line.strip()}"
        elif current is not None and not line.strip():
            result.append((start_line, current))
            current = None
    if current is not None:
        result.append((start_line, current))
    return result


def _render_and_validate_filters() -> tuple[bool, str]:
    """Validate every WPFY failregex under fail2ban 1.0 semantics.

    Each strict failregex line must carry a failure-id named group
    (fid/ip4/ip6/dns); a line using the ``<HOST>`` tag is exempt because
    fail2ban expands it to those named groups at filter load. This catches
    the t20 'No failure-id group' RegexException in-process, before the
    service is ever enabled -- ``fail2ban-client -t`` alone misses it.
    """
    filters = (
        ("wpfy-panel-auth", panel_filter_content()),
        ("wpfy-wordpress", wordpress_filter_content()),
        ("wpfy-wordpress-auth", wordpress_auth_filter_content()),
    )
    for name, content in filters:
        for lineno, pattern in _iter_failregex_lines(content):
            if "<HOST>" in pattern:
                continue
            try:
                compiled = re.compile(pattern)
            except re.error as exc:
                return False, (
                    f"filter {name} line {lineno}: invalid failregex: {exc}"
                )
            groups = set(compiled.groupindex)
            if not groups & FAILURE_ID_GROUPS:
                return False, (
                    f"filter {name} line {lineno}: failregex has no failure-id "
                    f"group (fid/ip4/ip6/dns); fail2ban >=1.0 rejects it with "
                    f"RegexException: {pattern!r}"
                )
    return True, "wpfy failregexes valid under fail2ban 1.0"


def validate_jail_logpath(content: str) -> tuple[bool, str]:
    """Guard: every jail section must declare ``logpath`` at most once.

    Blocker 2 contract (fail2ban 1.0.2-3ubuntu0.1): duplicate ``logpath =``
    keys in one jail section are rejected by the config parser, and a
    space-separated dual value passes ``fail2ban-client -t`` but fails at
    reload/restart because the client/server ``addlogpath`` protocol treats
    the second path as the log position option (``ValueError: File option
    must be 'head' or 'tail'``). The only supported multi-path form is a
    single space-separated value; a second ``logpath`` key in a section is
    never allowed. Sections are delimited by ``[name]`` headers, so a
    multi-jail file (per-site jails) is checked per section.
    """
    current: str | None = None
    seen: set[str] = set()
    for line in content.splitlines():
        stripped = line.strip()
        if re.match(r"^\[[^\]]+\]$", stripped):
            current = stripped
        elif re.match(r"^logpath\s*=", stripped) and not stripped.startswith("#"):
            if current is None:
                return False, "logpath key appears outside any jail section"
            if current in seen:
                return False, (
                    f"jail {current} declares a second logpath key; at most one "
                    "is allowed (space-separated paths in one value are the "
                    "only multi-path form fail2ban accepts)"
                )
            seen.add(current)
    return True, "jail logpath contract valid"


def _validate_managed_jails_logpath(root: Path) -> tuple[bool, str]:
    """In-process logpath-key guard over WPFY-owned jail files on disk.

    Scans ``jail.d`` files WPFY owns (``wpfy-*`` names) so a stale or corrupt
    per-site jail can never pass host-level validation. Purely content-based;
    never edits admin-owned jail files.
    """
    jail_d = root / "jail.d"
    if not jail_d.is_dir():
        return True, "no WPFY jail files"
    for path in sorted(jail_d.iterdir()):
        if not path.is_file() or not path.name.startswith("wpfy-"):
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        ok, msg = validate_jail_logpath(content)
        if not ok:
            return False, f"jail.d/{path.name}: {msg}"
    return True, "WPFY jail logpath contract valid"


def _validate_config() -> tuple[bool, str]:
    """Validate WPFY configs before any start or reload.

    Runs (1) the in-process fail2ban 1.0 failure-id check over every rendered
    WPFY filter, (2) the in-process single-logpath jail contract guard over
    WPFY-owned jail files on disk (Blocker 2: ``fail2ban-client -t`` alone
    accepts a broken dual-logpath render), then (3) ``fail2ban-client -t`` for
    full jail/config syntax. Any failure returns False so ensure_fail2ban_host
    rolls back before ``systemctl enable --now``.
    """
    if _runtime_skip_requested():
        return True, "skipped by WPFY_SKIP_RUNTIME"
    regex_ok, regex_msg = _render_and_validate_filters()
    if not regex_ok:
        return False, regex_msg
    jail_ok, jail_msg = _validate_managed_jails_logpath(_fail2ban_root())
    if not jail_ok:
        return False, jail_msg
    try:
        proc = subprocess.run(
            ["fail2ban-client", "-t"],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired) as exc:
        return False, f"fail2ban-client -t failed: {exc}"
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or "config validation failed"
        return False, detail
    return True, "config valid"


def _reload_fail2ban() -> tuple[bool, str]:
    """Reload fail2ban to apply new configuration."""
    if _runtime_skip_requested():
        return True, "skipped by WPFY_SKIP_RUNTIME"
    try:
        proc = subprocess.run(
            ["fail2ban-client", "reload"],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired) as exc:
        return False, f"fail2ban-client reload failed: {exc}"
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or "reload failed"
        return False, detail
    return True, "fail2ban reloaded"


def _restart_service() -> tuple[bool, str]:
    """Restart the fail2ban systemd unit (recovery path after a bad reload)."""
    if _runtime_skip_requested():
        return True, "skipped by WPFY_SKIP_RUNTIME"
    try:
        proc = subprocess.run(
            ["systemctl", "restart", "fail2ban"],
            check=False,
            capture_output=True,
            text=True,
            timeout=_SUBPROCESS_TIMEOUT,
        )
    except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired) as exc:
        return False, f"systemctl restart fail2ban failed: {exc}"
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or "restart returned non-zero"
        return False, f"systemctl restart fail2ban failed: {detail}"
    return True, "fail2ban service restarted"


def _fail2ban_log_tail() -> str:
    """Capture recent fail2ban diagnostics (journalctl + log tail) for errors.

    Read-only; used to surface the startup RegexException when ping fails so
    an operator sees why protection did not come up.
    """
    if _runtime_skip_requested():
        return ""
    chunks: list[str] = []
    for command in (
        ["journalctl", "-u", "fail2ban", "-n", "40", "--no-pager"],
        ["tail", "-n", "40", "/var/log/fail2ban.log"],
    ):
        try:
            proc = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=15,
            )
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            continue
        output = (proc.stdout or proc.stderr or "").strip()
        if output:
            chunks.append(output)
    return "\n".join(chunks)


def _get_version() -> str:
    """Return installed fail2ban version or 'unknown'."""
    if _runtime_skip_requested():
        return "skipped"
    try:
        proc = subprocess.run(
            ["fail2ban-client", "version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
        return "unknown"
    if proc.returncode == 0 and proc.stdout.strip():
        return proc.stdout.strip().splitlines()[0]
    return "unknown"


# ---------------------------------------------------------------------------
# Atomic config file management
# ---------------------------------------------------------------------------


def _managed_file_content(body: str) -> str:
    """Prepend the WPFY managed header to config body."""
    return f"{_MANAGED_HEADER}\n{body}"


def _is_wpfy_managed(path: Path) -> bool:
    """Return True if the file exists and contains the WPFY managed header."""
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, FileNotFoundError):
        return False
    return _MANAGED_HEADER in content


def _atomic_write(path: Path, content: str, mode: int = 0o644) -> bool:
    """Write content atomically using a temp file + rename. Returns True if changed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        current = path.read_text(encoding="utf-8")
    except (OSError, FileNotFoundError):
        current = None
    if current == content:
        return False
    candidate = path.with_name(f".{path.name}-{secrets.token_hex(8)}.candidate")
    try:
        candidate.write_text(content, encoding="utf-8")
        os.chmod(candidate, mode)
        os.replace(candidate, path)
    finally:
        with contextlib.suppress(OSError, FileNotFoundError):
            candidate.unlink()
    return True


def _backup_wpfy_files(root: Path) -> dict[str, str]:
    """Snapshot current WPFY-owned file contents for rollback. Returns {relpath: content}."""
    backups: dict[str, str] = {}
    for subdir in ("filter.d", "jail.d", "action.d"):
        directory = root / subdir
        if not directory.is_dir():
            continue
        for path in directory.iterdir():
            if path.is_file() and _is_wpfy_managed(path):
                with contextlib.suppress(OSError):
                    backups[f"{subdir}/{path.name}"] = path.read_text(encoding="utf-8")
    return backups


def _restore_wpfy_files(root: Path, backups: dict[str, str]) -> None:
    """Restore WPFY-owned files from backup snapshot."""
    for relpath, content in backups.items():
        target = root / relpath
        with contextlib.suppress(OSError):
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")


def wordpress_filter_content() -> str:
    """Render the WPFY WordPress filter body (single source of truth).

    fail2ban_host owns this render. site_security delegates to it so that
    ``filter.d/wpfy-wordpress.conf`` cannot diverge between writers.

    The filter is deliberately COMBINED (t13):

    - The coarse nginx access-log regex is the backstop: it matches failed
      POST /wp-login.php requests in the host-visible access log.
    - The strict WordPress auth regex (``wordpress_auth_failregex``) is the
      proven event path: it matches only the t10 bridge's fixed 7-key JSONL
      records in the per-site wp-auth.log. Login Shield coverage is reported
      from this event path, never from the access log alone.

    fail2ban compiles each failregex line independently, so a line is matched
    when either rule fires.
    """
    return _managed_file_content("\n".join((
        "[Definition]",
        "datepattern = {NONE}",
        'failregex = ^<HOST> \\S+ \\S+ \\[[^]]+\\] "POST /wp-login\\.php(?:\\?[^ ]*)? HTTP/\\d\\.\\d" (?:200|401|403) \\d+',
        f"            {wordpress_auth_failregex()}",
        "ignoreregex =",
        "",
    )))


# ---------------------------------------------------------------------------
# Panel auth filter (t12) — strict WPFY JSONL failure matcher
# ---------------------------------------------------------------------------

# t09 schema (panel-auth-log-format.md): one JSON object per line, exactly six
# keys in a fixed order, ``ensure_ascii`` + strict separators. Only fields the
# writer controls (fixed enums / hashed hex / normalized IP / UTC timestamp)
# are trusted; any attacker-controlled byte that reached the line cannot fit
# the tight patterns below and the record is rejected.

_PANEL_FAIL_IPV4 = (
    r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
    r"(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}"
)

_PANEL_FAIL_IPV6 = (
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,7}:"
    r"|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}"
    r"|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})"
    r"|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)"
    r"|::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}"
    r"|::"
)

# fail2ban >=1.0 extracts the ban target from a failure-id named group
# (ip4/ip6/dns/fid). Wrapping the two alternatives in a non-capturing group
# keeps both groups optional so exactly one is populated per match.
_PANEL_FAIL_IP = rf"(?:(?P<ip4>{_PANEL_FAIL_IPV4})|(?P<ip6>{_PANEL_FAIL_IPV6}))"

_PANEL_FAIL_PREFIX = (
    r'^\{"timestamp":"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",'
    r'"event":"panel_auth_failure",'
    r'"surface":"(?:password|setup|setup_totp)",'
    # Reject the never-ban sentinel. Proxy / loopback / Docker bridge /
    # Cloudflare edge / trusted edge identities are redacted to 0.0.0.0 at
    # emission (t05a); banning it is a no-op and must never reach the action.
    r'"client_ip":"(?!0\.0\.0\.0")'
)

_PANEL_FAIL_SUFFIX = (
    r'","account_hash":"sha256:[0-9a-f]{64}",'
    r'"reason_class":"(?:invalid_credentials|totp_failed|locked|throttled)"}$'
)


def panel_failregex() -> str:
    """Return the strict panel-auth failure regex (single source of truth)."""
    return _PANEL_FAIL_PREFIX + _PANEL_FAIL_IP + _PANEL_FAIL_SUFFIX


# ---------------------------------------------------------------------------
# WordPress auth filter (t13) — strict WPFY JSONL matcher over wp-auth.log
# ---------------------------------------------------------------------------

# The t10 bridge writes one JSONL record per WordPress auth failure with exactly
# seven keys in a fixed order (RECORD_FIELDS): timestamp, event, site, surface,
# client_ip, account_hash, reason_class. Only fields the writer controls (fixed
# enums / 64-hex hash / normalized IP / UTC timestamp / validated domain) are
# trusted; any attacker-controlled byte that reached the line cannot fit the
# tight patterns below and the record is rejected. This is the strict event
# path; the coarse nginx access-log filter remains the shared backstop.
WORDPRESS_AUTH_FILTER_NAME = "wpfy-wordpress-auth"

_WP_AUTH_IPV4 = _PANEL_FAIL_IPV4
_WP_AUTH_IPV6 = _PANEL_FAIL_IPV6

_WP_AUTH_IP = rf"(?:(?P<ip4>{_WP_AUTH_IPV4})|(?P<ip6>{_WP_AUTH_IPV6}))"

_WP_AUTH_PREFIX = (
    r'^\{"timestamp":"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",'
    r'"event":"wordpress_auth_failure",'
    r'"site":"[A-Za-z0-9.-]+",'
    r'"surface":"(?:wp_login|xmlrpc|rest|password_reset|user_enum|app_password)",'
    # Reject the never-ban sentinel. Proxy / loopback / Docker bridge /
    # Cloudflare edge / trusted edge identities are redacted to 0.0.0.0 at
    # emission, so banning it is a no-op and must never reach the action.
    r'"client_ip":"(?!0\.0\.0\.0")'
)

_WP_AUTH_SUFFIX = (
    r'","account_hash":"[0-9a-f]{64}",'
    r'"reason_class":"(?:hard|soft|extra)"}$'
)


def wordpress_auth_failregex() -> str:
    """Return the strict WordPress auth-failure regex (single source of truth).

    Matches only valid WPFY wp-auth.log failure records and extracts the
    resolved trusted client IP. ``datepattern = {NONE}`` because the record
    carries no date prefix to strip.
    """
    return _WP_AUTH_PREFIX + _WP_AUTH_IP + _WP_AUTH_SUFFIX


def wordpress_auth_filter_content() -> str:
    """Render the WPFY WordPress auth filter body (single source of truth)."""
    return _managed_file_content("\n".join((
        "[Definition]",
        "datepattern = {NONE}",
        f"failregex = {wordpress_auth_failregex()}",
        "ignoreregex =",
        "",
    )))


def panel_filter_content() -> str:
    """Render the WPFY panel-auth filter body (single source of truth).

    Matches only valid WPFY panel JSONL failure records and extracts the
    resolved trusted client IP. Never parses raw forwarded headers (the log
    already carries the WPFY-resolved client, t02). ``datepattern = {NONE}``
    because the record carries no date prefix to strip.
    """
    return _managed_file_content("\n".join((
        "[Definition]",
        "datepattern = {NONE}",
        f"failregex = {panel_failregex()}",
        "ignoreregex =",
        "",
    )))


def _panel_auth_log_path() -> Path:
    """Host path of the panel auth failure log (default /var/log/wpfy/...)."""
    return Path(current_paths().log_dir) / PANEL_AUTH_LOG_FILENAME


def panel_jail_content() -> str:
    """Render the WPFY panel-auth jail body (activated, PANEL_JAIL policy).

    Activation is gated by the t07 trusted-proxy approval (already passed);
    this jail is the panel's own protection layer over panel-auth.log.
    """
    return _managed_file_content("\n".join((
        "[wpfy-panel-auth]",
        "enabled = true",
        "filter = wpfy-panel-auth",
        f"logpath = {_panel_auth_log_path()}",
        "backend = auto",
        f"findtime = {PANEL_JAIL['findtime']}",
        f"maxretry = {PANEL_JAIL['maxretry']}",
        f"bantime = {PANEL_JAIL['bantime']}",
        f"ignoreip = {' '.join(SAFE_ALLOWLIST)}",
        f"action = {PANEL_JAIL_ACTION}",
        "",
    )))


def _section_enabled(content: str) -> bool:
    """Return True when any non-comment line enables a jail.

    Informational scan only; WPFY never edits admin-owned jail files.
    """
    return bool(
        re.search(r"^\s*enabled\s*=\s*true\b", content, flags=re.MULTILINE)
    )


def _default_enabled_jails(root: Path) -> tuple[str, ...]:
    """Names of non-WPFY jails that would start enabled.

    Reads ``jail.conf`` and non-WPFY ``jail.d`` files. WPFY-owned files and
    ``wpfy-*`` names are excluded. Informational: these jails are preserved
    untouched and surfaced in the result message so an operator knows what
    the freshly started service will enforce.
    """
    enabled: list[str] = []
    candidates: list[Path] = []
    jail_conf = root / "jail.conf"
    if jail_conf.is_file():
        candidates.append(jail_conf)
    jail_d = root / "jail.d"
    if jail_d.is_dir():
        candidates.extend(
            path
            for path in jail_d.iterdir()
            if path.is_file() and not _is_wpfy_managed(path)
        )
    for path in candidates:
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if _section_enabled(content):
            name = "jail.conf" if path.name == "jail.conf" else path.stem
            enabled.append(name)
    return tuple(dict.fromkeys(enabled))


def _enabled_site_chains(root: Path) -> tuple[str, ...]:
    """Chain names for every currently-enabled per-site Login Shield jail.

    Reads ``jail.d/wpfy-wordpress.conf`` directly -- the per-site jail
    aggregate site_security.py owns (``fail2ban_jail_path()``). site_security
    imports this module, so importing it back here would cycle; the filename
    is the stable jail.d contract between the two, not a private detail.
    """
    from .fail2ban_docker import CHAIN_PREFIX

    path = root / "jail.d" / "wpfy-wordpress.conf"
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ()
    chains: list[str] = []
    current: str | None = None
    for line in content.splitlines():
        stripped = line.strip()
        match = re.match(r"^\[([^\]]+)\]$", stripped)
        if match:
            current = match.group(1)
            continue
        if current and re.match(r"^enabled\s*=\s*true\b", stripped):
            chains.append(f"{CHAIN_PREFIX}{current}")
            current = None
    return tuple(chains)


def _install_wpfy_configs(root: Path) -> tuple[bool, list[str]]:
    """Install/update WPFY-owned config files. Returns (changed, list of written paths)."""
    changed = False
    written: list[str] = []

    # Panel auth filter — strict WPFY JSONL failure matcher (t12).
    panel_filter = panel_filter_content()
    if _atomic_write(root / "filter.d" / "wpfy-panel-auth.conf", panel_filter):
        changed = True
        written.append("filter.d/wpfy-panel-auth.conf")

    # WordPress filter — single owner is this module; site_security delegates.
    if _atomic_write(root / "filter.d" / "wpfy-wordpress.conf", wordpress_filter_content()):
        changed = True
        written.append("filter.d/wpfy-wordpress.conf")

    # Panel jail — activated (t07 gate passed); protects the panel login
    # surface with PANEL_JAIL policy over the panel auth log (t12).
    panel_jail = panel_jail_content()
    if _atomic_write(root / "jail.d" / "wpfy-panel-auth.local", panel_jail):
        changed = True
        written.append("jail.d/wpfy-panel-auth.local")

    # WordPress jail — aggregate per-site jails are managed by site_security.
    # This host-level baseline stays disabled until a site opts in (t13).
    wp_jail = _managed_file_content("\n".join((
        "[wpfy-wordpress]",
        "enabled = false",
        "filter = wpfy-wordpress",
        "# Per-site jails in site_security.py enable this per domain.",
        f"findtime = {WORDPRESS_JAIL['findtime']}",
        f"maxretry = {WORDPRESS_JAIL['maxretry']}",
        f"bantime = {WORDPRESS_JAIL['bantime']}",
        f"ignoreip = {' '.join(SAFE_ALLOWLIST)}",
        "",
    )))
    if _atomic_write(root / "jail.d" / "wpfy-wordpress.local", wp_jail):
        changed = True
        written.append("jail.d/wpfy-wordpress.local")

    # Docker-aware action — real body owned by fail2ban_docker.install_action.
    # No placeholder is ever written here (t08 dual-writer fix).
    from .fail2ban_docker import install_action as _install_docker_action

    if _install_docker_action():
        changed = True
        written.append("action.d/wpfy-docker-http.conf")

    return changed, written


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def ensure_fail2ban_host() -> HostFail2banResult:
    """Idempotent host-level fail2ban installation and configuration.

    Ordering (t08 wave-3 fix, documented in host-install-evidence.md):

    1. Install the package when absent (apt-get update with lock timeout first).
    2. Land WPFY-owned configs BEFORE the service starts.
    3. Validate with ``fail2ban-client -t`` before any start/reload.
    4. Surface (never modify) default-enabled distro jails.
    5. Enable + start the systemd unit.
    6. Verify ``fail2ban-client ping``.
    7. Reload so a running service adopts the new config.
    8. Report health.

    Rollback contract: any post-apt failure (validate, enable, ping, reload)
    restores the previous WPFY-owned files, and a fresh install additionally
    removes the package and stops the unit so no half-configured fail2ban
    remains. Healthy existing installs are NOT reinstalled. Administrator-
    owned config is preserved (never touches /etc/fail2ban/jail.conf or
    non-WPFY files). Honors WPFY_SKIP_RUNTIME=1.
    """
    if _runtime_skip_requested():
        return HostFail2banResult(
            exit_code=0,
            message="fail2ban host installation skipped by WPFY_SKIP_RUNTIME",
            changed=False,
            installed=_fail2ban_installed(),
            health_ok=False,
        )

    # Step 1: Install package if absent.
    package_installed = _fail2ban_installed()
    freshly_installed = False
    if not package_installed:
        ok, msg = _apt_update()
        if not ok:
            record_event(
                "site.security.fail2ban.install-failed",
                outcome="error",
                detail=f"package update: {msg}",
            )
            return HostFail2banResult(
                exit_code=1,
                message=f"fail2ban package installation failed: {msg}",
                changed=False,
                installed=False,
                health_ok=False,
            )
        ok, msg = _install_package()
        if not ok:
            record_event(
                "site.security.fail2ban.install-failed",
                outcome="error",
                detail=f"package install: {msg}",
            )
            return HostFail2banResult(
                exit_code=1,
                message=f"fail2ban package installation failed: {msg}",
                changed=False,
                installed=False,
                health_ok=False,
            )
        freshly_installed = True
        # Verify the binary is now available.
        if not _fail2ban_installed():
            record_event(
                "site.security.fail2ban.install-failed",
                outcome="error",
                detail="package installed but fail2ban-client not found on PATH",
            )
            return HostFail2banResult(
                exit_code=1,
                message="fail2ban package installed but fail2ban-client not found on PATH",
                changed=True,
                installed=False,
                health_ok=False,
            )

    root = _fail2ban_root()
    backups = _backup_wpfy_files(root)

    # The panel jail watches a log the panel only creates on its first auth
    # failure. Validation runs before that ever happens on a fresh host, and
    # fail2ban treats a missing logpath as a fatal config error, so the whole
    # install would roll back on every clean machine.
    try:
        from .panel_auth import ensure_panel_auth_log

        ensure_panel_auth_log()
    except OSError as exc:
        return HostFail2banResult(
            exit_code=1,
            message=f"panel auth log could not be created: {exc}",
            changed=False,
            installed=True,
            health_ok=False,
        )

    # Step 2: WPFY configs land before the service starts.
    config_changed, written_files = _install_wpfy_configs(root)

    # Step 3: Validate before any start or reload. On invalid, restore the
    # previous WPFY-owned files and keep the prior config active.
    if config_changed or freshly_installed:
        valid, validation_msg = _validate_config()
        if not valid:
            _restore_wpfy_files(root, backups)
            if freshly_installed:
                _rollback_fresh_install()
            record_event(
                "login_shield.health_failed",
                outcome="error",
                detail=f"config validation failed after update; rolled back: {validation_msg}",
            )
            return HostFail2banResult(
                exit_code=1,
                message=f"fail2ban config validation failed; previous config restored: {validation_msg}",
                changed=freshly_installed,
                installed=_fail2ban_installed(),
                health_ok=False,
            )

    # Step 4: Pre-start distro jail check (informational only, never modifies).
    default_jails = _default_enabled_jails(root)

    # Step 5: Enable and start the systemd service.
    enable_ok, enable_msg = _enable_service()
    if not enable_ok:
        _restore_wpfy_files(root, backups)
        if freshly_installed:
            _rollback_fresh_install()
        record_event(
            "site.security.fail2ban.install-failed",
            outcome="error",
            detail=f"service enable: {enable_msg}",
        )
        return HostFail2banResult(
            exit_code=1,
            message=f"fail2ban service enable failed: {enable_msg}",
            changed=freshly_installed,
            installed=_fail2ban_installed(),
            health_ok=False,
        )

    # Step 6: Verify fail2ban-client ping.
    ping_ok, ping_msg = _ping_fail2ban()
    if not ping_ok:
        log_tail = _fail2ban_log_tail()
        detail = f"ping: {ping_msg}"
        if log_tail:
            detail += f"; fail2ban diagnostics:\n{log_tail}"
        _restore_wpfy_files(root, backups)
        if freshly_installed:
            _rollback_fresh_install()
        record_event(
            "site.security.fail2ban.install-failed",
            outcome="error",
            detail=detail,
        )
        return HostFail2banResult(
            exit_code=1,
            message=(
                f"fail2ban service started but ping failed: {ping_msg}"
                + (f"; diagnostics:\n{log_tail}" if log_tail else "")
            ),
            changed=freshly_installed,
            installed=_fail2ban_installed(),
            health_ok=False,
        )

    # Step 7: Reload safely so a running service adopts the new config.
    if config_changed or freshly_installed:
        reload_ok, reload_msg = _reload_fail2ban()
        if not reload_ok:
            _restore_wpfy_files(root, backups)
            if freshly_installed:
                # Fresh install has no prior running config to fall back to:
                # roll the package back to baseline so nothing half-configured
                # remains.
                _rollback_fresh_install()
                record_event(
                    "login_shield.health_failed",
                    outcome="error",
                    detail=f"reload failed after config update; rolled back: {reload_msg}",
                )
                return HostFail2banResult(
                    exit_code=1,
                    message=(
                        f"fail2ban reload failed; previous config restored: {reload_msg}"
                    ),
                    changed=freshly_installed,
                    installed=_fail2ban_installed(),
                    health_ok=False,
                )
            # Existing install: restart with the restored (previously healthy)
            # config and verify ping, so protection is not silently off.
            restart_ok, restart_msg = _restart_service()
            if not restart_ok:
                log_tail = _fail2ban_log_tail()
                record_event(
                    "site.security.fail2ban.install-failed",
                    outcome="error",
                    detail=(
                        f"reload failed and recovery restart failed: {reload_msg}; "
                        f"restart: {restart_msg}"
                    ),
                )
                return HostFail2banResult(
                    exit_code=1,
                    message=(
                        f"fail2ban reload failed; restart with previous config "
                        f"failed: {restart_msg}"
                        + (f"; diagnostics:\n{log_tail}" if log_tail else "")
                    ),
                    changed=True,
                    installed=_fail2ban_installed(),
                    health_ok=False,
                )
            recovery_ping_ok, recovery_ping_msg = _ping_fail2ban()
            if not recovery_ping_ok:
                log_tail = _fail2ban_log_tail()
                record_event(
                    "site.security.fail2ban.install-failed",
                    outcome="error",
                    detail=(
                        f"reload failed; restart with previous config did not "
                        f"ping: {reload_msg}; ping: {recovery_ping_msg}"
                    ),
                )
                return HostFail2banResult(
                    exit_code=1,
                    message=(
                        f"fail2ban reload failed; service restarted but ping "
                        f"failed: {recovery_ping_msg}"
                        + (f"; diagnostics:\n{log_tail}" if log_tail else "")
                    ),
                    changed=True,
                    installed=_fail2ban_installed(),
                    health_ok=False,
                )
            # F3: a successful recovery restart is a repair, not a health
            # failure — record login_shield.repaired (outcome ok) so the
            # event log never claims health_failed on a healthy end state.
            record_event(
                "login_shield.repaired",
                outcome="ok",
                detail=(
                    f"reload failed; previous config restored and service "
                    f"restarted healthy: {reload_msg}"
                ),
            )
            return HostFail2banResult(
                exit_code=0,
                message=(
                    f"fail2ban reload failed; previous config restored and "
                    f"service restarted; protection active: {reload_msg}"
                ),
                changed=True,
                installed=True,
                health_ok=True,
            )

    # Step 7.5: Docker can restart independently of fail2ban and wipes
    # DOCKER-USER on the way back up. On the unchanged-config path fail2ban
    # itself never reloads (Step 7 only reloads when config changed), so
    # nothing else re-attaches the WPFY chains until a jail's next ban/unban
    # happens to trigger actioncheck -- which may be never. Repair it here
    # for the panel jail and every currently-enabled per-site jail.
    # Idempotent (create-if-missing + check-before-insert, never flushes a
    # chain that may hold live bans); a failed repair fails the health check
    # rather than reporting healthy (no fail-open).
    if not (config_changed or freshly_installed):
        from .fail2ban_docker import reattach_chain

        reattach_errors: list[str] = []
        for target_chain in (PANEL_JAIL_CHAIN, *_enabled_site_chains(root)):
            reattach_ok, reattach_detail = reattach_chain(target_chain)
            if not reattach_ok:
                reattach_errors.append(f"{target_chain}: {reattach_detail}")
        if reattach_errors:
            detail = f"DOCKER-USER chain reattach failed: {'; '.join(reattach_errors)}"
            record_event(
                "login_shield.health_failed",
                outcome="error",
                detail=detail,
            )
            return HostFail2banResult(
                exit_code=1,
                message=f"fail2ban healthy but {detail}",
                changed=False,
                installed=True,
                health_ok=False,
            )

    # Step 8: Final health verification.
    version = _get_version()
    changed = freshly_installed or config_changed
    detail = f"version={version}"
    if freshly_installed:
        detail += "; freshly installed"
    elif not config_changed:
        detail += "; healthy, no changes needed"
    if written_files:
        detail += f"; wrote {', '.join(written_files)}"
    if default_jails:
        detail += f"; enabled distro jails (untouched): {', '.join(default_jails)}"

    # Panel jail ban activation (Phase 11 event): emitted once, when the
    # activation write actually landed. fail2ban performs the per-IP bans
    # externally; this event records that the jail ban layer is now active.
    if "jail.d/wpfy-panel-auth.local" in written_files:
        record_event(
            "login_shield.panel_fail2ban_ban",
            outcome="ok",
            detail=(
                f"wpfy-panel-auth jail activated; action={PANEL_JAIL_ACTION} "
                f"chain={PANEL_JAIL_CHAIN} "
                f"policy=maxretry {PANEL_JAIL['maxretry']}/"
                f"findtime {PANEL_JAIL['findtime']}/"
                f"bantime {PANEL_JAIL['bantime']} "
                f"ignoreip={' '.join(SAFE_ALLOWLIST)}"
            ),
        )

    record_event(
        "login_shield.fail2ban_ensured",
        outcome="ok",
        detail=detail,
    )

    return HostFail2banResult(
        exit_code=0,
        message=f"fail2ban {detail}",
        changed=changed,
        installed=True,
        health_ok=True,
    )
