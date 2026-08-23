"""Docker-aware Fail2ban action for WPFY.

Renders and installs a WPFY-owned Fail2ban action file that blocks banned IPs
on Docker-published HTTP/HTTPS ports by attaching a dedicated iptables chain
to DOCKER-USER (the correct chain for Docker-published traffic, not INPUT).

Phase 3 of the Login Shield plan (login-shield-plan.md, lines 480-569).

Traffic path:
    External client -> FORWARD -> DOCKER-USER -> Docker -> Traefik -> site

The action creates a dedicated chain (e.g. f2b-wpfy-<jailname>), attaches it
to DOCKER-USER with an idempotent check-before-insert, and blocks TCP 80/443
only.  SSH (port 22) and the INPUT chain are never touched.  IPv6 support is
guarded by runtime capability detection (ipv6_capable).
"""

from __future__ import annotations

import os
import re
import secrets
import shutil
import subprocess
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

# ---------------------------------------------------------------------------
# Policy constants
# ---------------------------------------------------------------------------
# The single source of truth is fail2ban_host.SAFE_ALLOWLIST. These split
# aliases exist for callers that need v4/v6 separately and are derived from
# the canonical tuple so they cannot drift (t08 consolidation).
from .fail2ban_host import SAFE_ALLOWLIST

ALLOWLIST_IPV4: tuple[str, ...] = tuple(
    item for item in SAFE_ALLOWLIST if ":" not in item
)
ALLOWLIST_IPV6: tuple[str, ...] = tuple(
    item for item in SAFE_ALLOWLIST if ":" in item
)

# ---------------------------------------------------------------------------
# Module constants
# ---------------------------------------------------------------------------

ACTION_FILE_NAME = "wpfy-docker-http.conf"
MANAGED_HEADER = "# Managed by WPFY. Manual changes may be overwritten."
BLOCKED_PORTS = (80, 443)
BLOCKED_PROTOCOL = "tcp"

# Chain naming contract: every WPFY chain must carry this prefix so the action
# can never touch a chain it does not own. Fail2ban substitutes the <name> tag
# with the per-jail name parameter, so two jails never share a chain.
CHAIN_PREFIX = "f2b-wpfy-"

# iptables/ip6tables chain names are capped at 28 characters (excluding the
# terminating NUL). A longer name makes every -N/-I/-D fail with EINVAL; the
# action's ``2>/dev/null || true`` would swallow it and bans would silently
# no-op (blocker B1). The panel chain (f2b-wpfy-panel-auth, 19 chars) and the
# per-site scheme (f2b-wpfy-<16hex>, 25 chars) both stay under this limit.
IPTABLES_CHAIN_MAX_LENGTH = 28

# Bounded wall-clock for every iptables/ip6tables invocation: ``-w`` blocks on
# the xtables lock, and a stuck lock must surface as a timeout (returncode
# 124), never hang the caller forever (t16 W3).
SUBPROCESS_TIMEOUT_SECONDS = 10.0

# Render markers. The installed action records which capability it was built
# for so a later capability change can be detected (stale-action detection).
_IPV6_MARKER_RE = re.compile(r"^# Rendered with IPv6 support: (yes|no)$", re.MULTILINE)
_IPV6_MARKER_YES = "# Rendered with IPv6 support: yes"
_IPV6_MARKER_NO = "# Rendered with IPv6 support: no"

# Allowed characters in the jail-name fragment of a chain name.
_CHAIN_NAME_RE = re.compile(r"^[A-Za-z0-9_<>.-]+$")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EnforcementStatus:
    """Structured status for the Docker fail2ban action enforcement."""

    ipv4_active: bool
    ipv6_active: bool
    ipv6_applicable: bool
    docker_user_present: bool
    wpfy_chain_attached: bool
    chain_name: str
    action_stale: bool = False
    degraded_reason: str = ""


@dataclass(frozen=True)
class RunResult:
    """Result of a subprocess invocation."""

    returncode: int
    stdout: str
    stderr: str
    skipped: bool = False


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _current_paths():
    """Lazy import to pick up env-var-injected PATHS after test reload."""
    from .settings import PATHS as current_paths

    return current_paths


def _fail2ban_root() -> Path:
    """Derive fail2ban root from config_dir parent, mirroring site_security."""
    return Path(_current_paths().config_dir).parent / "fail2ban"


def _run(
    cmd: list[str],
    *,
    check: bool = False,
    timeout: float = SUBPROCESS_TIMEOUT_SECONDS,
) -> RunResult:
    """Run a subprocess command, honoring WPFY_SKIP_RUNTIME and test overrides.

    When ``WPFY_SKIP_RUNTIME=1`` the command is not executed and a skipped
    result is returned.  Tests can override the binary path via
    ``WPFY_TEST_IPTABLES_BIN`` / ``WPFY_TEST_IP6TABLES_BIN``.

    Every invocation is bounded by *timeout* (t16 W3): ``iptables -w`` blocks
    on the xtables lock, so an unbounded wait could hang enable/status
    forever.  A timeout is surfaced as returncode 124 with a diagnostic on
    stderr — never as success.
    """
    if os.environ.get("WPFY_SKIP_RUNTIME", "0") == "1":
        return RunResult(returncode=0, stdout="", stderr="", skipped=True)

    actual = list(cmd)
    override = os.environ.get("WPFY_TEST_IPTABLES_BIN")
    if override and actual and actual[0] == "iptables":
        actual[0] = override
    override6 = os.environ.get("WPFY_TEST_IP6TABLES_BIN")
    if override6 and actual and actual[0] == "ip6tables":
        actual[0] = override6

    try:
        proc = subprocess.run(
            actual,
            capture_output=True,
            text=True,
            check=check,
            timeout=timeout,
        )
        return RunResult(
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
        )
    except subprocess.TimeoutExpired as exc:
        return RunResult(
            returncode=124,
            stdout=exc.stdout or "" if isinstance(exc.stdout, str) else "",
            stderr=(
                exc.stderr or "" if isinstance(exc.stderr, str) else ""
            ) or f"timed out after {timeout:g}s",
        )
    except subprocess.CalledProcessError as exc:
        return RunResult(
            returncode=exc.returncode,
            stdout=exc.stdout or "",
            stderr=exc.stderr or "",
        )
    except FileNotFoundError:
        return RunResult(returncode=127, stdout="", stderr="binary not found")


def _safe_read(root: Path, name: str) -> str | None:
    """Read a file under *root* via directory-fd, returning None if absent."""
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
    """Atomically create a new file under *root* via directory-fd."""
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


def _replace_file(root: Path, target: str, replacement: str) -> None:
    """Atomic rename-replace under *root*, refusing symlinks."""
    import stat as stat_mod

    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            metadata = os.stat(target, dir_fd=root_fd, follow_symlinks=False)
            if stat_mod.S_ISLNK(metadata.st_mode):
                raise OSError(f"managed config is a symlink: {target}")
        except FileNotFoundError:
            pass
        os.replace(replacement, target, src_dir_fd=root_fd, dst_dir_fd=root_fd)
    finally:
        os.close(root_fd)


def _cleanup(root: Path, name: str) -> None:
    """Best-effort removal of a temporary file under *root*."""
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
    """Atomic write returning True when the file content changed.

    Mirrors ``site_security._install_text`` — writes to a candidate temp file
    then atomically replaces the target.
    """
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


# ---------------------------------------------------------------------------
# Public API — path and content
# ---------------------------------------------------------------------------


def validate_chain_name(chain: str) -> None:
    """Validate a WPFY-owned chain name.

    Chain names must carry the ``f2b-wpfy-`` prefix (never target chains the
    action does not own), a non-empty jail-name fragment, and stay at or
    under the iptables 28-character limit (blocker B1).  The fail2ban
    ``<name>`` tag is allowed so each jail instantiates its own chain.
    """
    if not isinstance(chain, str) or not chain:
        raise ValueError("chain name must not be empty")
    if not chain.startswith(CHAIN_PREFIX):
        raise ValueError(
            f"chain name must start with {CHAIN_PREFIX!r}: {chain!r}"
        )
    fragment = chain[len(CHAIN_PREFIX):]
    if not fragment:
        raise ValueError("chain name must include a jail name after f2b-wpfy-")
    if not _CHAIN_NAME_RE.fullmatch(fragment):
        raise ValueError(f"invalid chain name: {chain!r}")
    if len(chain) > IPTABLES_CHAIN_MAX_LENGTH:
        raise ValueError(
            f"chain name {chain!r} is {len(chain)} chars; iptables allows at "
            f"most {IPTABLES_CHAIN_MAX_LENGTH} (a longer chain silently "
            "fails to ban)"
        )


def validate_unique_chain_names(chains: Iterable[str]) -> None:
    """Reject two jails that resolve to the same literal WPFY chain.

    actionstart flushes the WPFY chain, so two jails sharing a chain name
    would wipe each other's bans on reload.  Chains containing the fail2ban
    ``<name>`` tag cannot collide (each jail substitutes its own name).
    """
    seen: set[str] = set()
    for chain in chains:
        validate_chain_name(chain)
        if "<name>" in chain:
            continue
        if chain in seen:
            raise ValueError(
                f"two jails share chain name {chain!r}; actionstart would "
                "flush the shared WPFY chain; use unique f2b-wpfy-<name> "
                "per jail"
            )
        seen.add(chain)


def action_file_path() -> Path:
    """Return the path to the WPFY Docker HTTP action file.

    ``<fail2ban-root>/action.d/wpfy-docker-http.conf``
    """
    return _fail2ban_root() / "action.d" / ACTION_FILE_NAME


def action_content(
    *,
    chain: str | None = None,
    ipv6: bool | None = None,
) -> str:
    """Render the Fail2ban action.d configuration text.

    The rendered action:

    * Creates a WPFY-owned chain on ``actionstart`` (idempotent, survives
      fail2ban reload).
    * Attaches the chain to ``DOCKER-USER`` with check-before-insert.
    * Blocks TCP ports 80 and 443 only — never SSH or INPUT.
    * Uses ``iptables -w`` for concurrent-safety.
    * Includes ip6tables commands only when *ipv6* is True.
    * Removes the chain on ``actionstop`` only when empty and WPFY-owned.

    Parameters
    ----------
    chain:
        Chain name.  Defaults to ``f2b-wpfy-<name>`` where ``<name>`` is
        the fail2ban jail-name tag supplied at jail instantiation.
    ipv6:
        Include ip6tables commands.  ``None`` probes via :func:`ipv6_capable`.
    """
    if chain is None:
        chain = "f2b-wpfy-<name>"
    validate_chain_name(chain)
    if ipv6 is None:
        ipv6 = ipv6_capable()

    ports_csv = ",".join(str(p) for p in BLOCKED_PORTS)

    # IPv6 block — included only when the host can route public IPv6.
    #
    # Every line here continues the `actionstart` value, so it must carry the
    # same indent as the IPv4 lines above. fail2ban parses this file with
    # configparser: an unindented line inside a multi-line value is a hard
    # parse error that fails `fail2ban-server --test` and takes the whole
    # install down. That is invisible on an IPv4-only host, where this block
    # is never rendered at all -- see `test_action_content_parses_as_ini`.
    if ipv6:
        ip6_block = (
            "              # IPv6 (host has public IPv6 or Docker IPv6)\n"
            "              ip6tables -w -N {chain} 2>/dev/null || true\n"
            "              ip6tables -w -F {chain} 2>/dev/null || true\n"
            "              ip6tables -w -C DOCKER-USER -j {chain} 2>/dev/null"
            " || ip6tables -w -I DOCKER-USER 1 -j {chain}\n"
        ).format(chain=chain)
    else:
        ip6_block = ""

    # Ban/unban: when rendered with IPv6 support, branch on the fail2ban
    # <family> tag so IPv6 bans use real ip6tables commands (reject with
    # icmp6-port-unreachable) and IPv4 bans keep iptables. The IPv4-only
    # render keeps the historical single-line actionban/actionunban contract.
    v4_ban = (
        f"iptables -w -I {chain} 1"
        f" -s <ip> -p {BLOCKED_PROTOCOL}"
        f" -m multiport --dports {ports_csv}"
        f' -m comment --comment "f2b-wpfy-<name>"'
        f" -j REJECT --reject-with icmp-port-unreachable"
    )
    v4_unban = (
        f"iptables -w -D {chain}"
        f" -s <ip> -p {BLOCKED_PROTOCOL}"
        f" -m multiport --dports {ports_csv}"
        f' -m comment --comment "f2b-wpfy-<name>"'
        f" -j REJECT --reject-with icmp-port-unreachable"
        f" 2>/dev/null || true"
    )
    if ipv6:
        v6_ban = (
            f"ip6tables -w -I {chain} 1"
            f" -s <ip> -p {BLOCKED_PROTOCOL}"
            f" -m multiport --dports {ports_csv}"
            f' -m comment --comment "f2b-wpfy-<name>"'
            f" -j REJECT --reject-with icmp6-port-unreachable"
        )
        v6_unban = (
            f"ip6tables -w -D {chain}"
            f" -s <ip> -p {BLOCKED_PROTOCOL}"
            f" -m multiport --dports {ports_csv}"
            f' -m comment --comment "f2b-wpfy-<name>"'
            f" -j REJECT --reject-with icmp6-port-unreachable"
            f" 2>/dev/null || true"
        )
        # fail2ban expands <family> to "inet4"/"inet6" -- NOT "ipv4"/"ipv6".
        # Testing for "ipv6" always fell through to the IPv4 branch, which ran
        # `iptables -s <v6 address>` and died with "host/network not found",
        # while `fail2ban-client status` went on reporting the address as
        # banned. An IPv6 client was never blocked and nothing showed the
        # operator that. Verified against fail2ban 1.0.2 on a live host.
        family_test = 'if [ "<family>" = "inet6" ]; then'
        actionban = (
            f"actionban   = {family_test}\n"
            f"              {v6_ban}\n"
            f"              else\n"
            f"              {v4_ban}\n"
            f"              fi\n"
        )
        actionunban = (
            f"actionunban = {family_test}\n"
            f"              {v6_unban}\n"
            f"              else\n"
            f"              {v4_unban}\n"
            f"              fi\n"
        )
    else:
        actionban = f"actionban   = {v4_ban}\n"
        actionunban = f"actionunban = {v4_unban}\n"

    ipv6_marker = _IPV6_MARKER_YES if ipv6 else _IPV6_MARKER_NO

    return (
        f"{MANAGED_HEADER}\n"
        f"# Docker-aware WPFY fail2ban action.\n"
        f"# Attaches a dedicated chain to DOCKER-USER for Docker-published\n"
        f"# HTTP/HTTPS traffic.  Never touches INPUT or SSH (port 22).\n"
        f"{ipv6_marker}\n"
        f"\n"
        f"[Definition]\n"
        f"\n"
        f"actionstart = "
        f"# Create WPFY chain (idempotent, survives fail2ban reload)\n"
        f"              "
        f"iptables -w -N {chain} 2>/dev/null || true\n"
        f"              "
        f"# Flush stale rules from a previous run\n"
        f"              "
        f"iptables -w -F {chain} 2>/dev/null || true\n"
        f"              "
        f"# Attach to DOCKER-USER (check before insert)\n"
        f"              "
        f"iptables -w -C DOCKER-USER -j {chain} 2>/dev/null"
        f" || iptables -w -I DOCKER-USER 1 -j {chain}\n"
        f"{ip6_block}"
        f"\n"
        f"actionstop  = "
        f"# Remove chain only when empty and WPFY-owned\n"
        f"              "
        f'if iptables -w -S {chain} >/dev/null 2>&1; then\n'
        f"              "
        f'  rule_count=$(iptables -w -S {chain} | wc -l)\n'
        f"              "
        f'  if [ "$rule_count" -le 1 ]; then\n'
        f"              "
        f"    iptables -w -D DOCKER-USER -j {chain} 2>/dev/null || true\n"
        f"              "
        f"    iptables -w -X {chain} 2>/dev/null || true\n"
        f"              "
        f"  fi\n"
        f"              "
        f"fi\n"
        f"\n"
        f"actioncheck = "
        f"# Verify chain exists and is attached; repair if needed\n"
        f"              "
        f"iptables -w -N {chain} 2>/dev/null || true\n"
        f"              "
        f"iptables -w -C DOCKER-USER -j {chain} 2>/dev/null"
        f" || iptables -w -I DOCKER-USER 1 -j {chain}\n"
        f"\n"
        f"{actionban}"
        f"\n"
        f"{actionunban}"
    )


# ---------------------------------------------------------------------------
# Public API — install
# ---------------------------------------------------------------------------


def install_action(
    *,
    chain: str | None = None,
    ipv6: bool | None = None,
) -> bool:
    """Atomically write the action file.  Returns True when content changed."""
    path = action_file_path()
    content = action_content(chain=chain, ipv6=ipv6)
    path.parent.mkdir(parents=True, exist_ok=True)
    return _install_text(path.parent, path.name, content, 0o644)


# ---------------------------------------------------------------------------
# Public API — IPv6 capability detection
# ---------------------------------------------------------------------------


def ipv6_capable() -> bool:
    """Return True when the host has a global IPv6 address or Docker IPv6.

    Probes via ``ip -6 addr show scope global`` and Docker network inspection.
    Returns False when ``WPFY_SKIP_RUNTIME=1`` unless the test override
    ``WPFY_TEST_IPV6_CAPABLE`` is set.
    """
    override = os.environ.get("WPFY_TEST_IPV6_CAPABLE")
    if override is not None:
        return override == "1"

    if os.environ.get("WPFY_SKIP_RUNTIME", "0") == "1":
        return False

    if not shutil.which("ip"):
        return False

    try:
        proc = subprocess.run(
            ["ip", "-6", "addr", "show", "scope", "global"],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return True
    except (FileNotFoundError, OSError):
        pass

    # Probe Docker edge network for IPv6 enablement.
    if shutil.which("docker"):
        try:
            proc = subprocess.run(
                [
                    "docker",
                    "network",
                    "inspect",
                    "wpfy",
                    "--format",
                    "{{.EnableIPv6}}",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout.strip().lower() == "true":
                return True
        except (FileNotFoundError, OSError):
            pass

    return False


# ---------------------------------------------------------------------------
# Public API — enforcement status
# ---------------------------------------------------------------------------


def enforcement_status(*, chain: str | None = None) -> EnforcementStatus:
    """Return structured enforcement status for the Docker action.

    Probes iptables for DOCKER-USER chain presence and WPFY chain attachment.
    All probes are safe (read-only ``iptables -S`` / ``iptables -L``).
    Reports ``action_stale`` (and a degraded reason) when the host gained
    IPv6 capability after the action was rendered without the ip6 block.
    """
    if chain is None:
        chain = "f2b-wpfy-http"
    validate_chain_name(chain)

    ipv6 = ipv6_capable()

    # DOCKER-USER chain present?
    docker_user_result = _run(["iptables", "-w", "-S", "DOCKER-USER"])
    docker_user_present = (
        docker_user_result.skipped or docker_user_result.returncode == 0
    )

    # WPFY chain attached to DOCKER-USER?
    attached = False
    if docker_user_present and not docker_user_result.skipped:
        list_result = _run(["iptables", "-w", "-L", "DOCKER-USER", "-n"])
        if list_result.returncode == 0:
            attached = chain in list_result.stdout
    elif docker_user_result.skipped:
        attached = True  # assume OK when runtime skipped

    # IPv6 status: ipv6_active is currently never True, and the three checks
    # below decide only *which* reason the operator is told.
    #
    # Those checks -- action rendered with ip6tables commands, ip6tables
    # DOCKER-USER present, WPFY chain attached to it -- were all satisfied on
    # an IPv6-only host on 2026-08-21, and the ban still did not hold. wpfy
    # enables IPv6 on neither the Docker daemon nor any Docker network, so
    # inbound IPv6 to a published port is relayed by docker-proxy in userland:
    # it never enters ip6tables FORWARD, the correctly installed rule sits at
    # zero packets while the v4 chain counts normally, and Traefik sees the
    # bridge gateway instead of the client. Nothing this module can install
    # changes that.
    #
    # So the claim is withheld rather than dressed up. Reporting "active" for
    # a rule that cannot match is worse than reporting nothing: it tells an
    # operator with public IPv6 that half their surface is covered when none
    # of it is. Restoring a real check belongs with the decision to enable
    # Docker IPv6, which needs its own ADR.
    ipv6_active = False
    degraded_reason = ""
    if ipv6:
        ip6_result = _run(["ip6tables", "-w", "-S", "DOCKER-USER"])
        ip6_docker_user_present = (
            ip6_result.skipped or ip6_result.returncode == 0
        )
        ip6_attached = False
        if ip6_docker_user_present and not ip6_result.skipped:
            ip6_list = _run(["ip6tables", "-w", "-L", "DOCKER-USER", "-n"])
            if ip6_list.returncode == 0:
                ip6_attached = chain in ip6_list.stdout
        elif ip6_result.skipped:
            ip6_attached = True
        ban_capable = action_rendered_ipv6() is True
        if ip6_docker_user_present and ip6_attached and ban_capable:
            # Everything this module owns is in place; the gap is above it.
            degraded_reason = (
                "IPv6 ban rules install but never match: wpfy does not enable "
                "IPv6 on the Docker network, so inbound IPv6 is relayed in "
                "userland and bypasses DOCKER-USER"
            )
        else:
            reasons = []
            if not ban_capable:
                reasons.append("action lacks IPv6 ban capability; re-render required")
            if not ip6_docker_user_present:
                reasons.append("IPv6 DOCKER-USER not configured")
            elif not ip6_attached:
                reasons.append("WPFY chain not attached in IPv6 DOCKER-USER")
            degraded_reason = "; ".join(reasons)
    else:
        # Not IPv6 capable — not degraded, just not applicable.
        pass

    # Stale-action detection: rendered without ip6 block but host now IPv6
    # capable.  Health stays degraded until the action is re-rendered.
    stale = action_is_stale()
    if stale:
        stale_reason = (
            "action stale: IPv6 capable but action rendered without IPv6 "
            "support; re-render required"
        )
        degraded_reason = (
            f"{degraded_reason}; {stale_reason}" if degraded_reason else stale_reason
        )

    return EnforcementStatus(
        ipv4_active=docker_user_present,
        ipv6_active=ipv6_active,
        ipv6_applicable=ipv6,
        docker_user_present=docker_user_present,
        wpfy_chain_attached=attached,
        chain_name=chain,
        action_stale=stale,
        degraded_reason=degraded_reason,
    )


def action_rendered_ipv6() -> bool | None:
    """Return the IPv6 capability the installed action was rendered for.

    Returns None when no action file exists or the render marker is absent.
    """
    path = action_file_path()
    try:
        content = path.read_text(encoding="utf-8")
    except OSError:
        return None
    match = _IPV6_MARKER_RE.search(content)
    if match is None:
        return None
    return match.group(1) == "yes"


def action_is_stale() -> bool:
    """Return True when the installed action lacks IPv6 support but the host
    now has public IPv6 (an action rendered without the ip6 block must be
    re-rendered when the host later gains IPv6)."""
    rendered = action_rendered_ipv6()
    if rendered is None:
        return False
    return ipv6_capable() and not rendered
