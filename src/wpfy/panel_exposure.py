from __future__ import annotations

import ipaddress
import os
from pathlib import Path
import re
import stat
import tempfile
from urllib.parse import urlsplit

from . import certificate_lifecycle, panel_auth, systemd, traefik
from .site_paths import validate_domain
from .site_runtime import RuntimeResult


PANEL_EDGE_NETWORK = "wpfy-panel-edge"
RATE_LIMIT_AVERAGE = 10
RATE_LIMIT_BURST = 20
DEFAULT_PANEL_PORT = 8642
_ROUTER_NAME = "wpfy-panel"
#: Distinguishes "use the stored credential" from an explicit None ("no credential").
_UNSET = "\0unset"
#: The `user:hash` line inside a rendered basicAuth block.
_BASIC_AUTH_USER_RE = re.compile(r'^\s+- "([^"]+)"\s*$', re.MULTILINE)
_SERVICE_NAME = "wpfy-panel.service"
_CONTAINER_DYNAMIC_DIR = "/etc/traefik/dynamic"
_DOMAIN_RULE_RE = re.compile(r"Host\(`([^`]+)`\)")


def dynamic_dir() -> Path:
    return traefik.traefik_dir() / "dynamic"


def panel_router_path() -> Path:
    return dynamic_dir() / "wpfy-panel.yml"


def panel_service_path() -> Path:
    return systemd.systemd_dir() / _SERVICE_NAME


def _validated_target_url(target_url: str) -> str:
    if not isinstance(target_url, str):
        raise TypeError("panel target URL must be a string")
    parsed = urlsplit(target_url)
    if parsed.scheme != "http" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("panel target URL must be an unauthenticated HTTP URL")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("panel target URL must not contain a path, query, or fragment")
    try:
        ipaddress.ip_address(parsed.hostname)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("panel target URL must use an IP address") from exc
    if port is None or not 1 <= port <= 65535:
        raise ValueError("panel target URL must include a valid port")
    return target_url


def render_router_config(domain, target_url, credential: str | None = _UNSET) -> str:
    if not isinstance(domain, str):
        raise TypeError("panel domain must be a string")
    validate_domain(domain)
    target_url = _validated_target_url(target_url)
    # Basic auth, when configured, guards the public router only. Loopback and
    # the SSH tunnel stay unguarded on purpose: a forgotten credential must
    # always be recoverable, and this is the only place it helps anyway --
    # a scanner hitting the public domain is stopped before the login form
    # loads.
    #
    # `credential` is explicit for `_router_details`, which must re-render a
    # file written before the credential existed. Defaulting to the stored one
    # made the recognition check disagree with any router written under a
    # different credential state -- including the moment a credential is first
    # stored, which is exactly when the router needs rewriting.
    if credential is _UNSET:
        credential = read_panel_basic_auth()
    middlewares = [f"        - {_ROUTER_NAME}-rate-limit"]
    if credential:
        middlewares.append(f"        - {_ROUTER_NAME}-basic-auth")
    basic_auth_block = []
    if credential:
        basic_auth_block = [
            f"    {_ROUTER_NAME}-basic-auth:",
            "      basicAuth:",
            "        users:",
            f'          - "{credential}"',
        ]
    return "\n".join([
        "http:",
        "  routers:",
        f"    {_ROUTER_NAME}:",
        f'      rule: "Host(`{domain}`)"',
        "      entryPoints:",
        "        - websecure",
        "      middlewares:",
        *middlewares,
        f"      service: {_ROUTER_NAME}",
        "      tls:",
        "        certResolver: le-http",
        "  middlewares:",
        f"    {_ROUTER_NAME}-rate-limit:",
        "      rateLimit:",
        f"        average: {RATE_LIMIT_AVERAGE}",
        f"        burst: {RATE_LIMIT_BURST}",
        *basic_auth_block,
        "  services:",
        f"    {_ROUTER_NAME}:",
        "      loadBalancer:",
        "        servers:",
        f'          - url: "{target_url}"',
        "",
    ])


def validate_edge_bind(host) -> str:
    if not isinstance(host, str) or not host:
        raise ValueError("panel edge bind must be an IP address")
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError("panel edge bind must be an IP address") from exc
    if address.is_unspecified:
        raise ValueError("panel edge bind cannot be a wildcard address")
    if address.is_loopback:
        raise ValueError("panel edge bind cannot be a loopback address")
    return str(address)


def validate_panel_edge_bind(host) -> str:
    """The stricter rule for an edge-bound panel: inside the panel's own bridge.

    Separate from `validate_edge_bind` because the domainless mode binds the
    host's *public* address, which is deliberately outside this network. One
    function cannot enforce both, so each caller names the rule it means.
    """
    address = ipaddress.ip_address(validate_edge_bind(host))
    unknown = ValueError(f"panel edge network {PANEL_EDGE_NETWORK} could not be inspected")
    try:
        # The rule is about the *network* range the gateway sits in, not the
        # /32 addresses Traefik holds on it -- `traefik_network_subnets` answers
        # that; `traefik_network_cidrs` names Traefik itself.
        raw = traefik.traefik_network_subnets(PANEL_EDGE_NETWORK)
        networks = [ipaddress.ip_network(cidr, strict=False) for cidr in raw]
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise unknown from exc
    if not networks:
        raise unknown
    network = next(
        (candidate for candidate in networks if address.version == candidate.version and address in candidate),
        None,
    )
    if network is None:
        raise ValueError(f"panel edge bind {address} is outside {PANEL_EDGE_NETWORK}")
    if address == network.network_address:
        raise ValueError(f"panel edge bind {address} is the network address of {network}")
    if address.version == 4 and address == network.broadcast_address:
        raise ValueError(f"panel edge bind {address} is the broadcast address of {network}")
    return str(address)


def edge_bind_address() -> str:
    gateway = traefik._network_gateway(PANEL_EDGE_NETWORK)
    if gateway is not None:
        return validate_panel_edge_bind(gateway)
    raise RuntimeError(f"cannot determine a gateway address for {PANEL_EDGE_NETWORK}")


def _target_url(host: str, port: int) -> str:
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ValueError("panel port must be between 1 and 65535")
    # Deliberately the loose check: this renders a config string and must work
    # with no Docker to ask, including in `render_router_config`.
    address = ipaddress.ip_address(validate_edge_bind(host))
    rendered_host = f"[{address}]" if address.version == 6 else str(address)
    return f"http://{rendered_host}:{port}"


def _ensure_dynamic_dir() -> None:
    directory = dynamic_dir()
    if directory.is_symlink():
        raise OSError(f"refusing symlinked Traefik dynamic directory: {directory}")
    directory.mkdir(parents=True, exist_ok=True, mode=0o755)
    os.chmod(directory, 0o755)


def _write_router(content: str) -> None:
    _ensure_dynamic_dir()
    destination = panel_router_path()
    if destination.is_symlink():
        raise OSError(f"refusing symlinked panel router config: {destination}")
    fd, temporary_name = tempfile.mkstemp(prefix=".wpfy-panel-", dir=dynamic_dir(), text=True)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def _install_prerequisites(domain) -> list[str]:
    """Best-effort host prerequisites for a publicly exposed panel.

    ufw and fail2ban are installed (idempotently), and the wpfy cron timers are
    put in place. Every step is recorded as an event and every failure is
    returned as a WARN line instead of failing the exposure: a VPS without
    network access to the apt mirrors must still be able to expose its panel.
    """
    from . import cron, events, firewall_ports
    from .fail2ban_host import ensure_fail2ban_host

    steps = (
        ("ufw", "panel.expose.ufw", firewall_ports.install_ufw),
        ("fail2ban", "panel.expose.fail2ban", ensure_fail2ban_host),
        ("cron timers", "panel.expose.cron-timers", cron.install_timers),
    )
    warnings: list[str] = []
    for label, action, step in steps:
        try:
            result = step()
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            outcome, detail = "failed", str(exc)
        else:
            outcome, detail = ("ok" if result.exit_code == 0 else "failed"), result.message
        events.record_event(action, domain=domain, outcome=outcome, detail=detail)
        if outcome != "ok":
            warnings.append(f"WARN {label}: {detail}")
    return warnings


def expose(domain, *, confirm, port=DEFAULT_PANEL_PORT, no_install=False) -> RuntimeResult:
    try:
        if not isinstance(domain, str):
            raise TypeError("panel domain must be a string")
        validate_domain(domain)
        if confirm != domain:
            return RuntimeResult(2, f"confirmation must exactly match {domain}")
        preflight = certificate_lifecycle.preflight_ssl(domain)
        if not preflight.passed:
            return RuntimeResult(2, preflight.message)
        # The site path has refused without a real contact address since ADR
        # 0016; this path did not, so `expose --domain` reported success and
        # then Traefik failed at ACME account registration -- "contact email has
        # invalid domain" -- leaving a panel that answers only with Traefik's
        # self-signed default and no clue why.
        email_problem = traefik.acme_email_problem()
        if email_problem:
            return RuntimeResult(2, email_problem)

        prerequisite_warnings = [] if no_install else _install_prerequisites(domain)

        if not traefik.runtime_skip_requested() and traefik.docker_available():
            pull_result = traefik._pull_traefik_image()
            if pull_result.exit_code != 0:
                return pull_result
        with traefik.traefik_transaction():
            traefik._ensure_traefik_scaffold()
            start_result = traefik._start_traefik_locked()
        if start_result.exit_code != 0:
            return start_result
        host = edge_bind_address()
        content = render_router_config(domain, _target_url(host, port))
        service_path = panel_service_path()
        if service_path.exists() and service_path.read_text(encoding="utf-8") != panel_service_content(host, port):
            return RuntimeResult(2, "remove the installed panel service before changing its bind or port")
        current = panel_router_path()
        unchanged = current.exists() and current.read_text(encoding="utf-8") == content
        if not unchanged:
            _write_router(content)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        return RuntimeResult(2, str(exc))
    if service_path.exists():
        lines = [f"panel router and service configured for https://{domain}; verify the public URL"]
    else:
        state = "already configured" if unchanged else "configured"
        lines = [f"panel router {state} for https://{domain}; required next: wpfy panel service install"]
    lines.extend(_setup_link_lines(domain))
    lines.extend(prerequisite_warnings)
    return RuntimeResult(0, "\n".join(lines), ran=True)


def _setup_link_lines(domain) -> list[str]:
    """The one-time setup grant for a panel with no account yet.

    A fresh host has no panel user, so the exposed domain would print a sign-in
    instruction that cannot be satisfied. Mirror the domainless mode: mint a
    single-use setup secret and hand the operator its link. The secret lives
    only in this returned message -- never in events or logs.
    """
    from . import panel_setup

    if panel_auth.login_required():
        return []
    secret = panel_setup.issue_setup_secret()
    return [
        f"no panel account exists yet; open https://{domain}/#setup={secret} to create it "
        f"(single-use, expires in {panel_setup.SETUP_SECRET_TTL_SECONDS // 60} minutes)",
    ]


def _router_details() -> dict | None:
    path = panel_router_path()
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None
    domain_match = _DOMAIN_RULE_RE.search(text)
    target_match = re.search(r'^\s*- url: "([^"]+)"\s*$', text, re.MULTILINE)
    if not domain_match or not target_match:
        return None
    domain = domain_match.group(1)
    target_url = target_match.group(1)
    try:
        validate_domain(domain)
        _validated_target_url(target_url)
        parsed = urlsplit(target_url)
        # Reading a file off disk must not require inspecting a Docker network:
        # status is most wanted precisely when the daemon is unreachable.
        host = validate_edge_bind(parsed.hostname)
        port = parsed.port
        # Re-render with the credential the file itself carries, not the one
        # stored now. Storing a credential changes what `render_router_config`
        # produces, so comparing against today's version made a router wpfy had
        # just written unrecognisable the moment basic auth was configured --
        # and `set_panel_basic_auth` only rewrites a router it recognises, so
        # the credential could never be applied at all.
        found = _BASIC_AUTH_USER_RE.search(text)
        if render_router_config(domain, target_url, found.group(1) if found else None) != text:
            return None
    except (RuntimeError, TypeError, ValueError):
        return None
    return {"domain": domain, "target_host": host, "target_port": port}


def exposure_status() -> dict:
    path = panel_router_path()
    router_present = path.exists()
    details = _router_details()
    return {
        "exposed": router_present,
        "recognised": details is not None,
        "domain": details["domain"] if details else None,
        "target_host": details["target_host"] if details else None,
        "target_port": details["target_port"] if details else None,
        "router_present": router_present,
        "router_path": str(path),
        "service_installed": panel_service_path().exists(),
    }


def panel_service_content(host, port) -> str:
    host = validate_panel_edge_bind(host)
    _target_url(host, port)
    command = systemd.command_line([
        "/usr/local/bin/wpfy", "panel", "--host", host, "--port", str(port), "--edge-service",
    ])
    return "\n".join([
        "[Unit]",
        "Description=wpfy browser panel",
        "After=docker.service network-online.target",
        "Wants=network-online.target",
        "",
        "[Service]",
        "Type=simple",
        f"ExecStart={command}",
        "Restart=on-failure",
        "RestartSec=5s",
        "NoNewPrivileges=true",
        "",
        "[Install]",
        "WantedBy=multi-user.target",
        "",
    ])


def install_service(host, port) -> RuntimeResult:
    try:
        content = panel_service_content(host, port)
        if not exposure_status()["exposed"]:
            return RuntimeResult(2, "expose the panel router before installing the panel service")
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        return RuntimeResult(2, str(exc))

    path = panel_service_path()
    result = systemd.install_units({path: content}, [_SERVICE_NAME], "panel service installed")
    if result.exit_code != 0:
        path.unlink(missing_ok=True)
    return result


def remove_service() -> RuntimeResult:
    path = panel_service_path()
    if not path.exists():
        return RuntimeResult(0, "panel service is not installed")
    return systemd.disable_units([_SERVICE_NAME], [path], "panel service removed")


def disable() -> RuntimeResult:
    errors: list[str] = []
    try:
        panel_router_path().unlink(missing_ok=True)
    except OSError as exc:
        errors.append(str(exc))
    service_result = remove_service()
    if service_result.exit_code != 0:
        errors.append(service_result.message)
    if errors:
        return RuntimeResult(1, "; ".join(errors))
    return RuntimeResult(0, "panel exposure disabled", ran=True)


# ---------------------------------------------------------------------------
# Domainless exposure
#
# `expose(domain)` puts the panel behind Traefik with an ACME certificate. Not
# every operator has a domain, so this binds the panel directly on a public
# address instead. No CA issues certificates for a bare IP, so the connection is
# carried by a self-signed certificate whose fingerprint is printed next to the
# URL -- a browser warning an operator can verify, rather than one they are
# trained to click through.
#
# Plaintext was considered and rejected: first-run account creation sends a
# password and a TOTP secret, and every request afterwards carries a bearer
# token. On the open internet all three are readable by anyone on the path.
# ---------------------------------------------------------------------------

DOMAINLESS_PANEL_PORT = 3939


def display_host(host: str) -> str:
    """Bracket IPv6 addresses for use inside a URL; leave everything else."""
    try:
        address = ipaddress.ip_address(str(host))
    except ValueError:
        return str(host)
    return f"[{address}]" if address.version == 6 else str(address)


def public_bind_address() -> str:
    """The address a domainless panel should listen on.

    Deliberately not `0.0.0.0`: the operator is told exactly which address the
    panel answers on, and the certificate is issued for that address, so the
    fingerprint they verify belongs to a name the browser actually saw.
    """
    ipv4, ipv6 = certificate_lifecycle.detect_public_ips()
    for candidate in (*ipv4, *ipv6):
        try:
            return validate_edge_bind(candidate)
        except ValueError:
            continue
    raise RuntimeError(
        "cannot determine a public address for this host; expose the panel with a domain instead"
    )


def domainless_status() -> dict:
    from . import panel_tls

    certificate = panel_tls.certificate_path()
    if not certificate.exists():
        return {"configured": False, "port": DOMAINLESS_PANEL_PORT}
    try:
        fingerprint = panel_tls.fingerprint_of(certificate)
    except (OSError, ValueError):
        fingerprint = None
    return {
        "configured": True,
        "port": DOMAINLESS_PANEL_PORT,
        "certificate": str(certificate),
        "fingerprint": fingerprint,
    }


def expose_without_domain(*, confirm: object, port: int = DOMAINLESS_PANEL_PORT,
                          no_install: bool = False) -> RuntimeResult:
    """Prepare a public, self-signed, domainless panel.

    Returns the URL to open and the certificate fingerprint to check against the
    browser warning. When no panel account exists yet, a one-time setup secret is
    minted and embedded in the URL: over a tunnel-less public address it stands
    in for the SSH tunnel that first-run setup would otherwise require.
    """
    from . import panel_setup, panel_tls

    if confirm != "expose":
        return RuntimeResult(2, 'confirmation must be exactly "expose"')
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        return RuntimeResult(2, "panel port must be between 1 and 65535")

    try:
        host = public_bind_address()
    except RuntimeError as exc:
        return RuntimeResult(2, str(exc))

    prerequisite_warnings = [] if no_install else _install_prerequisites(None)

    try:
        certificate = panel_tls.ensure_self_signed(host)
    except (OSError, RuntimeError, ValueError) as exc:
        return RuntimeResult(2, str(exc))

    url = f"https://{display_host(host)}:{port}/"
    lines = [
        f"panel: {url}",
        f"certificate fingerprint (SHA-256): {certificate.fingerprint}",
    ]

    if not panel_auth.login_required():
        secret = panel_setup.issue_setup_secret()
        lines.insert(0, f"panel: {url}#setup={secret}")
        lines[1] = f"panel (no account yet, open the link above): {url}"
        lines.append(
            f"the setup link is single-use and expires in "
            f"{panel_setup.SETUP_SECRET_TTL_SECONDS // 60} minutes"
        )

    lines.append(
        "the browser will warn that this certificate is untrusted -- that is expected for a "
        "bare address; check the fingerprint above before continuing"
    )
    # The panel is a host process, so ufw applies to it -- unlike the Docker
    # published ports, which bypass ufw's INPUT chain entirely. An operator with
    # the firewall on otherwise gets a panel that starts, reports the right URL,
    # and times out from everywhere.
    from . import firewall_ports

    if firewall_ports.port_allowed(port) is False:
        lines.append(
            f"the firewall is active and does not allow {port}/tcp; the panel will be "
            f"unreachable until you run: ufw allow {port}/tcp"
        )

    start = "wpfy panel --public" + (f" --port {port}" if port != DOMAINLESS_PANEL_PORT else "")
    lines.append(f"start the panel with: {start}")
    lines.extend(prerequisite_warnings)
    return RuntimeResult(0, "\n".join(lines), ran=True)


# ---------------------------------------------------------------------------
# Panel basic auth
#
# A second gate in front of the panel's own login form, applied to the public
# Traefik router only. Loopback and the SSH tunnel stay unguarded deliberately:
# a forgotten credential has to be recoverable, and the tunnel is the recovery
# path. It is also the only place the gate does anything -- a scanner reaching
# the public domain is refused before the login form is served.
# ---------------------------------------------------------------------------

_BASIC_AUTH_FILE = "panel-basic-auth"
_SAFE_BASIC_AUTH_USERNAME = re.compile(r"^[A-Za-z0-9._@-]{1,64}$")


def panel_basic_auth_path() -> Path:
    from . import settings

    return Path(settings.PATHS.config_dir) / _BASIC_AUTH_FILE


def read_panel_basic_auth() -> str | None:
    """The stored `user:hash` line, or None. Never the password."""
    try:
        line = panel_basic_auth_path().read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError):
        return None
    return line or None


def panel_basic_auth_status() -> dict:
    line = read_panel_basic_auth()
    return {
        "enabled": line is not None,
        "username": line.split(":", 1)[0] if line else None,
    }


def panel_basic_auth_enforcement() -> str:
    """What actually gates the public domain right now?

    enforced  a recognized router's basicAuth middleware carries exactly the
              stored credential
    staged    a credential is stored, and verifiably nothing enforces it --
              no router file at all, or a recognized router without
              basicAuth middleware
    stale     a recognized router enforces a DIFFERENT credential than the
              one stored here -- or enforces one while nothing is stored
              (orphaned). The old prompt is still live either way; the
              operator must rotate or disable to take over.
    unknown   a router exists but wpfy cannot attribute it to itself
              (unreadable, malformed, or unrecognized), so enforcement can
              be verified neither way; an unmanaged router may be prompting
    off       nothing stored and verifiably no middleware anywhere

    Derived from the router's own rendered content, never from intent: the
    UI must not claim the public domain is guarded -- or unguarded -- when
    disk says otherwise.
    """
    stored_line = read_panel_basic_auth()
    try:
        text = panel_router_path().read_text(encoding="utf-8")
    except FileNotFoundError:
        text = None
    except (OSError, UnicodeError):
        return "unknown"
    if text is None:
        return "staged" if stored_line else "off"
    if _router_details() is None:
        return "unknown"
    found = _BASIC_AUTH_USER_RE.search(text)
    if found is None:
        return "staged" if stored_line else "off"
    if stored_line and found.group(1) == stored_line:
        return "enforced"
    return "stale"


def set_panel_basic_auth(username: str, password: str) -> RuntimeResult:
    """Store a credential for the public router. The password is not kept."""
    # APR1, not the sha512crypt `_htpasswd_hash` the per-site gate uses. That
    # one is verified by nginx, which hashes through crypt(3) and takes `$6$`.
    # This one is verified by Traefik, whose basicAuth understands MD5-APR1,
    # SHA1 and bcrypt only -- a `$6$` line loads without complaint and then
    # rejects the correct password forever.
    from .site_security import _htpasswd_apr1

    if not isinstance(username, str) or not _SAFE_BASIC_AUTH_USERNAME.fullmatch(username):
        return RuntimeResult(2, "basic-auth username may use 1-64 letters, digits, '_', '.', '@', or '-'")
    if not isinstance(password, str) or len(password) < 12:
        return RuntimeResult(2, "basic-auth password must be at least 12 characters")

    hashed = _htpasswd_apr1(password)
    path = panel_basic_auth_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    # Written in place with a restrictive mode: the hash is not a password, but
    # it is offline-crackable and there is no reason for it to be readable.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(f"{username}:{hashed}\n")
    os.chmod(path, 0o600)

    status = exposure_status()
    if status.get("exposed") and status.get("domain"):
        refreshed = _rewrite_router(status["domain"], status.get("target_host"), status.get("target_port"))
        if refreshed.exit_code != 0:
            return refreshed
        return RuntimeResult(0, f"panel basic auth enabled for {username}; the public router now requires it", ran=True)
    return RuntimeResult(0, f"panel basic auth stored for {username}; it applies when the panel is published", ran=True)


def clear_panel_basic_auth() -> RuntimeResult:
    # Convergent disable: the credential file is removed only after its bytes
    # and mode are captured, and a failed router rewrite restores both so disk
    # state matches the still-enforced router. A retry where the file is
    # already gone but the router is stale still rewrites the router -- the
    # previous version returned "not configured" and never repaired it.
    path = panel_basic_auth_path()
    try:
        previous = path.read_bytes()
        previous_mode = stat.S_IMODE(path.stat().st_mode)
    except FileNotFoundError:
        previous = None
        previous_mode = None
    except OSError as exc:
        return RuntimeResult(1, str(exc))

    if previous is not None:
        try:
            path.unlink()
        except OSError as exc:
            return RuntimeResult(1, str(exc))

    status = exposure_status()
    if status.get("exposed") and status.get("domain"):
        refreshed = _rewrite_router(status["domain"], status.get("target_host"), status.get("target_port"))
        if refreshed.exit_code != 0:
            if previous is not None:
                try:
                    path.write_bytes(previous)
                    os.chmod(path, previous_mode)
                except OSError as exc:
                    return RuntimeResult(
                        refreshed.exit_code,
                        f"{refreshed.message}; credential restore also failed ({exc}) -- run disable again to converge",
                    )
            return refreshed
    elif status.get("exposed") and not status.get("domain"):
        # The panel is published but wpfy does not recognize the router that
        # serves it, so basic auth may still be enforced out-of-band. Removing
        # the credential here would report success while the prompt survives.
        if previous is not None:
            try:
                path.write_bytes(previous)
                os.chmod(path, previous_mode)
            except OSError as exc:
                return RuntimeResult(1, f"credential restore failed ({exc}) -- run disable again to converge")
        return RuntimeResult(
            1,
            "panel is exposed but no managed router was recognized; "
            "basic auth stays configured -- resolve the router manually, then disable again",
        )
    elif previous is None:
        # Nothing was configured and there is no router to repair.
        return RuntimeResult(0, "panel basic auth was not configured", ran=False)
    return RuntimeResult(0, "panel basic auth removed", ran=True)


def _rewrite_router(domain: str, host: object, port: object) -> RuntimeResult:
    """Re-render the router so a credential change takes effect immediately.

    Without this the file on disk still carries the previous middleware list and
    the change only lands the next time someone re-exposes the panel -- which
    reads, to the operator, as the credential not working.
    """
    try:
        target = _target_url(str(host), int(port)) if host and port else None
    except (TypeError, ValueError):
        target = None
    if target is None:
        return RuntimeResult(2, "the panel router is unrecognised; re-run wpfy panel expose to rewrite it")
    try:
        panel_router_path().write_text(render_router_config(domain, target), encoding="utf-8")
    except OSError as exc:
        return RuntimeResult(1, str(exc))
    return RuntimeResult(0, "router updated", ran=True)
