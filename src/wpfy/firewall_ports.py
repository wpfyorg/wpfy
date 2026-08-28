"""Host port management on top of ``ufw``.

The rest of the firewall surface (``fail2ban_host``/``fail2ban_docker``) reacts
to behaviour: it bans an address that already got in and misbehaved. This module
covers the other half -- which ports accept a connection at all.

wpfy installs ``ufw`` itself rather than leaving it to the operator:
:func:`install_ufw` runs during ``wpfy panel expose`` (unless the caller passes
``--no-install``) and from ``wpfy stack install --ufw``. It is idempotent --
when the binary is already present it reports a skipped success instead of
reaching for apt. fail2ban is ensured by :mod:`wpfy.fail2ban_host` on the same
paths.

Lockout is the failure mode that matters. A rule set that drops SSH cannot be
repaired from the panel, because the panel is reached over the connection the
rule just killed. Two guards, both here rather than in the caller:

* :func:`enable` allows the detected SSH port *before* it turns the firewall on,
  always, even when the caller did not ask.
* :func:`deny_port` and :func:`delete_rule` refuse to touch the SSH port unless
  the caller passes ``force=True``. The panel maps that to a typed confirmation.

Neither guard can save an operator who denies SSH from a shell, and neither is
a substitute for out-of-band console access. They only stop the panel from
being the thing that did it.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import ipaddress
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
from typing import cast

from .site_runtime import RuntimeResult
from .traefik import PANEL_EDGE_NETWORK, PanelEdgeNetworkFacts

DEFAULT_SSH_PORT = 22
_PORT_RANGE = re.compile(r"^(\d{1,5})(?::(\d{1,5}))?$")
_COMMENT_ALLOWED = re.compile(r"^[A-Za-z0-9 ._-]{1,64}$")
_PROTOCOLS = ("tcp", "udp")
_ACTIONS = ("allow", "deny", "reject")
PANEL_EDGE_RULE_COMMENT = "wpfy panel edge ingress"
PANEL_EDGE_RULE_MARKER = PANEL_EDGE_RULE_COMMENT
_LINUX_INTERFACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$")
_RFC1918_NETWORKS: tuple[ipaddress.IPv4Network, ...] = (
    cast(ipaddress.IPv4Network, ipaddress.ip_network("10.0.0.0/8")),
    cast(ipaddress.IPv4Network, ipaddress.ip_network("172.16.0.0/12")),
    cast(ipaddress.IPv4Network, ipaddress.ip_network("192.168.0.0/16")),
)
_ULA_NETWORK = cast(ipaddress.IPv6Network, ipaddress.ip_network("fc00::/7"))

# `To` column of `ufw status`: "22/tcp", "22", "2200:2210/udp", with an
# optional " (v6)" suffix on the IPv6 twin of a rule.
_RULE_LINE = re.compile(
    r"^(?P<target>\S+?)(?P<v6>\s+\(v6\))?\s+"
    r"(?P<action>ALLOW|DENY|REJECT|LIMIT)(?P<direction>\s+(?:IN|OUT|FWD))?\s+"
    r"(?P<source>.+?)\s*$"
)

# `ufw show added` -- the only listing that survives the firewall being off.
# Two grammars come back: the shorthand ufw normalises anywhere-rules into
# ("ufw allow 22/tcp comment 'x'") and the long form it keeps when the rule
# carries a source ("ufw allow from 10.0.0.0/8 to any port 8080 proto tcp").
_ADDED_LINE = re.compile(
    r"^ufw\s+(?P<action>allow|deny|reject|limit)\b(?:\s+(?:in|out))?\s+(?P<rest>.+?)"
    r"(?:\s+comment\s+'(?P<comment>[^']*)')?\s*$",
    re.IGNORECASE,
)
_ADDED_LONG = re.compile(
    r"^from\s+(?P<source>\S+)\s+to\s+\S+\s+port\s+(?P<port>[\d:]+)"
    r"(?:\s+proto\s+(?P<protocol>\w+))?\s*$",
    re.IGNORECASE,
)
_ADDED_SHORT = re.compile(r"^(?P<port>[\d:]+)(?:/(?P<protocol>\w+))?\s*$")


@dataclass(frozen=True, slots=True)
class PortRule:
    port: str
    protocol: str
    action: str
    source: str
    v6: bool
    #: ufw prints the rule comment inside the `From` column, padded. Left in
    #: `source` it becomes a source the panel renders and then sends back on
    #: delete, where it is rejected as an address -- so it is split out here.
    comment: str = ""


@dataclass(frozen=True, slots=True)
class PanelEdgeRuleSpec:
    """One fully scoped, WPFY-owned ingress rule for the panel edge."""

    port: str
    bridge: str
    subnet: str
    gateway: str
    protocol: str = "tcp"
    comment: str = PANEL_EDGE_RULE_COMMENT


@dataclass(frozen=True, slots=True)
class FirewallStatus:
    installed: bool
    active: bool
    default_incoming: str
    default_outgoing: str
    ssh_port: int
    rules: tuple[PortRule, ...]
    message: str
    #: False when nothing was read -- ufw absent, the probe failed, or the
    #: runtime skip is set. `active=False` then means "not known", not "off",
    #: and a caller that renders it as "off" is stating something it never
    #: checked. An empty rule list means the same thing.
    checked: bool = True


#: Ports an operator commonly wants, and the ones they commonly regret. The
#: `caution` entries are reachable from the panel but carry the warning with
#: them -- a database port open to the world is the single most common way one
#: of these boxes is lost, and a preset list that presents 3306 as neutral is
#: worse than no preset list.
PRESETS: tuple[dict[str, object], ...] = (
    {"label": "SSH", "port": "22", "protocol": "tcp", "note": "Remote shell. Closing this locks you out."},
    {"label": "HTTP", "port": "80", "protocol": "tcp", "note": "Required for Let's Encrypt HTTP-01 challenges."},
    {"label": "HTTPS", "port": "443", "protocol": "tcp", "note": "Required for every site served over TLS."},
    {"label": "SFTP (wpfy sites)", "port": "2222:2299", "protocol": "tcp",
     "note": "Range wpfy assigns to per-site SFTP containers."},
    {"label": "MySQL", "port": "3306", "protocol": "tcp", "caution": True,
     "note": "Site databases are reachable inside Docker already. Open this only for an external client, and prefer a source restriction."},
    {"label": "Redis", "port": "6379", "protocol": "tcp", "caution": True,
     "note": "Object caches are reachable inside Docker already. An open Redis port is remote code execution."},
    {"label": "Mail submission", "port": "587", "protocol": "tcp",
     "note": "Only needed if this host sends mail directly rather than through a relay."},
)


def _ufw_binary() -> str:
    return os.environ.get("WPFY_UFW_BIN", "ufw")


def _skip_runtime() -> bool:
    return os.environ.get("WPFY_SKIP_RUNTIME") == "1"


def ufw_available() -> bool:
    return shutil.which(_ufw_binary()) is not None


def _apt_install(package: str, *, timeout: int = 300) -> RuntimeResult:
    """Install a Debian package. The caller decides whether that is wanted."""
    try:
        proc = subprocess.run(
            ["apt-get", "-o", "DPkg::Lock::Timeout=300", "install", "-y", package],
            check=False, capture_output=True, text=True, timeout=timeout,
            env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"},
        )
    except FileNotFoundError:
        return RuntimeResult(127, "apt-get is not available on this host")
    except subprocess.TimeoutExpired:
        return RuntimeResult(1, f"apt-get did not respond within {timeout} seconds while installing {package}")
    except (OSError, subprocess.SubprocessError) as exc:
        return RuntimeResult(1, f"apt-get install {package} failed: {exc}")
    output = (proc.stdout or "").strip()
    error = (proc.stderr or "").strip()
    if proc.returncode != 0:
        return RuntimeResult(proc.returncode, error or output or f"apt-get install {package} failed")
    return RuntimeResult(0, f"installed {package} via apt-get", ran=True)


def install_ufw() -> RuntimeResult:
    """Make sure the ``ufw`` package exists; succeed idempotently when it does."""
    if ufw_available():
        return RuntimeResult(0, "ufw is already installed", skipped=True)
    if _skip_runtime():
        return RuntimeResult(0, "skipped by WPFY_SKIP_RUNTIME", skipped=True)
    return _apt_install("ufw")


def _run(args: list[str]) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            [_ufw_binary(), *args], check=False, capture_output=True, text=True, timeout=30,
        )
    except FileNotFoundError:
        return 127, "ufw is not installed on this host"
    except subprocess.TimeoutExpired:
        return 1, "ufw did not respond within 30 seconds"
    output = (proc.stdout or "").strip()
    error = (proc.stderr or "").strip()
    return proc.returncode, output if proc.returncode == 0 else (error or output or "ufw failed")


def ssh_port() -> int:
    """The port sshd actually listens on, so the guards protect the right one.

    A host moved off 22 and guarded on 22 is guarded on nothing. Only an
    uncommented, numeric ``Port`` directive counts; anything else falls back to
    22, which is the safer wrong answer -- it protects a port that may not need
    it rather than leaving the real one exposed to a delete.
    """
    config = Path(os.environ.get("WPFY_SSHD_CONFIG", "/etc/ssh/sshd_config"))
    try:
        for line in config.read_text(encoding="utf-8", errors="replace").splitlines():
            stripped = line.strip()
            if not stripped.lower().startswith("port "):
                continue
            value = stripped.split(None, 1)[1].strip()
            if value.isdigit() and 1 <= int(value) <= 65535:
                return int(value)
    except OSError:
        pass
    return DEFAULT_SSH_PORT


def validate_port(value: str) -> str:
    """Accept ``"443"`` or ``"2200:2210"``; reject everything else."""
    match = _PORT_RANGE.match(str(value).strip())
    if not match:
        raise ValueError(f"invalid port: {value!r}; use a number or a low:high range")
    low = int(match.group(1))
    high = int(match.group(2)) if match.group(2) else low
    if not (1 <= low <= 65535 and 1 <= high <= 65535):
        raise ValueError(f"port out of range: {value!r}")
    if high < low:
        raise ValueError(f"port range is inverted: {value!r}")
    return f"{low}:{high}" if match.group(2) else str(low)


def validate_protocol(value: str) -> str:
    protocol = str(value or "").strip().lower()
    if protocol not in _PROTOCOLS:
        raise ValueError(f"invalid protocol: {value!r}; accepted values: {', '.join(_PROTOCOLS)}")
    return protocol


def validate_source(value: str | None) -> str | None:
    """A single address or CIDR block, normalised. ``None`` means anywhere."""
    if value is None or str(value).strip() == "":
        return None
    source = str(value).strip()
    try:
        return str(ipaddress.ip_network(source, strict=False))
    except ValueError as exc:
        raise ValueError(f"invalid source address: {value!r}") from exc


def validate_comment(value: str | None) -> str | None:
    if value is None or str(value).strip() == "":
        return None
    comment = str(value).strip()
    if not _COMMENT_ALLOWED.match(comment):
        raise ValueError("comment may use letters, numbers, spaces, dots, underscores and hyphens only")
    if comment.startswith("-"):
        # argv keeps this out of the shell, but a leading dash still reaches
        # ufw's own option parser as something that looks like a flag.
        raise ValueError("comment may not start with a hyphen")
    return comment


def _covers_ssh(port: str, protocol: str) -> bool:
    """True when a rule on `port` would take the SSH port with it."""
    if protocol == "udp":
        return False
    target = ssh_port()
    low, _, high = port.partition(":")
    return int(low) <= target <= int(high or low)


def _source_is_ipv6(source: str) -> bool:
    """True when a ufw rule source is a literal IPv6 address or network."""
    candidate = source.replace("(v6)", "").strip()
    if not candidate or candidate.lower() == "anywhere":
        return False
    try:
        return ipaddress.ip_network(candidate, strict=False).version == 6
    except ValueError:
        return False


def _collapse(rules: list[PortRule]) -> tuple[PortRule, ...]:
    """One row per rule the operator wrote, not one per address family.

    ufw prints an IPv6 twin for every anywhere-rule, so a single "allow 22/tcp"
    lists twice. Two rows with two delete buttons, where deleting either removes
    both, describes the rule set as something it is not. The twin is folded into
    the v4 row; ``v6`` survives only on a rule that really is IPv6-only.
    """
    seen: dict[tuple[str, str, str, str], PortRule] = {}
    for rule in rules:
        source = rule.source.replace("(v6)", "").strip() or "Anywhere"
        key = (rule.port, rule.protocol, rule.action, source)
        if key in seen and not seen[key].v6:
            continue  # the v4 row already speaks for this rule
        seen[key] = PortRule(rule.port, rule.protocol, rule.action, source, rule.v6, rule.comment)
    return tuple(seen.values())


def parse_added(output: str) -> tuple[PortRule, ...]:
    """Parse ``ufw show added``. Kept pure so the tests need no ufw."""
    rules: list[PortRule] = []
    for line in output.splitlines():
        head = _ADDED_LINE.match(line.strip())
        if not head:
            continue
        rest = head.group("rest").strip()
        body = _ADDED_LONG.match(rest) or _ADDED_SHORT.match(rest)
        if not body:
            continue  # named profiles ("ufw allow OpenSSH"), routed rules
        port = body.group("port")
        if not _PORT_RANGE.match(port):
            continue
        source = "Anywhere"
        if "source" in body.groupdict():
            candidate = body.group("source")
            source = "Anywhere" if candidate.lower() == "any" else candidate
        rules.append(PortRule(
            port=port,
            protocol=(body.groupdict().get("protocol") or "any").lower(),
            action=head.group("action").lower(),
            source=source,
            v6=False,
            comment=(head.group("comment") or "").strip(),
        ))
    return _collapse(rules)


def parse_status(output: str) -> FirewallStatus:
    """Parse ``ufw status verbose``. Kept pure so the tests need no ufw."""
    active = False
    default_in = default_out = "unknown"
    rules: list[PortRule] = []
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("status:"):
            active = stripped.split(":", 1)[1].strip().lower() == "active"
            continue
        if stripped.lower().startswith("default:"):
            for part in stripped.split(":", 1)[1].split(","):
                words = part.strip().split()
                if len(words) < 2:
                    continue
                where = words[1].strip("()")
                if where == "incoming":
                    default_in = words[0]
                elif where == "outgoing":
                    default_out = words[0]
            continue
        if not stripped or stripped.startswith("--") or stripped.startswith("To "):
            continue
        if stripped.lower().startswith(("logging:", "new profiles:", "anywhere on")):
            continue
        match = _RULE_LINE.match(stripped)
        if not match:
            continue
        target = match.group("target")
        port, _, protocol = target.partition("/")
        if not _PORT_RANGE.match(port.replace("(v6)", "").strip()):
            continue  # named application profiles ("OpenSSH", "Nginx Full")
        source, _, comment = match.group("source").partition("#")
        source = source.strip()
        rules.append(PortRule(
            port=port.strip(),
            protocol=protocol.strip() or "any",
            action=match.group("action").lower(),
            source=source,
            # ufw prints the "(v6)" marker only on the Anywhere twins, so a
            # rule written against a literal IPv6 source ("allow 9443/tcp from
            # 2001:db8::/32") carries no marker at all. Reading the family off
            # the source is what makes `_collapse`'s promise true.
            v6=bool(match.group("v6")) or _source_is_ipv6(source),
            comment=comment.strip(),
        ))
    return FirewallStatus(
        installed=True, active=active, default_incoming=default_in, default_outgoing=default_out,
        ssh_port=ssh_port(), rules=_collapse(rules),
        message="firewall is active" if active else "firewall is installed but not enabled",
    )


def status() -> FirewallStatus:
    if not ufw_available():
        return FirewallStatus(
            installed=False, active=False, default_incoming="unknown", default_outgoing="unknown",
            ssh_port=ssh_port(), rules=(), checked=False,
            message="ufw is not installed on this host; install it with: apt-get install -y ufw",
        )
    if _skip_runtime():
        return FirewallStatus(
            installed=True, active=False, default_incoming="unknown", default_outgoing="unknown",
            ssh_port=ssh_port(), rules=(), checked=False, message="skipped by WPFY_SKIP_RUNTIME",
        )
    code, output = _run(["status", "verbose"])
    if code != 0:
        return FirewallStatus(
            installed=True, active=False, default_incoming="unknown", default_outgoing="unknown",
            ssh_port=ssh_port(), rules=(), checked=False, message=output,
        )
    parsed = parse_status(output)
    if parsed.active:
        return parsed
    # An inactive ufw prints "Status: inactive" and nothing else -- no rule
    # list at all. Reporting that as an empty rule set is wrong twice over: the
    # rules exist and will apply the moment the firewall comes up, and an
    # operator shown "no rules" adds the port again, so enabling it applies a
    # set of duplicates nobody asked for. `show added` is the only listing that
    # survives the firewall being off.
    added_code, added_output = _run(["show", "added"])
    if added_code != 0:
        return parsed
    return replace(parsed, rules=parse_added(added_output))


def port_allowed(port: int, protocol: str = "tcp") -> bool | None:
    """Whether an active firewall lets `port` through. None when nothing is known.

    None is not False: ufw absent, unreadable, or skipped means the caller may
    not tell the operator their port is blocked when it never looked.
    """
    state = status()
    if not state.checked:
        return None
    if not state.active:
        return True
    for rule in state.rules:
        if rule.action != "allow" or rule.protocol not in (protocol, "any"):
            continue
        low, _, high = rule.port.partition(":")
        try:
            if int(low) <= port <= int(high or low):
                return True
        except ValueError:
            continue
    return False


def _rule_spec(port: str, protocol: str, source: str | None, comment: str | None) -> list[str]:
    """ufw's own grammar: `allow from <src> to any port <p> proto <proto>`.

    The verbose form is used even for the anywhere case so that adding and
    deleting a rule go through one spec builder -- `ufw delete` matches on the
    rule text, and a delete written in a different shorthand than the add
    silently matches nothing and reports success.
    """
    spec = ["from", source or "any", "to", "any", "port", port, "proto", protocol]
    if comment:
        spec += ["comment", comment]
    return spec


def _guard(port: str, protocol: str, force: bool, verb: str) -> RuntimeResult | None:
    if force or not _covers_ssh(port, protocol):
        return None
    return RuntimeResult(
        1,
        f"refusing to {verb} port {port}/{protocol}: it carries SSH on port {ssh_port()}, "
        "and this panel is reached over that connection",
    )


def _mutate(args: list[str], success: str) -> RuntimeResult:
    if not ufw_available():
        return RuntimeResult(1, "ufw is not installed on this host; install it with: apt-get install -y ufw")
    if _skip_runtime():
        return RuntimeResult(0, "skipped by WPFY_SKIP_RUNTIME", skipped=True)
    code, output = _run(args)
    if code != 0:
        return RuntimeResult(code, output)
    return RuntimeResult(0, success, ran=True)


def _private_panel_edge_subnet(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("panel edge subnet must be a private CIDR")
    try:
        network = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError as exc:
        raise ValueError(f"invalid panel edge subnet: {value!r}") from exc
    if network.version == 4:
        private = any(cast(ipaddress.IPv4Network, network).subnet_of(candidate) for candidate in _RFC1918_NETWORKS)
    else:
        private = cast(ipaddress.IPv6Network, network).subnet_of(_ULA_NETWORK)
    if not private:
        raise ValueError(f"panel edge subnet must be RFC1918 or ULA, got {network}")
    return str(network)


def _panel_edge_gateway(value: object, subnet: str) -> str:
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        gateway = ipaddress.ip_address(str(value).strip())
    except (AttributeError, ValueError) as exc:
        raise ValueError(f"invalid panel edge gateway: {value!r}") from exc
    if gateway.version != network.version or gateway.is_unspecified or gateway not in network:
        raise ValueError(f"panel edge gateway {value!r} is outside private subnet {subnet}")
    if gateway == network.network_address:
        raise ValueError(f"panel edge gateway {gateway} cannot be the network address")
    if network.version == 4 and network.prefixlen < 31 and gateway == network.broadcast_address:
        raise ValueError(f"panel edge gateway {gateway} cannot be the broadcast address")
    return str(gateway)


def _panel_edge_bridge(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("panel edge bridge interface must be a Linux interface name")
    bridge = value.strip()
    if not _LINUX_INTERFACE_RE.fullmatch(bridge) or bridge.lower() in {"any", "all"}:
        raise ValueError(f"invalid panel edge bridge interface: {value!r}")
    return bridge


def _panel_edge_spec(
    port: str | int,
    facts: PanelEdgeNetworkFacts | None = None,
    *,
    network_facts: PanelEdgeNetworkFacts | None = None,
    bridge: str | None = None,
    subnet: str | None = None,
    gateway: str | None = None,
) -> PanelEdgeRuleSpec:
    if facts is not None and network_facts is not None:
        raise ValueError("provide panel edge network facts once")
    facts = facts if facts is not None else network_facts
    if facts is not None:
        if not isinstance(facts, PanelEdgeNetworkFacts):
            raise ValueError("panel edge facts must be PanelEdgeNetworkFacts")
        if any(value is not None for value in (bridge, subnet, gateway)):
            raise ValueError("do not mix panel edge facts with explicit network fields")
        if facts.network_name != PANEL_EDGE_NETWORK:
            raise ValueError(f"panel edge facts must describe {PANEL_EDGE_NETWORK}")
        if not isinstance(facts.driver, str) or facts.driver.strip().lower() != "bridge":
            raise ValueError(f"unsupported panel edge driver: {facts.driver!r}")
        bridge, subnet, gateway = facts.bridge, facts.subnet, facts.gateway
    elif bridge is None or subnet is None or gateway is None:
        raise ValueError("panel edge network facts or bridge, subnet, and gateway are required")

    validated_port = validate_port(str(port))
    validated_bridge = _panel_edge_bridge(bridge)
    validated_subnet = _private_panel_edge_subnet(subnet)
    validated_gateway = _panel_edge_gateway(gateway, validated_subnet)
    return PanelEdgeRuleSpec(
        port=validated_port,
        bridge=validated_bridge,
        subnet=validated_subnet,
        gateway=validated_gateway,
    )


@dataclass(frozen=True, slots=True)
class _AddedPanelEdgeRule:
    port: str
    bridge: str
    source: str
    destination: str
    protocol: str
    comment: str
    rule_argv: tuple[str, ...]

    def matches(self, spec: PanelEdgeRuleSpec) -> bool:
        return (
            self.port == spec.port
            and self.bridge == spec.bridge
            and self.source == spec.subnet
            and self.destination == spec.gateway
            and self.protocol == spec.protocol
            and self.comment == spec.comment
        )


def _panel_edge_marker(comment: str) -> bool:
    return comment == PANEL_EDGE_RULE_MARKER


def _line_has_exact_panel_edge_marker(line: str) -> bool:
    """Find an exact marker candidate without trusting shell parsing.

    This deliberately recognizes an unterminated quoted marker too. Such a
    line is evidence of a managed rule that cannot be safely removed, not
    evidence that no managed rule exists.
    """
    marker = re.escape(PANEL_EDGE_RULE_MARKER)
    return re.search(
        rf"(?i:\bcomment)\s+(?:['\"]{marker}(?=['\"]|$)|{marker}(?=['\"]|$))",
        line,
    ) is not None


def _panel_edge_parse_failure(line: str, reason: str) -> RuntimeResult:
    return RuntimeResult(
        1,
        f"refusing to change panel edge ingress: exact managed marker rule has {reason}: {line.strip()!r}",
    )


def _normalise_added_source(value: str) -> str | None:
    if value.lower() == "any":
        return "any"
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        return None


def _normalise_added_destination(value: str) -> str | None:
    if value.lower() == "any":
        return "any"
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return None
        if network.prefixlen != network.max_prefixlen:
            return None
        return str(network.network_address)


def _parse_panel_edge_added_line(line: str) -> _AddedPanelEdgeRule | None:
    try:
        tokens = shlex.split(line.strip())
    except ValueError:
        return None
    if len(tokens) < 15 or tokens[1:2] != ["allow"]:
        return None
    # ``ufw show added`` prints the literal command name even when WPFY_UFW_BIN
    # points at an absolute path.  Accept both forms for offline/test wrappers.
    command_name = Path(_ufw_binary()).name
    if tokens[0] not in {"ufw", command_name}:
        return None
    try:
        comment_index = tokens.index("comment", 2)
    except ValueError:
        return None
    if comment_index != len(tokens) - 2 or not _panel_edge_marker(tokens[-1]):
        return None
    rule = tokens[1:comment_index]
    if len(rule) != 12 or rule[0:3] != ["allow", "in", "on"]:
        return None
    if rule[4] != "from" or rule[6] != "to" or rule[8] != "port" or rule[10] != "proto":
        return None
    try:
        port = validate_port(rule[9])
    except ValueError:
        return None
    bridge = rule[3]
    if not _LINUX_INTERFACE_RE.fullmatch(bridge) or bridge.lower() in {"any", "all"}:
        return None
    source = _normalise_added_source(rule[5])
    destination = _normalise_added_destination(rule[7])
    protocol = rule[11].lower()
    if source is None or destination is None or protocol not in {"tcp", "udp", "any"}:
        return None
    return _AddedPanelEdgeRule(
        port=port,
        bridge=bridge,
        source=source,
        destination=destination,
        protocol=protocol,
        comment=tokens[-1],
        rule_argv=tuple(rule + ["comment", tokens[-1]]),
    )


def _panel_edge_added_rules(output: str) -> tuple[_AddedPanelEdgeRule, ...]:
    return tuple(
        parsed
        for line in output.splitlines()
        if (parsed := _parse_panel_edge_added_line(line)) is not None
    )


def _parse_panel_edge_added(output: str) -> tuple[_AddedPanelEdgeRule, ...] | RuntimeResult:
    """Parse managed rules, failing closed on every exact-marker candidate."""
    for line in output.splitlines():
        if not _line_has_exact_panel_edge_marker(line):
            continue
        try:
            tokens = shlex.split(line.strip())
        except ValueError:
            return _panel_edge_parse_failure(line, "malformed quoting")

        if tokens[1:2] != ["allow"]:
            if tokens[1:2] and tokens[1].lower() == "allow":
                return _panel_edge_parse_failure(line, "uppercase action")
            return _panel_edge_parse_failure(line, "unsupported grammar")
        if len(tokens) < 15:
            try:
                comment_index = tokens.index("comment", 2)
            except ValueError:
                return _panel_edge_parse_failure(line, "unsupported grammar")
            rule = tokens[1:comment_index]
            expected_prefix = ["allow", "in", "on"]
            if rule[:len(expected_prefix)] == expected_prefix:
                return _panel_edge_parse_failure(line, "truncated output")
            return _panel_edge_parse_failure(line, "unsupported grammar")
        if _parse_panel_edge_added_line(line) is None:
            return _panel_edge_parse_failure(line, "unsupported grammar")

    return _panel_edge_added_rules(output)


def _panel_edge_added() -> tuple[_AddedPanelEdgeRule, ...] | RuntimeResult:
    if not ufw_available():
        return RuntimeResult(1, "ufw is not installed on this host; install it with: apt-get install -y ufw")
    if _skip_runtime():
        return RuntimeResult(0, "skipped by WPFY_SKIP_RUNTIME", skipped=True)
    code, output = _run(["show", "added"])
    if code != 0:
        return RuntimeResult(code, output)
    return _parse_panel_edge_added(output)


def ensure_panel_edge_rule(
    port: str | int,
    facts: PanelEdgeNetworkFacts | None = None,
    *,
    network_facts: PanelEdgeNetworkFacts | None = None,
    bridge: str | None = None,
    subnet: str | None = None,
    gateway: str | None = None,
) -> RuntimeResult:
    """Stage one exact, WPFY-owned panel-edge ingress rule.

    The rule is persisted even while UFW is inactive; this function never
    enables UFW.  Existing marker variants are removed only after the desired
    rule is present, so a failed add cannot erase the last known-good rule.
    """
    spec = _panel_edge_spec(
        port,
        facts,
        network_facts=network_facts,
        bridge=bridge,
        subnet=subnet,
        gateway=gateway,
    )
    current = _panel_edge_added()
    if isinstance(current, RuntimeResult):
        return current

    desired_seen = False
    stale: list[_AddedPanelEdgeRule] = []
    for rule in current:
        if rule.matches(spec) and not desired_seen:
            desired_seen = True
        else:
            stale.append(rule)

    if not desired_seen:
        added = _mutate(
            [
                "allow",
                "in",
                "on",
                spec.bridge,
                "from",
                spec.subnet,
                "to",
                spec.gateway,
                "port",
                spec.port,
                "proto",
                spec.protocol,
                "comment",
                spec.comment,
            ],
            f"staged panel edge ingress for {spec.port}/{spec.protocol}",
        )
        if added.exit_code != 0:
            return added

    for rule in stale:
        removed = _mutate(
            ["delete", *rule.rule_argv],
            f"removed stale panel edge ingress for {rule.port}/{rule.protocol}",
        )
        if removed.exit_code != 0:
            return removed

    if desired_seen and not stale:
        return RuntimeResult(0, f"panel edge ingress already staged for {spec.port}/{spec.protocol}", ran=True)
    if stale:
        return RuntimeResult(0, f"panel edge ingress staged for {spec.port}/{spec.protocol}; stale rules removed", ran=True)
    return RuntimeResult(0, f"panel edge ingress staged for {spec.port}/{spec.protocol}", ran=True)


def _remove_panel_edge_rules(port: str | None) -> RuntimeResult:
    current = _panel_edge_added()
    if isinstance(current, RuntimeResult):
        return current

    managed = [rule for rule in current if port is None or rule.port == port]
    for rule in managed:
        removed = _mutate(
            ["delete", *rule.rule_argv],
            f"removed panel edge ingress for {rule.port}/{rule.protocol}",
        )
        if removed.exit_code != 0:
            return removed
    if not managed:
        if port is None:
            return RuntimeResult(0, "no managed panel edge ingress rules", ran=True)
        return RuntimeResult(0, f"no managed panel edge ingress for {port}", ran=True)
    return RuntimeResult(0, f"removed {len(managed)} panel edge ingress rule(s)", ran=True)


def remove_panel_edge_rule(
    port: str | int,
    facts: PanelEdgeNetworkFacts | None = None,
    *,
    network_facts: PanelEdgeNetworkFacts | None = None,
    bridge: str | None = None,
    subnet: str | None = None,
    gateway: str | None = None,
) -> RuntimeResult:
    """Remove only marker-tagged panel-edge rules for explicit ``port``."""
    validated_port = validate_port(str(port))
    if any(value is not None for value in (facts, network_facts, bridge, subnet, gateway)):
        _panel_edge_spec(
            validated_port,
            facts,
            network_facts=network_facts,
            bridge=bridge,
            subnet=subnet,
            gateway=gateway,
        )
    return _remove_panel_edge_rules(validated_port)


def remove_all_panel_edge_rules() -> RuntimeResult:
    """Remove every marker-tagged panel-edge rule, regardless of port."""
    return _remove_panel_edge_rules(None)


# Descriptive aliases for callers that use ingress vocabulary.
ensure_panel_edge_ingress = ensure_panel_edge_rule
remove_panel_edge_ingress = remove_panel_edge_rule
ensure_panel_edge_ingress_rule = ensure_panel_edge_rule
remove_panel_edge_ingress_rule = remove_panel_edge_rule
remove_all_panel_edge_ingress = remove_all_panel_edge_rules
remove_panel_edge_rules = remove_all_panel_edge_rules


def allow_port(port: str, protocol: str, *, source: str | None = None, comment: str | None = None) -> RuntimeResult:
    port, protocol = validate_port(port), validate_protocol(protocol)
    source, comment = validate_source(source), validate_comment(comment)
    scope = f" from {source}" if source else ""
    return _mutate(["allow", *_rule_spec(port, protocol, source, comment)],
                   f"allowed {port}/{protocol}{scope}")


def deny_port(port: str, protocol: str, *, source: str | None = None, comment: str | None = None,
              force: bool = False) -> RuntimeResult:
    port, protocol = validate_port(port), validate_protocol(protocol)
    source, comment = validate_source(source), validate_comment(comment)
    blocked = _guard(port, protocol, force, "deny")
    if blocked:
        return blocked
    scope = f" from {source}" if source else ""
    return _mutate(["deny", *_rule_spec(port, protocol, source, comment)],
                   f"denied {port}/{protocol}{scope}")


def delete_rule(port: str, protocol: str, action: str = "allow", *, source: str | None = None,
                force: bool = False) -> RuntimeResult:
    port, protocol = validate_port(port), validate_protocol(protocol)
    source = validate_source(source)
    action = str(action or "").strip().lower()
    if action not in _ACTIONS:
        raise ValueError(f"invalid action: {action!r}; accepted values: {', '.join(_ACTIONS)}")
    blocked = _guard(port, protocol, force, "delete the rule for") if action == "allow" else None
    if blocked:
        return blocked
    return _mutate(["delete", action, *_rule_spec(port, protocol, source, None)],
                   f"removed the {action} rule for {port}/{protocol}")


def enable() -> RuntimeResult:
    """Turn the firewall on, having first guaranteed SSH survives it.

    ``ufw enable`` applies a default-deny to incoming traffic the instant it
    runs. Adding the SSH rule afterwards is one round trip too late: the
    connection carrying the request is already gone.
    """
    if not ufw_available():
        return RuntimeResult(1, "ufw is not installed on this host; install it with: apt-get install -y ufw")
    port = str(ssh_port())
    reserved = allow_port(port, "tcp", comment="wpfy ssh lockout guard")
    if reserved.exit_code != 0:
        return RuntimeResult(reserved.exit_code, f"refusing to enable the firewall: {reserved.message}")
    result = _mutate(["--force", "enable"], f"firewall enabled with SSH ({port}/tcp) allowed")
    return result


def disable() -> RuntimeResult:
    return _mutate(["disable"], "firewall disabled; every port is open again")
