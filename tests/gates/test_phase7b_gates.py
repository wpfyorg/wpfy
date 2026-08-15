"""GATE TESTS — Phase 7b (optional Traefik exposure).

These tests are the security and correctness contract for Phase 7b. They were
written before the implementation and encode decisions, not implementation
details, so a gate failing usually means the product regressed rather than that
the gate is out of date.

They are editable, and were immutable until 2026-08-15. Change one only when
the decision it pins has genuinely changed, never to make a red test green:
say in the commit which decision moved and why, and keep the gate asserting the
new one. A gate deleted or weakened to pass takes its invariant with it.

This file is deliberately self-contained: it depends only on the stdlib and the
`wpfy` package, never on other test modules or shared fixtures.

What this phase can get wrong that nothing else catches:

    Every gate in this repository was written under an assumption nobody ever
    had to state: the panel is reachable only by someone who already has a shell
    on the box. That assumption is doing enormous load-bearing work. It is why a
    500 from an unhandled exception was a bug and not an incident, why the
    lockout could be per-user rather than per-IP, and why a slow endpoint was a
    slow endpoint rather than a denial-of-service vector.

    Phase 7b deletes that assumption on purpose, for one specific path. The
    instant it lands, every weakness in Phases 1 through 7a that was tolerable
    because of the loopback bound is reachable from the internet. This phase
    does not introduce those weaknesses — it changes their blast radius, which
    is why the gating on the *decision to expose* is the whole phase, and why
    every gate here is about refusing rather than about serving.

    Four things go wrong here and nowhere else:

    1. **The bind and the route are different questions, and only one of them is
       obvious.** Traefik runs in a container. It cannot reach `127.0.0.1` on
       the host, so something has to give. The tempting fix is to bind the panel
       to `0.0.0.0` and let Traefik find it — which also lets the entire
       internet find it, bypassing the TLS termination and the rate limit that
       were the whole justification for routing through Traefik at all. The
       locked design is a dedicated edge network whose gateway the panel binds;
       `0.0.0.0`, `::`, and any address outside that network stay refused.
    2. **A domain name is attacker-adjacent input that gets written into YAML.**
       The panel domain arrives from argv and lands in a Traefik dynamic config
       file. A domain carrying a newline injects arbitrary routing — including a
       router for someone else's hostname, or a middleware that strips
       authentication.
    3. **`--disable` is the security control, not the convenience.** An operator
       who exposes a panel to debug something and cannot fully reverse it has
       permanently widened their attack surface. Reversal has to be complete and
       repeatable, and it has to work when the state file has already been
       removed by hand.
    4. **The gate conditions are the product.** 2FA, a passing DNS/IP preflight,
       and a typed confirmation are not paperwork; they are the difference
       between publishing an authenticated admin panel and publishing an
       unauthenticated one. A gate that can be skipped with a flag is not a gate,
       and the standing project rule that ACME never runs without a passing
       preflight has no exception clause for this phase.

Invariants locked here:
  X1   Exposure is refused unless at least one user has TOTP enabled.
  X2   Exposure is refused unless the DNS/IP preflight passes.
  X3   Exposure is refused without the typed confirmation.
  X4   Exposure is refused while the panel still accepts the run token.
  X5   Anti-vacuity for X1-X4: with every condition met, exposure succeeds and
       writes a router config.
  X6   No flag or environment variable skips the preflight.
  X7   The router terminates TLS on the websecure entrypoint via ACME.
  X8   The router attaches a rate-limit middleware.
  X9   A hostile domain cannot inject YAML into the generated config.
  X10  The generated config carries no panel token, hash, or TOTP secret.
  X11  Exposing twice is exposing once.
  X12  Disable removes everything exposure added, and is idempotent.
  X13  Disable works when the state file was removed by hand.
  X14  The loopback default is untouched: a public bind is still refused.
  X15  The exposed bind is inside the wpfy edge network and is never a wildcard.
  X16  Traefik gains no new privilege, mount, or dashboard.
  X17  The dynamic-config directory is mounted read-only and is not site data.
  X18  The systemd unit embeds no panel token.
  X19  The systemd unit never binds a wildcard address.
  X20  `exposure_status()` tells the truth before, during, and after.

Contract pinned by these gates (the actor must match these names exactly):

  Module `wpfy.panel_exposure`:
    PANEL_EDGE_NETWORK = "wpfy-panel-edge"
    RATE_LIMIT_AVERAGE, RATE_LIMIT_BURST          module-level ints
    dynamic_dir() -> Path                         <traefik>/dynamic
    panel_router_path() -> Path                   <traefik>/dynamic/wpfy-panel.yml
    render_router_config(domain, target_url) -> str
    expose(domain, *, confirm, port=...) -> RuntimeResult
    disable() -> RuntimeResult
    exposure_status() -> dict                     {"exposed", "domain", ...}
    panel_service_path() -> Path                  <systemd>/wpfy-panel.service
    panel_service_content(host, port) -> str
    install_service(host, port) -> RuntimeResult
    remove_service() -> RuntimeResult
    validate_edge_bind(host) -> str               raises ValueError off-network

  `expose()` returns a `RuntimeResult`; `exit_code == 0` means exposed. The
  typed confirmation is the panel domain itself, matching the database-drop,
  site-delete, and file-delete confirmations already in the panel.

  Preflight is driven offline by `WPFY_TEST_DNS_IPS` and `WPFY_TEST_PUBLIC_IPS`,
  the hooks `certificate_lifecycle` already reads. The edge network CIDR comes
  from `WPFY_TEST_TRAEFIK_NETWORK_CIDRS`, the hook `traefik` already reads.
  No new test hook is needed and none may be added to weaken a gate condition.
"""

from __future__ import annotations

import json
import os
import re
import stat as stat_module
from pathlib import Path

import pytest

GATE_DOMAIN = "panel.gate.example"
ADMIN_USER = "gate-exposure-admin"
ADMIN_PASSWORD = "PH7B-admin-pw-71c3ae"
EDGE_CIDR = "172.31.240.0/24"
EDGE_GATEWAY = "172.31.240.1"
PUBLIC_IP = "203.0.113.77"
WRONG_IP = "198.51.100.9"

_GATE_ENV = (
    "WPFY_INSTALL_ROOT",
    "WPFY_CONFIG_DIR",
    "WPFY_STATE_DIR",
    "WPFY_LOG_DIR",
    "WPFY_SYSTEMD_DIR",
    "WPFY_SKIP_RUNTIME",
    "WPFY_SKIP_CHOWN",
    "WPFY_TEST_DNS_IPS",
    "WPFY_TEST_PUBLIC_IPS",
    "WPFY_TEST_TRAEFIK_NETWORK_CIDRS",
)

_PATH_FIELDS = ("install_root", "config_dir", "state_dir", "log_dir")

# Every way a domain can carry a second YAML line, plus the shapes that are
# simply not domains. None of these may reach a generated config.
HOSTILE_DOMAINS = (
    "panel.example\nrouters:",
    "panel.example\n  entryPoints:",
    "panel.example\r\nhttp:",
    "panel.example`\n`",
    "panel.example'\"",
    "panel.example ",
    " panel.example",
    "panel.example/../../etc/passwd",
    "../../etc/passwd",
    "panel.example\x00",
    "",
    "-",
    "*",
    "*.example.com",
    "http://panel.example",
    "panel.example:8080",
    "a" * 300 + ".example",
)


@pytest.fixture
def gate_home(tmp_path):
    """An isolated wpfy home with a Traefik scaffold and no exposure.

    Paths are redirected by mutating the frozen `settings.PATHS` singleton in
    place. `importlib.reload` is deliberately avoided: it reuses a module's
    __dict__, so symbols captured at import time by other test modules keep
    pointing at the old class while the module starts producing the new one,
    silently breaking unrelated tests with no possible teardown.

    The preflight starts in a PASSING state and the edge CIDR is injected, so
    every refusal gate below fails for the reason it names rather than because
    the environment happened to be unusable.
    """
    import wpfy.registry
    import wpfy.settings

    paths = wpfy.settings.PATHS
    previous_env = {name: os.environ.get(name) for name in _GATE_ENV}
    previous_paths = {field: getattr(paths, field) for field in _PATH_FIELDS}
    previous_registry = wpfy.registry._REGISTRY

    os.environ.update({
        "WPFY_INSTALL_ROOT": str(tmp_path / "install"),
        "WPFY_CONFIG_DIR": str(tmp_path / "config"),
        "WPFY_STATE_DIR": str(tmp_path / "state"),
        "WPFY_LOG_DIR": str(tmp_path / "log"),
        "WPFY_SYSTEMD_DIR": str(tmp_path / "systemd"),
        "WPFY_SKIP_RUNTIME": "1",
        "WPFY_SKIP_CHOWN": "1",
        "WPFY_TEST_DNS_IPS": PUBLIC_IP,
        "WPFY_TEST_PUBLIC_IPS": PUBLIC_IP,
        "WPFY_TEST_TRAEFIK_NETWORK_CIDRS": EDGE_CIDR,
        # `expose` refuses without a usable contact, the same way site SSL does.
        # These gates are about the router, the service and the bind, so the
        # host is given one rather than every gate asserting that refusal.
        "WPFY_ACME_EMAIL": "ops@example.test",
    })
    for field in _PATH_FIELDS:
        object.__setattr__(paths, field, os.environ[f"WPFY_{field.upper()}"])
    for directory in (paths.state_dir, paths.log_dir, paths.config_dir, paths.traefik_dir):
        Path(directory).mkdir(parents=True, exist_ok=True)
    Path(os.environ["WPFY_SYSTEMD_DIR"]).mkdir(parents=True, exist_ok=True)

    wpfy.registry._REGISTRY = None

    # The CIDR override alone left this self-contradictory: the subnet was
    # injected while `_network_gateway` still asked the real Docker daemon, so
    # the two disagreed on a machine with Docker and there was no gateway at all
    # on a machine without one. Both are pinned so the gates say the same thing
    # everywhere.
    import wpfy.traefik as _traefik

    previous_gateway = _traefik._network_gateway
    _traefik._network_gateway = (
        lambda network: EDGE_GATEWAY if network == "wpfy-panel-edge" else None)

    import wpfy.panel_auth as panel_auth

    panel_auth.reset_state()
    try:
        yield paths
    finally:
        panel_auth.reset_state()
        for field, value in previous_paths.items():
            object.__setattr__(paths, field, value)
        _traefik._network_gateway = previous_gateway
        wpfy.registry._REGISTRY = previous_registry
        for name, value in previous_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _seed_admin_with_totp():
    """The minimum state in which exposure is permitted to succeed."""
    import wpfy.panel_auth as panel_auth

    panel_auth.add_user(ADMIN_USER, ADMIN_PASSWORD, role=panel_auth.ROLE_ADMIN)
    panel_auth.enable_totp(ADMIN_USER)


def _expose(domain=GATE_DOMAIN, confirm=None):
    import wpfy.panel_exposure as panel_exposure

    return panel_exposure.expose(domain, confirm=domain if confirm is None else confirm)


def _router_text() -> str:
    import wpfy.panel_exposure as panel_exposure

    path = panel_exposure.panel_router_path()
    return path.read_text(encoding="utf-8") if path.exists() else ""


def _refused(result, label: str) -> None:
    assert result.exit_code != 0, f"{label} was allowed: {result.message}"
    assert not _router_text(), f"{label} was refused but still wrote a router config"


# ---------------------------------------------------------------------------
# X1-X6 — the conditions that make exposure safe
# ---------------------------------------------------------------------------

def test_gate_exposure_requires_two_factor(gate_home):
    """X1: publishing a password-only admin panel is the thing this phase is
    for. An operator with a weak password and no second factor is one
    credential-stuffing run from a root shell on every site on the box.
    """
    import wpfy.panel_auth as panel_auth

    panel_auth.add_user(ADMIN_USER, ADMIN_PASSWORD, role=panel_auth.ROLE_ADMIN)
    _refused(_expose(), "exposure with no user enrolled in TOTP")

    panel_auth.enable_totp(ADMIN_USER)
    panel_auth.disable_totp(ADMIN_USER)
    _refused(_expose(), "exposure after the only TOTP enrollment was removed")


def test_gate_exposure_requires_a_passing_preflight(gate_home):
    """X2: the standing project rule is that ACME is never attempted unless
    DNS/IP preflight passes, and it has no exception clause for this phase.
    Exposing a domain that does not resolve here also parks a router for a
    hostname somebody else controls.
    """
    _seed_admin_with_totp()
    os.environ["WPFY_TEST_DNS_IPS"] = WRONG_IP
    _refused(_expose(), "exposure with DNS pointing elsewhere")

    os.environ["WPFY_TEST_DNS_IPS"] = ""
    _refused(_expose(), "exposure with no DNS records at all")


def test_gate_exposure_requires_the_typed_confirmation(gate_home):
    """X3: matching the database-drop, site-delete and file-delete confirmations
    already in the panel. Publishing an admin panel deserves at least what
    dropping a database asks for.
    """
    _seed_admin_with_totp()
    for label, confirm in (
        ("no confirmation", ""),
        ("None confirmation", None if False else ""),
        ("wrong confirmation", "yes"),
        ("near-miss confirmation", GATE_DOMAIN.upper()),
        ("another domain", "panel.other.example"),
    ):
        _refused(_expose(confirm=confirm), f"exposure with {label}")


def test_gate_exposure_is_refused_while_the_run_token_still_works(gate_home):
    """X4: the run token is full admin and is printed to a terminal. Publishing
    a panel that still honours it publishes that terminal's scrollback.

    With no users at all this is the state a fresh box is in, and it is exactly
    when an impatient operator would reach for `expose`.
    """
    import wpfy.panel_auth as panel_auth

    assert panel_auth.login_required() is False
    _refused(_expose(), "exposure on a panel with no users")


def test_gate_exposure_succeeds_when_every_condition_is_met(gate_home):
    """X5: anti-vacuity for X1-X4. Every refusal gate above passes against an
    `expose()` that refuses unconditionally, or that does not exist.
    """
    import wpfy.panel_exposure as panel_exposure

    _seed_admin_with_totp()
    result = _expose()
    assert result.exit_code == 0, f"exposure refused with every condition met: {result.message}"

    text = _router_text()
    assert text, "exposure reported success but wrote no router config"
    assert GATE_DOMAIN in text, f"the router config does not mention the domain:\n{text}"
    status = panel_exposure.exposure_status()
    assert status.get("exposed") is True, f"status does not report exposure: {status}"
    assert status.get("domain") == GATE_DOMAIN, f"status reports the wrong domain: {status}"


def test_gate_no_switch_skips_the_preflight(gate_home):
    """X6: a gate that can be turned off is not a gate. `WPFY_SKIP_RUNTIME` is
    already set throughout this file, which proves the offline test hooks do not
    double as a bypass.
    """
    _seed_admin_with_totp()
    os.environ["WPFY_TEST_DNS_IPS"] = WRONG_IP

    for name in ("WPFY_SKIP_PREFLIGHT", "WPFY_FORCE_EXPOSE", "WPFY_SKIP_SSL_PREFLIGHT",
                 "WPFY_DRY_RUN", "WPFY_SKIP_RUNTIME"):
        previous = os.environ.get(name)
        os.environ[name] = "1"
        try:
            _refused(_expose(), f"exposure with {name}=1")
        finally:
            if previous is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = previous


# ---------------------------------------------------------------------------
# X7-X10 — what the generated routing actually says
# ---------------------------------------------------------------------------

def test_gate_router_terminates_tls_on_the_secure_entrypoint(gate_home):
    """X7: a router on the plain entrypoint publishes session bearer tokens in
    cleartext to every hop between the operator and the box.
    """
    _seed_admin_with_totp()
    assert _expose().exit_code == 0
    text = _router_text()

    assert "websecure" in text, f"the panel router is not on the TLS entrypoint:\n{text}"
    assert "tls" in text.lower(), f"the panel router does not enable TLS:\n{text}"
    assert "certresolver" in text.lower().replace("_", ""), (
        f"the panel router has no ACME certificate resolver:\n{text}"
    )
    assert not re.search(r"^\s*-?\s*web\s*$", text, re.MULTILINE), (
        f"the panel router is also published on the plain HTTP entrypoint:\n{text}"
    )


def test_gate_router_rate_limits(gate_home):
    """X8: 7a's lockout is per account, which stops guessing at one password and
    does nothing about a flood. On a loopback panel that was fine. Published, an
    unauthenticated endpoint that runs scrypt on every request is a CPU
    exhaustion primitive, so the throttle has to live at the edge.
    """
    import wpfy.panel_exposure as panel_exposure

    _seed_admin_with_totp()
    assert _expose().exit_code == 0
    text = _router_text().lower()

    assert "ratelimit" in text.replace("-", "").replace("_", ""), (
        f"the panel router attaches no rate-limit middleware:\n{_router_text()}"
    )
    assert "middlewares" in text, f"the router declares no middleware chain:\n{_router_text()}"
    assert panel_exposure.RATE_LIMIT_AVERAGE > 0
    assert panel_exposure.RATE_LIMIT_BURST > 0
    assert panel_exposure.RATE_LIMIT_AVERAGE <= 100, (
        f"RATE_LIMIT_AVERAGE is {panel_exposure.RATE_LIMIT_AVERAGE} requests/sec, "
        "which does not throttle an automated login flood"
    )


def test_gate_hostile_domains_cannot_inject_routing(gate_home):
    """X9: the domain comes from argv and is written into a YAML file that
    Traefik reloads automatically. A newline in it is arbitrary routing — a
    router for a hostname the operator does not own, or a middleware chain that
    drops authentication.
    """
    import wpfy.panel_exposure as panel_exposure

    _seed_admin_with_totp()
    escaped = []
    for domain in HOSTILE_DOMAINS:
        try:
            result = panel_exposure.expose(domain, confirm=domain)
        except (ValueError, TypeError):
            continue
        if result.exit_code == 0:
            escaped.append(f"accepted {domain!r}")
        text = _router_text()
        if text and ("routers:" in text.split(GATE_DOMAIN)[-1] or "\nhttp:" in text[1:]):
            escaped.append(f"{domain!r} injected structure into the config")
        if text:
            escaped.append(f"{domain!r} was refused but left a config behind")
    assert not escaped, "hostile domains reached the router config:\n  " + "\n  ".join(escaped)

    # The renderer itself must refuse too — a caller that reaches it directly,
    # in this phase or a later one, cannot be allowed to bypass the check.
    for domain in HOSTILE_DOMAINS:
        with pytest.raises((ValueError, TypeError)):
            panel_exposure.render_router_config(domain, f"http://{EDGE_GATEWAY}:8642")


def test_gate_generated_config_carries_no_secret(gate_home):
    """X10: the dynamic config is a file Traefik reads and an operator pastes
    into bug reports. Nothing that authenticates anybody may be in it.
    """
    import wpfy.panel_auth as panel_auth

    _seed_admin_with_totp()
    assert _expose().exit_code == 0

    record = next(entry for entry in json.loads(
        panel_auth.users_path().read_text(encoding="utf-8"))["users"]
        if entry["username"] == ADMIN_USER)
    forbidden = {
        "password hash": record["password_hash"],
        "password salt": record["password_salt"],
        "totp secret": record["totp_secret"],
        "admin password": ADMIN_PASSWORD,
    }
    text = _router_text()
    found = [label for label, value in forbidden.items() if value and value in text]
    assert not found, f"the router config contains: {', '.join(found)}"


# ---------------------------------------------------------------------------
# X11-X13 — idempotency and reversal
# ---------------------------------------------------------------------------

def test_gate_exposing_twice_is_exposing_once(gate_home):
    """X11: the project's standing idempotency rule. A second `expose` after a
    partial failure is the normal recovery path, not a mistake.
    """
    _seed_admin_with_totp()
    assert _expose().exit_code == 0
    first = _router_text()

    second_result = _expose()
    assert second_result.exit_code == 0, f"a repeat exposure failed: {second_result.message}"
    assert _router_text() == first, "a repeat exposure changed the router config"


def test_gate_disable_reverses_everything_and_repeats_safely(gate_home):
    """X12: `--disable` is the security control. An operator who exposed a panel
    to debug something and cannot fully close it has permanently widened their
    attack surface.
    """
    import wpfy.panel_exposure as panel_exposure

    _seed_admin_with_totp()
    assert _expose().exit_code == 0
    assert _router_text()

    result = panel_exposure.disable()
    assert result.exit_code == 0, f"disable failed: {result.message}"
    assert not panel_exposure.panel_router_path().exists(), (
        "disable left the router config in place, so Traefik still serves the panel"
    )
    assert panel_exposure.exposure_status().get("exposed") is False

    repeat = panel_exposure.disable()
    assert repeat.exit_code == 0, f"a second disable failed: {repeat.message}"

    fresh = panel_exposure.disable()
    assert fresh.exit_code == 0, f"disable on a never-exposed panel failed: {fresh.message}"


def test_gate_disable_works_after_the_state_file_is_removed(gate_home):
    """X13: state files get deleted by hand, by a restore, or by a half-finished
    uninstall. If reversal depends on the state file, the router outlives it and
    the panel stays published with nothing recording that it is.
    """
    import wpfy.panel_exposure as panel_exposure

    _seed_admin_with_totp()
    assert _expose().exit_code == 0
    router = panel_exposure.panel_router_path()
    assert router.exists()

    for candidate in Path(gate_home.config_dir).glob("panel-exposure*"):
        candidate.unlink()

    result = panel_exposure.disable()
    assert result.exit_code == 0, f"disable failed without its state file: {result.message}"
    assert not router.exists(), (
        "the router config outlived the state file, so the panel stays published "
        "with nothing recording that it is"
    )


# ---------------------------------------------------------------------------
# X14-X17 — the blast radius stays where it was
# ---------------------------------------------------------------------------

def test_gate_the_loopback_default_is_untouched(gate_home):
    """X14: "we have logins and TLS now" is exactly the argument that would
    loosen this. Exposure routes through Traefik; it is never a reason for the
    panel itself to answer on a public interface.
    """
    import wpfy.panel as panel

    _seed_admin_with_totp()
    assert _expose().exit_code == 0

    assert panel.PanelConfig().host == "127.0.0.1", "the panel default bind is no longer loopback"
    for host in ("0.0.0.0", "::", "10.0.0.5", PUBLIC_IP):
        with pytest.raises(ValueError):
            panel.make_panel_server(panel.PanelConfig(host=host, port=0, token="gate-token"))


def test_gate_the_exposed_bind_stays_on_the_edge_network(gate_home):
    """X15: Traefik is in a container and cannot reach `127.0.0.1` on the host,
    so something has to give. The tempting fix is `0.0.0.0`, which also hands
    the panel to the internet directly — bypassing the TLS termination and the
    rate limit that were the entire justification for routing through Traefik.

    The locked design is a dedicated edge network whose gateway the panel binds.
    Anything outside that network, and every wildcard, stays refused.
    """
    import wpfy.panel_exposure as panel_exposure

    # `validate_panel_edge_bind` is the rule this gate means. `validate_edge_bind`
    # is the weaker shared check, and since the domainless mode (ADR 0033) it
    # also serves a panel that binds the host's public address on purpose -- so
    # asserting the edge rule against it now pins two designs at once.
    assert panel_exposure.validate_panel_edge_bind(EDGE_GATEWAY) == EDGE_GATEWAY

    for host in ("0.0.0.0", "::", "", "*", PUBLIC_IP, "10.0.0.5", "192.168.1.1",
                 "example.com", "127.0.0.1 0.0.0.0"):
        with pytest.raises(ValueError):
            panel_exposure.validate_panel_edge_bind(host)


def test_gate_the_edge_proxy_gains_no_new_privilege(gate_home):
    """X16: the locked decision rejected running the panel in a container
    precisely because Traefik would then need the docker socket and every site
    directory. Exposure must not smuggle that in through the back door.
    """
    import wpfy.traefik as traefik

    _seed_admin_with_totp()
    assert _expose().exit_code == 0

    compose = traefik.traefik_compose_content()
    static = traefik.traefik_static_config()

    assert "/var/run/docker.sock:/var/run/docker.sock:ro" in compose, (
        "the docker socket mount is no longer read-only"
    )
    assert "no-new-privileges:true" in compose
    assert "privileged" not in compose, "the edge proxy is now privileged"
    assert "/sites" not in compose, "a site directory is now mounted into the edge proxy"
    assert "dashboard: false" in static, "the Traefik dashboard is now enabled"
    assert "insecure" not in static.lower(), "the Traefik API is now insecure"


def test_gate_the_dynamic_directory_is_read_only_and_is_not_site_data(gate_home):
    """X17: the file provider is a directory Traefik reloads automatically.
    Anything with write access to it can add a router for any hostname. Site
    data is attacker-influenced by construction, so the two must never overlap.
    """
    import wpfy.panel_exposure as panel_exposure
    import wpfy.traefik as traefik

    _seed_admin_with_totp()
    assert _expose().exit_code == 0

    dynamic = panel_exposure.dynamic_dir().resolve()
    compose = traefik.traefik_compose_content()
    static = traefik.traefik_static_config()

    assert "file:" in static.replace(" ", "") or "file:" in static, (
        f"Traefik has no file provider, so the router config is never read:\n{static}"
    )
    assert f"{dynamic}:" in compose, f"the dynamic directory is not mounted:\n{compose}"
    assert re.search(rf"{re.escape(str(dynamic))}:[^\s]+:ro\b", compose), (
        f"the dynamic directory is mounted writable:\n{compose}"
    )

    sites_root = Path(gate_home.sites_dir).resolve()
    assert sites_root not in dynamic.parents and dynamic != sites_root, (
        f"the dynamic config directory {dynamic} lives inside site data"
    )
    mode = stat_module.S_IMODE(dynamic.stat().st_mode)
    assert not mode & 0o022, f"the dynamic config directory is {oct(mode)}: group/world writable"


# ---------------------------------------------------------------------------
# X18-X20 — the service unit and honest status
# ---------------------------------------------------------------------------

def test_gate_the_systemd_unit_embeds_no_token(gate_home):
    """X18: a unit file is world-readable and `systemctl show` prints ExecStart
    to anyone. A token there is the same defect argv was, with a longer life.
    """
    import wpfy.panel_exposure as panel_exposure

    content = panel_exposure.panel_service_content(EDGE_GATEWAY, 8642)
    assert "--token" not in content, f"the unit passes a token on the command line:\n{content}"
    for marker in ("token=", "TOKEN=", "password", "secret"):
        assert marker not in content, f"the unit embeds {marker!r}:\n{content}"

    result = panel_exposure.install_service(EDGE_GATEWAY, 8642)
    assert result.exit_code == 0 or not panel_exposure.panel_service_path().exists(), (
        f"install_service failed but left a unit behind: {result.message}"
    )
    if panel_exposure.panel_service_path().exists():
        installed = panel_exposure.panel_service_path().read_text(encoding="utf-8")
        assert "--token" not in installed


def test_gate_the_systemd_unit_never_binds_a_wildcard(gate_home):
    """X19: the unit is what actually runs in production. Every other bind gate
    in this file is theatre if the shipped unit says `0.0.0.0`.
    """
    import wpfy.panel_exposure as panel_exposure

    content = panel_exposure.panel_service_content(EDGE_GATEWAY, 8642)
    assert "0.0.0.0" not in content, f"the unit binds a wildcard address:\n{content}"
    assert "--host" in content, f"the unit does not pin a bind address at all:\n{content}"

    for host in ("0.0.0.0", "::", PUBLIC_IP):
        with pytest.raises(ValueError):
            panel_exposure.panel_service_content(host, 8642)


def test_gate_status_tells_the_truth(gate_home):
    """X20: an operator asking "is my panel published?" has to get the real
    answer. A status that reads its own state file rather than the filesystem
    says "no" for a router that is still being served.
    """
    import wpfy.panel_exposure as panel_exposure

    before = panel_exposure.exposure_status()
    assert before.get("exposed") is False, f"a fresh panel reports itself exposed: {before}"
    assert before.get("domain") in (None, ""), f"a fresh panel reports a domain: {before}"

    _seed_admin_with_totp()
    assert _expose().exit_code == 0
    assert panel_exposure.exposure_status().get("exposed") is True

    for candidate in Path(gate_home.config_dir).glob("panel-exposure*"):
        candidate.unlink()
    assert panel_exposure.exposure_status().get("exposed") is True, (
        "status reads only its own state file, so a router still being served "
        "reports as not exposed"
    )

    assert panel_exposure.disable().exit_code == 0
    assert panel_exposure.exposure_status().get("exposed") is False
